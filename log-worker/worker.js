// BrokenBlade weblog ingestion Worker.
//
// POST /log
//   body: text/plain (raw weblog text) OR application/json { log, meta }
//   stores: r2://${BUCKET}/weblogs/<YYYY-MM-DD>/<YYYY-MM-DDTHH-MM-SS-Z>-<rand>.txt
//   returns: { id, key, size }
//
// GET /log/<key>
//   returns: text/plain content of the stored log
//
// GET /health
//   returns: 200 ok
//
// Admin (X-Admin-Token: ${env.ADMIN_TOKEN}):
//   GET    /admin/list?prefix=weblogs/...   - list keys
//   DELETE /admin/cleanup?prefix=weblogs/... - delete every key with prefix
//
// Rate limit: KV-backed counter, IP × hour-bucket, default 60/hr/IP.
// In-memory cache fallback if the KV binding is missing (e.g. local dev).
//
// Privacy: every request stores CF country / client IP in metadata.

const DEFAULT_RATE_LIMIT_PER_HOUR = 60;
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MB

// Browser origins permitted to make CORS requests. Hostile origins get
// no CORS headers (and POST is rejected outright) to stop drive-by
// uploads from any random site that learns the worker URL.
//
// Non-browser clients (curl, scripted attackers) don't send Origin and
// hit the no-Origin path, which still has rate-limit + body-cap +
// admin-token gates as their backstop.
const ALLOWED_ORIGINS = new Set([
  'https://zeroxjf.github.io',
  'http://localhost:8000',
  'http://127.0.0.1:8000',
]);

// Per-isolate fallback cache. Used only when env.RATE_LIMITER (KV) is missing.
const memRateCache = new Map();

function isAllowedOrigin(origin) {
  if (!origin) return true; // non-browser clients (no Origin header)
  return ALLOWED_ORIGINS.has(origin);
}

function corsHeaders(origin) {
  // Reflect only allowlisted origins. Hostile origins get no CORS
  // headers, which makes browsers refuse to read the response.
  const reflected = (origin && ALLOWED_ORIGINS.has(origin)) ? origin : '';
  const headers = {
    'Access-Control-Allow-Methods': 'POST, GET, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
  if (reflected) headers['Access-Control-Allow-Origin'] = reflected;
  return headers;
}

function jsonResponse(obj, status, origin) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin),
    },
  });
}

function hourBucket(now) {
  return Math.floor(now / (60 * 60 * 1000));
}

// Returns { allowed, count, limit }. KV-backed when env.RATE_LIMITER is
// present, in-memory fallback otherwise. KV is eventually consistent
// (~60s edge propagation), so the limit may overshoot under heavy
// concurrent burst — good enough for casual abuse mitigation, not a
// strict security boundary.
async function checkRate(env, ip) {
  const limit = parseInt(env.RATE_LIMIT_PER_HOUR || '', 10) || DEFAULT_RATE_LIMIT_PER_HOUR;
  const bucket = hourBucket(Date.now());
  const key = `rl:${ip}:${bucket}`;

  if (env.RATE_LIMITER) {
    let count = 0;
    try {
      const raw = await env.RATE_LIMITER.get(key);
      count = parseInt(raw || '0', 10) || 0;
    } catch (e) {}
    if (count >= limit) {
      return { allowed: false, count, limit };
    }
    try {
      await env.RATE_LIMITER.put(key, String(count + 1), { expirationTtl: 3600 });
    } catch (e) {}
    return { allowed: true, count: count + 1, limit };
  }

  const arr = (memRateCache.get(key) || 0) + 1;
  memRateCache.set(key, arr);
  return { allowed: arr <= limit, count: arr, limit };
}

function ts2() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const ymd = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  const hms = `${pad(d.getUTCHours())}-${pad(d.getUTCMinutes())}-${pad(d.getUTCSeconds())}`;
  return { ymd, full: `${ymd}T${hms}Z` };
}

function rand() {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function handleLogPost(request, env) {
  const origin = request.headers.get('Origin') || '';
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Browser-origin allowlist. Non-browser clients (Origin == '') still
  // get through; their gates are rate-limit + body-cap.
  if (!isAllowedOrigin(origin)) {
    return jsonResponse({ error: 'origin_not_allowed' }, 403, origin);
  }

  const rl = await checkRate(env, ip);
  if (!rl.allowed) {
    return jsonResponse({ error: 'rate_limited', count: rl.count, limit: rl.limit }, 429, origin);
  }

  const ct = (request.headers.get('Content-Type') || '').toLowerCase();
  let text = '';
  let meta = {};

  if (ct.startsWith('application/json')) {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return jsonResponse({ error: 'invalid_json' }, 400, origin);
    }
    text = String(body.log || '');
    meta = body.meta || {};
  } else if (ct.startsWith('text/plain') || ct.startsWith('text/')) {
    text = await request.text();
  } else if (!ct) {
    text = await request.text();
  } else {
    return jsonResponse({ error: 'unsupported_content_type', ct }, 415, origin);
  }

  if (!text || text.length === 0) {
    return jsonResponse({ error: 'empty_body' }, 400, origin);
  }

  if (text.length > MAX_BODY_BYTES) {
    return jsonResponse({ error: 'body_too_large', limit: MAX_BODY_BYTES }, 413, origin);
  }

  const { ymd, full } = ts2();
  const id = `${full}-${rand()}`;
  const key = `weblogs/${ymd}/${id}.txt`;

  const cf = request.cf || {};
  // IP is intentionally NOT persisted - used only in-memory above for
  // the rate-limit counter. Country/colo are kept (no per-user
  // resolution); city is dropped since it's narrower than necessary.
  const stamp = [
    `# BrokenBlade weblog`,
    `# uploaded: ${new Date().toISOString()}`,
    `# country: ${cf.country || ''}`,
    `# colo: ${cf.colo || ''}`,
    `# user-agent: ${request.headers.get('User-Agent') || ''}`,
    `# meta: ${JSON.stringify(meta)}`,
    `# ---`,
    '',
  ].join('\n');

  const body = stamp + text;

  try {
    await env.LOGS.put(key, body, {
      httpMetadata: { contentType: 'text/plain; charset=utf-8' },
      customMetadata: {
        country: String(cf.country || ''),
        ua: (request.headers.get('User-Agent') || '').slice(0, 256),
        meta: JSON.stringify(meta).slice(0, 1024),
      },
    });
  } catch (e) {
    return jsonResponse({ error: 'storage_failed', detail: String(e) }, 500, origin);
  }

  return jsonResponse({ ok: true, id, key, size: body.length }, 200, origin);
}

async function handleLogGet(request, env, key) {
  const origin = request.headers.get('Origin') || '';
  // /log/<key> reads are now admin-only. The page-side flow never
  // fetches uploaded logs - it only POSTs - so locking this down has
  // no impact on production behavior. Removes the "anyone with a key
  // can read someone else's log" disclosure path.
  if (!adminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized' }, 401, origin);
  }
  const obj = await env.LOGS.get(key);
  if (!obj) return new Response('not found', { status: 404, headers: corsHeaders(origin) });
  const text = await obj.text();
  return new Response(text, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      ...corsHeaders(origin),
    },
  });
}

function adminAuthorized(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const got = request.headers.get('X-Admin-Token') || '';
  return got && got === env.ADMIN_TOKEN;
}

async function listAllKeys(env, prefix, max) {
  const out = [];
  let cursor;
  let safety = 0;
  while (out.length < max && safety++ < 50) {
    const opts = { prefix, limit: 1000 };
    if (cursor) opts.cursor = cursor;
    const page = await env.LOGS.list(opts);
    for (const obj of page.objects) {
      out.push(obj.key);
      if (out.length >= max) break;
    }
    if (!page.truncated) break;
    cursor = page.cursor;
  }
  return out;
}

async function handleAdminList(request, env) {
  const origin = request.headers.get('Origin') || '';
  if (!adminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized' }, 401, origin);
  }
  const url = new URL(request.url);
  const prefix = url.searchParams.get('prefix') || 'weblogs/';
  const max = Math.min(parseInt(url.searchParams.get('max') || '5000', 10) || 5000, 50000);
  const keys = await listAllKeys(env, prefix, max);
  return jsonResponse({ ok: true, prefix, count: keys.length, keys }, 200, origin);
}

async function handleAdminCleanup(request, env) {
  const origin = request.headers.get('Origin') || '';
  if (!adminAuthorized(request, env)) {
    return jsonResponse({ error: 'unauthorized' }, 401, origin);
  }
  const url = new URL(request.url);
  const prefix = url.searchParams.get('prefix');
  if (!prefix || !prefix.startsWith('weblogs/')) {
    return jsonResponse({ error: 'prefix_required', detail: "must start with 'weblogs/'" }, 400, origin);
  }
  const keys = await listAllKeys(env, prefix, 50000);
  let deleted = 0;
  // R2 list-then-delete in 1000-key batches.
  for (let i = 0; i < keys.length; i += 1000) {
    const slice = keys.slice(i, i + 1000);
    try {
      await env.LOGS.delete(slice);
      deleted += slice.length;
    } catch (e) {
      return jsonResponse({ error: 'delete_failed', detail: String(e), deleted }, 500, origin);
    }
  }
  return jsonResponse({ ok: true, prefix, deleted }, 200, origin);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === '/health') {
      return new Response('ok', { status: 200, headers: corsHeaders(origin) });
    }

    if (url.pathname === '/log' && request.method === 'POST') {
      return handleLogPost(request, env);
    }

    if (url.pathname.startsWith('/log/') && request.method === 'GET') {
      const key = decodeURIComponent(url.pathname.slice('/log/'.length));
      return handleLogGet(request, env, key);
    }

    if (url.pathname === '/admin/list' && request.method === 'GET') {
      return handleAdminList(request, env);
    }

    if (url.pathname === '/admin/cleanup' && request.method === 'DELETE') {
      return handleAdminCleanup(request, env);
    }

    return new Response('not found', { status: 404, headers: corsHeaders(origin) });
  },
};
