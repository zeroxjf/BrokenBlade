// BrokenBlade weblog ingestion Worker.
//
// POST /log
//   body: text/plain (raw weblog text) OR application/json { log, meta }
//   stores: r2://${BUCKET}/weblogs/<YYYY-MM-DD>/<YYYY-MM-DDTHH-MM-SS-Z>-<rand>.txt
//   returns: { id, key, size }
//
// GET /log/<key>
//   returns: text/plain content of the stored log (only if KEY matches)
//
// GET /health
//   returns: 200 ok
//
// Abuse mitigations:
//   - 1 MB body cap
//   - per-IP rate limit (60 / hr) via in-memory cache (best-effort, resets on
//     Worker isolate cycling - fine for casual abuse, not a security boundary)
//   - rejects non-text payloads
//
// Privacy: every request stores CF country / client IP in metadata.
// Adjust if you want anonymized logs.

const RATE_LIMIT_PER_HOUR = 60;
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MB

// Per-isolate rate-limit cache. Maps IP -> array of timestamps within the
// rolling 1 hour window. Best-effort only.
const rateCache = new Map();

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
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

function rateOk(ip) {
  const now = Date.now();
  const horizon = now - 60 * 60 * 1000;
  let arr = rateCache.get(ip) || [];
  arr = arr.filter((t) => t > horizon);
  if (arr.length >= RATE_LIMIT_PER_HOUR) {
    rateCache.set(ip, arr);
    return false;
  }
  arr.push(now);
  rateCache.set(ip, arr);
  return true;
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

  if (!rateOk(ip)) {
    return jsonResponse({ error: 'rate_limited' }, 429, origin);
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
  const stamp = [
    `# BrokenBlade weblog`,
    `# uploaded: ${new Date().toISOString()}`,
    `# ip: ${ip}`,
    `# country: ${cf.country || ''}`,
    `# city: ${cf.city || ''}`,
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
        ip: ip,
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

    return new Response('not found', { status: 404, headers: corsHeaders(origin) });
  },
};
