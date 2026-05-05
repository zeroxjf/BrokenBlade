# brokenblade-weblogs

Cloudflare Worker that ingests WebContent log uploads from `index.html`
and stores them as `.txt` blobs in an R2 bucket. Auto-uploaded by the
page after every chain run; readable via the Cloudflare R2 dashboard or
the `GET /log/<key>` route.

## Endpoints

- `POST /log` body `{ log: "...", meta: {...} }` (or `text/plain`) →
  writes `weblogs/<YYYY-MM-DD>/<YYYY-MM-DDTHH-MM-SS-Z>-<rand>.txt` to R2
- `GET /log/<key>` → returns the stored text
- `GET /health` → 200 ok

## Deploy

One-time setup:

```sh
npm i -g wrangler
wrangler login
wrangler r2 bucket create brokenblade-weblogs
```

Each deploy:

```sh
cd log-worker
wrangler deploy
```

`wrangler deploy` prints the public URL, e.g.
`https://brokenblade-weblogs.<account>.workers.dev`. Bake that URL into
`index.html`'s `LOG_UPLOAD_URL` constant.

## Abuse posture

- 1 MB body cap
- 60 requests / hour / IP (best-effort, in-memory; resets on isolate
  cycling)
- No HMAC / auth - URL is effectively public. If abuse becomes an
  issue, gate with Cloudflare Turnstile or a per-page-load JWT minted by
  a separate Worker route.

## Browse logs

R2 dashboard → `brokenblade-weblogs` bucket → `weblogs/` prefix, sorted
by date. Each file is plain UTF-8 text with a small metadata header
(IP, country, user-agent, JSON meta blob) followed by the raw weblog.
