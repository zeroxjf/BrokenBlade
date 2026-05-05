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
wrangler kv namespace create RATE_LIMITER     # update wrangler.toml id
wrangler secret put ADMIN_TOKEN               # paste a long random hex
wrangler r2 bucket lifecycle add brokenblade-weblogs auto-expire-30d weblogs/ --expire-days 30 --force
```

Each deploy:

```sh
cd log-worker
./deploy.sh
```

`deploy.sh` exists because wrangler 4.x walks up to the nearest `.git`
root and treats every file as a candidate static asset. The BrokenBlade
repo root holds `firmware/extracted/` DSCs that exceed Cloudflare's
25 MiB per-asset limit, so direct `wrangler deploy` fails. The script
copies `worker.js` + `wrangler.toml` to a fresh tmp dir and deploys
from there.

`deploy.sh` prints the public URL, e.g.
`https://brokenblade-weblogs.<account>.workers.dev`. That URL is baked
into `index.html`'s `LOG_UPLOAD_URL` constant.

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
