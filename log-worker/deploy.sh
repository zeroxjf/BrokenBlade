#!/usr/bin/env bash
# Deploy the brokenblade-weblogs Worker.
#
# Why this script exists: wrangler 4.x walks up from the wrangler.toml
# directory to the nearest .git root and tries to bundle every file as
# a static asset. The BrokenBlade repo root contains firmware/extracted
# DSCs that exceed Cloudflare's 25 MiB per-asset limit, so the walk
# fails. Setting [assets] in wrangler.toml did not suppress the walk in
# our testing.
#
# Workaround: copy worker.js + a clean wrangler.toml to a fresh tmp
# directory (no .git ancestor) and deploy from there.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v wrangler >/dev/null 2>&1; then
  echo "wrangler not found. Install: npm i -g wrangler" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

cp worker.js "$TMPDIR/worker.js"
cp wrangler.toml "$TMPDIR/wrangler.toml"

cd "$TMPDIR"
wrangler deploy
