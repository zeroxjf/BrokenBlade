#!/usr/bin/env bash
# Pull tester weblogs from the Cloudflare R2 bucket into the local
# `tester-logs/` mirror. Idempotent: only downloads keys not already
# present locally. Run this any time you want to refresh the mirror.
#
# Usage:
#   log-worker/collect-logs.sh
#
# Auth: needs the Worker's ADMIN_TOKEN. Resolution order:
#   1. $BB_ADMIN_TOKEN environment variable
#   2. first line of file at $BB_ADMIN_TOKEN_FILE
#      (default: ~/Downloads/brokenblade-admin-token.txt)
#
# If you reimplement this in Python instead of running it: Cloudflare's
# edge bot-mitigation 403s the default `User-Agent: Python-urllib/3.x`
# before requests reach the Worker. Set a non-default UA (anything,
# e.g. `curl/8.0`) on the request or use curl/requests.
#
# Layout: logs land under <repo>/tester-logs/<build-tag>/<YYYY-MM-DD>/<id>.txt
# matching the worker's R2 key hierarchy.
#
# Cleanup: uses `mktemp -d` for a per-run scratch dir and `trash` on
# EXIT (per repo convention - never `rm`). If `trash` is unavailable
# the temp dir is left for macOS to age out.

set -euo pipefail

WORKER_URL="https://brokenblade-weblogs.hackerboii.workers.dev"
TOKEN_FILE="${BB_ADMIN_TOKEN_FILE:-$HOME/Downloads/brokenblade-admin-token.txt}"
ADMIN_TOKEN="${BB_ADMIN_TOKEN:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$REPO_ROOT/tester-logs"

if [ -z "$ADMIN_TOKEN" ]; then
  if [ -f "$TOKEN_FILE" ]; then
    ADMIN_TOKEN=$(head -1 "$TOKEN_FILE" | tr -d '\n\r')
  else
    echo "ERROR: no admin token. Set BB_ADMIN_TOKEN or put it in $TOKEN_FILE" >&2
    exit 1
  fi
fi

WORK_DIR=$(mktemp -d)
LIST_JSON="$WORK_DIR/list.json"
NEW_KEYS="$WORK_DIR/new_keys.txt"
trap 'command -v trash >/dev/null && trash "$WORK_DIR" 2>/dev/null || true' EXIT

echo "fetching key list from $WORKER_URL ..."
curl -fsS -H "X-Admin-Token: $ADMIN_TOKEN" \
  "$WORKER_URL/admin/list?prefix=weblogs/" > "$LIST_JSON"

mkdir -p "$DEST"

python3 - "$LIST_JSON" "$DEST" "$NEW_KEYS" <<'PY'
import json, os, sys
list_path, dest, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
remote = set(json.load(open(list_path)).get('keys', []))
local = set()
for dp, _, fs in os.walk(dest):
    for f in fs:
        if f.endswith('.txt'):
            local.add('weblogs/' + os.path.relpath(os.path.join(dp, f), dest))
new_keys = sorted(remote - local)
with open(out_path, 'w') as o:
    for k in new_keys:
        o.write(k + '\n')
print(f'remote: {len(remote)}  local: {len(local)}  new: {len(new_keys)}')
PY

new_count=$(grep -c . "$NEW_KEYS" || true)
if [ "$new_count" -eq 0 ]; then
  echo "already up to date."
else
  ok=0; fail=0
  while IFS= read -r key; do
    [ -z "$key" ] && continue
    rel="${key#weblogs/}"
    out="$DEST/$rel"
    mkdir -p "$(dirname "$out")"
    # Download into a per-fetch temp file so a failed download never
    # leaves a partial txt in the mirror. Only `mv` into place on 200,
    # so we never need to delete on the failure path.
    tmp_out=$(mktemp "$WORK_DIR/download.XXXXXX")
    http=$(curl -sS -o "$tmp_out" -w '%{http_code}' \
      -H "X-Admin-Token: $ADMIN_TOKEN" \
      "$WORKER_URL/log/$key" || echo "000")
    if [ "$http" = "200" ]; then
      mv "$tmp_out" "$out"
      ok=$((ok+1))
    else
      fail=$((fail+1))
      echo "FAIL ($http) $key" >&2
      # tmp_out stays in WORK_DIR; cleaned by the trap.
    fi
  done < "$NEW_KEYS"
  echo "downloaded: $ok  failed: $fail"
fi

echo
echo "=== per-build-tag breakdown ==="
for d in "$DEST"/v*; do
  [ -d "$d" ] || continue
  printf '%-30s %4d\n' "$(basename "$d")" "$(find "$d" -type f -name '*.txt' | wc -l | tr -d ' ')"
done
