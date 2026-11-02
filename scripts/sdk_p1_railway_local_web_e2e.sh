#!/usr/bin/env bash
set -euo pipefail
cd /web
pnpm start --hostname 0.0.0.0 --port 3000 >/tmp/sdk-p1-next.log 2>&1 &
pid=$!
cleanup() { kill "$pid" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 150); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo 'SDK_P1_NEXT_FAILED_START'; cat /tmp/sdk-p1-next.log; exit 1
  fi
  if curl -sS --max-time 2 -o /dev/null -H 'Host: observatory.localhost:3000' 'http://127.0.0.1:3000/uk/admin/plugins'; then break; fi
  sleep 1
done
echo 'SDK_P1_LOCAL_NEXT_BOOT=PASS'
if ! timeout 300s node /web/scripts/sdk_p1_railway_local_web_e2e.mjs; then
  echo 'SDK_P1_RAILWAY_LOCAL_WEB_UI=FAIL'
  tail -n 65 /tmp/sdk-p1-next.log || true
  exit 1
fi
echo 'SDK_P1_RAILWAY_QA_PASS'
