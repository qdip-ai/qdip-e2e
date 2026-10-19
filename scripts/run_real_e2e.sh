#!/usr/bin/env bash
# Live HTTP/Mongo/Worker/Browser. Raw private-source output stays in RUNNER_TEMP.
set -euo pipefail
[[ "$GITHUB_ACTIONS" == "true" ]] || exit 2
test -n "$E2E_KEY_A"
test -n "$RR_E2E_OPERATOR_PASSWORD"
test -n "$RR_E2E_API_REQUEST_PATH"
RR_E2E_CONTRACT_MODE="${RR_E2E_CONTRACT_MODE:-legacy}"
BROWSER_CONFIG_ARGS=()
case "$RR_E2E_CONTRACT_MODE" in
  legacy|rr-plugin-v1|rr-oidc-session-v1) ;;
  *) echo 'RR_E2E_CONTRACT_MODE=INVALID' >&2; exit 2 ;;
esac
(cd backend && exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 \
  > "$RUNNER_TEMP/qdip-fastapi.log" 2>&1) &
echo $! > "$RUNNER_TEMP/qdip-fastapi.pid"
curl --fail --silent --retry 35 --retry-delay 1 --retry-connrefused \
  http://127.0.0.1:8000/health >/dev/null
(
  cd backend
  python ../suite/scripts/safe_stage.py --timeout 180 backend-http -- \
    python ../suite/scripts/http_rr_e2e.py
)
if [[ "$RR_E2E_CONTRACT_MODE" != "legacy" ]]; then
  (
    cd backend
    python ../suite/scripts/safe_stage.py --timeout 180 rr-plugin-http -- \
      python ../suite/scripts/http_rr_plugin_e2e.py
  )
fi
python suite/scripts/safe_stage.py --timeout 120 backend-restart -- \
  bash suite/scripts/restart_fastapi.sh
(
  cd backend
  python ../suite/scripts/safe_stage.py --timeout 120 backend-restart-verify -- \
    python ../suite/scripts/check_fastapi_restart.py
)
python suite/scripts/safe_stage.py --timeout 70 rr-auth-revocation -- python suite/scripts/check_revocation.py
# Read-only p95 replay benchmark on the EXACT synthetic execution created
# above. No solver invocation, writes, production URL or customer source.
replay_id="$(python -c 'import json,os,pathlib; p=pathlib.Path(os.environ["RUNNER_TEMP"])/"qdip-rr-e2e-state.json"; print(json.loads(p.read_text())["revised_id"])')"
[[ "$replay_id" =~ ^rr-e2e-[a-f0-9]{14}-02$ ]] || {
  echo "RR_REPLAY_LOAD_EXECUTION_ID=INVALID" >&2; exit 2;
}
(
  cd backend
  RR_LOAD_ORG_API_KEY="$E2E_KEY_A" python ../suite/scripts/safe_stage.py --timeout 240 rr-replay-load -- \
    python scripts/verify_rr_http_load.py \
      --base-url http://127.0.0.1:8000 --execution-id "$replay_id" \
      --requests 40 --concurrency 4
)
# The test mode must match the selected *real* Web implementation.
# Never downgrade OIDC to the retired password-login suite.
case "$RR_E2E_CONTRACT_MODE" in
  rr-plugin-v1)
    if grep -q 'Password authentication retired' observatory/src/app/api/rr-operator/session/route.ts; then
      echo 'RR_E2E_AUTH_MODE_MISMATCH=OIDC_REQUIRES_SESSION_TEST' >&2
      exit 2
    fi
    SPEC='e2e/rr_plugin_real_e2e.spec.ts'
    ;;
  rr-oidc-session-v1)
    if ! grep -q 'Password authentication retired' observatory/src/app/api/rr-operator/session/route.ts; then
      echo 'RR_E2E_AUTH_MODE_MISMATCH=EXPECTED_ZITADEL_BFF' >&2
      exit 2
    fi
    SPEC='e2e/rr_oidc_session_real_e2e.spec.ts'
    python suite/scripts/check_oidc_session_contract.py
    ;;
  *)
    SPEC='e2e/rr-production-operator.spec.ts'
    ;;
esac
(
  cd observatory
  python ../suite/scripts/safe_stage.py --timeout 700 observatory-install -- pnpm install --frozen-lockfile
  python ../suite/scripts/safe_stage.py --timeout 300 observatory-lint -- pnpm lint
  python ../suite/scripts/safe_stage.py --timeout 300 observatory-typecheck -- pnpm typecheck
  python ../suite/scripts/safe_stage.py --timeout 300 observatory-format -- pnpm prettier
  # Collect independent RR browser evidence even when unrelated Web unit tests
  # fail. Persist that failure and force this runner to exit nonzero at the end;
  # no release gate is softened and no unit failure may be reported as PASS.
  if ! python ../suite/scripts/safe_stage.py --timeout 300 observatory-unit -- pnpm test; then
    printf 'FAIL\n' > "$RUNNER_TEMP/rr-web-unit.failed"
    echo 'RR_WEB_UNIT=FAIL; collecting independent native browser evidence (overall gate remains blocked)'
  fi
  # Only the built browser app uses localhost origins; the unit tests above
  # must retain their production-default routing contracts.
  if [[ "$RR_E2E_CONTRACT_MODE" == "rr-oidc-session-v1" ]]; then
    export NEXT_PUBLIC_SITE_URL=http://qdip.localhost:3000
    export NEXT_PUBLIC_STUDIO_URL=http://studio.localhost:3000
    export NEXT_PUBLIC_OBSERVATORY_URL=http://observatory.localhost:3000
  fi
  python ../suite/scripts/safe_stage.py --timeout 700 observatory-build -- pnpm build
  python ../suite/scripts/safe_stage.py --timeout 700 browser-install -- pnpm exec playwright install --with-deps chromium
)
if [[ "$RR_E2E_CONTRACT_MODE" == "rr-oidc-session-v1" ]]; then
  cp suite/scripts/rr_oidc_session_browser.spec.ts observatory/e2e/rr_oidc_session_real_e2e.spec.ts
  # The Web default config installs a *different* preauthenticated test
  # session and signing key. Use a clean, suite-controlled browser config.
  cp suite/scripts/rr_real_playwright.config.ts observatory/playwright.rr-real.config.ts
  BROWSER_CONFIG_ARGS=(--config=playwright.rr-real.config.ts)
elif [[ "$RR_E2E_CONTRACT_MODE" == "rr-plugin-v1" ]]; then
  cp suite/scripts/rr_plugin_browser.spec.ts observatory/e2e/rr_plugin_real_e2e.spec.ts
fi
python suite/scripts/safe_stage.py --timeout 180 sdk-install -- bash suite/scripts/start_remote_worker.sh
python suite/scripts/safe_stage.py --timeout 180 sdk-e2e -- python suite/scripts/http_sdk_e2e.py
python suite/scripts/safe_stage.py --timeout 80 sdk-negative -- python suite/scripts/check_remote_worker_failure.py
echo '127.0.0.1 observatory.localhost' | sudo tee -a /etc/hosts >/dev/null
test -s "$RR_E2E_API_REQUEST_PATH"
(
  cd observatory
  if [[ "$RR_E2E_CONTRACT_MODE" == "rr-oidc-session-v1" ]]; then
    export NEXT_PUBLIC_SITE_URL=http://qdip.localhost:3000
    export NEXT_PUBLIC_STUDIO_URL=http://studio.localhost:3000
    export NEXT_PUBLIC_OBSERVATORY_URL=http://observatory.localhost:3000
  fi
  python ../suite/scripts/safe_stage.py --timeout 350 \
    --output "$RUNNER_TEMP/qdip-browser-report.json" browser-e2e -- \
    pnpm exec playwright test "$SPEC" "${BROWSER_CONFIG_ARGS[@]}" \
      --project=chromium --workers=1 --retries=0 --reporter=json --forbid-only
)
python suite/scripts/safe_stage.py --timeout 40 test-report -- python suite/scripts/check_browser_report.py
if [[ -f "$RUNNER_TEMP/rr-web-unit.failed" ]]; then
  echo 'QDIP_REAL_NATIVE_E2E=FAIL (Web unit tests failed; browser evidence does not override release gate)' >&2
  exit 1
fi
echo 'QDIP_REAL_NATIVE_E2E=PASS (not production qualification)'
