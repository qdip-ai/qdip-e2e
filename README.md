# QDIP independent end-to-end tests

## Current Web role/session contract (2026-10-11)

The public hosted E2E suite's `rr-oidc-session-v1` mode exercises the real
qdip-web operator authorization and real Core/Mongo persistence, but only
with **isolated, test-only signed cookies**. It is not a real Zitadel login.

- Canonical source of truth: `qdip-web/src/lib/qdip-oidc.ts`, using
  `QDIP_AUTH_COOKIE_SECRET`, `ZITADEL_QDIP_PROJECT_ID`,
  `ZITADEL_QDIP_ORGANIZATION_ID`, and roles `rr_operator`/`studio`.
  A previous suite used the obsolete `QDIP_WEB_SESSION_SIGNING_SECRET`
  and a session body without project/org/roles. That older PASS **cannot**
  qualify the present Web auth flow.
- Disposable `scripts/provision_tenants.py` generates a fresh test-only
  cookie key and fake project/org/subject IDs, never using production secrets.
  Required Chromium cases test signed RR access as well as anonymous,
  studio-only, tampered, wrong-project, wrong-org, invalid-issuer and expired
  sessions against the real BFF. Each must pass with no skips. The suite
  asserts an authenticated RR browser **before** using the real Core API.
- `scripts/check_oidc_session_contract.py` detects drift between Web source
  and E2E signer before starting browser tests. This static check alone
  is **not** an authorization PASS.
- Automatic watcher now follows only `Core/dev + Web/dev`, not old merged
  feature-branch pairs. A Web SHA change participates in the qualification
  identity even if Core SHA is unchanged. Manual runs can pin both SHAs
  to test a staged Web PR without merging it.
- A green test-mode result is printed as
  `QDIP_AUTH_SIGNED_SESSION_INTEGRATION=PASS`; live Zitadel authorize,
  actual browser redirect, code exchange, token signature/JWKS, PKCE,
  issuer/client registration and real Zitadel role issuance stay explicitly
  `QDIP_AUTH_LIVE_ZITADEL_OIDC=NOT_TESTED` until a **separate isolated
  real-Zitadel test account and callback environment** are configured.
  Do not report auth production qualification based on signed-cookie tests.

To run on the independent public GitHub runner (no local Playwright/Docker),
select `rr-oidc-session-v1` and immutable `backend_ref` /`observatory_ref`.
The `QDIP_READ_TOKEN` GitHub Actions secret must be able to read both source
repositories. **Never disclose it in a chat or public repository.**
No changes to Web's real `QDIP_AUTH_COOKIE_SECRET` are necessary.

---


Independent GitHub Actions suite (manual E2E and public-repository SHA polling) for [QDIP](https://github.com/mentality-prj/dzvin-intelligence-platform) and [Observatory](https://github.com/mentality-prj/dip-observatory).

**Runs native MongoDB 8.0 replica set, FastAPI, Kernel/CP-SAT, independent Python SDK Worker, Next.js and Chromium Playwright on a GitHub-hosted Ubuntu runner. No Docker, no in-process fake persistence and no customer data.**

## Launch

1. Set **this E2E repository to Public**. The backend can remain private. Scheduled polling is disabled at the job level while this E2E repository is Private.
2. Configure repository secret `QDIP_READ_TOKEN`: fine-grained token with **Contents: Read-only** on exactly `qdip-ai/qdip-core` and `qdip-ai/qdip-web`. Never commit a token, use it as an Actions input, or expose it in logs. This public test repo does not need private source copied into it.
3. In **Actions → QDIP independent real E2E → Run workflow** choose source refs (defaults: backend `dev`, Observatory `dev`).
4. Read the **individual step results** and downloaded sanitized evidence artifact. All tested checkout SHAs are recorded.

The expensive test workflow accepts `workflow_dispatch` and `repository_dispatch` only. A separate lightweight `Watch QDIP Core (no Core Actions)` workflow polls once per hour at minute 17 UTC. Neither workflow runs on E2E repository pushes or PRs. Repository secrets are not available to unauthenticated visitors or ordinary public PRs.

## Automatic runs: NO GitHub Actions in the private Core

The former `dzvin-intelligence-platform/.github/workflows/dispatch-qdip-e2e.yml`
was **deleted from the active RR feature branch**. It never reached Core
`dev`. E2E now has **zero automatic Action jobs in the private Core**.

The only automatic watcher is in this **public E2E repository**:
`.github/workflows/watch-core.yml` scheduled for minute 17 of each hour.
It invokes `scripts/watch_core.py` to check `dev` and
`feat/rr-prod-01-normalized-source-import` through the GitHub REST API using
the E2E repository's already configured `QDIP_READ_TOKEN`. Branches without
the required RR reference proof are deferred until ready.

For an eligible new SHA, the watcher dispatches `qdip-core-updated` with
the **immutable Core SHA**. `real-e2e.yml` runs tests only in this E2E
repository. The watcher records each observed source commit, Observatory ref and E2E test-suite
fingerprint in the durable `.state/core-watch.json` ledger in this **E2E
repository**. Docs-only changes advance the observed head without triggering
the expensive test. A new source commit or changed test-suite code produces
a new qualification identity. The terminal E2E result records
`PASS`, `TEST_FAIL`, or `INFRA_FAIL` with the run ID. Failures are
not silently converted to PASS or retried indefinitely; manual reruns are
available. A stalled dispatch has one bounded retry after six hours.

**Runner-cost guard:** both `watch-core.yml` AND
`real-e2e.yml` use `if: github.event.repository.private == false`.
When the E2E repository reports Private, neither scheduled nor manually
started E2E jobs allocate a runner. **This repository is now public.** The runner guard remains fail-closed if its visibility changes; verify source token and source-repo read grants before initiating a run.
The API connector does not expose the visibility-changing operation.

**Only one secret is required:** `QDIP_READ_TOKEN` in **this E2E repository**,
fine-grained `Contents: Read-only` on the source Core and Observatory.
The watcher uses its own `GITHUB_TOKEN` for a self-repository dispatch
and an Actions artifact read, not a cross-repo write credential. The former
backend-side `QDIP_E2E_DISPATCH_TOKEN` is **no longer necessary** and should
be revoked/deleted from backend repository Secrets if it was created.

**Important:** Core still contains independent historical CI/GF2 workflows.
Removing the E2E trigger does not disable those unrelated workflows. To
enforce literally **zero Actions minutes in Core**, additionally set
`dzvin-intelligence-platform → Settings → Actions → General → Actions
permissions → Disable actions`. This is an administrative action, does
not affect this E2E repo polling Core's source via read-only token, and
cannot be performed with this connector.

GitHub may delay scheduled jobs, and scheduled workflows can be disabled
after long inactivity in public repositories. The watcher provides
eventual detection, not instant on-push delivery.

Public-repository logs are deliberately sanitized: private Core/Observatory
build commands, pytest, and Playwright subprocesses write raw output only
under the ephemeral runner's `RUNNER_TEMP`. Raw logs and Playwright JSON
results are NOT uploaded as artifacts. Public evidence contains only commit
SHAs and explicitly bounded outcome summaries. This prevents accidental
traceback/source exposure but means detailed private diagnostics require a
separately authorized restricted debugging process. Do not enable raw debug
logging on public runs.

The real-service tests now use independent versioned civilian API JSON
(`fixtures/rr_reference_api_v1.json`) instead of importing a Core-owned
fixture. They exercise real concurrent replans (one head wins),
process restart with retained MongoDB history, API-key revocation,
SDK Worker disconnect and fail-closed Chromium coverage (3 required
tests, zero skipped).

**Least privilege:** the integration job executing private source has only
`contents: read`. A separate public-suite-only finalizer job downloads
a sanitized stage-status artifact and updates the durable ledger with
`contents: write`. No private backend is checked out into this
write-capable job. The public `Validate public E2E suite` workflow
runs Actionlint, Python syntax and Bash syntax checks on suite changes,
but allocates no runner until this repository is Public.

**Limits:** E2E is `NOT_RUN` until an actual public hosted-runner
job succeeds. Browser login still tests temporary reference-password
authentication, not final OIDC; single-node Mongo replica does not
establish HA or production RTO/RPO.

The Observatory ref in automatic runs is currently the staged
`dev`; each E2E records its exact
checkout SHA. Once that frontend changes, update the configured ref in
`scripts/watch_core.py`. Stage browser operator authentication is not
production OIDC validation.

## What is tested

- Genuine MongoDB transaction/competing-replan tests in a single-node replica set; this is not HA/failover evidence.
- Real `mongodump → dropDatabase → mongorestore` on a hardcoded **disposable synthetic test database**, followed by persisted RR history/head/audit checks.
- Real HTTP FastAPI → CP-SAT Kernel → MongoDB: create, retry, replan, tenant isolation, history, integrity, replay and export.
- Independent separately installed Python Remote SDK Worker via WebSocket → live FastAPI → server-owned Kernel.
- Chromium Playwright → actual Next.js Observatory operator UI → live QDIP API / real MongoDB.

**Current Observatory branch uses a shared operator password as a staging test only. This is NOT final OAuth/OIDC qualification.** No live customer data, no cross-company training, no ROI claim, no enterprise security/SLA/HA assertion.

## Scope and gates

`E2E PASS` means only that the specified real integration tests passed on the recorded SHAs. The following remain separate release gates: proper OAuth/OIDC per-user authorization, internet-facing security, backup RTO/RPO, multi-node reliability, deployment review and customer-specific acceptance.

Backend roadmap [#270](https://github.com/mentality-prj/dzvin-intelligence-platform/issues/270), RR [#274](https://github.com/mentality-prj/dzvin-intelligence-platform/issues/274). **Do not infer product qualification from this suite alone.**

## Public repo safety

- Source checkouts use a read-only token and `persist-credentials: false`.
- All services listen on localhost; synthetic-only test content.
- Random test credentials are masked and are not included in uploaded artifacts.
- Hosted-runner APT and pip/pnpm downloads are required; test output is retained for 7 days.
- An Actions job that never started or fails to install a dependency is **NOT_RUN/FAIL**, never a PASS.

## New: real shared Core/Web RR plugin-contract E2E

These checks live in **this public independent suite**, not in qdip-core or
qdip-web. The existing legacy E2E mode is retained for older Core SHA pairs;
the new `rr-plugin-v1` mode is strict and **never silently falls back**.

To test the staged backend+web implementation, use **Actions → QDIP independent
real E2E → Run workflow** in this repository, with:

- **backend_ref** = `feat/rr-plugin-computation-ownership` (or an immutable Core commit SHA);
- **observatory_ref** = `fix/rr-ux-reverse-audit-integrity` (or a matched immutable Web SHA);
- **rr_contract_mode** = `rr-plugin-v1`.

The suite will record the exact checked-out Core/Web/E2E SHAs. This path
requires the existing `QDIP_READ_TOKEN` Actions secret with **read-only access
to both source repositories**. An earlier watcher failed because this secret
was empty; this cannot be corrected by editing repository test code. Store it
only in GitHub Actions secrets, never in logs, artifacts or chat messages.

### Additional required test matrix (no mocks, no skipped cases)

1. `scripts/http_rr_plugin_e2e.py`: real HTTP + native disposable Mongo
   backend admission/preflight, negative credentials and malformed schema,
   assertion that preflight did **not** persist an execution, actual CP-SAT
   execution, persisted plugin presentation, cross-tenant denial, replan,
   history, replay, and the plugin-attested complete export.
2. `scripts/rr_plugin_browser.spec.ts`: four Chromium scenarios for a
   guest-visible **input-only** civil reference; unauthenticated denial on
   preflight/evidence/export; real reference-operator login → backend preflight
   → actual Kernel execution → plugin read model → user-friendly job schedule
   → replan → replay → verified export → logout; and fail-closed invalid input.
   The test is copied into the checked-out Observatory's Playwright test
   directory **only on the disposable E2E runner** so it resolves that
   application's installed Playwright dependency; it never mocks the API.
3. `scripts/check_browser_report.py` rejects missing, failed or skipped
   required browser cases. The `rr-plugin-http` safe-stage reports a
   `TEST_FAIL`, not a silent success.

A successful old `legacy` suite result **does not** establish the new
presentation/preflight/verified-export contract. Once Core `dev` ships
`app/plugins/readiness_recovery/presentation.py`, the public Core watcher
**automatically requires** `rr-plugin-v1` on subsequent runs and fails closed
if Web `dev` has not yet been upgraded.

**Security and release limits:** the browser case tests the restricted staging
operator password, **not Zitadel OIDC**. The separate OIDC implementation must
receive its own live login/permission/browser acceptance using approved test
identities; this suite does not prove multi-tenant SSO, production SLA/HA,
field effectiveness, ROI or customer acceptance. The new tests intentionally
fail against unqualified Core/Web combinations; green static validation only
means test scripts are syntactically valid, not that real E2E passed.

### Signed Core actor audit acceptance (additional)

For `rr-plugin-v1`, the isolated runner also generates an independent
`RR_ACTOR_ASSERTION_SECRET` (masked in Actions output). A second real Core
HTTP/Mongo execution uses a short-lived HMAC actor assertion matching the
Zitadel BFF's wire format. It verifies immutable execution and replan audit
attribution and fail-closed forged, expired or wrong-operation assertions.

**This does not simulate or claim a real Zitadel login**. Live OAuth/OIDC
callback, token signature, approved subject and browser audit identity remain
a separate external end-to-end gate requiring a configured Zitadel test
account/issuer and matching Core/Web secrets. The default staged Web reference
operator uses password authentication only for isolated data-plane E2E; it
cannot qualify the final OIDC release.

### Additional `rr-oidc-session-v1` Core/Web data-plane gate

The independent E2E suite now has a **separate, explicitly labeled**
`rr-oidc-session-v1` mode, intended for Core
`feat/rr-plugin-computation-ownership` with Web `feat/qdip-zitadel-oidc`.
It does not use the retired shared-password operator.

For this mode the disposable runner creates **only synthetic**:
`ZITADEL_ISSUER=https://qdip-e2e.invalid`,
`ZITADEL_CLIENT_ID=qdip-e2e-client`,
`QDIP_WEB_SESSION_SIGNING_SECRET` (random per run),
`QDIP_RR_ALLOWED_ZITADEL_USER_IDS=qdip-e2e-operator`, and
`QDIP_STUDIO_ALLOWED_ZITADEL_USER_IDS=qdip-e2e-studio-only`.
It creates a short-lived HMAC-signed browser session with an independent
random actor signing secret. The two allowlists are intentionally disjoint:
a Studio-only session must not authorize RR. Retired
`QDIP_AUTH_COOKIE_SECRET`, `QDIP_AUTH_ALLOWED_SUBJECTS`, and
`QDIP_AUTH_OPERATOR_SUBJECTS` are not used by the runner. The browser exercises the actual BFF's authorization, signed
pseudonymous Core actor attribution, Core HTTP/CP-SAT, Mongo persistence,
read-model evidence, replanning and verified-page export without mocking
any backend or persistence. It also checks that the retired password route returns 410,
untrusted guests and Studio-only accounts cannot invoke RR, and tampered
signed cookies return 401.

**This does NOT authenticate with a real Zitadel issuer and does NOT
qualify authorization-code exchange, registered callback, JWKS signature,
token issuer/audience/state/nonce/PKCE or tenant/subject provisioning.**
Those require a separate approved isolated Zitadel test identity and
callback environment; no automated PASS here may substitute for them.
This test explicitly labels the auth fixture as `ISOLATED_SIGNED_SESSION`.

The watcher derives the strict test mode from both the checked-out Core
presentation module and the pinned Web authentication source. Unknown Web
authentication is rejected rather than downgraded. Manual invocation:
Actions -> QDIP independent real E2E -> Run workflow, enter the pinned
Core/Web refs and select `rr-oidc-session-v1`. The same missing
`QDIP_READ_TOKEN` private-read prerequisite applies.


## AutoDev claimed-run recovery — isolated Mongo integration

Run `scripts/autodev_claimed_recovery_mongo.py` using the existing QDIP
test sandbox with **a local MongoDB replica set** and the exact Core checkout
under test. It exercises the actual
`scripts.autodev.ai_attempt_review` implementation with real majority-read
Mongo collections, not mock persistence.

```sh
# In the existing isolated test sandbox, after checking out qdip-core:
QDIP_E2E_CORE_ROOT=/path/to/qdip-core \
QDIP_E2E_LOCAL_MONGO_PORT=27027 \
python3 scripts/autodev_claimed_recovery_mongo.py
```

The script only connects to `127.0.0.1`; it generates a random
`qdip_autodev_recovery_e2e_*` database and deletes **only that database**
afterwards. No staging/production Mongo credentials, real RR run IDs,
Zitadel sessions, new test accounts or additional roles are required.

Coverage: exact claimed-run eligibility; read-only review; confirmed
one-shot closure; immutable Broker claim preservation; persisted
`FAILED`/no-charge audit; `retryAuthorized=false`; owner-fenced slot release;
idempotent request; refusal on wrong run, wrong confirmation, saved result,
missing/foreign claim and foreign slot.

**Scope limit:** This qualifies the *recovery engine and real Mongo
persistence*, **not** the HTTP/PWA flow or an authenticated browser session.
Those checks are not marked PASS. Authorization is deliberately outside this
task: already existing Zitadel coverage remains unchanged.
