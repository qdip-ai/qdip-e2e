# SDK #383 — real Railway sealed credentials E2E (independent suite)

This gate belongs in **qdip-ai/qdip-e2e**, not in private Core CI. It tests the actual Railway GraphQL API and, in its second mode, the actual Core/Worker/Kernel. A successful build, mocks, an HTTP lease-only test, and an online Worker do **not** count as sealed delivery.

## 1. Safe sealed stage/commit acceptance

Script: `scripts/sdk383_sealed_railway_e2e.py`.

Target is pinned to the **existing** `qdip-sdk-staging` project/environment and its disposable `rr-sdk-staging-e2e-qa` Function. It does not overwrite `QDIP_REMOTE_API_KEY` or an RR Worker. It stages **only** two initially nonexistent names, `SDK383_E2E_SEALED_CANARY` (with `isSealed:true`) and `SDK383_E2E_SEALED_CANARY_ID` (public key UUID, `isSealed:false`), atomically commits them, verifies the sealed bit and ID through authoritative Railway metadata, and waits for a **new successful deployment**. Then it stages their deletion, commits, and verifies both names are absent. An existing canary, unrelated staged changes, wrong-scoped token, wrong project/environment/service, ambiguous commit, unsuccessful deployment, or unverifiable cleanup fails closed.

Run **only** from the existing trusted Railway operator runtime, with its already-configured environment-scoped `RAILWAY_PROJECT_TOKEN` (not from public CI or a developer's browser). The runner also needs its existing Railway-injected `RAILWAY_PROJECT_ID` and `RAILWAY_ENVIRONMENT_ID`. Activate only for the exact controlled run:

```sh
QDIP_SDK383_E2E_APPROVED=isolated-staging-qa-only \
  python scripts/sdk383_sealed_railway_e2e.py
```

Do not pass secrets in CLI arguments. Do not add a project token to `qdip-e2e` Actions, frontend, logs, or a test Worker. This is a **real mutation** of the existing staging QA service and causes two controlled QA redeployments. Confirm no concurrent QA use and inspect Railway deployment/staged-changes state before use. If a commit/cleanup is ambiguous, investigate manually; never blindly retry a sealed write or report PASS.

Success marker: `SDK383_RAILWAY_SEALED_E2E=PASS`; absent marker / `BLOCKED` is a failed acceptance gate.

## 2. Full Worker REGISTER → Gateway/Kernel → failed rotation → recovery

Script: `scripts/sdk383_sealed_worker_lifecycle_e2e.py`.

This is a **separate, potentially disruptive** test, available only when a previously provisioned, otherwise unused test Worker already exists in the **same staging project**. The target must be named `sdk383-e2e-...`, with its own `sdk383-e2e-...` plugin ID and `sdk383.e2e....` capability; it must not be any existing RR Scheduler, Economic, RO, Yara or production Worker. The real test Worker must implement the declared capability and expected synthetic fixture. Do **not** add a Worker merely to bypass acceptance gates.

Required trusted runtime environment:

```sh
QDIP_SDK383_E2E_APPROVED=disposable-worker-only
QDIP_PLATFORM_ADMIN_API_KEY=...     # already mounted in the trusted reconciler
RAILWAY_PROJECT_TOKEN=...          # already mounted; staging-scoped
RAILWAY_PROJECT_ID=...             # Railway-injected, exact staging project
RAILWAY_ENVIRONMENT_ID=...         # Railway-injected, exact staging environment
QDIP_SDK383_E2E_WORKER_SERVICE_ID=...     # existing disposable Worker ID
QDIP_SDK383_E2E_WORKER_SERVICE_NAME=sdk383-e2e-...
QDIP_SDK383_E2E_ORG_ID=...         # staging org UUID
QDIP_SDK383_E2E_PLUGIN_ID=sdk383-e2e-...
QDIP_SDK383_E2E_CAPABILITY=sdk383.e2e....
QDIP_SDK383_E2E_SMOKE_JSON='{"...":"synthetic test fixture"}'
```

Invoke `python scripts/sdk383_sealed_worker_lifecycle_e2e.py` after supplying these variables only through the trusted server-side runtime. Missing identity/fixture, preexisting Worker credential, non-isolated service, wrong organization, unrelated Railway stage, or missing live Kernel replay **fails closed**.

The script acquires the real Mongo-backed lease, issues a fenced scoped Worker registration credential, stages/commits it **sealed**, reads back only `isSealed` and the nonsecret key ID, waits for a real deployment, checks its live REGISTER key ID, issues a temporary execute key and invokes Gateway→Worker→Kernel with a replay proof. It then delivers an **invalid** secret under a second issued key ID, verifies the successor does not REGISTER and the previous key remains unrevoked, restores the first secret from memory (not by reading Railway), verifies a fresh REGISTER and smoke, deletes only its test-owned Worker variables, revokes the two test keys through the fenced Core endpoint, and releases its lease. It never reads the sealed value or sends a secret to public reports.

Success marker: `SDK383_SEALED_WORKER_LIFECYCLE_E2E=PASS`.

## Evidence and release decision

Do not combine separate older `RR_STAGING_E2E_SUMMARY=10/10`, `RR_CORE_ORACLE_SUMMARY=9/9`, `RR_S2S_E2E_SUMMARY=7/7`, or the previous 8/8 lease E2E into an invented sealed-delivery PASS. These remain useful regressions, **not** proof of `isSealed:true` stage/commit. Keep PR #623 **BLOCKED** until actual authenticated sealed transport plus live Worker registration/rotation/rollback and independent security review pass. No merge or production credential mutation is part of these scripts.

The scripts intentionally avoid storing raw keys, response payloads, or project tokens in public artifacts. If cleanup is not verified, report `BLOCKED` and inspect the exact staging patch/Worker before further actions.
