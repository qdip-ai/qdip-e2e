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


## 2026-11-02: independent Railway staging evidence (no production mutation)

- **Sealed transport passed** on pinned E2E source `72e124d11f53c20b6ac859f18d9d05a950198c8d`, disposable one-shot job `c10a14c3-736f-49c4-90c3-aa8290292a20`: `SDK383_RAILWAY_SEALED_STAGE_COMMIT_READBACK=PASS`, QA redeploy `88c4d0ef-a6f5-4d31-82e4-bfe57a7c3958`, `SDK383_RAILWAY_SEALED_ROLLBACK_CLEANUP=PASS`, `SDK383_RAILWAY_SEALED_E2E=PASS`. Final test canaries absent.
- **Initial full lifecycle blocked before issuance** because shared Core staging `7ca9dfd9a62ea3e983f07c50bbdc6075afb10669` lacked the actual Mongo lease API (404). To preserve RR, a separate temporary Gateway was built on Core `bac4e1a1bdeb718626cbe2d54c992d8b5ea53b6b` instead of replacing the shared Gateway. It used the existing staging MongoDB with a separate Core process; it was **not** a separate database.
- The first test against that isolated Gateway, E2E `7c4e954f87a009c8bfb38446a265b9f318369554` in Railway `8977fea5-ff06-4135-b03a-df59c877fb33`, exposed a race in the E2E runner: it checked sealed metadata before the Railway deployment settled. The exact test key was revoked using Core fenced revoke (HTTP 200), Worker variables deleted; no staged patch remained. Fixed by waiting for the new deployment before metadata readback, matching the already-successful transport canary.
- The next run, `9ea05cccb1f7ba0a2b3c1707bba911f75c415b73` / Railway `4a6cb9a4-35e6-413d-81ba-553d401eec37`, confirmed **real sealed Worker key delivery and live REGISTER**. Authenticated invoke returned HTTP 403 because the new test plugin was *not manually reviewed/allowlisted*. This is correct Security Gate denial, not a reason to bypass admission. All issued test keys were revoked and test Worker secrets deleted.
- **Independent credential lifecycle gates passed** on pinned E2E source `8ae9e26472dcd55fa1683e1a6401d7fee1df33c3`, actual Railway runner `6c878bd4-cb27-481d-addd-d781eb086d39`:
  - `SDK383_SEALED_WORKER_REGISTER=PASS` (new scoped first key, committed sealed and verified REGISTERED)
  - `SDK383_SEALED_FAILED_ROTATION_PRESERVES_KEY=PASS` (invalid successor does not REGISTER or prematurely revoke first key)
  - `SDK383_SEALED_WORKER_RECOVERY=PASS` (original key restored from in-memory value; new live REGISTER)
  - `SDK383_UNAPPROVED_DISPATCH_DENIED=PASS` (real Gateway HTTP 403)
  - **Overall** `SDK383_SEALED_WORKER_LIFECYCLE_E2E=BLOCKED:Manual Worker security admission is required before Kernel smoke`. This is a failed full-release gate; no Gateway→Kernel replay PASS is claimed.
- The runner finally block used the exact two test-owned Railway variable names and fenced Core revocations (HTTP 200), released its lease and left no Worker key variables or staged changes. The test Worker source and original WSS URL were preserved for future work. Both temporary services `sdk383-e2e-lifecycle-runner` and `sdk383-e2e-core-gateway` were removed from staging; no volumes attached. The permanent dedicated Worker `sdk383-e2e-credential-worker` was retained without credentials, as requested.
- **Remaining acceptance**: an authorized security reviewer must inspect the exact pinned first-party Worker and its persisted registration digest; explicitly approve its narrow staging-only risk/manifest using the existing `/api/v1/plugin-publications/{plugin_name}/security/approve` contract and deploy its exact digest via `QDIP_TRUSTED_REMOTE_MANIFESTS` on the isolated Gateway, then rerun signed Gateway→Worker→frozen Kernel smoke and verify manifest/replay plus final cleanup. No test should silently set `risk_acknowledged=true` or directly patch MongoDB to fake this state. The shared Core staging deployment and RR Workers must remain untouched.


## 2026-11-02: Security admission preflight and hardened Kernel proof gate

This is a **technical source review, not an operator security approval or risk acceptance**. Independent reviewer sign-off is still missing; do not call `/security/approve` or set `risk_acknowledged=true` from automated test code.

### Exact reviewed inputs

- Worker source: `qdip-ai/qdip-core@ffac08fea89c03e76f85e569cefc79dbde6eba53`. Native RR scheduling source `packages/rr_sdk02_worker/rr_spec.py` (blob `18b36e938a18714305c58ca7a2c12ad4260a226e`), `wire_contracts.py` (blob `4f1c9417c762bd428de8249c09b7ebe9ccd9ed78`), SDK transport `packages/qdip_remote_sdk/src/qdip_remote_sdk/worker.py` (blob `3282aac50ea440679af42b65c99c48931a0828a9`), Dockerfile (blob `7a2524cd31eb4e6eba1048856045ebfaa65bdef0`).
- Dockerfile runs as `USER worker` (non-root), bundles the narrow SDK handler, and does not copy the Core solver or DB client. SDK validates WSS/loopback URL policy; `rr_spec.make_spec` performs strict Pydantic validation, bans caller-provided `decision_id`, bounds technicians/jobs/horizon/variables/constraints/terms, and only produces a DecisionSpec.
- Existing successful live gates on `8ae9e26472dcd55fa1683e1a6401d7fee1df33c3`: real REGISTER, failed successor rotation preserving predecessor, restoration of original key, denied unapproved invoke (HTTP 403), fenced revocation, Worker secret deletion, and no staged Railway changes.
- **Supply-chain and admission caveats:** `FROM python:3.12-slim` is a moving tag; SDK build dependencies permit `setuptools>=68` and runtime `websockets>=14,<17` rather than immutable package hashes. A pinned Git commit alone therefore does not attest the exact built image or SBOM. The Gateway's `registration_digest` is a *contract digest including Worker key ID*, not a runtime image signature; it changes with a replacement key. Never reuse a previous approval/digest after key rotation. These are review findings requiring an explicit risk decision and artifact provenance evidence, not reasons to bypass admission.
- The signed-off exact digest must be read from the **currently persisted and live** registration via `GET /api/v1/plugin-publications/remote-admission-preflight`, inspected against the scoped key and manifest, deployed only to the isolated test Gateway's `QDIP_TRUSTED_REMOTE_MANIFESTS`, and then passed to the Gateway's audited `POST /api/v1/plugin-publications/{plugin_name}/security/approve` with a genuine actor, review reference and explicit risk acknowledgement. Approval must match the *post-rollback* registered key; approval on a previous randomly issued key cannot qualify a new run.
- **No manual approval was performed in this turn.** No external party has signed off the test Worker, so the positive Gateway→frozen Kernel path remains **BLOCKED**. Retain scoped credentials and clean up whenever a live operator-approved smoke is completed; do not leave test keys active merely to get a green result.

### False-positive smoke regression fixed

The original SDK383 smoke accepted `INFEASIBLE` as success and any dictionary (even `{}`) as a replay contract. On E2E commit `1f14b2bfa45fcf6b1d203fb93ee08509a35dd47d`, `assert_kernel_proof` now requires:
- `semantic_status=EXACT`, `backend_status=OPTIMAL`, nonempty `solution` and non-null `objective_value`;
- matching nonempty execution/decision IDs in execution result and server manifest;
- valid SHA-256-shaped `ir_hash` and `decision_spec_hash` agreeing between manifest and replay, plus matching decision/IR identity;
- frozen compiler `qdip-runtime-compiler.v1` and runtime `qdip-runtime-kernel.v1` identifiers.

Five focused unit regressions cover accepted exact proof; false success from INFEASIBLE, empty replay, mismatched hash and absent objective. Existing 11 guardrails remain. The independent Railway QA service used `deploy/sdk383-sealed-e2e-qa.Dockerfile` pinned to `1f14b2bfa45fcf6b1d203fb93ee08509a35dd47d`. Actual deployment `a2b0718e-62ff-4d7d-9255-40b380c5c788`: **build SUCCESS**, runtime `SDK383_E2E_STATIC_GUARDRAILS_PASS`. The pre-fix regression build on `71136b1bc981977dc9ddca5f0f45be97cdf13009` was FAILED; its full failure text was not available from Railway logs, so do not claim a specific recorded traceback. The temporary `sdk383-e2e-proof-regression-qa` service was removed afterward; no volume or secret was created.

**Acceptance boundary:** the added proof assertions have been tested with synthetic cases and real Railway build/runtime, **not** with an admitted positive Gateway→Kernel response. Keep PR #114 Draft until signed-off Security Gate admission and real live solve/replay proof pass on the exact PR SHA.
