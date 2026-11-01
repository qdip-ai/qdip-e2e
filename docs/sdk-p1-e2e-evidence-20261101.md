# SDK P1 evidence: staged Gateway, Mongo and Zitadel (2026-11-01)

## Scope and immutable identities

- Core publication PR: qdip-ai/qdip-core#621, latest head `8f352fdb468fc56b4afa400853670d331c378350`; conflict fix `5f72706001c9101a804e22b92971a19030cdf662`.
- Artifact provenance PR: qdip-ai/qdip-core#622; existing Railway regressions `8/8 PASS` on `2a2ac4afde55428c0a8ab519e7e6bce0cd2a5f5b`.
- Independent E2E repo: `qdip-ai/qdip-e2e`, branch `test/sdk-p1-zitadel-preflight-20261101`; scripts are `scripts/sdk_p1_publication_mongo_e2e.py` and `scripts/sdk_p1_two_gateway_e2e.py`.

## Actual Railway evidence

- Real replica-set integration `sdk_p1_publication_mongo_e2e.py`: Railway `qdip-sdk-staging`, ephemeral QA service, deployment `1d45bad8-3598-4b3d-8a11-4554f4840322`. **30/30 PASS** on Core code `e0268cfa363a58fdade6c994bad1b7718d1b0fde` (Railway `22006a24-a7bb-4ce1-a2b1-6dabc21a0660`); transaction write-conflict returned 409 after a reproduced 503 before the fix; single atomic audit; revision CAS, stale revision, org/key isolation and private pending state. Live Zitadel `_verified_publisher` boundary deliberately substituted only for this test. Test creates and drops a separate random `qdip_p1_e2e_*` database.
- Two independent real Uvicorn Core processes and isolated MongoDB `sdk_p1_two_gateway_e2e.py`: deployment `33649b3f-25a9-4b74-90df-4d02d3f1bd45`. **17/17 PASS**, two ports, anonymous / missing human / forged bearer / wrong organization fail closed, no persisted submission or audit, private catalog remains private. Positive human authentication is **NOT TESTED**. Database and processes cleaned.
- RR SDK staging existing actual Scheduler/Economic Workers: QA deployment `f263429d-47eb-49fd-a9e3-9a16c63dc804`. `RR_STAGING_E2E_SUMMARY=10/10`, `RR_S2S_E2E_SUMMARY=7/7`, `RR_CORE_ORACLE_SUMMARY=9/9`. This is existing staging SDK, not #621/#622 admission or publication.
- Real Zitadel existing-account Chromium login: public `qdip-e2e` Actions run `41203968314` job rerun `124993657999`. `LIVE_ZITADEL_REAL_USER_RR_OPERATOR_LOGIN=PASS`, token and userinfo PASS, Core auth boundary and logout revocation PASS. **NOT tested:** wrong-org real human, roleless real human, #621 publisher endpoint, third-party ownership approval.
- Existing Core/public Zitadel preflight from `qdip-e2e`: Railway deployment `19cede31-107c-495e-b1d9-57f686880bf0`, 43 public preflight checks PASS (not real login).

## Strict release gate

These independent successes **do not combine into a single full P1 user journey**. #621 still requires a real Zitadel developer/application/organization binding, domain TXT or well-known verification, reviewer approve/reject/suspend, exact artifact admission, browser publisher/moderator UX, two-org positive and negative end-to-end; #622 requires source/runtime image binding, Semgrep/SBOM/OSV and fail-closed real admission/Worker behavior. There is currently no implementation for several of those transitions, so tests cannot certify them. No merge/production deployment is authorized by these test outcomes alone.

## Isolation

No active Worker/Gateway services were overwritten. Disposable QA containers and databases must be deleted/confirmed after runs. Never publish API keys, live identity tokens or Mongo credentials in E2E reports.

- Latest scoped Web admin queue BFF and moderator UI: qdip-ai/qdip-web#318, SHA `770f13c094dd747b2314a52fa20c2c6167725ea6`; Railway `pnpm typecheck` PASS + Vitest 6/6 PASS. Non-production Vercel preview `dpl_CFyzJSEm6MyBzGN1Cx5ZZ6w9L41k` READY, **authenticated browser / mobile visual E2E NOT TESTED**.
- Expanded offline signed source archive preflight in qdip-ai/qdip-core#622: scanned only syntax/size/integrity; actual Semgrep/OSV/license scanner admission and runtime Worker digest binding remain NOT IMPLEMENTED.
