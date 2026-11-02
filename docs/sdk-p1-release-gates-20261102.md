# SDK P1 #399/#407 release-gate evidence — 2026-11-02

Scope: `qdip-ai/qdip-core#621` (third-party developer publication), `qdip-ai/qdip-web#318` (moderator UI), merged Core #622 (offline artifact evidence), and this independent `qdip-e2e` branch.

## Real Railway executions (reusable existing project, disposable QA service)

Project `qdip-sdk-staging`; temporary service `915e434a-990c-43d7-9718-4827a28f4270`, not a new project or sandbox. Only this temporary service was reconfigured; all existing Workers, Gateway, Mongo replica and reconciler remained untouched. Runs pinned to exact Git revisions:

- **Core #621, real MongoDB replica set**: Core SHA `b887c58876bbc9d8261333c9e6e851750c68eb8a` with canonical `qdip-e2e/scripts/sdk_p1_publication_mongo_e2e.py` test source SHA `feee14071f6e137f911d8b425822f0669429161c`. Railway deployment `947ab431-17e5-4489-b561-8fadda94afd4`: **48/48 PASS**, `QDIP_SDK_P1_DISPOSABLE_DB_CLEANUP=PASS`. Includes real Mongo transaction/CAS, domain ownership and rejection, other-org isolation, Core in-process Worker Hub lease CANCEL, and new real Mongo dispatch gate: an authenticated pending publisher, forged clean scanner state, absence of deployment-owned allowlist, and quarantine all fail closed; third-party plugin remains unpublished.
- **Core #621, two independent Uvicorn Gateway processes**: same Core SHA, Railway `2908d234-723a-4ab2-bd21-65cdf7224420`: **17/17 PASS**, independent process startup, anonymous / Worker-only / forged human bearer / wrong-org denial, no Mongo publication/audit writes, isolated DB cleanup PASS. Positive Zitadel human login NOT TESTED.
- **Web #318, moderator BFF**: exact Web SHA `770f13c094dd747b2314a52fa20c2c6167725ea6`, Railway `bfa26fe4-ec33-45f0-b7eb-a5827a1f317c`: `pnpm typecheck` **PASS** + **6/6 Vitest PASS**. These tests use synthetic session/BFF mocks, not real browser authentication.
- **Core dev, merged #622 offline source preflight**: exact dev SHA `ef5a8bad5ad0b9a3cf84ba74a475873934dd559f`, Railway `7e00209c-3cab-4767-a032-d9489b76462b`: **Ruff PASS + 44/44 pytest PASS**. These use synthetic signed scan reports; actual Semgrep/Gitleaks/CycloneDX/OSV/license scans and remote Worker image identity were NOT executed.

## Historical Vercel preview failure — superseded by Railway-local browser QA

The Vercel Preview `https://qdip-jb2lzygml-taras-gezs-projects.vercel.app` is READY at Web SHA `770f13c094dd747b2314a52fa20c2c6167725ea6`. A real Linux Chromium runner in Railway deployed this repository's `Dockerfile.sdk-p1-browser-qa`, Python Playwright script, and navigated `/uk/admin/plugins` at 1440x900, 390x844 and 844x390. Railway deployment `667d7fa5-6169-4c4e-b255-5826aa7f4acc` on browser source SHA `82488a496c17310cdc461e502f279b6f3a9e8ef7`:

- All three viewports navigated to **Vercel Authentication** (`vercel.com`), **not** the QDIP application.
- Three actual screenshots (PNG in the ephemeral container; JPEG encoded in the deployment logs with prefixes `SDK_P1_BROWSER_JPEG_desktop`, `SDK_P1_BROWSER_JPEG_mobile-portrait`, `SDK_P1_BROWSER_JPEG_mobile-landscape`) document the protection page, not UI correctness.
- Runner terminates **CRASHED / BLOCKED** deliberately with `QDIP_SDK_P1_BROWSER_PREVIEW=BLOCKED`; never marks the application E2E PASS. No bypass secret was created, no Vercel protection was removed, no production or real user identity was modified.

**Superseded:** this blocked Vercel Preview test runner and its Dockerfile have been removed from this PR. The replacement Railway-local production Next.js + Chromium runner exercises the exact Web #318 SHA without accessing Vercel. It verified desktop 1440×900, portrait 390×844 and landscape 844×390, anonymous 401, moderation reason, 409 conflict and horizontal overflow. Evidence: existing Railway deployment `12aac9ce-16df-4526-826c-3ef00d6a8867`, source `5b415607c6204085ba2d77358dfdb2fa4f3a247c`. These tests use a disposable signed QA cookie and intercepted Core fixture; they do **not** prove real Zitadel-to-Core moderation or public release.

## Release gate

**BLOCKED** for Core #621 and Web #318. The Mongo suite substitutes the human publisher identity and DNS TXT lookup with deterministic boundaries; two-Gateway tests are genuine HTTP but negative-only. A positive real developer Zitadel Application ownership and tenant isolation test is still missing. The third-party **approval/publication path and real scanner/runtime artifact admission are not implemented**; tests cannot certify functionality that does not exist. Browser admin UI was not reached because Vercel deployment protection rejected automation. These are functional release gates, not CI checks to skip. No merge to `dev` and no production deployment is authorized by this evidence.


## 2026-11-02 — verified global public-slug ownership (#407)

**Root cause**: Core validated `slug` syntax but did not reserve it in the shared `plugin_publication_slugs` collection. Two independently verified Zitadel-bound developer organizations could submit the same public slug; an abandoned/rejected draft could also leave an unclaimable reservation.

- **RED**: qdip-e2e commit `d1a8b536589315cc3bc5e226f212d2064e626529` against Core `00e7c899a09fc766f60c11091c1992b8ed74b33b`, Railway `abf3d3e4-0ff5-483c-97e3-1016af46c389` **CRASHED**, missing expected global slug reservation (`NoneType` access at `verified_headless_slug_claimed`), all prior checks passed and disposable DB was dropped.
- **Minimal Core fix**: `13396e5e51b2eb5d3926342d37b8d19965943a30` reserves a slug in the *existing canonical collection*, transactionally and only after the trusted publisher check: immediately for a headless Worker, or in the same transaction as successful DNS verification for hosted applications. An unverified URL cannot preempt a slug. Requests to reuse another plugin's slug fail 409; revised/rejected private proposals release only their provisional reservation, while published canonical slugs and historical aliases remain owned. Existing domain and tenant CAS logic is unchanged.
- **GREEN full real Mongo suite**: canonical fixture `c9dfe8abfa83c292c1e473e663dcdf787e1d3cb1`, Git blob `130ce7ee5f8a3a20cef609d99d4c614e1a5a5f88`, Core SHA `f792a6cd74708c865de962e6b70c34604012bc19`, Railway `d33e8836-9e3a-4d37-8b5b-8398ec94a67f`: **58/58 PASS**, `QDIP_SDK_P1_DISPOSABLE_DB_CLEANUP=PASS`. Covers distinct owner claims, concurrent claims (exactly one winner), slug reassignment, rejection, URL proof gating, published slug retention, and plugin identity shadowing.
- **Scoped Core quality**: Core SHA `24a7fcd0daae67a91b653f402b5313051370ffd8` (identical Core code; later commit only repins canonical E2E fixture), Railway `5e3588cb-dcc1-4fab-a230-fb4201a78077`: **Ruff PASS, 17 pytest PASS + 10 subtests**.
- **Two independent live Gateway processes**: exact final Core SHA `f792a6cd74708c865de962e6b70c34604012bc19`, Railway `c1798834-e54e-464e-bec6-873d41fc633d`: **17/17 HTTP E2E PASS**, isolated database and child-process cleanup PASS. Actual positive human Zitadel remains untested.

These results close the global-slug race/ownership defect, **not** the overall #407 developer-to-approved-catalog journey. Independent actual Semgrep/SBOM/OSV runtime attestation, positive Zitadel application ownership and verified authenticated Observatory browser E2E are still **BLOCKED**. No security bypass was introduced, no production mutation or merge executed.
