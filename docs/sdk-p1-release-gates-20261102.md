# SDK P1 #399/#407 release-gate evidence — 2026-11-02

Scope: `qdip-ai/qdip-core#621` (third-party developer publication), `qdip-ai/qdip-web#318` (moderator UI), merged Core #622 (offline artifact evidence), and this independent `qdip-e2e` branch.

## Real Railway executions (reusable existing project, disposable QA service)

Project `qdip-sdk-staging`; temporary service `915e434a-990c-43d7-9718-4827a28f4270`, not a new project or sandbox. Only this temporary service was reconfigured; all existing Workers, Gateway, Mongo replica and reconciler remained untouched. Runs pinned to exact Git revisions:

- **Core #621, real MongoDB replica set**: Core SHA `b887c58876bbc9d8261333c9e6e851750c68eb8a` with canonical `qdip-e2e/scripts/sdk_p1_publication_mongo_e2e.py` test source SHA `feee14071f6e137f911d8b425822f0669429161c`. Railway deployment `947ab431-17e5-4489-b561-8fadda94afd4`: **48/48 PASS**, `QDIP_SDK_P1_DISPOSABLE_DB_CLEANUP=PASS`. Includes real Mongo transaction/CAS, domain ownership and rejection, other-org isolation, Core in-process Worker Hub lease CANCEL, and new real Mongo dispatch gate: an authenticated pending publisher, forged clean scanner state, absence of deployment-owned allowlist, and quarantine all fail closed; third-party plugin remains unpublished.
- **Core #621, two independent Uvicorn Gateway processes**: same Core SHA, Railway `2908d234-723a-4ab2-bd21-65cdf7224420`: **17/17 PASS**, independent process startup, anonymous / Worker-only / forged human bearer / wrong-org denial, no Mongo publication/audit writes, isolated DB cleanup PASS. Positive Zitadel human login NOT TESTED.
- **Web #318, moderator BFF**: exact Web SHA `770f13c094dd747b2314a52fa20c2c6167725ea6`, Railway `bfa26fe4-ec33-45f0-b7eb-a5827a1f317c`: `pnpm typecheck` **PASS** + **6/6 Vitest PASS**. These tests use synthetic session/BFF mocks, not real browser authentication.
- **Core dev, merged #622 offline source preflight**: exact dev SHA `ef5a8bad5ad0b9a3cf84ba74a475873934dd559f`, Railway `7e00209c-3cab-4767-a032-d9489b76462b`: **Ruff PASS + 44/44 pytest PASS**. These use synthetic signed scan reports; actual Semgrep/Gitleaks/CycloneDX/OSV/license scans and remote Worker image identity were NOT executed.

## Real Chromium preview: BLOCKED, not UI E2E PASS

The Vercel Preview `https://qdip-jb2lzygml-taras-gezs-projects.vercel.app` is READY at Web SHA `770f13c094dd747b2314a52fa20c2c6167725ea6`. A real Linux Chromium runner in Railway deployed this repository's `Dockerfile.sdk-p1-browser-qa`, Python Playwright script, and navigated `/uk/admin/plugins` at 1440x900, 390x844 and 844x390. Railway deployment `667d7fa5-6169-4c4e-b255-5826aa7f4acc` on browser source SHA `82488a496c17310cdc461e502f279b6f3a9e8ef7`:

- All three viewports navigated to **Vercel Authentication** (`vercel.com`), **not** the QDIP application.
- Three actual screenshots (PNG in the ephemeral container; JPEG encoded in the deployment logs with prefixes `SDK_P1_BROWSER_JPEG_desktop`, `SDK_P1_BROWSER_JPEG_mobile-portrait`, `SDK_P1_BROWSER_JPEG_mobile-landscape`) document the protection page, not UI correctness.
- Runner terminates **CRASHED / BLOCKED** deliberately with `QDIP_SDK_P1_BROWSER_PREVIEW=BLOCKED`; never marks the application E2E PASS. No bypass secret was created, no Vercel protection was removed, no production or real user identity was modified.

To complete the browser gate, use the **existing Vercel authenticated Trusted Sources OIDC development token**, origin-scoped in Playwright, or another approved preview access method. Do not publish that token or disable deployment protection. Once access works, rerun desktop, mobile portrait and landscape **against actual logged-in moderator UI**, save screenshot artifacts, and exercise the queue / reject / suspend on an isolated test submission.

## Release gate

**BLOCKED** for Core #621 and Web #318. The Mongo suite substitutes the human publisher identity and DNS TXT lookup with deterministic boundaries; two-Gateway tests are genuine HTTP but negative-only. A positive real developer Zitadel Application ownership and tenant isolation test is still missing. The third-party **approval/publication path and real scanner/runtime artifact admission are not implemented**; tests cannot certify functionality that does not exist. Browser admin UI was not reached because Vercel deployment protection rejected automation. These are functional release gates, not CI checks to skip. No merge to `dev` and no production deployment is authorized by this evidence.
