## Yara: independent browser E2E

**Single browser owner:** [qdip-e2e](https://github.com/qdip-ai/qdip-e2e), manual
workflow `Yara centralized real-browser E2E`. Yara's own Railway
`qdip-ci-sandbox-yara` is for build, unit tests and disposable PostgreSQL.
No new E2E service, copy of test cases or Actions in the private Yara repository.

The workflow owns its browser tests directly in this repository:
`scripts/yara-playwright.config.cjs` and `scripts/yara-browser.spec.cjs`.
It installs a pinned isolated Playwright runner, without checking out the
private Yara repository or requiring `QDIP_READ_TOKEN`. The selected 40-character
Yara SHA is **an attestation input**, not proof of what production runs:
`scope=full` compares it to the deployed isolated QA application's
`/api/build-identity` response before executing authenticated tests.

1. `scope=public`: run anonymous login/privacy page smoke and overflow on
   desktop 1440x900, portrait 390x844 and landscape 844x390 in Chromium and
   Linux WebKit. By default target `https://yara.qdip.ai`. **This does not
   prove the unmerged source SHA was deployed**; it is never merge evidence.
   Login screenshots of the anonymous screen are retained for 7 days.
2. `scope=full`: only the verified existing QA hostname
   `https://yara-qa-web-sandbox.up.railway.app` is accepted, to prevent
   submitting a real Zitadel test identity to an attacker-owned Railway URL.
   Require an exact-SHA deployment at that isolated QA URL, plus its
   server-side `GET /api/build-identity` JSON `{"sha":"<SHA>"}` identical
   to checked-out commit. Fail closed if the endpoint, QA deployment or SHA is
   missing. Requires the already-existing encrypted `QDIP_E2E_ZITADEL_TEST_LOGIN`
   and `QDIP_E2E_ZITADEL_TEST_PASSWORD` secrets in `qdip-e2e`. A single
   **real Zitadel browser login** produces an ephemeral private Playwright
   storage state; no signed-cookie fixtures, credentials in code, or fake login.
   Runs the complete twelve-case browser matrix, including read-only Today,
   Tasks, Plans navigation and screenshots.
3. The full gate is **BLOCKED until the isolated QA Yara Web/API is available
   at the candidate SHA and serves build identity**. Browser storage state is
   stored only in the ephemeral runner; no session or authenticated screenshots
   are published by this **public** repository. Screenshot proof for signed-in
   UI needs a separately approved private artifact destination. Sanitized
   outcome counts are printed; raw stdout and Playwright JSON are ephemeral.
4. WebKit on Linux is **not native Safari**. A Safari-specific issue requires
   additional native macOS/iOS Safari validation.

Do not merge Yara PR solely because `scope=public` passed or browser code was
installed; the exact-SHA full gate and private visual evidence are separate.
