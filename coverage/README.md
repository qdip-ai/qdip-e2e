# QDIP E2E requirements and case-mapping baseline

The current **11/11** scope is **RR OIDC signed-session browser contract v1 only**,
derived from `scripts/check_browser_report.py` (required case prefixes) and
`scripts/rr_oidc_session_browser.spec.ts` (implemented browser test titles).

Run:

```sh
python scripts/case_coverage.py --check
python -m unittest discover -s tests -p test_case_coverage.py -v
```

This reports **mapped / required test cases** for the named scope and never
counts passing runs or asserts production readiness. It does **not** define
the denominator of all QDIP E2E requirements. Global coverage stays
`UNKNOWN` until the product and risk acceptance catalog is reviewed.

Test execution success must be measured separately from recent immutable
Core + Web + suite SHA-pinned GitHub Actions results. A successful older
mode must not qualify a failing newer mode. Real Zitadel is distinct from
test-only signed session authorization. The dashboard must retain
`UNKNOWN`, not fabricate a global percent, until an approved global
scope and independent run evidence exist.

Tracking issue: https://github.com/qdip-ai/qdip-e2e/issues/98
