# Claude Code — QDIP independent E2E evidence

**Canonical branch:** `main`. This is a local context entry point, not a new architecture.

## Local rules
Read `README.md`. Signed test-mode OIDC cookies are *not* a live Zitadel browser login. Keep immutable SHA, isolated tenants and negative auth results separate from provider/production evidence. Do not rewrite historical test results or issue fake PASS.

## Shared delivery contract
Read the private QDIP [engineering handover](https://github.com/qdip-ai/qdip-core/blob/dev/docs/handover/README.md) and its DECISIONS_AND_RULES.md, HISTORY.md, OPERATIONS.md and PRODUCT_STATUS.md with authenticated GitHub access. This link is not a copy of the files and does not grant access. Current source, issues, PRs and deployed runtime override dated summaries.

- Execute the literal user request; root cause first, minimal scoped patch. No hacks, duplicated UI or surprise design changes.
- Use real E2E and browser desktop/portrait/landscape for UI (Safari if Safari-specific), screenshot/evidence or explicit NOT VERIFIED.
- Never claim DONE from merge, CI, build or hosting SUCCESS. Merge only after tests/acceptance; verify production after merge. Stop on failed verification.
- Respect security, tenant/app/user authorization, least privilege and existing SDK boundaries. Never expose secrets or personal payloads to prompts/commits/logs.
- Respond concisely in Ukrainian with exact PR/SHA, executed tests and remaining blockers.
