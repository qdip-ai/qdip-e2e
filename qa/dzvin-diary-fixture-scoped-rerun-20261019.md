# Dzvin QA fixture-scoped E2E replay — 2026-10-19

This commit intentionally triggers the branch-scoped workflow
`.github/workflows/dzvin-qa1-qa2-diary-existing-backend.yml` once.

The workflow must first perform exact-window cleanup of failed QA fixtures
created at 2026-10-19T07:38 UTC using two verified QA identities.
No new diary records may be created unless cleanup completes successfully.

Corrected isolated browser E2E suite:
`mentality-prj/mentality-tests@4eeeeede781570cee1ae8d83ae298564ff01c81f`.
Exact Vercel / Render deployment SHAs are bound in the workflow.

Do not treat a successful push, authentication or preflight as a full E2E PASS.
Only a complete authenticated mutation run with verified cleanup qualifies.
