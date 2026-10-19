# Dzvin privacy inventory QA1/QA2, read-only

One-shot branch push to trigger `.github/workflows/dzvin-qa-privacy-inventory-20261019.yml` on the same existing QA browser environment.

Vercel web: `ec4a1875ebc9e6e3300d9728c3859dff88da3d79` READY.
Render develop: `56b954d2fb41e60d8da111d265330d1b273969f4` LIVE.

Must verify anonymous 401; QA1 and QA2 owner-only partial inventory and explicit refusal to enable erasure. No mutation or test fixtures; never print counts, user IDs or tokens.

Results appear in `qdip-e2e#90` as sanitized receipts. No production deployments or extra QA services.
