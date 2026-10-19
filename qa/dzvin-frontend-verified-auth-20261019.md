# Dzvin QA1/QA2 — verified-auth frontend E2E

Trigger branch-bound E2E with existing Zitadel QA secrets.

Vercel: dpl_BsbruPDQiv6PnHeuQzspQ7raXaRZ, READY, commit 6622a7b213cc6f47c72380c544c02e0c80d0aa65.
Backend: mentality-back-develop LIVE 9367147682caa5c8226519da38403c4b020fb4eb.

Previous E2E test (08:39 UTC) was FAIL (no native dialog), but its own marked fixture teardown PASS. New frontend handles confirmation within user gesture and resolves server-authenticated user only after confirmation.

The test may only mutate UUID-tagged records for the dedicated QA accounts; require final teardown PASS. No deployment to dzvin.co and no new QA backend.
