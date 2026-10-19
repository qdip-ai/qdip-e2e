# Dzvin expanded privacy inventory read-only E2E

Branch-bound push triggers `.github/workflows/dzvin-qa-privacy-inventory-20261019.yml` with existing real QA1/QA2 Zitadel secrets.

Existing web preview dpl_GTj2HAr1GTsk2cDk6zFsiWdM1PZy, web SHA ec4a1875ebc9e6e3300d9728c3859dff88da3d79.
Existing Render develop backend LIVE dep-dbav08jrjlhs73d1p2bg, SHA 8734d4c4166d3a91da9fab1e33b03c9bec7bb5dd.

Non-destructive authorization+schema-contract test: 12 direct + 11 related data classes, no user IDs/content logged, never enables deletion. Sanitized result goes to qdip-e2e issue #90.
