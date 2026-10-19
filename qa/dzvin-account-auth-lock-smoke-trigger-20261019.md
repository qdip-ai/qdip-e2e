# Dzvin account erasure auth-lock compatibility smoke

Trigger branch-bound QA1/QA2 read-only auth check on existing Render dev SHA `2d50bd63dd0d9b58b02ade8d119b403b4ecfb52c` (LIVE, deploy `dep-dbavgdjm8hqs73breqbg`). Existing Vercel preview `dpl_GTj2HAr1GTsk2cDk6zFsiWdM1PZy` and its fixed SHA `ec4a1875ebc9e6e3300d9728c3859dff88da3d79`.

Prove active QA accounts still authenticate and read owned privacy inventory; anonymous denied; erasure remains blocked. Does not mutate lifecycle state or test locked users. Sanitized result posts to `qdip-e2e#90`.
