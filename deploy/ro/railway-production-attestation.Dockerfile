# One-shot, synthetic-only production RO release verification.
# Reuse an existing Railway QA runner; no public domain, secrets or new services.
FROM node:22-alpine
WORKDIR /app
COPY scripts/ro_production_graph_attestation_live.mjs /app/ro_production_graph_attestation_live.mjs
RUN node --check /app/ro_production_graph_attestation_live.mjs
USER node
CMD ["node", "/app/ro_production_graph_attestation_live.mjs"]
