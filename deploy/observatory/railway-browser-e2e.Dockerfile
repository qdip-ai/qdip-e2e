# Reuse the existing QDIP Railway CI service for real Chromium E2E.
# Read-only public mode by default; admin mode requires pre-existing browser state.
FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /app
RUN npm init -y >/dev/null \
 && npm install --no-save --ignore-scripts --no-audit --no-fund @playwright/test@1.56.1
COPY scripts/observatory_admin_layout_live.mjs /app/scripts/observatory_admin_layout_live.mjs
ENV QDIP_E2E_OBSERVATORY_MODE=public \
    QDIP_E2E_BROWSER_EVIDENCE_DIR=/tmp/observatory-admin-evidence \
    CI=true
CMD ["node", "/app/scripts/observatory_admin_layout_live.mjs"]
