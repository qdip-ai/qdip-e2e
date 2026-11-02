# Existing QDIP Railway sandbox: real Chromium against current AutoDev staging.
# No backend mocks, no login credentials, no paid inference, no new service.
FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /app
RUN npm init -y >/dev/null \
 && npm install --no-save --ignore-scripts --no-audit --no-fund @playwright/test@1.56.1
COPY scripts/autodev_recovery_browser.mjs /app/scripts/autodev_recovery_browser.mjs
RUN node --check /app/scripts/autodev_recovery_browser.mjs
ENV QDIP_E2E_AUTODEV_MODE=smoke \
    QDIP_E2E_BROWSER_EVIDENCE_DIR=/tmp/autodev-browser-evidence \
    CI=true
CMD ["node", "/app/scripts/autodev_recovery_browser.mjs"]
