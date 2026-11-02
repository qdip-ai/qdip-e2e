# One-shot isolated real-browser security qualification.
# Secrets are injected only at deployment; the image never contains credentials.
FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /app
COPY scripts/zitadel_qa21_cross_org_live.mjs ./scripts/zitadel_qa21_cross_org_live.mjs
RUN npm init -y >/dev/null && npm install --no-save --ignore-scripts --no-audit --no-fund @playwright/test@1.56.1 && node --check ./scripts/zitadel_qa21_cross_org_live.mjs
USER pwuser
CMD ["node","/app/scripts/zitadel_qa21_cross_org_live.mjs"]
