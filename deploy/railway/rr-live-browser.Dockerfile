# One-shot, no-secrets real-browser acceptance on the existing Railway sandbox.
# Not the full isolated Core/Web authenticated RR matrix.
FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /e2e
COPY scripts/rr_live_observatory_browser_railway.mjs ./scripts/
RUN npm install --no-audit --no-fund --no-save playwright@1.56.1
CMD ["node", "scripts/rr_live_observatory_browser_railway.mjs"]
