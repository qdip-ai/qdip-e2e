FROM node:22-alpine
WORKDIR /qa
COPY scripts/dzvin_isolated_railway_mood_20261102.mjs ./qa.mjs
CMD ["node", "qa.mjs"]
