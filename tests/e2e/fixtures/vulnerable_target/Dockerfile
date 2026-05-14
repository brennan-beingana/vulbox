# INTENTIONALLY VULNERABLE — VulBox E2E fixture only. Do not deploy.
#
# node:14-alpine is EOL and ships with a known set of base-image CVEs, which
# makes Trivy results deterministic across runs.
FROM node:14-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev || npm install --production

COPY app.js ./

EXPOSE 3000
CMD ["node", "app.js"]
