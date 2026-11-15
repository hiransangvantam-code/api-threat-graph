# Node.js services of the test companies (companies/*/company.yaml with language: node).
# Contains none of the ATG platform's code.
FROM node:20-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY service.js ./
USER 10001
CMD ["node", "service.js"]
