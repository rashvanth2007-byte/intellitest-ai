# ---------- build the web UI ----------
FROM node:24-alpine AS build
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
COPY desktop/package.json desktop/package.json
RUN npm ci -w web --include-workspace-root=false --no-audit --no-fund
COPY web web
RUN npm run build -w web

# ---------- runtime ----------
FROM node:24-alpine
ENV NODE_ENV=production \
    ELECTRON_SKIP_BINARY_DOWNLOAD=1 \
    HOST=0.0.0.0 \
    PORT=10000 \
    DATA_DIR=/data
WORKDIR /app
COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY web/package.json web/package.json
COPY desktop/package.json desktop/package.json
RUN npm ci -w server --omit=dev --include-workspace-root=false --no-audit --no-fund && npm cache clean --force
COPY server/src server/src
COPY --from=build /app/web/dist web/dist
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "server/src/index.js"]
