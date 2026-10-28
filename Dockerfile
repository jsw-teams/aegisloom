FROM node:24-bookworm-slim AS build
WORKDIR /build
COPY package.json .npmrc tsconfig.json tsconfig.build.json ./
COPY scr ./scr
COPY tools/bootstrap.mjs tools/run.mjs tools/clean-build.mjs tools/copy-seclang-assets.mjs ./tools/
RUN npm install --ignore-scripts --no-audit --no-fund && node tools/bootstrap.mjs && npm run build

FROM node:24-bookworm-slim AS dependencies
WORKDIR /dependencies
COPY package.json .npmrc ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund

FROM node:24-bookworm-slim
WORKDIR /opt/shield
COPY --from=dependencies --chown=node:node /dependencies/node_modules ./tools/node_modules
COPY --from=build --chown=node:node /build/tools/.build ./tools/.build
COPY --chown=node:node package.json config.yml ./
COPY --chown=node:node rules ./rules
COPY --chown=node:node origin ./origin
COPY --chown=node:node respond ./respond
RUN mkdir -p secret tools/.state && chown node:node secret tools/.state
USER node
EXPOSE 8787
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "tools/.build/scr/cli/main.js"]
CMD ["serve", "config.yml"]
