FROM node:24-bookworm-slim AS build
WORKDIR /build
COPY package.json .npmrc tsconfig.json tsconfig.build.json ./
COPY packages ./packages
COPY adapters ./adapters
COPY integrations ./integrations
RUN npm install --ignore-scripts --no-audit --no-fund && npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /opt/shield
COPY --from=build --chown=node:node /build/node_modules ./node_modules
COPY --from=build --chown=node:node /build/dist ./dist
COPY --from=build --chown=node:node /build/package.json ./package.json
COPY --from=build --chown=node:node /build/packages/rule-ir/schema.json ./packages/rule-ir/schema.json
RUN mkdir /data && chown node:node /data
USER node
EXPOSE 8787
STOPSIGNAL SIGTERM
ENTRYPOINT ["node", "dist/packages/cli/main.js"]
CMD ["serve", "/etc/shield/shield.yaml"]
