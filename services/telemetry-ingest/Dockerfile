FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS build
WORKDIR /app/services/telemetry-ingest
COPY services/telemetry-ingest/package.json services/telemetry-ingest/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --cache /app/services/telemetry-ingest/.npm-cache
COPY assets/schemas/telemetry-event.schema.json /app/assets/schemas/telemetry-event.schema.json
COPY services/telemetry-ingest/tsconfig.json ./
COPY services/telemetry-ingest/Dockerfile services/telemetry-ingest/runtime-sources.lock.json ./
COPY LICENSE .dockerignore /app/
COPY services/telemetry-ingest/src ./src
COPY services/telemetry-ingest/schema ./schema
COPY services/telemetry-ingest/scripts/schema.mjs ./scripts/schema.mjs
COPY services/telemetry-ingest/scripts/runtime-sources.mjs ./scripts/runtime-sources.mjs
COPY services/telemetry-ingest/scripts/container-smoke.mjs ./scripts/container-smoke.mjs
COPY services/telemetry-ingest/scripts/container-qualification.mjs ./scripts/container-qualification.mjs
COPY services/telemetry-ingest/tests ./tests
COPY scripts/check-licenses.mjs /app/scripts/check-licenses.mjs
COPY licenses/reviewed-texts.json licenses/telemetry-runtime.json licenses/TELEMETRY_THIRD_PARTY_NOTICES /app/licenses/
RUN npm test
RUN node /app/scripts/check-licenses.mjs --scope service
RUN --mount=type=cache,id=missionspec-runtime-sources,target=/app/runtime-source-cache \
    node scripts/runtime-sources.mjs --lock runtime-sources.lock.json \
    --cache /app/runtime-source-cache --output /app/runtime-source-handoff \
    --project-root /app --download
RUN npm prune --omit=dev --ignore-scripts --no-audit --no-fund --cache /app/services/telemetry-ingest/.npm-cache

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:1ca671d851d5cd39326d095b949a1d4e6ec836f59c5022b21efcd2773bd3a6d5
ENV NODE_ENV=production
WORKDIR /app/services/telemetry-ingest
COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=build /usr/local/LICENSE /usr/share/doc/node/LICENSE
COPY --from=build --chown=65532:65532 /app/runtime-source-handoff/ /usr/share/doc/telemetry-runtime/
COPY --chown=65532:65532 LICENSE ./LICENSE
COPY --from=build --chown=65532:65532 /app/licenses/TELEMETRY_THIRD_PARTY_NOTICES ./THIRD_PARTY_NOTICES
COPY --from=build --chown=65532:65532 /app/licenses/telemetry-runtime.json ./runtime-inventory.json
COPY --from=build --chown=65532:65532 /app/services/telemetry-ingest/package.json ./
COPY --from=build --chown=65532:65532 /app/services/telemetry-ingest/node_modules ./node_modules
COPY --from=build --chown=65532:65532 /app/services/telemetry-ingest/dist ./dist
COPY --from=build --chown=65532:65532 /app/services/telemetry-ingest/schema ./schema
USER 65532:65532
EXPOSE 8080
ENTRYPOINT []
CMD ["/usr/local/bin/node", "--no-turbofan", "--no-maglev", "--disable-sigusr1", "dist/main.js"]
