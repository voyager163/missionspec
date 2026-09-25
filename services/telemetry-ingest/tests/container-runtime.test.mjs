import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const dockerfile = await readFile(new URL('../Dockerfile', import.meta.url), 'utf8');
const lock = JSON.parse(await readFile(new URL('../runtime-sources.lock.json', import.meta.url), 'utf8'));
const ignore = await readFile(new URL('../../../.dockerignore', import.meta.url), 'utf8');

test('final runtime genuinely selects minimal pinned closure rather than purging or concealing builder packages', () => {
  const stage = dockerfile.slice(dockerfile.lastIndexOf('\nFROM ') + 1);
  assert(stage.startsWith(`FROM ${lock.identities.runtimeBase}\n`));
  assert.match(stage, /COPY --from=build \/usr\/local\/bin\/node \/usr\/local\/bin\/node/u);
  assert.match(stage, /COPY --from=build \/usr\/local\/LICENSE \/usr\/share\/doc\/node\/LICENSE/u);
  assert.match(stage, /USER 65532:65532/u);
  assert.match(stage, /CMD \["\/usr\/local\/bin\/node", "--no-turbofan", "--no-maglev", "--disable-sigusr1", "dist\/main.js"\]/u);
  assert.doesNotMatch(stage, /^RUN /mu);
  assert.doesNotMatch(stage, /COPY.*(?:\/usr\/local\/lib\/node_modules|\/bin\/sh|\/usr\/bin|\/var\/lib\/dpkg)/u);
  assert.match(stage, /\/app\/runtime-source-handoff\/ \/usr\/share\/doc\/telemetry-runtime\//u);
});

test('build and source handoff use fixed inputs without operator state or verification binaries in the runtime', () => {
  assert.match(dockerfile, /node scripts\/runtime-sources.mjs/u);
  assert.match(dockerfile, /--project-root \/app --download/u);
  for (const file of ['runtime-sources.lock.json', 'scripts/runtime-sources.mjs', 'scripts/container-qualification.mjs']) {
    assert(ignore.includes(`!services/telemetry-ingest/${file}`));
    assert(dockerfile.includes(`COPY services/telemetry-ingest/${file}`) || dockerfile.includes(` services/telemetry-ingest/${file}`));
  }
  for (const file of ['licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md']) {
    assert(ignore.includes(`!${file}`));
    assert(dockerfile.includes(`COPY ${file} `));
  }
  assert(!ignore.includes('!.env'));
  assert(!ignore.includes('!.copilot/'));
  assert.doesNotMatch(dockerfile, /apt-get.*(?:upgrade|purge)|--ignore-unfixed|\.trivyignore/u);
});
