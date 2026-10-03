import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { parse, stringify } from 'yaml';
import { SkillCatalog, renderSkill, renderSkillSet, skillInvocation } from '../dist/engines/integration/index.js';
import { loadPackagedSkillCatalog } from '../dist/adapters/packaged-assets/skills.js';
import { OPERATION_IDS, OPERATIONS } from '../dist/kernel/registry.js';

const assets = new URL('../assets/', import.meta.url);
const manifestSource = await readFile(new URL('operations/manifest.yaml', assets), 'utf8');
const schemaSource = await readFile(new URL('schemas/operation-manifest.schema.json', assets), 'utf8');
const bodies = Object.fromEntries(await Promise.all(OPERATION_IDS.map(async (id) =>
  [id, await readFile(new URL(`operations/${id}.md`, assets), 'utf8')])));

test('packaged catalog matches runtime registry without reading the current directory', async () => {
  const catalog = await loadPackagedSkillCatalog();
  assert.deepEqual(Object.keys(catalog.manifest.operations), OPERATION_IDS);
  for (const id of OPERATION_IDS) {
    const metadata = catalog.manifest.operations[id];
    assert.equal(metadata.category, OPERATIONS[id].class);
    assert(OPERATIONS[id].engines.includes(metadata.engineOwner));
    assert.equal(catalog.body(id), bodies[id]);
    assert(Object.isFrozen(metadata.handoffs));
  }
});

test('all twelve skills render for each selected host with exact paths and truthful native handoffs', async () => {
  const catalog = await loadPackagedSkillCatalog();
  const rendered = renderSkillSet(catalog, ['copilot', 'codex', 'claude'], '0.0.0');
  assert.equal(rendered.length, 36);
  assert.equal(new Set(rendered.map((skill) => skill.path)).size, 36);
  for (const skill of rendered) {
    const [, headerText, body] = /^---\n([\s\S]*?)---\n\n([\s\S]*)$/.exec(skill.content);
    const header = parse(headerText);
    assert.equal(header.name, `missionspec-${skill.operation}`);
    assert.equal(header.license, 'Apache-2.0');
    assert.equal(header.description, catalog.manifest.operations[skill.operation].description);
    assert.equal(header['user-invocable'], skill.host === 'claude' ? true : undefined);
    assert.equal(header['allowed-tools'], undefined);
    assert.equal(header.mode, undefined);
    assert(!body.includes('{{'));
    assert(body.includes(skillInvocation(skill.host, skill.operation)));
    for (const next of catalog.manifest.operations[skill.operation].handoffs) {
      assert(body.includes(`\`${skillInvocation(skill.host, next)}\``));
    }
  }
  assert.equal(renderSkillSet(catalog, ['codex'], '0.0.0').length, 12);
  assert.deepEqual(renderSkillSet(catalog, [], '0.0.0'), []);
});

test('source schema and registry failures cannot be rendered as valid skills', () => {
  const original = parse(manifestSource);
  for (const mutate of [
    (value) => { delete value.operations.verify; },
    (value) => { value.operations.implement.engineOwner = 'discovery'; },
    (value) => { value.operations.draft.category = 'supporting'; },
    (value) => { value.operations.discover.handoffs = ['unknown']; },
    (value) => { value.operations.discover.description = ''; }
  ]) {
    const changed = structuredClone(original);
    mutate(changed);
    assert.throws(() => SkillCatalog.parse(stringify(changed), schemaSource, bodies));
  }
  assert.throws(() => SkillCatalog.parse(manifestSource, schemaSource, { ...bodies, discover: '{{private}}' }), /rendering token/);
  assert.throws(() => SkillCatalog.parse(manifestSource, schemaSource, { ...bodies, discover: 'no token' }), /rendering token/);
  assert.throws(() => SkillCatalog.parse('schemaVersion: 1\nschemaVersion: 1\n', schemaSource, bodies), /YAML/);
});

test('renderer rejects unsupported hosts, duplicate selections and injected version metadata', async () => {
  const catalog = await loadPackagedSkillCatalog();
  assert.throws(() => renderSkill(catalog, 'vscode', 'draft', '0.0.0'));
  assert.throws(() => renderSkill(catalog, 'codex', 'unknown', '0.0.0'));
  assert.throws(() => renderSkillSet(catalog, ['codex', 'codex'], '0.0.0'), /duplicate/);
  assert.throws(() => renderSkill(catalog, 'codex', 'draft', '0.0.0\nallowed-tools: "*"'));
});

test('catalog and projections are deterministic and bind instruction changes', () => {
  const first = SkillCatalog.parse(manifestSource, schemaSource, bodies);
  const second = SkillCatalog.parse(manifestSource, schemaSource, bodies);
  assert.equal(first.revision, second.revision);
  assert.deepEqual(renderSkill(first, 'copilot', 'draft', '0.0.0'), renderSkill(second, 'copilot', 'draft', '0.0.0'));
  const changed = SkillCatalog.parse(manifestSource, schemaSource, { ...bodies, draft: `${bodies.draft}\nAdditional safe clarification.\n` });
  assert.notEqual(first.revision, changed.revision);
});
