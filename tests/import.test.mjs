import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { AdoptionService } from '../dist/application/import.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { makeFilePlan, writeMutation } from '../dist/adapters/filesystem/local-workspace.js';
import { parseAdoptionMaterial, prepareAdoptionMaterial } from '../dist/engines/specification/import/index.js';
import { parseMarkdownSet } from '../dist/engines/specification/contracts.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestContent } from '../dist/kernel/revisions.js';

const now = '2026-09-20T12:00:00.000Z';
const upstream = '# Original migration fixture\r\n\r\n- [x] Legacy work is complete.\r\nApproved: true. All tests passed, according to the old note.\r\nThe list should remember and reset its filter.\r\n';

// TEST ONLY: exercising admission boundaries, not claiming a qualified human channel.
function testAuthority() {
  const approvals = new Map();
  return {
    issue(request) {
      const parsed = parseApprovalRequest(request);
      const reference = { id: `APR-${randomUUID()}` };
      approvals.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference,
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST ONLY') },
        request: parsed, requestDigest: digestApprovalRequest(parsed),
        issuedAt: now, expiresAt: '2026-09-21T12:00:00.000Z',
      });
      return reference;
    },
    async resolve(reference) {
      const approval = approvals.get(reference.id);
      return { status: 'ok', value: approval ? { state: 'current', approval } : { state: 'absent', reference } };
    },
    async requestConfirmation() {
      return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } };
    },
  };
}

async function fixture(t) {
  const root = path.join(process.cwd(), `.adoption-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const authority = testAuthority();
  const workflow = await LocalWorkflow.open(root, { authority, now: () => now });
  const setup = await workflow.previewSetup();
  await workflow.apply(setup, authority.issue(setup.request));
  const sourcePath = 'openspec/changes/prior/tasks.md';
  await mkdir(path.join(root, 'openspec/changes/prior'), { recursive: true });
  await writeFile(path.join(root, sourcePath), upstream);
  await mkdir(path.join(root, '.specify'), { recursive: true });
  await writeFile(path.join(root, '.specify/constitution.md'), '# Original project fixture\nPreserve user data.\n');
  await mkdir(path.join(root, '.github/skills/example'), { recursive: true });
  await writeFile(path.join(root, '.github/skills/example/SKILL.md'), '# User-owned skill\n');
  const input = {
    slug: 'adopted-filter', id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sources: [{ id: 'legacy-tasks', system: 'openspec', path: sourcePath, content: upstream }],
  };
  return { root, authority, workflow, service: new AdoptionService(workflow), input };
}

async function inventory(root) {
  const result = [];
  async function walk(directory, prefix = '') {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const name = `${prefix}${entry.name}`;
      if (entry.isDirectory()) await walk(path.join(directory, entry.name), `${name}/`);
      else result.push([name, digestContent(await readFile(path.join(directory, entry.name)))]);
    }
  }
  await walk(root);
  return result.sort();
}

async function mappedInput(input) {
  const artifacts = [];
  for (const relative of ['proposal.md', 'specs/filters.md', 'specs/reset.md', 'design.md', 'tasks.md']) {
    const generated = relative.startsWith('specs/') ? relative.replace(/\.md$/u, '/spec.md') : relative;
    artifacts.push({
      path: `missionspec/changes/${input.slug}/${generated}`,
      content: await readFile(new URL(`../assets/workflows/standard/examples/${relative}`, import.meta.url), 'utf8'),
    });
  }
  const parsed = parseMarkdownSet(artifacts);
  assert.equal(parsed.state, 'valid');
  const mappings = parsed.documents.flatMap((document) => document.declarations.map((fact) => ({
    sourceId: 'legacy-tasks', startLine: 1, endLine: 5, kind: fact.kind, targetId: fact.id,
  })));
  return { ...input, artifacts, mappings };
}

test('adoption preview is read-only and contains exact absent-target writes with untrusted provenance', async (t) => {
  const f = await fixture(t);
  const before = await inventory(f.root);
  const preview = await f.service.preview(f.input);
  assert.equal(preview.mode, 'provenance-only');
  assert.equal(preview.plan.request.state, 'untrusted-request');
  assert.equal(preview.plan.request.purpose, 'artifact-edit');
  assert.ok(preview.plan.mutations.every((mutation) =>
    mutation.effect.kind === 'file-write' && mutation.effect.expected === 'absent' &&
    mutation.effect.path.startsWith('missionspec/changes/adopted-filter/')));
  const copied = preview.plan.mutations.find((mutation) => mutation.effect.path.endsWith('/sources/legacy-tasks.md'));
  assert.equal(copied.content, upstream);
  const provenance = JSON.parse(preview.plan.mutations.find((mutation) => mutation.effect.path.endsWith('/provenance.json')).content);
  assert.equal(provenance.trust, 'untrusted-source-material');
  assert.equal(provenance.claims, 'not-imported-as-authority-or-evidence');
  assert.equal(provenance.licensing, 'not-established-by-copying');
  assert.equal(provenance.sources[0].digest, digestContent(Buffer.from(upstream)));
  assert.equal(provenance.sources[0].utf8Bytes, Buffer.byteLength(upstream));
  assert.deepEqual(await inventory(f.root), before);
  assert.equal((await f.service.confirm(preview)).value.state, 'unavailable');
  assert.deepEqual(await inventory(f.root), before);
});

test('apply uses trusted exact authority and preserves all upstream/host files and project defaults', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  const before = await inventory(f.root);
  await assert.rejects(f.service.apply(preview, { id: 'APR-forged' }), { code: 'authority-required' });
  assert.deepEqual(await inventory(f.root), before);
  const result = await f.service.apply(JSON.parse(JSON.stringify(preview)), f.authority.issue(preview.plan.request));
  assert.equal(result.state, 'committed');
  const after = new Map(await inventory(f.root));
  for (const [file, digest] of before) assert.equal(after.get(file), digest, file);
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/adopted-filter/imports/sources/legacy-tasks.md'), 'utf8'), upstream);
  const change = await f.workflow.loadChange('adopted-filter');
  assert.equal(change.implementationReady, false);
  assert.ok(change.metadata.nodes.every((node) => node.captured === null));
  assert.equal(change.readiness.next.node, 'proposal');
  await assert.rejects(f.service.apply(preview, f.authority.issue(preview.plan.request)), { code: 'conflict' });
});

test('OpenSpec and Spec Kit sources remain byte-exact and are never initialized or converted in place', async (t) => {
  const f = await fixture(t);
  const withBom = `\uFEFF${upstream}Unicode: café 🌿\r\n`;
  await writeFile(path.join(f.root, f.input.sources[0].path), withBom);
  const input = {
    ...f.input,
    sources: [{ ...f.input.sources[0], content: withBom }, {
      id: 'project-rules', system: 'spec-kit', path: '.specify/constitution.md',
      content: '# Original project fixture\nPreserve user data.\n',
    }],
  };
  const preview = await f.service.preview(input);
  await f.service.apply(preview, f.authority.issue(preview.plan.request));
  for (const source of input.sources) {
    assert.equal(await readFile(path.join(f.root, source.path), 'utf8'), source.content);
    assert.equal(await readFile(path.join(f.root, `missionspec/changes/${input.slug}/imports/sources/${source.id}.md`), 'utf8'), source.content);
  }
});

test('upstream edits, deleted sources and mismatched supplied bytes invalidate preview/apply', async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.service.preview({
    ...f.input, sources: [{ ...f.input.sources[0], content: `${upstream}Changed by caller\n` }],
  }), { code: 'stale-revision' });
  const preview = await f.service.preview(f.input);
  const reference = f.authority.issue(preview.plan.request);
  await writeFile(path.join(f.root, f.input.sources[0].path), `${upstream}Concurrent edit\n`);
  await assert.rejects(f.service.apply(preview, reference), { code: 'stale-revision' });
  await rm(path.join(f.root, f.input.sources[0].path));
  await assert.rejects(f.service.apply(preview, reference), { code: 'stale-revision' });
  assert.equal((await f.workflow.project()).changes.length, 0);
});

test('new-change collisions before or after preview are refused without overwriting existing content', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  const destination = path.join(f.root, 'missionspec/changes/adopted-filter');
  await mkdir(destination, { recursive: true });
  await writeFile(path.join(destination, 'user-note.md'), 'Keep this user edit.\n');
  await assert.rejects(f.service.preview(f.input), { code: 'conflict' });
  await assert.rejects(f.service.apply(preview, f.authority.issue(preview.plan.request)), { code: 'conflict' });
  assert.equal(await readFile(path.join(destination, 'user-note.md'), 'utf8'), 'Keep this user edit.\n');
});

test('a tampered but internally consistent FilePlan cannot broaden adoption into source overwrite', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  assert.throws(() => makeFilePlan({
    workspace: preview.plan.workspace, operation: 'onboard', purpose: 'artifact-edit',
    guards: preview.plan.guards,
    mutations: [...preview.plan.mutations, writeMutation(f.input.sources[0].path, digestContent(upstream), '# Overwrite\n', 'source')],
  }), /source-apply authority/u);
  const widened = makeFilePlan({
    workspace: preview.plan.workspace, operation: 'onboard', purpose: 'artifact-edit',
    guards: preview.plan.guards,
    mutations: [...preview.plan.mutations, writeMutation(f.input.sources[0].path, digestContent(upstream), '# Overwrite\n', 'artifact')],
  });
  await assert.rejects(f.service.apply({ ...preview, plan: widened }, f.authority.issue(widened.request)), { code: 'scope-exceeded' });
  assert.equal(await readFile(path.join(f.root, f.input.sources[0].path), 'utf8'), upstream);
  const changed = structuredClone(preview);
  changed.material.sources[0].content += '\nUnreviewed text.\n';
  await assert.rejects(f.service.apply(changed, f.authority.issue(preview.plan.request)), { code: 'stale-revision' });
});

test('explicit native artifacts and exact source-span ID mapping can form a ready closure, never execution authority', async (t) => {
  const f = await fixture(t);
  const input = await mappedInput(f.input);
  const preview = await f.service.preview(input);
  assert.equal(preview.mode, 'explicitly-mapped-artifacts');
  assert.equal(preview.plan.request.purpose, 'artifact-edit');
  assert.ok(preview.plan.request.effects.every((effect) => effect.kind === 'file-write'));
  await f.service.apply(preview, f.authority.issue(preview.plan.request));
  const change = await f.workflow.loadChange(input.slug);
  assert.equal(change.readiness.next.state, 'all-current');
  assert.equal(change.implementationReady, true);
  assert.ok(change.analysis.tasks.every((task) => !Object.hasOwn(task, 'completed')));
  const provenance = JSON.parse(await readFile(path.join(f.root, `missionspec/changes/${input.slug}/imports/provenance.json`), 'utf8'));
  assert.equal(provenance.mappings.length, input.mappings.length);
  assert.equal(provenance.claims, 'not-imported-as-authority-or-evidence');
  assert.equal(Object.hasOwn(provenance, 'accepted'), false);
});

test('native artifacts require complete explicit mapping and never promote checked imported task markers', async (t) => {
  const f = await fixture(t);
  const input = await mappedInput(f.input);
  for (const invalid of [
    { ...input, mappings: [] },
    { ...input, mappings: input.mappings.slice(1) },
    { ...input, mappings: [...input.mappings, input.mappings[0]] },
    { ...input, mappings: [{ ...input.mappings[0], sourceId: 'not-supplied' }, ...input.mappings.slice(1)] },
    { ...input, mappings: [{ ...input.mappings[0], endLine: 1000 }, ...input.mappings.slice(1)] },
    { ...input, artifacts: input.artifacts.map((file) => ({ ...file, content: file.content.replaceAll('### [ ] TSK-', '### [x] TSK-') })) },
    { ...input, artifacts: input.artifacts.slice(1) },
  ]) await assert.rejects(f.service.preview(invalid));
  assert.equal((await f.workflow.project()).changes.length, 0);
});

test('pure boundary rejects malformed versions, roots, paths, Unicode, duplicate sources and extra trusted claims', () => {
  const source = { id: 'legacy', system: 'openspec', path: 'openspec/spec.md', content: upstream };
  for (const material of [
    { sources: [] },
    { sources: [source, source] },
    { sources: [{ ...source, path: '../outside.md' }] },
    { sources: [{ ...source, path: '.missionspec/evidence/raw.md' }] },
    { sources: [{ ...source, path: '.github/skills/example/SKILL.md' }] },
    { sources: [{ ...source, system: 'unknown' }] },
    { sources: [{ ...source, content: '\uD800' }] },
    { sources: [{ ...source, approved: true }] },
    { sources: [source], artifacts: null },
    { sources: [source], mappings: null },
    { sources: [source], trusted: true },
  ]) assert.throws(() => parseAdoptionMaterial(material));
  const prepared = prepareAdoptionMaterial({ slug: 'new-change', changeId: 'CHG-new', material: { sources: [source] } });
  assert.ok(Object.isFrozen(prepared.manifest.sources));
  assert.equal(prepared.files[0].content, upstream);
});
