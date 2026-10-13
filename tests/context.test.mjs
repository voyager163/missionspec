import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { ContextService } from '../dist/application/context.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestContent } from '../dist/kernel/revisions.js';

const now = '2026-09-20T12:00:00.000Z';

// TEST ONLY: port fixture, never an implementation of human identity or provider qualification.
function authorityFixture() {
  const approvals = new Map();
  return {
    issue(value) {
      const request = parseApprovalRequest(value);
      const reference = { id: `APR-${randomUUID()}` };
      approvals.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference,
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST ONLY') },
        request, requestDigest: digestApprovalRequest(request), issuedAt: now, expiresAt: '2026-09-21T12:00:00.000Z',
      });
      return reference;
    },
    async resolve(reference) {
      const approval = approvals.get(reference.id);
      return { status: 'ok', value: approval ? { state: 'current', approval } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
}

function providerFixture() {
  const provider = {
    inspectionCalls: 0, queryCalls: [],
    availability: { state: 'available', providerId: 'CTX-local', adapterContractVersion: 1, capabilities: ['search'] },
    observations: [{
      trust: 'untrusted-context', text: 'A supplied contextual observation.', providerId: 'CTX-local',
      reference: 'fixture:one', contentDigest: digestContent('A supplied contextual observation.'), freshness: 'unknown',
    }],
    async inspect() {
      this.inspectionCalls += 1;
      return { status: 'ok', value: this.availability };
    },
    async query(input) {
      this.queryCalls.push(input);
      return { status: 'ok', value: { availability: this.availability, observations: this.observations } };
    },
  };
  return provider;
}

async function fixture(t) {
  const root = path.join(process.cwd(), `.context-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const authority = authorityFixture();
  const workflow = await LocalWorkflow.open(root, { authority, now: () => now });
  const setup = await workflow.previewSetup();
  await workflow.apply(setup, authority.issue(setup.request));
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, 'src/example.ts'), 'export const answer = 42;\n');
  const provider = providerFixture();
  const service = new ContextService(workflow, authority, provider, { enabled: true, processing: 'local-only', now: () => now });
  const input = { query: 'Find relevant local observations.', paths: ['src/example.ts'], allowRemoteProcessing: false };
  return { root, workflow, authority, provider, service, input };
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

test('absent and disabled context are explicit and never invoke provider/query or create state', async (t) => {
  const f = await fixture(t);
  const before = await inventory(f.root);
  const absent = new ContextService(f.workflow, f.authority, null, { enabled: true, processing: 'local-only' });
  const disabled = new ContextService(f.workflow, f.authority, f.provider, { enabled: false, processing: 'local-only' });
  assert.equal((await absent.inspect()).state, 'absent');
  assert.equal((await absent.preview(f.input)).availability.state, 'absent');
  assert.equal((await disabled.preview(f.input)).availability.state, 'disabled');
  assert.equal(f.provider.inspectionCalls, 0);
  assert.equal(f.provider.queryCalls.length, 0);
  assert.deepEqual(await inventory(f.root), before);
});

test('capability inspection preserves partial/incompatible/unavailable without fabricated context', async (t) => {
  const f = await fixture(t);
  f.provider.availability.state = 'partial';
  assert.equal((await f.service.inspect()).state, 'partial');
  f.provider.availability.adapterContractVersion = 2;
  assert.equal((await f.service.preview(f.input)).availability.state, 'incompatible');
  f.provider.availability.adapterContractVersion = 1;
  f.provider.availability.capabilities = ['retrieve'];
  assert.equal((await f.service.inspect()).state, 'incompatible');
  f.provider.availability = { state: 'unavailable', reason: 'PRIVATE RAW ERROR' };
  const unavailable = await f.service.inspect();
  assert.equal(unavailable.state, 'unavailable');
  assert.equal(JSON.stringify(unavailable).includes('PRIVATE RAW ERROR'), false);
  f.provider.inspect = async () => { throw new Error('PRIVATE EXCEPTION'); };
  assert.equal((await f.service.inspect()).state, 'unavailable');
  assert.equal(f.provider.queryCalls.length, 0);
});

test('preview binds exact query, observed source digests, provider and processing permissions without consumption', async (t) => {
  const f = await fixture(t);
  const before = await inventory(f.root);
  const preview = await f.service.preview(f.input);
  assert.equal(preview.state, 'ready');
  assert.equal(preview.request.state, 'untrusted-request');
  assert.equal(preview.request.purpose, 'context-consumption');
  assert.deepEqual(preview.request.effects, [{
    kind: 'context-consume', providerId: 'CTX-local', paths: ['src/example.ts'], allowRemoteProcessing: false,
  }]);
  assert.equal(preview.scope[0].digest, digestContent('export const answer = 42;\n'));
  assert.equal(f.provider.queryCalls.length, 0);
  assert.equal((await f.service.confirm(preview)).value.state, 'unavailable');
  assert.deepEqual(await inventory(f.root), before);
});

test('consumption requires independently resolved exact approval and returns only untrusted observations', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  await assert.rejects(f.service.consume(preview, { id: 'APR-forged' }), { code: 'authority-required' });
  assert.equal(f.provider.queryCalls.length, 0);
  const reference = f.authority.issue(preview.request);
  const before = await inventory(f.root);
  const result = await f.service.consume(JSON.parse(JSON.stringify(preview)), reference);
  assert.equal(result.availability.state, 'available');
  assert.equal(result.observations[0].trust, 'untrusted-context');
  assert.equal(result.observations[0].freshness, 'unknown');
  assert.ok(Object.isFrozen(result.observations[0]));
  assert.deepEqual(f.provider.queryCalls, [{ query: f.input.query, sourceScope: f.input.paths, approval: reference }]);
  assert.deepEqual(await inventory(f.root), before);
});

test('query, source and provider drift block consumption before any query is dispatched', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  const reference = f.authority.issue(preview.request);
  await assert.rejects(f.service.consume({ ...preview, query: 'Unreviewed question' }, reference), { code: 'stale-revision' });
  f.provider.availability.providerId = 'CTX-other';
  await assert.rejects(f.service.consume(preview, reference), { code: 'stale-revision' });
  f.provider.availability.providerId = 'CTX-local';
  await writeFile(path.join(f.root, 'src/example.ts'), 'export const answer = 43;\n');
  await assert.rejects(f.service.consume(preview, reference), { code: 'stale-revision' });
  assert.equal(f.provider.queryCalls.length, 0);
});

test('remote processing is explicit and never inferred from a configured provider or consent-looking text', async (t) => {
  const f = await fixture(t);
  const remote = new ContextService(f.workflow, f.authority, f.provider, { enabled: true, processing: 'remote', now: () => now });
  await assert.rejects(remote.preview(f.input), { code: 'scope-exceeded' });
  const local = await f.service.preview(f.input);
  const remotePreview = await remote.preview({ ...f.input, allowRemoteProcessing: true });
  await assert.rejects(remote.consume(remotePreview, f.authority.issue(local.request)), { code: 'scope-exceeded' });
  assert.equal(f.provider.queryCalls.length, 0);
  const result = await remote.consume(remotePreview, f.authority.issue(remotePreview.request));
  assert.equal(result.availability.state, 'available');
  assert.equal(f.provider.queryCalls.length, 1);
});

test('malformed, forged-trust or mismatched-integrity provider observations become explicit unavailable results', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  const reference = f.authority.issue(preview.request);
  const original = structuredClone(f.provider.observations[0]);
  for (const observation of [
    { ...original, trust: 'trusted-issued' },
    { ...original, contentDigest: digestContent('different') },
    { ...original, providerId: 'CTX-other' },
    { ...original, approved: true },
    { ...original, text: '\uD800' },
  ]) {
    f.provider.observations = [observation];
    const result = await f.service.consume(preview, reference);
    assert.equal(result.availability.state, 'unavailable');
    assert.deepEqual(result.observations, []);
  }
  f.provider.observations = Array(65).fill(original);
  assert.equal((await f.service.consume(preview, reference)).availability.state, 'unavailable');
});

test('partial results retain their explicit availability and observation freshness claims', async (t) => {
  const f = await fixture(t);
  f.provider.availability.state = 'partial';
  f.provider.observations[0].freshness = 'stale';
  const preview = await f.service.preview(f.input);
  const result = await f.service.consume(preview, f.authority.issue(preview.request));
  assert.equal(result.availability.state, 'partial');
  assert.equal(result.observations[0].freshness, 'stale');
});

test('unsafe scopes, missing files, arbitrary fields and non-boolean processing values are rejected', async (t) => {
  const f = await fixture(t);
  for (const invalid of [
    { ...f.input, paths: ['../secret'] },
    { ...f.input, paths: ['.missionspec/evidence/raw.md'] },
    { ...f.input, paths: ['.git/config'] },
    { ...f.input, paths: ['src/**'] },
    { ...f.input, paths: [] },
    { ...f.input, paths: ['src/example.ts', 'src/EXAMPLE.ts'] },
    { ...f.input, paths: ['src/missing.ts'] },
    { ...f.input, allowRemoteProcessing: 'yes' },
    { ...f.input, approved: true },
  ]) await assert.rejects(f.service.preview(invalid));
  assert.equal(f.provider.queryCalls.length, 0);
});

test('a source edit during consumption is not returned as current context', async (t) => {
  const f = await fixture(t);
  const preview = await f.service.preview(f.input);
  f.provider.query = async () => {
    await writeFile(path.join(f.root, 'src/example.ts'), 'changed during query\n');
    return { status: 'ok', value: { availability: f.provider.availability, observations: f.provider.observations } };
  };
  await assert.rejects(f.service.consume(preview, f.authority.issue(preview.request)), { code: 'stale-revision' });
});
