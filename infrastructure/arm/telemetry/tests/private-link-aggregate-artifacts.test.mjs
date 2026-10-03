import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { digest, digestJson, json } from '../definition.mjs';
import { load, MAX_PRIVATE_ARTIFACT_BYTES } from '../controller.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as stages } from '../private-link.mjs';

const hash = digestJson, clone = structuredClone, wire = value => JSON.stringify(value) + '\n';
const completionRef = 'private-link-runtime-completion-reference';
const localRef = 'private-link-local-control-prefix-reference';
function prefix() {
  return { version: 1, kind: 'reviewed-private-link-control-chain', planSha256: digest('UNIT plan'), originSha256: digest('UNIT origin'),
    records: stages.slice(0, 13).map(stage => ({ stage, unitSizeOnly: true })) };
}
function candidate(extra = '') {
  return { version: 2, profile: { version: 2, kind: 'reviewed-durable-queue-receiver', manifestDigest: 'sha256:' + 'a'.repeat(64),
    configDigest: 'sha256:' + 'b'.repeat(64), unitPadding: extra }, review: {}, legacyPublication: {}, publication: null,
  priorCandidate: { version: 1 }, topology: {} };
}
function completion(evidence, failed = false) {
  const image = candidate();
  const disabled = { version: 1, kind: 'private-link-disabled-receiver', controlEvidence: evidence, candidate: image,
    intent: { version: 2, kind: 'private-link-receiver-create-intent', candidate: image, controlEvidence: evidence } };
  return { version: 1, kind: 'private-link-runtime-completion', candidate: image, controlEvidence: evidence, disabled,
    intent: { version: 3, kind: 'private-link-window-intent', controlEvidence: evidence, disabled, candidate: image },
    preflight: { current: { unit: 'full-current-proof-slot' } }, requests: [], publicControl: null, enableIntent: null,
    outcome: failed ? 'stopped-disabled-unqualified' : 'qualified-private-delivery-disabled', terminalFalse: true, terminal503: true };
}
function record(stage, runtime) {
  return { version: 3, kind: 'reviewed-private-link-phase', stage,
    phase: { version: 1, kind: 'fixed-private-link-control-phase', stage }, publication: {}, approval: {},
    preflight: { version: 1, kind: 'checked-private-link-phase', runtimeCompletion: runtime },
    intent: {}, intentSha256: digest('UNIT intent'), journal: {}, after: {}, deployment: null, operations: null,
    completedAt: '2026-10-03T00:00:00.000Z', authority: {}, recovery: null };
}
function original(r) {
  return { phase: r.phase, publication: r.publication, approval: r.approval, preflight: r.preflight, journal: r.journal, intent: r.intent };
}
function noSubmission(r) {
  return { version: 1, kind: 'reviewed-private-link-no-submission', original: clone(original(r)), proposal: {}, review: {}, observed: {},
    publication: {}, costReview: {}, costEvidence: {}, migrationReview: {}, policyRevision: null,
    completedAt: '2026-10-03T00:00:00.000Z', qualified: false, successfulChainUnchanged: true, replayAuthorized: false,
    physicalFenceRetained: true, originalHistoryModified: false, resolution: 'terminal-abandoned', resumable: false };
}
function aggregate(count = 5) {
  const head = prefix(), runtime = completion(head);
  return { ...head, records: [...head.records, ...stages.slice(13, 13 + count).map(stage => record(stage, runtime))] };
}
function memory() {
  const files = new Map(), reads = new Map();
  const store = createPrivateLinkArtifactStore({ root: 'UNIT-blobs',
    read: async (dir, name, optional) => {
      const key = `${dir}/${name}`; reads.set(key, (reads.get(key) ?? 0) + 1);
      if (!files.has(key)) { if (optional) return null; throw new Error('UNIT_MISSING_BLOB'); }
      return JSON.parse(files.get(key));
    },
    immutable: async (dir, name, value) => {
      const key = `${dir}/${name}`;
      if (files.has(key)) throw Object.assign(new Error('UNIT_EXISTS'), { code: 'EEXIST' });
      assert.equal(typeof value, 'string'); assert(Buffer.byteLength(value) <= MAX_PRIVATE_ARTIFACT_BYTES);
      files.set(key, value);
    },
    update: async (dir, name, value) => { files.set(`${dir}/${name}`, value); } });
  const get = key => JSON.parse(files.get(key));
  const set = (key, value) => files.set(key, wire(value));
  const envelope = () => get('UNIT/result.json');
  const updateEnvelope = mutate => {
    const value = envelope(); mutate(value); value.payloadSha256 = digest(wire(value.payload)); set('UNIT/result.json', value);
  };
  return { files, reads, store, get, set, envelope, updateEnvelope };
}
function templateEntries(m) {
  return [...m.files.keys()].filter(key => key.startsWith('UNIT-blobs/private-link-completion-template-'));
}
function prefixOf(root) {
  return Object.fromEntries(Object.entries(root).map(([key, value]) => [key, key === 'records' ? value.slice(0, 13) : value]));
}
test('standalone runtime and original candidate/evidence blob bytes retain their frozen v1 hashes', async () => {
  const m = memory();
  await m.store.immutable('UNIT', 'standalone.json', completion(prefix()));
  const expected = {
    'UNIT-blobs/private-link-candidate-fe8f57656930d90d2aefc644f929421e18fc5abdce7e352d20e1e58321aea8df.json': '55bd43ca6f698a3027ecfe9e64d560777be452b9534689ac2e14495c528f503d',
    'UNIT-blobs/private-link-evidence-6f6ff0fcc587a3b672c90992fd784f2c5c501ccbbcdf9dba6fcd006a7fac60a8.json': '1b371fb87f83620db696bdff4fa98e872ed68231c3014884f5bb10240a0fc9cb',
    'UNIT/standalone.json': 'e59fe76617f30ae432a8bef92af7865f78acb071eab4fe38d912456af00f782c',
  };
  assert.deepEqual(Object.fromEntries([...m.files].map(([name, bytes]) => [name, digest(bytes)])), expected);
});

test('root v3 reuses the exact decoded prefix and one completion template across all five full records', async () => {
  const m = memory(), value = aggregate(), before = json(value);
  await m.store.immutable('UNIT', 'result.json', value);
  const envelope = m.envelope(), templates = templateEntries(m);
  assert.equal(envelope.version, 3); assert.equal(envelope.referenceCount, 5);
  assert.equal(envelope.rootSha256, hash(value)); assert.equal(envelope.prefixSha256, hash(prefixOf(value)));
  assert.equal(templates.length, 1); assert.equal(m.files.size, 3);
  assert(![...m.files.keys()].some(key => key.includes('private-link-evidence-')));
  assert(envelope.payload.records.slice(13).every(r => r.preflight.runtimeCompletion.kind === completionRef));
  const template = m.get(templates[0]);
  assert.equal(template.referenceCount, 12);
  assert.equal(template.payload.controlEvidence.kind, localRef);
  const loaded = await m.store.load('UNIT', 'result.json');
  assert.equal(json(loaded), before); assert.equal(json(value), before);
  assert.equal(loaded.records[13].preflight.runtimeCompletion, loaded.records[17].preflight.runtimeCompletion);
  assert.equal(loaded.records[0], loaded.records[13].preflight.runtimeCompletion.controlEvidence.records[0]);
  assert.equal(Object.isFrozen(loaded.records[13].preflight.runtimeCompletion), true);
  assert.equal(Object.isFrozen(value.records[13]), false);
  assert.equal(m.reads.get(templates[0]), 1);
  await m.store.load('UNIT', 'result.json');
  assert.equal(m.reads.get(templates[0]), 2, 'No template trust survives a load operation');
});

test('one prior failed runtime window remains unqualified nested data with the same exact prefix', async () => {
  const value = aggregate(), runtime = value.records[13].preflight.runtimeCompletion;
  const failed = completion(runtime.controlEvidence, true), previous = json(failed);
  runtime.intent.version = 4;
  runtime.intent.continuation = { version: 1, kind: 'reviewed-private-link-never-enabled-continuation',
    original: failed, originalDirectory: 'UNIT-previous', observation: {}, binding: {}, approval: {} };
  const m = memory(); await m.store.immutable('UNIT', 'result.json', value);
  const template = m.get(templateEntries(m)[0]);
  assert.equal(template.referenceCount, 24);
  assert.equal(template.payload.intent.continuation.original.kind, 'private-link-runtime-completion');
  assert.equal(template.payload.intent.continuation.original.outcome, 'stopped-disabled-unqualified');
  const loaded = await m.store.load('UNIT', 'result.json');
  const restored = loaded.records[13].preflight.runtimeCompletion.intent.continuation.original;
  assert.equal(json(restored), previous); assert.equal(restored.intent.version, 3);
  assert.equal(restored.controlEvidence.records[0], loaded.records[0]);
  assert.equal(restored.enableIntent, null); assert.deepEqual(restored.requests, []);
  assert.equal(restored.publicControl, null); assert.equal(hash(loaded), hash(value));
});

test('late recovery and control-continuation original preflights use only exact fixed stage paths', async () => {
  const m = memory(), value = aggregate(), first = value.records[13], continued = value.records[14];
  first.kind = 'reviewed-private-link-recovery';
  first.recovery = { original: clone(original(first)), proposal: {}, review: {}, costReview: {}, costEvidence: {},
    migrationReview: {}, currentPublication: {}, policyRevision: null };
  continued.phase.continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId: randomUUID(),
    resolution: noSubmission(continued), review: {} };
  // The retained prior original must not acquire this new continuation recursively.
  delete continued.phase.continuation.resolution.original.phase.continuation;
  const bytes = json(value);
  await m.store.immutable('UNIT', 'result.json', value);
  const envelope = m.envelope();
  assert.equal(envelope.referenceCount, 7);
  assert.equal(envelope.payload.records[13].recovery.original.preflight.runtimeCompletion.kind, completionRef);
  assert.equal(envelope.payload.records[14].phase.continuation.resolution.original.preflight.runtimeCompletion.kind, completionRef);
  assert.equal(json(await m.store.load('UNIT', 'result.json')), bytes);
  const bad = clone(value); bad.records[14].phase.continuation.resolution.original.phase.stage = 'record-migration';
  await assert.rejects(m.store.immutable('UNIT', 'invalid.json', bad), /AGGREGATE_STAGE/);
});

test('root and prefix key ordering survive exact hash-bound round trips', async () => {
  const value = aggregate();
  const reordered = Object.fromEntries(Object.entries(value).reverse());
  const head = prefixOf(reordered);
  for (const r of reordered.records.slice(13)) r.preflight.runtimeCompletion = completion(head);
  const m = memory(); await m.store.immutable('UNIT', 'result.json', reordered);
  assert.equal(json(await m.store.load('UNIT', 'result.json')), json(reordered));
  const wrong = clone(reordered); wrong.records[13].preflight.runtimeCompletion.controlEvidence = prefixOf(value);
  await assert.rejects(m.store.immutable('UNIT', 'wrong-prefix-order.json', wrong), /LOCAL_PREFIX_CHANGED/);
});

test('new v3 roots require exact complete ordered stages and closed known original/continuation shapes', async t => {
  for (const [name, mutate] of [
    ['unknown root key', value => { value.extra = true; }],
    ['wrong root version', value => { value.version = 3; }],
    ['missing stage', value => { delete value.records[13].stage; }],
    ['reordered stages', value => { [value.records[13], value.records[14]] = [value.records[14], value.records[13]]; }],
    ['extra record', value => { value.records.push(value.records[17]); }],
    ['wrong phase stage', value => { value.records[13].phase.stage = stages[14]; }],
    ['typed preflight cannot fall back', value => { value.records.slice(13).forEach(record => { record.preflight.kind = 'UNIT-unrecognized'; }); }],
    ['unknown record key', value => { value.records[13].unknown = true; }],
    ['unknown completion kind', value => { value.records[13].preflight.runtimeCompletion.kind = 'UNIT-unrelated'; }],
    ['later-record prefix', value => { value.records[13].preflight.runtimeCompletion.controlEvidence.records.push(value.records[12]); }],
    ['foreign prefix', value => { value.records[13].preflight.runtimeCompletion.controlEvidence.planSha256 = digest('UNIT foreign'); }],
    ['wrong target type', value => {
      const runtime = value.records[13].preflight.runtimeCompletion;
      runtime.controlEvidence = clone(runtime.controlEvidence); runtime.controlEvidence.records[0].type = 'UNIT changed';
    }],
  ]) await t.test(name, async () => {
    const m = memory(), value = clone(aggregate()); mutate(value);
    await assert.rejects(m.store.immutable('UNIT', 'result.json', value));
  });
});

test('forged root/template/local-prefix references never bypass full reconstruction and hash checks', async t => {
  for (const [name, modifyRoot, modifyTemplate] of [
    ['root hash', v => { v.rootSha256 = digest('UNIT changed'); }],
    ['root prefix hash', v => { v.prefixSha256 = digest('UNIT changed'); }],
    ['root reference count', v => { v.referenceCount--; }],
    ['root stage', v => { v.payload.records[13].stage = 'assign-queue-role'; }],
    ['completion reference hash', v => { v.payload.records[13].preflight.runtimeCompletion.completionSha256 = digest('UNIT missing'); }],
    ['completion reference bytes', v => { v.payload.records[13].preflight.runtimeCompletion.bytes++; }],
    ['completion reference path', v => { v.payload.records[13].preflight.runtimeCompletion.path = '../elsewhere'; }],
    ['completion reference foreign slot', v => { v.payload.records[13].approval = v.payload.records[13].preflight.runtimeCompletion; }],
    ['completion ref in prefix', v => { v.payload.records[0].untrusted = v.payload.records[13].preflight.runtimeCompletion; }],
    ['inline completion replacing reference', v => { v.payload.records[13].preflight.runtimeCompletion = completion(prefix()); }],
    ['local marker prefix', null, v => { v.payload.controlEvidence.evidenceSha256 = digest('UNIT changed'); }],
    ['local marker extra key', null, v => { v.payload.controlEvidence.records = 13; }],
    ['local marker foreign position', null, v => { v.payload.preflight.current.untrusted = v.payload.controlEvidence; }],
    ['local marker wrong type', null, v => { v.payload.controlEvidence.kind = 'private-link-control-evidence-reference'; }],
    ['inline foreign prefix', null, v => { v.payload.controlEvidence = prefix(); }],
    ['template identity', null, v => { v.completionSha256 = digest('UNIT changed'); }],
    ['template bound prefix', null, v => { v.prefixSha256 = digest('UNIT changed'); }],
    ['template count', null, v => { v.referenceCount--; }],
    ['template missing member', null, v => { delete v.payload.controlEvidence; }],
    ['failed outcome changed', null, v => { v.payload.outcome = 'in-progress'; }],
    ['cycle-like template reference', null, v => { v.payload.preflight.current.loop = { kind: completionRef }; }],
  ]) await t.test(name, async () => {
    const m = memory(); await m.store.immutable('UNIT', 'result.json', aggregate());
    if (modifyTemplate) {
      const path = templateEntries(m)[0], template = m.get(path); modifyTemplate(template);
      template.payloadSha256 = digest(wire(template.payload)); m.set(path, template);
      m.updateEnvelope(value => {
        for (const r of value.payload.records.slice(13)) r.preflight.runtimeCompletion.bytes = Buffer.byteLength(m.files.get(path));
      });
    } else m.updateEnvelope(modifyRoot);
    await assert.rejects(m.store.load('UNIT', 'result.json'));
  });
});

test('local-prefix markers and completion templates cannot leak into standalone/raw/v1/v2 files', async () => {
  const m = memory(); await m.store.immutable('UNIT', 'result.json', aggregate());
  const envelope = m.envelope(), template = m.get(templateEntries(m)[0]), marker = template.payload.controlEvidence;
  for (const value of [marker, template, envelope.payload.records[13].preflight.runtimeCompletion]) {
    await assert.rejects(m.store.immutable('UNIT', 'invalid.json', value), /ALREADY_ENCODED/);
    m.set('UNIT/raw.json', value); await assert.rejects(m.store.load('UNIT', 'raw.json'), /NESTED_REFERENCE/);
  }
  m.set('UNIT/old-envelope.json', { version: 2, kind: 'private-link-artifact-envelope', referenceCount: 1,
    payloadSha256: digest(wire({ kind: 'private-link-runtime-completion', controlEvidence: marker })),
    payload: { kind: 'private-link-runtime-completion', controlEvidence: marker } });
  await assert.rejects(m.store.load('UNIT', 'old-envelope.json'), /NESTED_REFERENCE/);
});

test('blob/reference/node/depth/byte limits remain bounded across root and nested template content', async () => {
  let m = memory(), value = aggregate(1), runtime = value.records[13].preflight.runtimeCompletion;
  runtime.extra = Array.from({ length: 53 }, () => ({ kind: 'private-link-window-intent', candidate: runtime.candidate }));
  await assert.rejects(m.store.immutable('UNIT', 'refs.json', value), /REFERENCE_LIMIT/);
  m = memory(); value = aggregate(5);
  value.records.slice(13).forEach((r, i) => { r.preflight.runtimeCompletion = completion(prefix());
    r.preflight.runtimeCompletion.candidate = candidate('UNIT-distinct-' + i); });
  await assert.rejects(m.store.immutable('UNIT', 'blobs.json', value), /REFERENCE_LIMIT/);
  m = memory(); value = aggregate(1); value.records[13].after = { padding: 'x'.repeat(MAX_PRIVATE_ARTIFACT_BYTES) };
  await assert.rejects(m.store.immutable('UNIT', 'outer.json', value), /ARTIFACT_TOO_LARGE/);
  m = memory(); value = aggregate(2);
  for (const [i, r] of value.records.slice(13).entries()) {
    r.preflight.runtimeCompletion = completion(prefix()); r.preflight.runtimeCompletion.padding = String(i).repeat(34 * 1024 * 1024);
  }
  await assert.rejects(m.store.immutable('UNIT', 'distinct-bytes.json', value), /REFERENCE_BYTES_LIMIT/);
  m = memory(); value = aggregate(1); value.records[13].after.self = value;
  await assert.rejects(m.store.immutable('UNIT', 'cycle.json', value), /DATA_REQUIRED|JSON_REQUIRED/);
  m = memory(); value = aggregate(1);
  let nested = {};
  for (let i = 0; i < 129; i++) nested = { next: nested };
  value.records[13].after = nested;
  await assert.rejects(m.store.immutable('UNIT', 'depth.json', value), /DEPTH_LIMIT|STRUCTURE_LIMIT/);
  m = memory(); value = aggregate(1); value.records[13].after.nodes = Array.from({ length: 4 * 1024 * 1024 }, () => null);
  await assert.rejects(m.store.immutable('UNIT', 'nodes.json', value), /STRUCTURE_LIMIT/);
});

test('64 reference and eight unique blob boundaries count nested local-prefix and candidate references', async () => {
  let m = memory(), value = aggregate(1), runtime = value.records[13].preflight.runtimeCompletion;
  runtime.extra = Array.from({ length: 51 }, () => ({ kind: 'private-link-window-intent', candidate: runtime.candidate }));
  await m.store.immutable('UNIT', 'result.json', value);
  assert.equal(m.envelope().referenceCount + m.get(templateEntries(m)[0]).referenceCount, 64);
  assert.equal(hash(await m.store.load('UNIT', 'result.json')), hash(value));
  m.updateEnvelope(v => { v.referenceCount = 65; });
  await assert.rejects(m.store.load('UNIT', 'result.json'), /ENVELOPE_INVALID/);

  m = memory(); value = aggregate(3);
  for (const [i, r] of value.records.slice(13).entries()) r.preflight.runtimeCompletion = {
    version: 1, kind: 'private-link-runtime-completion', controlEvidence: prefix(), candidate: candidate('UNIT primary ' + i),
  };
  value.records[13].preflight.runtimeCompletion.extra = [0, 1].map(i => ({
    kind: 'private-link-window-intent', candidate: candidate('UNIT additional ' + i),
  }));
  await m.store.immutable('UNIT', 'result.json', value);
  assert.equal([...m.files.keys()].filter(key => key.startsWith('UNIT-blobs/')).length, 8);
  assert.equal(hash(await m.store.load('UNIT', 'result.json')), hash(value));
  value.records[13].preflight.runtimeCompletion.extra.push({ kind: 'private-link-window-intent', candidate: candidate('UNIT ninth blob') });
  await assert.rejects(memory().store.immutable('UNIT', 'too-many.json', value), /REFERENCE_LIMIT/);
});

test('wire-side limits and unsupported original paths reject before trusting a root hash', async () => {
  let m = memory(); await m.store.immutable('UNIT', 'result.json', aggregate(1));
  m.updateEnvelope(value => { value.payload.records[13].after.nodes = Array.from({ length: 4 * 1024 * 1024 }, () => null); });
  await assert.rejects(m.store.load('UNIT', 'result.json'), /STRUCTURE_LIMIT/);
  m = memory(); await m.store.immutable('UNIT', 'result.json', aggregate(1));
  m.updateEnvelope(value => { value.payload.records[13].preflight.runtimeCompletion.bytes = MAX_PRIVATE_ARTIFACT_BYTES; });
  await assert.rejects(m.store.load('UNIT', 'result.json'), /CONTENT_CHANGED|REFERENCE_BYTES_LIMIT/);
  const value = aggregate(1);
  value.records[13].phase.continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation',
    attemptId: randomUUID(), resolution: noSubmission(value.records[13]), review: {} };
  value.records[13].phase.continuation.resolution.extra = {};
  await assert.rejects(memory().store.immutable('UNIT', 'extra-resolution.json', value), /CLOSED_INPUT_REQUIRED/);
  delete value.records[13].phase.continuation.resolution.extra;
  value.records[13].phase.continuation.resolution.original.extra = {};
  await assert.rejects(memory().store.immutable('UNIT', 'extra-original.json', value), /CLOSED_INPUT_REQUIRED/);
  delete value.records[13].phase.continuation.resolution.original.extra;
  let current = value.records[13].phase.continuation.resolution.original;
  for (let index = 0; index < 9; index++) {
    current.phase.continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation',
      attemptId: randomUUID(), resolution: noSubmission(value.records[13]), review: {} };
    current = current.phase.continuation.resolution.original;
    delete current.phase.continuation;
  }
  await assert.rejects(memory().store.immutable('UNIT', 'deep-continuation.json', value), /AGGREGATE_HISTORY_LIMIT/);
});

test('awaited aggregate writes use private stable snapshots rather than freezing or trusting caller mutations', async () => {
  const value = aggregate(), before = hash(value), files = new Map();
  const store = createPrivateLinkArtifactStore({ root: 'UNIT-blobs', read: async (dir, name) => JSON.parse(files.get(`${dir}/${name}`)),
    immutable: async (dir, name, bytes) => {
      await Promise.resolve();
      value.records[13].preflight.runtimeCompletion.outcome = 'UNIT caller changed';
      files.set(`${dir}/${name}`, bytes);
    } });
  await store.immutable('UNIT', 'result.json', value);
  assert.notEqual(hash(value), before);
  assert.equal(Object.isFrozen(value.records[13].preflight.runtimeCompletion), false);
  assert.equal(hash(await store.load('UNIT', 'result.json')), before);
});

test('filesystem template reads remain held, owner-only, non-symlinked and uncached across loads', async t => {
  const dir = join('infrastructure/arm/telemetry/tests', `.aggregate-${randomUUID()}`), root = join(dir, 'blobs');
  await mkdir(root, { recursive: true, mode: 0o700 }); t.after(() => rm(dir, { recursive: true }));
  const store = createPrivateLinkArtifactStore({ root }), value = aggregate();
  await store.immutable(dir, 'result.json', value);
  assert.equal(hash(await store.load(dir, 'result.json')), hash(value));
  const name = (await readdir(root)).find(value => value.startsWith('private-link-completion-template-'));
  const original = await readFile(join(root, name));
  const statValue = await stat(join(root, name));
  assert.equal(statValue.mode & 0o777, 0o600);
  await writeFile(join(root, 'alias.json'), original, { mode: 0o600 });
  await rm(join(root, name)); await symlink('alias.json', join(root, name));
  await assert.rejects(store.load(dir, 'result.json'));
  await rm(join(root, name)); await writeFile(join(root, name), original, { mode: 0o600 });
  assert.equal(hash(await store.load(dir, 'result.json')), hash(value));
  await rm(join(root, name)); await assert.rejects(store.load(dir, 'result.json'));
  assert.equal((await load(dir, 'result.json')).version, 3);
});
