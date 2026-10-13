import assert from 'node:assert/strict';
import test from 'node:test';
import { digestJson, digest, json } from '../definition.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as stages } from '../private-link.mjs';

function prefix(payload) {
  return { version: 1, kind: 'reviewed-private-link-control-chain', planSha256: digest('UNIT plan'), originSha256: digest('UNIT origin'),
    records: stages.slice(0, 13).map((stage, i) => ({ stage, ...(i === 0 ? { payload } : {}) })) };
}
function runtime(evidence) {
  return { version: 1, kind: 'private-link-runtime-completion', controlEvidence: evidence,
    disabled: { kind: 'private-link-disabled-receiver', controlEvidence: evidence },
    intent: { kind: 'private-link-window-intent', controlEvidence: evidence } };
}
function store() {
  const files = new Map();
  const value = createPrivateLinkArtifactStore({ root: 'UNIT-blobs', read: async (directory, name) => JSON.parse(files.get(`${directory}/${name}`)),
    immutable: async (directory, name, bytes) => {
      const key = `${directory}/${name}`;
      if (files.has(key)) throw Object.assign(new Error('UNIT exists'), { code: 'EEXIST' });
      files.set(key, bytes);
    }, update: async (directory, name, bytes) => files.set(`${directory}/${name}`, bytes) });
  return { value, files };
}
test('codec-local byte blocks match native canonical bytes across scalar, Unicode, key-order and shared-depth cases', async () => {
  const shared = { '\ud800': '\udc00', astral: '\u{1f680}', tabs: '\t\r\n\0\b\f', quotes: '"\\', separators: '\u2028\u2029',
    integers: { 20: 'twenty', 1: 'one', z: -0, a: 1e30 }, empty: [], finite: [0, -0, 1.25, 1e-20, Number.MAX_VALUE, true, false, null] };
  const big = { mixed: Array.from({ length: 600 }, (_, i) => ({ i, a: shared, b: [shared, { inner: shared }] })),
    sameAtRoot: shared, deep: [[[[shared]]]], longString: 'unicode \u{1f680}\n"'.repeat(20000) };
  for (const payload of [null, [], {}, shared, big, Object.assign(Object.create(null), { second: shared, first: big })]) {
    const evidence = prefix(payload), input = runtime(evidence), original = json(input), f = store();
    await f.value.immutable('UNIT', 'runtime.json', input);
    const wire = JSON.parse(f.files.get('UNIT/runtime.json'));
    assert.equal(wire.payload.controlEvidence.evidenceSha256, digestJson(evidence));
    assert.equal(wire.payload.controlEvidence.evidenceSha256, digest(json(evidence)));
    assert.equal(json(await f.value.load('UNIT', 'runtime.json')), original);
    assert.equal(json(input), original);
  }
});

test('canonical byte-block replay matches an independent native serializer for deterministic random JSON trees', async () => {
  let seed = 1298147;
  const next = () => (seed = (seed * 1664525 + 1013904223) >>> 0);
  const primitive = () => [null, true, false, -0, (next() % 10000) / 17, `x-${next()}-\u{1f680}-\n-\ud800`][next() % 6];
  const tree = depth => {
    if (!depth || next() % 4 === 0) return primitive();
    const values = Array.from({ length: next() % 6 }, () => tree(depth - 1));
    return next() % 2 ? values : Object.fromEntries(values.map((value, i) => [`key-${i}-${next()}`, value]));
  };
  const f = store();
  for (let i = 0; i < 50; i++) {
    const evidence = prefix(tree(6)), input = runtime(evidence), name = `random-${i}.json`;
    await f.value.immutable('UNIT', name, input);
    assert.equal(JSON.parse(f.files.get(`UNIT/${name}`)).payload.controlEvidence.evidenceSha256, digest(json(evidence)));
    assert.equal(digestJson(await f.value.load('UNIT', name)), digest(json(input)));
  }
});

test('legacy standalone serialization uses a private snapshot and never reuses mutated data across writes', async () => {
  const evidence = prefix({ value: 'before' }), input = runtime(evidence), original = json(input), files = new Map();
  let mutate = true;
  const codec = createPrivateLinkArtifactStore({ root: 'UNIT-blobs', read: async (directory, name) => JSON.parse(files.get(`${directory}/${name}`)),
    immutable: async (directory, name, bytes) => {
      if (mutate) { mutate = false; await Promise.resolve(); evidence.records[0].payload.value = 'after'; }
      const key = `${directory}/${name}`;
      if (files.has(key)) throw Object.assign(new Error('UNIT exists'), { code: 'EEXIST' });
      files.set(key, bytes);
    } });
  await codec.immutable('UNIT', 'first.json', input);
  assert.equal(json(await codec.load('UNIT', 'first.json')), original);
  assert.equal(Object.isFrozen(input), false); assert.equal(Object.isFrozen(evidence), false);
  await codec.immutable('UNIT', 'second.json', input);
  assert.equal(json(await codec.load('UNIT', 'second.json')), json(input));
  assert.notEqual(JSON.parse(files.get('UNIT/first.json')).payload.controlEvidence.evidenceSha256,
    JSON.parse(files.get('UNIT/second.json')).payload.controlEvidence.evidenceSha256);
});

test('private-copy and block hashing cannot admit custom prototypes, cycles or invalid JSON', async () => {
  class Invalid { constructor() { this.value = 1; } }
  for (const invalid of [new Invalid(), new Date(), new Map(), { value: undefined }, { value: Infinity }, { value: () => {} }, { value: 1n }]) {
    await assert.rejects(store().value.immutable('UNIT', 'invalid.json', invalid), /JSON_REQUIRED/);
  }
  const cycle = {}; cycle.self = cycle;
  await assert.rejects(store().value.immutable('UNIT', 'cycle.json', runtime(prefix(cycle))), /JSON_REQUIRED/);
  const f = store(), input = runtime(prefix('unit'));
  input.candidate = input.controlEvidence;
  await assert.rejects(f.value.immutable('UNIT', 'wrong-kind.json', input), /CANDIDATE_SCOPE|CLOSED_INPUT_REQUIRED/);
});

test('formerly over-limit closed standalone recovery shapes use v4 while generic roots remain bounded', async () => {
  const evidence = prefix('UNIT scope model'), candidate = { version: 2,
    profile: { version: 2, kind: 'reviewed-durable-queue-receiver', manifestDigest: 'sha256:' + 'a'.repeat(64), configDigest: 'sha256:' + 'b'.repeat(64) },
    review: {}, legacyPublication: {}, publication: null, priorCandidate: { version: 1 }, topology: {} };
  const window = outcome => {
    const disabled = { kind: 'private-link-disabled-receiver', candidate, controlEvidence: evidence,
      intent: { kind: 'private-link-receiver-create-intent', candidate, controlEvidence: evidence } };
    return { version: 1, kind: 'private-link-runtime-completion', candidate, controlEvidence: evidence, disabled,
      intent: { version: 3, kind: 'private-link-window-intent', disabled, candidate, controlEvidence: evidence }, outcome };
  };
  const failed = window('stopped-disabled-unqualified'), completed = window('qualified-private-delivery-disabled');
  completed.intent = { ...completed.intent, version: 4, continuation: { version: 1,
    kind: 'reviewed-private-link-never-enabled-continuation', original: failed } };
  const record = { version: 3, kind: 'reviewed-private-link-phase', stage: stages[13],
    phase: { version: 1, kind: 'fixed-private-link-control-phase', stage: stages[13], expectedHead: { unitModel: true } }, publication: {}, approval: {},
    preflight: { version: 1, kind: 'checked-private-link-phase', runtimeCompletion: completed }, intent: {},
    intentSha256: digestJson({}), journal: {}, after: {}, deployment: null, operations: null,
    completedAt: '2026-10-03T00:00:00.000Z', authority: {}, recovery: null };
  const original = value => Object.fromEntries(['phase', 'publication', 'approval', 'preflight', 'journal', 'intent'].map(key => [key, value[key]]));
  const late = value => ({ ...value, kind: 'reviewed-private-link-recovery', recovery: { original: original(value),
    proposal: {}, review: {}, costReview: {}, costEvidence: {}, migrationReview: {}, currentPublication: {}, policyRevision: null } });
  const continued = value => ({ ...value, phase: { ...value.phase, continuation: { version: 1,
    kind: 'reviewed-private-link-no-submission-continuation', attemptId: '00000000-0000-4000-8000-000000000099', review: {},
    resolution: { version: 1, kind: 'reviewed-private-link-no-submission', original: original(value),
      proposal: {}, review: {}, observed: {}, publication: {}, costReview: {}, costEvidence: {}, migrationReview: {}, policyRevision: null,
      completedAt: null, qualified: false, successfulChainUnchanged: true, replayAuthorized: false, physicalFenceRetained: true,
      originalHistoryModified: false, resolution: 'terminal-abandoned', resumable: false } } } });
  for (const [name, value, count] of [['ordinary', record, 24], ['late', late(record), 48], ['continued', continued(record), 48]]) {
    const f = store();
    for (const [filename, logical] of [[name + '.json', value], [name + '-resolution.json', { pending: {}, record: value, next: {} }]]) {
      await f.value.immutable('UNIT', filename, logical);
      assert.equal(JSON.parse(f.files.get(`UNIT/${filename}`)).referenceCount, count);
      assert.equal(digestJson(await f.value.load('UNIT', filename)), digestJson(logical));
    }
  }
  for (const value of [continued(continued(record)), late(continued(record))]) {
    const f = store();
    const resolution = { pending: { version: 1, kind: 'private-link-pending-head', targetKey: digest('UNIT target'),
      previous: value.phase.expectedHead, intentSha256: value.intentSha256 }, record: value,
    next: { version: 1, kind: 'private-link-terminal-head', targetKey: digest('UNIT target'), planSha256: evidence.planSha256,
      originSha256: evidence.originSha256, records: 14, stage: value.stage, recordSha256: digestJson(value) } };
    await f.value.immutable('UNIT', 'standalone.json', value);
    await f.value.immutable('UNIT', 'resolution.json', resolution);
    assert.equal(JSON.parse(f.files.get('UNIT/standalone.json')).version, 4);
    assert.equal(JSON.parse(f.files.get('UNIT/resolution.json')).version, 4);
    assert.equal(digestJson(await f.value.load('UNIT', 'standalone.json')), digestJson(value));
    assert.equal(digestJson(await f.value.load('UNIT', 'resolution.json')), digestJson(resolution));
    await assert.rejects(f.value.immutable('UNIT', 'foreign.json', { kind: 'UNIT foreign wrapper', value }), /REFERENCE_LIMIT/);
    const aggregate = { ...evidence, records: [...evidence.records, value] };
    await f.value.immutable('UNIT', 'aggregate.json', aggregate);
    assert.equal(JSON.parse(f.files.get('UNIT/aggregate.json')).version, 3);
    assert.equal(digestJson(await f.value.load('UNIT', 'aggregate.json')), digestJson(aggregate));
  }
});
