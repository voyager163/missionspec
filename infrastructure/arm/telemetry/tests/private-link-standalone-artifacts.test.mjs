import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, digestJson, json } from '../definition.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as stages } from '../private-link.mjs';
const hash = digestJson, wire = value => JSON.stringify(value) + '\n';
function prefix(recoveries) {
  const value = { version: 1, kind: 'reviewed-private-link-control-chain', planSha256: digest('UNIT plan'), originSha256: digest('UNIT origin'),
    records: stages.slice(0, 13).map(stage => ({ stage })) };
  for (const index of [6, 8].slice(0, recoveries)) {
    const phase = { kind: 'fixed-private-link-control-phase', stage: stages[index],
      continuation: { version: 1, kind: 'reviewed-private-link-no-submission-continuation' } };
    const preflight = { kind: 'checked-private-link-phase', runtimeCompletion: null };
    value.records[index] = { version: 3, kind: 'reviewed-private-link-recovery', stage: stages[index], phase, preflight,
      publication: {}, approval: {}, intent: {}, intentSha256: hash({}), journal: {}, after: {}, deployment: null, operations: null,
      completedAt: '2026-10-03T00:00:00.000Z', authority: {},
      recovery: { original: { phase, preflight, publication: {}, approval: {}, journal: {}, intent: {} } } };
  }
  return value;
}
function fixture(recoveries = 2) {
  const evidence = prefix(recoveries), candidate = { version: 2, profile: { version: 2, kind: 'reviewed-durable-queue-receiver',
    manifestDigest: 'sha256:' + 'a'.repeat(64), configDigest: 'sha256:' + 'b'.repeat(64) },
  review: {}, legacyPublication: {}, publication: null, priorCandidate: { version: 1 }, topology: {} };
  const disabled = { kind: 'private-link-disabled-receiver', candidate, controlEvidence: evidence,
    intent: { kind: 'private-link-receiver-create-intent', candidate, controlEvidence: evidence } };
  const runtime = { version: 1, kind: 'private-link-runtime-completion', candidate, controlEvidence: evidence, disabled,
    intent: { kind: 'private-link-window-intent', candidate, controlEvidence: evidence, disabled },
    extra: Array.from({ length: 9 }, () => ({ kind: 'private-link-window-intent', candidate })) };
  let record = { version: 3, kind: 'reviewed-private-link-phase', stage: stages[13],
    phase: { kind: 'fixed-private-link-control-phase', stage: stages[13], expectedHead: {} },
    preflight: { kind: 'checked-private-link-phase', runtimeCompletion: runtime }, publication: {}, approval: {}, intent: {},
    intentSha256: hash({}), journal: {}, after: {}, deployment: null, operations: null,
    completedAt: '2026-10-03T00:00:00.000Z', authority: {}, recovery: null };
  for (let i = 0; i < 2; i++) {
    const original = Object.fromEntries(['phase', 'publication', 'approval', 'preflight', 'journal', 'intent'].map(key => [key, record[key]]));
    record = { ...record, phase: { ...record.phase, continuation: { version: 1,
      kind: 'reviewed-private-link-no-submission-continuation', attemptId: '00000000-0000-4000-8000-000000000099', review: {},
      resolution: { version: 1, kind: 'reviewed-private-link-no-submission', original, proposal: {}, review: {}, observed: {},
        publication: {}, costReview: {}, costEvidence: {}, migrationReview: {}, policyRevision: null, completedAt: null,
        qualified: false, successfulChainUnchanged: true, replayAuthorized: false, physicalFenceRetained: true,
        originalHistoryModified: false, resolution: 'terminal-abandoned', resumable: false } } } };
  }
  return record;
}
function wrapper(record) {
  const evidence = record.preflight.runtimeCompletion.controlEvidence;
  return { pending: { version: 1, kind: 'private-link-pending-head', targetKey: digest('UNIT target'),
    previous: record.phase.expectedHead, intentSha256: record.intentSha256 }, record,
  next: { version: 1, kind: 'private-link-terminal-head', targetKey: digest('UNIT target'), planSha256: evidence.planSha256,
    originSha256: evidence.originSha256, records: 14, stage: record.stage, recordSha256: hash(record) } };
}
function memory() {
  const files = new Map(), reads = [];
  const store = createPrivateLinkArtifactStore({ root: 'blobs',
    read: async (path, name) => { reads.push(`${path}/${name}`); return JSON.parse(files.get(`${path}/${name}`)); },
    immutable: async (path, name, bytes) => {
      if (files.has(`${path}/${name}`)) throw Object.assign(new Error('UNIT exists'), { code: 'EEXIST' });
      files.set(`${path}/${name}`, bytes);
    } });
  return { files, reads, store };
}
test('legacy 64 includes nested recovery refs and stays byte-identical; 65 selects v4 only for admitted closed roots', async () => {
  const old = fixture(1), modern = fixture(2), f = memory();
  await f.store.immutable('records', 'legacy64.json', old);
  const legacy = JSON.parse(f.files.get('records/legacy64.json'));
  assert.equal(legacy.version, 2); assert.equal(legacy.referenceCount, 63);
  const evidenceBlob = [...f.files].find(([name]) => name.startsWith('blobs/private-link-evidence-v2-'));
  assert.equal(JSON.parse(evidenceBlob[1]).referenceCount, 1);
  assert.equal(digest(f.files.get('records/legacy64.json')), 'ec180fc3a8691592fc6b1c352bc4566440bd1bcf97a8679c345b7d782f28e0bf');
  assert.equal(hash(await f.store.load('records', 'legacy64.json')), hash(old));
  for (const [name, value] of [['modern65.json', modern], ['resolution65.json', wrapper(modern)]]) {
    await f.store.immutable('records', name, value);
    const raw = JSON.parse(f.files.get(`records/${name}`));
    assert.equal(raw.version, 4); assert.equal(raw.referenceCount, 3); assert.equal(raw.completions.length, 1);
    assert.equal(raw.completions[0].content.referenceCount, 21);
    assert.equal(hash(await f.store.load('records', name)), hash(value));
  }
  await assert.rejects(f.store.immutable('records', 'foreign65.json', { foreign: modern }), /REFERENCE_LIMIT/);
  for (const change of [
    r => { r.extra = true; }, r => { r.phase.stage = 'create-environment'; },
    r => { r.phase.continuation.resolution.original.extra = true; },
  ]) {
    const value = structuredClone(modern); change(value);
    await assert.rejects(f.store.immutable('records', 'malformed65.json', value), /CLOSED_INPUT_REQUIRED|AGGREGATE_STAGE/);
  }
});

test('v4 inline tables preserve all fields and enforce local-reference shape, order, hash and exact root position', async t => {
  for (const [name, mutate] of [
    ['root hash', v => { v.rootSha256 = digest('UNIT other'); }],
    ['unknown root field', v => { v.extra = true; }],
    ['local ref duplicate count', v => { v.referenceCount++; }],
    ['local ref foreign path', v => { v.payload.preflight.runtimeCompletion.path = '../foreign'; }],
    ['local ref different hash', v => { v.payload.preflight.runtimeCompletion.completionSha256 = digest('UNIT missing'); }],
    ['local ref misplaced', v => { v.payload.after = v.payload.preflight.runtimeCompletion; }],
    ['inline completion duplicate', v => { v.completions.push(v.completions[0]); }],
    ['inline completion missing', v => { v.completions = []; }],
    ['inline completion extra', v => { v.completions[0].extra = true; }],
    ['inline content hash', v => { v.completions[0].contentSha256 = digest('UNIT changed'); }],
    ['inline content nested local refs', v => { v.completions[0].content.payload.controlEvidence = v.payload.preflight.runtimeCompletion;
      v.completions[0].content.payloadSha256 = digest(wire(v.completions[0].content.payload));
      v.completions[0].contentSha256 = digest(wire(v.completions[0].content)); }],
    ['inline root-v3 reference', v => { v.completions[0].content.version = 3;
      v.completions[0].contentSha256 = digest(wire(v.completions[0].content)); }],
  ]) await t.test(name, async () => {
    const f = memory(); await f.store.immutable('records', 'value.json', fixture());
    const value = JSON.parse(f.files.get('records/value.json')); mutate(value);
    value.payloadSha256 = digest(wire(value.payload)); f.files.set('records/value.json', wire(value));
    await assert.rejects(f.store.load('records', 'value.json'));
  });
});

test('resolution identity and malformed JSON are rejected without scalar trust or prototype laundering', async () => {
  const f = memory(), base = wrapper(fixture());
  for (const mutate of [
    v => { v.pending.intentSha256 = digest('UNIT different'); }, v => { v.pending.previous = { changed: true }; },
    v => { v.next.stage = stages[14]; }, v => { v.next.records = 15; },
    v => { v.next.recordSha256 = digest('UNIT changed'); }, v => { v.unapproved = true; },
  ]) {
    const value = structuredClone(base); mutate(value);
    await assert.rejects(f.store.immutable('records', 'bad.json', value), /STANDALONE_SCOPE|CLOSED_INPUT_REQUIRED/);
  }
  class Bad { constructor() { this.value = 1; } }
  for (const payload of [new Bad(), { value: undefined }, [1, , 3], { value: Symbol('bad') }]) {
    const value = fixture(); value.after = payload;
    await assert.rejects(f.store.immutable('records', 'json.json', value), /JSON_REQUIRED/);
  }
  const cycle = fixture(); cycle.after = cycle;
  await assert.rejects(f.store.immutable('records', 'cycle.json', cycle), /JSON_REQUIRED/);
  let deep = {};
  for (let i = 0; i < 129; i++) deep = { child: deep };
  const value = fixture(); value.after = deep;
  await assert.rejects(f.store.immutable('records', 'depth.json', value), /STRUCTURE_LIMIT/);
});

test('inline completion table membership and first-use ordering are exact, not optional metadata', async () => {
  const value = fixture(), distinct = structuredClone(value.phase.continuation.resolution.original.preflight.runtimeCompletion);
  distinct.outcome = 'UNIT different preserved result';
  value.phase.continuation.resolution.original.preflight = { ...value.phase.continuation.resolution.original.preflight,
    runtimeCompletion: distinct };
  const f = memory(); await f.store.immutable('records', 'value.json', value);
  const raw = JSON.parse(f.files.get('records/value.json'));
  assert.equal(raw.version, 4); assert.equal(raw.completions.length, 2);
  assert.equal(hash(await f.store.load('records', 'value.json')), hash(value));
  raw.completions.reverse(); f.files.set('records/value.json', wire(raw));
  await assert.rejects(f.store.load('records', 'value.json'), /REFERENCE_COUNT_CHANGED/);
});

test('v4 cannot silently promote a formerly valid legacy record even with correctly recomputed hashes', async () => {
  const f = memory(), value = fixture();
  await f.store.immutable('records', 'value.json', value);
  const raw = JSON.parse(f.files.get('records/value.json'));
  raw.payload.phase = raw.payload.phase.continuation.resolution.original.phase;
  value.phase = value.phase.continuation.resolution.original.phase;
  raw.referenceCount = 2; raw.payloadSha256 = digest(wire(raw.payload)); raw.rootSha256 = hash(value);
  f.files.set('records/value.json', wire(raw));
  await assert.rejects(f.store.load('records', 'value.json'), /STANDALONE_SELECTION/);
});

test('invalid JSON is rejected before cloning or native block serialization can erase its shape', async () => {
  class Custom { constructor() { this.x = 1; } }
  const cycle = {}; cycle.self = cycle;
  let deep = {};
  for (let i = 0; i < 129; i++) deep = { next: deep };
  const invalid = [new Custom(), { missing: undefined }, [1, , 3], { bad: NaN }, cycle, deep];
  const originalClone = globalThis.structuredClone;
  let clones = 0;
  globalThis.structuredClone = () => { clones++; throw new Error('UNIT clone must not run'); };
  try {
    for (const value of invalid) await assert.rejects(memory().store.immutable('records', 'bad.json', value), /JSON_REQUIRED|STRUCTURE_LIMIT/);
    assert.equal(clones, 0);
  } finally { globalThis.structuredClone = originalClone; }
});

export { fixture as standaloneBoundaryFixture };
