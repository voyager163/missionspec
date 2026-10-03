import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { load, saveImmutable, MAX_PRIVATE_ARTIFACT_BYTES } from '../controller.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from '../private-link.mjs';
import { digest, digestJson, json } from '../definition.mjs';
import { verifyPrivateLinkControlEvidence } from '../private-link-controller.mjs';

function evidence(extra = '') {
  return { version: 1, kind: 'reviewed-private-link-control-chain',
    planSha256: digest('UNIT plan'), originSha256: digest('UNIT origin'),
    records: PRIVATE_LINK_CONTROL_STAGES.slice(0, 13).map((stage, index) => ({ stage, unit: true,
      ...(index === 0 ? { extra } : {}) })) };
}
function completion(controlEvidence) {
  return { version: 1, kind: 'private-link-runtime-completion', controlEvidence,
    disabled: { kind: 'private-link-disabled-receiver', controlEvidence,
      intent: { kind: 'private-link-receiver-create-intent', controlEvidence } },
    intent: { kind: 'private-link-window-intent', controlEvidence,
      disabled: { kind: 'private-link-disabled-receiver', controlEvidence,
        intent: { kind: 'private-link-receiver-create-intent', controlEvidence } } } };
}
function candidate(padding = '') {
  return { version: 2, profile: { version: 2, kind: 'reviewed-durable-queue-receiver',
    manifestDigest: 'sha256:' + 'a'.repeat(64), configDigest: 'sha256:' + 'b'.repeat(64), unitPadding: padding },
  review: {}, legacyPublication: {}, publication: null, priorCandidate: { version: 1 }, topology: {} };
}
function withCandidate(value, reviewedCandidate) {
  if (!value || typeof value !== 'object') return;
  if (Object.hasOwn(value, 'controlEvidence')) value.candidate = reviewedCandidate;
  for (const child of Object.values(value)) {
    if (child !== reviewedCandidate) withCandidate(child, reviewedCandidate);
  }
}
function continuedRecovery(stage, phasePadding = '', preflightPadding = '') {
  const phase = { version: 1, kind: 'fixed-private-link-control-phase', stage,
    continuation: { version: 1, kind: 'reviewed-private-link-no-submission-continuation' }, unitPadding: phasePadding };
  const preflight = { kind: 'checked-private-link-phase', runtimeCompletion: null, unitPadding: preflightPadding };
  const original = { phase, publication: {}, approval: {}, preflight, journal: {}, intent: {} };
  return { version: 3, kind: 'reviewed-private-link-recovery', stage, phase, publication: {}, approval: {},
    preflight, intent: {}, intentSha256: digest('UNIT intent'), journal: {}, after: {}, deployment: null, operations: null,
    completedAt: '2026-10-02T00:00:00.000Z', authority: {}, recovery: { original, proposal: {}, review: {} } };
}
async function fixture(t) {
  const directory = join('infrastructure/arm/telemetry/tests', `.artifacts-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  const root = join(directory, 'evidence');
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true }));
  return { directory, root, store: createPrivateLinkArtifactStore({ root }) };
}
async function rawEnvelope(f) {
  return JSON.parse(await readFile(join(f.directory, 'result.json'), 'utf8'));
}
async function replaceEnvelope(f, mutate) {
  const value = await rawEnvelope(f);
  mutate(value);
  value.payloadSha256 = digest(JSON.stringify(value.payload) + '\n');
  await writeFile(join(f.directory, 'result.json'), JSON.stringify(value) + '\n', { mode: 0o600 });
}

test('control evidence is stored once and restored losslessly without rewriting inputs or granting semantic authority', async t => {
  const f = await fixture(t), original = completion(evidence()), bytes = json(original);
  await f.store.immutable(f.directory, 'result.json', original);
  const raw = await rawEnvelope(f);
  assert.equal(raw.kind, 'private-link-artifact-envelope');
  assert.equal(raw.referenceCount, 6);
  assert.equal((await readdir(f.root)).length, 1);
  const restored = await f.store.load(f.directory, 'result.json');
  assert.deepEqual(restored, original);
  assert.equal(json(restored), bytes);
  assert.equal(json(original), bytes);
  assert.equal(Object.isFrozen(original.controlEvidence), false);
  assert.equal(Object.isFrozen(restored.controlEvidence), true);
  assert.equal(restored.controlEvidence, restored.disabled.controlEvidence);
  assert.throws(() => { restored.controlEvidence.records[0].unit = false; }, TypeError);
  assert.throws(() => verifyPrivateLinkControlEvidence({}, {}, restored.controlEvidence),
    'A content hash never substitutes for the production semantic/history validator.');
  await assert.rejects(f.store.immutable(f.directory, 'result.json', original), error => error.code === 'EEXIST');
  assert.equal(json(await f.store.load(f.directory, 'result.json')), bytes);
});

test('large repeated evidence produces bounded reloadable files without increasing the private IO cap', async t => {
  const f = await fixture(t), value = completion(evidence('x'.repeat(12 * 1024 * 1024)));
  assert(6 * value.controlEvidence.records[0].extra.length > MAX_PRIVATE_ARTIFACT_BYTES);
  await f.store.immutable(f.directory, 'result.json', value);
  const raw = await rawEnvelope(f);
  assert(raw.payload.controlEvidence.bytes < MAX_PRIVATE_ARTIFACT_BYTES);
  assert((await readFile(join(f.directory, 'result.json'))).length < 10000);
  const restored = await f.store.load(f.directory, 'result.json');
  assert.equal(restored.controlEvidence.records[0].extra, value.controlEvidence.records[0].extra);
  assert.equal(restored.intent.disabled.intent.controlEvidence, restored.controlEvidence);
  const files = await readdir(f.root);
  assert.equal(files.length, 1);
  assert((await readFile(join(f.root, files[0]))).length <= MAX_PRIVATE_ARTIFACT_BYTES);
  assert.equal((await load(f.root, files[0])).records.length, 13);
});

test('production-sized repeated candidates and full current-proof payloads remain bounded through final retirement storage', async t => {
  const f = await fixture(t);
  const prefix = evidence('x'.repeat(25 * 1024 * 1024)), reviewedCandidate = candidate('c'.repeat(5 * 1024 * 1024));
  const runtime = completion(prefix);
  withCandidate(runtime, reviewedCandidate);
  runtime.preflight = { current: { prerequisites: { oldReceiver: { unitPadding: 'r'.repeat(3 * 1024 * 1024) } },
    effectivePolicy: { unitPadding: 'p'.repeat(2 * 1024 * 1024) },
    snapshot: { unitPadding: 's'.repeat(256 * 1024) } } };
  // These are size-only payloads above measured live constituent sizes, not
  // fabricated semantic evidence or approvals. The genuine runtime test
  // separately verifies the codec round trip through the production validator.
  const final = { kind: 'unit-size-only-final-chain', originalPrefixPayload: 'o'.repeat(25 * 1024 * 1024),
    records: Array.from({ length: 5 }, () => ({ preflight: { runtimeCompletion: runtime } })) };
  const originalHash = digestJson(final);
  await f.store.immutable(f.directory, 'result.json', final);
  const raw = await rawEnvelope(f);
  assert.equal(raw.referenceCount, 60);
  assert.equal((await readdir(f.root)).length, 2);
  for (const dir of [f.root, f.directory]) {
    for (const name of await readdir(dir)) {
      if (name.endsWith('.json')) assert((await readFile(join(dir, name))).length <= MAX_PRIVATE_ARTIFACT_BYTES);
    }
  }
  const restored = await f.store.load(f.directory, 'result.json');
  assert.equal(digestJson(restored), originalHash);
  assert.equal(restored.records[0].preflight.runtimeCompletion.candidate,
    restored.records[4].preflight.runtimeCompletion.intent.disabled.intent.candidate);
  assert.equal(Object.isFrozen(restored.records[0].preflight.runtimeCompletion.candidate), true);
  assert.equal(digestJson(final), originalHash);
});

test('candidate references cannot substitute control evidence or escape their fixed fields', async t => {
  const f = await fixture(t), runtime = completion(evidence());
  withCandidate(runtime, candidate());
  await f.store.immutable(f.directory, 'result.json', runtime);
  assert.deepEqual(await f.store.load(f.directory, 'result.json'), runtime);
  const raw = await rawEnvelope(f);
  assert.equal(raw.payload.candidate.kind, 'private-link-receiver-candidate-reference');
  assert.equal(raw.referenceCount, 12);
  await replaceEnvelope(f, value => { value.payload.controlEvidence = value.payload.candidate; });
  await assert.rejects(f.store.load(f.directory, 'result.json'), /REFERENCE_SCOPE/);
  await f.store.immutable(f.directory, 'candidate.json', { kind: 'private-link-runtime-completion', candidate: candidate() });
  const stored = JSON.parse(await readFile(join(f.directory, 'candidate.json'), 'utf8'));
  await assert.rejects(f.store.immutable(f.directory, 'raw-reference.json', stored.payload.candidate), /ALREADY_ENCODED/);
  const invalid = candidate(); invalid.version = 1;
  await assert.rejects(f.store.immutable(f.directory, 'invalid-candidate.json',
    { kind: 'private-link-runtime-completion', candidate: invalid }), /CANDIDATE_SCOPE/);
});

test('legacy raw files stay readable and mutable progress updates never overwrite evidence blobs', async t => {
  const f = await fixture(t), old = { version: 1, kind: 'private-link-disabled-receiver', controlEvidence: evidence() };
  await saveImmutable(f.directory, 'legacy.json', old);
  const before = await readFile(join(f.directory, 'legacy.json'));
  assert.deepEqual(await f.store.load(f.directory, 'legacy.json'), old);
  assert.deepEqual(await readFile(join(f.directory, 'legacy.json')), before);
  assert.equal(await f.store.load(f.directory, 'absent.json', true), null);
  await f.store.update(f.directory, 'progress.json', completion(evidence()));
  const name = (await readdir(f.root))[0], first = await readFile(join(f.root, name));
  await f.store.update(f.directory, 'progress.json', { ...completion(evidence()), outcome: 'in-progress' });
  assert.deepEqual(await readFile(join(f.root, name)), first);
  assert.equal((await f.store.load(f.directory, 'progress.json')).outcome, 'in-progress');
});

test('reference shape, position, count and content integrity fail closed before any semantic use', async t => {
  for (const [name, mutate] of [
    ['foreign path', x => { x.payload.controlEvidence.path = '../outside'; }],
    ['unknown version', x => { x.payload.controlEvidence.version = 2; }],
    ['invalid digest', x => { x.payload.controlEvidence.evidenceSha256 = '../outside'; }],
    ['wrong size', x => { x.payload.controlEvidence.bytes++; }],
    ['wrong count', x => { x.referenceCount--; }],
    ['unapproved field', x => { x.payload.untrusted = x.payload.controlEvidence; }],
    ['unapproved owner', x => { x.payload.kind = 'unrelated-record'; }],
    ['nested envelope', x => { x.payload.extra = { kind: 'private-link-artifact-envelope' }; }],
  ]) await t.test(name, async sub => {
    const f = await fixture(sub);
    await f.store.immutable(f.directory, 'result.json', completion(evidence()));
    await replaceEnvelope(f, mutate);
    await assert.rejects(f.store.load(f.directory, 'result.json'), /PRIVATE_LINK_ARTIFACT|CLOSED_INPUT_REQUIRED/);
  });
});

test('missing, replaced, symlinked and recursively referenced evidence cannot be reused or cached across reads', async t => {
  for (const kind of ['missing', 'changed', 'symlink', 'nested']) await t.test(kind, async sub => {
    const f = await fixture(sub), value = completion(evidence());
    await f.store.immutable(f.directory, 'result.json', value);
    assert.deepEqual(await f.store.load(f.directory, 'result.json'), value);
    const envelope = await rawEnvelope(f), name = (await readdir(f.root))[0], path = join(f.root, name);
    if (kind === 'missing') await rm(path);
    if (kind === 'changed') {
      const modified = evidence('UNIT changed');
      await writeFile(path, JSON.stringify(modified), { mode: 0o600 });
    }
    if (kind === 'symlink') {
      const original = await readFile(path), target = join(f.root, 'outside.json');
      await writeFile(target, original, { mode: 0o600 });
      await rm(path); await symlink('outside.json', path);
    }
    if (kind === 'nested') {
      const modified = evidence();
      modified.records[0].extra = envelope.payload.controlEvidence;
      await writeFile(path, JSON.stringify(modified), { mode: 0o600 });
    }
    await assert.rejects(f.store.load(f.directory, 'result.json'));
    if (kind === 'missing') {
      // Missing immutable content can be regenerated only from the complete
      // caller-supplied bytes; corruption and aliasing are never overwritten.
      await f.store.immutable(f.directory, 'new-result.json', value);
      assert.deepEqual(await f.store.load(f.directory, 'new-result.json'), value);
    } else await assert.rejects(f.store.immutable(f.directory, 'new-result.json', value));
  });
});

test('only complete assigned-queue prefixes are externalized and malformed or oversized JSON is rejected', async t => {
  const f = await fixture(t);
  for (const mutate of [
    e => { e.records.pop(); },
    e => { e.records[12].stage = 'record-migration'; },
    e => { e.planSha256 = 'unbound'; },
    e => { e.extra = false; },
  ]) {
    const value = evidence(); mutate(value);
    await assert.rejects(f.store.immutable(f.directory, 'invalid.json', completion(value)));
  }
  for (const value of [{ invalid: undefined }, { invalid: NaN }, { invalid: 1n }]) {
    await assert.rejects(f.store.immutable(f.directory, 'invalid.json', value), /JSON_REQUIRED/);
  }
  const cycle = {}; cycle.self = cycle;
  await assert.rejects(f.store.immutable(f.directory, 'invalid.json', cycle), /JSON_REQUIRED/);
  await assert.rejects(f.store.immutable(f.directory, 'too-large.json', { unrelated: 'x'.repeat(MAX_PRIVATE_ARTIFACT_BYTES) }),
    /ARTIFACT_TOO_LARGE/);
  const many = Array.from({ length: 65 }, () => ({ kind: 'private-link-runtime-completion', controlEvidence: evidence() }));
  await assert.rejects(f.store.immutable(f.directory, 'too-many.json', many), /REFERENCE_LIMIT/);
});

test('continued recovery projection restores exact member order and canonical bytes in a partial prefix', async t => {
  const f = await fixture(t), value = evidence();
  value.records = value.records.slice(0, 9);
  value.records[8] = continuedRecovery('retire-nsp-association', 'UNIT phase', 'UNIT preflight');
  const before = json(value), originalHash = digestJson(value);
  await f.store.immutable(f.directory, 'result.json', value);
  const raw = await rawEnvelope(f), reference = raw.payload.records[8];
  assert.equal(raw.version, 2); assert.equal(raw.referenceCount, 1);
  assert.equal(reference.kind, 'private-link-continued-recovery-reference');
  const blobName = (await readdir(f.root))[0], blob = await load(f.root, blobName);
  assert.equal(blob.kind, 'private-link-continued-recovery-content');
  assert.equal(blob.payload.phase, null); assert.equal(blob.payload.preflight, null);
  assert.equal(blob.payloadSha256, digest(JSON.stringify(blob.payload) + '\n'));
  const restored = await f.store.load(f.directory, 'result.json');
  assert.equal(json(restored), before); assert.equal(digestJson(restored), originalHash);
  assert.equal(restored.records[8].phase, restored.records[8].recovery.original.phase);
  assert.equal(restored.records[8].preflight, restored.records[8].recovery.original.preflight);
  assert.equal(Object.isFrozen(restored.records[8]), true);
  assert.equal(Object.isFrozen(value.records[8]), false);
  assert.equal(json(value), before);
  assert.throws(() => verifyPrivateLinkControlEvidence({}, {}, restored),
    'Lossless storage does not make a size-only fixture valid control evidence.');
});

test('projection never repairs unequal members, key-order drift or out-of-scope recovery records', async t => {
  for (const [name, mutate] of [
    ['phase mismatch', r => { r.phase = { ...r.phase, unitPadding: 'changed' }; }],
    ['preflight mismatch', r => { r.preflight = { ...r.preflight, unitPadding: 'changed' }; }],
    ['phase key order', r => { r.phase = Object.fromEntries(Object.entries(r.phase).reverse()); }],
    ['unknown record field', r => { r.extra = true; }],
    ['unknown original field', r => { r.recovery.original.extra = true; }],
    ['runtime-bearing recovery', r => { r.preflight.runtimeCompletion = {}; }],
  ]) await t.test(name, async sub => {
    const f = await fixture(sub), value = evidence();
    value.records[8] = continuedRecovery('retire-nsp-association');
    mutate(value.records[8]);
    await assert.rejects(f.store.immutable(f.directory, 'result.json', value),
      /RECOVERY_|CLOSED_INPUT_REQUIRED/);
  });
  const f = await fixture(t), plain = continuedRecovery('retire-nsp-association');
  delete plain.phase.continuation;
  const value = evidence(); value.records[8] = plain;
  await f.store.immutable(f.directory, 'legacy-recovery.json', value);
  assert.equal((await readdir(f.root)).length, 0);
  assert.deepEqual(await f.store.load(f.directory, 'legacy-recovery.json'), value);
});

test('recovery references reject misplaced, corrupt, nested and substituted content', async t => {
  for (const kind of ['scope', 'count', 'missing', 'hash', 'projection', 'nested', 'member']) await t.test(kind, async sub => {
    const f = await fixture(sub), value = evidence();
    value.records[8] = continuedRecovery('retire-nsp-association');
    await f.store.immutable(f.directory, 'result.json', value);
    const raw = await rawEnvelope(f), ref = raw.payload.records[8], name = (await readdir(f.root))[0];
    if (kind === 'scope') await replaceEnvelope(f, envelope => { envelope.payload.untrusted = ref; });
    else if (kind === 'count') await replaceEnvelope(f, envelope => { envelope.referenceCount++; });
    else if (kind === 'missing') await rm(join(f.root, name));
    else {
      const blob = await load(f.root, name);
      if (kind === 'hash') blob.recordSha256 = digest('UNIT substituted hash');
      if (kind === 'projection') blob.payload.phase = blob.payload.recovery.original.phase;
      if (kind === 'nested') blob.payload.recovery.original.phase.unitPadding = ref;
      if (kind === 'member') blob.payload.recovery.original.phase.stage = 'create-network';
      blob.payloadSha256 = digest(JSON.stringify(blob.payload) + '\n');
      const wire = JSON.stringify(blob) + '\n';
      await writeFile(join(f.root, name), wire, { mode: 0o600 });
      await replaceEnvelope(f, envelope => { envelope.payload.records[8].bytes = Buffer.byteLength(wire); });
    }
    await assert.rejects(f.store.load(f.directory, 'result.json'));
  });
});

test('a recovery larger than the file cap is losslessly restored from a bounded projection', async t => {
  const f = await fixture(t), value = evidence();
  value.records = value.records.slice(0, 9);
  value.records[8] = continuedRecovery('retire-nsp-association', 'a'.repeat(24 * 1024 * 1024), 'b'.repeat(12 * 1024 * 1024));
  assert(Buffer.byteLength(JSON.stringify(value.records[8])) > MAX_PRIVATE_ARTIFACT_BYTES);
  const before = digestJson(value);
  await f.store.immutable(f.directory, 'result.json', value);
  const raw = await rawEnvelope(f);
  assert(raw.payload.records[8].bytes < MAX_PRIVATE_ARTIFACT_BYTES);
  assert.equal(digestJson(await f.store.load(f.directory, 'result.json')), before);
  for (const name of await readdir(f.root)) assert((await readFile(join(f.root, name))).length <= MAX_PRIVATE_ARTIFACT_BYTES);
});

test('partial-prefix recoveries compose with complete runtime evidence under unchanged byte and reference limits', async t => {
  const f = await fixture(t), mib = 1024 * 1024, prefix = evidence('x'.repeat(28 * mib));
  prefix.records[6] = continuedRecovery('create-environment', 'e'.repeat(3 * mib), 'f'.repeat(9 * mib / 4));
  prefix.records[8] = continuedRecovery('retire-nsp-association', 'a'.repeat(19 * mib / 2), 'b'.repeat(21 * mib / 8));
  for (let index = 9; index < 13; index++) prefix.records[index].unitPadding = 't'.repeat(3 * mib);
  const runtime = completion(prefix);
  withCandidate(runtime, candidate('c'.repeat(5 * mib)));
  runtime.preflight = { current: { prerequisites: { oldReceiver: { unitPadding: 'r'.repeat(2240000) } },
    effectivePolicy: { unitPadding: 'p'.repeat(1615000) }, snapshot: { unitPadding: 's'.repeat(208000) } } };
  runtime.unitOtherFields = 'o'.repeat(256 * 1024);
  // Size-only future fields include full measured current-proof constituents;
  // neither this fixture nor a successful codec read grants runtime authority.
  const final = { ...prefix, records: [...prefix.records, ...Array.from({ length: 5 },
    () => ({ preflight: { runtimeCompletion: runtime } }))] };
  const before = digestJson(final);
  await f.store.immutable(f.directory, 'result.json', final);
  const raw = await rawEnvelope(f);
  assert.equal(raw.version, 2); assert.equal(raw.referenceCount, 62);
  assert.equal((await readdir(f.root)).length, 4);
  const storedPrefix = await load(f.root, `private-link-evidence-v2-${digestJson(prefix)}.json`);
  assert.equal(storedPrefix.version, 2); assert.equal(storedPrefix.referenceCount, 2);
  const sizes = [];
  for (const name of await readdir(f.root)) sizes.push((await readFile(join(f.root, name))).length);
  assert(sizes.every(size => size <= MAX_PRIVATE_ARTIFACT_BYTES));
  assert(sizes.reduce((sum, size) => sum + size, 0) <= MAX_PRIVATE_ARTIFACT_BYTES);
  assert((await readFile(join(f.directory, 'result.json'))).length <= MAX_PRIVATE_ARTIFACT_BYTES);
  const restored = await f.store.load(f.directory, 'result.json');
  assert.equal(digestJson(restored), before);
  assert.equal(restored.records[6], restored.records[13].preflight.runtimeCompletion.controlEvidence.records[6]);
  assert.equal(restored.records[8], restored.records[17].preflight.runtimeCompletion.controlEvidence.records[8]);
  await assert.rejects(f.store.immutable(f.directory, 'too-many-nested.json',
    { ...final, extra: { kind: 'private-link-runtime-completion', candidate: runtime.candidate } }), /REFERENCE_LIMIT/);
});

test('new recovery content retains the eight-blob and total distinct-content byte caps', async t => {
  const f = await fixture(t), many = { ...evidence(), records: Array.from({ length: 9 }, (_, index) => ({
    ...continuedRecovery('retire-nsp-association'), completedAt: `2026-10-02T00:00:0${index}.000Z`,
  })) };
  await assert.rejects(f.store.immutable(f.directory, 'too-many-blobs.json', many), /REFERENCE_LIMIT/);
  const first = continuedRecovery('create-environment', 'p'.repeat(17 * 1024 * 1024), 'q'.repeat(17 * 1024 * 1024));
  const second = continuedRecovery('retire-nsp-association', 'p'.repeat(17 * 1024 * 1024), 'q'.repeat(17 * 1024 * 1024));
  await assert.rejects(f.store.immutable(f.directory, 'too-many-bytes.json', { ...evidence(), records: [first, second] }),
    /REFERENCE_BYTES_LIMIT/);
});
