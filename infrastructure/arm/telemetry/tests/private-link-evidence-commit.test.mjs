import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm, open, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { digest, digestJson as hash } from '../definition.mjs';
import { privateDirectory, saveImmutable, load } from '../controller.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { privateLinkAzureIO, privateLinkHead, privateLinkTargetKey, readPrivateLinkHead,
  executePrivateLinkPhase, reconcilePrivateLinkPhase, recoverPrivateLinkPhase, runPrivateLinkControl,
  verifyPrivateLinkControlEvidence } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';
import { retainedReadInvoke, retainedSourceLookup } from './private-link-nsg-adoption.fixture.mjs';

const f = await privateLinkFixture({ ...privateInput, version: 2 });
const evidence = await privateControlChain(f, 'review-migration'), stage = 'set-project-migration-budget';
const normalHarness = await privateControlHarness(f, evidence, stage);
const normal = await normalHarness.execute();
const lateHarness = await privateControlHarness(f, evidence, stage);
const originalWrite = lateHarness.io.write;
lateHarness.io.write = async (...args) => { await originalWrite(...args); throw new Error('UNIT_UNKNOWN_AFTER_ONE_WRITE'); };
await assert.rejects(lateHarness.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
const original = { phase: lateHarness.phase, publication: lateHarness.io.publication, approval: lateHarness.approval,
  preflight: lateHarness.proof, intent: lateHarness.intent, journal: structuredClone(lateHarness.journal) };
lateHarness.advance(121000);
const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, lateHarness.io);
const recoveryReview = { version: 1, action: 'adopt-exact-private-link-late-state-without-replay',
  proposalSha256: hash(proposal), sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead),
  approvedAt: new Date(lateHarness.io.now()).toISOString(), expiresAt: new Date(lateHarness.io.now() + 300000).toISOString() };
const recovered = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal, recoveryReview, lateHarness.io);

async function storeHarness(t, selected = normal) {
  const prefix = 'infrastructure/arm/telemetry/.operator-private', suffix = randomUUID().slice(0, 8);
  const directoryArg = `${prefix}/revision-20261003-commit-${suffix}`, directory = await privateDirectory(directoryArg);
  const rootArg = `${prefix}/revision-20261003-canonical-${suffix}`, root = await privateDirectory(rootArg);
  t.after(async () => { await rm(directory, { recursive: true }); await rm(root, { recursive: true }); });
  await mkdir('infrastructure/opentofu/telemetry/.operator-private', { recursive: true, mode: 0o700 });
  const record = structuredClone(selected), prior = structuredClone(evidence), target = privateLinkTargetKey(f.context);
  const next = privateLinkHead(f.context, { ...prior, records: [...prior.records, record] });
  const pending = { version: 1, kind: 'private-link-pending-head', targetKey: target,
    previous: record.phase.expectedHead, intentSha256: hash(record.intent) };
  const files = new Map(), key = (path, name) => `${path}/${name}`, events = [], writes = [];
  const seed = (name, value) => files.set(key(root, name), structuredClone(value));
  seed(`private-link-head-${target}.json`, pending);
  const fence = { version: 1, targetKey: target, stage, phase: record.phase, intent: record.intent, intentSha256: hash(record.intent) };
  seed(`private-link-fence-${target}.json`, fence);
  seed(`private-link-intent-${hash({ target, stage })}.json`, { phase: record.phase, intent: record.intent });
  let now = Date.parse(record.completedAt), source = f.source, cancelled = false, afterWrite = async () => {}, fault = null;
  const store = { root,
    read: async (path, name) => { events.push(['read', path, name]); return structuredClone(files.get(key(path, name)) ?? null); },
    save: async (path, name, value) => {
      events.push(['save', path, name]); files.set(key(path, name), structuredClone(value)); writes.push(name); await afterWrite(path, name, value);
    },
    saveImmutable: async (path, name, value) => {
      events.push(['immutable', path, name]); if (fault?.(path, name, value)) throw new Error('PRIVATE_LINK_ARTIFACT_TOO_LARGE');
      if (files.has(key(path, name))) throw new Error('UNIT_EEXIST');
      files.set(key(path, name), structuredClone(value)); writes.push(name); await afterWrite(path, name, value);
    } };
  const review = record.recovery ?? record.preflight;
  const inputs = { publication: record.recovery?.currentPublication ?? record.publication,
    policyRevision: record.recovery?.policyRevision ?? record.phase.policyRevision ?? null,
    proof: record.preflight, approval: record.approval,
    costReview: review.costReview, costEvidence: review.costEvidence, migrationReview: review.migrationReview };
  const options = { now: () => now, sourceDigest: async () => source, cancelled: () => cancelled, store };
  const adapter = privateLinkAzureIO(f.c, f.context, prior, record.phase, directory, inputs,
    async () => assert.fail('Append-only tests must never invoke Azure'), options);
  const names = { record: `private-link-${stage}-${record.recovery ? 'recovered-record' : 'record'}.json`,
    aggregate: `private-link-${stage}-${record.recovery ? 'recovered-evidence' : 'evidence'}.json`,
    resolution: `private-link-resolution-${hash(pending)}.json`, head: `private-link-head-${target}.json`,
    fence: `private-link-fence-${target}.json` };
  return { record, prior, pending, next, target, directory, directoryArg, root, rootArg, files, events, writes, inputs, options, adapter, names, key, fence,
    get: (path, name) => files.get(key(path, name)), setNow: value => { now = value; }, setSource: value => { source = value; },
    setCancelled: value => { cancelled = value; }, setFault: value => { fault = value; }, setAfterWrite: value => { afterWrite = value; },
    append: guard => adapter.append(pending, record, next, guard) };
}

for (const [kind, selected] of [['normal', normal], ['late recovery', recovered]]) {
  test(`${kind} aggregate persistence failure leaves pending head/fence and no canonical success`, async t => {
    const q = await storeHarness(t, selected), priorHash = hash(q.prior), recordHash = hash(q.record);
    q.setFault((path, name) => path === q.directory && name === q.names.aggregate);
    await assert.rejects(q.append(), /ARTIFACT_TOO_LARGE/);
    assert.deepEqual(q.get(q.root, q.names.head), q.pending);
    assert.deepEqual(q.get(q.root, q.names.fence), q.fence);
    assert.deepEqual(q.get(q.directory, q.names.record), q.record);
    assert.equal(q.get(q.directory, q.names.aggregate), undefined);
    assert.equal(q.get(q.root, q.names.resolution), undefined);
    assert.equal(q.writes.includes(q.names.head), false);
    assert.equal(hash(q.prior), priorHash); assert.equal(hash(q.record), recordHash);
  });

  test(`${kind} aggregate is written once before canonical resolution/head and reloads through codec`, async t => {
    const q = await storeHarness(t, selected);
    const codec = createPrivateLinkArtifactStore({ root: q.root });
    for (const [name, value] of [[q.names.head, q.pending], [q.names.fence, q.fence],
      [`private-link-intent-${hash({ target: q.target, stage })}.json`, { phase: q.record.phase, intent: q.record.intent }]]) {
      await codec.immutable(q.root, name, value);
    }
    const calls = [], inputs = q.inputs, options = { ...q.options, store: { root: q.root, read: codec.load,
      save: async (path, name, value) => { calls.push(['head', path, name]); await codec.update(path, name, value); },
      saveImmutable: async (path, name, value) => { calls.push(['immutable', path, name]); await codec.immutable(path, name, value); } } };
    const io = privateLinkAzureIO(f.c, f.context, q.prior, q.record.phase, q.directory, inputs,
      async () => assert.fail('Persistence is read-only with respect to Azure'), options);
    await io.append(q.pending, q.record, q.next);
    assert.deepEqual(calls.map(call => call[2]), [q.names.record, q.names.aggregate, q.names.resolution, q.names.head]);
    assert.deepEqual(calls.map(call => call[1]), [q.directory, q.directory, q.root, q.root]);
    const aggregate = await codec.load(q.directory, q.names.aggregate);
    assert.equal(hash(aggregate), hash({ ...q.prior, records: [...q.prior.records, q.record] }));
    assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, aggregate, q.options.now()).stage, stage);
    assert.deepEqual(await readPrivateLinkHead(f.context, aggregate, { root: q.root, read: codec.load }), q.next);
    assert.deepEqual((await codec.load(q.root, q.names.resolution)).record, q.record);
    assert.deepEqual(await codec.load(q.root, q.names.fence), q.fence);
  });
}

test('after-await expiry, source, cancellation, head and input guards block canonical success after aggregate persistence', async t => {
  for (const [name, alter, expect] of [
    ['rollout expires', q => q.setNow(q.record.journal.rolloutDeadline), /APPEND_EXPIRED/],
    ['approval expires', q => q.setNow(Date.parse(q.record.approval.expiresAt)), /REVIEW_EXPIRED|APPEND_EXPIRED/],
    ['source changes', q => q.setSource(digest('UNIT source drift')), /SOURCE_CHANGED/],
    ['cancelled', q => q.setCancelled(true), /APPEND_EXPIRED/],
    ['head changes', q => q.files.set(q.key(q.root, q.names.head), { ...q.pending, intentSha256: digest('UNIT other head') }), /HEAD_CHANGED/],
    ['operation input changed', q => { q.inputs.proof = { ...q.inputs.proof, phaseSha256: digest('UNIT other proof') }; }, /UNIT_INPUT_CHANGED/],
  ]) await t.test(name, async t => {
    const q = await storeHarness(t), savedInput = q.inputs.proof;
    q.setAfterWrite(async (_path, name) => { if (name === q.names.aggregate) { await Promise.resolve(); alter(q); } });
    await assert.rejects(q.append(() => assert.equal(q.inputs.proof, savedInput, 'UNIT_INPUT_CHANGED')), expect);
    assert(q.get(q.directory, q.names.aggregate));
    assert.equal(q.get(q.root, q.names.resolution), undefined); assert.equal(q.writes.includes(q.names.head), false);
    assert.deepEqual(q.get(q.root, q.names.fence), q.fence);
  });
});

test('a rejected canonical resolution write cannot advance the head after the aggregate', async t => {
  const q = await storeHarness(t);
  q.setFault((path, name) => path === q.root && name === q.names.resolution);
  await assert.rejects(q.append(), /ARTIFACT_TOO_LARGE/);
  assert(q.get(q.directory, q.names.aggregate)); assert.equal(q.get(q.root, q.names.resolution), undefined);
  assert.deepEqual(q.get(q.root, q.names.head), q.pending); assert.deepEqual(q.get(q.root, q.names.fence), q.fence);
});

test('late recovery review expiry after aggregate persistence keeps the original pending head', async t => {
  const q = await storeHarness(t, recovered);
  q.setAfterWrite(async (_path, name) => {
    if (name === q.names.aggregate) { await Promise.resolve(); q.setNow(Date.parse(q.record.recovery.review.expiresAt)); }
  });
  await assert.rejects(q.append(), /APPEND_EXPIRED/);
  assert(q.get(q.directory, q.names.aggregate)); assert.equal(q.get(q.root, q.names.resolution), undefined);
  assert.deepEqual(q.get(q.root, q.names.head), q.pending);
});

async function publicHarness(t, mode) {
  const h = await privateControlHarness({ ...f }, evidence, stage);
  const stopped = mode !== 'execute';
  if (stopped) {
    const write = h.io.write;
    h.io.write = mode === 'no-submit' ? async () => { throw new Error('UNIT_BEFORE_WRITE'); } :
      async (...args) => { await write(...args); throw new Error('UNIT_AFTER_WRITE'); };
    await assert.rejects(h.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  }
  const original = stopped ? { phase: h.phase, publication: h.io.publication, approval: h.approval, preflight: h.proof,
    journal: structuredClone(h.journal), intent: h.intent } : null;
  const sample = mode === 'execute' ? normal : { ...normal, intent: original.intent, phase: original.phase };
  const q = await storeHarness(t, sample), initial = privateLinkHead(f.context, evidence), prior = evidence.records.at(-1);
  let cloudWrites = 0;
  if (mode === 'execute') {
    q.files.set(q.key(q.root, q.names.head), initial);
    q.files.set(q.key(q.root, q.names.fence), { version: 1, targetKey: q.target, stage: prior.stage,
      phase: prior.phase, intent: prior.intent, intentSha256: prior.intentSha256 });
    q.files.delete(q.key(q.root, `private-link-intent-${hash({ target: q.target, stage })}.json`));
    q.files.set(q.key(q.root, `private-link-intent-${hash({ target: q.target, stage: prior.stage })}.json`),
      { phase: prior.phase, intent: prior.intent });
  } else {
    await saveImmutable(q.directory, `private-link-${stage}-journal.json`, original.journal);
  }
  const read = retainedReadInvoke(f, mode === 'no-submit' ? h.before : h.after, h.io.read);
  const options = { ...q.options, now: h.io.now, sourceDigest: h.io.sourceDigest,
    lookup: retainedSourceLookup(f.context, evidence, h.io.publication),
    invoke: async args => {
      if (args[0] === 'rest' && args[args.indexOf('--method') + 1] !== 'GET') {
        cloudWrites++; assert.equal(mode, 'execute'); h.setLive(h.after); return {};
      }
      return read(args);
    } };
  const inputs = { publication: h.io.publication, costReview: h.io.costReview, costEvidence: h.io.costEvidence,
    migrationReview: h.io.migrationReview, proof: h.proof, approval: h.approval };
  if (stopped) {
    const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, h.io);
    const recoveryReview = { version: 1, action: mode === 'no-submit' ? 'record-exact-private-link-no-submission-without-replay' :
      'adopt-exact-private-link-late-state-without-replay', proposalSha256: hash(proposal), sourceSha256: f.source,
      pendingHeadSha256: hash(proposal.pendingHead), approvedAt: new Date(h.io.now()).toISOString(),
      expiresAt: new Date(h.io.now() + 300000).toISOString() };
    Object.assign(inputs, { original, proposal, recoveryReview });
  }
  return { ...q, h, inputs, options, get cloudWrites() { return cloudWrites; },
    run: () => runPrivateLinkControl(f.c, f.context, evidence, stage, mode === 'execute' ? 'execute' : 'recover', q.directoryArg, inputs, options) };
}

for (const mode of ['execute', 'recover']) test(`public ${mode} relies on one injected append aggregate write without wrapper EEXIST`, async t => {
  const q = await publicHarness(t, mode), record = await q.run();
  const aggregateName = `private-link-${stage}-${mode === 'recover' ? 'recovered-' : ''}evidence.json`;
  assert.equal(q.writes.filter(name => name === aggregateName).length, 1);
  const aggregate = q.get(q.directory, aggregateName);
  assert.deepEqual(aggregate.records.at(-1), record);
  verifyPrivateLinkControlEvidence(f.c, f.context, aggregate, q.h.io.now());
  assert.equal(await load(q.directory, aggregateName, true), null, 'Wrapper must not bypass injected immutableStore');
  assert.equal(q.cloudWrites, mode === 'execute' ? 1 : 0);
});

test('public normal execution exposes aggregate failure without successful head/resolution or replay', async t => {
  const q = await publicHarness(t, 'execute');
  q.setFault((_path, name) => name === `private-link-${stage}-evidence.json`);
  await assert.rejects(q.run(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  const journal = await load(q.directory, `private-link-${stage}-journal.json`);
  assert.equal(journal.dispatchAttempted, true); assert.equal(journal.outcome, 'reconciliation-required');
  assert.equal(q.cloudWrites, 1);
  assert(!q.writes.some(name => name.startsWith('private-link-resolution-')));
  assert.equal(q.get(q.root, q.names.head).kind, 'private-link-pending-head');
  await assert.rejects(q.run(), /INTENT_REPLAY_FORBIDDEN/); assert.equal(q.cloudWrites, 1);
});

test('public late recovery exposes aggregate failure without a canonical resolution or head advancement', async t => {
  const q = await publicHarness(t, 'recover'), pending = hash(q.get(q.root, q.names.head));
  q.setFault((_path, name) => name === `private-link-${stage}-recovered-evidence.json`);
  await assert.rejects(q.run(), /ARTIFACT_TOO_LARGE/);
  assert(q.get(q.directory, `private-link-${stage}-recovered-record.json`));
  assert(!q.writes.some(name => name.startsWith('private-link-resolution-')));
  assert.equal(hash(q.get(q.root, q.names.head)), pending); assert.equal(q.cloudWrites, 0);
});

for (const mode of ['execute', 'recover']) test(`public ${mode} input mutation during aggregate await is rejected before canonical resolution`, async t => {
  const q = await publicHarness(t, mode);
  const aggregateName = `private-link-${stage}-${mode === 'recover' ? 'recovered-' : ''}evidence.json`;
  q.setAfterWrite(async (_path, name) => {
    if (name === aggregateName) {
      await Promise.resolve();
      if (mode === 'execute') q.inputs.approval.requestSha256 = digest('UNIT modified input');
      else q.inputs.costReview.evidenceSha256 = digest('UNIT modified input');
    }
  });
  await assert.rejects(q.run(), mode === 'execute' ? /STOPPED_ORIGINAL_INTENT_PRESERVED/ : /COST_REVIEW_REQUIRED/);
  assert(!q.writes.some(name => name.startsWith('private-link-resolution-')));
  assert.equal(q.get(q.root, q.names.head).kind, 'private-link-pending-head');
});

test('public no-submit resolution writes no aggregate and advances neither successful head nor fence', async t => {
  const q = await publicHarness(t, 'no-submit'), oldHead = hash(q.get(q.root, q.names.head)), oldFence = hash(q.get(q.root, q.names.fence));
  const record = await q.run();
  assert.equal(record.kind, 'reviewed-private-link-no-submission'); assert.equal(record.qualified, false);
  assert.equal(hash(q.get(q.root, q.names.head)), oldHead); assert.equal(hash(q.get(q.root, q.names.fence)), oldFence);
  assert(!q.writes.some(name => name.endsWith('-evidence.json') || name.startsWith('private-link-resolution-')));
  assert.equal(q.cloudWrites, 0);
});

test('injected canonical stores keep an exclusive lock per store without contending with independent fixtures', async t => {
  const first = await publicHarness(t, 'recover'), second = await publicHarness(t, 'recover');
  const firstPath = resolve(first.root, 'controller.lock');
  const held = await open(firstPath, 'wx', 0o600);
  try { await assert.rejects(first.run(), error => error.code === 'EEXIST'); }
  finally { await held.close(); await rm(firstPath); }
  for (const q of [first, second]) q.setAfterWrite(async (_path, name) => {
    if (name.endsWith('-recovered-evidence.json')) {
      assert.equal((await stat(resolve(q.root, 'controller.lock'))).mode & 0o777, 0o600);
    }
  });
  await Promise.all([first.run(), second.run()]);
  for (const q of [first, second]) {
    await assert.rejects(stat(resolve(q.root, 'controller.lock')), error => error.code === 'ENOENT');
    assert.equal(q.cloudWrites, 0);
  }
});
