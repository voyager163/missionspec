import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { digest, json } from '../definition.mjs';
import { privateLinkPhase } from '../private-link.mjs';
import { privateLinkAzureIO, privateLinkHead, privateLinkTargetKey, readPrivateLinkHead,
  preparePrivateLinkPhase, checkPrivateLinkPhase, executePrivateLinkPhase, reconcilePrivateLinkPhase,
  recoverPrivateLinkPhase, verifyPrivateLinkContinuation, verifyPrivateLinkControlEvidence, runPrivateLinkControl } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';

const hash = value => digest(json(value));
const f = await privateLinkFixture({ ...privateInput, version: 2 });
const evidence = await privateControlChain(f, 'retire-nsp-rule');
const stage = 'create-network';
function makeContinuation(resolution, now, attemptId = randomUUID()) {
  const fixed = privateLinkPhase(f.c, f.context, stage);
  return { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId, resolution,
    review: { version: 1, action: 'continue-exact-known-not-submitted-private-link-phase',
      configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
      stage, attemptId, resolutionSha256: hash(resolution), priorIntentSha256: hash(resolution.original.intent),
      pendingHeadSha256: hash(resolution.proposal.pendingHead), fixedPhaseSha256: hash(fixed),
      requestSha256: hash(fixed.request), sourceSha256: f.source, approvedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 600000).toISOString() } };
}
async function noSubmission(t) {
  const q = await privateControlHarness({ ...f }, evidence, stage), terminal = evidence.records.at(-1);
  const target = privateLinkTargetKey(f.context), files = new Map();
  files.set(`private-link-head-${target}.json`, privateLinkHead(f.context, evidence));
  files.set(`private-link-fence-${target}.json`, { version: 1, targetKey: target, stage: terminal.stage,
    phase: terminal.phase, intent: terminal.intent, intentSha256: terminal.intentSha256 });
  files.set(`private-link-intent-${hash({ target, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent });
  const store = { root: 'UNIT isolated store', read: async (_root, name) => structuredClone(files.get(name) ?? null),
    save: async (_root, name, value) => { files.set(name, structuredClone(value)); },
    saveImmutable: async (_root, name, value) => {
      if (files.has(name)) throw new Error('UNIT_CREATE_EXCLUSIVE_REPLAY_BLOCKED');
      files.set(name, structuredClone(value));
    } };
  const directory = `infrastructure/arm/telemetry/tests/.private-link-continuation-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const input = { publication: q.io.publication, proof: q.proof, approval: q.approval, costReview: q.io.costReview,
    costEvidence: q.io.costEvidence, migrationReview: q.io.migrationReview };
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, q.phase, directory, input,
    async () => assert.fail('Original attempt must never dispatch'), { now: q.io.now, sourceDigest: q.io.sourceDigest, store });
  const read = q.io.read;
  const io = { ...q.io, head: adapter.head, reserve: adapter.reserve, journal: adapter.journal,
    saveJournal: adapter.saveJournal, resolveNoSubmission: adapter.resolveNoSubmission, verifyOriginal: adapter.verifyOriginal,
    read: (request, deadline) => request.id === q.phase.deploymentId ? Promise.resolve(null) : read(request, deadline),
    write: async () => { throw new Error('UNIT_CAUGHT_BEFORE_ARM'); } };
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, q.phase, q.proof, q.approval, io), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  const archived = files.get(`private-link-intent-${hash({ target, stage })}.json`);
  const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
    intent: archived.intent, journal: await adapter.journal() };
  const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, io);
  const review = { version: 1, action: 'record-exact-private-link-no-submission-without-replay',
    proposalSha256: hash(proposal), pendingHeadSha256: hash(proposal.pendingHead), sourceSha256: f.source,
    approvedAt: new Date(io.now()).toISOString(), expiresAt: new Date(io.now() + 600000).toISOString() };
  const resolution = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal, review, io);
  return { q, files, store, input, io, original, resolution, target, archived };
}
function approval(phase, proof, now) {
  return { version: 1, action: `execute-exact-private-link-${stage}`, configSha256: hash(f.c),
    planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding),
    sourceSha256: f.source, requestSha256: hash(phase.request),
    approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() };
}

test('separately reviewed known-no-submit continuation uses a fresh immutable attempt and exactly one unchanged request', async t => {
  const x = await noSubmission(t), originalBytes = json(x.original), evidenceBytes = json(evidence);
  const resolutionBytes = json(x.resolution), continuation = makeContinuation(x.resolution, x.io.now());
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, continuation);
  assert.deepEqual(phase.request, x.original.phase.request);
  assert.deepEqual(phase.resources, x.original.phase.resources);
  assert.equal(phase.continuation.attemptId, continuation.attemptId);
  assert.notEqual(hash(phase), hash(x.original.phase));
  const directory = `infrastructure/arm/telemetry/tests/.private-link-new-attempt-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  let dispatched = 0;
  const input = { ...x.input, continuation, proof: null, approval: null };
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, phase, directory, input,
    async args => {
      dispatched++; assert.equal(args[args.indexOf('--method') + 1], 'PUT');
      assert(args.includes(`https://management.azure.com${phase.request.id}?api-version=${phase.request.apiVersion}`));
      x.q.setLive(x.q.after); return {};
    }, { now: x.io.now, sourceDigest: x.io.sourceDigest, store: x.store });
  const io = { ...x.q.io, head: adapter.head, reserve: adapter.reserve, journal: adapter.journal,
    saveJournal: adapter.saveJournal, append: adapter.append, write: adapter.write,
    read: (request, deadline) => request.id === phase.deploymentId && dispatched === 0 ? Promise.resolve(null) : x.q.io.read(request, deadline) };
  const proof = await checkPrivateLinkPhase(f.c, f.context, evidence, phase, io);
  input.proof = proof; input.approval = approval(phase, proof, io.now());
  const record = await executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, input.approval, io);
  assert.equal(dispatched, 1); assert.equal(record.intent.attemptId, continuation.attemptId);
  assert.equal(record.journal.dispatchAttempted, true);
  const result = { ...evidence, records: [...evidence.records, record] };
  verifyPrivateLinkControlEvidence(f.c, f.context, result, io.now());
  await readPrivateLinkHead(f.context, result, x.store);
  assert.equal(json(x.original), originalBytes); assert.equal(json(x.resolution), resolutionBytes);
  assert.equal(json(evidence), evidenceBytes);
  assert.deepEqual(x.files.get(`private-link-intent-${hash({ target: x.target, stage })}.json`), x.archived);
  assert(x.files.has(`private-link-intent-${hash({ target: x.target, stage, attemptId: continuation.attemptId })}.json`));
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, input.approval, io), /INTENT_REPLAY_FORBIDDEN/);
  const nextAttempt = makeContinuation(x.resolution, io.now());
  const stale = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, nextAttempt);
  const staleAdapter = privateLinkAzureIO(f.c, f.context, evidence, stale, directory, { ...input, continuation: nextAttempt },
    async () => assert.fail('Stale resolution must never dispatch'), { now: io.now, store: x.store });
  await assert.rejects(staleAdapter.head(evidence), /CONTINUATION_HEAD_CHANGED/);
  assert.equal(dispatched, 1);
});

test('continuation rejects unknown, legacy false, changed request, expired review and missing canonical resolution', async t => {
  const x = await noSubmission(t), valid = makeContinuation(x.resolution, x.io.now());
  verifyPrivateLinkContinuation(f.c, f.context, evidence, stage, f.source, valid, x.io.now());
  for (const [name, change] of [
    ['durable unknown', value => { value.resolution.original.journal.dispatchAttempted = null; }],
    ['legacy false', value => { value.resolution.original.journal.version = 2; }],
    ['confirmed invocation', value => { value.resolution.original.journal.dispatchAttempted = true; }],
    ['different request', value => { value.resolution.original.phase.request.body.properties.mode = 'Complete'; }],
    ['different stage', value => { value.review.stage = 'create-queue-endpoint'; }],
    ['new source without matching review', value => { value.review.sourceSha256 = digest('UNIT other source'); }],
    ['expired continuation', value => { value.review.expiresAt = new Date(x.io.now()).toISOString(); }],
    ['reused collector UUID', value => { value.attemptId = f.c.runId; value.review.attemptId = f.c.runId; }],
  ]) await t.test(name, () => {
    const value = structuredClone(valid); change(value);
    value.review.resolutionSha256 = hash(value.resolution);
    assert.throws(() => verifyPrivateLinkContinuation(f.c, f.context, evidence, stage, f.source, value, x.io.now()));
  });
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, valid);
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, phase, 'UNIT unused', { ...x.input, continuation: valid },
    async () => assert.fail('Missing resolution must not invoke'), { store: x.store, now: x.io.now });
  x.files.delete(`private-link-no-submission-${hash(x.original.intent)}.json`);
  await assert.rejects(adapter.head(evidence), /CONTINUATION_RESOLUTION_REQUIRED/);
});

test('new attempt still rejects live preimage/governance drift and cannot reuse its immutable UUID', async t => {
  const x = await noSubmission(t), continued = makeContinuation(x.resolution, x.io.now());
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, continued);
  const directory = `infrastructure/arm/telemetry/tests/.private-link-continued-drift-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const input = { ...x.input, continuation: continued, proof: null, approval: null };
  let writes = 0;
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, phase, directory, input, async () => { writes++; return {}; },
    { store: x.store, now: x.io.now, sourceDigest: x.io.sourceDigest });
  const io = { ...x.io, head: adapter.head, reserve: adapter.reserve, saveJournal: adapter.saveJournal,
    journal: adapter.journal, write: adapter.write };
  const proof = await checkPrivateLinkPhase(f.c, f.context, evidence, phase, io);
  assert.equal(proof.deploymentBefore, null);
  input.proof = proof; input.approval = approval(phase, proof, io.now());
  const drift = structuredClone(x.q.before);
  drift.resources[f.context.plan.topology.ids.account].properties.primaryEndpoints.unreviewed = 'UNIT drift';
  x.q.setLive(drift);
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, input.approval, io), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  assert.equal(writes, 0);
  assert.equal((await adapter.journal()).dispatchAttempted, false);
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, input.approval, io), /INTENT_REPLAY_FORBIDDEN/);
  assert.equal(writes, 0);
});

test('continued preflight independently requires absent deployment and fresh governance', async t => {
  const x = await noSubmission(t), continuation = makeContinuation(x.resolution, x.io.now());
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, continuation);
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, phase, 'UNIT-unused', { ...x.input, continuation },
    async () => assert.fail('Checks cannot dispatch'), { now: x.io.now, sourceDigest: x.io.sourceDigest, store: x.store });
  const io = { ...x.io, head: adapter.head };
  const read = io.read;
  io.read = (request, deadline) => request.id === phase.deploymentId
    ? Promise.resolve({ id: phase.deploymentId, properties: { provisioningState: 'Succeeded' } }) : read(request, deadline);
  await assert.rejects(checkPrivateLinkPhase(f.c, f.context, evidence, phase, io), /CONTINUATION_DEPLOYMENT_PRESENT/);
  io.read = (request, deadline) => request.id.endsWith('/denyAssignments')
    ? Promise.resolve({ value: [{ id: 'UNIT deny' }] }) : read(request, deadline);
  await assert.rejects(checkPrivateLinkPhase(f.c, f.context, evidence, phase, io), /DENY_ASSIGNMENT/);
  assert.equal(x.files.get(`private-link-head-${x.target}.json`).intentSha256, hash(x.original.intent));
});

test('reconciliation and recovery take continuation only from immutable original phase', async () => {
  for (const operation of ['reconcile', 'recover']) {
    await assert.rejects(runPrivateLinkControl(f.c, f.context, evidence, stage, operation,
      'must-not-be-created', { continuation: null }), /CONTINUATION_FROM_ORIGINAL_ONLY/);
  }
});
