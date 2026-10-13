import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { digest, digestJson as hash } from '../definition.mjs';
import { privateDirectory, saveImmutable, load, save } from '../controller.mjs';
import { privateLinkPhase } from '../private-link.mjs';
import { privateLinkAzureIO, privateLinkTargetKey, preparePrivateLinkPhase, checkPrivateLinkPhase, executePrivateLinkPhase,
  reconcilePrivateLinkPhase, recoverPrivateLinkPhase, resolvePrivateLinkNoSubmission, verifyPrivateLinkNoSubmissionResolution,
  runPrivateLinkControl, currentPrivateLinkRuntimeProof } from '../private-link-controller.mjs';
import { nsgAdoptionFixture, retainedReadInvoke, retainedSourceLookup } from './private-link-nsg-adoption.fixture.mjs';

const x = await nsgAdoptionFixture(() => {}, true), { f } = x, evidence = x.adoptedEvidence, at = x.io.now(), stage = 'create-environment';
const reviewFor = proposal => ({ version: 1, action: 'record-exact-private-link-no-submission-without-replay',
  proposalSha256: hash(proposal), sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead),
  approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 600000).toISOString() });
const previousProposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, x.original, x.io);
const previous = await recoverPrivateLinkPhase(f.c, f.context, evidence, x.original, previousProposal, reviewFor(previousProposal),
  { ...x.io, resolveNoSubmission: async () => {} });
const attemptId = randomUUID(), fixed = privateLinkPhase(f.c, f.context, stage);
const continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId, resolution: previous,
  review: { version: 1, action: 'continue-exact-known-not-submitted-private-link-phase', configSha256: hash(f.c),
    planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin), stage, attemptId,
    resolutionSha256: hash(previous), priorIntentSha256: hash(x.original.intent), pendingHeadSha256: hash(previousProposal.pendingHead),
    fixedPhaseSha256: hash(fixed), requestSha256: hash(fixed.request), sourceSha256: f.source,
    approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 600000).toISOString() } };
const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, continuation);
const proof = await checkPrivateLinkPhase(f.c, f.context, evidence, phase, { ...x.io, head: async () => previousProposal.pendingHead });
const approval = { version: 1, action: `execute-exact-private-link-${stage}`, configSha256: hash(f.c),
  planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding),
  sourceSha256: f.source, requestSha256: hash(phase.request), approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 600000).toISOString() };
let intent, journal;
await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, approval, {
  ...x.io, journal: async () => null, saveJournal: async value => { journal = structuredClone(value); },
  reserve: async (_e, p, i) => { intent = structuredClone(i); return { version: 1, kind: 'private-link-pending-head',
    targetKey: privateLinkTargetKey(f.context), previous: p.expectedHead, intentSha256: hash(i) }; },
  write: async () => { throw new Error('PRIVATE_LINK_DISPATCH_GOVERNANCE_CHANGED'); },
}), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
const stopped = { phase, publication: x.io.publication, approval, preflight: proof, intent, journal };
const stoppedHash = hash(stopped), evidenceHash = hash(evidence);

async function harness(t) {
  const original = structuredClone(stopped), current = structuredClone(evidence), target = privateLinkTargetKey(f.context);
  const pending = { version: 1, kind: 'private-link-pending-head', targetKey: target,
    previous: original.phase.expectedHead, intentSha256: hash(original.intent) };
  const suffix = randomUUID().slice(0, 8), root = 'infrastructure/arm/telemetry/.operator-private';
  const oldArg = `${root}/revision-20261003-recover-old-${suffix}`, newArg = `${root}/revision-20261003-recover-new-${suffix}`;
  const oldDirectory = await privateDirectory(oldArg), directory = await privateDirectory(newArg);
  t.after(async () => { await rm(oldDirectory, { recursive: true }); await rm(directory, { recursive: true }); });
  await mkdir('infrastructure/opentofu/telemetry/.operator-private', { recursive: true, mode: 0o700 });
  await saveImmutable(oldDirectory, `private-link-${stage}-journal.json`, original.journal);
  const files = new Map([
    [`private-link-head-${target}.json`, pending],
    [`private-link-fence-${target}.json`, { version: 1, targetKey: target, stage, phase: original.phase, intent: original.intent, intentSha256: hash(original.intent) }],
    [`private-link-intent-${hash({ target, stage, attemptId })}.json`, { phase: original.phase, intent: original.intent }],
    [`private-link-continuation-${hash({ targetKey: target, attemptId })}.json`, {
      continuation: original.phase.continuation, phase: original.phase, intent: original.intent, previousHead: original.phase.expectedHead }],
    [`private-link-nsg-adoption-${target}.json`, current.externalAdoption],
  ]);
  let now = at, source = f.source, persisted = 0, calls = 0;
  const inputs = { original, originalDirectory: oldArg, publication: x.io.publication, policyRevision: null,
    costReview: structuredClone(proof.costReview), costEvidence: structuredClone(proof.costEvidence), migrationReview: structuredClone(proof.migrationReview) };
  const retained = retainedReadInvoke(f, x.current, x.io.read);
  const options = { now: () => now, sourceDigest: async () => source, lookup: retainedSourceLookup(f.context, current, original),
    invoke: async args => { calls++; return retained(args); },
    store: { root: directory, read: async (_root, name) => structuredClone(files.get(name) ?? null),
      save: async () => assert.fail('Read-only recovery must not replace the head or fence'),
      saveImmutable: async (_root, name, value) => { assert(!files.has(name)); files.set(name, structuredClone(value)); persisted++; } } };
  const adapter = privateLinkAzureIO(f.c, f.context, current, original.phase, directory, inputs, options.invoke, options);
  const historical = privateLinkAzureIO(f.c, f.context, current, original.phase, oldDirectory, inputs, options.invoke, options);
  const io = { ...x.io, publication: inputs.publication, policyRevision: inputs.policyRevision, costReview: inputs.costReview,
    costEvidence: inputs.costEvidence, migrationReview: inputs.migrationReview, sourceDigest: options.sourceDigest, now: options.now,
    head: adapter.head, verifyOriginal: historical.verifyOriginal, verifySources: adapter.verifySources,
    resolveNoSubmission: adapter.resolveNoSubmission };
  return { original, evidence: current, pending, target, files, io, options, inputs, oldArg, newArg, oldDirectory, directory,
    adapter, setNow: value => { now = value; }, setSource: value => { source = value; },
    get calls() { return calls; }, get persisted() { return persisted; },
    reconcile: () => reconcilePrivateLinkPhase(f.c, f.context, current, original, io) };
}

test('public reconcile/recover bind the latest stopped continuation and originalDirectory without replay or head replacement', async t => {
  const q = await harness(t);
  const proposal = await runPrivateLinkControl(f.c, f.context, q.evidence, stage, 'reconcile', q.newArg, q.inputs, q.options);
  const review = reviewFor(proposal);
  const resolution = await runPrivateLinkControl(f.c, f.context, q.evidence, stage, 'recover', q.newArg,
    { ...q.inputs, proposal, recoveryReview: review }, q.options);
  assert.equal(resolution.proposal.originalSha256, hash(q.original));
  assert.equal(resolution.resolution, 'terminal-abandoned'); assert.equal(resolution.resumable, false); assert.equal(resolution.replayAuthorized, false);
  assert.equal(q.persisted, 1); assert.deepEqual(q.files.get(`private-link-head-${q.target}.json`), q.pending);
  assert.deepEqual(q.files.get(`private-link-no-submission-${hash(q.original.intent)}.json`), { pending: q.pending, record: resolution });
  assert.deepEqual(await load(q.oldDirectory, `private-link-${stage}-journal.json`), stopped.journal);
  assert.equal(hash(stopped), stoppedHash); assert.equal(hash(evidence), evidenceHash);
  verifyPrivateLinkNoSubmissionResolution(f.c, f.context, q.evidence, resolution);
  await assert.rejects(runPrivateLinkControl(f.c, f.context, q.evidence, stage, 'reconcile', q.newArg,
    { ...q.inputs, originalDirectory: q.newArg }, q.options), /NEW_REVISION_DIRECTORY_REQUIRED/);
  await save(q.oldDirectory, `private-link-${stage}-journal.json`, { ...stopped.journal, dispatchAttempted: null });
  await assert.rejects(q.reconcile(), /ORIGINAL_DURABLE_JOURNAL_CHANGED/);
});

test('recovery validates its original independently and rejects legacy/unknown markers before any resolution', async t => {
  for (const [name, mutate] of [
    ['possible submission', value => { value.journal.dispatchAttempted = null; }],
    ['legacy false', value => { value.journal.version = 2; }],
    ['earlier continuation basis', value => { value.phase.continuation.resolution.original.journal.dispatchAttempted = null; }],
    ['altered original preflight', value => { value.preflight.binding.policySha256 = digest('UNIT altered'); }],
  ]) await t.test(name, async t => {
    const q = await harness(t), proposal = await q.reconcile(), changed = structuredClone(q.original); mutate(changed);
    const review = reviewFor(proposal);
    await assert.rejects(recoverPrivateLinkPhase(f.c, f.context, q.evidence, changed, proposal, review, q.io));
    assert.equal(q.persisted, 0);
  });
});

test('reconcile rejects caller, source, cost, head, original journal and cancellation drift after awaits', async t => {
  for (const [name, mutate] of [
    ['caller original swap', q => { q.io.verifySources = async () => { await Promise.resolve(); q.original.approval.requestSha256 = digest('UNIT changed'); }; }],
    ['caller evidence swap', q => { q.io.verifySources = async () => { await Promise.resolve(); q.evidence.originSha256 = digest('UNIT changed'); }; }],
    ['replacement cost review', q => { const run = q.io.head; q.io.head = async (...args) => { const value = await run(...args);
      q.io.costReview = { ...q.io.costReview, userInstruction: 'UNIT substituted' }; return value; }; }],
    ['source drift', q => { const run = q.io.read; q.io.read = async (...args) => { const value = await run(...args); q.setSource(digest('UNIT source')); return value; }; }],
    ['head drift during reads', q => { const run = q.io.read; q.io.read = async (...args) => { const value = await run(...args);
      q.files.set(`private-link-head-${q.target}.json`, { ...q.pending, intentSha256: digest('UNIT changed') }); return value; }; }],
    ['original journal changed after read', q => { q.io.retain = async () => save(q.oldDirectory, `private-link-${stage}-journal.json`,
      { ...stopped.journal, dispatchAttempted: null }); }],
    ['deadline during source', q => { q.io.verifySources = async () => q.setNow(at + 120000); }],
    ['deadline after retain', q => { q.io.retain = async () => q.setNow(at + 120000); }],
    ['cancel during reads', q => { const run = q.io.read; q.io.read = async (...args) => { const value = await run(...args);
      q.io.cancelled = () => true; return value; }; }],
    ['targeted NSG export', q => { const run = q.io.read; q.io.read = (request, ...args) => request.id.endsWith('/flowLogs') ?
      Promise.resolve({ value: [{ id: x.watcherId + '/flowLogs/unit', type: 'Microsoft.Network/networkWatchers/flowLogs',
        properties: { enabled: false, targetResourceId: x.nsg.id } }] }) : run(request, ...args); }],
  ]) await t.test(name, async t => {
    const q = await harness(t); mutate(q);
    await assert.rejects(q.reconcile()); assert.equal(q.persisted, 0);
  });
});

test('recover rejects stale/changed inputs and rechecks guards before immutable canonical resolution', async t => {
  for (const [name, change] of [
    ['expired recovery review', (q, _p, review) => { review.expiresAt = new Date(at).toISOString(); }],
    ['proposal swapped after validation', (q, p) => { q.io.verifySources = async () => { await Promise.resolve(); p.sourceSha256 = digest('UNIT changed'); }; }],
    ['review swapped after validation', (q, _p, review) => { q.io.verifySources = async () => { await Promise.resolve(); review.action = 'UNIT changed'; }; }],
    ['expire after head await', q => { const run = q.io.head; q.io.head = async (...args) => { const value = await run(...args); q.setNow(at + 120000); return value; }; }],
    ['source changed before persistence', q => { const run = q.io.resolveNoSubmission; q.io.resolveNoSubmission = async (...args) => { q.setSource(digest('UNIT changed')); return run(...args); }; }],
    ['cancel before persistence', q => { const run = q.io.resolveNoSubmission; q.io.resolveNoSubmission = async (...args) => { q.io.cancelled = () => true; return run(...args); }; }],
    ['cost changed before persistence', q => { const run = q.io.resolveNoSubmission; q.io.resolveNoSubmission = async (...args) => {
      q.io.costReview = { ...q.io.costReview, expiresAt: new Date(at).toISOString() }; return run(...args); }; }],
  ]) await t.test(name, async t => {
    const q = await harness(t), proposal = await q.reconcile(), review = reviewFor(proposal); change(q, proposal, review);
    await assert.rejects(recoverPrivateLinkPhase(f.c, f.context, q.evidence, q.original, proposal, review, q.io));
    assert.equal(q.persisted, 0);
  });
});

test('reconciliation tokens are neither execute authority nor reusable after the operation', async t => {
  const q = await harness(t), source = q.io.verifySources; let captured;
  q.io.verifySources = async (deadline, validation) => {
    captured = validation;
    for (const token of [validation, structuredClone(validation), { validated: true }]) {
      await assert.rejects(q.adapter.write(q.original.phase, () => {}, async () => {}, async () => {}, at + 120000, token));
    }
    return source(deadline, validation);
  };
  const proposal = await q.reconcile();
  await assert.rejects(q.adapter.write(q.original.phase, () => {}, async () => {}, async () => {}, at + 120000, captured));
  await resolvePrivateLinkNoSubmission(f.c, f.context, q.evidence, q.original, proposal, reviewFor(proposal), q.io);
  assert.equal(q.persisted, 1);
});

test('public recovery includes adapter/originalDirectory CPU in the fixed deadline', async t => {
  const q = await harness(t); let reads = 0;
  const options = { ...q.options, now: () => reads++ === 0 ? at : at + 120000,
    invoke: async () => assert.fail('Expired entry must not spawn reads') };
  await assert.rejects(runPrivateLinkControl(f.c, f.context, q.evidence, stage, 'reconcile', q.newArg, q.inputs, options), /RECOVERY_EXPIRED/);
  assert.equal(q.persisted, 0);
});

test('current runtime still rejects pre-RBAC evidence without starting any resource reads', async t => {
  const q = await harness(t);
  await assert.rejects(currentPrivateLinkRuntimeProof(f.c, f.context, q.evidence, q.directory,
    async () => assert.fail('Incomplete runtime history must not read'), q.options), /RUNTIME_PREREQUISITES_REQUIRED/);
});
