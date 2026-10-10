import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { analyzeEffectivePolicies } from '../effective-policy.mjs';
import { buildQueuePhase, qualifiedQueueRecords, queuePreflightBaseline, QueueTopologyController,
  verifyQueuePreflight, verifyQueueRecord, verifyQueueWhatIf } from '../durable-queue.mjs';
import { emptyNspEvidence, nspLineageHead, nspReadinessBinding, nspTopology,
  verifyNspAdmission, verifyNspQueuePreflight } from '../nsp.mjs';
import { emptyPolicySnapshot } from './effective-policy.fixture.mjs';
import { queuePhaseFixture } from './durable-queue.fixture.mjs';
import { queueAdoptionFixture, rebindAdoption } from './queue-adoption.fixture.mjs';
import { nspAdmissionFixture, nspBillingFixture, nspPhaseFixture } from './nsp.fixture.mjs';

const hash = value => digest(json(value));
function operationalFixture(f, admission, name, priorRecords) {
  const q = queuePhaseFixture({ ...f, origin: f.foundationOrigin }, name, priorRecords);
  const context = { adoption: priorRecords['queue-storage'], admission };
  const phase = buildQueuePhase(f.c, name, f.topology, f.identity, context);
  const proof = q.proof, approval = q.approval;
  const observation = structuredClone(admission.records.at(-1).receipt.observation);
  observation.startedAt = f.at; observation.completedAt = f.at;
  const billing = nspBillingFixture(f, admission.topology, f.at), head = nspLineageHead(admission);
  Object.assign(proof, nspReadinessBinding(context, head, billing.review, observation), {
    phaseSha256: hash(phase), networkObservation: observation, networkBillingReview: billing.review,
    networkBillingEvidence: billing.evidence, networkLineageHead: head,
  });
  proof.queuePreview = verifyQueueWhatIf(f.c, phase, f.topology, q.whatIf, proof.preservedIds, f.identity, context);
  proof.queuePreviewSha256 = hash(proof.queuePreview);
  proof.effectivePolicy = analyzeEffectivePolicies(phase, emptyPolicySnapshot(phase));
  proof.effectivePolicySha256 = hash(proof.effectivePolicy);
  proof.baselineSha256 = queuePreflightBaseline(proof);
  approval.phaseSha256 = hash(phase); approval.baselineSha256 = proof.baselineSha256;
  const controller = new QueueTopologyController(f.c, phase, f.topology, q.review, q.io, context);
  return { ...q, phase, controller, context,
    record: () => ({ ...q.record(), version: 2, kind: 'reviewed-nsp-queue-phase', phase,
      publication: { commitSha: 'd'.repeat(40), sourceSha256: f.source }, networkAdmission: admission }),
    dispatched: () => q.dispatched };
}

async function fixture() {
  const f = await queueAdoptionFixture();
  const admission = await nspAdmissionFixture(f, f.adoption);
  f.at += 5000;
  return { ...f, admission };
}

test('real NSP lock qualification accepts authorized account modification metadata with unchanged creation identity', async () => {
  const f = await queueAdoptionFixture(), account = f.topology.ids.account;
  const createdAt = f.adoption.origin.firstReadback.resources[account].properties.creationTime;
  const metadata = { createdAt, createdBy: f.c.operatorPrincipalId, createdByType: 'User',
    lastModifiedAt: createdAt, lastModifiedBy: f.c.operatorPrincipalId, lastModifiedByType: 'User' };
  f.adoption.origin.firstReadback.resources[account].systemData = structuredClone(metadata);
  f.adoption.proposal.observation.resources[account].systemData = structuredClone(metadata);
  rebindAdoption(f.adoption);
  const evidence = emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
  for (const name of ['nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association', 'nsp-subscription-admission']) {
    const phase = nspPhaseFixture(f, f.adoption, evidence, name);
    if (name === 'nsp-storage-lock') Object.assign(phase.after.resources[account].systemData, {
      lastModifiedAt: new Date(f.at + 2000).toISOString(), lastModifiedBy: f.c.runId, lastModifiedByType: 'Application',
    });
    await phase.controller.execute(phase.approval);
    evidence.records.push(phase.record());
  }
  const receipt = verifyNspAdmission(f.c, evidence, f.topology, f.adoption);
  assert.equal(receipt.stage, 'subscription-admission-converged');
  assert.equal(receipt.observation.resources[account].systemData.createdAt, createdAt);
  assert.equal(receipt.observation.resources[account].systemData.lastModifiedByType, 'Application');
  assert.equal(f.adoption.origin.firstReadback.resources[account].systemData.lastModifiedByType, 'User');
});

test('v2 operational phase binds real Enforced NSP evidence, retained preflight and separate role/assignment approvals', async () => {
  const f = await fixture(), records = { 'queue-storage': f.adoption };
  const network = verifyNspAdmission(f.c, f.admission, f.topology, f.adoption);
  assert.equal(network.runtimeQualified, false);
  assert.equal(network.queueGrantsAuthorized, false);
  const role = operationalFixture(f, f.admission, 'queue-role', structuredClone(records));
  assert.equal(role.phase.version, 2);
  assert.deepEqual(role.phase.networkBinding, { adoptionSha256: hash(f.adoption), admissionSha256: hash(f.admission) });
  assert.deepEqual(role.phase.template, buildQueuePhase(f.c, 'queue-role', f.topology, f.identity).template);
  assert.deepEqual(verifyNspQueuePreflight(f.c, role.context, role.proof, f.at), role.proof.networkPreflight);
  verifyQueuePreflight(f.c, role.phase, f.topology, role.proof, role.context, f.at);
  assert.throws(() => qualifiedQueueRecords(f.c, records, f.topology));
  await role.controller.execute(role.approval);
  records['queue-role'] = role.record();
  verifyQueueRecord(f.c, records['queue-role']);
  assert.equal(Object.keys(qualifiedQueueRecords(f.c, records, f.topology, 'queue-role')).length, 4);
  assert.throws(() => qualifiedQueueRecords(f.c, records, f.topology));
  f.at += 1000;
  const assignment = operationalFixture(f, f.admission, 'queue-assignment', structuredClone(records));
  await assignment.controller.execute(assignment.approval);
  records['queue-assignment'] = assignment.record();
  verifyQueueRecord(f.c, records['queue-assignment']);
  assert.equal(Object.keys(qualifiedQueueRecords(f.c, records, f.topology)).length, 5);
  assert.equal(records['queue-storage'].observation.qualified, false);
  assert.equal(records['queue-assignment'].receipt.ingestionEnabled, false);
  assert.equal(records['queue-assignment'].receipt.qualificationKind, 'new-durable-queue-phase');
  const cyclic = structuredClone(records['queue-assignment']);
  cyclic.priorRecords['queue-role'] = cyclic;
  assert.throws(() => verifyQueueRecord(f.c, cyclic), /QUEUE_PREREQUISITE_CHANGED/);
});

test('v2 baseline and guard cannot accept naked hashes, absent full evidence or forged qualification', async t => {
  const f = await fixture();
  for (const [label, mutate] of [
    ['naked hash', p => { delete p.networkObservation; }],
    ['no billing evidence', p => { delete p.networkBillingEvidence; }],
    ['no billing review', p => { delete p.networkBillingReview; }],
    ['no lineage head', p => { delete p.networkLineageHead; }],
    ['wrong source', p => { p.sourceSha256 = digest('UNIT changed source'); }],
    ['wrong head', p => { p.networkLineageHead = { qualified: true }; }],
    ['wrong network binding', p => { p.networkBinding.adoptionSha256 = digest('UNIT different adoption'); }],
    ['observation qualified flag', p => { p.networkObservation.qualified = true; }],
    ['missing copied rule', p => { p.networkObservation.configuration.properties.profile.accessRules = []; }],
    ['wrong association mode', p => { p.networkObservation.configuration.properties.resourceAssociation.accessMode = 'Learning'; }],
    ['missing billing acceptance', p => { p.networkBillingReview.cost.explicitUncertaintyAccepted = false; }],
    ['missing ARM policy', p => { delete p.effectivePolicyVersion; }],
  ]) await t.test(label, async () => {
    const q = operationalFixture(f, f.admission, 'queue-role', { 'queue-storage': f.adoption });
    mutate(q.proof);
    await assert.rejects(q.controller.execute(q.approval));
    assert.equal(q.dispatched(), false);
  });
});

test('v2 records reject rehashed operational context substitution and v1 downgrade', async t => {
  const f = await fixture(), q = operationalFixture(f, f.admission, 'queue-role', { 'queue-storage': f.adoption });
  await q.controller.execute(q.approval);
  const record = q.record();
  for (const [label, mutate] of [
    ['qualified instead of network', r => { r.networkAdmission = { qualified: true }; }],
    ['changed admission chain', r => { r.networkAdmission.records.pop(); }],
    ['wrong adoption', r => { r.priorRecords['queue-storage'].identity.properties.principalId = f.c.operatorPrincipalId; }],
    ['v1 downgrade', r => { r.version = 1; r.kind = 'reviewed-queue-phase'; delete r.networkAdmission; }],
    ['wrong phase binding', r => { r.phase.networkBinding.admissionSha256 = digest('UNIT other'); }],
    ['extra permission', r => { r.phase.resources[0].expected.properties.permissions[0].dataActions.push('*'); }],
    ['forged current observation', r => { r.preflight.networkObservation = { qualified: true }; }],
  ]) await t.test(label, () => {
    const changed = structuredClone(record); mutate(changed);
    changed.approval.phaseSha256 = hash(changed.phase);
    changed.approval.receiptsSha256 = hash(changed.priorRecords);
    changed.journal.approvalSha256 = hash(changed.approval);
    changed.journal.phaseSha256 = hash(changed.phase);
    changed.receipt.approvalSha256 = hash(changed.approval);
    changed.receipt.phaseSha256 = hash(changed.phase);
    changed.journal.receiptSha256 = hash(changed.receipt);
    assert.throws(() => verifyQueueRecord(f.c, changed));
  });
});

test('operational context and freshness are checked before dispatch even if the phase object is later changed', async () => {
  const f = await fixture();
  const records = { 'queue-storage': f.adoption };
  const changed = operationalFixture(f, f.admission, 'queue-role', records);
  changed.phase.resources[0].expected.properties.permissions[0].dataActions.push('*');
  await assert.rejects(changed.controller.execute(changed.approval));
  assert.equal(changed.dispatched(), false);
  const absent = operationalFixture(f, f.admission, 'queue-role', records);
  const controller = new QueueTopologyController(f.c, absent.phase, f.topology, absent.review, absent.io);
  await assert.rejects(controller.execute(absent.approval));
  assert.equal(absent.dispatched(), false);
});
