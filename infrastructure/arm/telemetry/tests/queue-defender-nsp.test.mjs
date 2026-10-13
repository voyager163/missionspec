import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digest, json } from '../definition.mjs';
import { buildQueuePhase, queuePreflightBaseline, verifyQueueWhatIf, verifyQueueRecord, QueueTopologyController } from '../durable-queue.mjs';
import { analyzeEffectivePolicies } from '../effective-policy.mjs';
import { emptyPolicySnapshot } from './effective-policy.fixture.mjs';
import { NSP_AUTHORITY, emptyNspEvidence, nspTopology, nspState, nspLineageHead, nspPendingHead, nspIntentFence, nspTargetKey, nspReadinessBinding, nspResourceInventory,
  verifyNspObservation, verifyNspReview, verifyNspEvidence, verifyNspAdmission, verifyNspReconciliation } from '../nsp.mjs';
import { collectNspObservation, nspReadRequests } from '../nsp-controller.mjs';
import { collectNspReconciliation, qualifyNspReconciliation, verifyNspReconciledRecord } from '../nsp-reconciliation.mjs';
import { currentNspAdmission, readBatch, sourceDigest } from '../controller.mjs';
import { queuePhaseFixture } from './durable-queue.fixture.mjs';
import { nspBillingFixture } from './nsp.fixture.mjs';
import { defenderNspPhaseFixture, queueDefenderFixture, unitGuid } from './queue-defender.fixture.mjs';

const hash = value => digest(json(value));
const f = await queueDefenderFixture();
const initial = emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
function readIO(network, observation, now = observation.completedAt) {
  const requests = nspReadRequests(network), values = new Map(Object.entries(observation.resources));
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues']) {
    values.set(requests[key].id, observation[key]);
  }
  for (const [id, request] of Object.entries(requests.diagnostics)) values.set(request.id, observation.diagnostics[id]);
  if (observation.configuration) values.set(observation.configuration.id, observation.configuration);
  for (const [key, request] of Object.entries(f.requests)) values.set(request.id, observation.defender[key]);
  const calls = [], io = { now: () => now, batch: readBatch, read: async request => {
    assert(values.has(request.id), request.id);
    calls.push(request); return structuredClone(values.get(request.id));
  } };
  return { io, calls, values };
}

test('v3-derived NSP requires an exact current review and explicit queue-only risk acknowledgment before effects', async t => {
  const q = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary');
  assert.equal(initial.topology.version, 2);
  assert.equal(q.proof.topologyReview.version, 2);
  verifyNspReview(f.c, initial.topology, q.proof.topologyReview, f.source, q.proof.completedAt, q.proof.observation);
  for (const [name, change] of [
    ['missing acknowledgment', review => { delete review.queueOnlyRisk; }],
    ['legacy review', review => { review.version = 1; }],
    ['generic risk waiver', review => { review.queueOnlyRisk.action = 'allow-networking'; }],
    ['false risk acceptance', review => { review.queueOnlyRisk.explicitInterruptionRiskAccepted = false; }],
    ['functional clearance', review => { review.queueOnlyRisk.functionalBlobProtectionQualified = true; }],
    ['Blob uploads', review => { review.queueOnlyRisk.blobUploadsAuthorized = true; }],
    ['extra grant', review => { review.queueOnlyRisk.additionalRulesAuthorized = true; }],
    ['instruction substitution', review => { review.queueOnlyRisk.userInstruction += ' changed'; }],
    ['wrong state', review => { review.queueOnlyRisk.currentStateSha256 = digest('different state'); }],
    ['wrong topology', review => { review.topologySha256 = digest('different topology'); }],
    ['wrong source', review => { review.sourceSha256 = digest('different source'); }],
    ['expired review', review => { review.expiresAt = review.approvedAt; }],
  ]) await t.test(name, async () => {
    const phase = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary');
    change(phase.proof.topologyReview);
    await assert.rejects(phase.controller.execute(phase.approval));
    assert.equal(phase.writes, 0);
  });
  const legacy = structuredClone(initial.topology); legacy.version = 1; delete legacy.defenderEvidenceSha256;
  assert.throws(() => verifyNspReview(f.c, legacy, q.proof.topologyReview, f.source, q.proof.completedAt, q.proof.observation), /CLOSED_/);
});

test('initial inventory and reconciliation require full exact integration before any NSP receipt', () => {
  const q = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary');
  assert.deepEqual(Object.keys(nspResourceInventory(f.c, initial, f.adoption)),
    [f.evidence.snapshot.topic.id, f.evidence.snapshot.subscription.id]);
  verifyNspReconciliation(f.c, initial, f.adoption, q.proof.observation, nspLineageHead(initial), q.proof.completedAt);
  const changed = structuredClone(q.proof.observation);
  changed.defender.subscription.properties.destination.properties.azureActiveDirectoryTenantId = f.c.tenantId;
  assert.throws(() => verifyNspReconciliation(f.c, initial, f.adoption, changed, nspLineageHead(initial), q.proof.completedAt), /QUEUE_/);
});

test('NSP observation hashes do not depend on resource or inventory read completion order', async () => {
  const q = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary');
  const forward = readIO(initial.topology, q.proof.observation);
  const reverse = readIO(initial.topology, q.proof.observation);
  reverse.io.batch = async (values, operation) => {
    const results = Array(values.length);
    for (let index = values.length - 1; index >= 0; index--) results[index] = await operation(values[index]);
    return results;
  };
  const context = { c: f.c, adoption: f.adoption }, deadline = q.proof.completedAt + 120000;
  const first = await collectNspObservation(initial.topology, forward.io, deadline, context);
  const second = await collectNspObservation(initial.topology, reverse.io, deadline, context);
  assert.deepEqual(first, second);
  assert.equal(hash(first), hash(second), 'Serialization must not bind asynchronous completion order');
  assert.equal(hash(nspState(first)), hash(nspState(second)));
  const review = structuredClone(q.proof.topologyReview);
  review.queueOnlyRisk.currentStateSha256 = hash(nspState(first));
  verifyNspReview(f.c, initial.topology, review, f.source, q.proof.completedAt, second);
  const changed = structuredClone(second);
  changed.resources[f.topology.ids.account].properties.minimumTlsVersion = 'TLS1_0';
  assert.notEqual(hash(nspState(changed)), review.queueOnlyRisk.currentStateSha256);
  assert.throws(() => verifyNspReview(f.c, initial.topology, review, f.source, q.proof.completedAt, changed),
    /NSP_EXACT_QUEUE_ONLY_RISK_ACKNOWLEDGMENT_REQUIRED/);
});

test('new NSP collector requires verified context and exact current reads without any Blob data operation', async t => {
  const q = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary'), x = readIO(initial.topology, q.proof.observation);
  const observation = await collectNspObservation(initial.topology, x.io, q.proof.completedAt + 120000, { c: f.c, adoption: f.adoption });
  verifyNspObservation(f.c, initial.topology, f.adoption, observation, 'adopted-disabled');
  assert.deepEqual(nspState(observation), nspState(q.proof.observation));
  assert(x.calls.every(request => !/blobServices|listKeys|listServiceSas/iu.test(request.id)));
  assert.equal(x.calls.filter(request => Object.values(f.requests).some(value => value.id === request.id)).length, 10);
  await assert.rejects(collectNspObservation(initial.topology, x.io, q.proof.completedAt + 120000), /CLOSED_/);
  for (const [key, target] of Object.entries(f.requests)) await t.test(key, async () => {
    const io = { ...x.io, read: async request => {
      if (request.id === target.id) throw new Error('UNIT_CURRENT_READ_FAILED');
      return x.io.read(request);
    } };
    await assert.rejects(collectNspObservation(initial.topology, io, q.proof.completedAt + 120000,
      { c: f.c, adoption: f.adoption }), /UNIT_CURRENT_READ_FAILED/);
    const phase = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary');
    phase.io.verifyCurrent = async (_proof, deadline) => {
      await collectNspObservation(initial.topology, io, deadline, { c: f.c, adoption: f.adoption });
    };
    await assert.rejects(phase.controller.execute(phase.approval));
    assert.equal(phase.writes, 0);
  });
});

let admission;
test('all setup stages retain exact Defender configuration and durable queue-only risk acknowledgment', async () => {
  admission = structuredClone(initial);
  for (const name of ['nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association', 'nsp-subscription-admission']) {
    const q = defenderNspPhaseFixture(f, admission, name);
    await q.controller.execute(q.approval);
    admission.records.push(q.record());
    verifyNspEvidence(f.c, admission, f.topology, f.adoption);
    assert.equal(q.writes, 1);
    if (name === 'nsp-storage-lock') {
      assert.deepEqual(q.phase.resources[0].expected.properties.networkAcls.resourceAccessRules,
        f.adoption.observation.resources[f.topology.ids.account].properties.networkAcls.resourceAccessRules);
      assert.deepEqual(q.phase.request.body, { properties: { publicNetworkAccess: 'SecuredByPerimeter' } });
    }
    assert.deepEqual(q.after.defender, f.evidence.snapshot);
    assert.equal(q.record().preflight.topologyReview.queueOnlyRisk.explicitInterruptionRiskAccepted, true);
  }
  const receipt = verifyNspAdmission(f.c, admission, f.topology, f.adoption);
  assert.equal(receipt.stage, 'subscription-admission-converged');
  assert.equal(receipt.runtimeQualified, false);
  assert.equal(receipt.observation.defender.settings.properties.isEnabled, true);
  assert.equal(Object.keys(nspResourceInventory(f.c, admission, f.adoption)).length, 9);
  assert.throws(() => verifyNspReview(f.c, admission.topology, admission.records[0].preflight.topologyReview,
    f.source, receipt.observation.completedAt, receipt.observation), /RISK_ACKNOWLEDGMENT/);
});

test('fresh operational admission rechecks every integration read and fences current failures', async () => {
  const now = f.at + 10000, observation = structuredClone(admission.records.at(-1).receipt.observation);
  observation.startedAt = now; observation.completedAt = now;
  const x = readIO(admission.topology, observation, now), directory = await mkdtemp(join(tmpdir(), 'missionspec-defender-current-'));
  const currentSource = await sourceDigest(), billing = nspBillingFixture({ ...f, source: currentSource }, admission.topology, now);
  const context = { adoption: f.adoption, admission }, evidence = { nspBillingReview: billing.review, nspBillingEvidence: billing.evidence };
  let blockedId = null, calls = 0;
  const invoke = async args => {
    assert.equal(args[args.indexOf('--method') + 1], 'GET');
    const request = new URL(args[args.indexOf('--url') + 1]);
    if (request.pathname === blockedId) throw new Error('UNIT_BACKEND_UNAVAILABLE');
    assert(x.values.has(request.pathname), request.pathname); calls++;
    return structuredClone(x.values.get(request.pathname));
  };
  const tip = admission.records.at(-1);
  const reservation = { phase: tip.phase, approvalSha256: hash(tip.approval), journal: {
    ...Object.fromEntries(['version', 'phaseSha256', 'approvalSha256', 'requestSha256', 'predecessorSha256', 'intentAt']
      .map(key => [key, tip.journal[key]])), outcome: 'submission-possible', transportDispatchAttempted: false } };
  const fence = nspIntentFence(admission, reservation), headFiles = new Map([
    [`nsp-head-${nspTargetKey(admission.topology)}.json`, nspLineageHead(admission)],
    [`nsp-intent-fence-${nspTargetKey(admission.topology)}.json`, fence],
    [`nsp-intent-${fence.intentKey}.json`, reservation],
  ]);
  const options = { now: () => now, headRead: async (_root, name) => structuredClone(headFiles.get(name) ?? null) };
  try {
    const proof = await currentNspAdmission(f.c, context, evidence, directory, now + 120000, invoke, options);
    assert.deepEqual(proof.networkObservation.defender, f.evidence.snapshot);
    for (const request of Object.values(f.requests)) {
      blockedId = request.id;
      await assert.rejects(currentNspAdmission(f.c, context, evidence, directory, now + 120000, invoke, options), /UNIT_BACKEND_UNAVAILABLE/);
    }
    assert(calls > 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('operational role record accepts only the v3 adopted storage prerequisite and retains the reviewed network chain', async () => {
  const at = f.at + 10000, local = { ...f, at, origin: f.foundationOrigin };
  const records = { 'queue-storage': f.adoption }, q = queuePhaseFixture(local, 'queue-role', records);
  const context = { adoption: f.adoption, admission }, phase = buildQueuePhase(f.c, 'queue-role', f.topology, f.identity, context);
  const observation = structuredClone(admission.records.at(-1).receipt.observation);
  observation.startedAt = at; observation.completedAt = at;
  const billing = nspBillingFixture(local, admission.topology, at), head = nspLineageHead(admission);
  Object.assign(q.proof, nspReadinessBinding(context, head, billing.review, observation), {
    phaseSha256: hash(phase), networkObservation: observation, networkBillingReview: billing.review,
    networkBillingEvidence: billing.evidence, networkLineageHead: head,
  });
  q.proof.queuePreview = verifyQueueWhatIf(f.c, phase, f.topology, q.whatIf, q.proof.preservedIds, f.identity, context);
  q.proof.queuePreviewSha256 = hash(q.proof.queuePreview);
  q.proof.effectivePolicy = analyzeEffectivePolicies(phase, emptyPolicySnapshot(phase));
  q.proof.effectivePolicySha256 = hash(q.proof.effectivePolicy);
  q.proof.baselineSha256 = queuePreflightBaseline(q.proof);
  Object.assign(q.approval, { phaseSha256: hash(phase), baselineSha256: q.proof.baselineSha256 });
  const controller = new QueueTopologyController(f.c, phase, f.topology, q.review, q.io, context);
  await controller.execute(q.approval);
  const record = { ...q.record(), version: 2, kind: 'reviewed-nsp-queue-phase', phase, networkAdmission: admission };
  verifyQueueRecord(f.c, record);
  assert.equal(record.priorRecords['queue-storage'].version, 3);
  const missingRisk = structuredClone(record);
  delete missingRisk.networkAdmission.records[0].preflight.topologyReview.queueOnlyRisk;
  assert.throws(() => verifyQueueRecord(f.c, missingRisk));
});

test('deny and readmit require new current risk reviews without changing the inherited Defender integration', async () => {
  const network = structuredClone(admission);
  for (const name of ['nsp-network-deny', 'nsp-subscription-readmit']) {
    const instance = { version: 1, id: unitGuid(1000 + network.records.length),
      predecessorSha256: hash(network.records.at(-1)), previousInstanceIds: network.records.map(record => record.phase.instance?.id).filter(Boolean) };
    const q = defenderNspPhaseFixture(f, network, name, instance);
    await q.controller.execute(q.approval);
    network.records.push(q.record());
    verifyNspEvidence(f.c, network, f.topology, f.adoption);
    assert.equal(q.writes, 1);
    assert.deepEqual(q.after.defender, f.evidence.snapshot);
    assert.equal(q.proof.topologyReview.queueOnlyRisk.blobUploadsAuthorized, false);
  }
  assert.equal(verifyNspAdmission(f.c, network, f.topology, f.adoption).stage, 'subscription-readmission-converged');
});

test('stopped-attempt reconciliation freshly preserves the complete Defender state and never rewrites the failed attempt', async () => {
  const q = defenderNspPhaseFixture(f, initial, 'nsp-empty-boundary'), originalObserve = q.io.observe;
  let reservation;
  q.io.reserve = async journal => { reservation = structuredClone({ phase: q.phase, approvalSha256: hash(q.approval), journal }); };
  q.io.observe = async deadline => ({ ...await originalObserve(deadline), observation: q.proof.observation });
  await assert.rejects(q.controller.execute(q.approval), /STOPPED_RESOURCES_PRESERVED/);
  const attempt = q.record(), original = { ...Object.fromEntries(
    ['phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'journal', 'receipt']
      .map(key => [key, structuredClone(attempt[key])])), reservation };
  const originalBytes = json(original), now = q.proof.startedAt + 121000;
  const x = readIO(initial.topology, q.after, now), billing = nspBillingFixture(f, initial.topology, now);
  const deployment = structuredClone((await originalObserve(now + 120000)).deployment);
  deployment.properties.outputResources = q.phase.resources.map(({ id }) => ({ id }));
  x.values.set(q.phase.deploymentId, deployment);
  x.values.set(`${q.phase.deploymentId}/operations`, { value: q.phase.resources.map((resource, index) => ({
    id: `${q.phase.deploymentId}/operations/unit-${index}`, operationId: `unit-${index}`,
    properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded', statusCode: 'OK',
      targetResource: { id: resource.id, resourceName: resource.expected.name, resourceType: resource.type } },
  })) });
  const pending = nspPendingHead(initial, q.phase, reservation.journal);
  let appended = 0;
  const io = { ...x.io, sourceDigest: async () => f.source, pendingHead: async () => pending,
    billingReview: billing.review, billingEvidence: billing.evidence,
    compareAndAppend: async () => { appended++; } };
  const proposal = await collectNspReconciliation(f.c, original, f.topology, f.adoption, initial, io);
  const review = { version: 1, action: 'accept-exact-nsp-current-state-reconciliation', configSha256: hash(f.c),
    topologySha256: hash(initial.topology), phaseSha256: hash(q.phase), originalSha256: hash(original),
    proposalSha256: hash(proposal), pendingHeadSha256: hash(pending), sourceSha256: f.source,
    reviewedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString(), authority: NSP_AUTHORITY };
  const publication = { commitSha: 'f'.repeat(40), sourceSha256: f.source };
  const record = await qualifyNspReconciliation(f.c, original, f.topology, f.adoption, initial, proposal, review, publication, io);
  verifyNspReconciledRecord(f.c, record, f.topology, f.adoption, initial);
  assert.equal(appended, 1); assert.equal(json(original), originalBytes);
  assert.equal(record.receipt.originalExecutionQualified, false);
  for (const target of Object.values(f.requests)) {
    const failed = { ...io, read: async (request, deadline) => {
      if (request.id === target.id) throw new Error('UNIT_RECONCILIATION_READ_FAILED');
      return io.read(request, deadline);
    } };
    await assert.rejects(qualifyNspReconciliation(f.c, original, f.topology, f.adoption, initial,
      proposal, review, publication, failed), /UNIT_RECONCILIATION_READ_FAILED/);
  }
  assert.equal(appended, 1); assert.equal(json(original), originalBytes);
});
