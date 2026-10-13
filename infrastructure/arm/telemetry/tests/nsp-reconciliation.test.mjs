import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { NSP_AUTHORITY, nspTopology, emptyNspEvidence, nspPendingHead, nspLineageHead,
  verifyNspEvidence, verifyNspAdmission, verifyNspQueuePreflight, nspReadinessBinding } from '../nsp.mjs';
import { nspReadRequests } from '../nsp-controller.mjs';
import { collectNspReconciliation, qualifyNspReconciliation, verifyNspStoppedAttempt,
  verifyNspReconciliationProposal, verifyNspReconciledRecord } from '../nsp-reconciliation.mjs';
import { readBatch, readNspHead } from '../controller.mjs';
import { queueAdoptionFixture } from './queue-adoption.fixture.mjs';
import { nspPhaseFixture, nspBillingFixture, nspAdmissionFixture } from './nsp.fixture.mjs';

const hash = value => digest(json(value));
// These are synthetic request/response records, never retained cloud authority.
async function fixture(deny = false) {
  const f = await queueAdoptionFixture();
  const prior = deny ? await nspAdmissionFixture(f, f.adoption) : emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
  const name = deny ? 'nsp-network-deny' : 'nsp-empty-boundary';
  const instance = deny ? { version: 1, id: '00000000-0000-4000-8000-000000000097',
    predecessorSha256: hash(prior.records.at(-1)), previousInstanceIds: [] } : null;
  const q = nspPhaseFixture(f, f.adoption, prior, name, instance), observe = q.io.observe;
  let reservation;
  q.io.reserve = async journal => {
    reservation = structuredClone({ phase: q.phase, approvalSha256: hash(q.approval), journal });
  };
  q.io.observe = async deadline => ({ ...await observe(deadline), observation: q.proof.observation });
  await assert.rejects(q.controller.execute(q.approval), /STOPPED_RESOURCES_PRESERVED/);
  assert.equal(q.writes, 1);
  const attempt = q.record();
  const original = Object.fromEntries(['phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'journal', 'receipt']
    .map(key => [key, structuredClone(attempt[key])]));
  original.reservation = reservation;
  let now = q.proof.startedAt + 121000, head = nspPendingHead(prior, q.phase, reservation.journal), commits = 0;
  const pendingHead = structuredClone(head), beforeBytes = json(original);
  const billing = nspBillingFixture(f, prior.topology, now), requests = nspReadRequests(prior.topology);
  const state = structuredClone(q.after), values = new Map(Object.entries(state.resources));
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues']) {
    values.set(requests[key].id, state[key]);
  }
  for (const [id, request] of Object.entries(requests.diagnostics)) values.set(request.id, state.diagnostics[id]);
  if (state.configuration) values.set(state.configuration.id, state.configuration);
  if (q.phase.deploymentId) {
    const deployment = structuredClone((await observe(now + 120000)).deployment);
    deployment.properties.outputResources = q.phase.resources.map(({ id }) => ({ id }));
    values.set(q.phase.deploymentId, deployment);
    values.set(`${q.phase.deploymentId}/operations`, { value: q.phase.resources.map((resource, index) => ({
      id: `${q.phase.deploymentId}/operations/unit-${index}`, operationId: `unit-${index}`,
      properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded', statusCode: 'OK',
        targetResource: { id: resource.id, resourceName: resource.expected.name, resourceType: resource.type } },
    })) });
  }
  const calls = [];
  const io = { now: () => now, sourceDigest: async () => f.source, batch: readBatch,
    billingReview: billing.review, billingEvidence: billing.evidence, pendingHead: async () => structuredClone(head),
    read: async (request, deadline) => {
      assert(deadline <= now + 120000);
      assert.deepEqual(Object.keys(request).sort(), ['apiVersion', 'filter', 'id']);
      assert(values.has(request.id), request.id);
      calls.push(request);
      return structuredClone(values.get(request.id));
    },
    compareAndAppend: async (expected, record, next) => {
      assert.deepEqual(head, expected);
      assert.equal(json(original), beforeBytes);
      commits++;
      head = structuredClone(next);
    } };
  const proposal = await collectNspReconciliation(f.c, original, f.topology, f.adoption, prior, io);
  now++;
  const review = { version: 1, action: 'accept-exact-nsp-current-state-reconciliation', configSha256: hash(f.c),
    topologySha256: hash(prior.topology), phaseSha256: hash(original.phase), originalSha256: hash(original),
    proposalSha256: hash(proposal), pendingHeadSha256: hash(proposal.pendingHead), sourceSha256: f.source,
    reviewedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString(), authority: NSP_AUTHORITY };
  const publication = { commitSha: 'f'.repeat(40), sourceSha256: f.source };
  const qualify = () => qualifyNspReconciliation(f.c, original, f.topology, f.adoption, prior, proposal, review, publication, io);
  return { f, prior, q, original, beforeBytes, pendingHead, billing, proposal, review, publication, values, calls, io, qualify,
    advance: ms => { now += ms; }, setHead: value => { head = value; }, get commits() { return commits; }, get head() { return head; } };
}

test('genuine late convergence appends reviewed current state without changing the failed original or replaying it', async () => {
  const x = await fixture(), record = await x.qualify();
  assert.equal(record.version, 2);
  assert.equal(record.kind, 'reviewed-nsp-reconciliation');
  assert.equal(record.original.journal.outcome, 'reconciliation-required');
  assert.equal(record.original.receipt, null);
  assert.equal(record.receipt.originalExecutionQualified, false);
  assert.equal(record.receipt.outsideOriginalDeadline, true);
  assert.equal(record.receipt.originalHistoryModified, false);
  assert.equal(record.receipt.runtimeQualified, false);
  assert.equal(x.q.writes, 1);
  assert.equal(x.commits, 1);
  assert.equal(json(x.original), x.beforeBytes);
  const evidence = { ...x.prior, records: [record] };
  assert.equal(verifyNspEvidence(x.f.c, evidence, x.f.topology, x.f.adoption).stage, 'empty-boundary');
  assert.deepEqual(x.head, nspLineageHead(evidence));
  await assert.rejects(x.qualify(), /PENDING_HEAD_CHANGED/);
  assert.equal(x.commits, 1);
});

test('missing/no-dispatch provenance and changed original request remain quarantined', async t => {
  const x = await fixture();
  for (const [name, mutate] of [
    ['no dispatch', o => { o.journal.transportDispatchAttempted = false; }],
    ['no stopped outcome', o => { o.journal.outcome = 'submission-possible'; }],
    ['no reservation', o => { delete o.reservation; }],
    ['changed intent time', o => { o.reservation.journal.intentAt = new Date(0).toISOString(); }],
    ['changed request', o => { o.phase.request.body.properties.mode = 'Complete'; }],
    ['missing original policy', o => { delete o.preflight.effectivePolicyVersion; }],
    ['changed original approval', o => { o.approval.sourceSha256 = digest('changed'); }],
  ]) await t.test(name, () => {
    const original = structuredClone(x.original); mutate(original);
    assert.throws(() => verifyNspStoppedAttempt(x.f.c, original, x.f.topology, x.f.adoption, x.prior, x.pendingHead));
  });
});

test('partial provider state, wrong generation and missing deployment operations cannot be approved as late success', async t => {
  const x = await fixture(), perimeter = x.prior.topology.ids.perimeter;
  for (const [name, mutate] of [
    ['missing expected resource', p => { p.state.observation.resources[perimeter] = null; }],
    ['different generation', p => { p.state.observation.resources[perimeter].systemData.createdAt = new Date(0).toISOString(); }],
    ['missing outputResources', p => { delete p.state.deployment.properties.outputResources; }],
    ['wrong template hash', p => { p.state.deployment.properties.templateHash = 'wrong'; }],
    ['missing operations', p => { p.state.operations.value = []; }],
    ['incomplete operations', p => { p.state.operations.nextLink = 'more'; }],
    ['different target operation', p => { p.state.operations.value[0].properties.targetResource.id += '-foreign'; }],
    ['modify instead of create', p => { p.state.operations.value[0].properties.provisioningOperation = 'Update'; }],
    ['missing billing acknowledgment', p => { p.networkBillingReview.cost.explicitUncertaintyAccepted = false; }],
  ]) await t.test(name, () => {
    const proposal = structuredClone(x.proposal); mutate(proposal);
    assert.throws(() => verifyNspReconciliationProposal(x.f.c, x.original, x.f.topology, x.f.adoption, x.prior, proposal, x.io.now()));
  });
});

test('late-state review, current source and exact pending head are rechecked before append', async t => {
  for (const mode of ['expired-review', 'stale-observation', 'changed-source', 'changed-head', 'raced-head', 'changed-state']) await t.test(mode, async () => {
    const x = await fixture(), pending = x.io.pendingHead;
    if (mode === 'expired-review') x.review.expiresAt = new Date(x.io.now()).toISOString();
    if (mode === 'stale-observation') x.advance(300001);
    if (mode === 'changed-source') x.io.sourceDigest = async () => digest('UNIT changed source');
    if (mode === 'changed-head') x.setHead({ ...x.pendingHead, intentSha256: digest('different') });
    if (mode === 'raced-head') {
      let reads = 0;
      x.io.pendingHead = async () => ++reads > 1 ? { ...await pending(), intentSha256: digest('raced') } : pending();
    }
    if (mode === 'changed-state') {
      x.values.get(x.prior.topology.ids.perimeter).properties.perimeterGuid = '00000000-0000-4000-8000-000000000091';
    }
    await assert.rejects(x.qualify());
    assert.equal(x.commits, 0);
    assert.equal(x.q.writes, 1);
    assert.equal(json(x.original), x.beforeBytes);
  });
});

test('reconciled late deny fences historical admission and permits only an independently reviewed fresh readmit', async () => {
  const x = await fixture(true), record = await x.qualify(), evidence = { ...x.prior, records: [...x.prior.records, record] };
  assert.equal(verifyNspEvidence(x.f.c, evidence, x.f.topology, x.f.adoption).stage, 'deny-control-plane-converged');
  assert.throws(() => verifyNspAdmission(x.f.c, evidence, x.f.topology, x.f.adoption), /CURRENT_ADMISSION/);
  await assert.rejects(readNspHead(x.prior, null, async () => x.head), /CANONICAL_HEAD_CHANGED/);
  x.f.at = x.io.now() + 1000;
  const instance = { version: 1, id: '00000000-0000-4000-8000-000000000096', predecessorSha256: hash(record),
    previousInstanceIds: ['00000000-0000-4000-8000-000000000097'] };
  const readmit = nspPhaseFixture(x.f, x.f.adoption, evidence, 'nsp-subscription-readmit', instance);
  await readmit.controller.execute(readmit.approval); evidence.records.push(readmit.record());
  const admitted = verifyNspAdmission(x.f.c, evidence, x.f.topology, x.f.adoption);
  assert.equal(admitted.stage, 'subscription-readmission-converged');
  const at = Date.parse(admitted.completedAt), billing = nspBillingFixture(x.f, evidence.topology, at);
  const context = { adoption: x.f.adoption, admission: evidence }, head = nspLineageHead(evidence);
  const proof = { sourceSha256: x.f.source, networkObservation: admitted.observation, networkLineageHead: head,
    networkBillingReview: billing.review, networkBillingEvidence: billing.evidence,
    ...nspReadinessBinding(context, head, billing.review, admitted.observation) };
  verifyNspQueuePreflight(x.f.c, context, proof, at);
  assert.throws(() => verifyNspQueuePreflight(x.f.c, context, proof, at - 1), /ADMISSION_AFTER_INTENT/);
});

test('reconciled record cannot rewrite original completion or become a normal execution receipt', async () => {
  const x = await fixture(), record = await x.qualify();
  for (const mutate of [
    r => { r.original.journal.outcome = 'readback-qualified'; },
    r => { r.receipt.originalExecutionQualified = true; },
    r => { r.receipt.outsideOriginalDeadline = false; },
    r => { r.receipt.qualificationKind = 'reviewed-nsp-control-plane-only'; },
    r => { r.version = 1; r.kind = 'reviewed-nsp-phase'; },
    r => { r.receipt.ingestionEnabled = true; },
  ]) {
    const changed = structuredClone(record); mutate(changed);
    assert.throws(() => verifyNspReconciledRecord(x.f.c, changed, x.f.topology, x.f.adoption, x.prior));
  }
});
