import { isDeepStrictEqual } from 'node:util';
import { closed, digest, json, fail, sameId } from './definition.mjs';
import { canonicalInstant, verifyDeploymentIdentity } from './policy.mjs';
import { queueArmInstant } from './queue-adoption.mjs';
import { NSP_LIMITS, NSP_AUTHORITY, verifyNspAttempt, verifyNspEvidence, verifyNspTransition,
  verifyNspBilling, nspPendingHead, nspState, nspLineageHead } from './nsp.mjs';
import { collectNspObservation } from './nsp-controller.mjs';

const hash = value => digest(json(value));
const equal = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);

export function verifyNspStoppedAttempt(c, original, topology, adoption, prior, pendingHead) {
  closed(original, ['phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'reservation', 'journal', 'receipt']);
  const at = verifyNspAttempt(c, original, topology, adoption, prior), j = original.journal, reservation = original.reservation;
  const keys = ['version', 'phaseSha256', 'approvalSha256', 'requestSha256', 'predecessorSha256', 'intentAt', 'outcome', 'transportDispatchAttempted'];
  closed(j, [...keys, 'failureCode', ...(Object.hasOwn(j, 'failureDetails') ? ['failureDetails'] : [])]);
  if (j.version !== 1 || j.outcome !== 'reconciliation-required' || j.transportDispatchAttempted !== true ||
      !/^[A-Z_]+$/u.test(j.failureCode ?? '') || j.phaseSha256 !== hash(original.phase) ||
      j.requestSha256 !== hash(original.phase.request) || j.approvalSha256 !== hash(original.approval) ||
      j.predecessorSha256 !== original.phase.predecessorSha256) fail('NSP_DISPATCHED_STOP_REQUIRED');
  closed(reservation, ['phase', 'approvalSha256', 'journal']);
  closed(reservation.journal, keys);
  equal(reservation.phase, original.phase, 'NSP_ORIGINAL_INTENT_CHANGED');
  if (reservation.approvalSha256 !== hash(original.approval)) fail('NSP_ORIGINAL_INTENT_CHANGED');
  equal(reservation.journal, { ...Object.fromEntries(keys.map(key => [key, j[key]])),
    outcome: 'submission-possible', transportDispatchAttempted: false }, 'NSP_ORIGINAL_INTENT_CHANGED');
  equal(pendingHead, nspPendingHead(prior, original.phase, reservation.journal), 'NSP_PENDING_HEAD_CHANGED');
  if (original.receipt !== null && (!original.receipt || typeof original.receipt !== 'object' ||
      Array.isArray(original.receipt))) fail('NSP_ORIGINAL_RECEIPT_INVALID');
  return at;
}
function operationEvidence(original, observation, deployment, operations) {
  const phase = original.phase;
  if (phase.request.method !== 'PUT') {
    if (deployment !== null || operations !== null) fail('NSP_UNEXPECTED_DEPLOYMENT');
    return;
  }
  const validationHash = original.validation?.properties?.templateHash;
  if (typeof validationHash !== 'string' || !validationHash || !sameId(deployment?.id, phase.deploymentId) ||
      deployment?.properties?.templateHash !== validationHash || deployment.error || deployment.properties.error) fail('NSP_RECONCILIATION_DEPLOYMENT_UNPROVEN');
  verifyDeploymentIdentity(deployment, deployment);
  const outputs = deployment.properties.outputResources;
  if (!Array.isArray(outputs)) fail('NSP_RECONCILIATION_DEPLOYMENT_UNPROVEN');
  const targets = phase.resources.map(value => value.id.toLowerCase()).sort();
  equal(outputs.map(value => value.id?.toLowerCase()).sort(), targets, 'NSP_RECONCILIATION_TARGETS_CHANGED');
  if (!operations || !Array.isArray(operations.value) || operations.nextLink ||
      operations.value.length > NSP_LIMITS.items || operations.error) fail('NSP_RECONCILIATION_OPERATIONS_UNPROVEN');
  const seen = new Set(), operationIds = new Set();
  for (const operation of operations.value) {
    const p = operation?.properties, target = p?.targetResource;
    if (typeof operation.operationId !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(operation.operationId) ||
        !sameId(operation.id, `${phase.deploymentId}/operations/${operation.operationId}`) ||
        operationIds.has(operation.operationId) || p?.provisioningState !== 'Succeeded' ||
        !['OK', 'Created', '200', '201'].includes(p.statusCode) || p.error || operation.error) fail('NSP_RECONCILIATION_OPERATIONS_UNPROVEN');
    operationIds.add(operation.operationId);
    if (p.provisioningOperation === 'EvaluateDeploymentOutput' && target === undefined) continue;
    const descriptor = phase.resources.find(value => sameId(value.id, target?.id));
    if (!descriptor || seen.has(descriptor.id) || p.provisioningOperation !== 'Create' ||
        !sameId(target.resourceType, descriptor.type) ||
        ![descriptor.expected.name, descriptor.id.split('/').at(-1)].includes(target.resourceName)) fail('NSP_RECONCILIATION_OPERATIONS_UNPROVEN');
    const created = queueArmInstant(observation.resources[descriptor.id]?.systemData?.createdAt);
    if (created < queueArmInstant(original.journal.intentAt) ||
        created > BigInt(observation.completedAt) * 10000n) fail('NSP_RECONCILIATION_GENERATION_UNPROVEN');
    seen.add(descriptor.id);
  }
  if (seen.size !== phase.resources.length) fail('NSP_RECONCILIATION_OPERATIONS_UNPROVEN');
}
function observationEvidence(c, original, topology, adoption, prior, value, at) {
  closed(value, ['observation', 'deployment', 'operations']);
  const o = value.observation;
  verifyNspTransition(c, prior.topology, adoption, original.phase, original.preflight.observation, o);
  if (!Number.isSafeInteger(at) || o.startedAt < canonicalInstant(original.journal.intentAt) ||
      o.completedAt > at || at - o.startedAt > NSP_LIMITS.freshnessMs) fail('NSP_RECONCILIATION_OBSERVATION_EXPIRED');
  operationEvidence(original, o, value.deployment, value.operations);
}
export function verifyNspReconciliationProposal(c, original, topology, adoption, prior, proposal, at) {
  closed(proposal, ['version', 'kind', 'configSha256', 'topologySha256', 'phaseSha256', 'originalSha256',
    'priorEvidenceSha256', 'sourceSha256', 'pendingHead', 'state', 'networkBillingReview',
    'networkBillingEvidence', 'qualified', 'originalExecutionQualified', 'replayAuthorized']);
  if (proposal.version !== 1 || proposal.kind !== 'nsp-current-state-reconciliation-proposal' ||
      proposal.configSha256 !== hash(c) || proposal.topologySha256 !== hash(prior.topology) ||
      proposal.phaseSha256 !== hash(original.phase) || proposal.originalSha256 !== hash(original) ||
      proposal.priorEvidenceSha256 !== hash(prior) || !sha(proposal.sourceSha256) ||
      proposal.qualified !== false || proposal.originalExecutionQualified !== false || proposal.replayAuthorized !== false) fail('NSP_EXACT_RECONCILIATION_REQUIRED');
  verifyNspStoppedAttempt(c, original, topology, adoption, prior, proposal.pendingHead);
  observationEvidence(c, original, topology, adoption, prior, proposal.state, at);
  verifyNspBilling(c, prior.topology, proposal.networkBillingReview, proposal.networkBillingEvidence, proposal.sourceSha256, at);
  return proposal;
}
async function readState(original, prior, io, deadline) {
  const observation = await collectNspObservation(prior.topology, io, deadline);
  let deployment = null, operations = null;
  if (original.phase.deploymentId) {
    [deployment, operations] = await io.batch([
      { id: original.phase.deploymentId, apiVersion: '2022-09-01', filter: null },
      { id: `${original.phase.deploymentId}/operations`, apiVersion: '2022-09-01', filter: null },
    ], request => io.read(request, deadline, request.id.endsWith('/operations')));
  }
  return { observation, deployment, operations };
}
export async function collectNspReconciliation(c, original, topology, adoption, prior, io) {
  const started = io.now(), deadline = started + NSP_LIMITS.stageMs, source = await io.sourceDigest();
  verifyNspEvidence(c, prior, topology, adoption);
  const pendingHead = await io.pendingHead();
  verifyNspStoppedAttempt(c, original, topology, adoption, prior, pendingHead);
  const state = await readState(original, prior, io, deadline);
  equal(await io.pendingHead(), pendingHead, 'NSP_PENDING_HEAD_CHANGED');
  if (await io.sourceDigest() !== source || io.now() >= deadline) fail('NSP_RECONCILIATION_COLLECTION_EXPIRED');
  const proposal = { version: 1, kind: 'nsp-current-state-reconciliation-proposal',
    configSha256: hash(c), topologySha256: hash(prior.topology), phaseSha256: hash(original.phase), originalSha256: hash(original),
    priorEvidenceSha256: hash(prior), sourceSha256: source, pendingHead, state,
    networkBillingReview: io.billingReview, networkBillingEvidence: io.billingEvidence,
    qualified: false, originalExecutionQualified: false, replayAuthorized: false };
  verifyNspReconciliationProposal(c, original, topology, adoption, prior, proposal, io.now());
  return proposal;
}
function verifyReview(c, original, prior, proposal, review, source, at) {
  closed(review, ['version', 'action', 'configSha256', 'topologySha256', 'phaseSha256', 'originalSha256',
    'proposalSha256', 'pendingHeadSha256', 'sourceSha256', 'reviewedAt', 'expiresAt', 'authority']);
  const start = canonicalInstant(review.reviewedAt), end = canonicalInstant(review.expiresAt);
  if (review.version !== 1 || review.action !== 'accept-exact-nsp-current-state-reconciliation' ||
      review.configSha256 !== hash(c) || review.topologySha256 !== hash(prior.topology) ||
      review.phaseSha256 !== hash(original.phase) || review.originalSha256 !== hash(original) ||
      review.proposalSha256 !== hash(proposal) || review.pendingHeadSha256 !== hash(proposal.pendingHead) ||
      review.sourceSha256 !== source || start < proposal.state.observation.completedAt || start > at ||
      end <= at || end - start > NSP_LIMITS.reviewMs) fail('NSP_RECONCILIATION_REVIEW_REQUIRED');
  equal(review.authority, NSP_AUTHORITY, 'NSP_AUTHORITY_CHANGED');
}
export function verifyNspReconciledRecord(c, record, topology, adoption, prior) {
  closed(record, ['version', 'kind', 'phase', 'original', 'proposal', 'review', 'publication', 'receipt']);
  const { original, proposal, review, publication, receipt } = record, at = canonicalInstant(receipt?.completedAt);
  closed(publication, ['commitSha', 'sourceSha256']);
  if (record.version !== 2 || record.kind !== 'reviewed-nsp-reconciliation' ||
      !/^[0-9a-f]{40}$/u.test(publication.commitSha ?? '') || publication.sourceSha256 !== proposal.sourceSha256 ||
      !sha(publication.sourceSha256)) fail('NSP_RECONCILIATION_RECORD_INVALID');
  equal(record.phase, original.phase, 'NSP_ORIGINAL_PHASE_CHANGED');
  verifyNspReconciliationProposal(c, original, topology, adoption, prior, proposal, at);
  verifyReview(c, original, prior, proposal, review, publication.sourceSha256, at);
  closed(receipt, ['qualified', 'qualificationKind', 'stage', 'phaseSha256', 'configSha256', 'sourceSha256',
    'topologySha256', 'approvalSha256', 'originalSha256', 'pendingHeadSha256', 'originalExecutionQualified',
    'originalHistoryModified', 'outsideOriginalDeadline', ...Object.keys(NSP_AUTHORITY), 'observation', 'deployment', 'operations', 'completedAt']);
  if (receipt.qualified !== true || receipt.qualificationKind !== 'reviewed-nsp-current-state-reconciliation' ||
      receipt.stage !== original.phase.afterStage || receipt.phaseSha256 !== hash(original.phase) ||
      receipt.configSha256 !== hash(c) || receipt.sourceSha256 !== publication.sourceSha256 ||
      receipt.topologySha256 !== hash(prior.topology) || receipt.approvalSha256 !== hash(review) ||
      receipt.originalSha256 !== hash(original) || receipt.pendingHeadSha256 !== hash(proposal.pendingHead) ||
      receipt.originalExecutionQualified !== false || receipt.originalHistoryModified !== false ||
      receipt.outsideOriginalDeadline !== (receipt.observation.completedAt > canonicalInstant(original.journal.intentAt) + NSP_LIMITS.stageMs)) fail('NSP_RECONCILIATION_RECEIPT_INVALID');
  for (const [key, value] of Object.entries(NSP_AUTHORITY)) if (receipt[key] !== value) fail('NSP_AUTHORITY_CHANGED');
  observationEvidence(c, original, topology, adoption, prior,
    { observation: receipt.observation, deployment: receipt.deployment, operations: receipt.operations }, at);
  if (receipt.observation.startedAt < canonicalInstant(review.reviewedAt)) fail('NSP_RECONCILIATION_FRESH_READ_REQUIRED');
  equal(nspState(receipt.observation), nspState(proposal.state.observation), 'NSP_RECONCILIATION_STATE_CHANGED');
  equal(receipt.deployment, proposal.state.deployment, 'NSP_RECONCILIATION_DEPLOYMENT_CHANGED');
  equal(receipt.operations, proposal.state.operations, 'NSP_RECONCILIATION_OPERATIONS_CHANGED');
  return receipt;
}
export async function qualifyNspReconciliation(c, original, topology, adoption, prior, proposal, review, publication, io) {
  const start = io.now(), deadline = Math.min(start + NSP_LIMITS.stageMs, canonicalInstant(review.expiresAt));
  verifyNspEvidence(c, prior, topology, adoption);
  verifyNspReconciliationProposal(c, original, topology, adoption, prior, proposal, start);
  verifyReview(c, original, prior, proposal, review, publication.sourceSha256, start);
  equal(await io.pendingHead(), proposal.pendingHead, 'NSP_PENDING_HEAD_CHANGED');
  if (await io.sourceDigest() !== publication.sourceSha256) fail('NSP_RECONCILIATION_SOURCE_CHANGED');
  const state = await readState(original, prior, io, deadline);
  if (io.now() >= deadline || await io.sourceDigest() !== publication.sourceSha256) fail('NSP_RECONCILIATION_COLLECTION_EXPIRED');
  const record = { version: 2, kind: 'reviewed-nsp-reconciliation', phase: original.phase, original, proposal, review, publication,
    receipt: { qualified: true, qualificationKind: 'reviewed-nsp-current-state-reconciliation', stage: original.phase.afterStage,
      phaseSha256: hash(original.phase), configSha256: hash(c), sourceSha256: publication.sourceSha256,
      topologySha256: hash(prior.topology), approvalSha256: hash(review), originalSha256: hash(original),
      pendingHeadSha256: hash(proposal.pendingHead), originalExecutionQualified: false, originalHistoryModified: false,
      outsideOriginalDeadline: state.observation.completedAt > canonicalInstant(original.journal.intentAt) + NSP_LIMITS.stageMs,
      ...NSP_AUTHORITY, ...state, completedAt: new Date(io.now()).toISOString() } };
  verifyNspReconciledRecord(c, record, topology, adoption, prior);
  equal(await io.pendingHead(), proposal.pendingHead, 'NSP_PENDING_HEAD_CHANGED');
  if (io.now() >= deadline || await io.sourceDigest() !== publication.sourceSha256) fail('NSP_RECONCILIATION_COLLECTION_EXPIRED');
  await io.compareAndAppend(proposal.pendingHead, record, nspLineageHead({ ...prior, records: [...prior.records, record] }));
  return record;
}
