import { isDeepStrictEqual, types } from 'node:util';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { open, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closed, digest, fail, ids, json, sameId } from './definition.mjs';
import { canonicalInstant, verifyDeploymentIdentity } from './policy.mjs';
import { collectEffectivePolicies, verifyEffectivePolicyEvidence,
  collectEffectivePoliciesV3, verifyEffectivePolicyEvidenceV3 } from './effective-policy.mjs';
import { verifyQueueAdoptionSources, queueArmInstant } from './queue-adoption.mjs';
import { queueDefenderInventory } from './queue-defender.mjs';
import { nspTargetKey } from './nsp.mjs';
import { az, sourceDigest, publishedSourceDigest, save, saveImmutable, load, readBatch, limitReadConcurrency,
  asyncWhatIf, authenticatedWhatIfRequest, whatIfRequestContext, safeOperationFailure, verifyReceiverSource, readNspHead, privateDirectory,
  MAX_PRIVATE_ARTIFACT_BYTES } from './controller.mjs';
import { PRIVATE_LINK_API as API, PRIVATE_LINK_CONTROL_STAGES as STAGES, PRIVATE_LINK_LIMITS as LIMITS,
  privateLinkRuntimeResources, verifyPrivateLinkNameProjection, privateLinkNameBinding, withPrivateLinkAssignedPrefixHash,
  PRIVATE_LINK_RUNTIME_STAGES, privateLinkAtLeast, privateLinkCost, privateLinkPhase,
  verifyPrivateLinkControlContext, verifyPrivateLinkEnvironmentWire, withPrivateLinkControlValidation } from './private-link.mjs';
import { collectPrivateLinkSnapshot, privateLinkGeneration, privateLinkReadRequests,
  privateLinkResourceDescriptors, privateLinkResourceState, verifyPrivateLinkSnapshot, verifyPrivateLinkEndpoint,
  plEqual as equal, plList, plOnly } from './private-link-readback.mjs';
import { verifyPrivateLinkRuntimeCompletion, withPrivateLinkCompletionValidation, assertPrivateLinkCompletionInputs,
  privateLinkValidationCopy, privateLinkValidationInputCheck, privateLinkValidationIsImmutable,
  privateLinkValidationHash as hash, sameOrderedJson } from './private-link-runtime.mjs';
import { privateLinkNsgTarget, privateLinkNsgTargets, privateLinkNsgReadRequests, privateLinkNsgRegionalWatchers,
  verifyPrivateLinkNsgAdoption, verifyPrivateLinkNsgCurrent, verifyPrivateLinkNsgEvidenceBinding,
  privateLinkNsgOriginalBaseline, observePrivateLinkNsgAdoption, adoptPrivateLinkNsg, withPrivateLinkNsgValidation,
  privateLinkNsgValidatedRecord, privateLinkNsgValidatedAnchor, privateLinkNsgValidationFor,
  privateLinkNsgMembers } from './private-link-nsg-adoption.mjs';
import { loadPrivateLinkArtifact, savePrivateLinkArtifact, updatePrivateLinkArtifact } from './private-link-artifacts.mjs';

const here = dirname(fileURLToPath(import.meta.url)), sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const stamp = at => new Date(at).toISOString();
const operationLock = options => resolve(options.store?.root ?? resolve(here, '../../opentofu/telemetry/.operator-private'), 'controller.lock');
// Each operation binds its own immutable copies. Nothing is trusted across
// operations; caller inputs and clocks are checked again after awaits.
const dispatchValidations = new WeakMap();
const activeDispatchValidation = new AsyncLocalStorage();
const controlPureValidations = new AsyncLocalStorage();
function pureValidation(c, context) {
  const value = controlPureValidations.getStore();
  return value?.c === c && value.context === context && value.active ? value : null;
}
function withPureValidation(c, context, use) {
  if (pureValidation(c, context)) return use();
  const state = { c, context, active: true, histories: new WeakSet(), proofs: new WeakMap() };
  try {
    const result = controlPureValidations.run(state, use);
    if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => { state.active = false; });
    state.active = false; return result;
  } catch (error) { state.active = false; throw error; }
}
const runtimeValidations = new AsyncLocalStorage();
const activeRuntimeValidations = new WeakSet();
function runtimeValidation(c, context, evidence) {
  const state = runtimeValidations.getStore();
  if (!state) return null;
  if (!activeRuntimeValidations.has(state) || state.c !== c || state.context !== context || state.evidence !== evidence) {
    fail('PRIVATE_LINK_RUNTIME_VALIDATION_SCOPE_CHANGED');
  }
  state.check();
  return state;
}
// A forward runtime operation owns this scope until compensation and retention settle.
// No token is accepted from JSON/options, and no mutable observation is cached here.
export function withPrivateLinkRuntimeValidation(c, context, evidence, use) {
  if (runtimeValidations.getStore()) fail('PRIVATE_LINK_RUNTIME_VALIDATION_NESTED');
  const run = (snapshot, validation) => {
    const state = { c, context, evidence: snapshot.evidence, validation, prerequisites: null,
      statistics: { immutableHistoryVerifications: 0, prerequisiteVerifications: 0, prerequisiteReuses: 0 },
      check: () => {
        const dispatch = dispatchValidation(c, context, validation);
        if (dispatch) assertDispatchInputs(dispatch);
        else equal(evidence, snapshot.evidence, 'PRIVATE_LINK_RUNTIME_VALIDATION_SCOPE_CHANGED');
      } };
    activeRuntimeValidations.add(state);
    try {
      const result = runtimeValidations.run(state, () => use(state.evidence, state.check, state.statistics));
      if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => activeRuntimeValidations.delete(state));
      activeRuntimeValidations.delete(state); return result;
    } catch (error) { activeRuntimeValidations.delete(state); throw error; }
  };
  const dispatch = activeDispatchValidation.getStore();
  if (dispatch && dispatch.c === c && dispatch.context === context &&
      dispatchValidations.get(dispatch.validation) === dispatch && isDeepStrictEqual(evidence, dispatch.evidence)) {
    privateLinkValidationInputCheck(evidence, dispatch.evidence, 'PRIVATE_LINK_RUNTIME_VALIDATION_SCOPE_CHANGED')();
    return run(dispatch, dispatch.validation);
  }
  return withDispatchValidation(c, context, { evidence }, run);
}
function immutableDispatchCopy(value) {
  return privateLinkValidationCopy(value);
}
function dispatchValidation(c, context, validation) {
  const state = validation && dispatchValidations.get(validation);
  if (!state) return null;
  if (state.c !== c || state.context !== context) fail('PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
  return state;
}
function verifiedHistory(state, evidence) {
  if (evidence === state.evidence && state.verifiedEvidence) return state.verifiedEvidence;
  return state.histories.find(entry => isDeepStrictEqual(entry.value, evidence) &&
    (entry.sha256 === null ? sameOrderedJson(entry.value, evidence) : entry.sha256 === hash(evidence)))?.value;
}
function assertDispatchInputs(state) {
  assertPrivateLinkCompletionInputs(state.c, state.context);
  state.checkCallerInputs();
}
function withDispatchValidation(c, context, values, use) {
  return withPrivateLinkCompletionValidation(c, context, () => withPureValidation(c, context,
    () => dispatchWithValidation(c, context, values, use)));
}
function dispatchWithValidation(c, context, values, use) {
  const { evidence } = values;
  if (!externalNsg(evidence)) {
    return withPrivateLinkNsgValidation(c, context, externalNsg(evidence), evidence,
      validation => use(values, validation));
  }
  return withPrivateLinkNsgValidation(c, context, externalNsg(evidence), evidence, validation => {
    const copied = immutableDispatchCopy(values);
    const snapshot = { ...copied, evidence: Object.freeze({ ...copied.evidence, externalAdoption: evidence.externalAdoption }) };
    const state = { c, context, validation, ...snapshot, callerInputs: values,
      checkCallerInputs: privateLinkValidationInputCheck(values, snapshot, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED'),
      histories: [], proofs: new WeakMap(), continuations: [], originals: [], validated: false };
    state.checkCallerInputs();
    dispatchValidations.set(validation, state);
    try {
      const result = activeDispatchValidation.run(state, () =>
        withPrivateLinkAssignedPrefixHash(snapshot.evidence, () => use(snapshot, validation)));
      if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => dispatchValidations.delete(validation));
      dispatchValidations.delete(validation); return result;
    } catch (error) { dispatchValidations.delete(validation); throw error; }
  });
}
function currentDispatchReviews(c, context, evidence, phase, proof, approval, at) {
  fresh(proof, at); fresh(proof.before, at);
  phaseSource(c, context, phase, at);
  boundedReview(approval, at);
  if (phase.continuation) boundedReview(phase.continuation.review, at);
  verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, phase.sourceSha256, at);
  verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, at, phase.sourceSha256);
  verifyCostScope(c, context, evidence, proof.before, at);
}
export function privateLinkArtifactBytes(value) {
  const encoded = JSON.stringify(value);
  if (encoded === undefined) fail('PRIVATE_LINK_JSON_ARTIFACT_REQUIRED');
  const bytes = encoded + '\n';
  if (Buffer.byteLength(bytes) > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_FILE_TOO_LARGE');
  return bytes;
}
const originalState = evidence => evidence.records.at(-1)?.stage ?? 'initial';
function originalEvidence(evidence, phase) {
  return evidence.version === 2 && phase.externalAdoptionSha256 === undefined
    ? { version: 1, kind: evidence.kind, planSha256: evidence.planSha256, originSha256: evidence.originSha256, records: evidence.records }
    : evidence;
}
const externalNsg = evidence => evidence.version === 2 ? evidence.externalAdoption : null;
function phaseExternalNsg(evidence, phase) {
  const adoption = externalNsg(evidence);
  if (phase.externalAdoptionSha256 !== undefined && (!adoption || hash(adoption) !== phase.externalAdoptionSha256)) fail('PRIVATE_LINK_NSG_PHASE_BINDING_CHANGED');
  return phase.externalAdoptionSha256 === undefined ? null : adoption;
}
const environmentWireVersion = evidence => evidence.records.find(record => record.stage === 'create-environment')?.phase.version ?? 2;
const authority = Object.freeze({ originalNspExecutionQualified: false, originalHistoryModified: false,
  originalIntentReplayAuthorized: false, ingestionAuthorized: false, publicationAuthorized: false, clientActivationAuthorized: false });
export const PRIVATE_LINK_PRICE_METERS = Object.freeze({
  endpointHour: [0.01, '1 Hour', 'Virtual Network Private Link', 'Standard', 'Standard Private Endpoint', 'Global'],
  endpointIngressGB: [0.01, '1 GB', 'Virtual Network Private Link', 'Standard', 'Standard Data Processed - Ingress', 'Global'],
  endpointEgressGB: [0.01, '1 GB', 'Virtual Network Private Link', 'Standard', 'Standard Data Processed - Egress', 'Global'],
  dnsZone: [0.50, '1', 'Azure DNS', 'Private', 'Private Zone', ''],
  dnsQueries: [0.40, '1M', 'Azure DNS', 'Private', 'Private Queries', ''],
  loadBalancerHour: [0.025, '1 Hour', 'Load Balancer', 'Standard', 'Standard Included LB Rules and Outbound Rules', 'Global'],
  loadBalancerGB: [0.005, '1 GB', 'Load Balancer', 'Standard', 'Standard Data Processed', 'Global'],
  publicIpHour: [0.005, '1 Hour', 'IP Addresses', 'Standard', 'Standard IPv4 Static Public IP', 'australiaeast'],
});
function boundedReview(review, at) {
  const start = canonicalInstant(review.approvedAt), end = canonicalInstant(review.expiresAt);
  if (!Number.isSafeInteger(at) || start > at || at >= end || end <= start || end - start > LIMITS.reviewMs) fail('PRIVATE_LINK_REVIEW_EXPIRED');
}
export function verifyPrivateLinkPolicyRevision(c, context, revision, at) {
  if (revision === null || revision === undefined) return context.plan.sourceSha256;
  closed(revision, ['version', 'action', 'configSha256', 'planSha256', 'originSha256', 'originalSourceSha256',
    'sourceSha256', 'publication', 'userInstruction', 'userInstructionSha256', 'approvedAt', 'expiresAt']);
  closed(revision.publication, ['commitSha', 'sourceSha256']);
  boundedReview(revision, at);
  if (revision.version !== 1 || revision.action !== 'review-identical-private-link-plan-under-new-policy-source' ||
      revision.configSha256 !== hash(c) || revision.planSha256 !== context.plan.planSha256 ||
      revision.originSha256 !== hash(context.origin) || revision.originalSourceSha256 !== context.plan.sourceSha256 ||
      !sha(revision.sourceSha256) || revision.sourceSha256 === context.plan.sourceSha256 ||
      revision.publication.sourceSha256 !== revision.sourceSha256 || !/^[0-9a-f]{40}$/u.test(revision.publication.commitSha ?? '') ||
      typeof revision.userInstruction !== 'string' || !revision.userInstruction.trim() ||
      revision.userInstructionSha256 !== digest(revision.userInstruction)) fail('PRIVATE_LINK_POLICY_REVISION_REQUIRED');
  return revision.sourceSha256;
}
function phaseSource(c, context, phase, at) {
  const source = verifyPrivateLinkPolicyRevision(c, context, phase.policyRevision, at);
  if (phase.sourceSha256 !== source) fail('PRIVATE_LINK_POLICY_REVISION_CHANGED');
  return source;
}
function fresh(snapshot, at) {
  if (!Number.isSafeInteger(snapshot?.startedAt) || !Number.isSafeInteger(snapshot.completedAt) ||
      snapshot.completedAt < snapshot.startedAt || snapshot.completedAt > at ||
      snapshot.completedAt - snapshot.startedAt > LIMITS.checkMs || at - snapshot.startedAt > LIMITS.freshnessMs) fail('PRIVATE_LINK_STALE_EVIDENCE');
}
export function privateLinkTargetKey(context) {
  const n = context.plan.topology.ids;
  return hash({ account: n.account.toLowerCase(), vnet: n.vnet.toLowerCase(), oldPerimeter: context.origin.network.topology.ids.perimeter.toLowerCase() });
}
export function emptyPrivateLinkControlEvidence(context) {
  return { version: 1, kind: 'reviewed-private-link-control-chain', planSha256: context.plan.planSha256,
    originSha256: hash(context.origin), records: [] };
}
export function privateLinkHead(context, evidence) {
  return { version: 1, kind: 'private-link-terminal-head', targetKey: privateLinkTargetKey(context),
    planSha256: context.plan.planSha256, originSha256: hash(context.origin), records: evidence.records.length,
    stage: originalState(evidence), recordSha256: evidence.records.length ? hash(evidence.records.at(-1)) : null,
    ...(evidence.records.at(-1)?.phase.externalAdoptionSha256 ? { externalAdoptionSha256: hash(evidence.externalAdoption) } : {}) };
}
const headName = context => `private-link-head-${privateLinkTargetKey(context)}.json`;
const fenceName = context => `private-link-fence-${privateLinkTargetKey(context)}.json`;
const intentName = (context, stage, attemptId = null) =>
  `private-link-intent-${hash({ target: privateLinkTargetKey(context), stage, ...(attemptId ? { attemptId } : {}) })}.json`;
async function verifyOriginalArtifacts(context, original, directory, root, read) {
  const archived = await read(root, intentName(context, original.phase.stage, original.phase.continuation?.attemptId));
  equal(archived, { phase: original.phase, intent: original.intent }, 'PRIVATE_LINK_ORIGINAL_INTENT_ARCHIVE_CHANGED');
  equal(await load(directory, `private-link-${original.phase.stage}-journal.json`), original.journal,
    'PRIVATE_LINK_ORIGINAL_DURABLE_JOURNAL_CHANGED');
}
const pendingHead = (context, evidence, intent, phase = null) => ({ version: 1, kind: 'private-link-pending-head',
  targetKey: privateLinkTargetKey(context), previous: phase?.expectedHead ?? privateLinkHead(context, evidence), intentSha256: hash(intent) });
export async function readPrivateLinkHead(context, evidence, options = {}) {
  const root = options.root ?? resolve(here, '.operator-private'), read = options.read ?? loadPrivateLinkArtifact;
  const actual = await read(root, headName(context), true), expected = privateLinkHead(context, evidence);
  if (externalNsg(evidence)) equal(await read(root, `private-link-nsg-adoption-${privateLinkTargetKey(context)}.json`, true),
    evidence.externalAdoption, 'PRIVATE_LINK_NSG_CANONICAL_ADOPTION_REQUIRED');
  const fence = await read(root, fenceName(context), true);
  if (actual === null && evidence.records.length === 0 && fence === null) {
    if (await read(root, intentName(context, 'review-migration'), true) !== null) fail('PRIVATE_LINK_ORPHANED_INTENT');
    return expected;
  }
  if (!fence) fail('PRIVATE_LINK_CANONICAL_HEAD_CHANGED');
  closed(fence, ['version', 'targetKey', 'stage', 'intentSha256', 'phase', 'intent']);
  if (fence.version !== 1 || fence.targetKey !== privateLinkTargetKey(context) || fence.stage !== fence.phase?.stage ||
      fence.intentSha256 !== hash(fence.intent) || fence.intent.phaseSha256 !== hash(fence.phase)) fail('PRIVATE_LINK_INTENT_FENCE_CHANGED');
  const archive = await read(root, intentName(context, fence.stage, fence.phase?.continuation?.attemptId), true);
  equal(archive, { phase: fence.phase, intent: fence.intent }, 'PRIVATE_LINK_INTENT_ARCHIVE_CHANGED');
  if (fence.phase.continuation) {
    const reservation = await read(root, `private-link-continuation-${hash({ targetKey: privateLinkTargetKey(context),
      attemptId: fence.phase.continuation.attemptId })}.json`, true);
    equal(reservation, { continuation: fence.phase.continuation, phase: fence.phase, intent: fence.intent,
      previousHead: fence.phase.expectedHead }, 'PRIVATE_LINK_CONTINUATION_RESERVATION_CHANGED');
  }
  const continued = options.continuation;
  const expectedPredecessor = continued?.resolution.proposal.pendingHead ?? expected;
  if (options.pending && isDeepStrictEqual(actual, options.pending) &&
      isDeepStrictEqual(actual.previous, expectedPredecessor) && fence.intentSha256 === actual.intentSha256) {
    equal(fence.phase.expectedHead, expectedPredecessor, 'PRIVATE_LINK_PENDING_PREDECESSOR_CHANGED');
    if (continued) equal(fence.phase.continuation, continued, 'PRIVATE_LINK_CONTINUATION_CHANGED');
    return actual;
  }
  if (continued && !options.pending) {
    const resolution = continued.resolution, priorIntent = resolution.original.intent;
    equal(actual, resolution.proposal.pendingHead, 'PRIVATE_LINK_CONTINUATION_HEAD_CHANGED');
    equal(archive, { phase: resolution.original.phase, intent: priorIntent }, 'PRIVATE_LINK_CONTINUATION_ORIGINAL_CHANGED');
    const settled = await read(root, `private-link-no-submission-${hash(priorIntent)}.json`, true);
    equal(settled, { pending: actual, record: resolution }, 'PRIVATE_LINK_CONTINUATION_RESOLUTION_REQUIRED');
    return actual;
  }
  if (!isDeepStrictEqual(actual, expected) || fence.intentSha256 !== evidence.records.at(-1)?.intentSha256) fail('PRIVATE_LINK_CANONICAL_HEAD_CHANGED');
  const terminal = evidence.records.at(-1);
  equal(archive, { phase: terminal.phase, intent: terminal.intent }, 'PRIVATE_LINK_TERMINAL_INTENT_CHANGED');
  return actual;
}
export function verifyPrivateLinkCostReview(c, context, review, evidence, source, at) {
  closed(review, ['version', 'action', 'planSha256', 'configSha256', 'sourceSha256', 'evidenceSha256',
    'userInstruction', 'userInstructionSha256', 'cost', 'budgetTargets', 'approvedAt', 'expiresAt']);
  boundedReview(review, at);
  if (review.version !== 1 || review.action !== 'approve-exact-private-link-migration-cost-and-budget-coverage' ||
      review.planSha256 !== context.plan.planSha256 || review.configSha256 !== hash(c) || review.sourceSha256 !== source ||
      review.evidenceSha256 !== hash(evidence) || typeof review.userInstruction !== 'string' || !review.userInstruction.trim() ||
      review.userInstructionSha256 !== digest(review.userInstruction)) fail('PRIVATE_LINK_COST_REVIEW_REQUIRED');
  equal(review.cost, privateLinkCost(context.plan.input.overlapDays, context.plan.input.version === 2), 'PRIVATE_LINK_COST_SCOPE_CHANGED');
  equal(review.budgetTargets, { migration: { project: 425, telemetry: 375, state: 50 },
    steady: { project: 375, telemetry: 325, state: 50 }, additionalGroup: context.plan.topology.ids.managedGroup }, 'PRIVATE_LINK_BUDGET_AUTHORITY_REQUIRED');
  closed(evidence, ['version', 'kind', 'retrievedAt', 'region', 'currency', 'queries', 'unknownChargesAcknowledgment']);
  if (evidence.version !== 1 || evidence.kind !== 'private-link-price-evidence' || evidence.region !== 'australiaeast' ||
      evidence.currency !== 'USD' || canonicalInstant(evidence.retrievedAt) > canonicalInstant(review.approvedAt) ||
      at - canonicalInstant(evidence.retrievedAt) > 86400000 || !Array.isArray(evidence.queries) || evidence.queries.length !== 8 ||
      typeof evidence.unknownChargesAcknowledgment !== 'string' || !evidence.unknownChargesAcknowledgment.trim()) fail('PRIVATE_LINK_CURRENT_PRICING_REQUIRED');
  const seen = new Set();
  for (const query of evidence.queries) {
    closed(query, ['purpose', 'url', 'response', 'selectedMeterId']);
    const requirement = typeof query.purpose === 'string' && Object.hasOwn(PRIVATE_LINK_PRICE_METERS, query.purpose)
      ? PRIVATE_LINK_PRICE_METERS[query.purpose] : null;
    const url = new URL(query.url);
    if (!requirement || seen.has(query.purpose) || url.protocol !== 'https:' || url.hostname !== 'prices.azure.com' ||
        url.pathname !== '/api/retail/prices' || url.username || url.password || url.hash ||
        query.response?.NextPageLink !== null || !Array.isArray(query.response.Items)) fail('PRIVATE_LINK_PRICE_EVIDENCE_INVALID');
    const meters = query.response.Items.filter(item => item.meterId === query.selectedMeterId &&
      item.type === 'Consumption' && item.tierMinimumUnits === 0);
    if (meters.length !== 1 || meters[0].retailPrice !== requirement[0] || meters[0].unitPrice !== requirement[0] ||
        meters[0].unitOfMeasure !== requirement[1] || meters[0].currencyCode !== 'USD' ||
        meters[0].productName !== requirement[2] || meters[0].skuName !== requirement[3] ||
        meters[0].meterName !== requirement[4] || meters[0].armRegionName !== requirement[5]) fail('PRIVATE_LINK_PRICE_CHANGED');
    seen.add(query.purpose);
  }
  return review.cost;
}
export function verifyPrivateLinkMigrationReview(c, context, review, at, source = context.plan.sourceSha256) {
  closed(review, ['version', 'action', 'planSha256', 'originSha256', 'configSha256', 'sourceSha256',
    'pendingNspHeadSha256', 'opaqueRuleSha256', 'opaqueEffectiveSha256', 'userInstruction',
    'userInstructionSha256', 'approvedAt', 'expiresAt']);
  boundedReview(review, at);
  if (review.version !== 1 || review.action !== 'retire-exact-failed-nsp-intent-and-migrate-private-link' ||
      review.planSha256 !== context.plan.planSha256 || review.originSha256 !== hash(context.origin) ||
      review.configSha256 !== hash(c) || review.sourceSha256 !== source ||
      review.pendingNspHeadSha256 !== hash(context.origin.pendingHead) ||
      !sha(review.opaqueRuleSha256) || !sha(review.opaqueEffectiveSha256) ||
      typeof review.userInstruction !== 'string' || !review.userInstruction.trim() ||
      review.userInstructionSha256 !== digest(review.userInstruction)) fail('PRIVATE_LINK_MIGRATION_REVIEW_REQUIRED');
}
function order(evidence, stage) {
  if (stage !== STAGES[evidence.records.length]) fail('PRIVATE_LINK_PHASE_ORDER_INVALID');
}
export function preparePrivateLinkPhase(c, context, evidence, stage, policyRevision = null, continuation = null,
  version = stage === 'create-environment' ? 2 : 1) {
  return withPrivateLinkNsgValidation(c, context, externalNsg(evidence), evidence, validation =>
    preparePhase(c, context, evidence, stage, policyRevision, continuation, version, validation));
}
function preparePhase(c, context, evidence, stage, policyRevision, continuation, version, validation) {
  verifyControlEvidence(c, context, evidence, undefined, validation);
  order(evidence, stage);
  const source = policyRevision === null ? context.plan.sourceSha256 :
    verifyPrivateLinkPolicyRevision(c, context, policyRevision, canonicalInstant(policyRevision.approvedAt));
  if (continuation && continuation.resolution?.original?.phase?.version !== version) fail('PRIVATE_LINK_CONTINUATION_WIRE_CHANGED');
  if (continuation) verifyPrivateLinkContinuation(c, context, evidence, stage, source, continuation, canonicalInstant(continuation.review.approvedAt), validation);
  return phaseCandidate(c, context, evidence, stage, policyRevision, continuation, version);
}
function phaseCandidate(c, context, evidence, stage, policyRevision, continuation,
  version = stage === 'create-environment' ? 2 : 1) {
  const source = policyRevision === null ? context.plan.sourceSha256 : policyRevision.sourceSha256;
  return { ...privateLinkPhase(c, context, stage, version), predecessorSha256: evidence.records.length ? hash(evidence.records.at(-1)) : null,
    expectedHead: continuation ? continuation.resolution.proposal.pendingHead : privateLinkHead(context, evidence), sourceSha256: source,
    ...(policyRevision === null ? {} : { policyRevision: structuredClone(policyRevision) }),
    ...(continuation ? { continuation: structuredClone(continuation) } : {}),
    ...(externalNsg(evidence) ? { externalAdoptionSha256: hash(evidence.externalAdoption) } : {}) };
}
function snapshotState(s) {
  return { resources: Object.fromEntries(Object.entries(s.resources).map(([id, value]) => {
    if (value && sameId(value.type, 'Microsoft.Consumption/budgets')) {
      const result = privateLinkResourceState(value); delete result.properties.currentSpend; delete result.properties.forecastSpend;
      return [id, result];
    }
    return [id, privateLinkResourceState(value)];
  })), lists: s.lists, diagnostics: s.diagnostics, nic: s.nic ? privateLinkResourceState(s.nic) : null,
    effective: s.effective ? privateLinkResourceState(s.effective) : null, defender: s.defender, images: s.images, managed: s.managed,
    ...(s.externalNsg ? { externalNsg: { ...s.externalNsg, startedAt: null, completedAt: null } } : {}) };
}
export function privateLinkPermissions(c, context, phase) {
  const r = ids(c), n = context.plan.topology.ids, list = [
    { scope: r.group, actions: ['Microsoft.Resources/subscriptions/resourceGroups/resources/read',
      'Microsoft.Network/virtualNetworks/read', 'Microsoft.Network/privateEndpoints/read',
      'Microsoft.Network/privateDnsZones/read', 'Microsoft.App/managedEnvironments/read',
      'Microsoft.App/containerApps/read', 'Microsoft.ManagedIdentity/userAssignedIdentities/read',
      'Microsoft.Insights/diagnosticSettings/read', 'Microsoft.Authorization/roleAssignments/read',
      'Microsoft.Authorization/policyAssignments/read'] },
    { scope: n.account, actions: ['Microsoft.Storage/storageAccounts/read'] },
  ];
  if (phase.request) {
    const suffix = phase.request.method === 'DELETE' ? 'delete' : 'write';
    if (phase.deploymentId) list.push({ scope: phase.scope, actions: ['Microsoft.Resources/deployments/write',
      'Microsoft.Resources/deployments/validate/action', 'Microsoft.Resources/deployments/whatIf/action'] });
    for (const resource of phase.resources) list.push({ scope: phase.deploymentId ? phase.scope : resource.id, actions: [resource.type + '/' + suffix] });
    if (!phase.resources.length && phase.request.method === 'DELETE') {
      const parts = phase.request.id.split(/\/providers\//iu).at(-1).split('/');
      list.push({ scope: phase.request.id, actions: [[parts[0], ...parts.filter((_, i) => i % 2 === 1), suffix].join('/')] });
    }
  }
  if (phase.stage === 'create-queue-endpoint') list.push({ scope: n.endpointSubnet, actions: ['Microsoft.Network/virtualNetworks/subnets/join/action'] },
    { scope: n.account, actions: ['Microsoft.Storage/storageAccounts/privateEndpointConnectionsApproval/action'] });
  if (phase.stage === 'create-environment') list.push({ scope: n.appsSubnet, actions: ['Microsoft.Network/virtualNetworks/subnets/join/action'] });
  return list;
}
function verifyPermissions(c, context, phase, evidence) {
  const targets = privateLinkPermissions(c, context, phase), scopes = [...new Set(targets.map(value => value.scope))];
  closed(evidence, scopes);
  const matches = (pattern, action) => typeof pattern === 'string' &&
    new RegExp('^' + pattern.split('*').map(value => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')).join('.*') + '$', 'iu').test(action);
  for (const target of targets) {
    const response = evidence[target.scope]; closed(response, ['permissions', 'denies']);
    if (plList(response.denies).length) fail('PRIVATE_LINK_DENY_ASSIGNMENT');
    const granted = plList(response.permissions);
    for (const value of granted) plOnly(value, ['actions', 'notActions', 'dataActions', 'notDataActions'], 'PRIVATE_LINK_CONDITIONAL_PERMISSION_UNVERIFIED');
    for (const action of target.actions) if (!granted.some(value =>
      Array.isArray(value.actions) && Array.isArray(value.notActions) &&
      value.actions.some(pattern => matches(pattern, action)) && !value.notActions.some(pattern => matches(pattern, action)))) fail('PRIVATE_LINK_OPERATOR_PERMISSION_REQUIRED');
  }
}
function permissionRequest(scope, suffix) {
  return { id: `${scope}/providers/Microsoft.Authorization/${suffix}`, apiVersion: API.authorization,
    filter: suffix === 'denyAssignments' ? '$filter=atScope()' : null };
}
function verifyProviders(context, catalogs, phase) {
  closed(catalogs, ['network', 'storage', 'app']);
  for (const [key, namespace] of [['network', 'Microsoft.Network'], ['storage', 'Microsoft.Storage'], ['app', 'Microsoft.App']]) {
    if (!sameId(catalogs[key]?.namespace, namespace) || catalogs[key].registrationState !== 'Registered' ||
        !Array.isArray(catalogs[key].resourceTypes)) fail('PRIVATE_LINK_PROVIDER_NOT_REGISTERED');
  }
  const targets = phase.resources.filter(value => !value.type.startsWith('Microsoft.Authorization/') && !value.type.startsWith('Microsoft.Consumption/'));
  for (const d of targets) {
    const [namespace, ...segments] = d.type.split('/'), provider = Object.values(catalogs).find(value => sameId(value.namespace, namespace));
    const rows = provider?.resourceTypes.filter(value => sameId(value.resourceType, segments.join('/')));
    // Only known child omissions, never absence of a root API/region, are reviewable.
    if (!rows?.length && segments.length > 1 && ['Microsoft.Network/virtualNetworks/subnets',
      'Microsoft.Network/privateDnsZones/virtualNetworkLinks', 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups',
      'Microsoft.Network/networkSecurityPerimeters/resourceAssociations', 'Microsoft.Network/networkSecurityPerimeters/profiles',
      'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules'].includes(d.type)) continue;
    if (rows?.length !== 1 || !rows[0].apiVersions?.includes(d.apiVersion) ||
        (d.expected.location && d.expected.location !== 'global' && !rows[0].locations?.some(value => value.replaceAll(' ', '').toLowerCase() === context.plan.topology.location))) fail('PRIVATE_LINK_PINNED_API_UNVERIFIED');
  }
}
export function privateLinkPreservedIds(c, context, snapshot, adoption = null, evidence = null) {
  const ids = Object.keys(snapshot.resources).filter(id => snapshot.resources[id] !== null);
  if (snapshot.nic !== null && snapshot.nic !== undefined) {
    verifyPrivateLinkEndpoint(c, context, snapshot);
    ids.push(snapshot.nic.id);
  }
  if (context.origin.adoption.version === 3) {
    ids.push(...Object.keys(queueDefenderInventory(c, context.origin.adoption.origin,
      context.origin.adoption.proposal.defender, snapshot.defender)));
  }
  if (adoption) {
    adoption = privateLinkNsgValidatedRecord(c, context, adoption, evidence);
    verifyPrivateLinkNsgCurrent(c, context, snapshot.externalNsg, adoption.proposal.current.externalNsg);
    ids.push(...Object.values(privateLinkNsgTargets(c, context)).map(value => value.id));
  }
  return [...new Set(ids)];
}
export function verifyPrivateLinkPreview(phase, preview, snapshot, known) {
  if (phase.version === 2 || phase.wireProjection !== undefined) verifyPrivateLinkEnvironmentWire(phase);
  if (!phase.deploymentId) {
    closed(preview, ['version', 'kind', 'request', 'preimageSha256', 'nativeArmWhatIf']);
    equal(preview.request, phase.request, 'PRIVATE_LINK_REQUEST_DRIFT');
    if (preview.version !== 1 || preview.kind !== 'exact-private-link-request-preimage' || preview.nativeArmWhatIf !== false ||
        preview.preimageSha256 !== hash(phase.request ? snapshot.resources[phase.request.id] : null)) fail('PRIVATE_LINK_PREIMAGE_UNBOUND');
    return hash(preview);
  }
  if (preview?.status !== 'Succeeded' || preview.error || preview.nextLink || !Array.isArray(preview.changes)) fail('PRIVATE_LINK_NATIVE_WHATIF_REQUIRED');
  const seen = new Set();
  for (const change of preview.changes) {
    const id = change.resourceId?.toLowerCase();
    if (!id || seen.has(id) || change.error || change.nextLink) fail('PRIVATE_LINK_WHATIF_INCOMPLETE');
    seen.add(id);
    const d = phase.resources.find(value => sameId(value.id, change.resourceId));
    if (!d) {
      if (change.changeType !== 'Ignore' || !known.some(value => sameId(value, change.resourceId))) fail('PRIVATE_LINK_WHATIF_SCOPE_CHANGED');
      continue;
    }
    if (change.changeType !== 'Create' || change.before !== undefined) fail('PRIVATE_LINK_CREATE_ONLY_REQUIRED');
    const actual = structuredClone(change.after), expected = { ...structuredClone(d.expected), id: d.id };
    if (!actual || typeof actual !== 'object') fail('PRIVATE_LINK_WHATIF_AFTER_REQUIRED');
    if (phase.stage === 'create-network' && d.type === 'Microsoft.Network/virtualNetworks' &&
        Object.hasOwn(actual.properties ?? {}, 'subnets')) {
      const children = phase.resources.filter(value => value.type === 'Microsoft.Network/virtualNetworks/subnets' &&
        sameId(value.id.slice(0, value.id.lastIndexOf('/subnets/')), d.id));
      if (children.length !== 2) fail('PRIVATE_LINK_WHATIF_CONTRADICTION');
      expected.properties.subnets = children.map(value => ({
        name: value.id.split('/').at(-1), properties: structuredClone(value.expected.properties),
      }));
    }
    if (['Microsoft.Network/virtualNetworks/subnets', 'Microsoft.Network/privateDnsZones/virtualNetworkLinks',
      'Microsoft.Network/privateEndpoints/privateDnsZoneGroups'].includes(d.type) &&
        actual.name === d.id.split('/').at(-1)) expected.name = actual.name;
    if (phase.stage === 'create-queue-endpoint' && d.type === 'Microsoft.Network/privateDnsZones' &&
        !Object.hasOwn(actual, 'properties') && isDeepStrictEqual(expected.properties, {})) delete expected.properties;
    if (phase.version === 2 && phase.stage === 'create-environment' && d.type === 'Microsoft.App/managedEnvironments' &&
        actual.properties && !Object.hasOwn(actual.properties, 'appLogsConfiguration') &&
        isDeepStrictEqual(expected.properties.appLogsConfiguration, { destination: null, logAnalyticsConfiguration: null })) {
      delete expected.properties.appLogsConfiguration;
    }
    if (phase.stage === 'create-queue-role' && d.type === 'Microsoft.Authorization/roleDefinitions' &&
        Array.isArray(actual.properties?.permissions) && actual.properties.permissions.length === 1 &&
        expected.properties.permissions.length === 1) {
      for (const key of ['notActions', 'notDataActions']) {
        if (!Object.hasOwn(actual.properties.permissions[0] ?? {}, key) &&
            isDeepStrictEqual(expected.properties.permissions[0][key], [])) delete expected.properties.permissions[0][key];
      }
    }
    if (phase.stage === 'assign-queue-role' && d.type === 'Microsoft.Authorization/roleAssignments') {
      const scope = d.id.slice(0, d.id.toLowerCase().lastIndexOf('/providers/microsoft.authorization/roleassignments/'));
      if (!Object.hasOwn(actual, 'scope') && sameId(expected.scope, scope)) delete expected.scope;
      if (actual.properties && !Object.hasOwn(actual.properties, 'principalType') &&
          expected.properties.principalType === 'ServicePrincipal' &&
          Object.values(snapshot.resources ?? {}).some(value => value?.type === 'Microsoft.ManagedIdentity/userAssignedIdentities' &&
            value.properties?.principalId === expected.properties.principalId)) delete expected.properties.principalType;
    }
    for (const key of ['apiVersion', 'dependsOn']) {
      if (Object.hasOwn(actual, key)) equal(actual[key], expected[key], 'PRIVATE_LINK_WHATIF_CONTRADICTION');
      delete actual[key]; delete expected[key];
    }
    equal(actual, expected, 'PRIVATE_LINK_WHATIF_CONTRADICTION');
  }
  if (phase.resources.some(value => !seen.has(value.id.toLowerCase()))) fail('PRIVATE_LINK_WHATIF_INCOMPLETE');
  return hash(preview);
}
function verifyOpaquePreimage(context, evidence, snapshot, review) {
  if (evidence.records.length > STAGES.indexOf('retire-nsp-rule')) return;
  const rule = snapshot.resources[context.origin.network.topology.ids.rule];
  if (!rule || hash(rule) !== review.opaqueRuleSha256 || hash(snapshot.effective) !== review.opaqueEffectiveSha256) fail('PRIVATE_LINK_OPAQUE_PREIMAGE_CHANGED');
  if (rule.properties?.provisioningState !== 'Succeeded' || privateLinkGeneration(rule).createdAt === null) fail('PRIVATE_LINK_RULE_GENERATION_UNVERIFIED');
}
function proofBindings(proof) {
  return { sourceSha256: proof.sourceSha256, phaseSha256: proof.phaseSha256, planSha256: proof.planSha256,
    contextSha256: proof.contextSha256, headSha256: hash(proof.head), beforeSha256: hash(snapshotState(proof.before)),
    policySha256: hash(proof.policy), permissionsSha256: hash(proof.permissions), providerSha256: hash(proof.providers),
    costReviewSha256: hash(proof.costReview), costEvidenceSha256: hash(proof.costEvidence),
    migrationReviewSha256: hash(proof.migrationReview), previewSha256: hash(proof.preview),
    validationSha256: hash(proof.validation), runtimeCompletionSha256: hash(proof.runtimeCompletion),
    ...(proof.before.nameProjection ? { nameProjectionSha256: hash(proof.before.nameProjection) } : {}),
    ...(Object.hasOwn(proof, 'deploymentBefore') ? { deploymentBeforeSha256: hash(proof.deploymentBefore) } : {}) };
}
function verifyCostScope(c, context, evidence, snapshot, at) {
  const created = evidence.records.find(record => record.stage === 'create-environment');
  const retired = evidence.records.find(record => record.stage === 'retire-old-environment');
  const overlapMs = created ? (retired ? canonicalInstant(retired.completedAt) : at) - canonicalInstant(created.intent.at) : 0;
  if (overlapMs < 0 || overlapMs > context.plan.input.overlapDays * 86400000) fail('PRIVATE_LINK_OVERLAP_ALLOWANCE_EXCEEDED');
  for (const [id, ceiling] of [[ids(c).projectBudget, 425], [ids(c).budget, 375], [ids(c).stateBudget, 50]]) {
    const spend = snapshot.resources[id]?.properties?.currentSpend;
    if (!spend || typeof spend.amount !== 'number' || !Number.isFinite(spend.amount) || spend.amount < 0 || spend.unit !== 'USD') fail('PRIVATE_LINK_CURRENT_SPEND_UNVERIFIED');
    if (spend.amount > ceiling) fail('PRIVATE_LINK_SPEND_REVIEW_REQUIRED');
  }
}
function verifyProof(c, context, evidence, phase, proof, at, validation = null) {
  closed(proof, ['version', 'kind', 'startedAt', 'completedAt', 'sourceSha256', 'phaseSha256', 'planSha256',
    'contextSha256', 'head', 'before', 'policy', 'permissions', 'providers', 'costReview', 'costEvidence',
    'migrationReview', 'preview', 'validation', 'runtimeCompletion', 'binding',
    ...(phase.continuation ? ['deploymentBefore'] : [])]);
  fresh(proof, at); fresh(proof.before, at);
  const source = phaseSource(c, context, phase, at);
  if (phase.continuation) verifyPrivateLinkContinuation(c, context, evidence, phase.stage, source, phase.continuation, at, validation);
  const state = dispatchValidation(c, context, validation), proofs = state?.proofs ?? pureValidation(c, context)?.proofs;
  const cached = proofs?.get(proof);
  if (cached && cached.phase === phase && cached.records === evidence.records.length &&
      cached.last === evidence.records.at(-1) && cached.adoption === externalNsg(evidence)) {
    verifyCostScope(c, context, evidence, proof.before, at);
    verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, proof.sourceSha256, at);
    verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, at, source);
    if (proof.before.nameProjection) verifyPrivateLinkNameProjection(c, context, proof.before.nameProjection, at, evidence);
    return;
  }
  if (phase.continuation && proof.deploymentBefore !== null) fail('PRIVATE_LINK_CONTINUATION_DEPLOYMENT_PRESENT');
  if (proof.version !== 1 || proof.kind !== 'checked-private-link-phase' || proof.sourceSha256 !== source ||
      proof.phaseSha256 !== hash(phase) || proof.planSha256 !== context.plan.planSha256 ||
      proof.contextSha256 !== hash(context.origin)) fail('PRIVATE_LINK_PREFLIGHT_BINDING_CHANGED');
  equal(proof.binding, proofBindings(proof), 'PRIVATE_LINK_PREFLIGHT_BINDING_CHANGED');
  equal(proof.head, phase.expectedHead, 'PRIVATE_LINK_PREFLIGHT_HEAD_CHANGED');
  const adoption = phaseExternalNsg(evidence, phase), checked = privateLinkNsgValidationFor(c, context, adoption, validation);
  verifyPrivateLinkSnapshot(c, context, proof.before, originalState(evidence), environmentWireVersion(evidence), checked, evidence);
  verifyCostScope(c, context, evidence, proof.before, at);
  verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, proof.sourceSha256, at);
  verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, at, source);
  verifyOpaquePreimage(context, evidence, proof.before, proof.migrationReview);
  verifyPermissions(c, context, phase, proof.permissions); verifyProviders(context, proof.providers, phase);
  const policyPhase = policyTargetPhase(c, context, phase, proof.before);
  verifyEffectivePolicyEvidence(policyPhase, proof.policy);
  verifyPrivateLinkPreview(phase, proof.preview, proof.before, privateLinkPreservedIds(c, context, proof.before, checked, evidence));
  if (privateLinkAtLeast(phase.stage, 'retire-old-receiver')) {
    verifyPrivateLinkRuntimeCompletion(c, context, proof.runtimeCompletion, at);
    const runtimeEvidence = proof.runtimeCompletion.controlEvidence;
    closed(runtimeEvidence, ['version', 'kind', 'planSha256', 'originSha256', 'records', ...(adoption ? ['externalAdoption'] : [])]);
    if (runtimeEvidence.version !== (adoption ? 2 : 1) || runtimeEvidence.kind !== evidence.kind ||
        runtimeEvidence.planSha256 !== evidence.planSha256 || runtimeEvidence.originSha256 !== evidence.originSha256) fail('PRIVATE_LINK_RUNTIME_CONTROL_LINEAGE_CHANGED');
    if (adoption) equal(runtimeEvidence.externalAdoption, adoption, 'PRIVATE_LINK_NSG_RUNTIME_ADOPTION_CHANGED');
    const prefix = evidence.records.slice(0, STAGES.indexOf('assign-queue-role') + 1);
    equal(runtimeEvidence.records, prefix, 'PRIVATE_LINK_RUNTIME_CONTROL_LINEAGE_CHANGED');
    if (prefix.at(-1)?.stage !== 'assign-queue-role') fail('PRIVATE_LINK_RUNTIME_PREREQUISITES_REQUIRED');
    const projection = proof.before.nameProjection ?? null;
    const admitted = proof.runtimeCompletion.binding.runtimeReview?.nameProjection ?? null;
    if (projection || admitted) {
      if (!projection || !admitted) fail('PRIVATE_LINK_RETIREMENT_NAME_REVIEW_REQUIRED');
      verifyPrivateLinkNameProjection(c, context, projection, at, evidence);
      if (projection.sourceSha256 !== source) fail('PRIVATE_LINK_NAME_POLICY_CHANGED');
      equal(privateLinkNameBinding(c, context, projection, evidence), privateLinkNameBinding(c, context, admitted, runtimeEvidence),
        'PRIVATE_LINK_RETIREMENT_NAMES_CHANGED');
    }
    const currentApp = proof.before.resources[privateLinkRuntimeResources(c, context, projection, evidence).ids.app];
    equal(privateLinkResourceState(currentApp), privateLinkResourceState(proof.runtimeCompletion.disable.observation.app),
      'PRIVATE_LINK_QUALIFIED_REPLACEMENT_CHANGED');
  } else if (proof.runtimeCompletion !== null) fail('PRIVATE_LINK_UNEXPECTED_RUNTIME_AUTHORITY');
  if (proof.before.nameProjection && !privateLinkAtLeast(phase.stage, 'retire-old-receiver')) fail('PRIVATE_LINK_NAME_STAGE_FORBIDDEN');
  if (phase.deploymentId && (proof.validation?.properties?.provisioningState !== 'Succeeded' ||
      proof.validation.error || proof.validation.properties.error || proof.validation.nextLink)) fail('PRIVATE_LINK_TEMPLATE_VALIDATION_REQUIRED');
  if (proofs && privateLinkValidationIsImmutable(proof) && privateLinkValidationIsImmutable(phase)) {
    proofs.set(proof, { phase, records: evidence.records.length, last: evidence.records.at(-1), adoption: externalNsg(evidence) });
  }
}
function policyTargetPhase(c, context, phase, snapshot) {
  const resources = phase.resources.length ? structuredClone(phase.resources) : [{
    id: context.plan.topology.ids.account, type: 'Microsoft.Storage/storageAccounts', apiVersion: API.storage,
    expected: structuredClone(snapshot.resources[context.plan.topology.ids.account]),
  }];
  if (phase.request?.method === 'DELETE') for (const d of resources) d.expected = structuredClone(snapshot.resources[d.id]);
  if (phase.stage === 'disable-storage-public') resources[0].expected = {
    ...structuredClone(snapshot.resources[phase.request.id]),
    properties: { ...structuredClone(snapshot.resources[phase.request.id].properties), publicNetworkAccess: 'Disabled' },
  };
  if (phase.externalAdoptionSha256 && snapshot?.externalNsg) {
    for (const value of Object.values(privateLinkNsgMembers(snapshot.externalNsg))) resources.push({ id: value.id,
      type: 'Microsoft.Network/networkSecurityGroups', apiVersion: API.network, expected: structuredClone(value) });
  }
  return { ...phase, resources };
}
async function governance(c, context, phase, snapshot, io, deadline) {
  const r = ids(c);
  const providerTask = io.batch([['network', 'Microsoft.Network'], ['storage', 'Microsoft.Storage'], ['app', 'Microsoft.App']],
    async ([key, ns]) => [key, await io.read({ id: `${r.sub}/providers/${ns}`, apiVersion: '2021-04-01', filter: null }, deadline)]);
  const scopes = [...new Set(privateLinkPermissions(c, context, phase).map(value => value.scope))];
  const permissionTask = io.batch(scopes, async scope => [scope,
    Object.fromEntries(await io.batch([['permissions', 'permissions'], ['denies', 'denyAssignments']], async ([key, suffix]) => [key,
      await io.read(permissionRequest(scope, suffix), deadline, true)]))]);
  const policyTask = (async () => {
    const independent = !phase.externalAdoptionSha256 && phase.resources.length && phase.request?.method !== 'DELETE' && phase.stage !== 'disable-storage-public';
    const targets = independent ? null : await snapshot;
    const evaluation = collectEffectivePolicies(policyTargetPhase(c, context, phase, targets), async (id, apiVersion, filter) => {
      const request = { id, apiVersion, filter: filter ?? null };
      io.allowPolicyRead(request);
      return io.read(request, deadline, /\/(?:policyAssignments|policyExemptions|versions)$/iu.test(id));
    }, io.batch, value => io.retain('effective-policy', value));
    return independent ? (await Promise.all([evaluation, snapshot]))[0] : evaluation;
  })();
  const [providers, permissions, policy] = await Promise.all([providerTask, permissionTask, policyTask]);
  return { providers: Object.fromEntries(providers), permissions: Object.fromEntries(permissions), policy };
}
function snapshotWithTargets(c, context, io, deadline, adoption = null) {
  let ready, failed;
  const targets = new Promise((resolve, reject) => { ready = resolve; failed = reject; });
  const snapshot = collectPrivateLinkSnapshot(c, context, io, deadline, ready, adoption);
  snapshot.catch(failed);
  return { snapshot, targets };
}
export async function checkPrivateLinkPhase(c, context, evidence, phase, io) {
  return checkWithValidation(c, context, evidence, phase, io, io.now());
}
function checkWithValidation(c, context, evidence, phase, io, startedAt) {
  return withDispatchValidation(c, context, { evidence, phase }, (snapshot, validation) =>
    checkPhase(c, context, snapshot.evidence, snapshot.phase, io, startedAt, validation));
}
async function checkPhase(c, context, evidence, phase, io, startedAt, validation) {
  const deadline = startedAt + LIMITS.checkMs, source = await io.sourceDigest(), state = dispatchValidation(c, context, validation);
  const nameReviewSha256 = hash(io.nameProjection ?? null);
  let reviewed = null;
  const guard = () => {
    if (state) assertDispatchInputs(state);
    io.checkRuntimeCompletion?.();
    if (hash(io.nameProjection ?? null) !== nameReviewSha256) fail('PRIVATE_LINK_NAME_REVIEW_CHANGED');
    if (reviewed) {
      equal(io.costReview, reviewed.costReview, 'PRIVATE_LINK_PREFLIGHT_BINDING_CHANGED');
      equal(io.costEvidence, reviewed.costEvidence, 'PRIVATE_LINK_PREFLIGHT_BINDING_CHANGED');
      equal(io.migrationReview, reviewed.migrationReview, 'PRIVATE_LINK_PREFLIGHT_BINDING_CHANGED');
      phaseSource(c, context, phase, io.now());
      if (phase.continuation) boundedReview(phase.continuation.review, io.now());
      verifyPrivateLinkCostReview(c, context, io.costReview, io.costEvidence, source, io.now());
      verifyPrivateLinkMigrationReview(c, context, io.migrationReview, io.now(), source);
    }
    if (io.cancelled?.() || io.now() >= deadline) fail('PRIVATE_LINK_CHECK_EXPIRED');
  };
  guard();
  equal(phase, preparePhase(c, context, evidence, phase.stage, phase.policyRevision ?? null, phase.continuation ?? null,
    phase.stage === 'create-environment' ? 2 : 1, validation), 'PRIVATE_LINK_PREPARED_PHASE_CHANGED');
  if (source !== phaseSource(c, context, phase, io.now())) fail('PRIVATE_LINK_SOURCE_CHANGED');
  if (io.nameProjection) {
    if (!privateLinkAtLeast(phase.stage, 'retire-old-receiver')) fail('PRIVATE_LINK_NAME_STAGE_FORBIDDEN');
    verifyPrivateLinkNameProjection(c, context, io.nameProjection, io.now(), evidence);
    if (io.nameProjection.sourceSha256 !== source) fail('PRIVATE_LINK_NAME_POLICY_CHANGED');
  }
  // Finish synchronous source/history validation before spawning bounded reads.
  await io.verifySources(deadline, validation);
  guard();
  const collection = snapshotWithTargets(c, context, io, deadline, externalNsg(evidence));
  const [head, before, controls, deploymentPreview, deploymentBefore] = await Promise.all([
    io.head(evidence), collection.snapshot, governance(c, context, phase, collection.targets, io, deadline),
    phase.deploymentId ? io.preview(phase, deadline) : null,
    phase.continuation && phase.deploymentId ? io.read({ id: phase.deploymentId, apiVersion: API.deployment, filter: null }, deadline) : null,
  ]);
  guard();
  // verifyProof below validates this same fresh snapshot before preflight retention.
  if (phase.stage === 'review-migration') equal(await io.nspHead(), context.origin.pendingHead, 'PRIVATE_LINK_ORIGINAL_PENDING_HEAD_CHANGED');
  const preview = phase.deploymentId ? deploymentPreview : { validation: null, preview: {
    version: 1, kind: 'exact-private-link-request-preimage', request: phase.request,
    preimageSha256: hash(phase.request ? before.resources[phase.request.id] : null), nativeArmWhatIf: false,
  } };
  const runtimeInput = privateLinkAtLeast(phase.stage, 'retire-old-receiver') ? await io.runtimeCompletion(deadline) : null;
  if (runtimeInput) io.verifyRuntimeCompletion(runtimeInput, io.now());
  const runtimeCompletion = runtimeInput ? immutableDispatchCopy(runtimeInput) : null;
  const proof = { version: 1, kind: 'checked-private-link-phase', startedAt, completedAt: io.now(),
    sourceSha256: source, phaseSha256: hash(phase), planSha256: context.plan.planSha256, contextSha256: hash(context.origin),
    head, before, ...controls, costReview: io.costReview, costEvidence: io.costEvidence,
    migrationReview: io.migrationReview, ...preview, runtimeCompletion,
    ...(phase.continuation ? { deploymentBefore } : {}) };
  proof.binding = proofBindings(proof);
  if (await io.sourceDigest() !== source || io.now() >= deadline) fail('PRIVATE_LINK_CHECK_EXPIRED');
  verifyProof(c, context, evidence, phase, proof, io.now(), validation);
  reviewed = immutableDispatchCopy({ costReview: proof.costReview, costEvidence: proof.costEvidence, migrationReview: proof.migrationReview });
  guard();
  await io.retain('preflight', proof);
  equal(await io.head(evidence), head, 'PRIVATE_LINK_PREFLIGHT_HEAD_CHANGED');
  if (await io.sourceDigest() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
  guard();
  return proof;
}
export function verifyPrivateLinkApproval(c, context, phase, proof, approval, at) {
  closed(approval, ['version', 'action', 'configSha256', 'planSha256', 'phaseSha256', 'bindingSha256',
    'sourceSha256', 'requestSha256', 'approvedAt', 'expiresAt']);
  boundedReview(approval, at);
  if (approval.version !== 1 || approval.action !== `execute-exact-private-link-${phase.stage}` ||
      approval.configSha256 !== hash(c) || approval.planSha256 !== context.plan.planSha256 ||
      approval.phaseSha256 !== hash(phase) || approval.bindingSha256 !== hash(proof.binding) ||
      approval.sourceSha256 !== phaseSource(c, context, phase, at) || approval.requestSha256 !== hash(phase.request)) fail('PRIVATE_LINK_EXACT_APPROVAL_REQUIRED');
  if (phase.continuation) boundedReview(phase.continuation.review, at);
  if (proof.before?.nameProjection) {
    verifyPrivateLinkNameProjection(c, context, proof.before.nameProjection, at);
    if (proof.before.nameProjection.sourceSha256 !== approval.sourceSha256) fail('PRIVATE_LINK_NAME_POLICY_CHANGED');
  }
}
function verifyTransition(c, context, phase, before, after, evidence, validation = null) {
  verifyPrivateLinkSnapshot(c, context, after, phase.stage,
    phase.stage === 'create-environment' ? phase.version : environmentWireVersion(evidence),
    privateLinkNsgValidationFor(c, context, phaseExternalNsg(evidence, phase), validation), evidence);
  if (after.nameProjection || before.nameProjection) {
    if (!after.nameProjection || !before.nameProjection) fail('PRIVATE_LINK_NAME_REVIEW_CHANGED');
    equal(privateLinkNameBinding(c, context, after.nameProjection, evidence),
      privateLinkNameBinding(c, context, before.nameProjection, evidence), 'PRIVATE_LINK_NAME_REVIEW_CHANGED');
  }
  const n = context.plan.topology.ids, q = context.origin.adoption.topology.ids;
  for (const [id, previous] of Object.entries(before.resources)) if (previous && after.resources[id]) {
    equal(privateLinkGeneration(previous), privateLinkGeneration(after.resources[id]), 'PRIVATE_LINK_GENERATION_CHANGED');
  }
  for (const id of [n.account, q.service, q.queue, n.ingestIdentity, n.pullIdentity, n.oldApp, n.oldEnvironment]) {
    if (!before.resources[id] || !after.resources[id]) continue;
    equal(privateLinkGeneration(before.resources[id]), privateLinkGeneration(after.resources[id]), 'PRIVATE_LINK_GENERATION_CHANGED');
    if (id !== n.account && id !== n.oldApp && id !== n.oldEnvironment) equal(privateLinkResourceState(before.resources[id]),
      privateLinkResourceState(after.resources[id]), 'PRIVATE_LINK_PRESERVED_RESOURCE_CHANGED');
    if ([n.oldApp, n.oldEnvironment].includes(id)) equal(privateLinkResourceState(before.resources[id]),
      privateLinkResourceState(after.resources[id]), 'PRIVATE_LINK_OLD_RUNTIME_CHANGED');
  }
  const account = privateLinkResourceState(before.resources[n.account]);
  if (phase.stage === 'disable-storage-public') account.properties.publicNetworkAccess = 'Disabled';
  if (phase.stage === 'create-queue-endpoint') account.properties.privateEndpointConnections =
    structuredClone(after.resources[n.account].properties.privateEndpointConnections);
  equal(account, privateLinkResourceState(after.resources[n.account]), 'PRIVATE_LINK_UNRELATED_ACCOUNT_CHANGE');
  for (const id of Object.values(context.origin.network.topology.ids).filter(id =>
    id.toLowerCase().includes('/providers/microsoft.network/networksecurityperimeters/'))) {
    if (!before.resources[id] || !after.resources[id]) continue;
    equal(privateLinkGeneration(before.resources[id]), privateLinkGeneration(after.resources[id]), 'PRIVATE_LINK_NSP_GENERATION_CHANGED');
    const expected = privateLinkResourceState(before.resources[id]);
    if (id === context.origin.network.topology.ids.profile && phase.stage === 'retire-nsp-rule') {
      expected.properties.accessRulesVersion = after.resources[id].properties.accessRulesVersion;
    }
    equal(expected, privateLinkResourceState(after.resources[id]), 'PRIVATE_LINK_UNRELATED_NSP_CHANGE');
  }
  if (phase.stage === 'retire-nsp-rule') {
    const old = context.origin.network.topology.ids.profile;
    if (Number(after.resources[old].properties.accessRulesVersion) <= Number(before.resources[old].properties.accessRulesVersion)) fail('PRIVATE_LINK_RULE_REMOVAL_VERSION_UNVERIFIED');
  }
}
function verifyDeploymentOperations(phase, deployment, operations) {
  if (!phase.deploymentId) {
    if (deployment !== null || operations !== null) fail('PRIVATE_LINK_UNEXPECTED_DEPLOYMENT');
    return;
  }
  if (!sameId(deployment?.id, phase.deploymentId)) fail('PRIVATE_LINK_DEPLOYMENT_ID_CHANGED');
  verifyDeploymentIdentity(deployment, deployment);
  queueArmInstant(deployment.properties.timestamp);
  if (!Array.isArray(deployment.properties.outputResources)) fail('PRIVATE_LINK_DEPLOYMENT_OUTPUTS_REQUIRED');
  equal(deployment.properties.outputResources.map(value => value.id?.toLowerCase()).sort(),
    phase.resources.map(value => value.id.toLowerCase()).sort(), 'PRIVATE_LINK_DEPLOYMENT_TARGETS_CHANGED');
  const seen = new Set(), idsSeen = new Set();
  for (const operation of plList(operations)) {
    const p = operation?.properties, id = operation?.operationId;
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(id) || idsSeen.has(id) ||
        !sameId(operation.id, `${phase.deploymentId}/operations/${id}`) || p?.provisioningState !== 'Succeeded' ||
        !['OK', 'Created', '200', '201'].includes(p.statusCode)) fail('PRIVATE_LINK_DEPLOYMENT_OPERATIONS_UNVERIFIED');
    idsSeen.add(id);
    if (p.provisioningOperation === 'EvaluateDeploymentOutput' && !p.targetResource) continue;
    const d = phase.resources.find(value => sameId(value.id, p.targetResource?.id));
    if (!d || seen.has(d.id) || p.provisioningOperation !== 'Create' ||
        !sameId(d.type, p.targetResource.resourceType)) fail('PRIVATE_LINK_UNEXPECTED_DEPLOYMENT_EFFECT');
    seen.add(d.id);
  }
  if (seen.size !== phase.resources.length) fail('PRIVATE_LINK_DEPLOYMENT_OPERATIONS_INCOMPLETE');
}
export function verifyPrivateLinkControlEvidence(c, context, evidence, at) {
  return withDispatchValidation(c, context, { evidence }, (snapshot, validation) => {
    verifyControlEvidence(c, context, snapshot.evidence, at, validation);
    return evidence.records.at(-1) ?? null;
  });
}
function verifyControlEvidence(c, context, evidence, at, validation) {
  const state = dispatchValidation(c, context, validation), prior = state && verifiedHistory(state, evidence);
  if (prior) {
    if (at !== undefined && (prior.records.some(record => canonicalInstant(record.completedAt) > at) ||
        (externalNsg(prior) && canonicalInstant(prior.externalAdoption.adoptedAt) > at))) fail('PRIVATE_LINK_RECORD_INVALID');
    return evidence.records.at(-1) ?? null;
  }
  const pure = pureValidation(c, context);
  if (!state && pure && !externalNsg(evidence)) {
    const copy = immutableDispatchCopy(evidence);
    if (!pure.histories.has(copy)) {
      const scope = runtimeValidations.getStore();
      if (scope && activeRuntimeValidations.has(scope) && evidence === scope.evidence) scope.statistics.immutableHistoryVerifications++;
      withPrivateLinkControlValidation(c, context, () => verifyControlRecords(c, context, copy, at, null));
      pure.histories.add(copy);
    }
    if (at !== undefined && copy.records.some(record => canonicalInstant(record.completedAt) > at)) fail('PRIVATE_LINK_RECORD_INVALID');
    return evidence.records.at(-1) ?? null;
  }
  if (externalNsg(evidence) && !validation) return withPrivateLinkNsgValidation(c, context, externalNsg(evidence), evidence,
    proof => verifyControlEvidence(c, context, evidence, at, proof));
  const scope = runtimeValidations.getStore();
  if (scope && activeRuntimeValidations.has(scope) && evidence === scope.evidence) scope.statistics.immutableHistoryVerifications++;
  const result = withPrivateLinkControlValidation(c, context, () => verifyControlRecords(c, context, evidence, at, validation));
  if (state) {
    const value = evidence === state.evidence ? state.evidence : immutableDispatchCopy(evidence);
    state.histories.push({ value, sha256: hash(value) });
    if (evidence === state.evidence) state.verifiedEvidence = value;
  }
  return result;
}
function verifyControlRecords(c, context, evidence, at, validation) {
  verifyPrivateLinkControlContext(c, context);
  closed(evidence, ['version', 'kind', 'planSha256', 'originSha256', 'records', ...(evidence.version === 2 ? ['externalAdoption'] : [])]);
  if (![1, 2].includes(evidence.version) || evidence.kind !== 'reviewed-private-link-control-chain' ||
      evidence.planSha256 !== context.plan.planSha256 || evidence.originSha256 !== hash(context.origin) ||
      !Array.isArray(evidence.records) || evidence.records.length > STAGES.length) fail('PRIVATE_LINK_CHAIN_INVALID');
  const prior = emptyPrivateLinkControlEvidence(context);
  const adoption = validation ? privateLinkNsgValidatedRecord(c, context,
    privateLinkNsgValidationFor(c, context, externalNsg(evidence), validation)) : verifyPrivateLinkNsgEvidenceBinding(c, context, evidence);
  if (adoption) {
    const anchor = privateLinkNsgValidatedAnchor(c, context, validation);
    equal(evidence.records.slice(0, 6), anchor.records, 'PRIVATE_LINK_NSG_ANCHOR_CHANGED');
    if (at !== undefined && canonicalInstant(adoption.adoptedAt) > at) fail('PRIVATE_LINK_NSG_ADOPTION_FROM_FUTURE');
    prior.records.push(...anchor.records);
  }
  const verified = dispatchValidation(c, context, validation)?.verifiedEvidence;
  if (verified && verified.records.length > prior.records.length &&
      verified.records.length <= evidence.records.length &&
      verified.records.every((record, index) => record === evidence.records[index]) &&
      externalNsg(verified) === externalNsg(evidence)) {
    if (at !== undefined && verified.records.some(record => canonicalInstant(record.completedAt) > at)) fail('PRIVATE_LINK_RECORD_INVALID');
    prior.records = [...verified.records];
    prior.version = verified.version;
    if (verified.version === 2) prior.externalAdoption = verified.externalAdoption;
  }
  for (const record of evidence.records.slice(prior.records.length)) {
    if (adoption && prior.records.length === adoption.proposal.anchor.records) {
      prior.version = 2; prior.externalAdoption = adoption;
    }
    closed(record, ['version', 'kind', 'stage', 'phase', 'publication', 'approval', 'preflight', 'intent',
      'intentSha256', 'journal', 'after', 'deployment', 'operations', 'completedAt', 'authority', 'recovery']);
    order(prior, record.stage);
    const expected = { ...privateLinkPhase(c, context, record.stage, record.phase.version), predecessorSha256: prior.records.length ? hash(prior.records.at(-1)) : null,
      expectedHead: record.phase.continuation?.resolution.proposal.pendingHead ?? privateLinkHead(context, prior),
      sourceSha256: record.phase.policyRevision?.sourceSha256 ?? context.plan.sourceSha256,
      ...(record.phase.policyRevision ? { policyRevision: record.phase.policyRevision } : {}),
      ...(record.phase.continuation ? { continuation: record.phase.continuation } : {}),
      ...(externalNsg(prior) ? { externalAdoptionSha256: hash(prior.externalAdoption) } : {}) };
    equal(record.phase, expected, 'PRIVATE_LINK_PHASE_CHANGED');
    const intentAt = canonicalInstant(record.intent.at), completedAt = canonicalInstant(record.completedAt);
    const modern = record.intent.version === 2;
    closed(record.intent, ['version', 'stage', 'phaseSha256', 'approvalSha256', 'requestSha256', 'previousHeadSha256', 'at',
      ...(modern ? ['finalCheckDeadline', 'maximumRolloutMs'] : []),
      ...(record.phase.continuation ? ['attemptId'] : [])]);
    closed(record.journal, ['version', 'intentSha256', 'outcome', 'dispatchAttempted', 'failure',
      ...(modern ? ['dispatchAt', 'rolloutStartedAt', 'rolloutDeadline'] : [])]);
    closed(record.publication, ['commitSha', 'sourceSha256']);
    if (![1, 2, 3].includes(record.version) || !['reviewed-private-link-phase', 'reviewed-private-link-recovery'].includes(record.kind) ||
        !/^[0-9a-f]{40}$/u.test(record.publication.commitSha ?? '') || record.publication.sourceSha256 !== record.phase.sourceSha256 ||
        ![1, 2].includes(record.intent.version) || record.intent.stage !== record.stage ||
        (record.journal.version !== record.intent.version && !(modern && record.journal.version === 3)) ||
        record.intentSha256 !== hash(record.intent) || record.intent.phaseSha256 !== hash(record.phase) ||
        record.intent.approvalSha256 !== hash(record.approval) || record.intent.requestSha256 !== hash(record.phase.request) ||
        record.intent.previousHeadSha256 !== hash(record.phase.expectedHead) || completedAt < intentAt ||
        (record.phase.continuation && record.intent.attemptId !== record.phase.continuation.attemptId) ||
        (at !== undefined && completedAt > at)) fail('PRIVATE_LINK_RECORD_INVALID');
    if (prior.records.length && intentAt < canonicalInstant(prior.records.at(-1).completedAt)) fail('PRIVATE_LINK_PREDECESSOR_TIME_CHANGED');
    verifyProof(c, context, prior, record.phase, record.preflight, intentAt, validation);
    verifyPrivateLinkApproval(c, context, record.phase, record.preflight, record.approval, intentAt);
    equal(record.authority, authority, 'PRIVATE_LINK_AUTHORITY_CHANGED');
    if (record.kind === 'reviewed-private-link-phase') {
      const rolloutAt = modern ? canonicalInstant(record.journal.rolloutStartedAt) : intentAt;
      if (modern) {
        if (!Number.isSafeInteger(record.intent.finalCheckDeadline) ||
            record.intent.finalCheckDeadline > intentAt + LIMITS.checkMs ||
            record.intent.maximumRolloutMs !== record.phase.rolloutMs || rolloutAt < intentAt ||
            rolloutAt >= record.intent.finalCheckDeadline || !Number.isSafeInteger(record.journal.rolloutDeadline) ||
            record.journal.rolloutDeadline <= rolloutAt || record.journal.rolloutDeadline > rolloutAt + record.phase.rolloutMs ||
            record.journal.rolloutDeadline > Math.min(canonicalInstant(record.approval.expiresAt),
              canonicalInstant(record.preflight.costReview.expiresAt), canonicalInstant(record.preflight.migrationReview.expiresAt)) ||
            (record.phase.request === null ? record.journal.dispatchAt !== null :
              record.journal.version === 3 ? canonicalInstant(record.journal.dispatchAt) < rolloutAt ||
                canonicalInstant(record.journal.dispatchAt) >= record.journal.rolloutDeadline :
                record.journal.dispatchAt !== record.journal.rolloutStartedAt)) fail('PRIVATE_LINK_EXECUTION_CLOCK_INVALID');
        verifyProof(c, context, prior, record.phase, record.preflight, rolloutAt, validation);
        verifyPrivateLinkApproval(c, context, record.phase, record.preflight, record.approval, rolloutAt);
        if (record.journal.dispatchAt !== null) {
          const dispatchedAt = canonicalInstant(record.journal.dispatchAt);
          verifyProof(c, context, prior, record.phase, record.preflight, dispatchedAt, validation);
          verifyPrivateLinkApproval(c, context, record.phase, record.preflight, record.approval, dispatchedAt);
        }
      }
      if (record.recovery !== null || record.journal.outcome !== 'readback-qualified' ||
          record.journal.failure !== null ||
          record.journal.intentSha256 !== record.intentSha256 || record.journal.dispatchAttempted !== (record.phase.request !== null) ||
          completedAt > (modern ? record.journal.rolloutDeadline : intentAt + record.phase.rolloutMs) ||
          record.after.startedAt < rolloutAt || record.after.completedAt > completedAt) fail('PRIVATE_LINK_EXECUTION_RECORD_INVALID');
    } else verifyRecovery(c, context, prior, record, validation);
    verifyTransition(c, context, record.phase, record.preflight.before, record.after, prior, validation);
    verifyDeploymentOperations(record.phase, record.deployment, record.operations);
    if (record.phase.deploymentId) {
      const templateHash = record.preflight.validation?.properties?.templateHash;
      if (typeof templateHash !== 'string' || record.deployment.properties.templateHash !== templateHash) fail('PRIVATE_LINK_DEPLOYMENT_TEMPLATE_CHANGED');
      for (const resource of record.phase.resources) {
        const generation = privateLinkGeneration(record.after.resources[resource.id]);
        if (!generation || (generation.createdAt === null && generation.resourceGuid === null &&
            !['Microsoft.Network/virtualNetworks/subnets', 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups',
              'Microsoft.Network/privateDnsZones/virtualNetworkLinks'].includes(resource.type))) fail('PRIVATE_LINK_RESOURCE_GENERATION_UNVERIFIED');
        if (generation?.createdAt?.startsWith('opaque-recorded-aca:')) {
          if (resource.type !== 'Microsoft.App/managedEnvironments' || record.preflight.before.resources[resource.id] !== null ||
              queueArmInstant(record.deployment.properties.timestamp) < BigInt(intentAt) * 10000n ||
              queueArmInstant(record.deployment.properties.timestamp) > BigInt(completedAt) * 10000n) fail('PRIVATE_LINK_ACA_CREATION_CAUSALITY_UNPROVEN');
        } else if (generation?.createdAt !== null && (BigInt(generation.createdAt) < BigInt(intentAt) * 10000n ||
            BigInt(generation.createdAt) > BigInt(completedAt) * 10000n)) fail('PRIVATE_LINK_CREATION_TIME_CHANGED');
      }
    }
    prior.records.push(record);
    const state = dispatchValidation(c, context, validation);
    if (state) state.histories.push({ value: Object.freeze({ ...prior, records: Object.freeze([...prior.records]) }), sha256: null });
  }
  return evidence.records.at(-1) ?? null;
}
async function verifyCurrent(c, context, evidence, phase, proof, io, deadline, pending, validation) {
  if (await io.sourceDigest() !== phaseSource(c, context, phase, io.now())) fail('PRIVATE_LINK_SOURCE_CHANGED');
  await io.head(evidence, pending);
  const collection = snapshotWithTargets(c, context, io, deadline, externalNsg(evidence));
  const [current, controls, deploymentBefore] = await Promise.all([collection.snapshot, governance(c, context, phase, collection.targets, io, deadline),
    phase.continuation && phase.deploymentId ? io.read({ id: phase.deploymentId, apiVersion: API.deployment, filter: null }, deadline) : null]);
  if (phase.continuation && deploymentBefore !== null) fail('PRIVATE_LINK_CONTINUATION_DEPLOYMENT_PRESENT');
  verifyPrivateLinkSnapshot(c, context, current, originalState(evidence), environmentWireVersion(evidence),
    privateLinkNsgValidationFor(c, context, externalNsg(evidence), validation), evidence);
  verifyCostScope(c, context, evidence, current, io.now());
  equal(snapshotState(current), snapshotState(proof.before), 'PRIVATE_LINK_DISPATCH_PREIMAGE_CHANGED');
  for (const key of ['providers', 'permissions', 'policy']) equal(controls[key], proof[key], 'PRIVATE_LINK_DISPATCH_GOVERNANCE_CHANGED');
  if (proof.runtimeCompletion) {
    const runtime = await io.runtimeCompletion(deadline);
    equal(runtime, proof.runtimeCompletion, 'PRIVATE_LINK_RUNTIME_QUALIFICATION_CHANGED');
    io.verifyRuntimeCompletion(runtime, io.now());
  }
  await io.head(evidence, pending);
  if (await io.sourceDigest() !== phaseSource(c, context, phase, io.now()) || io.now() >= deadline) fail('PRIVATE_LINK_SOURCE_OR_DEADLINE_CHANGED');
  if (phase.stage === 'retire-old-environment' && plList(current.lists.apps).some(value =>
    sameId(value.properties?.managedEnvironmentId, context.plan.topology.ids.oldEnvironment))) fail('PRIVATE_LINK_OLD_ENVIRONMENT_NOT_EMPTY');
}
export async function executePrivateLinkPhase(c, context, evidence, phase, proof, approval, io) {
  return withDispatchValidation(c, context, { evidence, phase, proof, approval }, (snapshot, validation) =>
    executePhase(c, context, snapshot.evidence, snapshot.phase, snapshot.proof, snapshot.approval, io, validation));
}
async function executePhase(c, context, evidence, phase, proof, approval, io, validation) {
  const state = dispatchValidation(c, context, validation);
  equal(phase, preparePhase(c, context, evidence, phase.stage, phase.policyRevision ?? null, phase.continuation ?? null,
    phase.stage === 'create-environment' ? 2 : 1, validation), 'PRIVATE_LINK_PREPARED_PHASE_CHANGED');
  verifyProof(c, context, evidence, phase, proof, io.now(), validation);
  verifyPrivateLinkApproval(c, context, phase, proof, approval, io.now());
  if (state) { assertDispatchInputs(state); state.validated = true; }
  await io.verifySources(io.now() + LIMITS.checkMs, validation);
  if (await io.journal()) fail('PRIVATE_LINK_INTENT_REPLAY_FORBIDDEN');
  if (state) {
    assertDispatchInputs(state);
    currentDispatchReviews(c, context, evidence, phase, proof, approval, io.now());
  }
  const at = io.now(), reviewDeadline = Math.min(canonicalInstant(approval.expiresAt),
    canonicalInstant(proof.costReview.expiresAt), canonicalInstant(proof.migrationReview.expiresAt),
    phase.policyRevision ? canonicalInstant(phase.policyRevision.expiresAt) : Infinity,
    phase.continuation ? canonicalInstant(phase.continuation.review.expiresAt) : Infinity);
  const finalCheckDeadline = Math.min(at + LIMITS.checkMs, reviewDeadline, proof.startedAt + LIMITS.freshnessMs);
  let deadline = finalCheckDeadline;
  const intent = { version: 2, stage: phase.stage, phaseSha256: hash(phase), approvalSha256: hash(approval),
    requestSha256: hash(phase.request), previousHeadSha256: hash(phase.expectedHead), at: stamp(at),
    finalCheckDeadline, maximumRolloutMs: phase.rolloutMs,
    ...(phase.continuation ? { attemptId: phase.continuation.attemptId } : {}) };
  const pending = await io.reserve(evidence, phase, intent, validation);
  const journal = { version: 3, intentSha256: hash(intent), outcome: 'submission-possible', dispatchAttempted: false,
    dispatchAt: null, rolloutStartedAt: null, rolloutDeadline: null, failure: null };
  await io.saveJournal(journal);
  const guard = () => {
    if (state) assertDispatchInputs(state);
    io.checkRuntimeCompletion?.();
    if (hash(io.nameProjection ?? null) !== hash(proof.before.nameProjection ?? null)) fail('PRIVATE_LINK_NAME_REVIEW_CHANGED');
    verifyPrivateLinkApproval(c, context, phase, proof, approval, io.now());
    verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, phase.sourceSha256, io.now());
    verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, io.now(), phase.sourceSha256);
    if (journal.dispatchAttempted !== true) fresh(proof, io.now());
    if (io.cancelled?.() || io.now() >= deadline) fail('PRIVATE_LINK_OPERATION_EXPIRED');
  };
  const beginRollout = dispatchPossible => {
    guard();
    const start = io.now();
    journal.dispatchAttempted = dispatchPossible ? null : false; journal.dispatchAt = null;
    journal.rolloutStartedAt = stamp(start); deadline = Math.min(start + phase.rolloutMs, reviewDeadline);
    journal.rolloutDeadline = deadline;
  };
  try {
    if (phase.request) await io.write(phase, guard, async () => {
      await verifyCurrent(c, context, evidence, phase, proof, io, finalCheckDeadline, pending, validation);
      guard();
    }, async () => {
      beginRollout(true);
      // Durability precedes the final synchronous guard and transport invocation.
      await io.saveJournal(journal);
      return { rolloutDeadline: deadline, beforeInvoke: () => {
        journal.dispatchAttempted = true; journal.dispatchAt = stamp(io.now());
      } };
    }, finalCheckDeadline, validation);
    else {
      await verifyCurrent(c, context, evidence, phase, proof, io, finalCheckDeadline, pending, validation);
      beginRollout(false);
    }
    const maximum = Math.ceil(phase.rolloutMs / LIMITS.pollMs);
    for (let poll = 0; poll < maximum; poll++) {
      guard();
      const deployment = phase.deploymentId ? await io.read({ id: phase.deploymentId, apiVersion: API.deployment, filter: null }, deadline) : null;
      if (deployment && ['Failed', 'Canceled'].includes(deployment.properties?.provisioningState)) fail('PRIVATE_LINK_DEPLOYMENT_FAILED');
      const after = await collectPrivateLinkSnapshot(c, context, io, Math.min(deadline, io.now() + LIMITS.checkMs), null, externalNsg(evidence));
      await io.retain(`readback-${poll}`, { deployment, after });
      guard();
      let pendingState = phase.deploymentId && deployment?.properties?.provisioningState !== 'Succeeded';
      if (!pendingState) {
        try { verifyTransition(c, context, phase, proof.before, after, evidence, validation); }
        catch (error) {
          if (['PRIVATE_LINK_PROPAGATION_PENDING', 'PRIVATE_LINK_NSP_PROPAGATION_PENDING', 'PRIVATE_LINK_NSP_RULE_COPY_PRESENT',
            'PRIVATE_LINK_NSP_EFFECTIVE_COPY_PRESENT', 'PRIVATE_LINK_STAGE_RESOURCE_MISMATCH', 'PRIVATE_LINK_RETIREMENT_UNVERIFIED',
            'PRIVATE_LINK_CONNECTION_NOT_APPROVED', 'PRIVATE_LINK_DNS_LINK_UNVERIFIED'].includes(error.message)) pendingState = true;
          else throw error;
        }
      }
      if (!pendingState) {
        const operations = phase.deploymentId ? await io.read({ id: `${phase.deploymentId}/operations`,
          apiVersion: API.deployment, filter: null }, deadline, true) : null;
        verifyDeploymentOperations(phase, deployment, operations);
        journal.outcome = 'readback-qualified';
        const record = { version: 3, kind: 'reviewed-private-link-phase', stage: phase.stage, phase,
          publication: io.publication, approval, preflight: proof, intent, intentSha256: hash(intent),
          journal: structuredClone(journal), after, deployment, operations, completedAt: stamp(io.now()), authority, recovery: null };
        const result = { ...evidence, records: [...evidence.records, record] };
        verifyControlEvidence(c, context, result, io.now(), validation);
        guard();
        await io.append(pending, record, privateLinkHead(context, result), guard);
        await io.saveJournal(journal);
        return record;
      }
      await io.sleep(Math.min(LIMITS.pollMs, Math.max(0, deadline - io.now())));
    }
    fail('PRIVATE_LINK_ROLLOUT_UNRESOLVED');
  } catch (error) {
    // A live process knows that its synchronous invocation marker was not reached.
    // A crashed process instead leaves the persisted null (dispatch-possible) marker.
    if (journal.dispatchAttempted === null) journal.dispatchAttempted = false;
    journal.outcome = 'reconciliation-required'; journal.failure = safeOperationFailure(error);
    await io.saveJournal(journal);
    fail('PRIVATE_LINK_STOPPED_ORIGINAL_INTENT_PRESERVED');
  }
}
export function privateLinkSubmissionState(original) {
  const j = original?.journal, intent = original?.intent, phase = original?.phase;
  if (!j || !intent || !phase || !['submission-possible', 'reconciliation-required'].includes(j.outcome) ||
      j.intentSha256 !== hash(intent) || ![false, true, null].includes(j.dispatchAttempted)) fail('PRIVATE_LINK_STOPPED_INTENT_REQUIRED');
  if (phase.request === null) {
    if (j.dispatchAttempted !== false) fail('PRIVATE_LINK_NONMUTATING_INTENT_CHANGED');
    return 'nonmutating';
  }
  if (j.version < 3 && j.dispatchAttempted === false) return 'legacy-dispatch-unknown';
  if (j.version === 3 && j.dispatchAttempted === false) {
    if (j.dispatchAt !== null) fail('PRIVATE_LINK_DISPATCH_MARKER_INVALID');
    return 'known-not-submitted';
  }
  if (j.version === 3) {
    const possibleAt = canonicalInstant(j.rolloutStartedAt), reservedAt = canonicalInstant(intent.at);
    if (intent.version !== 2 || possibleAt < reservedAt || possibleAt >= intent.finalCheckDeadline ||
        !Number.isSafeInteger(j.rolloutDeadline) || j.rolloutDeadline <= possibleAt ||
        j.rolloutDeadline > possibleAt + phase.rolloutMs ||
        (j.dispatchAttempted === null ? j.dispatchAt !== null :
          canonicalInstant(j.dispatchAt) < possibleAt || canonicalInstant(j.dispatchAt) >= j.rolloutDeadline)) fail('PRIVATE_LINK_DISPATCH_MARKER_INVALID');
    return j.dispatchAttempted === null ? 'dispatch-possible' : 'dispatch-attempted';
  }
  if (j.dispatchAttempted !== true) fail('PRIVATE_LINK_DISPATCH_MARKER_INVALID');
  return 'dispatch-attempted';
}
function verifyRecovery(c, context, prior, record, validation) {
  const recovery = record.recovery;
  closed(recovery, ['original', 'proposal', 'review', 'costReview', 'costEvidence', 'migrationReview', 'currentPublication', 'policyRevision']);
  const { original, proposal, review } = recovery, at = canonicalInstant(record.completedAt);
  closed(original, ['phase', 'publication', 'approval', 'preflight', 'journal', 'intent']);
  const source = verifyPrivateLinkPolicyRevision(c, context, recovery.policyRevision, at);
  closed(recovery.currentPublication, ['commitSha', 'sourceSha256']);
  if (recovery.currentPublication.sourceSha256 !== source ||
      !/^[0-9a-f]{40}$/u.test(recovery.currentPublication.commitSha ?? '')) fail('PRIVATE_LINK_RECOVERY_PUBLICATION_INVALID');
  closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'pendingHeadSha256', 'approvedAt', 'expiresAt']);
  boundedReview(review, at);
  verifyPrivateLinkCostReview(c, context, recovery.costReview, recovery.costEvidence, source, at);
  verifyPrivateLinkMigrationReview(c, context, recovery.migrationReview, at, source);
  closed(proposal, ['version', 'kind', 'sourceSha256', 'originalSha256', 'pendingHead', 'after', 'deployment',
    'operations', 'originalExecutionQualified', 'replayAuthorized', 'policyRevision',
    ...([3, 4].includes(proposal.version) ? ['submissionState'] : []),
    ...(proposal.version === 4 ? ['externalAdoptionSha256'] : [])]);
  const submissionState = privateLinkSubmissionState(original);
  if (review.version !== 1 || review.action !== 'adopt-exact-private-link-late-state-without-replay' ||
      review.proposalSha256 !== hash(proposal) || review.sourceSha256 !== source ||
      review.pendingHeadSha256 !== hash(proposal.pendingHead) || submissionState === 'known-not-submitted' ||
      proposal.originalSha256 !== hash(original) || proposal.sourceSha256 !== source ||
      ![2, 3, 4].includes(proposal.version) || proposal.kind !== 'private-link-late-state-proposal' ||
      ([3, 4].includes(proposal.version) && proposal.submissionState !== submissionState) ||
      proposal.originalExecutionQualified !== false || proposal.replayAuthorized !== false) fail('PRIVATE_LINK_RECONCILIATION_REVIEW_REQUIRED');
  if (proposal.version === 4 && (!externalNsg(prior) || proposal.externalAdoptionSha256 !== hash(prior.externalAdoption))) fail('PRIVATE_LINK_NSG_RECOVERY_BINDING_CHANGED');
  equal(original.phase, record.phase, 'PRIVATE_LINK_ORIGINAL_PHASE_CHANGED');
  equal(original.publication, record.publication, 'PRIVATE_LINK_ORIGINAL_PUBLICATION_CHANGED');
  equal(proposal.policyRevision, recovery.policyRevision, 'PRIVATE_LINK_RECOVERY_POLICY_CHANGED');
  equal(original.preflight, record.preflight, 'PRIVATE_LINK_ORIGINAL_PREFLIGHT_CHANGED');
  equal(original.approval, record.approval, 'PRIVATE_LINK_ORIGINAL_APPROVAL_CHANGED');
  equal(original.intent, record.intent, 'PRIVATE_LINK_ORIGINAL_INTENT_CHANGED');
  equal(original.journal, record.journal, 'PRIVATE_LINK_ORIGINAL_JOURNAL_CHANGED');
  fresh(proposal.after, at);
  if (Boolean(proposal.after.nameProjection) !== Boolean(record.after.nameProjection)) fail('PRIVATE_LINK_NAME_REVIEW_CHANGED');
  for (const snapshot of [proposal.after, record.after]) if (snapshot.nameProjection) {
    verifyPrivateLinkNameProjection(c, context, snapshot.nameProjection, at, prior);
    equal(snapshot.nameProjection.publication, recovery.currentPublication, 'PRIVATE_LINK_NAME_POLICY_CHANGED');
  }
  if (record.after.startedAt < canonicalInstant(review.approvedAt) || record.after.completedAt > at) fail('PRIVATE_LINK_RECOVERY_FRESH_READ_REQUIRED');
  equal(snapshotState(record.after), snapshotState(proposal.after), 'PRIVATE_LINK_RECONCILIATION_STATE_CHANGED');
  equal(record.deployment, proposal.deployment, 'PRIVATE_LINK_RECOVERY_DEPLOYMENT_CHANGED');
  equal(record.operations, proposal.operations, 'PRIVATE_LINK_RECOVERY_OPERATIONS_CHANGED');
  equal(proposal.pendingHead, pendingHead(context, prior, record.intent, record.phase), 'PRIVATE_LINK_PENDING_HEAD_CHANGED');
  verifyTransition(c, context, record.phase, record.preflight.before, record.after, prior, validation);
}
export function verifyPrivateLinkOriginalNoSubmission(c, context, evidence, original, validation = null) {
  const state = dispatchValidation(c, context, validation);
  if (state?.originals.some(value => isDeepStrictEqual(value.evidence, evidence) && isDeepStrictEqual(value.original, original) &&
      value.evidenceSha256 === hash(evidence) && value.originalSha256 === hash(original))) return original;
  if (externalNsg(evidence) && !validation) return withDispatchValidation(c, context, { evidence, original }, (snapshot, proof) => {
    verifyPrivateLinkOriginalNoSubmission(c, context, snapshot.evidence, snapshot.original, proof);
    return original;
  });
  closed(original, ['phase', 'publication', 'approval', 'preflight', 'journal', 'intent']);
  if (validation) {
    const adoption = privateLinkNsgValidatedRecord(c, context, privateLinkNsgValidationFor(c, context, externalNsg(evidence), validation));
    if (isDeepStrictEqual(original, adoption.proposal.original)) {
      verifyControlEvidence(c, context, evidence, undefined, validation);
      equal(evidence.records, privateLinkNsgValidatedAnchor(c, context, validation).records, 'PRIVATE_LINK_NSG_ANCHOR_CHANGED');
      return original;
    }
  }
  const historical = originalEvidence(evidence, original.phase);
  equal(original.phase, preparePhase(c, context, historical, original.phase.stage, original.phase.policyRevision ?? null,
    original.phase.continuation ?? null, original.phase.version, validation), 'PRIVATE_LINK_ORIGINAL_PHASE_CHANGED');
  closed(original.publication, ['commitSha', 'sourceSha256']);
  if (original.publication.sourceSha256 !== original.phase.sourceSha256 || !/^[0-9a-f]{40}$/u.test(original.publication.commitSha ?? '')) fail('PRIVATE_LINK_ORIGINAL_PUBLICATION_CHANGED');
  verifyProof(c, context, historical, original.phase, original.preflight, canonicalInstant(original.intent.at), validation);
  verifyPrivateLinkApproval(c, context, original.phase, original.preflight, original.approval, canonicalInstant(original.intent.at));
  if (original.intent.phaseSha256 !== hash(original.phase) || original.intent.requestSha256 !== hash(original.phase.request) ||
      original.intent.approvalSha256 !== hash(original.approval) || original.intent.previousHeadSha256 !== hash(original.phase.expectedHead)) fail('PRIVATE_LINK_ORIGINAL_INTENT_CHANGED');
  if (state) state.originals.push(immutableDispatchCopy({ evidence, original,
    evidenceSha256: hash(evidence), originalSha256: hash(original) }));
  return original;
}
function verifyNoSubmissionCurrent(c, context, evidence, original, after, validation = null) {
  const adoption = privateLinkNsgValidationFor(c, context, externalNsg(evidence), validation);
  verifyPrivateLinkSnapshot(c, context, after, originalState(evidence), environmentWireVersion(evidence), adoption, evidence);
  if (adoption && original.phase.externalAdoptionSha256 === undefined) {
    privateLinkNsgOriginalBaseline(c, context, adoption, after, original);
  } else equal(snapshotState(after), snapshotState(original.preflight.before), 'PRIVATE_LINK_NOT_SUBMITTED_STATE_CONFLICT');
}
export async function reconcilePrivateLinkPhase(c, context, evidence, original, io) {
  return reconcileWithValidation(c, context, evidence, original, io, io.now());
}
function recoveryInputs(io, original) {
  return { publication: io.publication, policyRevision: io.policyRevision ?? original.phase.policyRevision ?? null,
    costReview: io.costReview, costEvidence: io.costEvidence, migrationReview: io.migrationReview,
    ...(io.nameProjection ? { nameProjection: io.nameProjection } : {}) };
}
function recoveryGuard(c, context, original, io, validation, startedAt, review = null) {
  const state = dispatchValidation(c, context, validation);
  if (state) {
    assertDispatchInputs(state);
    equal(recoveryInputs(io, original), state.reviews, 'PRIVATE_LINK_RECOVERY_INPUT_CHANGED');
  }
  const source = verifyPrivateLinkPolicyRevision(c, context, io.policyRevision ?? original.phase.policyRevision ?? null, io.now());
  if (io.nameProjection) {
    const prefix = original.preflight.runtimeCompletion?.controlEvidence;
    if (!prefix || !original.preflight.before.nameProjection) fail('PRIVATE_LINK_NAME_RECOVERY_ORIGIN_REQUIRED');
    verifyPrivateLinkNameProjection(c, context, io.nameProjection, io.now(), prefix);
    equal(privateLinkNameBinding(c, context, io.nameProjection, prefix),
      privateLinkNameBinding(c, context, original.preflight.before.nameProjection, prefix), 'PRIVATE_LINK_NAME_RECOVERY_ORIGIN_CHANGED');
    if (source !== io.nameProjection.sourceSha256) fail('PRIVATE_LINK_NAME_POLICY_CHANGED');
  }
  if (review) boundedReview(review, io.now());
  verifyPrivateLinkCostReview(c, context, io.costReview, io.costEvidence, source, io.now());
  verifyPrivateLinkMigrationReview(c, context, io.migrationReview, io.now(), source);
  if (io.cancelled?.() || io.now() >= startedAt + LIMITS.checkMs) fail('PRIVATE_LINK_RECOVERY_EXPIRED');
  return source;
}
async function recheckRecovery(c, context, evidence, original, io, validation, startedAt, pending, review = null) {
  const source = recoveryGuard(c, context, original, io, validation, startedAt, review);
  await io.verifyOriginal(original);
  await io.head(evidence, pending);
  if (await io.sourceDigest() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
  recoveryGuard(c, context, original, io, validation, startedAt, review);
}
function reconcileWithValidation(c, context, evidence, original, io, startedAt, persist = null) {
  return withDispatchValidation(c, context, { evidence, original, reviews: recoveryInputs(io, original) }, async (snapshot, validation) => {
    const proposal = await reconcilePhase(c, context, snapshot.evidence, snapshot.original, io, validation, startedAt);
    if (persist) {
      await persist(proposal);
      await recheckRecovery(c, context, snapshot.evidence, snapshot.original, io, validation, startedAt, proposal.pendingHead);
    }
    return proposal;
  });
}
async function reconcilePhase(c, context, evidence, original, io, validation, startedAt) {
  const guard = () => recoveryGuard(c, context, original, io, validation, startedAt);
  guard();
  verifyPrivateLinkOriginalNoSubmission(c, context, evidence, original, validation);
  const submissionState = privateLinkSubmissionState(original);
  await io.verifyOriginal(original);
  guard();
  if (externalNsg(evidence) && original.phase.externalAdoptionSha256 === undefined && submissionState !== 'known-not-submitted') fail('PRIVATE_LINK_NSG_UNKNOWN_OUTCOME_FORBIDDEN');
  const deadline = startedAt + LIMITS.checkMs, pending = pendingHead(context, evidence, original.intent, original.phase);
  const revision = io.policyRevision ?? original.phase.policyRevision ?? null;
  const source = verifyPrivateLinkPolicyRevision(c, context, revision, io.now());
  await io.verifySources(deadline, validation);
  if (await io.sourceDigest() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
  verifyPrivateLinkCostReview(c, context, io.costReview, io.costEvidence, source, io.now());
  verifyPrivateLinkMigrationReview(c, context, io.migrationReview, io.now(), source);
  await io.head(evidence, pending);
  guard();
  const after = await collectPrivateLinkSnapshot(c, context, io, deadline, null, externalNsg(evidence));
  const deployment = original.phase.deploymentId ? await io.read({ id: original.phase.deploymentId, apiVersion: API.deployment, filter: null }, deadline) : null;
  const operations = original.phase.deploymentId && deployment ? await io.read({ id: `${original.phase.deploymentId}/operations`,
    apiVersion: API.deployment, filter: null }, deadline, true) : null;
  guard();
  if (submissionState === 'known-not-submitted') {
    verifyNoSubmissionCurrent(c, context, evidence, original, after, validation);
    if (deployment !== null || operations !== null) fail('PRIVATE_LINK_NOT_SUBMITTED_DEPLOYMENT_EXISTS');
  } else {
    verifyTransition(c, context, original.phase, original.preflight.before, after, evidence, validation);
    verifyDeploymentOperations(original.phase, deployment, operations);
  }
  const proposal = { version: externalNsg(evidence) ? 4 : 3, kind: submissionState === 'known-not-submitted'
    ? 'private-link-not-submitted-proposal' : 'private-link-late-state-proposal', sourceSha256: source,
    originalSha256: hash(original), pendingHead: pending, after, deployment, operations, policyRevision: revision,
    submissionState, originalExecutionQualified: false, replayAuthorized: false,
    ...(externalNsg(evidence) ? { externalAdoptionSha256: hash(evidence.externalAdoption) } : {}) };
  await io.retain('reconciliation-proposal', proposal);
  await io.head(evidence, pending);
  await io.verifyOriginal(original);
  if (io.now() >= deadline || await io.sourceDigest() !== source) fail('PRIVATE_LINK_RECOVERY_EXPIRED');
  guard();
  return proposal;
}
export async function recoverPrivateLinkPhase(c, context, evidence, original, proposal, review, io) {
  return recoverWithValidation(c, context, evidence, original, proposal, review, io, io.now());
}
function recoverWithValidation(c, context, evidence, original, proposal, review, io, startedAt) {
  return withDispatchValidation(c, context, { evidence, original, proposal, review, reviews: recoveryInputs(io, original) },
    (snapshot, validation) => recoverPhase(c, context, snapshot.evidence, snapshot.original, snapshot.proposal, snapshot.review, io, validation, startedAt));
}
async function recoverPhase(c, context, evidence, original, proposal, review, io, validation, startedAt) {
  recoveryGuard(c, context, original, io, validation, startedAt, review);
  if (proposal.kind === 'private-link-not-submitted-proposal') {
    return resolveNoSubmission(c, context, evidence, original, proposal, review, io, validation, startedAt);
  }
  const pending = pendingHead(context, evidence, original.intent, original.phase);
  await io.head(evidence, pending);
  if (hash(proposal) !== review.proposalSha256 || proposal.originalSha256 !== hash(original)) fail('PRIVATE_LINK_RECONCILIATION_REVIEW_REQUIRED');
  boundedReview(review, io.now());
  const source = verifyPrivateLinkPolicyRevision(c, context, io.policyRevision ?? original.phase.policyRevision ?? null, io.now());
  verifyPrivateLinkCostReview(c, context, io.costReview, io.costEvidence, source, io.now());
  verifyPrivateLinkMigrationReview(c, context, io.migrationReview, io.now(), source);
  const freshProposal = await reconcilePhase(c, context, evidence, original, io, validation, startedAt);
  equal(snapshotState(freshProposal.after), snapshotState(proposal.after), 'PRIVATE_LINK_RECONCILIATION_STATE_CHANGED');
  equal(freshProposal.deployment, proposal.deployment, 'PRIVATE_LINK_RECOVERY_DEPLOYMENT_CHANGED');
  equal(freshProposal.operations, proposal.operations, 'PRIVATE_LINK_RECOVERY_OPERATIONS_CHANGED');
  const record = { version: 3, kind: 'reviewed-private-link-recovery', stage: original.phase.stage,
    phase: original.phase, publication: original.publication, approval: original.approval, preflight: original.preflight,
    intent: original.intent, intentSha256: hash(original.intent), journal: original.journal, after: freshProposal.after,
    deployment: freshProposal.deployment, operations: freshProposal.operations,
    completedAt: stamp(io.now()), authority, recovery: { original, proposal, review,
      costReview: io.costReview, costEvidence: io.costEvidence, migrationReview: io.migrationReview,
      currentPublication: io.publication, policyRevision: io.policyRevision ?? original.phase.policyRevision ?? null } };
  const next = { ...evidence, records: [...evidence.records, record] };
  verifyControlEvidence(c, context, next, io.now(), validation);
  if (await io.sourceDigest() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
  await io.head(evidence, pending);
  boundedReview(review, io.now());
  verifyPrivateLinkCostReview(c, context, io.costReview, io.costEvidence, source, io.now());
  verifyPrivateLinkMigrationReview(c, context, io.migrationReview, io.now(), source);
  const guard = () => recoveryGuard(c, context, original, io, validation, startedAt, review);
  guard();
  await io.append(pending, record, privateLinkHead(context, next), guard);
  guard();
  return record;
}
export async function resolvePrivateLinkNoSubmission(c, context, evidence, original, proposal, review, io) {
  const startedAt = io.now();
  return withDispatchValidation(c, context, { evidence, original, proposal, review, reviews: recoveryInputs(io, original) },
    (snapshot, validation) => resolveNoSubmission(c, context, snapshot.evidence, snapshot.original, snapshot.proposal, snapshot.review, io, validation, startedAt));
}
async function resolveNoSubmission(c, context, evidence, original, proposal, review, io, validation, startedAt) {
  closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'pendingHeadSha256', 'approvedAt', 'expiresAt']);
  boundedReview(review, io.now());
  if (review.version !== 1 || review.action !== 'record-exact-private-link-no-submission-without-replay' ||
      review.proposalSha256 !== hash(proposal) || review.pendingHeadSha256 !== hash(proposal.pendingHead) ||
      proposal.originalSha256 !== hash(original) || proposal.submissionState !== 'known-not-submitted' ||
      review.sourceSha256 !== proposal.sourceSha256 || privateLinkSubmissionState(original) !== 'known-not-submitted') fail('PRIVATE_LINK_NO_SUBMISSION_REVIEW_REQUIRED');
  const freshProposal = await reconcilePhase(c, context, evidence, original, io, validation, startedAt);
  if (freshProposal.kind !== proposal.kind || freshProposal.sourceSha256 !== proposal.sourceSha256) fail('PRIVATE_LINK_NO_SUBMISSION_CHANGED');
  equal(snapshotState(freshProposal.after), snapshotState(proposal.after), 'PRIVATE_LINK_NO_SUBMISSION_CHANGED');
  equal(freshProposal.pendingHead, proposal.pendingHead, 'PRIVATE_LINK_PENDING_HEAD_CHANGED');
  boundedReview(review, io.now());
  const record = { version: externalNsg(evidence) ? 2 : 1, kind: 'reviewed-private-link-no-submission', original, proposal, review,
    observed: freshProposal, publication: io.publication, costReview: io.costReview, costEvidence: io.costEvidence,
    migrationReview: io.migrationReview, policyRevision: io.policyRevision ?? original.phase.policyRevision ?? null,
    completedAt: stamp(io.now()), qualified: false, successfulChainUnchanged: true, replayAuthorized: false,
    physicalFenceRetained: true, originalHistoryModified: false, resolution: 'terminal-abandoned', resumable: false,
    ...(externalNsg(evidence) ? { externalAdoptionSha256: hash(evidence.externalAdoption) } : {}) };
  verifyPrivateLinkNoSubmissionResolution(c, context, evidence, record, validation);
  await recheckRecovery(c, context, evidence, original, io, validation, startedAt, proposal.pendingHead, review);
  const guard = () => recoveryGuard(c, context, original, io, validation, startedAt, review);
  guard();
  await io.resolveNoSubmission(proposal.pendingHead, record, guard);
  await recheckRecovery(c, context, evidence, original, io, validation, startedAt, proposal.pendingHead, review);
  guard();
  return record;
}
export function verifyPrivateLinkNoSubmissionResolution(c, context, evidence, resolution, validation = null) {
  if (externalNsg(evidence) && !validation) return withDispatchValidation(c, context, { evidence, resolution }, (snapshot, proof) => {
    verifyPrivateLinkNoSubmissionResolution(c, context, snapshot.evidence, snapshot.resolution, proof);
    return resolution;
  });
  closed(resolution, ['version', 'kind', 'original', 'proposal', 'review', 'observed', 'publication', 'costReview',
    'costEvidence', 'migrationReview', 'policyRevision', 'completedAt', 'qualified', 'successfulChainUnchanged',
    'replayAuthorized', 'physicalFenceRetained', 'originalHistoryModified', 'resolution', 'resumable',
    ...(resolution.version === 2 ? ['externalAdoptionSha256'] : [])]);
  const { original, proposal, review, observed } = resolution, at = canonicalInstant(resolution.completedAt);
  closed(original, ['phase', 'publication', 'approval', 'preflight', 'journal', 'intent']);
  if (![1, 2].includes(resolution.version) || resolution.kind !== 'reviewed-private-link-no-submission' ||
      resolution.qualified !== false || resolution.successfulChainUnchanged !== true || resolution.replayAuthorized !== false ||
      resolution.physicalFenceRetained !== true || resolution.originalHistoryModified !== false ||
      resolution.resolution !== 'terminal-abandoned' || resolution.resumable !== false ||
      original.journal.version !== 3 || original.journal.outcome !== 'reconciliation-required' ||
      original.phase.request === null || privateLinkSubmissionState(original) !== 'known-not-submitted') fail('PRIVATE_LINK_PROVEN_NO_SUBMISSION_REQUIRED');
  if (resolution.version === 2 && (!externalNsg(evidence) || resolution.externalAdoptionSha256 !== hash(evidence.externalAdoption))) fail('PRIVATE_LINK_NSG_RESOLUTION_BINDING_CHANGED');
  verifyPrivateLinkOriginalNoSubmission(c, context, evidence, original, validation);
  const source = verifyPrivateLinkPolicyRevision(c, context, resolution.policyRevision, at);
  closed(resolution.publication, ['commitSha', 'sourceSha256']);
  if (resolution.publication.sourceSha256 !== source || !/^[0-9a-f]{40}$/u.test(resolution.publication.commitSha ?? '')) fail('PRIVATE_LINK_NO_SUBMISSION_PUBLICATION_CHANGED');
  closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'pendingHeadSha256', 'approvedAt', 'expiresAt']);
  boundedReview(review, at);
  if (review.version !== 1 || review.action !== 'record-exact-private-link-no-submission-without-replay' ||
      review.proposalSha256 !== hash(proposal) || review.sourceSha256 !== source ||
      review.pendingHeadSha256 !== hash(proposal.pendingHead)) fail('PRIVATE_LINK_NO_SUBMISSION_REVIEW_REQUIRED');
  verifyPrivateLinkCostReview(c, context, resolution.costReview, resolution.costEvidence, source, at);
  verifyPrivateLinkMigrationReview(c, context, resolution.migrationReview, at, source);
  for (const p of [proposal, observed]) {
    closed(p, ['version', 'kind', 'sourceSha256', 'originalSha256', 'pendingHead', 'after', 'deployment', 'operations',
      'policyRevision', 'submissionState', 'originalExecutionQualified', 'replayAuthorized',
      ...(p.version === 4 ? ['externalAdoptionSha256'] : [])]);
    if (p.version !== (resolution.version === 2 ? 4 : 3) || p.kind !== 'private-link-not-submitted-proposal' || p.sourceSha256 !== source ||
        p.originalSha256 !== hash(original) || p.submissionState !== 'known-not-submitted' ||
        p.originalExecutionQualified !== false || p.replayAuthorized !== false ||
        p.deployment !== null || p.operations !== null) fail('PRIVATE_LINK_NO_SUBMISSION_EVIDENCE_CHANGED');
    if (resolution.version === 2 && p.externalAdoptionSha256 !== resolution.externalAdoptionSha256) fail('PRIVATE_LINK_NSG_RESOLUTION_BINDING_CHANGED');
    equal(p.pendingHead, pendingHead(context, evidence, original.intent, original.phase), 'PRIVATE_LINK_PENDING_HEAD_CHANGED');
    equal(p.policyRevision, resolution.policyRevision, 'PRIVATE_LINK_POLICY_REVISION_CHANGED');
    fresh(p.after, at);
    if (p.after.nameProjection) {
      verifyPrivateLinkNameProjection(c, context, p.after.nameProjection, at, evidence);
      equal(p.after.nameProjection.publication, resolution.publication, 'PRIVATE_LINK_NAME_POLICY_CHANGED');
    }
    verifyNoSubmissionCurrent(c, context, evidence, original, p.after, validation);
  }
  if (observed.after.startedAt < canonicalInstant(review.approvedAt)) fail('PRIVATE_LINK_NO_SUBMISSION_FRESH_READ_REQUIRED');
  return resolution;
}
export function verifyPrivateLinkContinuation(c, context, evidence, stage, source, continuation, at, validation = null) {
  const state = dispatchValidation(c, context, validation);
  const cached = state?.continuations.find(value => value.stage === stage && value.source === source &&
    isDeepStrictEqual(value.continuation, continuation) && isDeepStrictEqual(value.evidence, evidence) &&
    value.continuationSha256 === hash(continuation) && value.evidenceSha256 === hash(evidence));
  if (cached) {
    boundedReview(continuation.review, at);
    return continuation;
  }
  const ancestors = new Set(), attempts = new Set();
  for (let value = continuation, depth = 0; value; value = value.resolution?.original?.phase?.continuation, depth++) {
    if (depth >= 8 || ancestors.has(value) || attempts.has(value.attemptId)) fail('PRIVATE_LINK_CONTINUATION_HISTORY_LIMIT');
    ancestors.add(value); attempts.add(value.attemptId);
  }
  closed(continuation, ['version', 'kind', 'attemptId', 'resolution', 'review']);
  const { resolution, review, attemptId } = continuation;
  if (continuation.version !== 1 || continuation.kind !== 'reviewed-private-link-no-submission-continuation' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(attemptId ?? '') ||
      attemptId === c.runId) fail('PRIVATE_LINK_NEW_ATTEMPT_ID_REQUIRED');
  verifyPrivateLinkNoSubmissionResolution(c, context, evidence, resolution, validation);
  const fixed = privateLinkPhase(c, context, stage, resolution.original.phase.version);
  if (resolution.original.phase.stage !== stage || fixed.request === null) fail('PRIVATE_LINK_CONTINUATION_STAGE_CHANGED');
  equal(resolution.original.phase.request, fixed.request, 'PRIVATE_LINK_CONTINUATION_REQUEST_CHANGED');
  equal(resolution.original.phase.resources, fixed.resources, 'PRIVATE_LINK_CONTINUATION_RESOURCES_CHANGED');
  closed(review, ['version', 'action', 'configSha256', 'planSha256', 'originSha256', 'stage', 'attemptId',
    'resolutionSha256', 'priorIntentSha256', 'pendingHeadSha256', 'fixedPhaseSha256', 'requestSha256',
    'sourceSha256', 'approvedAt', 'expiresAt']);
  boundedReview(review, at);
  if (review.version !== 1 || review.action !== 'continue-exact-known-not-submitted-private-link-phase' ||
      review.configSha256 !== hash(c) || review.planSha256 !== context.plan.planSha256 ||
      review.originSha256 !== hash(context.origin) || review.stage !== stage || review.attemptId !== attemptId ||
      review.resolutionSha256 !== hash(resolution) || review.priorIntentSha256 !== hash(resolution.original.intent) ||
      review.pendingHeadSha256 !== hash(resolution.proposal.pendingHead) ||
      review.fixedPhaseSha256 !== hash(fixed) || review.requestSha256 !== hash(fixed.request) ||
      review.sourceSha256 !== source || canonicalInstant(review.approvedAt) < canonicalInstant(resolution.completedAt)) fail('PRIVATE_LINK_CONTINUATION_REVIEW_REQUIRED');
  if (state) state.continuations.push(immutableDispatchCopy({ stage, source, continuation, evidence,
    continuationSha256: hash(continuation), evidenceSha256: hash(evidence) }));
  return continuation;
}
export function verifyPrivateLinkRuntimePrerequisites(c, context, evidence, at) {
  const scope = runtimeValidation(c, context, evidence);
  if (scope) {
    if (!scope.prerequisites) {
      scope.statistics.prerequisiteVerifications++;
      scope.prerequisites = immutableDispatchCopy(runtimePrerequisites(c, context, evidence, at, scope.validation));
    } else scope.statistics.prerequisiteReuses++;
    if (at !== undefined && evidence.records.some(record => canonicalInstant(record.completedAt) > at)) fail('PRIVATE_LINK_RECORD_INVALID');
    return scope.prerequisites;
  }
  return withDispatchValidation(c, context, { evidence }, (snapshot, validation) => runtimePrerequisites(c, context, snapshot.evidence, at, validation));
}
function runtimePrerequisites(c, context, evidence, at, validation) {
  const terminal = verifyControlEvidence(c, context, evidence, at, validation);
  if (!terminal || !privateLinkAtLeast(terminal.stage, 'assign-queue-role')) fail('PRIVATE_LINK_RUNTIME_PREREQUISITES_REQUIRED');
  const s = terminal.after, n = context.plan.topology.ids, q = context.origin.adoption.topology.ids;
  const path = verifyPrivateLinkSnapshot(c, context, s, terminal.stage, environmentWireVersion(evidence),
    privateLinkNsgValidationFor(c, context, externalNsg(evidence), validation), evidence);
  return { version: 1, kind: 'private-link-runtime-prerequisites', controlHeadSha256: hash(privateLinkHead(context, evidence)),
    planSha256: context.plan.planSha256, queueTopology: context.origin.adoption.topology,
    queueResources: Object.fromEntries([q.account, q.service, q.queue].map(id => [id, s.resources[id]])),
    queueRole: s.resources[q.role], queueAssignment: s.resources[q.assignment],
    identity: s.resources[n.ingestIdentity], pullIdentity: s.resources[n.pullIdentity],
    environment: s.resources[n.environment], privateEndpoint: s.resources[n.endpoint], dnsZone: s.resources[n.dnsZone],
    dnsLink: s.resources[n.dnsLink], dnsZoneGroup: s.resources[n.dnsZoneGroup], nic: s.nic,
    privateIp: path.privateIp, queueHost: path.queueHost, oldApp: s.resources[n.oldApp], oldEnvironment: s.resources[n.oldEnvironment],
    oldReceiver: context.origin.receiver,
    ...(n.publicProbe ? { publicProbe: context.plan.publicProbe, publicProbeResource: s.resources[n.publicProbe] } : {}),
    workspace: s.resources[ids(c).workspace],
    budgets: Object.fromEntries([ids(c).projectBudget, ids(c).budget, ids(c).stateBudget].map(id => [id, s.resources[id]])) };
}

export function privateLinkReadIO(c, context, directory, invoke = az, options = {}) {
  return withPrivateLinkControlValidation(c, context, () => readIO(c, context, directory, invoke, options));
}
function readIO(c, context, directory, invoke, options) {
  verifyPrivateLinkControlContext(c, context);
  const now = options.now ?? Date.now, allowed = new Set(), policy = new Set(), r = ids(c);
  const nameProjection = options.nameProjection ?? null, projectionEvidence = options.projectionEvidence ?? null;
  if (nameProjection && !projectionEvidence) fail('PRIVATE_LINK_NAME_PREFIX_REQUIRED');
  const n = privateLinkRuntimeResources(c, context, nameProjection, projectionEvidence, now()).ids;
  const key = request => json([request.id.toLowerCase(), request.apiVersion, request.filter ?? null]);
  const allow = request => allowed.add(key(request));
  for (const d of privateLinkResourceDescriptors(c, context, nameProjection, projectionEvidence)) allow({ ...d, filter: null });
  for (const { parent, ...request } of Object.values(privateLinkReadRequests(c, context))) allow(request);
  for (const id of [n.vnet, n.endpoint, n.dnsZone, n.environment, n.app, n.account, context.origin.adoption.topology.ids.service,
    n.oldApp, n.oldEnvironment, context.origin.network.topology.ids.perimeter, r.workspace, r.dcr, ...(n.publicProbe ? [n.publicProbe] : [])]) allow({
    id: `${id}/providers/Microsoft.Insights/diagnosticSettings`, apiVersion: '2021-05-01-preview', filter: null });
  for (const ns of ['Microsoft.Network', 'Microsoft.Storage', 'Microsoft.App']) allow({ id: `${r.sub}/providers/${ns}`, apiVersion: '2021-04-01', filter: null });
  const nsgRequests = privateLinkNsgReadRequests(c, context);
  for (const request of Object.values(nsgRequests)) allow(request);
  for (const stage of STAGES) {
    const phase = privateLinkPhase(c, context, stage);
    if (phase.deploymentId) for (const id of [phase.deploymentId, `${phase.deploymentId}/operations`]) {
      allow({ id, apiVersion: API.deployment, filter: null });
    }
    for (const { scope } of privateLinkPermissions(c, context, phase)) for (const suffix of ['permissions', 'denyAssignments']) {
      allow(permissionRequest(scope, suffix));
    }
  }
  const dispatch = (args, timeout, deadline) => {
    if (!Number.isSafeInteger(deadline) || now() >= deadline) fail('PRIVATE_LINK_READ_DEADLINE');
    return invoke(args, Math.min(LIMITS.commandMs, timeout, deadline - now()));
  };
  const pendingReads = new Set();
  const track = pending => {
    pendingReads.add(pending);
    pending.then(() => pendingReads.delete(pending), () => pendingReads.delete(pending));
    return pending;
  };
  const schedule = limitReadConcurrency(work => work());
  const scheduleRead = work => track(schedule(work));
  const limited = (args, timeout, deadline) => scheduleRead(() => dispatch(args, timeout, deadline)), batch = readBatch;
  const retain = (kind, value) => savePrivateLinkArtifact(directory, `private-link-${kind}-${randomUUID()}.json`, value);
  const io = { now, batch, scheduleRead, invokeRead: limited, sourceDigest: options.sourceDigest ?? sourceDigest, sleep: options.sleep ?? sleep, retain,
    ...(nameProjection ? { nameProjection, projectionEvidence } : {}),
    allowPolicyRead: request => policy.add(key(request)),
    account: deadline => limited(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], LIMITS.commandMs, deadline),
    registry: async deadline => {
      const call = args => limited([...args, '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], LIMITS.commandMs, deadline);
      const repositories = await call(['acr', 'repository', 'list', '--name', c.registryName]);
      const manifests = await call(['acr', 'manifest', 'list-metadata', '--registry', c.registryName, '--name', 'missionspec/telemetry-ingest']);
      if (!Array.isArray(manifests) || manifests.length > 3) fail('PRIVATE_LINK_IMAGE_INVENTORY_CHANGED');
      const old = context.origin.receiver.candidate, queued = context.origin.queueProfile.manifestDigest;
      const targets = [c.receiverDigest, old.profile.manifestDigest, ...(manifests.some(value => value.digest === queued) ? [queued] : [])];
      const results = await batch(targets, async id => {
        const name = `missionspec/telemetry-ingest@${id}`;
        const [manifest, references] = await batch([
          ['acr', 'manifest', 'show', '--registry', c.registryName, '--name', name],
          ['acr', 'manifest', 'list-referrers', '--registry', c.registryName, '--name', name],
        ], call);
        const referrers = Array.isArray(references) ? references : references?.manifests;
        if (!Array.isArray(referrers) || references?.nextLink || referrers.length) fail('PRIVATE_LINK_IMAGE_REFERRER_CHANGED');
        return manifest;
      });
      return { repositories, manifests, legacyManifest: results[0], preparedManifest: results[1], queueManifest: results[2] ?? null, referrers: [] };
    },
    read: async (request, deadline, paginated = false) => {
      closed(request, ['id', 'apiVersion', 'filter']);
      if (typeof request.id !== 'string' || /[%?#\\]|\.\./u.test(request.id)) fail('PRIVATE_LINK_READ_SCOPE_FORBIDDEN');
      const dynamic = request.filter === null && ((request.apiVersion === API.network &&
        new RegExp('^' + `${r.group}/providers/Microsoft.Network/networkInterfaces/`.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&') + '[A-Za-z0-9_.-]+$', 'iu').test(request.id)) ||
        (request.apiVersion === API.storage && sameId(request.id.slice(0, `${n.account}/networkSecurityPerimeterConfigurations/`.length),
          `${n.account}/networkSecurityPerimeterConfigurations/`) && /^[A-Za-z0-9_.-]+$/u.test(request.id.split('/').at(-1))) ||
        ([API.network, '2024-11-01'].includes(request.apiVersion) &&
          new RegExp('^' + `${n.managedGroup}/providers/`.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&') +
            '(?:Microsoft\\.Network/(?:loadBalancers|publicIPAddresses|networkSecurityGroups|networkInterfaces)|Microsoft\\.Compute/virtualMachineScaleSets)/[A-Za-z0-9_.-]+$', 'iu').test(request.id)));
      if (!allowed.has(key(request)) && !policy.has(key(request)) && !dynamic) fail('PRIVATE_LINK_READ_SCOPE_FORBIDDEN');
      const initial = `https://management.azure.com${request.id}?api-version=${request.apiVersion}${request.filter ? '&' + request.filter : ''}`;
      const old = context.origin.network.topology.ids;
      const emptyTerminal = request.apiVersion === '2025-09-01' && request.filter === null &&
        [`${old.perimeter}/profiles`, `${old.perimeter}/resourceAssociations`, `${old.perimeter}/links`,
          `${old.perimeter}/linkReferences`, `${old.profile}/accessRules`].some(id => sameId(id, request.id));
      let url = initial, bytes = 0, failure = null, result;
      const pages = [], seen = new Set(), values = [], valueIds = new Set();
      try {
        for (let page = 0; page < LIMITS.pages; page++) {
          if (seen.has(url)) fail('PRIVATE_LINK_PAGINATION_LOOP'); seen.add(url);
          const response = await limited(['rest', '--method', 'GET', '--url', url, '--subscription', c.subscriptionId,
            '--only-show-errors', '--output', 'json'], LIMITS.commandMs, deadline);
          const size = Buffer.byteLength(json({ url, response }));
          if (bytes + size > LIMITS.bytes) fail('PRIVATE_LINK_READ_LIMIT');
          bytes += size; pages.push({ url, response });
          if (now() >= deadline) fail('PRIVATE_LINK_READ_DEADLINE');
          if (!paginated) {
            if (response?.nextLink || response?.error) fail('PRIVATE_LINK_INCOMPLETE_READ');
            result = response; break;
          }
          if (!response || response.error || !Array.isArray(response.value)) fail('PRIVATE_LINK_LIST_INCOMPLETE');
          for (const value of response.value) {
            const id = value?.id?.toLowerCase();
            if (id && valueIds.has(id)) fail('PRIVATE_LINK_DUPLICATE_INVENTORY');
            if (id) valueIds.add(id); values.push(value);
          }
          if (values.length > LIMITS.items) fail('PRIVATE_LINK_READ_LIMIT');
          if (response.nextLink === undefined || response.nextLink === null || (emptyTerminal && response.nextLink === '')) { result = { value: values }; break; }
          if (typeof response.nextLink !== 'string' || !response.nextLink) fail('PRIVATE_LINK_LIST_INCOMPLETE');
          const next = new URL(response.nextLink), first = new URL(initial);
          if (next.origin !== first.origin || !sameId(next.pathname, first.pathname) || /[%?#\\]|\.\./u.test(next.pathname) ||
              next.username || next.password || next.hash || next.searchParams.get('api-version') !== request.apiVersion ||
              [...next.searchParams].some(([k, v]) => next.searchParams.getAll(k).length !== 1 ||
                (!['$skiptoken', '$skipToken'].includes(k) && first.searchParams.get(k) !== v)) ||
              [...first.searchParams].some(([k, v]) => next.searchParams.get(k) !== v)) fail('PRIVATE_LINK_NEXT_PAGE_SCOPE_CHANGED');
          url = next.href;
        }
        if (result === undefined) fail('PRIVATE_LINK_PAGINATION_LIMIT');
      } catch (error) { failure = safeOperationFailure(error); throw error; }
      finally { await retain('read', { request, pages, complete: failure === null && result !== undefined, failure }); }
      if (sameId(request.id, nsgRequests.watchers.id) && request.apiVersion === API.network && request.filter === null) {
        for (const watcher of privateLinkNsgRegionalWatchers(c, result)) allow({ id: `${watcher.id}/flowLogs`, apiVersion: API.network, filter: null });
      }
      return result;
    } };
  if (context.origin.adoption.version === 3) {
    // Provider-managed Defender reads are generated by its already reviewed module.
    const evidence = context.origin.adoption.proposal.defender;
    const snapshot = evidence.snapshot;
    for (const [name, value] of Object.entries(snapshot)) if (value?.id) {
      const api = name === 'settings' ? '2025-06-01' : name === 'scanner' ? '2023-01-01-preview'
        : ['role', 'assignment'].includes(name) ? API.authorization : '2025-02-15';
      allow({ id: value.id, apiVersion: api, filter: null });
    }
    allow({ id: `${r.group}/providers/Microsoft.EventGrid/systemTopics`, apiVersion: '2025-02-15', filter: null });
    allow({ id: `${snapshot.topic.id}/eventSubscriptions`, apiVersion: '2025-02-15', filter: null });
    for (const id of [snapshot.settings.id, snapshot.topic.id]) allow({ id: `${id}/providers/Microsoft.Insights/diagnosticSettings`, apiVersion: '2021-05-01-preview', filter: null });
  }
  const read = io.read;
  io.read = (...args) => track(read(...args));
  io.settleReads = async () => {
    while (pendingReads.size) await Promise.allSettled([...pendingReads]);
  };
  return io;
}
export async function verifyPrivateLinkNsgSources(c, context, adoption, lookup = publishedSourceDigest, validation = null, evidence = null) {
  adoption = privateLinkNsgValidatedRecord(c, context, privateLinkNsgValidationFor(c, context, adoption, validation), evidence);
  const anchor = validation ? privateLinkNsgValidatedAnchor(c, context, validation) : evidence;
  const publications = [adoption.publication, adoption.proposal.original.publication,
    ...anchor.records.slice(0, 6).flatMap(record => [record.publication, record.recovery?.currentPublication])].filter(Boolean);
  for (const publication of publications) if (await lookup(publication.commitSha) !== publication.sourceSha256) fail('PRIVATE_LINK_NSG_PUBLISHED_SOURCE_CHANGED');
}
export async function runPrivateLinkNsgAdoption(c, context, evidence, operation, directoryArg, inputs, options = {}) {
  const invoke = options.invoke ?? az, now = options.now ?? Date.now, deadline = now() + LIMITS.checkMs;
  if (!['observe-nsg-adoption', 'adopt-nsg'].includes(operation)) fail('PRIVATE_LINK_NSG_READONLY_COMMAND_REQUIRED');
  if (evidence.version !== 1) fail('PRIVATE_LINK_NSG_ORIGINAL_ANCHOR_REQUIRED');
  closed(inputs, ['original', 'originalDirectory', 'publication', 'policyRevision', 'costReview', 'costEvidence', 'migrationReview',
    ...(operation === 'observe-nsg-adoption' ? ['provenance'] : ['proposal', 'review'])]);
  const directory = await privateDirectory(directoryArg), original = inputs.original, phase = original.phase;
  const originalDirectory = await privateDirectory(inputs.originalDirectory);
  if (originalDirectory === directory) fail('PRIVATE_LINK_NSG_NEW_REVISION_DIRECTORY_REQUIRED');
  if (operation === 'adopt-nsg') {
    equal(original, inputs.proposal.original, 'PRIVATE_LINK_NSG_ORIGINAL_PENDING_CHANGED');
    if (evidence.records.length !== 6) fail('PRIVATE_LINK_NSG_ANCHOR_CHANGED');
    for (const key of ['policyRevision', 'costReview', 'costEvidence', 'migrationReview']) {
      equal(inputs[key], inputs.proposal[key], 'PRIVATE_LINK_NSG_REVIEW_INPUT_CHANGED');
    }
  }
  const io = privateLinkAzureIO(c, context, evidence, phase, directory, inputs, invoke, options);
  io.verifyOriginal = value => verifyOriginalArtifacts(context, value, originalDirectory,
    options.store?.root ?? resolve(here, '.operator-private'), options.store?.read ?? loadPrivateLinkArtifact);
  io.adoptionDeadline = deadline;
  io.saveAdoption = async (record, validation) => {
    privateLinkNsgValidatedRecord(c, context, privateLinkNsgValidationFor(c, context, record, validation));
    const root = options.store?.root ?? resolve(here, '.operator-private'), read = options.store?.read ?? loadPrivateLinkArtifact;
    const immutable = options.store?.saveImmutable ?? savePrivateLinkArtifact;
    const guard = async () => {
      if (now() >= canonicalInstant(record.review.expiresAt) ||
          now() >= io.adoptionDeadline || now() - record.verifiedCurrent.startedAt > LIMITS.freshnessMs) fail('PRIVATE_LINK_NSG_ADOPTION_EXPIRED');
      if (verifyPrivateLinkPolicyRevision(c, context, record.proposal.policyRevision, now()) !== record.publication.sourceSha256) fail('PRIVATE_LINK_NSG_SOURCE_CHANGED');
      verifyPrivateLinkCostReview(c, context, record.proposal.costReview, record.proposal.costEvidence, record.publication.sourceSha256, now());
      verifyPrivateLinkMigrationReview(c, context, record.proposal.migrationReview, now(), record.publication.sourceSha256);
      await readPrivateLinkHead(context, evidence, { root, read, pending: record.proposal.pendingHead });
      await io.verifyOriginal(record.proposal.original);
      if (await io.sourceDigest() !== record.publication.sourceSha256) fail('PRIVATE_LINK_NSG_SOURCE_CHANGED');
    };
    await guard();
    await savePrivateLinkArtifact(directory, 'private-link-nsg-adoption.json', record);
    await savePrivateLinkArtifact(directory, 'private-link-nsg-adopted-evidence.json', {
      ...evidence, version: 2, externalAdoption: record,
    });
    await guard();
    await immutable(root, `private-link-nsg-adoption-${privateLinkTargetKey(context)}.json`, record);
  };
  if (operation === 'observe-nsg-adoption') {
    const deadline = io.adoptionDeadline, provenance = structuredClone(inputs.provenance);
    const actor = provenance.actor;
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(actor?.appId ?? '')) fail('PRIVATE_LINK_NSG_ACTOR_PINS_REQUIRED');
    const response = await invoke(['ad', 'sp', 'show', '--id', actor.appId, '--query',
      '{accountEnabled:accountEnabled,appId:appId,appOwnerOrganizationId:appOwnerOrganizationId,displayName:displayName,id:id,servicePrincipalType:servicePrincipalType}',
      '--only-show-errors', '--output', 'json'], Math.min(LIMITS.commandMs, deadline - now()));
    provenance.writer = { appid: actor.appId, response, observedAt: stamp(now()) };
    const proposal = await observePrivateLinkNsgAdoption(c, context, evidence, original, provenance, io);
    await savePrivateLinkArtifact(directory, 'private-link-nsg-adoption-proposal.json', proposal);
    return proposal;
  }
  const lockPath = operationLock(options), lock = await open(lockPath, 'wx', 0o600);
  try { return await adoptPrivateLinkNsg(c, context, evidence, inputs.proposal, inputs.review, inputs.publication, io); }
  finally { await lock.close(); await rm(lockPath); }
}
export function privateLinkAzureIO(c, context, evidence, phase, directory, inputs, invoke = az, options = {}) {
  if (inputs.nameProjection && !privateLinkAtLeast(phase.stage, 'retire-old-receiver')) fail('PRIVATE_LINK_NAME_STAGE_FORBIDDEN');
  const io = privateLinkReadIO(c, context, directory, invoke, { ...options, nameProjection: inputs.nameProjection,
    projectionEvidence: evidence }), root = options.store?.root ?? resolve(here, '.operator-private');
  const readStore = options.store?.read ?? loadPrivateLinkArtifact, saveStore = options.store?.save ?? updatePrivateLinkArtifact;
  const immutableStore = options.store?.saveImmutable ?? savePrivateLinkArtifact;
  const publication = inputs.publication;
  const runtimeInput = inputs.runtimeCompletion;
  const policyRevision = inputs.policyRevision ?? phase.policyRevision ?? null;
  const continuation = inputs.continuation ?? phase.continuation ?? null;
  if (!isDeepStrictEqual(continuation, phase.continuation ?? null)) fail('PRIVATE_LINK_CONTINUATION_CHANGED');
  const file = suffix => `private-link-${phase.stage}-${suffix}.json`;
  const verifySources = async (_deadline, validation = null) => {
    const source = verifyPrivateLinkPolicyRevision(c, context, policyRevision, io.now());
    if (await io.sourceDigest() !== source || publication.sourceSha256 !== source ||
        await (options.lookup ?? publishedSourceDigest)(publication.commitSha) !== publication.sourceSha256) fail('PRIVATE_LINK_PUBLISHED_SOURCE_CHANGED');
    if (policyRevision && !isDeepStrictEqual(policyRevision.publication, publication)) fail('PRIVATE_LINK_POLICY_PUBLICATION_CHANGED');
    if (inputs.nameProjection) {
      verifyPrivateLinkNameProjection(c, context, inputs.nameProjection, io.now(), evidence);
      equal(inputs.nameProjection.publication, publication, 'PRIVATE_LINK_NAME_POLICY_CHANGED');
    }
    if (continuation) verifyPrivateLinkContinuation(c, context, evidence, phase.stage,
      inputs.original ? inputs.original.phase.sourceSha256 : source, continuation,
      inputs.original ? canonicalInstant(inputs.original.intent.at) : io.now(), validation);
    for (const p of [...evidence.records.flatMap(record => [record.publication, record.recovery?.currentPublication]),
      inputs.original?.publication].filter(Boolean)) {
      if (await (options.lookup ?? publishedSourceDigest)(p.commitSha) !== p.sourceSha256) fail('PRIVATE_LINK_HISTORICAL_POLICY_CHANGED');
    }
    for (let previous = continuation, depth = 0; previous; previous = previous.resolution.original.phase.continuation, depth++) {
      if (depth >= 8) fail('PRIVATE_LINK_CONTINUATION_HISTORY_LIMIT');
      for (const p of [previous.resolution.publication, previous.resolution.original.publication]) {
        if (await (options.lookup ?? publishedSourceDigest)(p.commitSha) !== p.sourceSha256) fail('PRIVATE_LINK_CONTINUATION_PUBLICATION_CHANGED');
      }
    }
    await verifyQueueAdoptionSources(c, context.origin.adoption, options.lookup ?? publishedSourceDigest);
    for (const record of context.origin.network.records) {
      for (const p of [record.publication, record.original?.publication].filter(Boolean)) {
        if (await (options.lookup ?? publishedSourceDigest)(p.commitSha) !== p.sourceSha256) fail('PRIVATE_LINK_ORIGINAL_SOURCE_CHANGED');
      }
    }
    if (await (options.lookup ?? publishedSourceDigest)(context.origin.original.publication.commitSha) !==
        context.origin.original.publication.sourceSha256) fail('PRIVATE_LINK_ORIGINAL_SOURCE_CHANGED');
    if (externalNsg(evidence)) await verifyPrivateLinkNsgSources(c, context, evidence.externalAdoption, options.lookup ?? publishedSourceDigest, validation);
  };
  return { ...io, publication, policyRevision, costReview: inputs.costReview, costEvidence: inputs.costEvidence,
    migrationReview: inputs.migrationReview, cancelled: options.cancelled, verifySources,
    head: (value, pending = null) => readPrivateLinkHead(context, value, { root, read: readStore, pending, continuation }),
    nspHead: () => readStore(root, `nsp-head-${nspTargetKey(context.origin.network.topology)}.json`),
    journal: () => load(directory, file('journal'), true),
    saveJournal: value => save(directory, file('journal'), value),
    verifyOriginal: original => verifyOriginalArtifacts(context, original, directory, root, readStore),
    runtimeCompletion: async () => {
      if (!inputs.runtimeCompletion) fail('PRIVATE_LINK_RUNTIME_QUALIFICATION_REQUIRED');
      return inputs.runtimeCompletion;
    },
    checkRuntimeCompletion: () => {
      if (inputs.runtimeCompletion !== runtimeInput) fail('PRIVATE_LINK_RUNTIME_QUALIFICATION_CHANGED');
      assertPrivateLinkCompletionInputs(c, context);
    },
    verifyRuntimeCompletion: (record, at) => {
      return verifyPrivateLinkRuntimeCompletion(c, context, record, at);
    },
    reserve: async (prior, exact, intent, validation) => {
      await readPrivateLinkHead(context, prior, { root, read: readStore, continuation });
      if (continuation) {
        verifyPrivateLinkContinuation(c, context, prior, exact.stage, exact.sourceSha256, continuation, io.now(), validation);
        await immutableStore(root, `private-link-continuation-${hash({ targetKey: privateLinkTargetKey(context),
          attemptId: continuation.attemptId })}.json`, { continuation, phase: exact, intent, previousHead: exact.expectedHead });
        await readPrivateLinkHead(context, prior, { root, read: readStore, continuation });
        boundedReview(continuation.review, io.now());
      }
      await saveStore(root, fenceName(context), { version: 1, targetKey: privateLinkTargetKey(context),
        stage: exact.stage, intentSha256: hash(intent), phase: exact, intent });
      await immutableStore(root, intentName(context, exact.stage, continuation?.attemptId), { phase: exact, intent });
      const head = pendingHead(context, prior, intent, exact); await saveStore(root, headName(context), head);
      if (exact.stage === 'review-migration') {
        const name = `nsp-head-${nspTargetKey(context.origin.network.topology)}.json`;
        equal(await readStore(root, name), context.origin.pendingHead, 'PRIVATE_LINK_ORIGINAL_PENDING_HEAD_CHANGED');
        const supersession = { version: 1, kind: 'reviewed-private-link-supersession', originalPendingHead: context.origin.pendingHead,
          originalAttemptSha256: hash(context.origin.original), migrationReview: inputs.migrationReview, intent, ...authority };
        await immutableStore(root, `private-link-nsp-supersession-${privateLinkTargetKey(context)}.json`, supersession);
        await saveStore(root, name, { kind: 'superseded-by-private-link-retirement', supersessionSha256: hash(supersession), targetKey: privateLinkTargetKey(context) });
      }
      return head;
    },
    append: async (pending, record, next, operationGuard = null) => {
      const guard = () => {
        operationGuard?.();
        const expires = record.recovery ? record.recovery.review.expiresAt : record.approval.expiresAt;
        const proof = record.recovery ?? record.preflight;
        const source = verifyPrivateLinkPolicyRevision(c, context, record.recovery?.policyRevision ?? record.phase.policyRevision ?? null, io.now());
        verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, source, io.now());
        verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, io.now(), source);
        if (record.phase.continuation && !record.recovery) boundedReview(record.phase.continuation.review, io.now());
        if (options.cancelled?.() || io.now() >= canonicalInstant(expires) || (!record.recovery &&
            io.now() >= record.journal.rolloutDeadline)) fail('PRIVATE_LINK_APPEND_EXPIRED');
      };
      const current = async () => {
        guard();
        await readPrivateLinkHead(context, evidence, { root, read: readStore, pending, continuation });
        if (await io.sourceDigest() !== publication.sourceSha256) fail('PRIVATE_LINK_SOURCE_CHANGED');
        guard();
      };
      await current();
      await immutableStore(directory, file(record.recovery ? 'recovered-record' : 'record'), record);
      guard();
      await immutableStore(directory, file(record.recovery ? 'recovered-evidence' : 'evidence'),
        { ...evidence, records: [...evidence.records, record] });
      await current();
      await immutableStore(root, `private-link-resolution-${hash(pending)}.json`, { pending, record, next });
      await current();
      await saveStore(root, headName(context), next);
    },
    resolveNoSubmission: async (pending, record, operationGuard = null) => {
      const guard = async () => {
        operationGuard?.();
        boundedReview(record.review, io.now());
        const source = verifyPrivateLinkPolicyRevision(c, context, record.policyRevision, io.now());
        verifyPrivateLinkCostReview(c, context, record.costReview, record.costEvidence, source, io.now());
        verifyPrivateLinkMigrationReview(c, context, record.migrationReview, io.now(), source);
        if (await io.sourceDigest() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
        await readPrivateLinkHead(context, evidence, { root, read: readStore, pending, continuation });
        boundedReview(record.review, io.now());
        operationGuard?.();
      };
      if (record.resolution !== 'terminal-abandoned' || record.resumable !== false ||
          record.qualified !== false || record.replayAuthorized !== false ||
          privateLinkSubmissionState(record.original) !== 'known-not-submitted') fail('PRIVATE_LINK_NO_SUBMISSION_REVIEW_REQUIRED');
      await guard();
      await savePrivateLinkArtifact(directory, file('not-submitted-resolution'), record);
      await immutableStore(root, `private-link-no-submission-${hash(record.original.intent)}.json`, { pending, record });
      await guard();
    },
    preview: async (exact, deadline) => {
      if (options.preview) return options.preview(c, exact, directory, deadline);
      const path = resolve(directory, `private-link-template-${randomUUID()}.json`);
      await save(directory, path.split('/').at(-1), exact.template);
      try {
        const level = exact.scope === ids(c).sub ? 'sub' : 'group';
        const validation = await io.invokeRead(['deployment', level, 'validate', '--subscription', c.subscriptionId,
          ...(level === 'sub' ? ['--location', c.location] : ['--resource-group', `${c.namePrefix}-telemetry`]),
          '--name', exact.deploymentId.split('/').at(-1), '--template-file', path, '--only-show-errors', '--output', 'json'],
        Math.min(LIMITS.commandMs, deadline - io.now()), deadline);
        const base = privateLinkPhase(c, context, exact.stage, exact.version), requestContext = whatIfRequestContext(c, base);
        const request = options.request ?? (operation => authenticatedWhatIfRequest(requestContext, directory, operation));
        const whatif = await asyncWhatIf(c, base, directory, { ...options, deadline,
          request: operation => io.scheduleRead(() => {
            if (io.now() >= operation.deadlineMs) fail('PRIVATE_LINK_READ_DEADLINE');
            return request({ ...operation, timeoutMs: Math.min(operation.timeoutMs, operation.deadlineMs - io.now()) });
          }) });
        return { validation, preview: whatif.result };
      } finally { await rm(path); }
    },
    write: async (exact, guard, current, mark, deadline, validation) => {
      const state = dispatchValidation(c, context, validation);
      const check = () => {
        if (state?.validated) {
          assertDispatchInputs(state);
          equal(evidence, state.evidence, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
          equal(exact, state.phase, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
          equal(inputs.proof, state.proof, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
          equal(inputs.approval, state.approval, 'PRIVATE_LINK_DISPATCH_VALIDATION_CHANGED');
          currentDispatchReviews(c, context, evidence, exact, inputs.proof, inputs.approval, io.now());
        } else {
          verifyProof(c, context, evidence, exact, inputs.proof, io.now(), validation);
          verifyPrivateLinkApproval(c, context, exact, inputs.proof, inputs.approval, io.now());
        }
      };
      if (!state?.validated) equal(exact, preparePhase(c, context, evidence, exact.stage, exact.policyRevision ?? null,
        exact.continuation ?? null, exact.stage === 'create-environment' ? 2 : 1, validation), 'PRIVATE_LINK_FIXED_WRITE_REQUIRED');
      if (!exact.request || typeof guard !== 'function' || types.isAsyncFunction(guard) ||
          typeof mark !== 'function') fail('PRIVATE_LINK_FIXED_WRITE_REQUIRED');
      const { method, id, apiVersion, body } = exact.request;
      check();
      const bodyName = body === null ? null : `private-link-request-${randomUUID()}.json`;
      if (bodyName) await saveImmutable(directory, bodyName, body);
      try {
        await current();
        const args = ['rest', '--method', method, '--url', `https://management.azure.com${id}?api-version=${apiVersion}`,
          '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json',
          ...(bodyName ? ['--body', '@' + resolve(directory, bodyName), '--headers', 'Content-Type=application/json'] : [])];
        guard();
        verifyPrivateLinkApproval(c, context, exact, inputs.proof, inputs.approval, io.now());
        if (io.now() >= deadline) fail('PRIVATE_LINK_FINAL_CHECK_EXPIRED');
        const marker = await mark();
        closed(marker, ['rolloutDeadline', 'beforeInvoke']);
        if (!Number.isSafeInteger(marker.rolloutDeadline) || marker.rolloutDeadline <= io.now() ||
            marker.rolloutDeadline > io.now() + exact.rolloutMs ||
            typeof marker.beforeInvoke !== 'function' || types.isAsyncFunction(marker.beforeInvoke)) fail('PRIVATE_LINK_DISPATCH_GUARD_REQUIRED');
        guard();
        check();
        guard();
        const timeout = Math.min(LIMITS.commandMs, marker.rolloutDeadline - io.now());
        if (timeout <= 0) fail('PRIVATE_LINK_OPERATION_EXPIRED');
        if (marker.beforeInvoke() !== undefined) fail('PRIVATE_LINK_DISPATCH_GUARD_REQUIRED');
        const result = await invoke(args, timeout);
        await io.retain('dispatch-response', { method, id, apiVersion, response: result });
        if (result?.error || result?.properties?.error) fail('PRIVATE_LINK_WRITE_RESPONSE_ERROR');
      } finally { if (bodyName) await rm(resolve(directory, bodyName)); }
    },
  };
}
export async function currentPrivateLinkRuntimeProof(c, context, evidence, directory, invoke = az, options = {}) {
  if (Object.hasOwn(options, 'runtimeValidation') || Object.hasOwn(options, 'validationScope')) fail('PRIVATE_LINK_RUNTIME_VALIDATION_FORGED');
  const at = (options.now ?? Date.now)(), deadline = Math.min(options.deadline ?? at + LIMITS.checkMs, at + LIMITS.checkMs);
  const scope = runtimeValidation(c, context, evidence);
  if (scope) return currentRuntimeProof(c, context, evidence, directory, invoke, options, at, deadline, scope.validation, scope);
  return withDispatchValidation(c, context, { evidence }, (snapshot, validation) =>
    currentRuntimeProof(c, context, snapshot.evidence, directory, invoke, options, at, deadline, validation));
}
async function currentRuntimeProof(c, context, evidence, directory, invoke, options, at, deadline, validation, scope = null) {
  const prerequisites = scope ? verifyPrivateLinkRuntimePrerequisites(c, context, evidence, at) :
    runtimePrerequisites(c, context, evidence, at, validation);
  const originalNameProjection = options.nameProjection ?? null;
  const nameProjection = originalNameProjection ? immutableDispatchCopy(originalNameProjection) : null;
  const nameReviewSha256 = hash(nameProjection);
  const view = privateLinkRuntimeResources(c, context, nameProjection, evidence, at);
  const io = privateLinkReadIO(c, context, directory, invoke, { ...options, nameProjection, projectionEvidence: evidence }), source = await io.sourceDigest();
  if (nameProjection && (nameProjection.sourceSha256 !== source ||
      await (options.lookup ?? publishedSourceDigest)(nameProjection.publication.commitSha) !== source)) fail('PRIVATE_LINK_NAME_POLICY_CHANGED');
  const terminal = evidence.records.at(-1);
  const revision = options.policyRevision ?? terminal.recovery?.policyRevision ?? terminal.phase.policyRevision ?? null;
  if (source !== verifyPrivateLinkPolicyRevision(c, context, revision, io.now())) fail('PRIVATE_LINK_SOURCE_CHANGED');
  if (revision && await (options.lookup ?? publishedSourceDigest)(revision.publication.commitSha) !== source) fail('PRIVATE_LINK_POLICY_PUBLICATION_CHANGED');
  const adoption = externalNsg(evidence);
  if (adoption) await verifyPrivateLinkNsgSources(c, context, adoption, options.lookup ?? publishedSourceDigest, validation);
  const checkedAdoption = privateLinkNsgValidationFor(c, context, adoption, validation);
  const guard = () => {
    const state = dispatchValidation(c, context, validation);
    if (state) assertDispatchInputs(state);
    if (hash(options.nameProjection ?? null) !== nameReviewSha256) fail('PRIVATE_LINK_NAME_REVIEW_CHANGED');
    if (options.cancelled?.() || io.now() >= deadline) fail('PRIVATE_LINK_RUNTIME_PROOF_EXPIRED');
    if (nameProjection) verifyPrivateLinkNameProjection(c, context, nameProjection, io.now(), evidence);
  };
  guard();
  const collection = snapshotWithTargets(c, context, io, deadline, adoption);
  const policyTask = (async () => {
    const targets = await collection.targets, { resources } = targets;
    const policyResources = privateLinkResourceDescriptors(c, context, nameProjection, evidence).filter(d => {
      const resource = resources[d.id];
      return resource && ![view.ids.app, view.ids.oldApp,
        view.ids.oldEnvironment, view.ids.managedGroup, view.ids.publicProbe,
        view.ids.ingestIdentity, view.ids.pullIdentity].includes(d.id) &&
        !resource.type?.startsWith('Microsoft.Consumption/') && !resource.type?.startsWith('Microsoft.ManagedIdentity/');
    }).map(d => {
      const resource = resources[d.id];
      let type = resource.type;
      if (sameId(d.id, ids(c).table)) {
        const tableType = 'Microsoft.OperationalInsights/workspaces/tables';
        if (!sameId(resource.id, d.id) || Object.hasOwn(resource, 'type') && !sameId(type, tableType)) {
          fail('PRIVATE_LINK_RUNTIME_POLICY_TYPE_CHANGED');
        }
        type = tableType;
      }
      return { ...d, type, expected: resource };
    });
    if (adoption) {
      for (const value of Object.values(privateLinkNsgMembers(targets.externalNsg))) policyResources.push({ id: value.id,
        type: 'Microsoft.Network/networkSecurityGroups', apiVersion: API.network, expected: value });
    }
    if (context.plan.publicProbe) policyResources.push(structuredClone(view.resources.publicProbe));
    if (nameProjection) policyResources.push(structuredClone(view.resources.app));
    const policyPhase = { version: 1, kind: 'private-link-runtime-effective-policy', planSha256: context.plan.planSha256, resources: policyResources };
    const policy = await collectEffectivePoliciesV3(policyPhase, async (id, apiVersion, filter) => {
      const request = { id, apiVersion, filter: filter ?? null }; io.allowPolicyRead(request);
      return io.read(request, deadline, /\/(?:policyAssignments|policyExemptions|versions)$/u.test(id));
    }, io.batch, snapshot => io.retain('runtime-effective-policy', snapshot));
    verifyEffectivePolicyEvidenceV3(policyPhase, policy);
    return policy;
  })();
  const tasks = [readPrivateLinkHead(context, evidence, options.store ?? {}), collection.snapshot, policyTask];
  let values;
  try { values = await Promise.all(tasks); }
  catch (error) {
    await Promise.allSettled(tasks);
    await io.settleReads();
    throw error;
  }
  const [head, snapshot, policy] = values;
  guard();
  const currentPath = verifyPrivateLinkSnapshot(c, context, snapshot, originalState(evidence), environmentWireVersion(evidence), checkedAdoption, evidence);
  verifyCostScope(c, context, evidence, snapshot, io.now());
  for (const [id, previous] of Object.entries(terminal.after.resources)) {
    if (!previous || sameId(id, context.plan.topology.ids.app)) continue;
    const current = snapshot.resources[id];
    if (!current) fail('PRIVATE_LINK_CURRENT_RESOURCE_MISSING');
    equal(privateLinkGeneration(current), privateLinkGeneration(previous), 'PRIVATE_LINK_CURRENT_GENERATION_CHANGED');
  }
  if (currentPath.privateIp !== prerequisites.privateIp || currentPath.queueHost !== prerequisites.queueHost) fail('PRIVATE_LINK_PRIVATE_TARGET_CHANGED');
  const currentReview = terminal.recovery ?? terminal.preflight;
  verifyPrivateLinkCostReview(c, context, options.costReview ?? currentReview.costReview,
    options.costEvidence ?? currentReview.costEvidence, source, io.now());
  await readPrivateLinkHead(context, evidence, options.store ?? {});
  if (await io.sourceDigest() !== source || io.now() >= deadline) fail('PRIVATE_LINK_RUNTIME_PROOF_EXPIRED');
  guard();
  verifyPrivateLinkPolicyRevision(c, context, revision, io.now());
  verifyPrivateLinkCostReview(c, context, options.costReview ?? currentReview.costReview,
    options.costEvidence ?? currentReview.costEvidence, source, io.now());
  const result = { version: 1, kind: 'current-private-link-runtime-proof', sourceSha256: source, checkedAt: stamp(io.now()),
    head, headSha256: hash(head), planSha256: context.plan.planSha256, snapshot,
    effectivePolicy: policy, preservedResourceIds: privateLinkPreservedIds(c, context, snapshot, checkedAdoption),
    billingReview: options.costReview ?? currentReview.costReview, costEvidence: options.costEvidence ?? currentReview.costEvidence,
    policyRevision: revision,
    ...(nameProjection ? { nameProjection: structuredClone(nameProjection), nameBinding: privateLinkNameBinding(c, context, nameProjection, evidence) } : {}),
    prerequisites: { ...prerequisites, environment: snapshot.resources[context.plan.topology.ids.environment] } };
  guard();
  return result;
}
export async function runPrivateLinkControl(c, context, evidence, stage, operation, directoryArg, inputs = {}, options = {}) {
  const startedAt = (options.now ?? Date.now)();
  return withPrivateLinkCompletionValidation(c, context, () =>
    runControl(c, context, evidence, stage, operation, directoryArg, inputs, options, startedAt));
}
async function runControl(c, context, evidence, stage, operation, directoryArg, inputs, options, startedAt) {
  if (Object.hasOwn(inputs, 'nameProjection')) {
    if (!privateLinkAtLeast(stage, 'retire-old-receiver')) fail('PRIVATE_LINK_NAME_STAGE_FORBIDDEN');
    verifyPrivateLinkNameProjection(c, context, inputs.nameProjection, startedAt, evidence);
  }
  if (['reconcile', 'recover'].includes(operation) && Object.hasOwn(inputs, 'continuation')) fail('PRIVATE_LINK_CONTINUATION_FROM_ORIGINAL_ONLY');
  const directory = await privateDirectory(directoryArg);
  const deferred = ['check', 'execute', 'retire'].includes(operation) && externalNsg(evidence);
  // Each operation validates its candidate once before any read/reservation.
  const phase = ['reconcile', 'recover'].includes(operation) ? inputs.original.phase :
    deferred ? phaseCandidate(c, context, evidence, stage, inputs.policyRevision ?? null, inputs.continuation) :
      preparePrivateLinkPhase(c, context, evidence, stage, inputs.policyRevision ?? null, inputs.continuation ?? null);
  if (phase.stage !== stage) fail('PRIVATE_LINK_STAGE_CHANGED');
  if (operation === 'prepare') {
    await savePrivateLinkArtifact(directory, `private-link-${stage}-plan.json`, phase);
    return phase;
  }
  const io = privateLinkAzureIO(c, context, evidence, phase, directory, inputs, options.invoke ?? az, options);
  if (['reconcile', 'recover'].includes(operation) && externalNsg(evidence)) {
    const originalDirectory = await privateDirectory(inputs.originalDirectory);
    if (originalDirectory === directory) fail('PRIVATE_LINK_NSG_NEW_REVISION_DIRECTORY_REQUIRED');
    io.verifyOriginal = original => verifyOriginalArtifacts(context, original, originalDirectory,
      options.store?.root ?? resolve(here, '.operator-private'), options.store?.read ?? loadPrivateLinkArtifact);
  }
  if (operation === 'check') {
    const proof = await checkWithValidation(c, context, evidence, phase, io, startedAt);
    await savePrivateLinkArtifact(directory, `private-link-${stage}-preflight.json`, proof);
    io.checkRuntimeCompletion();
    const at = io.now();
    if (io.cancelled?.() || at >= startedAt + LIMITS.checkMs) fail('PRIVATE_LINK_CHECK_EXPIRED');
    phaseSource(c, context, phase, at);
    if (phase.continuation) boundedReview(phase.continuation.review, at);
    verifyPrivateLinkCostReview(c, context, proof.costReview, proof.costEvidence, proof.sourceSha256, at);
    verifyPrivateLinkMigrationReview(c, context, proof.migrationReview, at, proof.sourceSha256);
    if (io.cancelled?.() || io.now() >= startedAt + LIMITS.checkMs) fail('PRIVATE_LINK_CHECK_EXPIRED');
    return proof;
  }
  if (operation === 'reconcile') {
    return reconcileWithValidation(c, context, evidence, inputs.original, io, startedAt, proposal =>
      savePrivateLinkArtifact(directory, `private-link-${stage}-reconciliation-proposal.json`, proposal));
  }
  if (!['execute', 'recover', 'retire'].includes(operation)) fail('PRIVATE_LINK_FIXED_COMMAND_REQUIRED');
  if (operation === 'retire' && !stage.startsWith('retire-')) fail('PRIVATE_LINK_RETIREMENT_STAGE_REQUIRED');
  const lockPath = operationLock(options), lock = await open(lockPath, 'wx', 0o600);
  try {
    const record = operation === 'recover' ? await recoverWithValidation(c, context, evidence, inputs.original,
      inputs.proposal, inputs.recoveryReview, io, startedAt) : await executePrivateLinkPhase(c, context, evidence, phase, inputs.proof, inputs.approval, io);
    return record;
  } finally { await lock.close(); await rm(lockPath); }
}
