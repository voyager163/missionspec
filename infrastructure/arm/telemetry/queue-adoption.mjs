import { isDeepStrictEqual } from 'node:util';
import { assertOwned, closed, digest, fail, ids, json, sameId, validateConfig } from './definition.mjs';
import { canonicalInstant, verifyApproval, verifyDeploymentIdentity, verifyFreshReview } from './policy.mjs';
import { buildQueuePhase, durableQueueCost, queuePostCreateRequirements,
  verifyQueuePreflight, verifyQueuePrivacy, verifyQueueProviderOperations, verifyQueueResource,
  verifyQueueReview, verifyQueueTopology, verifyQueueWhatIf } from './durable-queue.mjs';
import { collectQueueDefender, queueDefenderRule, verifyCurrentQueueDefender,
  verifyQueueDefenderEvidence, verifyQueueDefenderReview } from './queue-defender.mjs';

export const QUEUE_ADOPTION_AUTHORITY = Object.freeze({
  deployment: false, publication: false, ingestion: false, clientActivation: false, productionClearance: false,
  delete: false, retag: false, repush: false, registryAdmin: false, securityChanges: false,
});
export const QUEUE_ADOPTION_LIMITS = Object.freeze({
  bytes: 8 * 1024 * 1024, stringBytes: 2 * 1024 * 1024, depth: 32,
  nodes: 100000, items: 4096, collectionMs: 120000, freshnessMs: 300000,
});
export const QUEUE_ADOPTION_ASSURANCE = Object.freeze({
  kind: 'reviewed-intended-submission-and-observed-creation',
  originalRequestBody: 'not-retained', originalPutResponse: 'digest-only',
  fullWireAttestation: false, accountGeneration: 'retained-creation-time',
  childGeneration: 'historical-create-and-current-identity-only',
  uninterruptedChildGenerationProven: false,
  systemDataCreationIdentity: 'only-originally-observed-creation-fields-pinned',
  missingOriginalSystemDataCreationIdentityProven: false,
  rbacEvidence: 'arm-role-assignment-inventories-only',
  roleDefinitionsEvaluated: false, transitiveGroupMembershipEvaluated: false,
  allEffectiveDataAccessExcluded: false,
});
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const guid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(value);
const historicalArtifacts = Object.freeze([
  'config', 'topology', 'plan', 'template', 'review', 'approval', 'preflight', 'validation',
  'whatIf', 'publication', 'providerOperations', 'journal', 'authorization', 'lineage',
  'priorJournal', 'priorApproval', 'priorReview', 'priorPreflight', 'priorPublication',
  'absence', 'dispatch', 'stop',
]);
const excludedEffects = Object.freeze([
  'queue-role', 'queue-assignment', 'image-publication', 'receiver-change', 'ingestion', 'release', 'merge',
]);
const copiedFiles = Object.freeze([
  'config.json', 'origin.json', 'scanner-adoption.json', 'foundation-budgets.json', 'receipts.json',
  'execution-origins-v3.json', 'receiver-candidate.json', 'receiver-upgrade.json', 'window-predecessor.json',
  'queue-topology.json', 'queue-records.json', 'reconciliation-proposal.json', 'reconciliation-review.json',
  'reconciliation-receipts.json', 'queue-storage-plan.json', 'queue-storage-template.json',
  'queue-policy-publication.json', 'reviewed-validation-summary.json', 'reviewed-queue-storage-what-if.json',
]);
const authorizationFiles = Object.freeze(copiedFiles.filter(name => ![
  'reconciliation-review.json', 'reconciliation-receipts.json', 'queue-policy-publication.json',
  'reviewed-validation-summary.json', 'reviewed-queue-storage-what-if.json',
].includes(name)));

function bounded(value) {
  let nodes = 0, bytes = 0;
  const ancestors = new Set();
  const visit = (entry, depth) => {
    if (++nodes > QUEUE_ADOPTION_LIMITS.nodes || depth > QUEUE_ADOPTION_LIMITS.depth) fail('QUEUE_ADOPTION_INPUT_LIMIT');
    if (typeof entry === 'string') {
      const size = Buffer.byteLength(entry);
      if (size > QUEUE_ADOPTION_LIMITS.stringBytes) fail('QUEUE_ADOPTION_INPUT_LIMIT');
      bytes += size;
    } else if (typeof entry === 'number') {
      if (!Number.isFinite(entry)) fail('QUEUE_ADOPTION_JSON_REQUIRED');
    } else if (entry !== null && typeof entry !== 'boolean') {
      if (typeof entry !== 'object' || ancestors.has(entry) ||
          ![Object.prototype, Array.prototype, null].includes(Object.getPrototypeOf(entry))) fail('QUEUE_ADOPTION_JSON_REQUIRED');
      const entries = Object.entries(entry);
      if (entries.length > QUEUE_ADOPTION_LIMITS.items ||
          (Array.isArray(entry) && entries.length !== entry.length)) fail('QUEUE_ADOPTION_INPUT_LIMIT');
      ancestors.add(entry);
      for (const [key, child] of entries) { bytes += Buffer.byteLength(key); visit(child, depth + 1); }
      ancestors.delete(entry);
    }
    if (bytes > QUEUE_ADOPTION_LIMITS.bytes) fail('QUEUE_ADOPTION_INPUT_LIMIT');
  };
  visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(value)) > QUEUE_ADOPTION_LIMITS.bytes) fail('QUEUE_ADOPTION_INPUT_LIMIT');
}
export { bounded as boundedQueueAdoptionInput };
function only(value, fields, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !fields.includes(key))) fail(code);
}
function parseArtifact(artifact) {
  closed(artifact, ['json', 'sha256']);
  if (typeof artifact.json !== 'string' || !sha(artifact.sha256) ||
      digest(artifact.json) !== artifact.sha256) fail('QUEUE_ADOPTION_ARTIFACT_CHANGED');
  let value;
  try { value = JSON.parse(artifact.json); }
  catch { fail('QUEUE_ADOPTION_ARTIFACT_JSON_INVALID'); }
  bounded(value);
  return value;
}
function publication(value) {
  closed(value, ['commitSha', 'sourceSha256']);
  if (!/^[0-9a-f]{40}$/u.test(value.commitSha ?? '') || !sha(value.sourceSha256)) fail('QUEUE_ADOPTION_PUBLICATION_REQUIRED');
}
function milliseconds(value) {
  if (!Number.isSafeInteger(value) || value < 0 || !Number.isFinite(new Date(value).getTime())) fail('QUEUE_ADOPTION_TIME_INVALID');
  return value;
}

// ARM retains 100ns fractions; Date.parse alone silently discards part of this identity.
export function queueArmInstant(value) {
  const match = typeof value === 'string' && /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z$/u.exec(value);
  if (!match) fail('QUEUE_ADOPTION_ARM_TIME_INVALID');
  const seconds = Date.parse(`${match[1]}.000Z`);
  if (!Number.isSafeInteger(seconds) || seconds < 0 ||
      new Date(seconds).toISOString().slice(0, 19) !== match[1]) fail('QUEUE_ADOPTION_ARM_TIME_INVALID');
  return BigInt(seconds) * 10000n + BigInt((match[2] ?? '').padEnd(7, '0'));
}
function between(value, start, end, code) {
  const instant = queueArmInstant(value);
  if (instant < queueArmInstant(start) || instant > queueArmInstant(end)) fail(code);
}
function emptyList(value, code) {
  closed(value, ['value', ...(Object.hasOwn(value ?? {}, 'nextLink') ? ['nextLink'] : [])]);
  if (!Array.isArray(value.value) || value.value.length || (value.nextLink !== undefined && value.nextLink !== null)) fail(code);
}
function completeList(value, maximum, code) {
  closed(value, ['value', ...(Object.hasOwn(value ?? {}, 'nextLink') ? ['nextLink'] : [])]);
  if (!Array.isArray(value.value) || value.value.length > maximum ||
      (value.nextLink !== undefined && value.nextLink !== null)) fail(code);
  return value.value;
}
function verifyIdentity(c, identity) {
  assertOwned(identity, ids(c).ingestIdentity, c);
  if (identity.properties?.tenantId !== c.tenantId ||
      !guid(identity.properties.principalId) || !guid(identity.properties.clientId)) fail('QUEUE_ADOPTION_IDENTITY_CHANGED');
}
function identityPin(value) {
  return { id: value.id.toLowerCase(), tags: value.tags,
    tenantId: value.properties.tenantId, principalId: value.properties.principalId,
    clientId: value.properties.clientId, createdAt: value.systemData?.createdAt ?? null };
}
function verifyJournal(value, phase, approvalArtifact, dispatched) {
  closed(value, ['phase', 'phaseSha256', 'approvalSha256', 'intentAt', 'outcome', 'transportDispatchAttempted', 'failureCode']);
  canonicalInstant(value.intentAt);
  if (value.phase !== 'queue-storage' || value.phaseSha256 !== digest(json(phase)) ||
      value.approvalSha256 !== approvalArtifact.sha256 || value.outcome !== 'reconciliation-required' ||
      value.transportDispatchAttempted !== dispatched ||
      !(dispatched ? ['QUEUE_RESOURCE_DRIFT', 'QUEUE_NETWORK_POLICY_MISMATCH'] : ['ARM_OPERATION_FAILED']).includes(value.failureCode)) {
    fail('QUEUE_ADOPTION_STOPPED_JOURNAL_REQUIRED');
  }
}
function verifyHistoricalAttempt(c, origin, values, prior) {
  const key = name => prior ? `prior${name[0].toUpperCase()}${name.slice(1)}` : name;
  const journal = values[key('journal')], approval = values[key('approval')], review = values[key('review')];
  const source = values[key('publication')], proof = values[key('preflight')];
  publication(source);
  verifyJournal(journal, origin.phase, origin.artifacts[key('approval')], !prior);
  const at = canonicalInstant(journal.intentAt);
  verifyQueueReview(c, origin.topology, review, source.sourceSha256, at);
  verifyApproval(approval, c, origin.phase, source.sourceSha256, at);
  verifyFreshReview(proof, approval, proof.startedAt, at);
  verifyQueuePreflight(c, origin.phase, origin.topology, proof);
  if (approval.originSha256 !== c.originSha256 || approval.receiptsSha256 !== digest(json({})) ||
      proof.topologyReviewSha256 !== origin.artifacts[key('review')].sha256 ||
      !isDeepStrictEqual(proof.cost, durableQueueCost())) fail('QUEUE_ADOPTION_HISTORICAL_BINDING_CHANGED');
}
function verifyLineage(c, origin, values) {
  const { absence, lineage, authorization, dispatch, stop, journal, priorJournal } = values;
  closed(absence, ['originalJournalSha256', 'deploymentAbsent', 'queueResourcesAbsent', 'receiverDisabled',
    'exactFinalGuardReproduced', 'currentFinalGuardPassed', 'originalFailureDetailsUnavailable',
    'originalHistoryModified', 'writes', 'calls', 'completedAt', 'retryAuthorized']);
  if (absence.originalJournalSha256 !== origin.artifacts.priorJournal.sha256 ||
      absence.deploymentAbsent !== true || absence.queueResourcesAbsent !== true || absence.receiverDisabled !== true ||
      absence.exactFinalGuardReproduced !== false || absence.currentFinalGuardPassed !== true ||
      absence.originalFailureDetailsUnavailable !== true || absence.originalHistoryModified !== false ||
      absence.writes !== 0 || !Number.isSafeInteger(absence.calls) || absence.calls < 1 ||
      absence.retryAuthorized !== false) fail('QUEUE_ADOPTION_PRIOR_ABSENCE_REQUIRED');
  closed(lineage, ['version', 'recordedAt', 'expiresAt', 'originalDirectory', 'copies', 'originalJournalSha256',
    'readonlyResultSha256', 'originalHistoryModified', 'permittedNewAttempts', 'exactPhaseSha256', 'excludedEffects']);
  closed(lineage.copies, copiedFiles);
  if (lineage.version !== 1 || lineage.originalJournalSha256 !== origin.artifacts.priorJournal.sha256 ||
      lineage.readonlyResultSha256 !== origin.artifacts.absence.sha256 || lineage.originalHistoryModified !== false ||
      lineage.permittedNewAttempts !== 1 || lineage.exactPhaseSha256 !== digest(json(origin.phase)) ||
      typeof lineage.originalDirectory !== 'string' || !lineage.originalDirectory ||
      !Object.values(lineage.copies).every(sha) || !isDeepStrictEqual(lineage.excludedEffects, excludedEffects)) fail('QUEUE_ADOPTION_RETRY_LINEAGE_CHANGED');
  for (const [name, key] of Object.entries({
    'config.json': 'config', 'queue-topology.json': 'topology', 'queue-storage-plan.json': 'plan',
    'queue-storage-template.json': 'template', 'queue-policy-publication.json': 'publication',
    'reviewed-queue-storage-what-if.json': 'whatIf',
  })) if (lineage.copies[name] !== origin.artifacts[key].sha256) fail('QUEUE_ADOPTION_COPIED_HISTORY_CHANGED');
  if (lineage.copies['origin.json'] !== c.originSha256 || lineage.copies['queue-records.json'] !== digest(json({}))) fail('QUEUE_ADOPTION_COPIED_HISTORY_CHANGED');
  closed(authorization, ['version', 'approvedAt', 'expiresAt', 'action', 'proposalSha256', 'phaseSha256',
    'templateSha256', 'topologySha256', 'whatIfSha256', 'cost', 'priorDirectory', 'copiedHistory',
    'originalHistoryModified', 'allowedEffects', 'excludedEffects', 'exactFreshPreflightRequired',
    'postCreateReadbacksRequired', 'originalApprovalDirectory', 'originalJournalSha256',
    'absenceReconciliationSha256', 'freshAttemptApproval', 'permittedNewAttempts', 'repeatedDispatchAuthorized']);
  closed(authorization.copiedHistory, authorizationFiles);
  if (authorization.version !== 1 || authorization.action !== 'storage-only-and-read-only-reconciliation' ||
      authorization.proposalSha256 !== lineage.copies['reconciliation-proposal.json'] ||
      authorization.phaseSha256 !== digest(json(origin.phase)) ||
      authorization.templateSha256 !== origin.artifacts.template.sha256 ||
      authorization.topologySha256 !== origin.artifacts.topology.sha256 ||
      authorization.whatIfSha256 !== origin.artifacts.whatIf.sha256 ||
      !isDeepStrictEqual(authorization.cost, durableQueueCost()) ||
      authorization.originalHistoryModified !== false || authorization.exactFreshPreflightRequired !== true ||
      authorization.postCreateReadbacksRequired !== 8 || authorization.permittedNewAttempts !== 1 ||
      authorization.repeatedDispatchAuthorized !== false ||
      authorization.originalJournalSha256 !== origin.artifacts.priorJournal.sha256 ||
      authorization.absenceReconciliationSha256 !== origin.artifacts.absence.sha256 ||
      authorization.originalApprovalDirectory !== lineage.originalDirectory ||
      typeof authorization.priorDirectory !== 'string' || !authorization.priorDirectory ||
      authorization.freshAttemptApproval !== 'User explicitly selected Approve one fresh storage-only attempt.' ||
      !isDeepStrictEqual(authorization.allowedEffects, [
        'Create exact reviewed storage account, queue service and queue', 'Record validated read-only reconciliation',
      ]) || !isDeepStrictEqual(authorization.excludedEffects, excludedEffects)) fail('QUEUE_ADOPTION_FRESH_AUTHORIZATION_REQUIRED');
  for (const [name, hashes] of Object.entries(authorization.copiedHistory)) {
    closed(hashes, ['priorBytesSha256', 'copiedJsonSha256']);
    if (hashes.priorBytesSha256 !== lineage.copies[name] || hashes.copiedJsonSha256 !== lineage.copies[name]) fail('QUEUE_ADOPTION_COPIED_HISTORY_CHANGED');
  }
  const initial = canonicalInstant(priorJournal.intentAt), absent = canonicalInstant(absence.completedAt);
  const approved = canonicalInstant(authorization.approvedAt), expires = canonicalInstant(authorization.expiresAt);
  const intent = canonicalInstant(journal.intentAt);
  if (initial > absent || absent > approved || approved > intent || expires <= intent || expires - approved > 3600000 ||
      authorization.approvedAt !== lineage.recordedAt || authorization.expiresAt !== lineage.expiresAt ||
      values.approval.approvedAt !== authorization.approvedAt || values.approval.expiresAt !== authorization.expiresAt ||
      values.approval.sourceSha256 !== values.priorApproval.sourceSha256 ||
      origin.artifacts.approval.sha256 === origin.artifacts.priorApproval.sha256) fail('QUEUE_ADOPTION_RETRY_TIME_CHANGED');
  closed(dispatch, ['index', 'stage', 'args', 'timeoutMs', 'startedAt', 'success', 'resultSha256', 'completedAt']);
  const args = dispatch.args;
  if (!Number.isSafeInteger(dispatch.index) || dispatch.index < 0 || dispatch.stage !== 'execute' ||
      dispatch.success !== true || !sha(dispatch.resultSha256) ||
      dispatch.timeoutMs !== 15000 ||
      !Array.isArray(args) || args.length !== 14 || typeof args[11] !== 'string' ||
      !args[11].startsWith('@') || !args[11].endsWith('.json') ||
      !isDeepStrictEqual(args, ['rest', '--method', 'PUT', '--url',
        `https://management.azure.com${origin.phase.deploymentId}?api-version=2022-09-01`,
        '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json',
        '--body', args[11], '--headers', 'Content-Type=application/json'])) {
    fail('QUEUE_ADOPTION_DISPATCH_EVIDENCE_CHANGED');
  }
  closed(stop, ['stage', 'writes', 'failure', 'recordedAt', 'originalHistoryModified', 'furtherRetriesAuthorized']);
  closed(stop.failure, ['code', 'armCode', 'httpStatus', 'bridgeCode', 'diagnostics']);
  if (stop.stage !== 'execute' || stop.writes !== 1 || stop.originalHistoryModified !== false ||
      stop.furtherRetriesAuthorized !== false || stop.failure.code !== 'QUEUE_CHANGE_STOPPED_RESOURCES_PRESERVED' ||
      ['armCode', 'httpStatus', 'bridgeCode', 'diagnostics'].some(key => stop.failure[key] !== null)) fail('QUEUE_ADOPTION_SINGLE_DISPATCH_REQUIRED');
  const started = canonicalInstant(dispatch.startedAt), completed = canonicalInstant(dispatch.completedAt);
  const stopped = canonicalInstant(stop.recordedAt);
  if (started < intent || completed < started || completed > started + dispatch.timeoutMs ||
      stopped < completed || stopped > intent + 120000 || stopped >= expires) fail('QUEUE_ADOPTION_DISPATCH_TIME_CHANGED');
}
function verifyDeployment(origin, values, actual) {
  const expected = origin.firstReadback.deployment;
  only(actual, ['id', 'name', 'type', 'properties'], 'QUEUE_ADOPTION_DEPLOYMENT_CHANGED');
  only(actual.properties, ['correlationId', 'dependencies', 'duration', 'mode', 'outputResources',
    'providers', 'provisioningState', 'templateHash', 'timestamp'], 'QUEUE_ADOPTION_DEPLOYMENT_CHANGED');
  verifyDeploymentIdentity(expected, actual);
  if (!sameId(actual.id, origin.phase.deploymentId) ||
      (actual.name !== undefined && actual.name !== origin.phase.deploymentId.split('/').at(-1)) ||
      (actual.type !== undefined && !sameId(actual.type, 'Microsoft.Resources/deployments')) ||
      !guid(actual.properties.correlationId) ||
      actual.properties.templateHash !== values.validation.properties?.templateHash ||
      !/^[0-9]+$/u.test(actual.properties.templateHash)) fail('QUEUE_ADOPTION_DEPLOYMENT_CHANGED');
  const outputs = actual.properties.outputResources;
  if (!Array.isArray(outputs) || outputs.length !== 3) fail('QUEUE_ADOPTION_OUTPUT_RESOURCES_CHANGED');
  const wanted = origin.phase.resources.map(value => value.id.toLowerCase()).sort();
  for (const value of outputs) closed(value, ['id']);
  if (!isDeepStrictEqual(outputs.map(value => typeof value.id === 'string' ? value.id.toLowerCase() : null).sort(), wanted)) fail('QUEUE_ADOPTION_OUTPUT_RESOURCES_CHANGED');
  if (actual.properties.dependencies !== undefined) {
    const dependencies = actual.properties.dependencies;
    if (!Array.isArray(dependencies) || dependencies.length !== 2) fail('QUEUE_ADOPTION_DEPLOYMENT_GRAPH_CHANGED');
    const target = (value, descriptor) => {
      closed(value, ['id', 'resourceName', 'resourceType']);
      if (!sameId(value.id, descriptor.id) || value.resourceName !== descriptor.expected.name ||
          !sameId(value.resourceType, descriptor.type)) fail('QUEUE_ADOPTION_DEPLOYMENT_GRAPH_CHANGED');
    };
    for (const [index, value] of dependencies.entries()) {
      closed(value, ['id', 'resourceName', 'resourceType', 'dependsOn']);
      if (!Array.isArray(value.dependsOn) || value.dependsOn.length !== 1) fail('QUEUE_ADOPTION_DEPLOYMENT_GRAPH_CHANGED');
      const { dependsOn, ...resource } = value;
      target(resource, origin.phase.resources[index + 1]); target(dependsOn[0], origin.phase.resources[index]);
    }
  }
  if (actual.properties.providers !== undefined) {
    const providers = [{ namespace: 'Microsoft.Storage', resourceTypes: origin.phase.resources.map((descriptor, index) => ({
      locations: [index === 0 ? origin.topology.location : null],
      resourceType: descriptor.type.slice('Microsoft.Storage/'.length),
    })) }];
    if (!isDeepStrictEqual(actual.properties.providers, providers)) fail('QUEUE_ADOPTION_DEPLOYMENT_GRAPH_CHANGED');
  }
  between(actual.properties.timestamp, values.dispatch.startedAt, values.stop.recordedAt, 'QUEUE_ADOPTION_DEPLOYMENT_TIME_CHANGED');
}
function operationPins(origin, values, operations) {
  const list = completeList(operations, 4, 'QUEUE_ADOPTION_OPERATIONS_INCOMPLETE');
  if (list.length < 3) fail('QUEUE_ADOPTION_OPERATIONS_INCOMPLETE');
  const targets = new Set(), operationIds = new Set(), trackingIds = new Set();
  let evaluations = 0;
  const pins = list.map(operation => {
    closed(operation, ['id', 'operationId', 'properties']);
    const p = operation.properties, target = p?.targetResource;
    closed(p, ['duration', 'provisioningOperation', 'provisioningState', 'statusCode', 'timestamp', 'trackingId',
      ...(Object.hasOwn(p ?? {}, 'targetResource') ? ['targetResource'] : [])]);
    if (typeof operation.operationId !== 'string' || !/^[0-9A-Fa-f]{8,32}$/u.test(operation.operationId) ||
        !sameId(operation.id, `${origin.phase.deploymentId}/operations/${operation.operationId}`) ||
        operationIds.has(operation.operationId.toLowerCase()) || !guid(p.trackingId) || trackingIds.has(p.trackingId) ||
        p.provisioningState !== 'Succeeded' || !['OK', 'Created'].includes(p.statusCode) ||
        typeof p.duration !== 'string' || !/^PT(?:0|[1-9]\d{0,2})(?:\.\d{1,7})?S$/u.test(p.duration)) fail('QUEUE_ADOPTION_OPERATION_CHANGED');
    between(p.timestamp, values.dispatch.startedAt, origin.firstReadback.deployment.properties.timestamp, 'QUEUE_ADOPTION_OPERATION_TIME_CHANGED');
    operationIds.add(operation.operationId.toLowerCase()); trackingIds.add(p.trackingId);
    if (p.provisioningOperation === 'EvaluateDeploymentOutput') {
      if (target !== undefined || ++evaluations > 1) fail('QUEUE_ADOPTION_OPERATION_CHANGED');
    } else {
      closed(target, ['id', 'resourceName', 'resourceType']);
      const descriptor = origin.phase.resources.find(value => sameId(value.id, target.id));
      if (p.provisioningOperation !== 'Create' || !descriptor || targets.has(descriptor.id) ||
          target.resourceName !== descriptor.expected.name || !sameId(target.resourceType, descriptor.type)) fail('QUEUE_ADOPTION_CREATE_TARGET_CHANGED');
      targets.add(descriptor.id);
    }
    return { id: operation.id, operationId: operation.operationId, ...p };
  });
  if (targets.size !== 3) fail('QUEUE_ADOPTION_OPERATIONS_INCOMPLETE');
  return pins.sort((a, b) => a.id.localeCompare(b.id));
}
function systemDataCreation(value, start, end) {
  if (!Object.hasOwn(value, 'systemData')) return {};
  const data = value.systemData;
  only(data, ['createdAt', 'createdBy', 'createdByType', 'lastModifiedAt', 'lastModifiedBy', 'lastModifiedByType'],
    'QUEUE_ADOPTION_SYSTEM_DATA_SHAPE');
  for (const key of ['createdBy', 'lastModifiedBy']) {
    if (Object.hasOwn(data, key) && (typeof data[key] !== 'string' || !data[key].length ||
        data[key].length > 2048 || /[\u0000-\u001f\u007f]/u.test(data[key]))) fail('QUEUE_ADOPTION_SYSTEM_DATA_SHAPE');
  }
  for (const key of ['createdByType', 'lastModifiedByType']) {
    if (Object.hasOwn(data, key) && !['User', 'Application', 'ManagedIdentity', 'Key'].includes(data[key])) fail('QUEUE_ADOPTION_SYSTEM_DATA_SHAPE');
  }
  for (const key of ['createdAt', 'lastModifiedAt']) if (Object.hasOwn(data, key)) queueArmInstant(data[key]);
  if (Object.hasOwn(data, 'createdAt')) {
    between(data.createdAt, start, end, 'QUEUE_ADOPTION_RESOURCE_CREATION_TIME_CHANGED');
    if (Object.hasOwn(data, 'lastModifiedAt') && queueArmInstant(data.lastModifiedAt) < queueArmInstant(data.createdAt)) {
      fail('QUEUE_ADOPTION_SYSTEM_DATA_TIME_CHANGED');
    }
  }
  return Object.fromEntries(['createdAt', 'createdBy', 'createdByType'].filter(key => Object.hasOwn(data, key)).map(key => [key, data[key]]));
}
function storageResources(c, origin, resources, expectedAccess, defender = null) {
  if (!['Disabled', 'SecuredByPerimeter'].includes(expectedAccess)) fail('QUEUE_ADOPTION_EXPECTED_NETWORK_MODE_REQUIRED');
  closed(resources, origin.phase.resources.map(value => value.id));
  for (const original of origin.phase.resources) {
    const descriptor = structuredClone(original);
    if (descriptor.id === origin.topology.ids.account) {
      descriptor.expected.properties.publicNetworkAccess = expectedAccess;
      if (defender !== null) descriptor.expected.properties.networkAcls.resourceAccessRules = [queueDefenderRule(c)];
    }
    verifyQueueResource(c, origin.topology, descriptor, resources[descriptor.id]);
  }
  if (!Object.hasOwn(resources[origin.topology.ids.service].properties, 'logging') ||
      !isDeepStrictEqual(resources[origin.topology.ids.account].properties.privateEndpointConnections, [])) {
    fail('QUEUE_ADOPTION_SECURITY_READBACK_REQUIRED');
  }
  const account = resources[origin.topology.ids.account], initial = origin.firstReadback.resources[origin.topology.ids.account];
  if (account.properties.creationTime !== initial.properties.creationTime) fail('QUEUE_ADOPTION_ACCOUNT_GENERATION_CHANGED');
  const start = parseArtifact(origin.artifacts.dispatch).startedAt, end = origin.firstReadback.deployment.properties.timestamp;
  for (const descriptor of origin.phase.resources) {
    const previous = origin.firstReadback.resources[descriptor.id], actual = resources[descriptor.id];
    const before = systemDataCreation(previous, start, end), after = systemDataCreation(actual, start, end);
    if (Object.entries(before).some(([key, value]) => after[key] !== value)) fail('QUEUE_ADOPTION_RESOURCE_IDENTITY_CHANGED');
  }
  return resources;
}
function postconditions(c, origin, resources, defender = null) {
  return { version: defender === null ? 1 : 2, kind: 'observed-queue-storage-postconditions',
    ...(defender === null ? {} : { historicalRequirementsSha256: digest(json(queuePostCreateRequirements(c, origin.topology))),
      defenderEvidenceSha256: digest(json(defender)) }),
    observations: queuePostCreateRequirements(c, origin.topology).map(requirement => {
      if (defender !== null && requirement.path === 'properties.networkAcls.resourceAccessRules') {
        requirement = { ...requirement, expected: [queueDefenderRule(c)] };
      }
      const actual = requirement.path.split('.').reduce((parent, key) => parent?.[key], resources[requirement.resourceId]);
      if (!isDeepStrictEqual(actual, requirement.expected)) fail('QUEUE_ADOPTION_POSTCONDITION_MISSING');
      return { ...requirement, actual: structuredClone(actual) };
    }), complete: true };
}
function verifyQueues(c, origin, queues) {
  const list = completeList(queues, 1, 'QUEUE_ADOPTION_QUEUE_INVENTORY_CHANGED');
  if (list.length !== 1) fail('QUEUE_ADOPTION_QUEUE_INVENTORY_CHANGED');
  verifyQueueResource(c, origin.topology, origin.phase.resources[2], list[0]);
}
function verifyAccess(c, origin, access) {
  closed(access, ['identity', 'role', 'assignment', 'assignments']);
  verifyIdentity(c, access.identity);
  if (!isDeepStrictEqual(identityPin(access.identity), identityPin(origin.identity)) ||
      access.role !== null || access.assignment !== null) fail('QUEUE_ADOPTION_ACCESS_DRIFT');
  const scopes = [origin.topology.ids.account, origin.topology.ids.service, origin.topology.ids.queue];
  closed(access.assignments, scopes);
  // Inventories do not resolve role permissions or transitive group membership.
  for (const assignments of Object.values(access.assignments)) {
    const seen = new Set();
    for (const assignment of completeList(assignments, 256, 'QUEUE_ADOPTION_ACCESS_INCOMPLETE')) {
      const p = assignment?.properties;
      only(assignment, ['id', 'type', 'name', 'properties'], 'QUEUE_ADOPTION_ACCESS_INCOMPLETE');
      only(p, ['roleDefinitionId', 'principalId', 'principalType', 'scope', 'condition', 'conditionVersion',
        'createdOn', 'updatedOn', 'createdBy', 'updatedBy', 'description', 'delegatedManagedIdentityResourceId'], 'QUEUE_ADOPTION_ACCESS_INCOMPLETE');
      if (typeof assignment?.id !== 'string' || seen.has(assignment.id.toLowerCase()) ||
          !guid(p?.principalId) || typeof p.scope !== 'string' || typeof p.roleDefinitionId !== 'string') fail('QUEUE_ADOPTION_ACCESS_INCOMPLETE');
      seen.add(assignment.id.toLowerCase());
      if (sameId(p.principalId, origin.identity.properties.principalId) ||
          scopes.some(scope => sameId(scope, p.scope) || p.scope.toLowerCase().startsWith(scope.toLowerCase() + '/'))) fail('QUEUE_ADOPTION_ACCESS_DRIFT');
    }
  }
}

export function verifyQueueAdoptionOrigin(c, origin) {
  bounded(origin); validateConfig(c);
  closed(origin, ['version', 'kind', 'topology', 'identity', 'phase', 'artifacts', 'firstReadback', 'originalReceipt', 'assurance']);
  if (origin.version !== 1 || origin.kind !== 'stopped-queue-storage-origin' || origin.originalReceipt !== null ||
      !isDeepStrictEqual(origin.assurance, QUEUE_ADOPTION_ASSURANCE)) fail('QUEUE_ADOPTION_ORIGIN_INVALID');
  verifyQueueTopology(c, origin.topology); verifyIdentity(c, origin.identity);
  if (!isDeepStrictEqual(origin.phase, buildQueuePhase(c, 'queue-storage', origin.topology))) fail('QUEUE_ADOPTION_HISTORICAL_PHASE_CHANGED');
  closed(origin.artifacts, historicalArtifacts);
  const values = Object.fromEntries(historicalArtifacts.map(name => [name, parseArtifact(origin.artifacts[name])]));
  if (!isDeepStrictEqual(values.config, c) || !isDeepStrictEqual(values.topology, origin.topology) ||
      !isDeepStrictEqual(values.template, origin.phase.template)) fail('QUEUE_ADOPTION_HISTORICAL_PHASE_CHANGED');
  closed(values.plan, ['version', 'phase', 'sourceSha256', 'cost', 'qualified', 'executionAuthorized', 'exactReviewRequired']);
  if (values.plan.version !== 1 || !isDeepStrictEqual(values.plan.phase, origin.phase) ||
      values.plan.sourceSha256 !== values.publication.sourceSha256 ||
      !isDeepStrictEqual(values.plan.cost, durableQueueCost()) || values.plan.qualified !== false ||
      values.plan.executionAuthorized !== false || values.plan.exactReviewRequired !== true) fail('QUEUE_ADOPTION_HISTORICAL_PHASE_CHANGED');
  verifyHistoricalAttempt(c, origin, values, true);
  verifyHistoricalAttempt(c, origin, values, false);
  if (values.preflight.armValidationSha256 !== origin.artifacts.validation.sha256 ||
      values.preflight.providerOperationsSha256 !== verifyQueueProviderOperations(values.providerOperations) ||
      values.approval.whatIfSha256 !== origin.artifacts.whatIf.sha256 ||
      values.validation?.properties?.provisioningState !== 'Succeeded' || values.validation.error ||
      values.validation.properties.error || values.validation.nextLink) fail('QUEUE_ADOPTION_HISTORICAL_BINDING_CHANGED');
  const preview = verifyQueueWhatIf(c, origin.phase, origin.topology, values.whatIf, values.preflight.preservedIds);
  if (!isDeepStrictEqual(values.preflight.queuePreview, preview)) fail('QUEUE_ADOPTION_HISTORICAL_BINDING_CHANGED');
  verifyLineage(c, origin, values);
  const first = origin.firstReadback;
  closed(first, ['checkedAt', 'deployment', 'operations', 'resources', 'queues', 'privacy']);
  canonicalInstant(first.checkedAt);
  if (canonicalInstant(first.checkedAt) < canonicalInstant(values.stop.recordedAt)) fail('QUEUE_ADOPTION_READBACK_TIME_CHANGED');
  verifyDeployment(origin, values, first.deployment);
  operationPins(origin, values, first.operations);
  storageResources(c, origin, first.resources, 'Disabled');
  between(first.resources[origin.topology.ids.account].properties.creationTime,
    values.dispatch.startedAt, first.deployment.properties.timestamp, 'QUEUE_ADOPTION_ACCOUNT_CREATION_TIME_CHANGED');
  postconditions(c, origin, first.resources); verifyQueues(c, origin, first.queues);
  verifyQueuePrivacy(origin.topology, first.privacy);
  return values;
}

function verifyObservation(c, origin, values, observation, source, defender = null) {
  bounded(observation);
  closed(observation, ['version', 'kind', 'startedAt', 'completedAt', 'sourceSha256', 'originSha256',
    'deployment', 'operations', 'resources', 'queues', 'privacy', 'access', 'postconditions', 'qualified', 'operationallyQualified',
    ...(defender === null ? [] : ['defender'])]);
  const start = canonicalInstant(observation.startedAt), end = canonicalInstant(observation.completedAt);
  if (observation.version !== (defender === null ? 1 : 2) || observation.kind !== 'observed-disabled-queue-storage' ||
      !sha(source) || observation.sourceSha256 !== source || source === values.publication.sourceSha256 ||
      observation.originSha256 !== digest(json(origin)) || start < canonicalInstant(origin.firstReadback.checkedAt) ||
      end < start || end - start >= QUEUE_ADOPTION_LIMITS.collectionMs ||
      observation.qualified !== false || observation.operationallyQualified !== false) fail('QUEUE_ADOPTION_OBSERVATION_INVALID');
  verifyDeployment(origin, values, observation.deployment);
  if (!isDeepStrictEqual(operationPins(origin, values, observation.operations),
    operationPins(origin, values, origin.firstReadback.operations))) fail('QUEUE_ADOPTION_OPERATION_IDENTITY_CHANGED');
  if (defender !== null) {
    verifyQueueDefenderEvidence(c, origin, defender);
    for (const value of Object.values(defender.activity)) {
      if (canonicalInstant(value.receipt.completedAt) > start) fail('QUEUE_DEFENDER_PROVENANCE_AFTER_OBSERVATION');
    }
    verifyCurrentQueueDefender(c, origin, defender, observation.defender);
  }
  storageResources(c, origin, observation.resources, 'Disabled', defender);
  verifyQueues(c, origin, observation.queues); verifyQueuePrivacy(origin.topology, observation.privacy);
  for (const value of Object.values(observation.privacy.diagnostics)) emptyList(value, 'QUEUE_ADOPTION_DIAGNOSTICS_INCOMPLETE');
  verifyAccess(c, origin, observation.access);
  if (!isDeepStrictEqual(observation.postconditions, postconditions(c, origin, observation.resources, defender))) fail('QUEUE_ADOPTION_POSTCONDITION_MISSING');
}

/** The port performs one bounded GET per descriptor; it never receives a method or body. */
export async function collectQueueAdoption(c, origin, io, defender = null) {
  closed(io, ['now', 'sourceDigest', 'read']);
  if (['now', 'sourceDigest', 'read'].some(key => typeof io[key] !== 'function')) fail('QUEUE_ADOPTION_READ_PORT_REQUIRED');
  const values = verifyQueueAdoptionOrigin(c, origin);
  if (defender !== null) {
    verifyQueueDefenderEvidence(c, origin, defender);
    defender = structuredClone(defender);
  }
  const started = milliseconds(io.now()), deadline = started + QUEUE_ADOPTION_LIMITS.collectionMs;
  const source = await io.sourceDigest();
  const guard = async () => {
    if (milliseconds(io.now()) >= deadline) fail('QUEUE_ADOPTION_COLLECTION_DEADLINE');
    if (!sha(source) || source === values.publication.sourceSha256 || await io.sourceDigest() !== source) fail('QUEUE_ADOPTION_SOURCE_CHANGED');
  };
  const read = async (id, apiVersion, filter = null) => {
    await guard();
    const value = await io.read(Object.freeze({ id, apiVersion, filter }), deadline);
    bounded(value); await guard();
    return value;
  };
  const q = origin.topology.ids;
  const deployment = await read(origin.phase.deploymentId, '2022-09-01');
  const operations = await read(`${origin.phase.deploymentId}/operations`, '2022-09-01');
  const resources = {};
  for (const descriptor of origin.phase.resources) resources[descriptor.id] = await read(descriptor.id, descriptor.apiVersion);
  const queues = await read(`${q.service}/queues`, '2025-01-01');
  const diagnostics = {};
  for (const id of [q.account, q.service]) diagnostics[id] = await read(`${id}/providers/Microsoft.Insights/diagnosticSettings`, '2021-05-01-preview');
  const identity = await read(ids(c).ingestIdentity, '2023-01-31');
  const role = await read(q.role, '2022-04-01'), assignment = await read(q.assignment, '2022-04-01');
  const assignments = {};
  for (const scope of [q.account, q.service, q.queue]) {
    assignments[scope] = await read(`${scope}/providers/Microsoft.Authorization/roleAssignments`, '2022-04-01', '$filter=atScope()');
  }
  const currentDefender = defender === null ? null : await collectQueueDefender(c, origin, defender,
    { now: io.now, read: (request, limit) => {
      if (limit !== deadline) fail('QUEUE_DEFENDER_READ_DEADLINE');
      return read(request.id, request.apiVersion, request.filter);
    } }, deadline);
  await guard();
  const observation = { version: defender === null ? 1 : 2, kind: 'observed-disabled-queue-storage',
    startedAt: new Date(started).toISOString(), completedAt: new Date(milliseconds(io.now())).toISOString(),
    sourceSha256: source, originSha256: digest(json(origin)), deployment, operations, resources, queues,
    privacy: { diagnostics }, access: { identity, role, assignment, assignments },
    ...(defender === null ? {} : { defender: currentDefender }),
    postconditions: postconditions(c, origin, resources, defender), qualified: false, operationallyQualified: false };
  verifyObservation(c, origin, values, observation, source, defender);
  return { version: defender === null ? 1 : 2, kind: 'queue-storage-adoption-proposal', configSha256: digest(json(c)),
    originSha256: digest(json(origin)), sourceSha256: source, observation,
    ...(defender === null ? {} : { defender }) };
}

export function adoptQueueStorage(c, proposal, origin, review, policyPublication, at) {
  const record = { version: proposal?.version === 2 ? 3 : 2, kind: 'reviewed-queue-storage-adoption', topology: origin.topology,
    identity: origin.identity, origin, proposal, review, publication: policyPublication,
    observation: proposal.observation, adoptedAt: new Date(milliseconds(at)).toISOString(), authority: QUEUE_ADOPTION_AUTHORITY };
  verifyQueueAdoptionRecord(c, record);
  return structuredClone(record);
}

export function verifyQueueAdoptionRecord(c, record) {
  bounded(record);
  const withDefender = record?.version === 3;
  closed(record, ['version', 'kind', 'topology', 'identity', 'origin', 'proposal', 'review', 'publication',
    'observation', 'adoptedAt', 'authority']);
  if (![2, 3].includes(record.version) || record.kind !== 'reviewed-queue-storage-adoption' ||
      !isDeepStrictEqual(record.authority, QUEUE_ADOPTION_AUTHORITY)) fail('QUEUE_ADOPTION_RECORD_INVALID');
  const values = verifyQueueAdoptionOrigin(c, record.origin), proposal = record.proposal, review = record.review;
  publication(record.publication);
  closed(proposal, ['version', 'kind', 'configSha256', 'originSha256', 'sourceSha256', 'observation', ...(withDefender ? ['defender'] : [])]);
  closed(review, ['version', 'action', 'configSha256', 'originSha256', 'proposalSha256', 'sourceSha256', 'reviewedAt', 'expiresAt', 'authority',
    ...(withDefender ? ['defender'] : [])]);
  const source = record.publication.sourceSha256, originHash = digest(json(record.origin));
  const reviewed = canonicalInstant(review.reviewedAt), expires = canonicalInstant(review.expiresAt);
  const adopted = canonicalInstant(record.adoptedAt);
  if (!isDeepStrictEqual(record.topology, record.origin.topology) || !isDeepStrictEqual(record.identity, record.origin.identity) ||
      proposal.version !== (withDefender ? 2 : 1) || proposal.kind !== 'queue-storage-adoption-proposal' ||
      proposal.configSha256 !== digest(json(c)) || proposal.originSha256 !== originHash || proposal.sourceSha256 !== source ||
      !isDeepStrictEqual(record.observation, proposal.observation) || review.version !== (withDefender ? 2 : 1) ||
      review.action !== (withDefender ? 'adopt-exact-observed-queue-storage-with-inherited-defender' : 'adopt-exact-observed-queue-storage') ||
      review.configSha256 !== digest(json(c)) ||
      review.originSha256 !== originHash || review.proposalSha256 !== digest(json(proposal)) || review.sourceSha256 !== source ||
      !isDeepStrictEqual(review.authority, QUEUE_ADOPTION_AUTHORITY) ||
      reviewed < canonicalInstant(proposal.observation.completedAt) || reviewed > adopted || adopted >= expires ||
      expires - reviewed > 3600000 || adopted - canonicalInstant(proposal.observation.startedAt) > QUEUE_ADOPTION_LIMITS.freshnessMs ||
      record.publication.commitSha === values.publication.commitSha) fail('QUEUE_ADOPTION_EXACT_REVIEW_REQUIRED');
  if (withDefender) verifyQueueDefenderReview(c, record.origin, proposal.defender, review.defender);
  verifyObservation(c, record.origin, values, record.observation, source, withDefender ? proposal.defender : null);
  return record.observation;
}

export function verifyAdoptedQueueStorage(c, record, resources, expectedAccess) {
  verifyQueueAdoptionRecord(c, record);
  bounded(resources);
  return storageResources(c, record.origin, resources, expectedAccess, record.version === 3 ? record.proposal.defender : null);
}

export async function verifyQueueAdoptionSources(c, record, lookup) {
  verifyQueueAdoptionRecord(c, record);
  if (typeof lookup !== 'function') fail('QUEUE_ADOPTION_SOURCE_LOOKUP_REQUIRED');
  const values = verifyQueueAdoptionOrigin(c, record.origin);
  for (const policy of [values.priorPublication, values.publication, record.publication]) {
    if (await lookup(policy.commitSha) !== policy.sourceSha256) fail('QUEUE_ADOPTION_PUBLISHED_SOURCE_CHANGED');
  }
}
