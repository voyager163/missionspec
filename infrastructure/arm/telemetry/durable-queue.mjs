import { isDeepStrictEqual } from 'node:util';
import { assertOwned, BUDGET, closed, deploymentName, digest, fail, firstReleaseCost, ids, json,
  ownerTags, sameId, stableGuid, validateConfig } from './definition.mjs';
import { canonicalInstant, verifyApproval, verifyDeploymentIdentity, verifyFreshReview } from './policy.mjs';

export const QUEUE_PHASES = Object.freeze(['queue-storage', 'queue-role', 'queue-assignment']);
export const QUEUE_PROFILE_KIND = 'reviewed-durable-queue-receiver';
export const QUEUE_RUNTIME = Object.freeze({
  version: 1, kind: 'durable-queue-v1', producerScope: 'https://storage.azure.com/.default',
  consumerScope: 'https://monitor.azure.com/.default', preparationTimeoutMs: 20000,
  storageTimeoutMs: 650, clientTimeoutMs: 1000, maxPayloadBytes: 1024, messageTtlSeconds: 3600,
  maxApproximateMessages: 10000, maxBatchMessages: 32, maxConcurrentUploads: 1,
  workerTimeoutMs: 15000, visibilityTimeoutSeconds: 60, maxDeliveryAttempts: 3,
  maxConcurrentEnqueues: 8, queueTransactionTimeoutMs: 5000, workerBatchTimeoutMs: 45000,
  queuePropertiesIntervalMs: 30000, idlePollMs: 30000, backoffInitialMs: 5000, backoffMaximumMs: 60000,
  readinessRequiresFreshQueueMetadata: true, consumerReadinessGatesAdmission: false,
  identityRefreshMarginMs: 120000, visibilityUpdates: 0, queueSdkMaxTries: 1, logsSdkMaxRetries: 0,
  redirectRetries: 0, maxDeletesPerBatch: 32, shutdownMaxMs: 10000,
  disabledNetworkRequests: 0, acceptedStatus: 202, admissionMeans: 'durably-enqueued-not-logs-persisted',
});
export const QUEUE_PERMISSIONS = Object.freeze({
  actions: ['Microsoft.Storage/storageAccounts/queueServices/queues/read'], notActions: [],
  dataActions: [
    'Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action',
    'Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action',
  ], notDataActions: [],
});
export const QUEUE_PERMISSION_EVIDENCE = Object.freeze({
  provider: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/storage#microsoftstorage',
  operations: 'https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-queue-service-operations',
  roles: 'https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/storage',
  mapping: [
    { operation: 'Get Queue Metadata', name: QUEUE_PERMISSIONS.actions[0], isDataAction: false },
    { operation: 'Put Message', name: QUEUE_PERMISSIONS.dataActions[0], isDataAction: true },
    { operation: 'Get Messages', name: QUEUE_PERMISSIONS.dataActions[1], isDataAction: true },
    { operation: 'Delete Message', name: QUEUE_PERMISSIONS.dataActions[1], isDataAction: true },
  ],
});
export const QUEUE_AUTHORITY = Object.freeze({
  deployment: false, publication: false, ingestion: false, clientActivation: false, productionClearance: false,
  delete: false, retag: false, repush: false, registryAdmin: false, securityChanges: false,
});
const sha = v => typeof v === 'string' && /^[0-9a-f]{64}$/u.test(v);
const api = '2025-01-01';

export function verifyOfficialQueuePrices(evidence) {
  const url = new URL(evidence?.url);
  if (url.protocol !== 'https:' || url.host !== 'prices.azure.com' || url.username || url.password ||
      url.pathname !== '/api/retail/prices' || url.hash || !Number.isFinite(Date.parse(evidence.retrievedAt))) fail('OFFICIAL_QUEUE_PRICES_REQUIRED');
  const response = evidence.response;
  if (response?.BillingCurrency !== 'USD' || response.NextPageLink !== null || !Array.isArray(response.Items) ||
      response.Items.length !== 5 || response.Count !== 5) fail('OFFICIAL_QUEUE_PRICES_INCOMPLETE');
  const expected = { 'LRS Data Stored': [0.045, '1 GB/Month'], 'LRS Class 1 Operations': [0.004, '10K'],
    'Class 2 Operations': [0.004, '10K'], 'LRS Class 1 Additional IO': [0.004, '10K'], 'LRS Class 2 Additional IO': [0.004, '10K'] };
  const seen = new Set();
  for (const item of response.Items) {
    const meter = expected[item.meterName];
    if (!meter || seen.has(item.meterName) || item.currencyCode !== 'USD' || item.type !== 'Consumption' ||
        item.serviceName !== 'Storage' || item.productName !== 'Queues v2' || item.skuName !== 'Standard LRS' ||
        item.armRegionName !== 'australiaeast' || item.tierMinimumUnits !== 0 ||
        item.retailPrice !== meter[0] || item.unitPrice !== meter[0] || item.unitOfMeasure !== meter[1]) fail('OFFICIAL_QUEUE_PRICE_CHANGED');
    seen.add(item.meterName);
  }
  return digest(json(evidence));
}

export function durableQueueCost() {
  const previous = firstReleaseCost(2);
  // Preserve the already reviewed rounded base and every reserve; round only the new total.
  const units = { thirdImageInitialPlusDailyAndPullReserve: 33 * 29000, additionalStorageSecurityReserve: 1000000,
    acceptedEventOperations: 31 * 100000 * 5 * 400 / 10000,
    conservativeIdleOperations: 31 * 86400 * 2 * 400 / 10000, fiveGBStorage: 5 * 4500, retryReserve: 1000000 };
  const additions = Object.fromEntries(Object.entries(units).map(([k, v]) => [k, v / 100000]));
  const unroundedTotal = (previous.total * 100000 + Object.values(units).reduce((a, b) => a + b, 0)) / 100000;
  const total = Math.round(unroundedTotal * 100) / 100;
  return { version: 1, kind: 'durable-queue-three-image-cost', currency: 'USD', days: 31, recentDigestCount: 3,
    previous, additions, acceptedEventsPerDay: 100000, operationsPerAcceptedEvent: 5, idleOperationsPerSecond: 2,
    unroundedTotal, total, estimateLimit: BUDGET.projectAmount, withinEstimate: total <= BUDGET.projectAmount,
    headroom: Math.round((BUDGET.projectAmount - total) * 100) / 100, headroomWarning: 'Only USD 0.63 modeled headroom; not a billing cap.',
    freeGrantsAssumed: false, deductionsAssumed: false, isHardCap: false,
    runtimeCountersReset: true, queueCountIsApproximate: true, exactBacklogOrSpendBoundClaimed: false };
}
export function queueIds(c, namespace) {
  validateConfig(c);
  if (typeof namespace !== 'string' || !/^[a-z0-9]{8,16}$/u.test(namespace)) fail('EXPLICIT_QUEUE_NAMESPACE_REQUIRED');
  const r = ids(c), accountName = `msrtq${namespace}`, queueName = 'telemetry-events-v1';
  const account = `${r.group}/providers/Microsoft.Storage/storageAccounts/${accountName}`;
  const service = `${account}/queueServices/default`, queue = `${service}/queues/${queueName}`;
  return { accountName, queueName, account, service, queue,
    role: `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/${stableGuid(`${queue}/durable-message-worker-v1`)}`,
    assignment: `${queue}/providers/Microsoft.Authorization/roleAssignments/${stableGuid(`${queue}/${r.ingestIdentity}/worker-v1`)}`,
    queueUrl: `https://${accountName}.queue.core.windows.net/${queueName}` };
}
export function queueEnvironment(topology) {
  return { AZURE_QUEUE_URL: topology.ids.queueUrl, AZURE_QUEUE_RESOURCE_ID: topology.ids.queue };
}
export function queueTopology(c, namespace) {
  const targets = queueIds(c, namespace);
  return { version: 1, kind: 'durable-queue-topology', configSha256: digest(json(c)), namespace, location: c.location,
    ids: targets, identity: ids(c).ingestIdentity, runtime: QUEUE_RUNTIME, environment: queueEnvironment({ ids: targets }),
    identityLifecycle: 'Main', registryPullLifecycle: 'None', queueCreatedBy: 'ARM-only',
    messageTtlEnforcedBy: 'producer-per-message', permissions: QUEUE_PERMISSIONS,
    permissionEvidence: QUEUE_PERMISSION_EVIDENCE, securityBaseline: 'inherit-without-mutation',
    cost: durableQueueCost(), authority: QUEUE_AUTHORITY };
}
export function verifyQueueTopology(c, topology) {
  if (!isDeepStrictEqual(topology, queueTopology(c, topology?.namespace))) fail('QUEUE_TOPOLOGY_DRIFT');
  return topology;
}
export function verifyQueueReview(c, topology, review, source, at) {
  verifyQueueTopology(c, topology);
  closed(review, ['version', 'action', 'topologySha256', 'configSha256', 'sourceSha256', 'approvedAt', 'expiresAt', 'authority']);
  const start = canonicalInstant(review.approvedAt), end = canonicalInstant(review.expiresAt);
  if (review.version !== 1 || review.action !== 'accept-exact-durable-queue-topology' ||
      review.topologySha256 !== digest(json(topology)) || review.configSha256 !== digest(json(c)) ||
      !sha(source) || review.sourceSha256 !== source || !isDeepStrictEqual(review.authority, QUEUE_AUTHORITY) ||
      !Number.isSafeInteger(at) || start > at || end <= at || end - start > 3600000) fail('EXACT_QUEUE_TOPOLOGY_REVIEW_REQUIRED');
}
export function verifyQueueProviderOperations(value) {
  if (!Array.isArray(value?.value) || value.nextLink) fail('QUEUE_PROVIDER_OPERATIONS_REQUIRED');
  for (const [name, isDataAction] of [...QUEUE_PERMISSIONS.actions.map(v => [v, false]), ...QUEUE_PERMISSIONS.dataActions.map(v => [v, true])]) {
    const matches = value.value.filter(v => sameId(v.name, name));
    if (matches.length !== 1 || matches[0].isDataAction !== isDataAction) fail('QUEUE_PROVIDER_PERMISSION_MISMATCH');
  }
  return digest(json(value));
}
export function queueRoleProperties(c, topology) {
  verifyQueueTopology(c, topology);
  return { roleName: `${c.namePrefix}-queue-worker-${topology.namespace}`,
    description: 'Only metadata, add, receive/delete messages in the reviewed telemetry queue; no updates or clear-all.',
    type: 'CustomRole', permissions: [structuredClone(QUEUE_PERMISSIONS)], assignableScopes: [topology.ids.queue] };
}
export function queueResources(c, topology, identity) {
  verifyQueueTopology(c, topology);
  const q = topology.ids, r = ids(c);
  if (identity) {
    assertOwned(identity, r.ingestIdentity, c);
    if (identity.properties?.tenantId !== c.tenantId ||
        !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(identity.properties?.principalId ?? '')) fail('QUEUE_IDENTITY_REQUIRED');
  }
  const descriptor = (id, expected) => ({ id, type: expected.type, apiVersion: expected.apiVersion, expected });
  return {
    'queue-storage': [
      descriptor(q.account, { type: 'Microsoft.Storage/storageAccounts', apiVersion: api, name: q.accountName,
        location: c.location, tags: ownerTags(c), kind: 'StorageV2', sku: { name: 'Standard_LRS' },
        properties: { supportsHttpsTrafficOnly: true, minimumTlsVersion: 'TLS1_2', allowSharedKeyAccess: false,
          allowBlobPublicAccess: false, publicNetworkAccess: 'Enabled', defaultToOAuthAuthentication: true,
          allowCrossTenantReplication: false, isLocalUserEnabled: false, isSftpEnabled: false, isHnsEnabled: false,
          networkAcls: { bypass: 'None', defaultAction: 'Allow', ipRules: [], virtualNetworkRules: [], resourceAccessRules: [] },
          encryption: { keySource: 'Microsoft.Storage', services: { queue: { enabled: true, keyType: 'Account' } } } } }),
      descriptor(q.service, { type: 'Microsoft.Storage/storageAccounts/queueServices', apiVersion: api,
        name: `${q.accountName}/default`, dependsOn: [q.account], properties: { cors: { corsRules: [] } } }),
      descriptor(q.queue, { type: 'Microsoft.Storage/storageAccounts/queueServices/queues', apiVersion: api,
        name: `${q.accountName}/default/${q.queueName}`, dependsOn: [q.service], properties: { metadata: {} } }),
    ],
    'queue-role': [descriptor(q.role, { type: 'Microsoft.Authorization/roleDefinitions', apiVersion: '2022-04-01',
      name: q.role.split('/').at(-1), properties: queueRoleProperties(c, topology) })],
    'queue-assignment': identity ? [descriptor(q.assignment, { type: 'Microsoft.Authorization/roleAssignments', apiVersion: '2022-04-01',
      name: q.assignment.split('/').at(-1), scope: q.queue,
      properties: { roleDefinitionId: q.role, principalId: identity.properties.principalId, principalType: 'ServicePrincipal' } })] : [],
  };
}
export function buildQueuePhase(c, name, topology, identity) {
  if (!QUEUE_PHASES.includes(name)) fail('FIXED_QUEUE_PHASE_REQUIRED');
  const resources = queueResources(c, topology, identity)[name], scope = name === 'queue-role' ? ids(c).sub : ids(c).group;
  if (!resources.length) fail('QUEUE_IDENTITY_REQUIRED');
  return { version: 1, phase: name, configSha256: digest(json(c)), topologySha256: digest(json(topology)), scope,
    deploymentId: `${scope}/providers/Microsoft.Resources/deployments/${deploymentName(c, name)}`,
    resources, template: {
      $schema: `https://schema.management.azure.com/schemas/${name === 'queue-role' ? '2018-05-01/subscriptionDeploymentTemplate' : '2019-04-01/deploymentTemplate'}.json#`,
      contentVersion: '1.0.0.0', resources: resources.map(v => v.expected) },
    allowedModify: {}, computedReadbacksRequired: [], requiredReceipts: QUEUE_PHASES.slice(0, QUEUE_PHASES.indexOf(name)),
    publicationAuthorized: false, cliActivationAuthorized: false, ingestEnabled: false };
}
function only(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !fields.includes(k))) fail('QUEUE_RESOURCE_DRIFT');
}
export function verifyQueueResource(c, topology, descriptor, actual, whatIf = false) {
  verifyQueueTopology(c, topology);
  const e = descriptor.expected, p = actual?.properties;
  only(actual, ['id', 'name', 'type', 'apiVersion', 'location', 'tags', 'kind', 'sku', 'properties', 'systemData', 'etag', 'scope', 'dependsOn']);
  if (!sameId(actual.id, descriptor.id) || !sameId(actual.type, e.type) ||
      (actual.apiVersion !== undefined && actual.apiVersion !== descriptor.apiVersion) ||
      (actual.scope !== undefined && actual.scope !== e.scope) ||
      (actual.dependsOn !== undefined && !isDeepStrictEqual(actual.dependsOn, e.dependsOn)) ||
      (actual.name !== e.name && actual.name !== descriptor.id.split('/').at(-1))) fail('QUEUE_RESOURCE_DRIFT');
  if (e.tags) {
    assertOwned(actual, descriptor.id, c);
    if (!isDeepStrictEqual(actual.tags, e.tags) || !['australiaeast', 'Australia East'].includes(actual.location)) fail('QUEUE_RESOURCE_DRIFT');
  }
  if (e.type === 'Microsoft.Storage/storageAccounts') {
    only(p, [...Object.keys(e.properties), 'provisioningState', 'creationTime', 'primaryLocation', 'statusOfPrimary',
      'primaryEndpoints', 'privateEndpointConnections', 'accessTier', 'isHnsEnabled', 'isLocalUserEnabled',
      'isSftpEnabled', 'allowCrossTenantReplication', 'keyCreationTime']);
    only(actual.sku, ['name', 'tier']);
    if (actual.kind !== 'StorageV2' || actual.sku.name !== 'Standard_LRS' ||
        (actual.sku.tier !== undefined && actual.sku.tier !== 'Standard') ||
        (!whatIf && p.provisioningState !== 'Succeeded') ||
        (p.privateEndpointConnections !== undefined && !isDeepStrictEqual(p.privateEndpointConnections, [])) ||
        [p.isHnsEnabled, p.isLocalUserEnabled, p.isSftpEnabled, p.allowCrossTenantReplication].some(v => v !== undefined && v !== false) ||
        (p.accessTier !== undefined && p.accessTier !== 'Hot')) fail('QUEUE_RESOURCE_DRIFT');
    for (const [k, v] of Object.entries(e.properties)) {
      if (k === 'encryption') continue;
      if (!isDeepStrictEqual(p[k], v)) fail('QUEUE_RESOURCE_DRIFT');
    }
    only(p.encryption, ['keySource', 'services', 'requireInfrastructureEncryption']);
    if (p.encryption.keySource !== 'Microsoft.Storage' ||
        (p.encryption.requireInfrastructureEncryption !== undefined && typeof p.encryption.requireInfrastructureEncryption !== 'boolean')) fail('QUEUE_RESOURCE_DRIFT');
    only(p.encryption.services, ['queue', 'blob', 'file', 'table']);
    for (const [kind, encryption] of Object.entries(p.encryption.services)) {
      only(encryption, ['enabled', 'keyType', 'lastEnabledTime']);
      if (encryption.enabled !== true || !['Account', ...(kind === 'queue' ? [] : ['Service'])].includes(encryption.keyType)) fail('QUEUE_RESOURCE_DRIFT');
    }
    if (!p.encryption.services.queue || (!whatIf && p.primaryEndpoints?.queue !== `https://${topology.ids.accountName}.queue.core.windows.net/`)) fail('QUEUE_ENDPOINT_DRIFT');
    if (!whatIf && !Number.isFinite(Date.parse(p.creationTime))) fail('QUEUE_CREATION_IDENTITY_REQUIRED');
  } else if (e.type.endsWith('/queueServices')) {
    only(p, ['cors']);
    if (!isDeepStrictEqual(p, e.properties)) fail('QUEUE_CORS_DRIFT');
  } else if (e.type.endsWith('/queues')) {
    only(p, ['metadata', 'approximateMessageCount']);
    if (!isDeepStrictEqual(p.metadata, {}) ||
        (p.approximateMessageCount !== undefined && (!Number.isSafeInteger(p.approximateMessageCount) || p.approximateMessageCount < 0))) fail('QUEUE_METADATA_DRIFT');
  } else {
    only(p, [...Object.keys(e.properties), 'scope', 'createdOn', 'updatedOn', 'createdBy', 'updatedBy',
      ...(e.type.endsWith('/roleAssignments') ? ['condition', 'conditionVersion', 'delegatedManagedIdentityResourceId', 'description'] : [])]);
    for (const [key, value] of Object.entries(e.properties)) if (!isDeepStrictEqual(p[key], value)) fail('QUEUE_ROLE_SCOPE_DRIFT');
    if (e.type.endsWith('/roleAssignments') &&
        ((!whatIf && !sameId(p.scope, topology.ids.queue)) ||
          ['condition', 'conditionVersion', 'delegatedManagedIdentityResourceId', 'description'].some(k => p[k] !== undefined && p[k] !== null))) fail('QUEUE_ROLE_SCOPE_DRIFT');
    if (!whatIf && !Number.isFinite(Date.parse(p.createdOn))) fail('QUEUE_CREATION_IDENTITY_REQUIRED');
  }
  return actual;
}
export function verifyQueueWhatIf(c, phase, topology, result, preservedIds = []) {
  if (result?.status !== 'Succeeded' || !Array.isArray(result.changes)) fail('WHAT_IF_INCOMPLETE');
  const pending = new Map(phase.resources.map(v => [v.id.toLowerCase(), v])), seen = new Set();
  for (const change of result.changes) {
    const id = change.resourceId?.toLowerCase();
    if (!id || seen.has(id)) fail('WHAT_IF_ID_INVALID');
    seen.add(id);
    const descriptor = pending.get(id);
    if (!descriptor) {
      if (change.changeType !== 'Ignore' || !preservedIds.some(v => sameId(v, id))) fail('UNREVIEWED_RESOURCE_CHANGE');
      continue;
    }
    if (change.changeType !== 'Create' || (change.before !== undefined && change.before !== null) || !change.after) fail('EXPECTED_NEW_RESOURCE_ONLY');
    verifyQueueResource(c, topology, descriptor, change.after, true);
    pending.delete(id);
  }
  if (pending.size) fail('WHAT_IF_INCOMPLETE');
  return digest(json(result));
}
export function verifyQueuePrivacy(topology, privacy) {
  closed(privacy, ['diagnostics']);
  closed(privacy.diagnostics, [topology.ids.account, topology.ids.service]);
  for (const value of Object.values(privacy.diagnostics)) {
    if (!Array.isArray(value?.value) || value.nextLink || value.value.length) fail('QUEUE_DIAGNOSTIC_DRIFT');
  }
}
export function verifyQueueDrain(verification, observation) {
  closed(observation, ['version', 'kind', 'queueId', 'approximateMessageCount', 'observedAt']);
  if (verification?.version !== 1 || verification.acceptedStatus !== 202 ||
      verification.requiresOwnedLogsRows !== true || verification.requiresObservedApproximateDrain !== true ||
      verification.exactBacklogClaimed !== false || observation.version !== 1 ||
      observation.kind !== 'owned-arm-approximate-queue-count' || !sameId(observation.queueId, verification.queueId) ||
      !Number.isSafeInteger(observation.approximateMessageCount) || observation.approximateMessageCount < 0) fail('QUEUE_DRAIN_EVIDENCE_REQUIRED');
  canonicalInstant(observation.observedAt);
  return observation.approximateMessageCount === 0;
}

// An immutable record is required before the new account becomes known inventory.
// A "qualified" field alone never adopts a resource or changes historical receipts.
export function verifyQueueRecord(c, record) {
  closed(record, ['version', 'kind', 'topology', 'review', 'publication', 'identity', 'priorRecords', 'phase',
    'approval', 'preflight', 'providerOperations', 'whatIf', 'journal', 'receipt']);
  const { topology, phase, receipt, preflight, journal, approval, publication } = record;
  closed(publication, ['commitSha', 'sourceSha256']);
  if (record.version !== 1 || record.kind !== 'reviewed-queue-phase' || !sha(publication.sourceSha256) ||
      !/^[0-9a-f]{40}$/u.test(publication.commitSha ?? '')) fail('QUEUE_RECORD_INVALID');
  const at = canonicalInstant(journal.intentAt);
  verifyQueueReview(c, topology, record.review, publication.sourceSha256, at);
  if (!isDeepStrictEqual(phase, buildQueuePhase(c, phase.phase, topology, record.identity))) fail('QUEUE_PHASE_CHANGED');
  closed(record.priorRecords, phase.requiredReceipts);
  for (const [name, previous] of Object.entries(record.priorRecords)) {
    verifyQueueRecord(c, previous);
    if (previous.phase.phase !== name || !isDeepStrictEqual(previous.topology, topology) ||
        !isDeepStrictEqual(previous.identity, record.identity) || canonicalInstant(previous.receipt.completedAt) > at) fail('QUEUE_PREREQUISITE_CHANGED');
  }
  verifyApproval(approval, c, phase, publication.sourceSha256, at);
  verifyFreshReview(preflight, approval, preflight.startedAt, at);
  const operationsSha256 = verifyQueueProviderOperations(record.providerOperations);
  if (!isDeepStrictEqual(preflight.cost, durableQueueCost()) || preflight.providerOperationsSha256 !== operationsSha256 ||
      preflight.topologyReviewSha256 !== digest(json(record.review)) ||
      !Array.isArray(preflight.preservedIds) || preflight.preservedIds.some(v => typeof v !== 'string') ||
      preflight.baselineSha256 !== digest(json({ foundationBaselineSha256: preflight.foundationBaselineSha256,
        topologyReviewSha256: preflight.topologyReviewSha256, providerOperationsSha256: operationsSha256,
        preservedIdsSha256: digest(json(preflight.preservedIds)) })) ||
      approval.originSha256 !== c.originSha256 ||
      approval.whatIfSha256 !== digest(json(record.whatIf)) ||
      approval.receiptsSha256 !== digest(json(record.priorRecords)) ||
      journal.phaseSha256 !== digest(json(phase)) || journal.approvalSha256 !== digest(json(approval)) ||
      journal.outcome !== 'readback-qualified' || journal.transportDispatchAttempted !== true ||
      journal.receiptSha256 !== digest(json(receipt)) || receipt.qualified !== true || receipt.qualificationKind !== 'new-durable-queue-phase' ||
      receipt.phaseSha256 !== digest(json(phase)) || receipt.configSha256 !== digest(json(c)) ||
      receipt.topologySha256 !== digest(json(topology)) || receipt.sourceSha256 !== publication.sourceSha256 ||
      receipt.approvalSha256 !== digest(json(approval)) || receipt.ingestionEnabled !== false ||
      canonicalInstant(receipt.completedAt) < at || canonicalInstant(receipt.completedAt) > at + 120000 ||
      !sameId(receipt.deployment?.id, phase.deploymentId)) fail('QUEUE_RECORD_EXECUTION_INVALID');
  verifyDeploymentIdentity(receipt.deployment, receipt.deployment);
  verifyQueueWhatIf(c, phase, topology, record.whatIf, preflight.preservedIds);
  closed(receipt.resources, phase.resources.map(v => v.id));
  for (const d of phase.resources) verifyQueueResource(c, topology, d, receipt.resources[d.id]);
  if (phase.phase === 'queue-storage') {
    const created = Date.parse(receipt.resources[topology.ids.account].properties.creationTime);
    if (created < at || created > canonicalInstant(receipt.completedAt)) fail('QUEUE_CREATION_IDENTITY_REQUIRED');
  }
  verifyQueuePrivacy(topology, receipt.privacy);
  return receipt;
}
export function qualifiedQueueRecords(c, records, topology, through = 'queue-assignment') {
  const names = QUEUE_PHASES.slice(0, QUEUE_PHASES.indexOf(through) + 1);
  if (!names.length) fail('FIXED_QUEUE_PHASE_REQUIRED');
  closed(records, names);
  for (const name of names) {
    verifyQueueRecord(c, records[name]);
    if (records[name].phase.phase !== name || !isDeepStrictEqual(records[name].topology, topology) ||
        !isDeepStrictEqual(records[name].priorRecords, Object.fromEntries(names.slice(0, names.indexOf(name)).map(k => [k, records[k]])))) fail('QUEUE_RECORD_LINEAGE_CHANGED');
  }
  return Object.assign({}, ...names.map(name => records[name].receipt.resources));
}

export class QueueTopologyController {
  constructor(c, phase, topology, review, io) { Object.assign(this, { c, phase, topology, review, io }); }
  async execute(approval) {
    const { c, phase, topology, review, io } = this, source = await io.sourceDigest();
    if (!QUEUE_PHASES.includes(phase.phase) || phase.topologySha256 !== digest(json(topology))) fail('FIXED_QUEUE_PHASE_REQUIRED');
    verifyQueueReview(c, topology, review, source, io.now());
    verifyApproval(approval, c, phase, source, io.now());
    if (await io.loadJournal()) fail('QUEUE_INTENT_REPLAY_FORBIDDEN');
    const started = io.now(), proof = await io.check();
    const guard = deadline => {
      verifyQueueReview(c, topology, review, source, io.now());
      verifyApproval(approval, c, phase, source, io.now());
      verifyFreshReview(proof, approval, started, io.now());
      if (!isDeepStrictEqual(proof.cost, durableQueueCost()) || proof.topologyReviewSha256 !== digest(json(review))) fail('QUEUE_COST_REVIEW_REQUIRED');
      if (io.cancelled?.() || io.now() >= deadline) fail('QUEUE_OPERATION_DEADLINE');
    };
    const finalDeadline = Math.min(io.now() + 120000, canonicalInstant(approval.expiresAt), canonicalInstant(review.expiresAt));
    const current = async deadline => {
      guard(deadline);
      await io.verifyCurrent(deadline);
      if (await io.sourceDigest() !== source) fail('QUEUE_SOURCE_CHANGED');
      guard(deadline);
    };
    await current(finalDeadline);
    const at = io.now(), deadline = Math.min(at + 120000, canonicalInstant(approval.expiresAt),
      canonicalInstant(review.expiresAt), proof.startedAt + 300000);
    const journal = { phase: phase.phase, phaseSha256: digest(json(phase)), approvalSha256: digest(json(approval)),
      intentAt: new Date(at).toISOString(), outcome: 'submission-possible', transportDispatchAttempted: false };
    await io.saveJournal(journal);
    try {
      await io.arm('PUT', phase.deploymentId, '2022-09-01', {
        ...(phase.scope === ids(c).sub ? { location: c.location } : {}),
        properties: { mode: 'Incremental', template: phase.template },
      }, () => { guard(deadline); journal.transportDispatchAttempted = true; }, () => current(deadline), deadline);
      guard(deadline);
      for (let i = 0; i < 40; i++) {
        guard(deadline);
        const observation = await io.observe(deadline);
        guard(deadline);
        if (['Failed', 'Canceled'].includes(observation.deployment?.properties?.provisioningState)) fail('QUEUE_DEPLOYMENT_FAILED');
        if (observation.deployment?.properties?.provisioningState === 'Succeeded') {
          closed(observation, ['deployment', 'resources', 'privacy']);
          closed(observation.resources, phase.resources.map(d => d.id));
          if (!sameId(observation.deployment.id, phase.deploymentId)) fail('QUEUE_DEPLOYMENT_IDENTITY_CHANGED');
          verifyDeploymentIdentity(observation.deployment, observation.deployment);
          for (const d of phase.resources) verifyQueueResource(c, topology, d, observation.resources[d.id]);
          verifyQueuePrivacy(topology, observation.privacy);
          guard(deadline);
          const receipt = { qualified: true, qualificationKind: 'new-durable-queue-phase', phaseSha256: digest(json(phase)),
            configSha256: digest(json(c)), topologySha256: digest(json(topology)), sourceSha256: source,
            approvalSha256: digest(json(approval)), ...observation, ingestionEnabled: false, completedAt: new Date(io.now()).toISOString() };
          await io.saveReceipt(receipt);
          journal.outcome = 'readback-qualified'; journal.receiptSha256 = digest(json(receipt));
          await io.saveJournal(journal);
          return receipt;
        }
        await io.sleep(Math.min(3000, deadline - io.now()));
      }
      fail('QUEUE_ROLLOUT_UNRESOLVED');
    } catch (error) {
      journal.outcome = 'reconciliation-required';
      journal.failureCode = /^[A-Z_]+$/u.test(error.message) ? error.message : 'QUEUE_OPERATION_FAILED';
      await io.saveJournal(journal);
      fail('QUEUE_CHANGE_STOPPED_RESOURCES_PRESERVED');
    }
  }
}
