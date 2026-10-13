import { isDeepStrictEqual } from 'node:util';
import { closed, digest, fail, ids, json, sameId } from './definition.mjs';
import { canonicalInstant } from './policy.mjs';
import { boundedQueueAdoptionInput, queueArmInstant } from './queue-adoption.mjs';

export const QUEUE_DEFENDER_ASSURANCE = Object.freeze({
  kind: 'exact-observed-inherited-defender-preservation',
  historicalEmptyAclPreserved: true, configurationOnly: true,
  scannerFunctionalityProven: false, enforcedNspCompatibility: 'unverified',
  uninterruptedScanningProven: false, fullWireAttestation: false,
  uninterruptedTopicGenerationProven: false, effectiveGroupRbacEvaluated: false,
  securityChangesAuthorized: false, additionalPerimeterRulesAuthorized: false,
});
export const QUEUE_DEFENDER_ACTIVITY_LIMITS = Object.freeze({
  maxPages: 8, maxEvents: 1000, maxBytes: 8 * 1024 * 1024,
  requestDeadlineMs: 15000, collectionDeadlineMs: 120000,
});
const hash = value => digest(json(value));
const guid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(value);
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const equal = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
const serialization = 'Retained parsed ARM JSON serialized canonically; not raw HTTP byte attestation';
const snapshotFields = ['settings', 'topic', 'subscription', 'topics', 'subscriptions',
  'scanner', 'role', 'assignment', 'topicDiagnostics', 'settingsDiagnostics'];
const scannerRole = '0f641de8-0b88-4198-bdef-bd8b45ceba96';

function artifact(value) {
  closed(value, ['json', 'sha256']);
  if (typeof value.json !== 'string' || !sha(value.sha256) || digest(value.json) !== value.sha256) fail('QUEUE_DEFENDER_ARTIFACT_CHANGED');
  let parsed;
  try { parsed = JSON.parse(value.json); } catch { fail('QUEUE_DEFENDER_ARTIFACT_JSON_INVALID'); }
  boundedQueueAdoptionInput(parsed);
  if (json(parsed) !== value.json) fail('QUEUE_DEFENDER_CANONICAL_JSON_REQUIRED');
  return parsed;
}
function complete(value, maximum) {
  closed(value, ['value', ...(Object.hasOwn(value ?? {}, 'nextLink') ? ['nextLink'] : [])]);
  if (!Array.isArray(value.value) || value.value.length > maximum ||
      (value.nextLink !== undefined && value.nextLink !== null)) fail('QUEUE_DEFENDER_LIST_INCOMPLETE');
  return value.value;
}
function resource(value, id, type, fields) {
  closed(value, ['id', 'name', 'type', ...fields]);
  if (!sameId(value.id, id) || value.name !== id.split('/').at(-1) || !sameId(value.type, type)) fail('QUEUE_DEFENDER_RESOURCE_CHANGED');
}
export function queueDefenderRule(c) {
  return { tenantId: c.tenantId, resourceId: `${ids(c).sub}/providers/Microsoft.Security/datascanners/StorageDataScanner` };
}
function targets(c, origin, evidence) {
  const r = ids(c), q = origin.topology.ids, topic = evidence.snapshot.topic;
  if (typeof topic?.name !== 'string' || !topic.name.startsWith(`${q.accountName}-`) ||
      !guid(topic.name.slice(q.accountName.length + 1))) fail('QUEUE_DEFENDER_TOPIC_IDENTITY_REQUIRED');
  const topicId = `${r.group}/providers/Microsoft.EventGrid/systemTopics/${topic.name}`;
  return { topic: topicId, subscription: `${topicId}/eventSubscriptions/StorageAntimalwareSubscription`,
    settings: `${q.account}/providers/Microsoft.Security/defenderForStorageSettings/current`,
    scanner: `${r.sub}/providers/Microsoft.Security/pricings/StorageAccounts/securityOperators/DefenderForStorageSecurityOperator`,
    role: `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/${scannerRole}` };
}
function directoryActor(value, label) {
  closed(value, ['appId', 'appOwnerOrganizationId', 'displayName', 'id', 'servicePrincipalType']);
  if (![value.appId, value.appOwnerOrganizationId, value.id].every(guid) ||
      value.servicePrincipalType !== 'Application' || value.displayName !== label) fail('QUEUE_DEFENDER_ACTOR_INVALID');
}
function verifySnapshot(c, origin, evidence, value) {
  closed(value, snapshotFields);
  const t = targets(c, origin, evidence), q = origin.topology.ids, rule = queueDefenderRule(c);
  resource(value.settings, t.settings, 'Microsoft.Security/defenderForStorageSettings', ['properties']);
  equal(value.settings.properties, { dataScannerResourceId: rule.resourceId, isEnabled: true,
    malwareScanning: { blobScanResultsOptions: 'BlobIndexTags', onUpload: { capGBPerMonth: 10000, isEnabled: true } },
    overrideSubscriptionLevelSettings: false, sensitiveDataDiscovery: { isEnabled: true } }, 'QUEUE_DEFENDER_SETTINGS_CHANGED');
  resource(value.topic, t.topic, 'Microsoft.EventGrid/systemTopics', ['location', 'properties', 'systemData', 'tags']);
  closed(value.topic.properties, ['metricResourceId', 'provisioningState', 'source', 'topicType']);
  if (value.topic.location !== c.location || value.topic.tags !== null || value.topic.systemData !== null ||
      !guid(value.topic.properties.metricResourceId) || value.topic.properties.provisioningState !== 'Succeeded' ||
      !sameId(value.topic.properties.source, q.account) ||
      value.topic.properties.topicType !== 'microsoft.storage.storageaccounts') fail('QUEUE_DEFENDER_TOPIC_CHANGED');
  resource(value.subscription, t.subscription, 'Microsoft.EventGrid/systemTopics/eventSubscriptions', ['properties', 'systemData']);
  const p = value.subscription.properties;
  closed(p, ['destination', 'eventDeliverySchema', 'filter', 'labels', 'provisioningState', 'retryPolicy', 'topic']);
  closed(p.destination, ['endpointType', 'properties']);
  const d = p.destination.properties;
  closed(d, ['azureActiveDirectoryApplicationIdOrUri', 'azureActiveDirectoryTenantId',
    'endpointBaseUrl', 'endpointUrl', 'maxEventsPerBatch', 'preferredBatchSizeInKilobytes']);
  // AAD destination identifiers are independent review pins, not the customer tenant.
  if (value.subscription.systemData !== null || p.destination.endpointType !== 'WebHook' ||
      !guid(d.azureActiveDirectoryApplicationIdOrUri) || !guid(d.azureActiveDirectoryTenantId) ||
      d.azureActiveDirectoryTenantId === c.tenantId ||
      d.endpointBaseUrl !== `https://australiaeast.a3.storageav.azure.com:5142/EventCapture/${c.subscriptionId}/${q.accountName}` ||
      d.endpointUrl !== null || d.maxEventsPerBatch !== 1 || d.preferredBatchSizeInKilobytes !== 64 ||
      p.eventDeliverySchema !== 'EventGridSchema' || p.labels !== null ||
      p.provisioningState !== 'Succeeded' || !sameId(p.topic, t.topic)) fail('QUEUE_DEFENDER_DESTINATION_CHANGED');
  equal(p.filter, { advancedFilters: [{ key: 'data.blobType', operatorType: 'StringContains', values: ['BlockBlob'] }],
    includedEventTypes: ['Microsoft.Storage.BlobCreated', 'Microsoft.Storage.BlobRenamed'],
    subjectBeginsWith: '', subjectEndsWith: '' }, 'QUEUE_DEFENDER_FILTER_CHANGED');
  equal(p.retryPolicy, { eventTimeToLiveInMinutes: 1440, maxDeliveryAttempts: 30 }, 'QUEUE_DEFENDER_RETRY_CHANGED');
  equal(complete(value.topics, 1), [value.topic], 'QUEUE_DEFENDER_TOPIC_INVENTORY_CHANGED');
  equal(complete(value.subscriptions, 1), [value.subscription], 'QUEUE_DEFENDER_SUBSCRIPTION_INVENTORY_CHANGED');
  complete(value.topicDiagnostics, 0); complete(value.settingsDiagnostics, 0);
  const prior = evidence.priorScannerAdoption.evidence;
  resource(value.scanner, t.scanner, 'Microsoft.Security/pricings/securityOperators', ['identity']);
  closed(value.scanner.identity, ['principalId', 'tenantId']);
  if (!guid(value.scanner.identity.principalId) || value.scanner.identity.tenantId !== c.tenantId ||
      !sameId(value.role?.id, t.role) || value.role.properties?.type !== 'BuiltInRole' ||
      value.role.properties.roleName !== 'Defender for Storage Scanner Operator' ||
      !sameId(value.assignment?.properties?.scope, ids(c).sub) ||
      !sameId(value.assignment.properties.roleDefinitionId, t.role) ||
      value.assignment.properties.principalId !== value.scanner.identity.principalId ||
      value.assignment.properties.principalType !== 'ServicePrincipal' ||
      value.assignment.properties.condition !== null || value.assignment.properties.conditionVersion !== null ||
      value.assignment.properties.delegatedManagedIdentityResourceId !== null) fail('QUEUE_DEFENDER_SCANNER_AUTHORITY_CHANGED');
  equal(value.scanner, prior.actorResource, 'QUEUE_DEFENDER_SCANNER_IDENTITY_CHANGED');
  equal(value.role, prior.roleDefinition, 'QUEUE_DEFENDER_SCANNER_ROLE_CHANGED');
  equal(value.assignment, prior.roleAssignment, 'QUEUE_DEFENDER_SCANNER_ASSIGNMENT_CHANGED');
}
function projectEvent(value) {
  const claims = value.claims ?? {};
  return Object.fromEntries([
    ...['eventDataId', 'eventTimestamp', 'submissionTimestamp', 'correlationId', 'resourceId',
      'caller', 'operationName', 'status'].map(key => [key, value[key] ?? null]),
    ['claimAppId', claims.appid ?? null],
    ['claimTenant', claims['http://schemas.microsoft.com/identity/claims/tenantid'] ?? null],
    ['claimObjectId', claims['http://schemas.microsoft.com/identity/claims/objectidentifier'] ?? null],
    ['claimResourceId', claims.xms_mirid ?? null],
  ]);
}
function activity(c, origin, input, target, scopes) {
  closed(input, ['receipt', 'pages', 'projection']);
  const r = input.receipt;
  closed(r, ['version', 'method', 'targetResource', 'apiVersion', 'start', 'end', 'filter', 'startedAt', 'completedAt',
    ...Object.keys(QUEUE_DEFENDER_ACTIVITY_LIMITS), 'pages', 'terminalNextLink', 'paginationComplete', 'eventCount',
    'totalBytes', 'projectionSha256', 'serialization', 'cloudMutations']);
  const start = canonicalInstant(r.start), end = canonicalInstant(r.end);
  const collected = canonicalInstant(r.startedAt), completed = canonicalInstant(r.completedAt);
  if (r.version !== 1 || r.method !== 'GET' || r.apiVersion !== '2015-04-01' ||
      r.targetResource !== target || end <= start || end - start > 31 * 86400000 ||
      start > canonicalInstant(origin.firstReadback.checkedAt) || end < canonicalInstant(origin.firstReadback.checkedAt) ||
      collected < end || completed < collected || completed - collected >= 120000 ||
      collected - end > 300000 || r.terminalNextLink !== null || r.paginationComplete !== true ||
      r.serialization !== serialization || r.cloudMutations !== 0 ||
      Object.entries(QUEUE_DEFENDER_ACTIVITY_LIMITS).some(([key, expected]) => r[key] !== expected) ||
      !Array.isArray(r.pages) || !r.pages.length || r.pages.length > r.maxPages ||
      !Array.isArray(input.pages) || input.pages.length !== r.pages.length) fail('QUEUE_DEFENDER_ACTIVITY_INCOMPLETE');
  const filter = `eventTimestamp ge '${r.start}' and eventTimestamp le '${r.end}' and resourceUri eq '${target}'`;
  if (r.filter !== filter) fail('QUEUE_DEFENDER_ACTIVITY_SCOPE_CHANGED');
  const path = `https://management.azure.com${ids(c).sub}/providers/Microsoft.Insights/eventtypes/management/values`;
  const seenRequests = new Set(), seenEvents = new Set(), events = [];
  let next = null, bytes = 0;
  for (const [index, page] of r.pages.entries()) {
    closed(page, ['request', 'filename', 'canonicalResponseSha256', 'bytes']);
    let url;
    try { url = new URL(page.request); } catch { fail('QUEUE_DEFENDER_ACTIVITY_SCOPE_CHANGED'); }
    if (url.origin + url.pathname !== path || url.username || url.password || url.hash ||
        url.searchParams.getAll('api-version').length !== 1 || url.searchParams.get('api-version') !== r.apiVersion ||
        url.searchParams.getAll('$filter').length !== 1 || url.searchParams.get('$filter') !== filter ||
        [...url.searchParams.keys()].some(key => !['api-version', '$filter', '$skiptoken', '$skipToken'].includes(key)) ||
        [...url.searchParams.keys()].some(key => url.searchParams.getAll(key).length !== 1) ||
        (index === 0 ? url.searchParams.size !== 2 : page.request !== next) ||
        seenRequests.has(page.request) || typeof page.filename !== 'string' ||
        !/^complete-(?:account|topic)-activity-page-[1-8]\.json$/u.test(page.filename)) fail('QUEUE_DEFENDER_ACTIVITY_SCOPE_CHANGED');
    seenRequests.add(page.request);
    const value = artifact(input.pages[index]);
    if (page.canonicalResponseSha256 !== input.pages[index].sha256 ||
        page.bytes !== Buffer.byteLength(input.pages[index].json)) fail('QUEUE_DEFENDER_ACTIVITY_HASH_CHANGED');
    closed(value, ['value', ...(Object.hasOwn(value, 'nextLink') ? ['nextLink'] : [])]);
    if (!Array.isArray(value.value) || value.value.length > r.maxEvents) fail('QUEUE_DEFENDER_ACTIVITY_INCOMPLETE');
    next = value.nextLink ?? null;
    if (next !== null && (typeof next !== 'string' || !next)) fail('QUEUE_DEFENDER_ACTIVITY_INCOMPLETE');
    for (const raw of value.value) {
      const event = projectEvent(raw);
      if (!guid(event.eventDataId) || seenEvents.has(event.eventDataId) || !guid(event.correlationId) ||
          !scopes.some(scope => sameId(scope, event.resourceId)) ||
          queueArmInstant(event.eventTimestamp) < queueArmInstant(r.start) ||
          queueArmInstant(event.eventTimestamp) > queueArmInstant(r.end) ||
          queueArmInstant(event.submissionTimestamp) < queueArmInstant(event.eventTimestamp) ||
          queueArmInstant(event.submissionTimestamp) > queueArmInstant(r.completedAt)) fail('QUEUE_DEFENDER_ACTIVITY_EVENT_INVALID');
      seenEvents.add(event.eventDataId); events.push(event);
    }
    bytes += page.bytes;
    if (bytes > r.maxBytes || events.length > r.maxEvents ||
        (index === r.pages.length - 1 ? next !== null : next === null)) fail('QUEUE_DEFENDER_ACTIVITY_INCOMPLETE');
  }
  if (r.totalBytes !== bytes || r.eventCount !== events.length || r.projectionSha256 !== input.projection.sha256) fail('QUEUE_DEFENDER_ACTIVITY_HASH_CHANGED');
  equal(artifact(input.projection), { source: 'scoped-ARM-activity-pages', projection: 'allowlisted-attribution-fields', events },
    'QUEUE_DEFENDER_ACTIVITY_PROJECTION_CHANGED');
  return events;
}
function attributed(events, resourceId, operation, actor, tenant, actorResourceId, first) {
  const matching = events.filter(event => sameId(event.resourceId, resourceId) && sameId(event.operationName?.value, operation));
  if (!matching.some(event => event.status?.value === 'Succeeded')) fail('QUEUE_DEFENDER_ATTRIBUTION_REQUIRED');
  for (const event of matching) {
    if (event.caller !== actor.id || event.claimObjectId !== actor.id || event.claimAppId !== actor.appId ||
        event.claimTenant !== tenant || event.claimResourceId !== actorResourceId ||
        !['Started', 'Succeeded', 'Accepted'].includes(event.status?.value) ||
        queueArmInstant(event.eventTimestamp) < queueArmInstant(first)) fail('QUEUE_DEFENDER_ATTRIBUTION_CHANGED');
  }
}
export function verifyQueueDefenderEvidence(c, origin, evidence) {
  boundedQueueAdoptionInput(evidence);
  closed(evidence, ['version', 'kind', 'configSha256', 'originSha256', 'priorScannerAdoption', 'actors',
    'activity', 'snapshot', 'assurance']);
  if (evidence.version !== 1 || evidence.kind !== 'exact-inherited-queue-defender' ||
      evidence.configSha256 !== hash(c) || evidence.originSha256 !== hash(origin) ||
      hash(evidence.priorScannerAdoption) !== c.scannerAdoptionSha256 ||
      evidence.priorScannerAdoption.kind !== 'exact-storage-scanner-instance' ||
      evidence.priorScannerAdoption.originSha256 !== c.originSha256) fail('QUEUE_DEFENDER_PRIOR_BINDING_CHANGED');
  equal(evidence.assurance, QUEUE_DEFENDER_ASSURANCE, 'QUEUE_DEFENDER_ASSURANCE_CHANGED');
  closed(evidence.actors, ['topic', 'subscription']);
  directoryActor(evidence.actors.topic, 'Microsoft.EventGrid');
  directoryActor(evidence.actors.subscription, 'Microsoft Defender for Cloud Scanner Resource Provider');
  if (evidence.actors.topic.appOwnerOrganizationId !== evidence.actors.subscription.appOwnerOrganizationId ||
      evidence.actors.topic.appOwnerOrganizationId === c.tenantId ||
      evidence.actors.topic.id === evidence.actors.subscription.id ||
      evidence.actors.topic.appId === evidence.actors.subscription.appId) fail('QUEUE_DEFENDER_ACTOR_INVALID');
  verifySnapshot(c, origin, evidence, evidence.snapshot);
  const t = targets(c, origin, evidence), prior = evidence.priorScannerAdoption.evidence;
  if (!guid(prior.servicePrincipal?.id) || !guid(prior.servicePrincipal.appId) ||
      prior.servicePrincipal.servicePrincipalType !== 'ManagedIdentity' ||
      prior.servicePrincipal.id !== evidence.snapshot.scanner.identity.principalId ||
      [evidence.actors.topic.id, evidence.actors.subscription.id].includes(prior.servicePrincipal.id)) fail('QUEUE_DEFENDER_SCANNER_IDENTITY_CHANGED');
  closed(evidence.activity, ['account', 'topic']);
  const accountSubscription = `${origin.topology.ids.account}/providers/Microsoft.EventGrid/eventSubscriptions/StorageAntimalwareSubscription`;
  // These original/legacy targets are retained query history, not new current-state or actor trust.
  const account = activity(c, origin, evidence.activity.account, origin.topology.ids.account,
    [origin.topology.ids.account, origin.topology.ids.service, origin.topology.ids.queue, t.settings, accountSubscription,
      `${origin.topology.ids.account}/providers/Microsoft.Security/advancedThreatProtectionSettings/current`]);
  const topic = activity(c, origin, evidence.activity.topic, t.topic, [t.topic]);
  const accountEventIds = new Set(account.map(event => event.eventDataId));
  if (topic.some(event => accountEventIds.has(event.eventDataId))) fail('QUEUE_DEFENDER_ACTIVITY_EVENT_INVALID');
  for (const key of ['start', 'end']) if (evidence.activity.account.receipt[key] !== evidence.activity.topic.receipt[key]) fail('QUEUE_DEFENDER_ACTIVITY_WINDOW_CHANGED');
  for (const [resourceId, operation] of [[origin.topology.ids.account, 'Microsoft.Storage/storageAccounts/write'],
    [t.settings, 'Microsoft.Security/defenderForStorageSettings/write']]) {
    // The original user create precedes the later inherited scanner delta.
    attributed(account.filter(event => queueArmInstant(event.eventTimestamp) >= queueArmInstant(origin.firstReadback.checkedAt)),
      resourceId, operation, prior.servicePrincipal, c.tenantId, t.scanner, origin.firstReadback.checkedAt);
  }
  attributed(account, accountSubscription, 'Microsoft.EventGrid/eventSubscriptions/write',
    evidence.actors.subscription, c.tenantId, null, origin.firstReadback.checkedAt);
  attributed(topic, t.topic, 'Microsoft.EventGrid/systemTopics/write',
    evidence.actors.topic, c.tenantId, null, origin.firstReadback.checkedAt);
  return evidence;
}
export function queueDefenderReviewPins(c, origin, evidence) {
  verifyQueueDefenderEvidence(c, origin, evidence);
  return { evidenceSha256: hash(evidence), snapshotSha256: hash(evidence.snapshot),
    scannerAdoptionSha256: c.scannerAdoptionSha256,
    scannerPrincipalId: evidence.snapshot.scanner.identity.principalId,
    topicActor: structuredClone(evidence.actors.topic), subscriptionActor: structuredClone(evidence.actors.subscription),
    topicId: evidence.snapshot.topic.id, topicMetricResourceId: evidence.snapshot.topic.properties.metricResourceId,
    destination: structuredClone(evidence.snapshot.subscription.properties.destination),
    assurance: QUEUE_DEFENDER_ASSURANCE };
}
export function verifyQueueDefenderReview(c, origin, evidence, review) {
  closed(review, ['action', 'pins', 'userInstruction', 'userInstructionSha256']);
  if (review.action !== 'preserve-exact-inherited-queue-defender' ||
      typeof review.userInstruction !== 'string' || !review.userInstruction.trim() ||
      review.userInstruction.length > 4096 || digest(review.userInstruction) !== review.userInstructionSha256) fail('QUEUE_DEFENDER_EXACT_REVIEW_REQUIRED');
  equal(review.pins, queueDefenderReviewPins(c, origin, evidence), 'QUEUE_DEFENDER_REVIEW_PINS_CHANGED');
}
export function queueDefenderReadRequests(c, origin, evidence) {
  verifyQueueDefenderEvidence(c, origin, evidence);
  const t = targets(c, origin, evidence);
  const request = (id, apiVersion) => Object.freeze({ id, apiVersion, filter: null });
  return {
    settings: request(t.settings, '2025-06-01'), topic: request(t.topic, '2025-02-15'),
    subscription: request(t.subscription, '2025-02-15'),
    topics: request(`${ids(c).group}/providers/Microsoft.EventGrid/systemTopics`, '2025-02-15'),
    subscriptions: request(`${t.topic}/eventSubscriptions`, '2025-02-15'),
    scanner: request(t.scanner, '2023-01-01-preview'), role: request(t.role, '2022-04-01'),
    assignment: request(evidence.snapshot.assignment.id, '2022-04-01'),
    topicDiagnostics: request(`${t.topic}/providers/Microsoft.Insights/diagnosticSettings`, '2021-05-01-preview'),
    settingsDiagnostics: request(`${t.settings}/providers/Microsoft.Insights/diagnosticSettings`, '2021-05-01-preview'),
  };
}
export function verifyCurrentQueueDefender(c, origin, evidence, snapshot) {
  boundedQueueAdoptionInput(snapshot);
  verifySnapshot(c, origin, evidence, snapshot);
  equal(snapshot, evidence.snapshot, 'QUEUE_DEFENDER_CURRENT_STATE_CHANGED');
  return snapshot;
}
export async function collectQueueDefender(c, origin, evidence, io, deadline) {
  evidence = structuredClone(verifyQueueDefenderEvidence(c, origin, evidence));
  c = structuredClone(c); origin = structuredClone(origin);
  const requests = queueDefenderReadRequests(c, origin, evidence), snapshot = {};
  const start = io.now();
  const guard = () => {
    const now = io.now();
    if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(now) || now < start ||
        !Number.isSafeInteger(deadline) || deadline > start + 120000 || now >= deadline) fail('QUEUE_DEFENDER_READ_DEADLINE');
  };
  guard();
  for (const [key, request] of Object.entries(requests)) {
    guard();
    snapshot[key] = structuredClone(await io.read(request, deadline));
    boundedQueueAdoptionInput(snapshot[key]);
    guard();
  }
  return verifyCurrentQueueDefender(c, origin, evidence, snapshot);
}
export function queueDefenderInventory(c, origin, evidence, snapshot = evidence.snapshot) {
  verifyQueueDefenderEvidence(c, origin, evidence);
  verifyCurrentQueueDefender(c, origin, evidence, snapshot);
  return { [snapshot.topic.id]: snapshot.topic, [snapshot.subscription.id]: snapshot.subscription };
}
