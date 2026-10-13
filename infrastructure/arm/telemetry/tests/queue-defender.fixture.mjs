import assert from 'node:assert/strict';
import { digest, ids, json } from '../definition.mjs';
import { queueTopology } from '../durable-queue.mjs';
import { adoptQueueStorage, collectQueueAdoption } from '../queue-adoption.mjs';
import { QUEUE_DEFENDER_ASSURANCE, QUEUE_DEFENDER_ACTIVITY_LIMITS, queueDefenderReadRequests,
  queueDefenderReviewPins, queueDefenderRule } from '../queue-defender.mjs';
import { nspPreflightBaseline, nspState } from '../nsp.mjs';
import { baseFixture } from './durable-queue.fixture.mjs';
import { queueAdoptionFixture } from './queue-adoption.fixture.mjs';
import { nspPhaseFixture } from './nsp.fixture.mjs';

// Generated unit evidence only; no operator identity, approval or cloud receipt.
export const unitGuid = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const hash = value => digest(json(value));
const timestamp = at => new Date(at).toISOString();
export const unitArtifact = value => ({ json: json(value), sha256: hash(value) });
export function unitActivity(c, target, scopes, at, first, actor, actorResource) {
  const end = timestamp(at - 1000), start = timestamp(first - 1000);
  const events = scopes.map(([resourceId, operation], index) => ({
    eventDataId: unitGuid((target.includes('/systemTopics/') ? 150 : 100) + index), eventTimestamp: timestamp(first + 1000 + index),
    submissionTimestamp: timestamp(first + 2000 + index), correlationId: unitGuid(200),
    resourceId, caller: actor.id, operationName: { value: operation, localizedValue: 'UNIT operation' },
    status: { value: 'Succeeded', localizedValue: 'Succeeded' },
    claims: { appid: actor.appId, 'http://schemas.microsoft.com/identity/claims/tenantid': c.tenantId,
      'http://schemas.microsoft.com/identity/claims/objectidentifier': actor.id,
      ...(actorResource ? { xms_mirid: actorResource } : {}) },
  }));
  const projection = unitArtifact({ source: 'scoped-ARM-activity-pages', projection: 'allowlisted-attribution-fields',
    events: events.map(({ claims, ...event }) => ({ ...event, claimAppId: claims.appid,
      claimTenant: c.tenantId, claimObjectId: actor.id, claimResourceId: actorResource ?? null })) });
  const page = unitArtifact({ value: events });
  const filter = `eventTimestamp ge '${start}' and eventTimestamp le '${end}' and resourceUri eq '${target}'`;
  const params = new URLSearchParams({ 'api-version': '2015-04-01', '$filter': filter });
  return { receipt: { version: 1, method: 'GET', targetResource: target, apiVersion: '2015-04-01', start, end,
    filter, startedAt: timestamp(at - 999), completedAt: timestamp(at - 500), ...QUEUE_DEFENDER_ACTIVITY_LIMITS,
    pages: [{ request: `https://management.azure.com${ids(c).sub}/providers/Microsoft.Insights/eventtypes/management/values?${params}`,
      filename: 'complete-account-activity-page-1.json', canonicalResponseSha256: page.sha256, bytes: Buffer.byteLength(page.json) }],
    terminalNextLink: null, paginationComplete: true, eventCount: events.length, totalBytes: Buffer.byteLength(page.json),
    projectionSha256: projection.sha256,
    serialization: 'Retained parsed ARM JSON serialized canonically; not raw HTTP byte attestation', cloudMutations: 0 },
  pages: [page], projection };
}
export function rehashActivity(value, change) {
  const page = JSON.parse(value.pages[0].json), projection = JSON.parse(value.projection.json);
  change(page, projection);
  value.pages[0] = unitArtifact(page); value.projection = unitArtifact(projection);
  Object.assign(value.receipt.pages[0], { canonicalResponseSha256: value.pages[0].sha256, bytes: Buffer.byteLength(value.pages[0].json) });
  Object.assign(value.receipt, { projectionSha256: value.projection.sha256,
    totalBytes: Buffer.byteLength(value.pages[0].json), eventCount: page.value.length });
}
export async function queueDefenderFixture() {
  const base = baseFixture(), c = base.c, r = base.r;
  const scanner = { id: `${r.sub}/providers/Microsoft.Security/pricings/StorageAccounts/securityOperators/DefenderForStorageSecurityOperator`,
    name: 'DefenderForStorageSecurityOperator', type: 'Microsoft.Security/pricings/securityOperators',
    identity: { principalId: unitGuid(300), tenantId: c.tenantId } };
  const role = { id: `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/0f641de8-0b88-4198-bdef-bd8b45ceba96`,
    properties: { type: 'BuiltInRole', roleName: 'Defender for Storage Scanner Operator',
      permissions: [{ actions: ['Microsoft.Storage/storageAccounts/write', 'Microsoft.Security/defenderForStorageSettings/write'],
        dataActions: [], notActions: [], notDataActions: [] }], assignableScopes: ['/'] } };
  const assignment = { id: `${r.sub}/providers/Microsoft.Authorization/roleAssignments/${unitGuid(302)}`,
    properties: { scope: r.sub, roleDefinitionId: role.id, principalId: scanner.identity.principalId,
      principalType: 'ServicePrincipal', condition: null, conditionVersion: null, delegatedManagedIdentityResourceId: null } };
  const scannerPrincipal = { id: scanner.identity.principalId, appId: unitGuid(301), servicePrincipalType: 'ManagedIdentity' };
  const priorScannerAdoption = { version: 1, kind: 'exact-storage-scanner-instance', originSha256: c.originSha256,
    evidence: { actorResource: scanner, roleDefinition: role, roleAssignment: assignment, servicePrincipal: scannerPrincipal } };
  c.scannerAdoptionSha256 = hash(priorScannerAdoption);
  base.topology = queueTopology(c, base.topology.namespace);
  const f = await queueAdoptionFixture(base), q = f.topology.ids;
  const actor = (number, displayName) => ({ appId: unitGuid(number), appOwnerOrganizationId: unitGuid(900),
    displayName, id: unitGuid(number + 1), servicePrincipalType: 'Application' });
  const actors = { topic: actor(400, 'Microsoft.EventGrid'),
    subscription: actor(500, 'Microsoft Defender for Cloud Scanner Resource Provider') };
  const topicName = `${q.accountName}-${unitGuid(600)}`, topicId = `${r.group}/providers/Microsoft.EventGrid/systemTopics/${topicName}`;
  const topic = { id: topicId, name: topicName, type: 'Microsoft.EventGrid/systemTopics', location: c.location,
    tags: null, systemData: null, properties: { metricResourceId: unitGuid(601),
      provisioningState: 'Succeeded', source: q.account.toLowerCase(), topicType: 'microsoft.storage.storageaccounts' } };
  const settings = { id: `${q.account}/providers/Microsoft.Security/defenderForStorageSettings/current`, name: 'current',
    type: 'Microsoft.Security/defenderForStorageSettings', properties: { dataScannerResourceId: queueDefenderRule(c).resourceId,
      isEnabled: true, malwareScanning: { blobScanResultsOptions: 'BlobIndexTags', onUpload: { capGBPerMonth: 10000, isEnabled: true } },
      overrideSubscriptionLevelSettings: false, sensitiveDataDiscovery: { isEnabled: true } } };
  const subscription = { id: `${topicId}/eventSubscriptions/StorageAntimalwareSubscription`, name: 'StorageAntimalwareSubscription',
    type: 'Microsoft.EventGrid/systemTopics/eventSubscriptions', systemData: null, properties: {
      destination: { endpointType: 'WebHook', properties: { azureActiveDirectoryApplicationIdOrUri: unitGuid(700),
        azureActiveDirectoryTenantId: unitGuid(701),
        endpointBaseUrl: `https://australiaeast.a3.storageav.azure.com:5142/EventCapture/${c.subscriptionId}/${q.accountName}`,
        endpointUrl: null, maxEventsPerBatch: 1, preferredBatchSizeInKilobytes: 64 } },
      eventDeliverySchema: 'EventGridSchema', filter: { advancedFilters: [{ key: 'data.blobType', operatorType: 'StringContains', values: ['BlockBlob'] }],
        includedEventTypes: ['Microsoft.Storage.BlobCreated', 'Microsoft.Storage.BlobRenamed'], subjectBeginsWith: '', subjectEndsWith: '' },
      labels: null, provisioningState: 'Succeeded', retryPolicy: { eventTimeToLiveInMinutes: 1440, maxDeliveryAttempts: 30 }, topic: topicId } };
  const first = Date.parse(f.origin.firstReadback.checkedAt);
  const accountActivity = unitActivity(c, q.account, [[q.account, 'Microsoft.Storage/storageAccounts/write'],
    [settings.id, 'Microsoft.Security/defenderForStorageSettings/write']], f.at, first, scannerPrincipal, scanner.id);
  const subscriptionActivity = unitActivity(c, q.account, [[`${q.account}/providers/Microsoft.EventGrid/eventSubscriptions/StorageAntimalwareSubscription`,
    'Microsoft.EventGrid/eventSubscriptions/write']], f.at, first, actors.subscription, null);
  rehashActivity(accountActivity, (page, projection) => {
    const event = JSON.parse(subscriptionActivity.pages[0].json).value[0];
    const projected = JSON.parse(subscriptionActivity.projection.json).events[0];
    event.eventDataId = unitGuid(103); projected.eventDataId = unitGuid(103);
    page.value.push(event); projection.events.push(projected);
  });
  const evidence = { version: 1, kind: 'exact-inherited-queue-defender', configSha256: hash(c), originSha256: hash(f.origin),
    priorScannerAdoption, actors, activity: { account: accountActivity,
      topic: unitActivity(c, topicId, [[topicId, 'Microsoft.EventGrid/systemTopics/write']], f.at, first, actors.topic, null) },
    snapshot: { settings, topic, subscription, topics: { value: [structuredClone(topic)] },
      subscriptions: { value: [structuredClone(subscription)] }, scanner, role, assignment,
      topicDiagnostics: { value: [] }, settingsDiagnostics: { value: [] } }, assurance: QUEUE_DEFENDER_ASSURANCE };
  const responses = structuredClone(f.responses);
  responses[q.account].properties.networkAcls.resourceAccessRules = [queueDefenderRule(c)];
  const requests = queueDefenderReadRequests(c, f.origin, evidence);
  for (const [key, request] of Object.entries(requests)) responses[request.id] = structuredClone(evidence.snapshot[key]);
  let now = f.at, source = f.source;
  const reads = [], io = { now: () => now, sourceDigest: async () => source, read: async (request, deadline) => {
    assert.equal(Object.isFrozen(request), true);
    assert(deadline > now); assert(Object.hasOwn(responses, request.id), request.id);
    reads.push(structuredClone(request));
    return structuredClone(responses[request.id]);
  } };
  const proposal = await collectQueueAdoption(c, f.origin, io, evidence);
  const userInstruction = 'UNIT explicit reviewed preservation; not a human or cloud authorization.';
  const review = { ...f.review, version: 2, action: 'adopt-exact-observed-queue-storage-with-inherited-defender',
    proposalSha256: hash(proposal), defender: { action: 'preserve-exact-inherited-queue-defender',
      pins: queueDefenderReviewPins(c, f.origin, evidence), userInstruction, userInstructionSha256: digest(userInstruction) } };
  const adoption = adoptQueueStorage(c, proposal, f.origin, review, f.publication, now);
  return { ...f, evidence, proposal, review, adoption, io, responses, reads, requests,
    advance: ms => { now += ms; }, setSource: value => { source = value; } };
}
export function defenderNspPhaseFixture(f, evidence, name, instance = null) {
  const fixture = nspPhaseFixture(f, f.adoption, evidence, name, instance);
  for (const observation of [fixture.proof.observation, fixture.after]) {
    observation.version = 2; observation.defender = structuredClone(f.evidence.snapshot);
  }
  const userInstruction = 'UNIT proceed queue-only and accept disclosed Blob-scanner uncertainty and possible interruption.';
  fixture.proof.topologyReview.version = 2;
  fixture.proof.topologyReview.queueOnlyRisk = { action: 'accept-queue-only-nsp-with-unverified-blob-protection',
    currentStateSha256: hash(nspState(fixture.proof.observation)), userInstruction,
    userInstructionSha256: digest(userInstruction), functionalBlobProtectionQualified: false,
    blobUploadsAuthorized: false, explicitInterruptionRiskAccepted: true };
  fixture.proof.baselineSha256 = nspPreflightBaseline(fixture.proof);
  fixture.approval.baselineSha256 = fixture.proof.baselineSha256;
  return fixture;
}
