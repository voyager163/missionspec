import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { buildPhase, deploymentName, digest, ids, json, firstReleaseCost, PHASES, SYNTHETIC_FIXTURES } from '../definition.mjs';
import { buildQueuePhase, durableQueueCost, queueEnvironment, queueIds, queueTopology, QUEUE_AUTHORITY, QUEUE_PERMISSIONS,
  QUEUE_RUNTIME, verifyQueueReview, verifyQueueTopology, verifyQueueProviderOperations, verifyQueueResource, verifyQueueWhatIf,
  verifyQueueRecord, qualifiedQueueRecords, verifyQueueDrain, verifyOfficialQueuePrices, verifyQueueApiCatalog } from '../durable-queue.mjs';
import { QUEUE_BUILD_INPUTS, QUEUE_SOURCE_INPUTS, QUEUE_SDK_FIXTURES, RECEIVER_BUILD_INPUTS, RECEIVER_SOURCE_INPUTS, PREPARED_IDENTITY_RUNTIME,
  buildDisabledImagePhase, verifyReceiverCandidate, verifyReceiverProfile, verifyQueueEncodingProof,
  prepareReceiverPublication, verifyReceiverInventory, verifyDisabledImageRecord } from '../receiver-upgrade.mjs';
import { admissionFlag, verifyWhatIf, verifyWindowPredecessor, resourceContext } from '../policy.mjs';
import { emptyAcrReferrers, knownResourceIds, readPublishedImage, readQueueRecords, whatIfRequestContext, transport, verifyPublishedQueueRecords,
  buildSyntheticWindow, SyntheticWindowDriver, SyntheticDeadlines } from '../controller.mjs';
import { baseFixture, queuePhaseFixture, queueUpgradeFixture, imageRecordFixture } from './durable-queue.fixture.mjs';

test('queue cost preserves both-image base and every reserve; third digest requires separate reviewed profile', () => {
  const cost = durableQueueCost();
  assert.equal(firstReleaseCost(2).total, 311.23);
  assert.throws(() => firstReleaseCost(3), /NEW_DIGEST_COST_REVIEW_REQUIRED/);
  assert.deepEqual(cost.previous, firstReleaseCost(2));
  assert.deepEqual(cost.additions, { thirdImageInitialPlusDailyAndPullReserve: 9.57, additionalStorageSecurityReserve: 10,
    acceptedEventOperations: 6.2, conservativeIdleOperations: 2.14272, fiveGBStorage: 0.225, retryReserve: 10 });
  assert.equal(cost.unroundedTotal, 349.36772);
  assert.equal(cost.total, 349.37); assert.equal(cost.headroom, 0.63);
  assert.equal(cost.isHardCap, false); assert.equal(cost.exactBacklogOrSpendBoundClaimed, false);
  assert.equal(cost.previous.httpRequests.includesRejectedRequests, true);
  assert.deepEqual(PHASES.slice(0, 7), ['project-budget', 'core', 'workspace-access', 'data', 'upload-role', 'assignments', 'disabled-app']);
});

test('new namespace is explicit/bounded and topology binds config, queue URL, identity, runtime and TLS-only Entra account', () => {
  const f = baseFixture(), q = f.topology;
  verifyQueueTopology(f.c, q);
  assert.equal(q.ids.queueUrl, `https://${q.ids.accountName}.queue.core.windows.net/${q.ids.queueName}`);
  assert(q.ids.account.startsWith(ids(f.c).group + '/')); assert(!q.ids.account.includes('-state/'));
  assert.deepEqual(q.authority, QUEUE_AUTHORITY); assert.equal(q.queueCreatedBy, 'ARM-only');
  assert.deepEqual(queueEnvironment(q), { AZURE_QUEUE_URL: q.ids.queueUrl, AZURE_QUEUE_RESOURCE_ID: q.ids.queue });
  for (const namespace of ['*', '../state', 'UPPER123', 'x'.repeat(17), '', 'short', 'a-b-cdef']) {
    assert.throws(() => queueIds(f.c, namespace), /NAMESPACE/);
  }
  for (const mutate of [
    x => { x.configSha256 = digest('other collector run'); },
    x => { x.ids.queueUrl += '?sig=not-a-key'; }, x => { x.ids.queueUrl = x.ids.queueUrl.replace('https:', 'http:'); },
    x => { x.ids.queueUrl += '/'; }, x => { x.ids.queue = ids(f.c).stateGroup + '/account'; },
    x => { x.identity = ids(f.c).pullIdentity; }, x => { x.runtime.messageTtlSeconds = -1; },
    x => { x.runtime.storageTimeoutMs = 1001; }, x => { x.runtime.workerTimeoutMs = 20000; },
    x => { x.runtime.maxApproximateMessages = 10001; }, x => { x.runtime.producerScope = QUEUE_RUNTIME.consumerScope; },
    x => { x.authority.deployment = true; }, x => { x.environment.AZURE_STORAGE_CONNECTION_STRING = 'forbidden'; },
  ]) { const copy = structuredClone(q); mutate(copy); assert.throws(() => verifyQueueTopology(f.c, copy)); }
  const phase = buildQueuePhase(f.c, 'queue-storage', q), [account, service, queue] = phase.template.resources;
  assert.equal(account.kind, 'StorageV2'); assert.deepEqual(account.sku, { name: 'Standard_LRS' });
  assert.equal(account.properties.allowSharedKeyAccess, false); assert.equal(account.properties.allowBlobPublicAccess, false);
  assert.equal(account.properties.minimumTlsVersion, 'TLS1_2'); assert.equal(account.properties.supportsHttpsTrafficOnly, true);
  assert.equal(account.properties.publicNetworkAccess, 'Enabled');
  assert.deepEqual(service.properties.cors.corsRules, []); assert.deepEqual(queue.properties.metadata, {});
  assert.equal(JSON.stringify(phase).includes('Microsoft.Security'), false);
  assert.equal(JSON.stringify(phase).includes('listKeys'), false);
  assert.equal(phase.template.resources.filter(v => v.type.endsWith('/queues')).length, 1);
  assert.equal(q.runtime.messageEncoding, 'base64-json-v1');
  assert.equal(q.runtime.maxEncodedMessageBytes, 1024);
  assert.equal(q.runtime.maxPayloadBytes, 1024);
  assert.equal(q.runtime.canonicalBase64, true);
  assert.equal(q.runtime.plaintextFallback, false);
  assert.equal(Object.hasOwn(PREPARED_IDENTITY_RUNTIME, 'messageEncoding'), false);
  assert.equal(Object.hasOwn(q.runtime, 'messageCodec'), false);
  assert.equal(Object.hasOwn(q.runtime, 'maxDecodedMessageBytes'), false);
});

test('minimal official queue permissions classify metadata as Action, add and receive/delete as DataActions', () => {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-role');
  const permissions = q.phase.resources[0].expected.properties;
  assert.deepEqual(permissions.permissions, [QUEUE_PERMISSIONS]);
  assert.deepEqual(permissions.assignableScopes, [f.topology.ids.queue]);
  assert.equal(QUEUE_PERMISSIONS.actions.length, 1); assert.equal(QUEUE_PERMISSIONS.dataActions.length, 2);
  assert(!JSON.stringify(QUEUE_PERMISSIONS).includes('messages/delete'));
  assert(!JSON.stringify(QUEUE_PERMISSIONS).includes('messages/read'));
  assert(!JSON.stringify(QUEUE_PERMISSIONS).includes('messages/write'));
  assert(QUEUE_PERMISSIONS.dataActions.includes('Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action'));
  assert.equal(QUEUE_RUNTIME.visibilityUpdates, 0);
  assert(!JSON.stringify(QUEUE_PERMISSIONS).includes('queues/write'));
  const catalog = q.record().providerOperations;
  verifyQueueProviderOperations(catalog);
  const upper = structuredClone(catalog); upper.value.forEach(v => { v.name = v.name.toUpperCase(); });
  verifyQueueProviderOperations(upper);
  const repeated = structuredClone(catalog);
  repeated.value.push({ ...repeated.value[0], display: { provider: 'Microsoft Storage' } }, { ...repeated.value[0] });
  verifyQueueProviderOperations(repeated);
  for (const mutate of [x => x.value.pop(), x => { x.value[0].isDataAction = true; },
    x => { x.value[1].isDataAction = false; }, x => x.value.push({ ...x.value[0], isDataAction: true }), x => { x.nextLink = 'more'; }]) {
    const copy = structuredClone(catalog); mutate(copy); assert.throws(() => verifyQueueProviderOperations(copy));
  }
  const grant = buildQueuePhase(f.c, 'queue-assignment', f.topology, f.identity).resources[0];
  assert.equal(grant.expected.scope, f.topology.ids.queue); assert.equal(grant.expected.properties.principalId, f.identity.properties.principalId);
  assert.throws(() => buildQueuePhase(f.c, 'queue-assignment', f.topology), /IDENTITY_REQUIRED/);
});

test('Storage catalog may omit the documented queue child but cannot contradict its API version or parent registration', () => {
  const provider = { namespace: 'Microsoft.Storage', registrationState: 'Registered', resourceTypes: [
    { resourceType: 'storageAccounts', apiVersions: ['2025-01-01'] },
    { resourceType: 'storageAccounts/queueServices', apiVersions: ['2025-01-01'] },
  ] };
  verifyQueueApiCatalog(provider);
  verifyQueueApiCatalog({ ...provider, resourceTypes: [...provider.resourceTypes,
    { resourceType: 'storageAccounts/queueServices/queues', apiVersions: ['2025-01-01'] }] });
  for (const changed of [
    { ...provider, registrationState: 'NotRegistered' },
    { ...provider, resourceTypes: provider.resourceTypes.slice(0, 1) },
    { ...provider, resourceTypes: [{ ...provider.resourceTypes[0], apiVersions: [] }, provider.resourceTypes[1]] },
    { ...provider, resourceTypes: [...provider.resourceTypes,
      { resourceType: 'storageAccounts/queueServices/queues', apiVersions: ['2024-01-01'] }] },
  ]) assert.throws(() => verifyQueueApiCatalog(changed), /QUEUE_API_NOT_REGISTERED/);
});

test('unapproved topology, config swaps, expired/source-shifted review and namespace wildcards cannot authorize effects', async () => {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage');
  assert.throws(() => verifyQueueReview(f.c, f.topology, { qualified: true }, f.source, f.at));
  verifyQueueReview(f.c, f.topology, q.review, f.source, f.at);
  assert.throws(() => verifyQueueReview(f.c, f.topology, q.review, digest('changed'), f.at));
  assert.throws(() => verifyQueueReview(f.c, f.topology, q.review, f.source, f.at + 3600000));
  const changed = { ...f.c, runId: '00000000-0000-4000-8000-000000000044' };
  assert.throws(() => verifyQueueReview(changed, f.topology, q.review, f.source, f.at));
  assert.throws(() => knownResourceIds(f.c, { queueRecords: { 'queue-storage': { qualified: true } } }));
  const review = q.review; review.authority = { ...QUEUE_AUTHORITY, ingestion: true };
  await assert.rejects(q.controller.execute(q.approval)); assert.equal(q.dispatched, false);
});

test('queue what-if permits exact three-resource Create payloads and known Ignores only', () => {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage');
  verifyQueueWhatIf(f.c, q.phase, f.topology, q.whatIf);
  const known = structuredClone(q.whatIf); known.changes.push({ resourceId: f.r.app, changeType: 'Ignore' });
  verifyQueueWhatIf(f.c, q.phase, f.topology, known, [f.r.app]);
  for (const mutate of [
    x => { x.changes[0].changeType = 'Modify'; }, x => { x.changes[0].before = {}; },
    x => x.changes.pop(), x => x.changes.push({ resourceId: `${f.r.group}/providers/Microsoft.Compute/virtualMachines/other`, changeType: 'Ignore' }),
    x => { x.changes[0].after.properties.allowSharedKeyAccess = true; },
    x => { x.changes[0].after.properties.minimumTlsVersion = 'TLS1_0'; },
    x => { x.changes[0].after.properties.supportsHttpsTrafficOnly = false; },
    x => { x.changes[0].after.properties.networkAcls.bypass = 'AzureServices'; },
    x => { x.changes[0].after.properties.customDomain = { name: 'other' }; },
    x => { x.changes[0].after.sku.name = 'Standard_GRS'; },
    x => { x.changes[1].after.properties.cors.corsRules = [{ allowedOrigins: ['*'] }]; },
    x => { x.changes[2].after.properties.metadata = { ttl: 'forever' }; },
  ]) { const value = structuredClone(q.whatIf); mutate(value); assert.throws(() => verifyQueueWhatIf(f.c, q.phase, f.topology, value)); }
});

test('queue resource readback refuses secrets, TLS weakening, role expansion, foreign principal and missing endpoint/creation identity', async () => {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage');
  await q.controller.execute(q.approval); verifyQueueRecord(f.c, q.record());
  const d = q.phase.resources[0], actual = q.resources[d.id];
  verifyQueueResource(f.c, f.topology, d, actual);
  for (const mutate of [x => { delete x.properties.primaryEndpoints; }, x => { delete x.properties.creationTime; },
    x => { x.properties.allowBlobPublicAccess = true; }, x => { x.properties.encryption.keySource = 'Microsoft.Keyvault'; },
    x => { x.properties.primaryEndpoints.queue = 'https://other.queue.core.windows.net/'; }]) {
    const copy = structuredClone(actual); mutate(copy);
    assert.throws(() => verifyQueueResource(f.c, f.topology, d, copy));
  }
  const roles = queuePhaseFixture(f, 'queue-role');
  const rd = roles.phase.resources[0], role = roles.resources[rd.id];
  for (const mutate of [x => { x.properties.permissions[0].actions.push('*'); },
    x => { x.properties.assignableScopes = [f.r.group]; }, x => { x.properties.permissions[0].dataActions.push('Microsoft.Storage/storageAccounts/queueServices/queues/messages/delete'); }]) {
    const copy = structuredClone(role); mutate(copy); assert.throws(() => verifyQueueResource(f.c, f.topology, rd, copy));
  }
  const updates = structuredClone(role);
  updates.properties.permissions[0].dataActions[0] = 'Microsoft.Storage/storageAccounts/queueServices/queues/messages/write';
  assert.throws(() => verifyQueueResource(f.c, f.topology, rd, updates));
  const grant = queuePhaseFixture(f, 'queue-assignment'), gd = grant.phase.resources[0];
  for (const mutate of [x => { x.properties.principalId = f.c.operatorPrincipalId; }, x => { x.properties.scope = f.r.group; },
    x => { x.properties.roleDefinitionId = f.r.uploadRole; }, x => { x.properties.condition = 'bypass'; }]) {
    const copy = structuredClone(grant.resources[gd.id]); mutate(copy);
    assert.throws(() => verifyQueueResource(f.c, f.topology, gd, copy));
  }
});

test('queue controller anchors one durable intent, bounded final checks and 120s rollout without replay', async t => {
  for (const mode of ['success', 'late-check', 'late-body', 'unknown-write', 'late-read', 'provider-drift']) await t.test(mode, async () => {
    const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage');
    if (mode === 'late-check') q.io.verifyCurrent = async () => q.advance(120000);
    if (mode === 'late-body') q.io.arm = async (_method, _id, _api, _body, guard) => { q.advance(120000); guard(); };
    if (mode === 'unknown-write') q.io.arm = async (_method, _id, _api, _body, guard) => { guard(); throw new Error('UNKNOWN'); };
    if (mode === 'provider-drift') q.io.verifyCurrent = async () => { throw new Error('QUEUE_PROVIDER_PERMISSION_MISMATCH'); };
    if (mode === 'late-read') {
      const original = q.io.observe;
      q.io.observe = async () => { q.advance(120000); return original(); };
    }
    if (mode === 'success') {
      await q.controller.execute(q.approval);
      verifyQueueRecord(f.c, q.record());
      await assert.rejects(q.controller.execute(q.approval), /REPLAY_FORBIDDEN/);
      assert.equal(q.record().journal.transportDispatchAttempted, true);
    } else {
      await assert.rejects(q.controller.execute(q.approval));
      assert.equal(q.record().receipt, null);
    }
  });
});

test('three-image admission preserves old candidate/publication tags and requires queue-specific typed SDK/source qualification', async t => {
  const f = await queueUpgradeFixture(), original = json(f.priorCandidate);
  verifyReceiverCandidate(f.c, f.candidate); assert.equal(json(f.candidate.priorCandidate), original);
  assert.equal(RECEIVER_SOURCE_INPUTS.length, 35); assert.equal(QUEUE_SOURCE_INPUTS.length, 40);
  assert.equal(RECEIVER_BUILD_INPUTS.length, 9); assert.equal(QUEUE_BUILD_INPUTS.length, 11);
  const pending = structuredClone(f.candidate); pending.publication = null;
  const preview = prepareReceiverPublication(f.c, pending, f.priorCandidate.publication, f.at);
  assert.equal(preview.recentDigestCount, 3); assert.equal(preview.pushExecuted, false); assert.equal(preview.cost.total, 349.37);
  for (const [label, mutate] of [
    ['bare qualified profile', x => { x.profile = { qualified: true }; }],
    ['legacy closure', x => { delete x.profile.source.files['services/telemetry-ingest/src/queue-storage.ts']; }],
    ['external license manifest missing', x => { delete x.profile.source.files['licenses/external-service-licenses.json']; }],
    ['external license text missing', x => { delete x.profile.source.files['licenses/external/nodable-entities-2.1.0/LICENSE.md']; }],
    ['external license text hash changed', x => { x.profile.source.files['licenses/external/nodable-entities-2.1.0/LICENSE.md'] = digest('other license'); }],
    ['unbound SDK source', x => { const p = JSON.parse(x.profile.qualification.reportJson); p.durableQueue.sdkSourceManifestSha256 = digest('other'); x.profile.qualification.reportJson = json(p); x.profile.qualification.reportSha256 = digest(json(p)); }],
    ['missing typed fixture counts', x => { const p = JSON.parse(x.profile.qualification.reportJson); delete p.durableQueue.fixtures['single-worker'].failed; x.profile.qualification.reportJson = json(p); x.profile.qualification.reportSha256 = digest(json(p)); }],
    ['direct approval for queue profile', x => { x.version = 1; }],
    ['old manifest erased', x => x.publication.manifests.shift()],
    ['fourth manifest', x => x.publication.manifests.push({ digest: 'sha256:' + 'f'.repeat(64), tags: ['extra'] })],
    ['retag prepared image', x => { x.publication.manifests[1].tags = ['latest']; }],
    ['extra referrer', x => x.publication.referrers.push({ digest: 'sha256:' + 'f'.repeat(64) })],
    ['old cost reused', x => { x.review.cost = firstReleaseCost(2); }],
    ['changed old source', x => { x.priorCandidate.review.sourceSha256 = digest('other'); }],
  ]) await t.test(label, () => { const copy = structuredClone(f.candidate); mutate(copy); assert.throws(() => verifyReceiverCandidate(f.c, copy)); });
});

function encodingFixture(record = { ...SYNTHETIC_FIXTURES[0], TimeGenerated: '2026-09-23T08:10:00.000Z' }) {
  const decodedJson = JSON.stringify(record), encodedMessage = Buffer.from(decodedJson, 'utf8').toString('base64');
  return { version: 1, kind: 'base64-json-v1', encodedMessage, decodedJson,
    encodedBytes: Buffer.byteLength(encodedMessage, 'utf8'), decodedBytes: Buffer.byteLength(decodedJson, 'utf8') };
}

test('queued encoding proof binds canonical Base64 and exact compact unchanged nine-field UTF-8 JSON', () => {
  const proof = encodingFixture();
  verifyQueueEncodingProof(proof);
  const record = JSON.parse(proof.decodedJson); record.durationBucket = null;
  verifyQueueEncodingProof(encodingFixture(record));
  assert.equal(Object.keys(record).length, 9);
  assert(!Object.hasOwn(record, 'messageEncoding'));
  assert.deepEqual(JSON.parse(Buffer.from(proof.encodedMessage, 'base64').toString('utf8')), JSON.parse(proof.decodedJson));
  assert(proof.encodedBytes <= 1024 && proof.decodedBytes <= 1024);
  assert.equal(QUEUE_SDK_FIXTURES.length, 15);
});

test('Base64 qualification rejects plaintext fallback, noncanonical wire, invalid UTF-8, size/count and analytics drift', async t => {
  for (const [name, mutate] of [
    ['plaintext', x => { x.encodedMessage = x.decodedJson; x.encodedBytes = Buffer.byteLength(x.encodedMessage); }],
    ['whitespace', x => { x.encodedMessage += '\n'; x.encodedBytes++; }],
    ['base64url alphabet', x => { x.encodedMessage = '-' + x.encodedMessage.slice(1); }],
    ['wire byte count', x => { x.encodedBytes++; }],
    ['JSON byte count', x => { x.decodedBytes++; }],
    ['encoded ceiling', x => { x.encodedMessage = 'A'.repeat(1028); x.encodedBytes = 1028; }],
    ['decoded ceiling', x => { x.decodedJson = 'A'.repeat(1025); x.decodedBytes = 1025; }],
    ['different decoded bytes', x => { x.decodedJson = x.decodedJson.replace('draft', 'wrong'); }],
    ['invalid UTF8', x => {
      const bytes = Buffer.from(x.decodedJson); bytes[bytes.indexOf('draft')] = 255;
      x.encodedMessage = bytes.toString('base64'); x.encodedBytes = x.encodedMessage.length;
      x.decodedJson = bytes.toString('utf8'); x.decodedBytes = Buffer.byteLength(x.decodedJson);
    }],
    ['not compact', x => {
      x.decodedJson = JSON.stringify(JSON.parse(x.decodedJson), null, 2);
      x.encodedMessage = Buffer.from(x.decodedJson).toString('base64');
      x.encodedBytes = x.encodedMessage.length; x.decodedBytes = Buffer.byteLength(x.decodedJson);
    }],
    ['extra analytics marker', x => Object.assign(x, encodingFixture({ ...JSON.parse(x.decodedJson), messageEncoding: 'base64-json-v1' }))],
    ['invalid analytics enum', x => Object.assign(x, encodingFixture({ ...JSON.parse(x.decodedJson), operation: 'unknown-command' }))],
    ['wrong kind', x => { x.kind = 'plaintext-json-v1'; }],
  ]) await t.test(name, () => {
    const proof = encodingFixture(); mutate(proof);
    assert.throws(() => verifyQueueEncodingProof(proof));
  });
  const padded = ['0.0.0', '0.0.10', '0.0.100'].map(cliVersion =>
    encodingFixture({ ...SYNTHETIC_FIXTURES[0], cliVersion, TimeGenerated: '2026-09-23T08:10:00.000Z' }))
    .find(v => v.encodedMessage.endsWith('=='));
  assert(padded);
  const unpadded = { ...padded, encodedMessage: padded.encodedMessage.replace(/=+$/u, '') };
  unpadded.encodedBytes = unpadded.encodedMessage.length;
  assert.throws(() => verifyQueueEncodingProof(unpadded), /QUEUE_BASE64_PROOF_INVALID/);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const index = padded.encodedMessage.length - 3;
  const nonzeroPadding = { ...padded, encodedMessage: padded.encodedMessage.slice(0, index) +
    alphabet[alphabet.indexOf(padded.encodedMessage[index]) + 1] + '==' };
  assert.throws(() => verifyQueueEncodingProof(nonzeroPadding), /QUEUE_BASE64_PROOF_INVALID/);
});

test('new queued profile requires measured codec sample and all four codec report groups; old profiles stay unchanged', async () => {
  const f = await queueUpgradeFixture();
  const oldProfileBytes = json(f.priorCandidate.profile);
  verifyReceiverProfile(f.priorCandidate.profile);
  for (const path of ['licenses/external-service-licenses.json', 'licenses/external/nodable-entities-2.1.0/LICENSE.md']) {
    assert(QUEUE_BUILD_INPUTS.includes(path)); assert(QUEUE_SOURCE_INPUTS.includes(path));
    assert(!RECEIVER_BUILD_INPUTS.includes(path)); assert(!RECEIVER_SOURCE_INPUTS.includes(path));
    assert.equal(Object.hasOwn(f.priorCandidate.profile.source.files, path), false);
  }
  for (const field of ['messageEncoding', 'maxEncodedMessageBytes', 'maxPayloadBytes', 'canonicalBase64', 'plaintextFallback']) {
    const profile = structuredClone(f.candidate.profile); delete profile.runtime[field];
    assert.throws(() => verifyReceiverProfile(profile), /RECEIVER_PROFILE_INVALID/);
  }
  const alias = structuredClone(f.candidate.profile);
  alias.runtime.messageCodec = alias.runtime.messageEncoding; delete alias.runtime.messageEncoding;
  assert.throws(() => verifyReceiverProfile(alias), /RECEIVER_PROFILE_INVALID/);
  for (const name of ['encoding', ...QUEUE_SDK_FIXTURES.slice(11)]) {
    const profile = structuredClone(f.candidate.profile), report = JSON.parse(profile.qualification.reportJson);
    if (name === 'encoding') delete report.durableQueue.encoding;
    else delete report.durableQueue.fixtures[name];
    profile.qualification.reportJson = json(report); profile.qualification.reportSha256 = digest(profile.qualification.reportJson);
    assert.throws(() => verifyReceiverProfile(profile));
  }
  const profile = structuredClone(f.candidate.profile), report = JSON.parse(profile.qualification.reportJson);
  report.durableQueue.encoding.encodedMessage = report.durableQueue.encoding.decodedJson;
  report.durableQueue.encoding.encodedBytes = Buffer.byteLength(report.durableQueue.encoding.encodedMessage);
  profile.qualification.reportJson = json(report); profile.qualification.reportSha256 = digest(profile.qualification.reportJson);
  assert.throws(() => verifyReceiverProfile(profile), /QUEUE_BASE64_PROOF_INVALID/);
  const vulnerable = structuredClone(f.candidate.profile), scan = JSON.parse(vulnerable.scan.reportJson);
  scan.Results[0].Vulnerabilities[0].VulnerabilityID = 'CVE-2026-41650';
  vulnerable.scan.reportJson = json(scan); vulnerable.scan.reportSha256 = digest(vulnerable.scan.reportJson);
  assert.throws(() => verifyReceiverProfile(vulnerable), /QUEUE_XML_PATCH_REQUIRED/);
  assert.equal(json(f.priorCandidate.profile), oldProfileBytes);
});

test('third-image registry reader checks all three full manifests/referrers and rejects unknown images', async () => {
  const f = await queueUpgradeFixture(), calls = [];
  const arm = async () => ({ id: f.r.registry, tags: ownerTagsFor(f), properties: {
    adminUserEnabled: false, anonymousPullEnabled: false, loginServer: `${f.c.registryName}.azurecr.io`,
  } });
  const invoke = async args => {
    calls.push(args);
    if (args[1] === 'repository') return ['missionspec/telemetry-ingest'];
    if (args[2] === 'list-metadata') return f.candidate.publication.manifests;
    if (args[2] === 'list-referrers') return { manifests: [] };
    const name = args[args.indexOf('--name') + 1];
    const profile = [f.candidate.profile, f.priorCandidate.profile].find(p => name.endsWith(p.manifestDigest));
    return JSON.parse(profile?.manifestJson ?? f.candidate.legacyPublication.manifestJson);
  };
  const read = await readPublishedImage(f.c, f.candidate.legacyPublication, arm, invoke, f.candidate);
  assert.equal(read.manifests.length, 3); assert.equal(calls.filter(v => v[2] === 'list-referrers').length, 3);
  assert.deepEqual(emptyAcrReferrers({ manifests: [] }), []);
  const bad = structuredClone(read); bad.manifests.push({ digest: 'sha256:' + 'e'.repeat(64), tags: [] });
  assert.throws(() => verifyReceiverInventory(f.c, f.candidate, bad, true));
});
function ownerTagsFor(f) { return f.receipts.core.resources[f.r.registry].tags; }

test('qualified queue records alone adopt account inventory; all prior phases, ownership and fresh role reads remain exact', async () => {
  const f = await queueUpgradeFixture();
  assert(knownResourceIds(f.c, f.receipts).includes(f.topology.ids.account));
  assert(!knownResourceIds(f.c, { ...f.receipts, queueRecords: {} }).includes(f.topology.ids.account));
  assert(!knownResourceIds(f.c, { core: { resources: { [f.topology.ids.account]: { qualified: true } } } }).includes(f.topology.ids.account));
  assert.equal(Object.keys(qualifiedQueueRecords(f.c, f.records, f.topology)).length, 5);
  const catalog = new Map();
  for (const record of Object.values(f.records)) {
    catalog.set(record.phase.deploymentId, record.receipt.deployment);
    for (const [id, value] of Object.entries(record.receipt.resources)) catalog.set(id, value);
  }
  catalog.set(`${f.topology.ids.service}/queues`, { value: [{ id: f.topology.ids.queue }] });
  for (const id of [f.topology.ids.account, f.topology.ids.service]) catalog.set(`${id}/providers/Microsoft.Insights/diagnosticSettings`, { value: [] });
  await readQueueRecords(f.c, f.topology, f.records, async (_method, id) => catalog.get(id));
  const role = structuredClone(catalog.get(f.topology.ids.role)); role.properties.permissions[0].dataActions.push('*');
  catalog.set(f.topology.ids.role, role);
  await assert.rejects(readQueueRecords(f.c, f.topology, f.records, async (_method, id) => catalog.get(id)), /ROLE_SCOPE_DRIFT/);
  const changed = structuredClone(f.records); changed['queue-storage'].receipt.resources[f.topology.ids.account].properties.creationTime = '2026-09-22T00:00:00.000Z';
  assert.throws(() => qualifiedQueueRecords(f.c, changed, f.topology));
});

test('new disabled queue upgrade starts from failed prepared-identity window without changing false flag or prior history', async () => {
  const f = await queueUpgradeFixture(), history = json(f.predecessor), cBefore = json(f.c);
  const record = await imageRecordFixture(f, f.candidate, f.predecessor, 'disabled-queue-upgrade', '00000000-0000-4000-8000-000000000096');
  verifyDisabledImageRecord(f.c, record); assert.equal(json(f.predecessor), history); assert.equal(json(f.c), cBefore);
  assert.equal(record.predecessor.run.outcome, 'stopped-disabled');
  assert.equal(admissionFlag(record.receipt.resources[f.r.app]), 'false');
  assert.equal(record.phase.transition.fromDigest, f.priorCandidate.profile.manifestDigest);
  assert.equal(record.phase.transition.toDigest, f.candidate.profile.manifestDigest);
  const instance = record.phase.windowInstance;
  assert.equal(whatIfRequestContext(f.c, record.phase).windowInstanceId, instance.id);
  assert.equal(record.phase.deploymentId.split('/').at(-1), deploymentName(f.c, 'disabled-queue-upgrade', instance));
  for (const mutate of [x => { x.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; },
    x => { x.properties.template.containers[0].env.push({ name: 'NODE_OPTIONS', value: '--inspect' }); },
    x => { x.properties.template.containers[0].env.find(v => v.name === 'AZURE_QUEUE_URL').value += '?sig=x'; },
    x => { x.properties.configuration.identitySettings[0].lifecycle = 'All'; }]) {
    const whatIf = structuredClone(record.whatIf); mutate(whatIf.changes[0].after);
    assert.throws(() => verifyWhatIf(record.phase, whatIf, [], { config: f.c, ...resourceContext(f.c, f.receipts),
      receiverCandidate: f.candidate, app: f.predecessor.readback.app }));
  }
  const receipts = { ...f.receipts, receiverUpgrade: record };
  const phase = buildPhase(f.c, 'synthetic-admission', null, receipts, undefined, undefined, {
    version: 1, id: '00000000-0000-4000-8000-000000000095', predecessorSha256: digest(json(record)),
    previousInstanceIds: [...instance.previousInstanceIds, instance.id],
  });
  assert.equal(phase.queueVerification.acceptedStatus, 202);
  assert.equal(phase.queueVerification.requiresOwnedLogsRows, true);
  assert.equal(phase.queueVerification.exactBacklogClaimed, false);
  const noQueue = { ...f.receipts }; delete noQueue.queueRecords;
  assert.throws(() => buildDisabledImagePhase(f.c, 'disabled-queue-upgrade', noQueue, f.candidate, f.predecessor, instance));
});

test('queue ACK and approximate drain cannot imply Logs persistence or default missing count to zero', () => {
  const f = baseFixture(), verification = { version: 1, queueId: f.topology.ids.queue, acceptedStatus: 202,
    requiresOwnedLogsRows: true, requiresObservedApproximateDrain: true, exactBacklogClaimed: false };
  const observation = { version: 1, kind: 'owned-arm-approximate-queue-count', queueId: f.topology.ids.queue,
    approximateMessageCount: 0, observedAt: new Date(f.at).toISOString() };
  assert.equal(verifyQueueDrain(verification, observation), true);
  assert.equal(verifyQueueDrain(verification, { ...observation, approximateMessageCount: 1 }), false);
  for (const count of [undefined, null, -1, '0', NaN, 0.5]) assert.throws(() => verifyQueueDrain(verification,
    { ...observation, approximateMessageCount: count }));
  assert.throws(() => verifyQueueDrain(verification, { ...observation, queueId: f.topology.ids.queue + '-other' }));
});

test('queued synthetic driver requires 202 plus owned Logs rows plus observed drain, always returning to disabled', async t => {
  const f = await queueUpgradeFixture();
  const record = await imageRecordFixture(f, f.candidate, f.predecessor, 'disabled-queue-upgrade', '00000000-0000-4000-8000-000000000096');
  const receipts = { ...f.receipts, receiverUpgrade: record };
  const instance = { version: 1, id: '00000000-0000-4000-8000-000000000095',
    predecessorSha256: digest(json(record)), previousInstanceIds: [...record.phase.windowInstance.previousInstanceIds, record.phase.windowInstance.id] };
  const phases = Object.fromEntries(['synthetic-admission', 'synthetic-disable'].map(name =>
    [name, buildPhase(f.c, name, null, receipts, undefined, undefined, instance)]));
  const anchor = record.receipt.resources[f.r.app];
  const whatifs = { 'synthetic-admission': { status: 'Succeeded', changes: [{ resourceId: f.r.app, changeType: 'Modify',
    before: anchor, after: { ...structuredClone(phases['synthetic-admission'].resources[0].expected), id: f.r.app } }] },
  'synthetic-disable': { status: 'Succeeded', changes: [{ resourceId: f.r.app, changeType: 'NoChange' }] } };
  const window = buildSyntheticWindow(f.c, phases, receipts, f.origin, f.source, whatifs);
  for (const mode of ['complete', 'direct-204', 'no-logs', 'missing-count', 'not-drained']) await t.test(mode, async () => {
    let now = f.at + 1000, enabled = false, enableJournal;
    const approvals = Object.fromEntries(Object.entries(phases).map(([name, phase]) => [name, {
      version: 2, windowInstanceId: instance.id, predecessorSha256: instance.predecessorSha256,
      action: `synthetic-window-${name}`, windowSha256: digest(json(window)), phaseSha256: digest(json(phase)),
      configSha256: digest(json(f.c)), sourceSha256: f.source, originSha256: window.originSha256, receiptsSha256: window.receiptsSha256,
      baselineSha256: window.baselineSha256, reviewedWhatIfSha256: window.phases[name].reviewedWhatIfSha256,
      transitionSha256: window.phases[name].transitionSha256, approvedAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 1800000).toISOString(),
    }]));
    const io = { now: () => now, sourceDigest: async () => f.source, sleep: async ms => { now += ms; },
      setTimer: () => ({}), clearTimer: () => {}, loadRun: async () => null, saveRun: async () => {},
      http: async (method, _path, _fixture, guard) => {
        guard(); now += 20;
        return { status: method === 'POST' ? enabled ? mode === 'direct-204' ? 204 : 202 : 503 : 204,
          bodyBytes: 0, tlsVerified: true, errorCode: null, durationMs: 20, headerPolicy: { noStore: true } };
      },
      query: async (start, _end, guard, _deadline, dispatched) => {
        guard(); dispatched();
        const names = ['TimeGenerated', 'schemaVersion', 'event', 'operation', 'cliVersion', 'outcome', 'host', 'os', 'durationBucket'];
        return { tables: [{ columns: names.map((name, i) => ({ name, type: i === 0 ? 'datetime' : i === 1 ? 'long' : 'string' })),
          rows: mode === 'no-logs' ? [] : SYNTHETIC_FIXTURES.map(v => [new Date(Date.parse(start) + 1).toISOString(), ...names.slice(1).map(name => v[name])]) }] };
      },
      queueDrain: async guard => {
        guard();
        return { version: 1, kind: 'owned-arm-approximate-queue-count', queueId: f.topology.ids.queue,
          approximateMessageCount: mode === 'missing-count' ? undefined : mode === 'not-drained' ? 1 : 0, observedAt: new Date(now).toISOString() };
      },
    };
    const deadlines = new SyntheticDeadlines(window, approvals, io);
    const toggle = { deadlines, io: { loadJournal: async () => enableJournal }, ready: async () => {},
      execute: async name => {
        enabled = name === 'synthetic-admission';
        if (enabled) enableJournal = { phase: name, windowSha256: digest(json(window)), phaseSha256: digest(json(phases[name])),
          approvalSha256: digest(json(approvals[name])), windowInstanceId: instance.id, predecessorSha256: instance.predecessorSha256,
          intentAt: new Date(now).toISOString() };
        else deadlines.terminalFalse();
        return { qualified: true, resources: { [f.r.app]: anchor }, operationDeadline: now + 120000 };
      } };
    const run = await new SyntheticWindowDriver(f.c, phases, window, approvals, toggle, io).run();
    assert.equal(run.outcome, mode === 'complete' ? 'qualified-and-disabled' : 'stopped-disabled');
    assert.equal(run.terminalFalseVerified, true); assert.equal(run.terminalDisabled503Verified, true);
    if (mode === 'complete') { assert.equal(run.queueDrainIsApproximate, true); assert.equal(run.queueAdmissionOnly, true); }
    if (mode === 'direct-204') assert.equal(run.queries.length, 0);
  });
});

test('queue module has no credential retrieval, dynamic account creation or standalone data/receiver network route', async () => {
  const source = await readFile(new URL('../durable-queue.mjs', import.meta.url), 'utf8');
  assert(!/fetch\(|https\.request|listkeys|listAccountSas|listServiceSas|createIfNotExists|connectionString/u.test(source));
  const f = baseFixture();
  assert.equal(whatIfRequestContext(f.c, buildQueuePhase(f.c, 'queue-role', f.topology)).scope, 'subscription');
  assert.equal(whatIfRequestContext(f.c, buildQueuePhase(f.c, 'queue-storage', f.topology)).scope, 'group');
});

test('only the topology-bound, read-only official Storage operation catalog can cross subscription path prefix', async () => {
  const f = baseFixture(), phase = buildQueuePhase(f.c, 'queue-storage', f.topology), calls = [];
  const invoke = async args => { calls.push(args); return { value: [] }; };
  const arm = transport(f.c, phase, '.', invoke, f.topology), path = '/providers/Microsoft.Storage/operations';
  await arm('GET', path, '2025-01-01');
  assert.equal(calls.length, 1);
  assert(calls[0].includes(`https://management.azure.com${path}?api-version=2025-01-01`));
  for (const [method, id, api, body] of [['POST', path, '2025-01-01'], ['PUT', path, '2025-01-01'],
    ['GET', path, '2024-01-01'], ['GET', '/providers/Microsoft.Storage/other', '2025-01-01'],
    ['GET', path, '2025-01-01', {}], ['GET', `${f.topology.ids.account}/listKeys`, '2025-01-01']]) {
    await assert.rejects(arm(method, id, api, body));
  }
  await assert.rejects(transport(f.c, phase, '.', invoke)('GET', path, '2025-01-01'));
  assert.equal(calls.length, 1);
});

test('queue records require immutable published policy lookup and official prices cannot silently change region or tier', async () => {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage');
  await q.controller.execute(q.approval);
  const records = { 'queue-storage': q.record() };
  await verifyPublishedQueueRecords(f.c, records, async () => f.source);
  await assert.rejects(verifyPublishedQueueRecords(f.c, records, async () => digest('other policy')), /QUEUE_PUBLISHED_SOURCE_CHANGED/);
  const prices = { retrievedAt: new Date(f.at).toISOString(), url: 'https://prices.azure.com/api/retail/prices?%24filter=unit',
    response: { BillingCurrency: 'USD', Count: 5, NextPageLink: null,
      Items: ['LRS Data Stored', 'LRS Class 1 Operations', 'Class 2 Operations', 'LRS Class 1 Additional IO', 'LRS Class 2 Additional IO']
        .map(meterName => ({ meterName, currencyCode: 'USD', type: 'Consumption', serviceName: 'Storage', productName: 'Queues v2',
          skuName: 'Standard LRS', armRegionName: 'australiaeast', tierMinimumUnits: 0,
          retailPrice: meterName === 'LRS Data Stored' ? 0.045 : 0.004,
          unitPrice: meterName === 'LRS Data Stored' ? 0.045 : 0.004, unitOfMeasure: meterName === 'LRS Data Stored' ? '1 GB/Month' : '10K' })) } };
  verifyOfficialQueuePrices(prices);
  for (const mutate of [x => { x.response.NextPageLink = 'more'; }, x => { x.response.Items[0].unitPrice = 0; },
    x => { x.response.Items[0].skuName = 'Standard GRS'; }, x => { x.response.Items[0].armRegionName = 'westus'; },
    x => { x.url = 'https://foreign.invalid/api/retail/prices'; }]) {
    const copy = structuredClone(prices); mutate(copy); assert.throws(() => verifyOfficialQueuePrices(copy));
  }
});
