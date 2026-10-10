import assert from 'node:assert/strict';
import { digest, json } from '../definition.mjs';
import { durableQueueCost } from '../durable-queue.mjs';
import { adoptQueueStorage, collectQueueAdoption, QUEUE_ADOPTION_ASSURANCE,
  QUEUE_ADOPTION_AUTHORITY } from '../queue-adoption.mjs';
import { baseFixture, queuePhaseFixture } from './durable-queue.fixture.mjs';

// Entirely generated unit evidence; none of these bytes are an operator or cloud receipt.
export async function queueAdoptionFixture(input = null) {
  const f = input === null ? baseFixture() : structuredClone(input), initialAt = f.at;
  const prior = queuePhaseFixture(f, 'queue-storage');
  prior.io.arm = async () => { throw new Error('ARM_OPERATION_FAILED'); };
  await assert.rejects(prior.controller.execute(prior.approval), /QUEUE_CHANGE_STOPPED/);
  f.at += 180000;
  const q = queuePhaseFixture(f, 'queue-storage');
  const validation = q.record().validation;
  validation.properties.templateHash = '1234567890123456789';
  q.proof.armValidationSha256 = digest(json(validation));
  q.resources[f.topology.ids.account].properties.publicNetworkAccess = 'Disabled';
  q.resources[f.topology.ids.account].properties.networkAcls.ipv6Rules = [];
  q.resources[f.topology.ids.account].properties.privateEndpointConnections = [];
  q.resources[f.topology.ids.account].properties.creationTime = new Date(f.at + 500).toISOString().replace('.500Z', '.5000001Z');
  q.resources[f.topology.ids.service].properties.logging = {
    delete: false, read: false, write: false, version: '1.0', retentionPolicy: { enabled: false },
  };
  await assert.rejects(q.controller.execute(q.approval), /QUEUE_CHANGE_STOPPED/);
  const phase = q.phase, current = q.record(), old = prior.record();
  const timestamp = ms => new Date(ms).toISOString();
  const artifacts = {};
  const put = (name, value) => {
    const text = json(value);
    artifacts[name] = { json: text, sha256: digest(text) };
  };
  put('config', f.c); put('topology', f.topology); put('template', phase.template);
  put('plan', { version: 1, phase, sourceSha256: f.source, cost: durableQueueCost(),
    qualified: false, executionAuthorized: false, exactReviewRequired: true });
  for (const name of ['review', 'approval', 'preflight', 'validation', 'whatIf', 'publication', 'providerOperations', 'journal']) put(name, current[name]);
  for (const name of ['review', 'approval', 'preflight', 'publication', 'journal']) put(`prior${name[0].toUpperCase()}${name.slice(1)}`, old[name]);
  const absent = { originalJournalSha256: artifacts.priorJournal.sha256, deploymentAbsent: true,
    queueResourcesAbsent: true, receiverDisabled: true, exactFinalGuardReproduced: false, currentFinalGuardPassed: true,
    originalFailureDetailsUnavailable: true, originalHistoryModified: false, writes: 0, calls: 1,
    completedAt: timestamp(initialAt + 10000), retryAuthorized: false };
  put('absence', absent);
  const copies = Object.fromEntries([
    'config.json', 'origin.json', 'scanner-adoption.json', 'foundation-budgets.json', 'receipts.json',
    'execution-origins-v3.json', 'receiver-candidate.json', 'receiver-upgrade.json', 'window-predecessor.json',
    'queue-topology.json', 'queue-records.json', 'reconciliation-proposal.json', 'reconciliation-review.json',
    'reconciliation-receipts.json', 'queue-storage-plan.json', 'queue-storage-template.json',
    'queue-policy-publication.json', 'reviewed-validation-summary.json', 'reviewed-queue-storage-what-if.json',
  ].map(name => [name, digest(`UNIT copied ${name}`)]));
  for (const [name, key] of Object.entries({
    'config.json': 'config', 'queue-topology.json': 'topology', 'queue-storage-plan.json': 'plan',
    'queue-storage-template.json': 'template', 'queue-policy-publication.json': 'publication',
    'reviewed-queue-storage-what-if.json': 'whatIf',
  })) copies[name] = artifacts[key].sha256;
  copies['origin.json'] = f.c.originSha256; copies['queue-records.json'] = digest(json({}));
  const excludedEffects = ['queue-role', 'queue-assignment', 'image-publication', 'receiver-change', 'ingestion', 'release', 'merge'];
  const lineage = { version: 1, recordedAt: q.approval.approvedAt, expiresAt: q.approval.expiresAt,
    originalDirectory: '/unit/stopped-attempt', copies, originalJournalSha256: artifacts.priorJournal.sha256,
    readonlyResultSha256: artifacts.absence.sha256, originalHistoryModified: false, permittedNewAttempts: 1,
    exactPhaseSha256: digest(json(phase)), excludedEffects };
  put('lineage', lineage);
  const copiedHistory = Object.fromEntries(Object.entries(copies).filter(([name]) => ![
    'reconciliation-review.json', 'reconciliation-receipts.json', 'queue-policy-publication.json',
    'reviewed-validation-summary.json', 'reviewed-queue-storage-what-if.json',
  ].includes(name)).map(([name, hash]) => [name, { priorBytesSha256: hash, copiedJsonSha256: hash }]));
  put('authorization', { version: 1, approvedAt: q.approval.approvedAt, expiresAt: q.approval.expiresAt,
    action: 'storage-only-and-read-only-reconciliation', proposalSha256: copies['reconciliation-proposal.json'],
    phaseSha256: digest(json(phase)), templateSha256: artifacts.template.sha256, topologySha256: artifacts.topology.sha256,
    whatIfSha256: artifacts.whatIf.sha256, cost: durableQueueCost(), priorDirectory: '/unit/preflight', copiedHistory,
    originalHistoryModified: false, allowedEffects: [
      'Create exact reviewed storage account, queue service and queue', 'Record validated read-only reconciliation',
    ], excludedEffects, exactFreshPreflightRequired: true, postCreateReadbacksRequired: 8,
    originalApprovalDirectory: lineage.originalDirectory, originalJournalSha256: artifacts.priorJournal.sha256,
    absenceReconciliationSha256: artifacts.absence.sha256,
    freshAttemptApproval: 'User explicitly selected Approve one fresh storage-only attempt.',
    permittedNewAttempts: 1, repeatedDispatchAuthorized: false });
  put('dispatch', { index: 1, stage: 'execute',
    args: ['rest', '--method', 'PUT', '--url', `https://management.azure.com${phase.deploymentId}?api-version=2022-09-01`,
      '--subscription', f.c.subscriptionId, '--only-show-errors', '--output', 'json',
      '--body', '@/unit/request.json', '--headers', 'Content-Type=application/json'],
    timeoutMs: 15000, startedAt: timestamp(f.at), success: true,
    resultSha256: digest('UNIT unretained response'), completedAt: timestamp(f.at + 1000) });
  put('stop', { stage: 'execute', writes: 1, failure: { code: 'QUEUE_CHANGE_STOPPED_RESOURCES_PRESERVED',
    armCode: null, httpStatus: null, bridgeCode: null, diagnostics: null }, recordedAt: timestamp(f.at + 3000),
    originalHistoryModified: false, furtherRetriesAuthorized: false });
  const deployment = { id: phase.deploymentId, name: phase.deploymentId.split('/').at(-1),
    type: 'Microsoft.Resources/deployments', properties: { provisioningState: 'Succeeded', mode: 'Incremental',
      correlationId: '00000000-0000-4000-8000-000000000050', templateHash: validation.properties.templateHash,
      timestamp: timestamp(f.at + 2000).replace('.000Z', '.0000001Z'),
      outputResources: phase.resources.map(({ id }) => ({ id })) } };
  const operations = { value: [...phase.resources, null].map((descriptor, index) => {
    const operationId = `000000000000000${index}`;
    return { id: `${phase.deploymentId}/operations/${operationId}`, operationId, properties: {
      duration: 'PT1.0000001S', provisioningOperation: descriptor ? 'Create' : 'EvaluateDeploymentOutput',
      provisioningState: 'Succeeded', statusCode: 'OK',
      ...(descriptor ? { targetResource: { id: descriptor.id, resourceName: descriptor.expected.name, resourceType: descriptor.type } } : {}),
      timestamp: timestamp(f.at).replace('.000Z', '.0000001Z'),
      trackingId: `00000000-0000-4000-8000-00000000006${index}`,
    } };
  }) };
  const resources = structuredClone(q.resources), queues = { value: [structuredClone(resources[f.topology.ids.queue])] };
  const privacy = { diagnostics: { [f.topology.ids.account]: { value: [] }, [f.topology.ids.service]: { value: [] } } };
  const origin = { version: 1, kind: 'stopped-queue-storage-origin', topology: f.topology, identity: f.identity,
    phase, artifacts, firstReadback: { checkedAt: timestamp(f.at + 4000), deployment, operations, resources, queues, privacy },
    originalReceipt: null, assurance: QUEUE_ADOPTION_ASSURANCE };
  f.at += 600000; f.source = digest('UNIT new adoption source');
  let now = f.at, source = f.source;
  const responses = {
    [phase.deploymentId]: deployment, [`${phase.deploymentId}/operations`]: operations,
    ...resources, [`${f.topology.ids.service}/queues`]: queues, [f.r.ingestIdentity]: f.identity,
    [f.topology.ids.role]: null, [f.topology.ids.assignment]: null,
  };
  for (const [id, value] of Object.entries(privacy.diagnostics)) responses[`${id}/providers/Microsoft.Insights/diagnosticSettings`] = value;
  for (const scope of [f.topology.ids.account, f.topology.ids.service, f.topology.ids.queue]) {
    responses[`${scope}/providers/Microsoft.Authorization/roleAssignments`] = { value: [] };
  }
  const reads = [];
  const io = { now: () => now, sourceDigest: async () => source, read: async (request, deadline) => {
    assert.equal(Object.isFrozen(request), true); assert.equal(deadline, now + 120000);
    assert(Object.hasOwn(responses, request.id));
    reads.push(structuredClone(request));
    return structuredClone(responses[request.id]);
  } };
  const proposal = await collectQueueAdoption(f.c, origin, io);
  const review = { version: 1, action: 'adopt-exact-observed-queue-storage',
    configSha256: digest(json(f.c)), originSha256: digest(json(origin)), proposalSha256: digest(json(proposal)),
    sourceSha256: f.source, reviewedAt: timestamp(now), expiresAt: timestamp(now + 1800000),
    authority: QUEUE_ADOPTION_AUTHORITY };
  const publication = { commitSha: 'd'.repeat(40), sourceSha256: f.source };
  const adoption = adoptQueueStorage(f.c, proposal, origin, review, publication, now);
  return { ...f, foundationOrigin: f.origin, origin, proposal, review, publication, adoption, io, reads, responses,
    advance: ms => { now += ms; }, setSource: value => { source = value; } };
}

export function replaceOriginArtifact(origin, name, mutate) {
  const value = JSON.parse(origin.artifacts[name].json);
  mutate(value);
  const text = json(value);
  origin.artifacts[name] = { json: text, sha256: digest(text) };
}

export function rebindAdoption(record) {
  record.topology = structuredClone(record.origin.topology);
  record.identity = structuredClone(record.origin.identity);
  record.proposal.originSha256 = digest(json(record.origin));
  record.proposal.observation.originSha256 = record.proposal.originSha256;
  record.observation = structuredClone(record.proposal.observation);
  record.review.originSha256 = record.proposal.originSha256;
  record.review.proposalSha256 = digest(json(record.proposal));
  return record;
}
