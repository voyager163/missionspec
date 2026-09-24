import { BUDGET, buildPhase, digest, ids, json, ownerTags, RECEIVER_COMMAND, RECEIVER_DIGEST } from '../definition.mjs';
import { resourceContext, predecessorInstanceIds, verifyWindowPredecessor } from '../policy.mjs';
import { buildDisabledImagePhase, verifyDisabledImageRecord, verifyReceiverCandidate,
  QUEUE_SOURCE_INPUTS, receiverCost, ReceiverUpgradeController } from '../receiver-upgrade.mjs';
import { buildQueuePhase, durableQueueCost, queueTopology, QUEUE_AUTHORITY, QUEUE_PERMISSIONS, QUEUE_PROFILE_KIND, QUEUE_RUNTIME,
  verifyQueueProviderOperations, verifyQueueRecord, QueueTopologyController } from '../durable-queue.mjs';
import { candidateFixture } from './receiver-upgrade.fixture.mjs';
import { terminalReceiverWindow } from './receiver-window.fixture.mjs';

// Generated UNIT evidence only. No saved profile, source archive, review, or cloud receipt is represented by these bytes.
export function baseFixture() {
  const source = digest('UNIT queue policy'), origin = { policyBaselineSha256: digest('UNIT security baseline') };
  const c = { version: 2, subscriptionId: '00000000-0000-4000-8000-000000000001',
    tenantId: '00000000-0000-4000-8000-000000000002', operatorPrincipalId: '00000000-0000-4000-8000-000000000003',
    runId: '00000000-0000-4000-8000-000000000004', namePrefix: 'missionspec-test', registryName: 'missionspectest',
    location: 'australiaeast', budgetEmail: 'operator@example.invalid', budgetStart: '2026-09-01T00:00:00Z',
    budgetEnd: '2027-09-01T00:00:00Z', queryPrincipalIds: ['00000000-0000-4000-8000-000000000003'],
    receiverDigest: RECEIVER_DIGEST, budget: BUDGET, originSha256: digest(json(origin)),
    scannerAdoptionSha256: digest('UNIT scanner'), foundationBudgetsSha256: digest('UNIT foundation') };
  const r = ids(c), configSha256 = digest(json(c)), owned = (id, properties) => ({ id, tags: ownerTags(c), properties });
  const identity = owned(r.ingestIdentity, { clientId: '00000000-0000-4000-8000-000000000005',
    principalId: '00000000-0000-4000-8000-000000000006', tenantId: c.tenantId });
  const core = { qualified: true, configSha256, resources: {
    [r.ingestIdentity]: identity,
    [r.pullIdentity]: owned(r.pullIdentity, { clientId: '00000000-0000-4000-8000-000000000007',
      principalId: '00000000-0000-4000-8000-000000000008', tenantId: c.tenantId }),
    [r.workspace]: owned(r.workspace, { features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: false } }),
    [r.registry]: owned(r.registry, { loginServer: `${c.registryName}.azurecr.io` }),
  } };
  const receipts = { core, 'workspace-access': core,
    data: { qualified: true, configSha256, resources: { [r.dcr]: owned(r.dcr,
      { immutableId: 'dcr-' + 'a'.repeat(32), endpoints: { logsIngestion: 'https://unit.australiaeast-1.ingest.monitor.azure.com' } }) } },
    assignments: { qualified: true, configSha256 }, publication: { qualified: true, digest: RECEIVER_DIGEST,
      registryId: r.registry, recentDigestCount: 1, configUser: '65532:65532',
      configSha256: 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204',
      configSha256Inputs: configSha256, command: RECEIVER_COMMAND } };
  const phase = buildPhase(c, 'disabled-app', null, receipts);
  const app = { ...structuredClone(phase.resources[0].expected), id: r.app, systemData: { createdAt: '2026-09-23T00:00:00.000Z' } };
  app.properties.configuration.ingress.fqdn = 'unit.australiaeast.azurecontainerapps.io';
  Object.assign(app.properties, { provisioningState: 'Succeeded', runningStatus: 'Running',
    latestRevisionName: 'unit-initial', latestReadyRevisionName: 'unit-initial' });
  for (const id of [r.ingestIdentity, r.pullIdentity]) {
    const { clientId, principalId } = core.resources[id].properties;
    app.identity.userAssignedIdentities[id] = { clientId, principalId };
  }
  receipts['disabled-app'] = { qualified: true, configSha256, resources: { [r.app]: app } };
  const topology = queueTopology(c, 'unittest');
  return { c, r, receipts, identity, source, origin, topology, at: Date.parse('2026-09-23T08:10:00.000Z') };
}
export function queueCandidateFixture(f, priorCandidate) {
  const candidate = candidateFixture(f.c, f.receipts.publication);
  candidate.version = 2; candidate.priorCandidate = priorCandidate; candidate.topology = f.topology;
  candidate.legacyPublication = structuredClone(priorCandidate.legacyPublication);
  candidate.review.legacyPublicationSha256 = digest(json(candidate.legacyPublication));
  const p = candidate.profile;
  p.version = 2; p.kind = QUEUE_PROFILE_KIND; p.runtime = QUEUE_RUNTIME;
  p.source.files = Object.fromEntries(QUEUE_SOURCE_INPUTS.map(path => [path, digest(`UNIT queue ${path}`)]));
  const config = JSON.parse(p.configJson); config.created = '2026-09-23T08:12:00Z';
  p.configJson = json(config); p.configDigest = 'sha256:' + digest(p.configJson);
  const manifest = JSON.parse(p.manifestJson); manifest.config.digest = p.configDigest; manifest.config.size = Buffer.byteLength(p.configJson);
  p.manifestJson = json(manifest); p.manifestDigest = 'sha256:' + digest(p.manifestJson);
  const scan = JSON.parse(p.scan.reportJson); scan.ArtifactName = p.manifestDigest;
  p.scan.reportJson = json(scan); p.scan.reportSha256 = digest(p.scan.reportJson);
  const qualification = JSON.parse(p.qualification.reportJson);
  qualification.artifact.manifest = p.manifestDigest; qualification.artifact.config = p.configDigest;
  qualification.durableQueue = { version: 1, kind: 'source-bound-local-queue-sdk-proof',
    sourceFilesSha256: digest(json(p.source.files)), sdkSourceManifestSha256: p.source.files['services/telemetry-ingest/runtime-sources.lock.json'],
    runtime: QUEUE_RUNTIME, disabledNetworkRequests: 0, producerStatus: 202, producerElapsedMs: 30,
    storageScope: QUEUE_RUNTIME.producerScope, consumerScope: QUEUE_RUNTIME.consumerScope, cloudPublication: false, azureEffects: false,
    fixtures: Object.fromEntries(['slow-monitor-fast-durable-ack', 'failed-producer-readiness', 'restart-preserves-queued-message',
      'queue-overflow', 'ttl-expiration', 'three-delivery-attempts', 'visibility-retry', 'single-worker', 'ambiguous-send-no-retry',
      'disabled-zero-network', 'no-implicit-queue-creation'].map(name => [name,
      { result: 'LOCAL_QUEUE_SDK_FIXTURE_PASSED', reportSha256: digest(`UNIT fixture ${name}`), passed: 2, failed: 0 }])) };
  p.qualification.reportJson = json(qualification); p.qualification.reportSha256 = digest(p.qualification.reportJson);
  Object.assign(candidate.review, { version: 2, action: 'publish-one-reviewed-queue-receiver',
    profileSha256: digest(json(p)), priorCandidateSha256: digest(json(priorCandidate)), topologySha256: digest(json(f.topology)),
    recentDigestCount: 3, cost: durableQueueCost(), tag: `receiver-${p.manifestDigest.slice(7, 19)}` });
  Object.assign(candidate.publication, { profileSha256: candidate.review.profileSha256,
    reviewSha256: digest(json(candidate.review)), manifestJson: p.manifestJson, configJson: p.configJson,
    remoteBlobs: [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size })),
    manifests: [...priorCandidate.publication.manifests, { digest: p.manifestDigest, tags: [candidate.review.tag] }] });
  verifyReceiverCandidate(f.c, candidate);
  return candidate;
}
export function queuePhaseFixture(f, name, priorRecords = {}) {
  const { c, topology, source, at, identity } = f, phase = buildQueuePhase(c, name, topology, identity);
  let now = at, journal = null, receipt = null, dispatched = false;
  const review = { version: 1, action: 'accept-exact-durable-queue-topology', topologySha256: digest(json(topology)),
    configSha256: digest(json(c)), sourceSha256: source, approvedAt: new Date(at - 60000).toISOString(),
    expiresAt: new Date(at + 1800000).toISOString(), authority: QUEUE_AUTHORITY };
  const whatIf = { status: 'Succeeded', changes: phase.resources.map(d => ({
    resourceId: d.id, changeType: 'Create', after: { ...structuredClone(d.expected), id: d.id },
  })) };
  const providerOperations = { value: [
    ...QUEUE_PERMISSIONS.actions.map(name => ({ name, isDataAction: false })),
    ...QUEUE_PERMISSIONS.dataActions.map(name => ({ name, isDataAction: true })),
  ] };
  const binding = { foundationBaselineSha256: f.origin.policyBaselineSha256, topologyReviewSha256: digest(json(review)),
    providerOperationsSha256: verifyQueueProviderOperations(providerOperations), preservedIdsSha256: digest(json([])) };
  const approval = { action: `direct-arm-${name}`, configSha256: digest(json(c)), phaseSha256: digest(json(phase)),
    sourceSha256: source, originSha256: c.originSha256, receiptsSha256: digest(json(priorRecords)),
    baselineSha256: digest(json(binding)), whatIfSha256: digest(json(whatIf)),
    approvedAt: review.approvedAt, expiresAt: review.expiresAt };
  const proof = { ...Object.fromEntries(Object.entries(approval).filter(([k]) => k.endsWith('Sha256'))), ...binding,
    preservedIds: [], qualified: true, startedAt: now, completedAt: now, cost: durableQueueCost() };
  const resources = Object.fromEntries(phase.resources.map(d => {
    const actual = { ...structuredClone(d.expected), id: d.id };
    if (d.type === 'Microsoft.Storage/storageAccounts') Object.assign(actual.properties, { provisioningState: 'Succeeded',
      creationTime: new Date(now).toISOString(), primaryEndpoints: { queue: `https://${topology.ids.accountName}.queue.core.windows.net/` } });
    else if (d.type.startsWith('Microsoft.Authorization/')) {
      actual.properties.createdOn = new Date(now).toISOString();
      if (d.type.endsWith('/roleAssignments')) actual.properties.scope = topology.ids.queue;
    }
    return [d.id, actual];
  }));
  const deployment = { id: phase.deploymentId, properties: { mode: 'Incremental', provisioningState: 'Succeeded',
    correlationId: `UNIT ${name}`, templateHash: digest(json(phase.template)), timestamp: new Date(now).toISOString() } };
  const privacy = { diagnostics: { [topology.ids.account]: { value: [] }, [topology.ids.service]: { value: [] } } };
  const io = { now: () => now, sourceDigest: async () => source, check: async () => proof,
    loadJournal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
    saveReceipt: async value => { receipt = structuredClone(value); },
    verifyCurrent: async () => {}, sleep: async ms => { now += ms; },
    arm: async (_method, _id, _api, _body, guard, current) => { await current(); guard(); dispatched = true; },
    observe: async () => ({ deployment, resources, privacy }) };
  const controller = new QueueTopologyController(c, phase, topology, review, io);
  const record = () => ({ version: 1, kind: 'reviewed-queue-phase', topology, review,
    publication: { commitSha: 'c'.repeat(40), sourceSha256: source }, identity, priorRecords, phase, approval,
    preflight: proof, providerOperations, whatIf, journal, receipt });
  return { phase, io, review, approval, proof, controller, record, resources, whatIf,
    get dispatched() { return dispatched; }, advance: ms => { now += ms; } };
}
export async function imageRecordFixture(f, candidate, predecessor, name, instanceId) {
  const { c, r, receipts, source, at } = f;
  const instance = { version: 1, id: instanceId, predecessorSha256: digest(json(predecessor)),
    previousInstanceIds: predecessorInstanceIds(predecessor) };
  const phase = buildDisabledImagePhase(c, name, receipts, candidate, predecessor, instance);
  let app = structuredClone(predecessor.readback.app), journal, receipt, deployment;
  const context = { ...resourceContext(c, receipts), receiverCandidate: candidate };
  const whatIf = { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'Modify', before: app,
    after: { ...structuredClone(phase.resources[0].expected), id: r.app } }] };
  const approval = { action: `direct-arm-${name}`, configSha256: digest(json(c)), phaseSha256: digest(json(phase)),
    sourceSha256: source, originSha256: c.originSha256, receiptsSha256: digest(json(receipts)),
    baselineSha256: f.origin.policyBaselineSha256, whatIfSha256: digest(json(whatIf)),
    approvedAt: new Date(at - 60000).toISOString(), expiresAt: new Date(at + 1800000).toISOString() };
  const proof = { ...Object.fromEntries(Object.entries(approval).filter(([k]) => k.endsWith('Sha256'))),
    qualified: true, startedAt: at, completedAt: at, cost: receiverCost(candidate) };
  const privacy = { diagnostics: { [r.app]: { value: [] } }, exports: { value: [] } };
  const io = { now: () => at, sourceDigest: async () => source, check: async () => proof,
    loadJournal: async () => journal, saveJournal: async v => { journal = structuredClone(v); },
    saveReceipt: async v => { receipt = structuredClone(v); }, reserve: async () => {}, security: async () => {}, privacy: async () => privacy,
    deployment: async () => deployment, observe: async () => ({ app, context, revisions: { value: [
      { id: `${r.app}/revisions/${app.properties.latestRevisionName}`, name: app.properties.latestRevisionName,
        properties: { active: true, provisioningState: 'Provisioned', healthState: 'Healthy', runningState: 'Running',
          replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template) } },
    ] } }),
    arm: async (_method, id, _api, body, _filter, guard, _role, current, deadline) => {
      await current(deadline); guard();
      const previous = app;
      app = { ...structuredClone(body.properties.template.resources[0]), id: r.app, identity: previous.identity, systemData: previous.systemData };
      app.properties.configuration.ingress.fqdn = previous.properties.configuration.ingress.fqdn;
      Object.assign(app.properties, { provisioningState: 'Succeeded', runningStatus: 'Running',
        latestRevisionName: `UNIT-${name}`, latestReadyRevisionName: `UNIT-${name}` });
      deployment = { id, properties: { provisioningState: 'Succeeded', mode: 'Incremental', correlationId: `UNIT ${name}`,
        timestamp: new Date(at).toISOString(), templateHash: digest(json(phase.template)) } };
    } };
  const controller = new ReceiverUpgradeController(c, phase, candidate, predecessor.readback.app, io);
  await controller.execute(approval);
  const record = { version: 1, kind: 'reviewed-disabled-image-change',
    publication: { commitSha: 'c'.repeat(40), sourceSha256: source }, candidate, predecessor,
    prerequisiteReceipts: receipts, phase, approval, preflight: proof, whatIf, journal, receipt };
  verifyDisabledImageRecord(c, record);
  return record;
}
export async function queueUpgradeFixture() {
  const f = baseFixture();
  const first = terminalReceiverWindow(f.c, f.receipts, f.origin, f.source, f.at - 10000);
  const priorCandidate = candidateFixture(f.c, f.receipts.publication);
  const prepared = await imageRecordFixture(f, priorCandidate, first, 'disabled-image-upgrade', '00000000-0000-4000-8000-000000000098');
  f.receipts = { ...f.receipts, receiverUpgrade: prepared };
  const predecessor = terminalReceiverWindow(f.c, f.receipts, f.origin, f.source, f.at + 1000, {
    version: 1, id: '00000000-0000-4000-8000-000000000097', predecessorSha256: digest(json(prepared)),
    previousInstanceIds: predecessorInstanceIds(prepared),
  });
  verifyWindowPredecessor(f.c, predecessor);
  f.at += 5000;
  const records = {};
  for (const name of ['queue-storage', 'queue-role', 'queue-assignment']) {
    const q = queuePhaseFixture(f, name, structuredClone(records));
    await q.controller.execute(q.approval);
    records[name] = q.record(); verifyQueueRecord(f.c, records[name]);
  }
  f.receipts = { ...f.receipts, queueRecords: records };
  const candidate = queueCandidateFixture(f, priorCandidate);
  return { ...f, predecessor, priorCandidate, candidate, records };
}
