import { digest, ids, json, SYNTHETIC_FIXTURES } from '../definition.mjs';
import { candidateFixture } from './receiver-upgrade.fixture.mjs';
import { baseFixture, queueCandidateFixture } from './durable-queue.fixture.mjs';
import { privateLinkRuntimeTarget, privateRuntimePhase, createPrivateLinkReceiver,
  qualifyPrivateLinkDelivery, privateLinkWindowBinding, verifyPrivateLinkRuntimeCompletion,
  privateProbeProgram, privateLinkExecEndpoint, publicControlTarget } from '../private-link-runtime.mjs';

// Generated offline evidence only. No fixture is a live approval, publication or Azure observation.
export function runtimeFixture() {
  const f = baseFixture(), { c, r, at } = f;
  const prior = candidateFixture(c, f.receipts.publication);
  const candidate = queueCandidateFixture(f, prior);
  const original = f.receipts['disabled-app'].resources[r.app];
  original.properties.template.containers[0].image = `${c.registryName}.azurecr.io/missionspec/telemetry-ingest@${prior.profile.manifestDigest}`;
  const oldDescriptor = { id: r.app, type: 'Microsoft.App/containerApps', apiVersion: '2025-07-01',
    expected: structuredClone(original) };
  delete oldDescriptor.expected.id; delete oldDescriptor.expected.systemData;
  const appId = `${r.group}/providers/Microsoft.App/containerApps/${c.namePrefix}-private-ingest`;
  const environmentId = `${r.group}/providers/Microsoft.App/managedEnvironments/${c.namePrefix}-private-environment`;
  const resource = structuredClone(f.receipts['disabled-app'].resources[r.app]);
  delete resource.id; delete resource.systemData;
  resource.name = `${c.namePrefix}-private-ingest`;
  const p = resource.properties;
  delete p.runningStatus; delete p.provisioningState; delete p.latestRevisionName; delete p.latestReadyRevisionName;
  delete p.configuration.ingress.fqdn;
  p.managedEnvironmentId = environmentId;
  p.template.containers[0].image = `${c.registryName}.azurecr.io/missionspec/telemetry-ingest@${candidate.profile.manifestDigest}`;
  p.template.containers[0].env.push({ name: 'AZURE_QUEUE_URL', value: f.topology.ids.queueUrl },
    { name: 'AZURE_QUEUE_RESOURCE_ID', value: f.topology.ids.queue });
  const descriptor = { id: appId, type: 'Microsoft.App/containerApps', apiVersion: '2025-07-01', expected: resource };
  const publicDescriptor = structuredClone(descriptor);
  publicDescriptor.id = `${r.group}/providers/Microsoft.App/containerApps/${c.namePrefix}-public-probe`;
  publicDescriptor.expected.name = `${c.namePrefix}-public-probe`;
  publicDescriptor.expected.properties.managedEnvironmentId = r.environment;
  const context = { plan: { version: 3, input: { version: 2 }, publicProbe: publicDescriptor,
    topology: { ids: { app: appId, environment: environmentId, publicProbe: publicDescriptor.id } },
    stages: [{ id: 'create-disabled-receiver', resources: [descriptor] }] },
  origin: { receiver: { candidate: prior, phase: { resources: [oldDescriptor] }, receipt: { resources: { [r.app]: original } } },
    queueProfile: candidate.profile } };
  const identities = Object.fromEntries([r.ingestIdentity, r.pullIdentity].map(id => [id, f.receipts.core.resources[id]]));
  const prerequisites = { environment: { id: environmentId, properties: { defaultDomain: 'unit.australiaeast.azurecontainerapps.io' } },
    identity: identities[r.ingestIdentity], pullIdentity: identities[r.pullIdentity], privateIp: '10.82.0.68',
    workspace: f.receipts.core.resources[r.workspace], queueTopology: f.topology, oldApp: original,
    oldEnvironment: { id: r.environment, properties: { vnetConfiguration: null, defaultDomain: 'unit-old.australiaeast.azurecontainerapps.io' } },
    oldReceiver: { phase: { resources: [oldDescriptor] } } };
  const evidence = { version: 1, kind: 'reviewed-private-link-control-chain', planSha256: digest(json(context.plan)),
    originSha256: digest(json(context.origin)), records: [{ after: { resources: { [r.environment]: prerequisites.oldEnvironment } } }] };
  const target = privateLinkRuntimeTarget(c, context, candidate, prerequisites);
  const publicTarget = publicControlTarget(c, target, context, evidence);
  const instanceId = '00000000-0000-4000-8000-000000000077';
  const observation = flag => {
    const app = { ...structuredClone(resource), id: appId, systemData: { createdAt: new Date(at).toISOString() } };
    app.properties.configuration.ingress.fqdn = target.fqdn;
    app.properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value = flag;
    const revision = `${resource.name}--${flag === 'true' ? 'enabled' : 'disabled'}`;
    Object.assign(app.properties, { latestRevisionName: revision, latestReadyRevisionName: revision,
      provisioningState: 'Succeeded', runningStatus: 'Running' });
    const revisions = { value: [{ id: `${appId}/revisions/${revision}`, name: revision, properties: {
      active: true, provisioningState: 'Provisioned', healthState: 'Healthy', runningState: 'Running',
      replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template),
    } }] };
    return { app, revisions, identities, oldApp: structuredClone(original), privacy: { diagnostic: { value: [] }, exports: { value: [] } },
      observedAt: new Date(at).toISOString() };
  };
  const hash = value => digest(json(value));
  const binding = { version: 1, configSha256: hash(c), planSha256: hash(context.plan), originSha256: hash(context.origin),
    controlEvidenceSha256: hash(evidence), candidateSha256: hash(candidate) };
  const phase = privateRuntimePhase(c, target, instanceId, 'create-disabled', hash(evidence));
  const disabledBinding = { ...binding, targetSha256: hash(target), phaseSha256: hash(phase) };
  const approval = (action, bound) => ({ version: 1, action, bindingSha256: hash(bound), sourceSha256: f.source,
    policyCommitSha: 'c'.repeat(40), approvedAt: new Date(at - 60000).toISOString(), expiresAt: new Date(at + 1800000).toISOString() });
  const http = status => ({ status, errorCode: null, tlsVerified: true, bodyBytes: 0, durationMs: 50, headerPolicy: { noStore: true } });
  const disabled = { version: 1, kind: 'private-link-disabled-receiver', binding: disabledBinding, target, phase,
    approval: approval('private-link-create-disabled-receiver', disabledBinding), controlEvidence: evidence,
    candidate, observation: observation('false'), disabledResponse: http(503), completedAt: new Date(at).toISOString(), ingestionEnabled: false };
  disabled.intent = { version: 2, kind: 'private-link-receiver-create-intent', binding: disabledBinding, target, candidate, phase,
    approval: disabled.approval, controlEvidence: evidence, intentAt: new Date(at).toISOString(), effectDeadline: at + 120000, outcome: 'write-possible' };
  const probe = runtimeProbeFixture(c, target, observation('false'), candidate, prerequisites, f.source, 'a'.repeat(64), at);
  const oldObservation = () => {
    const app = structuredClone(original), revision = app.properties.latestRevisionName;
    return { app, revisions: { value: [{ id: `${r.app}/revisions/${revision}`, name: revision, properties: {
      active: true, provisioningState: 'Provisioned', healthState: 'Healthy', runningState: 'Running',
      replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template),
    } }] }, identities, oldApp: original, privacy: { diagnostic: { value: [] }, exports: { value: [] } }, observedAt: new Date(at).toISOString() };
  };
  const publicObservation = (createdAt = at) => {
    const observed = observation('false'), app = observed.app;
    app.id = publicTarget.appId; app.name = publicTarget.descriptor.expected.name;
    app.systemData.createdAt = new Date(createdAt).toISOString();
    app.properties.managedEnvironmentId = r.environment;
    app.properties.configuration.ingress.fqdn = publicTarget.fqdn;
    app.properties.latestRevisionName = app.properties.latestReadyRevisionName = `${app.name}--unit-false`;
    observed.revisions.value[0].id = `${app.id}/revisions/${app.properties.latestRevisionName}`;
    observed.revisions.value[0].name = app.properties.latestRevisionName;
    return observed;
  };
  const rows = (start, end) => ({ tables: [{ name: 'PrimaryResult',
    columns: [{ name: 'TimeGenerated', type: 'datetime' }, ...Object.keys(SYNTHETIC_FIXTURES[0]).map(name => ({ name, type: name === 'schemaVersion' ? 'long' : 'string' }))],
    rows: SYNTHETIC_FIXTURES.map(event => [start, ...Object.values(event)]),
  }] });
  return { ...f, candidate, context, evidence, prerequisites, target, publicTarget, instanceId, observation,
    oldObservation, publicObservation, approval, disabled, probe, http, rows };
}

export function runtimeProbeFixture(c, target, observation, candidate, prerequisites, source, head, at, mode = 'private') {
  const { payloadSha256, commandSha256 } = privateProbeProgram(c, prerequisites, mode), positive = mode === 'private';
  const app = structuredClone(observation.app), revision = app.properties.latestRevisionName;
  const replicas = { value: [{ name: 'unit-replica', properties: { containers: [{ name: 'telemetry-ingest', ready: true,
    started: true, runningState: 'Running', restartCount: 0, execEndpoint: privateLinkExecEndpoint(c, target, revision, 'unit-replica') }] } }] };
  const side = { app, replicas, observedAt: new Date(at).toISOString(),
    control: { sourceSha256: source, headSha256: head, checkedAt: new Date(at).toISOString() } };
  return { version: 1, kind: 'bounded-private-queue-exec', sessions: 1, payloadFrames: 1, sessionClosed: true,
    appId: target.appId, revision, replica: 'unit-replica', imageDigest: candidate.profile.manifestDigest,
    restartCount: 0, payloadSha256, commandSha256, before: structuredClone(side), after: structuredClone(side),
    processStartedAt: new Date(at).toISOString(), processCompletedAt: new Date(at).toISOString(), observedAt: new Date(at).toISOString(),
    result: { version: 1, kind: 'same-container-private-queue-metadata', nodeVersion: '24.21.0', queueHost: target.queueHost,
      privateIp: target.privateIp, clientId: prerequisites.identity.properties.clientId, principalId: prerequisites.identity.properties.principalId,
      mode, dnsPrivate: positive, dnsPublic: !positive, tlsVerified: true, remotePrivate: positive, remotePublic: !positive,
      tokenIdentityMatched: true, metadataStatus: positive ? 200 : 403, storageErrorCode: positive ? null : 'AuthorizationFailure',
      tokenRequests: 1, metadataRequests: 1, enqueues: 0, elapsedMs: 30, failureCode: null } };
}

// Composes real control evidence with the production runtime driver; every cloud effect remains inert.
export async function privateRuntimeCompletionFixture(f, evidence, prerequisites) {
  const { c, context, candidate } = f, r = ids(c), hash = value => digest(json(value));
  const target = privateLinkRuntimeTarget(c, context, candidate, prerequisites);
  const instanceId = '00000000-0000-4000-8000-000000000088';
  const identityValues = { [r.ingestIdentity]: prerequisites.identity, [r.pullIdentity]: prerequisites.pullIdentity };
  const store = new Map();
  let now = f.at, flag = 'false', created = false, publicCreated = false, publicCreatedAt = f.at;
  const publicTarget = publicControlTarget(c, target, context, evidence);
  const approval = (action, binding) => ({ version: 1, action, bindingSha256: hash(binding), sourceSha256: f.source,
    policyCommitSha: 'c'.repeat(40), approvedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 1800000).toISOString() });
  const response = status => ({ status, errorCode: null, tlsVerified: true, bodyBytes: 0, durationMs: 30, headerPolicy: { noStore: true } });
  const observe = selected => {
    const isPublic = selected.appId === publicTarget.appId;
    const app = selected.appId === r.app ? structuredClone(prerequisites.oldApp) :
      { ...structuredClone(selected.descriptor.expected), id: selected.appId, systemData: { createdAt: new Date(isPublic ? publicCreatedAt : f.at).toISOString() } };
    if (selected.appId !== r.app) {
      app.properties.configuration.ingress.fqdn = selected.fqdn;
      const selectedFlag = isPublic ? 'false' : flag;
      app.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = selectedFlag;
      Object.assign(app.properties, { latestRevisionName: `${app.name}--unit-${selectedFlag}`,
        latestReadyRevisionName: `${app.name}--unit-${selectedFlag}`, provisioningState: 'Succeeded', runningStatus: 'Running' });
      for (const [id, identity] of Object.entries(identityValues)) {
        app.identity.userAssignedIdentities[id] = { clientId: identity.properties.clientId, principalId: identity.properties.principalId };
      }
    }
    const revision = app.properties.latestRevisionName;
    return { app, revisions: { value: [{ id: `${selected.appId}/revisions/${revision}`, name: revision,
      properties: { active: true, provisioningState: 'Provisioned', healthState: 'Healthy', runningState: 'Running',
        replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template) } }] },
    identities: identityValues, oldApp: prerequisites.oldApp, privacy: { diagnostic: { value: [] }, exports: { value: [] } },
    observedAt: new Date(now).toISOString() };
  };
  const io = {
    now: () => now, sleep: async ms => { now += ms; }, verifyPrerequisites: () => prerequisites,
    published: async () => {}, verifySource: async () => {}, inventory: async () => candidate.publication,
    sourceDigest: async () => f.source, load: async name => store.get(name) ?? null,
    save: async (name, value) => store.set(name, structuredClone(value)),
    immutable: async (name, value) => { if (store.has(name)) throw new Error('UNIT_HISTORY_REPLAY'); store.set(name, structuredClone(value)); },
    reserve: async (kind, key, value) => { const name = `${kind}-${key}`; if (store.has(name)) throw new Error('UNIT_FENCE_REPLAY');
      store.set(name, structuredClone(value)); },
    windowHead: async intent => store.get(`window-${intent.physicalKey}`),
    current: async () => ({ sourceSha256: f.source, headSha256: prerequisites.controlHeadSha256, prerequisites }),
    identities: async () => identityValues,
    observe: async selected => observe(selected),
    read: async id => id === target.appId ? created ? observe(target).app : null :
      id === publicTarget.appId ? publicCreated ? observe(publicTarget).app : null :
        id.endsWith('-p/operations') ? { value: [{ properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded',
          targetResource: { id: publicTarget.appId } } }] } :
          id.endsWith('-p') ? { id, properties: { mode: 'Incremental', provisioningState: 'Succeeded', timestamp: new Date(publicCreatedAt).toISOString() } } :
            { id, properties: { approximateMessageCount: 0 } },
    preview: async phase => ({ validation: { properties: { provisioningState: 'Succeeded' } },
      whatIf: { status: 'Succeeded', changes: [{ resourceId: phase.action === 'create-public-probe' ? publicTarget.appId : target.appId,
        changeType: phase.action.startsWith('create-') ? 'Create' : 'Modify',
        ...(phase.action.startsWith('create-') ? {} : { before: observe(target).app }),
        after: phase.request.body.properties.template.resources[0] }] } }),
    deploy: async (request, guard, until, check, intent) => { await check(until); guard(); await intent(); guard();
      if (request.id.endsWith('-p')) { publicCreated = true; publicCreatedAt = now; return; }
      created = true;
      flag = request.body.properties.template.resources[0].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value; },
    deletePublic: async (_target, guard, until, check, intent) => { await check(until); guard(); await intent(); guard(); publicCreated = false; },
    http: async (_host, _method, _path, _event, guard) => { guard(); return response(flag === 'true' ? 202 : 503); },
    query: async (_workspace, _source, start, _end, guard) => {
      guard(); return { tables: [{ name: 'PrimaryResult', columns: [
        { name: 'TimeGenerated', type: 'datetime' }, ...Object.keys(SYNTHETIC_FIXTURES[0]).map(name => ({ name, type: name === 'schemaVersion' ? 'long' : 'string' })),
      ], rows: SYNTHETIC_FIXTURES.map(event => [start, ...Object.values(event)]) }] };
    },
    probe: async (selected, observation, image, _prereq, _transport, _until, guard, mode = 'private') => {
      guard();
      return runtimeProbeFixture(c, selected, observation, image, prerequisites, f.source, prerequisites.controlHeadSha256, now, mode);
    },
  };
  const phase = privateRuntimePhase(c, target, instanceId, 'create-disabled', hash(evidence));
  const createBinding = { version: 1, configSha256: hash(c), planSha256: hash(context.plan), originSha256: hash(context.origin),
    controlEvidenceSha256: hash(evidence), candidateSha256: hash(candidate), targetSha256: hash(target), phaseSha256: hash(phase) };
  const disabled = await createPrivateLinkReceiver(c, context, evidence, candidate, instanceId,
    approval('private-link-create-disabled-receiver', createBinding), '/UNIT', { io });
  const transport = { pythonPath: '/UNIT/python', pythonSha256: digest('UNIT python'), bridgeSha256: digest('UNIT bridge') };
  const binding = privateLinkWindowBinding(c, context, evidence, candidate, disabled, instanceId, transport);
  const approvals = { enable: approval('private-link-bounded-enable', binding), disable: approval('private-link-false-only-disable', binding),
    publicCreate: approval('private-link-create-public-control', binding), publicDelete: approval('private-link-delete-public-control', binding) };
  const completion = await qualifyPrivateLinkDelivery(c, context, evidence, candidate, disabled, instanceId, approvals, transport, '/UNIT', { io });
  if (completion.outcome !== 'qualified-private-delivery-disabled') throw new Error(JSON.stringify({
    failure: completion.failure, disableFailure: completion.disableFailure, outcome: completion.outcome,
  }));
  verifyPrivateLinkRuntimeCompletion(c, context, completion, now);
  return { completion, disabled, target, at: now, store };
}
