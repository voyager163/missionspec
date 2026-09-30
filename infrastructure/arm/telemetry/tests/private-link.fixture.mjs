import assert from 'node:assert/strict';
import { digest, ids, json, ownerTags, budgetProperties, projectBudgetFilter, buildPhase, storageContract } from '../definition.mjs';
import { queueUpgradeFixture } from './durable-queue.fixture.mjs';
import { queueAdoptionFixture } from './queue-adoption.fixture.mjs';
import { nspPhaseFixture } from './nsp.fixture.mjs';
import { emptyNspEvidence, nspTopology, nspPendingHead, nspPreflightBaseline } from '../nsp.mjs';
import { buildPrivateLinkPlan, PRIVATE_LINK_API as API, PRIVATE_LINK_CONTROL_STAGES, privateLinkAtLeast,
  privateLinkResources, privateLinkBudgetConfiguration } from '../private-link.mjs';
import { privateLinkReadRequests, privateLinkResourceDescriptors } from '../private-link-readback.mjs';
import { emptyPrivateLinkControlEvidence, privateLinkHead, preparePrivateLinkPhase, privateLinkPermissions,
  checkPrivateLinkPhase, executePrivateLinkPhase, PRIVATE_LINK_PRICE_METERS } from '../private-link-controller.mjs';
import { privateLinkCachedFixture } from './private-link-cache.fixture.mjs';

const hash = value => digest(json(value));
const clone = structuredClone;
const telemetry = await storageContract();
export const privateInput = Object.freeze({ version: 1, addresses: { vnet: '10.240.8.0/24', apps: '10.240.8.0/26',
  endpoint: '10.240.8.64/28', knownAddressSpaces: ['10.88.0.0/24', '192.168.0.0/20'] }, overlapDays: 7 });
// Entirely generated unit history. No cloud identity, approval or operator receipt.
export async function privateLinkFixture(input = privateInput) {
  const upgraded = await privateLinkCachedFixture('queue-upgrade-origin', {}, queueUpgradeFixture);
  const f = await queueAdoptionFixture(upgraded);
  const network = emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
  for (const name of ['nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association']) {
    const phase = nspPhaseFixture(f, f.adoption, network, name);
    await phase.controller.execute(phase.approval); network.records.push(phase.record());
  }
  const q = nspPhaseFixture(f, f.adoption, network, 'nsp-subscription-admission'), receiver = upgraded.receipts.receiverUpgrade;
  Object.assign(q.proof.foundationBinding, { receiverRecordSha256: hash(receiver), receiverManifestDigest: receiver.candidate.profile.manifestDigest,
    receiverConfigDigest: receiver.candidate.profile.configDigest });
  q.proof.baselineSha256 = nspPreflightBaseline(q.proof); q.approval.baselineSha256 = q.proof.baselineSha256;
  let reservation;
  q.io.reserve = async journal => { reservation = clone({ phase: q.phase, approvalSha256: hash(q.approval), journal }); };
  q.after.resources[network.topology.ids.rule].properties.appliesTo = [{ resourceType: '*', features: ['*'] }];
  q.after.rules.value[0] = clone(q.after.resources[network.topology.ids.rule]);
  q.after.configuration.properties.profile.accessRules[0].properties.appliesTo = [{ resourceType: '*', features: ['*'] }];
  q.after.configurations.value[0] = clone(q.after.configuration);
  await assert.rejects(q.controller.execute(q.approval), /NSP_CHANGE_STOPPED/);
  const original = Object.fromEntries(['phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'journal', 'receipt']
    .map(key => [key, clone(q.record()[key])]));
  original.reservation = reservation;
  const origin = { adoption: f.adoption, network, original, pendingHead: nspPendingHead(network, q.phase, reservation.journal),
    receiver, queueProfile: upgraded.candidate.profile };
  const plan = buildPrivateLinkPlan(f.c, origin, clone(input), f.source);
  f.at += 10000;
  return { ...f, origin, context: { plan, origin }, opaque: q.after, evidence: emptyPrivateLinkControlEvidence({ plan, origin }) };
}
export function privateCostFixture(f, at = f.at) {
  const evidence = { version: 1, kind: 'private-link-price-evidence', retrievedAt: new Date(at - 1000).toISOString(),
    region: 'australiaeast', currency: 'USD', unknownChargesAcknowledgment: 'UNIT explicit exclusions; not human approval.',
    queries: Object.entries(PRIVATE_LINK_PRICE_METERS).map(([purpose, [rate, unit, productName, skuName, meterName, armRegionName]]) => ({ purpose,
      url: `https://prices.azure.com/api/retail/prices?$filter=meterName%20eq%20%27UNIT-${purpose}%27`,
      selectedMeterId: `UNIT-${purpose}`, response: { NextPageLink: null, Items: [{ meterId: `UNIT-${purpose}`, type: 'Consumption',
        retailPrice: rate, unitPrice: rate, unitOfMeasure: unit, currencyCode: 'USD', armRegionName,
        productName, skuName, meterName, tierMinimumUnits: 0 }] } })) };
  const review = { version: 1, action: 'approve-exact-private-link-migration-cost-and-budget-coverage',
    planSha256: f.context.plan.planSha256, configSha256: hash(f.c), sourceSha256: f.source, evidenceSha256: hash(evidence),
    userInstruction: 'UNIT exact budget changes and cost planning; no real authorization.',
    cost: f.context.plan.topology.cost, budgetTargets: { migration: { project: 425, telemetry: 375, state: 50 },
      steady: { project: 375, telemetry: 325, state: 50 }, additionalGroup: f.context.plan.topology.ids.managedGroup },
    approvedAt: new Date(at - 1000).toISOString(), expiresAt: new Date(at + 1800000).toISOString() };
  review.userInstructionSha256 = digest(review.userInstruction);
  return { review, evidence };
}
export function privateSnapshotFixture(f, stage, at = f.at) {
  const context = f.context, n = context.plan.topology.ids, old = context.origin.network.topology.ids, r = ids(f.c), q = f.topology.ids;
  const d = privateLinkResources(f.c, context.plan.topology, context.origin);
  const s = { version: 1, kind: 'private-link-control-snapshot', startedAt: at, completedAt: at,
    accountContext: { id: f.c.subscriptionId, tenantId: f.c.tenantId, environmentName: 'AzureCloud', state: 'Enabled' },
    resources: Object.fromEntries(privateLinkResourceDescriptors(f.c, context).map(value => [value.id, null])),
    lists: Object.fromEntries(Object.keys(privateLinkReadRequests(f.c, context)).map(key => [key, { value: [] }])),
    diagnostics: Object.fromEntries([n.vnet, n.endpoint, n.dnsZone, n.environment, n.app, n.account, q.service,
      n.oldApp, n.oldEnvironment, old.perimeter, r.workspace, r.dcr, ...(n.publicProbe ? [n.publicProbe] : [])].map(id => [id, { value: [] }])), nic: null, effective: null, defender: null,
    images: { repositories: ['missionspec/telemetry-ingest'], manifests: clone(context.origin.receiver.candidate.publication.manifests),
      legacyManifest: JSON.parse(context.origin.receiver.candidate.legacyPublication.manifestJson),
      preparedManifest: JSON.parse(context.origin.receiver.candidate.profile.manifestJson), queueManifest: null, referrers: [] }, managed: {} };
  Object.assign(s.resources, clone(f.opaque.resources));
  s.resources[r.ingestIdentity] = clone(context.origin.receiver.prerequisiteReceipts.core.resources[r.ingestIdentity]);
  s.resources[r.pullIdentity] = clone(context.origin.receiver.prerequisiteReceipts.core.resources[r.pullIdentity]);
  s.resources[r.registry] = { id: r.registry, type: 'Microsoft.ContainerRegistry/registries', name: f.c.registryName,
    properties: { adminUserEnabled: false, anonymousPullEnabled: false } };
  s.resources[r.workspace] = { id: r.workspace, type: 'Microsoft.OperationalInsights/workspaces', name: `${f.c.namePrefix}-analytics`,
    tags: ownerTags(f.c), properties: { retentionInDays: 180, customerId: '00000000-0000-4000-8000-000000000009',
      features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: false } } };
  const data = buildPhase(f.c, 'data', telemetry, context.origin.receiver.prerequisiteReceipts);
  for (const descriptor of data.resources) s.resources[descriptor.id] = { ...clone(descriptor.expected), id: descriptor.id };
  const retainedDcr = context.origin.receiver.prerequisiteReceipts.data.resources[r.dcr];
  Object.assign(s.resources[r.dcr].properties, { immutableId: retainedDcr.properties.immutableId, endpoints: clone(retainedDcr.properties.endpoints) });
  s.resources[r.dcr].properties.destinations.logAnalytics[0].workspaceId = s.resources[r.workspace].properties.customerId;
  s.resources[n.oldApp] = clone(context.origin.receiver.receipt.resources[n.oldApp]);
  s.resources[n.oldEnvironment] = { id: n.oldEnvironment, name: n.oldEnvironment.split('/').at(-1),
    type: 'Microsoft.App/managedEnvironments', location: f.c.location, tags: ownerTags(f.c),
    systemData: { createdAt: '2026-09-23T00:10:00.000Z' }, properties: { provisioningState: 'Succeeded',
      vnetConfiguration: null, infrastructureResourceGroup: null, publicNetworkAccess: 'Enabled', zoneRedundant: false,
      defaultDomain: 'unit-old.australiaeast.azurecontainerapps.io' } };
  const budget = (id, properties) => ({ id, name: id.split('/').at(-1), type: 'Microsoft.Consumption/budgets',
    properties: { ...properties, currentSpend: { amount: 0, unit: 'USD' } } });
  const amounts = privateLinkBudgetConfiguration(f.c, context.plan.topology), steady = privateLinkBudgetConfiguration(f.c, context.plan.topology, true);
  s.resources[r.projectBudget] = budget(r.projectBudget, privateLinkAtLeast(stage, 'set-project-steady-budget') ? steady.project :
    privateLinkAtLeast(stage, 'set-project-migration-budget') ? amounts.project :
      { ...budgetProperties(f.c, 350), filter: projectBudgetFilter(f.c) });
  s.resources[r.budget] = budget(r.budget, privateLinkAtLeast(stage, 'set-telemetry-steady-budget') ? steady.telemetry :
    privateLinkAtLeast(stage, 'set-telemetry-migration-budget') ? amounts.telemetry : budgetProperties(f.c, 300));
  s.resources[r.stateBudget] = budget(r.stateBudget, amounts.state);
  const make = descriptor => {
    const { dependsOn, ...expected } = clone(descriptor.expected);
    return { ...expected, id: descriptor.id, name: descriptor.id.split('/').at(-1),
      systemData: { createdAt: new Date(at).toISOString() }, properties: { ...expected.properties, provisioningState: 'Succeeded' } };
  };
  for (const phase of context.plan.stages) if (privateLinkAtLeast(stage, phase.id)) for (const value of phase.resources) {
    if (value.expected.type !== 'Microsoft.Consumption/budgets' && value.id !== n.app) s.resources[value.id] = make(value);
  }
  s.resources[n.account].properties.publicNetworkAccess = privateLinkAtLeast(stage, 'disable-storage-public') ? 'Disabled' : 'SecuredByPerimeter';
  s.lists.addressSpaces.value = privateInput.addresses.knownAddressSpaces.map((range, i) => ({
    id: `${r.sub}/resourceGroups/unit-existing/providers/Microsoft.Network/virtualNetworks/unit-${i}`,
    properties: { addressSpace: { addressPrefixes: [range] } },
  }));
  if (privateLinkAtLeast(stage, 'create-network')) {
    const p = s.resources[n.vnet].properties;
    p.subnets = [s.resources[n.appsSubnet], s.resources[n.endpointSubnet]];
    p.virtualNetworkPeerings = []; p.dhcpOptions = { dnsServers: [] };
    s.resources[n.endpointSubnet].properties.delegations = [];
    s.lists.subnets.value = clone(p.subnets);
    s.lists.addressSpaces.value.push(s.resources[n.vnet]);
  }
  if (privateLinkAtLeast(stage, 'create-queue-endpoint')) {
    const p = s.resources[n.endpoint].properties, nicId = `${r.group}/providers/Microsoft.Network/networkInterfaces/unit-private-nic`;
    p.networkInterfaces = [{ id: nicId }];
    Object.assign(p.privateLinkServiceConnections[0].properties, { provisioningState: 'Succeeded',
      privateLinkServiceConnectionState: { status: 'Approved', actionsRequired: 'None', description: 'UNIT approved connection' } });
    s.nic = { id: nicId, name: 'unit-private-nic', type: 'Microsoft.Network/networkInterfaces', location: f.c.location,
      properties: { provisioningState: 'Succeeded', privateEndpoint: { id: n.endpoint }, enableIPForwarding: false,
        ipConfigurations: [{ name: 'queue', properties: { provisioningState: 'Succeeded', privateIPAddress: '10.240.8.68',
          privateIPAddressVersion: 'IPv4', privateIPAllocationMethod: 'Dynamic', primary: true, subnet: { id: n.endpointSubnet },
          privateLinkConnectionProperties: { groupId: 'queue', requiredMemberName: 'queue', fqdns: [new URL(f.topology.ids.queueUrl).hostname] } } }] } };
    const connection = { id: `${q.account}/privateEndpointConnections/unit-connection`, properties: { provisioningState: 'Succeeded',
      privateEndpoint: { id: n.endpoint }, privateLinkServiceConnectionState: { status: 'Approved' } } };
    s.resources[n.account].properties.privateEndpointConnections = [clone(connection)];
    s.lists.storageConnections.value = [connection];
    s.resources[n.dnsZone].properties.numberOfVirtualNetworkLinksWithRegistration = 0;
    s.resources[n.dnsLink].properties.virtualNetworkLinkState = 'Completed';
    s.lists.dnsLinks.value = [clone(s.resources[n.dnsLink])];
    s.lists.dnsRecords.value = [{ id: `${n.dnsZone}/A/${q.accountName}`, type: 'Microsoft.Network/privateDnsZones/A',
      name: q.accountName, properties: { ttl: 10, aRecords: [{ ipv4Address: '10.240.8.68' }],
        fqdn: `${q.accountName}.privatelink.queue.core.windows.net.`, isAutoRegistered: false } },
    { id: `${n.dnsZone}/SOA/@`, type: 'Microsoft.Network/privateDnsZones/SOA', name: '@', properties: {} }];
  }
  if (privateLinkAtLeast(stage, 'create-environment')) {
    Object.assign(s.resources[n.environment].properties, { defaultDomain: 'unit.australiaeast.azurecontainerapps.io', staticIp: '203.0.113.15' });
    s.resources[n.managedGroup] = { id: n.managedGroup, location: f.c.location, managedBy: n.environment, properties: { provisioningState: 'Succeeded' } };
    const ip = `${n.managedGroup}/providers/Microsoft.Network/publicIPAddresses/unit-ip`;
    const lb = `${n.managedGroup}/providers/Microsoft.Network/loadBalancers/unit`;
    s.managed = { [ip]: { id: ip, name: 'unit-ip', type: 'Microsoft.Network/publicIPAddresses', location: f.c.location,
      sku: { name: 'Standard' }, properties: { provisioningState: 'Succeeded', ipAddress: '203.0.113.15',
        publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' } },
    [lb]: { id: lb, name: 'unit', type: 'Microsoft.Network/loadBalancers', location: f.c.location, sku: { name: 'Standard' },
      properties: { provisioningState: 'Succeeded', frontendIPConfigurations: [{ properties: { publicIPAddress: { id: ip } } }],
        backendAddressPools: [], loadBalancingRules: [], probes: [] } } };
    s.lists.managedResources.value = Object.values(s.managed).map(({ id, type }) => ({ id, type }));
  }
  for (const [id, retired] of [[old.rule, 'retire-nsp-rule'], [old.association, 'retire-nsp-association'],
    [old.profile, 'retire-nsp-profile'], [old.perimeter, 'retire-nsp-perimeter'], [n.oldApp, 'retire-old-receiver'], [n.oldEnvironment, 'retire-old-environment']]) {
    if (privateLinkAtLeast(stage, retired)) s.resources[id] = null;
  }
  if (s.resources[old.profile]) s.resources[old.profile].properties.accessRulesVersion = privateLinkAtLeast(stage, 'retire-nsp-rule') ? '2' : '1';
  for (const [key, id] of [['rules', old.rule], ['profiles', old.profile], ['associations', old.association]]) s.lists[key].value = s.resources[id] ? [clone(s.resources[id])] : [];
  if (s.resources[old.association]) {
    s.effective = clone(f.opaque.configuration);
    if (privateLinkAtLeast(stage, 'retire-nsp-rule')) {
      s.effective.properties.profile.accessRules = []; s.effective.properties.profile.accessRulesVersion = 2;
    }
    s.lists.effective.value = [clone(s.effective)];
  }
  s.lists.queues.value = [clone(s.resources[q.queue])];
  for (const [id, expected] of [[q.role, d.queueRole], [q.assignment, d.queueAssignment]]) if (s.resources[id]) {
    delete s.resources[id].properties.provisioningState;
    s.resources[id].properties.createdOn = s.resources[id].systemData.createdAt;
    if (id === q.assignment) s.resources[id].properties.scope = q.queue;
  }
  if (s.resources[q.assignment]) s.lists.queueGrants.value = [clone(s.resources[q.assignment])];
  s.lists.apps.value = s.resources[n.oldApp] ? [clone(s.resources[n.oldApp])] : [];
  s.lists.groupResources.value = Object.values(s.resources).filter(value => value &&
    value.id?.startsWith(r.group + '/') && !value.id.includes('/providers/Microsoft.Consumption/'));
  return s;
}
function privateControlSetup(f, evidence, stage, options) {
  const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage), previous = evidence.records.at(-1);
  const now = f.at, before = previous ? clone(previous.after) : privateSnapshotFixture(f, 'initial', now);
  before.startedAt = before.completedAt = now;
  const after = privateSnapshotFixture(f, stage, now);
  for (const [id, value] of Object.entries(before.resources)) if (value && after.resources[id]) {
    if (value.systemData) after.resources[id].systemData = clone(value.systemData);
    if (value.properties?.createdOn) after.resources[id].properties.createdOn = value.properties.createdOn;
  }
  if (options.snapshot) { options.snapshot(before); options.snapshot(after); }
  const cost = privateCostFixture(f, now), migrationReview = { version: 1,
    action: 'retire-exact-failed-nsp-intent-and-migrate-private-link', planSha256: f.context.plan.planSha256,
    originSha256: hash(f.context.origin), configSha256: hash(f.c), sourceSha256: f.source,
    pendingNspHeadSha256: hash(f.context.origin.pendingHead), opaqueRuleSha256: hash(f.opaque.resources[f.context.origin.network.topology.ids.rule]),
    opaqueEffectiveSha256: hash(f.opaque.configuration), userInstruction: 'UNIT deliberate exact retirement; not operator authorization.',
    approvedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  migrationReview.userInstructionSha256 = digest(migrationReview.userInstruction);
  const permissions = {};
  for (const { scope, actions } of privateLinkPermissions(f.c, f.context, phase)) {
    permissions[scope] ??= { permissions: { value: [{ actions: [], notActions: [] }] }, denies: { value: [] } };
    permissions[scope].permissions.value[0].actions.push(...actions);
  }
  const catalogs = Object.fromEntries([['network', 'Microsoft.Network'], ['storage', 'Microsoft.Storage'], ['app', 'Microsoft.App']].map(([key, namespace]) => [key, {
    namespace, registrationState: 'Registered', resourceTypes: [...new Map(f.context.plan.stages.flatMap(v => v.resources)
      .filter(d => d.type.startsWith(namespace + '/')).map(d => [d.type, { resourceType: d.type.slice(namespace.length + 1),
        apiVersions: [d.apiVersion], locations: ['Australia East'] }])).values()],
  }]));
  catalogs.network.resourceTypes.push({ resourceType: 'networkSecurityPerimeters', apiVersions: ['2025-09-01'], locations: ['Australia East'] });
  catalogs.storage.resourceTypes.push({ resourceType: 'storageAccounts', apiVersions: [API.storage], locations: ['Australia East'] });
  const requests = privateLinkReadRequests(f.c, f.context);
  const deployment = phase.deploymentId ? { id: phase.deploymentId, properties: { provisioningState: 'Succeeded',
    mode: 'Incremental', correlationId: 'UNIT-private-link', timestamp: new Date(now).toISOString(), templateHash: hash(phase.template),
    outputResources: phase.resources.map(({ id }) => ({ id })) } } : null;
  const operations = phase.deploymentId ? { value: phase.resources.map((d, i) => ({
    id: `${phase.deploymentId}/operations/unit-${i}`, operationId: `unit-${i}`,
    properties: { provisioningState: 'Succeeded', provisioningOperation: 'Create', statusCode: 'OK',
      targetResource: { id: d.id, resourceType: d.type, resourceName: d.expected.name } },
  })) } : null;
  return { phase, before, after, cost, migrationReview, permissions, catalogs, requests, deployment, operations };
}
async function controlHarnessFromSetup(f, evidence, stage, options, setup) {
  const { phase, before, after, cost, migrationReview, permissions, catalogs, requests, deployment, operations } = setup;
  let now = f.at, live = before, journal = null, head = privateLinkHead(f.context, evidence),
    writes = 0, reserved = false, appended = null, savedIntent = null;
  const traces = clone(setup.traces ?? []), retained = clone(setup.retained ?? []);
  const io = { now: () => now, sourceDigest: async () => f.source, sleep: async ms => { now += ms; },
    batch: async (values, map) => Promise.all(values.map(map)), account: async () => clone(live.accountContext),
    registry: async () => clone(live.images), allowPolicyRead: () => {},
    costReview: cost.review, costEvidence: cost.evidence, migrationReview, publication: { commitSha: 'e'.repeat(40), sourceSha256: f.source },
    verifySources: async () => {}, verifyOriginal: async () => {}, nspHead: async () => clone(f.context.origin.pendingHead),
    head: async (_value, pending) => { if (pending) assert.deepEqual(head, pending); else assert.deepEqual(head, privateLinkHead(f.context, evidence)); return clone(head); },
    read: async (request, deadline) => {
      traces.push(request); assert(deadline > now);
      if (request.id === phase.deploymentId) return clone(deployment);
      if (request.id === `${phase.deploymentId}/operations`) return clone(operations);
      if (Object.hasOwn(live.resources, request.id)) return clone(live.resources[request.id]);
      if (Object.hasOwn(live.managed, request.id)) return clone(live.managed[request.id]);
      if (live.nic?.id === request.id) return clone(live.nic);
      if (live.effective?.id === request.id) return clone(live.effective);
      const list = Object.entries(requests).find(([, v]) => v.id === request.id);
      if (list) return clone(live.lists[list[0]]);
      const diagnostics = '/providers/Microsoft.Insights/diagnosticSettings';
      if (request.id.endsWith(diagnostics)) return clone(live.diagnostics[request.id.slice(0, -diagnostics.length)]);
      for (const [scope, value] of Object.entries(permissions)) {
        if (request.id === `${scope}/providers/Microsoft.Authorization/permissions`) return clone(value.permissions);
        if (request.id === `${scope}/providers/Microsoft.Authorization/denyAssignments`) return clone(value.denies);
      }
      for (const provider of Object.values(catalogs)) if (request.id === `${ids(f.c).sub}/providers/${provider.namespace}`) return clone(provider);
      if (/\/(?:policyAssignments|policyExemptions)$/u.test(request.id)) return { value: [] };
      assert.fail('Unexpected unit request ' + request.id);
    },
    retain: async (name, value) => { retained.push({ name, value: clone(value) }); },
    preview: async () => ({ validation: { properties: { provisioningState: 'Succeeded', templateHash: hash(phase.template) } },
      preview: { status: 'Succeeded', changes: phase.resources.map(d => ({ resourceId: d.id, changeType: 'Create',
        after: { ...clone(d.expected), id: d.id } })) } }),
    runtimeCompletion: async () => options.runtimeCompletion ?? null,
    verifyRuntimeCompletion: () => { if (!options.runtimeCompletion) assert.fail('No runtime authority in unit control setup'); },
    journal: async () => journal, saveJournal: async value => { journal = clone(value); },
    reserve: async (_evidence, _phase, intent) => {
      if (reserved) throw new Error('PRIVATE_LINK_INTENT_REPLAY_FORBIDDEN'); reserved = true;
      savedIntent = clone(intent);
      head = { version: 1, kind: 'private-link-pending-head', targetKey: head.targetKey,
        previous: privateLinkHead(f.context, evidence), intentSha256: hash(intent) };
      return clone(head);
    },
    write: async (_phase, guard, current, mark) => {
      await current(); guard(); const marker = await mark(); guard(); marker.beforeInvoke(); writes++; live = after;
    },
    append: async (pending, record, next) => { assert.deepEqual(head, pending); appended = clone(record); head = next; },
  };
  const proof = setup.proof ?? await checkPrivateLinkPhase(f.c, f.context, evidence, phase, io);
  const approval = setup.approval ?? { version: 1, action: `execute-exact-private-link-${stage}`, configSha256: hash(f.c),
    planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding),
    sourceSha256: f.source, requestSha256: hash(phase.request),
    approvedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  return { phase, proof, approval, io, before, after, traces, retained,
    fixtureSetup: { ...setup, proof, approval, traces, retained },
    execute: () => executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, approval, io),
    advance: ms => { now += ms; }, get journal() { return journal; }, get intent() { return savedIntent; }, get writes() { return writes; },
    get appended() { return appended; }, setLive: value => { live = value; } };
}
function controlFixtureKey(f, evidence, stage) {
  return { config: f.c, context: f.context, source: f.source, at: f.at,
    topology: f.topology, opaque: f.opaque, evidence, stage };
}
export async function privateControlHarness(f, evidence, stage, options = {}) {
  if (options.uncached || options.snapshot || options.runtimeCompletion) {
    return controlHarnessFromSetup(f, evidence, stage, options, privateControlSetup(f, evidence, stage, options));
  }
  const setup = await privateLinkCachedFixture('checked-control-setup', controlFixtureKey(f, evidence, stage), async () => {
    const original = await controlHarnessFromSetup(f, evidence, stage, options, privateControlSetup(f, evidence, stage, options));
    return original.fixtureSetup;
  });
  return controlHarnessFromSetup(f, evidence, stage, options, setup);
}
export async function privateControlChain(f, through = 'assign-queue-role', options = {}) {
  const evidence = emptyPrivateLinkControlEvidence(f.context);
  for (const stage of PRIVATE_LINK_CONTROL_STAGES) {
    const build = async () => {
      const q = await privateControlHarness(f, evidence, stage, options);
      return q.execute();
    };
    const record = options.uncached ? await build() :
      await privateLinkCachedFixture('verified-control-prefix', controlFixtureKey(f, evidence, stage), build);
    evidence.records.push(record); f.at += 1000;
    if (stage === through) return evidence;
  }
  return evidence;
}
