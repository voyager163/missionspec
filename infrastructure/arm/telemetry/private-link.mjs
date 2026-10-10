import { isDeepStrictEqual, types } from 'node:util';
import { AsyncLocalStorage } from 'node:async_hooks';
import { BUDGET, budgetProperties, closed, digestJson, fail, ids, ownerTags, projectBudgetFilter, sameId, validateConfig } from './definition.mjs';
import { durableQueueCost, QUEUE_PROFILE_KIND, QUEUE_RUNTIME, queueEnvironment, queueResources, verifyQueueTopology } from './durable-queue.mjs';
import { verifyQueueAdoptionRecord } from './queue-adoption.mjs';
import { queueDefenderInventory } from './queue-defender.mjs';
import { nspTargetKey, verifyNspEvidence } from './nsp.mjs';
import { verifyNspStoppedAttempt } from './nsp-reconciliation.mjs';
import { verifyDisabledImageRecord, verifyReceiverProfile } from './receiver-upgrade.mjs';

export const PRIVATE_LINK_API = Object.freeze({ network: '2024-05-01', dns: '2024-06-01',
  app: '2025-07-01', storage: '2025-01-01', deployment: '2022-09-01', authorization: '2022-04-01' });
export const PRIVATE_LINK_AUTHORITY = Object.freeze({ deployment: false, retirement: false, imagePublication: false,
  queueGrants: false, ingestion: false, clientActivation: false, budgetMutation: false, productionClearance: false });

export function privateLinkRuntimeNameIds(c) {
  const r = ids(c), app = name => `${r.group}/providers/Microsoft.App/containerApps/${name}`;
  return { original: { app: app(`${c.namePrefix}-private-ingest`), publicProbe: app(`${c.namePrefix}-public-probe`) },
    projected: { app: app(`${c.namePrefix}-pl-ingest`), publicProbe: app(`${c.namePrefix}-pub-probe`) } };
}
export function verifyPrivateLinkRuntimeName(value) {
  if (typeof value !== 'string' || value.length > 32 || !/^[a-z][a-z0-9-]*[a-z0-9]$/u.test(value) || value.includes('--')) {
    fail('PRIVATE_LINK_RUNTIME_NAME_INVALID');
  }
  return value;
}
export function privateLinkAssignedPrefix(evidence) {
  const stages = PRIVATE_LINK_CONTROL_STAGES.slice(0, PRIVATE_LINK_CONTROL_STAGES.indexOf('assign-queue-role') + 1);
  if (!evidence || !Array.isArray(evidence.records) || evidence.records.length < stages.length ||
      stages.some((stage, index) => evidence.records[index]?.stage !== stage)) fail('PRIVATE_LINK_ASSIGNED_PREFIX_REQUIRED');
  return { ...evidence, records: evidence.records.slice(0, stages.length) };
}
const assignedPrefixHashes = new WeakMap();
export function withPrivateLinkAssignedPrefixHash(evidence, use) {
  const stages = PRIVATE_LINK_CONTROL_STAGES.slice(0, PRIVATE_LINK_CONTROL_STAGES.indexOf('assign-queue-role') + 1);
  if (!Array.isArray(evidence?.records) || evidence.records.length < stages.length ||
      stages.some((stage, index) => evidence.records[index]?.stage !== stage) || assignedPrefixHashes.has(evidence)) return use();
  const seen = new WeakSet();
  const frozen = value => {
    if (value === null || typeof value !== 'object' || seen.has(value)) return true;
    if (!Object.isFrozen(value)) return false;
    seen.add(value);
    return Object.values(value).every(frozen);
  };
  if (!frozen(evidence)) return use();
  // This is a digest of immutable bytes, not a semantic/admission result.
  assignedPrefixHashes.set(evidence, hash(privateLinkAssignedPrefix(evidence)));
  try {
    const result = use();
    if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => assignedPrefixHashes.delete(evidence));
    assignedPrefixHashes.delete(evidence);
    return result;
  } catch (error) { assignedPrefixHashes.delete(evidence); throw error; }
}
export function verifyPrivateLinkNameProjection(c, context, revision, at, evidence = null) {
  closed(revision, ['version', 'action', 'decision', 'configSha256', 'planSha256', 'originSha256', 'controlEvidenceSha256',
    'original', 'projected', 'sourceSha256', 'publication', 'approvedAt', 'expiresAt']);
  closed(revision.original, ['app', 'publicProbe']); closed(revision.projected, ['app', 'publicProbe']);
  closed(revision.publication, ['commitSha', 'sourceSha256']);
  const exact = privateLinkRuntimeNameIds(c);
  if (revision.version !== 1 || revision.action !== 'use-reviewed-private-link-runtime-names' ||
      revision.decision !== 'use-two-shortened-runtime-names' || revision.configSha256 !== hash(c) ||
      revision.planSha256 !== context.plan.planSha256 || revision.originSha256 !== hash(context.origin) ||
      !sha(revision.controlEvidenceSha256) || !sha(revision.sourceSha256) ||
      revision.publication.sourceSha256 !== revision.sourceSha256 || !/^[a-f0-9]{40}$/u.test(revision.publication.commitSha ?? '') ||
      context.plan.version !== 3 || context.plan.topology.ids.app !== exact.original.app ||
      context.plan.topology.ids.publicProbe !== exact.original.publicProbe) fail('PRIVATE_LINK_NAME_PROJECTION_REQUIRED');
  equal(revision.original, exact.original, 'PRIVATE_LINK_ORIGINAL_NAMES_CHANGED');
  equal(revision.projected, exact.projected, 'PRIVATE_LINK_PROJECTED_NAMES_CHANGED');
  for (const id of Object.values(exact.projected)) verifyPrivateLinkRuntimeName(id.split('/').at(-1));
  if (new Set([...Object.values(exact.original), ...Object.values(exact.projected), ids(c).app, ids(c).environment]).size !== 6) {
    fail('PRIVATE_LINK_RUNTIME_NAME_COLLISION');
  }
  const time = value => {
    const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
    if (!Number.isSafeInteger(parsed) || new Date(parsed).toISOString() !== value) fail('PRIVATE_LINK_NAME_REVIEW_TIME_INVALID');
    return parsed;
  };
  const start = time(revision.approvedAt), end = time(revision.expiresAt);
  if (!Number.isSafeInteger(at) || at < start || at >= end || end <= start || end - start > 3600000) fail('PRIVATE_LINK_NAME_REVIEW_EXPIRED');
  if (evidence !== null && revision.controlEvidenceSha256 !==
      (assignedPrefixHashes.get(evidence) ?? hash(privateLinkAssignedPrefix(evidence)))) fail('PRIVATE_LINK_NAME_PREFIX_CHANGED');
  return exact;
}
// Only current runtime coordinates are projected. The caller continues validating all
// historical records against the original context and passes that original prefix here.
export function privateLinkRuntimeResources(c, context, nameProjection = null, evidence = null, at = null) {
  const resources = privateLinkResources(c, context.plan.topology, context.origin);
  const n = { ...context.plan.topology.ids };
  if (nameProjection === null) return { ids: n, resources, legacyAbsentIds: [] };
  const times = at ?? Date.parse(nameProjection.approvedAt);
  const names = verifyPrivateLinkNameProjection(c, context, nameProjection, times, evidence);
  for (const [key, member] of [['app', 'app'], ['publicProbe', 'publicProbe']]) {
    resources[member] = structuredClone(resources[member]);
    resources[member].id = names.projected[key];
    resources[member].expected.name = names.projected[key].split('/').at(-1);
    n[key] = names.projected[key];
  }
  return { ids: n, resources, legacyAbsentIds: Object.values(names.original) };
}
export function privateLinkNameBinding(c, context, revision, evidence = null) {
  verifyPrivateLinkNameProjection(c, context, revision, Date.parse(revision.approvedAt), evidence);
  const { configSha256, planSha256, originSha256, controlEvidenceSha256, original, projected } = revision;
  return { version: 1, kind: 'private-link-short-runtime-names', configSha256, planSha256, originSha256,
    controlEvidenceSha256, original: structuredClone(original), projected: structuredClone(projected) };
}
export function verifyPrivateLinkNameBinding(c, binding) {
  closed(binding, ['version', 'kind', 'configSha256', 'planSha256', 'originSha256', 'controlEvidenceSha256', 'original', 'projected']);
  if (binding.version !== 1 || binding.kind !== 'private-link-short-runtime-names' || binding.configSha256 !== hash(c) ||
      !['planSha256', 'originSha256', 'controlEvidenceSha256'].every(key => sha(binding[key]))) fail('PRIVATE_LINK_NAME_BINDING_INVALID');
  const names = privateLinkRuntimeNameIds(c);
  equal(binding.original, names.original, 'PRIVATE_LINK_ORIGINAL_NAMES_CHANGED');
  equal(binding.projected, names.projected, 'PRIVATE_LINK_PROJECTED_NAMES_CHANGED');
  Object.values(names.projected).forEach(id => verifyPrivateLinkRuntimeName(id.split('/').at(-1)));
  return names;
}
export const PRIVATE_LINK_STAGES = Object.freeze([
  'review-migration', 'set-project-migration-budget', 'set-telemetry-migration-budget',
  'retire-nsp-rule', 'create-network', 'create-queue-endpoint', 'create-environment',
  'disable-storage-public', 'retire-nsp-association', 'retire-nsp-profile', 'retire-nsp-perimeter',
  'create-queue-role', 'assign-queue-role', 'publish-queue-image', 'create-disabled-receiver',
  'qualify-private-delivery', 'retire-old-receiver', 'retire-old-environment',
  'set-project-steady-budget', 'set-telemetry-steady-budget', 'record-migration',
]);
export const PRIVATE_LINK_RUNTIME_STAGES = Object.freeze(['publish-queue-image', 'create-disabled-receiver', 'qualify-private-delivery']);
export const PRIVATE_LINK_CONTROL_STAGES = Object.freeze(PRIVATE_LINK_STAGES.filter(value => !PRIVATE_LINK_RUNTIME_STAGES.includes(value)));
export const PRIVATE_LINK_LIMITS = Object.freeze({ commandMs: 15000, checkMs: 120000, rolloutMs: 120000,
  environmentRolloutMs: 1800000, freshnessMs: 300000, reviewMs: 3600000, concurrency: 4,
  pages: 32, items: 2048, bytes: 16 * 1024 * 1024, pollMs: 3000 });
export const PRIVATE_LINK_BUDGETS = Object.freeze({ migration: { project: 425, telemetry: 375, state: 50 },
  steady: { project: 375, telemetry: 325, state: 50 } });
const hash = digestJson;
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const equal = (actual, expected, code) => { if (!isDeepStrictEqual(actual, expected)) fail(code); };
const networkReserved = ['169.254.0.0/16', '172.30.0.0/16', '172.31.0.0/16', '192.0.2.0/24',
  '100.100.0.0/17', '100.100.128.0/19', '100.100.160.0/19', '100.100.192.0/19'];

function cidr(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}\/(?:[0-9]|[12][0-9]|3[0-2])$/u.test(value)) {
    fail('PRIVATE_LINK_CANONICAL_IPV4_CIDR_REQUIRED');
  }
  const [ip, bits] = value.split('/'), parts = ip.split('.').map(Number), prefix = Number(bits);
  if (parts.some(part => part > 255)) fail('PRIVATE_LINK_CANONICAL_IPV4_CIDR_REQUIRED');
  const start = parts.reduce((sum, part) => sum * 256 + part, 0), size = 2 ** (32 - prefix);
  if (start % size !== 0) fail('PRIVATE_LINK_CANONICAL_IPV4_CIDR_REQUIRED');
  return { start, end: start + size - 1, prefix };
}
const overlap = (a, b) => a.start <= b.end && b.start <= a.end;
const contains = (a, b) => a.start <= b.start && a.end >= b.end;

export function privateLinkAddresses(input) {
  closed(input, ['vnet', 'apps', 'endpoint', 'knownAddressSpaces']);
  const vnet = cidr(input.vnet), apps = cidr(input.apps), endpoint = cidr(input.endpoint);
  if (vnet.prefix !== 24 || apps.prefix !== 26 || endpoint.prefix !== 28 ||
      !['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some(value => contains(cidr(value), vnet)) ||
      !contains(vnet, apps) || !contains(vnet, endpoint) || overlap(apps, endpoint) ||
      networkReserved.some(value => overlap(vnet, cidr(value)))) fail('PRIVATE_LINK_ADDRESS_SCOPE_INVALID');
  if (!Array.isArray(input.knownAddressSpaces) || input.knownAddressSpaces.length > 512 ||
      new Set(input.knownAddressSpaces).size !== input.knownAddressSpaces.length) fail('PRIVATE_LINK_ADDRESS_INVENTORY_INVALID');
  for (const value of input.knownAddressSpaces) if (overlap(vnet, cidr(value))) fail('PRIVATE_LINK_ADDRESS_OVERLAP');
  return structuredClone(input);
}
export function privateLinkIpInSubnet(ip, range) {
  if (typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(ip)) return false;
  const address = cidr(`${ip}/32`), subnet = cidr(range);
  return contains(subnet, address) && address.start >= subnet.start + 4 && address.start < subnet.end;
}
export function privateLinkStageIndex(stage) {
  const index = PRIVATE_LINK_STAGES.indexOf(stage);
  if (index < 0 && stage !== 'initial') fail('PRIVATE_LINK_FIXED_STAGE_REQUIRED');
  return index;
}
export function privateLinkAtLeast(stage, required) {
  return privateLinkStageIndex(stage) >= privateLinkStageIndex(required);
}
export function privateLinkBudgetConfiguration(c, topology, steady = false) {
  const amounts = PRIVATE_LINK_BUDGETS[steady ? 'steady' : 'migration'];
  const filter = structuredClone(projectBudgetFilter(c));
  filter.dimensions.values.push(topology.ids.managedGroup.split('/').at(-1));
  return { project: { ...budgetProperties(c, amounts.project), filter },
    telemetry: budgetProperties(c, amounts.telemetry), state: budgetProperties(c, amounts.state) };
}

export function privateLinkCost(overlapDays, publicProbe = false) {
  if (typeof publicProbe !== 'boolean') fail('PRIVATE_LINK_PUBLIC_PROBE_COST_INVALID');
  if (!Number.isInteger(overlapDays) || overlapDays < 1 || overlapDays > 7) fail('PRIVATE_LINK_OVERLAP_REVIEW_REQUIRED');
  const base = durableQueueCost();
  if (base.total !== 349.37) fail('PRIVATE_LINK_BASE_COST_CHANGED');
  const incremental = { endpointHours: 744 * 0.01, privateDnsZone: 0.50, millionDnsQueries: 0.40,
    privateLinkData100GB: 100 * 0.01, loadBalancerData200GB: 200 * 0.005 };
  const overlapMonthly = { warmCompute: base.previous.items.warmCpu + base.previous.items.warmMemory,
    managementReserve: base.previous.items.ambiguousEnvironmentManagement, loadBalancer: 744 * 0.025,
    publicIps: 744 * 2 * 0.005, securityReserve: base.previous.items.defenderCspmTwoFullNodes,
    oldEndpointRequests: base.previous.items.requests };
  const ceiling = value => Math.ceil((value - 1e-9) * 100) / 100;
  const steady = ceiling(base.total + Object.values(incremental).reduce((a, b) => a + b, 0));
  return { version: 1, currency: 'USD', days: 31, carriedForwardBase: base.total, baseRepriced: false,
    incremental, steadyMonthly: steady, overlapMonthly, overlapDays,
    migrationMonth: ceiling(steady + Object.values(overlapMonthly).reduce((a, b) => a + b, 0) * overlapDays / 31 + (publicProbe ? 1 : 0)),
    proposedSteadyPlanning: 375, proposedMigrationPlanning: 425, planningApproved: false,
    actualBudgetSettings: BUDGET, isHardCap: false, originalReservesPreserved: true,
    exclusions: ['taxes', 'unverified residual NSP charges', 'new policy-mandated infrastructure'],
    retirementRequiredForSteadyEstimate: true, freshPricingReviewRequired: true,
    ...(publicProbe ? { transientPublicProbe: { maximumMs: 900000, reserveUSD: 1, additionalEnvironments: 0,
      maximumInstances: 1, cpu: 0.25, memoryGiB: 0.5, disabledOnly: true } } : {}) };
}

export function privateLinkTopology(c, queue, input) {
  validateConfig(c); verifyQueueTopology(c, queue);
  closed(input, ['version', 'addresses', 'overlapDays']);
  if (![1, 2].includes(input.version)) fail('PRIVATE_LINK_INPUT_VERSION_REQUIRED');
  const addresses = privateLinkAddresses(input.addresses), r = ids(c);
  const name = `${c.namePrefix}-queue-${queue.namespace}`, vnet = `${r.group}/providers/Microsoft.Network/virtualNetworks/${name}`;
  const endpoint = `${r.group}/providers/Microsoft.Network/privateEndpoints/${name}`;
  const dnsZone = `${r.group}/providers/Microsoft.Network/privateDnsZones/privatelink.queue.core.windows.net`;
  const managedGroup = `${r.sub}/resourceGroups/${c.namePrefix}-private-managed`;
  return { version: 1, kind: 'private-link-queue-replacement', configSha256: hash(c), queueTopologySha256: hash(queue),
    addresses, location: c.location,
    ids: { vnet, appsSubnet: `${vnet}/subnets/apps`, endpointSubnet: `${vnet}/subnets/private-endpoints`,
      endpoint, dnsZone, dnsLink: `${dnsZone}/virtualNetworkLinks/${name}`,
      dnsZoneGroup: `${endpoint}/privateDnsZoneGroups/queue`,
      environment: `${r.group}/providers/Microsoft.App/managedEnvironments/${c.namePrefix}-private-environment`,
      app: `${r.group}/providers/Microsoft.App/containerApps/${c.namePrefix}-private-ingest`, managedGroup,
      ...(input.version === 2 ? { publicProbe: `${r.group}/providers/Microsoft.App/containerApps/${c.namePrefix}-public-probe` } : {}),
      account: queue.ids.account, queue: queue.ids.queue, ingestIdentity: r.ingestIdentity, pullIdentity: r.pullIdentity,
      oldEnvironment: r.environment, oldApp: r.app },
    queueUrl: queue.ids.queueUrl, subresources: ['queue'], tlsVerification: 'required',
    receiverIngress: 'public-https', storagePublicNetworkAccess: 'Disabled',
    registryAndMonitorPath: 'existing-reviewed-https-not-private-link',
    addressInventoryVerified: false, exactManagedGroupAbsenceRequired: true,
    budgetCoverage: { existingFilter: projectBudgetFilter(c), additionalResourceGroup: managedGroup,
      explicitFilterReviewRequired: true, automaticBudgetChange: false },
    cost: privateLinkCost(input.overlapDays, input.version === 2), authority: PRIVATE_LINK_AUTHORITY };
}

export function verifyPrivateLinkContext(c, context) {
  closed(context, ['adoption', 'network', 'original', 'pendingHead', 'receiver', 'queueProfile']);
  const { adoption, network, original, pendingHead, receiver, queueProfile } = context;
  verifyQueueAdoptionRecord(c, adoption);
  verifyNspEvidence(c, network, adoption.topology, adoption);
  verifyNspStoppedAttempt(c, original, adoption.topology, adoption, network, pendingHead);
  if (original.phase.phase !== 'nsp-subscription-admission' || original.journal.failureCode !== 'NSP_RULE_DRIFT' ||
      network.records.length !== 3 || network.records.at(-1).receipt.stage !== 'enforced-empty' ||
      original.receipt !== null) fail('PRIVATE_LINK_STOPPED_RULE_ORIGIN_REQUIRED');
  verifyDisabledImageRecord(c, receiver);
  if (receiver.phase.phase !== 'disabled-image-upgrade' ||
      receiver.candidate.version !== 1 || receiver.receipt.ingestionEnabled !== false ||
      original.preflight.foundationBinding.receiverRecordSha256 !== hash(receiver) ||
      original.preflight.foundationBinding.receiverManifestDigest !== receiver.candidate.profile.manifestDigest ||
      original.preflight.foundationBinding.receiverConfigDigest !== receiver.candidate.profile.configDigest) fail('PRIVATE_LINK_DISABLED_RECEIVER_REQUIRED');
  verifyReceiverProfile(queueProfile);
  if (queueProfile.version !== 2 || queueProfile.kind !== QUEUE_PROFILE_KIND ||
      queueProfile.manifestDigest === receiver.candidate.profile.manifestDigest) fail('PRIVATE_LINK_QUEUE_PROFILE_REQUIRED');
  equal(JSON.parse(queueProfile.configJson).config, JSON.parse(receiver.candidate.profile.configJson).config,
    'PRIVATE_LINK_IMAGE_DEFAULTS_CHANGED');
  return context;
}

function descriptor(id, type, apiVersion, properties, extra = {}) {
  const parts = id.split('/providers/')[1].split('/');
  const name = parts.filter((_, index) => index > 0 && index % 2 === 0).join('/');
  return { id, type, apiVersion, expected: { type, apiVersion, name, properties, ...extra } };
}

export function privateLinkResources(c, topology, context) {
  const n = topology.ids, r = ids(c), tags = ownerTags(c), regional = { location: c.location, tags };
  const network = PRIVATE_LINK_API.network, dns = PRIVATE_LINK_API.dns;
  const subnet = (id, properties) => descriptor(id, 'Microsoft.Network/virtualNetworks/subnets', network, properties);
  const app = structuredClone(context.receiver.phase.resources[0]);
  app.id = n.app;
  app.expected.name = n.app.split('/').at(-1);
  app.expected.properties.managedEnvironmentId = n.environment;
  const container = app.expected.properties.template.containers[0];
  container.image = `${c.registryName}.azurecr.io/missionspec/telemetry-ingest@${context.queueProfile.manifestDigest}`;
  const env = new Map(container.env.map(value => [value.name, value]));
  if (env.size !== container.env.length || env.get('MSR_INGESTION_ENABLED')?.value !== 'false') fail('PRIVATE_LINK_DISABLED_RECEIVER_REQUIRED');
  for (const [name, value] of Object.entries(queueEnvironment(context.adoption.topology))) {
    if (env.has(name)) fail('PRIVATE_LINK_PREPARED_RECEIVER_REQUIRED');
    env.set(name, { name, value });
  }
  container.env = [...env.values()];
  const publicProbe = topology.ids.publicProbe ? structuredClone(app) : null;
  if (publicProbe) {
    publicProbe.id = topology.ids.publicProbe;
    publicProbe.expected.name = publicProbe.id.split('/').at(-1);
    publicProbe.expected.properties.managedEnvironmentId = n.oldEnvironment;
  }
  const queue = queueResources(c, context.adoption.topology, context.adoption.identity);
  const defender = context.adoption.version === 3 ? context.adoption.proposal.defender : null;
  const defenderIds = defender ? [defender.snapshot.settings.id,
    ...Object.keys(queueDefenderInventory(c, context.adoption.origin, defender))] : [];
  return {
    vnet: descriptor(n.vnet, 'Microsoft.Network/virtualNetworks', network,
      { addressSpace: { addressPrefixes: [topology.addresses.vnet] } }, regional),
    appsSubnet: subnet(n.appsSubnet, { addressPrefix: topology.addresses.apps,
      delegations: [{ name: 'container-apps', properties: { serviceName: 'Microsoft.App/environments' } }] }),
    endpointSubnet: subnet(n.endpointSubnet, { addressPrefix: topology.addresses.endpoint,
      privateEndpointNetworkPolicies: 'Disabled' }),
    endpoint: descriptor(n.endpoint, 'Microsoft.Network/privateEndpoints', network, {
      subnet: { id: n.endpointSubnet },
      privateLinkServiceConnections: [{ name: 'queue', properties: { privateLinkServiceId: n.account, groupIds: ['queue'] } }],
    }, regional),
    dnsZone: descriptor(n.dnsZone, 'Microsoft.Network/privateDnsZones', dns, {}, { location: 'global', tags }),
    dnsLink: descriptor(n.dnsLink, 'Microsoft.Network/privateDnsZones/virtualNetworkLinks', dns,
      { registrationEnabled: false, virtualNetwork: { id: n.vnet } }, { location: 'global', tags }),
    dnsZoneGroup: descriptor(n.dnsZoneGroup, 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups', network,
      { privateDnsZoneConfigs: [{ name: 'queue', properties: { privateDnsZoneId: n.dnsZone } }] }),
    environment: descriptor(n.environment, 'Microsoft.App/managedEnvironments', PRIVATE_LINK_API.app,
      { publicNetworkAccess: 'Enabled', workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }],
        zoneRedundant: false, infrastructureResourceGroup: n.managedGroup.split('/').at(-1),
        appLogsConfiguration: { destination: 'none' },
        vnetConfiguration: { infrastructureSubnetId: n.appsSubnet, internal: false } }, regional),
    app, ...(publicProbe ? { publicProbe } : {}), queueRole: queue['queue-role'][0], queueAssignment: queue['queue-assignment'][0],
    preserved: [r.registry, r.ingestIdentity, r.pullIdentity, r.workspace, r.table, r.dcr, n.account,
      context.adoption.topology.ids.service, n.queue, ...defenderIds],
  };
}
export function privateLinkPublicProbeDescriptor(c, context) {
  verifyPrivateLinkControlContext(c, context);
  const descriptor = privateLinkResources(c, context.plan.topology, context.origin).publicProbe;
  if (!descriptor) fail('PRIVATE_LINK_PUBLIC_PROBE_PLAN_REQUIRED');
  return descriptor;
}

export function buildPrivateLinkPlan(c, context, input, sourceSha256) {
  if (!sha(sourceSha256)) fail('PRIVATE_LINK_SOURCE_BINDING_REQUIRED');
  verifyPrivateLinkContext(c, context);
  const topology = privateLinkTopology(c, context.adoption.topology, input), r = ids(c);
  const n = topology.ids, old = context.network.topology.ids, resources = privateLinkResources(c, topology, context);
  const stages = [];
  const add = (id, resources, request, requirements) => {
    const previous = stages.at(-1);
    stages.push({ id, requires: previous ? [previous.id] : [], resources, proposedRequest: request,
      requiredEvidence: requirements, executionAuthorized: false, qualified: false });
  };
  const remove = (id, target, apiVersion, requirements) =>
    add(id, [], { method: 'DELETE', id: target, apiVersion, body: null }, requirements);
  const create = (id, keys, requirements) => {
    const selected = keys.map(key => structuredClone(resources[key]));
    for (const value of selected) {
      const dependencies = selected.filter(parent => value.id.startsWith(parent.id + '/') ||
        (value.id === n.dnsZoneGroup && parent.id === n.dnsZone)).map(parent => parent.id);
      if (dependencies.length) value.expected.dependsOn = dependencies;
    }
    const subscriptionScope = id === 'create-queue-role';
    const scope = subscriptionScope ? r.sub : r.group;
    const deployment = `${scope}/providers/Microsoft.Resources/deployments/${c.namePrefix}-pl-${hash(topology).slice(0, 12)}-${stages.length}`;
    add(id, selected, { method: 'PUT', id: deployment, apiVersion: PRIVATE_LINK_API.deployment, body: {
      ...(subscriptionScope ? { location: c.location } : {}),
      properties: { mode: 'Incremental', template: {
        $schema: subscriptionScope ? 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'
          : 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0', resources: selected.map(value => value.expected),
      } },
    } }, requirements);
  };
  add('review-migration', [], null, ['explicit-new-topology-and-cost-approval', 'fresh-policy-permission-and-provider-readback',
    'complete-address-inventory-and-no-overlap', 'new-resources-and-managed-group-absent',
    'project-budget-filter-coverage-reviewed-without-implicit-mutation', 'old-receiver-disabled-and-replacement-absent',
    'current-original-pending-intent-and-opaque-rule-preimage-bound', 'inherited-defender-preservation-review']);
  const budget = (stage, target, steady) => {
    const configuration = privateLinkBudgetConfiguration(c, topology, steady);
    add(stage, [descriptor(target, 'Microsoft.Consumption/budgets', '2024-08-01',
      target === r.projectBudget ? configuration.project : configuration.telemetry)], {
      method: 'PUT', id: target, apiVersion: '2024-08-01',
      body: { properties: target === r.projectBudget ? configuration.project : configuration.telemetry },
    }, ['separate-exact-budget-change-approval', 'exact-current-amount-filter-period-notifications',
      'preserve-notifications-and-state-budget', 'include-private-managed-resource-group']);
  };
  budget('set-project-migration-budget', r.projectBudget, false);
  budget('set-telemetry-migration-budget', r.budget, false);
  remove('retire-nsp-rule', old.rule, context.network.topology.networkApiVersion, [
    'separate-exact-delete-approval', 'raw-rule-preimage-and-generation-match-without-semantic-acceptance',
    'network-list-and-get-rule-absent', 'storage-effective-rules-empty-and-copied-version-converged',
    'no-other-associations-links-or-rules', 'original-failed-attempt-retained', 'data-plane-denial-not-inferred']);
  create('create-network', ['vnet', 'appsSubnet', 'endpointSubnet'],
    ['fresh-create-only-native-validation-and-what-if', 'exact-subnets-and-delegation', 'no-peering-nat-gateway-or-routes', 'no-diagnostic-export']);
  create('create-queue-endpoint', ['endpoint', 'dnsZone', 'dnsLink', 'dnsZoneGroup'],
    ['fresh-create-only-native-validation-and-what-if', 'exact-queue-subresource-and-approved-storage-connection',
      'endpoint-nic-ip-within-endpoint-subnet', 'only-intended-private-dns-a-record-and-vnet-link', 'no-blob-endpoint-or-public-fallback']);
  create('create-environment', ['environment'], ['fresh-create-only-native-validation-and-what-if',
    'exact-consumption-profile-and-external-ingress', 'exact-app-subnet-and-platform-managed-group',
    'platform-managed-lb-ip-inventory-and-budget-coverage', 'logging-and-exports-disabled', 'no-platform-managed-resource-direct-writes']);
  add('disable-storage-public', [], { method: 'PATCH', id: n.account, apiVersion: PRIVATE_LINK_API.storage,
    body: { properties: { publicNetworkAccess: 'Disabled' } } },
  ['enforced-association-and-empty-rules-still-current', 'exact-account-preimage-and-amount-of-change',
    'only-public-network-access-changed', 'queue-and-defender-security-configuration-preserved']);
  remove('retire-nsp-association', old.association, context.network.topology.networkApiVersion,
    ['storage-public-network-access-disabled-before-dispatch', 'rules-empty', 'exact-association-generation',
      'network-association-absent-and-storage-effective-configurations-empty', 'private-endpoint-preserved']);
  remove('retire-nsp-profile', old.profile, context.network.topology.networkApiVersion,
    ['no-associations-rules-or-links', 'exact-profile-generation', 'profile-list-and-get-absence']);
  remove('retire-nsp-perimeter', old.perimeter, context.network.topology.networkApiVersion,
    ['exact-empty-perimeter-generation', 'perimeter-absence', 'no-other-perimeter-resource-deletion']);
  create('create-queue-role', ['queueRole'], ['fresh-native-validation-and-what-if', 'unchanged-exact-queue-permissions',
    'no-role-assignment-yet', 'current-private-endpoint-and-public-disabled-network-proof']);
  create('assign-queue-role', ['queueAssignment'], ['fresh-native-validation-and-what-if', 'exact-existing-ingest-uami-principal',
    'queue-only-assignment-and-role-definition-readback', 'no-broad-account-role-or-identity-replacement']);
  add('publish-queue-image', [], null, ['separate-single-copy-publication-approval', 'fresh-unsuppressed-scan-and-source-notice-provenance',
    'same-qualified-local-image', 'exact-three-image-registry-inventory', 'no-retry-after-unknown-copy', 'credential-cleanup']);
  create('create-disabled-receiver', ['app'], ['fresh-create-only-native-validation-and-what-if',
    'published-exact-image-config-and-three-image-inventory', 'same-uami-runtime-and-pull-lifecycles',
    'replacement-fqdn-readback', 'readiness-and-ingestion-false-503', 'old-receiver-stays-disabled']);
  add('qualify-private-delivery', [], null, ['separate-paired-bounded-enable-disable-approval',
    'actual-same-uami-queue-hostname-resolves-to-owned-private-endpoint-ip', 'tls-hostname-verification',
    'private-path-success-and-unintended-path-denial', 'no-unauthorized-principal-access',
    'one-second-client-and-650ms-durable-ack', 'actual-owned-nine-column-logs-rows-and-180-day-retention',
    'bounded-worker-upload-and-approximate-drain', 'final-both-receivers-disabled-503',
    'no-blob-scanner-functionality-claim-or-blob-test']);
  remove('retire-old-receiver', n.oldApp, PRIVATE_LINK_API.app,
    ['separate-retirement-approval', 'replacement-qualified-and-disabled', 'old-app-generation-and-image-bound',
      'no-outstanding-worker-or-unknown-request', 'old-app-absence', 'no-image-or-evidence-deletion']);
  remove('retire-old-environment', n.oldEnvironment, PRIVATE_LINK_API.app,
    ['separate-retirement-approval', 'old-environment-empty-and-generation-bound',
      'platform-owned-cleanup-observed-not-directly-performed', 'actual-overlap-days-and-spend-reviewed']);
  budget('set-project-steady-budget', r.projectBudget, true);
  budget('set-telemetry-steady-budget', r.budget, true);
  add('record-migration', [], null, ['append-only-private-link-lineage-and-physical-target-cas',
    'original-nsp-execution-remains-failed', 'original-journals-approvals-and-records-unchanged',
    'pending-nsp-intent-resolved-only-by-separate-reviewed-retirement-receipt',
    'old-nsp-admission-never-reusable', 'no-client-endpoint-or-release-activation']);
  equal(stages.map(value => value.id), PRIVATE_LINK_STAGES, 'PRIVATE_LINK_STAGE_DRIFT');
  const body = { version: input.version === 2 ? 3 : 2, kind: 'local-private-link-migration-plan', configSha256: hash(c), sourceSha256,
    input: structuredClone(input), topology, contextSha256: hash(context),
    originalAttemptSha256: hash(context.original), pendingHeadSha256: hash(context.pendingHead),
    physicalTargetKey: nspTargetKey(context.network.topology), originalOutcome: context.original.journal.outcome,
    originalExecutionQualified: false, originalHistoryModified: false, originalIntentReplayAuthorized: false,
    receiverRecordSha256: hash(context.receiver), queueProfileSha256: hash(context.queueProfile),
    receiverManifestDigest: context.queueProfile.manifestDigest, preservedResourceIds: resources.preserved,
    ...(resources.publicProbe ? { publicProbe: resources.publicProbe } : {}),
    runtime: QUEUE_RUNTIME, authority: PRIVATE_LINK_AUTHORITY, stages,
    executable: true, cloudPreflightPerformed: false, liveQualificationPerformed: false,
    requiredNextReview: 'approve-exact-fresh-phase-state-cost-and-one-dispatch',
    unsupportedCommands: [],
  };
  return { ...body, planSha256: hash(body) };
}
// Only synchronous checks share this proof; its inputs are deeply immutable.
let synchronousContextProof = null;
const immutableContextProofs = new AsyncLocalStorage();
export function withPrivateLinkImmutableControlValidation(c, context, use) {
  const seen = new WeakSet();
  const immutable = value => {
    if (value === null || ['string', 'boolean'].includes(typeof value) ||
        typeof value === 'number' && Number.isFinite(value)) return true;
    if (typeof value !== 'object') return false;
    if (seen.has(value)) return true;
    if (types.isProxy(value) || !Object.isFrozen(value) ||
        !Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
    seen.add(value);
    return Object.values(Object.getOwnPropertyDescriptors(value))
      .every(descriptor => Object.hasOwn(descriptor, 'value') && immutable(descriptor.value));
  };
  if (!immutable(c) || !immutable(context)) fail('PRIVATE_LINK_IMMUTABLE_CONTEXT_REQUIRED');
  const scope = { c, context, active: true, verified: false };
  try {
    const result = immutableContextProofs.run(scope, use);
    if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => { scope.active = false; });
    scope.active = false; return result;
  } catch (error) { scope.active = false; throw error; }
}
function verifiedImmutableContext(c, context) {
  const scope = immutableContextProofs.getStore();
  if (!scope) return false;
  if (!scope.active) fail('PRIVATE_LINK_CONTEXT_VALIDATION_SCOPE_CLOSED');
  if (scope.c !== c || scope.context !== context) return false;
  // Only this scope's private frozen pair can reuse its pure plan proof.
  if (!scope.verified) {
    closed(context, ['plan', 'origin']);
    verifyPrivateLinkPlan(c, context.origin, context.plan, context.plan?.sourceSha256);
    scope.verified = true;
  }
  return true;
}
function freezeContext(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freezeContext); Object.freeze(value);
  }
  return value;
}
export function withPrivateLinkControlValidation(c, context, verify) {
  if (verifiedImmutableContext(c, context)) {
    const result = verify();
    if (result && typeof result.then === 'function') fail('PRIVATE_LINK_SYNCHRONOUS_VALIDATION_REQUIRED');
    return result;
  }
  closed(context, ['plan', 'origin']);
  verifyPrivateLinkPlan(c, context.origin, context.plan, context.plan?.sourceSha256);
  const previous = synchronousContextProof;
  synchronousContextProof = { c: freezeContext(c), context: freezeContext(context) };
  try {
    const result = verify();
    if (result && typeof result.then === 'function') fail('PRIVATE_LINK_SYNCHRONOUS_VALIDATION_REQUIRED');
    return result;
  } finally { synchronousContextProof = previous; }
}
export function verifyPrivateLinkControlContext(c, context) {
  if (verifiedImmutableContext(c, context)) return context;
  if (synchronousContextProof?.c === c && synchronousContextProof.context === context) return context;
  closed(context, ['plan', 'origin']);
  verifyPrivateLinkPlan(c, context.origin, context.plan, context.plan?.sourceSha256);
  return context;
}
export function privateLinkPhase(c, context, stage, version = stage === 'create-environment' ? 2 : 1) {
  verifyPrivateLinkControlContext(c, context);
  if (!PRIVATE_LINK_CONTROL_STAGES.includes(stage)) fail('PRIVATE_LINK_CONTROL_STAGE_REQUIRED');
  if (version !== 1 && !(version === 2 && stage === 'create-environment')) fail('PRIVATE_LINK_WIRE_VERSION_UNSUPPORTED');
  const selected = context.plan.stages.find(value => value.id === stage);
  const request = structuredClone(selected.proposedRequest), resourceIds = [];
  if (request?.method === 'DELETE' || stage === 'disable-storage-public') resourceIds.push(request.id);
  const resources = structuredClone(selected.resources);
  for (const id of resourceIds) {
    const isStorage = id === context.plan.topology.ids.account;
    const source = isStorage ? queueResources(c, context.origin.adoption.topology)['queue-storage'][0] : null;
    const parts = id.split('/providers/')[1].split('/');
    const value = source ?? descriptor(id, [parts[0], ...parts.filter((_, i) => i % 2 === 1)].join('/'), request.apiVersion, {});
    if (isStorage) value.expected.properties.publicNetworkAccess = 'Disabled';
    resources.push(value);
  }
  if (version === 2) {
    if (resources.length !== 1 || resources[0].id !== context.plan.topology.ids.environment ||
        resources[0].type !== 'Microsoft.App/managedEnvironments' || resources[0].apiVersion !== PRIVATE_LINK_API.app ||
        request?.method !== 'PUT' || request.apiVersion !== PRIVATE_LINK_API.deployment) fail('PRIVATE_LINK_NO_LOG_WIRE_TARGET_CHANGED');
    equal(resources[0].expected.properties.appLogsConfiguration, { destination: 'none' }, 'PRIVATE_LINK_NO_LOG_INTENT_CHANGED');
    equal(request.body.properties.template.resources, resources.map(value => value.expected), 'PRIVATE_LINK_NO_LOG_INTENT_CHANGED');
    resources[0].expected.properties.appLogsConfiguration = { destination: null, logAnalyticsConfiguration: null };
    request.body.properties.template.resources = resources.map(value => structuredClone(value.expected));
  }
  return { version, kind: 'fixed-private-link-control-phase', phase: `private-link-${stage}`, stage,
    planSha256: context.plan.planSha256, contextSha256: hash(context.origin), request,
    resources, scope: stage === 'create-queue-role' ? ids(c).sub : ids(c).group,
    deploymentId: request?.body?.properties?.template ? request.id : null,
    template: request?.body?.properties?.template ?? null,
    rolloutMs: ['create-environment', 'retire-old-environment'].includes(stage) ? PRIVATE_LINK_LIMITS.environmentRolloutMs : PRIVATE_LINK_LIMITS.rolloutMs,
    ...(version === 2 ? { wireProjection: { version: 1, kind: 'aca-no-log-export-explicit-null',
      plannedRequestSha256: hash(selected.proposedRequest) } } : {}) };
}
export function verifyPrivateLinkEnvironmentWire(phase) {
  if (phase?.version !== 2 || phase.kind !== 'fixed-private-link-control-phase' ||
      phase.stage !== 'create-environment' || phase.phase !== 'private-link-create-environment') fail('PRIVATE_LINK_NO_LOG_WIRE_VERSION_REQUIRED');
  closed(phase.wireProjection, ['version', 'kind', 'plannedRequestSha256']);
  if (phase.wireProjection.version !== 1 || phase.wireProjection.kind !== 'aca-no-log-export-explicit-null' ||
      !sha(phase.wireProjection.plannedRequestSha256) || phase.resources?.length !== 1) fail('PRIVATE_LINK_NO_LOG_WIRE_PROJECTION_CHANGED');
  const descriptor = phase.resources[0], expected = descriptor.expected;
  if (descriptor.type !== 'Microsoft.App/managedEnvironments' || descriptor.apiVersion !== PRIVATE_LINK_API.app ||
      expected?.type !== descriptor.type || expected.apiVersion !== descriptor.apiVersion ||
      !sameId(descriptor.id, `${phase.scope}/providers/Microsoft.App/managedEnvironments/${expected.name}`) ||
      !/^missionspec-[a-z0-9]{2,10}-private-environment$/u.test(expected.name ?? '') ||
      phase.request?.method !== 'PUT' || phase.request.id !== phase.deploymentId ||
      phase.request.apiVersion !== PRIVATE_LINK_API.deployment) fail('PRIVATE_LINK_NO_LOG_WIRE_TARGET_CHANGED');
  equal(expected.properties?.appLogsConfiguration, { destination: null, logAnalyticsConfiguration: null }, 'PRIVATE_LINK_NO_LOG_WIRE_CONFIGURATION_CHANGED');
  equal(phase.template?.resources, [expected], 'PRIVATE_LINK_NO_LOG_WIRE_TEMPLATE_CHANGED');
  equal(phase.request.body, { properties: { mode: 'Incremental', template: phase.template } }, 'PRIVATE_LINK_NO_LOG_WIRE_REQUEST_CHANGED');
  const planned = structuredClone(phase.request);
  planned.body.properties.template.resources[0].properties.appLogsConfiguration = { destination: 'none' };
  if (hash(planned) !== phase.wireProjection.plannedRequestSha256) fail('PRIVATE_LINK_NO_LOG_WIRE_INTENT_CHANGED');
  return phase;
}

export function verifyPrivateLinkPlan(c, context, plan, sourceSha256) {
  equal(plan, buildPrivateLinkPlan(c, context, plan?.input, sourceSha256), 'PRIVATE_LINK_PLAN_DRIFT');
  return { version: 1, kind: 'local-private-link-plan-check', planSha256: plan.planSha256, sourceSha256,
    localContractValid: true, cloudStateVerified: false, executionAuthorized: false,
    retirementAuthorized: false, productionClearance: false };
}
