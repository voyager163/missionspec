import { isDeepStrictEqual } from 'node:util';
import { BUDGET, closed, deploymentName, digest, fail, ids, json, ownerTags, sameId, validateWindowInstance } from './definition.mjs';
import { canonicalInstant, verifyApproval, verifyDeploymentIdentity } from './policy.mjs';
import { durableQueueCost, queueResources, verifyQueueTopology } from './durable-queue.mjs';
import { verifyAdoptedQueueStorage, verifyQueueAdoptionRecord, queueArmInstant } from './queue-adoption.mjs';
import { verifyEffectivePolicyEvidence } from './effective-policy.mjs';
import { verifyNspReconciledRecord } from './nsp-reconciliation.mjs';
import { queueDefenderInventory, queueDefenderRule, verifyCurrentQueueDefender } from './queue-defender.mjs';

export const NSP_API = '2025-09-01';
export const NSP_STORAGE_API = '2025-01-01';
export const NSP_DIAGNOSTIC_API = '2021-05-01-preview';
export const NSP_CHILD_TYPES = Object.freeze(['networkSecurityPerimeters/profiles',
  'networkSecurityPerimeters/resourceAssociations', 'networkSecurityPerimeters/profiles/accessRules']);
export const NSP_SETUP_PHASES = Object.freeze([
  'nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association', 'nsp-subscription-admission',
]);
export const NSP_LIFECYCLE_PHASES = Object.freeze(['nsp-network-deny', 'nsp-subscription-readmit']);
export const NSP_PHASES = Object.freeze([...NSP_SETUP_PHASES, ...NSP_LIFECYCLE_PHASES]);
export const NSP_LIMITS = Object.freeze({ commandMs: 15000, stageMs: 120000, freshnessMs: 300000,
  reviewMs: 3600000, polls: 40, pollMs: 3000, pages: 32, items: 512, bytes: 8 * 1024 * 1024, records: 64 });
export const NSP_AUTHORITY = Object.freeze({ queueGrantsAuthorized: false, runtimeQualified: false,
  ingestionEnabled: false, publicationAuthorized: false, clientActivationAuthorized: false,
  productionClearance: false, budgetMutationAuthorized: false, policyMutationAuthorized: false });
const sha = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const guid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(value);
const hash = value => digest(json(value));
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const equal = (actual, expected, code) => { if (!isDeepStrictEqual(actual, expected)) fail(code); };
const stages = Object.freeze({ 'nsp-empty-boundary': 'empty-boundary', 'nsp-storage-lock': 'locked-unassociated',
  'nsp-enforced-association': 'enforced-empty', 'nsp-subscription-admission': 'subscription-admission-converged',
  'nsp-network-deny': 'deny-control-plane-converged', 'nsp-subscription-readmit': 'subscription-readmission-converged' });
export const nspAdmissionStage = stage => ['subscription-admission-converged', 'subscription-readmission-converged'].includes(stage);
function only(value, keys, code) {
  if (!object(value) || Object.keys(value).some(key => !keys.includes(key))) fail(code);
}
function timed(review, at) {
  const start = canonicalInstant(review.approvedAt), end = canonicalInstant(review.expiresAt);
  if (!Number.isSafeInteger(at) || start > at || end <= at || end <= start || end - start > NSP_LIMITS.reviewMs) fail('NSP_REVIEW_EXPIRED');
}
function fresh(observation, at) {
  if (!Number.isSafeInteger(observation.startedAt) || !Number.isSafeInteger(observation.completedAt) ||
      observation.completedAt < observation.startedAt || observation.completedAt > at ||
      observation.completedAt - observation.startedAt > NSP_LIMITS.stageMs ||
      at - observation.startedAt > NSP_LIMITS.freshnessMs) fail('NSP_OBSERVATION_EXPIRED');
}
function list(value) {
  only(value, ['value', 'nextLink'], 'NSP_LIST_INCOMPLETE');
  if (!Array.isArray(value.value) || (value.nextLink !== undefined && value.nextLink !== null) ||
      value.value.length > NSP_LIMITS.items) fail('NSP_LIST_INCOMPLETE');
  return value.value;
}
function inventory(value, expected) {
  const values = list(value), actual = values.map(item => item?.id?.toLowerCase());
  if (actual.some(id => !id) || new Set(actual).size !== actual.length) fail('NSP_INVENTORY_DRIFT');
  equal(actual.sort(), expected.map(id => id.toLowerCase()).sort(), 'NSP_INVENTORY_DRIFT');
  return values;
}
function regional(value) { return ['australiaeast', 'Australia East'].includes(value); }
function networkVersion(value) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d{0,15})$/u.test(value) ||
      !Number.isSafeInteger(Number(value))) fail('NSP_VERSION_UNVERIFIED');
  return Number(value);
}
function systemData(value, required = false) {
  if (value === undefined && !required) return {};
  only(value, ['createdAt', 'createdBy', 'createdByType', 'lastModifiedAt', 'lastModifiedBy', 'lastModifiedByType'], 'NSP_SYSTEM_DATA_UNVERIFIED');
  if (required || Object.hasOwn(value, 'createdAt')) queueArmInstant(value.createdAt);
  if (Object.hasOwn(value, 'lastModifiedAt')) queueArmInstant(value.lastModifiedAt);
  for (const key of ['createdBy', 'lastModifiedBy']) {
    if (Object.hasOwn(value, key) && (typeof value[key] !== 'string' || !value[key])) fail('NSP_SYSTEM_DATA_UNVERIFIED');
  }
  for (const key of ['createdByType', 'lastModifiedByType']) {
    if (Object.hasOwn(value, key) && !['User', 'Application', 'ManagedIdentity', 'Key'].includes(value[key])) fail('NSP_SYSTEM_DATA_UNVERIFIED');
  }
  return Object.fromEntries(Object.entries(value).filter(([key]) => key.startsWith('created'))
    .map(([key, value]) => [key, key === 'createdAt' ? queueArmInstant(value).toString() : value]));
}
function resource(value, id, type) {
  only(value, ['id', 'name', 'type', 'location', 'tags', 'properties', 'systemData', 'etag', 'apiVersion'], 'NSP_RESOURCE_SHAPE_UNREVIEWED');
  if (!sameId(value.id, id) || !sameId(value.type, type) ||
      (Object.hasOwn(value, 'apiVersion') && value.apiVersion !== (type.startsWith('Microsoft.Network/') ? NSP_API : NSP_STORAGE_API)) ||
      ![id.split('/').at(-1), id.split('/providers/')[1]?.split('/').filter((_, i) => i > 0 && i % 2 === 0).join('/')].includes(value.name) ||
      !object(value.properties)) fail('NSP_RESOURCE_DRIFT');
  systemData(value.systemData, type.startsWith('Microsoft.Network/'));
}
function comparisonIds(value) {
  const result = structuredClone(value);
  if (!object(result)) return result;
  if (typeof result.id === 'string') result.id = result.id.toLowerCase();
  if (sameId(result.type, 'Microsoft.Network/networkSecurityPerimeters/resourceAssociations')) {
    for (const key of ['privateLinkResource', 'profile']) {
      if (typeof result.properties?.[key]?.id === 'string') result.properties[key].id = result.properties[key].id.toLowerCase();
    }
  }
  if (sameId(result.type, 'Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations') &&
      typeof result.properties?.networkSecurityPerimeter?.id === 'string') {
    result.properties.networkSecurityPerimeter.id = result.properties.networkSecurityPerimeter.id.toLowerCase();
  }
  return result;
}
export function nspConfigurationId(network, id) {
  const prefix = `${network.ids.account}/networkSecurityPerimeterConfigurations/`;
  if (typeof id !== 'string' || /[%?#\\]|\.\./u.test(id) ||
      !sameId(id.slice(0, prefix.length), prefix) || !/^[A-Za-z0-9_.-]+$/u.test(id.slice(prefix.length))) fail('NSP_CONFIGURATION_SCOPE_CHANGED');
  return id;
}
export function verifyNspApiCatalog(provider) {
  if (!provider || provider.error || provider.nextLink || !sameId(provider.namespace, 'Microsoft.Network') ||
      provider.registrationState !== 'Registered' || !Array.isArray(provider.resourceTypes) ||
      provider.resourceTypes.length > NSP_LIMITS.items) fail('NSP_PROVIDER_NOT_QUALIFIED');
  for (const entry of provider.resourceTypes) {
    if (typeof entry?.resourceType !== 'string' ||
        !/^[A-Za-z][A-Za-z0-9_-]*(?:\/[A-Za-z][A-Za-z0-9_-]*)*$/u.test(entry.resourceType) ||
        (Object.hasOwn(entry, 'namespace') && !sameId(entry.namespace, 'Microsoft.Network'))) fail('NSP_PROVIDER_CLASSIFICATION_UNVERIFIED');
  }
  const omittedChildTypes = [];
  for (const type of ['networkSecurityPerimeters', ...NSP_CHILD_TYPES]) {
    const matches = provider.resourceTypes.filter(entry => sameId(entry.resourceType, type));
    if (!matches.length && NSP_CHILD_TYPES.includes(type)) { omittedChildTypes.push(type); continue; }
    if (matches.length !== 1 || !Array.isArray(matches[0].apiVersions) ||
        matches[0].apiVersions.some(version => typeof version !== 'string') ||
        new Set(matches[0].apiVersions).size !== matches[0].apiVersions.length ||
        !matches[0].apiVersions.includes(NSP_API)) fail('NSP_PROVIDER_NOT_QUALIFIED');
    if (type === 'networkSecurityPerimeters' && (!Array.isArray(matches[0].locations) ||
        matches[0].locations.some(location => typeof location !== 'string') ||
        !matches[0].locations.some(regional))) fail('NSP_REGION_NOT_QUALIFIED');
  }
  return { version: 1, kind: 'documented-nsp-child-api-review', providerSha256: hash(provider),
    apiVersion: NSP_API, location: 'australiaeast', omittedChildTypes, rootApiAndRegionVerified: true,
    omittedChildApisVerified: false, nativeTemplateValidationRequired: true, exactPostReadbacksRequired: true, qualified: false };
}

export function nspTopology(c, topology, adoption) {
  verifyQueueTopology(c, topology);
  verifyQueueAdoptionRecord(c, adoption);
  equal(adoption.topology, topology, 'NSP_ADOPTION_TOPOLOGY_CHANGED');
  const r = ids(c), name = `${c.namePrefix}-queue-${topology.namespace}`;
  const perimeter = `${r.group}/providers/Microsoft.Network/networkSecurityPerimeters/${name}`;
  const profile = `${perimeter}/profiles/queue-storage-v1`;
  return { version: adoption.version === 3 ? 2 : 1, kind: 'enforced-queue-network-perimeter', configSha256: hash(c),
    ...(adoption.version === 3 ? { defenderEvidenceSha256: hash(adoption.proposal.defender) } : {}),
    queueTopologySha256: hash(topology), adoptionSha256: hash(adoption), location: c.location,
    tenantId: c.tenantId, admittedSubscription: r.sub, host: r.app, identity: r.ingestIdentity,
    ids: { perimeter, profile, association: `${perimeter}/resourceAssociations/queue-storage-v1`,
      rule: `${profile}/accessRules/same-subscription-v1`, account: topology.ids.account,
      service: topology.ids.service, queue: topology.ids.queue },
    networkApiVersion: NSP_API, storageApiVersion: NSP_STORAGE_API, accessMode: 'Enforced',
    publicNetworkAccess: 'SecuredByPerimeter', admissionScope: 'subscription-not-app-or-identity',
    authority: NSP_AUTHORITY };
}
export function verifyNspTopology(c, network, topology, adoption) {
  equal(network, nspTopology(c, topology, adoption), 'NSP_TOPOLOGY_DRIFT');
  return network;
}
export function nspRule(network) {
  return { direction: 'Inbound', subscriptions: [{ id: network.admittedSubscription }] };
}
function descriptor(id, properties, extra = {}) {
  const parts = id.split('/providers/')[1].split('/');
  const type = [parts[0], ...parts.filter((_, i) => i % 2 === 1)].join('/');
  return { id, type, apiVersion: NSP_API, expected: { type, apiVersion: NSP_API,
    name: parts.filter((_, i) => i > 0 && i % 2 === 0).join('/'), properties, ...extra } };
}
export function nspDescriptors(c, network) {
  const n = network.ids;
  return {
    perimeter: descriptor(n.perimeter, {}, { location: c.location, tags: ownerTags(c) }),
    profile: descriptor(n.profile, {}, { dependsOn: [n.perimeter] }),
    association: descriptor(n.association, { accessMode: 'Enforced',
      privateLinkResource: { id: n.account }, profile: { id: n.profile } }),
    rule: descriptor(n.rule, nspRule(network)),
  };
}
export function nspLineageHead(evidence) {
  const record = evidence.records.at(-1);
  return { version: 1, kind: 'nsp-terminal-lineage-head', targetKey: nspTargetKey(evidence.topology), topologySha256: hash(evidence.topology),
    recordSha256: record ? hash(record) : null, recordCount: evidence.records.length,
    stage: record?.receipt.stage ?? 'adopted-disabled' };
}
export function nspTargetKey(network) {
  const n = network?.ids;
  const prefix = '^/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9_-]+/providers/';
  if (!n || !new RegExp(prefix + 'Microsoft\\.Network/networkSecurityPerimeters/[A-Za-z0-9_.-]{1,80}$', 'iu').test(n.perimeter ?? '') ||
      !new RegExp(prefix + 'Microsoft\\.Storage/storageAccounts/[a-z0-9]{3,24}$', 'iu').test(n.account ?? '')) fail('NSP_TARGET_IDENTITY_REQUIRED');
  return hash({ perimeter: n.perimeter.toLowerCase(), account: n.account.toLowerCase() });
}
export function nspIntentKey(evidence, phase) {
  if (!NSP_PHASES.includes(phase.phase)) fail('FIXED_NSP_PHASE_REQUIRED');
  return hash({ targetKey: nspTargetKey(evidence.topology), phase: phase.phase, instanceId: phase.instance?.id ?? null });
}
export function nspIntentFence(evidence, reservation) {
  return { version: 1, kind: 'nsp-target-intent-fence', targetKey: nspTargetKey(evidence.topology),
    topologySha256: hash(evidence.topology), intentKey: nspIntentKey(evidence, reservation.phase), reservation };
}
export function nspPendingHead(evidence, phase, intent) {
  return { version: 1, kind: 'nsp-pending-lineage-head', targetKey: nspTargetKey(evidence.topology), phaseSha256: hash(phase),
    intentSha256: hash(intent), previousHead: nspLineageHead(evidence) };
}
export function emptyNspEvidence(network) {
  return { version: 1, kind: 'reviewed-enforced-nsp-network', topology: network, records: [] };
}
function checkSequence(evidence, name, instance) {
  const previous = evidence.records.at(-1), count = evidence.records.length;
  if (count >= NSP_LIMITS.records) fail('NSP_LINEAGE_LIMIT');
  if (name === 'nsp-subscription-readmit' && count + 2 > NSP_LIMITS.records) fail('NSP_DENY_RESERVE_REQUIRED');
  if (count < NSP_SETUP_PHASES.length) {
    if (name !== NSP_SETUP_PHASES[count] || instance !== null) fail('NSP_PHASE_ORDER_INVALID');
  } else {
    if (!NSP_LIFECYCLE_PHASES.includes(name) ||
        (name === 'nsp-network-deny' ? !nspAdmissionStage(previous.receipt.stage) : previous.receipt.stage !== stages['nsp-network-deny'])) fail('NSP_TERMINAL_PREDECESSOR_REQUIRED');
    if (!instance || instance.predecessorSha256 !== hash(previous) ||
        !isDeepStrictEqual(instance.previousInstanceIds, evidence.records.map(v => v.phase.instance?.id).filter(Boolean))) fail('NSP_INSTANCE_LINEAGE_CHANGED');
  }
}
export function buildNspPhase(c, name, topology, adoption, evidence, instance = null) {
  verifyNspTopology(c, evidence.topology, topology, adoption);
  if (!NSP_PHASES.includes(name)) fail('FIXED_NSP_PHASE_REQUIRED');
  checkSequence(evidence, name, instance);
  if (instance) validateWindowInstance(c, instance);
  const network = evidence.topology, d = nspDescriptors(c, network), r = ids(c);
  const prior = evidence.records.at(-1), beforeStage = prior?.receipt.stage ?? 'adopted-disabled';
  const resources = name === 'nsp-empty-boundary' ? [d.perimeter, d.profile]
    : name === 'nsp-enforced-association' ? [d.association]
      : name === 'nsp-storage-lock' ? [structuredClone(queueResources(c, topology)['queue-storage'][0])] : [d.rule];
  if (name === 'nsp-storage-lock') {
    resources[0].expected.properties.publicNetworkAccess = 'SecuredByPerimeter';
    if (adoption.version === 3) resources[0].expected.properties.networkAcls.resourceAccessRules = [queueDefenderRule(c)];
  }
  const method = name === 'nsp-storage-lock' ? 'PATCH' : name === 'nsp-network-deny' ? 'DELETE' : 'PUT';
  const deploymentId = method === 'PUT' ? `${r.group}/providers/Microsoft.Resources/deployments/${deploymentName(c, name, instance ?? undefined)}` : null;
  const template = method === 'PUT' ? { $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0', resources: resources.map(value => value.expected) } : null;
  return { version: 1, phase: name, configSha256: hash(c), topologySha256: hash(network), adoptionSha256: hash(adoption),
    predecessorSha256: prior ? hash(prior) : null, lineageHeadSha256: hash(nspLineageHead(evidence)), instance,
    beforeStage, afterStage: stages[name], scope: r.group, deploymentId, resources, template,
    request: { method, id: method === 'PATCH' ? network.ids.account : method === 'DELETE' ? network.ids.rule : deploymentId,
      apiVersion: method === 'PATCH' ? NSP_STORAGE_API : method === 'DELETE' ? NSP_API : '2022-09-01',
      body: method === 'PATCH' ? { properties: { publicNetworkAccess: 'SecuredByPerimeter' } }
        : method === 'DELETE' ? null : { properties: { mode: 'Incremental', template } } },
    allowedModify: method === 'PATCH' ? { [network.ids.account]: ['properties.publicNetworkAccess'] } : {},
    authority: NSP_AUTHORITY };
}

function verifyRuleProperties(properties, network, networkProvider) {
  only(properties, ['direction', 'subscriptions', 'addressPrefixes', 'fullyQualifiedDomainNames', 'serviceTags',
    'emailAddresses', 'phoneNumbers', 'networkSecurityPerimeters', ...(networkProvider ? ['provisioningState'] : [])], 'NSP_RULE_DRIFT');
  if (properties.direction !== 'Inbound' || !isDeepStrictEqual(properties.subscriptions, nspRule(network).subscriptions) ||
      (networkProvider && properties.provisioningState !== 'Succeeded') ||
      ['addressPrefixes', 'fullyQualifiedDomainNames', 'serviceTags', 'emailAddresses', 'phoneNumbers', 'networkSecurityPerimeters']
        .some(key => Object.hasOwn(properties, key) && !isDeepStrictEqual(properties[key], []))) fail('NSP_RULE_DRIFT');
}
export function verifyNspObservation(c, network, adoption, observation, stage) {
  const defender = adoption.version === 3;
  if (defender) verifyNspTopology(c, network, adoption.topology, adoption);
  closed(observation, ['version', 'kind', 'startedAt', 'completedAt', 'resources', 'profiles', 'associations',
    'rules', 'links', 'linkReferences', 'configurations', 'configuration', 'privateEndpoints', 'queues', 'diagnostics',
    ...(defender ? ['defender'] : [])]);
  if (observation.version !== (defender ? 2 : 1) || observation.kind !== 'observed-nsp-control-plane' ||
      !['adopted-disabled', ...Object.values(stages)].includes(stage)) fail('NSP_OBSERVATION_INVALID');
  fresh(observation, observation.completedAt);
  if (defender) verifyCurrentQueueDefender(c, adoption.origin, adoption.proposal.defender, observation.defender);
  const n = network.ids, exists = stage !== 'adopted-disabled';
  const associated = !['adopted-disabled', 'empty-boundary', 'locked-unassociated'].includes(stage);
  const admitted = nspAdmissionStage(stage), values = observation.resources;
  closed(values, Object.values(n));
  verifyAdoptedQueueStorage(c, adoption,
    Object.fromEntries([n.account, n.service, n.queue].map(id => [id, values[id]])),
    ['adopted-disabled', 'empty-boundary'].includes(stage) ? 'Disabled' : 'SecuredByPerimeter');
  inventory(observation.queues, [n.queue]);
  inventory(observation.privateEndpoints, []);
  inventory(observation.profiles, exists ? [n.profile] : []);
  inventory(observation.associations, associated ? [n.association] : []);
  inventory(observation.rules, admitted ? [n.rule] : []);
  inventory(observation.links, []);
  inventory(observation.linkReferences, []);
  closed(observation.diagnostics, [n.perimeter, n.account, n.service]);
  for (const value of Object.values(observation.diagnostics)) inventory(value, []);
  for (const [id, expected] of [[n.perimeter, exists], [n.profile, exists], [n.association, associated], [n.rule, admitted]]) {
    if ((values[id] !== null) !== expected) fail('NSP_STATE_DRIFT');
  }
  if (exists) {
    resource(values[n.perimeter], n.perimeter, 'Microsoft.Network/networkSecurityPerimeters');
    const perimeter = values[n.perimeter];
    only(perimeter.properties, ['perimeterGuid', 'provisioningState'], 'NSP_PERIMETER_DRIFT');
    if (!regional(perimeter.location) || !isDeepStrictEqual(perimeter.tags, ownerTags(c)) ||
        !guid(perimeter.properties.perimeterGuid) || perimeter.properties.provisioningState !== 'Succeeded') fail('NSP_PERIMETER_DRIFT');
    resource(values[n.profile], n.profile, 'Microsoft.Network/networkSecurityPerimeters/profiles');
    closed(values[n.profile].properties, ['accessRulesVersion', 'diagnosticSettingsVersion']);
    networkVersion(values[n.profile].properties.accessRulesVersion);
    networkVersion(values[n.profile].properties.diagnosticSettingsVersion);
    equal(comparisonIds(list(observation.profiles)[0]), comparisonIds(values[n.profile]), 'NSP_LIST_GET_DRIFT');
  }
  if (associated) {
    const association = values[n.association];
    resource(association, n.association, 'Microsoft.Network/networkSecurityPerimeters/resourceAssociations');
    closed(association.properties, ['accessMode', 'privateLinkResource', 'profile', 'provisioningState', 'hasProvisioningIssues']);
    if (association.properties.accessMode !== 'Enforced' || association.properties.provisioningState !== 'Succeeded' ||
        association.properties.hasProvisioningIssues !== 'no') fail('NSP_ASSOCIATION_UNVERIFIED');
    closed(association.properties.privateLinkResource, ['id']);
    closed(association.properties.profile, ['id']);
    if (!sameId(association.properties.privateLinkResource.id, n.account) ||
        !sameId(association.properties.profile.id, n.profile)) fail('NSP_ASSOCIATION_DRIFT');
    equal(comparisonIds(list(observation.associations)[0]), comparisonIds(association), 'NSP_LIST_GET_DRIFT');
    const effective = observation.configuration, p = effective?.properties, profile = values[n.profile].properties;
    const configurations = list(observation.configurations);
    if (configurations.length !== 1 || !effective || !sameId(effective.id, configurations[0].id)) fail('NSP_EFFECTIVE_CONFIGURATION_UNVERIFIED');
    nspConfigurationId(network, effective.id); nspConfigurationId(network, configurations[0].id);
    equal(comparisonIds(configurations[0]), comparisonIds(effective), 'NSP_LIST_GET_DRIFT');
    resource(effective, effective.id, 'Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations');
    const issuesPresent = Object.hasOwn(p, 'provisioningIssues');
    closed(p, ['provisioningState', 'networkSecurityPerimeter', 'resourceAssociation', 'profile',
      ...(issuesPresent ? ['provisioningIssues'] : [])]);
    closed(p.networkSecurityPerimeter, ['id', 'perimeterGuid', 'location']);
    closed(p.profile, ['name', 'accessRulesVersion', 'accessRules', 'diagnosticSettingsVersion', 'enabledLogCategories']);
    equal(p.resourceAssociation, { name: n.association.split('/').at(-1), accessMode: 'Enforced' }, 'NSP_EFFECTIVE_ASSOCIATION_DRIFT');
    if (p.provisioningState !== 'Succeeded' || (issuesPresent && !isDeepStrictEqual(p.provisioningIssues, [])) ||
        !sameId(p.networkSecurityPerimeter.id, n.perimeter) || !regional(p.networkSecurityPerimeter.location) ||
        p.networkSecurityPerimeter.perimeterGuid !== values[n.perimeter].properties.perimeterGuid ||
        p.profile.name !== n.profile.split('/').at(-1) ||
        !Number.isSafeInteger(p.profile.accessRulesVersion) || p.profile.accessRulesVersion < 0 ||
        !Number.isSafeInteger(p.profile.diagnosticSettingsVersion) || p.profile.diagnosticSettingsVersion < 0 ||
        p.profile.accessRulesVersion !== networkVersion(profile.accessRulesVersion) ||
        p.profile.diagnosticSettingsVersion !== networkVersion(profile.diagnosticSettingsVersion) ||
        !isDeepStrictEqual(p.profile.enabledLogCategories, [])) fail('NSP_PROPAGATION_UNVERIFIED');
    if (!Array.isArray(p.profile.accessRules) || p.profile.accessRules.length !== (admitted ? 1 : 0)) fail('NSP_EFFECTIVE_RULE_DRIFT');
    if (admitted) {
      const rule = p.profile.accessRules[0];
      closed(rule, ['name', 'properties']);
      if (rule.name !== n.rule.split('/').at(-1)) fail('NSP_EFFECTIVE_RULE_DRIFT');
      verifyRuleProperties(rule.properties, network, false);
    }
  } else if (list(observation.configurations).length || observation.configuration !== null) fail('NSP_UNASSOCIATED_LOCK_UNVERIFIED');
  if (admitted) {
    resource(values[n.rule], n.rule, 'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules');
    verifyRuleProperties(values[n.rule].properties, network, true);
    equal(comparisonIds(list(observation.rules)[0]), comparisonIds(values[n.rule]), 'NSP_LIST_GET_DRIFT');
  }
  return observation;
}
function resourceState(value) {
  if (!object(value) || typeof value.id !== 'string' || ![
    'Microsoft.Network/networkSecurityPerimeters', 'Microsoft.Network/networkSecurityPerimeters/profiles',
    'Microsoft.Network/networkSecurityPerimeters/resourceAssociations', 'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules',
    'Microsoft.Storage/storageAccounts', 'Microsoft.Storage/storageAccounts/queueServices',
    'Microsoft.Storage/storageAccounts/queueServices/queues', 'Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations',
  ].some(type => sameId(type, value.type))) return structuredClone(value);
  const result = comparisonIds(value);
  if (Object.hasOwn(result, 'etag')) {
    if (typeof result.etag !== 'string') fail('NSP_RESOURCE_ETAG_UNVERIFIED');
    delete result.etag;
  }
  if (Object.hasOwn(result, 'systemData')) result.systemData = systemData(result.systemData);
  if (sameId(result.type, 'Microsoft.Storage/storageAccounts/queueServices/queues') &&
      object(result.properties) && Object.hasOwn(result.properties, 'approximateMessageCount')) {
    if (!Number.isSafeInteger(result.properties.approximateMessageCount) ||
        result.properties.approximateMessageCount < 0) fail('NSP_QUEUE_COUNT_UNVERIFIED');
    delete result.properties.approximateMessageCount;
  }
  return result;
}
export function nspState(observation) {
  if (observation?.kind !== 'observed-nsp-control-plane' || ![1, 2].includes(observation.version)) return resourceState(observation);
  const result = structuredClone(observation);
  if (!Number.isSafeInteger(result.startedAt) || !Number.isSafeInteger(result.completedAt) ||
      !object(result.resources)) fail('NSP_OBSERVATION_INVALID');
  delete result.startedAt; delete result.completedAt;
  result.resources = Object.fromEntries(Object.entries(result.resources).map(([id, value]) => [id, resourceState(value)]));
  result.configuration = resourceState(result.configuration);
  for (const name of ['profiles', 'associations', 'rules', 'configurations', 'queues']) {
    result[name].value = list(result[name]).map(resourceState);
  }
  return result;
}
export function verifyNspTransition(c, network, adoption, phase, before, after) {
  verifyNspObservation(c, network, adoption, before, phase.beforeStage);
  verifyNspObservation(c, network, adoption, after, phase.afterStage);
  const n = network.ids;
  for (const id of [n.account, n.service, n.queue]) {
    const expected = structuredClone(before.resources[id]), actual = structuredClone(after.resources[id]);
    if (phase.phase === 'nsp-storage-lock' && id === n.account) {
      expected.properties.publicNetworkAccess = 'SecuredByPerimeter';
    }
    equal(nspState(actual), nspState(expected), 'NSP_UNRELATED_STORAGE_CHANGE');
  }
  for (const id of [n.perimeter, n.profile, n.association, n.rule]) {
    if (before.resources[id] && after.resources[id]) equal(systemData(before.resources[id].systemData, true),
      systemData(after.resources[id].systemData, true), 'NSP_GENERATION_CHANGED');
  }
  if (before.resources[n.perimeter] && after.resources[n.perimeter]?.properties.perimeterGuid !== before.resources[n.perimeter].properties.perimeterGuid) fail('NSP_GENERATION_CHANGED');
  if (before.resources[n.profile]) {
    const old = before.resources[n.profile].properties, next = after.resources[n.profile].properties;
    if (next.diagnosticSettingsVersion !== old.diagnosticSettingsVersion) fail('NSP_DIAGNOSTIC_VERSION_CHANGED');
    const changesRule = ['nsp-subscription-admission', ...NSP_LIFECYCLE_PHASES].includes(phase.phase);
    if (changesRule ? networkVersion(next.accessRulesVersion) <= networkVersion(old.accessRulesVersion)
      : next.accessRulesVersion !== old.accessRulesVersion) fail('NSP_RULE_VERSION_CHANGED');
  }
}

export function nspUncertaintyCost() {
  if (durableQueueCost().total !== 349.37) fail('NSP_BASE_COST_CHANGED');
  return { version: 1, currency: 'USD', days: 31, hours: 744, knownBase: 349.37,
    discretionaryNspAllowance: 10, total: 359.37, planningLimit: 375,
    feeVerified: false, zeroFeeProven: false, isHardCap: false, explicitUncertaintyAccepted: true };
}
export function verifyNspBilling(c, network, review, evidence, source, at) {
  closed(review, ['version', 'action', 'configSha256', 'topologySha256', 'sourceSha256', 'evidenceSha256',
    'acknowledgmentSha256', 'location', 'cost', 'budgets', 'approvedAt', 'expiresAt']);
  if (review.version !== 2 || review.action !== 'accept-exact-nsp-price-uncertainty' ||
      review.configSha256 !== hash(c) || review.topologySha256 !== hash(network) ||
      !sha(source) || review.sourceSha256 !== source || review.evidenceSha256 !== hash(evidence) ||
      review.location !== 'australiaeast') fail('NSP_BILLING_REVIEW_REQUIRED');
  timed(review, at);
  equal(review.cost, nspUncertaintyCost(), 'NSP_COST_DIVERGENCE');
  equal(review.budgets, BUDGET, 'NSP_BUDGET_MUTATION_FORBIDDEN');
  closed(evidence, ['version', 'kind', 'subscriptionId', 'tenantId', 'priceSheet', 'retailQueries', 'acknowledgment']);
  closed(evidence.priceSheet, ['httpStatus', 'response', 'responseSha256']);
  closed(evidence.acknowledgment, ['action', 'userInstruction', 'userInstructionSha256', 'recordedAt']);
  if (evidence.version !== 1 || evidence.kind !== 'disclosed-nsp-price-uncertainty' ||
      evidence.subscriptionId !== c.subscriptionId || evidence.tenantId !== c.tenantId ||
      evidence.priceSheet.httpStatus !== 401 || evidence.priceSheet.responseSha256 !== hash(evidence.priceSheet.response) ||
      evidence.acknowledgment.action !== 'accept-375-planning-and-disclosed-nsp-price-uncertainty' ||
      typeof evidence.acknowledgment.userInstruction !== 'string' || !evidence.acknowledgment.userInstruction.trim() ||
      evidence.acknowledgment.userInstructionSha256 !== digest(evidence.acknowledgment.userInstruction) ||
      review.acknowledgmentSha256 !== hash(evidence.acknowledgment) ||
      canonicalInstant(evidence.acknowledgment.recordedAt) > canonicalInstant(review.approvedAt) ||
      !Array.isArray(evidence.retailQueries) || evidence.retailQueries.length !== 2) fail('NSP_UNCERTAINTY_ACKNOWLEDGMENT_REQUIRED');
  const urls = new Set();
  for (const query of evidence.retailQueries) {
    closed(query, ['url', 'retrievedAt', 'response', 'responseSha256']);
    const url = new URL(query.url);
    if (url.protocol !== 'https:' || url.host !== 'prices.azure.com' || url.pathname !== '/api/retail/prices' ||
        url.username || url.password || url.hash || urls.has(url.href) || !url.searchParams.has('$filter') ||
        query.responseSha256 !== hash(query.response) || !isDeepStrictEqual(query.response?.Items, []) ||
        query.response.NextPageLink !== null || canonicalInstant(query.retrievedAt) > canonicalInstant(review.approvedAt)) fail('NSP_PRICE_EVIDENCE_INVALID');
    urls.add(url.href);
  }
  return review.cost;
}
export function verifyNspReview(c, network, review, source, at, observation = null) {
  const queueOnly = network.version === 2;
  closed(review, ['version', 'action', 'configSha256', 'topologySha256', 'sourceSha256', 'approvedAt', 'expiresAt', 'authority',
    ...(queueOnly ? ['queueOnlyRisk'] : [])]);
  if (review.version !== (queueOnly ? 2 : 1) || review.action !== 'accept-exact-enforced-nsp-topology' ||
      review.configSha256 !== hash(c) || review.topologySha256 !== hash(network) || review.sourceSha256 !== source || !sha(source)) fail('NSP_TOPOLOGY_REVIEW_REQUIRED');
  equal(review.authority, NSP_AUTHORITY, 'NSP_AUTHORITY_CHANGED');
  timed(review, at);
  if (queueOnly) {
    const risk = review.queueOnlyRisk;
    closed(risk, ['action', 'currentStateSha256', 'userInstruction', 'userInstructionSha256',
      'functionalBlobProtectionQualified', 'blobUploadsAuthorized', 'explicitInterruptionRiskAccepted']);
    if (risk.action !== 'accept-queue-only-nsp-with-unverified-blob-protection' ||
        observation?.version !== 2 || risk.currentStateSha256 !== hash(nspState(observation)) ||
        typeof risk.userInstruction !== 'string' || !risk.userInstruction.trim() || risk.userInstruction.length > 4096 ||
        risk.userInstructionSha256 !== digest(risk.userInstruction) ||
        risk.functionalBlobProtectionQualified !== false || risk.blobUploadsAuthorized !== false ||
        risk.explicitInterruptionRiskAccepted !== true) fail('NSP_EXACT_QUEUE_ONLY_RISK_ACKNOWLEDGMENT_REQUIRED');
  }
}
export function nspPreflightBaseline(proof) {
  return hash({ foundationBaselineSha256: proof.foundationBaselineSha256,
    foundationBindingSha256: hash(proof.foundationBinding),
    providerCatalogSha256: hash(proof.providerCatalog), providerCatalogReviewSha256: hash(proof.providerCatalogReview),
    adoptionSha256: proof.adoptionSha256, topologyReviewSha256: hash(proof.topologyReview),
    networkBillingReviewSha256: hash(proof.networkBillingReview), networkBillingEvidenceSha256: hash(proof.networkBillingEvidence),
    effectivePolicyVersion: proof.effectivePolicyVersion, effectivePolicySha256: proof.effectivePolicySha256,
    permissionsSha256: hash(proof.permissions), observationSha256: hash(nspState(proof.observation)),
    lineageHeadSha256: hash(proof.networkLineageHead), requestSha256: hash(proof.request) });
}
export function verifyNspPreflight(c, phase, topology, adoption, evidence, proof, at) {
  closed(proof, ['startedAt', 'completedAt', 'qualified', 'configSha256', 'phaseSha256', 'sourceSha256',
    'originSha256', 'receiptsSha256', 'adoptionSha256', 'foundationBaselineSha256', 'topologyReview',
    'foundationBinding',
    'providerCatalog', 'providerCatalogReview',
    'networkBillingReview', 'networkBillingEvidence', 'observation', 'permissions', 'networkLineageHead',
    'request', 'preservedIds', 'effectivePolicyVersion', 'effectivePolicySha256', 'effectivePolicy',
    'validationSha256', 'whatIfSha256', 'baselineSha256']);
  fresh(proof, at);
  equal(proof.providerCatalogReview, verifyNspApiCatalog(proof.providerCatalog), 'NSP_PROVIDER_REVIEW_CHANGED');
  closed(proof.foundationBinding, ['executionOriginsSha256', 'reconciliationSha256', 'receiverRecordSha256', 'receiverManifestDigest', 'receiverConfigDigest']);
  if (!['executionOriginsSha256', 'reconciliationSha256', 'receiverRecordSha256'].every(key => sha(proof.foundationBinding[key])) ||
      !['receiverManifestDigest', 'receiverConfigDigest'].every(key => /^sha256:[0-9a-f]{64}$/u.test(proof.foundationBinding[key] ?? ''))) fail('NSP_RECEIVER_BINDING_REQUIRED');
  verifyNspTopology(c, evidence.topology, topology, adoption);
  verifyNspReview(c, evidence.topology, proof.topologyReview, proof.sourceSha256, at, proof.observation);
  verifyNspBilling(c, evidence.topology, proof.networkBillingReview, proof.networkBillingEvidence, proof.sourceSha256, at);
  verifyNspObservation(c, evidence.topology, adoption, proof.observation, phase.beforeStage);
  fresh(proof.observation, at);
  equal(proof.request, phase.request, 'NSP_REQUEST_DRIFT');
  equal(proof.networkLineageHead, nspLineageHead(evidence), 'NSP_LINEAGE_HEAD_CHANGED');
  if (proof.qualified !== true || proof.configSha256 !== hash(c) || proof.phaseSha256 !== hash(phase) ||
      proof.originSha256 !== c.originSha256 || proof.receiptsSha256 !== hash(evidence) ||
      proof.adoptionSha256 !== hash(adoption) || !sha(proof.foundationBaselineSha256) ||
      proof.effectivePolicyVersion !== 1 || proof.effectivePolicySha256 !== hash(proof.effectivePolicy) ||
      proof.baselineSha256 !== nspPreflightBaseline(proof)) fail('NSP_PREFLIGHT_BINDING_REQUIRED');
  verifyEffectivePolicyEvidence(phase, proof.effectivePolicy);
  verifyNspPermissions(c, phase, evidence.topology, proof.permissions);
}
export function verifyNspPreview(phase, preview, known = []) {
  if (phase.request.method !== 'PUT') {
    closed(preview, ['version', 'kind', 'request', 'preimageSha256', 'nativeArmWhatIf']);
    if (preview.version !== 1 || preview.kind !== 'fixed-nsp-direct-request-preview' || preview.nativeArmWhatIf !== false ||
        !sha(preview.preimageSha256)) fail('NSP_DIRECT_PREVIEW_REQUIRED');
    equal(preview.request, phase.request, 'NSP_REQUEST_DRIFT');
    return hash(preview);
  }
  if (preview?.status !== 'Succeeded' || preview.error || preview.nextLink || !Array.isArray(preview.changes)) fail('NSP_WHATIF_INVALID');
  const seen = new Set();
  for (const change of preview.changes) {
    if (!change || seen.has(change.resourceId?.toLowerCase()) || change.error || change.nextLink) fail('NSP_WHATIF_INVALID');
    seen.add(change.resourceId?.toLowerCase());
    const d = phase.resources.find(v => sameId(v.id, change.resourceId));
    if (!d) {
      if (change.changeType !== 'Ignore' || !known.some(id => sameId(id, change.resourceId))) fail('NSP_WHATIF_SCOPE_CHANGED');
      continue;
    }
    if (change.changeType !== 'Create' || change.before !== undefined) fail('NSP_WHATIF_CREATE_REQUIRED');
    const expected = { ...structuredClone(d.expected), id: d.id };
    const after = structuredClone(change.after);
    if (!object(after)) fail('NSP_WHATIF_INVALID');
    for (const key of ['apiVersion', 'dependsOn']) {
      if (Object.hasOwn(after, key) && (!Object.hasOwn(expected, key) ||
          !isDeepStrictEqual(after[key], expected[key]))) fail('NSP_WHATIF_RESOURCE_CHANGED');
    }
    if (phase.phase === 'nsp-empty-boundary' && [
      'Microsoft.Network/networkSecurityPerimeters', 'Microsoft.Network/networkSecurityPerimeters/profiles',
    ].includes(d.type) && isDeepStrictEqual(expected.properties, {}) && !Object.hasOwn(after, 'properties')) {
      delete expected.properties;
    }
    if (after.name === d.id.split('/').at(-1)) expected.name = after.name;
    delete expected.apiVersion; delete after.apiVersion; delete expected.dependsOn; delete after.dependsOn;
    equal(after, expected, 'NSP_WHATIF_RESOURCE_CHANGED');
  }
  if (phase.resources.some(d => !seen.has(d.id.toLowerCase()))) fail('NSP_WHATIF_INCOMPLETE');
  return hash(preview);
}
export function nspPermissionTargets(c, phase, network) {
  const r = ids(c), n = network.ids, creating = phase.phase === 'nsp-empty-boundary', pairs = [
    [r.group, 'Microsoft.Network/networkSecurityPerimeters/read'],
    [creating ? r.group : n.perimeter, 'Microsoft.Network/networkSecurityPerimeters/profiles/read'],
    [creating ? r.group : n.perimeter, 'Microsoft.Network/networkSecurityPerimeters/resourceAssociations/read'],
    [creating ? r.group : n.profile, 'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules/read'],
    [creating ? r.group : n.perimeter, 'Microsoft.Network/networkSecurityPerimeters/links/read'],
    [creating ? r.group : n.perimeter, 'Microsoft.Network/networkSecurityPerimeters/linkReferences/read'],
    [n.account, 'Microsoft.Storage/storageAccounts/read'],
    [n.account, 'Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations/read'],
    [n.account, 'Microsoft.Storage/storageAccounts/privateEndpointConnections/read'],
    [n.service, 'Microsoft.Storage/storageAccounts/queueServices/read'],
    [n.queue, 'Microsoft.Storage/storageAccounts/queueServices/queues/read'],
    ...[creating ? r.group : n.perimeter, n.account, n.service].map(scope =>
      [scope, 'Microsoft.Insights/diagnosticSettings/read']),
  ];
  if (phase.request.method === 'PUT') pairs.push([r.group, 'Microsoft.Resources/deployments/write'],
    [r.group, 'Microsoft.Resources/deployments/read'], [r.group, 'Microsoft.Resources/deployments/operations/read'],
    [r.group, 'Microsoft.Resources/deployments/validate/action'], [r.group, 'Microsoft.Resources/deployments/whatIf/action']);
  if (phase.phase === 'nsp-empty-boundary') pairs.push([r.group, 'Microsoft.Network/networkSecurityPerimeters/write'],
    [r.group, 'Microsoft.Network/networkSecurityPerimeters/profiles/write']);
  if (phase.phase === 'nsp-storage-lock') pairs.push([n.account, 'Microsoft.Storage/storageAccounts/write']);
  if (phase.phase === 'nsp-enforced-association') pairs.push([n.perimeter, 'Microsoft.Network/networkSecurityPerimeters/resourceAssociations/write'],
    [n.profile, 'Microsoft.Network/networkSecurityPerimeters/profiles/join/action'],
    [n.account, 'Microsoft.Storage/storageAccounts/joinPerimeter/action']);
  if (['nsp-subscription-admission', 'nsp-subscription-readmit'].includes(phase.phase)) pairs.push(
    [n.profile, 'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules/write'],
    [r.sub, 'Microsoft.Resources/subscriptions/joinPerimeterRule/action']);
  if (phase.phase === 'nsp-network-deny') pairs.push([n.rule, 'Microsoft.Network/networkSecurityPerimeters/profiles/accessRules/delete']);
  return pairs.map(([scope, action]) => ({ scope, action }));
}
export function verifyNspPermissions(c, phase, network, evidence) {
  const targets = nspPermissionTargets(c, phase, network), scopes = [...new Set(targets.map(v => v.scope))];
  closed(evidence, scopes);
  const match = (pattern, action) => typeof pattern === 'string' &&
    new RegExp('^' + pattern.split('*').map(v => v.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')).join('.*') + '$', 'iu').test(action);
  for (const { scope, action } of targets) {
    const value = evidence[scope];
    closed(value, ['permissions', 'denies']);
    const permissions = list(value.permissions);
    for (const entry of permissions) {
      only(entry, ['actions', 'notActions', 'dataActions', 'notDataActions'], 'NSP_CONDITIONAL_PERMISSION_UNVERIFIED');
      for (const key of ['actions', 'notActions', 'dataActions', 'notDataActions']) {
        if (Object.hasOwn(entry, key) && (!Array.isArray(entry[key]) ||
            entry[key].some(pattern => typeof pattern !== 'string' || !pattern.length || pattern.length > 512))) fail('NSP_PERMISSION_SHAPE_UNVERIFIED');
      }
    }
    if (list(value.denies).length || !permissions.some(entry =>
      Array.isArray(entry.actions) && Array.isArray(entry.notActions) &&
      entry.actions.some(pattern => match(pattern, action)) && !entry.notActions.some(pattern => match(pattern, action)))) fail('NSP_OPERATOR_PERMISSION_REQUIRED');
  }
}
export function verifyNspAttempt(c, attempt, topology, adoption, prior) {
  const { phase, publication, preflight, approval, journal } = attempt;
  closed(publication, ['commitSha', 'sourceSha256']);
  if (!/^[0-9a-f]{40}$/u.test(publication.commitSha ?? '') || !sha(publication.sourceSha256)) fail('NSP_RECORD_INVALID');
  equal(phase, buildNspPhase(c, phase.phase, topology, adoption, prior, phase.instance), 'NSP_PHASE_CHANGED');
  const at = canonicalInstant(journal.intentAt);
  if (at < canonicalInstant(prior.records.at(-1)?.receipt.completedAt ?? adoption.adoptedAt)) fail('NSP_PREDECESSOR_AFTER_INTENT');
  verifyApproval(approval, c, phase, publication.sourceSha256, at);
  verifyNspPreflight(c, phase, topology, adoption, prior, preflight, at);
  for (const key of ['configSha256', 'phaseSha256', 'sourceSha256', 'originSha256', 'receiptsSha256', 'baselineSha256', 'whatIfSha256']) {
    if (preflight[key] !== approval[key]) fail('NSP_APPROVAL_BINDING_CHANGED');
  }
  if (preflight.whatIfSha256 !== verifyNspPreview(phase, attempt.preview, preflight.preservedIds) ||
      preflight.validationSha256 !== hash(attempt.validation) ||
      (phase.request.method === 'PUT' && (attempt.validation?.properties?.provisioningState !== 'Succeeded' ||
        attempt.validation.error || attempt.validation.properties.error || attempt.validation.nextLink))) fail('NSP_PREVIEW_BINDING_CHANGED');
  if (phase.request.method !== 'PUT' && (attempt.validation !== null ||
      attempt.preview.preimageSha256 !== hash(preflight.observation.resources[phase.request.id]))) fail('NSP_PREIMAGE_BINDING_CHANGED');
  return at;
}
export function verifyNspEvidence(c, evidence, topology, adoption) {
  closed(evidence, ['version', 'kind', 'topology', 'records']);
  if (evidence.version !== 1 || evidence.kind !== 'reviewed-enforced-nsp-network' ||
      !Array.isArray(evidence.records) || evidence.records.length > NSP_LIMITS.records ||
      Buffer.byteLength(json(evidence)) > 64 * 1024 * 1024) fail('NSP_EVIDENCE_INVALID');
  verifyNspTopology(c, evidence.topology, topology, adoption);
  const prior = emptyNspEvidence(evidence.topology);
  for (const record of evidence.records) {
    if (record?.kind === 'reviewed-nsp-reconciliation') {
      verifyNspReconciledRecord(c, record, topology, adoption, prior);
      prior.records.push(record); continue;
    }
    closed(record, ['version', 'kind', 'phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'journal', 'receipt']);
    const { phase, publication, preflight, receipt, journal, approval } = record;
    if (record.version !== 1 || record.kind !== 'reviewed-nsp-phase') fail('NSP_RECORD_INVALID');
    const at = verifyNspAttempt(c, record, topology, adoption, prior);
    closed(journal, ['version', 'phaseSha256', 'approvalSha256', 'requestSha256', 'predecessorSha256',
      'intentAt', 'outcome', 'transportDispatchAttempted', 'receiptSha256']);
    closed(receipt, ['qualified', 'qualificationKind', 'stage', 'configSha256', 'phaseSha256', 'sourceSha256',
      'topologySha256', 'approvalSha256', ...Object.keys(NSP_AUTHORITY), 'deployment', 'observation', 'completedAt']);
    if (journal.version !== 1 || journal.requestSha256 !== hash(phase.request) ||
        journal.predecessorSha256 !== phase.predecessorSha256 ||
        journal.phaseSha256 !== hash(phase) || journal.approvalSha256 !== hash(approval) ||
        journal.outcome !== 'readback-qualified' || journal.transportDispatchAttempted !== true ||
        journal.receiptSha256 !== hash(receipt) || receipt.qualified !== true ||
        receipt.qualificationKind !== 'reviewed-nsp-control-plane-only' || receipt.stage !== phase.afterStage ||
        receipt.phaseSha256 !== hash(phase) || receipt.sourceSha256 !== publication.sourceSha256 ||
        receipt.approvalSha256 !== hash(approval) || receipt.configSha256 !== hash(c) ||
        receipt.topologySha256 !== hash(evidence.topology) || canonicalInstant(receipt.completedAt) < at ||
        canonicalInstant(receipt.completedAt) > at + NSP_LIMITS.stageMs) fail('NSP_RECORD_EXECUTION_INVALID');
    for (const [key, value] of Object.entries(NSP_AUTHORITY)) if (receipt[key] !== value) fail('NSP_AUTHORITY_CHANGED');
    if (phase.request.method === 'PUT') {
      if (!sameId(receipt.deployment?.id, phase.deploymentId)) fail('NSP_DEPLOYMENT_CHANGED');
      verifyDeploymentIdentity(receipt.deployment, receipt.deployment);
    } else if (receipt.deployment !== null) fail('NSP_UNEXPECTED_DEPLOYMENT');
    verifyNspTransition(c, evidence.topology, adoption, phase, preflight.observation, receipt.observation);
    if (receipt.observation.startedAt < at || receipt.observation.completedAt > canonicalInstant(receipt.completedAt)) fail('NSP_OBSERVATION_TIME_CHANGED');
    if (phase.request.method === 'PUT') for (const target of phase.resources) {
      const created = queueArmInstant(receipt.observation.resources[target.id].systemData.createdAt);
      if (created < queueArmInstant(journal.intentAt) || created > queueArmInstant(receipt.completedAt)) fail('NSP_CREATION_OUTSIDE_INTENT');
    }
    prior.records.push(record);
  }
  return evidence.records.at(-1)?.receipt ?? null;
}
export function verifyNspAdmission(c, evidence, topology, adoption) {
  const receipt = verifyNspEvidence(c, evidence, topology, adoption);
  if (!receipt || !nspAdmissionStage(receipt.stage)) fail('NSP_CURRENT_ADMISSION_REQUIRED');
  return receipt;
}
export function nspResourceInventory(c, evidence, adoption) {
  const receipt = verifyNspEvidence(c, evidence, adoption.topology, adoption);
  return { ...(receipt ? Object.fromEntries(Object.entries(receipt.observation.resources).filter(([, value]) => value !== null)) : {}),
    ...(adoption.version === 3 ? queueDefenderInventory(c, adoption.origin, adoption.proposal.defender,
      receipt?.observation.defender ?? adoption.observation.defender) : {}) };
}
export function verifyNspReconciliation(c, evidence, adoption, observation, head, at) {
  const receipt = verifyNspEvidence(c, evidence, adoption.topology, adoption);
  verifyNspObservation(c, evidence.topology, adoption, observation, receipt?.stage ?? 'adopted-disabled');
  fresh(observation, at);
  equal(head, nspLineageHead(evidence), 'NSP_LINEAGE_HEAD_CHANGED');
  if (receipt) equal(nspState(observation), nspState(receipt.observation), 'NSP_RECONCILIATION_STATE_CHANGED');
  return nspResourceInventory(c, evidence, adoption);
}
export function verifyNspQueuePreflight(c, context, proof, at) {
  closed(context, ['adoption', 'admission']);
  const { adoption, admission } = context, receipt = verifyNspAdmission(c, admission, adoption.topology, adoption);
  if (canonicalInstant(receipt.completedAt) > at ||
      proof.networkObservation?.startedAt < receipt.observation.completedAt) fail('NSP_ADMISSION_AFTER_INTENT');
  verifyNspObservation(c, admission.topology, adoption, proof.networkObservation, receipt.stage);
  fresh(proof.networkObservation, at);
  equal(nspState(proof.networkObservation), nspState(receipt.observation), 'NSP_CURRENT_STATE_CHANGED');
  equal(proof.networkLineageHead, nspLineageHead(admission), 'NSP_LINEAGE_HEAD_CHANGED');
  verifyNspBilling(c, admission.topology, proof.networkBillingReview, proof.networkBillingEvidence, proof.sourceSha256, at);
  equal(proof.networkBinding, { adoptionSha256: hash(adoption), admissionSha256: hash(admission) }, 'NSP_NETWORK_BINDING_CHANGED');
  const expected = { version: 1, admissionSha256: hash(admission), adoptionSha256: hash(adoption),
    lineageHeadSha256: hash(proof.networkLineageHead), billingReviewSha256: hash(proof.networkBillingReview),
    observationSha256: hash(proof.networkObservation) };
  equal(proof.networkPreflight, expected, 'NSP_NETWORK_PREFLIGHT_CHANGED');
  return expected;
}
export function nspReadinessBinding(context, head, billingReview, observation) {
  return { networkBinding: { adoptionSha256: hash(context.adoption), admissionSha256: hash(context.admission) },
    networkPreflight: { version: 1, admissionSha256: hash(context.admission), adoptionSha256: hash(context.adoption),
      lineageHeadSha256: hash(head), billingReviewSha256: hash(billingReview), observationSha256: hash(observation) } };
}
