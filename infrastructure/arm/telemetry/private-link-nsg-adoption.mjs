import { isDeepStrictEqual } from 'node:util';
import { closed, digest, digestJson, fail, ids, ownerTags, sameId } from './definition.mjs';
import { canonicalInstant } from './policy.mjs';
import { queueArmInstant } from './queue-adoption.mjs';
import { PRIVATE_LINK_API as API, PRIVATE_LINK_LIMITS as LIMITS, withPrivateLinkControlValidation } from './private-link.mjs';
import { privateLinkHead, privateLinkSubmissionState,
  verifyPrivateLinkOriginalNoSubmission, verifyPrivateLinkCostReview, verifyPrivateLinkMigrationReview,
  verifyPrivateLinkPolicyRevision } from './private-link-controller.mjs';
import { collectPrivateLinkSnapshot, privateLinkResourceState, verifyPrivateLinkSnapshot } from './private-link-readback.mjs';

const hash = digestJson;
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(value);
const equal = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const validationProofs = new WeakMap();
const anchorProofs = new WeakMap();
function freeze(value) {
  if (object(value) || Array.isArray(value)) {
    Object.values(value).forEach(freeze); Object.freeze(value);
  }
  return value;
}
export function withPrivateLinkNsgValidation(c, context, adoption, evidence, use) {
  if (!adoption) return use(null);
  const anchor = anchorEvidence(context, evidence);
  withPrivateLinkControlValidation(c, context, () => verifyAdoption(c, context, adoption, anchor, null));
  return useValidatedRecord(c, context, adoption, anchor, use);
}
function useValidatedRecord(c, context, adoption, anchor, use) {
  const proof = Object.freeze(Object.create(null));
  validationProofs.set(proof, { c: freeze(c), context: freeze(context), record: freeze(adoption), anchor: freeze(anchor) });
  try {
    const result = use(proof);
    if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => validationProofs.delete(proof));
    validationProofs.delete(proof); return result;
  } catch (error) { validationProofs.delete(proof); throw error; }
}
function withAnchor(c, context, evidence, original, use) {
  withPrivateLinkControlValidation(c, context, () => verifyAnchor(c, context, evidence, original));
  const proof = Object.freeze(Object.create(null));
  anchorProofs.set(proof, { c: freeze(c), context: freeze(context), evidence: freeze(evidence), original: freeze(original) });
  try {
    const result = use(proof);
    if (result && typeof result.then === 'function') return Promise.resolve(result).finally(() => anchorProofs.delete(proof));
    anchorProofs.delete(proof); return result;
  } catch (error) { anchorProofs.delete(proof); throw error; }
}
export function privateLinkNsgValidatedRecord(c, context, value, evidence = null) {
  const proof = validationProofs.get(value);
  if (!proof) return verifyPrivateLinkNsgAdoption(c, context, value, evidence);
  if (proof.c !== c || proof.context !== context) fail('PRIVATE_LINK_NSG_VALIDATION_INPUT_CHANGED');
  return proof.record;
}
export function privateLinkNsgValidatedAnchor(c, context, value) {
  const proof = validationProofs.get(value);
  if (!proof || proof.c !== c || proof.context !== context) fail('PRIVATE_LINK_NSG_VALIDATION_PROOF_REQUIRED');
  return proof.anchor;
}
export function privateLinkNsgValidationFor(c, context, adoption, proof) {
  if (!adoption) return null;
  if (!proof) return adoption;
  const record = privateLinkNsgValidatedRecord(c, context, proof);
  if (record !== adoption) fail('PRIVATE_LINK_NSG_VALIDATION_INPUT_CHANGED');
  return proof;
}
export const PRIVATE_LINK_NSG_AUTHORITY = Object.freeze({ cloudMutation: false, originalHistoryModified: false,
  originalEnvironmentExecutionQualified: false, nsgWrite: false, nsgDelete: false, nsgDetach: false,
  continuationAuthorized: false, functionalNsgEnforcementProven: false, zeroAdditionalFeeProven: false });
export const PRIVATE_LINK_NSG_ASSURANCE = Object.freeze({
  actorAttribution: 'successful-resource-writes-plus-independent-application-service-principal',
  actorHomeObjectIsLocalPrincipal: false, auditPolicyIsDeploymentAttribution: false,
  requestBodyAttestation: 'retained-provider-activity-body-with-provider-redactions',
  privacyScope: 'exact-nsg-diagnostics-and-regional-network-watcher-target-flow-log-inventories',
  globalPacketCaptureExcluded: false, privateEndpointPolicies: 'Disabled', functionalNsgEnforcementProven: false,
});
export const PRIVATE_LINK_NSG_ATTACHED_MODE = 'both-corresponding-subnets';
const unattachedMode = 'endpoint-only-apps-unattached';
export function privateLinkNsgAttachmentMode(value) {
  if (value.version === 2 && value.attachmentMode === undefined) return unattachedMode;
  if (value.version === 3 && value.attachmentMode === PRIVATE_LINK_NSG_ATTACHED_MODE) return value.attachmentMode;
  fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_REQUIRED');
}
const mode = privateLinkNsgAttachmentMode;
function modeFields(value) { mode(value); return value.version === 3 ? ['attachmentMode'] : []; }
function modeVersion(attachmentMode) {
  if (![unattachedMode, PRIVATE_LINK_NSG_ATTACHED_MODE].includes(attachmentMode)) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_REQUIRED');
  return attachmentMode === unattachedMode ? { version: 2 } : { version: 3, attachmentMode };
}
function appsTarget(targets) { return targets.apps ?? targets.unattachedApps; }
export function privateLinkNsgMembers(observed) {
  return { endpoint: observed.nsg, apps: mode(observed) === unattachedMode ? observed.unattachedNsg : observed.appsNsg };
}
function assurance(attachmentMode) {
  return attachmentMode === unattachedMode ? PRIVATE_LINK_NSG_ASSURANCE : {
    ...PRIVATE_LINK_NSG_ASSURANCE, acaCompatibility: 'unchanged-consumption-subnet-delegation-and-default-only-nsg',
    platformTrafficQualified: false, environmentProvisioningRequired: true, runtimeQualificationRequired: true,
  };
}
function adoptionAuthority(attachmentMode) {
  return attachmentMode === unattachedMode ? PRIVATE_LINK_NSG_AUTHORITY : { ...PRIVATE_LINK_NSG_AUTHORITY, nsgAttach: false };
}
function only(value, keys, code = 'PRIVATE_LINK_NSG_SHAPE_UNREVIEWED') {
  if (!object(value) || Object.keys(value).some(key => !keys.includes(key))) fail(code);
}
function list(response) {
  only(response, ['value', 'nextLink'], 'PRIVATE_LINK_NSG_LIST_INCOMPLETE');
  if (!Array.isArray(response.value) || response.value.length > LIMITS.items ||
      (response.nextLink !== undefined && response.nextLink !== null)) fail('PRIVATE_LINK_NSG_LIST_INCOMPLETE');
  return response.value;
}
function times(startedAt, completedAt) {
  if (!Number.isSafeInteger(startedAt) || !Number.isSafeInteger(completedAt) || completedAt < startedAt ||
      completedAt - startedAt > LIMITS.checkMs) fail('PRIVATE_LINK_NSG_OBSERVATION_TIME_INVALID');
}
function fresh(value, at) {
  times(value.startedAt, value.completedAt);
  if (value.completedAt > at || at - value.startedAt > LIMITS.freshnessMs) fail('PRIVATE_LINK_NSG_OBSERVATION_EXPIRED');
}
function reviewTime(review, at) {
  const start = canonicalInstant(review.approvedAt), end = canonicalInstant(review.expiresAt);
  if (!Number.isSafeInteger(at) || start > at || at >= end || end - start > LIMITS.reviewMs) fail('PRIVATE_LINK_NSG_REVIEW_EXPIRED');
}
function safeResourceId(value) {
  return typeof value === 'string' && !/[%?#\\]|\.\./u.test(value) &&
    /^\/subscriptions\/[0-9a-f-]{36}\/resourceGroups\/[A-Za-z0-9_.()-]+\/providers\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+$/u.test(value);
}
export function privateLinkNsgTarget(c, context) {
  const n = context.plan.topology.ids, name = `${n.vnet.split('/').at(-1)}-private-endpoints-nsg-australiaeast`;
  return { id: `${ids(c).group}/providers/Microsoft.Network/networkSecurityGroups/${name}`,
    name, subnet: n.endpointSubnet, vnet: n.vnet, apiVersion: API.network };
}
export function privateLinkNsgTargets(c, context, attachmentMode = unattachedMode) {
  modeVersion(attachmentMode);
  const endpoint = privateLinkNsgTarget(c, context);
  const name = `${context.plan.topology.ids.vnet.split('/').at(-1)}-apps-nsg-australiaeast`;
  return { endpoint, [attachmentMode === unattachedMode ? 'unattachedApps' : 'apps']: {
    id: `${ids(c).group}/providers/Microsoft.Network/networkSecurityGroups/${name}`,
    name, subnet: attachmentMode === unattachedMode ? null : context.plan.topology.ids.appsSubnet,
    vnet: endpoint.vnet, apiVersion: API.network } };
}
const defaults = Object.freeze([
  ['AllowVnetInBound', 65000, 'Allow', 'Inbound', 'VirtualNetwork', 'VirtualNetwork'],
  ['AllowAzureLoadBalancerInBound', 65001, 'Allow', 'Inbound', 'AzureLoadBalancer', '*'],
  ['DenyAllInBound', 65500, 'Deny', 'Inbound', '*', '*'],
  ['AllowVnetOutBound', 65000, 'Allow', 'Outbound', 'VirtualNetwork', 'VirtualNetwork'],
  ['AllowInternetOutBound', 65001, 'Allow', 'Outbound', '*', 'Internet'],
  ['DenyAllOutBound', 65500, 'Deny', 'Outbound', '*', '*'],
]);
function nsgValue(c, context, value, t = privateLinkNsgTarget(c, context)) {
  only(value, ['id', 'name', 'type', 'location', 'tags', 'etag', 'properties', 'systemData']);
  if (!sameId(value.id, t.id) || value.name !== t.name || value.type !== 'Microsoft.Network/networkSecurityGroups' ||
      value.location !== 'australiaeast' || !isDeepStrictEqual(value.tags, ownerTags(c))) fail('PRIVATE_LINK_NSG_EXACT_TARGET_REQUIRED');
  const p = value.properties;
  only(p, ['provisioningState', 'resourceGuid', 'securityRules', 'defaultSecurityRules', 'subnets', 'networkInterfaces', 'flowLogs']);
  if (p.provisioningState !== 'Succeeded' || !uuid(p.resourceGuid) || !isDeepStrictEqual(p.securityRules, []) ||
      !Array.isArray(p.defaultSecurityRules) || p.defaultSecurityRules.length !== defaults.length ||
      (t.subnet ? !Array.isArray(p.subnets) || p.subnets.length !== 1 : p.subnets !== undefined && !isDeepStrictEqual(p.subnets, [])) ||
      (t.subnet && !sameId(p.subnets[0]?.id, t.subnet))) fail('PRIVATE_LINK_NSG_RULES_OR_ATTACHMENTS_CHANGED');
  if (t.subnet) closed(p.subnets[0], ['id']);
  for (const key of ['networkInterfaces', 'flowLogs']) if (Object.hasOwn(p, key)) equal(p[key], [], 'PRIVATE_LINK_NSG_ADDITIONAL_BINDING');
  const seen = new Set();
  for (const rule of p.defaultSecurityRules) {
    only(rule, ['id', 'name', 'type', 'etag', 'properties']);
    const expected = defaults.find(row => row[0] === rule.name);
    if (!expected || seen.has(rule.name) || !sameId(rule.id, `${t.id}/defaultSecurityRules/${rule.name}`) ||
        rule.type !== 'Microsoft.Network/networkSecurityGroups/defaultSecurityRules') fail('PRIVATE_LINK_NSG_DEFAULT_RULE_CHANGED');
    seen.add(rule.name);
    const rp = rule.properties;
    closed(rp, ['access', 'description', 'destinationAddressPrefix', 'destinationAddressPrefixes', 'destinationPortRange',
      'destinationPortRanges', 'direction', 'priority', 'protocol', 'provisioningState', 'sourceAddressPrefix',
      'sourceAddressPrefixes', 'sourcePortRange', 'sourcePortRanges']);
    if (typeof rp.description !== 'string' || !rp.description ||
        !isDeepStrictEqual([rp.priority, rp.access, rp.direction, rp.sourceAddressPrefix, rp.destinationAddressPrefix], expected.slice(1)) ||
        rp.protocol !== '*' || rp.sourcePortRange !== '*' || rp.destinationPortRange !== '*' ||
        rp.provisioningState !== 'Succeeded' ||
        ['sourceAddressPrefixes', 'destinationAddressPrefixes', 'sourcePortRanges', 'destinationPortRanges'].some(key => !isDeepStrictEqual(rp[key], []))) fail('PRIVATE_LINK_NSG_DEFAULT_RULE_CHANGED');
  }
  return value;
}
function nsgState(value) {
  const result = privateLinkResourceState(value);
  if (result.properties.subnets !== undefined) result.properties.subnets = result.properties.subnets.map(v => ({ id: v.id.toLowerCase() }));
  result.properties.defaultSecurityRules = result.properties.defaultSecurityRules.map(v => {
    const rule = structuredClone(v);
    if (Object.hasOwn(rule, 'etag')) { if (typeof rule.etag !== 'string') fail('PRIVATE_LINK_NSG_ETAG_INVALID'); delete rule.etag; }
    rule.id = rule.id.toLowerCase(); return rule;
  }).sort((a, b) => a.name.localeCompare(b.name));
  return result;
}
export function privateLinkNsgReadRequests(c, context) {
  const targets = privateLinkNsgTargets(c, context), t = targets.endpoint, request = id => ({ id, apiVersion: API.network, filter: null });
  return { nsg: request(t.id), diagnostics: { id: `${t.id}/providers/Microsoft.Insights/diagnosticSettings`,
    apiVersion: '2021-05-01-preview', filter: null },
  unattachedNsg: request(targets.unattachedApps.id), unattachedDiagnostics: {
    id: `${targets.unattachedApps.id}/providers/Microsoft.Insights/diagnosticSettings`, apiVersion: '2021-05-01-preview', filter: null },
  watchers: request(`${ids(c).sub}/providers/Microsoft.Network/networkWatchers`) };
}
export function privateLinkNsgRegionalWatchers(c, response) {
  const seen = new Set();
  return list(response).filter(value => {
    if (!safeResourceId(value?.id) || !sameId(value.id.split('/resourceGroups/')[0], ids(c).sub) ||
        !new RegExp('/providers/Microsoft\\.Network/networkWatchers/[A-Za-z0-9_-]+$', 'iu').test(value.id) ||
        !sameId(value.type, 'Microsoft.Network/networkWatchers') || typeof value.location !== 'string' ||
        seen.has(value.id.toLowerCase())) fail('PRIVATE_LINK_NSG_WATCHER_SCOPE_INVALID');
    seen.add(value.id.toLowerCase());
    if (value.location.replaceAll(' ', '').toLowerCase() !== c.location) return false;
    if (value.properties?.provisioningState !== 'Succeeded') fail('PRIVATE_LINK_NSG_WATCHER_UNVERIFIED');
    return true;
  });
}
export function verifyPrivateLinkNsgCurrent(c, context, observed, pinned = null) {
  const attachmentMode = mode(observed), attached = attachmentMode === PRIVATE_LINK_NSG_ATTACHED_MODE;
  closed(observed, ['version', 'kind', 'startedAt', 'completedAt', 'nsg', 'diagnostics',
    ...(attached ? ['attachmentMode', 'appsNsg', 'appsDiagnostics'] : ['unattachedNsg', 'unattachedDiagnostics']), 'watchers', 'flowLogs']);
  if (observed.kind !== 'observed-exact-private-link-governance-nsgs') fail('PRIVATE_LINK_NSG_OBSERVATION_REQUIRED');
  times(observed.startedAt, observed.completedAt);
  const targets = privateLinkNsgTargets(c, context, attachmentMode), members = privateLinkNsgMembers(observed), apps = appsTarget(targets);
  nsgValue(c, context, observed.nsg);
  nsgValue(c, context, members.apps, apps);
  if (list(observed.diagnostics).length || list(attached ? observed.appsDiagnostics : observed.unattachedDiagnostics).length) fail('PRIVATE_LINK_NSG_DIAGNOSTICS_FORBIDDEN');
  const regional = privateLinkNsgRegionalWatchers(c, observed.watchers), t = privateLinkNsgTarget(c, context);
  closed(observed.flowLogs, regional.map(value => value.id));
  for (const watcher of regional) {
    for (const flow of list(observed.flowLogs[watcher.id])) {
      if (!safeResourceId(flow?.id) || !sameId(flow.id.slice(0, flow.id.lastIndexOf('/flowLogs/')), watcher.id) ||
          !sameId(flow.type, 'Microsoft.Network/networkWatchers/flowLogs') || typeof flow.properties?.targetResourceId !== 'string') fail('PRIVATE_LINK_NSG_FLOW_LOG_UNVERIFIED');
      if ([t.id, apps.id, t.vnet, t.subnet, context.plan.topology.ids.appsSubnet].some(id => sameId(flow.properties.targetResourceId, id))) {
        fail('PRIVATE_LINK_NSG_TARGET_FLOW_LOG_FORBIDDEN');
      }
    }
  }
  if (pinned) {
    if (mode(pinned) !== attachmentMode) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_CHANGED');
    equal(nsgState(observed.nsg), nsgState(pinned.nsg), 'PRIVATE_LINK_NSG_PINNED_STATE_CHANGED');
    equal(nsgState(members.apps), nsgState(privateLinkNsgMembers(pinned).apps), 'PRIVATE_LINK_NSG_PINNED_STATE_CHANGED');
  }
  return observed;
}
export async function collectPrivateLinkNsgCurrent(c, context, io, deadline, attachmentMode = unattachedMode) {
  const version = modeVersion(attachmentMode);
  const startedAt = io.now(), requests = privateLinkNsgReadRequests(c, context);
  const [nsg, diagnostics, unattachedNsg, unattachedDiagnostics, watchers] = await io.batch(Object.values(requests),
    request => io.read(request, deadline, [requests.diagnostics, requests.unattachedDiagnostics, requests.watchers].includes(request)));
  const flows = await io.batch(privateLinkNsgRegionalWatchers(c, watchers), async watcher => [watcher.id,
    await io.read({ id: `${watcher.id}/flowLogs`, apiVersion: API.network, filter: null }, deadline, true)]);
  const result = { ...version, kind: 'observed-exact-private-link-governance-nsgs', startedAt, completedAt: io.now(),
    nsg, diagnostics, ...(version.version === 2 ? { unattachedNsg, unattachedDiagnostics } : {
      appsNsg: unattachedNsg, appsDiagnostics: unattachedDiagnostics }), watchers, flowLogs: Object.fromEntries(flows) };
  if (result.completedAt >= deadline) fail('PRIVATE_LINK_NSG_READ_DEADLINE');
  return verifyPrivateLinkNsgCurrent(c, context, result);
}
function idCopies(value) {
  const copy = structuredClone(value);
  const clean = entry => {
    if (!object(entry)) return;
    if (typeof entry.id === 'string') {
      entry.id = entry.id.toLowerCase();
      if (Object.hasOwn(entry, 'etag')) {
        if (typeof entry.etag !== 'string') fail('PRIVATE_LINK_NSG_ETAG_INVALID');
        delete entry.etag;
      }
    }
    if (Array.isArray(entry.properties?.subnets)) {
      entry.properties.subnets.forEach(clean);
      entry.properties.subnets.sort((a, b) => a.id.localeCompare(b.id));
    }
    if (Array.isArray(entry.properties?.delegations)) entry.properties.delegations.forEach(clean);
  };
  clean(copy);
  return copy;
}
function compareState(s) {
  const value = structuredClone(s);
  delete value.startedAt; delete value.completedAt; delete value.externalNsg;
  value.version = 1;
  value.resources = Object.fromEntries(Object.entries(value.resources).map(([id, resource]) => {
    if (!resource) return [id, resource];
    const result = idCopies(privateLinkResourceState(resource));
    if (sameId(result.type, 'Microsoft.Consumption/budgets')) { delete result.properties.currentSpend; delete result.properties.forecastSpend; }
    return [id, result];
  }));
  for (const key of ['subnets', 'addressSpaces', 'groupResources']) {
    const values = value.lists[key].value.map(idCopies);
    value.lists[key].value = values.sort((a, b) => a.id.localeCompare(b.id));
  }
  return value;
}
function stripAttachment(c, context, observed, original) {
  const result = structuredClone(observed), n = context.plan.topology.ids, target = privateLinkNsgTarget(c, context);
  const attached = mode(observed.externalNsg) === PRIVATE_LINK_NSG_ATTACHED_MODE;
  const apps = appsTarget(privateLinkNsgTargets(c, context, mode(observed.externalNsg)));
  delete result.externalNsg; result.version = 1;
  function subnet(value, before) {
    const copy = structuredClone(value);
    if (sameId(copy.id, n.endpointSubnet) || (attached && sameId(copy.id, n.appsSubnet))) {
      closed(copy.properties.networkSecurityGroup, ['id']);
      if (!sameId(copy.properties.networkSecurityGroup.id, sameId(copy.id, n.endpointSubnet) ? target.id : apps.id)) fail('PRIVATE_LINK_NSG_ATTACHMENT_CHANGED');
      delete copy.properties.networkSecurityGroup;
    } else if (copy.properties.networkSecurityGroup) fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_FORBIDDEN');
    if (!Object.hasOwn(before.properties, 'serviceEndpoints') && isDeepStrictEqual(copy.properties.serviceEndpoints, [])) delete copy.properties.serviceEndpoints;
    return copy;
  }
  function vnet(value, before) {
    const copy = structuredClone(value);
    if (!Object.hasOwn(before.properties, 'dhcpOptions') && isDeepStrictEqual(copy.properties.dhcpOptions, { dnsServers: [] })) delete copy.properties.dhcpOptions;
    copy.properties.subnets = copy.properties.subnets.map(s => {
      const matching = before.properties.subnets.find(old => sameId(old.id, s.id));
      if (!matching) fail('PRIVATE_LINK_NSG_SUBNET_SET_CHANGED');
      return subnet(s, matching);
    });
    return copy;
  }
  for (const id of [n.appsSubnet, n.endpointSubnet]) result.resources[id] = subnet(result.resources[id], original.resources[id]);
  result.resources[n.vnet] = vnet(result.resources[n.vnet], original.resources[n.vnet]);
  result.lists.subnets.value = result.lists.subnets.value.map(value => subnet(value,
    original.lists.subnets.value.find(old => sameId(old.id, value.id))));
  result.lists.addressSpaces.value = result.lists.addressSpaces.value.map(value => sameId(value.id, n.vnet)
    ? vnet(value, original.lists.addressSpaces.value.find(old => sameId(old.id, n.vnet))) : value);
  const allowed = Object.values(privateLinkNsgTargets(c, context)).map(value => value.id);
  result.lists.groupResources.value = result.lists.groupResources.value.filter(value => !allowed.some(id => sameId(value.id, id)));
  return result;
}
export function verifyPrivateLinkNsgDelta(c, context, observed, original) {
  if (!observed.externalNsg) fail('PRIVATE_LINK_NSG_CURRENT_READBACK_REQUIRED');
  verifyPrivateLinkNsgCurrent(c, context, observed.externalNsg);
  if (mode(observed.externalNsg) === PRIVATE_LINK_NSG_ATTACHED_MODE) verifyPrivateLinkNsgAcaCompatibility(c, context, observed);
  const projected = stripAttachment(c, context, observed, original);
  equal(compareState(projected), compareState(original), 'PRIVATE_LINK_NSG_UNRELATED_EXTERNAL_DRIFT');
  return projected;
}
export function verifyPrivateLinkNsgAcaCompatibility(c, context, observed) {
  if (mode(observed.externalNsg) !== PRIVATE_LINK_NSG_ATTACHED_MODE) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_REQUIRED');
  const n = context.plan.topology.ids, targets = privateLinkNsgTargets(c, context, PRIVATE_LINK_NSG_ATTACHED_MODE);
  const apps = observed.resources[n.appsSubnet]?.properties;
  const environment = context.plan.stages.find(stage => stage.id === 'create-environment')?.resources[0]?.expected?.properties;
  if (!apps || apps.addressPrefix !== context.plan.topology.addresses.apps ||
      !sameId(apps.networkSecurityGroup?.id, targets.apps.id) || apps.routeTable || apps.natGateway ||
      apps.privateEndpointNetworkPolicies !== 'Disabled' || apps.privateLinkServiceNetworkPolicies !== 'Enabled' ||
      apps.delegations?.length !== 1 || apps.delegations[0].properties?.serviceName !== 'Microsoft.App/environments' ||
      !sameId(environment?.vnetConfiguration?.infrastructureSubnetId, n.appsSubnet) ||
      !isDeepStrictEqual(environment.workloadProfiles, [{ name: 'Consumption', workloadProfileType: 'Consumption' }])) {
    fail('PRIVATE_LINK_NSG_ACA_CONFIGURATION_INCOMPATIBLE');
  }
  verifyPrivateLinkNsgCurrent(c, context, observed.externalNsg);
  return { version: 1, kind: 'private-link-aca-default-nsg-configuration-compatibility', appsSubnetId: n.appsSubnet,
    appsNsgId: targets.apps.id, environmentId: n.environment, environmentApiVersion: API.app,
    delegation: 'Microsoft.App/environments', workloadProfile: 'Consumption', customSecurityRules: 0,
    defaultsSha256: hash(nsgState(observed.externalNsg.appsNsg).properties.defaultSecurityRules),
    platformTrafficQualified: false, environmentProvisioningRequired: true, runtimeQualificationRequired: true };
}
function rawActivity(c, context, capture, target) {
  const response = capture.response, events = list(response), endpoint = `${ids(c).sub}/providers/Microsoft.Insights/eventtypes/management/values`;
  if (capture.id !== undefined) {
    closed(capture, ['id', 'version', 'startedAt', 'completedAt', 'response']);
    if (!sameId(capture.id, endpoint) || capture.version !== '2015-04-01' ||
        canonicalInstant(capture.completedAt) < canonicalInstant(capture.startedAt)) fail('PRIVATE_LINK_NSG_ACTIVITY_CAPTURE_INVALID');
  } else {
    closed(capture, ['url', 'response', 'observedAt']);
    const url = new URL(capture.url);
    if (url.origin !== 'https://management.azure.com' || !sameId(url.pathname, endpoint) || url.username || url.password || url.hash ||
        url.searchParams.get('api-version') !== '2015-04-01' ||
        !url.searchParams.get('$filter')?.toLowerCase().includes(`resourceuri eq '${target.toLowerCase()}'`)) fail('PRIVATE_LINK_NSG_ACTIVITY_CAPTURE_INVALID');
    canonicalInstant(capture.observedAt);
  }
  const seen = new Set();
  for (const event of events) {
    if (!sameId(event.resourceId, target) || !sameId(event.subscriptionId, c.subscriptionId) ||
        !uuid(event.tenantId) || !uuid(event.eventDataId) || seen.has(event.eventDataId) ||
        typeof event.operationName?.value !== 'string' || typeof event.status?.value !== 'string') fail('PRIVATE_LINK_NSG_ACTIVITY_SCOPE_CHANGED');
    queueArmInstant(event.eventTimestamp); queueArmInstant(event.submissionTimestamp);
    seen.add(event.eventDataId);
  }
  return events;
}
function actorMatch(event, actor) {
  const claims = event.claims;
  return claims?.idtyp === 'app' && sameId(claims.appid, actor.appId) &&
    sameId(event.tenantId, actor.homeTenantId) &&
    sameId(claims['http://schemas.microsoft.com/identity/claims/tenantid'], actor.homeTenantId) &&
    sameId(claims['http://schemas.microsoft.com/identity/claims/objectidentifier'], actor.homeObjectId) &&
    sameId(event.caller, actor.homeObjectId) && claims.iss === `https://sts.windows.net/${actor.homeTenantId}/`;
}
function eventBody(event, key) {
  const bytes = event.properties?.[key];
  if (typeof bytes !== 'string' || Buffer.byteLength(bytes) > 2 * 1024 * 1024) fail('PRIVATE_LINK_NSG_ACTIVITY_BODY_REQUIRED');
  try { return JSON.parse(bytes); } catch { fail('PRIVATE_LINK_NSG_ACTIVITY_BODY_INVALID'); }
}
export function verifyPrivateLinkNsgProvenance(c, context, provenance, observed, original) {
  const attachmentMode = mode(provenance), attached = attachmentMode === PRIVATE_LINK_NSG_ATTACHED_MODE;
  closed(provenance, ['version', 'kind', 'actor', 'writer', 'nsgActivity', 'unattachedNsgActivity', 'subnetActivity', 'vnetActivity',
    ...(attached ? ['attachmentMode', 'appsAttachmentActivity'] : [])]);
  if (mode(observed) !== attachmentMode) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_CHANGED');
  closed(provenance.actor, ['appId', 'homeTenantId', 'homeObjectId', 'localServicePrincipalId', 'displayName']);
  const actor = provenance.actor, target = privateLinkNsgTarget(c, context), writer = provenance.writer;
  if (provenance.kind !== 'exact-private-link-governance-nsgs-provenance' ||
      !['appId', 'homeTenantId', 'homeObjectId', 'localServicePrincipalId'].every(key => uuid(actor[key])) ||
      typeof actor.displayName !== 'string' || !actor.displayName.trim()) fail('PRIVATE_LINK_NSG_ACTOR_PINS_REQUIRED');
  closed(writer, ['appid', 'response', 'observedAt']);
  const sp = writer.response;
  closed(sp, ['accountEnabled', 'appId', 'appOwnerOrganizationId', 'displayName', 'id', 'servicePrincipalType']);
  if (!sameId(writer.appid, actor.appId) || !sameId(sp.appId, actor.appId) ||
      !sameId(sp.appOwnerOrganizationId, actor.homeTenantId) || !sameId(sp.id, actor.localServicePrincipalId) ||
      sp.accountEnabled !== true || sp.servicePrincipalType !== 'Application' || sp.displayName !== actor.displayName) fail('PRIVATE_LINK_NSG_ACTOR_ATTRIBUTION_CHANGED');
  canonicalInstant(writer.observedAt);
  const nsgEvents = rawActivity(c, context, provenance.nsgActivity, target.id);
  const appsTarget = privateLinkNsgTargets(c, context).unattachedApps;
  const appsEvents = rawActivity(c, context, provenance.unattachedNsgActivity, appsTarget.id);
  const subnetEvents = rawActivity(c, context, provenance.subnetActivity, target.subnet);
  const vnetEvents = rawActivity(c, context, provenance.vnetActivity, target.vnet);
  const laterThan = BigInt(original.preflight.before.completedAt) * 10000n;
  const before = BigInt(observed.completedAt) * 10000n;
  const successes = (events, operation, id) => events.filter(e => {
    if (queueArmInstant(e.eventTimestamp) < laterThan) return false;
    if (!sameId(e.operationName.value, operation)) {
      if (!/^Microsoft\.Authorization\/policies\/(?:audit|auditIfNotExists)\/action$/iu.test(e.operationName.value)) fail('PRIVATE_LINK_NSG_UNREVIEWED_ACTIVITY');
      return false;
    }
    if (!actorMatch(e, actor) || !sameId(e.authorization?.action, operation) ||
        !sameId(e.authorization?.scope, id) || queueArmInstant(e.eventTimestamp) > before) fail('PRIVATE_LINK_NSG_WRITE_ATTRIBUTION_CHANGED');
    if (['Failed', 'Canceled'].includes(e.status.value)) fail('PRIVATE_LINK_NSG_ACTIVITY_UNSETTLED');
    return e.status.value === 'Succeeded';
  });
  const nsgWrites = successes(nsgEvents, 'Microsoft.Network/networkSecurityGroups/write', target.id);
  const appsWrites = successes(appsEvents, 'Microsoft.Network/networkSecurityGroups/write', appsTarget.id);
  const vnetWrites = successes(vnetEvents, 'Microsoft.Network/virtualNetworks/write', target.vnet);
  if (nsgWrites.length !== 1 || appsWrites.length !== 1 || !vnetWrites.length) fail('PRIVATE_LINK_NSG_SUCCESSFUL_WRITES_REQUIRED');
  for (const [events, writes, operation] of [[nsgEvents, nsgWrites, 'Microsoft.Network/networkSecurityGroups/write'],
    [appsEvents, appsWrites, 'Microsoft.Network/networkSecurityGroups/write'],
    [vnetEvents, vnetWrites, 'Microsoft.Network/virtualNetworks/write']]) {
    const mutations = events.filter(event => queueArmInstant(event.eventTimestamp) >= laterThan && sameId(event.operationName.value, operation));
    if (mutations.length !== writes.length * 3 || mutations.some(event => !uuid(event.correlationId) ||
        !writes.some(write => write.correlationId === event.correlationId))) fail('PRIVATE_LINK_NSG_ACTIVITY_UNSETTLED');
  }
  for (const event of subnetEvents) if (queueArmInstant(event.eventTimestamp) >= laterThan &&
      !sameId(event.operationName.value, 'Microsoft.Authorization/policies/audit/action') &&
      !sameId(event.operationName.value, 'Microsoft.Authorization/policies/auditIfNotExists/action')) fail('PRIVATE_LINK_NSG_UNREVIEWED_SUBNET_WRITE');
  const eventsFor = (events, success) => {
    const group = events.filter(e => e.correlationId === success.correlationId &&
      sameId(e.operationName.value, success.operationName.value));
    const starts = group.filter(e => e.status.value === 'Started'), accepted = group.filter(e => e.status.value === 'Accepted');
    if (starts.length !== 1 || accepted.length !== 1 || group.some(e => !actorMatch(e, actor)) ||
        queueArmInstant(starts[0].eventTimestamp) > queueArmInstant(accepted[0].eventTimestamp) ||
        queueArmInstant(accepted[0].eventTimestamp) > queueArmInstant(success.eventTimestamp)) fail('PRIVATE_LINK_NSG_ACTIVITY_SEQUENCE_REQUIRED');
    return { request: eventBody(starts[0], 'requestbody'), response: eventBody(accepted[0], 'responseBody'),
      startedAt: starts[0].eventTimestamp, acceptedAt: accepted[0].eventTimestamp };
  };
  for (const [events, success, targetId, current] of [[nsgEvents, nsgWrites[0], target.id, observed.nsg],
    [appsEvents, appsWrites[0], appsTarget.id, privateLinkNsgMembers(observed).apps]]) {
  const nsgWrite = eventsFor(events, success);
  closed(nsgWrite.request, ['properties', 'location', 'tags']); closed(nsgWrite.request.properties, ['securityRules']);
  if (!isDeepStrictEqual(nsgWrite.request.properties.securityRules, []) || nsgWrite.request.location !== c.location ||
      !(nsgWrite.request.tags === '******' || isDeepStrictEqual(nsgWrite.request.tags, ownerTags(c))) ||
      !sameId(nsgWrite.response.id, targetId) ||
      nsgWrite.response.properties?.resourceGuid !== current.properties.resourceGuid ||
      !isDeepStrictEqual(nsgWrite.response.properties.securityRules, [])) fail('PRIVATE_LINK_NSG_CREATED_BODY_CHANGED');
  const acceptedRules = nsgWrite.response.properties.defaultSecurityRules;
  if (!Array.isArray(acceptedRules) || acceptedRules.length !== 6) fail('PRIVATE_LINK_NSG_CREATED_BODY_CHANGED');
  equal(acceptedRules.map(rule => {
    const copy = structuredClone(rule); delete copy.etag; copy.id = copy.id.toLowerCase();
    if (!['Updating', 'Succeeded'].includes(copy.properties.provisioningState)) fail('PRIVATE_LINK_NSG_CREATED_RULES_CHANGED');
    copy.properties.provisioningState = 'Succeeded'; return copy;
  }).sort((a, b) => a.name.localeCompare(b.name)), nsgState(current).properties.defaultSecurityRules, 'PRIVATE_LINK_NSG_CREATED_RULES_CHANGED');
  }
  const writes = vnetWrites.map(success => ({ success, ...eventsFor(vnetEvents, success) }))
    .sort((a, b) => queueArmInstant(a.acceptedAt) < queueArmInstant(b.acceptedAt) ? -1 : 1);
  const vnetWrite = writes.at(-1), last = vnetWrite.success;
  // Successful terminal events can arrive out of order for overlapping VNet writes.
  // The latest accepted body must independently match the freshly observed attachment.
  for (const prior of writes.slice(0, -1)) {
    const request = prior.request, response = prior.response;
    const subnets = request.properties?.subnets, returned = response.properties?.subnets;
    const apps = subnets?.find(value => sameId(value.id, context.plan.topology.ids.appsSubnet));
    const endpoint = subnets?.find(value => sameId(value.id, target.subnet));
    if (!sameId(request.id, target.vnet) || !sameId(response.id, target.vnet) || subnets?.length !== 2 || returned?.length !== 2 ||
        !sameId(apps?.properties?.networkSecurityGroup?.id, appsTarget.id) || endpoint?.properties?.networkSecurityGroup ||
        !sameId(returned.find(value => sameId(value.id, apps.id))?.properties?.networkSecurityGroup?.id, appsTarget.id) ||
        returned.find(value => sameId(value.id, endpoint.id))?.properties?.networkSecurityGroup ||
        response.properties.resourceGuid !== original.preflight.before.resources[target.vnet].properties.resourceGuid ||
        queueArmInstant(prior.acceptedAt) >= queueArmInstant(vnetWrite.acceptedAt)) fail('PRIVATE_LINK_NSG_PRIOR_ASSOCIATION_BODY_CHANGED');
    equal(apps.properties.networkSecurityGroup.properties?.securityRules, [], 'PRIVATE_LINK_NSG_PRIOR_ASSOCIATION_BODY_CHANGED');
    if (endpoint.properties.addressPrefix !== context.plan.topology.addresses.endpoint ||
        apps.properties.addressPrefix !== context.plan.topology.addresses.apps ||
        endpoint.properties.privateEndpointNetworkPolicies !== 'Disabled' || !isDeepStrictEqual(endpoint.properties.delegations, []) ||
        apps.properties.delegations?.length !== 1 || apps.properties.delegations[0].properties?.serviceName !== 'Microsoft.App/environments' ||
        endpoint.properties.routeTable || endpoint.properties.natGateway || apps.properties.routeTable || apps.properties.natGateway) {
      fail('PRIVATE_LINK_NSG_PRIOR_ASSOCIATION_BODY_CHANGED');
    }
  }
  if (!sameId(vnetWrite.request.id, target.vnet) || !sameId(vnetWrite.response.id, target.vnet) ||
      vnetWrite.response.properties?.resourceGuid !== original.preflight.before.resources[target.vnet].properties.resourceGuid ||
      !isDeepStrictEqual(vnetWrite.request.properties?.addressSpace, { addressPrefixes: [context.plan.topology.addresses.vnet] })) fail('PRIVATE_LINK_NSG_VNET_BODY_CHANGED');
  const endpoint = vnetWrite.request.properties.subnets?.find(s => sameId(s.id, target.subnet));
  const apps = vnetWrite.request.properties.subnets?.find(s => sameId(s.id, context.plan.topology.ids.appsSubnet));
  if (vnetWrite.request.properties.subnets?.length !== 2 || !sameId(endpoint?.properties?.networkSecurityGroup?.id, target.id) ||
      endpoint.properties.privateEndpointNetworkPolicies !== 'Disabled' || apps?.properties?.networkSecurityGroup ||
      endpoint.properties.routeTable || endpoint.properties.natGateway || apps?.properties?.routeTable || apps?.properties?.natGateway) fail('PRIVATE_LINK_NSG_ASSOCIATION_BODY_CHANGED');
  equal(endpoint.properties.networkSecurityGroup.properties?.securityRules, [], 'PRIVATE_LINK_NSG_ASSOCIATION_BODY_CHANGED');
  if (endpoint.properties.addressPrefix !== context.plan.topology.addresses.endpoint ||
      apps.properties.addressPrefix !== context.plan.topology.addresses.apps ||
      !isDeepStrictEqual(endpoint.properties.delegations, []) ||
      apps.properties.delegations?.length !== 1 ||
      apps.properties.delegations[0].properties?.serviceName !== 'Microsoft.App/environments') fail('PRIVATE_LINK_NSG_ASSOCIATION_BODY_CHANGED');
  const responseEndpoint = vnetWrite.response.properties.subnets?.find(s => sameId(s.id, target.subnet));
  const responseApps = vnetWrite.response.properties.subnets?.find(s => sameId(s.id, context.plan.topology.ids.appsSubnet));
  if (vnetWrite.response.properties.subnets?.length !== 2 || !responseApps || responseApps.properties.networkSecurityGroup ||
      !sameId(responseEndpoint?.properties?.networkSecurityGroup?.id, target.id)) fail('PRIVATE_LINK_NSG_ASSOCIATION_BODY_CHANGED');
  let appsAttachment = null;
  if (attached) {
    const events = rawActivity(c, context, provenance.appsAttachmentActivity, target.vnet);
    const matches = successes(events, 'Microsoft.Network/virtualNetworks/write', target.vnet);
    const mutations = events.filter(event => queueArmInstant(event.eventTimestamp) >= laterThan &&
      sameId(event.operationName.value, 'Microsoft.Network/virtualNetworks/write'));
    if (matches.length !== 1 || mutations.length !== 3 || mutations.some(event => event.correlationId !== matches[0].correlationId) ||
        !uuid(matches[0].correlationId) || writes.some(value => value.success.correlationId === matches[0].correlationId)) {
      fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_SEQUENCE_REQUIRED');
    }
    const change = eventsFor(events, matches[0]);
    if (writes.some(value => queueArmInstant(value.success.eventTimestamp) >= queueArmInstant(change.startedAt))) {
      fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_SEQUENCE_REQUIRED');
    }
    for (const body of [change.request, change.response]) {
      if (!sameId(body.id, target.vnet) || body.properties.subnets?.length !== 2 ||
          !isDeepStrictEqual(body.properties.addressSpace, { addressPrefixes: [context.plan.topology.addresses.vnet] })) {
        fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_BODY_CHANGED');
      }
      for (const [id, address, expectedNsg, isApps] of [
        [target.subnet, context.plan.topology.addresses.endpoint, target.id, false],
        [context.plan.topology.ids.appsSubnet, context.plan.topology.addresses.apps, appsTarget.id, true],
      ]) {
        const subnet = body.properties.subnets.find(value => sameId(value.id, id)), p = subnet?.properties;
        if (!p || p.addressPrefix !== address || !sameId(p.networkSecurityGroup?.id, expectedNsg) ||
            p.routeTable || p.natGateway || p.privateEndpointNetworkPolicies !== 'Disabled' ||
            p.privateLinkServiceNetworkPolicies !== 'Enabled' ||
            (isApps ? p.delegations?.length !== 1 || p.delegations[0].properties?.serviceName !== 'Microsoft.App/environments'
              : !isDeepStrictEqual(p.delegations, []))) fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_BODY_CHANGED');
        if (body === change.request && p.networkSecurityGroup.properties !== undefined) {
          closed(p.networkSecurityGroup.properties, ['securityRules']);
          equal(p.networkSecurityGroup.properties.securityRules, [], 'PRIVATE_LINK_NSG_APPS_ATTACHMENT_BODY_CHANGED');
        }
      }
    }
    if (change.response.properties.resourceGuid !== original.preflight.before.resources[target.vnet].properties.resourceGuid) {
      fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_BODY_CHANGED');
    }
    appsAttachment = { correlationId: matches[0].correlationId, startedAt: change.startedAt,
      acceptedAt: change.acceptedAt, succeededAt: matches[0].eventTimestamp,
      requestSha256: hash(change.request), acceptedResponseSha256: hash(change.response) };
  }
  return { actor: structuredClone(actor), nsgGeneration: observed.nsg.properties.resourceGuid,
    ...(attached ? { appsNsgGeneration: observed.appsNsg.properties.resourceGuid, appsNsgWriteCorrelation: appsWrites[0].correlationId }
      : { unattachedNsgGeneration: observed.unattachedNsg.properties.resourceGuid, unattachedNsgWriteCorrelation: appsWrites[0].correlationId }),
    nsgWriteCorrelation: nsgWrites[0].correlationId, associationCorrelation: last.correlationId,
    vnetWriteHistory: writes.map(value => ({ correlationId: value.success.correlationId, startedAt: value.startedAt,
      acceptedAt: value.acceptedAt, succeededAt: value.success.eventTimestamp,
      requestSha256: hash(value.request), acceptedResponseSha256: hash(value.response) })),
    nsgWrittenAt: nsgWrites[0].eventTimestamp, associatedAt: last.eventTimestamp,
    provenanceSha256: hash(provenance), assurance: assurance(attachmentMode),
    ...(attached ? { attachmentMode, appsAttachment } : {}) };
}
function verifyAnchor(c, context, evidence, original, proof = null) {
  if (proof) {
    const verified = anchorProofs.get(proof);
    if (!verified || verified.c !== c || verified.context !== context ||
        verified.evidence !== evidence || verified.original !== original) fail('PRIVATE_LINK_NSG_VALIDATION_INPUT_CHANGED');
    return;
  }
  if (evidence.version !== 1 || evidence.records.length !== 6 || evidence.records.at(-1).stage !== 'create-queue-endpoint' ||
      original.phase.stage !== 'create-environment' || original.phase.version !== 2 ||
      original.journal.version !== 3 || original.journal.outcome !== 'reconciliation-required' ||
      privateLinkSubmissionState(original) !== 'known-not-submitted') fail('PRIVATE_LINK_NSG_EXACT_PENDING_ENVIRONMENT_REQUIRED');
  verifyPrivateLinkOriginalNoSubmission(c, context, evidence, original);
}
function anchorEvidence(context, evidence) {
  if (!evidence) fail('PRIVATE_LINK_NSG_ACTUAL_ANCHOR_REQUIRED');
  closed(evidence, ['version', 'kind', 'planSha256', 'originSha256', 'records',
    ...(evidence.version === 2 ? ['externalAdoption'] : [])]);
  if (![1, 2].includes(evidence.version) || evidence.kind !== 'reviewed-private-link-control-chain' ||
      evidence.planSha256 !== context.plan.planSha256 || evidence.originSha256 !== hash(context.origin) ||
      !Array.isArray(evidence.records) || evidence.records.length < 6) fail('PRIVATE_LINK_NSG_ANCHOR_REQUIRED');
  return { version: 1, kind: evidence.kind, planSha256: evidence.planSha256, originSha256: evidence.originSha256,
    records: evidence.records.slice(0, 6) };
}
function anchorReference(context, evidence) {
  return { version: 1, kind: 'private-link-verified-original-prefix', records: 6,
    evidenceSha256: hash(evidence), head: privateLinkHead(context, evidence) };
}
function pending(original, context, evidence) {
  return { version: 1, kind: 'private-link-pending-head', targetKey: privateLinkHead(context, evidence).targetKey,
    previous: original.phase.expectedHead, intentSha256: hash(original.intent) };
}
export function privateLinkNsgAdoptionPins(c, context, proposal) {
  const attachmentMode = mode(proposal);
  return { configSha256: hash(c), planSha256: context.plan.planSha256, originSha256: hash(context.origin),
    anchorEvidenceSha256: proposal.anchor.evidenceSha256, originalSha256: hash(proposal.original),
    pendingHeadSha256: hash(proposal.pendingHead), currentStateSha256: hash(proposal.current),
    nsgSha256: hash(nsgState(proposal.current.externalNsg.nsg)),
    [proposal.version === 3 ? 'appsNsgSha256' : 'unattachedNsgSha256']: hash(nsgState(privateLinkNsgMembers(proposal.current.externalNsg).apps)),
    provenanceSha256: hash(proposal.provenance),
    actor: proposal.attribution.actor, nsgGeneration: proposal.attribution.nsgGeneration,
    targets: privateLinkNsgTargets(c, context, attachmentMode), assurance: assurance(attachmentMode),
    ...(proposal.version === 3 ? { attachmentMode, acaCompatibility: verifyPrivateLinkNsgAcaCompatibility(c, context, proposal.current) } : {}) };
}
export function verifyPrivateLinkNsgProposal(c, context, proposal, at, evidence) {
  const anchor = anchorEvidence(context, evidence);
  return withPrivateLinkControlValidation(c, context, () => verifyProposal(c, context, proposal, at, anchor, null));
}
function verifyProposal(c, context, proposal, at, anchor, anchorProof) {
  closed(proposal, ['version', 'kind', 'sourceSha256', 'anchor', 'original', 'pendingHead', 'current',
    'provenance', 'attribution', 'costReview', 'costEvidence', 'migrationReview', 'policyRevision', ...modeFields(proposal)]);
  if (proposal.kind !== 'private-link-governance-nsg-adoption-proposal') fail('PRIVATE_LINK_NSG_PROPOSAL_REQUIRED');
  if (mode(proposal) !== mode(proposal.current.externalNsg) || mode(proposal) !== mode(proposal.provenance)) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_CHANGED');
  verifyAnchor(c, context, anchor, proposal.original, anchorProof);
  equal(proposal.anchor, anchorReference(context, anchor), 'PRIVATE_LINK_NSG_ANCHOR_CHANGED');
  equal(proposal.pendingHead, pending(proposal.original, context, anchor), 'PRIVATE_LINK_NSG_PENDING_HEAD_CHANGED');
  const source = verifyPrivateLinkPolicyRevision(c, context, proposal.policyRevision, at);
  if (source !== proposal.sourceSha256) fail('PRIVATE_LINK_NSG_SOURCE_CHANGED');
  verifyPrivateLinkCostReview(c, context, proposal.costReview, proposal.costEvidence, source, at);
  verifyPrivateLinkMigrationReview(c, context, proposal.migrationReview, at, source);
  fresh(proposal.current, at); fresh(proposal.current.externalNsg, at);
  const added = proposal.current.lists.groupResources.value.filter(value => !proposal.original.preflight.before.lists.groupResources.value
    .some(before => sameId(value.id, before.id)));
  const targetIds = Object.values(privateLinkNsgTargets(c, context)).map(value => value.id.toLowerCase()).sort();
  equal(added.map(value => value.id.toLowerCase()).sort(), targetIds, 'PRIVATE_LINK_NSG_UNREVIEWED_ADDED_RESOURCE');
  const baseline = verifyPrivateLinkNsgDelta(c, context, proposal.current, proposal.original.preflight.before);
  verifyPrivateLinkSnapshot(c, context, baseline, 'create-queue-endpoint');
  equal(proposal.attribution, verifyPrivateLinkNsgProvenance(c, context, proposal.provenance,
    proposal.current.externalNsg, proposal.original), 'PRIVATE_LINK_NSG_ATTRIBUTION_CHANGED');
  return proposal;
}
export function verifyPrivateLinkNsgAdoption(c, context, record, evidence) {
  const anchor = anchorEvidence(context, evidence);
  return withPrivateLinkControlValidation(c, context, () => verifyAdoption(c, context, record, anchor, null));
}
function verifyAdoption(c, context, record, anchor, anchorProof) {
  closed(record, ['version', 'kind', 'proposal', 'review', 'publication', 'verifiedCurrent', 'adoptedAt', 'authority', ...modeFields(record)]);
  const { proposal, review, publication } = record, at = canonicalInstant(record.adoptedAt);
  const attachmentMode = mode(record);
  if (record.kind !== 'reviewed-private-link-governance-nsg-adoption') fail('PRIVATE_LINK_NSG_ADOPTION_REQUIRED');
  if (mode(proposal) !== attachmentMode || mode(review) !== attachmentMode) fail('PRIVATE_LINK_NSG_ATTACHMENT_MODE_CHANGED');
  closed(publication, ['commitSha', 'sourceSha256']);
  if (!/^[0-9a-f]{40}$/u.test(publication.commitSha ?? '') || publication.sourceSha256 !== proposal.sourceSha256) fail('PRIVATE_LINK_NSG_PUBLICATION_CHANGED');
  verifyProposal(c, context, proposal, at, anchor, anchorProof);
  closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'pins', 'userDecision',
    'userDecisionSha256', 'costDisclosure', 'approvedAt', 'expiresAt', ...modeFields(review)]);
  reviewTime(review, at);
  if (review.action !== (record.version === 2 ? 'preserve-two-exact-private-link-governance-nsgs-readonly'
    : 'preserve-both-exact-private-link-nsg-attachments-readonly') ||
      review.proposalSha256 !== hash(proposal) || review.sourceSha256 !== publication.sourceSha256 ||
      typeof review.userDecision !== 'string' || !review.userDecision.trim() ||
      review.userDecisionSha256 !== digest(review.userDecision)) fail('PRIVATE_LINK_NSG_EXPLICIT_REVIEW_REQUIRED');
  equal(review.pins, privateLinkNsgAdoptionPins(c, context, proposal), 'PRIVATE_LINK_NSG_REVIEW_PINS_CHANGED');
  closed(review.costDisclosure, ['currency', 'additionalFeeVerified', 'zeroFeeProven', 'unknownCostAccepted', 'budgetMutationAuthorized',
    'evidence', 'evidenceSha256']);
  const cost = review.costDisclosure;
  if (cost.currency !== 'USD' || cost.additionalFeeVerified !== false || cost.zeroFeeProven !== false ||
      cost.unknownCostAccepted !== true || cost.budgetMutationAuthorized !== false ||
      typeof cost.evidence !== 'string' || !cost.evidence.trim() || cost.evidenceSha256 !== digest(cost.evidence)) fail('PRIVATE_LINK_NSG_COST_DISCLOSURE_REQUIRED');
  fresh(record.verifiedCurrent, at); fresh(record.verifiedCurrent.externalNsg, at);
  if (record.verifiedCurrent.startedAt < canonicalInstant(review.approvedAt)) fail('PRIVATE_LINK_NSG_FRESH_READ_REQUIRED');
  verifyPrivateLinkNsgDelta(c, context, record.verifiedCurrent, proposal.original.preflight.before);
  verifyPrivateLinkNsgCurrent(c, context, record.verifiedCurrent.externalNsg, proposal.current.externalNsg);
  equal(compareState(record.verifiedCurrent), compareState(proposal.current), 'PRIVATE_LINK_NSG_ADOPTION_STATE_CHANGED');
  equal(record.authority, adoptionAuthority(attachmentMode), 'PRIVATE_LINK_NSG_AUTHORITY_CHANGED');
  return record;
}
export function withPrivateLinkNsgAdoption(c, context, evidence, adoption) {
  verifyPrivateLinkNsgAdoption(c, context, adoption, evidence);
  equal(evidence, anchorEvidence(context, evidence), 'PRIVATE_LINK_NSG_ANCHOR_CHANGED');
  return { ...evidence, version: 2, externalAdoption: adoption };
}
export function verifyPrivateLinkNsgEvidenceBinding(c, context, evidence) {
  if (evidence.version === 1) {
    if (evidence.externalAdoption !== undefined) fail('PRIVATE_LINK_NSG_VERSION_REQUIRED');
    return null;
  }
  if (evidence.version !== 2) fail('PRIVATE_LINK_NSG_VERSION_REQUIRED');
  return verifyPrivateLinkNsgAdoption(c, context, evidence.externalAdoption, evidence);
}
export function privateLinkNsgOriginalBaseline(c, context, adoption, current, original) {
  adoption = privateLinkNsgValidatedRecord(c, context, adoption);
  equal(original, adoption.proposal.original, 'PRIVATE_LINK_NSG_ORIGINAL_PENDING_CHANGED');
  verifyPrivateLinkNsgCurrent(c, context, current.externalNsg, adoption.proposal.current.externalNsg);
  return verifyPrivateLinkNsgDelta(c, context, current, original.preflight.before);
}
export async function observePrivateLinkNsgAdoption(c, context, evidence, original, provenance, io) {
  const deadline = Math.min(io.adoptionDeadline ?? Infinity, io.now() + LIMITS.checkMs);
  const anchor = anchorEvidence(context, evidence);
  return withAnchor(c, context, anchor, original, async anchorProof => {
  const source = await io.sourceDigest(), head = pending(original, context, anchor);
  await io.verifyOriginal(original); await io.verifySources(deadline); await io.head(evidence, head);
  const version = modeVersion(mode(provenance));
  const current = await collectPrivateLinkSnapshot(c, context, io, deadline, null, { observeOnly: true, ...version });
  const proposal = { ...version, kind: 'private-link-governance-nsg-adoption-proposal', sourceSha256: source,
    anchor: anchorReference(context, anchor), original, pendingHead: head, current, provenance,
    attribution: verifyPrivateLinkNsgProvenance(c, context, provenance, current.externalNsg, original),
    costReview: io.costReview, costEvidence: io.costEvidence, migrationReview: io.migrationReview,
    policyRevision: io.policyRevision ?? original.phase.policyRevision ?? null };
  verifyProposal(c, context, proposal, io.now(), anchor, anchorProof);
  await io.head(evidence, head);
  if (await io.sourceDigest() !== source || io.now() >= deadline) fail('PRIVATE_LINK_NSG_COLLECTION_EXPIRED');
  await io.retain('nsg-adoption-proposal', proposal);
  return proposal;
  });
}
export async function adoptPrivateLinkNsg(c, context, evidence, proposal, review, publication, io) {
  const deadline = Math.min(io.adoptionDeadline ?? Infinity, io.now() + LIMITS.checkMs);
  const anchor = anchorEvidence(context, evidence);
  return withAnchor(c, context, anchor, proposal.original, async anchorProof => {
  verifyProposal(c, context, proposal, io.now(), anchor, anchorProof);
  await io.verifyOriginal(proposal.original); await io.verifySources(deadline); await io.head(evidence, proposal.pendingHead);
  const version = modeVersion(mode(proposal));
  const current = await collectPrivateLinkSnapshot(c, context, io, deadline, null, { observeOnly: true, ...version });
  const record = { ...version, kind: 'reviewed-private-link-governance-nsg-adoption', proposal, review,
    publication, verifiedCurrent: current, adoptedAt: new Date(io.now()).toISOString(), authority: adoptionAuthority(mode(proposal)) };
  verifyAdoption(c, context, record, anchor, anchorProof);
  if (await io.sourceDigest() !== publication.sourceSha256 || io.now() >= deadline) fail('PRIVATE_LINK_NSG_COLLECTION_EXPIRED');
  await io.head(evidence, proposal.pendingHead);
  await useValidatedRecord(c, context, record, anchor, validation => io.saveAdoption(record, validation));
  return record;
  });
}
