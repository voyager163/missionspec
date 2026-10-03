import { isDeepStrictEqual } from 'node:util';
import { readFileSync } from 'node:fs';
import { budgetConfiguration, budgetProperties, buildPhase, closed, digestJson, fail, ids, json, ownerTags, projectBudgetFilter, sameId } from './definition.mjs';
import { verifyAdoptedQueueStorage, queueArmInstant } from './queue-adoption.mjs';
import { queueDefenderReadRequests, verifyCurrentQueueDefender } from './queue-defender.mjs';
import { admissionFlag, canonicalAppWrite, executionIdentity, resourceContext, verifyResource } from './policy.mjs';
import { verifyQueueResource } from './durable-queue.mjs';
import { PRIVATE_LINK_API as API, PRIVATE_LINK_LIMITS as LIMITS, privateLinkAtLeast as atLeast,
  privateLinkAddresses, privateLinkBudgetConfiguration, privateLinkIpInSubnet, privateLinkResources,
  verifyPrivateLinkControlContext, privateLinkRuntimeResources, verifyPrivateLinkNameProjection } from './private-link.mjs';
import { collectPrivateLinkNsgCurrent, privateLinkNsgTarget, privateLinkNsgTargets, privateLinkNsgValidatedRecord,
  verifyPrivateLinkNsgCurrent, privateLinkNsgAttachmentMode, PRIVATE_LINK_NSG_ATTACHED_MODE,
  verifyPrivateLinkNsgAcaCompatibility } from './private-link-nsg-adoption.mjs';

export const privateLinkHash = digestJson;
const hash = privateLinkHash;
const telemetryColumns = JSON.parse(readFileSync(new URL('../../../services/telemetry-ingest/schema/storage-columns.json', import.meta.url), 'utf8'));
export const plEqual = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
export function plOnly(value, fields, code = 'PRIVATE_LINK_UNREVIEWED_SHAPE') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !fields.includes(key))) fail(code);
}
export function plList(value, emptyTerminal = false) {
  plOnly(value, ['value', 'nextLink'], 'PRIVATE_LINK_LIST_INCOMPLETE');
  if (!Array.isArray(value.value) || value.value.length > LIMITS.items ||
      (value.nextLink !== undefined && value.nextLink !== null && !(emptyTerminal && value.nextLink === ''))) fail('PRIVATE_LINK_LIST_INCOMPLETE');
  return value.value;
}
function exactIds(response, wanted, emptyTerminal = false) {
  const values = plList(response, emptyTerminal), actual = values.map(value => value?.id?.toLowerCase());
  if (actual.some(value => !value) || new Set(actual).size !== actual.length) fail('PRIVATE_LINK_DUPLICATE_INVENTORY');
  plEqual(actual.sort(), wanted.map(value => value.toLowerCase()).sort(), 'PRIVATE_LINK_INVENTORY_DRIFT');
  return values;
}
function acaId(id) {
  return typeof id === 'string' && /^\/subscriptions\/[0-9a-f-]{36}\/resourceGroups\/missionspec-[a-z0-9]{2,10}-telemetry\/providers\/Microsoft\.App\/(?:containerApps\/missionspec-[a-z0-9]{2,10}-(?:ingest|private-ingest|public-probe|pl-ingest|pub-probe)|managedEnvironments\/missionspec-[a-z0-9]{2,10}-(?:environment|private-environment))$/iu.test(id);
}
function opaqueAcaDate(value) {
  if (typeof value !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?$/u.exec(value);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  const days = [31, year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year > 0 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] && hour < 24 && minute < 60 && second < 60;
}
function metadataInstant(value) {
  // ACR returns explicit +00:00 UTC. Keep the original record bytes; only the
  // arithmetic parser receives the equivalent Z suffix, never an inferred zone.
  return queueArmInstant(typeof value === 'string' && value.endsWith('+00:00') ? value.slice(0, -6) + 'Z' : value);
}
export function privateLinkAcaCreationIdentity(resource, expectedId) {
  if (!acaId(expectedId) || !sameId(resource?.id, expectedId) ||
      !sameId(resource.type, expectedId.toLowerCase().includes('/managedenvironments/')
        ? 'Microsoft.App/managedEnvironments' : 'Microsoft.App/containerApps') ||
      !resource.systemData || typeof resource.systemData.createdAt !== 'string') fail('PRIVATE_LINK_ACA_CREATION_IDENTITY_REQUIRED');
  const data = resource.systemData;
  plOnly(data, ['createdAt', 'createdBy', 'createdByType', 'lastModifiedAt', 'lastModifiedBy', 'lastModifiedByType']);
  const opaque = opaqueAcaDate(data.createdAt);
  const ticks = opaque ? null : metadataInstant(data.createdAt).toString();
  if (data.lastModifiedAt !== undefined && !opaqueAcaDate(data.lastModifiedAt)) metadataInstant(data.lastModifiedAt);
  for (const key of ['createdBy', 'lastModifiedBy']) if (data[key] !== undefined && (typeof data[key] !== 'string' || !data[key])) fail('PRIVATE_LINK_METADATA_INVALID');
  for (const key of ['createdByType', 'lastModifiedByType']) if (data[key] !== undefined &&
      !['User', 'Application', 'ManagedIdentity', 'Key'].includes(data[key])) fail('PRIVATE_LINK_METADATA_INVALID');
  return { id: resource.id.toLowerCase(), type: resource.type.toLowerCase(), createdAt: data.createdAt,
    createdAtKind: opaque ? 'opaque-aca' : 'utc-arm', createdAtTicks: ticks,
    createdBy: data.createdBy ?? null, createdByType: data.createdByType ?? null };
}
export function privateLinkGeneration(resource) {
  if (!resource) return null;
  const scopedAca = acaId(resource.id) &&
    ['Microsoft.App/containerApps', 'Microsoft.App/managedEnvironments'].some(type => sameId(type, resource.type));
  if (scopedAca && resource.systemData?.createdAt !== undefined) privateLinkAcaCreationIdentity(resource, resource.id);
  const time = value => scopedAca && opaqueAcaDate(value)
    ? `opaque-recorded-aca:${value}` : metadataInstant(value).toString();
  const data = resource.systemData;
  if (data !== undefined && data !== null) {
    plOnly(data, ['createdAt', 'createdBy', 'createdByType', 'lastModifiedAt', 'lastModifiedBy', 'lastModifiedByType']);
    for (const key of ['createdAt', 'lastModifiedAt']) if (data[key] !== undefined) time(data[key]);
    for (const key of ['createdBy', 'lastModifiedBy']) if (data[key] !== undefined && typeof data[key] !== 'string') fail('PRIVATE_LINK_METADATA_INVALID');
    for (const key of ['createdByType', 'lastModifiedByType']) if (data[key] !== undefined &&
      !['User', 'Application', 'ManagedIdentity', 'Key'].includes(data[key])) fail('PRIVATE_LINK_METADATA_INVALID');
  }
  const created = data?.createdAt ?? resource.properties?.creationTime ?? resource.properties?.createdOn ?? null;
  return { id: resource.id.toLowerCase(), type: resource.type?.toLowerCase() ?? null,
    createdAt: created === null ? null : time(created),
    createdBy: data?.createdBy ?? null, createdByType: data?.createdByType ?? null,
    resourceGuid: resource.properties?.resourceGuid ?? resource.properties?.perimeterGuid ?? resource.properties?.internalId ?? null };
}
export function privateLinkResourceState(value) {
  if (value === null) return null;
  const copy = structuredClone(value);
  if (typeof copy?.id !== 'string') fail('PRIVATE_LINK_RESOURCE_ID_REQUIRED');
  copy.id = copy.id.toLowerCase();
  if (Object.hasOwn(copy, 'etag')) { if (typeof copy.etag !== 'string') fail('PRIVATE_LINK_ETAG_INVALID'); delete copy.etag; }
  if (copy.systemData) {
    privateLinkGeneration(copy);
    for (const key of ['lastModifiedAt', 'lastModifiedBy', 'lastModifiedByType']) delete copy.systemData[key];
  }
  if (sameId(copy.type, 'Microsoft.Storage/storageAccounts/queueServices/queues') &&
      Object.hasOwn(copy.properties ?? {}, 'approximateMessageCount')) {
    if (!Number.isSafeInteger(copy.properties.approximateMessageCount) || copy.properties.approximateMessageCount < 0) fail('PRIVATE_LINK_QUEUE_COUNT_INVALID');
    delete copy.properties.approximateMessageCount;
  }
  return copy;
}
function resource(value, id, type, api, properties, extras = []) {
  plOnly(value, ['id', 'name', 'type', 'apiVersion', 'location', 'tags', 'etag', 'systemData', 'properties', ...extras]);
  if (!sameId(value.id, id) || !sameId(value.type, type) || (Object.hasOwn(value, 'apiVersion') && value.apiVersion !== api) ||
      ![id.split('/').at(-1), id.split(/\/providers\//iu).at(-1).split('/').filter((_, i) => i > 0 && i % 2 === 0).join('/')].includes(value.name)) fail('PRIVATE_LINK_RESOURCE_DRIFT');
  plOnly(value.properties, properties);
  privateLinkGeneration(value);
  return value.properties;
}
function owned(c, value, descriptor) {
  if (!sameId(value.id, descriptor.id) || !sameId(value.type, descriptor.type)) fail('PRIVATE_LINK_OWNERSHIP_DRIFT');
  if (descriptor.expected.tags) plEqual(value.tags, ownerTags(c), 'PRIVATE_LINK_TAGS_CHANGED');
  if (descriptor.expected.location && !sameId(value.location?.replaceAll(' ', ''), descriptor.expected.location)) fail('PRIVATE_LINK_LOCATION_CHANGED');
}
function ref(value, id, extra = []) {
  plOnly(value, ['id', ...extra]);
  if (!sameId(value.id, id)) fail('PRIVATE_LINK_REFERENCE_DRIFT');
}
function succeeded(p) { if (p.provisioningState !== 'Succeeded') fail('PRIVATE_LINK_PROPAGATION_PENDING'); }
function verifyNetwork(c, context, s, externalAdoption) {
  const attachedApps = externalAdoption && privateLinkNsgAttachmentMode(externalAdoption) === PRIVATE_LINK_NSG_ATTACHED_MODE;
  const appsNsg = attachedApps ? privateLinkNsgTargets(c, context, PRIVATE_LINK_NSG_ATTACHED_MODE).apps : null;
  const { topology } = context.plan, n = topology.ids, d = privateLinkResources(c, topology, context.origin), r = s.resources;
  owned(c, r[n.vnet], d.vnet);
  const p = resource(r[n.vnet], n.vnet, d.vnet.type, API.network, [
    'addressSpace', 'subnets', 'virtualNetworkPeerings', 'dhcpOptions', 'provisioningState', 'resourceGuid',
    'enableDdosProtection', 'enableVmProtection', 'privateEndpointVNetPolicies',
  ]);
  succeeded(p); plEqual(p.addressSpace, { addressPrefixes: [topology.addresses.vnet] }, 'PRIVATE_LINK_ADDRESS_DRIFT');
  if (p.enableDdosProtection === true || p.enableVmProtection === true ||
      (p.privateEndpointVNetPolicies !== undefined && p.privateEndpointVNetPolicies !== 'Disabled')) fail('PRIVATE_LINK_NETWORK_FEATURE_DRIFT');
  if (p.dhcpOptions !== undefined) plEqual(p.dhcpOptions, { dnsServers: [] }, 'PRIVATE_LINK_CUSTOM_DNS_FORBIDDEN');
  exactIds({ value: p.subnets }, [n.appsSubnet, n.endpointSubnet]);
  plEqual(p.virtualNetworkPeerings, [], 'PRIVATE_LINK_PEERING_FORBIDDEN');
  exactIds(s.lists.subnets, [n.appsSubnet, n.endpointSubnet]); exactIds(s.lists.peerings, []);
  for (const [id, address, isApps] of [[n.appsSubnet, topology.addresses.apps, true], [n.endpointSubnet, topology.addresses.endpoint, false]]) {
    const a = resource(r[id], id, 'Microsoft.Network/virtualNetworks/subnets', API.network,
      ['addressPrefix', 'delegations', 'privateEndpointNetworkPolicies', 'privateLinkServiceNetworkPolicies',
        'provisioningState', 'ipConfigurations', 'privateEndpoints', 'serviceAssociationLinks', 'resourceNavigationLinks',
        'serviceEndpoints', 'serviceEndpointPolicies', 'networkSecurityGroup', 'routeTable', 'natGateway', 'defaultOutboundAccess', 'purpose']);
    succeeded(a);
    if (a.addressPrefix !== address || (a.networkSecurityGroup && (!externalAdoption || (isApps && !attachedApps))) || a.routeTable || a.natGateway ||
        (a.defaultOutboundAccess !== undefined && typeof a.defaultOutboundAccess !== 'boolean')) fail('PRIVATE_LINK_SUBNET_DRIFT');
    if (externalAdoption && (!isApps || attachedApps)) {
      closed(a.networkSecurityGroup, ['id']);
      if (!sameId(a.networkSecurityGroup.id, isApps ? appsNsg.id : privateLinkNsgTarget(c, context).id)) fail('PRIVATE_LINK_NSG_ATTACHMENT_CHANGED');
      const copies = [p.subnets.find(value => sameId(value.id, id)), s.lists.subnets.value.find(value => sameId(value.id, id)),
        s.lists.addressSpaces.value.find(value => sameId(value.id, n.vnet))?.properties?.subnets?.find(value => sameId(value.id, id))];
      for (const copy of copies) {
        if (!sameId(copy?.properties?.networkSecurityGroup?.id, a.networkSecurityGroup.id)) fail('PRIVATE_LINK_NSG_ATTACHMENT_COPY_CHANGED');
        closed(copy.properties.networkSecurityGroup, ['id']);
      }
    }
    if (externalAdoption && isApps && !attachedApps) {
      const copies = [p.subnets.find(value => sameId(value.id, id)), s.lists.subnets.value.find(value => sameId(value.id, id)),
        s.lists.addressSpaces.value.find(value => sameId(value.id, n.vnet))?.properties?.subnets?.find(value => sameId(value.id, id))];
      if (copies.some(copy => !copy || copy.properties?.networkSecurityGroup)) fail('PRIVATE_LINK_NSG_APPS_ATTACHMENT_FORBIDDEN');
    }
    for (const key of ['serviceEndpoints', 'serviceEndpointPolicies']) if (a[key] !== undefined) plEqual(a[key], [], 'PRIVATE_LINK_SUBNET_FEATURE_DRIFT');
    if (a.purpose !== undefined && (isApps || r[n.endpoint] === null || a.purpose !== 'PrivateEndpoints')) {
      fail('PRIVATE_LINK_SUBNET_PURPOSE_UNVERIFIED');
    }
    if (isApps) {
      if (!Array.isArray(a.delegations) || a.delegations.length !== 1) fail('PRIVATE_LINK_ACA_DELEGATION_REQUIRED');
      const delegation = a.delegations[0];
      plOnly(delegation, ['id', 'name', 'etag', 'type', 'properties']);
      if (delegation.name !== 'container-apps' || (delegation.id && !sameId(delegation.id, `${id}/delegations/container-apps`))) fail('PRIVATE_LINK_ACA_DELEGATION_REQUIRED');
      plOnly(delegation.properties, ['serviceName', 'actions', 'provisioningState']);
      if (delegation.properties.serviceName !== 'Microsoft.App/environments' ||
          (delegation.properties.provisioningState !== undefined && delegation.properties.provisioningState !== 'Succeeded')) fail('PRIVATE_LINK_ACA_DELEGATION_REQUIRED');
      if (delegation.properties.actions !== undefined) plEqual(delegation.properties.actions,
        ['Microsoft.Network/virtualNetworks/subnets/join/action'], 'PRIVATE_LINK_DELEGATION_ACTIONS_DRIFT');
    } else {
      if (a.privateEndpointNetworkPolicies !== 'Disabled') fail('PRIVATE_LINK_ENDPOINT_POLICIES_DRIFT');
      if (a.delegations !== undefined) plEqual(a.delegations, [], 'PRIVATE_LINK_ENDPOINT_DELEGATION_FORBIDDEN');
    }
    if (a.privateEndpoints !== undefined) {
      if (!Array.isArray(a.privateEndpoints)) fail('PRIVATE_LINK_SUBNET_ENDPOINTS_UNVERIFIED');
      exactIds({ value: a.privateEndpoints }, !isApps && r[n.endpoint] !== null ? [n.endpoint] : []);
    }
    if (a.ipConfigurations !== undefined) {
      if (!Array.isArray(a.ipConfigurations)) fail('PRIVATE_LINK_SUBNET_IPS_UNVERIFIED');
      for (const configuration of a.ipConfigurations) {
        plOnly(configuration, ['id']);
        const id = configuration.id, prefix = isApps ? `${n.managedGroup}/providers/Microsoft.Network/networkInterfaces/`
          : `${s.nic?.id}/ipConfigurations/`;
        if (typeof id !== 'string' || !id.toLowerCase().startsWith(prefix.toLowerCase()) || /[%?#\\]|\.\./u.test(id)) fail('PRIVATE_LINK_FOREIGN_SUBNET_ATTACHMENT');
      }
    }
    for (const key of ['serviceAssociationLinks', 'resourceNavigationLinks']) {
      if (a[key] !== undefined) for (const link of a[key]) {
        plOnly(link, ['id', 'name', 'type', 'etag', 'properties']);
        if (key === 'serviceAssociationLinks' && link.name === 'legionservicelink') {
          const environment = r[n.environment];
          const expectedLink = `${ids(c).group}/virtualnetworks/${n.vnet.split('/').at(-1)}/subnets/apps`;
          plOnly(link.properties, ['linkedResourceType', 'link', 'allowDelete', 'enabledForArmDeployments',
            'locations', 'provisioningState', 'subnetId']);
          if (!isApps || a[key].length !== 1 || !sameId(link.id, `${n.appsSubnet}/serviceAssociationLinks/legionservicelink`) ||
              !sameId(link.type, 'Microsoft.Network/virtualNetworks/subnets/serviceAssociationLinks') ||
              !sameId(link.properties.linkedResourceType, 'Microsoft.App/environments') ||
              !sameId(link.properties.link, expectedLink) || link.properties.allowDelete !== false ||
              link.properties.enabledForArmDeployments !== false || link.properties.provisioningState !== 'Succeeded' ||
              !isDeepStrictEqual(link.properties.locations, []) ||
              !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(link.properties.subnetId ?? '') ||
              !sameId(environment?.id, n.environment) || environment.properties?.provisioningState !== 'Succeeded' ||
              !sameId(environment.properties.vnetConfiguration?.infrastructureSubnetId, n.appsSubnet)) {
            fail('PRIVATE_LINK_SUBNET_LINK_UNVERIFIED');
          }
          continue;
        }
        if (!isApps || !sameId(link.properties?.linkedResourceType, 'Microsoft.App/environments') ||
            (link.properties?.link && !sameId(link.properties.link, n.environment))) fail('PRIVATE_LINK_SUBNET_LINK_UNVERIFIED');
      }
    }
  }
}
export function verifyPrivateLinkEndpoint(c, context, s) {
  const t = context.plan.topology, n = t.ids, r = s.resources, d = privateLinkResources(c, t, context.origin);
  owned(c, r[n.endpoint], d.endpoint);
  const p = resource(r[n.endpoint], n.endpoint, d.endpoint.type, API.network, ['provisioningState', 'subnet',
    'privateLinkServiceConnections', 'manualPrivateLinkServiceConnections', 'networkInterfaces', 'customDnsConfigs',
    'ipConfigurations', 'customNetworkInterfaceName', 'resourceGuid', 'isIPv6EnabledPrivateEndpoint']);
  succeeded(p); ref(p.subnet, n.endpointSubnet);
  if (p.isIPv6EnabledPrivateEndpoint !== undefined && p.isIPv6EnabledPrivateEndpoint !== false) fail('PRIVATE_LINK_IPV6_UNREVIEWED');
  if (p.customNetworkInterfaceName !== undefined && p.customNetworkInterfaceName !== '') fail('PRIVATE_LINK_NIC_NAME_UNREVIEWED');
  if (p.customDnsConfigs !== undefined) plEqual(p.customDnsConfigs, [], 'PRIVATE_LINK_CUSTOM_DNS_FORBIDDEN');
  if (p.manualPrivateLinkServiceConnections !== undefined) plEqual(p.manualPrivateLinkServiceConnections, [], 'PRIVATE_LINK_MANUAL_CONNECTION_FORBIDDEN');
  if (p.ipConfigurations !== undefined) plEqual(p.ipConfigurations, [], 'PRIVATE_LINK_STATIC_IP_UNREVIEWED');
  if (!Array.isArray(p.privateLinkServiceConnections) || p.privateLinkServiceConnections.length !== 1) fail('PRIVATE_LINK_QUEUE_CONNECTION_REQUIRED');
  const connection = p.privateLinkServiceConnections[0];
  plOnly(connection, ['id', 'name', 'type', 'etag', 'properties']);
  if (connection.name !== 'queue') fail('PRIVATE_LINK_QUEUE_CONNECTION_REQUIRED');
  const cp = connection.properties;
  plOnly(cp, ['privateLinkServiceId', 'groupIds', 'requestMessage', 'provisioningState', 'privateLinkServiceConnectionState']);
  if (!sameId(cp.privateLinkServiceId, n.account)) fail('PRIVATE_LINK_STORAGE_TARGET_DRIFT');
  plEqual(cp.groupIds, ['queue'], 'PRIVATE_LINK_QUEUE_ONLY_REQUIRED');
  if (cp.provisioningState !== undefined) succeeded(cp);
  plOnly(cp.privateLinkServiceConnectionState, ['status', 'description', 'actionsRequired']);
  if (cp.privateLinkServiceConnectionState.status !== 'Approved' ||
      !['None', ''].includes(cp.privateLinkServiceConnectionState.actionsRequired ?? 'missing')) fail('PRIVATE_LINK_CONNECTION_NOT_APPROVED');
  if (!Array.isArray(p.networkInterfaces) || p.networkInterfaces.length !== 1 || !s.nic) fail('PRIVATE_LINK_NIC_REQUIRED');
  const nicId = p.networkInterfaces[0].id;
  if (!sameId(nicId, s.nic.id) || !sameId(nicId.slice(0, nicId.lastIndexOf('/')),
    `${ids(c).group}/providers/Microsoft.Network/networkInterfaces`)) fail('PRIVATE_LINK_NIC_SCOPE_DRIFT');
  const np = resource(s.nic, nicId, 'Microsoft.Network/networkInterfaces', API.network, ['provisioningState',
    'resourceGuid', 'ipConfigurations', 'privateEndpoint', 'dnsSettings', 'enableAcceleratedNetworking',
    'enableIPForwarding', 'disableTcpStateTracking', 'hostedWorkloads', 'nicType', 'macAddress', 'tapConfigurations',
    'allowPort25Out', 'auxiliaryMode', 'auxiliarySku', 'defaultOutboundConnectivityEnabled', 'vnetEncryptionSupported'],
  ['kind', 'managedBy']);
  succeeded(np); ref(np.privateEndpoint, n.endpoint);
  if (s.nic.kind !== undefined && s.nic.kind !== 'Regular' ||
      s.nic.managedBy !== undefined && !sameId(s.nic.managedBy, n.endpoint)) fail('PRIVATE_LINK_NIC_OWNER_DRIFT');
  for (const [key, value] of Object.entries({ allowPort25Out: true, auxiliaryMode: 'None', auxiliarySku: 'None',
    defaultOutboundConnectivityEnabled: false, vnetEncryptionSupported: false, disableTcpStateTracking: false,
    nicType: 'Standard', macAddress: '' })) {
    if (np[key] !== undefined && np[key] !== value) fail('PRIVATE_LINK_NIC_FEATURE_DRIFT');
  }
  for (const key of ['hostedWorkloads', 'tapConfigurations']) if (np[key] !== undefined) plEqual(np[key], [], 'PRIVATE_LINK_NIC_FEATURE_DRIFT');
  if (np.dnsSettings !== undefined) {
    plOnly(np.dnsSettings, ['dnsServers', 'appliedDnsServers', 'internalDomainNameSuffix']);
    for (const key of ['dnsServers', 'appliedDnsServers']) if (np.dnsSettings[key] !== undefined) {
      plEqual(np.dnsSettings[key], [], 'PRIVATE_LINK_CUSTOM_DNS_FORBIDDEN');
    }
    if (np.dnsSettings.internalDomainNameSuffix !== undefined &&
        !/^[a-z0-9]+(?:\.[a-z0-9]+)*\.internal\.cloudapp\.net$/u.test(np.dnsSettings.internalDomainNameSuffix)) fail('PRIVATE_LINK_NIC_DNS_SUFFIX_UNVERIFIED');
  }
  if (np.enableIPForwarding === true || np.enableAcceleratedNetworking === true ||
      !Array.isArray(np.ipConfigurations) || np.ipConfigurations.length !== 1) fail('PRIVATE_LINK_NIC_DRIFT');
  const ip = np.ipConfigurations[0];
  plOnly(ip, ['id', 'name', 'type', 'etag', 'properties']);
  plOnly(ip.properties, ['provisioningState', 'privateIPAddress', 'privateIPAllocationMethod', 'privateIPAddressVersion',
    'subnet', 'primary', 'privateLinkConnectionProperties']);
  succeeded(ip.properties); ref(ip.properties.subnet, n.endpointSubnet);
  if (!privateLinkIpInSubnet(ip.properties.privateIPAddress, t.addresses.endpoint) ||
      ip.properties.privateIPAddressVersion !== 'IPv4' || ip.properties.primary !== true ||
      !['Dynamic', 'Static'].includes(ip.properties.privateIPAllocationMethod)) fail('PRIVATE_LINK_IP_UNVERIFIED');
  const privateIp = ip.properties.privateIPAddress, queueHost = new URL(t.queueUrl).hostname;
  plOnly(ip.properties.privateLinkConnectionProperties, ['groupId', 'requiredMemberName', 'fqdns']);
  const ipc = ip.properties.privateLinkConnectionProperties;
  if (ipc.groupId !== 'queue' || ipc.requiredMemberName !== 'queue') fail('PRIVATE_LINK_QUEUE_ONLY_REQUIRED');
  plEqual(ipc.fqdns, [queueHost], 'PRIVATE_LINK_HOST_DRIFT');
  const connections = plList(s.lists.storageConnections);
  if (connections.length !== 1 || !sameId(connections[0].properties?.privateEndpoint?.id, n.endpoint) ||
      connections[0].properties?.privateLinkServiceConnectionState?.status !== 'Approved' ||
      connections[0].properties?.provisioningState !== 'Succeeded') fail('PRIVATE_LINK_STORAGE_CONNECTION_UNVERIFIED');
  const dns = resource(r[n.dnsZone], n.dnsZone, d.dnsZone.type, API.dns,
    ['provisioningState', 'maxNumberOfRecordSets', 'numberOfRecordSets', 'maxNumberOfVirtualNetworkLinks',
      'numberOfVirtualNetworkLinks', 'maxNumberOfVirtualNetworkLinksWithRegistration', 'numberOfVirtualNetworkLinksWithRegistration', 'internalId']);
  owned(c, r[n.dnsZone], d.dnsZone); succeeded(dns);
  if (dns.numberOfVirtualNetworkLinksWithRegistration !== 0) fail('PRIVATE_LINK_DNS_REGISTRATION_FORBIDDEN');
  const link = resource(r[n.dnsLink], n.dnsLink, d.dnsLink.type, API.dns, ['registrationEnabled', 'virtualNetwork',
    'provisioningState', 'virtualNetworkLinkState', 'resolutionPolicy']);
  owned(c, r[n.dnsLink], d.dnsLink); succeeded(link); ref(link.virtualNetwork, n.vnet);
  if (link.registrationEnabled !== false || link.virtualNetworkLinkState !== 'Completed' ||
      (link.resolutionPolicy !== undefined && link.resolutionPolicy !== 'Default')) fail('PRIVATE_LINK_DNS_LINK_UNVERIFIED');
  exactIds(s.lists.dnsLinks, [n.dnsLink]);
  const group = resource(r[n.dnsZoneGroup], n.dnsZoneGroup, d.dnsZoneGroup.type, API.network,
    ['provisioningState', 'privateDnsZoneConfigs']);
  succeeded(group);
  if (!Array.isArray(group.privateDnsZoneConfigs) || group.privateDnsZoneConfigs.length !== 1) fail('PRIVATE_LINK_DNS_ZONE_GROUP_DRIFT');
  const config = group.privateDnsZoneConfigs[0];
  plOnly(config, ['id', 'name', 'type', 'etag', 'properties']);
  if (config.id !== undefined && !sameId(config.id, `${n.dnsZoneGroup}/privateDnsZoneConfigs/queue`) ||
      config.type !== undefined && !sameId(config.type, 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups/privateDnsZoneConfigs') ||
      config.etag !== undefined && typeof config.etag !== 'string') fail('PRIVATE_LINK_DNS_ZONE_GROUP_DRIFT');
  plOnly(config.properties, ['privateDnsZoneId', 'recordSets', 'provisioningState']);
  if (config.properties.provisioningState !== undefined) succeeded(config.properties);
  if (config.name !== 'queue' || !sameId(config.properties.privateDnsZoneId, n.dnsZone)) fail('PRIVATE_LINK_DNS_ZONE_GROUP_DRIFT');
  if (config.properties.recordSets !== undefined) for (const value of config.properties.recordSets) {
    plOnly(value, ['recordType', 'recordSetName', 'fqdn', 'ipAddresses', 'ttl', 'provisioningState']);
    if (value.recordType !== 'A' || value.recordSetName !== context.origin.adoption.topology.ids.accountName ||
        value.fqdn !== `${context.origin.adoption.topology.ids.accountName}.privatelink.queue.core.windows.net` ||
        !isDeepStrictEqual(value.ipAddresses, [privateIp])) fail('PRIVATE_LINK_DNS_RECORD_DRIFT');
  }
  if (config.properties.recordSets !== undefined && config.properties.recordSets.length !== 1) fail('PRIVATE_LINK_DNS_ZONE_GROUP_DRIFT');
  const records = plList(s.lists.dnsRecords), name = context.origin.adoption.topology.ids.accountName;
  exactIds(s.lists.dnsRecords, [`${n.dnsZone}/A/${name}`, `${n.dnsZone}/SOA/@`]);
  const a = records.find(value => sameId(value.id, `${n.dnsZone}/A/${name}`));
  const ap = resource(a, `${n.dnsZone}/A/${name}`, 'Microsoft.Network/privateDnsZones/A', API.dns,
    ['ttl', 'aRecords', 'fqdn', 'isAutoRegistered', 'metadata']);
  if (!Number.isSafeInteger(ap.ttl) || ap.ttl <= 0 || ap.ttl > 3600 || ap.isAutoRegistered !== false ||
      ![`${name}.privatelink.queue.core.windows.net`, `${name}.privatelink.queue.core.windows.net.`].includes(ap.fqdn)) fail('PRIVATE_LINK_DNS_RECORD_DRIFT');
  plEqual(ap.aRecords, [{ ipv4Address: privateIp }], 'PRIVATE_LINK_DNS_ADDRESS_DRIFT');
  return { privateIp, queueHost };
}
export function verifyPrivateLinkEnvironmentNoLogs(value, version = 2) {
  if (version === 1) {
    // Preserve the original phase-1 readback interpretation for immutable history.
    if (value?.destination !== 'none' || value.logAnalyticsConfiguration) fail('PRIVATE_LINK_ENVIRONMENT_LOGGING_OR_DOMAIN_DRIFT');
    return;
  }
  if (version !== 2) fail('PRIVATE_LINK_WIRE_VERSION_UNSUPPORTED');
  plOnly(value, ['destination', 'logAnalyticsConfiguration'], 'PRIVATE_LINK_ENVIRONMENT_LOGGING_OR_DOMAIN_DRIFT');
  if (!Object.hasOwn(value, 'destination') || value.destination !== null ||
      (Object.hasOwn(value, 'logAnalyticsConfiguration') && value.logAnalyticsConfiguration !== null)) {
    fail('PRIVATE_LINK_ENVIRONMENT_LOGGING_OR_DOMAIN_DRIFT');
  }
}
function verifyEnvironment(c, context, s, environmentWireVersion) {
  const t = context.plan.topology, n = t.ids, d = privateLinkResources(c, t, context.origin);
  const value = s.resources[n.environment]; owned(c, value, d.environment);
  const p = resource(value, n.environment, d.environment.type, API.app, [
    'provisioningState', 'deploymentErrors', 'defaultDomain', 'staticIp', 'infrastructureResourceGroup',
    'publicNetworkAccess', 'workloadProfiles', 'zoneRedundant', 'vnetConfiguration', 'appLogsConfiguration',
    'daprAIInstrumentationKey', 'daprAIConnectionString', 'customDomainConfiguration', 'eventStreamEndpoint',
    'peerAuthentication', 'peerTrafficConfiguration', 'kedaConfiguration', 'daprConfiguration', 'infrastructureSubnetId',
    'appInsightsConfiguration', 'openTelemetryConfiguration', 'ingressConfiguration',
  ]);
  succeeded(p);
  if (p.deploymentErrors || p.publicNetworkAccess !== 'Enabled' || p.zoneRedundant !== false ||
      p.infrastructureResourceGroup !== n.managedGroup.split('/').at(-1) ||
      typeof p.defaultDomain !== 'string' || !/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(p.defaultDomain) ||
      typeof p.staticIp !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(p.staticIp)) fail('PRIVATE_LINK_ENVIRONMENT_UNVERIFIED');
  plOnly(p.vnetConfiguration, ['infrastructureSubnetId', 'internal', 'dockerBridgeCidr', 'platformReservedCidr', 'platformReservedDnsIP']);
  if (!sameId(p.vnetConfiguration.infrastructureSubnetId, n.appsSubnet) || p.vnetConfiguration.internal !== false ||
      p.vnetConfiguration.dockerBridgeCidr || p.vnetConfiguration.platformReservedCidr || p.vnetConfiguration.platformReservedDnsIP) fail('PRIVATE_LINK_ENVIRONMENT_NETWORK_DRIFT');
  if (!Array.isArray(p.workloadProfiles) || p.workloadProfiles.length !== 1) fail('PRIVATE_LINK_CONSUMPTION_REQUIRED');
  plOnly(p.workloadProfiles[0], ['name', 'workloadProfileType', 'minimumCount', 'maximumCount', 'enableFips']);
  if (p.workloadProfiles[0].name !== 'Consumption' || p.workloadProfiles[0].workloadProfileType !== 'Consumption' ||
      p.workloadProfiles[0].minimumCount != null || p.workloadProfiles[0].maximumCount != null ||
      p.workloadProfiles[0].enableFips !== undefined && p.workloadProfiles[0].enableFips !== false) fail('PRIVATE_LINK_CONSUMPTION_REQUIRED');
  verifyPrivateLinkEnvironmentNoLogs(p.appLogsConfiguration, environmentWireVersion);
  for (const key of ['appInsightsConfiguration', 'openTelemetryConfiguration', 'ingressConfiguration']) {
    if (p[key] !== undefined && p[key] !== null) fail('PRIVATE_LINK_ENVIRONMENT_LOGGING_OR_DOMAIN_DRIFT');
  }
  if (p.daprAIInstrumentationKey || p.daprAIConnectionString ||
      p.customDomainConfiguration?.dnsSuffix || p.customDomainConfiguration?.certificateValue ||
      p.customDomainConfiguration?.certificateKeyVaultProperties) fail('PRIVATE_LINK_ENVIRONMENT_LOGGING_OR_DOMAIN_DRIFT');
  const group = s.resources[n.managedGroup];
  if (!sameId(group?.id, n.managedGroup) || !sameId(group.managedBy, n.environment) ||
      !sameId(group.location?.replaceAll(' ', ''), c.location) ||
      group.properties?.provisioningState !== 'Succeeded') fail('PRIVATE_LINK_MANAGED_GROUP_UNVERIFIED');
  const inventory = plList(s.lists.managedResources);
  if (!inventory.length || inventory.some(item => !item.id?.toLowerCase().startsWith(n.managedGroup.toLowerCase() + '/') ||
      !['microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups',
        'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets'].includes(item.type?.toLowerCase()))) fail('PRIVATE_LINK_PLATFORM_INVENTORY_UNREVIEWED');
  closed(s.managed, inventory.map(value => value.id));
  const publicIps = inventory.filter(value => sameId(value.type, 'Microsoft.Network/publicIPAddresses'));
  const balancers = inventory.filter(value => sameId(value.type, 'Microsoft.Network/loadBalancers'));
  if (publicIps.length < 1 || publicIps.length > 2 || balancers.length !== 1) fail('PRIVATE_LINK_PLATFORM_COST_SCOPE_CHANGED');
  const addresses = new Set();
  for (const entry of inventory) {
    const value = s.managed[entry.id];
    if (!sameId(value?.id, entry.id) || !sameId(value.type, entry.type) ||
        value.properties?.provisioningState !== 'Succeeded' || !sameId(value.location?.replaceAll(' ', ''), c.location)) fail('PRIVATE_LINK_PLATFORM_READBACK_UNVERIFIED');
    privateLinkGeneration(value);
    if (sameId(value.type, 'Microsoft.Network/publicIPAddresses')) {
      const props = resource(value, value.id, value.type, API.network, [
        'provisioningState', 'resourceGuid', 'ipAddress', 'publicIPAllocationMethod', 'publicIPAddressVersion',
        'idleTimeoutInMinutes', 'ipConfiguration', 'ipTags', 'dnsSettings', 'ddosSettings', 'deleteOption'], ['sku', 'zones']);
      if (value.sku?.name !== 'Standard' || props.publicIPAllocationMethod !== 'Static' ||
          props.publicIPAddressVersion !== 'IPv4' || typeof props.ipAddress !== 'string' ||
          !/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(props.ipAddress) ||
          props.ipAddress.split('.').some(part => Number(part) > 255)) fail('PRIVATE_LINK_PLATFORM_PUBLIC_IP_DRIFT');
      if (props.ipTags !== undefined && !isDeepStrictEqual(props.ipTags, [])) {
        if (!isDeepStrictEqual(props.ipTags, [{ ipTagType: 'FirstPartyUsage', tag: '/Unprivileged' }]) ||
            !sameId(value.id, `${n.managedGroup}/providers/Microsoft.Network/publicIPAddresses/capp-svc-lb-ip`) ||
            !sameId(value.tags?.['aca-managed-env-id'], n.environment) || props.ipAddress !== p.staticIp ||
            !sameId(props.ipConfiguration?.id,
              `${n.managedGroup}/providers/Microsoft.Network/loadBalancers/capp-svc-lb/frontendIPConfigurations/capp-svc-lbfe`)) {
          fail('PRIVATE_LINK_PLATFORM_PUBLIC_IP_DRIFT');
        }
      }
      addresses.add(props.ipAddress);
    } else if (sameId(value.type, 'Microsoft.Network/loadBalancers')) {
      const props = resource(value, value.id, value.type, API.network, [
        'provisioningState', 'resourceGuid', 'frontendIPConfigurations', 'backendAddressPools',
        'loadBalancingRules', 'probes', 'inboundNatRules', 'inboundNatPools', 'outboundRules'], ['sku']);
      if (value.sku?.name !== 'Standard' || !Array.isArray(props.frontendIPConfigurations) || !props.frontendIPConfigurations.length ||
          !Array.isArray(props.backendAddressPools) || !Array.isArray(props.loadBalancingRules) || !Array.isArray(props.probes)) fail('PRIVATE_LINK_PLATFORM_LOAD_BALANCER_UNVERIFIED');
      for (const frontend of props.frontendIPConfigurations) {
        if (!publicIps.some(ip => sameId(frontend.properties?.publicIPAddress?.id, ip.id)) ||
            frontend.properties?.privateIPAddress) fail('PRIVATE_LINK_PLATFORM_FRONTEND_UNVERIFIED');
      }
    } else if (sameId(value.type, 'Microsoft.Compute/virtualMachineScaleSets')) {
      // Dedicated VMSS is outside the sole Consumption-profile reserve.
      fail('PRIVATE_LINK_PLATFORM_COMPUTE_COST_REVIEW_REQUIRED');
    }
  }
  if (!addresses.has(p.staticIp)) fail('PRIVATE_LINK_PLATFORM_INGRESS_IP_UNVERIFIED');
}
function verifyRuntimeApp(c, context, s, descriptor, flag) {
  const n = context.plan.topology.ids, actual = s.resources[descriptor.id], p = actual?.properties;
  if (s.images.queueManifest === null || !sameId(actual?.id, descriptor.id) || actual.name !== descriptor.expected.name ||
      !sameId(p?.managedEnvironmentId, descriptor.expected.properties.managedEnvironmentId) ||
      admissionFlag(actual) !== flag || p.template?.containers?.[0]?.image !== descriptor.expected.properties.template.containers[0].image) fail('PRIVATE_LINK_RUNTIME_APP_DRIFT');
  const domain = s.resources[descriptor.expected.properties.managedEnvironmentId]?.properties?.defaultDomain;
  if (typeof domain !== 'string' || p.configuration?.ingress?.fqdn !== `${descriptor.expected.name}.${domain}`) fail('PRIVATE_LINK_RUNTIME_FQDN_CHANGED');
  const projected = structuredClone(actual), expected = context.origin.receiver.phase.resources[0], r = ids(c);
  const entries = projected.properties.template.containers[0].env, q = context.origin.adoption.topology;
  for (const [name, value] of [['AZURE_QUEUE_URL', q.ids.queueUrl], ['AZURE_QUEUE_RESOURCE_ID', q.ids.queue]]) {
    const matches = entries.filter(entry => entry.name === name);
    if (matches.length !== 1 || matches[0].value !== value) fail('PRIVATE_LINK_RUNTIME_QUEUE_ENV_CHANGED');
  }
  projected.properties.template.containers[0].env = entries.filter(entry => !['AZURE_QUEUE_URL', 'AZURE_QUEUE_RESOURCE_ID'].includes(entry.name));
  projected.properties.template.containers[0].image = expected.expected.properties.template.containers[0].image;
  projected.properties.template.containers[0].env.find(entry => entry.name === 'MSR_INGESTION_ENABLED').value = 'false';
  projected.id = r.app; projected.name = expected.expected.name;
  projected.properties.managedEnvironmentId = r.environment;
  if (Object.hasOwn(projected.properties, 'environmentId')) projected.properties.environmentId = r.environment;
  canonicalAppWrite(c, expected, projected, { ...resourceContext(c, {
    ...context.origin.receiver.prerequisiteReceipts, receiverUpgrade: context.origin.receiver }),
    identities: { [n.ingestIdentity]: s.resources[n.ingestIdentity], [n.pullIdentity]: s.resources[n.pullIdentity] } });
}
export function privateLinkResourceDescriptors(c, context, nameProjection = null, evidence = null) {
  const n = context.plan.topology.ids, q = context.origin.adoption.topology.ids, r = ids(c), old = context.origin.network.topology.ids;
  const projected = privateLinkRuntimeResources(c, context, nameProjection, evidence);
  const d = projected.resources;
  const values = Object.values(d).filter(value => value?.id).map(value => ({ id: value.id, apiVersion: value.apiVersion }));
  values.push(...[q.account, q.service, q.queue].map(id => ({ id, apiVersion: API.storage })),
    ...[old.perimeter, old.profile, old.association, old.rule].map(id => ({ id, apiVersion: '2025-09-01' })),
    ...[r.ingestIdentity, r.pullIdentity].map(id => ({ id, apiVersion: '2023-01-31' })),
    { id: n.oldApp, apiVersion: API.app }, { id: n.oldEnvironment, apiVersion: API.app },
    { id: n.managedGroup, apiVersion: '2024-03-01' }, { id: r.registry, apiVersion: '2023-07-01' },
    { id: r.workspace, apiVersion: '2023-09-01' },
    { id: r.table, apiVersion: '2022-10-01' }, { id: r.dcr, apiVersion: '2024-03-11' },
    ...[r.projectBudget, r.budget, r.stateBudget].map(id => ({ id, apiVersion: '2024-08-01' })));
  values.push(...projected.legacyAbsentIds.map(id => ({ id, apiVersion: API.app })));
  return [...new Map(values.map(value => [value.id.toLowerCase(), value])).values()];
}
export function privateLinkReadRequests(c, context) {
  const n = context.plan.topology.ids, old = context.origin.network.topology.ids, r = ids(c);
  const req = (id, apiVersion, parent = null) => ({ id, apiVersion, filter: null, parent });
  return {
    addressSpaces: req(`${r.sub}/providers/Microsoft.Network/virtualNetworks`, API.network),
    groupResources: req(`${r.group}/resources`, '2021-04-01'),
    managedResources: req(`${n.managedGroup}/resources`, '2021-04-01', n.managedGroup),
    subnets: req(`${n.vnet}/subnets`, API.network, n.vnet),
    peerings: req(`${n.vnet}/virtualNetworkPeerings`, API.network, n.vnet),
    storageConnections: req(`${n.account}/privateEndpointConnections`, API.storage),
    effective: req(`${n.account}/networkSecurityPerimeterConfigurations`, API.storage),
    queues: req(`${context.origin.adoption.topology.ids.service}/queues`, API.storage),
    dnsLinks: req(`${n.dnsZone}/virtualNetworkLinks`, API.dns, n.dnsZone),
    dnsRecords: req(`${n.dnsZone}/recordsets`, API.dns, n.dnsZone),
    profiles: req(`${old.perimeter}/profiles`, '2025-09-01', old.perimeter),
    associations: req(`${old.perimeter}/resourceAssociations`, '2025-09-01', old.perimeter),
    rules: req(`${old.profile}/accessRules`, '2025-09-01', old.profile),
    links: req(`${old.perimeter}/links`, '2025-09-01', old.perimeter),
    linkReferences: req(`${old.perimeter}/linkReferences`, '2025-09-01', old.perimeter),
    apps: req(`${r.group}/providers/Microsoft.App/containerApps`, API.app),
    accountGrants: { ...req(`${n.account}/providers/Microsoft.Authorization/roleAssignments`, API.authorization), filter: '$filter=atScope()' },
    serviceGrants: { ...req(`${context.origin.adoption.topology.ids.service}/providers/Microsoft.Authorization/roleAssignments`, API.authorization), filter: '$filter=atScope()' },
    queueGrants: { ...req(`${n.queue}/providers/Microsoft.Authorization/roleAssignments`, API.authorization), filter: '$filter=atScope()' },
    workspaceExports: req(`${r.workspace}/dataExports`, '2020-08-01'),
  };
}
export async function collectPrivateLinkSnapshot(c, context, io, deadline, resourcesReady = null, externalAdoption = null) {
  verifyPrivateLinkControlContext(c, context);
  const start = io.now(), nameProjection = io.nameProjection ?? null, projectionEvidence = io.projectionEvidence ?? null;
  if (nameProjection && !projectionEvidence) fail('PRIVATE_LINK_NAME_PREFIX_REQUIRED');
  const view = privateLinkRuntimeResources(c, context, nameProjection, projectionEvidence, start), n = view.ids;
  if (!Number.isSafeInteger(deadline) || deadline <= start) fail('PRIVATE_LINK_READ_DEADLINE');
  deadline = Math.min(deadline, start + LIMITS.checkMs);
  const s = { version: 1, kind: 'private-link-control-snapshot', startedAt: start, completedAt: null,
    accountContext: null, resources: {}, lists: {}, diagnostics: {}, nic: null, effective: null, defender: null, images: null, managed: {},
    ...(nameProjection ? { nameProjection: structuredClone(nameProjection) } : {}) };
  const attachmentMode = externalAdoption?.observeOnly && externalAdoption.version === undefined ? undefined
    : externalAdoption ? privateLinkNsgAttachmentMode(externalAdoption) : undefined;
  const nsgTask = externalAdoption ? collectPrivateLinkNsgCurrent(c, context, io, deadline, attachmentMode).then(value => {
    s.version = 2; s.externalNsg = value;
  }) : Promise.resolve();
  const resources = new Map(privateLinkResourceDescriptors(c, context, nameProjection, projectionEvidence).map(d => [d.id, Promise.resolve().then(async () => {
    const value = await io.read({ ...d, filter: null }, deadline); s.resources[d.id] = value; return value;
  })]));
  const targets = [n.vnet, n.endpoint, n.dnsZone, n.environment, n.app, n.account,
    context.origin.adoption.topology.ids.service, n.oldApp, n.oldEnvironment, context.origin.network.topology.ids.perimeter,
    ids(c).workspace, ids(c).dcr, ...(n.publicProbe ? [n.publicProbe] : [])];
  const listTasks = Object.entries(privateLinkReadRequests(c, context)).map(async ([key, { parent, ...request }]) => {
    s.lists[key] = parent && await resources.get(parent) === null ? { value: [] } : await io.read(request, deadline, true);
  });
  const diagnosticTasks = targets.map(async id => {
    s.diagnostics[id] = await resources.get(id) === null ? { value: [] } : await io.read({
      id: `${id}/providers/Microsoft.Insights/diagnosticSettings`, apiVersion: '2021-05-01-preview', filter: null }, deadline, true);
  });
  const defenderTask = context.origin.adoption.version === 3 ? (async () => {
    const e = context.origin.adoption.proposal.defender;
    s.defender = Object.fromEntries(await io.batch(Object.entries(queueDefenderReadRequests(c, context.origin.adoption.origin, e)),
      async ([key, request]) => [key, await io.read(request, deadline)]));
    verifyCurrentQueueDefender(c, context.origin.adoption.origin, e, s.defender);
  })() : Promise.resolve();
  await Promise.all([Promise.all(resources.values()).then(async () => {
    if (externalAdoption) await nsgTask;
    return resourcesReady?.({ resources: structuredClone(s.resources),
      ...(externalAdoption ? { externalNsg: structuredClone(s.externalNsg) } : {}) });
  }), ...listTasks, ...diagnosticTasks, defenderTask, nsgTask,
    io.account(deadline).then(value => { s.accountContext = value; }),
    io.registry(deadline).then(value => { s.images = value; })]);
  await io.batch(plList(s.lists.managedResources), async item => {
    const prefix = `${n.managedGroup}/providers/`;
    if (typeof item?.id !== 'string' || !sameId(item.id.slice(0, prefix.length), prefix) ||
        /[%?#\\]|\.\./u.test(item.id) || !['Microsoft.Network/loadBalancers', 'Microsoft.Network/publicIPAddresses',
          'Microsoft.Network/networkSecurityGroups', 'Microsoft.Network/networkInterfaces', 'Microsoft.Compute/virtualMachineScaleSets']
          .some(type => sameId(item.type, type))) fail('PRIVATE_LINK_PLATFORM_INVENTORY_UNREVIEWED');
    s.managed[item.id] = await io.read({ id: item.id,
      apiVersion: item.type.startsWith('Microsoft.Compute/') ? '2024-11-01' : API.network, filter: null }, deadline);
  });
  const nics = s.resources[n.endpoint]?.properties?.networkInterfaces;
  if (nics !== undefined && (!Array.isArray(nics) || nics.length !== 1)) fail('PRIVATE_LINK_NIC_REQUIRED');
  if (nics?.length) {
    const id = nics[0]?.id, prefix = `${ids(c).group}/providers/Microsoft.Network/networkInterfaces/`;
    if (typeof id !== 'string' || !sameId(id.slice(0, prefix.length), prefix) || !/^[A-Za-z0-9_.-]+$/u.test(id.slice(prefix.length))) fail('PRIVATE_LINK_NIC_SCOPE_DRIFT');
    s.nic = await io.read({ id, apiVersion: API.network, filter: null }, deadline);
  }
  const configurations = plList(s.lists.effective);
  if (configurations.length > 1) fail('PRIVATE_LINK_EFFECTIVE_SCOPE_DRIFT');
  if (configurations.length) {
    const id = configurations[0]?.id, prefix = `${n.account}/networkSecurityPerimeterConfigurations/`;
    if (typeof id !== 'string' || !sameId(id.slice(0, prefix.length), prefix) || !/^[A-Za-z0-9_.-]+$/u.test(id.slice(prefix.length))) fail('PRIVATE_LINK_EFFECTIVE_SCOPE_DRIFT');
    s.effective = await io.read({ id, apiVersion: API.storage, filter: null }, deadline);
  }
  s.completedAt = io.now();
  if (s.completedAt >= deadline) fail('PRIVATE_LINK_READ_DEADLINE');
  if (Buffer.byteLength(json(s)) > LIMITS.bytes) fail('PRIVATE_LINK_SNAPSHOT_SIZE_LIMIT');
  s.resources = Object.fromEntries(privateLinkResourceDescriptors(c, context, nameProjection, projectionEvidence).map(d => [d.id, s.resources[d.id]]));
  s.lists = Object.fromEntries(Object.keys(privateLinkReadRequests(c, context)).map(key => [key, s.lists[key]]));
  s.diagnostics = Object.fromEntries(targets.map(id => [id, s.diagnostics[id]]));
  s.managed = Object.fromEntries(Object.entries(s.managed).sort(([a], [b]) => a.localeCompare(b)));
  return s;
}
export function verifyPrivateLinkSnapshot(c, context, s, stage = 'initial', environmentWireVersion = 2, externalAdoption = null, evidence = null) {
  verifyPrivateLinkControlContext(c, context);
  const nameProjection = s.nameProjection ?? null;
  if (nameProjection && (!evidence || !atLeast(stage, 'assign-queue-role'))) fail('PRIVATE_LINK_NAME_PREFIX_REQUIRED');
  const view = privateLinkRuntimeResources(c, context, nameProjection, evidence, s.startedAt);
  if (nameProjection) verifyPrivateLinkNameProjection(c, context, nameProjection, s.completedAt, evidence);
  closed(s, ['version', 'kind', 'startedAt', 'completedAt', 'accountContext', 'resources', 'lists', 'diagnostics', 'nic', 'effective', 'defender', 'images', 'managed',
    ...(externalAdoption ? ['externalNsg'] : []), ...(nameProjection ? ['nameProjection'] : [])]);
  if (s.version !== (externalAdoption ? 2 : 1) || s.kind !== 'private-link-control-snapshot' || !Number.isSafeInteger(s.startedAt) ||
      !Number.isSafeInteger(s.completedAt) || s.completedAt < s.startedAt || s.completedAt - s.startedAt > LIMITS.checkMs) fail('PRIVATE_LINK_SNAPSHOT_INVALID');
  if (externalAdoption) {
    externalAdoption = privateLinkNsgValidatedRecord(c, context, externalAdoption, evidence);
    verifyPrivateLinkNsgCurrent(c, context, s.externalNsg, externalAdoption.proposal.current.externalNsg);
    if (privateLinkNsgAttachmentMode(externalAdoption) === PRIVATE_LINK_NSG_ATTACHED_MODE) verifyPrivateLinkNsgAcaCompatibility(c, context, s);
    if (s.externalNsg.startedAt < s.startedAt || s.externalNsg.completedAt > s.completedAt) fail('PRIVATE_LINK_NSG_READBACK_WINDOW_CHANGED');
  }
  const a = s.accountContext;
  if (a?.id !== c.subscriptionId || a.tenantId !== c.tenantId || a.environmentName !== 'AzureCloud' || a.state !== 'Enabled') fail('PRIVATE_LINK_ACCOUNT_CONTEXT_CHANGED');
  const t = context.plan.topology, n = view.ids, old = context.origin.network.topology.ids, q = context.origin.adoption.topology.ids, r = ids(c);
  closed(s.images, ['repositories', 'manifests', 'legacyManifest', 'preparedManifest', 'queueManifest', 'referrers']);
  equalImageInventory(c, context, s.images, stage);
  closed(s.resources, privateLinkResourceDescriptors(c, context, nameProjection, evidence).map(value => value.id));
  for (const id of view.legacyAbsentIds) {
    if (s.resources[id] !== null || plList(s.lists.apps).some(value => sameId(value.id, id)) ||
        plList(s.lists.groupResources).some(value => sameId(value.id, id))) fail('PRIVATE_LINK_RETIRED_RUNTIME_NAME_PRESENT');
  }
  closed(s.lists, Object.keys(privateLinkReadRequests(c, context)));
  for (const [key, value] of Object.entries(s.lists)) plList(value, ['profiles', 'associations', 'rules', 'links', 'linkReferences'].includes(key));
  const created = Object.fromEntries(context.plan.stages.flatMap(value => value.resources.map(d => [d.id, value.id])));
  for (const id of [n.vnet, n.appsSubnet, n.endpointSubnet, n.endpoint, n.dnsZone, n.dnsLink, n.dnsZoneGroup,
    n.environment, q.role, q.assignment]) {
    if ((s.resources[id] !== null) !== atLeast(stage, created[id])) fail('PRIVATE_LINK_STAGE_RESOURCE_MISMATCH');
  }
  const removed = { [old.rule]: 'retire-nsp-rule', [old.association]: 'retire-nsp-association',
    [old.profile]: 'retire-nsp-profile', [old.perimeter]: 'retire-nsp-perimeter',
    [n.oldApp]: 'retire-old-receiver', [n.oldEnvironment]: 'retire-old-environment' };
  for (const [id, after] of Object.entries(removed)) if ((s.resources[id] === null) !== atLeast(stage, after)) fail('PRIVATE_LINK_RETIREMENT_UNVERIFIED');
  for (const id of [n.ingestIdentity, n.pullIdentity]) {
    const expected = context.origin.receiver.prerequisiteReceipts.core.resources[id], value = s.resources[id];
    if (!value || !sameId(value.id, id) || value.properties?.tenantId !== c.tenantId) fail('PRIVATE_LINK_IDENTITY_SCOPE_CHANGED');
    plEqual(executionIdentity(value, 'Microsoft.ManagedIdentity/userAssignedIdentities'),
      executionIdentity(expected, 'Microsoft.ManagedIdentity/userAssignedIdentities'), 'PRIVATE_LINK_IDENTITY_CHANGED');
  }
  if (s.resources[n.oldApp]) {
    const anchor = context.origin.receiver.receipt.resources[n.oldApp], actual = s.resources[n.oldApp];
    const ctx = resourceContext(c, { ...context.origin.receiver.prerequisiteReceipts, receiverUpgrade: context.origin.receiver });
    if (admissionFlag(actual) !== 'false') fail('PRIVATE_LINK_OLD_RECEIVER_ENABLED');
    plEqual(canonicalAppWrite(c, context.origin.receiver.phase.resources[0], actual, ctx),
      canonicalAppWrite(c, context.origin.receiver.phase.resources[0], anchor, ctx), 'PRIVATE_LINK_OLD_APP_DRIFT');
    plEqual(executionIdentity(actual, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps'), 'PRIVATE_LINK_OLD_APP_GENERATION_CHANGED');
  }
  if (s.resources[n.oldEnvironment]) {
    const value = s.resources[n.oldEnvironment], p = value.properties;
    if (!sameId(value.id, n.oldEnvironment) || !isDeepStrictEqual(value.tags, ownerTags(c)) ||
        p?.provisioningState !== 'Succeeded' || p.vnetConfiguration !== null || p.infrastructureResourceGroup !== null ||
        p.publicNetworkAccess !== 'Enabled' || p.zoneRedundant !== false ||
        (p.appLogsConfiguration?.destination ?? '') !== '') fail('PRIVATE_LINK_OLD_ENVIRONMENT_DRIFT');
    privateLinkGeneration(value);
    const retained = context.origin.receiver.prerequisiteReceipts.core.resources[n.oldEnvironment];
    if (retained) plEqual(privateLinkGeneration(value), privateLinkGeneration(retained), 'PRIVATE_LINK_OLD_ENVIRONMENT_GENERATION_CHANGED');
  }
  const registry = s.resources[r.registry];
  if (!sameId(registry?.id, r.registry) || registry.properties?.adminUserEnabled !== false ||
      registry.properties.anonymousPullEnabled !== false) fail('PRIVATE_LINK_REGISTRY_SECURITY_CHANGED');
  if (stage === 'retire-old-environment' || atLeast(stage, 'set-project-steady-budget')) {
    if (plList(s.lists.apps).some(value => sameId(value.properties?.managedEnvironmentId, n.oldEnvironment))) fail('PRIVATE_LINK_OLD_ENVIRONMENT_NOT_EMPTY');
  }
  const expectedAccess = atLeast(stage, 'disable-storage-public') ? 'Disabled' : 'SecuredByPerimeter';
  const accountCopy = structuredClone(s.resources[n.account]);
  if (!accountCopy) fail('PRIVATE_LINK_ACCOUNT_MISSING');
  const connections = accountCopy.properties.privateEndpointConnections;
  if (atLeast(stage, 'create-queue-endpoint')) {
    if (!Array.isArray(connections) || connections.length !== 1 ||
        !sameId(connections[0].properties?.privateEndpoint?.id, n.endpoint)) fail('PRIVATE_LINK_ACCOUNT_CONNECTION_DRIFT');
  } else if (connections !== undefined && !isDeepStrictEqual(connections, [])) fail('PRIVATE_LINK_ALTERNATIVE_ENDPOINT');
  // The separately validated private endpoint is the sole intentional account delta.
  accountCopy.properties.privateEndpointConnections = [];
  const baseline = context.origin.adoption.observation.resources[n.account].properties;
  if (!Object.hasOwn(baseline, 'privateEndpointConnections')) delete accountCopy.properties.privateEndpointConnections;
  verifyAdoptedQueueStorage(c, context.origin.adoption, { [n.account]: accountCopy,
    [q.service]: s.resources[q.service], [q.queue]: s.resources[q.queue] }, expectedAccess);
  exactIds(s.lists.queues, [q.queue]);
  const original = context.origin.receiver.prerequisiteReceipts;
  const workspace = s.resources[r.workspace];
  const expectedWorkspace = original['workspace-access']?.resources?.[r.workspace] ?? original.core?.resources?.[r.workspace];
  if (!workspace || !expectedWorkspace || !sameId(workspace.id, r.workspace) ||
      workspace.properties?.features?.disableLocalAuth !== true ||
      workspace.properties.features.enableLogAccessUsingOnlyResourcePermissions !== false ||
      (expectedWorkspace.properties.retentionInDays !== undefined &&
        workspace.properties.retentionInDays !== expectedWorkspace.properties.retentionInDays)) fail('PRIVATE_LINK_WORKSPACE_DRIFT');
  for (const [key, value] of Object.entries(expectedWorkspace.properties)) {
    if (key === 'workspaceCapping') {
      const actual = structuredClone(workspace.properties.workspaceCapping), expected = structuredClone(value);
      for (const item of [actual, expected]) {
        if (Object.hasOwn(item, 'quotaNextResetTime')) { queueArmInstant(item.quotaNextResetTime); delete item.quotaNextResetTime; }
        if (Object.hasOwn(item, 'dataIngestionStatus')) {
          if (typeof item.dataIngestionStatus !== 'string') fail('PRIVATE_LINK_WORKSPACE_DRIFT');
          delete item.dataIngestionStatus;
        }
      }
      plEqual(actual, expected, 'PRIVATE_LINK_WORKSPACE_DRIFT');
    } else if (!['provisioningState', 'modifiedDate', 'lastModifiedDate'].includes(key)) plEqual(workspace.properties[key], value, 'PRIVATE_LINK_WORKSPACE_DRIFT');
  }
  if (expectedWorkspace.properties.customerId !== undefined &&
      workspace.properties.customerId !== expectedWorkspace.properties.customerId) fail('PRIVATE_LINK_WORKSPACE_GENERATION_CHANGED');
  const data = buildPhase(c, 'data', { columns: telemetryColumns }, original);
  for (const descriptor of data.resources) verifyResource(c, data, descriptor, s.resources[descriptor.id], { workspace });
  const retainedDcr = original.data?.resources?.[r.dcr];
  if (!retainedDcr || s.resources[r.dcr].properties.immutableId !== retainedDcr.properties.immutableId) fail('PRIVATE_LINK_DCR_GENERATION_CHANGED');
  plEqual(s.resources[r.dcr].properties.endpoints, retainedDcr.properties.endpoints, 'PRIVATE_LINK_DCR_ENDPOINT_CHANGED');
  exactIds(s.lists.workspaceExports, []);
  if (context.origin.adoption.version === 3) verifyCurrentQueueDefender(c, context.origin.adoption.origin,
    context.origin.adoption.proposal.defender, s.defender);
  else if (s.defender !== null) fail('PRIVATE_LINK_DEFENDER_CONTEXT_CHANGED');
  const originalNetwork = context.origin.network.records.at(-1).receipt.observation.resources;
  for (const id of [old.perimeter, old.profile, old.association]) if (s.resources[id]) {
    plEqual(privateLinkGeneration(s.resources[id]), privateLinkGeneration(originalNetwork[id]), 'PRIVATE_LINK_ORIGINAL_NSP_GENERATION_CHANGED');
  }
  if (!atLeast(stage, 'retire-nsp-profile')) {
    const p = s.resources[old.profile]?.properties;
    plOnly(p, ['accessRulesVersion', 'diagnosticSettingsVersion']);
    if (!p || !/^(0|[1-9]\d*)$/u.test(p.accessRulesVersion) ||
        !/^(0|[1-9]\d*)$/u.test(p.diagnosticSettingsVersion)) fail('PRIVATE_LINK_NSP_PROFILE_UNVERIFIED');
    exactIds(s.lists.profiles, [old.profile], true);
    plEqual(privateLinkResourceState(s.lists.profiles.value[0]), privateLinkResourceState(s.resources[old.profile]), 'PRIVATE_LINK_NSP_LIST_GET_CHANGED');
  } else exactIds(s.lists.profiles, [], true);
  exactIds(s.lists.links, [], true); exactIds(s.lists.linkReferences, [], true);
  exactIds(s.lists.associations, atLeast(stage, 'retire-nsp-association') ? [] : [old.association], true);
  exactIds(s.lists.rules, atLeast(stage, 'retire-nsp-rule') ? [] : [old.rule], true);
  if (!atLeast(stage, 'retire-nsp-association')) {
    const association = s.resources[old.association]?.properties;
    plOnly(association, ['accessMode', 'provisioningState', 'hasProvisioningIssues', 'profile', 'privateLinkResource']);
    if (association?.accessMode !== 'Enforced' || association.provisioningState !== 'Succeeded' ||
        association.hasProvisioningIssues !== 'no') fail('PRIVATE_LINK_NSP_ASSOCIATION_DRIFT');
    ref(association.profile, old.profile); ref(association.privateLinkResource, n.account);
    plEqual(privateLinkResourceState(s.lists.associations.value[0]), privateLinkResourceState(s.resources[old.association]), 'PRIVATE_LINK_NSP_LIST_GET_CHANGED');
    const effective = s.effective?.properties, profile = s.resources[old.profile].properties;
    plOnly(effective, ['provisioningState', 'provisioningIssues', 'networkSecurityPerimeter', 'resourceAssociation', 'profile']);
    plOnly(effective.profile, ['name', 'accessRulesVersion', 'diagnosticSettingsVersion', 'accessRules', 'enabledLogCategories']);
    plOnly(effective.networkSecurityPerimeter, ['id', 'location', 'perimeterGuid']);
    plOnly(effective.resourceAssociation, ['name', 'accessMode']);
    if (plList(s.lists.effective).length !== 1 || !sameId(s.lists.effective.value[0].id, s.effective?.id) ||
        effective?.provisioningState !== 'Succeeded' ||
        (Object.hasOwn(effective, 'provisioningIssues') && !isDeepStrictEqual(effective.provisioningIssues, [])) ||
        !sameId(effective.networkSecurityPerimeter?.id, old.perimeter) ||
        effective.networkSecurityPerimeter.perimeterGuid !== s.resources[old.perimeter].properties.perimeterGuid ||
        effective.resourceAssociation?.accessMode !== 'Enforced' ||
        effective.resourceAssociation.name !== old.association.split('/').at(-1) ||
        effective.profile?.name !== old.profile.split('/').at(-1) ||
        effective.profile.accessRulesVersion !== Number(profile.accessRulesVersion) ||
        effective.profile.diagnosticSettingsVersion !== Number(profile.diagnosticSettingsVersion) ||
        !isDeepStrictEqual(effective.profile.enabledLogCategories, [])) fail('PRIVATE_LINK_NSP_PROPAGATION_PENDING');
    plEqual(privateLinkResourceState(s.lists.effective.value[0]), privateLinkResourceState(s.effective), 'PRIVATE_LINK_EFFECTIVE_LIST_GET_CHANGED');
    if (atLeast(stage, 'retire-nsp-rule')) plEqual(effective.profile.accessRules, [], 'PRIVATE_LINK_NSP_RULE_COPY_PRESENT');
    else if (!Array.isArray(effective.profile.accessRules) || effective.profile.accessRules.length !== 1) fail('PRIVATE_LINK_OPAQUE_RULE_PREIMAGE_REQUIRED');
  } else if (plList(s.lists.effective).length || s.effective !== null) fail('PRIVATE_LINK_NSP_EFFECTIVE_COPY_PRESENT');
  if (!atLeast(stage, 'create-network')) {
    const spaces = plList(s.lists.addressSpaces).flatMap(value => {
      if (!Array.isArray(value.properties?.addressSpace?.addressPrefixes)) fail('PRIVATE_LINK_ADDRESS_INVENTORY_INCOMPLETE');
      return value.properties.addressSpace.addressPrefixes;
    });
    privateLinkAddresses({ ...t.addresses, knownAddressSpaces: spaces });
    plEqual([...new Set(spaces)].sort(), [...t.addresses.knownAddressSpaces].sort(), 'PRIVATE_LINK_ADDRESS_INVENTORY_CHANGED');
  } else verifyNetwork(c, context, s, externalAdoption);
  let privatePath = null;
  if (atLeast(stage, 'create-queue-endpoint')) privatePath = verifyPrivateLinkEndpoint(c, context, s);
  else if (plList(s.lists.storageConnections).length || s.nic !== null) fail('PRIVATE_LINK_ALTERNATIVE_ENDPOINT');
  if (atLeast(stage, 'create-environment')) verifyEnvironment(c, context, s, environmentWireVersion);
  else if (s.resources[n.managedGroup] !== null || Object.keys(s.managed).length) fail('PRIVATE_LINK_MANAGED_GROUP_ALREADY_EXISTS');
  const budgets = privateLinkBudgetConfiguration(c, t), steady = privateLinkBudgetConfiguration(c, t, true);
  const expectedProject = atLeast(stage, 'set-project-steady-budget') ? steady.project : atLeast(stage, 'set-project-migration-budget')
    ? budgets.project : { ...budgetProperties(c, c.budget.projectAmount), filter: projectBudgetFilter(c) };
  const expectedTelemetry = atLeast(stage, 'set-telemetry-steady-budget') ? steady.telemetry : atLeast(stage, 'set-telemetry-migration-budget')
    ? budgets.telemetry : budgetProperties(c, c.budget.telemetryAmount);
  for (const [id, expected] of [[r.projectBudget, expectedProject], [r.budget, expectedTelemetry], [r.stateBudget, budgets.state]]) {
    if (!sameId(s.resources[id]?.id, id)) fail('PRIVATE_LINK_BUDGET_TARGET_CHANGED');
    plEqual(budgetConfiguration(s.resources[id]), { ...expected, filter: expected.filter ?? {} }, 'PRIVATE_LINK_BUDGET_COVERAGE_REQUIRED');
  }
  const descriptor = view.resources;
  if (atLeast(stage, 'create-queue-role')) verifyQueueResource(c, context.origin.adoption.topology, descriptor.queueRole, s.resources[q.role]);
  if (atLeast(stage, 'assign-queue-role')) verifyQueueResource(c, context.origin.adoption.topology, descriptor.queueAssignment, s.resources[q.assignment]);
  for (const key of ['accountGrants', 'serviceGrants', 'queueGrants']) for (const grant of plList(s.lists[key])) {
    const p = grant?.properties;
    if (!p || typeof grant.id !== 'string' || typeof p.scope !== 'string' || typeof p.principalId !== 'string' ||
        typeof p.roleDefinitionId !== 'string') fail('PRIVATE_LINK_GRANTS_INCOMPLETE');
    const scoped = [q.account, q.service, q.queue].some(id => sameId(p.scope, id));
    const worker = sameId(p.principalId, context.origin.adoption.identity.properties.principalId);
    if ((scoped || worker) && (!atLeast(stage, 'assign-queue-role') || !sameId(grant.id, q.assignment) ||
        !sameId(p.scope, q.queue) || !worker || !sameId(p.roleDefinitionId, q.role) || p.condition ||
        p.principalType !== 'ServicePrincipal')) fail('PRIVATE_LINK_UNREVIEWED_QUEUE_AUTHORIZATION');
  }
  if (s.resources[n.app] !== null) {
    if (!atLeast(stage, 'assign-queue-role') || !['false', 'true'].includes(admissionFlag(s.resources[n.app]))) fail('PRIVATE_LINK_RUNTIME_APP_DRIFT');
    verifyRuntimeApp(c, context, s, descriptor.app, admissionFlag(s.resources[n.app]));
  }
  if (n.publicProbe && s.resources[n.publicProbe] !== null) {
    if (!atLeast(stage, 'assign-queue-role') || atLeast(stage, 'retire-old-receiver')) fail('PRIVATE_LINK_PUBLIC_PROBE_MUST_BE_ABSENT');
    verifyRuntimeApp(c, context, s, descriptor.publicProbe, 'false');
  }
  if (atLeast(stage, 'retire-old-receiver') && (!s.resources[n.app] || admissionFlag(s.resources[n.app]) !== 'false')) fail('PRIVATE_LINK_REPLACEMENT_DISABLED_REQUIRED');
  if (n.publicProbe) {
    const listed = plList(s.lists.apps).filter(value => sameId(value.id, n.publicProbe));
    if (listed.length !== (s.resources[n.publicProbe] === null ? 0 : 1)) fail('PRIVATE_LINK_PUBLIC_PROBE_INVENTORY_CHANGED');
  }
  const diagnosticTargets = [n.vnet, n.endpoint, n.dnsZone, n.environment, n.app, n.account, q.service, n.oldApp, n.oldEnvironment, old.perimeter, r.workspace, r.dcr,
    ...(n.publicProbe ? [n.publicProbe] : [])];
  closed(s.diagnostics, diagnosticTargets);
  for (const value of Object.values(s.diagnostics)) exactIds(value, []);
  const known = new Set([...context.plan.preservedResourceIds, ...context.origin.original.preflight.preservedIds,
    ...Object.keys(s.resources).filter(id => s.resources[id] !== null), ...(s.nic ? [s.nic.id] : []),
    ...(externalAdoption ? Object.values(privateLinkNsgTargets(c, context)).map(value => value.id) : [])].map(id => id.toLowerCase()));
  if (plList(s.lists.groupResources).some(value => !known.has(value.id?.toLowerCase()))) fail('PRIVATE_LINK_UNREVIEWED_RESOURCE');
  return { stage, ...(privatePath ?? {}), snapshotSha256: hash(s) };
}
function equalImageInventory(c, context, image, stage) {
  const prior = context.origin.receiver.candidate, profile = context.origin.queueProfile;
  plEqual(image.repositories, ['missionspec/telemetry-ingest'], 'PRIVATE_LINK_IMAGE_INVENTORY_CHANGED');
  plEqual(image.referrers, [], 'PRIVATE_LINK_IMAGE_REFERRER_CHANGED');
  if (!Array.isArray(image.manifests) || ![2, 3].includes(image.manifests.length) ||
      (image.manifests.length === 3 && !atLeast(stage, 'assign-queue-role'))) fail('PRIVATE_LINK_IMAGE_INVENTORY_CHANGED');
  const expected = [{ digest: c.receiverDigest, tags: [prior.legacyPublication.release.tag] },
    { digest: prior.profile.manifestDigest, tags: [prior.review.tag] }];
  if (image.manifests.length === 3) expected.push({ digest: profile.manifestDigest, tags: [`receiver-${profile.manifestDigest.slice(7, 19)}`] });
  plEqual(image.manifests.map(({ digest, tags }) => ({ digest, tags })).sort((a, b) => a.digest.localeCompare(b.digest)),
    expected.sort((a, b) => a.digest.localeCompare(b.digest)), 'PRIVATE_LINK_IMAGE_INVENTORY_CHANGED');
  plEqual(image.legacyManifest, JSON.parse(prior.legacyPublication.manifestJson), 'PRIVATE_LINK_IMAGE_BYTES_CHANGED');
  plEqual(image.preparedManifest, JSON.parse(prior.profile.manifestJson), 'PRIVATE_LINK_IMAGE_BYTES_CHANGED');
  plEqual(image.queueManifest, image.manifests.length === 3 ? JSON.parse(profile.manifestJson) : null, 'PRIVATE_LINK_IMAGE_BYTES_CHANGED');
}
