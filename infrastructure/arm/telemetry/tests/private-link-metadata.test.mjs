import assert from 'node:assert/strict';
import test from 'node:test';
import { privateLinkGeneration, privateLinkResourceState, verifyPrivateLinkSnapshot } from '../private-link-readback.mjs';
import { queueArmInstant } from '../queue-adoption.mjs';
import { privateLinkFixture, privateInput, privateSnapshotFixture } from './private-link.fixture.mjs';

function registry(createdAt) {
  return {
    id: '/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/missionspec-unit-telemetry/providers/Microsoft.ContainerRegistry/registries/unitregistry',
    type: 'Microsoft.ContainerRegistry/registries',
    systemData: { createdAt, lastModifiedAt: createdAt, createdByType: 'Application' },
    properties: {},
  };
}

test('explicit zero-offset provider metadata retains raw bytes and exact 100ns creation identity', () => {
  const value = '2026-09-23T03:52:56.5359041+00:00', original = registry(value), saved = structuredClone(original);
  assert.deepEqual(privateLinkGeneration(original), privateLinkGeneration(registry('2026-09-23T03:52:56.5359041Z')));
  assert.equal(privateLinkGeneration(original).createdAt, queueArmInstant('2026-09-23T03:52:56.5359041Z').toString());
  assert.equal(privateLinkResourceState(original).systemData.createdAt, value);
  assert.deepEqual(original, saved);
  assert.notEqual(privateLinkGeneration(original).createdAt,
    privateLinkGeneration(registry('2026-09-23T03:52:56.5359042+00:00')).createdAt);
});

test('metadata UTC support cannot invent a timezone or admit malformed and unknown offsets', () => {
  for (const value of [
    '2026-09-23T03:52:56.5359041', '2026-09-23T03:52:56.5359041+01:00',
    '2026-09-23T03:52:56.5359041-00:00', '2026-09-23T03:52:56.53590410+00:00',
    '2026-02-30T03:52:56.5359041+00:00', '2026-09-23T03:52:56.5359041Z+00:00', null,
  ]) assert.throws(() => privateLinkGeneration(registry(value)), /QUEUE_ADOPTION_ARM_TIME_INVALID/);
  assert.throws(() => queueArmInstant('2026-09-23T03:52:56.5359041+00:00'), /QUEUE_ADOPTION_ARM_TIME_INVALID/);
});

test('provider-created queue endpoint metadata stays exact and cannot add routes, IPv6 or another owner', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const snapshot = privateSnapshotFixture(f, 'create-queue-endpoint'), n = f.context.plan.topology.ids;
  snapshot.resources[n.endpointSubnet].properties.purpose = 'PrivateEndpoints';
  Object.assign(snapshot.resources[n.endpoint].properties, {
    isIPv6EnabledPrivateEndpoint: false, customNetworkInterfaceName: '', customDnsConfigs: [],
  });

  Object.assign(snapshot.nic, { kind: 'Regular', managedBy: n.endpoint });
  Object.assign(snapshot.nic.properties, {
    allowPort25Out: true, auxiliaryMode: 'None', auxiliarySku: 'None',
    defaultOutboundConnectivityEnabled: false, vnetEncryptionSupported: false,
    disableTcpStateTracking: false, nicType: 'Standard', macAddress: '', hostedWorkloads: [], tapConfigurations: [],
    dnsSettings: { dnsServers: [], appliedDnsServers: [], internalDomainNameSuffix: 'unit.px.internal.cloudapp.net' },
  });
  const config = snapshot.resources[n.dnsZoneGroup].properties.privateDnsZoneConfigs[0];
  Object.assign(config, { id: `${n.dnsZoneGroup}/privateDnsZoneConfigs/queue`,
    type: 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups/privateDnsZoneConfigs', etag: 'UNIT etag' });
  config.properties.provisioningState = 'Succeeded';
  const original = structuredClone(snapshot);
  assert.equal(verifyPrivateLinkSnapshot(f.c, f.context, snapshot, 'create-queue-endpoint').privateIp, '10.240.8.68');
  assert.deepEqual(snapshot, original);
  for (const change of [
    s => { s.resources[n.appsSubnet].properties.purpose = 'PrivateEndpoints'; },
    s => { s.resources[n.endpointSubnet].properties.purpose = 'Other'; },
    s => { s.resources[n.endpoint].properties.isIPv6EnabledPrivateEndpoint = true; },
    s => { s.resources[n.endpoint].properties.isIPv6EnabledPrivateEndpoint = null; },
    s => { s.resources[n.endpoint].properties.customNetworkInterfaceName = 'foreign'; },
    s => { s.resources[n.endpoint].properties.customDnsConfigs = [{ fqdn: 'foreign' }]; },
    s => { s.nic.managedBy += '-foreign'; },
    s => { s.nic.kind = 'Elastic'; },
    s => { s.nic.properties.defaultOutboundConnectivityEnabled = true; },
    s => { s.nic.properties.auxiliaryMode = 'AcceleratedConnections'; },
    s => { s.nic.properties.dnsSettings.dnsServers = ['8.8.8.8']; },
    s => { s.nic.properties.dnsSettings.appliedDnsServers = ['8.8.8.8']; },
    s => { s.nic.properties.dnsSettings.internalDomainNameSuffix = 'foreign.invalid'; },
    s => { s.nic.properties.hostedWorkloads = ['foreign']; },
    s => { s.nic.properties.tapConfigurations = [{ id: 'foreign' }]; },
    s => { s.resources[n.dnsZoneGroup].properties.privateDnsZoneConfigs[0].id += '-foreign'; },
    s => { s.resources[n.dnsZoneGroup].properties.privateDnsZoneConfigs[0].properties.provisioningState = 'Failed'; },
    s => { s.nic.properties.unreviewed = false; },
  ]) {
    const altered = structuredClone(snapshot); change(altered);
    assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, altered, 'create-queue-endpoint'));
  }
  const absent = privateSnapshotFixture(f, 'create-network');
  absent.resources[n.endpointSubnet].properties.purpose = 'PrivateEndpoints';
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, absent, 'create-network'), /PURPOSE_UNVERIFIED/);
});

test('actual ACA subnet association and disabled optional features bind only the owned ready environment', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const snapshot = privateSnapshotFixture(f, 'create-environment'), n = f.context.plan.topology.ids;
  const properties = snapshot.resources[n.environment].properties;
  Object.assign(properties, { appInsightsConfiguration: null, openTelemetryConfiguration: null, ingressConfiguration: null });
  properties.workloadProfiles[0].enableFips = false;
  const group = n.vnet.split('/providers/')[0];
  const association = { id: `${n.appsSubnet}/serviceAssociationLinks/legionservicelink`, name: 'legionservicelink',
    type: 'Microsoft.Network/virtualNetworks/subnets/serviceAssociationLinks', properties: {
      linkedResourceType: 'Microsoft.App/environments',
      link: `${group}/virtualnetworks/${n.vnet.split('/').at(-1)}/subnets/apps`,
      allowDelete: false, enabledForArmDeployments: false, locations: [], provisioningState: 'Succeeded',
      subnetId: '00000000-0000-4000-8000-000000000123',
    } };
  snapshot.resources[n.appsSubnet].properties.serviceAssociationLinks = [association];
  const original = structuredClone(snapshot);
  assert.equal(verifyPrivateLinkSnapshot(f.c, f.context, snapshot, 'create-environment').stage, 'create-environment');
  assert.deepEqual(snapshot, original);
  for (const change of [
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.link += '-foreign'; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].id += '-foreign'; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.allowDelete = true; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.enabledForArmDeployments = true; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.locations = ['foreign']; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.subnetId = 'unbound'; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks[0].properties.extra = false; },
    s => { s.resources[n.appsSubnet].properties.serviceAssociationLinks.push(structuredClone(association)); },
    s => { s.resources[n.endpointSubnet].properties.serviceAssociationLinks = [structuredClone(association)]; },
    s => { s.resources[n.environment].properties.vnetConfiguration.infrastructureSubnetId = n.endpointSubnet; },
    s => { s.resources[n.environment].properties.appInsightsConfiguration = {}; },
    s => { s.resources[n.environment].properties.openTelemetryConfiguration = {}; },
    s => { s.resources[n.environment].properties.ingressConfiguration = {}; },
    s => { s.resources[n.environment].properties.workloadProfiles[0].enableFips = true; },
    s => { s.resources[n.environment].properties.workloadProfiles[0].enableFips = null; },
  ]) {
    const altered = structuredClone(snapshot); change(altered);
    assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, altered, 'create-environment'));
  }
  const before = privateSnapshotFixture(f, 'create-queue-endpoint');
  before.resources[n.appsSubnet].properties.serviceAssociationLinks = [association];
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, before, 'create-queue-endpoint'), /SUBNET_LINK_UNVERIFIED/);
});

test('the first-party public-IP marker requires the exact managed ACA ingress resource and frontend', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const snapshot = privateSnapshotFixture(f, 'create-environment'), n = f.context.plan.topology.ids;
  const oldId = Object.keys(snapshot.managed).find(id => id.includes('/publicIPAddresses/'));
  const id = `${n.managedGroup}/providers/Microsoft.Network/publicIPAddresses/capp-svc-lb-ip`;
  const ip = snapshot.managed[oldId];
  delete snapshot.managed[oldId]; snapshot.managed[id] = ip;
  ip.id = id; ip.name = 'capp-svc-lb-ip'; ip.tags = { 'aca-managed-env-id': n.environment };
  ip.properties.ipTags = [{ ipTagType: 'FirstPartyUsage', tag: '/Unprivileged' }];
  ip.properties.ipConfiguration = {
    id: `${n.managedGroup}/providers/Microsoft.Network/loadBalancers/capp-svc-lb/frontendIPConfigurations/capp-svc-lbfe`,
  };
  snapshot.lists.managedResources.value.find(value => value.id === oldId).id = id;
  const balancer = Object.values(snapshot.managed).find(value => value.type === 'Microsoft.Network/loadBalancers');
  balancer.properties.frontendIPConfigurations[0].properties.publicIPAddress.id = id;
  const original = structuredClone(snapshot);
  verifyPrivateLinkSnapshot(f.c, f.context, snapshot, 'create-environment');
  assert.deepEqual(snapshot, original);
  for (const change of [
    value => { value.properties.ipTags[0].tag = '/Other'; },
    value => { value.properties.ipTags[0].ipTagType = 'Other'; },
    value => { value.properties.ipTags.push({ ipTagType: 'FirstPartyUsage', tag: '/Unprivileged' }); },
    value => { value.tags['aca-managed-env-id'] += '-foreign'; },
    value => { value.properties.ipConfiguration.id += '-foreign'; },
    value => { value.properties.ipAddress = '203.0.113.16'; },
  ]) {
    const altered = structuredClone(snapshot); change(altered.managed[id]);
    assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, altered, 'create-environment'), /PUBLIC_IP_DRIFT/);
  }
});
