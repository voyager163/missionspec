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
