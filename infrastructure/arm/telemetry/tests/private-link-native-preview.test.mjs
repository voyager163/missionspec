import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { privateLinkPhase } from '../private-link.mjs';
import { privateLinkPreservedIds, verifyPrivateLinkPreview } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateSnapshotFixture } from './private-link.fixture.mjs';
import { queueDefenderFixture } from './queue-defender.fixture.mjs';

test('native queue-role Create preview may omit only its two empty exclusion arrays', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const phase = privateLinkPhase(f.c, f.context, 'create-queue-role'), descriptor = phase.resources[0];
  const preview = { status: 'Succeeded', changes: [{ resourceId: descriptor.id, changeType: 'Create',
    after: { ...structuredClone(descriptor.expected), id: descriptor.id } }] };
  const permission = preview.changes[0].after.properties.permissions[0];
  delete permission.notActions; delete permission.notDataActions;
  const original = json(preview), phaseBytes = json(phase);
  assert.equal(verifyPrivateLinkPreview(phase, preview, {}, []), digest(original));
  assert.equal(json(preview), original); assert.equal(json(phase), phaseBytes);
  for (const mutate of [
    p => { p.changes[0].after.properties.permissions[0].notActions = null; },
    p => { p.changes[0].after.properties.permissions[0].notDataActions = null; },
    p => { p.changes[0].after.properties.permissions[0].notActions = ['*']; },
    p => { p.changes[0].after.properties.permissions[0].notDataActions = ['*']; },
    p => { delete p.changes[0].after.properties.permissions[0].actions; },
    p => { delete p.changes[0].after.properties.permissions[0].dataActions; },
    p => { p.changes[0].after.properties.permissions[0].actions.push('*'); },
    p => { p.changes[0].after.properties.permissions[0].dataActions.push('Microsoft.Storage/storageAccounts/queueServices/queues/messages/write'); },
    p => { p.changes[0].after.properties.permissions.push(structuredClone(p.changes[0].after.properties.permissions[0])); },
    p => { p.changes[0].after.properties.permissions = []; },
    p => { p.changes[0].after.properties.assignableScopes = [`/subscriptions/${f.c.subscriptionId}`]; },
    p => { p.changes[0].after.properties.type = 'BuiltInRole'; },
    p => { p.changes[0].resourceId += '-foreign'; },
    p => { p.changes[0].changeType = 'Modify'; },
  ]) {
    const changed = structuredClone(preview); mutate(changed);
    assert.throws(() => verifyPrivateLinkPreview(phase, changed, {}, []));
  }
  const changedPhase = structuredClone(phase);
  changedPhase.resources[0].expected.properties.permissions[0].notActions = ['*'];
  assert.throws(() => verifyPrivateLinkPreview(changedPhase, preview, {}, []), /WHATIF_CONTRADICTION/);
  assert.throws(() => verifyPrivateLinkPreview({ ...phase, stage: 'create-network' }, preview, {}, []), /WHATIF_CONTRADICTION/);
});

test('native network preview binds exact aggregated subnets plus both separate child creates without changing bytes', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const phase = privateLinkPhase(f.c, f.context, 'create-network');
  const preview = { status: 'Succeeded', changes: phase.resources.map(d => ({
    resourceId: d.id, changeType: 'Create', after: { ...structuredClone(d.expected), id: d.id },
  })) };
  for (const child of preview.changes.slice(1)) {
    child.after.name = child.resourceId.split('/').at(-1);
    delete child.after.dependsOn;
  }
  preview.changes[0].after.properties.subnets = preview.changes.slice(1).map(child => ({
    name: child.after.name, properties: structuredClone(child.after.properties),
  }));
  const bytes = json(preview);
  assert.equal(verifyPrivateLinkPreview(phase, preview, {}, []), digest(bytes));
  assert.equal(json(preview), bytes);
  for (const change of [
    p => { p.changes[0].after.properties.subnets[0].properties.addressPrefix = '10.240.9.0/26'; },
    p => { p.changes[0].after.properties.subnets.push(structuredClone(p.changes[0].after.properties.subnets[0])); },
    p => { p.changes[0].after.properties.subnets[0].properties.networkSecurityGroup = { id: 'unreviewed' }; },
    p => { p.changes[1].after.name = 'foreign/apps'; },
    p => { p.changes[1].resourceId = p.changes[1].resourceId.replace('/subnets/', '-foreign/subnets/'); },
    p => { p.changes[1].after.properties.addressPrefix = '10.240.9.0/26'; },
    p => { p.changes.pop(); },
    p => { p.changes[0].changeType = 'Modify'; },
  ]) {
    const changed = structuredClone(preview); change(changed);
    assert.throws(() => verifyPrivateLinkPreview(phase, changed, {}, []));
  }
});

test('only independently verified current Defender resources enter preserved Ignore inventory', async () => {
  const f = await queueDefenderFixture();
  const context = { origin: { adoption: { version: 3, origin: f.origin, proposal: { defender: f.evidence } } } };
  const snapshot = { resources: { [f.topology.ids.account]: {}, 'unit-absent': null },
    defender: structuredClone(f.evidence.snapshot) };
  const known = privateLinkPreservedIds(f.c, context, snapshot);
  assert(known.includes(snapshot.defender.topic.id));
  assert(known.includes(snapshot.defender.subscription.id));
  assert(!known.includes('unit-absent'));
  const preview = { status: 'Succeeded', changes: [{ resourceId: snapshot.defender.topic.id, changeType: 'Ignore' }] };
  const phase = { deploymentId: 'unit-deployment', resources: [] };
  verifyPrivateLinkPreview(phase, preview, snapshot, known);
  for (const type of ['Create', 'Modify', 'Delete']) {
    assert.throws(() => verifyPrivateLinkPreview(phase,
      { ...preview, changes: [{ ...preview.changes[0], changeType: type }] }, snapshot, known), /SCOPE_CHANGED/);
  }
  assert.throws(() => verifyPrivateLinkPreview(phase,
    { ...preview, changes: [{ resourceId: snapshot.defender.topic.id + '-foreign', changeType: 'Ignore' }] },
    snapshot, known), /SCOPE_CHANGED/);
  snapshot.defender.topic.id += '-foreign';
  assert.throws(() => privateLinkPreservedIds(f.c, context, snapshot));
});

test('DNS previews permit only exact child leaf names and omission of the empty zone property bag', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const phase = privateLinkPhase(f.c, f.context, 'create-queue-endpoint');
  const preview = { status: 'Succeeded', changes: phase.resources.map(d => {
    const after = { ...structuredClone(d.expected), id: d.id };
    delete after.dependsOn;
    if (d.type === 'Microsoft.Network/privateDnsZones') delete after.properties;
    if (['Microsoft.Network/privateDnsZones/virtualNetworkLinks',
      'Microsoft.Network/privateEndpoints/privateDnsZoneGroups'].includes(d.type)) after.name = d.id.split('/').at(-1);
    return { resourceId: d.id, changeType: 'Create', after };
  }) };
  const bytes = json(preview);
  verifyPrivateLinkPreview(phase, preview, {}, []);
  assert.equal(json(preview), bytes);
  const locate = (p, type) => p.changes.find(c => c.after.type === `Microsoft.Network/${type}`).after;
  for (const change of [
    p => { locate(p, 'privateDnsZones').properties = null; },
    p => { locate(p, 'privateDnsZones').properties = { unreviewed: true }; },
    p => { delete locate(p, 'privateEndpoints').properties; },
    p => { delete locate(p, 'privateDnsZones/virtualNetworkLinks').properties; },
    p => { locate(p, 'privateDnsZones/virtualNetworkLinks').name = 'foreign/link'; },
    p => { locate(p, 'privateEndpoints/privateDnsZoneGroups').name = 'foreign/queue'; },
    p => { locate(p, 'privateEndpoints/privateDnsZoneGroups').properties.privateDnsZoneConfigs[0].properties.privateDnsZoneId += '-foreign'; },
    p => { locate(p, 'privateDnsZones/virtualNetworkLinks').properties.registrationEnabled = true; },
  ]) {
    const changed = structuredClone(preview); change(changed);
    assert.throws(() => verifyPrivateLinkPreview(phase, changed, {}, []));
  }
});

test('only the fully verified owned endpoint NIC may be preserved by later control and runtime previews', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 });
  const snapshot = privateSnapshotFixture(f, 'create-queue-endpoint');
  const known = privateLinkPreservedIds(f.c, f.context, snapshot);
  assert(known.includes(snapshot.nic.id));
  const phase = privateLinkPhase(f.c, f.context, 'create-environment');
  const preview = { status: 'Succeeded', changes: [
    { resourceId: snapshot.nic.id, changeType: 'Ignore' },
    ...phase.resources.map(d => ({ resourceId: d.id, changeType: 'Create',
      after: { ...structuredClone(d.expected), id: d.id } })),
  ] };
  verifyPrivateLinkPreview(phase, preview, snapshot, known);
  for (const change of [
    s => { s.nic.id += '-foreign'; },
    s => { s.nic.properties.privateEndpoint.id += '-foreign'; },
    s => { s.nic.properties.enableIPForwarding = true; },
    s => { s.nic.properties.ipConfigurations[0].properties.privateIPAddress = '10.1.1.1'; },
    s => { s.nic.properties.ipConfigurations[0].properties.privateLinkConnectionProperties.groupId = 'blob'; },
  ]) {
    const changed = structuredClone(snapshot); change(changed);
    assert.throws(() => privateLinkPreservedIds(f.c, f.context, changed));
  }
  for (const changeType of ['Create', 'Modify', 'Delete']) {
    const changed = structuredClone(preview); changed.changes[0].changeType = changeType;
    assert.throws(() => verifyPrivateLinkPreview(phase, changed, snapshot, known), /SCOPE_CHANGED/);
  }
});
