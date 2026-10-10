import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { digest, json, ids } from '../definition.mjs';
import { privateDirectory, saveImmutable, load, MAX_PRIVATE_ARTIFACT_BYTES } from '../controller.mjs';
import { withPrivateLinkControlValidation,
  verifyPrivateLinkControlContext } from '../private-link.mjs';
import { privateLinkNsgTarget, verifyPrivateLinkNsgCurrent, verifyPrivateLinkNsgProvenance,
  verifyPrivateLinkNsgAdoption, verifyPrivateLinkNsgDelta,
  privateLinkNsgAdoptionPins, withPrivateLinkNsgValidation, privateLinkNsgValidatedRecord,
  privateLinkNsgValidationFor, PRIVATE_LINK_NSG_ATTACHED_MODE, verifyPrivateLinkNsgAcaCompatibility } from '../private-link-nsg-adoption.mjs';
import { collectPrivateLinkSnapshot, verifyPrivateLinkSnapshot } from '../private-link-readback.mjs';
import { preparePrivateLinkPhase, verifyPrivateLinkControlEvidence, privateLinkTargetKey,
  privateLinkPreservedIds, verifyPrivateLinkPreview, privateLinkReadIO,
  runPrivateLinkNsgAdoption, runPrivateLinkControl, readPrivateLinkHead, privateLinkArtifactBytes } from '../private-link-controller.mjs';
import { nsgAdoptionFixture, retainedReadInvoke, retainedSourceLookup } from './private-link-nsg-adoption.fixture.mjs';
const hash = value => digest(json(value));
const x = await nsgAdoptionFixture();
const attached = await nsgAdoptionFixture(() => {}, true);
const { f } = x;

test('exact governance adoption is distinct read-only evidence and retains original plan, six records and pending failure', () => {
  const old = json(x.original), prior = json(x.evidence), plan = json(f.context.plan);
  verifyPrivateLinkNsgAdoption(f.c, f.context, x.adoption, x.evidence);
  assert.equal(x.adoptedEvidence.version, 2); assert.equal(x.adoptedEvidence.records.length, 6);
  assert.equal(json(x.adoptedEvidence.records), json(x.evidence.records));
  assert.equal(x.original.journal.dispatchAttempted, false); assert.equal(x.original.journal.outcome, 'reconciliation-required');
  assert(Object.values(x.adoption.authority).every(value => value === false));
  assert.equal(x.adoption.review.costDisclosure.zeroFeeProven, false);
  assert.equal(x.adoption.proposal.attribution.assurance.auditPolicyIsDeploymentAttribution, false);
  assert.notEqual(x.provenance.actor.homeTenantId, f.c.tenantId);
  assert.notEqual(x.provenance.actor.homeObjectId, x.provenance.actor.localServicePrincipalId);
  assert.equal(x.adoption.proposal.attribution.vnetWriteHistory.length, 2);
  const [priorWrite, last] = x.adoption.proposal.attribution.vnetWriteHistory;
  assert(priorWrite.acceptedAt < last.acceptedAt); assert(priorWrite.succeededAt > last.succeededAt);
  verifyPrivateLinkSnapshot(f.c, f.context, x.current, 'create-queue-endpoint', 2, x.adoption, x.evidence);
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, x.current, 'create-queue-endpoint'));
  assert.equal(json(x.original), old); assert.equal(json(x.evidence), prior); assert.equal(json(f.context.plan), plan);
});

test('operation-local validation proof cannot be forged, serialized, reused or survive input/context mutation', async () => {
  const adoption = structuredClone(x.adoption); let expired;
  await withPrivateLinkNsgValidation(f.c, f.context, adoption, x.evidence, async proof => {
    expired = proof;
    assert.equal(privateLinkNsgValidatedRecord(f.c, f.context, proof).version, 2);
    for (const fake of [JSON.parse(JSON.stringify(proof)), structuredClone(proof), {}, { validated: true, adoptionSha256: hash(adoption) }]) {
      assert.throws(() => privateLinkNsgValidatedRecord(f.c, f.context, fake));
    }
    await Promise.resolve();
    assert.throws(() => privateLinkNsgValidatedRecord({ ...f.c, runId: randomUUID() }, f.context, proof), /VALIDATION_INPUT_CHANGED/);
    const wrong = structuredClone(f.context); wrong.plan.topology.ids.vnet += '-other';
    assert.throws(() => privateLinkNsgValidatedRecord(f.c, wrong, proof), /VALIDATION_INPUT_CHANGED/);
    assert.throws(() => { adoption.proposal.pendingHead.intentSha256 = digest('UNIT different pending head'); }, TypeError);
    const replaced = structuredClone(adoption); replaced.proposal.pendingHead.intentSha256 = digest('UNIT different pending head');
    assert.throws(() => privateLinkNsgValidationFor(f.c, f.context, replaced, proof), /VALIDATION_INPUT_CHANGED/);
  });
  assert.throws(() => privateLinkNsgValidatedRecord(f.c, f.context, expired));
  const invalid = structuredClone(adoption); invalid.proposal.pendingHead.intentSha256 = digest('UNIT different pending head');
  assert.throws(() => withPrivateLinkNsgValidation(f.c, f.context, invalid, x.evidence, () => assert.fail('mutated history accepted')));
  const changed = structuredClone(x.adoptedEvidence); changed.externalAdoption.proposal.original.journal.dispatchAttempted = null;
  assert.throws(() => preparePrivateLinkPhase(f.c, f.context, changed, 'create-environment'));
  assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context, changed));
  assert.throws(() => verifyPrivateLinkNsgAdoption(f.c, f.context, x.adoption), /ACTUAL_ANCHOR_REQUIRED/);
  assert.throws(() => verifyPrivateLinkNsgAdoption(f.c, f.context, x.adoption, { ...x.evidence, records: [] }), /ANCHOR_REQUIRED/);
  const tampered = structuredClone(x.evidence); tampered.records[0].approval.sourceSha256 = digest('UNIT substituted anchor source');
  assert.throws(() => verifyPrivateLinkNsgAdoption(f.c, f.context, x.adoption, tampered));
});

test('context proof is synchronous, immutable and unavailable outside its verified operation', () => {
  withPrivateLinkControlValidation(f.c, f.context, () => {
    verifyPrivateLinkControlContext(f.c, f.context);
    assert.throws(() => { f.context.plan.sourceSha256 = digest('UNIT mutated'); }, TypeError);
    const other = structuredClone(f.context); other.plan.sourceSha256 = digest('UNIT different');
    assert.throws(() => verifyPrivateLinkControlContext(f.c, other));
  });
  assert.throws(() => withPrivateLinkControlValidation(f.c, f.context, () => Promise.resolve()),
    /SYNCHRONOUS_VALIDATION_REQUIRED/);
  const other = structuredClone(f.context); other.plan.sourceSha256 = digest('UNIT different');
  assert.throws(() => verifyPrivateLinkControlContext(f.c, other));
});

test('compact new artifacts reload under the unchanged cap with exact parsed history and canonical hashes', async t => {
  const directory = `infrastructure/arm/telemetry/tests/.private-link-nsg-size-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const before = hash(x.adoptedEvidence), original = json(x.original), bytes = privateLinkArtifactBytes(x.adoptedEvidence);
  assert(Buffer.byteLength(bytes) < Buffer.byteLength(json(x.adoptedEvidence)));
  await saveImmutable(directory, 'compact-evidence.json', bytes);
  const restored = await load(directory, 'compact-evidence.json');
  assert.deepEqual(restored, x.adoptedEvidence); assert.equal(hash(restored), before);
  verifyPrivateLinkControlEvidence(f.c, f.context, restored);
  assert.equal(json(x.original), original);
  assert.equal(Buffer.byteLength(privateLinkArtifactBytes('x'.repeat(MAX_PRIVATE_ARTIFACT_BYTES - 3))), MAX_PRIVATE_ARTIFACT_BYTES);
  assert.throws(() => privateLinkArtifactBytes('x'.repeat(MAX_PRIVATE_ARTIFACT_BYTES - 2)), /PRIVATE_FILE_TOO_LARGE/);
});

test('current NSG validation rejects custom/default-rule, generation, attachment, diagnostics and targeted flow-log drift', async t => {
  const target = privateLinkNsgTarget(f.c, f.context);
  for (const [name, mutate] of [
    ['custom rule', o => { o.nsg.properties.securityRules.push({ name: 'UNIT-unapproved' }); }],
    ['default rule changed', o => { o.nsg.properties.defaultSecurityRules[0].properties.access = 'Deny'; }],
    ['default rule missing', o => { o.nsg.properties.defaultSecurityRules.pop(); }],
    ['rule selector added', o => { o.nsg.properties.defaultSecurityRules[0].properties.destinationApplicationSecurityGroups = []; }],
    ['new generation', o => { o.nsg.properties.resourceGuid = '20000000-0000-4000-8000-000000000001'; }],
    ['other NSG', o => { o.nsg.id += '-other'; }],
    ['apps attachment', o => { o.nsg.properties.subnets[0].id = f.context.plan.topology.ids.appsSubnet; }],
    ['extra subnet', o => { o.nsg.properties.subnets.push({ id: f.context.plan.topology.ids.appsSubnet }); }],
    ['NIC attachment', o => { o.nsg.properties.networkInterfaces = [{ id: 'UNIT-nic' }]; }],
    ['previously unattached NSG attached', o => { o.unattachedNsg.properties.subnets = [{ id: f.context.plan.topology.ids.appsSubnet }]; }],
    ['unattached generation changed', o => { o.unattachedNsg.properties.resourceGuid = '20000000-0000-4000-8000-000000000002'; }],
    ['unattached custom rule', o => { o.unattachedNsg.properties.securityRules.push({ name: 'UNIT-unapproved' }); }],
    ['unattached default rule changed', o => { o.unattachedNsg.properties.defaultSecurityRules[0].properties.access = 'Deny'; }],
    ['unattached diagnostics export', o => { o.unattachedDiagnostics.value.push({ id: 'UNIT-export' }); }],
    ['third NSG bundle', o => { o.thirdNsg = structuredClone(o.nsg); }],
    ['diagnostics export', o => { o.diagnostics.value.push({ id: target.id + '/providers/Microsoft.Insights/diagnosticSettings/unit' }); }],
    ['missing watcher completeness', o => { o.watchers.nextLink = 'more'; }],
    ['unknown watcher scope', o => { o.watchers.value[0].id = 'https://example.invalid/watcher'; }],
    ['flow log bound NSG', o => { o.flowLogs[x.watcherId].value.push({ id: x.watcherId + '/flowLogs/unit',
      type: 'Microsoft.Network/networkWatchers/flowLogs', properties: { enabled: true, targetResourceId: target.id } }); }],
    ['disabled flow log still bound VNet', o => { o.flowLogs[x.watcherId].value.push({ id: x.watcherId + '/flowLogs/unit',
      type: 'Microsoft.Network/networkWatchers/flowLogs', properties: { enabled: false, targetResourceId: target.vnet } }); }],
    ['flow log bound unattached NSG', o => { o.flowLogs[x.watcherId].value.push({ id: x.watcherId + '/flowLogs/unit',
      type: 'Microsoft.Network/networkWatchers/flowLogs', properties: { enabled: false, targetResourceId: o.unattachedNsg.id } }); }],
    ['missing regional page', o => { delete o.flowLogs[x.watcherId]; }],
    ['unrequested watcher data', o => { o.flowLogs['foreign'] = { value: [] }; }],
    ['missing flow target', o => { o.flowLogs[x.watcherId].value.push({ id: x.watcherId + '/flowLogs/unit',
      type: 'Microsoft.Network/networkWatchers/flowLogs', properties: { enabled: false } }); }],
  ]) await t.test(name, () => {
    const changed = structuredClone(x.current.externalNsg); mutate(changed);
    assert.throws(() => verifyPrivateLinkNsgCurrent(f.c, f.context, changed, x.adoption.proposal.current.externalNsg));
  });
});

test('only exact reviewed external NSG delta is attributable; unrelated governance is not silently adopted', () => {
  const n = f.context.plan.topology.ids, snapshot = x.current;
  verifyPrivateLinkNsgDelta(f.c, f.context, snapshot, x.original.preflight.before);
  for (const change of [
    s => { s.resources[n.endpointSubnet].properties.routeTable = { id: 'UNIT-route' }; },
    s => { s.resources[n.appsSubnet].properties.networkSecurityGroup = { id: s.externalNsg.nsg.id }; },
    s => { s.resources[n.endpointSubnet].properties.privateEndpointNetworkPolicies = 'Enabled'; },
    s => { s.resources[n.account].properties.networkAcls.bypass = 'AzureServices'; },
    s => { s.lists.groupResources.value.push({ id: s.externalNsg.nsg.id + '-third', type: 'Microsoft.Network/networkSecurityGroups' }); },
    s => { s.resources[n.vnet].properties.resourceGuid = '20000000-0000-4000-8000-000000000002'; },
    s => { s.lists.subnets.value.find(v => v.id === n.endpointSubnet).properties.networkSecurityGroup.id += '-other'; },
    s => { s.resources[n.endpointSubnet].properties.unreviewed = true; },
  ]) {
    const changed = structuredClone(snapshot); change(changed);
    assert.throws(() => verifyPrivateLinkNsgDelta(f.c, f.context, changed, x.original.preflight.before));
  }
});

test('attribution requires successful writes, exact raw body lineage and independent home-tenant application pins', async t => {
  for (const [name, mutate] of [
    ['display name alone', p => { p.writer.response.appId = f.c.runId; }],
    ['wrong actor home tenant', p => { p.actor.homeTenantId = f.c.tenantId; }],
    ['home object mistaken for local SP', p => { p.actor.localServicePrincipalId = p.actor.homeObjectId; }],
    ['local disabled application', p => { p.writer.response.accountEnabled = false; }],
    ['wrong SP type', p => { p.writer.response.servicePrincipalType = 'ManagedIdentity'; }],
    ['missing NSG success', p => { p.nsgActivity.response.value = p.nsgActivity.response.value.filter(v => v.status.value !== 'Succeeded'); }],
    ['audit is not a deployment', p => { p.nsgActivity.response.value.forEach(v => { v.operationName.value = 'Microsoft.Authorization/policies/auditIfNotExists/action'; }); }],
    ['foreign actor', p => { p.vnetActivity.response.value.find(v => v.status.value === 'Succeeded').claims.appid = f.c.runId; }],
    ['top-level tenant conflicts with home claim', p => { p.nsgActivity.response.value[0].tenantId = f.c.tenantId; }],
    ['missing unattached NSG provenance', p => { p.unattachedNsgActivity.response.value = []; }],
    ['wrong request attachment', p => {
      const e = p.vnetActivity.response.value.find(v => v.status.value === 'Started'), body = JSON.parse(e.properties.requestbody);
      body.properties.subnets.find(v => v.id === f.context.plan.topology.ids.endpointSubnet).properties.networkSecurityGroup.id += '-other';
      e.properties.requestbody = json(body);
    }],
    ['changed accepted generation', p => {
      const e = p.nsgActivity.response.value.find(v => v.status.value === 'Accepted'), body = JSON.parse(e.properties.responseBody);
      body.properties.resourceGuid = f.c.runId; e.properties.responseBody = json(body);
    }],
    ['partial pages', p => { p.vnetActivity.response.nextLink = 'more'; }],
    ['foreign event', p => { p.nsgActivity.response.value[0].resourceId += '-other'; }],
    ['duplicate event', p => { p.nsgActivity.response.value.push(p.nsgActivity.response.value[0]); }],
    ['unsettled later write', p => {
      const event = structuredClone(p.vnetActivity.response.value.find(value => value.status.value === 'Started'));
      event.eventDataId = randomUUID(); event.correlationId = randomUUID(); p.vnetActivity.response.value.push(event);
    }],
    ['unretained body', p => { delete p.nsgActivity.response.value.find(v => v.status.value === 'Started').properties.requestbody; }],
  ]) await t.test(name, () => {
    const changed = structuredClone(x.provenance); mutate(changed);
    assert.throws(() => verifyPrivateLinkNsgProvenance(f.c, f.context, changed, x.current.externalNsg, x.original));
  });
});

test('source, exact adoption review, cost disclosure, pending intent and user-decision hashes cannot be substituted', () => {
  for (const mutate of [
    a => { a.review.sourceSha256 = digest('UNIT changed'); },
    a => { a.review.userDecision = 'UNIT substituted decision'; },
    a => { a.review.costDisclosure.zeroFeeProven = true; },
    a => { a.review.costDisclosure.unknownCostAccepted = false; },
    a => { a.proposal.original.journal.dispatchAttempted = null; },
    a => { a.proposal.pendingHead.intentSha256 = digest('UNIT other intent'); },
    a => { a.proposal.anchor.records = 5; },
    a => { a.review.expiresAt = a.adoptedAt; },
    a => { a.authority.nsgDetach = true; },
  ]) {
    const changed = structuredClone(x.adoption); mutate(changed);
    assert.throws(() => verifyPrivateLinkNsgAdoption(f.c, f.context, changed, x.evidence));
  }
});

test('verified NSG is known Ignore inventory only, never a native extra write', () => {
  const target = privateLinkNsgTarget(f.c, f.context), current = x.current;
  const known = privateLinkPreservedIds(f.c, f.context, current, x.adoption, x.evidence);
  assert(known.includes(target.id));
  assert(known.includes(x.unattachedNsg.id));
  assert(!privateLinkPreservedIds(f.c, f.context, current).includes(target.id));
  const phase = { deploymentId: 'UNIT', resources: [] }, raw = { status: 'Succeeded',
    changes: [{ resourceId: target.id, changeType: 'Ignore' }] };
  verifyPrivateLinkPreview(phase, raw, current, known);
  for (const changeType of ['Create', 'Modify', 'Delete']) assert.throws(() => verifyPrivateLinkPreview(phase,
    { ...raw, changes: [{ resourceId: target.id, changeType }] }, current, known));
});

test('verified two-NSG policy targets are available without serializing behind registry inventory', async () => {
  let finishRegistry, targetsReady;
  const registry = new Promise(resolve => { finishRegistry = resolve; });
  const targets = new Promise(resolve => { targetsReady = resolve; });
  const io = { ...x.io, registry: () => registry };
  const collection = collectPrivateLinkSnapshot(f.c, f.context, io, io.now() + 120000, targetsReady, { observeOnly: true });
  try {
    const ready = await targets;
    assert.equal(ready.externalNsg.nsg.id, x.nsg.id);
    assert.equal(ready.externalNsg.unattachedNsg.id, x.unattachedNsg.id);
    assert.deepEqual(ready.resources[f.context.plan.topology.ids.endpointSubnet].properties.networkSecurityGroup, { id: x.nsg.id });
  } finally { finishRegistry(x.current.images); }
  assert.equal((await collection).version, 2);
});

test('v3 adoption explicitly binds both attachments without reinterpreting v2 or qualifying ACA traffic', () => {
      const y = attached, mode = PRIVATE_LINK_NSG_ATTACHED_MODE, old = json(x.adoption);
      verifyPrivateLinkNsgAdoption(y.f.c, y.f.context, y.adoption, y.evidence);
      verifyPrivateLinkSnapshot(y.f.c, y.f.context, y.current, 'create-queue-endpoint', 2, y.adoption, y.evidence);
      assert.equal(y.adoption.version, 3); assert.equal(y.adoption.attachmentMode, mode);
      assert.equal(y.review.attachmentMode, mode); assert.equal(y.review.pins.targets.apps.subnet, y.f.context.plan.topology.ids.appsSubnet);
      assert.equal(y.review.pins.acaCompatibility.platformTrafficQualified, false);
      assert.equal(y.review.pins.acaCompatibility.environmentProvisioningRequired, true);
      assert.equal(y.review.pins.acaCompatibility.runtimeQualificationRequired, true);
      assert.equal(y.adoption.authority.nsgAttach, false);
      assert.equal(y.provenance.vnetActivity.response.value.length, x.provenance.vnetActivity.response.value.length);
      assert(y.proposal.attribution.appsAttachment);
      assert.throws(() => verifyPrivateLinkNsgCurrent(y.f.c, y.f.context, y.current.externalNsg, x.current.externalNsg), /MODE_CHANGED/);
      assert.throws(() => verifyPrivateLinkSnapshot(y.f.c, y.f.context, y.current, 'create-queue-endpoint', 2, x.adoption, x.evidence));
      verifyPrivateLinkNsgAdoption(f.c, f.context, x.adoption, x.evidence);
      assert.equal(json(x.adoption), old);
    });

test('v3 rejects detach, swapped/extra attachments, rules/exports, unreviewed modes and ACA configuration drift', async t => {
      const y = attached, c = y.f.c, context = y.f.context, n = context.plan.topology.ids;
      for (const [name, mutate] of [
        ['Apps detached', s => { s.externalNsg.appsNsg.properties.subnets = []; }],
        ['Apps bound to endpoint subnet', s => { s.externalNsg.appsNsg.properties.subnets[0].id = n.endpointSubnet; }],
        ['PE bound to Apps subnet', s => { s.externalNsg.nsg.properties.subnets[0].id = n.appsSubnet; }],
        ['third attachment', s => { s.externalNsg.appsNsg.properties.subnets.push({ id: n.appsSubnet + '-other' }); }],
        ['custom Apps rule', s => { s.externalNsg.appsNsg.properties.securityRules.push({ name: 'UNIT additional' }); }],
        ['default egress deny', s => { s.externalNsg.appsNsg.properties.defaultSecurityRules.find(value => value.name === 'AllowInternetOutBound').properties.access = 'Deny'; }],
        ['new Apps generation', s => { s.externalNsg.appsNsg.properties.resourceGuid = randomUUID(); }],
        ['Apps diagnostics', s => { s.externalNsg.appsDiagnostics.value.push({ id: 'UNIT export' }); }],
        ['Apps targeted flow logs', s => { s.externalNsg.flowLogs[y.watcherId].value.push({ id: y.watcherId + '/flowLogs/unit',
          type: 'Microsoft.Network/networkWatchers/flowLogs', properties: { enabled: false, targetResourceId: s.externalNsg.appsNsg.id } }); }],
        ['missing explicit mode', s => { delete s.externalNsg.attachmentMode; }],
        ['unknown mode', s => { s.externalNsg.attachmentMode = 'auto'; }],
        ['unattached slot in v3', s => { s.externalNsg.unattachedNsg = s.externalNsg.appsNsg; delete s.externalNsg.appsNsg; }],
        ['Apps direct read detached', s => { delete s.resources[n.appsSubnet].properties.networkSecurityGroup; }],
        ['Apps VNet copy detached', s => { delete s.resources[n.vnet].properties.subnets.find(value => value.id === n.appsSubnet).properties.networkSecurityGroup; }],
        ['Apps subnet list swapped', s => { s.lists.subnets.value.find(value => value.id === n.appsSubnet).properties.networkSecurityGroup.id = y.nsg.id; }],
        ['route table', s => { s.resources[n.appsSubnet].properties.routeTable = { id: 'UNIT unreviewed' }; }],
        ['changed delegation', s => { s.resources[n.appsSubnet].properties.delegations[0].properties.serviceName = 'Microsoft.Web/serverFarms'; }],
        ['changed subnet network policies', s => { s.resources[n.appsSubnet].properties.privateEndpointNetworkPolicies = 'Enabled'; }],
      ]) await t.test(name, () => {
        const changed = structuredClone(y.current); mutate(changed);
        assert.throws(() => verifyPrivateLinkSnapshot(c, context, changed, 'create-queue-endpoint', 2, y.adoption, y.evidence));
      });
      const changed = structuredClone(context);
      changed.plan.stages.find(value => value.id === 'create-environment').resources[0].expected.properties.workloadProfiles[0].workloadProfileType = 'D4';
      assert.throws(() => verifyPrivateLinkNsgAcaCompatibility(c, changed, y.current), /CONFIGURATION_INCOMPATIBLE/);
    });

test('attached mode requires fresh explicit review and exact later governance actor/body lineage', async t => {
      const y = attached;
      for (const [name, mutate] of [
        ['v2 review', value => { value.review = structuredClone(x.review); }],
        ['mode removed', value => { delete value.attachmentMode; }],
        ['mode changed only on proposal', value => { value.proposal.attachmentMode = 'endpoint-only-apps-unattached'; }],
        ['ACA traffic claim', value => { value.review.pins.acaCompatibility.platformTrafficQualified = true; }],
        ['association write authority', value => { value.authority.nsgAttach = true; }],
        ['missing fresh attachment capture', value => { delete value.proposal.provenance.appsAttachmentActivity; }],
        ['prior actor is insufficient', value => { value.proposal.provenance.appsAttachmentActivity.response.value[0].claims.appid = randomUUID(); }],
        ['only success is insufficient', value => { value.proposal.provenance.appsAttachmentActivity.response.value =
          value.proposal.provenance.appsAttachmentActivity.response.value.filter(event => event.status.value === 'Succeeded'); }],
        ['later attachment body changed', value => {
          const event = value.proposal.provenance.appsAttachmentActivity.response.value.find(event => event.status.value === 'Started');
          const body = JSON.parse(event.properties.requestbody);
          body.properties.subnets.find(value => value.id === y.f.context.plan.topology.ids.appsSubnet).properties.networkSecurityGroup.id += '-other';
          event.properties.requestbody = json(body);
        }],
        ['expired exact review', value => { value.review.expiresAt = value.adoptedAt; }],
        ['user decision substituted', value => { value.review.userDecision = 'UNIT different authority'; }],
      ]) await t.test(name, () => {
        const value = structuredClone(y.adoption); mutate(value);
        assert.throws(() => verifyPrivateLinkNsgAdoption(y.f.c, y.f.context, value, y.evidence));
      });
});

test('concrete read-only adoption routes preserve the original journal and pending head in separate canonical directories', async t => {
      const suffix = randomUUID().slice(0, 8), root = 'infrastructure/arm/telemetry/.operator-private';
      const oldArg = `${root}/revision-20261001-nsg-old-${suffix}`, newArg = `${root}/revision-20261001-nsg-new-${suffix}`;
      const oldDirectory = await privateDirectory(oldArg), directory = await privateDirectory(newArg);
      t.after(async () => { await rm(oldDirectory, { recursive: true }); await rm(directory, { recursive: true }); });
      await mkdir('infrastructure/opentofu/telemetry/.operator-private', { recursive: true, mode: 0o700 });
      await saveImmutable(oldDirectory, 'private-link-create-environment-journal.json', x.original.journal);
      const key = privateLinkTargetKey(f.context), pending = x.proposal.pendingHead;
      const canonical = new Map([
        [`private-link-head-${key}.json`, pending],
        [`private-link-fence-${key}.json`, { version: 1, targetKey: key, stage: 'create-environment',
          intentSha256: hash(x.original.intent), phase: x.original.phase, intent: x.original.intent }],
        [`private-link-intent-${hash({ target: key, stage: 'create-environment' })}.json`, { phase: x.original.phase, intent: x.original.intent }],
      ]);
      const calls = [], invoke = retainedReadInvoke(f, x.current, x.io.read, x.provenance.writer.response);
      const options = { invoke: async args => { calls.push(args); return invoke(args); }, now: x.io.now,
        sourceDigest: async () => f.source, lookup: retainedSourceLookup(f.context, x.evidence, x.original),
        store: { root: directory, read: async (_root, name) => structuredClone(canonical.get(name) ?? null),
          saveImmutable: async (_root, name, value) => { assert(!canonical.has(name)); canonical.set(name, structuredClone(value)); } } };
      const common = { original: x.original, originalDirectory: oldArg, publication: x.io.publication, policyRevision: null,
        costReview: x.proposal.costReview, costEvidence: x.proposal.costEvidence, migrationReview: x.proposal.migrationReview };
      await assert.rejects(runPrivateLinkNsgAdoption(f.c, f.context, x.evidence, 'observe-nsg-adoption', newArg,
        { ...common, provenance: x.provenance, options: { skipValidation: true } }, options), /CLOSED_INPUT_REQUIRED/);
      await assert.rejects(runPrivateLinkNsgAdoption(f.c, f.context, x.evidence, 'observe-nsg-adoption', newArg,
        { ...common, originalDirectory: resolve(oldDirectory), provenance: x.provenance }, options), /PRIVATE_CANONICAL_DIRECTORY_REQUIRED/);
      const proposal = await runPrivateLinkNsgAdoption(f.c, f.context, x.evidence, 'observe-nsg-adoption', newArg,
        { ...common, provenance: x.provenance }, options);
      const review = { ...x.review, proposalSha256: hash(proposal), pins: privateLinkNsgAdoptionPins(f.c, f.context, proposal) };
      const adoption = await runPrivateLinkNsgAdoption(f.c, f.context, x.evidence, 'adopt-nsg', newArg,
        { ...common, proposal, review }, options);
      assert.deepEqual(await load(oldDirectory, 'private-link-create-environment-journal.json'), x.original.journal);
      assert.deepEqual(canonical.get(`private-link-head-${key}.json`), pending);
      assert.deepEqual(canonical.get(`private-link-nsg-adoption-${key}.json`), adoption);
      const wrapped = await load(directory, 'private-link-nsg-adopted-evidence.json');
      assert.equal(wrapped.version, 2); assert.equal(json(wrapped.records), json(x.evidence.records));
      await readPrivateLinkHead(f.context, wrapped, { ...options.store, pending });
      const noSubmission = await runPrivateLinkControl(f.c, f.context, wrapped, 'create-environment', 'reconcile', newArg, common, options);
      const recoveryReview = { version: 1, action: 'record-exact-private-link-no-submission-without-replay',
        proposalSha256: hash(noSubmission), sourceSha256: f.source, pendingHeadSha256: hash(pending),
        approvedAt: new Date(x.io.now()).toISOString(), expiresAt: new Date(x.io.now() + 600000).toISOString() };
      const resolved = await runPrivateLinkControl(f.c, f.context, wrapped, 'create-environment', 'recover', newArg,
        { ...common, proposal: noSubmission, recoveryReview }, options);
      assert.equal(resolved.version, 2); assert.equal(resolved.resumable, false);
      assert.deepEqual(canonical.get(`private-link-head-${key}.json`), pending);
      assert.deepEqual(await load(oldDirectory, 'private-link-create-environment-journal.json'), x.original.journal);
      canonical.delete(`private-link-nsg-adoption-${key}.json`);
      await assert.rejects(readPrivateLinkHead(f.context, wrapped, { ...options.store, pending }), /CANONICAL_ADOPTION_REQUIRED/);
      assert(calls.every(args => ['account', 'acr', 'ad'].includes(args[0]) ||
        (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET')));
});

test('concrete read adapter permits only enumerated same-subscription regional watcher flow-log reads', async t => {
  const directory = `infrastructure/arm/telemetry/tests/.private-link-nsg-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const calls = [], now = x.io.now(), watcherList = `${ids(f.c).sub}/providers/Microsoft.Network/networkWatchers`;
  const io = privateLinkReadIO(f.c, f.context, directory, async args => {
    const method = args[args.indexOf('--method') + 1], url = new URL(args[args.indexOf('--url') + 1]);
    assert.equal(method, 'GET'); calls.push(url.pathname);
    if (url.pathname === watcherList) return structuredClone(x.watchers);
    if (url.pathname === x.watcherId + '/flowLogs') return { value: [] };
    assert.fail('Unreviewed read');
  }, { now: () => now });
  const flow = { id: x.watcherId + '/flowLogs', apiVersion: '2024-05-01', filter: null };
  await assert.rejects(io.read(flow, now + 120000, true), /READ_SCOPE_FORBIDDEN/);
  await io.read({ id: watcherList, apiVersion: '2024-05-01', filter: null }, now + 120000, true);
  await io.read(flow, now + 120000, true);
  await assert.rejects(io.read({ ...flow, id: x.watcherId + '-other/flowLogs' }, now + 120000, true), /READ_SCOPE_FORBIDDEN/);
  assert.equal(calls.length, 2);
});
