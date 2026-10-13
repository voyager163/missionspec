import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { analyzeEffectivePolicies } from '../effective-policy.mjs';
import { PRIVATE_LINK_CONTROL_STAGES, privateLinkPhase, verifyPrivateLinkEnvironmentWire, verifyPrivateLinkPlan } from '../private-link.mjs';
import { preparePrivateLinkPhase, verifyPrivateLinkPreview, verifyPrivateLinkApproval,
  verifyPrivateLinkControlEvidence, checkPrivateLinkPhase, executePrivateLinkPhase } from '../private-link-controller.mjs';
import { verifyPrivateLinkEnvironmentNoLogs, verifyPrivateLinkSnapshot } from '../private-link-readback.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness, privateSnapshotFixture } from './private-link.fixture.mjs';

const hash = value => digest(json(value));
const fixture = await privateLinkFixture({ ...privateInput, version: 2 });
const legacy = privateLinkPhase(fixture.c, fixture.context, 'create-environment', 1);
const current = privateLinkPhase(fixture.c, fixture.context, 'create-environment');
const nullLogs = { destination: null, logAnalyticsConfiguration: null };
function preview(phase, omitted = true) {
  // Synthetic copy of the captured native response shape, never live IDs or authority.
  const after = { ...structuredClone(phase.resources[0].expected), id: phase.resources[0].id };
  if (omitted) delete after.properties.appLogsConfiguration;
  return { status: 'Succeeded', changes: [
    { resourceId: fixture.context.plan.topology.ids.oldApp, changeType: 'Ignore' },
    { resourceId: phase.resources[0].id, changeType: 'Create', after },
    { resourceId: fixture.context.plan.topology.ids.oldEnvironment, changeType: 'Ignore' },
  ] };
}
const preserved = [fixture.context.plan.topology.ids.oldApp, fixture.context.plan.topology.ids.oldEnvironment];

test('current phase-2 no-export wire changes no immutable plan, topology, source or earlier phase bytes', () => {
  const before = json(fixture.context), planned = fixture.context.plan.stages.find(value => value.id === 'create-environment');
  assert.equal(legacy.version, 1); assert.equal(legacy.wireProjection, undefined);
  assert.deepEqual(legacy.request, planned.proposedRequest);
  assert.deepEqual(legacy.resources, planned.resources);
  assert.equal(legacy.resources[0].expected.properties.appLogsConfiguration.destination, 'none');
  assert.equal(current.version, 2);
  assert.deepEqual(current.wireProjection, { version: 1, kind: 'aca-no-log-export-explicit-null',
    plannedRequestSha256: hash(planned.proposedRequest) });
  for (const resource of [current.resources[0].expected, current.template.resources[0], current.request.body.properties.template.resources[0]]) {
    assert.deepEqual(resource.properties.appLogsConfiguration, nullLogs);
  }
  const projectedBack = structuredClone(current);
  projectedBack.version = 1; delete projectedBack.wireProjection;
  projectedBack.resources[0].expected.properties.appLogsConfiguration = { destination: 'none' };
  projectedBack.request.body.properties.template.resources[0].properties.appLogsConfiguration = { destination: 'none' };
  projectedBack.template.resources[0].properties.appLogsConfiguration = { destination: 'none' };
  assert.deepEqual(projectedBack, legacy);
  assert.notEqual(hash(current), hash(legacy)); assert.notEqual(hash(current.request), hash(legacy.request));
  assert.equal(current.planSha256, legacy.planSha256); assert.equal(current.contextSha256, legacy.contextSha256);
  assert.equal(current.deploymentId, legacy.deploymentId);
  for (const stage of PRIVATE_LINK_CONTROL_STAGES.filter(value => value !== 'create-environment')) {
    assert.deepEqual(privateLinkPhase(fixture.c, fixture.context, stage), privateLinkPhase(fixture.c, fixture.context, stage, 1));
    assert.throws(() => privateLinkPhase(fixture.c, fixture.context, stage, 2), /WIRE_VERSION_UNSUPPORTED/);
  }
  assert.throws(() => privateLinkPhase(fixture.c, fixture.context, 'create-environment', 3), /WIRE_VERSION_UNSUPPORTED/);
  verifyPrivateLinkEnvironmentWire(current);
  verifyPrivateLinkPlan(fixture.c, fixture.context.origin, fixture.context.plan, fixture.source);
  assert.equal(json(fixture.context), before);
});

test('captured null-bag omission is accepted only for the exact phase-2 null projection and preserves raw evidence', async t => {
  for (const omitted of [false, true]) {
    const value = preview(current, omitted), original = json(value);
    assert.equal(verifyPrivateLinkPreview(current, value, {}, preserved), digest(original));
    assert.equal(json(value), original);
  }
  assert.throws(() => verifyPrivateLinkPreview(legacy, preview(legacy), {}, preserved), /WHATIF/);
  const scenarios = [
    ['literal none', value => { value.changes[1].after.properties.appLogsConfiguration = { destination: 'none' }; }],
    ['azure monitor', value => { value.changes[1].after.properties.appLogsConfiguration = { destination: 'azure-monitor' }; }],
    ['log analytics', value => { value.changes[1].after.properties.appLogsConfiguration = { destination: 'log-analytics' }; }],
    ['whole bag null', value => { value.changes[1].after.properties.appLogsConfiguration = null; }],
    ['empty bag', value => { value.changes[1].after.properties.appLogsConfiguration = {}; }],
    ['partial present bag', value => { value.changes[1].after.properties.appLogsConfiguration = { destination: null }; }],
    ['nested destination', value => { value.changes[1].after.properties.appLogsConfiguration = { ...nullLogs, logAnalyticsConfiguration: { customerId: 'UNIT' } }; }],
    ['extra field', value => { value.changes[1].after.properties.appLogsConfiguration = { ...nullLogs, extra: null }; }],
    ['other property omitted', value => { delete value.changes[1].after.properties.zoneRedundant; }],
    ['wrong API', value => { value.changes[1].after.apiVersion = '2024-01-01'; }],
    ['extra resource', value => { value.changes.push({ resourceId: current.resources[0].id + '-other', changeType: 'Create', after: {} }); }],
  ];
  for (const [name, change] of scenarios) await t.test(name, () => {
    const value = preview(current); change(value);
    const original = json(value);
    assert.throws(() => verifyPrivateLinkPreview(current, value, {}, preserved));
    assert.equal(json(value), original);
  });
  for (const change of [
    p => { p.version = 1; }, p => { delete p.wireProjection; },
    p => { p.wireProjection.plannedRequestSha256 = digest('UNIT altered intent'); },
    p => { p.stage = 'create-network'; }, p => { p.resources[0].id += '-other'; },
    p => { p.request.body.properties.template.resources[0].properties.appLogsConfiguration.destination = 'azure-monitor'; },
    p => { p.resources[0].expected.properties.appLogsConfiguration = { destination: null }; },
  ]) {
    const p = structuredClone(current); change(p);
    assert.throws(() => verifyPrivateLinkPreview(p, preview(current), {}, preserved));
  }
});

test('current actual readback accepts explicit no-export nulls only and rejects destinations, keys and diagnostics', async t => {
  const id = fixture.context.plan.topology.ids.environment;
  for (const logs of [nullLogs, { destination: null }]) {
    const snapshot = privateSnapshotFixture(fixture, 'create-environment');
    snapshot.resources[id].properties.appLogsConfiguration = structuredClone(logs);
    const before = json(snapshot);
    verifyPrivateLinkSnapshot(fixture.c, fixture.context, snapshot, 'create-environment');
    assert.equal(json(snapshot), before);
  }
  for (const [name, logs] of [
    ['missing bag', undefined], ['null bag', null], ['empty bag', {}],
    ['legacy sentinel is not current wire', { destination: 'none' }], ['empty destination', { destination: '' }],
    ['monitor', { destination: 'azure-monitor', logAnalyticsConfiguration: null }],
    ['analytics', { destination: 'log-analytics', logAnalyticsConfiguration: null }],
    ['customer', { destination: null, logAnalyticsConfiguration: { customerId: 'UNIT' } }],
    ['shared key', { destination: null, logAnalyticsConfiguration: { sharedKey: 'UNIT-not-a-secret' } }],
    ['empty analytics object', { destination: null, logAnalyticsConfiguration: {} }],
    ['unknown field', { destination: null, extra: null }],
    ['false destination', { destination: false }], ['undefined destination', { destination: undefined }],
  ]) await t.test(name, () => assert.throws(() => verifyPrivateLinkEnvironmentNoLogs(logs), /LOGGING_OR_DOMAIN_DRIFT/));
  for (const change of [
    s => { s.diagnostics[id].value.push({ id: `${id}/providers/Microsoft.Insights/diagnosticSettings/UNIT` }); },
    s => { s.resources[id].properties.openTelemetryConfiguration = { destination: 'UNIT' }; },
    s => { s.resources[id].properties.appInsightsConfiguration = {}; },
  ]) {
    const snapshot = privateSnapshotFixture(fixture, 'create-environment'); change(snapshot);
    assert.throws(() => verifyPrivateLinkSnapshot(fixture.c, fixture.context, snapshot, 'create-environment'));
  }
  verifyPrivateLinkEnvironmentNoLogs({ destination: 'none' }, 1);
  assert.throws(() => verifyPrivateLinkEnvironmentNoLogs(nullLogs, 1));
});

test('current execution and immutable legacy record verification bind their own wire/body/preview hashes', async () => {
  const f = { ...fixture }, evidence = await privateControlChain(f, 'create-queue-endpoint');
  const before = json(evidence), context = json(f.context), q = await privateControlHarness(f, evidence, 'create-environment');
  assert.equal(q.phase.version, 2);
  assert.equal(q.approval.phaseSha256, hash(q.phase)); assert.equal(q.approval.requestSha256, hash(q.phase.request));
  const oldPhase = preparePrivateLinkPhase(f.c, f.context, evidence, 'create-environment', null, null, 1);
  assert.throws(() => preparePrivateLinkPhase(f.c, f.context, evidence, 'create-environment', null,
    { resolution: { original: { phase: oldPhase } } }), /CONTINUATION_WIRE_CHANGED/);
  assert.throws(() => verifyPrivateLinkApproval(f.c, f.context, oldPhase, q.proof, q.approval, f.at), /EXACT_APPROVAL_REQUIRED/);
  await assert.rejects(checkPrivateLinkPhase(f.c, f.context, evidence, oldPhase, q.io), /PREPARED_PHASE_CHANGED/);
  await assert.rejects(executePrivateLinkPhase(f.c, f.context, evidence, oldPhase, q.proof, q.approval, q.io), /PREPARED_PHASE_CHANGED/);
  assert.equal(q.writes, 0);
  const record = await q.execute();
  verifyPrivateLinkControlEvidence(f.c, f.context, { ...evidence, records: [...evidence.records, record] }, f.at);
  assert.equal(q.writes, 1);
  assert.equal(json(evidence), before); assert.equal(json(f.context), context);

  // Independent synthetic phase-1 record, not a rewritten live receipt.
  const archived = structuredClone(record), oldPreview = preview(oldPhase, false);
  archived.phase = oldPhase;
  archived.preflight.phaseSha256 = hash(oldPhase);
  archived.preflight.preview = oldPreview;
  archived.preflight.policy = analyzeEffectivePolicies(oldPhase, archived.preflight.policy.snapshot);
  archived.preflight.validation.properties.templateHash = hash(oldPhase.template);
  Object.assign(archived.preflight.binding, { phaseSha256: hash(oldPhase), previewSha256: hash(oldPreview),
    policySha256: hash(archived.preflight.policy), validationSha256: hash(archived.preflight.validation) });
  Object.assign(archived.approval, { phaseSha256: hash(oldPhase), requestSha256: hash(oldPhase.request),
    bindingSha256: hash(archived.preflight.binding) });
  Object.assign(archived.intent, { phaseSha256: hash(oldPhase), requestSha256: hash(oldPhase.request),
    approvalSha256: hash(archived.approval) });
  archived.intentSha256 = hash(archived.intent); archived.journal.intentSha256 = archived.intentSha256;
  archived.deployment.properties.templateHash = hash(oldPhase.template);
  archived.after.resources[f.context.plan.topology.ids.environment].properties.appLogsConfiguration = { destination: 'none' };
  const history = { ...evidence, records: [...evidence.records, archived] }, archivedBytes = json(history);
  verifyPrivateLinkControlEvidence(f.c, f.context, history, f.at);
  assert.equal(json(history), archivedBytes);
  const next = preparePrivateLinkPhase(f.c, f.context, history, 'disable-storage-public');
  assert.equal(next.version, 1); assert.equal(next.predecessorSha256, hash(archived));
  assert.equal(json(history), archivedBytes);
});
