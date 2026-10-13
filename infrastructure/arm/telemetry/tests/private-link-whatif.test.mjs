import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { digest, json, ids, ownerTags } from '../definition.mjs';
import { whatIfRequestContext } from '../controller.mjs';
import { PRIVATE_LINK_WHATIF_STAGES, PRIVATE_LINK_RUNTIME_SUFFIXES } from '../private-link-whatif.mjs';
import { baseFixture } from './durable-queue.fixture.mjs';

const f = baseFixture(), r = ids(f.c);
function control(stage) {
  const scope = stage === 'create-queue-role' ? r.sub : r.group;
  const expected = { type: 'Microsoft.Network/virtualNetworks', apiVersion: '2024-05-01',
    name: 'unit-private-network', location: f.c.location, properties: { addressSpace: { addressPrefixes: ['10.240.8.0/24'] } } };
  const deploymentId = `${scope}/providers/Microsoft.Resources/deployments/${f.c.namePrefix}-pl-123456789abc-${PRIVATE_LINK_WHATIF_STAGES[stage]}`;
  const template = { $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
    contentVersion: '1.0.0.0', resources: [expected] };
  return { version: 1, kind: 'fixed-private-link-control-phase', phase: `private-link-${stage}`, stage,
    planSha256: digest('UNIT plan'), contextSha256: digest('UNIT context'),
    request: { method: 'PUT', id: deploymentId, apiVersion: '2022-09-01',
      body: { ...(scope === r.sub ? { location: f.c.location } : {}), properties: { mode: 'Incremental', template } } },
    resources: [{ id: `${r.group}/providers/Microsoft.Network/virtualNetworks/unit-private-network`,
      type: expected.type, apiVersion: expected.apiVersion, expected }], scope, deploymentId, template, rolloutMs: 120000 };
}
function noLogControl() {
  const phase = control('create-environment');
  const expected = { type: 'Microsoft.App/managedEnvironments', apiVersion: '2025-07-01',
    name: `${f.c.namePrefix}-private-environment`, location: f.c.location,
    properties: { appLogsConfiguration: { destination: 'none' } } };
  phase.template.resources = [expected];
  phase.resources = [{ id: `${r.group}/providers/Microsoft.App/managedEnvironments/${expected.name}`,
    type: expected.type, apiVersion: expected.apiVersion, expected }];
  const plannedRequestSha256 = digest(json(phase.request));
  expected.properties.appLogsConfiguration = { destination: null, logAnalyticsConfiguration: null };
  return { ...phase, version: 2, wireProjection: { version: 1, kind: 'aca-no-log-export-explicit-null', plannedRequestSha256 } };
}
function runtime(action) {
  const instance = '00000000-0000-4000-8000-000000000099';
  const publicProbe = action === 'create-public-probe';
  const app = { type: 'Microsoft.App/containerApps', apiVersion: '2025-07-01',
    name: `${f.c.namePrefix}-${publicProbe ? 'public-probe' : 'private-ingest'}`, location: f.c.location, tags: ownerTags(f.c),
    properties: {
      managedEnvironmentId: publicProbe ? r.environment
        : `${r.group}/providers/Microsoft.App/managedEnvironments/${f.c.namePrefix}-private-environment`,
      template: { containers: [{ env: [{ name: 'MSR_INGESTION_ENABLED', value: String(action === 'enable') }] }] },
    } };
  return { version: 1, kind: 'fixed-private-link-runtime-phase', phase: `private-link-runtime-${action}`, action,
    windowInstanceId: instance, predecessorSha256: digest('UNIT predecessor'), targetSha256: digest('UNIT target'),
    request: { id: `${r.group}/providers/Microsoft.Resources/deployments/${f.c.namePrefix}-plr-${instance.replaceAll('-', '')}-${PRIVATE_LINK_RUNTIME_SUFFIXES[action]}`,
      body: { properties: { mode: 'Incremental', template: {
        $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
        contentVersion: '1.0.0.0', resources: [app],
      } } } } };
}

test('Private Link what-if binds fixed control stages, exact scope and whole static request', async () => {
  const cases = Object.keys(PRIVATE_LINK_WHATIF_STAGES).map(stage => {
    const phase = control(stage), context = whatIfRequestContext(f.c, phase);
    assert.equal(context.scope, stage === 'create-queue-role' ? 'subscription' : 'group');
    assert.equal(context.phaseSha256, digest(json(phase)));
    assert.equal(context.bodySha256, digest(context.body));
    assert.equal(context.migrationKey, '123456789abc');
    assert.equal(context.migrationPlanSha256, phase.planSha256);
    assert.equal(context.windowInstanceId, null);
    return { context, expected: phase.deploymentId.split('/').at(-1) };
  });
  const script = `import importlib.util,json,sys,hashlib
s=importlib.util.spec_from_file_location("bridge","infrastructure/arm/telemetry/arm-whatif.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for case in json.loads(sys.argv[1]):
 r=case["context"]
 assert m.fixed_deployment_name(r)==case["expected"]
 fields=("subscriptionId","tenantId","location","namePrefix","runId","phase","scope","phaseSha256","bodySha256","windowInstanceId","predecessorSha256","migrationKey","migrationPlanSha256","migrationContextSha256")
 assert hashlib.sha256("\\n".join("" if r[k] is None else str(r[k]) for k in fields).encode()).hexdigest()==r["contextSha256"]
print("PRIVATE_LINK_NAMES_AND_CONTEXT_MATCH_NO_AUTH")`;
  const result = await promisify(execFile)('python3', ['-I', '-B', '-c', script, JSON.stringify(cases)], { timeout: 10000 });
  assert.equal(result.stdout.trim(), 'PRIVATE_LINK_NAMES_AND_CONTEXT_MATCH_NO_AUTH');
});

test('Private Link what-if cannot spoof an old phase, another deployment, request body or expression', () => {
  for (const change of [
    p => { p.deploymentId += '-other'; }, p => { p.scope = r.stateGroup; },
    p => { p.stage = 'retire-nsp-rule'; }, p => { p.phase = 'core'; },
    p => { p.request.method = 'DELETE'; }, p => { p.request.apiVersion = '2025-09-01'; },
    p => { p.request.body.properties.mode = 'Complete'; }, p => { p.request.id = r.app; },
    p => { p.template.resources.push({ type: 'UNIT unknown' }); },
    p => { p.template.resources[0].properties.unreviewed = '[listKeys()]'; },
    p => { p.template.templateLink = { uri: 'https://foreign.invalid' }; },
    p => { p.planSha256 = 'missing'; }, p => { p.contextSha256 = null; },
    p => { p.windowInstanceId = f.c.runId; },
  ]) {
    const phase = structuredClone(control('create-network')); change(phase);
    assert.throws(() => whatIfRequestContext(f.c, phase));
  }
});

test('no-log execution-wire version is closed and bound to the unchanged planned request', () => {
  const phase = noLogControl(), context = whatIfRequestContext(f.c, phase);
  assert.equal(context.phaseSha256, digest(json(phase)));
  assert.deepEqual(JSON.parse(context.body).properties.template.resources[0].properties.appLogsConfiguration,
    { destination: null, logAnalyticsConfiguration: null });
  for (const change of [
    p => { p.version = 1; }, p => { p.version = 3; }, p => { p.stage = 'create-network'; },
    p => { p.wireProjection.plannedRequestSha256 = 'a'.repeat(64); },
    p => { p.wireProjection.extra = false; },
    p => { p.resources[0].expected.properties.appLogsConfiguration.destination = 'azure-monitor'; },
    p => { p.resources[0].expected.properties.appLogsConfiguration.logAnalyticsConfiguration = {}; },
    p => { p.resources[0].expected.apiVersion = '2025-01-01'; },
  ]) {
    const changed = structuredClone(phase); change(changed);
    assert.throws(() => whatIfRequestContext(f.c, changed));
  }
});

test('Private Link runtime what-if binds fixed app roles and distinct UUID-controlled operation names', async () => {
  const contexts = Object.keys(PRIVATE_LINK_RUNTIME_SUFFIXES).map(action => {
    const phase = runtime(action), context = whatIfRequestContext(f.c, phase);
    assert.equal(context.runtimeTargetSha256, phase.targetSha256);
    assert.equal(context.windowInstanceId, phase.windowInstanceId);
    assert.equal(context.predecessorSha256, phase.predecessorSha256);
    assert.equal(context.scope, 'group');
    return { context, expected: phase.request.id.split('/').at(-1) };
  });
  assert.equal(new Set(contexts.map(value => value.expected)).size, 4);
  const script = `import importlib.util,json,sys,hashlib
s=importlib.util.spec_from_file_location("bridge","infrastructure/arm/telemetry/arm-whatif.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for case in json.loads(sys.argv[1]):
 r=case["context"]
 assert m.fixed_deployment_name(r)==case["expected"]
 fields=("subscriptionId","tenantId","location","namePrefix","runId","phase","scope","phaseSha256","bodySha256","windowInstanceId","predecessorSha256","runtimeTargetSha256")
 assert hashlib.sha256("\\n".join("" if r[k] is None else str(r[k]) for k in fields).encode()).hexdigest()==r["contextSha256"]
print("PRIVATE_RUNTIME_NAMES_MATCH_NO_AUTH")`;
  const result = await promisify(execFile)('python3', ['-I', '-B', '-c', script, JSON.stringify(contexts)], { timeout: 10000 });
  assert.equal(result.stdout.trim(), 'PRIVATE_RUNTIME_NAMES_MATCH_NO_AUTH');
});

test('runtime what-if rejects wrong scope, old app, duplicate flags, source drift and target substitution', () => {
  for (const change of [
    p => { p.windowInstanceId = f.c.runId; }, p => { p.windowInstanceId = 'unbound'; },
    p => { p.targetSha256 = null; }, p => { p.predecessorSha256 = 'not-a-hash'; },
    p => { p.request.id += '-new'; }, p => { p.action = 'unknown'; },
    p => { p.request.body.properties.template.resources[0].name = `${f.c.namePrefix}-ingest`; },
    p => { p.request.body.properties.template.resources[0].properties.managedEnvironmentId = r.environment; },
    p => { p.request.body.properties.template.resources[0].properties.template.containers[0].env[0].value = 'false'; },
    p => { p.request.body.properties.template.resources[0].properties.template.containers[0].env.push({ name: 'MSR_INGESTION_ENABLED', value: 'true' }); },
    p => { p.request.body.properties.template.resources[0].tags.unreviewed = 'allowed'; },
    p => { p.request.body.properties.template.resources.push({ type: 'UNIT extra' }); },
  ]) {
    const phase = runtime('enable'); change(phase);
    assert.throws(() => whatIfRequestContext(f.c, phase));
  }
});

test('public probe what-if cannot enable ingestion, modify the old app or select a different environment', () => {
  for (const change of [
    p => { p.request.body.properties.template.resources[0].name = `${f.c.namePrefix}-ingest`; },
    p => { p.request.body.properties.template.resources[0].name = `${f.c.namePrefix}-private-ingest`; },
    p => { p.request.body.properties.template.resources[0].properties.managedEnvironmentId =
      `${r.group}/providers/Microsoft.App/managedEnvironments/${f.c.namePrefix}-private-environment`; },
    p => { p.request.body.properties.template.resources[0].properties.template.containers[0].env[0].value = 'true'; },
    p => { p.request.body.properties.template.resources[0].properties.template.containers[0].env.push(
      { name: 'MSR_INGESTION_ENABLED', value: 'false' }); },
    p => { p.action = 'enable'; p.phase = 'private-link-runtime-enable';
      p.request.id = p.request.id.slice(0, -1) + 'e'; },
  ]) {
    const phase = runtime('create-public-probe'); change(phase);
    assert.throws(() => whatIfRequestContext(f.c, phase), /FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED/);
  }
  const phase = runtime('enable');
  phase.request.body.properties.template.resources[0].name = `${f.c.namePrefix}-public-probe`;
  phase.request.body.properties.template.resources[0].properties.managedEnvironmentId = r.environment;
  assert.throws(() => whatIfRequestContext(f.c, phase), /FIXED_PRIVATE_LINK_RUNTIME_WHATIF_REQUIRED/);
});

test('Python bridge version branches are closed, context-bound and reject cross-family requests before authentication', async () => {
  const cases = [
    ...Object.keys(PRIVATE_LINK_WHATIF_STAGES).map(stage => ({ version: 3, ...whatIfRequestContext(f.c, control(stage)) })),
    { version: 3, ...whatIfRequestContext(f.c, noLogControl()) },
    ...Object.keys(PRIVATE_LINK_RUNTIME_SUFFIXES).map(action => ({ version: 4, ...whatIfRequestContext(f.c, runtime(action)) })),
  ].map(value => ({ ...value, action: 'start', pollUrl: null, initialResponseFile: null,
    timeoutMs: 15000, deadlineMs: 2000000000000 }));
  const script = `import importlib.util,json,sys
s=importlib.util.spec_from_file_location("bridge","infrastructure/arm/telemetry/arm-whatif.py")
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
for original in json.loads(sys.argv[1]):
 name,scope=m.request_context(original)
 assert scope==original["scope"]
 assert name==m.fixed_deployment_name(original)
 changes=[("version",2),("version",True),("scope","unrelated"),("contextSha256","a"*64),("timeoutMs",15001),("deadlineMs",True),("unexpected","value")]
 changes.append(("migrationKey", "bad") if original["version"]==3 else ("runtimeTargetSha256","bad"))
 for key,value in changes:
  changed=dict(original);changed[key]=value
  try:m.request_context(changed);raise AssertionError("accepted unbound version or context")
  except m.Stop:pass
print("CLOSED_PRIVATE_LINK_CONTEXT_BRANCHES_PASSED_NO_AUTH")`;
  const result = await promisify(execFile)('python3', ['-I', '-B', '-c', script, JSON.stringify(cases)], { timeout: 10000 });
  assert.equal(result.stdout.trim(), 'CLOSED_PRIVATE_LINK_CONTEXT_BRANCHES_PASSED_NO_AUTH');
});
