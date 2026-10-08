import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import test from 'node:test';
import { runtimeFixture, privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';
import { privateLinkRuntimeIO, readyPrivateLinkRuntime, qualifyPrivateLinkDelivery, verifyPrivateLinkRuntimeCompletion,
  runPrivateLinkRuntime, privateRuntimePhase, privateLinkWindowBinding } from '../private-link-runtime.mjs';
import { withPrivateLinkRuntimeValidation, currentPrivateLinkRuntimeProof, verifyPrivateLinkRuntimePrerequisites } from '../private-link-controller.mjs';
import { privateLinkFixture, privateControlChain, privateInput } from './private-link.fixture.mjs';
import { digestJson as hash } from '../definition.mjs';

async function readinessFixture(t, behavior) {
  const f = runtimeFixture(), directory = await mkdtemp(path.join(os.tmpdir(), 'msr-ready-propagation-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let now = f.at, active = 0, maximum = 0;
  const calls = [], observations = [], value = f.observation('false');
  const parent = { id: f.target.environmentId, type: 'Microsoft.App/managedEnvironments',
    location: f.c.location, systemData: { createdAt: new Date(f.at - 100000).toISOString() },
    properties: { provisioningState: 'Succeeded', defaultDomain: 'unit.australiaeast.azurecontainerapps.io' } };
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, directory, {
    control: {}, now: () => now, sleep: async ms => { now += ms; },
    invoke: async (args, timeout) => {
      active++; maximum = Math.max(maximum, active);
      try {
        assert(timeout <= 15000 && timeout > 0);
        assert.equal(args[args.indexOf('--method') + 1], 'GET');
        const id = new URL(args[args.indexOf('--url') + 1]).pathname; calls.push(id);
        const special = await behavior({ id, calls, parent, advance: ms => { now += ms; } });
        if (special !== undefined) return special;
        if (id === f.target.environmentId) return structuredClone(parent);
        if (id === f.target.appId) return structuredClone(value.app);
        if (id === `${f.target.appId}/revisions`) return structuredClone(value.revisions);
        if (id === f.r.app) return value.oldApp;
        if (id === f.r.ingestIdentity || id === f.r.pullIdentity) return value.identities[id];
        if (id.endsWith('/diagnosticSettings') || id.endsWith('/dataExports')) return { value: [] };
        throw new Error('UNIT_UNEXPECTED_GET');
      } finally { active--; }
    },
  });
  const record = io.recordPropagation;
  io.recordPropagation = async evidence => { observations.push(structuredClone(evidence)); return record(evidence); };
  return { ...f, io, directory, calls, observations, now: () => now, maximum: () => maximum };
}
const missing = (code = 'ContainerAppNotFound', status = 404) => Object.assign(new Error('ARM_OPERATION_FAILED'),
  { armCode: code, httpStatus: status });

test('advancing clock binds each effect deadline to its one recorded start, including exact enable +120000', async () => {
  const f = runtimeFixture();
  f.prerequisites.controlHeadSha256 = 'a'.repeat(64);
  const value = await privateRuntimeCompletionFixture(f, f.evidence, f.prerequisites, { clockTickMs: 1 });
  const r = value.completion;
  assert.equal(r.enableIntent.effectDeadline - Date.parse(r.enableIntent.intentAt), 120000);
  for (const intent of [value.disabled.intent, r.publicControl.intent, r.disable.intent, r.publicCleanup.deleteIntent]) {
    assert(intent.effectDeadline > Date.parse(intent.intentAt));
    assert(intent.effectDeadline - Date.parse(intent.intentAt) <= 120000);
  }
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, JSON.parse(JSON.stringify(r)), value.at + 100);
  const invalid = structuredClone(r);
  invalid.enableIntent.effectDeadline = Date.parse(invalid.enableIntent.intentAt) + 120001;
  assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, invalid, value.at + 100), /ENABLE_INTENT_CHANGED/);
});

test('readiness alone retries exact app/revision propagation 404s with parent before/after checks and no PUT', async t => {
  let appMissing = true, revisionMissing = true;
  const f = await readinessFixture(t, ({ id }) => {
    if (id.endsWith('/missionspec-test-private-ingest') && appMissing) { appMissing = false; throw missing(); }
    if (id.endsWith('/revisions') && revisionMissing) { revisionMissing = false; throw missing(); }
  });
  const result = await readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 10000);
  assert.equal(result.app.id, f.target.appId);
  assert.equal(f.observations.length, 2);
  assert(f.observations.every(value => value.kind === 'private-runtime-readiness-propagation' &&
    value.state === 'propagating' && !Object.hasOwn(value, 'qualified')));
  assert.equal(f.calls.filter(id => id === f.target.environmentId).length, 4);
  for (let index = 0; index < f.calls.length; index++) {
    if (f.calls[index] === f.target.environmentId && f.calls[index + 2] === f.target.environmentId) {
      assert([f.target.appId, `${f.target.appId}/revisions`].includes(f.calls[index + 1]));
    }
  }
  assert.equal(f.now() - f.at, 6000);
  assert(f.maximum() <= 4);
});

test('healthy readiness keeps its original reads and has no new environment prerequisite', async t => {
  const f = await readinessFixture(t, ({ id }) => {
    if (id.includes('/managedEnvironments/')) throw new Error('UNIT_PARENT_READ_NOT_ADMITTED');
  });
  const result = await readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 10000);
  assert.equal(result.app.id, f.target.appId);
  assert(!f.calls.includes(f.target.environmentId));
  assert.equal(f.observations.length, 0);
});

test('raw readiness drift and partial read errors are retained without normalizing observed values', async t => {
  for (const mode of ['drift', 'partial-auth']) {
    let bad;
    const f = await readinessFixture(t, ({ id }) => {
      if (mode === 'drift' && id.endsWith('/missionspec-test-private-ingest')) return bad;
      if (mode === 'partial-auth' && id.endsWith('/revisions')) throw missing('AuthorizationFailed', 403);
    });
    bad = f.observation('false').app;
    bad.properties.configuration.ingress.fqdn = 'UNQUALIFIED.invalid';
    const effect = { intentSha256: 'a'.repeat(64), request: { method: 'PUT', id: '/UNIT-exact-deployment' }, incarnation: null };
    await assert.rejects(readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 10000, effect));
    const files = await readdir(f.directory), rawName = files.find(name => name.startsWith('private-runtime-readiness-raw-'));
    assert(rawName);
    const raw = JSON.parse(await readFile(path.join(f.directory, rawName), 'utf8'));
    assert.deepEqual(raw.effect, effect); assert.equal(raw.effectDeadline, f.at + 10000);
    assert(raw.responses.app);
    if (mode === 'drift') {
      assert.equal(raw.responses.app.value.value.properties.configuration.ingress.fqdn, 'UNQUALIFIED.invalid');
      const validated = JSON.parse(await readFile(path.join(f.directory, files.find(name => name.startsWith('private-runtime-readiness-validation-'))), 'utf8'));
      assert.equal(validated.state, 'failed'); assert.equal(validated.failure.code, 'PRIVATE_RUNTIME_TARGET_DRIFT');
    } else {
      assert.equal(raw.complete, false); assert.equal(raw.failure.httpStatus, 403);
      assert.equal(raw.failure.armCode, 'AuthorizationFailed'); assert(!raw.responses.revisions);
    }
  }
});

test('post-delete ContainerAppNotFound is explicit unconfirmed evidence, never null or successful absence', async t => {
  let calls = 0;
  const f = await readinessFixture(t, ({ id }) => {
    if (id.endsWith('/missionspec-test-public-probe')) {
      if (calls++ === 0) throw missing();
      return null;
    }
  });
  const intent = { request: { method: 'DELETE', id: f.publicTarget.appId }, effectDeadline: f.at + 10000 };
  const pending = await f.io.observeDeletion(f.publicTarget, intent, intent.effectDeadline);
  assert.equal(pending.state, 'not-yet-confirmed');
  assert.equal(pending.response.armCode, 'ContainerAppNotFound');
  assert(!Object.hasOwn(pending.response, 'value'));
  const absent = await f.io.observeDeletion(f.publicTarget, intent, intent.effectDeadline);
  assert.equal(absent.state, 'observed'); assert.equal(absent.response.value, null);
  assert.equal((await readdir(f.directory)).filter(name => name.startsWith('private-public-delete-observation-')).length, 2);
  await assert.rejects(f.io.observeDeletion(f.target, intent, intent.effectDeadline), /DELETE_SCOPE/);
  const unauth = await readinessFixture(t, ({ id }) => { if (id.endsWith('/missionspec-test-public-probe')) throw missing('AuthorizationFailed', 403); });
  await assert.rejects(unauth.io.observeDeletion(unauth.publicTarget, { ...intent, request: { method: 'DELETE', id: unauth.publicTarget.appId } },
    intent.effectDeadline), error => error.httpStatus === 403);
});

test('newly-created readiness binds the admitted exact deployment Create operation before returning', async t => {
  for (const wrong of [false, true]) {
    const f = await readinessFixture(t, () => undefined);
    const { candidate, controlEvidence, ...intent } = structuredClone(f.disabled.intent);
    intent.effectDeadline = f.at + 10000;
    const effect = { intentSha256: hash(intent), request: intent.phase.request, incarnation: null, createIntent: intent };
    let observed = 0;
    f.io.observeCreation = async (target, retained, until) => {
      assert.equal(target.appId, f.target.appId); assert.deepEqual(retained, effect);
      observed++; assert.equal(until, f.at + 10000);
      return { deployment: { id: wrong ? `${intent.phase.request.id}-foreign` : intent.phase.request.id,
        properties: { provisioningState: 'Succeeded', mode: 'Incremental', timestamp: new Date(f.at).toISOString() } },
      operations: { value: [{ properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded', targetResource: { id: f.target.appId } } }] },
      completedAt: new Date(f.at).toISOString() };
    };
    const promise = readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 10000,
      effect);
    if (wrong) await assert.rejects(promise, /CREATION_DEPLOYMENT/);
    else assert.equal((await promise).app.id, f.target.appId);
    assert.equal(observed, 1);
  }
});

test('concrete creation reads admit only a coherent fixed effect and reject foreign coordinates before GETs', async t => {
  for (const publicCreate of [false, true]) {
  for (const variant of ['valid', 'foreign-deployment', 'request', 'target', 'hash', 'action', 'deadline', 'method', 'swap']) {
    let current;
    const f = await readinessFixture(t, async ({ id }) => {
      if (id === current?.createIntent.phase.request.id) {
        if (variant === 'swap') {
          await Promise.resolve();
          current.createIntent.phase.request.id += '-changed';
        }
        return { id, properties: { provisioningState: 'Succeeded' } };
      }
      if (id === `${current?.createIntent.phase.request.id}/operations`) return { value: [] };
    });
    const target = publicCreate ? f.publicTarget : f.target;
    const binding = publicCreate ? privateLinkWindowBinding(f.c, f.context, f.evidence, f.candidate, f.disabled,
      f.instanceId, { pythonPath: '/UNIT', pythonSha256: 'a'.repeat(64), bridgeSha256: 'b'.repeat(64) }) : null;
    const intent = publicCreate ? { version: 1, kind: 'private-link-public-control-create-intent',
      windowIntentSha256: 'c'.repeat(64), phase: privateRuntimePhase(f.c, target, f.instanceId, 'create-public-probe', hash(f.disabled)),
      target, approval: f.approval('private-link-create-public-control', binding), binding,
      intentAt: new Date(f.at).toISOString(), outcome: 'create-possible' } : structuredClone(f.disabled.intent);
    intent.effectDeadline = f.at + 10000;
    current = { intentSha256: hash(intent), request: structuredClone(intent.phase.request), incarnation: null, createIntent: intent };
    if (variant === 'foreign-deployment') {
      current.createIntent.phase.request.id = '/subscriptions/foreign/providers/Microsoft.Resources/deployments/foreign';
      current.request = structuredClone(current.createIntent.phase.request);
    }
    if (variant === 'request') current.request.id += '-unapproved';
    if (variant === 'target') current.createIntent.target = { ...current.createIntent.target, environmentId: '/foreign-environment' };
    if (variant === 'action') current.createIntent.phase.action = 'enable';
    if (variant === 'deadline') current.createIntent.effectDeadline++;
    if (variant === 'method') { current.createIntent.phase.request.method = 'PUT'; current.request.method = 'PUT'; }
    if (variant !== 'hash') current.intentSha256 = hash(current.createIntent);
    else current.intentSha256 = '0'.repeat(64);
    const invoke = () => f.io.observeCreation(target, current, f.at + 10000);
    if (variant === 'valid') {
      assert.equal(Object.hasOwn(intent.phase.request, 'method'), false, 'canonical requests imply PUT via the fixed phase');
      const observation = await invoke();
      assert.equal(observation.deploymentId, intent.phase.request.id);
      assert.deepEqual(f.calls, [intent.phase.request.id, `${intent.phase.request.id}/operations`]);
    } else {
      await assert.rejects(invoke());
      assert.equal(f.calls.length, variant === 'swap' ? 1 : 0, variant);
      if (variant !== 'swap') {
        await assert.rejects(readyPrivateLinkRuntime(f.c, target, f.candidate, f.io, 'false', f.at + 10000, current));
        assert.equal(f.calls.length, 0, variant);
      }
    }
  }
  }
});

test('readiness rejects unknown or mismatched app/environment coordinates before any GET', async t => {
  for (const changed of ['app', 'environment', 'descriptor', 'public-environment']) {
    const f = await readinessFixture(t, () => {});
    const target = structuredClone(changed === 'public-environment' ? f.publicTarget : f.target);
    if (changed === 'app') target.appId += '-unapproved';
    if (changed === 'environment') target.environmentId = f.r.environment;
    if (changed === 'descriptor') target.descriptor.id += '-unapproved';
    if (changed === 'public-environment') target.environmentId = f.target.environmentId;
    await assert.rejects(readyPrivateLinkRuntime(f.c, target, f.candidate, f.io, 'false', f.at + 10000), /PHASE_TARGET/);
    await assert.rejects(f.io.observe(target, f.at + 10000, true), /PHASE_TARGET/);
    assert.equal(f.calls.length, 0, changed);
  }
});

test('propagation never normalizes authorization, other missing codes, missing parents, changed parents or expired checks', async t => {
  for (const kind of ['auth', 'other-code', 'parent-missing', 'parent-changed', 'deadline']) {
    let parents = 0;
    const f = await readinessFixture(t, ({ id, parent, advance }) => {
      if (id.includes('/managedEnvironments/')) {
        parents++;
        if (kind === 'parent-missing') return null;
        if (kind === 'parent-changed' && parents === 2) return { ...parent, systemData: { createdAt: new Date(Date.parse(parent.systemData.createdAt) + 1).toISOString() } };
        if (kind === 'deadline' && parents === 2) advance(10001);
      }
      if (id.endsWith('/missionspec-test-private-ingest')) throw missing(kind === 'other-code' ? 'ResourceNotFound' : 'ContainerAppNotFound', kind === 'auth' ? 403 : 404);
    });
    await assert.rejects(readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 10000));
    assert.equal(f.observations.length, 0, kind);
  }
});

test('ordinary observation retains original 404 failure behavior and endless readiness propagation ends at the original deadline', async t => {
  const f = await readinessFixture(t, ({ id }) => {
    if (id.endsWith('/missionspec-test-private-ingest')) throw missing();
  });
  await assert.rejects(f.io.observe(f.target, f.at + 10000), error => error.armCode === 'ContainerAppNotFound');
  await f.io.beginRecoveryReads(f.at + 10000);
  await assert.rejects(readyPrivateLinkRuntime(f.c, f.target, f.candidate, f.io, 'false', f.at + 6000), /DEADLINE/);
  assert.equal(f.now() - f.at, 6000);
  assert.equal(f.observations.length, 2);
});

test('operation-local immutable history scope rejects foreign inputs and remains wired through the closed runtime dispatcher', async t => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 }), evidence = await privateControlChain(f);
  let late;
  await withPrivateLinkRuntimeValidation(f.c, f.context, evidence, async scoped => {
    const first = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, scoped, f.at);
    assert.equal(verifyPrivateLinkRuntimePrerequisites(f.c, f.context, scoped, f.at), first);
    assert(Object.isFrozen(first));
    assert.throws(() => verifyPrivateLinkRuntimePrerequisites(f.c, f.context, structuredClone(scoped), f.at), /SCOPE_CHANGED/);
    assert.throws(() => withPrivateLinkRuntimeValidation(f.c, f.context, scoped, () => {}), /NESTED/);
    await assert.rejects(currentPrivateLinkRuntimeProof(f.c, f.context, scoped, '/UNIT', async () => {
      throw new Error('UNIT_CLOUD_FORBIDDEN');
    }, { now: () => f.at, validationScope: {} }), /FORGED/);
    late = new Promise(resolve => setTimeout(() => {
      try { verifyPrivateLinkRuntimePrerequisites(f.c, f.context, scoped, f.at); resolve(null); } catch (error) { resolve(error); }
    }, 25));
  });
  assert.match((await late).message, /SCOPE_CHANGED/);
  await withPrivateLinkRuntimeValidation(f.c, f.context, evidence, scoped => {
    assert(verifyPrivateLinkRuntimePrerequisites(f.c, f.context, scoped, f.at));
  });
  await assert.rejects(qualifyPrivateLinkDelivery(f.c, f.context, evidence, f.candidate, {}, 'id', {}, {}, '/UNIT',
    { runtimeValidation: {} }), /SCOPE_FORGED/);
  const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
  const { completion, disabled } = await privateRuntimeCompletionFixture(f, evidence, prerequisites);
  const directory = path.resolve(`infrastructure/arm/telemetry/.operator-private/revision-20261003-${randomUUID().replaceAll('-', '')}`);
  await mkdir(directory, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  let statistics, calls = 0;
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-window', path.relative(process.cwd(), directory),
    { candidate: f.candidate, disabled, instanceId: completion.binding.instanceId,
      transport: completion.transport, approvals: completion.approvals },
    { now: () => f.at, lookup: async () => f.source, sourceDigest: async () => f.source,
      run: async () => { throw new Error('UNIT_ROUTER_PRE_EFFECT_STOP'); },
      invoke: async () => { calls++; throw new Error('UNIT_CLOUD_FORBIDDEN'); },
      onValidationStats: value => { statistics = value; } }), /UNIT_ROUTER_PRE_EFFECT_STOP/);
  assert.equal(calls, 0);
  assert.equal(statistics.immutableHistoryVerifications, 1);
  assert.equal(statistics.prerequisiteVerifications, 1);
});
