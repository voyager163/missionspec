import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, rm, writeFile, stat } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { digestJson as hash, json } from '../definition.mjs';
import { privateInput, privateLinkFixture, privateControlChain, privateCostFixture } from './private-link.fixture.mjs';
import { verifyPrivateLinkRuntimePrerequisites } from '../private-link-controller.mjs';
import { privateRuntimeCompletionFixture, runtimeProbeFixture } from './private-link-runtime.fixture.mjs';
import { verifyNeverEnabledPrivateLinkWindow, runPrivateLinkRuntime, privateWindowFence,
  verifyPrivateLinkRuntimeCompletion, preparePrivateLinkDisableRecovery, recoverPrivateLinkDisabled,
  preparePublicControlCleanup, recoverPublicControlCleanup, privateLinkRuntimeIO } from '../private-link-runtime.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';

const f = await privateLinkFixture({ ...privateInput, version: 2 });
const evidence = await privateControlChain(f);
const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
const failed = await privateRuntimeCompletionFixture(f, evidence, prerequisites, { failFirstProbe: true, withHistoryHead: true });
const original = failed.completion, originalBytes = json(original);
const originalDirectory = 'infrastructure/arm/telemetry/.operator-private/revision-20261003-original-stopped';
const actions = { enable: 'private-link-bounded-enable', disable: 'private-link-false-only-disable',
  publicCreate: 'private-link-create-public-control', publicDelete: 'private-link-delete-public-control' };

async function fixture(t) {
  const relative = `infrastructure/arm/telemetry/.operator-private/revision-20261003-${randomUUID().replaceAll('-', '')}`;
  await mkdir(relative, { mode: 0o700 });
  t.after(() => rm(relative, { recursive: true, force: true }));
  let now = failed.at + 1000, effective = privateWindowFence(original.intent), locked = false;
  const files = new Map(), effects = [], oldFiles = new Map([
    ['private-window-result.json', original], ['private-window-intent.json', original.intent],
    ['private-disable-intent.json', original.disable.intent], ['private-disable-receipt.json', original.disable],
    ['private-enable-intent.json', null], ['private-public-create-intent.json', null],
  ]);
  const cost = privateCostFixture(f, now);
  await failed.io.sleep(now - failed.io.now());
  const runtimeReview = { policyRevision: null, costReview: cost.review, costEvidence: cost.evidence };
  const io = { ...failed.io, now: () => now, sleep: async ms => { now += ms; await failed.io.sleep(ms); },
    load: async name => files.get(name) ?? null,
    loadOriginal: async (directory, name) => {
      assert.equal(directory, originalDirectory); assert(oldFiles.has(name)); return oldFiles.get(name);
    },
    immutable: async (name, value) => {
      if (files.has(name)) throw new Error('UNIT_IMMUTABLE');
      files.set(name, structuredClone(value));
    },
    save: async (name, value) => files.set(name, structuredClone(value)),
    withWindowAdmission: async (_intent, use) => {
      assert.equal(locked, false); locked = true;
      try { return await use(); } finally { locked = false; }
    },
    windowHead: async () => effective,
    appendWindow: async (prior, next) => {
      assert.deepEqual(effective, privateWindowFence(prior));
      effective = privateWindowFence(next);
    },
    current: async () => ({ ...await failed.io.current(), checkedAt: new Date(now).toISOString() }),
    observe: async (...args) => ({ ...await failed.io.observe(...args), observedAt: new Date(now).toISOString() }),
    read: async id => [original.phases.enable.request.id, original.intent.publicPhase.request.id].includes(id) ? null : failed.io.read(id),
    probe: async (target, observation, candidate, _prerequisites, _transport, _until, guard, mode = 'private') => {
      guard(); effects.push('probe');
      return runtimeProbeFixture(f.c, target, observation, candidate, prerequisites, f.source,
        prerequisites.controlHeadSha256, now, mode);
    },
    deploy: async (...args) => { effects.push('deploy'); return failed.io.deploy(...args); },
    deletePublic: async (...args) => { effects.push('delete'); return failed.io.deletePublic(...args); },
    http: async (...args) => { effects.push('http'); return failed.io.http(...args); },
  };
  const inputs = { candidate: f.candidate, disabled: failed.disabled, instanceId: randomUUID(),
    transport: original.transport, runtimeReview };
  const approve = (action, binding) => ({ version: 1, action, bindingSha256: hash(binding), sourceSha256: f.source,
    policyCommitSha: 'c'.repeat(40), approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString() });
  const prepare = () => runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window-continuation', relative,
    { ...inputs, originalDirectory }, { io });
  const qualify = prepared => runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-window-continuation', relative,
    { ...inputs, continuationApproval: approve(prepared.approvalAction, prepared.continuationBinding),
      approvals: Object.fromEntries(Object.entries(actions).map(([key, action]) => [key, approve(action, prepared.binding)])) }, { io });
  return { relative, io, inputs, effects, files, oldFiles, prepare, qualify, approve, advance: ms => { now += ms; },
    now: () => now, head: () => effective, setHead: value => { effective = value; } };
}

test('never-enabled eligibility requires complete original semantic facts and rejects any possible enable or public creation', () => {
  assert.deepEqual(verifyNeverEnabledPrivateLinkWindow(f.c, f.context, evidence, original, failed.at), privateWindowFence(original.intent));
  for (const mutate of [
    value => { value.enableIntent = {}; },
    value => { value.enableIntentAt = value.completedAt; },
    value => { value.requests = [{}]; },
    value => { value.publicControl = {}; },
    value => { value.outcome = 'held-terminal-state-unproven'; },
    value => { value.terminal503 = false; },
    value => { value.publicCleanupFailure = { code: 'UNIT_FAILED' }; },
    value => { value.intent.version = 4; value.intent.continuation = {}; },
  ]) {
    const changed = structuredClone(original); mutate(changed);
    assert.throws(() => verifyNeverEnabledPrivateLinkWindow(f.c, f.context, evidence, changed, failed.at));
  }
});

test('one reviewed continuation retains prepared facts and original ancestor, then qualifies and fully reloads through codec', async t => {
  const x = await fixture(t), prepared = await x.prepare();
  const preparedHash = hash(prepared.continuation), oldFence = privateWindowFence(original.intent);
  assert.equal(prepared.binding.continuationSha256, preparedHash);
  const completion = await x.qualify(prepared);
  assert.equal(completion.intent.version, 4);
  assert.equal(completion.binding.continuationSha256, preparedHash);
  assert.deepEqual(completion.intent.continuation.original, original);
  assert.equal(json(original), originalBytes);
  assert.notDeepEqual(x.head(), oldFence);
  assert.deepEqual(x.head(), privateWindowFence(completion.intent));
  assert.equal(completion.outcome, 'qualified-private-delivery-disabled');
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, completion, x.now());
  const stored = new Map(), store = createPrivateLinkArtifactStore({ root: '/BLOBS',
    read: async (directory, name) => JSON.parse(stored.get(`${directory}/${name}`)),
    immutable: async (directory, name, value) => stored.set(`${directory}/${name}`, typeof value === 'string' ? value : JSON.stringify(value)),
  });
  await store.immutable('/RESULT', 'window.json', completion);
  const envelope = JSON.parse(stored.get('/RESULT/window.json'));
  assert(envelope.referenceCount <= 64);
  const reloaded = await store.load('/RESULT', 'window.json');
  assert.equal(hash(reloaded), hash(completion));
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, reloaded, x.now());
  await assert.rejects(preparePrivateLinkDisableRecovery(f.c, f.context, evidence, randomUUID(), '/UNIT',
    { io: { ...x.io, load: async () => original.intent } }), /GLOBAL_HEAD_CHANGED/);
  assert.equal(json(original), originalBytes);

  // A process can die after enable with its mutex still present. Only the exact
  // effective successor may use independent reviewed false/delete recovery.
  const ledger = await privateLinkRuntimeIO(f.c, f.context, evidence, path.resolve(x.relative), { store: { root: path.resolve(x.relative) } });
  await ledger.reserve('window', original.intent.physicalKey, oldFence);
  await ledger.appendWindow(original.intent, completion.intent);
  const lock = path.join(x.relative, `private-link-runtime-window-admission-${original.intent.physicalKey}.lock`);
  await writeFile(lock, '', { flag: 'wx', mode: 0o600 });
  await assert.rejects(ledger.withWindowAdmission(original.intent, () => assert.fail('new admission')), /ADMISSION_IN_PROGRESS/);
  await assert.rejects(ledger.windowHead(completion.intent), /ADMISSION_IN_PROGRESS/);
  await assert.rejects(ledger.windowHead(original.intent, true), /ADMISSION_IN_PROGRESS/);
  assert.deepEqual(await ledger.windowHead(completion.intent, true), privateWindowFence(completion.intent));
  let enabled = true, publicPresent = true, falseWrites = 0, deletes = 0;
  const recoveryIO = { ...x.io, windowHead: ledger.windowHead,
    current: async () => assert.fail('unhealthy backend must not be needed'),
    inventory: async () => assert.fail('unhealthy registry must not be needed'),
    verifyPrerequisites: () => assert.fail('forward prerequisite port must not be needed'),
    probe: async () => assert.fail('no probe in frozen recovery'),
    observe: async () => ({ ...structuredClone(enabled ? completion.enabled : completion.disable.observation), observedAt: new Date(x.now()).toISOString() }),
    deploy: async (_request, guard, until, check, intent) => { await check(until); guard(); await intent(); guard(); enabled = false; falseWrites++; },
    http: async (_host, _method, _path, _event, guard) => { guard(); return completion.disable.response; },
    read: async id => {
      if (id === completion.publicTarget.appId) return publicPresent ? completion.publicControl.observation.app : null;
      if (id === completion.publicControl.intent.phase.request.id) return completion.publicCleanup.creation.deployment;
      if (id === `${completion.publicControl.intent.phase.request.id}/operations`) return completion.publicCleanup.creation.operations;
      return x.io.read(id);
    },
    deletePublic: async (_target, guard, until, check, intent) => { await check(until); guard(); await intent(); guard(); publicPresent = false; deletes++; },
  };
  const falseId = randomUUID(), falsePrepared = await preparePrivateLinkDisableRecovery(f.c, f.context, evidence, falseId, '/UNIT', { io: recoveryIO });
  await recoverPrivateLinkDisabled(f.c, f.context, evidence, falseId,
    x.approve(falsePrepared.approvalAction, falsePrepared.binding), '/UNIT', { io: recoveryIO });
  const deleteId = randomUUID(), deletePrepared = await preparePublicControlCleanup(f.c, f.context, evidence, deleteId, '/UNIT', { io: recoveryIO });
  await recoverPublicControlCleanup(f.c, f.context, evidence, deleteId,
    x.approve(deletePrepared.approvalAction, deletePrepared.binding), '/UNIT', { io: recoveryIO });
  assert.equal(falseWrites, 1); assert.equal(deletes, 1); assert.equal(publicPresent, false);
  assert((await stat(lock)).isFile(), 'recovery must not clear the abandoned admission mutex');
  assert.deepEqual(await ledger.windowHead(completion.intent, true), privateWindowFence(completion.intent));
});

test('changed head, missing original files, current resources or expired review never admit a new effect', async t => {
  for (const changed of ['head', 'missing-intent', 'enable-file', 'public-file', 'enable-deployment', 'public-app', 'generation', 'expired']) {
    const x = await fixture(t);
    if (changed === 'head') x.setHead({ ...x.head(), intentSha256: '0'.repeat(64) });
    if (changed === 'missing-intent') x.oldFiles.set('private-window-intent.json', null);
    if (changed === 'enable-file') x.oldFiles.set('private-enable-intent.json', {});
    if (changed === 'public-file') x.oldFiles.set('private-public-create-intent.json', {});
    if (changed === 'enable-deployment' || changed === 'public-app') {
      const read = x.io.read;
      const id = changed === 'public-app' ? original.publicTarget.appId : original.phases.enable.request.id;
      x.io.read = async target => target === id ? { id } : read(target);
    }
    if (changed === 'generation') {
      const observe = x.io.observe;
      x.io.observe = async (...args) => {
        const value = structuredClone(await observe(...args));
        value.app.systemData.createdAt = new Date(f.at + 1).toISOString(); return value;
      };
    }
    if (changed === 'expired') x.advance(3600001);
    await assert.rejects(x.prepare(), undefined, changed);
    assert(!x.effects.includes('deploy') && !x.effects.includes('delete') && !x.effects.includes('probe'), changed);
    assert(!x.files.has('private-window-intent.json'));
  }
});

test('exclusive successor loser cannot compensate or touch a winning window', async t => {
  const x = await fixture(t), prepared = await x.prepare();
  x.effects.length = 0;
  x.io.withWindowAdmission = async () => { throw new Error('PRIVATE_WINDOW_ADMISSION_IN_PROGRESS'); };
  await assert.rejects(x.qualify(prepared), /ADMISSION_IN_PROGRESS/);
  assert.deepEqual(x.effects, []);
  assert(!x.files.has('private-disable-intent.json'));
  assert.equal(json(original), originalBytes);
});

test('tampered preparation, stale reviews and changed original source/false receipt cannot become continuation authority', async t => {
  for (const changed of ['prepared-source', 'prepared-head', 'original-source', 'original-503', 'stale']) {
    const x = await fixture(t), prepared = await x.prepare();
    x.effects.length = 0;
    if (changed.startsWith('prepared-')) {
      const value = structuredClone(x.files.get('private-window-continuation-preparation.json'));
      if (changed === 'prepared-source') value.continuation.observation.current.sourceSha256 = '0'.repeat(64);
      else value.continuation.observation.current.headSha256 = '0'.repeat(64);
      x.files.set('private-window-continuation-preparation.json', value);
    } else if (changed.startsWith('original-')) {
      const value = structuredClone(original);
      if (changed === 'original-source') value.approvals.enable.sourceSha256 = '0'.repeat(64);
      else value.disable.response.status = 202;
      x.oldFiles.set('private-window-result.json', value);
    } else x.advance(3600001);
    await assert.rejects(x.qualify(prepared), undefined, changed);
    assert.deepEqual(x.effects, [], changed);
    assert(!x.files.has('private-enable-intent.json'));
    assert(!x.files.has('private-disable-intent.json'));
  }
});

test('failed exclusive successor creation is outside all effect compensation', async t => {
  const x = await fixture(t), prepared = await x.prepare();
  x.effects.length = 0;
  x.io.appendWindow = async () => { throw Object.assign(new Error('UNIT_CAS_LOST'), { code: 'EEXIST' }); };
  await assert.rejects(x.qualify(prepared), /UNIT_CAS_LOST/);
  assert(!x.effects.includes('deploy') && !x.effects.includes('delete') && !x.effects.includes('probe'));
  assert(!x.files.has('private-disable-intent.json'));
  assert(x.files.has('private-window-intent.json'));
  assert.deepEqual(x.head(), privateWindowFence(original.intent));
});

test('production head CAS is append-only and blocks stale original recovery', async t => {
  const directory = path.resolve(`infrastructure/arm/telemetry/.operator-private/revision-20261003-${randomUUID().replaceAll('-', '')}`);
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true, force: true }));
  const io = await privateLinkRuntimeIO(f.c, f.context, evidence, directory, { store: { root: directory } });
  const missing = `infrastructure/arm/telemetry/.operator-private/revision-20261003-${randomUUID().replaceAll('-', '')}`;
  await assert.rejects(io.loadOriginal(missing, 'private-window-result.json'), error => error.code === 'ENOENT');
  await assert.rejects(stat(missing), error => error.code === 'ENOENT');
  await io.reserve('window', original.intent.physicalKey, privateWindowFence(original.intent));
  const next = { ...original.intent, version: 4, binding: { ...original.binding, instanceId: randomUUID() }, continuation: { offline: true } };
  await io.withWindowAdmission(original.intent, async () => {
    const other = await privateLinkRuntimeIO(f.c, f.context, evidence, directory, { store: { root: directory } });
    await assert.rejects(other.windowHead(original.intent), /ADMISSION_IN_PROGRESS/);
    await io.appendWindow(original.intent, next);
    await assert.rejects(io.appendWindow(original.intent, { ...next, intentAt: new Date(f.at + 1).toISOString() }), error => error.code === 'EEXIST');
    assert.deepEqual(await io.windowHead(next), privateWindowFence(next));
  });
  assert.deepEqual(await io.windowHead(original.intent), privateWindowFence(next));
});
