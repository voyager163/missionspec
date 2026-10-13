import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  ExecutionController, executionApprovalRequest, executionPlanApprovalRequest, digestContent, digestApprovalRequest,
  digestEffectScope, openRuntimeStore, observeWorkspaceRoot,
} from '../dist/api/index.js';
import { parseTaskDefinition } from '../dist/engines/planning/contracts.js';

const instant = '2026-09-20T12:00:00.000Z';
const ok = (value) => { assert.equal(value.status, 'ok', JSON.stringify(value)); return value.value; };

async function fixture(t) {
  const root = path.join(process.cwd(), `.execution-controller-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  await mkdir(path.join(root, '.missionspec'), { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const workspace = { workspaceId: 'WSP-test-only', rootDigest: (await observeWorkspaceRoot(root)).rootDigest };
  const store = ok(await openRuntimeStore({ directory: path.join(root, '.missionspec/state'), mode: 'create', expectedWorkspace: workspace }));
  t.after(() => store.close());
  const approvals = new Map();
  // TEST ONLY: no human confirmation or actual host version is qualified by these fixtures.
  const authority = {
    async resolve(reference) { return { status: 'ok', value: approvals.has(reference.id) ? { state: 'current', approval: approvals.get(reference.id) } : { state: 'absent', reference } }; },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
  const task = parseTaskDefinition({
    contractVersion: 1, id: 'TSK-test', title: 'Test fixture task', dependsOn: [],
    requirements: ['REQ-test'], scenarios: ['SCN-test'], checks: ['CHK-test'], writeScope: ['src/test.ts'],
  });
  return finishFixture({ root, workspace, store, approvals, authority, task });
}

async function multiTaskFixture(t, mode = 'auto') {
    const f = await fixture(t);
    const first = f.workOrder({ mode, limits: { maxTasks: 2, maxDurationMs: 60_000, maxRepairsPerTask: 2, concurrency: 1 } });
    const task = parseTaskDefinition({ ...first.task, id: 'TSK-second', title: 'Second TEST task', dependsOn: [first.task.id] });
    const lastSource = digestContent('TEST second source');
    const effects = [
      { kind: 'host-dispatch', host: first.host, taskIds: [task.id] },
      { kind: 'file-write', purpose: 'source', path: 'src/test.ts', expected: f.state.after, proposed: lastSource },
    ];
    const second = {
      ...first, id: 'WRK-second', task, sourceBefore: f.state.after,
      revisions: { ...first.revisions, source: f.state.after, effects: digestEffectScope(effects) }, effects,
    };
    const plan = { orders: [first, second] };
    const definition = digestContent('TEST ONLY check definition');
    let verified = true;
    const observe = async (work) => ({
      revisions: { ...work.revisions, source: f.state.source }, task: work.task, ready: true,
      checks: [{ contractVersion: 1, id: 'CHK-test', definition, kind: 'executed', description: 'TEST ONLY', requirements: [], scenarios: [] }],
    });
    // TEST ONLY qualified port: this is not a real coding host.
    f.host.dispatch = async (work, token) => {
      const durable = ok(await f.store.readRun(work.runId)).snapshot;
      assert.equal(durable.admissions.at(-1).dispatchToken, token);
      f.state.dispatches++;
      f.state.source = work.effects.find((effect) => effect.kind === 'file-write').proposed;
      const previous = durable.attempts.filter((attempt) => attempt.workOrderId === work.id);
      return { status: 'ok', value: {
        contractVersion: 1, id: `ATT-multi-${f.state.dispatches}`, workOrderId: work.id,
        sequence: previous.length ? { kind: 'repair', number: previous.length, failedAttempt: previous.at(-1).id } : { kind: 'initial' },
        observation: { state: 'host-returned', startedAt: instant, finishedAt: instant, exitCode: f.state.exitCode, sourceAfter: f.state.source, reportedTaskStatus: 'claimed-complete' },
      } };
    };
    const verifyTask = async (work, snapshot) => {
      if (!verified) return [];
      const reference = {
        contractVersion: 1, id: `EVD-${randomUUID()}`, revisions: snapshot.revisions, source: snapshot.revisions.source,
        checkId: 'CHK-test', checkDefinition: definition, attemptId: snapshot.attempts.at(-1).id,
        storage: { state: 'retained', path: '.missionspec/evidence/TEST-only.json', digest: digestContent('TEST ONLY trusted observation fixture') },
      };
      const current = ok(await f.store.readRun(work.runId));
      ok(await f.store.commitRun({ expectedRevision: current.revision, snapshot: current.snapshot, attempts: [], evidence: [reference] }));
      return [{ state: 'observed', basis: 'executed', result: 'passed', checkId: 'CHK-test', evidence: reference }];
    };
    const issuePlan = (value = plan) => {
      const reference = f.issue({ ...first, approval: { id: `APR-${randomUUID()}` } }).approval;
      const previous = f.approvals.get(reference.id);
      const request = executionPlanApprovalRequest(value);
      f.approvals.set(reference.id, { ...previous, request, requestDigest: digestApprovalRequest(request) });
      return reference;
    };
    const readEvidence = async (id) => ({ state: 'observed', basis: 'executed', result: 'passed',
      checkId: 'CHK-test', evidence: ok(await f.store.readEvidence(id)) });
    const composition = { ...f.composition, observe, verifyTask, readEvidence };
    return { ...f, plan, issuePlan, composition, setVerified: (value) => { verified = value; }, controller: new ExecutionController(composition) };
  }

  test('Auto schedules dependent tasks only after durable source-bound verification, preserves mapping and completes scheduling not acceptance', async (t) => {
    const f = await multiTaskFixture(t);
    const approval = f.issuePlan();
    const snapshot = await f.controller.runPlan(f.plan, approval);
    assert.equal(snapshot.state, 'quiesced');
    assert.equal(f.state.dispatches, 2);
    assert.equal(snapshot.attempts.length, 2);
    assert.deepEqual(snapshot.attempts.map((attempt) => attempt.sequence.kind), ['initial', 'initial']);
    assert.deepEqual(snapshot.completions.map((entry) => entry.taskId), ['TSK-test', 'TSK-second']);
    assert.equal(snapshot.completions[0].source, f.plan.orders[1].sourceBefore);
    assert.equal(ok(await f.store.readAcceptance(approval)), null);
    assert.equal(ok(await f.store.readRunEvidence(snapshot.id)).length, 2);
  });

  test('Interactive plan pauses after one verified task and restart resumes remaining exact reviewed scope', async (t) => {
    const f = await multiTaskFixture(t, 'interactive');
    const approval = f.issuePlan();
    const first = await f.controller.runPlan(f.plan, approval);
    assert.equal(first.state, 'paused');
    assert.equal(f.state.dispatches, 1);
    const second = await new ExecutionController(f.composition).runPlan(f.plan, approval);
    assert.equal(second.completions.length, 2);
    assert.equal(f.state.dispatches, 2);
    assert.equal(second.state, 'quiesced');
  });

  test('host claims and removed pending IDs never advance Auto; retained evidence must be independently verified', async (t) => {
    const f = await multiTaskFixture(t);
    f.setVerified(false);
    const approval = f.issuePlan();
    const first = await f.controller.runPlan(f.plan, approval);
    assert.equal(first.completions, undefined);
    assert.equal(f.state.dispatches, 1);
    const durable = ok(await f.store.readRun(first.id));
    ok(await f.store.commitRun({ expectedRevision: durable.revision, snapshot: { ...durable.snapshot, pendingTasks: [] }, attempts: [], evidence: [] }));
    await f.controller.runPlan(f.plan, approval);
    assert.equal(f.state.dispatches, 1);
    f.setVerified(true);
    assert.equal((await f.controller.runPlan(f.plan, approval)).state, 'quiesced');
    assert.equal(f.state.dispatches, 2);
  });

  test('unknown dispatch cannot resume until exact qualified fenced terminal inspection is persisted', async (t) => {
    const f = await fixture(t);
    const work = f.issue(f.workOrder());
    f.state.failure = new Error('TEST lost terminal response');
    await assert.rejects(f.controller.dispatch(work), { code: 'effect-outcome-unknown' });
    await assert.rejects(f.controller.reconcile(work.runId, work.approval), { code: 'capability-unavailable' });
    f.host.inspectDispatch = async (_work, token) => ({ status: 'ok', value: {
      state: 'fenced-terminal', dispatchToken: token, evidence: digestContent('TEST ONLY durable inspection'),
      attempt: { contractVersion: 1, id: 'ATT-reconciled', workOrderId: work.id, sequence: { kind: 'initial' },
        observation: { state: 'host-returned', startedAt: instant, finishedAt: instant, exitCode: 1, sourceAfter: f.state.source, reportedTaskStatus: 'unspecified' } },
    } });
    const reconciled = await f.controller.reconcile(work.runId, work.approval);
    assert.equal(reconciled.state, 'paused');
    assert.equal(reconciled.quiescence, 'confirmed');
    assert.equal(reconciled.reconciliations.length, 1);
    assert.equal(f.state.dispatches, 1);
    assert.equal(reconciled.completions, undefined);
  });
function finishFixture({ root, workspace, store, approvals, authority, task }) {
  const state = { source: digestContent('before'), dispatches: 0, stops: 0, exitCode: 0, after: digestContent('after'), failure: null, stopUnknown: false };
  const fenced = new Set();
  const revisions = (effects) => ({
    workspace, changeId: 'CHG-test', specification: digestContent('spec'), tasks: digestContent('tasks'),
    workflow: digestContent('workflow'), source: state.source, effects: digestEffectScope(effects),
  });
  const qualification = {
    state: 'qualified', host: 'copilot', exactVersion: 'TEST-FIXTURE-NOT-A-HOST-VERSION',
    operatingSystem: process.platform === 'darwin' ? 'macos' : 'linux',
    evidence: digestContent('TEST ONLY host qualification evidence'),
    permissions: 'exact-effect-scope',
    limits: { maxTasks: 'hard', maxDurationMs: 'hard', maxRepairsPerTask: 'hard', concurrency: 'hard' },
    cancellation: 'confirmed-quiescence',
    dispatchFencing: 'durable-admission-token',
  };
  const host = {
    async inspect() { return { status: 'ok', value: qualification }; },
    async dispatch(work, dispatchToken) {
      if (fenced.has(dispatchToken)) return { status: 'blocked', error: { code: 'conflict', message: 'TEST fenced admission', retry: 'never', fields: [] } };
      state.dispatches++;
      const durable = ok(await store.readRun(work.runId)).snapshot;
      assert.equal(durable.admissions.at(-1).dispatchToken, dispatchToken);
      assert.equal(durable.state, 'running');
      assert.equal(durable.quiescence, 'unconfirmed');
      assert.equal(durable.admissions.at(-1).requestDigest, digestApprovalRequest(executionApprovalRequest(work)));
      if (state.failure) throw state.failure;
      const last = durable.attempts.at(-1);
      state.source = state.after;
      return { status: 'ok', value: {
        contractVersion: 1, id: `ATT-test-${state.dispatches}`, workOrderId: work.id,
        sequence: last ? { kind: 'repair', number: durable.attempts.length, failedAttempt: last.id } : { kind: 'initial' },
        observation: { state: 'host-returned', startedAt: instant, finishedAt: instant, exitCode: state.exitCode, sourceAfter: state.source, reportedTaskStatus: 'claimed-complete' },
      } };
    },
    async requestStop(_workOrderId, dispatchToken) {
      state.stops++;
      if (!state.stopUnknown) fenced.add(dispatchToken);
      return { status: 'ok', value: state.stopUnknown
        ? { state: 'outcome-unknown', reason: 'TEST missing cancellation receipt' }
        : { state: 'quiesced', evidence: digestContent('TEST ONLY stop receipt'), dispatchToken } };
    },
  };
  const observe = async (work) => ({ revisions: { ...work.revisions, source: state.source }, task, ready: true });
  const clock = { wallTime: () => instant, monotonicMilliseconds: () => 0 };
  const issue = (work) => {
    const request = executionApprovalRequest(work);
    approvals.set(work.approval.id, {
      contractVersion: 1, state: 'trusted-issued', reference: work.approval,
      assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST ONLY local confirmation fixture') },
      request, requestDigest: digestApprovalRequest(request), issuedAt: instant, expiresAt: '2026-09-21T12:00:00.000Z',
    });
    return work;
  };
  const workOrder = (overrides = {}) => {
    const effects = [
      { kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-test'] },
      { kind: 'file-write', purpose: 'source', path: 'src/test.ts', expected: state.source, proposed: state.after },
    ];
    return {
      contractVersion: 1, id: 'WRK-test', runId: 'RUN-test', task, revisions: revisions(effects),
      sourceBefore: state.source, approval: { id: `APR-${randomUUID()}` }, mode: 'interactive', host: 'copilot',
      limits: { maxTasks: 1, maxDurationMs: 60_000, maxRepairsPerTask: 2, concurrency: 1 }, effects, ...overrides,
    };
  };
  const composition = { store, authority, host, observe, clock };
  return { root, workspace, store, authority, host, observe, clock, state, qualification, approvals, workOrder, issue, composition, controller: new ExecutionController(composition) };
}

test('default authority and default native host ports fail closed without durable admission or dispatch', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  await assert.rejects(new ExecutionController({ store: f.store, observe: f.observe, host: f.host, clock: f.clock }).dispatch(work), { code: 'authority-required' });
  await assert.rejects(new ExecutionController({ store: f.store, observe: f.observe, authority: f.authority, clock: f.clock }).dispatch(work), { code: 'host-unqualified' });
  assert.equal(f.state.dispatches, 0);
  assert.equal(ok(await f.store.readRun('RUN-test')), null);
});

test('material remaining source changes require persisted reapproval after bounded repair and cannot extend original limits', async (t) => {
  const f = await multiTaskFixture(t);
  f.setVerified(false);
  f.state.exitCode = 1;
  const approval = f.issuePlan();
  await f.controller.runPlan(f.plan, approval);
  const extended = { orders: f.plan.orders.map((work) => ({ ...work, limits: { ...work.limits, maxDurationMs: 120_000 } })) };
  await assert.rejects(f.controller.reapprovePlan(extended, f.issuePlan(extended)), { code: 'scope-exceeded' });
  const source = digestContent('TEST repaired source');
  const first = f.plan.orders[0];
  const effects = first.effects.map((effect) => effect.kind === 'file-write'
    ? { ...effect, expected: f.state.source, proposed: source } : effect);
  const repair = f.issue({ ...first, approval: { id: `APR-${randomUUID()}` }, sourceBefore: f.state.source,
    effects, revisions: { ...first.revisions, source: f.state.source, effects: digestEffectScope(effects) } });
  f.state.exitCode = 0;
  await f.controller.dispatch(repair);
  f.setVerified(true);
  await assert.rejects(f.controller.runPlan(f.plan, approval), { code: 'stale-revision' });
  assert.equal(f.state.dispatches, 2);
  const second = f.plan.orders[1];
  const nextEffects = second.effects.map((effect) => effect.kind === 'file-write' ? { ...effect, expected: source } : effect);
  const next = { orders: [first, { ...second, effects: nextEffects, sourceBefore: source,
    revisions: { ...second.revisions, source, effects: digestEffectScope(nextEffects) } }] };
  const reapproval = f.issuePlan(next);
  await f.controller.reapprovePlan(next, reapproval);
  const completed = await f.controller.runPlan(next, reapproval);
  assert.equal(completed.state, 'quiesced');
  assert.equal(completed.replans.length, 1);
  assert.deepEqual(completed.replans[0].approval, reapproval);
  assert.equal(completed.attempts[1].sequence.kind, 'repair');
  assert.equal(f.state.dispatches, 3);
});

test('restart checks retained dependency bytes again instead of trusting recorded completion IDs', async (t) => {
  const f = await multiTaskFixture(t, 'interactive');
  const approval = f.issuePlan();
  await f.controller.runPlan(f.plan, approval);
  const restarted = new ExecutionController({ ...f.composition, readEvidence: async () => {
    throw Object.assign(new Error('TEST retained bytes missing'), { code: 'evidence-unavailable' });
  } });
  await assert.rejects(restarted.runPlan(f.plan, approval), { code: 'evidence-unavailable' });
  assert.equal(f.state.dispatches, 1);
});

test('serial Auto consumes a durable monotonic budget even when wall time does not advance', async (t) => {
  const f = await multiTaskFixture(t);
  let ticks = 0;
  const controller = new ExecutionController({ ...f.composition,
    clock: { wallTime: () => instant, monotonicMilliseconds: () => { ticks += 35_000; return ticks; } } });
  await assert.rejects(controller.runPlan(f.plan, f.issuePlan()), { code: 'effect-outcome-unknown' });
  const current = ok(await f.store.readRun('RUN-test'));
  assert.equal(current.snapshot.elapsedMs, 35_000);
  assert.equal(current.snapshot.admissions[1].workOrder.limits.maxDurationMs, 25_000);
  assert.equal(current.snapshot.state, 'outcome-unknown');
  assert.notEqual((await f.store.commitRun({ expectedRevision: current.revision,
    snapshot: { ...current.snapshot, elapsedMs: 0 }, attempts: [], evidence: [] })).status, 'ok');
});

test('retained failed verification can authorize a bounded reviewed repair despite a host exit-zero claim', async (t) => {
  const f = await fixture(t);
  const definition = digestContent('TEST ONLY failed check');
  const controller = new ExecutionController({ ...f.composition,
    observe: async (work) => ({ ...await f.observe(work), checks: [{
      contractVersion: 1, id: 'CHK-test', definition, kind: 'executed', description: 'TEST ONLY', requirements: [], scenarios: [],
    }] }),
    readEvidence: async (id) => ({ state: 'observed', checkId: 'CHK-test', basis: 'executed', result: 'failed', evidence: ok(await f.store.readEvidence(id)) }),
  });
  const initial = await controller.dispatch(f.issue(f.workOrder()));
  const current = ok(await f.store.readRun(initial.id));
  const evidence = {
    contractVersion: 1, id: 'EVD-failed-check', revisions: initial.revisions, source: initial.revisions.source,
    checkId: 'CHK-test', checkDefinition: definition, attemptId: initial.attempts[0].id,
    storage: { state: 'retained', path: '.missionspec/evidence/TEST-failed.json', digest: digestContent('TEST ONLY failure observation') },
  };
  ok(await f.store.commitRun({ expectedRevision: current.revision, snapshot: initial, attempts: [], evidence: [evidence] }));
  f.state.after = digestContent('TEST repaired result');
  const repaired = await controller.dispatch(f.issue(f.workOrder()));
  assert.equal(repaired.attempts.length, 2);
  assert.equal(repaired.attempts[1].sequence.kind, 'repair');
  assert.equal(repaired.state, 'paused');
});

test('cancellation fences an admitted dispatcher paused before host hand-off', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  let release;
  let reached;
  const gate = new Promise((resolve) => { release = resolve; });
  const ready = new Promise((resolve) => { reached = resolve; });
  let observations = 0;
  const controller = new ExecutionController({
    ...f.composition,
    observe: async (order, phase) => {
      if (phase === 'before' && ++observations === 2) { reached(); await gate; }
      return f.observe(order, phase);
    },
  });
  const pending = controller.dispatch(work);
  const rejected = assert.rejects(pending, { code: 'effect-outcome-unknown' });
  await ready;
  const controlled = await new ExecutionController(f.composition).control(work.runId, 'cancel', work.approval);
  assert.equal(controlled.state, 'quiesced');
  assert.equal(controlled.quiescence, 'confirmed');
  release();
  await rejected;
  assert.equal(f.state.dispatches, 0);
  const durable = await controller.status(work.runId);
  assert.equal(durable.state, 'quiesced');
  assert.equal(durable.quiescence, 'confirmed');
});

test('a qualified stop tombstone rejects a hand-off that arrives after confirmed cancellation', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  let release;
  let reached;
  const gate = new Promise((resolve) => { release = resolve; });
  const ready = new Promise((resolve) => { reached = resolve; });
  const dispatch = f.host.dispatch;
  f.host.dispatch = async (order, token) => {
    reached();
    await gate;
    return dispatch(order, token);
  };
  const pending = f.controller.dispatch(work);
  const rejected = assert.rejects(pending, { code: 'effect-outcome-unknown' });
  await ready;
  assert.equal((await f.controller.control(work.runId, 'cancel', work.approval)).quiescence, 'confirmed');
  release();
  await rejected;
  assert.equal(f.state.dispatches, 0);
  assert.equal((await f.controller.status(work.runId)).state, 'quiesced');
});

test('unqualified fencing and mismatched cancellation receipts never establish quiescence', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  f.qualification.dispatchFencing = undefined;
  await assert.rejects(f.controller.dispatch(work), { code: 'host-unqualified' });
  assert.equal(f.state.dispatches, 0);
  f.qualification.dispatchFencing = 'durable-admission-token';
  f.state.failure = new Error('TEST dispatch unknown');
  f.host.requestStop = async () => ({
    status: 'ok', value: { state: 'quiesced', evidence: digestContent('TEST receipt'), dispatchToken: digestContent('wrong token') }
  });
  await assert.rejects(f.controller.dispatch(work), { code: 'effect-outcome-unknown' });
  assert.equal((await f.controller.status(work.runId)).quiescence, 'unconfirmed');
  assert.equal((await f.controller.control(work.runId, 'cancel', work.approval)).quiescence, 'unconfirmed');
});

test('qualified TEST dispatch persists full admission before effects and never treats exit zero as acceptance', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  const result = await f.controller.dispatch(work);
  assert.equal(result.state, 'paused');
  assert.equal(result.quiescence, 'confirmed');
  assert.equal(result.attempts[0].observation.reportedTaskStatus, 'claimed-complete');
  assert.equal(result.revisions.source, f.state.after);
  assert.equal(result.admissions[0].workOrder.mode, 'interactive');
  assert.deepEqual(ok(await f.store.readRunEvidence(work.runId)), []);
  assert.equal(ok(await f.store.readAcceptance(work.approval)), null);
  assert.deepEqual(await f.controller.status(work.runId), result);
  await assert.rejects(f.controller.dispatch(f.issue(f.workOrder())), { code: 'conflict' });
});

test('Auto is explicit, bounded and serial, and grants cannot replay across run/workspace identities', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder({ mode: 'auto' }));
  await assert.rejects(f.controller.dispatch({ ...work, runId: 'RUN-replay' }), { code: 'scope-exceeded' });
  await assert.rejects(f.controller.dispatch({ ...work, id: 'WRK-replay' }), { code: 'scope-exceeded' });
  await assert.rejects(f.controller.dispatch({ ...work, revisions: { ...work.revisions, workspace: { ...f.workspace, workspaceId: 'WSP-other' } } }), { code: 'scope-exceeded' });
  await assert.rejects(f.controller.dispatch({ ...work, limits: { ...work.limits, concurrency: 2 } }));
  await assert.rejects(f.controller.dispatch({ ...work, limits: { ...work.limits, maxRepairsPerTask: 3 } }));
  const result = await f.controller.dispatch(work);
  assert.equal(result.admissions[0].workOrder.mode, 'auto');
  assert.equal(f.state.dispatches, 1);
});

test('advisory limits, wrong OS, unknown cancellation and stale observed scope block before effects', async (t) => {
  const f = await fixture(t);
  const work = f.issue(f.workOrder());
  f.qualification.limits.maxDurationMs = 'advisory';
  await assert.rejects(f.controller.dispatch(work), { code: 'host-unqualified' });
  f.qualification.limits.maxDurationMs = 'hard';
  f.qualification.cancellation = 'unknown-outcome-possible';
  await assert.rejects(f.controller.dispatch(work), { code: 'host-unqualified' });
  f.qualification.cancellation = 'confirmed-quiescence';
  const operatingSystem = f.qualification.operatingSystem;
  f.qualification.operatingSystem = 'windows';
  await assert.rejects(f.controller.dispatch(work), { code: 'host-unqualified' });
  f.qualification.operatingSystem = operatingSystem;
  f.qualification.permissions = 'advisory';
  await assert.rejects(f.controller.dispatch(work), { code: 'host-unqualified' });
  f.qualification.permissions = 'exact-effect-scope';
  f.state.source = digestContent('unreviewed edit');
  await assert.rejects(f.controller.dispatch(work), { code: 'stale-revision' });
  assert.equal(f.state.dispatches, 0);
});

test('invalid monotonic clocks block dispatch rather than defeating the duration limit', async (t) => {
  const f = await fixture(t);
  const controller = new ExecutionController({ ...f.composition, clock: { wallTime: () => instant, monotonicMilliseconds: () => NaN } });
  await assert.rejects(controller.dispatch(f.issue(f.workOrder())), { code: 'limit-reached' });
  assert.equal(f.state.dispatches, 0);
});

test('required admission storage failure blocks effects', async (t) => {
  const f = await fixture(t);
  const broken = new ExecutionController({
    ...f.composition,
    store: {
      readRun: (id) => f.store.readRun(id),
      async commitRun() { return { status: 'failed', error: { code: 'persistence-failed', message: 'TEST disk full', retry: 'never', fields: [] } }; },
    },
  });

  await t.test('SQLite admission serializes distinct workspace runs before either can dispatch concurrently', async (t) => {
    const f = await fixture(t);
    let release;
    let started;
    const gate = new Promise((resolve) => { release = resolve; });
    const admitted = new Promise((resolve) => { started = resolve; });
    const dispatch = f.host.dispatch;
    f.host.dispatch = async (work, token) => { started(); await gate; return dispatch(work, token); };
    const first = f.controller.dispatch(f.issue(f.workOrder()));
    await admitted;
    try {
      const other = f.issue(f.workOrder({ id: 'WRK-other', runId: 'RUN-other' }));
      await assert.rejects(f.controller.dispatch(other), { code: 'persistence-failed' });
      assert.equal(ok(await f.store.readRun('RUN-other')), null);
    } finally { release(); }
    await first;
    assert.equal(f.state.dispatches, 1);
  });

  await t.test('post-dispatch persistence failure is unknown, requests stop and leaves no fabricated durable success', async (t) => {
    const f = await fixture(t);
    let commits = 0;
    const controller = new ExecutionController({
      ...f.composition,
      store: {
        readRun: (id) => f.store.readRun(id),
        async commitRun(input) {
          if (++commits > 1) return { status: 'failed', error: { code: 'persistence-failed', message: 'TEST disk full after dispatch', retry: 'never', fields: [] } };
          return f.store.commitRun(input);
        },
      },
    });
    await assert.rejects(controller.dispatch(f.issue(f.workOrder())), { code: 'effect-outcome-unknown' });
    assert.equal(f.state.dispatches, 1);
    assert.equal(f.state.stops, 1);
    const snapshot = ok(await f.store.readRun('RUN-test')).snapshot;
    assert.equal(snapshot.state, 'running');
    assert.equal(snapshot.quiescence, 'unconfirmed');
    assert.deepEqual(snapshot.attempts, []);
  });
  await assert.rejects(broken.dispatch(f.issue(f.workOrder())), { code: 'persistence-failed' });
  assert.equal(f.state.dispatches, 0);
});

test('host failures leave durable unknown outcome and cancellation does not invent an attempt', async (t) => {
  const f = await fixture(t);
  f.state.failure = new Error('TEST host interruption');
  f.state.stopUnknown = true;
  const work = f.issue(f.workOrder());
  await assert.rejects(f.controller.dispatch(work), { code: 'effect-outcome-unknown' });
  let snapshot = await f.controller.status('RUN-test');
  assert.equal(snapshot.state, 'outcome-unknown');
  assert.equal(snapshot.quiescence, 'unconfirmed');
  assert.equal(snapshot.attempts.length, 0);
  assert.equal(f.state.stops, 1);
  await assert.rejects(f.controller.dispatch(f.issue(f.workOrder())), { code: 'conflict' });
  f.state.stopUnknown = false;
  await assert.rejects(f.controller.control('RUN-test', 'cancel', { id: 'APR-untrusted' }), { code: 'authority-required' });
  snapshot = await f.controller.control('RUN-test', 'cancel', work.approval);
  assert.equal(snapshot.state, 'quiesced');
  assert.equal(snapshot.quiescence, 'confirmed');
  assert.equal(snapshot.activeTask, null);
  assert.equal(snapshot.attempts.length, 0);
});

test('no-progress failure stops earlier than the repair bound', async (t) => {
  const f = await fixture(t);
  f.state.exitCode = 1;
  f.state.after = f.state.source;
  await f.controller.dispatch(f.issue(f.workOrder()));
  await assert.rejects(f.controller.dispatch(f.issue(f.workOrder())), { code: 'limit-reached' });
  assert.equal(f.state.dispatches, 1);
});

test('material scope changes require reapproval and at most two repairs persist in the original run', async (t) => {
  const f = await fixture(t);
  f.state.exitCode = 1;
  let last;
  for (let index = 0; index < 3; index++) {
    f.state.after = digestContent(`TEST scoped revision ${index}`);
    const work = f.workOrder({ mode: 'auto' });
    if (last) {
      await assert.rejects(f.controller.dispatch({ ...work, approval: last.approval }), { code: 'scope-exceeded' });
    }
    last = f.issue(work);
    const snapshot = await f.controller.dispatch(last);
    assert.equal(snapshot.admissions.length, index + 1);
    assert.equal(snapshot.attempts.length, index + 1);
    if (index > 0) assert.equal(snapshot.attempts[index].sequence.number, index);
  }
  f.state.after = digestContent('would exceed scope');
  await assert.rejects(f.controller.dispatch(f.issue(f.workOrder())), { code: 'limit-reached' });
  assert.equal(f.state.dispatches, 3);
});

test('admission audit is append-only across durable snapshot revisions', async (t) => {
  const f = await fixture(t);
  const snapshot = await f.controller.dispatch(f.issue(f.workOrder()));
  const current = ok(await f.store.readRun('RUN-test'));
  const tampered = { ...snapshot, admissions: [{ ...snapshot.admissions[0], requestDigest: digestContent('different request') }] };
  const result = await f.store.commitRun({ expectedRevision: current.revision, snapshot: tampered, attempts: [], evidence: [] });
  assert.notEqual(result.status, 'ok');
  assert.deepEqual(ok(await f.store.readRun('RUN-test')).snapshot, snapshot);
});

test('dependent tasks do not become admissible from a host completion claim', async (t) => {
  const f = await fixture(t);
  const work = f.workOrder();
  const task = { ...work.task, dependsOn: ['TSK-prior'] };
  const controller = new ExecutionController({ ...f.composition, observe: async () => ({ revisions: work.revisions, task, ready: true }) });
  await assert.rejects(controller.dispatch(f.issue({ ...work, task })), { code: 'evidence-unavailable' });
  assert.equal(f.state.dispatches, 0);
});
