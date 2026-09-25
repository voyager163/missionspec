import { digestApprovalRequest, parseApprovalRequest } from '../kernel/authority.js';
import type { ApprovalReference } from '../kernel/authority.js';
import { parseId, type EvidenceId, type RunId } from '../kernel/identifiers.js';
import { digestContent, sameRevisionBinding, type RevisionBinding } from '../kernel/revisions.js';
import { parseExecutionPlan, parseWorkOrder, type ExecutionPlan, type AttemptRecord, type RunSnapshot, type WorkOrder } from '../engines/execution/contracts.js';
import type { PlannedCheck, TaskDefinition } from '../engines/planning/contracts.js';
import type { CheckObservation } from '../engines/verification/contracts.js';
import type { ClockPort, CodingHostPort, LocalAuthorityPort, RuntimeStorePort } from '../ports/contracts.js';
import { parseAttempt } from '../adapters/persistence/parsers.js';
import { requireApproval, unavailableAuthority } from './authority.js';
import { WorkflowError } from './errors.js';

export const unavailableCodingHost = Object.freeze<CodingHostPort>({
  async inspect(host) { return { status: 'ok', value: { state: 'unqualified', host, reason: 'No exact native host/version/permission/cancellation channel is qualified.' } }; },
  async dispatch() { return { status: 'blocked', error: { code: 'host-unqualified', message: 'Native host dispatch is disabled.', retry: 'never', fields: [] } }; },
  async requestStop() { return { status: 'ok', value: { state: 'outcome-unknown', reason: 'No qualified cancellation channel.' } }; },
});

export function executionApprovalRequest(input: WorkOrder) {
  const work = parseWorkOrder(input);
  return parseApprovalRequest({
    contractVersion: 1, state: 'untrusted-request', operation: 'implement', purpose: 'execution',
    binding: { kind: 'change', revisions: work.revisions }, effects: work.effects,
    execution: { mode: work.mode, host: work.host, limits: work.limits }, runId: work.runId, workOrderId: work.id,
  });
}

export function executionPlanApprovalRequest(input: ExecutionPlan) {
  const plan = parseExecutionPlan(input);
  return parseApprovalRequest({
    ...executionApprovalRequest(plan.orders[0]!),
    executionPlan: digestContent(JSON.stringify(plan.orders.map(({ approval: _approval, ...work }) => work))),
  });
}

export interface ExecutionObservation {
  readonly revisions: RevisionBinding;
  readonly task: TaskDefinition;
  readonly ready: boolean;
  readonly checks?: readonly PlannedCheck[];
}

export class ExecutionController {
  private readonly host: CodingHostPort;
  private readonly authority: LocalAuthorityPort;
  private readonly clock: ClockPort;

  constructor(private readonly composition: {
    readonly store: RuntimeStorePort;
    readonly observe: (workOrder: WorkOrder, phase: 'before' | 'after') => Promise<ExecutionObservation>;
    readonly host?: CodingHostPort;
    readonly authority?: LocalAuthorityPort;
    readonly clock?: ClockPort;
    readonly verifyTask?: (workOrder: WorkOrder, snapshot: RunSnapshot) => Promise<readonly CheckObservation[]>;
    readonly readEvidence?: (id: EvidenceId) => Promise<CheckObservation>;
  }) {
    this.host = composition.host ?? unavailableCodingHost;
    this.authority = composition.authority ?? unavailableAuthority;
    this.clock = composition.clock ?? { wallTime: () => new Date().toISOString(), monotonicMilliseconds: () => performance.now() };
  }

  async status(id: RunId): Promise<RunSnapshot> {
    const result = await this.composition.store.readRun(parseId('run', id));
    if (result.status !== 'ok' || result.value === null) throw new WorkflowError('not-found', 'The durable run is unavailable.');
    return result.value.snapshot;
  }

  private async persist(expectedRevision: Parameters<RuntimeStorePort['commitRun']>[0]['expectedRevision'], snapshot: RunSnapshot, attempts: readonly AttemptRecord[] = []) {
    const result = await this.composition.store.commitRun({ expectedRevision, snapshot, attempts, evidence: [] });
    if (result.status !== 'ok') throw new WorkflowError('persistence-failed', 'Required execution state could not be durably persisted; dispatch is blocked.');
    return result.value.revision;
  }

  async dispatch(input: WorkOrder): Promise<RunSnapshot> {
    return this.dispatchWork(input);
  }

  private async dispatchWork(input: WorkOrder, plan?: ExecutionPlan, planApproval?: ApprovalReference): Promise<RunSnapshot> {
    const work = parseWorkOrder(input);
    const request = plan === undefined ? executionApprovalRequest(work) : executionPlanApprovalRequest(plan);
    const approval = planApproval ?? work.approval;
    const approved = await requireApproval(this.authority, approval, request, this.clock.wallTime());
    const qualification = await this.host.inspect(work.host);
    if (qualification.status !== 'ok' || qualification.value.state !== 'qualified' ||
        qualification.value.host !== work.host || qualification.value.exactVersion.trim() === '' ||
        qualification.value.cancellation !== 'confirmed-quiescence' ||
        qualification.value.dispatchFencing !== 'durable-admission-token' ||
        qualification.value.permissions !== 'exact-effect-scope') {
      throw new WorkflowError('host-unqualified', 'The exact host/version must have qualified hard limits, scoped permissions and confirmed cancellation.');
    }
    const qualified = qualification.value;
    if (!['darwin', 'linux', 'win32'].includes(process.platform) || Object.values(qualified.limits).length !== 4 ||
        !['maxTasks', 'maxDurationMs', 'maxRepairsPerTask', 'concurrency'].every((key) => Reflect.get(qualified.limits, key) === 'hard') ||
        qualified.operatingSystem !== (process.platform === 'darwin' ? 'macos' : process.platform === 'linux' ? 'linux' : 'windows')) {
      throw new WorkflowError('host-unqualified', 'The selected host does not enforce all approved limits on this operating system.');
    }
    const observation = await this.composition.observe(work, 'before');
    if (!observation.ready || !sameRevisionBinding(observation.revisions, work.revisions) ||
        JSON.stringify(observation.task) !== JSON.stringify(work.task)) {
      throw new WorkflowError('stale-revision', 'Live task, artifact, workspace, source or effect scope differs from the reviewed work order.');
    }
    const dispatches = work.effects.filter((effect) => effect.kind === 'host-dispatch');
    if (dispatches.length !== 1 || dispatches[0]!.host !== work.host || dispatches[0]!.taskIds.length !== 1 ||
        dispatches[0]!.taskIds[0] !== work.task.id || work.effects.some((effect) =>
          effect.kind === 'context-consume' || effect.kind === 'runtime-state' ||
          ((effect.kind === 'file-write' || effect.kind === 'file-remove') &&
            (effect.purpose !== 'source' || !work.task.writeScope.includes(effect.path))) ||
          (effect.kind === 'check-execute' && !work.task.checks.includes(effect.checkId)))) {
      throw new WorkflowError('scope-exceeded', 'A work order admits only its exact task, source files and planned checks.');
    }
    const previous = await this.composition.store.readRun(work.runId);
    if (previous.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot observe the run admission state.');
    const prior = previous.value?.snapshot;
    const priorAdmission = prior?.admissions?.[0];
    const attempts = prior?.attempts ?? [];
    const last = attempts.at(-1);
    let sequence: AttemptRecord['sequence'] = { kind: 'initial' };
    let verifiedFailure = false;
    if (prior !== undefined && last?.observation.state === 'host-returned' && last.observation.exitCode === 0 &&
        this.composition.readEvidence !== undefined) {
      const evidenceIds = await this.composition.store.readRunEvidence(work.runId);
      if (evidenceIds.status !== 'ok') throw new WorkflowError('evidence-unavailable', 'Repair evidence inventory is unavailable.');
      for (const id of evidenceIds.value) {
        const stored = await this.composition.store.readEvidence(id);
        if (stored.status !== 'ok') throw new WorkflowError('evidence-unavailable', 'Repair evidence could not be read.');
        if (stored.value === null || !work.task.checks.includes(stored.value.checkId) ||
            !sameRevisionBinding(stored.value.revisions, prior.revisions) || stored.value.source !== work.sourceBefore) continue;
        const check = observation.checks?.find((check) => check.id === stored.value!.checkId);
        const observed = await this.composition.readEvidence(id);
        if (observed.state === 'observed' && observed.result === 'failed' && check?.kind === observed.basis &&
            check.definition === stored.value.checkDefinition && stored.value.storage.state === 'retained' &&
            JSON.stringify(observed.evidence) === JSON.stringify(stored.value)) verifiedFailure = true;
      }
    }
    const advancing = prior !== undefined && plan !== undefined && !prior.admissions?.some((entry) => entry.workOrder.task.id === work.task.id);
    if (advancing) {
      if (prior.quiescence !== 'confirmed' || prior.state !== 'paused' || prior.plan === undefined ||
          JSON.stringify(prior.replans?.at(-1)?.plan ?? prior.plan) !== JSON.stringify(plan) ||
          work.task.dependsOn.some((id) => !prior.completions?.some((entry) => entry.taskId === id)) ||
          prior.admissions?.some((entry) => !prior.completions?.some((completion) => completion.taskId === entry.workOrder.task.id))) {
        throw new WorkflowError('evidence-unavailable', 'Dependent tasks require durable verified predecessor evidence and quiescence.');
      }
      await this.dependenciesIntact(work, prior);
    } else if (prior !== undefined) {
      if (prior.state !== 'paused' || prior.quiescence !== 'confirmed' || priorAdmission === undefined ||
          last?.observation.state !== 'host-returned' || last.observation.exitCode === 0 && !verifiedFailure ||
          prior.activeTask !== work.task.id || last.workOrderId !== work.id ||
          prior.admissions?.at(-1)?.workOrder.task.id !== work.task.id) {
        throw new WorkflowError('conflict', 'Resume requires a quiescent failed task and explicit scoped repair review; claims never advance tasks.');
      }
      if (work.task.dependsOn.length > 0) await this.dependenciesIntact(work, prior);
      const latest = prior.admissions!.at(-1)!;
      if (Date.parse(this.clock.wallTime()) < Date.parse(latest.admittedAt)) {
        throw new WorkflowError('limit-reached', 'Wall time moved backwards relative to durable admission; review timing before resuming.');
      }
      if (last.observation.sourceAfter === latest.workOrder.sourceBefore) throw new WorkflowError('limit-reached', 'No-progress failure stops repair; revise the plan instead.');
      const repairs = attempts.filter((attempt) => attempt.workOrderId === work.id && attempt.sequence.kind === 'repair').length;
      if (repairs >= Math.min(work.limits.maxRepairsPerTask, priorAdmission.workOrder.limits.maxRepairsPerTask) || repairs >= 2) {
        throw new WorkflowError('limit-reached', 'The approved repair bound is exhausted.');
      }
      if (work.limits.maxTasks > priorAdmission.workOrder.limits.maxTasks ||
          work.limits.maxDurationMs > priorAdmission.workOrder.limits.maxDurationMs -
            (Date.parse(this.clock.wallTime()) - Date.parse(priorAdmission.admittedAt)) ||
          work.limits.maxRepairsPerTask > priorAdmission.workOrder.limits.maxRepairsPerTask ||
          Date.parse(this.clock.wallTime()) - Date.parse(priorAdmission.admittedAt) >= priorAdmission.workOrder.limits.maxDurationMs) {
        throw new WorkflowError('limit-reached', 'A run cannot extend its original task, repair or duration limits.');
      }
      sequence = { kind: 'repair', number: (repairs + 1) as 1 | 2, failedAttempt: last.id };
    } else if (work.task.dependsOn.length > 0) {
      throw new WorkflowError('evidence-unavailable', 'Dependent-task scheduling requires verified dependency evidence; automatic advancement is unavailable.');
    }
    let elapsedBefore = 0;
    if (priorAdmission !== undefined) {
      const now = Date.parse(this.clock.wallTime());
      const elapsed = Math.max(prior?.elapsedMs ?? 0, now - Date.parse(priorAdmission.admittedAt));
      elapsedBefore = elapsed;
      if (elapsed < 0 || work.limits.maxDurationMs > priorAdmission.workOrder.limits.maxDurationMs - elapsed ||
          now < Date.parse(prior?.observedAt ?? priorAdmission.admittedAt) ||
          (new Set((prior?.admissions ?? []).map((entry) => entry.workOrder.task.id)).size + (advancing ? 1 : 0)) > priorAdmission.workOrder.limits.maxTasks) {
        throw new WorkflowError('limit-reached', 'The original run task and wall-duration limits cannot be extended.');
      }
    }
    const start = this.clock.monotonicMilliseconds();
    if (!Number.isFinite(start) || start < 0) throw new WorkflowError('limit-reached', 'A valid monotonic execution clock is required.');
    const dispatchToken = digestContent(JSON.stringify({
      request: digestApprovalRequest(request), predecessor: previous.value?.revision ?? 'absent', sequence,
    }));
    let snapshot: RunSnapshot = {
      contractVersion: 1, id: work.runId, revisions: work.revisions, state: 'running', activeTask: work.task.id,
      pendingTasks: (plan ?? prior?.plan)?.orders.filter((order) => order.task.id !== work.task.id && !prior?.completions?.some((entry) => entry.taskId === order.task.id)).map((order) => order.task.id) ?? [],
      attempts, quiescence: 'unconfirmed',
      elapsedMs: elapsedBefore, observedAt: this.clock.wallTime(),
      ...((plan ?? prior?.plan) === undefined ? {} : { plan: (prior?.plan ?? plan)! }),
      ...(prior?.replans === undefined ? {} : { replans: prior.replans }),
      ...(prior?.completions === undefined ? {} : { completions: prior.completions }),
      ...(prior?.reconciliations === undefined ? {} : { reconciliations: prior.reconciliations }),
      admissions: [...(prior?.admissions ?? []), {
        workOrder: work, requestDigest: digestApprovalRequest(approved.request),
        dispatchToken,
        qualificationEvidence: qualification.value.evidence, admittedAt: this.clock.wallTime(),
        authorization: request,
      }],
    };
    let revision = await this.persist(previous.value?.revision ?? 'absent', snapshot);
    try {
      await requireApproval(this.authority, approval, request, this.clock.wallTime());
      const again = await this.composition.observe(work, 'before');
      if (!again.ready || !sameRevisionBinding(again.revisions, work.revisions) || JSON.stringify(again.task) !== JSON.stringify(work.task)) {
        throw new WorkflowError('stale-revision', 'The observed scope changed after durable admission.');
      }
      const admission = await this.composition.store.readRun(work.runId);
      if (admission.status !== 'ok' || admission.value?.revision !== revision ||
          admission.value.snapshot.state !== 'running' ||
          admission.value.snapshot.admissions?.at(-1)?.dispatchToken !== dispatchToken) {
        throw new WorkflowError('conflict', 'Dispatch admission changed or was cancelled before hand-off.');
      }
      // A qualified port, not model text, owns dispatch and hard enforcement.
      const result = await this.host.dispatch(work, dispatchToken);
      if (result.status !== 'ok') throw new WorkflowError('effect-outcome-unknown', 'The host did not return a qualified terminal observation.');
      const attempt = parseAttempt(result.value);
      if (attempt.workOrderId !== work.id || JSON.stringify(attempt.sequence) !== JSON.stringify(sequence) ||
          attempt.observation.state !== 'host-returned') {
        throw new WorkflowError('effect-outcome-unknown', 'The host returned an unexpected attempt identity, sequence or nonterminal observation.');
      }
      const after = await this.composition.observe(work, 'after');
      const elapsed = this.clock.monotonicMilliseconds() - start;
      const finishedAt = this.clock.wallTime();
      if (attempt.observation.sourceAfter !== after.revisions.source ||
          !sameRevisionBinding({ ...after.revisions, source: work.revisions.source }, work.revisions) ||
          JSON.stringify(after.task) !== JSON.stringify(work.task) ||
          !Number.isFinite(elapsed) || elapsed < 0 || elapsed >= work.limits.maxDurationMs ||
          elapsedBefore + Math.ceil(elapsed) >= snapshot.admissions![0]!.workOrder.limits.maxDurationMs ||
          Date.parse(finishedAt) < Date.parse(snapshot.observedAt!) ||
          Date.parse(this.clock.wallTime()) - Date.parse(snapshot.admissions![0]!.admittedAt) >= snapshot.admissions![0]!.workOrder.limits.maxDurationMs) {
        throw new WorkflowError('effect-outcome-unknown', 'The observed effects differ from the qualified terminal result or approved duration.');
      }
      snapshot = {
        ...snapshot, state: 'paused', quiescence: 'confirmed', revisions: after.revisions,
        elapsedMs: elapsedBefore + Math.ceil(elapsed), observedAt: finishedAt,
        attempts: [...attempts, attempt],
      };
      revision = await this.persist(revision, snapshot, [attempt]);
      return snapshot;
    } catch {
      let quiescence: RunSnapshot['quiescence'] = 'unconfirmed';
      try {
        const stopped = await this.host.requestStop(work.id, dispatchToken);
        if (stopped.status === 'ok' && stopped.value.state === 'quiesced' &&
            stopped.value.dispatchToken === dispatchToken) quiescence = 'confirmed';
      } catch { /* Failure to cancel is not proof that effects stopped. */ }
      snapshot = { ...snapshot, state: 'outcome-unknown', quiescence };
      try { await this.persist(revision, snapshot); } catch { /* The last durable admission remains nonterminal. */ }
      throw new WorkflowError('effect-outcome-unknown', 'Dispatch or outcome persistence failed. No further task or repair is admitted until reconciliation.');
    }
  }

  async control(id: RunId, action: 'pause' | 'cancel', approval: ApprovalReference): Promise<RunSnapshot> {
    const result = await this.composition.store.readRun(parseId('run', id));
    if (result.status !== 'ok' || result.value === null) throw new WorkflowError('not-found', 'The durable run is unavailable.');
    const prior = result.value.snapshot;
    const admission = prior.admissions?.at(-1);
    if (admission?.dispatchToken === undefined) throw new WorkflowError('capability-unavailable', 'This snapshot lacks a qualified durable dispatch fence.');
    if (action !== 'pause' && action !== 'cancel') throw new WorkflowError('invalid-input', 'Choose pause or cancel.');
    await requireApproval(this.authority, approval, admission.authorization ?? executionApprovalRequest(admission.workOrder), this.clock.wallTime());
    let snapshot: RunSnapshot = { ...prior, state: 'paused' };
    const revision = await this.persist(result.value.revision, snapshot);
    if (snapshot.quiescence !== 'confirmed') {
      let qualifiedStop = false;
      try {
        const current = await this.host.inspect(admission.workOrder.host);
        qualifiedStop = current.status === 'ok' && current.value.state === 'qualified' &&
          current.value.host === admission.workOrder.host &&
          current.value.evidence === admission.qualificationEvidence &&
          current.value.cancellation === 'confirmed-quiescence' &&
          current.value.dispatchFencing === 'durable-admission-token';
      } catch { /* An unavailable qualification cannot establish quiescence. */ }
      let stopped;
      try { stopped = await this.host.requestStop(admission.workOrder.id, admission.dispatchToken); } catch { stopped = null; }
      snapshot = qualifiedStop && stopped?.status === 'ok' && stopped.value.state === 'quiesced' &&
        stopped.value.dispatchToken === admission.dispatchToken
        ? { ...snapshot, quiescence: 'confirmed' }
        : { ...snapshot, state: 'outcome-unknown', quiescence: 'unconfirmed' };
    }
    if (action === 'cancel' && snapshot.quiescence === 'confirmed') snapshot = { ...snapshot, state: 'quiesced', activeTask: null, pendingTasks: [] };
    await this.persist(revision, snapshot);
    return snapshot;
  }

  /** Trusted verification composition reads retained bytes; an exit code or checkbox is never a completion. */
  private async dependenciesIntact(work: WorkOrder, snapshot: RunSnapshot): Promise<void> {
    const ids = await this.composition.store.readRunEvidence(work.runId);
    if (ids.status !== 'ok') throw new WorkflowError('evidence-unavailable', 'Dependency evidence inventory is unavailable.');
    for (const taskId of work.task.dependsOn) {
      const completion = snapshot.completions?.find((entry) => entry.taskId === taskId);
      if (completion === undefined || this.composition.readEvidence === undefined) throw new WorkflowError('evidence-unavailable', 'Dependency verification requires a trusted retained-byte reader.');
      for (const id of completion.evidence) {
        const observed = await this.composition.readEvidence(id);
        const stored = await this.composition.store.readEvidence(id);
        if (!ids.value.includes(id) || observed.state !== 'observed' || observed.result !== 'passed' ||
            stored.status !== 'ok' || stored.value === null || stored.value.source !== completion.source ||
            stored.value.storage.state !== 'retained' || JSON.stringify(stored.value) !== JSON.stringify(observed.evidence)) {
          throw new WorkflowError('evidence-unavailable', 'Dependency evidence is no longer retained, verified or bound to its recorded completion.');
        }
      }
    }
  }

  private async certify(work: WorkOrder, snapshot: RunSnapshot): Promise<RunSnapshot> {
    if (this.composition.verifyTask === undefined || work.task.checks.length === 0) return snapshot;
    const observations = await this.composition.verifyTask(work, snapshot);
    const current = await this.composition.observe(work, 'after');
    if (!current.ready || !sameRevisionBinding(current.revisions, snapshot.revisions)) throw new WorkflowError('stale-revision', 'Verification changed the live source or intent.');
    const ids: EvidenceId[] = [];
    const recorded = await this.composition.store.readRunEvidence(work.runId);
    if (recorded.status !== 'ok') throw new WorkflowError('persistence-failed', 'Dependency evidence ledger is unavailable.');
    for (const id of work.task.checks) {
      const candidates = observations.filter((observation) => observation.checkId === id);
      const observation = candidates[0];
      const check = current.checks?.find((entry) => entry.id === id);
      if (candidates.length !== 1 || observation?.state !== 'observed' || observation.result !== 'passed' ||
          check === undefined || observation.basis !== check.kind || observation.evidence.checkDefinition !== check.definition ||
          !recorded.value.includes(observation.evidence.id)) return snapshot;
      const stored = await this.composition.store.readEvidence(observation.evidence.id);
      if (stored.status !== 'ok' || stored.value === null || JSON.stringify(stored.value) !== JSON.stringify(observation.evidence) ||
          stored.value.storage.state !== 'retained' || stored.value.source !== snapshot.revisions.source ||
          !sameRevisionBinding(stored.value.revisions, snapshot.revisions)) throw new WorkflowError('evidence-unavailable', 'Verified dependency evidence is stale or not retained in this run.');
      ids.push(stored.value.id);
    }
    const durable = await this.composition.store.readRun(work.runId);
    if (durable.status !== 'ok' || durable.value === null || durable.value.snapshot.state !== 'paused' ||
        durable.value.snapshot.quiescence !== 'confirmed' || !sameRevisionBinding(durable.value.snapshot.revisions, snapshot.revisions)) {
      throw new WorkflowError('conflict', 'Run changed during dependency verification.');
    }
    const attempt = snapshot.attempts.at(-1)!;
    const next: RunSnapshot = { ...durable.value.snapshot, activeTask: null, completions: [
      ...(snapshot.completions ?? []), { taskId: work.task.id, workOrderId: work.id, attemptId: attempt.id, source: snapshot.revisions.source, evidence: ids },
    ] };
    await this.persist(durable.value.revision, next);
    return next;
  }

  async runPlan(input: ExecutionPlan, approval: ApprovalReference): Promise<RunSnapshot> {
    const plan = parseExecutionPlan(input);
    const first = plan.orders[0]!;
    await requireApproval(this.authority, approval, executionPlanApprovalRequest(plan), this.clock.wallTime());
    const durable = await this.composition.store.readRun(first.runId);
    if (durable.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot read reviewed execution plan state.');
    let snapshot = durable.value?.snapshot;
    if (snapshot !== undefined && (snapshot.plan === undefined || JSON.stringify(snapshot.replans?.at(-1)?.plan ?? snapshot.plan) !== JSON.stringify(plan) ||
        snapshot.quiescence !== 'confirmed' || snapshot.state !== 'paused')) {
      throw new WorkflowError('conflict', 'Resume requires the identical reviewed plan and reconciled, quiescent state.');
    }
    for (const original of plan.orders) {
      if (snapshot?.completions?.some((entry) => entry.taskId === original.task.id)) continue;
      const started = snapshot?.admissions?.[0]?.admittedAt;
      const remaining = first.limits.maxDurationMs - Math.max(snapshot?.elapsedMs ?? 0, started === undefined ? 0 : Date.parse(this.clock.wallTime()) - Date.parse(started));
      if (remaining <= 0 || remaining > first.limits.maxDurationMs) throw new WorkflowError('limit-reached', 'Reviewed run duration is exhausted or clock moved backwards.');
      const work = parseWorkOrder({ ...original, approval, limits: { ...original.limits, maxDurationMs: remaining } });
      const admission = snapshot?.admissions?.findLast((entry) => entry.workOrder.task.id === work.task.id);
      if (admission === undefined) snapshot = await this.dispatchWork(work, plan, approval);
      else if (snapshot?.attempts.at(-1)?.workOrderId !== work.id) throw new WorkflowError('conflict', 'Unverified admitted work cannot be automatically retried.');
      if (snapshot === undefined) throw new WorkflowError('conflict', 'Missing durable attempt.');
      snapshot = await this.certify(admission?.workOrder ?? work, snapshot);
      if (!snapshot.completions?.some((entry) => entry.taskId === work.task.id) ||
          first.mode === 'interactive' && snapshot.completions.length < plan.orders.length) return snapshot;
    }
    if (snapshot === undefined) throw new WorkflowError('conflict', 'No reviewed work was admitted.');
    const latest = await this.composition.store.readRun(first.runId);
    if (latest.status !== 'ok' || latest.value === null) throw new WorkflowError('persistence-failed', 'Cannot close completed scheduling.');
    const next: RunSnapshot = { ...snapshot, state: 'quiesced', activeTask: null, pendingTasks: [] };
    await this.persist(latest.value.revision, next);
    return next;
  }

  async reapprovePlan(input: ExecutionPlan, approval: ApprovalReference): Promise<RunSnapshot> {
    const plan = parseExecutionPlan(input);
    const first = plan.orders[0]!;
    await requireApproval(this.authority, approval, executionPlanApprovalRequest(plan), this.clock.wallTime());
    const result = await this.composition.store.readRun(first.runId);
    if (result.status !== 'ok' || result.value?.snapshot.plan === undefined) throw new WorkflowError('not-found', 'No durable reviewed plan exists.');
    const prior = result.value.snapshot;
    const original = prior.plan!;
    const elapsed = Math.max(prior.elapsedMs ?? 0, Date.parse(this.clock.wallTime()) - Date.parse(prior.admissions![0]!.admittedAt));
    if (prior.state !== 'paused' || prior.quiescence !== 'confirmed' || elapsed < 0 ||
        Date.parse(this.clock.wallTime()) < Date.parse(prior.observedAt ?? prior.admissions![0]!.admittedAt) ||
        elapsed >= original.orders[0]!.limits.maxDurationMs ||
        first.limits.maxDurationMs > original.orders[0]!.limits.maxDurationMs ||
        first.limits.maxRepairsPerTask > original.orders[0]!.limits.maxRepairsPerTask ||
        first.limits.maxTasks > original.orders[0]!.limits.maxTasks ||
        plan.orders.length !== original.orders.length ||
        plan.orders.some((order, index) => {
          const previous = original.orders[index]!;
          return order.id !== previous.id || JSON.stringify(order.task) !== JSON.stringify(previous.task) ||
            !sameRevisionBinding({ ...order.revisions, source: previous.revisions.source, effects: previous.revisions.effects }, previous.revisions);
        })) {
      throw new WorkflowError('scope-exceeded', 'Reapproval may revise exact remaining source effects, not reset timing, task identity, intent or repair limits. Changed intent needs a separately reviewed new run.');
    }
    const next = { ...prior, replans: [...(prior.replans ?? []), {
      plan, approval, requestDigest: digestApprovalRequest(executionPlanApprovalRequest(plan)), approvedAt: this.clock.wallTime(),
    }] };
    await this.persist(result.value.revision, next);
    return next;
  }

  async reconcile(id: RunId, approval: ApprovalReference): Promise<RunSnapshot> {
    const result = await this.composition.store.readRun(id);
    if (result.status !== 'ok' || result.value === null) throw new WorkflowError('not-found', 'Run is unavailable.');
    const prior = result.value.snapshot;
    const admission = prior.admissions?.at(-1);
    if (!['running', 'outcome-unknown', 'paused'].includes(prior.state)) throw new WorkflowError('conflict', 'Only a nonterminal admitted attempt can be reconciled.');
    if (admission?.dispatchToken === undefined || this.host.inspectDispatch === undefined) throw new WorkflowError('capability-unavailable', 'Reconciliation requires qualified durable-token inspection, not a client claim.');
    if (Date.parse(this.clock.wallTime()) < Date.parse(prior.observedAt ?? admission.admittedAt)) throw new WorkflowError('limit-reached', 'Clock rollback must be resolved before reconciliation.');
    await requireApproval(this.authority, approval, admission.authorization ?? executionApprovalRequest(admission.workOrder), this.clock.wallTime());
    const qualification = await this.host.inspect(admission.workOrder.host);
    if (qualification.status !== 'ok' || qualification.value.state !== 'qualified' ||
        qualification.value.evidence !== admission.qualificationEvidence || qualification.value.dispatchFencing !== 'durable-admission-token' ||
        qualification.value.cancellation !== 'confirmed-quiescence') throw new WorkflowError('host-unqualified', 'Reconciliation needs the original exact host qualification.');
    const observed = await this.host.inspectDispatch(admission.workOrder, admission.dispatchToken);
    if (observed.status !== 'ok' || observed.value.state !== 'fenced-terminal' || observed.value.dispatchToken !== admission.dispatchToken) {
      throw new WorkflowError('effect-outcome-unknown', 'No qualified terminal inspection is available; retry remains blocked.');
    }
    const attempt = parseAttempt(observed.value.attempt);
    const live = await this.composition.observe(admission.workOrder, 'after');
    if (attempt.workOrderId !== admission.workOrder.id || attempt.observation.state !== 'host-returned' ||
        attempt.observation.sourceAfter !== live.revisions.source || !live.ready ||
        !sameRevisionBinding({ ...live.revisions, source: admission.workOrder.sourceBefore }, admission.workOrder.revisions)) {
      throw new WorkflowError('effect-outcome-unknown', 'Inspected terminal effects differ from reviewed scope.');
    }
    const exists = prior.attempts.some((entry) => entry.id === attempt.id);
    if (exists && !prior.attempts.some((entry) => JSON.stringify(entry) === JSON.stringify(attempt))) {
      throw new WorkflowError('effect-outcome-unknown', 'Inspection cannot rewrite an existing immutable attempt.');
    }
    if (!exists) {
      const previous = prior.attempts.filter((entry) => entry.workOrderId === attempt.workOrderId);
      const sequence = previous.length === 0 ? { kind: 'initial' } :
        { kind: 'repair', number: previous.length, failedAttempt: previous.at(-1)!.id };
      if (JSON.stringify(attempt.sequence) !== JSON.stringify(sequence)) throw new WorkflowError('effect-outcome-unknown', 'Inspection has the wrong admitted repair sequence.');
    }
    const snapshot: RunSnapshot = {
      ...prior, state: 'paused', quiescence: 'confirmed', revisions: live.revisions,
      elapsedMs: Math.max((prior.elapsedMs ?? 0) + (exists ? 0 : Date.parse(attempt.observation.finishedAt) - Date.parse(attempt.observation.startedAt)),
        Date.parse(this.clock.wallTime()) - Date.parse(prior.admissions![0]!.admittedAt)),
      observedAt: this.clock.wallTime(),
      attempts: exists ? prior.attempts : [...prior.attempts, attempt],
      reconciliations: [...(prior.reconciliations ?? []), { dispatchToken: admission.dispatchToken, evidence: observed.value.evidence, recordedAt: this.clock.wallTime() }],
    };
    await this.persist(result.value.revision, snapshot, exists ? [] : [attempt]);
    return snapshot;
  }
}
