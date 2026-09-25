import { parseApprovalReference, parseExecutionLimits, parseExecutionMode, type ApprovalReference, type ApprovalRequest, type ExecutionLimits, type ExecutionMode } from '../../kernel/authority.js';
import { digestEffectScope, parseEffectScope, type RequestedEffect } from '../../kernel/effects.js';
import { parseId, parseNativeHost, type AttemptId, type EvidenceId, type NativeHost, type RunId, type TaskId, type WorkOrderId } from '../../kernel/identifiers.js';
import type { DomainError, ExecutionState, Outcome } from '../../kernel/outcomes.js';
import { parseContractVersion, type Versioned } from '../../kernel/protocol.js';
import { parseDigest, parseRevisionBinding, type ContentDigest, type RevisionBinding } from '../../kernel/revisions.js';
import { orderTaskDefinitions, parseTaskDefinition, type TaskDefinition } from '../planning/contracts.js';
import { array, ContractError, record, unique } from '../../kernel/validation.js';

/** Exact, already-known effects. A task writeScope is not permission to invent new proposed bytes. */
export interface WorkOrder extends Versioned {
  readonly id: WorkOrderId;
  readonly runId: RunId;
  readonly task: TaskDefinition;
  readonly revisions: RevisionBinding;
  readonly sourceBefore: ContentDigest;
  readonly approval: ApprovalReference;
  readonly mode: ExecutionMode;
  readonly host: NativeHost;
  readonly limits: ExecutionLimits;
  readonly effects: readonly RequestedEffect[];
}

export interface AttemptRecord extends Versioned {
  readonly id: AttemptId;
  readonly workOrderId: WorkOrderId;
  readonly sequence:
    | { readonly kind: 'initial' }
    | { readonly kind: 'repair'; readonly number: 1 | 2; readonly failedAttempt: AttemptId };
  readonly observation:
    | { readonly state: 'running'; readonly startedAt: string }
    | {
      readonly state: 'host-returned';
      readonly startedAt: string;
      readonly finishedAt: string;
      readonly exitCode: number | null;
      readonly sourceAfter: ContentDigest;
      readonly reportedTaskStatus: 'claimed-complete' | 'claimed-incomplete' | 'unspecified';
    }
    | { readonly state: 'outcome-unknown'; readonly error: DomainError };
}

export interface RunSnapshot extends Versioned {
  readonly id: RunId;
  readonly revisions: RevisionBinding;
  readonly state: ExecutionState;
  readonly activeTask: TaskId | null;
  readonly pendingTasks: readonly TaskId[];
  readonly attempts: readonly AttemptRecord[];
  readonly quiescence: 'confirmed' | 'unconfirmed';
  readonly elapsedMs?: number;
  readonly observedAt?: string;
  readonly admissions?: readonly ExecutionAdmission[];
  readonly plan?: ExecutionPlan;
  readonly replans?: readonly {
    readonly plan: ExecutionPlan; readonly approval: ApprovalReference;
    readonly requestDigest: ContentDigest; readonly approvedAt: string;
  }[];
  readonly completions?: readonly TaskCompletion[];
  readonly reconciliations?: readonly { readonly dispatchToken: ContentDigest; readonly evidence: ContentDigest; readonly recordedAt: string }[];
}

/** Auto replays reviewed byte transitions; unknown generated patches need separate source-apply review. */
export interface ExecutionPlan {
  readonly orders: readonly WorkOrder[];
}

export interface TaskCompletion {
  readonly taskId: TaskId;
  readonly workOrderId: WorkOrderId;
  readonly attemptId: AttemptId;
  readonly source: ContentDigest;
  readonly evidence: readonly EvidenceId[];
}

export function parseExecutionPlan(value: unknown): ExecutionPlan {
  const input = record(value, 'executionPlan', ['orders']);
  const orders = array(input.orders, 'executionPlan.orders', parseWorkOrder, 1);
  const first = orders[0]!;
  unique(orders.map((order) => order.id), 'workOrders');
  const ordered = orderTaskDefinitions(orders.map((order) => order.task));
  if (orders.length > first.limits.maxTasks || orders.some((order, index) =>
    order.task.id !== ordered[index]!.id || order.runId !== first.runId || order.host !== first.host ||
    order.mode !== first.mode || JSON.stringify(order.limits) !== JSON.stringify(first.limits) ||
    JSON.stringify({ ...order.revisions, source: first.revisions.source, effects: first.revisions.effects }) !== JSON.stringify(first.revisions))) {
    throw new ContractError('executionPlan', 'one bounded, topologically ordered plan must share run, intent, host and limits');
  }
  return Object.freeze({ orders: Object.freeze(orders) });
}

export interface ExecutionAdmission {
  readonly dispatchToken?: ContentDigest;
  readonly workOrder: WorkOrder;
  readonly requestDigest: ContentDigest;
  readonly qualificationEvidence: ContentDigest;
  readonly admittedAt: string;
  readonly authorization?: ApprovalRequest;
}

export function parseWorkOrder(value: unknown): WorkOrder {
  const input = record(value, 'workOrder', [
    'contractVersion', 'id', 'runId', 'task', 'revisions', 'sourceBefore', 'approval', 'mode', 'host', 'limits', 'effects',
  ]);
  const revisions = parseRevisionBinding(input.revisions);
  const effects = parseEffectScope(input.effects);
  const sourceBefore = parseDigest(input.sourceBefore);
  if (revisions.effects !== digestEffectScope(effects) || revisions.source !== sourceBefore) {
    throw new ContractError('workOrder', 'work-order effect and source scope does not match its revisions');
  }
  return Object.freeze({
    contractVersion: parseContractVersion(input.contractVersion), id: parseId('workOrder', input.id),
    runId: parseId('run', input.runId), task: parseTaskDefinition(input.task), revisions, effects, sourceBefore,
    approval: parseApprovalReference(input.approval), mode: parseExecutionMode(input.mode),
    host: parseNativeHost(input.host), limits: parseExecutionLimits(input.limits),
  });
}

export interface ExecutionOperations {
  dispatch(workOrder: WorkOrder): Promise<Outcome<AttemptRecord>>;
  status(runId: RunId): Promise<Outcome<RunSnapshot>>;
  pause(runId: RunId): Promise<Outcome<RunSnapshot>>;
  cancel(runId: RunId): Promise<Outcome<RunSnapshot>>;
  resume(runId: RunId, revisions: RevisionBinding, approval: ApprovalReference): Promise<Outcome<RunSnapshot>>;
  reconcile(runId: RunId): Promise<Outcome<RunSnapshot>>;
}
