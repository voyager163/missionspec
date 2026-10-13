import { parseEffectScope, digestEffectScope, type RequestedEffect } from './effects.js';
import { parseId, parseNativeHost, type ApprovalId, type NativeHost, type RunId, type WorkOrderId } from './identifiers.js';
import { parseContractVersion, type Versioned } from './protocol.js';
import { parseOperationId, type OperationId } from './registry.js';
import { digestContent, parseDigest, parseReviewBinding, type ContentDigest, type ReviewBinding } from './revisions.js';
import { ContractError, integer, oneOf, record } from './validation.js';

export type ExecutionMode = 'interactive' | 'auto';
export type ApprovalPurpose =
  | 'artifact-edit' | 'execution' | 'source-apply' | 'verification' | 'acceptance'
  | 'promotion' | 'closure' | 'integration' | 'context-consumption';

export function parseExecutionMode(value: unknown = undefined): ExecutionMode {
  return value === undefined ? 'interactive' : oneOf(value, ['interactive', 'auto'], 'executionMode');
}

export interface ExecutionLimits {
  readonly maxTasks: number;
  readonly maxDurationMs: number;
  readonly maxRepairsPerTask: 0 | 1 | 2;
  readonly concurrency: 1;
}

export function parseExecutionLimits(value: unknown): ExecutionLimits {
  const input = record(value, 'limits', ['maxTasks', 'maxDurationMs', 'maxRepairsPerTask', 'concurrency']);
  const repairs = integer(input.maxRepairsPerTask, 'limits.maxRepairsPerTask', 0, 2);
  if (input.concurrency !== undefined && input.concurrency !== 1) {
    throw new ContractError('limits.concurrency', 'only serial execution is defined by this contract');
  }
  return Object.freeze({
    maxTasks: integer(input.maxTasks, 'limits.maxTasks', 1),
    maxDurationMs: integer(input.maxDurationMs, 'limits.maxDurationMs', 1),
    maxRepairsPerTask: repairs as 0 | 1 | 2,
    concurrency: 1,
  });
}

export interface ExecutionRequest {
  readonly mode: ExecutionMode;
  readonly host: NativeHost;
  readonly limits: ExecutionLimits;
}

export function parseExecutionRequest(value: unknown): ExecutionRequest {
  const input = record(value, 'execution', ['mode', 'host', 'limits']);
  return Object.freeze({
    mode: parseExecutionMode(input.mode),
    host: parseNativeHost(input.host),
    limits: parseExecutionLimits(input.limits),
  });
}

interface ApprovalRequestBase extends Versioned {
  readonly state: 'untrusted-request';
  readonly purpose: ApprovalPurpose;
  readonly binding: ReviewBinding;
  readonly effects: readonly RequestedEffect[];
}

export type ApprovalRequest =
  | (ApprovalRequestBase & {
    readonly operation: 'implement';
    readonly purpose: 'execution';
    readonly binding: Extract<ReviewBinding, { readonly kind: 'change' }>;
    readonly execution: ExecutionRequest;
    readonly runId?: RunId;
    readonly workOrderId?: WorkOrderId;
    readonly executionPlan?: ContentDigest;
  })
  | (ApprovalRequestBase & {
    readonly operation: 'implement';
    readonly purpose: 'source-apply';
    readonly binding: Extract<ReviewBinding, { readonly kind: 'review' }>;
  })
  | (ApprovalRequestBase & {
    readonly operation: Exclude<OperationId, 'implement'>;
    readonly purpose: Exclude<ApprovalPurpose, 'execution' | 'source-apply'>;
  });

export function parseApprovalRequest(value: unknown): ApprovalRequest {
  const input = record(value, 'approvalRequest', [
    'contractVersion', 'state', 'purpose', 'operation', 'binding', 'effects', 'execution', 'runId', 'workOrderId', 'executionPlan',
  ]);
  if (input.state !== 'untrusted-request') {
    throw new ContractError('approvalRequest.state', 'only untrusted requests can be parsed');
  }
  const operation = parseOperationId(input.operation);
  const purpose = oneOf(input.purpose, [
    'artifact-edit', 'execution', 'source-apply', 'verification', 'acceptance',
    'promotion', 'closure', 'integration', 'context-consumption',
  ], 'approvalRequest.purpose');
  if ((operation === 'implement') !== (purpose === 'execution' || purpose === 'source-apply')) {
    throw new ContractError('approvalRequest.purpose', 'implementation requires execution or exact source-apply authority');
  }
  const binding = parseReviewBinding(input.binding);
  if (binding.kind === 'review' && !['verification', 'acceptance', 'promotion', 'closure', 'source-apply'].includes(purpose)) {
    throw new ContractError('approvalRequest.binding', 'review bindings cannot grant native execution or artifact editing');
  }
  const effects = parseEffectScope(input.effects);
  if (effects.some((effect) => effect.kind === 'runtime-state') &&
      (operation !== 'onboard' || purpose !== 'integration' || binding.kind !== 'project')) {
    throw new ContractError('approvalRequest.effects', 'runtime lifecycle effects require separate project integration authority, never execution authority');
  }
  const expected = binding.kind === 'change' ? binding.revisions.effects : binding.effects;
  if (expected !== digestEffectScope(effects)) {
    throw new ContractError('approvalRequest.binding', 'effect revision does not match the requested scope');
  }
  const base = {
    contractVersion: parseContractVersion(input.contractVersion),
    state: 'untrusted-request' as const,
    purpose,
    binding,
    effects,
  };
  if (operation === 'implement' && purpose === 'source-apply') {
    if (binding.kind !== 'review' || effects.length === 0 ||
        effects.some((effect) => effect.kind !== 'file-write' || effect.purpose !== 'source') ||
        ['execution', 'runId', 'workOrderId', 'executionPlan'].some((field) => Object.hasOwn(input, field))) {
      throw new ContractError('approvalRequest', 'source-apply reviews exact source writes, never host dispatch or execution controls');
    }
    return Object.freeze({ ...base, operation, purpose, binding });
  }
  if (operation === 'implement') {
    if (binding.kind !== 'change') {
      throw new ContractError('approvalRequest.binding', 'implementation requires change revisions');
    }
    const execution = parseExecutionRequest(input.execution);
    for (const effect of effects) {
      if (effect.kind === 'host-dispatch' && effect.host !== execution.host) {
        throw new ContractError('approvalRequest.effects', 'host dispatch must match the selected host');
      }
    }
    if (Object.hasOwn(input, 'runId') !== Object.hasOwn(input, 'workOrderId')) {
      throw new ContractError('approvalRequest', 'run and work-order identities must be bound together');
    }
    return Object.freeze({
      ...base, operation, purpose: 'execution', binding, execution,
      ...(Object.hasOwn(input, 'runId') ? { runId: parseId('run', input.runId), workOrderId: parseId('workOrder', input.workOrderId) } : {}),
      ...(input.executionPlan === undefined ? {} : { executionPlan: parseDigest(input.executionPlan) }),
    });
  }
  if (Object.hasOwn(input, 'execution') || Object.hasOwn(input, 'runId') || Object.hasOwn(input, 'workOrderId') || Object.hasOwn(input, 'executionPlan')) {
    throw new ContractError('approvalRequest.execution', 'execution controls belong to implement only');
  }
  if (purpose === 'execution' || purpose === 'source-apply') {
    throw new ContractError('approvalRequest.purpose', 'execution authority belongs to implement only');
  }
  return Object.freeze({ ...base, operation, purpose });
}

export function digestApprovalRequest(value: ApprovalRequest): ContentDigest {
  return digestContent(JSON.stringify(parseApprovalRequest(value)));
}

export interface ApprovalReference {
  readonly id: ApprovalId;
}

export function parseApprovalReference(value: unknown): ApprovalReference {
  const input = record(value, 'approvalReference', ['id']);
  return Object.freeze({ id: parseId('approval', input.id) });
}

export interface LocalUserAssurance {
  readonly kind: 'local-user';
  readonly channel: 'terminal-confirmation' | 'mcp-elicitation' | 'trusted-callback';
  readonly protocolIdentity: { readonly id: string; readonly version: string };
  readonly qualification: { readonly state: 'not-established' };
  readonly humanPresence: 'not-attested';
  readonly organizationIdentity: 'not-attested';
}

export interface TrustedIssuedApproval extends Versioned {
  readonly state: 'trusted-issued';
  readonly reference: ApprovalReference;
  readonly assurance: LocalUserAssurance;
  readonly request: ApprovalRequest;
  readonly requestDigest: ContentDigest;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export type ApprovalResolution =
  | { readonly state: 'absent'; readonly reference: ApprovalReference }
  | {
    readonly state: 'expired' | 'revoked' | 'superseded';
    readonly reference: ApprovalReference;
    readonly recordedAt: string;
  }
  | { readonly state: 'current'; readonly approval: TrustedIssuedApproval };
