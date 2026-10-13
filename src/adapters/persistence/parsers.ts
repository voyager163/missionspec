import { parseExecutionPlan, parseWorkOrder, type AttemptRecord, type RunSnapshot } from '../../engines/execution/contracts.js';
import type { AcceptanceRecord, EvidenceReference } from '../../engines/verification/contracts.js';
import { digestApprovalRequest, parseApprovalReference, parseApprovalRequest } from '../../kernel/authority.js';
import { parseId, parseProjectPath } from '../../kernel/identifiers.js';
import { parseDomainError } from '../../kernel/outcomes.js';
import { parseContractVersion } from '../../kernel/protocol.js';
import { parseDigest, parseRevisionBinding, type ContentDigest } from '../../kernel/revisions.js';
import { array, ContractError, integer, oneOf, record, text, unique } from '../../kernel/validation.js';

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 24);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(result)) {
    throw new ContractError(field, 'expected a UTC ISO timestamp');
  }
  const date = new Date(result);
  if (!Number.isFinite(date.valueOf()) || date.toISOString() !== result.replace(/(?<!\.\d{3})Z$/u, '.000Z')) {
    throw new ContractError(field, 'expected a valid UTC ISO timestamp');
  }
  return result;
}

export function parseAttempt(value: unknown): AttemptRecord {
  const input = record(value, 'attempt', ['contractVersion', 'id', 'workOrderId', 'sequence', 'observation']);
  const sequence = record(input.sequence, 'attempt.sequence', ['kind', 'number', 'failedAttempt']);
  let parsedSequence: AttemptRecord['sequence'];
  if (sequence.kind === 'initial') {
    record(sequence, 'attempt.sequence', ['kind']);
    parsedSequence = { kind: 'initial' };
  } else {
    if (sequence.kind !== 'repair' || (sequence.number !== 1 && sequence.number !== 2)) {
      throw new ContractError('attempt.sequence', 'expected initial or bounded repair');
    }
    parsedSequence = {
      kind: 'repair',
      number: sequence.number,
      failedAttempt: parseId('attempt', sequence.failedAttempt),
    };
  }
  const observation = record(input.observation, 'attempt.observation', [
    'state', 'startedAt', 'finishedAt', 'exitCode', 'sourceAfter', 'reportedTaskStatus', 'error',
  ]);
  let parsedObservation: AttemptRecord['observation'];
  if (observation.state === 'running') {
    record(observation, 'attempt.observation', ['state', 'startedAt']);
    parsedObservation = { state: 'running', startedAt: timestamp(observation.startedAt, 'attempt.startedAt') };
  } else if (observation.state === 'host-returned') {
    record(observation, 'attempt.observation', [
      'state', 'startedAt', 'finishedAt', 'exitCode', 'sourceAfter', 'reportedTaskStatus',
    ]);
    const startedAt = timestamp(observation.startedAt, 'attempt.startedAt');
    const finishedAt = timestamp(observation.finishedAt, 'attempt.finishedAt');
    if (Date.parse(finishedAt) < Date.parse(startedAt)) {
      throw new ContractError('attempt.finishedAt', 'cannot precede startedAt');
    }
    parsedObservation = {
      state: 'host-returned',
      startedAt,
      finishedAt,
      exitCode: observation.exitCode === null ? null
        : integer(observation.exitCode, 'attempt.exitCode', -2147483648, 2147483647),
      sourceAfter: parseDigest(observation.sourceAfter),
      reportedTaskStatus: oneOf(observation.reportedTaskStatus,
        ['claimed-complete', 'claimed-incomplete', 'unspecified'], 'attempt.reportedTaskStatus'),
    };
  } else {
    record(observation, 'attempt.observation', ['state', 'error']);
    if (observation.state !== 'outcome-unknown') {
      throw new ContractError('attempt.observation.state', 'unsupported observation state');
    }
    parsedObservation = { state: 'outcome-unknown', error: parseDomainError(observation.error) };
  }
  const result: AttemptRecord = {
    contractVersion: parseContractVersion(input.contractVersion),
    id: parseId('attempt', input.id),
    workOrderId: parseId('workOrder', input.workOrderId),
    sequence: parsedSequence,
    observation: parsedObservation,
  };
  if (result.sequence.kind === 'repair' && result.sequence.failedAttempt === result.id) {
    throw new ContractError('attempt.sequence.failedAttempt', 'cannot refer to itself');
  }
  return result;
}

export function parseRun(value: unknown): RunSnapshot {
  const input = record(value, 'snapshot', [
    'contractVersion', 'id', 'revisions', 'state', 'activeTask', 'pendingTasks', 'attempts', 'quiescence', 'admissions', 'plan', 'completions', 'reconciliations', 'replans', 'elapsedMs', 'observedAt',
  ]);
  const attempts = array(input.attempts, 'snapshot.attempts', parseAttempt);
  unique(attempts.map((attempt) => attempt.id), 'snapshot.attempts');
  const pendingTasks = unique(array(input.pendingTasks, 'snapshot.pendingTasks',
    (id) => parseId('task', id)), 'snapshot.pendingTasks');
  const activeTask = input.activeTask === null ? null : parseId('task', input.activeTask);
  if (activeTask !== null && pendingTasks.includes(activeTask)) {
    throw new ContractError('snapshot.pendingTasks', 'active task cannot also be pending');
  }
  return {
    contractVersion: parseContractVersion(input.contractVersion),
    id: parseId('run', input.id),
    revisions: parseRevisionBinding(input.revisions),
    state: oneOf(input.state,
      ['pending', 'running', 'paused', 'blocked', 'outcome-unknown', 'quiesced'], 'snapshot.state'),
    activeTask,
    pendingTasks,
    attempts,
    quiescence: oneOf(input.quiescence, ['confirmed', 'unconfirmed'], 'snapshot.quiescence'),
    ...(input.elapsedMs === undefined ? {} : { elapsedMs: integer(input.elapsedMs, 'snapshot.elapsedMs', 0) }),
    ...(input.observedAt === undefined ? {} : { observedAt: timestamp(input.observedAt, 'snapshot.observedAt') }),
    ...(input.plan === undefined ? {} : { plan: parseExecutionPlan(input.plan) }),
    ...(input.replans === undefined ? {} : { replans: array(input.replans, 'replans', (entry) => {
      const replan = record(entry, 'replan', ['plan', 'approval', 'requestDigest', 'approvedAt']);
      return { plan: parseExecutionPlan(replan.plan), approval: parseApprovalReference(replan.approval),
        requestDigest: parseDigest(replan.requestDigest), approvedAt: timestamp(replan.approvedAt, 'replan.approvedAt') };
    }) }),
    ...(input.completions === undefined ? {} : { completions: array(input.completions, 'completions', (entry) => {
      const completion = record(entry, 'completion', ['taskId', 'workOrderId', 'attemptId', 'source', 'evidence']);
      return {
        taskId: parseId('task', completion.taskId), workOrderId: parseId('workOrder', completion.workOrderId),
        attemptId: parseId('attempt', completion.attemptId), source: parseDigest(completion.source),
        evidence: unique(array(completion.evidence, 'completion.evidence', (id) => parseId('evidence', id), 1), 'completion.evidence'),
      };
    }) }),
    ...(input.reconciliations === undefined ? {} : { reconciliations: array(input.reconciliations, 'reconciliations', (entry) => {
      const receipt = record(entry, 'reconciliation', ['dispatchToken', 'evidence', 'recordedAt']);
      return { dispatchToken: parseDigest(receipt.dispatchToken), evidence: parseDigest(receipt.evidence), recordedAt: timestamp(receipt.recordedAt, 'reconciliation.recordedAt') };
    }) }),
    ...(input.admissions === undefined ? {} : {
      admissions: array(input.admissions, 'snapshot.admissions', (entry) => {
        const admission = record(entry, 'admission', ['workOrder', 'requestDigest', 'qualificationEvidence', 'admittedAt', 'dispatchToken', 'authorization']);
        const workOrder = parseWorkOrder(admission.workOrder);
        if (workOrder.runId !== input.id) throw new ContractError('admission', 'work order belongs to another run');
        const authorization = admission.authorization === undefined ? undefined : parseApprovalRequest(admission.authorization);
        if (authorization !== undefined && digestApprovalRequest(authorization) !== admission.requestDigest) throw new ContractError('admission', 'authorization digest differs');
        return {
          workOrder, requestDigest: parseDigest(admission.requestDigest),
          qualificationEvidence: parseDigest(admission.qualificationEvidence),
          ...(admission.dispatchToken === undefined ? {} : { dispatchToken: parseDigest(admission.dispatchToken) }),
          admittedAt: timestamp(admission.admittedAt, 'admission.admittedAt'),
          ...(authorization === undefined ? {} : { authorization }),
        };
      }, 1),
    }),
  };
}

export function parseEvidence(value: unknown): EvidenceReference {
  const input = record(value, 'evidence', [
    'contractVersion', 'id', 'revisions', 'source', 'checkId', 'checkDefinition', 'attemptId', 'storage',
  ]);
  const storage = record(input.storage, 'evidence.storage', ['state', 'path', 'digest', 'prunedAt', 'approval', 'reason']);
  let parsedStorage: EvidenceReference['storage'];
  if (storage.state === 'retained') {
    record(storage, 'evidence.storage', ['state', 'path', 'digest']);
    parsedStorage = { state: 'retained', path: parseProjectPath(storage.path), digest: parseDigest(storage.digest) };
  } else if (storage.state === 'pruned') {
    record(storage, 'evidence.storage', ['state', 'prunedAt', 'approval']);
    parsedStorage = {
      state: 'pruned',
      prunedAt: timestamp(storage.prunedAt, 'evidence.prunedAt'),
      approval: parseApprovalReference(storage.approval),
    };
  } else {
    record(storage, 'evidence.storage', ['state', 'reason']);
    if (storage.state !== 'unavailable') {
      throw new ContractError('evidence.storage.state', 'unsupported evidence storage state');
    }
    parsedStorage = { state: 'unavailable', reason: text(storage.reason, 'evidence.reason') };
  }
  return {
    contractVersion: parseContractVersion(input.contractVersion),
    id: parseId('evidence', input.id),
    revisions: parseRevisionBinding(input.revisions),
    source: parseDigest(input.source),
    checkId: parseId('check', input.checkId),
    checkDefinition: parseDigest(input.checkDefinition),
    attemptId: input.attemptId === null ? null : parseId('attempt', input.attemptId),
    storage: parsedStorage,
  };
}

export function parseAcceptance(value: unknown): AcceptanceRecord {
  const input = record(value, 'acceptance', [
    'contractVersion', 'state', 'revisions', 'source', 'evidence', 'approval',
  ]);
  if (input.state !== 'accepted') throw new ContractError('acceptance.state', 'expected accepted');
  return {
    contractVersion: parseContractVersion(input.contractVersion),
    state: 'accepted',
    revisions: parseRevisionBinding(input.revisions),
    source: parseDigest(input.source),
    evidence: unique(array(input.evidence, 'acceptance.evidence', (id) => parseId('evidence', id), 1),
      'acceptance.evidence'),
    approval: parseApprovalReference(input.approval),
  };
}

export interface RunEnvelope {
  readonly snapshot: RunSnapshot;
  readonly evidence: readonly { readonly id: EvidenceReference['id']; readonly digest: ContentDigest }[];
  readonly previousRevision: ContentDigest | 'absent';
}

export function parseEnvelope(value: unknown): RunEnvelope {
  const input = record(value, 'runEnvelope', ['snapshot', 'evidence', 'previousRevision']);
  const evidence = array(input.evidence, 'runEnvelope.evidence', (entry) => {
    const item = record(entry, 'runEnvelope.evidence[]', ['id', 'digest']);
    return { id: parseId('evidence', item.id), digest: parseDigest(item.digest) };
  });
  unique(evidence.map((item) => item.id), 'runEnvelope.evidence');
  if (evidence.some((item, index) => index > 0 && item.id <= evidence[index - 1]!.id)) {
    throw new ContractError('runEnvelope.evidence', 'expected sorted identities');
  }
  return {
    snapshot: parseRun(input.snapshot),
    evidence,
    previousRevision: input.previousRevision === 'absent' ? 'absent' : parseDigest(input.previousRevision),
  };
}
