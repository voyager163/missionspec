import type { ErrorCode, Outcome } from '../kernel/outcomes.js';
import { ContractError } from '../kernel/validation.js';

export class WorkflowError extends Error {
  constructor(readonly code: ErrorCode, message: string) {
    super(message);
    this.name = 'WorkflowError';
  }
}

export function failed(error: unknown): Exclude<Outcome<never>, { status: 'ok' }> {
  const code = error instanceof WorkflowError ? error.code : error instanceof ContractError ? 'invalid-input' : 'persistence-failed';
  const message = error instanceof WorkflowError || error instanceof ContractError
    ? error.message : 'The local operation could not complete safely.';
  const detail = { code, message, retry: 'after-review' as const, fields: [] };
  return code === 'effect-outcome-unknown'
    ? { status: 'outcome-unknown', error: detail, reconciliationRequired: true }
    : { status: 'blocked', error: detail };
}
