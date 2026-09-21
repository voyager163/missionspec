import type { ProjectPath, StableId } from './identifiers.js';
import { array, oneOf, record, text } from './validation.js';

export const ERROR_CODES = Object.freeze([
  'invalid-input',
  'unsupported-version',
  'capability-unavailable',
  'not-found',
  'conflict',
  'stale-revision',
  'authority-required',
  'authority-expired',
  'authority-revoked',
  'scope-exceeded',
  'limit-reached',
  'host-unqualified',
  'check-unqualified',
  'provider-unavailable',
  'evidence-unavailable',
  'persistence-failed',
  'effect-outcome-unknown',
] as const);
export type ErrorCode = (typeof ERROR_CODES)[number];

export interface DomainError {
  readonly code: ErrorCode;
  readonly message: string;
  readonly retry: 'never' | 'after-review' | 'after-reconciliation';
  readonly fields: readonly string[];
}

export type Outcome<T> =
  | { readonly status: 'ok'; readonly value: T }
  | { readonly status: 'blocked'; readonly error: DomainError }
  | { readonly status: 'failed'; readonly error: DomainError }
  | { readonly status: 'outcome-unknown'; readonly error: DomainError; readonly reconciliationRequired: true };

export function parseDomainError(value: unknown): DomainError {
  const input = record(value, 'error', ['code', 'message', 'retry', 'fields']);
  return Object.freeze({
    code: oneOf(input.code, ERROR_CODES, 'error.code'),
    message: text(input.message, 'error.message'),
    retry: oneOf(input.retry, ['never', 'after-review', 'after-reconciliation'], 'error.retry'),
    fields: array(input.fields, 'error.fields', (field) => text(field, 'error.fields[]', 128)),
  });
}

export interface Finding {
  readonly id: StableId<'finding'>;
  readonly basis: 'structural-validation' | 'static-inspection' | 'executed-check' | 'agent-judgment';
  readonly severity: 'information' | 'warning' | 'blocking';
  readonly summary: string;
  readonly paths: readonly ProjectPath[];
}

export type ArtifactReadiness = 'missing' | 'draft' | 'valid' | 'stale' | 'not-applicable' | 'blocked';
export type AuthorityState = 'absent' | 'current' | 'expired' | 'revoked' | 'superseded';
export type ExecutionState = 'pending' | 'running' | 'paused' | 'blocked' | 'outcome-unknown' | 'quiesced';
export type EvidenceState = 'missing' | 'applicable' | 'failed' | 'stale' | 'unavailable';
export type ChangeOutcome = 'not-accepted' | 'accepted' | 'rejected' | 'cancelled' | 'incomplete';
