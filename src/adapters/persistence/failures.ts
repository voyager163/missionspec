import type { ErrorCode, Outcome } from '../../kernel/outcomes.js';
import { ContractError } from '../../kernel/validation.js';
import { WindowsPrivateStateError, windowsPrivateStateDiagnostic } from '../platform/windows-private-state.js';

export class StoreFailure extends Error {
  constructor(
    readonly kind: 'missing' | 'busy' | 'corrupt' | 'incompatible' | 'unavailable' | 'read-only'
      | 'closed' | 'conflict' | 'stale-revision' | 'workspace-mismatch' | 'capacity' | 'unknown' | 'io',
    message: string,
  ) {
    super(message);
  }
}

export function failure<T>(error: unknown): Outcome<T> {
  if (error instanceof ContractError) {
    return { status: 'blocked', error: {
      code: error.field === 'contractVersion' ? 'unsupported-version' : 'invalid-input',
      message: error.message, retry: 'never', fields: [error.field],
    } };
  }
  let issue = error instanceof StoreFailure ? error : undefined;
  if (error instanceof WindowsPrivateStateError) {
    issue = new StoreFailure('unavailable', `Windows private runtime storage is unavailable (${windowsPrivateStateDiagnostic(error)}).`);
  }
  if (issue === undefined && typeof error === 'object' && error !== null) {
    const code: unknown = Reflect.get(error, 'code');
    const sqliteCode: unknown = Reflect.get(error, 'errcode');
    const primary = typeof sqliteCode === 'number' ? sqliteCode & 255 : null;
    if (primary === 5 || primary === 6) issue = new StoreFailure('busy', 'Runtime store is busy; retry is bounded.');
    else if (primary === 13 || code === 'ENOSPC' || code === 'EDQUOT') {
      issue = new StoreFailure('capacity', 'Runtime storage capacity or quota is exhausted; no automatic pruning is performed.');
    }
    else if (primary === 11 || primary === 26) issue = new StoreFailure('corrupt', 'Runtime store is corrupt or not SQLite.');
    else if (primary === 3 || primary === 8 || primary === 14 || primary === 23) {
      issue = new StoreFailure('unavailable', 'SQLite could not obtain the requested local file access.');
    }
    else if (code === 'ENOENT') issue = new StoreFailure('missing', 'Runtime store or its directory does not exist.');
    else if (code === 'EEXIST') issue = new StoreFailure('conflict', 'Exclusive runtime store creation found an existing path.');
    else if (code === 'EACCES' || code === 'EPERM') {
      issue = new StoreFailure('unavailable', 'Runtime store filesystem permissions are unavailable.');
    }
  }
  issue ??= new StoreFailure('io', 'Runtime store I/O failed; no success is implied.');
  if (issue.kind === 'unknown') {
    return { status: 'outcome-unknown', reconciliationRequired: true, error: {
      code: 'effect-outcome-unknown', message: issue.message, retry: 'after-reconciliation',
      fields: ['runtimeStore', 'unknown'],
    } };
  }
  const codes: Record<Exclude<StoreFailure['kind'], 'unknown'>, ErrorCode> = {
    missing: 'not-found', busy: 'conflict', corrupt: 'persistence-failed', incompatible: 'unsupported-version',
    unavailable: 'capability-unavailable', 'read-only': 'capability-unavailable', closed: 'capability-unavailable',
    conflict: 'conflict', 'stale-revision': 'stale-revision', 'workspace-mismatch': 'scope-exceeded',
    capacity: 'limit-reached', io: 'persistence-failed',
  };
  return {
    status: issue.kind === 'corrupt' || issue.kind === 'io' ? 'failed' : 'blocked',
    error: {
      code: codes[issue.kind], message: issue.message,
      retry: issue.kind === 'busy' ? 'after-reconciliation' : 'after-review',
      fields: ['runtimeStore', issue.kind],
    },
  };
}
