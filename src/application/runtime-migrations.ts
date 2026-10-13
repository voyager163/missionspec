import { digestContent, type ContentDigest } from '../kernel/revisions.js';
import { integer, oneOf, record } from '../kernel/validation.js';
import { WorkflowError } from './errors.js';

export interface RuntimeFormat {
  readonly kind: 'sqlite-ledger' | 'logical-backup';
  readonly version: number;
}
export interface RuntimeMigrationPlan {
  readonly policyVersion: 1;
  readonly source: RuntimeFormat;
  readonly target: RuntimeFormat;
  readonly disposition: 'current' | 'export' | 'stage-native-replica';
  readonly preserves: readonly ['recorded-facts', 'original-files', 'independent-authority'];
  readonly activation: 'never-implicit';
  readonly digest: ContentDigest;
}

const supportedFormats = { 'sqlite-ledger': 3, 'logical-backup': 1 } as const;
function format(input: unknown): RuntimeFormat {
  const value = record(input, 'runtimeFormat', ['kind', 'version']);
  const kind = oneOf(value.kind, ['sqlite-ledger', 'logical-backup'], 'runtimeFormat.kind');
  const version = integer(value.version, 'runtimeFormat.version', 1);
  if (version !== supportedFormats[kind]) {
    throw new WorkflowError('unsupported-version', 'No verified upgrade edge exists for this source format. Preserve original bytes; unreleased prototypes are not a supported historical schema.');
  }
  return { kind, version };
}

/** Explicit supported version edges; future upgrades must add validated, fact-preserving converters. */
export function planRuntimeMigration(source: RuntimeFormat, target: RuntimeFormat): RuntimeMigrationPlan {
  const from = format(source);
  const to = format(target);
  const body = {
    policyVersion: 1 as const, source: from, target: to,
    disposition: from.kind === to.kind ? 'current' as const
      : from.kind === 'sqlite-ledger' ? 'export' as const : 'stage-native-replica' as const,
    preserves: ['recorded-facts', 'original-files', 'independent-authority'] as const,
    activation: 'never-implicit' as const,
  };
  return { ...body, digest: digestContent(JSON.stringify(body)) };
}
