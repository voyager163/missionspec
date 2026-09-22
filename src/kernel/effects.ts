import {
  parseId, parseNativeHost, parseProjectPath,
  type CheckId, type NativeHost, type ProjectPath, type StableId, type TaskId,
} from './identifiers.js';
import { digestContent, parseDigest, type ContentDigest } from './revisions.js';
import { array, ContractError, oneOf, record, unique } from './validation.js';

export type FilePurpose = 'artifact' | 'source' | 'configuration' | 'baseline' | 'closure';
export type RequestedEffect =
  | {
    readonly kind: 'file-write';
    readonly purpose: FilePurpose;
    readonly path: ProjectPath;
    readonly expected: ContentDigest | 'absent';
    readonly proposed: ContentDigest;
  }
  | {
    readonly kind: 'file-remove';
    readonly purpose: FilePurpose;
    readonly path: ProjectPath;
    readonly expected: ContentDigest;
  }
  | { readonly kind: 'check-execute'; readonly checkId: CheckId; readonly definition: ContentDigest }
  | { readonly kind: 'host-dispatch'; readonly host: NativeHost; readonly taskIds: readonly TaskId[] }
  | {
    readonly kind: 'runtime-state';
    readonly action: 'backup' | 'stage' | 'restore' | 'select';
    readonly subject: ContentDigest;
  }
  | {
    readonly kind: 'context-consume';
    readonly providerId: StableId<'provider'>;
    readonly paths: readonly ProjectPath[];
    readonly allowRemoteProcessing: boolean;
  };

export function parseRequestedEffect(value: unknown): RequestedEffect {
  const tag = record(value, 'effect', [
    'kind', 'purpose', 'path', 'expected', 'proposed', 'checkId', 'definition',
    'host', 'taskIds', 'providerId', 'paths', 'allowRemoteProcessing', 'action', 'subject',
  ]);
  switch (tag.kind) {
    case 'runtime-state': {
      const input = record(value, 'effect', ['kind', 'action', 'subject']);
      return Object.freeze({
        kind: 'runtime-state', action: oneOf(input.action, ['backup', 'stage', 'restore', 'select'], 'effect.action'),
        subject: parseDigest(input.subject),
      });
    }
    case 'file-write': {
      const input = record(value, 'effect', ['kind', 'purpose', 'path', 'expected', 'proposed']);
      return Object.freeze({
        kind: 'file-write',
        purpose: oneOf(input.purpose, ['artifact', 'source', 'configuration', 'baseline', 'closure'], 'effect.purpose'),
        path: parseProjectPath(input.path),
        expected: input.expected === 'absent' ? 'absent' : parseDigest(input.expected),
        proposed: parseDigest(input.proposed),
      });
    }
    case 'file-remove': {
      const input = record(value, 'effect', ['kind', 'purpose', 'path', 'expected']);
      return Object.freeze({
        kind: 'file-remove',
        purpose: oneOf(input.purpose, ['artifact', 'source', 'configuration', 'baseline', 'closure'], 'effect.purpose'),
        path: parseProjectPath(input.path),
        expected: parseDigest(input.expected),
      });
    }
    case 'check-execute': {
      const input = record(value, 'effect', ['kind', 'checkId', 'definition']);
      return Object.freeze({
        kind: 'check-execute', checkId: parseId('check', input.checkId), definition: parseDigest(input.definition),
      });
    }
    case 'host-dispatch': {
      const input = record(value, 'effect', ['kind', 'host', 'taskIds']);
      return Object.freeze({
        kind: 'host-dispatch', host: parseNativeHost(input.host),
        taskIds: unique(array(input.taskIds, 'effect.taskIds', (id) => parseId('task', id), 1), 'effect.taskIds'),
      });
    }
    case 'context-consume': {
      const input = record(value, 'effect', ['kind', 'providerId', 'paths', 'allowRemoteProcessing']);
      if (typeof input.allowRemoteProcessing !== 'boolean') {
        throw new ContractError('effect.allowRemoteProcessing', 'expected an explicit boolean');
      }
      return Object.freeze({
        kind: 'context-consume', providerId: parseId('provider', input.providerId),
        paths: unique(array(input.paths, 'effect.paths', parseProjectPath, 1), 'effect.paths'),
        allowRemoteProcessing: input.allowRemoteProcessing,
      });
    }
    default:
      throw new ContractError('effect.kind', 'unrecognized effect');
  }
}

export function parseEffectScope(value: unknown): readonly RequestedEffect[] {
  const effects = array(value, 'effects', parseRequestedEffect);
  unique(effects.map((effect) => {
    switch (effect.kind) {
      case 'file-write':
      case 'file-remove': return `file:${effect.path}`;
      case 'check-execute': return `check:${effect.checkId}`;
      case 'host-dispatch': return `host:${effect.host}`;
      case 'runtime-state': return `runtime:${effect.action}`;
      case 'context-consume': return `context:${effect.providerId}`;
    }
  }), 'effects');
  return effects;
}

export function digestEffectScope(effects: readonly RequestedEffect[]): ContentDigest {
  return digestContent(JSON.stringify(parseEffectScope(effects)));
}
