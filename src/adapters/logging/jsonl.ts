import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { lstat, open, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import { record } from '../../kernel/validation.js';
import { MAX_EVENT_BYTES } from '../../observability/events.js';
import { serializeDiagnosticEvent } from './diagnostics.js';
import type { DiagnosticSink } from './diagnostics.js';
import { windowsPrivateEntries } from '../platform/windows-private-state.js';

export interface AuthorizedJsonlSink extends DiagnosticSink {
  previewPrune(): Promise<LogPruneInspection>;
  prune(preview: LogPrunePreview): Promise<LogPruneResult>;
}

export interface LogPrunePreview {
  readonly state: 'ready';
  readonly scope: 'local-diagnostics-only';
  readonly path: string;
  readonly bytes: number;
  readonly revision: string;
}
export type LogPruneInspection = LogPrunePreview | { readonly state: 'absent' } |
  { readonly state: 'unavailable'; readonly reason: 'io' };
export type LogPruneResult = { readonly state: 'pruned' } | {
  readonly state: 'unavailable';
  readonly reason: 'io' | 'stale-preview' | 'invalid-preview';
  readonly effect: 'unchanged' | 'unknown';
};

export const MAX_LOG_BYTES = 1_048_576;

export function parseLogPrunePreview(value: unknown): LogPrunePreview {
  const input = record(value, 'logPrunePreview', ['state', 'scope', 'path', 'bytes', 'revision']);
  if (input.state !== 'ready' || input.scope !== 'local-diagnostics-only' ||
    typeof input.path !== 'string' || !isAbsolute(input.path) || !input.path.endsWith('.jsonl') ||
    input.path.length > 4096 || /[\u0000-\u001f\u007f]/u.test(input.path) ||
    typeof input.bytes !== 'number' || !Number.isSafeInteger(input.bytes) || input.bytes < 0 ||
    input.bytes > MAX_LOG_BYTES || typeof input.revision !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(input.revision)) {
    throw new TypeError('Invalid diagnostic prune preview');
  }
  return Object.freeze({
    state: 'ready', scope: 'local-diagnostics-only', path: input.path, bytes: input.bytes, revision: input.revision,
  });
}

async function validateFile(file: FileHandle, path: string): Promise<void> {
  const info = await file.stat();
  if (process.platform === 'win32') {
    windowsPrivateEntries([
      { path: dirname(path), directory: true, writable: true },
      { path, directory: false, writable: true },
    ]);
    const current = await lstat(path);
    if (info.dev !== current.dev || info.ino !== current.ino) throw new TypeError('Diagnostic path changed');
  }
  if (!info.isFile() || info.nlink !== 1 ||
    (process.platform !== 'win32' && ((info.mode & 0o077) !== 0 || info.uid !== process.getuid?.()))) {
    throw new TypeError('Diagnostic destination is not a private regular file');
  }
}

function validateLine(line: string): void {
  if (typeof line !== 'string' || Buffer.byteLength(line) > MAX_EVENT_BYTES || !line.endsWith('\n')) {
    throw new TypeError('Invalid diagnostic record');
  }
  const value: unknown = JSON.parse(line);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('Invalid diagnostic record');
  const { recordedAt, ...event } = value as Record<string, unknown>;
  if (serializeDiagnosticEvent(event, recordedAt) !== line) throw new TypeError('Noncanonical diagnostic record');
}

async function snapshot(file: FileHandle, path: string): Promise<LogPrunePreview> {
  await validateFile(file, path);
  const before = await file.stat({ bigint: true });
  if (before.size > BigInt(MAX_LOG_BYTES)) throw new TypeError('Diagnostic segment exceeds preview bound');
  const hash = createHash('sha256');
  const buffer = Buffer.alloc(16_384);
  let offset = 0;
  let pending = '';
  while (offset < Number(before.size)) {
    const { bytesRead } = await file.read(buffer, 0, Math.min(buffer.length, Number(before.size) - offset), offset);
    if (bytesRead === 0) throw new TypeError('Diagnostic segment changed during preview');
    hash.update(buffer.subarray(0, bytesRead));
    const lines = (pending + buffer.subarray(0, bytesRead).toString('utf8')).split('\n');
    pending = lines.pop() ?? '';
    if (Buffer.byteLength(pending) > MAX_EVENT_BYTES) throw new TypeError('Unrecognized diagnostic file');
    for (const line of lines) validateLine(`${line}\n`);
    offset += bytesRead;
  }
  if (pending !== '') throw new TypeError('Unterminated diagnostic record');
  const after = await file.stat({ bigint: true });
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new TypeError('Diagnostic segment changed during preview');
  }
  hash.update(`\0${before.dev}:${before.ino}:${before.size}:${before.mtimeNs}:${before.ctimeNs}`);
  return Object.freeze({
    state: 'ready', scope: 'local-diagnostics-only', path, bytes: offset, revision: `sha256:${hash.digest('hex')}`,
  });
}

/** The embedding application, not a skill or project setting, authorizes this path. */
export function createAuthorizedJsonlSink(path: string): AuthorizedJsonlSink {
  function validatePath(): void {
    if (typeof path !== 'string' || !isAbsolute(path) || !path.endsWith('.jsonl') ||
      path.length > 4096 || /[\u0000-\u001f\u007f]/u.test(path)) {
      throw new TypeError('Invalid diagnostic destination');
    }
    if (process.platform === 'win32') {
      windowsPrivateEntries([{ path: dirname(path), directory: true, writable: true }]);
    }
  }
  async function openLock(): Promise<FileHandle> {
    if (process.platform === 'win32') {
      windowsPrivateEntries([{ path: `${path}.lock`, directory: false, writable: true, create: true }]);
      return open(`${path}.lock`, constants.O_WRONLY);
    }
    return open(`${path}.lock`, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  }
  let pending: Promise<void> = Promise.resolve();
  let queued = 0;
  const serialize = <T>(action: () => Promise<T>): Promise<T> => {
    if (queued >= 64) return Promise.reject(new TypeError('Local diagnostic queue is full'));
    queued += 1;
    const result = pending.then(action).finally(() => { queued -= 1; });
    pending = result.then(() => {}, () => {});
    return result;
  };
  return Object.freeze({
    write(line: string): Promise<void> {
      return serialize(async () => {
        let file;
        let lock;
        try {
          validatePath();
          validateLine(line);
          lock = await openLock();
          if (process.platform === 'win32') {
            let create = false;
            try { await lstat(path); } catch (error) {
              if (typeof error !== 'object' || error === null || Reflect.get(error, 'code') !== 'ENOENT') throw error;
              create = true;
            }
            windowsPrivateEntries([{ path, directory: false, writable: true, create }]);
          }
          file = await open(path, constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
          const current = await snapshot(file, path);
          const bytes = Buffer.from(line);
          if (current.bytes + bytes.length > MAX_LOG_BYTES) throw new TypeError('Diagnostic segment is full');
          const result = await file.write(bytes);
          if (result.bytesWritten !== bytes.length) throw new TypeError('Incomplete diagnostic append');
          await file.sync();
          await file.close();
          file = undefined;
        } catch {
          throw new TypeError('Local diagnostic persistence unavailable');
        } finally {
          await file?.close().catch(() => {});
          if (lock !== undefined) {
            try {
              await lock.close();
              await unlink(`${path}.lock`);
            } catch {
              throw new TypeError('Local diagnostic persistence unavailable');
            }
          }
        }
      });
    },
    async previewPrune(): Promise<LogPruneInspection> {
      let file;
      let result: LogPruneInspection;
      try {
        validatePath();
        file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        result = await snapshot(file, path);
      } catch (error) {
        result = typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT'
          ? { state: 'absent' } : { state: 'unavailable', reason: 'io' };
      } finally {
        if (file !== undefined) {
          try { await file.close(); } catch { result = { state: 'unavailable', reason: 'io' }; }
        }
      }
      return result;
    },
    prune(preview: LogPrunePreview): Promise<LogPruneResult> {
      let reviewed: LogPrunePreview;
      try {
        reviewed = parseLogPrunePreview(preview);
        if (reviewed.path !== path) throw new TypeError('Preview target does not match the configured diagnostic file');
      } catch {
        return Promise.resolve({ state: 'unavailable', reason: 'invalid-preview', effect: 'unchanged' });
      }
      return serialize(async (): Promise<LogPruneResult> => {
        let file;
        let lock;
        let truncated = false;
        let result: LogPruneResult = { state: 'unavailable', reason: 'io', effect: 'unchanged' };
        try {
          validatePath();
          lock = await openLock();
          file = await open(path, constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          const current = await snapshot(file, path);
          if (current.revision !== reviewed.revision || current.bytes !== reviewed.bytes) {
            result = { state: 'unavailable', reason: 'stale-preview', effect: 'unchanged' };
          } else {
            truncated = true;
            await file.truncate(0);
            await file.sync();
            result = { state: 'pruned' };
          }
        } catch {
          result = { state: 'unavailable', reason: 'io', effect: truncated ? 'unknown' : 'unchanged' };
        } finally {
          if (file !== undefined) {
            try { await file.close(); } catch { result = { state: 'unavailable', reason: 'io', effect: truncated ? 'unknown' : 'unchanged' }; }
          }
          if (lock !== undefined) {
            try {
              await lock.close();
              await unlink(`${path}.lock`);
            } catch {
              result = { state: 'unavailable', reason: 'io', effect: truncated ? 'unknown' : 'unchanged' };
            }
          }
        }
        return result;
      }).catch(() => ({ state: 'unavailable' as const, reason: 'io' as const, effect: 'unchanged' as const }));
    },
  });
}
