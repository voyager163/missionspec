import type { ClockPort, DiagnosticEvent, DiagnosticsPort } from '../../ports/contracts.js';
import { OPERATIONS } from '../../kernel/registry.js';
import { MAX_EVENT_BYTES, parseDiagnosticEvent } from '../../observability/events.js';

export interface DiagnosticSink {
  write(line: string): Promise<void>;
}

export interface DiagnosticsOptions {
  readonly clock: Pick<ClockPort, 'wallTime'>;
  readonly stderr: DiagnosticSink;
  readonly localLog?: DiagnosticSink;
}

export function serializeDiagnosticEvent(value: unknown, wallTime: unknown): string {
  const event = parseDiagnosticEvent(value);
  if (typeof wallTime !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(wallTime) ||
    !Number.isFinite(Date.parse(wallTime)) || new Date(wallTime).toISOString() !== wallTime) {
    throw new TypeError('Invalid diagnostic clock');
  }
  const line = JSON.stringify({ ...event, recordedAt: wallTime }) + '\n';
  if (Buffer.byteLength(line) > MAX_EVENT_BYTES) throw new TypeError('Diagnostic exceeds byte limit');
  return line;
}

const rejected = '{"severity":"warning","code":"boundary-rejected","errorCode":"invalid-input"}\n';
const storageFailed = '{"severity":"warning","code":"storage-failed","errorCode":"persistence-failed"}\n';

export function createDiagnostics(options: DiagnosticsOptions): DiagnosticsPort {
  async function fallback(line: string): Promise<'emitted' | 'unavailable'> {
    try {
      await options.stderr.write(line);
      return 'emitted';
    } catch {
      return 'unavailable';
    }
  }
  return Object.freeze({
    async emit(event: DiagnosticEvent, persistence: 'console-only' | 'authorized-local-log') {
      let line: string;
      try {
        if (persistence !== 'console-only' && persistence !== 'authorized-local-log') throw new TypeError('Invalid destination');
        const parsed = parseDiagnosticEvent(event);
        line = serializeDiagnosticEvent(parsed, options.clock.wallTime());
        if (persistence === 'authorized-local-log' && OPERATIONS[parsed.operation].defaultAccess === 'read-only') {
          throw new TypeError('Read-only operation cannot persist diagnostics');
        }
      } catch {
        return { state: 'unavailable' as const, consoleFallback: await fallback(rejected) };
      }
      if (persistence === 'console-only') {
        const state = await fallback(line);
        return state === 'emitted'
          ? { state: 'emitted' as const, destination: 'console' as const }
          : { state: 'unavailable' as const, consoleFallback: 'unavailable' as const };
      }
      try {
        if (options.localLog === undefined) throw new TypeError('No authorized log sink');
        await options.localLog.write(line);
        return { state: 'emitted' as const, destination: 'local-log' as const };
      } catch {
        return { state: 'unavailable' as const, consoleFallback: await fallback(storageFailed) };
      }
    },
  });
}

export function createStderrDiagnosticSink(): DiagnosticSink {
  let tail = Promise.resolve();
  const write = (line: string): Promise<void> => new Promise((resolve, reject) => {
    if (process.stderr.destroyed || !process.stderr.writable) {
      reject(new Error('Diagnostic output unavailable'));
      return;
    }
    let failed = false;
    let scheduled = false;
    const settle = (error?: Error | null): void => {
      if (error) failed = true;
      if (scheduled) return;
      scheduled = true;
      // Native streams emit their error event after the write callback.
      setImmediate(() => {
        process.stderr.removeListener('error', onError);
        if (failed) reject(new Error('Diagnostic output unavailable'));
        else resolve();
      });
    };
    const onError = (error: Error): void => settle(error);
    process.stderr.once('error', onError);
    try {
      process.stderr.write(line, (error?: Error | null) => settle(error));
    } catch {
      settle(new Error('Diagnostic output unavailable'));
    }
  });
  return {
    write(line: string): Promise<void> {
      const result = tail.then(() => write(line));
      // Keep the queue usable; the caller still receives the original rejection.
      tail = result.then(() => undefined, () => undefined);
      return result;
    },
  };
}
