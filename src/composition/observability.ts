import { AsyncLocalStorage } from 'node:async_hooks';
import { createDiagnostics, createStderrDiagnosticSink } from '../adapters/logging/diagnostics.js';
import type { DiagnosticSink } from '../adapters/logging/diagnostics.js';
import { createAuthorizedJsonlSink, parseLogPrunePreview } from '../adapters/logging/jsonl.js';
import type { LogPrunePreview, LogPruneResult, LogPruneInspection } from '../adapters/logging/jsonl.js';
import { createUserTelemetryPreferenceStore, saveTelemetryPreference } from '../adapters/telemetry/preferences.js';
import { parseApprovalReference } from '../kernel/authority.js';
import type { ApprovalReference } from '../kernel/authority.js';
import { ERROR_CODES } from '../kernel/outcomes.js';
import type { ErrorCode } from '../kernel/outcomes.js';
import { OPERATION_IDS, OPERATIONS } from '../kernel/registry.js';
import type { EngineId, OperationId } from '../kernel/registry.js';
import { oneOf, record } from '../kernel/validation.js';
import { createTelemetryClient } from '../observability/client.js';
import type { QualifiedTelemetrySink, TelemetryResult } from '../observability/client.js';
import { DISCLOSURE_VERSION, parseTelemetrySummary, telemetryEvent } from '../observability/events.js';
import type { TelemetryEvent } from '../observability/events.js';
import { hardDisabled, parsePreference } from '../observability/policy.js';
import type { InvocationPolicy, PreferenceWrite, TelemetryPreferenceStore } from '../observability/policy.js';
import type { ClockPort, DiagnosticEvent, DiagnosticsPort, OperationTelemetrySummary } from '../ports/contracts.js';

const observingRoot = new AsyncLocalStorage<boolean>();
type DiagnosticResult = Awaited<ReturnType<DiagnosticsPort['emit']>>;
type TelemetryOutcome = OperationTelemetrySummary['outcome'];

export interface ObservedOperation {
  readonly operation: OperationId;
  readonly access: 'read-only' | 'stateful';
  readonly scope: 'root' | 'child';
  readonly persistence?: 'console-only' | 'authorized-local-log';
  readonly host?: OperationTelemetrySummary['host'];
  readonly engine?: EngineId | null;
}

export interface OperationCompletion {
  readonly outcome: TelemetryOutcome;
  readonly errorCode?: ErrorCode | null;
}

export interface LifecycleObservation {
  readonly operation: OperationId;
  readonly started: DiagnosticResult;
  readonly stopped: DiagnosticResult;
  readonly telemetry: TelemetryResult;
  readonly classification: 'available' | 'unavailable';
}

export interface LogPruneAuthorizationPort {
  /** Resolve persisted authority and validate its current status and exact preview scope. Never prompt or issue authority here. */
  authorize(input: {
    readonly preview: LogPrunePreview;
    readonly approval: ApprovalReference;
  }): Promise<{ readonly state: 'authorized' | 'rejected' | 'unavailable' }>;
}

export interface ObservabilityOptions {
  readonly policy: InvocationPolicy;
  readonly distributedVersion: string;
  readonly stderr?: DiagnosticSink;
  readonly clock?: ClockPort;
  readonly os?: OperationTelemetrySummary['os'];
  readonly preferencePath?: string;
  readonly preferences?: TelemetryPreferenceStore;
  readonly localLogPath?: string;
  readonly logPruneAuthorization?: LogPruneAuthorizationPort;
  readonly sink?: QualifiedTelemetrySink;
  readonly signal?: AbortSignal;
  readonly onCompletion?: (result: LifecycleObservation) => void | Promise<void>;
}

export type TelemetryStatus = {
  readonly state: 'ready';
  readonly configured: boolean;
  readonly eligibleAfterNotice: boolean;
  readonly reason: 'ready' | 'opted-out' | 'notice-required' | 'not-configured';
  readonly preference: 'enabled' | 'disabled' | 'default' | 'not-read';
  readonly disclosureVersion: number | null;
} | { readonly state: 'unavailable'; readonly reason: 'preference-read-failed' };

export type TelemetryPreview = { readonly state: 'ready'; readonly event: TelemetryEvent; readonly delivery: 'not-attempted' } |
  { readonly state: 'suppressed'; readonly reason: 'read-only' } |
  { readonly state: 'unavailable'; readonly reason: 'invalid-input' };

export interface ObservabilityLifecycle {
  run<T>(
    operation: ObservedOperation,
    work: () => Promise<T>,
    classify: (value: T) => OperationCompletion,
    classifyError?: (error: unknown) => OperationCompletion,
  ): Promise<T>;
  telemetryStatus(): Promise<TelemetryStatus>;
  setTelemetryPreference(preference: 'enabled' | 'disabled'): Promise<PreferenceWrite | { readonly state: 'unavailable'; readonly reason: 'not-configured' }>;
  previewTelemetry(summary: OperationTelemetrySummary): TelemetryPreview;
  previewLogPrune(): Promise<LogPruneInspection | { readonly state: 'unavailable'; readonly reason: 'not-configured' }>;
  pruneLog(preview: LogPrunePreview, approval: ApprovalReference): Promise<LogPruneResult | {
    readonly state: 'unavailable';
    readonly reason: 'not-configured' | 'authorization-required' | 'authorization-unavailable' | 'authorization-rejected';
    readonly effect: 'unchanged';
  }>;
}

async function boundedAttempt<T>(work: () => T | Promise<T>, milliseconds: number): Promise<
  { readonly state: 'available'; readonly value: T } | { readonly state: 'unavailable' }
> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(work).then((value) => ({ state: 'available' as const, value })),
      new Promise<{ readonly state: 'unavailable' }>((resolve) => {
        timer = setTimeout(() => resolve({ state: 'unavailable' }), milliseconds);
      }),
    ]);
  } catch {
    return { state: 'unavailable' };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function completion(value: unknown): Required<OperationCompletion> {
  const input = record(value, 'completion', ['outcome', 'errorCode']);
  return {
    outcome: oneOf(input.outcome, ['completed', 'blocked', 'failed', 'cancelled', 'unknown'], 'outcome'),
    errorCode: input.errorCode === undefined || input.errorCode === null ? null : oneOf(input.errorCode, ERROR_CODES, 'errorCode'),
  };
}

function osFamily(): OperationTelemetrySummary['os'] {
  switch (process.platform) {
    case 'darwin': return 'macos';
    case 'win32': return 'windows';
    case 'linux': return 'linux';
    default: return 'other';
  }
}

function monotonic(clock: ClockPort): number | null {
  try {
    const value = clock.monotonicMilliseconds();
    return Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER ? value : null;
  } catch {
    return null;
  }
}

function elapsed(start: number | null, end: number | null): number | null {
  return start === null || end === null || end < start ? null : end - start;
}

/** Optional observation wraps work; it never substitutes for mandatory audit or authority. */
export function createObservabilityLifecycle(options: ObservabilityOptions): ObservabilityLifecycle {
  if (options.preferencePath !== undefined && options.preferences !== undefined) {
    throw new TypeError('Select one telemetry preference authority');
  }
  const stderr = options.stderr ?? createStderrDiagnosticSink();
  const clock: ClockPort = options.clock ?? {
    wallTime: () => new Date().toISOString(),
    monotonicMilliseconds: () => performance.now(),
  };
  const preferences = options.preferences ?? (options.preferencePath === undefined ? undefined :
    createUserTelemetryPreferenceStore(options.preferencePath, { ownership: 'missionspec-telemetry-only' }));
  const localLog = options.localLogPath === undefined ? undefined : createAuthorizedJsonlSink(options.localLogPath);
  const diagnostics = createDiagnostics({ clock, stderr, ...(localLog === undefined ? {} : { localLog }) });

  async function emit(event: DiagnosticEvent, persistence: 'console-only' | 'authorized-local-log'): Promise<DiagnosticResult> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        diagnostics.emit(event, persistence),
        new Promise<DiagnosticResult>((resolve) => {
          timer = setTimeout(() => resolve({ state: 'unavailable', consoleFallback: 'unavailable' }), 100);
        }),
      ]);
    } catch {
      return { state: 'unavailable', consoleFallback: 'unavailable' };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async function observeTelemetry(summary: OperationTelemetrySummary): Promise<TelemetryResult> {
    if (hardDisabled(options.policy)) return { state: 'suppressed', reason: 'opted-out' };
    if (options.sink === undefined) return { state: 'suppressed', reason: 'not-configured' };
    let warned = false;
    const telemetryDiagnostics: DiagnosticsPort = {
      async emit(event, persistence) {
        if (warned) return { state: 'unavailable', consoleFallback: 'unavailable' };
        warned = true;
        return emit(event, persistence);
      },
    };
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let finishBudget!: (result: TelemetryResult) => void;
    let externalSignal: AbortSignal | undefined;
    let listening = false;
    let cancellationFailed = false;
    let cancelled = false;
    let result: TelemetryResult = { state: 'unavailable' };
    const abort = (): void => {
      try { controller.abort(); } catch { cancellationFailed = true; }
    };
    const stop = (): void => {
      cancelled = true;
      abort();
      finishBudget({ state: 'unavailable' });
    };
    try {
      const budget = new Promise<TelemetryResult>((resolve) => {
        finishBudget = resolve;
        timer = setTimeout(stop, 1000);
      });
      externalSignal = options.signal;
      if (externalSignal !== undefined && !(externalSignal instanceof AbortSignal)) {
        throw new TypeError('Invalid telemetry cancellation signal');
      }
      listening = externalSignal !== undefined;
      externalSignal?.addEventListener('abort', stop, { once: true });
      if (externalSignal?.aborted) stop();
      result = await Promise.race([
        budget,
        createTelemetryClient({
          policy: options.policy, diagnostics: telemetryDiagnostics, signal: controller.signal,
          sink: options.sink,
          ...(preferences === undefined ? {} : { preferences }),
          writeNotice: (text) => stderr.write(text),
        }).recordCompletion(summary),
      ]);
    } catch {
      result = { state: 'unavailable' };
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (listening) {
        try { externalSignal?.removeEventListener('abort', stop); } catch { cancellationFailed = true; }
      }
      abort();
      if (cancellationFailed || cancelled) result = { state: 'unavailable' };
    }
    if (result.state === 'unavailable') await telemetryDiagnostics.emit({
      contractVersion: 1, operation: summary.operation, engine: null, severity: 'warning',
      code: 'telemetry-unavailable', errorCode: 'provider-unavailable', elapsedMilliseconds: null,
    }, 'console-only');
    return result;
  }

  return Object.freeze({
    async run<T>(
      operation: ObservedOperation, work: () => Promise<T>,
      classify: (value: T) => OperationCompletion, classifyError?: (error: unknown) => OperationCompletion,
    ): Promise<T> {
      if (observingRoot.getStore() === true) return work();
      return observingRoot.run(true, async () => {
        if (operation.scope !== 'root' || operation.access !== 'stateful' ||
          !OPERATION_IDS.includes(operation.operation) || OPERATIONS[operation.operation].defaultAccess === 'read-only') {
          return work();
        }
        const persistence = operation.persistence ?? 'console-only';
        const base = {
          contractVersion: 1 as const, operation: operation.operation, engine: operation.engine ?? null,
        };
        const started = await emit({
          ...base, severity: 'information', code: 'operation-started', errorCode: null, elapsedMilliseconds: null,
        }, persistence);
        const start = monotonic(clock);
        let value: T | undefined;
        let failed = false;
        let originalError: unknown;
        let classificationValid = true;
        let finished: Required<OperationCompletion> = { outcome: 'unknown', errorCode: null };
        try {
          value = await work();
          try { finished = completion(classify(value)); } catch {
            classificationValid = false;
            finished = { outcome: 'unknown', errorCode: 'invalid-input' };
          }
        } catch (error) {
          failed = true;
          originalError = error;
          finished = { outcome: 'failed', errorCode: null };
          if (classifyError !== undefined) {
            try {
              finished = completion(classifyError(error));
              if (finished.outcome === 'completed') throw new TypeError('A thrown operation cannot be completed');
            } catch {
              classificationValid = false;
              finished = { outcome: 'unknown', errorCode: 'invalid-input' };
            }
          }
        }
        const duration = elapsed(start, monotonic(clock));
        const stopped = await emit({
          ...base, severity: finished.outcome === 'failed' ? 'error' : finished.outcome === 'completed' ? 'information' : 'warning',
          code: classificationValid ? 'operation-stopped' : 'boundary-rejected', errorCode: finished.errorCode, elapsedMilliseconds: duration,
        }, persistence);
        let telemetry: TelemetryResult = { state: 'unavailable' };
        try {
          if (classificationValid) telemetry = await observeTelemetry({
            operation: operation.operation, access: 'stateful', distributedVersion: options.distributedVersion,
            outcome: finished.outcome, host: operation.host ?? 'none', os: options.os ?? osFamily(), monotonicDurationMs: duration,
          });
        } catch {
          telemetry = { state: 'unavailable' };
          await emit({
            ...base, severity: 'warning', code: 'telemetry-unavailable', errorCode: 'provider-unavailable', elapsedMilliseconds: null,
          }, 'console-only');
        }
        const reported = await boundedAttempt(() => options.onCompletion?.({
          operation: operation.operation, started, stopped, telemetry,
          classification: classificationValid ? 'available' : 'unavailable',
        }), 100);
        if (reported.state === 'unavailable') await emit({
          ...base, severity: 'warning', code: 'boundary-rejected', errorCode: 'provider-unavailable', elapsedMilliseconds: null,
        }, 'console-only');
        if (failed) throw originalError;
        return value as T;
      });
    },
    async telemetryStatus(): Promise<TelemetryStatus> {
      const configured = options.sink !== undefined;
      if (hardDisabled(options.policy)) return {
        state: 'ready', configured, eligibleAfterNotice: false, reason: 'opted-out',
        preference: 'not-read', disclosureVersion: null,
      };
      try {
        const loaded = preferences === undefined ? { state: 'ready' as const, value: {} } : await preferences.read();
        if (loaded.state !== 'ready') return { state: 'unavailable', reason: 'preference-read-failed' };
        const value = parsePreference(loaded.value);
        const reason = value.preference === 'disabled' ? 'opted-out' : !configured ? 'not-configured' :
          value.disclosureVersion !== DISCLOSURE_VERSION ? 'notice-required' : 'ready';
        return {
          state: 'ready', configured, eligibleAfterNotice: reason === 'ready', reason,
          preference: value.preference ?? 'default', disclosureVersion: value.disclosureVersion ?? null,
        };
      } catch {
        return { state: 'unavailable', reason: 'preference-read-failed' };
      }
    },
    async setTelemetryPreference(preference: 'enabled' | 'disabled') {
      if (preferences === undefined) return { state: 'unavailable' as const, reason: 'not-configured' as const };
      return saveTelemetryPreference(preferences, preference);
    },
    previewTelemetry(value: OperationTelemetrySummary): TelemetryPreview {
      try {
        const parsed = parseTelemetrySummary(value);
        if (parsed.access === 'read-only' || OPERATIONS[parsed.operation].defaultAccess === 'read-only') {
          return { state: 'suppressed', reason: 'read-only' };
        }
        return { state: 'ready', event: telemetryEvent(parsed), delivery: 'not-attempted' };
      } catch {
        return { state: 'unavailable', reason: 'invalid-input' };
      }
    },
    async previewLogPrune() {
      if (localLog === undefined) return { state: 'unavailable' as const, reason: 'not-configured' as const };
      return localLog.previewPrune();
    },
    async pruneLog(preview: LogPrunePreview, approval: ApprovalReference) {
      if (localLog === undefined) return { state: 'unavailable' as const, reason: 'not-configured' as const, effect: 'unchanged' as const };
      let reviewed: LogPrunePreview;
      let reference: ApprovalReference;
      try {
        reviewed = parseLogPrunePreview(preview);
        if (reviewed.path !== options.localLogPath) throw new TypeError('Preview does not match the configured diagnostic file');
      } catch {
        return { state: 'unavailable' as const, reason: 'invalid-preview' as const, effect: 'unchanged' as const };
      }
      try { reference = parseApprovalReference(approval); } catch {
        return { state: 'unavailable' as const, reason: 'authorization-required' as const, effect: 'unchanged' as const };
      }
      const authorization = await boundedAttempt(async () => {
        if (options.logPruneAuthorization === undefined) return 'unavailable';
        const decision = record(await options.logPruneAuthorization.authorize(Object.freeze({
          preview: reviewed, approval: reference,
        })), 'logPruneAuthorization', ['state']);
        return oneOf(decision.state, ['authorized', 'rejected', 'unavailable'], 'logPruneAuthorization.state');
      }, 1000);
      if (authorization.state === 'unavailable' || authorization.value === 'unavailable') {
        return { state: 'unavailable' as const, reason: 'authorization-unavailable' as const, effect: 'unchanged' as const };
      }
      if (authorization.value === 'rejected') {
        return { state: 'unavailable' as const, reason: 'authorization-rejected' as const, effect: 'unchanged' as const };
      }
      return localLog.prune(reviewed);
    },
  });
}
