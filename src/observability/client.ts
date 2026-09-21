import type { DiagnosticsPort, OperationTelemetrySummary, TelemetryPort } from '../ports/contracts.js';
import { OPERATION_IDS } from '../kernel/registry.js';
import {
  DISCLOSURE_VERSION, parseTelemetrySummary, serializeTelemetryEvent, TELEMETRY_OPERATIONS, telemetryEvent,
} from './events.js';
import {
  hardDisabled, parsePreference, TELEMETRY_NOTICE,
} from './policy.js';
import type { InvocationPolicy, TelemetryPreferenceStore } from './policy.js';

export interface TelemetryTransport {
  send(input: {
    readonly endpoint: string;
    readonly body: string;
    readonly signal: AbortSignal;
  }): Promise<{ readonly state: 'delivered' | 'unavailable' }>;
}

export interface QualifiedTelemetrySink {
  readonly endpoint: string;
  readonly transport: TelemetryTransport;
}

export interface TelemetryClientOptions {
  readonly policy: InvocationPolicy;
  readonly sink?: QualifiedTelemetrySink;
  readonly preferences?: TelemetryPreferenceStore;
  readonly diagnostics?: DiagnosticsPort;
  readonly writeNotice?: (text: string) => Promise<void>;
  readonly signal?: AbortSignal;
}

export type TelemetryResult = Awaited<ReturnType<TelemetryPort['recordCompletion']>>;

export function validEndpoint(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' &&
      url.search === '' && url.hash === '' && url.hostname !== '' && url.href === value;
  } catch {
    return false;
  }
}

function safeDiagnostic(options: TelemetryClientOptions, operation: OperationTelemetrySummary['operation']): void {
  try {
    const pending = options.diagnostics?.emit({
      contractVersion: 1, severity: 'warning', code: 'telemetry-unavailable', operation,
      engine: null, errorCode: 'provider-unavailable', elapsedMilliseconds: null,
    }, 'console-only');
    void pending?.catch(() => {});
  } catch {
    // Optional diagnostics must not replace the functional operation's result.
  }
}

export function createTelemetryClient(options: TelemetryClientOptions): TelemetryPort {
  let used = false;
  let reported = false;
  const report = (operation: OperationTelemetrySummary['operation']): void => {
    if (!reported) {
      reported = true;
      safeDiagnostic(options, operation);
    }
  };
  return Object.freeze({
    async recordCompletion(value: OperationTelemetrySummary): Promise<TelemetryResult> {
      if (hardDisabled(options.policy)) return { state: 'suppressed', reason: 'opted-out' };
      // Check the no-side-effect exceptions before configuration, notice, or diagnostic initialization.
      let operationDescriptor: PropertyDescriptor | undefined;
      let accessDescriptor: PropertyDescriptor | undefined;
      try {
        operationDescriptor = value && Object.getOwnPropertyDescriptor(value, 'operation');
        accessDescriptor = value && Object.getOwnPropertyDescriptor(value, 'access');
      } catch {
        return { state: 'unavailable' };
      }
      if ((accessDescriptor && 'value' in accessDescriptor && accessDescriptor.value === 'read-only') ||
        (operationDescriptor && 'value' in operationDescriptor &&
          ['discover', 'clarify', 'analyze', 'onboard'].includes(operationDescriptor.value))) {
        return { state: 'suppressed', reason: 'read-only' };
      }
      if (options.sink === undefined) return { state: 'suppressed', reason: 'not-configured' };
      let summary: OperationTelemetrySummary;
      try {
        summary = parseTelemetrySummary(value);
      } catch {
        const candidate: unknown = operationDescriptor && 'value' in operationDescriptor ? operationDescriptor.value : undefined;
        if (typeof candidate === 'string' && OPERATION_IDS.includes(candidate as OperationTelemetrySummary['operation'])) {
          report(candidate as OperationTelemetrySummary['operation']);
        }
        return { state: 'unavailable' };
      }
      const unavailable = (): TelemetryResult => {
        report(summary.operation);
        return { state: 'unavailable' };
      };
      if (used || !TELEMETRY_OPERATIONS.some((operation) => operation === summary.operation)) return unavailable();
      used = true;
      try {
        if (options.signal?.aborted) return unavailable();
        if (options.preferences === undefined) return { state: 'suppressed', reason: 'notice-required' };
        const loaded = await options.preferences.read();
        if (options.signal?.aborted) return unavailable();
        if (loaded.state !== 'ready') return unavailable();
        const preference = parsePreference(loaded.value);
        if (preference.preference === 'disabled') return { state: 'suppressed', reason: 'opted-out' };
        if (!validEndpoint(options.sink.endpoint)) return unavailable();
        if (preference.disclosureVersion !== DISCLOSURE_VERSION) {
          if (options.policy.channel !== 'interactive' || options.writeNotice === undefined) {
            return { state: 'suppressed', reason: 'notice-required' };
          }
          await options.writeNotice(TELEMETRY_NOTICE + `Qualified destination: ${options.sink.endpoint}\n`);
          if (options.signal?.aborted) return unavailable();
          const saved = await options.preferences.save({ disclosureVersion: DISCLOSURE_VERSION });
          if (saved.state !== 'saved') return unavailable();
          // A newly displayed notice is not prior notice for this completed operation.
          return { state: 'suppressed', reason: 'notice-required' };
        }
        if (options.signal?.aborted) return unavailable();
        const controller = new AbortController();
        let timer: ReturnType<typeof setTimeout> | undefined;
        let onAbort: (() => void) | undefined;
        const budget = new Promise<{ readonly state: 'unavailable' }>((resolve) => {
          const stop = (): void => {
            controller.abort();
            resolve({ state: 'unavailable' });
          };
          timer = setTimeout(stop, 1000);
          onAbort = stop;
          options.signal?.addEventListener('abort', stop, { once: true });
        });
        try {
          const result = await Promise.race([
            budget,
            options.sink.transport.send({
              endpoint: options.sink.endpoint, body: serializeTelemetryEvent(telemetryEvent(summary)),
              signal: controller.signal,
            }),
          ]);
          if (controller.signal.aborted || result.state !== 'delivered') return unavailable();
          return { state: 'delivered' };
        } finally {
          if (timer !== undefined) clearTimeout(timer);
          if (onAbort !== undefined) options.signal?.removeEventListener('abort', onAbort);
          controller.abort();
        }
      } catch {
        return unavailable();
      }
    },
  });
}
