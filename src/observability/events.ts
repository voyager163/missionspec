import { NATIVE_HOSTS } from '../kernel/identifiers.js';
import { ERROR_CODES } from '../kernel/outcomes.js';
import { parseContractVersion } from '../kernel/protocol.js';
import { ENGINE_IDS, OPERATION_IDS, OPERATIONS } from '../kernel/registry.js';
import { ContractError, oneOf, record } from '../kernel/validation.js';
import type { DiagnosticEvent, OperationTelemetrySummary } from '../ports/contracts.js';

export const MAX_EVENT_BYTES = 1024;
export const DISCLOSURE_VERSION = 1;
export const DURATION_BUCKETS = Object.freeze([
  'under-1s', '1s-to-10s', '10s-to-1m', '1m-to-10m', '10m-to-1h', '1h-or-more',
] as const);
export type TelemetryOperationId = Exclude<OperationTelemetrySummary['operation'], 'discover' | 'clarify' | 'analyze' | 'onboard'>;
export const TELEMETRY_OPERATIONS = Object.freeze(
  OPERATION_IDS.filter((id): id is TelemetryOperationId => OPERATIONS[id].defaultAccess !== 'read-only'),
);
export const VERSION_PATTERN = '^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})(-(alpha|beta|rc)\\.(0|[1-9][0-9]{0,5}))?$(?![\\s\\S])';
const versionPattern = new RegExp(VERSION_PATTERN, 'u');
const outcomes = ['completed', 'blocked', 'failed', 'cancelled', 'unknown'] as const;
const hosts = [...NATIVE_HOSTS, 'none', 'multiple', 'unknown'] as const;
const systems = ['macos', 'windows', 'linux', 'other'] as const;
const eventKeys = ['schemaVersion', 'event', 'operation', 'cliVersion', 'outcome', 'host', 'os', 'durationBucket'] as const;

export interface TelemetryEvent {
  readonly schemaVersion: 1;
  readonly event: 'operation-completed';
  readonly operation: TelemetryOperationId;
  readonly cliVersion: string;
  readonly outcome: OperationTelemetrySummary['outcome'];
  readonly host: OperationTelemetrySummary['host'];
  readonly os: OperationTelemetrySummary['os'];
  readonly durationBucket: (typeof DURATION_BUCKETS)[number] | null;
}

export function parseDuration(value: unknown): number | null {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) {
    throw new ContractError('duration', 'expected bounded nonnegative milliseconds or null');
  }
  return value;
}

export function durationBucket(value: unknown): TelemetryEvent['durationBucket'] {
  const duration = parseDuration(value);
  if (duration === null) return null;
  if (duration < 1000) return 'under-1s';
  if (duration < 10_000) return '1s-to-10s';
  if (duration < 60_000) return '10s-to-1m';
  if (duration < 600_000) return '1m-to-10m';
  if (duration < 3_600_000) return '10m-to-1h';
  return '1h-or-more';
}

function version(value: unknown): string {
  if (typeof value !== 'string' || value.length > 48 || !versionPattern.test(value)) {
    throw new ContractError('version', 'expected a bounded release or alpha/beta/rc numeric version');
  }
  return value;
}

export function parseTelemetrySummary(value: unknown): OperationTelemetrySummary {
  const input = record(value, 'summary', [
    'operation', 'access', 'distributedVersion', 'outcome', 'host', 'os', 'monotonicDurationMs',
  ]);
  return Object.freeze({
    operation: oneOf(input.operation, OPERATION_IDS, 'operation'),
    access: oneOf(input.access, ['read-only', 'stateful'], 'access'),
    distributedVersion: version(input.distributedVersion),
    outcome: oneOf(input.outcome, outcomes, 'outcome'),
    host: oneOf(input.host, hosts, 'host'),
    os: oneOf(input.os, systems, 'os'),
    monotonicDurationMs: parseDuration(input.monotonicDurationMs),
  });
}

export function parseTelemetryEvent(value: unknown): TelemetryEvent {
  const input = record(value, 'event', eventKeys);
  if (input.schemaVersion !== 1 || input.event !== 'operation-completed') {
    throw new ContractError('event', 'unsupported telemetry event or schema version');
  }
  return Object.freeze({
    schemaVersion: 1,
    event: 'operation-completed',
    operation: oneOf(input.operation, TELEMETRY_OPERATIONS, 'operation'),
    cliVersion: version(input.cliVersion),
    outcome: oneOf(input.outcome, outcomes, 'outcome'),
    host: oneOf(input.host, hosts, 'host'),
    os: oneOf(input.os, systems, 'os'),
    durationBucket: input.durationBucket === null ? null : oneOf(input.durationBucket, DURATION_BUCKETS, 'durationBucket'),
  });
}

export function telemetryEvent(value: unknown): TelemetryEvent {
  const input = parseTelemetrySummary(value);
  if (input.access !== 'stateful') throw new ContractError('access', 'read-only operations are excluded');
  return parseTelemetryEvent({
    schemaVersion: 1, event: 'operation-completed',
    operation: input.operation, cliVersion: input.distributedVersion, outcome: input.outcome,
    host: input.host, os: input.os, durationBucket: durationBucket(input.monotonicDurationMs),
  });
}

export function serializeTelemetryEvent(value: unknown): string {
  const serialized = JSON.stringify(parseTelemetryEvent(value));
  if (Buffer.byteLength(serialized) > MAX_EVENT_BYTES) {
    throw new ContractError('event', 'event exceeds byte limit');
  }
  return serialized;
}

export function parseDiagnosticEvent(value: unknown): DiagnosticEvent {
  const input = record(value, 'diagnostic', [
    'contractVersion', 'severity', 'code', 'operation', 'engine', 'errorCode', 'elapsedMilliseconds',
  ]);
  return Object.freeze({
    contractVersion: parseContractVersion(input.contractVersion),
    severity: oneOf(input.severity, ['debug', 'information', 'warning', 'error'], 'severity'),
    code: oneOf(input.code, [
      'operation-started', 'operation-stopped', 'boundary-rejected', 'storage-failed', 'telemetry-unavailable',
    ], 'code'),
    operation: oneOf(input.operation, OPERATION_IDS, 'operation'),
    engine: input.engine === null ? null : oneOf(input.engine, ENGINE_IDS, 'engine'),
    errorCode: input.errorCode === null ? null : oneOf(input.errorCode, ERROR_CODES, 'errorCode'),
    elapsedMilliseconds: parseDuration(input.elapsedMilliseconds),
  });
}
