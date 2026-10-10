import { DISCLOSURE_VERSION } from './events.js';
import { record } from '../kernel/validation.js';

export interface TelemetryPreference {
  readonly preference?: 'enabled' | 'disabled';
  readonly disclosureVersion?: number;
}

export type PreferenceFailureReason = 'invalid' | 'io' | 'conflict' | 'busy' | 'unrecognized-store' | 'cleanup-failed';
export interface PreferenceStorageFailure {
  readonly state: 'unavailable';
  readonly reason: PreferenceFailureReason;
  readonly persistence: 'unchanged' | 'committed' | 'unknown';
  readonly cleanup: 'complete' | 'incomplete';
}
export type PreferenceRead =
  | { readonly state: 'ready'; readonly value: TelemetryPreference }
  | { readonly state: 'unavailable'; readonly reason?: PreferenceFailureReason; readonly cleanup?: 'complete' | 'incomplete' };
export type PreferenceWrite =
  | { readonly state: 'saved' }
  | {
    readonly state: 'unavailable';
    readonly reason: PreferenceFailureReason;
    readonly persistence?: PreferenceStorageFailure['persistence'];
    readonly cleanup?: PreferenceStorageFailure['cleanup'];
  };
export interface TelemetryPreferenceStore {
  read(): Promise<PreferenceRead>;
  /** Atomically merge the supplied fields with the current committed preference. */
  save(value: TelemetryPreference): Promise<PreferenceWrite>;
}

export interface InvocationPolicy {
  readonly disabled?: boolean;
  readonly tests?: boolean;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly channel: 'interactive' | 'json' | 'mcp' | 'unattended';
}

type Switch = 'true' | 'false' | 'absent' | 'invalid';
function parseSwitch(value: unknown): Switch {
  if (value === undefined) return 'absent';
  if (typeof value !== 'string') return 'invalid';
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return 'true';
  if (['0', 'false', 'no', 'off'].includes(normalized)) return 'false';
  return 'invalid';
}

export function hardDisabled(policy: InvocationPolicy): boolean {
  try {
    if (policy.disabled !== undefined && policy.disabled !== false) return true;
    if (policy.tests !== undefined && policy.tests !== false) return true;
    if (!['interactive', 'json', 'mcp', 'unattended'].includes(policy.channel)) return true;
    if (policy.environment !== undefined &&
      (typeof policy.environment !== 'object' || policy.environment === null || Array.isArray(policy.environment))) return true;
    const environment = policy.environment ?? process.env;
    const product = parseSwitch(environment.MISSIONSPEC_TELEMETRY);
    const dnt = parseSwitch(environment.DO_NOT_TRACK);
    const ci = parseSwitch(environment.CI);
    if (product === 'false' || product === 'invalid') return true;
    if (dnt === 'true' || dnt === 'invalid' || ci === 'true' || ci === 'invalid') return true;
    if (environment.NODE_TEST_CONTEXT !== undefined) return true;
    if (environment.NODE_ENV !== undefined) {
      const mode = environment.NODE_ENV.trim().toLowerCase();
      if (mode !== 'production' && mode !== 'development') return true;
    }
    return false;
  } catch {
    return true;
  }
}

export function parsePreference(value: unknown): TelemetryPreference {
  const input = record(value, 'preference', ['preference', 'disclosureVersion']);
  if (input.preference !== undefined && input.preference !== 'enabled' && input.preference !== 'disabled') {
    throw new TypeError('Invalid telemetry preference');
  }
  if (Object.hasOwn(input, 'preference') && input.preference === undefined) {
    throw new TypeError('Invalid telemetry preference');
  }
  if (Object.hasOwn(input, 'disclosureVersion') &&
    (typeof input.disclosureVersion !== 'number' || !Number.isSafeInteger(input.disclosureVersion) ||
      input.disclosureVersion < 1 || input.disclosureVersion > DISCLOSURE_VERSION)) {
    throw new TypeError('Invalid telemetry disclosure');
  }
  return Object.freeze({
    ...(input.preference === undefined ? {} : { preference: input.preference }),
    ...(input.disclosureVersion === undefined ? {} : { disclosureVersion: input.disclosureVersion as number }),
  });
}

export const TELEMETRY_NOTICE = [
  'MissionSpec optional usage analytics: default-on after this disclosure, not affirmative consent.',
  'Fields: schema/event version, registered operation, CLI version, coarse outcome, selected host, OS family, duration bucket.',
  'No persistent IDs, client timestamps, paths, arguments, project content, raw errors, model names, or tokens.',
  'A qualified MissionSpec-operated Azure service is required; planned remote analytics/total retention is 180 days, with no extra archive.',
  'Disable with --no-telemetry, MISSIONSPEC_TELEMETRY=0, DO_NOT_TRACK=1, or saved user preference; CI/tests are excluded.',
  'Network operators can observe connection metadata. Disabling does not delete previously accepted aggregates.',
].join('\n') + '\n';
