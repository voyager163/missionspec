import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { parsePreference } from '../../observability/policy.js';
import type {
  PreferenceFailureReason, PreferenceRead, PreferenceStorageFailure, PreferenceWrite,
  TelemetryPreference, TelemetryPreferenceStore,
} from '../../observability/policy.js';

export const MAX_PREFERENCE_STORE_BYTES = 65_536;
export const PREFERENCE_BUSY_TIMEOUT_MS = 250;
const applicationId = 0x4d535450;
const schema = `CREATE TABLE missionspec_telemetry_preferences (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  preference TEXT CHECK (preference IN ('enabled', 'disabled')),
  disclosure_version INTEGER CHECK (disclosure_version BETWEEN 1 AND 2147483647)
) STRICT`;
type PreferenceDatabase = Pick<DatabaseSync, 'exec' | 'prepare' | 'close' | 'isTransaction'>;
type AccessResult = { readonly state: 'ready'; readonly value: TelemetryPreference } |
  { readonly state: 'saved' } | PreferenceStorageFailure;
export interface PersistentTelemetryPreferenceStore extends TelemetryPreferenceStore {
  read(): Promise<Extract<PreferenceRead, { state: 'ready' }> | PreferenceStorageFailure>;
  save(value: TelemetryPreference): Promise<Extract<PreferenceWrite, { state: 'saved' }> | PreferenceStorageFailure>;
}
export interface PreferenceStoreOptions {
  readonly ownership: 'missionspec-telemetry-only';
  /** Trusted fault-injection seams, not user or project configuration. */
  readonly openFile?: typeof open;
  readonly openDatabase?: (path: string, readOnly: boolean) => PreferenceDatabase;
}

function errorCode(error: unknown): unknown {
  return typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
}

function failureReason(error: unknown): PreferenceFailureReason {
  if (typeof error === 'object' && error !== null && 'errcode' in error &&
    (error.errcode === 5 || error.errcode === 6)) return 'busy';
  return 'io';
}

function failure(
  reason: PreferenceFailureReason,
  persistence: PreferenceStorageFailure['persistence'] = 'unchanged',
  cleanup: PreferenceStorageFailure['cleanup'] = 'complete',
): PreferenceStorageFailure {
  return { state: 'unavailable', reason, persistence, cleanup };
}

function openDatabase(path: string, readOnly: boolean): PreferenceDatabase {
  return new DatabaseSync(path, {
    readOnly, timeout: PREFERENCE_BUSY_TIMEOUT_MS, defensive: true,
    allowExtension: false, enableDoubleQuotedStringLiterals: false,
  });
}

function readOwnedPreference(database: PreferenceDatabase): TelemetryPreference {
  const app = database.prepare('PRAGMA application_id').get();
  const version = database.prepare('PRAGMA user_version').get();
  const journal = database.prepare('PRAGMA journal_mode').get();
  const pageSize = database.prepare('PRAGMA page_size').get();
  const objects = database.prepare("SELECT type, name, sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").all();
  if (app?.application_id !== applicationId || version?.user_version !== 1 ||
    journal?.journal_mode !== 'delete' || pageSize?.page_size !== 4096 || objects.length !== 1 ||
    objects[0]?.type !== 'table' || objects[0]?.name !== 'missionspec_telemetry_preferences' ||
    objects[0]?.sql !== schema) throw new TypeError('Unrecognized preference store');
  const rows = database.prepare('SELECT singleton, preference, disclosure_version FROM missionspec_telemetry_preferences').all();
  if (rows.length !== 1 || rows[0]?.singleton !== 1) throw new TypeError('Invalid preference record');
  return parsePreference({
    ...(rows[0].preference === null ? {} : { preference: rows[0].preference }),
    ...(rows[0].disclosure_version === null ? {} : { disclosureVersion: rows[0].disclosure_version }),
  });
}

/**
 * The dedicated SQLite file is the sole preference authority. It is never a
 * JSON mirror, and existing JSON/foreign databases are never migrated in place.
 */
export function createUserTelemetryPreferenceStore(
  path: string,
  options: PreferenceStoreOptions,
): PersistentTelemetryPreferenceStore {
  const validPath = typeof path === 'string' && isAbsolute(path) && path.length <= 4096 &&
    !/[\u0000-\u001f\u007f]/u.test(path) && options?.ownership === 'missionspec-telemetry-only';
  const openFile = options?.openFile ?? open;
  const connect = options?.openDatabase ?? openDatabase;

  async function access(patch?: TelemetryPreference): Promise<AccessResult> {
    if (!validPath) return failure('invalid');
    let file: Awaited<ReturnType<typeof open>> | undefined;
    let database: PreferenceDatabase | undefined;
    let created = false;
    let committed = false;
    let commitAttempted = false;
    let transactionStarted = false;
    let reason: PreferenceFailureReason = 'io';
    let result: AccessResult = failure('io');
    let cleanup: PreferenceStorageFailure['cleanup'] = 'complete';
    let persistence: PreferenceStorageFailure['persistence'] = 'unchanged';
    try {
      try {
        file = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      } catch (error) {
        if (errorCode(error) !== 'ENOENT') throw error;
        if (patch === undefined) return { state: 'ready', value: Object.freeze({}) };
        try {
          file = await openFile(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
          created = true;
        } catch (creationError) {
          if (errorCode(creationError) !== 'EEXIST') throw creationError;
          file = await openFile(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
        }
      }
      const info = await file.stat();
      reason = 'unrecognized-store';
      if (!info.isFile() || info.nlink !== 1 || info.size > MAX_PREFERENCE_STORE_BYTES ||
        (process.platform !== 'win32' && (info.uid !== process.getuid?.() || (info.mode & 0o022) !== 0))) {
        throw new TypeError('Unsafe preference store');
      }
      if (!created) {
        const header = Buffer.alloc(100);
        const { bytesRead } = await file.read(header, 0, header.length, 0);
        if (bytesRead !== 100 || header.subarray(0, 16).toString('binary') !== 'SQLite format 3\0' ||
          header.readUInt16BE(16) !== 4096 || header[18] !== 1 || header[19] !== 1) {
          throw new TypeError('Unrecognized preference store');
        }
      }
      reason = 'cleanup-failed';
      await file.close();
      file = undefined;
      reason = 'io';
      database = connect(path, patch === undefined);
      database.exec('PRAGMA trusted_schema = OFF; PRAGMA temp_store = MEMORY; PRAGMA mmap_size = 0');
      if (patch !== undefined) {
        if (created) database.exec('PRAGMA page_size = 4096');
        database.exec('PRAGMA synchronous = EXTRA; PRAGMA fullfsync = ON; PRAGMA max_page_count = 16');
      }
      database.exec(patch === undefined ? 'BEGIN' : 'BEGIN IMMEDIATE');
      transactionStarted = true;
      let current: TelemetryPreference;
      if (created) {
        database.exec(`${schema}; PRAGMA application_id = ${applicationId}; PRAGMA user_version = 1`);
        database.prepare('INSERT INTO missionspec_telemetry_preferences VALUES (1, NULL, NULL)').run();
        current = Object.freeze({});
      } else {
        reason = 'unrecognized-store';
        current = readOwnedPreference(database);
      }
      reason = 'io';
      if (patch !== undefined) {
        const next = parsePreference({ ...current, ...patch });
        database.prepare('UPDATE missionspec_telemetry_preferences SET preference = ?, disclosure_version = ? WHERE singleton = 1')
          .run(next.preference ?? null, next.disclosureVersion ?? null);
      }
      commitAttempted = true;
      database.exec('COMMIT');
      committed = true;
      transactionStarted = false;
      result = patch === undefined ? { state: 'ready', value: current } : { state: 'saved' };
    } catch (error) {
      persistence = committed ? 'committed' : commitAttempted ? 'unknown' : 'unchanged';
      if (database !== undefined && transactionStarted) {
        try {
          if (database.isTransaction) {
            database.exec('ROLLBACK');
            persistence = 'unchanged';
          }
        } catch {
          cleanup = 'incomplete';
          persistence = 'unknown';
        }
      }
      if (created && !committed) cleanup = 'incomplete';
      result = failure(failureReason(error) === 'busy' ? 'busy' : reason, persistence, cleanup);
    } finally {
      if (file !== undefined) {
        try {
          await file.close();
        } catch {
          cleanup = 'incomplete';
          result = failure('cleanup-failed', committed ? 'committed' : persistence, cleanup);
        }
      }
      if (database !== undefined) {
        try {
          database.close();
        } catch {
          cleanup = 'incomplete';
          result = failure('cleanup-failed', committed && patch !== undefined ? 'committed' : persistence, cleanup);
        }
      }
    }
    return result;
  }

  return Object.freeze({
    async read(): ReturnType<PersistentTelemetryPreferenceStore['read']> {
      const result = await access();
      return result.state === 'saved' ? failure('io', 'unknown') : result;
    },
    async save(value: TelemetryPreference): ReturnType<PersistentTelemetryPreferenceStore['save']> {
      let patch: TelemetryPreference;
      try {
        patch = parsePreference(value);
        if (Object.keys(patch).length === 0) return failure('invalid');
      } catch {
        return failure('invalid');
      }
      const result = await access(patch);
      if (result.state === 'ready') return failure('io', 'unknown');
      return result;
    },
  });
}

/** Controls patch only their own field; no stale read can erase a disclosure update. */
export async function saveTelemetryPreference(
  store: TelemetryPreferenceStore,
  preference: 'enabled' | 'disabled',
): Promise<PreferenceWrite> {
  try {
    if (preference !== 'enabled' && preference !== 'disabled') return failure('invalid');
    return await store.save({ preference });
  } catch {
    return failure('io', 'unknown', 'incomplete');
  }
}
