import type { DatabaseSync } from 'node:sqlite';
import type { AttemptRecord, RunSnapshot } from '../../engines/execution/contracts.js';
import type { AcceptanceRecord, EvidenceReference } from '../../engines/verification/contracts.js';
import { parseId, type EvidenceId, type RunId } from '../../kernel/identifiers.js';
import type { Outcome } from '../../kernel/outcomes.js';
import {
  digestContent, parseDigest, parseWorkspaceBinding, sameRevisionBinding, sameWorkspaceBinding,
  type ContentDigest, type WorkspaceBinding,
} from '../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../kernel/validation.js';
import type { RuntimeStorePort } from '../../ports/contracts.js';
import type {
  EvidencePruneCompletion, EvidencePruneInventory, EvidencePrunePrepared, EvidencePruneState, EvidencePruningStorePort,
} from '../../ports/evidence-pruning.js';
import { parseApprovalReference } from '../../kernel/authority.js';
import { failure, StoreFailure } from './failures.js';
import {
  checkFiles, parseOptions, prepareFiles, requireSupportedPlatform,
  type RuntimeStoreOptions, type StoreFiles,
} from './filesystem.js';
import { parseAcceptance, parseAttempt, parseEnvelope, parseEvidence, parseRun, type RunEnvelope } from './parsers.js';
import { makePruneInventory, parsePruneCompletion, parsePrunePrepared } from './pruning.js';

export type { RuntimeStoreOptions } from './filesystem.js';

export interface SqliteRuntimeStore extends RuntimeStorePort {
  readonly evidencePruning: EvidencePruningStorePort;
  close(): Outcome<null>;
}

const APPLICATION_ID = 0x4d534e31;
const SCHEMA_VERSION = 3;
const tables = {
  store_metadata: `CREATE TABLE store_metadata (
    id TEXT PRIMARY KEY CHECK (id = 'workspace'),
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  runs: `CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    revision TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  run_history: `CREATE TABLE run_history (
    run_id TEXT NOT NULL REFERENCES runs(id),
    revision TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (run_id, revision)
  ) STRICT, WITHOUT ROWID`,
  attempts: `CREATE TABLE attempts (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    work_order_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  evidence: `CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    attempt_id TEXT REFERENCES attempts(id),
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  acceptances: `CREATE TABLE acceptances (
    approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    run_revision TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (run_id, run_revision) REFERENCES run_history(run_id, revision)
  ) STRICT, WITHOUT ROWID`,
  evidence_prune_prepared: `CREATE TABLE evidence_prune_prepared (
    id TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
  evidence_prune_items: `CREATE TABLE evidence_prune_items (
    evidence_id TEXT PRIMARY KEY REFERENCES evidence(id),
    prune_id TEXT NOT NULL REFERENCES evidence_prune_prepared(id)
  ) STRICT, WITHOUT ROWID`,
  evidence_prune_completed: `CREATE TABLE evidence_prune_completed (
    prune_id TEXT PRIMARY KEY REFERENCES evidence_prune_prepared(id),
    digest TEXT NOT NULL,
    payload TEXT NOT NULL
  ) STRICT, WITHOUT ROWID`,
};

interface Stored<T> {
  readonly value: T;
  readonly digest: ContentDigest;
  readonly payload: string;
}
interface Owned<T> extends Stored<T> {
  readonly runId: RunId;
}
interface StoreState {
  readonly runs: Map<string, Stored<RunEnvelope>>;
  readonly history: readonly Owned<RunEnvelope>[];
  readonly attempts: Map<string, Owned<AttemptRecord>>;
  readonly evidence: Map<string, Owned<EvidenceReference>>;
  readonly acceptances: Map<string, Owned<AcceptanceRecord> & { readonly runRevision: ContentDigest }>;
  readonly prunePrepared: Map<string, Stored<EvidencePrunePrepared>>;
  readonly pruneItems: Map<string, ContentDigest>;
  readonly pruneCompleted: Map<string, Stored<EvidencePruneCompletion>>;
}

function encoded<T>(value: T): Stored<T> {
  const payload = JSON.stringify(value);
  text(payload, 'payload', 16 * 1024 * 1024);
  return { value, payload, digest: digestContent(payload) };
}

function decoded<T>(payload: unknown, digest: unknown, parse: (value: unknown) => T): Stored<T> {
  const raw = text(payload, 'payload', 16 * 1024 * 1024);
  const expected = parseDigest(digest);
  if (digestContent(raw) !== expected) throw new StoreFailure('corrupt', 'Persisted content digest does not match.');
  const untrusted: unknown = JSON.parse(raw);
  const value = parse(untrusted);
  if (JSON.stringify(value) !== raw) throw new StoreFailure('corrupt', 'Persisted content is not canonical contract data.');
  return { value, payload: raw, digest: expected };
}

function intact(condition: unknown, message: string): asserts condition {
  if (!condition) throw new StoreFailure('corrupt', message);
}

function requireReference(condition: unknown, message: string): asserts condition {
  if (!condition) throw new StoreFailure('conflict', message);
}

function sameRecord(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function requireWorkspace(actual: WorkspaceBinding, expected: WorkspaceBinding): void {
  if (!sameWorkspaceBinding(actual, expected)) {
    throw new StoreFailure('workspace-mismatch', 'Runtime store workspace identity/root binding does not match the expected local workspace.');
  }
}

function checkSchema(db: DatabaseSync): void {
  const version = db.prepare('PRAGMA user_version').get();
  const application = db.prepare('PRAGMA application_id').get();
  if (version?.user_version !== SCHEMA_VERSION || application?.application_id !== APPLICATION_ID) {
    throw new StoreFailure('incompatible', 'Runtime store application/schema version is unsupported; no migration was attempted.');
  }
  if (db.prepare('PRAGMA journal_mode').get()?.journal_mode !== 'delete') {
    throw new StoreFailure('incompatible', 'Runtime store requires DELETE journaling; no journal downgrade was attempted.');
  }
  const schema = db.prepare('SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name').all();
  if (schema.length !== Object.keys(tables).length) {
    throw new StoreFailure('incompatible', 'Runtime store has an unexpected schema object set.');
  }
  for (const row of schema) {
    const name = row.name;
    if (typeof name !== 'string' || !Object.hasOwn(tables, name) || row.type !== 'table' ||
        row.tbl_name !== name || row.sql !== Reflect.get(tables, name)) {
      throw new StoreFailure('incompatible', 'Runtime store schema definition does not match the supported format.');
    }
  }
  const integrity = db.prepare('PRAGMA integrity_check').all();
  intact(integrity.length === 1 && integrity[0]?.integrity_check === 'ok', 'SQLite integrity check failed.');
  intact(db.prepare('PRAGMA foreign_key_check').all().length === 0, 'Runtime store contains orphaned foreign keys.');
}

function loadState(db: DatabaseSync, expectedWorkspace: WorkspaceBinding): StoreState {
  checkSchema(db);
  try {
    const metadata = db.prepare('SELECT id, digest, payload FROM store_metadata').all();
    const row = metadata[0];
    intact(metadata.length === 1 && row?.id === 'workspace', 'Runtime store workspace metadata is missing or malformed.');
    const workspace = decoded(row.payload, row.digest, parseWorkspaceBinding).value;
    requireWorkspace(workspace, expectedWorkspace);
    const runs = new Map<string, Stored<RunEnvelope>>();
    for (const row of db.prepare('SELECT id, revision, payload FROM runs').all()) {
      const id = parseId('run', row.id);
      const stored = decoded(row.payload, row.revision, parseEnvelope);
      intact(sameWorkspaceBinding(stored.value.snapshot.revisions.workspace, workspace), 'Run belongs to another workspace.');
      intact(stored.value.snapshot.id === id, 'Run row identity disagrees with its content.');
      runs.set(id, stored);
    }
    const history = db.prepare('SELECT run_id, revision, payload FROM run_history').all().map((row) => {
      const runId = parseId('run', row.run_id);
      const stored = decoded(row.payload, row.revision, parseEnvelope);
      intact(sameWorkspaceBinding(stored.value.snapshot.revisions.workspace, workspace), 'Run history belongs to another workspace.');
      intact(stored.value.snapshot.id === runId, 'Run history identity disagrees with its content.');
      return { ...stored, runId };
    });
    const attempts = new Map<string, Owned<AttemptRecord>>();
    for (const row of db.prepare('SELECT id, run_id, work_order_id, digest, payload FROM attempts').all()) {
      const stored = decoded(row.payload, row.digest, parseAttempt);
      intact(stored.value.id === parseId('attempt', row.id) &&
        stored.value.workOrderId === parseId('workOrder', row.work_order_id), 'Attempt row identity disagrees with its content.');
      attempts.set(stored.value.id, { ...stored, runId: parseId('run', row.run_id) });
    }
    const evidence = new Map<string, Owned<EvidenceReference>>();
    for (const row of db.prepare('SELECT id, run_id, attempt_id, digest, payload FROM evidence').all()) {
      const stored = decoded(row.payload, row.digest, parseEvidence);
      intact(sameWorkspaceBinding(stored.value.revisions.workspace, workspace), 'Evidence belongs to another workspace.');
      intact(stored.value.id === parseId('evidence', row.id) && stored.value.attemptId === row.attempt_id,
        'Evidence row identity disagrees with its content.');
      evidence.set(stored.value.id, { ...stored, runId: parseId('run', row.run_id) });
    }
    const acceptances: StoreState['acceptances'] = new Map();
    for (const row of db.prepare('SELECT approval_id, run_id, run_revision, digest, payload FROM acceptances').all()) {
      const stored = decoded(row.payload, row.digest, parseAcceptance);
      intact(sameWorkspaceBinding(stored.value.revisions.workspace, workspace), 'Acceptance belongs to another workspace.');
      intact(stored.value.approval.id === parseId('approval', row.approval_id), 'Acceptance identity disagrees with its content.');
      acceptances.set(stored.value.approval.id, {
        ...stored, runId: parseId('run', row.run_id), runRevision: parseDigest(row.run_revision),
      });
    }
    const prunePrepared: StoreState['prunePrepared'] = new Map();
    for (const row of db.prepare('SELECT id, digest, payload FROM evidence_prune_prepared').all()) {
      const stored = decoded(row.payload, row.digest, parsePrunePrepared);
      intact(stored.value.id === parseDigest(row.id) &&
        sameWorkspaceBinding(stored.value.plan.inventory.workspace, workspace), 'Prune preparation identity or workspace differs.');
      prunePrepared.set(stored.value.id, stored);
    }
    const pruneItems: StoreState['pruneItems'] = new Map();
    for (const row of db.prepare('SELECT evidence_id, prune_id FROM evidence_prune_items').all()) {
      pruneItems.set(parseId('evidence', row.evidence_id), parseDigest(row.prune_id));
    }
    const pruneCompleted: StoreState['pruneCompleted'] = new Map();
    for (const row of db.prepare('SELECT prune_id, digest, payload FROM evidence_prune_completed').all()) {
      const stored = decoded(row.payload, row.digest, parsePruneCompletion);
      intact(stored.value.id === parseDigest(row.prune_id), 'Prune completion identity differs.');
      pruneCompleted.set(stored.value.id, stored);
    }
    const state = { runs, history, attempts, evidence, acceptances, prunePrepared, pruneItems, pruneCompleted };
    validateRelationships(state);
    validatePruning(state);
    return state;
  } catch (error) {
    if (error instanceof ContractError || error instanceof SyntaxError) {
      throw new StoreFailure('corrupt', 'Persisted row does not satisfy the current closed contracts.');
    }
    throw error;
  }
}

function validateRelationships(state: StoreState): void {
  const workOrders = new Map<string, string>();
  const sequences = new Set<string>();
  for (const [id, run] of state.runs) {
    intact(state.history.some((entry) => entry.runId === id && entry.digest === run.digest &&
      entry.payload === run.payload), 'Current run revision has no matching immutable history.');
    const revisions = new Map(state.history.filter((entry) => entry.runId === id).map((entry) => [entry.digest, entry]));
    const visited = new Set<string>();
    let previous: ContentDigest | 'absent' = run.digest;
    while (previous !== 'absent') {
      const history = revisions.get(previous);
      intact(history !== undefined && !visited.has(previous), 'Run revision history is missing or cyclic.');
      visited.add(previous);
      previous = history.value.previousRevision;
    }
    intact(visited.size === revisions.size, 'Run revision history contains disconnected branches.');
  }
  for (const entry of state.history) {
    const current = state.runs.get(entry.runId);
    intact(current !== undefined, 'Run history has no run.');
    intact(entry.value.snapshot.revisions.changeId === current.value.snapshot.revisions.changeId,
      'Run history changes its change identity.');
    intact((entry.value.snapshot.elapsedMs ?? 0) <= (current.value.snapshot.elapsedMs ?? 0), 'Consumed duration cannot decrease.');
    if (entry.value.snapshot.observedAt !== undefined) intact(current.value.snapshot.observedAt !== undefined &&
      Date.parse(entry.value.snapshot.observedAt) <= Date.parse(current.value.snapshot.observedAt), 'Observed execution time cannot move backwards.');
    for (const plan of [
      ...(entry.value.snapshot.plan === undefined ? [] : [entry.value.snapshot.plan]),
      ...(entry.value.snapshot.replans ?? []).map((entry) => entry.plan),
    ]) {
      intact(plan.orders.every((work) => work.runId === entry.runId &&
        sameWorkspaceBinding(work.revisions.workspace, current.value.snapshot.revisions.workspace) &&
        work.revisions.changeId === current.value.snapshot.revisions.changeId), 'Plan belongs to a different run, workspace or change.');
    }
    intact(entry.value.snapshot.attempts.every((attempt, index) =>
      sameRecord(attempt, current.value.snapshot.attempts[index])), 'Run history is not append-only.');
    intact((entry.value.snapshot.admissions ?? []).every((admission, index) =>
      sameRecord(admission, current.value.snapshot.admissions?.[index])), 'Admission history is not append-only.');
    intact((entry.value.snapshot.completions ?? []).every((completion, index) =>
      sameRecord(completion, current.value.snapshot.completions?.[index])), 'Completion evidence history is not append-only.');
    intact((entry.value.snapshot.reconciliations ?? []).every((receipt, index) =>
      sameRecord(receipt, current.value.snapshot.reconciliations?.[index])), 'Reconciliation history is not append-only.');
    if (entry.value.snapshot.plan !== undefined) intact(sameRecord(entry.value.snapshot.plan, current.value.snapshot.plan), 'Reviewed plan is immutable.');
    intact((entry.value.snapshot.replans ?? []).every((plan, index) =>
      sameRecord(plan, current.value.snapshot.replans?.[index])), 'Reapproved plans are append-only.');
    intact((entry.value.snapshot.admissions ?? []).every((admission) =>
      sameWorkspaceBinding(admission.workOrder.revisions.workspace, current.value.snapshot.revisions.workspace) &&
      admission.workOrder.revisions.changeId === current.value.snapshot.revisions.changeId),
    'Admission scope differs from its run.');
    for (const attempt of entry.value.snapshot.attempts) {
      const stored = state.attempts.get(attempt.id);
      intact(stored?.runId === entry.runId && sameRecord(stored.value, attempt), 'Snapshot attempt reference is invalid.');
    }
    for (const reference of entry.value.evidence) {
      const stored = state.evidence.get(reference.id);
      intact(stored?.runId === entry.runId && stored.digest === reference.digest &&
        current.value.evidence.some((item) => item.id === reference.id && item.digest === reference.digest),
      'Snapshot evidence reference is invalid.');
    }
    const completedTasks = new Set<string>();
    for (const completion of entry.value.snapshot.completions ?? []) {
      intact(!completedTasks.has(completion.taskId), 'Duplicate verified task completion.');
      completedTasks.add(completion.taskId);
      const admission = entry.value.snapshot.admissions?.find((item) => item.workOrder.id === completion.workOrderId && item.workOrder.task.id === completion.taskId);
      const attempt = state.attempts.get(completion.attemptId);
      intact(admission !== undefined && attempt?.runId === entry.runId && attempt.value.workOrderId === completion.workOrderId &&
        attempt.value.observation.state === 'host-returned' && attempt.value.observation.sourceAfter === completion.source, 'Completion requires its actual task attempt.');
      for (const id of completion.evidence) {
        const item = state.evidence.get(id);
        intact(item?.runId === entry.runId && item.value.source === completion.source &&
          admission.workOrder.task.checks.includes(item.value.checkId) &&
          entry.value.evidence.some((reference) => reference.id === id), 'Completion evidence must exist in this run revision and task.');
      }
      intact(new Set(completion.evidence.map((id) => state.evidence.get(id)!.value.checkId)).size === admission.workOrder.task.checks.length,
        'Completion requires evidence for every task check.');
    }
  }
  for (const attempt of state.attempts.values()) {
    const run = state.runs.get(attempt.runId);
    intact(run !== undefined && run.value.snapshot.attempts.some((item) => item.id === attempt.value.id), 'Orphaned attempt row.');
    const owner = workOrders.get(attempt.value.workOrderId);
    intact(owner === undefined || owner === attempt.runId, 'Work order spans multiple runs.');
    workOrders.set(attempt.value.workOrderId, attempt.runId);
    const sequence = `${attempt.value.workOrderId}:${attempt.value.sequence.kind === 'initial' ? 0 : attempt.value.sequence.number}`;
    intact(!sequences.has(sequence), 'Work order has duplicate initial or repair sequence observations.');
    sequences.add(sequence);
    if (attempt.value.sequence.kind === 'repair') {
      const previous = state.attempts.get(attempt.value.sequence.failedAttempt);
      intact(previous?.runId === attempt.runId && previous.value.workOrderId === attempt.value.workOrderId,
        'Repair references another run or work order.');
      const previousNumber = previous.value.sequence.kind === 'initial' ? 0 : previous.value.sequence.number;
      intact(previousNumber + 1 === attempt.value.sequence.number, 'Repair sequence is not contiguous.');
      const previousIndex = run.value.snapshot.attempts.findIndex((item) => item.id === previous.value.id);
      const currentIndex = run.value.snapshot.attempts.findIndex((item) => item.id === attempt.value.id);
      intact(previousIndex < currentIndex, 'Repair precedes its referenced attempt.');
    }
  }
  for (const item of state.evidence.values()) {
    const run = state.runs.get(item.runId);
    intact(run?.value.evidence.some((reference) => reference.id === item.value.id && reference.digest === item.digest),
      'Orphaned evidence row.');
    intact(state.history.some((entry) => entry.runId === item.runId &&
      entry.value.evidence.some((reference) => reference.id === item.value.id) &&
      sameRevisionBinding(entry.value.snapshot.revisions, item.value.revisions)),
    'Evidence revisions have no matching run history.');
    if (item.value.attemptId !== null) {
      const attempt = state.attempts.get(item.value.attemptId);
      intact(attempt?.runId === item.runId, 'Evidence references an attempt from another run.');
      if (attempt.value.observation.state === 'host-returned') {
        intact(attempt.value.observation.sourceAfter === item.value.source, 'Evidence source differs from its observed attempt.');
      }
    } else {
      intact(item.value.source === item.value.revisions.source, 'Unattributed evidence source differs from its revision binding.');
    }
  }
  for (const acceptance of state.acceptances.values()) {
    const history = state.history.find((entry) =>
      entry.runId === acceptance.runId && entry.digest === acceptance.runRevision);
    intact(history !== undefined && sameRevisionBinding(history.value.snapshot.revisions, acceptance.value.revisions),
      'Acceptance revisions have no matching run history.');
    for (const id of acceptance.value.evidence) {
      const item = state.evidence.get(id);
      intact(item?.runId === acceptance.runId && item.value.source === acceptance.value.source &&
        sameRevisionBinding(item.value.revisions, acceptance.value.revisions) &&
        history.value.evidence.some((reference) => reference.id === id),
      'Acceptance contains orphaned, cross-run, or mismatched evidence.');
    }
  }
}

function workspaceQuiescent(state: StoreState): boolean {
  return [...state.runs.values()].every((run) =>
    run.value.snapshot.quiescence === 'confirmed' && !['running', 'outcome-unknown'].includes(run.value.snapshot.state));
}

function pendingPrunes(state: StoreState): boolean {
  return [...state.prunePrepared.keys()].some((id) => !state.pruneCompleted.has(id));
}

function acceptanceImpact(state: StoreState, ids: readonly EvidenceId[]): EvidencePruneInventory['acceptances'] {
  return [...state.acceptances.values()].flatMap((entry) => {
    const affectedEvidence = entry.value.evidence.filter((id) => ids.includes(id)).sort();
    return affectedEvidence.length === 0 ? [] : [{
      approval: entry.value.approval, revision: entry.digest, affectedEvidence,
    }];
  }).sort((a, b) => a.approval.id < b.approval.id ? -1 : a.approval.id > b.approval.id ? 1 : 0);
}

function pruneInventory(state: StoreState, workspace: WorkspaceBinding, input: readonly EvidenceId[]): EvidencePruneInventory {
  const ids = unique(array(input, 'prune.evidence', (id) => parseId('evidence', id), 1), 'prune.evidence');
  requireReference(workspaceQuiescent(state), 'Raw evidence pruning requires every workspace run to be quiescent.');
  requireReference(!pendingPrunes(state), 'A prepared prune must be recovered before another prune can begin.');
  const items = ids.map((id) => {
    const item = state.evidence.get(id);
    requireReference(item !== undefined && item.value.storage.state === 'retained' && !state.pruneItems.has(id),
      'Pruning requires existing retained evidence that has never entered a prune lifecycle.');
    return {
      id, runId: item.runId, runRevision: state.runs.get(item.runId)!.digest,
      evidenceDigest: item.digest, path: item.value.storage.path, rawDigest: item.value.storage.digest,
    };
  });
  return makePruneInventory({ schemaVersion: 1, workspace, items, acceptances: acceptanceImpact(state, ids) });
}

function pruneState(state: StoreState, id: string): EvidencePruneState | null {
  const prepared = state.prunePrepared.get(id);
  if (prepared === undefined) return null;
  const completion = state.pruneCompleted.get(id);
  return completion === undefined
    ? { state: 'prepared', prepared: prepared.value, revision: prepared.digest }
    : { state: 'pruned', prepared: prepared.value, completion: completion.value, revision: completion.digest };
}

function effectiveEvidence(state: StoreState, id: EvidenceId): EvidenceReference | null {
  const original = state.evidence.get(id)?.value;
  if (original === undefined) return null;
  const pruneId = state.pruneItems.get(id);
  if (pruneId === undefined) return original;
  const completion = state.pruneCompleted.get(pruneId)?.value;
  return { ...original, storage: completion === undefined
    ? { state: 'unavailable', reason: `Raw evidence prune is prepared and requires recovery: ${pruneId}` }
    : { state: 'pruned', prunedAt: completion.completedAt, approval: completion.approval } };
}

function validatePruning(state: StoreState): void {
  intact([...state.prunePrepared.keys()].filter((id) => !state.pruneCompleted.has(id)).length <= 1,
    'Only one prepared prune may fence the workspace at a time.');
  for (const [id, prepared] of state.prunePrepared) {
    const inventory = prepared.value.plan.inventory;
    const references = [...state.pruneItems].filter(([, owner]) => owner === id);
    intact(references.length === inventory.items.length, 'Prune preparation has incomplete item references.');
    for (const item of inventory.items) {
      const original = state.evidence.get(item.id);
      intact(state.pruneItems.get(item.id) === id && original?.runId === item.runId &&
        original.digest === item.evidenceDigest && original.value.storage.state === 'retained' &&
        original.value.storage.path === item.path && original.value.storage.digest === item.rawDigest,
      'Prune preparation must preserve and reference its exact original retained evidence.');
      intact(state.history.some((entry) => entry.runId === item.runId && entry.digest === item.runRevision &&
        entry.value.evidence.some((reference) => reference.id === item.id)), 'Prune run-revision reference is dangling.');
    }
    intact(sameRecord(inventory.acceptances, acceptanceImpact(state, inventory.items.map((item) => item.id))),
      'Prune acceptance impact differs from immutable accepted history.');
  }
  for (const [id, owner] of state.pruneItems) {
    intact(state.prunePrepared.get(owner)?.value.plan.inventory.items.some((item) => item.id === id), 'Dangling prune item.');
  }
  for (const [id, completed] of state.pruneCompleted) {
    const prepared = state.prunePrepared.get(id);
    intact(prepared !== undefined && prepared.digest === completed.value.preparedDigest &&
      Date.parse(completed.value.completedAt) >= Date.parse(prepared.value.preparedAt), 'Prune completion has no matching preparation.');
  }
  intact(!pendingPrunes(state) || workspaceQuiescent(state), 'Prepared pruning cannot coexist with active or unreconciled runs.');
}

class Store implements SqliteRuntimeStore {
  #closed = false;
  #unusable = false;
  #uncertainCommit = false;
  readonly #db: DatabaseSync;
  readonly #files: StoreFiles;
  readonly #readOnly: boolean;
  readonly #workspace: WorkspaceBinding;
  readonly evidencePruning: EvidencePruningStorePort;

  constructor(
    db: DatabaseSync,
    files: StoreFiles,
    readOnly: boolean,
    workspace: WorkspaceBinding,
  ) {
    this.#db = db;
    this.#files = files;
    this.#readOnly = readOnly;
    this.#workspace = workspace;
    this.evidencePruning = Object.freeze({
      access: readOnly ? 'read-only' : 'read-write',
      inspectEvidencePrune: async (ids: readonly EvidenceId[]) =>
        this.#transaction(false, (state) => pruneInventory(state, this.#workspace, ids)),
      prepareEvidencePrune: (record: EvidencePrunePrepared) => this.#preparePrune(record),
      readEvidencePrune: async (id: ContentDigest): Promise<Outcome<EvidencePruneState | null>> => {
        try {
          const identity = parseDigest(id);
          return this.#transaction(false, (state) => pruneState(state, identity));
        } catch (error) { return failure(error); }
      },
      listEvidencePrunes: async () => this.#transaction(false, (state) =>
        [...state.prunePrepared.keys()].sort().map((id) => pruneState(state, id)!)),
      completeEvidencePrune: (record: EvidencePruneCompletion) => this.#completePrune(record),
    });
  }

  #transaction<T>(write: boolean, operation: (state: StoreState) => T): Outcome<T> {
    let committing = false;
    try {
      if (this.#closed) throw new StoreFailure('closed', 'Runtime store is closed.');
      if (this.#unusable || (write && this.#uncertainCommit)) {
        throw new StoreFailure('unknown', 'Runtime store requires explicit reopen and reconciliation before further writes.');
      }
      if (write && this.#readOnly) throw new StoreFailure('read-only', 'Runtime store was explicitly opened read-only.');
      checkFiles(this.#files);
      this.#db.exec(write ? 'BEGIN IMMEDIATE' : 'BEGIN');
      const state = loadState(this.#db, this.#workspace);
      const result = operation(state);
      committing = true;
      this.#db.exec('COMMIT');
      return { status: 'ok', value: result };
    } catch (error) {
      if (!this.#closed && this.#db.isTransaction) {
        try {
          this.#db.exec('ROLLBACK');
          committing = false;
        } catch {
          this.#unusable = true;
          this.close();
          return failure(new StoreFailure('unknown', 'Runtime transaction rollback could not be confirmed; reopen and reconcile.'));
        }
      }
      if (committing && write) {
        this.#uncertainCommit = true;
        return failure(new StoreFailure('unknown', 'Runtime transaction commit could not be confirmed; reopen and reconcile.'));
      }
      return failure(error);
    }
  }

  async listRuns(): ReturnType<RuntimeStorePort['listRuns']> {
    return this.#transaction(false, (state) => [...state.runs.values()].map((entry) => entry.value.snapshot));
  }

  async readRun(runId: RunId): ReturnType<RuntimeStorePort['readRun']> {
    try {
      const id = parseId('run', runId);
      return this.#transaction(false, (state) => {
        const stored = state.runs.get(id);
        return stored === undefined ? null : { revision: stored.digest, snapshot: stored.value.snapshot };
      });
    } catch (error) { return failure(error); }
  }

  async readEvidence(id: EvidenceId): ReturnType<RuntimeStorePort['readEvidence']> {
    try {
      const identity = parseId('evidence', id);
      return this.#transaction(false, (state) => effectiveEvidence(state, identity));
    } catch (error) { return failure(error); }
  }

  async readRunEvidence(runId: RunId): ReturnType<RuntimeStorePort['readRunEvidence']> {
    try {
      const id = parseId('run', runId);
      return this.#transaction(false, (state) => {
        const stored = state.runs.get(id);
        if (stored === undefined) throw new StoreFailure('missing', 'The selected run is not recorded.');
        return stored.value.evidence.filter((reference) => !state.pruneItems.has(reference.id)).map((reference) => reference.id);
      });
    } catch (error) { return failure(error); }
  }

  async readAcceptance(reference: Parameters<RuntimeStorePort['readAcceptance']>[0]): ReturnType<RuntimeStorePort['readAcceptance']> {
    try {
      const identity = parseApprovalReference(reference);
      return this.#transaction(false, (state) => state.acceptances.get(identity.id)?.value ?? null);
    } catch (error) { return failure(error); }
  }

  async commitRun(input: Parameters<RuntimeStorePort['commitRun']>[0]): ReturnType<RuntimeStorePort['commitRun']> {
    try {
      const raw = record(input, 'commitRun', ['expectedRevision', 'snapshot', 'attempts', 'evidence']);
      const expected = raw.expectedRevision === 'absent' ? 'absent' : parseDigest(raw.expectedRevision);
      const snapshot = parseRun(raw.snapshot);
      const attempts = array(raw.attempts, 'commitRun.attempts', parseAttempt);
      const evidence = array(raw.evidence, 'commitRun.evidence', parseEvidence);
      requireWorkspace(snapshot.revisions.workspace, this.#workspace);
      for (const item of evidence) requireWorkspace(item.revisions.workspace, this.#workspace);
      unique(attempts.map((item) => item.id), 'commitRun.attempts');
      unique(evidence.map((item) => item.id), 'commitRun.evidence');
      return this.#transaction(true, (state) => {
        requireReference(!pendingPrunes(state), 'Prepared evidence pruning fences run mutations until explicit recovery completes.');
        const old = state.runs.get(snapshot.id);
        if ((old?.digest ?? 'absent') !== expected) {
          throw new StoreFailure('stale-revision', 'Expected run revision is stale; read and review before retrying.');
        }
        if ((snapshot.admissions?.length ?? 0) > (old?.value.snapshot.admissions?.length ?? 0)) {
          requireReference(snapshot.state === 'running' && snapshot.quiescence === 'unconfirmed',
            'New admissions must first persist a nonterminal running observation.');
          requireReference(![...state.runs.values()].some((run) => run.value.snapshot.id !== snapshot.id &&
            (run.value.snapshot.quiescence !== 'confirmed' || run.value.snapshot.state === 'running' || run.value.snapshot.state === 'outcome-unknown')),
          'Another workspace run is active or unreconciled; serial admission is required.');
        }
        if (old !== undefined) {
          requireReference(old.value.snapshot.revisions.changeId === snapshot.revisions.changeId,
            'An existing run cannot change its change identity.');
          requireReference((snapshot.elapsedMs ?? 0) >= (old.value.snapshot.elapsedMs ?? 0), 'Consumed duration cannot decrease.');
          requireReference(old.value.snapshot.observedAt === undefined || snapshot.observedAt !== undefined &&
            Date.parse(snapshot.observedAt) >= Date.parse(old.value.snapshot.observedAt), 'Observed execution time cannot move backwards.');
          requireReference(old.value.snapshot.attempts.every((attempt, index) => sameRecord(attempt, snapshot.attempts[index])),
            'Run attempts are append-only and immutable.');
          requireReference((old.value.snapshot.admissions ?? []).every((admission, index) => sameRecord(admission, snapshot.admissions?.[index])),
            'Run admissions are append-only and immutable.');
          requireReference(old.value.snapshot.plan === undefined || sameRecord(old.value.snapshot.plan, snapshot.plan), 'Reviewed execution plan is immutable.');
          requireReference((old.value.snapshot.replans ?? []).every((item, index) => sameRecord(item, snapshot.replans?.[index])), 'Reapproved plans are append-only.');
          requireReference((old.value.snapshot.completions ?? []).every((item, index) => sameRecord(item, snapshot.completions?.[index])), 'Task completions are append-only.');
          requireReference((old.value.snapshot.reconciliations ?? []).every((item, index) => sameRecord(item, snapshot.reconciliations?.[index])), 'Reconciliation receipts are append-only.');
        }
        for (const completion of (snapshot.completions ?? []).slice(old?.value.snapshot.completions?.length ?? 0)) {
          requireReference(!completion.evidence.some((id) => state.pruneItems.has(id)),
            'New task completion cannot rely on prepared or pruned raw evidence.');
        }
        for (const attempt of attempts) {
          requireReference(snapshot.attempts.some((item) => sameRecord(item, attempt)),
            'Submitted attempt must occur identically in the snapshot.');
        }
        for (const attempt of snapshot.attempts) {
          const existing = state.attempts.get(attempt.id);
          requireReference(existing === undefined || (existing.runId === snapshot.id && sameRecord(existing.value, attempt)),
            'Attempt identity already belongs to different content or another run.');
          requireReference(existing !== undefined || attempts.some((item) => sameRecord(item, attempt)),
            'Snapshot contains an attempt that was not supplied for persistence.');
          requireReference(![...state.attempts.values()].some((item) =>
            item.value.workOrderId === attempt.workOrderId && item.runId !== snapshot.id),
          'Work order already belongs to another run.');
        }
        const references = new Map((old?.value.evidence ?? []).map((item) => [item.id, item]));
        for (const item of evidence) {
          const stored = encoded(item);
          const existing = state.evidence.get(item.id);
          requireReference(existing === undefined || (existing.runId === snapshot.id && existing.payload === stored.payload),
            'Evidence identity already belongs to different content or another run.');
          if (existing === undefined) {
            requireReference(sameRevisionBinding(item.revisions, snapshot.revisions),
              'New evidence must bind to the committed snapshot revisions.');
          }
          references.set(item.id, { id: item.id, digest: stored.digest });
        }
        const nextEvidence = [...references.values()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
        if (old !== undefined && sameRecord(snapshot, old.value.snapshot) && sameRecord(nextEvidence, old.value.evidence)) {
          return { revision: old.digest };
        }
        const next = encoded<RunEnvelope>({ snapshot, evidence: nextEvidence, previousRevision: old?.digest ?? 'absent' });
        this.#db.prepare('INSERT INTO runs (id, revision, payload) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET revision = excluded.revision, payload = excluded.payload')
          .run(snapshot.id, next.digest, next.payload);
        this.#db.prepare('INSERT INTO run_history (run_id, revision, payload) VALUES (?, ?, ?) ON CONFLICT (run_id, revision) DO NOTHING')
          .run(snapshot.id, next.digest, next.payload);
        for (const attempt of attempts) {
          const stored = encoded(attempt);
          this.#db.prepare('INSERT INTO attempts (id, run_id, work_order_id, digest, payload) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING')
            .run(attempt.id, snapshot.id, attempt.workOrderId, stored.digest, stored.payload);
        }
        for (const item of evidence) {
          if (item.attemptId !== null) {
            requireReference(snapshot.attempts.some((attempt) => attempt.id === item.attemptId),
              'Evidence attempt must belong to this run.');
          }
          const stored = encoded(item);
          this.#db.prepare('INSERT INTO evidence (id, run_id, attempt_id, digest, payload) VALUES (?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING')
            .run(item.id, snapshot.id, item.attemptId, stored.digest, stored.payload);
        }
        try {
          loadState(this.#db, this.#workspace);
        } catch (error) {
          if (error instanceof StoreFailure && error.kind === 'corrupt') {
            throw new StoreFailure('conflict', 'Commit would violate append-only runtime references or source bindings.');
          }
          throw error;
        }
        return { revision: next.digest };
      });
    } catch (error) { return failure(error); }
  }

  async recordAcceptance(input: AcceptanceRecord): ReturnType<RuntimeStorePort['recordAcceptance']> {
    try {
      const acceptance = parseAcceptance(input);
      requireWorkspace(acceptance.revisions.workspace, this.#workspace);
      const stored = encoded(acceptance);
      return this.#transaction(true, (state) => {
        const existing = state.acceptances.get(acceptance.approval.id);
        if (existing !== undefined) {
          requireReference(existing.payload === stored.payload,
            'Acceptance approval identity is already bound to different content.');
          return { revision: existing.digest };
        }
        const first = state.evidence.get(acceptance.evidence[0]!);
        requireReference(first !== undefined, 'Acceptance references missing evidence.');
        requireReference(![...state.runs.values()].some((run) => run.value.snapshot.quiescence !== 'confirmed' ||
          ['running', 'outcome-unknown'].includes(run.value.snapshot.state)), 'Acceptance requires established workspace quiescence.');
        requireReference(sameRevisionBinding(state.runs.get(first.runId)!.value.snapshot.revisions, acceptance.revisions),
          'Acceptance must still match the current run revision.');
        for (const id of acceptance.evidence) {
          const item = state.evidence.get(id);
          requireReference(!state.pruneItems.has(id), 'New acceptance cannot rely on prepared or pruned raw evidence.');
          requireReference(item !== undefined && item.runId === first.runId &&
            item.value.source === acceptance.source && sameRevisionBinding(item.value.revisions, acceptance.revisions),
          'Acceptance references missing, cross-run, or mismatched evidence.');
        }
        const history = state.history.find((entry) => entry.runId === first.runId &&
          sameRevisionBinding(entry.value.snapshot.revisions, acceptance.revisions) &&
          acceptance.evidence.every((id) => entry.value.evidence.some((item) => item.id === id)));
        requireReference(history !== undefined, 'Acceptance must bind to a recorded run revision containing its evidence.');
        this.#db.prepare('INSERT INTO acceptances (approval_id, run_id, run_revision, digest, payload) VALUES (?, ?, ?, ?, ?)')
          .run(acceptance.approval.id, first.runId, history.digest, stored.digest, stored.payload);
        return { revision: stored.digest };
      });
    } catch (error) { return failure(error); }
  }

  async #preparePrune(input: EvidencePrunePrepared): Promise<Outcome<EvidencePruneState>> {
    try {
      const prepared = parsePrunePrepared(input);
      requireWorkspace(prepared.plan.inventory.workspace, this.#workspace);
      const stored = encoded(prepared);
      return this.#transaction(true, (state) => {
        const existing = state.prunePrepared.get(prepared.id);
        if (existing !== undefined) {
          requireReference(existing.payload === stored.payload, 'Prune identity cannot be rebound to different preparation content.');
          return pruneState(state, prepared.id)!;
        }
        const current = pruneInventory(state, this.#workspace, prepared.plan.inventory.items.map((item) => item.id));
        if (current.digest !== prepared.plan.inventory.digest) {
          throw new StoreFailure('stale-revision', 'Evidence, run revisions or accepted-history impact changed after pruning preview.');
        }
        this.#db.prepare('INSERT INTO evidence_prune_prepared (id, digest, payload) VALUES (?, ?, ?)')
          .run(prepared.id, stored.digest, stored.payload);
        for (const item of prepared.plan.inventory.items) {
          this.#db.prepare('INSERT INTO evidence_prune_items (evidence_id, prune_id) VALUES (?, ?)').run(item.id, prepared.id);
        }
        const next = loadState(this.#db, this.#workspace);
        return pruneState(next, prepared.id)!;
      });
    } catch (error) { return failure(error); }
  }

  async #completePrune(input: EvidencePruneCompletion): Promise<Outcome<EvidencePruneState>> {
    try {
      const completion = parsePruneCompletion(input);
      const stored = encoded(completion);
      return this.#transaction(true, (state) => {
        const prepared = state.prunePrepared.get(completion.id);
        requireReference(prepared !== undefined && prepared.digest === completion.preparedDigest,
          'Prune completion must refer to the exact durable preparation.');
        const existing = state.pruneCompleted.get(completion.id);
        if (existing !== undefined) {
          requireReference(existing.payload === stored.payload, 'Prune completion is immutable.');
          return pruneState(state, completion.id)!;
        }
        requireReference(workspaceQuiescent(state), 'Prune completion requires confirmed workspace quiescence.');
        requireReference(Date.parse(completion.completedAt) >= Date.parse(prepared.value.preparedAt),
          'Prune completion cannot precede its preparation.');
        this.#db.prepare('INSERT INTO evidence_prune_completed (prune_id, digest, payload) VALUES (?, ?, ?)')
          .run(completion.id, stored.digest, stored.payload);
        return pruneState(loadState(this.#db, this.#workspace), completion.id)!;
      });
    } catch (error) { return failure(error); }
  }

  close(): Outcome<null> {
    if (this.#closed) return { status: 'ok', value: null };
    try {
      this.#db.close();
      this.#closed = true;
      return { status: 'ok', value: null };
    } catch (error) { return failure(error); }
  }
}

/**
 * Explicit lifecycle boundary. Importing this module never opens SQLite or touches disk.
 * This adapter stores records; it does not issue or resolve local-user authority.
 */
export async function openRuntimeStore(options: RuntimeStoreOptions): Promise<Outcome<SqliteRuntimeStore>> {
  let db: DatabaseSync | undefined;
  try {
    requireSupportedPlatform();
    const parsed = parseOptions(options);
    const [major, minor] = process.versions.node.split('.').map(Number);
    if (major !== 24 || minor === undefined || minor < 21) {
      throw new StoreFailure('unavailable', 'The SQLite adapter requires qualified Node 24.21 or later in the Node 24 line.');
    }
    let sqlite: typeof import('node:sqlite');
    try { sqlite = await import('node:sqlite'); } catch {
      throw new StoreFailure('unavailable', 'Built-in node:sqlite is unavailable; no addon fallback is permitted.');
    }
    const files = prepareFiles(parsed);
    db = new sqlite.DatabaseSync(files.filename, {
      readOnly: parsed.mode === 'read-only',
      enableForeignKeyConstraints: true,
      enableDoubleQuotedStringLiterals: false,
      allowExtension: false,
      timeout: parsed.busyTimeoutMs,
    });
    db.exec('PRAGMA trusted_schema = OFF');
    if (parsed.mode === 'read-only') db.exec('PRAGMA query_only = ON');
    else db.exec('PRAGMA synchronous = FULL');
    if (parsed.mode === 'create') {
      db.exec('BEGIN IMMEDIATE');
      let committing = false;
      try {
        for (const sql of Object.values(tables)) db.exec(sql);
        const workspace = encoded(parsed.expectedWorkspace);
        db.prepare("INSERT INTO store_metadata (id, digest, payload) VALUES ('workspace', ?, ?)")
          .run(workspace.digest, workspace.payload);
        db.exec(`PRAGMA application_id = ${APPLICATION_ID}`);
        db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
        committing = true;
        db.exec('COMMIT');
      } catch (error) {
        if (db.isTransaction) {
          try {
            db.exec('ROLLBACK');
            committing = false;
          } catch {
            throw new StoreFailure('unknown', 'Runtime store initialization rollback could not be confirmed.');
          }
        }
        if (committing) throw new StoreFailure('unknown', 'Runtime store initialization commit could not be confirmed.');
        throw error;
      }
    }
    const store = new Store(db, files, parsed.mode === 'read-only', parsed.expectedWorkspace);
    const inspection = await store.readRun(parseId('run', 'RUN-storage-inspection'));
    if (inspection.status !== 'ok') {
      store.close();
      return inspection;
    }
    return { status: 'ok', value: store };
  } catch (error) {
    try { db?.close(); } catch { /* Failed initialization is never treated as a usable store. */ }
    return failure(error);
  }
}
