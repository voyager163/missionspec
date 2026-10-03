import { lstatSync } from 'node:fs';
import path from 'node:path';
import { LocalWorkspace, makeFilePlan, parseRuntimeSelectionPlan, runtimeSelectionCompletionRecords, writeMutation, type FilePlan } from '../adapters/filesystem/local-workspace.js';
import { openWorkspaceRuntimeStore, type SqliteRuntimeStore, type RuntimeSnapshot } from '../adapters/persistence/index.js';
import { inspectRuntimeReplica, materializeRuntimeSnapshot, validateRuntimeSnapshot } from '../adapters/persistence/sqlite-runtime-store.js';
import { checkPrivatePath, parseOptions } from '../adapters/persistence/filesystem.js';
import { readPrivateStateFile } from '../adapters/persistence/lifecycle-files.js';
import { resolveRuntimeState, runtimeSelectionPath } from '../adapters/persistence/selection.js';
import { withStateLifecycleLock } from '../adapters/persistence/evidence-files.js';
import { digestApprovalRequest, parseApprovalRequest, type ApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { digestEffectScope, type RequestedEffect } from '../kernel/effects.js';
import { parseId, parseProjectPath, type EvidenceId } from '../kernel/identifiers.js';
import { digestContent, parseDigest, parseWorkspaceBinding, sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../kernel/revisions.js';
import { array, oneOf, record, text, unique } from '../kernel/validation.js';
import type { LocalAuthorityPort } from '../ports/contracts.js';
import type { Outcome } from '../kernel/outcomes.js';
import { requireApproval, unavailableAuthority } from './authority.js';
import { WorkflowError } from './errors.js';
import { planRuntimeMigration } from './runtime-migrations.js';

const MAX_BACKUP_BYTES = 6_000_000;
const exclusions = ['authority-grants-and-revocations', 'host-admission-fences', 'canonical-project-documents', 'telemetry-and-preferences'] as const;
export interface RuntimeBackup {
  readonly formatVersion: 1;
  readonly workspace: WorkspaceBinding;
  readonly ledger: RuntimeSnapshot;
  readonly evidence: readonly {
    readonly id: EvidenceId;
    readonly state: 'included' | 'pruned' | 'unavailable';
    readonly content: string | null;
  }[];
  readonly exclusions: typeof exclusions;
  readonly digest: ContentDigest;
}
export interface RuntimeLifecyclePreview {
  readonly id: ContentDigest;
  readonly request: ApprovalRequest;
  readonly action: 'backup' | 'stage' | 'restore' | 'select';
  readonly ledger: ContentDigest | null;
  readonly artifact: ContentDigest;
  readonly destination: string | null;
}
interface SelectionStage {
  readonly schemaVersion: 1;
  readonly workspace: WorkspaceBinding;
  readonly sourceSelection: ContentDigest | 'absent';
  readonly sourceDirectory: string;
  readonly directory: string;
  readonly snapshot: ContentDigest;
  readonly id: ContentDigest;
}

function value<T>(outcome: Outcome<T>): T {
  if (outcome.status !== 'ok') throw new WorkflowError(outcome.error.code, outcome.error.message);
  return outcome.value;
}
function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT';
}
function exists(filename: string): boolean {
  try { lstatSync(filename); return true; } catch (error) { if (missing(error)) return false; throw error; }
}
function boundedBackup(body: Omit<RuntimeBackup, 'digest'>): RuntimeBackup {
  const content = JSON.stringify(body);
  if (Buffer.byteLength(content) > MAX_BACKUP_BYTES - 100) throw new WorkflowError('limit-reached', 'Backup exceeds the 6 MB bounded logical-plus-raw format; no partial backup is written.');
  return { ...body, digest: digestContent(content) };
}
function evidenceContent(content: string, id: EvidenceId, expected: ContentDigest): void {
  if (digestContent(content) !== expected) throw new WorkflowError('evidence-unavailable', 'Raw evidence content differs from its immutable ledger digest.');
  const raw = record(JSON.parse(content) as unknown, 'backup.raw', ['schemaVersion', 'evidenceId', 'basis', 'result', 'output']);
  if (JSON.stringify(raw) !== content) throw new WorkflowError('evidence-unavailable', 'Raw evidence must use its original canonical envelope; noncanonical bytes are preserved, not rewritten.');
  if (raw.schemaVersion !== 1 || raw.evidenceId !== id || typeof raw.output !== 'string') {
    throw new WorkflowError('evidence-unavailable', 'Raw evidence is not a supported original observation.');
  }
  oneOf(raw.basis, ['executed', 'static-inspection', 'agent-review'], 'backup.raw.basis');
  oneOf(raw.result, ['passed', 'failed'], 'backup.raw.result');
}

export async function validateRuntimeBackup(input: unknown, expected: WorkspaceBinding): Promise<RuntimeBackup> {
  const raw = record(input, 'runtimeBackup', ['formatVersion', 'workspace', 'ledger', 'evidence', 'exclusions', 'digest']);
  if (raw.formatVersion !== 1) throw new WorkflowError('unsupported-version', 'Only logical backup format 1 is supported.');
  const workspace = parseWorkspaceBinding(raw.workspace);
  if (!sameWorkspaceBinding(workspace, expected)) throw new WorkflowError('scope-exceeded', 'Backup belongs to a different workspace/root; automatic adoption is forbidden.');
  const inspected = value(await validateRuntimeSnapshot(raw.ledger, workspace));
  const evidence = array(raw.evidence, 'runtimeBackup.evidence', (item) => {
    const entry = record(item, 'backup.evidence', ['id', 'state', 'content']);
    return {
      id: parseId('evidence', entry.id),
      state: oneOf(entry.state, ['included', 'pruned', 'unavailable'], 'backup.evidence.state'),
      content: entry.content === null ? null : text(entry.content, 'backup.evidence.content', MAX_BACKUP_BYTES),
    };
  });
  unique(evidence.map((entry) => entry.id), 'backup.evidence');
  if (evidence.length !== inspected.evidence.length || JSON.stringify(raw.exclusions) !== JSON.stringify(exclusions)) {
    throw new WorkflowError('invalid-input', 'Backup must account for every effective evidence record and independent excluded state.');
  }
  for (const [index, item] of inspected.evidence.entries()) {
    const raw = evidence[index]!;
    if (raw.id !== item.id) throw new WorkflowError('invalid-input', 'Backup evidence inventory is not canonical.');
    if (item.storage.state === 'retained') {
      if (item.storage.path !== `.missionspec/evidence/${item.id}.json` || raw.state !== 'included' || raw.content === null) {
        throw new WorkflowError('evidence-unavailable', 'Retained evidence must include its exact canonical raw file.');
      }
      evidenceContent(raw.content, item.id, item.storage.digest);
    } else if (raw.content !== null || raw.state !== item.storage.state) {
      throw new WorkflowError('invalid-input', 'Pruned/unavailable evidence cannot acquire invented raw content.');
    }
  }
  const backup = boundedBackup({ formatVersion: 1, workspace, ledger: inspected.snapshot, evidence, exclusions });
  if (backup.digest !== parseDigest(raw.digest)) throw new WorkflowError('invalid-input', 'Backup digest differs from its canonical payload.');
  return backup;
}

/** No reset/rollback API: independent authority and the healthy current ledger remain authoritative. */
export class LocalRuntimeState {
  private constructor(readonly files: LocalWorkspace, private readonly authority: LocalAuthorityPort, private readonly now: () => string) {}

  static async open(root: string, options: { readonly authority?: LocalAuthorityPort; readonly now?: () => string } = {}): Promise<LocalRuntimeState> {
    const authority = options.authority ?? unavailableAuthority;
    const now = options.now ?? (() => new Date().toISOString());
    return new LocalRuntimeState(await LocalWorkspace.open(root, { authority, now }), authority, now);
  }

  private async workspace(): Promise<WorkspaceBinding> {
    const workspace = await this.files.identity();
    if (workspace === null) throw new WorkflowError('not-found', 'Explicit workspace identity is required; state operations never initialize or rebind it.');
    return workspace;
  }

  private async store<T>(write: boolean, operation: (store: SqliteRuntimeStore) => Promise<T>): Promise<T> {
    const store = value(await openWorkspaceRuntimeStore({
      workspaceRoot: this.files.root, expectedWorkspace: await this.workspace(), mode: write ? 'read-write' : 'read-only',
    }));
    try { return await operation(store); } finally { value(store.close()); }
  }

  async status() {
    return this.store(false, async (store) => ({
      ...value(await store.inspectState()), selection: resolveRuntimeState(this.files.root, await this.workspace()).kind,
      writesPerformed: false as const,
    }));
  }

  private preview(action: RuntimeLifecyclePreview['action'], workspace: WorkspaceBinding,
    ledger: ContentDigest | null, artifact: ContentDigest, destination: string | null): RuntimeLifecyclePreview {
    const subject = { action, workspace, ledger, artifact, destination };
    const id = digestContent(JSON.stringify(subject));
    const effects: readonly RequestedEffect[] = [{ kind: 'runtime-state', action, subject: id }];
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'onboard', purpose: 'integration',
      binding: { kind: 'project', workspace, revision: id, effects: digestEffectScope(effects) }, effects,
    });
    return { id, request, action, ledger, artifact, destination };
  }

  private async authorize(preview: RuntimeLifecyclePreview, approval: ApprovalReference): Promise<void> {
    const request = this.preview(preview.action, await this.workspace(), preview.ledger, preview.artifact, preview.destination);
    if (request.id !== preview.id || digestApprovalRequest(request.request) !== digestApprovalRequest(preview.request)) {
      throw new WorkflowError('stale-revision', 'Lifecycle review was modified.');
    }
    await requireApproval(this.authority, approval, request.request, this.now());
  }

  private async capture(snapshot: RuntimeSnapshot): Promise<RuntimeBackup> {
    const inspected = value(await validateRuntimeSnapshot(snapshot, await this.workspace()));
    const evidence: RuntimeBackup['evidence'][number][] = [];
    for (const item of inspected.evidence) {
      if (item.storage.state !== 'retained') {
        evidence.push({ id: item.id, state: item.storage.state, content: null });
      } else {
        if (item.storage.path !== `.missionspec/evidence/${item.id}.json`) throw new WorkflowError('evidence-unavailable', 'Backup requires canonical private raw evidence paths.');
        const content = readPrivateStateFile(path.join(this.files.root, item.storage.path), MAX_BACKUP_BYTES);
        evidenceContent(content, item.id, item.storage.digest);
        evidence.push({ id: item.id, state: 'included', content });
      }
    }
    return boundedBackup({ formatVersion: 1, workspace: inspected.snapshot.workspace, ledger: inspected.snapshot, evidence, exclusions });
  }

  async previewBackup(): Promise<RuntimeLifecyclePreview> {
    return this.store(false, async (store) => {
      const snapshot = value(await store.snapshot());
      const backup = await this.capture(snapshot);
      if (value(await store.snapshot()).digest !== snapshot.digest) throw new WorkflowError('stale-revision', 'Runtime changed during backup review.');
      return this.preview('backup', backup.workspace, snapshot.digest, backup.digest, null);
    });
  }

  private async immutable(area: 'backups' | 'recovery', name: string, content: unknown): Promise<string> {
    const relative = `.missionspec/${area}/${name}.json`;
    const filename = path.join(this.files.root, relative);
    if (exists(filename)) {
      if (readPrivateStateFile(filename, MAX_BACKUP_BYTES) !== JSON.stringify(content)) throw new WorkflowError('conflict', 'A different immutable recovery record already exists; original bytes are retained.');
    } else {
      try { await this.files.recordRuntime(area, name, content); }
      catch (error) {
        const code: unknown = typeof error === 'object' && error !== null ? Reflect.get(error, 'code') : undefined;
        if (code === 'ENOSPC' || code === 'EDQUOT') throw new WorkflowError('limit-reached', 'State capacity or quota is exhausted; preserve partial recovery files and inspect before retrying.');
        throw error;
      }
    }
    return relative;
  }

  async backup(preview: RuntimeLifecyclePreview, approval: ApprovalReference) {
    if (preview.action !== 'backup' || preview.ledger === null) throw new WorkflowError('invalid-input', 'Select a backup preview.');
    await this.authorize(preview, approval);
    return this.store(true, async (store) => value(await store.withLifecycleLease(preview.ledger!, async (snapshot) =>
      withStateLifecycleLock(this.files, await this.workspace(), preview.id, async () => {
        const backup = await this.capture(snapshot);
        if (backup.digest !== preview.artifact) throw new WorkflowError('stale-revision', 'Raw evidence changed after backup review.');
        await this.authorize(preview, approval);
        const file = await this.immutable('backups', backup.digest.slice(7), backup);
        return { state: 'backed-up' as const, digest: backup.digest, file, completeness: 'ledger-and-accounted-raw-evidence' as const, exclusions };
      }))));
  }

  async readBackup(file: string): Promise<RuntimeBackup> {
    const relative = parseProjectPath(file);
    if (!relative.startsWith('.missionspec/')) throw new WorkflowError('scope-exceeded', 'Backup input must be in private .missionspec storage.');
    return validateRuntimeBackup(JSON.parse(readPrivateStateFile(path.join(this.files.root, relative), MAX_BACKUP_BYTES)) as unknown, await this.workspace());
  }

  async previewStage(input: unknown): Promise<RuntimeLifecyclePreview> {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    return this.preview('stage', backup.workspace, null, backup.digest, null);
  }

  async stage(input: unknown, preview: RuntimeLifecyclePreview, approval: ApprovalReference) {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    const current = await this.previewStage(backup);
    if (current.id !== preview.id) throw new WorkflowError('stale-revision', 'Selected backup changed.');
    await this.authorize(preview, approval);
    return withStateLifecycleLock(this.files, backup.workspace, preview.id, async () => {
      await this.authorize(preview, approval);
      const file = await this.immutable('recovery', `snapshot-${backup.digest.slice(7)}`, backup);
      return { state: 'staged' as const, file, digest: backup.digest, activation: 'requires-healthy-current-state-continuity' as const };
    });
  }

  private async continuity(backup: RuntimeBackup, current: RuntimeSnapshot) {
    const inspected = value(await validateRuntimeSnapshot(current, backup.workspace));
    if (!inspected.quiescent || inspected.pendingPrunes) throw new WorkflowError('conflict', 'Activation requires current recorded quiescence and completed pruning; user approval is not proof a remote host stopped.');
    for (const [table, rows] of Object.entries(backup.ledger.rows)) {
      const known = new Set(current.rows[table]!.map((row) => JSON.stringify(row)));
      for (const row of rows) {
        if (table === 'runs') {
          if (!current.rows.run_history!.some((history) => history[0] === row[0] && history[1] === row[1] && history[2] === row[2])) {
            throw new WorkflowError('conflict', 'Current ledger cannot establish continuity with this backup run; recovery stays inert.');
          }
        } else if (!known.has(JSON.stringify(row))) {
          throw new WorkflowError('conflict', 'Backup has facts missing from current authoritative history; automatic rollback/merge would lose independent safety history.');
        }
      }
    }
    return inspected;
  }

  async previewRestore(input: unknown): Promise<RuntimeLifecyclePreview> {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    return this.store(false, async (store) => {
      const current = value(await store.snapshot());
      const inspected = await this.continuity(backup, current);
      for (const raw of backup.evidence) {
        const live = inspected.evidence.find((item) => item.id === raw.id);
        if (raw.content === null || live?.storage.state !== 'retained') continue;
        const filename = path.join(this.files.root, live.storage.path);
        if (exists(filename) && readPrivateStateFile(filename, MAX_BACKUP_BYTES) !== raw.content) throw new WorkflowError('stale-revision', 'Newer raw evidence bytes are preserved; restore cannot overwrite them.');
      }
      return this.preview('restore', backup.workspace, current.digest, backup.digest, null);
    });
  }

  async restore(input: unknown, preview: RuntimeLifecyclePreview, approval: ApprovalReference) {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    if ((await this.previewRestore(backup)).id !== preview.id) throw new WorkflowError('stale-revision', 'Restore review no longer matches current state.');
    await this.authorize(preview, approval);
    return this.store(true, async (store) => value(await store.withLifecycleLease(preview.ledger!, async (snapshot) =>
      withStateLifecycleLock(this.files, backup.workspace, preview.id, async () => {
        const live = await this.continuity(backup, snapshot);
        await this.authorize(preview, approval);
        await this.immutable('recovery', `snapshot-${backup.digest.slice(7)}`, backup);
        await this.immutable('recovery', `restore-${preview.id.slice(7)}`, { schemaVersion: 1, preview, backup: backup.digest });
        let restored = 0;
        let suppressed = 0;
        for (const raw of backup.evidence) {
          if (raw.content === null) continue;
          const item = live.evidence.find((entry) => entry.id === raw.id);
          if (item?.storage.state !== 'retained') { suppressed += 1; continue; }
          evidenceContent(raw.content, raw.id, item.storage.digest);
          await this.authorize(preview, approval);
          const filename = path.join(this.files.root, item.storage.path);
          if (exists(filename)) {
            if (readPrivateStateFile(filename, MAX_BACKUP_BYTES) !== raw.content) throw new WorkflowError('stale-revision', 'Restore preserves newer evidence bytes; recovery remains pending.');
          } else {
            await this.files.recordRuntime('evidence', raw.id, JSON.parse(raw.content) as unknown);
            if (readPrivateStateFile(filename, MAX_BACKUP_BYTES) !== raw.content) throw new WorkflowError('effect-outcome-unknown', 'Restored evidence differs; retain recovery preparation.');
            restored += 1;
          }
        }
        await this.immutable('recovery', `restore-${preview.id.slice(7)}.done`, { schemaVersion: 1, id: preview.id, ledger: snapshot.digest, state: 'restored' });
        return { state: 'restored' as const, restored, suppressed, ledger: 'preserved-current' as const, runsResumed: 0 };
      }))));
  }

  async previewSelection(directory: string): Promise<RuntimeLifecyclePreview> {
    const workspace = await this.workspace();
    if ((await this.files.pending()).length !== 0) throw new WorkflowError('conflict', 'Pending file recovery blocks another runtime selection.');
    parseOptions({ directory, workspaceRoot: this.files.root, expectedWorkspace: workspace, mode: 'create' });
    checkPrivatePath(path.dirname(directory), true, true);
    const selected = resolveRuntimeState(this.files.root, workspace);
    if (directory === selected.directory) throw new WorkflowError('conflict', 'That runtime location is already selected.');
    return this.store(false, async (store) => {
      const snapshot = value(await store.snapshot());
      const inspected = value(await validateRuntimeSnapshot(snapshot, workspace));
      if (!inspected.quiescent || inspected.pendingPrunes) throw new WorkflowError('conflict', 'State relocation requires quiescence and completed pruning.');
      return this.preview('select', workspace, snapshot.digest,
        digestContent(JSON.stringify({ selected, snapshot: snapshot.digest, directory })), directory);
    });
  }

  async prepareSelection(preview: RuntimeLifecyclePreview, approval: ApprovalReference) {
    if (preview.action !== 'select' || preview.destination === null || preview.ledger === null ||
        (await this.previewSelection(preview.destination)).id !== preview.id) throw new WorkflowError('stale-revision', 'State selection review changed.');
    const workspace = await this.workspace();
    await this.authorize(preview, approval);
    return this.store(true, async (store) => value(await store.withLifecycleLease(preview.ledger!, async (snapshot) =>
      withStateLifecycleLock(this.files, workspace, preview.id, async () => {
        const selected = resolveRuntimeState(this.files.root, workspace);
        const current = this.preview('select', workspace, snapshot.digest,
          digestContent(JSON.stringify({ selected, snapshot: snapshot.digest, directory: preview.destination })), preview.destination);
        if (current.id !== preview.id) throw new WorkflowError('stale-revision', 'Source selection changed after review; no replica was created.');
        const stage: SelectionStage = { schemaVersion: 1, workspace, sourceSelection: selected.revision,
          sourceDirectory: selected.directory, directory: preview.destination!, snapshot: snapshot.digest, id: preview.id };
        const journal = `.missionspec/recovery/selection-${preview.id.slice(7)}.json`;
        const target = path.join(stage.directory, 'ledger.sqlite');
        if (exists(target) && !exists(path.join(this.files.root, journal))) throw new WorkflowError('conflict', 'External selection never adopts or overwrites an existing ledger.');
        await this.authorize(preview, approval);
        await this.immutable('recovery', `selection-${preview.id.slice(7)}`, stage);
        await this.authorize(preview, approval);
        if (!exists(target)) value(await materializeRuntimeSnapshot({
          directory: stage.directory, workspaceRoot: this.files.root, mode: 'create', expectedWorkspace: workspace,
        }, snapshot));
        const replica = value(await inspectRuntimeReplica({ directory: stage.directory, workspaceRoot: this.files.root, mode: 'read-only', expectedWorkspace: workspace }));
        if (replica.digest !== snapshot.digest) throw new WorkflowError('conflict', 'Prepared target differs from reviewed state; preserve it and select a new destination.');
        return { state: 'prepared' as const, id: stage.id, activation: 'separate-exact-review-required' as const };
      }))));
  }

  private async selectionStage(id: ContentDigest): Promise<SelectionStage> {
    const raw = record(JSON.parse(readPrivateStateFile(path.join(this.files.root, `.missionspec/recovery/selection-${parseDigest(id).slice(7)}.json`), 16_384)) as unknown,
      'selectionStage', ['schemaVersion', 'workspace', 'sourceSelection', 'sourceDirectory', 'directory', 'snapshot', 'id']);
    if (raw.schemaVersion !== 1 || raw.id !== id || !sameWorkspaceBinding(parseWorkspaceBinding(raw.workspace), await this.workspace())) {
      throw new WorkflowError('scope-exceeded', 'Selection stage has a different workspace or identity.');
    }
    const stage: SelectionStage = { schemaVersion: 1, workspace: parseWorkspaceBinding(raw.workspace),
      sourceSelection: raw.sourceSelection === 'absent' ? 'absent' : parseDigest(raw.sourceSelection),
      sourceDirectory: text(raw.sourceDirectory, 'sourceDirectory', 4096), directory: text(raw.directory, 'directory', 4096),
      snapshot: parseDigest(raw.snapshot), id };
    const selected = { directory: stage.sourceDirectory, workspaceRoot: this.files.root, revision: stage.sourceSelection,
      kind: stage.sourceDirectory === path.join(this.files.root, '.missionspec/state') ? 'default' : 'external' };
    const expected = this.preview('select', stage.workspace, stage.snapshot,
      digestContent(JSON.stringify({ selected, snapshot: stage.snapshot, directory: stage.directory })), stage.directory);
    if (expected.id !== stage.id) throw new WorkflowError('invalid-input', 'Selection stage digest does not match its original reviewed intent.');
    return stage;
  }

  async previewActivation(id: ContentDigest): Promise<FilePlan> {
    const stage = await this.selectionStage(id);
    const selected = resolveRuntimeState(this.files.root, stage.workspace);
    if (selected.revision !== stage.sourceSelection || selected.directory !== stage.sourceDirectory) throw new WorkflowError('stale-revision', 'Source selection changed; prepared target cannot become active.');
    await this.store(false, async (store) => {
      const snapshot = value(await store.snapshot());
      if (snapshot.digest !== stage.snapshot) throw new WorkflowError('stale-revision', 'Source runtime advanced after staging; preserve both stores and prepare a new target.');
      const checked = value(await validateRuntimeSnapshot(snapshot, stage.workspace));
      if (!checked.quiescent || checked.pendingPrunes) throw new WorkflowError('conflict', 'Current quiescence is not established.');
    });
    const replica = value(await inspectRuntimeReplica({ directory: stage.directory, workspaceRoot: this.files.root, expectedWorkspace: stage.workspace, mode: 'read-only' }));
    if (replica.digest !== stage.snapshot) throw new WorkflowError('stale-revision', 'Replica content changed after staging.');
    const location = parseProjectPath(runtimeSelectionPath);
    const journal = parseProjectPath(`.missionspec/recovery/selection-${id.slice(7)}.json`);
    const content = JSON.stringify({ schemaVersion: 1, workspace: stage.workspace, directory: stage.directory, generation: id });
    const publication = writeMutation(location, selected.revision, content, 'configuration');
    const guards = [{ path: location, digest: selected.revision }, { path: journal, digest: digestContent(JSON.stringify(stage)) }];
    const mutations = [publication];
    for (const file of runtimeSelectionCompletionRecords(stage.workspace, publication)) {
      const existing = await this.files.read(file.path);
      if (existing !== null && (file.path !== '.missionspec/recovery/selection-established.json' || existing.digest !== file.digest)) {
        throw new WorkflowError('conflict', 'Existing selection history differs from the reviewed activation; preserve it and inspect recovery.');
      }
      guards.push({ path: file.path, digest: existing?.digest ?? 'absent' });
      if (existing === null) mutations.push(writeMutation(file.path, 'absent', file.content, 'configuration'));
    }
    return makeFilePlan({ workspace: stage.workspace, operation: 'onboard', purpose: 'integration',
      guards, mutations });
  }

  async activate(id: ContentDigest, plan: FilePlan, approval: ApprovalReference) {
    if ((await this.previewActivation(id)).digest !== plan.digest) throw new WorkflowError('stale-revision', 'Selection activation plan changed.');
    const stage = await this.selectionStage(id);
    return this.store(true, async (store) => value(await store.withLifecycleLease(stage.snapshot, async (_snapshot, lease) => {
      const replica = value(await inspectRuntimeReplica({ directory: stage.directory, workspaceRoot: this.files.root, expectedWorkspace: stage.workspace, mode: 'read-only' }));
      if (replica.digest !== stage.snapshot) throw new WorkflowError('stale-revision', 'Replica changed before activation.');
      const result = await this.files.commitRuntimeSelection(plan, approval, lease);
      return { ...result, selection: 'activated' as const, previousStore: 'preserved' as const, runsResumed: 0 };
    })));
  }

  async previewActivationRecovery(id: ContentDigest, transactionId: string): Promise<FilePlan> {
    const stage = await this.selectionStage(id);
    const plan = parseRuntimeSelectionPlan(await this.files.recoveryPlan(transactionId));
    const selected = resolveRuntimeState(this.files.root, stage.workspace);
    if (plan.mutations[0]!.effect.path !== runtimeSelectionPath ||
        !plan.guards.some((guard) => guard.path === `.missionspec/recovery/selection-${id.slice(7)}.json` &&
          guard.digest === digestContent(JSON.stringify(stage)))) throw new WorkflowError('scope-exceeded', 'Recovery transaction does not belong to this exact selection stage.');
    const proposed = plan.mutations[0]!.effect;
    const activated = selected.directory === stage.directory && proposed.kind === 'file-write' && selected.revision === proposed.proposed;
    if (!activated) {
      if ((await this.previewActivation(id)).digest !== plan.digest) throw new WorkflowError('stale-revision', 'Pending activation no longer matches its source state.');
    }
    return plan;
  }

  async recoverActivation(id: ContentDigest, transactionId: string, approval: ApprovalReference) {
    const plan = await this.previewActivationRecovery(id, transactionId);
    const stage = await this.selectionStage(id);
    return this.store(true, async (store) => {
      const snapshot = value(await store.snapshot());
      return value(await store.withLifecycleLease(snapshot.digest, async (_snapshot, lease) => {
        const selected = resolveRuntimeState(this.files.root, stage.workspace);
        const effect = plan.mutations[0]!.effect;
        const published = effect.kind === 'file-write' && selected.directory === stage.directory && selected.revision === effect.proposed;
        if (!published) {
          if (selected.directory !== stage.sourceDirectory || selected.revision !== stage.sourceSelection || snapshot.digest !== stage.snapshot) {
            throw new WorkflowError('stale-revision', 'Source state advanced before activation recovery acquired its lease.');
          }
          const replica = value(await inspectRuntimeReplica({
            directory: stage.directory, workspaceRoot: this.files.root, expectedWorkspace: stage.workspace, mode: 'read-only',
          }));
          if (replica.digest !== stage.snapshot) throw new WorkflowError('stale-revision', 'Prepared replica changed before activation recovery.');
        }
        return this.files.commitRuntimeSelection(plan, approval, lease, transactionId);
      }));
    });
  }

  async migrationPolicy() {
    const state = await this.status();
    return { policyVersion: 1, state: 'current' as const, source: { ledger: state.schemaVersion, backup: 1 },
      target: { ledger: 3, backup: 1 }, applicableMigrations: [],
      supportedTransfers: [
        planRuntimeMigration({ kind: 'sqlite-ledger', version: state.schemaVersion }, { kind: 'logical-backup', version: 1 }),
        planRuntimeMigration({ kind: 'logical-backup', version: 1 }, { kind: 'sqlite-ledger', version: state.schemaVersion }),
      ],
      unsupported: ['unreleased-sqlite-1', 'unreleased-sqlite-2', 'prototype-json-projects'],
      rule: 'explicit-reviewed-version-path-only; preserve-facts-authority-and-original-bytes',
      projectArtifacts: 'outside-runtime-migration-policy',
      writesPerformed: false as const };
  }

  async previewMigration(input: unknown, directory: string): Promise<RuntimeLifecyclePreview> {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    const migration = planRuntimeMigration({ kind: 'logical-backup', version: backup.formatVersion }, { kind: 'sqlite-ledger', version: backup.ledger.schemaVersion });
    parseOptions({ directory, workspaceRoot: this.files.root, expectedWorkspace: backup.workspace, mode: 'create' });
    checkPrivatePath(path.dirname(directory), true, true);
    if (resolveRuntimeState(this.files.root, backup.workspace).directory === directory) {
      throw new WorkflowError('conflict', 'Migration never writes the active runtime location.');
    }
    return this.preview('stage', backup.workspace, null, digestContent(JSON.stringify({ backup: backup.digest, migration: migration.digest })), directory);
  }

  async migrate(input: unknown, preview: RuntimeLifecyclePreview, approval: ApprovalReference) {
    const backup = await validateRuntimeBackup(input, await this.workspace());
    if (preview.destination === null || (await this.previewMigration(backup, preview.destination)).id !== preview.id) {
      throw new WorkflowError('stale-revision', 'Migration source, target or version policy differs from review.');
    }
    await this.authorize(preview, approval);
    return withStateLifecycleLock(this.files, backup.workspace, preview.id, async () => {
      if (resolveRuntimeState(this.files.root, backup.workspace).directory === preview.destination) {
        throw new WorkflowError('stale-revision', 'Migration destination became active after review.');
      }
      const journal = `migration-${preview.id.slice(7)}`;
      const target = path.join(preview.destination!, 'ledger.sqlite');
      if (exists(target) && !exists(path.join(this.files.root, `.missionspec/recovery/${journal}.json`))) {
        throw new WorkflowError('conflict', 'Migration cannot adopt or overwrite an existing destination.');
      }
      await this.authorize(preview, approval);
      await this.immutable('recovery', `snapshot-${backup.digest.slice(7)}`, backup);
      await this.immutable('recovery', journal, { schemaVersion: 1, preview, backup: backup.digest });
      await this.authorize(preview, approval);
      if (!exists(target)) value(await materializeRuntimeSnapshot({
        directory: preview.destination!, workspaceRoot: this.files.root, expectedWorkspace: backup.workspace, mode: 'create',
      }, backup.ledger));
      const replica = value(await inspectRuntimeReplica({
        directory: preview.destination!, workspaceRoot: this.files.root, expectedWorkspace: backup.workspace, mode: 'read-only',
      }));
      if (replica.digest !== backup.ledger.digest) throw new WorkflowError('conflict', 'Converted replica differs from the verified source; no activation is performed.');
      return { state: 'staged' as const, id: preview.id, conversion: 'logical-backup-1-to-sqlite-3' as const,
        ledger: replica.digest, activation: 'not-authorized' as const, rawEvidence: 'retained-in-recovery-package' as const };
    });
  }
}
