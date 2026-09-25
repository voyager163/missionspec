import { constants, lstatSync, type BigIntStats } from 'node:fs';
import { link, lstat, mkdir, open, readdir, realpath, rename, unlink, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { digestApprovalRequest, parseApprovalReference, parseApprovalRequest, type ApprovalPurpose, type ApprovalReference, type ApprovalRequest } from '../../kernel/authority.js';
import { digestEffectScope, parseEffectScope, type FilePurpose } from '../../kernel/effects.js';
import { isReservedSourcePath, parseChangeSlug, parseId, parseNativeHost, parseProjectPath, type ChangeSlug, type EvidenceId, type NativeHost, type ProjectPath, type RunId } from '../../kernel/identifiers.js';
import { parseOperationId, type OperationId } from '../../kernel/registry.js';
import { digestContent, parseDigest, parseRevisionBinding, parseWorkspaceBinding, sameWorkspaceBinding, type ContentDigest, type RevisionBinding, type WorkspaceBinding } from '../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../kernel/validation.js';
import type { FileMutation, FileSnapshot, LocalAuthorityPort } from '../../ports/contracts.js';
import { requireApproval, unavailableAuthority } from '../../application/authority.js';
import { WorkflowError } from '../../application/errors.js';
import { requireRuntimeLifecycleLease, type RuntimeLifecycleLease } from '../persistence/lifecycle-lease.js';
import { acquirePosixWriterMutex } from '../persistence/writer-mutex.js';
import { readPrivateBytes } from '../persistence/private-reader.js';
import { parseTaskDefinition, type TaskDefinition } from '../../engines/planning/contracts.js';
import {
  syncWindowsPrivateDirectory, validateWindowsStatePath, windowsPrivateEntries,
  ensureWindowsPrivateDirectories, inspectWindowsPrivateFile, removeWindowsPrivateFile, syncWindowsPrivateFile,
  windowsPublication, writeWindowsPrivateFile, WindowsDirectoryDurabilityError, WindowsPrivateStateError,
  windowsPrivateStateDiagnostic, currentWindowsProcessInstance, parseWindowsWriterLock,
  type WindowsFileReference, type WindowsFileScope, type WindowsPrivateEntry, type WindowsWriterLease,
} from '../platform/windows-private-state.js';

export interface FileGuard {
  readonly path: ProjectPath;
  readonly digest: ContentDigest | 'absent';
}

export interface FilePlan {
  readonly schemaVersion: 1;
  readonly workspace: WorkspaceBinding;
  readonly guards: readonly FileGuard[];
  readonly mutations: readonly FileMutation[];
  readonly request: ApprovalRequest;
  readonly digest: ContentDigest;
  readonly sourcePatch?: SourcePatchBinding;
}

interface HeldPosixFile {
  readonly filename: string;
  readonly handle: FileHandle;
  readonly identity: BigIntStats;
}

export interface SourcePatchDependencies {
  readonly runId: RunId;
  readonly evidence: readonly EvidenceId[];
}

export interface SourcePatchBinding {
  readonly slug: ChangeSlug;
  readonly task: TaskDefinition;
  readonly proposal: { readonly kind: 'inert-proposal'; readonly host: NativeHost; readonly summary: string; readonly digest: ContentDigest };
  readonly dependencies: SourcePatchDependencies | null;
}

export function runtimeSelectionCompletionRecords(workspace: WorkspaceBinding, selection: FileMutation): readonly FileSnapshot[] {
  if (selection.effect.path !== '.missionspec/runtime-selection.json' || selection.effect.kind !== 'file-write' ||
      selection.effect.purpose !== 'configuration' || !('content' in selection)) {
    throw new ContractError('runtimeSelection', 'expected the exact selector publication');
  }
  const value = record(JSON.parse(selection.content) as unknown, 'runtimeSelection', ['schemaVersion', 'workspace', 'directory', 'generation']);
  if (value.schemaVersion !== 1 || !sameWorkspaceBinding(parseWorkspaceBinding(value.workspace), workspace)) {
    throw new ContractError('runtimeSelection', 'selector must bind this workspace');
  }
  text(value.directory, 'runtimeSelection.directory', 4096);
  const generation = parseDigest(value.generation);
  return [
    {
      path: parseProjectPath(`.missionspec/recovery/selection-generation-${generation.slice(7)}.json`),
      content: JSON.stringify({ schemaVersion: 1, workspace, before: selection.effect.expected, after: selection.effect.proposed, generation }),
    },
    {
      path: parseProjectPath('.missionspec/recovery/selection-established.json'),
      content: JSON.stringify({ schemaVersion: 1, workspace }),
    },
  ].map((file) => ({ ...file, digest: digestContent(file.content) }));
}

function material(plan: Pick<FilePlan, 'workspace' | 'guards' | 'mutations' | 'sourcePatch'>): ContentDigest {
  return digestContent(JSON.stringify({ workspace: plan.workspace, guards: plan.guards, mutations: plan.mutations,
    ...(plan.sourcePatch === undefined ? {} : { sourcePatch: plan.sourcePatch }) }));
}

export function makeFilePlan(input: {
  workspace: WorkspaceBinding; guards: readonly FileGuard[]; mutations: readonly FileMutation[];
  operation: OperationId; purpose: Exclude<ApprovalPurpose, 'execution'>;
  revisions?: RevisionBinding;
  sourcePatch?: SourcePatchBinding;
}): FilePlan {
  const workspace = parseWorkspaceBinding(input.workspace);
  const guards = unique(array(input.guards, 'guards', (value) => {
    const guard = record(value, 'guard', ['path', 'digest']);
    return Object.freeze({ path: parseProjectPath(guard.path), digest: guard.digest === 'absent' ? 'absent' as const : parseDigest(guard.digest) });
  }).map((guard) => JSON.stringify(guard)), 'guards').map((guard): FileGuard => Object.freeze(JSON.parse(guard) as FileGuard))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  unique(guards.map((guard) => guard.path.toLowerCase()), 'guards.paths');
  const mutations = array(input.mutations, 'mutations', (value): FileMutation => {
    const mutation = record(value, 'mutation', ['effect', 'content']);
    const effect = parseEffectScope([mutation.effect])[0]!;
    if (effect.kind !== 'file-write' && effect.kind !== 'file-remove') throw new ContractError('mutation', 'only file effects are supported');
    if (effect.kind === 'file-remove') {
      record(value, 'mutation', ['effect']);
      return Object.freeze({ effect });
    }
    parseProjectPath(`${effect.path}.msn-00000000-0000-0000-0000-000000000000`);
    const content = typeof mutation.content === 'string' ? mutation.content : text(mutation.content, 'content', 1_000_000);
    if (Buffer.byteLength(content) > 1_000_000 || digestContent(content) !== effect.proposed) {
      throw new ContractError('mutation.content', 'content does not match the bounded proposed digest');
    }
    return Object.freeze({ effect, content });
  }, 1);
  const effects = parseEffectScope(mutations.map((mutation) => mutation.effect));
  if (mutations.some((mutation) => mutation.effect.purpose === 'source') && input.purpose !== 'source-apply') {
    throw new ContractError('mutation.purpose', 'local source writes require separate exact source-apply authority');
  }
  let sourcePatch: SourcePatchBinding | undefined;
  if (input.sourcePatch !== undefined) {
    const context = record(input.sourcePatch, 'sourcePatch', ['slug', 'task', 'proposal', 'dependencies']);
    const proposal = record(context.proposal, 'sourcePatch.proposal', ['kind', 'host', 'summary', 'digest']);
    const task = parseTaskDefinition(context.task);
    const dependencies = context.dependencies === null ? null : record(context.dependencies, 'sourcePatch.dependencies', ['runId', 'evidence']);
    sourcePatch = {
      slug: parseChangeSlug(context.slug), task,
      proposal: { kind: 'inert-proposal', host: parseNativeHost(proposal.host), summary: text(proposal.summary, 'proposal.summary', 4096), digest: parseDigest(proposal.digest) },
      dependencies: dependencies === null ? null : {
        runId: parseId('run', dependencies.runId),
        evidence: unique(array(dependencies.evidence, 'dependency.evidence', (id) => parseId('evidence', id), 1), 'dependency.evidence'),
      },
    };
    if (proposal.kind !== 'inert-proposal' || input.operation !== 'implement' || input.purpose !== 'source-apply' ||
        input.revisions === undefined || (task.dependsOn.length > 0) !== (sourcePatch.dependencies !== null) ||
        mutations.some((mutation) => mutation.effect.kind !== 'file-write' || mutation.effect.purpose !== 'source' ||
          !task.writeScope.includes(mutation.effect.path) ||
          isReservedSourcePath(mutation.effect.path))) {
      throw new ContractError('sourcePatch', 'source patches bind one exact task scope and dependency evidence, not execution authority');
    }
    const candidate = { kind: 'inert-proposal', host: sourcePatch.proposal.host, summary: sourcePatch.proposal.summary,
      changes: mutations.map((mutation) => ({ path: mutation.effect.path, expected: mutation.effect.expected,
        content: 'content' in mutation ? mutation.content : null })) };
    if (digestContent(JSON.stringify(candidate)) !== sourcePatch.proposal.digest) throw new ContractError('sourcePatch.proposal', 'derived effects differ from the reviewed inert proposal');
  } else if (input.purpose === 'source-apply') {
    throw new ContractError('sourcePatch', 'source-apply requires the explicit task and inert-proposal binding');
  }
  if (mutations.length > 128 || guards.length > 1024 ||
      Buffer.byteLength(JSON.stringify({ guards, mutations, sourcePatch })) > 6_000_000) {
    throw new WorkflowError('limit-reached', 'A recoverable local transaction is limited to 128 mutations, 1024 observations and 6 MB of payload.');
  }
  unique(mutations.map((mutation) => mutation.effect.path.toLowerCase()), 'mutations.paths');
  const selector = mutations.find((mutation) => mutation.effect.path === '.missionspec/runtime-selection.json');
  const selectionRecords = selector === undefined ? [] : runtimeSelectionCompletionRecords(workspace, selector);
  for (const mutation of mutations) {
    if (!guards.some((guard) => guard.path === mutation.effect.path && guard.digest === mutation.effect.expected)) {
      throw new ContractError('guards', 'every mutation requires an exact prior observation');
    }
    const installationRecord = mutation.effect.path === '.missionspec/installation.json' &&
      input.operation === 'onboard' && input.purpose === 'integration' && mutation.effect.purpose === 'configuration';
    const runtimeSelection = mutation.effect.path === '.missionspec/runtime-selection.json' &&
      input.operation === 'onboard' && input.purpose === 'integration' && mutation.effect.purpose === 'configuration';
    const selectionRecord = selectionRecords.some((file) => file.path === mutation.effect.path &&
      mutation.effect.kind === 'file-write' && mutation.effect.expected === 'absent' && 'content' in mutation && mutation.content === file.content) &&
      input.operation === 'onboard' && input.purpose === 'integration' && mutation.effect.purpose === 'configuration';
    if (mutation.effect.path.startsWith('.missionspec/') && mutation.effect.path !== '.missionspec/workspace.json' &&
        !installationRecord && !runtimeSelection && !selectionRecord) {
      throw new ContractError('mutation.path', 'runtime journals and ledgers are not editable artifact targets');
    }
  }
  const subject = material({ workspace, guards, mutations, ...(sourcePatch === undefined ? {} : { sourcePatch }) });
  const binding = input.revisions === undefined
    ? { kind: 'project' as const, workspace, revision: subject, effects: digestEffectScope(effects) }
    : { kind: 'review' as const, revisions: parseRevisionBinding(input.revisions), subject, effects: digestEffectScope(effects) };
  if (binding.kind === 'review' && !sameWorkspaceBinding(binding.revisions.workspace, workspace)) {
    throw new ContractError('workspace', 'review and file scopes differ');
  }
  const request = parseApprovalRequest({
    contractVersion: 1, state: 'untrusted-request', operation: input.operation, purpose: input.purpose, binding, effects,
  });
  return Object.freeze({
    schemaVersion: 1, workspace, guards: Object.freeze(guards), mutations: Object.freeze(mutations), request,
    digest: digestApprovalRequest(request),
    ...(sourcePatch === undefined ? {} : { sourcePatch }),
  });
}

export function parseFilePlan(value: unknown): FilePlan {
  const input = record(value, 'filePlan', ['schemaVersion', 'workspace', 'guards', 'mutations', 'request', 'digest', 'sourcePatch']);
  if (input.schemaVersion !== 1) throw new ContractError('filePlan', 'unsupported version');
  const request = parseApprovalRequest(input.request);
  const operation = parseOperationId(request.operation);
  if (request.purpose === 'execution' || (operation === 'implement' && request.purpose !== 'source-apply') || request.binding.kind === 'change') {
    throw new ContractError('filePlan', 'not a local file transaction request');
  }
  const plan = makeFilePlan({
    workspace: parseWorkspaceBinding(input.workspace),
    guards: input.guards as readonly FileGuard[], mutations: input.mutations as readonly FileMutation[],
    operation, purpose: request.purpose,
    ...(request.binding.kind === 'review' ? { revisions: request.binding.revisions } : {}),
    ...(input.sourcePatch === undefined ? {} : { sourcePatch: input.sourcePatch as SourcePatchBinding }),
  });
  if (plan.digest !== parseDigest(input.digest) || plan.digest !== digestApprovalRequest(request)) {
    throw new ContractError('filePlan', 'preview was changed after review');
  }
  return plan;
}

export function writeMutation(file: ProjectPath, expected: ContentDigest | 'absent', content: string, purpose: FilePurpose): FileMutation {
  return { effect: { kind: 'file-write', path: file, expected, proposed: digestContent(content), purpose }, content };
}

export function parseRuntimeSelectionPlan(value: unknown): FilePlan {
  const plan = parseFilePlan(value);
  const records = runtimeSelectionCompletionRecords(plan.workspace, plan.mutations[0]!);
  if (plan.mutations.length < 2 || plan.mutations.length > 3 || records.some((file, index) => {
    const mutation = plan.mutations[index + 1];
    return mutation === undefined
      ? index !== 1 || !plan.guards.some((guard) => guard.path === file.path && guard.digest === file.digest)
      : mutation.effect.kind !== 'file-write' || mutation.effect.path !== file.path ||
        mutation.effect.expected !== 'absent' || !('content' in mutation) || mutation.content !== file.content;
  })) {
    throw new ContractError('runtimeSelection', 'activation must journal its exact generation receipt and retained marker with the selector');
  }
  return plan;
}

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

export function windowsIoDetail(error: unknown): string {
  if (error instanceof WindowsPrivateStateError) return `Windows private-state diagnostic: ${windowsPrivateStateDiagnostic(error)}.`;
  if (error instanceof WindowsDirectoryDurabilityError) return 'Windows directory durability is unconfirmed.';
  const code: unknown = typeof error === 'object' && error !== null ? Reflect.get(error, 'code') : undefined;
  return typeof code === 'string' && ['EACCES', 'EPERM', 'EBADF', 'EIO', 'EEXIST', 'ENOENT', 'EBUSY', 'ENOTDIR', 'ENOSPC'].includes(code)
    ? `Filesystem code: ${code}.` : 'Filesystem outcome is unconfirmed.';
}

export async function observeWorkspaceRoot(directory: string): Promise<{ root: string; rootDigest: ContentDigest }> {
  const root = await realpath(directory);
  const info = await lstat(root, { bigint: true });
  if (!info.isDirectory()) throw new WorkflowError('invalid-input', 'Select an existing local directory.');
  return { root, rootDigest: digestContent(JSON.stringify({ root, device: String(info.dev), inode: String(info.ino) })) };
}

export class LocalWorkspace {
  private windowsLease: WindowsWriterLease | undefined;
  private runtimeSelectionLease: RuntimeLifecycleLease | undefined;
  private constructor(
    readonly root: string, readonly rootDigest: ContentDigest,
    private readonly authority: LocalAuthorityPort, private readonly now: () => string,
    private readonly beforeEffects: (plan: FilePlan) => Promise<void>,
  ) {}

  static async open(directory: string, options: {
    authority?: LocalAuthorityPort; now?: () => string; beforeEffects?: (plan: FilePlan) => Promise<void>;
  } = {}): Promise<LocalWorkspace> {
    const observed = await observeWorkspaceRoot(directory);
    return new LocalWorkspace(observed.root, observed.rootDigest, options.authority ?? unavailableAuthority,
      options.now ?? (() => new Date().toISOString()), options.beforeEffects ?? (async () => {}));
  }

  private async target(relative: ProjectPath, createParents = false, writable = false): Promise<string> {
    parseProjectPath(relative);
    if ((await observeWorkspaceRoot(this.root)).rootDigest !== this.rootDigest) {
      throw new WorkflowError('scope-exceeded', 'The observed workspace root changed.');
    }
    let current = this.root;
    if (process.platform === 'win32' && createParents) {
      const parent = path.dirname(path.join(this.root, relative));
      if (parent !== this.root) {
        try { ensureWindowsPrivateDirectories(this.windowsScope(), parent); } catch (error) {
          throw new WorkflowError('effect-outcome-unknown', `Private parent creation was not confirmed. ${windowsIoDetail(error)}`);
        }
      }
    }
    const checks: WindowsPrivateEntry[] = [];
    if (process.platform === 'win32' && writable) checks.push({ path: this.root, directory: true, writable: true });
    const parts = relative.split('/');
    for (let index = 0; index < parts.length; index += 1) {
      current = path.join(current, parts[index]!);
      if (process.platform === 'win32' && writable) validateWindowsStatePath(current);
      const parent = index < parts.length - 1;
      if (parent && createParents && process.platform !== 'win32') {
        try { await mkdir(current, { mode: 0o700 }); } catch (error) {
          if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST')) throw error;
        }
      }
      try {
        const info = await lstat(current);
        if (info.isSymbolicLink() || (parent && !info.isDirectory()) || (!parent && !info.isFile() && !info.isDirectory())) {
          throw new WorkflowError('scope-exceeded', 'Local paths must not traverse links or special files.');
        }
        if (info.isFile() && info.nlink !== 1) throw new WorkflowError('scope-exceeded', 'Hard-linked files are not supported.');
        if (relative.startsWith('.missionspec/') || (process.platform === 'win32' && writable)) {
          if (process.platform === 'win32') {
            checks.push({ path: current, directory: info.isDirectory(), writable,
              ...(writable && info.isFile() ? { ordinaryFile: true } : {}) });
          } else if (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) {
            throw new WorkflowError('scope-exceeded', 'Runtime state requires current-user ownership and owner-only permissions.');
          }
        }
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
    for (let index = 0; index < checks.length; index += 8) windowsPrivateEntries(checks.slice(index, index + 8));
    return current;
  }

  private windowsScope(withLease = true): WindowsFileScope {
    const observed = lstatSync(this.root, { bigint: true });
    if (!observed.isDirectory() || observed.isSymbolicLink() ||
        digestContent(JSON.stringify({ root: this.root, device: String(observed.dev), inode: String(observed.ino) })) !== this.rootDigest) {
      throw new WorkflowError('scope-exceeded', 'The workspace root identity changed before native admission.');
    }
    return { root: this.root, dev: observed.dev, ino: observed.ino,
      ...(withLease && this.windowsLease !== undefined ? { lease: this.windowsLease } : {}) };
  }

  private async writeRoot(): Promise<void> {
    if (process.platform === 'win32') {
      windowsPrivateEntries([{ path: this.root, directory: true, writable: true }]);
      return;
    }
    if (!['darwin', 'linux'].includes(process.platform)) throw new WorkflowError('capability-unavailable', 'This local filesystem is not qualified for private effects.');
    const info = await lstat(this.root);
    if (info.uid !== process.getuid?.() || (info.mode & 0o022) !== 0) {
      throw new WorkflowError('scope-exceeded', 'File effects require a current-user-owned root without group/world write access.');
    }
  }

  async read(input: ProjectPath): Promise<FileSnapshot | null> {
    const relative = parseProjectPath(input);
    if (relative === '.missionspec/writer-mutex.lock' || relative === '.missionspec/writer-mutex.sqlite' ||
        relative === '.missionspec/writer-mutex.bootstrap') {
      throw new WorkflowError('scope-exceeded', 'The stable writer mutex is not a workspace text input.');
    }
    let handle;
    try {
      const target = await this.target(relative);
      if (relative.startsWith('.missionspec/')) {
        const bytes = readPrivateBytes(target, 8_000_000);
        return { path: relative, content: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes),
          digest: digestContent(bytes) };
      }
      handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      const before = await handle.stat({ bigint: true });
      if (!before.isFile() || before.nlink !== 1n || before.size > 8_000_000n) {
        throw new WorkflowError('scope-exceeded', 'Only bounded regular single-link files may be read.');
      }
      const bytes = Buffer.alloc(Number(before.size) + 1);
      let length = 0;
      while (length < bytes.length) {
        const result = await handle.read(bytes, length, bytes.length - length, null);
        if (result.bytesRead === 0) break;
        length += result.bytesRead;
      }
      const after = await handle.stat({ bigint: true });
      const current = await lstat(await this.target(relative), { bigint: true });
      if (before.size !== BigInt(length) || before.ino !== current.ino || before.dev !== current.dev ||
          before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
          after.mtimeNs !== current.mtimeNs || after.ctimeNs !== current.ctimeNs) {
        throw new WorkflowError('stale-revision', 'A file changed while it was being observed.');
      }
      const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, length));
      return { path: relative, content, digest: digestContent(bytes.subarray(0, length)) };
    } catch (error) {
      if (missing(error)) return null;
      throw error;
    } finally { await handle?.close(); }
  }

  async list(input: ProjectPath): Promise<readonly ProjectPath[]> {
    const relative = parseProjectPath(input);
    try {
      const entries = await readdir(await this.target(relative), { withFileTypes: true });
      if (entries.length > 1024 || entries.some((entry) => entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile()))) {
        throw new WorkflowError('scope-exceeded', 'Directory contains unsupported entries or exceeds the local listing limit.');
      }
      return entries.map((entry) => parseProjectPath(`${relative}/${entry.name}`)).sort();
    } catch (error) {
      if (missing(error)) return [];
      throw error;
    }
  }

  async directories(input: ProjectPath): Promise<readonly ProjectPath[]> {
    const paths = await this.list(input);
    const directories: ProjectPath[] = [];
    for (const relative of paths) if ((await lstat(await this.target(relative))).isDirectory()) directories.push(relative);
    return directories;
  }

  async identity(): Promise<WorkspaceBinding | null> {
    const file = await this.read(parseProjectPath('.missionspec/workspace.json'));
    if (file === null) return null;
    const workspace = parseWorkspaceBinding(JSON.parse(file.content) as unknown);
    if (workspace.rootDigest !== this.rootDigest) throw new WorkflowError('scope-exceeded', 'Workspace identity belongs to another observed root. No automatic rebinding is permitted.');
    return workspace;
  }

  private async checkScope(plan: FilePlan): Promise<void> {
    const current = await this.identity();
    if (plan.workspace.rootDigest !== this.rootDigest || (current !== null && !sameWorkspaceBinding(current, plan.workspace))) {
      throw new WorkflowError('scope-exceeded', 'Preview belongs to a different local workspace.');
    }
    if (current === null && !plan.mutations.some((mutation) =>
      mutation.effect.kind === 'file-write' && mutation.effect.path === '.missionspec/workspace.json' &&
      mutation.effect.expected === 'absent' && 'content' in mutation && sameWorkspaceBinding(parseWorkspaceBinding(JSON.parse(mutation.content) as unknown), plan.workspace))) {
      throw new WorkflowError('authority-required', 'Explicit workspace setup must precede mutations.');
    }
    for (const mutation of plan.mutations) {
      if (mutation.effect.path === '.missionspec/workspace.json' &&
          (mutation.effect.kind !== 'file-write' || mutation.effect.expected !== 'absent' ||
          !('content' in mutation) || !sameWorkspaceBinding(parseWorkspaceBinding(JSON.parse(mutation.content) as unknown), plan.workspace))) {
        throw new WorkflowError('scope-exceeded', 'Workspace identity cannot be replaced by a file transaction.');
      }
    }
  }

  private async compare(plan: FilePlan, recovery: boolean, transactionId?: string): Promise<void> {
    for (const guard of plan.guards) {
      const actual = (await this.read(guard.path))?.digest ?? 'absent';
      const mutation = plan.mutations.find((entry) => entry.effect.path === guard.path);
      const proposed = mutation?.effect.kind === 'file-write' ? mutation.effect.proposed : mutation ? 'absent' : null;
      if (actual !== guard.digest && !(recovery && actual === proposed)) {
        if (process.platform === 'win32' && recovery && transactionId !== undefined && actual === 'absent' &&
            mutation?.effect.kind === 'file-write' && mutation.effect.expected !== 'absent') {
          const state = windowsPublication(this.windowsScope(), {
            relative: mutation.effect.path, transactionId, index: plan.mutations.indexOf(mutation),
            plan: plan.digest, expected: mutation.effect.expected, proposed: mutation.effect.proposed,
          }, true);
          if (state === 'preimage-retained') continue;
        }
        throw new WorkflowError('stale-revision', 'A reviewed input or output changed; preserve edits and preview again.');
      }
    }
  }

  private async syncDirectory(file: string): Promise<void> {
    if (process.platform === 'win32') {
      try {
        const directory = path.dirname(file);
        syncWindowsPrivateDirectory(directory, await lstat(directory, { bigint: true }));
      } catch (error) {
        throw new WorkflowError('effect-outcome-unknown', `The directory effect was not durably confirmed; preserve its journal and explicitly reconcile. ${windowsIoDetail(error)}`);
      }
      return;
    }
    const directory = await open(path.dirname(file), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  }

  private async unchangedPosixFile(file: HeldPosixFile): Promise<void> {
    const held = await file.handle.stat({ bigint: true });
    const current = await lstat(file.filename, { bigint: true });
    if ([held, current].some((stat) => !stat.isFile() || stat.dev !== file.identity.dev || stat.ino !== file.identity.ino ||
        stat.uid !== file.identity.uid || stat.gid !== file.identity.gid || stat.mode !== file.identity.mode ||
        stat.nlink !== 1n || stat.size !== file.identity.size ||
        stat.mtimeNs !== file.identity.mtimeNs || stat.ctimeNs !== file.identity.ctimeNs)) {
      throw new WorkflowError('stale-revision', 'A retained file changed identity, bytes or security; preserve it for review.');
    }
  }

  private async verifiedPosixFile(relative: ProjectPath, content: string, mode: number): Promise<HeldPosixFile> {
    const filename = await this.target(relative);
    const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const identity = await handle.stat({ bigint: true });
      const size = Buffer.byteLength(content);
      if (!identity.isFile() || identity.nlink !== 1n || identity.uid !== BigInt(process.getuid!()) ||
          (identity.mode & 0o7777n) !== BigInt(mode) || identity.size !== BigInt(size)) {
        throw new WorkflowError('stale-revision', 'Retained file size or security differs from the reviewed publication; it is preserved.');
      }
      const bytes = Buffer.alloc(size + 1);
      let length = 0;
      while (length < bytes.length) {
        const read = await handle.read(bytes, length, bytes.length - length, length);
        if (read.bytesRead === 0) break;
        length += read.bytesRead;
      }
      if (length !== size || digestContent(bytes.subarray(0, length)) !== digestContent(content)) {
        throw new WorkflowError('stale-revision', 'Retained file content differs from the exact reviewed bytes; it is preserved.');
      }
      const file = { filename, handle, identity };
      await this.unchangedPosixFile(file);
      await handle.sync();
      await this.unchangedPosixFile(file);
      return file;
    } catch (error) { await handle.close(); throw error; }
  }

  private async exclusive(relative: ProjectPath, content: string, mode = 0o600, securityFrom?: string): Promise<WindowsFileReference | undefined> {
    if (process.platform === 'win32') {
      await this.writeRoot();
      const target = await this.target(relative, true, true);
      try { await lstat(target); throw new WorkflowError('conflict', 'Exclusive private creation found an existing path.'); }
      catch (error) { if (!missing(error)) throw error; }
      try {
        return writeWindowsPrivateFile(this.windowsScope(), target, content, securityFrom);
      } catch (error) {
        throw new WorkflowError('effect-outcome-unknown', `The private file write or flush was not confirmed; preserve the existing record for reconciliation. ${windowsIoDetail(error)}`);
      }
    }
    if (!['darwin', 'linux'].includes(process.platform)) throw new WorkflowError('capability-unavailable', 'Private local effects are unavailable on this platform.');
    const target = await this.target(relative, true);
    const handle = await open(target, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try {
      await handle.writeFile(content, 'utf8');
      if (mode !== 0o600) await handle.chmod(mode);
      await handle.sync();
    } finally { await handle.close(); }
    await this.syncDirectory(target);
  }

  /** Trusted adapter composition only; never expose as an arbitrary client write tool. */
  async recordRuntime(area: 'approvals' | 'checks' | 'evidence' | 'audit' | 'backups' | 'recovery', name: string, value: unknown): Promise<FileSnapshot> {
    if (!['approvals', 'checks', 'evidence', 'audit', 'backups', 'recovery'].includes(area)) throw new ContractError('record.area', 'unsupported runtime record area');
    if (!/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/u.test(name)) throw new ContractError('record.name', 'invalid immutable record name');
    await this.writeRoot();
    const content = JSON.stringify(value);
    if (Buffer.byteLength(content) > 6_000_000) throw new WorkflowError('limit-reached', 'Runtime record exceeds its retained payload limit.');
    const target = parseProjectPath(`.missionspec/${area}/${name}.json`);
    await this.exclusive(target, content);
    try {
      const result = await this.read(target);
      if (result?.digest !== digestContent(content)) throw new WorkflowError('persistence-failed', 'Immutable runtime record could not be verified.');
      return result;
    } catch (error) {
      if (process.platform === 'win32') throw new WorkflowError('effect-outcome-unknown', `The written runtime record could not be verified. ${windowsIoDetail(error)}`);
      throw error;
    }
  }

  async withRuntimeLock<T>(operation: () => Promise<T>): Promise<T> {
    await this.writeRoot();
    if (process.platform !== 'win32' && await this.read(parseProjectPath('.missionspec/transaction.lock')) !== null) {
      throw new WorkflowError('conflict', 'Existing workspace writer metadata blocks runtime effects, including mutex bootstrap.');
    }
    const releaseMutex = acquirePosixWriterMutex(this.root, this.rootDigest);
    try { return await this.withRuntimeOwner(operation); } finally { releaseMutex(); }
  }

  private async withRuntimeOwner<T>(operation: () => Promise<T>): Promise<T> {
    const lock = parseProjectPath('.missionspec/transaction.lock');
    const writer = process.platform === 'win32' ? currentWindowsProcessInstance() : undefined;
    const content = JSON.stringify({ kind: 'runtime', pid: process.pid,
      ...(writer === undefined ? {} : { schemaVersion: 2, nonce: randomUUID(), process: writer }) });
    const identity = await this.exclusive(lock, content);
    if (identity !== undefined) this.windowsLease = {
      path: path.join(this.root, lock), dev: BigInt(identity.device), ino: BigInt(identity.inode), digest: identity.digest,
      ...(writer === undefined ? {} : { process: writer }),
    };
    try {
      if ((await this.pending()).length > 0) throw new WorkflowError('conflict', 'Pending file recovery blocks runtime effects.');
      return await operation();
    } finally {
      this.windowsLease = undefined;
      if (identity !== undefined) {
        try {
          removeWindowsPrivateFile(this.windowsScope(false), path.join(this.root, lock), digestContent(content), identity);
        } catch {
          throw new WorkflowError('effect-outcome-unknown', 'Runtime writer-lock release was not confirmed; preserve the lock for explicit reconciliation.');
        }
      } else { const target = await this.target(lock); await unlink(target); await this.syncDirectory(target); }
    }
  }

  async pending(): Promise<readonly string[]> {
    const entries = await this.list(parseProjectPath('.missionspec/transactions'));
    const workspace = await this.identity();
    const pending: string[] = [];
    for (const entry of entries.filter((entry) => /\/[a-f0-9-]{36}\.json$/u.test(entry))) {
      const id = path.posix.basename(entry, '.json');
      const completed = await this.read(parseProjectPath(entry.replace(/\.json$/u, '.done.json')));
      if (completed === null) { pending.push(id); continue; }
      const receipt = record(JSON.parse(completed.content) as unknown, 'receipt', ['schemaVersion', 'transactionId', 'plan', 'approval', 'state']);
      const journal = await this.read(entry);
      if (journal === null) throw new WorkflowError('persistence-failed', 'A completion receipt has no prepared journal.');
      const prepared = record(JSON.parse(journal.content) as unknown, 'journal', ['schemaVersion', 'plan', 'approval']);
      const plan = parseFilePlan(prepared.plan);
      parseApprovalReference(receipt.approval);
      if (receipt.schemaVersion !== 1 || prepared.schemaVersion !== 1 || receipt.state !== 'committed' ||
          receipt.transactionId !== id || receipt.plan !== plan.digest || plan.workspace.rootDigest !== this.rootDigest ||
          (workspace !== null && !sameWorkspaceBinding(workspace, plan.workspace))) {
        throw new WorkflowError('persistence-failed', 'Transaction journal/receipt integrity is invalid; no automatic repair is attempted.');
      }
    }
    return pending;
  }

  async committedFilePlans(): Promise<readonly FilePlan[]> {
    if ((await this.pending()).length > 0) throw new WorkflowError('conflict', 'Pending file outcomes cannot establish source-evolution provenance.');
    const entries = await this.list(parseProjectPath('.missionspec/transactions'));
    const plans: FilePlan[] = [];
    for (const entry of entries.filter((entry) => /\/[a-f0-9-]{36}\.done\.json$/u.test(entry))) {
      const journal = await this.read(parseProjectPath(entry.replace(/\.done\.json$/u, '.json')));
      if (journal === null) throw new WorkflowError('persistence-failed', 'A committed file receipt has no retained plan.');
      const prepared = record(JSON.parse(journal.content) as unknown, 'journal', ['schemaVersion', 'plan', 'approval']);
      if (prepared.schemaVersion !== 1) throw new WorkflowError('unsupported-version', 'Unknown file provenance version.');
      plans.push(parseFilePlan(prepared.plan));
    }
    return plans;
  }

  async commit(value: FilePlan, approval: ApprovalReference): Promise<{ transactionId: string; state: 'committed' }> {
    return this.commitPlan(value, approval);
  }

  /** Trusted lifecycle composition only; caller holds the source ledger's exclusive lifecycle lease. */
  async commitRuntimeSelection(plan: FilePlan, approval: ApprovalReference, lease: RuntimeLifecycleLease, recoveryId?: string): Promise<{ transactionId: string; state: 'committed' }> {
    requireRuntimeLifecycleLease(lease, plan.workspace);
    if (this.runtimeSelectionLease !== undefined) {
      throw new WorkflowError('conflict', 'Only one exact runtime selection can be published under a lifecycle lease.');
    }
    const selected = parseRuntimeSelectionPlan(plan);
    this.runtimeSelectionLease = lease;
    try { return await this.commitPlan(selected, approval, recoveryId); }
    finally { this.runtimeSelectionLease = undefined; }
  }

  private async commitPlan(value: FilePlan, approval: ApprovalReference, recoveryId?: string): Promise<{ transactionId: string; state: 'committed' }> {
    if (value.mutations.some((entry) => entry.effect.path === '.missionspec/runtime-selection.json') && this.runtimeSelectionLease === undefined) {
      throw new WorkflowError('conflict', 'Runtime selection requires state activate/recover and an exclusive current-ledger lease; generic file recovery cannot activate it.');
    }
    const plan = parseFilePlan(value);
    await this.writeRoot();
    if (process.platform === 'win32') {
      for (const mutation of plan.mutations) {
        await this.target(mutation.effect.path, false, true);
        if (mutation.effect.kind === 'file-write') validateWindowsStatePath(path.join(this.root, `${mutation.effect.path}.msn-00000000-0000-0000-0000-000000000000.before`));
      }
    }
    await this.checkScope(plan);
    const issued = await requireApproval(this.authority, approval, plan.request, this.now());
    const pending = await this.pending();
    if (pending.some((id) => id !== recoveryId)) throw new WorkflowError('conflict', 'An unfinished file transaction requires explicit recovery first.');
    await this.compare(plan, recoveryId !== undefined, recoveryId);
    const id = recoveryId ?? randomUUID();
    const lock = parseProjectPath('.missionspec/transaction.lock');
    const writer = process.platform === 'win32' ? currentWindowsProcessInstance() : undefined;
    const lockContent = JSON.stringify({ transactionId: id, pid: process.pid,
      ...(writer === undefined ? {} : { schemaVersion: 2, nonce: randomUUID(), process: writer }) });
    let locked = false;
    let prepared = false;
    let lockIdentity: WindowsFileReference | undefined;
    let releaseMutex: (() => void) | undefined;
    try {
      if (process.platform !== 'win32') {
        if (recoveryId !== undefined && this.runtimeSelectionLease) await this.reclaimSelectionTransactionLock(lock, id, false);
        else if (await this.read(lock) !== null) throw new WorkflowError('conflict', 'Existing workspace writer metadata blocks a new transaction.');
      }
      releaseMutex = acquirePosixWriterMutex(this.root, this.rootDigest);
      if (recoveryId !== undefined) {
        if (process.platform === 'win32') await this.reclaimWindowsTransactionLock(lock, id);
        else if (this.runtimeSelectionLease) await this.reclaimSelectionTransactionLock(lock, id);
      }
      lockIdentity = await this.exclusive(lock, lockContent);
      locked = true;
      if (lockIdentity !== undefined) this.windowsLease = {
        path: path.join(this.root, lock), dev: BigInt(lockIdentity.device), ino: BigInt(lockIdentity.inode),
        digest: lockIdentity.digest, ...(writer === undefined ? {} : { process: writer }),
      };
      if ((await this.pending()).some((pending) => pending !== recoveryId)) {
        throw new WorkflowError('conflict', 'A pending transaction was observed after acquiring the local writer lock.');
      }
      await this.beforeEffects(plan);
      if (this.runtimeSelectionLease !== undefined) requireRuntimeLifecycleLease(this.runtimeSelectionLease, plan.workspace);
      if (recoveryId === undefined) {
        await this.exclusive(parseProjectPath(`.missionspec/transactions/${id}.json`), JSON.stringify({ schemaVersion: 1, plan, approval: issued }));
      } else if (process.platform === 'win32') {
        prepared = true;
        const relative = parseProjectPath(`.missionspec/transactions/${id}.json`);
        const journal = await this.read(relative);
        if (journal === null) throw new WorkflowError('effect-outcome-unknown', 'The retained journal disappeared.');
        syncWindowsPrivateFile(this.windowsScope(), path.join(this.root, relative), journal.digest);
      }
      prepared = true;
      await this.checkScope(plan);
      await this.compare(plan, recoveryId !== undefined, recoveryId);
      for (const mutation of plan.mutations) {
        await requireApproval(this.authority, approval, plan.request, this.now());
        await this.compare(plan, true, id);
        if (this.runtimeSelectionLease !== undefined) requireRuntimeLifecycleLease(this.runtimeSelectionLease, plan.workspace);
        const actual = (await this.read(mutation.effect.path))?.digest ?? 'absent';
        const proposed = mutation.effect.kind === 'file-write' ? mutation.effect.proposed : 'absent';
        if (process.platform === 'win32' && mutation.effect.kind === 'file-write' && 'content' in mutation) {
          const publication = {
            relative: mutation.effect.path, transactionId: id, index: plan.mutations.indexOf(mutation),
            plan: plan.digest, expected: mutation.effect.expected, proposed: mutation.effect.proposed,
          };
          const state = windowsPublication(this.windowsScope(), publication, true);
          if (state === 'absent' && recoveryId !== undefined && actual === proposed) {
            await this.syncDirectory(path.join(this.root, mutation.effect.path));
            continue;
          }
          let stageIdentity: { dev: bigint; ino: bigint } | undefined;
          if (state === 'absent') {
            if (actual !== mutation.effect.expected) throw new WorkflowError('stale-revision', 'An output changed before publication.');
            const target = await this.target(mutation.effect.path, true, true);
            const stage = parseProjectPath(`${mutation.effect.path}.msn-${id}`);
            let observed;
            try { observed = lstatSync(path.join(this.root, stage), { bigint: true }); } catch (error) { if (!missing(error)) throw error; }
            const retained = recoveryId === undefined ? null : await this.read(stage);
            if (retained !== null) {
              if (observed === undefined || retained.digest !== mutation.effect.proposed) throw new WorkflowError('stale-revision', 'The retained stage changed; it is preserved.');
              stageIdentity = { dev: observed.dev, ino: observed.ino };
            } else {
              if (observed !== undefined) throw new WorkflowError('conflict', 'An unadmitted stage already exists; it is preserved.');
              const created = await this.exclusive(stage, mutation.content, 0o600, actual === 'absent' ? undefined : target);
              if (created === undefined) throw new WorkflowError('effect-outcome-unknown', 'Native stage creation did not return an identity.');
              stageIdentity = { dev: BigInt(created.device), ino: BigInt(created.inode) };
            }
          }
          windowsPublication(this.windowsScope(), { ...publication, ...(stageIdentity === undefined ? {} : { stageIdentity }) });
          continue;
        }
        if (recoveryId !== undefined && actual === proposed) {
          if (mutation.effect.kind === 'file-write' && 'content' in mutation) {
            const mode = (await lstat(await this.target(mutation.effect.path))).mode & 0o777;
            const file = await this.verifiedPosixFile(mutation.effect.path, mutation.content, mode);
            try { await this.syncDirectory(file.filename); await this.unchangedPosixFile(file); }
            finally { await file.handle.close(); }
          } else await this.syncDirectory(path.join(this.root, mutation.effect.path));
          continue;
        }
        if (actual !== mutation.effect.expected) throw new WorkflowError('stale-revision', 'An output changed before its write.');
        const target = await this.target(mutation.effect.path, true, process.platform === 'win32');
        const existing = actual === 'absent' ? null : await lstat(target);
        if (process.platform !== 'win32' && existing !== null && (existing.uid !== process.getuid?.() || (existing.mode & 0o7000) !== 0)) {
          throw new WorkflowError('scope-exceeded', 'Replacement/removal requires an ordinary current-user-owned file.');
        }
        if (mutation.effect.kind === 'file-remove') {
          if (process.platform === 'win32') {
            removeWindowsPrivateFile(this.windowsScope(), target, mutation.effect.expected);
          } else await unlink(target);
        }
        else if ('content' in mutation) {
          const stage = parseProjectPath(`${mutation.effect.path}.msn-${id}`);
          const mode = existing === null ? 0o600 : existing.mode & 0o777;
          let retained = false;
          if (recoveryId !== undefined) {
            try { await lstat(await this.target(stage)); retained = true; }
            catch (error) { if (!missing(error)) throw error; }
          }
          if (!retained) await this.exclusive(stage, mutation.content, mode);
          const file = await this.verifiedPosixFile(stage, mutation.content, mode);
          try {
            if (((await this.read(mutation.effect.path))?.digest ?? 'absent') !== mutation.effect.expected) {
              throw new WorkflowError('stale-revision', 'An output changed before replacement.');
            }
            await this.target(stage);
            await this.unchangedPosixFile(file);
            if (mutation.effect.expected === 'absent') {
              await link(file.filename, target);
              const linked = await lstat(file.filename, { bigint: true });
              if (linked.dev !== file.identity.dev || linked.ino !== file.identity.ino) {
                throw new WorkflowError('effect-outcome-unknown', 'Publication stage was replaced; no replacement entry was removed.');
              }
              await unlink(file.filename);
            } else await rename(file.filename, target);
          } finally { await file.handle.close(); }
        }
        await this.syncDirectory(target);
      }
      for (const mutation of plan.mutations) {
        if (process.platform === 'win32') await this.target(mutation.effect.path, false, true);
        const expected = mutation.effect.kind === 'file-write' ? mutation.effect.proposed : 'absent';
        if (((await this.read(mutation.effect.path))?.digest ?? 'absent') !== expected) {
          throw new WorkflowError('stale-revision', 'An output changed before the transaction could record completion.');
        }
      }
      await this.exclusive(parseProjectPath(`.missionspec/transactions/${id}.done.json`), JSON.stringify({
        schemaVersion: 1, transactionId: id, plan: plan.digest, approval: issued.reference, state: 'committed',
      }));
      return { transactionId: id, state: 'committed' };
    } catch (error) {
      if (process.platform === 'win32' && error instanceof WorkflowError && error.code === 'effect-outcome-unknown') throw error;
      if (prepared) throw new WorkflowError('effect-outcome-unknown', 'The prepared file transaction did not finish. Inspect pending transactions and recover without overwriting changed files.' +
        (process.platform === 'win32' ? ` ${windowsIoDetail(error)}` : ''));
      if (!locked) {
        if (error instanceof WorkflowError) throw error;
        throw new WorkflowError('conflict', 'Local transaction lock or audit storage is unavailable. Do not remove a lock without establishing writer quiescence.' +
          (process.platform === 'win32' ? ` ${windowsIoDetail(error)}` : ''));
      }
      throw error;
    } finally {
      try {
        if (locked) {
          this.windowsLease = undefined;
          if (process.platform === 'win32') {
            try {
              if (lockIdentity === undefined) throw new Error('Writer lock identity unavailable');
              removeWindowsPrivateFile(this.windowsScope(false), path.join(this.root, lock),
                digestContent(lockContent), lockIdentity);
            } catch {
              throw new WorkflowError('effect-outcome-unknown', 'Writer-lock release was not confirmed; do not infer transaction completion or steal a replacement lock.');
            }
          } else { const target = await this.target(lock); await unlink(target); await this.syncDirectory(target); }
        }
      } finally { releaseMutex?.(); }
    }
  }

  private async reclaimWindowsTransactionLock(lock: ProjectPath, id: string): Promise<void> {
    const filename = await this.target(lock, false, true);
    const original = await this.read(lock);
    if (original === null) return;
    try {
      const owner = parseWindowsWriterLock(JSON.parse(original.content) as unknown);
      if (owner.kind !== 'transaction' || owner.id !== id) throw new Error('Writer lock scope differs');
      const reference = inspectWindowsPrivateFile(this.windowsScope(false), filename);
      if (reference.digest !== original.digest) throw new Error('Writer lock changed');
      removeWindowsPrivateFile(this.windowsScope(false), filename, original.digest, reference, owner.process ?? owner.pid);
    } catch (error) {
      throw new WorkflowError('conflict', `The recorded writer may still exist; its lock is preserved. ${windowsIoDetail(error)}`);
    }
  }

  private async reclaimSelectionTransactionLock(lock: ProjectPath, id: string, reclaim = true): Promise<void> {
    const filename = await this.target(lock);
    const original = await this.read(lock);
    if (original === null) return;
    const before = await lstat(filename, { bigint: true });
    const owner = record(JSON.parse(original.content) as unknown, 'transaction.lock', ['transactionId', 'pid']);
    if (owner.transactionId !== id || typeof owner.pid !== 'number' || !Number.isSafeInteger(owner.pid) || owner.pid <= 0) {
      throw new WorkflowError('conflict', 'Only this selection transaction can recover its own dead writer lock.');
    }
    let dead = false;
    try { process.kill(owner.pid, 0); }
    catch (error) { dead = typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ESRCH'; }
    if (!dead) throw new WorkflowError('conflict', 'Selection writer may still exist; its lock is preserved.');
    const after = await lstat(filename, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.ctimeNs !== after.ctimeNs ||
        before.mtimeNs !== after.mtimeNs || (await this.read(lock))?.digest !== original.digest) {
      throw new WorkflowError('stale-revision', 'Selection writer lock changed; no unrelated lock was removed.');
    }
    if (reclaim) {
      await unlink(filename);
      await this.syncDirectory(filename);
    }
  }

  async recoveryPlan(id: string): Promise<FilePlan> {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new ContractError('transactionId', 'invalid transaction identity');
    const file = await this.read(parseProjectPath(`.missionspec/transactions/${id}.json`));
    if (file === null || !(await this.pending()).includes(id)) throw new WorkflowError('not-found', 'No pending transaction with this identity.');
    const data = record(JSON.parse(file.content) as unknown, 'journal', ['schemaVersion', 'plan', 'approval']);
    if (data.schemaVersion !== 1) throw new ContractError('journal', 'unsupported journal version');
    const plan = parseFilePlan(data.plan);
    await this.checkScope(plan);
    await this.compare(plan, true, id);
    return plan;
  }

  async recover(id: string, approval: ApprovalReference): Promise<{ transactionId: string; state: 'committed' }> {
    return this.commitPlan(await this.recoveryPlan(id), approval, id);
  }
}
