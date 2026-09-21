import { constants, linkSync, lstatSync, readFileSync, renameSync, unlinkSync, type BigIntStats } from 'node:fs';
import { link, lstat, mkdir, open, readdir, realpath, rename, unlink } from 'node:fs/promises';
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
import { parseTaskDefinition, type TaskDefinition } from '../../engines/planning/contracts.js';
import {
  requireWindowsProcessAbsent, syncWindowsPrivateDirectory, validateWindowsStatePath, windowsPrivateEntries,
  WindowsDirectoryDurabilityError, WindowsPrivateStateError, type WindowsPrivateEntry, type WindowsWriterLease,
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
  for (const mutation of mutations) {
    if (!guards.some((guard) => guard.path === mutation.effect.path && guard.digest === mutation.effect.expected)) {
      throw new ContractError('guards', 'every mutation requires an exact prior observation');
    }
    const installationRecord = mutation.effect.path === '.missionspec/installation.json' &&
      input.operation === 'onboard' && input.purpose === 'integration' && mutation.effect.purpose === 'configuration';
    if (mutation.effect.path.startsWith('.missionspec/') && mutation.effect.path !== '.missionspec/workspace.json' && !installationRecord) {
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

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

function windowsIoDetail(error: unknown): string {
  if (error instanceof WindowsPrivateStateError || error instanceof WindowsDirectoryDurabilityError) return error.message;
  const code: unknown = typeof error === 'object' && error !== null ? Reflect.get(error, 'code') : undefined;
  return typeof code === 'string' && ['EACCES', 'EPERM', 'EBADF', 'EIO', 'EEXIST', 'ENOENT', 'EBUSY', 'ENOTDIR', 'ENOSPC'].includes(code)
    ? `Filesystem code: ${code}.` : 'Filesystem outcome is unconfirmed.';
}

function sameWindowsStage(left: BigIntStats, right: BigIntStats): boolean {
  return right.isFile() && !right.isSymbolicLink() && right.nlink === 1n &&
    left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

export async function observeWorkspaceRoot(directory: string): Promise<{ root: string; rootDigest: ContentDigest }> {
  const root = await realpath(directory);
  const info = await lstat(root, { bigint: true });
  if (!info.isDirectory()) throw new WorkflowError('invalid-input', 'Select an existing local directory.');
  return { root, rootDigest: digestContent(JSON.stringify({ root, device: String(info.dev), inode: String(info.ino) })) };
}

export class LocalWorkspace {
  private windowsLease: WindowsWriterLease | undefined;
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
    const checks: WindowsPrivateEntry[] = [];
    if (process.platform === 'win32' && writable) checks.push({ path: this.root, directory: true, writable: true });
    const parts = relative.split('/');
    for (let index = 0; index < parts.length; index += 1) {
      current = path.join(current, parts[index]!);
      if (process.platform === 'win32' && writable) validateWindowsStatePath(current);
      const parent = index < parts.length - 1;
      if (parent && createParents) {
        if (process.platform === 'win32') {
          let exists = true;
          try { await lstat(current); } catch (error) { if (!missing(error)) throw error; exists = false; }
          if (!exists) {
            const directory = path.dirname(current);
            const identity = await lstat(directory, { bigint: true });
            try {
              windowsPrivateEntries([
                { path: directory, directory: true, writable: true },
                { path: current, directory: true, writable: true, create: true },
              ], this.windowsLease);
              syncWindowsPrivateDirectory(directory, identity);
            } catch (error) {
              throw new WorkflowError('effect-outcome-unknown', `Private directory creation was not durably confirmed; inspect the retained state before retrying. ${windowsIoDetail(error)}`);
            }
          }
        } else {
          try { await mkdir(current, { mode: 0o700 }); } catch (error) {
            if (!(typeof error === 'object' && error !== null && 'code' in error && error.code === 'EEXIST')) throw error;
          }
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
    let handle;
    try {
      const target = await this.target(relative);
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

  private async compare(plan: FilePlan, recovery: boolean): Promise<void> {
    for (const guard of plan.guards) {
      const actual = (await this.read(guard.path))?.digest ?? 'absent';
      const mutation = plan.mutations.find((entry) => entry.effect.path === guard.path);
      const proposed = mutation?.effect.kind === 'file-write' ? mutation.effect.proposed : mutation ? 'absent' : null;
      if (actual !== guard.digest && !(recovery && actual === proposed)) {
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

  private async exclusive(relative: ProjectPath, content: string, mode = 0o600, securityFrom?: string): Promise<void> {
    if (process.platform === 'win32') {
      await this.writeRoot();
      const target = await this.target(relative, true, true);
      try { await lstat(target); throw new WorkflowError('conflict', 'Exclusive private creation found an existing path.'); }
      catch (error) { if (!missing(error)) throw error; }
      try {
        windowsPrivateEntries([{ path: target, directory: false, writable: true, create: true, ordinaryFile: true,
          ...(securityFrom === undefined ? {} : { copySecurityFrom: securityFrom }) }], this.windowsLease);
        const identity = await lstat(target, { bigint: true });
        const handle = await open(target, constants.O_WRONLY | constants.O_NOFOLLOW);
        try {
          const actual = await handle.stat({ bigint: true });
          if (actual.dev !== identity.dev || actual.ino !== identity.ino) throw new Error('Private file identity changed');
          await handle.writeFile(content, 'utf8');
          await handle.sync();
        } finally { await handle.close(); }
        await this.syncDirectory(target);
      } catch (error) {
        throw new WorkflowError('effect-outcome-unknown', `The private file write or flush was not confirmed; preserve the existing record for reconciliation. ${windowsIoDetail(error)}`);
      }
      return;
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
  async recordRuntime(area: 'approvals' | 'checks' | 'evidence' | 'audit', name: string, value: unknown): Promise<FileSnapshot> {
    if (!['approvals', 'checks', 'evidence', 'audit'].includes(area)) throw new ContractError('record.area', 'unsupported runtime record area');
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
    const lock = parseProjectPath('.missionspec/transaction.lock');
    const content = JSON.stringify({ kind: 'runtime', pid: process.pid });
    await this.exclusive(lock, content);
    let identity;
    try { identity = process.platform === 'win32' ? await lstat(path.join(this.root, lock), { bigint: true }) : undefined; }
    catch { throw new WorkflowError('effect-outcome-unknown', 'The written runtime lock identity could not be confirmed.'); }
    if (identity !== undefined) this.windowsLease = { path: path.join(this.root, lock), dev: identity.dev, ino: identity.ino, digest: digestContent(content) };
    try {
      if ((await this.pending()).length > 0) throw new WorkflowError('conflict', 'Pending file recovery blocks runtime effects.');
      return await operation();
    } finally {
      this.windowsLease = undefined;
      if (identity !== undefined) {
        try {
          const target = await this.target(lock);
          const current = lstatSync(target, { bigint: true });
          if (current.dev !== identity.dev || current.ino !== identity.ino ||
              current.mtimeNs !== identity.mtimeNs || current.ctimeNs !== identity.ctimeNs ||
              readFileSync(target, 'utf8') !== content) throw new Error('Runtime writer lock changed');
          unlinkSync(target);
          await this.syncDirectory(target);
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

  private async commitPlan(value: FilePlan, approval: ApprovalReference, recoveryId?: string): Promise<{ transactionId: string; state: 'committed' }> {
    const plan = parseFilePlan(value);
    await this.writeRoot();
    if (process.platform === 'win32') {
      for (const mutation of plan.mutations) {
        await this.target(mutation.effect.path, false, true);
        if (mutation.effect.kind === 'file-write') validateWindowsStatePath(path.join(this.root, `${mutation.effect.path}.msn-00000000-0000-0000-0000-000000000000`));
      }
    }
    await this.checkScope(plan);
    const issued = await requireApproval(this.authority, approval, plan.request, this.now());
    const pending = await this.pending();
    if (pending.some((id) => id !== recoveryId)) throw new WorkflowError('conflict', 'An unfinished file transaction requires explicit recovery first.');
    await this.compare(plan, recoveryId !== undefined);
    const id = recoveryId ?? randomUUID();
    const lock = parseProjectPath('.missionspec/transaction.lock');
    let locked = false;
    let prepared = false;
    let lockIdentity: { dev: bigint; ino: bigint; mtimeNs: bigint; ctimeNs: bigint } | undefined;
    try {
      if (process.platform === 'win32' && recoveryId !== undefined) await this.reclaimWindowsTransactionLock(lock, id);
      await this.exclusive(lock, JSON.stringify({ transactionId: id, pid: process.pid }));
      locked = true;
      if (process.platform === 'win32') lockIdentity = await lstat(path.join(this.root, lock), { bigint: true });
      if (lockIdentity !== undefined) this.windowsLease = {
        path: path.join(this.root, lock), dev: lockIdentity.dev, ino: lockIdentity.ino,
        digest: digestContent(JSON.stringify({ transactionId: id, pid: process.pid })),
      };
      if ((await this.pending()).some((pending) => pending !== recoveryId)) {
        throw new WorkflowError('conflict', 'A pending transaction was observed after acquiring the local writer lock.');
      }
      await this.beforeEffects(plan);
      if (recoveryId === undefined) {
        await this.exclusive(parseProjectPath(`.missionspec/transactions/${id}.json`), JSON.stringify({ schemaVersion: 1, plan, approval: issued }));
      } else if (process.platform === 'win32') {
        prepared = true;
        const journal = await this.target(parseProjectPath(`.missionspec/transactions/${id}.json`), false, true);
        const handle = await open(journal, constants.O_RDWR | constants.O_NOFOLLOW);
        try { await handle.sync(); } finally { await handle.close(); }
        await this.syncDirectory(journal);
      }
      prepared = true;
      await this.checkScope(plan);
      await this.compare(plan, recoveryId !== undefined);
      for (const mutation of plan.mutations) {
        await requireApproval(this.authority, approval, plan.request, this.now());
        await this.compare(plan, true);
        const actual = (await this.read(mutation.effect.path))?.digest ?? 'absent';
        const proposed = mutation.effect.kind === 'file-write' ? mutation.effect.proposed : 'absent';
        if (recoveryId !== undefined && actual === proposed) {
          if (process.platform === 'win32') await this.syncDirectory(path.join(this.root, mutation.effect.path));
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
            const removalGuard = lstatSync(target, { bigint: true });
            windowsPrivateEntries([{ path: target, directory: false, writable: true, ordinaryFile: true }]);
            if (((await this.read(mutation.effect.path))?.digest ?? 'absent') !== mutation.effect.expected) {
              throw new WorkflowError('stale-revision', 'An output changed before removal.');
            }
            const current = lstatSync(target, { bigint: true });
            if (current.dev !== removalGuard.dev || current.ino !== removalGuard.ino ||
                current.mtimeNs !== removalGuard.mtimeNs || current.ctimeNs !== removalGuard.ctimeNs) {
              throw new WorkflowError('stale-revision', 'An output or its metadata changed before removal.');
            }
            unlinkSync(target);
          } else await unlink(target);
        }
        else if ('content' in mutation) {
          const stage = parseProjectPath(`${mutation.effect.path}.msn-${id}`);
          const stagePath = path.join(this.root, stage);
          let stageIdentity: BigIntStats | undefined;
          if (process.platform === 'win32' && recoveryId !== undefined) {
            try { stageIdentity = lstatSync(stagePath, { bigint: true }); } catch (error) { if (!missing(error)) throw error; }
          }
          const stageFile = process.platform === 'win32' && recoveryId !== undefined ? await this.read(stage) : null;
          if (process.platform === 'win32' && recoveryId !== undefined &&
              ((stageIdentity === undefined) !== (stageFile === null))) {
            throw new WorkflowError('stale-revision', 'The retained stage appeared or disappeared while being admitted; it is preserved for reconciliation.');
          }
          if (stageIdentity !== undefined && !sameWindowsStage(stageIdentity, lstatSync(stagePath, { bigint: true }))) {
            throw new WorkflowError('stale-revision', 'The retained stage identity or metadata changed while being read; it is preserved for reconciliation.');
          }
          if (stageFile === null) {
            await this.exclusive(stage, mutation.content, process.platform === 'win32' || existing === null ? 0o600 : existing.mode & 0o777,
              process.platform === 'win32' && existing !== null ? target : undefined);
            if (process.platform === 'win32') stageIdentity = lstatSync(stagePath, { bigint: true });
          } else if (stageFile.digest !== mutation.effect.proposed) {
            throw new WorkflowError('stale-revision', 'The retained stage differs from the reviewed bytes; no stage edit is overwritten.');
          }
          try {
            if (process.platform === 'win32') {
              const securityGuard = existing === null ? null : lstatSync(target, { bigint: true });
              windowsPrivateEntries([{ path: path.join(this.root, stage), directory: false, writable: true, ordinaryFile: true,
                ...(existing === null ? {} : { sameSecurityAs: target }) }]);
              if (securityGuard !== null) {
                const current = lstatSync(target, { bigint: true });
                if (current.dev !== securityGuard.dev || current.ino !== securityGuard.ino ||
                    current.mtimeNs !== securityGuard.mtimeNs || current.ctimeNs !== securityGuard.ctimeNs) {
                  throw new WorkflowError('stale-revision', 'Source data or security changed during the final permission check.');
                }
              }
              if (stageFile !== null) {
                const handle = await open(path.join(this.root, stage), constants.O_RDWR | constants.O_NOFOLLOW);
                try { await handle.sync(); } finally { await handle.close(); }
                await this.syncDirectory(path.join(this.root, stage));
              }
            }
            if (((await this.read(mutation.effect.path))?.digest ?? 'absent') !== mutation.effect.expected) {
              throw new WorkflowError('stale-revision', 'An output changed before replacement.');
            }
            if (process.platform === 'win32') {
              const currentStage = lstatSync(stagePath, { bigint: true });
              if (stageIdentity === undefined || !sameWindowsStage(stageIdentity, currentStage) ||
                  digestContent(readFileSync(stagePath)) !== mutation.effect.proposed ||
                  !sameWindowsStage(currentStage, lstatSync(stagePath, { bigint: true }))) {
                throw new WorkflowError('stale-revision', 'The admitted stage changed; neither it nor a replacement stage is removed.');
              }
              if (mutation.effect.expected === 'absent') {
                linkSync(stagePath, target);
                const linked = lstatSync(stagePath, { bigint: true });
                const published = lstatSync(target, { bigint: true });
                if (!linked.isFile() || linked.isSymbolicLink() || linked.nlink !== 2n ||
                    !published.isFile() || published.isSymbolicLink() || published.nlink !== 2n ||
                    linked.dev !== stageIdentity.dev || linked.ino !== stageIdentity.ino ||
                    published.dev !== stageIdentity.dev || published.ino !== stageIdentity.ino ||
                    digestContent(readFileSync(stagePath)) !== mutation.effect.proposed) {
                  throw new WorkflowError('stale-revision', 'The published stage pair changed; both paths are preserved for reconciliation.');
                }
                const checked = lstatSync(stagePath, { bigint: true });
                const checkedTarget = lstatSync(target, { bigint: true });
                if (checked.dev !== linked.dev || checked.ino !== linked.ino || checked.nlink !== 2n ||
                    checked.size !== linked.size || checked.mtimeNs !== linked.mtimeNs || checked.ctimeNs !== linked.ctimeNs ||
                    checkedTarget.dev !== linked.dev || checkedTarget.ino !== linked.ino || checkedTarget.nlink !== 2n ||
                    checkedTarget.size !== linked.size || checkedTarget.mtimeNs !== linked.mtimeNs ||
                    checkedTarget.ctimeNs !== linked.ctimeNs) {
                  throw new WorkflowError('stale-revision', 'The linked stage changed during cleanup verification; no pathname is removed.');
                }
                unlinkSync(stagePath);
              } else renameSync(stagePath, target);
            } else if (mutation.effect.expected === 'absent') await link(await this.target(stage), target);
            else await rename(await this.target(stage), target);
          } finally {
            if (process.platform !== 'win32') {
              try { await unlink(stagePath); } catch (error) { if (!missing(error)) throw error; }
            }
          }
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
      if (!locked) throw new WorkflowError('conflict', 'Local transaction lock or audit storage is unavailable. Do not remove a lock without establishing writer quiescence.');
      throw error;
    } finally {
      if (locked) {
        this.windowsLease = undefined;
        if (process.platform === 'win32') {
          try {
            const target = await this.target(lock);
            const current = await lstat(target, { bigint: true });
            if (lockIdentity === undefined || current.dev !== lockIdentity.dev || current.ino !== lockIdentity.ino ||
                current.mtimeNs !== lockIdentity.mtimeNs || current.ctimeNs !== lockIdentity.ctimeNs ||
                readFileSync(target, 'utf8') !== JSON.stringify({ transactionId: id, pid: process.pid })) throw new Error('Writer lock changed');
            unlinkSync(target);
            await this.syncDirectory(target);
          } catch {
            throw new WorkflowError('effect-outcome-unknown', 'Writer-lock release was not confirmed; do not infer transaction completion or steal a replacement lock.');
          }
        } else { const target = await this.target(lock); await unlink(target); await this.syncDirectory(target); }
      }
    }
  }

  private async reclaimWindowsTransactionLock(lock: ProjectPath, id: string): Promise<void> {
    const filename = await this.target(lock, false, true);
    let identity;
    try { identity = lstatSync(filename, { bigint: true }); } catch (error) { if (missing(error)) return; throw error; }
    const original = await this.read(lock);
    if (original === null) throw new WorkflowError('conflict', 'Writer lock changed during recovery.');
    const owner = record(JSON.parse(original.content) as unknown, 'transaction.lock', ['transactionId', 'pid']);
    if (owner.transactionId !== id || typeof owner.pid !== 'number' || !Number.isSafeInteger(owner.pid)) {
      throw new WorkflowError('conflict', 'Only this transaction can reclaim its own demonstrably dead writer lock.');
    }
    try { requireWindowsProcessAbsent(owner.pid); } catch {
      throw new WorkflowError('conflict', 'The recorded writer may still exist; its lock is preserved.');
    }
    const current = lstatSync(filename, { bigint: true });
    if (identity.dev !== current.dev || identity.ino !== current.ino || identity.mtimeNs !== current.mtimeNs ||
        identity.ctimeNs !== current.ctimeNs || readFileSync(filename, 'utf8') !== original.content) {
      throw new WorkflowError('conflict', 'Writer lock changed before recovery; no unrelated lock is removed.');
    }
    unlinkSync(filename);
    await this.syncDirectory(filename);
  }

  async recoveryPlan(id: string): Promise<FilePlan> {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new ContractError('transactionId', 'invalid transaction identity');
    const file = await this.read(parseProjectPath(`.missionspec/transactions/${id}.json`));
    if (file === null || !(await this.pending()).includes(id)) throw new WorkflowError('not-found', 'No pending transaction with this identity.');
    const data = record(JSON.parse(file.content) as unknown, 'journal', ['schemaVersion', 'plan', 'approval']);
    if (data.schemaVersion !== 1) throw new ContractError('journal', 'unsupported journal version');
    const plan = parseFilePlan(data.plan);
    await this.checkScope(plan);
    await this.compare(plan, true);
    return plan;
  }

  async recover(id: string, approval: ApprovalReference): Promise<{ transactionId: string; state: 'committed' }> {
    return this.commitPlan(await this.recoveryPlan(id), approval, id);
  }
}
