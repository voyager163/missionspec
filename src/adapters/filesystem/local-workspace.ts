import { constants } from 'node:fs';
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
import { windowsPrivateEntries } from '../platform/windows-private-state.js';

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

export async function observeWorkspaceRoot(directory: string): Promise<{ root: string; rootDigest: ContentDigest }> {
  const root = await realpath(directory);
  const info = await lstat(root, { bigint: true });
  if (!info.isDirectory()) throw new WorkflowError('invalid-input', 'Select an existing local directory.');
  return { root, rootDigest: digestContent(JSON.stringify({ root, device: String(info.dev), inode: String(info.ino) })) };
}

export class LocalWorkspace {
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

  private async target(relative: ProjectPath, createParents = false): Promise<string> {
    parseProjectPath(relative);
    if ((await observeWorkspaceRoot(this.root)).rootDigest !== this.rootDigest) {
      throw new WorkflowError('scope-exceeded', 'The observed workspace root changed.');
    }
    let current = this.root;
    const parts = relative.split('/');
    for (let index = 0; index < parts.length; index += 1) {
      current = path.join(current, parts[index]!);
      const parent = index < parts.length - 1;
      if (parent && createParents) {
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
        if (relative.startsWith('.missionspec/')) {
          if (process.platform === 'win32') {
            windowsPrivateEntries([{ path: current, directory: info.isDirectory(), writable: false }]);
          } else if (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) {
            throw new WorkflowError('scope-exceeded', 'Runtime state requires current-user ownership and owner-only permissions.');
          }
        }
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
    return current;
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
    const directory = await open(path.dirname(file), constants.O_RDONLY);
    try { await directory.sync(); } finally { await directory.close(); }
  }

  private async exclusive(relative: ProjectPath, content: string, mode = 0o600): Promise<void> {
    if (!['darwin', 'linux'].includes(process.platform)) {
      throw new WorkflowError('capability-unavailable', 'Runtime journals require a qualified durable directory-entry barrier, not only file flushing or ACLs.');
    }
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
    if (!['darwin', 'linux'].includes(process.platform)) throw new WorkflowError('capability-unavailable', 'Private runtime writes require qualified POSIX permissions.');
    const info = await lstat(this.root);
    if (info.uid !== process.getuid?.() || (info.mode & 0o022) !== 0) throw new WorkflowError('scope-exceeded', 'Runtime records require a private current-user-owned root.');
    const content = JSON.stringify(value);
    if (Buffer.byteLength(content) > 6_000_000) throw new WorkflowError('limit-reached', 'Runtime record exceeds its retained payload limit.');
    const target = parseProjectPath(`.missionspec/${area}/${name}.json`);
    await this.exclusive(target, content);
    const result = await this.read(target);
    if (result?.digest !== digestContent(content)) throw new WorkflowError('persistence-failed', 'Immutable runtime record could not be verified.');
    return result;
  }

  async withRuntimeLock<T>(operation: () => Promise<T>): Promise<T> {
    const lock = parseProjectPath('.missionspec/transaction.lock');
    await this.exclusive(lock, JSON.stringify({ kind: 'runtime', pid: process.pid }));
    try {
      if ((await this.pending()).length > 0) throw new WorkflowError('conflict', 'Pending file recovery blocks runtime effects.');
      return await operation();
    } finally {
      const target = await this.target(lock);
      await unlink(target);
      await this.syncDirectory(target);
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
    if (process.platform !== 'darwin' && process.platform !== 'linux') {
      throw new WorkflowError('capability-unavailable', 'Private local file transactions are not qualified on this platform.');
    }
    const rootInfo = await lstat(this.root);
    if (rootInfo.uid !== process.getuid?.() || (rootInfo.mode & 0o022) !== 0) {
      throw new WorkflowError('scope-exceeded', 'File effects require a current-user-owned root without group/world write access.');
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
    try {
      await this.exclusive(lock, JSON.stringify({ transactionId: id, pid: process.pid }));
      locked = true;
      if ((await this.pending()).some((pending) => pending !== recoveryId)) {
        throw new WorkflowError('conflict', 'A pending transaction was observed after acquiring the local writer lock.');
      }
      await this.beforeEffects(plan);
      if (recoveryId === undefined) {
        await this.exclusive(parseProjectPath(`.missionspec/transactions/${id}.json`), JSON.stringify({ schemaVersion: 1, plan, approval: issued }));
      }
      prepared = true;
      await this.checkScope(plan);
      await this.compare(plan, recoveryId !== undefined);
      for (const mutation of plan.mutations) {
        await requireApproval(this.authority, approval, plan.request, this.now());
        await this.compare(plan, true);
        const actual = (await this.read(mutation.effect.path))?.digest ?? 'absent';
        const proposed = mutation.effect.kind === 'file-write' ? mutation.effect.proposed : 'absent';
        if (recoveryId !== undefined && actual === proposed) continue;
        if (actual !== mutation.effect.expected) throw new WorkflowError('stale-revision', 'An output changed before its write.');
        const target = await this.target(mutation.effect.path, true);
        const existing = actual === 'absent' ? null : await lstat(target);
        if (existing !== null && (existing.uid !== process.getuid?.() || (existing.mode & 0o7000) !== 0)) {
          throw new WorkflowError('scope-exceeded', 'Replacement/removal requires an ordinary current-user-owned file.');
        }
        if (mutation.effect.kind === 'file-remove') await unlink(target);
        else if ('content' in mutation) {
          const stage = parseProjectPath(`${mutation.effect.path}.msn-${id}`);
          await this.exclusive(stage, mutation.content, existing === null ? 0o600 : existing.mode & 0o777);
          try {
            if (((await this.read(mutation.effect.path))?.digest ?? 'absent') !== mutation.effect.expected) {
              throw new WorkflowError('stale-revision', 'An output changed before replacement.');
            }
            if (mutation.effect.expected === 'absent') await link(await this.target(stage), target);
            else await rename(await this.target(stage), target);
          } finally {
            try { await unlink(path.join(this.root, stage)); } catch (error) { if (!missing(error)) throw error; }
          }
        }
        await this.syncDirectory(target);
      }
      for (const mutation of plan.mutations) {
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
      if (prepared) throw new WorkflowError('effect-outcome-unknown', 'The prepared file transaction did not finish. Inspect pending transactions and recover without overwriting changed files.');
      if (!locked) throw new WorkflowError('conflict', 'Local transaction lock or audit storage is unavailable. Do not remove a lock without establishing writer quiescence.');
      throw error;
    } finally {
      if (locked) { const target = await this.target(lock); await unlink(target); await this.syncDirectory(target); }
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
    await this.compare(plan, true);
    return plan;
  }

  async recover(id: string, approval: ApprovalReference): Promise<{ transactionId: string; state: 'committed' }> {
    return this.commitPlan(await this.recoveryPlan(id), approval, id);
  }
}
