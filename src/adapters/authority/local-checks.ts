import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { LocalWorkflow } from '../../application/local-workflow.js';
import { requireApproval } from '../../application/authority.js';
import { WorkflowError } from '../../application/errors.js';
import { parseApprovalRequest, type ApprovalReference } from '../../kernel/authority.js';
import { digestContent, sameRevisionBinding, type WorkspaceBinding } from '../../kernel/revisions.js';
import { digestEffectScope } from '../../kernel/effects.js';
import { parseId, parseProjectPath, type RunId } from '../../kernel/identifiers.js';
import { array, integer, record, text, unique } from '../../kernel/validation.js';
import type { LocalAuthorityPort, RuntimeStorePort } from '../../ports/contracts.js';
import type { RunSnapshot } from '../../engines/execution/contracts.js';
import type { EvidenceReference } from '../../engines/verification/contracts.js';

export interface LocalCheckInput {
  readonly checkId: string;
  readonly program: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly controlFiles: readonly string[];
  readonly timeoutMs: number;
  readonly guarantees: 'trusted-local-process';
}

async function programIdentity(program: string) {
  if (!path.isAbsolute(program) || await realpath(program) !== program) throw new WorkflowError('check-unqualified', 'Select the real absolute executable path, without symlinks.');
  const handle = await open(program, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > 256_000_000n) throw new WorkflowError('check-unqualified', 'Executable must be a bounded regular file.');
    const digest = digestContent(await handle.readFile());
    const after = await lstat(program, { bigint: true });
    if (before.ino !== after.ino || before.dev !== after.dev || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      throw new WorkflowError('stale-revision', 'Executable changed while observing it.');
    }
    return digest;
  } finally { await handle.close(); }
}

/** Explicitly trusted local programs, NOT a filesystem/network/process-tree sandbox. */
export class LocalChecks {
  constructor(
    private readonly workflow: LocalWorkflow, private readonly store: RuntimeStorePort | undefined,
    private readonly authority: LocalAuthorityPort,
  ) {}

  async previewRegistration(slug: string, value: LocalCheckInput) {
    if (!['darwin', 'linux'].includes(process.platform)) throw new WorkflowError('check-unqualified', 'This local process adapter requires POSIX permissions and process groups.');
    const input = record(value, 'localCheck', ['checkId', 'program', 'argv', 'cwd', 'controlFiles', 'timeoutMs', 'guarantees']);
    if (input.guarantees !== 'trusted-local-process') throw new WorkflowError('check-unqualified', 'Filesystem/network confinement and hard process-tree cancellation are not supported by this adapter.');
    const change = await this.workflow.loadChange(slug);
    const checkId = parseId('check', input.checkId);
    const check = change.analysis.checks.find((check) => check.id === checkId);
    if (check?.kind !== 'executed') throw new WorkflowError('check-unqualified', 'Register one current declared executed check; prose is not a command.');
    const program = text(input.program, 'program');
    const cwd = input.cwd === '.' ? '.' : parseProjectPath(input.cwd);
    if (await realpath(path.join(this.workflow.files.root, cwd)) !== path.join(this.workflow.files.root, cwd)) throw new WorkflowError('scope-exceeded', 'Check working directory must not traverse symlinks.');
    const controlFiles = unique(array(input.controlFiles, 'controlFiles', parseProjectPath), 'controlFiles');
    const controls = await Promise.all(controlFiles.map(async (file) => {
      const observed = await this.workflow.files.read(file);
      if (observed === null) throw new WorkflowError('not-found', 'Every selected check control file must exist.');
      return { path: file, digest: observed.digest };
    }));
    const registration = {
      schemaVersion: 1, workspace: change.workspace, changeId: change.metadata.id,
      checkId, definition: check.definition, program, programDigest: await programIdentity(program),
      argv: array(input.argv, 'argv', (arg) => typeof arg === 'string' && !arg.includes('\0') ? arg : text(arg, 'arg'), 0),
      cwd, controls, sourceScope: change.metadata.sourcePaths,
      timeoutMs: integer(input.timeoutMs, 'timeoutMs', 1, 300_000),
      guarantees: 'trusted-local-process' as const,
      limitations: 'No filesystem/network confinement. Timeout kills the POSIX process group best-effort; escaped descendants cannot be proven stopped. Trust the program and its selected control files; a timeout is outcome-unknown, never passing evidence.',
    };
    const digest = digestContent(JSON.stringify(registration));
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'verification', effects: [],
      binding: { kind: 'review', revisions: change.revisions, subject: digest, effects: digestEffectScope([]) },
    });
    return { registration, digest, request };
  }

  async register(slug: string, value: LocalCheckInput, approval: ApprovalReference) {
    const preview = await this.previewRegistration(slug, value);
    await requireApproval(this.authority, approval, preview.request, new Date().toISOString());
    const id = `check-${randomUUID()}`;
    await this.workflow.files.recordRuntime('checks', id, { ...preview, approval });
    return { id, ...preview };
  }

  private async registration(slug: string, id: string) {
    if (!/^check-[a-f0-9-]{36}$/u.test(id)) throw new WorkflowError('invalid-input', 'Select an immutable check registration identity.');
    const file = await this.workflow.files.read(parseProjectPath(`.missionspec/checks/${id}.json`));
    if (file === null) throw new WorkflowError('check-unqualified', 'Check registration was not found.');
    const stored = JSON.parse(file.content) as Awaited<ReturnType<LocalChecks['previewRegistration']>> & { approval: ApprovalReference };
    const r = stored.registration;
    const current = await this.previewRegistration(slug, {
      checkId: r.checkId, program: r.program, argv: r.argv, cwd: r.cwd,
      controlFiles: r.controls.map((file) => file.path), timeoutMs: r.timeoutMs, guarantees: r.guarantees,
    });
    if (current.digest !== stored.digest || digestContent(JSON.stringify(r)) !== stored.digest) throw new WorkflowError('stale-revision', 'Registration definition, executable, controls, workspace or selected source scope changed; independently register again.');
    const approved = await this.authority.resolve(stored.approval);
    if (approved.status !== 'ok' || !['current', 'expired'].includes(approved.value.state)) {
      throw new WorkflowError('authority-required', 'The original registration is unavailable or revoked.');
    }
    return current;
  }

  async previewCollection(slug: string, runId: RunId, ids: readonly string[]) {
    unique(ids, 'registrations');
    if (ids.length === 0 || ids.length > 32) throw new WorkflowError('limit-reached', 'Select between one and 32 registered checks.');
    const registrations = await Promise.all(ids.map((id) => this.registration(slug, id)));
    unique(registrations.map((entry) => entry.registration.checkId), 'checks');
    const effects = registrations.map(({ registration }) => ({ kind: 'check-execute' as const, checkId: registration.checkId, definition: registration.definition }));
    const change = await this.workflow.loadChange(slug, effects);
    if (this.store === undefined && (await this.workflow.files.list(parseProjectPath('.missionspec/state'))).includes(parseProjectPath('.missionspec/state/ledger.sqlite'))) {
      throw new WorkflowError('persistence-failed', 'The existing ledger must be composed for verification.');
    }
    const previous = this.store === undefined ? { status: 'ok' as const, value: null } : await this.store.readRun(runId);
    if (previous.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot establish verification run state.');
    const revisions = previous.value === null ? change.revisions : { ...change.revisions, effects: previous.value.snapshot.revisions.effects };
    if (previous.value !== null && (!sameRevisionBinding(revisions, previous.value.snapshot.revisions) ||
        previous.value.snapshot.quiescence !== 'confirmed' || ['running', 'outcome-unknown'].includes(previous.value.snapshot.state))) {
      throw new WorkflowError('stale-revision', 'Verification requires matching live source and a quiescent, reconciled run.');
    }
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'verification', effects,
      binding: { kind: 'review', revisions, subject: digestContent(JSON.stringify({ runId, ids, registrations: registrations.map((entry) => entry.digest) })), effects: digestEffectScope(effects) },
    });
    return { request, registrations, revisions, previous };
  }

  async collect(slug: string, runId: RunId, ids: readonly string[], approval: ApprovalReference) {
    const store = this.store;
    if (store === undefined) throw new WorkflowError('persistence-failed', 'Collection requires an explicitly opened runtime ledger.');
    const preview = await this.previewCollection(slug, runId, ids);
    await requireApproval(this.authority, approval, preview.request, new Date().toISOString());
    return this.workflow.files.withRuntimeLock(async () => {
      const fresh = await this.previewCollection(slug, runId, ids);
      await requireApproval(this.authority, approval, fresh.request, new Date().toISOString());
      const runs = await store.listRuns();
      if (runs.status !== 'ok' || runs.value.some((run) => run.quiescence !== 'confirmed' || ['running', 'outcome-unknown'].includes(run.state))) {
        throw new WorkflowError('conflict', 'An active or unreconciled workspace run blocks check execution.');
      }
      let snapshot: RunSnapshot = fresh.previous.status === 'ok' && fresh.previous.value !== null
        ? fresh.previous.value.snapshot
        : { contractVersion: 1, id: runId, revisions: fresh.revisions, state: 'paused', activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed' };
      const admission = await store.commitRun({ expectedRevision: fresh.previous.status === 'ok' ? fresh.previous.value?.revision ?? 'absent' : 'absent',
        snapshot: { ...snapshot, state: 'running', quiescence: 'unconfirmed' }, attempts: [], evidence: [] });
      if (admission.status !== 'ok') throw new WorkflowError('persistence-failed', 'Check admission audit could not be persisted.');
      let revision = admission.value.revision;
      const evidence: EvidenceReference[] = [];
      try {
        for (let index = 0; index < ids.length; index += 1) {
          const { registration: r } = await this.registration(slug, ids[index]!);
          await requireApproval(this.authority, approval, fresh.request, new Date().toISOString());
          const id = parseId('evidence', `EVD-${randomUUID()}`);
          await this.workflow.files.recordRuntime('audit', id, { state: 'check-admitted', runId, approval, request: fresh.request, registration: r });
          const startedAt = new Date().toISOString();
          const observation = await this.execute(r);
          const after = await this.workflow.loadChange(slug);
          const unchanged = sameRevisionBinding({ ...after.revisions, effects: fresh.revisions.effects }, fresh.revisions);
          const output = { ...observation, startedAt, finishedAt: new Date().toISOString(), registration: r, sourceBefore: fresh.revisions.source, sourceAfter: after.revisions.source };
          const raw = await this.workflow.files.recordRuntime('evidence', id, {
            schemaVersion: 1, evidenceId: id, basis: 'executed',
            result: observation.exitCode === 0 && !observation.interrupted && unchanged ? 'passed' : 'failed',
            output: JSON.stringify(output),
          });
          if (observation.interrupted || !unchanged) throw new WorkflowError('effect-outcome-unknown', 'Check cancellation or source changes require investigation; no passing evidence is issued.');
          await this.registration(slug, ids[index]!);
          evidence.push({
            contractVersion: 1, id, revisions: fresh.revisions, source: fresh.revisions.source, checkId: r.checkId,
            checkDefinition: r.definition, attemptId: null, storage: { state: 'retained', path: raw.path, digest: raw.digest },
          });
        }
        snapshot = { ...snapshot, state: 'paused', quiescence: 'confirmed' };
        const result = await store.commitRun({ expectedRevision: revision, snapshot, attempts: [], evidence });
        if (result.status !== 'ok') throw new WorkflowError('persistence-failed', 'Check evidence could not be durably recorded.');
        revision = result.value.revision;
        return { runId, evidence: evidence.map((entry) => entry.id), state: 'collected' as const };
      } catch (error) {
        await store.commitRun({ expectedRevision: revision, snapshot: { ...snapshot, state: 'outcome-unknown', quiescence: 'unconfirmed' }, attempts: [], evidence: [] });
        throw error;
      }
    });
  }

  private async execute(r: { program: string; argv: readonly string[]; cwd: string; timeoutMs: number; workspace: WorkspaceBinding }) {
    return new Promise<{ exitCode: number | null; signal: string | null; interrupted: boolean; stdout: string; stderr: string }>((resolve, reject) => {
      const child = spawn(r.program, [...r.argv], {
        cwd: path.join(this.workflow.files.root, r.cwd), shell: false, detached: true,
        env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let interrupted = false;
      let length = 0;
      let settlement: ReturnType<typeof setTimeout> | undefined;
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      const stop = () => {
        if (interrupted) return;
        interrupted = true;
        if (child.pid !== undefined) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Unknown cancellation remains blocking. */ } }
        settlement = setTimeout(() => {
          child.stdout.destroy();
          child.stderr.destroy();
          resolve({ exitCode: null, signal: null, interrupted: true, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
        }, 1000);
      };
      const timer = setTimeout(stop, r.timeoutMs);
      const receive = (target: Buffer[]) => (chunk: Buffer) => {
        length += chunk.length;
        if (length <= 1_000_000) target.push(chunk); else stop();
      };
      child.stdout.on('data', receive(stdout));
      child.stderr.on('data', receive(stderr));
      child.once('error', (error) => { clearTimeout(timer); clearTimeout(settlement); reject(error); });
      child.once('close', (exitCode, signal) => {
        clearTimeout(timer);
        clearTimeout(settlement);
        resolve({ exitCode, signal, interrupted, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') });
      });
    });
  }
}
