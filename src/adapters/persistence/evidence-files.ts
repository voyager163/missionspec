import {
  closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync, type BigIntStats,
} from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { LocalWorkspace } from '../filesystem/local-workspace.js';
import { observeWorkspaceRoot, windowsIoDetail } from '../filesystem/local-workspace.js';
import { WorkflowError } from '../../application/errors.js';
import { digestContent, parseDigest, sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../../kernel/revisions.js';
import { integer, oneOf, record, text } from '../../kernel/validation.js';
import type { EvidencePruneObservation, EvidencePruneTarget } from '../../ports/evidence-pruning.js';
import { parsePruneTarget } from './pruning.js';
import { requireSupportedPlatform } from './filesystem.js';
import { acquirePosixWriterMutex } from './writer-mutex.js';
import { checkPosixAncestors, readPrivateBytes, samePrivateObservation } from './private-reader.js';
import { readPrivateStateFile, writePrivateStateFile } from './lifecycle-files.js';
import {
  inspectWindowsPrivateFile, removeWindowsPrivateFile, syncWindowsPrivateDirectory, windowsPrivateEntries, writeWindowsPrivateFile,
  currentWindowsProcessInstance, parseWindowsWriterLock,
  type WindowsFileScope, type WindowsWriterLease,
} from '../platform/windows-private-state.js';

const windowsLeases = new WeakMap<LocalWorkspace, WindowsWriterLease>();
const posixJobs = new WeakMap<LocalWorkspace, ContentDigest>();

function windowsScope(files: LocalWorkspace, lease = true): WindowsFileScope {
  const root = lstatSync(files.root, { bigint: true });
  if (!root.isDirectory() || root.isSymbolicLink() ||
      digestContent(JSON.stringify({ root: files.root, device: String(root.dev), inode: String(root.ino) })) !== files.rootDigest) {
    throw new WorkflowError('scope-exceeded', 'Evidence workspace identity changed before native admission.');
  }
  const held = lease ? windowsLeases.get(files) : undefined;
  return { root: files.root, dev: root.dev, ino: root.ino, ...(held === undefined ? {} : { lease: held }) };
}

function missing(error: unknown): boolean {
  return typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT';
}

function privateEntry(stat: BigIntStats, directory: boolean): void {
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) ||
      (process.platform !== 'win32' && (stat.uid !== BigInt(process.getuid!()) || (stat.mode & 0o077n) !== 0n)) ||
      (!directory && stat.nlink !== 1n)) {
    throw new WorkflowError('scope-exceeded', 'Pruning requires real owner-only directories and ordinary single-link private evidence files.');
  }
}

function sameIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

async function scope(files: LocalWorkspace, expected: WorkspaceBinding, area: 'evidence' | 'lifecycle' = 'evidence'): Promise<string> {
  requireSupportedPlatform();
  const observed = await observeWorkspaceRoot(files.root);
  const identity = await files.identity();
  const root = lstatSync(files.root, { bigint: true });
  if (identity === null || !sameWorkspaceBinding(identity, expected) || expected.rootDigest !== observed.rootDigest ||
      files.rootDigest !== observed.rootDigest ||
      (process.platform !== 'win32' && (root.uid !== BigInt(process.getuid!()) || (root.mode & 0o022n) !== 0n))) {
    throw new WorkflowError('scope-exceeded', 'Evidence pruning must bind the independently observed, private current workspace root.');
  }
  privateEntry(lstatSync(path.join(files.root, '.missionspec'), { bigint: true }), true);
  const directory = area === 'evidence' ? path.join(files.root, '.missionspec', 'evidence') : path.join(files.root, '.missionspec');
  privateEntry(lstatSync(directory, { bigint: true }), true);
  if (process.platform !== 'win32') checkPosixAncestors(directory);
  if (process.platform === 'win32') {
    windowsPrivateEntries([
      { path: files.root, directory: true, writable: true },
      { path: path.join(files.root, '.missionspec'), directory: true, writable: true },
      { path: directory, directory: true, writable: true },
    ]);
  }
  return directory;
}

function syncDirectory(directory: string): void {
  if (process.platform === 'win32') {
    try { syncWindowsPrivateDirectory(directory, lstatSync(directory, { bigint: true })); } catch {
      throw new WorkflowError('effect-outcome-unknown', 'Evidence directory durability was not confirmed; its prepared job must remain recoverable.');
    }
    return;
  }
  const descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

function reclaimDeadPruneLock(filename: string, id: ContentDigest, kind: 'evidence-prune' | 'state-lifecycle', reclaim = true): void {
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor, { bigint: true });
    privateEntry(stat, false);
    if (stat.size > 2048n) throw new WorkflowError('conflict', 'Writer lock is not a bounded prune lock.');
    const bytes = Buffer.alloc(Number(stat.size));
    if (readSync(descriptor, bytes, 0, bytes.length, 0) !== bytes.length) {
      throw new WorkflowError('conflict', 'Writer lock changed while being observed.');
    }
    const owner = record(JSON.parse(bytes.toString('utf8')) as unknown, 'prune.lock', ['schemaVersion', 'kind', 'id', 'pid', 'nonce']);
    if (owner.schemaVersion !== 1 || owner.kind !== kind || parseDigest(owner.id) !== id) {
      throw new WorkflowError('conflict', 'Only the exact reviewed prune job can recover its own abandoned writer lock.');
    }
    text(owner.nonce, 'prune.lock.nonce', 80);
    const pid = integer(owner.pid, 'prune.lock.pid', 1, 2147483647);
    let dead = false;
    try { process.kill(pid, 0); } catch (error) {
      dead = typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ESRCH';
    }
    if (!dead) throw new WorkflowError('conflict', 'The prune writer may still be alive; its lock cannot be removed.');
    const current = lstatSync(filename, { bigint: true });
    if (!sameIdentity(stat, current) || stat.mtimeNs !== current.mtimeNs || stat.ctimeNs !== current.ctimeNs) {
      throw new WorkflowError('conflict', 'Writer lock changed before explicit recovery.');
    }
    if (reclaim) {
      unlinkSync(filename);
      syncDirectory(path.dirname(filename));
    }
  } finally { closeSync(descriptor); }
}

/** Same fixed cooperative lock as LocalWorkspace, with a prune-specific crash-recovery identity. */
export async function withEvidencePruneLock<T>(
  files: LocalWorkspace, workspace: WorkspaceBinding, id: ContentDigest, operation: () => Promise<T>,
): Promise<T> {
  return withPrivateStateLock(files, workspace, id, 'evidence-prune', operation);
}

export async function withStateLifecycleLock<T>(
  files: LocalWorkspace, workspace: WorkspaceBinding, id: ContentDigest, operation: () => Promise<T>,
): Promise<T> {
  return withPrivateStateLock(files, workspace, id, 'state-lifecycle', operation);
}

async function withPrivateStateLock<T>(
  files: LocalWorkspace, workspace: WorkspaceBinding, id: ContentDigest,
  kind: 'evidence-prune' | 'state-lifecycle', operation: () => Promise<T>,
): Promise<T> {
  parseDigest(id);
  await scope(files, workspace, kind === 'evidence-prune' ? 'evidence' : 'lifecycle');
  const filename = path.join(files.root, '.missionspec', 'transaction.lock');
  const writer = process.platform === 'win32' ? currentWindowsProcessInstance() : undefined;
  const lockContent = JSON.stringify({ schemaVersion: writer === undefined ? 1 : 2, kind, id, pid: process.pid, nonce: randomUUID(),
    ...(writer === undefined ? {} : { process: writer }) });
  if (process.platform === 'win32') {
    let old: string | undefined;
    try { old = readPrivateStateFile(filename, 2048); } catch (error) { if (!missing(error)) throw error; }
    if (old !== undefined) {
      try {
        const owner = parseWindowsWriterLock(JSON.parse(old) as unknown);
        if (owner.kind !== kind || owner.id !== id) throw new Error('Writer lock scope differs');
        const previous = inspectWindowsPrivateFile(windowsScope(files, false), filename);
        if (previous.digest !== digestContent(old)) throw new Error('Writer changed');
        removeWindowsPrivateFile(windowsScope(files, false), filename, previous.digest, previous, owner.process ?? owner.pid);
      } catch (error) {
        throw new WorkflowError('conflict', `The prune writer is live, unknown, or changed; its lock is retained. ${windowsIoDetail(error)}`);
      }
    }
    const owned = writeWindowsPrivateFile(windowsScope(files, false), filename, lockContent);
    windowsLeases.set(files, { path: filename, dev: BigInt(owned.device), ino: BigInt(owned.inode), digest: owned.digest,
      ...(writer === undefined ? {} : { process: writer }) });
    try {
      if ((await files.pending()).length !== 0) throw new WorkflowError('conflict', 'Pending file transactions block pruning.');
      return await operation();
    } finally {
      windowsLeases.delete(files);
      try { removeWindowsPrivateFile(windowsScope(files, false), filename, owned.digest, owned); }
      catch (error) {
        throw new WorkflowError('effect-outcome-unknown', `Prune lock release was not confirmed; reconcile its durable state. ${windowsIoDetail(error)}`);
      }
    }
  }
  // A live/foreign legacy owner blocks even first-time mutex provisioning.
  if (maybeStat(filename) !== undefined) reclaimDeadPruneLock(filename, id, kind, false);
  const releaseMutex = acquirePosixWriterMutex(files.root, files.rootDigest);
  try {
    let descriptor: number;
    const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW;
    try { descriptor = openSync(filename, flags, 0o600); } catch (error) {
      if (typeof error !== 'object' || error === null || Reflect.get(error, 'code') !== 'EEXIST') throw error;
      reclaimDeadPruneLock(filename, id, kind);
      descriptor = openSync(filename, flags, 0o600);
    }
    let identity: BigIntStats;
    try {
      writeFileSync(descriptor, lockContent);
      fsyncSync(descriptor);
      identity = fstatSync(descriptor, { bigint: true });
      syncDirectory(path.dirname(filename));
    } finally { closeSync(descriptor); }
    try {
      if (kind === 'evidence-prune') posixJobs.set(files, id);
      if ((await files.pending()).length !== 0) throw new WorkflowError('conflict', 'Pending file transactions block pruning.');
      return await operation();
    } finally {
      posixJobs.delete(files);
      const current = lstatSync(filename, { bigint: true });
      privateEntry(current, false);
      if (!sameIdentity(identity, current) || identity.mtimeNs !== current.mtimeNs || identity.ctimeNs !== current.ctimeNs) {
        throw new WorkflowError('effect-outcome-unknown', 'Prune writer lock changed; no unrelated lock is removed.');
      }
      unlinkSync(filename);
      syncDirectory(path.dirname(filename));
    }
  } finally { releaseMutex(); }
}

function readExact(directory: string, item: EvidencePruneTarget, allowAbsent: boolean) {
  const target = path.join(directory, `${item.id}.json`);
  let descriptor: number;
  let entry: BigIntStats;
  try {
    entry = lstatSync(target, { bigint: true });
    privateEntry(entry, false);
    if (process.platform === 'win32') {
      const bytes = readPrivateBytes(target, 8_000_000, { expected: entry });
      if (digestContent(bytes) !== item.rawDigest) throw new WorkflowError('stale-revision', 'Raw evidence digest changed.');
      return { descriptor: undefined, identity: entry, target, bytes };
    }
    descriptor = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (missing(error) && allowAbsent) return null;
    if (missing(error)) throw new WorkflowError('evidence-unavailable', 'Raw evidence is missing; it cannot be newly prepared for pruning.');
    throw error;
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    privateEntry(before, false);
    if (!samePrivateObservation(entry, before)) {
      throw new WorkflowError('stale-revision', 'Raw evidence changed before descriptor admission; an identical replacement is not the observed object.');
    }
    if (before.size > 8_000_000n) throw new WorkflowError('limit-reached', 'Raw evidence exceeds the bounded pruning reader.');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (read === 0) break;
      length += read;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(target, { bigint: true });
    privateEntry(current, false);
    if (BigInt(length) !== before.size || !sameIdentity(before, current) ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        after.mtimeNs !== current.mtimeNs || after.ctimeNs !== current.ctimeNs ||
        digestContent(bytes.subarray(0, length)) !== item.rawDigest) {
      throw new WorkflowError('stale-revision', 'Raw evidence changed; preserve the user edit and do not unlink it.');
    }
    return { descriptor, identity: current, target, bytes: bytes.subarray(0, length) };
  } catch (error) {
    closeSync(descriptor);
    throw error;
  }
}

/** Narrow trusted composition only: no arbitrary private path, approval, or deletion API is exported publicly. */
export async function inspectPrunableEvidence(
  files: LocalWorkspace, workspace: WorkspaceBinding, value: EvidencePruneTarget, allowAbsent = false,
): Promise<EvidencePruneObservation | null> {
  const item = parsePruneTarget(value);
  const opened = readExact(await scope(files, workspace), item, allowAbsent);
  if (opened === null) return null;
  try {
    const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(opened.bytes);
    const envelope = record(JSON.parse(content) as unknown, 'prune.rawEvidence', ['schemaVersion', 'evidenceId', 'basis', 'result', 'output']);
    if (envelope.schemaVersion !== 1 || envelope.evidenceId !== item.id || typeof envelope.output !== 'string') {
      throw new WorkflowError('evidence-unavailable', 'Pruning requires a valid original evidence observation envelope.');
    }
    return {
      evidenceId: item.id,
      basis: oneOf(envelope.basis, ['executed', 'static-inspection', 'agent-review'], 'prune.rawEvidence.basis'),
      result: oneOf(envelope.result, ['passed', 'failed'], 'prune.rawEvidence.result'),
      outputDigest: digestContent(envelope.output),
    };
  } finally { if (opened.descriptor !== undefined) closeSync(opened.descriptor); }
}

export class EvidenceQuarantineFailure extends WorkflowError {
  constructor(readonly retainedPath: string) {
    super('effect-outcome-unknown', `Evidence quarantine is unresolved; retain and inspect ${retainedPath}. No automatic restoration or overwrite is allowed.`);
  }
}

const identityKeys = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'] as const;
type CapturedIdentity = Record<typeof identityKeys[number], string>;

function capturedIdentity(stat: BigIntStats): CapturedIdentity {
  return Object.fromEntries(identityKeys.map((key) => [key, String(stat[key])])) as CapturedIdentity;
}

function parseCapturedIdentity(value: unknown): CapturedIdentity {
  const input = record(value, 'quarantine.identity', identityKeys);
  for (const key of identityKeys) {
    if (typeof input[key] !== 'string' || !/^[0-9]{1,30}$/u.test(input[key])) {
      throw new WorkflowError('conflict', 'Quarantine identity is malformed; preserve all retained files.');
    }
  }
  return input as CapturedIdentity;
}

function matchesCapture(stat: BigIntStats, expected: CapturedIdentity, moved = false): boolean {
  return identityKeys.every((key) => moved && key === 'ctimeNs' || String(stat[key]) === expected[key]);
}

function maybeStat(filename: string): BigIntStats | undefined {
  try { return lstatSync(filename, { bigint: true }); } catch (error) { if (missing(error)) return undefined; throw error; }
}

function quarantineDirectory(directory: string): BigIntStats {
  try { mkdirSync(directory, { mode: 0o700 }); syncDirectory(path.dirname(directory)); }
  catch (error) {
    if (typeof error !== 'object' || error === null || Reflect.get(error, 'code') !== 'EEXIST') throw error;
  }
  const stat = lstatSync(directory, { bigint: true });
  privateEntry(stat, true);
  checkPosixAncestors(directory);
  return stat;
}

function captureBytes(descriptor: number, expected: CapturedIdentity, digest: ContentDigest): BigIntStats {
  const before = fstatSync(descriptor, { bigint: true });
  privateEntry(before, false);
  if (!matchesCapture(before, expected, true) || before.size > 8_000_000n) throw new Error('Captured object differs');
  const bytes = Buffer.alloc(Number(before.size) + 1);
  let length = 0;
  while (length < bytes.length) {
    const count = readSync(descriptor, bytes, length, bytes.length - length, length);
    if (count === 0) break;
    length += count;
  }
  const after = fstatSync(descriptor, { bigint: true });
  privateEntry(after, false);
  if (!samePrivateObservation(before, after) || BigInt(length) !== after.size ||
      digestContent(bytes.subarray(0, length)) !== digest) throw new Error('Captured bytes differ');
  return after;
}

/** The only POSIX unlink is inside a job-owned private UUID namespace while the stable kernel mutex is held. */
function quarantinePreparedEvidence(files: LocalWorkspace, workspace: WorkspaceBinding, item: EvidencePruneTarget, directory: string):
  'removed' | 'already-absent' {
  const job = posixJobs.get(files);
  if (job === undefined) throw new WorkflowError('conflict', 'Evidence quarantine requires the current exact-job kernel writer lease.');
  const base = path.join(files.root, '.missionspec', 'prune-quarantine');
  quarantineDirectory(base);
  const jobDirectory = path.join(base, job.slice(7));
  const jobIdentity = quarantineDirectory(jobDirectory);
  const sourceParent = lstatSync(directory, { bigint: true });
  if (jobIdentity.dev !== sourceParent.dev) throw new WorkflowError('scope-exceeded', 'Evidence quarantine must be on the same volume.');
  const intentPath = path.join(jobDirectory, `${item.id}.intent.json`);
  const deletedPath = path.join(jobDirectory, `${item.id}.deleted.json`);
  const source = path.join(directory, `${item.id}.json`);
  let intentContent: string;
  try { intentContent = readPrivateStateFile(intentPath, 16_384); }
  catch (error) {
    if (!missing(error)) throw error;
    if (maybeStat(deletedPath) !== undefined) throw new EvidenceQuarantineFailure(deletedPath);
    const original = readExact(directory, item, true);
    if (original === null || original.descriptor === undefined) throw new EvidenceQuarantineFailure(intentPath);
    try {
      const nonce = randomUUID();
      const captureDirectory = path.join(jobDirectory, nonce);
      // No existing UUID directory is ever adopted for a new intent.
      mkdirSync(captureDirectory, { mode: 0o700 });
      syncDirectory(jobDirectory);
      intentContent = JSON.stringify({
        schemaVersion: 1, job, workspace, target: item, nonce,
        directory: capturedIdentity(lstatSync(captureDirectory, { bigint: true })),
        original: capturedIdentity(original.identity),
      });
      writePrivateStateFile(files.root, intentPath, intentContent);
    } finally { closeSync(original.descriptor); }
  }
  const intent = record(JSON.parse(intentContent) as unknown, 'quarantine.intent',
    ['schemaVersion', 'job', 'workspace', 'target', 'nonce', 'directory', 'original']);
  if (intent.schemaVersion !== 1 || intent.job !== job || JSON.stringify(intent.workspace) !== JSON.stringify(workspace) ||
      JSON.stringify(intent.target) !== JSON.stringify(item) || typeof intent.nonce !== 'string' ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(intent.nonce)) {
    throw new EvidenceQuarantineFailure(intentPath);
  }
  const expected = parseCapturedIdentity(intent.original);
  const expectedDirectory = parseCapturedIdentity(intent.directory);
  const captureDirectory = path.join(jobDirectory, intent.nonce);
  const captured = path.join(captureDirectory, 'captured');
  const verifyDirectories = () => {
    checkPosixAncestors(captureDirectory);
    const current = lstatSync(captureDirectory, { bigint: true });
    privateEntry(current, true);
    const currentJob = lstatSync(jobDirectory, { bigint: true });
    const currentSource = lstatSync(directory, { bigint: true });
    privateEntry(currentSource, true);
    if (String(current.dev) !== expectedDirectory.dev || String(current.ino) !== expectedDirectory.ino ||
        current.mode.toString() !== expectedDirectory.mode || current.uid.toString() !== expectedDirectory.uid ||
        !sameIdentity(currentJob, jobIdentity) || !sameIdentity(currentSource, sourceParent)) {
      throw new EvidenceQuarantineFailure(captured);
    }
  };
  verifyDirectories();
  const receiptContent = JSON.stringify({ schemaVersion: 1, job, target: item.id, intentDigest: digestContent(intentContent), state: 'deleted' });
  if (maybeStat(deletedPath) !== undefined) {
    if (readPrivateStateFile(deletedPath, 16_384) !== receiptContent || maybeStat(captured) !== undefined ||
        maybeStat(source) !== undefined) throw new EvidenceQuarantineFailure(captured);
    return 'already-absent';
  }
  if (maybeStat(captured) === undefined) {
    // Absence alone cannot distinguish a completed delete from lost/tampered
    // state. Only an unchanged pre-move object permits resuming an intent.
    const sourceStat = maybeStat(source);
    if (sourceStat === undefined || !matchesCapture(sourceStat, expected)) throw new EvidenceQuarantineFailure(captured);
    const original = readExact(directory, item, false);
    if (original === null || original.descriptor === undefined) throw new EvidenceQuarantineFailure(captured);
    try {
      if (!matchesCapture(original.identity, expected)) throw new EvidenceQuarantineFailure(captured);
      verifyDirectories();
      if (maybeStat(captured) !== undefined) throw new EvidenceQuarantineFailure(captured);
      renameSync(source, captured);
      syncDirectory(directory);
      syncDirectory(captureDirectory);
      // The rename may have captured a replacement, not the descriptor we
      // inspected. Never delete until the actual moved object is admitted.
      if (!sameIdentity(fstatSync(original.descriptor, { bigint: true }), lstatSync(captured, { bigint: true }))) {
        throw new EvidenceQuarantineFailure(captured);
      }
    } catch {
      throw new EvidenceQuarantineFailure(captured);
    } finally { closeSync(original.descriptor); }
  }
  let descriptor: number | undefined;
  try {
    verifyDirectories();
    const entry = lstatSync(captured, { bigint: true });
    privateEntry(entry, false);
    if (!matchesCapture(entry, expected, true)) throw new EvidenceQuarantineFailure(captured);
    descriptor = openSync(captured, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const admitted = captureBytes(descriptor, expected, item.rawDigest);
    if (!samePrivateObservation(entry, admitted)) throw new EvidenceQuarantineFailure(captured);
    verifyDirectories();
    const current = lstatSync(captured, { bigint: true });
    const held = fstatSync(descriptor, { bigint: true });
    privateEntry(current, false);
    privateEntry(held, false);
    if (!samePrivateObservation(admitted, current) || !samePrivateObservation(current, held)) throw new EvidenceQuarantineFailure(captured);
    unlinkSync(captured);
    syncDirectory(captureDirectory);
    writePrivateStateFile(files.root, deletedPath, receiptContent);
    return 'removed';
  } catch {
    throw new EvidenceQuarantineFailure(captured);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

export async function removePreparedEvidence(
  files: LocalWorkspace, workspace: WorkspaceBinding, value: EvidencePruneTarget,
): Promise<'removed' | 'already-absent'> {
  const item = parsePruneTarget(value);
  const directory = await scope(files, workspace);
  if (process.platform !== 'win32') return quarantinePreparedEvidence(files, workspace, item, directory);
  const parent = lstatSync(directory, { bigint: true });
  const opened = readExact(directory, item, true);
  if (opened === null) {
    if (process.platform === 'win32') syncWindowsPrivateDirectory(directory, parent);
    return 'already-absent';
  }
  if (process.platform === 'win32') {
    try {
      const reference = inspectWindowsPrivateFile(windowsScope(files), opened.target);
      if (reference.device !== String(opened.identity.dev) || reference.inode !== String(opened.identity.ino) || reference.digest !== item.rawDigest) {
        throw new WorkflowError('stale-revision', 'Evidence changed before native deletion admission.');
      }
      removeWindowsPrivateFile(windowsScope(files), opened.target, item.rawDigest, reference);
      return 'removed';
    } finally { if (opened.descriptor !== undefined) closeSync(opened.descriptor); }
  }
  throw new WorkflowError('capability-unavailable', 'No qualified evidence deletion protocol.');
}
