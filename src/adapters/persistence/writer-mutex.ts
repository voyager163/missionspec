import {
  closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readSync,
  unlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { WorkflowError } from '../../application/errors.js';
import { digestContent } from '../../kernel/revisions.js';
import { checkPrivatePath } from './filesystem.js';
import { checkPosixAncestors, checkPrivateDescriptor, samePrivateObservation } from './private-reader.js';
import { posixDescriptorLock } from '../platform/posix-descriptor-lock.js';

const mutexName = 'writer-mutex.lock';
const bootstrapName = 'writer-mutex.bootstrap';

function sync(directory: string): void {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function exists(filename: string): boolean {
  try { lstatSync(filename); return true; }
  catch (error) {
    if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') return false;
    throw error;
  }
}

function rejectLegacy(directory: string): void {
  if (['', '-journal', '-wal', '-shm'].some((suffix) => exists(path.join(directory, `writer-mutex.sqlite${suffix}`)))) {
    throw new WorkflowError('conflict', 'Experimental SQLite writer-mutex state is not compatible with descriptor locks; preserve it for explicit reconciliation.');
  }
}

function initialize(directory: string, filename: string, content: string): void {
  const candidate = path.join(directory, bootstrapName);
  if (exists(candidate)) throw new WorkflowError('conflict', 'Writer mutex bootstrap is in progress or interrupted; it is never adopted or reset.');
  if (exists(filename)) return;
  let descriptor: number;
  try { descriptor = openSync(candidate, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); }
  catch (error) {
    if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'EEXIST') {
      throw new WorkflowError('conflict', 'Another writer owns mutex bootstrap; retry only after it has completed.');
    }
    throw error;
  }
  let publish = false;
  try {
    // Another initializer may have completed after our first absence check.
    if (!exists(filename)) {
      sync(directory);
      writeFileSync(descriptor, content);
      fsyncSync(descriptor);
      publish = true;
    }
  } finally { closeSync(descriptor); }
  // A complete private object is published without replacing an existing inode.
  // Any interruption retains bootstrap state, including an ambiguous two-link object.
  if (publish) linkSync(candidate, filename);
  unlinkSync(candidate);
  sync(directory);
}

/** A stable inode and one privately held OS descriptor, never SQLite's process-associated record locks. */
export function acquirePosixWriterMutex(root: string, rootDigest: string): () => void {
  if (process.platform === 'win32') return () => {};
  const native = posixDescriptorLock();
  checkPosixAncestors(root);
  const observed = lstatSync(root, { bigint: true });
  if (!observed.isDirectory() || observed.uid !== BigInt(process.getuid!()) || (observed.mode & 0o022n) !== 0n ||
      digestContent(JSON.stringify({ root, device: String(observed.dev), inode: String(observed.ino) })) !== rootDigest) {
    throw new WorkflowError('scope-exceeded', 'Writer mutex requires the independently observed current private workspace root.');
  }
  const directory = path.join(root, '.missionspec');
  try { mkdirSync(directory, { mode: 0o700 }); sync(root); }
  catch (error) {
    if (typeof error !== 'object' || error === null || Reflect.get(error, 'code') !== 'EEXIST') throw error;
  }
  checkPrivatePath(directory, true, true);
  rejectLegacy(directory);
  const filename = path.join(directory, mutexName);
  const content = `${JSON.stringify({ format: 'missionspec-posix-descriptor-mutex', schemaVersion: 1, rootDigest })}\n`;
  initialize(directory, filename, content);
  checkPrivatePath(filename, false, true);
  const before = lstatSync(filename, { bigint: true });
  const parent = lstatSync(directory, { bigint: true });
  const descriptor = openSync(filename, constants.O_RDWR | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let held = false;
  const close = () => {
    let failed = false;
    try { if (held) native.unlock(descriptor); } catch { failed = true; }
    try { closeSync(descriptor); } catch { failed = true; }
    if (failed) throw new WorkflowError('effect-outcome-unknown', 'Native writer-mutex release was not confirmed.');
  };
  try {
    const admitted = fstatSync(descriptor, { bigint: true });
    checkPrivateDescriptor(admitted);
    if (!samePrivateObservation(before, admitted) || (admitted.mode & 0o600n) !== 0o600n) {
      throw new WorkflowError('conflict', 'Writer mutex changed before descriptor admission.');
    }
    try { held = native.tryLock(descriptor); }
    catch {
      throw new WorkflowError('capability-unavailable', 'The local filesystem cannot grant the qualified native descriptor lock; no fallback is attempted.');
    }
    if (!held) throw new WorkflowError('conflict', 'Another descriptor holds the workspace writer mutex.');
    const bytes = Buffer.alloc(Buffer.byteLength(content) + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(descriptor, bytes, length, bytes.length - length, length);
      if (read === 0) break;
      length += read;
    }
    const after = fstatSync(descriptor, { bigint: true });
    const current = lstatSync(filename, { bigint: true });
    checkPrivateDescriptor(after);
    checkPrivateDescriptor(current);
    checkPrivatePath(directory, true, true);
    const currentParent = lstatSync(directory, { bigint: true });
    if (!samePrivateObservation(admitted, after) || !samePrivateObservation(after, current) ||
        parent.dev !== currentParent.dev || parent.ino !== currentParent.ino ||
        BigInt(length) !== after.size || !bytes.subarray(0, length).equals(Buffer.from(content))) {
      throw new WorkflowError('conflict', 'The existing writer mutex is foreign, partial, replaced or incompatible; it is never initialized or reset.');
    }
    rejectLegacy(directory);
    // Also cover observing another initializer between publication and its barrier.
    fsyncSync(descriptor);
    sync(directory);
  } catch (error) { close(); throw error; }
  let released = false;
  return () => {
    if (released) return;
    released = true;
    close();
  };
}
