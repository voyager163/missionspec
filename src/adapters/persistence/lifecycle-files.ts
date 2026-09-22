import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { WorkflowError } from '../../application/errors.js';
import { checkPrivatePath } from './filesystem.js';
import { syncWindowsPrivateDirectory, writeWindowsPrivateFile } from '../platform/windows-private-state.js';

export function readPrivateStateFile(filename: string, maxBytes: number): string {
  lstatSync(filename);
  checkPrivatePath(filename, false);
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (before.size > BigInt(maxBytes)) throw new WorkflowError('limit-reached', 'Private state input exceeds its bounded reader.');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    const size = readSync(descriptor, bytes, 0, bytes.length, 0);
    const current = lstatSync(filename, { bigint: true });
    const after = fstatSync(descriptor, { bigint: true });
    if (BigInt(size) !== before.size || before.dev !== current.dev || before.ino !== current.ino ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        after.mtimeNs !== current.mtimeNs || after.ctimeNs !== current.ctimeNs) {
      throw new WorkflowError('stale-revision', 'Private state input changed while being read.');
    }
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, size));
  } finally { closeSync(descriptor); }
}

export function syncStateDirectory(directory: string): void {
  if (process.platform === 'win32') {
    syncWindowsPrivateDirectory(directory, lstatSync(directory, { bigint: true }));
    return;
  }
  const descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

/** Exclusive private creation only. Failed/partial outputs are retained for explicit diagnosis. */
export function writePrivateStateFile(root: string, filename: string, content: string): void {
  checkPrivatePath(path.dirname(filename), true, true);
  if (process.platform === 'win32') {
    const stat = lstatSync(root, { bigint: true });
    writeWindowsPrivateFile({ root, dev: stat.dev, ino: stat.ino }, filename, content);
  } else {
    const descriptor = openSync(filename, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
    syncStateDirectory(path.dirname(filename));
  }
}
