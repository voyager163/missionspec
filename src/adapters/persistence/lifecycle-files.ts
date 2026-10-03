import { closeSync, constants, fsyncSync, lstatSync, openSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { checkPrivatePath } from './filesystem.js';
import { readPrivateBytes } from './private-reader.js';
import { syncWindowsPrivateDirectory, writeWindowsPrivateFile } from '../platform/windows-private-state.js';

export function readPrivateStateFile(filename: string, maxBytes: number): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(readPrivateBytes(filename, maxBytes));
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
