import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, type BigIntStats } from 'node:fs';
import path from 'node:path';
import { StoreFailure } from './failures.js';
import { readWindowsPrivateFile, readWindowsSqliteHeader, type WindowsSqliteStoreAdmission } from '../platform/windows-private-state.js';

export function checkPosixAncestors(directory: string): void {
  let current = path.parse(directory).root;
  let parentWritable = false;
  for (const part of ['', ...directory.slice(current.length).split(path.sep).filter(Boolean)]) {
    if (part) current = path.join(current, part);
    const stat = lstatSync(current);
    const trustedOwner = stat.uid === 0 || stat.uid === process.getuid?.();
    const writable = (stat.mode & 0o022) !== 0;
    const sticky = (stat.mode & 0o1000) !== 0 && trustedOwner;
    if (!stat.isDirectory() || stat.isSymbolicLink() || writable && !sticky || parentWritable && !trustedOwner) {
      throw new StoreFailure('unavailable', 'Private reads require real trusted ancestors; writable ancestors require protected sticky ownership.');
    }
    parentWritable = writable;
  }
}

export function checkPrivateDescriptor(stat: BigIntStats): void {
  if (!stat.isFile() || stat.nlink !== 1n || stat.uid !== BigInt(process.getuid!()) ||
      (stat.mode & 0o077n) !== 0n || (stat.mode & 0o400n) === 0n) {
    throw new StoreFailure('unavailable', 'Private input requires a current-user-owned, owner-readable, single-link owner-only regular descriptor.');
  }
}

export function samePrivateObservation(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size &&
    left.mode === right.mode && left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

/** Admission precedes every read; O_NONBLOCK prevents FIFO substitution from hanging admission. */
export function readPrivateBytes(filename: string, maxBytes: number, options: {
  readonly expected?: { readonly dev: bigint; readonly ino: bigint };
  readonly prefix?: boolean;
  readonly privateRoot?: string;
} = {}): Buffer {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 8_000_000) {
    throw new StoreFailure('capacity', 'Private reader requires an explicit bounded byte limit.');
  }
  const initial = lstatSync(filename, { bigint: true });
  if (options.expected !== undefined && (initial.dev !== options.expected.dev || initial.ino !== options.expected.ino)) {
    throw new StoreFailure('stale-revision', 'Private input differs from its expected identity.');
  }

  if (process.platform === 'win32') return readWindowsPrivateFile(filename, initial, maxBytes, options.prefix === true, options.privateRoot);
  checkPosixAncestors(path.dirname(filename));
  checkPrivateDescriptor(initial);
  const parent = lstatSync(path.dirname(filename), { bigint: true });
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor, { bigint: true });
    checkPrivateDescriptor(before);
    if (!samePrivateObservation(initial, before)) throw new StoreFailure('stale-revision', 'Private input changed before descriptor admission.');
    if (!options.prefix && before.size > BigInt(maxBytes)) throw new StoreFailure('capacity', 'Private input exceeds its bounded reader.');
    const bytes = Buffer.alloc(options.prefix ? maxBytes : Number(before.size) + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    checkPrivateDescriptor(after);
    const current = lstatSync(filename, { bigint: true });
    checkPrivateDescriptor(current);
    checkPosixAncestors(path.dirname(filename));
    const currentParent = lstatSync(path.dirname(filename), { bigint: true });
    if (!samePrivateObservation(before, after) || !samePrivateObservation(after, current) ||
        parent.dev !== currentParent.dev || parent.ino !== currentParent.ino ||
        BigInt(length) !== (options.prefix && before.size > BigInt(maxBytes) ? BigInt(maxBytes) : before.size)) {
      throw new StoreFailure('stale-revision', 'Private input changed while held and read.');
    }
    return bytes.subarray(0, length);
  } finally { closeSync(descriptor); }
}

/** Only the SQLite admission path may share with existing read/write database handles. */
export function readPrivateSqliteHeader(filename: string, expected: { readonly dev: bigint; readonly ino: bigint },
  store?: WindowsSqliteStoreAdmission): Buffer {
  if (process.platform === 'win32') return readWindowsSqliteHeader(filename, expected, store);
  return readPrivateBytes(filename, 100, { expected, prefix: true });
}
