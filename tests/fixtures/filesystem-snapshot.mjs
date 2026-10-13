import fs from 'node:fs';
import path from 'node:path';

const metadataFields = ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'];
const defaultMaxBytes = 64 * 1024 * 1024;
const readFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0);

export class FixtureSnapshotChangedError extends Error {
  constructor() { super('Fixture changed during snapshot'); }
}

function unchanged(before, after) {
  if (metadataFields.some((field) => before[field] !== after[field])) {
    throw new FixtureSnapshotChangedError();
  }
}

// These observers measure deliberately insecure fixtures too: permissions and link
// counts are evidence, not a private-file admission policy. Each call opens anew.
// O_NOFOLLOW protects only the basename where supported. Node does not provide
// portable handle-relative traversal: ancestor replacement/ABA is not excluded by
// these endpoint checks, nor are these observers a production security boundary.
export function fixtureFileSnapshot(filename, { maxBytes = defaultMaxBytes, expected } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new Error('Invalid fixture read limit');
  const descriptor = fs.openSync(filename, readFlags);
  try {
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.size < 0n || stat.size > BigInt(maxBytes)) {
      throw new Error('Unexpected fixture file type or size');
    }
    if (expected !== undefined) unchanged(expected, stat);
    unchanged(stat, fs.lstatSync(filename, { bigint: true }));
    const bytes = Buffer.alloc(Number(stat.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, Math.min(bytes.length - offset, 65_536), offset);
      if (count === 0) throw new FixtureSnapshotChangedError();
      offset += count;
    }
    unchanged(stat, fs.fstatSync(descriptor, { bigint: true }));
    unchanged(stat, fs.lstatSync(filename, { bigint: true }));
    return { stat, bytes };
  } finally {
    fs.closeSync(descriptor);
  }
}

export function fixtureTreeSnapshot(filename, { validateEntry, ...options } = {}) {
  const stat = fs.lstatSync(filename, { bigint: true });
  validateEntry?.(filename, stat);
  if (stat.isFile()) return fixtureFileSnapshot(filename, { ...options, expected: stat });
  if (stat.isSymbolicLink()) {
    const link = fs.readlinkSync(filename);
    unchanged(stat, fs.lstatSync(filename, { bigint: true }));
    if (fs.readlinkSync(filename) !== link) throw new FixtureSnapshotChangedError();
    unchanged(stat, fs.lstatSync(filename, { bigint: true }));
    return { stat, link };
  }
  if (!stat.isDirectory()) throw new Error('Unexpected fixture entry type');
  const names = fs.readdirSync(filename).sort();
  const entries = Object.fromEntries(names.map((name) => [
    name, fixtureTreeSnapshot(path.join(filename, name), { ...options, validateEntry }),
  ]));
  const currentNames = fs.readdirSync(filename).sort();
  if (names.length !== currentNames.length || names.some((name, index) => name !== currentNames[index])) {
    throw new FixtureSnapshotChangedError();
  }
  unchanged(stat, fs.lstatSync(filename, { bigint: true }));
  return { stat, entries };
}

const describeEntry = (name, stat, contents) => [
  name, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs, contents, stat.mode, stat.dev, stat.nlink,
];

export function fixtureInventory(root, encodeBytes, describe = describeEntry) {
  function entries(snapshot) {
    return Object.entries(snapshot.entries).map(([name, entry]) => describe(name, entry.stat,
      entry.entries !== undefined ? entries(entry) :
        entry.link !== undefined ? { link: entry.link } : encodeBytes(entry.bytes)));
  }
  return entries(fixtureTreeSnapshot(root));
}
