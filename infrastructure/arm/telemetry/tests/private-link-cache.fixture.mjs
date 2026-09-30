import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { constants, closeSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs';
import { lstat, mkdir, open, readFile, readdir, rename, rmdir, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as pause } from 'node:timers/promises';

const memory = new Map();
const stats = { builds: 0, hits: 0, workerHits: 0 };
const hash = value => createHash('sha256').update(value).digest('hex');
const maximumBytes = 64 * 1024 * 1024;
let scope;
function directoryIdentity(info, named, ownerOnly) {
  assert(info.isDirectory() && named.isDirectory() && !named.isSymbolicLink() &&
    ['dev', 'ino', 'uid', 'gid', 'mode'].every(key => info[key] === named[key]) &&
    (ownerOnly ? info.uid === process.getuid() && (info.mode & 0o7777) === 0o700
      : [0, process.getuid()].includes(info.uid) && (info.mode & 0o022) === 0),
  'Unit cache directory ownership, permissions or identity is unsafe.');
}
export async function verifyPrivateLinkCacheAncestors(path, ownerOnly = false) {
  const absolute = resolve(path), paths = [];
  for (let current = absolute; ; current = dirname(current)) {
    paths.unshift(current);
    if (dirname(current) === current) break;
  }
  for (const current of paths) {
    const handle = await open(current, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      directoryIdentity(await handle.stat(), await lstat(current), ownerOnly && current === absolute);
    } finally { await handle.close(); }
  }
  return absolute;
}
export async function verifyPrivateLinkCacheContention(path) {
  try { await verifyPrivateLinkCacheAncestors(path, true); return true; }
  catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}
function verifyPrivateDirectorySync(path) {
  const handle = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { directoryIdentity(fstatSync(handle), lstatSync(path), true); }
  finally { closeSync(handle); }
}
async function privateStorageParent(here) {
  await verifyPrivateLinkCacheAncestors(here);
  const operatorPrivate = join(dirname(here), '.operator-private');
  const parent = join(operatorPrivate, 'private-link-test-cache');
  for (const directory of [operatorPrivate, parent]) {
    await mkdir(directory, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
    await verifyPrivateLinkCacheAncestors(directory, true);
  }
  return parent;
}
function absentOkay(operation, fallback) {
  try { return operation(); } catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}
function immutable(value, seen = new Set()) {
  if (value && typeof value === 'object' && !seen.has(value)) {
    seen.add(value);
    for (const entry of Object.values(value)) immutable(entry, seen);
    Object.freeze(value);
  }
  return value;
}
function exactJson(value) {
  const bytes = JSON.stringify(value);
  assert.deepEqual(JSON.parse(bytes), value, 'Only lossless generated JSON can identify a test-cache entry.');
  return bytes;
}

// Only sibling Node test workers share setup: parent birth time and source bytes
// isolate each run. Production validators and effect ports never use this cache.
async function workerScope() {
  if (process.env.NODE_TEST_CONTEXT !== 'child-v8' || !['linux', 'darwin'].includes(process.platform)) return null;
  if (!scope) scope = (async () => {
    const here = dirname(fileURLToPath(import.meta.url)), source = createHash('sha256');
    const parentDirectory = await privateStorageParent(here);
    for (const directory of [dirname(here), here]) {
      for (const name of (await readdir(directory)).sort()) if (/\.(?:mjs|py)$/u.test(name)) {
        source.update(name).update(await readFile(join(directory, name)));
      }
    }
    for (const path of ['assets/schemas/telemetry-event.schema.json', 'services/telemetry-ingest/schema/storage-columns.json']) {
      source.update(path).update(await readFile(new URL(`../../../../${path}`, import.meta.url)));
    }
    const started = execFileSync('ps', ['-p', String(process.ppid), '-o', 'lstart='], { encoding: 'utf8', timeout: 1000 }).trim();
    assert(started, 'Test-runner birth time must be observable.');
    const root = join(parentDirectory, `run-${hash(JSON.stringify({
      parent: process.ppid, started, source: source.digest('hex'), node: process.version,
    }))}`);
    const worker = join(root, `worker-${process.pid}`), lifecycle = root + '.lifecycle', until = performance.now() + 30000;
    while (true) {
      try { await mkdir(lifecycle, { mode: 0o700 }); break; }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        await verifyPrivateLinkCacheContention(lifecycle);
        assert(performance.now() < until, 'Unit fixture lifecycle lock is bounded.'); await pause(10);
      }
    }
    try {
      await verifyPrivateLinkCacheAncestors(lifecycle, true);
      await mkdir(root, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
      await verifyPrivateLinkCacheAncestors(root, true);
      await writeFile(worker, '', { mode: 0o600, flag: 'wx' });
    } finally { await rmdir(lifecycle); }
    process.once('exit', () => {
      verifyPrivateDirectorySync(parentDirectory);
      verifyPrivateDirectorySync(root);
      absentOkay(() => unlinkSync(worker));
      try { mkdirSync(lifecycle, { mode: 0o700 }); }
      catch (error) {
        if (error.code === 'EEXIST') { absentOkay(() => verifyPrivateDirectorySync(lifecycle)); return; }
        throw error;
      }
      try {
        const names = absentOkay(() => readdirSync(root), []);
        if (names.some(name => name.startsWith('worker-'))) return;
        for (const name of names) {
          const path = join(root, name);
          if (/^[0-9a-f]{64}\.(?:json|pending-\d+)$/u.test(name) && absentOkay(() => lstatSync(path).isFile(), false)) {
            absentOkay(() => unlinkSync(path));
          }
        }
        if (absentOkay(() => readdirSync(root), []).length === 0) absentOkay(() => rmdirSync(root));
      } finally { rmdirSync(lifecycle); }
    });
    return root;
  })();
  return scope;
}
async function readEntry(path, key) {
  await verifyPrivateLinkCacheAncestors(dirname(path), true);
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  try {
    const before = await handle.stat({ bigint: true });
    assert(before.isFile() && before.nlink === 1n && before.uid === BigInt(process.getuid()) &&
      (before.mode & 0o777n) === 0o600n && before.size <= BigInt(maximumBytes));
    const bytes = await handle.readFile(), after = await handle.stat({ bigint: true });
    for (const field of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(after[field], before[field]);
    assert.equal(BigInt(bytes.length), before.size);
    const entry = JSON.parse(bytes);
    assert.equal(entry.key, key); assert.equal(typeof entry.payload, 'string'); assert.equal(entry.sha256, hash(entry.payload));
    return immutable(JSON.parse(entry.payload));
  } finally { await handle.close(); }
}
async function sharedSetup(root, key, build) {
  const path = join(root, `${key}.json`), lock = join(root, `${key}.lock`), until = performance.now() + 300000;
  while (true) {
    const prior = await readEntry(path, key);
    if (prior !== null) { stats.workerHits++; return prior; }
    try { await mkdir(lock, { mode: 0o700 }); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      await verifyPrivateLinkCacheContention(lock);
      assert(performance.now() < until, 'Unit fixture construction exceeded its bounded cache wait.');
      await pause(25); continue;
    }
    const pending = join(root, `${key}.pending-${process.pid}`);
    try {
      const ready = await readEntry(path, key);
      if (ready !== null) { stats.workerHits++; return ready; }
      stats.builds++;
      const result = immutable(structuredClone(await build())), payload = exactJson(result);
      const bytes = JSON.stringify({ key, sha256: hash(payload), payload });
      assert(Buffer.byteLength(bytes) <= maximumBytes);
      await writeFile(pending, bytes, { mode: 0o600, flag: 'wx' });
      await rename(pending, path);
      return result;
    } finally {
      await unlink(pending).catch(error => { if (error.code !== 'ENOENT') throw error; });
      await rmdir(lock);
    }
  }
}

// No IO closures or earlier-run receipts are cached. Every consumer gets a clone.
export async function privateLinkCachedFixture(namespace, input, build) {
  assert(/^[a-z-]+$/u.test(namespace));
  const key = hash(exactJson({ namespace, input }));
  let pending = memory.get(key);
  if (!pending) {
    pending = (async () => {
      const root = await workerScope();
      if (root) return sharedSetup(root, key, build);
      stats.builds++;
      const result = immutable(structuredClone(await build()));
      exactJson(result);
      return result;
    })();
    memory.set(key, pending);
    pending.catch(() => { memory.delete(key); });
  } else stats.hits++;
  return structuredClone(await pending);
}
export function privateLinkFixtureCacheStats() { return { ...stats }; }
export async function privateLinkFixtureCacheDirectory() { return workerScope(); }
