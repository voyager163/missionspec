import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { closeSync, linkSync, lstatSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { readPrivateStateFile } from '../dist/adapters/persistence/lifecycle-files.js';
import { readPrivateBytes, readPrivateSqliteHeader } from '../dist/adapters/persistence/private-reader.js';
import { readWindowsPrivateFile, windowsPrivateEntries, windowsPrivateStateDiagnostic } from '../dist/adapters/platform/windows-private-state.js';
import { failure } from '../dist/adapters/persistence/failures.js';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { checkFiles } from '../dist/adapters/persistence/filesystem.js';
import { windowsFileSecurity } from './fixtures/windows-file-security.mjs';
import { createPrivateFixtureRoot, removeFixtureRoot, profileWindowsHelpers } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 180_000 };
const helper = fileURLToPath(new URL('../assets/platform/windows-private-state.ps1', import.meta.url));
const powerShell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

function fixture(t) {
  const { root, identity } = createPrivateFixtureRoot([
    'private.json', 'private.json.alias', 'private.json.moved', 'replacement.json',
    '.missionspec/state/ledger.sqlite', '.missionspec/state/ledger.sqlite.old',
    '.missionspec/state/ledger.sqlite.alias', '.missionspec/state/ledger.sqlite-journal',
  ]);
  t.after(() => removeFixtureRoot(root, identity));
  const filename = path.join(root, 'private.json');
  windowsPrivateEntries([{ path: filename, directory: false, writable: true, create: true }]);
  const content = JSON.stringify({ marker: 'bounded private UTF-8 \u2603', payload: 'x'.repeat(20_000) });
  writeFileSync(filename, content);
  return { root, filename, content };
}

function sqliteFixture(t) {
  const f = fixture(t);
  for (const directory of ['.missionspec', '.missionspec/state']) {
    windowsPrivateEntries([{ path: path.join(f.root, directory), directory: true, writable: true, create: true }]);
  }
  const filename = path.join(f.root, '.missionspec/state/ledger.sqlite');
  windowsPrivateEntries([{ path: filename, directory: false, writable: true, create: true }]);
  const db = new DatabaseSync(filename, { timeout: 0 });
  db.exec('PRAGMA journal_mode=DELETE; CREATE TABLE sample(value INTEGER); INSERT INTO sample VALUES(1)');
  return { ...f, filename, db, identity: lstatSync(filename, { bigint: true }) };
}

function heldReader(operation) {
  const child = spawn(powerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper],
    { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const closed = once(child, 'close');
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  child.stdin.write(`${JSON.stringify({ operation })}\n`);
  return {
    async next() {
      const line = await lines.next();
      assert.equal(line.done, false, stderr);
      return JSON.parse(line.value);
    },
    proceed() { child.stdin.write('continue\n'); },
    async finish() { return (await closed)[0]; },
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await closed;
    },
  };
}

function headerOperation(f) {
  const root = path.dirname(f.filename);
  const parent = lstatSync(root, { bigint: true });
  return {
    kind: 'sqlite-header', root, rootIdentity: { device: String(parent.dev), inode: String(parent.ino) },
    path: f.filename, expected: { device: String(f.identity.dev), inode: String(f.identity.ino) },
    maxBytes: 100, prefix: true,
  };
}

test('Windows persistence reader returns bounded bytes from the ACL-validated native handle', windows, (t) => {
  const f = fixture(t);
  const before = lstatSync(f.filename, { bigint: true });
  assert.equal(readPrivateStateFile(f.filename, 30_000), f.content);
  assert.deepEqual(readPrivateBytes(f.filename, 100, { expected: before, prefix: true }), Buffer.from(f.content).subarray(0, 100));
  assert.throws(() => readPrivateStateFile(f.filename, 100));
  const replacement = path.join(f.root, 'replacement.json');
  renameSync(f.filename, replacement);
  windowsPrivateEntries([{ path: f.filename, directory: false, writable: true, create: true }]);
  writeFileSync(f.filename, f.content);
  assert.throws(() => readWindowsPrivateFile(f.filename, before, 30_000));
  assert.equal(readFileSync(replacement, 'utf8'), f.content);
  windowsFileSecurity({ path: f.filename, publicRead: true });
  assert.throws(() => readPrivateStateFile(f.filename, 30_000));
});

test('Windows held read excludes competing replacement/writes and rechecks ACL and link admission before bytes', windows, async (t) => {
  for (const mutation of ['rename', 'write', 'links', 'acl']) {
    await t.test(mutation, async (t) => {
      const f = fixture(t);
      const root = lstatSync(f.root, { bigint: true });
      const identity = lstatSync(f.filename, { bigint: true });
      const operation = {
        kind: 'read', root: f.root, rootIdentity: { device: String(root.dev), inode: String(root.ino) },
        path: f.filename, expected: { device: String(identity.dev), inode: String(identity.ino) },
        maxBytes: 30_000, prefix: false,
      };
      const reader = heldReader(operation);
      try {
        assert.deepEqual(await reader.next(), { phase: 'read-held' });
        let changed = false;
        try {
          if (mutation === 'rename') renameSync(f.filename, `${f.filename}.moved`);
          if (mutation === 'write') writeFileSync(f.filename, 'competing writer');
          if (mutation === 'links') linkSync(f.filename, `${f.filename}.alias`);
          if (mutation === 'acl') windowsFileSecurity({ path: f.filename, publicRead: true });
          changed = true;
        } catch (error) {
          if (mutation === 'acl') throw error;
          assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code), error.message);
        }
        if (mutation === 'rename' || mutation === 'write') assert.equal(changed, false);
        reader.proceed();
        const result = await reader.next();
        const code = await reader.finish();
        if (changed) {
          assert.equal(result.ok, false);
          assert.notEqual(code, 0);
          assert.equal(Object.hasOwn(result, 'value'), false);
        } else {
          assert.equal(code, 0);
          assert.equal(result.ok, true);
          assert.equal(Buffer.from(result.value.contentBase64, 'base64').toString(), f.content);
        }
        assert.equal(readFileSync(f.filename, 'utf8'), f.content);
      } finally { await reader.stop(); }
    });
  }
});

test('Windows SQLite header admission coexists with real read/write connections and preserves SQLite contention', windows, async (t) => {
  const f = sqliteFixture(t);
  const second = new DatabaseSync(f.filename, { timeout: 0 });
  try {
    assert.equal(readPrivateSqliteHeader(f.filename, f.identity).subarray(0, 16).toString(), 'SQLite format 3\0');
    assert.throws(() => readPrivateBytes(f.filename, 100, { expected: f.identity, prefix: true }),
      (error) => windowsPrivateStateDiagnostic(error).startsWith('effect-open'));
    const reader = heldReader(headerOperation(f));
    try {
      assert.deepEqual(await reader.next(), { phase: 'read-held' });
      assert.throws(() => second.exec('BEGIN EXCLUSIVE'), (error) => (error.errcode & 255) === 5);
      reader.proceed();
      assert.deepEqual(await reader.next(), { phase: 'sqlite-header-read' });
      reader.proceed();
      const result = await reader.next();
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(await reader.finish(), 0);
    } finally { await reader.stop(); }
    second.exec('BEGIN EXCLUSIVE');
    try {
      assert.throws(() => readPrivateSqliteHeader(f.filename, f.identity),
        (error) => failure(error).error.fields.includes('busy'));
    } finally { second.exec('ROLLBACK'); }
    second.exec('INSERT INTO sample VALUES(2)');
    assert.equal(f.db.prepare('SELECT count(*) AS n FROM sample').get().n, 2);
    assert.equal(readPrivateSqliteHeader(f.filename, f.identity).length, 100);
  } finally { second.close(); f.db.close(); }
});

test('Windows SQLite shared-header mode still refuses in-flight header, ACL and link changes', windows, async (t) => {
  for (const mutation of ['header', 'acl', 'links']) {
    await t.test(mutation, async (t) => {
      const f = sqliteFixture(t);
      f.db.close();
      const descriptor = openSync(f.filename, 'r+');
      const reader = heldReader(headerOperation(f));
      try {
        assert.deepEqual(await reader.next(), { phase: 'read-held' });
        reader.proceed();
        assert.deepEqual(await reader.next(), { phase: 'sqlite-header-read' });
        let changed = false;
        try {
          if (mutation === 'header') writeSync(descriptor, Buffer.from([0xff]), 0, 1, 68);
          if (mutation === 'acl') windowsFileSecurity({ path: f.filename, publicRead: true });
          if (mutation === 'links') linkSync(f.filename, `${f.filename}.alias`);
          changed = true;
        } catch (error) {
          assert.equal(mutation, 'links');
          assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code), error.message);
        }
        reader.proceed();
        const result = await reader.next();
        assert.equal(result.ok, !changed, JSON.stringify(result));
        assert.equal((await reader.finish()) === 0, !changed);
        if (changed) assert.equal(Object.hasOwn(result, 'value'), false);
      } finally { await reader.stop(); closeSync(descriptor); }
    });
  }
});

test('Windows SQLite header admission retains foreign replacements and rejects non-ledger aliases', windows, (t) => {
  const f = sqliteFixture(t);
  f.db.close();
  const saved = `${f.filename}.old`;
  renameSync(f.filename, saved);
  windowsPrivateEntries([{ path: f.filename, directory: false, writable: true, create: true }]);
  writeFileSync(f.filename, readFileSync(saved));
  assert.throws(() => readPrivateSqliteHeader(f.filename, f.identity),
    (error) => windowsPrivateStateDiagnostic(error).startsWith('effect-identity'));
  assert.throws(() => readPrivateSqliteHeader(path.join(f.root, 'private.json'), f.identity));
  assert.throws(() => readPrivateSqliteHeader('\\\\.\\pipe\\missionspec-header-fixture', f.identity));
  const current = lstatSync(f.filename, { bigint: true });
  linkSync(f.filename, `${f.filename}.alias`);
  assert.throws(() => readPrivateSqliteHeader(f.filename, current));
  rmSync(`${f.filename}.alias`);
  assert.equal(readPrivateSqliteHeader(f.filename, current).length, 100);
});

test('Windows private workspace reads validate every private ancestor in one native invocation', windows, async (t) => {
  const f = fixture(t);
  const root = path.join(f.root, '.missionspec');
  const nested = path.join(root, 'nested');
  for (const directory of [root, nested]) {
    windowsPrivateEntries([{ path: directory, directory: true, writable: true, create: true }]);
  }
  const filename = path.join(nested, 'private.json');
  renameSync(f.filename, filename);
  const files = await LocalWorkspace.open(f.root);
  const calls = profileWindowsHelpers(t);
  assert.equal((await files.read('.missionspec/nested/private.json')).content, f.content);
  assert.deepEqual(calls.map((call) => call.kind), ['read']);
  for (const directory of [root, nested]) {
    const saved = windowsFileSecurity({ path: directory, directory: true }).sddl;
    try {
      windowsFileSecurity({ path: directory, directory: true, publicRead: true });
      await assert.rejects(files.read('.missionspec/nested/private.json'));
      await assert.rejects(files.read('.missionspec/nested/missing.json'));
    } finally { windowsFileSecurity({ path: directory, directory: true, restoreSddl: saved }); }
  }
  assert.equal(await files.read('.missionspec/nested/missing.json'), null);
  const identity = lstatSync(filename, { bigint: true });
  const parent = lstatSync(root, { bigint: true });
  const reader = heldReader({
    kind: 'read', root, rootIdentity: { device: String(parent.dev), inode: String(parent.ino) },
    path: filename, expected: { device: String(identity.dev), inode: String(identity.ino) },
    maxBytes: 30_000, prefix: false,
  });
  const saved = windowsFileSecurity({ path: root, directory: true }).sddl;
  try {
    assert.deepEqual(await reader.next(), { phase: 'read-held' });
    windowsFileSecurity({ path: root, directory: true, publicRead: true });
    reader.proceed();
    const result = await reader.next();
    assert.equal(result.ok, false);
    assert.equal(Object.hasOwn(result, 'value'), false);
    assert.notEqual(await reader.finish(), 0);
  } finally {
    await reader.stop();
    windowsFileSecurity({ path: root, directory: true, restoreSddl: saved });
  }
});

test('Windows store checks fuse held header, exact directory identity and writable ACL admission', windows, (t) => {
  const f = sqliteFixture(t);
  const directory = path.dirname(f.filename);
  const files = {
    filename: f.filename, directory, directoryIdentity: lstatSync(directory, { bigint: true }),
    identity: f.identity, writable: true,
  };
  const calls = profileWindowsHelpers(t);
  try {
    checkFiles(files);
    assert.deepEqual(calls.map((call) => call.kind), ['sqlite-header']);
    assert.throws(() => readPrivateSqliteHeader(f.filename, f.identity, {
      directoryIdentity: { dev: files.directoryIdentity.dev, ino: files.directoryIdentity.ino + 1n }, writable: true,
    }), (error) => windowsPrivateStateDiagnostic(error).startsWith('effect-identity'));
    for (const target of [path.dirname(directory), directory]) {
      const saved = windowsFileSecurity({ path: target, directory: true }).sddl;
      try {
        windowsFileSecurity({ path: target, directory: true, publicRead: true });
        assert.throws(() => checkFiles(files));
      } finally { windowsFileSecurity({ path: target, directory: true, restoreSddl: saved }); }
    }
    const saved = windowsFileSecurity({ path: directory, directory: true }).sddl;
    try {
      windowsFileSecurity({ path: directory, directory: true, readOnly: true });
      assert.throws(() => checkFiles(files));
      assert.doesNotThrow(() => checkFiles({ ...files, writable: false }));
    } finally { windowsFileSecurity({ path: directory, directory: true, restoreSddl: saved }); }
    f.db.exec('BEGIN EXCLUSIVE');
    try { assert.throws(() => checkFiles(files), (error) => failure(error).error.fields.includes('busy')); }
    finally { f.db.exec('ROLLBACK'); }
    assert.doesNotThrow(() => checkFiles(files));
  } finally { f.db.close(); }
});
