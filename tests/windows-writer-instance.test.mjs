import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, renameSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {
  currentWindowsProcessInstance, ensureWindowsPrivateDirectories, parseWindowsWriterLock,
  removeWindowsPrivateFile, requireWindowsProcessAbsent, windowsPrivateEntries, writeWindowsPrivateFile,
} from '../dist/adapters/platform/windows-private-state.js';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { withEvidencePruneLock, withStateLifecycleLock } from '../dist/adapters/persistence/evidence-files.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { createPrivateFixtureRoot, powershell, removeFixtureRoot } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 240_000 };
const workspaceUrl = new URL('../dist/adapters/filesystem/local-workspace.js', import.meta.url).href;
const evidenceUrl = new URL('../dist/adapters/persistence/evidence-files.js', import.meta.url).href;

function fixture(t) {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  const scope = { root: f.root, dev: f.identity.dev, ino: f.identity.ino };
  ensureWindowsPrivateDirectories(scope, path.join(f.root, '.missionspec', 'evidence'));
  return { ...f, scope, lock: path.join(f.root, '.missionspec', 'transaction.lock') };
}

function owner(instance, extra = {}) {
  return { schemaVersion: 2, transactionId: randomUUID(), pid: instance.pid, nonce: randomUUID(), process: instance, ...extra };
}

function realBirth(pid) {
  return powershell(String.raw`
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
$process = [Diagnostics.Process]::GetProcessById([int]$v.pid)
try {
  [void]$process.Handle
  [Console]::Out.Write((@{pid=$process.Id;birth=$process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(
    [Globalization.CultureInfo]::InvariantCulture)} | ConvertTo-Json -Compress))
} finally { $process.Dispose() }
`, { pid });
}

test('Windows current writer birth is OS-backed, cached per process, and a matching live instance blocks reclaim', windows, (t) => {
  const f = fixture(t);
  const instance = currentWindowsProcessInstance();
  assert.equal(currentWindowsProcessInstance(), instance);
  assert.equal(Object.isFrozen(instance), true);
  assert.deepEqual(realBirth(process.pid), { pid: instance.pid, birth: instance.creationFileTime });
  const content = JSON.stringify(owner(instance));
  const reference = writeWindowsPrivateFile(f.scope, f.lock, content);
  assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, instance), /process-present/u);
  assert.throws(() => requireWindowsProcessAbsent(process.pid), /process-present/u);
  assert.equal(readFileSync(f.lock, 'utf8'), content);
});

test('Windows synthetic stale birth under a real live PID reclaims only the original lock, never the successor process', windows, (t) => {
  const f = fixture(t);
  const live = currentWindowsProcessInstance();
  // Synthetic stale record, not a claim that Windows PID allocation reuse was observed.
  const stale = { ...live, creationFileTime: String(BigInt(live.creationFileTime) - 1n) };
  const content = JSON.stringify(owner(stale));
  const reference = writeWindowsPrivateFile(f.scope, f.lock, content);
  assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, process.pid), /process-present/u);
  removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, stale);
  assert.equal(existsSync(f.lock), false);
  assert.deepEqual(realBirth(process.pid), { pid: live.pid, birth: live.creationFileTime });
  assert.throws(() => requireWindowsProcessAbsent(process.pid), /process-present/u);
  const replacement = writeWindowsPrivateFile(f.scope, f.lock, JSON.stringify(owner(live)));
  assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, stale));
  assert.equal(readFileSync(f.lock, 'utf8').includes(live.creationFileTime), true);
  removeWindowsPrivateFile(f.scope, f.lock, replacement.digest, replacement);
});

test('Windows future, unknown, mismatched and partial process identities fail closed without lock deletion', windows, (t) => {
  const f = fixture(t);
  const live = currentWindowsProcessInstance();
  for (const instance of [{ ...live, creationFileTime: '9223372036854775807' }]) {
    const content = JSON.stringify(owner(instance));
    const reference = writeWindowsPrivateFile(f.scope, f.lock, content);
    assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, instance),
      /process-instance|process-inspection/u);
    assert.equal(readFileSync(f.lock, 'utf8'), content);
    removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference);
  }
  const content = JSON.stringify(owner(live));
  const reference = writeWindowsPrivateFile(f.scope, f.lock, content);
  for (const bad of [{ pid: live.pid }, { ...live, schemaVersion: 3 }, { ...live, creationFileTime: 'unknown' },
    { ...live, extra: true }]) {
    assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference, bad), /process-instance/u);
    assert.equal(readFileSync(f.lock, 'utf8'), content);
  }
  assert.throws(() => removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference,
    { ...live, creationFileTime: String(BigInt(live.creationFileTime) - 1n) }), /writer-lease/u);
});

test('Windows instance-bearing leases survive both dispatch paths and cannot drop or change their process binding', windows, (t) => {
  const f = fixture(t);
  const instance = currentWindowsProcessInstance();
  const reference = writeWindowsPrivateFile(f.scope, f.lock, JSON.stringify(owner(instance)));
  const legacyLease = { path: f.lock, dev: BigInt(reference.device), ino: BigInt(reference.inode), digest: reference.digest };
  const lease = { ...legacyLease, process: instance };
  const target = path.join(f.root, 'admitted');
  windowsPrivateEntries([{ path: f.root, directory: true, writable: true }], lease);
  ensureWindowsPrivateDirectories({ ...f.scope, lease }, target);
  assert.equal(existsSync(target), true);
  const forbidden = path.join(f.root, 'not-admitted');
  for (const supplied of [legacyLease, { ...lease, process: { ...instance, creationFileTime: String(BigInt(instance.creationFileTime) - 1n) } }]) {
    assert.throws(() => windowsPrivateEntries([{ path: forbidden, directory: true, writable: true, create: true }], supplied));
    assert.throws(() => ensureWindowsPrivateDirectories({ ...f.scope, lease: supplied }, forbidden));
    assert.equal(existsSync(forbidden), false);
  }
  removeWindowsPrivateFile(f.scope, f.lock, reference.digest, reference);
  const stale = { ...instance, creationFileTime: String(BigInt(instance.creationFileTime) - 1n) };
  const old = writeWindowsPrivateFile(f.scope, f.lock, JSON.stringify(owner(stale)));
  const staleLease = { path: f.lock, dev: BigInt(old.device), ino: BigInt(old.inode), digest: old.digest, process: stale };
  assert.throws(() => ensureWindowsPrivateDirectories({ ...f.scope, lease: staleLease }, forbidden), /process-instance/u);
  assert.equal(existsSync(forbidden), false);
});

async function initialized(t) {
  const f = fixture(t);
  const files = await LocalWorkspace.open(f.root);
  const workspace = { workspaceId: `WSP-${randomUUID()}`, rootDigest: files.rootDigest };
  writeWindowsPrivateFile(f.scope, path.join(f.root, '.missionspec', 'workspace.json'), JSON.stringify(workspace));
  return { ...f, files, workspace };
}

test('Windows runtime and shared prune/lifecycle locks bind the real instance; legacy live owners and cleanup substitution stay blocked', windows, async (t) => {
  const f = await initialized(t);
  const live = currentWindowsProcessInstance();
  await f.files.withRuntimeLock(async () => {
    const parsed = parseWindowsWriterLock(JSON.parse(readFileSync(f.lock, 'utf8')));
    assert.equal(parsed.kind, 'runtime');
    assert.deepEqual(parsed.process, live);
  });
  assert.equal(existsSync(f.lock), false);
  const id = digestContent('instance-bound shared-lock component test');
  for (const [kind, acquire] of [['evidence-prune', withEvidencePruneLock], ['state-lifecycle', withStateLifecycleLock]]) {
    const legacy = JSON.stringify({ schemaVersion: 1, kind, id, pid: process.pid, nonce: randomUUID() });
    const legacyRef = writeWindowsPrivateFile(f.scope, f.lock, legacy);
    await assert.rejects(acquire(f.files, f.workspace, id, async () => assert.fail('Live legacy writer must block')), { code: 'conflict' });
    assert.equal(readFileSync(f.lock, 'utf8'), legacy);
    removeWindowsPrivateFile(f.scope, f.lock, legacyRef.digest, legacyRef);
    const stale = { ...live, creationFileTime: String(BigInt(live.creationFileTime) - 1n) };
    const previous = JSON.stringify({ schemaVersion: 2, kind, id, pid: process.pid, nonce: randomUUID(), process: stale });
    writeWindowsPrivateFile(f.scope, f.lock, previous);
    const failure = new Error('component callback failure');
    await assert.rejects(acquire(f.files, f.workspace, id, async () => {
      const parsed = parseWindowsWriterLock(JSON.parse(readFileSync(f.lock, 'utf8')));
      assert.equal(parsed.kind, kind);
      assert.equal(parsed.id, id);
      assert.deepEqual(parsed.process, live);
      await assert.rejects(acquire(f.files, f.workspace, id, async () => assert.fail('Concurrent live instance must block')), { code: 'conflict' });
      throw failure;
    }), (error) => error === failure);
    assert.equal(existsSync(f.lock), false);
  }
  let replacement;
  await assert.rejects(withStateLifecycleLock(f.files, f.workspace, id, async () => {
    renameSync(f.lock, `${f.lock}.retained`);
    replacement = JSON.stringify({ schemaVersion: 2, kind: 'state-lifecycle', id, pid: process.pid, nonce: randomUUID(), process: live });
    writeWindowsPrivateFile(f.scope, f.lock, replacement);
  }), { code: 'effect-outcome-unknown' });
  assert.equal(readFileSync(f.lock, 'utf8'), replacement);
});

test('Windows exited child instance locks are reclaimed through the real lifecycle lock path', windows, async (t) => {
  const f = await initialized(t);
  const id = digestContent('real child instance exit');
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { readFileSync } from 'node:fs';
    const { LocalWorkspace } = await import(${JSON.stringify(workspaceUrl)});
    const { withStateLifecycleLock } = await import(${JSON.stringify(evidenceUrl)});
    const input = JSON.parse(readFileSync(0, 'utf8'));
    const files = await LocalWorkspace.open(input.root);
    await withStateLifecycleLock(files, input.workspace, input.id, async () => process.exit(73));
  `], { input: JSON.stringify({ root: f.root, workspace: f.workspace, id }), encoding: 'utf8', timeout: 120_000 });
  assert.equal(child.status, 73);
  const owner = parseWindowsWriterLock(JSON.parse(readFileSync(f.lock, 'utf8')));
  assert.equal(owner.process.pid, child.pid);
  let recovered = false;
  await withStateLifecycleLock(f.files, f.workspace, id, async () => { recovered = true; });
  assert.equal(recovered, true);
  assert.equal(existsSync(f.lock), false);
});
