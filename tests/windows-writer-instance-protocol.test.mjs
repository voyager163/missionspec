import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { parseWindowsProcessInstance, parseWindowsWriterLock } from '../dist/adapters/platform/windows-private-state.js';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { withEvidencePruneLock, withStateLifecycleLock } from '../dist/adapters/persistence/evidence-files.js';
import { digestContent } from '../dist/kernel/revisions.js';

const instance = { schemaVersion: 1, pid: 123, creationFileTime: '134000000000000000' };
const transactionId = '00000000-0000-4000-8000-000000000000';
const nonce = '00000000-0000-4000-8000-000000000001';

test('Windows writer process tuples are closed canonical FILETIME data, never an inferred clock or PID alone', () => {
  assert.deepEqual(parseWindowsProcessInstance(instance), instance);
  assert.equal(Object.isFrozen(parseWindowsProcessInstance(instance)), true);
  let getterCalls = 0;
  const getter = { ...instance };
  Object.defineProperty(getter, 'creationFileTime', { get() { getterCalls++; return instance.creationFileTime; } });
  for (const value of [null, {}, [], getter, { ...instance, extra: true }, { ...instance, schemaVersion: 2 },
    { ...instance, pid: '123' }, { ...instance, pid: 0 }, { ...instance, pid: 2147483648 }, { ...instance, pid: 1.5 },
    ...[undefined, null, 134000000000000000, '', 'unknown', '0', '1', '0134000000000000000', '-1',
      '134000000000000000 ', '9223372036854775808'].map((creationFileTime) => ({ ...instance, creationFileTime }))]) {
    assert.throws(() => parseWindowsProcessInstance(value), /process-instance/u);
  }
  assert.equal(getterCalls, 0);
});

test('Windows lock versions require exact process, PID, scope and nonce fields without upgrading legacy locks', () => {
  const id = digestContent('prune fixture');
  const variants = [{ transactionId, pid: 123 }, { kind: 'runtime', pid: 123 },
    ...['evidence-prune', 'state-lifecycle'].map((kind) => ({ schemaVersion: 1, kind, id, pid: 123, nonce }))];
  for (const legacy of variants) {
    assert.equal(parseWindowsWriterLock(legacy).process, undefined);
    const modern = { ...legacy, schemaVersion: 2, nonce, process: instance };
    assert.deepEqual(parseWindowsWriterLock(modern).process, instance);
    for (const bad of [{ ...modern, process: undefined }, { ...modern, schemaVersion: 3 }, { ...modern, extra: true },
      { ...modern, nonce: 'not-a-nonce' }, { ...modern, process: { ...instance, pid: 124 } },
      { ...legacy, process: instance }]) assert.throws(() => parseWindowsWriterLock(bad));
    const missing = { ...modern };
    delete missing.pid;
    assert.throws(() => parseWindowsWriterLock(missing));
  }
});

test('POSIX transaction, runtime and shared prune/lifecycle lock bytes retain their existing formats and cleanup', {
  skip: process.platform === 'win32',
}, async (t) => {
  const root = path.resolve(`.writer-instance-posix-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  // Component approval only; not terminal or human-presence qualification.
  const authority = await openLocalAuthority({ directory: root, transport: {
    channel: 'trusted-callback', protocolIdentity: { id: 'test.writer-format', version: '1' },
    async confirm() { return 'accept'; },
  } });
  const workflow = await LocalWorkflow.open(root, { authority });
  const setup = await workflow.previewSetup();
  const issued = await authority.confirmPlan(setup);
  assert.equal(issued.status, 'ok');
  const lock = path.join(root, '.missionspec', 'transaction.lock');
  let observed = false;
  const files = await LocalWorkspace.open(root, { authority, beforeEffects: async () => {
    const owner = JSON.parse(await readFile(lock, 'utf8'));
    assert.deepEqual(Object.keys(owner), ['transactionId', 'pid']);
    assert.equal(owner.pid, process.pid);
    observed = true;
  } });
  await files.commit(setup, issued.value.approval.reference);
  assert.equal(observed, true);
  await files.withRuntimeLock(async () => {
    assert.deepEqual(JSON.parse(await readFile(lock, 'utf8')), { kind: 'runtime', pid: process.pid });
  });
  await mkdir(path.join(root, '.missionspec', 'evidence'), { mode: 0o700 });
  const workspace = await files.identity();
  const id = digestContent('shared-lock-format');
  for (const [kind, acquire] of [['evidence-prune', withEvidencePruneLock], ['state-lifecycle', withStateLifecycleLock]]) {
    const failure = new Error('component-operation-failed');
    await assert.rejects(acquire(files, workspace, id, async () => {
      const owner = JSON.parse(await readFile(lock, 'utf8'));
      assert.deepEqual(Object.keys(owner), ['schemaVersion', 'kind', 'id', 'pid', 'nonce']);
      assert.equal(owner.schemaVersion, 1);
      assert.equal(owner.kind, kind);
      assert.equal(owner.id, id);
      assert.equal(owner.pid, process.pid);
      throw failure;
    }), (error) => error === failure);
    assert.equal((await readdir(path.dirname(lock))).includes('transaction.lock'), false);
  }
});
