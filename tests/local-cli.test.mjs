import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';

const executable = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));

async function fixture(t) {
  const root = path.join(process.cwd(), `.local-cli-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const invoke = async (...args) => {
    try {
      const result = await promisify(execFile)(process.execPath, [executable, ...args, '--json'], { cwd: root });
      return { ...result, code: 0, parsed: JSON.parse(result.stdout) };
    } catch (error) { return { ...error, parsed: JSON.parse(error.stdout) }; }
  };
  return { root, invoke };
}

test('local CLI setup, project status, recovery inspection and onboard guidance write no state', async (t) => {
  const { root, invoke } = await fixture(t);
  const status = await invoke('project', 'status');
  assert.equal(status.code, 0);
  assert.equal(status.parsed.value.state, 'not-initialized');
  for (const args of [['init', '--preview'], ['init', '--preview', '--profile', 'compact'], ['recover'], ['recover', '--preview'], ['onboard']]) {
    const result = await invoke(...args);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(result.stderr, '');
    assert.equal(result.parsed.status, 'ok');
  }
  assert.deepEqual(await readdir(root), []);
});

test('local CLI fails closed on mutation attempts, untrusted approval flags and irrelevant options', async (t) => {
  const { root, invoke } = await fixture(t);
  for (const args of [
    ['init'], ['init', '--yes'], ['init', '--approved', 'true'],
    ['status', 'change', '--acceptance', 'sensitive-fixture-marker'],
    ['verify', 'change', '--evidence', 'EVD-a'],
    ['init', '--preview', '--profile', 'sensitive-fixture-marker'],
    ['run', 'CHG-a'], ['change', 'new', 'a', '--preview'],
  ]) {
    const result = await invoke(...args);
    assert.notEqual(result.code, 0, result.stdout);
    assert.equal(result.stderr, '');
    assert.ok(!result.stdout.includes('sensitive-fixture-marker'));
    assert.notEqual(result.parsed.status, 'ok');
  }
  assert.deepEqual(await readdir(root), []);
});

test('state status reports current ledger capacity without creating or modifying state', async (t) => {
  const { root, invoke } = await fixture(t);
  const missing = await invoke('state', 'status');
  assert.notEqual(missing.code, 0);
  assert.equal(missing.parsed.error.code, 'not-found');
  assert.deepEqual(await readdir(root), []);
  const files = await LocalWorkspace.open(root);
  const workspace = { workspaceId: 'WSP-capacity-cli', rootDigest: files.rootDigest };
  await mkdir(path.join(root, '.missionspec'), { mode: 0o700 });
  await writeFile(path.join(root, '.missionspec/workspace.json'), JSON.stringify(workspace), { mode: 0o600 });
  const opened = await openRuntimeStore({
    directory: path.join(root, '.missionspec/state'), mode: 'create', expectedWorkspace: workspace,
  });
  assert.equal(opened.status, 'ok');
  assert.equal(opened.value.close().status, 'ok');
  const filename = path.join(root, '.missionspec/state/ledger.sqlite');
  const before = await stat(filename, { bigint: true });
  const names = await readdir(root, { recursive: true });
  const result = await invoke('state', 'status');
  assert.equal(result.code, 0, result.stdout);
  assert.equal(result.parsed.value.writesPerformed, false);
  assert.equal(result.parsed.value.access, 'read-only');
  assert.equal(result.parsed.value.capacity.reservation, 'none');
  assert.equal(result.parsed.value.capacity.databaseBytes, before.size.toString());
  assert.equal(result.parsed.value.records.runs, 0);
  assert.deepEqual(await readdir(root, { recursive: true }), names);
  const after = await stat(filename, { bigint: true });
  assert.equal(after.mtimeNs, before.mtimeNs);
  assert.equal(after.ctimeNs, before.ctimeNs);
  for (const args of [['state', 'status', '--preview'], ['state', 'status', '--approval', 'APR-fake'], ['state', 'reset']]) {
    const rejected = await invoke(...args);
    assert.notEqual(rejected.code, 0);
    assert.equal(rejected.parsed.error.code, 'invalid-input');
  }
});
