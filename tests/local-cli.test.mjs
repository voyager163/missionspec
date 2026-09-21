import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';

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
