import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { runCli } from '../dist/cli/main.js';

async function invoke(args) {
  let stdout = '';
  let stderr = '';
  const code = await runCli(args, {
    stdout: (value) => { stdout += value; },
    stderr: (value) => { stderr += value; },
  });
  return { code, stdout, stderr };
}

test('development CLI lists all twelve sources without claiming runtime support', async () => {
  const result = await invoke(['skills', 'list', '--json']);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  const output = JSON.parse(result.stdout);
  assert.equal(output.value.skills.length, 12);
  assert(output.value.skills.every((skill) => skill.sourceAvailable && !skill.executionAvailable));
  const capabilities = JSON.parse((await invoke(['capabilities', '--json', '--no-telemetry'])).stdout).value;
  assert.equal(capabilities.executionAvailable, false);
  assert.equal(capabilities.approvalIssuanceAvailable, true);
  assert.equal(capabilities.approvalChannel, 'interactive-local-terminal-only');
  assert(capabilities.hosts.every((host) => host.qualifiedVersions.length === 0));
});

test('render is a read-only content projection, not an installation', async () => {
  const result = await invoke(['skills', 'render', '--host', 'codex', '--operation', 'draft', '--json']);
  assert.equal(result.code, 0);
  const output = JSON.parse(result.stdout).value;
  assert.equal(output.path, '.agents/skills/missionspec-draft/SKILL.md');
  assert(output.content.includes('$missionspec-draft'));
  assert.equal(output.installed, false);
  assert.equal(output.hostQualified, false);
});

test('unimplemented operations are explicitly blocked rather than simulated', async () => {
  const result = await invoke(['run', 'CHG-example', '--json']);
  assert.equal(result.code, 2);
  assert.equal(JSON.parse(result.stdout).status, 'blocked');
  assert.equal(JSON.parse(result.stdout).error.code, 'host-unqualified');
});

test('bad CLI options never echo sensitive input and JSON errors stay parseable', async () => {
  for (const args of [
    ['--password', 'sensitive-fixture-marker', '--json'],
    ['skills', 'render', '--operation', 'draft', '--json'],
    ['capabilities', '--host', 'codex', '--json']
  ]) {
    const result = await invoke(args);
    assert.equal(result.code, 1);
    assert(!result.stdout.includes('sensitive-fixture-marker'));
    assert(!result.stderr.includes('sensitive-fixture-marker'));
    assert.equal(JSON.parse(result.stdout).status, 'failed');
  }
});

test('metadata commands work outside the checkout without creating project/user state', async (context) => {
  const cwd = await mkdtemp(path.join(os.tmpdir(), 'missionspec-cli-'));
  context.after(() => rm(cwd, { recursive: true, force: true }));
  const entry = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
  const { stdout, stderr } = await promisify(execFile)(process.execPath, [entry, 'capabilities', '--json'], {
    cwd,
    env: { ...process.env, HOME: cwd, USERPROFILE: cwd, XDG_CONFIG_HOME: cwd, APPDATA: cwd },
  });
  assert.equal(JSON.parse(stdout).status, 'ok');
  assert.equal(stderr, '');
  assert.deepEqual(await readdir(cwd), []);
});

test('real CLI telemetry controls persist the sole preference without an endpoint or incidental project state', async (context) => {
  const cwd = await mkdtemp(path.join(process.cwd(), '.cli-controls-'));
  context.after(() => rm(cwd, { recursive: true, force: true }));
  const entry = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
  const env = { ...process.env, MISSIONSPEC_CONFIG_HOME: path.join(cwd, 'private-preferences') };
  for (const key of ['CI', 'NODE_ENV', 'NODE_TEST_CONTEXT', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY']) delete env[key];
  const call = async (action) => JSON.parse((await promisify(execFile)(process.execPath,
    [entry, 'telemetry', action, '--json'], { cwd, env })).stdout);
  if (process.platform === 'win32') {
    await assert.rejects(call('status'), (error) => JSON.parse(error.stdout).status === 'blocked');
    await assert.rejects(call('off'), (error) => JSON.parse(error.stdout).status === 'blocked');
    assert.equal((await call('preview')).value.delivery, 'not-attempted');
    assert.deepEqual(await readdir(cwd), []);
    return;
  }
  const status = await call('status');
  assert.equal(status.value.configured, false);
  assert.deepEqual(await readdir(cwd), []);
  const preview = await call('preview');
  assert.equal(preview.value.delivery, 'not-attempted');
  assert.deepEqual(await readdir(cwd), []);
  assert.equal((await call('off')).status, 'ok');
  assert.equal((await call('status')).value.preference, 'disabled');
  assert.equal((await call('on')).status, 'ok');
  const enabled = await call('status');
  assert.equal(enabled.value.preference, 'enabled');
  assert.equal(enabled.value.configured, false);
  assert.deepEqual(await readdir(cwd), ['private-preferences']);
  assert.deepEqual(await readdir(path.join(cwd, 'private-preferences')), ['telemetry.sqlite']);
});
