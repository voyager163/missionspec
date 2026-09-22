import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import {
  copyFileSync, existsSync, lstatSync, readFileSync, realpathSync, renameSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { executeWindowsCheck, windowsExecutionAsset, windowsPowerShell } from '../dist/adapters/platform/windows-execution.js';
import { requireWindowsProcessAbsent, windowsPrivateEntries, WindowsPrivateStateError } from '../dist/adapters/platform/windows-private-state.js';
import { createPrivateFixtureRoot, powershell, removeFixtureRoot } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 240_000 };
const digest = (filename) => `sha256:${createHash('sha256').update(readFileSync(filename)).digest('hex')}`;
function fixture(t) {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  const program = realpathSync.native(process.execPath);
  return { ...f, input: { program, programDigest: digest(program), cwd: f.root, timeoutMs: 10_000 } };
}
async function observedPids(root) {
  const filename = path.join(root, 'owned-pids.json');
  const limit = Date.now() + 60_000;
  while (!existsSync(filename) && Date.now() < limit) await delay(50);
  assert.ok(existsSync(filename), 'The actual owned child and descendant must start before cancellation');
  const pids = JSON.parse(readFileSync(filename, 'utf8'));
  assert.equal(pids.length, 2);
  for (const pid of pids) assert.ok(Number.isSafeInteger(pid) && pid > 0);
  return pids;
}
const descendants = `
const fs = require('node:fs');
const child = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 100)'], { stdio: 'ignore', detached: true });
fs.writeFileSync('owned-pids.json', JSON.stringify([process.pid, child.pid]));
setInterval(() => {}, 100);
`;

test('Windows execution asset preflight validates the real OS host without private entries', { ...windows, timeout: 60_000 }, () => {
  assert.throws(() => windowsPrivateEntries([]), WindowsPrivateStateError, 'The private-entry contract must still reject empty input');
  for (const name of ['windows-console.ps1', 'windows-check-process.ps1']) {
    assert.equal(windowsExecutionAsset(name), path.resolve('assets/platform', name));
  }
  const systemRoot = process.env.SystemRoot;
  try {
    process.env.SystemRoot = 'C:\\not-the-reviewed-system';
    assert.throws(() => windowsExecutionAsset('windows-console.ps1'), /system-executable/u);
    assert.throws(() => windowsExecutionAsset('windows-check-process.ps1'), /system-executable/u);
  } finally {
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
  }
});

test('Windows dot-sourced parent inspection is callable before any cleanup', windows, () => {
  const result = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | Microsoft.PowerShell.Utility\ConvertFrom-Json
. ([string]$request.helper)
try {
  $command = Get-Command Open-Parent -CommandType Function -ErrorAction Stop
  $parent = Open-Parent ([uint32]$request.parent)
  if ($native::WaitForSingleObject($parent, 0) -ne 258) { throw 'parent-not-alive' }
  [Console]::Out.Write('{"callableBeforeCleanup":true,"parentAlive":true}')
} finally { Release-Native }
`, { helper: path.resolve('assets/platform/windows-execution-native.ps1'), parent: process.pid });
  assert.deepEqual(result, { callableBeforeCleanup: true, parentAlive: true });
});

test('Windows owned job preserves exact CRT argv, bounded streams, exit and sanitized environment', windows, async (t) => {
  const f = fixture(t);
  const values = ['', 'two words', '"quoted"', 'ends\\', 'before\\"after', 'a\\\\\\"b', '& | % ! $ ;', '\u00e9 \ud83d\ude80'];
  const previous = process.env.MISSIONSPEC_TEST_INHERIT;
  process.env.MISSIONSPEC_TEST_INHERIT = 'must-not-reach-check';
  try {
    const result = await executeWindowsCheck({ ...f.input, argv: ['-e',
      'console.log(JSON.stringify({argv:process.argv.slice(1),secret:process.env.MISSIONSPEC_TEST_INHERIT??null})); console.error("actual stderr");process.exitCode=5;', '--', ...values] });
    assert.deepEqual(JSON.parse(result.stdout), { argv: values, secret: null });
    assert.equal(result.stderr, 'actual stderr\n');
    assert.equal(result.exitCode, 5);
    assert.equal(result.interrupted, false);
    assert.equal(result.quiescence, 'confirmed');
  } finally {
    if (previous === undefined) delete process.env.MISSIONSPEC_TEST_INHERIT;
    else process.env.MISSIONSPEC_TEST_INHERIT = previous;
  }
});

test('Windows job waits for detached ordinary descendants after the root exits', windows, async (t) => {
  const f = fixture(t);
  const result = await executeWindowsCheck({ ...f.input, argv: ['-e', `
    const child = require('node:child_process').spawn(process.execPath,
      ['-e', 'setTimeout(() => require("node:fs").writeFileSync("descendant-finished", "done"), 750)'],
      { detached: true, stdio: 'ignore' });
    console.log(child.pid); child.unref();
  `] });
  assert.equal(result.exitCode, 0);
  assert.equal(result.interrupted, false);
  assert.equal(result.quiescence, 'confirmed');
  assert.equal(readFileSync(path.join(f.root, 'descendant-finished'), 'utf8'), 'done');
  requireWindowsProcessAbsent(Number(result.stdout.trim()));
});

test('Windows timeout terminates the owned job but never becomes passing evidence', windows, async (t) => {
  const f = fixture(t);
  const result = await executeWindowsCheck({ ...f.input, timeoutMs: 2000, argv: ['-e', descendants] });
  assert.equal(result.interrupted, true);
  assert.equal(result.quiescence, 'confirmed');
  for (const pid of await observedPids(f.root)) requireWindowsProcessAbsent(pid);
});

test('Windows aggregate output bound stops an actual noisy job', windows, async (t) => {
  const f = fixture(t);
  const result = await executeWindowsCheck({ ...f.input, argv: ['-e',
    'process.stdout.write("x".repeat(1_500_000));process.stderr.write("y".repeat(1_500_000));setInterval(()=>{},100);'] });
  assert.equal(result.interrupted, true);
  assert.equal(result.quiescence, 'confirmed');
  assert.equal(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr), 1_000_000);
});

test('Windows cancellation closes the sole job handle and reports unknown instead of invented quiescence', windows, async (t) => {
  const f = fixture(t);
  const abort = new AbortController();
  t.after(() => abort.abort());
  const pending = executeWindowsCheck({ ...f.input, timeoutMs: 60_000, argv: ['-e', descendants] }, abort.signal);
  const failure = assert.rejects(pending, { code: 'effect-outcome-unknown' });
  const pids = await observedPids(f.root);
  abort.abort();
  await failure;
  for (const pid of pids) requireWindowsProcessAbsent(pid);
});

test('Windows parent death is observed and owned ordinary descendants cannot outlive the supervisor', windows, async (t) => {
  const f = fixture(t);
  const owner = spawn(process.execPath, [path.resolve('tests/fixtures/windows-check-owner.mjs'), f.root], { stdio: ['ignore', 'pipe', 'pipe'] });
  let diagnostics = '';
  owner.stderr.on('data', (chunk) => { diagnostics += chunk; });
  const closed = once(owner, 'close');
  t.after(() => { if (owner.exitCode === null && owner.signalCode === null) owner.kill(); });
  const pids = await observedPids(f.root);
  assert.ok(owner.kill(), diagnostics);
  await closed;
  await delay(1500);
  for (const pid of pids) requireWindowsProcessAbsent(pid);
});

test('Windows executable preimage and held executable/cwd reject concurrent replacement', windows, async (t) => {
  const f = fixture(t);
  await assert.rejects(executeWindowsCheck({ ...f.input, programDigest: `sha256:${'0'.repeat(64)}`, argv: ['-e', 'process.exit(0)'] }),
    { code: 'effect-outcome-unknown' });
  const program = path.join(f.root, 'selected program.exe');
  copyFileSync(f.input.program, program);
  const programDigest = digest(program);
  const abort = new AbortController();
  t.after(() => abort.abort());
  const pending = executeWindowsCheck({ ...f.input, program, programDigest, timeoutMs: 60_000, argv: ['-e', descendants] }, abort.signal);
  const failure = assert.rejects(pending, { code: 'effect-outcome-unknown' });
  const pids = await observedPids(f.root);
  try {
    assert.throws(() => writeFileSync(program, 'unreviewed executable'));
    assert.throws(() => renameSync(program, path.join(f.root, 'replaced.exe')));
    assert.throws(() => renameSync(f.root, `${f.root}-moved`));
    assert.equal(digest(program), programDigest);
  } finally { abort.abort(); await failure; }
  for (const pid of pids) requireWindowsProcessAbsent(pid);
});

test('Windows owned job does not grant CREATE_BREAKAWAY_FROM_JOB', windows, async (t) => {
  const f = fixture(t);
  windowsExecutionAsset('windows-check-process.ps1');
  t.diagnostic(`Fixed OS host: canonicalSpelling=${realpathSync.native(windowsPowerShell) === windowsPowerShell}; links=${lstatSync(windowsPowerShell).nlink}`);
  // Fixed machine-host validation does not prove an ordinary, single-link image.
  // Keep the held canonical Node image as the check and launch the fixed probe
  // as its real ordinary descendant, which must inherit the same job.
  const result = await executeWindowsCheck({ ...f.input, argv: ['-e', `
    const result = require('node:child_process').spawnSync(process.argv[1],
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', process.argv[2],
        '-Program', process.argv[3], '-WorkingDirectory', process.cwd()],
      { encoding: 'utf8', shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    process.stdout.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    if (result.error || result.signal || result.status !== 0) throw new Error('breakaway-probe-failed');
  `, '--', windowsPowerShell, path.resolve('tests/fixtures/windows-breakaway.ps1'), f.input.program] });
  const failure = result.stdout.match(/^WINDOWS_BREAKAWAY_FAILURE:\{"phase":"(bootstrap|control-create|breakaway-create)","line":([0-9]{1,4}),"nativeStatus":(-?[0-9]{1,10})\}$/u);
  assert.equal(result.exitCode, 0, failure
    ? `breakaway phase=${failure[1]}; line=${failure[2]}; nativeStatus=${failure[3]}`
    : `breakaway helper failed; stderrPresent=${result.stderr.length !== 0}`);
  assert.equal(result.interrupted, false);
  assert.equal(result.stdout, 'breakaway-denied');
  assert.equal(result.quiescence, 'confirmed');
});
