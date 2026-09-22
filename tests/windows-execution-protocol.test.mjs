import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parseWindowsCheckObservation, windowsExecutionFailure, executeWindowsCheck } from '../dist/adapters/platform/windows-execution.js';
import { confirmWindowsConsole } from '../dist/adapters/platform/windows-console.js';

test('Windows Open-Parent is a script-scope function available before native cleanup', () => {
  const source = readFileSync(new URL('../assets/platform/windows-execution-native.ps1', import.meta.url), 'utf8');
  const release = source.match(/^function Release-Native \{([\s\S]*?)^\}/mu);
  assert.ok(release, 'The cleanup function must have an explicit script-scope boundary');
  assert.doesNotMatch(release[1], /\bfunction\s+Open-Parent\b/u, 'Parent inspection must not be defined only when cleanup runs');
  assert.match(source.slice(release.index + release[0].length),
    /^\s*function Open-Parent\(\[uint32\]\$processId\) \{/u,
    'Open-Parent must follow the closed cleanup function at script scope');
});

test('Windows empty-job success rechecks the monotonic deadline after exit observation', () => {
  const source = readFileSync(new URL('../assets/platform/windows-check-process.ps1', import.meta.url), 'utf8');
  const success = source.match(/if \(\$pending -eq 0 -and \$pendingError -eq 0\) \{([\s\S]*?)\n {8}\}/u);
  assert.ok(success, 'The empty-job/drained-pipes completion branch must exist');
  assert.match(success[1],
    /GetExitCodeProcess[\s\S]*\n\s*if \(\$watch\.ElapsedMilliseconds -ge \$timeout\) \{ \$interrupted = \$true \}\s+\$quiescent = \$true\s+break\s*$/u,
    'Expiry must be sampled after native exit observation and before the successful break');
  assert.doesNotMatch(success[1], /\$interrupted\s*=\s*\$false/u, 'Observed quiescence cannot clear interruption');
  assert.equal(parseWindowsCheckObservation({
    ok: true, exitCode: 0, interrupted: true, quiescence: 'confirmed', stdout: '', stderr: '',
  }).interrupted, true, 'Even exit zero in an empty job must retain an expired/interrupted result');
});

test('Windows job observations require exact bounded output and observed quiescence', () => {
  const valid = { ok: true, exitCode: 0, interrupted: false, quiescence: 'confirmed', stdout: Buffer.from('real\n').toString('base64'), stderr: '' };
  assert.deepEqual(parseWindowsCheckObservation(valid), {
    exitCode: 0, signal: null, interrupted: false, quiescence: 'confirmed', stdout: 'real\n', stderr: '',
  });
  for (const value of [
    {}, { ...valid, ok: false }, { ...valid, approved: true }, { ...valid, exitCode: null },
    { ...valid, quiescence: 'unconfirmed' }, { ...valid, quiescence: true },
    { ...valid, stdout: 'invalid%%' }, { ...valid, stderr: 'a===' }, { ...valid, exitCode: 2 ** 32 },
    { ...valid, stdout: Buffer.alloc(1_000_001).toString('base64') },
  ]) assert.throws(() => parseWindowsCheckObservation(value), { code: 'effect-outcome-unknown' });
  assert.equal(parseWindowsCheckObservation({ ...valid, exitCode: null, interrupted: true, quiescence: 'unconfirmed' }).interrupted, true);
});

test('Windows execution diagnostics contain only static phases and bounded line numbers', () => {
  assert.equal(windowsExecutionFailure({ phase: 'create', line: 12, message: 'secret path SID ACL' }), 'create; line=12');
  assert.equal(windowsExecutionFailure({ phase: 'secret', line: 20_000 }), 'native-failure');
});

test('console cancellation needs no platform mock or caller approval flag', async () => {
  const signal = AbortSignal.abort();
  assert.equal(await confirmWindowsConsole({ approved: true }, signal), 'cancel');
  assert.equal(await confirmWindowsConsole({
    expiresAt: new Date(Date.now() + 1000).toISOString(), deadlineAt: new Date(Date.now() - 1).toISOString(),
  }, new AbortController().signal), 'cancel');
});

test('Windows native execution cannot be enabled by POSIX platform impersonation', { skip: process.platform === 'win32' }, async () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  try {
    Object.defineProperty(process, 'platform', { value: 'win32' });
    await assert.rejects(executeWindowsCheck({ program: process.execPath, programDigest: `sha256:${'0'.repeat(64)}`, argv: [], cwd: process.cwd(), timeoutMs: 100 }));
  } finally { Object.defineProperty(process, 'platform', descriptor); }
});
