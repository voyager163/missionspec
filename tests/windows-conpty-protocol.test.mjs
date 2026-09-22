import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { conptyDiagnostic, parseConptyChild, parseConptyDriver } from './fixtures/windows-conpty-protocol.mjs';

const driverMarker = 'MISSIONSPEC_CONPTY_DRIVER:';
const childResult = 'WINDOWS_CONSOLE_RESULT:{"decision":"decline"}\r\n';
const complete = (overrides = {}) => ({
  ok: true, code: 0, challenges: 1, parentKilled: false, jobEmpty: false, output: childResult, ...overrides,
});
const result = (frame, overrides = {}) => ({
  status: 0, signal: null, stdout: `${driverMarker}${JSON.stringify(frame)}\r\n`, stderr: '', ...overrides,
});

test('ConPTY driver requires one isolated native frame, never raw or prefixed child JSON', () => {
  assert.deepEqual(parseConptyChild(parseConptyDriver(result(complete()))), { decision: 'decline' });
  for (const stdout of [
    childResult, childResult + result(complete()).stdout, result(complete()).stdout.repeat(2),
    '{"ok":true}', `${driverMarker}{invalid}\n`,
  ]) assert.throws(() => parseConptyDriver(result(complete(), { stdout })), /ConPTY (?:driver-protocol-contamination|invalid-driver-json)/u);
  assert.throws(() => parseConptyDriver(result(complete(), { status: 1 })), /driver-exit-or-stderr/u);
  assert.throws(() => parseConptyDriver(result(complete(), { stderr: 'unexpected native failure' })), /driver-exit-or-stderr/u);
  assert.throws(() => parseConptyDriver(result(complete({ accepted: true }))), /invalid-driver-frame/u);
});

test('ConPTY native failures retain bounded diagnostics even on nonzero exit and protocol contamination', () => {
  const failure = { ok: false, phase: 'create', reason: 'stdio-clear', line: 85, output: '' };
  assert.throws(() => parseConptyDriver(result(failure, { status: 1 })),
    /native-driver-failure; phase=create; reason=stdio-clear; line=85/u);
  const childFailure = 'WINDOWS_CONSOLE_FAILURE:{"stage":"component","code":"capability-unavailable","native":"pipe; line=34"}\n';
  assert.throws(() => parseConptyDriver(result(failure, { status: 1, stdout: childFailure + result(failure).stdout })),
    /driver-protocol-contamination; .*stage=component.*native=pipe; line=34/u);
  assert.throws(() => parseConptyChild(parseConptyDriver(result(complete({
    code: 1, output: '\u001b]0;Windows PowerShell\u0007\u001b[?25l' + childFailure,
  })))), /child-exit; stage=component; code=capability-unavailable; native=pipe; line=34/u);
});

test('ConPTY title-only, malformed, duplicate and failure-shaped child results never pass', () => {
  for (const output of [
    '\u001b]0;Windows PowerShell\u0007\u001b[?25l', childResult.repeat(2),
    'WINDOWS_CONSOLE_RESULT:{invalid}', 'WINDOWS_CONSOLE_RESULT:true',
    'WINDOWS_CONSOLE_FAILURE:{"stage":"confirmation","actual":"unavailable","expected":"declined"}\n' + childResult,
  ]) assert.throws(() => parseConptyChild(parseConptyDriver(result(complete({ output })))), /ConPTY /u);
  assert.equal(conptyDiagnostic({ phase: 'private path', line: -1, stdout: 'raw private SID/ACL',
    output: 'WINDOWS_CONSOLE_FAILURE:{"stage":"stdio-probe","inputType":3,"outputType":2,"inputMode":0,"outputMode":3,"message":"private SID/ACL"}' }),
  'stage=stdio-probe; inputType=3; outputType=2; inputMode=0; outputMode=3');
});

test('ConPTY fixture clears inherited redirection only around its own native child launch', () => {
  const source = readFileSync(new URL('./fixtures/windows-conpty.ps1', import.meta.url), 'utf8');
  assert.match(source, /\$standardIds = @\(-10, -11, -12\)/u);
  const clear = source.indexOf('$conpty::SetStdHandle($id, [IntPtr]::Zero)');
  const create = source.indexOf('$native::CreateProcessW');
  const restore = source.indexOf('$conpty::SetStdHandle($standardIds[$index], $standardHandles[$index])');
  assert.ok(clear >= 0 && create > clear && restore > create);
  assert.match(source.slice(create, restore), /\} finally \{/u);
  assert.match(source, /\$protocolOutput\.WriteLine\(\('MISSIONSPEC_CONPTY_DRIVER:'/u);
});

test('Breakaway fixture proves the same command works normally before asserting flag refusal', () => {
  const source = readFileSync(new URL('./fixtures/windows-breakaway.ps1', import.meta.url), 'utf8');
  const ordinary = source.indexOf('$native::CreateProcessW($Program, $ordinary');
  const observed = source.indexOf('$native::IsProcessInJob($control');
  const breakaway = source.indexOf('0x01000000');
  assert.ok(ordinary >= 0 && observed > ordinary && breakaway > observed);
  assert.equal(source.match(/\[IntPtr\]::Zero, \$WorkingDirectory, \$startup, \$info/g)?.length, 2);
  assert.doesNotMatch(source, /\[IntPtr\]::Zero, \$null, \$startup, \$info/u);
  assert.match(source, /if \(\$nativeStatus -ne 5\)/u);
  const native = readFileSync(new URL('../assets/platform/windows-execution-native.ps1', import.meta.url), 'utf8');
  assert.match(native, /\$attribute\.GetField\('SetLastError'\)/u);
});
