import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { windowsPowerShell, windowsExecutionAsset } from '../dist/adapters/platform/windows-execution.js';
import { createPrivateFixtureRoot, removeFixtureRoot } from './fixtures/windows-private-state.mjs';
import { conptyDiagnostic, parseConptyChild, parseConptyDriver } from './fixtures/windows-conpty-protocol.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
function driver(root, scenario, responses = []) {
  windowsExecutionAsset('windows-console.ps1');
  const result = spawnSync(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File',
    path.resolve('tests/fixtures/windows-conpty.ps1')], {
    input: JSON.stringify({ program: process.execPath, argv: [path.resolve('tests/fixtures/windows-console-child.mjs'), scenario, root],
      cwd: root, responses, timeoutMs: 240_000 }),
    encoding: 'utf8', shell: false, windowsHide: true, timeout: 260_000, maxBuffer: 12_000_000,
  });
  const response = parseConptyDriver(result);
  const { output } = response;
  if (scenario === 'parent-death') {
    assert.equal(response.code, 123, conptyDiagnostic(response));
    assert.equal(response.parentKilled, true);
    assert.equal(response.jobEmpty, true, 'The helper must exit before ConPTY/job cleanup, not because cleanup killed it');
    assert.doesNotMatch(output, /WINDOWS_CONSOLE_RESULT/u);
    return { ...response, output };
  }
  return { ...response, value: parseConptyChild(response) };
}

function stdioProbe(root) {
  const probe = driver(root, 'stdio-probe');
  assert.equal(probe.challenges, 0);
  assert.equal(probe.value.state, 'stdio-probe');
  assert.match(probe.output, /CONPTY_STDOUT/u);
  assert.match(probe.output, /CONPTY_STDERR/u);
}

test('Windows ConPTY exact challenge, replay, JSON refusal and redirected OS handles', windows, (t) => {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  stdioProbe(f.root);
  const accepted = driver(f.root, 'component', ['accept']);
  assert.equal(accepted.challenges, 1);
  assert.equal(accepted.value.decision, 'accept');
  assert.match(accepted.output, /EXACT WINDOWS REVIEW/u);
  assert.match(accepted.output, /END EXACT REVIEW/u);
  assert.match(accepted.output, /Unicode: \u00e9 \ud83d\ude80/u);
  const replay = driver(f.root, 'replay', ['accept', 'replay']);
  assert.equal(replay.challenges, 2);
  assert.deepEqual(replay.value, { decision: 'accept', second: 'decline' });
  const json = driver(f.root, 'component', ['json']);
  assert.equal(json.challenges, 1);
  assert.equal(json.value.decision, 'decline');
  for (const scenario of ['redirect-input', 'redirect-output']) {
    const redirected = driver(f.root, scenario);
    assert.equal(redirected.challenges, 0);
    assert.equal(redirected.value.decision, 'unavailable');
  }
});

test('Windows ConPTY deadlines and AbortSignal cannot issue late confirmation', windows, (t) => {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  stdioProbe(f.root);
  const expired = driver(f.root, 'expired');
  assert.equal(expired.challenges, 0);
  assert.equal(expired.value.decision, 'cancel');
  const aborted = driver(f.root, 'abort');
  assert.equal(aborted.challenges, 1);
  assert.equal(aborted.value.decision, 'cancel');
  const late = driver(f.root, 'late', ['late']);
  assert.equal(late.challenges, 1);
  assert.equal(late.value.decision, 'cancel');
  const dead = driver(f.root, 'parent-death', ['kill-parent']);
  assert.equal(dead.challenges, 1);
});

test('Windows ConPTY real terminal receipts bind setup display, reopen and reviewed revocation', windows, (t) => {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  stdioProbe(f.root);
  assert.equal(driver(f.root, 'component', ['decline']).value.decision, 'decline');
  const declined = driver(f.root, 'authority-decline', ['decline']);
  assert.equal(declined.challenges, 1);
  assert.deepEqual(declined.value, { state: 'declined', unchanged: true });
  const accepted = driver(f.root, 'authority', ['accept', 'accept']);
  assert.equal(accepted.challenges, 2);
  assert.equal(accepted.value.state, 'revoked');
  assert.match(accepted.output, /no organization or tamper-proof assurance/u);
  assert.equal(accepted.value.displayBound, true);
});
