import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TerminalAuthority } from '../../dist/adapters/authority/terminal.js';
import { LocalWorkflow } from '../../dist/application/local-workflow.js';
import { confirmWindowsConsole } from '../../dist/adapters/platform/windows-console.js';
import { windowsExecutionAsset, windowsExecutionFailure, windowsPowerShell } from '../../dist/adapters/platform/windows-execution.js';
import { digestApprovalRequest } from '../../dist/kernel/authority.js';

const [scenario, root] = process.argv.slice(2);
const ok = (result) => { assert.equal(result.status, 'ok'); return result.value; };
const emit = (value) => console.log(`\nWINDOWS_CONSOLE_RESULT:${JSON.stringify(value)}`);
let stage = 'bootstrap';
let nativeObservation = {};

try {
if (scenario === 'stdio-probe') {
  stage = 'stdio-probe';
  console.log('CONPTY_STDOUT');
  console.error('CONPTY_STDERR');
  windowsExecutionAsset('windows-console.ps1');
  const result = spawnSync(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File',
    fileURLToPath(new URL('./windows-console-probe.ps1', import.meta.url))], {
    stdio: ['inherit', 'pipe', 'inherit'], encoding: 'utf8', shell: false, timeout: 30_000,
  });
  if (result.stdout?.startsWith('WINDOWS_CONSOLE_FAILURE:') && result.stdout.length < 4096) process.stdout.write(`\n${result.stdout}\n`);
  assert.equal(result.status, 0);
  const probe = JSON.parse(result.stdout);
  for (const key of ['inputType', 'outputType', 'inputMode', 'outputMode', 'inputConsole', 'outputConsole']) {
    if (typeof probe[key] === 'boolean' || (Number.isInteger(probe[key]) && probe[key] >= 0 && probe[key] <= 0xffff_ffff)) {
      nativeObservation[key] = probe[key];
    }
  }
  assert.equal(probe.inputType, 2);
  assert.equal(probe.outputType, 2);
  assert.equal(probe.inputConsole, true);
  assert.equal(probe.outputConsole, true);
  assert.equal(probe.inputMode & 3, 3);
  emit({ state: 'stdio-probe' });
} else if (scenario.startsWith('redirect-')) {
  stage = 'redirect';
  const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), 'component', root], {
    stdio: [scenario === 'redirect-input' ? 'ignore' : 'inherit', 'inherit', scenario === 'redirect-output' ? 'ignore' : 'inherit'],
    timeout: 60_000, shell: false,
  });
  assert.equal(result.status, 0);
} else if (scenario === 'authority' || scenario === 'authority-decline') {
  stage = 'authority-open';
  const authority = await TerminalAuthority.open(root);
  const workflow = await LocalWorkflow.open(root, { authority });
  stage = 'setup-preview';
  const plan = await workflow.previewSetup();
  stage = 'confirmation';
  const value = ok(await authority.confirmPlan(plan));
  if (scenario === 'authority-decline') {
    assert.equal(value.state, 'declined');
    assert.deepEqual(readdirSync(root), []);
    emit({ state: 'declined', unchanged: true });
  } else {
    assert.equal(value.state, 'issued');
    stage = 'receipt';
    const approval = value.approval;
    assert.equal(approval.assurance.channel, 'terminal-confirmation');
    assert.equal(approval.assurance.humanPresence, 'not-attested');
    assert.equal(approval.requestDigest, digestApprovalRequest(plan.request));
    const receipt = JSON.parse(readFileSync(path.join(root, '.missionspec/approvals', `${approval.reference.id}.json`), 'utf8'));
    assert.equal(receipt.approval.requestDigest, digestApprovalRequest(receipt.display.request));
    assert.equal(receipt.renderedDisplay.includes('onboard'), true);
    stage = 'reopen';
    const reopened = await TerminalAuthority.open(root);
    assert.equal(ok(await reopened.resolve(approval.reference)).state, 'current');
    stage = 'revocation';
    await reopened.revoke(approval.reference);
    assert.equal(ok(await (await TerminalAuthority.open(root)).resolve(approval.reference)).state, 'revoked');
    emit({ state: 'revoked', displayBound: true });
  }
} else {
  stage = 'component';
  const abort = new AbortController();
  const now = Date.now();
  const review = {
    renderedDisplay: 'EXACT WINDOWS REVIEW\nSynthetic ConPTY test only. No human presence is attested.\nUnicode: \u00e9 \ud83d\ude80\nEND EXACT REVIEW',
    action: 'issue', expiresAt: new Date(now + 1_800_000).toISOString(),
    deadlineAt: new Date(now + (scenario === 'expired' ? -1 : 90_000)).toISOString(),
  };
  if (scenario === 'late') review.deadlineAt = new Date(now + 45_000).toISOString();
  const pending = confirmWindowsConsole(review, abort.signal);
  let timer;
  if (scenario === 'abort') timer = setTimeout(() => abort.abort(), 10_000);
  let decision;
  try { decision = await pending; } finally { clearTimeout(timer); }
  if (scenario === 'replay') {
    const second = await confirmWindowsConsole({ ...review, deadlineAt: new Date(Date.now() + 90_000).toISOString() }, abort.signal);
    emit({ decision, second });
  } else emit({ decision });
}
} catch (error) {
  const scalar = (value) => typeof value === 'boolean' || (Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff) ||
    ['accept', 'decline', 'cancel', 'unavailable', 'declined', 'issued', 'current', 'revoked', 'ok'].includes(value) ? value : 'other';
  const native = typeof error?.message === 'string' ? error.message.match(/\(([a-z-]+)(?:; line=([0-9]+))?\)\.$/u) : null;
  const diagnostic = { stage, code: ['ERR_ASSERTION', 'EPERM', 'capability-unavailable', 'effect-outcome-unknown'].includes(error?.code) ? error.code : 'other',
    actual: scalar(error?.actual), expected: scalar(error?.expected), ...nativeObservation,
    ...(native === null ? {} : { native: windowsExecutionFailure({ phase: native[1], line: Number(native[2]) }) }) };
  console.log(`\nWINDOWS_CONSOLE_FAILURE:${JSON.stringify(diagnostic)}`);
  process.exitCode = 1;
}
