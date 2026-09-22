import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TerminalAuthority } from '../../dist/adapters/authority/terminal.js';
import { LocalWorkflow } from '../../dist/application/local-workflow.js';
import { confirmWindowsConsole } from '../../dist/adapters/platform/windows-console.js';
import { digestApprovalRequest } from '../../dist/kernel/authority.js';

const [scenario, root] = process.argv.slice(2);
const ok = (result) => { assert.equal(result.status, 'ok'); return result.value; };
const emit = (value) => console.log(`WINDOWS_CONSOLE_RESULT:${JSON.stringify(value)}`);

if (scenario.startsWith('redirect-')) {
  const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), 'component', root], {
    stdio: [scenario === 'redirect-input' ? 'ignore' : 'inherit', 'inherit', scenario === 'redirect-output' ? 'ignore' : 'inherit'],
    timeout: 60_000, shell: false,
  });
  assert.equal(result.status, 0);
} else if (scenario === 'authority' || scenario === 'authority-decline') {
  const authority = await TerminalAuthority.open(root);
  const workflow = await LocalWorkflow.open(root, { authority });
  const plan = await workflow.previewSetup();
  const value = ok(await authority.confirmPlan(plan));
  if (scenario === 'authority-decline') {
    assert.equal(value.state, 'declined');
    assert.deepEqual(readdirSync(root), []);
    emit({ state: 'declined', unchanged: true });
  } else {
    assert.equal(value.state, 'issued');
    const approval = value.approval;
    assert.equal(approval.assurance.channel, 'terminal-confirmation');
    assert.equal(approval.assurance.humanPresence, 'not-attested');
    assert.equal(approval.requestDigest, digestApprovalRequest(plan.request));
    const receipt = JSON.parse(readFileSync(path.join(root, '.missionspec/approvals', `${approval.reference.id}.json`), 'utf8'));
    assert.equal(receipt.approval.requestDigest, digestApprovalRequest(receipt.display.request));
    assert.equal(receipt.renderedDisplay.includes('onboard'), true);
    const reopened = await TerminalAuthority.open(root);
    assert.equal(ok(await reopened.resolve(approval.reference)).state, 'current');
    await reopened.revoke(approval.reference);
    assert.equal(ok(await (await TerminalAuthority.open(root)).resolve(approval.reference)).state, 'revoked');
    emit({ state: 'revoked', displayBound: true });
  }
} else {
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
  const decision = await pending;
  clearTimeout(timer);
  if (scenario === 'replay') {
    const second = await confirmWindowsConsole({ ...review, deadlineAt: new Date(Date.now() + 90_000).toISOString() }, abort.signal);
    emit({ decision, second });
  } else emit({ decision });
}
