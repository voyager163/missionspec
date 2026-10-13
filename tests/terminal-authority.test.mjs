import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readdir, readFile, rm, writeFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { TerminalAuthority, LocalWorkflow, digestApprovalRequest } from '../dist/api/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createAuthorizedJsonlSink } from '../dist/adapters/logging/jsonl.js';
import { serializeDiagnosticEvent } from '../dist/adapters/logging/diagnostics.js';

const driver = path.resolve('tests/fixtures/terminal-driver.py');
const cli = path.resolve('dist/cli/main.js');
const exec = promisify(execFile);
async function fixture(t) {
  const root = path.resolve(`.terminal-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const tty = async (mode, ...args) => JSON.parse((await exec('python3', [driver, mode, root, process.execPath, cli, ...args, '--json'], { maxBuffer: 10_000_000 })).stdout);
  return { root, tty };
}

test('production terminal authority refuses non-TTY, arbitrary approval IDs and caller approved booleans without writes', async (t) => {
  const { root } = await fixture(t);
  const workflow = await LocalWorkflow.open(root);
  const authority = await TerminalAuthority.open(root);
  const plan = await workflow.previewSetup();
  await assert.rejects(authority.confirmPlan({ ...plan, approved: true }));
  assert.equal((await authority.confirmPlan(plan)).value.state, 'unavailable');
  assert.equal((await authority.resolve({ id: 'APR-client-claim' })).value.state, 'absent');
  assert.deepEqual(await readdir(root), []);
});

test('real controlled TTY declines without bootstrap state; confirmation persists exact display and survives restart/revocation', async (t) => {
  const f = await fixture(t);
  const declined = await f.tty('decline', 'init');
  assert.equal(declined.confirmations, 1);
  assert.notEqual(declined.code, 0);
  assert.deepEqual(await readdir(f.root), []);
  const initialized = await f.tty('confirm', 'init', '--profile', 'compact');
  assert.equal(initialized.code, 0, initialized.output);
  assert.equal(initialized.confirmations, 1);
  const names = await readdir(path.join(f.root, '.missionspec/approvals'));
  assert.equal(names.length, 1);
  const receipt = JSON.parse(await readFile(path.join(f.root, '.missionspec/approvals', names[0]), 'utf8'));
  assert.equal(receipt.approval.assurance.kind, 'local-user');
  assert.equal(receipt.approval.requestDigest, digestApprovalRequest(receipt.display.request));
  assert(receipt.display.detail.filePlan.mutations.some((mutation) => mutation.content?.includes('compact')));
  assert.equal(receipt.approval.assurance.channel, 'terminal-confirmation');
  assert.deepEqual(receipt.approval.assurance.qualification, { state: 'not-established' });
  const reopened = await TerminalAuthority.open(f.root);
  assert.equal((await reopened.resolve(receipt.approval.reference)).value.state, 'current');
  const created = await f.tty('confirm', 'change', 'new', 'terminal', '--spec', 'demo');
  assert.equal(created.code, 0, created.output);
  assert.equal(created.confirmations, 1);
  const revoked = await f.tty('confirm', 'approval', 'revoke', receipt.approval.reference.id);
  assert.equal(revoked.code, 0, revoked.output);
  assert.equal((await reopened.resolve(receipt.approval.reference)).value.state, 'revoked');
  assert.equal((await LocalWorkflow.open(f.root)).files.rootDigest, receipt.approval.request.binding.workspace.rootDigest);
});

test('real terminal CLI guides verified acceptance, promotion and accepted archive without separate commands', async (t) => {
  const f = await fixture(t);
  const invoke = async (...args) => {
    const result = await f.tty('confirm', ...args);
    assert.equal(result.code, 0, result.output);
    const line = result.output.split(/\r?\n/u).findLast((line) => line.startsWith('{"contractVersion":'));
    assert(line, result.output);
    return { ...result, value: JSON.parse(line).value };
  };
  await invoke('init');
  await invoke('change', 'new', 'guided', '--spec', 'filters', '--spec', 'reset',
    '--source', 'src/filter-preference.ts', '--source', 'tests/filter-preference.test.ts');
  const change = await (await LocalWorkflow.open(f.root)).loadChange('guided');
  for (const node of change.metadata.nodes) {
    for (const output of node.outputs) {
      const relative = output.slice('missionspec/changes/guided/'.length).replace('/spec.md', '.md');
      const content = (await readFile(path.resolve('assets/workflows/standard/examples', relative), 'utf8')).replaceAll('CHG-remember-filter', change.metadata.id);
      await mkdir(path.dirname(path.join(f.root, output)), { recursive: true });
      await writeFile(path.join(f.root, output), content);
    }
    await invoke('capture', 'guided', '--artifact', node.node);
  }
  await writeFile(path.join(f.root, 'candidate.json'), JSON.stringify({
    kind: 'inert-proposal', host: 'copilot', summary: 'TEST fixture proposal, not a native host invocation.',
    changes: [{ path: 'src/filter-preference.ts', expected: 'absent', content: 'reviewed fixture source\n' }],
  }));
  const patched = await invoke('patch', 'guided', '--task', 'TSK-filter', '--file', 'candidate.json');
  assert.equal(patched.confirmations, 1);
  assert.equal(patched.value.state, 'committed');
  assert.equal(await readFile(path.join(f.root, 'src/filter-preference.ts'), 'utf8'), 'reviewed fixture source\n');
  const registrations = [];
  for (const id of ['CHK-filter', 'CHK-reset']) {
    await writeFile(path.join(f.root, 'registration.json'), JSON.stringify({
      checkId: id, program: await realpath(process.execPath), argv: ['-e',
        'require("node:assert/strict").equal(require("node:fs").readFileSync("src/filter-preference.ts", "utf8"), "reviewed fixture source\\n"); console.log("observed fixture verification")'],
      cwd: '.', controlFiles: [], timeoutMs: 2000, guarantees: 'trusted-local-process',
    }));
    registrations.push((await invoke('check', 'register', 'guided', '--file', 'registration.json')).value.id);
  }
  const collected = await invoke('collect', 'guided', '--run', 'RUN-guided', ...registrations.flatMap((id) => ['--registration', id]));
  assert.equal(collected.value.evidence.length, 2);
  const evidenceArgs = collected.value.evidence.flatMap((id) => ['--evidence', id]);
  const mcp = new Client({ name: 'TEST-existing-ledger', version: '0.0.0' }, { capabilities: {} });
  let mcpDiagnostics = '';
  try {
    const transport = new StdioClientTransport({
      command: process.execPath, args: [cli, 'mcp'], cwd: f.root, stderr: 'pipe',
      env: { MISSIONSPEC_TELEMETRY: '0', DO_NOT_TRACK: '1' },
    });
    transport.stderr.on('data', (chunk) => { mcpDiagnostics += chunk; });
    await mcp.connect(transport, { timeout: 5000 });
    const listing = await mcp.listTools();
    assert(listing.tools.some((tool) => tool.name === 'missionspec_lessons'));
    assert(listing.tools.some((tool) => tool.name === 'missionspec_evidence_pruning'));
    assert(!listing.tools.some((tool) => tool.name === 'missionspec_apply'));
    const verified = await mcp.callTool({ name: 'missionspec_verify', arguments: {
      change: 'guided', run: 'RUN-guided', evidence: collected.value.evidence,
    } });
    assert.equal(verified.structuredContent.value.acceptanceEligibility.state, 'eligible-for-human-review');
  } catch (error) {
    assert.fail(`MCP existing-ledger fixture failed: ${error.message}; diagnostics: ${mcpDiagnostics}`);
  } finally { await mcp.close(); }
  const current = await (await LocalWorkflow.open(f.root)).loadChange('guided');
  const review = {
    schemaVersion: 1, revisions: current.revisions, scope: 'declared-source-files-only',
    sourceFiles: await Promise.all(current.metadata.sourcePaths.map(async (file) => ({
      path: file, digest: (await currentFile(f.root, file))?.digest ?? 'absent',
    }))),
    findings: [],
  };
  review.findings.push({
    id: 'FND-terminal-review', basis: 'static-inspection', severity: 'blocking',
    summary: 'Synthetic user-reviewed gap, not a native semantic evaluation.',
    paths: [review.sourceFiles[0].path], gap: 'partial', requirements: ['REQ-filter'], tasks: ['TSK-filter'],
    evidence: [collected.value.evidence[0]], observations: [review.sourceFiles[0]],
  });
  await writeFile(path.join(f.root, 'review.json'), JSON.stringify(review));
  const captured = await invoke('convergence', 'guided', '--file', 'review.json');
  assert.equal(captured.confirmations, 1);
  const blocked = await invoke('verify', 'guided', '--run', 'RUN-guided', ...evidenceArgs);
  assert.equal(blocked.value.acceptanceEligibility.state, 'ineligible');
  const attemptedAcceptance = await f.tty('confirm', 'accept', 'guided', '--run', 'RUN-guided', ...evidenceArgs);
  assert.notEqual(attemptedAcceptance.code, 0);
  assert.equal(attemptedAcceptance.confirmations, 0);
  review.findings = [];
  await writeFile(path.join(f.root, 'review.json'), JSON.stringify(review));
  await invoke('convergence', 'guided', '--file', 'review.json');
  await writeFile(path.join(f.root, 'lesson.json'), JSON.stringify({
    schemaVersion: 1, lessonId: 'terminal-advice', title: 'Review exact evidence', advice: 'Treat prior results as context, not permission.',
    provenance: { kind: 'human-observation', rationale: 'Original fixture review.', evidence: collected.value.evidence },
    applicability: { changeId: current.metadata.id, operations: ['verify'], sourcePaths: ['src/filter-preference.ts'] },
  }));
  await invoke('lessons', 'capture', 'guided', '--file', 'lesson.json');
  const history = await invoke('lessons', 'history', 'terminal-advice');
  assert.equal(history.value.state, 'inactive');
  const version = history.value.versions[0].digest;
  await writeFile(path.join(f.root, 'evaluation.json'), JSON.stringify({ lesson: 'terminal-advice', version }));
  await invoke('lessons', 'evaluate', 'guided', '--file', 'evaluation.json');
  await writeFile(path.join(f.root, 'transition.json'), JSON.stringify({
    lesson: 'terminal-advice', transition: { action: 'activate', version, reason: 'Explicit original fixture human review.' },
  }));
  await invoke('lessons', 'transition', 'guided', '--file', 'transition.json');
  assert.equal((await invoke('lessons', 'history', 'terminal-advice')).value.state, 'active');
  await writeFile(path.join(f.root, 'selection.json'), JSON.stringify({ operation: 'verify', paths: ['src/filter-preference.ts'] }));
  await invoke('lessons', 'select', 'guided', '--file', 'selection.json');
  const archived = await invoke('archive', 'guided', '--run', 'RUN-guided', ...collected.value.evidence.flatMap((id) => ['--evidence', id]));
  assert.equal(archived.confirmations, 3);
  assert.equal(archived.value.state, 'committed');
  const archive = (await readdir(path.join(f.root, 'missionspec/changes/archive')))[0];
  assert.match(archive, /^\d{4}-\d{2}-\d{2}-guided$/u);
  assert.equal(JSON.parse(await readFile(path.join(f.root, 'missionspec/changes/archive', archive, 'closure.json'), 'utf8')).outcome, 'accepted');
  assert.match(await readFile(path.join(f.root, 'missionspec/specs/filters/spec.md'), 'utf8'), /kind: baseline/u);
  assert.equal((await (await LocalWorkflow.open(f.root)).project()).changes.length, 0);
  const prunePreview = await invoke('evidence', 'prune', ...evidenceArgs, '--preview');
  assert.equal(prunePreview.confirmations, 0);
  const pruned = await invoke('evidence', 'prune', ...evidenceArgs);
  assert.equal(pruned.confirmations, 1);
  assert.equal(pruned.value.state, 'pruned');
  assert.equal((await invoke('evidence', 'status', prunePreview.value.id)).value.state, 'pruned');
  assert.deepEqual((await invoke('evidence', 'pending')).value, []);
});

async function currentFile(root, file) {
  return (await LocalWorkflow.open(root)).files.read(file);
}

test('terminal adoption preserves original sources, previews without writes, and archives imported provenance', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.tty('confirm', 'init')).code, 0);
  await mkdir(path.join(f.root, 'openspec/changes/old'), { recursive: true });
  const source = { id: 'old-proposal', system: 'openspec', path: 'openspec/changes/old/proposal.md', content: '# Original test source\n\nNot imported authority.\n' };
  await writeFile(path.join(f.root, source.path), source.content);
  await writeFile(path.join(f.root, 'adoption.json'), JSON.stringify({ slug: 'adopted', specs: ['demo'], sources: [source] }));
  const before = await readdir(path.join(f.root, '.missionspec/approvals'));
  const preview = await f.tty('confirm', 'adopt', '--file', 'adoption.json', '--preview');
  assert.equal(preview.code, 0, preview.output);
  assert.equal(preview.confirmations, 0);
  assert.deepEqual(await readdir(path.join(f.root, '.missionspec/approvals')), before);
  const applied = await f.tty('confirm', 'adopt', '--file', 'adoption.json');
  assert.equal(applied.code, 0, applied.output);
  assert.equal(applied.confirmations, 1);
  const closure = await f.tty('confirm', 'archive', 'adopted', '--outcome', 'incomplete');
  assert.equal(closure.code, 0, closure.output);
  const archived = (await readdir(path.join(f.root, 'missionspec/changes/archive')))[0];
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/archive', archived, 'imports/sources/old-proposal.md'), 'utf8'), source.content);
  assert.equal(await readFile(path.join(f.root, source.path), 'utf8'), source.content);
});

test('terminal CLI bootstraps exact selected skill files and removes only reviewed owned files', async (t) => {
  const f = await fixture(t);
  const installed = await f.tty('confirm', 'skills', 'install', '--host', 'codex');
  assert.equal(installed.code, 0, installed.output.slice(-3000));
  assert.equal(installed.confirmations, 1);
  const directory = path.join(f.root, '.agents/skills');
  assert.equal((await readdir(directory)).length, 12);
  await mkdir(path.join(directory, 'personal'));
  await writeFile(path.join(directory, 'personal/keep.md'), 'Unrelated user content.\n');
  const updated = await f.tty('confirm', 'skills', 'update', '--host', 'codex');
  assert.equal(updated.code, 0, updated.output.slice(-3000));
  assert.equal(updated.confirmations, 0);
  const removed = await f.tty('confirm', 'skills', 'remove', '--host', 'codex');
  assert.equal(removed.code, 0, removed.output.slice(-3000));
  assert.equal(removed.confirmations, 1);
  assert.equal(await readFile(path.join(directory, 'personal/keep.md'), 'utf8'), 'Unrelated user content.\n');
  const inspection = await exec(process.execPath, [cli, 'skills', 'inspect', '--host', 'codex', '--json'], { cwd: f.root });
  assert(JSON.parse(inspection.stdout).value.files.every((entry) => entry.state === 'absent'));
});

test('terminal CLI diagnostic pruning reviews one log without changing retained evidence', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.tty('confirm', 'init')).code, 0);
  const log = path.join(f.root, '.missionspec/logs/diagnostics.jsonl');
  await mkdir(path.dirname(log), { mode: 0o700 });
  await createAuthorizedJsonlSink(log).write(serializeDiagnosticEvent({
    contractVersion: 1, operation: 'draft', engine: 'specification', severity: 'information',
    code: 'operation-stopped', errorCode: null, elapsedMilliseconds: 1,
  }, new Date().toISOString()));
  await mkdir(path.join(f.root, '.missionspec/evidence'), { mode: 0o700 });
  const retained = path.join(f.root, '.missionspec/evidence/keep.json');
  await writeFile(retained, '{"preserve":"not a log"}', { mode: 0o600 });
  const preview = await f.tty('confirm', 'logs', 'prune', '--preview');
  assert.equal(preview.code, 0, preview.output);
  assert.equal(preview.confirmations, 0);
  const applied = await f.tty('confirm', 'logs', 'prune');
  assert.equal(applied.code, 0, applied.output);
  assert.equal(applied.confirmations, 1);
  assert.equal(await readFile(log, 'utf8'), '');
  assert.equal(await readFile(retained, 'utf8'), '{"preserve":"not a log"}');
});
