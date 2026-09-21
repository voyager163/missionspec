import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  closeSync, existsSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync,
  readdirSync, renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { describe } from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalEvidencePruning } from '../dist/application/evidence-pruning.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { TerminalAuthority } from '../dist/adapters/authority/terminal.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { requireWindowsProcessAbsent, windowsPrivateEntries } from '../dist/adapters/platform/windows-private-state.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { createPrivateFixtureRoot, removeFixtureRoot, privateEntry } from './fixtures/windows-private-state.mjs';
import { windowsFileSecurity } from './fixtures/windows-file-security.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
const issued = (result) => { const value = ok(result); assert.equal(value.state, 'issued'); return value.approval; };
const childFile = fileURLToPath(new URL('./fixtures/windows-application-interruption.mjs', import.meta.url));

function inventory(root) {
  return readdirSync(root).sort().map((name) => {
    const filename = path.join(root, name);
    const stat = lstatSync(filename, { bigint: true });
    return [name, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs,
      stat.isDirectory() ? inventory(filename) : digestContent(readFileSync(filename))];
  });
}

function writeExisting(filename, value) {
  const handle = openSync(filename, 'w');
  try { writeFileSync(handle, value); fsyncSync(handle); } finally { closeSync(handle); }
}

async function fixture(t) {
  const f = createPrivateFixtureRoot();
  const stores = [];
  t.after(() => {
    try { for (const store of stores) ok(store.close()); }
    finally { removeFixtureRoot(f.root, f.identity); }
  });
  const decisions = { value: 'accept', reviews: [] };
  // TEST ONLY: installed callback substitute, not evidence of human presence or a native UI.
  const transport = {
    channel: 'trusted-callback', protocolIdentity: { id: 'test.windows-application', version: '1' },
    async confirm(review) { decisions.reviews.push(review); return decisions.value; },
  };
  const authority = await openLocalAuthority({ directory: f.root, transport });
  const workflow = await LocalWorkflow.open(f.root, { authority });
  const approve = async (plan) => issued(await authority.confirmPlan(plan)).reference;
  const setup = await workflow.previewSetup();
  return { ...f, stores, decisions, transport, authority, workflow, approve, setup };
}

async function initialized(t) {
  const f = await fixture(t);
  await f.workflow.apply(f.setup, await f.approve(f.setup));
  f.workspace = (await f.workflow.project()).workspace;
  return f;
}

function child(input, status) {
  const result = spawnSync(process.execPath, [childFile], {
    input: JSON.stringify(input), encoding: 'utf8', timeout: 180_000, maxBuffer: 65_536,
  });
  assert.equal(result.status, status, result.stderr || result.stdout || result.error?.message);
  return result;
}

describe('Windows real application integration', { ...windows, timeout: 780_000 }, () => {
test('real Windows setup, callback receipts, draft/capture and exact source patches preserve private data and ACLs', windows, async (t) => {
  const f = await fixture(t);
  for (const decision of ['decline', 'cancel', true, { approved: true }]) {
    f.decisions.value = decision;
    assert.notEqual(ok(await f.authority.confirmPlan(f.setup)).state, 'issued');
    assert.deepEqual(readdirSync(f.root), []);
  }
  f.decisions.value = 'accept';
  const grant = issued(await f.authority.confirmPlan(f.setup));
  assert.equal(grant.assurance.humanPresence, 'not-attested');
  assert.equal(grant.assurance.qualification.state, 'not-established');
  const reader = await openLocalAuthority({ directory: f.root });
  assert.equal(ok(await reader.resolve(grant.reference)).state, 'current');
  await f.workflow.apply(f.setup, grant.reference);
  const project = await f.workflow.project();
  assert.equal(project.state, 'initialized');
  assert.deepEqual(await f.workflow.files.pending(), []);
  const beforeTerminal = inventory(f.root);
  assert.equal(ok(await (await TerminalAuthority.open(f.root)).requestConfirmation(f.setup.request)).state, 'unavailable');
  assert.deepEqual(inventory(f.root), beforeTerminal);
  await assert.rejects(f.authority.requestConfirmation({ ...f.setup.request, approved: true }));

  const sourceDir = path.join(f.root, 'src');
  privateEntry(sourceDir, true, true);
  const source = path.join(sourceDir, 'filter-preference.ts');
  privateEntry(source, false, true);
  const original = 'export const filter = "before";\n';
  writeExisting(source, original);
  const permissions = windowsFileSecurity({ path: source, removeSystem: true }).fingerprint;
  const change = await f.workflow.previewNewChange({
    slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'],
  });
  await f.workflow.apply(change, await f.approve(change));
  const instructions = await f.workflow.instructions('filters', 'proposal');
  const draft = await f.workflow.previewArtifact('filters', 'proposal', instructions.templates, { mode: 'draft' });
  await f.workflow.apply(draft, await f.approve(draft));
  assert.equal((await f.workflow.loadChange('filters')).implementationReady, false);

  const drafts = {};
  for (const node of ['proposal', 'specs', 'design', 'tasks']) {
    const names = node === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${node}.md`];
    drafts[node] = names.map((name) => ({
      path: `missionspec/changes/filters/${name.replace(/specs\/(.*)\.md$/u, 'specs/$1/spec.md')}`,
      content: readFileSync(new URL(`../assets/workflows/standard/examples/${name}`, import.meta.url), 'utf8'),
    }));
  }
  const batch = await f.workflow.previewDraftAll('filters', drafts);
  assert.deepEqual(batch.completed, ['proposal', 'specs', 'design', 'tasks']);
  await f.workflow.apply(batch.plan, await f.approve(batch.plan));
  assert.equal((await f.workflow.loadChange('filters')).implementationReady, true);
  const proposal = {
    kind: 'inert-proposal', host: 'copilot', summary: 'TEST ONLY inert bytes; no host or check execution.',
    changes: [
      { path: 'src/filter-preference.ts', expected: digestContent(original), content: 'export const filter = "reviewed";\n' },
      { path: 'tests/filter-preference.test.ts', expected: 'absent', content: '// reviewed fixture, not an executed check\n' },
    ],
  };
  const patch = await f.workflow.previewSourcePatch('filters', 'TSK-filter', proposal);
  const approval = await f.approve(patch);
  await assert.rejects(f.workflow.commitSourcePatch('filters', 'TSK-filter', proposal, patch, grant.reference), { code: 'scope-exceeded' });
  writeExisting(source, 'unreviewed user edit\n');
  await assert.rejects(f.workflow.commitSourcePatch('filters', 'TSK-filter', proposal, patch, approval));
  assert.equal(readFileSync(source, 'utf8'), 'unreviewed user edit\n');
  writeExisting(source, original);
  await f.workflow.commitSourcePatch('filters', 'TSK-filter', proposal, patch, approval);
  assert.equal(readFileSync(source, 'utf8'), proposal.changes[0].content);
  assert.equal(readFileSync(path.join(f.root, proposal.changes[1].path), 'utf8'), proposal.changes[1].content);
  assert.equal(windowsFileSecurity({ path: source }).fingerprint, permissions);
  assert.equal(lstatSync(source).nlink, 1);
  const reopened = await openLocalAuthority({ directory: f.root, transport: f.transport });
  assert.equal(ok(await reopened.resolve(approval)).state, 'current');
  await reopened.revoke(approval);
  assert.equal(ok(await (await openLocalAuthority({ directory: f.root })).resolve(approval)).state, 'revoked');

  const stream = `${source}:unreviewed`;
  writeFileSync(stream, 'retain named-stream bytes');
  assert.throws(() => windowsPrivateEntries([{ path: source, directory: false, writable: true, ordinaryFile: true }]));
  assert.equal(readFileSync(stream, 'utf8'), 'retain named-stream bytes');
  unlinkSync(stream);
  const alias = path.join(f.root, 'hardlink');
  linkSync(source, alias);
  assert.throws(() => windowsPrivateEntries([{ path: source, directory: false, writable: true, ordinaryFile: true }]));
  unlinkSync(alias);
});

test('real Windows file journals recover after process exit, preserve edits, and block live or unrelated locks', windows, async (t) => {
  const f = await fixture(t);
  const approval = await f.approve(f.setup);
  const crashed = child({ mode: 'file-exit', root: f.root, plan: f.setup, approval }, 74);
  requireWindowsProcessAbsent(crashed.pid);
  assert.throws(() => requireWindowsProcessAbsent(process.pid), /process-present/u);
  const [id] = await f.workflow.files.pending();
  assert.ok(id);
  const lock = path.join(f.root, '.missionspec', 'transaction.lock');
  const originalLock = readFileSync(lock, 'utf8');
  const journal = path.join(f.root, '.missionspec', 'transactions', `${id}.json`);
  const retained = readFileSync(journal);
  const edit = path.join(f.root, '.gitignore');
  privateEntry(edit, false, true);
  writeExisting(edit, 'unreviewed ignore edit\n');
  await assert.rejects(f.workflow.files.recover(id, approval), { code: 'stale-revision' });
  assert.equal(readFileSync(edit, 'utf8'), 'unreviewed ignore edit\n');
  assert.equal(readFileSync(lock, 'utf8'), originalLock);
  unlinkSync(edit);
  const recovery = await f.workflow.files.recoveryPlan(id);
  const current = await f.approve(recovery);
  writeExisting(lock, JSON.stringify({ transactionId: id, pid: process.pid }));
  await assert.rejects(f.workflow.files.recover(id, current), { code: 'conflict' });
  assert.equal(JSON.parse(readFileSync(lock, 'utf8')).pid, process.pid);
  writeExisting(lock, originalLock);
  await f.workflow.files.recover(id, current);
  assert.equal((await f.workflow.project()).state, 'initialized');
  assert.deepEqual(await f.workflow.files.pending(), []);
  assert.deepEqual(readFileSync(journal), retained);
  assert.equal(existsSync(lock), false);

  const failure = await fixture(t);
  const failedApproval = await failure.approve(failure.setup);
  const outcome = child({
    mode: 'journal-sync-failure', root: failure.root, plan: failure.setup, approval: failedApproval,
  }, 0);
  assert.equal(JSON.parse(outcome.stdout).code, 'effect-outcome-unknown');
  assert.equal(existsSync(path.join(failure.root, 'missionspec', 'config.yaml')), false);
  const [pending] = await failure.workflow.files.pending();
  const failedPlan = await failure.workflow.files.recoveryPlan(pending);
  await failure.workflow.files.recover(pending, await failure.approve(failedPlan));
  assert.equal((await failure.workflow.project()).state, 'initialized');

  const staged = await failure.workflow.previewNewChange({ slug: 'retained-stage', id: 'CHG-retained-stage', specs: ['filters'] });
  const stageApproval = await failure.approve(staged);
  child({ mode: 'stage-exit', root: failure.root, plan: staged, approval: stageApproval }, 74);
  const [stageId] = await failure.workflow.files.pending();
  const first = staged.mutations[0];
  const stage = path.join(failure.root, `${first.effect.path}.msn-${stageId}`);
  const destination = path.join(failure.root, first.effect.path);
  assert.equal(readFileSync(stage, 'utf8'), first.content);
  const stagePlan = await failure.workflow.files.recoveryPlan(stageId);
  const stageGrant = await failure.approve(stagePlan);
  writeFileSync(`${stage}:user`, 'unreviewed retained-stage stream');
  await assert.rejects(failure.workflow.files.recover(stageId, stageGrant), { code: 'effect-outcome-unknown' });
  assert.equal(readFileSync(`${stage}:user`, 'utf8'), 'unreviewed retained-stage stream');
  assert.equal(readFileSync(stage, 'utf8'), first.content);
  assert.equal(existsSync(destination), false);
  unlinkSync(`${stage}:user`);
  const stageSecurity = windowsFileSecurity({ path: stage }).sddl;
  const changedSecurity = windowsFileSecurity({ path: stage, publicRead: true }).fingerprint;
  await assert.rejects(failure.workflow.files.recover(stageId, stageGrant), { code: 'effect-outcome-unknown' });
  assert.equal(windowsFileSecurity({ path: stage }).fingerprint, changedSecurity);
  assert.equal(readFileSync(stage, 'utf8'), first.content);
  assert.equal(existsSync(destination), false);
  windowsFileSecurity({ path: stage, restoreSddl: stageSecurity });
  const replaced = child({
    mode: 'recovery-stage-replace', root: failure.root, transactionId: stageId,
    approval: stageGrant, stage, stageContent: first.content,
  }, 0);
  assert.equal(JSON.parse(replaced.stdout).replacedStage, true);
  assert.equal(readFileSync(stage, 'utf8'), first.content);
  assert.equal(readFileSync(`${stage}.saved`, 'utf8'), first.content);
  assert.notEqual(lstatSync(stage, { bigint: true }).ino, lstatSync(`${stage}.saved`, { bigint: true }).ino);
  assert.equal(existsSync(destination), false);
  unlinkSync(stage);
  renameSync(`${stage}.saved`, stage);
  await failure.workflow.files.recover(stageId, stageGrant);
  assert.equal(readFileSync(destination, 'utf8'), first.content);
  assert.equal(existsSync(stage), false);
});

test('real Windows evidence-pruning application preserves history through preparation, exit, recovery and replay', windows, async (t) => {
  const f = await initialized(t);
  const directory = path.join(f.root, '.missionspec', 'state');
  const openStore = async (mode = 'read-write') => {
    const store = ok(await openRuntimeStore({ directory, expectedWorkspace: f.workspace, mode }));
    f.stores.push(store);
    return store;
  };
  let store = await openStore('create');
  let workflow = await LocalWorkflow.open(f.root, { authority: f.authority, store });
  const revisions = {
    workspace: f.workspace, changeId: 'CHG-prune-windows', specification: digestContent('spec'),
    tasks: digestContent('tasks'), workflow: digestContent('workflow'), effects: digestContent('effects'),
    source: digestContent('source'),
  };
  const evidence = [];
  for (let index = 0; index < 4; index++) {
    const id = `EVD-windows-app-${index}`;
    const raw = await workflow.files.recordRuntime('evidence', id, {
      schemaVersion: 1, evidenceId: id, basis: 'static-inspection', result: index % 2 === 0 ? 'passed' : 'failed',
      output: `TEST ONLY retained observation ${index}; not a process result or task completion`,
    });
    evidence.push({
      contractVersion: 1, id, revisions, source: revisions.source, checkId: `CHK-windows-${index}`,
      checkDefinition: digestContent(`check ${index}`), attemptId: null,
      storage: { state: 'retained', path: raw.path, digest: raw.digest },
    });
  }
  const snapshot = {
    contractVersion: 1, id: 'RUN-windows-prune', revisions, state: 'quiesced',
    activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed',
  };
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot, attempts: [], evidence }));
  // Historical storage fixture only, not an application-issued acceptance or human assertion.
  const acceptance = {
    contractVersion: 1, state: 'accepted', revisions, source: revisions.source,
    evidence: evidence.map((item) => item.id), approval: { id: 'APR-test-only-historical-windows' },
  };
  ok(await store.recordAcceptance(acceptance));
  let pruning = new LocalEvidencePruning(workflow, store, f.authority);
  for (const [index, mode] of [[0, 'prune-prepare-exit'], [2, 'prune-delete-exit']]) {
    const selected = evidence.slice(index, index + 2);
    const preview = await pruning.preview(selected.map((item) => item.id));
    const approval = issued(await pruning.confirm(preview)).reference;
    ok(store.close());
    child({ mode, root: f.root, preview, approval }, 75);
    store = await openStore();
    workflow = await LocalWorkflow.open(f.root, { authority: f.authority, store });
    pruning = new LocalEvidencePruning(workflow, store, f.authority);
    assert.equal((await pruning.status(preview.id)).state, 'prepared');
    assert.equal(ok(await store.readEvidence(selected[0].id)).storage.state, 'unavailable');
    const recovery = await pruning.previewRecovery(preview.id);
    assert.deepEqual(recovery.remaining.map((item) => item.state),
      mode === 'prune-prepare-exit' ? ['retained', 'retained'] : ['already-absent', 'retained']);
    const remaining = path.join(f.root, selected[1].storage.path);
    const original = readFileSync(remaining);
    writeExisting(remaining, 'user changed retained evidence');
    await assert.rejects(pruning.recover(preview.id, approval), { code: 'stale-revision' });
    assert.equal(readFileSync(remaining, 'utf8'), 'user changed retained evidence');
    writeExisting(remaining, original);
    await f.authority.revoke(approval);
    await assert.rejects(pruning.recover(preview.id, approval), { code: 'authority-required' });
    const current = issued(await pruning.confirm(await pruning.previewRecovery(preview.id))).reference;
    const completed = await pruning.recover(preview.id, current);
    assert.equal(completed.state, 'pruned');
    assert.equal(completed.prepared.approval.id, approval.id);
    assert.equal(completed.completion.approval.id, current.id);
    for (const item of selected) assert.equal(existsSync(path.join(f.root, item.storage.path)), false);
    const replacement = path.join(f.root, selected[0].storage.path);
    privateEntry(replacement, false, true);
    writeExisting(replacement, 'new user-retained replacement');
    assert.equal((await pruning.recover(preview.id, current)).state, 'pruned');
    assert.equal(readFileSync(replacement, 'utf8'), 'new user-retained replacement');
  }
  assert.deepEqual(ok(await store.readRun('RUN-windows-prune')).snapshot, snapshot);
  assert.deepEqual(ok(await store.readAcceptance(acceptance.approval)), acceptance);
  assert.deepEqual(ok(await store.readRunEvidence(snapshot.id)), []);
});
});
