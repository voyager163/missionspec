import assert from 'node:assert/strict';
import { lstatSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalRuntimeState } from '../dist/application/runtime-state.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { openRuntimeStore, openWorkspaceRuntimeStore } from '../dist/adapters/persistence/index.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { createPrivateFixtureRoot, removeFixtureRoot, privateEntry } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
function inventory(root) {
  return readdirSync(root).sort().map((name) => {
    const filename = path.join(root, name);
    const stat = lstatSync(filename, { bigint: true });
    return [name, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs,
      stat.isDirectory() ? inventory(filename) : digestContent(readFileSync(filename))];
  });
}

test('Windows native private runtime backup, raw restore, migration and external selection preserve current facts', windows, async (t) => {
  const fixture = createPrivateFixtureRoot();
  const stores = [];
  t.after(() => {
    try { for (const store of stores) ok(store.close()); }
    finally { removeFixtureRoot(fixture.root, fixture.identity); }
  });
  // TEST ONLY: callback admission is not qualification of a real user interface.
  const authority = await openLocalAuthority({
    directory: fixture.root,
    transport: { channel: 'trusted-callback', protocolIdentity: { id: 'test.windows-lifecycle', version: '1' },
      async confirm() { return 'accept'; } },
  });
  const approve = async (request) => {
    const result = ok(await authority.requestConfirmation(request));
    assert.equal(result.state, 'issued');
    return result.approval.reference;
  };
  const workflow = await LocalWorkflow.open(fixture.root, { authority });
  const setup = await workflow.previewSetup();
  await assert.rejects(authority.requestConfirmation(setup.request), { code: 'scope-exceeded' });
  assert.deepEqual(readdirSync(fixture.root), []);
  const confirmedSetup = ok(await authority.confirmPlan(setup));
  assert.equal(confirmedSetup.state, 'issued');
  await workflow.apply(setup, confirmedSetup.approval.reference);
  const workspace = (await workflow.project()).workspace;
  const store = ok(await openRuntimeStore({ directory: path.join(fixture.root, '.missionspec/state'), expectedWorkspace: workspace, mode: 'create' }));
  stores.push(store);
  const revisions = { workspace, changeId: 'CHG-windows-backup', specification: digestContent('spec'), tasks: digestContent('tasks'),
    workflow: digestContent('workflow'), source: digestContent('source'), effects: digestContent('effects') };
  const raw = await workflow.files.recordRuntime('evidence', 'EVD-windows-backup', {
    schemaVersion: 1, evidenceId: 'EVD-windows-backup', basis: 'executed', result: 'passed', output: 'retained fixture observation',
  });
  const snapshot = { contractVersion: 1, id: 'RUN-windows-backup', revisions, state: 'quiesced',
    activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed' };
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot, attempts: [], evidence: [{
    contractVersion: 1, id: 'EVD-windows-backup', revisions, source: revisions.source, checkId: 'CHK-windows-backup',
    checkDefinition: digestContent('check'), attemptId: null, storage: { state: 'retained', path: raw.path, digest: raw.digest },
  }] }));
  const service = await LocalRuntimeState.open(fixture.root, { authority });
  const before = inventory(fixture.root);
  const preview = await service.previewBackup();
  await service.status();
  assert.deepEqual(inventory(fixture.root), before);
  const created = await service.backup(preview, await approve(preview.request));
  const backup = await service.readBackup(created.file);
  const filename = path.join(fixture.root, raw.path);
  unlinkSync(filename);
  const restore = await service.previewRestore(backup);
  assert.equal((await service.restore(backup, restore, await approve(restore.request))).restored, 1);
  assert.equal(readFileSync(filename, 'utf8'), raw.content);
  const destination = (name) => {
    const base = path.join(fixture.root, name);
    privateEntry(base, true, true);
    privateEntry(path.join(base, '.missionspec'), true, true);
    return path.join(base, '.missionspec/state');
  };
  const migration = await service.previewMigration(backup, destination('recovery-volume'));
  assert.equal((await service.migrate(backup, migration, await approve(migration.request))).activation, 'not-authorized');
  const selection = await service.previewSelection(destination('active-volume'));
  const stage = await service.prepareSelection(selection, await approve(selection.request));
  const activation = await service.previewActivation(stage.id);
  const exclusive = service.files.exclusive;
  service.files.exclusive = async function(relative, ...args) {
    if (relative.startsWith('.missionspec/recovery/selection-generation-')) {
      throw Object.assign(new Error('injected activation record quota exhaustion'), { code: 'EDQUOT' });
    }
    return exclusive.call(this, relative, ...args);
  };
  await assert.rejects(service.activate(stage.id, activation, await approve(activation.request)),
    (error) => error.code === 'effect-outcome-unknown');
  service.files.exclusive = exclusive;
  const pending = await service.files.pending();
  assert.equal(pending.length, 1);
  const recovery = await service.previewActivationRecovery(stage.id, pending[0]);
  await service.recoverActivation(stage.id, pending[0], await approve(recovery.request));
  assert.deepEqual(await service.files.pending(), []);
  assert.equal((await store.listRuns()).error.code, 'stale-revision');
  const active = ok(await openWorkspaceRuntimeStore({ workspaceRoot: fixture.root, expectedWorkspace: workspace, mode: 'read-only' }));
  stores.push(active);
  assert.equal(ok(await active.readRun(snapshot.id)).snapshot.id, snapshot.id);
  assert.equal((await service.status()).selection, 'external');
});
