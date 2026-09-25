import assert from 'node:assert/strict';
import { readFileSync, readdirSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalRuntimeState } from '../dist/application/runtime-state.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { openRuntimeStore, openWorkspaceRuntimeStore } from '../dist/adapters/persistence/index.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { createPrivateFixtureRoot, removeFixtureRoot, privateEntry, checkPrivateFixturePathBudget } from './fixtures/windows-private-state.mjs';
import { WindowsPrivateStateError, windowsFailureDiagnostic, windowsPrivateStateDiagnostic } from '../dist/adapters/platform/windows-private-state.js';
import { failure } from '../dist/adapters/persistence/failures.js';
import { fixtureInventory } from './fixtures/filesystem-snapshot.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
const fixtureId = '00000000-0000-0000-0000-000000000000';
const reservedPublication = `.missionspec/recovery/selection-generation-${'0'.repeat(64)}.json.msn-${fixtureId}.before`;
function inventory(root) {
  return fixtureInventory(root, digestContent);
}

test('Windows lifecycle fixtures reserve the complete publication path, including the retained preimage', () => {
  const profile = String.raw`C:\Users\runneradmin`;
  const localRoot = path.win32.join(profile, 'AppData', 'Local', `.windows-state-${fixtureId}`);
  assert.equal(path.win32.join(localRoot, reservedPublication).length, 247);
  assert.throws(() => checkPrivateFixturePathBudget(localRoot, [reservedPublication]),
    (error) => error instanceof WindowsPrivateStateError && windowsPrivateStateDiagnostic(error) === 'path-length');
  const profileRoot = path.win32.join(profile, `.windows-state-${fixtureId}`);
  assert.equal(path.win32.join(profileRoot, reservedPublication).length, 233);
  assert.doesNotThrow(() => checkPrivateFixturePathBudget(profileRoot, [reservedPublication]));
});

test('runtime error translation preserves bounded Windows diagnostics without exposing exception text', () => {
  const details = {
    reason: 'effect-open', phase: 'file-operation', boundary: 'private', nativeStatus: 32, line: 123,
    message: String.raw`PRIVATE C:\private\state S-1-5-21-PRIVATE private ACL`,
  };
  const diagnostic = windowsFailureDiagnostic(details);
  const native = new WindowsPrivateStateError(details);
  details.nativeStatus = 999;
  const translated = failure(native);
  assert.equal(translated.status, 'blocked');
  assert.equal(translated.error.code, 'capability-unavailable');
  assert.deepEqual(translated.error.fields, ['runtimeStore', 'unavailable']);
  assert.equal(translated.error.message, `Windows private runtime storage is unavailable (${diagnostic}).`);
  assert.equal(JSON.stringify(translated).includes('PRIVATE'), false);
  for (const error of [
    new WindowsPrivateStateError(String.raw`PRIVATE C:\private\state S-1-5-21-PRIVATE private ACL`),
    new WindowsPrivateStateError({ reason: 'effect-open', phase: 'PRIVATE', nativeStatus: Infinity, line: 10001 }),
    new WindowsPrivateStateError({ reason: 'effect-open', path: 'PRIVATE' }),
    Object.assign(new WindowsPrivateStateError(details), { message: 'PRIVATE mutated exception text' }),
    Object.assign(new Error('PRIVATE raw filesystem exception'), { code: 'EPERM' }),
  ]) {
    const result = failure(error);
    assert.equal(result.status, 'blocked');
    assert.equal(result.error.code, 'capability-unavailable');
    assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  }
  assert.equal(failure(Object.assign(new Error('PRIVATE quota path'), { code: 'EDQUOT' })).error.code, 'limit-reached');
});

test('Windows native private runtime backup, raw restore, migration and external selection preserve current facts', windows, async (t) => {
  const fixture = createPrivateFixtureRoot([reservedPublication]);
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
  checkPrivateFixturePathBudget(fixture.root, activation.mutations.map((mutation) => `${mutation.effect.path}.msn-${fixtureId}.before`));
  const exclusive = service.files.exclusive;
  let quotaFaults = 0;
  service.files.exclusive = async function(relative, ...args) {
    if (relative.startsWith('.missionspec/recovery/selection-generation-')) {
      quotaFaults += 1;
      throw Object.assign(new Error('injected activation record quota exhaustion'), { code: 'EDQUOT' });
    }
    return exclusive.call(this, relative, ...args);
  };
  await assert.rejects(service.activate(stage.id, activation, await approve(activation.request)),
    (error) => error.code === 'effect-outcome-unknown');
  service.files.exclusive = exclusive;
  assert.equal(quotaFaults, 1, 'the exact generation-record allocation fault must be reached');
  assert.equal(digestContent(readFileSync(path.join(fixture.root, '.missionspec/runtime-selection.json'))),
    activation.mutations[0].effect.proposed);
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
