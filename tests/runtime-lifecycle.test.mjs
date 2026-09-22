import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalRuntimeState, validateRuntimeBackup } from '../dist/application/runtime-state.js';
import { LocalEvidencePruning } from '../dist/application/evidence-pruning.js';
import { openRuntimeStore, openWorkspaceRuntimeStore, resolveRuntimeState, runtimeStateExists, validateRuntimeSnapshot } from '../dist/adapters/persistence/index.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestEffectScope } from '../dist/kernel/effects.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { planRuntimeMigration } from '../dist/application/runtime-migrations.js';
import { inspectRuntimeReplica } from '../dist/adapters/persistence/sqlite-runtime-store.js';

const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
const posix = { skip: process.platform === 'win32' };
function authorityFixture() {
  const approvals = new Map();
  return {
    issue(request) {
      const parsed = parseApprovalRequest(request);
      const reference = { id: `APR-${randomUUID()}` };
      approvals.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference,
        assurance: { kind: 'local-user', channel: 'trusted-callback',
          protocolIdentity: { id: 'test.runtime-lifecycle', version: '1' },
          qualification: { state: 'not-established' }, humanPresence: 'not-attested', organizationIdentity: 'not-attested' },
        request: parsed, requestDigest: digestApprovalRequest(parsed), issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      });
      return reference;
    },
    revoke(reference) { approvals.delete(reference.id); },
    async resolve(reference) {
      if (this.onResolve) await this.onResolve();
      return { status: 'ok', value: approvals.has(reference.id)
        ? { state: 'current', approval: approvals.get(reference.id) } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
}

function inventory(root) {
  return readdirSync(root).sort().map((name) => {
    const filename = path.join(root, name);
    const stat = lstatSync(filename, { bigint: true });
    return [name, stat.ino, stat.size, stat.mode, stat.mtimeNs, stat.ctimeNs,
      stat.isDirectory() ? inventory(filename) : digestContent(readFileSync(filename))];
  });
}
async function fixture(t) {
  const root = path.join(process.cwd(), `.runtime-lifecycle-test-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  const stores = [];
  t.after(() => { for (const store of stores) ok(store.close()); rmSync(root, { recursive: true, force: true }); });
  const authority = authorityFixture();
  const app = await LocalWorkflow.open(root, { authority });
  const setup = await app.previewSetup();
  await app.apply(setup, authority.issue(setup.request));
  const workspace = (await app.project()).workspace;
  const directory = path.join(root, '.missionspec/state');
  const store = ok(await openRuntimeStore({ directory, expectedWorkspace: workspace, mode: 'create' }));
  stores.push(store);
  const revisions = { workspace, changeId: 'CHG-backup', specification: digestContent('spec'), tasks: digestContent('tasks'),
    workflow: digestContent('workflow'), effects: digestEffectScope([]), source: digestContent('source') };
  const evidence = [];
  for (const id of ['EVD-one', 'EVD-two']) {
    const file = await app.files.recordRuntime('evidence', id, {
      schemaVersion: 1, evidenceId: id, basis: 'executed', result: 'passed', output: `private recorded output for ${id}`,
    });
    evidence.push({ contractVersion: 1, id, revisions, source: revisions.source, checkId: 'CHK-one',
      checkDefinition: digestContent('check'), attemptId: null, storage: { state: 'retained', path: file.path, digest: file.digest } });
  }
  const snapshot = { contractVersion: 1, id: 'RUN-backup', revisions, state: 'quiesced',
    activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed' };
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot, attempts: [], evidence }));
  const service = await LocalRuntimeState.open(root, { authority });
  const f = { root, directory, workspace, authority, app, store, stores, snapshot, evidence, service };
  f.backup = async () => {
    const preview = await service.previewBackup();
    const result = await service.backup(preview, authority.issue(preview.request));
    return { preview, result, backup: await service.readBackup(result.file) };
  };
  f.external = () => {
    const base = path.join(root, `volume-${randomUUID()}`);
    mkdirSync(base, { mode: 0o700 });
    mkdirSync(path.join(base, '.missionspec'), { mode: 0o700 });
    return path.join(base, '.missionspec/state');
  };
  return f;
}

test('logical backup is fully validated, includes exact raw evidence and never exports authority state', posix, async (t) => {
  const f = await fixture(t);
  await f.app.files.recordRuntime('approvals', 'independent-revocation', { state: 'revoked', secret: 'never export this' });
  const before = inventory(f.root);
  const preview = await f.service.previewBackup();
  assert.deepEqual(inventory(f.root), before);
  assert.equal(preview.request.effects[0].kind, 'runtime-state');
  const result = await f.service.backup(preview, f.authority.issue(preview.request));
  const backup = await f.service.readBackup(result.file);
  assert.equal(backup.evidence.length, 2);
  assert.equal(backup.evidence[0].content, readFileSync(path.join(f.root, f.evidence[0].storage.path), 'utf8'));
  assert.ok(!JSON.stringify(backup).includes('never export this'));
  assert.equal(backup.ledger.digest, ok(await f.store.snapshot()).digest);
  assert.equal(ok(await validateRuntimeSnapshot(backup.ledger, f.workspace)).quiescent, true);
  const stable = inventory(f.root);
  await f.service.status();
  const policy = await f.service.migrationPolicy();
  assert.equal(policy.state, 'current');
  assert.deepEqual(policy.applicableMigrations, []);
  assert.deepEqual(inventory(f.root), stable);
});

test('backup validation rejects tampered, foreign, missing-raw and incompatible snapshots before any write', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  const before = inventory(f.root);
  for (const modify of [
    (copy) => { copy.evidence[0].content += 'tamper'; },
    (copy) => { copy.workspace.workspaceId = 'WSP-foreign'; },
    (copy) => { copy.ledger.schemaVersion = 2; },
    (copy) => { copy.ledger.rows.runs[0][2] = '{}'; },
    (copy) => { copy.evidence.pop(); },
    (copy) => { copy.extra = true; },
    (copy) => { copy.ledger.rows.evidence[0][2] = 'ATT-dangling'; },
  ]) {
    const copy = structuredClone(backup);
    modify(copy);
    await assert.rejects(f.service.previewStage(copy));
  }
  assert.deepEqual(inventory(f.root), before);
  const copy = structuredClone(backup);
  copy.ledger.rows.run_history = [];
  const { digest, ...body } = copy.ledger;
  copy.ledger.digest = digestContent(JSON.stringify(body));
  assert.notEqual((await validateRuntimeSnapshot(copy.ledger, f.workspace)).status, 'ok');
  assert.deepEqual(inventory(f.root), before);
});

test('fresh exact authorization, current quiescence and final raw-byte checks gate backup effects', posix, async (t) => {
  const f = await fixture(t);
  const preview = await f.service.previewBackup();
  const approval = f.authority.issue(preview.request);
  f.authority.revoke(approval);
  await assert.rejects(f.service.backup(preview, approval), /approval|authority|current/i);
  assert.equal(existsSync(path.join(f.root, '.missionspec/backups')), false);
  const run = ok(await f.store.readRun(f.snapshot.id));
  ok(await f.store.commitRun({ expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'running', quiescence: 'unconfirmed' }, attempts: [], evidence: [] }));
  const running = await f.service.previewBackup();
  await assert.rejects(f.service.backup(running, f.authority.issue(running.request)), /quiescence|Active/);
  assert.equal(existsSync(path.join(f.root, '.missionspec/backups')), false);
});

test('restore preserves newer ledger facts and authority, restores missing raw bytes but never resurrects pruning', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  const workflow = await LocalWorkflow.open(f.root, { authority: f.authority, store: f.store });
  const pruning = new LocalEvidencePruning(workflow, f.store, f.authority);
  const prune = await pruning.preview(['EVD-one']);
  await pruning.commit(prune, f.authority.issue(prune.request));
  const original = readFileSync(path.join(f.root, f.evidence[1].storage.path));
  unlinkSync(path.join(f.root, f.evidence[1].storage.path));
  await f.app.files.recordRuntime('approvals', 'newer-revocation', { state: 'revoked', usedAdmissionToken: 'consumed' });
  const authorities = inventory(path.join(f.root, '.missionspec/approvals'));
  const ledger = readFileSync(path.join(f.directory, 'ledger.sqlite'));
  const preview = await f.service.previewRestore(backup);
  const result = await f.service.restore(backup, preview, f.authority.issue(preview.request));
  assert.equal(result.restored, 1);
  assert.equal(result.suppressed, 1);
  assert.equal(result.runsResumed, 0);
  assert.equal(existsSync(path.join(f.root, f.evidence[0].storage.path)), false);
  assert.deepEqual(readFileSync(path.join(f.root, f.evidence[1].storage.path)), original);
  assert.deepEqual(readFileSync(path.join(f.directory, 'ledger.sqlite')), ledger);
  assert.deepEqual(inventory(path.join(f.root, '.missionspec/approvals')), authorities);
  assert.equal(ok(await f.store.readEvidence('EVD-one')).storage.state, 'pruned');
});

test('non-destructive recovery stage works with missing current ledger but cannot fabricate activation continuity', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  ok(f.store.close());
  const original = readFileSync(path.join(f.directory, 'ledger.sqlite'));
  unlinkSync(path.join(f.directory, 'ledger.sqlite'));
  const preview = await f.service.previewStage(backup);
  const stage = await f.service.stage(backup, preview, f.authority.issue(preview.request));
  assert.equal(stage.state, 'staged');
  assert.deepEqual(await f.service.readBackup(stage.file), backup);
  await assert.rejects(f.service.previewRestore(backup), /exist|missing/i);
  assert.equal(existsSync(path.join(f.directory, 'ledger.sqlite')), false);
  writeFileSync(path.join(f.directory, 'ledger.sqlite'), original, { mode: 0o600 });
});

test('missing workspace identity never makes existing runtime state appear absent for setup', posix, async (t) => {
  const f = await fixture(t);
  const before = inventory(f.root);
  await assert.rejects(runtimeStateExists(f.root, null), /independent workspace identity/);
  assert.deepEqual(inventory(f.root), before);
});

test('restore cannot overwrite newer raw bytes or import records absent from healthy current history', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  const filename = path.join(f.root, f.evidence[0].storage.path);
  writeFileSync(filename, 'new user observation');
  const before = inventory(f.root);
  await assert.rejects(f.service.previewRestore(backup), /preserved/);
  assert.deepEqual(inventory(f.root), before);
  const foreign = structuredClone(backup);
  foreign.ledger.rows.runs[0][1] = digestContent('changed');
  await assert.rejects(validateRuntimeBackup(foreign, f.workspace));
});

test('external selection uses a closed exact replica, independent activation and stale-handle fences across CLI/API', posix, async (t) => {
  const f = await fixture(t);
  const directory = f.external();
  const before = readFileSync(path.join(f.directory, 'ledger.sqlite'));
  const preview = await f.service.previewSelection(directory);
  assert.equal(existsSync(directory), false);
  const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
  assert.equal(resolveRuntimeState(f.root, f.workspace).kind, 'default');
  assert.notEqual((await openRuntimeStore({ directory, expectedWorkspace: f.workspace, mode: 'read-write' })).status, 'ok');
  const plan = await f.service.previewActivation(staged.id);
  await assert.rejects(f.app.files.commit(plan, f.authority.issue(plan.request)), /current-ledger lease/);
  const leaseSnapshot = ok(await f.store.snapshot());
  await assert.rejects(f.app.files.commitRuntimeSelection(plan, f.authority.issue(plan.request), {
    kind: 'runtime-lifecycle-lease', workspace: f.workspace, snapshot: leaseSnapshot.digest,
  }), /store-issued/);
  const expiredLease = ok(await f.store.withLifecycleLease(leaseSnapshot.digest, async (_snapshot, lease) => lease));
  await assert.rejects(f.app.files.commitRuntimeSelection(plan, f.authority.issue(plan.request), expiredLease), /store-issued/);
  await f.service.activate(staged.id, plan, f.authority.issue(plan.request));
  assert.equal(resolveRuntimeState(f.root, f.workspace).directory, directory);
  assert.equal((await f.store.listRuns()).error.code, 'stale-revision');
  assert.deepEqual(readFileSync(path.join(f.directory, 'ledger.sqlite')), before);
  assert.notEqual((await openRuntimeStore({ directory: f.directory, expectedWorkspace: f.workspace, mode: 'read-write' })).status, 'ok');
  const selected = ok(await openWorkspaceRuntimeStore({ workspaceRoot: f.root, expectedWorkspace: f.workspace, mode: 'read-write' }));
  f.stores.push(selected);
  assert.equal(ok(await selected.listRuns()).length, 1);
  for (const args of [['state', 'status'], ['run', 'status', 'RUN-backup']]) {
    const child = spawnSync(process.execPath, [new URL('../dist/cli/main.js', import.meta.url).pathname, ...args, '--json'], { cwd: f.root, encoding: 'utf8' });
    assert.equal(child.status, 0, child.stderr || child.stdout);
  }
  unlinkSync(path.join(f.root, '.missionspec/runtime-selection.json'));
  assert.notEqual((await f.store.listRuns()).status, 'ok');
  await assert.rejects(f.service.status(), /fallback/);
});

test('source advances, pending pruning, destination conflicts and symlink aliases cannot be activated', posix, async (t) => {
  const f = await fixture(t);
  const directory = f.external();
  const preview = await f.service.previewSelection(directory);
  const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
  const run = ok(await f.store.readRun(f.snapshot.id));
  ok(await f.store.commitRun({ expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'paused' }, attempts: [], evidence: [] }));
  await assert.rejects(f.service.previewActivation(staged.id), /advanced/);
  const another = await f.service.previewSelection(directory);
  await assert.rejects(f.service.prepareSelection(another, f.authority.issue(another.request)), /adopts|overwrites/);
  assert.equal(existsSync(path.join(f.root, '.missionspec/runtime-selection.json')), false);
  const alias = path.join(f.root, 'alias');
  symlinkSync(path.dirname(path.dirname(directory)), alias, 'dir');
  await assert.rejects(f.service.previewSelection(path.join(alias, '.missionspec/state')));
});

test('preserved activation history rejects rollback to an older valid external selector', posix, async (t) => {
  const f = await fixture(t);
  const relocate = async () => {
    const preview = await f.service.previewSelection(f.external());
    const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
    const plan = await f.service.previewActivation(staged.id);
    await f.service.activate(staged.id, plan, f.authority.issue(plan.request));
  };
  await relocate();
  const first = readFileSync(path.join(f.root, '.missionspec/runtime-selection.json'));
  await relocate();
  writeFileSync(path.join(f.root, '.missionspec/runtime-selection.json'), first);
  await assert.rejects(f.service.status(), /rolled back|diverges/);
});

test('authority callback edits and revoked grants cannot overwrite evidence or approve another effect', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  const filename = path.join(f.root, f.evidence[0].storage.path);
  unlinkSync(filename);
  const preview = await f.service.previewRestore(backup);
  const approval = f.authority.issue(preview.request);
  let resolves = 0;
  f.authority.onResolve = async () => {
    resolves += 1;
    if (resolves === 3) writeFileSync(filename, 'user edit during final authority callback', { mode: 0o600 });
  };
  await assert.rejects(f.service.restore(backup, preview, approval), /preserves newer/);
  assert.equal(readFileSync(filename, 'utf8'), 'user edit during final authority callback');
  delete f.authority.onResolve;
  const staged = await f.service.previewStage(backup);
  await assert.rejects(f.service.stage(backup, staged, approval), /approval|authority|scope/i);
});

test('quota failure during restore reports capacity, retains recovery state and never declares partial success', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  for (const item of f.evidence) unlinkSync(path.join(f.root, item.storage.path));
  const preview = await f.service.previewRestore(backup);
  const original = f.service.files.recordRuntime;
  let writes = 0;
  f.service.files.recordRuntime = async function(area, name, content) {
    if (area === 'evidence' && ++writes === 2) throw Object.assign(new Error('injected quota exhaustion'), { code: 'EDQUOT' });
    return original.call(this, area, name, content);
  };
  await assert.rejects(f.service.restore(backup, preview, f.authority.issue(preview.request)), (error) => error.code === 'limit-reached');
  assert.equal(existsSync(path.join(f.root, f.evidence[0].storage.path)), true);
  assert.equal(existsSync(path.join(f.root, f.evidence[1].storage.path)), false);
  assert.equal(existsSync(path.join(f.root, `.missionspec/recovery/restore-${preview.id.slice(7)}.done.json`)), false);
  assert.equal(ok(await f.store.snapshot()).digest, preview.ledger);
  f.service.files.recordRuntime = original;
  assert.equal((await f.service.restore(backup, preview, f.authority.issue(preview.request))).restored, 1);
});

test('exclusive lifecycle lease prevents writers and cannot be accidentally rolled back by a nested call', posix, async (t) => {
  const f = await fixture(t);
  const other = ok(await openRuntimeStore({ directory: f.directory, expectedWorkspace: f.workspace, mode: 'read-write', busyTimeoutMs: 1 }));
  f.stores.push(other);
  const snapshot = ok(await f.store.snapshot());
  ok(await f.store.withLifecycleLease(snapshot.digest, async () => {
    assert.notEqual((await f.store.listRuns()).status, 'ok');
    assert.notEqual(f.store.close().status, 'ok');
    const run = ok(await other.readRun(f.snapshot.id));
    const write = await other.commitRun({ expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'paused' }, attempts: [], evidence: [] });
    assert.notEqual(write.status, 'ok');
    assert.ok(write.error.fields.includes('busy'));
    return null;
  }));
  assert.equal(ok(await f.store.snapshot()).digest, snapshot.digest);
});

test('real process exit during raw restoration leaves an exact recoverable job, not successful partial restore', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  for (const item of f.evidence) unlinkSync(path.join(f.root, item.storage.path));
  const preview = await f.service.previewRestore(backup);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync} from 'node:fs';
    import {LocalWorkspace} from ${JSON.stringify(new URL('../dist/adapters/filesystem/local-workspace.js', import.meta.url).href)};
    import {LocalRuntimeState} from ${JSON.stringify(new URL('../dist/application/runtime-state.js', import.meta.url).href)};
    const authorityFixture = ${authorityFixture.toString()};
    import {randomUUID} from 'node:crypto';
    import {parseApprovalRequest,digestApprovalRequest} from ${JSON.stringify(new URL('../dist/kernel/authority.js', import.meta.url).href)};
    const input = JSON.parse(readFileSync(0,'utf8'));
    const authority = authorityFixture();
    const service = await LocalRuntimeState.open(input.root,{authority});
    const original = LocalWorkspace.prototype.recordRuntime;
    LocalWorkspace.prototype.recordRuntime = async function(area,name,value) {
      const result = await original.call(this,area,name,value);
      if (area === 'evidence') process.exit(71);
      return result;
    };
    await service.restore(input.backup,input.preview,authority.issue(input.preview.request));
  `], { input: JSON.stringify({ root: f.root, backup, preview }), encoding: 'utf8' });
  assert.equal(child.status, 71, child.stderr);
  assert.equal(existsSync(path.join(f.root, f.evidence[0].storage.path)), true);
  assert.equal(existsSync(path.join(f.root, f.evidence[1].storage.path)), false);
  const result = await f.service.restore(backup, preview, f.authority.issue(preview.request));
  assert.equal(result.restored, 1);
  assert.equal(existsSync(path.join(f.root, '.missionspec/transaction.lock')), false);
  assert.equal(ok(await f.store.snapshot()).digest, preview.ledger);
});

test('logical snapshot corruption and real SQLite capacity failures leave current history intact', posix, async (t) => {
  const f = await fixture(t);
  const snapshot = ok(await f.store.snapshot());
  const bad = structuredClone(snapshot);
  bad.rows.evidence.push(bad.rows.evidence[0]);
  const { digest, ...body } = bad;
  bad.digest = digestContent(JSON.stringify(body));
  assert.notEqual((await validateRuntimeSnapshot(bad, f.workspace)).status, 'ok');
  const db = new DatabaseSync(path.join(f.directory, 'ledger.sqlite'));
  try {
    const pages = db.prepare('PRAGMA page_count').get().page_count;
    db.exec(`PRAGMA max_page_count=${pages}`);
    assert.throws(() => {
      db.exec('BEGIN IMMEDIATE');
      db.prepare('INSERT INTO evidence_prune_prepared(id,digest,payload) VALUES(?,?,?)').run('large', 'large', 'x'.repeat(2_000_000));
    }, /full/i);
    if (db.isTransaction) db.exec('ROLLBACK');
  } finally { db.close(); }
  assert.equal(ok(await f.store.snapshot()).digest, snapshot.digest);
});

test('explicit versioned backup-to-native migration preserves facts without selecting or adopting a historical ledger', posix, async (t) => {
  const f = await fixture(t);
  const { backup } = await f.backup();
  const directory = f.external();
  const before = inventory(f.root);
  const preview = await f.service.previewMigration(backup, directory);
  assert.deepEqual(inventory(f.root), before);
  assert.equal(planRuntimeMigration({ kind: 'logical-backup', version: 1 }, { kind: 'sqlite-ledger', version: 3 }).disposition, 'stage-native-replica');
  assert.throws(() => planRuntimeMigration({ kind: 'sqlite-ledger', version: 2 }, { kind: 'sqlite-ledger', version: 3 }), /verified upgrade edge/);
  const result = await f.service.migrate(backup, preview, f.authority.issue(preview.request));
  assert.equal(result.activation, 'not-authorized');
  assert.equal(ok(await inspectRuntimeReplica({ directory, workspaceRoot: f.root, expectedWorkspace: f.workspace, mode: 'read-only' })).digest, backup.ledger.digest);
  assert.equal(resolveRuntimeState(f.root, f.workspace).kind, 'default');
  assert.notEqual((await openRuntimeStore({ directory, workspaceRoot: f.root, expectedWorkspace: f.workspace, mode: 'read-write' })).status, 'ok');
  assert.equal(ok(await f.store.snapshot()).digest, backup.ledger.digest);
});

test('process exit after replica commit is recoverable without recopying or overwriting current state', posix, async (t) => {
  const f = await fixture(t);
  const directory = f.external();
  const preview = await f.service.previewSelection(directory);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync,existsSync} from 'node:fs';
    import {DatabaseSync} from 'node:sqlite';
    import {randomUUID} from 'node:crypto';
    import {LocalRuntimeState} from ${JSON.stringify(new URL('../dist/application/runtime-state.js', import.meta.url).href)};
    import {parseApprovalRequest,digestApprovalRequest} from ${JSON.stringify(new URL('../dist/kernel/authority.js', import.meta.url).href)};
    const authorityFixture = ${authorityFixture.toString()};
    const input = JSON.parse(readFileSync(0,'utf8'));
    const authority = authorityFixture();
    const service = await LocalRuntimeState.open(input.root,{authority});
    const exec = DatabaseSync.prototype.exec;
    DatabaseSync.prototype.exec = function(sql) {
      const result = exec.call(this,sql);
      if (sql === 'COMMIT' && existsSync(input.directory+'/workspace-root.json')) process.exit(72);
      return result;
    };
    await service.prepareSelection(input.preview,authority.issue(input.preview.request));
  `], { input: JSON.stringify({ root: f.root, directory, preview }), encoding: 'utf8' });
  assert.equal(child.status, 72, child.stderr);
  assert.equal(existsSync(path.join(directory, 'ledger.sqlite')), true);
  assert.equal(existsSync(path.join(f.root, '.missionspec/runtime-selection.json')), false);
  const bytes = readFileSync(path.join(directory, 'ledger.sqlite'));
  const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
  assert.equal(staged.state, 'prepared');
  assert.deepEqual(readFileSync(path.join(directory, 'ledger.sqlite')), bytes);
  assert.equal(existsSync(path.join(f.root, '.missionspec/transaction.lock')), false);
});

test('process exit after selection publication recovers its journal without rolling back the selected ledger', posix, async (t) => {
  const f = await fixture(t);
  const directory = f.external();
  const preview = await f.service.previewSelection(directory);
  const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
  const plan = await f.service.previewActivation(staged.id);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync} from 'node:fs';
    import {randomUUID} from 'node:crypto';
    import {LocalWorkspace} from ${JSON.stringify(new URL('../dist/adapters/filesystem/local-workspace.js', import.meta.url).href)};
    import {LocalRuntimeState} from ${JSON.stringify(new URL('../dist/application/runtime-state.js', import.meta.url).href)};
    import {parseApprovalRequest,digestApprovalRequest} from ${JSON.stringify(new URL('../dist/kernel/authority.js', import.meta.url).href)};
    const authorityFixture = ${authorityFixture.toString()};
    const input = JSON.parse(readFileSync(0,'utf8'));
    const authority = authorityFixture();
    const service = await LocalRuntimeState.open(input.root,{authority});
    const read = LocalWorkspace.prototype.read;
    LocalWorkspace.prototype.read = async function(relative) {
      const result = await read.call(this,relative);
      if (relative === '.missionspec/runtime-selection.json' && result !== null) process.exit(73);
      return result;
    };
    await service.activate(input.id,input.plan,authority.issue(input.plan.request));
  `], { input: JSON.stringify({ root: f.root, id: staged.id, plan }), encoding: 'utf8' });
  assert.equal(child.status, 73, child.stderr);
  assert.equal(resolveRuntimeState(f.root, f.workspace).directory, directory);
  const pending = await f.app.files.pending();
  assert.equal(pending.length, 1);
  const bytes = readFileSync(path.join(directory, 'ledger.sqlite'));
  const recovery = await f.service.previewActivationRecovery(staged.id, pending[0]);
  await f.service.recoverActivation(staged.id, pending[0], f.authority.issue(recovery.request));
  assert.deepEqual(await f.app.files.pending(), []);
  assert.deepEqual(readFileSync(path.join(directory, 'ledger.sqlite')), bytes);
  assert.equal(existsSync(path.join(f.root, '.missionspec/transaction.lock')), false);
});

test('quota failures in activation records keep the same journal pending and fence the next relocation', posix, async (t) => {
  for (const boundary of ['selection-generation-', 'selection-established.json', 'completion-receipt']) {
    await t.test(boundary, async (t) => {
      const f = await fixture(t);
      const directory = f.external();
      const preview = await f.service.previewSelection(directory);
      const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
      const plan = await f.service.previewActivation(staged.id);
      const originalLedger = readFileSync(path.join(f.directory, 'ledger.sqlite'));
      const replica = readFileSync(path.join(directory, 'ledger.sqlite'));
      const exclusive = f.service.files.exclusive;
      let failures = 0;
      f.service.files.exclusive = async function(relative, ...args) {
        if (relative.startsWith(`.missionspec/recovery/${boundary}`) ||
            boundary === 'completion-receipt' && /^\.missionspec\/transactions\/[a-f0-9-]{36}\.done\.json$/u.test(relative)) {
          failures += 1;
          throw Object.assign(new Error('injected allocation quota exhaustion'), { code: 'EDQUOT' });
        }
        return exclusive.call(this, relative, ...args);
      };
      await assert.rejects(f.service.activate(staged.id, plan, f.authority.issue(plan.request)),
        (error) => error.code === 'effect-outcome-unknown');
      assert.equal(failures, 1);
      assert.equal(resolveRuntimeState(f.root, f.workspace).directory, directory);
      const pending = await f.app.files.pending();
      assert.equal(pending.length, 1, 'activation must not complete before both independent records are durable');
      assert.equal(existsSync(path.join(f.root, `.missionspec/transactions/${pending[0]}.done.json`)), false);
      const nextDirectory = f.external();
      await assert.rejects(f.service.previewSelection(nextDirectory), /pending|unfinished|recovery/i);
      assert.equal(existsSync(nextDirectory), false);
      const recovery = await f.service.previewActivationRecovery(staged.id, pending[0]);
      await assert.rejects(f.service.recoverActivation(staged.id, pending[0], f.authority.issue(recovery.request)),
        (error) => error.code === 'effect-outcome-unknown');
      assert.deepEqual(await f.app.files.pending(), pending);
      f.service.files.exclusive = exclusive;
      await f.service.recoverActivation(staged.id, pending[0], f.authority.issue(recovery.request));
      assert.deepEqual(await f.app.files.pending(), []);
      assert.deepEqual(readFileSync(path.join(f.directory, 'ledger.sqlite')), originalLedger);
      assert.deepEqual(readFileSync(path.join(directory, 'ledger.sqlite')), replica);
      assert.equal((await f.service.status()).selection, 'external');
      const next = await f.service.previewSelection(nextDirectory);
      const nextStage = await f.service.prepareSelection(next, f.authority.issue(next.request));
      const nextPlan = await f.service.previewActivation(nextStage.id);
      await f.service.activate(nextStage.id, nextPlan, f.authority.issue(nextPlan.request));
      assert.equal(resolveRuntimeState(f.root, f.workspace).directory, nextDirectory);
      assert.equal((await f.service.status()).selection, 'external');
    });
  }
});

async function interruptedSelectorStage(f) {
  const directory = f.external();
  const preview = await f.service.previewSelection(directory);
  const staged = await f.service.prepareSelection(preview, f.authority.issue(preview.request));
  const plan = await f.service.previewActivation(staged.id);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync} from 'node:fs';
    import {randomUUID} from 'node:crypto';
    import {LocalWorkspace} from ${JSON.stringify(new URL('../dist/adapters/filesystem/local-workspace.js', import.meta.url).href)};
    import {LocalRuntimeState} from ${JSON.stringify(new URL('../dist/application/runtime-state.js', import.meta.url).href)};
    import {parseApprovalRequest,digestApprovalRequest} from ${JSON.stringify(new URL('../dist/kernel/authority.js', import.meta.url).href)};
    const authorityFixture = ${authorityFixture.toString()};
    const input = JSON.parse(readFileSync(0,'utf8'));
    const authority = authorityFixture();
    const service = await LocalRuntimeState.open(input.root,{authority});
    const exclusive = LocalWorkspace.prototype.exclusive;
    LocalWorkspace.prototype.exclusive = async function(relative,...args) {
      const result = await exclusive.call(this,relative,...args);
      if (relative.startsWith('.missionspec/runtime-selection.json.msn-')) process.exit(74);
      return result;
    };
    await service.activate(input.id,input.plan,authority.issue(input.plan.request));
  `], { input: JSON.stringify({ root: f.root, id: staged.id, plan }), encoding: 'utf8' });
  assert.equal(child.status, 74, child.stderr);
  const pending = await f.app.files.pending();
  assert.equal(pending.length, 1);
  const stageFile = path.join(f.root, `.missionspec/runtime-selection.json.msn-${pending[0]}`);
  assert.equal(existsSync(path.join(f.root, '.missionspec/runtime-selection.json')), false);
  assert.equal(digestContent(readFileSync(stageFile)), plan.mutations[0].effect.proposed);
  return { id: staged.id, transaction: pending[0], stageFile, directory };
}

test('real POSIX exit after selector stage fsync resumes that exact inode rather than recreating it', posix, async (t) => {
  const f = await fixture(t);
  const interrupted = await interruptedSelectorStage(f);
  const retained = lstatSync(interrupted.stageFile, { bigint: true });
  const bytes = readFileSync(interrupted.stageFile);
  const originalLedger = readFileSync(path.join(f.directory, 'ledger.sqlite'));
  const plan = await f.service.previewActivationRecovery(interrupted.id, interrupted.transaction);
  await f.service.recoverActivation(interrupted.id, interrupted.transaction, f.authority.issue(plan.request));
  const filename = path.join(f.root, '.missionspec/runtime-selection.json');
  assert.equal(lstatSync(filename, { bigint: true }).ino, retained.ino);
  assert.deepEqual(readFileSync(filename), bytes);
  assert.equal(existsSync(interrupted.stageFile), false);
  assert.deepEqual(await f.app.files.pending(), []);
  assert.equal((await f.service.status()).selection, 'external');
  assert.deepEqual(readFileSync(path.join(f.directory, 'ledger.sqlite')), originalLedger);
});

test('POSIX recovery preserves mismatched, insecure and linked retained stages on repeated attempts', posix, async (t) => {
  for (const change of ['content', 'mode', 'hard-link', 'symlink']) {
    await t.test(change, async (t) => {
      const f = await fixture(t);
      const interrupted = await interruptedSelectorStage(f);
      if (change === 'content') writeFileSync(interrupted.stageFile, 'user replacement bytes');
      if (change === 'mode') chmodSync(interrupted.stageFile, 0o400);
      if (change === 'hard-link') linkSync(interrupted.stageFile, path.join(f.root, 'other-link'));
      if (change === 'symlink') {
        const bytes = readFileSync(interrupted.stageFile);
        unlinkSync(interrupted.stageFile);
        const other = path.join(f.root, 'other-file');
        writeFileSync(other, bytes, { mode: 0o600 });
        symlinkSync(other, interrupted.stageFile);
      }
      const stat = lstatSync(interrupted.stageFile, { bigint: true });
      const bytes = readFileSync(interrupted.stageFile);
      const plan = await f.service.previewActivationRecovery(interrupted.id, interrupted.transaction);
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await assert.rejects(f.service.recoverActivation(interrupted.id, interrupted.transaction, f.authority.issue(plan.request)));
        const current = lstatSync(interrupted.stageFile, { bigint: true });
        assert.equal(current.ino, stat.ino);
        assert.equal(current.mode, stat.mode);
        assert.deepEqual(readFileSync(interrupted.stageFile), bytes);
        assert.deepEqual(await f.app.files.pending(), [interrupted.transaction]);
        assert.equal(existsSync(path.join(f.root, '.missionspec/runtime-selection.json')), false);
      }
    });
  }
});

test('POSIX recovery retains an identical-byte replacement made after the held stage was verified', posix, async (t) => {
  const f = await fixture(t);
  const interrupted = await interruptedSelectorStage(f);
  const plan = await f.service.previewActivationRecovery(interrupted.id, interrupted.transaction);
  const verify = f.service.files.verifiedPosixFile;
  let replacement;
  f.service.files.verifiedPosixFile = async function(relative, ...args) {
    const held = await verify.call(this, relative, ...args);
    if (relative.startsWith('.missionspec/runtime-selection.json.msn-')) {
      const bytes = readFileSync(interrupted.stageFile);
      unlinkSync(interrupted.stageFile);
      writeFileSync(interrupted.stageFile, bytes, { mode: 0o600 });
      replacement = lstatSync(interrupted.stageFile, { bigint: true });
      assert.notEqual(replacement.ino, held.identity.ino);
    }
    return held;
  };
  await assert.rejects(f.service.recoverActivation(interrupted.id, interrupted.transaction, f.authority.issue(plan.request)));
  assert.equal(lstatSync(interrupted.stageFile, { bigint: true }).ino, replacement.ino);
  assert.deepEqual(await f.app.files.pending(), [interrupted.transaction]);
  assert.equal(existsSync(path.join(f.root, '.missionspec/runtime-selection.json')), false);
});
