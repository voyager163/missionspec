import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  chmodSync, chownSync, copyFileSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync,
  readdirSync, renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { openRuntimeStore as openBoundRuntimeStore } from '../dist/adapters/persistence/index.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { fixtureInventory } from './fixtures/filesystem-snapshot.mjs';

const workspace = { workspaceId: 'WSP-local', rootDigest: digestContent('test-worktree-root') };
const openRuntimeStore = (options) => openBoundRuntimeStore({ expectedWorkspace: workspace, ...options });
const revisions = {
  workspace,
  changeId: 'CHG-local', specification: digestContent('spec'), tasks: digestContent('tasks'),
  workflow: digestContent('workflow'), effects: digestContent('effects'), source: digestContent('source'),
};
const attempt = (id = 'ATT-first', workOrderId = 'WRK-first') => ({
  contractVersion: 1, id, workOrderId, sequence: { kind: 'initial' },
  observation: {
    state: 'host-returned', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:00:01.000Z',
    exitCode: 0, sourceAfter: revisions.source, reportedTaskStatus: 'claimed-complete',
  },
});
const snapshot = (id = 'RUN-first', attempts = []) => ({
  contractVersion: 1, id, revisions, state: 'pending', activeTask: null,
  pendingTasks: ['TSK-first'], attempts, quiescence: 'confirmed',
});
const evidence = (id = 'EVD-first', attemptId = null) => ({
  contractVersion: 1, id, revisions, source: revisions.source, checkId: 'CHK-first',
  checkDefinition: digestContent('check'), attemptId,
  storage: { state: 'unavailable', reason: 'not retained' },
});
const acceptance = (ids = ['EVD-first'], approval = 'APR-first') => ({
  contractVersion: 1, state: 'accepted', revisions, source: revisions.source, evidence: ids,
  approval: { id: approval },
});

function ok(result) {
  assert.equal(result.status, 'ok', JSON.stringify(result));
  return result.value;
}
function rejected(result, reason, code) {
  assert.notEqual(result.status, 'ok', JSON.stringify(result));
  assert.ok(result.error.fields.includes(reason), JSON.stringify(result));
  if (code !== undefined) assert.equal(result.error.code, code);
}
function fixture(t) {
  const root = path.join(process.cwd(), `.runtime-store-test-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, '.missionspec'), { mode: 0o700 });
  const directory = path.join(root, '.missionspec', 'state');
  return { root, directory, filename: path.join(directory, 'ledger.sqlite') };
}
async function opened(t, directory, mode = 'create', busyTimeoutMs = 25) {
  const store = ok(await openRuntimeStore({ directory, mode, busyTimeoutMs }));
  t.after(() => ok(store.close()));
  return store;
}
function inventory(directory) {
  return fixtureInventory(directory, digestContent, (name, stat, contents) => ({
    name, mode: stat.mode, size: stat.size, mtime: stat.mtimeNs, ctime: stat.ctimeNs, ino: stat.ino,
    dev: stat.dev, nlink: stat.nlink, contents,
  }));
}
function mutate(filename, operation) {
  const db = new DatabaseSync(filename);
  try { return operation(db); } finally { db.close(); }
}
async function seeded(t, directory) {
  const store = await opened(t, directory);
  const initial = snapshot('RUN-first', [attempt()]);
  const revision = ok(await store.commitRun({
    expectedRevision: 'absent', snapshot: initial, attempts: initial.attempts,
    evidence: [evidence('EVD-first', 'ATT-first')],
  })).revision;
  return { store, initial, revision };
}

test('runtime adapter module import and missing read-only opens create nothing', async (t) => {
  const { root, directory } = fixture(t);
  const before = inventory(root);
  const imported = spawnSync(process.execPath, ['--input-type=module', '-e',
    `await import(${JSON.stringify(new URL('../dist/adapters/persistence/index.js', import.meta.url).href)});`],
  { cwd: root, encoding: 'utf8' });
  assert.equal(imported.status, 0, imported.stderr);
  assert.deepEqual(inventory(root), before);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'missing', 'not-found');
  rejected(await openRuntimeStore({ directory, mode: 'read-write' }), 'missing');
  assert.deepEqual(inventory(root), before);
  mkdirSync(directory, { mode: 0o700 });
  const existingDirectory = inventory(root);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'missing');
  assert.deepEqual(inventory(root), existingDirectory);
});

test('unavailable built-in SQLite is an explicit blocker with no native fallback or created paths', (t) => {
  const { root, directory } = fixture(t);
  const before = inventory(root);
  const probe = spawnSync(process.execPath, ['--no-experimental-sqlite', '--input-type=module', '-e', `
    const {openRuntimeStore} = await import(${JSON.stringify(new URL('../dist/adapters/persistence/index.js', import.meta.url).href)});
    process.stdout.write(JSON.stringify(await openRuntimeStore(${JSON.stringify({
      directory, mode: 'create', expectedWorkspace: workspace,
    })})));
  `], { cwd: root, encoding: 'utf8' });
  assert.equal(probe.status, 0, probe.stderr);
  rejected(JSON.parse(probe.stdout), 'unavailable', 'capability-unavailable');
  assert.deepEqual(inventory(root), before);
});

test('explicit creation is exclusive, private, and exposes only storage operations', async (t) => {
  const { directory, filename } = fixture(t);
  const store = await opened(t, directory);
  assert.equal(lstatSync(directory).mode & 0o777, 0o700);
  assert.equal(lstatSync(filename).mode & 0o777, 0o600);
  assert.equal(store.db, undefined);
  assert.equal(store.resolve, undefined);
  assert.equal(store.requestConfirmation, undefined);
  assert.equal(path.basename(filename), 'ledger.sqlite');
  assert.equal(mutate(filename, (db) => db.prepare('PRAGMA user_version').get().user_version), 3);
  assert.deepEqual(mutate(filename, (db) => JSON.parse(
    db.prepare("SELECT payload FROM store_metadata WHERE id = 'workspace'").get().payload)), workspace);
  rejected(await openRuntimeStore({ directory, mode: 'create' }), 'conflict');
  assert.equal(ok(await store.readRun('RUN-absent')), null);
  assert.equal(ok(await store.readEvidence('EVD-absent')), null);
  ok(store.close());
  rejected(await store.readRun('RUN-first'), 'closed');
  ok(store.close());
});

test('state inspection reports exact database accounting without writes or a capacity reservation', async (t) => {
  const { root, directory, filename } = fixture(t);
  const { store } = await seeded(t, directory);
  ok(store.close());
  const readOnly = await opened(t, directory, 'read-only');
  const before = inventory(root);
  const report = ok(await readOnly.inspectState());
  assert.equal(report.schemaVersion, 3);
  assert.deepEqual(report.workspace, workspace);
  assert.equal(report.access, 'read-only');
  assert.equal(report.recordedQuiescence, 'confirmed');
  assert.deepEqual(report.records, {
    runs: 1, revisions: 1, attempts: 1, evidence: 1, acceptances: 0,
    pendingPrunes: 0, completedPrunes: 0,
  });
  assert.equal(report.capacity.databaseBytes, lstatSync(filename, { bigint: true }).size.toString());
  assert.equal(report.capacity.allocatedPageBytes, report.capacity.databaseBytes);
  assert(BigInt(report.capacity.reusablePageBytes) <= BigInt(report.capacity.databaseBytes));
  assert.match(report.capacity.filesystemAvailableBytes, /^(0|[1-9]\d*)$/u);
  assert.equal(report.capacity.reservation, 'none');
  assert.deepEqual(inventory(root), before);
  ok(readOnly.close());
  rejected(await readOnly.inspectState(), 'closed');
});

test('actual SQLite page exhaustion rolls back without deleting history or claiming capacity', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const execute = DatabaseSync.prototype.exec;
  let constrained = false;
  DatabaseSync.prototype.exec = function (sql) {
    if (!constrained && sql === 'BEGIN IMMEDIATE') {
      const pages = this.prepare('PRAGMA page_count').get().page_count;
      execute.call(this, `PRAGMA max_page_count = ${pages}`);
      constrained = true;
    }
    return execute.call(this, sql);
  };
  let result;
  try {
    result = await store.commitRun({
      expectedRevision: revision,
      snapshot: { ...initial, pendingTasks: Array.from({ length: 1000 }, (_, index) => `TSK-capacity-${index}`) },
      attempts: [], evidence: [],
    });
  } finally {
    DatabaseSync.prototype.exec = execute;
  }
  assert.equal(constrained, true);
  rejected(result, 'capacity', 'limit-reached');
  const after = ok(await store.readRun(initial.id));
  assert.equal(after.revision, revision);
  assert.deepEqual(after.snapshot, initial);
  assert.deepEqual(ok(await store.readRunEvidence(initial.id)), ['EVD-first']);
});

test('workspace binding is mandatory and malformed identities never create a ledger', async (t) => {
  const { root, directory } = fixture(t);
  const before = inventory(root);
  for (const expectedWorkspace of [
    undefined, { ...workspace, workspaceId: 'RUN-wrong-kind' },
    { ...workspace, rootDigest: 'not-a-digest' }, { ...workspace, confirmed: true },
  ]) {
    const result = await openRuntimeStore({ directory, mode: 'create', expectedWorkspace });
    assert.equal(result.status, 'blocked');
    assert.equal(result.error.code, 'invalid-input');
    assert.deepEqual(inventory(root), before);
  }
});

test('reopen requires both workspace identity and root binding even when all content hashes match', async (t) => {
  const { root, directory } = fixture(t);
  const { store } = await seeded(t, directory);
  ok(store.close());
  const before = inventory(root);
  for (const expectedWorkspace of [
    { ...workspace, workspaceId: 'WSP-other' },
    { ...workspace, rootDigest: digestContent('another-worktree-root') },
  ]) {
    for (const mode of ['read-only', 'read-write']) {
      rejected(await openRuntimeStore({ directory, mode, expectedWorkspace }), 'workspace-mismatch', 'scope-exceeded');
      assert.deepEqual(inventory(root), before);
    }
  }
});

test('copied ledgers and replayed run/evidence/acceptance records cannot cross workspace boundaries', async (t) => {
  const source = fixture(t);
  const { store, initial, revision } = await seeded(t, source.directory);
  ok(await store.recordAcceptance(acceptance()));
  const foreignWorkspace = { workspaceId: 'WSP-second', rootDigest: digestContent('second-root') };
  const foreignRevisions = { ...revisions, workspace: foreignWorkspace };
  assert.equal(foreignRevisions.specification, revisions.specification);
  assert.equal(foreignRevisions.source, revisions.source);
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, revisions: foreignRevisions }, attempts: [], evidence: [],
  }), 'workspace-mismatch');
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [],
    evidence: [{ ...evidence('EVD-foreign'), revisions: foreignRevisions }],
  }), 'workspace-mismatch');
  rejected(await store.recordAcceptance({ ...acceptance(), revisions: foreignRevisions }), 'workspace-mismatch');
  ok(store.close());
  const copied = fixture(t);
  mkdirSync(copied.directory, { mode: 0o700 });
  copyFileSync(source.filename, copied.filename);
  const before = inventory(copied.root);
  rejected(await openRuntimeStore({
    directory: copied.directory, mode: 'read-only', expectedWorkspace: foreignWorkspace,
  }), 'workspace-mismatch');
  assert.deepEqual(inventory(copied.root), before);
  const destination = fixture(t);
  const target = ok(await openRuntimeStore({
    directory: destination.directory, mode: 'create', expectedWorkspace: foreignWorkspace,
  }));
  t.after(() => ok(target.close()));
  rejected(await target.commitRun({
    expectedRevision: 'absent', snapshot: initial, attempts: initial.attempts, evidence: [],
  }), 'workspace-mismatch');
  rejected(await target.recordAcceptance(acceptance()), 'workspace-mismatch');
  assert.equal(ok(await target.readRun(initial.id)), null);
  const scoped = { ...initial, revisions: foreignRevisions };
  rejected(await target.commitRun({
    expectedRevision: 'absent', snapshot: scoped, attempts: scoped.attempts,
    evidence: [evidence('EVD-first', 'ATT-first')],
  }), 'workspace-mismatch');
  ok(await target.commitRun({
    expectedRevision: 'absent', snapshot: scoped, attempts: scoped.attempts,
    evidence: [{ ...evidence('EVD-first', 'ATT-first'), revisions: foreignRevisions }],
  }));
  const read = ok(await target.readRun(scoped.id));
  assert.deepEqual(read.snapshot.revisions.workspace, foreignWorkspace);
  assert.notEqual(read.revision, revision);
});

test('workspace metadata is rechecked on reads and every mutation, not just on open', async (t) => {
  const { root, directory, filename } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const payload = JSON.stringify({ ...workspace, workspaceId: 'WSP-replaced-metadata' });
  mutate(filename, (db) => db.prepare('UPDATE store_metadata SET payload = ?, digest = ?')
    .run(payload, digestContent(payload)));
  const before = inventory(root);
  rejected(await store.readRun(initial.id), 'workspace-mismatch');
  rejected(await store.readEvidence('EVD-first'), 'workspace-mismatch');
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [], evidence: [],
  }), 'workspace-mismatch');
  rejected(await store.recordAcceptance(acceptance()), 'workspace-mismatch');
  assert.deepEqual(inventory(root), before);
});

test('recomputed payload digests do not admit persisted records from another workspace', async (t) => {
  for (const table of ['runs', 'evidence', 'acceptances']) {
    const { directory, filename } = fixture(t);
    const { store } = await seeded(t, directory);
    ok(await store.recordAcceptance(acceptance()));
    ok(store.close());
    mutate(filename, (db) => {
      const original = JSON.parse(db.prepare(`SELECT payload FROM ${table}`).get().payload);
      const value = table === 'runs' ? original.snapshot : original;
      value.revisions.workspace = { ...workspace, workspaceId: 'WSP-foreign' };
      const payload = JSON.stringify(original);
      const column = table === 'runs' ? 'revision' : 'digest';
      db.prepare(`UPDATE ${table} SET payload = ?, ${column} = ?`).run(payload, digestContent(payload));
    });
    rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'corrupt');
  }
});

test('older prototype paths and schema versions fail explicitly without migration or parallel initialization', async (t) => {
  const fixtureOne = fixture(t);
  const oldDirectory = path.join(fixtureOne.root, '.missionspec-runtime');
  const before = inventory(fixtureOne.root);
  rejected(await openRuntimeStore({ directory: oldDirectory, mode: 'create' }), 'incompatible');
  assert.deepEqual(inventory(fixtureOne.root), before);
  mkdirSync(oldDirectory, { mode: 0o700 });
  writeFileSync(path.join(oldDirectory, 'runtime.sqlite'), 'prototype', { mode: 0o600 });
  rmSync(path.join(fixtureOne.root, '.missionspec'), { recursive: true });
  const prototypeBefore = inventory(fixtureOne.root);
  for (const mode of ['read-only', 'create']) {
    rejected(await openRuntimeStore({ directory: fixtureOne.directory, mode }), 'incompatible');
    assert.deepEqual(inventory(fixtureOne.root), prototypeBefore);
  }
  const fixtureTwo = fixture(t);
  mkdirSync(fixtureTwo.directory, { mode: 0o700 });
  writeFileSync(path.join(fixtureTwo.directory, 'runtime.sqlite'), 'prototype', { mode: 0o600 });
  const oldFileBefore = inventory(fixtureTwo.root);
  for (const mode of ['read-only', 'create']) {
    rejected(await openRuntimeStore({ directory: fixtureTwo.directory, mode }), 'incompatible');
    assert.deepEqual(inventory(fixtureTwo.root), oldFileBefore);
    assert.equal(existsSync(fixtureTwo.filename), false);
  }
});

test('real SQLite commit, acceptance idempotency and reopen durability', async (t) => {
  const { directory, filename } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  assert.deepEqual(ok(await store.readRun('RUN-first')), { revision, snapshot: initial });
  assert.deepEqual(ok(await store.readEvidence('EVD-first')), evidence('EVD-first', 'ATT-first'));
  const accepted = ok(await store.recordAcceptance(acceptance()));
  assert.deepEqual(ok(await store.recordAcceptance(acceptance())), accepted);
  assert.equal(mutate(filename, (db) => db.prepare('SELECT count(*) AS n FROM acceptances').get().n), 1);
  ok(store.close());
  const reopened = await opened(t, directory, 'read-write');
  assert.deepEqual(ok(await reopened.readRun('RUN-first')), { revision, snapshot: initial });
  assert.deepEqual(ok(await reopened.recordAcceptance(acceptance())), accepted);
  assert.deepEqual(readdirSync(directory), ['ledger.sqlite']);
});

test('two handles enforce CAS and evidence-only commits change the revision', async (t) => {
  const { directory } = fixture(t);
  const { store: first, initial, revision } = await seeded(t, directory);
  const second = await opened(t, directory, 'read-write');
  assert.equal(ok(await second.readRun('RUN-first')).revision, revision);
  const next = ok(await first.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [], evidence: [evidence('EVD-second')],
  })).revision;
  assert.notEqual(next, revision);
  rejected(await second.commitRun({
    expectedRevision: revision, snapshot: { ...initial, state: 'paused' }, attempts: [], evidence: [],
  }), 'stale-revision', 'stale-revision');
  rejected(await second.commitRun({
    expectedRevision: 'absent', snapshot: initial, attempts: [], evidence: [],
  }), 'stale-revision');
  assert.equal(ok(await second.readRun('RUN-first')).revision, next);
  assert.equal(ok(await second.commitRun({
    expectedRevision: next, snapshot: initial, attempts: initial.attempts,
    evidence: [evidence('EVD-first', 'ATT-first')],
  })).revision, next);
});

test('returning to an earlier snapshot does not reuse its revision (CAS ABA protection)', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const paused = ok(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, state: 'paused' }, attempts: [], evidence: [],
  })).revision;
  const returned = ok(await store.commitRun({
    expectedRevision: paused, snapshot: initial, attempts: [], evidence: [],
  })).revision;
  assert.notEqual(returned, revision);
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [], evidence: [],
  }), 'stale-revision');
});

test('failed multi-record commits roll back the run, history, attempts and earlier evidence inserts', async (t) => {
  const { directory, filename } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const nextAttempt = attempt('ATT-next', 'WRK-next');
  const before = mutate(filename, (db) => ['runs', 'run_history', 'attempts', 'evidence'].map((table) =>
    db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n));
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, attempts: [...initial.attempts, nextAttempt] },
    attempts: [nextAttempt], evidence: [evidence('EVD-next', 'ATT-next'), evidence('EVD-orphan', 'ATT-missing')],
  }), 'conflict');
  assert.deepEqual(ok(await store.readRun('RUN-first')), { revision, snapshot: initial });
  assert.equal(ok(await store.readEvidence('EVD-next')), null);
  assert.deepEqual(mutate(filename, (db) => ['runs', 'run_history', 'attempts', 'evidence'].map((table) =>
    db.prepare(`SELECT count(*) AS n FROM ${table}`).get().n)), before);
  ok(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, state: 'paused' }, attempts: [], evidence: [],
  }));
});

test('attempts, evidence and acceptance identities cannot be rewritten', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const changed = { ...attempt(), observation: { ...attempt().observation, reportedTaskStatus: 'claimed-incomplete' } };
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, attempts: [changed] }, attempts: [changed], evidence: [],
  }), 'conflict');
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, attempts: [] }, attempts: [], evidence: [],
  }), 'conflict');
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [],
    evidence: [{ ...evidence('EVD-first', 'ATT-first'), storage: { state: 'unavailable', reason: 'changed' } }],
  }), 'conflict');
  ok(await store.recordAcceptance(acceptance()));
  rejected(await store.recordAcceptance({ ...acceptance(), source: digestContent('different') }), 'conflict');
});

test('orphan, cross-run, cross-work-order and source-mismatched references fail closed', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const reusedOrder = attempt('ATT-other', 'WRK-first');
  rejected(await store.commitRun({
    expectedRevision: 'absent', snapshot: snapshot('RUN-other', [reusedOrder]), attempts: [reusedOrder], evidence: [],
  }), 'conflict');
  rejected(await store.commitRun({
    expectedRevision: 'absent', snapshot: snapshot('RUN-other'), attempts: [], evidence: [evidence('EVD-other', 'ATT-first')],
  }), 'conflict');
  const repair = {
    ...attempt('ATT-repair', 'WRK-other'),
    sequence: { kind: 'repair', number: 1, failedAttempt: 'ATT-first' },
  };
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: { ...initial, attempts: [...initial.attempts, repair] },
    attempts: [repair], evidence: [],
  }), 'conflict');
  rejected(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [],
    evidence: [{ ...evidence('EVD-wrong-source', 'ATT-first'), source: digestContent('wrong') }],
  }), 'conflict');
  rejected(await store.recordAcceptance(acceptance(['EVD-missing'])), 'conflict');
  ok(await store.commitRun({
    expectedRevision: 'absent', snapshot: snapshot('RUN-other'), attempts: [], evidence: [evidence('EVD-other')],
  }));
  rejected(await store.recordAcceptance(acceptance(['EVD-first', 'EVD-other'])), 'conflict');
});

test('repair observations form one bounded immutable sequence and retained evidence is only a reference', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const repair = { ...attempt('ATT-repair'), sequence: { kind: 'repair', number: 1, failedAttempt: 'ATT-first' } };
  const retained = { ...evidence('EVD-retained', 'ATT-repair'), storage: {
    state: 'retained', path: 'evidence/not-read-by-store.txt', digest: digestContent('external bytes'),
  } };
  const repaired = { ...initial, attempts: [...initial.attempts, repair] };
  const next = ok(await store.commitRun({
    expectedRevision: revision, snapshot: repaired, attempts: [repair], evidence: [retained],
  })).revision;
  assert.deepEqual(ok(await store.readEvidence('EVD-retained')), retained);
  const branch = { ...repair, id: 'ATT-forked' };
  rejected(await store.commitRun({
    expectedRevision: next, snapshot: { ...repaired, attempts: [...repaired.attempts, branch] },
    attempts: [branch], evidence: [],
  }), 'conflict');
  const second = { ...attempt('ATT-repair-two'), sequence: { kind: 'repair', number: 2, failedAttempt: 'ATT-repair' } };
  ok(await store.commitRun({
    expectedRevision: next, snapshot: { ...repaired, attempts: [...repaired.attempts, second] },
    attempts: [second], evidence: [],
  }));
});

test('unknown outcomes and unavailable/pruned evidence survive without inferred completion or authority', async (t) => {
  const { directory } = fixture(t);
  const store = await opened(t, directory);
  const unknown = {
    ...attempt(), observation: { state: 'outcome-unknown', error: {
      code: 'effect-outcome-unknown', message: 'Host detached', retry: 'after-reconciliation', fields: ['host'],
    } },
  };
  const run = { ...snapshot('RUN-first', [unknown]), state: 'outcome-unknown', quiescence: 'unconfirmed' };
  const pruned = { ...evidence('EVD-pruned'), storage: {
    state: 'pruned', prunedAt: '2026-01-02T00:00:00Z', approval: { id: 'APR-pruning' },
  } };
  ok(await store.commitRun({
    expectedRevision: 'absent', snapshot: run, attempts: [unknown], evidence: [evidence(), pruned],
  }));
  rejected(await store.recordAcceptance(acceptance()), 'conflict');
  ok(store.close());
  const reader = await opened(t, directory, 'read-only');
  assert.deepEqual(ok(await reader.readRun('RUN-first')).snapshot, run);
  assert.deepEqual(ok(await reader.readEvidence('EVD-first')).storage, evidence().storage);
  assert.deepEqual(ok(await reader.readEvidence('EVD-pruned')), pruned);
});

test('read-only status, missing IDs, rejected writes and close leave no file-content or mtime changes', async (t) => {
  const { root, directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  ok(store.close());
  const before = inventory(root);
  const reader = await opened(t, directory, 'read-only');
  assert.equal(ok(await reader.readRun('RUN-first')).revision, revision);
  assert.equal(ok(await reader.readRun('RUN-none')), null);
  assert.equal(ok(await reader.readEvidence('EVD-none')), null);
  rejected(await reader.commitRun({ expectedRevision: revision, snapshot: initial, attempts: [], evidence: [] }), 'read-only');
  rejected(await reader.recordAcceptance(acceptance()), 'read-only');
  ok(reader.close());
  assert.deepEqual(inventory(root), before);
});

test('busy SQLite locks are bounded and recover after explicit unlock', async (t) => {
  const { directory, filename } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const blocker = new DatabaseSync(filename);
  t.after(() => blocker.close());
  blocker.exec('BEGIN IMMEDIATE');
  const start = performance.now();
  rejected(await store.commitRun({ expectedRevision: revision, snapshot: initial, attempts: [], evidence: [] }), 'busy');
  assert.ok(performance.now() - start < 1500);
  blocker.exec('ROLLBACK');
  assert.equal(ok(await store.commitRun({
    expectedRevision: revision, snapshot: initial, attempts: [], evidence: [],
  })).revision, revision);
});

test('an uncertain commit is not reported as success and blocks writes until reopen', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const exec = DatabaseSync.prototype.exec;
  let armed = true;
  DatabaseSync.prototype.exec = function (sql) {
    const result = exec.call(this, sql);
    if (armed && sql === 'COMMIT') {
      armed = false;
      throw new Error('Injected transport error after the real SQLite commit');
    }
    return result;
  };
  try {
    const result = await store.commitRun({
      expectedRevision: revision, snapshot: { ...initial, state: 'paused' }, attempts: [], evidence: [],
    });
    assert.equal(result.status, 'outcome-unknown');
    assert.equal(result.reconciliationRequired, true);
    const observed = ok(await store.readRun('RUN-first'));
    assert.equal(observed.snapshot.state, 'paused');
    assert.equal((await store.commitRun({
      expectedRevision: observed.revision, snapshot: observed.snapshot, attempts: [], evidence: [],
    })).status, 'outcome-unknown');
    ok(store.close());
  } finally {
    DatabaseSync.prototype.exec = exec;
  }
  const reopened = await opened(t, directory, 'read-write');
  assert.equal(ok(await reopened.readRun('RUN-first')).snapshot.state, 'paused');
});

test('failed rollback is explicitly unknown and a failed close is never silently marked closed', async (t) => {
  const { directory } = fixture(t);
  const { store, initial, revision } = await seeded(t, directory);
  const exec = DatabaseSync.prototype.exec;
  const close = DatabaseSync.prototype.close;
  DatabaseSync.prototype.exec = function (sql) {
    if (sql === 'ROLLBACK') throw new Error('Injected rollback failure');
    return exec.call(this, sql);
  };
  DatabaseSync.prototype.close = function () { throw new Error('Injected close failure'); };
  try {
    const result = await store.commitRun({
      expectedRevision: revision, snapshot: { ...initial, state: 'paused' }, attempts: [],
      evidence: [evidence('EVD-orphan', 'ATT-no-such-attempt')],
    });
    assert.equal(result.status, 'outcome-unknown');
    assert.equal(result.reconciliationRequired, true);
    assert.notEqual(store.close().status, 'ok');
  } finally {
    DatabaseSync.prototype.exec = exec;
    DatabaseSync.prototype.close = close;
  }
  ok(store.close());
  const reopened = await opened(t, directory, 'read-write');
  assert.equal(ok(await reopened.readRun('RUN-first')).revision, revision);
});

test('unknown versions, extra schema objects and invalid SQLite files are not repaired', async (t) => {
  for (const alteration of ['PRAGMA user_version = 99', 'PRAGMA user_version = 1', 'PRAGMA user_version = 2', 'PRAGMA application_id = 1',
    'CREATE TABLE unexpected (value TEXT)']) {
    const { root, directory, filename } = fixture(t);
    const store = await opened(t, directory);
    ok(store.close());
    mutate(filename, (db) => db.exec(alteration));
    const before = inventory(root);
    rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'incompatible', 'unsupported-version');
    assert.deepEqual(inventory(root), before);
  }
  const { directory, filename } = fixture(t);
  mkdirSync(directory, { mode: 0o700 });
  writeFileSync(filename, 'not a database', { mode: 0o600 });
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'corrupt', 'persistence-failed');
});

test('malformed, digest-mismatched, extra-field and identity-mismatched stored rows fail validation', async (t) => {
  const corruptions = [
    (db) => db.prepare("UPDATE evidence SET payload = 'not JSON'").run(),
    (db) => {
      const payload = JSON.stringify({ ...evidence('EVD-first', 'ATT-first'), approved: true });
      db.prepare('UPDATE evidence SET payload = ?, digest = ?').run(payload, digestContent(payload));
    },
    (db) => {
      const payload = JSON.stringify({ ...evidence('EVD-first', 'ATT-first'), contractVersion: 99 });
      db.prepare('UPDATE evidence SET payload = ?, digest = ?').run(payload, digestContent(payload));
    },
    (db) => db.prepare("UPDATE evidence SET id = 'EVD-different'").run(),
    (db) => {
      const payload = '{"bad":';
      db.prepare('UPDATE evidence SET payload = ?, digest = ?').run(payload, digestContent(payload));
    },
    (db) => db.exec('DELETE FROM run_history'),
  ];
  for (const corrupt of corruptions) {
    const { root, directory, filename } = fixture(t);
    const { store } = await seeded(t, directory);
    ok(store.close());
    mutate(filename, corrupt);
    const before = inventory(root);
    rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'corrupt', 'persistence-failed');
    assert.deepEqual(inventory(root), before);
  }
});

test('persisted acceptance references and attempt union payloads are revalidated on status', async (t) => {
  for (const table of ['acceptances', 'attempts']) {
    const { directory, filename } = fixture(t);
    const { store } = await seeded(t, directory);
    ok(await store.recordAcceptance(acceptance()));
    ok(store.close());
    mutate(filename, (db) => {
      const value = table === 'acceptances' ? { ...acceptance(), evidence: ['EVD-missing'] }
        : { ...attempt(), observation: { state: 'outcome-unknown', error: {
          code: 'not-a-closed-error-code', message: 'bad input', retry: 'never', fields: [],
        } } };
      const payload = JSON.stringify(value);
      db.prepare(`UPDATE ${table} SET payload = ?, digest = ?`).run(payload, digestContent(payload));
    });
    rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'corrupt');
  }
});
test('WAL headers and journal sidecars are rejected without recovery, deletion or hidden writes', async (t) => {
  const { root, directory, filename } = fixture(t);
  const store = await opened(t, directory);
  ok(store.close());
  mutate(filename, (db) => db.exec('PRAGMA journal_mode = WAL'));
  const walBefore = inventory(root);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'incompatible');
  assert.deepEqual(inventory(root), walBefore);
  const other = fixture(t);
  const writer = await opened(t, other.directory);
  ok(writer.close());
  writeFileSync(`${other.filename}-journal`, 'unreconciled journal', { mode: 0o600 });
  const journalBefore = inventory(other.root);
  rejected(await openRuntimeStore({ directory: other.directory, mode: 'read-only' }), 'busy');
  assert.deepEqual(inventory(other.root), journalBefore);
});

test('active WAL databases are refused rather than opened with immutable=1 or downgraded', async (t) => {
  const { root, directory, filename } = fixture(t);
  const store = await opened(t, directory);
  ok(store.close());
  const writer = new DatabaseSync(filename);
  t.after(() => writer.close());
  writer.exec('PRAGMA journal_mode = WAL; BEGIN IMMEDIATE; PRAGMA user_version = 1; COMMIT');
  assert.equal(existsSync(`${filename}-wal`), true);
  const before = inventory(root);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'busy');
  rejected(await openRuntimeStore({ directory, mode: 'read-write' }), 'busy');
  assert.deepEqual(inventory(root), before);
});

test('symlinks, hard links, broad permissions, invalid options and malformed inputs are rejected', async (t) => {
  const { root, directory, filename } = fixture(t);
  const store = await opened(t, directory);
  const alias = path.join(root, 'alias');
  symlinkSync(root, alias);
  rejected(await openRuntimeStore({ directory: path.join(alias, '.missionspec', 'state'), mode: 'read-only' }), 'unavailable');
  chmodSync(filename, 0o644);
  rejected(await store.readRun('RUN-first'), 'unavailable');
  chmodSync(filename, 0o600);
  chmodSync(filename, 0o400);
  rejected(await openRuntimeStore({ directory, mode: 'read-write' }), 'unavailable');
  const reader = await opened(t, directory, 'read-only');
  assert.equal(ok(await reader.readRun('RUN-first')), null);
  ok(reader.close());
  chmodSync(filename, 0o600);
  const hardLink = path.join(root, 'hard-link.sqlite');
  linkSync(filename, hardLink);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'unavailable');
  rmSync(hardLink);
  chmodSync(directory, 0o750);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'unavailable');
  chmodSync(directory, 0o700);
  for (const options of [
    { directory: '.', mode: 'create' },
    { directory, mode: 'read-only', busyTimeoutMs: Infinity },
    { directory, mode: 'read-only', approved: true },
  ]) assert.notEqual((await openRuntimeStore(options)).status, 'ok');
  for (const change of [
    { state: 'completed' }, { contractVersion: 2 }, { approved: true },
    { revisions: { ...revisions, workspace: undefined } },
    { pendingTasks: ['TSK-first', 'TSK-first'] }, { pendingTasks: [true] },
    { attempts: [{ ...attempt(), observation: { state: 'host-returned' } }] },
    { attempts: [{ ...attempt(), observation: { state: 'running', startedAt: '2026-02-30T00:00:00Z' } }] },
    { attempts: [{ ...attempt(), sequence: { kind: 'repair', number: 3, failedAttempt: 'ATT-old' } }] },
  ]) {
    assert.notEqual((await store.commitRun({
      expectedRevision: 'absent', snapshot: { ...snapshot(), ...change }, attempts: [], evidence: [],
    })).status, 'ok');
  }
  assert.notEqual((await store.readRun("RUN-x'; DROP TABLE runs; --")).status, 'ok');
  assert.notEqual((await store.recordAcceptance({ ...acceptance(), approval: { id: 'APR-first', confirmed: true } })).status, 'ok');
  assert.notEqual((await store.recordAcceptance(acceptance([]))).status, 'ok');
  assert.equal(existsSync(filename), true);
});

test('replacement of an open database path is detected before another operation', async (t) => {
  const { directory, filename } = fixture(t);
  const store = await opened(t, directory);
  renameSync(filename, `${filename}.old`);
  writeFileSync(filename, readFileSync(`${filename}.old`), { mode: 0o600 });
  rejected(await store.readRun('RUN-first'), 'unavailable');
});

test('only root/current-user-owned sticky writable ancestors are allowed, never a public state directory', async (t) => {
  const { root, directory } = fixture(t);
  chmodSync(root, 0o1777);
  const store = await opened(t, directory);
  ok(store.close());
  const reader = await opened(t, directory, 'read-only');
  ok(reader.close());
  chmodSync(root, 0o777);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'unavailable');
  chmodSync(root, 0o1777);
  chmodSync(directory, 0o1777);
  rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'unavailable');
  chmodSync(directory, 0o700);
  if (process.getuid() === 0) {
    for (const changedOwner of [root, path.join(root, '.missionspec')]) {
      chownSync(changedOwner, 12345, process.getgid());
      try {
        rejected(await openRuntimeStore({ directory, mode: 'read-only' }), 'unavailable');
      } finally {
        chownSync(changedOwner, 0, process.getgid());
      }
    }
  }
  assert.equal(ok(await (await opened(t, directory, 'read-only')).readRun('RUN-absent')), null);
});

test('Windows remains explicitly unsupported before any file creation; no ACL readiness is inferred', (t) => {
  const { root, directory } = fixture(t);
  const before = inventory(root);
  const probe = spawnSync(process.execPath, ['--input-type=module', '-e', `
    const {openRuntimeStore} = await import(${JSON.stringify(new URL('../dist/adapters/persistence/index.js', import.meta.url).href)});
    Object.defineProperty(process, 'platform', {value: 'win32'});
    process.stdout.write(JSON.stringify(await openRuntimeStore(${JSON.stringify({
      directory: 'C:\\workspace\\.missionspec\\state', mode: 'create', expectedWorkspace: workspace,
    })})));
  `], { cwd: root, encoding: 'utf8' });
  assert.equal(probe.status, 0, probe.stderr);
  rejected(JSON.parse(probe.stdout), 'unavailable', 'capability-unavailable');
  assert.deepEqual(inventory(root), before);
});
