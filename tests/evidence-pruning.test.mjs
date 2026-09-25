import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { link, lstat, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalEvidencePruning } from '../dist/application/evidence-pruning.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestEffectScope } from '../dist/kernel/effects.js';
import { digestContent } from '../dist/kernel/revisions.js';

const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };

// TEST ONLY: admission responses, not qualified human identity or a production authority issuer.
function authorityFixture(now) {
  const approvals = new Map();
  return {
    onResolve: undefined,
    issue(request) {
      const reference = { id: `APR-${randomUUID()}` };
      const parsed = parseApprovalRequest(request);
      approvals.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference,
        assurance: { kind: 'local-user', channel: 'qualified-host-callback',
          qualificationEvidence: digestContent('TEST ONLY, not human or native-host qualification') },
        request: parsed, requestDigest: digestApprovalRequest(parsed), issuedAt: now,
        expiresAt: new Date(Date.parse(now) + 3_600_000).toISOString(),
      });
      return reference;
    },
    revoke(reference) { approvals.delete(reference.id); },
    async resolve(reference) {
      if (this.onResolve) await this.onResolve(reference);
      return { status: 'ok', value: approvals.has(reference.id)
        ? { state: 'current', approval: approvals.get(reference.id) } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
}

async function fixture(t) {
  const root = path.join(process.cwd(), `.evidence-pruning-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const authority = authorityFixture(now);
  let app = await LocalWorkflow.open(root, { authority, now: () => now });
  const setup = await app.previewSetup();
  await app.apply(setup, authority.issue(setup.request));
  const workspace = (await app.project()).workspace;
  const stores = [];
  t.after(() => { for (const store of stores) ok(store.close()); });
  const open = async (mode = 'read-write') => {
    const store = ok(await openRuntimeStore({ directory: path.join(root, '.missionspec/state'), expectedWorkspace: workspace, mode }));
    stores.push(store);
    return store;
  };
  const store = await open('create');
  const revisions = {
    workspace, changeId: 'CHG-pruning-fixture', specification: digestContent('fixture specification'),
    tasks: digestContent('fixture tasks'), workflow: digestContent('fixture workflow'),
    effects: digestEffectScope([]), source: digestContent('fixture declared source'),
  };
  const ids = ['EVD-pruning-first', 'EVD-pruning-second'];
  const evidence = [];
  for (const [index, id] of ids.entries()) {
    const executed = spawnSync(process.execPath, ['-e', `console.log("private raw output ${index}"); process.exitCode = ${index};`],
      { encoding: 'utf8' });
    assert.equal(executed.status, index, executed.stderr);
    const raw = await app.files.recordRuntime('evidence', id, {
      schemaVersion: 1, evidenceId: id, basis: 'executed', result: executed.status === 0 ? 'passed' : 'failed',
      output: JSON.stringify({ stdout: executed.stdout, stderr: executed.stderr, exitCode: executed.status }),
    });
    evidence.push({
      contractVersion: 1, id, revisions, source: revisions.source, checkId: `CHK-pruning-${index}`,
      checkDefinition: digestContent(`fixture definition ${index}`), attemptId: null,
      storage: { state: 'retained', path: raw.path, digest: raw.digest },
    });
  }
  const snapshot = {
    contractVersion: 1, id: 'RUN-pruning-fixture', revisions, state: 'quiesced',
    activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed',
  };
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot, attempts: [], evidence }));
  const acceptance = {
    contractVersion: 1, state: 'accepted', revisions, source: revisions.source, evidence: ids,
    approval: { id: 'APR-historical-test-fixture' },
  };
  // A pre-existing storage fixture, not an acceptance issued by this pruning workflow.
  ok(await store.recordAcceptance(acceptance));
  const f = { root, now, authority, workspace, store, app, ids, evidence, acceptance, snapshot, open };
  f.reopen = async () => {
    ok(f.store.close());
    f.store = await open();
    f.app = await LocalWorkflow.open(root, { authority, store: f.store, now: () => now });
    f.pruning = new LocalEvidencePruning(f.app, f.store, authority, { now: () => now });
  };
  await f.reopen();
  return f;
}

async function prepared(f, ids = f.ids) {
  const preview = await f.pruning.preview(ids);
  const approval = f.authority.issue(preview.request);
  return {
    preview, approval,
    record: { schemaVersion: 1, id: preview.id, plan: preview.plan, request: preview.request, approval, preparedAt: f.now },
  };
}

function sql(f, operation) {
  const db = new DatabaseSync(path.join(f.root, '.missionspec/state/ledger.sqlite'));
  try { return operation(db); } finally { db.close(); }
}

async function inventory(root) {
  const result = [];
  async function walk(relative = '') {
    for (const entry of await readdir(path.join(root, relative), { withFileTypes: true })) {
      const file = path.join(relative, entry.name);
      const stat = await lstat(path.join(root, file), { bigint: true });
      result.push([file, stat.mode, stat.mtimeNs, stat.ctimeNs, stat.ino,
        entry.isDirectory() ? null : digestContent(await readFile(path.join(root, file)))]);
      if (entry.isDirectory()) await walk(file);
    }
  }
  await walk();
  return result.sort((a, b) => a[0].localeCompare(b[0]));
}

async function crash(f, record, phase) {
  ok(f.store.close());
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync} from 'node:fs';
    import {LocalWorkspace} from ${JSON.stringify(new URL('../dist/adapters/filesystem/local-workspace.js', import.meta.url).href)};
    import {openRuntimeStore} from ${JSON.stringify(new URL('../dist/adapters/persistence/index.js', import.meta.url).href)};
    import {withEvidencePruneLock,removePreparedEvidence} from ${JSON.stringify(new URL('../dist/adapters/persistence/evidence-files.js', import.meta.url).href)};
    const {root,record,phase} = JSON.parse(readFileSync(0,'utf8'));
    const files = await LocalWorkspace.open(root);
    const opened = await openRuntimeStore({directory: root+'/.missionspec/state', mode:'read-write', expectedWorkspace:record.plan.inventory.workspace});
    if (opened.status !== 'ok') throw new Error(JSON.stringify(opened));
    await withEvidencePruneLock(files, record.plan.inventory.workspace, record.id, async () => {
      if (phase === 'before-prepare') process.exit(0);
      const prepared = await opened.value.evidencePruning.prepareEvidencePrune(record);
      if (prepared.status !== 'ok') throw new Error(JSON.stringify(prepared));
      if (phase === 'after-delete') {
        await removePreparedEvidence(files, record.plan.inventory.workspace, record.plan.inventory.items[0]);
      }
      process.exit(0);
    });
  `], { input: JSON.stringify({ root: f.root, record, phase }), encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(await readFile(path.join(f.root, '.missionspec/transaction.lock'), 'utf8')).kind, 'evidence-prune');
  await f.reopen();
}

test('prune preview is read-only and binds exact files, original outcomes and accepted-history impact', async (t) => {
  const f = await fixture(t);
  const before = await inventory(f.root);
  const preview = await f.pruning.preview(f.ids);
  assert.deepEqual(preview.plan.inventory.items.map((item) => item.id), f.ids);
  assert.deepEqual(preview.plan.observations.map((item) => item.result), ['passed', 'failed']);
  assert.equal(preview.plan.inventory.acceptances[0].approval.id, f.acceptance.approval.id);
  assert.deepEqual(preview.plan.inventory.acceptances[0].affectedEvidence, f.ids);
  assert.deepEqual(preview.request.effects.map((effect) => [effect.kind, effect.path, effect.expected]),
    f.evidence.map((item) => ['file-remove', item.storage.path, item.storage.digest]));
  assert.equal(JSON.stringify(preview.plan).includes('private raw output'), false);
  assert.equal(await f.pruning.status(preview.id), null);
  assert.deepEqual(await f.pruning.pending(), []);
  assert.deepEqual(await inventory(f.root), before);
});

test('commit preserves original evidence/acceptance bytes and appends immutable compact preparation/completion', async (t) => {
  const f = await fixture(t);
  const before = sql(f, (db) => ({
    evidence: db.prepare('SELECT id, payload, digest FROM evidence ORDER BY id').all(),
    acceptance: db.prepare('SELECT approval_id, payload, digest FROM acceptances').all(),
  }));
  const { preview, approval } = await prepared(f);
  const completed = await f.pruning.commit(preview, approval);
  assert.equal(completed.state, 'pruned');
  assert.equal(completed.prepared.approval.id, approval.id);
  for (const item of f.evidence) {
    await assert.rejects(readFile(path.join(f.root, item.storage.path)), { code: 'ENOENT' });
    assert.equal(ok(await f.store.readEvidence(item.id)).storage.state, 'pruned');
    assert.equal((await f.app.readObservation(item.id)).state, 'unavailable');
  }
  assert.deepEqual(ok(await f.store.readRunEvidence(f.snapshot.id)), []);
  assert.deepEqual(ok(await f.store.readAcceptance(f.acceptance.approval)), f.acceptance);
  assert.deepEqual(sql(f, (db) => ({
    evidence: db.prepare('SELECT id, payload, digest FROM evidence ORDER BY id').all(),
    acceptance: db.prepare('SELECT approval_id, payload, digest FROM acceptances').all(),
  })), before);
  assert.equal(sql(f, (db) => db.prepare('SELECT count(*) n FROM evidence_prune_prepared').get().n), 1);
  assert.equal(sql(f, (db) => db.prepare('SELECT count(*) n FROM evidence_prune_completed').get().n), 1);
  await f.reopen();
  assert.equal((await f.pruning.status(preview.id)).state, 'pruned');
});

test('actual child exit after preparation leaves bytes unavailable and a same-job dead lock recoverable', async (t) => {
  const f = await fixture(t);
  const { record, approval, preview } = await prepared(f);
  await crash(f, record, 'after-prepare');
  assert.equal(ok(await f.store.readEvidence(f.ids[0])).storage.state, 'unavailable');
  assert.deepEqual(ok(await f.store.readRunEvidence(f.snapshot.id)), []);
  for (const item of f.evidence) assert.equal(digestContent(await readFile(path.join(f.root, item.storage.path))), item.storage.digest);
  assert.equal((await f.pruning.pending()).length, 1);
  const before = await inventory(f.root);
  assert.deepEqual((await f.pruning.previewRecovery(preview.id)).remaining.map((item) => item.state), ['retained', 'retained']);
  assert.deepEqual(await inventory(f.root), before);
  const completed = await f.pruning.recover(preview.id, approval);
  assert.equal(completed.state, 'pruned');
  await assert.rejects(readFile(path.join(f.root, '.missionspec/transaction.lock')), { code: 'ENOENT' });
});

test('actual exit after one delete resumes remaining files and preserves the prepared request', async (t) => {
  const f = await fixture(t);
  const { record, approval, preview } = await prepared(f);
  await crash(f, record, 'after-delete');
  assert.deepEqual((await f.pruning.previewRecovery(preview.id)).remaining.map((item) => item.state), ['already-absent', 'retained']);
  f.authority.revoke(approval);
  await assert.rejects(f.pruning.recover(preview.id, approval), { code: 'authority-required' });
  const unrelated = f.authority.issue({ ...preview.request, purpose: 'acceptance' });
  await assert.rejects(f.pruning.recover(preview.id, unrelated), { code: 'scope-exceeded' });
  const current = f.authority.issue(preview.request);
  const completed = await f.pruning.recover(preview.id, current);
  assert.equal(completed.prepared.approval.id, approval.id);
  assert.equal(completed.completion.approval.id, current.id);
  assert.deepEqual(completed.prepared.request, record.request);
});

test('exit before preparation has no availability effect and explicit same-plan retry can recover only its dead lock', async (t) => {
  const f = await fixture(t);
  const { record, preview, approval } = await prepared(f);
  await crash(f, record, 'before-prepare');
  assert.equal(await f.pruning.status(preview.id), null);
  assert.equal(ok(await f.store.readEvidence(f.ids[0])).storage.state, 'retained');
  assert.equal((await f.pruning.commit(preview, approval)).state, 'pruned');
});

test('user edits after prepare are preserved; recovery remains pending instead of falsely marking deletion', async (t) => {
  const f = await fixture(t);
  const { record, preview, approval } = await prepared(f);
  await crash(f, record, 'after-prepare');
  const target = path.join(f.root, f.evidence[0].storage.path);
  const original = await readFile(target);
  await writeFile(target, 'user changed raw evidence', { mode: 0o600 });
  await assert.rejects(f.pruning.recover(preview.id, approval), { code: 'stale-revision' });
  assert.equal(await readFile(target, 'utf8'), 'user changed raw evidence');
  assert.equal((await f.pruning.status(preview.id)).state, 'prepared');
  assert.equal(sql(f, (db) => db.prepare('SELECT count(*) n FROM evidence_prune_completed').get().n), 0);
  await writeFile(target, original, { mode: 0o600 });
  assert.equal((await f.pruning.recover(preview.id, approval)).state, 'pruned');
});

test('raw hash is checked after the last authority callback immediately before unlink', async (t) => {
  const f = await fixture(t);
  const { preview, approval } = await prepared(f, [f.ids[0]]);
  const target = path.join(f.root, f.evidence[0].storage.path);
  let changed = false;
  f.authority.onResolve = async () => {
    const state = await f.pruning.status(preview.id);
    if (!changed && state?.state === 'prepared') {
      changed = true;
      await writeFile(target, 'edited after prepare', { mode: 0o600 });
    }
  };
  await assert.rejects(f.pruning.commit(preview, approval), { code: 'stale-revision' });
  assert.equal(await readFile(target, 'utf8'), 'edited after prepare');
  assert.equal((await f.pruning.status(preview.id)).state, 'prepared');
});

test('hard links and dangling symlinks cannot be deleted or counted as absent', async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, f.evidence[0].storage.path);
  const alias = path.join(f.root, 'raw-hard-link');
  await link(target, alias);
  await assert.rejects(f.pruning.preview([f.ids[0]]), { code: 'scope-exceeded' });
  await rm(alias);
  const { record, preview, approval } = await prepared(f, [f.ids[0]]);
  await crash(f, record, 'after-prepare');
  await link(target, alias);
  await assert.rejects(f.pruning.recover(preview.id, approval), { code: 'scope-exceeded' });
  await rm(alias);
  await rm(target);
  await symlink(path.join(f.root, 'missing-user-file'), target);
  await assert.rejects(f.pruning.recover(preview.id, approval), { code: 'scope-exceeded' });
  assert.equal((await lstat(target)).isSymbolicLink(), true);
  assert.equal((await f.pruning.status(preview.id)).state, 'prepared');
});

test('active runs, changed run revisions and new accepted-history impact invalidate preview', async (t) => {
  const f = await fixture(t);
  const { preview, approval } = await prepared(f);
  ok(await f.store.recordAcceptance({ ...f.acceptance, approval: { id: 'APR-added-history' } }));
  await assert.rejects(f.pruning.commit(preview, approval), { code: 'stale-revision' });
  assert.equal(await f.pruning.status(preview.id), null);
  const next = await prepared(f);
  const run = ok(await f.store.readRun(f.snapshot.id));
  ok(await f.store.commitRun({
    expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'running', quiescence: 'unconfirmed' },
    attempts: [], evidence: [],
  }));
  await assert.rejects(f.pruning.preview(f.ids), { code: 'conflict' });
  await assert.rejects(f.pruning.commit(next.preview, next.approval), { code: 'conflict' });
  for (const item of f.evidence) assert.equal(digestContent(await readFile(path.join(f.root, item.storage.path))), item.storage.digest);
});

test('prepared pruning fences all run writes and newly accepted uses of unavailable evidence', async (t) => {
  const f = await fixture(t);
  const { record, preview, approval } = await prepared(f);
  ok(await f.store.evidencePruning.prepareEvidencePrune(record));
  const run = ok(await f.store.readRun(f.snapshot.id));
  assert.equal((await f.store.commitRun({
    expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'running', quiescence: 'unconfirmed' }, attempts: [], evidence: [],
  })).status, 'blocked');
  assert.equal((await f.store.recordAcceptance({ ...f.acceptance, approval: { id: 'APR-late-acceptance' } })).status, 'blocked');
  assert.equal((await f.store.evidencePruning.inspectEvidencePrune(f.ids)).status, 'blocked');
  assert.equal((await f.pruning.recover(preview.id, approval)).state, 'pruned');
  assert.equal((await f.store.recordAcceptance({ ...f.acceptance, approval: { id: 'APR-after-prune' } })).status, 'blocked');
});

test('read-only pruning queries create nothing and recovery cannot delete before a writable store is selected', async (t) => {
  const f = await fixture(t);
  const { record, preview, approval } = await prepared(f);
  ok(await f.store.evidencePruning.prepareEvidencePrune(record));
  const reader = await f.open('read-only');
  const app = await LocalWorkflow.open(f.root, { store: reader, authority: f.authority, now: () => f.now });
  const pruning = new LocalEvidencePruning(app, reader, f.authority, { now: () => f.now });
  const before = await inventory(f.root);
  assert.equal((await pruning.status(preview.id)).state, 'prepared');
  assert.equal((await pruning.pending()).length, 1);
  assert.equal((await pruning.previewRecovery(preview.id)).remaining.length, 2);
  await assert.rejects(pruning.recover(preview.id, approval), { code: 'capability-unavailable' });
  await assert.rejects(pruning.commit(preview, approval), { code: 'capability-unavailable' });
  assert.deepEqual(await inventory(f.root), before);
});

test('missing raw evidence cannot be newly prepared and already-completed recovery never deletes a replacement file', async (t) => {
  const f = await fixture(t);
  const absent = path.join(f.root, f.evidence[1].storage.path);
  await rm(absent);
  await assert.rejects(f.pruning.preview([f.ids[1]]), { code: 'evidence-unavailable' });
  const { preview, approval } = await prepared(f, [f.ids[0]]);
  assert.equal((await f.pruning.commit(preview, approval)).state, 'pruned');
  const target = path.join(f.root, f.evidence[0].storage.path);
  await writeFile(target, 'new user-owned replacement', { mode: 0o600 });
  assert.equal((await f.pruning.recover(preview.id, { id: 'APR-no-new-delete' })).state, 'pruned');
  assert.equal(await readFile(target, 'utf8'), 'new user-owned replacement');
  await assert.rejects(f.pruning.preview([f.ids[0]]), { code: 'conflict' });
  await assert.rejects(f.pruning.commit(preview, approval), { code: 'conflict' });
});

test('foreign workspace plans, forged confirmation, and stores without pruning capability fail closed', async (t) => {
  const f = await fixture(t);
  const other = await fixture(t);
  const { preview, record } = await prepared(f);
  await assert.rejects(other.pruning.commit(preview, other.authority.issue(preview.request)), { code: 'scope-exceeded' });
  assert.equal((await other.store.evidencePruning.prepareEvidencePrune(record)).error.code, 'scope-exceeded');
  await assert.rejects(f.pruning.commit({ ...preview, confirmed: true }, { id: 'APR-invented' }), { code: 'authority-required' });
  const unavailable = new LocalEvidencePruning(f.app, {}, f.authority);
  await assert.rejects(unavailable.preview(f.ids), { code: 'capability-unavailable' });
  for (const item of f.evidence) assert.equal(digestContent(await readFile(path.join(f.root, item.storage.path))), item.storage.digest);
});

test('live and unrelated writer locks are never stolen by prune recovery', async (t) => {
  const f = await fixture(t);
  const { record, preview, approval } = await prepared(f);
  ok(await f.store.evidencePruning.prepareEvidencePrune(record));
  const lock = path.join(f.root, '.missionspec/transaction.lock');
  await writeFile(lock, JSON.stringify({ schemaVersion: 1, kind: 'evidence-prune', id: preview.id, pid: process.pid, nonce: 'test' }), { mode: 0o600 });
  await assert.rejects(f.pruning.recover(preview.id, approval), { code: 'conflict' });
  assert.equal(JSON.parse(await readFile(lock, 'utf8')).pid, process.pid);
  await rm(lock);
  await writeFile(lock, JSON.stringify({ kind: 'runtime', pid: process.pid }), { mode: 0o600 });
  await assert.rejects(f.pruning.recover(preview.id, approval));
  assert.equal(JSON.parse(await readFile(lock, 'utf8')).kind, 'runtime');
});

test('dangling prune rows and unsupported older schemas are rejected without migration', async (t) => {
  const f = await fixture(t);
  const { record } = await prepared(f);
  ok(await f.store.evidencePruning.prepareEvidencePrune(record));
  ok(f.store.close());
  sql(f, (db) => db.prepare('DELETE FROM evidence_prune_items WHERE evidence_id = ?').run(f.ids[0]));
  const corrupt = await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'read-only', expectedWorkspace: f.workspace });
  assert.equal(corrupt.status, 'failed');
  assert.ok(corrupt.error.fields.includes('corrupt'));
  const other = await fixture(t);
  ok(other.store.close());
  sql(other, (db) => db.exec('PRAGMA user_version = 2'));
  const before = await inventory(other.root);
  const old = await openRuntimeStore({ directory: path.join(other.root, '.missionspec/state'), mode: 'read-only', expectedWorkspace: other.workspace });
  assert.equal(old.status, 'blocked');
  assert.equal(old.error.code, 'unsupported-version');
  assert.deepEqual(await inventory(other.root), before);
});

test('completion failure leaves absence recoverable and never fabricates a completed receipt', async (t) => {
  const f = await fixture(t);
  const { preview, approval } = await prepared(f);
  const actual = f.store.evidencePruning;
  const faulty = new Proxy(f.store, {
    get(target, property) {
      if (property === 'evidencePruning') return {
        ...actual, async completeEvidencePrune() { throw new Error('TEST crash after delete, before completion'); },
      };
      const value = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const pruning = new LocalEvidencePruning(f.app, faulty, f.authority, { now: () => f.now });
  await assert.rejects(pruning.commit(preview, approval), { code: 'effect-outcome-unknown' });
  assert.equal((await f.pruning.status(preview.id)).state, 'prepared');
  assert.equal(sql(f, (db) => db.prepare('SELECT count(*) n FROM evidence_prune_completed').get().n), 0);
  for (const item of f.evidence) await assert.rejects(readFile(path.join(f.root, item.storage.path)), { code: 'ENOENT' });
  await f.reopen();
  assert.equal((await f.pruning.recover(preview.id, approval)).state, 'pruned');
});
