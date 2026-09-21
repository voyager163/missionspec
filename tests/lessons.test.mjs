import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { LocalLessons } from '../dist/application/lessons.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalChecks } from '../dist/adapters/authority/local-checks.js';
import { TerminalAuthority } from '../dist/adapters/authority/terminal.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { parseLessonCandidate } from '../dist/engines/verification/contracts.js';
import { digestApprovalRequest, parseApprovalRequest } from '../dist/kernel/authority.js';
import { digestContent } from '../dist/kernel/revisions.js';

const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };

// TEST ONLY: controlled authority responses test admission checks, not real human-channel qualification.
function testAuthority(now) {
  const approvals = new Map();
  return {
    onResolve: undefined,
    issue(request) {
      const parsed = parseApprovalRequest(request);
      const reference = { id: `APR-${randomUUID()}` };
      approvals.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference,
        assurance: { kind: 'local-user', channel: 'qualified-host-callback',
          qualificationEvidence: digestContent('TEST ONLY; neither human confirmation nor host qualification') },
        request: parsed, requestDigest: digestApprovalRequest(parsed), issuedAt: now,
        expiresAt: new Date(Date.parse(now) + 3_600_000).toISOString(),
      });
      return reference;
    },
    async resolve(reference) {
      if (this.onResolve) await this.onResolve(reference);
      return { status: 'ok', value: approvals.has(reference.id)
        ? { state: 'current', approval: approvals.get(reference.id) } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
}

async function fixture(t) {
  const root = path.join(process.cwd(), `.lessons-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const now = new Date().toISOString();
  const authority = testAuthority(now);
  let app = await LocalWorkflow.open(root, { authority, now: () => now });
  const setup = await app.previewSetup();
  await app.apply(setup, authority.issue(setup.request));
  await mkdir(path.join(root, 'src'));
  await mkdir(path.join(root, 'tests'));
  await writeFile(path.join(root, 'src/filter-preference.ts'), 'export const preference = "all";\n');
  await writeFile(path.join(root, 'tests/filter-preference.test.ts'), '// Declared local fixture source.\n');
  const create = await app.previewNewChange({
    slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'],
  });
  await app.apply(create, authority.issue(create.request));
  const drafts = {};
  for (const node of ['proposal', 'specs', 'design', 'tasks']) {
    const files = node === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${node}.md`];
    drafts[node] = await Promise.all(files.map(async (file) => ({
      path: `missionspec/changes/filters/${file.startsWith('specs/') ? file.replace(/\.md$/u, '/spec.md') : file}`,
      content: await readFile(new URL(`../assets/workflows/standard/examples/${file}`, import.meta.url), 'utf8'),
    })));
  }
  const batch = await app.previewDraftAll('filters', drafts);
  await app.apply(batch.plan, authority.issue(batch.plan.request));
  const store = ok(await openRuntimeStore({
    directory: path.join(root, '.missionspec/state'), mode: 'create', expectedWorkspace: (await app.project()).workspace,
  }));
  t.after(() => ok(store.close()));
  app = await LocalWorkflow.open(root, { authority, store, now: () => now });
  const checks = new LocalChecks(app, store, authority);
  const input = {
    checkId: 'CHK-filter', program: await realpath(process.execPath),
    argv: ['-e', 'console.log("real observed lesson fixture"); process.exitCode = 1'],
    cwd: '.', controlFiles: [], timeoutMs: 2000, guarantees: 'trusted-local-process',
  };
  const registration = await checks.previewRegistration('filters', input);
  const registered = await checks.register('filters', input, authority.issue(registration.request));
  const collection = await checks.previewCollection('filters', 'RUN-lesson-fixture', [registered.id]);
  const collected = await checks.collect('filters', 'RUN-lesson-fixture', [registered.id], authority.issue(collection.request));
  const lessons = new LocalLessons(app, authority, store, { now: () => now });
  const candidate = {
    schemaVersion: 1, lessonId: 'review-source-guards', title: 'Review exact source guards',
    advice: 'Treat prior check output as context; inspect the current source before reusing a conclusion.',
    provenance: { kind: 'agent-proposal', rationale: 'A real failed check motivates a human-reviewed suggestion.', evidence: collected.evidence },
    applicability: { changeId: 'CHG-remember-filter', operations: ['implement', 'verify'], sourcePaths: ['src/filter-preference.ts'] },
  };
  return { root, app, store, authority, now, lessons, candidate, evidenceId: collected.evidence[0] };
}

async function capture(f, candidate = f.candidate) {
  const preview = await f.lessons.previewCapture('filters', candidate);
  const approval = f.authority.issue(preview.request);
  const committed = await f.lessons.capture('filters', candidate, approval);
  return { version: preview.version, approval, committed };
}
async function evaluate(f, version) {
  const preview = await f.lessons.previewEvaluation('filters', f.candidate.lessonId, version);
  return f.lessons.evaluate('filters', f.candidate.lessonId, version, f.authority.issue(preview.request));
}
async function transition(f, input) {
  const preview = await f.lessons.previewTransition('filters', f.candidate.lessonId, input);
  return f.lessons.transition('filters', f.candidate.lessonId, input, f.authority.issue(preview.request));
}
const selection = { operation: 'implement', paths: ['src/filter-preference.ts'] };
async function inventory(root) {
  const files = [];
  async function walk(relative = '') {
    for (const entry of await readdir(path.join(root, relative), { withFileTypes: true })) {
      const child = path.join(relative, entry.name);
      if (entry.isDirectory()) await walk(child);
      else files.push([child, digestContent(await readFile(path.join(root, child)))]);
    }
  }
  await walk();
  return files.sort();
}

test('closed lesson contracts reject caller approval, invented evidence and permission-like fields', async (t) => {
  const f = await fixture(t);
  for (const candidate of [
    { ...f.candidate, approved: true },
    { ...f.candidate, permissions: ['execute-anything'] },
    { ...f.candidate, provenance: { ...f.candidate.provenance, passed: true } },
    { ...f.candidate, applicability: { ...f.candidate.applicability, sourcePaths: ['src/**'] } },
    { ...f.candidate, provenance: { ...f.candidate.provenance, evidence: [f.evidenceId, f.evidenceId] } },
  ]) assert.throws(() => parseLessonCandidate(candidate));
  await assert.rejects(f.lessons.previewCapture('filters', {
    ...f.candidate, provenance: { ...f.candidate.provenance, evidence: ['EVD-invented'] },
  }), { code: 'evidence-unavailable' });
  await assert.rejects(f.lessons.previewCapture('filters', {
    ...f.candidate, applicability: { ...f.candidate.applicability, sourcePaths: ['other-file.ts'] },
  }), { code: 'scope-exceeded' });
  assert.equal((await f.lessons.history(f.candidate.lessonId)).state, 'empty');
});

test('capture and evidence evaluation are inert, preserve actual failure, and never become benchmark or acceptance proof', async (t) => {
  const f = await fixture(t);
  const captured = await capture(f);
  assert.equal(captured.committed.history.state, 'inactive');
  const before = await inventory(f.root);
  const selected = await f.lessons.select('filters', selection);
  assert.deepEqual(selected.lessons, []);
  assert.equal(selected.excluded[0].reason, 'inactive');
  assert.deepEqual(await inventory(f.root), before);
  await assert.rejects(f.lessons.previewTransition('filters', f.candidate.lessonId, {
    action: 'activate', version: captured.version, reason: 'No evaluation exists yet.',
  }), { code: 'evidence-unavailable' });
  const report = await f.lessons.previewEvaluation('filters', f.candidate.lessonId, captured.version);
  assert.equal(report.evaluation.observations[0].result, 'failed');
  assert.equal(report.evaluation.semanticAssessment, 'unavailable');
  assert.equal(report.evaluation.acceptance, 'not-assessed');
  assert.equal(report.evaluation.benchmark, 'not-performed');
  await evaluate(f, captured.version);
  assert.equal((await f.lessons.history(f.candidate.lessonId)).active, null);
  await assert.rejects(f.lessons.previewEvaluation('filters', f.candidate.lessonId, captured.version, 'semantic'),
    { code: 'capability-unavailable' });
});

test('activation requires a separate current confirmation; caller booleans and capture approvals cannot promote advice', async (t) => {
  const f = await fixture(t);
  const verificationBefore = await f.app.verify('filters', 'RUN-lesson-fixture', [f.evidenceId]);
  assert.equal(verificationBefore.acceptanceEligibility.state, 'ineligible');
  const captured = await capture(f);
  await evaluate(f, captured.version);
  const input = { action: 'activate', version: captured.version, reason: 'Reviewed limited advice for this exact source.' };
  await assert.rejects(f.lessons.transition('filters', f.candidate.lessonId, input, captured.approval), { code: 'scope-exceeded' });
  await assert.rejects(f.lessons.previewTransition('filters', f.candidate.lessonId, { ...input, approved: true }));
  await assert.rejects(f.lessons.transition('filters', f.candidate.lessonId, input, { id: 'APR-invented' }), { code: 'authority-required' });
  const terminal = new LocalLessons(f.app, await TerminalAuthority.open(f.root), f.store, { now: () => f.now });
  const preview = await terminal.previewTransition('filters', f.candidate.lessonId, input);
  const unavailable = ok(await terminal.confirm(preview));
  assert.equal(unavailable.state, 'unavailable');
  const activated = await transition(f, input);
  assert.equal(activated.history.active, captured.version);
  assert.equal(ok(await f.store.readAcceptance(activated.record.approval)), null);
  const before = await inventory(f.root);
  const selected = await f.lessons.select('filters', selection);
  assert.equal(selected.lessons.length, 1);
  assert.equal(selected.lessons[0].trust, 'untrusted-advice');
  assert.equal(selected.permissions, 'unchanged');
  assert.equal(selected.requirements, 'unchanged');
  assert.equal(selected.acceptanceCriteria, 'unchanged');
  assert.deepEqual(await inventory(f.root), before);
  const verificationAfter = await f.app.verify('filters', 'RUN-lesson-fixture', [f.evidenceId]);
  assert.deepEqual(verificationAfter, verificationBefore);
});

test('versions remain immutable; replacement, retirement and rollback each require explicit review', async (t) => {
  const f = await fixture(t);
  const first = await capture(f);
  await evaluate(f, first.version);
  await transition(f, { action: 'activate', version: first.version, reason: 'First reviewed version.' });
  const firstPath = path.join(f.root, `.missionspec/audit/${first.committed.record.id}.json`);
  const original = await readFile(firstPath, 'utf8');
  const second = await capture(f, { ...f.candidate, advice: 'An updated, still untrusted suggestion.' });
  assert.notEqual(first.version, second.version);
  assert.equal((await f.lessons.select('filters', selection)).lessons[0].version, first.version);
  await evaluate(f, second.version);
  await assert.rejects(f.lessons.previewTransition('filters', f.candidate.lessonId, {
    action: 'rollback', version: second.version, reason: 'Never activated, so cannot roll back to it.',
  }), { code: 'conflict' });
  await transition(f, { action: 'activate', version: second.version, reason: 'Reviewed replacement.' });
  await transition(f, { action: 'rollback', version: first.version, reason: 'Explicitly restore prior reviewed advice.' });
  assert.equal((await f.lessons.select('filters', selection)).lessons[0].version, first.version);
  await transition(f, { action: 'retire', reason: 'Stop suggesting this lesson.' });
  assert.deepEqual((await f.lessons.select('filters', selection)).lessons, []);
  await transition(f, { action: 'rollback', version: second.version, reason: 'Explicitly restore previously reviewed replacement.' });
  assert.equal((await f.lessons.history(f.candidate.lessonId)).reviewedVersions.length, 2);
  assert.equal(await readFile(firstPath, 'utf8'), original);
});

test('source and evidence freshness gate activation and selection while stale advice can still be retired', async (t) => {
  const f = await fixture(t);
  const captured = await capture(f);
  await evaluate(f, captured.version);
  await transition(f, { action: 'activate', version: captured.version, reason: 'Reviewed live evidence.' });
  const raw = ok(await f.store.readEvidence(f.evidenceId));
  const rawPath = path.join(f.root, raw.storage.path);
  const bytes = await readFile(rawPath);
  await rm(rawPath);
  assert.equal((await f.lessons.select('filters', selection)).excluded[0].reason, 'evidence-unavailable');
  await writeFile(rawPath, bytes, { mode: 0o600 });
  await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'export const preference = "changed";\n');
  assert.equal((await f.lessons.select('filters', selection)).excluded[0].reason, 'stale');
  await assert.rejects(f.lessons.previewEvaluation('filters', f.candidate.lessonId, captured.version), { code: 'stale-revision' });
  await transition(f, { action: 'retire', reason: 'Stale lessons must be removable without pretending their old evidence is fresh.' });
  assert.equal((await f.lessons.history(f.candidate.lessonId)).state, 'retired');
});

test('approval cannot survive source edits or another immutable history append during review', async (t) => {
  const f = await fixture(t);
  const preview = await f.lessons.previewCapture('filters', f.candidate);
  const approval = f.authority.issue(preview.request);
  await capture(f, { ...f.candidate, advice: 'A separate candidate was captured first.' });
  await assert.rejects(f.lessons.capture('filters', f.candidate, approval), { code: 'scope-exceeded' });
  assert.equal((await f.lessons.history(f.candidate.lessonId)).records.length, 1);
  let changed = false;
  const next = await f.lessons.previewCapture('filters', f.candidate);
  const nextApproval = f.authority.issue(next.request);
  f.authority.onResolve = async () => {
    if (!changed) {
      changed = true;
      await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'export const changedDuringReview = true;\n');
    }
  };
  await assert.rejects(f.lessons.capture('filters', f.candidate, nextApproval), { code: 'stale-revision' });
  assert.equal((await f.lessons.history(f.candidate.lessonId)).records.length, 1);
});

test('read-only applicability is exact, and active/unreconciled runs block lesson use', async (t) => {
  const f = await fixture(t);
  const captured = await capture(f);
  await evaluate(f, captured.version);
  await transition(f, { action: 'activate', version: captured.version, reason: 'Reviewed narrow scope.' });
  assert.equal((await f.lessons.select('filters', { ...selection, operation: 'archive' })).excluded[0].reason, 'not-applicable');
  assert.equal((await f.lessons.select('filters', {
    operation: 'implement', paths: ['tests/filter-preference.test.ts'],
  })).excluded[0].reason, 'not-applicable');
  await assert.rejects(f.lessons.select('filters', { ...selection, paths: ['undeclared.ts'] }), { code: 'scope-exceeded' });
  const run = ok(await f.store.readRun('RUN-lesson-fixture'));
  ok(await f.store.commitRun({
    expectedRevision: run.revision,
    snapshot: { ...run.snapshot, state: 'outcome-unknown', quiescence: 'unconfirmed' }, attempts: [], evidence: [],
  }));
  await assert.rejects(f.lessons.select('filters', selection), { code: 'conflict' });
  const retire = await f.lessons.previewTransition('filters', f.candidate.lessonId, { action: 'retire', reason: 'Wait for reconciliation.' });
  await assert.rejects(f.lessons.transition('filters', f.candidate.lessonId, { action: 'retire', reason: 'Wait for reconciliation.' },
    f.authority.issue(retire.request)), { code: 'conflict' });
});

test('audit branches, changed subjects and unknown fields are not silently adopted', async (t) => {
  const f = await fixture(t);
  const captured = await capture(f);
  const duplicate = { ...captured.committed.record, id: `lesson-${randomUUID()}` };
  await f.app.files.recordRuntime('audit', duplicate.id, duplicate);
  await assert.rejects(f.lessons.history(f.candidate.lessonId), { code: 'persistence-failed' });
  await assert.rejects(f.lessons.select('filters', selection), { code: 'persistence-failed' });
  await rm(path.join(f.root, `.missionspec/audit/${duplicate.id}.json`));
  const recordPath = path.join(f.root, `.missionspec/audit/${captured.committed.record.id}.json`);
  await writeFile(recordPath, JSON.stringify({ ...captured.committed.record, approved: true }), { mode: 0o600 });
  await assert.rejects(f.lessons.history(f.candidate.lessonId), { code: 'persistence-failed' });
});

test('copied private lesson history is rejected in another independently observed workspace', async (t) => {
  const source = await fixture(t);
  const destination = await fixture(t);
  const captured = await capture(source);
  await destination.app.files.recordRuntime('audit', captured.committed.record.id, captured.committed.record);
  await assert.rejects(destination.lessons.history(source.candidate.lessonId), { code: 'persistence-failed' });
});
