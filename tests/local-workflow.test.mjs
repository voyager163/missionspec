import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm, writeFile, symlink, chmod, stat, realpath } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { LocalChecks, LocalWorkflow, ExecutionController, executionApprovalRequest, digestApprovalRequest, digestContent, digestEffectScope, openRuntimeStore, parseApprovalRequest } from '../dist/api/index.js';
import { parseMarkdownDocument, parseMarkdownSet, promoteBaseline } from '../dist/engines/specification/contracts.js';
import { requireApproval } from '../dist/application/authority.js';

const now = '2026-09-20T12:00:00.000Z';
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };

// TEST ONLY. This is not a qualified human channel and is never composed by the CLI.
function testAuthority() {
  const approvals = new Map();
  let resolutions = 0;
  return {
    approvals,
    failAfter: Infinity,
    issue(request) {
      const parsed = parseApprovalRequest(request);
      const approval = {
        contractVersion: 1, state: 'trusted-issued', reference: { id: `APR-${randomUUID()}` },
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST FIXTURE ONLY: no human or native host qualification') },
        request: parsed, requestDigest: digestApprovalRequest(parsed), issuedAt: now, expiresAt: '2026-09-21T12:00:00.000Z',
      };
      approvals.set(approval.reference.id, approval);
      return approval.reference;
    },
    async resolve(reference) {
      const approval = approvals.get(reference.id);
      return { status: 'ok', value: ++resolutions <= this.failAfter && approval ? { state: 'current', approval } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
}

async function fixture(t, initialized = true) {
  const root = path.join(process.cwd(), `.local-workflow-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const authority = testAuthority();
  const app = await LocalWorkflow.open(root, { authority, now: () => now });
  if (initialized) {
    const preview = await app.previewSetup();
    await app.apply(preview, authority.issue(preview.request));
  }
  return { root, authority, app };
}

async function newChange(f, slug = 'filters') {
  const plan = await f.app.previewNewChange({
    slug, id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'],
  });
  await f.app.apply(plan, f.authority.issue(plan.request));
  return slug;
}

async function drafts(slug = 'filters') {
  const sources = {};
  for (const node of ['proposal', 'specs', 'design', 'tasks']) {
    const files = node === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${node}.md`];
    sources[node] = await Promise.all(files.map(async (file) => ({
      path: `missionspec/changes/${slug}/${file.startsWith('specs/') ? file.replace(/\.md$/u, '/spec.md') : file}`,
      content: await readFile(new URL(`../assets/workflows/standard/examples/${file}`, import.meta.url), 'utf8'),
    })));
  }
  return sources;
}

async function prepared(t) {
  const f = await fixture(t);
  await newChange(f);
  const batch = await f.app.previewDraftAll('filters', await drafts());
  assert.equal(batch.stop, 'required-drafts-complete');
  assert.deepEqual(batch.completed, ['proposal', 'specs', 'design', 'tasks']);
  await f.app.apply(batch.plan, f.authority.issue(batch.plan.request));
  assert.equal((await f.app.loadChange('filters')).implementationReady, true);
  return f;
}

async function inventory(root) {
  const result = [];
  async function walk(directory, prefix = '') {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relative = `${prefix}${entry.name}`;
      if (entry.isDirectory()) await walk(path.join(directory, entry.name), `${relative}/`);
      else result.push([relative, digestContent(await readFile(path.join(directory, entry.name)))]);
    }
  }
  await walk(root);
  return result.sort();
}

test('Compact explicitly reviews separate-design applicability while retaining combined Design and predecessor provenance', async (t) => {
      const f = await fixture(t);
      const plan = await f.app.previewNewChange({ slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'], profile: 'compact' });
      await f.app.apply(plan, f.authority.issue(plan.request));
      const content = await drafts();
      for (const node of ['proposal', 'specs']) {
        const capture = await f.app.previewArtifact('filters', node, content[node]);
        await f.app.apply(capture, f.authority.issue(capture.request));
      }
      const applicability = await f.app.previewApplicability('filters', 'Design is combined with the small task plan.');
      await f.app.apply(applicability, f.authority.issue(applicability.request));
      await assert.rejects(f.app.previewArtifact('filters', 'tasks', content.tasks), { code: 'invalid-input' });
      const capture = await f.app.previewArtifact('filters', 'tasks', content.tasks.map((file) => ({
        ...file, content: file.content.replace('## Tasks', '## Design\n\nUse the existing preference service.\n\n## Tasks'),
      })));
      await f.app.apply(capture, f.authority.issue(capture.request));
      const current = await f.app.loadChange('filters');
      assert.equal(current.implementationReady, true);
      assert.equal(current.readiness.assessments.find((entry) => entry.node === 'design').readiness, 'not-applicable');
      await assert.rejects(f.app.previewArtifact('filters', 'design', content.design), { code: 'conflict' });
      const required = await f.app.previewApplicability('filters', null);
      await f.app.apply(required, f.authority.issue(required.request));
      assert.equal((await f.app.loadChange('filters')).implementationReady, false);
    });

test('explicit expanded verification is part of the one tasks artifact and cannot be omitted or silently edited', async (t) => {
  const f = await fixture(t);
  const plan = await f.app.previewNewChange({
    slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'], verificationPlan: true,
  });
  await f.app.apply(plan, f.authority.issue(plan.request));
  const authored = await drafts();
  for (const node of ['proposal', 'specs', 'design']) {
    const capture = await f.app.previewArtifact('filters', node, authored[node]);
    await f.app.apply(capture, f.authority.issue(capture.request));
  }
  const [tasks, checks] = authored.tasks[0].content.split('\n## Checks\n');
  const taskSources = [
    { ...authored.tasks[0], content: `${tasks.replace('kind: tasks', 'kind: tasks\nchecks: verification.md')}\n## Checks\n\nCanonical check definitions are in verification.md.\n` },
    { path: 'missionspec/changes/filters/verification.md', content: `---\nschemaVersion: 1\nid: ART-expanded-checks\nkind: verification\nchangeId: CHG-remember-filter\n---\n# Expanded checks\n\n## Checks\n${checks}` },
  ];
  const instructions = await f.app.instructions('filters', 'tasks');
  assert.equal(instructions.templates.length, 2);
  assert(instructions.templates[1].content.includes('kind: verification'));
  await assert.rejects(f.app.previewArtifact('filters', 'tasks', [taskSources[0]]), /complete output set/u);
  const captured = await f.app.previewArtifact('filters', 'tasks', taskSources);
  await f.app.apply(captured, f.authority.issue(captured.request));
  let current = await f.app.loadChange('filters');
  assert.equal(current.implementationReady, true);
  assert.equal(current.analysis.checks.length, 2);
  await writeFile(path.join(f.root, taskSources[1].path), taskSources[1].content.replace('Check reset persistence', 'Review changed reset behavior'));
  current = await f.app.loadChange('filters');
  assert.equal(current.implementationReady, false);
  assert.notEqual(current.readiness.assessments.find((entry) => entry.node === 'tasks').readiness, 'valid');
});

    async function checkFixture(t) {
      const f = await prepared(t);
      const store = ok(await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'create', expectedWorkspace: (await f.app.project()).workspace }));
      t.after(() => store.close());
      f.app = await LocalWorkflow.open(f.root, { store, authority: f.authority, now: () => now });
      const checks = new LocalChecks(f.app, store, f.authority);
      const input = { checkId: 'CHK-filter', program: await realpath(process.execPath), argv: ['-e', 'console.log("real subprocess output")'], cwd: '.', controlFiles: [], timeoutMs: 2000, guarantees: 'trusted-local-process' };
      const register = async (value) => {
        const preview = await checks.previewRegistration('filters', value);
        return (await checks.register('filters', value, f.authority.issue(preview.request))).id;
      };
      return { ...f, store, checks, input, register };
    }

    test('real registered local subprocesses retain actual output and observed exit/source bindings, not caller success', async (t) => {
      const f = await checkFixture(t);
      const registrations = [await f.register(f.input), await f.register({ ...f.input, checkId: 'CHK-reset', argv: ['-e', 'console.log("reset observed"); process.exitCode = 3;'] })];
      const preview = await f.checks.previewCollection('filters', 'RUN-local-checks', registrations);
      const collected = await f.checks.collect('filters', 'RUN-local-checks', registrations, f.authority.issue(preview.request));
      assert.equal(collected.evidence.length, 2);
      const report = await f.app.verify('filters', collected.runId, collected.evidence);
      assert.equal(report.acceptanceEligibility.state, 'ineligible');
      assert.deepEqual(report.observations.map((entry) => entry.result), ['passed', 'failed']);
      const evidence = ok(await f.store.readEvidence(collected.evidence[0]));
      const raw = JSON.parse(await readFile(path.join(f.root, evidence.storage.path), 'utf8'));
      const output = JSON.parse(raw.output);
      assert.equal(output.exitCode, 0);
      assert.equal(output.stdout, 'real subprocess output\n');
      assert.equal(output.sourceBefore, output.sourceAfter);
      assert.match(output.registration.limitations, /No filesystem\/network confinement/);
      await assert.rejects(f.checks.previewRegistration('filters', { ...f.input, passed: true }));
      await assert.rejects(f.checks.previewRegistration('filters', { ...f.input, guarantees: 'hard-confinement' }), { code: 'check-unqualified' });
    });

    test('local check registration independently binds selected control files and requires verification-purpose authority', async (t) => {
      const f = await checkFixture(t);
      await writeFile(path.join(f.root, 'check.mjs'), 'console.log("original")');
      const id = await f.register({ ...f.input, argv: ['check.mjs'], controlFiles: ['check.mjs'] });
      const preview = await f.checks.previewCollection('filters', 'RUN-check-scope', [id]);
      const ref = f.authority.issue({ ...preview.request, purpose: 'acceptance' });
      await assert.rejects(f.checks.collect('filters', 'RUN-check-scope', [id], ref), { code: 'scope-exceeded' });
      assert.equal(ok(await f.store.readRun('RUN-check-scope')), null);
      await writeFile(path.join(f.root, 'check.mjs'), 'console.log("changed")');
      await assert.rejects(f.checks.previewCollection('filters', 'RUN-check-scope', [id]), { code: 'stale-revision' });
    });

    test('timed-out real local processes persist unknown outcome and never permit acceptance or unchecked retry', async (t) => {
      const f = await checkFixture(t);
      const id = await f.register({ ...f.input, argv: ['-e', 'setInterval(() => {}, 100)'], timeoutMs: 50 });
      const preview = await f.checks.previewCollection('filters', 'RUN-timeout', [id]);
      await assert.rejects(f.checks.collect('filters', 'RUN-timeout', [id], f.authority.issue(preview.request)), { code: 'effect-outcome-unknown' });
      assert.equal(ok(await f.store.readRun('RUN-timeout')).snapshot.state, 'outcome-unknown');
      assert.deepEqual(ok(await f.store.readRunEvidence('RUN-timeout')), []);
      await assert.rejects(f.checks.previewCollection('filters', 'RUN-timeout', [id]), { code: 'stale-revision' });
    });
test('live execution observation preserves admitted source evolution but rejects other selected source changes', async (t) => {
  const f = await prepared(t);
  const change = await f.app.loadChange('filters');
  const task = change.analysis.tasks[0];
  const effects = [
    { kind: 'host-dispatch', host: 'copilot', taskIds: [task.id] },
    { kind: 'file-write', path: 'src/filter-preference.ts', purpose: 'source', expected: 'absent', proposed: digestContent('reviewed source') },
  ];
  const work = {
    contractVersion: 1, id: 'WRK-observation', runId: 'RUN-observation', task,
    revisions: { ...change.revisions, effects: digestEffectScope(effects) }, sourceBefore: change.revisions.source,
    approval: { id: 'APR-unissued-test-observation-only' }, mode: 'interactive', host: 'copilot',
    limits: { maxTasks: 1, maxDurationMs: 1000, maxRepairsPerTask: 0, concurrency: 1 }, effects,
  };
  await mkdir(path.join(f.root, 'src'));
  await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'reviewed source');
  assert.equal((await f.app.observeExecution('filters', work, 'after')).ready, true);
  await mkdir(path.join(f.root, 'tests'));
  await writeFile(path.join(f.root, 'tests/filter-preference.test.ts'), 'unreviewed side effect');
  await assert.rejects(f.app.observeExecution('filters', work, 'after'), { code: 'scope-exceeded' });
});

test('setup previews and uninitialized read-only status never manufacture a workspace identity', async (t) => {
  const f = await fixture(t, false);
  const before = await inventory(f.root);
  assert.equal((await f.app.project()).state, 'not-initialized');
  const plan = await f.app.previewSetup();
  assert.equal(plan.request.state, 'untrusted-request');
  assert.equal(plan.mutations.length, 3);
  assert.equal((await f.app.confirm(plan)).value.state, 'unavailable');
  await assert.rejects(f.app.apply(plan, { id: 'APR-fake' }), { code: 'authority-required' });
  assert.deepEqual(await inventory(f.root), before);
  const defaultComposition = await LocalWorkflow.open(f.root);
  const ref = f.authority.issue(plan.request);
  await assert.rejects(defaultComposition.apply(plan, ref), { code: 'authority-required' });
  await f.app.apply(plan, ref);
  assert.equal((await f.app.project()).state, 'initialized');
  assert.match(await readFile(path.join(f.root, '.gitignore'), 'utf8'), /^\.missionspec\/\n$/);
  await assert.rejects(f.app.previewSetup(), { code: 'conflict' });
});

test('project metadata and nested capability outputs follow the approved YAML layout', async (t) => {
  const f = await fixture(t);
  assert((await readFile(path.join(f.root, 'missionspec/config.yaml'), 'utf8')).startsWith('schemaVersion: 1\n'));
  const preview = await f.app.previewNewChange({
    slug: 'nested-auth', id: 'CHG-nested-auth', specs: ['identity/user-auth'],
  });
  await f.app.apply(preview, f.authority.issue(preview.request));
  const change = await f.app.loadChange('nested-auth');
  assert.equal(change.metadataFile.path, 'missionspec/changes/nested-auth/change.yaml');
  assert.deepEqual(change.metadata.baseline.map((entry) => entry.path), ['missionspec/specs/identity/user-auth/spec.md']);
  assert.deepEqual(change.metadata.nodes.find((node) => node.node === 'specs').outputs,
    ['missionspec/changes/nested-auth/specs/identity/user-auth/spec.md']);
  assert.equal(await f.app.files.read('missionspec/config.json'), null);
  assert.equal(await f.app.files.read('missionspec/changes/nested-auth/change.json'), null);
});

test('legacy JSON configuration is preserved and never shadowed by new YAML setup', async (t) => {
  const f = await fixture(t, false);
  await mkdir(path.join(f.root, 'missionspec'));
  await writeFile(path.join(f.root, 'missionspec/config.json'), '{"schemaVersion":1,"defaultProfile":"standard"}\n');
  const before = await inventory(f.root);
  await assert.rejects(f.app.project(), { code: 'unsupported-version' });
  await assert.rejects(f.app.previewSetup(), { code: 'unsupported-version' });
  assert.deepEqual(await inventory(f.root), before);
});

test('setup preserves existing ignore content and rejects copied identities at another observed root', async (t) => {
  const f = await fixture(t, false);
  await writeFile(path.join(f.root, '.gitignore'), '# user content\nimportant.txt');
  await chmod(path.join(f.root, '.gitignore'), 0o640);
  const plan = await f.app.previewSetup('compact');
  await f.app.apply(plan, f.authority.issue(plan.request));
  assert.equal((await f.app.project()).defaultProfile, 'compact');
  assert.equal(await readFile(path.join(f.root, '.gitignore'), 'utf8'), '# user content\nimportant.txt\n.missionspec/\n');
  assert.equal((await stat(path.join(f.root, '.gitignore'))).mode & 0o777, 0o640);
  const other = await fixture(t, false);
  await mkdir(path.join(other.root, '.missionspec'), { mode: 0o700 });
  await writeFile(path.join(other.root, '.missionspec/workspace.json'), await readFile(path.join(f.root, '.missionspec/workspace.json')), { mode: 0o600 });
  await assert.rejects(other.app.project(), { code: 'scope-exceeded' });
  await assert.rejects(other.app.apply(plan, f.authority.issue(plan.request)), { code: 'scope-exceeded' });
});

test('durable file journal recovers a partial write only when every remaining observation still matches', async (t) => {
  const f = await fixture(t, false);
  const plan = await f.app.previewSetup();
  f.authority.failAfter = 2;
  await assert.rejects(f.app.apply(plan, f.authority.issue(plan.request)), { code: 'effect-outcome-unknown' });
  const pending = await f.app.files.pending();
  assert.equal(pending.length, 1);
  assert.ok(await f.app.files.identity());
  f.authority.failAfter = Infinity;
  const recovery = await f.app.files.recoveryPlan(pending[0]);
  assert.equal(recovery.digest, plan.digest);
  await f.app.files.recover(pending[0], f.authority.issue(recovery.request));
  assert.deepEqual(await f.app.files.pending(), []);
  assert.equal((await f.app.project()).state, 'initialized');
  await assert.rejects(f.app.files.recoveryPlan(pending[0]), { code: 'not-found' });
});

test('recovery does not overwrite an unrelated user edit after interrupted setup', async (t) => {
  const f = await fixture(t, false);
  const plan = await f.app.previewSetup();
  f.authority.failAfter = 2;
  await assert.rejects(f.app.apply(plan, f.authority.issue(plan.request)), { code: 'effect-outcome-unknown' });
  await mkdir(path.join(f.root, 'missionspec'), { recursive: true });
  await writeFile(path.join(f.root, 'missionspec/config.yaml'), 'user owned');
  const [pending] = await f.app.files.pending();
  await assert.rejects(f.app.files.recoveryPlan(pending), { code: 'stale-revision' });
  assert.equal(await readFile(path.join(f.root, 'missionspec/config.yaml'), 'utf8'), 'user owned');
});

test('symlink paths and permissive existing runtime directories are blocked without writes', async (t) => {
  const f = await fixture(t, false);
  await symlink('../', path.join(f.root, 'missionspec'));
  await assert.rejects(f.app.previewSetup(), { code: 'scope-exceeded' });
  const other = await fixture(t, false);
  await mkdir(path.join(other.root, '.missionspec'), { mode: 0o755 });
  await chmod(path.join(other.root, '.missionspec'), 0o755);
  await assert.rejects(other.app.previewSetup(), { code: 'scope-exceeded' });
});

test('drafting one skeleton stops before capture and implementation; explicit capture records dependency provenance', async (t) => {
  const f = await fixture(t);
  await newChange(f);
  const instructions = await f.app.instructions('filters');
  assert.equal(instructions.selected, 'proposal');
  const plan = await f.app.previewArtifact('filters', 'proposal', instructions.templates, { mode: 'draft' });
  await f.app.apply(plan, f.authority.issue(plan.request));
  let change = await f.app.loadChange('filters');
  assert.equal(change.implementationReady, false);
  assert.equal(change.metadata.nodes[0].captured, null);
  assert.equal(change.validation.state, 'invalid');
  assert.deepEqual(change.uncaptured, ['proposal']);
  const sources = await drafts();
  await assert.rejects(f.app.previewArtifact('filters', 'specs', sources.specs), { code: 'conflict' });
  const captured = await f.app.previewArtifact('filters', 'proposal', sources.proposal);
  await f.app.apply(captured, f.authority.issue(captured.request));
  change = await f.app.loadChange('filters');
  assert.deepEqual(change.readiness.next, { state: 'selection-required', candidates: ['specs', 'design'] });
  await assert.rejects(f.app.previewArtifact('filters', 'specs', [sources.specs[0]]), /complete output set/);
});

test('draft-all captures the bounded closure without host execution and repeated reads write no files', async (t) => {
  const f = await prepared(t);
  const before = await inventory(f.root);
  const change = await f.app.loadChange('filters');
  assert.equal(change.analysis.tasks.length, 2);
  assert.equal(change.analysis.checks.length, 2);
  assert.deepEqual(change.analysis.coverage, []);
  assert.equal((await f.app.verificationGaps('filters')).acceptanceEligibility.state, 'ineligible');
  assert.equal((await f.app.previewDraftAll('filters', await drafts())).plan, null);
  await f.app.instructions('filters');
  assert.deepEqual(await inventory(f.root), before);
  assert.equal(change.metadata.promotedContent, null);
  assert.ok(!JSON.stringify(change.metadata).includes('WSP-'));
});

test('captured dependencies become stale after revise, and edits made after preview are preserved', async (t) => {
  const f = await prepared(t);
  const sources = await drafts();
  sources.proposal[0].content += '\n';
  const plan = await f.app.previewArtifact('filters', 'proposal', sources.proposal, { mode: 'revise' });
  const sourcePath = path.join(f.root, 'src/filter-preference.ts');
  await mkdir(path.dirname(sourcePath), { recursive: true });
  await writeFile(sourcePath, 'unreviewed user edit');
  await assert.rejects(f.app.apply(plan, f.authority.issue(plan.request)), { code: 'stale-revision' });
  const fresh = await f.app.previewArtifact('filters', 'proposal', sources.proposal, { mode: 'revise' });
  await f.app.apply(fresh, f.authority.issue(fresh.request));
  const change = await f.app.loadChange('filters');
  assert.equal(change.implementationReady, false);
  assert.equal(change.readiness.assessments.find((node) => node.node === 'specs').readiness, 'stale');
  assert.equal(change.readiness.assessments.find((node) => node.node === 'tasks').readiness, 'stale');
  assert.equal(await readFile(sourcePath, 'utf8'), 'unreviewed user edit');
});

test('manual Markdown edits are not silently recaptured and checkbox claims never create evidence', async (t) => {
  const f = await prepared(t);
  const filename = path.join(f.root, 'missionspec/changes/filters/tasks.md');
  await writeFile(filename, (await readFile(filename, 'utf8')).replaceAll('[ ]', '[x]'));
  const change = await f.app.loadChange('filters');
  assert.equal(change.readiness.assessments.find((node) => node.node === 'tasks').readiness, 'blocked');
  assert.equal(change.implementationReady, false);
  const plan = await f.app.previewArtifact('filters', 'tasks', [{ path: 'missionspec/changes/filters/tasks.md', content: await readFile(filename, 'utf8') }]);
  await f.app.apply(plan, f.authority.issue(plan.request));
  assert.equal((await f.app.loadChange('filters')).implementationReady, true);
  assert.equal((await f.app.verificationGaps('filters')).acceptanceEligibility.state, 'ineligible');
});

test('blocking clarification requires an explicit reviewed user answer and becomes stale on artifact changes', async (t) => {
  const f = await prepared(t);
  const change = await f.app.loadChange('filters');
  const question = {
    id: 'QST-filter', question: 'Which default applies?', blocking: true,
    artifactRevision: change.analysis.artifactRevision,
    response: { answer: 'Use the fallback.', source: 'proposed-assumption' },
  };
  let plan = await f.app.previewClarification('filters', [question]);
  await f.app.apply(plan, f.authority.issue(plan.request));
  assert.equal((await f.app.loadChange('filters')).implementationReady, false);
  question.response.source = 'user';
  plan = await f.app.previewClarification('filters', [question]);
  await f.app.apply(plan, f.authority.issue(plan.request));
  assert.equal((await f.app.loadChange('filters')).implementationReady, true);
  const sources = await drafts();
  sources.tasks[0].content += '\n';
  plan = await f.app.previewArtifact('filters', 'tasks', sources.tasks, { mode: 'revise' });
  await f.app.apply(plan, f.authority.issue(plan.request));
  assert.deepEqual((await f.app.loadChange('filters')).analysis.clarificationBlockers, ['QST-filter']);
});

test('baseline Markdown has project scope with no fabricated change ID or delta operations', () => {
  const content = '---\nschemaVersion: 1\nid: ART-baseline\nkind: baseline\n---\n# Baseline\n\n## Requirements\n\n### REQ-a: Retained intent\n\n```missionspec\n{}\n```\n\nRetained prose.\n';
  const parsed = parseMarkdownDocument({ path: 'missionspec/specs/a.md', content });
  assert.equal(parsed.state, 'parsed');
  assert.equal(parsed.document.changeId, null);
  assert.equal(parsed.document.declarations[0].operation, 'retain');
  assert.equal(parseMarkdownDocument({ path: 'a.md', content: content.replace('kind: baseline', 'kind: baseline\nchangeId: CHG-fake') }).state, 'invalid');
  assert.equal(parseMarkdownDocument({ path: 'a.md', content: content.replace('{}', 'operation: add') }).state, 'invalid');
});

async function accepted(t) {
  const f = await prepared(t);
  const change = await f.app.loadChange('filters');
  const revisions = { ...change.revisions, effects: digestEffectScope([{ kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-filter'] }]) };
  const store = ok(await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'create', expectedWorkspace: change.workspace }));
  t.after(() => store.close());
  const evidence = [];
  for (const check of change.analysis.checks) {
    const id = `EVD-${check.id.slice(4)}`;
    const relative = `.missionspec/evidence/${id}.json`;
    const content = JSON.stringify({ schemaVersion: 1, evidenceId: id, basis: 'executed', result: 'passed', output: 'TEST FIXTURE ONLY: recorded assertion output, not a real project test invocation.' });
    await mkdir(path.join(f.root, '.missionspec/evidence'), { recursive: true, mode: 0o700 });
    await writeFile(path.join(f.root, relative), content, { mode: 0o600 });
    evidence.push({
      contractVersion: 1, id, revisions, source: revisions.source,
      checkId: check.id, checkDefinition: check.definition, attemptId: null,
      storage: { state: 'retained', path: relative, digest: digestContent(content) },
    });
  }
  const snapshot = {
    contractVersion: 1, id: 'RUN-fixture', revisions, state: 'paused',
    activeTask: null, pendingTasks: [], attempts: [], quiescence: 'confirmed',
  };
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot, attempts: [], evidence }));
  f.app = await LocalWorkflow.open(f.root, { store, authority: f.authority, now: () => now });
  const ids = evidence.map((entry) => entry.id);
  const preview = await f.app.previewAcceptance('filters', 'RUN-fixture', ids);
  const reference = f.authority.issue(preview.request);
  const acceptance = await f.app.accept('filters', 'RUN-fixture', ids, reference);
  return { ...f, store, evidence, ids, acceptance, reference };
}

test('verification requires persisted digest-checked raw evidence, with acceptance scoped to a distinct review purpose', async (t) => {
  const f = await accepted(t);
  const result = await f.app.verify('filters', 'RUN-fixture', f.ids);
  assert.equal(result.acceptanceEligibility.state, 'eligible-for-human-review');
  assert.deepEqual(ok(await f.store.readAcceptance(f.reference)), f.acceptance);
  const request = f.authority.approvals.get(f.reference.id).request;
  assert.equal(request.binding.effects, digestEffectScope([]));
  assert.notEqual(request.binding.revisions.effects, request.binding.effects);
  assert.equal((await f.app.verify('filters', 'RUN-fixture', [])).acceptanceEligibility.state, 'ineligible');
  await writeFile(path.join(f.root, f.evidence[0].storage.path), '{"tampered":true}');
  await assert.rejects(f.app.verify('filters', 'RUN-fixture', f.ids), { code: 'evidence-unavailable' });
  await assert.rejects(f.app.previewPromotion('filters', f.reference), { code: 'evidence-unavailable' });
});

test('evidence from an identical-content different run cannot satisfy the selected run', async (t) => {
  const f = await accepted(t);
  const snapshot = ok(await f.store.readRun('RUN-fixture')).snapshot;
  ok(await f.store.commitRun({ expectedRevision: 'absent', snapshot: { ...snapshot, id: 'RUN-other' }, attempts: [], evidence: [] }));
  await assert.rejects(f.app.verify('filters', 'RUN-other', f.ids), { code: 'evidence-unavailable' });
});

test('failed retained check outputs report correctness gaps and scoped repair proposals without executing them', async (t) => {
  const f = await accepted(t);
  const current = ok(await f.store.readRun('RUN-fixture'));
  const evidence = { ...f.evidence[0], id: 'EVD-failed' };
  const content = JSON.stringify({ schemaVersion: 1, evidenceId: evidence.id, basis: 'executed', result: 'failed', output: 'TEST ONLY: assertion did not match.' });
  evidence.storage = { state: 'retained', path: '.missionspec/evidence/failed.json', digest: digestContent(content) };
  await writeFile(path.join(f.root, evidence.storage.path), content, { mode: 0o600 });
  ok(await f.store.commitRun({ expectedRevision: current.revision, snapshot: current.snapshot, attempts: [], evidence: [evidence] }));
  const report = await f.app.verify('filters', 'RUN-fixture', [evidence.id, f.ids[1]]);
  assert.equal(report.acceptanceEligibility.state, 'ineligible');
  assert.equal(report.correctness.length, 1);
  assert.deepEqual(report.proposedRepairs.map((task) => task.id), ['TSK-filter']);
  await assert.rejects(f.app.previewAcceptance('filters', 'RUN-fixture', [evidence.id, f.ids[1]]), { code: 'evidence-unavailable' });
});

test('project principles need no change and discovery capture stays inside its change', async (t) => {
  const f = await fixture(t);
  const principles = '---\nschemaVersion: 1\nid: ART-principles\nkind: principles\n---\n# Principles\n\n## Principles\n\nPreserve reviewed boundaries; no runtime grant.\n';
  const preview = await f.app.previewPrinciples(principles);
  assert.deepEqual(preview.affectedChanges, []);
  await f.app.apply(preview.plan, f.authority.issue(preview.plan.request));
  await newChange(f);
  const discovery = '---\nschemaVersion: 1\nid: ART-discovery\nkind: discovery\nchangeId: CHG-remember-filter\n---\n# Findings\n\n## Findings\n\nReported need, not authority.\n\n## Questions\n\nClarification still needed.\n';
  const captured = await f.app.previewCapture('filters', 'discovery', discovery);
  await f.app.apply(captured, f.authority.issue(captured.request));
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/filters/discovery.md'), 'utf8'), discovery);
  assert.equal(await f.app.files.read('missionspec/discovery.md'), null);
});

test('an active durable run blocks archive and journaled local effects before artifact writes', async (t) => {
  const f = await accepted(t);
  const run = ok(await f.store.readRun('RUN-fixture'));
  ok(await f.store.commitRun({
    expectedRevision: run.revision, snapshot: { ...run.snapshot, state: 'running', quiescence: 'unconfirmed' }, attempts: [], evidence: [],
  }));
  await assert.rejects(f.app.previewArchive('filters', 'incomplete'), { code: 'conflict' });
  const source = (await drafts()).tasks;
  const preview = await f.app.previewArtifact('filters', 'tasks', source);
  await assert.rejects(f.app.apply(preview, f.authority.issue(preview.request)), { code: 'conflict' });
  assert.equal((await f.app.files.pending()).length, 0);
  assert.equal(await readFile(path.join(f.root, source[0].path), 'utf8'), source[0].content);
});

test('injected TEST dispatch integrates live root/source/effect observation with durable admission', async (t) => {
  const f = await prepared(t);
  const effects = [
    { kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-filter'] },
    { kind: 'file-write', purpose: 'source', path: 'src/filter-preference.ts', expected: 'absent', proposed: digestContent('TEST ONLY source bytes\n') },
  ];
  const change = await f.app.loadChange('filters', effects);
  const store = ok(await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'create', expectedWorkspace: change.workspace }));
  t.after(() => store.close());
  f.app = await LocalWorkflow.open(f.root, { store, authority: f.authority, now: () => now });
  let work = {
    contractVersion: 1, id: 'WRK-live-fixture', runId: 'RUN-live-fixture', task: change.analysis.tasks[0],
    revisions: change.revisions, sourceBefore: change.revisions.source, approval: { id: 'APR-placeholder' },
    mode: 'interactive', host: 'copilot', limits: { maxTasks: 1, maxDurationMs: 10_000, maxRepairsPerTask: 0, concurrency: 1 }, effects,
  };
  work = { ...work, approval: f.authority.issue(executionApprovalRequest(work)) };
  const host = {
    async inspect() {
      return { status: 'ok', value: {
        state: 'qualified', host: 'copilot', exactVersion: 'TEST ONLY - NOT NATIVE HOST QUALIFICATION',
        operatingSystem: process.platform === 'darwin' ? 'macos' : 'linux', evidence: digestContent('TEST ONLY'),
        permissions: 'exact-effect-scope',
        dispatchFencing: 'durable-admission-token',
        cancellation: 'confirmed-quiescence', limits: { maxTasks: 'hard', maxDurationMs: 'hard', maxRepairsPerTask: 'hard', concurrency: 'hard' },
      } };
    },
    async dispatch(order) {
      assert.equal(ok(await store.readRun(order.runId)).snapshot.quiescence, 'unconfirmed');
      await mkdir(path.join(f.root, 'src'), { recursive: true });
      await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'TEST ONLY source bytes\n');
      return { status: 'ok', value: {
        contractVersion: 1, id: 'ATT-live-fixture', workOrderId: order.id, sequence: { kind: 'initial' },
        observation: {
          state: 'host-returned', startedAt: now, finishedAt: now, exitCode: 0,
          sourceAfter: (await f.app.loadChange('filters', effects)).revisions.source, reportedTaskStatus: 'claimed-complete',
        },
      } };
    },
    async requestStop(_id, dispatchToken) { return { status: 'ok', value: { state: 'quiesced', evidence: digestContent('TEST STOP'), dispatchToken } }; },
  };
  const controller = new ExecutionController({
    store, authority: f.authority, host, clock: { wallTime: () => now, monotonicMilliseconds: () => 0 },
    observe: (order, phase) => f.app.observeExecution('filters', order, phase),
  });
  const result = await controller.dispatch(work);
  assert.equal(result.state, 'paused');
  assert.notEqual(result.revisions.source, work.sourceBefore);
  assert.equal((await f.app.verify('filters', work.runId, [])).acceptanceEligibility.state, 'ineligible');
  await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'outside the approved bytes');
  await assert.rejects(f.app.observeExecution('filters', work, 'after'), { code: 'scope-exceeded' });
});

test('sync and accepted archive share conflict-aware promotion while preserving unrelated files', async (t) => {
  const f = await accepted(t);
  const preview = await f.app.previewPromotion('filters', f.reference);
  assert.equal(preview.state, 'ready');
  assert.equal(preview.plan.request.purpose, 'promotion');
  assert.equal(preview.plan.request.binding.kind, 'review');
  await assert.rejects(f.app.commitPromotion('filters', f.reference, preview.plan, f.reference), { code: 'scope-exceeded' });
  await f.app.commitPromotion('filters', f.reference, preview.plan, f.authority.issue(preview.plan.request));
  assert.equal((await f.app.project()).changes.includes('filters'), true);
  assert.equal((await f.app.previewPromotion('filters', f.reference)).state, 'already-synced');
  const baseline = await readFile(path.join(f.root, 'missionspec/specs/filters/spec.md'), 'utf8');
  assert.match(baseline, /kind: baseline/);
  assert.ok(!baseline.includes('changeId:') && !baseline.includes('operation:'));
  await writeFile(path.join(f.root, 'missionspec/changes/filters/personal-note.txt'), 'preserve this');
  const archive = await f.app.previewArchive('filters', 'accepted', f.reference);
  await f.app.commitArchive('filters', 'accepted', archive, f.authority.issue(archive.request), f.reference);
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/archive/2026-09-20-filters/personal-note.txt'), 'utf8'), 'preserve this');
  assert.equal((await f.app.files.read('missionspec/changes/filters/change.yaml')), null);
  const closure = JSON.parse(await readFile(path.join(f.root, 'missionspec/changes/archive/2026-09-20-filters/closure.json'), 'utf8'));
  assert.equal(closure.outcome, 'accepted');
  assert.deepEqual(closure.acceptance, f.reference);
});

test('archive preserves nested imported/user documents and rejects new unreviewed inventory', async (t) => {
  const f = await fixture(t);
  await newChange(f);
  const imported = 'missionspec/changes/filters/imports/sources/original.md';
  await mkdir(path.dirname(path.join(f.root, imported)), { recursive: true });
  await writeFile(path.join(f.root, imported), '# Original source\n\nNot authority.\n');
  const preview = await f.app.previewArchive('filters', 'incomplete');
  assert(preview.mutations.some((mutation) => mutation.effect.path.endsWith('/imports/sources/original.md')));
  await writeFile(path.join(f.root, 'missionspec/changes/filters/later.md'), 'Unreviewed work');
  await assert.rejects(f.app.commitArchive('filters', 'incomplete', preview, f.authority.issue(preview.request)), { code: 'stale-revision' });
  assert.equal(await readFile(path.join(f.root, imported), 'utf8'), '# Original source\n\nNot authority.\n');
  const refreshed = await f.app.previewArchive('filters', 'incomplete');
  await f.app.commitArchive('filters', 'incomplete', refreshed, f.authority.issue(refreshed.request));
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/archive/2026-09-20-filters/imports/sources/original.md'), 'utf8'), '# Original source\n\nNot authority.\n');
  assert.equal(await readFile(path.join(f.root, 'missionspec/changes/archive/2026-09-20-filters/later.md'), 'utf8'), 'Unreviewed work');
});

test('baseline edits conflict rather than being overwritten, and unaccepted archive cannot claim success', async (t) => {
  const f = await accepted(t);
  await mkdir(path.join(f.root, 'missionspec/specs'), { recursive: true });
  await mkdir(path.join(f.root, 'missionspec/specs/filters'), { recursive: true });
  await writeFile(path.join(f.root, 'missionspec/specs/filters/spec.md'), 'concurrent baseline work');
  const preview = await f.app.previewPromotion('filters', f.reference);
  assert.equal(preview.state, 'conflict');
  assert.equal(preview.plan, null);
  await assert.rejects(f.app.previewArchive('filters', 'accepted', f.reference), { code: 'conflict' });
  const archive = await f.app.previewArchive('filters', 'incomplete');
  await f.app.commitArchive('filters', 'incomplete', archive, f.authority.issue(archive.request));
  assert.equal(await readFile(path.join(f.root, 'missionspec/specs/filters/spec.md'), 'utf8'), 'concurrent baseline work');
});

test('same-content cross-workspace and operation-purpose review replay are rejected', async (t) => {
  const f = await accepted(t);
  const { request } = await f.app.previewAcceptance('filters', 'RUN-fixture', f.ids);
  const different = structuredClone(request);
  different.binding.revisions.workspace.workspaceId = 'WSP-another';
  await assert.rejects(requireApproval(f.authority, f.reference, different, now), { code: 'scope-exceeded' });
  const promotion = structuredClone(request);
  promotion.operation = 'sync';
  promotion.purpose = 'promotion';
  await assert.rejects(requireApproval(f.authority, f.reference, promotion, now), { code: 'scope-exceeded' });
  const execute = structuredClone(request);
  execute.operation = 'implement'; execute.purpose = 'execution';
  assert.throws(() => parseApprovalRequest(execute));
});

test('baseline promotion preserves retained prose/notes and detects add/modify/remove conflicts', () => {
  const source = (kind, body, change = '') => `---\nschemaVersion: 1\nid: ART-${kind}\nkind: ${kind}\n${change}---\n# Intent\n\n## Requirements\n\n${body}`;
  const fact = (op, prose) => `### REQ-a: Requirement\n\n\`\`\`missionspec\n${op}\n\`\`\`\n\n${prose}\n`;
  const baseline = parseMarkdownDocument({ path: 'missionspec/specs/a.md', content: source('baseline', `${fact('{}', 'Old prose')}\n## Notes\n\nUser note.\n`) }).document;
  const delta = parseMarkdownDocument({ path: 'change.md', content: source('specs', fact('operation: modify', 'New prose'), 'changeId: CHG-a\n') }).document;
  const promoted = promoteBaseline({ baseline, delta, path: 'missionspec/specs/a.md' });
  assert.match(promoted.content, /New prose/);
  assert.match(promoted.content, /User note/);
  assert.equal(parseMarkdownSet([{ path: 'missionspec/specs/a.md', content: promoted.content }]).state, 'valid');
  assert.equal(promoteBaseline({ baseline: null, delta, path: 'missionspec/specs/a.md' }).conflicts.length, 1);
});

test('promotion preserves baseline introductions and Requirements preambles verbatim', () => {
  const baselineSource = '---\nschemaVersion: 1\nid: ART-original\nkind: baseline\n---\n# Existing capability\n\nImportant introduction.\n\n## Requirements\n\nRequired context before declarations.\n\n### REQ-old: Old\n\n```missionspec\n{}\n```\n\nRetained behavior.\n';
  const deltaSource = '---\nschemaVersion: 1\nid: ART-delta\nkind: specs\nchangeId: CHG-a\n---\n# Proposed\n\n## Requirements\n\n### REQ-new: New\n\n```missionspec\noperation: add\n```\n\nAdded behavior.\n';
  const baseline = parseMarkdownDocument({ path: 'missionspec/specs/a/spec.md', content: baselineSource }).document;
  const delta = parseMarkdownDocument({ path: 'missionspec/changes/a/specs/a/spec.md', content: deltaSource }).document;
  const promoted = promoteBaseline({ baseline, delta, path: 'missionspec/specs/a/spec.md' });
  assert.deepEqual(promoted.conflicts, []);
  assert(promoted.content.includes('Important introduction.\n\n## Requirements\n\nRequired context before declarations.'));
  assert(promoted.content.includes('Retained behavior.'));
  const remove = parseMarkdownDocument({
    path: 'change.md',
    content: deltaSource.replaceAll('REQ-new', 'REQ-old').replace('operation: add', 'operation: remove'),
  }).document;
  assert.notEqual(promoteBaseline({ baseline, delta: remove, path: 'missionspec/specs/a/spec.md' }).conflicts.length, 0);
});

test('promotion validates untouched nested capabilities and guards newly added baselines', async (t) => {
  const f = await accepted(t);
  const preview = await f.app.previewPromotion('filters', f.reference);
  assert.equal(preview.state, 'ready');
  const proposed = preview.plan.mutations.find((mutation) =>
    mutation.effect.kind === 'file-write' && mutation.effect.path === 'missionspec/specs/filters/spec.md').content;
  const duplicate = proposed.replace(/^id: .+$/m, 'id: ART-untouched');
  await mkdir(path.join(f.root, 'missionspec/specs/identity/untouched'), { recursive: true });
  await writeFile(path.join(f.root, 'missionspec/specs/identity/untouched/spec.md'), duplicate);
  const conflict = await f.app.previewPromotion('filters', f.reference);
  assert.equal(conflict.state, 'conflict');
  assert.match(conflict.conflicts.join('\n'), /duplicate identities/);
  await assert.rejects(
    f.app.commitPromotion('filters', f.reference, preview.plan, f.authority.issue(preview.plan.request)),
    { code: 'stale-revision' },
  );
});

test('promotion rechecks the full inventory inside the writer lock after preview recomputation', async (t) => {
  const f = await accepted(t);
  const preview = await f.app.previewPromotion('filters', f.reference);
  const added = preview.plan.mutations.find((mutation) =>
    mutation.effect.kind === 'file-write' && mutation.effect.path === 'missionspec/specs/filters/spec.md').content
    .replace(/^id: .+$/m, 'id: ART-concurrent')
    .replaceAll('REQ-filter', 'REQ-other-filter')
    .replaceAll('SCN-filter-reload', 'SCN-other-filter-reload');
  const commit = f.app.files.commit.bind(f.app.files);
  f.app.files.commit = async (plan, approval) => {
    await mkdir(path.join(f.root, 'missionspec/specs/other'), { recursive: true });
    await writeFile(path.join(f.root, 'missionspec/specs/other/spec.md'), added);
    return commit(plan, approval);
  };
  await assert.rejects(
    f.app.commitPromotion('filters', f.reference, preview.plan, f.authority.issue(preview.plan.request)),
    { code: 'stale-revision' },
  );
  assert.equal(await f.app.files.read('missionspec/specs/filters/spec.md'), null);
  assert.equal(await readFile(path.join(f.root, 'missionspec/specs/other/spec.md'), 'utf8'), added);
});
