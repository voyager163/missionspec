import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {
  LocalWorkflow, LocalChecks, openRuntimeStore, digestContent, digestApprovalRequest,
  parseApprovalRequest, executionApprovalRequest, digestEffectScope, makeFilePlan,
} from '../dist/api/index.js';

const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
async function fixture(t, profile = 'standard') {
  const root = path.resolve(`.source-patch-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const approvals = new Map();
  // TEST ONLY authority fixture. No human, native host or model is represented by this map.
  const authority = {
    issue(request) {
      const parsed = parseApprovalRequest(request);
      const approval = { contractVersion: 1, state: 'trusted-issued', reference: { id: `APR-${randomUUID()}` },
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST ONLY patch review fixture') },
        request: parsed, requestDigest: digestApprovalRequest(parsed), issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 1_800_000).toISOString() };
      approvals.set(approval.reference.id, approval);
      return approval.reference;
    },
    async resolve(reference) { return { status: 'ok', value: approvals.has(reference.id)
      ? { state: 'current', approval: approvals.get(reference.id) } : { state: 'absent', reference } }; },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
  let app = await LocalWorkflow.open(root, { authority });
  const setup = await app.previewSetup(profile);
  await app.apply(setup, authority.issue(setup.request));
  const change = await app.previewNewChange({ slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'] });
  await app.apply(change, authority.issue(change.request));
  for (const node of ['proposal', 'specs', 'design', 'tasks']) {
    if (profile === 'compact' && node === 'design') {
      const applicability = await app.previewApplicability('filters', 'The small design is combined with tasks.');
      await app.apply(applicability, authority.issue(applicability.request));
      continue;
    }
    const names = node === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${node}.md`];
    const files = await Promise.all(names.map(async (name) => {
      let content = await readFile(path.resolve('assets/workflows/standard/examples', name), 'utf8');
      if (profile === 'compact' && node === 'tasks') content = content.replace('## Tasks', '## Design\n\nUse the existing preference service.\n\n## Tasks');
      return { path: `missionspec/changes/filters/${name.replace(/specs\/(.*)\.md/u, 'specs/$1/spec.md')}`, content };
    }));
    const capture = await app.previewArtifact('filters', node, files);
    await app.apply(capture, authority.issue(capture.request));
  }
  const candidate = (content = 'version one\n', expected = 'absent') => ({
    kind: 'inert-proposal', host: 'copilot', summary: 'TEST untrusted text proposal; no host execution occurred.',
    changes: [{ path: 'src/filter-preference.ts', expected, content }],
  });
  const connectStore = async () => {
    const store = ok(await openRuntimeStore({ directory: path.join(root, '.missionspec/state'),
      mode: 'create', expectedWorkspace: (await app.project()).workspace }));
    t.after(() => store.close());
    app = await LocalWorkflow.open(root, { authority, store });
    return { store, app, checks: new LocalChecks(app, store, authority) };
  };
  return { root, app, authority, candidate, connectStore };
}

test('inert output derives exact source effects but needs distinct approval and never manufactures host attempts or evidence', async (t) => {
  const f = await fixture(t);
  const before = await f.app.loadChange('filters');
  const journals = await readdir(path.join(f.root, '.missionspec/transactions'));
  const candidate = f.candidate();
  const plan = await f.app.previewSourcePatch('filters', 'TSK-filter', candidate);
  assert.equal(plan.request.operation, 'implement');
  assert.equal(plan.request.purpose, 'source-apply');
  assert.equal(plan.request.binding.kind, 'review');
  assert.equal(plan.sourcePatch.task.id, 'TSK-filter');
  assert.equal(plan.sourcePatch.proposal.digest, digestContent(JSON.stringify(candidate)));
  assert.equal(plan.mutations[0].effect.proposed, digestContent(candidate.changes[0].content));
  assert(plan.request.effects.every((effect) => effect.kind === 'file-write' && effect.purpose === 'source'));
  assert(!('execution' in plan.request));
  const hostEffects = [...plan.request.effects, { kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-filter'] }];
  assert.throws(() => parseApprovalRequest({ ...plan.request, effects: hostEffects,
    binding: { ...plan.request.binding, effects: digestEffectScope(hostEffects) } }));
  assert.throws(() => parseApprovalRequest({ ...plan.request, execution: {
    mode: 'auto', host: 'copilot', limits: { maxTasks: 1, maxDurationMs: 1000, maxRepairsPerTask: 2, concurrency: 1 },
  } }));
  assert.deepEqual(await readdir(path.join(f.root, '.missionspec/transactions')), journals);
  assert.equal(await f.app.files.read('src/filter-preference.ts'), null);
  const effects = [...plan.request.effects, { kind: 'host-dispatch', host: 'copilot', taskIds: ['TSK-filter'] }];
  const work = {
    contractVersion: 1, id: 'WRK-test-only', runId: 'RUN-test-only', task: plan.sourcePatch.task,
    revisions: { ...before.revisions, effects: digestEffectScope(effects) }, sourceBefore: before.revisions.source,
    approval: { id: 'APR-unissued' }, mode: 'auto', host: 'copilot',
    limits: { maxTasks: 1, maxDurationMs: 1000, maxRepairsPerTask: 2, concurrency: 1 }, effects,
  };
  const execution = f.authority.issue(executionApprovalRequest(work));
  await assert.rejects(f.app.commitSourcePatch('filters', 'TSK-filter', candidate, plan, execution), { code: 'scope-exceeded' });
  const approval = f.authority.issue(plan.request);
  await assert.rejects(f.app.apply(plan, approval), { code: 'invalid-input' });
  const committed = await f.app.commitSourcePatch('filters', 'TSK-filter', candidate, plan, approval);
  assert.equal(committed.state, 'committed');
  assert.equal((await f.app.files.read('src/filter-preference.ts')).content, 'version one\n');
  assert.equal(await f.app.files.read('.missionspec/state/ledger.sqlite'), null);
  assert.equal((await f.app.verificationGaps('filters')).acceptanceEligibility.state, 'ineligible');
  assert.equal((await f.app.loadChange('filters')).revisions.tasks, before.revisions.tasks);
  const journal = JSON.parse(await readFile(path.join(f.root, '.missionspec/transactions', `${committed.transactionId}.json`), 'utf8'));
  assert.equal(journal.plan.sourcePatch.task.id, 'TSK-filter');
  assert.equal(journal.approval.request.purpose, 'source-apply');
});

test('scope widening, control-file aliases, claimed approvals and unreviewed material changes are refused', async (t) => {
  const f = await fixture(t);
  const candidate = f.candidate();
  for (const path of ['other.ts', '.git', '.GIT/config', '.MISSIONSPEC/workspace.json', 'MissionSpec/config.yaml', 'packages/subproject/.git']) {
    await assert.rejects(f.app.previewSourcePatch('filters', 'TSK-filter', {
      ...candidate, changes: [{ ...candidate.changes[0], path }],
    }), { code: 'scope-exceeded' });
  }
  await assert.rejects(f.app.previewSourcePatch('filters', 'TSK-filter', { ...candidate, approved: true }));
  for (const path of ['.GIT/config', 'packages/subproject/.git', 'packages/subproject/.MISSIONSPEC/state/ledger.sqlite']) {
    await assert.rejects(f.app.previewNewChange({ slug: 'bad-root', specs: ['demo'], sourcePaths: [path] }));
  }
  const plan = await f.app.previewSourcePatch('filters', 'TSK-filter', candidate);
  assert.throws(() => makeFilePlan({ workspace: plan.workspace, guards: plan.guards, mutations: plan.mutations,
    operation: 'revise', purpose: 'artifact-edit' }));
  const approval = f.authority.issue(plan.request);
  await mkdir(path.join(f.root, 'src'));
  await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'concurrent user edit\n');
  await assert.rejects(f.app.commitSourcePatch('filters', 'TSK-filter', candidate, plan, approval), { code: 'stale-revision' });
  assert.equal((await f.app.files.read('src/filter-preference.ts')).content, 'concurrent user edit\n');
  const updated = f.candidate('new candidate\n', digestContent('concurrent user edit\n'));
  const next = await f.app.previewSourcePatch('filters', 'TSK-filter', updated);
  await assert.rejects(f.app.commitSourcePatch('filters', 'TSK-filter', updated, next, approval), { code: 'scope-exceeded' });
  assert.equal((await f.app.files.read('src/filter-preference.ts')).content, 'concurrent user edit\n');
});

test('source-patch recovery rolls forward only the exact reviewed bytes without widening scope', async (t) => {
  const f = await fixture(t);
  const candidate = { ...f.candidate(), changes: [
    ...f.candidate().changes, { path: 'tests/filter-preference.test.ts', expected: 'absent', content: 'TEST fixture assertion source\n' },
  ] };
  const plan = await f.app.previewSourcePatch('filters', 'TSK-filter', candidate);
  const approval = f.authority.issue(plan.request);
  const resolve = f.authority.resolve;
  let resolutions = 0;
  f.authority.resolve = async (ref) => ref.id === approval.id && ++resolutions === 3
    ? { status: 'ok', value: { state: 'absent', reference: ref } } : resolve(ref);
  await assert.rejects(f.app.commitSourcePatch('filters', 'TSK-filter', candidate, plan, approval), { code: 'effect-outcome-unknown' });
  assert.equal((await f.app.files.read('src/filter-preference.ts')).content, 'version one\n');
  assert.equal(await f.app.files.read('tests/filter-preference.test.ts'), null);
  const [id] = await f.app.files.pending();
  f.authority.resolve = resolve;
  const recovery = await f.app.files.recoveryPlan(id);
  await f.app.files.recover(id, f.authority.issue(recovery.request));
  assert.equal((await f.app.files.read('tests/filter-preference.test.ts')).content, 'TEST fixture assertion source\n');
  assert.deepEqual(await f.app.files.pending(), []);
});

test('dependent patch application requires real retained predecessor checks and does not turn patches into task-completion claims', async (t) => {
  const f = await fixture(t);
  const { app, store, checks } = await f.connectStore();
  const initial = f.candidate();
  const first = await app.previewSourcePatch('filters', 'TSK-filter', initial);
  await app.commitSourcePatch('filters', 'TSK-filter', initial, first, f.authority.issue(first.request));
  const candidate = f.candidate('version two\n', digestContent('version one\n'));
  await assert.rejects(app.previewSourcePatch('filters', 'TSK-reset', candidate), { code: 'evidence-unavailable' });
  const input = { checkId: 'CHK-filter', program: await realpath(process.execPath),
    argv: ['-e', 'require("node:assert/strict").equal(require("node:fs").readFileSync("src/filter-preference.ts", "utf8"), "version one\\n"); console.log("Actual fixture assertion passed");'],
    cwd: '.', controlFiles: [], timeoutMs: 2000, guarantees: 'trusted-local-process' };
  const registration = await checks.previewRegistration('filters', input);
  const registered = await checks.register('filters', input, f.authority.issue(registration.request));
  const preview = await checks.previewCollection('filters', 'RUN-predecessor', [registered.id]);
  const collected = await checks.collect('filters', 'RUN-predecessor', [registered.id], f.authority.issue(preview.request));
  const dependencies = { runId: collected.runId, evidence: collected.evidence };
  const plan = await app.previewSourcePatch('filters', 'TSK-reset', candidate, dependencies);
  assert.deepEqual(plan.sourcePatch.dependencies, dependencies);
  const otherTask = await app.previewSourcePatch('filters', 'TSK-filter', candidate);
  await assert.rejects(app.commitSourcePatch('filters', 'TSK-reset', candidate, plan,
    f.authority.issue(otherTask.request), dependencies), { code: 'scope-exceeded' });
  const ref = ok(await store.readEvidence(collected.evidence[0]));
  const raw = await readFile(path.join(f.root, ref.storage.path), 'utf8');
  await writeFile(path.join(f.root, ref.storage.path), 'tampered evidence');
  await assert.rejects(app.commitSourcePatch('filters', 'TSK-reset', candidate, plan, f.authority.issue(plan.request), dependencies), { code: 'evidence-unavailable' });
  await writeFile(path.join(f.root, ref.storage.path), raw);
  await app.commitSourcePatch('filters', 'TSK-reset', candidate, plan, f.authority.issue(plan.request), dependencies);
  const run = ok(await store.readRun(collected.runId)).snapshot;
  assert.deepEqual(run.attempts, []);
  assert.equal(run.completions, undefined);
  assert.equal((await app.files.read('src/filter-preference.ts')).content, 'version two\n');
  await assert.rejects(app.verify('filters', collected.runId, collected.evidence), { code: 'stale-revision' });
});

test('Compact applicability follows only committed exact source transitions, never arbitrary source edits', async (t) => {
  const f = await fixture(t, 'compact');
  const initial = await f.app.loadChange('filters');
  const original = initial.metadata.nodes.find((node) => node.node === 'design').applicability;
  for (const [before, after] of [['absent', 'version one\n'], [digestContent('version one\n'), 'version two\n']]) {
    const candidate = f.candidate(after, before);
    const plan = await f.app.previewSourcePatch('filters', 'TSK-filter', candidate);
    await f.app.commitSourcePatch('filters', 'TSK-filter', candidate, plan, f.authority.issue(plan.request));
    const current = await f.app.loadChange('filters');
    assert.equal(current.implementationReady, true);
    assert.deepEqual(current.metadata.nodes.find((node) => node.node === 'design').applicability, original);
    assert.equal(current.revisions.workflow, initial.revisions.workflow);
  }
  await writeFile(path.join(f.root, 'src/filter-preference.ts'), 'unreviewed source change\n');
  assert.equal((await f.app.loadChange('filters')).implementationReady, false);
});
