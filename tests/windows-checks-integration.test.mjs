import assert from 'node:assert/strict';
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalChecks } from '../dist/adapters/authority/local-checks.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { createPrivateFixtureRoot, privateEntry, removeFixtureRoot } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 840_000 };
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
const issued = (result) => { const value = ok(result); assert.equal(value.state, 'issued'); return value.approval.reference; };

test('Windows registered checks bind real job output, controls, authority and persistent unknown outcomes', windows, async (t) => {
  const f = createPrivateFixtureRoot();
  let store;
  t.after(() => { try { if (store) ok(store.close()); } finally { removeFixtureRoot(f.root, f.identity); } });
  // TEST ONLY: independent trusted callback for storage/process qualification.
  // Actual console issuance is qualified separately through the ConPTY suite.
  const authority = await openLocalAuthority({ directory: f.root, transport: {
    channel: 'trusted-callback', protocolIdentity: { id: 'test.windows-checks', version: '1' },
    async confirm() { return 'accept'; },
  } });
  let workflow = await LocalWorkflow.open(f.root, { authority });
  const apply = async (plan) => workflow.apply(plan, issued(await authority.confirmPlan(plan)));
  await apply(await workflow.previewSetup());
  await apply(await workflow.previewNewChange({
    slug: 'filters', id: 'CHG-remember-filter', specs: ['filters', 'reset'],
    sourcePaths: ['src/filter-preference.ts', 'tests/filter-preference.test.ts'],
  }));
  const drafts = {};
  for (const node of ['proposal', 'specs', 'design', 'tasks']) {
    const names = node === 'specs' ? ['specs/filters.md', 'specs/reset.md'] : [`${node}.md`];
    drafts[node] = names.map((name) => ({
      path: `missionspec/changes/filters/${name.replace(/specs\/(.*)\.md$/u, 'specs/$1/spec.md')}`,
      content: readFileSync(new URL(`../assets/workflows/standard/examples/${name}`, import.meta.url), 'utf8'),
    }));
  }
  await apply((await workflow.previewDraftAll('filters', drafts)).plan);
  const workspace = (await workflow.project()).workspace;
  store = ok(await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'create', expectedWorkspace: workspace }));
  workflow = await LocalWorkflow.open(f.root, { store, authority });
  let checks = new LocalChecks(workflow, store, authority);
  const control = path.join(f.root, 'selected-control.txt');
  privateEntry(control, false, true);
  writeFileSync(control, 'reviewed control');
  const input = { checkId: 'CHK-filter', program: realpathSync.native(process.execPath),
    argv: ['-e', 'console.log("actual Windows registered check");'], cwd: '.', controlFiles: ['selected-control.txt'],
    timeoutMs: 5000, guarantees: 'trusted-local-process' };
  const register = async (value) => {
    const preview = await checks.previewRegistration('filters', value);
    const approval = issued(await authority.requestConfirmation(preview.request));
    return { ...await checks.register('filters', value, approval), approval };
  };
  await assert.rejects(checks.previewRegistration('filters', { ...input, approved: true }));
  await assert.rejects(checks.previewRegistration('filters', { ...input, guarantees: 'hard-confinement' }), { code: 'check-unqualified' });
  const registered = await register(input);
  writeFileSync(control, 'unreviewed control');
  await assert.rejects(checks.previewCollection('filters', 'RUN-windows-check', [registered.id]), { code: 'stale-revision' });
  writeFileSync(control, 'reviewed control');
  const preview = await checks.previewCollection('filters', 'RUN-windows-check', [registered.id]);
  const approval = issued(await authority.requestConfirmation(preview.request));
  const collected = await checks.collect('filters', 'RUN-windows-check', [registered.id], approval);
  assert.equal(collected.state, 'collected');
  assert.equal(collected.evidence.length, 1);
  const evidence = ok(await store.readEvidence(collected.evidence[0]));
  const raw = JSON.parse(readFileSync(path.join(f.root, evidence.storage.path), 'utf8'));
  assert.equal(raw.result, 'passed');
  const output = JSON.parse(raw.output);
  assert.equal(output.stdout, 'actual Windows registered check\n');
  assert.equal(output.quiescence, 'confirmed');
  assert.equal(output.interrupted, false);
  assert.equal(output.sourceBefore, output.sourceAfter);
  assert.match(output.registration.limitations, /No filesystem\/network confinement/u);
  assert.equal(ok(await store.readRun('RUN-windows-check')).snapshot.quiescence, 'confirmed');
  ok(store.close()); store = undefined;
  store = ok(await openRuntimeStore({ directory: path.join(f.root, '.missionspec/state'), mode: 'read-write', expectedWorkspace: workspace }));
  workflow = await LocalWorkflow.open(f.root, { store, authority });
  checks = new LocalChecks(workflow, store, authority);
  assert.equal(ok(await store.readEvidence(collected.evidence[0])).storage.digest, evidence.storage.digest);
  await checks.previewCollection('filters', 'RUN-windows-check', [registered.id]);

  const expiringPreview = await checks.previewRegistration('filters', input);
  const expiring = issued(await authority.requestConfirmation(expiringPreview.request));
  const expired = new LocalChecks(workflow, store, authority, { now: () => new Date(Date.now() + 31 * 60_000).toISOString() });
  await assert.rejects(expired.register('filters', input, expiring), { code: 'authority-expired' });
  const timed = await register({ ...input, checkId: 'CHK-reset', argv: ['-e', 'setInterval(()=>{},100)'], timeoutMs: 100 });
  const timeoutPreview = await checks.previewCollection('filters', 'RUN-windows-timeout', [timed.id]);
  await assert.rejects(checks.collect('filters', 'RUN-windows-timeout', [timed.id],
    issued(await authority.requestConfirmation(timeoutPreview.request))), { code: 'effect-outcome-unknown' });
  const unknown = ok(await store.readRun('RUN-windows-timeout')).snapshot;
  assert.equal(unknown.state, 'outcome-unknown');
  assert.equal(unknown.quiescence, 'unconfirmed');
  assert.deepEqual(ok(await store.readRunEvidence('RUN-windows-timeout')), []);
  const retained = await workflow.files.list('.missionspec/evidence');
  const interruptedRaw = await Promise.all(retained.map(async (file) => JSON.parse((await workflow.files.read(file)).content)));
  assert.ok(interruptedRaw.some((record) => record.result === 'failed' && JSON.parse(record.output).interrupted === true));
  await assert.rejects(checks.previewCollection('filters', 'RUN-windows-timeout', [timed.id]), { code: 'stale-revision' });
  await authority.revoke(registered.approval);
  await assert.rejects(checks.previewCollection('filters', 'RUN-windows-check', [registered.id]), { code: 'authority-required' });
});
