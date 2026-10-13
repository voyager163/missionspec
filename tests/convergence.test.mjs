import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import test from 'node:test';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { LocalConvergence } from '../dist/application/convergence.js';
import { digestApprovalRequest } from '../dist/kernel/authority.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { digestEffectScope } from '../dist/kernel/effects.js';
import {
  includeConvergence, parseConvergenceReview, proposedConvergenceRepairs,
} from '../dist/engines/verification/contracts.js';

const hash = digestContent('TEST original review fixture');
const revisions = {
  workspace: { workspaceId: 'WSP-review-test', rootDigest: hash }, changeId: 'CHG-review',
  specification: hash, tasks: hash, workflow: hash, effects: digestEffectScope([]), source: hash,
};
const observed = { path: 'src/example.ts', digest: digestContent('export const value = 1;\n') };
const task = {
  contractVersion: 1, id: 'TSK-example', title: 'Provide the example', dependsOn: [],
  requirements: ['REQ-example'], scenarios: ['SCN-example'], checks: ['CHK-example'], writeScope: [observed.path],
};
const analysis = { tasks: [task], checks: [], coverage: [], clarificationBlockers: [], artifactRevision: hash };
const report = {
  contractVersion: 1, revisions, source: hash, observations: [], completeness: [], correctness: [],
  coherence: [], proposedRepairs: [], acceptanceEligibility: { state: 'eligible-for-human-review', evidence: [] },
};
const finding = (gap, id = 'FND-example') => ({
  id, basis: 'static-inspection', severity: 'blocking', summary: 'Original synthetic behavior observation.',
  paths: [observed.path], gap, requirements: ['REQ-example'], tasks: [task.id], evidence: [], observations: [observed],
});
const review = (findings) => ({
  schemaVersion: 1, revisions, scope: 'declared-source-files-only', sourceFiles: [observed], findings,
});

test('all four convergence categories retain basis/traceability and block acceptance without effects', () => {
  const value = review(['missing', 'partial', 'contradictory', 'unrequested'].map((gap) => finding(gap, `FND-${gap}`)));
  const merged = includeConvergence(report, value, analysis);
  assert.deepEqual(merged.completeness.map((finding) => finding.gap), ['missing', 'partial']);
  assert.deepEqual(merged.correctness.map((finding) => finding.gap), ['contradictory']);
  assert.deepEqual(merged.coherence.map((finding) => finding.gap), ['unrequested']);
  assert.equal(merged.acceptanceEligibility.state, 'ineligible');
  assert.equal(merged.proposedRepairs.length, 4);
  for (const task of merged.proposedRepairs) {
    assert.deepEqual(task.writeScope, [observed.path]);
    assert.deepEqual(task.checks, ['CHK-example']);
    assert.match(task.id, /^TSK-repair-/u);
  }
  assert.deepEqual(proposedConvergenceRepairs(value, analysis), merged.proposedRepairs);
  assert.equal(report.coherence.length, 0);
});

test('empty semantic findings cannot clear failed/missing checks and do not pretend to execute tests', () => {
  const failed = { ...report, acceptanceEligibility: { state: 'ineligible', reasons: ['An executed check failed.'] } };
  const merged = includeConvergence(failed, review([]), analysis);
  assert.deepEqual(merged.acceptanceEligibility, failed.acceptanceEligibility);
  assert.deepEqual(merged.observations, []);
});

test('unknown identities, mismatched source, stale revisions and claimed executed review basis are rejected', () => {
  assert.throws(() => includeConvergence(report, review([{ ...finding('partial'), requirements: ['REQ-absent'] }]), analysis));
  assert.throws(() => includeConvergence(report, review([{ ...finding('partial'), evidence: ['EVD-forged'] }]), analysis));
  assert.throws(() => parseConvergenceReview(review([{ ...finding('partial'), observations: [{ ...observed, digest: hash }] }])));
  assert.throws(() => includeConvergence(report, { ...review([]), revisions: { ...revisions, source: digestContent('changed') } }, analysis));
  assert.throws(() => parseConvergenceReview(review([{ ...finding('partial'), basis: 'executed-check' }])));
  assert.throws(() => parseConvergenceReview({ ...review([]), approved: true }));
});

async function fixture(context) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-convergence-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  const records = new Map();
  // TEST ONLY: this channel does not qualify human review or a native host.
  const authority = {
    issue(request) {
      const reference = { id: `APR-${randomUUID()}` };
      const now = Date.now();
      records.set(reference.id, {
        contractVersion: 1, state: 'trusted-issued', reference, request, requestDigest: digestApprovalRequest(request),
        assurance: { kind: 'local-user', channel: 'qualified-host-callback', qualificationEvidence: digestContent('TEST ONLY') },
        issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60_000).toISOString(),
      });
      return reference;
    },
    async resolve(reference) {
      const approval = records.get(reference.id);
      return { status: 'ok', value: approval ? { state: 'current', approval } : { state: 'absent', reference } };
    },
    async requestConfirmation() { return { status: 'ok', value: { state: 'unavailable', reason: 'no-local-user' } }; },
  };
  const workflow = await LocalWorkflow.open(root, { authority });
  const setup = await workflow.previewSetup();
  await workflow.apply(setup, authority.issue(setup.request));
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, observed.path), 'export const value = 1;\n');
  const change = await workflow.previewNewChange({ slug: 'example', specs: ['example'], sourcePaths: [observed.path] });
  await workflow.apply(change, authority.issue(change.request));
  const loaded = await workflow.loadChange('example');
  const service = new LocalConvergence(workflow, authority);
  const value = {
    ...review([{ ...finding('unrequested'), requirements: [], tasks: [] }]), revisions: loaded.revisions,
  };
  return { root, workflow, service, authority, value };
}

test('review capture requires exact authority, preserves immutable history and supersedes only after review', async (context) => {
  const f = await fixture(context);
  const before = await readdir(path.join(f.root, '.missionspec'));
  const prepared = await f.service.preview('example', f.value);
  assert.deepEqual(await readdir(path.join(f.root, '.missionspec')), before);
  await assert.rejects(f.service.capture('example', f.value, { id: 'APR-forged' }), { code: 'authority-required' });
  const first = await f.service.capture('example', f.value, f.authority.issue(prepared.request));
  assert.equal((await f.service.current('example')).id, first.id);
  const reportAtSource = { ...report, revisions: f.value.revisions, source: f.value.revisions.source };
  const emptyAnalysis = { ...analysis, tasks: [] };
  assert.equal((await f.service.include('example', reportAtSource, emptyAnalysis)).acceptanceEligibility.state, 'ineligible');
  const next = { ...f.value, findings: [] };
  const nextPreview = await f.service.preview('example', next);
  await assert.rejects(f.service.capture('example', next, f.authority.issue(prepared.request)), { code: 'scope-exceeded' });
  const second = await f.service.capture('example', next, f.authority.issue(nextPreview.request));
  assert.equal(second.supersedes, first.id);
  assert.equal((await f.service.current('example')).id, second.id);
  assert.equal((await readdir(path.join(f.root, '.missionspec/audit'))).filter((name) => name.startsWith('convergence-')).length, 2);
});

test('source changes stale the captured review rather than dropping its blockers', async (context) => {
  const f = await fixture(context);
  const prepared = await f.service.preview('example', f.value);
  await f.service.capture('example', f.value, f.authority.issue(prepared.request));
  await writeFile(path.join(f.root, observed.path), 'export const value = 2;\n');
  await assert.rejects(f.service.preview('example', f.value), { code: 'stale-revision' });
  const loaded = await f.workflow.loadChange('example');
  const currentReport = { ...report, revisions: loaded.revisions, source: loaded.revisions.source };
  const result = await f.service.include('example', currentReport, loaded.analysis);
  assert.equal(result.acceptanceEligibility.state, 'ineligible');
  assert(result.acceptanceEligibility.reasons.some((reason) => reason.includes('stale')));
});
