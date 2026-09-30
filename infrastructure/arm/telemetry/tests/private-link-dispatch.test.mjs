import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { digest, json } from '../definition.mjs';
import { load } from '../controller.mjs';
import { privateLinkAzureIO, executePrivateLinkPhase, reconcilePrivateLinkPhase, recoverPrivateLinkPhase,
  privateLinkSubmissionState, verifyPrivateLinkControlEvidence } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';

const hash = value => digest(json(value));
const f = await privateLinkFixture({ ...privateInput, version: 2 });
const evidence = await privateControlChain(f, 'retire-nsp-rule');
async function fixture(t, invoke) {
  const q = await privateControlHarness({ ...f }, evidence, 'create-network');
  const directory = `infrastructure/arm/telemetry/tests/.private-link-dispatch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true }));
  const input = { publication: q.io.publication, proof: q.proof, approval: q.approval,
    costReview: q.io.costReview, costEvidence: q.io.costEvidence, migrationReview: q.io.migrationReview };
  const adapter = privateLinkAzureIO(f.c, f.context, evidence, q.phase, directory, input,
    (...args) => invoke(q, directory, ...args), { now: q.io.now, sourceDigest: q.io.sourceDigest });
  const io = { ...q.io, write: adapter.write, journal: adapter.journal,
    saveJournal: adapter.saveJournal };
  return { q, directory, adapter, io,
    execute: () => executePrivateLinkPhase(f.c, f.context, evidence, q.phase, q.proof, q.approval, io),
    original: journal => ({ phase: q.phase, publication: q.io.publication, approval: q.approval,
      preflight: q.proof, intent: q.intent, journal }) };
}
function recoveryReview(original, proposal, io, action = 'adopt-exact-private-link-late-state-without-replay') {
  return { version: 1, action, proposalSha256: hash(proposal), sourceSha256: proposal.sourceSha256,
    pendingHeadSha256: hash(proposal.pendingHead), approvedAt: new Date(io.now()).toISOString(),
    expiresAt: new Date(io.now() + 600000).toISOString() };
}

test('119-second post-body final check receives a full request allowance from the persisted rollout clock', async t => {
  let invocations = 0;
  const x = await fixture(t, async (q, directory, args, timeout) => {
    invocations++;
    assert.equal(args[args.indexOf('--method') + 1], 'PUT');
    assert.equal(timeout, 15000, 'fresh rollout must not inherit the one-second final-check remainder');
    const journal = await load(directory, 'private-link-create-network-journal.json');
    assert.equal(journal.version, 3);
    assert.equal(journal.dispatchAttempted, null);
    assert.equal(journal.dispatchAt, null);
    assert.equal(journal.outcome, 'submission-possible');
    assert.equal(journal.rolloutDeadline - Date.parse(journal.rolloutStartedAt), 120000);
    for (const d of q.phase.resources) q.after.resources[d.id].systemData.createdAt = new Date(q.io.now()).toISOString();
    q.advance(10000);
    q.setLive(q.after);
    return {};
  });
  const actualWrite = x.io.write;
  x.io.write = (phase, guard, current, mark, deadline) => actualWrite(phase, guard, async () => {
    x.q.advance(119000);
    await current();
  }, mark, deadline);
  const record = await x.execute();
  assert.equal(invocations, 1);
  assert.equal(Date.parse(record.journal.rolloutStartedAt) - Date.parse(record.intent.at), 119000);
  assert.equal(Date.parse(record.completedAt) - Date.parse(record.intent.at), 129000);
  assert.equal(record.journal.dispatchAttempted, true);
  verifyPrivateLinkControlEvidence(f.c, f.context, { ...evidence, records: [...evidence.records, record] });
});

test('a crash after actual dispatch leaves durable unknown evidence recoverable only by reviewed read-only state', async t => {
  let crashed = false, invocations = 0;
  const x = await fixture(t, async (q, directory) => {
    invocations++;
    const journal = await load(directory, 'private-link-create-network-journal.json');
    assert.equal(journal.dispatchAttempted, null);
    q.setLive(q.after);
    crashed = true;
    throw new Error('UNIT_PROCESS_LOST_AFTER_PUT');
  });
  x.io.saveJournal = value => {
    if (crashed) throw new Error('UNIT_PROCESS_GONE_NO_CATCH_PERSISTENCE');
    return x.adapter.saveJournal(value);
  };
  await assert.rejects(x.execute(), /UNIT_PROCESS_GONE/);
  const persisted = await x.adapter.journal(), original = x.original(persisted), bytes = json(original);
  assert.equal(privateLinkSubmissionState(original), 'dispatch-possible');
  assert.equal(persisted.dispatchAttempted, null);
  assert.equal(persisted.outcome, 'submission-possible');
  await assert.rejects(x.execute(), /INTENT_REPLAY_FORBIDDEN/);
  x.q.advance(121000);
  const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, x.q.io);
  assert.equal(proposal.submissionState, 'dispatch-possible');
  assert.equal(proposal.kind, 'private-link-late-state-proposal');
  const record = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal,
    recoveryReview(original, proposal, x.q.io), x.q.io);
  assert.equal(record.kind, 'reviewed-private-link-recovery');
  assert.equal(record.journal.dispatchAttempted, null);
  assert.equal(record.journal.outcome, 'submission-possible');
  assert.equal(record.recovery.proposal.originalExecutionQualified, false);
  assert.equal(json(original), bytes);
  assert.equal(invocations, 1);
});

test('resource absence never downgrades a durable possible-dispatch marker or legacy false journal', async t => {
  let crashed = false;
  const x = await fixture(t, async () => { crashed = true; throw new Error('UNIT_PROCESS_CRASH'); });
  x.io.saveJournal = value => {
    if (crashed) throw new Error('UNIT_PROCESS_GONE');
    return x.adapter.saveJournal(value);
  };
  await assert.rejects(x.execute(), /PROCESS_GONE/);
  const original = x.original(await x.adapter.journal()), read = x.q.io.read;
  x.q.setLive(x.q.before);
  x.q.io.read = (request, deadline) => request.id === x.q.phase.deploymentId
    ? Promise.resolve(null) : read(request, deadline);
  assert.equal(privateLinkSubmissionState(original), 'dispatch-possible');
  await assert.rejects(reconcilePrivateLinkPhase(f.c, f.context, evidence, original, x.q.io), /STAGE_RESOURCE_MISMATCH/);
  const legacy = structuredClone(original);
  legacy.journal.version = 2; legacy.journal.dispatchAttempted = false;
  legacy.journal.rolloutStartedAt = legacy.journal.rolloutDeadline = null;
  assert.equal(privateLinkSubmissionState(legacy), 'legacy-dispatch-unknown');
  await assert.rejects(reconcilePrivateLinkPhase(f.c, f.context, evidence, legacy, x.q.io), /STAGE_RESOURCE_MISMATCH/);
});

test('caught pre-arm failure is a terminal-abandoned no-submission resolution, not success or automatic continuation', async t => {
  const x = await fixture(t, async () => assert.fail('No transport invocation is allowed'));
  const head = x.io.head;
  x.io.head = async (value, pending) => {
    if (pending) throw new Error('UNIT_CAUGHT_PRE_ARM_FAILURE');
    return head(value, pending);
  };
  await assert.rejects(x.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  const original = x.original(await x.adapter.journal()), bytes = json(original), initial = json(evidence);
  assert.equal(privateLinkSubmissionState(original), 'known-not-submitted');
  assert.equal(original.journal.dispatchAttempted, false);
  assert.equal(original.journal.rolloutStartedAt, null);
  const read = x.q.io.read;
  x.q.io.read = (request, deadline) => request.id === x.q.phase.deploymentId ? Promise.resolve(null) : read(request, deadline);
  const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, x.q.io);
  assert.equal(proposal.kind, 'private-link-not-submitted-proposal');
  assert.equal(proposal.replayAuthorized, false);
  await assert.rejects(recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal,
    recoveryReview(original, proposal, x.q.io), x.q.io), /NO_SUBMISSION_REVIEW_REQUIRED/);
  let resolution;
  x.q.io.resolveNoSubmission = async (pending, record) => {
    await x.q.io.head(evidence, pending); resolution = record;
  };
  const record = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal,
    recoveryReview(original, proposal, x.q.io, 'record-exact-private-link-no-submission-without-replay'), x.q.io);
  assert.equal(record, resolution);
  assert.equal(record.qualified, false); assert.equal(record.resolution, 'terminal-abandoned');
  assert.equal(record.resumable, false); assert.equal(record.physicalFenceRetained, true);
  assert.equal(x.q.appended, null); assert.equal(json(evidence), initial);
  assert.equal(json(original), bytes);
  await assert.rejects(x.execute(), /INTENT_REPLAY_FORBIDDEN/);
});

test('marker persistence and post-persistence guard failures cannot dispatch', async t => {
  for (const failure of ['persistence', 'expiry']) await t.test(failure, async t => {
    const x = await fixture(t, async () => assert.fail('No dispatch after failed marker/guard'));
    x.io.saveJournal = async value => {
      if (value.dispatchAttempted === null) {
        if (failure === 'persistence') throw new Error('UNIT_DURABLE_MARKER_FAILED');
        await x.adapter.saveJournal(value);
        x.q.advance(1800000);
      } else await x.adapter.saveJournal(value);
    };
    await assert.rejects(x.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
    const original = x.original(await x.adapter.journal());
    assert.equal(privateLinkSubmissionState(original), 'known-not-submitted');
    assert.equal(original.journal.dispatchAttempted, false);
  });
});
