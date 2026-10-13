import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, readdir, rm, stat } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { digestJson as hash, json } from '../definition.mjs';
import { load, MAX_PRIVATE_ARTIFACT_BYTES } from '../controller.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as STAGES, privateLinkPhase } from '../private-link.mjs';
import { verifyPrivateLinkControlEvidence, verifyPrivateLinkRuntimePrerequisites, preparePrivateLinkPhase,
  checkPrivateLinkPhase, executePrivateLinkPhase, reconcilePrivateLinkPhase, recoverPrivateLinkPhase,
  privateLinkHead } from '../private-link-controller.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';
import { privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';

test('all 18 stages including post-runtime late recovery and explicit continuation remain semantic evidence after root-codec reload', async t => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 }), evidence = await privateControlChain(f);
  f.at = Date.parse(evidence.records.at(-1).completedAt) + 1000;
  const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
  const runtime = await privateRuntimeCompletionFixture(f, structuredClone(evidence), prerequisites);
  f.at = runtime.at + 1000;
  const n = f.context.plan.topology.ids, runtimeHash = hash(runtime.completion);
  const snapshot = value => {
    value.resources[n.app] = structuredClone(runtime.completion.disable.observation.app);
    value.images.manifests = structuredClone(runtime.completion.candidate.publication.manifests);
    value.images.queueManifest = JSON.parse(runtime.completion.candidate.profile.manifestJson);
    if (!value.lists.groupResources.value.some(resource => resource.id === n.app)) value.lists.groupResources.value.push(value.resources[n.app]);
    value.lists.apps.value.push(value.resources[n.app]);
  };
  for (const stage of STAGES.slice(13)) {
    const q = await privateControlHarness(f, evidence, stage, { runtimeCompletion: runtime.completion, snapshot });
    let record;
    if (stage === 'retire-old-receiver' || stage === 'retire-old-environment') {
      const write = q.io.write, invoked = stage === 'retire-old-receiver';
      q.io.write = async (...args) => {
        if (invoked) await write(...args);
        throw new Error(invoked ? 'UNIT_POST_RUNTIME_UNKNOWN' : 'UNIT_POST_RUNTIME_NO_SUBMISSION');
      };
      await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
      const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
        intent: q.intent, journal: structuredClone(q.journal) };
      const proposal = await reconcilePrivateLinkPhase(f.c, f.context, evidence, original, q.io);
      const recoveryReview = { version: 1,
        action: invoked ? 'adopt-exact-private-link-late-state-without-replay' : 'record-exact-private-link-no-submission-without-replay',
        proposalSha256: hash(proposal), sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead),
        approvedAt: new Date(q.io.now()).toISOString(), expiresAt: new Date(q.io.now() + 600000).toISOString() };
      const recovered = await recoverPrivateLinkPhase(f.c, f.context, evidence, original, proposal, recoveryReview,
        { ...q.io, resolveNoSubmission: async () => {} });
      if (invoked) record = recovered;
      else {
        const attemptId = randomUUID(), fixed = privateLinkPhase(f.c, f.context, stage);
        const continuation = { version: 1, kind: 'reviewed-private-link-no-submission-continuation', attemptId, resolution: recovered,
          review: { version: 1, action: 'continue-exact-known-not-submitted-private-link-phase', configSha256: hash(f.c),
            planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin), stage, attemptId,
            resolutionSha256: hash(recovered), priorIntentSha256: hash(original.intent), pendingHeadSha256: hash(proposal.pendingHead),
            fixedPhaseSha256: hash(fixed), requestSha256: hash(fixed.request), sourceSha256: f.source,
            approvedAt: new Date(q.io.now()).toISOString(), expiresAt: new Date(q.io.now() + 600000).toISOString() } };
        const phase = preparePrivateLinkPhase(f.c, f.context, evidence, stage, null, continuation);
        let head = proposal.pendingHead, journal = null;
        const io = { ...q.io, write, journal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
          head: async (_prior, expected) => { if (expected) assert.deepEqual(head, expected); return head; },
          reserve: async (_prior, exact, intent) => (head = { version: 1, kind: 'private-link-pending-head',
            targetKey: phase.expectedHead.targetKey, previous: exact.expectedHead, intentSha256: hash(intent) }),
          append: async (pending, _record, next) => { assert.deepEqual(head, pending); head = next; } };
        const proof = await checkPrivateLinkPhase(f.c, f.context, evidence, phase, io);
        const approval = { version: 1, action: `execute-exact-private-link-${stage}`, configSha256: hash(f.c),
          planSha256: f.context.plan.planSha256, phaseSha256: hash(phase), bindingSha256: hash(proof.binding),
          sourceSha256: f.source, requestSha256: hash(phase.request), approvedAt: new Date(q.io.now()).toISOString(),
          expiresAt: new Date(q.io.now() + 600000).toISOString() };
        record = await executePrivateLinkPhase(f.c, f.context, evidence, phase, proof, approval, io);
        assert.deepEqual(head, privateLinkHead(f.context, { ...evidence, records: [...evidence.records, record] }));
        assert.equal(record.phase.continuation.attemptId, attemptId);
      }
    } else record = await q.execute();
    evidence.records.push(record); f.at += 1000;
  }
  assert.equal(evidence.records.length, 18);
  assert.equal(evidence.records[13].kind, 'reviewed-private-link-recovery');
  assert(evidence.records[14].phase.continuation);
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, evidence, f.at).stage, 'record-migration');
  const directory = resolve(`infrastructure/arm/telemetry/tests/.full-aggregate-${randomUUID()}`), root = resolve(directory, 'blobs');
  await mkdir(root, { recursive: true, mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const codec = createPrivateLinkArtifactStore({ root }), originalHash = hash(evidence);
  await codec.immutable(directory, 'complete-evidence.json', evidence);
  const disk = await load(directory, 'complete-evidence.json');
  assert.equal(disk.version, 3);
  const restored = await codec.load(directory, 'complete-evidence.json');
  assert.equal(hash(restored), originalHash);
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, restored, f.at).stage, 'record-migration');
  assert.equal(hash(restored.records[13].preflight.runtimeCompletion), runtimeHash);
  assert.equal(hash(restored.records[13].recovery.original.preflight.runtimeCompletion), runtimeHash);
  assert.equal(hash(restored.records[14].phase.continuation.resolution.original.preflight.runtimeCompletion), runtimeHash);
  const sizes = {};
  for (const name of await readdir(root)) sizes[name] = (await stat(resolve(root, name))).size;
  assert(Object.values(sizes).reduce((sum, value) => sum + value, 0) <= MAX_PRIVATE_ARTIFACT_BYTES);
  assert((await stat(resolve(directory, 'complete-evidence.json'))).size <= MAX_PRIVATE_ARTIFACT_BYTES);
  assert.equal(hash(evidence), originalHash);
  const bad = structuredClone(restored); bad.records[14].phase.continuation.resolution.original.journal.dispatchAttempted = null;
  assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context, bad, f.at));
  t.diagnostic(json({ records: 18, fullSemanticVerifierAfterReload: true, postRuntimeLateRecovery: true,
    postRuntimeContinuedRecord: true, totalDistinctBytes: Object.values(sizes).reduce((a, b) => a + b), sizes }));
});
