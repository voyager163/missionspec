import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { digest, digestJson as hash, ids, json } from '../definition.mjs';
import { privateInput, privateLinkFixture, privateControlChain, privateCostFixture, privateControlHarness } from './private-link.fixture.mjs';
import { PRIVATE_LINK_CONTROL_STAGES, verifyPrivateLinkNameProjection, privateLinkRuntimeNameIds,
  privateLinkNameBinding, privateLinkRuntimeResources, verifyPrivateLinkRuntimeName } from '../private-link.mjs';
import { withPrivateLinkAssignedPrefixHash } from '../private-link.mjs';
import { verifyPrivateLinkControlEvidence, verifyPrivateLinkRuntimePrerequisites, privateLinkReadIO,
  currentPrivateLinkRuntimeProof, privateLinkTargetKey, privateLinkHead, reconcilePrivateLinkPhase,
  recoverPrivateLinkPhase } from '../private-link-controller.mjs';
import { verifyPrivateLinkSnapshot, collectPrivateLinkSnapshot } from '../private-link-readback.mjs';
import { verifyRuntimeReview, privateLinkRuntimeTarget, privateRuntimePhase, verifyCreateIntent, verifyWindowIntent,
  verifyPrivateLinkRuntimeCompletion, publicControlTarget, preparePrivateLinkDisableRecovery, recoverPrivateLinkDisabled,
  privateLinkRuntimeIO } from '../private-link-runtime.mjs';
import { privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';
import { privateLinkRuntimeWhatIfContext } from '../private-link-whatif.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';
import { retainedReadInvoke } from './private-link-nsg-adoption.fixture.mjs';

const f = await privateLinkFixture({ ...structuredClone(privateInput), version: 2 });
const evidence = await privateControlChain(f);
const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
const originalBytes = json({ context: f.context, evidence, candidate: f.candidate });
function projection(at = f.at, ttl = 1800000) {
  return { version: 1, action: 'use-reviewed-private-link-runtime-names', decision: 'use-two-shortened-runtime-names',
    configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
    controlEvidenceSha256: hash(evidence), ...privateLinkRuntimeNameIds(f.c), sourceSha256: f.source,
    publication: { commitSha: 'c'.repeat(40), sourceSha256: f.source }, approvedAt: new Date(at - 1).toISOString(),
    expiresAt: new Date(at + ttl).toISOString() };
}
function review(at = f.at, names = projection(at)) {
  const cost = privateCostFixture(f, at);
  return { policyRevision: null, costReview: cost.review, costEvidence: cost.evidence, nameProjection: names };
}
function projectedSnapshot(base, names, app = null, probe = null) {
  const s = structuredClone(base);
  s.nameProjection = structuredClone(names);
  const old = names.original, n = names.projected;
  for (const [key, value] of [['app', app], ['publicProbe', probe]]) {
    s.resources[old[key]] = null;
    s.resources[n[key]] = value ? structuredClone(value) : null;
    delete s.diagnostics[old[key]];
    s.diagnostics[n[key]] = { value: [] };
  }
  s.lists.apps.value = s.lists.apps.value.filter(v => !Object.values(old).includes(v.id) && !Object.values(n).includes(v.id));
  s.lists.groupResources.value = s.lists.groupResources.value.filter(v => !Object.values(old).includes(v.id) && !Object.values(n).includes(v.id));
  for (const value of [app, probe].filter(Boolean)) {
    s.lists.apps.value.push(structuredClone(value));
    s.lists.groupResources.value.push(structuredClone(value));
  }
  if (app || probe) {
    s.images.manifests = structuredClone(f.candidate.publication.manifests);
    s.images.queueManifest = JSON.parse(f.candidate.profile.manifestJson);
  }
  return s;
}

test('name projection is exact, explicitly reviewed, prefix-bound and never mutates original plan/history/image', () => {
  const names = projection(), runtimeReview = review(f.at, names);
  verifyRuntimeReview(f.c, f.context, runtimeReview, f.at);
  verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, evidence);
  const target = privateLinkRuntimeTarget(f.c, f.context, f.candidate, prerequisites, runtimeReview, evidence);
  assert.equal(target.version, 2);
  assert.equal(target.appId, names.projected.app);
  assert.equal(publicControlTarget(f.c, target, f.context, evidence).appId, names.projected.publicProbe);
  assert(target.descriptor.expected.name.endsWith('-pl-ingest'));
  assert.equal(target.descriptor.expected.properties.template.containers[0].image,
    f.context.plan.stages.find(v => v.id === 'create-disabled-receiver').resources[0].expected.properties.template.containers[0].image);
  assert.equal(json({ context: f.context, evidence, candidate: f.candidate }), originalBytes);
  assert.deepEqual(verifyPrivateLinkControlEvidence(f.c, f.context, evidence, f.at), evidence.records.at(-1));
  const legacyTarget = privateLinkRuntimeTarget(f.c, f.context, f.candidate, prerequisites);
  const changed = structuredClone(f.context);
  changed.plan.topology.ids.publicProbe += '-foreign';
  assert.throws(() => publicControlTarget(f.c, legacyTarget, changed, evidence), /PRIVATE_PUBLIC_CONTROL_ID_CHANGED/);
});

test('changed mapping, prefix, source, review, old-app collision or assigned prefix never gain projection authority', () => {
  for (const mutate of [
    v => { v.projected.app = ids(f.c).app; },
    v => { v.projected.publicProbe = v.projected.app; },
    v => { v.original.app += '-changed'; },
    v => { v.projected.app = v.projected.app.replace(f.c.namePrefix, 'missionspec-other'); },
    v => { v.controlEvidenceSha256 = '0'.repeat(64); },
    v => { v.planSha256 = '0'.repeat(64); },
    v => { v.configSha256 = '0'.repeat(64); },
    v => { v.originSha256 = '0'.repeat(64); },
    v => { v.publication.sourceSha256 = '0'.repeat(64); },
    v => { v.decision = 'automatic-truncation'; },
    v => { v.version = 2; },
    v => { v.expiresAt = new Date(f.at - 1).toISOString(); },
    v => { v.extra = true; },
  ]) {
    const names = projection(); mutate(names);
    assert.throws(() => verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, evidence));
  }
  const wrongSource = review();
  wrongSource.nameProjection.sourceSha256 = wrongSource.nameProjection.publication.sourceSha256 = 'a'.repeat(64);
  assert.throws(() => verifyRuntimeReview(f.c, f.context, wrongSource, f.at));
  assert.throws(() => verifyPrivateLinkNameProjection(f.c, f.context, projection(), f.at, { ...evidence, records: evidence.records.slice(0, 12) }));
  for (const version of [1, 2]) {
    const context = { ...f.context, plan: { ...f.context.plan, version } };
    assert.throws(() => verifyPrivateLinkNameProjection(f.c, context, projection(), f.at, evidence));
  }
  assert.equal(verifyPrivateLinkRuntimeName('a'.repeat(32)).length, 32);
  assert.throws(() => verifyPrivateLinkRuntimeName('a'.repeat(33)), /RUNTIME_NAME_INVALID/);
  assert.throws(() => verifyPrivateLinkRuntimeName('missionspec-au260922-private-ingest'), /RUNTIME_NAME_INVALID/);
  assert.throws(() => verifyPrivateLinkRuntimeName('missionspec-au260922-public-probe'), /RUNTIME_NAME_INVALID/);
});

test('prefix digest reuse never trusts a shallow freeze or shares review validity across operations', async () => {
  const shallow = structuredClone(evidence), names = projection();
  Object.freeze(shallow);
  await withPrivateLinkAssignedPrefixHash(shallow, async () => {
    verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, shallow);
    await Promise.resolve();
    shallow.records[0].authority.ingestionAuthorized = true;
    assert.throws(() => verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, shallow), /NAME_PREFIX_CHANGED/);
  });
  const immutable = structuredClone(evidence);
  const freeze = value => {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      Object.values(value).forEach(freeze);
      Object.freeze(value);
    }
  };
  freeze(immutable);
  await withPrivateLinkAssignedPrefixHash(immutable, async () => {
    verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, immutable);
    await Promise.resolve();
    assert.throws(() => verifyPrivateLinkNameProjection(f.c, f.context, names, Date.parse(names.expiresAt), immutable),
      /NAME_REVIEW_EXPIRED/);
  });
  assert.throws(() => withPrivateLinkAssignedPrefixHash(immutable, () => {
    verifyPrivateLinkNameProjection(f.c, f.context, { ...names, controlEvidenceSha256: '0'.repeat(64) }, f.at, immutable);
  }), /NAME_PREFIX_CHANGED/);
  verifyPrivateLinkNameProjection(f.c, f.context, names, f.at, immutable);
});

test('renewed admission review has stable target identity and a closed projected native what-if phase', () => {
  const first = projection(f.at, 1000), second = projection(f.at + 2000);
  const a = privateLinkRuntimeTarget(f.c, f.context, f.candidate, prerequisites, review(f.at, first), evidence);
  const b = privateLinkRuntimeTarget(f.c, f.context, f.candidate, prerequisites, review(f.at + 2000, second), evidence);
  assert.deepEqual(a, b);
  assert.deepEqual(privateLinkNameBinding(f.c, f.context, first, evidence), privateLinkNameBinding(f.c, f.context, second, evidence));
  for (const action of ['create-disabled', 'enable', 'disable', 'create-public-probe']) {
    const target = action === 'create-public-probe' ? publicControlTarget(f.c, a, f.context, evidence) : a;
    const phase = privateRuntimePhase(f.c, target, '00000000-0000-4000-8000-000000000077', action, hash(evidence));
    assert.equal(phase.version, 2);
    const context = privateLinkRuntimeWhatIfContext(f.c, phase);
    assert.equal(context.runtimeTargetSha256, hash(target));
    const changed = structuredClone(phase);
    changed.request.body.properties.template.resources[0].name = `${f.c.namePrefix}-ingest`;
    assert.throws(() => privateLinkRuntimeWhatIfContext(f.c, changed));
    const unprojected = structuredClone(phase); delete unprojected.nameBinding; unprojected.version = 1;
    assert.throws(() => privateLinkRuntimeWhatIfContext(f.c, unprojected));
  }
});

test('projected current read allowlist checks shortened IDs and both legacy names absent while original snapshots stay valid', async t => {
  const names = projection(), state = projectedSnapshot(evidence.records.at(-1).after, names);
  state.startedAt = state.completedAt = f.at;
  verifyPrivateLinkSnapshot(f.c, f.context, state, 'assign-queue-role', 2, null, evidence);
  verifyPrivateLinkSnapshot(f.c, f.context, evidence.records.at(-1).after, 'assign-queue-role');
  const calls = [];
  const directory = await mkdtemp(path.join(process.cwd(), '.runtime-name-reads-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const io = privateLinkReadIO(f.c, f.context, directory, async args => { calls.push(args); return null; },
    { now: () => f.at, nameProjection: names, projectionEvidence: evidence });
  for (const id of [...Object.values(names.projected), ...Object.values(names.original)]) {
    await io.read({ id, apiVersion: '2025-07-01', filter: null }, f.at + 1000);
  }
  assert.equal(calls.length, 4);
  await assert.rejects(io.read({ id: `${names.projected.app}-other`, apiVersion: '2025-07-01', filter: null }, f.at + 1000), /READ_SCOPE_FORBIDDEN/);
  const bad = structuredClone(state); bad.resources[names.original.app] = { id: names.original.app };
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, bad, 'assign-queue-role', 2, null, evidence), /RETIRED_RUNTIME_NAME_PRESENT/);
  const noReview = structuredClone(state); delete noReview.nameProjection;
  assert.throws(() => verifyPrivateLinkSnapshot(f.c, f.context, noReview, 'assign-queue-role', 2, null, evidence));
});

test('concrete current proof collects the projected IDs under original history and binds current policy to both new descriptors', async t => {
  const names = projection(), state = projectedSnapshot(evidence.records.at(-1).after, names);
  const terminal = evidence.records.at(-1), key = privateLinkTargetKey(f.context);
  const files = new Map([
    [`private-link-head-${key}.json`, privateLinkHead(f.context, evidence)],
    [`private-link-fence-${key}.json`, { version: 1, targetKey: key, stage: terminal.stage, phase: terminal.phase,
      intent: terminal.intent, intentSha256: terminal.intentSha256 }],
    [`private-link-intent-${hash({ target: key, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent }],
  ]);
  const h = await privateControlHarness(f, { ...evidence, records: evidence.records.slice(0, 12) }, 'assign-queue-role');
  h.setLive(state);
  const invoke = retainedReadInvoke(f, state, h.io.read), calls = [];
  const directory = await mkdtemp(path.join(process.cwd(), '.runtime-name-proof-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const proof = await currentPrivateLinkRuntimeProof(f.c, f.context, evidence, directory, async (...args) => {
    calls.push(args[0]); return invoke(...args);
  }, { now: () => f.at, sourceDigest: async () => f.source, lookup: async () => f.source,
    nameProjection: names, store: { root: directory, read: async (_root, name) => structuredClone(files.get(name) ?? null) } });
  assert.deepEqual(proof.nameBinding, privateLinkNameBinding(f.c, f.context, names, evidence));
  assert.deepEqual(proof.nameProjection, names);
  assert.equal(proof.effectivePolicy.qualified, true);
  for (const id of Object.values(names.projected)) {
    assert(Object.hasOwn(proof.snapshot.resources, id));
    assert(calls.some(args => args.includes(`https://management.azure.com${id}?api-version=2025-07-01`)));
  }
  assert.equal(json({ context: f.context, evidence, candidate: f.candidate }), originalBytes);
  for (const mutate of [
    value => { value.sourceSha256 = value.publication.sourceSha256 = 'a'.repeat(64); },
    value => { value.expiresAt = new Date(Date.parse(value.expiresAt) + 1000).toISOString(); },
  ]) {
    const changed = projection();
    let mutated = false;
    await assert.rejects(currentPrivateLinkRuntimeProof(f.c, f.context, evidence, directory, async (...args) => {
      const value = await invoke(...args);
      if (!mutated) { mutated = true; mutate(changed); }
      return value;
    }, { now: () => f.at, sourceDigest: async () => f.source, lookup: async () => f.source,
      nameProjection: changed, store: { root: directory, read: async (_root, name) => structuredClone(files.get(name) ?? null) } }),
    /PRIVATE_LINK_NAME_REVIEW_CHANGED/);
  }
});

test('receiver under expired review A continues under renewed review B without recreation, then all five retirement stages verify after codec reload', async () => {
  const a = projection(f.at, 1000), b = projection(f.at + 2000);
  const bReview = review(f.at + 2000, b);
  b.sourceSha256 = b.publication.sourceSha256 = digest('UNIT newly published naming policy');
  b.publication.commitSha = 'd'.repeat(40);
  bReview.costReview.sourceSha256 = b.sourceSha256;
  bReview.policyRevision = { version: 1, action: 'review-identical-private-link-plan-under-new-policy-source',
    configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
    originalSourceSha256: f.context.plan.sourceSha256, sourceSha256: b.sourceSha256, publication: b.publication,
    userInstruction: 'UNIT new published source, same exact names', userInstructionSha256: digest('UNIT new published source, same exact names'),
    approvedAt: b.approvedAt, expiresAt: b.expiresAt };
  const runtime = await privateRuntimeCompletionFixture(f, evidence, prerequisites, {
    runtimeReview: review(f.at, a), windowReview: bReview, afterCreateMs: 2000,
  });
  assert.equal(runtime.disabled.target.version, 2);
  assert.equal(runtime.completion.binding.runtimeReview.nameProjection.approvedAt, b.approvedAt);
  assert.equal(runtime.disabled.binding.runtimeReview.nameProjection.expiresAt, a.expiresAt);
  assert.deepEqual(runtime.disabled.target, runtime.completion.target);
  assert.notEqual(runtime.disabled.approval.sourceSha256, runtime.completion.approvals.enable.sourceSha256);
  verifyCreateIntent(f.c, f.context, evidence, runtime.disabled.intent);
  verifyWindowIntent(f.c, f.context, evidence, runtime.completion.intent);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, runtime.completion, runtime.at);
  const targetBytes = json(runtime.target);
  const later = runtime.at + 3600001;
  const recoveryIo = { ...runtime.io, now: () => later,
    observe: async (...args) => ({ ...await runtime.io.observe(...args), observedAt: new Date(later).toISOString() }),
    current: async () => { throw new Error('UNIT_BACKEND_NOT_REQUIRED_FOR_FROZEN_FALSE'); },
    published: async (_approval, frozen) => assert.equal(frozen, true) };
  const recoveryId = '00000000-0000-4000-8000-000000000099';
  const preparation = await preparePrivateLinkDisableRecovery(f.c, f.context, evidence, recoveryId, '/UNIT', { io: recoveryIo });
  const recovered = await recoverPrivateLinkDisabled(f.c, f.context, evidence, recoveryId, {
    version: 1, action: 'private-link-recover-frozen-false', bindingSha256: preparation.bindingSha256,
    sourceSha256: f.source, policyCommitSha: 'c'.repeat(40), approvedAt: new Date(later - 1).toISOString(),
    expiresAt: new Date(later + 300000).toISOString(),
  }, '/UNIT', { io: recoveryIo });
  assert.equal(recovered.qualification, false);
  assert.equal(recovered.receipt.observation.app.id, b.projected.app);
  assert.equal(json(runtime.target), targetBytes);
  const fields = new Map();
  const codec = createPrivateLinkArtifactStore({ root: '/UNIT',
    read: async (_root, name) => fields.get(name),
    immutable: async (_root, name, value) => {
      if (fields.has(name)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      fields.set(name, JSON.parse(value));
    },
    update: async (_root, name, value) => fields.set(name, JSON.parse(value)),
  });
  await codec.immutable('/UNIT', 'runtime.json', runtime.completion);
  const restored = await codec.load('/UNIT', 'runtime.json');
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, restored, runtime.at + 1000);
  const full = { ...evidence, records: [...evidence.records] }, rf = { ...f, at: runtime.at + 1000 };
  let names = { ...projection(rf.at), publication: structuredClone(evidence.records.at(-1).publication) };
  const change = state => {
    const adjusted = projectedSnapshot(state, names, restored.disable.observation.app);
    Object.assign(state, adjusted);
  };
  for (const stage of PRIVATE_LINK_CONTROL_STAGES.slice(13)) {
    const q = await privateControlHarness(rf, full, stage, { runtimeCompletion: restored, snapshot: change,
      configureIO: io => {
        assert.deepEqual(names.publication, io.publication);
        io.nameProjection = names; io.projectionEvidence = full;
      } });
    let record;
    if (stage === 'retire-old-receiver') {
      const write = q.io.write;
      q.io.write = async (...args) => { await write(...args); throw new Error('UNIT_POST_RUNTIME_UNKNOWN'); };
      await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
      const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
        intent: q.intent, journal: structuredClone(q.journal) };
      const originalBytes = json(original);
      q.advance(1800001);
      names = projection(q.io.now());
      names.publication = structuredClone(q.io.publication);
      q.io.nameProjection = names;
      const times = { approvedAt: new Date(q.io.now() - 1).toISOString(), expiresAt: new Date(q.io.now() + 1800000).toISOString() };
      q.io.costReview = { ...q.io.costReview, ...times };
      q.io.migrationReview = { ...q.io.migrationReview, ...times };
      const proposal = await reconcilePrivateLinkPhase(f.c, f.context, full, original, q.io);
      assert.deepEqual(proposal.after.nameProjection, names);
      record = await recoverPrivateLinkPhase(f.c, f.context, full, original, proposal, {
        version: 1, action: 'adopt-exact-private-link-late-state-without-replay', proposalSha256: hash(proposal),
        sourceSha256: f.source, pendingHeadSha256: hash(proposal.pendingHead), ...times,
      }, q.io);
      assert.equal(json(original), originalBytes);
      const wrongPublication = structuredClone(record);
      wrongPublication.after.nameProjection.publication.commitSha = 'f'.repeat(40);
      assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context,
        { ...full, records: [...full.records, wrongPublication] }, q.io.now()), /PRIVATE_LINK_NAME_POLICY_CHANGED/);
      const missingProposalReview = structuredClone(record);
      delete missingProposalReview.recovery.proposal.after.nameProjection;
      missingProposalReview.recovery.review.proposalSha256 = hash(missingProposalReview.recovery.proposal);
      assert.throws(() => verifyPrivateLinkControlEvidence(f.c, f.context,
        { ...full, records: [...full.records, missingProposalReview] }, q.io.now()), /PRIVATE_LINK_NAME_REVIEW_CHANGED/);
      rf.at = q.io.now();
    } else record = await q.execute();
    assert.equal(q.writes, stage === 'record-migration' ? 0 : 1);
    full.records.push(record); rf.at += 1000;
  }
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, full, rf.at).stage, 'record-migration');
  assert.equal(full.records.at(-1).after.resources[names.projected.publicProbe], null);
  assert.deepEqual(full.records.slice(0, 13), evidence.records);
  assert.equal(json({ context: f.context, evidence, candidate: f.candidate }), originalBytes);
});
