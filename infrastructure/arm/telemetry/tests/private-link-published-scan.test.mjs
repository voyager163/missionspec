import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdir, rm, readFile, writeFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { digest, digestJson as hash } from '../definition.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateCostFixture, privateControlHarness } from './private-link.fixture.mjs';
import { privateRuntimeCompletionFixture, runtimeProbeFixture } from './private-link-runtime.fixture.mjs';
import { verifyPrivateLinkRuntimePrerequisites, verifyPrivateLinkControlEvidence, privateLinkHead } from '../private-link-controller.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from '../private-link.mjs';
import { verifyPublishedScanAttestation, verifyRuntimeReview, runPrivateLinkRuntime, verifyPrivateLinkRuntimeCompletion,
  verifyWindowIntent, privateWindowFence, preparePrivateLinkDisableRecovery, recoverPrivateLinkDisabled } from '../private-link-runtime.mjs';
import { publishPrivateLinkImage, createPrivateLinkReceiver } from '../private-link-runtime.mjs';
import { preparePrivateLinkWindowContinuation, qualifyPrivateLinkDelivery } from '../private-link-runtime.mjs';
import { verifyCleanedPrivateLinkWindow, preparePublicControlCleanup, recoverPublicControlCleanup,
  reconcilePublicControl, privateLinkRuntimeIO, prepareCleanedPrivateLinkWindowSuccessor } from '../private-link-runtime.mjs';
import { createPrivateLinkArtifactStore } from '../private-link-artifacts.mjs';

const f = await privateLinkFixture({ ...privateInput, version: 2 }), evidence = await privateControlChain(f);
const prerequisites = verifyPrivateLinkRuntimePrerequisites(f.c, f.context, evidence, f.at);
const prior = await privateRuntimeCompletionFixture(f, evidence, prerequisites);
const actions = { enable: 'private-link-bounded-enable', disable: 'private-link-false-only-disable',
  publicCreate: 'private-link-create-public-control', publicDelete: 'private-link-delete-public-control' };
function scanOnly(original, at) {
  const p = structuredClone(original), q = JSON.parse(p.qualification.reportJson), oldRefresh = q.scanRefresh;
  const scan = JSON.parse(p.scan.reportJson);
  scan.CreatedAt = new Date(at - 1000).toISOString();
  p.scan.reportJson = JSON.stringify(scan); p.scan.reportSha256 = digest(p.scan.reportJson);
  p.scan.databaseSha256 = digest('UNIT fresh scan DB');
  p.scan.databaseUpdatedAt = new Date(at - 10000).toISOString();
  p.scan.databaseNextUpdate = new Date(at + 86400000).toISOString();
  q.scanner.dbSha256 = p.scan.databaseSha256;
  Object.assign(q.scanner.dbMetadata, { UpdatedAt: p.scan.databaseUpdatedAt, NextUpdate: p.scan.databaseNextUpdate,
    DownloadedAt: new Date(at - 5000).toISOString() });
  q.scanRefresh = { version: 1, kind: 'same-image-scan-refresh', startedAt: new Date(at - 2000).toISOString(),
    completedAt: new Date(at - 500).toISOString(), previousProfileSha256: hash(original),
    previousRefreshSha256: oldRefresh ? hash(oldRefresh) : null, imageUnchanged: true,
    archiveSha256: oldRefresh?.archiveSha256 ?? null, runtimeMeasurementsRepeated: false, historicalProfileModified: false };
  p.qualification.reportJson = JSON.stringify(q); p.qualification.reportSha256 = digest(p.qualification.reportJson);
  return p;
}
async function fixture(t, origin = prior, published = f.candidate) {
  const directory = `infrastructure/arm/telemetry/.operator-private/revision-20261003-${randomUUID().replaceAll('-', '')}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true, force: true }));
  const candidate = structuredClone(published), disabled = structuredClone(origin.disabled);
  let now = Date.parse(candidate.profile.scan.databaseNextUpdate) + 1000;
  await origin.io.sleep(now - origin.io.now());
  const facts = { version: 1, kind: 'private-link-published-image-scan-attestation',
    candidateSha256: hash(candidate), candidatePublicationSha256: hash(candidate.publication),
    originalProfileSha256: hash(f.context.origin.queueProfile), publishedProfileSha256: hash(candidate.profile),
    receiverCreateIntentSha256: hash(disabled.intent), freshProfile: scanOnly(candidate.profile, now) };
  const review = { version: 1, action: 'review-published-private-link-image-scan-attestation',
    decision: 'retain-published-image-and-receipts', configSha256: hash(f.c), contextSha256: hash(f.context),
    planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin), controlEvidenceSha256: hash(evidence),
    candidateSha256: facts.candidateSha256, candidatePublicationSha256: facts.candidatePublicationSha256,
    originalProfileSha256: facts.originalProfileSha256, publishedProfileSha256: facts.publishedProfileSha256,
    freshProfileSha256: hash(facts.freshProfile), attestationSha256: hash(facts),
    manifestDigest: candidate.profile.manifestDigest, configDigest: candidate.profile.configDigest,
    sourceSha256: f.source, publication: { commitSha: 'c'.repeat(40), sourceSha256: f.source },
    approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  const cost = privateCostFixture(f, now);
  const runtimeReview = { policyRevision: null, costReview: cost.review, costEvidence: cost.evidence, publishedScanReview: review };
  const files = new Map(), effects = [];
  let head = null;
  const io = { ...origin.io, now: () => now, sleep: async ms => { now += ms; await origin.io.sleep(ms); },
    load: async name => files.get(name) ?? null,
    save: async (name, value) => files.set(name, structuredClone(value)),
    immutable: async (name, value) => { assert(!files.has(name)); files.set(name, structuredClone(value)); },
    reserve: async (kind, _key, value) => { if (kind === 'window') { assert.equal(head, null); head = value; } },
    windowHead: async () => head,
    observe: async (...args) => ({ ...await origin.io.observe(...args), observedAt: new Date(now).toISOString() }),
    probe: async (target, observation, image, _prereq, _transport, _until, guard, mode = 'private') => {
      guard(); effects.push('probe');
      return runtimeProbeFixture(f.c, target, observation, image, prerequisites, f.source, prerequisites.controlHeadSha256, now, mode);
    },
    deploy: async (...args) => { effects.push('deploy'); return origin.io.deploy(...args); },
    deletePublic: async (...args) => { effects.push('delete'); return origin.io.deletePublic(...args); },
  };
  const inputs = { candidate, disabled, instanceId: randomUUID(), transport: origin.completion.transport, runtimeReview };
  const approve = (action, binding) => ({ version: 1, action, bindingSha256: hash(binding), sourceSha256: f.source,
    policyCommitSha: 'c'.repeat(40), approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 1800000).toISOString() });
  const prepareInputs = { ...inputs, publishedScanAttestation: facts };
  const prepare = () => runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window', directory, prepareInputs, { io });
  const qualify = prepared => runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-window', directory,
    { ...inputs, approvals: Object.fromEntries(Object.entries(actions).map(([key, action]) => [key, approve(action, prepared.binding)])) }, { io });
  return { directory, facts, review, runtimeReview, inputs, prepareInputs, prepare, qualify, io, files, effects, approve,
    now: () => now, advance: async ms => { now += ms; await origin.io.sleep(ms); } };
}

test('published attestation keeps candidate/publication/normal receipt unchanged and stores fresh facts once in v5', async t => {
  const x = await fixture(t), bytes = hash([x.inputs.candidate, x.inputs.disabled, evidence, f.context]);
  verifyPublishedScanAttestation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled, x.facts, x.review, x.now());
  const prepared = await x.prepare();
  assert.equal(prepared.version, 2);
  assert.equal(prepared.binding.publishedScanAttestationSha256, hash(x.facts));
  const probe = x.io.probe;
  let ports = 0, escaped;
  const forbiddenIO = new Proxy({}, { get: () => () => { ports++; assert.fail('disallowed attestation used a port'); } });
  x.io.probe = async (...args) => {
    await assert.rejects(createPrivateLinkReceiver(f.c, f.context, evidence, x.inputs.candidate, randomUUID(), {}, '/UNIT', { io: forbiddenIO }), /INPUT_SCOPE/);
    await assert.rejects(publishPrivateLinkImage(f.c, f.context, evidence, x.inputs.candidate, {}, {}, '/UNIT', { io: forbiddenIO }), /INPUT_SCOPE/);
    for (const operation of ['prepare-image', 'publish-image', 'prepare-receiver', 'create-receiver']) {
      await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, operation, '/UNIT', {}, { io: forbiddenIO }), /INPUT_SCOPE/);
    }
    for (const kind of ['config', 'context', 'candidate']) {
      const c = kind === 'config' ? { ...f.c, budgetEmail: 'different@example.invalid' } : f.c;
      const context = kind === 'context' ? { ...f.context, plan: { ...f.context.plan, sourceSha256: '0'.repeat(64) } } : f.context;
      const candidate = kind === 'candidate' ? { ...x.inputs.candidate, publication: null } : x.inputs.candidate;
      await assert.rejects(runPrivateLinkRuntime(c, context, evidence, 'prepare-window', '/UNIT',
        { ...x.prepareInputs, candidate }, { now: x.now, io: forbiddenIO }), /PRIVATE_PUBLISHED_SCAN/);
    }
    escaped ??= new Promise(resolve => setTimeout(async () => {
      const errors = [];
      for (const call of [
        () => runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window', '/UNIT', x.prepareInputs, { now: x.now, io: forbiddenIO }),
        () => verifyPublishedScanAttestation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled, x.facts, x.review, x.now()),
      ]) {
        try { await call(); errors.push(null); } catch (error) { errors.push(error.message); }
      }
      resolve(errors);
    }, 0));
    return probe(...args);
  };
  const completion = await x.qualify(prepared);
  assert.deepEqual(await escaped, ['PRIVATE_PUBLISHED_SCAN_SCOPE_CLOSED', 'PRIVATE_PUBLISHED_SCAN_SCOPE_CLOSED']);
  assert.equal(ports, 0);
  assert.equal(completion.intent.version, 5); assert.equal(completion.intent.continuation, null);
  assert.deepEqual(completion.intent.publishedScanAttestation, x.facts);
  assert.equal(hash([x.inputs.candidate, x.inputs.disabled, evidence, f.context]), bytes);
  assert.equal(Object.isFrozen(x.facts), false);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, completion, x.now());
  const count = value => !value || typeof value !== 'object' ? 0 :
    (value.kind === x.facts.kind ? 1 : 0) + Object.values(value).reduce((sum, entry) => sum + count(entry), 0);
  assert.equal(count(completion), 1);
  const stored = new Map(), store = createPrivateLinkArtifactStore({ root: '/BLOBS',
    read: async (directory, name) => JSON.parse(stored.get(`${directory}/${name}`)),
    immutable: async (directory, name, value) => stored.set(`${directory}/${name}`, typeof value === 'string' ? value : JSON.stringify(value)) });
  await store.immutable('/RESULT', 'window.json', completion);
  const restored = await store.load('/RESULT', 'window.json');
  assert.equal(hash(restored), hash(completion)); verifyPrivateLinkRuntimeCompletion(f.c, f.context, restored, x.now());
  const full = { ...evidence, records: [...evidence.records] }, rf = { ...f, at: x.now() + 1 };
  const n = f.context.plan.topology.ids;
  const snapshot = value => {
    value.resources[n.app] = structuredClone(restored.disable.observation.app);
    value.images.manifests = structuredClone(restored.candidate.publication.manifests);
    value.images.queueManifest = JSON.parse(restored.candidate.profile.manifestJson);
    if (!value.lists.groupResources.value.some(resource => resource.id === n.app)) value.lists.groupResources.value.push(value.resources[n.app]);
    value.lists.apps.value.push(value.resources[n.app]);
  };
  for (const stage of PRIVATE_LINK_CONTROL_STAGES.slice(13)) {
    const q = await privateControlHarness(rf, full, stage, { runtimeCompletion: restored, snapshot });
    full.records.push(await q.execute()); rf.at += 1000;
  }
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, full, rf.at).stage, 'record-migration');
  await store.immutable('/RESULT', 'full.json', full);
  const all = await store.load('/RESULT', 'full.json');
  assert.equal(hash(all), hash(full));
  assert.equal(verifyPrivateLinkControlEvidence(f.c, f.context, all, rf.at).stage, 'record-migration');
  await x.advance(2 * 86400000);
  const recoveryId = randomUUID(), recoveryIO = { ...x.io, current: async () => assert.fail('backend not needed'),
    probe: async () => assert.fail('probe not needed'), published: async (_approval, frozen) => assert.equal(frozen, true) };
  const recovery = await preparePrivateLinkDisableRecovery(f.c, f.context, evidence, recoveryId, '/UNIT', { io: recoveryIO });
  const recovered = await recoverPrivateLinkDisabled(f.c, f.context, evidence, recoveryId,
    x.approve(recovery.approvalAction, recovery.binding), '/UNIT', { io: recoveryIO });
  assert.equal(recovered.receipt.response.status, 503);
  verifyWindowIntent(f.c, f.context, evidence, restored.intent);
  assert.deepEqual(await x.io.windowHead(), privateWindowFence(completion.intent));
});

test('closed pairing, historical lineage and immutable-image facts fail before any forward effect', async t => {
  const x = await fixture(t);
  for (const change of [
    value => { value.review.candidateSha256 = '0'.repeat(64); },
    value => { value.review.candidatePublicationSha256 = '0'.repeat(64); },
    value => { value.facts.receiverCreateIntentSha256 = '0'.repeat(64); },
    value => { value.facts.freshProfile.nativeClearance = 'waived'; },
    value => { value.facts.freshProfile.source.commitSha = '0'.repeat(40); },
    value => { value.facts.extra = true; },
    value => { value.review.expiresAt = value.review.approvedAt; },
    value => { value.review.approvedAt = new Date(x.now() - 10000).toISOString(); },
  ]) {
    const value = structuredClone({ facts: x.facts, review: x.review }); change(value);
    value.review.attestationSha256 = hash(value.facts); value.review.freshProfileSha256 = hash(value.facts.freshProfile);
    assert.throws(() => verifyPublishedScanAttestation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      value.facts, value.review, x.now()));
  }
  assert.throws(() => verifyRuntimeReview(f.c, f.context, { ...x.runtimeReview, imageProfileRevision: {} }, x.now()), /EXCLUSIVE/);
  for (const operation of ['prepare-image', 'publish-image', 'prepare-receiver', 'create-receiver']) {
    await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, operation, x.directory, x.prepareInputs, { io: x.io }), /INPUT_SCOPE/);
    for (const injected of [{ publishedScanReview: x.review }, { publishedScanAttestation: x.facts },
      { runtimeReview: x.runtimeReview }]) {
      const io = new Proxy({}, { get: () => () => assert.fail('disallowed operation used a port') });
      await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, operation, '/UNIT', {}, { io, ...injected }), /INPUT_SCOPE/);
      await assert.rejects(createPrivateLinkReceiver(f.c, f.context, evidence, x.inputs.candidate, randomUUID(), {}, '/UNIT',
        { io, ...injected }), /INPUT_SCOPE/);
      await assert.rejects(publishPrivateLinkImage(f.c, f.context, evidence, x.inputs.candidate, {}, {}, '/UNIT',
        { io, ...injected }), /INPUT_SCOPE/);
    }
  }
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window', x.directory, x.inputs, { io: x.io }), /INPUT_SCOPE/);
  const noReview = { ...x.prepareInputs, runtimeReview: { ...x.runtimeReview } }; delete noReview.runtimeReview.publishedScanReview;
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window', x.directory, noReview, { io: x.io }), /INPUT_SCOPE/);
  assert.deepEqual(x.effects, []);
});

test('replacement facts or expiry after preparation cannot refresh the immutable binding', async t => {
  const x = await fixture(t), prepared = await x.prepare();
  const changed = structuredClone(prepared); changed.publishedScanAttestation.freshProfile.notices.sha256 = '0'.repeat(64);
  x.files.set('private-window-preparation.json', changed);
  await assert.rejects(x.qualify(prepared));
  assert.deepEqual(x.effects, []);
  x.files.set('private-window-preparation.json', prepared);
  await x.advance(1800001);
  await assert.rejects(x.qualify(prepared), /EXPIRED/);
  assert.deepEqual(x.effects, []);
});

test('reviewed fresh scan cannot waive severity, scanner identity, native measurements or chain chronology', async t => {
  const x = await fixture(t);
  for (const kind of ['critical', 'high', 'ignored', 'unknown-severity', 'wrong-image', 'scanner', 'native', 'previous', 'backdated']) {
    const facts = structuredClone(x.facts), profile = facts.freshProfile;
    const scan = JSON.parse(profile.scan.reportJson), q = JSON.parse(profile.qualification.reportJson);
    if (['critical', 'high', 'unknown-severity'].includes(kind)) {
      const severity = kind === 'unknown-severity' ? 'UNREVIEWED' : kind.toUpperCase();
      scan.Results[0].Vulnerabilities ??= [];
      scan.Results[0].Vulnerabilities.push({ VulnerabilityID: 'CVE-2099-99999', Severity: severity });
      if (kind !== 'unknown-severity') { profile.scan.counts[severity]++; q.scanCounts[severity]++; }
    }
    if (kind === 'ignored') scan.Results[0].SuppressedFindings = [{ VulnerabilityID: 'CVE-2099-99999' }];
    if (kind === 'wrong-image') scan.ArtifactName = `sha256:${'0'.repeat(64)}`;
    if (kind === 'scanner') q.scanner.version = 'unreviewed-scanner';
    if (kind === 'native') q.nativeCoverage = 'all native risk waived';
    if (kind === 'previous') q.scanRefresh.previousProfileSha256 = '0'.repeat(64);
    if (kind === 'backdated') q.scanRefresh.startedAt = new Date(x.now() - 86400000).toISOString();
    profile.scan.reportJson = JSON.stringify(scan); profile.scan.reportSha256 = digest(profile.scan.reportJson);
    profile.qualification.reportJson = JSON.stringify(q); profile.qualification.reportSha256 = digest(profile.qualification.reportJson);
    const review = { ...x.review, attestationSha256: hash(facts), freshProfileSha256: hash(profile) };
    assert.throws(() => verifyPublishedScanAttestation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      facts, review, x.now()), undefined, kind);
  }
});

test('published profile may retain its old v1 scan revision only at the original normal creation time', async t => {
  const candidate = structuredClone(f.candidate), at = f.at;
  candidate.profile = scanOnly(candidate.profile, at);
  candidate.review.profileSha256 = hash(candidate.profile);
  candidate.review.approvedAt = new Date(at - 200).toISOString();
  candidate.review.expiresAt = new Date(at + 1800000).toISOString();
  candidate.publication.profileSha256 = hash(candidate.profile);
  candidate.publication.reviewSha256 = hash(candidate.review);
  candidate.publication.intentAt = new Date(at - 100).toISOString();
  candidate.publication.completedAt = new Date(at - 50).toISOString();
  const cost = privateCostFixture(f, at);
  const imageProfileRevision = { version: 1, action: 'review-same-image-private-link-scan-refresh',
    configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
    originalProfileSha256: hash(f.context.origin.queueProfile), profileSha256: hash(candidate.profile),
    manifestDigest: candidate.profile.manifestDigest, configDigest: candidate.profile.configDigest,
    sourceSha256: f.source, publication: { commitSha: 'c'.repeat(40), sourceSha256: f.source },
    approvedAt: new Date(at).toISOString(), expiresAt: new Date(at + 1800000).toISOString() };
  const old = await privateRuntimeCompletionFixture({ ...f, candidate }, evidence, prerequisites,
    { runtimeReview: { policyRevision: null, costReview: cost.review, costEvidence: cost.evidence, imageProfileRevision } });
  const x = await fixture(t, old, candidate);
  assert.notEqual(hash(x.inputs.candidate.profile), hash(f.context.origin.queueProfile));
  assert(Date.parse(imageProfileRevision.expiresAt) < x.now());
  const originalAnchor = hash(x.inputs.disabled.intent);
  const prepared = await x.prepare(), completion = await x.qualify(prepared);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, completion, x.now());
  assert.equal(hash(x.inputs.disabled.intent), originalAnchor);
  assert.deepEqual(completion.disabled.intent.binding.runtimeReview.imageProfileRevision, imageProfileRevision);
  assert(!Object.hasOwn(completion.binding.runtimeReview, 'imageProfileRevision'));
  const missing = structuredClone(x.inputs.disabled); delete missing.intent.binding.runtimeReview.imageProfileRevision;
  assert.throws(() => verifyPublishedScanAttestation(f.c, f.context, evidence, x.inputs.candidate, missing, x.facts, x.review, x.now()));
});

test('mutable caller facts after an await are rejected and attestation expiry never blocks frozen public cleanup', async t => {
  for (const mode of ['caller-facts', 'caller-candidate', 'caller-review', 'expired-public-probe']) {
    const x = await fixture(t), prepared = await x.prepare(), probe = x.io.probe;
    let changed = false;
    x.io.probe = async (...args) => {
      const value = await probe(...args); await Promise.resolve();
      if (mode === 'caller-facts' && !changed) {
        const borrowed = x.files.get('private-window-preparation.json').publishedScanAttestation;
        assert.equal(Object.isFrozen(borrowed), false);
        borrowed.freshProfile.scan.reportSha256 = '0'.repeat(64); changed = true;
      }
      if (mode === 'caller-candidate' && !changed) {
        assert.equal(Object.isFrozen(x.inputs.candidate), false);
        x.inputs.candidate.review.sourceSha256 = '0'.repeat(64); changed = true;
      }
      if (mode === 'caller-review' && !changed) {
        assert.equal(Object.isFrozen(x.runtimeReview.publishedScanReview), false);
        x.runtimeReview.publishedScanReview.sourceSha256 = '0'.repeat(64); changed = true;
      }
      if (mode === 'expired-public-probe' && args[7] === 'public-deny') { await x.advance(1800001); changed = true; }
      return value;
    };
    const approvals = Object.fromEntries(Object.entries(actions).map(([key, action]) =>
      [key, { ...x.approve(action, prepared.binding), expiresAt: new Date(x.now() + 3600000).toISOString() }]));
    await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-window', x.directory,
      { ...x.inputs, approvals }, { io: x.io }), /QUALIFICATION_HELD/);
    const result = x.files.get('private-window-result.json');
    assert.equal(changed, true);
    assert.equal(result.terminalFalse, true); assert.equal(result.terminal503, true);
    assert.equal(result.publicCleanup.absent, true);
    assert(!x.files.has('private-enable-intent.json'));
    if (mode === 'expired-public-probe') assert(x.effects.includes('delete'));
  }
});

test('direct continuation preparation rejects unpaired facts and options reference/content swaps before cloud ports', async t => {
  const x = await fixture(t);
  let ports = 0;
  await assert.rejects(preparePrivateLinkWindowContinuation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
    randomUUID(), x.inputs.transport, 'infrastructure/arm/telemetry/.operator-private/revision-20261003-original', '/UNIT',
    { publishedScanAttestation: x.facts, io: { loadOriginal: async () => { ports++; assert.fail('unpaired read'); } } }), /INPUT_SCOPE/);
  assert.equal(ports, 0);
  const failed = await privateRuntimeCompletionFixture(f, evidence, prerequisites, { failFirstProbe: true, withHistoryHead: true });
  const original = failed.completion;
  const originalFiles = new Map([['private-window-result.json', original], ['private-window-intent.json', original.intent],
    ['private-disable-intent.json', original.disable.intent], ['private-disable-receipt.json', original.disable],
    ['private-enable-intent.json', null], ['private-public-create-intent.json', null]]);
  for (const mode of ['facts-reference', 'facts-content', 'review-reference']) {
    const facts = structuredClone(x.facts);
    assert.equal(facts.receiverCreateIntentSha256, hash(failed.disabled.intent));
    const options = { publishedScanAttestation: facts, runtimeReview: structuredClone(x.runtimeReview) };
    let reads = 0, locks = 0, retained = 0, clouds = 0;
    options.io = { now: x.now,
      loadOriginal: async (_directory, name) => {
        await Promise.resolve();
        if (reads++ === 0) {
          if (mode === 'facts-reference') options.publishedScanAttestation = { ...facts };
          if (mode === 'facts-content') facts.freshProfile.scan.reportSha256 = '0'.repeat(64);
          if (mode === 'review-reference') options.runtimeReview = { ...options.runtimeReview };
        }
        return originalFiles.get(name);
      },
      windowHead: async () => privateWindowFence(original.intent),
      withWindowAdmission: async () => { locks++; assert.fail('changed inputs acquired admission'); },
      current: async () => { clouds++; assert.fail('changed inputs reached cloud'); },
      immutable: async () => { retained++; assert.fail('changed facts retained'); } };
    await assert.rejects(preparePrivateLinkWindowContinuation(f.c, f.context, evidence, x.inputs.candidate, failed.disabled,
      randomUUID(), x.inputs.transport, 'infrastructure/arm/telemetry/.operator-private/revision-20261003-original', '/UNIT-new', options),
    /INPUT_CHANGED/, mode);
    assert(reads > 0); assert.equal(locks, 0); assert.equal(clouds, 0); assert.equal(retained, 0);
  }
});

test('outer attested preparation cannot lend freshness to unpaired windows or non-v5 historical verification', async t => {
  const x = await fixture(t), pending = [];
  const legacyReview = { ...x.runtimeReview }; delete legacyReview.publishedScanReview;
  let ports = 0;
  const forbiddenIO = new Proxy({}, { get: () => () => { ports++; assert.fail('ambient freshness borrowed a port'); } });
  x.io.verifyPrerequisites = () => {
    for (const operation of ['prepare-window', 'qualify-window', 'prepare-window-continuation', 'qualify-window-continuation',
      'prepare-cleaned-window-successor', 'qualify-cleaned-window-successor']) {
      pending.push(assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, operation, '/UNIT',
        { ...x.inputs, runtimeReview: legacyReview }, { now: x.now, io: forbiddenIO }), /INPUT_SCOPE/));
    }
    pending.push(assert.rejects(preparePrivateLinkWindowContinuation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      randomUUID(), x.inputs.transport, 'infrastructure/arm/telemetry/.operator-private/revision-20261003-original', '/UNIT-new',
      { runtimeReview: legacyReview, io: forbiddenIO }), /INPUT_SCOPE/));
    pending.push(assert.rejects(qualifyPrivateLinkDelivery(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      randomUUID(), {}, x.inputs.transport, '/UNIT', { runtimeReview: legacyReview, io: forbiddenIO }), /INPUT_SCOPE/));
    pending.push(assert.rejects(prepareCleanedPrivateLinkWindowSuccessor(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      randomUUID(), x.inputs.transport, { originalDirectory: '/UNIT', cleanupRecoveryId: randomUUID(),
        publicReconciliationId: randomUUID(), terminalObservationId: randomUUID(), parentAbsenceObservationId: randomUUID() },
      '/UNIT-new', { runtimeReview: legacyReview, io: forbiddenIO }), /INPUT_SCOPE/));
    verifyWindowIntent(f.c, f.context, evidence, prior.completion.intent);
    verifyPrivateLinkRuntimeCompletion(f.c, f.context, prior.completion, x.now());
    const changed = structuredClone(prior.completion);
    const expiredCreate = changed.disabled.intent, start = x.now();
    expiredCreate.intentAt = new Date(start).toISOString(); expiredCreate.effectDeadline = start + 120000;
    expiredCreate.approval.approvedAt = new Date(start - 1).toISOString();
    expiredCreate.approval.expiresAt = new Date(start + 120000).toISOString();
    changed.disabled.approval = expiredCreate.approval;
    changed.disabled.completedAt = new Date(start).toISOString();
    changed.intent.disabled = changed.disabled;
    assert.throws(() => verifyWindowIntent(f.c, f.context, evidence, changed.intent), /PRIVATE_IMAGE_SCAN_EXPIRED/);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, changed, start), /PRIVATE_IMAGE_SCAN_EXPIRED/);
    return prerequisites;
  };
  const write = x.io.immutable;
  x.io.immutable = async (...args) => { await Promise.all(pending); return write(...args); };
  await x.prepare();
  assert.equal(ports, 0);
});

async function cleanedCase(t) {
  const first = await privateRuntimeCompletionFixture(f, evidence, prerequisites, { failFirstProbe: true, withHistoryHead: true });
  const x = await fixture(t, first);
  const originalDirectory = 'infrastructure/arm/telemetry/.operator-private/revision-20261003-unit-first';
  const failedDirectory = 'infrastructure/arm/telemetry/.operator-private/revision-20261003-unit-cleaned';
  const originals = new Map([['private-window-result.json', first.completion], ['private-window-intent.json', first.completion.intent],
    ['private-disable-intent.json', first.completion.disable.intent], ['private-disable-receipt.json', first.completion.disable],
    ['private-enable-intent.json', null], ['private-public-create-intent.json', null]]);
  let head = privateWindowFence(first.completion.intent);
  x.io.loadOriginal = async (directory, name) => {
    assert.equal(directory, originalDirectory); assert(originals.has(name)); return originals.get(name);
  };
  x.io.windowHead = async () => head;
  x.io.appendWindow = async (_old, next) => { head = privateWindowFence(next); };
  x.io.withWindowAdmission = async (_old, use) => use();
  const current = x.io.current;
  x.io.current = async (...args) => ({ ...await current(...args), head: privateLinkHead(f.context, evidence),
    headSha256: prerequisites.controlHeadSha256, checkedAt: new Date(x.now()).toISOString() });
  const originalRead = x.io.read;
  x.io.read = async id => [first.completion.phases.enable.request.id, first.completion.intent.publicPhase.request.id].includes(id) ? null : originalRead(id);
  const prepared = await runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-window-continuation', x.directory,
    { ...x.prepareInputs, originalDirectory }, { io: x.io });
  const observe = x.io.observe;
  x.io.observe = async (target, ...args) => {
    const value = structuredClone(await observe(target, ...args));
    if (target.appId.endsWith('-public-probe')) value.app.properties.configuration.ingress.fqdn = 'wrong.invalid';
    return value;
  };
  const approvals = Object.fromEntries(Object.entries(actions).map(([key, action]) => [key, x.approve(action, prepared.binding)]));
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-window-continuation', x.directory,
    { ...x.inputs, approvals, continuationApproval: x.approve(prepared.approvalAction, prepared.continuationBinding) },
    { io: x.io }), /QUALIFICATION_HELD/);
  x.io.observe = observe;
  const original = x.files.get('private-window-result.json'), recoveryId = randomUUID();
  assert.equal(original.intent.version, 5); assert.equal(original.failure.code, 'PRIVATE_RUNTIME_TARGET_DRIFT');
  const cleanupPreparation = await preparePublicControlCleanup(f.c, f.context, evidence, recoveryId, '/UNIT', { io: x.io });
  const cleanupApproval = x.approve(cleanupPreparation.approvalAction, cleanupPreparation.binding);
  const del = x.io.deletePublic, read = x.io.read;
  let deletionSent = false;
  x.io.deletePublic = async (...args) => { await del(...args); deletionSent = true; };
  x.io.read = async id => {
    if (deletionSent && id === original.publicTarget.appId) throw Object.assign(new Error('ARM_OPERATION_FAILED'),
      { httpStatus: 404, armCode: 'ContainerAppNotFound', diagnostics: { step: 'arm.get', kind: 'http-error',
        configuredTimeoutMs: 15000, elapsedMs: 50, killed: false, timeoutObserved: false, processCode: 1, signal: null } });
    return read(id);
  };
  await assert.rejects(recoverPublicControlCleanup(f.c, f.context, evidence, recoveryId, cleanupApproval, '/UNIT', { io: x.io }), /RECOVERY_HELD/);
  x.io.read = read;
  await x.advance(1000);
  const reconciliationId = randomUUID(), reconciliation = await reconcilePublicControl(f.c, f.context, evidence, reconciliationId, '/UNIT', { io: x.io });
  const deleteIntent = x.files.get(`private-public-recovery-${recoveryId}-intent.json`), start = Date.parse(deleteIntent.intentAt);
  const correlationId = randomUUID(), requestId = randomUUID();
  const events = ['Started', 'Accepted', 'Succeeded'].map((status, i) => ({
    eventDataId: randomUUID(), correlationId, eventTimestamp: new Date(start + i * 100).toISOString(),
    submissionTimestamp: new Date(start + 300).toISOString(), resourceId: original.publicTarget.appId,
    subscriptionId: f.c.subscriptionId, tenantId: f.c.tenantId, category: { value: 'Administrative' },
    operationName: { value: 'Microsoft.App/containerApps/delete' }, status: { value: status },
    authorization: { action: 'Microsoft.App/containerApps/delete', scope: original.publicTarget.appId },
    properties: { entity: original.publicTarget.appId, ...(status === 'Accepted' ? { statusCode: 'Accepted' } : {}) },
    claims: { appid: '04b07795-8ddb-461a-bbee-02f9e1bf7b46', idtyp: 'user', iss: `https://sts.windows.net/${f.c.tenantId}/`,
      'http://schemas.microsoft.com/identity/claims/objectidentifier': f.c.operatorPrincipalId,
      'http://schemas.microsoft.com/identity/claims/tenantid': f.c.tenantId }, caller: 'UNIT-operator',
    ...(i < 2 ? { httpRequest: { method: 'DELETE', clientRequestId: requestId,
      uri: `https://management.azure.com${original.publicTarget.appId}?api-version=2025-07-01` } } : {}),
  }));
  const terminalActivity = { version: 1, kind: 'parent-readonly-cleaned-window-observation', windowInstanceId: original.binding.instanceId,
    start: deleteIntent.intentAt, end: new Date(x.now()).toISOString(), enableDeployment: null, activity: events,
    readOnly: true, originalWindowQualified: false, executionAuthorized: false };
  const env = { ...prerequisites.oldEnvironment, properties: { ...prerequisites.oldEnvironment.properties, provisioningState: 'Succeeded' } };
  const parentAbsenceObservation = { version: 1, kind: 'parent-readonly-public-control-observation',
    startedAt: new Date(x.now()).toISOString(), completedAt: new Date(x.now()).toISOString(),
    appId: original.publicTarget.appId, environmentId: original.publicTarget.environmentId, before: env, after: env,
    app: { value: null, error: null }, apps: { value: [original.disable.observation.app] },
    resources: { value: [] }, absenceObserved: true, protocolRecoveryQualified: false, originalWindowQualified: false, resourceWrites: 0 };
  const cleanup = { preparation: cleanupPreparation, deleteIntent,
    result: x.files.get(`private-public-recovery-${recoveryId}-result.json`), reconciliation, terminalActivity, parentAbsenceObservation };
  const selection = { originalDirectory: failedDirectory, cleanupRecoveryId: recoveryId, publicReconciliationId: reconciliationId,
    terminalObservationId: randomUUID(), parentAbsenceObservationId: randomUUID() };
  const failedFiles = new Map(x.files);
  failedFiles.set(`parent-cleaned-window-observation-${selection.terminalObservationId}.json`, terminalActivity);
  failedFiles.set(`parent-public-absence-${selection.parentAbsenceObservationId}.json`, parentAbsenceObservation);
  failedFiles.set(`private-public-reconciliation-${reconciliationId}.json`, reconciliation);
  failedFiles.set('private-public-create-receipt.json', null); failedFiles.set('private-enable-intent.json', null);
  const nextFiles = new Map(), decision = { kind: 'parent-retained-user-cleaned-window-successor-decision',
    selectedAnswer: 'Add one reviewed successor after proven cleanup (Recommended)', failedWindowRevision: failedDirectory,
    additionalSuccessorsAuthorized: 1, bothFailedWindowsAndFencesMustRemainImmutable: true, freshFalseAndPublicAbsenceProofRequired: true,
    readinessObservationsMustBeRetained: true, existingLimitsMustRemainUnchanged: true, receiverRecreationAuthorized: false,
    imageRepublishAuthorized: false, priorIntentReplayAuthorized: false, runtimeExecutionAuthorizedByThisFile: false };
  nextFiles.set('private-cleaned-window-user-decision.json', decision);
  const nextIO = { ...x.io,
    load: async name => nextFiles.get(name) ?? null,
    loadOriginal: async (directory, name) => {
      const files = directory === originalDirectory ? originals : directory === failedDirectory ? failedFiles : null;
      assert(files?.has(name), name); return files.get(name);
    },
    immutable: async (name, value) => { assert(!nextFiles.has(name), name); nextFiles.set(name, structuredClone(value)); },
    save: async (name, value) => nextFiles.set(name, structuredClone(value)),
    read: async id => [original.phases.enable.request.id, first.completion.phases.enable.request.id].includes(id) ? null : read(id),
  };
  const nextInputs = { ...x.inputs, instanceId: randomUUID() };
  return { ...x, first, original, cleanup, selection, nextFiles, nextIO, nextInputs, decision, originals, failedFiles,
    head: () => head, setHead: value => { head = value; } };
}

test('held cleanup rejects future completion and failures not attributable to the post-delete GET', async t => {
  const x = await cleanedCase(t);
  for (const [name, mutate] of [
    ['future-result', value => { value.result.completedAt = new Date(x.now() + 1000).toISOString(); }],
    ['after-reconciliation', value => {
      value.result.completedAt = new Date(Date.parse(value.reconciliation.state.observedAt) + 1).toISOString();
    }],
    ['failed-delete', value => {
      value.result.failure.diagnostics = { step: 'arm.delete', kind: 'http-error',
        configuredTimeoutMs: 15000, elapsedMs: 50, killed: false, timeoutObserved: false, processCode: 1, signal: null };
    }],
    ['missing-step', value => { value.result.failure.diagnostics = null; }],
  ]) {
    await t.test(name, () => {
      const cleanup = structuredClone(x.cleanup); mutate(cleanup);
      assert.throws(() => verifyCleanedPrivateLinkWindow(f.c, f.context, evidence, x.original, cleanup, name === 'future-result' ? x.now() : x.now() + 2000),
        /CLEANED_HELD_RESULT/);
    });
  }
});

test('second reviewed successor preserves both histories once and rejects terminal-evidence mutations', async t => {
  const x = await cleanedCase(t), originalHash = hash(x.original), firstHash = hash(x.first.completion);
  verifyCleanedPrivateLinkWindow(f.c, f.context, evidence, x.original, x.cleanup, x.now());
  for (const mutate of [
    value => { value.terminalActivity.activity[2].status.value = 'Accepted'; },
    value => { value.terminalActivity.activity[0].correlationId = randomUUID(); },
    value => { value.terminalActivity.activity[1].authorization.scope += '-foreign'; },
    value => { value.terminalActivity.activity[0].claims['http://schemas.microsoft.com/identity/claims/objectidentifier'] = randomUUID(); },
    value => { value.reconciliation.absent = false; },
    value => { value.preparation.generation.app.systemData.createdAt = new Date(f.at + 1).toISOString(); },
    value => { value.terminalActivity.activity[0].httpRequest.clientRequestId = randomUUID(); },
    value => { value.terminalActivity.activity[2].eventTimestamp = new Date(x.cleanup.deleteIntent.effectDeadline + 1).toISOString(); },
    value => { value.result.receipt = { absent: true }; },
  ]) {
    const cleanup = structuredClone(x.cleanup); mutate(cleanup);
    assert.throws(() => verifyCleanedPrivateLinkWindow(f.c, f.context, evidence, x.original, cleanup, x.now()));
  }
  for (const mutate of [
    value => { value.enableIntentAt = value.completedAt; },
    value => { value.requests.push({ dispatched: true }); },
    value => { value.enableIntent = {}; },
    value => { value.intent.continuation.original.intent.version = 5; },
    value => { value.disable.response.status = 202; },
    value => { value.probe.before.control.sourceSha256 = '0'.repeat(64); },
  ]) {
    const changed = structuredClone(x.original); mutate(changed);
    assert.throws(() => verifyCleanedPrivateLinkWindow(f.c, f.context, evidence, changed, x.cleanup, x.now()));
  }
  const ledger = await privateLinkRuntimeIO(f.c, f.context, evidence, path.resolve(x.directory), { now: x.now, store: { root: path.resolve(x.directory) } });
  const key = x.original.intent.physicalKey;
  await ledger.reserve('window', key, privateWindowFence(x.first.completion.intent));
  await ledger.appendWindow(x.first.completion.intent, x.original.intent);
  const ancestorBytes = await readFile(path.join(x.directory, `private-link-runtime-window-${key}.json`), 'utf8');
  const firstBytes = await readFile(path.join(x.directory, `private-link-runtime-window-successor-${key}.json`), 'utf8');
  x.nextIO.windowHead = ledger.windowHead;
  x.nextIO.withWindowAdmission = ledger.withWindowAdmission;
  x.nextIO.appendWindow = ledger.appendWindow;
  x.nextIO.reserve = ledger.reserve;
  x.nextIO.reservePublicProbe = ledger.reservePublicProbe;
  const oldPublicKey = hash({ appId: x.original.publicTarget.appId.toLowerCase() });
  await ledger.reserve('public-probe', oldPublicKey, {
    intentSha256: hash(x.cleanup.reconciliation.state.intent), outcome: 'create-possible' });
  const oldPublicFile = path.join(x.directory, `private-link-runtime-public-probe-${oldPublicKey}.json`);
  const oldPublicBytes = await readFile(oldPublicFile, 'utf8');
  const prepareInputs = { ...x.nextInputs, publishedScanAttestation: x.facts, ...x.selection };
  for (const mode of ['selection', 'review-reference', 'facts-reference']) {
    const selection = { ...x.selection }, options = { runtimeReview: structuredClone(x.runtimeReview),
      publishedScanAttestation: structuredClone(x.facts) };
    let reads = 0, ports = 0;
    options.io = { ...x.nextIO, loadOriginal: async (...args) => {
      const value = await x.nextIO.loadOriginal(...args); await Promise.resolve();
      if (reads++ === 0) {
        if (mode === 'selection') selection.terminalObservationId = randomUUID();
        if (mode === 'review-reference') options.runtimeReview = { ...options.runtimeReview };
        if (mode === 'facts-reference') options.publishedScanAttestation = { ...options.publishedScanAttestation };
      }
      return value;
    }, current: async () => { ports++; assert.fail('changed preparation reached cloud'); },
    withWindowAdmission: async () => { ports++; assert.fail('changed preparation reached mutex'); } };
    await assert.rejects(prepareCleanedPrivateLinkWindowSuccessor(f.c, f.context, evidence, x.nextInputs.candidate,
      x.nextInputs.disabled, x.nextInputs.instanceId, x.nextInputs.transport, selection, x.directory, options), /INPUT_CHANGED/);
    assert.equal(ports, 0);
  }
  const decision = x.nextFiles.get('private-cleaned-window-user-decision.json');
  x.nextFiles.set('private-cleaned-window-user-decision.json', { ...decision, additionalSuccessorsAuthorized: 2 });
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-cleaned-window-successor', x.directory, prepareInputs,
    { io: x.nextIO }), /DECISION_REQUIRED/);
  x.nextFiles.set('private-cleaned-window-user-decision.json', decision);
  for (const id of [x.original.binding.instanceId, x.first.completion.binding.instanceId]) {
    await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-cleaned-window-successor', x.directory,
      { ...prepareInputs, instanceId: id }, { io: x.nextIO }), /NEW_INSTANCE_REQUIRED/);
  }
  const prepared = await runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-cleaned-window-successor', x.directory,
    prepareInputs, { io: x.nextIO });
  assert.equal(prepared.continuation.ordinal, 2);
  const approvals = Object.fromEntries(Object.entries(actions).map(([key, action]) => [key, x.approve(action, prepared.binding)]));
  const qualifyInputs = { ...x.nextInputs, approvals, successorApproval: x.approve(prepared.approvalAction, prepared.successorBinding) };
  const badPrepared = structuredClone(prepared); badPrepared.continuation.cleanup.result.outcome = 'reclassified-success';
  x.nextFiles.set('private-cleaned-window-successor-preparation.json', badPrepared);
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-cleaned-window-successor', x.directory, qualifyInputs, { io: x.nextIO }));
  assert(!x.nextFiles.has('private-window-intent.json'));
  x.nextFiles.set('private-cleaned-window-successor-preparation.json', prepared);
  const completion = await runPrivateLinkRuntime(f.c, f.context, evidence, 'qualify-cleaned-window-successor', x.directory,
    qualifyInputs, { io: x.nextIO });
  assert.equal(completion.intent.version, 6); assert.equal(completion.intent.continuation.ordinal, 2);
  assert.equal(hash(completion.intent.continuation.original), originalHash);
  assert.equal(hash(completion.intent.continuation.original.intent.continuation.original), firstHash);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, completion, x.now());
  const stored = new Map(), codec = createPrivateLinkArtifactStore({ root: '/BLOBS',
    read: async (directory, name) => JSON.parse(stored.get(`${directory}/${name}`)),
    immutable: async (directory, name, value) => stored.set(`${directory}/${name}`, typeof value === 'string' ? value : JSON.stringify(value)) });
  await codec.immutable('/RESULT', 'v6.json', completion);
  const restored = await codec.load('/RESULT', 'v6.json');
  assert.equal(hash(restored), hash(completion));
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, restored, x.now());
  assert.equal(hash(x.original), originalHash); assert.equal(hash(x.first.completion), firstHash);
  assert.equal(await readFile(oldPublicFile, 'utf8'), oldPublicBytes);
  const publicSuccessor = JSON.parse(await readFile(path.join(x.directory,
    `private-link-runtime-public-probe-successor-2-${hash({ appId: completion.publicTarget.appId.toLowerCase(), physicalKey: key })}.json`), 'utf8'));
  assert.equal(publicSuccessor.originalReservationSha256, hash(JSON.parse(oldPublicBytes)));
  assert.equal(publicSuccessor.previousCreateIntentSha256, hash(x.cleanup.reconciliation.state.intent));
  assert.equal(publicSuccessor.windowIntentSha256, hash(completion.intent));
  assert.equal(publicSuccessor.resolutionSha256, hash(completion.intent.continuation));
  assert.equal(publicSuccessor.intentSha256, hash(completion.publicControl.intent));
  await assert.rejects(ledger.reservePublicProbe(completion.intent, completion.publicControl.intent), /PHYSICAL_FENCE_NO_RETRY/);
  await assert.rejects(ledger.reservePublicProbe(x.original.intent, x.cleanup.reconciliation.state.intent), /RESERVATION_REQUIRED/);
  const tampered = structuredClone(completion); tampered.intent.continuation.ordinal = 3;
  assert.throws(() => verifyWindowIntent(f.c, f.context, evidence, tampered.intent));
  await assert.rejects(preparePrivateLinkDisableRecovery(f.c, f.context, evidence, randomUUID(), '/UNIT',
    { io: { ...x.nextIO, load: async () => x.original.intent } }), /GLOBAL_HEAD_CHANGED/);
  await assert.rejects(preparePrivateLinkDisableRecovery(f.c, f.context, evidence, randomUUID(), '/UNIT',
    { io: { ...x.nextIO, load: async () => x.first.completion.intent } }), /GLOBAL_HEAD_CHANGED/);
  assert.equal(await readFile(path.join(x.directory, `private-link-runtime-window-${key}.json`), 'utf8'), ancestorBytes);
  assert.equal(await readFile(path.join(x.directory, `private-link-runtime-window-successor-${key}.json`), 'utf8'), firstBytes);
  const second = JSON.parse(await readFile(path.join(x.directory, `private-link-runtime-window-successor-2-${key}.json`), 'utf8'));
  assert.equal(second.resolutionSha256, hash(completion.intent.continuation));
  assert.equal(second.ordinal, 2);
  const firstFile = path.join(x.directory, `private-link-runtime-window-successor-${key}.json`);
  const secondFile = path.join(x.directory, `private-link-runtime-window-successor-2-${key}.json`);
  const secondBytes = await readFile(secondFile, 'utf8');
  const modifiedFirst = { ...JSON.parse(firstBytes), continuationSha256: '0'.repeat(64) };
  await writeFile(firstFile, JSON.stringify(modifiedFirst));
  await assert.rejects(ledger.appendWindow(x.original.intent, completion.intent), /SUCCESSOR_HEAD_CHANGED/);
  assert.equal(await readFile(secondFile, 'utf8'), secondBytes, 'invalid first fence cannot enter exclusive append');
  await writeFile(secondFile, JSON.stringify({ ...second, firstSuccessorSha256: hash(modifiedFirst) }));
  await assert.rejects(ledger.windowHead(completion.intent), /SUCCESSOR_HEAD_CHANGED/);
  await writeFile(firstFile, firstBytes);
  await writeFile(secondFile, secondBytes);
  assert.deepEqual(await ledger.windowHead(completion.intent), privateWindowFence(completion.intent));
  await assert.rejects(ledger.appendWindow(x.original.intent, completion.intent), error => error.code === 'EEXIST');
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, 'prepare-cleaned-window-successor', x.directory,
    { ...prepareInputs, instanceId: randomUUID() }, { io: x.nextIO }), /GLOBAL_HEAD_CHANGED/);
  const lock = path.join(x.directory, `private-link-runtime-window-admission-${key}.lock`);
  await writeFile(lock, '', { flag: 'wx', mode: 0o600 });
  await assert.rejects(ledger.windowHead(completion.intent), /ADMISSION_IN_PROGRESS/);
  await assert.rejects(ledger.windowHead(x.original.intent, true), /ADMISSION_IN_PROGRESS/);
  assert.deepEqual(await ledger.windowHead(completion.intent, true), privateWindowFence(completion.intent));
  const recoveryIO = { ...x.nextIO, current: async () => assert.fail('unhealthy backend not needed'),
    probe: async () => assert.fail('no probe'), verifyPrerequisites: () => assert.fail('no new prerequisites'),
    published: async (_review, frozen) => assert.equal(frozen, true) };
  const recoveryId = randomUUID(), recovery = await preparePrivateLinkDisableRecovery(f.c, f.context, evidence, recoveryId, '/UNIT', { io: recoveryIO });
  await recoverPrivateLinkDisabled(f.c, f.context, evidence, recoveryId, x.approve(recovery.approvalAction, recovery.binding), '/UNIT', { io: recoveryIO });
  const publicId = randomUUID(), publicPreparation = await preparePublicControlCleanup(f.c, f.context, evidence, publicId, '/UNIT', { io: recoveryIO });
  const publicRecovery = await recoverPublicControlCleanup(f.c, f.context, evidence, publicId,
    x.approve(publicPreparation.approvalAction, publicPreparation.binding), '/UNIT', { io: recoveryIO });
  assert.equal(publicRecovery.receipt.absent, true);
  assert((await stat(lock)).isFile());
  const next = { ...x.original, intent: completion.intent };
  assert.throws(() => verifyCleanedPrivateLinkWindow(f.c, f.context, evidence, next, x.cleanup, x.now()), /FAILURE_SCOPE/);
});
