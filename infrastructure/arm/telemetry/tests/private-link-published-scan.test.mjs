import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { digest, digestJson as hash } from '../definition.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateCostFixture, privateControlHarness } from './private-link.fixture.mjs';
import { privateRuntimeCompletionFixture, runtimeProbeFixture } from './private-link-runtime.fixture.mjs';
import { verifyPrivateLinkRuntimePrerequisites, verifyPrivateLinkControlEvidence } from '../private-link-controller.mjs';
import { PRIVATE_LINK_CONTROL_STAGES } from '../private-link.mjs';
import { verifyPublishedScanAttestation, verifyRuntimeReview, runPrivateLinkRuntime, verifyPrivateLinkRuntimeCompletion,
  verifyWindowIntent, privateWindowFence, preparePrivateLinkDisableRecovery, recoverPrivateLinkDisabled } from '../private-link-runtime.mjs';
import { publishPrivateLinkImage, createPrivateLinkReceiver } from '../private-link-runtime.mjs';
import { preparePrivateLinkWindowContinuation, qualifyPrivateLinkDelivery } from '../private-link-runtime.mjs';
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
    for (const operation of ['prepare-window', 'qualify-window', 'prepare-window-continuation', 'qualify-window-continuation']) {
      pending.push(assert.rejects(runPrivateLinkRuntime(f.c, f.context, evidence, operation, '/UNIT',
        { ...x.inputs, runtimeReview: legacyReview }, { now: x.now, io: forbiddenIO }), /INPUT_SCOPE/));
    }
    pending.push(assert.rejects(preparePrivateLinkWindowContinuation(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      randomUUID(), x.inputs.transport, 'infrastructure/arm/telemetry/.operator-private/revision-20261003-original', '/UNIT-new',
      { runtimeReview: legacyReview, io: forbiddenIO }), /INPUT_SCOPE/));
    pending.push(assert.rejects(qualifyPrivateLinkDelivery(f.c, f.context, evidence, x.inputs.candidate, x.inputs.disabled,
      randomUUID(), {}, x.inputs.transport, '/UNIT', { runtimeReview: legacyReview, io: forbiddenIO }), /INPUT_SCOPE/));
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
