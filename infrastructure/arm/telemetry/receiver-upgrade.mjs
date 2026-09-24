import { isDeepStrictEqual } from 'node:util';
import { buildPhase, closed, digest, fail, firstReleaseCost, ids, json, RECEIVER_COMMAND, RECEIVER_DIGEST,
  sameId, validateConfig, validateWindowInstance } from './definition.mjs';
import { admissionFlag, canonicalAppWrite, canonicalInstant, executionIdentity, resourceContext,
  verifyApproval, verifyDeploymentIdentity, verifyFreshReview, verifyImagePublication,
  verifyResource, verifyWhatIf, verifyWindowPredecessor } from './policy.mjs';
import { durableQueueCost, QUEUE_PROFILE_KIND, QUEUE_RUNTIME, queueEnvironment, qualifiedQueueRecords,
  verifyQueueTopology } from './durable-queue.mjs';

export const IMAGE_PHASES = Object.freeze(['disabled-image-upgrade', 'disabled-image-rollback', 'disabled-queue-upgrade']);
export const PREPARED_IDENTITY_RUNTIME = Object.freeze({
  version: 1, kind: 'explicit-uami-prepared-v1', preparationTimeoutMs: 20000,
  scope: 'https://monitor.azure.com/.default', refreshMarginMs: 120000,
  singleFlight: true, refreshBeforeExpiry: true, disabledAcquisitions: 0,
  readinessRequiresPreparedToken: true, postRequiresPreparedToken: true,
  failedInitializationRequiresRestart: true, storageTimeoutMs: 650, clientTimeoutMs: 1000,
});
export const RECEIVER_BUILD_INPUTS = Object.freeze([
  '.dockerignore', 'LICENSE', 'assets/schemas/telemetry-event.schema.json', 'scripts/check-licenses.mjs',
  'licenses/reviewed-texts.json', 'licenses/telemetry-runtime.json', 'licenses/TELEMETRY_THIRD_PARTY_NOTICES',
  'docs/telemetry-runtime.md', 'docs/telemetry-operations.md',
]);
export const RECEIVER_SOURCE_INPUTS = Object.freeze([...RECEIVER_BUILD_INPUTS, ...[
  'Dockerfile', 'package.json', 'package-lock.json', 'tsconfig.json', 'runtime-sources.lock.json',
  'scripts/schema.mjs', 'scripts/runtime-sources.mjs', 'scripts/container-smoke.mjs', 'scripts/container-qualification.mjs',
  'src/azure-storage.ts', 'src/config.ts', 'src/contract.ts', 'src/identity-readiness.ts', 'src/main.ts', 'src/server.ts',
  'schema/provenance.json', 'schema/storage-columns.json', 'schema/telemetry-event.schema.json',
  'tests/config-storage.test.mjs', 'tests/container-runtime.test.mjs', 'tests/helpers.mjs', 'tests/http.test.mjs',
  'tests/identity-readiness.test.mjs', 'tests/loopback-tls.json', 'tests/runtime-sources.test.mjs', 'tests/sdk-deadline.test.mjs',
].map(path => `services/telemetry-ingest/${path}`)]);
export const QUEUE_SOURCE_INPUTS = Object.freeze([...RECEIVER_SOURCE_INPUTS,
  'services/telemetry-ingest/src/queue-storage.ts',
  'services/telemetry-ingest/tests/queue-storage.test.mjs', 'services/telemetry-ingest/tests/queue-sdk.test.mjs',
]);
export const receiverSourceInputs = profile => profile?.kind === QUEUE_PROFILE_KIND ? QUEUE_SOURCE_INPUTS : RECEIVER_SOURCE_INPUTS;
export const receiverCost = candidate => candidate?.version === 2 ? durableQueueCost() : firstReleaseCost(2);
export const NATIVE_CONDITIONS = Object.freeze([
  'CVE-2026-91745:optimization-disabled',
  'CVE-2026-93377:debugger-disabled',
  'CVE-2026-91728:applicability-unproven',
]);
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const imageHash = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
const repository = 'missionspec/telemetry-ingest';
const clearance = 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY';

function parseArtifact(bytes) {
  if (typeof bytes !== 'string' || bytes.length > 64 * 1024 * 1024) fail('RECEIVER_ARTIFACT_INVALID');
  try { return JSON.parse(bytes); } catch { fail('RECEIVER_ARTIFACT_INVALID'); }
}
function instant(value) {
  try { return canonicalInstant(value); } catch { fail('RECEIVER_REVIEW_TIME_INVALID'); }
}
export function receiverDatabaseInstant(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3,9}Z$/u.test(value)) fail('RECEIVER_DATABASE_TIME_INVALID');
  const milliseconds = value.replace(/(\.\d{3})\d*Z$/u, '$1Z'), time = Date.parse(milliseconds);
  if (!Number.isSafeInteger(time) || new Date(time).toISOString() !== milliseconds) fail('RECEIVER_DATABASE_TIME_INVALID');
  return time;
}
function reviewTime(review, at) {
  const start = instant(review.approvedAt), end = instant(review.expiresAt);
  if (!Number.isSafeInteger(at) || start > at || end <= at || end - start > 3600000) fail('RECEIVER_APPROVAL_EXPIRED');
}
function noAuthority(value) {
  closed(value, ['ingestion', 'clientActivation', 'productionClearance', 'delete', 'retag', 'repush', 'registryAdmin']);
  if (Object.values(value).some(v => v !== false)) fail('RECEIVER_AUTHORITY_INVALID');
}
export function verifyReceiverProfile(profile) {
  closed(profile, ['version', 'kind', 'manifestDigest', 'configDigest', 'manifestJson', 'configJson',
    'source', 'notices', 'scan', 'qualification', 'runtime', 'nativeClearance', 'retainedAdvisories', 'priorUnknownGlibcCaveatWaived', 'authority']);
  closed(profile.source, ['commitSha', 'files', 'archiveSha256', 'manifestSha256', 'remoteLayerDigests']);
  closed(profile.notices, ['sha256', 'bytes']);
  closed(profile.scan, ['reportSha256', 'reportJson', 'databaseSha256', 'databaseUpdatedAt', 'databaseNextUpdate',
    'counts', 'suppressedFindings']);
  closed(profile.scan.counts, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
  closed(profile.qualification, ['reportJson', 'reportSha256']);
  noAuthority(profile.authority);
  const queued = profile.version === 2 && profile.kind === QUEUE_PROFILE_KIND;
  const manifest = parseArtifact(profile.manifestJson), config = parseArtifact(profile.configJson);
  if ((!queued && (profile.version !== 1 || profile.kind !== 'reviewed-prepared-identity-receiver')) ||
      !imageHash(profile.manifestDigest) || profile.manifestDigest === RECEIVER_DIGEST ||
      profile.manifestDigest !== 'sha256:' + digest(profile.manifestJson) ||
      profile.configDigest !== 'sha256:' + digest(profile.configJson) ||
      manifest.schemaVersion !== 2 || manifest.mediaType !== 'application/vnd.oci.image.manifest.v1+json' ||
      manifest.config?.digest !== profile.configDigest || manifest.config.mediaType !== 'application/vnd.oci.image.config.v1+json' ||
      manifest.config.size !== Buffer.byteLength(profile.configJson) ||
      !Array.isArray(manifest.layers) || !manifest.layers.length ||
      manifest.layers.some(v => !imageHash(v.digest) || !Number.isSafeInteger(v.size) || v.size <= 0) ||
      manifest.subject !== undefined || manifest.artifactType !== undefined || manifest.manifests !== undefined ||
      config.os !== 'linux' || config.architecture !== 'amd64' || config.config?.User !== '65532:65532' ||
      !isDeepStrictEqual(config.config?.Cmd, RECEIVER_COMMAND) || (config.config?.Entrypoint?.length ?? 0) !== 0 ||
      !isDeepStrictEqual(profile.runtime, queued ? QUEUE_RUNTIME : PREPARED_IDENTITY_RUNTIME) || profile.nativeClearance !== clearance ||
      !isDeepStrictEqual(profile.retainedAdvisories, NATIVE_CONDITIONS) || profile.priorUnknownGlibcCaveatWaived !== false) fail('RECEIVER_PROFILE_INVALID');
  const source = profile.source, notices = profile.notices, scan = profile.scan;
  closed(source.files, receiverSourceInputs(profile));
  const report = parseArtifact(scan.reportJson);
  const noticeBundle = parseArtifact(notices.bytes);
  closed(noticeBundle, ['version', 'inventoryJson', 'inventorySha256', 'files']);
  const inventory = parseArtifact(noticeBundle.inventoryJson);
  if (noticeBundle.version !== 1 || noticeBundle.inventorySha256 !== digest(noticeBundle.inventoryJson) ||
      !Array.isArray(inventory) || !inventory.length || !Array.isArray(noticeBundle.files) ||
      inventory.length !== noticeBundle.files.length || new Set(inventory.map(v => v.path)).size !== inventory.length) fail('RECEIVER_NOTICES_INVALID');
  for (const [i, entry] of inventory.entries()) {
    closed(entry, ['path', 'bytes', 'sha256']);
    const file = noticeBundle.files[i];
    closed(file, ['path', 'base64']);
    if (typeof file.base64 !== 'string') fail('RECEIVER_NOTICES_INVALID');
    const bytes = Buffer.from(file.base64, 'base64');
    if (typeof entry.path !== 'string' || !/^(?:[a-zA-Z0-9_.@+-]+\/)*[a-zA-Z0-9_.@+-]+$/u.test(entry.path) ||
        entry.path.split('/').some(v => ['.', '..'].includes(v)) || file.path !== entry.path ||
        bytes.toString('base64') !== file.base64 || bytes.length !== entry.bytes ||
        digest(bytes) !== entry.sha256) fail('RECEIVER_NOTICES_INVALID');
  }
  if (!/^[0-9a-f]{40}$/u.test(source.commitSha ?? '') || !hash(source.archiveSha256) || !hash(source.manifestSha256) ||
      Object.values(source.files).some(value => !hash(value)) ||
      !isDeepStrictEqual(source.remoteLayerDigests, manifest.layers.map(v => v.digest)) ||
      typeof notices.bytes !== 'string' || !notices.bytes.length || notices.sha256 !== digest(notices.bytes) ||
      !hash(scan.databaseSha256) || scan.reportSha256 !== digest(scan.reportJson) ||
      Object.values(scan.counts).some(v => !Number.isSafeInteger(v) || v < 0) ||
      scan.counts.CRITICAL !== 0 || scan.counts.HIGH !== 0 || scan.suppressedFindings !== 0 ||
      receiverDatabaseInstant(scan.databaseNextUpdate) <= receiverDatabaseInstant(scan.databaseUpdatedAt)) fail('RECEIVER_SOURCE_OR_SCAN_INVALID');
  if ((report.ArtifactName !== profile.manifestDigest && report.Metadata?.ImageID !== profile.configDigest) ||
      !Array.isArray(report.Results)) fail('RECEIVER_SCAN_TARGET_INVALID');
  const counts = Object.fromEntries(Object.keys(scan.counts).map(v => [v, 0]));
  for (const result of report.Results) {
    if (result.Misconfigurations?.length || result.Secrets?.length || result.SuppressedFindings?.length) fail('RECEIVER_SCAN_FINDINGS_INVALID');
    if (result.Vulnerabilities !== undefined && !Array.isArray(result.Vulnerabilities)) fail('RECEIVER_SCAN_FINDINGS_INVALID');
    for (const finding of result.Vulnerabilities ?? []) {
      if (!Object.hasOwn(counts, finding.Severity) || typeof finding.VulnerabilityID !== 'string') fail('RECEIVER_SCAN_FINDINGS_INVALID');
      counts[finding.Severity]++;
    }
  }
  if (!isDeepStrictEqual(counts, scan.counts)) fail('RECEIVER_SCAN_COUNTS_INVALID');
  const qualification = parseArtifact(profile.qualification.reportJson), artifact = qualification.artifact;
  if (profile.qualification.reportSha256 !== digest(profile.qualification.reportJson) ||
      qualification.result !== 'LOCAL_TECHNICAL_QUALIFICATION_PASSED_CONDITIONAL_RELEASE_ONLY' ||
      artifact?.manifest !== profile.manifestDigest || artifact.config !== profile.configDigest ||
      artifact.platform !== 'linux/amd64' || artifact.user !== '65532:65532' || !isDeepStrictEqual(artifact.command, RECEIVER_COMMAND) ||
      artifact.sourceReceipt?.sha256 !== source.archiveSha256 || artifact.sourceReceipt?.manifestSha256 !== source.manifestSha256 ||
      artifact.noticeFiles !== inventory.length || artifact.serviceSourceMatchesIntentAndDisk !== true ||
      artifact.includesNewIdentityReadinessSource !== true || artifact.cloudPublication !== false ||
      qualification.allSavedOciLayerHashesVerified !== true || qualification.buildTests?.failed !== 0 ||
      !Number.isSafeInteger(qualification.buildTests?.passed) || qualification.buildTests.passed < 56 ||
      qualification.buildTests.platform !== 'linux/amd64' ||
      !isDeepStrictEqual(qualification.scanCounts, scan.counts) ||
      qualification.scanner?.dbSha256 !== scan.databaseSha256 ||
      qualification.scanner?.dbMetadata?.UpdatedAt !== scan.databaseUpdatedAt ||
      qualification.scanner?.dbMetadata?.NextUpdate !== scan.databaseNextUpdate ||
      qualification.scanner.localOnlyScan !== true ||
      qualification.nativeCoverage !== 'partial; no new native patch proof; CVE-2026-91745, CVE-2026-93377, CVE-2026-91728 conditions retained' ||
      qualification.priorUnknownGlibcCaveatWaived !== false || qualification.productionAzureQualification !== false ||
      qualification.publicationAuthorized !== false || qualification.azureEffects !== false ||
      qualification.oldImagePreserved !== RECEIVER_DIGEST ||
      !isDeepStrictEqual(qualification.runtimeConstraints, { cpuMax: '25000 100000', memoryMaxBytes: 536870912,
        capEff: '0000000000000000', noNewPrivs: 1, uid: 65532, gid: 65532, network: 'none', readOnlyRoot: true })) fail('RECEIVER_QUALIFICATION_INVALID');
  if (queued) verifyQueueQualification(profile, qualification);
  else for (const [name, identityRequests, ingestionRequests, status] of [
    ['disabled-main', 0, 0, 503], ['slow-identity', 1, 1, 204], ['failed-identity', 1, 0, null],
  ]) {
    const result = qualification.resourceFixtures?.[name];
    if (result?.result !== 'LOCAL_RESOURCE_READINESS_PASSED' || result.scenario !== name || result.uid !== 65532 ||
        result.identityRequests !== identityRequests || result.ingestionRequests !== ingestionRequests ||
        result.productionAzureQualification !== false || (status !== null &&
          (result.firstEvent?.status !== status || !Number.isFinite(result.firstEvent.elapsedMs) ||
            result.firstEvent.elapsedMs < 0 || result.firstEvent.elapsedMs > 1000))) fail('RECEIVER_QUALIFICATION_INVALID');
  }
  return { digest: profile.manifestDigest, configSha256: profile.configDigest, configUser: config.config.User,
    command: config.config.Cmd, manifest, nativeV8Clearance: clearance,
    ...(queued ? { queueRuntime: QUEUE_RUNTIME } : {}) };
}

function verifyQueueQualification(profile, qualification) {
  const proof = qualification.durableQueue;
  closed(proof, ['version', 'kind', 'sourceFilesSha256', 'sdkSourceManifestSha256', 'runtime',
    'disabledNetworkRequests', 'producerStatus', 'producerElapsedMs', 'storageScope', 'consumerScope',
    'fixtures', 'cloudPublication', 'azureEffects']);
  const fixtures = ['slow-monitor-fast-durable-ack', 'failed-producer-readiness', 'restart-preserves-queued-message',
    'queue-overflow', 'ttl-expiration', 'three-delivery-attempts', 'visibility-retry', 'single-worker',
    'ambiguous-send-no-retry', 'disabled-zero-network', 'no-implicit-queue-creation'];
  closed(proof.fixtures, fixtures);
  if (proof.version !== 1 || proof.kind !== 'source-bound-local-queue-sdk-proof' ||
      proof.sourceFilesSha256 !== digest(json(profile.source.files)) ||
      proof.sdkSourceManifestSha256 !== profile.source.files['services/telemetry-ingest/runtime-sources.lock.json'] ||
      !isDeepStrictEqual(proof.runtime, QUEUE_RUNTIME) || proof.disabledNetworkRequests !== 0 ||
      proof.producerStatus !== 202 || !Number.isFinite(proof.producerElapsedMs) || proof.producerElapsedMs < 0 ||
      proof.producerElapsedMs > 1000 || proof.storageScope !== QUEUE_RUNTIME.producerScope ||
      proof.consumerScope !== QUEUE_RUNTIME.consumerScope || proof.cloudPublication !== false || proof.azureEffects !== false) fail('QUEUE_SDK_QUALIFICATION_REQUIRED');
  for (const name of fixtures) {
    const value = proof.fixtures[name];
    closed(value, ['result', 'reportSha256', 'passed', 'failed']);
    if (value.result !== 'LOCAL_QUEUE_SDK_FIXTURE_PASSED' || !hash(value.reportSha256) ||
        !Number.isSafeInteger(value.passed) || value.passed < 1 || value.failed !== 0) fail('QUEUE_SDK_QUALIFICATION_REQUIRED');
  }
}

export function verifyReceiverCandidate(c, candidate, at, published = true) {
  validateConfig(c);
  const queued = candidate?.version === 2;
  closed(candidate, ['version', 'profile', 'review', 'legacyPublication', 'publication',
    ...(queued ? ['priorCandidate', 'topology'] : [])]);
  const artifact = verifyReceiverProfile(candidate.profile), review = candidate.review;
  verifyImagePublication(c, candidate.legacyPublication);
  if (queued) {
    if (candidate.priorCandidate?.version !== 1 || candidate.profile.kind !== QUEUE_PROFILE_KIND) fail('QUEUE_PRIOR_RECEIVER_REQUIRED');
    verifyReceiverCandidate(c, candidate.priorCandidate);
    verifyQueueTopology(c, candidate.topology);
    if (!isDeepStrictEqual(candidate.legacyPublication, candidate.priorCandidate.legacyPublication) ||
        artifact.digest === candidate.priorCandidate.profile.manifestDigest) fail('QUEUE_PRIOR_RECEIVER_CHANGED');
  } else if (candidate.profile.kind === QUEUE_PROFILE_KIND) fail('QUEUE_PRIOR_RECEIVER_REQUIRED');
  if (!isDeepStrictEqual(parseArtifact(candidate.profile.configJson).config,
    parseArtifact(candidate.legacyPublication.configJson).config)) fail('RECEIVER_IMAGE_DEFAULTS_CHANGED');
  closed(review, ['version', 'action', 'configSha256', 'profileSha256', 'legacyPublicationSha256',
    'sourceSha256', 'policyCommitSha', 'registryId', 'repository', 'tag', 'recentDigestCount', 'cost', 'authority', 'approvedAt', 'expiresAt',
    ...(queued ? ['priorCandidateSha256', 'topologySha256'] : [])]);
  noAuthority(review.authority);
  if ((!queued && candidate.version !== 1) || review.version !== (queued ? 2 : 1) ||
      review.action !== (queued ? 'publish-one-reviewed-queue-receiver' : 'publish-one-reviewed-receiver-upgrade') ||
      review.configSha256 !== digest(json(c)) || review.profileSha256 !== digest(json(candidate.profile)) ||
      review.legacyPublicationSha256 !== digest(json(candidate.legacyPublication)) || !hash(review.sourceSha256) ||
      !/^[0-9a-f]{40}$/u.test(review.policyCommitSha ?? '') ||
      !sameId(review.registryId, ids(c).registry) || review.repository !== repository ||
      review.tag !== `receiver-${artifact.digest.slice(7, 19)}` ||
      review.tag === candidate.legacyPublication.release.tag || review.recentDigestCount !== (queued ? 3 : 2) ||
      !isDeepStrictEqual(review.cost, receiverCost(candidate)) || !review.cost.withinEstimate ||
      (queued && (review.priorCandidateSha256 !== digest(json(candidate.priorCandidate)) ||
        review.topologySha256 !== digest(json(candidate.topology)) || review.tag === candidate.priorCandidate.review.tag))) fail('EXACT_RECEIVER_PUBLICATION_REVIEW_REQUIRED');
  if (at !== undefined) {
    reviewTime(review, at);
    if (receiverDatabaseInstant(candidate.profile.scan.databaseUpdatedAt) > at || receiverDatabaseInstant(candidate.profile.scan.databaseNextUpdate) <= at) fail('RECEIVER_SCAN_EXPIRED');
  }
  if (!published) {
    if (candidate.publication !== null) fail('RECEIVER_PUBLICATION_ALREADY_RECORDED');
    return artifact;
  }
  const p = candidate.publication;
  closed(p, ['version', 'kind', 'profileSha256', 'reviewSha256', 'configSha256', 'intentAt', 'completedAt',
    'copyInvocations', 'manifestJson', 'configJson', 'repositories', 'manifests', 'referrers',
    'remoteBlobs', 'sourceArchiveSha256', 'sourceManifestSha256', 'noticesSha256', 'credentialDirectoriesRemoved']);
  reviewTime(review, instant(p.intentAt));
  if (receiverDatabaseInstant(candidate.profile.scan.databaseUpdatedAt) > instant(p.intentAt) ||
      receiverDatabaseInstant(candidate.profile.scan.databaseNextUpdate) <= instant(p.intentAt)) fail('RECEIVER_SCAN_EXPIRED');
  if (p.version !== 1 || p.kind !== 'single-copy-readback' || p.profileSha256 !== review.profileSha256 ||
      p.reviewSha256 !== digest(json(review)) || p.configSha256 !== digest(json(c)) || p.copyInvocations !== 1 ||
      instant(p.completedAt) < instant(p.intentAt) || instant(p.completedAt) >= instant(review.expiresAt) ||
      p.manifestJson !== candidate.profile.manifestJson || p.configJson !== candidate.profile.configJson ||
      !isDeepStrictEqual(p.remoteBlobs, [artifact.manifest.config, ...artifact.manifest.layers].map(({ digest, size }) => ({ digest, size }))) ||
      p.sourceArchiveSha256 !== candidate.profile.source.archiveSha256 ||
      p.sourceManifestSha256 !== candidate.profile.source.manifestSha256 || p.noticesSha256 !== candidate.profile.notices.sha256 ||
      p.credentialDirectoriesRemoved !== true) fail('RECEIVER_PUBLICATION_EVIDENCE_INVALID');
  verifyReceiverInventory(c, candidate, p, true);
  return artifact;
}

export function verifyReceiverInventory(c, candidate, inventory, published) {
  const old = candidate.legacyPublication.release, review = candidate.review, profile = candidate.profile;
  const prior = candidate.version === 2 ? candidate.priorCandidate : null;
  if (!isDeepStrictEqual(inventory.repositories, [repository]) || !Array.isArray(inventory.manifests) ||
      inventory.manifests.length !== (prior ? 2 : 1) + Number(published) ||
      !Array.isArray(inventory.referrers) || inventory.referrers.length) fail('RECEIVER_INVENTORY_CHANGED');
  const expected = [{ digest: old.manifestDigest, tags: [old.tag] },
    ...(prior ? [{ digest: prior.profile.manifestDigest, tags: [prior.review.tag] }] : []),
    ...(published ? [{ digest: profile.manifestDigest, tags: [review.tag] }] : [])];
  const actual = inventory.manifests.map(v => ({ digest: v.digest, tags: v.tags }));
  if (!isDeepStrictEqual(actual.sort((a, b) => a.digest.localeCompare(b.digest)), expected.sort((a, b) => a.digest.localeCompare(b.digest))) ||
      !sameId(review.registryId, ids(c).registry)) fail('RECEIVER_INVENTORY_CHANGED');
}

export function prepareReceiverPublication(c, candidate, inventory, at) {
  verifyReceiverCandidate(c, candidate, at, false);
  verifyReceiverInventory(c, candidate, inventory, false);
  return { version: 1, qualified: false, kind: 'receiver-publication-preview',
    configSha256: digest(json(c)), candidateSha256: digest(json(candidate)), inventorySha256: digest(json(inventory)),
    oldDigest: RECEIVER_DIGEST, candidateDigest: candidate.profile.manifestDigest, maximumNewImageDigests: 1,
    recentDigestCount: candidate.version === 2 ? 3 : 2, cost: receiverCost(candidate), pushExecuted: false, executionAuthorized: false };
}

export function receiverAnchor(c, receipts) {
  const upgrade = receipts.receiverUpgrade;
  if (!upgrade) return receipts['disabled-app']?.resources?.[ids(c).app];
  verifyDisabledImageRecord(c, upgrade);
  return upgrade.receipt.resources[ids(c).app];
}
export function runtimeReceiver(c, receipts) {
  if (!receipts.receiverUpgrade) return null;
  verifyDisabledImageRecord(c, receipts.receiverUpgrade);
  return ['disabled-image-upgrade', 'disabled-queue-upgrade'].includes(receipts.receiverUpgrade.phase.phase)
    ? { ...verifyReceiverCandidate(c, receipts.receiverUpgrade.candidate),
      ...(receipts.receiverUpgrade.candidate.version === 2 ? { queueTopology: receipts.receiverUpgrade.candidate.topology } : {}) } : null;
}

export function buildDisabledImagePhase(c, name, receipts, candidate, predecessor, instance, lineage) {
  if (!IMAGE_PHASES.includes(name)) fail('FIXED_DISABLED_IMAGE_PHASE_REQUIRED');
  verifyReceiverCandidate(c, candidate);
  validateWindowInstance(c, instance);
  const summary = verifyWindowPredecessor(c, predecessor);
  if (instance.predecessorSha256 !== digest(json(predecessor)) ||
      !isDeepStrictEqual(instance.previousInstanceIds, summary.usedInstanceIds)) fail('IMAGE_PREDECESSOR_BINDING_CHANGED');
  if (name === 'disabled-image-upgrade' && predecessor.kind !== 'terminal-disabled-window') fail('IMAGE_UPGRADE_ORIGIN_REQUIRED');
  const queued = name === 'disabled-queue-upgrade';
  if (queued !== (candidate.version === 2)) fail('QUEUE_PROFILE_PHASE_REQUIRED');
  if (queued) {
    if (predecessor.kind !== 'terminal-disabled-window' || predecessor.prerequisiteReceipts.receiverUpgrade?.phase?.phase !== 'disabled-image-upgrade' ||
        !isDeepStrictEqual(predecessor.prerequisiteReceipts.receiverUpgrade.candidate, candidate.priorCandidate)) fail('QUEUE_PREPARED_RECEIVER_PREDECESSOR_REQUIRED');
    qualifiedQueueRecords(c, receipts.queueRecords, candidate.topology);
  }
  if (name === 'disabled-image-rollback' && (predecessor.kind !== 'reviewed-disabled-image-change' ||
      predecessor.phase.phase !== 'disabled-image-upgrade' ||
      !isDeepStrictEqual(predecessor.candidate, candidate))) fail('IMAGE_ROLLBACK_ORIGIN_REQUIRED');
  const anchor = predecessor.kind === 'reviewed-disabled-image-change' ? predecessor.receipt.resources[ids(c).app] : predecessor.readback.app;
  const baseReceipts = { ...receipts }; delete baseReceipts.receiverUpgrade;
  const phase = buildPhase(c, 'synthetic-disable', null, baseReceipts, undefined, lineage, instance);
  phase.phase = name;
  phase.deploymentId = `${ids(c).group}/providers/Microsoft.Resources/deployments/${c.namePrefix}-u${instance.id.replaceAll('-', '')}-${queued ? 'qu' : name === 'disabled-image-upgrade' ? 'iu' : 'ir'}`;
  const fromDigest = queued ? candidate.priorCandidate.profile.manifestDigest : name === 'disabled-image-upgrade' ? RECEIVER_DIGEST : candidate.profile.manifestDigest;
  const toDigest = queued || name === 'disabled-image-upgrade' ? candidate.profile.manifestDigest : RECEIVER_DIGEST;
  if (queued) {
    phase.template.resources[0].properties.template.containers[0].env.push(...Object.entries(queueEnvironment(candidate.topology)).map(([name, value]) => ({ name, value })));
    phase.queueRecordsSha256 = digest(json(receipts.queueRecords));
  }
  phase.template.resources[0].properties.template.containers[0].image = `${c.registryName}.azurecr.io/${repository}@${toDigest}`;
  phase.resources[0].expected = phase.template.resources[0];
  phase.transition = { version: 1, from: ['false'], to: 'false', maximumWrites: 1,
    anchorAppSha256: digest(json(anchor)), fromDigest, toDigest, candidateSha256: digest(json(candidate)),
    predecessorSha256: digest(json(predecessor)) };
  phase.allowedModify = { [ids(c).app]: ['properties.template.containers[0].image',
    ...(queued ? ['properties.template.containers[0].env'] : [])] };
  phase.ingestEnabled = false;
  return phase;
}

function withImage(descriptor, c, image) {
  const value = structuredClone(descriptor);
  value.expected.properties.template.containers[0].image = `${c.registryName}.azurecr.io/${repository}@${image}`;
  // The v2 preimage is the prepared-identity receiver, never a queue-configured app.
  if (value.expected.properties.template.containers[0].env.some(v => v.name === 'AZURE_QUEUE_URL')) {
    value.expected.properties.template.containers[0].env = value.expected.properties.template.containers[0].env
      .filter(v => !['AZURE_QUEUE_URL', 'AZURE_QUEUE_RESOURCE_ID'].includes(v.name));
  }
  return value;
}
export function verifyDisabledImageBefore(c, phase, app, anchor, context) {
  if (!IMAGE_PHASES.includes(phase.phase) || admissionFlag(app) !== 'false' || admissionFlag(anchor) !== 'false' ||
      phase.transition.anchorAppSha256 !== digest(json(anchor)) ||
      !isDeepStrictEqual(executionIdentity(app, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps')) ||
      app.properties.latestRevisionName !== anchor.properties.latestRevisionName ||
      app.properties.latestReadyRevisionName !== app.properties.latestRevisionName) fail('DISABLED_IMAGE_PREIMAGE_CHANGED');
  const descriptor = withImage(phase.resources[0], c, phase.transition.fromDigest);
  if (!isDeepStrictEqual(canonicalAppWrite(c, descriptor, app, context), canonicalAppWrite(c, descriptor, anchor, context))) fail('DISABLED_IMAGE_PREIMAGE_CHANGED');
}
export function verifyDisabledImageWhatIf(phase, change, context) {
  const c = context?.config, candidate = context?.receiverCandidate;
  if (!c || !candidate || phase.resources.length !== 1 || phase.transition.candidateSha256 !== digest(json(candidate))) fail('IMAGE_WHATIF_CONTEXT_REQUIRED');
  verifyReceiverCandidate(c, candidate);
  if (change.changeType !== 'Modify' || !change.before || !change.after ||
      admissionFlag(change.before) !== 'false' || admissionFlag(change.after) !== 'false') fail('DISABLED_IMAGE_ONLY_REQUIRED');
  const expectedPair = phase.phase === 'disabled-queue-upgrade' && candidate.version === 2 ? [candidate.priorCandidate.profile.manifestDigest, candidate.profile.manifestDigest]
    : phase.phase === 'disabled-image-upgrade' ? [RECEIVER_DIGEST, candidate.profile.manifestDigest]
    : phase.phase === 'disabled-image-rollback' ? [candidate.profile.manifestDigest, RECEIVER_DIGEST] : [];
  if (!isDeepStrictEqual([phase.transition.fromDigest, phase.transition.toDigest], expectedPair) ||
      [change.before, change.after].some((value, i) =>
        value.properties.template.containers[0].image !== `${c.registryName}.azurecr.io/${repository}@${expectedPair[i]}`)) fail('DISABLED_IMAGE_DIRECTION_CHANGED');
  const beforeDescriptor = withImage(phase.resources[0], c, phase.transition.fromDigest);
  const before = canonicalAppWrite(c, beforeDescriptor, change.before, context, true);
  // The current observation is the preimage, not the target image.
  const after = canonicalAppWrite(c, phase.resources[0], change.after, { ...context, appDescriptor: beforeDescriptor }, true);
  if (!isDeepStrictEqual(before, canonicalAppWrite(c, beforeDescriptor, context.app, context))) fail('DISABLED_IMAGE_PREIMAGE_CHANGED');
  before.properties.template.containers[0].image = after.properties.template.containers[0].image;
  if (phase.phase === 'disabled-queue-upgrade') Object.assign(before.properties.template.containers[0].env, queueEnvironment(candidate.topology));
  if (!isDeepStrictEqual(before, after) || phase.transition.fromDigest === phase.transition.toDigest) fail('DISABLED_IMAGE_ONLY_REQUIRED');
}

export function verifyImageRuntimePublication(c, expected, context) {
  const image = expected.properties.template.containers[0].image;
  if (image === `${c.registryName}.azurecr.io/${repository}@${RECEIVER_DIGEST}`) return false;
  const candidate = context?.receiverCandidate ?? context?.receiverUpgrade?.candidate;
  if (!candidate) fail('REVIEWED_RECEIVER_PROFILE_REQUIRED');
  const artifact = verifyReceiverCandidate(c, candidate);
  if (candidate.version === 2 && image === `${c.registryName}.azurecr.io/${repository}@${candidate.priorCandidate.profile.manifestDigest}`) return true;
  if (image !== `${c.registryName}.azurecr.io/${repository}@${artifact.digest}`) fail('REVIEWED_RECEIVER_PROFILE_REQUIRED');
  return true;
}

export function verifyDisabledImageRecord(c, record) {
  closed(record, ['version', 'kind', 'publication', 'candidate', 'predecessor', 'prerequisiteReceipts', 'phase',
    'approval', 'preflight', 'whatIf', 'journal', 'receipt']);
  closed(record.publication, ['commitSha', 'sourceSha256']);
  if (record.version !== 1 || record.kind !== 'reviewed-disabled-image-change' ||
      !/^[0-9a-f]{40}$/u.test(record.publication.commitSha ?? '') || !hash(record.publication.sourceSha256)) fail('IMAGE_RECORD_INVALID');
  const { candidate, predecessor, phase, approval, preflight, journal, receipt } = record;
  verifyReceiverCandidate(c, candidate);
  const expected = buildDisabledImagePhase(c, phase.phase, record.prerequisiteReceipts, candidate, predecessor, phase.windowInstance);
  if (phase.reconciliation) expected.reconciliation = phase.reconciliation;
  if (!isDeepStrictEqual(phase, expected)) fail('IMAGE_RECORD_PHASE_CHANGED');
  const intentAt = instant(journal.intentAt);
  verifyApproval(approval, c, phase, record.publication.sourceSha256, intentAt);
  verifyFreshReview(preflight, approval, preflight.startedAt, intentAt);
  if (!isDeepStrictEqual(preflight.cost, receiverCost(candidate)) ||
      approval.receiptsSha256 !== digest(json(record.prerequisiteReceipts)) ||
      approval.whatIfSha256 !== digest(json(record.whatIf)) || approval.originSha256 !== c.originSha256 ||
      journal.phaseSha256 !== digest(json(phase)) || journal.approvalSha256 !== digest(json(approval)) ||
      journal.outcome !== 'readback-qualified' || journal.transportDispatchAttempted !== true ||
      journal.receiptSha256 !== digest(json(receipt)) || receipt.qualified !== true ||
      receipt.qualificationKind !== 'ready-disabled-image-change' || receipt.noOtherChange !== true ||
      receipt.ingestionEnabled !== false || receipt.configSha256 !== digest(json(c)) ||
      receipt.phaseSha256 !== digest(json(phase)) || receipt.sourceSha256 !== record.publication.sourceSha256 ||
      receipt.approvalSha256 !== digest(json(approval)) || receipt.candidateSha256 !== digest(json(candidate)) ||
      !sameId(receipt.deployment?.id, phase.deploymentId) ||
      instant(receipt.completedAt) < intentAt || instant(receipt.completedAt) > intentAt + 120000) fail('IMAGE_RECORD_EXECUTION_INVALID');
  verifyDeploymentIdentity(receipt.deployment, receipt.deployment);
  const anchor = predecessor.kind === 'reviewed-disabled-image-change' ? predecessor.receipt.resources[ids(c).app] : predecessor.readback.app;
  const context = { ...resourceContext(c, record.prerequisiteReceipts), receiverCandidate: candidate, config: c, app: anchor };
  const preserved = Object.values(record.prerequisiteReceipts).flatMap(v => Object.keys(v.resources ?? {}));
  if (candidate.version === 2) preserved.push(...Object.keys(qualifiedQueueRecords(c, record.prerequisiteReceipts.queueRecords, candidate.topology)));
  verifyWhatIf(phase, record.whatIf, preserved, context);
  closed(receipt.resources, [ids(c).app]);
  const app = receipt.resources[ids(c).app];
  verifyResource(c, phase, phase.resources[0], app, context);
  if (admissionFlag(app) !== 'false' || app.properties.latestRevisionName === anchor.properties.latestRevisionName ||
      app.properties.latestReadyRevisionName !== app.properties.latestRevisionName ||
      !isDeepStrictEqual(executionIdentity(app, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps'))) fail('IMAGE_RECORD_READBACK_INVALID');
  verifyImageRevision(c, phase, app, receipt.revisions, context);
  verifyImagePrivacy(c, receipt.privacy);
  return { outcome: 'reviewed-disabled-image-change', appIdentity: executionIdentity(app, 'Microsoft.App/containerApps'),
    usedInstanceIds: [...verifyWindowPredecessor(c, predecessor).usedInstanceIds, phase.windowInstance.id] };
}
function verifyImagePrivacy(c, privacy) {
  closed(privacy, ['diagnostics', 'exports']);
  closed(privacy.diagnostics, [ids(c).app]);
  for (const v of [...Object.values(privacy.diagnostics), privacy.exports]) {
    if (!Array.isArray(v?.value) || v.nextLink || v.value.length) fail('IMAGE_PRIVACY_DRIFT');
  }
}

export function verifyImageRevision(c, phase, app, revisions, context) {
  if (!Array.isArray(revisions?.value) || revisions.nextLink || app.properties.runningStatus !== 'Running' ||
      app.properties.provisioningState !== 'Succeeded' ||
      app.properties.latestReadyRevisionName !== app.properties.latestRevisionName) fail('IMAGE_REVISION_NOT_READY');
  const active = revisions.value.filter(v => v.properties?.active === true), name = app.properties.latestRevisionName;
  if (active.length !== 1 || active[0].name !== name || !sameId(active[0].id, `${ids(c).app}/revisions/${name}`)) fail('IMAGE_REVISION_NOT_READY');
  const p = active[0].properties;
  if (p.provisioningState !== 'Provisioned' || p.healthState !== 'Healthy' || !['Running', 'RunningAtMaxScale'].includes(p.runningState) ||
      p.replicas !== 1 || p.trafficWeight !== 100) fail('IMAGE_REVISION_NOT_READY');
  const copy = structuredClone(app); copy.properties.template = structuredClone(p.template);
  if (copy.properties.template.revisionSuffix === null) delete copy.properties.template.revisionSuffix;
  for (const k of ['cooldownPeriod', 'pollingInterval']) if (copy.properties.template.scale?.[k] === null) delete copy.properties.template.scale[k];
  if (!isDeepStrictEqual(canonicalAppWrite(c, phase.resources[0], copy, context), canonicalAppWrite(c, phase.resources[0], app, context))) fail('IMAGE_REVISION_TEMPLATE_CHANGED');
}

// The IO boundary is the same narrow deployment transport as the original controller.
// It is intentionally not a registry publisher or a generic resource executor.
export class ReceiverUpgradeController {
  constructor(c, phase, candidate, anchor, io) { Object.assign(this, { c, phase, candidate, anchor, io }); }
  async execute(approval) {
    const { c, phase, candidate, anchor, io } = this, source = await io.sourceDigest();
    if (!IMAGE_PHASES.includes(phase.phase) || phase.transition.candidateSha256 !== digest(json(candidate))) fail('FIXED_DISABLED_IMAGE_PHASE_REQUIRED');
    verifyReceiverCandidate(c, candidate);
    verifyApproval(approval, c, phase, source, io.now());
    if (await io.loadJournal()) fail('IMAGE_INTENT_REPLAY_FORBIDDEN');
    const started = io.now(), proof = await io.check();
    const freshnessDeadline = () => Math.min(proof.startedAt + 300000, instant(approval.expiresAt));
    const guard = deadline => {
      verifyApproval(approval, c, phase, source, io.now());
      verifyFreshReview(proof, approval, started, io.now());
      if (!isDeepStrictEqual(proof.cost, receiverCost(candidate))) fail('IMAGE_COST_REVIEW_REQUIRED');
      if (['disabled-image-upgrade', 'disabled-queue-upgrade'].includes(phase.phase) &&
          receiverDatabaseInstant(candidate.profile.scan.databaseNextUpdate) <= io.now()) fail('RECEIVER_SCAN_EXPIRED');
      if (io.cancelled?.()) fail('IMAGE_UPGRADE_CANCELLED');
      if (!Number.isSafeInteger(deadline) || io.now() >= deadline) fail('IMAGE_OPERATION_DEADLINE');
    };
    const checkCurrent = async deadline => {
      guard(deadline);
      await io.security(deadline);
      guard(deadline);
      if (await io.deployment(deadline)) fail('IMAGE_DEPLOYMENT_ALREADY_EXISTS');
      guard(deadline);
      const observation = await io.observe(deadline);
      guard(deadline);
      verifyDisabledImageBefore(c, phase, observation.app, anchor, observation.context);
      if (await io.sourceDigest() !== source) fail('IMAGE_SOURCE_CHANGED');
      guard(deadline);
    };
    const finalCheckDeadline = Math.min(io.now() + 120000, freshnessDeadline());
    guard(finalCheckDeadline);
    await checkCurrent(finalCheckDeadline);
    await io.reserve();
    guard(finalCheckDeadline);
    const intentAt = io.now(), rolloutDeadline = intentAt + 120000;
    const deadline = Math.min(rolloutDeadline, freshnessDeadline());
    const journal = { phase: phase.phase, phaseSha256: digest(json(phase)), approvalSha256: digest(json(approval)),
      intentAt: new Date(intentAt).toISOString(), finalCheckDeadline, rolloutDeadline, operationDeadline: deadline,
      outcome: 'submission-possible', transportDispatchAttempted: null };
    await io.saveJournal(journal);
    const dispatchGuard = () => guard(deadline);
    let dispatched = false;
    try {
      await io.arm('PUT', phase.deploymentId, '2022-09-01', { properties: { mode: 'Incremental', template: phase.template } },
        undefined, () => { dispatchGuard(); dispatched = true; }, undefined, () => checkCurrent(deadline), deadline);
      dispatchGuard();
      journal.transportDispatchAttempted = dispatched;
      let deployment, ready;
      for (let polls = 0; polls < 40 && io.now() < deadline; polls++) {
        dispatchGuard();
        deployment = await io.deployment(deadline);
        dispatchGuard();
        if (deployment && !sameId(deployment.id, phase.deploymentId)) fail('IMAGE_DEPLOYMENT_IDENTITY_CHANGED');
        if (['Failed', 'Canceled'].includes(deployment?.properties?.provisioningState)) fail('IMAGE_DEPLOYMENT_FAILED_PRESERVED');
        if (deployment?.properties?.provisioningState === 'Succeeded') {
          const observation = await io.observe(deadline);
          dispatchGuard();
          verifyResource(c, phase, phase.resources[0], observation.app, observation.context);
          if (!isDeepStrictEqual(executionIdentity(observation.app, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps')) ||
              observation.app.properties.latestRevisionName === anchor.properties.latestRevisionName) fail('IMAGE_READBACK_IDENTITY_CHANGED');
          try { verifyImageRevision(c, phase, observation.app, observation.revisions, observation.context); ready = observation; }
          catch (error) { if (error.message !== 'IMAGE_REVISION_NOT_READY') throw error; }
          if (ready) break;
        }
        await io.sleep(Math.min(3000, Math.max(0, deadline - io.now())));
      }
      if (!ready) fail('IMAGE_ROLLOUT_UNRESOLVED');
      const privacy = await io.privacy(deadline);
      dispatchGuard();
      verifyImagePrivacy(c, privacy);
      await io.security(deadline);
      dispatchGuard();
      const final = await io.observe(deadline);
      dispatchGuard();
      verifyResource(c, phase, phase.resources[0], final.app, final.context);
      verifyImageRevision(c, phase, final.app, final.revisions, final.context);
      if (final.app.properties.latestRevisionName !== ready.app.properties.latestRevisionName ||
          !isDeepStrictEqual(executionIdentity(final.app, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps'))) fail('IMAGE_FINAL_READBACK_CHANGED');
      ready = final;
      dispatchGuard();
      const receipt = { qualified: true, qualificationKind: 'ready-disabled-image-change',
        configSha256: digest(json(c)), phaseSha256: digest(json(phase)), sourceSha256: source,
        approvalSha256: digest(json(approval)), candidateSha256: digest(json(candidate)), deployment,
        resources: { [ids(c).app]: ready.app }, revisions: ready.revisions, privacy,
        finalCheckDeadline, rolloutDeadline, operationDeadline: deadline,
        noOtherChange: true, ingestionEnabled: false, completedAt: new Date(io.now()).toISOString() };
      await io.saveReceipt(receipt);
      journal.outcome = 'readback-qualified'; journal.receiptSha256 = digest(json(receipt));
      await io.saveJournal(journal);
      return receipt;
    } catch (error) {
      journal.outcome = 'reconciliation-required'; journal.transportDispatchAttempted = dispatched;
      journal.failureCode = /^[A-Z_]+$/u.test(error.message) ? error.message : 'IMAGE_OPERATION_FAILED';
      await io.saveJournal(journal);
      fail('IMAGE_CHANGE_STOPPED_RESOURCES_PRESERVED');
    }
  }
}
