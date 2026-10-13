import { digest, ids, json, firstReleaseCost } from '../definition.mjs';
import { NATIVE_CONDITIONS, PREPARED_IDENTITY_RUNTIME, RECEIVER_SOURCE_INPUTS } from '../receiver-upgrade.mjs';
import { manifestJson, configJson } from './receiver-oci.fixture.mjs';
import assert from 'node:assert/strict';

export async function receiverSourceFixtureRun(command, args) {
  assert.equal(command, 'git');
  if (args[0] === 'merge-base') return { stdout: Buffer.alloc(0) };
  assert.deepEqual(args.slice(0, 2), ['--no-pager', 'show']);
  const path = args[2].slice(41);
  assert(RECEIVER_SOURCE_INPUTS.includes(path));
  const value = path === 'services/telemetry-ingest/src/identity-readiness.ts' ? 'fixture readiness'
    : path === 'services/telemetry-ingest/Dockerfile' ? 'fixture Dockerfile' : `fixture ${path}`;
  return { stdout: Buffer.from(value) };
}

// Inert generated test evidence, never an operator approval or a published candidate.
export function candidateFixture(c, legacyReceipt) {
  let manifest = JSON.parse(manifestJson);
  const imageConfig = JSON.parse(configJson);
  const target = { subscriptionId: c.subscriptionId, registryResourceId: ids(c).registry, registry: `${c.registryName}.azurecr.io`,
    repository: 'missionspec/telemetry-ingest', tag: 'receiver-91c72962bdb2', manifestDigest: c.receiverDigest,
    configDigest: manifest.config.digest, maximumNewImageDigests: 1 };
  const currentScan = { reportSha256: digest('scan'), databaseSha256: digest('db'),
    databaseUpdatedAt: '2026-09-23T00:00:00.000Z', databaseNextUpdate: '2026-09-24T00:00:00.000Z', counts: { MEDIUM: 13, LOW: 7, UNKNOWN: 2 } };
  const binding = { target, currentScan };
  const release = { version: 1, action: 'publish-one-receiver-digest', publicationBindingSha256: digest(json(binding)),
    ...Object.fromEntries(['registry', 'repository', 'tag', 'manifestDigest', 'configDigest', 'maximumNewImageDigests'].map(k => [k, target[k]])),
    approvedAt: '2026-09-23T00:27:00.000Z', expiresAt: '2026-09-23T00:57:00.000Z',
    runtimeQualification: 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY',
    retainedAdvisories: ['CVE-2026-95818', 'CVE-2026-86805', 'CVE-2026-91745', 'CVE-2026-93377', 'CVE-2026-91728'],
    applicationDeploymentAuthorized: false, ingestionAuthorized: false, clientActivationAuthorized: false, repushOrDeletionAuthorized: false };
  const blobs = [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size }));
  const receipt = { ...legacyReceipt, manifest, checkedAt: '2026-09-23T00:29:00.000Z',
    nativeV8Clearance: release.runtimeQualification, publicationReleaseSha256: digest(json(release)), publicationBindingSha256: release.publicationBindingSha256,
    copyInvocations: 1, copySucceeded: true,
    independentlyVerifiedRemoteGraph: { manifestDigest: target.manifestDigest, configDigest: target.configDigest, blobs, platform: 'linux/amd64',
      user: imageConfig.config.User, command: imageConfig.config.Cmd },
    correspondingSource: { archiveSha256: digest('source archive'), manifestSha256: digest('source manifest'), boundToVerifiedRemoteLayerBytes: true },
    securityQualification: { scanReportSha256: currentScan.reportSha256, databaseSha256: currentScan.databaseSha256,
      databaseUpdatedAt: currentScan.databaseUpdatedAt, databaseNextUpdate: currentScan.databaseNextUpdate, counts: currentScan.counts,
      suppressedFindings: 0, nativeV8ConditionsRetained: true, patchedOrCompleteNativeCoverageClaimed: false,
      runtimeQualification: release.runtimeQualification, retainedAdvisories: release.retainedAdvisories },
    applicationDeploymentAuthorized: false, ingestionAuthorized: false, clientActivationAuthorized: false };
  const legacyPublication = { version: 1, receipt, release, binding, manifestJson, configJson,
    journal: { version: 1, action: release.action, target, bindingSha256: release.publicationBindingSha256, releaseSha256: digest(json(release)),
      publicationReceiptSha256: digest(json(receipt)), outcome: 'published-readback-qualified', maximumCopyInvocations: 1,
      copyInvocations: 1, copySucceeded: true, verifiedRemoteBlobCount: blobs.length, intentAt: '2026-09-23T00:28:00.000Z' },
    qualification: { checkedAt: '2026-09-23T00:29:30.000Z', publicationReceiptSha256: digest(json(receipt)),
      copyInvocations: 1, copySucceeded: true, remoteBlobCount: blobs.length, credentialDirectoriesRemoved: true } };
  manifest = structuredClone(manifest);
  imageConfig.created = '2026-09-23T08:00:00Z';
  const configBytes = json(imageConfig);
  manifest.config.digest = 'sha256:' + digest(configBytes); manifest.config.size = Buffer.byteLength(configBytes);
  const manifestBytes = json(manifest), manifestDigest = 'sha256:' + digest(manifestBytes);
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 13, LOW: 7, UNKNOWN: 2 };
  const reportJson = json({ ArtifactName: manifestDigest, Results: [{ Vulnerabilities: Object.entries(counts).flatMap(([Severity, n]) =>
    Array.from({ length: n }, (_, i) => ({ Severity, VulnerabilityID: `fixture-${Severity}-${i}` }))) }] });
  const authority = { ingestion: false, clientActivation: false, productionClearance: false, delete: false,
    retag: false, repush: false, registryAdmin: false };
  const noticeInventory = json([{ path: 'NOTICE', bytes: Buffer.byteLength('fixture notices'), sha256: digest('fixture notices') }]);
  const noticeBytes = json({ version: 1, inventoryJson: noticeInventory, inventorySha256: digest(noticeInventory),
    files: [{ path: 'NOTICE', base64: Buffer.from('fixture notices').toString('base64') }] });
  const profile = { version: 1, kind: 'reviewed-prepared-identity-receiver', manifestDigest, configDigest: manifest.config.digest,
    manifestJson: manifestBytes, configJson: configBytes,
    source: { commitSha: 'b'.repeat(40), files: {
      ...Object.fromEntries(RECEIVER_SOURCE_INPUTS.map(path => [path, digest(`fixture ${path}`)])),
      'services/telemetry-ingest/src/identity-readiness.ts': digest('fixture readiness'),
      'services/telemetry-ingest/Dockerfile': digest('fixture Dockerfile'),
    }, archiveSha256: digest('fixture archive'), manifestSha256: digest('fixture source manifest'),
    remoteLayerDigests: manifest.layers.map(v => v.digest) },
    notices: { sha256: digest(noticeBytes), bytes: noticeBytes },
    scan: { reportSha256: digest(reportJson), reportJson, databaseSha256: digest('fixture db'),
      databaseUpdatedAt: '2026-09-23T08:00:00.000Z', databaseNextUpdate: '2026-09-24T08:00:00.000Z', counts, suppressedFindings: 0 },
    runtime: PREPARED_IDENTITY_RUNTIME, nativeClearance: 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY', retainedAdvisories: NATIVE_CONDITIONS,
    priorUnknownGlibcCaveatWaived: false, authority };
  const qualificationJson = json({ result: 'LOCAL_TECHNICAL_QUALIFICATION_PASSED_CONDITIONAL_RELEASE_ONLY',
    artifact: { manifest: profile.manifestDigest, config: profile.configDigest, platform: 'linux/amd64', user: '65532:65532',
      command: imageConfig.config.Cmd, sourceReceipt: { sha256: profile.source.archiveSha256, manifestSha256: profile.source.manifestSha256 },
      noticeFiles: 1, serviceSourceMatchesIntentAndDisk: true, includesNewIdentityReadinessSource: true, cloudPublication: false },
    allSavedOciLayerHashesVerified: true, buildTests: { passed: 56, failed: 0, platform: 'linux/amd64' }, scanCounts: counts,
    scanner: { dbSha256: profile.scan.databaseSha256, dbMetadata: { UpdatedAt: profile.scan.databaseUpdatedAt, NextUpdate: profile.scan.databaseNextUpdate }, localOnlyScan: true },
    priorUnknownGlibcCaveatWaived: false, productionAzureQualification: false, publicationAuthorized: false, azureEffects: false,
    nativeCoverage: 'partial; no new native patch proof; CVE-2026-91745, CVE-2026-93377, CVE-2026-91728 conditions retained',
    oldImagePreserved: c.receiverDigest,
    runtimeConstraints: { cpuMax: '25000 100000', memoryMaxBytes: 536870912, capEff: '0000000000000000', noNewPrivs: 1,
      uid: 65532, gid: 65532, network: 'none', readOnlyRoot: true },
    resourceFixtures: Object.fromEntries([['disabled-main', 0, 0, 503], ['slow-identity', 1, 1, 204], ['failed-identity', 1, 0, null]].map(
      ([scenario, identityRequests, ingestionRequests, status]) => [scenario, { result: 'LOCAL_RESOURCE_READINESS_PASSED',
        scenario, uid: 65532, identityRequests, ingestionRequests, productionAzureQualification: false,
        ...(status === null ? {} : { firstEvent: { status, elapsedMs: 20 } }) }])) });
  profile.qualification = { reportJson: qualificationJson, reportSha256: digest(qualificationJson) };
  const review = { version: 1, action: 'publish-one-reviewed-receiver-upgrade', configSha256: digest(json(c)),
    profileSha256: digest(json(profile)), legacyPublicationSha256: digest(json(legacyPublication)), sourceSha256: digest('upgrade-policy'), policyCommitSha: 'c'.repeat(40),
    registryId: ids(c).registry, repository: target.repository, tag: `receiver-${manifestDigest.slice(7, 19)}`,
    recentDigestCount: 2, cost: firstReleaseCost(2), authority, approvedAt: '2026-09-23T08:00:00.000Z', expiresAt: '2026-09-23T09:00:00.000Z' };
  const publication = { version: 1, kind: 'single-copy-readback', profileSha256: review.profileSha256,
    reviewSha256: digest(json(review)), configSha256: digest(json(c)), intentAt: '2026-09-23T08:01:00.000Z', completedAt: '2026-09-23T08:02:00.000Z',
    copyInvocations: 1, manifestJson: manifestBytes, configJson: configBytes, repositories: [target.repository],
    manifests: [{ digest: target.manifestDigest, tags: [target.tag] }, { digest: manifestDigest, tags: [review.tag] }], referrers: [],
    remoteBlobs: [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size })),
    sourceArchiveSha256: profile.source.archiveSha256, sourceManifestSha256: profile.source.manifestSha256,
    noticesSha256: profile.notices.sha256, credentialDirectoriesRemoved: true };
  return { version: 1, profile, review, legacyPublication, publication };
}
