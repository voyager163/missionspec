import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { open, lstat, mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { join, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';
import { isDeepStrictEqual, promisify, types } from 'node:util';
import { closed, digest, digestJson, fail, ids, json, sameId, SYNTHETIC_FIXTURES, SYNTHETIC_LIMITS } from './definition.mjs';
import { admissionFlag, canonicalAppWrite, canonicalInstant, executionIdentity, verifySyntheticRows } from './policy.mjs';
import { receiverDatabaseInstant, verifyReceiverProfile, verifyReceiverCandidate, verifyReceiverInventory } from './receiver-upgrade.mjs';
import { QUEUE_RUNTIME, queueEnvironment } from './durable-queue.mjs';
import { queueArmInstant } from './queue-adoption.mjs';
import { privateLinkAcaCreationIdentity } from './private-link-readback.mjs';
import { verifyPrivateLinkPolicyRevision, verifyPrivateLinkCostReview } from './private-link-controller.mjs';
import { loadPrivateLinkArtifact, savePrivateLinkArtifact, updatePrivateLinkArtifact } from './private-link-artifacts.mjs';
import { az, sourceDigest, publishedSourceDigest, verifyReceiverSource, saveImmutable, save, load,
  emptyAcrReferrers, safeOperationFailure, syntheticHttp, readSyntheticQuery, asyncWhatIf, privateDirectory,
  limitReadConcurrency, authenticatedWhatIfRequest, whatIfRequestContext } from './controller.mjs';

const execute = promisify(execFile);
const repository = 'missionspec/telemetry-ingest';
const privateRoot = fileURLToPath(new URL('./.operator-private/', import.meta.url));
const appApi = '2025-07-01';
const hash = digestJson;
const equal = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
const iso = at => new Date(at).toISOString();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export const PRIVATE_RUNTIME_LIMITS = Object.freeze({ ...SYNTHETIC_LIMITS,
  publicationMs: 600000, currentProofMs: 120000, armRequestMs: 15000, maximumImageCopies: 1, privateProbeMs: 30000,
  publicControlMs: 900000 });
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(value);
const stageDeadline = (io, cap, ms = 120000) => {
  deadline(io.now, cap);
  return Math.min(io.now() + ms, cap);
};

function deadline(now, until) {
  if (!Number.isSafeInteger(until) || now() >= until) fail('PRIVATE_RUNTIME_DEADLINE');
}
function review(value, action, binding, at) {
  closed(value, ['version', 'action', 'bindingSha256', 'sourceSha256', 'policyCommitSha', 'approvedAt', 'expiresAt']);
  if (value.version !== 1 || value.action !== action || value.bindingSha256 !== hash(binding) ||
      !sha(value.sourceSha256) || !/^[a-f0-9]{40}$/u.test(value.policyCommitSha)) fail('PRIVATE_RUNTIME_REVIEW_REQUIRED');
  const start = canonicalInstant(value.approvedAt), end = canonicalInstant(value.expiresAt);
  if (start > at || end <= at || end - start > 3600000) fail('PRIVATE_RUNTIME_REVIEW_EXPIRED');
  const selected = binding.runtimeReview;
  if (selected) {
    const revision = selected.policyRevision;
    const image = selected.imageProfileRevision;
    if (value.sourceSha256 !== selected.costReview.sourceSha256 ||
        revision && (value.sourceSha256 !== revision.sourceSha256 || value.policyCommitSha !== revision.publication.commitSha) ||
        image && (value.sourceSha256 !== image.sourceSha256 || value.policyCommitSha !== image.publication.commitSha)) fail('PRIVATE_RUNTIME_REVIEW_SOURCE_CHANGED');
    if (!['private-link-false-only-disable', 'private-link-delete-public-control'].includes(action)) {
      if (at < canonicalInstant(selected.costReview.approvedAt) || at >= canonicalInstant(selected.costReview.expiresAt) ||
          at - canonicalInstant(selected.costEvidence.retrievedAt) > 86400000 ||
          revision && (at < canonicalInstant(revision.approvedAt) || at >= canonicalInstant(revision.expiresAt)) ||
          image && (at < canonicalInstant(image.approvedAt) || at >= canonicalInstant(image.expiresAt))) fail('PRIVATE_RUNTIME_CURRENT_REVIEW_EXPIRED');
    }
  }
}
function imageRevisionReview(c, context, revision, source, at) {
  closed(revision, ['version', 'action', 'configSha256', 'planSha256', 'originSha256', 'originalProfileSha256',
    'profileSha256', 'manifestDigest', 'configDigest', 'sourceSha256', 'publication', 'approvedAt', 'expiresAt']);
  closed(revision.publication, ['commitSha', 'sourceSha256']);
  const original = context.origin.queueProfile;
  if (revision.version !== 1 || revision.action !== 'review-same-image-private-link-scan-refresh' ||
      revision.configSha256 !== hash(c) || revision.planSha256 !== context.plan.planSha256 ||
      revision.originSha256 !== hash(context.origin) || revision.originalProfileSha256 !== hash(original) ||
      !sha(revision.profileSha256) || revision.profileSha256 === revision.originalProfileSha256 ||
      revision.manifestDigest !== original.manifestDigest || revision.configDigest !== original.configDigest ||
      revision.sourceSha256 !== source || revision.publication.sourceSha256 !== source ||
      !/^[a-f0-9]{40}$/u.test(revision.publication.commitSha ?? '')) fail('PRIVATE_IMAGE_PROFILE_REVISION_REQUIRED');
  const approved = canonicalInstant(revision.approvedAt), expires = canonicalInstant(revision.expiresAt);
  if (!Number.isSafeInteger(at) || approved > at || at >= expires || expires - approved > 3600000 || expires <= approved) {
    fail('PRIVATE_IMAGE_PROFILE_REVISION_EXPIRED');
  }
}
function profileQualification(profile) {
  if (typeof profile.qualification?.reportJson !== 'string' ||
      Buffer.byteLength(profile.qualification.reportJson) > 64 * 1024 * 1024) fail('PRIVATE_IMAGE_QUALIFICATION_INVALID');
  try { return JSON.parse(profile.qualification.reportJson); } catch { fail('PRIVATE_IMAGE_QUALIFICATION_INVALID'); }
}
function scanReportInstant(value) {
  const match = typeof value === 'string' && /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u.exec(value);
  if (!match || Number(match[5] ?? 0) > 14 || Number(match[6] ?? 0) > 59 ||
      Number(match[5] ?? 0) === 14 && Number(match[6] ?? 0) !== 0) fail('PRIVATE_IMAGE_SCAN_REPORT_TIME_INVALID');
  const local = receiverDatabaseInstant(`${match[1]}.${(match[2] ?? '').padEnd(3, '0')}Z`);
  const offset = (Number(match[5] ?? 0) * 60 + Number(match[6] ?? 0)) * 60000;
  return local + (match[4] === '-' ? offset : -offset);
}
export function verifyImageProfileRevision(c, context, profile, revision, at) {
  imageRevisionReview(c, context, revision, revision.sourceSha256, at);
  const original = context.origin.queueProfile;
  verifyReceiverProfile(original);
  verifyReceiverProfile(profile);
  if (revision.profileSha256 !== hash(profile)) fail('PRIVATE_IMAGE_PROFILE_REVISION_CHANGED');
  const { scan: oldScan, qualification: oldQualification, ...oldImage } = original;
  const { scan, qualification, ...image } = profile;
  equal(image, oldImage, 'PRIVATE_IMAGE_IMMUTABLE_BYTES_CHANGED');
  const before = profileQualification(original), after = profileQualification(profile);
  const { scanCounts: oldCounts, scanner: oldScanner, scanRefresh: priorRefresh, ...oldMeasurements } = before;
  const { scanCounts, scanner, scanRefresh, ...measurements } = after;
  equal(measurements, oldMeasurements, 'PRIVATE_IMAGE_QUALIFICATION_MEASUREMENTS_CHANGED');
  closed(scanner, Object.keys(oldScanner));
  const { dbSha256: oldDb, dbMetadata: oldMetadata, ...oldScannerIdentity } = oldScanner;
  const { dbSha256: newDb, dbMetadata, ...scannerIdentity } = scanner;
  equal(scannerIdentity, oldScannerIdentity, 'PRIVATE_IMAGE_SCANNER_CHANGED');
  closed(dbMetadata, [...new Set([...Object.keys(oldMetadata), 'UpdatedAt', 'NextUpdate', 'DownloadedAt'])]);
  const { UpdatedAt: oldUpdated, NextUpdate: oldNext, DownloadedAt: oldDownloaded, ...oldDbIdentity } = oldMetadata;
  const { UpdatedAt, NextUpdate, DownloadedAt, ...dbIdentity } = dbMetadata;
  equal(dbIdentity, oldDbIdentity, 'PRIVATE_IMAGE_SCANNER_DATABASE_CHANGED');
  closed(scanRefresh, ['version', 'kind', 'startedAt', 'completedAt', 'previousProfileSha256', 'previousRefreshSha256',
    'imageUnchanged', 'archiveSha256', 'runtimeMeasurementsRepeated', 'historicalProfileModified']);
  const started = canonicalInstant(scanRefresh.startedAt), completed = canonicalInstant(scanRefresh.completedAt);
  const approved = canonicalInstant(revision.approvedAt), expires = canonicalInstant(revision.expiresAt);
  const updated = receiverDatabaseInstant(UpdatedAt), next = receiverDatabaseInstant(NextUpdate);
  const downloaded = receiverDatabaseInstant(DownloadedAt);
  if (scanRefresh.version !== 1 || scanRefresh.kind !== 'same-image-scan-refresh' ||
      scanRefresh.previousProfileSha256 !== hash(original) ||
      scanRefresh.previousRefreshSha256 !== (priorRefresh === undefined ? null : hash(priorRefresh)) ||
      scanRefresh.archiveSha256 !== (priorRefresh?.archiveSha256 ?? null) ||
      scanRefresh.imageUnchanged !== true || scanRefresh.runtimeMeasurementsRepeated !== false ||
      scanRefresh.historicalProfileModified !== false || completed < started || completed - started > 3600000 ||
      completed > approved || updated > started || updated <= receiverDatabaseInstant(oldScan.databaseUpdatedAt) ||
      next <= receiverDatabaseInstant(oldScan.databaseNextUpdate) || downloaded < updated || downloaded > completed ||
      next <= completed || at < updated || at >= next || expires > next) fail('PRIVATE_IMAGE_SCAN_REFRESH_INVALID');
  // The full profile validator owns severity/count/provenance checks; a refreshed report
  // additionally cannot carry a conflicting content-addressed image identity.
  const report = JSON.parse(scan.reportJson);
  const scanned = scanReportInstant(report.CreatedAt);
  if (scanned < started || scanned > completed) fail('PRIVATE_IMAGE_SCAN_REPORT_TIME_INVALID');
  if (report.Metadata?.ImageID !== undefined && report.Metadata.ImageID !== profile.configDigest ||
      typeof report.ArtifactName === 'string' && report.ArtifactName.startsWith('sha256:') &&
        report.ArtifactName !== profile.manifestDigest) fail('PRIVATE_IMAGE_SCAN_TARGET_CHANGED');
  return revision.sourceSha256;
}
export function verifyRuntimeReview(c, context, value, at) {
  closed(value, ['policyRevision', 'costReview', 'costEvidence',
    ...(Object.hasOwn(value ?? {}, 'imageProfileRevision') ? ['imageProfileRevision'] : [])]);
  const source = verifyPrivateLinkPolicyRevision(c, context, value.policyRevision, at);
  verifyPrivateLinkCostReview(c, context, value.costReview, value.costEvidence, source, at);
  if (Object.hasOwn(value, 'imageProfileRevision')) {
    imageRevisionReview(c, context, value.imageProfileRevision, source, at);
    if (value.policyRevision) equal(value.imageProfileRevision.publication, value.policyRevision.publication, 'PRIVATE_IMAGE_REVISION_SOURCE_CHANGED');
  }
  return source;
}
function runtimeReviewTime(runtimeReview) {
  return Math.max(canonicalInstant(runtimeReview.costReview.approvedAt),
    runtimeReview.policyRevision === null ? 0 : canonicalInstant(runtimeReview.policyRevision.approvedAt),
    runtimeReview.imageProfileRevision === undefined ? 0 : canonicalInstant(runtimeReview.imageProfileRevision.approvedAt));
}
function runtimeBinding(c, context, evidence, candidate, runtimeReview = null) {
  closed(context, ['plan', 'origin']);
  if (candidate?.version !== 2) fail('PRIVATE_RUNTIME_QUEUED_CANDIDATE_REQUIRED');
  if (runtimeReview !== null) verifyRuntimeReview(c, context, runtimeReview, runtimeReviewTime(runtimeReview));
  planCandidate(c, context, candidate, runtimeReview);
  return { version: 1, configSha256: hash(c), planSha256: hash(context.plan), originSha256: hash(context.origin),
    controlEvidenceSha256: hash(evidence), candidateSha256: hash(candidate),
    ...(runtimeReview === null ? {} : { runtimeReview: structuredClone(runtimeReview) }) };
}
function planCandidate(c, context, candidate, runtimeReview = null, at) {
  equal(candidate.priorCandidate, context.origin.receiver.candidate, 'PRIVATE_PLAN_PRIOR_CANDIDATE_CHANGED');
  if (runtimeReview?.imageProfileRevision !== undefined) {
    const checkedAt = at ?? runtimeReviewTime(runtimeReview);
    verifyRuntimeReview(c, context, runtimeReview, checkedAt);
    verifyImageProfileRevision(c, context, candidate.profile, runtimeReview.imageProfileRevision, checkedAt);
  } else equal(candidate.profile, context.origin.queueProfile, 'PRIVATE_PLAN_QUEUE_PROFILE_CHANGED');
}
export function privateRuntimeIncarnation(app) {
  const creation = privateLinkAcaCreationIdentity(app, app?.id);
  return { appId: app.id.toLowerCase(), createdAt: creation.createdAt, identity: creation };
}
export function privateWindowFence(intent) {
  return { version: 1, kind: 'private-app-window-pending-head', physicalKey: intent.physicalKey,
    windowInstanceId: intent.binding.instanceId, intentSha256: hash(intent), outcome: 'pending-no-enable-retry' };
}
function samePreimage(c, target, candidate, expected, actual, identities) {
  if (expected === null) {
    if (actual !== null) fail('PRIVATE_RUNTIME_PREIMAGE_CHANGED');
    return;
  }
  equal(privateRuntimeIncarnation(actual), privateRuntimeIncarnation(expected), 'PRIVATE_PREIMAGE_GENERATION_CHANGED');
  if (actual.properties.latestRevisionName !== expected.properties.latestRevisionName) fail('PRIVATE_PREIMAGE_REVISION_CHANGED');
  equal(verifyPrivateLinkApp(c, target, candidate, actual, identities, admissionFlag(expected)),
    verifyPrivateLinkApp(c, target, candidate, expected, identities, admissionFlag(expected)), 'PRIVATE_RUNTIME_PREIMAGE_CHANGED');
}
function freshImage(c, candidate, at) {
  verifyReceiverCandidate(c, candidate);
  if (receiverDatabaseInstant(candidate.profile.scan.databaseUpdatedAt) > at ||
      receiverDatabaseInstant(candidate.profile.scan.databaseNextUpdate) <= at) fail('PRIVATE_IMAGE_SCAN_EXPIRED');
}
async function fileDigest(filename, expectedSize = null) {
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true }), named = await lstat(filename, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || !named.isFile() || named.isSymbolicLink() ||
        before.dev !== named.dev || before.ino !== named.ino ||
        before.size > 1024n * 1024n * 1024n || expectedSize !== null && before.size !== BigInt(expectedSize)) fail('PRIVATE_IMAGE_FILE_INVALID');
    const sum = createHash('sha256'), buffer = Buffer.alloc(65536);
    let size = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (!bytesRead) break;
      size += bytesRead;
      if (size > Number(before.size)) fail('PRIVATE_IMAGE_FILE_CHANGED');
      sum.update(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true }), current = await lstat(filename, { bigint: true });
    if (BigInt(size) !== before.size || ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'nlink'].some(key =>
      before[key] !== after[key] || after[key] !== current[key]) || current.isSymbolicLink()) fail('PRIVATE_IMAGE_FILE_CHANGED');
    return sum.digest('hex');
  } finally { await handle.close(); }
}

// All production effects have concrete defaults. Tests replace the narrow effect ports, not validators.
export async function privateLinkRuntimeIO(c, context, evidence, directory, options = {}) {
  const now = options.now ?? Date.now, invoke = options.invoke ?? az, run = options.run ?? execute;
  const control = options.control ?? await import('./private-link-controller.mjs');
  const readSource = options.sourceDigest ?? sourceDigest, lookup = options.lookup ?? publishedSourceDigest;
  const pendingReads = new Set();
  const admittedRead = async (work, until, limit) => {
    deadline(now, until);
    // Queue wait consumes the absolute stage budget, not a timeout computed before admission.
    const value = await work(Math.min(limit, until - now()));
    deadline(now, until);
    return value;
  };
  let limitedReads = limitReadConcurrency(admittedRead);
  const readJobs = (work, until, limit) => {
    const pending = limitedReads(work, until, limit);
    pendingReads.add(pending);
    pending.then(() => pendingReads.delete(pending), () => pendingReads.delete(pending));
    return pending;
  };
  const mutation = args => args[0] === 'rest' && args[args.indexOf('--method') + 1] !== 'GET';
  const readCall = (args, until, limit = 15000) => readJobs(
    timeout => invoke(args, timeout), until, Math.min(limit,
      args.includes('--url') && args[args.indexOf('--url') + 1]?.startsWith('https://api.loganalytics.azure.com/') ? 30000 : 15000));
  const call = async (args, until, limit = 15000) => {
    if (!mutation(args)) return readCall(args, until, limit);
    // Effects stay directly after their synchronous dispatch guards, never behind the read queue.
    deadline(now, until);
    const value = await invoke(args, Math.min(15000, limit, until - now()));
    deadline(now, until);
    return value;
  };
  const current = async until => {
    deadline(now, until);
    if (options.runtimeReview) verifyRuntimeReview(c, context, options.runtimeReview, now());
    const proof = await control.currentPrivateLinkRuntimeProof(c, context, evidence, directory, (args, timeout) => {
      if (mutation(args)) fail('PRIVATE_CURRENT_READ_ONLY_REQUIRED');
      return readCall(args, until, timeout);
    },
      { now, deadline: until, sourceDigest: readSource, lookup,
        policyRevision: options.runtimeReview?.policyRevision ?? options.policyRevision,
        costReview: options.runtimeReview?.costReview, costEvidence: options.runtimeReview?.costEvidence });
    if (proof.sourceSha256 !== await readSource() ||
        proof.planSha256 !== (context.plan.planSha256 ?? hash(context.plan)) ||
        proof.headSha256 !== hash(proof.head) || proof.prerequisites?.controlHeadSha256 !== proof.headSha256 ||
        canonicalInstant(proof.checkedAt) > now() || now() - canonicalInstant(proof.checkedAt) > 120000) fail('PRIVATE_CURRENT_PROOF_CHANGED');
    if (options.runtimeReview) {
      verifyRuntimeReview(c, context, options.runtimeReview, now());
      equal(proof.policyRevision, options.runtimeReview.policyRevision, 'PRIVATE_CURRENT_REVIEW_CHANGED');
      equal(proof.billingReview, options.runtimeReview.costReview, 'PRIVATE_CURRENT_REVIEW_CHANGED');
      equal(proof.costEvidence, options.runtimeReview.costEvidence, 'PRIVATE_CURRENT_REVIEW_CHANGED');
    }
    deadline(now, until);
    return proof;
  };
  const read = (id, api, until) => call(['rest', '--method', 'GET', '--url',
    `https://management.azure.com${id}?api-version=${api}`, '--subscription', c.subscriptionId,
    '--only-show-errors', '--output', 'json'], until);
  const identities = async until => Object.fromEntries(await Promise.all([ids(c).ingestIdentity, ids(c).pullIdentity]
    .map(async id => [id, await read(id, '2023-01-31', until)])));
  return { now, sleep: options.sleep ?? sleep, sourceDigest: readSource, lookup, current, read, call, identities, run,
    beginRecoveryReads: async until => {
      deadline(now, until);
      // Preserve fail-stop for the failed phase. A false-only/read-only recovery starts a new
      // read epoch only after all admitted and rejected jobs settle; it cannot exceed four.
      while (pendingReads.size) {
        await Promise.allSettled([...pendingReads]);
        deadline(now, until);
      }
      deadline(now, until);
      limitedReads = limitReadConcurrency(admittedRead);
    },
    verifyPrerequisites: (at = now()) => control.verifyPrivateLinkRuntimePrerequisites(c, context, evidence, at),
    published: async (approval, frozen = false) => {
      if (!sha(approval?.sourceSha256) || !/^[a-f0-9]{40}$/u.test(approval?.policyCommitSha ?? '')) fail('PRIVATE_RUNTIME_UNPUBLISHED_SOURCE');
      if (await lookup(approval.policyCommitSha) !== approval.sourceSha256) fail('PRIVATE_RUNTIME_UNPUBLISHED_SOURCE');
      if (frozen) return;
      const result = await run('git', ['rev-parse', 'HEAD'], { timeout: 10000, maxBuffer: 1024 });
      if (result.stdout.trim() !== approval.policyCommitSha || await readSource() !== approval.sourceSha256) fail('PRIVATE_RUNTIME_SOURCE_CHANGED');
    },
    verifySource: candidate => verifyReceiverSource(candidate, options.sourceRun ?? run, lookup),
    load: name => loadPrivateLinkArtifact(directory, name, true),
    immutable: (name, value) => savePrivateLinkArtifact(directory, name, value),
    save: (name, value) => updatePrivateLinkArtifact(directory, name, value),
    reserve: async (kind, key, value) => {
      if (!['image', 'receiver', 'window', 'recovery', 'public-probe', 'public-cleanup'].includes(kind) || !sha(key)) fail('PRIVATE_RUNTIME_FENCE_INVALID');
      try { await saveImmutable(privateRoot, `private-link-runtime-${kind}-${key}.json`, value); }
      catch (error) { if (error.code === 'EEXIST') fail('PRIVATE_RUNTIME_PHYSICAL_FENCE_NO_RETRY'); throw error; }
    },
    windowHead: intent => load(privateRoot, `private-link-runtime-window-${intent.physicalKey}.json`, true),
    inventory: async (candidate, until, published) => {
      const registry = await read(ids(c).registry, '2023-07-01', until);
      if (!sameId(registry?.id, ids(c).registry) || registry.properties?.adminUserEnabled !== false ||
          registry.properties?.anonymousPullEnabled !== false || registry.properties?.loginServer !== `${c.registryName}.azurecr.io`) fail('PRIVATE_REGISTRY_AUTH_CHANGED');
      const commands = [['repository', 'list', '--name', c.registryName],
        ['manifest', 'list-metadata', '--registry', c.registryName, '--name', repository]];
      const [repositories, manifests] = await Promise.all(commands.map(args =>
        call(['acr', ...args, '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], until)));
      const expected = [candidate.legacyPublication.release.manifestDigest, candidate.priorCandidate.profile.manifestDigest,
        ...(published ? [candidate.profile.manifestDigest] : [])];
      if (!Array.isArray(manifests) || manifests.length !== expected.length ||
          manifests.some(entry => !expected.includes(entry.digest))) fail('PRIVATE_IMAGE_INVENTORY_CHANGED');
      const referrers = [];
      for (const image of expected) referrers.push(...emptyAcrReferrers(await call(['acr', 'manifest', 'list-referrers',
        '--registry', c.registryName, '--name', `${repository}@${image}`, '--subscription', c.subscriptionId,
        '--only-show-errors', '--output', 'json'], until)));
      const inventory = { repositories, manifests, referrers };
      verifyReceiverInventory(c, candidate, inventory, published);
      return inventory;
    },
    deploy: async (request, guard, until, check, intent) => {
      if (typeof guard !== 'function' || types.isAsyncFunction(guard) ||
          typeof check !== 'function' || typeof intent !== 'function') fail('PRIVATE_RUNTIME_DISPATCH_PROTOCOL_REQUIRED');
      const name = `private-runtime-body-${randomUUID()}.json`;
      await saveImmutable(directory, name, request.body);
      try {
        await check(until);
        deadline(now, until);
        if (guard() !== undefined) fail('PRIVATE_RUNTIME_SYNC_GUARD_REQUIRED');
        const effectUntil = await intent();
        deadline(now, effectUntil);
        if (guard() !== undefined) fail('PRIVATE_RUNTIME_SYNC_GUARD_REQUIRED');
        return await call(['rest', '--method', 'PUT', '--url',
          `https://management.azure.com${request.id}?api-version=2022-09-01`, '--subscription', c.subscriptionId,
          '--body', '@' + join(directory, name), '--headers', 'Content-Type=application/json',
          '--only-show-errors', '--output', 'json'], effectUntil);
      } finally { await rm(join(directory, name)); }
    },
    deletePublic: async (target, guard, until, check, intent) => {
      if (target.appId !== `${ids(c).group}/providers/Microsoft.App/containerApps/${c.namePrefix}-public-probe` ||
          typeof check !== 'function' || typeof intent !== 'function' || typeof guard !== 'function' || types.isAsyncFunction(guard)) {
        fail('PRIVATE_PUBLIC_DELETE_SCOPE');
      }
      await check(until); deadline(now, until); guard();
      const end = await intent(); deadline(now, end); guard();
      return call(['rest', '--method', 'DELETE', '--url', `https://management.azure.com${target.appId}?api-version=${appApi}`,
        '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], end);
    },
    preview: async (phase, until) => {
      const name = `private-runtime-preview-${randomUUID()}.json`;
      await saveImmutable(directory, name, phase.request.body.properties.template);
      try {
        const args = ['deployment', 'group', '--subscription', c.subscriptionId, '--resource-group', `${c.namePrefix}-telemetry`,
          '--name', phase.request.id.split('/').at(-1), '--template-file', join(directory, name), '--only-show-errors', '--output', 'json'];
        const validation = await call([...args.slice(0, 2), 'validate', ...args.slice(2)], until);
        const whatIf = await asyncWhatIf(c, phase, directory, { now, deadline: until,
          request: operation => readJobs(timeout => (options.whatIfRequest ?? (request =>
            authenticatedWhatIfRequest(whatIfRequestContext(c, phase), directory, request)))(
          { ...operation, timeoutMs: timeout, deadlineMs: Math.min(until, operation.deadlineMs) }), until, operation.timeoutMs) });
        return { validation, whatIf: whatIf.result };
      } finally { await rm(join(directory, name)); }
    },
    observe: async (target, until) => {
      const [app, revisions, identityValues, diagnostic, exports, oldApp] = await Promise.all([
        read(target.appId, appApi, until), read(`${target.appId}/revisions`, appApi, until), identities(until),
        read(`${target.appId}/providers/Microsoft.Insights/diagnosticSettings`, '2021-05-01-preview', until),
        read(`${ids(c).workspace}/dataExports`, '2020-08-01', until), read(ids(c).app, appApi, until),
      ]);
      return { app, revisions, identities: identityValues, privacy: { diagnostic, exports }, oldApp, observedAt: iso(now()) };
    },
    http: syntheticHttp,
    query: (workspace, source, start, end, guard, until) =>
      readSyntheticQuery(c, workspace, source, start, end, guard, until, (args, timeout) => readJobs(async remaining => {
        guard();
        const value = await invoke(args, Math.min(remaining, timeout));
        guard();
        return value;
      }, until, args[args.indexOf('--url') + 1]?.startsWith('https://management.azure.com/') ? 15000 : 30000), readSource, now),
    probe: async (target, observation, candidate, prerequisite, transportReview, until, beforeDispatch, mode = 'private') =>
      runPrivateLinkProbe(c, target, observation, candidate, prerequisite, transportReview,
        { now, call, read, run, current, directory }, until, beforeDispatch, mode),
  };
}

export async function publishPrivateLinkImage(c, context, evidence, candidate, approval, local, directory, options = {}) {
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const binding = runtimeBinding(c, context, evidence, candidate, options.runtimeReview ?? null);
  closed(local, ['orasPath', 'orasSha256', 'layoutPath']);
  if (![local.orasPath, local.layoutPath].every(isAbsolute) || !sha(local.orasSha256)) fail('PRIVATE_UPLOADER_PIN_REQUIRED');
  const bound = { ...binding, local };
  const until = Math.min(io.now() + PRIVATE_RUNTIME_LIMITS.publicationMs, canonicalInstant(approval.expiresAt));
  const guard = () => {
    planCandidate(c, context, candidate, options.runtimeReview ?? null, io.now());
    review(approval, 'private-link-publish-one-queued-image', bound, io.now());
    verifyReceiverCandidate(c, candidate, io.now(), false);
    if (candidate.review.sourceSha256 !== approval.sourceSha256 ||
        candidate.review.policyCommitSha !== approval.policyCommitSha) fail('PRIVATE_PUBLICATION_POLICY_CHANGED');
    deadline(io.now, until);
  };
  guard(); io.verifyPrerequisites();
  if (await io.load('private-image-intent.json') || await io.load('private-image-result.json')) fail('PRIVATE_IMAGE_HISTORY_NO_RETRY');
  await io.published(approval); await io.verifySource(candidate);
  const profile = candidate.profile, manifest = JSON.parse(profile.manifestJson);
  if (await fileDigest(local.orasPath) !== local.orasSha256) fail('PRIVATE_UPLOADER_CHANGED');
  for (const entry of [{ digest: profile.manifestDigest, size: Buffer.byteLength(profile.manifestJson) }, manifest.config, ...manifest.layers]) {
    if (await fileDigest(join(local.layoutPath, 'blobs', 'sha256', entry.digest.slice(7)), entry.size) !== entry.digest.slice(7)) fail('PRIVATE_LOCAL_IMAGE_CHANGED');
  }
  const before = await io.inventory(candidate, until, false);
  await io.immutable('private-image-before.json', before);
  let authDirectory, completed, intentAt, copies = 0, failure = null, cleanup = false;
  const registry = `${c.registryName}.azurecr.io`;
  try {
    guard();
    const endpoint = (await io.run('docker', ['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
      { timeout: Math.min(10000, until - io.now()), maxBuffer: 4096 })).stdout.trim();
    guard();
    if (!/^unix:\/\/\/[^\r\n]+$/u.test(endpoint)) fail('PRIVATE_LOCAL_DOCKER_REQUIRED');
    authDirectory = await mkdtemp(join(directory, 'image-auth-'));
    await chmod(authDirectory, 0o700);
    await saveImmutable(authDirectory, 'config.json', { auths: { [registry]: {} }, credsStore: '', credHelpers: { [registry]: '' } });
    const env = { ...process.env, DOCKER_CONFIG: authDirectory,
      AZURE_CORE_COLLECT_TELEMETRY: 'false', AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no' };
    for (const key of ['DOCKER_CONTEXT', 'DOCKER_AUTH_CONFIG', 'REGISTRY_AUTH_FILE', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
      'http_proxy', 'https_proxy', 'all_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
      'NODE_TLS_REJECT_UNAUTHORIZED', 'AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', 'PYTHONHTTPSVERIFY']) delete env[key];
    const command = async (file, args, maxBuffer = 65536) => {
      guard();
      const result = await io.run(file, args, { env, timeout: Math.min(120000, until - io.now()), maxBuffer });
      guard();
      return result.stdout;
    };
    env.DOCKER_HOST = endpoint;
    await command('az', ['acr', 'login', '--name', c.registryName, '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'none']);
    const authPath = join(authDirectory, 'config.json');
    await chmod(authPath, 0o600);
    const auth = await load(authDirectory, 'config.json');
    if (!isDeepStrictEqual(Object.keys(auth.auths ?? {}), [registry]) || auth.credsStore ||
        Object.values(auth.credHelpers ?? {}).some(Boolean)) fail('PRIVATE_REGISTRY_CREDENTIAL_SCOPE');
    const authArgs = ['--registry-config', authPath];
    if ((await command(local.orasPath, ['repo', 'ls', ...authArgs, registry])).trim() !== repository) fail('PRIVATE_IMAGE_REPOSITORY_CHANGED');
    await io.inventory(candidate, until, false);
    const current = await io.current(until);
    await io.published(approval);
    intentAt = iso(io.now());
    await io.reserve('image', hash({ registry: ids(c).registry, image: profile.manifestDigest }),
      { version: 1, bindingSha256: hash(bound), approvalSha256: hash(approval), intentAt, outcome: 'copy-possible' });
    await io.immutable('private-image-intent.json', { version: 1, bindingSha256: hash(bound), approvalSha256: hash(approval),
      controlProofSha256: hash(current), intentAt, outcome: 'copy-possible', maximumCopyInvocations: 1 });
    await io.published(approval);
    await io.current(until);
    guard();
    copies = 1;
    await command(local.orasPath, ['copy', '--from-oci-layout', '--concurrency', '2', '--to-registry-config', authPath,
      `${local.layoutPath}@${profile.manifestDigest}`, `${registry}/${repository}:${candidate.review.tag}`]);
    const after = await io.inventory(candidate, until, true);
    for (const prior of [candidate.legacyPublication.release.manifestDigest, candidate.priorCandidate.profile.manifestDigest]) {
      const bytes = await command(local.orasPath, ['manifest', 'fetch', ...authArgs, `${registry}/${repository}@${prior}`]);
      if ('sha256:' + digest(bytes) !== prior) fail('PRIVATE_PRIOR_IMAGE_CHANGED');
    }
    const manifestJson = await command(local.orasPath, ['manifest', 'fetch', ...authArgs, `${registry}/${repository}@${profile.manifestDigest}`]);
    if (manifestJson !== profile.manifestJson) fail('PRIVATE_REMOTE_MANIFEST_CHANGED');
    const remote = await mkdtemp(join(directory, 'image-readback-'));
    try {
      for (const entry of [manifest.config, ...manifest.layers]) {
        const file = join(remote, entry.digest.slice(7));
        await command(local.orasPath, ['blob', 'fetch', ...authArgs, '--output', file, `${registry}/${repository}@${entry.digest}`], 4096);
        await chmod(file, 0o600);
        if (await fileDigest(file, entry.size) !== entry.digest.slice(7)) fail('PRIVATE_REMOTE_BLOB_CHANGED');
      }
      const configJson = await readFile(join(remote, profile.configDigest.slice(7)), 'utf8');
      if (configJson !== profile.configJson) fail('PRIVATE_REMOTE_CONFIG_CHANGED');
      completed = { version: 1, kind: 'single-copy-readback', profileSha256: hash(profile), reviewSha256: hash(candidate.review),
        configSha256: hash(c), intentAt, completedAt: iso(io.now()), copyInvocations: copies, manifestJson, configJson,
        ...after, remoteBlobs: [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size })),
        sourceArchiveSha256: profile.source.archiveSha256, sourceManifestSha256: profile.source.manifestSha256,
        noticesSha256: profile.notices.sha256, credentialDirectoriesRemoved: false };
    } finally { await rm(remote, { recursive: true }); }
  } catch (error) { failure = safeOperationFailure(error).code; }
  finally {
    if (authDirectory) {
      try { await rm(authDirectory, { recursive: true }); cleanup = true; }
      catch { failure = 'PRIVATE_CREDENTIAL_CLEANUP_UNCONFIRMED'; }
    } else cleanup = true;
  }
  if (completed && !failure && cleanup) {
    completed.credentialDirectoriesRemoved = true;
    verifyReceiverCandidate(c, { ...candidate, publication: completed });
    await io.immutable('private-image-publication.json', completed);
  }
  const result = { version: 1, kind: 'private-link-image-result', bindingSha256: hash(bound), copyInvocations: copies,
    outcome: completed && !failure ? 'published-readback-qualified' : 'held-no-automatic-retry',
    failureCode: failure, credentialDirectoriesRemoved: cleanup, completedAt: iso(io.now()) };
  await io.immutable('private-image-result.json', result);
  if (result.outcome !== 'published-readback-qualified') fail('PRIVATE_IMAGE_PUBLICATION_HELD');
  return { ...candidate, publication: completed };
}

export function privateLinkRuntimeTarget(c, context, candidate, prerequisites, runtimeReview = null) {
  verifyReceiverCandidate(c, candidate);
  planCandidate(c, context, candidate, runtimeReview);
  const n = context.plan.topology?.ids ?? context.plan.ids;
  const stage = context.plan.stages?.find(value => value.id === 'create-disabled-receiver');
  if (!n || !stage?.resources?.length || stage.resources.length !== 1) fail('PRIVATE_REPLACEMENT_DESCRIPTOR_REQUIRED');
  const descriptor = structuredClone(stage.resources[0]);
  const container = descriptor.expected.properties.template.containers[0];
  if (!sameId(descriptor.id, n.app) || !sameId(descriptor.expected.properties.managedEnvironmentId, n.environment) ||
      sameId(n.app, ids(c).app) || sameId(n.environment, ids(c).environment) ||
      !sameId(prerequisites.environment.id, n.environment) ||
      container.image !== `${c.registryName}.azurecr.io/${repository}@${candidate.profile.manifestDigest}` ||
      admissionFlag(descriptor.expected) !== 'false') fail('PRIVATE_REPLACEMENT_TARGET_CHANGED');
  const env = Object.fromEntries(container.env.map(value => [value.name, value.value]));
  for (const [name, value] of Object.entries(queueEnvironment(candidate.topology))) if (env[name] !== value) fail('PRIVATE_QUEUE_RUNTIME_CHANGED');
  const domain = prerequisites.environment.properties?.defaultDomain;
  if (!/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(domain ?? '')) fail('PRIVATE_ENVIRONMENT_FQDN_REQUIRED');
  return { version: 1, appId: n.app, environmentId: n.environment, fqdn: `${descriptor.expected.name}.${domain}`, descriptor,
    queueHost: new URL(candidate.topology.ids.queueUrl).hostname, privateIp: prerequisites.privateIp };
}

// Project only the explicitly checked target coordinates, then reuse the existing full runtime validator.
export function verifyPrivateLinkApp(c, target, candidate, actual, identities, flag, preview = false) {
  if (preview) {
    actual = structuredClone(actual);
    actual.id ??= target.appId;
    actual.properties.configuration.ingress.fqdn ??= target.fqdn;
    for (const [id, value] of Object.entries(actual.identity?.userAssignedIdentities ?? {})) {
      if (value && Object.keys(value).length === 0) {
        const identity = Object.entries(identities).find(([key]) => sameId(key, id))?.[1];
        if (!identity) fail('PRIVATE_PREVIEW_IDENTITY_CHANGED');
        actual.identity.userAssignedIdentities[id] = { clientId: identity.properties.clientId, principalId: identity.properties.principalId };
      }
    }
  }
  if (!sameId(actual?.id, target.appId) || actual?.name !== target.descriptor.expected.name ||
      !sameId(actual.properties?.managedEnvironmentId ?? actual.properties?.environmentId, target.environmentId) ||
      actual.properties?.configuration?.ingress?.fqdn !== target.fqdn || admissionFlag(actual) !== flag) fail('PRIVATE_RUNTIME_TARGET_DRIFT');
  const descriptor = structuredClone(target.descriptor), projected = structuredClone(actual);
  for (const value of [descriptor.expected, projected]) {
    value.name = `${c.namePrefix}-ingest`;
    value.properties.managedEnvironmentId = ids(c).environment;
    if (value.properties.environmentId !== undefined) value.properties.environmentId = ids(c).environment;
  }
  descriptor.id = ids(c).app; projected.id = ids(c).app;
  descriptor.expected.properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value = flag;
  return canonicalAppWrite(c, descriptor, projected, { identities, receiverCandidate: candidate });
}

function verifyObservation(c, target, candidate, observation, flag, requireReady = true) {
  closed(observation, ['app', 'revisions', 'identities', 'privacy', 'oldApp', 'observedAt']);
  canonicalInstant(observation.observedAt);
  verifyPrivateLinkApp(c, target, candidate, observation.app, observation.identities, flag);
  if (admissionFlag(observation.oldApp) !== 'false' || !sameId(observation.oldApp.id, ids(c).app)) fail('PRIVATE_OLD_RECEIVER_CHANGED');
  closed(observation.privacy, ['diagnostic', 'exports']);
  for (const value of Object.values(observation.privacy)) if (!Array.isArray(value?.value) || value.nextLink || value.value.length) fail('PRIVATE_RUNTIME_PRIVACY_DRIFT');
  if (!requireReady) return;
  const app = observation.app, revisions = observation.revisions;
  if (!Array.isArray(revisions?.value) || revisions.nextLink) fail('PRIVATE_REVISIONS_INCOMPLETE');
  const active = revisions.value.filter(value => value.properties?.active === true), name = app.properties.latestRevisionName;
  if (active.length !== 1 || active[0].name !== name || !sameId(active[0].id, `${target.appId}/revisions/${name}`) ||
      app.properties.latestReadyRevisionName !== name || app.properties.provisioningState !== 'Succeeded' ||
      app.properties.runningStatus !== 'Running' || active[0].properties.provisioningState !== 'Provisioned' ||
      active[0].properties.healthState !== 'Healthy' || !['Running', 'RunningAtMaxScale'].includes(active[0].properties.runningState) ||
      active[0].properties.replicas !== 1 || active[0].properties.trafficWeight !== 100) fail('PRIVATE_REVISION_NOT_READY');
  const replica = structuredClone(app);
  replica.properties.template = structuredClone(active[0].properties.template);
  if (replica.properties.template.revisionSuffix === null) delete replica.properties.template.revisionSuffix;
  for (const key of ['cooldownPeriod', 'pollingInterval']) if (replica.properties.template.scale[key] === null) delete replica.properties.template.scale[key];
  equal(verifyPrivateLinkApp(c, target, candidate, replica, observation.identities, flag),
    verifyPrivateLinkApp(c, target, candidate, app, observation.identities, flag), 'PRIVATE_REVISION_TEMPLATE_CHANGED');
}

export function privateRuntimePhase(c, target, instanceId, action, predecessorSha256) {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(instanceId) ||
      !['create-disabled', 'enable', 'disable', 'create-public-probe'].includes(action) || !sha(predecessorSha256)) fail('PRIVATE_RUNTIME_PHASE_INVALID');
  const publicProbe = action === 'create-public-probe';
  if (target.appId !== `${ids(c).group}/providers/Microsoft.App/containerApps/${c.namePrefix}-${publicProbe ? 'public-probe' : 'private-ingest'}` ||
      target.environmentId !== (publicProbe ? ids(c).environment : `${ids(c).group}/providers/Microsoft.App/managedEnvironments/${c.namePrefix}-private-environment`)) fail('PRIVATE_RUNTIME_PHASE_TARGET');
  const resource = structuredClone(target.descriptor.expected);
  resource.properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value = action === 'enable' ? 'true' : 'false';
  const id = `${ids(c).group}/providers/Microsoft.Resources/deployments/${c.namePrefix}-plr-${instanceId.replaceAll('-', '')}-${publicProbe ? 'p' : action === 'create-disabled' ? 'c' : action === 'enable' ? 'e' : 'd'}`;
  return { version: 1, kind: 'fixed-private-link-runtime-phase', phase: `private-link-runtime-${action}`,
    action, windowInstanceId: instanceId, predecessorSha256, targetSha256: hash(target),
    request: { id, body: { properties: { mode: 'Incremental',
    template: { $schema: 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#',
      contentVersion: '1.0.0.0', resources: [resource] } } } } };
}

export function verifyPrivateRuntimePreview(target, phase, preview, before, preserved, runtime) {
  if (!Array.isArray(preserved) || preserved.some(id => typeof id !== 'string')) fail('PRIVATE_RUNTIME_PRESERVED_INVENTORY_REQUIRED');
  if (preview.validation?.properties?.provisioningState !== 'Succeeded' || preview.validation.error ||
      preview.validation.properties.error || preview.validation.properties.errors?.length ||
      preview.validation.errors?.length || preview.validation.nextLink ||
      preview.whatIf?.status !== 'Succeeded' || preview.whatIf.error || preview.whatIf.nextLink ||
      preview.whatIf.properties?.error || preview.whatIf.properties?.nextLink ||
      !Array.isArray(preview.whatIf.changes)) fail('PRIVATE_RUNTIME_PREVIEW_REQUIRED');
  const seen = new Set(), changes = [];
  for (const change of preview.whatIf.changes) {
    if (typeof change.resourceId !== 'string' || seen.has(change.resourceId.toLowerCase()) ||
        change.error || change.nextLink) fail('PRIVATE_RUNTIME_PREVIEW_SCOPE');
    seen.add(change.resourceId.toLowerCase());
    if (['NoChange', 'Ignore'].includes(change.changeType) && preserved.some(id => sameId(id, change.resourceId))) continue;
    changes.push(change);
  }
  const create = ['create-disabled', 'create-public-probe'].includes(phase.action);
  if (changes.length !== 1 || !sameId(changes[0].resourceId, target.appId) ||
      changes[0].changeType !== (create ? 'Create' : 'Modify')) fail('PRIVATE_RUNTIME_PREVIEW_SCOPE');
  if (create ? before !== null : !before || admissionFlag(before) !== (phase.action === 'enable' ? 'false' : 'true')) {
    fail('PRIVATE_RUNTIME_PREIMAGE_CHANGED');
  }
  if (before !== null) {
    const returned = changes[0].before;
    equal(verifyPrivateLinkApp(runtime.c, target, runtime.candidate, returned, runtime.identities, admissionFlag(before), true),
      verifyPrivateLinkApp(runtime.c, target, runtime.candidate, before, runtime.identities, admissionFlag(before)), 'PRIVATE_WHATIF_PREIMAGE_CHANGED');
    if (returned.properties.latestRevisionName !== undefined && returned.properties.latestRevisionName !== before.properties.latestRevisionName) {
      fail('PRIVATE_WHATIF_PREIMAGE_CHANGED');
    }
    if (returned.systemData !== undefined) equal(privateRuntimeIncarnation(returned), privateRuntimeIncarnation(before), 'PRIVATE_WHATIF_PREIMAGE_CHANGED');
  } else if (changes[0].before !== undefined && changes[0].before !== null) fail('PRIVATE_WHATIF_PREIMAGE_CHANGED');
  const after = changes[0].after;
  const wanted = phase.request.body.properties.template.resources[0];
  const flag = phase.action === 'enable' ? 'true' : 'false';
  equal(verifyPrivateLinkApp(runtime.c, target, runtime.candidate, after, runtime.identities, flag, true),
    verifyPrivateLinkApp(runtime.c, target, runtime.candidate, wanted, runtime.identities, flag, true),
    'PRIVATE_RUNTIME_PREVIEW_CHANGED');
}

async function ready(c, target, candidate, io, flag, until) {
  let last;
  for (let index = 0; index < PRIVATE_RUNTIME_LIMITS.maxRolloutPolls; index++) {
    deadline(io.now, until);
    last = await io.observe(target, until);
    deadline(io.now, until);
    try { verifyObservation(c, target, candidate, last, flag); return last; }
    catch (error) {
      if (!['PRIVATE_REVISION_NOT_READY', 'PRIVATE_RUNTIME_TARGET_DRIFT'].includes(error.message)) throw error;
      // A mismatched desired flag is allowed only while the exact fixed deployment rolls out.
      if (last.app && admissionFlag(last.app) === flag) verifyPrivateLinkApp(c, target, candidate, last.app, last.identities, flag);
    }
    await io.sleep(Math.min(3000, Math.max(0, until - io.now())));
  }
  fail('PRIVATE_RUNTIME_ROLLOUT_UNQUALIFIED');
}

export async function createPrivateLinkReceiver(c, context, evidence, candidate, instanceId, approval, directory, options = {}) {
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  freshImage(c, candidate, io.now());
  const prerequisites = io.verifyPrerequisites(), target = privateLinkRuntimeTarget(c, context, candidate, prerequisites, options.runtimeReview ?? null);
  const phase = privateRuntimePhase(c, target, instanceId, 'create-disabled', hash(evidence));
  const binding = { ...runtimeBinding(c, context, evidence, candidate, options.runtimeReview ?? null), targetSha256: hash(target), phaseSha256: hash(phase) };
  const cap = canonicalInstant(approval.expiresAt);
  const guard = () => { review(approval, 'private-link-create-disabled-receiver', binding, io.now()); freshImage(c, candidate, io.now()); };
  guard();
  if (await io.load('private-receiver-intent.json')) fail('PRIVATE_RECEIVER_HISTORY_NO_RETRY');
  await io.published(approval); await io.verifySource(candidate);
  guard();
  await io.inventory(candidate, stageDeadline(io, cap), true); guard();
  const current = await io.current(stageDeadline(io, cap)); guard();
  const before = await io.read(target.appId, appApi, stageDeadline(io, cap));
  const preview = await io.preview(phase, stageDeadline(io, cap)); guard();
  verifyPrivateRuntimePreview(target, phase, preview, before, current.preservedResourceIds,
    { c, candidate, identities: { [ids(c).ingestIdentity]: prerequisites.identity, [ids(c).pullIdentity]: prerequisites.pullIdentity } });
  await io.immutable('private-receiver-preview.json', { binding, current, before, preview });
  let receipt, intent, effectUntil;
  try {
    await io.deploy(phase.request, guard, stageDeadline(io, cap), async until => {
      await io.current(until); await io.published(approval); guard();
      samePreimage(c, target, candidate, null, await io.read(target.appId, appApi, until), {});
      deadline(io.now, until); guard();
    }, async () => {
      guard();
      effectUntil = stageDeadline(io, cap);
      intent = { version: 2, kind: 'private-link-receiver-create-intent', binding, target, candidate, phase, approval,
        controlEvidence: evidence, intentAt: iso(io.now()), effectDeadline: effectUntil, outcome: 'write-possible' };
      await io.immutable('private-receiver-intent.json', intent);
      await io.reserve('receiver', hash({ app: target.appId.toLowerCase() }), { version: 1, intentSha256: hash(intent), outcome: 'create-possible' });
      return effectUntil;
    });
    const observation = await ready(c, target, candidate, io, 'false', effectUntil);
    const response = await io.http(target.fqdn, 'POST', '/v1/events', SYNTHETIC_FIXTURES[0],
      () => deadline(io.now, effectUntil), Math.min(effectUntil, io.now() + 1000));
    deadline(io.now, effectUntil); guard();
    verifyHttp(response, 503);
    receipt = { version: 1, kind: 'private-link-disabled-receiver', binding, target, phase, approval, controlEvidence: evidence,
      candidate, observation, disabledResponse: response, intent, completedAt: iso(io.now()), ingestionEnabled: false };
    await io.immutable('private-receiver-receipt.json', receipt);
  } catch (error) {
    await io.immutable('private-receiver-failure.json', { version: 1, binding, failure: safeOperationFailure(error),
      intentSha256: intent ? hash(intent) : null, outcome: 'held-readback-required-no-retry', observedAt: iso(io.now()) });
    throw error;
  }
  return receipt;
}

function verifyHttp(response, status) {
  if (response?.status !== status || response.errorCode !== null || response.tlsVerified !== true ||
      response.bodyBytes !== 0 || response.headerPolicy?.noStore !== true ||
      !Number.isFinite(response.durationMs) || response.durationMs < 0 || response.durationMs > 1000) fail('PRIVATE_HTTP_UNQUALIFIED_NO_RETRY');
}

function verifyDisabledReceiver(c, context, evidence, candidate, record) {
  if (record?.kind === 'private-link-reconciled-disabled-receiver') {
    closed(record, ['version', 'kind', 'intent', 'target', 'candidate', 'controlEvidence', 'observation', 'deployment', 'operations',
      'reconciliationId', 'completedAt', 'originalFailure', 'ingestionEnabled', 'creationAnchor']);
    verifyCreateIntent(c, context, evidence, record.intent);
    equal(record.candidate, candidate, 'PRIVATE_CANDIDATE_CHANGED');
    equal(record.target, record.intent.target, 'PRIVATE_RUNTIME_TARGET_CHANGED');
    equal(record.controlEvidence, evidence, 'PRIVATE_CONTROL_EVIDENCE_CHANGED');
    verifyCreationDeployment(record.intent, record.deployment, record.operations, record.observation.app, record.completedAt);
    verifyCreationAnchor(record.intent, record.creationAnchor, record.observation.app);
    verifyObservation(c, record.target, candidate, record.observation, 'false');
    if (record.version !== 1 || record.ingestionEnabled !== false || !uuid(record.reconciliationId) ||
        canonicalInstant(record.completedAt) < canonicalInstant(record.intent.intentAt)) fail('PRIVATE_RECONCILIATION_RECORD_CHANGED');
    return;
  }
  closed(record, ['version', 'kind', 'binding', 'target', 'phase', 'approval', 'controlEvidence', 'candidate',
    'observation', 'disabledResponse', 'intent', 'completedAt', 'ingestionEnabled']);
  if (record.version !== 1 || record.kind !== 'private-link-disabled-receiver' || record.ingestionEnabled !== false ||
      record.binding.configSha256 !== hash(c) || record.binding.planSha256 !== hash(context.plan) ||
      record.binding.controlEvidenceSha256 !== hash(evidence) || record.binding.candidateSha256 !== hash(candidate) ||
      record.binding.targetSha256 !== hash(record.target) || record.binding.phaseSha256 !== hash(record.phase)) fail('PRIVATE_DISABLED_RECORD_CHANGED');
  equal(record.controlEvidence, evidence, 'PRIVATE_CONTROL_EVIDENCE_CHANGED');
  equal(record.candidate, candidate, 'PRIVATE_CANDIDATE_CHANGED');
  verifyCreateIntent(c, context, evidence, record.intent);
  equal(record.intent.binding, record.binding, 'PRIVATE_CREATE_INTENT_CHANGED');
  equal(record.intent.phase, record.phase, 'PRIVATE_CREATE_INTENT_CHANGED');
  equal(record.intent.approval, record.approval, 'PRIVATE_CREATE_INTENT_CHANGED');
  if (canonicalInstant(record.completedAt) > record.intent.effectDeadline) fail('PRIVATE_CREATE_RECEIPT_LATE');
  verifyReceiverCandidate(c, candidate);
  verifyObservation(c, record.target, candidate, record.observation, 'false');
  verifyHttp(record.disabledResponse, 503);
}

export function verifyCreateIntent(c, context, evidence, intent) {
  closed(intent, ['version', 'kind', 'binding', 'target', 'candidate', 'phase', 'approval',
    'controlEvidence', 'intentAt', 'effectDeadline', 'outcome']);
  if (intent.version !== 2 || intent.kind !== 'private-link-receiver-create-intent' || intent.outcome !== 'write-possible') fail('PRIVATE_CREATE_INTENT_CHANGED');
  equal(intent.controlEvidence, evidence, 'PRIVATE_CONTROL_EVIDENCE_CHANGED');
  planCandidate(c, context, intent.candidate, intent.binding.runtimeReview ?? null, canonicalInstant(intent.intentAt));
  const phase = privateRuntimePhase(c, intent.target, intent.phase.windowInstanceId, 'create-disabled', hash(evidence));
  equal(intent.phase, phase, 'PRIVATE_CREATE_PHASE_CHANGED');
  const binding = { ...runtimeBinding(c, context, evidence, intent.candidate, intent.binding.runtimeReview ?? null), targetSha256: hash(intent.target), phaseSha256: hash(phase) };
  equal(intent.binding, binding, 'PRIVATE_CREATE_BINDING_CHANGED');
  const start = canonicalInstant(intent.intentAt);
  review(intent.approval, 'private-link-create-disabled-receiver', binding, start);
  freshImage(c, intent.candidate, start);
  if (!Number.isSafeInteger(intent.effectDeadline) || intent.effectDeadline <= start ||
      intent.effectDeadline > Math.min(start + 120000, canonicalInstant(intent.approval.expiresAt))) fail('PRIVATE_CREATE_DEADLINE_CHANGED');
}
export function verifyCreationDeployment(intent, deployment, operations, app, observedAt) {
  const p = deployment?.properties;
  if (!sameId(deployment?.id, intent.phase.request.id) || p?.provisioningState !== 'Succeeded' || p.mode !== 'Incremental' ||
      queueArmInstant(p.timestamp) < queueArmInstant(intent.intentAt) || queueArmInstant(p.timestamp) > queueArmInstant(observedAt) ||
      !Array.isArray(operations?.value) || operations.nextLink || operations.value.length < 1 || operations.value.length > 64) fail('PRIVATE_CREATION_DEPLOYMENT_UNPROVEN');
  const writes = operations.value.filter(value => ['Create', 'Write', 'Update', 'Delete'].includes(value.properties?.provisioningOperation));
  if (writes.length !== 1 || writes[0].properties.provisioningOperation !== 'Create' ||
      writes[0].properties.provisioningState !== 'Succeeded' ||
      !sameId(writes[0].properties.targetResource?.id, intent.target.appId) ||
      !sameId(app?.id, intent.target.appId)) fail('PRIVATE_CREATION_OPERATION_UNPROVEN');
  privateRuntimeIncarnation(app);
}
function verifyCreationAnchor(intent, anchor, app) {
  closed(anchor, ['version', 'kind', 'intentSha256', 'incarnation', 'observedAt']);
  if (anchor.version !== 1 || anchor.kind !== 'private-receiver-first-observed-generation' ||
      anchor.intentSha256 !== hash(intent) || canonicalInstant(anchor.observedAt) < canonicalInstant(intent.intentAt)) fail('PRIVATE_CREATION_ANCHOR_CHANGED');
  equal(anchor.incarnation, privateRuntimeIncarnation(app), 'PRIVATE_CREATION_GENERATION_CHANGED');
}
export async function reconcilePrivateLinkReceiver(c, context, evidence, reconciliationId, directory, options = {}) {
  if (!uuid(reconciliationId)) fail('PRIVATE_RECONCILIATION_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const intent = await io.load('private-receiver-intent.json');
  verifyCreateIntent(c, context, evidence, intent);
  await io.published(intent.approval, true);
  const until = io.now() + 120000;
  const [deployment, operations, observation] = await Promise.all([
    io.read(intent.phase.request.id, '2022-09-01', until),
    io.read(`${intent.phase.request.id}/operations`, '2022-09-01', until),
    io.observe(intent.target, until),
  ]);
  deadline(io.now, until);
  verifyObservation(c, intent.target, intent.candidate, observation, 'false');
  verifyCreationDeployment(intent, deployment, operations, observation.app, iso(io.now()));
  let creationAnchor = await io.load('private-receiver-creation-observation.json');
  if (creationAnchor) verifyCreationAnchor(intent, creationAnchor, observation.app);
  else {
    const original = await io.load('private-receiver-receipt.json');
    if (original) {
      equal(original.intent, intent, 'PRIVATE_CREATION_ANCHOR_CHANGED');
      equal(privateRuntimeIncarnation(original.observation.app), privateRuntimeIncarnation(observation.app), 'PRIVATE_CREATION_GENERATION_CHANGED');
    }
    creationAnchor = { version: 1, kind: 'private-receiver-first-observed-generation', intentSha256: hash(intent),
      incarnation: privateRuntimeIncarnation(observation.app), observedAt: iso(io.now()) };
    await io.immutable('private-receiver-creation-observation.json', creationAnchor);
  }
  await io.published(intent.approval, true); deadline(io.now, until);
  const record = { version: 1, kind: 'private-link-reconciled-disabled-receiver', intent, target: intent.target,
    candidate: intent.candidate, controlEvidence: evidence, observation, deployment, operations, reconciliationId,
    completedAt: iso(io.now()), originalFailure: await io.load('private-receiver-failure.json'), ingestionEnabled: false, creationAnchor };
  deadline(io.now, until);
  await io.immutable(`private-receiver-reconciliation-${reconciliationId}.json`, record);
  return record;
}

function windowBinding(c, context, evidence, candidate, disabled, instanceId, transport, runtimeReview = null) {
  return { ...runtimeBinding(c, context, evidence, candidate, runtimeReview), disabledRecordSha256: hash(disabled),
    instanceId, targetSha256: hash(disabled.target), transportSha256: hash(transport),
    publicTargetSha256: hash(publicControlTarget(c, disabled.target, context, evidence)),
    limits: PRIVATE_RUNTIME_LIMITS, runtime: QUEUE_RUNTIME };
}

// The source is streamed only after a fixed short bootstrap validates its byte count and SHA-256.
export function privateQueueProbeCode(expected) {
  closed(expected, ['clientId', 'principalId', 'tenantId', 'queueUrl', 'privateIp', 'enabled', 'mode']);
  if (!/^[a-f0-9-]{36}$/u.test(expected.clientId) || !/^[a-f0-9-]{36}$/u.test(expected.tenantId) ||
      !/^[a-f0-9-]{36}$/u.test(expected.principalId) || !['private', 'public-deny'].includes(expected.mode) ||
      !/^https:\/\/msrtq[a-z0-9]{8,16}\.queue\.core\.windows\.net\/telemetry-events-v1$/u.test(expected.queueUrl) ||
      !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(expected.privateIp) || !['true', 'false'].includes(expected.enabled)) fail('PRIVATE_PROBE_BINDING_INVALID');
  return `(${async function (pin) {
    const fs = require('node:fs'), dns = require('node:dns').promises, http = require('node:http'), https = require('node:https');
    const start = performance.now();
    const report = { version: 1, kind: 'same-container-private-queue-metadata', queueHost: new URL(pin.queueUrl).hostname,
      nodeVersion: process.versions.node,
      privateIp: pin.privateIp, clientId: pin.clientId, principalId: pin.principalId, mode: pin.mode,
      dnsPrivate: false, dnsPublic: false, tlsVerified: false, remotePrivate: false, remotePublic: false,
      tokenIdentityMatched: false, metadataStatus: null, storageErrorCode: null,
      tokenRequests: 0, metadataRequests: 0, enqueues: 0, elapsedMs: 0, failureCode: null };
    const isPublic = ip => {
      if (!/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(ip)) return false;
      const [a, b, c] = ip.split('.').map(Number);
      return ip.split('.').every(v => Number(v) <= 255) && a > 0 && a < 224 && a !== 10 && a !== 127 &&
        !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && b === 168) &&
        !(a === 100 && b >= 64 && b <= 127) && !(a === 192 && b === 0 && [0, 2].includes(c)) &&
        !(a === 198 && [18, 19].includes(b)) && !(a === 198 && b === 51 && c === 100) &&
        !(a === 203 && b === 0 && c === 113);
    };
    let finished = false, active;
    const finish = code => {
      if (finished) return;
      finished = true; clearTimeout(timer); active?.destroy();
      report.failureCode = code; report.elapsedMs = Math.round(performance.now() - start);
      fs.writeSync(1, JSON.stringify(report) + '\n');
      process.exit(code === null ? 0 : 1);
    };
    const timer = setTimeout(() => finish('PROBE_DEADLINE'), 25000);
    process.stdout.write = () => true; process.stderr.write = () => true;
    process.on('uncaughtException', () => finish('PROBE_FAILED'));
    process.on('unhandledRejection', () => finish('PROBE_FAILED'));
    const request = (url, headers, privateTls = false) => new Promise((resolve, reject) => {
      let verified = false, bytes = 0, chunks = [];
      active = (url.protocol === 'https:' ? https : http).request(url, {
        method: 'GET', headers, agent: false, rejectUnauthorized: true, maxHeaderSize: 8192,
      }, response => {
        response.on('data', data => {
          bytes += data.length;
          if (bytes > 32768) { response.destroy(); reject(new Error('bound')); } else chunks.push(data);
        });
        response.once('error', reject);
        response.once('end', () => {
          if (privateTls && !verified) return reject(new Error('tls'));
          const error = response.headers['x-ms-error-code'];
          report.storageErrorCode = ['AuthorizationFailure', 'AuthenticationFailed', 'AuthorizationPermissionMismatch',
            'InvalidAuthenticationInfo'].includes(error) ? error : error ? 'unclassified' : null;
          resolve({ status: response.statusCode, body: Buffer.concat(chunks) });
        });
      });
      active.once('socket', socket => socket.once('secureConnect', () => {
        if (!privateTls) return;
        report.tlsVerified = socket.authorized === true;
        report.remotePrivate = socket.remoteAddress === pin.privateIp || socket.remoteAddress === '::ffff:' + pin.privateIp;
        report.remotePublic = isPublic(socket.remoteAddress?.replace(/^::ffff:/u, '') ?? '');
        verified = report.tlsVerified && (pin.mode === 'private' ? report.remotePrivate : report.remotePublic);
        if (!verified) active.destroy(new Error('private-tls'));
      }));
      active.once('error', reject);
      active.setTimeout(privateTls ? 5000 : 20000, () => active.destroy(new Error('timeout')));
      active.end();
    });
    try {
      if (process.versions.node !== '24.21.0' || process.getuid() !== 65532 ||
          process.cwd() !== '/app/services/telemetry-ingest' || process.env.NODE_OPTIONS ||
          process.env.AZURE_CLIENT_ID !== pin.clientId || process.env.AZURE_TENANT_ID !== pin.tenantId ||
          process.env.AZURE_QUEUE_URL !== pin.queueUrl ||
          process.env.MSR_INGESTION_ENABLED !== pin.enabled) return finish('CONTEXT_CHANGED');
      const queue = new URL(pin.queueUrl);
      const addresses = await dns.lookup(queue.hostname, { all: true });
      report.dnsPrivate = addresses.length > 0 && addresses.every(value => value.address === pin.privateIp && value.family === 4);
      report.dnsPublic = addresses.length > 0 && addresses.every(value => value.family === 4 && isPublic(value.address));
      if (addresses.length > 8 || !(pin.mode === 'private' ? report.dnsPrivate : report.dnsPublic)) return finish('PRIVATE_DNS_UNPROVEN');
      const identity = new URL(process.env.IDENTITY_ENDPOINT);
      if (!['http:', 'https:'].includes(identity.protocol) || identity.username || identity.password || identity.search || identity.hash ||
          !['localhost', '127.0.0.1', '[::1]'].includes(identity.hostname) && !/^169\.254\.\d{1,3}\.\d{1,3}$/u.test(identity.hostname) ||
          typeof process.env.IDENTITY_HEADER !== 'string' || !process.env.IDENTITY_HEADER) return finish('IDENTITY_ENDPOINT_INVALID');
      identity.searchParams.set('api-version', '2019-08-01');
      identity.searchParams.set('resource', 'https://storage.azure.com');
      identity.searchParams.set('client_id', pin.clientId);
      report.tokenRequests++;
      const auth = await request(identity, { 'X-IDENTITY-HEADER': process.env.IDENTITY_HEADER, Connection: 'close' });
      if (auth.status !== 200) return finish('IDENTITY_UNAVAILABLE');
      let token = JSON.parse(auth.body.toString('utf8')).access_token;
      if (typeof token !== 'string' || token.length < 20 || token.length > 32768) return finish('IDENTITY_UNAVAILABLE');
      const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
      report.tokenIdentityMatched = claims.oid === pin.principalId && claims.tid === pin.tenantId &&
        ['https://storage.azure.com', 'https://storage.azure.com/'].includes(claims.aud) &&
        (claims.appid ?? claims.azp) === pin.clientId && Number.isSafeInteger(claims.exp) && claims.exp * 1000 > Date.now();
      if (!report.tokenIdentityMatched) return finish('IDENTITY_UNAVAILABLE');
      queue.searchParams.set('comp', 'metadata');
      report.metadataRequests++;
      const result = await request(queue, { Authorization: 'Bearer ' + token, 'x-ms-version': '2023-11-03',
        'x-ms-date': new Date().toUTCString(), Connection: 'close' }, true);
      token = null;
      report.metadataStatus = result.status;
      if (pin.mode === 'private' ? result.status !== 200 : result.status !== 403 ||
          report.storageErrorCode !== 'AuthorizationFailure') return finish('QUEUE_METADATA_UNAVAILABLE');
      finish(null);
    } catch { finish('PROBE_FAILED'); }
  }.toString()})(${JSON.stringify(expected)});`;
}

export function verifyPrivateQueueProbe(probe, target, identity, mode = 'private') {
  closed(probe, ['version', 'kind', 'nodeVersion', 'queueHost', 'privateIp', 'clientId', 'principalId', 'mode', 'dnsPrivate', 'dnsPublic',
    'tlsVerified', 'remotePrivate', 'remotePublic', 'tokenIdentityMatched', 'metadataStatus', 'storageErrorCode',
    'tokenRequests', 'metadataRequests', 'enqueues', 'elapsedMs', 'failureCode']);
  if (probe.version !== 1 || probe.kind !== 'same-container-private-queue-metadata' || probe.nodeVersion !== '24.21.0' || probe.queueHost !== target.queueHost ||
      probe.privateIp !== target.privateIp || probe.clientId !== identity.properties.clientId ||
      probe.principalId !== identity.properties.principalId || probe.mode !== mode || probe.tokenIdentityMatched !== true ||
      probe.tlsVerified !== true ||
      (mode === 'private' ? probe.dnsPrivate !== true || probe.remotePrivate !== true || probe.metadataStatus !== 200 ||
        probe.storageErrorCode !== null : probe.dnsPublic !== true || probe.remotePublic !== true ||
        probe.dnsPrivate !== false || probe.remotePrivate !== false || probe.metadataStatus !== 403 ||
        probe.storageErrorCode !== 'AuthorizationFailure') ||
      probe.tokenRequests !== 1 || probe.metadataRequests !== 1 || probe.enqueues !== 0 || probe.failureCode !== null ||
      !Number.isSafeInteger(probe.elapsedMs) || probe.elapsedMs < 0 || probe.elapsedMs > 25000) fail('PRIVATE_QUEUE_ROUTE_UNQUALIFIED');
}

export function privateLinkExecEndpoint(c, target, revision, replica) {
  const app = target.appId.split('/').at(-1);
  if (![`${c.namePrefix}-public-probe`, `${c.namePrefix}-private-ingest`].includes(app) ||
      ![revision, replica].every(value => typeof value === 'string' && /^[a-z0-9-]{1,128}$/u.test(value))) fail('PRIVATE_EXEC_TARGET_INVALID');
  return `wss://australiaeast.azurecontainerapps.dev/subscriptions/${c.subscriptionId}/resourceGroups/${c.namePrefix}-telemetry/containerApps/${app}/revisions/${revision}/replicas/${replica}/containers/telemetry-ingest/exec`;
}

export function privateProbeProgram(c, prerequisites, mode) {
  const payload = privateQueueProbeCode({ clientId: prerequisites.identity.properties.clientId,
    principalId: prerequisites.identity.properties.principalId, tenantId: c.tenantId,
    queueUrl: prerequisites.queueTopology.ids.queueUrl, privateIp: prerequisites.privateIp, enabled: 'false', mode });
  const bytes = Buffer.byteLength(payload), checksum = digest(payload);
  const bootstrap = `(()=>{const f=require('node:fs'),h=require('node:crypto');let b=Buffer.alloc(0);const t=setTimeout(()=>process.exit(2),3500);if(process.stdin.isTTY)process.stdin.setRawMode(true);process.stdin.on('data',c=>{b=Buffer.concat([b,c]);if(b.length>${bytes})process.exit(2);if(b.length===${bytes}){if(h.createHash('sha256').update(b).digest('hex')!=='${checksum}')process.exit(2);clearTimeout(t);process.stdin.removeAllListeners('data');process.stdin.pause();require('node:vm').runInThisContext(b.toString('utf8'))}});f.writeSync(1,'MSP_PRIVATE_READY\\n')})()`;
  const command = `/usr/local/bin/node --no-turbofan --no-maglev --disable-sigusr1 --max-old-space-size=64 --eval "${bootstrap}"`;
  return { payload, command, payloadSha256: checksum, commandSha256: digest(command) };
}
function probeReplica(c, target, app, replicas) {
  if (!Array.isArray(replicas?.value) || replicas.nextLink || replicas.value.length !== 1) fail('PRIVATE_SINGLE_REPLICA_REQUIRED');
  const replica = replicas.value[0], containers = replica.properties?.containers;
  if (!/^[a-z0-9-]{1,128}$/u.test(replica.name ?? '') || containers?.length !== 1 || containers[0].name !== 'telemetry-ingest' ||
      containers[0].ready !== true || containers[0].started !== true || containers[0].runningState !== 'Running' ||
      !Number.isSafeInteger(containers[0].restartCount) || containers[0].restartCount < 0 ||
      containers[0].execEndpoint !== privateLinkExecEndpoint(c, target, app.properties.latestRevisionName, replica.name)) fail('PRIVATE_REPLICA_NOT_READY');
  return { replica: replica.name, restartCount: containers[0].restartCount, endpoint: containers[0].execEndpoint };
}
export function verifyPrivateProbeEvidence(c, target, candidate, identityValues, probe, original, cap) {
  closed(probe, ['version', 'kind', 'sessions', 'payloadFrames', 'sessionClosed', 'result', 'appId', 'revision', 'replica',
    'imageDigest', 'restartCount', 'payloadSha256', 'commandSha256', 'before', 'after', 'processStartedAt', 'processCompletedAt', 'observedAt']);
  if (probe.version !== 1 || probe.kind !== 'bounded-private-queue-exec' || probe.sessions !== 1 ||
      probe.payloadFrames !== 1 || probe.sessionClosed !== true || !sameId(probe.appId, target.appId) ||
      probe.imageDigest !== candidate.profile.manifestDigest) fail('PRIVATE_PROBE_BINDING_CHANGED');
  const mode = probe.result.mode, identity = identityValues[ids(c).ingestIdentity];
  verifyPrivateQueueProbe(probe.result, target, identity, mode);
  const program = privateProbeProgram(c, { identity, queueTopology: { ids: { queueUrl: `https://${target.queueHost}/telemetry-events-v1` } },
    privateIp: target.privateIp }, mode);
  equal([probe.payloadSha256, probe.commandSha256], [program.payloadSha256, program.commandSha256], 'PRIVATE_PROBE_CODE_CHANGED');
  const start = canonicalInstant(probe.processStartedAt), end = canonicalInstant(probe.processCompletedAt), observed = canonicalInstant(probe.observedAt);
  if (end < start || end - start > 30000 || observed < end || observed > cap) fail('PRIVATE_PROBE_TIME_CHANGED');
  for (const [side, anchor] of [[probe.before, start], [probe.after, observed]]) {
    closed(side, ['app', 'replicas', 'observedAt', 'control']);
    closed(side.control, ['sourceSha256', 'headSha256', 'checkedAt']);
    const at = canonicalInstant(side.observedAt), checked = canonicalInstant(side.control.checkedAt);
    if (at > anchor || anchor - at > 120000 || checked > observed || observed - checked > 360000 ||
        !sha(side.control.sourceSha256) || !sha(side.control.headSha256)) fail('PRIVATE_PROBE_OBSERVATION_STALE');
    verifyPrivateLinkApp(c, target, candidate, side.app, identityValues, 'false');
    equal(privateRuntimeIncarnation(side.app), privateRuntimeIncarnation(original), 'PRIVATE_PROBE_INCARNATION_CHANGED');
    if (side.app.properties.latestRevisionName !== probe.revision || original.properties.latestRevisionName !== probe.revision) fail('PRIVATE_PROBE_REVISION_CHANGED');
    equal(probeReplica(c, target, side.app, side.replicas), {
      replica: probe.replica, restartCount: probe.restartCount, endpoint: privateLinkExecEndpoint(c, target, probe.revision, probe.replica),
    }, 'PRIVATE_PROBE_REPLICA_CHANGED');
  }
  equal(probe.before.control.headSha256, probe.after.control.headSha256, 'PRIVATE_PROBE_HEAD_CHANGED');
  equal(probe.before.control.sourceSha256, probe.after.control.sourceSha256, 'PRIVATE_PROBE_SOURCE_CHANGED');
  if (canonicalInstant(probe.after.observedAt) < end) fail('PRIVATE_PROBE_TIME_CHANGED');
  freshImage(c, candidate, start);
}
export async function runPrivateLinkProbe(c, target, observation, candidate, prerequisites, transportReview, io, cap, beforeDispatch, mode = 'private') {
  closed(transportReview, ['pythonPath', 'pythonSha256', 'bridgeSha256']);
  if (!isAbsolute(transportReview.pythonPath) || !sha(transportReview.pythonSha256) || !sha(transportReview.bridgeSha256)) fail('PRIVATE_PROBE_TRANSPORT_PIN_REQUIRED');
  if (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch)) fail('PRIVATE_PROBE_GUARD_REQUIRED');
  const guard = () => { beforeDispatch(); deadline(io.now, cap); freshImage(c, candidate, io.now()); };
  const bridge = fileURLToPath(new URL('./private-link-exec.py', import.meta.url));
  if (await fileDigest(bridge) !== transportReview.bridgeSha256 ||
      await fileDigest(transportReview.pythonPath) !== transportReview.pythonSha256) fail('PRIVATE_PROBE_TRANSPORT_CHANGED');
  guard();
  verifyObservation(c, target, candidate, observation, 'false');
  const proof = await io.current(stageDeadline(io, cap)); guard();
  const app = await io.read(target.appId, appApi, stageDeadline(io, cap));
  samePreimage(c, target, candidate, observation.app, app, observation.identities); guard();
  const revision = app.properties.latestRevisionName;
  const replicas = await io.read(`${target.appId}/revisions/${revision}/replicas`, appApi, stageDeadline(io, cap)); guard();
  const selected = probeReplica(c, target, app, replicas);
  const control = value => ({ sourceSha256: value.sourceSha256, headSha256: value.headSha256, checkedAt: value.checkedAt });
  const before = { app, replicas, observedAt: iso(io.now()), control: control(proof) };
  const program = privateProbeProgram(c, prerequisites, mode);
  const auth = await io.call(['rest', '--method', 'POST', '--url', `https://management.azure.com${target.appId}/getAuthToken?api-version=${appApi}`,
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], stageDeadline(io, cap, 10000), 10000);
  guard();
  const token = auth?.properties?.token;
  if (typeof token !== 'string' || token.length < 20 || token.length > 32768) fail('PRIVATE_EXEC_TOKEN_UNAVAILABLE');
  const processStartedAt = iso(io.now()), processUntil = stageDeadline(io, cap, 30000);
  const request = { version: 1, endpoint: selected.endpoint, token, command: program.command, payload: program.payload,
    payloadSha256: program.payloadSha256, remainingMs: processUntil - io.now() };
  const invocation = io.run(transportReview.pythonPath, ['-I', bridge], {
    timeout: request.remainingMs, maxBuffer: 4096, env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
      !/proxy|token|secret|password|azure_cli_disable_connection|requests_ca_bundle|curl_ca_bundle|ssl_cert/i.test(name))),
  });
  if (!invocation.child?.stdin) fail('PRIVATE_EXEC_STDIN_TRANSPORT_REQUIRED');
  invocation.child.stdin.end(JSON.stringify(request));
  let output;
  try { output = JSON.parse((await invocation).stdout); } catch { fail('PRIVATE_EXEC_TRANSPORT_UNCONFIRMED'); }
  deadline(io.now, processUntil); guard();
  const processCompletedAt = iso(io.now());
  closed(output, ['version', 'kind', 'sessions', 'payloadFrames', 'sessionClosed', 'result']);
  if (output.version !== 1 || output.kind !== 'bounded-private-queue-exec' || output.sessions !== 1 ||
      output.payloadFrames !== 1 || output.sessionClosed !== true) fail('PRIVATE_EXEC_TRANSPORT_UNCONFIRMED');
  verifyPrivateQueueProbe(output.result, target, prerequisites.identity, mode);
  const afterProof = await io.current(stageDeadline(io, cap)); guard();
  const afterApp = await io.read(target.appId, appApi, stageDeadline(io, cap)); guard();
  const afterReplicas = await io.read(`${target.appId}/revisions/${revision}/replicas`, appApi, stageDeadline(io, cap)); guard();
  const after = { app: afterApp, replicas: afterReplicas, observedAt: iso(io.now()), control: control(afterProof) };
  const result = { ...output, appId: target.appId, revision, replica: selected.replica, imageDigest: candidate.profile.manifestDigest,
    restartCount: selected.restartCount, payloadSha256: program.payloadSha256, commandSha256: program.commandSha256,
    before, after, processStartedAt, processCompletedAt, observedAt: iso(io.now()) };
  verifyPrivateProbeEvidence(c, target, candidate, observation.identities, result, observation.app, io.now());
  return result;
}

export async function qualifyPrivateLinkDelivery(c, context, evidence, candidate, disabled, instanceId, approvals, transport, directory, options = {}) {
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  freshImage(c, candidate, io.now());
  const prerequisites = io.verifyPrerequisites();
  verifyDisabledReceiver(c, context, evidence, candidate, disabled);
  const target = privateLinkRuntimeTarget(c, context, candidate, prerequisites, options.runtimeReview ?? null);
  equal(target, disabled.target, 'PRIVATE_RUNTIME_TARGET_CHANGED');
  const binding = windowBinding(c, context, evidence, candidate, disabled, instanceId, transport, options.runtimeReview ?? null);
  closed(approvals, ['enable', 'disable', 'publicCreate', 'publicDelete']);
  const phases = { enable: privateRuntimePhase(c, target, instanceId, 'enable', hash(disabled)),
    disable: privateRuntimePhase(c, target, instanceId, 'disable', hash(disabled)) };
  review(approvals.enable, 'private-link-bounded-enable', binding, io.now());
  review(approvals.disable, 'private-link-false-only-disable', binding, io.now());
  review(approvals.publicCreate, 'private-link-create-public-control', binding, io.now());
  review(approvals.publicDelete, 'private-link-delete-public-control', binding, io.now());
  if (await io.load('private-window-intent.json') || await io.load('private-window-result.json')) fail('PRIVATE_WINDOW_HISTORY_NO_RETRY');
  const approvalCap = canonicalInstant(approvals.enable.expiresAt);
  const reviewed = () => {
    review(approvals.enable, 'private-link-bounded-enable', binding, io.now());
    review(approvals.disable, 'private-link-false-only-disable', binding, io.now());
    freshImage(c, candidate, io.now());
  };
  for (const approval of Object.values(approvals)) await io.published(approval);
  await io.verifySource(candidate); reviewed();
  await io.inventory(candidate, stageDeadline(io, approvalCap), true); reviewed();
  const current = await io.current(stageDeadline(io, approvalCap)); reviewed();
  const initial = await io.observe(target, stageDeadline(io, approvalCap)); reviewed();
  verifyObservation(c, target, candidate, initial, 'false');
  const preview = await io.preview(phases.enable, stageDeadline(io, approvalCap)); reviewed();
  verifyPrivateRuntimePreview(target, phases.enable, preview, initial.app, current.preservedResourceIds,
    { c, candidate, identities: initial.identities });
  const disableBody = structuredClone(phases.disable.request);
  const publicTarget = publicControlTarget(c, target, context, evidence);
  if (prerequisites.oldEnvironment.properties.vnetConfiguration != null) fail('PRIVATE_PUBLIC_ENVIRONMENT_MUST_BE_NONVNET');
  const run = { version: 1, kind: 'private-link-runtime-completion', binding, approvals, disabled, candidate,
    controlEvidence: evidence, transport, target, publicTarget, phases, preflight: { current, initial, preview }, probe: null, publicProbe: null,
    requests: [], queries: [], drain: null, enableIntentAt: null, disable: null, failure: null,
    publicControl: null, publicCleanup: null,
    outcome: 'in-progress', terminalFalse: false, terminal503: false, enabledWindowExceeded: false, publicLifetimeExceeded: false, completedAt: null };
  const incarnation = privateRuntimeIncarnation(initial.app);
  const intent = { version: 3, kind: 'private-link-window-intent', contextSha256: hash(context), binding, approvals, phases,
    disabled, candidate, controlEvidence: evidence, transport, target, publicTarget, incarnation,
    physicalKey: hash({ appId: incarnation.appId, createdAt: incarnation.createdAt }), intentAt: iso(io.now()),
    rollbackRequest: disableBody,
    publicPhase: privateRuntimePhase(c, publicTarget, instanceId, 'create-public-probe', hash(disabled)),
    publicCleanupRequest: { method: 'DELETE', id: publicTarget.appId, apiVersion: appApi, body: null },
    outcome: 'probe-or-enable-possible-no-retry' };
  verifyWindowIntent(c, context, evidence, intent);
  await io.immutable('private-window-intent.json', intent);
  await io.reserve('window', intent.physicalKey, privateWindowFence(intent));
  run.intent = intent;
  let enabledAt = null, workUntil = approvalCap;
  const active = () => {
    deadline(io.now, workUntil);
    freshImage(c, candidate, io.now());
    review(approvals.enable, 'private-link-bounded-enable', binding, io.now());
  };
  const persist = () => io.save('private-window-progress.json', run);
  try {
    run.probe = await io.probe(target, initial, candidate, prerequisites, transport, approvalCap, active);
    active();
    run.publicControl = await createPublicControl(c, intent, io);
    workUntil = Math.min(workUntil, canonicalInstant(run.publicControl.intent.intentAt) + 900000 - 300000);
    const publicObservation = run.publicControl.observation;
    verifyObservation(c, publicTarget, candidate, publicObservation, 'false');
    run.publicProbe = await io.probe(publicTarget, publicObservation, candidate, prerequisites, transport,
      approvalCap, active, 'public-deny');
    verifyPrivateProbeEvidence(c, target, candidate, initial.identities, run.probe, initial.app, io.now());
    verifyPrivateProbeEvidence(c, publicTarget, candidate, publicObservation.identities,
      run.publicProbe, publicObservation.app, io.now());
    run.publicInitial = publicObservation;
    active();
    let effectUntil;
    await io.deploy(phases.enable.request, active, stageDeadline(io, approvalCap), async until => {
      await io.current(until); await io.published(approvals.enable); await io.published(approvals.disable); reviewed();
      await assertWindowHead(io, intent);
      const latest = await io.observe(target, until);
      verifyObservation(c, target, candidate, latest, 'false');
      samePreimage(c, target, candidate, initial.app, latest.app, latest.identities);
      if (canonicalInstant(approvals.disable.expiresAt) < io.now() + 780000) fail('PRIVATE_ROLLBACK_RESERVE_REQUIRED');
      if (canonicalInstant(approvals.publicDelete.expiresAt) < io.now() + 900000) fail('PRIVATE_PUBLIC_CLEANUP_RESERVE_REQUIRED');
      deadline(io.now, until); active();
    }, async () => {
      reviewed();
      enabledAt = io.now(); workUntil = Math.min(enabledAt + 420000, approvalCap,
        canonicalInstant(run.publicControl.intent.intentAt) + 900000 - 300000);
      effectUntil = stageDeadline(io, workUntil);
      run.enableIntentAt = iso(enabledAt);
      run.enableIntent = { version: 1, windowIntentSha256: hash(intent), phaseSha256: hash(phases.enable),
        intentAt: run.enableIntentAt, effectDeadline: effectUntil, outcome: 'enable-possible' };
      await io.immutable('private-enable-intent.json', run.enableIntent);
      await persist();
      return effectUntil;
    });
    const enabled = await ready(c, target, candidate, io, 'true', effectUntil);
    run.enabled = enabled; active();
    for (const fixture of SYNTHETIC_FIXTURES) {
      await io.current(Math.min(workUntil, io.now() + 120000)); await io.published(approvals.enable);
      active();
      const entry = { fixture, intentAt: iso(io.now()), dispatched: false, response: null };
      run.requests.push(entry); await persist(); active();
      const end = Math.min(workUntil, io.now() + 1000);
      entry.response = await io.http(target.fqdn, 'POST', '/v1/events', fixture, () => {
        active(); deadline(io.now, end); entry.dispatched = true;
      }, end);
      active(); await persist();
      verifyHttp(entry.response, 202);
    }
    const start = iso(enabledAt), end = iso(io.now());
    for (const wait of [15000, 60000, 180000]) {
      if (io.now() + wait >= workUntil) fail('PRIVATE_WINDOW_WORK_EXPIRED');
      await io.sleep(wait); active();
      await io.current(Math.min(workUntil, io.now() + 120000)); active();
      const queryDeadline = Math.min(workUntil, io.now() + 30000);
      const rows = await io.query(prerequisites.workspace, approvals.enable.sourceSha256, start, end, active, queryDeadline);
      active();
      const verification = verifySyntheticRows(rows, start, end);
      run.queries.push({ start, end, rows, verification }); await persist();
      if (verification.complete) {
        const queue = await io.read(candidate.topology.ids.queue, '2025-01-01', queryDeadline);
        active();
        const count = queue?.properties?.approximateMessageCount;
        if (!sameId(queue?.id, candidate.topology.ids.queue) || !Number.isSafeInteger(count) || count < 0) fail('PRIVATE_DRAIN_UNPROVEN');
        run.drain = { queueId: queue.id, approximateMessageCount: count, observedAt: iso(io.now()), approximate: true };
        if (count === 0) break;
      }
    }
    if (!run.drain || run.drain.approximateMessageCount !== 0) fail('PRIVATE_DELIVERY_OR_DRAIN_UNPROVEN');
  } catch (error) { run.failure = safeOperationFailure(error); }
  finally {
    // This path deliberately does not require healthy storage, a network probe, or an enable review.
    const disableUntil = Math.min(canonicalInstant(approvals.disable.expiresAt),
      Math.max((enabledAt ?? io.now()) + 600000, io.now() + 180000),
      run.publicControl ? Math.max(canonicalInstant(run.publicControl.intent.intentAt) + 900000 - 120000, io.now() + 180000) : Infinity);
    try {
      await persist();
    } catch { run.failure ??= { code: 'PRIVATE_PROGRESS_SAVE_FAILED' }; }
    try {
      run.disable = await falseOnlyDisable(c, context, intent, approvals.disable, binding, 'private-link-false-only-disable',
        'private-disable', io, disableUntil);
      run.terminalFalse = true; run.terminal503 = true;
    } catch (error) { run.disableFailure = safeOperationFailure(error); }
    try {
      run.publicCleanup = await cleanupPublicControl(c, intent, approvals.publicDelete, binding,
        'private-link-delete-public-control', 'private-public-delete', io,
        stageDeadline(io, Math.min(canonicalInstant(approvals.publicDelete.expiresAt),
          run.publicControl ? Math.max(canonicalInstant(run.publicControl.intent.intentAt) + 900000, io.now() + 180000) : Infinity), 180000));
    } catch (error) { run.publicCleanupFailure = safeOperationFailure(error); }
    run.completedAt = iso(io.now());
    run.enabledWindowExceeded = enabledAt !== null && (run.disable ? canonicalInstant(run.disable.completedAt) : io.now()) > enabledAt + 600000;
    if (run.enabledWindowExceeded) run.failure ??= { code: 'PRIVATE_ENABLED_WINDOW_EXCEEDED' };
    const publicCreated = run.publicControl?.intent ?? run.publicCleanup?.creation?.intent;
    run.publicLifetimeExceeded = publicCreated !== undefined && io.now() > canonicalInstant(publicCreated.intentAt) + 900000;
    if (run.publicLifetimeExceeded) run.failure ??= { code: 'PRIVATE_PUBLIC_LIFETIME_EXCEEDED' };
    run.outcome = !run.terminalFalse || !run.terminal503 || run.publicCleanup?.absent !== true ? 'held-terminal-state-unproven' :
      run.failure ? 'stopped-disabled-unqualified' : 'qualified-private-delivery-disabled';
    await io.immutable('private-window-result.json', run);
  }
  return run;
}

export function verifyWindowIntent(c, context, evidence, intent) {
  closed(intent, ['version', 'kind', 'contextSha256', 'binding', 'approvals', 'phases', 'disabled', 'candidate',
    'controlEvidence', 'transport', 'target', 'publicTarget', 'incarnation', 'physicalKey', 'intentAt', 'rollbackRequest',
    'publicPhase', 'publicCleanupRequest', 'outcome']);
  if (intent.version !== 3 || intent.kind !== 'private-link-window-intent' || intent.contextSha256 !== hash(context) ||
      intent.outcome !== 'probe-or-enable-possible-no-retry') fail('PRIVATE_WINDOW_INTENT_CHANGED');
  equal(intent.controlEvidence, evidence, 'PRIVATE_CONTROL_EVIDENCE_CHANGED');
  verifyDisabledReceiver(c, context, evidence, intent.candidate, intent.disabled);
  equal(intent.target, intent.disabled.target, 'PRIVATE_RUNTIME_TARGET_CHANGED');
  equal(intent.incarnation, privateRuntimeIncarnation(intent.disabled.observation.app), 'PRIVATE_WINDOW_INCARNATION_CHANGED');
  equal(intent.physicalKey, hash({ appId: intent.incarnation.appId, createdAt: intent.incarnation.createdAt }), 'PRIVATE_WINDOW_PHYSICAL_KEY_CHANGED');
  const binding = windowBinding(c, context, evidence, intent.candidate, intent.disabled, intent.binding.instanceId, intent.transport, intent.binding.runtimeReview ?? null);
  equal(intent.binding, binding, 'PRIVATE_WINDOW_BINDING_CHANGED');
  equal(intent.phases, {
    enable: privateRuntimePhase(c, intent.target, binding.instanceId, 'enable', hash(intent.disabled)),
    disable: privateRuntimePhase(c, intent.target, binding.instanceId, 'disable', hash(intent.disabled)),
  }, 'PRIVATE_WINDOW_PHASE_CHANGED');
  equal(intent.rollbackRequest, intent.phases.disable.request, 'PRIVATE_FROZEN_ROLLBACK_CHANGED');
  equal(intent.publicTarget, publicControlTarget(c, intent.target, context, evidence), 'PRIVATE_PUBLIC_TARGET_CHANGED');
  equal(intent.publicPhase, publicCreatePhase(c, intent), 'PRIVATE_PUBLIC_CREATE_PHASE_CHANGED');
  equal(intent.publicCleanupRequest, publicDeleteRequest(intent), 'PRIVATE_PUBLIC_DELETE_SCOPE');
  closed(intent.approvals, ['enable', 'disable', 'publicCreate', 'publicDelete']);
  const at = canonicalInstant(intent.intentAt);
  review(intent.approvals.enable, 'private-link-bounded-enable', binding, at);
  review(intent.approvals.disable, 'private-link-false-only-disable', binding, at);
  review(intent.approvals.publicCreate, 'private-link-create-public-control', binding, at);
  review(intent.approvals.publicDelete, 'private-link-delete-public-control', binding, at);
}
async function assertWindowHead(io, intent) {
  equal(await io.windowHead(intent), privateWindowFence(intent), 'PRIVATE_WINDOW_GLOBAL_HEAD_CHANGED');
}
async function falseOnlyDisable(c, context, original, approval, binding, action, prefix, io, cap) {
  const { target, candidate } = original;
  const guard = () => { deadline(io.now, cap); review(approval, action, binding, io.now()); };
  guard();
  await io.beginRecoveryReads?.(cap); guard();
  await io.published(original.approvals.enable, true);
  await io.published(original.approvals.disable, true);
  await io.published(approval, true); guard();
  await assertWindowHead(io, original); guard();
  const before = await io.observe(target, stageDeadline(io, cap)); guard();
  verifyPrivateLinkApp(c, target, candidate, before.app, before.identities, admissionFlag(before.app));
  equal(privateRuntimeIncarnation(before.app), original.incarnation, 'PRIVATE_ROLLBACK_INCARNATION_CHANGED');
  let effectUntil, intent;
  await io.deploy(original.rollbackRequest, guard, stageDeadline(io, cap), async until => {
    // Publication lookup and exact target checks remain mandatory; storage/network health is irrelevant.
    await io.published(original.approvals.enable, true); await io.published(original.approvals.disable, true);
    await io.published(approval, true); await assertWindowHead(io, original); guard();
    const latest = await io.observe(target, until);
    samePreimage(c, target, candidate, before.app, latest.app, latest.identities);
    deadline(io.now, until); guard();
  }, async () => {
    guard(); effectUntil = stageDeadline(io, cap);
    intent = { version: 1, originalIntentSha256: hash(original), approval, binding, action,
      request: original.rollbackRequest, intentAt: iso(io.now()), effectDeadline: effectUntil, outcome: 'false-write-possible' };
    await io.immutable(`${prefix}-intent.json`, intent);
    return effectUntil;
  });
  const terminal = await ready(c, target, candidate, io, 'false', effectUntil); guard();
  const oldTarget = oldPublicRuntimeTarget(c, { oldApp: context.origin.receiver.receipt.resources[ids(c).app],
    oldEnvironment: { id: ids(c).environment, properties: { vnetConfiguration: null } },
    oldReceiver: context.origin.receiver }, target);
  verifyPrivateLinkApp(c, oldTarget, candidate.priorCandidate, terminal.oldApp, terminal.identities, 'false');
  // The original receiver is not executed; its current shape must still match its retained disabled observation.
  equal(executionIdentity(terminal.oldApp, 'Microsoft.App/containerApps'),
    executionIdentity(original.disabled.observation.oldApp, 'Microsoft.App/containerApps'), 'PRIVATE_OLD_RECEIVER_GENERATION_CHANGED');
  if (admissionFlag(terminal.oldApp) !== 'false') fail('PRIVATE_OLD_TERMINAL_FALSE_REQUIRED');
  const response = await io.http(target.fqdn, 'POST', '/v1/events', SYNTHETIC_FIXTURES[0],
    () => { deadline(io.now, effectUntil); guard(); }, Math.min(effectUntil, io.now() + 1000));
  deadline(io.now, effectUntil); guard(); verifyHttp(response, 503);
  const result = { intent, observation: terminal, response, oldApp: terminal.oldApp, completedAt: iso(io.now()) };
  await io.immutable(`${prefix}-receipt.json`, result);
  return result;
}

export async function preparePrivateLinkDisableRecovery(c, context, evidence, recoveryId, directory, options = {}) {
  if (!uuid(recoveryId)) fail('PRIVATE_RECOVERY_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const intent = await io.load('private-window-intent.json');
  verifyWindowIntent(c, context, evidence, intent);
  await assertWindowHead(io, intent);
  await io.published(intent.approvals.enable, true); await io.published(intent.approvals.disable, true);
  const binding = { version: 1, kind: 'private-link-frozen-false-recovery-binding', recoveryId, physicalKey: intent.physicalKey,
    windowInstanceId: intent.binding.instanceId, originalIntentSha256: hash(intent), requestSha256: hash(intent.rollbackRequest),
    frozenDisableSource: { policyCommitSha: intent.approvals.disable.policyCommitSha, sourceSha256: intent.approvals.disable.sourceSha256 },
    configSha256: hash(c), contextSha256: hash(context) };
  const prepared = { version: 1, kind: 'private-link-disable-recovery-preparation', binding, bindingSha256: hash(binding),
    approvalAction: 'private-link-recover-frozen-false', executionAuthorized: false };
  await io.immutable(`private-recovery-${recoveryId}-preparation.json`, prepared);
  return prepared;
}

export async function recoverPrivateLinkDisabled(c, context, evidence, recoveryId, approval, directory, options = {}) {
  if (!uuid(recoveryId)) fail('PRIVATE_RECOVERY_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const intent = await io.load('private-window-intent.json');
  verifyWindowIntent(c, context, evidence, intent);
  const prepared = await io.load(`private-recovery-${recoveryId}-preparation.json`);
  closed(prepared, ['version', 'kind', 'binding', 'bindingSha256', 'approvalAction', 'executionAuthorized']);
  const binding = { version: 1, kind: 'private-link-frozen-false-recovery-binding', recoveryId, physicalKey: intent.physicalKey,
    windowInstanceId: intent.binding.instanceId, originalIntentSha256: hash(intent), requestSha256: hash(intent.rollbackRequest),
    frozenDisableSource: { policyCommitSha: intent.approvals.disable.policyCommitSha, sourceSha256: intent.approvals.disable.sourceSha256 },
    configSha256: hash(c), contextSha256: hash(context) };
  if (prepared.version !== 1 || prepared.kind !== 'private-link-disable-recovery-preparation' ||
      prepared.executionAuthorized !== false || prepared.bindingSha256 !== hash(binding) ||
      prepared.approvalAction !== 'private-link-recover-frozen-false') fail('PRIVATE_RECOVERY_PREPARATION_CHANGED');
  equal(prepared.binding, binding, 'PRIVATE_RECOVERY_BINDING_CHANGED');
  review(approval, prepared.approvalAction, binding, io.now());
  await io.published(approval, true); await assertWindowHead(io, intent);
  await io.reserve('recovery', hash({ physicalKey: intent.physicalKey, recoveryId }), {
    version: 1, originalIntentSha256: hash(intent), recoveryId, approvalSha256: hash(approval), outcome: 'false-recovery-possible' });
  const prefix = `private-recovery-${recoveryId}`, cap = stageDeadline(io, canonicalInstant(approval.expiresAt), 180000);
  let result;
  try {
    const receipt = await falseOnlyDisable(c, context, intent, approval, binding, prepared.approvalAction, prefix, io, cap);
    result = { version: 1, kind: 'private-link-false-only-recovery', recoveryId, originalIntentSha256: hash(intent),
      outcome: 'recovered-disabled-original-outcome-retained', receipt, failure: null, qualification: false, completedAt: iso(io.now()) };
  } catch (error) {
    result = { version: 1, kind: 'private-link-false-only-recovery', recoveryId, originalIntentSha256: hash(intent),
      outcome: 'held-terminal-state-unproven', receipt: null, failure: safeOperationFailure(error), qualification: false, completedAt: iso(io.now()) };
  }
  await io.immutable(`${prefix}-result.json`, result);
  if (result.outcome !== 'recovered-disabled-original-outcome-retained') fail('PRIVATE_DISABLE_RECOVERY_HELD');
  return result;
}

export function verifyPrivateLinkRuntimeCompletion(c, context, record, at) {
  closed(record, ['version', 'kind', 'binding', 'approvals', 'disabled', 'candidate', 'controlEvidence', 'transport', 'target', 'publicTarget', 'phases',
    'preflight', 'probe', 'publicProbe', 'requests', 'queries', 'drain', 'enableIntentAt', 'disable', 'failure', 'outcome',
    'terminalFalse', 'terminal503', 'enabledWindowExceeded', 'publicLifetimeExceeded', 'completedAt', 'enabled', 'intent', 'enableIntent', 'publicInitial',
    'publicControl', 'publicCleanup']);
  if (record.version !== 1 || record.kind !== 'private-link-runtime-completion' ||
      record.outcome !== 'qualified-private-delivery-disabled' || record.failure !== null ||
      record.terminalFalse !== true || record.terminal503 !== true || record.enabledWindowExceeded !== false || record.publicLifetimeExceeded !== false ||
      canonicalInstant(record.completedAt) > at) fail('PRIVATE_RUNTIME_COMPLETION_UNQUALIFIED');
  verifyDisabledReceiver(c, context, record.controlEvidence, record.candidate, record.disabled);
  verifyWindowIntent(c, context, record.controlEvidence, record.intent);
  equal(record.intent.binding, record.binding, 'PRIVATE_WINDOW_BINDING_CHANGED');
  equal(record.intent.approvals, record.approvals, 'PRIVATE_WINDOW_APPROVAL_CHANGED');
  verifyReceiverCandidate(c, record.candidate);
  equal(record.binding, windowBinding(c, context, record.controlEvidence, record.candidate, record.disabled,
    record.binding.instanceId, record.transport, record.binding.runtimeReview ?? null), 'PRIVATE_RUNTIME_COMPLETION_BINDING');
  equal(record.target, record.disabled.target, 'PRIVATE_RUNTIME_TARGET_CHANGED');
  equal(record.publicTarget, publicControlTarget(c, record.target, context, record.controlEvidence), 'PRIVATE_PUBLIC_DESCRIPTOR_CHANGED');
  equal(executionIdentity(record.disable.observation.oldApp, 'Microsoft.App/containerApps'),
    executionIdentity(context.origin.receiver.receipt.resources[ids(c).app], 'Microsoft.App/containerApps'),
    'PRIVATE_OLD_RECEIVER_GENERATION_CHANGED');
  equal(record.phases, {
    enable: privateRuntimePhase(c, record.target, record.binding.instanceId, 'enable', hash(record.disabled)),
    disable: privateRuntimePhase(c, record.target, record.binding.instanceId, 'disable', hash(record.disabled)),
  }, 'PRIVATE_RUNTIME_PHASE_CHANGED');
  if (record.binding.configSha256 !== hash(c) || record.binding.planSha256 !== hash(context.plan) ||
      record.binding.controlEvidenceSha256 !== hash(record.controlEvidence) ||
      record.binding.candidateSha256 !== hash(record.candidate) ||
      record.binding.disabledRecordSha256 !== hash(record.disabled) ||
      record.binding.targetSha256 !== hash(record.target)) fail('PRIVATE_RUNTIME_COMPLETION_BINDING');
  equal(record.binding.limits, PRIVATE_RUNTIME_LIMITS, 'PRIVATE_RUNTIME_LIMITS_CHANGED');
  equal(record.binding.runtime, QUEUE_RUNTIME, 'PRIVATE_RUNTIME_LIMITS_CHANGED');
  const enabled = canonicalInstant(record.enableIntentAt), stopped = canonicalInstant(record.disable.completedAt);
  if (stopped < enabled || stopped - enabled > 600000) fail('PRIVATE_RUNTIME_WINDOW_EXCEEDED');
  review(record.approvals.enable, 'private-link-bounded-enable', record.binding, enabled);
  review(record.approvals.disable, 'private-link-false-only-disable', record.binding, stopped);
  closed(record.approvals, ['enable', 'disable', 'publicCreate', 'publicDelete']);
  closed(record.transport, ['pythonPath', 'pythonSha256', 'bridgeSha256']);
  const identity = record.disabled.observation.identities[ids(c).ingestIdentity];
  closed(record.enableIntent, ['version', 'windowIntentSha256', 'phaseSha256', 'intentAt', 'effectDeadline', 'outcome']);
  if (record.enableIntent.version !== 1 || record.enableIntent.windowIntentSha256 !== hash(record.intent) ||
      record.enableIntent.phaseSha256 !== hash(record.phases.enable) || record.enableIntent.intentAt !== record.enableIntentAt ||
      record.enableIntent.outcome !== 'enable-possible' || record.enableIntent.effectDeadline > enabled + 120000 ||
      record.enableIntent.effectDeadline <= enabled || canonicalInstant(record.enabled.observedAt) > record.enableIntent.effectDeadline) fail('PRIVATE_ENABLE_INTENT_CHANGED');
  closed(record.preflight, ['current', 'initial', 'preview']);
  verifyObservation(c, record.target, record.candidate, record.preflight.initial, 'false');
  verifyObservation(c, record.publicTarget, record.candidate, record.publicInitial, 'false');
  if (record.probe.result.mode !== 'private' || record.publicProbe.result.mode !== 'public-deny') fail('PRIVATE_PROBE_MODE_CHANGED');
  verifyPrivateProbeEvidence(c, record.target, record.candidate, record.preflight.initial.identities,
    record.probe, record.preflight.initial.app, enabled);
  verifyPrivateProbeEvidence(c, record.publicTarget, record.candidate, record.publicInitial.identities,
    record.publicProbe, record.publicInitial.app, enabled);
  for (const probe of [record.probe, record.publicProbe]) {
    if (canonicalInstant(probe.processStartedAt) < canonicalInstant(record.intent.intentAt) ||
        probe.before.control.sourceSha256 !== record.approvals.enable.sourceSha256 ||
        probe.before.control.headSha256 !== record.preflight.current.headSha256) fail('PRIVATE_PROBE_WINDOW_CHANGED');
  }
  if (record.probe.sessions !== 1 || record.probe.payloadFrames !== 1 || record.probe.sessionClosed !== true ||
      record.probe.imageDigest !== record.candidate.profile.manifestDigest || !sameId(record.probe.appId, record.target.appId)) fail('PRIVATE_PROBE_BINDING_CHANGED');
  if (record.publicProbe.sessions !== 1 || record.publicProbe.payloadFrames !== 1 || record.publicProbe.sessionClosed !== true ||
      record.publicProbe.imageDigest !== record.candidate.profile.manifestDigest ||
      !sameId(record.publicProbe.appId, record.publicTarget.appId) || !sameId(record.publicTarget.environmentId, ids(c).environment) ||
      record.publicTarget.queueHost !== record.target.queueHost || record.publicTarget.privateIp !== record.target.privateIp ||
      !record.publicTarget.appId.endsWith('/' + c.namePrefix + '-public-probe')) fail('PRIVATE_PUBLIC_PROBE_BINDING_CHANGED');
  verifyPublicCompletion(c, record);
  if (!Array.isArray(record.requests) || record.requests.length !== 2 || record.queries.length < 1 || record.queries.length > 3) fail('PRIVATE_SYNTHETIC_BOUND_CHANGED');
  for (const [index, request] of record.requests.entries()) {
    closed(request, ['fixture', 'intentAt', 'dispatched', 'response']);
    equal(request.fixture, SYNTHETIC_FIXTURES[index], 'PRIVATE_SYNTHETIC_FIXTURE_CHANGED');
    if (canonicalInstant(request.intentAt) < enabled || canonicalInstant(request.intentAt) >= enabled + 420000) fail('PRIVATE_REQUEST_TIME_UNQUALIFIED');
    if (request.dispatched !== true) fail('PRIVATE_SYNTHETIC_DISPATCH_UNPROVEN');
    verifyHttp(request.response, 202);
  }
  for (const query of record.queries) {
    closed(query, ['start', 'end', 'rows', 'verification']);
    if (canonicalInstant(query.start) !== enabled || canonicalInstant(query.end) > stopped) fail('PRIVATE_QUERY_TIME_UNQUALIFIED');
    equal(query.verification, verifySyntheticRows(query.rows, query.start, query.end), 'PRIVATE_QUERY_VERIFICATION_CHANGED');
  }
  closed(record.drain, ['queueId', 'approximateMessageCount', 'observedAt', 'approximate']);
  if (canonicalInstant(record.drain.observedAt) > stopped || canonicalInstant(record.drain.observedAt) < enabled ||
      !record.queries.some(query => verifySyntheticRows(query.rows, query.start, query.end).complete) ||
      !sameId(record.drain?.queueId, record.candidate.topology.ids.queue) ||
      record.drain.approximateMessageCount !== 0 || record.drain.approximate !== true) fail('PRIVATE_DELIVERY_OR_DRAIN_UNPROVEN');
  verifyObservation(c, record.target, record.candidate, record.enabled, 'true');
  verifyObservation(c, record.target, record.candidate, record.disable.observation, 'false');
  closed(record.disable, ['intent', 'observation', 'response', 'oldApp', 'completedAt']);
  closed(record.disable.intent, ['version', 'originalIntentSha256', 'approval', 'binding', 'action',
    'request', 'intentAt', 'effectDeadline', 'outcome']);
  equal(record.disable.intent.approval, record.approvals.disable, 'PRIVATE_DISABLE_APPROVAL_CHANGED');
  equal(record.disable.intent.binding, record.binding, 'PRIVATE_DISABLE_BINDING_CHANGED');
  equal(record.disable.intent.request, record.phases.disable.request, 'PRIVATE_FROZEN_ROLLBACK_CHANGED');
  if (record.disable.intent.version !== 1 || record.disable.intent.originalIntentSha256 !== hash(record.intent) ||
      record.disable.intent.action !== 'private-link-false-only-disable' || record.disable.intent.outcome !== 'false-write-possible' ||
      canonicalInstant(record.disable.intent.intentAt) < enabled || stopped > record.disable.intent.effectDeadline ||
      record.disable.intent.effectDeadline > canonicalInstant(record.disable.intent.intentAt) + 120000) fail('PRIVATE_DISABLE_INTENT_CHANGED');
  const oldTarget = oldPublicRuntimeTarget(c, { oldApp: context.origin.receiver.receipt.resources[ids(c).app],
    oldEnvironment: { id: ids(c).environment, properties: { vnetConfiguration: null } }, oldReceiver: context.origin.receiver }, record.target);
  verifyPrivateLinkApp(c, oldTarget, record.candidate.priorCandidate, record.disable.oldApp,
    record.disable.observation.identities, 'false');
  if (admissionFlag(record.disable.oldApp) !== 'false' || !sameId(record.disable.oldApp?.id, ids(c).app)) fail('PRIVATE_OLD_TERMINAL_FALSE_REQUIRED');
  verifyHttp(record.disable.response, 503);
  return { appId: record.target.appId, environmentId: record.target.environmentId,
    completedAt: record.completedAt, recordSha256: hash(record), terminalDisabled: true };
}

export function oldPublicRuntimeTarget(c, prerequisites, target) {
  const old = prerequisites.oldApp, environment = prerequisites.oldEnvironment;
  if (!sameId(old?.id, ids(c).app) || admissionFlag(old) !== 'false' ||
      !sameId(environment?.id, ids(c).environment) ||
      environment.properties?.vnetConfiguration !== null && environment.properties?.vnetConfiguration !== undefined) {
    fail('PRIVATE_PUBLIC_CONTROL_MUST_BE_OLD_NONVNET_APP');
  }
  const descriptor = prerequisites.oldReceiver?.phase?.resources?.find(value => sameId(value.id, ids(c).app));
  if (!descriptor) fail('PRIVATE_PUBLIC_RECEIVER_HISTORY_REQUIRED');
  return { version: 1, appId: ids(c).app, environmentId: ids(c).environment,
    fqdn: old.properties.configuration.ingress.fqdn, descriptor: structuredClone(descriptor),
    queueHost: target.queueHost, privateIp: target.privateIp };
}

export function publicControlTarget(c, target, context, evidence) {
  if (context.plan.version !== 3 || context.plan.input?.version !== 2 || !context.plan.publicProbe) fail('PRIVATE_PUBLIC_CONTROL_PLAN_REQUIRED');
  const environment = evidence.records.at(-1)?.after?.resources?.[ids(c).environment];
  const domain = environment?.properties?.defaultDomain;
  if (!sameId(environment?.id, ids(c).environment) || environment.properties.vnetConfiguration != null) fail('PRIVATE_PUBLIC_ENVIRONMENT_REQUIRED');
  if (!/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(domain)) fail('PRIVATE_PUBLIC_ENVIRONMENT_DOMAIN_REQUIRED');
  const descriptor = structuredClone(target.descriptor);
  descriptor.id = `${ids(c).group}/providers/Microsoft.App/containerApps/${c.namePrefix}-public-probe`;
  descriptor.expected.name = `${c.namePrefix}-public-probe`;
  descriptor.expected.properties.managedEnvironmentId = ids(c).environment;
  equal(descriptor, context.plan.publicProbe, 'PRIVATE_PUBLIC_CONTROL_PLAN_CHANGED');
  if (context.plan.topology.ids.publicProbe !== descriptor.id) fail('PRIVATE_PUBLIC_CONTROL_ID_CHANGED');
  if (admissionFlag(descriptor.expected) !== 'false') fail('PRIVATE_PUBLIC_CONTROL_DISABLED_ONLY');
  return { version: 1, appId: descriptor.id, environmentId: ids(c).environment,
    fqdn: `${descriptor.expected.name}.${domain}`, descriptor, queueHost: target.queueHost, privateIp: target.privateIp };
}

function publicCreatePhase(c, intent) {
  return privateRuntimePhase(c, intent.publicTarget, intent.binding.instanceId, 'create-public-probe', hash(intent.disabled));
}
function publicDeleteRequest(intent) {
  return { method: 'DELETE', id: intent.publicTarget.appId, apiVersion: appApi, body: null };
}
function verifyPublicCreateIntent(c, window, value) {
  closed(value, ['version', 'kind', 'windowIntentSha256', 'phase', 'target', 'approval', 'binding', 'intentAt', 'effectDeadline', 'outcome']);
  if (value.version !== 1 || value.kind !== 'private-link-public-control-create-intent' ||
      value.windowIntentSha256 !== hash(window) || value.outcome !== 'create-possible' ||
      !Number.isSafeInteger(value.effectDeadline) || value.effectDeadline <= canonicalInstant(value.intentAt) ||
      value.effectDeadline > Math.min(canonicalInstant(value.intentAt) + 120000, canonicalInstant(value.approval.expiresAt))) fail('PRIVATE_PUBLIC_CREATE_INTENT_CHANGED');
  equal(value.phase, publicCreatePhase(c, window), 'PRIVATE_PUBLIC_CREATE_PHASE_CHANGED');
  equal(value.target, window.publicTarget, 'PRIVATE_PUBLIC_TARGET_CHANGED');
  equal(value.binding, window.binding, 'PRIVATE_PUBLIC_CREATE_BINDING_CHANGED');
  equal(value.approval, window.approvals.publicCreate, 'PRIVATE_PUBLIC_CREATE_APPROVAL_CHANGED');
  review(value.approval, 'private-link-create-public-control', window.binding, canonicalInstant(value.intentAt));
}
async function createPublicControl(c, window, io) {
  const { publicTarget: target, candidate, approvals, binding } = window, phase = publicCreatePhase(c, window);
  const cap = Math.min(canonicalInstant(approvals.enable.expiresAt), canonicalInstant(approvals.publicCreate.expiresAt));
  const guard = () => {
    review(approvals.publicCreate, 'private-link-create-public-control', binding, io.now());
    review(approvals.publicDelete, 'private-link-delete-public-control', binding, io.now());
    deadline(io.now, cap); freshImage(c, candidate, io.now());
  };
  guard();
  if (await io.load('private-public-create-intent.json')) fail('PRIVATE_PUBLIC_CREATE_NO_RETRY');
  const current = await io.current(stageDeadline(io, cap)); guard();
  const environment = value => {
    const old = value.prerequisites?.oldEnvironment;
    if (!sameId(old?.id, target.environmentId) || old.properties.vnetConfiguration != null ||
        `${target.descriptor.expected.name}.${old.properties.defaultDomain}` !== target.fqdn) fail('PRIVATE_PUBLIC_ENVIRONMENT_MUST_BE_NONVNET');
  };
  environment(current);
  const before = await io.read(target.appId, appApi, stageDeadline(io, cap));
  const preview = await io.preview(phase, stageDeadline(io, cap)); guard();
  const identities = await io.identities(stageDeadline(io, cap));
  verifyPrivateRuntimePreview(target, phase, preview, before, current.preservedResourceIds, { c, candidate, identities });
  await io.immutable('private-public-preview.json', { phase, current, before, preview });
  let intent, effectUntil;
  await io.deploy(phase.request, guard, stageDeadline(io, cap), async until => {
    environment(await io.current(until)); await io.published(approvals.publicCreate); await io.published(approvals.publicDelete);
    await assertWindowHead(io, window);
    samePreimage(c, target, candidate, null, await io.read(target.appId, appApi, until), {});
    deadline(io.now, until); guard();
  }, async () => {
    guard(); effectUntil = stageDeadline(io, cap);
    intent = { version: 1, kind: 'private-link-public-control-create-intent', windowIntentSha256: hash(window),
      phase, target, approval: approvals.publicCreate, binding, intentAt: iso(io.now()), effectDeadline: effectUntil, outcome: 'create-possible' };
    await io.immutable('private-public-create-intent.json', intent);
    await io.reserve('public-probe', hash({ appId: target.appId.toLowerCase() }), { intentSha256: hash(intent), outcome: 'create-possible' });
    return effectUntil;
  });
  const observation = await ready(c, target, candidate, io, 'false', effectUntil); guard();
  const record = { version: 1, kind: 'private-link-disabled-public-control', intent, observation, completedAt: iso(io.now()) };
  await io.immutable('private-public-create-receipt.json', record);
  return record;
}
async function publicCreationSettled(c, window, io, cap) {
  const intent = await io.load('private-public-create-intent.json');
  if (!intent) return null;
  verifyPublicCreateIntent(c, window, intent);
  await io.published(intent.approval, true);
  for (let count = 0; count < 40; count++) {
    const until = stageDeadline(io, cap), deployment = await io.read(intent.phase.request.id, '2022-09-01', until);
    deadline(io.now, until);
    if (['Succeeded', 'Failed', 'Canceled', 'Cancelled'].includes(deployment?.properties?.provisioningState)) {
      const operations = await io.read(`${intent.phase.request.id}/operations`, '2022-09-01', until);
      const app = await io.read(window.publicTarget.appId, appApi, until);
      deadline(io.now, until);
      if (!sameId(deployment.id, intent.phase.request.id) || deployment.properties.mode !== 'Incremental' ||
          queueArmInstant(deployment.properties.timestamp) < queueArmInstant(intent.intentAt) ||
          queueArmInstant(deployment.properties.timestamp) > queueArmInstant(iso(io.now()))) fail('PRIVATE_PUBLIC_DEPLOYMENT_CHANGED');
      if (app !== null) {
        if (deployment.properties.provisioningState === 'Succeeded') verifyCreationDeployment(intent, deployment, operations, app, iso(io.now()));
        else if (!Array.isArray(operations?.value) || operations.nextLink ||
            !operations.value.some(value => value.properties?.provisioningOperation === 'Create' &&
              sameId(value.properties.targetResource?.id, window.publicTarget.appId))) fail('PRIVATE_PUBLIC_FAILED_CREATE_SCOPE_UNPROVEN');
        privateRuntimeIncarnation(app);
        verifyPrivateLinkApp(c, window.publicTarget, window.candidate, app, await io.identities(until), 'false');
      } else if (deployment.properties.provisioningState === 'Succeeded') {
        if (!Array.isArray(operations?.value) || operations.nextLink || !operations.value.some(value =>
          value.properties?.provisioningOperation === 'Create' && value.properties.provisioningState === 'Succeeded' &&
          sameId(value.properties.targetResource?.id, window.publicTarget.appId))) fail('PRIVATE_PUBLIC_CREATE_UNPROVEN');
      }
      return { intent, deployment, operations, app, observedAt: iso(io.now()) };
    }
    await io.sleep(Math.min(3000, Math.max(0, cap - io.now())));
  }
  fail('PRIVATE_PUBLIC_CREATE_NOT_TERMINAL');
}
async function publicCleanupGeneration(c, window, creation, io, reviewed = null, prepare = false) {
  const receipt = await io.load('private-public-create-receipt.json');
  let original = null;
  if (receipt !== null) {
    closed(receipt, ['version', 'kind', 'intent', 'observation', 'completedAt']);
    if (receipt.version !== 1 || receipt.kind !== 'private-link-disabled-public-control' ||
        canonicalInstant(receipt.completedAt) > receipt.intent.effectDeadline) fail('PRIVATE_PUBLIC_CREATE_RECEIPT_CHANGED');
    equal(receipt.intent, creation.intent, 'PRIVATE_PUBLIC_CREATE_RECEIPT_CHANGED');
    verifyPublicCreateIntent(c, window, receipt.intent);
    verifyObservation(c, window.publicTarget, window.candidate, receipt.observation, 'false');
    original = privateRuntimeIncarnation(receipt.observation.app);
  }
  const actual = creation.app === null ? null : privateRuntimeIncarnation(creation.app);
  if (original && actual) equal(actual, original, 'PRIVATE_PUBLIC_CLEANUP_GENERATION_CHANGED');
  if (reviewed !== null) {
    closed(reviewed, ['version', 'kind', 'createIntentSha256', 'createReceiptSha256', 'incarnation', 'app', 'observedAt']);
    if (reviewed.version !== 1 || reviewed.kind !== 'private-public-cleanup-observed-generation' ||
        reviewed.createIntentSha256 !== hash(creation.intent) ||
        reviewed.createReceiptSha256 !== (receipt === null ? null : hash(receipt))) fail('PRIVATE_PUBLIC_GENERATION_REVIEW_CHANGED');
    canonicalInstant(reviewed.observedAt);
    if (reviewed.app === null) {
      if (actual !== null || reviewed.incarnation !== null) fail('PRIVATE_PUBLIC_GENERATION_REVIEW_CHANGED');
    } else {
      if (!sameId(reviewed.app.id, window.publicTarget.appId)) fail('PRIVATE_PUBLIC_GENERATION_REVIEW_CHANGED');
      equal(reviewed.incarnation, privateRuntimeIncarnation(reviewed.app), 'PRIVATE_PUBLIC_GENERATION_REVIEW_CHANGED');
      if (actual !== null) equal(actual, reviewed.incarnation, 'PRIVATE_PUBLIC_CLEANUP_GENERATION_CHANGED');
      if (original !== null) equal(original, reviewed.incarnation, 'PRIVATE_PUBLIC_CLEANUP_GENERATION_CHANGED');
    }
  } else if (original === null && actual !== null && !prepare) {
    fail('PRIVATE_PUBLIC_GENERATION_REVIEW_REQUIRED');
  }
  return { version: 1, kind: 'private-public-cleanup-observed-generation', createIntentSha256: hash(creation.intent),
    createReceiptSha256: receipt === null ? null : hash(receipt), incarnation: actual, app: creation.app, observedAt: creation.observedAt };
}
async function cleanupPublicControl(c, window, approval, binding, action, prefix, io, cap, reviewedGeneration = null) {
  const guard = () => { deadline(io.now, cap); review(approval, action, binding, io.now()); };
  guard(); await io.beginRecoveryReads?.(cap); guard(); await assertWindowHead(io, window);
  await io.published(window.approvals.publicCreate, true); await io.published(window.approvals.publicDelete, true);
  await io.published(approval, true); guard();
  const creation = await publicCreationSettled(c, window, io, cap); guard();
  if (!creation) {
    if (await io.read(window.publicTarget.appId, appApi, stageDeadline(io, cap)) !== null) fail('PRIVATE_PUBLIC_UNOWNED_CONTROL_PRESENT');
    guard();
    return { version: 1, kind: 'private-link-public-control-cleanup', createAdmitted: false, absent: true,
      creation: null, deleteIntent: null, completedAt: iso(io.now()) };
  }
  await publicCleanupGeneration(c, window, creation, io, reviewedGeneration); guard();
  let deleteIntent = null, effectUntil = cap;
  if (creation.app !== null) {
    const check = async until => {
      await io.published(approval, true); await assertWindowHead(io, window); guard();
      const app = await io.read(window.publicTarget.appId, appApi, until), identities = await io.identities(until);
      await publicCleanupGeneration(c, window, { ...creation, app }, io, reviewedGeneration); guard();
      samePreimage(c, window.publicTarget, window.candidate, creation.app, app, identities); deadline(io.now, until); guard();
    };
    await io.deletePublic(window.publicTarget, guard, stageDeadline(io, cap), check, async () => {
      guard(); effectUntil = stageDeadline(io, cap);
      deleteIntent = { version: 1, windowIntentSha256: hash(window), createIntentSha256: hash(creation.intent),
        request: publicDeleteRequest(window), approval, binding, action, intentAt: iso(io.now()), effectDeadline: effectUntil, outcome: 'delete-possible' };
      await io.immutable(`${prefix}-intent.json`, deleteIntent);
      await io.reserve('public-cleanup', hash({ appId: window.publicTarget.appId, prefix, createIntentSha256: hash(creation.intent) }),
        { intentSha256: hash(deleteIntent), outcome: 'delete-possible-no-retry' });
      return effectUntil;
    });
    let absent = false;
    for (let count = 0; count < 40; count++) {
      deadline(io.now, effectUntil);
      if (await io.read(window.publicTarget.appId, appApi, effectUntil) === null) { absent = true; break; }
      await io.sleep(Math.min(3000, Math.max(0, effectUntil - io.now())));
    }
    if (!absent) fail('PRIVATE_PUBLIC_ABSENCE_UNPROVEN');
  }
  guard(); deadline(io.now, effectUntil);
  const receipt = { version: 1, kind: 'private-link-public-control-cleanup', createAdmitted: true, absent: true,
    creation, deleteIntent, absence: { id: window.publicTarget.appId, app: null, observedAt: iso(io.now()) }, completedAt: iso(io.now()) };
  await io.immutable(`${prefix}-receipt.json`, receipt);
  return receipt;
}

function verifyPublicCompletion(c, record) {
  const created = record.publicControl, cleanup = record.publicCleanup;
  closed(created, ['version', 'kind', 'intent', 'observation', 'completedAt']);
  if (created.version !== 1 || created.kind !== 'private-link-disabled-public-control') fail('PRIVATE_PUBLIC_CREATE_REQUIRED');
  verifyPublicCreateIntent(c, record.intent, created.intent);
  verifyObservation(c, record.publicTarget, record.candidate, created.observation, 'false');
  equal(created.observation, record.publicInitial, 'PRIVATE_PUBLIC_PROBE_ORIGIN_CHANGED');
  if (canonicalInstant(created.completedAt) < canonicalInstant(created.intent.intentAt) || canonicalInstant(created.completedAt) > created.intent.effectDeadline ||
      canonicalInstant(record.publicProbe.processStartedAt) < canonicalInstant(created.completedAt)) fail('PRIVATE_PUBLIC_CREATION_TIME_CHANGED');
  closed(cleanup, ['version', 'kind', 'createAdmitted', 'absent', 'creation', 'deleteIntent', 'absence', 'completedAt']);
  if (cleanup.version !== 1 || cleanup.kind !== 'private-link-public-control-cleanup' || cleanup.createAdmitted !== true ||
      cleanup.absent !== true || canonicalInstant(cleanup.completedAt) - canonicalInstant(created.intent.intentAt) > 900000 ||
      canonicalInstant(cleanup.completedAt) < canonicalInstant(record.disable.completedAt)) fail('PRIVATE_PUBLIC_CLEANUP_UNPROVEN');
  equal(cleanup.creation.intent, created.intent, 'PRIVATE_PUBLIC_CREATION_LINEAGE_CHANGED');
  verifyCreationDeployment(created.intent, cleanup.creation.deployment, cleanup.creation.operations, cleanup.creation.app, cleanup.completedAt);
  equal(privateRuntimeIncarnation(cleanup.creation.app), privateRuntimeIncarnation(created.observation.app), 'PRIVATE_PUBLIC_CLEANUP_GENERATION_CHANGED');
  closed(cleanup.deleteIntent, ['version', 'windowIntentSha256', 'createIntentSha256', 'request', 'approval', 'binding',
    'action', 'intentAt', 'effectDeadline', 'outcome']);
  if (cleanup.deleteIntent.version !== 1 || cleanup.deleteIntent.windowIntentSha256 !== hash(record.intent) ||
      cleanup.deleteIntent.createIntentSha256 !== hash(created.intent) || cleanup.deleteIntent.outcome !== 'delete-possible' ||
      cleanup.deleteIntent.action !== 'private-link-delete-public-control') fail('PRIVATE_PUBLIC_DELETE_INTENT_CHANGED');
  equal(cleanup.deleteIntent.request, publicDeleteRequest(record.intent), 'PRIVATE_PUBLIC_DELETE_SCOPE');
  equal(cleanup.deleteIntent.approval, record.approvals.publicDelete, 'PRIVATE_PUBLIC_DELETE_APPROVAL_CHANGED');
  equal(cleanup.deleteIntent.binding, record.binding, 'PRIVATE_PUBLIC_DELETE_BINDING_CHANGED');
  review(record.approvals.publicDelete, 'private-link-delete-public-control', record.binding, canonicalInstant(cleanup.deleteIntent.intentAt));
  closed(cleanup.absence, ['id', 'app', 'observedAt']);
  if (!sameId(cleanup.absence.id, record.publicTarget.appId) || cleanup.absence.app !== null ||
      canonicalInstant(cleanup.absence.observedAt) < canonicalInstant(cleanup.deleteIntent.intentAt) ||
      canonicalInstant(cleanup.absence.observedAt) > cleanup.deleteIntent.effectDeadline ||
      canonicalInstant(cleanup.completedAt) < canonicalInstant(cleanup.absence.observedAt) ||
      cleanup.deleteIntent.effectDeadline > Math.min(canonicalInstant(cleanup.deleteIntent.intentAt) + 120000,
        canonicalInstant(record.approvals.publicDelete.expiresAt))) fail('PRIVATE_PUBLIC_ABSENCE_UNPROVEN');
}

function publicRecoveryBinding(c, context, window, creation, recoveryId, generation) {
  return { version: 1, kind: 'private-link-public-cleanup-recovery-binding', recoveryId,
    windowIntentSha256: hash(window), createIntentSha256: hash(creation), requestSha256: hash(publicDeleteRequest(window)),
    generationSha256: hash(generation), physicalKey: window.physicalKey, configSha256: hash(c), contextSha256: hash(context) };
}
export async function preparePublicControlCleanup(c, context, evidence, recoveryId, directory, options = {}) {
  if (!uuid(recoveryId)) fail('PRIVATE_RECOVERY_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const window = await io.load('private-window-intent.json'), creation = await io.load('private-public-create-intent.json');
  verifyWindowIntent(c, context, evidence, window); verifyPublicCreateIntent(c, window, creation);
  await assertWindowHead(io, window);
  await io.published(window.approvals.publicCreate, true); await io.published(window.approvals.publicDelete, true);
  await io.beginRecoveryReads?.(io.now() + 120000);
  const state = await publicCreationSettled(c, window, io, io.now() + 120000);
  const generation = await publicCleanupGeneration(c, window, state, io, null, true);
  const binding = publicRecoveryBinding(c, context, window, creation, recoveryId, generation);
  const prepared = { version: 1, kind: 'private-link-public-cleanup-preparation', binding, bindingSha256: hash(binding),
    generation, approvalAction: 'private-link-recover-public-cleanup', executionAuthorized: false };
  await io.immutable(`private-public-recovery-${recoveryId}-preparation.json`, prepared);
  return prepared;
}
export async function recoverPublicControlCleanup(c, context, evidence, recoveryId, approval, directory, options = {}) {
  if (!uuid(recoveryId)) fail('PRIVATE_RECOVERY_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const window = await io.load('private-window-intent.json'), creation = await io.load('private-public-create-intent.json');
  verifyWindowIntent(c, context, evidence, window); verifyPublicCreateIntent(c, window, creation);
  const prepared = await io.load(`private-public-recovery-${recoveryId}-preparation.json`);
  const binding = publicRecoveryBinding(c, context, window, creation, recoveryId, prepared?.generation);
  equal(prepared, { version: 1, kind: 'private-link-public-cleanup-preparation', binding, bindingSha256: hash(binding),
    generation: prepared.generation, approvalAction: 'private-link-recover-public-cleanup', executionAuthorized: false }, 'PRIVATE_PUBLIC_RECOVERY_CHANGED');
  review(approval, prepared.approvalAction, binding, io.now()); await io.published(approval, true);
  await io.reserve('recovery', hash({ publicControl: window.publicTarget.appId, recoveryId }),
    { bindingSha256: hash(binding), approvalSha256: hash(approval), outcome: 'public-cleanup-possible' });
  let receipt = null, failure = null;
  try {
    receipt = await cleanupPublicControl(c, window, approval, binding, prepared.approvalAction,
      `private-public-recovery-${recoveryId}`, io, stageDeadline(io, canonicalInstant(approval.expiresAt), 180000), prepared.generation);
  } catch (error) { failure = safeOperationFailure(error); }
  const result = { version: 1, kind: 'private-link-public-cleanup-recovery', recoveryId,
    originalIntentSha256: hash(window), outcome: receipt?.absent ? 'public-control-absent-original-history-retained' : 'held-public-control-state-unproven',
    receipt, failure, qualification: false, completedAt: iso(io.now()) };
  await io.immutable(`private-public-recovery-${recoveryId}-result.json`, result);
  if (result.outcome !== 'public-control-absent-original-history-retained') fail('PRIVATE_PUBLIC_CLEANUP_RECOVERY_HELD');
  return result;
}
export async function reconcilePublicControl(c, context, evidence, reconciliationId, directory, options = {}) {
  if (!uuid(reconciliationId)) fail('PRIVATE_RECONCILIATION_ID_REQUIRED');
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const window = await io.load('private-window-intent.json');
  verifyWindowIntent(c, context, evidence, window); await assertWindowHead(io, window);
  const state = await publicCreationSettled(c, window, io, io.now() + 120000);
  if (!state) fail('PRIVATE_PUBLIC_CREATE_INTENT_REQUIRED');
  const result = { version: 1, kind: 'private-link-public-control-reconciliation', reconciliationId, state,
    absent: state.app === null, qualified: false, originalHistoryModified: false, observedAt: iso(io.now()) };
  await io.immutable(`private-public-reconciliation-${reconciliationId}.json`, result);
  return result;
}

export { runtimeBinding as privateLinkRuntimeBinding, windowBinding as privateLinkWindowBinding };

export const PRIVATE_LINK_RUNTIME_OPERATIONS = Object.freeze([
  'prepare-image', 'publish-image', 'prepare-receiver', 'create-receiver', 'prepare-window', 'qualify-window',
  'prepare-disable-recovery', 'recover-disable', 'reconcile-receiver',
  'prepare-public-cleanup', 'recover-public-cleanup', 'reconcile-public-probe',
]);
export async function runPrivateLinkRuntime(c, context, evidence, operation, directoryArg, inputs, options = {}) {
  if (!PRIVATE_LINK_RUNTIME_OPERATIONS.includes(operation)) fail('PRIVATE_RUNTIME_FIXED_OPERATION_REQUIRED');
  const forward = ['prepare-image', 'publish-image', 'prepare-receiver', 'create-receiver', 'prepare-window', 'qualify-window'].includes(operation);
  let runtimeReview = null;
  if (Object.hasOwn(inputs ?? {}, 'runtimeReview')) {
    if (!forward || inputs.runtimeReview === null) fail('PRIVATE_RUNTIME_REVIEW_DATA_SCOPE');
    runtimeReview = structuredClone(inputs.runtimeReview);
    verifyRuntimeReview(c, context, runtimeReview, (options.now ?? options.io?.now ?? Date.now)());
    inputs = { ...inputs }; delete inputs.runtimeReview;
  }
  if (options.policyRevision !== undefined || options.costReview !== undefined || options.costEvidence !== undefined ||
      options.runtimeReview !== undefined && !isDeepStrictEqual(options.runtimeReview, runtimeReview)) fail('PRIVATE_RUNTIME_TYPED_REVIEW_DATA_REQUIRED');
  options = { ...options, runtimeReview };
  const directory = await privateDirectory(directoryArg);
  const io = options.io ?? await privateLinkRuntimeIO(c, context, evidence, directory, options);
  const effects = { ...options, io };
  if (operation === 'prepare-public-cleanup' || operation === 'recover-public-cleanup') {
    closed(inputs, operation === 'prepare-public-cleanup' ? ['recoveryId'] : ['recoveryId', 'approval']);
    return operation === 'prepare-public-cleanup' ?
      preparePublicControlCleanup(c, context, evidence, inputs.recoveryId, directory, effects) :
      recoverPublicControlCleanup(c, context, evidence, inputs.recoveryId, inputs.approval, directory, effects);
  }
  if (operation === 'reconcile-public-probe') {
    closed(inputs, ['reconciliationId']);
    const result = await reconcilePublicControl(c, context, evidence, inputs.reconciliationId, directory, effects);
    if (!result.absent) fail('PRIVATE_PUBLIC_CONTROL_STILL_PRESENT');
    return result;
  }
  if (operation === 'prepare-disable-recovery' || operation === 'recover-disable') {
    closed(inputs, operation === 'prepare-disable-recovery' ? ['recoveryId'] : ['recoveryId', 'approval']);
    return operation === 'prepare-disable-recovery' ?
      preparePrivateLinkDisableRecovery(c, context, evidence, inputs.recoveryId, directory, effects) :
      recoverPrivateLinkDisabled(c, context, evidence, inputs.recoveryId, inputs.approval, directory, effects);
  }
  if (operation === 'reconcile-receiver') {
    closed(inputs, ['reconciliationId']);
    return reconcilePrivateLinkReceiver(c, context, evidence, inputs.reconciliationId, directory, effects);
  }
  if (operation.endsWith('image')) {
    closed(inputs, operation === 'prepare-image' ? ['candidate', 'local'] : ['candidate', 'local', 'approval']);
    if (operation === 'publish-image') return publishPrivateLinkImage(c, context, evidence, inputs.candidate,
      inputs.approval, inputs.local, directory, effects);
    io.verifyPrerequisites();
    verifyReceiverCandidate(c, inputs.candidate, io.now(), false);
    const binding = { ...runtimeBinding(c, context, evidence, inputs.candidate, runtimeReview), local: inputs.local };
    const prepared = { version: 1, kind: 'private-link-runtime-preparation', operation,
      binding, bindingSha256: hash(binding), approvalAction: 'private-link-publish-one-queued-image', executionAuthorized: false };
    await io.immutable('private-image-preparation.json', prepared);
    return prepared;
  }
  if (operation.endsWith('receiver')) {
    closed(inputs, operation === 'prepare-receiver' ? ['candidate', 'instanceId'] : ['candidate', 'instanceId', 'approval']);
    if (operation === 'create-receiver') return createPrivateLinkReceiver(c, context, evidence, inputs.candidate,
      inputs.instanceId, inputs.approval, directory, effects);
    const target = privateLinkRuntimeTarget(c, context, inputs.candidate, io.verifyPrerequisites(), runtimeReview);
    const phase = privateRuntimePhase(c, target, inputs.instanceId, 'create-disabled', hash(evidence));
    const binding = { ...runtimeBinding(c, context, evidence, inputs.candidate, runtimeReview), targetSha256: hash(target), phaseSha256: hash(phase) };
    const prepared = { version: 1, kind: 'private-link-runtime-preparation', operation, target, phase,
      binding, bindingSha256: hash(binding), approvalAction: 'private-link-create-disabled-receiver', executionAuthorized: false };
    await io.immutable('private-receiver-preparation.json', prepared);
    return prepared;
  }
  closed(inputs, operation === 'prepare-window' ? ['candidate', 'disabled', 'instanceId', 'transport'] :
    ['candidate', 'disabled', 'instanceId', 'transport', 'approvals']);
  if (operation === 'qualify-window') {
    const result = await qualifyPrivateLinkDelivery(c, context, evidence, inputs.candidate,
      inputs.disabled, inputs.instanceId, inputs.approvals, inputs.transport, directory, effects);
    if (result.outcome !== 'qualified-private-delivery-disabled') fail('PRIVATE_RUNTIME_QUALIFICATION_HELD');
    return result;
  }
  io.verifyPrerequisites();
  verifyDisabledReceiver(c, context, evidence, inputs.candidate, inputs.disabled);
  const binding = windowBinding(c, context, evidence, inputs.candidate, inputs.disabled, inputs.instanceId, inputs.transport, runtimeReview);
  const phases = Object.fromEntries(['enable', 'disable'].map(action => [action,
    privateRuntimePhase(c, inputs.disabled.target, inputs.instanceId, action, hash(inputs.disabled))]));
  const prepared = { version: 1, kind: 'private-link-runtime-preparation', operation, binding, bindingSha256: hash(binding), phases,
    publicPhase: privateRuntimePhase(c, publicControlTarget(c, inputs.disabled.target, context, evidence),
      inputs.instanceId, 'create-public-probe', hash(inputs.disabled)),
    publicCleanupRequest: { method: 'DELETE', id: context.plan.topology.ids.publicProbe, apiVersion: appApi, body: null },
    approvalActions: { enable: 'private-link-bounded-enable', disable: 'private-link-false-only-disable',
      publicCreate: 'private-link-create-public-control', publicDelete: 'private-link-delete-public-control' }, executionAuthorized: false };
  await io.immutable('private-window-preparation.json', prepared);
  return prepared;
}
