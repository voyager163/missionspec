import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import https from 'node:https';
import { constants } from 'node:fs';
import { readFile, open, mkdir, rename, rm, realpath } from 'node:fs/promises';
import { basename, dirname, resolve, isAbsolute, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, types } from 'node:util';
import { IMAGE_PHASES, buildDisabledImagePhase, receiverAnchor, prepareReceiverPublication, receiverSourceInputs, receiverCost, receiverDatabaseInstant,
  verifyReceiverCandidate, verifyDisabledImageRecord, verifyDisabledImageBefore, verifyImageRevision,
  ReceiverUpgradeController } from './receiver-upgrade.mjs';
import { QUEUE_PHASES, durableQueueCost, buildQueuePhase, queueEnvironment, queueTopology,
  qualifiedQueueRecords, verifyQueueTopology, verifyQueueReview, verifyQueueRecord, verifyQueueProviderOperations, verifyQueueApiCatalog,
  verifyQueueResource, verifyQueuePrivacy, verifyQueueDrain, verifyQueueWhatIf, queuePreflightBaseline, QueueTopologyController } from './durable-queue.mjs';
import { collectEffectivePolicies, verifyEffectivePolicyEvidence, effectivePolicyScopes } from './effective-policy.mjs';
import { collectQueueAdoption, adoptQueueStorage, verifyQueueAdoptionRecord, verifyAdoptedQueueStorage,
  verifyQueueAdoptionSources } from './queue-adoption.mjs';
import { collectQueueDefender, queueDefenderInventory } from './queue-defender.mjs';
import { NSP_PHASES, NSP_LIMITS, NSP_API, NSP_STORAGE_API, nspTopology, emptyNspEvidence, buildNspPhase,
  verifyNspEvidence, verifyNspAdmission, verifyNspObservation, verifyNspQueuePreflight, nspLineageHead,
  nspState, nspReadinessBinding, verifyNspPreview, nspIntentKey, nspPendingHead, nspTargetKey, nspIntentFence, verifyNspApiCatalog } from './nsp.mjs';
import { NspController, nspTransport, collectNspObservation, checkNspReadOnly, collectNspPermissions, collectNspEffectivePolicies } from './nsp-controller.mjs';
import { collectNspReconciliation, qualifyNspReconciliation, verifyNspStoppedAttempt } from './nsp-reconciliation.mjs';
import { buildPrivateLinkPlan, verifyPrivateLinkPlan, verifyPrivateLinkContext, PRIVATE_LINK_CONTROL_STAGES } from './private-link.mjs';
import { privateLinkWhatIfContext, privateLinkRuntimeWhatIfContext } from './private-link-whatif.mjs';
import { runPrivateLinkControl, runPrivateLinkNsgAdoption } from './private-link-controller.mjs';
import { runPrivateLinkRuntime } from './private-link-runtime.mjs';
import { loadPrivateLinkArtifact, savePrivateLinkArtifact } from './private-link-artifacts.mjs';
import { PHASES, buildPhase, deploymentName, validateConfig, ids, digest, digestJson, json, fail, sameId, storageContract, firstReleaseCost, assertOwned, RECEIVER_COMMAND,
  closed, budgetConfiguration, projectBudgetFilter, verifyFoundationBudgets, reconciliationBinding, assignmentRoleTargets,
  TOGGLE_PHASES, SYNTHETIC_LIMITS, SYNTHETIC_FIXTURES, requireAccess, validateWindowInstance } from './definition.mjs';
import { assertBudget, verifyWhatIf, verifyResource, verifyApproval, verifyFreshReview, sourceContractsSummary, permitFirstPush,
  executionIdentity, verifyExecutionOrigins, verifyReconciliation, verifyDeploymentIdentity, roleDefinitionSignature, verifyPublicationReadback,
  resourceContext, admissionFlag, descriptorWithFlag, canonicalAppWrite, syntheticTransitionHash, verifySyntheticWindow,
  verifyWindowApproval, verifyWindowState, canonicalInstant, verifySyntheticRows,
  verifyWindowPredecessor, verifyWindowInstancePredecessor, predecessorInstanceIds } from './policy.mjs';

const execute = promisify(execFile), here = dirname(fileURLToPath(import.meta.url));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export const MAX_PRIVATE_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const DIAGNOSTIC_API = '2021-05-01-preview';
export const WHAT_IF_API = '2025-04-01';
export const WHAT_IF_MAX_POLLS = 40;
export const MAX_CONCURRENT_READS = 4;
const invokeDeadlines = new WeakMap();
const limitedReadInvokes = new WeakSet();
export async function readBatch(values, read) {
  const results = new Array(values.length);
  let next = 0, failed = false, failure;
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_READS, values.length) }, async () => {
    while (!failed && next < values.length) {
      const index = next++;
      try { results[index] = await read(values[index], index); }
      catch (error) { if (!failed) failure = error; failed = true; }
    }
  }));
  if (failed) throw failure;
  return results;
}
export function limitReadConcurrency(invoke) {
  if (limitedReadInvokes.has(invoke)) return invoke;
  const queue = [];
  let active = 0, failed = false, failure;
  const drain = () => {
    while (!failed && active < MAX_CONCURRENT_READS && queue.length) {
      const job = queue.shift(); active++;
      (async () => {
        try { job.resolve(await invoke(...job.args)); }
        catch (error) {
          if (!failed) failure = error;
          failed = true; job.reject(error);
          for (const pending of queue.splice(0)) pending.reject(failure);
        } finally { active--; drain(); }
      })();
    }
  };
  const limited = (...args) => new Promise((resolve, reject) => {
    if (failed) { reject(failure); return; }
    queue.push({ args, resolve, reject }); drain();
  });
  limitedReadInvokes.add(limited);
  return limited;
}
function privateOwner() {
  if (!['darwin', 'linux'].includes(process.platform) || typeof process.getuid !== 'function' ||
      typeof process.geteuid !== 'function' || !constants.O_NOFOLLOW || !constants.O_DIRECTORY || !constants.O_NONBLOCK) fail('PRIVATE_POSIX_IO_REQUIRED');
  const uid = process.getuid();
  if (!Number.isSafeInteger(uid) || uid < 0 || uid !== process.geteuid()) fail('PRIVATE_POSIX_IDENTITY_REQUIRED');
  return BigInt(uid);
}
function verifyPrivateFile(info, owner) {
  if (!info.isFile() || info.nlink !== 1n || info.uid !== owner || (info.mode & 0o7777n) !== 0o600n) fail('PRIVATE_FILE_REQUIRED');
  if (info.size < 0n || info.size > BigInt(MAX_PRIVATE_ARTIFACT_BYTES)) fail('PRIVATE_FILE_TOO_LARGE');
}
export async function privateDirectory(relative) {
  const owner = privateOwner();
  const path = resolve(relative), root = resolve(here, '.operator-private');
  if (isAbsolute(relative) || (path !== root &&
      (dirname(path) !== root || !/^revision-\d{8}-[a-z0-9-]{1,32}$/u.test(basename(path))))) fail('PRIVATE_CANONICAL_DIRECTORY_REQUIRED');
  for (const directory of new Set([root, path])) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const handle = await open(directory, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
    try {
      const info = await handle.stat({ bigint: true });
      if (!info.isDirectory() || info.uid !== owner || (info.mode & 0o7777n) !== 0o700n) fail('PRIVATE_DIRECTORY_REQUIRED');
    } finally { await handle.close(); }
  }
  return path;
}
export async function saveImmutable(directory, name, value) {
  if (!/^[a-z0-9.-]+$/u.test(name)) fail('PRIVATE_FILENAME_INVALID');
  const handle = await open(resolve(directory, name), 'wx', 0o600);
  try { await handle.writeFile(typeof value === 'string' ? value : json(value)); await handle.sync(); }
  finally { await handle.close(); }
  const dir = await open(directory, 'r'); try { await dir.sync(); } finally { await dir.close(); }
}
export async function save(directory, name, value) {
  if (!/^[a-z0-9.-]+$/u.test(name)) fail('PRIVATE_FILENAME_INVALID');
  const temp = resolve(directory, `${name}.${randomUUID()}.pending`);
  const handle = await open(temp, 'wx', 0o600);
  try { await handle.writeFile(typeof value === 'string' ? value : json(value)); await handle.sync(); }
  finally { await handle.close(); }
  await rename(temp, resolve(directory, name));
  const dir = await open(directory, 'r'); try { await dir.sync(); } finally { await dir.close(); }
}
export async function load(directory, name, optional = false) {
  if (!/^[a-z0-9.-]+$/u.test(name)) fail('PRIVATE_FILENAME_INVALID');
  const owner = privateOwner();
  let handle;
  try {
    handle = await open(resolve(directory, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    throw new Error('PRIVATE_FILE_OPEN_FAILED');
  }
  try {
    const before = await handle.stat({ bigint: true });
    verifyPrivateFile(before, owner);
    const chunks = [];
    let size = 0;
    while (true) {
      const buffer = Buffer.alloc(Math.min(65536, MAX_PRIVATE_ARTIFACT_BYTES + 1 - size));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, size);
      size += bytesRead;
      if (size > MAX_PRIVATE_ARTIFACT_BYTES) fail('PRIVATE_FILE_TOO_LARGE');
      if (!bytesRead) break;
      chunks.push(buffer.subarray(0, bytesRead));
    }
    const after = await handle.stat({ bigint: true });
    verifyPrivateFile(after, owner);
    if (BigInt(size) !== before.size ||
        ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].some(k => before[k] !== after[k])) fail('PRIVATE_FILE_CHANGED');
    try { return JSON.parse(Buffer.concat(chunks, size).toString('utf8')); }
    catch { fail('PRIVATE_JSON_INVALID'); }
  } catch (error) {
    if (['PRIVATE_FILE_REQUIRED', 'PRIVATE_FILE_TOO_LARGE', 'PRIVATE_FILE_CHANGED', 'PRIVATE_JSON_INVALID'].includes(error.message)) throw error;
    throw new Error('PRIVATE_FILE_READ_FAILED');
  } finally {
    try { await handle.close(); } catch { fail('PRIVATE_FILE_CLOSE_FAILED'); }
  }
}
export async function sourceDigest() {
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs', 'arm-whatif.py', 'receiver-upgrade.mjs', 'durable-queue.mjs', 'effective-policy.mjs',
    'queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs', 'queue-defender.mjs',
    'private-link.mjs', 'private-link-whatif.mjs', 'private-link-controller.mjs', 'private-link-readback.mjs',
    'private-link-runtime.mjs', 'private-link-exec.py', 'private-link-artifacts.mjs', 'private-link-nsg-adoption.mjs'];
  const hash = createHash('sha256');
  for (const name of names) hash.update(name).update(await readFile(resolve(here, name)));
  const contract = await storageContract(); hash.update(json(contract));
  return hash.digest('hex');
}
export async function registryReview(c, receipts, directory, beforePush, invoke = az, ledger = receipts) {
  const r = ids(c), core = receipts.core;
  if (core?.configSha256 !== digest(json(c)) || !core?.resources?.[r.registry]) fail('REGISTRY_CORE_RECEIPT_REQUIRED');
  assertOwned(core.resources[r.registry], r.registry, c);
  const arm = transport(c, buildPhase(c, 'core', await storageContract(), receipts), directory, invoke);
  const current = await arm('GET', r.registry, '2023-07-01');
  const descriptor = buildPhase(c, 'core', await storageContract(), receipts).resources.find(v => v.id === r.registry);
  verifyResource(c, { phase: 'core' }, descriptor, current);
  // ACR admin auth stays disabled; no username/password/expose-token command is
  // available here. The CLI performs only authenticated manifest inventory reads.
  const repositories = await invoke(['acr', 'repository', 'list', '--name', c.registryName,
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (!Array.isArray(repositories)) fail('REGISTRY_INVENTORY_UNAVAILABLE');
  const manifests = [];
  for (const repository of repositories) {
    if (repository !== 'missionspec/telemetry-ingest') fail('UNREVIEWED_REGISTRY_REPOSITORY');
    const list = await invoke(['acr', 'manifest', 'list-metadata', '--registry', c.registryName, '--name', repository,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
    if (!Array.isArray(list)) fail('REGISTRY_INVENTORY_UNAVAILABLE');
    manifests.push(...list);
  }
  await save(directory, 'registry-image-inventory.json', { checkedAt: new Date().toISOString(), repositories, manifests });
  if (beforePush) {
    const result = permitFirstPush(c, repositories, manifests);
    await save(directory, 'first-image-publication-admission.json', { ...result, separatePublicationApprovalRequired: true });
    return result;
  }
  if (!isDeepStrictEqual(repositories, ['missionspec/telemetry-ingest']) || manifests.length !== 1 ||
      manifests[0].digest !== c.receiverDigest) fail('SINGLE_IMMUTABLE_IMAGE_REQUIRED');
  const manifest = await invoke(['acr', 'manifest', 'show', '--registry', c.registryName,
    '--name', `missionspec/telemetry-ingest@${c.receiverDigest}`, '--subscription', c.subscriptionId,
    '--only-show-errors', '--output', 'json']);
  if (manifest?.config?.digest !== 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204' ||
      !['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'].includes(manifest.mediaType)) fail('PUBLISHED_CONFIG_MISMATCH');
  // Content-addressed config must match the separately qualified receiver config,
  // not the retired operator image. This is not a claim that SHA is a signature.
  const receipt = { qualified: true, digest: c.receiverDigest, registryId: r.registry, recentDigestCount: 1,
    configUser: '65532:65532', configSha256: manifest.config.digest, command: RECEIVER_COMMAND,
    configSha256Inputs: digest(json(c)), manifest, checkedAt: new Date().toISOString(), nativeV8Clearance: 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY' };
  receipts.publication = receipt;
  ledger.publication = receipt;
  await save(directory, 'publication-receipt.json', receipt); await save(directory, 'receipts.json', ledger);
  return receipt;
}
function cliError(error) {
  const text = typeof error.stderr === 'string' ? error.stderr.trim() : '';
  const match = /^ERROR: (Not Found|Forbidden|Unauthorized|Bad Request|Conflict|Too Many Requests)\((\{[\s\S]*\})\)$/u.exec(text);
  try {
    const body = JSON.parse(match?.[2] ?? /^ERROR: (\{[\s\S]*\})$/u.exec(text)?.[1] ?? '{}');
    const code = body.error?.code ?? body.code;
    return { code: code === '404' || code === 404 ? '404' : typeof code === 'string' && /^[A-Za-z][A-Za-z0-9]{0,127}$/u.test(code) ? code : 'Unclassified',
      status: { 'Not Found': 404, Forbidden: 403, Unauthorized: 401, 'Bad Request': 400, Conflict: 409, 'Too Many Requests': 429 }[match?.[1]] ?? null };
  } catch { return { code: 'Unclassified', status: null }; }
}
export async function az(args, timeout = 60000, run = execute) {
  const started = performance.now();
  try {
    const { stdout } = await run('az', args, { timeout, maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, AZURE_CORE_COLLECT_TELEMETRY: 'false', AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no' } });
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && ['', 'null'].includes(stdout.trim())) fail('ARM_EMPTY_READ_RESPONSE');
    return stdout.trim() ? JSON.parse(stdout) : null;
  } catch (error) {
    const { code, status } = cliError(error);
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 &&
        ['ResourceNotFound', 'ResourceGroupNotFound', 'DeploymentNotFound', 'ParentResourceNotFound', 'BudgetNotFound'].includes(code)) return null;
    // Consumption's individual-budget GET uses a numeric error code for an absent budget.
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 && code === '404' &&
        /^https:\/\/management\.azure\.com\/subscriptions\/[0-9a-f-]{36}(?:\/resourceGroups\/[a-z0-9-]+)?\/providers\/Microsoft\.Consumption\/budgets\/[a-z0-9-]+\?api-version=2024-08-01$/u.test(args[args.indexOf('--url') + 1] ?? '')) return null;
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 && code === 'RoleDefinitionDoesNotExist' &&
        /^https:\/\/management\.azure\.com\/subscriptions\/[0-9a-f-]{36}\/providers\/Microsoft\.Authorization\/roleDefinitions\/[0-9a-f-]{36}\?api-version=2022-04-01$/u.test(args[args.indexOf('--url') + 1] ?? '')) return null;
    const assignment = /^https:\/\/management\.azure\.com\/subscriptions\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\/resourceGroups\/[a-z0-9-]+\/providers\/(?:Microsoft\.ContainerRegistry\/registries\/[a-z0-9]+|Microsoft\.Insights\/dataCollectionRules\/[a-z0-9-]+|Microsoft\.OperationalInsights\/workspaces\/[a-z0-9-]+)\/providers\/Microsoft\.Authorization\/roleAssignments\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\?api-version=2022-04-01$/iu.exec(args[args.indexOf('--url') + 1] ?? '');
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 && code === 'RoleAssignmentNotFound' &&
        assignment && sameId(assignment[1], args[args.indexOf('--subscription') + 1])) return null;
    const queueAssignment = /^https:\/\/management\.azure\.com\/subscriptions\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\/resourceGroups\/missionspec-[a-z0-9]{2,10}-telemetry\/providers\/Microsoft\.Storage\/storageAccounts\/msrtq[a-z0-9]{8,16}\/queueServices\/default\/queues\/telemetry-events-v1\/providers\/Microsoft\.Authorization\/roleAssignments\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\?api-version=2022-04-01$/iu.exec(args[args.indexOf('--url') + 1] ?? '');
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 && code === 'RoleAssignmentNotFound' &&
        queueAssignment && sameId(queueAssignment[1], args[args.indexOf('--subscription') + 1])) return null;
    const nspResource = /^https:\/\/management\.azure\.com\/subscriptions\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\/resourceGroups\/(missionspec-[a-z0-9]{2,10})-telemetry\/providers\/Microsoft\.Network\/networkSecurityPerimeters\/\2-queue-[a-z0-9]{8,16}(?:\/(?:resourceAssociations\/queue-storage-v1|profiles\/queue-storage-v1(?:\/accessRules\/same-subscription-v1)?))?\?api-version=2025-09-01$/iu.exec(args[args.indexOf('--url') + 1] ?? '');
    const storageNspConfiguration = /^https:\/\/management\.azure\.com\/subscriptions\/([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\/resourceGroups\/missionspec-[a-z0-9]{2,10}-telemetry\/providers\/Microsoft\.Storage\/storageAccounts\/msrtq[a-z0-9]{8,16}\/networkSecurityPerimeterConfigurations\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.queue-storage-v1\?api-version=2025-01-01$/iu.exec(args[args.indexOf('--url') + 1] ?? '');
    const nspAbsent = nspResource ?? storageNspConfiguration;
    if (args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'GET' && status === 404 && code === 'NotFound' &&
        nspAbsent && sameId(nspAbsent[1], args[args.indexOf('--subscription') + 1])) return null;
    const safe = new Error('ARM_OPERATION_FAILED'); safe.armCode = code; safe.httpStatus = status;
    safe.diagnostics = processFailureMetadata(error, timeout, performance.now() - started, azureStep(args), status, code);
    throw safe;
  }
}
function azureStep(args) {
  if (args[0] === 'deployment' && ['group', 'sub'].includes(args[1]) && ['validate', 'what-if'].includes(args[2])) return `deployment.${args[1]}.${args[2]}`;
  if (args[0] === 'rest' && ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(args[args.indexOf('--method') + 1])) return `arm.${args[args.indexOf('--method') + 1].toLowerCase()}`;
  return 'azure-cli';
}
export function processFailureMetadata(error, timeoutMs, elapsedMs, step, httpStatus = null, armCode = null) {
  const killed = error?.killed === true;
  return { step, kind: killed && elapsedMs >= timeoutMs ? 'process-timeout' : httpStatus !== null ? 'http-error' : 'process-or-response-error',
    configuredTimeoutMs: timeoutMs, elapsedMs, killed, timeoutObserved: killed && elapsedMs >= timeoutMs,
    processCode: Number.isInteger(error?.code) ? error.code : typeof error?.code === 'string' && /^[A-Z_]+$/u.test(error.code) ? error.code : null,
    signal: ['SIGTERM', 'SIGKILL', 'SIGINT'].includes(error?.signal) ? error.signal : null, httpStatus, armCode };
}
export function safeOperationFailure(error) {
  const d = error?.diagnostics;
  return { code: typeof error?.message === 'string' && /^[A-Z_]+$/u.test(error.message) ? error.message : 'OPERATION_FAILED',
    armCode: typeof error?.armCode === 'string' && /^[A-Za-z][A-Za-z0-9]{0,127}$/u.test(error.armCode) ? error.armCode : null,
    httpStatus: Number.isInteger(error?.httpStatus) && error.httpStatus >= 100 && error.httpStatus <= 599 ? error.httpStatus : null,
    bridgeCode: typeof error?.bridgeCode === 'string' && /^[A-Z_]+$/u.test(error.bridgeCode) ? error.bridgeCode : null,
    diagnostics: d ? {
      step: typeof d.step === 'string' && /^(?:what-if\.(?:start|poll|region)|deployment\.(?:group|sub)\.(?:validate|what-if)|arm\.(?:get|post|put|patch|delete)|azure-cli)$/u.test(d.step) ? d.step : 'unclassified',
      kind: ['process-timeout', 'http-error', 'process-or-response-error'].includes(d.kind) ? d.kind : 'unclassified',
      configuredTimeoutMs: Number.isFinite(d.configuredTimeoutMs) ? d.configuredTimeoutMs : null,
      elapsedMs: Number.isFinite(d.elapsedMs) ? d.elapsedMs : null, killed: d.killed === true, timeoutObserved: d.timeoutObserved === true,
      processCode: Number.isInteger(d.processCode) ? d.processCode : typeof d.processCode === 'string' && /^[A-Z_]+$/u.test(d.processCode) ? d.processCode : null,
      signal: ['SIGTERM', 'SIGKILL', 'SIGINT'].includes(d.signal) ? d.signal : null,
    } : null };
}
export function whatIfOperationUrl(c, value, pinned) {
  if (typeof value !== 'string' || value.length > 8192 || /[%\\#\r\n]/u.test(value)) fail('WHAT_IF_LOCATION_INVALID');
  const text = value.startsWith('/subscriptions/') ? 'https://management.azure.com' + value : value;
  if (!text.startsWith('https://management.azure.com/')) fail('WHAT_IF_LOCATION_INVALID');
  let url;
  try { url = new URL(text); } catch { fail('WHAT_IF_LOCATION_INVALID'); }
  if (url.protocol !== 'https:' || url.host !== 'management.azure.com' || url.username || url.password || url.hash ||
      url.pathname.includes('//') || value.includes('/../') || value.includes('/./')) fail('WHAT_IF_LOCATION_INVALID');
  const entries = [...url.searchParams], query = Object.fromEntries(entries);
  if (entries.length !== Object.keys(query).length || query['api-version'] !== WHAT_IF_API) fail('WHAT_IF_OPERATION_API_INVALID');
  const prefix = `/subscriptions/${c.subscriptionId}`;
  const opaque = new RegExp(`^${prefix}/operationresults/[A-Za-z0-9_-]{16,1024}$`, 'iu').test(url.pathname);
  if (opaque) {
    if (!isDeepStrictEqual(Object.keys(query).sort(), ['api-version', 'c', 'h', 's', 't']) ||
        !/^\d{10,20}$/u.test(query.t) || !/^[A-Za-z0-9_-]{1,4096}$/u.test(query.c) ||
        !/^[A-Za-z0-9_-]{1,1024}$/u.test(query.s) || !/^[A-Za-z0-9_-]{43}$/u.test(query.h)) fail('WHAT_IF_OPERATION_CONTEXT_INVALID');
  } else {
    const region = c.location;
    const paths = [`${prefix}/locations/${region}/operationresults/`,
      `${prefix}/providers/Microsoft.Resources/locations/${region}/operationResults/`,
      `${prefix}/providers/Microsoft.Resources/locations/${region}/whatIfOperationResults/`];
    if (entries.length !== 1 || !paths.some(path => url.pathname.toLowerCase().startsWith(path.toLowerCase()) &&
        /^[A-Za-z0-9-]{16,128}$/u.test(url.pathname.slice(path.length)))) fail('WHAT_IF_OPERATION_PATH_INVALID');
  }
  if (pinned !== undefined && text !== pinned) fail('WHAT_IF_OPERATION_HANDLE_CHANGED');
  return text;
}
async function azureCliPython() {
  for (const entry of (process.env.PATH ?? '').split(delimiter).filter(isAbsolute)) {
    let launcher;
    try { launcher = await realpath(resolve(entry, 'az')); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    const handle = await open(launcher, constants.O_RDONLY | constants.O_NOFOLLOW);
    let text;
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o022) || info.size > 8192 || ![0, Number(privateOwner())].includes(info.uid)) fail('TRUSTED_AZURE_CLI_REQUIRED');
      text = await handle.readFile('utf8');
    } finally { await handle.close(); }
    const match = /^#!\/usr\/bin\/env bash\nAZ_INSTALLER=HOMEBREW (\/[A-Za-z0-9_./@-]+\/python) -Im azure\.cli "\$@"\n?$/u.exec(text);
    if (!match) fail('AZURE_CLI_RUNTIME_QUALIFICATION_REQUIRED');
    await realpath(match[1]);
    return match[1]; // Keep the CLI virtual environment, rather than executing its resolved base interpreter.
  }
  fail('AZURE_CLI_RUNTIME_UNAVAILABLE');
}
export function whatIfRequestContext(c, phase) {
  if (phase.kind === 'fixed-private-link-control-phase') return privateLinkWhatIfContext(c, phase);
  if (phase.kind === 'fixed-private-link-runtime-phase') return privateLinkRuntimeWhatIfContext(c, phase);
  const r = ids(c), scope = ['project-budget', 'upload-role', 'queue-role'].includes(phase.phase) ? 'subscription' : 'group';
  const instance = phase.windowInstance ?? (phase.phase === 'nsp-subscription-readmit' ? phase.instance : undefined);
  if ([...TOGGLE_PHASES, ...IMAGE_PHASES].includes(phase.phase)) validateWindowInstance(c, phase.windowInstance);
  if (phase.scope !== (scope === 'subscription' ? r.sub : r.group) ||
      phase.deploymentId !== `${phase.scope}/providers/Microsoft.Resources/deployments/${deploymentName(c, phase.phase, instance)}`) fail('FIXED_WHAT_IF_PHASE_REQUIRED');
  const inspect = value => {
    if (typeof value === 'string' && /^\s*\[/u.test(value)) fail('STATIC_WHAT_IF_TEMPLATE_REQUIRED');
    if (Array.isArray(value)) value.forEach(inspect);
    else if (value && typeof value === 'object') {
      if (Object.hasOwn(value, 'templateLink') || Object.hasOwn(value, 'parametersLink')) fail('INLINE_WHAT_IF_REQUIRED');
      Object.values(value).forEach(inspect);
    }
  };
  inspect(phase.template);
  const body = JSON.stringify({ ...(scope === 'subscription' ? { location: c.location } : {}), properties: {
    mode: 'Incremental', parameters: {}, template: phase.template, whatIfSettings: { resultFormat: 'FullResourcePayloads' } } });
  const fields = { subscriptionId: c.subscriptionId, tenantId: c.tenantId, location: c.location,
    namePrefix: c.namePrefix, runId: c.runId, phase: phase.phase, scope, phaseSha256: digest(json(phase)), bodySha256: digest(body),
    windowInstanceId: instance?.id ?? null, predecessorSha256: instance?.predecessorSha256 ?? null };
  return { ...fields, contextSha256: digest(Object.values(fields).join('\n')), body };
}
export async function authenticatedWhatIfRequest(context, directory, operation, run = execute, locate = azureCliPython) {
  const { action, pollUrl, initialResponseFile, timeoutMs, deadlineMs, beforeDispatch } = operation;
  if (!['start', 'poll'].includes(action) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15000 ||
      !Number.isSafeInteger(deadlineMs) || typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch)) fail('BOUNDED_WHAT_IF_REQUEST_REQUIRED');
  if (action === 'poll') whatIfOperationUrl({ subscriptionId: context.subscriptionId, location: context.location }, pollUrl);
  else if (pollUrl !== null || initialResponseFile !== null) fail('WHAT_IF_START_HANDLE_FORBIDDEN');
  const id = randomUUID(), requestFile = `whatif-request-${id}.json`, responseFile = `whatif-response-${id}.json`;
  const { body, ...fields } = context;
  await saveImmutable(directory, requestFile, { version: Object.hasOwn(fields, 'runtimeTargetSha256') ? 4
    : Object.hasOwn(fields, 'migrationKey') ? 3 : 2,
    ...fields, action, body: action === 'start' ? body : null,
    pollUrl, initialResponseFile, timeoutMs, deadlineMs });
  const started = performance.now();
  try {
    const python = await locate();
    if (beforeDispatch() !== undefined) fail('WHAT_IF_DISPATCH_GUARD_INVALID');
    const remaining = Math.min(timeoutMs - (performance.now() - started), deadlineMs - Date.now());
    if (remaining <= 0) fail('WHAT_IF_REQUEST_DEADLINE');
    const env = { ...process.env, AZURE_CORE_COLLECT_TELEMETRY: 'false', AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no', PYTHONDONTWRITEBYTECODE: '1' };
    for (const key of ['AZURE_CLI_DISABLE_CONNECTION_VERIFICATION', 'PYTHONHTTPSVERIFY', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
      'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) delete env[key];
    const result = await run(python, ['-I', '-B', resolve(here, 'arm-whatif.py'), resolve(directory, requestFile), resolve(directory, responseFile)],
      { cwd: resolve(here, '../../..'), env, timeout: Math.max(1, Math.floor(remaining)), maxBuffer: 8192 });
    if (result.stdout.trim() !== 'PRIVATE_WHATIF_RESPONSE_SAVED') fail('WHAT_IF_BRIDGE_OUTPUT_INVALID');
    return { ...await load(directory, responseFile), responseFile };
  } catch (error) {
    if (['WHAT_IF_CANCELLED', 'WHAT_IF_DEADLINE_EXCEEDED', 'WHAT_IF_REQUEST_DEADLINE'].includes(error.message)) throw error;
    const safe = new Error('WHAT_IF_REQUEST_FAILED');
    safe.diagnostics = processFailureMetadata(error, timeoutMs, performance.now() - started, `what-if.${action}`);
    if (typeof error.stderr === 'string' && /^[A-Z_]+\n?$/u.test(error.stderr)) safe.bridgeCode = error.stderr.trim();
    throw safe;
  }
}
export async function asyncWhatIf(c, phase, directory, options = {}) {
  const now = options.now ?? Date.now, sleep = options.sleep ?? pause, cancelled = options.cancelled ?? (() => false);
  const deadline = options.deadline ?? now() + 120000, context = whatIfRequestContext(c, phase);
  const request = options.request ?? (operation => authenticatedWhatIfRequest(context, directory, operation));
  const trace = { version: 1, phaseSha256: digest(json(phase)), contextSha256: context.contextSha256,
    region: c.location, regionBinding: 'Verified resource-group location or exact subscription-start location; opaque ARM handles are not decoded as regions.',
    startedAt: new Date(now()).toISOString(), deadlineAt: new Date(deadline).toISOString(), calls: [], startPosts: 0 };
  const record = options.record ?? (value => save(directory, `${phase.phase}-async-what-if-trace.json`, value));
  const guard = () => {
    if (cancelled()) fail('WHAT_IF_CANCELLED');
    if (!Number.isSafeInteger(deadline) || now() >= deadline) fail('WHAT_IF_DEADLINE_EXCEEDED');
  };
  let action = 'start', location, rawLocation, initialResponseFile, retryMs = 0;
  try {
    for (let poll = 0; poll < WHAT_IF_MAX_POLLS; poll++) {
      guard();
      if (retryMs) {
        if (retryMs >= deadline - now()) fail('WHAT_IF_RETRY_AFTER_EXCEEDS_DEADLINE');
        await sleep(retryMs); guard();
      }
      const call = { step: `what-if.${action}`, startedAt: new Date(now()).toISOString(), timeoutMs: Math.min(15000, deadline - now()) };
      trace.calls.push(call); await record(trace); guard();
      const timeoutMs = Math.min(call.timeoutMs, deadline - now());
      if (action === 'start') trace.startPosts++;
      const requestStarted = now();
      const response = await request({ action, pollUrl: action === 'start' ? null : rawLocation,
        initialResponseFile: initialResponseFile ?? null, timeoutMs, deadlineMs: deadline, beforeDispatch: guard });
      call.elapsedMs = now() - requestStarted;
      guard();
      call.completedAt = new Date(now()).toISOString(); call.statusCode = response?.statusCode;
      closed(response, ['version', 'statusCode', 'headers', 'body', 'bodyParseError', 'contextSha256', 'responseFile', 'step', 'verifiedRegion']);
      if (response.version !== 1 || response.contextSha256 !== context.contextSha256 || !Number.isInteger(response.statusCode) ||
          response.statusCode < 100 || response.statusCode > 599 || typeof response.bodyParseError !== 'boolean' ||
          !/^whatif-response-[0-9a-f-]+\.json$/u.test(response.responseFile ?? '') ||
          !response.headers || typeof response.headers !== 'object' || Array.isArray(response.headers) ||
          !['what-if.region', 'what-if.start', 'what-if.poll'].includes(response.step) ||
          Object.keys(response.headers).some(k => !['location', 'retry-after', 'azure-asyncoperation'].includes(k))) fail('WHAT_IF_RESPONSE_INVALID');
      call.responseStep = response.step;
      if (response.statusCode >= 300 && response.statusCode < 400) fail('WHAT_IF_REDIRECT_FORBIDDEN');
      if (![200, 202].includes(response.statusCode)) {
        const error = new Error('WHAT_IF_HTTP_FAILED'); error.httpStatus = response.statusCode;
        const code = response.body?.error?.code;
        error.armCode = typeof code === 'string' && /^[A-Za-z][A-Za-z0-9]{0,127}$/u.test(code) ? code : 'Unclassified';
        throw error;
      }
      if (response.step !== `what-if.${action}` || response.verifiedRegion !== c.location) fail('WHAT_IF_REGION_OR_STEP_MISMATCH');
      if (response.bodyParseError) fail('WHAT_IF_NON_JSON_RESPONSE');
      if (Object.hasOwn(response.headers, 'azure-asyncoperation')) fail('WHAT_IF_UNREVIEWED_ASYNC_HEADER');
      if (action === 'start' && response.statusCode === 202) {
        rawLocation = response.headers.location;
        location = whatIfOperationUrl(c, rawLocation);
        if (!/^whatif-response-[0-9a-f-]+\.json$/u.test(response.responseFile)) fail('WHAT_IF_START_RECEIPT_REQUIRED');
        initialResponseFile = response.responseFile;
        trace.operationHandleSha256 = digest(location);
      } else if (response.headers.location !== undefined) whatIfOperationUrl(c, response.headers.location, location);
      const status = response.body?.status;
      if (['Failed', 'Canceled', 'Cancelled'].includes(status) || response.body?.error) {
        const error = new Error('WHAT_IF_OPERATION_FAILED'); error.httpStatus = response.statusCode;
        const code = response.body?.error?.code;
        error.armCode = typeof code === 'string' && /^[A-Za-z][A-Za-z0-9]{0,127}$/u.test(code) ? code : 'Unclassified';
        throw error;
      }
      if (response.statusCode === 200 && status === 'Succeeded') {
        if (!response.body.properties || !Array.isArray(response.body.properties.changes) ||
            response.body.properties.nextLink || response.body.nextLink) fail('WHAT_IF_RESULT_INCOMPLETE');
        if (QUEUE_PHASES.includes(phase.phase) && response.body.properties.error) fail('WHAT_IF_OPERATION_FAILED');
        await record({ ...trace, outcome: 'succeeded', completedAt: new Date(now()).toISOString() }); guard();
        return { raw: response.body, result: { status, changes: response.body.properties.changes } };
      }
      if (response.statusCode === 200 && !['Accepted', 'Running', 'InProgress'].includes(status)) fail('WHAT_IF_UNKNOWN_OPERATION_STATUS');
      if (response.statusCode === 202 && status !== undefined && !['Accepted', 'Running', 'InProgress'].includes(status)) fail('WHAT_IF_UNKNOWN_OPERATION_STATUS');
      if (!location || !initialResponseFile) fail('WHAT_IF_OPERATION_HANDLE_REQUIRED');
      const retry = response.headers['retry-after'];
      if (retry !== undefined && (typeof retry !== 'string' || !/^\d{1,6}$/u.test(retry))) fail('WHAT_IF_RETRY_AFTER_INVALID');
      retryMs = retry === undefined ? 1000 : Math.max(1000, Number(retry) * 1000);
      action = 'poll';
    }
    fail('WHAT_IF_POLL_LIMIT_EXCEEDED');
  } catch (error) {
    trace.outcome = 'failed'; trace.failureCode = /^[A-Z_]+$/u.test(error.message) ? error.message : 'WHAT_IF_FAILED';
    trace.failure = { step: trace.calls.at(-1)?.step ?? 'what-if.start', ...safeOperationFailure(error) };
    await record(trace);
    throw error;
  }
}
export function transport(c, phase, directory, invoke = az, topology, policyReads = new Set()) {
  const r = ids(c);
  const forbiddenOperations = new Set(['listkeys', 'listsecrets', 'listaccountsas', 'listservicesas', 'regeneratekey', 'register']);
  if (topology) verifyQueueTopology(c, topology);
  const diagnosticTargets = [r.workspace, r.environment, r.app, ...(topology ? [topology.ids.account, topology.ids.service] : [])]
    .map(id => id + '/providers/Microsoft.Insights/diagnosticSettings');
  return async (method, id, version, body, filter, beforeDispatch, beforeAssignmentWrite, beforeToggleWrite) => {
    const policyRead = method === 'GET' && body === undefined && policyReads.has(json([id, version, filter ?? null]));
    const diagnosticRead = diagnosticTargets.includes(id) && method === 'GET' && version === DIAGNOSTIC_API && body === undefined && filter === undefined;
    const queueOperationsRead = topology && id === '/providers/Microsoft.Storage/operations' && method === 'GET' &&
      version === '2025-01-01' && body === undefined && filter === undefined;
    if (!['GET', 'POST', 'PUT'].includes(method) || (!queueOperationsRead && !policyRead && id !== r.sub && !id.startsWith(`${r.sub}/`)) ||
        /[?#\\]|\.\.|%/u.test(id) || (!/^\d{4}-\d{2}-\d{2}$/u.test(version) && !diagnosticRead && !policyRead) ||
        (id.toLowerCase().includes('/providers/microsoft.insights/diagnosticsettings') && !diagnosticRead) ||
        id.split('/').some(component => forbiddenOperations.has(component.toLowerCase()))) fail('ARM_SCOPE_FORBIDDEN');
    if (method === 'PUT' && id !== phase.deploymentId) fail('FIXED_PHASE_PUT_ONLY');
    if (method === 'PUT' && (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch))) fail('DISPATCH_GUARD_REQUIRED');
    if (method === 'PUT' && phase.phase === 'assignments' && typeof beforeAssignmentWrite !== 'function') fail('ASSIGNMENT_ROLE_READBACK_REQUIRED');
    if (beforeAssignmentWrite !== undefined && (method !== 'PUT' || phase.phase !== 'assignments')) fail('ASSIGNMENT_ROLE_READBACK_ONLY');
    if (method === 'PUT' && [...TOGGLE_PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES].includes(phase.phase) && typeof beforeToggleWrite !== 'function') fail('PAIRED_TOGGLE_GUARD_REQUIRED');
    if (beforeToggleWrite !== undefined && (method !== 'PUT' || ![...TOGGLE_PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES].includes(phase.phase))) fail('FIXED_TOGGLE_WRITE_ONLY');
    if (method === 'POST' && id !== `${r.sub}/providers/Microsoft.ContainerRegistry/checkNameAvailability`) fail('NONMUTATING_POST_ONLY');
    const inventoryMetadata = method === 'GET' && id === `${r.group}/resources` && version === '2021-04-01' &&
      body === undefined && filter === '$expand=createdTime,changedTime';
    if (filter && !filter.startsWith('$filter=') && !inventoryMetadata && !policyRead) fail('QUERY_NOT_SUPPORTED');
    const args = ['rest', '--method', method, '--url', `https://management.azure.com${id}?api-version=${version}${filter ? '&' + filter : ''}`,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'];
    let name;
    if (body !== undefined) {
      name = `request-${randomUUID()}.json`; await save(directory, name, body);
      args.push('--body', '@' + resolve(directory, name), '--headers', 'Content-Type=application/json');
    }
    try {
      if (method === 'PUT' && phase.phase === 'assignments') {
        if (beforeDispatch() !== undefined) fail('DISPATCH_GUARD_REQUIRED');
        await beforeAssignmentWrite();
      }
      if (method === 'PUT' && [...TOGGLE_PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES].includes(phase.phase)) await beforeToggleWrite();
      // No await between the guard and transport invocation, including body-file preparation.
      if (method === 'PUT' && beforeDispatch() !== undefined) fail('DISPATCH_GUARD_REQUIRED');
      const result = await invoke(args);
      if (result?.nextLink && !policyRead) fail('PAGINATION_REQUIRES_REVIEW');
      return result;
    } finally { if (name) await rm(resolve(directory, name)); }
  };
}
export function stableReadback(input) {
  if (Array.isArray(input)) return input.map(stableReadback);
  if (!input || typeof input !== 'object') return input;
  return Object.fromEntries(Object.entries(input).filter(([key]) => key !== 'etag').map(([key, value]) => [key, stableReadback(value)]));
}
export function verifyScannerAdoption(c, origin, adoption) {
  closed(adoption, ['version', 'kind', 'originSha256', 'resourceId', 'apiVersion', 'beforeSha256', 'after', 'evidence', 'decision']);
  closed(adoption.decision, ['action', 'recordedAt', 'userInstructionSha256']);
  const r = ids(c), item = origin.resources.find(v => sameId(v.id, adoption.resourceId));
  if (adoption.version !== 1 || adoption.kind !== 'exact-storage-scanner-instance' ||
      digest(json(origin)) !== c.originSha256 || adoption.originSha256 !== c.originSha256 ||
      digest(json(adoption)) !== c.scannerAdoptionSha256 || !item ||
      !item.id.startsWith(`${r.stateGroup}/providers/Microsoft.Storage/storageAccounts/`) ||
      item.id.split('/').length !== 9 || item.apiVersion !== adoption.apiVersion ||
      digest(json(item.snapshot)) !== adoption.beforeSha256 ||
      adoption.decision.action !== 'preserve-exact-storage-scanner-instance' ||
      !/^[0-9a-f]{64}$/u.test(adoption.decision.userInstructionSha256) ||
      !Number.isFinite(Date.parse(adoption.decision.recordedAt))) fail('SCANNER_ADOPTION_INVALID');
  const expected = structuredClone(item.snapshot), p = expected.properties;
  if (p.publicNetworkAccess !== 'Disabled' || p.allowSharedKeyAccess !== false ||
      p.networkAcls?.bypass !== 'None' || p.networkAcls.defaultAction !== 'Deny' ||
      ['ipRules', 'ipv6Rules', 'virtualNetworkRules', 'resourceAccessRules'].some(k => (p.networkAcls[k]?.length ?? 0) !== 0)) fail('SCANNER_ADOPTION_INVALID');
  p.networkAcls.resourceAccessRules = [{ tenantId: c.tenantId,
    resourceId: `${r.sub}/providers/Microsoft.Security/datascanners/StorageDataScanner` }];
  if (!isDeepStrictEqual(stableReadback(expected), stableReadback(adoption.after))) fail('SCANNER_ADOPTION_INVALID');
  const e = adoption.evidence;
  closed(e, ['activitySha256', 'correlationId', 'events', 'actorResource', 'roleDefinition', 'roleAssignment', 'servicePrincipal']);
  const actorId = `${r.sub}/providers/Microsoft.Security/pricings/StorageAccounts/securityOperators/DefenderForStorageSecurityOperator`;
  const roleId = `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/0f641de8-0b88-4198-bdef-bd8b45ceba96`;
  const principal = e.actorResource?.identity?.principalId;
  if (!/^[0-9a-f-]{36}$/u.test(principal) || !sameId(e.actorResource.id, actorId) ||
      e.actorResource.identity.tenantId !== c.tenantId || !sameId(e.roleDefinition?.id, roleId) ||
      e.roleDefinition.properties?.roleName !== 'Defender for Storage Scanner Operator' ||
      !['Microsoft.Storage/storageAccounts/write', 'Microsoft.Security/defenderForStorageSettings/write'].every(action =>
        e.roleDefinition.properties.permissions?.some(v => v.actions?.some(a => a.toLowerCase() === action.toLowerCase()))) ||
      e.roleAssignment?.properties?.principalId !== principal || !sameId(e.roleAssignment.properties.roleDefinitionId, roleId) ||
      !sameId(e.roleAssignment.properties.scope, r.sub) || e.roleAssignment.properties.condition ||
      e.servicePrincipal?.id !== principal || e.servicePrincipal.servicePrincipalType !== 'ManagedIdentity' ||
      e.servicePrincipal.displayName !== 'StorageAccounts/securityOperators/DefenderForStorageSecurityOperator' ||
      !/^[0-9a-f]{64}$/u.test(e.activitySha256) || !Array.isArray(e.events) || !e.events.length ||
      e.events.some(v => v.correlationId !== e.correlationId || v.caller !== principal ||
        v.appId !== e.servicePrincipal.appId || !sameId(v.actorResourceId, actorId)) ||
      !e.events.some(v => sameId(v.resourceId, item.id) && v.operation.toLowerCase() === 'microsoft.storage/storageaccounts/write' && v.status === 'Succeeded')) fail('SCANNER_ATTRIBUTION_INVALID');
  return { id: item.id, snapshot: expected };
}
export async function verifyOrigin(origin, arm, c, adoption) {
  if (origin.version !== 1 || origin.adoptionDecision?.accepted !== true || origin.adoptionDecision.opaqueTagIsUTC !== false ||
      origin.latestLedger.sessions.length !== 0 || origin.latestLedgerSha256 !== digest(json(origin.latestLedger))) fail('ORIGIN_NOT_RECONCILED');
  const scanner = verifyScannerAdoption(c, origin, adoption);
  await readBatch(origin.resources, async item => {
    const actual = await arm('GET', item.id, item.apiVersion);
    const expected = sameId(item.id, scanner.id) ? scanner.snapshot : item.snapshot;
    if (!sameId(actual?.id, item.id) || !isDeepStrictEqual(stableReadback(actual), stableReadback(expected))) fail('FOUNDATION_DRIFT');
  });
  await readBatch(origin.absent, async item => {
    if (await arm('GET', item.id, item.apiVersion)) fail('RETIRED_OPERATOR_RESOURCE_PRESENT');
  });
  const dep = await arm('GET', origin.bootstrap.id, '2022-09-01');
  if (dep?.properties?.provisioningState !== 'Succeeded' ||
      ['correlationId', 'timestamp', 'templateHash'].some(k => dep.properties[k] !== origin.bootstrap[k])) fail('ORIGINAL_CREATION_RECEIPT_CHANGED');
}
export async function publishedSourceDigest(commitSha, run = execute) {
  if (!/^[0-9a-f]{40}$/u.test(commitSha)) fail('PUBLISHED_ORIGIN_INVALID');
  const options = { cwd: resolve(here, '../../..'), encoding: 'buffer', maxBuffer: MAX_PRIVATE_ARTIFACT_BYTES };
  try {
    await run('git', ['merge-base', '--is-ancestor', commitSha, 'HEAD'], options);
    const file = async path => (await run('git', ['--no-pager', 'show', `${commitSha}:${path}`], options)).stdout;
    const hash = createHash('sha256');
    let controller;
    for (const name of ['definition.mjs', 'policy.mjs', 'controller.mjs']) {
      const bytes = await file(`infrastructure/arm/telemetry/${name}`);
      if (name === 'controller.mjs') controller = bytes.toString();
      hash.update(name).update(bytes);
    }
    const bridgePath = 'infrastructure/arm/telemetry/arm-whatif.py';
    const bridge = (await run('git', ['ls-tree', '--name-only', commitSha, '--', bridgePath], options)).stdout.toString().trim();
    if (bridge) {
      if (bridge !== bridgePath) fail('PUBLISHED_ORIGIN_INVALID');
      hash.update('arm-whatif.py').update(await file(bridgePath));
    }
    const upgradePath = 'infrastructure/arm/telemetry/receiver-upgrade.mjs';
    const upgrade = (await run('git', ['ls-tree', '--name-only', commitSha, '--', upgradePath], options)).stdout.toString().trim();
    if (upgrade) {
      if (upgrade !== upgradePath) fail('PUBLISHED_ORIGIN_INVALID');
      hash.update('receiver-upgrade.mjs').update(await file(upgradePath));
    }
    const queuePath = 'infrastructure/arm/telemetry/durable-queue.mjs';
    const queue = (await run('git', ['ls-tree', '--name-only', commitSha, '--', queuePath], options)).stdout.toString().trim();
    if (queue) {
      if (queue !== queuePath) fail('PUBLISHED_ORIGIN_INVALID');
      hash.update('durable-queue.mjs').update(await file(queuePath));
    }
    // Historical controllers did not import this module or include it in their digest.
    if (controller.includes("from './effective-policy.mjs'")) {
      hash.update('effective-policy.mjs').update(await file('infrastructure/arm/telemetry/effective-policy.mjs'));
    }
    let privateLinkController;
    for (const name of ['queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs', 'queue-defender.mjs',
      'private-link.mjs', 'private-link-whatif.mjs', 'private-link-controller.mjs', 'private-link-readback.mjs',
      'private-link-runtime.mjs']) {
      const dependency = name === 'private-link-readback.mjs' ? 'private-link-controller.mjs' : name;
      if (controller.includes(`from './${dependency}'`)) {
        const bytes = await file(`infrastructure/arm/telemetry/${name}`);
        if (name === 'private-link-controller.mjs') privateLinkController = bytes.toString();
        hash.update(name).update(bytes);
      }
    }
    if (controller.includes("from './private-link-runtime.mjs'")) {
      hash.update('private-link-exec.py').update(await file('infrastructure/arm/telemetry/private-link-exec.py'));
    }
    if (controller.includes("from './private-link-artifacts.mjs'")) {
      hash.update('private-link-artifacts.mjs').update(await file('infrastructure/arm/telemetry/private-link-artifacts.mjs'));
    }
    if (controller.includes("from './private-link-nsg-adoption.mjs'") ||
        privateLinkController?.includes("from './private-link-nsg-adoption.mjs'")) {
      hash.update('private-link-nsg-adoption.mjs').update(await file('infrastructure/arm/telemetry/private-link-nsg-adoption.mjs'));
    }
    const schema = JSON.parse(await file('assets/schemas/telemetry-event.schema.json'));
    const columns = JSON.parse(await file('services/telemetry-ingest/schema/storage-columns.json'));
    hash.update(json({ schema, columns, schemaSha256: digest(json(schema)), columnsSha256: digest(json(columns)) }));
    return hash.digest('hex');
  } catch { fail('PUBLISHED_ORIGIN_UNAVAILABLE'); }
}
export async function verifyReceiverSource(candidate, run = execute, lookup = publishedSourceDigest) {
  const source = candidate?.profile?.source;
  if (!/^[0-9a-f]{40}$/u.test(source?.commitSha ?? '')) fail('RECEIVER_SOURCE_UNAVAILABLE');
  const options = { cwd: resolve(here, '../../..'), encoding: 'buffer', maxBuffer: MAX_PRIVATE_ARTIFACT_BYTES };
  try {
    closed(source.files, receiverSourceInputs(candidate.profile));
    await run('git', ['merge-base', '--is-ancestor', source.commitSha, 'HEAD'], options);
    for (const [path, sha256] of Object.entries(source.files)) {
      const bytes = (await run('git', ['--no-pager', 'show', `${source.commitSha}:${path}`], options)).stdout;
      if (digest(bytes) !== sha256) fail('RECEIVER_SOURCE_FILES_CHANGED');
    }
    if (await lookup(candidate.review.policyCommitSha, run) !== candidate.review.sourceSha256) fail('RECEIVER_POLICY_SOURCE_CHANGED');
  } catch { fail('RECEIVER_SOURCE_UNAVAILABLE'); }
  if (candidate.version === 2) await verifyReceiverSource(candidate.priorCandidate, run, lookup);
}
async function verifyPublishedOrigins(c, foundation, origins, lookup = publishedSourceDigest, contract) {
  verifyExecutionOrigins(c, foundation, origins, contract ?? await storageContract());
  await readBatch(origins.records, async record => {
    if (await lookup(record.publication.commitSha) !== record.publication.sourceSha256) fail('PUBLISHED_SOURCE_MISMATCH');
  });
}
export async function readPrivacy(c, phase, arm) {
  const diagnosticEntries = await readBatch(phase.resources.filter(v =>
    ['Microsoft.OperationalInsights/workspaces', 'Microsoft.App/managedEnvironments', 'Microsoft.App/containerApps'].includes(v.type)), async descriptor => {
    const value = await arm('GET', descriptor.id + '/providers/Microsoft.Insights/diagnosticSettings', DIAGNOSTIC_API);
    if (!Array.isArray(value?.value) || value.nextLink || value.value.length) fail('DIAGNOSTIC_ROUTE_DRIFT');
    return [descriptor.id, value];
  });
  const diagnostics = Object.fromEntries(diagnosticEntries);
  let exports = null;
  if (['core', 'workspace-access', 'data', 'assignments', 'disabled-app', ...TOGGLE_PHASES, ...IMAGE_PHASES].includes(phase.phase)) {
    exports = await arm('GET', ids(c).workspace + '/dataExports', '2020-08-01');
    if (!Array.isArray(exports?.value) || exports.nextLink || exports.value.length) fail('WORKSPACE_EXPORT_DRIFT');
  }
  return { diagnostics, exports };
}
export async function readAssignmentRoleDefinitions(c, phase, arm, uploadRoleReceipt) {
  const targets = assignmentRoleTargets(c), r = ids(c);
  if (phase.phase !== 'assignments' || phase.resources.length !== targets.length) fail('EXACT_ASSIGNMENT_SCOPES_REQUIRED');
  if (uploadRoleReceipt?.qualified !== true || uploadRoleReceipt.configSha256 !== digest(json(c)) ||
      !uploadRoleReceipt.resources?.[r.uploadRole]) fail('UPLOAD_ROLE_RECEIPT_REQUIRED');
  const roles = [], readbacks = [];
  // Check the mutable custom role last, immediately before the dispatch guard in the write path.
  for (const target of targets) {
    const matches = phase.resources.filter(v => sameId(v.expected.scope, target.scope));
    const properties = matches[0]?.expected?.properties;
    if (matches.length !== 1 || !sameId(properties?.roleDefinitionId, target.roleDefinitionId) ||
        properties.principalType !== (target.scope === r.workspace ? 'User' : 'ServicePrincipal') ||
        (target.scope === r.workspace && properties.principalId !== c.operatorPrincipalId)) fail('EXACT_ASSIGNMENT_SCOPES_REQUIRED');
    const resource = await arm('GET', `${target.scope}/providers/Microsoft.Authorization/roleDefinitions/${target.roleDefinitionId.split('/').at(-1)}`, '2022-04-01');
    if (target.roleType === 'CustomRole' && !isDeepStrictEqual(executionIdentity(resource, 'Microsoft.Authorization/roleDefinitions'),
      executionIdentity(uploadRoleReceipt.resources[r.uploadRole], 'Microsoft.Authorization/roleDefinitions'))) fail('UPLOAD_ROLE_IDENTITY_CHANGED');
    roles.push(roleDefinitionSignature(c, target, resource));
    readbacks.push({ scope: target.scope, resource });
  }
  return { roles, readbacks };
}
async function readReconciledPhase(c, record, arm, context = {}) {
  const phase = record.phase;
  const [deployment, ...actuals] = await readBatch([{ id: phase.deploymentId, apiVersion: '2022-09-01' }, ...phase.resources],
    descriptor => arm('GET', descriptor.id, descriptor.apiVersion));
  const resources = {}, identityPins = {};
  verifyDeploymentIdentity(record.firstReadback.deployment, deployment);
  for (const [index, descriptor] of phase.resources.entries()) {
    const actual = actuals[index];
    let expected = descriptor.type === 'Microsoft.App/containerApps' && context.imageDescriptor ? context.imageDescriptor : descriptor;
    if (descriptor.type === 'Microsoft.App/containerApps' && context.transition) {
      const { phases, window, approvals, journals, source } = context.transition;
      const flag = verifyWindowState(c, phases, window, approvals, journals, actual, context, source);
      expected = descriptorWithFlag(descriptor, flag);
    }
    if (!(descriptor.type === 'Microsoft.App/containerApps' && context.transition)) verifyResource(c, phase, expected, actual, context);
    const pin = executionIdentity(actual, descriptor.type);
    if (!isDeepStrictEqual(pin, executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type))) fail('RESOURCE_IDENTITY_CHANGED');
    resources[descriptor.id] = actual; identityPins[descriptor.id] = pin;
  }
  return { executionOriginSha256: digest(json(record)), deployment, resources, identityPins, ...await readPrivacy(c, phase, arm) };
}
export function emptyAcrReferrers(value) {
  if (!Array.isArray(value)) {
    closed(value, ['manifests']);
    value = value.manifests;
  }
  if (!Array.isArray(value) || value.length !== 0) fail('RECEIVER_REFERRER_READBACK_REQUIRED');
  return [];
}
export async function readPublishedImage(c, imagePublication, arm, invoke = az, candidate) {
  if (candidate) verifyReceiverCandidate(c, candidate);
  const [registry, repositories] = await readBatch([
    () => arm('GET', ids(c).registry, '2023-07-01'),
    () => invoke(['acr', 'repository', 'list', '--name', c.registryName,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']),
  ], read => read());
  if (!isDeepStrictEqual(repositories, ['missionspec/telemetry-ingest'])) fail('PUBLICATION_READBACK_CHANGED');
  const commands = [
    ['list-metadata', 'missionspec/telemetry-ingest'],
    ['show', `missionspec/telemetry-ingest@${c.receiverDigest}`],
    ...(candidate ? [['show', `missionspec/telemetry-ingest@${candidate.profile.manifestDigest}`],
      ...(candidate.version === 2 ? [['show', `missionspec/telemetry-ingest@${candidate.priorCandidate.profile.manifestDigest}`]] : []),
      ...[c.receiverDigest, ...(candidate.version === 2 ? [candidate.priorCandidate.profile.manifestDigest] : []),
        candidate.profile.manifestDigest].map(d => ['list-referrers', `missionspec/telemetry-ingest@${d}`])] : []),
  ];
  const [manifests, manifest, candidateManifest, ...refs] = await readBatch(commands, ([command, name]) =>
    invoke(['acr', 'manifest', command, '--registry', c.registryName, '--name', name,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']));
  const result = { registry, repositories, manifests, manifest };
  if (candidate) {
    result.candidateManifest = candidateManifest;
    if (candidate.version === 2) result.priorManifest = refs.shift();
    result.referrers = refs.flatMap(emptyAcrReferrers);
  }
  verifyPublicationReadback(c, imagePublication, result, candidate);
  return result;
}
async function reconciliationContext(c, origins, arm, invoke, candidate) {
  const r = ids(c), hasApp = origins.records.some(v => v.phase.phase === 'disabled-app');
  const assignments = origins.records.find(v => v.phase.phase === 'assignments');
  const [workspace, ingest, pull, imagePublication, roleDefinitions] = await readBatch([
    () => origins.records.some(v => v.phase.phase === 'data') ? arm('GET', r.workspace, '2023-09-01') : null,
    () => hasApp ? arm('GET', r.ingestIdentity, '2023-01-31') : null,
    () => hasApp ? arm('GET', r.pullIdentity, '2023-01-31') : null,
    () => hasApp ? readPublishedImage(c, origins.imagePublication, arm, invoke, candidate) : null,
    async () => {
      if (!assignments) return null;
      const upload = origins.records.find(v => v.phase.phase === 'upload-role');
      const reads = await readAssignmentRoleDefinitions(c, assignments.phase, arm, upload.originalReceipt);
      const value = { checkedAt: new Date().toISOString(), ...reads, roleDefinitionsSha256: digest(json(reads.roles)) };
      if (value.roleDefinitionsSha256 !== assignments.preflight.roleDefinitionsSha256) fail('ASSIGNMENT_ROLE_DEFINITION_DRIFT');
      return value;
    },
  ], read => read());
  const identities = hasApp ? { [r.ingestIdentity]: ingest, [r.pullIdentity]: pull } : null;
  if (workspace) {
    const access = origins.records.find(v => v.phase.phase === 'workspace-access');
    if (!isDeepStrictEqual(executionIdentity(workspace),
      executionIdentity(access.firstReadback.resources[r.workspace]))) fail('RESOURCE_IDENTITY_CHANGED');
  }
  return { workspace, identities, imagePublication, roleDefinitions };
}
export function reconciliationReceiverCandidate(proposal, candidate) {
  if (![4, 5, 6].includes(proposal?.version)) return null;
  const match = [candidate, candidate?.priorCandidate].find(value => value &&
    value.publication !== null && value.publication !== undefined &&
    digest(json(value)) === proposal.receiverCandidateSha256);
  if (!match) fail('RECONCILIATION_RECEIVER_PUBLICATION_REQUIRED');
  return match;
}
function publishedReceiverCandidate(candidate) {
  const value = candidate?.version === 2 && candidate.publication === null ? candidate.priorCandidate : candidate;
  return value?.publication !== undefined && value.publication !== null ? value : null;
}
export async function collectReconciliation(c, origin, directory, evidence, invoke = az, lookup = publishedSourceDigest, options = {}) {
  const now = options.now ?? Date.now, deadline = Math.min(options.deadline ?? now() + 120000, now() + 120000);
  const policySource = await sourceDigest();
  invoke = limitReadConcurrency(boundedInvoke(deadline, invoke, now));
  const foundation = verifyFoundationBudgets(c, evidence.foundationBudgets), origins = evidence.reconciliation.origins;
  const suppliedCandidate = evidence.receiverCandidate ?? evidence.reconciliation.receiverCandidate;
  const receiverCandidate = publishedReceiverCandidate(suppliedCandidate);
  const nsp = evidence.queueRecords?.['queue-storage']?.kind === 'reviewed-queue-storage-adoption';
  const overlay = evidence.receiverUpgrade ? { receiverUpgrade: evidence.receiverUpgrade, queueRecords: evidence.queueRecords ?? {},
    ...(nsp ? { nspNetwork: evidence.nspNetwork } : {}) } : null;
  const contract = await storageContract();
  await verifyPublishedOrigins(c, foundation, origins, lookup, contract);
  if (receiverCandidate) {
    verifyReceiverCandidate(c, receiverCandidate);
    await verifyReceiverSource(receiverCandidate, options.sourceRun, lookup);
    if (!isDeepStrictEqual(receiverCandidate.legacyPublication, origins.imagePublication)) fail('RECONCILIATION_RECEIVER_PUBLICATION_REQUIRED');
  }
  if (overlay) {
    await verifyPublishedWindowPredecessor(c, overlay.receiverUpgrade, lookup, options.sourceRun);
    knownResourceIds(c, { queueRecords: overlay.queueRecords });
    await verifyPublishedQueueRecords(c, overlay.queueRecords, lookup);
    if (nsp) await verifyPublishedNspEvidence(c, overlay.nspNetwork, overlay.queueRecords['queue-storage'].topology, overlay.queueRecords['queue-storage'], lookup);
  }
  const r = ids(c), arm = transport(c, origins.records[0].phase, directory, invoke);
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account?.tenantId !== c.tenantId || account?.state !== 'Enabled' || account?.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  await verifyOrigin(origin, arm, c, evidence.scannerAdoption);
  const [policies, defender, provider] = await readBatch([
    [`${r.sub}/providers/Microsoft.Authorization/policyAssignments`, '2023-04-01'],
    [`${r.sub}/providers/Microsoft.Security/pricings`, '2024-01-01'],
    [`${r.sub}/providers/Microsoft.Insights`, '2021-04-01'],
  ], ([id, api]) => arm('GET', id, api));
  const baselineSha256 = digest(json({ policies, defender }));
  if (baselineSha256 !== origin.policyBaselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
  if (provider?.registrationState !== 'Registered' || !provider.resourceTypes?.some(v =>
    v.resourceType?.toLowerCase() === 'diagnosticsettings' && v.apiVersions?.includes(DIAGNOSTIC_API))) fail('DIAGNOSTIC_API_NOT_REGISTERED');
  const context = await reconciliationContext(c, origins, arm, invoke, receiverCandidate ?? undefined);
  const results = Object.fromEntries(await readBatch(origins.records, async record => [record.phase.phase,
    await readReconciledPhase(c, record, arm, { ...context, publication: origins.imagePublication?.receipt,
      ...(overlay ? { receiverCandidate, imageDescriptor: overlay.receiverUpgrade.phase.resources[0] } : {}) })]));
  const [stateBudget, inventory, managedGroup] = await readBatch([
    () => arm('GET', r.stateBudget, '2024-08-01'),
    () => arm('GET', `${r.group}/resources`, '2021-04-01', undefined, '$expand=createdTime,changedTime'),
    () => arm('GET', r.managedGroup, '2024-03-01'),
  ], read => read());
  const nspReadback = nsp ? {
    nspObservation: await collectNspObservation(overlay.nspNetwork.topology, nspReadIO(c, directory, invoke, { now }), deadline,
      { c, adoption: overlay.queueRecords['queue-storage'] }),
    nspLineageHead: await readNspHead(overlay.nspNetwork),
  } : {};
  if (await sourceDigest() !== policySource) fail('RECONCILIATION_SOURCE_CHANGED');
  const proposal = { version: nsp ? 6 : overlay ? 5 : receiverCandidate ? 4 : 3, kind: 'read-only-completed-phases', sourceSha256: policySource,
    ...(receiverCandidate ? { receiverCandidateSha256: digest(json(receiverCandidate)) } : {}),
    ...(overlay ? { receiverUpgradeSha256: digest(json(overlay.receiverUpgrade)), queueRecordsSha256: digest(json(overlay.queueRecords)) } : {}),
    ...(nsp ? { queueAdoptionSha256: digest(json(overlay.queueRecords['queue-storage'])), nspNetworkSha256: digest(json(overlay.nspNetwork)) } : {}),
    ...nspReadback,
    configSha256: digest(json(c)), executionOriginsSha256: digest(json(origins)), baselineSha256,
    checkedAt: new Date().toISOString(), results, stateBudget, ...context, inventory, managedGroup };
  verifyReconciliation(c, foundation, origins, proposal, proposal.sourceSha256, null, contract, receiverCandidate, overlay);
  if (overlay && Object.keys(overlay.queueRecords).length) {
    const topology = overlay.queueRecords['queue-storage'].topology;
    await readQueueRecords(c, topology, overlay.queueRecords, transport(c, origins.records[0].phase, directory, invoke, topology),
      nspReadIO(c, directory, invoke, { now }), deadline);
  }
  if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
  return proposal;
}
export async function reviewedReconciliationReceipts(c, foundation, evidence, sourceSha256, lookup = publishedSourceDigest, options = {}) {
  if (!evidence?.origins || !evidence.proposal || !evidence.review) fail('RECONCILIATION_REVIEW_REQUIRED');
  const contract = await storageContract();
  await verifyPublishedOrigins(c, foundation, evidence.origins, lookup, contract);
  const receiverCandidate = reconciliationReceiverCandidate(evidence.proposal, evidence.receiverCandidate);
  const overlay = [5, 6].includes(evidence.proposal.version) ? { receiverUpgrade: evidence.receiverUpgrade, queueRecords: evidence.queueRecords ?? {},
    ...(evidence.proposal.version === 6 ? { nspNetwork: evidence.nspNetwork } : {}) } : null;
  if (receiverCandidate) await verifyReceiverSource(receiverCandidate, options.sourceRun, lookup);
  if (overlay) {
    await verifyPublishedWindowPredecessor(c, overlay.receiverUpgrade, lookup, options.sourceRun);
    await verifyPublishedQueueRecords(c, overlay.queueRecords, lookup);
    if (evidence.proposal.version === 6) await verifyPublishedNspEvidence(c, overlay.nspNetwork, overlay.queueRecords['queue-storage'].topology, overlay.queueRecords['queue-storage'], lookup);
  }
  verifyReconciliation(c, foundation, evidence.origins, evidence.proposal, sourceSha256, evidence.review, contract, receiverCandidate, overlay);
  return Object.fromEntries(evidence.origins.records.map(record => {
    const phase = record.phase.phase, result = evidence.proposal.results[phase];
    return [phase, { qualificationKind: 'reviewed-read-only-reconciliation', qualified: true, phase,
      configSha256: digest(json(c)), phaseSha256: digest(json(record.phase)), sourceSha256: record.publication.sourceSha256,
      deployment: result.deployment, resources: result.resources,
      reconciliation: { contractVersion: evidence.proposal.version, ...reconciliationBinding(evidence), policySourceSha256: sourceSha256,
        ...(receiverCandidate ? { receiverCandidateSha256: digest(json(receiverCandidate)) } : {}),
        executionOriginSha256: digest(json(record)), checkedAt: evidence.proposal.checkedAt, reviewedAt: evidence.review.reviewedAt,
        originalJournalOutcome: record.journal.outcome, originalReceiptQualified: record.originalReceipt?.qualified === true } }];
  }));
}
export async function verifyFreshReconciliation(c, directory, evidence, invoke = az, transition, imageContext = {}) {
  invoke = limitReadConcurrency(invoke);
  const arm = transport(c, evidence.origins.records[0].phase, directory, invoke);
  const suppliedCandidate = imageContext.receiverCandidate ?? evidence.receiverCandidate;
  const historicalCandidate = reconciliationReceiverCandidate(evidence.proposal, suppliedCandidate);
  const receiverCandidate = publishedReceiverCandidate(suppliedCandidate) ?? historicalCandidate;
  const context = await reconciliationContext(c, evidence.origins, arm, invoke, receiverCandidate);
  if (context.workspace && !isDeepStrictEqual(executionIdentity(context.workspace), executionIdentity(evidence.proposal.workspace))) fail('RESOURCE_IDENTITY_CHANGED');
  const currentApps = await readBatch(evidence.origins.records, async record => {
    const current = await readReconciledPhase(c, record, arm, { ...context, ...imageContext, receiverCandidate,
      publication: evidence.origins.imagePublication?.receipt, transition });
    if (!isDeepStrictEqual(current.identityPins, evidence.proposal.results[record.phase.phase].identityPins)) fail('RESOURCE_IDENTITY_CHANGED');
    return record.phase.phase === 'disabled-app' ? {
      app: current.resources[ids(c).app], identities: context.identities,
      privacy: { diagnostics: current.diagnostics, exports: current.exports },
    } : null;
  });
  const [stateBudget, managedGroup, inventory] = await readBatch([
    () => arm('GET', ids(c).stateBudget, '2024-08-01'),
    () => arm('GET', ids(c).managedGroup, '2024-03-01'),
    () => arm('GET', `${ids(c).group}/resources`, '2021-04-01', undefined, '$expand=createdTime,changedTime'),
  ], read => read());
  assertBudget(stateBudget, c, 50);
  if (managedGroup) fail('RECONCILIATION_INVENTORY_CHANGED');
  if (!Array.isArray(inventory?.value) || evidence.proposal.inventory.value.some(previous => {
    const current = inventory.value.filter(v => sameId(v.id, previous.id));
    return current.length !== 1 || current[0].createdTime !== previous.createdTime;
  })) fail('RESOURCE_CREATION_IDENTITY_CHANGED');
  return currentApps.find(Boolean);
}
export async function verifyPublishedWindowPredecessor(c, predecessor, lookup = publishedSourceDigest, sourceRun = execute) {
  const summary = verifyWindowPredecessor(c, predecessor);
  if (await lookup(predecessor.publication.commitSha) !== predecessor.publication.sourceSha256) fail('PREDECESSOR_PUBLISHED_SOURCE_MISMATCH');
  if (predecessor.kind === 'reviewed-disabled-image-change') {
    await verifyPublishedWindowPredecessor(c, predecessor.predecessor, lookup, sourceRun);
    await verifyReceiverSource(predecessor.candidate, sourceRun, lookup);
    return summary;
  }
  if (predecessor.prerequisiteReceipts.receiverUpgrade) {
    await verifyPublishedWindowPredecessor(c, predecessor.prerequisiteReceipts.receiverUpgrade, lookup, sourceRun);
  }
  const context = resourceContext(c, predecessor.prerequisiteReceipts);
  for (const name of TOGGLE_PHASES) {
    const receipt = predecessor.receipts[name];
    if (!latestRevisionReady(c, predecessor.phases[name], predecessor.window,
      { app: receipt.resources[ids(c).app], revisions: receipt.revisionReadback, context })) fail('PREDECESSOR_ROLLOUT_NOT_QUALIFIED');
  }
  if (!latestRevisionReady(c, predecessor.phases['synthetic-disable'], predecessor.window,
    { app: predecessor.readback.app, revisions: predecessor.readback.revisions,
      context: { ...context, identities: predecessor.readback.identities } })) fail('PREDECESSOR_CURRENT_DISABLED_NOT_READY');
  return summary;
}
export async function readWindowPredecessor(c, predecessor, directory, invoke = az, transition, verifiedApp) {
  if (predecessor.kind === 'reviewed-disabled-image-change') {
    const arm = transport(c, predecessor.phase, directory, invoke), r = ids(c);
    const deployment = await arm('GET', predecessor.phase.deploymentId, '2022-09-01');
    verifyDeploymentIdentity(predecessor.receipt.deployment, deployment);
    const identities = verifiedApp?.identities ?? { [r.ingestIdentity]: await arm('GET', r.ingestIdentity, '2023-01-31'),
      [r.pullIdentity]: await arm('GET', r.pullIdentity, '2023-01-31') };
    const app = verifiedApp?.app ?? await arm('GET', r.app, '2025-07-01');
    const context = { ...resourceContext(c, predecessor.prerequisiteReceipts), identities, receiverCandidate: predecessor.candidate };
    if (transition?.journals['synthetic-admission']) {
      verifyWindowState(c, transition.phases, transition.window, transition.approvals, transition.journals, app, context, transition.source);
    } else {
      verifyResource(c, predecessor.phase, predecessor.phase.resources[0], app, context);
      if (app.properties.latestRevisionName !== predecessor.receipt.resources[r.app].properties.latestRevisionName) fail('UNREVIEWED_PREDECESSOR_REVISION');
      verifyImageRevision(c, predecessor.phase, app, await arm('GET', `${r.app}/revisions`, '2025-07-01'), context);
    }
    if (!isDeepStrictEqual(executionIdentity(app, 'Microsoft.App/containerApps'),
      executionIdentity(predecessor.receipt.resources[r.app], 'Microsoft.App/containerApps'))) fail('PREDECESSOR_CURRENT_IDENTITY_CHANGED');
    return { checkedAt: new Date().toISOString(), sourceSha256: await sourceDigest(), deployment, app, identities };
  }
  const arm = transport(c, predecessor.phases['synthetic-disable'], directory, invoke), r = ids(c);
  const deployments = {};
  for (const name of TOGGLE_PHASES) {
    deployments[name] = await arm('GET', predecessor.phases[name].deploymentId, '2022-09-01');
    verifyDeploymentIdentity(predecessor.receipts[name].deployment, deployments[name]);
  }
  const identities = verifiedApp?.identities ?? { [r.ingestIdentity]: await arm('GET', r.ingestIdentity, '2023-01-31'),
    [r.pullIdentity]: await arm('GET', r.pullIdentity, '2023-01-31') };
  const app = verifiedApp?.app ?? await arm('GET', r.app, '2025-07-01');
  const context = { ...resourceContext(c, predecessor.prerequisiteReceipts), identities };
  if (transition?.journals['synthetic-admission']) {
    verifyWindowState(c, transition.phases, transition.window, transition.approvals, transition.journals, app, context, transition.source);
  } else {
    verifyResource(c, predecessor.phases['synthetic-disable'], predecessor.phases['synthetic-disable'].resources[0], app, context);
    if (app.properties.latestRevisionName !== predecessor.receipts['synthetic-disable'].resources[r.app].properties.latestRevisionName) fail('UNREVIEWED_PREDECESSOR_REVISION');
  }
  if (!isDeepStrictEqual(executionIdentity(app, 'Microsoft.App/containerApps'), predecessor.window.appIdentity)) fail('PREDECESSOR_CURRENT_IDENTITY_CHANGED');
  const revisions = await arm('GET', `${r.app}/revisions`, '2025-07-01');
  if (!transition?.journals['synthetic-admission'] && !latestRevisionReady(c, predecessor.phases['synthetic-disable'], predecessor.window,
    { app, revisions, context })) fail('PREDECESSOR_CURRENT_DISABLED_NOT_READY');
  const privacy = verifiedApp?.privacy ?? await readPrivacy(c, predecessor.phases['synthetic-disable'], arm);
  return { checkedAt: new Date().toISOString(), sourceSha256: await sourceDigest(), deployments, app, identities, revisions, privacy };
}
async function checkWindowLineage(c, phase, predecessor, directory, invoke, lookup, transition, verifiedApp) {
  const instance = validateWindowInstance(c, phase.windowInstance);
  verifyWindowInstancePredecessor(c, instance, predecessor);
  await verifyPublishedWindowPredecessor(c, predecessor, lookup);
  const fresh = await readWindowPredecessor(c, predecessor, directory, invoke, transition, verifiedApp);
  const arm = transport(c, phase, directory, invoke);
  for (const name of TOGGLE_PHASES) {
    const id = `${ids(c).group}/providers/Microsoft.Resources/deployments/${deploymentName(c, name, instance)}`;
    const existing = await arm('GET', id, '2022-09-01');
    if (existing && !transition?.journals[name]) fail('WINDOW_INSTANCE_DEPLOYMENT_ALREADY_EXISTS');
  }
  await save(directory, `${phase.phase}-predecessor-readback.json`, fresh);
}
export function verifyProjectBudgetReceipt(c, receipt, foundation, sourceSha256, reconciled = {}) {
  const phase = buildPhase(c, 'project-budget', null, {}, foundation), r = ids(c);
  if (receipt?.qualified !== true || receipt.phase !== 'project-budget' ||
      receipt.phaseSha256 !== digest(json(phase)) || receipt.configSha256 !== digest(json(c)) ||
      !sameId(receipt.deployment?.id, phase.deploymentId) ||
      receipt.deployment.properties?.provisioningState !== 'Succeeded' ||
      !isDeepStrictEqual(Object.keys(receipt.resources ?? {}), [r.projectBudget])) fail('PROJECT_BUDGET_RECEIPT_REQUIRED');
  verifyResource(c, phase, phase.resources[0], receipt.resources[r.projectBudget]);
  if (receipt.sourceSha256 !== sourceSha256 && !isDeepStrictEqual(receipt, reconciled['project-budget'])) fail('RECONCILIATION_REVIEW_REQUIRED');
}
export async function validateReadOnly(c, phase, receipts, directory, invoke = az, currentApp, options = {}) {
  const now = options.now ?? Date.now, maximumDeadline = now() + 120000;
  const deadline = Math.min(options.deadline ?? invokeDeadlines.get(invoke) ?? maximumDeadline, maximumDeadline);
  invoke = boundedInvoke(deadline, invoke, now);
  const r = ids(c), known = knownResourceIds(c, receipts);
  const executionName = deploymentName(c, phase.phase, phase.windowInstance);
  if (phase.deploymentId !== `${phase.scope}/providers/Microsoft.Resources/deployments/${executionName}`) fail('DEPLOYMENT_NAME_INVALID');
  const name = `${phase.phase}-template.json`; await save(directory, name, phase.template);
  const level = phase.scope === r.sub ? 'sub' : 'group';
  const args = ['--subscription', c.subscriptionId, ...(level === 'sub' ? ['--location', c.location] : ['--resource-group', `${c.namePrefix}-telemetry`]),
    '--name', executionName, '--template-file', resolve(directory, name), '--only-show-errors', '--output', 'json'];
  const validation = await invoke(['deployment', level, 'validate', ...args], 180000);
  await save(directory, `${phase.phase}-validation.json`, validation);
  if (validation?.properties?.provisioningState !== 'Succeeded' || validation.error ||
      (QUEUE_PHASES.includes(phase.phase) && (validation.nextLink || validation.properties.error))) fail('TEMPLATE_NOT_VALIDATED');
  const { result: whatif, raw } = await asyncWhatIf(c, phase, directory, { ...options, deadline });
  await save(directory, `${phase.phase}-what-if-raw.json`, raw);
  await save(directory, `${phase.phase}-what-if.json`, whatif);
  if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
  const context = [...TOGGLE_PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES].includes(phase.phase) ? { config: c, ...resourceContext(c, receipts),
    ...(options.queueTopology ? { queueTopology: options.queueTopology } : {}),
    ...(options.networkContext ? { networkContext: options.networkContext } : {}),
    ...(options.receiverCandidate ? { receiverCandidate: options.receiverCandidate } : {}),
    app: currentApp ?? receiverAnchor(c, receipts) } : undefined;
  const queuePreview = QUEUE_PHASES.includes(phase.phase)
    ? verifyQueueWhatIf(c, phase, options.queueTopology, whatif, known, context.identities[r.ingestIdentity], options.networkContext ?? null) : undefined;
  const whatIfSha256 = queuePreview?.whatIfSha256 ?? verifyWhatIf(phase, whatif, known, context);
  if (queuePreview) await save(directory, `${phase.phase}-preview-uncertainty.json`, queuePreview);
  if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
  return { whatIfSha256, templateValidationOnly: true, ...(queuePreview ? {
    queuePreview, queuePreviewSha256: digest(json(queuePreview)),
    requiredPostCreateReadbacksSha256: queuePreview.requiredPostCreateReadbacksSha256,
    armValidationSha256: digest(json(validation)), validatedTemplateSha256: digest(json(phase.template)),
  } : {}) };
}
export function knownResourceIds(c, receipts) {
  const known = Object.entries(receipts).filter(([name]) => PHASES.includes(name))
    .flatMap(([, v]) => Object.keys(v.resources ?? {}))
    .filter(id => !id.toLowerCase().includes('/providers/microsoft.storage/'));
  if (receipts.queueRecords && Object.keys(receipts.queueRecords).length) {
    const last = QUEUE_PHASES.filter(name => Object.hasOwn(receipts.queueRecords, name)).at(-1);
    const topology = receipts.queueRecords[last]?.topology;
    known.push(...Object.keys(qualifiedQueueRecords(c, receipts.queueRecords, topology, last)));
    const adoption = receipts.queueRecords['queue-storage'];
    if (adoption.version === 3) known.push(...Object.keys(queueDefenderInventory(c, adoption.origin,
      adoption.proposal.defender, adoption.observation.defender)));
  }
  if (receipts.nspNetwork) {
    const adoption = receipts.queueRecords?.['queue-storage'];
    const tip = verifyNspEvidence(c, receipts.nspNetwork, adoption?.topology, adoption);
    if (tip) known.push(...Object.entries(tip.observation.resources).filter(([, value]) => value !== null).map(([id]) => id));
  }
  return [...new Set(known)];
}
export async function readQueueRecords(c, topology, records, arm, defenderIO = null, deadline = null) {
  if (!Object.keys(records).length) return;
  qualifiedQueueRecords(c, records, topology, QUEUE_PHASES.filter(name => Object.hasOwn(records, name)).at(-1));
  await readBatch(Object.values(records), async record => {
    if (record.kind === 'reviewed-queue-storage-adoption') {
      const adopted = verifyQueueAdoptionRecord(c, record), resources = {};
      const deployment = await arm('GET', record.origin.phase.deploymentId, '2022-09-01');
      verifyDeploymentIdentity(adopted.deployment, deployment);
      await readBatch([topology.ids.account, topology.ids.service, topology.ids.queue], async id => {
        resources[id] = await arm('GET', id, NSP_STORAGE_API);
      });
      const access = resources[topology.ids.account]?.properties?.publicNetworkAccess;
      verifyAdoptedQueueStorage(c, record, resources, access);
      if (record.version === 3) {
        if (!defenderIO || typeof defenderIO.read !== 'function' || typeof defenderIO.now !== 'function') fail('QUEUE_DEFENDER_READ_PORT_REQUIRED');
        await collectQueueDefender(c, record.origin, record.proposal.defender, defenderIO, deadline);
      }
      return;
    }
    const deployment = await arm('GET', record.phase.deploymentId, '2022-09-01');
    verifyDeploymentIdentity(record.receipt.deployment, deployment);
    await readBatch(record.phase.resources, async descriptor => {
      const actual = await arm('GET', descriptor.id, descriptor.apiVersion), previous = record.receipt.resources[descriptor.id];
      verifyQueueResource(c, topology, descriptor, actual);
      if (actual.properties.creationTime !== previous.properties.creationTime ||
          actual.properties.createdOn !== previous.properties.createdOn) fail('QUEUE_CREATION_IDENTITY_CHANGED');
    });
  });
  const queues = await arm('GET', `${topology.ids.service}/queues`, '2025-01-01');
  if (!Array.isArray(queues?.value) || queues.nextLink || queues.value.length !== 1 ||
      !sameId(queues.value[0].id, topology.ids.queue)) fail('UNEXPECTED_QUEUE_RESOURCE');
  await readQueuePrivacy(topology, arm);
}
export async function verifyPublishedQueueRecords(c, records, lookup = publishedSourceDigest) {
  for (const record of Object.values(records)) {
    if (record.kind === 'reviewed-queue-storage-adoption') {
      await verifyQueueAdoptionSources(c, record, lookup); continue;
    }
    verifyQueueRecord(c, record);
    if (await lookup(record.publication.commitSha) !== record.publication.sourceSha256) fail('QUEUE_PUBLISHED_SOURCE_CHANGED');
  }
}
export async function readQueuePrivacy(topology, arm) {
  const diagnostics = Object.fromEntries(await readBatch([topology.ids.account, topology.ids.service],
    async id => [id, await arm('GET', `${id}/providers/Microsoft.Insights/diagnosticSettings`, DIAGNOSTIC_API)]));
  const value = { diagnostics };
  verifyQueuePrivacy(topology, value);
  return value;
}
export async function checkEffectivePolicies(c, phase, directory, invoke, topology, expectedSha256, options = {}) {
  if (effectivePolicyScopes(phase).some(scope => !sameId(scope, ids(c).sub) && !sameId(scope, ids(c).group))) fail('EFFECTIVE_POLICY_SCOPE_FORBIDDEN');
  const now = options.now ?? Date.now, deadline = Math.min(options.deadline ?? invokeDeadlines.get(invoke) ?? now() + 120000, now() + 120000);
  const policyReads = new Set(), arm = transport(c, phase, directory,
    limitReadConcurrency(boundedInvoke(deadline, invoke, now)), topology, policyReads);
  const name = `${phase.phase}-effective-policy${expectedSha256 ? '-dispatch' : ''}`;
  let failedRead;
  try {
    const evidence = await collectEffectivePolicies(phase, async (id, apiVersion, filter) => {
      policyReads.add(json([id, apiVersion, filter ?? null]));
      try { return await arm('GET', id, apiVersion, undefined, filter); }
      catch (error) { failedRead ??= { id, apiVersion, filter: filter ?? null }; throw error; }
    }, readBatch, snapshot => save(directory, `${name}-reads.json`, snapshot));
    if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
    await save(directory, `${name}.json`, evidence);
    if (!evidence.qualified) fail('EFFECTIVE_POLICY_CONFLICT');
    verifyEffectivePolicyEvidence(phase, evidence);
    const effectivePolicySha256 = digest(json(evidence));
    if (expectedSha256 && expectedSha256 !== effectivePolicySha256) fail('EFFECTIVE_POLICY_DRIFT');
    return { effectivePolicyVersion: 1, effectivePolicySha256, effectivePolicy: evidence };
  } catch (error) {
    await save(directory, `${name}-failure.json`, { phaseSha256: digest(json(phase)), failure: safeOperationFailure(error),
      ...(failedRead ? { failedRead, failedReadSha256: digest(json(failedRead)) } : {}) });
    throw error;
  }
}
function nspContext(c, receipts, evidence) {
  const adoption = receipts.queueRecords?.['queue-storage'];
  if (adoption?.kind !== 'reviewed-queue-storage-adoption') return null;
  const admission = evidence.nspNetwork ?? receipts.nspNetwork;
  if (!admission) fail('NSP_CURRENT_ADMISSION_REQUIRED');
  verifyNspAdmission(c, admission, adoption.topology, adoption);
  return { adoption, admission };
}
function nspHeadName(network) { return `nsp-head-${nspTargetKey(network)}.json`; }
function nspFenceName(network) { return `nsp-intent-fence-${nspTargetKey(network)}.json`; }
export async function readNspHead(evidence, pending = null, read = load) {
  const root = resolve(here, '.operator-private'), expected = nspLineageHead(evidence);
  const actual = await read(root, nspHeadName(evidence.topology), true);
  const empty = actual === null && evidence.records.length === 0;
  const ownedPending = pending && isDeepStrictEqual(actual, pending) && isDeepStrictEqual(pending.previousHead, expected);
  if (!empty && !ownedPending && !isDeepStrictEqual(actual, expected)) fail('NSP_CANONICAL_HEAD_CHANGED');
  const fence = await read(root, nspFenceName(evidence.topology), true);
  if (empty) {
    const firstIntent = await read(root, `nsp-intent-${nspIntentKey(evidence, { phase: 'nsp-empty-boundary', instance: null })}.json`, true);
    if (fence !== null || firstIntent !== null) fail('NSP_UNRESOLVED_GLOBAL_INTENT');
    return expected;
  }
  if (!fence?.reservation || !isDeepStrictEqual(fence, nspIntentFence(evidence, fence.reservation))) fail('NSP_INTENT_FENCE_CHANGED');
  const archived = await read(root, `nsp-intent-${fence.intentKey}.json`, true);
  if (!isDeepStrictEqual(archived, fence.reservation)) fail('NSP_INTENT_ARCHIVE_CHANGED');
  if (ownedPending) {
    if (!isDeepStrictEqual(actual, nspPendingHead(evidence, archived.phase, archived.journal))) fail('NSP_INTENT_FENCE_CHANGED');
    return expected;
  }
  const record = evidence.records.at(-1);
  if (!record) fail('NSP_UNRESOLVED_GLOBAL_INTENT');
  const reservation = record.kind === 'reviewed-nsp-reconciliation' ? record.original.reservation : {
    phase: record.phase, approvalSha256: digest(json(record.approval)),
    journal: { ...Object.fromEntries(['version', 'phaseSha256', 'approvalSha256', 'requestSha256', 'predecessorSha256', 'intentAt']
      .map(key => [key, record.journal[key]])), outcome: 'submission-possible', transportDispatchAttempted: false },
  };
  if (!isDeepStrictEqual(fence.reservation, reservation)) fail('NSP_UNRESOLVED_GLOBAL_INTENT');
  return actual;
}
export async function reserveNspIntent(evidence, phase, journal, store = { read: load, save, saveImmutable }) {
  const root = resolve(here, '.operator-private');
  await readNspHead(evidence, null, store.read);
  const reservation = { phase, approvalSha256: journal.approvalSha256, journal };
  // Fence the physical target before either archive or head persistence can fail.
  await store.save(root, nspFenceName(evidence.topology), nspIntentFence(evidence, reservation));
  await store.saveImmutable(root, `nsp-intent-${nspIntentKey(evidence, phase)}.json`, reservation);
  const pending = nspPendingHead(evidence, phase, journal);
  await store.save(root, nspHeadName(evidence.topology), pending);
  return pending;
}
export function nspReadIO(c, directory, invoke = az, options = {}, phase = null, binding = null) {
  const now = options.now ?? Date.now, policyReads = new Set();
  const dispatch = (args, timeout, deadline) => {
    if (!Number.isSafeInteger(deadline) || now() >= deadline) fail('NSP_READ_DEADLINE');
    return invoke(args, Math.min(timeout, NSP_LIMITS.commandMs, deadline - now()));
  };
  const limitedReads = limitReadConcurrency(dispatch);
  const io = {
    now, binding, batch: readBatch,
    invoke: (args, timeout, deadline) => args[args.indexOf('--method') + 1] === 'GET'
      ? limitedReads(args, timeout, deadline) : dispatch(args, timeout, deadline),
    policyReadAllowed: request => policyReads.has(json(request)),
    allowPolicyRead: request => policyReads.add(json(request)),
    describeFailure: safeOperationFailure,
    retainRead: (request, pages, outcome) => saveImmutable(directory, `nsp-read-${randomUUID()}.json`, { request, pages, outcome }),
    prepareBody: async body => {
      const name = `request-${randomUUID()}.json`; await saveImmutable(directory, name, body);
      return { name, path: resolve(directory, name) };
    },
    removeBody: prepared => rm(prepared.path),
  };
  return { ...io, ...nspTransport(c, phase, io) };
}
export async function verifyPublishedNspEvidence(c, evidence, topology, adoption, lookup = publishedSourceDigest) {
  verifyNspEvidence(c, evidence, topology, adoption);
  await verifyQueueAdoptionSources(c, adoption, lookup);
  await readBatch(evidence.records, async record => {
    if (await lookup(record.publication.commitSha) !== record.publication.sourceSha256) fail('NSP_PUBLISHED_SOURCE_CHANGED');
    if (record.kind === 'reviewed-nsp-reconciliation' &&
        await lookup(record.original.publication.commitSha) !== record.original.publication.sourceSha256) fail('NSP_ORIGINAL_PUBLISHED_SOURCE_CHANGED');
  });
}
export async function originalNspAttempt(phase, evidence, directory) {
  const reservation = await load(resolve(here, '.operator-private'), `nsp-intent-${nspIntentKey(evidence, phase)}.json`);
  return { phase, publication: await load(directory, 'nsp-policy-publication.json'),
    approval: await load(directory, `${phase.phase}-approval.json`), preflight: await load(directory, `${phase.phase}-preflight.json`),
    preview: await load(directory, `${phase.phase}-what-if.json`), validation: await load(directory, `${phase.phase}-validation.json`),
    reservation, journal: await load(directory, `${phase.phase}-journal.json`), receipt: await load(directory, `${phase.phase}-receipt.json`, true) };
}
export function nspReconciliationIO(c, original, topology, adoption, prior, billing, directory, invoke = az, options = {}) {
  const now = options.now ?? Date.now, root = resolve(here, '.operator-private');
  return {
    ...nspReadIO(c, directory, invoke, options), sourceDigest,
    billingReview: billing.review, billingEvidence: billing.evidence,
    pendingHead: async () => {
      const pending = nspPendingHead(prior, original.phase, original.reservation.journal);
      await readNspHead(prior, pending);
      return pending;
    },
    compareAndAppend: async (expected, record, nextHead) => {
      await readNspHead(prior, expected);
      const unchanged = await originalNspAttempt(original.phase, prior, directory);
      if (!isDeepStrictEqual(unchanged, original)) fail('NSP_ORIGINAL_ATTEMPT_CHANGED');
      const guard = async () => {
        if (now() >= canonicalInstant(record.review.expiresAt) ||
            now() >= canonicalInstant(record.proposal.networkBillingReview.expiresAt) ||
            now() - record.proposal.state.observation.startedAt > NSP_LIMITS.freshnessMs ||
            await sourceDigest() !== record.publication.sourceSha256) fail('NSP_RECONCILIATION_COMMIT_EXPIRED');
        await readNspHead(prior, expected);
      };
      await guard();
      const result = { ...prior, records: [...prior.records, record] };
      verifyNspEvidence(c, result, topology, adoption);
      await saveImmutable(directory, `${original.phase.phase}-reconciled-record.json`, record);
      await saveImmutable(directory, `${original.phase.phase}-reconciled-network.json`, result);
      await guard();
      await saveImmutable(root, `nsp-resolution-${digest(json(original.reservation))}.json`, {
        version: 1, kind: 'append-only-nsp-lineage-resolution', previousHead: expected, nextHead, record });
      await guard();
      await save(root, nspHeadName(prior.topology), nextHead);
    },
  };
}
export async function currentNspAdmission(c, context, evidence, directory, deadline, invoke = az, options = {}) {
  const now = options.now ?? Date.now, sourceSha256 = await sourceDigest();
  const io = nspReadIO(c, directory, invoke, options);
  const [networkObservation, networkLineageHead] = await readBatch([
    () => collectNspObservation(context.admission.topology, io, deadline, { c, adoption: context.adoption }),
    () => readNspHead(context.admission, null, options.headRead ?? load),
  ], read => read());
  const proof = { sourceSha256, networkObservation, networkLineageHead,
    networkBillingReview: evidence.nspBillingReview, networkBillingEvidence: evidence.nspBillingEvidence,
    ...nspReadinessBinding(context, networkLineageHead, evidence.nspBillingReview, networkObservation) };
  verifyNspQueuePreflight(c, context, proof, now());
  if (now() >= deadline || await sourceDigest() !== sourceSha256) fail('NSP_CURRENT_CHECK_EXPIRED');
  return proof;
}
export async function checkQueuedPublication(c, receipts, evidence, directory, invoke = az, options = {}) {
  const candidate = evidence.receiverCandidate;
  if (candidate?.version !== 2) fail('QUEUE_PROFILE_PHASE_REQUIRED');
  const now = options.now ?? Date.now, deadline = now() + NSP_LIMITS.stageMs, source = await sourceDigest();
  invoke = limitReadConcurrency(boundedInvoke(deadline, invoke, now));
  verifyReceiverCandidate(c, candidate, now(), false);
  if (candidate.review.sourceSha256 !== source) fail('IMAGE_SOURCE_CHANGED');
  const lookup = options.lookup ?? publishedSourceDigest;
  await verifyReceiverSource(candidate, options.sourceRun, lookup);
  const historical = reconciliationReceiverCandidate(evidence.reconciliation?.proposal, candidate);
  if (!isDeepStrictEqual(historical, candidate.priorCandidate)) fail('QUEUE_PRIOR_RECEIVER_CHANGED');
  const reconciled = await reviewedReconciliationReceipts(c, evidence.foundationBudgets,
    { ...evidence.reconciliation, receiverCandidate: candidate }, source, lookup, options);
  if (Object.entries(reconciled).some(([name, value]) => !isDeepStrictEqual(receipts[name], value))) fail('RECONCILIATION_RECEIPTS_REQUIRED');
  if (!receipts.receiverUpgrade || !isDeepStrictEqual(receipts.receiverUpgrade.candidate, historical)) fail('QUEUE_PRIOR_RECEIVER_CHANGED');
  await verifyFreshReconciliation(c, directory, { ...evidence.reconciliation, receiverCandidate: candidate }, invoke, undefined,
    { receiverCandidate: historical, imageDescriptor: receipts.receiverUpgrade.phase.resources[0] });
  qualifiedQueueRecords(c, receipts.queueRecords, candidate.topology);
  const context = nspContext(c, receipts, evidence);
  if (!context) fail('NSP_CURRENT_ADMISSION_REQUIRED');
  await verifyPublishedNspEvidence(c, context.admission, candidate.topology, context.adoption, lookup);
  const arm = transport(c, evidence.reconciliation.origins.records[0].phase, directory, invoke, candidate.topology);
  await readQueueRecords(c, candidate.topology, receipts.queueRecords, arm, nspReadIO(c, directory, invoke, { now }), deadline);
  const publicationReadback = await readPublishedImage(c, evidence.reconciliation.origins.imagePublication, arm, invoke, historical);
  if (!isDeepStrictEqual(executionIdentity(publicationReadback.registry, 'Microsoft.ContainerRegistry/registries'),
    executionIdentity(receipts.core.resources[ids(c).registry], 'Microsoft.ContainerRegistry/registries'))) fail('RESOURCE_IDENTITY_CHANGED');
  const inventory = { repositories: publicationReadback.repositories, manifests: publicationReadback.manifests,
    referrers: publicationReadback.referrers };
  const publicationPreview = prepareReceiverPublication(c, candidate, inventory, now());
  const proof = await currentNspAdmission(c, context, evidence, directory, deadline, invoke, options);
  Object.assign(proof, { candidateSha256: digest(json(candidate)), priorCandidateSha256: digest(json(historical)),
    reconciliationProposalSha256: digest(json(evidence.reconciliation.proposal)),
    reconciliationReviewSha256: digest(json(evidence.reconciliation.review)), inventory, inventorySha256: digest(json(inventory)),
    publicationPreview });
  if (await sourceDigest() !== source || now() >= deadline) fail('NSP_PUBLICATION_PREFLIGHT_CHANGED');
  await save(directory, 'nsp-publication-preflight.json', proof);
  return proof;
}
export async function captureQueuedPublication(c, candidate, directory, invoke = az, options = {}) {
  verifyReceiverCandidate(c, candidate, undefined, candidate?.publication !== null);
  if (candidate.version !== 2) fail('QUEUE_PROFILE_PHASE_REQUIRED');
  const now = options.now ?? Date.now, deadline = now() + NSP_LIMITS.stageMs;
  const bounded = boundedInvoke(deadline, invoke, now), digestValue = candidate.profile.manifestDigest;
  try {
    const [manifest, manifests] = await readBatch([
      () => bounded(['acr', 'manifest', 'show', '--registry', c.registryName,
        '--name', `missionspec/telemetry-ingest@${digestValue}`, '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']),
      () => bounded(['acr', 'manifest', 'list-metadata', '--registry', c.registryName,
        '--name', 'missionspec/telemetry-ingest', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']),
    ], read => read());
    const observation = { version: 1, kind: 'queued-publication-readback-not-admission', observedAt: new Date(now()).toISOString(),
      registryId: ids(c).registry, digest: digestValue, manifest, manifests,
      qualified: false, networkAdmissionQualified: false, replayAuthorized: false };
    await saveImmutable(directory, 'queued-publication-observation.json', observation);
    return observation;
  } catch (error) {
    await saveImmutable(directory, 'queued-publication-observation-failure.json', {
      digest: digestValue, failure: safeOperationFailure(error), replayAuthorized: false });
    throw error;
  }
}
export function nspIO(c, phase, receipts, origin, evidence, directory, invoke = az, options = {}) {
  const now = options.now ?? Date.now, topology = evidence.queueTopology;
  const rawInvoke = invoke;
  let activeDeadline = now() + NSP_LIMITS.stageMs;
  const sharedReads = limitReadConcurrency((args, timeout) => boundedInvoke(activeDeadline, rawInvoke, now)(args, timeout));
  invoke = (args, timeout) => args[0] === 'rest' && ['PUT', 'PATCH', 'DELETE'].includes(args[args.indexOf('--method') + 1])
    ? boundedInvoke(activeDeadline, rawInvoke, now)(args, timeout) : sharedReads(args, timeout);
  const adoption = receipts.queueRecords?.['queue-storage'], network = evidence.nspNetwork;
  verifyNspEvidence(c, network, topology, adoption);
  const port = nspReadIO(c, directory, invoke, options, phase, { topology, adoption, evidence: network });
  const disabledEvidence = { ...evidence, receiverCandidate: receipts.receiverUpgrade?.candidate };
  const common = receiverUpgradeIO(c, phase, receipts, origin, disabledEvidence, directory, invoke, options);
  let pending = null;
  const at = deadline => transport(c, phase, directory, limitReadConcurrency(boundedInvoke(deadline, invoke, now)), topology);
  const disabled = async deadline => {
    const observation = await common.observe(deadline), record = receipts.receiverUpgrade;
    if (!record || admissionFlag(observation.app) !== 'false') fail('NSP_DISABLED_RECEIVER_REQUIRED');
    verifyDisabledImageRecord(c, record);
    verifyResource(c, record.phase, record.phase.resources[0], observation.app, observation.context);
    if (!isDeepStrictEqual(executionIdentity(observation.app, 'Microsoft.App/containerApps'),
      executionIdentity(record.receipt.resources[ids(c).app], 'Microsoft.App/containerApps'))) fail('NSP_RECEIVER_IDENTITY_CHANGED');
    const identity = observation.context.identities[ids(c).ingestIdentity];
    if (!sameId(identity.id, network.topology.identity) || identity.properties.tenantId !== c.tenantId ||
        !sameId(observation.app.id, network.topology.host)) fail('NSP_CALLER_SCOPE_CHANGED');
    const arm = at(deadline), q = topology.ids;
    const [role, assignment, ...grants] = await readBatch([
      () => arm('GET', q.role, '2022-04-01'), () => arm('GET', q.assignment, '2022-04-01'),
      ...[q.account, q.service, q.queue].map(scope => () =>
        port.read({ id: `${scope}/providers/Microsoft.Authorization/roleAssignments`, apiVersion: '2022-04-01', filter: '$filter=atScope()' }, deadline, true)),
    ], read => read());
    const expectedRole = phase.instance ? receipts.queueRecords?.['queue-role'] : null;
    const expectedAssignment = phase.instance ? receipts.queueRecords?.['queue-assignment'] : null;
    for (const [expected, actual] of [[expectedRole, role], [expectedAssignment, assignment]]) {
      if (expected) verifyQueueResource(c, topology, expected.phase.resources[0], actual);
      else if (actual !== null) fail('NSP_UNREVIEWED_QUEUE_GRANT');
    }
    for (const list of grants) for (const grant of list.value) {
      const p = grant?.properties;
      if (!p || typeof p.scope !== 'string' || typeof p.principalId !== 'string' || typeof p.roleDefinitionId !== 'string') fail('NSP_GRANT_EVIDENCE_UNVERIFIED');
      const scoped = [q.account, q.service, q.queue].some(scope => sameId(p.scope, scope) || p.scope.toLowerCase().startsWith(scope.toLowerCase() + '/'));
      if ((scoped || sameId(p.principalId, identity.properties.principalId)) &&
          (!expectedAssignment || !sameId(grant.id, q.assignment) || !sameId(p.scope, q.queue) ||
            !sameId(p.principalId, identity.properties.principalId) || !sameId(p.roleDefinitionId, q.role) || p.condition)) fail('NSP_UNREVIEWED_QUEUE_GRANT');
    }
  };
  const io = {
    ...port, sourceDigest, sleep: options.sleep ?? pause, cancelled: options.cancelled,
    describeFailure: safeOperationFailure,
    topologyReview: evidence.nspReview, billingReview: evidence.nspBillingReview, billingEvidence: evidence.nspBillingEvidence,
    readHead: value => readNspHead(value, pending),
    retainPolicy: snapshot => save(directory, `${phase.phase}-effective-policy-reads.json`, snapshot),
    foundation: async deadline => {
      activeDeadline = deadline;
      verifyScannerAdoption(c, origin, evidence.scannerAdoption);
      const foundation = verifyFoundationBudgets(c, evidence.foundationBudgets);
      await verifyPublishedNspEvidence(c, network, topology, adoption, options.lookup ?? publishedSourceDigest);
      const reconciled = await reviewedReconciliationReceipts(c, foundation, evidence.reconciliation, await sourceDigest(), options.lookup ?? publishedSourceDigest, options);
      for (const [name, value] of Object.entries(reconciled)) {
        if (!isDeepStrictEqual(receipts[name], value)) fail('NSP_RECONCILIATION_REQUIRED');
      }
      const account = await boundedInvoke(deadline, invoke, now)(['account', 'show', '--subscription', c.subscriptionId,
        '--only-show-errors', '--output', 'json']);
      if (account?.id !== c.subscriptionId || account.tenantId !== c.tenantId ||
          account.state !== 'Enabled' || account.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
      await readBatch([
        () => verifyOrigin(origin, at(deadline), c, evidence.scannerAdoption),
        () => verifyFreshReconciliation(c, directory, evidence.reconciliation, boundedInvoke(deadline, invoke, now), undefined,
          { receiverCandidate: receipts.receiverUpgrade.candidate, imageDescriptor: receipts.receiverUpgrade.phase.resources[0] }),
        () => common.security(deadline),
        () => disabled(deadline),
      ], read => read());
      const known = knownResourceIds(c, { ...receipts, nspNetwork: network });
      const inventory = await port.read({ id: `${ids(c).group}/resources`, apiVersion: '2021-04-01', filter: null }, deadline, true);
      if (inventory.value.some(value => !known.some(id => sameId(id, value.id)))) fail('UNEXPECTED_TELEMETRY_RESOURCE');
      const providers = await port.read({ id: `${ids(c).sub}/providers`, apiVersion: '2021-04-01', filter: null }, deadline, true);
      const networkProviders = providers.value.filter(value => sameId(value.namespace, 'Microsoft.Network'));
      if (networkProviders.length !== 1) fail('NSP_PROVIDER_NOT_QUALIFIED');
      const provider = networkProviders[0];
      verifyNspApiCatalog(provider);
      verifyQueueApiCatalog(providers.value.find(value => sameId(value.namespace, 'Microsoft.Storage')));
      if (phase.deploymentId && await at(deadline)('GET', phase.deploymentId, '2022-09-01')) fail('NSP_DEPLOYMENT_ALREADY_EXISTS');
      return { known, providerCatalog: provider, baselineSha256: origin.policyBaselineSha256, binding: {
        executionOriginsSha256: digest(json(evidence.reconciliation.origins)),
        reconciliationSha256: digest(json(evidence.reconciliation)), receiverRecordSha256: digest(json(receipts.receiverUpgrade)),
        receiverManifestDigest: receipts.receiverUpgrade.candidate.profile.manifestDigest,
        receiverConfigDigest: receipts.receiverUpgrade.candidate.profile.configDigest } };
    },
    preview: async deadline => {
      activeDeadline = deadline;
      await save(directory, `${phase.phase}-template.json`, phase.template);
      const validation = await boundedInvoke(deadline, invoke, now)(['deployment', 'group', 'validate', '--subscription', c.subscriptionId,
        '--resource-group', `${c.namePrefix}-telemetry`, '--name', phase.deploymentId.split('/').at(-1),
        '--template-file', resolve(directory, `${phase.phase}-template.json`), '--only-show-errors', '--output', 'json']);
      if (validation?.properties?.provisioningState !== 'Succeeded' || validation.error || validation.properties.error || validation.nextLink) fail('NSP_TEMPLATE_NOT_VALIDATED');
      const result = await asyncWhatIf(c, phase, directory, { ...options, deadline });
      await save(directory, `${phase.phase}-what-if-raw.json`, result.raw);
      return { validation, preview: result.result };
    },
    saveCheck: async (proof, preview) => {
      await save(directory, `${phase.phase}-preflight.json`, proof);
      await save(directory, `${phase.phase}-what-if.json`, preview.preview);
      await save(directory, `${phase.phase}-validation.json`, preview.validation);
    },
    loadJournal: () => load(directory, `${phase.phase}-journal.json`, true),
    saveJournal: journal => save(directory, `${phase.phase}-journal.json`, journal),
    saveReceipt: receipt => saveImmutable(directory, `${phase.phase}-receipt.json`, receipt),
    reserve: async journal => {
      pending = await reserveNspIntent(network, phase, journal);
    },
    observe: async deadline => {
      activeDeadline = deadline;
      const deployment = phase.deploymentId ? await at(deadline)('GET', phase.deploymentId, '2022-09-01') : null;
      if (phase.deploymentId && deployment?.properties?.provisioningState !== 'Succeeded') return { deployment, observation: null };
      return { deployment, observation: await collectNspObservation(network.topology, port, deadline, { c, adoption }) };
    },
    verifyCurrent: async (proof, deadline) => {
      activeDeadline = deadline;
      await readNspHead(network, pending);
      await readBatch([() => common.security(deadline), () => disabled(deadline)], read => read());
      const [observation, permissions] = await readBatch([
        () => collectNspObservation(network.topology, port, deadline, { c, adoption }),
        () => collectNspPermissions(c, phase, network.topology, port, deadline),
      ], read => read());
      verifyNspObservation(c, network.topology, adoption, observation, phase.beforeStage);
      if (!isDeepStrictEqual(nspState(observation), nspState(proof.observation)) ||
          !isDeepStrictEqual(permissions, proof.permissions)) fail('NSP_DISPATCH_STATE_CHANGED');
      const effective = await collectNspEffectivePolicies(phase, io, deadline);
      if (digest(json(effective)) !== proof.effectivePolicySha256) fail('NSP_EFFECTIVE_POLICY_DRIFT');
      if (phase.deploymentId && await at(deadline)('GET', phase.deploymentId, '2022-09-01')) fail('NSP_DEPLOYMENT_ALREADY_EXISTS');
    },
  };
  io.check = () => {
    activeDeadline = now() + NSP_LIMITS.stageMs;
    return checkNspReadOnly(c, phase, topology, adoption, network, io);
  };
  return io;
}
async function checkQueuedDisableReadOnly(c, phase, origin, receipts, directory, evidence, invoke, lookup, transition, options) {
  const now = options.now ?? Date.now, startedAt = now();
  const deadline = Math.min(options.deadline ?? startedAt + 120000, startedAt + 120000);
  invoke = limitReadConcurrency(boundedInvoke(deadline, invoke, now));
  const source = await sourceDigest(), candidate = receipts.receiverUpgrade?.candidate;
  if (phase.phase !== 'synthetic-disable' || phase.ingestEnabled !== false || candidate?.version !== 2 ||
      !transition || transition.source !== source ||
      !isDeepStrictEqual(transition.phases?.['synthetic-disable'], phase)) fail('PAIRED_RECEIVER_DISABLE_REQUIRED');
  verifySyntheticWindow(c, transition.phases, transition.window, transition.approvals, source, now(), false);
  if (transition.window.receiptsSha256 !== digest(json(receipts)) || transition.window.originSha256 !== digest(json(origin)) ||
      !isDeepStrictEqual(phase, buildPhase(c, 'synthetic-disable', null, receipts, evidence.foundationBudgets,
        evidence.reconciliation, phase.windowInstance))) fail('RECEIVER_DISABLE_PREREQUISITES_CHANGED');
  verifyScannerAdoption(c, origin, evidence.scannerAdoption);
  const foundation = verifyFoundationBudgets(c, evidence.foundationBudgets);
  verifyDisabledImageRecord(c, receipts.receiverUpgrade);
  await verifyReceiverSource(candidate, options.sourceRun, lookup);
  const history = { ...evidence.reconciliation, receiverCandidate: candidate,
    queueRecords: receipts.queueRecords, nspNetwork: receipts.nspNetwork };
  const reconciled = await reviewedReconciliationReceipts(c, foundation, history, source, lookup, options);
  if (Object.entries(reconciled).some(([name, value]) => !isDeepStrictEqual(receipts[name], value))) fail('RECONCILIATION_RECEIPTS_REQUIRED');
  if (!evidence.windowPredecessor) fail('TERMINAL_WINDOW_PREDECESSOR_REQUIRED');
  verifyWindowInstancePredecessor(c, phase.windowInstance, evidence.windowPredecessor);
  await verifyPublishedWindowPredecessor(c, evidence.windowPredecessor, lookup, options.sourceRun);
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account.tenantId !== c.tenantId ||
      account.state !== 'Enabled' || account.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  const r = ids(c), arm = transport(c, phase, directory, invoke);
  const [app, ingest, pull] = await readBatch([
    [r.app, '2025-07-01'], [r.ingestIdentity, '2023-01-31'], [r.pullIdentity, '2023-01-31'],
  ], ([id, api]) => arm('GET', id, api));
  const context = { ...resourceContext(c, receipts), identities: { [r.ingestIdentity]: ingest, [r.pullIdentity]: pull } };
  const observedFlag = verifyWindowState(c, transition.phases, transition.window, transition.approvals,
    transition.journals, app, context, source);
  const validation = await validateReadOnly(c, phase, receipts, directory, invoke, app, { ...options, deadline, receiverCandidate: candidate });
  const cost = durableQueueCost();
  const proof = { startedAt, completedAt: now(), qualified: cost.withinEstimate,
    qualificationKind: 'paired-receiver-disable-only-preflight', liveQueueNetworkRechecked: false,
    liveFoundationRechecked: false, costBasis: 'unchanged-reviewed-receiver-estimate-not-current-network-billing',
    configSha256: digest(json(c)), phaseSha256: digest(json(phase)), sourceSha256: source,
    originSha256: digest(json(origin)), receiptsSha256: digest(json(receipts)),
    baselineSha256: origin.policyBaselineSha256, whatIfSha256: validation.whatIfSha256,
    transitionSha256: syntheticTransitionHash(phase), observedFlag, appObservationSha256: digest(json(app)),
    cost, computedValuesReviewed: phase.computedReadbacksRequired.length === 0 };
  if (await sourceDigest() !== source || now() >= deadline) fail('WINDOW_READ_DEADLINE');
  await save(directory, `${phase.phase}-preflight.json`, proof);
  if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
  return proof;
}
export async function checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles, invoke = az, lookup = publishedSourceDigest, transition, options = {}) {
  if (phase.phase === 'synthetic-disable' && receipts.receiverUpgrade?.candidate.version === 2 &&
      receipts.queueRecords?.['queue-storage']?.kind === 'reviewed-queue-storage-adoption' && transition) {
    return checkQueuedDisableReadOnly(c, phase, origin, receipts, directory, evidenceFiles, invoke, lookup, transition, options);
  }
  const now = options.now ?? Date.now, started = now(), deadline = Math.min(options.deadline ?? invokeDeadlines.get(invoke) ?? started + 120000, started + 120000);
  const bounded = boundedInvoke(deadline, invoke, now);
  invoke = limitReadConcurrency(async (args, timeout) => {
    try { return await bounded(args, timeout); }
    catch (error) {
      await save(directory, `${phase.phase}-readonly-failure.json`, { recordedAt: new Date().toISOString(), phase: phase.phase,
        step: azureStep(args), deadlineAt: new Date(deadline).toISOString(), failure: safeOperationFailure(error) });
      throw error;
    }
  });
  const topology = evidenceFiles.queueTopology ?? evidenceFiles.receiverCandidate?.topology ?? receipts.receiverUpgrade?.candidate.topology;
  const queuePhase = QUEUE_PHASES.includes(phase.phase);
  const networkContext = phase.phase === 'synthetic-disable' ? null : nspContext(c, receipts, evidenceFiles);
  const arm = transport(c, phase, directory, invoke, topology), r = ids(c);
  const foundation = verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
  if (evidenceFiles.reconciliation?.origins?.records.some(v => v.phase.phase === phase.phase)) fail('COMPLETED_PHASE_REQUIRES_RECONCILIATION');
  const source = await sourceDigest();
  const receiverCandidate = evidenceFiles.receiverCandidate ?? receipts.receiverUpgrade?.candidate;
  const imagePhase = IMAGE_PHASES.includes(phase.phase);
  if (queuePhase || topology) {
    verifyQueueReview(c, topology, evidenceFiles.queueReview, source, now());
    const names = queuePhase ? phase.requiredReceipts : QUEUE_PHASES;
    if (names.length) qualifiedQueueRecords(c, receipts.queueRecords, topology, names.at(-1));
    else closed(receipts.queueRecords ?? {}, []);
    await verifyPublishedQueueRecords(c, receipts.queueRecords ?? {}, lookup);
  }
  if ((imagePhase || receipts.receiverUpgrade) && !receiverCandidate) fail('REVIEWED_RECEIVER_PROFILE_REQUIRED');
  if (receiverCandidate) {
    verifyReceiverCandidate(c, receiverCandidate);
    await verifyReceiverSource(receiverCandidate, options.sourceRun, lookup);
    if (['disabled-image-upgrade', 'disabled-queue-upgrade', 'synthetic-admission'].includes(phase.phase) &&
        receiverDatabaseInstant(receiverCandidate.profile.scan.databaseNextUpdate) <= now()) fail('RECEIVER_SCAN_EXPIRED');
  }
  if (transition && (!TOGGLE_PHASES.includes(phase.phase) || transition.source !== source)) fail('CURRENT_WINDOW_SOURCE_REQUIRED');
  let reconciled = {};
  if (evidenceFiles.reconciliation?.origins) {
    const historicalCandidate = reconciliationReceiverCandidate(evidenceFiles.reconciliation.proposal, receiverCandidate);
    if (receiverCandidate && (![4, 5, 6].includes(evidenceFiles.reconciliation.proposal?.version) ||
        evidenceFiles.reconciliation.proposal.receiverCandidateSha256 !== digest(json(historicalCandidate)))) fail('VERSIONED_RECEIVER_RECONCILIATION_REQUIRED');
    reconciled = await reviewedReconciliationReceipts(c, foundation,
      { ...evidenceFiles.reconciliation, ...(historicalCandidate ? { receiverCandidate: historicalCandidate } : {}) }, source, lookup, options);
    if ((!queuePhase && !isDeepStrictEqual(phase.reconciliation, reconciliationBinding(evidenceFiles.reconciliation))) ||
        Object.entries(reconciled).some(([name, value]) => !isDeepStrictEqual(receipts[name], value))) fail('RECONCILIATION_RECEIPTS_REQUIRED');
  }
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account?.tenantId !== c.tenantId || account?.state !== 'Enabled' || account?.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  const imageDescriptor = imagePhase ? structuredClone(phase.resources[0])
    : receipts.receiverUpgrade ? receipts.receiverUpgrade.phase.resources[0] : undefined;
  if (imagePhase) imageDescriptor.expected.properties.template.containers[0].image =
    `${c.registryName}.azurecr.io/missionspec/telemetry-ingest@${phase.transition.fromDigest}`;
  if (phase.phase === 'disabled-queue-upgrade') imageDescriptor.expected.properties.template.containers[0].env =
    imageDescriptor.expected.properties.template.containers[0].env.filter(v => !Object.hasOwn(queueEnvironment(topology), v.name));
  const [, verifiedApp] = await readBatch([
    () => verifyOrigin(origin, arm, c, evidenceFiles.scannerAdoption),
    () => evidenceFiles.reconciliation?.origins
      ? verifyFreshReconciliation(c, directory, evidenceFiles.reconciliation, invoke, transition,
        { ...(receiverCandidate ? { receiverCandidate } : {}), ...(imageDescriptor ? { imageDescriptor } : {}) }) : undefined,
  ], read => read());
  if (imagePhase) {
    if (!evidenceFiles.reconciliation?.origins || !evidenceFiles.windowPredecessor) fail('IMAGE_HISTORY_REQUIRED');
    await verifyPublishedWindowPredecessor(c, evidenceFiles.windowPredecessor, lookup, options.sourceRun);
    await readWindowPredecessor(c, evidenceFiles.windowPredecessor, directory, invoke, undefined, verifiedApp);
    if (await arm('GET', phase.deploymentId, '2022-09-01')) fail('IMAGE_DEPLOYMENT_ALREADY_EXISTS');
  }
  if (queuePhase) {
    if (!evidenceFiles.reconciliation?.origins || !evidenceFiles.windowPredecessor || !receipts.receiverUpgrade) fail('QUEUE_DISABLED_PREPARED_RECEIVER_REQUIRED');
    await verifyPublishedWindowPredecessor(c, evidenceFiles.windowPredecessor, lookup, options.sourceRun);
    await readWindowPredecessor(c, evidenceFiles.windowPredecessor, directory, invoke, undefined, verifiedApp);
  }
  if (TOGGLE_PHASES.includes(phase.phase)) await checkWindowLineage(c, phase, evidenceFiles.windowPredecessor, directory, invoke, lookup, transition, verifiedApp);
  if (phase.phase !== 'project-budget') {
    verifyProjectBudgetReceipt(c, receipts['project-budget'], foundation, source, reconciled);
  }
  const evidence = {};
  await readBatch([
    ['providers', `${r.sub}/providers`, '2021-04-01'],
    ['permissions', `${r.sub}/providers/Microsoft.Authorization/permissions`, '2022-04-01'],
    ['denies', `${r.sub}/providers/Microsoft.Authorization/denyAssignments`, '2022-04-01'],
    ['policies', `${r.sub}/providers/Microsoft.Authorization/policyAssignments`, '2023-04-01'],
    ['defender', `${r.sub}/providers/Microsoft.Security/pricings`, '2024-01-01'],
    ['quota', `${r.sub}/providers/Microsoft.App/locations/${c.location}/usages`, '2025-01-01'],
    ['telemetry-inventory', `${r.group}/resources`, '2021-04-01'],
  ], async ([name, id, api]) => {
    evidence[name] = await arm('GET', id, api); await save(directory, `${phase.phase}-${name}.json`, evidence[name]);
  });
  if (!evidence.permissions?.value?.some(v => v.actions?.includes('*') && !v.notActions?.length) || evidence.denies?.value?.length) fail('PERMISSION_REVIEW_REQUIRED');
  for (const ns of ['Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.ManagedIdentity', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.Consumption', 'Microsoft.Authorization',
    ...(topology ? ['Microsoft.Storage'] : [])]) {
    if (!evidence.providers.value.some(v => v.namespace?.toLowerCase() === ns.toLowerCase() && v.registrationState === 'Registered')) fail('PROVIDER_NOT_REGISTERED');
  }
  for (const [ns, type] of [['Microsoft.App', 'managedEnvironments'], ['Microsoft.App', 'containerApps'],
    ['Microsoft.ContainerRegistry', 'registries'], ['Microsoft.OperationalInsights', 'workspaces'], ['Microsoft.Insights', 'dataCollectionRules'],
    ...(topology ? [['Microsoft.Storage', 'storageAccounts']] : [])]) {
    const provider = evidence.providers.value.find(v => v.namespace.toLowerCase() === ns.toLowerCase());
    if (!provider.resourceTypes.some(v => v.resourceType === type && v.locations?.includes('Australia East'))) fail('REGION_NOT_SUPPORTED');
  }
  if (topology) {
    const storage = evidence.providers.value.find(v => v.namespace.toLowerCase() === 'microsoft.storage');
    verifyQueueApiCatalog(storage);
  }
  const baseline = digest(json({ policies: evidence.policies, defender: evidence.defender }));
  if (baseline !== origin.policyBaselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
  const effectivePolicy = queuePhase ? await checkEffectivePolicies(c, phase, directory, invoke, topology, undefined, { now, deadline }) : undefined;
  const known = knownResourceIds(c, receipts);
  if (evidence['telemetry-inventory'].value.some(v => !known.some(id => sameId(id, v.id)))) fail('UNEXPECTED_TELEMETRY_RESOURCE');
  let providerOperationsSha256;
  if (topology) {
    const operations = await arm('GET', '/providers/Microsoft.Storage/operations', '2025-01-01');
    providerOperationsSha256 = verifyQueueProviderOperations(operations);
    await save(directory, 'queue-provider-operations.json', operations);
    await readQueueRecords(c, topology, receipts.queueRecords ?? {}, arm, nspReadIO(c, directory, invoke, { now }), deadline);
  }
  if (phase.phase === 'core') {
    const q = evidence.quota.value.find(v => v.name?.value === 'ManagedEnvironmentCount');
    if (!q || q.limit - q.currentValue < 1) fail('ENVIRONMENT_QUOTA_UNAVAILABLE');
    if (await arm('GET', r.managedGroup, '2024-03-01')) fail('MANAGED_GROUP_NAME_EXISTS');
    const name = await arm('POST', `${r.sub}/providers/Microsoft.ContainerRegistry/checkNameAvailability`, '2023-07-01',
      { name: c.registryName, type: 'Microsoft.ContainerRegistry/registries' });
    if (name?.nameAvailable !== true) fail('REGISTRY_NAME_UNAVAILABLE');
  }
  let currentApp;
  const currentResources = await readBatch(phase.resources, descriptor => arm('GET', descriptor.id, descriptor.apiVersion));
  for (const [index, descriptor] of phase.resources.entries()) {
    const actual = currentResources[index];
    if (Object.keys(phase.allowedModify).some(id => sameId(id, descriptor.id))) {
      if (!actual) fail('OWNED_UPDATE_TARGET_MISSING');
      const historical = phase.phase === 'project-budget' ? foundation.project
        : Object.values(receipts).map(v => v.resources?.[descriptor.id]).filter(Boolean).at(-1);
      if (imagePhase) {
        const predecessor = evidenceFiles.windowPredecessor;
        const anchor = predecessor.kind === 'reviewed-disabled-image-change' ? predecessor.receipt.resources[r.app] : predecessor.readback.app;
        verifyDisabledImageBefore(c, phase, actual, anchor, { ...resourceContext(c, receipts), receiverCandidate });
        currentApp = actual; continue;
      }
      if (TOGGLE_PHASES.includes(phase.phase)) {
        const context = resourceContext(c, receipts), flag = admissionFlag(actual);
        if (!historical || !phase.transition.from.includes(flag)) fail('TOGGLE_CURRENT_STATE_INVALID');
        if (transition) verifyWindowState(c, transition.phases, transition.window, transition.approvals, transition.journals, actual, context, source);
        else if (flag !== 'false') fail('UNREVIEWED_ENABLED_APP_STATE');
        const current = canonicalAppWrite(c, descriptorWithFlag(descriptor, flag), actual, context);
        current.properties.template.containers[0].env.MSR_INGESTION_ENABLED = 'false';
        if (!isDeepStrictEqual(current, canonicalAppWrite(c, descriptorWithFlag(descriptor, 'false'),
          receiverAnchor(c, receipts), context))) fail('TOGGLE_IMMUTABLE_APP_DRIFT');
        currentApp = actual; continue;
      }
      const normalize = phase.phase === 'project-budget' ? budgetConfiguration : stableReadback;
      if (!historical || !sameId(actual.id, descriptor.id) || !isDeepStrictEqual(normalize(actual), normalize(historical))) fail('OWNED_TARGET_DRIFT');
    } else if (actual) fail('NEW_RESOURCE_NAME_EXISTS');
  }
  const [projectBudget, stateBudget] = await readBatch([r.projectBudget, r.stateBudget], id => arm('GET', id, '2024-08-01'));
  assertBudget(projectBudget, c,
    phase.phase === 'project-budget' ? c.budget.previousProjectAmount : c.budget.projectAmount, projectBudgetFilter(c));
  assertBudget(stateBudget, c, c.budget.stateAmount);
  let roleDefinitionsSha256;
  if (phase.phase === 'assignments') {
    const definitions = await readAssignmentRoleDefinitions(c, phase, arm, receipts['upload-role']);
    roleDefinitionsSha256 = digest(json(definitions.roles));
    await save(directory, 'assignments-role-definitions.json', { checkedAt: new Date().toISOString(), ...definitions, roleDefinitionsSha256 });
  }
  const validationProof = await validateReadOnly(c, phase, receipts, directory, invoke, currentApp,
    { ...options, deadline, receiverCandidate, queueTopology: topology, networkContext });
  const networkProof = networkContext
    ? await currentNspAdmission(c, networkContext, evidenceFiles, directory, deadline, invoke, { now }) : null;
  const { whatIfSha256 } = validationProof;
  const cost = topology ? durableQueueCost() : firstReleaseCost(receiverCandidate ? 2 : 1);
  const verifiedSource = await sourceDigest();
  if (verifiedSource !== source) fail('CURRENT_POLICY_SOURCE_CHANGED');
  if (now() >= deadline) fail('WINDOW_READ_DEADLINE');
  const proof = { startedAt: started, completedAt: now(), qualified: cost.withinEstimate, configSha256: digest(json(c)),
    phaseSha256: digest(json(phase)), sourceSha256: verifiedSource, originSha256: digest(json(origin)),
    receiptsSha256: digest(json(receipts)),
    baselineSha256: roleDefinitionsSha256 ? digest(json({ foundationBaselineSha256: baseline, roleDefinitionsSha256 })) : baseline, whatIfSha256,
    ...(roleDefinitionsSha256 ? { foundationBaselineSha256: baseline, roleDefinitionsSha256 } : {}),
    ...(receiverCandidate ? { receiverScanExpiresAt: receiverCandidate.profile.scan.databaseNextUpdate } : {}),
    ...(topology ? { topologyReviewSha256: digest(json(evidenceFiles.queueReview)), providerOperationsSha256, preservedIds: known } : {}),
    ...(effectivePolicy ?? {}),
    ...(networkProof ?? {}),
    ...(currentApp ? { ...(imagePhase ? {} : { transitionSha256: syntheticTransitionHash(phase) }), observedFlag: admissionFlag(currentApp),
      appObservationSha256: digest(json(currentApp)) } : {}),
    cost, computedValuesReviewed: phase.computedReadbacksRequired.length === 0 };
  if (queuePhase) {
    proof.receiptsSha256 = digest(json(receipts.queueRecords ?? {}));
    proof.foundationBaselineSha256 = baseline;
    for (const key of ['queuePreview', 'queuePreviewSha256', 'requiredPostCreateReadbacksSha256', 'armValidationSha256', 'validatedTemplateSha256']) proof[key] = validationProof[key];
    proof.baselineSha256 = queuePreflightBaseline(proof);
  }
  await save(directory, `${phase.phase}-preflight.json`, proof);
  if (now() >= deadline) {
    proof.qualified = false; proof.failureCode = 'WINDOW_READ_DEADLINE';
    await save(directory, `${phase.phase}-preflight.json`, proof);
    fail('WINDOW_READ_DEADLINE');
  }
  if (!cost.withinEstimate) fail('FIRST_RELEASE_COST_EXCEEDS_ESTIMATE');
  return proof;
}

export class CollectorController {
  constructor(c, phase, io) { this.config = c; this.phase = phase; this.io = io; }
  async execute(approval) {
    const p = this.phase;
    if ([...TOGGLE_PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES].includes(p.phase)) fail('PAIRED_SYNTHETIC_WINDOW_REQUIRED');
    verifyApproval(approval, this.config, p, await this.io.sourceDigest(), this.io.now());
    if (await this.io.loadJournal()) fail('EXISTING_PHASE_INTENT_REQUIRES_RECONCILIATION');
    const checkStartedAt = this.io.now();
    const proof = await this.io.check();
    const beforeDispatch = () => { verifyFreshReview(proof, approval, checkStartedAt, this.io.now()); };
    beforeDispatch();
    if (p.phase === 'assignments' && typeof this.io.assignmentRoleDefinitions !== 'function') fail('ASSIGNMENT_ROLE_READBACK_REQUIRED');
    const beforeAssignmentWrite = p.phase === 'assignments' ? async () => {
      const current = await this.io.assignmentRoleDefinitions();
      if (digest(json(current.roles)) !== proof.roleDefinitionsSha256) fail('ASSIGNMENT_ROLE_DEFINITION_DRIFT');
    } : undefined;
    if (await this.io.arm('GET', p.deploymentId, '2022-09-01')) fail('DEPLOYMENT_NAME_EXISTS');
    beforeDispatch();
    const journal = { phase: p.phase, phaseSha256: approval.phaseSha256, intentAt: new Date(this.io.now()).toISOString(), outcome: 'submission-possible' };
    await this.io.saveJournal(journal);
    try {
      beforeDispatch();
      await this.io.arm('PUT', p.deploymentId, '2022-09-01',
        { ...(p.scope === ids(this.config).sub ? { location: this.config.location } : {}),
          properties: { mode: 'Incremental', template: p.template } }, undefined, beforeDispatch, beforeAssignmentWrite);
      while (this.io.now() < Date.parse(approval.expiresAt)) {
        const d = await this.io.arm('GET', p.deploymentId, '2022-09-01');
        const state = d?.properties?.provisioningState;
        if (state === 'Succeeded') {
          const resources = {};
          const context = p.resources.some(v => v.type === 'Microsoft.Insights/dataCollectionRules')
            ? { workspace: await this.io.arm('GET', ids(this.config).workspace, '2023-09-01') } : {};
          if (p.resources.some(v => v.type === 'Microsoft.App/containerApps')) {
            const r = ids(this.config);
            context.identities = { [r.ingestIdentity]: await this.io.arm('GET', r.ingestIdentity, '2023-01-31'),
              [r.pullIdentity]: await this.io.arm('GET', r.pullIdentity, '2023-01-31') };
            context.publication = this.io.publicationReceipt;
          }
          for (const descriptor of p.resources) resources[descriptor.id] =
            verifyResource(this.config, p, descriptor, await this.io.arm('GET', descriptor.id, descriptor.apiVersion), context);
          await this.io.privacyChecks(resources);
          const receipt = { qualified: true, phase: p.phase, configSha256: approval.configSha256, phaseSha256: approval.phaseSha256,
            sourceSha256: approval.sourceSha256, deployment: d, resources, completedAt: new Date(this.io.now()).toISOString() };
          await this.io.saveReceipt(receipt); journal.outcome = 'readback-qualified'; await this.io.saveJournal(journal); return receipt;
        }
        if (['Failed', 'Canceled'].includes(state)) fail('DEPLOYMENT_FAILED_RESOURCES_PRESERVED');
        await this.io.sleep(3000);
      }
      fail('DEADLINE_RECONCILIATION_REQUIRED');
    } catch (e) {
      journal.outcome = 'reconciliation-required'; journal.failureCode = /^[A-Z_]+$/u.test(e.message) ? e.message : 'ARM_PHASE_FAILED';
      if (typeof e.armCode === 'string') journal.armCode = e.armCode;
      await this.io.saveJournal(journal);
      throw new Error('PHASE_STOPPED_OWNED_RESOURCES_PRESERVED');
    }
  }
}
function checkWindowProof(c, phase, window, proof, started, now) {
  if (phase.receiverUpgradeSha256 && phase.phase === 'synthetic-admission' &&
      receiverDatabaseInstant(proof?.receiverScanExpiresAt) <= now) fail('RECEIVER_SCAN_EXPIRED');
  if (proof?.qualified !== true || proof.configSha256 !== digest(json(c)) || proof.phaseSha256 !== digest(json(phase)) ||
      proof.sourceSha256 !== window.sourceSha256 || proof.originSha256 !== window.originSha256 ||
      proof.receiptsSha256 !== window.receiptsSha256 || proof.baselineSha256 !== window.baselineSha256 ||
      proof.transitionSha256 !== syntheticTransitionHash(phase) || !phase.transition.from.includes(proof.observedFlag) ||
      !/^[0-9a-f]{64}$/u.test(proof.whatIfSha256 ?? '') ||
      proof.cost?.withinEstimate !== true || proof.cost.estimateLimit !== 350 || !Number.isFinite(proof.cost.total) || proof.cost.total < 0 || proof.cost.total > 350 ||
      !Number.isSafeInteger(started) || !Number.isSafeInteger(now) ||
      !Number.isSafeInteger(proof.startedAt) || !Number.isSafeInteger(proof.completedAt) || proof.startedAt < started ||
      proof.completedAt < proof.startedAt || proof.completedAt > now || now - proof.startedAt > 300000) fail('FRESH_WINDOW_REVIEW_MISMATCH');
}
export function latestRevisionReady(c, phase, window, observation) {
  const { app, revisions, context } = observation, descriptor = phase.resources[0], r = ids(c);
  const flag = admissionFlag(app);
  const canonical = canonicalAppWrite(c, descriptorWithFlag(descriptor, flag), app, context);
  canonical.properties.template.containers[0].env.MSR_INGESTION_ENABLED = 'false';
  if (!isDeepStrictEqual(canonical, canonicalAppWrite(c, descriptorWithFlag(descriptor, 'false'), window.anchorApp, context))) fail('ROLLOUT_IMMUTABLE_APP_DRIFT');
  if (!Array.isArray(revisions?.value) || revisions.nextLink) fail('REVISION_READBACK_INCOMPLETE');
  if (flag !== phase.transition.to || app.properties.provisioningState !== 'Succeeded' || app.properties.runningStatus !== 'Running') return false;
  const name = app.properties.latestRevisionName;
  if (typeof name !== 'string' || !/^[a-z0-9-]+$/u.test(name) || name !== app.properties.latestReadyRevisionName) return false;
  const active = revisions.value.filter(v => v.properties?.active === true);
  if (active.length !== 1 || active[0].name !== name || !sameId(active[0].id, `${r.app}/revisions/${name}`)) return false;
  const p = active[0].properties;
  if (p.provisioningState === 'Failed' || p.healthState === 'Unhealthy') fail('LATEST_REVISION_UNHEALTHY');
  if (p.provisioningState !== 'Provisioned' || p.healthState !== 'Healthy' ||
      !['Running', 'RunningAtMaxScale'].includes(p.runningState) || p.replicas !== 1 || p.trafficWeight !== 100) return false;
  const replicaApp = structuredClone(app);
  // The immutable revision GET omits these optional defaults as null; the live app was checked above.
  replicaApp.properties.template = structuredClone(p.template);
  if (replicaApp.properties.template.revisionSuffix === null) delete replicaApp.properties.template.revisionSuffix;
  for (const key of ['cooldownPeriod', 'pollingInterval']) {
    if (replicaApp.properties.template.scale?.[key] === null) delete replicaApp.properties.template.scale[key];
  }
  if (!isDeepStrictEqual(canonicalAppWrite(c, descriptorWithFlag(descriptor, phase.transition.to), replicaApp, context),
    canonicalAppWrite(c, descriptorWithFlag(descriptor, phase.transition.to), app, context))) fail('LATEST_REVISION_TEMPLATE_DRIFT');
  return true;
}
export async function syntheticHttp(host, method, path, event, beforeDispatch, deadline = Date.now() + SYNTHETIC_LIMITS.httpTimeoutMs) {
  if (typeof host !== 'string' || !/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(host) ||
      !((method === 'GET' && ['/health/live', '/health/ready'].includes(path) && event === undefined) ||
        (method === 'POST' && path === '/v1/events' && SYNTHETIC_FIXTURES.some(v => isDeepStrictEqual(v, event))))) fail('FIXED_SYNTHETIC_REQUEST_REQUIRED');
  if (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch) || !Number.isSafeInteger(deadline)) fail('SYNTHETIC_DISPATCH_GUARD_REQUIRED');
  const body = event === undefined ? undefined : Buffer.from(JSON.stringify(event));
  if (body && body.length > 1024) fail('SYNTHETIC_BODY_BOUND');
  const started = performance.now();
  return new Promise(resolve => {
    let timer, request, responseStream, done = false, size = 0, tlsVerified = false, headersObserved = false, monotonicDeadline;
    const timings = { dnsCompleteMs: null, tcpConnectMs: null, tlsVerifiedMs: null, requestFinishMs: null,
      firstByteMs: null, responseEndMs: null, timeoutMs: null };
    const stamp = key => {
      if (!done && timings[key] === null) timings[key] = Math.max(0, performance.now() - started);
    };
    const phase = () => timings.responseEndMs !== null ? 'response-end' : headersObserved ? 'response-body' : timings.firstByteMs !== null ? 'response-headers' :
      timings.requestFinishMs !== null ? 'waiting-for-response' : timings.tlsVerifiedMs !== null ? 'request-write' :
      timings.tcpConnectMs !== null ? 'tls-handshake' : timings.dnsCompleteMs !== null ? 'tcp-connect' : 'socket-or-dns';
    const finish = result => {
      if (done) return;
      const observedAt = performance.now(), elapsed = observedAt - started;
      const late = observedAt >= monotonicDeadline || Date.now() >= deadline;
      if (late || result.errorCode === 'TOTAL_TIMEOUT_1000MS') {
        if (timings.timeoutMs === null) timings.timeoutMs = Math.max(0, elapsed);
        result = { ...result, errorCode: 'TOTAL_TIMEOUT_1000MS', failureCategory: 'deadline', failurePhase: phase() };
      }
      done = true; clearTimeout(timer);
      resolve({ ...result, bodyBytes: size, tlsVerified, durationMs: elapsed, timingsMs: { ...timings } });
      if (result.errorCode) { responseStream?.destroy(); request?.destroy(); }
    };
    if (beforeDispatch() !== undefined) fail('SYNTHETIC_DISPATCH_GUARD_REQUIRED');
    monotonicDeadline = started + SYNTHETIC_LIMITS.httpTimeoutMs;
    const remaining = Math.min(monotonicDeadline - performance.now(), deadline - Date.now());
    if (remaining <= 0) fail('SYNTHETIC_REQUEST_DEADLINE');
    const requestError = error => {
      const tlsErrors = ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'UNABLE_TO_GET_ISSUER_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID',
        'ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED'];
      const category = tlsErrors.includes(error?.code) ? 'tls-validation' : ['ENOTFOUND', 'EAI_AGAIN'].includes(error?.code) ? 'dns' : 'transport';
      finish({ status: null, errorCode: 'HTTPS_REQUEST_FAILED', failureCategory: category, failurePhase: phase() });
    };
    try {
      request = https.request({ protocol: 'https:', hostname: host, servername: host, port: 443, method, path,
        agent: false, rejectUnauthorized: true, maxHeaderSize: 8192,
        headers: { Connection: 'close', ...(body ? { 'Content-Type': 'application/json', 'Content-Length': String(body.length) } : {}) } }, response => {
        if (done) { response.destroy(); return; }
        responseStream = response; stamp('firstByteMs'); headersObserved = true;
        const headerPolicy = { noStore: response.headers['cache-control'] === 'no-store',
          zeroContentLength: response.headers['content-length'] === '0', connectionClose: response.headers.connection === 'close' };
        response.on('data', chunk => {
          if (done) return;
          size += chunk.length;
          if (size > 1024) finish({ status: response.statusCode, headerPolicy, errorCode: 'BODY_LIMIT', failureCategory: 'body-limit', failurePhase: phase() });
        });
        response.once('end', () => { stamp('responseEndMs'); finish({ status: response.statusCode, headerPolicy, errorCode: null, failureCategory: null, failurePhase: null }); });
        response.once('error', () => finish({ status: response.statusCode, headerPolicy, errorCode: 'RESPONSE_ERROR', failureCategory: 'response-stream', failurePhase: phase() }));
      });
    } catch (error) { requestError(error); return; }
    request.once('socket', socket => {
      socket.once('lookup', error => { if (!error) stamp('dnsCompleteMs'); });
      socket.once('connect', () => stamp('tcpConnectMs'));
      socket.once('secureConnect', () => { if (!done && socket.authorized === true) { tlsVerified = true; stamp('tlsVerifiedMs'); } });
      socket.once('data', () => stamp('firstByteMs'));
    });
    request.once('finish', () => stamp('requestFinishMs'));
    request.once('error', requestError);
    timer = setTimeout(() => { stamp('timeoutMs'); finish({ status: null, errorCode: 'TOTAL_TIMEOUT_1000MS' }); }, remaining);
    request.end(body);
  });
}
export function syntheticQuery(start, end) {
  if (canonicalInstant(end) < canonicalInstant(start) || canonicalInstant(end) - canonicalInstant(start) > SYNTHETIC_LIMITS.enabledWindowMs) fail('SYNTHETIC_QUERY_WINDOW_INVALID');
  return ['MissionSpecTelemetry_CL',
    `| where TimeGenerated between (datetime(${start}) .. datetime(${end}))`,
    '| where schemaVersion == 1 and event == "operation-completed" and cliVersion == "0.0.0" and outcome == "completed" and host == "none" and os == "linux"',
    '| where (operation == "draft" and durationBucket == "under-1s") or (operation == "verify" and durationBucket == "1s-to-10s")',
    '| project TimeGenerated, schemaVersion, event, operation, cliVersion, outcome, host, os, durationBucket',
    '| take 3'].join('\n');
}
export class SyntheticDeadlines {
  constructor(window, approvals, io) {
    Object.assign(this, { window, approvals, io, enabledAt: null, terminalFalseAt: null, incident: null,
      incidentPersistenceFailure: false, pendingIncident: Promise.resolve(), timer: null, reserveExhaustedAt: null });
  }
  bind(journal) {
    if (!journal) return;
    const enabledAt = canonicalInstant(journal.intentAt);
    if (journal.phase !== 'synthetic-admission' || journal.windowSha256 !== digest(json(this.window)) ||
        journal.phaseSha256 !== this.window.phases['synthetic-admission'].phaseSha256 ||
        journal.approvalSha256 !== digest(json(this.approvals['synthetic-admission'])) ||
        journal.windowInstanceId !== this.window.windowInstance.id ||
        journal.predecessorSha256 !== this.window.windowInstance.predecessorSha256 ||
        (this.enabledAt !== null && this.enabledAt !== enabledAt)) fail('WINDOW_INTENT_BINDING_CHANGED');
    if (this.enabledAt === null) {
      this.enabledAt = enabledAt;
      const delay = this.windowDeadline - this.io.now();
      if (delay > 0) {
        this.timer = (this.io.setTimer ?? setTimeout)(() => this.observe(), delay);
        this.timer?.unref?.();
      }
    }
    this.observe();
  }
  get workDeadline() { return this.enabledAt === null ? null : this.enabledAt + SYNTHETIC_LIMITS.enabledWindowMs - SYNTHETIC_LIMITS.rollbackReserveMs; }
  get windowDeadline() { return this.enabledAt === null ? null : this.enabledAt + SYNTHETIC_LIMITS.enabledWindowMs; }
  get recoveryDeadline() {
    return this.enabledAt === null ? null : Math.min(canonicalInstant(this.approvals['synthetic-disable'].expiresAt),
      this.windowDeadline + SYNTHETIC_LIMITS.rollbackReserveMs);
  }
  observe() {
    if (this.enabledAt !== null && this.terminalFalseAt === null && this.io.now() >= this.windowDeadline && !this.incident) {
      this.incident = { version: 1, code: 'ENABLED_WINDOW_EXCEEDED', windowSha256: digest(json(this.window)),
        enableIntentAt: new Date(this.enabledAt).toISOString(), deadlineAt: new Date(this.windowDeadline).toISOString(),
        observedAt: new Date(this.io.now()).toISOString(), terminalFalseVerified: false };
      try {
        this.pendingIncident = Promise.resolve(this.io.recordWindowIncident?.(this.incident))
          .catch(() => { this.incidentPersistenceFailure = true; });
      } catch { this.incidentPersistenceFailure = true; }
    }
  }
  check(deadline, code = 'SYNTHETIC_OPERATION_DEADLINE') {
    this.observe();
    if (!Number.isSafeInteger(deadline) || this.io.now() >= deadline) fail(code);
  }
  reserveRollout() {
    this.observe();
    if (this.windowDeadline !== null && this.io.now() + SYNTHETIC_LIMITS.rolloutTimeoutMs > this.windowDeadline && this.reserveExhaustedAt === null) {
      this.reserveExhaustedAt = this.io.now();
    }
  }
  terminalFalse() {
    this.observe(); this.terminalFalseAt = this.io.now(); this.dispose();
  }
  dispose() {
    if (this.timer !== null) (this.io.clearTimer ?? clearTimeout)(this.timer);
    this.timer = null;
  }
  snapshot() {
    return { enableIntentAt: this.enabledAt, workDeadline: this.workDeadline, windowDeadline: this.windowDeadline,
      recoveryDeadline: this.recoveryDeadline, terminalFalseAt: this.terminalFalseAt, reserveExhaustedAt: this.reserveExhaustedAt,
      incident: this.incident, incidentPersistenceFailure: this.incidentPersistenceFailure };
  }
}
export class SyntheticWindowDriver {
  constructor(c, phases, window, approvals, toggle, io) { Object.assign(this, { config: c, phases, window, approvals, toggle, io }); }
  async run() {
    verifySyntheticWindow(this.config, this.phases, this.window, this.approvals, await this.io.sourceDigest(), this.io.now(), true);
    if (await this.io.loadRun()) fail('SYNTHETIC_WINDOW_HISTORY_REQUIRES_RECONCILIATION');
    const run = { version: 1, windowSha256: digest(json(this.window)), startedAt: new Date(this.io.now()).toISOString(),
      stage: 'initial-disabled', requests: [], queries: [], enabledPosts: 0, disabledPosts: 0, healthGets: 0,
      outcome: 'in-progress', terminalFalseVerified: false };
    const queueVerification = this.phases['synthetic-admission'].queueVerification;
    if (queueVerification) run.queueObservations = [];
    await this.io.saveRun(run);
    let failure = null, rollbackFailure = null, terminalDeadline = null;
    const deadlines = this.toggle.deadlines;
    const initialDeadline = Math.min(this.io.now() + SYNTHETIC_LIMITS.rolloutTimeoutMs, canonicalInstant(this.approvals['synthetic-admission'].expiresAt));
    const persist = () => {
      deadlines.observe(); run.deadlines = deadlines.snapshot();
      if (deadlines.incident) { run.enabledWindowExceeded = true; run.expiryIncident = deadlines.incident; }
      return this.io.saveRun(run);
    };
    const admit = () => {
      deadlines.observe();
      if (this.io.cancelled?.()) fail('SYNTHETIC_CANCELLED');
      deadlines.check(Math.min(deadlines.workDeadline ?? initialDeadline,
        canonicalInstant(this.approvals['synthetic-admission'].expiresAt)), 'SYNTHETIC_REQUEST_WINDOW_CLOSED');
    };
    const request = async (method, path, fixture, disabled = false) => {
      if (!disabled) admit();
      if (run.requests.length >= SYNTHETIC_LIMITS.maximumHttpRequests) fail('SYNTHETIC_HTTP_BOUND');
      if (method === 'GET') { if (++run.healthGets > SYNTHETIC_LIMITS.maximumHealthGets) fail('SYNTHETIC_HTTP_BOUND'); }
      else if (disabled) { if (++run.disabledPosts > SYNTHETIC_LIMITS.maximumDisabledPosts) fail('SYNTHETIC_POST_RETRY_FORBIDDEN'); }
      else if (++run.enabledPosts > SYNTHETIC_LIMITS.maximumEnabledPosts) fail('SYNTHETIC_POST_RETRY_FORBIDDEN');
      if (!disabled && method === 'POST' && this.io.beforeRuntimeDispatch) {
        await this.io.beforeRuntimeDispatch(Math.min(deadlines.workDeadline ?? initialDeadline, this.io.now() + NSP_LIMITS.stageMs));
        admit();
      }
      const entry = { stage: run.stage, method, path, fixture: fixture ?? null, intentAt: new Date(this.io.now()).toISOString(), transportDispatchAttempted: false };
      run.requests.push(entry); await persist();
      const source = await this.io.sourceDigest();
      const operationDeadline = Math.min(disabled ? terminalDeadline : deadlines.workDeadline ?? initialDeadline,
        this.io.now() + SYNTHETIC_LIMITS.httpTimeoutMs);
      const guard = () => {
        if (source !== this.window.sourceSha256) fail('CURRENT_WINDOW_SOURCE_REQUIRED');
        if (!disabled) admit();
        deadlines.check(operationDeadline, 'SYNTHETIC_HTTP_DEADLINE');
      };
      guard();
      const response = await this.io.http(method, path, fixture, () => {
        guard(); entry.transportDispatchAttempted = true; entry.dispatchedAt = new Date(this.io.now()).toISOString();
      }, operationDeadline);
      entry.response = response;
      guard(); await persist();
      if (!disabled) admit();
      const queued = this.phases['synthetic-admission'].queueVerification !== undefined;
      const expected = method === 'POST' ? disabled ? 503 : queued ? 202 : 204 : 204;
      return response.status === expected && response.bodyBytes === 0 && response.tlsVerified === true &&
        response.errorCode === null && response.durationMs <= SYNTHETIC_LIMITS.httpTimeoutMs &&
        response.headerPolicy?.noStore === true;
    };
    const health = async (attempts, disabled = false) => {
      for (const path of ['/health/live', '/health/ready']) {
        let passed = false;
        for (let i = 0; i < attempts; i++) {
          if (await request('GET', path, undefined, disabled)) { passed = true; break; }
          if (i + 1 < attempts) await this.io.sleep(400);
        }
        if (!passed) fail('SYNTHETIC_HEALTH_FAILED');
      }
    };
    try {
      await this.toggle.ready('synthetic-disable', initialDeadline);
      await health(1);
      run.stage = 'enabling'; await persist();
      await this.toggle.execute('synthetic-admission');
      const journal = await this.toggle.io.loadJournal('synthetic-admission');
      deadlines.bind(journal);
      run.enabledIntentAt = journal.intentAt;
      run.stage = 'enabled-health'; await persist(); admit();
      await health(2);
      run.stage = 'two-fixed-events'; await persist();
      const queryStart = new Date(deadlines.enabledAt).toISOString();
      for (const [index, fixture] of SYNTHETIC_FIXTURES.entries()) {
        if (index) await this.io.sleep(2000);
        if (!await request('POST', '/v1/events', fixture)) fail('SYNTHETIC_POST_FAILED_NO_RETRY');
      }
      const queryEnd = new Date(this.io.now()).toISOString();
      run.stage = 'bounded-read-queries'; await persist();
      let matched = false;
      for (const delay of [15000, 60000, 180000]) {
        if (this.io.now() + delay >= deadlines.workDeadline) fail('SYNTHETIC_REQUEST_WINDOW_CLOSED');
        await this.io.sleep(delay); admit();
        if (run.queries.length >= SYNTHETIC_LIMITS.maximumQueries) fail('SYNTHETIC_QUERY_BOUND');
        const entry = { startedAt: new Date(this.io.now()).toISOString(), start: queryStart, end: queryEnd, transportDispatchAttempted: false };
        run.queries.push(entry); await persist();
        const source = await this.io.sourceDigest(), queryDeadline = Math.min(deadlines.workDeadline, this.io.now() + 30000);
        const guard = () => {
          if (source !== this.window.sourceSha256) fail('CURRENT_WINDOW_SOURCE_REQUIRED');
          admit(); deadlines.check(queryDeadline, 'SYNTHETIC_QUERY_DEADLINE');
        };
        guard();
        const result = await this.io.query(queryStart, queryEnd, guard, queryDeadline, () => {
          entry.transportDispatchAttempted = true; entry.dispatchedAt = new Date(this.io.now()).toISOString();
        });
        guard();
        entry.result = result; entry.verification = verifySyntheticRows(result, queryStart, queryEnd);
        await persist();
        admit();
        if (entry.verification.complete) {
          if (queueVerification) {
            if (typeof this.io.queueDrain !== 'function') fail('QUEUE_DRAIN_EVIDENCE_REQUIRED');
            guard();
            const observation = await this.io.queueDrain(guard, queryDeadline);
            guard(); run.queueObservations.push(observation);
            const drained = verifyQueueDrain(queueVerification, observation);
            if (canonicalInstant(observation.observedAt) < canonicalInstant(entry.startedAt) ||
                canonicalInstant(observation.observedAt) > this.io.now()) fail('QUEUE_DRAIN_EVIDENCE_REQUIRED');
            await persist(); admit();
            if (!drained) continue;
            run.queueAdmissionOnly = true;
            run.queueDrainIsApproximate = true;
          }
          matched = true; break;
        }
      }
      if (!matched) fail('SYNTHETIC_ROWS_NOT_CONFIRMED');
    } catch (error) {
      failure = /^[A-Z_]+$/u.test(error.message) ? error.message : 'SYNTHETIC_WINDOW_FAILED';
      run.failureDetails = safeOperationFailure(error);
    } finally {
      run.stage = 'disabling'; run.failureCode = failure;
      try { await persist(); } catch { failure ??= 'WINDOW_JOURNAL_WRITE_FAILED'; }
      try {
        const receipt = await this.toggle.execute('synthetic-disable');
        if (receipt.qualified !== true || admissionFlag(receipt.resources?.[ids(this.config).app]) !== 'false') fail('TERMINAL_FALSE_NOT_VERIFIED');
        run.disableReceiptSha256 = digest(json(receipt)); run.terminalFalseVerified = true;
        run.lateDisableRecovery = receipt.lateRecovery === true;
        terminalDeadline = deadlines.recoveryDeadline ?? receipt.operationDeadline;
        run.stage = 'terminal-disabled-http'; await persist();
        await health(1, true);
        if (!await request('POST', '/v1/events', SYNTHETIC_FIXTURES[0], true)) fail('TERMINAL_DISABLED_POST_FAILED');
        run.terminalDisabled503Verified = true;
      } catch (error) {
        rollbackFailure = /^[A-Z_]+$/u.test(error.message) ? error.message : 'DISABLE_RECONCILIATION_REQUIRED';
        run.disableFailureDetails = safeOperationFailure(error);
      }
      deadlines.observe(); await deadlines.pendingIncident;
      if (deadlines.incident) { run.enabledWindowExceeded = true; failure ??= 'ENABLED_WINDOW_EXCEEDED'; }
      if (deadlines.reserveExhaustedAt !== null) failure ??= 'ROLLBACK_RESERVE_EXHAUSTED';
      if (deadlines.incidentPersistenceFailure) failure ??= 'WINDOW_EXPIRY_RECORD_FAILED';
      run.failureCode = failure; run.disableFailureCode = rollbackFailure;
      run.outcome = rollbackFailure ? 'held-terminal-state-or-http-unproven' :
        run.lateDisableRecovery ? 'stopped-disabled-late-recovery' : failure ? 'stopped-disabled' : 'qualified-and-disabled';
      run.stage = 'finished'; run.completedAt = new Date(this.io.now()).toISOString();
      try { await persist(); } finally { deadlines.dispose(); }
    }
    return run;
  }
}
export class SyntheticToggleController {
  constructor(c, phases, window, approvals, io) {
    Object.assign(this, { config: c, phases, window, approvals, io });
    this.deadlines = new SyntheticDeadlines(window, approvals, io);
  }
  async transition(deadline) {
    const source = await this.io.sourceDigest();
    if (deadline !== undefined) this.deadlines.check(deadline);
    const journals = Object.fromEntries(await Promise.all(TOGGLE_PHASES.map(async name => [name, await this.io.loadJournal(name)])));
    if (deadline !== undefined) this.deadlines.check(deadline);
    return { phases: this.phases, window: this.window, approvals: this.approvals, source, journals };
  }
  async settleEnable(deadline) {
    const journal = await this.io.loadJournal('synthetic-admission');
    this.deadlines.check(deadline, 'SYNTHETIC_RECOVERY_DEADLINE');
    if (!journal || journal.transportDispatchAttempted === false) return;
    for (let poll = 0; poll < SYNTHETIC_LIMITS.maxRolloutPolls && this.io.now() < deadline; poll++) {
      const deployment = await this.io.deployment('synthetic-admission', deadline);
      this.deadlines.check(deadline, 'SYNTHETIC_RECOVERY_DEADLINE');
      if (deployment && !sameId(deployment.id, this.phases['synthetic-admission'].deploymentId)) fail('TOGGLE_DEPLOYMENT_IDENTITY_CHANGED');
      if (['Succeeded', 'Failed', 'Canceled'].includes(deployment?.properties?.provisioningState)) return;
      await this.io.sleep(Math.min(SYNTHETIC_LIMITS.rolloutPollMs, Math.max(0, deadline - this.io.now())));
      this.deadlines.observe();
    }
    fail('ENABLE_SUBMISSION_UNRESOLVED_NO_REPLAY');
  }
  async ready(name, deadline, polls = { remaining: SYNTHETIC_LIMITS.maxRolloutPolls }) {
    const phase = this.phases[name];
    while (polls.remaining > 0 && this.io.now() < deadline) {
      polls.remaining--;
      const observation = await this.io.rollout(deadline);
      this.deadlines.check(deadline, 'LATEST_REVISION_NOT_READY_WITHIN_BOUND');
      const state = await this.transition(deadline);
      this.deadlines.check(deadline, 'LATEST_REVISION_NOT_READY_WITHIN_BOUND');
      verifyWindowState(this.config, this.phases, this.window, this.approvals, state.journals,
        observation.app, observation.context, state.source);
      if (latestRevisionReady(this.config, phase, this.window, observation)) return observation;
      await this.io.sleep(Math.min(SYNTHETIC_LIMITS.rolloutPollMs, Math.max(0, deadline - this.io.now())));
      this.deadlines.observe();
    }
    fail('LATEST_REVISION_NOT_READY_WITHIN_BOUND');
  }
  async execute(name) {
    if (!TOGGLE_PHASES.includes(name)) fail('FIXED_TOGGLE_PHASE_REQUIRED');
    const operationStarted = this.io.now();
    const c = this.config, phase = this.phases[name], approval = this.approvals[name], source = await this.io.sourceDigest();
    verifySyntheticWindow(c, this.phases, this.window, this.approvals, source, this.io.now(), name === 'synthetic-admission');
    if (await this.io.loadJournal(name)) fail('EXISTING_TOGGLE_INTENT_REQUIRES_RECONCILIATION');
    const enableIntent = await this.io.loadJournal('synthetic-admission');
    this.deadlines.bind(enableIntent);
    // After the recovery write bound, only a bounded already-false observation can complete.
    const recoveryExpired = this.deadlines.recoveryDeadline !== null && this.io.now() >= this.deadlines.recoveryDeadline;
    const operationDeadline = name === 'synthetic-disable' && this.deadlines.recoveryDeadline !== null && !recoveryExpired
      ? this.deadlines.recoveryDeadline : operationStarted + SYNTHETIC_LIMITS.rolloutTimeoutMs;
    this.deadlines.check(operationDeadline);
    if (name === 'synthetic-disable') await this.settleEnable(operationDeadline);
    const started = this.io.now(), state = await this.transition(operationDeadline);
    const proof = await this.io.check(phase, state, operationDeadline);
    this.deadlines.check(operationDeadline);
    checkWindowProof(c, phase, this.window, proof, started, this.io.now());
    let rolloutDeadline = null;
    const remainingDeadline = () => rolloutDeadline === null ? operationDeadline :
      name === 'synthetic-admission' ? rolloutDeadline : Math.min(operationDeadline, rolloutDeadline);
    const checkCurrent = async () => {
      this.deadlines.check(remainingDeadline());
      const value = await this.io.observe(remainingDeadline());
      this.deadlines.check(remainingDeadline());
      const latest = await this.transition(remainingDeadline());
      if (latest.source !== this.window.sourceSha256) fail('CURRENT_WINDOW_SOURCE_REQUIRED');
      const flag = verifyWindowState(c, this.phases, this.window, this.approvals, latest.journals, value.app, value.context, latest.source);
      if (flag !== proof.observedFlag) fail('TOGGLE_STATE_CHANGED_AFTER_PREFLIGHT');
      return value;
    };
    await checkCurrent();
    const noWrite = name === 'synthetic-disable' && proof.observedFlag === 'false';
    const guard = () => {
      checkWindowProof(c, phase, this.window, proof, started, this.io.now());
      verifyWindowApproval(c, phase, this.window, approval, source, this.io.now());
      this.deadlines.check(remainingDeadline());
      if (name === 'synthetic-disable' && this.deadlines.recoveryDeadline !== null) this.deadlines.check(this.deadlines.recoveryDeadline, 'SYNTHETIC_RECOVERY_DEADLINE');
      if (name === 'synthetic-admission' && this.io.cancelled?.()) fail('SYNTHETIC_CANCELLED');
      if (name === 'synthetic-admission' &&
          canonicalInstant(this.approvals['synthetic-disable'].expiresAt) < this.io.now() + SYNTHETIC_LIMITS.enabledWindowMs + SYNTHETIC_LIMITS.rollbackReserveMs) fail('DISABLE_AUTHORITY_WINDOW_TOO_SHORT');
    };
    if (!noWrite) guard();
    if (!noWrite && await this.io.deployment(name, remainingDeadline())) fail('DEPLOYMENT_NAME_EXISTS');
    if (!noWrite) guard();
    const journal = { phase: name, phaseSha256: digest(json(phase)), windowSha256: digest(json(this.window)),
      windowInstanceId: this.window.windowInstance.id, predecessorSha256: this.window.windowInstance.predecessorSha256,
      approvalSha256: digest(json(approval)), intentAt: new Date(this.io.now()).toISOString(),
      outcome: noWrite ? 'read-only-observation' : 'submission-possible', transportDispatchAttempted: noWrite ? false : null };
    if (name === 'synthetic-admission') this.deadlines.bind(journal);
    if (!noWrite) {
      if (name === 'synthetic-disable') this.deadlines.reserveRollout();
      rolloutDeadline = Math.min(canonicalInstant(journal.intentAt) + SYNTHETIC_LIMITS.rolloutTimeoutMs,
        name === 'synthetic-disable' ? this.deadlines.recoveryDeadline ?? operationDeadline :
          this.deadlines.workDeadline ?? Number.MAX_SAFE_INTEGER);
    }
    journal.preparationDeadline = operationDeadline;
    journal.operationDeadline = remainingDeadline();
    journal.rolloutDeadline = rolloutDeadline;
    journal.deadlines = this.deadlines.snapshot();
    await this.io.saveJournal(name, journal);
    let dispatched = false;
    try {
      let deployment = null;
      const polls = { remaining: SYNTHETIC_LIMITS.maxRolloutPolls };
      if (!noWrite) {
        guard();
        await this.io.arm(phase, remainingDeadline())('PUT', phase.deploymentId, '2022-09-01',
          { properties: { mode: 'Incremental', template: phase.template } }, undefined,
          () => { guard(); dispatched = true; }, undefined, checkCurrent);
        journal.transportDispatchAttempted = true;
        this.deadlines.check(remainingDeadline(), 'TOGGLE_ROLLOUT_DEADLINE');
        const deadline = remainingDeadline();
        while (polls.remaining > 0 && this.io.now() < deadline) {
          polls.remaining--;
          deployment = await this.io.deployment(name, deadline);
          this.deadlines.check(deadline, 'TOGGLE_ROLLOUT_DEADLINE');
          if (deployment && !sameId(deployment.id, phase.deploymentId)) fail('TOGGLE_DEPLOYMENT_IDENTITY_CHANGED');
          if (deployment?.properties?.provisioningState === 'Succeeded') break;
          if (['Failed', 'Canceled'].includes(deployment?.properties?.provisioningState)) fail('TOGGLE_DEPLOYMENT_FAILED_PRESERVED');
          await this.io.sleep(Math.min(SYNTHETIC_LIMITS.rolloutPollMs, Math.max(0, deadline - this.io.now())));
          this.deadlines.observe();
        }
        if (deployment?.properties?.provisioningState !== 'Succeeded') fail('TOGGLE_DEPLOYMENT_OUTCOME_UNRESOLVED');
      }
      const ready = await this.ready(name, remainingDeadline(), polls);
      this.deadlines.check(remainingDeadline(), 'TOGGLE_ROLLOUT_DEADLINE');
      await this.io.privacy(phase, remainingDeadline());
      this.deadlines.check(remainingDeadline(), 'TOGGLE_ROLLOUT_DEADLINE');
      if (name === 'synthetic-disable') this.deadlines.terminalFalse();
      const lateRecovery = name === 'synthetic-disable' && this.deadlines.incident !== null;
      const receipt = { qualified: true, qualificationKind: noWrite ? 'read-only-terminal-disable' : 'ready-toggle-deployment',
        phase: name, configSha256: digest(json(c)), phaseSha256: digest(json(phase)), sourceSha256: source,
        windowSha256: digest(json(this.window)), approvalSha256: digest(json(approval)), deployment,
        windowInstanceId: this.window.windowInstance.id, predecessorSha256: this.window.windowInstance.predecessorSha256,
        resources: { [ids(c).app]: ready.app }, revisionReadback: ready.revisions, noCloudWrite: noWrite,
        operationDeadline: remainingDeadline(), preparationDeadline: operationDeadline, rolloutDeadline, deadlines: this.deadlines.snapshot(), lateRecovery,
        withinEnabledWindow: !lateRecovery,
        completedAt: new Date(this.io.now()).toISOString() };
      await this.io.saveReceipt(name, receipt);
      journal.outcome = noWrite ? 'read-only-already-disabled' : lateRecovery ? 'readback-qualified-late-recovery' : 'readback-qualified';
      journal.deadlines = this.deadlines.snapshot();
      journal.transportDispatchAttempted = dispatched; journal.receiptSha256 = digest(json(receipt));
      await this.io.saveJournal(name, journal); return receipt;
    } catch (error) {
      journal.outcome = 'reconciliation-required'; journal.transportDispatchAttempted = dispatched;
      journal.failureCode = /^[A-Z_]+$/u.test(error.message) ? error.message : 'TOGGLE_STOPPED';
      journal.failureDetails = safeOperationFailure(error);
      journal.deadlines = this.deadlines.snapshot();
      await this.io.saveJournal(name, journal); fail('TOGGLE_STOPPED_RESOURCES_PRESERVED');
    }
  }
}
export function buildSyntheticWindow(c, phases, receipts, origin, source, whatifs) {
  const instance = validateWindowInstance(c, phases['synthetic-admission']?.windowInstance);
  if (!isDeepStrictEqual(phases['synthetic-disable']?.windowInstance, instance)) fail('PAIRED_WINDOW_INSTANCE_MISMATCH');
  const anchorApp = receiverAnchor(c, receipts);
  if (!anchorApp || admissionFlag(anchorApp) !== 'false') fail('QUALIFIED_DISABLED_ANCHOR_REQUIRED');
  const context = { config: c, ...resourceContext(c, receipts), app: anchorApp };
  const known = knownResourceIds(c, receipts);
  const entries = {};
  for (const name of TOGGLE_PHASES) {
    const phase = phases[name], whatif = whatifs[name];
    verifyWhatIf(phase, whatif, known, context);
    entries[name] = { phaseSha256: digest(json(phase)), transitionSha256: syntheticTransitionHash(phase),
      reviewedWhatIfSha256: digest(json(whatif)), reviewedWhatIf: whatif };
  }
  return { version: 2, kind: 'bounded-two-event-window', windowInstance: structuredClone(instance),
    configSha256: digest(json(c)), sourceSha256: source,
    originSha256: digest(json(origin)), receiptsSha256: digest(json(receipts)), baselineSha256: origin.policyBaselineSha256,
    appIdentity: executionIdentity(anchorApp, 'Microsoft.App/containerApps'), anchorApp,
    phases: entries, limits: SYNTHETIC_LIMITS, fixtures: SYNTHETIC_FIXTURES };
}
export async function reserveWindowInstance(c, directory, window) {
  const instance = validateWindowInstance(c, window.windowInstance);
  try {
    await saveImmutable(directory, `window-instance-${instance.id}.json`, {
      version: 1, instanceId: instance.id, windowSha256: digest(json(window)),
      predecessorSha256: instance.predecessorSha256, sourceSha256: window.sourceSha256,
      reservedAt: new Date().toISOString(),
    });
  } catch (error) {
    if (error.code === 'EEXIST') fail('WINDOW_INSTANCE_REPLAY_FORBIDDEN');
    throw error;
  }
}
function boundedInvoke(deadline, invoke = az, now = Date.now) {
  const call = (args, timeout = 60000) => {
    if (!Number.isSafeInteger(deadline)) fail('WINDOW_READ_DEADLINE');
    const remaining = deadline - now();
    if (remaining <= 0) fail('WINDOW_READ_DEADLINE');
    return invoke(args, Math.min(timeout, remaining, 15000));
  };
  invokeDeadlines.set(call, deadline);
  return call;
}
export async function readSyntheticQuery(c, expectedWorkspace, expectedSource, start, end, beforeDispatch, deadline,
  invoke = az, readSource = sourceDigest, now = Date.now, onDispatch = () => {}) {
  if (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch) || !Number.isSafeInteger(deadline)) fail('SYNTHETIC_QUERY_GUARD_REQUIRED');
  if (typeof onDispatch !== 'function' || types.isAsyncFunction(onDispatch)) fail('SYNTHETIC_QUERY_GUARD_REQUIRED');
  const guard = () => {
    if (beforeDispatch() !== undefined) fail('SYNTHETIC_QUERY_GUARD_REQUIRED');
    if (now() >= deadline) fail('SYNTHETIC_QUERY_DEADLINE');
  };
  const r = ids(c), query = syntheticQuery(start, end);
  guard();
  const workspace = await invoke(['rest', '--method', 'GET', '--url', `https://management.azure.com${r.workspace}?api-version=2023-09-01`,
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'], Math.max(1, Math.min(15000, deadline - now())));
  if (!isDeepStrictEqual(executionIdentity(workspace), executionIdentity(expectedWorkspace))) fail('QUERY_WORKSPACE_IDENTITY_CHANGED');
  assertOwned(workspace, r.workspace, c); requireAccess(workspace);
  const customer = workspace.properties.customerId;
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(customer)) fail('QUERY_WORKSPACE_IDENTITY_CHANGED');
  if (await readSource() !== expectedSource) fail('CURRENT_WINDOW_SOURCE_REQUIRED');
  const args = ['rest', '--method', 'GET', '--url', `https://api.loganalytics.azure.com/v1/workspaces/${customer}/query?query=${encodeURIComponent(query)}`,
    '--resource', 'https://api.loganalytics.io', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'];
  guard();
  const remaining = deadline - now();
  if (remaining <= 0) fail('SYNTHETIC_QUERY_DEADLINE');
  if (onDispatch() !== undefined) fail('SYNTHETIC_QUERY_GUARD_REQUIRED');
  return invoke(args, Math.min(30000, remaining));
}
export function syntheticWindowIO(c, phases, window, approvals, receipts, rawReceipts, origin, evidenceFiles, directory, cancelled = () => false, invoke = az, options = {}) {
  const r = ids(c);
  const observe = async deadline => {
    const arm = transport(c, phases['synthetic-disable'], directory, boundedInvoke(deadline, invoke));
    const identities = { [r.ingestIdentity]: await arm('GET', r.ingestIdentity, '2023-01-31'),
      [r.pullIdentity]: await arm('GET', r.pullIdentity, '2023-01-31') };
    const app = await arm('GET', r.app, '2025-07-01');
    return { app, context: { ...resourceContext(c, receipts), identities } };
  };
  return {
    now: Date.now, sourceDigest, sleep: pause, cancelled,
    setTimer: setTimeout, clearTimer: clearTimeout,
    recordWindowIncident: async value => {
      const prior = await load(directory, 'synthetic-window-expiry.json', true);
      if (prior) {
        if (prior.windowSha256 !== value.windowSha256 || prior.enableIntentAt !== value.enableIntentAt || prior.deadlineAt !== value.deadlineAt) fail('WINDOW_INCIDENT_BINDING_CHANGED');
        return;
      }
      await saveImmutable(directory, 'synthetic-window-expiry.json', value);
    },
    loadJournal: name => load(directory, `${name}-journal.json`, true),
    saveJournal: (name, value) => save(directory, `${name}-journal.json`, value),
    saveReceipt: async (name, value) => {
      if (Object.hasOwn(rawReceipts, name)) fail('PRESERVE_PRIOR_TOGGLE_RECEIPT');
      await saveImmutable(directory, `${name}-receipt.json`, value);
      rawReceipts[name] = value; await save(directory, 'receipts.json', rawReceipts);
    },
    check: (phase, transition, deadline) => checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles,
      boundedInvoke(deadline, invoke), options.lookup ?? publishedSourceDigest, transition, {
        ...options, now: Date.now, deadline, cancelled: phase.phase === 'synthetic-admission' ? cancelled : () => false }),
    observe,
    deployment: (name, deadline) => transport(c, phases[name], directory, boundedInvoke(deadline, invoke))('GET', phases[name].deploymentId, '2022-09-01'),
    arm: (phase, deadline) => {
      const arm = transport(c, phase, directory, boundedInvoke(deadline, invoke));
      if (phase.phase !== 'synthetic-admission' || receipts.queueRecords?.['queue-storage']?.kind !== 'reviewed-queue-storage-adoption') return arm;
      return (method, id, api, body, filter, guard, roleGuard, current) => arm(method, id, api, body, filter, guard, roleGuard,
        method === 'PUT' ? async () => {
          if (typeof current !== 'function') fail('PAIRED_TOGGLE_GUARD_REQUIRED');
          await current();
          await currentNspAdmission(c, nspContext(c, receipts, evidenceFiles), evidenceFiles, directory, deadline, invoke);
        } : current);
    },
    rollout: async deadline => ({ ...await observe(deadline),
      revisions: await transport(c, phases['synthetic-disable'], directory, boundedInvoke(deadline, invoke))('GET', `${r.app}/revisions`, '2025-07-01') }),
    privacy: (phase, deadline) => readPrivacy(c, phase, transport(c, phase, directory, boundedInvoke(deadline, invoke))),
    loadRun: () => load(directory, 'synthetic-window-journal.json', true),
    saveRun: value => save(directory, 'synthetic-window-journal.json', value),
    ...(receipts.queueRecords?.['queue-storage']?.kind === 'reviewed-queue-storage-adoption' ? {
      beforeRuntimeDispatch: deadline => currentNspAdmission(c, nspContext(c, receipts, evidenceFiles),
        evidenceFiles, directory, deadline, invoke),
    } : {}),
    http: (method, path, event, guard, deadline) => syntheticHttp(window.anchorApp.properties.configuration.ingress.fqdn, method, path, event, guard, deadline),
    query: (start, end, guard, deadline, onDispatch) => readSyntheticQuery(c, receipts['workspace-access'].resources[r.workspace],
      window.sourceSha256, start, end, guard, deadline, invoke, sourceDigest, Date.now, onDispatch),
    ...(phases['synthetic-admission'].queueVerification ? { queueDrain: async (guard, deadline) => {
      const topology = receipts.receiverUpgrade.candidate.topology;
      const arm = transport(c, phases['synthetic-disable'], directory, async (args, timeout) => {
        guard(); return boundedInvoke(deadline, invoke)(args, timeout);
      }, topology);
      const actual = await arm('GET', topology.ids.queue, '2025-01-01');
      guard();
      const storageRecord = receipts.queueRecords['queue-storage'];
      const descriptor = (storageRecord.kind === 'reviewed-queue-storage-adoption' ? storageRecord.origin.phase : storageRecord.phase)
        .resources.find(v => v.id === topology.ids.queue);
      verifyQueueResource(c, topology, descriptor, actual);
      const result = { version: 1, kind: 'owned-arm-approximate-queue-count', queueId: topology.ids.queue,
        approximateMessageCount: actual.properties.approximateMessageCount, observedAt: new Date().toISOString() };
      verifyQueueDrain(phases['synthetic-admission'].queueVerification, result);
      return result;
    } } : {}),
  };
}

export function receiverUpgradeIO(c, phase, receipts, origin, evidence, directory, invoke = az, options = {}) {
  const candidate = evidence.receiverCandidate, r = ids(c), now = options.now ?? Date.now;
  const reads = limitReadConcurrency((deadline, args, timeout) => boundedInvoke(deadline, invoke, now)(args, timeout));
  const invokeAt = deadline => {
    if (!Number.isSafeInteger(deadline)) fail('IMAGE_ABSOLUTE_DEADLINE_REQUIRED');
    const bounded = boundedInvoke(deadline, invoke, now);
    return async (args, timeout) => {
      const write = args[0] === 'rest' && args[args.indexOf('--method') + 1] === 'PUT';
      const result = await (write ? bounded(args, timeout) : reads(deadline, args, timeout));
      if (now() >= deadline) fail('IMAGE_OPERATION_DEADLINE');
      return result;
    };
  };
  const topology = evidence.queueTopology ?? candidate?.topology;
  const armAt = deadline => transport(c, phase, directory, invokeAt(deadline), topology);
  const observe = async until => {
    const arm = armAt(until);
    const [ingest, pull, app, revisions] = await Promise.all([
      arm('GET', r.ingestIdentity, '2023-01-31'), arm('GET', r.pullIdentity, '2023-01-31'),
      arm('GET', r.app, '2025-07-01'), arm('GET', `${r.app}/revisions`, '2025-07-01'),
    ]);
    const identities = { [r.ingestIdentity]: ingest, [r.pullIdentity]: pull };
    return { app, revisions,
      context: { ...resourceContext(c, receipts), identities, receiverCandidate: candidate } };
  };
  return {
    now, sourceDigest, sleep: options.sleep ?? pause,
    loadJournal: () => load(directory, `${phase.phase}-journal.json`, true),
    saveJournal: value => save(directory, `${phase.phase}-journal.json`, value),
    saveReceipt: value => saveImmutable(directory, `${phase.phase}-receipt.json`, value),
    check: () => checkReadOnly(c, phase, origin, receipts, directory, evidence, invoke, options.lookup ?? publishedSourceDigest, undefined, options),
    observe,
    deployment: until => armAt(until)('GET', phase.deploymentId, '2022-09-01'),
    arm: (method, id, api, body, filter, guard, roleGuard, current, deadline) =>
      armAt(deadline)(method, id, api, body, filter, guard, roleGuard,
        method === 'PUT' && phase.phase === 'disabled-queue-upgrade' &&
          receipts.queueRecords?.['queue-storage']?.kind === 'reviewed-queue-storage-adoption'
          ? async () => {
            if (typeof current !== 'function') fail('PAIRED_TOGGLE_GUARD_REQUIRED');
            await current();
            await currentNspAdmission(c, nspContext(c, receipts, evidence), evidence, directory, deadline, invoke, { now });
          } : current),
    security: async until => {
      const arm = armAt(until);
      const origins = evidence.reconciliation.origins, assignments = origins.records.find(v => v.phase.phase === 'assignments');
      if (!assignments) fail('IMAGE_ASSIGNMENT_HISTORY_REQUIRED');
      // History, providers and account are fully rechecked by the fresh preflight.
      // Recheck mutable governance/privacy, live grants, identities and the exact image at dispatch.
      await Promise.all([
        (async () => {
          const [policies, defender, project, state] = await Promise.all([
            arm('GET', `${r.sub}/providers/Microsoft.Authorization/policyAssignments`, '2023-04-01'),
            arm('GET', `${r.sub}/providers/Microsoft.Security/pricings`, '2024-01-01'),
            arm('GET', r.projectBudget, '2024-08-01'), arm('GET', r.stateBudget, '2024-08-01'),
          ]);
          if (digest(json({ policies, defender })) !== origin.policyBaselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
          assertBudget(project, c, c.budget.projectAmount, projectBudgetFilter(c));
          assertBudget(state, c, c.budget.stateAmount);
        })(),
        (async () => {
          const descriptors = [r.workspace, r.environment, r.dcr, r.budget].map(id => {
            const record = origins.records.findLast(v => v.phase.resources.some(d => d.id === id));
            if (!record) fail('IMAGE_RESOURCE_HISTORY_REQUIRED');
            return { record, descriptor: record.phase.resources.find(d => d.id === id) };
          });
          const current = await Promise.all(descriptors.map(({ descriptor: d }) => arm('GET', d.id, d.apiVersion)));
          const context = { ...resourceContext(c, receipts), workspace: current[0] };
          for (const [i, { record, descriptor }] of descriptors.entries()) {
            verifyResource(c, record.phase, descriptor, current[i], context);
            if (!isDeepStrictEqual(executionIdentity(current[i], descriptor.type),
              executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type))) fail('RESOURCE_IDENTITY_CHANGED');
          }
        })(),
        (async () => {
          const publication = await readPublishedImage(c, origins.imagePublication, arm, invokeAt(until), candidate);
          if (!isDeepStrictEqual(executionIdentity(publication.registry, 'Microsoft.ContainerRegistry/registries'),
            executionIdentity(receipts.core.resources[r.registry], 'Microsoft.ContainerRegistry/registries'))) fail('RESOURCE_IDENTITY_CHANGED');
        })(),
        (async () => {
          const definitions = await readAssignmentRoleDefinitions(c, assignments.phase, arm, receipts['upload-role']);
          if (digest(json(definitions.roles)) !== assignments.preflight.roleDefinitionsSha256) fail('ASSIGNMENT_ROLE_DEFINITION_DRIFT');
          const current = await Promise.all(assignments.phase.resources.map(d => arm('GET', d.id, d.apiVersion)));
          for (const [i, descriptor] of assignments.phase.resources.entries()) {
            verifyResource(c, assignments.phase, descriptor, current[i]);
            if (!isDeepStrictEqual(executionIdentity(current[i], descriptor.type),
              executionIdentity(assignments.firstReadback.resources[descriptor.id], descriptor.type))) fail('RESOURCE_IDENTITY_CHANGED');
          }
        })(),
        readPrivacy(c, { phase: phase.phase, resources: [r.workspace, r.environment, r.app].map(id => ({
          id, type: id === r.workspace ? 'Microsoft.OperationalInsights/workspaces'
            : id === r.environment ? 'Microsoft.App/managedEnvironments' : 'Microsoft.App/containerApps',
        })) }, arm),
        ...(topology ? [readQueueRecords(c, topology, receipts.queueRecords ?? {}, arm,
          nspReadIO(c, directory, invokeAt(until), { now }), until)] : []),
      ]);
      if (topology) {
        const inventory = await arm('GET', `${r.group}/resources`, '2021-04-01'), known = knownResourceIds(c, receipts);
        if (!Array.isArray(inventory?.value) || inventory.nextLink ||
            inventory.value.some(v => !known.some(id => sameId(id, v.id)))) fail('UNEXPECTED_TELEMETRY_RESOURCE');
      }
    },
    privacy: until => readPrivacy(c, phase, armAt(until)),
    reserve: async () => {
      try {
        await saveImmutable(resolve(here, '.operator-private'), `window-instance-${phase.windowInstance.id}.json`, {
          version: 1, kind: 'disabled-image-change', instanceId: phase.windowInstance.id, phaseSha256: digest(json(phase)),
          predecessorSha256: phase.windowInstance.predecessorSha256, reservedAt: new Date(now()).toISOString(),
        });
      } catch (error) { if (error.code === 'EEXIST') fail('IMAGE_INSTANCE_REPLAY_FORBIDDEN'); throw error; }
    },
  };
}

export function queueTopologyIO(c, phase, receipts, origin, evidence, directory, invoke = az, options = {}) {
  const topology = evidence.queueTopology, now = options.now ?? Date.now;
  verifyQueueTopology(c, topology);
  const identity = receipts.core.resources[ids(c).ingestIdentity];
  const networkContext = nspContext(c, receipts, evidence);
  const common = receiverUpgradeIO(c, phase, receipts, origin, evidence, directory, invoke, options);
  const armAt = deadline => transport(c, phase, directory, limitReadConcurrency(boundedInvoke(deadline, invoke, now)), topology);
  let proof;
  return {
    ...common,
    check: async () => {
      proof = await checkReadOnly(c, phase, origin, receipts, directory, evidence, invoke,
        options.lookup ?? publishedSourceDigest, undefined, options);
      return proof;
    },
    verifyCurrent: async deadline => {
      if (proof?.effectivePolicyVersion !== 1 || proof.effectivePolicySha256 !== digest(json(proof.effectivePolicy))) fail('EFFECTIVE_POLICY_BINDING_REQUIRED');
      verifyEffectivePolicyEvidence(phase, proof.effectivePolicy);
      if (!isDeepStrictEqual(phase, buildQueuePhase(c, phase.phase, topology, identity, networkContext))) fail('QUEUE_PHASE_CHANGED');
      verifyQueueReview(c, topology, evidence.queueReview, await sourceDigest(), now());
      await common.security(deadline);
      if (networkContext) {
        const current = await currentNspAdmission(c, networkContext, evidence, directory, deadline, invoke, { now });
        if (!isDeepStrictEqual(current.networkBinding, proof.networkBinding) ||
            !isDeepStrictEqual(current.networkLineageHead, proof.networkLineageHead) ||
            !isDeepStrictEqual(current.networkBillingReview, proof.networkBillingReview)) fail('NSP_DISPATCH_STATE_CHANGED');
      }
      await checkEffectivePolicies(c, phase, directory, limitReadConcurrency(boundedInvoke(deadline, invoke, now)),
        topology, proof.effectivePolicySha256, { now, deadline });
      const arm = armAt(deadline);
      const operations = await arm('GET', '/providers/Microsoft.Storage/operations', '2025-01-01');
      if (verifyQueueProviderOperations(operations) !== proof.providerOperationsSha256) fail('QUEUE_PROVIDER_PERMISSION_MISMATCH');
      const observation = await common.observe(deadline);
      if (!receipts.receiverUpgrade || admissionFlag(observation.app) !== 'false') fail('QUEUE_DISABLED_PREPARED_RECEIVER_REQUIRED');
      const prior = receipts.receiverUpgrade;
      verifyResource(c, prior.phase, prior.phase.resources[0], observation.app, observation.context);
      const anchor = prior.receipt.resources[ids(c).app];
      if (!isDeepStrictEqual(executionIdentity(observation.app, 'Microsoft.App/containerApps'), executionIdentity(anchor, 'Microsoft.App/containerApps'))) fail('QUEUE_APP_IDENTITY_CHANGED');
      // A failed terminal window may advance the revision without changing the disabled profile.
      if (evidence.windowPredecessor) await readWindowPredecessor(c, evidence.windowPredecessor, directory,
        boundedInvoke(deadline, invoke, now), undefined, observation);
      const values = await readBatch([{ id: phase.deploymentId, apiVersion: '2022-09-01' }, ...phase.resources],
        d => arm('GET', d.id, d.apiVersion));
      if (values.some(Boolean)) fail('QUEUE_NEW_RESOURCE_OR_DEPLOYMENT_EXISTS');
    },
    arm: (method, id, api, body, guard, current, deadline) =>
      armAt(deadline)(method, id, api, body, undefined, guard, undefined, current),
    observe: async deadline => {
      const arm = armAt(deadline), deployment = await arm('GET', phase.deploymentId, '2022-09-01');
      if (deployment?.properties?.provisioningState !== 'Succeeded') return { deployment };
      const resources = Object.fromEntries(await readBatch(phase.resources, async d => [d.id, await arm('GET', d.id, d.apiVersion)]));
      const queues = await arm('GET', `${topology.ids.service}/queues`, '2025-01-01');
      if (!Array.isArray(queues?.value) || queues.nextLink || queues.value.length !== 1 ||
          !sameId(queues.value[0].id, topology.ids.queue)) fail('UNEXPECTED_QUEUE_RESOURCE');
      return { deployment, resources, privacy: await readQueuePrivacy(topology, arm) };
    },
  };
}

export async function preparePrivateLinkLocal(c, operation, directory, io = {
  read: load, save: saveImmutable, source: sourceDigest, readHead: readNspHead, lookup: publishedSourceDigest,
}) {
  if (!['preview-private-link', 'check-private-link-plan'].includes(operation)) fail('FIXED_PHASE_COMMAND_REQUIRED');
  const source = await io.source(), context = await io.read(directory, 'private-link-context.json');
  verifyPrivateLinkContext(c, context);
  await io.readHead(context.network, context.pendingHead);
  await verifyPublishedNspEvidence(c, context.network, context.adoption.topology, context.adoption, io.lookup);
  if (await io.lookup(context.original.publication.commitSha) !== context.original.publication.sourceSha256) {
    fail('NSP_ORIGINAL_PUBLISHED_SOURCE_CHANGED');
  }
  const input = await io.read(directory, 'private-link-input.json');
  const plan = buildPrivateLinkPlan(c, context, input, source);
  const saved = operation === 'check-private-link-plan' ? await io.read(directory, 'private-link-plan.json') : plan;
  if (!isDeepStrictEqual(saved, plan)) fail('PRIVATE_LINK_PLAN_DRIFT');
  const result = verifyPrivateLinkPlan(c, context, saved, source);
  await io.readHead(context.network, context.pendingHead);
  if (await io.source() !== source) fail('PRIVATE_LINK_SOURCE_CHANGED');
  if (operation === 'preview-private-link') await io.save(directory, 'private-link-plan.json', plan);
  return result;
}

export const PRIVATE_LINK_CONTROL_COMMANDS = Object.freeze({
  'prepare-private-link': 'prepare', 'check-private-link': 'check', 'execute-private-link': 'execute',
  'reconcile-private-link': 'reconcile', 'recover-private-link': 'recover', 'retire-private-link': 'retire',
});
export const PRIVATE_LINK_RUNTIME_COMMANDS = Object.freeze({
  'prepare-private-link-image': 'prepare-image', 'publish-private-link-image': 'publish-image',
  'prepare-private-link-receiver': 'prepare-receiver', 'create-private-link-receiver': 'create-receiver',
  'prepare-private-link-window': 'prepare-window', 'qualify-private-link-window': 'qualify-window',
  'prepare-private-link-window-continuation': 'prepare-window-continuation',
  'qualify-private-link-window-continuation': 'qualify-window-continuation',
  'prepare-private-link-disable-recovery': 'prepare-disable-recovery',
  'recover-private-link-disable': 'recover-disable', 'reconcile-private-link-receiver': 'reconcile-receiver',
  'prepare-private-link-public-cleanup': 'prepare-public-cleanup',
  'recover-private-link-public-cleanup': 'recover-public-cleanup',
  'reconcile-private-link-public-probe': 'reconcile-public-probe',
});
export const PRIVATE_LINK_NSG_COMMANDS = Object.freeze({
  'observe-private-link-nsg-adoption': 'observe-nsg-adoption', 'adopt-private-link-nsg': 'adopt-nsg',
});

export async function dispatchPrivateLinkOperation(c, operation, stage, directoryArg, io = {
  directory: privateDirectory, read: loadPrivateLinkArtifact, immutable: savePrivateLinkArtifact,
  control: runPrivateLinkControl, runtime: runPrivateLinkRuntime, nsg: runPrivateLinkNsgAdoption,
}) {
  const control = Object.hasOwn(PRIVATE_LINK_CONTROL_COMMANDS, operation);
  const runtime = Object.hasOwn(PRIVATE_LINK_RUNTIME_COMMANDS, operation);
  const nsg = Object.hasOwn(PRIVATE_LINK_NSG_COMMANDS, operation);
  if (control ? !PRIVATE_LINK_CONTROL_STAGES.includes(stage) : nsg ? stage !== 'private-link-nsg-adoption'
    : !runtime || stage !== 'private-link-runtime') {
    fail('FIXED_PHASE_COMMAND_REQUIRED');
  }
  const directory = await io.directory(directoryArg);
  const context = await io.read(directory, 'private-link-control-context.json');
  const evidence = await io.read(directory, 'private-link-control-evidence.json');
  if (nsg) {
    const action = PRIVATE_LINK_NSG_COMMANDS[operation];
    const inputs = await io.read(directory, 'private-link-nsg-adoption-inputs.json');
    closed(inputs, ['original', 'originalDirectory', 'publication', 'policyRevision',
      'costReview', 'costEvidence', 'migrationReview', ...(action === 'observe-nsg-adoption' ? ['provenance'] : ['proposal', 'review'])]);
    return io.nsg(c, context, evidence, action, directoryArg, inputs);
  }
  if (control) {
    const action = PRIVATE_LINK_CONTROL_COMMANDS[operation];
    const keys = ['publication', 'costReview', 'costEvidence', 'migrationReview'];
    const inputs = await io.read(directory, 'private-link-control-inputs.json');
    const fields = action === 'prepare' ? [] : [...keys,
      ...(['execute', 'retire'].includes(action) ? ['proof', 'approval'] : []),
      ...(['reconcile', 'recover'].includes(action) ? ['original'] : []),
      ...(action === 'recover' ? ['proposal', 'recoveryReview'] : []),
      ...(stage.startsWith('retire-old-') || stage.includes('steady-budget') || stage === 'record-migration' ? ['runtimeCompletion'] : []),
    ];
    if (inputs && Object.hasOwn(inputs, 'policyRevision')) fields.push('policyRevision');
    if (['retire-old-receiver', 'retire-old-environment', 'set-project-steady-budget', 'set-telemetry-steady-budget', 'record-migration'].includes(stage) &&
        inputs && Object.hasOwn(inputs, 'nameProjection')) fields.push('nameProjection');
    if (['prepare', 'check', 'execute', 'retire'].includes(action) &&
        inputs && Object.hasOwn(inputs, 'continuation')) fields.push('continuation');
    if (evidence.version === 2 && ['reconcile', 'recover'].includes(action)) fields.push('originalDirectory');
    closed(inputs, fields);
    return io.control(c, context, evidence, stage, action, directoryArg, inputs);
  }
  const action = PRIVATE_LINK_RUNTIME_COMMANDS[operation];
  const inputs = await io.read(directory, 'private-link-runtime-inputs.json');
  const result = await io.runtime(c, context, evidence, action, directoryArg, inputs);
  if (action === 'publish-image') await io.immutable(directory, 'private-link-published-candidate.json', result);
  if (['qualify-window', 'qualify-window-continuation'].includes(action) && result?.outcome !== 'qualified-private-delivery-disabled') {
    fail('PRIVATE_LINK_WINDOW_STOPPED_INSPECT_RETAINED_RESULT');
  }
  return result;
}

async function main() {
  const [operation, phaseName, directoryArg, ...extra] = process.argv.slice(2);
  if (Object.hasOwn(PRIVATE_LINK_CONTROL_COMMANDS, operation) || Object.hasOwn(PRIVATE_LINK_RUNTIME_COMMANDS, operation) ||
      Object.hasOwn(PRIVATE_LINK_NSG_COMMANDS, operation)) {
    if (!directoryArg || extra.length ||
        (Object.hasOwn(PRIVATE_LINK_CONTROL_COMMANDS, operation) ? !PRIVATE_LINK_CONTROL_STAGES.includes(phaseName)
          : Object.hasOwn(PRIVATE_LINK_NSG_COMMANDS, operation) ? phaseName !== 'private-link-nsg-adoption'
            : phaseName !== 'private-link-runtime')) fail('FIXED_PHASE_COMMAND_REQUIRED');
    if (Object.entries(process.env).some(([key, value]) => value && /^(CI$|GITHUB_|ACTIONS_|RUNNER_)/u.test(key))) fail('UNTRUSTED_RUNNER_FORBIDDEN');
    const directory = await privateDirectory(directoryArg), c = validateConfig(await load(directory, 'config.json'));
    const result = await dispatchPrivateLinkOperation(c, operation, phaseName, directoryArg);
    console.log(json({ operation, stage: phaseName, resultKind: result?.kind ?? null,
      resultSha256: digestJson(result), outcome: result?.outcome ?? null }));
    return;
  }
  const privateLinkOperation = ['preview-private-link', 'check-private-link-plan'].includes(operation);
  if (privateLinkOperation !== (phaseName === 'private-link-migration')) fail('FIXED_PHASE_COMMAND_REQUIRED');
  if (!['prepare', 'check', 'validate-preview', 'prepare-window', 'run-window', 'execute-disable',
    'reconcile', 'qualify-reconciliation', 'image-before-push', 'image-readback', 'execute',
    'prepare-image', 'check-image', 'execute-image', 'preview-image-publication',
    'preview-queue', 'prepare-queue', 'check-queue', 'execute-queue',
    'observe-queue-adoption', 'adopt-queue-storage', 'preview-nsp', 'prepare-nsp', 'check-nsp', 'execute-nsp',
    'reconcile-nsp', 'prepare-nsp-reconciliation', 'qualify-nsp-reconciliation', 'check-image-publication',
    'preview-private-link', 'check-private-link-plan'].includes(operation) ||
      ![...PHASES, ...IMAGE_PHASES, ...QUEUE_PHASES, ...NSP_PHASES, 'private-link-migration'].includes(phaseName) ||
      !directoryArg || extra.length) fail('FIXED_PHASE_COMMAND_REQUIRED');
  const directory = await privateDirectory(directoryArg), c = validateConfig(await load(directory, 'config.json'));
  if (Object.entries(process.env).some(([key, value]) => value && /^(CI$|GITHUB_|ACTIONS_|RUNNER_)/u.test(key))) fail('UNTRUSTED_RUNNER_FORBIDDEN');
  if (privateLinkOperation) {
    await preparePrivateLinkLocal(c, operation, directory);
    console.log(operation === 'preview-private-link' ? 'PRIVATE_LINK_LOCAL_PLAN_NO_CLOUD_OR_RETIREMENT_AUTHORITY'
      : 'PRIVATE_LINK_LOCAL_CONTRACT_VALID_CLOUD_STATE_UNVERIFIED');
    return;
  }
  if (operation === 'image-readback' && phaseName === 'disabled-queue-upgrade') {
    await captureQueuedPublication(c, await load(directory, 'receiver-candidate.json'), directory);
    console.log('QUEUED_IMAGE_READBACK_CAPTURED_NO_RETRY_OR_ADMISSION_AUTHORITY'); return;
  }
  if (['observe-queue-adoption', 'adopt-queue-storage'].includes(operation)) {
    if (phaseName !== 'queue-storage') fail('FIXED_QUEUE_ADOPTION_COMMAND_REQUIRED');
    const origin = await load(directory, 'queue-storage-origin.json');
    if (operation === 'observe-queue-adoption') {
      const readIO = nspReadIO(c, directory);
      const proposal = await collectQueueAdoption(c, origin, { now: Date.now, sourceDigest,
        read: (request, deadline) => readIO.read(request, deadline) },
      await load(directory, 'queue-defender-evidence.json', true));
      await saveImmutable(directory, 'queue-adoption-proposal.json', proposal);
      console.log('QUEUE_EXISTENCE_OBSERVED_NO_OPERATIONAL_AUTHORITY'); return;
    }
    const proposal = await load(directory, 'queue-adoption-proposal.json'), review = await load(directory, 'queue-adoption-review.json');
    const publication = await load(directory, 'queue-adoption-publication.json');
    const record = adoptQueueStorage(c, proposal, origin, review, publication, Date.now());
    if (publication.sourceSha256 !== await sourceDigest()) fail('QUEUE_ADOPTION_SOURCE_CHANGED');
    await verifyQueueAdoptionSources(c, record, publishedSourceDigest);
    await saveImmutable(directory, 'queue-storage-adoption-record.json', record);
    console.log('QUEUE_STORAGE_ADOPTED_READONLY_NOT_NETWORK_QUALIFIED'); return;
  }
  if (operation === 'preview-nsp') {
    if (phaseName !== 'nsp-empty-boundary') fail('FIXED_NSP_PHASE_REQUIRED');
    const adoption = await load(directory, 'queue-storage-adoption-record.json');
    const topology = nspTopology(c, adoption.topology, adoption), evidence = emptyNspEvidence(topology);
    await saveImmutable(directory, 'nsp-network.json', evidence);
    await saveImmutable(directory, 'nsp-preview.json', { version: 1, kind: 'unapproved-nsp-preview',
      evidence, phase: buildNspPhase(c, phaseName, adoption.topology, adoption, evidence),
      sourceSha256: await sourceDigest(), qualified: false, executionAuthorized: false });
    console.log('UNAPPROVED_NSP_PREVIEW_NO_CLOUD_CALLS'); return;
  }
  if (operation === 'preview-queue') {
    if (phaseName !== 'queue-storage') fail('FIXED_QUEUE_PHASE_REQUIRED');
    const input = await load(directory, 'queue-namespace.json'); closed(input, ['namespace']);
    const topology = queueTopology(c, input.namespace);
    await saveImmutable(directory, 'queue-topology.json', topology);
    await saveImmutable(directory, 'queue-preview.json', { version: 1, kind: 'unapproved-durable-queue-preview',
      topology, sourceSha256: await sourceDigest(), qualified: false, exactReviewRequired: true,
      candidateManifestDigest: null, candidateBindingRequired: true, executionAuthorized: false,
      phases: ['queue-storage', 'queue-role'].map(name => buildQueuePhase(c, name, topology)) });
    console.log('UNAPPROVED_QUEUE_PREVIEW_NO_CLOUD_CALLS'); return;
  }
  const origin = await load(directory, 'origin.json'), rawReceipts = await load(directory, 'receipts.json');
  const evidenceFiles = { scannerAdoption: await load(directory, 'scanner-adoption.json'),
    foundationBudgets: await load(directory, 'foundation-budgets.json'),
    windowInstance: await load(directory, 'window-instance.json', true),
    windowPredecessor: await load(directory, 'window-predecessor.json', true),
    receiverCandidate: await load(directory, 'receiver-candidate.json', true),
    queueTopology: await load(directory, 'queue-topology.json', true),
    queueReview: await load(directory, 'queue-review.json', true),
    receiverUpgrade: await load(directory, 'receiver-upgrade.json', true),
    queueRecords: await load(directory, 'queue-records.json', true),
    nspNetwork: await load(directory, 'nsp-network.json', true),
    nspReview: await load(directory, 'nsp-review.json', true),
    nspBillingReview: await load(directory, 'nsp-billing-review.json', true),
    nspBillingEvidence: await load(directory, 'nsp-billing-evidence.json', true),
    reconciliation: { origins: await load(directory, 'execution-origins-v3.json', true),
      proposal: await load(directory, 'reconciliation-proposal.json', true),
      review: await load(directory, 'reconciliation-review.json', true) } };
  evidenceFiles.reconciliation.receiverCandidate = evidenceFiles.reconciliation.proposal
    ? reconciliationReceiverCandidate(evidenceFiles.reconciliation.proposal, evidenceFiles.receiverCandidate)
    : publishedReceiverCandidate(evidenceFiles.receiverCandidate);
  evidenceFiles.reconciliation.receiverUpgrade = evidenceFiles.receiverUpgrade;
  evidenceFiles.reconciliation.queueRecords = evidenceFiles.queueRecords ?? {};
  evidenceFiles.reconciliation.nspNetwork = evidenceFiles.nspNetwork;
  if (['prepare-nsp-reconciliation', 'qualify-nsp-reconciliation'].includes(operation)) {
    if (!NSP_PHASES.includes(phaseName)) fail('FIXED_NSP_COMMAND_REQUIRED');
    const prior = evidenceFiles.nspNetwork, topology = evidenceFiles.queueTopology, adoption = evidenceFiles.queueRecords?.['queue-storage'];
    verifyNspEvidence(c, prior, topology, adoption);
    const phase = buildNspPhase(c, phaseName, topology, adoption, prior, await load(directory, 'nsp-instance.json', true));
    const original = await originalNspAttempt(phase, prior, directory);
    const billing = { review: await load(directory, 'nsp-reconciliation-billing-review.json'),
      evidence: await load(directory, 'nsp-reconciliation-billing-evidence.json') };
    const io = nspReconciliationIO(c, original, topology, adoption, prior, billing, directory);
    verifyNspStoppedAttempt(c, original, topology, adoption, prior, await io.pendingHead());
    await verifyPublishedNspEvidence(c, prior, topology, adoption);
    if (await publishedSourceDigest(original.publication.commitSha) !== original.publication.sourceSha256) fail('NSP_ORIGINAL_PUBLISHED_SOURCE_CHANGED');
    if (operation === 'prepare-nsp-reconciliation') {
      const proposal = await collectNspReconciliation(c, original, topology, adoption, prior, io);
      await saveImmutable(directory, `${phaseName}-reconciliation-proposal.json`, proposal);
      console.log('NSP_CURRENT_STATE_PROPOSED_ORIGINAL_FAILURE_PRESERVED'); return;
    }
    const proposal = await load(directory, `${phaseName}-reconciliation-proposal.json`);
    const review = await load(directory, `${phaseName}-reconciliation-review.json`);
    const publication = await load(directory, 'nsp-reconciliation-publication.json');
    closed(publication, ['commitSha', 'sourceSha256']);
    if (publication.sourceSha256 !== await sourceDigest() || await publishedSourceDigest(publication.commitSha) !== publication.sourceSha256) fail('NSP_SOURCE_NOT_PUBLISHED');
    const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock'), lock = await open(lockPath, 'wx', 0o600);
    try {
      await qualifyNspReconciliation(c, original, topology, adoption, prior, proposal, review, publication, io);
      console.log('NSP_CURRENT_CONTROL_STATE_RECONCILED_NOT_ORIGINAL_EXECUTION_SUCCESS');
    } finally { await lock.close(); await rm(lockPath); }
    return;
  }
  if (operation === 'reconcile-nsp') {
    if (!NSP_PHASES.includes(phaseName)) fail('FIXED_NSP_COMMAND_REQUIRED');
    const adoption = evidenceFiles.queueRecords?.['queue-storage'], evidence = evidenceFiles.nspNetwork;
    verifyNspEvidence(c, evidence, evidenceFiles.queueTopology, adoption);
    const phase = buildNspPhase(c, phaseName, evidenceFiles.queueTopology, adoption, evidence, await load(directory, 'nsp-instance.json', true));
    const journal = await load(directory, `${phaseName}-journal.json`);
    if (journal.phaseSha256 !== digest(json(phase))) fail('NSP_RECONCILIATION_PHASE_CHANGED');
    const observation = await collectNspObservation(evidence.topology, nspReadIO(c, directory), Date.now() + NSP_LIMITS.stageMs, { c, adoption });
    await saveImmutable(directory, `${phaseName}-reconciliation.json`, { version: 1,
      kind: 'observed-nsp-reconciliation-not-execution-proof', phaseSha256: digest(json(phase)), journalSha256: digest(json(journal)),
      sourceSha256: await sourceDigest(), observation, qualified: false, originalHistoryModified: false, replayAuthorized: false });
    console.log('NSP_STATE_OBSERVED_HISTORY_PRESERVED_NO_REPLAY'); return;
  }
  if (!evidenceFiles.reconciliation.origins && await load(directory, 'execution-origins-v2.json', true)) fail('RECONCILIATION_REVISION_REQUIRED');
  verifyScannerAdoption(c, origin, evidenceFiles.scannerAdoption);
  verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
  if (operation === 'preview-image-publication') {
    if (!['disabled-image-upgrade', 'disabled-queue-upgrade'].includes(phaseName)) fail('FIXED_DISABLED_IMAGE_PHASE_REQUIRED');
    const candidate = evidenceFiles.receiverCandidate;
    if ((phaseName === 'disabled-queue-upgrade') !== (candidate?.version === 2)) fail('QUEUE_PROFILE_PHASE_REQUIRED');
    let inventory;
    if (candidate?.version === 2 && evidenceFiles.queueRecords?.['queue-storage']?.kind === 'reviewed-queue-storage-adoption') {
      qualifiedQueueRecords(c, evidenceFiles.queueRecords, candidate.topology);
      const context = nspContext(c, { queueRecords: evidenceFiles.queueRecords }, evidenceFiles);
      const proof = await load(directory, 'nsp-publication-preflight.json');
      if (proof.sourceSha256 !== await sourceDigest() || proof.candidateSha256 !== digest(json(candidate)) ||
          proof.inventorySha256 !== digest(json(proof.inventory)) ||
          !isDeepStrictEqual(proof.publicationPreview, prepareReceiverPublication(c, candidate, proof.inventory, Date.now()))) fail('NSP_PUBLICATION_PREFLIGHT_CHANGED');
      verifyNspQueuePreflight(c, context, proof, Date.now());
      await readNspHead(context.admission);
      inventory = proof.inventory;
    } else inventory = await load(directory, 'receiver-publication-inventory.json');
    await verifyReceiverSource(candidate);
    const preview = prepareReceiverPublication(c, candidate, inventory, Date.now());
    if (candidate.review.sourceSha256 !== await sourceDigest()) fail('IMAGE_SOURCE_CHANGED');
    await saveImmutable(directory, 'receiver-publication-preview.json', preview);
    console.log('RECEIVER_PUBLICATION_PREVIEW_NO_PUSH_AUTHORITY'); return;
  }
  if (['reconcile', 'qualify-reconciliation'].includes(operation)) {
    if (evidenceFiles.reconciliation.origins?.records.at(-1)?.phase.phase !== phaseName) fail('RECONCILIATION_ORIGINS_REQUIRED');
    if (operation === 'reconcile') {
      if (evidenceFiles.reconciliation.proposal || evidenceFiles.reconciliation.review) fail('PRESERVE_RECONCILIATION_HISTORY');
      const proposal = await collectReconciliation(c, origin, directory, evidenceFiles);
      await saveImmutable(directory, 'reconciliation-proposal.json', proposal);
      console.log('READONLY_RECONCILIATION_PROPOSED_NOT_QUALIFIED'); return;
    }
    const adopted = await reviewedReconciliationReceipts(c, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation, await sourceDigest());
    const fresh = await collectReconciliation(c, origin, directory, evidenceFiles);
    await saveImmutable(directory, 'reconciliation-receipts.json', adopted);
    await saveImmutable(directory, 'reconciliation-qualification.json', { checkedAt: new Date().toISOString(),
      sourceSha256: await sourceDigest(), receiptsSha256: digest(json(adopted)), freshReadback: fresh,
      executionAuthorized: false, originalHistoryRewritten: false });
    console.log('READONLY_RECONCILIATION_QUALIFIED_NO_EXECUTION_AUTHORITY'); return;
  }
  if (evidenceFiles.reconciliation.origins?.records.some(v => v.phase.phase === phaseName)) fail('COMPLETED_PHASE_REQUIRES_RECONCILIATION');
  let receipts = rawReceipts;
  if (evidenceFiles.reconciliation.origins) {
    const adopted = await reviewedReconciliationReceipts(c, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation, await sourceDigest());
    if (!isDeepStrictEqual(await load(directory, 'reconciliation-receipts.json', true), adopted)) fail('RECONCILIATION_RECEIPTS_REQUIRED');
    receipts = { ...adopted, ...rawReceipts };
    // The raw ledger retains original receipts; never let its historical source replace an adopted readback.
    for (const name of Object.keys(adopted)) receipts[name] = adopted[name];
  }
  const receiverUpgrade = evidenceFiles.receiverUpgrade;
  if (receiverUpgrade) {
    verifyDisabledImageRecord(c, receiverUpgrade);
    receipts = { ...receipts, receiverUpgrade };
  }
  const queueRecords = evidenceFiles.queueRecords;
  if (queueRecords) {
    knownResourceIds(c, { queueRecords });
    receipts = { ...receipts, queueRecords };
  }
  if (evidenceFiles.nspNetwork) {
    receipts = { ...receipts, nspNetwork: evidenceFiles.nspNetwork,
      nspBillingReview: evidenceFiles.nspBillingReview, nspBillingEvidence: evidenceFiles.nspBillingEvidence };
    knownResourceIds(c, receipts);
  }
  if (['check-image-publication', 'image-before-push'].includes(operation) && phaseName === 'disabled-queue-upgrade') {
    await checkQueuedPublication(c, receipts, evidenceFiles, directory);
    console.log('QUEUED_IMAGE_NETWORK_CHECK_PASSED_NO_PUSH_AUTHORITY');
    return;
  }
  if (operation === 'check-image-publication') fail('QUEUE_PROFILE_PHASE_REQUIRED');
  if (NSP_PHASES.includes(phaseName)) {
    if (!['prepare-nsp', 'check-nsp', 'execute-nsp', 'reconcile-nsp'].includes(operation)) fail('FIXED_NSP_COMMAND_REQUIRED');
    const adoption = receipts.queueRecords?.['queue-storage'], topology = evidenceFiles.queueTopology, evidence = evidenceFiles.nspNetwork;
    verifyNspEvidence(c, evidence, topology, adoption);
    const instance = await load(directory, 'nsp-instance.json', true);
    const phase = buildNspPhase(c, phaseName, topology, adoption, evidence, instance), source = await sourceDigest();
    if (operation === 'prepare-nsp') {
      if (await load(directory, `${phaseName}-journal.json`, true) || await load(directory, `${phaseName}-approval.json`, true)) fail('PRESERVE_PHASE_HISTORY');
      await saveImmutable(directory, `${phaseName}-plan.json`, { version: 1, phase, sourceSha256: source,
        qualified: false, executionAuthorized: false });
      console.log('UNAPPROVED_NSP_PHASE_NO_CLOUD_CALLS'); return;
    }
    const io = nspIO(c, phase, receipts, origin, evidenceFiles, directory);
    const plan = await load(directory, `${phaseName}-plan.json`);
    if (plan.sourceSha256 !== source || !isDeepStrictEqual(plan.phase, phase)) fail('NSP_PREPARED_PHASE_DRIFT');
    if (operation === 'check-nsp') {
      await io.check(); console.log('NSP_READONLY_CHECK_PASSED_NO_EXECUTION_AUTHORITY'); return;
    }
    const publication = await load(directory, 'nsp-policy-publication.json');
    closed(publication, ['commitSha', 'sourceSha256']);
    if (publication.sourceSha256 !== source || await publishedSourceDigest(publication.commitSha) !== source) fail('NSP_SOURCE_NOT_PUBLISHED');
    const approval = await load(directory, `${phaseName}-approval.json`);
    const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock'), lock = await open(lockPath, 'wx', 0o600);
    try {
      const receipt = await new NspController(c, phase, topology, adoption, evidence, io).execute(approval);
      const record = { version: 1, kind: 'reviewed-nsp-phase', phase, publication, approval,
        preflight: await load(directory, `${phaseName}-preflight.json`), preview: await load(directory, `${phaseName}-what-if.json`),
        validation: await load(directory, `${phaseName}-validation.json`), journal: await load(directory, `${phaseName}-journal.json`), receipt };
      const result = { ...evidence, records: [...evidence.records, record] };
      verifyNspEvidence(c, result, topology, adoption);
      await saveImmutable(directory, `${phaseName}-record.json`, record);
      await saveImmutable(directory, `${phaseName}-network.json`, result);
      await save(resolve(here, '.operator-private'), nspHeadName(evidence.topology), nspLineageHead(result));
      console.log('NSP_CONTROL_PLANE_QUALIFIED_NO_RUNTIME_OR_INGESTION_AUTHORITY');
    } finally { await lock.close(); await rm(lockPath); }
    return;
  }
  if (['prepare-nsp', 'check-nsp', 'execute-nsp', 'reconcile-nsp'].includes(operation)) fail('FIXED_NSP_COMMAND_REQUIRED');
  if (['prepare-queue', 'check-queue', 'execute-queue'].includes(operation)) {
    if (!QUEUE_PHASES.includes(phaseName)) fail('FIXED_QUEUE_PHASE_REQUIRED');
    const topology = verifyQueueTopology(c, evidenceFiles.queueTopology), source = await sourceDigest();
    const identity = receipts.core.resources[ids(c).ingestIdentity];
    const networkContext = nspContext(c, receipts, evidenceFiles);
    const phase = buildQueuePhase(c, phaseName, topology, identity, networkContext);
    const priorRecords = receipts.queueRecords ?? {};
    closed(priorRecords, phase.requiredReceipts);
    if (phase.requiredReceipts.length) qualifiedQueueRecords(c, priorRecords, topology, phase.requiredReceipts.at(-1));
    if (operation === 'prepare-queue') {
      if (await load(directory, `${phaseName}-journal.json`, true) || await load(directory, `${phaseName}-approval.json`, true)) fail('PRESERVE_PHASE_HISTORY');
      await saveImmutable(directory, `${phaseName}-plan.json`, { version: 1, phase, sourceSha256: source,
        cost: durableQueueCost(), qualified: false, executionAuthorized: false, exactReviewRequired: true });
      await saveImmutable(directory, `${phaseName}-template.json`, phase.template);
      console.log('UNAPPROVED_QUEUE_PHASE_NO_CLOUD_CALLS'); return;
    }
    verifyQueueReview(c, topology, evidenceFiles.queueReview, source, Date.now());
    const plan = await load(directory, `${phaseName}-plan.json`);
    if (plan.sourceSha256 !== source || !isDeepStrictEqual(plan.phase, phase)) fail('PREPARED_PHASE_DRIFT');
    if (operation === 'check-queue') {
      await checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles);
      console.log('QUEUE_READONLY_CHECK_PASSED_NO_EXECUTION_AUTHORITY'); return;
    }
    const publication = await load(directory, 'queue-policy-publication.json');
    closed(publication, ['commitSha', 'sourceSha256']);
    if (publication.sourceSha256 !== source || await publishedSourceDigest(publication.commitSha) !== source) fail('QUEUE_SOURCE_NOT_PUBLISHED');
    const approval = await load(directory, `${phaseName}-approval.json`);
    const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock'), lock = await open(lockPath, 'wx', 0o600);
    try {
      const controller = new QueueTopologyController(c, phase, topology, evidenceFiles.queueReview,
        queueTopologyIO(c, phase, receipts, origin, evidenceFiles, directory), networkContext);
      const receipt = await controller.execute(approval);
      const record = { version: networkContext ? 2 : 1, kind: networkContext ? 'reviewed-nsp-queue-phase' : 'reviewed-queue-phase',
        ...(networkContext ? { networkAdmission: networkContext.admission } : {}), topology, review: evidenceFiles.queueReview,
        publication, identity, priorRecords, phase, approval, preflight: await load(directory, `${phaseName}-preflight.json`),
        validation: await load(directory, `${phaseName}-validation.json`),
        providerOperations: await load(directory, 'queue-provider-operations.json'),
        whatIf: await load(directory, `${phaseName}-what-if.json`), journal: await load(directory, `${phaseName}-journal.json`), receipt };
      verifyQueueRecord(c, record);
      await saveImmutable(directory, `${phaseName}-record.json`, record);
      console.log('QUEUE_PHASE_QUALIFIED_RECEIVER_STILL_DISABLED');
    } finally { await lock.close(); await rm(lockPath); }
    return;
  }
  if (QUEUE_PHASES.includes(phaseName)) fail('FIXED_QUEUE_COMMAND_REQUIRED');
  if (['prepare-image', 'check-image', 'execute-image'].includes(operation)) {
    if (!IMAGE_PHASES.includes(phaseName)) fail('FIXED_DISABLED_IMAGE_PHASE_REQUIRED');
    const candidate = evidenceFiles.receiverCandidate, predecessor = evidenceFiles.windowPredecessor;
    verifyReceiverCandidate(c, candidate);
    await verifyReceiverSource(candidate);
    await verifyPublishedWindowPredecessor(c, predecessor);
    let instance = await load(directory, 'image-instance.json', true);
    if (!instance && operation === 'prepare-image') {
      instance = { version: 1, id: randomUUID(), predecessorSha256: digest(json(predecessor)), previousInstanceIds: predecessorInstanceIds(predecessor) };
      await saveImmutable(directory, 'image-instance.json', instance);
    }
    const phase = buildDisabledImagePhase(c, phaseName, receipts, candidate, predecessor, instance, evidenceFiles.reconciliation);
    const source = await sourceDigest();
    if (operation === 'prepare-image') {
      if (await load(directory, `${phaseName}-journal.json`, true) || await load(directory, `${phaseName}-approval.json`, true)) fail('PRESERVE_PHASE_HISTORY');
      await saveImmutable(directory, `${phaseName}-plan.json`, { phase, sourceSha256: source, candidateSha256: digest(json(candidate)),
        cost: receiverCost(candidate), qualified: false, executionAuthorized: false });
      await saveImmutable(directory, `${phaseName}-template.json`, phase.template);
      console.log('DISABLED_IMAGE_PREVIEW_NO_CLOUD_CALLS'); return;
    }
    const plan = await load(directory, `${phaseName}-plan.json`);
    if (plan.sourceSha256 !== source || !isDeepStrictEqual(plan.phase, phase) || plan.candidateSha256 !== digest(json(candidate))) fail('PREPARED_PHASE_DRIFT');
    if (operation === 'check-image') {
      await checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles);
      console.log('DISABLED_IMAGE_READONLY_CHECK_PASSED'); return;
    }
    const publication = await load(directory, 'image-policy-publication.json');
    closed(publication, ['commitSha', 'sourceSha256']);
    if (publication.sourceSha256 !== source || await publishedSourceDigest(publication.commitSha) !== source) fail('IMAGE_SOURCE_NOT_PUBLISHED');
    const approval = await load(directory, `${phaseName}-approval.json`);
    const anchor = predecessor.kind === 'reviewed-disabled-image-change' ? predecessor.receipt.resources[ids(c).app] : predecessor.readback.app;
    const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock');
    const lock = await open(lockPath, 'wx', 0o600);
    try {
      const controller = new ReceiverUpgradeController(c, phase, candidate, anchor,
        receiverUpgradeIO(c, phase, receipts, origin, evidenceFiles, directory));
      const receipt = await controller.execute(approval);
      const record = { version: 1, kind: 'reviewed-disabled-image-change', publication, candidate, predecessor,
        prerequisiteReceipts: receipts, phase, approval, preflight: await load(directory, `${phaseName}-preflight.json`),
        whatIf: await load(directory, `${phaseName}-what-if.json`), journal: await load(directory, `${phaseName}-journal.json`), receipt };
      verifyDisabledImageRecord(c, record);
      await saveImmutable(directory, 'disabled-image-record.json', record);
      console.log('DISABLED_IMAGE_READY_NO_INGESTION_AUTHORITY');
    } finally { await lock.close(); await rm(lockPath); }
    return;
  }
  if (IMAGE_PHASES.includes(phaseName)) fail('FIXED_DISABLED_IMAGE_COMMAND_REQUIRED');
  if (['image-before-push', 'image-readback'].includes(operation)) {
    if (phaseName !== 'disabled-app') fail('IMAGE_GATE_PHASE_REQUIRED');
    await registryReview(c, receipts, directory, operation === 'image-before-push', az, rawReceipts);
    console.log('PRIVATE_IMAGE_REVIEW_RECORDED_NO_PUSH_AUTHORITY'); return;
  }
  if (['prepare-window', 'run-window', 'execute-disable'].includes(operation)) {
    if ((operation === 'execute-disable' ? phaseName !== 'synthetic-disable' : phaseName !== 'synthetic-admission')) fail('FIXED_WINDOW_COMMAND_REQUIRED');
    if (operation === 'prepare-window') {
      if (!evidenceFiles.windowPredecessor) fail('TERMINAL_WINDOW_PREDECESSOR_REQUIRED');
      await verifyPublishedWindowPredecessor(c, evidenceFiles.windowPredecessor);
      if (!evidenceFiles.windowInstance) {
        evidenceFiles.windowInstance = { version: 1, id: randomUUID(), predecessorSha256: digest(json(evidenceFiles.windowPredecessor)),
          previousInstanceIds: predecessorInstanceIds(evidenceFiles.windowPredecessor) };
        await saveImmutable(directory, 'window-instance.json', evidenceFiles.windowInstance);
      }
      verifyWindowInstancePredecessor(c, evidenceFiles.windowInstance, evidenceFiles.windowPredecessor);
      if (TOGGLE_PHASES.some(name => Object.hasOwn(rawReceipts, name))) fail('NEW_WINDOW_LEDGER_REQUIRED_PRIOR_HISTORY_PRESERVED');
      for (const name of TOGGLE_PHASES) if (await load(directory, `${name}-journal.json`, true) || await load(directory, `${name}-approval.json`, true)) fail('PRESERVE_WINDOW_HISTORY');
      if (await load(directory, 'synthetic-window-plan.json', true)) fail('PRESERVE_WINDOW_HISTORY');
      const phases = Object.fromEntries(TOGGLE_PHASES.map(name => [name, buildPhase(c, name, null, receipts, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation, evidenceFiles.windowInstance)]));
      const source = await sourceDigest(), whatifs = {};
      for (const name of TOGGLE_PHASES) {
        const phase = phases[name];
        await checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles);
        whatifs[name] = await load(directory, `${name}-what-if.json`);
        await save(directory, `${name}-plan.json`, { ...phase, sourceSha256: source, config: c });
      }
      if (source !== await sourceDigest()) fail('WINDOW_SOURCE_CHANGED');
      const window = buildSyntheticWindow(c, phases, receipts, origin, source, whatifs);
      await saveImmutable(directory, 'synthetic-window-prerequisite-receipts.json', receipts);
      await saveImmutable(directory, 'synthetic-window-plan.json', window);
      console.log('PAIRED_WINDOW_PREPARED_READONLY_NO_AUTHORITY'); return;
    }
    const window = await load(directory, 'synthetic-window-plan.json');
    if (window.version !== 2 || !evidenceFiles.windowPredecessor || !isDeepStrictEqual(window.windowInstance, evidenceFiles.windowInstance)) fail('NEW_WINDOW_INSTANCE_REQUIRED');
    verifyWindowInstancePredecessor(c, window.windowInstance, evidenceFiles.windowPredecessor);
    const base = await load(directory, 'synthetic-window-prerequisite-receipts.json');
    const current = Object.fromEntries(Object.entries(receipts).filter(([name]) => !TOGGLE_PHASES.includes(name)));
    if (!isDeepStrictEqual(base, current) || digest(json(base)) !== window.receiptsSha256 ||
        digest(json(origin)) !== window.originSha256) fail('WINDOW_PREREQUISITE_DRIFT');
    const phases = Object.fromEntries(TOGGLE_PHASES.map(name => [name, buildPhase(c, name, null, base, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation, evidenceFiles.windowInstance)]));
    const approvals = Object.fromEntries(await Promise.all(TOGGLE_PHASES.map(async name => [name, await load(directory, `${name}-approval.json`)])));
    const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock');
    const lock = await open(lockPath, 'wx', 0o600);
    let interrupted = false, toggle;
    const interrupt = () => { interrupted = true; };
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, interrupt);
    try {
      const io = syntheticWindowIO(c, phases, window, approvals, base, rawReceipts, origin, evidenceFiles, directory, () => interrupted);
      toggle = new SyntheticToggleController(c, phases, window, approvals, io);
      if (operation === 'execute-disable') {
        const receipt = await toggle.execute('synthetic-disable');
        console.log(receipt.lateRecovery ? 'SYNTHETIC_LATE_RECOVERY_DISABLED_NO_CLIENT_ACTIVATION' : 'SYNTHETIC_DISABLED_READY_NO_CLIENT_ACTIVATION');
      } else {
        verifySyntheticWindow(c, phases, window, approvals, await sourceDigest(), Date.now(), true);
        await reserveWindowInstance(c, resolve(here, '.operator-private'), window);
        const result = await new SyntheticWindowDriver(c, phases, window, approvals, toggle, io).run();
        console.log(result.outcome === 'qualified-and-disabled' ? 'SYNTHETIC_WINDOW_QUALIFIED_AND_DISABLED' :
          result.outcome === 'stopped-disabled' ? 'SYNTHETIC_WINDOW_STOPPED_DISABLED' :
          result.outcome === 'stopped-disabled-late-recovery' ? 'SYNTHETIC_WINDOW_LATE_RECOVERY_DISABLED' : 'SYNTHETIC_WINDOW_HELD_TERMINAL_PROOF_REQUIRED');
        if (result.outcome !== 'qualified-and-disabled') process.exitCode = 1;
      }
    } finally {
      toggle?.deadlines.dispose();
      if (toggle) await toggle.deadlines.pendingIncident;
      for (const signal of ['SIGINT', 'SIGTERM']) process.off(signal, interrupt);
      await lock.close(); await rm(lockPath);
    }
    return;
  }
  if (operation === 'execute' && TOGGLE_PHASES.includes(phaseName)) fail('PAIRED_SYNTHETIC_WINDOW_REQUIRED');
  if (TOGGLE_PHASES.includes(phaseName)) {
    if (!evidenceFiles.windowInstance || !evidenceFiles.windowPredecessor) fail('TERMINAL_WINDOW_PREDECESSOR_REQUIRED');
    verifyWindowInstancePredecessor(c, evidenceFiles.windowInstance, evidenceFiles.windowPredecessor);
  }
  const phase = buildPhase(c, phaseName, await storageContract(), receipts, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation,
    TOGGLE_PHASES.includes(phaseName) ? evidenceFiles.windowInstance : undefined);
  if (operation === 'prepare') {
    if (await load(directory, `${phaseName}-journal.json`, true) || await load(directory, `${phaseName}-approval.json`, true)) fail('PRESERVE_PHASE_HISTORY');
    await save(directory, `${phaseName}-plan.json`, { ...phase, sourceSha256: await sourceDigest(), config: c,
      contracts: sourceContractsSummary(await storageContract()), firstReleaseCost: firstReleaseCost(1) });
    await save(directory, `${phaseName}-template.json`, phase.template);
    console.log('PRIVATE_PHASE_PREPARED_NO_CLOUD_CALLS'); return;
  }
  const prepared = await load(directory, `${phaseName}-plan.json`);
  if (prepared.sourceSha256 !== await sourceDigest() || prepared.configSha256 !== digest(json(c)) ||
      !isDeepStrictEqual(prepared.template, phase.template) ||
      !isDeepStrictEqual(prepared.reconciliation ?? null, phase.reconciliation ?? null)) fail('PREPARED_PHASE_DRIFT');
  if (operation === 'check') {
    await checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles); console.log('READONLY_PHASE_CHECK_PASSED'); return;
  }
  if (operation === 'validate-preview') {
    const preview = await validateReadOnly(c, phase, receipts, directory);
    await save(directory, `${phaseName}-preview-only.json`, { ...preview, qualified: false,
      note: 'Template/what-if evidence only. Does not waive account, foundation, cost or approval gates.' });
    console.log('READONLY_TEMPLATE_PREVIEW_PASSED_NOT_DEPLOYMENT_QUALIFIED'); return;
  }
  // Preserve the shared historical lock; never reset the old operator ledger.
  const lockPath = resolve(here, '../../opentofu/telemetry/.operator-private/controller.lock');
  const lock = await open(lockPath, 'wx', 0o600);
  try {
    const arm = transport(c, phase, directory);
    const controller = new CollectorController(c, phase, {
      now: Date.now, sourceDigest, sleep: pause, arm,
      publicationReceipt: receipts.publication,
      assignmentRoleDefinitions: () => readAssignmentRoleDefinitions(c, phase, arm, receipts['upload-role']),
      loadJournal: () => load(directory, `${phaseName}-journal.json`, true),
      saveJournal: value => save(directory, `${phaseName}-journal.json`, value),
      check: () => checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles),
      saveReceipt: async value => { receipts[phaseName] = value; rawReceipts[phaseName] = value;
        await save(directory, `${phaseName}-receipt.json`, value); await save(directory, 'receipts.json', rawReceipts); },
      privacyChecks: () => readPrivacy(c, phase, arm),
    });
    await controller.execute(await load(directory, `${phaseName}-approval.json`));
    console.log('PHASE_READBACK_QUALIFIED_NO_CLIENT_ACTIVATION');
  } finally { await lock.close(); await rm(lockPath); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => {
  console.error(/^[A-Z_]+$/u.test(e.message) ? e.message : 'COLLECTOR_CONTROLLER_FAILED'); process.exitCode = 1;
});
