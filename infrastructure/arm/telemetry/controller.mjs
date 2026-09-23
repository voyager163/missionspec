import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { readFile, open, mkdir, rename, rm } from 'node:fs/promises';
import { basename, dirname, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, types } from 'node:util';
import { PHASES, buildPhase, deploymentName, validateConfig, ids, digest, json, fail, sameId, storageContract, firstReleaseCost, assertOwned, RECEIVER_COMMAND,
  closed, budgetConfiguration, projectBudgetFilter, verifyFoundationBudgets, reconciliationBinding, assignmentRoleTargets } from './definition.mjs';
import { assertBudget, verifyWhatIf, verifyResource, verifyApproval, verifyFreshReview, sourceContractsSummary, permitFirstPush,
  executionIdentity, verifyExecutionOrigins, verifyReconciliation, verifyDeploymentIdentity, roleDefinitionSignature, verifyPublicationReadback } from './policy.mjs';

const execute = promisify(execFile), here = dirname(fileURLToPath(import.meta.url));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export const MAX_PRIVATE_ARTIFACT_BYTES = 64 * 1024 * 1024;
export const DIAGNOSTIC_API = '2021-05-01-preview';
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
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs'];
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
  try {
    const { stdout } = await run('az', args, { timeout, maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, AZURE_CORE_COLLECT_TELEMETRY: 'false', AZURE_EXTENSION_USE_DYNAMIC_INSTALL: 'no' } });
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
    const safe = new Error('ARM_OPERATION_FAILED'); safe.armCode = code; safe.httpStatus = status; throw safe;
  }
}
export function transport(c, phase, directory, invoke = az) {
  const r = ids(c);
  const forbiddenOperations = new Set(['listkeys', 'listsecrets', 'listaccountsas', 'listservicesas', 'regeneratekey', 'register']);
  const diagnosticTargets = [r.workspace, r.environment, r.app].map(id => id + '/providers/Microsoft.Insights/diagnosticSettings');
  return async (method, id, version, body, filter, beforeDispatch, beforeAssignmentWrite) => {
    const diagnosticRead = diagnosticTargets.includes(id) && method === 'GET' && version === DIAGNOSTIC_API && body === undefined && filter === undefined;
    if (!['GET', 'POST', 'PUT'].includes(method) || (id !== r.sub && !id.startsWith(`${r.sub}/`)) ||
        /[?#\\]|\.\.|%/u.test(id) || (!/^\d{4}-\d{2}-\d{2}$/u.test(version) && !diagnosticRead) ||
        (id.toLowerCase().includes('/providers/microsoft.insights/diagnosticsettings') && !diagnosticRead) ||
        id.split('/').some(component => forbiddenOperations.has(component.toLowerCase()))) fail('ARM_SCOPE_FORBIDDEN');
    if (method === 'PUT' && id !== phase.deploymentId) fail('FIXED_PHASE_PUT_ONLY');
    if (method === 'PUT' && (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch))) fail('DISPATCH_GUARD_REQUIRED');
    if (method === 'PUT' && phase.phase === 'assignments' && typeof beforeAssignmentWrite !== 'function') fail('ASSIGNMENT_ROLE_READBACK_REQUIRED');
    if (beforeAssignmentWrite !== undefined && (method !== 'PUT' || phase.phase !== 'assignments')) fail('ASSIGNMENT_ROLE_READBACK_ONLY');
    if (method === 'POST' && id !== `${r.sub}/providers/Microsoft.ContainerRegistry/checkNameAvailability`) fail('NONMUTATING_POST_ONLY');
    const inventoryMetadata = method === 'GET' && id === `${r.group}/resources` && version === '2021-04-01' &&
      body === undefined && filter === '$expand=createdTime,changedTime';
    if (filter && !filter.startsWith('$filter=') && !inventoryMetadata) fail('QUERY_NOT_SUPPORTED');
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
      // No await between the guard and transport invocation, including body-file preparation.
      if (method === 'PUT' && beforeDispatch() !== undefined) fail('DISPATCH_GUARD_REQUIRED');
      const result = await invoke(args);
      if (result?.nextLink) fail('PAGINATION_REQUIRES_REVIEW');
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
  for (const item of origin.resources) {
    const actual = await arm('GET', item.id, item.apiVersion);
    const expected = sameId(item.id, scanner.id) ? scanner.snapshot : item.snapshot;
    if (!sameId(actual?.id, item.id) || !isDeepStrictEqual(stableReadback(actual), stableReadback(expected))) fail('FOUNDATION_DRIFT');
  }
  for (const item of origin.absent) if (await arm('GET', item.id, item.apiVersion)) fail('RETIRED_OPERATOR_RESOURCE_PRESENT');
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
    for (const name of ['definition.mjs', 'policy.mjs', 'controller.mjs']) hash.update(name).update(await file(`infrastructure/arm/telemetry/${name}`));
    const schema = JSON.parse(await file('assets/schemas/telemetry-event.schema.json'));
    const columns = JSON.parse(await file('services/telemetry-ingest/schema/storage-columns.json'));
    hash.update(json({ schema, columns, schemaSha256: digest(json(schema)), columnsSha256: digest(json(columns)) }));
    return hash.digest('hex');
  } catch { fail('PUBLISHED_ORIGIN_UNAVAILABLE'); }
}
async function verifyPublishedOrigins(c, foundation, origins, lookup = publishedSourceDigest, contract) {
  verifyExecutionOrigins(c, foundation, origins, contract ?? await storageContract());
  for (const record of origins.records) {
    if (await lookup(record.publication.commitSha) !== record.publication.sourceSha256) fail('PUBLISHED_SOURCE_MISMATCH');
  }
}
export async function readPrivacy(c, phase, arm) {
  const diagnostics = {};
  for (const descriptor of phase.resources.filter(v =>
    ['Microsoft.OperationalInsights/workspaces', 'Microsoft.App/managedEnvironments', 'Microsoft.App/containerApps'].includes(v.type))) {
    const value = await arm('GET', descriptor.id + '/providers/Microsoft.Insights/diagnosticSettings', DIAGNOSTIC_API);
    if (!Array.isArray(value?.value) || value.nextLink || value.value.length) fail('DIAGNOSTIC_ROUTE_DRIFT');
    diagnostics[descriptor.id] = value;
  }
  let exports = null;
  if (['core', 'workspace-access', 'data', 'assignments', 'disabled-app', 'synthetic-admission'].includes(phase.phase)) {
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
  const phase = record.phase, deployment = await arm('GET', phase.deploymentId, '2022-09-01'), resources = {}, identityPins = {};
  verifyDeploymentIdentity(record.firstReadback.deployment, deployment);
  for (const descriptor of phase.resources) {
    const actual = await arm('GET', descriptor.id, descriptor.apiVersion);
    verifyResource(c, phase, descriptor, actual, context);
    const pin = executionIdentity(actual, descriptor.type);
    if (!isDeepStrictEqual(pin, executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type))) fail('RESOURCE_IDENTITY_CHANGED');
    resources[descriptor.id] = actual; identityPins[descriptor.id] = pin;
  }
  return { executionOriginSha256: digest(json(record)), deployment, resources, identityPins, ...await readPrivacy(c, phase, arm) };
}
export async function readPublishedImage(c, imagePublication, arm, invoke = az) {
  const registry = await arm('GET', ids(c).registry, '2023-07-01');
  const repositories = await invoke(['acr', 'repository', 'list', '--name', c.registryName,
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (!isDeepStrictEqual(repositories, ['missionspec/telemetry-ingest'])) fail('PUBLICATION_READBACK_CHANGED');
  const manifests = await invoke(['acr', 'manifest', 'list-metadata', '--registry', c.registryName, '--name', 'missionspec/telemetry-ingest',
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  const manifest = await invoke(['acr', 'manifest', 'show', '--registry', c.registryName, '--name', `missionspec/telemetry-ingest@${c.receiverDigest}`,
    '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  const result = { registry, repositories, manifests, manifest };
  verifyPublicationReadback(c, imagePublication, result);
  return result;
}
async function reconciliationContext(c, origins, arm, invoke) {
  const r = ids(c), hasApp = origins.records.some(v => v.phase.phase === 'disabled-app');
  const workspace = origins.records.some(v => v.phase.phase === 'data') ? await arm('GET', r.workspace, '2023-09-01') : null;
  let identities = null, imagePublication = null, roleDefinitions = null;
  if (hasApp) {
    identities = { [r.ingestIdentity]: await arm('GET', r.ingestIdentity, '2023-01-31'),
      [r.pullIdentity]: await arm('GET', r.pullIdentity, '2023-01-31') };
    imagePublication = await readPublishedImage(c, origins.imagePublication, arm, invoke);
  }
  const assignments = origins.records.find(v => v.phase.phase === 'assignments');
  if (assignments) {
    const upload = origins.records.find(v => v.phase.phase === 'upload-role');
    const reads = await readAssignmentRoleDefinitions(c, assignments.phase, arm, upload.originalReceipt);
    roleDefinitions = { checkedAt: new Date().toISOString(), ...reads, roleDefinitionsSha256: digest(json(reads.roles)) };
    if (roleDefinitions.roleDefinitionsSha256 !== assignments.preflight.roleDefinitionsSha256) fail('ASSIGNMENT_ROLE_DEFINITION_DRIFT');
  }
  return { workspace, identities, imagePublication, roleDefinitions };
}
export async function collectReconciliation(c, origin, directory, evidence, invoke = az, lookup = publishedSourceDigest) {
  const foundation = verifyFoundationBudgets(c, evidence.foundationBudgets), origins = evidence.reconciliation.origins;
  const contract = await storageContract();
  await verifyPublishedOrigins(c, foundation, origins, lookup, contract);
  const r = ids(c), arm = transport(c, origins.records[0].phase, directory, invoke);
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account?.tenantId !== c.tenantId || account?.state !== 'Enabled' || account?.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  await verifyOrigin(origin, arm, c, evidence.scannerAdoption);
  const policies = await arm('GET', `${r.sub}/providers/Microsoft.Authorization/policyAssignments`, '2023-04-01');
  const defender = await arm('GET', `${r.sub}/providers/Microsoft.Security/pricings`, '2024-01-01');
  const baselineSha256 = digest(json({ policies, defender }));
  if (baselineSha256 !== origin.policyBaselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
  const provider = await arm('GET', `${r.sub}/providers/Microsoft.Insights`, '2021-04-01');
  if (provider?.registrationState !== 'Registered' || !provider.resourceTypes?.some(v =>
    v.resourceType?.toLowerCase() === 'diagnosticsettings' && v.apiVersions?.includes(DIAGNOSTIC_API))) fail('DIAGNOSTIC_API_NOT_REGISTERED');
  const results = {};
  const context = await reconciliationContext(c, origins, arm, invoke);
  for (const record of origins.records) results[record.phase.phase] = await readReconciledPhase(c, record, arm,
    { ...context, publication: origins.imagePublication?.receipt });
  const stateBudget = await arm('GET', r.stateBudget, '2024-08-01');
  const inventory = await arm('GET', `${r.group}/resources`, '2021-04-01', undefined, '$expand=createdTime,changedTime');
  const managedGroup = await arm('GET', r.managedGroup, '2024-03-01');
  const proposal = { version: 3, kind: 'read-only-completed-phases', sourceSha256: await sourceDigest(),
    configSha256: digest(json(c)), executionOriginsSha256: digest(json(origins)), baselineSha256,
    checkedAt: new Date().toISOString(), results, stateBudget, ...context, inventory, managedGroup };
  verifyReconciliation(c, foundation, origins, proposal, proposal.sourceSha256, null, contract);
  return proposal;
}
export async function reviewedReconciliationReceipts(c, foundation, evidence, sourceSha256, lookup = publishedSourceDigest) {
  if (!evidence?.origins || !evidence.proposal || !evidence.review) fail('RECONCILIATION_REVIEW_REQUIRED');
  const contract = await storageContract();
  await verifyPublishedOrigins(c, foundation, evidence.origins, lookup, contract);
  verifyReconciliation(c, foundation, evidence.origins, evidence.proposal, sourceSha256, evidence.review, contract);
  return Object.fromEntries(evidence.origins.records.map(record => {
    const phase = record.phase.phase, result = evidence.proposal.results[phase];
    return [phase, { qualificationKind: 'reviewed-read-only-reconciliation', qualified: true, phase,
      configSha256: digest(json(c)), phaseSha256: digest(json(record.phase)), sourceSha256: record.publication.sourceSha256,
      deployment: result.deployment, resources: result.resources,
      reconciliation: { contractVersion: 3, ...reconciliationBinding(evidence), policySourceSha256: sourceSha256,
        executionOriginSha256: digest(json(record)), checkedAt: evidence.proposal.checkedAt, reviewedAt: evidence.review.reviewedAt,
        originalJournalOutcome: record.journal.outcome, originalReceiptQualified: record.originalReceipt?.qualified === true } }];
  }));
}
export async function verifyFreshReconciliation(c, directory, evidence, invoke = az) {
  const arm = transport(c, evidence.origins.records[0].phase, directory, invoke);
  const context = await reconciliationContext(c, evidence.origins, arm, invoke);
  for (const record of evidence.origins.records) {
    const current = await readReconciledPhase(c, record, arm, { ...context, publication: evidence.origins.imagePublication?.receipt });
    if (!isDeepStrictEqual(current.identityPins, evidence.proposal.results[record.phase.phase].identityPins)) fail('RESOURCE_IDENTITY_CHANGED');
  }
  assertBudget(await arm('GET', ids(c).stateBudget, '2024-08-01'), c, 50);
  if (await arm('GET', ids(c).managedGroup, '2024-03-01')) fail('RECONCILIATION_INVENTORY_CHANGED');
  const inventory = await arm('GET', `${ids(c).group}/resources`, '2021-04-01', undefined, '$expand=createdTime,changedTime');
  if (!Array.isArray(inventory?.value) || evidence.proposal.inventory.value.some(previous => {
    const current = inventory.value.filter(v => sameId(v.id, previous.id));
    return current.length !== 1 || current[0].createdTime !== previous.createdTime;
  })) fail('RESOURCE_CREATION_IDENTITY_CHANGED');
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
export async function validateReadOnly(c, phase, receipts, directory, invoke = az) {
  const r = ids(c), known = Object.values(receipts).flatMap(v => Object.keys(v.resources ?? {}));
  const executionName = deploymentName(c, phase.phase);
  if (phase.deploymentId !== `${phase.scope}/providers/Microsoft.Resources/deployments/${executionName}`) fail('DEPLOYMENT_NAME_INVALID');
  const name = `${phase.phase}-template.json`; await save(directory, name, phase.template);
  const level = phase.scope === r.sub ? 'sub' : 'group';
  const args = ['--subscription', c.subscriptionId, ...(level === 'sub' ? ['--location', c.location] : ['--resource-group', `${c.namePrefix}-telemetry`]),
    '--name', executionName, '--template-file', resolve(directory, name), '--only-show-errors', '--output', 'json'];
  const validation = await invoke(['deployment', level, 'validate', ...args], 180000);
  await save(directory, `${phase.phase}-validation.json`, validation);
  if (validation?.properties?.provisioningState !== 'Succeeded' || validation.error) fail('TEMPLATE_NOT_VALIDATED');
  const whatif = await invoke(['deployment', level, 'what-if', ...args, '--no-pretty-print', '--result-format', 'FullResourcePayloads'], 180000);
  await save(directory, `${phase.phase}-what-if.json`, whatif);
  return { whatIfSha256: verifyWhatIf(phase, whatif, known), templateValidationOnly: true };
}
export async function checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles, invoke = az, lookup = publishedSourceDigest) {
  const started = Date.now(), arm = transport(c, phase, directory, invoke), r = ids(c);
  const foundation = verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
  if (evidenceFiles.reconciliation?.origins?.records.some(v => v.phase.phase === phase.phase)) fail('COMPLETED_PHASE_REQUIRES_RECONCILIATION');
  const source = await sourceDigest();
  let reconciled = {};
  if (evidenceFiles.reconciliation?.origins) {
    reconciled = await reviewedReconciliationReceipts(c, foundation, evidenceFiles.reconciliation, source, lookup);
    if (!isDeepStrictEqual(phase.reconciliation, reconciliationBinding(evidenceFiles.reconciliation)) ||
        Object.entries(reconciled).some(([name, value]) => !isDeepStrictEqual(receipts[name], value))) fail('RECONCILIATION_RECEIPTS_REQUIRED');
  }
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account?.tenantId !== c.tenantId || account?.state !== 'Enabled' || account?.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  await verifyOrigin(origin, arm, c, evidenceFiles.scannerAdoption);
  if (evidenceFiles.reconciliation?.origins) await verifyFreshReconciliation(c, directory, evidenceFiles.reconciliation, invoke);
  if (phase.phase !== 'project-budget') {
    verifyProjectBudgetReceipt(c, receipts['project-budget'], foundation, source, reconciled);
  }
  const evidence = {};
  for (const [name, id, api] of [
    ['providers', `${r.sub}/providers`, '2021-04-01'],
    ['permissions', `${r.sub}/providers/Microsoft.Authorization/permissions`, '2022-04-01'],
    ['denies', `${r.sub}/providers/Microsoft.Authorization/denyAssignments`, '2022-04-01'],
    ['policies', `${r.sub}/providers/Microsoft.Authorization/policyAssignments`, '2023-04-01'],
    ['defender', `${r.sub}/providers/Microsoft.Security/pricings`, '2024-01-01'],
    ['quota', `${r.sub}/providers/Microsoft.App/locations/${c.location}/usages`, '2025-01-01'],
    ['telemetry-inventory', `${r.group}/resources`, '2021-04-01'],
  ]) {
    evidence[name] = await arm('GET', id, api); await save(directory, `${phase.phase}-${name}.json`, evidence[name]);
  }
  if (!evidence.permissions?.value?.some(v => v.actions?.includes('*') && !v.notActions?.length) || evidence.denies?.value?.length) fail('PERMISSION_REVIEW_REQUIRED');
  for (const ns of ['Microsoft.App', 'Microsoft.ContainerRegistry', 'Microsoft.ManagedIdentity', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.Consumption', 'Microsoft.Authorization']) {
    if (!evidence.providers.value.some(v => v.namespace?.toLowerCase() === ns.toLowerCase() && v.registrationState === 'Registered')) fail('PROVIDER_NOT_REGISTERED');
  }
  for (const [ns, type] of [['Microsoft.App', 'managedEnvironments'], ['Microsoft.App', 'containerApps'],
    ['Microsoft.ContainerRegistry', 'registries'], ['Microsoft.OperationalInsights', 'workspaces'], ['Microsoft.Insights', 'dataCollectionRules']]) {
    const provider = evidence.providers.value.find(v => v.namespace.toLowerCase() === ns.toLowerCase());
    if (!provider.resourceTypes.some(v => v.resourceType === type && v.locations?.includes('Australia East'))) fail('REGION_NOT_SUPPORTED');
  }
  const baseline = digest(json({ policies: evidence.policies, defender: evidence.defender }));
  if (baseline !== origin.policyBaselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
  const known = Object.values(receipts).flatMap(v => Object.keys(v.resources ?? {}));
  if (evidence['telemetry-inventory'].value.some(v => !known.some(id => sameId(id, v.id)))) fail('UNEXPECTED_TELEMETRY_RESOURCE');
  if (phase.phase === 'core') {
    const q = evidence.quota.value.find(v => v.name?.value === 'ManagedEnvironmentCount');
    if (!q || q.limit - q.currentValue < 1) fail('ENVIRONMENT_QUOTA_UNAVAILABLE');
    if (await arm('GET', r.managedGroup, '2024-03-01')) fail('MANAGED_GROUP_NAME_EXISTS');
    const name = await arm('POST', `${r.sub}/providers/Microsoft.ContainerRegistry/checkNameAvailability`, '2023-07-01',
      { name: c.registryName, type: 'Microsoft.ContainerRegistry/registries' });
    if (name?.nameAvailable !== true) fail('REGISTRY_NAME_UNAVAILABLE');
  }
  for (const descriptor of phase.resources) {
    const actual = await arm('GET', descriptor.id, descriptor.apiVersion);
    if (Object.keys(phase.allowedModify).some(id => sameId(id, descriptor.id))) {
      if (!actual) fail('OWNED_UPDATE_TARGET_MISSING');
      const historical = phase.phase === 'project-budget' ? foundation.project
        : Object.values(receipts).map(v => v.resources?.[descriptor.id]).filter(Boolean).at(-1);
      const normalize = phase.phase === 'project-budget' ? budgetConfiguration : stableReadback;
      if (!historical || !sameId(actual.id, descriptor.id) || !isDeepStrictEqual(normalize(actual), normalize(historical))) fail('OWNED_TARGET_DRIFT');
    } else if (actual) fail('NEW_RESOURCE_NAME_EXISTS');
  }
  assertBudget(await arm('GET', r.projectBudget, '2024-08-01'), c,
    phase.phase === 'project-budget' ? c.budget.previousProjectAmount : c.budget.projectAmount, projectBudgetFilter(c));
  assertBudget(await arm('GET', r.stateBudget, '2024-08-01'), c, c.budget.stateAmount);
  let roleDefinitionsSha256;
  if (phase.phase === 'assignments') {
    const definitions = await readAssignmentRoleDefinitions(c, phase, arm, receipts['upload-role']);
    roleDefinitionsSha256 = digest(json(definitions.roles));
    await save(directory, 'assignments-role-definitions.json', { checkedAt: new Date().toISOString(), ...definitions, roleDefinitionsSha256 });
  }
  const { whatIfSha256 } = await validateReadOnly(c, phase, receipts, directory, invoke);
  const cost = firstReleaseCost(1);
  const proof = { startedAt: started, completedAt: Date.now(), qualified: cost.withinEstimate, configSha256: digest(json(c)),
    phaseSha256: digest(json(phase)), sourceSha256: await sourceDigest(), originSha256: digest(json(origin)),
    receiptsSha256: digest(json(receipts)),
    baselineSha256: roleDefinitionsSha256 ? digest(json({ foundationBaselineSha256: baseline, roleDefinitionsSha256 })) : baseline, whatIfSha256,
    ...(roleDefinitionsSha256 ? { foundationBaselineSha256: baseline, roleDefinitionsSha256 } : {}),
    cost, computedValuesReviewed: phase.computedReadbacksRequired.length === 0 };
  await save(directory, `${phase.phase}-preflight.json`, proof);
  if (!cost.withinEstimate) fail('FIRST_RELEASE_COST_EXCEEDS_ESTIMATE');
  return proof;
}

export class CollectorController {
  constructor(c, phase, io) { this.config = c; this.phase = phase; this.io = io; }
  async execute(approval) {
    const p = this.phase;
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

async function main() {
  const [operation, phaseName, directoryArg, ...extra] = process.argv.slice(2);
  if (!['prepare', 'check', 'validate-preview', 'reconcile', 'qualify-reconciliation', 'image-before-push', 'image-readback', 'execute'].includes(operation) ||
      !PHASES.includes(phaseName) || !directoryArg || extra.length) fail('FIXED_PHASE_COMMAND_REQUIRED');
  const directory = await privateDirectory(directoryArg), c = validateConfig(await load(directory, 'config.json'));
  if (Object.entries(process.env).some(([key, value]) => value && /^(CI$|GITHUB_|ACTIONS_|RUNNER_)/u.test(key))) fail('UNTRUSTED_RUNNER_FORBIDDEN');
  const origin = await load(directory, 'origin.json'), rawReceipts = await load(directory, 'receipts.json');
  const evidenceFiles = { scannerAdoption: await load(directory, 'scanner-adoption.json'),
    foundationBudgets: await load(directory, 'foundation-budgets.json'),
    reconciliation: { origins: await load(directory, 'execution-origins-v3.json', true),
      proposal: await load(directory, 'reconciliation-proposal.json', true),
      review: await load(directory, 'reconciliation-review.json', true) } };
  if (!evidenceFiles.reconciliation.origins && await load(directory, 'execution-origins-v2.json', true)) fail('RECONCILIATION_REVISION_REQUIRED');
  verifyScannerAdoption(c, origin, evidenceFiles.scannerAdoption);
  verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
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
  if (['image-before-push', 'image-readback'].includes(operation)) {
    if (phaseName !== 'disabled-app') fail('IMAGE_GATE_PHASE_REQUIRED');
    await registryReview(c, receipts, directory, operation === 'image-before-push', az, rawReceipts);
    console.log('PRIVATE_IMAGE_REVIEW_RECORDED_NO_PUSH_AUTHORITY'); return;
  }
  const phase = buildPhase(c, phaseName, await storageContract(), receipts, evidenceFiles.foundationBudgets, evidenceFiles.reconciliation);
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
