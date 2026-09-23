import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, open, mkdir, lstat, rename, rm } from 'node:fs/promises';
import { basename, dirname, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, types } from 'node:util';
import { PHASES, buildPhase, deploymentName, validateConfig, ids, digest, json, fail, sameId, storageContract, firstReleaseCost, assertOwned, RECEIVER_COMMAND,
  closed, budgetConfiguration, projectBudgetFilter, verifyFoundationBudgets } from './definition.mjs';
import { assertBudget, verifyWhatIf, verifyResource, verifyApproval, verifyFreshReview, sourceContractsSummary, permitFirstPush } from './policy.mjs';

const execute = promisify(execFile), here = dirname(fileURLToPath(import.meta.url));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function privateDirectory(relative) {
  const path = resolve(relative), root = resolve(here, '.operator-private');
  if (isAbsolute(relative) || (path !== root &&
      (dirname(path) !== root || !/^revision-\d{8}-[a-z0-9-]{1,32}$/u.test(basename(path))))) fail('PRIVATE_CANONICAL_DIRECTORY_REQUIRED');
  for (const directory of new Set([root, path])) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077)) fail('PRIVATE_DIRECTORY_REQUIRED');
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
  try {
    const path = resolve(directory, name), info = await lstat(path);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077)) fail('PRIVATE_FILE_REQUIRED');
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (e) { if (optional && e.code === 'ENOENT') return null; throw e; }
}
export async function sourceDigest() {
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs'];
  const hash = createHash('sha256');
  for (const name of names) hash.update(name).update(await readFile(resolve(here, name)));
  const contract = await storageContract(); hash.update(json(contract));
  return hash.digest('hex');
}
export async function registryReview(c, receipts, directory, beforePush, invoke = az) {
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
  await save(directory, 'publication-receipt.json', receipt); await save(directory, 'receipts.json', receipts);
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
    const safe = new Error('ARM_OPERATION_FAILED'); safe.armCode = code; safe.httpStatus = status; throw safe;
  }
}
export function transport(c, phase, directory, invoke = az) {
  const r = ids(c);
  return async (method, id, version, body, filter, beforeDispatch) => {
    if (!['GET', 'POST', 'PUT'].includes(method) || (id !== r.sub && !id.startsWith(`${r.sub}/`)) ||
        /[?#\\]|\.\.|%/u.test(id) || !/^\d{4}-\d{2}-\d{2}$/u.test(version) ||
        /listKeys|listSecrets|listAccountSas|listServiceSas|regenerateKey|\/register$/iu.test(id)) fail('ARM_SCOPE_FORBIDDEN');
    if (method === 'PUT' && id !== phase.deploymentId) fail('FIXED_PHASE_PUT_ONLY');
    if (method === 'PUT' && (typeof beforeDispatch !== 'function' || types.isAsyncFunction(beforeDispatch))) fail('DISPATCH_GUARD_REQUIRED');
    if (method === 'POST' && id !== `${r.sub}/providers/Microsoft.ContainerRegistry/checkNameAvailability`) fail('NONMUTATING_POST_ONLY');
    if (filter && !filter.startsWith('$filter=')) fail('QUERY_NOT_SUPPORTED');
    const args = ['rest', '--method', method, '--url', `https://management.azure.com${id}?api-version=${version}${filter ? '&' + filter : ''}`,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'];
    let name;
    if (body !== undefined) {
      name = `request-${randomUUID()}.json`; await save(directory, name, body);
      args.push('--body', '@' + resolve(directory, name), '--headers', 'Content-Type=application/json');
    }
    try {
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
export function verifyProjectBudgetReceipt(c, receipt, foundation, sourceSha256) {
  const phase = buildPhase(c, 'project-budget', null, {}, foundation), r = ids(c);
  if (receipt?.qualified !== true || receipt.phase !== 'project-budget' ||
      receipt.phaseSha256 !== digest(json(phase)) || receipt.configSha256 !== digest(json(c)) ||
      receipt.sourceSha256 !== sourceSha256 || !sameId(receipt.deployment?.id, phase.deploymentId) ||
      receipt.deployment.properties?.provisioningState !== 'Succeeded' ||
      !isDeepStrictEqual(Object.keys(receipt.resources ?? {}), [r.projectBudget])) fail('PROJECT_BUDGET_RECEIPT_REQUIRED');
  verifyResource(c, phase, phase.resources[0], receipt.resources[r.projectBudget]);
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
export async function checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles, invoke = az) {
  const started = Date.now(), arm = transport(c, phase, directory, invoke), r = ids(c);
  const foundation = verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
  const account = await invoke(['account', 'show', '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json']);
  if (account?.id !== c.subscriptionId || account?.tenantId !== c.tenantId || account?.state !== 'Enabled' || account?.environmentName !== 'AzureCloud') fail('EXPLICIT_ACCOUNT_MISMATCH');
  await verifyOrigin(origin, arm, c, evidenceFiles.scannerAdoption);
  if (phase.phase !== 'project-budget') verifyProjectBudgetReceipt(c, receipts['project-budget'], foundation, await sourceDigest());
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
  const { whatIfSha256 } = await validateReadOnly(c, phase, receipts, directory, invoke);
  const cost = firstReleaseCost(1);
  const proof = { startedAt: started, completedAt: Date.now(), qualified: cost.withinEstimate, configSha256: digest(json(c)),
    phaseSha256: digest(json(phase)), sourceSha256: await sourceDigest(), originSha256: digest(json(origin)),
    receiptsSha256: digest(json(receipts)), baselineSha256: baseline, whatIfSha256,
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
    if (await this.io.arm('GET', p.deploymentId, '2022-09-01')) fail('DEPLOYMENT_NAME_EXISTS');
    beforeDispatch();
    const journal = { phase: p.phase, phaseSha256: approval.phaseSha256, intentAt: new Date(this.io.now()).toISOString(), outcome: 'submission-possible' };
    await this.io.saveJournal(journal);
    try {
      beforeDispatch();
      await this.io.arm('PUT', p.deploymentId, '2022-09-01',
        { ...(p.scope === ids(this.config).sub ? { location: this.config.location } : {}),
          properties: { mode: 'Incremental', template: p.template } }, undefined, beforeDispatch);
      while (this.io.now() < Date.parse(approval.expiresAt)) {
        const d = await this.io.arm('GET', p.deploymentId, '2022-09-01');
        const state = d?.properties?.provisioningState;
        if (state === 'Succeeded') {
          const resources = {};
          for (const descriptor of p.resources) resources[descriptor.id] =
            verifyResource(this.config, p, descriptor, await this.io.arm('GET', descriptor.id, descriptor.apiVersion));
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
  if (!['prepare', 'check', 'validate-preview', 'image-before-push', 'image-readback', 'execute'].includes(operation) ||
      !PHASES.includes(phaseName) || !directoryArg || extra.length) fail('FIXED_PHASE_COMMAND_REQUIRED');
  const directory = await privateDirectory(directoryArg), c = validateConfig(await load(directory, 'config.json'));
  if (Object.entries(process.env).some(([key, value]) => value && /^(CI$|GITHUB_|ACTIONS_|RUNNER_)/u.test(key))) fail('UNTRUSTED_RUNNER_FORBIDDEN');
  const origin = await load(directory, 'origin.json'), receipts = await load(directory, 'receipts.json');
  const evidenceFiles = { scannerAdoption: await load(directory, 'scanner-adoption.json'),
    foundationBudgets: await load(directory, 'foundation-budgets.json') };
  verifyScannerAdoption(c, origin, evidenceFiles.scannerAdoption);
  verifyFoundationBudgets(c, evidenceFiles.foundationBudgets);
  if (['image-before-push', 'image-readback'].includes(operation)) {
    if (phaseName !== 'disabled-app') fail('IMAGE_GATE_PHASE_REQUIRED');
    await registryReview(c, receipts, directory, operation === 'image-before-push');
    console.log('PRIVATE_IMAGE_REVIEW_RECORDED_NO_PUSH_AUTHORITY'); return;
  }
  const phase = buildPhase(c, phaseName, await storageContract(), receipts, evidenceFiles.foundationBudgets);
  if (operation === 'prepare') {
    if (await load(directory, `${phaseName}-journal.json`, true) || await load(directory, `${phaseName}-approval.json`, true)) fail('PRESERVE_PHASE_HISTORY');
    await save(directory, `${phaseName}-plan.json`, { ...phase, sourceSha256: await sourceDigest(), config: c,
      contracts: sourceContractsSummary(await storageContract()), firstReleaseCost: firstReleaseCost(1) });
    await save(directory, `${phaseName}-template.json`, phase.template);
    console.log('PRIVATE_PHASE_PREPARED_NO_CLOUD_CALLS'); return;
  }
  const prepared = await load(directory, `${phaseName}-plan.json`);
  if (prepared.sourceSha256 !== await sourceDigest() || prepared.configSha256 !== digest(json(c)) ||
      !isDeepStrictEqual(prepared.template, phase.template)) fail('PREPARED_PHASE_DRIFT');
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
      loadJournal: () => load(directory, `${phaseName}-journal.json`, true),
      saveJournal: value => save(directory, `${phaseName}-journal.json`, value),
      check: () => checkReadOnly(c, phase, origin, receipts, directory, evidenceFiles),
      saveReceipt: async value => { receipts[phaseName] = value; await save(directory, `${phaseName}-receipt.json`, value); await save(directory, 'receipts.json', receipts); },
      privacyChecks: async resources => {
        for (const id of phase.resources.filter(value =>
          ['Microsoft.OperationalInsights/workspaces', 'Microsoft.App/managedEnvironments', 'Microsoft.App/containerApps'].includes(value.type)).map(value => value.id)) {
          const diag = await arm('GET', id + '/providers/Microsoft.Insights/diagnosticSettings', '2021-05-01');
          if (!Array.isArray(diag?.value) || diag.value.length) fail('DIAGNOSTIC_ROUTE_DRIFT');
        }
        if (['workspace-access', 'data', 'assignments', 'disabled-app', 'synthetic-admission'].includes(phaseName)) {
          const exports = await arm('GET', ids(c).workspace + '/dataExports', '2020-08-01');
          if (!Array.isArray(exports?.value) || exports.value.length) fail('WORKSPACE_EXPORT_DRIFT');
        }
      },
    });
    await controller.execute(await load(directory, `${phaseName}-approval.json`));
    console.log('PHASE_READBACK_QUALIFIED_NO_CLIENT_ACTIVATION');
  } finally { await lock.close(); await rm(lockPath); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => {
  console.error(/^[A-Z_]+$/u.test(e.message) ? e.message : 'COLLECTOR_CONTROLLER_FAILED'); process.exitCode = 1;
});
