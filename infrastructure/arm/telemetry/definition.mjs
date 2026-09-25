import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { IMAGE_PHASES, receiverAnchor, runtimeReceiver } from './receiver-upgrade.mjs';
import { queueEnvironment } from './durable-queue.mjs';

const PHASE_CODES = Object.freeze({ 'project-budget': 'pb', core: 'co', 'workspace-access': 'wa', data: 'da', 'upload-role': 'ur',
  assignments: 'ra', 'disabled-app': 'di', 'synthetic-admission': 'sy', 'synthetic-disable': 'sd',
  'disabled-image-upgrade': 'iu', 'disabled-image-rollback': 'ir', 'disabled-queue-upgrade': 'qu',
  'queue-storage': 'qs', 'queue-role': 'qr', 'queue-assignment': 'qa' });
export const PHASES = Object.freeze(['project-budget', 'core', 'workspace-access', 'data', 'upload-role', 'assignments',
  'disabled-app', 'synthetic-admission', 'synthetic-disable']);
export const TOGGLE_PHASES = Object.freeze(['synthetic-admission', 'synthetic-disable']);
export const SYNTHETIC_LIMITS = Object.freeze({ enabledWindowMs: 600000, rollbackReserveMs: 180000,
  rolloutTimeoutMs: 120000, rolloutPollMs: 3000, maxRolloutPolls: 40, httpTimeoutMs: 1000,
  maximumHttpRequests: 11, maximumHealthGets: 8, maximumEnabledPosts: 2, maximumDisabledPosts: 1,
  maximumQueries: 3 });
export const SYNTHETIC_FIXTURES = Object.freeze([
  Object.freeze({ schemaVersion: 1, event: 'operation-completed', operation: 'draft', cliVersion: '0.0.0',
    outcome: 'completed', host: 'none', os: 'linux', durationBucket: 'under-1s' }),
  Object.freeze({ schemaVersion: 1, event: 'operation-completed', operation: 'verify', cliVersion: '0.0.0',
    outcome: 'completed', host: 'none', os: 'linux', durationBucket: '1s-to-10s' }),
]);
export const BUDGET = Object.freeze({ currency: 'USD', previousProjectAmount: 250, projectAmount: 350, stateAmount: 50, telemetryAmount: 300 });
export const RECEIVER_DIGEST = 'sha256:91c72962bdb2586e179e46659ab2140a5e88e0bb6905d0aa6a89225047ac9f8a';
export const RECEIVER_COMMAND = ['/usr/local/bin/node', '--no-turbofan', '--no-maglev', '--disable-sigusr1', 'dist/main.js'];
export const LIMITS = Object.freeze({ body_timeout_ms: 150, storage_timeout_ms: 650, headers_timeout_ms: 150,
  max_connections: 128, max_concurrent_requests: 32, max_concurrent_ingestions: 8, requests_per_minute: 3000, events_per_day: 100000 });
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u;
export const digest = value => createHash('sha256').update(value).digest('hex');
export const json = value => `${JSON.stringify(value, null, 2)}\n`;
export const fail = code => { throw new Error(code); };
export const sameId = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
export function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !isDeepStrictEqual(Object.keys(value).sort(), [...fields].sort())) fail('CLOSED_INPUT_REQUIRED');
}
export function validateConfig(c) {
  closed(c, ['version', 'subscriptionId', 'tenantId', 'operatorPrincipalId', 'namePrefix', 'registryName', 'location',
    'runId', 'budgetEmail', 'budgetStart', 'budgetEnd', 'queryPrincipalIds', 'receiverDigest', 'budget',
    'originSha256', 'scannerAdoptionSha256', 'foundationBudgetsSha256']);
  closed(c.budget, Object.keys(BUDGET));
  if (c.version !== 2 || !isDeepStrictEqual(c.budget, BUDGET) ||
      !['originSha256', 'scannerAdoptionSha256', 'foundationBudgetsSha256'].every(k => /^[0-9a-f]{64}$/u.test(c[k])) ||
      ![c.subscriptionId, c.tenantId, c.operatorPrincipalId, c.runId].every(v => uuid.test(v)) ||
      !/^missionspec-[a-z0-9]{2,10}$/u.test(c.namePrefix) || c.registryName !== c.namePrefix.replace('-', '') ||
      c.location !== 'australiaeast' || c.receiverDigest !== RECEIVER_DIGEST ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(c.budgetEmail) ||
      !/^\d{4}-\d{2}-01T00:00:00Z$/u.test(c.budgetStart) || !/^\d{4}-\d{2}-01T00:00:00Z$/u.test(c.budgetEnd) ||
      Date.parse(c.budgetEnd) <= Date.parse(c.budgetStart) ||
      !Array.isArray(c.queryPrincipalIds) || c.queryPrincipalIds.length < 1 || c.queryPrincipalIds.length > 4 ||
      c.queryPrincipalIds.some(v => !uuid.test(v) || v !== c.operatorPrincipalId) ||
      new Set(c.queryPrincipalIds).size !== c.queryPrincipalIds.length) fail('COLLECTOR_SCOPE_INVALID');
  return c;
}
export function validateWindowInstance(c, instance) {
  closed(instance, ['version', 'id', 'predecessorSha256', 'previousInstanceIds']);
  const v4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  if (instance.version !== 1 || typeof instance.id !== 'string' || !v4.test(instance.id) || instance.id === c.runId ||
      typeof instance.predecessorSha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(instance.predecessorSha256) || !Array.isArray(instance.previousInstanceIds) ||
      instance.previousInstanceIds.length > 64 || instance.previousInstanceIds.some(v => typeof v !== 'string' || !v4.test(v) || v === instance.id || v === c.runId) ||
      new Set(instance.previousInstanceIds).size !== instance.previousInstanceIds.length) fail('WINDOW_INSTANCE_INVALID_OR_REUSED');
  return instance;
}
export function deploymentName(c, phase, instance) {
  validateConfig(c);
  if (!Object.hasOwn(PHASE_CODES, phase)) fail('PHASE_NOT_SUPPORTED');
  if (instance !== undefined) {
    if (![...TOGGLE_PHASES, ...IMAGE_PHASES].includes(phase)) fail('WINDOW_INSTANCE_TOGGLE_ONLY');
    validateWindowInstance(c, instance);
  }
  if (IMAGE_PHASES.includes(phase) && !instance) fail('IMAGE_INSTANCE_REQUIRED');
  const identity = instance ? (IMAGE_PHASES.includes(phase) ? 'u' : 'w') + instance.id.replaceAll('-', '') : c.runId.replaceAll('-', '');
  const name = `${c.namePrefix}-${identity}-${PHASE_CODES[phase]}`;
  if (!/^[a-z0-9-]{1,64}$/u.test(name)) fail('DEPLOYMENT_NAME_INVALID');
  return name;
}
export function stableGuid(value) {
  const b = createHash('sha256').update(value).digest().subarray(0, 16);
  b[6] = (b[6] & 15) | 80; b[8] = (b[8] & 63) | 128;
  const h = b.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
export function ids(c) {
  validateConfig(c);
  const sub = `/subscriptions/${c.subscriptionId}`, group = `${sub}/resourceGroups/${c.namePrefix}-telemetry`;
  return { sub, group, stateGroup: `${sub}/resourceGroups/${c.namePrefix}-state`, managedGroup: `${sub}/resourceGroups/${c.namePrefix}-managed`,
    registry: `${group}/providers/Microsoft.ContainerRegistry/registries/${c.registryName}`,
    ingestIdentity: `${group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${c.namePrefix}-ingest`,
    pullIdentity: `${group}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${c.namePrefix}-pull`,
    workspace: `${group}/providers/Microsoft.OperationalInsights/workspaces/${c.namePrefix}-analytics`,
    table: `${group}/providers/Microsoft.OperationalInsights/workspaces/${c.namePrefix}-analytics/tables/MissionSpecTelemetry_CL`,
    dcr: `${group}/providers/Microsoft.Insights/dataCollectionRules/${c.namePrefix}-dcr`,
    environment: `${group}/providers/Microsoft.App/managedEnvironments/${c.namePrefix}-environment`,
    app: `${group}/providers/Microsoft.App/containerApps/${c.namePrefix}-ingest`,
    budget: `${group}/providers/Microsoft.Consumption/budgets/${c.namePrefix}-budget`,
    projectBudget: `${sub}/providers/Microsoft.Consumption/budgets/${c.namePrefix}-project-budget`,
    stateBudget: `${sub}/resourceGroups/${c.namePrefix}-state/providers/Microsoft.Consumption/budgets/${c.namePrefix}-state-budget`,
    uploadRole: `${sub}/providers/Microsoft.Authorization/roleDefinitions/${stableGuid(`${group}/dcr-upload-only`)}` };
}
export async function storageContract() {
  const root = new URL('../../../', import.meta.url);
  const schema = JSON.parse(await readFile(new URL('assets/schemas/telemetry-event.schema.json', root)));
  const columns = JSON.parse(await readFile(new URL('services/telemetry-ingest/schema/storage-columns.json', root)));
  if (schema.additionalProperties !== false || columns.length !== 9 ||
      !isDeepStrictEqual(columns.map(v => v.name).sort(), ['TimeGenerated', ...Object.keys(schema.properties)].sort()) ||
      !isDeepStrictEqual(columns[0], { name: 'TimeGenerated', type: 'datetime' })) fail('CANONICAL_SCHEMA_DRIFT');
  return { schema, columns, schemaSha256: digest(json(schema)), columnsSha256: digest(json(columns)) };
}
export function ownerTags(c) { return { product: 'MissionSpec', purpose: 'aggregate-telemetry', collectorRun: c.runId }; }
function resource(type, apiVersion, name, properties, extra = {}) { return { type, apiVersion, name, properties, ...extra }; }
function template(resources, subscription = false) {
  return { $schema: `https://schema.management.azure.com/schemas/${subscription ? '2018-05-01/subscriptionDeploymentTemplate' : '2019-04-01/deploymentTemplate'}.json#`,
    contentVersion: '1.0.0.0', resources };
}
export function budgetProperties(c, amount) {
  return { category: 'Cost', amount, timeGrain: 'Monthly', timePeriod: { startDate: c.budgetStart, endDate: c.budgetEnd },
    notifications: Object.fromEntries([['actual80', 'Actual', 80], ['forecast100', 'Forecasted', 100]].map(([name, thresholdType, threshold]) =>
      [name, { enabled: true, operator: 'GreaterThanOrEqualTo', thresholdType, threshold,
        contactEmails: [c.budgetEmail], contactGroups: [], contactRoles: [] }])) };
}
export function projectBudgetFilter(c) {
  return { dimensions: { name: 'ResourceGroupName', operator: 'In', values: ['telemetry', 'state', 'managed'].map(s => `${c.namePrefix}-${s}`) } };
}
export function uploadRoleProperties(c) {
  return { roleName: `${c.namePrefix}-dcr-upload-only`, description: 'Only upload to the intended MissionSpec DCR.',
    type: 'CustomRole', permissions: [{ actions: [], notActions: [], dataActions: ['Microsoft.Insights/Telemetry/Write'], notDataActions: [] }],
    assignableScopes: [ids(c).group] };
}
export function assignmentRoleTargets(c) {
  const r = ids(c);
  return [
    { scope: r.registry, roleDefinitionId: `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d`, roleName: 'AcrPull', roleType: 'BuiltInRole' },
    { scope: r.workspace, roleDefinitionId: `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/73c42c96-874c-492b-b04d-ab87d138a893`, roleName: 'Log Analytics Reader', roleType: 'BuiltInRole' },
    { scope: r.dcr, roleDefinitionId: r.uploadRole, roleName: `${c.namePrefix}-dcr-upload-only`, roleType: 'CustomRole' },
  ];
}
export function notificationKeys(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('BUDGET_NOTIFICATIONS_INVALID');
  const result = {};
  for (const [key, value] of Object.entries(input)) {
    const k = key.toLowerCase();
    if (!['actual80', 'forecast100'].includes(k) || Object.hasOwn(result, k)) fail('BUDGET_NOTIFICATION_KEYS_INVALID');
    result[k] = value;
  }
  if (Object.keys(result).length !== 2) fail('BUDGET_NOTIFICATION_KEYS_INVALID');
  return result;
}
export function budgetConfiguration(value) {
  const p = value?.properties;
  if (!p || Object.keys(p).some(k => !['amount', 'category', 'timeGrain', 'timePeriod', 'filter', 'notifications', 'currentSpend', 'forecastSpend'].includes(k))) fail('BUDGET_READBACK_FAILED');
  const { currentSpend, forecastSpend, ...configuration } = p;
  return { ...configuration, filter: p.filter ?? {}, notifications: notificationKeys(p.notifications) };
}
export function assertBudget(value, c, amount, filter = {}) {
  if (!isDeepStrictEqual(budgetConfiguration(value), { ...budgetProperties(c, amount), filter })) fail('BUDGET_READBACK_FAILED');
}
export function verifyFoundationBudgets(c, foundation) {
  closed(foundation, ['version', 'originSha256', 'checkedAt', 'project', 'state']);
  const r = ids(c);
  if (foundation.version !== 1 || foundation.originSha256 !== c.originSha256 || digest(json(foundation)) !== c.foundationBudgetsSha256 ||
      !sameId(foundation.project?.id, r.projectBudget) || !sameId(foundation.state?.id, r.stateBudget)) fail('FOUNDATION_BUDGET_RECEIPT_REQUIRED');
  assertBudget(foundation.project, c, c.budget.previousProjectAmount, projectBudgetFilter(c));
  assertBudget(foundation.state, c, c.budget.stateAmount);
  return foundation;
}
function workspace(c) {
  return resource('Microsoft.OperationalInsights/workspaces', '2023-09-01', `${c.namePrefix}-analytics`, {
    sku: { name: 'PerGB2018' }, retentionInDays: 180, workspaceCapping: { dailyQuotaGb: 0.25 },
    publicNetworkAccessForIngestion: 'Enabled', publicNetworkAccessForQuery: 'Enabled',
    features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: false },
  }, { location: c.location, tags: ownerTags(c) });
}
export function assertOwned(value, expectedId, c) {
  if (!sameId(value?.id, expectedId) || value.tags?.product !== 'MissionSpec' ||
      value.tags?.purpose !== 'aggregate-telemetry' || value.tags?.collectorRun !== c.runId) fail('COLLECTOR_OWNERSHIP_MISMATCH');
}
export function requireAccess(value) {
  if (value?.properties?.features?.disableLocalAuth !== true ||
      value?.properties?.features?.enableLogAccessUsingOnlyResourcePermissions !== false) fail('WORKSPACE_ACCESS_NOT_QUALIFIED');
}
function bindPrior(c, receipts, phase, target) {
  const receipt = receipts[phase];
  if (receipt?.qualified !== true || receipt.configSha256 !== digest(json(c)) || !receipt.resources?.[target]) fail('PRIOR_READBACK_REQUIRED');
  const value = receipt.resources[target];
  assertOwned(value, target, c);
  return value;
}
function assignment(scope, principal, role, c, purpose) {
  if (!uuid.test(principal)) fail('GENERATED_IDENTITY_READBACK_REQUIRED');
  return resource('Microsoft.Authorization/roleAssignments', '2022-04-01', stableGuid(`${scope}/${principal}/${purpose}`), {
    roleDefinitionId: role, principalId: principal, principalType: purpose === 'query' ? 'User' : 'ServicePrincipal',
  }, { scope });
}
function appResource(c, receipts, enabled) {
  const r = ids(c);
  const runtime = runtimeReceiver(c, receipts);
  const core = receipts.core;
  const ingest = bindPrior(c, receipts, 'core', r.ingestIdentity), pull = bindPrior(c, receipts, 'core', r.pullIdentity);
  const dcr = bindPrior(c, receipts, 'data', r.dcr);
  const ws = bindPrior(c, receipts, 'workspace-access', r.workspace); requireAccess(ws);
  if (!receipts.assignments?.qualified || receipts.assignments.configSha256 !== digest(json(c)) ||
      !receipts.publication?.qualified || receipts.publication.digest !== c.receiverDigest ||
      receipts.publication.configSha256Inputs !== digest(json(c)) ||
      receipts.publication.registryId !== r.registry || receipts.publication.recentDigestCount !== 1 ||
      receipts.publication.configUser !== '65532:65532' || !isDeepStrictEqual(receipts.publication.command, RECEIVER_COMMAND) ||
      receipts.publication.configSha256 !== 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204') fail('IMAGE_OR_ROLES_NOT_QUALIFIED');
  if (!uuid.test(ingest.properties.clientId) || !uuid.test(pull.properties.clientId) ||
      !/^dcr-[0-9a-f]{32}$/u.test(dcr.properties.immutableId)) fail('DCR_IDENTITY_READBACK_INVALID');
  const endpoint = new URL(dcr.properties.endpoints.logsIngestion);
  if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.ingest.monitor.azure.com') ||
      endpoint.username || endpoint.password || endpoint.port || endpoint.search || endpoint.hash ||
      !['', '/'].includes(endpoint.pathname)) fail('DCR_ENDPOINT_INVALID');
  const loginServer = core.resources[r.registry]?.properties?.loginServer;
  if (loginServer !== `${c.registryName}.azurecr.io`) fail('REGISTRY_ENDPOINT_MISMATCH');
  const values = { PORT: '8080', MSR_BIND_HOST: '0.0.0.0', MSR_INGESTION_ENABLED: String(enabled),
    MSR_RESOURCE_GROUP: `${c.namePrefix}-telemetry`, AZURE_SUBSCRIPTION_ID: c.subscriptionId, AZURE_TENANT_ID: c.tenantId,
    AZURE_CLIENT_ID: ingest.properties.clientId, AZURE_DCR_RESOURCE_ID: r.dcr,
    AZURE_DCR_IMMUTABLE_ID: dcr.properties.immutableId, AZURE_LOGS_ENDPOINT: endpoint.origin,
    ...Object.fromEntries(Object.entries(LIMITS).map(([key, value]) => [`MSR_${key.toUpperCase()}`, String(value)])),
    ...(runtime?.queueTopology ? queueEnvironment(runtime.queueTopology) : {}) };
  return resource('Microsoft.App/containerApps', '2025-07-01', `${c.namePrefix}-ingest`, {
    managedEnvironmentId: r.environment, workloadProfileName: 'Consumption',
    configuration: { activeRevisionsMode: 'Single', maxInactiveRevisions: 3,
      registries: [{ server: loginServer, identity: r.pullIdentity }],
      identitySettings: [{ identity: r.ingestIdentity, lifecycle: 'Main' }, { identity: r.pullIdentity, lifecycle: 'None' }],
      ingress: { external: true, allowInsecure: false, targetPort: 8080, transport: 'http', traffic: [{ latestRevision: true, weight: 100 }] } },
    template: { terminationGracePeriodSeconds: 10,
      scale: { minReplicas: 1, maxReplicas: 1, rules: [{ name: 'bounded-http', http: { metadata: { concurrentRequests: '16' } } }] },
      containers: [{ name: 'telemetry-ingest', image: `${loginServer}/missionspec/telemetry-ingest@${runtime?.digest ?? c.receiverDigest}`,
        resources: { cpu: 0.25, memory: '0.5Gi' }, env: Object.entries(values).map(([name, value]) => ({ name, value })),
        probes: [
          { type: 'Startup', httpGet: { path: '/health/live', port: 8080, scheme: 'HTTP' }, periodSeconds: 1, failureThreshold: 30 },
          { type: 'Liveness', httpGet: { path: '/health/live', port: 8080, scheme: 'HTTP' }, periodSeconds: 10 },
          { type: 'Readiness', httpGet: { path: '/health/ready', port: 8080, scheme: 'HTTP' }, periodSeconds: 5, failureThreshold: 2, successThreshold: 1 },
        ] }] },
  }, { location: c.location, tags: ownerTags(c), identity: {
    type: 'UserAssigned', userAssignedIdentities: { [r.ingestIdentity]: {}, [r.pullIdentity]: {} } } });
}
export function reconciliationBinding(lineage) {
  return lineage?.proposal ? { proposalSha256: digest(json(lineage.proposal)),
    reviewSha256: lineage.review ? digest(json(lineage.review)) : null } : null;
}
export function buildPhase(c, phase, contract, receipts = {}, foundation, sourceLineage, windowInstance) {
  validateConfig(c); if (!PHASES.includes(phase)) fail('PHASE_NOT_SUPPORTED');
  if (IMAGE_PHASES.includes(phase)) fail('REVIEWED_IMAGE_OVERLAY_REQUIRED');
  const r = ids(c), regional = { location: c.location, tags: ownerTags(c) };
  let resources, scope = r.group;
  if (phase === 'project-budget') {
    const before = verifyFoundationBudgets(c, foundation).project;
    scope = r.sub;
    // Preserve the reviewed writable fields and notification-key spelling; only amount changes.
    const { currentSpend, forecastSpend, ...properties } = structuredClone(before.properties);
    properties.amount = c.budget.projectAmount;
    resources = [resource('Microsoft.Consumption/budgets', '2024-08-01', `${c.namePrefix}-project-budget`, properties)];
  }
  if (phase === 'core') resources = [
    resource('Microsoft.ContainerRegistry/registries', '2023-07-01', c.registryName,
      { adminUserEnabled: false, anonymousPullEnabled: false, publicNetworkAccess: 'Enabled' }, { ...regional, sku: { name: 'Basic' } }),
    ...['ingest', 'pull'].map(name => resource('Microsoft.ManagedIdentity/userAssignedIdentities', '2023-01-31', `${c.namePrefix}-${name}`, {}, regional)),
    workspace(c),
    resource('Microsoft.App/managedEnvironments', '2025-07-01', `${c.namePrefix}-environment`, {
      publicNetworkAccess: 'Enabled',
      workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }], zoneRedundant: false,
    }, regional),
    resource('Microsoft.Consumption/budgets', '2024-08-01', `${c.namePrefix}-budget`, budgetProperties(c, c.budget.telemetryAmount)),
  ];
  if (phase === 'workspace-access') {
    bindPrior(c, receipts, 'core', r.workspace);
    resources = [workspace(c)];
  }
  if (phase === 'data') {
    requireAccess(bindPrior(c, receipts, 'workspace-access', r.workspace));
    resources = [
      resource('Microsoft.OperationalInsights/workspaces/tables', '2022-10-01', `${c.namePrefix}-analytics/MissionSpecTelemetry_CL`,
        { plan: 'Analytics', retentionInDays: 180, totalRetentionInDays: 180, schema: { name: 'MissionSpecTelemetry_CL', columns: contract.columns } }),
      resource('Microsoft.Insights/dataCollectionRules', '2024-03-11', `${c.namePrefix}-dcr`, {
        streamDeclarations: { 'Custom-MissionSpecTelemetry': { columns: contract.columns } },
        destinations: { logAnalytics: [{ name: 'missionspec', workspaceResourceId: r.workspace }] },
        dataFlows: [{ streams: ['Custom-MissionSpecTelemetry'], destinations: ['missionspec'],
          outputStream: 'Custom-MissionSpecTelemetry_CL', transformKql: `source | project ${contract.columns.map(value => value.name).join(', ')}` }],
      }, { ...regional, kind: 'Direct', dependsOn: [r.table] }),
    ];
  }
  if (phase === 'upload-role') {
    bindPrior(c, receipts, 'data', r.dcr); scope = r.sub;
    resources = [resource('Microsoft.Authorization/roleDefinitions', '2022-04-01', r.uploadRole.split('/').at(-1), uploadRoleProperties(c))];
  }
  if (phase === 'assignments') {
    requireAccess(bindPrior(c, receipts, 'workspace-access', r.workspace));
    const ingest = bindPrior(c, receipts, 'core', r.ingestIdentity), pull = bindPrior(c, receipts, 'core', r.pullIdentity);
    if (!receipts['upload-role']?.qualified || receipts['upload-role'].configSha256 !== digest(json(c))) fail('UPLOAD_ROLE_NOT_QUALIFIED');
    bindPrior(c, receipts, 'data', r.dcr);
    resources = [
      assignment(r.registry, pull.properties.principalId, `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/7f951dda-4ed3-4680-a7ca-43fe172d538d`, c, 'pull'),
      assignment(r.dcr, ingest.properties.principalId, r.uploadRole, c, 'upload'),
      ...c.queryPrincipalIds.map(principal => assignment(r.workspace, principal, `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/73c42c96-874c-492b-b04d-ab87d138a893`, c, 'query')),
    ];
  }
  if (phase === 'disabled-app') {
    if (receipts.receiverUpgrade) fail('HISTORICAL_DISABLED_APP_PROFILE_IMMUTABLE');
    resources = [appResource(c, receipts, false)];
  }
  if (TOGGLE_PHASES.includes(phase)) {
    if (!receipts['disabled-app']?.qualified || receipts['disabled-app'].configSha256 !== digest(json(c)) ||
        !receipts['disabled-app'].resources?.[r.app]) fail('DISABLED_APP_NOT_QUALIFIED');
    resources = [appResource(c, receipts, phase === 'synthetic-admission')];
    resources[0].properties.configuration.ingress.exposedPort = 0;
    resources[0].properties.template.scale.cooldownPeriod = 300;
    resources[0].properties.template.scale.pollingInterval = 30;
    resources[0].properties.template.containers[0].probes.sort((a, b) => a.type.localeCompare(b.type));
  }
  const descriptors = resources.map(value => {
    const parts = value.type.split('/'), names = value.name.split('/');
    return { id: `${value.scope ?? scope}/providers/${parts[0]}/${parts.slice(1).map((part, i) => `${part}/${names[i]}`).join('/')}`,
      apiVersion: value.apiVersion, type: value.type, expected: value };
  });
  const runtime = TOGGLE_PHASES.includes(phase) ? runtimeReceiver(c, receipts) : null;
  return { version: 1, phase, configSha256: digest(json(c)), scope,
    deploymentId: `${scope}/providers/Microsoft.Resources/deployments/${deploymentName(c, phase, windowInstance)}`,
    ...(windowInstance ? { windowInstance: structuredClone(validateWindowInstance(c, windowInstance)) } : {}),
    ...(TOGGLE_PHASES.includes(phase) && receipts.receiverUpgrade ? { receiverUpgradeSha256: digest(json(receipts.receiverUpgrade)) } : {}),
    ...(runtime?.queueTopology ? { queueVerification: { version: 1, queueId: runtime.queueTopology.ids.queue,
      topologySha256: digest(json(runtime.queueTopology)), acceptedStatus: 202,
      requiresOwnedLogsRows: true, requiresObservedApproximateDrain: true, exactBacklogClaimed: false } } : {}),
    template: template(resources, scope === r.sub), resources: descriptors,
    ...(sourceLineage?.proposal ? { reconciliation: reconciliationBinding(sourceLineage) } : {}),
    ...(TOGGLE_PHASES.includes(phase) ? { transition: {
      version: 1, anchorAppSha256: digest(json(receiverAnchor(c, receipts))),
      from: phase === 'synthetic-admission' ? ['false'] : ['true', 'false'],
      to: phase === 'synthetic-admission' ? 'true' : 'false',
      maximumWrites: 1, limits: SYNTHETIC_LIMITS,
    } } : {}),
    requiredReceipts: phase === 'project-budget' ? [] : ['project-budget'],
    ...(phase === 'project-budget' ? { budgetBefore: budgetConfiguration(foundation.project) } : {}),
    allowedModify: phase === 'project-budget' ? { [r.projectBudget]: ['properties.amount'] }
      : phase === 'workspace-access' ? { [r.workspace]: ['properties.features.disableLocalAuth', 'properties.features.enableLogAccessUsingOnlyResourcePermissions'] }
      : TOGGLE_PHASES.includes(phase) ? { [r.app]: ['properties.template.containers'] } : {},
    computedReadbacksRequired: phase === 'core' ? ['UAMI client/principal IDs', 'workspace customerId/access flags', 'default-network environment identity/privacy settings']
      : phase === 'data' ? ['same DCR immutable ID and ingestion endpoint'] : [],
    publicationAuthorized: false, cliActivationAuthorized: false, ingestEnabled: phase === 'synthetic-admission' };
}

export function firstReleaseCost(recentDigestCount = 1) {
  if (![1, 2].includes(recentDigestCount)) fail('NEW_DIGEST_COST_REVIEW_REQUIRED');
  const hours = 31 * 24;
  // Disabled/invalid requests can still be billed without accepting an event.
  const httpRequests = { sustainedPerMinute: LIMITS.requests_per_minute, monthlyVolume: hours * 60 * LIMITS.requests_per_minute,
    includesRejectedRequests: true, beyondRateLimitCanBeBilled: true };
  const items = {
    warmCpu: hours * 3600 * 0.25 * 0.000034, warmMemory: hours * 3600 * 0.5 * 0.000004,
    requests: httpRequests.monthlyVolume / 1e6 * 0.4,
    analyticsAtDailyCap: 31 * 0.25 * 3.34, retentionAll180Days: 180 * 0.25 * 0.15,
    basicRegistry: 31 * 0.1666, existingBlobPrivateEndpoint: hours * 0.01,
    existingPrivateDns: 0.5, stateStorageAndTransactions: 0.15, privateEndpointData: 0.05,
    defenderStorage: hours * 0.0134, defenderCspmTwoFullNodes: hours * 2 * 0.007,
    stateMalware1GB: 0.15, oneImageInitialPlusDailyAndPullReserve: (31 + 2) * 0.29,
    ambiguousEnvironmentManagement: hours * 0.145,
    possibleManagedLoadBalancer: hours * 0.025, possibleTwoManagedPublicIPs: hours * 2 * 0.005,
    contingency: 10,
    ...(recentDigestCount === 2 ? { additionalImageInitialPlusDailyAndPullReserve: (31 + 2) * 0.29 } : {}),
  };
  const total = Math.ceil(Object.values(items).reduce((sum, v) => sum + v, 0) * 100) / 100;
  return { currency: 'USD', days: 31, recentDigestCount, httpRequests, items, total,
    estimateLimit: BUDGET.projectAmount, withinEstimate: total <= BUDGET.projectAmount,
    freeGrantsAssumed: false, operatorInfrastructureAdded: false, isHardCap: false };
}
