import { isDeepStrictEqual } from 'node:util';
import { assertOwned, assertBudget, BUDGET, budgetConfiguration, closed, digest, fail, ids, json, LIMITS, RECEIVER_COMMAND, requireAccess, sameId, projectBudgetFilter } from './definition.mjs';
export { assertBudget, notificationKeys } from './definition.mjs';

const REVIEW_HASH_FIELDS = ['configSha256', 'phaseSha256', 'sourceSha256', 'originSha256', 'receiptsSha256', 'baselineSha256', 'whatIfSha256'];
function approvalTimes(approval, now, code) {
  const timestamps = ['approvedAt', 'expiresAt'].map(key => {
    const value = approval[key];
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) fail(code);
    const time = Date.parse(value);
    if (!Number.isSafeInteger(time) || new Date(time).toISOString() !== value) fail(code);
    return time;
  });
  const [approvedAt, expiresAt] = timestamps;
  if (!Number.isSafeInteger(now) || approvedAt > now || expiresAt <= now || expiresAt <= approvedAt ||
      expiresAt - approvedAt > 3600000) fail(code);
}
export function verifyApproval(approval, config, phase, sourceSha256, now) {
  try { closed(approval, ['action', ...REVIEW_HASH_FIELDS, 'approvedAt', 'expiresAt']); }
  catch { fail('EXACT_PHASE_RELEASE_REQUIRED'); }
  if (approval.action !== `direct-arm-${phase.phase}` ||
      REVIEW_HASH_FIELDS.some(key => typeof approval[key] !== 'string' || !/^[0-9a-f]{64}$/u.test(approval[key])) ||
      approval.configSha256 !== digest(json(config)) || approval.phaseSha256 !== digest(json(phase)) ||
      approval.sourceSha256 !== sourceSha256) fail('EXACT_PHASE_RELEASE_REQUIRED');
  approvalTimes(approval, now, 'EXACT_PHASE_RELEASE_REQUIRED');
}
export function verifyFreshReview(proof, approval, checkStartedAt, now) {
  approvalTimes(approval, now, 'FRESH_REVIEW_MISMATCH');
  if (proof?.qualified !== true || proof.cost?.withinEstimate !== true || proof.cost.estimateLimit !== BUDGET.projectAmount ||
      !Number.isFinite(proof.cost?.total) || proof.cost.total < 0 || proof.cost.total > BUDGET.projectAmount ||
      REVIEW_HASH_FIELDS.some(key => proof[key] !== approval[key]) ||
      !Number.isSafeInteger(checkStartedAt) || !Number.isSafeInteger(proof.startedAt) || !Number.isSafeInteger(proof.completedAt) ||
      proof.startedAt < checkStartedAt || proof.completedAt < proof.startedAt || proof.completedAt > now ||
      now - proof.startedAt > 300000) fail('FRESH_REVIEW_MISMATCH');
}
function diffLeaves(a, b, path = '') {
  if (isDeepStrictEqual(a, b)) return [];
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    return [...new Set([...Object.keys(a), ...Object.keys(b)])].flatMap(k => diffLeaves(a[k], b[k], path ? `${path}.${k}` : k));
  }
  return [path];
}
function budgetWhatIfConfiguration(value) {
  const configuration = budgetConfiguration(value);
  configuration.notifications = structuredClone(configuration.notifications);
  // ARM what-if omits empty contactGroups/contactRoles; actual GET readbacks still require arrays.
  for (const notification of Object.values(configuration.notifications)) {
    for (const key of ['contactGroups', 'contactRoles']) if (!Object.hasOwn(notification, key)) notification[key] = [];
  }
  return configuration;
}
export function verifyWhatIf(phase, result, preservedIds = []) {
  if (result?.status !== 'Succeeded' || !Array.isArray(result.changes)) fail('WHAT_IF_INCOMPLETE');
  const target = new Map(phase.resources.map(v => [v.id.toLowerCase(), v]));
  const preserved = new Set(preservedIds.map(v => v.toLowerCase()));
  const seen = new Set();
  for (const change of result.changes) {
    const id = change.resourceId?.toLowerCase();
    if (!id || seen.has(id)) fail('WHAT_IF_ID_INVALID');
    seen.add(id);
    if (!target.has(id)) {
      if (preserved.has(id) && ['Ignore', 'NoChange'].includes(change.changeType)) continue;
      fail('UNREVIEWED_RESOURCE_CHANGE');
    }
    const allowed = Object.entries(phase.allowedModify).find(([key]) => key.toLowerCase() === id)?.[1];
    if (phase.phase === 'project-budget') {
      if (change.changeType !== 'Modify' || !change.before || !change.after) fail('BUDGET_AMOUNT_ONLY_REQUIRED');
      for (const value of [change.before, change.after]) {
        if (Object.keys(value).some(k => !['id', 'name', 'type', 'apiVersion', 'eTag', 'etag', 'properties'].includes(k)) ||
            (value.id !== undefined && !sameId(value.id, change.resourceId)) ||
            (value.name !== undefined && value.name !== target.get(id).expected.name) ||
            (value.type !== undefined && !sameId(value.type, target.get(id).type))) fail('BUDGET_AMOUNT_ONLY_REQUIRED');
      }
      const before = budgetWhatIfConfiguration(change.before), after = budgetWhatIfConfiguration(change.after);
      if (!isDeepStrictEqual(before, phase.budgetBefore) ||
          !isDeepStrictEqual(after, budgetConfiguration(target.get(id).expected)) ||
          !isDeepStrictEqual(diffLeaves(before, after), ['amount'])) fail('BUDGET_AMOUNT_ONLY_REQUIRED');
      target.delete(id); continue;
    }
    if (!allowed) {
      if (change.changeType !== 'Create') fail('EXPECTED_NEW_RESOURCE_ONLY');
    } else if (change.changeType === 'Modify') {
      if (!change.before || !change.after) fail('FULL_WHAT_IF_READBACK_REQUIRED');
      const delta = diffLeaves(change.before, change.after);
      if (delta.length === 0 || delta.some(path => !allowed.includes(path))) fail('UNREVIEWED_MODIFY');
      if (phase.phase === 'synthetic-admission') {
        const before = structuredClone(change.before.properties.template.containers);
        const after = change.after.properties.template.containers;
        if (before.length !== 1) fail('SYNTHETIC_DELTA_INVALID');
        const flag = before[0].env?.filter(v => v.name === 'MSR_INGESTION_ENABLED');
        if (flag?.length !== 1 || flag[0].value !== 'false') fail('SYNTHETIC_DELTA_INVALID');
        flag[0].value = 'true';
        if (!isDeepStrictEqual(before, after)) fail('SYNTHETIC_DELTA_INVALID');
      }
    } else if (change.changeType !== 'NoChange') fail('OWNED_UPDATE_ONLY');
    target.delete(id);
  }
  if (target.size) fail('WHAT_IF_INCOMPLETE');
  return digest(json(result));
}
export function verifyPublication(c, repositories, manifests, config) {
  if (!isDeepStrictEqual(repositories, ['missionspec/telemetry-ingest']) || manifests.length !== 1 ||
      manifests[0].digest !== c.receiverDigest || config.os !== 'linux' || config.architecture !== 'amd64' ||
      config.config?.User !== '65532:65532' || !isDeepStrictEqual(config.config?.Cmd, RECEIVER_COMMAND) ||
      (config.config?.Entrypoint?.length ?? 0) !== 0) fail('SINGLE_IMMUTABLE_IMAGE_REQUIRED');
  return { qualified: true, digest: c.receiverDigest, registryId: ids(c).registry, recentDigestCount: 1,
    configUser: config.config.User, command: config.config.Cmd,
    configSha256: 'sha256:' + digest(Buffer.from(JSON.stringify(config))) };
}
export function permitFirstPush(c, repositories, manifests) {
  if (repositories.length !== 0 || manifests.length !== 0) fail('REGISTRY_NOT_EMPTY_NEW_DIGEST_REVIEW_REQUIRED');
  return { allowedDigest: c.receiverDigest, maximumNewImages: 1, pushExecuted: false, futurePushAuthorized: false };
}
function envMap(env) {
  if (!Array.isArray(env)) fail('APP_ENV_INVALID');
  const out = {};
  for (const row of env) {
    if (Object.keys(row).some(k => !['name', 'value'].includes(k)) || typeof row.value !== 'string' || Object.hasOwn(out, row.name)) fail('APP_ENV_INVALID');
    out[row.name] = row.value;
  }
  return out;
}
export function verifyResource(c, phase, descriptor, actual) {
  const r = ids(c), expected = descriptor.expected, p = actual?.properties;
  if (!sameId(actual?.id, descriptor.id)) fail('RESOURCE_ID_MISMATCH');
  if (expected.tags) assertOwned(actual, descriptor.id, c);
  if (p?.provisioningState && p.provisioningState !== 'Succeeded') fail('RESOURCE_NOT_SUCCEEDED');
  if (expected.type === 'Microsoft.ContainerRegistry/registries') {
    if (actual.sku?.name !== 'Basic' || p.adminUserEnabled !== false || p.anonymousPullEnabled !== false ||
        p.publicNetworkAccess !== 'Enabled' || p.loginServer !== `${c.registryName}.azurecr.io`) fail('REGISTRY_READBACK_FAILED');
  } else if (expected.type === 'Microsoft.ManagedIdentity/userAssignedIdentities') {
    if (!/^[0-9a-f-]{36}$/u.test(p.clientId) || !/^[0-9a-f-]{36}$/u.test(p.principalId) || p.tenantId !== c.tenantId) fail('IDENTITY_READBACK_FAILED');
  } else if (expected.type === 'Microsoft.OperationalInsights/workspaces') {
    if (p.sku?.name !== 'PerGB2018' || p.retentionInDays !== 180 || p.workspaceCapping?.dailyQuotaGb !== 0.25 ||
        p.features?.disableLocalAuth !== true || !/^[0-9a-f-]{36}$/u.test(p.customerId)) fail('WORKSPACE_READBACK_FAILED');
    if (phase.phase !== 'core') requireAccess(actual);
  } else if (expected.type.endsWith('/tables')) {
    if (p.plan !== 'Analytics' || p.retentionInDays !== 180 || p.totalRetentionInDays !== 180 ||
        !isDeepStrictEqual(p.schema?.columns, expected.properties.schema.columns)) fail('TABLE_RETENTION_SCHEMA_DRIFT');
  } else if (expected.type === 'Microsoft.Insights/dataCollectionRules') {
    if (actual.kind !== 'Direct' || !isDeepStrictEqual(p.streamDeclarations, expected.properties.streamDeclarations) ||
        !isDeepStrictEqual(p.destinations, expected.properties.destinations) || !isDeepStrictEqual(p.dataFlows, expected.properties.dataFlows) ||
        !/^dcr-[0-9a-f]{32}$/u.test(p.immutableId)) fail('DCR_READBACK_FAILED');
    const endpoint = new URL(p.endpoints?.logsIngestion);
    if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.ingest.monitor.azure.com') ||
        endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.port) fail('DCR_ENDPOINT_INVALID');
  } else if (expected.type === 'Microsoft.App/managedEnvironments') {
    if (p.publicNetworkAccess !== 'Enabled' || (p.appLogsConfiguration?.destination ?? '') !== '' ||
        p.appLogsConfiguration?.logAnalyticsConfiguration || p.daprAIInstrumentationKey || p.daprAIConnectionString ||
        p.openTelemetryConfiguration || p.vnetConfiguration?.infrastructureSubnetId ||
        !isDeepStrictEqual(p.workloadProfiles?.map(v => ({ name: v.name, workloadProfileType: v.workloadProfileType })), expected.properties.workloadProfiles) ||
        ![`${c.namePrefix}-managed`, r.managedGroup].includes(p.infrastructureResourceGroup)) fail('ENVIRONMENT_PRIVACY_DRIFT');
  } else if (expected.type === 'Microsoft.Consumption/budgets') {
    if (phase.phase === 'project-budget') assertBudget(actual, c, c.budget.projectAmount, projectBudgetFilter(c));
    else assertBudget(actual, c, c.budget.telemetryAmount);
  } else if (expected.type === 'Microsoft.Authorization/roleDefinitions') {
    if (p.roleName !== expected.properties.roleName || !isDeepStrictEqual(p.permissions, expected.properties.permissions) ||
        !isDeepStrictEqual(p.assignableScopes, [r.group])) fail('UPLOAD_ROLE_SCOPE_DRIFT');
  } else if (expected.type === 'Microsoft.Authorization/roleAssignments') {
    if (!sameId(p.scope, expected.scope) || p.principalId !== expected.properties.principalId ||
        !sameId(p.roleDefinitionId, expected.properties.roleDefinitionId) || p.condition) fail('ROLE_ASSIGNMENT_DRIFT');
  } else if (expected.type === 'Microsoft.App/containerApps') {
    const e = expected.properties, container = p.template?.containers?.[0], wanted = e.template.containers[0];
    if (p.template?.containers?.length !== 1 || p.template?.initContainers?.length || container?.command?.length || container?.args?.length ||
        container?.image !== wanted.image || container?.name !== wanted.name ||
        !isDeepStrictEqual(container.resources, wanted.resources) || !isDeepStrictEqual(envMap(container.env), envMap(wanted.env)) ||
        !isDeepStrictEqual(container.probes, wanted.probes) || p.configuration?.activeRevisionsMode !== 'Single' ||
        p.configuration?.ingress?.allowInsecure !== false || p.configuration?.ingress?.external !== true ||
        p.configuration?.ingress?.targetPort !== 8080 || p.configuration?.ingress?.transport !== 'http' ||
        !isDeepStrictEqual(p.configuration?.ingress?.traffic, e.configuration.ingress.traffic) ||
        p.configuration?.maxInactiveRevisions !== 3 || !sameId(p.managedEnvironmentId ?? p.environmentId, r.environment) ||
        p.template.scale?.minReplicas !== 1 || p.template.scale?.maxReplicas !== 1 ||
        !isDeepStrictEqual(p.template.scale.rules, e.template.scale.rules) ||
        p.template.terminationGracePeriodSeconds !== 10 || p.workloadProfileName !== 'Consumption' ||
        !isDeepStrictEqual(p.configuration.registries, e.configuration.registries) ||
        !isDeepStrictEqual(p.configuration.identitySettings, e.configuration.identitySettings) ||
        !isDeepStrictEqual(Object.keys(actual.identity?.userAssignedIdentities ?? {}).sort(), [r.ingestIdentity, r.pullIdentity].sort()) ||
        actual.identity?.type !== 'UserAssigned' || p.configuration?.dapr?.enabled ||
        (p.configuration?.secrets?.length ?? 0) !== 0 || p.configuration?.service) fail('APP_PRIVACY_RUNTIME_DRIFT');
    const host = p.configuration.ingress.fqdn;
    if (typeof host !== 'string' || !/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(host)) fail('APP_FQDN_INVALID');
  } else fail('UNSUPPORTED_RESOURCE_READBACK');
  return actual;
}
export function sourceContractsSummary(contract) {
  return { schema: contract.schemaSha256, columns: contract.columnsSha256, limits: LIMITS,
    tableRetention: { plan: 'Analytics', analyticsDays: 180, totalDays: 180, extraArchive: false },
    noLoginKeys: true, noClientActivation: true, initialImageCount: 1 };
}
