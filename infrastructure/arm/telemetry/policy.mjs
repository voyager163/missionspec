import { isDeepStrictEqual } from 'node:util';
import { assertOwned, assertBudget, BUDGET, buildPhase, budgetConfiguration, closed, digest, fail, ids, json, LIMITS, PHASES, RECEIVER_COMMAND, requireAccess, sameId, projectBudgetFilter } from './definition.mjs';
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
export function canonicalInstant(value) {
  const time = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isSafeInteger(time) || new Date(time).toISOString() !== value) fail('RECONCILIATION_TIME_INVALID');
  return time;
}
export function verifyDeploymentIdentity(expected, actual) {
  if (!sameId(actual?.id, expected.id) || actual.properties?.provisioningState !== 'Succeeded' ||
      actual.properties.mode !== 'Incremental' ||
      ['correlationId', 'timestamp', 'templateHash'].some(k => typeof expected.properties?.[k] !== 'string' ||
        !expected.properties[k] || actual.properties[k] !== expected.properties[k])) fail('DEPLOYMENT_IDENTITY_CHANGED');
}
export function executionIdentity(value, expectedType) {
  const p = value?.properties ?? {}, type = value?.type?.toLowerCase() ?? expectedType?.toLowerCase() ?? null;
  if (expectedType && type !== expectedType.toLowerCase()) fail('RESOURCE_TYPE_CHANGED');
  const identity = { id: value?.id?.toLowerCase(), type, location: value?.location?.toLowerCase() ?? null,
    resourceGuid: p.resourceGuid ?? null, createdAt: value?.systemData?.createdAt ?? p.creationDate ?? p.createdDate ?? null };
  if (type === 'microsoft.managedidentity/userassignedidentities') {
    for (const name of ['clientId', 'principalId', 'tenantId']) {
      if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(p[name] ?? '')) fail('GENERATED_IDENTITY_REQUIRED');
      identity[name] = p[name];
    }
  } else if (type === 'microsoft.operationalinsights/workspaces') identity.customerId = p.customerId;
  else if (type === 'microsoft.app/managedenvironments') {
    identity.defaultDomain = p.defaultDomain;
    identity.domainVerificationId = p.customDomainConfiguration?.customDomainVerificationId ?? null;
    if (typeof identity.defaultDomain !== 'string' || !identity.defaultDomain) fail('GENERATED_IDENTITY_REQUIRED');
  } else if (type === 'microsoft.insights/datacollectionrules') {
    identity.immutableId = p.immutableId;
    identity.logsIngestion = p.endpoints?.logsIngestion;
    if (!/^dcr-[0-9a-f]{32}$/u.test(identity.immutableId ?? '') || typeof identity.logsIngestion !== 'string') fail('GENERATED_IDENTITY_REQUIRED');
  }
  if (['microsoft.containerregistry/registries', 'microsoft.operationalinsights/workspaces', 'microsoft.app/managedenvironments',
    'microsoft.operationalinsights/workspaces/tables', 'microsoft.insights/datacollectionrules'].includes(type) &&
      (typeof identity.createdAt !== 'string' || !Number.isFinite(Date.parse(identity.createdAt)))) fail('CREATION_TIME_REQUIRED');
  return identity;
}
function historicalTemplate(c, phase) {
  const copy = structuredClone(phase.template);
  if (phase.phase === 'core') {
    const environment = copy.resources.find(v => v.type === 'Microsoft.App/managedEnvironments');
    if (Object.hasOwn(environment?.properties ?? {}, 'infrastructureResourceGroup')) {
      if (environment.properties.infrastructureResourceGroup !== `${c.namePrefix}-managed`) fail('HISTORICAL_TEMPLATE_CHANGED');
      delete environment.properties.infrastructureResourceGroup;
    }
  }
  return copy;
}
export const RECONCILABLE_PHASES = Object.freeze(PHASES.slice(0, 4));
function prerequisiteWorkspace(c, receipts) {
  return receipts['workspace-access']?.resources?.[ids(c).workspace] ?? receipts.core?.resources?.[ids(c).workspace] ?? null;
}
function verifyPrerequisites(c, record, priorRecords) {
  const receipts = record.prerequisiteReceipts;
  if (!receipts || typeof receipts !== 'object' || Array.isArray(receipts) ||
      digest(json(receipts)) !== record.approval.receiptsSha256 ||
      record.preflight.receiptsSha256 !== record.approval.receiptsSha256 ||
      !isDeepStrictEqual(Object.keys(receipts).sort(), priorRecords.map(v => v.phase.phase).sort())) fail('PREREQUISITE_RECEIPTS_CHANGED');
  const context = { workspace: prerequisiteWorkspace(c, receipts) };
  for (const [name, receipt] of Object.entries(receipts)) {
    const prior = priorRecords.find(v => v.phase.phase === name);
    if (!prior || canonicalInstant(prior.firstReadback.checkedAt) > canonicalInstant(record.journal.intentAt) ||
        receipt?.qualified !== true || receipt.phase !== name ||
        receipt.configSha256 !== digest(json(c)) || receipt.sourceSha256 !== prior.publication.sourceSha256 ||
        receipt.phaseSha256 !== digest(json(prior.phase)) ||
        !isDeepStrictEqual(Object.keys(receipt.resources ?? {}).sort(), prior.phase.resources.map(v => v.id).sort())) fail('PREREQUISITE_ORIGIN_MISMATCH');
    verifyDeploymentIdentity(prior.firstReadback.deployment, receipt.deployment);
    if (receipt.qualificationKind === undefined) {
      if (!isDeepStrictEqual(receipt, prior.originalReceipt)) fail('PREREQUISITE_RECEIPTS_CHANGED');
    } else {
      const review = receipt.reconciliation;
      if (receipt.qualificationKind !== 'reviewed-read-only-reconciliation' ||
          review?.policySourceSha256 !== record.publication.sourceSha256 ||
          review.originalJournalOutcome !== prior.journal.outcome ||
          review.originalReceiptQualified !== (prior.originalReceipt?.qualified === true) ||
          ['proposalSha256', 'reviewSha256', 'executionOriginSha256'].some(k => !/^[0-9a-f]{64}$/u.test(review[k] ?? '')) ||
          canonicalInstant(review.checkedAt) > canonicalInstant(review.reviewedAt) ||
          canonicalInstant(review.reviewedAt) > canonicalInstant(record.journal.intentAt)) fail('PREREQUISITE_REVIEW_MISMATCH');
    }
    for (const descriptor of prior.phase.resources) {
      const value = receipt.resources[descriptor.id];
      verifyResource(c, prior.phase, descriptor, value, context);
      if (!isDeepStrictEqual(executionIdentity(value, descriptor.type),
        executionIdentity(prior.firstReadback.resources[descriptor.id], descriptor.type))) fail('PREREQUISITE_IDENTITY_CHANGED');
    }
  }
}
export function verifyExecutionOrigin(c, foundation, record, contract, priorRecords = []) {
  closed(record, ['version', 'publication', 'phase', 'approval', 'journal', 'preflight', 'validation', 'whatIf', 'firstReadback', 'originalReceipt', 'prerequisiteReceipts']);
  closed(record.publication, ['commitSha', 'sourceSha256']);
  closed(record.firstReadback, ['checkedAt', 'deployment', 'resources']);
  closed(record.journal, ['phase', 'phaseSha256', 'intentAt', 'outcome',
    ...(Object.hasOwn(record.journal, 'failureCode') ? ['failureCode'] : []),
    ...(Object.hasOwn(record.journal, 'armCode') ? ['armCode'] : [])]);
  const p = record.phase, r = ids(c);
  if (record.version !== 2 || !RECONCILABLE_PHASES.includes(p?.phase) ||
      !/^[0-9a-f]{40}$/u.test(record.publication.commitSha) || !/^[0-9a-f]{64}$/u.test(record.publication.sourceSha256)) fail('EXECUTION_ORIGIN_INVALID');
  verifyPrerequisites(c, record, priorRecords);
  const expected = buildPhase(c, p.phase, contract, record.prerequisiteReceipts, foundation);
  if (p.version !== 1 || p.configSha256 !== digest(json(c)) || p.deploymentId !== expected.deploymentId || p.scope !== expected.scope ||
      p.publicationAuthorized !== false || p.cliActivationAuthorized !== false || p.ingestEnabled !== false ||
      !isDeepStrictEqual(p.allowedModify, expected.allowedModify) || !isDeepStrictEqual(p.requiredReceipts, expected.requiredReceipts) ||
      !isDeepStrictEqual(historicalTemplate(c, p), expected.template) ||
      p.resources.length !== expected.resources.length ||
      p.resources.some((v, i) => v.id !== expected.resources[i].id || v.type !== expected.resources[i].type ||
        v.apiVersion !== expected.resources[i].apiVersion || !isDeepStrictEqual(v.expected, p.template.resources[i]))) fail('HISTORICAL_TEMPLATE_CHANGED');
  const intentAt = canonicalInstant(record.journal.intentAt);
  verifyApproval(record.approval, c, p, record.publication.sourceSha256, intentAt);
  verifyFreshReview(record.preflight, record.approval, record.preflight.startedAt, intentAt);
  if (record.approval.originSha256 !== c.originSha256 || record.journal.phase !== p.phase || record.journal.phaseSha256 !== digest(json(p)) ||
      !['readback-qualified', 'reconciliation-required'].includes(record.journal.outcome) ||
      record.validation?.properties?.provisioningState !== 'Succeeded' || record.validation.error ||
      record.validation.properties.templateHash !== record.firstReadback.deployment.properties?.templateHash ||
      digest(json(record.whatIf)) !== record.approval.whatIfSha256 ||
      canonicalInstant(record.firstReadback.checkedAt) < intentAt) fail('EXECUTION_ORIGIN_INVALID');
  verifyWhatIf(p, record.whatIf, Object.values(record.prerequisiteReceipts).flatMap(v => Object.keys(v.resources ?? {})));
  verifyDeploymentIdentity(record.firstReadback.deployment, record.firstReadback.deployment);
  if (!sameId(record.firstReadback.deployment.id, p.deploymentId) ||
      !isDeepStrictEqual(Object.keys(record.firstReadback.resources).sort(), p.resources.map(v => v.id).sort())) fail('EXECUTION_ORIGIN_INVALID');
  for (const descriptor of p.resources) {
    const value = record.firstReadback.resources[descriptor.id];
    verifyResource(c, p, descriptor, value, { workspace: prerequisiteWorkspace(c, record.prerequisiteReceipts) });
    executionIdentity(value, descriptor.type);
  }
  if (record.originalReceipt !== null && (record.originalReceipt.qualified !== true ||
      record.originalReceipt.sourceSha256 !== record.publication.sourceSha256 ||
      record.originalReceipt.phaseSha256 !== digest(json(p)) || record.originalReceipt.configSha256 !== digest(json(c)) ||
      !isDeepStrictEqual(record.originalReceipt.resources, record.firstReadback.resources) ||
      !isDeepStrictEqual(record.originalReceipt.deployment, record.firstReadback.deployment))) fail('ORIGINAL_RECEIPT_CHANGED');
  if (p.phase === 'project-budget') assertBudget(record.firstReadback.resources[r.projectBudget], c, 350, projectBudgetFilter(c));
}
export function verifyExecutionOrigins(c, foundation, origins, contract) {
  closed(origins, ['version', 'records']);
  if (origins.version !== 2 || !Array.isArray(origins.records) || !origins.records.length ||
      origins.records.length > RECONCILABLE_PHASES.length ||
      origins.records.some((v, i) => v.phase?.phase !== RECONCILABLE_PHASES[i])) fail('EXECUTION_ORIGIN_INVALID');
  for (const [index, record] of origins.records.entries()) verifyExecutionOrigin(c, foundation, record, contract, origins.records.slice(0, index));
}
export function verifyReconciliation(c, foundation, origins, proposal, sourceSha256, review = null, contract) {
  closed(origins, ['version', 'records']);
  closed(proposal, ['version', 'kind', 'sourceSha256', 'configSha256', 'executionOriginsSha256', 'baselineSha256', 'checkedAt', 'results', 'stateBudget', 'workspace', 'inventory', 'managedGroup']);
  verifyExecutionOrigins(c, foundation, origins, contract);
  if (proposal.version !== 2 || proposal.kind !== 'read-only-completed-phases' ||
      !/^[0-9a-f]{64}$/u.test(sourceSha256) || proposal.sourceSha256 !== sourceSha256 || proposal.configSha256 !== digest(json(c)) ||
      proposal.executionOriginsSha256 !== digest(json(origins)) || canonicalInstant(proposal.checkedAt) > Date.now()) fail('RECONCILIATION_INVALID');
  const r = ids(c), expectedResults = origins.records.map(v => v.phase.phase);
  if (expectedResults.includes('data')) {
    const access = origins.records.find(v => v.phase.phase === 'workspace-access');
    if (!sameId(proposal.workspace?.id, r.workspace) ||
        !isDeepStrictEqual(executionIdentity(proposal.workspace), executionIdentity(access.firstReadback.resources[r.workspace]))) fail('DCR_WORKSPACE_IDENTITY_CHANGED');
  } else if (proposal.workspace !== null) fail('RECONCILIATION_INVALID');
  if (!isDeepStrictEqual(Object.keys(proposal.results).sort(), [...expectedResults].sort())) fail('RECONCILIATION_INVALID');
  assertBudget(proposal.stateBudget, c, 50);
  if (!sameId(proposal.stateBudget.id, r.stateBudget) || proposal.managedGroup !== null ||
      !Array.isArray(proposal.inventory?.value) || proposal.inventory.nextLink) fail('RECONCILIATION_INVENTORY_CHANGED');
  const known = new Set(origins.records.flatMap(v => v.phase.resources.map(d => d.id.toLowerCase())));
  if (proposal.inventory.value.some(v => !v.id?.toLowerCase().startsWith(`${r.group.toLowerCase()}/`) || !known.has(v.id.toLowerCase()))) fail('UNEXPECTED_TELEMETRY_RESOURCE');
  for (const record of origins.records) {
    if (proposal.baselineSha256 !== record.preflight.baselineSha256) fail('POLICY_OR_SECURITY_DRIFT');
    const p = record.phase, result = proposal.results[p.phase];
    closed(result, ['executionOriginSha256', 'deployment', 'resources', 'identityPins', 'diagnostics', 'exports']);
    if (result.executionOriginSha256 !== digest(json(record)) || canonicalInstant(proposal.checkedAt) < canonicalInstant(record.firstReadback.checkedAt) ||
        !isDeepStrictEqual(Object.keys(result.resources).sort(), p.resources.map(v => v.id).sort()) ||
        !isDeepStrictEqual(Object.keys(result.identityPins).sort(), p.resources.map(v => v.id).sort())) fail('RECONCILIATION_INVALID');
    verifyDeploymentIdentity(record.firstReadback.deployment, result.deployment);
    for (const descriptor of p.resources) {
      const value = result.resources[descriptor.id], pin = executionIdentity(value, descriptor.type);
      verifyResource(c, p, descriptor, value, { workspace: proposal.workspace });
      if (!isDeepStrictEqual(pin, executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type)) ||
          !isDeepStrictEqual(pin, result.identityPins[descriptor.id])) fail('RESOURCE_IDENTITY_CHANGED');
      if (descriptor.type !== 'Microsoft.Consumption/budgets') {
        const metadata = proposal.inventory.value.filter(v => sameId(v.id, descriptor.id));
        const creation = origins.records.find(v => v.whatIf.changes.some(change => sameId(change.resourceId, descriptor.id) && change.changeType === 'Create'));
        const created = metadata.length === 1 ? Date.parse(metadata[0].createdTime)
          : metadata.length === 0 && descriptor.type === 'Microsoft.OperationalInsights/workspaces/tables' ? Date.parse(pin.createdAt) : NaN;
        if (!creation || !Number.isFinite(created) || created < canonicalInstant(creation.journal.intentAt) ||
            created > canonicalInstant(proposal.checkedAt)) fail('CREATION_TIME_OUTSIDE_EXECUTION');
      }
    }
    const diagnosticIds = p.resources.filter(v => ['Microsoft.App/managedEnvironments', 'Microsoft.OperationalInsights/workspaces'].includes(v.type)).map(v => v.id);
    if (!isDeepStrictEqual(Object.keys(result.diagnostics).sort(), diagnosticIds.sort()) ||
        Object.values(result.diagnostics).some(v => !Array.isArray(v?.value) || v.nextLink || v.value.length !== 0)) fail('DIAGNOSTIC_ROUTE_DRIFT');
    if (['core', 'workspace-access', 'data'].includes(p.phase)) {
      if (!Array.isArray(result.exports?.value) || result.exports.nextLink || result.exports.value.length) fail('WORKSPACE_EXPORT_DRIFT');
    } else if (result.exports !== null) fail('RECONCILIATION_INVALID');
  }
  if (review !== null) {
    closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'reviewedAt']);
    if (review.version !== 2 || review.action !== 'accept-exact-arm-reconciliation' || review.proposalSha256 !== digest(json(proposal)) ||
        review.sourceSha256 !== sourceSha256 || canonicalInstant(review.reviewedAt) < canonicalInstant(proposal.checkedAt) ||
        canonicalInstant(review.reviewedAt) > Date.now()) fail('RECONCILIATION_REVIEW_INVALID');
  }
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
function columnsWithDisplayMetadata(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length && actual.every((column, i) =>
    column && column.name === expected[i].name && column.type === expected[i].type &&
    Object.keys(column).every(k => ['name', 'type', 'isDefaultDisplay', 'isHidden'].includes(k)) &&
    ['isDefaultDisplay', 'isHidden'].every(k => !Object.hasOwn(column, k) || typeof column[k] === 'boolean'));
}
export function verifyResource(c, phase, descriptor, actual, context = {}) {
  const r = ids(c), expected = descriptor.expected, p = actual?.properties;
  if (!sameId(actual?.id, descriptor.id)) fail('RESOURCE_ID_MISMATCH');
  if (actual.type !== undefined && !sameId(actual.type, expected.type)) fail('RESOURCE_TYPE_CHANGED');
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
        (p.archiveRetentionInDays !== undefined && p.archiveRetentionInDays !== 0) ||
        p.schema?.name !== expected.properties.schema.name ||
        !columnsWithDisplayMetadata(p.schema?.columns, expected.properties.schema.columns) ||
        Object.keys(p.schema).some(k => !['name', 'columns', 'standardColumns', 'tableType', 'tableSubType', 'solutions', 'isTroubleshootingAllowed'].includes(k)) ||
        (p.schema.tableType !== undefined && p.schema.tableType !== 'CustomLog') ||
        (p.schema.tableSubType !== undefined && p.schema.tableSubType !== 'DataCollectionRuleBased') ||
        (p.schema.solutions !== undefined && !isDeepStrictEqual(p.schema.solutions, ['LogManagement'])) ||
        (p.schema.isTroubleshootingAllowed !== undefined && typeof p.schema.isTroubleshootingAllowed !== 'boolean') ||
        (p.schema.standardColumns !== undefined && !columnsWithDisplayMetadata(p.schema.standardColumns, [{ name: 'TenantId', type: 'guid' }]))) fail('TABLE_RETENTION_SCHEMA_DRIFT');
  } else if (expected.type === 'Microsoft.Insights/dataCollectionRules') {
    const workspace = context.workspace;
    if (!sameId(workspace?.id, r.workspace) || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(workspace?.properties?.customerId ?? '')) fail('DCR_WORKSPACE_READBACK_REQUIRED');
    assertOwned(workspace, r.workspace, c); requireAccess(workspace);
    const destinations = structuredClone(expected.properties.destinations);
    for (const destination of destinations.logAnalytics) destination.workspaceId = workspace.properties.customerId;
    if (actual.kind !== 'Direct' || !isDeepStrictEqual(p.streamDeclarations, expected.properties.streamDeclarations) ||
        !isDeepStrictEqual(p.destinations, destinations) || !isDeepStrictEqual(p.dataFlows, expected.properties.dataFlows) ||
        !/^dcr-[0-9a-f]{32}$/u.test(p.immutableId)) fail('DCR_READBACK_FAILED');
    let endpoint;
    try { endpoint = new URL(p.endpoints?.logsIngestion); } catch { fail('DCR_ENDPOINT_INVALID'); }
    if (endpoint.protocol !== 'https:' || !endpoint.hostname.endsWith('.ingest.monitor.azure.com') ||
        endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.port ||
        !['', '/'].includes(endpoint.pathname)) fail('DCR_ENDPOINT_INVALID');
  } else if (expected.type === 'Microsoft.App/managedEnvironments') {
    if (p.publicNetworkAccess !== 'Enabled' || (p.appLogsConfiguration?.destination ?? '') !== '' ||
        p.appLogsConfiguration?.logAnalyticsConfiguration || p.daprAIInstrumentationKey || p.daprAIConnectionString ||
        p.openTelemetryConfiguration || p.appInsightsConfiguration || p.ingressConfiguration ||
        p.vnetConfiguration !== null || expected.properties.vnetConfiguration ||
        p.infrastructureResourceGroup !== null || p.zoneRedundant !== false ||
        p.customDomainConfiguration?.dnsSuffix || p.customDomainConfiguration?.certificateValue ||
        p.customDomainConfiguration?.certificatePassword || p.customDomainConfiguration?.certificateKeyVaultProperties ||
        !isDeepStrictEqual(p.workloadProfiles?.map(v => ({ name: v.name, workloadProfileType: v.workloadProfileType })), expected.properties.workloadProfiles) ||
        p.workloadProfiles?.some(v => v.minimumCount != null || v.maximumCount != null)) fail('ENVIRONMENT_PRIVACY_DRIFT');
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
