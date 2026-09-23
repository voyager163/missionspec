import { isDeepStrictEqual } from 'node:util';
import { assertOwned, assertBudget, BUDGET, buildPhase, budgetConfiguration, closed, digest, fail, ids, json, LIMITS, PHASES, RECEIVER_COMMAND, requireAccess, sameId, projectBudgetFilter, uploadRoleProperties, assignmentRoleTargets } from './definition.mjs';
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
  if (approval.action === 'direct-arm-assignments' &&
      (!/^[0-9a-f]{64}$/u.test(proof.foundationBaselineSha256 ?? '') || !/^[0-9a-f]{64}$/u.test(proof.roleDefinitionsSha256 ?? '') ||
        proof.baselineSha256 !== digest(json({ foundationBaselineSha256: proof.foundationBaselineSha256, roleDefinitionsSha256: proof.roleDefinitionsSha256 })))) fail('FRESH_ROLE_REVIEW_MISMATCH');
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
  } else if (type === 'microsoft.authorization/roledefinitions') {
    identity.createdAt = p.createdOn ?? null;
    identity.roleGuid = value.name;
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(identity.roleGuid ?? '')) fail('GENERATED_IDENTITY_REQUIRED');
  } else if (type === 'microsoft.authorization/roleassignments') {
    identity.createdAt = p.createdOn ?? null;
    identity.principalId = p.principalId; identity.principalType = p.principalType;
    identity.roleDefinitionId = p.roleDefinitionId?.toLowerCase(); identity.scope = p.scope?.toLowerCase();
  } else if (type === 'microsoft.app/containerapps') {
    identity.fqdn = p.configuration?.ingress?.fqdn;
    identity.customDomainVerificationId = p.customDomainVerificationId ?? null;
    const entries = uniqueBy(Object.entries(value.identity?.userAssignedIdentities ?? {}).map(([id, v]) => ({ id, ...v })), 'id', v => v.toLowerCase());
    identity.userAssignedIdentities = [...entries].sort(([a], [b]) => a.localeCompare(b)).map(([id, v]) => ({ id, clientId: v.clientId, principalId: v.principalId }));
  }
  if (['microsoft.containerregistry/registries', 'microsoft.operationalinsights/workspaces', 'microsoft.app/managedenvironments',
    'microsoft.operationalinsights/workspaces/tables', 'microsoft.insights/datacollectionrules', 'microsoft.authorization/roledefinitions',
    'microsoft.authorization/roleassignments', 'microsoft.app/containerapps'].includes(type) &&
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
export const RECONCILABLE_PHASES = Object.freeze(PHASES.slice(0, 7));
function prerequisiteWorkspace(c, receipts) {
  return receipts['workspace-access']?.resources?.[ids(c).workspace] ?? receipts.core?.resources?.[ids(c).workspace] ?? null;
}
function resourceContext(c, receipts) {
  const r = ids(c);
  return { workspace: prerequisiteWorkspace(c, receipts), identities: {
    [r.ingestIdentity]: receipts.core?.resources?.[r.ingestIdentity],
    [r.pullIdentity]: receipts.core?.resources?.[r.pullIdentity],
  }, publication: receipts.publication };
}
export function verifyImagePublication(c, record) {
  closed(record, ['version', 'receipt', 'release', 'binding', 'journal', 'qualification', 'manifestJson', 'configJson']);
  const { receipt, release, binding, journal, qualification } = record, r = ids(c);
  closed(release, ['version', 'action', 'publicationBindingSha256', 'registry', 'repository', 'tag', 'manifestDigest', 'configDigest',
    'maximumNewImageDigests', 'approvedAt', 'expiresAt', 'runtimeQualification', 'retainedAdvisories',
    'applicationDeploymentAuthorized', 'ingestionAuthorized', 'clientActivationAuthorized', 'repushOrDeletionAuthorized']);
  if (record.version !== 1 || release.version !== 1 || release.action !== 'publish-one-receiver-digest' ||
      release.publicationBindingSha256 !== digest(json(binding)) || release.registry !== `${c.registryName}.azurecr.io` ||
      release.repository !== 'missionspec/telemetry-ingest' || release.manifestDigest !== c.receiverDigest ||
      release.configDigest !== 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204' ||
      release.maximumNewImageDigests !== 1 || receipt?.qualified !== true || receipt.digest !== release.manifestDigest ||
      receipt.configSha256 !== release.configDigest || receipt.configSha256Inputs !== digest(json(c)) ||
      !sameId(receipt.registryId, r.registry) || receipt.recentDigestCount !== 1 ||
      !isDeepStrictEqual(journal.target, binding.target) || journal.bindingSha256 !== release.publicationBindingSha256 ||
      journal.version !== 1 || journal.action !== release.action ||
      journal.releaseSha256 !== digest(json(release)) || journal.publicationReceiptSha256 !== digest(json(receipt)) ||
      journal.outcome !== 'published-readback-qualified' || journal.copyInvocations !== 1 || journal.maximumCopyInvocations !== 1 ||
      journal.copySucceeded !== true || receipt.copyInvocations !== 1 || receipt.copySucceeded !== true ||
      qualification.publicationReceiptSha256 !== digest(json(receipt)) || qualification.copyInvocations !== 1 ||
      qualification.copySucceeded !== true || qualification.credentialDirectoriesRemoved !== true ||
      receipt.publicationReleaseSha256 !== digest(json(release)) || receipt.publicationBindingSha256 !== release.publicationBindingSha256) fail('PUBLICATION_HISTORY_INVALID');
  for (const key of ['registry', 'repository', 'tag', 'manifestDigest', 'configDigest', 'maximumNewImageDigests']) {
    if (release[key] !== binding.target[key]) fail('PUBLICATION_TARGET_CHANGED');
  }
  if (binding.target.subscriptionId !== c.subscriptionId || !sameId(binding.target.registryResourceId, r.registry) ||
      ['applicationDeploymentAuthorized', 'ingestionAuthorized', 'clientActivationAuthorized', 'repushOrDeletionAuthorized'].some(k => release[k] !== false) ||
      ['applicationDeploymentAuthorized', 'ingestionAuthorized', 'clientActivationAuthorized'].some(k => receipt[k] !== false)) fail('PUBLICATION_AUTHORITY_CHANGED');
  const approvedAt = canonicalInstant(release.approvedAt), expiresAt = canonicalInstant(release.expiresAt), intentAt = canonicalInstant(journal.intentAt);
  if (expiresAt <= approvedAt || expiresAt - approvedAt > 3600000 || intentAt < approvedAt || intentAt >= expiresAt ||
      canonicalInstant(receipt.checkedAt) < intentAt || canonicalInstant(qualification.checkedAt) < canonicalInstant(receipt.checkedAt)) fail('PUBLICATION_INTENT_TIME_INVALID');
  if (typeof record.manifestJson !== 'string' || typeof record.configJson !== 'string' ||
      'sha256:' + digest(record.manifestJson) !== receipt.digest || 'sha256:' + digest(record.configJson) !== receipt.configSha256) fail('PUBLICATION_BYTES_CHANGED');
  let manifest, config;
  try { manifest = JSON.parse(record.manifestJson); config = JSON.parse(record.configJson); } catch { fail('PUBLICATION_BYTES_INVALID'); }
  if (!isDeepStrictEqual(manifest, receipt.manifest) || manifest.mediaType !== 'application/vnd.oci.image.manifest.v1+json' ||
      manifest.config?.digest !== receipt.configSha256 || !Array.isArray(manifest.layers) || !manifest.layers.length ||
      config.os !== 'linux' || config.architecture !== 'amd64' || config.config?.User !== '65532:65532' ||
      !isDeepStrictEqual(config.config?.Cmd, RECEIVER_COMMAND) || (config.config?.Entrypoint?.length ?? 0) !== 0 ||
      receipt.configUser !== config.config.User || !isDeepStrictEqual(receipt.command, config.config.Cmd)) fail('PUBLICATION_RUNTIME_CHANGED');
  const graph = receipt.independentlyVerifiedRemoteGraph, blobs = [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size }));
  if (graph?.manifestDigest !== receipt.digest || graph.configDigest !== receipt.configSha256 || graph.platform !== 'linux/amd64' ||
      graph.user !== receipt.configUser || !isDeepStrictEqual(graph.command, receipt.command) || !isDeepStrictEqual(graph.blobs, blobs) ||
      journal.verifiedRemoteBlobCount !== blobs.length || qualification.remoteBlobCount !== blobs.length ||
      receipt.correspondingSource?.boundToVerifiedRemoteLayerBytes !== true ||
      !['archiveSha256', 'manifestSha256'].every(k => /^[0-9a-f]{64}$/u.test(receipt.correspondingSource[k] ?? ''))) fail('PUBLICATION_GRAPH_EVIDENCE_CHANGED');
  const security = receipt.securityQualification;
  if (security?.scanReportSha256 !== binding.currentScan.reportSha256 || security.databaseSha256 !== binding.currentScan.databaseSha256 ||
      security.databaseUpdatedAt !== binding.currentScan.databaseUpdatedAt || security.databaseNextUpdate !== binding.currentScan.databaseNextUpdate ||
      !isDeepStrictEqual(security.counts, binding.currentScan.counts) || security.suppressedFindings !== 0 ||
      security.nativeV8ConditionsRetained !== true || security.patchedOrCompleteNativeCoverageClaimed !== false ||
      security.runtimeQualification !== release.runtimeQualification || !isDeepStrictEqual(security.retainedAdvisories, release.retainedAdvisories) ||
      receipt.nativeV8Clearance !== 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY' ||
      typeof release.runtimeQualification !== 'string' ||
      !['conditional', 'disabled', 'synthetic'].every(word => release.runtimeQualification.toLowerCase().includes(word)) ||
      !Number.isFinite(Date.parse(security.databaseUpdatedAt)) || Date.parse(security.databaseUpdatedAt) > intentAt ||
      !Number.isFinite(Date.parse(security.databaseNextUpdate)) || Date.parse(security.databaseNextUpdate) <= intentAt) fail('PUBLICATION_SECURITY_EVIDENCE_CHANGED');
}
export function verifyPublicationReadback(c, publication, current) {
  closed(current, ['repositories', 'manifests', 'manifest', 'registry']);
  const receipt = publication.receipt, r = ids(c), p = current.registry?.properties;
  if (!isDeepStrictEqual(current.repositories, ['missionspec/telemetry-ingest']) || !Array.isArray(current.manifests) ||
      current.manifests.length !== 1 || current.manifests[0].digest !== receipt.digest ||
      !isDeepStrictEqual(current.manifest, receipt.manifest) || !sameId(current.registry.id, r.registry) ||
      p?.adminUserEnabled !== false || p.anonymousPullEnabled !== false || p.loginServer !== `${c.registryName}.azurecr.io`) fail('PUBLICATION_READBACK_CHANGED');
  assertOwned(current.registry, r.registry, c);
}
export function verifyAssignmentRoleEvidence(c, phase, evidence) {
  closed(evidence, ['checkedAt', 'roles', 'readbacks', 'roleDefinitionsSha256']);
  const targets = assignmentRoleTargets(c);
  if (phase.phase !== 'assignments' || evidence.readbacks?.length !== targets.length) fail('ROLE_DEFINITION_EVIDENCE_INVALID');
  const signatures = targets.map((target, i) => {
    const value = evidence.readbacks[i];
    if (!sameId(value?.scope, target.scope) ||
        phase.resources.filter(v => sameId(v.expected.scope, target.scope) && sameId(v.expected.properties.roleDefinitionId, target.roleDefinitionId)).length !== 1) fail('ROLE_DEFINITION_EVIDENCE_INVALID');
    return roleDefinitionSignature(c, target, value.resource);
  });
  if (!isDeepStrictEqual(evidence.roles, signatures) || evidence.roleDefinitionsSha256 !== digest(json(signatures))) fail('ROLE_DEFINITION_EVIDENCE_INVALID');
  return signatures;
}
function verifyPrerequisites(c, record, priorRecords, imagePublication) {
  const receipts = record.prerequisiteReceipts;
  const publicationRequired = record.phase.phase === 'disabled-app';
  const expectedKeys = [...priorRecords.map(v => v.phase.phase), ...(publicationRequired ? ['publication'] : [])];
  if (!receipts || typeof receipts !== 'object' || Array.isArray(receipts) ||
      digest(json(receipts)) !== record.approval.receiptsSha256 ||
      record.preflight.receiptsSha256 !== record.approval.receiptsSha256 ||
      !isDeepStrictEqual(Object.keys(receipts).sort(), expectedKeys.sort())) fail('PREREQUISITE_RECEIPTS_CHANGED');
  const context = resourceContext(c, receipts);
  for (const [name, receipt] of Object.entries(receipts)) {
    if (name === 'publication') {
      if (!imagePublication || !isDeepStrictEqual(receipt, imagePublication.receipt) ||
          canonicalInstant(receipt.checkedAt) > canonicalInstant(record.journal.intentAt)) fail('PUBLICATION_PREREQUISITE_CHANGED');
      continue;
    }
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
export function verifyExecutionOrigin(c, foundation, record, contract, priorRecords = [], imagePublication = null) {
  closed(record, ['version', 'publication', 'phase', 'approval', 'journal', 'preflight', 'validation', 'whatIf', 'firstReadback', 'originalReceipt', 'prerequisiteReceipts', 'roleDefinitions']);
  closed(record.publication, ['commitSha', 'sourceSha256']);
  closed(record.firstReadback, ['checkedAt', 'deployment', 'resources']);
  closed(record.journal, ['phase', 'phaseSha256', 'intentAt', 'outcome',
    ...(Object.hasOwn(record.journal, 'failureCode') ? ['failureCode'] : []),
    ...(Object.hasOwn(record.journal, 'armCode') ? ['armCode'] : [])]);
  const p = record.phase, r = ids(c);
  if (record.version !== 3 || !RECONCILABLE_PHASES.includes(p?.phase) ||
      !/^[0-9a-f]{40}$/u.test(record.publication.commitSha) || !/^[0-9a-f]{64}$/u.test(record.publication.sourceSha256)) fail('EXECUTION_ORIGIN_INVALID');
  verifyPrerequisites(c, record, priorRecords, imagePublication);
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
  if (p.phase === 'assignments') {
    const roles = verifyAssignmentRoleEvidence(c, p, record.roleDefinitions);
    if (digest(json(roles)) !== record.preflight.roleDefinitionsSha256 ||
        canonicalInstant(record.roleDefinitions.checkedAt) < record.preflight.startedAt ||
        canonicalInstant(record.roleDefinitions.checkedAt) > intentAt) fail('ROLE_DEFINITION_BASELINE_CHANGED');
  } else if (record.roleDefinitions !== null) fail('UNEXPECTED_ROLE_BASELINE');
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
    verifyResource(c, p, descriptor, value, resourceContext(c, record.prerequisiteReceipts));
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
  closed(origins, ['version', 'records', 'imagePublication']);
  if (origins.version !== 3 || !Array.isArray(origins.records) || !origins.records.length ||
      origins.records.length > RECONCILABLE_PHASES.length ||
      origins.records.some((v, i) => v.phase?.phase !== RECONCILABLE_PHASES[i])) fail('EXECUTION_ORIGIN_INVALID');
  if (origins.records.some(v => v.phase.phase === 'disabled-app')) verifyImagePublication(c, origins.imagePublication);
  else if (origins.imagePublication !== null) fail('UNEXPECTED_PUBLICATION_ORIGIN');
  for (const [index, record] of origins.records.entries()) verifyExecutionOrigin(c, foundation, record, contract, origins.records.slice(0, index), origins.imagePublication);
}
export function verifyReconciliation(c, foundation, origins, proposal, sourceSha256, review = null, contract) {
  closed(origins, ['version', 'records', 'imagePublication']);
  closed(proposal, ['version', 'kind', 'sourceSha256', 'configSha256', 'executionOriginsSha256', 'baselineSha256', 'checkedAt', 'results',
    'stateBudget', 'workspace', 'identities', 'imagePublication', 'roleDefinitions', 'inventory', 'managedGroup']);
  verifyExecutionOrigins(c, foundation, origins, contract);
  if (proposal.version !== 3 || proposal.kind !== 'read-only-completed-phases' ||
      !/^[0-9a-f]{64}$/u.test(sourceSha256) || proposal.sourceSha256 !== sourceSha256 || proposal.configSha256 !== digest(json(c)) ||
      proposal.executionOriginsSha256 !== digest(json(origins)) || canonicalInstant(proposal.checkedAt) > Date.now()) fail('RECONCILIATION_INVALID');
  const r = ids(c), expectedResults = origins.records.map(v => v.phase.phase);
  const core = origins.records.find(v => v.phase.phase === 'core'), assignments = origins.records.find(v => v.phase.phase === 'assignments');
  if (expectedResults.includes('disabled-app')) {
    closed(proposal.identities, [r.ingestIdentity, r.pullIdentity]);
    for (const id of [r.ingestIdentity, r.pullIdentity]) {
      if (!isDeepStrictEqual(executionIdentity(proposal.identities[id]), executionIdentity(core.firstReadback.resources[id]))) fail('APP_IDENTITY_READBACK_CHANGED');
    }
    verifyPublicationReadback(c, origins.imagePublication, proposal.imagePublication);
  } else if (proposal.identities !== null || proposal.imagePublication !== null) fail('UNEXPECTED_APP_CONTEXT');
  if (assignments) {
    const roles = verifyAssignmentRoleEvidence(c, assignments.phase, proposal.roleDefinitions);
    if (digest(json(roles)) !== assignments.preflight.roleDefinitionsSha256 ||
        canonicalInstant(proposal.roleDefinitions.checkedAt) > canonicalInstant(proposal.checkedAt)) fail('ASSIGNMENT_ROLE_DEFINITION_DRIFT');
  } else if (proposal.roleDefinitions !== null) fail('UNEXPECTED_ROLE_BASELINE');
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
    const foundationBaseline = record.phase.phase === 'assignments' ? record.preflight.foundationBaselineSha256 : record.preflight.baselineSha256;
    if (proposal.baselineSha256 !== foundationBaseline) fail('POLICY_OR_SECURITY_DRIFT');
    const p = record.phase, result = proposal.results[p.phase];
    closed(result, ['executionOriginSha256', 'deployment', 'resources', 'identityPins', 'diagnostics', 'exports']);
    if (result.executionOriginSha256 !== digest(json(record)) || canonicalInstant(proposal.checkedAt) < canonicalInstant(record.firstReadback.checkedAt) ||
        !isDeepStrictEqual(Object.keys(result.resources).sort(), p.resources.map(v => v.id).sort()) ||
        !isDeepStrictEqual(Object.keys(result.identityPins).sort(), p.resources.map(v => v.id).sort())) fail('RECONCILIATION_INVALID');
    verifyDeploymentIdentity(record.firstReadback.deployment, result.deployment);
    for (const descriptor of p.resources) {
      const value = result.resources[descriptor.id], pin = executionIdentity(value, descriptor.type);
      verifyResource(c, p, descriptor, value, { workspace: proposal.workspace, identities: proposal.identities, publication: origins.imagePublication?.receipt });
      if (!isDeepStrictEqual(pin, executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type)) ||
          !isDeepStrictEqual(pin, result.identityPins[descriptor.id])) fail('RESOURCE_IDENTITY_CHANGED');
      if (descriptor.type !== 'Microsoft.Consumption/budgets') {
        const metadata = proposal.inventory.value.filter(v => sameId(v.id, descriptor.id));
        const creation = origins.records.find(v => v.whatIf.changes.some(change => sameId(change.resourceId, descriptor.id) && change.changeType === 'Create'));
        const created = metadata.length === 1 ? Date.parse(metadata[0].createdTime)
          : metadata.length === 0 && ['Microsoft.OperationalInsights/workspaces/tables', 'Microsoft.Authorization/roleDefinitions', 'Microsoft.Authorization/roleAssignments'].includes(descriptor.type) ? Date.parse(pin.createdAt) : NaN;
        if (!creation || !Number.isFinite(created) || created < canonicalInstant(creation.journal.intentAt) ||
            created > canonicalInstant(proposal.checkedAt)) fail('CREATION_TIME_OUTSIDE_EXECUTION');
      }
    }
    const diagnosticIds = p.resources.filter(v => ['Microsoft.App/managedEnvironments', 'Microsoft.OperationalInsights/workspaces', 'Microsoft.App/containerApps'].includes(v.type)).map(v => v.id);
    if (!isDeepStrictEqual(Object.keys(result.diagnostics).sort(), diagnosticIds.sort()) ||
        Object.values(result.diagnostics).some(v => !Array.isArray(v?.value) || v.nextLink || v.value.length !== 0)) fail('DIAGNOSTIC_ROUTE_DRIFT');
    if (['core', 'workspace-access', 'data', 'assignments', 'disabled-app'].includes(p.phase)) {
      if (!Array.isArray(result.exports?.value) || result.exports.nextLink || result.exports.value.length) fail('WORKSPACE_EXPORT_DRIFT');
    } else if (result.exports !== null) fail('RECONCILIATION_INVALID');
  }
  if (review !== null) {
    closed(review, ['version', 'action', 'proposalSha256', 'sourceSha256', 'reviewedAt']);
    if (review.version !== 3 || review.action !== 'accept-exact-arm-reconciliation' || review.proposalSha256 !== digest(json(proposal)) ||
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
function onlyKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
}
function emptyOptionalArray(value) {
  return value === undefined || value === null || (Array.isArray(value) && value.length === 0);
}
function uniqueBy(values, key, fold = value => value) {
  if (!Array.isArray(values)) fail('APP_PRIVACY_RUNTIME_DRIFT');
  const result = new Map();
  for (const value of values) {
    if (!value || typeof value[key] !== 'string') fail('APP_PRIVACY_RUNTIME_DRIFT');
    const id = fold(value[key]);
    if (result.has(id)) fail('APP_DUPLICATE_IDENTITY_OR_PROBE');
    result.set(id, value);
  }
  return result;
}
function verifyAppIdentities(c, actual, expected, identities) {
  const r = ids(c), wanted = [r.ingestIdentity, r.pullIdentity];
  if (!onlyKeys(actual.identity, ['type', 'userAssignedIdentities']) || actual.identity.type !== 'UserAssigned' ||
      !onlyKeys(actual.identity.userAssignedIdentities, Object.keys(actual.identity.userAssignedIdentities ?? {}))) fail('APP_IDENTITY_DRIFT');
  const entries = uniqueBy(Object.entries(actual.identity.userAssignedIdentities).map(([id, value]) => ({ id, value })), 'id', v => v.toLowerCase());
  if (entries.size !== wanted.length) fail('APP_IDENTITY_DRIFT');
  for (const id of wanted) {
    const assignment = entries.get(id.toLowerCase())?.value, identity = identities?.[id];
    if (!identity || !sameId(identity.id, id)) fail('APP_IDENTITY_READBACK_REQUIRED');
    assertOwned(identity, id, c);
    if (!onlyKeys(assignment, ['clientId', 'principalId']) || Object.keys(assignment).length !== 2 ||
        !['clientId', 'principalId'].every(key => /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(identity.properties?.[key] ?? '') &&
          assignment[key] === identity.properties[key]) || identity.properties.tenantId !== c.tenantId) fail('APP_IDENTITY_DRIFT');
  }
  const settings = uniqueBy(actual.properties.configuration.identitySettings, 'identity', v => v.toLowerCase());
  if (settings.size !== expected.properties.configuration.identitySettings.length) fail('APP_IDENTITY_DRIFT');
  for (const value of expected.properties.configuration.identitySettings) {
    const setting = settings.get(value.identity.toLowerCase());
    if (!onlyKeys(setting, ['identity', 'lifecycle']) || setting.lifecycle !== value.lifecycle) fail('APP_IDENTITY_DRIFT');
  }
}
function verifyApp(c, expected, actual, context) {
  const r = ids(c), p = actual.properties, e = expected.properties, template = p.template, configuration = p.configuration;
  const wanted = e.template.containers[0], container = template?.containers?.[0];
  if (!onlyKeys(p, ['configuration', 'customDomainVerificationId', 'delegatedIdentities', 'environmentId', 'eventStreamEndpoint',
    'latestReadyRevisionName', 'latestRevisionFqdn', 'latestRevisionName', 'managedEnvironmentId', 'outboundIpAddresses',
    'provisioningState', 'runningStatus', 'template', 'workloadProfileName']) ||
      !emptyOptionalArray(p.delegatedIdentities) ||
      !onlyKeys(template, ['containers', 'initContainers', 'revisionSuffix', 'scale', 'serviceBinds', 'terminationGracePeriodSeconds', 'volumes']) ||
      !Array.isArray(template.containers) || template.containers.length !== 1 ||
      !['initContainers', 'volumes', 'serviceBinds'].every(key => emptyOptionalArray(template[key])) ||
      (template.revisionSuffix !== undefined && template.revisionSuffix !== '') ||
      !onlyKeys(container, ['name', 'image', 'resources', 'env', 'probes', 'command', 'args', 'volumeMounts']) ||
      !['command', 'args', 'volumeMounts'].every(key => emptyOptionalArray(container[key])) ||
      container.name !== wanted.name || container.image !== wanted.image ||
      !isDeepStrictEqual(envMap(container.env), envMap(wanted.env))) fail('APP_PRIVACY_RUNTIME_DRIFT');
  if (!onlyKeys(container.resources, ['cpu', 'memory', 'ephemeralStorage']) ||
      container.resources.cpu !== wanted.resources.cpu || container.resources.memory !== wanted.resources.memory ||
      (Object.hasOwn(container.resources, 'ephemeralStorage') &&
        (wanted.resources.cpu !== 0.25 || wanted.resources.memory !== '0.5Gi' || container.resources.ephemeralStorage !== '1Gi'))) fail('APP_RESOURCE_DRIFT');
  const probes = uniqueBy(container.probes, 'type');
  if (probes.size !== wanted.probes.length || wanted.probes.some(v => !isDeepStrictEqual(probes.get(v.type), v))) fail('APP_PROBE_DRIFT');
  if (!onlyKeys(template.scale, ['minReplicas', 'maxReplicas', 'rules', 'cooldownPeriod', 'pollingInterval']) ||
      template.scale.minReplicas !== 1 || template.scale.maxReplicas !== 1 ||
      !isDeepStrictEqual(template.scale.rules, e.template.scale.rules) ||
      (template.scale.cooldownPeriod !== undefined && template.scale.cooldownPeriod !== 300) ||
      (template.scale.pollingInterval !== undefined && template.scale.pollingInterval !== 30) ||
      template.terminationGracePeriodSeconds !== 10 || p.workloadProfileName !== 'Consumption') fail('APP_SCALE_DRIFT');
  if (!onlyKeys(configuration, ['activeRevisionsMode', 'dapr', 'identitySettings', 'ingress', 'maxInactiveRevisions', 'registries', 'runtime', 'secrets', 'service']) ||
      configuration.activeRevisionsMode !== 'Single' || configuration.maxInactiveRevisions !== 3 ||
      ['dapr', 'runtime', 'service'].some(key => configuration[key] !== undefined && configuration[key] !== null) ||
      !emptyOptionalArray(configuration.secrets)) fail('APP_PRIVACY_RUNTIME_DRIFT');
  const ingress = configuration.ingress;
  if (!onlyKeys(ingress, ['additionalPortMappings', 'allowInsecure', 'clientCertificateMode', 'corsPolicy', 'customDomains',
    'exposedPort', 'external', 'fqdn', 'ipSecurityRestrictions', 'stickySessions', 'targetPort', 'traffic', 'transport']) ||
      ingress.allowInsecure !== false || ingress.external !== true || ingress.targetPort !== 8080 || !['http', 'Http'].includes(ingress.transport) ||
      !isDeepStrictEqual(ingress.traffic, e.configuration.ingress.traffic) ||
      (ingress.exposedPort !== undefined && ingress.exposedPort !== 0) ||
      !['additionalPortMappings', 'customDomains', 'ipSecurityRestrictions'].every(key => emptyOptionalArray(ingress[key])) ||
      ['clientCertificateMode', 'corsPolicy', 'stickySessions'].some(key => ingress[key] !== undefined && ingress[key] !== null) ||
      !sameId(p.managedEnvironmentId ?? p.environmentId, r.environment) ||
      (p.managedEnvironmentId !== undefined && !sameId(p.managedEnvironmentId, r.environment)) ||
      (p.environmentId !== undefined && !sameId(p.environmentId, r.environment))) fail('APP_INGRESS_DRIFT');
  if (!Array.isArray(configuration.registries) || configuration.registries.length !== 1) fail('APP_REGISTRY_DRIFT');
  const registry = configuration.registries[0], wantedRegistry = e.configuration.registries[0];
  if (!onlyKeys(registry, ['server', 'identity', 'username', 'passwordSecretRef']) || registry.server !== wantedRegistry.server ||
      !sameId(registry.identity, wantedRegistry.identity) ||
      ['username', 'passwordSecretRef'].some(key => Object.hasOwn(registry, key) && registry[key] !== '')) fail('APP_REGISTRY_DRIFT');
  verifyAppIdentities(c, actual, expected, context.identities);
  const publication = context.publication;
  if (publication?.qualified !== true || publication.digest !== c.receiverDigest || !sameId(publication.registryId, r.registry) ||
      publication.configSha256Inputs !== digest(json(c)) || publication.recentDigestCount !== 1 ||
      publication.configSha256 !== 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204' ||
      publication.configUser !== '65532:65532' || !isDeepStrictEqual(publication.command, RECEIVER_COMMAND)) fail('APP_PUBLICATION_READBACK_REQUIRED');
  if (typeof ingress.fqdn !== 'string' || !/^[a-z0-9.-]+\.azurecontainerapps\.io$/u.test(ingress.fqdn)) fail('APP_FQDN_INVALID');
}
export function roleDefinitionSignature(c, target, actual) {
  const p = actual?.properties;
  if (!sameId(actual?.id, target.roleDefinitionId) || !sameId(actual?.type, 'Microsoft.Authorization/roleDefinitions') ||
      !sameId(actual?.name, target.roleDefinitionId.split('/').at(-1)) ||
      p?.type !== target.roleType || p.roleName !== target.roleName || !Array.isArray(p.permissions) || !p.permissions.length ||
      typeof p.createdOn !== 'string' || !Number.isFinite(Date.parse(p.createdOn)) ||
      !Array.isArray(p.assignableScopes) || !p.assignableScopes.length || p.assignableScopes.some(v => typeof v !== 'string' || !v)) fail('ASSIGNMENT_ROLE_IDENTITY_MISMATCH');
  if (target.roleType === 'CustomRole') {
    const expected = uploadRoleProperties(c);
    if (!isDeepStrictEqual(p.permissions, expected.permissions) || !isDeepStrictEqual(p.assignableScopes, expected.assignableScopes)) fail('UPLOAD_ROLE_SCOPE_DRIFT');
  }
  if (!p.assignableScopes.some(scope => scope === '/' || sameId(scope, target.scope) ||
      target.scope.toLowerCase().startsWith(scope.toLowerCase() + '/'))) fail('ASSIGNMENT_ROLE_SCOPE_MISMATCH');
  const permissions = p.permissions.map(value => {
    closed(value, ['actions', 'notActions', 'dataActions', 'notDataActions']);
    return Object.fromEntries(['actions', 'notActions', 'dataActions', 'notDataActions'].map(key => {
      if (!Array.isArray(value[key]) || value[key].some(v => typeof v !== 'string')) fail('ASSIGNMENT_ROLE_PERMISSIONS_INVALID');
      return [key, value[key]];
    }));
  });
  return { scope: target.scope, roleDefinitionId: target.roleDefinitionId, roleName: p.roleName,
    roleType: p.type, createdAt: p.createdOn, permissions, assignableScopes: p.assignableScopes };
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
    if (p.type !== 'CustomRole' || p.roleName !== expected.properties.roleName || !isDeepStrictEqual(p.permissions, expected.properties.permissions) ||
        !isDeepStrictEqual(p.assignableScopes, [r.group])) fail('UPLOAD_ROLE_SCOPE_DRIFT');
  } else if (expected.type === 'Microsoft.Authorization/roleAssignments') {
    if (!sameId(p.scope, expected.scope) || p.principalId !== expected.properties.principalId ||
        p.principalType !== expected.properties.principalType || !sameId(p.roleDefinitionId, expected.properties.roleDefinitionId) ||
        p.condition || p.conditionVersion || p.delegatedManagedIdentityResourceId) fail('ROLE_ASSIGNMENT_DRIFT');
  } else if (expected.type === 'Microsoft.App/containerApps') {
    verifyApp(c, expected, actual, context);
  } else fail('UNSUPPORTED_RESOURCE_READBACK');
  return actual;
}
export function sourceContractsSummary(contract) {
  return { schema: contract.schemaSha256, columns: contract.columnsSha256, limits: LIMITS,
    tableRetention: { plan: 'Analytics', analyticsDays: 180, totalDays: 180, extraArchive: false },
    noLoginKeys: true, noClientActivation: true, initialImageCount: 1 };
}
