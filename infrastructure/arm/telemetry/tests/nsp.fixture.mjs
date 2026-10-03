import { digest, json, ownerTags } from '../definition.mjs';
import { analyzeEffectivePolicies } from '../effective-policy.mjs';
import { emptyPolicySnapshot } from './effective-policy.fixture.mjs';
import { NSP_AUTHORITY, NSP_API, nspTopology, emptyNspEvidence, buildNspPhase, nspDescriptors,
  nspLineageHead, nspPermissionTargets, nspPreflightBaseline, nspUncertaintyCost, verifyNspEvidence, verifyNspApiCatalog } from '../nsp.mjs';
import { NspController } from '../nsp-controller.mjs';

// Generated unit inputs only. No live price, operator approval or cloud effect is represented.
const hash = value => digest(json(value));
export function nspBillingFixture(f, network, at = f.at) {
  const acknowledgment = { action: 'accept-375-planning-and-disclosed-nsp-price-uncertainty',
    userInstruction: 'UNIT acknowledgment: no real user or billing authority.',
    recordedAt: new Date(at - 1000).toISOString() };
  acknowledgment.userInstructionSha256 = digest(acknowledgment.userInstruction);
  const response = { code: 'UNIT price-sheet denial' };
  const evidence = { version: 1, kind: 'disclosed-nsp-price-uncertainty', subscriptionId: f.c.subscriptionId,
    tenantId: f.c.tenantId, priceSheet: { httpStatus: 401, response, responseSha256: hash(response) },
    retailQueries: ['productName', 'serviceName'].map(key => {
      const response = { Items: [], Count: 0, NextPageLink: null };
      return { url: `https://prices.azure.com/api/retail/prices?$filter=${key}%20eq%20%27UNIT%20NSP%27`,
        retrievedAt: new Date(at - 1000).toISOString(), response, responseSha256: hash(response) };
    }), acknowledgment };
  const review = { version: 2, action: 'accept-exact-nsp-price-uncertainty',
    configSha256: hash(f.c), topologySha256: hash(network), sourceSha256: f.source, evidenceSha256: hash(evidence),
    acknowledgmentSha256: hash(acknowledgment), location: 'australiaeast', cost: nspUncertaintyCost(), budgets: f.c.budget,
    approvedAt: new Date(at - 1000).toISOString(), expiresAt: new Date(at + 1800000).toISOString() };
  return { evidence, review };
}
export function nspObservationFixture(f, adoption, network, stage = 'adopted-disabled', prior = null) {
  const n = network.ids;
  const observation = prior ? structuredClone(prior) : {
    version: 1, kind: 'observed-nsp-control-plane', startedAt: f.at, completedAt: f.at,
    resources: { ...structuredClone(adoption.observation.resources),
      [n.perimeter]: null, [n.profile]: null, [n.association]: null, [n.rule]: null },
    profiles: { value: [] }, associations: { value: [] }, rules: { value: [] }, links: { value: [] },
    linkReferences: { value: [] }, configurations: { value: [] }, configuration: null,
    privateEndpoints: { value: [] }, queues: { value: [structuredClone(adoption.observation.resources[n.queue])] },
    diagnostics: Object.fromEntries([n.perimeter, n.account, n.service].map(id => [id, { value: [] }])),
  };
  const actual = descriptor => {
    const { apiVersion, dependsOn, ...value } = structuredClone(descriptor.expected);
    return { ...value, id: descriptor.id, name: descriptor.id.split('/').at(-1),
      systemData: { createdAt: new Date(observation.startedAt).toISOString() } };
  };
  const descriptors = nspDescriptors(f.c, network), resources = observation.resources;
  if (stage !== 'adopted-disabled' && !resources[n.perimeter]) {
    resources[n.perimeter] = { ...actual(descriptors.perimeter), tags: ownerTags(f.c),
      properties: { perimeterGuid: '00000000-0000-4000-8000-000000000090', provisioningState: 'Succeeded' } };
    resources[n.profile] = { ...actual(descriptors.profile), properties: { accessRulesVersion: '0', diagnosticSettingsVersion: '0' } };
  }
  if (!['adopted-disabled', 'empty-boundary'].includes(stage)) resources[n.account].properties.publicNetworkAccess = 'SecuredByPerimeter';
  const associated = !['adopted-disabled', 'empty-boundary', 'locked-unassociated'].includes(stage);
  if (associated) {
    resources[n.association] ??= { ...actual(descriptors.association),
      properties: { ...descriptors.association.expected.properties, provisioningState: 'Succeeded', hasProvisioningIssues: 'no' } };
    const admitted = ['subscription-admission-converged', 'subscription-readmission-converged'].includes(stage);
    const hadRule = resources[n.rule] !== null;
    if (hadRule !== admitted) resources[n.profile].properties.accessRulesVersion =
      String(Number(resources[n.profile].properties.accessRulesVersion) + 1);
    resources[n.rule] = admitted ? { ...actual(descriptors.rule),
      properties: { ...descriptors.rule.expected.properties, provisioningState: 'Succeeded' } } : null;
    const name = `${resources[n.perimeter].properties.perimeterGuid}.queue-storage-v1`;
    observation.configuration = { id: `${n.account}/networkSecurityPerimeterConfigurations/${name}`, name,
      type: 'Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations', properties: {
        provisioningState: 'Succeeded', provisioningIssues: [],
        networkSecurityPerimeter: { id: n.perimeter, perimeterGuid: resources[n.perimeter].properties.perimeterGuid, location: 'Australia East' },
        resourceAssociation: { name: 'queue-storage-v1', accessMode: 'Enforced' },
        profile: { name: 'queue-storage-v1', accessRulesVersion: Number(resources[n.profile].properties.accessRulesVersion),
          diagnosticSettingsVersion: 0, accessRules: admitted ? [{ name: 'same-subscription-v1',
            properties: descriptors.rule.expected.properties }] : [], enabledLogCategories: [] },
      } };
    observation.configurations = { value: [structuredClone(observation.configuration)] };
  }
  for (const [key, id] of [['profiles', n.profile], ['associations', n.association], ['rules', n.rule]]) {
    observation[key] = { value: resources[id] ? [structuredClone(resources[id])] : [] };
  }
  return observation;
}
export function nspPhaseFixture(f, adoption, evidence, name, instance = null) {
  const phase = buildNspPhase(f.c, name, f.topology, adoption, evidence, instance);
  const at = f.at + (evidence.records.length + 1) * 1000;
  const observation = nspObservationFixture(f, adoption, evidence.topology, phase.beforeStage,
    evidence.records.at(-1)?.receipt.observation);
  observation.startedAt = at; observation.completedAt = at;
  const after = nspObservationFixture(f, adoption, evidence.topology, phase.afterStage, observation);
  after.startedAt = at; after.completedAt = at;
  const billing = nspBillingFixture(f, evidence.topology, at);
  const topologyReview = { version: 1, action: 'accept-exact-enforced-nsp-topology',
    configSha256: hash(f.c), topologySha256: hash(evidence.topology), sourceSha256: f.source,
    approvedAt: new Date(at - 1000).toISOString(), expiresAt: new Date(at + 1800000).toISOString(), authority: NSP_AUTHORITY };
  const permissions = {};
  for (const { scope, action } of nspPermissionTargets(f.c, phase, evidence.topology)) {
    permissions[scope] ??= { permissions: { value: [{ actions: [], notActions: [] }] }, denies: { value: [] } };
    permissions[scope].permissions.value[0].actions.push(action);
  }
  const policy = analyzeEffectivePolicies(phase, emptyPolicySnapshot(phase));
  const preview = phase.template ? { status: 'Succeeded', changes: phase.resources.map(d => ({
    resourceId: d.id, changeType: 'Create', after: { ...structuredClone(d.expected), id: d.id },
  })) } : { version: 1, kind: 'fixed-nsp-direct-request-preview',
    request: phase.request, preimageSha256: hash(observation.resources[phase.request.id]), nativeArmWhatIf: false };
  const validation = phase.template ? { properties: { provisioningState: 'Succeeded', templateHash: hash(phase.template) } } : null;
  // Synthetic reproduction of the observed catalog structure, not a cloud catalog.
  const providerCatalog = { namespace: 'Microsoft.Network', registrationState: 'Registered',
    resourceTypes: [{ resourceType: 'networkSecurityPerimeters', apiVersions: [NSP_API], locations: ['Australia East'] }] };
  const proof = { startedAt: at, completedAt: at, qualified: true,
    configSha256: hash(f.c), phaseSha256: hash(phase), sourceSha256: f.source, originSha256: f.c.originSha256,
    receiptsSha256: hash(evidence), adoptionSha256: hash(adoption), foundationBaselineSha256: digest('UNIT foundation'),
    foundationBinding: { executionOriginsSha256: digest('UNIT execution origins'), reconciliationSha256: digest('UNIT reconciliation'),
      receiverRecordSha256: digest('UNIT receiver record'), receiverManifestDigest: 'sha256:' + digest('UNIT manifest'),
      receiverConfigDigest: 'sha256:' + digest('UNIT config') },
    providerCatalog, providerCatalogReview: verifyNspApiCatalog(providerCatalog),
    topologyReview, networkBillingReview: billing.review, networkBillingEvidence: billing.evidence,
    permissions, observation, request: phase.request, networkLineageHead: nspLineageHead(evidence), preservedIds: [],
    effectivePolicyVersion: 1, effectivePolicySha256: hash(policy), effectivePolicy: policy,
    whatIfSha256: hash(preview), validationSha256: hash(validation) };
  proof.baselineSha256 = nspPreflightBaseline(proof);
  const approval = { action: `direct-arm-${name}`,
    ...Object.fromEntries(['configSha256', 'phaseSha256', 'sourceSha256', 'originSha256', 'receiptsSha256', 'baselineSha256', 'whatIfSha256'].map(key => [key, proof[key]])),
    approvedAt: topologyReview.approvedAt, expiresAt: topologyReview.expiresAt };
  let now = at, journal = null, receipt = null, writes = 0, reservations = 0;
  const deployment = phase.deploymentId ? { id: phase.deploymentId, properties: { mode: 'Incremental',
    provisioningState: 'Succeeded', correlationId: 'UNIT correlation', templateHash: hash(phase.template), timestamp: new Date(at).toISOString() } } : null;
  const io = { now: () => now, sourceDigest: async () => f.source, sleep: async ms => { now += ms; },
    loadJournal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
    saveReceipt: async value => { receipt = structuredClone(value); },
    check: async () => proof, verifyCurrent: async () => {},
    reserve: async () => { if (reservations++) throw new Error('NSP_INTENT_REPLAY_FORBIDDEN'); },
    write: async (_request, guard, current, deadline) => { await current(deadline); guard(); writes++; },
    observe: async () => ({ deployment, observation: after }) };
  const controller = new NspController(f.c, phase, f.topology, adoption, evidence, io);
  return { phase, proof, approval, preview, validation, after, io, controller, advance: ms => { now += ms; },
    get writes() { return writes; },
    record: () => ({ version: 1, kind: 'reviewed-nsp-phase', phase,
      publication: { commitSha: 'e'.repeat(40), sourceSha256: f.source }, approval,
      preflight: proof, preview, validation, journal, receipt }) };
}
export async function nspAdmissionFixture(f, adoption) {
  const evidence = emptyNspEvidence(nspTopology(f.c, f.topology, adoption));
  for (const name of ['nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association', 'nsp-subscription-admission']) {
    const fixture = nspPhaseFixture(f, adoption, evidence, name);
    await fixture.controller.execute(fixture.approval);
    evidence.records.push(fixture.record());
    verifyNspEvidence(f.c, evidence, f.topology, adoption);
  }
  return evidence;
}
