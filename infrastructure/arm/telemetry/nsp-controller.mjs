import { isDeepStrictEqual, types } from 'node:util';
import { digest, json, closed, fail, sameId, ids } from './definition.mjs';
import { canonicalInstant, verifyApproval } from './policy.mjs';
import { collectEffectivePolicies } from './effective-policy.mjs';
import { NSP_API, NSP_STORAGE_API, NSP_DIAGNOSTIC_API, NSP_LIMITS, NSP_AUTHORITY,
  buildNspPhase, verifyNspEvidence, verifyNspPreflight, verifyNspTransition, verifyNspObservation,
  verifyNspPreview, verifyNspPermissions, nspPermissionTargets, nspLineageHead, nspPreflightBaseline,
  nspState, nspConfigurationId, verifyNspApiCatalog } from './nsp.mjs';
import { verifyNspTopology } from './nsp.mjs';
import { collectQueueDefender } from './queue-defender.mjs';

const hash = value => digest(json(value));
const equal = (a, b, code) => { if (!isDeepStrictEqual(a, b)) fail(code); };
const armOrigin = 'https://management.azure.com';
function requestUrl(request) {
  closed(request, ['id', 'apiVersion', 'filter']);
  if (typeof request.id !== 'string' || !request.id.startsWith('/') || /[?#\\%]|\.\./u.test(request.id) ||
      !/^\d{4}-\d{2}-\d{2}(?:-preview)?$/u.test(request.apiVersion) ||
      (request.filter !== null && (typeof request.filter !== 'string' || !/^\$(?:filter|expand)=/u.test(request.filter)))) fail('NSP_READ_REQUEST_INVALID');
  return `${armOrigin}${request.id}?api-version=${request.apiVersion}${request.filter ? '&' + request.filter : ''}`;
}
export function nspNextPage(initial, value) {
  if (typeof value !== 'string' || value.length > 8192) fail('NSP_PAGINATION_SCOPE_CHANGED');
  const first = new URL(initial), next = new URL(value);
  if (next.origin !== armOrigin || next.origin !== first.origin || next.username || next.password || next.hash ||
      next.pathname !== first.pathname || /%|\\|\.\./u.test(next.pathname) ||
      next.searchParams.getAll('api-version').length !== 1 ||
      next.searchParams.get('api-version') !== first.searchParams.get('api-version')) fail('NSP_PAGINATION_SCOPE_CHANGED');
  for (const [key, entry] of next.searchParams) {
    if (next.searchParams.getAll(key).length !== 1 ||
        (key !== '$skiptoken' && key !== '$skipToken' && first.searchParams.get(key) !== entry)) fail('NSP_PAGINATION_SCOPE_CHANGED');
  }
  for (const [key, entry] of first.searchParams) if (next.searchParams.get(key) !== entry) fail('NSP_PAGINATION_SCOPE_CHANGED');
  if ([...next.searchParams.keys()].filter(key => ['$skiptoken', '$skipToken'].includes(key)).length !== 1) fail('NSP_PAGINATION_SCOPE_CHANGED');
  return next.href;
}

// This port has one precomputed write capability. It is not a general ARM executor.
export function nspTransport(c, phase, io) {
  const subscription = ids(c).sub;
  const read = async (request, deadline, paginated = false) => {
    const initial = requestUrl(request);
    const networkPrefix = `${ids(c).group}/providers/Microsoft.Network/networkSecurityPerimeters/${c.namePrefix}-queue-`;
    const emptyTerminalLink = request.apiVersion === NSP_API && request.filter === null &&
      request.id.startsWith(networkPrefix) &&
      /^[a-z0-9]{8,16}\/(?:profiles|resourceAssociations|links|linkReferences|profiles\/queue-storage-v1\/accessRules)$/u
        .test(request.id.slice(networkPrefix.length));
    if (!request.id.toLowerCase().startsWith(subscription.toLowerCase() + '/') && !sameId(request.id, subscription) &&
        !io.policyReadAllowed?.(request)) fail('NSP_READ_SCOPE_FORBIDDEN');
    if (/(?:listkeys|listsecrets|listaccountsas|listservicesas|regeneratekey|register)(?:\/|$)/iu.test(request.id)) fail('NSP_READ_SCOPE_FORBIDDEN');
    let url = initial, bytes = 0, invocations = 0, lastRequestedUrl = null, omittedPage = null, result, complete = false;
    const seen = new Set(), seenIds = new Set(), pages = [], values = [];
    try {
      for (let index = 0; index < NSP_LIMITS.pages; index++) {
        if (seen.has(url)) fail('NSP_PAGINATION_LOOP');
        seen.add(url);
        const remaining = deadline - io.now();
        if (remaining <= 0) fail('NSP_READ_DEADLINE');
        lastRequestedUrl = url; invocations++;
        const response = await io.invoke(['rest', '--method', 'GET', '--url', url, '--subscription', c.subscriptionId,
          '--only-show-errors', '--output', 'json'], Math.min(NSP_LIMITS.commandMs, remaining), deadline);
        const page = { url, response }, pageBytes = Buffer.byteLength(json(page));
        const items = Array.isArray(response?.value) ? response.value.length : 0;
        if (bytes + pageBytes > NSP_LIMITS.bytes || (paginated && values.length + items > NSP_LIMITS.items)) {
          omittedPage = { sha256: hash(page), bytes: pageBytes, items };
          fail('NSP_READ_LIMIT');
        }
        bytes += pageBytes; pages.push(page);
        if (io.now() >= deadline) fail('NSP_READ_DEADLINE');
        if (!paginated) {
          if (response?.nextLink) fail('NSP_LIST_INCOMPLETE');
          result = response; complete = true; break;
        }
        if (!response || response.error || !Array.isArray(response.value)) fail('NSP_LIST_INCOMPLETE');
        if (response.nextLink !== undefined && response.nextLink !== null &&
            (typeof response.nextLink !== 'string' || (!response.nextLink && !emptyTerminalLink))) fail('NSP_LIST_INCOMPLETE');
        for (const value of response.value) {
          const key = value?.id?.toLowerCase();
          if (key && seenIds.has(key)) fail('NSP_PAGINATION_DUPLICATE');
          if (key) seenIds.add(key);
          values.push(value);
        }
        if (!response.nextLink) {
          result = { value: values }; complete = true; break;
        }
        url = nspNextPage(initial, response.nextLink);
      }
      if (!complete) fail('NSP_PAGINATION_LIMIT');
    } catch (error) {
      const failure = io.describeFailure ? io.describeFailure(error) : {
        code: typeof error?.message === 'string' && /^[A-Z_]+$/u.test(error.message) ? error.message : 'NSP_READ_FAILED',
      };
      await io.retainRead(request, pages, { version: 1, complete: false, bytes, invocations,
        lastRequestedUrlSha256: lastRequestedUrl === null ? null : hash(lastRequestedUrl), omittedPage, failure });
      throw error;
    }
    await io.retainRead(request, pages, { version: 1, complete: true, bytes, invocations });
    return result;
  };
  const write = async (request, guard, current, deadline) => {
    const binding = io.binding;
    if (!phase || !binding) fail('NSP_FIXED_REQUEST_REQUIRED');
    equal(phase, buildNspPhase(c, phase.phase, binding.topology, binding.adoption, binding.evidence, phase.instance), 'NSP_FIXED_REQUEST_REQUIRED');
    equal(request, phase.request, 'NSP_FIXED_REQUEST_REQUIRED');
    if (typeof guard !== 'function' || types.isAsyncFunction(guard) || typeof current !== 'function') fail('NSP_DISPATCH_GUARD_REQUIRED');
    const { method, id, apiVersion, body } = request;
    if (!['PUT', 'PATCH', 'DELETE'].includes(method) || !id.startsWith(subscription + '/') ||
        /[?#\\%]|\.\./u.test(id)) fail('NSP_FIXED_REQUEST_REQUIRED');
    const args = ['rest', '--method', method, '--url', `${armOrigin}${id}?api-version=${apiVersion}`,
      '--subscription', c.subscriptionId, '--only-show-errors', '--output', 'json'];
    const prepared = body === null ? null : await io.prepareBody(body);
    try {
      if (prepared) args.push('--body', '@' + prepared.path, '--headers', 'Content-Type=application/json');
      await current(deadline);
      const remaining = deadline - io.now();
      if (remaining <= 0) fail('NSP_OPERATION_DEADLINE');
      if (guard() !== undefined) fail('NSP_DISPATCH_GUARD_REQUIRED');
      const response = await io.invoke(args, Math.min(NSP_LIMITS.commandMs, remaining), deadline);
      if (response?.error || response?.properties?.error) fail('NSP_WRITE_RESPONSE_ERROR');
      return response;
    } finally { if (prepared) await io.removeBody(prepared); }
  };
  return { read, write };
}

export function nspReadRequests(network) {
  const n = network.ids;
  const item = (id, apiVersion) => ({ id, apiVersion, filter: null });
  return {
    resources: Object.fromEntries(Object.values(n).map(id => [id, item(id,
      [n.account, n.service, n.queue].includes(id) ? NSP_STORAGE_API : NSP_API)])),
    profiles: item(`${n.perimeter}/profiles`, NSP_API), associations: item(`${n.perimeter}/resourceAssociations`, NSP_API),
    rules: item(`${n.profile}/accessRules`, NSP_API), links: item(`${n.perimeter}/links`, NSP_API),
    linkReferences: item(`${n.perimeter}/linkReferences`, NSP_API),
    configurations: item(`${n.account}/networkSecurityPerimeterConfigurations`, NSP_STORAGE_API),
    privateEndpoints: item(`${n.account}/privateEndpointConnections`, NSP_STORAGE_API),
    queues: item(`${n.service}/queues`, NSP_STORAGE_API),
    diagnostics: Object.fromEntries([n.perimeter, n.account, n.service].map(id => [id,
      item(`${id}/providers/Microsoft.Insights/diagnosticSettings`, NSP_DIAGNOSTIC_API)])),
  };
}
export async function collectNspObservation(network, io, deadline, context = null) {
  const defender = network.version === 2;
  if (defender) {
    closed(context, ['c', 'adoption']);
    verifyNspTopology(context.c, network, context.adoption.topology, context.adoption);
    if (context.adoption.version !== 3) fail('QUEUE_DEFENDER_NSP_CONTEXT_REQUIRED');
  } else if (network.version !== 1 || context?.adoption.version === 3) fail('QUEUE_DEFENDER_NSP_CONTEXT_REQUIRED');
  const startedAt = io.now(), requests = nspReadRequests(network);
  const resources = Object.fromEntries(await io.batch(Object.entries(requests.resources),
    async ([id, request]) => [id, await io.read(request, deadline)]));
  const observation = { version: defender ? 2 : 1, kind: 'observed-nsp-control-plane', startedAt, completedAt: null, resources };
  const absentPerimeter = resources[network.ids.perimeter] === null, absentProfile = resources[network.ids.profile] === null;
  const absent = new Set(absentPerimeter ? ['profiles', 'associations', 'links', 'linkReferences', 'rules'] : absentProfile ? ['rules'] : []);
  Object.assign(observation, Object.fromEntries(await io.batch([
    'profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues',
  ], async key => [key, absent.has(key) ? { value: [] } : await io.read(requests[key], deadline, true)])));
  observation.diagnostics = Object.fromEntries(await io.batch(Object.entries(requests.diagnostics), async ([id, request]) =>
    [id, absentPerimeter && id === network.ids.perimeter ? { value: [] } : await io.read(request, deadline, true)]));
  const configs = observation.configurations.value;
  if (configs.length > 1) fail('NSP_EFFECTIVE_CONFIGURATION_UNVERIFIED');
  observation.configuration = null;
  if (configs.length) {
    const id = nspConfigurationId(network, configs[0]?.id);
    observation.configuration = await io.read({ id, apiVersion: NSP_STORAGE_API, filter: null }, deadline);
  }
  if (defender) observation.defender = await collectQueueDefender(context.c, context.adoption.origin,
    context.adoption.proposal.defender, io, deadline);
  observation.completedAt = io.now();
  if (observation.completedAt >= deadline) fail('NSP_READ_DEADLINE');
  return observation;
}
export async function collectNspPermissions(c, phase, network, io, deadline) {
  const scopes = [...new Set(nspPermissionTargets(c, phase, network).map(value => value.scope))];
  const evidence = Object.fromEntries(await io.batch(scopes, async scope => {
    const [permissions, denies] = await io.batch(['permissions', 'denyAssignments'], name =>
      io.read({ id: `${scope}/providers/Microsoft.Authorization/${name}`, apiVersion: '2022-04-01', filter: null }, deadline, true));
    return [scope, { permissions, denies }];
  }));
  verifyNspPermissions(c, phase, network, evidence);
  return evidence;
}
export async function collectNspEffectivePolicies(phase, io, deadline) {
  const evidence = await collectEffectivePolicies(phase, async (id, apiVersion, filter) => {
    const request = { id, apiVersion, filter: filter ?? null };
    io.allowPolicyRead(request);
    return io.read(request, deadline, /\/(?:policyAssignments|policyExemptions|versions)$/iu.test(id));
  }, io.batch, snapshot => io.retainPolicy(snapshot));
  if (!evidence.qualified) fail('NSP_EFFECTIVE_POLICY_CONFLICT');
  return evidence;
}
export async function checkNspReadOnly(c, phase, topology, adoption, evidence, io) {
  const startedAt = io.now(), deadline = startedAt + NSP_LIMITS.stageMs, source = await io.sourceDigest();
  verifyNspEvidence(c, evidence, topology, adoption);
  equal(phase, buildNspPhase(c, phase.phase, topology, adoption, evidence, phase.instance), 'NSP_PHASE_CHANGED');
  const [foundation, observation, permissions, networkLineageHead, effectivePolicy] = await io.batch([
    () => io.foundation(deadline),
    () => collectNspObservation(evidence.topology, io, deadline, { c, adoption }),
    () => collectNspPermissions(c, phase, evidence.topology, io, deadline),
    () => io.readHead(evidence),
    () => collectNspEffectivePolicies(phase, io, deadline),
  ], read => read());
  verifyNspObservation(c, evidence.topology, adoption, observation, phase.beforeStage);
  const preview = phase.request.method === 'PUT' ? await io.preview(deadline) : {
    validation: null, preview: { version: 1, kind: 'fixed-nsp-direct-request-preview',
      request: phase.request, preimageSha256: hash(observation.resources[phase.request.id]), nativeArmWhatIf: false },
  };
  const proof = { startedAt, completedAt: io.now(), qualified: true,
    configSha256: hash(c), phaseSha256: hash(phase), sourceSha256: source, originSha256: c.originSha256,
    receiptsSha256: hash(evidence), adoptionSha256: hash(adoption), foundationBaselineSha256: foundation.baselineSha256,
    foundationBinding: foundation.binding,
    providerCatalog: foundation.providerCatalog, providerCatalogReview: verifyNspApiCatalog(foundation.providerCatalog),
    topologyReview: io.topologyReview, networkBillingReview: io.billingReview, networkBillingEvidence: io.billingEvidence,
    observation, permissions, networkLineageHead, request: phase.request, preservedIds: foundation.known,
    effectivePolicyVersion: 1, effectivePolicySha256: hash(effectivePolicy), effectivePolicy,
    validationSha256: hash(preview.validation), whatIfSha256: verifyNspPreview(phase, preview.preview, foundation.known) };
  proof.baselineSha256 = nspPreflightBaseline(proof);
  if (await io.sourceDigest() !== source || io.now() >= deadline) fail('NSP_PREFLIGHT_EXPIRED');
  verifyNspPreflight(c, phase, topology, adoption, evidence, proof, io.now());
  await io.saveCheck(proof, preview);
  return proof;
}
function pendingPropagation(phase, network, before, after, error) {
  if (isDeepStrictEqual(nspState(after), nspState(before))) return true;
  if (error.message === 'NSP_EFFECTIVE_CONFIGURATION_UNVERIFIED' && phase.phase === 'nsp-enforced-association' &&
      after.configuration === null && after.configurations?.value?.length === 0) return true;
  if (!['NSP_PROPAGATION_UNVERIFIED', 'NSP_EFFECTIVE_RULE_DRIFT'].includes(error.message)) return false;
  const p = after.configuration?.properties, profile = after.resources[network.ids.profile]?.properties;
  const previous = before.configuration?.properties?.profile;
  if (!p || !profile || !['Accepted', 'Succeeded'].includes(p.provisioningState) ||
      !isDeepStrictEqual(p.provisioningIssues, []) ||
      !sameId(p.networkSecurityPerimeter?.id, network.ids.perimeter) ||
      p.networkSecurityPerimeter?.perimeterGuid !== after.resources[network.ids.perimeter]?.properties?.perimeterGuid ||
      !['australiaeast', 'Australia East'].includes(p.networkSecurityPerimeter?.location) ||
      p.profile?.name !== network.ids.profile.split('/').at(-1) ||
      !isDeepStrictEqual(p.profile?.enabledLogCategories, []) ||
      !Number.isSafeInteger(p.profile?.accessRulesVersion) || p.profile.accessRulesVersion < 0 ||
      p.profile.accessRulesVersion > Number(profile.accessRulesVersion) ||
      p.profile.diagnosticSettingsVersion !== Number(profile.diagnosticSettingsVersion) ||
      !isDeepStrictEqual(p.profile.accessRules, previous?.accessRules ?? [])) return false;
  return p.provisioningState === 'Accepted' || p.profile.accessRulesVersion === previous?.accessRulesVersion;
}

export class NspController {
  constructor(c, phase, topology, adoption, evidence, io) { Object.assign(this, { c, phase, topology, adoption, evidence, io }); }
  async execute(approval) {
    const { c, phase, topology, adoption, evidence, io } = this, source = await io.sourceDigest();
    verifyNspEvidence(c, evidence, topology, adoption);
    equal(phase, buildNspPhase(c, phase.phase, topology, adoption, evidence, phase.instance), 'NSP_PHASE_CHANGED');
    verifyApproval(approval, c, phase, source, io.now());
    if (await io.loadJournal()) fail('NSP_INTENT_REPLAY_FORBIDDEN');
    const proof = await io.check();
    const guard = deadline => {
      verifyNspPreflight(c, phase, topology, adoption, evidence, proof, io.now());
      verifyApproval(approval, c, phase, source, io.now());
      for (const key of ['configSha256', 'phaseSha256', 'sourceSha256', 'originSha256', 'receiptsSha256', 'baselineSha256', 'whatIfSha256']) {
        if (approval[key] !== proof[key]) fail('NSP_APPROVAL_BINDING_CHANGED');
      }
      if (io.cancelled?.() || io.now() >= deadline) fail('NSP_OPERATION_DEADLINE');
    };
    const deadlineAt = at => Math.min(at + NSP_LIMITS.stageMs, canonicalInstant(approval.expiresAt),
      canonicalInstant(proof.topologyReview.expiresAt), canonicalInstant(proof.networkBillingReview.expiresAt),
      proof.startedAt + NSP_LIMITS.freshnessMs);
    const current = async deadline => {
      guard(deadline);
      await io.verifyCurrent(proof, deadline);
      if (await io.sourceDigest() !== source) fail('NSP_SOURCE_CHANGED');
      guard(deadline);
    };
    await current(deadlineAt(io.now()));
    const at = io.now(), deadline = deadlineAt(at);
    const journal = { version: 1, phaseSha256: hash(phase), approvalSha256: hash(approval),
      requestSha256: hash(phase.request), predecessorSha256: phase.predecessorSha256,
      intentAt: new Date(at).toISOString(), outcome: 'submission-possible', transportDispatchAttempted: false };
    await io.reserve(journal);
    await io.saveJournal(journal);
    try {
      await io.write(phase.request, () => { guard(deadline); journal.transportDispatchAttempted = true; }, current, deadline);
      guard(deadline);
      for (let i = 0; i < NSP_LIMITS.polls; i++) {
        const observed = await io.observe(deadline);
        guard(deadline);
        if (observed.deployment && ['Failed', 'Canceled'].includes(observed.deployment.properties?.provisioningState)) fail('NSP_DEPLOYMENT_FAILED');
        if (phase.request.method !== 'PUT' || observed.deployment?.properties?.provisioningState === 'Succeeded') {
          // Pending propagation is observable, never a reason to repeat the write.
          let pending = false;
          try { verifyNspTransition(c, evidence.topology, adoption, phase, proof.observation, observed.observation); }
          catch (error) {
            if (pendingPropagation(phase, evidence.topology, proof.observation, observed.observation, error)) pending = true;
            else throw error;
          }
          if (!pending) {
            guard(deadline);
            const receipt = { qualified: true, qualificationKind: 'reviewed-nsp-control-plane-only', stage: phase.afterStage,
              configSha256: hash(c), phaseSha256: hash(phase), sourceSha256: source, topologySha256: hash(evidence.topology),
              approvalSha256: hash(approval), ...NSP_AUTHORITY, deployment: observed.deployment,
              observation: observed.observation, completedAt: new Date(io.now()).toISOString() };
            await io.saveReceipt(receipt);
            guard(deadline);
            journal.outcome = 'readback-qualified'; journal.receiptSha256 = hash(receipt);
            await io.saveJournal(journal);
            return receipt;
          }
        }
        await io.sleep(Math.min(NSP_LIMITS.pollMs, deadline - io.now()));
        guard(deadline);
      }
      fail('NSP_PROPAGATION_UNRESOLVED');
    } catch (error) {
      journal.outcome = 'reconciliation-required';
      journal.failureCode = /^[A-Z_]+$/u.test(error.message) ? error.message : 'NSP_OPERATION_FAILED';
      if (io.describeFailure) journal.failureDetails = io.describeFailure(error);
      await io.saveJournal(journal);
      fail('NSP_CHANGE_STOPPED_RESOURCES_PRESERVED');
    }
  }
}
