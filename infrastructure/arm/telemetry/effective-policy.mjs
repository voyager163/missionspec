import { isDeepStrictEqual } from 'node:util';
import { digest, json, fail, sameId, closed } from './definition.mjs';

export const POLICY_API = '2023-04-01';
export const EXEMPTION_API = '2022-07-01-preview';
export const POLICY_ASSIGNMENT_QUERY = '$expand=EffectiveDefinitionVersion';
export const POLICY_LIMITS = Object.freeze({ reads: 512, items: 512, observations: 4096, bytes: 8 * 1024 * 1024, depth: 24, waves: 8 });
const unknown = Symbol('unresolved-policy-expression');
const versionPattern = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const definitionPattern = /^(?:(\/subscriptions\/[0-9a-f-]{36})|(\/providers\/Microsoft\.Management\/managementGroups\/[A-Za-z0-9_-]{1,90}))?\/providers\/Microsoft\.Authorization\/(policyDefinitions|policySetDefinitions)\/([A-Za-z0-9_.-]{1,128})(?:\/versions\/(\d+\.\d+\.\d+))?$/iu;
const authorizationScope = /^(.*)\/providers\/Microsoft\.Authorization\/(?:policyAssignments|policyExemptions)\/[A-Za-z0-9_.-]{1,128}$/iu;
const managementScope = /^\/providers\/Microsoft\.Management\/managementGroups\/[A-Za-z0-9_-]{1,90}$/iu;
const validScope = value => typeof value === 'string' && !/[?#\\%]|\.\./u.test(value) &&
  (managementScope.test(value) || /^\/subscriptions\/[0-9a-f-]{36}(?:\/[A-Za-z0-9_.-]+)*$/iu.test(value));
const scalar = value => value === null || ['string', 'boolean', 'number'].includes(typeof value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const within = (id, scope) => sameId(id, scope) || id.toLowerCase().startsWith(scope.toLowerCase() + '/');
const requestKey = request => json([request.id.toLowerCase(), request.apiVersion, request.filter]);
const sha = value => digest(json(value));
const hasContent = value => value !== undefined && value !== null && (!Array.isArray(value) || value.length !== 0);
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' ? a.toLowerCase() === b.toLowerCase() : isDeepStrictEqual(a, b);

// Only explicit aliases whose requested values are present in the template are understood.
const storageFields = Object.freeze(Object.fromEntries([
  'publicNetworkAccess', 'allowSharedKeyAccess', 'allowBlobPublicAccess', 'minimumTlsVersion',
  'supportsHttpsTrafficOnly', 'defaultToOAuthAuthentication', 'allowCrossTenantReplication',
  'isLocalUserEnabled', 'isSftpEnabled', 'isHnsEnabled', 'networkAcls.bypass', 'networkAcls.defaultAction',
].map(path => [`microsoft.storage/storageaccounts/${path.toLowerCase()}`, path])));

export function effectivePolicyScopes(phase) {
  if (!Array.isArray(phase?.resources) || !phase.resources.length || phase.resources.length > 32) fail('EFFECTIVE_POLICY_TARGETS_INVALID');
  const scopes = phase.resources.map(d => {
    const match = /^(\/subscriptions\/[0-9a-f-]{36})(\/resourceGroups\/[A-Za-z0-9_-]+)?\/providers\//iu.exec(d.id ?? '');
    if (!match || typeof d.type !== 'string' || !object(d.expected)) fail('EFFECTIVE_POLICY_TARGETS_INVALID');
    return match[1] + (match[2] ?? '');
  });
  if (new Set(scopes.map(id => id.split('/')[2].toLowerCase())).size !== 1) fail('EFFECTIVE_POLICY_TARGETS_INVALID');
  return [...new Set(scopes)].sort();
}

function policyId(id, scopes) {
  const match = definitionPattern.exec(id ?? '');
  if (!match || /[?#\\%]|\.\./u.test(id) || (match[1] && !scopes.some(scope => within(scope, match[1])))) fail('EFFECTIVE_POLICY_REFERENCE_INVALID');
  return { base: id.replace(/\/versions\/[^/]+$/iu, ''), kind: match[3], version: match[5] };
}
function list(response) {
  if (!object(response) || response.error || response.nextLink || !Array.isArray(response.value) ||
      response.value.length > POLICY_LIMITS.items) fail('EFFECTIVE_POLICY_LIST_INCOMPLETE');
  return response.value;
}
function document(response, id) {
  if (!object(response) || response.error || response.nextLink || !sameId(response.id, id) || !object(response.properties)) fail('EFFECTIVE_POLICY_DEFINITION_INVALID');
  return response;
}
function expression(value, parameters) {
  if (typeof value !== 'string' || !value.startsWith('[')) return value;
  const match = /^\[parameters\('([A-Za-z0-9_-]+)'\)\]$/iu.exec(value);
  return match && Object.hasOwn(parameters, match[1]) ? parameters[match[1]] : unknown;
}
function parameters(definitions, supplied, parent = {}) {
  if (!object(definitions ?? {}) || !object(supplied ?? {})) fail('EFFECTIVE_POLICY_PARAMETERS_INVALID');
  const resolved = {};
  for (const key of Object.keys(supplied ?? {})) if (!Object.hasOwn(definitions ?? {}, key)) fail('EFFECTIVE_POLICY_PARAMETERS_INVALID');
  for (const [key, schema] of Object.entries(definitions ?? {})) {
    if (!object(schema)) fail('EFFECTIVE_POLICY_PARAMETERS_INVALID');
    const suppliedValue = supplied?.[key];
    if (suppliedValue !== undefined && (!object(suppliedValue) || !Object.hasOwn(suppliedValue, 'value'))) fail('EFFECTIVE_POLICY_PARAMETERS_INVALID');
    const value = expression(suppliedValue === undefined ? schema.defaultValue : suppliedValue.value, parent);
    const types = { string: v => typeof v === 'string', boolean: v => typeof v === 'boolean',
      integer: v => Number.isSafeInteger(v), float: v => typeof v === 'number' && Number.isFinite(v),
      array: Array.isArray, object };
    if (value === undefined || value === unknown || !types[schema.type?.toLowerCase()]?.(value) ||
        (schema.allowedValues && (!Array.isArray(schema.allowedValues) || !schema.allowedValues.some(v => equal(v, value))))) fail('EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED');
    resolved[key] = value;
  }
  return resolved;
}
function fieldValue(field, resource) {
  if (typeof field !== 'string') return unknown;
  const name = field.toLowerCase(), expected = resource.expected;
  if (name === 'type') return resource.type;
  if (name === 'name') return expected.name ?? unknown;
  if (name === 'location') return expected.location ?? unknown;
  const path = storageFields[name];
  if (!path || resource.type.toLowerCase() !== 'microsoft.storage/storageaccounts') return unknown;
  let value = expected.properties;
  for (const key of path.split('.')) {
    if (!object(value) || !Object.hasOwn(value, key)) return unknown;
    value = value[key];
  }
  return value;
}
function condition(rule, params, resource, depth = 0) {
  if (depth > POLICY_LIMITS.depth || !object(rule)) return unknown;
  const keys = Object.keys(rule);
  if (keys.length === 1 && ['allOf', 'anyOf'].includes(keys[0])) {
    const values = rule[keys[0]];
    if (!Array.isArray(values) || !values.length || values.length > POLICY_LIMITS.items) return unknown;
    const results = values.map(value => condition(value, params, resource, depth + 1));
    if (keys[0] === 'allOf') return results.includes(false) ? false : results.includes(unknown) ? unknown : true;
    return results.includes(true) ? true : results.includes(unknown) ? unknown : false;
  }
  if (keys.length === 1 && keys[0] === 'not') {
    const result = condition(rule.not, params, resource, depth + 1);
    return result === unknown ? unknown : !result;
  }
  const operators = ['equals', 'notEquals', 'in', 'notIn'];
  const operator = operators.find(key => Object.hasOwn(rule, key));
  if (keys.length !== 2 || !operator || (!Object.hasOwn(rule, 'field') && !Object.hasOwn(rule, 'value'))) return unknown;
  const actual = Object.hasOwn(rule, 'field') ? fieldValue(expression(rule.field, params), resource) : expression(rule.value, params);
  const requested = expression(rule[operator], params);
  if (actual === unknown || requested === unknown) return unknown;
  if (['in', 'notIn'].includes(operator)) {
    if (!scalar(actual) || !Array.isArray(requested) || !requested.every(scalar)) return unknown;
    const included = requested.some(v => equal(actual, v));
    return operator === 'in' ? included : !included;
  }
  if (!scalar(actual) || !scalar(requested)) return unknown;
  return operator === 'equals' ? equal(actual, requested) : !equal(actual, requested);
}
function operationCondition(value, params, resource) {
  if (value === undefined) return true;
  const resolved = expression(value, params);
  if (typeof resolved === 'boolean') return resolved;
  const match = typeof value === 'string' && /^\[greaterOrEquals\(requestContext\(\)\.apiVersion, '(\d{4}-\d{2}-\d{2})'\)\]$/iu.exec(value);
  if (!match || !/^\d{4}-\d{2}-\d{2}$/u.test(resource.apiVersion ?? '')) return unknown;
  return resource.apiVersion >= match[1];
}
function assignmentScope(assignment) {
  const scope = authorizationScope.exec(assignment?.id ?? '')?.[1];
  if (!validScope(scope) || !sameId(scope, assignment.properties?.scope)) fail('EFFECTIVE_POLICY_ASSIGNMENT_INVALID');
  return scope;
}
function applies(scope, resource) {
  // A management-group assignment returned by the scoped ARM list is inherited.
  return managementScope.test(scope) || scope === '' || within(resource.id, scope);
}

function evaluate(phase, snapshot) {
  const scopes = effectivePolicyScopes(phase), pending = new Map(), entries = new Map(), used = new Set();
  const observations = [], blockers = [];
  if (!object(snapshot) || !Array.isArray(snapshot.reads) || snapshot.reads.length > POLICY_LIMITS.reads ||
      Buffer.byteLength(json(snapshot)) > POLICY_LIMITS.bytes) fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
  closed(snapshot, ['reads']);
  for (const read of snapshot.reads) {
    closed(read, ['id', 'apiVersion', 'filter', 'response']);
    if (typeof read.id !== 'string' || ![POLICY_API, EXEMPTION_API].includes(read.apiVersion) ||
        ![null, POLICY_ASSIGNMENT_QUERY, '$filter=atScope()&$expand=EffectiveDefinitionVersion', '$filter=atScope()'].includes(read.filter)) fail('EFFECTIVE_POLICY_READ_INVALID');
    const key = requestKey(read);
    if (entries.has(key)) fail('EFFECTIVE_POLICY_DUPLICATE_READ');
    entries.set(key, read.response);
  }
  const get = (id, apiVersion = POLICY_API, filter = null) => {
    const request = { id, apiVersion, filter }, key = requestKey(request);
    used.add(key);
    if (entries.has(key)) return entries.get(key);
    pending.set(key, request);
    return undefined;
  };
  const resolve = reference => {
    const parsed = policyId(reference.policyDefinitionId, scopes);
    const selector = reference.definitionVersion;
    const effective = reference.effectiveDefinitionVersion;
    if (selector !== undefined && !/^(?:\*\.\*\.\*|\d+\.\*\.\*|\d+\.\d+\.\*|\d+\.\d+\.\d+)$/u.test(selector)) fail('EFFECTIVE_POLICY_VERSION_INVALID');
    const matches = version => !selector || selector.split('.').every((part, i) => part === '*' || part === version.split('.')[i]);
    const pin = parsed.version ?? effective ?? (versionPattern.test(selector ?? '') ? selector : null);
    if (effective !== undefined && (!versionPattern.test(effective) || (parsed.version && parsed.version !== effective))) fail('EFFECTIVE_POLICY_VERSION_INVALID');
    if (pin && !matches(pin)) fail('EFFECTIVE_POLICY_VERSION_INVALID');
    let versions;
    if (pin) versions = [pin];
    else {
      const catalog = get(`${parsed.base}/versions`);
      if (catalog === undefined) return [];
      versions = list(catalog).map(value => {
        const version = value?.properties?.version ?? value?.name;
        if (!versionPattern.test(version ?? '') || !sameId(value.id, `${parsed.base}/versions/${version}`)) fail('EFFECTIVE_POLICY_VERSION_INVALID');
        return version;
      }).filter(matches);
      if (!versions.length || new Set(versions).size !== versions.length) fail('EFFECTIVE_POLICY_VERSION_UNRESOLVED');
    }
    return versions.sort().flatMap(version => {
      const id = `${parsed.base}/versions/${version}`, raw = get(id);
      if (raw === undefined) return [];
      const value = document(raw, id);
      if (value.properties.version !== version) fail('EFFECTIVE_POLICY_VERSION_INVALID');
      return [{ value, kind: parsed.kind, resolution: pin ? 'exact-version' : 'all-matching-versions' }];
    });
  };
  const assignmentLists = [], exemptions = [];
  for (const scope of scopes) {
    const subscription = /^\/subscriptions\/[^/]+$/iu.test(scope);
    // Unfiltered RG lists include ancestors AND descendant resource scopes; atScope excludes descendants.
    // https://learn.microsoft.com/rest/api/policy-authorization/policy-assignments/list-for-resource-group?view=rest-policy-authorization-2023-04-01
    // https://learn.microsoft.com/rest/api/policy-authorization/policy-exemptions/list-for-resource-group?view=rest-policy-authorization-2023-04-01
    const assignments = get(`${scope}/providers/Microsoft.Authorization/policyAssignments`, POLICY_API,
      subscription ? '$filter=atScope()&$expand=EffectiveDefinitionVersion' : POLICY_ASSIGNMENT_QUERY);
    const exempt = get(`${scope}/providers/Microsoft.Authorization/policyExemptions`, EXEMPTION_API, subscription ? '$filter=atScope()' : null);
    if (assignments !== undefined) {
      for (const assignment of list(assignments)) {
        const assignedScope = assignmentScope(assignment);
        if (!managementScope.test(assignedScope) && !within(scope, assignedScope) &&
            (subscription || !within(assignedScope, scope))) fail('EFFECTIVE_POLICY_ASSIGNMENT_SCOPE_UNPROVEN');
        assignmentLists.push(assignment);
      }
    }
    if (exempt !== undefined) exemptions.push(...list(exempt));
  }
  for (const exemption of exemptions) {
    const p = exemption?.properties;
    if (!/\/providers\/Microsoft\.Authorization\/policyExemptions\//iu.test(exemption?.id ?? '') ||
        !validScope(authorizationScope.exec(exemption.id)?.[1]) || !object(p) || typeof p.policyAssignmentId !== 'string' ||
        !/\/providers\/Microsoft\.Authorization\/policyAssignments\//iu.test(p.policyAssignmentId) ||
        !validScope(authorizationScope.exec(p.policyAssignmentId)?.[1]) || !['Waiver', 'Mitigated'].includes(p.exemptionCategory) ||
        (p.expiresOn !== undefined && p.expiresOn !== null && !Number.isFinite(Date.parse(p.expiresOn))) ||
        (p.policyDefinitionReferenceIds !== undefined && (!Array.isArray(p.policyDefinitionReferenceIds) ||
          p.policyDefinitionReferenceIds.some(v => typeof v !== 'string')))) fail('EFFECTIVE_POLICY_EXEMPTION_INVALID');
  }
  const assignments = new Map();
  for (const assignment of assignmentLists) {
    assignmentScope(assignment);
    const key = assignment.id.toLowerCase();
    if (assignments.has(key) && !isDeepStrictEqual(assignments.get(key), assignment)) fail('EFFECTIVE_POLICY_ASSIGNMENT_DRIFT');
    assignments.set(key, assignment);
  }
  if (assignments.size > POLICY_LIMITS.items || exemptions.length > POLICY_LIMITS.items) fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
  const inspect = (assignment, definition, params, resources, referenceId = null) => {
    const p = definition.value.properties, rule = p.policyRule;
    if (!object(rule) || !object(rule.then)) fail('EFFECTIVE_POLICY_RULE_INVALID');
    const resolvedEffect = expression(rule.then.effect, params);
    const effect = typeof resolvedEffect === 'string' ? resolvedEffect.toLowerCase() : 'unknown';
    for (const resource of resources) {
      const detail = { assignmentSha256: sha(assignment), definitionSha256: sha(definition.value),
        definitionVersion: p.version, versionResolution: definition.resolution, parametersSha256: sha(params),
        referenceSha256: sha(referenceId), resourceSha256: sha(resource), effect: ['audit', 'auditifnotexists', 'disabled',
          'deny', 'modify', 'append', 'deployifnotexists', 'denyaction', 'manual'].includes(effect) ? effect : 'unknown' };
      const match = condition(rule.if, params, resource);
      const relatedExemptions = exemptions.filter(e => sameId(e.properties.policyAssignmentId, assignment.id) &&
        applies(authorizationScope.exec(e.id)[1], resource) &&
        (!e.properties.policyDefinitionReferenceIds?.length || e.properties.policyDefinitionReferenceIds.includes(referenceId)));
      const record = (outcome, reason, extra = {}) => {
        if (observations.length >= POLICY_LIMITS.observations) fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
        const observation = { ...detail, condition: match === unknown ? 'unknown' : match,
          outcome, reason, exemptionEvidenceSha256: sha(relatedExemptions), exemptionsApplied: false, ...extra };
        observations.push(observation);
        if (outcome === 'blocked') blockers.push(observation);
      };
      if (hasContent(assignment.properties.overrides) || hasContent(assignment.properties.resourceSelectors)) {
        record('blocked', 'UNSUPPORTED_ASSIGNMENT_SELECTOR_OR_OVERRIDE'); continue;
      }
      if (['audit', 'auditifnotexists', 'disabled', 'manual'].includes(effect)) { record('nonmutating', 'NONMUTATING_EFFECT'); continue; }
      if (match === false) { record('not-applicable', 'RULE_FALSE'); continue; }
      if (!['All', 'Indexed'].includes(p.mode ?? 'All')) { record('blocked', 'UNSUPPORTED_POLICY_MODE'); continue; }
      if (effect === 'deny' || effect === 'denyaction') { record('blocked', 'POTENTIAL_DENY'); continue; }
      if (effect !== 'modify') { record('blocked', 'UNSUPPORTED_POTENTIAL_MUTATION'); continue; }
      const details = rule.then.details;
      if (!object(details) || Object.keys(details).some(k => !['operations', 'roleDefinitionIds', 'conflictEffect'].includes(k)) ||
          !Array.isArray(details.operations) || !details.operations.length || details.operations.length > POLICY_LIMITS.items ||
          (details.conflictEffect !== undefined && !['audit', 'deny'].includes(expression(details.conflictEffect, params)))) {
        record('blocked', 'UNSUPPORTED_MODIFY_DETAILS'); continue;
      }
      for (const operation of details.operations) {
        if (!object(operation)) { record('blocked', 'UNSUPPORTED_MODIFY_OPERATION'); continue; }
        const enabled = operationCondition(operation.condition, params, resource);
        if (enabled === false) { record('not-applicable', 'OPERATION_FALSE'); continue; }
        const field = expression(operation.field, params), current = fieldValue(field, resource), value = expression(operation.value, params);
        if (Object.keys(operation).some(k => !['operation', 'condition', 'field', 'value'].includes(k)) ||
            operation.operation !== 'addOrReplace' || current === unknown || value === unknown || !scalar(value)) {
          record('blocked', 'UNSUPPORTED_MODIFY_OPERATION'); continue;
        }
        // This compares only the requested property, not reachability or topology security.
        if (isDeepStrictEqual(current, value)) record('compatible', 'EXACT_REQUEST_PRESERVED', { field });
        else record('blocked', relatedExemptions.length ? 'MUTATION_CONFLICT_EXEMPTION_REVIEW_REQUIRED' : 'REQUEST_REWRITTEN',
          { field, requestedSha256: sha(current), mutationSha256: sha(value),
            ...(field.toLowerCase().endsWith('/publicnetworkaccess') &&
              ['Enabled', 'Disabled', 'SecuredByPerimeter'].includes(current) && ['Enabled', 'Disabled', 'SecuredByPerimeter'].includes(value)
              ? { requested: current, mutation: value } : {}) });
      }
    }
  };
  for (const assignment of [...assignments.values()].sort((a, b) => a.id.localeCompare(b.id))) {
    const p = assignment.properties, scope = assignmentScope(assignment);
    if (!['Default', 'DoNotEnforce'].includes(p.enforcementMode ?? 'Default') ||
        (p.notScopes !== undefined && (!Array.isArray(p.notScopes) || p.notScopes.some(v => !validScope(v))))) fail('EFFECTIVE_POLICY_ASSIGNMENT_INVALID');
    const resources = phase.resources.filter(resource => applies(scope, resource) &&
      !(p.notScopes ?? []).some(excluded => within(resource.id, excluded)));
    if (!resources.length || p.enforcementMode === 'DoNotEnforce') continue;
    for (const definition of resolve(p)) {
      const params = parameters(definition.value.properties.parameters, p.parameters);
      if (definition.kind.toLowerCase() === 'policydefinitions') inspect(assignment, definition, params, resources);
      else {
        const references = definition.value.properties.policyDefinitions;
        if (!Array.isArray(references) || !references.length || references.length > POLICY_LIMITS.items) fail('EFFECTIVE_POLICY_INITIATIVE_INVALID');
        const seen = new Set();
        for (const reference of references) {
          const id = reference?.policyDefinitionReferenceId;
          if (typeof id !== 'string' || seen.has(id) || policyId(reference.policyDefinitionId, scopes).kind.toLowerCase() !== 'policydefinitions') fail('EFFECTIVE_POLICY_INITIATIVE_INVALID');
          seen.add(id);
          for (const child of resolve(reference)) {
            const childParams = parameters(child.value.properties.parameters, reference.parameters, params);
            inspect(assignment, child, childParams, resources, id);
          }
        }
      }
    }
  }
  if (entries.size + pending.size > POLICY_LIMITS.reads || [...entries.keys()].some(key => !used.has(key))) fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
  return { pending: [...pending.values()], analysis: { observations, blockers, exemptionsApplied: false } };
}

export function analyzeEffectivePolicies(phase, snapshot) {
  const result = evaluate(phase, snapshot);
  if (result.pending.length) fail('EFFECTIVE_POLICY_EVIDENCE_INCOMPLETE');
  return { version: 1, kind: 'effective-policy-preflight', phaseSha256: sha(phase),
    snapshot, analysis: result.analysis, qualified: result.analysis.blockers.length === 0 };
}
export function verifyEffectivePolicyEvidence(phase, evidence) {
  closed(evidence, ['version', 'kind', 'phaseSha256', 'snapshot', 'analysis', 'qualified']);
  if (evidence.version !== 1 || evidence.kind !== 'effective-policy-preflight' ||
      evidence.phaseSha256 !== sha(phase) || evidence.qualified !== true ||
      !isDeepStrictEqual(evidence, analyzeEffectivePolicies(phase, evidence.snapshot))) fail('EFFECTIVE_POLICY_BINDING_INVALID');
  return evidence;
}
export async function collectEffectivePolicies(phase, read, readBatch, retain) {
  const snapshot = { reads: [] };
  let bytes = 0;
  try {
    for (let wave = 0; wave < POLICY_LIMITS.waves; wave++) {
      const { pending } = evaluate(phase, snapshot);
      if (!pending.length) return analyzeEffectivePolicies(phase, snapshot);
      await readBatch(pending, async request => {
        const response = await read(request.id, request.apiVersion, request.filter ?? undefined);
        bytes += Buffer.byteLength(json({ ...request, response }));
        if (bytes > POLICY_LIMITS.bytes) fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
        snapshot.reads.push({ ...request, response });
      });
      snapshot.reads.sort((a, b) => requestKey(a).localeCompare(requestKey(b)));
    }
    fail('EFFECTIVE_POLICY_EVIDENCE_LIMIT');
  } finally {
    await retain(snapshot);
  }
}
