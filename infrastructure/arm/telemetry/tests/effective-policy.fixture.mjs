import { collectEffectivePolicies, effectivePolicyScopes, POLICY_API, EXEMPTION_API, POLICY_ASSIGNMENT_QUERY } from '../effective-policy.mjs';
import { readBatch } from '../controller.mjs';
import { baseFixture, queuePhaseFixture } from './durable-queue.fixture.mjs';

// Entirely synthetic unit inputs, not governance exports or cloud authorization.
export function effectivePolicyFixture() {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage'), phase = q.phase;
  const scope = '/providers/Microsoft.Management/managementGroups/unit-governance';
  const setId = `${scope}/providers/Microsoft.Authorization/policySetDefinitions/unit-initiative`;
  const definitionId = `${scope}/providers/Microsoft.Authorization/policyDefinitions/unit-storage-network`;
  const assignment = { id: `${scope}/providers/Microsoft.Authorization/policyAssignments/unit-assignment`,
    properties: { scope, enforcementMode: 'Default', notScopes: [], policyDefinitionId: setId,
      definitionVersion: '1.*.*', effectiveDefinitionVersion: '1.0.0', parameters: {} } };
  const initiative = { id: `${setId}/versions/1.0.0`, properties: { version: '1.0.0',
    parameters: {}, policyDefinitions: [{ policyDefinitionId: definitionId, definitionVersion: '1.*.*',
      policyDefinitionReferenceId: 'unit-storage', parameters: {} }] } };
  const definition = { id: `${definitionId}/versions/1.0.0`, properties: { version: '1.0.0', mode: 'Indexed',
    parameters: {
      effect: { type: 'String', defaultValue: 'modify', allowedValues: ['modify', 'audit', 'disabled', 'deny'] },
      ignoredTag: { type: 'String', defaultValue: 'unit-tag' }, ignoredValue: { type: 'String', defaultValue: 'unit-value' },
    },
    policyRule: {
      if: { allOf: [
        { field: 'type', equals: 'Microsoft.Storage/storageAccounts' },
        { field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', notEquals: 'Disabled' },
        { field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', notEquals: 'SecuredByPerimeter' },
        { not: { anyOf: [
          { field: "[concat('tags[', parameters('ignoredTag'), ']')]", equals: "[parameters('ignoredValue')]" },
          { value: "[resourceGroup().tags[parameters('ignoredTag')]]", equals: "[parameters('ignoredValue')]" },
        ] } },
      ] },
      then: { effect: "[parameters('effect')]", details: { conflictEffect: 'audit', roleDefinitionIds: [],
        operations: [{ operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess',
          value: 'Disabled', condition: "[greaterOrEquals(requestContext().apiVersion, '2021-04-01')]" }] } },
  } } };
  const assignments = { value: [assignment] }, exemptions = { value: [] };
  const catalog = { value: [{ id: definition.id, name: '1.0.0', properties: { version: '1.0.0' } }] };
  const responses = new Map([[initiative.id, initiative], [`${definitionId}/versions`, catalog], [definition.id, definition]]);
  for (const id of effectivePolicyScopes(phase)) {
    responses.set(`${id}/providers/Microsoft.Authorization/policyAssignments`, assignments);
    responses.set(`${id}/providers/Microsoft.Authorization/policyExemptions`, exemptions);
  }
  const calls = [];
  const read = async (id, apiVersion, filter) => {
    calls.push({ id, apiVersion, filter });
    if (!responses.has(id)) throw new Error('UNEXPECTED_UNIT_POLICY_READ');
    return structuredClone(responses.get(id));
  };
  const invoke = async args => {
    if (args[0] !== 'rest' || args[args.indexOf('--method') + 1] !== 'GET') throw new Error('UNIT_MUTATION_FORBIDDEN');
    const url = new URL(args[args.indexOf('--url') + 1]);
    const query = [...url.searchParams].filter(([key]) => key !== 'api-version').map(([key, value]) => `${key}=${value}`).join('&');
    return read(url.pathname, url.searchParams.get('api-version'), query || undefined);
  };
  return { f, q, phase, scope, setId, definitionId, assignment, initiative, definition, assignments, exemptions,
    catalog, responses, calls, read, invoke,
    analyze: () => collectEffectivePolicies(phase, read, readBatch, async () => {}) };
}

export function emptyPolicySnapshot(phase) {
  return { reads: effectivePolicyScopes(phase).flatMap(id => {
    const subscription = /^\/subscriptions\/[^/]+$/iu.test(id);
    return [
      { id: `${id}/providers/Microsoft.Authorization/policyAssignments`, apiVersion: POLICY_API,
        filter: subscription ? '$filter=atScope()&$expand=EffectiveDefinitionVersion' : POLICY_ASSIGNMENT_QUERY, response: { value: [] } },
      { id: `${id}/providers/Microsoft.Authorization/policyExemptions`, apiVersion: EXEMPTION_API,
        filter: subscription ? '$filter=atScope()' : null, response: { value: [] } },
    ];
  }) };
}
