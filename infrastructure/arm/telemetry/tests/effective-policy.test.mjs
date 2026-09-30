import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { digest, json, storageContract } from '../definition.mjs';
import { analyzeEffectivePolicies, verifyEffectivePolicyEvidence, POLICY_LIMITS,
  POLICY_API, EXEMPTION_API, POLICY_ASSIGNMENT_QUERY } from '../effective-policy.mjs';
import { checkEffectivePolicies, transport, sourceDigest, publishedSourceDigest } from '../controller.mjs';
import { queuePreflightBaseline } from '../durable-queue.mjs';
import { effectivePolicyFixture, emptyPolicySnapshot } from './effective-policy.fixture.mjs';

async function scratch(t) {
  const directory = `infrastructure/arm/telemetry/tests/.effective-policy-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true }));
  return directory;
}
const network = 'Microsoft.Storage/storageAccounts/publicNetworkAccess';

test('inherited initiative/default modify blocks Enabled to Disabled before a queue controller can dispatch', async t => {
  const x = effectivePolicyFixture(), directory = await scratch(t);
  let dispatches = 0;
  x.q.io.check = () => checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology);
  x.q.io.arm = async () => { dispatches++; };
  await assert.rejects(x.q.controller.execute(x.q.approval), { message: 'EFFECTIVE_POLICY_CONFLICT' });
  assert.equal(dispatches, 0);
  assert.equal(x.q.record().journal, null);
  const proof = JSON.parse(await readFile(`${directory}/queue-storage-effective-policy.json`, 'utf8'));
  assert.equal(proof.qualified, false);
  assert.deepEqual(proof.analysis.blockers.map(v => [v.reason, v.field, v.requested, v.mutation, v.condition]),
    [['REQUEST_REWRITTEN', network, 'Enabled', 'Disabled', 'unknown']]);
  assert.equal(proof.analysis.blockers[0].versionResolution, 'latest-matching-versions');
  assert.equal(proof.analysis.blockers[0].exemptionsApplied, false);
  assert.deepEqual(proof, analyzeEffectivePolicies(x.phase, proof.snapshot));
  assert.equal(x.calls.length, 5);
  assert(x.calls.some(v => v.id.startsWith(x.scope)));
  assert(x.calls.filter(v => v.id.endsWith('/policyAssignments')).every(v => v.filter === POLICY_ASSIGNMENT_QUERY));
  assert.doesNotMatch(json(proof.analysis), /unit-governance|unit-assignment|unit-tag|unit-value/u);
});

test('supported rule guards distinguish exact requested Disabled and SecuredByPerimeter without asserting topology reachability', async () => {
  for (const value of ['Disabled', 'SecuredByPerimeter']) {
    const x = effectivePolicyFixture();
    x.phase.resources[0].expected.properties.publicNetworkAccess = value;
    const proof = await x.analyze();
    assert.equal(proof.qualified, true);
    assert(proof.analysis.observations.every(v => v.reason === 'RULE_FALSE'));
    verifyEffectivePolicyEvidence(x.phase, proof);
    assert.equal(Object.hasOwn(proof, 'executionAuthorized'), false);
    assert.equal(Object.hasOwn(proof, 'networkReachable'), false);
  }
});

test('a positive audit-only policy produces the bound fresh proof before mocked execution', async t => {
  const x = effectivePolicyFixture(), directory = await scratch(t);
  x.definition.properties.policyRule.then.effect = 'audit';
  Object.assign(x.q.proof, await checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology));
  x.q.proof.baselineSha256 = queuePreflightBaseline(x.q.proof);
  x.q.approval.baselineSha256 = x.q.proof.baselineSha256;
  const receipt = await x.q.controller.execute(x.q.approval);
  assert.equal(receipt.qualified, true);
  assert.equal(x.q.dispatched, true);
  assert.equal(receipt.ingestionEnabled, false);
});

test('nonmutating effects, unrelated types, nonenforced and exact excluded scopes do not blindly block', async t => {
  for (const mode of ['audit', 'auditIfNotExists', 'disabled', 'unrelated', 'notScopes', 'DoNotEnforce', 'resource-scope-unrelated']) await t.test(mode, async () => {
    const x = effectivePolicyFixture();
    if (['audit', 'auditIfNotExists', 'disabled'].includes(mode)) x.definition.properties.policyRule.then.effect = mode;
    if (mode === 'unrelated') {
      x.definition.properties.policyRule.if.allOf[0].equals = 'Microsoft.Compute/virtualMachines';
      x.definition.properties.policyRule.then.effect = 'deployIfNotExists';
    }
    if (mode === 'notScopes') x.assignment.properties.notScopes = [x.f.r.group.toUpperCase()];
    if (mode === 'DoNotEnforce') x.assignment.properties.enforcementMode = mode;
    if (mode === 'resource-scope-unrelated') {
      x.assignment.properties.scope = x.f.r.group + '/providers/Microsoft.Storage/storageAccounts/unrelated-unit';
      x.assignment.id = x.assignment.properties.scope + '/providers/Microsoft.Authorization/policyAssignments/unit';
    }
    const proof = await x.analyze();
    assert.equal(proof.qualified, true);
    verifyEffectivePolicyEvidence(x.phase, proof);
    if (['notScopes', 'DoNotEnforce', 'resource-scope-unrelated'].includes(mode)) assert.equal(x.calls.length, 2);
  });

});

test('resource-scoped direct definitions are covered by the RG list with case-normalized exact scope matching', async () => {
  const x = effectivePolicyFixture();
  x.assignment.properties.scope = x.phase.resources[0].id.toUpperCase();
  x.assignment.id = x.assignment.properties.scope + '/providers/Microsoft.Authorization/policyAssignments/unit-resource';
  x.assignment.properties.policyDefinitionId = x.definitionId;
  x.assignment.properties.definitionVersion = '1.0.0';
  const proof = await x.analyze();
  assert.equal(proof.qualified, false);
  assert.equal(proof.analysis.blockers.length, 1);
  assert.equal(x.calls.length, 3);
  x.assignment.properties.notScopes = [x.phase.resources[0].id.toLowerCase()];
  assert.equal((await x.analyze()).qualified, true);
});

test('nested service and queue leaf-name policy mutations cannot be waived by parent-qualified template names', async t => {
  for (const [index, leafName] of [[1, 'default'], [2, 'telemetry-events-v1']]) await t.test(leafName, async () => {
    const x = effectivePolicyFixture(), resource = x.phase.resources[index];
    assert.notEqual(resource.expected.name, leafName);
    x.definition.properties.policyRule.if = { allOf: [
      { field: 'type', equals: resource.type }, { field: 'name', equals: leafName },
    ] };
    x.definition.properties.policyRule.then.effect = 'deployIfNotExists';
    const proof = await x.analyze();
    assert.equal(proof.qualified, false);
    assert.equal(proof.analysis.blockers.length, 1);
    assert.equal(proof.analysis.blockers[0].condition, true);
    assert.equal(proof.analysis.blockers[0].reason, 'UNSUPPORTED_POTENTIAL_MUTATION');
    resource.expected.name = 'unit-misleading/template-name';
    assert.equal((await x.analyze()).analysis.blockers[0].condition, true);
  });
});

test('fullName uses validated parent/child identity, distinct from name, and unsupported identities stay unknown', async t => {
  for (const index of [0, 1, 2]) await t.test(`resource ${index}`, async () => {
    const x = effectivePolicyFixture(), resource = x.phase.resources[index], fullName = resource.expected.name;
    const rule = { allOf: [{ field: 'type', equals: resource.type }, { field: 'fullName', equals: fullName }] };
    x.definition.properties.policyRule.if = rule;
    x.definition.properties.policyRule.then.effect = 'deployIfNotExists';
    assert.equal((await x.analyze()).analysis.blockers[0].condition, true);
    rule.allOf[1].equals = 'unit-unrelated';
    assert.equal((await x.analyze()).qualified, true);
    if (index > 0) {
      rule.allOf[1] = { field: 'name', equals: fullName };
      assert.equal((await x.analyze()).qualified, true);
      rule.allOf[1] = { field: 'fullName', equals: resource.id.split('/').at(-1) };
      assert.equal((await x.analyze()).qualified, true);
    }
    for (const field of ['name', 'fullName']) {
      rule.allOf[1] = { field, equals: 'unit-unrelated' };
      const id = resource.id;
      for (const unsupported of [id + '/unexpected', id + '/providers/Unit.Extension/children/leaf',
        id.replace('/storageAccounts/', '/unitWrongType/')]) {
        resource.id = unsupported;
        const proof = await x.analyze();
        assert.equal(proof.qualified, false);
        assert.equal(proof.analysis.blockers[0].condition, 'unknown');
      }
      resource.id = id;
    }
  });
});

test('location comparisons normalize documented display names for direct and parameterized scalar/array operators', async t => {
  const cases = [
    ['equals', 'Australia East', true],
    ['equals', 'West US', false],
    ['notEquals', 'Australia East', false],
    ['notEquals', 'West US', true],
    ['in', ['West US', 'Australia East'], true],
    ['in', ['West US'], false],
    ['notIn', ['West US', 'Australia East'], false],
    ['notIn', ['West US'], true],
  ];
  for (const parameterized of [false, true]) for (const [operator, value, blocked] of cases) {
    await t.test(`${parameterized ? 'parameterized' : 'direct'} ${operator} ${JSON.stringify(value)}`, async () => {
      const x = effectivePolicyFixture(), resource = x.phase.resources[0];
      if (parameterized) x.definition.properties.parameters.region = {
        type: Array.isArray(value) ? 'Array' : 'String', defaultValue: value,
      };
      x.definition.properties.policyRule.if = { allOf: [
        { field: 'type', equals: resource.type },
        { field: 'location', [operator]: parameterized ? "[parameters('region')]" : value },
      ] };
      assert.equal(resource.expected.location, 'australiaeast');
      const proof = await x.analyze();
      assert.equal(proof.qualified, !blocked);
      if (blocked) assert.equal(proof.analysis.blockers[0].condition, true);
      resource.expected.location = 'Australia East';
      assert.equal((await x.analyze()).qualified, !blocked);
    });
  }
});

test('ambiguous location formats stay unknown and location normalization does not alter name or property strings', async () => {
  for (const operator of ['equals', 'notEquals', 'in', 'notIn']) {
    const x = effectivePolicyFixture(), value = 'Australia-East';
    x.definition.properties.policyRule.if = { allOf: [
      { field: 'type', equals: x.phase.resources[0].type },
      { field: 'location', [operator]: ['in', 'notIn'].includes(operator) ? [value] : value },
    ] };
    const proof = await x.analyze();
    assert.equal(proof.qualified, false);
    assert.equal(proof.analysis.blockers[0].condition, 'unknown');
  }
  for (const field of ['name', 'fullName', network]) {
    const x = effectivePolicyFixture();
    const value = field === network ? 'En abled' : x.phase.resources[0].expected.name.replace('msrtq', 'ms rtq');
    x.definition.properties.policyRule.if = { allOf: [
      { field: 'type', equals: x.phase.resources[0].type }, { field, equals: value },
    ] };
    assert.equal((await x.analyze()).qualified, true);
  }
});

test('nested AND/OR/not unknown tags and resourceGroup expressions cannot create an exemption', async t => {
  const unknown = { value: "[resourceGroup().tags['unit-tag']]", equals: 'unit-value' };
  const type = { field: 'type', equals: 'Microsoft.Storage/storageAccounts' };
  for (const [name, rule, compatible] of [
    ['and unknown', { allOf: [type, unknown] }, false],
    ['or unknown', { anyOf: [{ field: 'type', equals: 'Unit/unrelated' }, unknown] }, false],
    ['not unknown', { not: unknown }, false],
    ['double not unknown', { not: { not: unknown } }, false],
    ['and false', { allOf: [{ field: 'type', equals: 'Unit/unrelated' }, unknown] }, true],
    ['not true or', { not: { anyOf: [type, unknown] } }, true],
    ['or true', { anyOf: [type, unknown] }, false],
  ]) await t.test(name, async () => {
    const x = effectivePolicyFixture(); x.definition.properties.policyRule.if = { allOf: [type, rule] };
    const proof = await x.analyze();
    assert.equal(proof.qualified, compatible);
  });
});

test('stored logical-key casing preserves type guards without normalizing literals or unknown operators', async () => {
  const x = effectivePolicyFixture();
  x.definition.properties.policyRule.if = {
    AllOf: [
      { AnyOf: [{ field: 'type', Equals: 'Microsoft.Compute/virtualMachines' }] },
      { unknownOperator: 'unresolved' },
    ],
  };
  const before = structuredClone(x.definition);
  assert.equal((await x.analyze()).qualified, true);
  assert.deepEqual(x.definition, before);
  x.definition.properties.policyRule.if.AllOf[0].AnyOf[0].Equals = 'Microsoft.Storage/storageAccounts';
  assert.equal((await x.analyze()).qualified, false);
  x.definition.properties.policyRule.if = {
    allof: [{ field: 'type', equals: 'Microsoft.Storage/storageAccounts' }, { field: network, notEquals: 'Disabled' }],
  };
  assert.equal((await x.analyze()).qualified, false);
  x.definition.properties.policyRule.if = {
    allOf: [{ field: 'type', equals: 'Microsoft.Compute/virtualMachines' }],
    AllOf: [{ field: 'type', equals: 'Microsoft.Storage/storageAccounts' }],
  };
  assert.equal((await x.analyze()).qualified, false, 'Conflicting case-folded keys must remain unresolved');
  x.definition.properties.policyRule.if = { unknownAllOf: [{ field: 'type', equals: 'Microsoft.Compute/virtualMachines' }] };
  assert.equal((await x.analyze()).qualified, false);
});

test('assignment to initiative to definition forwarding and defaults are exact evidence, not ignored overrides', async () => {
  const x = effectivePolicyFixture();
  x.initiative.properties.parameters = { behavior: { type: 'String', defaultValue: 'audit' } };
  x.initiative.properties.policyDefinitions[0].parameters = { effect: { value: "[parameters('behavior')]" } };
  assert.equal((await x.analyze()).qualified, true);
  x.assignment.properties.parameters = { behavior: { value: 'modify' } };
  const blocked = await x.analyze();
  assert.equal(blocked.qualified, false);
  x.assignment.properties.parameters = { behavior: { value: 'disabled' } };
  assert.equal((await x.analyze()).qualified, true);
  x.assignment.properties.parameters.behavior.value = "[concat('audit','')]";
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED/);
  delete x.assignment.properties.parameters.behavior;
  delete x.initiative.properties.parameters.behavior.defaultValue;
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED/);
});

test('array allowedValues validates each selected item through defaults and initiative forwarding', async () => {
  const x = effectivePolicyFixture();
  x.initiative.properties.parameters = {
    selectedTypes: { type: 'Array', defaultValue: ['Microsoft.Storage/storageAccounts'],
      allowedValues: ['Microsoft.Storage/storageAccounts', 'Microsoft.Compute/virtualMachines'] },
  };
  x.definition.properties.parameters.selectedTypes = {
    type: 'Array', defaultValue: [], allowedValues: ['Microsoft.Storage/storageAccounts', 'Microsoft.Compute/virtualMachines'],
  };
  x.initiative.properties.policyDefinitions[0].parameters = { selectedTypes: { value: "[parameters('selectedTypes')]" } };
  x.definition.properties.policyRule.if = { field: 'type', in: "[parameters('selectedTypes')]" };
  assert.equal((await x.analyze()).qualified, false, 'Valid array must not hide the matching network rewrite');
  x.assignment.properties.parameters = { selectedTypes: { value: ['Microsoft.Compute/virtualMachines'] } };
  assert.equal((await x.analyze()).qualified, true);
  x.assignment.properties.parameters.selectedTypes.value = [
    'Microsoft.Compute/virtualMachines', 'Microsoft.Storage/storageAccounts',
  ];
  assert.equal((await x.analyze()).qualified, false);
  x.assignment.properties.parameters.selectedTypes.value = [];
  assert.equal((await x.analyze()).qualified, true);
  for (const value of [
    ['Microsoft.Storage/storageAccounts', 'unlisted'], ['microsoft.storage/storageaccounts'],
    [['Microsoft.Storage/storageAccounts']], [null], 'Microsoft.Storage/storageAccounts',
  ]) {
    x.assignment.properties.parameters.selectedTypes.value = value;
    await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED/);
  }
});

test('allowedValues assignment validation remains case-sensitive and rejects malformed lists', async () => {
  const x = effectivePolicyFixture();
  x.definition.properties.parameters.effect.allowedValues = ['modify', 'audit', 'disabled', 'deny'];
  x.initiative.properties.policyDefinitions[0].parameters = { effect: { value: 'AUDIT' } };
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED/);
  x.initiative.properties.policyDefinitions[0].parameters.effect.value = 'audit';
  assert.equal((await x.analyze()).qualified, true);
  for (const allowedValues of [null, false, {}, 'audit', [], undefined]) {
    x.definition.properties.parameters.effect.allowedValues = allowedValues;
    await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_UNRESOLVED/);
  }
});

test('all matching unpinned versions are checked; no optimistic latest-version selection', async () => {
  const x = effectivePolicyFixture();
  delete x.initiative.properties.policyDefinitions[0].definitionVersion;
  x.definition.properties.policyRule.then.effect = 'audit';
  const other = structuredClone(x.definition);
  other.id = `${x.definitionId}/versions/1.1.0`; other.properties.version = '1.1.0';
  other.properties.policyRule.then.effect = 'modify';
  x.catalog.value.push({ id: other.id, properties: { version: '1.1.0' } });
  x.responses.set(other.id, other);
  const ambiguous = await x.analyze();
  assert.equal(ambiguous.qualified, false);
  assert(ambiguous.analysis.blockers.some(v => v.definitionVersion === '1.1.0'));
  x.initiative.properties.policyDefinitions[0].definitionVersion = '1.0.0';
  const exact = await x.analyze();
  assert.equal(exact.qualified, true);
  assert(exact.analysis.observations.every(v => v.versionResolution === 'exact-version'));
  x.initiative.properties.policyDefinitions[0].effectiveDefinitionVersion = '2.0.0';
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_VERSION_INVALID/);
});

test('preview annotations preserve legacy matches while explicit wildcards auto-ingest numeric updates', async () => {
  const x = effectivePolicyFixture(), reference = x.initiative.properties.policyDefinitions[0];
  reference.definitionVersion = '1.*.*-preview';
  x.catalog.value = [];
  for (const [version, effect] of [['1.0.0-preview', 'audit'], ['1.1.0-preview', 'modify'], ['1.2.0', 'audit']]) {
    const definition = structuredClone(x.definition);
    definition.id = `${x.definitionId}/versions/${version}`;
    definition.properties.version = version;
    definition.properties.policyRule.then.effect = effect;
    x.catalog.value.push(structuredClone(definition));
    x.responses.set(definition.id, definition);
  }
  const current = await x.analyze();
  assert.equal(current.version, 2);
  assert.equal(current.qualified, true);
  assert.deepEqual([...new Set(current.analysis.observations.map(value => value.definitionVersion))], ['1.2.0']);
  const ambiguous = analyzeEffectivePolicies(x.phase, current.snapshot, 1);
  assert.equal(ambiguous.qualified, false);
  assert.deepEqual([...new Set(ambiguous.analysis.observations.map(value => value.definitionVersion))].sort(),
    ['1.0.0-preview', '1.1.0-preview', '1.2.0']);
  assert(ambiguous.analysis.blockers.some(value => value.definitionVersion === '1.1.0-preview'));
  reference.effectiveDefinitionVersion = '1.0.0-preview';
  assert.equal((await x.analyze()).qualified, true);
  reference.effectiveDefinitionVersion = '1.2.0';
  assert.equal((await x.analyze()).qualified, true, 'GA promotion must not hide a still-assigned policy');
  reference.effectiveDefinitionVersion = '2.0.0';
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_VERSION_INVALID/);
  delete reference.effectiveDefinitionVersion;
  reference.definitionVersion = '1.0.0-preview';
  assert.equal((await x.analyze()).qualified, true);
  reference.policyDefinitionId = `${x.definitionId}/versions/1.0.0-preview`;
  assert.equal((await x.analyze()).qualified, true);
  reference.policyDefinitionId = x.definitionId;
  reference.definitionVersion = '2.*.*-preview';
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_VERSION_UNRESOLVED/);
  for (const selector of ['1.*.*-other', '1.*.*-preview.1', '1.*.*-Preview', '1.*.0-preview']) {
    reference.definitionVersion = selector;
    await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_VERSION_INVALID/);
  }
});

test('explicit wildcard selection uses the newest matching schema without ignoring unknown parameters', async () => {
  const x = effectivePolicyFixture(), reference = x.initiative.properties.policyDefinitions[0];
  x.definition.properties.policyRule.then.effect = 'audit';
  reference.parameters = { excludedManagedByResourceProviders: { value: [] } };
  const latest = structuredClone(x.definition);
  latest.id = `${x.definitionId}/versions/1.2.0`; latest.properties.version = '1.2.0';
  latest.properties.parameters.excludedManagedByResourceProviders = { type: 'Array', defaultValue: [] };
  x.catalog.value = [structuredClone(x.definition), latest];
  const current = await x.analyze();
  assert.equal(current.qualified, true);
  assert(current.analysis.observations.every(value => value.definitionVersion === '1.2.0'));
  verifyEffectivePolicyEvidence(x.phase, current);
  assert.throws(() => analyzeEffectivePolicies(x.phase, current.snapshot, 1), /EFFECTIVE_POLICY_PARAMETERS_INVALID/);
  reference.effectiveDefinitionVersion = '1.0.0';
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_INVALID/);
  delete reference.effectiveDefinitionVersion;
  reference.parameters.unrecognized = { value: [] };
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_PARAMETERS_INVALID/);
});

test('numeric wildcard updates cannot choose a safer old version or cross a pinned major/minor', async () => {
  const x = effectivePolicyFixture(), reference = x.initiative.properties.policyDefinitions[0];
  x.catalog.value = [];
  for (const [version, effect] of [['1.9.0', 'audit'], ['1.10.0', 'deny'], ['1.10.1', 'audit'], ['2.0.0', 'deny']]) {
    const definition = structuredClone(x.definition);
    definition.id = `${x.definitionId}/versions/${version}`; definition.properties.version = version;
    definition.properties.policyRule.then.effect = effect;
    x.catalog.value.push(definition);
  }
  let current = await x.analyze();
  assert.equal(current.qualified, true);
  assert(current.analysis.observations.every(value => value.definitionVersion === '1.10.1'));
  reference.definitionVersion = '1.9.*';
  assert((await x.analyze()).analysis.observations.every(value => value.definitionVersion === '1.9.0'));
  reference.definitionVersion = '1.*.*';
  x.catalog.value = x.catalog.value.filter(value => value.properties.version !== '1.10.1');
  current = await x.analyze();
  assert.equal(current.qualified, false);
  assert(current.analysis.blockers.every(value => value.definitionVersion === '1.10.0'));
  const tied = structuredClone(x.catalog.value.find(value => value.properties.version === '1.10.0'));
  tied.id += '-preview'; tied.properties.version += '-preview'; tied.properties.policyRule.then.effect = 'audit';
  x.catalog.value.push(tied);
  current = await x.analyze();
  assert.equal(current.qualified, false, 'preview status ties cannot hide a potentially enforced rule');
  assert.deepEqual([...new Set(current.analysis.observations.map(value => value.definitionVersion))].sort(), ['1.10.0', '1.10.0-preview']);
});

test('historical version-one evidence is rechecked with its original algorithm, never relabeled', async () => {
  const x = effectivePolicyFixture();
  x.definition.properties.policyRule.then.effect = 'audit';
  const latest = structuredClone(x.definition);
  latest.id = `${x.definitionId}/versions/1.1.0`; latest.properties.version = '1.1.0';
  x.catalog.value = [structuredClone(x.definition), latest];
  const current = await x.analyze(), historical = analyzeEffectivePolicies(x.phase, current.snapshot, 1);
  const original = structuredClone(historical);
  assert.equal(historical.version, 1);
  assert(historical.analysis.observations.every(value => value.versionResolution === 'all-matching-versions'));
  assert.equal(historical.analysis.observations.length, current.analysis.observations.length * 2);
  verifyEffectivePolicyEvidence(x.phase, historical);
  assert.deepEqual(historical, original);
  assert.throws(() => verifyEffectivePolicyEvidence(x.phase, { ...historical, version: 2 }), /EFFECTIVE_POLICY_BINDING_INVALID/);
  assert.throws(() => verifyEffectivePolicyEvidence(x.phase, { ...current, version: 1 }), /EFFECTIVE_POLICY_BINDING_INVALID/);
  assert.throws(() => analyzeEffectivePolicies(x.phase, current.snapshot, 3), /EFFECTIVE_POLICY_BINDING_INVALID/);
});

test('complete version-list documents avoid redundant reads while summary lists still require exact GETs', async () => {
  const x = effectivePolicyFixture();
  x.catalog.value = [structuredClone(x.definition)];
  const proof = await x.analyze();
  assert.equal(proof.qualified, false);
  assert.equal(x.calls.length, 4);
  assert(!x.calls.some(call => call.id === x.definition.id));
  const oldStyle = structuredClone(proof);
  oldStyle.snapshot.reads.push({ id: x.definition.id, apiVersion: POLICY_API, filter: null,
    response: structuredClone(x.definition) });
  assert.deepEqual(analyzeEffectivePolicies(x.phase, oldStyle.snapshot).analysis, proof.analysis);
  oldStyle.snapshot.reads.at(-1).response.properties.policyRule.then.effect = 'audit';
  assert.throws(() => analyzeEffectivePolicies(x.phase, oldStyle.snapshot), /EFFECTIVE_POLICY_DEFINITION_DRIFT/);
  x.calls.length = 0;
  x.catalog.value = [{ id: x.definition.id, properties: { version: '1.0.0' } }];
  assert.equal((await x.analyze()).qualified, false);
  assert.equal(x.calls.length, 5);
  assert(x.calls.some(call => call.id === x.definition.id));
  x.catalog.value = [structuredClone(x.definition)];
  x.catalog.value[0].properties.policyRule = null;
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_RULE_INVALID/);
});

test('potential network/auth/logging mutations outside the subset fail closed with sanitized reasons', async t => {
  for (const [name, mutate, reason] of [
    ['logging deployment', d => { d.policyRule.then.effect = 'deployIfNotExists'; }, 'UNSUPPORTED_POTENTIAL_MUTATION'],
    ['unknown effect', d => { d.policyRule.then.effect = 'unit-private-effect'; }, 'UNSUPPORTED_POTENTIAL_MUTATION'],
    ['unknown mode', d => { d.mode = 'Unit/dataMode'; }, 'UNSUPPORTED_POLICY_MODE'],
    ['unknown alias', d => { d.policyRule.then.details.operations[0].field = 'Unit/privateAlias'; }, 'UNSUPPORTED_MODIFY_OPERATION'],
    ['remove', d => { d.policyRule.then.details.operations[0].operation = 'remove'; }, 'UNSUPPORTED_MODIFY_OPERATION'],
    ['append', d => { d.policyRule.then.effect = 'append'; }, 'UNSUPPORTED_POTENTIAL_MUTATION'],
    ['deny', d => { d.policyRule.then.effect = 'deny'; }, 'POTENTIAL_DENY'],
    ['shared key mutation', d => { d.policyRule.then.details.operations[0].field = 'Microsoft.Storage/storageAccounts/allowSharedKeyAccess';
      d.policyRule.then.details.operations[0].value = true; }, 'REQUEST_REWRITTEN'],
  ]) await t.test(name, async () => {
    const x = effectivePolicyFixture(); mutate(x.definition.properties);
    const proof = await x.analyze();
    assert.equal(proof.qualified, false);
    assert(proof.analysis.blockers.some(v => v.reason === reason));
    assert.doesNotMatch(json(proof.analysis), /unit-private|Unit\/privateAlias/u);
  });
  const compatible = effectivePolicyFixture();
  compatible.definition.properties.policyRule.then.details.operations[0].field = 'Microsoft.Storage/storageAccounts/allowSharedKeyAccess';
  compatible.definition.properties.policyRule.then.details.operations[0].value = false;
  assert.equal((await compatible.analyze()).qualified, true);
});

test('assignment overrides cannot turn a nominal audit/disabled effect into an unchecked mutation', async () => {
  for (const effect of ['audit', 'disabled']) {
    const x = effectivePolicyFixture(); x.definition.properties.policyRule.then.effect = effect;
    x.assignment.properties.overrides = [{ kind: 'policyEffect', value: 'modify' }];
    assert.equal((await x.analyze()).analysis.blockers[0].reason, 'UNSUPPORTED_ASSIGNMENT_SELECTOR_OR_OVERRIDE');
  }
});

test('exemption scope/reference/category/expiration evidence is retained but never grants a mutation bypass', async () => {
  for (const expiresOn of [undefined, '2020-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z']) {
    const x = effectivePolicyFixture();
    x.exemptions.value.push({ id: `${x.f.r.group}/providers/Microsoft.Authorization/policyExemptions/unit`,
      properties: { policyAssignmentId: x.assignment.id.toUpperCase(), exemptionCategory: 'Mitigated',
        policyDefinitionReferenceIds: ['unit-storage'], ...(expiresOn ? { expiresOn } : {}) } });
    const proof = await x.analyze();
    assert.equal(proof.qualified, false);
    assert.equal(proof.analysis.blockers[0].reason, 'MUTATION_CONFLICT_EXEMPTION_REVIEW_REQUIRED');
    assert.equal(proof.analysis.exemptionsApplied, false);
    x.exemptions.value[0].properties.policyDefinitionReferenceIds = ['unrelated'];
    assert.equal((await x.analyze()).analysis.blockers[0].reason, 'REQUEST_REWRITTEN');
    x.exemptions.value[0].properties.expiresOn = 'not-an-instant';
    await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_EXEMPTION_INVALID/);
  }
});

test('unproven scope, malformed parameters, pagination, duplicate and absent version evidence fail closed', async t => {
  for (const [name, mutate, error] of [
    ['assignment page', x => { x.assignments.nextLink = 'https://unit.invalid/private'; }, 'LIST_INCOMPLETE'],
    ['exemption page', x => { x.exemptions.nextLink = 'more'; }, 'LIST_INCOMPLETE'],
    ['version page', x => { x.catalog.nextLink = 'more'; }, 'LIST_INCOMPLETE'],
    ['empty versions', x => { x.catalog.value = []; }, 'VERSION_UNRESOLVED'],
    ['duplicate versions', x => { x.catalog.value.push(x.catalog.value[0]); }, 'VERSION_UNRESOLVED'],
    ['foreign version id', x => { x.catalog.value[0].id = '/unit-private'; }, 'VERSION_INVALID'],
    ['version body mismatch', x => { x.definition.properties.version = '9.0.0'; }, 'VERSION_INVALID'],
    ['definition missing', x => { x.responses.set(x.definition.id, null); }, 'DEFINITION_INVALID'],
    ['foreign assignment scope', x => { x.assignment.properties.scope = '/subscriptions/00000000-0000-4000-8000-000000000099';
      x.assignment.id = x.assignment.properties.scope + '/providers/Microsoft.Authorization/policyAssignments/unit'; }, 'ASSIGNMENT_SCOPE_UNPROVEN'],
    ['scope identity mismatch', x => { x.assignment.properties.scope = x.f.r.group; }, 'ASSIGNMENT_INVALID'],
    ['malformed notScope', x => { x.assignment.properties.notScopes = ['/unit?private']; }, 'ASSIGNMENT_INVALID'],
    ['unknown enforcement', x => { x.assignment.properties.enforcementMode = 'Unknown'; }, 'ASSIGNMENT_INVALID'],
    ['missing default', x => { delete x.definition.properties.parameters.effect.defaultValue; }, 'PARAMETERS_UNRESOLVED'],
    ['unknown parameter', x => { x.assignment.properties.parameters = { unexpected: { value: true } }; }, 'PARAMETERS_INVALID'],
    ['foreign subscription definition', x => { x.assignment.properties.policyDefinitionId =
      '/subscriptions/00000000-0000-4000-8000-000000000099/providers/Microsoft.Authorization/policyDefinitions/unit'; }, 'REFERENCE_INVALID'],
    ['nested initiative', x => { x.initiative.properties.policyDefinitions[0].policyDefinitionId = x.setId; }, 'INITIATIVE_INVALID'],
    ['unsupported wildcard shape', x => { x.initiative.properties.policyDefinitions[0].definitionVersion = '1.*.0'; }, 'VERSION_INVALID'],
  ]) await t.test(name, async () => {
    const x = effectivePolicyFixture(); mutate(x);
    await assert.rejects(x.analyze(), new RegExp(`EFFECTIVE_POLICY_${error}`, 'u'));
  });
});

test('definition drift, including safe-effect changes, invalidates the fresh evidence hash and never reuses approvals', async t => {
  const x = effectivePolicyFixture(), directory = await scratch(t);
  x.definition.properties.policyRule.then.effect = 'audit';
  const first = await checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology);
  assert.equal(first.effectivePolicyVersion, 1);
  assert.equal(first.effectivePolicySha256, digest(json(first.effectivePolicy)));
  await checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology, first.effectivePolicySha256);
  x.definition.properties.policyRule.then.effect = 'disabled';
  await assert.rejects(checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology, first.effectivePolicySha256),
    /EFFECTIVE_POLICY_DRIFT/);
  x.definition.properties.policyRule.then.effect = 'modify';
  await assert.rejects(checkEffectivePolicies(x.f.c, x.phase, directory, x.invoke, x.f.topology, first.effectivePolicySha256),
    /EFFECTIVE_POLICY_CONFLICT/);
  const forged = structuredClone(first.effectivePolicy); forged.analysis.observations = [];
  assert.throws(() => verifyEffectivePolicyEvidence(x.phase, forged), /EFFECTIVE_POLICY_BINDING_INVALID/);
  const wrongPhase = structuredClone(x.phase); wrongPhase.resources[0].expected.properties.publicNetworkAccess = 'Disabled';
  assert.throws(() => verifyEffectivePolicyEvidence(wrongPhase, first.effectivePolicy), /EFFECTIVE_POLICY_BINDING_INVALID/);
});

test('scoped routes remain GET-only, explicit-account authenticated, bounded and four-way concurrency limited', async t => {
  const x = effectivePolicyFixture(), directory = await scratch(t);
  delete x.initiative.properties.policyDefinitions[0].definitionVersion;
  x.definition.properties.policyRule.then.effect = 'audit';
  for (let i = 1; i < 9; i++) {
    const version = `1.${i}.0`, d = structuredClone(x.definition);
    d.id = `${x.definitionId}/versions/${version}`; d.properties.version = version;
    x.catalog.value.push({ id: d.id, properties: { version } }); x.responses.set(d.id, d);
  }
  let active = 0, maximum = 0;
  await checkEffectivePolicies(x.f.c, x.phase, directory, async (args, timeout) => {
    assert(timeout > 0 && timeout <= 15000);
    assert.equal(args[args.indexOf('--subscription') + 1], x.f.c.subscriptionId);
    assert.equal(args[args.indexOf('--method') + 1], 'GET');
    assert(!args.includes('--body'));
    active++; maximum = Math.max(maximum, active);
    await new Promise(resolve => setImmediate(resolve));
    try { return await x.invoke(args); } finally { active--; }
  }, x.f.topology);
  assert.equal(maximum, 4);
  const arm = transport(x.f.c, x.phase, directory, async () => { throw new Error('UNEXPECTED_DISPATCH'); }, x.f.topology);
  await assert.rejects(arm('GET', x.definition.id, POLICY_API), /ARM_SCOPE_FORBIDDEN/);
  await assert.rejects(arm('PUT', x.definition.id, POLICY_API, {}), /ARM_SCOPE_FORBIDDEN/);
  await assert.rejects(arm('GET', `${x.f.r.group}/providers/Microsoft.Authorization/policyExemptions`, EXEMPTION_API), /ARM_SCOPE_FORBIDDEN/);
  const foreign = structuredClone(x.phase);
  for (const resource of foreign.resources) resource.id = resource.id.replace(x.f.c.subscriptionId, '00000000-0000-4000-8000-000000000099');
  await assert.rejects(checkEffectivePolicies(x.f.c, foreign, directory, async () => { throw new Error('UNEXPECTED_DISPATCH'); }, x.f.topology),
    /EFFECTIVE_POLICY_SCOPE_FORBIDDEN/);
});

test('read errors/deadlines retain partial private evidence without success-shaped fallback or unbounded calls', async t => {
  for (const mode of ['forbidden', 'missing', 'pagination', 'timeout']) await t.test(mode, async t => {
    const x = effectivePolicyFixture(), directory = await scratch(t);
    let at = 1000;
    const invoke = async (args, timeout) => {
      assert(timeout <= 15000);
      const url = new URL(args[args.indexOf('--url') + 1]);
      if (url.pathname === x.initiative.id) {
        if (mode === 'forbidden') throw Object.assign(new Error('ARM_OPERATION_FAILED'), { httpStatus: 403, armCode: 'AuthorizationFailed' });
        if (mode === 'missing') return null;
        if (mode === 'pagination') return { ...x.initiative, nextLink: 'https://unit.invalid/private' };
        at = 121000;
      }
      return x.invoke(args);
    };
    await assert.rejects(checkEffectivePolicies(x.f.c, x.phase, directory, invoke, x.f.topology, undefined, { now: () => at }));
    const failure = JSON.parse(await readFile(`${directory}/queue-storage-effective-policy-failure.json`, 'utf8'));
    assert.notEqual(failure.failure.code, 'OPERATION_FAILED');
    const partial = JSON.parse(await readFile(`${directory}/queue-storage-effective-policy-reads.json`, 'utf8'));
    assert(partial.reads.length >= 2);
    if (mode === 'pagination') assert(partial.reads.some(v => v.response.nextLink));
    await assert.rejects(readFile(`${directory}/queue-storage-effective-policy.json`), { code: 'ENOENT' });
  });
});

test('finite catalog/item/byte/read limits reject expansion without following nextLink', async () => {
  const x = effectivePolicyFixture();
  x.catalog.value = Array.from({ length: POLICY_LIMITS.items + 1 }, () => x.catalog.value[0]);
  await assert.rejects(x.analyze(), /EFFECTIVE_POLICY_LIST_INCOMPLETE/);
  assert.equal(x.calls.length, 4);
  const y = effectivePolicyFixture();
  y.definition.properties.description = 'x'.repeat(POLICY_LIMITS.bytes);
  await assert.rejects(y.analyze(), /EFFECTIVE_POLICY_EVIDENCE_LIMIT/);
  const snapshot = emptyPolicySnapshot(y.phase);
  snapshot.reads.push(...Array.from({ length: POLICY_LIMITS.reads }, () => snapshot.reads[0]));
  assert.throws(() => analyzeEffectivePolicies(y.phase, snapshot), /EFFECTIVE_POLICY_EVIDENCE_LIMIT/);
});

test('empty evidence is reproducible and extra/missing/duplicate reads cannot be substituted', () => {
  const x = effectivePolicyFixture(), snapshot = emptyPolicySnapshot(x.phase);
  const proof = analyzeEffectivePolicies(x.phase, snapshot);
  verifyEffectivePolicyEvidence(x.phase, proof);
  assert.equal(proof.qualified, true);
  assert.throws(() => analyzeEffectivePolicies(x.phase, { reads: snapshot.reads.slice(1) }), /EVIDENCE_INCOMPLETE/);
  assert.throws(() => analyzeEffectivePolicies(x.phase, { reads: [...snapshot.reads, snapshot.reads[0]] }), /DUPLICATE_READ/);
});

test('source publication hashes include the new imported module but preserve pre-module historical bytes', async () => {
  const contract = await storageContract(), commit = 'a'.repeat(40);
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs', 'arm-whatif.py', 'receiver-upgrade.mjs', 'durable-queue.mjs'];
  const prefix = 'infrastructure/arm/telemetry/';
  const historical = Object.fromEntries(names.map(name => [prefix + name, `unit historical ${name}`]));
  const schemas = { 'assets/schemas/telemetry-event.schema.json': json(contract.schema),
    'services/telemetry-ingest/schema/storage-columns.json': json(contract.columns) };
  const nspNames = ['queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs'];
  for (const modern of [false, true, 'nsp']) {
    const files = { ...historical, ...schemas };
    if (modern) {
      files[prefix + 'controller.mjs'] = "import { collectEffectivePolicies } from './effective-policy.mjs';";
      files[prefix + 'effective-policy.mjs'] = 'unit new policy';
    }
    if (modern === 'nsp') for (const name of nspNames) {
      files[prefix + 'controller.mjs'] += `\nimport {} from './${name}';`;
      files[prefix + name] = `unit ${name}`;
    }
    const expected = createHash('sha256');
    for (const name of [...names, ...(modern ? ['effective-policy.mjs'] : []), ...(modern === 'nsp' ? nspNames : [])]) expected.update(name).update(files[prefix + name]);
    expected.update(json(contract));
    const run = async (_command, args) => {
      if (args[0] === 'merge-base') return { stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { stdout: Buffer.from(Object.hasOwn(files, args.at(-1)) ? args.at(-1) + '\n' : '') };
      const path = args.at(-1).slice(41);
      assert(Object.hasOwn(files, path), path);
      return { stdout: Buffer.from(files[path]) };
    };
    assert.equal(await publishedSourceDigest(commit, run), expected.digest('hex'));
  }
  const current = createHash('sha256');
  for (const name of [...names, 'effective-policy.mjs', ...nspNames, 'queue-defender.mjs', 'private-link.mjs', 'private-link-whatif.mjs',
    'private-link-controller.mjs', 'private-link-readback.mjs', 'private-link-runtime.mjs', 'private-link-exec.py']) current.update(name).update(await readFile(prefix + name));
  current.update(json(contract));
  assert.equal(await sourceDigest(), current.digest('hex'));
});
