import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { analyzeEffectivePolicies, collectEffectivePolicies, verifyEffectivePolicyEvidence,
  analyzeEffectivePoliciesV3, collectEffectivePoliciesV3, verifyEffectivePolicyEvidenceV3,
  POLICY_LIMITS, POLICY_API, EXEMPTION_API } from '../effective-policy.mjs';
import { effectivePolicyFixture } from './effective-policy.fixture.mjs';

const hash = value => digest(json(value));
const batch = (values, map) => Promise.all(values.map(map));
const expand = groups => groups.flatMap(({ resourceSha256s, ...detail }) =>
  resourceSha256s.map(resourceSha256 => ({ ...detail, resourceSha256 })));
const comparisons = observations => observations.map(value => JSON.stringify(Object.fromEntries(
  Object.entries(value).sort(([a], [b]) => a.localeCompare(b))))).sort();
function workspaceCapacity(sku = { name: 'PerGB2018' }, threshold = 100) {
  const x = effectivePolicyFixture();
  const resource = x.phase.resources[0], group = resource.id.split('/providers/')[0];
  x.phase.resources = [{ id: `${group}/providers/Microsoft.OperationalInsights/workspaces/unit-workspace`,
    type: 'Microsoft.OperationalInsights/workspaces', apiVersion: '2023-09-01',
    expected: { name: 'unit-workspace', properties: { sku } } }];
  x.definition.properties.mode = 'All';
  x.definition.properties.policyRule = { if: { allOf: [
    { field: 'type', equals: 'Microsoft.OperationalInsights/workspaces' },
    { field: 'Microsoft.OperationalInsights/workspaces/sku.capacityReservationLevel', greater: threshold },
  ] }, then: { effect: 'deny' } };
  return x;
}
async function collect(x, version = 3) {
  let retained;
  const evidence = await (version === 3 ? collectEffectivePoliciesV3 : collectEffectivePolicies)(
    x.phase, x.read, batch, async snapshot => { retained = structuredClone(snapshot); });
  assert.deepEqual(retained, evidence.snapshot);
  return evidence;
}
function many(resources = 20, references = 256) {
  const x = effectivePolicyFixture(), sample = x.phase.resources[0];
  x.phase.resources = Array.from({ length: resources }, (_, i) => ({
    ...structuredClone(sample), id: sample.id + i,
    expected: { ...structuredClone(sample.expected), name: sample.expected.name + i },
  }));
  x.definition.properties.policyRule.if = { field: 'type', equals: sample.type };
  x.definition.properties.policyRule.then.effect = 'audit';
  const reference = x.initiative.properties.policyDefinitions[0];
  x.initiative.properties.policyDefinitions = Array.from({ length: references }, (_, i) => ({
    ...structuredClone(reference), policyDefinitionReferenceId: `unit-${i}`,
  }));
  return x;
}

test('v1/v2 full historical evidence bytes and default collectors remain unchanged', async () => {
  const x = effectivePolicyFixture(), evidence = await collect(x, 2);
  assert.equal(evidence.version, 2);
  assert.equal(hash(evidence), '32af10b9230ab1ac5104cf669e3dfd607b8a75749f0666aa7998e5f33e07cfa0');
  const v1 = analyzeEffectivePolicies(x.phase, evidence.snapshot, 1);
  assert.equal(hash(v1), 'b8bd6a8ba1373493d647472686efd97ee2ebac347ac721f7688ba1a5247fca21');
  const grouped = analyzeEffectivePoliciesV3(x.phase, evidence.snapshot);
  assert.deepEqual(comparisons(expand(grouped.analysis.observations)), comparisons(evidence.analysis.observations));
  assert.deepEqual(comparisons(expand(grouped.analysis.blockers)), comparisons(evidence.analysis.blockers));
  assert.equal(grouped.analysis.observationCount, evidence.analysis.observations.length);
  assert.deepEqual(grouped.snapshot, evidence.snapshot);
  assert.throws(() => analyzeEffectivePolicies(x.phase, evidence.snapshot, 3), /BINDING_INVALID/);
  x.definition.properties.policyRule.then.effect = 'audit';
  const safe = await collect(x, 2), modern = analyzeEffectivePoliciesV3(x.phase, safe.snapshot);
  for (const v of [1, 2]) verifyEffectivePolicyEvidence(x.phase, analyzeEffectivePolicies(x.phase, safe.snapshot, v));
  verifyEffectivePolicyEvidenceV3(x.phase, modern);
  assert.throws(() => verifyEffectivePolicyEvidence(x.phase, modern), /BINDING_INVALID/);
  assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, safe), /BINDING_INVALID/);
  assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, { ...safe, version: 3 }), /BINDING_INVALID/);
});

test('v3 alone evaluates the pinned workspace capacity predicate without an exemption or guessed numeric default', async () => {
  for (const [sku, expected] of [
    [{ name: 'PerGB2018' }, false],
    [{ name: 'CapacityReservation', capacityReservationLevel: 100 }, false],
    [{ name: 'CapacityReservation', capacityReservationLevel: 200 }, true],
  ]) {
    const x = workspaceCapacity(sku), bytes = json(x.phase), evidence = await collect(x);
    assert.equal(evidence.analysis.observationCount, 1);
    assert.equal(evidence.analysis.observations[0].condition, expected);
    assert.equal(evidence.qualified, !expected);
    assert.equal(evidence.analysis.exemptionsApplied, false);
    assert.equal(evidence.analysis.observations[0].exemptionsApplied, false);
    assert.equal(json(x.phase), bytes);
    const legacy = analyzeEffectivePolicies(x.phase, evidence.snapshot);
    assert.equal(legacy.qualified, false);
    assert.equal(legacy.analysis.blockers[0].condition, 'unknown');
    assert.equal(analyzeEffectivePolicies(x.phase, evidence.snapshot, 1).qualified, false);
    if (expected) {
      assert.equal(evidence.analysis.blockers[0].reason, 'POTENTIAL_DENY');
      assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, evidence), /BINDING_INVALID/);
    } else {
      assert.equal(evidence.analysis.observations[0].reason, 'RULE_FALSE');
      verifyEffectivePolicyEvidenceV3(x.phase, evidence);
    }
  }
});

test('unsupported workspace capacity shapes and numeric types stay unknown and blocked', async t => {
  for (const [name, mutate] of [
    ['absent sku', x => { delete x.phase.resources[0].expected.properties.sku; }],
    ['missing committed level', x => { x.phase.resources[0].expected.properties.sku.name = 'CapacityReservation'; }],
    ['unknown sku', x => { x.phase.resources[0].expected.properties.sku.name = 'Free'; }],
    ['null level', x => { x.phase.resources[0].expected.properties.sku.capacityReservationLevel = null; }],
    ['string level', x => { x.phase.resources[0].expected.properties.sku = { name: 'CapacityReservation', capacityReservationLevel: '200' }; }],
    ['fractional level', x => { x.phase.resources[0].expected.properties.sku = { name: 'CapacityReservation', capacityReservationLevel: 100.5 }; }],
    ['invalid minimum', x => { x.phase.resources[0].expected.properties.sku = { name: 'CapacityReservation', capacityReservationLevel: 0 }; }],
    ['level on pay-as-you-go', x => { x.phase.resources[0].expected.properties.sku.capacityReservationLevel = 100; }],
    ['string threshold', x => { x.definition.properties.policyRule.if.allOf[1].greater = '100'; }],
    ['unqualified missing-value threshold', x => { x.definition.properties.policyRule.if.allOf[1].greater = 200; }],
    ['negative threshold', x => { x.definition.properties.policyRule.if.allOf[1].greater = -1; }],
    ['unreviewed api', x => { x.phase.resources[0].apiVersion = '2026-03-01'; }],
    ['unrecognized alias', x => { x.definition.properties.policyRule.if.allOf[1].field += 'Other'; }],
    ['other numeric field', x => { x.definition.properties.policyRule.if.allOf[1].field = 'Microsoft.OperationalInsights/workspaces/retentionInDays'; }],
    ['value instead of field', x => { x.definition.properties.policyRule.if.allOf[1] = { value: 200, greater: 100 }; }],
  ]) await t.test(name, async () => {
    const x = workspaceCapacity(); mutate(x);
    const evidence = await collect(x);
    assert.equal(evidence.qualified, false);
    assert.equal(evidence.analysis.blockers[0].condition, 'unknown');
    assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, evidence), /BINDING_INVALID/);
  });
});

test('capacity predicate respects logical operators and never suppresses other denies or unsupported assignment controls', async () => {
  const x = workspaceCapacity();
  const reservation = structuredClone(x.definition.properties.policyRule.if);
  x.definition.properties.policyRule.if = { not: reservation };
  assert.equal((await collect(x)).qualified, false);
  x.definition.properties.policyRule.if = { anyOf: [reservation, { field: 'type', equals: x.phase.resources[0].type }] };
  assert.equal((await collect(x)).qualified, false);
  x.definition.properties.policyRule.if = reservation;
  x.assignment.properties.overrides = [{}];
  const controlled = await collect(x);
  assert.equal(controlled.qualified, false);
  assert.equal(controlled.analysis.blockers[0].reason, 'UNSUPPORTED_ASSIGNMENT_SELECTOR_OR_OVERRIDE');
});

test('more than 4096 target observations fit as groups without dropping targets or raw reads', async () => {
  const x = many(), phaseBytes = json(x.phase), evidence = await collect(x);
  assert.equal(evidence.version, 3); assert.equal(evidence.qualified, true);
  assert.equal(evidence.analysis.observationCount, 5120);
  assert.equal(evidence.analysis.observations.length, 256);
  assert.equal(evidence.analysis.blockers.length, 0);
  const members = x.phase.resources.map(hash);
  for (const group of evidence.analysis.observations) {
    assert.deepEqual(group.resourceSha256s, members);
    assert.equal(Object.hasOwn(group, 'resourceSha256'), false);
  }
  assert.equal(expand(evidence.analysis.observations).length, 5120);
  assert.equal(evidence.snapshot.reads.length, 5);
  assert.equal(new Set(x.calls.map(value => JSON.stringify(value))).size, x.calls.length);
  assert(Buffer.byteLength(json(evidence.snapshot)) < POLICY_LIMITS.bytes);
  verifyEffectivePolicyEvidenceV3(x.phase, JSON.parse(json(evidence)));
  assert.equal(json(x.phase), phaseBytes);
  assert.throws(() => analyzeEffectivePolicies(x.phase, evidence.snapshot), /EVIDENCE_LIMIT/);
  assert.throws(() => analyzeEffectivePolicies(x.phase, evidence.snapshot, 1), /EVIDENCE_LIMIT/);
  await assert.rejects(collect(x, 2), /EVIDENCE_LIMIT/);
});

test('each distinct semantic result remains separate, including repeated identical operations on one target', async () => {
  const x = many(4, 2);
  x.definition.properties.policyRule.then.effect = 'modify';
  x.definition.properties.policyRule.then.details.operations = [
    { operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', value: 'Disabled' },
    { operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', value: 'Disabled' },
    { operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/publicNetworkAccess', value: 'Enabled', condition: false },
    { operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/allowSharedKeyAccess', value: false },
  ];
  x.phase.resources[0].expected.properties.publicNetworkAccess = 'Disabled';
  x.phase.resources[1].expected.properties.publicNetworkAccess = 'SecuredByPerimeter';
  const legacy = await collect(x, 2), grouped = await collect(x);
  assert.equal(grouped.qualified, false); assert.equal(grouped.analysis.observationCount, 32);
  assert.deepEqual(comparisons(expand(grouped.analysis.observations)), comparisons(legacy.analysis.observations));
  assert.deepEqual(comparisons(expand(grouped.analysis.blockers)), comparisons(legacy.analysis.blockers));
  assert(grouped.analysis.observations.some(value => value.reason === 'EXACT_REQUEST_PRESERVED'));
  assert(grouped.analysis.observations.some(value => value.reason === 'OPERATION_FALSE'));
  assert(grouped.analysis.observations.some(value => value.reason === 'REQUEST_REWRITTEN'));
  for (const group of grouped.analysis.observations) assert.equal(new Set(group.resourceSha256s).size, group.resourceSha256s.length);
  const repeated = grouped.analysis.observations.filter(value => value.reason === 'REQUEST_REWRITTEN' && value.requested === 'Enabled');
  assert.equal(repeated.length, 4, 'two reference IDs times two identical operations must remain four groups');
  assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, { ...grouped, qualified: true }), /BINDING_INVALID/);
});

test('conditions and exemption evidence separate otherwise identical observations', async () => {
  const x = many(4, 1);
  x.definition.properties.policyRule.if = { field: 'location', equals: 'australiaeast' };
  delete x.phase.resources[1].expected.location;
  x.phase.resources[2].expected.location = 'westus';
  x.exemptions.value.push({ id: `${x.phase.resources[3].id}/providers/Microsoft.Authorization/policyExemptions/unit`,
    properties: { policyAssignmentId: x.assignment.id, exemptionCategory: 'Waiver', policyDefinitionReferenceIds: ['unit-0'] } });
  const old = await collect(x, 2), grouped = await collect(x);
  assert.equal(grouped.analysis.observations.length, 4);
  assert.deepEqual(comparisons(expand(grouped.analysis.observations)), comparisons(old.analysis.observations));
  assert.deepEqual(grouped.analysis.observations.map(value => value.condition), [true, 'unknown', false, true]);
  assert.notEqual(grouped.analysis.observations[0].exemptionEvidenceSha256, grouped.analysis.observations[3].exemptionEvidenceSha256);
  assert(grouped.analysis.observations.every(value => value.exemptionsApplied === false));
});

test('grouping preserves unknown, selector, exemption, mutation and nonmutating semantics', async t => {
  for (const [name, mutate] of [
    ['conflicting mutation', x => {}],
    ['unsupported alias', x => { x.definition.properties.policyRule.then.details.operations[0].field = 'Unit/unknown'; }],
    ['unknown condition', x => { x.definition.properties.policyRule.if = { field: 'Unit/unknown', equals: true }; }],
    ['assignment selector', x => { x.assignment.properties.resourceSelectors = [{ name: 'unit', selectors: [] }]; }],
    ['assignment override', x => { x.assignment.properties.overrides = [{ kind: 'policyEffect', value: 'audit' }]; }],
    ['exemption is not applied', x => { x.exemptions.value.push({ id: `${x.f.r.group}/providers/Microsoft.Authorization/policyExemptions/unit`,
      properties: { policyAssignmentId: x.assignment.id, exemptionCategory: 'Mitigated' } }); }],
    ['unsupported policy mode', x => { x.definition.properties.mode = 'Unit/data'; }],
    ['deny', x => { x.definition.properties.policyRule.then.effect = 'deny'; }],
    ['unsupported effect', x => { x.definition.properties.policyRule.then.effect = 'unitUnknown'; }],
    ['nonmutating', x => { x.definition.properties.policyRule.then.effect = 'audit'; }],
    ['false rule', x => { x.definition.properties.policyRule.if = { field: 'type', equals: 'Unit/unused' }; }],
    ['not enforced', x => { x.assignment.properties.enforcementMode = 'DoNotEnforce'; }],
  ]) await t.test(name, async () => {
    const x = effectivePolicyFixture(); mutate(x);
    const old = await collect(x, 2), modern = await collect(x);
    assert.equal(modern.qualified, old.qualified);
    assert.deepEqual(modern.snapshot, old.snapshot);
    assert.deepEqual(comparisons(expand(modern.analysis.observations)), comparisons(old.analysis.observations));
    assert.deepEqual(comparisons(expand(modern.analysis.blockers)), comparisons(old.analysis.blockers));
    if (old.qualified) verifyEffectivePolicyEvidenceV3(x.phase, modern);
    else assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, modern), /BINDING_INVALID/);
  });
});

test('version and reference/parameter bindings cannot collapse into one group', async () => {
  const x = many(3, 2);
  const reference = x.initiative.properties.policyDefinitions[0];
  delete reference.definitionVersion;
  const latest = structuredClone(x.definition);
  latest.id = `${x.definitionId}/versions/1.1.0`; latest.properties.version = '1.1.0';
  x.catalog.value = [structuredClone(x.definition), latest];
  x.initiative.properties.policyDefinitions[1].parameters = { effect: { value: 'disabled' } };
  x.definition.properties.policyRule.then.effect = "[parameters('effect')]";
  x.definition.properties.parameters.effect.defaultValue = 'audit';
  latest.properties.policyRule = structuredClone(x.definition.properties.policyRule);
  latest.properties.parameters = structuredClone(x.definition.properties.parameters);
  x.catalog.value[0] = structuredClone(x.definition);
  const old = await collect(x, 2), modern = await collect(x);
  assert.deepEqual(comparisons(expand(modern.analysis.observations)), comparisons(old.analysis.observations));
  assert.equal(modern.analysis.observations.length, 3);
  assert.equal(new Set(modern.analysis.observations.map(value => value.referenceSha256)).size, 2);
  assert.equal(new Set(modern.analysis.observations.map(value => value.parametersSha256)).size, 2);
  assert.equal(new Set(modern.analysis.observations.map(value => value.definitionVersion)).size, 2);
  assert(modern.analysis.observations.some(value => value.versionResolution === 'all-matching-versions'));
  assert(modern.analysis.observations.some(value => value.versionResolution === 'latest-matching-versions'));
});

test('v3 inherits only v2 explicit wildcard semantics, never v1 or a new optimistic selection', async () => {
  const x = many(3, 1), reference = x.initiative.properties.policyDefinitions[0];
  const next = structuredClone(x.definition);
  next.id = `${x.definitionId}/versions/1.1.0`; next.properties.version = '1.1.0';
  next.properties.policyRule.then.effect = 'deny';
  x.catalog.value = [structuredClone(x.definition), next];
  const blocked = await collect(x);
  assert.equal(blocked.qualified, false);
  assert.equal(blocked.analysis.observationCount, 3);
  assert.equal(blocked.analysis.observations.length, 1);
  assert.equal(blocked.analysis.observations[0].definitionVersion, '1.1.0');
  assert.equal(blocked.analysis.observations[0].versionResolution, 'latest-matching-versions');
  const historical = analyzeEffectivePolicies(x.phase, blocked.snapshot, 1);
  assert.equal(historical.analysis.observations.length, 6);
  const previousHash = hash(historical);
  delete reference.definitionVersion;
  const all = await collect(x);
  assert.equal(all.analysis.observationCount, 6); assert.equal(all.analysis.observations.length, 2);
  assert(all.analysis.observations.every(value => value.versionResolution === 'all-matching-versions'));
  reference.definitionVersion = '1.0.0';
  const pinned = await collect(x);
  assert.equal(pinned.qualified, true);
  assert(pinned.analysis.observations.every(value => value.definitionVersion === '1.0.0'));
  assert.equal(hash(historical), previousHash);
});

test('explicit v3 verifier rejects malformed groups, memberships, evidence and changed targets', async t => {
  const x = many(4, 3), proof = await collect(x);
  for (const [name, mutate] of [
    ['group missing', v => { v.analysis.observations.pop(); }],
    ['group duplicated', v => { v.analysis.observations.push(structuredClone(v.analysis.observations[0])); }],
    ['group reordered', v => { v.analysis.observations.reverse(); }],
    ['member missing', v => { v.analysis.observations[0].resourceSha256s.pop(); }],
    ['member duplicated', v => { v.analysis.observations[0].resourceSha256s.push(v.analysis.observations[0].resourceSha256s[0]); }],
    ['member reordered', v => { v.analysis.observations[0].resourceSha256s.reverse(); }],
    ['member foreign', v => { v.analysis.observations[0].resourceSha256s[0] = digest('unit foreign resource'); }],
    ['member type changed', v => { v.analysis.observations[0].resourceSha256s[0] = { sha256: v.analysis.observations[0].resourceSha256s[0] }; }],
    ['members not array', v => { v.analysis.observations[0].resourceSha256s = hash(x.phase.resources[0]); }],
    ['empty members', v => { v.analysis.observations[0].resourceSha256s = []; }],
    ['old scalar member added', v => { v.analysis.observations[0].resourceSha256 = hash(x.phase.resources[0]); }],
    ['misstated raw count', v => { v.analysis.observationCount--; }],
    ['missing raw count', v => { delete v.analysis.observationCount; }],
    ['reason changed', v => { v.analysis.observations[0].reason = 'RULE_FALSE'; }],
    ['condition changed', v => { v.analysis.observations[0].condition = false; }],
    ['version changed', v => { v.analysis.observations[0].definitionVersion = '2.0.0'; }],
    ['selector ignored flag', v => { v.analysis.observations[0].selectorsIgnored = true; }],
    ['exemption claimed', v => { v.analysis.exemptionsApplied = true; }],
    ['foreign blockers', v => { v.analysis.blockers.push(v.analysis.observations[0]); }],
    ['extra top-level field', v => { v.validation = true; }],
    ['missing raw read', v => { v.snapshot.reads.pop(); }],
    ['changed raw rule', v => { v.snapshot.reads.find(read => read.id === x.definition.id).response.properties.policyRule.then.effect = 'deny'; }],
  ]) await t.test(name, () => {
    const changed = structuredClone(proof); mutate(changed);
    assert.throws(() => verifyEffectivePolicyEvidenceV3(x.phase, changed));
  });
  for (const mutate of [
    phase => { phase.resources.reverse(); },
    phase => { phase.resources[0].type = 'Unit/changed'; },
    phase => { phase.resources[0].expected.tags = { unit: 'changed' }; },
    phase => { phase.resources[0].id += '-changed'; },
  ]) {
    const phase = structuredClone(x.phase); mutate(phase);
    assert.throws(() => verifyEffectivePolicyEvidenceV3(phase, { ...proof, phaseSha256: hash(phase) }));
  }
});

test('v3 keeps 4096 groups, 32 distinct targets and the aggregate read/byte/item limits', async () => {
  assert.deepEqual(POLICY_LIMITS, { reads: 512, items: 512, observations: 4096, bytes: 8388608, depth: 24, waves: 8 });
  const x = many(32, 128);
  x.definition.properties.policyRule.then.effect = 'modify';
  x.definition.properties.policyRule.then.details.operations = [
    { operation: 'addOrReplace', field: 'Microsoft.Storage/storageAccounts/minimumTlsVersion', value: 'TLS1_2' },
  ];
  x.phase.resources.forEach((resource, i) => { resource.expected.properties.minimumTlsVersion = `UNIT-${i}`; });
  const boundary = await collect(x);
  assert.equal(boundary.analysis.observations.length, 4096);
  x.initiative.properties.policyDefinitions.push({ ...x.initiative.properties.policyDefinitions[0], policyDefinitionReferenceId: 'unit-128' });
  await assert.rejects(collect(x), /EVIDENCE_LIMIT/);
  for (const value of [33, 0]) {
    const y = many(value, 1);
    await assert.rejects(collect(y), /TARGETS_INVALID/);
  }
  const y = many(2, 1), proof = await collect(y);
  for (const phase of [
    { ...y.phase, resources: [y.phase.resources[0], y.phase.resources[0]] },
    { ...y.phase, resources: [y.phase.resources[0], { ...y.phase.resources[1], id: y.phase.resources[0].id.toUpperCase() }] },
  ]) assert.throws(() => analyzeEffectivePoliciesV3(phase, proof.snapshot), /TARGETS_INVALID/);
  const duplicated = { reads: Array.from({ length: 513 }, () => proof.snapshot.reads[0]) };
  assert.throws(() => analyzeEffectivePoliciesV3(y.phase, duplicated), /EVIDENCE_LIMIT/);
  const oversized = structuredClone(proof.snapshot);
  oversized.reads[0].response.metadata = 'x'.repeat(POLICY_LIMITS.bytes);
  assert.throws(() => analyzeEffectivePoliciesV3(y.phase, oversized), /EVIDENCE_LIMIT/);
  y.exemptions.value = Array.from({ length: 513 }, () => ({}));
  await assert.rejects(collect(y), /LIST_INCOMPLETE/);
  const maximumMembers = await collect(many(32, 1));
  assert.equal(maximumMembers.analysis.observations[0].resourceSha256s.length, 32);
  assert.equal(maximumMembers.analysis.observationCount, 32);
});

test('512 raw reads remain an aggregate budget and 513 cannot be split across groups or waves', async () => {
  function workload(definitions) {
    const x = many(2, definitions);
    x.initiative.properties.policyDefinitions.forEach((reference, i) => {
      reference.policyDefinitionId = `${x.definitionId}-${i}`;
      reference.definitionVersion = '1.0.0';
      const definition = structuredClone(x.definition);
      definition.id = `${reference.policyDefinitionId}/versions/1.0.0`;
      x.responses.set(definition.id, definition);
    });
    return x;
  }
  const boundary = await collect(workload(509));
  assert.equal(boundary.snapshot.reads.length, 512);
  verifyEffectivePolicyEvidenceV3(workload(509).phase, boundary);
  const tooMany = workload(510);
  let retained;
  await assert.rejects(collectEffectivePoliciesV3(tooMany.phase, tooMany.read, batch, async snapshot => {
    retained = structuredClone(snapshot);
  }), /EVIDENCE_LIMIT/);
  assert(retained.reads.length <= 512);
  assert.equal(tooMany.calls.length, 3, 'The oversized pending wave is rejected before its extra requests are issued');
});

test('raw snapshot changes, incomplete lists, excessive depth and unresolved parameters still fail closed', async () => {
  const x = many(2, 1), original = await collect(x);
  const duplicate = structuredClone(original.snapshot);
  duplicate.reads.push(structuredClone(duplicate.reads[0]));
  assert.throws(() => analyzeEffectivePoliciesV3(x.phase, duplicate), /DUPLICATE_READ/);
  const extra = structuredClone(original.snapshot);
  extra.reads.push({ id: x.definitionId + '-unused/versions/1.0.0', apiVersion: POLICY_API, filter: null,
    response: structuredClone(x.definition) });
  assert.throws(() => analyzeEffectivePoliciesV3(x.phase, extra), /EVIDENCE_LIMIT/);
  x.exemptions.nextLink = 'https://unit.invalid/more';
  await assert.rejects(collect(x), /LIST_INCOMPLETE/);
  delete x.exemptions.nextLink;
  x.initiative.properties.policyDefinitions[0].parameters = { unknown: { value: true } };
  await assert.rejects(collect(x), /PARAMETERS_INVALID/);
  x.initiative.properties.policyDefinitions[0].parameters = {};
  x.definition.properties.policyRule.then.effect = 'deny';
  let rule = { field: 'type', equals: 'Unit/unrelated' };
  for (let i = 0; i <= POLICY_LIMITS.depth; i++) rule = { not: rule };
  x.definition.properties.policyRule.if = rule;
  const deep = await collect(x);
  assert.equal(deep.qualified, false);
  assert(deep.analysis.blockers.every(value => value.condition === 'unknown' && value.reason === 'POTENTIAL_DENY'));
});

test('v3 retains full partial raw evidence on bounded collection failure', async () => {
  const x = many(), reads = [], retained = [];
  await assert.rejects(collectEffectivePoliciesV3(x.phase, async (id, apiVersion, filter) => {
    reads.push(id);
    if (id === x.definition.id) throw new Error('UNIT_FIXED_READ_FAILED');
    return x.read(id, apiVersion, filter);
  }, batch, async snapshot => { retained.push(structuredClone(snapshot)); }), /UNIT_FIXED_READ_FAILED/);
  assert.equal(retained.length, 1);
  assert(retained[0].reads.length > 0);
  assert(retained[0].reads.every(value => [POLICY_API, EXEMPTION_API].includes(value.apiVersion)));
  assert(reads.includes(x.definition.id));
});
