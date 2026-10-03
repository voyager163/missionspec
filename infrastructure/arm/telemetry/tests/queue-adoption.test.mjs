import assert from 'node:assert/strict';
import test from 'node:test';
import { digest, json } from '../definition.mjs';
import { buildQueuePhase, qualifiedQueueRecords, verifyQueueRecord, verifyQueueResource } from '../durable-queue.mjs';
import { knownResourceIds } from '../controller.mjs';
import { adoptQueueStorage, collectQueueAdoption, queueArmInstant, QUEUE_ADOPTION_AUTHORITY,
  QUEUE_ADOPTION_LIMITS, verifyAdoptedQueueStorage, verifyQueueAdoptionOrigin,
  verifyQueueAdoptionRecord, verifyQueueAdoptionSources } from '../queue-adoption.mjs';
import { queueAdoptionFixture, rebindAdoption, replaceOriginArtifact } from './queue-adoption.fixture.mjs';
import { baseFixture, queuePhaseFixture } from './durable-queue.fixture.mjs';

function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

test('supplied fixture context preserves bound history and is cloned before adoption-specific changes', async () => {
  const input = baseFixture();
  input.source = digest('UNIT supplied historical source');
  input.at += 90000;
  const before = json(input);
  freeze(input);
  const f = await queueAdoptionFixture(input);
  assert.equal(json(input), before);
  for (const key of ['c', 'r', 'receipts', 'identity', 'topology']) {
    assert.deepEqual(f[key], input[key]);
    assert.notEqual(f[key], input[key]);
  }
  assert.deepEqual(f.foundationOrigin, input.origin);
  assert.equal(JSON.parse(f.origin.artifacts.priorJournal.json).intentAt, new Date(input.at).toISOString());
  assert.equal(JSON.parse(f.origin.artifacts.publication.json).sourceSha256, input.source);
  assert.equal(f.at, input.at + 780000);
  verifyQueueAdoptionRecord(f.c, f.adoption);
  const defaultFixture = await queueAdoptionFixture(), explicitDefault = await queueAdoptionFixture(null);
  assert.deepEqual(defaultFixture.adoption, explicitDefault.adoption);
});

test('read-only adoption preserves exact stopped history, admits inventory and never claims operational qualification', async () => {
  const f = await queueAdoptionFixture(), before = json(f.adoption);
  freeze(f.adoption);
  assert.equal(verifyQueueAdoptionRecord(f.c, f.adoption), f.adoption.observation);
  assert.equal(json(f.adoption), before);
  const values = verifyQueueAdoptionOrigin(f.c, f.origin);
  assert.equal(values.priorJournal.transportDispatchAttempted, false);
  assert.equal(values.journal.transportDispatchAttempted, true);
  for (const journal of [values.priorJournal, values.journal]) assert.equal(journal.outcome, 'reconciliation-required');
  assert.equal(f.adoption.observation.qualified, false);
  assert.equal(f.adoption.observation.operationallyQualified, false);
  assert.deepEqual(f.adoption.authority, QUEUE_ADOPTION_AUTHORITY);
  assert(Object.values(f.adoption.authority).every(value => value === false));
  assert(!Object.hasOwn(f.adoption, 'receipt')); assert(!Object.hasOwn(f.adoption, 'phase'));
  assert.equal(f.adoption.origin.originalReceipt, null);
  assert.equal(f.adoption.origin.assurance.fullWireAttestation, false);
  assert.equal(f.adoption.origin.assurance.uninterruptedChildGenerationProven, false);
  assert.equal(f.adoption.origin.assurance.missingOriginalSystemDataCreationIdentityProven, false);
  assert.equal(f.adoption.origin.assurance.rbacEvidence, 'arm-role-assignment-inventories-only');
  assert.equal(f.adoption.origin.assurance.roleDefinitionsEvaluated, false);
  assert.equal(f.adoption.origin.assurance.transitiveGroupMembershipEvaluated, false);
  assert.equal(f.adoption.origin.assurance.allEffectiveDataAccessExcluded, false);
  assert.equal(f.adoption.observation.postconditions.observations.length, 8);
  assert.equal(f.adoption.origin.phase.resources[0].expected.properties.publicNetworkAccess, 'Enabled');
  assert.equal(f.adoption.observation.resources[f.topology.ids.account].properties.publicNetworkAccess, 'Disabled');
  assert.throws(() => verifyQueueResource(f.c, f.topology, f.origin.phase.resources[0],
    f.adoption.observation.resources[f.topology.ids.account]), /QUEUE_NETWORK_POLICY_MISMATCH/);
});

test('adoption uses exact new source/review, never original creation approval or qualified flags', async t => {
  const f = await queueAdoptionFixture();
  for (const [label, mutate] of [
    ['qualified', x => { x.qualified = true; }],
    ['observed qualified', x => { x.proposal.observation.qualified = true; }],
    ['operational qualified', x => { x.proposal.observation.operationallyQualified = true; }],
    ['deployment authority', x => { x.authority.deployment = true; }],
    ['review publication authority', x => { x.review.authority.publication = true; }],
    ['legacy receipt', x => { x.receipt = { qualified: true }; }],
    ['rewritten success', x => { x.origin.originalReceipt = { qualified: true }; }],
    ['generic adopter version', x => { x.version = 3; }],
    ['old review action', x => { x.review.action = 'direct-arm-queue-storage'; }],
    ['old source', x => {
      const publication = JSON.parse(x.origin.artifacts.publication.json);
      x.publication = publication; x.review.sourceSha256 = publication.sourceSha256;
      x.proposal.sourceSha256 = publication.sourceSha256; x.proposal.observation.sourceSha256 = publication.sourceSha256;
    }],
    ['source not proposal', x => { x.publication.sourceSha256 = digest('UNIT wrong source'); }],
    ['wrong config', x => { x.review.configSha256 = digest('UNIT wrong config'); }],
    ['review before observation', x => { x.review.reviewedAt = new Date(f.at - 1).toISOString(); }],
    ['expired', x => { x.review.expiresAt = x.adoptedAt; }],
    ['unbounded review', x => { x.review.expiresAt = new Date(f.at + 3600001).toISOString(); }],
    ['stale observation', x => { x.adoptedAt = new Date(f.at + QUEUE_ADOPTION_LIMITS.freshnessMs + 1).toISOString(); }],
    ['review after adoption', x => { x.review.reviewedAt = new Date(f.at + 1).toISOString(); }],
    ['wire attestation invented', x => { x.origin.assurance.fullWireAttestation = true; }],
    ['child continuity invented', x => { x.origin.assurance.uninterruptedChildGenerationProven = true; }],
    ['effective RBAC exclusion invented', x => { x.origin.assurance.allEffectiveDataAccessExcluded = true; }],
    ['role permission evaluation invented', x => { x.origin.assurance.roleDefinitionsEvaluated = true; }],
    ['group evaluation invented', x => { x.origin.assurance.transitiveGroupMembershipEvaluated = true; }],
    ['missing creation metadata claimed', x => { x.origin.assurance.missingOriginalSystemDataCreationIdentityProven = true; }],
  ]) await t.test(label, () => {
    const changed = structuredClone(f.adoption); mutate(changed); rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed));
  });
  const unknown = structuredClone(f.adoption); unknown.review.unrelated = false;
  assert.throws(() => verifyQueueAdoptionRecord(f.c, unknown), /CLOSED_INPUT_REQUIRED/);
});

test('rewritten or rehashed journal, dispatch, copied history and one-attempt lineage cannot be adopted', async t => {
  const f = await queueAdoptionFixture();
  const cases = [
    ['journal', 'undispatched later', x => { x.transportDispatchAttempted = false; }],
    ['journal', 'unresolved dispatch', x => { x.transportDispatchAttempted = null; }],
    ['journal', 'successful history', x => { x.outcome = 'readback-qualified'; }],
    ['journal', 'different failure', x => { x.failureCode = 'QUEUE_ROLLOUT_UNRESOLVED'; }],
    ['journal', 'different phase', x => { x.phaseSha256 = digest('UNIT wrong phase'); }],
    ['journal', 'different approval', x => { x.approvalSha256 = digest('UNIT wrong approval'); }],
    ['priorJournal', 'prior dispatch', x => { x.transportDispatchAttempted = true; }],
    ['absence', 'no prior absence', x => { x.deploymentAbsent = false; }],
    ['absence', 'absence wrote', x => { x.writes = 1; }],
    ['absence', 'wrong journal', x => { x.originalJournalSha256 = digest('UNIT other journal'); }],
    ['lineage', 'two attempts', x => { x.permittedNewAttempts = 2; }],
    ['lineage', 'copied different topology', x => { x.copies['queue-topology.json'] = digest('UNIT other topology'); }],
    ['authorization', 'no explicit retry', x => { x.repeatedDispatchAuthorized = true; }],
    ['authorization', 'wrong original', x => { x.originalJournalSha256 = digest('UNIT other'); }],
    ['authorization', 'missing effects boundary', x => { x.excludedEffects = []; }],
    ['authorization', 'new source old human review', x => { x.sourceSha256 = digest('UNIT new'); }],
    ['dispatch', 'unknown result', x => { x.success = false; }],
    ['dispatch', 'foreign deployment', x => { x.args[4] += '/other'; }],
    ['dispatch', 'extra request flags', x => { x.args.push('--query', '*'); }],
    ['dispatch', 'POST instead', x => { x.args[2] = 'POST'; }],
    ['dispatch', 'late dispatch', x => { x.startedAt = new Date(f.at).toISOString(); }],
    ['stop', 'second write', x => { x.writes = 2; }],
    ['stop', 'replay allowed', x => { x.furtherRetriesAuthorized = true; }],
    ['validation', 'wrong decimal templateHash', x => { x.properties.templateHash = '999999'; }],
    ['preflight', 'missing postcreate requirements', x => { x.requiredPostCreateReadbacksSha256 = digest('UNIT absent'); }],
    ['priorApproval', 'old approval changed', x => { x.phaseSha256 = digest('UNIT changed old phase'); }],
  ];
  for (const [artifact, label, mutate] of cases) await t.test(label, () => {
    const changed = structuredClone(f.adoption);
    replaceOriginArtifact(changed.origin, artifact, mutate); rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed));
  });
  const changed = structuredClone(f.adoption);
  changed.origin.artifacts.journal.json += ' ';
  rebindAdoption(changed);
  assert.throws(() => verifyQueueAdoptionRecord(f.c, changed), /ARTIFACT_CHANGED/);
});

test('rehashed wrong resources, ownership, authentication, logging and incomplete actual postconditions fail', async t => {
  const f = await queueAdoptionFixture(), q = f.topology.ids;
  for (const [label, mutate] of [
    ['missing account', x => { delete x.resources[q.account]; }],
    ['foreign account', x => { x.resources[q.account].id += '-foreign'; }],
    ['wrong owner', x => { x.resources[q.account].tags.collectorRun = f.c.tenantId; }],
    ['wrong location', x => { x.resources[q.account].location = 'westus'; }],
    ['wrong endpoint', x => { x.resources[q.account].properties.primaryEndpoints.queue = 'https://foreign.invalid/'; }],
    ['generation changed at 100ns', x => { x.resources[q.account].properties.creationTime =
      x.resources[q.account].properties.creationTime.replace('5000001Z', '5000002Z'); }],
    ['new systemData', x => { x.resources[q.queue].systemData = { createdAt: new Date(f.at).toISOString() }; }],
    ['Enabled remains mismatch', x => { x.resources[q.account].properties.publicNetworkAccess = 'Enabled'; }],
    ['perimeter not initial adoption', x => { x.resources[q.account].properties.publicNetworkAccess = 'SecuredByPerimeter'; }],
    ['shared key', x => { x.resources[q.account].properties.allowSharedKeyAccess = true; }],
    ['OAuth disabled', x => { x.resources[q.account].properties.defaultToOAuthAuthentication = false; }],
    ['HTTP enabled', x => { x.resources[q.account].properties.supportsHttpsTrafficOnly = false; }],
    ['cross tenant', x => { x.resources[q.account].properties.allowCrossTenantReplication = true; }],
    ['TLS drift', x => { x.resources[q.account].properties.minimumTlsVersion = 'TLS1_0'; }],
    ['IPv6 rule', x => { x.resources[q.account].properties.networkAcls.ipv6Rules = [{ value: '2001:db8::/32' }]; }],
    ['missing ACL postcondition', x => { delete x.resources[q.account].properties.networkAcls.ipRules; }],
    ['missing queue encryption', x => { delete x.resources[q.account].properties.encryption.services.queue; }],
    ['logging enabled', x => { x.resources[q.service].properties.logging.read = true; }],
    ['logging evidence missing', x => { delete x.resources[q.service].properties.logging; }],
    ['logging retention', x => { x.resources[q.service].properties.logging.retentionPolicy.enabled = true; }],
    ['private endpoint evidence missing', x => { delete x.resources[q.account].properties.privateEndpointConnections; }],
    ['missing CORS', x => { delete x.resources[q.service].properties.cors; }],
    ['metadata drift', x => { x.resources[q.queue].properties.metadata = { unknown: 'value' }; }],
    ['diagnostic route', x => { x.privacy.diagnostics[q.account].value = [{ id: 'UNIT route' }]; }],
    ['missing diagnostic evidence', x => { delete x.privacy.diagnostics[q.service]; }],
    ['second queue', x => { x.queues.value.push(structuredClone(x.queues.value[0])); }],
    ['missing queue', x => { x.queues.value = []; }],
    ['pagination incomplete', x => { x.queues.nextLink = 'https://management.azure.com/unreviewed'; }],
    ['forged postconditions', x => { x.postconditions.observations.pop(); }],
    ['unknown resource property', x => { x.resources[q.account].properties.unknown = false; }],
  ]) await t.test(label, () => {
    const changed = structuredClone(f.adoption); mutate(changed.proposal.observation); rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed));
  });
});

test('deployment and successful operations bind exact approved template, target set and retained identities', async t => {
  const f = await queueAdoptionFixture();
  for (const [label, mutate] of [
    ['wrong deployment', x => { x.deployment.id += '-other'; }],
    ['correlation changed', x => { x.deployment.properties.correlationId = f.c.runId; }],
    ['templateHash changed', x => { x.deployment.properties.templateHash = '9'; }],
    ['precise timestamp changed', x => { x.deployment.properties.timestamp =
      x.deployment.properties.timestamp.replace('0000001Z', '0000002Z'); }],
    ['not terminal', x => { x.deployment.properties.provisioningState = 'Running'; }],
    ['foreign output', x => { x.deployment.properties.outputResources[2].id += '-other'; }],
    ['extra output', x => { x.deployment.properties.outputResources.push(x.deployment.properties.outputResources[0]); }],
    ['missing operations', x => { x.operations.value.pop(); x.operations.value.pop(); }],
    ['duplicate operations', x => { x.operations.value[1] = structuredClone(x.operations.value[0]); }],
    ['operation target', x => { x.operations.value[0].properties.targetResource.id += '-foreign'; }],
    ['not Create', x => { x.operations.value[0].properties.provisioningOperation = 'Read'; }],
    ['pending operation', x => { x.operations.value[0].properties.provisioningState = 'Running'; }],
    ['operation tracking changed', x => { x.operations.value[0].properties.trackingId = f.c.runId; }],
    ['operation timestamp changed', x => { x.operations.value[0].properties.timestamp =
      x.operations.value[0].properties.timestamp.replace('0000001Z', '0000002Z'); }],
    ['foreign operation prefix', x => { x.operations.value[0].id = x.operations.value[0].id.replace('/operations/', '/other/'); }],
    ['partial operation page', x => { x.operations.nextLink = 'https://management.azure.com/more'; }],
    ['output evaluation has a target', x => { x.operations.value[3].properties.targetResource =
      structuredClone(x.operations.value[0].properties.targetResource); }],
  ]) await t.test(label, () => {
    const changed = structuredClone(f.adoption); mutate(changed.proposal.observation); rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed));
  });
  const changed = structuredClone(f.adoption);
  for (const observation of [changed.origin.firstReadback, changed.proposal.observation]) {
    observation.resources[f.topology.ids.account].properties.creationTime = '2020-01-01T00:00:00.0000001Z';
  }
  rebindAdoption(changed);
  assert.throws(() => verifyQueueAdoptionRecord(f.c, changed), /ACCOUNT_CREATION_TIME_CHANGED/);
});

test('queue grants and identity drift are blockers, not adoption capabilities', async t => {
  const f = await queueAdoptionFixture(), q = f.topology.ids;
  const assignment = scope => ({ id: `${scope}/providers/Microsoft.Authorization/roleAssignments/${f.c.runId}`,
    properties: { principalId: f.c.operatorPrincipalId, scope, roleDefinitionId: q.role } });
  for (const [label, mutate] of [
    ['role exists', x => { x.role = { id: q.role }; }],
    ['assignment exists', x => { x.assignment = { id: q.assignment }; }],
    ['missing absent proof', x => { delete x.role; }],
    ['different identity', x => { x.identity.properties.principalId = f.c.operatorPrincipalId; }],
    ['different tenant', x => { x.identity.properties.tenantId = f.c.runId; }],
    ['different identity ID', x => { x.identity.id = f.r.pullIdentity; }],
    ['direct foreign grant', x => { x.assignments[q.account].value = [assignment(q.account)]; }],
    ['inherited ingest grant', x => {
      const inherited = assignment(f.r.sub); inherited.properties.principalId = f.identity.properties.principalId;
      x.assignments[q.queue].value = [inherited];
    }],
    ['truncated grants', x => { x.assignments[q.queue].nextLink = 'more'; }],
    ['missing scope evidence', x => { delete x.assignments[q.service]; }],
    ['unknown permission observation', x => { x.qualified = true; }],
  ]) await t.test(label, () => {
    const changed = structuredClone(f.adoption); mutate(changed.proposal.observation.access); rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed));
  });
});

test('inherited group assignments remain unresolved RBAC evidence, never proof excluding all effective data access', async () => {
  const f = await queueAdoptionFixture(), changed = structuredClone(f.adoption);
  const inherited = { id: `${f.r.sub}/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-8000-000000000077`,
    properties: { principalId: '00000000-0000-4000-8000-000000000078', principalType: 'Group', scope: f.r.sub,
      roleDefinitionId: `${f.r.sub}/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-4000-8000-000000000079` } };
  for (const list of Object.values(changed.proposal.observation.access.assignments)) {
    list.value = [structuredClone(inherited)];
  }
  rebindAdoption(changed);
  const observation = verifyQueueAdoptionRecord(f.c, changed);
  assert.equal(observation.qualified, false);
  assert.equal(observation.operationallyQualified, false);
  assert.equal(changed.origin.assurance.roleDefinitionsEvaluated, false);
  assert.equal(changed.origin.assurance.transitiveGroupMembershipEvaluated, false);
  assert.equal(changed.origin.assurance.allEffectiveDataAccessExcluded, false);
  assert.throws(() => qualifiedQueueRecords(f.c, { 'queue-storage': changed }, f.topology));
});

test('historical dispatch pins exactly fifteen seconds, separately from the longer read-only collection bound', async t => {
  const f = await queueAdoptionFixture();
  assert.equal(JSON.parse(f.origin.artifacts.dispatch.json).timeoutMs, 15000);
  assert.equal(QUEUE_ADOPTION_LIMITS.collectionMs, 120000);
  for (const timeoutMs of [15001, 120000, 14999, 0, null, '15000']) await t.test(`timeout ${timeoutMs}`, () => {
    const changed = structuredClone(f.adoption);
    replaceOriginArtifact(changed.origin, 'dispatch', value => { value.timeoutMs = timeoutMs; });
    rebindAdoption(changed);
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changed), /DISPATCH_EVIDENCE_CHANGED/);
  });
  const boundary = structuredClone(f.adoption);
  const start = Date.parse(JSON.parse(boundary.origin.artifacts.dispatch.json).startedAt);
  replaceOriginArtifact(boundary.origin, 'dispatch', value => { value.completedAt = new Date(start + 15000).toISOString(); });
  replaceOriginArtifact(boundary.origin, 'stop', value => { value.recordedAt = new Date(start + 20000).toISOString(); });
  boundary.origin.firstReadback.checkedAt = new Date(start + 21000).toISOString();
  rebindAdoption(boundary);
  verifyQueueAdoptionRecord(f.c, boundary);
  replaceOriginArtifact(boundary.origin, 'dispatch', value => { value.completedAt = new Date(start + 15001).toISOString(); });
  rebindAdoption(boundary);
  assert.throws(() => verifyQueueAdoptionRecord(f.c, boundary), /DISPATCH_TIME_CHANGED/);
});

test('ARM time comparison retains 100ns precision and rejects malformed calendar, offset and excessive precision', () => {
  const a = queueArmInstant('2026-09-23T08:10:00.1234567Z');
  assert.equal(queueArmInstant('2026-09-23T08:10:00.1234568Z') - a, 1n);
  assert.equal(queueArmInstant('2026-09-23T08:10:00.123Z') - queueArmInstant('2026-09-23T08:10:00Z'), 1230000n);
  for (const value of [null, 0, '2026-02-30T00:00:00.0000001Z', '2026-01-01T24:00:00Z',
    '2026-09-23T08:10:00.12345678Z', '2026-09-23T08:10:00+00:00', '2026-09-23', 'invalid']) {
    assert.throws(() => queueArmInstant(value), /ARM_TIME_INVALID/);
  }
});

test('bounded collector exposes exactly fourteen allowlisted GETs, no write/replay/default or new source substitution', async t => {
  const f = await queueAdoptionFixture();
  assert.equal(f.reads.length, 14); assert.equal(new Set(f.reads.map(value => value.id)).size, 14);
  assert(f.reads.every(value => Object.keys(value).sort().join(',') === 'apiVersion,filter,id'));
  assert.equal(f.reads.filter(value => value.filter === '$filter=atScope()').length, 3);
  for (const [label, update] of [
    ['write port rejected', io => { io.arm = async () => {}; }],
    ['missing source port', io => { delete io.sourceDigest; }],
    ['unknown read', io => { io.read = async () => null; }],
    ['read failure propagated', io => { io.read = async () => { throw new Error('UNIT_READ_FAILED'); }; }],
    ['source changes', io => { let calls = 0; io.sourceDigest = async () => ++calls === 1 ? f.source : digest('UNIT changed'); }],
    ['deadline before response', io => {
      let now = f.at; io.now = () => now;
      io.read = async request => { now += 120000; return structuredClone(f.responses[request.id]); };
    }],
    ['infinite timestamp', io => { io.now = () => Infinity; }],
    ['unqualified partial list', io => {
      io.read = async request => request.id.endsWith('/operations')
        ? { value: [], nextLink: 'https://foreign.invalid/' } : structuredClone(f.responses[request.id]);
    }],
  ]) await t.test(label, async () => {
    const io = { ...f.io }; update(io);
    await assert.rejects(collectQueueAdoption(f.c, f.origin, io));
  });
});

test('finite closed inputs reject cycles, oversized/deep payloads, nonfinite values and malformed raw evidence', async () => {
  const f = await queueAdoptionFixture();
  const cycle = structuredClone(f.adoption); cycle.loop = cycle;
  assert.throws(() => verifyQueueAdoptionRecord(f.c, cycle), /JSON_REQUIRED/);
  const huge = structuredClone(f.adoption); huge.padding = 'x'.repeat(QUEUE_ADOPTION_LIMITS.stringBytes + 1);
  assert.throws(() => verifyQueueAdoptionRecord(f.c, huge), /INPUT_LIMIT/);
  const deep = structuredClone(f.adoption);
  let node = deep; for (let i = 0; i <= QUEUE_ADOPTION_LIMITS.depth; i++) node = node.next = {};
  assert.throws(() => verifyQueueAdoptionRecord(f.c, deep), /INPUT_LIMIT/);
  const bad = structuredClone(f.adoption); bad.proposal.observation.access.role = Infinity;
  assert.throws(() => verifyQueueAdoptionRecord(f.c, bad), /JSON_REQUIRED/);
  const malformed = structuredClone(f.adoption); malformed.origin.artifacts.journal = { json: '{', sha256: digest('{') };
  assert.throws(() => verifyQueueAdoptionRecord(f.c, malformed), /ARTIFACT_JSON_INVALID/);
});

test('later storage-mode verification preserves identity and cannot qualify networking or accept generic modes', async () => {
  const f = await queueAdoptionFixture(), resources = structuredClone(f.adoption.observation.resources);
  assert.equal(verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'Disabled'), resources);
  resources[f.topology.ids.account].properties.publicNetworkAccess = 'SecuredByPerimeter';
  assert.equal(verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'SecuredByPerimeter'), resources);
  for (const mode of [true, false, null, 'Enabled', 'Enforced', undefined]) {
    assert.throws(() => verifyAdoptedQueueStorage(f.c, f.adoption, resources, mode), /EXPECTED_NETWORK_MODE_REQUIRED/);
  }
  assert.throws(() => verifyQueueResource(f.c, f.topology, f.origin.phase.resources[0],
    resources[f.topology.ids.account]), /QUEUE_NETWORK_POLICY_MISMATCH/);
  assert.equal(f.adoption.observation.operationallyQualified, false);
  resources[f.topology.ids.account].properties.allowSharedKeyAccess = true;
  assert.throws(() => verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'SecuredByPerimeter'));
});

test('an authorized storage network transition may update modification metadata but not retained creation identity', async t => {
  const f = await queueAdoptionFixture(), adoption = structuredClone(f.adoption), account = f.topology.ids.account;
  const createdAt = adoption.origin.firstReadback.resources[account].properties.creationTime;
  const metadata = { createdAt, createdBy: f.c.operatorPrincipalId, createdByType: 'User',
    lastModifiedAt: createdAt, lastModifiedBy: f.c.operatorPrincipalId, lastModifiedByType: 'User' };
  adoption.origin.firstReadback.resources[account].systemData = structuredClone(metadata);
  adoption.proposal.observation.resources[account].systemData = structuredClone(metadata);
  rebindAdoption(adoption); verifyQueueAdoptionRecord(f.c, adoption);
  const before = json(adoption), resources = structuredClone(adoption.observation.resources);
  resources[account].properties.publicNetworkAccess = 'SecuredByPerimeter';
  Object.assign(resources[account].systemData, { lastModifiedAt: new Date(f.at).toISOString(),
    lastModifiedBy: f.c.runId, lastModifiedByType: 'Application' });
  const actual = json(resources);
  assert.equal(verifyAdoptedQueueStorage(f.c, adoption, resources, 'SecuredByPerimeter'), resources);
  assert.equal(json(resources), actual);
  assert.equal(json(adoption), before);
  for (const [label, mutate] of [
    ['created time', x => { x.systemData.createdAt = x.systemData.createdAt.replace('5000001Z', '5000002Z'); }],
    ['creator', x => { x.systemData.createdBy = f.c.tenantId; }],
    ['creator type', x => { x.systemData.createdByType = 'ManagedIdentity'; }],
    ['missing creator', x => { delete x.systemData.createdBy; }],
    ['missing creation metadata', x => { delete x.systemData; }],
    ['resource type', x => { x.type = 'Microsoft.Storage/storageAccounts/queueServices'; }],
    ['account generation', x => { x.properties.creationTime = new Date(f.at).toISOString(); }],
    ['unknown metadata', x => { x.systemData.unknown = false; }],
    ['null metadata', x => { x.systemData = null; }],
    ['invalid modification type', x => { x.systemData.lastModifiedByType = 'Unknown'; }],
    ['invalid modifier', x => { x.systemData.lastModifiedBy = {}; }],
    ['invalid modification timestamp', x => { x.systemData.lastModifiedAt = 'invalid'; }],
    ['modification before creation', x => { x.systemData.lastModifiedAt = '2020-01-01T00:00:00Z'; }],
  ]) await t.test(label, () => {
    const changed = structuredClone(resources); mutate(changed[account]);
    assert.throws(() => verifyAdoptedQueueStorage(f.c, adoption, changed, 'SecuredByPerimeter'));
  });
});

test('newly returned creation metadata cannot invent original pins or claim uninterrupted child generation', async () => {
  const f = await queueAdoptionFixture(), resources = structuredClone(f.adoption.observation.resources);
  const q = f.topology.ids, createdAt = resources[q.account].properties.creationTime;
  assert.equal(Object.hasOwn(f.adoption.origin.firstReadback.resources[q.account], 'systemData'), false);
  resources[q.account].properties.publicNetworkAccess = 'SecuredByPerimeter';
  resources[q.account].systemData = { createdAt, createdBy: f.c.operatorPrincipalId, createdByType: 'User',
    lastModifiedAt: new Date(f.at).toISOString(), lastModifiedBy: f.c.runId, lastModifiedByType: 'Application' };
  verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'SecuredByPerimeter');
  assert.equal(Object.hasOwn(f.adoption.origin.firstReadback.resources[q.account], 'systemData'), false);
  assert.equal(f.adoption.origin.assurance.missingOriginalSystemDataCreationIdentityProven, false);
  assert.equal(f.adoption.origin.assurance.uninterruptedChildGenerationProven, false);
  resources[q.queue].systemData = { createdAt: new Date(f.at).toISOString() };
  assert.throws(() => verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'SecuredByPerimeter'), /RESOURCE_CREATION_TIME_CHANGED/);
});

test('published source verification checks both attempts and new adoption without granting effects', async () => {
  const f = await queueAdoptionFixture(), values = verifyQueueAdoptionOrigin(f.c, f.origin), seen = [];
  await verifyQueueAdoptionSources(f.c, f.adoption, async commit => {
    seen.push(commit);
    return commit === f.publication.commitSha ? f.source : values.publication.sourceSha256;
  });
  assert.deepEqual(seen, [values.priorPublication.commitSha, values.publication.commitSha, f.publication.commitSha]);
  await assert.rejects(verifyQueueAdoptionSources(f.c, f.adoption, async () => f.source), /PUBLISHED_SOURCE_CHANGED/);
  await assert.rejects(verifyQueueAdoptionSources(f.c, f.adoption, async commit =>
    commit === f.publication.commitSha ? digest('UNIT wrong new code') : values.publication.sourceSha256), /PUBLISHED_SOURCE_CHANGED/);
  assert.throws(() => adoptQueueStorage(f.c, f.proposal, f.origin, { qualified: true }, f.publication, f.at));
});

test('adopted storage is known inventory only; operational phases need actual NSP and cannot launder v2 through v1', async () => {
  const f = await queueAdoptionFixture(), records = { 'queue-storage': f.adoption };
  assert.equal(verifyQueueRecord(f.c, f.adoption), f.adoption.observation);
  assert.deepEqual(Object.keys(qualifiedQueueRecords(f.c, records, f.topology, 'queue-storage')),
    f.origin.phase.resources.map(value => value.id));
  assert.deepEqual(knownResourceIds(f.c, { queueRecords: records }), f.origin.phase.resources.map(value => value.id));
  assert.throws(() => qualifiedQueueRecords(f.c, records, f.topology));
  assert.throws(() => qualifiedQueueRecords(f.c, records, f.topology, 'queue-role'));
  for (const context of [true, { adoption: f.adoption, admission: { qualified: true } },
    { adoption: f.adoption, admission: null }, { adoption: f.adoption }]) {
    assert.throws(() => buildQueuePhase(f.c, 'queue-role', f.topology, f.identity, context));
    assert.throws(() => buildQueuePhase(f.c, 'queue-assignment', f.topology, f.identity, context));
  }
  assert.throws(() => buildQueuePhase(f.c, 'queue-storage', f.topology, f.identity,
    { adoption: f.adoption, admission: { qualified: true } }), /NSP_OPERATIONAL_PHASE_REQUIRED/);
  const legacy = queuePhaseFixture({ ...f, origin: f.foundationOrigin }, 'queue-role', records);
  await legacy.controller.execute(legacy.approval);
  assert.throws(() => verifyQueueRecord(f.c, legacy.record()), /QUEUE_NSP_VERSION_REQUIRED/);
});
