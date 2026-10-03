import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { digest, ids, json } from '../definition.mjs';
import { PRIVATE_LINK_CONTROL_STAGES as STAGES, PRIVATE_LINK_LIMITS, buildPrivateLinkPlan,
  privateLinkPhase, privateLinkPublicProbeDescriptor } from '../private-link.mjs';
import { checkPrivateLinkPhase, executePrivateLinkPhase, preparePrivateLinkPhase, privateLinkAzureIO, privateLinkReadIO,
  privateLinkHead, privateLinkTargetKey, emptyPrivateLinkControlEvidence, verifyPrivateLinkControlEvidence,
  verifyPrivateLinkRuntimePrerequisites, verifyPrivateLinkPreview, verifyPrivateLinkApproval,
  reconcilePrivateLinkPhase, recoverPrivateLinkPhase, readPrivateLinkHead, verifyPrivateLinkCostReview,
  verifyPrivateLinkPolicyRevision } from '../private-link-controller.mjs';
import { verifyPrivateLinkSnapshot, privateLinkResourceState, privateLinkAcaCreationIdentity, privateLinkGeneration } from '../private-link-readback.mjs';
import { privateLinkFixture, privateInput, privateControlHarness, privateControlChain, privateSnapshotFixture, privateCostFixture } from './private-link.fixture.mjs';
import { effectivePolicyFixture } from './effective-policy.fixture.mjs';
import { whatIfRequestContext, limitReadConcurrency, az } from '../controller.mjs';

const hash = value => digest(json(value));
const base = await privateLinkFixture({ ...privateInput, version: 2 });
const chain = await privateControlChain({ ...base });
function prefix(stage) { return { ...chain, records: chain.records.slice(0, STAGES.indexOf(stage)) }; }
const at = Date.parse(chain.records.at(-1).completedAt) + 1000;
function f() { return { ...base, at }; }

test('missing effective-configuration GET does not qualify retirement while its listing is stale', () => {
  const before = chain.records.find(value => value.stage === 'disable-storage-public').after;
  const after = structuredClone(chain.records.find(value => value.stage === 'retire-nsp-association').after);
  assert.equal(after.effective, null);
  after.lists.effective = { value: [structuredClone(before.lists.effective.value[0])] };
  assert.throws(() => verifyPrivateLinkSnapshot(base.c, base.context, after, 'retire-nsp-association'),
    /PRIVATE_LINK_NSP_EFFECTIVE_COPY_PRESENT/);
  after.lists.effective = { value: [] };
  verifyPrivateLinkSnapshot(base.c, base.context, after, 'retire-nsp-association');
});

test('production controller executes each budget/network/retirement/RBAC setup boundary and preserves failed original NSP', () => {
  const record = verifyPrivateLinkControlEvidence(base.c, base.context, chain, at);
  assert.equal(record.stage, 'assign-queue-role');
  assert.deepEqual(chain.records.map(value => value.stage), STAGES.slice(0, STAGES.indexOf('assign-queue-role') + 1));
  assert.equal(chain.records.filter(value => value.phase.request).length, 12);
  assert.equal(chain.records[0].journal.dispatchAttempted, false);
  assert.equal(base.context.origin.original.journal.outcome, 'reconciliation-required');
  for (const value of chain.records) {
    assert.equal(value.authority.originalNspExecutionQualified, false);
    assert.equal(value.authority.originalIntentReplayAuthorized, false);
    assert.equal(value.authority.ingestionAuthorized, false);
    assert.equal(value.journal.dispatchAttempted, value.phase.request !== null);
  }
  const ready = verifyPrivateLinkRuntimePrerequisites(base.c, base.context, chain, at);
  assert.equal(ready.privateIp, '10.240.8.68');
  assert.equal(ready.queueHost, new URL(base.topology.ids.queueUrl).hostname);
  assert.equal(ready.queueResources[base.topology.ids.account].properties.publicNetworkAccess, 'Disabled');
  assert.equal(ready.environment.properties.vnetConfiguration.internal, false);
  assert.equal(ready.identity.properties.tenantId, base.c.tenantId);
  assert.equal(ready.oldEnvironment.properties.vnetConfiguration, null);
  assert.equal(ready.workspace.properties.retentionInDays, 180);
  assert.throws(() => verifyPrivateLinkRuntimePrerequisites(base.c, base.context, prefix('assign-queue-role'), at));
});

test('explicit budget phases cover new managed group and preserve notifications; no amounts are silently inferred', async () => {
  const project = chain.records.find(value => value.stage === 'set-project-migration-budget');
  const telemetry = chain.records.find(value => value.stage === 'set-telemetry-migration-budget');
  assert.equal(project.phase.request.body.properties.amount, 425);
  assert.equal(telemetry.phase.request.body.properties.amount, 375);
  assert(project.phase.request.body.properties.filter.dimensions.values.includes(`${base.c.namePrefix}-private-managed`));
  assert.deepEqual(project.phase.request.body.properties.notifications,
    project.preflight.before.resources[ids(base.c).projectBudget].properties.notifications);
  const cost = privateCostFixture(base);
  verifyPrivateLinkCostReview(base.c, base.context, cost.review, cost.evidence, base.source, base.at);
  for (const mutate of [
    x => { x.review.budgetTargets.migration.project = 350; }, x => { x.review.cost.migrationMonth = 349.37; },
    x => { x.evidence.queries.pop(); }, x => { x.evidence.queries[0].response.Items[0].unitPrice = 0; },
    x => { x.evidence.unknownChargesAcknowledgment = ''; }, x => { x.review.sourceSha256 = digest('UNIT wrong source'); },
  ]) {
    const value = structuredClone(cost); mutate(value);
    assert.throws(() => verifyPrivateLinkCostReview(base.c, base.context, value.review, value.evidence, base.source, base.at));
  }
});

test('unknown appliesTo rule is only an exact delete preimage, never a admitted NSP selector or successful prior receipt', async () => {
  const evidence = prefix('retire-nsp-rule'), q = await privateControlHarness(f(), evidence, 'retire-nsp-rule');
  const rule = base.context.origin.network.topology.ids.rule;
  assert.deepEqual(q.before.resources[rule].properties.appliesTo, [{ resourceType: '*', features: ['*'] }]);
  assert.equal(q.phase.request.method, 'DELETE'); assert.equal(q.phase.request.id, rule);
  q.before.resources[rule].properties.appliesTo.push({ resourceType: 'UNIT different' });
  q.setLive(q.before);
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  assert.equal(q.journal.failure.code, 'PRIVATE_LINK_DISPATCH_PREIMAGE_CHANGED');
  assert.equal(q.writes, 0);
  const after = chain.records.find(value => value.stage === 'retire-nsp-rule').after;
  assert.equal(after.resources[rule], null);
  assert.deepEqual(after.lists.rules.value, []);
  assert.deepEqual(after.effective.properties.profile.accessRules, []);
  assert.equal(after.effective.properties.profile.accessRulesVersion, 2);
});

test('native previews are create-only and direct requests bind exact preimages with no generic executor', async () => {
  const q = await privateControlHarness(f(), prefix('create-network'), 'create-network');
  verifyPrivateLinkPreview(q.phase, q.proof.preview, q.before, []);
  for (const mutate of [
    p => { p.changes[0].changeType = 'Modify'; }, p => { p.changes[0].after.apiVersion = '2020-01-01'; },
    p => { p.changes[1].after.dependsOn = ['/subscriptions/foreign']; },
    p => { p.changes.push({ resourceId: '/subscriptions/foreign', changeType: 'Ignore' }); },
    p => { p.changes[1].after.properties.routeTable = { id: 'UNIT public route' }; },
    p => { p.changes.pop(); }, p => { p.nextLink = 'more'; },
  ]) {
    const preview = structuredClone(q.proof.preview); mutate(preview);
    assert.throws(() => verifyPrivateLinkPreview(q.phase, preview, q.before, []));
  }
  const copy = structuredClone(q.phase); copy.request.body.properties.mode = 'Complete';
  assert.throws(() => verifyPrivateLinkApproval(base.c, base.context, copy, q.proof, q.approval, at));
});

test('readback requires private queue-only endpoint, approved connection, exact NIC/IP and authoritative DNS', async t => {
  const full = chain.records.at(-1).after, n = base.context.plan.topology.ids;
  const cases = [
    ['blob endpoint', s => { s.resources[n.endpoint].properties.privateLinkServiceConnections[0].properties.groupIds = ['blob']; }],
    ['pending approval', s => { s.resources[n.endpoint].properties.privateLinkServiceConnections[0].properties.privateLinkServiceConnectionState.status = 'Pending'; }],
    ['foreign account', s => { s.resources[n.endpoint].properties.privateLinkServiceConnections[0].properties.privateLinkServiceId += '-other'; }],
    ['foreign NIC', s => { s.nic.id = s.nic.id.replace('/networkInterfaces/', '/loadBalancers/'); }],
    ['public NIC IP', s => { s.nic.properties.ipConfigurations[0].properties.privateIPAddress = '198.51.100.1'; }],
    ['wrong subnet', s => { s.nic.properties.ipConfigurations[0].properties.subnet.id = n.appsSubnet; }],
    ['other queue hostname', s => { s.nic.properties.ipConfigurations[0].properties.privateLinkConnectionProperties.fqdns = ['foreign.invalid']; }],
    ['DNS registration', s => { s.resources[n.dnsLink].properties.registrationEnabled = true; }],
    ['foreign DNS VNet', s => { s.resources[n.dnsLink].properties.virtualNetwork.id += '-other'; }],
    ['foreign zone group', s => { s.resources[n.dnsZoneGroup].properties.privateDnsZoneConfigs[0].properties.privateDnsZoneId += '-other'; }],
    ['wrong A record', s => { s.lists.dnsRecords.value[0].properties.aRecords[0].ipv4Address = '10.240.8.69'; }],
    ['extra DNS record', s => { s.lists.dnsRecords.value.push({ id: n.dnsZone + '/A/foreign' }); }],
    ['unknown property', s => { s.resources[n.environment].properties.openTelemetryConfiguration = { destination: 'UNIT' }; }],
    ['missing environment domain', s => { delete s.resources[n.environment].properties.defaultDomain; }],
    ['wrong managed group', s => { s.resources[n.managedGroup].managedBy = n.oldEnvironment; }],
    ['public enabled', s => { s.resources[n.account].properties.publicNetworkAccess = 'Enabled'; }],
    ['Defender rule mutated', s => { s.resources[n.account].properties.networkAcls.resourceAccessRules.push({ resourceId: 'UNIT' }); }],
    ['missing sole queue', s => { s.lists.queues.value = []; }],
    ['role widened', s => { s.resources[base.topology.ids.role].properties.permissions[0].actions.push('*'); }],
    ['second assignment', s => { s.resources[base.topology.ids.assignment].properties.scope = n.account; }],
    ['old app enabled', s => { s.resources[n.oldApp].properties.template.containers[0].env.find(x => x.name === 'MSR_INGESTION_ENABLED').value = 'true'; }],
    ['diagnostic export', s => { s.diagnostics[n.account].value.push({ id: 'UNIT-export' }); }],
  ];
  for (const [name, mutate] of cases) await t.test(name, () => {
    const state = structuredClone(full); mutate(state);
    assert.throws(() => verifyPrivateLinkSnapshot(base.c, base.context, state, 'assign-queue-role'));
  });
});

test('source/preimage/permission/policy/expiry faults stop before dispatch', async t => {
  for (const mode of ['source', 'preimage', 'permissions', 'policy', 'expiry', 'body-expiry']) await t.test(mode, async () => {
    const q = await privateControlHarness(f(), prefix('create-network'), 'create-network');
    if (mode === 'source') q.io.sourceDigest = async () => digest('UNIT source drift');
    if (mode === 'preimage') {
      const changed = structuredClone(q.before);
      changed.resources[base.context.plan.topology.ids.oldEnvironment].systemData.createdAt = '2026-09-22T00:00:00.000Z';
      q.setLive(changed);
    }
    if (mode === 'permissions') q.proof.permissions[ids(base.c).group].permissions.value[0].notActions.push('*');
    if (mode === 'policy') q.proof.policy.qualified = false;
    if (mode === 'expiry') q.advance(1800000);
    if (mode === 'body-expiry') q.io.write = async (_phase, guard, current) => { await current(); q.advance(1800000); guard(); };
    await assert.rejects(q.execute());
    assert.equal(q.writes, 0);
  });

  await t.test('fresh inherited governance is actually reread and a new Network deny prevents dispatch', async () => {
    const q = await privateControlHarness(f(), prefix('create-network'), 'create-network');
    const policy = effectivePolicyFixture(), read = q.io.read;
    policy.definition.properties.policyRule = { if: { field: 'type', equals: 'Microsoft.Network/virtualNetworks' }, then: { effect: 'deny' } };
    q.io.read = async (request, deadline) => policy.responses.has(request.id)
      ? structuredClone(policy.responses.get(request.id)) : read(request, deadline);
    await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
    assert.equal(q.journal.failure.code, 'PRIVATE_LINK_DISPATCH_GOVERNANCE_CHANGED');
    assert.equal(q.writes, 0);
  });
});

test('ambiguous write and late readback preserve journal/fence; separate reviewed recovery never replays', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network');
  const invoke = q.io.write;
  q.io.write = async (...args) => { await invoke(...args); throw new Error('UNIT_AMBIGUOUS_WRITE'); };
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  assert.equal(q.writes, 1); assert.equal(q.journal.dispatchAttempted, true);
  await assert.rejects(q.execute(), /INTENT_REPLAY_FORBIDDEN|CANONICAL|deepStrictEqual/);
  const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
    journal: structuredClone(q.journal), intent: q.intent };
  const bytes = json(original);
  q.advance(121000);
  const proposal = await reconcilePrivateLinkPhase(base.c, base.context, evidence, original, q.io);
  const now = q.io.now(), review = { version: 1, action: 'adopt-exact-private-link-late-state-without-replay',
    proposalSha256: hash(proposal), sourceSha256: base.source, pendingHeadSha256: hash(proposal.pendingHead),
    approvedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() };
  const record = await recoverPrivateLinkPhase(base.c, base.context, evidence, original, proposal, review, q.io);
  assert.equal(record.kind, 'reviewed-private-link-recovery');
  assert.equal(record.journal.outcome, 'reconciliation-required');
  assert.equal(record.recovery.proposal.originalExecutionQualified, false);
  assert.equal(json(original), bytes); assert.equal(q.writes, 1);
  assert.throws(() => verifyPrivateLinkControlEvidence(base.c, base.context, {
    ...evidence, records: [...evidence.records, { ...record, kind: 'reviewed-private-link-phase', recovery: null }],
  }), /EXECUTION_RECORD_INVALID/);
});

test('omitted NSP issues are conditional evidence, while present nonempty/null or mismatched copies fail', () => {
  const record = chain.records.find(value => value.stage === 'retire-nsp-rule');
  const s = structuredClone(record.after), old = base.context.origin.network.topology.ids;
  delete s.effective.properties.provisioningIssues;
  delete s.lists.effective.value[0].properties.provisioningIssues;
  verifyPrivateLinkSnapshot(base.c, base.context, s, record.stage);
  for (const change of [
    v => { v.effective.properties.provisioningIssues = null; v.lists.effective.value[0] = structuredClone(v.effective); },
    v => { v.effective.properties.provisioningIssues = [{ issue: 'Unknown' }]; v.lists.effective.value[0] = structuredClone(v.effective); },
    v => { v.resources[old.association].properties.hasProvisioningIssues = false; },
    v => { v.lists.associations.value[0].properties.profile.id += '-other'; },
    v => { v.lists.profiles.value[0].properties.accessRulesVersion = '999'; },
    v => { v.lists.effective.value[0].properties.profile.accessRulesVersion = 999; },
  ]) {
    const bad = structuredClone(s); change(bad);
    assert.throws(() => verifyPrivateLinkSnapshot(base.c, base.context, bad, record.stage));
  }
});

test('DCR/table and workspace exact retained settings remain part of every control snapshot', () => {
  const s = structuredClone(chain.records.at(-1).after), r = ids(base.c);
  verifyPrivateLinkSnapshot(base.c, base.context, s, 'assign-queue-role');
  for (const change of [
    v => { v.resources[r.table].properties.totalRetentionInDays = 30; },
    v => { v.resources[r.table].properties.schema.columns.pop(); },
    v => { v.resources[r.dcr].properties.immutableId = 'dcr-' + 'b'.repeat(32); },
    v => { v.resources[r.dcr].properties.endpoints.logsIngestion = 'https://other.ingest.monitor.azure.com'; },
    v => { v.resources[r.workspace].properties.features.disableLocalAuth = false; },
    v => { v.lists.workspaceExports.value.push({ id: 'UNIT export' }); },
    v => { v.diagnostics[r.dcr].value.push({ id: 'UNIT export' }); },
  ]) {
    const bad = structuredClone(s); change(bad);
    assert.throws(() => verifyPrivateLinkSnapshot(base.c, base.context, bad, 'assign-queue-role'));
  }
  const old = s.resources[base.context.plan.topology.ids.oldEnvironment];
  old.systemData.createdAt = '2026-09-23T03:52:56.5359041';
  old.systemData.lastModifiedAt = '2026-09-23T04:00:01.1234567';
  assert.equal(privateLinkResourceState(old).systemData.createdAt, '2026-09-23T03:52:56.5359041');
  const network = structuredClone(s.resources[base.context.plan.topology.ids.vnet]);
  network.systemData.createdAt = old.systemData.createdAt;
  assert.throws(() => privateLinkResourceState(network), /ARM_TIME_INVALID/);
});

test('new ACA environment/app/probe generations retain exact opaque provider timestamps without a timezone assumption', async () => {
  const n = base.context.plan.topology.ids, sample = '2026-09-23T08:09:25.4679184';
  for (const [id, type] of [[n.environment, 'Microsoft.App/managedEnvironments'], [n.app, 'Microsoft.App/containerApps'],
    [n.publicProbe, 'Microsoft.App/containerApps']]) {
    const resource = { id, type, systemData: { createdAt: sample, lastModifiedAt: sample } };
    const identity = privateLinkAcaCreationIdentity(resource, id);
    assert.equal(identity.createdAt, sample); assert.equal(identity.createdAtKind, 'opaque-aca');
    assert.equal(identity.createdAtTicks, null);
    assert.equal(privateLinkGeneration(resource).createdAt, 'opaque-recorded-aca:' + sample);
    const changed = structuredClone(resource); changed.systemData.createdAt = '2026-09-23T08:09:25.4679185';
    assert.notDeepEqual(privateLinkAcaCreationIdentity(changed, id), identity);
    for (const value of ['2026-02-30T08:09:25.4679184', '2026-09-23T25:09:25.4679184', sample + '0', sample + '+08:00']) {
      const bad = structuredClone(resource); bad.systemData.createdAt = value;
      assert.throws(() => privateLinkAcaCreationIdentity(bad, id));
    }
  }
  const evidence = prefix('create-environment'), q = await privateControlHarness(f(), evidence, 'create-environment');
  q.after.resources[n.environment].systemData.createdAt = sample;
  q.after.resources[n.environment].systemData.lastModifiedAt = sample;
  const record = await q.execute();
  assert.equal(record.after.resources[n.environment].systemData.createdAt, sample);
  const tampered = structuredClone(record);
  tampered.preflight.before.resources[n.environment] = tampered.after.resources[n.environment];
  assert.throws(() => verifyPrivateLinkControlEvidence(base.c, base.context, {
    ...evidence, records: [...evidence.records, tampered],
  }));
  const next = { ...evidence, records: [...evidence.records, record] }, nextFixture = await privateControlHarness(f(), next, 'disable-storage-public');
  nextFixture.after.resources[n.environment].systemData.createdAt = '2026-09-23T08:09:25.4679185';
  await assert.rejects(nextFixture.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
});

test('unrelated account state and preserved NSP generation changes cannot be hidden by expected effects', async () => {
  for (const [stage, mutate] of [
    ['disable-storage-public', s => { s.resources[base.topology.ids.account].properties.primaryEndpoints.etag = 'UNIT hidden drift'; }],
    ['create-network', s => { s.resources[base.context.origin.network.topology.ids.perimeter].properties.perimeterGuid = '00000000-0000-4000-8000-000000000099'; }],
  ]) {
    const q = await privateControlHarness(f(), prefix(stage), stage);
    mutate(q.after);
    await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
    assert.equal(q.journal.outcome, 'reconciliation-required');
    assert.equal(q.writes, 1);
  }
});

function policyRevision(context, source, now) {
  const instruction = 'UNIT reviewed identical migration plan after implementation correction';
  return { version: 1, action: 'review-identical-private-link-plan-under-new-policy-source',
    configSha256: hash(base.c), planSha256: context.plan.planSha256, originSha256: hash(context.origin),
    originalSourceSha256: context.plan.sourceSha256, sourceSha256: source,
    publication: { commitSha: 'f'.repeat(40), sourceSha256: source }, userInstruction: instruction,
    userInstructionSha256: digest(instruction), approvedAt: new Date(now - 1000).toISOString(),
    expiresAt: new Date(now + 600000).toISOString() };
}
test('a distinct reviewed new-source recovery preserves original plan, publication, approval and failed intent', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network');
  const write = q.io.write;
  q.io.write = async (...args) => { await write(...args); throw new Error('UNIT_UNKNOWN'); };
  await assert.rejects(q.execute(), /STOPPED_ORIGINAL_INTENT_PRESERVED/);
  const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
    intent: q.intent, journal: structuredClone(q.journal) };
  const unchanged = json(original), plan = json(base.context.plan), source = digest('UNIT corrected implementation');
  q.advance(121000);
  const revision = policyRevision(base.context, source, q.io.now());
  q.io.policyRevision = revision; q.io.publication = revision.publication; q.io.sourceDigest = async () => source;
  q.io.costReview = { ...q.io.costReview, sourceSha256: source };
  q.io.migrationReview = { ...q.io.migrationReview, sourceSha256: source };
  const proposal = await reconcilePrivateLinkPhase(base.c, base.context, evidence, original, q.io);
  const review = { version: 1, action: 'adopt-exact-private-link-late-state-without-replay',
    proposalSha256: hash(proposal), sourceSha256: source, pendingHeadSha256: hash(proposal.pendingHead),
    approvedAt: new Date(q.io.now()).toISOString(), expiresAt: new Date(q.io.now() + 300000).toISOString() };
  const record = await recoverPrivateLinkPhase(base.c, base.context, evidence, original, proposal, review, q.io);
  assert.equal(record.publication.sourceSha256, base.source);
  assert.equal(record.phase.sourceSha256, base.source);
  assert.equal(record.recovery.currentPublication.sourceSha256, source);
  assert.equal(record.recovery.policyRevision.planSha256, base.context.plan.planSha256);
  assert.equal(record.journal.outcome, 'reconciliation-required');
  assert.equal(json(original), unchanged); assert.equal(json(base.context.plan), plan); assert.equal(q.writes, 1);
  const next = { ...evidence, records: [...evidence.records, record] };
  const phase = preparePrivateLinkPhase(base.c, base.context, next, 'create-queue-endpoint', revision);
  assert.equal(phase.sourceSha256, source); assert.equal(phase.planSha256, base.context.plan.planSha256);
  const altered = structuredClone(revision); altered.planSha256 = digest('different topology');
  assert.throws(() => verifyPrivateLinkPolicyRevision(base.c, base.context, altered, q.io.now()));
});

test('recovery rejects same-byte replacement deployment or operation identity outside reviewed proposal', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network');
  const write = q.io.write;
  q.io.write = async (...args) => { await write(...args); throw new Error('UNIT_UNKNOWN'); };
  await assert.rejects(q.execute());
  const original = { phase: q.phase, publication: q.io.publication, approval: q.approval, preflight: q.proof,
    intent: q.intent, journal: structuredClone(q.journal) };
  q.advance(121000);
  const proposal = await reconcilePrivateLinkPhase(base.c, base.context, evidence, original, q.io);
  const review = { version: 1, action: 'adopt-exact-private-link-late-state-without-replay', proposalSha256: hash(proposal),
    sourceSha256: base.source, pendingHeadSha256: hash(proposal.pendingHead), approvedAt: new Date(q.io.now()).toISOString(),
    expiresAt: new Date(q.io.now() + 300000).toISOString() };
  const read = q.io.read;
  q.io.read = async (request, deadline) => {
    const response = await read(request, deadline);
    if (request.id === q.phase.deploymentId) response.properties.correlationId = 'UNIT replacement same template and targets';
    return response;
  };
  await assert.rejects(recoverPrivateLinkPhase(base.c, base.context, evidence, original, proposal, review, q.io), /RECOVERY_DEPLOYMENT_CHANGED/);
  q.io.read = async (request, deadline) => {
    const response = await read(request, deadline);
    if (request.id.endsWith('/operations')) response.value[0].properties.trackingId = 'UNIT replacement operation';
    return response;
  };
  await assert.rejects(recoverPrivateLinkPhase(base.c, base.context, evidence, original, proposal, review, q.io), /RECOVERY_OPERATIONS_CHANGED/);
  assert.equal(q.writes, 1);
});

test('retirement and completion never proceed from topology-only or qualified boolean runtime substitutes', async () => {
  const phase = preparePrivateLinkPhase(base.c, base.context, chain, 'retire-old-receiver');
  assert.equal(phase.request.id, ids(base.c).app);
  const state = privateSnapshotFixture(base, 'assign-queue-role', at);
  const shadow = { ...chain, records: [...chain.records, { qualified: true, runtimeQualified: true, stage: 'retire-old-receiver' }] };
  assert.throws(() => verifyPrivateLinkControlEvidence(base.c, base.context, shadow));
  assert.equal(state.resources[base.context.plan.topology.ids.app], null);
});

test('plan3 permits only its fixed patched false-only public probe and excludes it from retirement', () => {
  const plan = buildPrivateLinkPlan(base.c, base.origin, { ...base.context.plan.input, version: 2 }, base.source);
  const f3 = { ...base, context: { plan, origin: base.origin } }, s = privateSnapshotFixture(f3, 'assign-queue-role', at);
  const descriptor = privateLinkPublicProbeDescriptor(base.c, f3.context), n = plan.topology.ids;
  const app = { ...structuredClone(descriptor.expected), id: descriptor.id, systemData: { createdAt: new Date(at).toISOString() } };
  app.properties.configuration.ingress.fqdn = `${descriptor.expected.name}.${s.resources[n.oldEnvironment].properties.defaultDomain}`;
  for (const [id, value] of Object.entries(app.identity.userAssignedIdentities)) {
    const actual = s.resources[id.toLowerCase()] ?? Object.values(s.resources).find(value => value?.id?.toLowerCase() === id.toLowerCase());
    app.identity.userAssignedIdentities[id] = { clientId: actual.properties.clientId, principalId: actual.properties.principalId };
  }
  s.resources[n.publicProbe] = app;
  s.lists.apps.value.push(structuredClone(app)); s.lists.groupResources.value.push(structuredClone(app));
  s.images.queueManifest = JSON.parse(base.origin.queueProfile.manifestJson);
  s.images.manifests.push({ digest: base.origin.queueProfile.manifestDigest, tags: [`receiver-${base.origin.queueProfile.manifestDigest.slice(7, 19)}`] });
  verifyPrivateLinkSnapshot(base.c, f3.context, s, 'assign-queue-role');
  for (const mutate of [
    value => { value.resources[n.publicProbe].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; },
    value => { value.resources[n.publicProbe].properties.managedEnvironmentId = n.environment; },
    value => { value.resources[n.publicProbe].properties.template.containers[0].resources.cpu = 1; },
    value => { value.resources[n.publicProbe].properties.template.containers[0].image = base.origin.receiver.phase.resources[0].expected.properties.template.containers[0].image; },
    value => { value.lists.apps.value = value.lists.apps.value.filter(v => v.id !== n.publicProbe); },
  ]) {
    const invalid = structuredClone(s); mutate(invalid);
    assert.throws(() => verifyPrivateLinkSnapshot(base.c, f3.context, invalid, 'assign-queue-role'));
  }
  const before = privateSnapshotFixture(f3, 'retire-old-receiver', at);
  before.resources[n.publicProbe] = app;
  assert.throws(() => verifyPrivateLinkSnapshot(base.c, f3.context, before, 'retire-old-receiver'), /PUBLIC_PROBE_MUST_BE_ABSENT/);
});

test('concrete Azure adapter uses exact fixed requests, post-body guard and one 15-second invocation', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network');
  const directory = `infrastructure/arm/telemetry/tests/.private-link-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  try {
    const events = [], calls = [];
    const io = privateLinkAzureIO(base.c, base.context, evidence, q.phase, directory, {
      publication: { commitSha: 'e'.repeat(40), sourceSha256: base.source },
      costReview: q.proof.costReview, costEvidence: q.proof.costEvidence, migrationReview: q.proof.migrationReview,
      proof: q.proof, approval: q.approval,
    }, async (args, timeout) => {
      calls.push(args); events.push('invoke'); assert.equal(timeout, 15000);
      assert.deepEqual(JSON.parse(await readFile(args[args.indexOf('--body') + 1].slice(1))), q.phase.request.body);
      return {};
    }, { now: () => at, sourceDigest: async () => base.source });
    await io.write(q.phase, () => { events.push('guard'); }, async () => { events.push('current'); },
      async () => { events.push('durable-marker'); return { rolloutDeadline: at + 120000,
        beforeInvoke: () => { events.push('mark'); } }; }, at + 120000);
    assert.deepEqual(events, ['current', 'guard', 'durable-marker', 'guard', 'guard', 'mark', 'invoke']);
    assert.equal(calls.length, 1);
    const wrong = structuredClone(q.phase); wrong.request.id = base.topology.ids.account;
    await assert.rejects(io.write(wrong, () => {}, async () => {}, () => {}, at + 120000), /FIXED_WRITE_REQUIRED/);
    assert.equal(calls.length, 1);
  } finally { await rm(directory, { recursive: true }); }
});

test('concrete native validate and async what-if use the parent fixed context without phase spoofing', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network');
  const directory = `infrastructure/arm/telemetry/tests/.private-link-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  try {
    const exact = privateLinkPhase(base.c, base.context, 'create-network'), context = whatIfRequestContext(base.c, exact);
    const calls = [], io = privateLinkAzureIO(base.c, base.context, evidence, q.phase, directory,
      { publication: { commitSha: 'e'.repeat(40), sourceSha256: base.source } }, async (args, timeout) => {
        calls.push(args); assert.equal(args[0], 'deployment'); assert.equal(args[2], 'validate');
        assert(timeout <= 15000);
        assert.deepEqual(JSON.parse(await readFile(args[args.indexOf('--template-file') + 1])), q.phase.template);
        return { properties: { provisioningState: 'Succeeded', templateHash: hash(q.phase.template) } };
      }, { now: () => at, request: async operation => {
        operation.beforeDispatch();
        return { version: 1, statusCode: 200, headers: {}, body: { status: 'Succeeded', properties: { changes: q.proof.preview.changes } },
          bodyParseError: false, contextSha256: context.contextSha256, responseFile: 'whatif-response-0000.json',
          step: 'what-if.start', verifiedRegion: base.c.location };
      } });
    const preview = await io.preview(q.phase, at + 120000);
    assert.equal(calls.length, 1);
    verifyPrivateLinkPreview(q.phase, preview.preview, q.before, []);
  } finally { await rm(directory, { recursive: true }); }
});

test('physical global fence survives directory/context changes and failed head persistence', async () => {
  const evidence = prefix('create-network'), q = await privateControlHarness(f(), evidence, 'create-network'), files = new Map();
  const target = privateLinkTargetKey(base.context), head = privateLinkHead(base.context, evidence);
  files.set(`private-link-head-${target}.json`, head);
  const terminal = evidence.records.at(-1);
  files.set(`private-link-fence-${target}.json`, { version: 1, targetKey: target, stage: terminal.stage,
    phase: terminal.phase, intent: terminal.intent, intentSha256: terminal.intentSha256 });
  files.set(`private-link-intent-${hash({ target, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent });
  const writes = [], store = { root: 'UNIT no filesystem writes',
    read: async (_root, name) => structuredClone(files.get(name) ?? null),
    save: async (_root, name, value) => { writes.push(name); if (name.startsWith('private-link-head-')) throw new Error('UNIT_HEAD_FAILURE'); files.set(name, structuredClone(value)); },
    saveImmutable: async (_root, name, value) => { if (files.has(name)) throw new Error('UNIT_EXISTS'); writes.push(name); files.set(name, structuredClone(value)); } };
  const inputs = { publication: { commitSha: 'e'.repeat(40), sourceSha256: base.source } };
  const io = privateLinkAzureIO(base.c, base.context, evidence, q.phase, 'UNIT-unused-dir', inputs,
    async () => assert.fail('Cloud call'), { store });
  const intent = { version: 2, stage: q.phase.stage, phaseSha256: hash(q.phase), approvalSha256: hash(q.approval), requestSha256: hash(q.phase.request),
    previousHeadSha256: hash(head), at: new Date(at).toISOString() };
  await assert.rejects(io.reserve(evidence, q.phase, intent), /HEAD_FAILURE/);
  const changed = { ...base.context, plan: { ...base.context.plan, sourceSha256: digest('UNIT changed context') } };
  assert.equal(privateLinkTargetKey(changed), target);
  await assert.rejects(readPrivateLinkHead(changed, evidence, store), /CANONICAL_HEAD_CHANGED/);
  await assert.rejects(readPrivateLinkHead(base.context, evidence, store), /CANONICAL_HEAD_CHANGED/);
  assert.equal(writes.length, 3);
});

test('immutable intent archive tampering is rejected for both pending and terminal heads', async () => {
  const evidence = prefix('create-network'), terminal = evidence.records.at(-1), target = privateLinkTargetKey(base.context);
  const files = new Map([
    [`private-link-head-${target}.json`, privateLinkHead(base.context, evidence)],
    [`private-link-fence-${target}.json`, { version: 1, targetKey: target, stage: terminal.stage,
      intentSha256: terminal.intentSha256, phase: terminal.phase, intent: terminal.intent }],
    [`private-link-intent-${hash({ target, stage: terminal.stage })}.json`, { phase: terminal.phase, intent: terminal.intent }],
  ]);
  const store = { root: 'UNIT', read: async (_root, name) => structuredClone(files.get(name) ?? null) };
  await readPrivateLinkHead(base.context, evidence, store);
  files.get(`private-link-intent-${hash({ target, stage: terminal.stage })}.json`).intent =
    { ...terminal.intent, requestSha256: digest('UNIT corrupted archive') };
  await assert.rejects(readPrivateLinkHead(base.context, evidence, store), /INTENT_ARCHIVE_CHANGED/);
  const first = { ...evidence, records: [] }, old = files.get(`private-link-fence-${target}.json`);
  files.set(`private-link-head-${target}.json`, { version: 1, kind: 'private-link-pending-head',
    targetKey: target, previous: privateLinkHead(base.context, first), intentSha256: old.intentSha256 });
  await assert.rejects(readPrivateLinkHead(base.context, first, { ...store,
    pending: files.get(`private-link-head-${target}.json`) }), /INTENT_ARCHIVE_CHANGED/);
});

test('324 policy reads overlap fresh collection under the shared four-command and 120-second bounds', async t => {
  const q = await privateControlHarness(f(), prefix('create-network'), 'create-network');
  const policy = effectivePolicyFixture(), map = new Map(policy.responses), raw = q.io.read;
  delete policy.assignment.properties.effectiveDefinitionVersion;
  map.set(`${policy.setId}/versions`, { value: [{ id: policy.initiative.id, name: '1.0.0', properties: { version: '1.0.0' } }] });
  policy.initiative.properties.policyDefinitions = [];
  for (let i = 0; i < 160; i++) {
    const id = policy.definitionId + '-' + i, child = structuredClone(policy.definition);
    child.id = id + '/versions/1.0.0'; child.properties.parameters = {};
    child.properties.policyRule = { if: { field: 'type', equals: 'Microsoft.Unrelated/widgets' }, then: { effect: 'deny' } };
    policy.initiative.properties.policyDefinitions.push({ policyDefinitionId: id, policyDefinitionReferenceId: 'unit-' + i });
    map.set(id + '/versions', { value: [{ id: child.id, name: '1.0.0', properties: { version: '1.0.0' } }] });
    map.set(child.id, child);
  }
  const start = q.io.now(), pending = [];
  let scheduled = false, active = 0, maximum = 0, reads = 0, policyReads = 0;
  const delay = ms => new Promise(resolve => {
    pending.push({ at: q.io.now() + ms, resolve });
    const flush = () => {
      scheduled = false;
      const next = Math.min(...pending.map(value => value.at)); q.advance(Math.max(0, next - q.io.now()));
      for (const value of pending.filter(value => value.at <= q.io.now())) { pending.splice(pending.indexOf(value), 1); value.resolve(); }
      if (pending.length) { scheduled = true; setImmediate(flush); }
    };
    if (!scheduled) { scheduled = true; setImmediate(flush); }
  });
  const command = limitReadConcurrency(async work => {
    active++; reads++; maximum = Math.max(maximum, active);
    await delay(850);
    try { return await work(); } finally { active--; }
  });
  q.io.read = (request, deadline) => command(() => {
    if (map.has(request.id)) { policyReads++; return structuredClone(map.get(request.id)); }
    return raw(request, deadline);
  });
  const account = q.io.account, registry = q.io.registry, preview = q.io.preview;
  q.io.account = () => command(account);
  q.io.registry = async () => {
    await command(async () => null); await command(async () => null);
    await Promise.all(Array.from({ length: 6 }, () => command(async () => null)));
    return registry();
  };
  q.io.preview = async () => { await command(async () => null); await delay(7000); return preview(); };
  const proof = await checkPrivateLinkPhase(base.c, base.context, prefix('create-network'), q.phase, q.io);
  assert.equal(maximum, 4); assert.equal(policyReads, 324); assert(reads > 360);
  assert(proof.completedAt - proof.startedAt < 120000);
  assert(q.io.now() - start >= 75000);
  t.diagnostic(JSON.stringify({ totalCommands: reads, policyReads, maximumConcurrentCommands: maximum,
    preflightMs: proof.completedAt - proof.startedAt, commandLatencyMs: 850, checkBoundMs: 120000 }));
});

test('post-body final checks do not consume the separately recorded 120-second rollout', async () => {
  const q = await privateControlHarness(f(), prefix('create-network'), 'create-network');
  const write = q.io.write;
  q.io.write = async (phase, guard, current, mark, deadline) => {
    q.advance(80000);
    await write(phase, guard, current, mark, deadline);
    for (const d of phase.resources) q.after.resources[d.id].systemData.createdAt = new Date(q.io.now()).toISOString();
    q.advance(90000);
  };
  const record = await q.execute();
  assert.equal(Date.parse(record.journal.rolloutStartedAt) - Date.parse(record.intent.at), 80000);
  assert.equal(record.journal.rolloutDeadline, Date.parse(record.journal.rolloutStartedAt) + 120000);
  assert(Date.parse(record.completedAt) - Date.parse(record.intent.at) > 120000);
  assert(Date.parse(record.completedAt) < record.journal.rolloutDeadline);
  assert.equal(q.writes, 1);
});

test('concrete reader follows only exact pinned list pages and preserves failures instead of partial success', async () => {
  const directory = `infrastructure/arm/telemetry/tests/.private-link-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  const request = { id: `${ids(base.c).sub}/providers/Microsoft.Network/virtualNetworks`, apiVersion: '2024-05-01', filter: null };
  const url = `https://management.azure.com${request.id}?api-version=${request.apiVersion}`;
  try {
    let calls = 0;
    const reader = privateLinkReadIO(base.c, base.context, directory, async () => ++calls === 1
      ? { value: [{ id: 'UNIT-first' }], nextLink: url + '&$skiptoken=unit' } : { value: [{ id: 'UNIT-second' }] }, { now: () => at });
    assert.equal((await reader.read(request, at + 120000, true)).value.length, 2);
    assert.equal(calls, 2);
    const wrong = privateLinkReadIO(base.c, base.context, directory, async () =>
      ({ value: [{ id: 'UNIT' }], nextLink: 'https://foreign.invalid/more' }), { now: () => at });
    await assert.rejects(wrong.read(request, at + 120000, true), /NEXT_PAGE_SCOPE_CHANGED/);
    await assert.rejects(wrong.read({ ...request, id: request.id + '/listKeys' }, at + 120000), /READ_SCOPE_FORBIDDEN/);
    for (const [id, api, accepted] of [
      [request.id, request.apiVersion, false],
      [`${base.topology.ids.service}/queues`, '2025-01-01', false],
      [`${base.context.origin.network.topology.ids.perimeter}/profiles`, '2025-09-01', true],
    ]) {
      const io = privateLinkReadIO(base.c, base.context, directory, async () => ({ value: [], nextLink: '' }), { now: () => at });
      if (accepted) assert.deepEqual(await io.read({ id, apiVersion: api, filter: null }, at + 120000, true), { value: [] });
      else await assert.rejects(io.read({ id, apiVersion: api, filter: null }, at + 120000, true), /LIST_INCOMPLETE/);
    }
  } finally { await rm(directory, { recursive: true }); }
});

test('known queue role/assignment absence is exact; authentication and foreign-path failures are never absence', async () => {
  const invoke = code => async () => { const error = new Error('UNIT CLI error');
    error.stderr = `ERROR: Not Found({"error":{"code":"${code}"}})`; throw error; };
  for (const [id, code] of [[base.topology.ids.role, 'RoleDefinitionDoesNotExist'],
    [base.topology.ids.assignment, 'RoleAssignmentNotFound']]) {
    const args = ['rest', '--method', 'GET', '--url', `https://management.azure.com${id}?api-version=2022-04-01`,
      '--subscription', base.c.subscriptionId, '--only-show-errors', '--output', 'json'];
    assert.equal(await az(args, 15000, invoke(code)), null);
    await assert.rejects(az(args, 15000, invoke('AuthorizationFailed')), /ARM_OPERATION_FAILED/);
    const foreign = [...args]; foreign[4] = 'https://management.azure.com/subscriptions/foreign/providers/Microsoft.Authorization/roleAssignments/foreign?api-version=2022-04-01';
    await assert.rejects(az(foreign, 15000, invoke(code)), /ARM_OPERATION_FAILED/);
  }
});
