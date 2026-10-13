import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { digest, ids, json, storageContract } from '../definition.mjs';
import { PRIVATE_LINK_AUTHORITY, PRIVATE_LINK_STAGES, buildPrivateLinkPlan, privateLinkAddresses,
  privateLinkCost, privateLinkTopology, verifyPrivateLinkContext, verifyPrivateLinkPlan } from '../private-link.mjs';
import { nspTopology, emptyNspEvidence, nspPendingHead, nspPreflightBaseline, nspTargetKey, verifyNspObservation } from '../nsp.mjs';
import { verifyNspStoppedAttempt } from '../nsp-reconciliation.mjs';
import { preparePrivateLinkLocal, publishedSourceDigest, sourceDigest } from '../controller.mjs';
import { QUEUE_PERMISSIONS, QUEUE_RUNTIME } from '../durable-queue.mjs';
import { queueUpgradeFixture } from './durable-queue.fixture.mjs';
import { queueAdoptionFixture } from './queue-adoption.fixture.mjs';
import { nspPhaseFixture } from './nsp.fixture.mjs';

const hash = value => digest(json(value));
// Entirely synthetic history and address space; no live approvals or network reservations.
const input = { version: 1, addresses: { vnet: '10.240.8.0/24', apps: '10.240.8.0/26',
  endpoint: '10.240.8.64/28', knownAddressSpaces: ['10.10.0.0/16', '192.168.0.0/24'] }, overlapDays: 7 };
async function fixture() {
  const upgraded = await queueUpgradeFixture(), f = await queueAdoptionFixture(upgraded);
  const network = emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
  for (const phase of ['nsp-empty-boundary', 'nsp-storage-lock', 'nsp-enforced-association']) {
    const q = nspPhaseFixture(f, f.adoption, network, phase);
    await q.controller.execute(q.approval);
    network.records.push(q.record());
  }
  const q = nspPhaseFixture(f, f.adoption, network, 'nsp-subscription-admission');
  const receiver = upgraded.receipts.receiverUpgrade;
  Object.assign(q.proof.foundationBinding, { receiverRecordSha256: hash(receiver),
    receiverManifestDigest: receiver.candidate.profile.manifestDigest, receiverConfigDigest: receiver.candidate.profile.configDigest });
  q.proof.baselineSha256 = nspPreflightBaseline(q.proof);
  q.approval.baselineSha256 = q.proof.baselineSha256;
  let reservation;
  q.io.reserve = async journal => { reservation = structuredClone({ phase: q.phase, approvalSha256: hash(q.approval), journal }); };
  q.after.resources[network.topology.ids.rule].properties.appliesTo = [{ resourceType: '*', features: ['*'] }];
  q.after.rules.value[0] = structuredClone(q.after.resources[network.topology.ids.rule]);
  await assert.rejects(q.controller.execute(q.approval), /NSP_CHANGE_STOPPED/);
  assert.equal(q.writes, 1);
  const original = Object.fromEntries(['phase', 'publication', 'approval', 'preflight', 'preview', 'validation', 'journal', 'receipt']
    .map(key => [key, q.record()[key]]));
  original.reservation = reservation;
  const context = { adoption: f.adoption, network, original,
    pendingHead: nspPendingHead(network, q.phase, reservation.journal),
    receiver, queueProfile: upgraded.candidate.profile };
  return { f, context, q };
}
const fixtureValue = await fixture();
const planFor = (context = fixtureValue.context, proposed = input) =>
  buildPrivateLinkPlan(fixtureValue.f.c, context, proposed, fixtureValue.f.source);

test('local Private Link plan preserves the stopped NSP attempt and never grants effect authority', () => {
  const { f, context, q } = fixtureValue, before = json(context), plan = planFor();
  verifyNspStoppedAttempt(f.c, context.original, f.topology, f.adoption, context.network, context.pendingHead);
  assert.equal(context.original.journal.failureCode, 'NSP_RULE_DRIFT');
  assert.equal(plan.originalAttemptSha256, hash(context.original));
  assert.equal(plan.pendingHeadSha256, hash(context.pendingHead));
  assert.equal(plan.physicalTargetKey, nspTargetKey(context.network.topology));
  assert.equal(plan.originalExecutionQualified, false);
  assert.equal(plan.originalHistoryModified, false);
  assert.equal(plan.originalIntentReplayAuthorized, false);
  assert.equal(plan.executable, true);
  assert.equal(plan.version, 2);
  assert.deepEqual(plan.authority, PRIVATE_LINK_AUTHORITY);
  assert(Object.values(plan.authority).every(value => value === false));
  assert.deepEqual(planFor(), plan);
  assert.equal(json(context), before);
  assert.throws(() => verifyNspObservation(f.c, context.network.topology, f.adoption, q.after,
    'subscription-admission-converged'), /NSP_RULE_DRIFT/);
  const checked = verifyPrivateLinkPlan(f.c, context, plan, f.source);
  assert.equal(checked.localContractValid, true);
  assert.equal(checked.cloudStateVerified, false);
  assert.equal(checked.executionAuthorized, false);
  assert.equal(checked.retirementAuthorized, false);
});

test('address inputs are explicit canonical RFC1918 subnets with containment, disjointness and reserved-space checks', () => {
  assert.deepEqual(privateLinkAddresses(input.addresses), input.addresses);
  for (const change of [
    value => { value.vnet = '10.240.8.1/24'; }, value => { value.vnet = '10.240.08.0/24'; },
    value => { value.vnet = '8.8.8.0/24'; }, value => { value.vnet = '172.30.8.0/24'; },
    value => { value.vnet = '100.100.1.0/24'; }, value => { value.vnet = '2001:db8::/64'; },
    value => { value.apps = '10.240.9.0/26'; }, value => { value.endpoint = '10.240.8.16/28'; },
    value => { value.apps = '10.240.8.0/27'; }, value => { value.endpoint = '10.240.8.64/27'; },
    value => { value.knownAddressSpaces = ['10.0.0.0/8']; }, value => { value.knownAddressSpaces = ['10.240.8.128/25']; },
    value => { value.knownAddressSpaces = ['10.10.0.0/16', '10.10.0.0/16']; },
    value => { value.knownAddressSpaces = Array(513).fill('10.10.0.0/16'); },
    value => { value.knownAddressSpaces = null; }, value => { value.approved = true; },
  ]) {
    const changed = structuredClone(input.addresses);
    change(changed);
    assert.throws(() => privateLinkAddresses(changed));
  }
  const topology = privateLinkTopology(fixtureValue.f.c, fixtureValue.f.topology, input);
  assert.equal(topology.addressInventoryVerified, false);
  assert.equal(topology.exactManagedGroupAbsenceRequired, true);
});

test('cost preserves conservative reserves, overlap and unapproved budgets without treating estimates as caps', () => {
  assert.equal(privateLinkCost(1).steadyMonthly, 359.71);
  assert.equal(privateLinkCost(1).migrationMonth, 367.01);
  assert.equal(privateLinkCost(7).migrationMonth, 410.75);
  const cost = privateLinkCost(7);
  assert.equal(cost.carriedForwardBase, 349.37);
  assert.equal(cost.baseRepriced, false);
  assert.equal(cost.planningApproved, false);
  assert.equal(cost.isHardCap, false);
  assert.equal(cost.actualBudgetSettings.projectAmount, 350);
  assert.equal(cost.proposedMigrationPlanning, 425);
  assert.equal(cost.retirementRequiredForSteadyEstimate, true);
  for (const days of [0, 8, 1.1, '1', null, Infinity]) assert.throws(() => privateLinkCost(days));
});

test('migration order revokes the uncertain rule and disables Storage before removing the association', () => {
  const plan = planFor(), stages = plan.stages, n = plan.topology.ids, old = fixtureValue.context.network.topology.ids;
  assert.deepEqual(stages.map(value => value.id), PRIVATE_LINK_STAGES);
  for (let index = 1; index < stages.length; index++) assert.deepEqual(stages[index].requires, [stages[index - 1].id]);
  const stage = id => stages.find(value => value.id === id);
  assert.deepEqual(stage('retire-nsp-rule').proposedRequest, {
    method: 'DELETE', id: old.rule, apiVersion: '2025-09-01', body: null,
  });

  assert.deepEqual(stage('disable-storage-public').proposedRequest.body, { properties: { publicNetworkAccess: 'Disabled' } });
  assert.equal(stage('disable-storage-public').proposedRequest.id, n.account);
  assert(stages.indexOf(stage('disable-storage-public')) < stages.indexOf(stage('retire-nsp-association')));
  assert(stages.indexOf(stage('qualify-private-delivery')) < stages.indexOf(stage('retire-old-receiver')));
  assert.equal(stage('retire-old-environment').proposedRequest.id, ids(fixtureValue.f.c).environment);
  assert(stages.every(value => value.qualified === false && value.executionAuthorized === false));
  assert(!stages.some(value => value.proposedRequest?.method === 'DELETE' &&
    plan.preservedResourceIds.includes(value.proposedRequest.id)));
  assert(stage('record-migration').requiredEvidence.includes('original-nsp-execution-remains-failed'));
});

test('explicit input v2 adds only the patched disabled public probe and transient reserve without rewriting v1 plans', () => {
  const original = planFor(), before = json(original), next = planFor(fixtureValue.context, { ...input, version: 2 });
  assert.equal(original.version, 2); assert.equal(next.version, 3);
  assert.equal(original.publicProbe, undefined);
  assert.equal(next.publicProbe.id, `${ids(fixtureValue.f.c).group}/providers/Microsoft.App/containerApps/${fixtureValue.f.c.namePrefix}-public-probe`);
  assert.equal(next.publicProbe.expected.properties.managedEnvironmentId, ids(fixtureValue.f.c).environment);
  assert.equal(next.publicProbe.expected.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value, 'false');
  assert(next.publicProbe.expected.properties.template.containers[0].image.endsWith(fixtureValue.context.queueProfile.manifestDigest));
  assert.equal(next.topology.cost.migrationMonth, 411.75);
  assert.equal(next.topology.cost.steadyMonthly, original.topology.cost.steadyMonthly);
  assert.equal(next.topology.cost.transientPublicProbe.maximumMs, 900000);
  assert.equal(next.topology.cost.transientPublicProbe.additionalEnvironments, 0);
  assert.equal(json(original), before);
  verifyPrivateLinkPlan(fixtureValue.f.c, fixtureValue.context, original, fixtureValue.f.source);
  verifyPrivateLinkPlan(fixtureValue.f.c, fixtureValue.context, next, fixtureValue.f.source);
});

test('templates produce a queue-only private endpoint, exact DNS and a separate externally reachable Consumption environment', () => {
  const plan = planFor(), n = plan.topology.ids;
  const resources = plan.stages.flatMap(value => value.resources);
  const find = id => resources.find(value => value.id === id).expected;
  assert.equal(find(n.appsSubnet).properties.addressPrefix, input.addresses.apps);
  assert.equal(find(n.appsSubnet).properties.delegations[0].properties.serviceName, 'Microsoft.App/environments');
  assert.equal(find(n.endpointSubnet).properties.addressPrefix, input.addresses.endpoint);
  assert.deepEqual(find(n.endpoint).properties.privateLinkServiceConnections, [
    { name: 'queue', properties: { privateLinkServiceId: n.account, groupIds: ['queue'] } },
  ]);
  assert.equal(find(n.dnsZone).name, 'privatelink.queue.core.windows.net');
  assert.deepEqual(find(n.dnsLink).properties, { registrationEnabled: false, virtualNetwork: { id: n.vnet } });
  assert.deepEqual(find(n.dnsZoneGroup).properties.privateDnsZoneConfigs,
    [{ name: 'queue', properties: { privateDnsZoneId: n.dnsZone } }]);
  assert.deepEqual(find(n.environment).properties.vnetConfiguration, { infrastructureSubnetId: n.appsSubnet, internal: false });
  assert.equal(find(n.environment).properties.publicNetworkAccess, 'Enabled');
  assert.deepEqual(find(n.environment).properties.workloadProfiles, [{ name: 'Consumption', workloadProfileType: 'Consumption' }]);
  assert.notEqual(n.environment, ids(fixtureValue.f.c).environment);
  assert.equal(plan.topology.budgetCoverage.explicitFilterReviewRequired, true);
  assert.equal(plan.topology.budgetCoverage.automaticBudgetChange, false);
  assert.equal(plan.topology.budgetCoverage.additionalResourceGroup, n.managedGroup);
  assert(!resources.some(value => /natGateways|azureFirewalls|dnsResolvers|frontDoors|publicIPAddresses/iu.test(value.type)));
});

test('replacement receiver reuses the frozen contract, UAMIs and runtime limits with only the explicit overlay', () => {
  const { f, context } = fixtureValue, plan = planFor(), n = plan.topology.ids;
  const app = plan.stages.find(value => value.id === 'create-disabled-receiver').resources[0].expected;
  const before = structuredClone(context.receiver.phase.resources[0].expected);
  before.name = n.app.split('/').at(-1);
  before.properties.managedEnvironmentId = n.environment;
  before.properties.template.containers[0].image = `${f.c.registryName}.azurecr.io/missionspec/telemetry-ingest@${context.queueProfile.manifestDigest}`;
  before.properties.template.containers[0].env.push(
    { name: 'AZURE_QUEUE_URL', value: f.topology.ids.queueUrl },
    { name: 'AZURE_QUEUE_RESOURCE_ID', value: f.topology.ids.queue });
  assert.deepEqual(app, before);
  assert.equal(app.properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value, 'false');
  assert.equal(app.properties.configuration.ingress.external, true);
  assert.equal(app.properties.configuration.ingress.allowInsecure, false);
  assert(!plan.topology.queueUrl.includes('privatelink.'));
  assert.deepEqual(plan.runtime, QUEUE_RUNTIME);
  const role = plan.stages.find(value => value.id === 'create-queue-role').resources[0];
  assert.deepEqual(role.expected.properties.permissions, [QUEUE_PERMISSIONS]);
  assert.deepEqual(role.expected.properties.assignableScopes, [f.topology.ids.queue]);
});

test('modified plans, authority flags, source/history substitution and unknown inputs are rejected', () => {
  const { f, context } = fixtureValue;
  for (const change of [
    value => { value.executable = false; }, value => { value.authority.deployment = true; },
    value => { value.originalExecutionQualified = true; }, value => { value.stages.reverse(); },
    value => { value.stages[1].proposedRequest.id = ids(f.c).app; }, value => { value.sourceSha256 = digest('new source'); },
    value => { value.topology.cost.steadyMonthly = 1; }, value => { value.topology.addressInventoryVerified = true; },
  ]) {
    const plan = structuredClone(planFor());
    change(plan);
    assert.throws(() => verifyPrivateLinkPlan(f.c, context, plan, f.source));
  }
  for (const change of [
    value => { value.original.journal.transportDispatchAttempted = false; },
    value => { value.original.journal.outcome = 'readback-qualified'; },
    value => { value.original.journal.failureCode = 'UNIT_UNKNOWN'; },
    value => { value.original.approval.sourceSha256 = digest('substitution'); },
    value => { value.pendingHead.intentSha256 = digest('different intent'); },
    value => { value.receiver.receipt.ingestionEnabled = true; },
    value => { value.queueProfile.runtime.producerDeadlineMs = 60000; },
    value => { value.approved = true; },
  ]) {
    const changed = structuredClone(context);
    change(changed);
    assert.throws(() => verifyPrivateLinkContext(f.c, changed));
  }
  assert.throws(() => planFor(context, { ...input, approved: true }));
  assert.throws(() => buildPrivateLinkPlan(f.c, context, input, 'unbound'));
});

test('the operator refuses private-link execution and cross-phase dispatch before any input or cloud read', async () => {
  const run = promisify(execFile);
  for (const [operation, phase] of [
    ['execute-private-link', 'private-link-migration'], ['execute', 'private-link-migration'],
    ['check-private-link-plan', 'nsp-storage-lock'], ['preview-private-link', 'queue-role'],
    ['retire-private-link', 'private-link-migration'], ['qualify-private-link', 'private-link-migration'],
  ]) await assert.rejects(run(process.execPath, ['infrastructure/arm/telemetry/controller.mjs',
    operation, phase, 'must-not-be-created'], { timeout: 10000 }),
  error => error.code === 1 && error.stderr.trim() === 'FIXED_PHASE_COMMAND_REQUIRED');
});

test('local preparation and recheck bind source, retained history and unchanged pending head without an executor', async () => {
  const { f, context } = fixtureValue;
  const files = new Map([['private-link-context.json', context], ['private-link-input.json', input]]);
  const sources = new Map([
    ...['priorPublication', 'publication'].map(key => {
      const value = JSON.parse(context.adoption.origin.artifacts[key].json);
      return [value.commitSha, value.sourceSha256];
    }),
    [context.adoption.publication.commitSha, context.adoption.publication.sourceSha256],
    ...context.network.records.map(value => [value.publication.commitSha, value.publication.sourceSha256]),
    [context.original.publication.commitSha, context.original.publication.sourceSha256],
  ]);
  let writes = 0, heads = 0, calls = 0, changed = false;
  const io = {
    read: async (_directory, name) => { assert(files.has(name), name); return structuredClone(files.get(name)); },
    save: async (_directory, name, value) => {
      assert.equal(name, 'private-link-plan.json');
      assert(!files.has(name), 'Existing plan cannot be overwritten');
      files.set(name, structuredClone(value)); writes++;
    },
    source: async () => ++calls % 2 === 0 && changed ? digest('UNIT changed source') : f.source,
    readHead: async (network, pending) => {
      assert.deepEqual(network, context.network); assert.deepEqual(pending, context.pendingHead); heads++;
    },
    lookup: async commit => { assert(sources.has(commit), commit); return sources.get(commit); },
  };
  const original = json(context);
  const prepared = await preparePrivateLinkLocal(f.c, 'preview-private-link', 'UNIT private directory', io);
  assert.equal(writes, 1); assert.equal(heads, 2);
  assert.equal(prepared.executionAuthorized, false);
  assert.deepEqual(await preparePrivateLinkLocal(f.c, 'check-private-link-plan', 'UNIT private directory', io), prepared);
  assert.equal(writes, 1); assert.equal(heads, 4); assert.equal(json(context), original);
  files.get('private-link-plan.json').executable = false;
  await assert.rejects(preparePrivateLinkLocal(f.c, 'check-private-link-plan', 'UNIT', io), /PRIVATE_LINK_PLAN_DRIFT/);
  files.delete('private-link-plan.json');
  calls = 0; changed = true;
  await assert.rejects(preparePrivateLinkLocal(f.c, 'preview-private-link', 'UNIT', io), /PRIVATE_LINK_SOURCE_CHANGED/);
  assert.equal(writes, 1);
  changed = false; calls = 0;
  await assert.rejects(preparePrivateLinkLocal(f.c, 'preview-private-link', 'UNIT',
    { ...io, readHead: async () => { throw new Error('NSP_INTENT_FENCE_CHANGED'); } }), /NSP_INTENT_FENCE_CHANGED/);
  await assert.rejects(preparePrivateLinkLocal(f.c, 'preview-private-link', 'UNIT',
    { ...io, lookup: async () => digest('UNIT unknown source') }), /PUBLISHED_SOURCE_CHANGED/);
  assert.equal(writes, 1);
});

test('Private Link code enters current source hashing but is not retroactively added to historical controllers', async () => {
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs', 'arm-whatif.py', 'receiver-upgrade.mjs', 'durable-queue.mjs',
    'effective-policy.mjs', 'queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs', 'queue-defender.mjs'];
  const privateNames = ['private-link.mjs', 'private-link-whatif.mjs', 'private-link-controller.mjs',
    'private-link-readback.mjs', 'private-link-runtime.mjs', 'private-link-exec.py', 'private-link-artifacts.mjs',
    'private-link-nsg-adoption.mjs'];
  const prefix = 'infrastructure/arm/telemetry/', contract = await storageContract(), commit = 'e'.repeat(40);
  for (const include of [false, true, 'runtime', 'indirect-adoption']) {
    const additions = ['runtime', 'indirect-adoption'].includes(include) ? privateNames : include ? ['private-link.mjs'] : [];
    const files = Object.fromEntries([...names, ...privateNames].map(name => [prefix + name, `UNIT ${name}`]));
    files[prefix + 'controller.mjs'] = names.slice(6).map(name => `import {} from './${name}';`).join('\n') +
      additions.filter(name => !['private-link-readback.mjs', 'private-link-exec.py'].includes(name))
        .filter(name => include !== 'indirect-adoption' || name !== 'private-link-nsg-adoption.mjs')
        .map(name => `\nimport {} from './${name}';`).join('');
    if (include === 'indirect-adoption') files[prefix + 'private-link-controller.mjs'] =
      "import { verifyPrivateLinkNsgAdoption } from './private-link-nsg-adoption.mjs';";
    files['assets/schemas/telemetry-event.schema.json'] = json(contract.schema);
    files['services/telemetry-ingest/schema/storage-columns.json'] = json(contract.columns);
    const expected = createHash('sha256');
    for (const name of [...names, ...additions]) expected.update(name).update(files[prefix + name]);
    expected.update(json(contract));
    const run = async (_command, args) => {
      if (args[0] === 'merge-base') return { stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { stdout: Buffer.from(args.at(-1) + '\n') };
      const filename = args.at(-1).slice(41);
      assert(Object.hasOwn(files, filename), filename);
      return { stdout: Buffer.from(files[filename]) };
    };
    assert.equal(await publishedSourceDigest(commit, run), expected.digest('hex'));
  }
  const current = createHash('sha256');
  for (const name of [...names, ...privateNames]) current.update(name).update(await readFile(prefix + name));
  current.update(json(contract));
  assert.equal(await sourceDigest(), current.digest('hex'));
});
