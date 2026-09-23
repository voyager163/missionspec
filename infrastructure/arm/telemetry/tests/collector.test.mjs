import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, rm } from 'node:fs/promises';
import { buildPhase, storageContract, ids, json, digest, ownerTags, firstReleaseCost, PHASES, LIMITS, RECEIVER_DIGEST, RECEIVER_COMMAND,
  BUDGET, budgetProperties, budgetConfiguration, projectBudgetFilter, validateConfig } from '../definition.mjs';
import { verifyWhatIf, assertBudget, permitFirstPush, verifyResource } from '../policy.mjs';
import { CollectorController, az, transport, validateReadOnly, verifyScannerAdoption, verifyOrigin, verifyProjectBudgetReceipt,
  checkReadOnly, saveImmutable } from '../controller.mjs';

const c = { version: 2, subscriptionId: '00000000-0000-4000-8000-000000000001',
  tenantId: '00000000-0000-4000-8000-000000000002', operatorPrincipalId: '00000000-0000-4000-8000-000000000003',
  runId: '00000000-0000-4000-8000-000000000004', namePrefix: 'missionspec-test', registryName: 'missionspectest',
  location: 'australiaeast', budgetEmail: 'operator@example.invalid', budgetStart: '2026-09-01T00:00:00Z',
  budgetEnd: '2027-09-01T00:00:00Z', queryPrincipalIds: ['00000000-0000-4000-8000-000000000003'], receiverDigest: RECEIVER_DIGEST,
  budget: { ...BUDGET }, originSha256: digest('origin'), scannerAdoptionSha256: digest('adoption'), foundationBudgetsSha256: digest('foundation') };
function fixtureFoundation(config = c) {
  const r = ids(config);
  const record = (id, amount, filter) => ({ id, name: id.split('/').at(-1), type: 'Microsoft.Consumption/budgets', eTag: 'old',
    properties: { ...budgetProperties(config, amount), filter, currentSpend: { amount: 0, unit: 'USD' }, forecastSpend: null } });
  const foundation = { version: 1, originSha256: config.originSha256, checkedAt: '2026-09-23T00:00:00.000Z',
    project: record(r.projectBudget, 250, projectBudgetFilter(config)), state: record(r.stateBudget, 50, {}) };
  config.foundationBudgetsSha256 = digest(json(foundation));
  return foundation;
}
const foundation = fixtureFoundation();
const contract = await storageContract(), r = ids(c);
function fixtureReceipts(config = c) {
  const c = config, r = ids(c);
  const foundation = fixtureFoundation(c), budgetPhase = buildPhase(c, 'project-budget', null, {}, foundation);
  const owned = (id, properties) => ({ id, tags: ownerTags(c), properties });
  const core = { configSha256: digest(json(c)), qualified: true, resources: {
    [r.workspace]: owned(r.workspace, { features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: false } }),
    [r.ingestIdentity]: owned(r.ingestIdentity, { clientId: '00000000-0000-4000-8000-000000000005', principalId: '00000000-0000-4000-8000-000000000006' }),
    [r.pullIdentity]: owned(r.pullIdentity, { clientId: '00000000-0000-4000-8000-000000000007', principalId: '00000000-0000-4000-8000-000000000008' }),
    [r.registry]: owned(r.registry, { loginServer: `${c.registryName}.azurecr.io` }),
  } };
  return { 'project-budget': { qualified: true, phase: 'project-budget', configSha256: digest(json(c)),
    sourceSha256: digest('source'), phaseSha256: digest(json(budgetPhase)),
    deployment: { id: budgetPhase.deploymentId, properties: { provisioningState: 'Succeeded' } },
    resources: { [r.projectBudget]: { id: r.projectBudget, ...structuredClone(budgetPhase.resources[0].expected) } } },
    core, 'workspace-access': { ...core, resources: { [r.workspace]: core.resources[r.workspace] } },
    data: { configSha256: digest(json(c)), qualified: true, resources: { [r.dcr]: owned(r.dcr,
      { immutableId: 'dcr-' + 'a'.repeat(32), endpoints: { logsIngestion: 'https://missionspec-test.australiaeast-1.ingest.monitor.azure.com' } }) } },
    'upload-role': { configSha256: digest(json(c)), qualified: true, resources: {} },
    assignments: { configSha256: digest(json(c)), qualified: true, resources: {} },
    publication: { qualified: true, digest: RECEIVER_DIGEST, registryId: r.registry, recentDigestCount: 1, configUser: '65532:65532',
      configSha256: 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204',
      configSha256Inputs: digest(json(c)), command: RECEIVER_COMMAND },
    'disabled-app': { configSha256: digest(json(c)), qualified: true } };
}
async function scratch(t) {
  const directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true }));
  return directory;
}
function executionFixture(phase = 'core') {
  const p = buildPhase(c, phase, contract, fixtureReceipts(), foundation);
  let now = Date.parse('2026-09-23T00:00:00.000Z'), journal = null, writes = 0, receipt = null;
  const bindings = { phaseSha256: digest(json(p)), configSha256: digest(json(c)),
    ...Object.fromEntries(['source', 'whatIf', 'origin', 'receipts', 'baseline'].map(key => [`${key}Sha256`, digest(key)])) };
  const approval = { action: `direct-arm-${phase}`, ...bindings,
    approvedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  const proof = { qualified: true, cost: firstReleaseCost(1), ...bindings, startedAt: now, completedAt: now };
  const io = { now: () => now, sourceDigest: async () => bindings.sourceSha256, loadJournal: async () => journal,
    check: async () => proof, saveJournal: async v => { journal = structuredClone(v); },
    saveReceipt: async value => { receipt = value; }, privacyChecks: async () => {}, sleep: async () => {},
    arm: async (method, _id, _api, _body, _filter, beforeDispatch) => {
      if (method === 'GET') return null;
      beforeDispatch?.(); writes++; throw new Error('UNKNOWN_SUBMISSION');
    } };
  return { p, proof, approval, io, advance: ms => { now += ms; },
    get journal() { return journal; }, get writes() { return writes; }, get receipt() { return receipt; } };
}
test('one canonical schema supplies exactly eight closed fields plus server TimeGenerated', () => {
  assert.equal(contract.columns.length, 9);
  assert.equal(contract.schema.additionalProperties, false);
  const p = buildPhase(c, 'data', contract, fixtureReceipts());
  assert.equal(p.resources.length, 2);
  const table = p.resources.find(v => v.id === r.table).expected.properties;
  assert.equal(table.plan, 'Analytics'); assert.equal(table.retentionInDays, 180); assert.equal(table.totalRetentionInDays, 180);
  assert.deepEqual(table.schema.columns, contract.columns);
  assert.equal(p.resources.find(v => v.id === r.dcr).expected.kind, 'Direct');
  assert.doesNotMatch(JSON.stringify(p), /rawBody|clientIp|connectionString|listKeys|dataExports/u);
});
test('core creates only six named resources and never overwrites the owned resource group or foundation', () => {
  const p = buildPhase(c, 'core', contract);
  assert.equal(p.resources.length, 6);
  assert(p.resources.every(v => v.id.startsWith(r.group + '/providers/')));
  assert(!p.resources.some(v => /resourceGroups$|virtualMachines|jobs|storageAccounts/u.test(v.type)));
  const env = p.resources.find(v => v.id === r.environment).expected.properties;
  assert.equal(env.infrastructureResourceGroup, 'missionspec-test-managed');
  assert.equal(env.appLogsConfiguration, undefined);
  assert.deepEqual(env.workloadProfiles, [{ name: 'Consumption', workloadProfileType: 'Consumption' }]);
  assert.throws(() => buildPhase({ ...c, location: 'westus' }, 'core', contract));
  assert.throws(() => buildPhase({ ...c, extra: true }, 'core', contract));
});
test('every permitted prefix length and phase retains the full run ID in a unique bounded ARM name', () => {
  for (let length = 2; length <= 10; length++) {
    const config = { ...c, namePrefix: `missionspec-${'a'.repeat(length)}`, registryName: `missionspec${'a'.repeat(length)}` };
    const f = fixtureFoundation(config);
    const names = PHASES.map(phase => buildPhase(config, phase, contract, fixtureReceipts(config), f).deploymentId.split('/').at(-1));
    assert.equal(new Set(names).size, PHASES.length);
    for (const name of names) {
      assert.match(name, /^[a-z0-9-]{1,64}$/u);
      assert(name.startsWith(config.namePrefix + '-'));
      assert(name.includes(config.runId.replaceAll('-', '')));
      assert.match(name, /-[a-z]{2}$/u);
    }
    const other = { ...config, runId: 'ffffffff-ffff-4fff-8fff-ffffffffffff' };
    assert.notEqual(buildPhase(config, 'core', contract).deploymentId, buildPhase(other, 'core', contract).deploymentId);
  }
  for (const suffix of ['a', 'a'.repeat(11), 'a_', 'AA', 'a/']) {
    const config = { ...c, namePrefix: `missionspec-${suffix}`, registryName: `missionspec${suffix}` };
    assert.throws(() => buildPhase(config, 'core', contract));
  }
  assert.throws(() => buildPhase(c, 'unreviewed-phase', contract));
});
test('read-only validate and full what-if use the actual execution name for every phase', async t => {
  const directory = await scratch(t);
  const config = { ...c, namePrefix: 'missionspec-0123456789', registryName: 'missionspec0123456789' };
  const f = fixtureFoundation(config), receipts = fixtureReceipts(config);
  for (const phaseName of PHASES) {
    const p = buildPhase(config, phaseName, contract, receipts, f), calls = [];
    const invoke = async args => {
      calls.push(args);
      assert.equal(args[0], 'deployment');
      assert.equal(args[1], p.scope === ids(config).sub ? 'sub' : 'group');
      assert.equal(args[args.indexOf('--name') + 1], p.deploymentId.split('/').at(-1));
      if (args[2] === 'validate') return { properties: { provisioningState: 'Succeeded' } };
      assert.equal(args[2], 'what-if');
      assert.equal(args[args.indexOf('--result-format') + 1], 'FullResourcePayloads');
      return { status: 'Succeeded', changes: p.resources.map(v => phaseName === 'project-budget'
        ? { resourceId: v.id, changeType: 'Modify', before: f.project, after: v.expected }
        : { resourceId: v.id, changeType: p.allowedModify[v.id] ? 'NoChange' : 'Create' }) };
    };
    const result = await validateReadOnly(config, p, receipts, directory, invoke);
    assert.equal(result.templateValidationOnly, true);
    assert.equal(calls.length, 2);
    const malformed = { ...p, deploymentId: p.deploymentId + '-unexpected' };
    await assert.rejects(validateReadOnly(config, malformed, receipts, directory, invoke), /DEPLOYMENT_NAME_INVALID/);
    assert.equal(calls.length, 2);
  }
});
test('data and privilege phases require real prior generated-ID and access readbacks', () => {
  assert.throws(() => buildPhase(c, 'data', contract, {}), /READBACK_REQUIRED/);
  const bad = fixtureReceipts(); bad['workspace-access'].resources[r.workspace].properties.features.enableLogAccessUsingOnlyResourcePermissions = true;
  assert.throws(() => buildPhase(c, 'data', contract, bad), /ACCESS_NOT_QUALIFIED/);
  const role = buildPhase(c, 'upload-role', contract, fixtureReceipts()).resources[0].expected.properties;
  assert.deepEqual(role.permissions[0].actions, []);
  assert.deepEqual(role.permissions[0].dataActions, ['Microsoft.Insights/Telemetry/Write']);
  assert.deepEqual(role.assignableScopes, [r.group]);
  const grants = buildPhase(c, 'assignments', contract, fixtureReceipts()).resources;
  assert.equal(grants.length, 3);
  assert(grants.every(v => [r.registry, r.dcr, r.workspace].includes(v.expected.scope)));
});
test('disabled receiver is digest-bound, singleton HTTPS, explicit identities and unchanged image command', () => {
  const p = buildPhase(c, 'disabled-app', contract, fixtureReceipts());
  const body = p.resources[0].expected;
  const app = body.properties, container = app.template.containers[0];
  assert.equal(container.command, undefined); assert.equal(container.args, undefined);
  assert(container.image.endsWith('@' + RECEIVER_DIGEST));
  assert.deepEqual(container.resources, { cpu: 0.25, memory: '0.5Gi' });
  assert.equal(app.template.scale.minReplicas, 1); assert.equal(app.template.scale.maxReplicas, 1);
  assert.equal(app.configuration.ingress.allowInsecure, false);
  assert.equal(app.configuration.activeRevisionsMode, 'Single');
  assert.equal(container.env.find(v => v.name === 'MSR_INGESTION_ENABLED').value, 'false');
  assert.equal(container.env.find(v => v.name === 'MSR_EVENTS_PER_DAY').value, '100000');
  assert.equal(Object.keys(body.identity.userAssignedIdentities).length, 2);
  assert.equal(app.configuration.identitySettings.find(v => v.identity === r.pullIdentity).lifecycle, 'None');
  const bad = fixtureReceipts(); bad.publication.recentDigestCount = 2;
  assert.throws(() => buildPhase(c, 'disabled-app', contract, bad), /NOT_QUALIFIED/);
  assert.throws(() => permitFirstPush(c, ['old'], [{ digest: RECEIVER_DIGEST }]));
  assert.equal(permitFirstPush(c, [], []).maximumNewImages, 1);
});
test('runtime readback rejects command, identity, secret, ingress, scaler and quota drift', () => {
  const p = buildPhase(c, 'disabled-app', contract, fixtureReceipts()), d = p.resources[0];
  const actual = { ...structuredClone(d.expected), id: d.id };
  actual.properties.configuration.ingress.fqdn = 'missionspec-test.australiaeast.azurecontainerapps.io';
  verifyResource(c, p, d, actual);
  for (const mutate of [
    value => { value.properties.template.containers[0].command = ['sh']; },
    value => { value.properties.template.containers[0].env.push({ name: 'NODE_OPTIONS', value: '--inspect' }); },
    value => { value.properties.configuration.identitySettings[1].lifecycle = 'All'; },
    value => { value.properties.configuration.ingress.allowInsecure = true; },
    value => { value.properties.template.scale.rules[0].http.metadata.concurrentRequests = '100'; },
    value => { value.properties.configuration.secrets = [{ name: 'unexpected' }]; },
    value => { value.properties.template.containers[0].env.find(v => v.name === 'MSR_EVENTS_PER_DAY').value = '1000000'; },
  ]) {
    const bad = structuredClone(actual); mutate(bad);
    assert.throws(() => verifyResource(c, p, d, bad));
  }
});
test('what-if allows exact creates or narrow approved flags, never unknown modification or deletion', () => {
  const p = buildPhase(c, 'core', contract);
  const changes = p.resources.map(v => ({ resourceId: v.id, changeType: 'Create' }));
  verifyWhatIf(p, { status: 'Succeeded', changes });
  for (const changeType of ['Modify', 'Delete', 'NoChange', 'Ignore']) {
    assert.throws(() => verifyWhatIf(p, { status: 'Succeeded', changes: [{ ...changes[0], changeType }, ...changes.slice(1)] }));
  }
  const update = buildPhase(c, 'workspace-access', contract, fixtureReceipts());
  const before = { properties: { features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: true }, retentionInDays: 180 } };
  const after = structuredClone(before); after.properties.features.enableLogAccessUsingOnlyResourcePermissions = false;
  verifyWhatIf(update, { status: 'Succeeded', changes: [{ resourceId: r.workspace, changeType: 'Modify', before, after }] });
  after.properties.retentionInDays = 30;
  assert.throws(() => verifyWhatIf(update, { status: 'Succeeded', changes: [{ resourceId: r.workspace, changeType: 'Modify', before, after }] }), /UNREVIEWED_MODIFY/);
});
test('synthetic admission cannot hide command, image or quota changes inside a container-array modification', () => {
  const receipts = fixtureReceipts(), p = buildPhase(c, 'synthetic-admission', contract, receipts);
  const before = { properties: buildPhase(c, 'disabled-app', contract, receipts).resources[0].expected.properties };
  const after = { properties: p.resources[0].expected.properties };
  verifyWhatIf(p, { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'Modify', before, after }] });
  after.properties.template.containers[0].command = ['other'];
  assert.throws(() => verifyWhatIf(p, { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'Modify', before, after }] }));
});
test('budget key folding never relaxes values, arrays, types, recipients or count', () => {
  const b = structuredClone(buildPhase(c, 'core', contract).resources.find(v => v.id === r.budget).expected);
  b.properties.filter = {};
  assertBudget(b, c, 300);
  b.properties.notifications.Actual80 = b.properties.notifications.actual80;
  assert.throws(() => assertBudget(b, c, 300));
  delete b.properties.notifications.Actual80;
  b.properties.notifications.actual80.enabled = 'true';
  assert.throws(() => assertBudget(b, c, 300));
});
test('budget configuration is closed and the exact project-only amount update precedes collector creation', () => {
  const p = buildPhase(c, 'project-budget', contract, {}, foundation);
  assert.equal(PHASES[0], 'project-budget');
  assert.deepEqual(p.requiredReceipts, []);
  assert.equal(p.resources.length, 1); assert.equal(p.resources[0].id, r.projectBudget);
  assert.equal(p.scope, r.sub);
  assert.deepEqual(p.allowedModify, { [r.projectBudget]: ['properties.amount'] });
  const expected = budgetConfiguration(foundation.project); expected.amount = 350;
  assert.deepEqual(budgetConfiguration(p.resources[0].expected), expected);
  const core = buildPhase(c, 'core', contract);
  assert.deepEqual(core.requiredReceipts, ['project-budget']);
  assert(!core.resources.some(v => v.id === r.projectBudget || v.id === r.stateBudget));
  assert.equal(core.resources.find(v => v.id === r.budget).expected.properties.amount, 300);
  assert.equal(c.budget.stateAmount + c.budget.telemetryAmount, c.budget.projectAmount);
  for (const mutate of [
    value => { value.budget.projectAmount = 400; }, value => { value.budget.stateAmount = 0; },
    value => { value.budget.telemetryAmount = 350; }, value => { value.budget.previousProjectAmount = 200; },
    value => { value.budget.currency = 'AUD'; }, value => { value.budget.extra = true; },
    value => { delete value.budget; }, value => { value.version = 1; },
  ]) {
    const bad = structuredClone(c); mutate(bad); assert.throws(() => validateConfig(bad));
  }
  assert.throws(() => buildPhase(c, 'project-budget', contract), /CLOSED_INPUT_REQUIRED/);
  const changed = structuredClone(foundation); changed.project.properties.amount = 300;
  assert.throws(() => buildPhase(c, 'project-budget', contract, {}, changed), /FOUNDATION_BUDGET_RECEIPT_REQUIRED/);
});
test('full budget what-if and readback accept only the exact 250-to-350 amount change', () => {
  const p = buildPhase(c, 'project-budget', contract, {}, foundation), d = p.resources[0];
  const before = structuredClone(foundation.project), after = { id: d.id, ...structuredClone(d.expected) };
  const result = { status: 'Succeeded', changes: [{ resourceId: d.id, changeType: 'Modify', before, after }] };
  verifyWhatIf(p, result);
  verifyResource(c, p, d, after);
  const serviceWhatIf = structuredClone(result);
  for (const side of ['before', 'after']) for (const notification of Object.values(serviceWhatIf.changes[0][side].properties.notifications)) {
    delete notification.contactGroups; delete notification.contactRoles;
  }
  verifyWhatIf(p, serviceWhatIf);
  assert.throws(() => verifyResource(c, p, d, serviceWhatIf.changes[0].after));
  for (const key of ['contactEmails', 'contactGroups', 'contactRoles']) for (const value of [null, '', ['unexpected@example.invalid']]) {
    const bad = structuredClone(serviceWhatIf); bad.changes[0].after.properties.notifications.actual80[key] = value;
    assert.throws(() => verifyWhatIf(p, bad));
  }
  for (const mutate of [
    v => { v.properties.amount = 351; }, v => { v.properties.amount = 250; },
    v => { v.properties.timePeriod.endDate = '2030-09-01T00:00:00Z'; },
    v => { v.properties.timeGrain = 'Annually'; }, v => { v.properties.category = 'Usage'; },
    v => { v.properties.filter.dimensions.values.push('unowned'); },
    v => { v.properties.notifications.actual80.contactEmails = ['someone@example.invalid']; },
    v => { v.properties.notifications.actual80.threshold = 90; },
    v => { v.properties.notifications.actual80.enabled = false; },
    v => { v.properties.notifications.actual80.contactGroups = ['unexpected']; },
    v => { v.properties.notifications.actual80.contactRoles = ['Owner']; },
    v => { v.properties.notifications.extra = v.properties.notifications.actual80; },
    v => { v.properties.extra = true; },
  ]) {
    const bad = structuredClone(after); mutate(bad);
    assert.throws(() => verifyResource(c, p, d, bad));
    assert.throws(() => verifyWhatIf(p, { ...result, changes: [{ ...result.changes[0], after: bad }] }));
    const hidden = structuredClone(before); mutate(hidden);
    if (JSON.stringify(hidden) !== JSON.stringify(before)) {
      assert.throws(() => verifyWhatIf(p, { ...result, changes: [{ ...result.changes[0], before: hidden }] }));
    }
  }
  for (const changeType of ['Create', 'NoChange', 'Delete', 'Ignore']) {
    assert.throws(() => verifyWhatIf(p, { ...result, changes: [{ ...result.changes[0], changeType }] }));
  }
  assert.throws(() => verifyWhatIf(p, { ...result, changes: [...result.changes, { resourceId: r.stateBudget, changeType: 'Modify' }] }));
  const spend = structuredClone(after); spend.eTag = 'new'; spend.properties.currentSpend = { amount: 12, unit: 'USD' };
  spend.properties.forecastSpend = { amount: 30, unit: 'USD' };
  verifyResource(c, p, d, spend);
});
test('later phases require a matching qualified budget deployment receipt, never a preview or a fabricated 350 snapshot', () => {
  const receipt = fixtureReceipts()['project-budget'];
  verifyProjectBudgetReceipt(c, receipt, foundation, digest('source'));
  for (const mutate of [
    v => { v.qualified = false; }, v => { v.phase = 'core'; }, v => { v.configSha256 = digest('old'); },
    v => { v.sourceSha256 = digest('old'); }, v => { v.phaseSha256 = digest('old'); },
    v => { delete v.deployment; }, v => { v.deployment.properties.provisioningState = 'Running'; },
    v => { v.deployment.id = r.projectBudget; }, v => { v.resources[r.projectBudget].properties.amount = 250; },
    v => { v.resources[r.stateBudget] = foundation.state; },
  ]) {
    const bad = structuredClone(receipt); mutate(bad);
    assert.throws(() => verifyProjectBudgetReceipt(c, bad, foundation, digest('source')));
  }
  assert.throws(() => verifyProjectBudgetReceipt(c, undefined, foundation, digest('source')));
});
function fixtureAdoption() {
  const config = structuredClone(c), storageId = `${r.stateGroup}/providers/Microsoft.Storage/storageAccounts/fixturestate`;
  const snapshot = { id: storageId, properties: { publicNetworkAccess: 'Disabled', allowSharedKeyAccess: false,
    networkAcls: { bypass: 'None', defaultAction: 'Deny', ipRules: [], ipv6Rules: [], virtualNetworkRules: [], resourceAccessRules: [] } } };
  const ledger = { sessions: [] };
  const origin = { version: 1, adoptionDecision: { accepted: true, opaqueTagIsUTC: false }, latestLedger: ledger, latestLedgerSha256: digest(json(ledger)),
    resources: [{ id: storageId, apiVersion: '2023-05-01', snapshot }], absent: [],
    bootstrap: { id: `${r.stateGroup}/providers/Microsoft.Resources/deployments/foundation`, correlationId: 'original', timestamp: 'original', templateHash: 'original' } };
  config.originSha256 = digest(json(origin));
  const principal = '00000000-0000-4000-8000-000000000011', app = '00000000-0000-4000-8000-000000000012';
  const actorId = `${r.sub}/providers/Microsoft.Security/pricings/StorageAccounts/securityOperators/DefenderForStorageSecurityOperator`;
  const roleId = `${r.sub}/providers/Microsoft.Authorization/roleDefinitions/0f641de8-0b88-4198-bdef-bd8b45ceba96`;
  const after = structuredClone(snapshot);
  after.properties.networkAcls.resourceAccessRules = [{ tenantId: c.tenantId, resourceId: `${r.sub}/providers/Microsoft.Security/datascanners/StorageDataScanner` }];
  const adoption = { version: 1, kind: 'exact-storage-scanner-instance', originSha256: config.originSha256, resourceId: storageId,
    apiVersion: '2023-05-01', beforeSha256: digest(json(snapshot)), after,
    decision: { action: 'preserve-exact-storage-scanner-instance', recordedAt: '2026-09-23T00:00:00.000Z', userInstructionSha256: digest('explicit user decision') },
    evidence: { activitySha256: digest('activity'), correlationId: 'correlation',
      events: [{ correlationId: 'correlation', resourceId: storageId, operation: 'Microsoft.Storage/storageAccounts/write', status: 'Succeeded',
        caller: principal, appId: app, actorResourceId: actorId }],
      actorResource: { id: actorId, identity: { principalId: principal, tenantId: c.tenantId } },
      roleDefinition: { id: roleId, properties: { roleName: 'Defender for Storage Scanner Operator',
        permissions: [{ actions: ['Microsoft.Storage/storageAccounts/write', 'Microsoft.Security/defenderForStorageSettings/write'] }] } },
      roleAssignment: { properties: { principalId: principal, roleDefinitionId: roleId, scope: r.sub, condition: null } },
      servicePrincipal: { id: principal, appId: app, servicePrincipalType: 'ManagedIdentity',
        displayName: 'StorageAccounts/securityOperators/DefenderForStorageSecurityOperator' } } };
  config.scannerAdoptionSha256 = digest(json(adoption));
  const foundationBudgets = fixtureFoundation(config);
  return { config, origin, adoption, foundationBudgets };
}
test('scanner adoption is hash-bound to the original origin and only the exact single private instance exception', async () => {
  const { config, origin, adoption } = fixtureAdoption();
  assert.deepEqual(verifyScannerAdoption(config, origin, adoption).snapshot, adoption.after);
  const read = async (_method, id) => id === adoption.resourceId ? adoption.after
    : { id, properties: { ...origin.bootstrap, provisioningState: 'Succeeded' } };
  await verifyOrigin(origin, read, config, adoption);
  for (const mutate of [
    v => { v.properties.networkAcls.bypass = 'AzureServices'; }, v => { v.properties.publicNetworkAccess = 'Enabled'; },
    v => { v.properties.allowSharedKeyAccess = true; }, v => { v.properties.networkAcls.defaultAction = 'Allow'; },
    v => { v.properties.networkAcls.resourceAccessRules.push({ tenantId: c.tenantId, resourceId: r.registry }); },
    v => { v.properties.networkAcls.resourceAccessRules[0].tenantId = c.operatorPrincipalId; },
    v => { v.properties.networkAcls.ipRules = [{ value: '192.0.2.1' }]; },
    v => { v.properties.networkAcls.virtualNetworkRules = [{ id: 'other' }]; },
    v => { v.properties.extra = true; },
  ]) {
    const bad = structuredClone(adoption.after); mutate(bad);
    await assert.rejects(verifyOrigin(origin, async (...args) => args[1] === adoption.resourceId ? bad : read(...args), config, adoption), /FOUNDATION_DRIFT/);
    const altered = { ...adoption, after: bad }, rehashed = { ...config, scannerAdoptionSha256: digest(json(altered)) };
    assert.throws(() => verifyScannerAdoption(rehashed, origin, altered), /SCANNER_ADOPTION_INVALID/);
  }
  const wrongActor = structuredClone(adoption); wrongActor.evidence.servicePrincipal.id = c.operatorPrincipalId;
  assert.throws(() => verifyScannerAdoption({ ...config, scannerAdoptionSha256: digest(json(wrongActor)) }, origin, wrongActor), /ATTRIBUTION/);
  const changedOrigin = structuredClone(origin); changedOrigin.adoptionDecision.opaqueTagIsUTC = true;
  assert.throws(() => verifyScannerAdoption(config, changedOrigin, adoption), /SCANNER_ADOPTION_INVALID/);
});
test('full core preflight cannot proceed on a budget preview and immutable evidence cannot be overwritten', async t => {
  const { config, origin, adoption, foundationBudgets } = fixtureAdoption(), directory = await scratch(t);
  const phase = buildPhase(config, 'core', contract);
  let calls = 0;
  const invoke = async args => {
    calls++;
    if (args[0] === 'account') return { id: config.subscriptionId, tenantId: config.tenantId, state: 'Enabled', environmentName: 'AzureCloud' };
    assert.equal(args[args.indexOf('--method') + 1], 'GET');
    const url = args[args.indexOf('--url') + 1];
    if (url.includes(adoption.resourceId)) return adoption.after;
    if (url.includes(origin.bootstrap.id)) return { id: origin.bootstrap.id, properties: { ...origin.bootstrap, provisioningState: 'Succeeded' } };
    throw new Error('UNEXPECTED_READ');
  };
  await assert.rejects(checkReadOnly(config, phase, origin, {}, directory, { scannerAdoption: adoption, foundationBudgets }, invoke), /PROJECT_BUDGET_RECEIPT_REQUIRED/);
  assert.equal(calls, 3);
  await saveImmutable(directory, 'origin.json', origin);
  await assert.rejects(saveImmutable(directory, 'origin.json', { replaced: true }), { code: 'EEXIST' });
  assert.deepEqual(JSON.parse(await readFile(`${directory}/origin.json`)), origin);
});
test('transport absence handling does not convert auth/quota/general strings into missing resources', async () => {
  const error = stderr => async () => { throw Object.assign(new Error('failure'), { stderr }); };
  const args = ['rest', '--method', 'GET'];
  assert.equal(await az(args, 10, error('ERROR: Not Found({"error":{"code":"ResourceNotFound"}})')), null);
  for (const text of ['ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})', 'ERROR: Not Found({"error":{"code":"NotFound"}})', 'ERROR: ResourceNotFound']) {
    await assert.rejects(az(args, 10, error(text)), /ARM_OPERATION_FAILED/);
  }
  const budgetArgs = [...args, '--url', `https://management.azure.com${r.budget}?api-version=2024-08-01`];
  assert.equal(await az(budgetArgs, 10, error('ERROR: Not Found({"error":{"code":"404"}})')), null);
  for (const text of ['ERROR: Forbidden({"error":{"code":"404"}})', 'ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})',
    'ERROR: {"error":{"code":"404"}}', 'ERROR: Not Found({"error":{"code":"NotFound"}})']) {
    await assert.rejects(az(budgetArgs, 10, error(text)), /ARM_OPERATION_FAILED/);
  }
  await assert.rejects(az([...args, '--url', `https://management.azure.com${r.registry}?api-version=2024-08-01`],
    10, error('ERROR: Not Found({"error":{"code":"404"}})')), /ARM_OPERATION_FAILED/);
  await assert.rejects(az(['rest', '--method', 'PUT', ...budgetArgs.slice(3)], 10, error('ERROR: Not Found({"error":{"code":"404"}})')), /ARM_OPERATION_FAILED/);
  const p = buildPhase(c, 'core', contract), arm = transport(c, p, 'unused', async () => ({}));
  await assert.rejects(arm('PUT', r.workspace, '2023-09-01'), /FIXED_PHASE/);
  await assert.rejects(arm('POST', r.registry + '/listCredentials', '2023-07-01'), /NONMUTATING/);
  await assert.rejects(arm('DELETE', r.group, '2024-03-01'), /FORBIDDEN/);
});
test('uncertain submission is never replayed or followed by destructive rollback', async () => {
  const f = executionFixture(), controller = new CollectorController(c, f.p, f.io);
  await assert.rejects(controller.execute(f.approval), /OWNED_RESOURCES_PRESERVED/);
  assert.equal(f.journal.outcome, 'reconciliation-required'); assert.equal(f.writes, 1);
  await assert.rejects(controller.execute(f.approval), /RECONCILIATION/);
  assert.equal(f.writes, 1);
});
test('successful access phase writes only its fixed deployment and persists qualified readback', async () => {
  const f = executionFixture('workspace-access'), { p } = f;
  let created = false, privacyChecked = false;
  const changes = [];
  const actual = { id: r.workspace, tags: ownerTags(c), properties: {
    ...p.resources[0].expected.properties, customerId: '00000000-0000-4000-8000-000000000009', provisioningState: 'Succeeded',
  } };
  f.io.privacyChecks = async () => { privacyChecked = true; };
  f.io.arm = async (method, id, _api, _body, _filter, beforeDispatch) => {
      if (method === 'PUT') {
        beforeDispatch();
        assert.equal(f.journal.outcome, 'submission-possible');
        assert.equal(id, p.deploymentId); created = true; changes.push(id); return {};
      }
      if (id === p.deploymentId) return created ? { id, properties: { provisioningState: 'Succeeded' } } : null;
      if (id === r.workspace) return actual;
      throw new Error('UNEXPECTED_ARM_READ');
    };
  await new CollectorController(c, p, f.io).execute(f.approval);
  assert.equal(privacyChecked, true); assert.equal(f.receipt.qualified, true);
  assert.equal(f.journal.outcome, 'readback-qualified'); assert.equal(changes.length, 1);
});
test('successful project-budget execution qualifies only the amount-update deployment and its exact readback', async () => {
  const f = executionFixture('project-budget');
  let submitted = false, writes = 0;
  f.io.arm = async (method, id, _api, body, _filter, guard) => {
    if (method === 'PUT') {
      guard();
      assert.equal(f.journal.outcome, 'submission-possible');
      assert.equal(id, f.p.deploymentId);
      assert.equal(body.location, c.location);
      assert.equal(body.properties.mode, 'Incremental');
      assert.deepEqual(body.properties.template, f.p.template);
      writes++; submitted = true; return {};
    }
    if (id === f.p.deploymentId) return submitted ? { id, properties: { provisioningState: 'Succeeded' } } : null;
    assert.equal(id, r.projectBudget);
    return { ...structuredClone(foundation.project), properties: { ...foundation.project.properties, amount: 350 } };
  };
  await new CollectorController(c, f.p, f.io).execute(f.approval);
  assert.equal(writes, 1);
  assert.equal(f.journal.outcome, 'readback-qualified');
  verifyProjectBudgetReceipt(c, f.receipt, foundation, digest('source'));
});
test('approval is closed, hash-bound and requires finite canonical UTC dates and a bounded interval', async t => {
  const mutations = [
    ['missing approval', () => undefined], ['null approval', () => null], ['array approval', () => []],
    ['extra field', a => ({ ...a, authorized: true })], ['wrong action', a => ({ ...a, action: 'direct-arm-data' })],
    ...['approvedAt', 'expiresAt'].flatMap(key => [
      [`missing ${key}`, a => { delete a[key]; return a; }],
      [`object ${key}`, a => ({ ...a, [key]: { toString: null } })],
      [`array ${key}`, a => ({ ...a, [key]: [] })],
      ...['NaN', 'not-a-date', '2026-02-30T00:00:00.000Z', '2026-09-23T00:00:00Z', '2026-09-23T00:00:00.000+00:00', null, 0]
        .map(value => [`invalid ${key} ${String(value)}`, a => ({ ...a, [key]: value })]),
    ]),
    ['expired', a => ({ ...a, expiresAt: '2026-09-23T00:00:00.000Z' })],
    ['future', a => ({ ...a, approvedAt: '2026-09-23T00:01:00.000Z' })],
    ['inverted', a => ({ ...a, expiresAt: '2026-09-22T23:58:00.000Z' })],
    ['empty interval', a => ({ ...a, expiresAt: a.approvedAt })],
    ['unbounded interval', a => ({ ...a, expiresAt: '2099-09-23T00:00:00.000Z' })],
    ...['phase', 'config', 'source', 'whatIf', 'origin', 'receipts', 'baseline'].flatMap(key => [
      [`wrong ${key} binding`, a => ({ ...a, [`${key}Sha256`]: digest('wrong') })],
      [`invalid ${key} hash`, a => ({ ...a, [`${key}Sha256`]: 'not-a-hash' })],
      [`missing ${key} hash`, a => { delete a[`${key}Sha256`]; return a; }],
    ]),
  ];
  for (const [name, mutate] of mutations) await t.test(name, async () => {
    const f = executionFixture();
    await assert.rejects(new CollectorController(c, f.p, f.io).execute(mutate({ ...f.approval })),
      /^(?:Error: )?(?:EXACT_PHASE_RELEASE_REQUIRED|FRESH_REVIEW_MISMATCH)$/u);
    assert.equal(f.writes, 0); assert.equal(f.journal, null); assert.equal(f.receipt, null);
  });
});
test('fresh preflight rejects stale, malformed or mismatched receipts and estimates exceeding the explicit 350 decision', async t => {
  const mutations = [
    ['missing proof', () => undefined], ['truthy qualified', p => ({ ...p, qualified: 'true' })],
    ['truthy budget', p => ({ ...p, cost: { withinEstimate: 'true', estimateLimit: 350, total: 200 } })],
    ...[undefined, NaN, Infinity, -1, '200', 350.01].map(total =>
      [`invalid cost ${String(total)}`, p => ({ ...p, cost: { withinEstimate: true, estimateLimit: 350, total } })]),
    ['old budget decision', p => ({ ...p, cost: { ...firstReleaseCost(1), estimateLimit: 250 } })],
    ...['phase', 'config', 'source', 'whatIf', 'origin', 'receipts', 'baseline'].map(key =>
      [`wrong ${key} binding`, p => ({ ...p, [`${key}Sha256`]: digest('wrong') })]),
    ...['startedAt', 'completedAt'].flatMap(key => [NaN, Infinity, undefined, '2026-09-23T00:00:00.000Z']
      .map(value => [`invalid ${key} ${String(value)}`, p => ({ ...p, [key]: value })])),
    ['stale', p => ({ ...p, startedAt: p.startedAt - 300001 })],
    ['reused proof', p => ({ ...p, startedAt: p.startedAt - 1 })],
    ['future start', p => ({ ...p, startedAt: p.startedAt + 1 })],
    ['future completion', p => ({ ...p, completedAt: p.completedAt + 1 })],
    ['inverted timing', p => ({ ...p, completedAt: p.startedAt - 1 })],
  ];
  for (const [name, mutate] of mutations) await t.test(name, async () => {
    const f = executionFixture(); f.io.check = async () => mutate(f.proof);
    await assert.rejects(new CollectorController(c, f.p, f.io).execute(f.approval), /FRESH_REVIEW_MISMATCH/);
    assert.equal(f.writes, 0); assert.equal(f.journal, null);
  });
});
test('expiry and preflight freshness are rechecked after final GET, intent save and transport body preparation', async t => {
  const directory = await scratch(t);
  for (const gate of ['expiry', 'preflight']) for (const boundary of ['GET', 'intent-save', 'body-preparation']) {
    await t.test(`${gate} at ${boundary}`, async () => {
      const f = executionFixture(), originalArm = f.io.arm, originalSave = f.io.saveJournal;
      if (gate === 'expiry') f.approval.expiresAt = new Date(f.io.now() + 60000).toISOString();
      const delay = gate === 'expiry' ? 60000 : 300001;
      let dispatched = 0;
      const arm = transport(c, f.p, directory, async () => { dispatched++; throw new Error('UNEXPECTED_DISPATCH'); });
      if (boundary === 'GET') f.io.arm = async (...args) => {
        const result = await originalArm(...args); if (args[0] === 'GET') f.advance(delay); return result;
      };
      if (boundary === 'intent-save') f.io.saveJournal = async value => {
        await originalSave(value); if (value.outcome === 'submission-possible') f.advance(delay);
      };
      if (boundary === 'body-preparation') f.io.arm = (method, id, api, body, filter, guard) =>
        method === 'PUT'
          ? arm(method, id, api, { toJSON() { f.advance(delay); return body; } }, filter, guard)
          : originalArm(method, id, api, body, filter, guard);
      const controller = new CollectorController(c, f.p, f.io);
      await assert.rejects(controller.execute(f.approval), boundary === 'GET' ? /FRESH_REVIEW_MISMATCH/ : /OWNED_RESOURCES_PRESERVED/);
      assert.equal(f.writes, 0); assert.equal(dispatched, 0); assert.equal(f.receipt, null);
      if (boundary === 'GET') assert.equal(f.journal, null);
      else {
        assert.equal(f.journal.outcome, 'reconciliation-required');
        assert.equal(f.journal.failureCode, 'FRESH_REVIEW_MISMATCH');
        // Even when submission was prevented locally, a persisted intent is not reset or replayable.
        f.io.now = () => Date.parse('2026-09-23T00:00:00.000Z');
        await assert.rejects(controller.execute(f.approval), /RECONCILIATION/);
        assert.equal(f.writes, 0); assert.equal(dispatched, 0);
      }
      assert.deepEqual(await readdir(directory), []);
    });
  }
});
test('fixed PUT transport requires a synchronous dispatch guard and cleans prepared bodies on rejection', async t => {
  const directory = await scratch(t), p = buildPhase(c, 'core', contract);
  let calls = 0;
  const arm = transport(c, p, directory, async () => { calls++; return {}; });
  await assert.rejects(arm('PUT', p.deploymentId, '2022-09-01', {}), /DISPATCH_GUARD_REQUIRED/);
  await assert.rejects(arm('PUT', p.deploymentId, '2022-09-01', {}, undefined, async () => {}), /DISPATCH_GUARD_REQUIRED/);
  assert.equal(calls, 0); assert.deepEqual(await readdir(directory), []);
  let prepared = false, guarded = false;
  const body = { properties: { mode: 'Incremental', template: p.template } };
  const guardedArm = transport(c, p, directory, async args => {
    assert.equal(guarded, true);
    assert.equal(args[args.indexOf('--method') + 1], 'PUT');
    assert.equal(args[args.indexOf('--url') + 1], `https://management.azure.com${p.deploymentId}?api-version=2022-09-01`);
    assert.equal(args[args.indexOf('--subscription') + 1], c.subscriptionId);
    assert.deepEqual(JSON.parse(await readFile(args[args.indexOf('--body') + 1].slice(1))), body);
    calls++; return {};
  });
  await guardedArm('PUT', p.deploymentId, '2022-09-01', { toJSON() { prepared = true; return body; } }, undefined, () => {
    assert.equal(prepared, true); assert.equal(calls, 0); guarded = true;
  });
  assert.equal(calls, 1); assert.deepEqual(await readdir(directory), []);
});
test('one-image conservative release cost includes full ambiguous environment/network/security reserves', () => {
  const cost = firstReleaseCost(1);
  assert(cost.items.ambiguousEnvironmentManagement > 100);
  assert(cost.items.possibleManagedLoadBalancer > 0 && cost.items.possibleTwoManagedPublicIPs > 0);
  assert(cost.items.oneImageInitialPlusDailyAndPullReserve > 9);
  assert.equal(cost.freeGrantsAssumed, false);
  assert.equal(cost.operatorInfrastructureAdded, false);
  assert.throws(() => firstReleaseCost(2), /NEW_DIGEST_COST_REVIEW/);
});
test('default HTTP request cost is independent of the accepted-event quota and is not a billing hard cap', () => {
  const cost = firstReleaseCost(1);
  const app = buildPhase(c, 'disabled-app', contract, fixtureReceipts()).resources[0].expected.properties;
  const env = Object.fromEntries(app.template.containers[0].env.map(v => [v.name, v.value]));
  assert.equal(Number(env.MSR_REQUESTS_PER_MINUTE), LIMITS.requests_per_minute);
  assert.equal(Number(env.MSR_EVENTS_PER_DAY), LIMITS.events_per_day);
  assert.equal(cost.httpRequests.sustainedPerMinute, 3000);
  assert.equal(cost.httpRequests.monthlyVolume, 133920000);
  assert.equal(cost.httpRequests.monthlyVolume, 31 * 24 * 60 * Number(env.MSR_REQUESTS_PER_MINUTE));
  assert.notEqual(cost.httpRequests.monthlyVolume, 31 * Number(env.MSR_EVENTS_PER_DAY));
  assert.equal(cost.httpRequests.includesRejectedRequests, true);
  assert.equal(cost.httpRequests.beyondRateLimitCanBeBilled, true);
  assert.equal(cost.items.requests, 53.568);
  assert.equal(cost.total, 301.66);
  assert.equal(cost.estimateLimit, 350);
  assert.equal(cost.withinEstimate, true);
  assert.equal(cost.isHardCap, false);
  assert.equal(Math.round(Object.entries(cost.items).filter(([key]) => key !== 'requests')
    .reduce((sum, [, value]) => sum + value, 0) * 10000), 2480884);
});
