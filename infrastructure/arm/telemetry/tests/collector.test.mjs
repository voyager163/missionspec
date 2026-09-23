import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, link, mkdir, open, readFile, readdir, rename, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { buildPhase, storageContract, ids, json, digest, ownerTags, firstReleaseCost, PHASES, LIMITS, RECEIVER_DIGEST, RECEIVER_COMMAND,
  BUDGET, budgetProperties, budgetConfiguration, projectBudgetFilter, validateConfig, assignmentRoleTargets } from '../definition.mjs';
import { verifyWhatIf, assertBudget, permitFirstPush, verifyResource, executionIdentity,
  verifyExecutionOrigins, verifyReconciliation, verifyDeploymentIdentity, roleDefinitionSignature, verifyImagePublication, verifyPublicationReadback } from '../policy.mjs';
import { manifestJson, configJson } from './receiver-oci.fixture.mjs';
import { CollectorController, az, transport, validateReadOnly, verifyScannerAdoption, verifyOrigin, verifyProjectBudgetReceipt,
  checkReadOnly, load, saveImmutable, MAX_PRIVATE_ARTIFACT_BYTES, DIAGNOSTIC_API, privateDirectory, sourceDigest,
  publishedSourceDigest, collectReconciliation, reviewedReconciliationReceipts, verifyFreshReconciliation, readPrivacy, readAssignmentRoleDefinitions } from '../controller.mjs';

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
    [r.ingestIdentity]: owned(r.ingestIdentity, { clientId: '00000000-0000-4000-8000-000000000005', principalId: '00000000-0000-4000-8000-000000000006', tenantId: c.tenantId }),
    [r.pullIdentity]: owned(r.pullIdentity, { clientId: '00000000-0000-4000-8000-000000000007', principalId: '00000000-0000-4000-8000-000000000008', tenantId: c.tenantId }),
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
async function interleavePrivateStat(t, path, action) {
  const probe = await open(path, 'r'), prototype = Object.getPrototypeOf(probe), initial = await probe.stat({ bigint: true });
  await probe.close();
  const original = prototype.stat;
  let held;
  t.mock.method(prototype, 'stat', async function (...args) {
    const info = await original.apply(this, args);
    if (!held && info.ino === initial.ino && info.dev === initial.dev) { held = this; await action(info, this); }
    return info;
  });
  return () => held;
}
test('private JSON loads use a single no-follow held inode with exact permissions, bounded reads and closed errors', async t => {
  const directory = await scratch(t);
  await saveImmutable(directory, 'valid.json', { valid: true });
  assert.deepEqual(await load(directory, 'valid.json'), { valid: true });
  assert.equal(await load(directory, 'missing.json', true), null);
  await assert.rejects(load(directory, 'missing.json'), /PRIVATE_FILE_OPEN_FAILED/);
  await writeFile(`${directory}/invalid.json`, '{"private":"must-not-appear",BAD}', { mode: 0o600 });
  await assert.rejects(load(directory, 'invalid.json', true), { message: 'PRIVATE_JSON_INVALID' });
  for (const mode of [0o400, 0o640, 0o644, 0o700, 0o1600]) await t.test(`rejects mode ${mode.toString(8)}`, async () => {
    await chmod(`${directory}/valid.json`, mode);
    await assert.rejects(load(directory, 'valid.json', true), /PRIVATE_FILE_REQUIRED/);
    await chmod(`${directory}/valid.json`, 0o600);
  });
  await symlink('valid.json', `${directory}/symlink.json`);
  await symlink('missing.json', `${directory}/dangling.json`);
  for (const name of ['symlink.json', 'dangling.json']) await assert.rejects(load(directory, name, true), /PRIVATE_FILE_OPEN_FAILED/);
  await link(`${directory}/valid.json`, `${directory}/hardlink.json`);
  for (const name of ['valid.json', 'hardlink.json']) await assert.rejects(load(directory, name), /PRIVATE_FILE_REQUIRED/);
  await rm(`${directory}/hardlink.json`);
  await mkdir(`${directory}/directory.json`, { mode: 0o700 });
  await assert.rejects(load(directory, 'directory.json'), /PRIVATE_FILE_REQUIRED/);
  await promisify(execFile)('mkfifo', [`${directory}/fifo.json`]);
  await assert.rejects(load(directory, 'fifo.json'), /PRIVATE_FILE_REQUIRED/);
});
test('real replacement, link, permission and content races never return unchecked replacement bytes', async t => {
  for (const operation of ['replace', 'symlink', 'hardlink', 'chmod', 'rewrite', 'foreign-owner-stat', 'read-failure', 'parse-failure', 'success']) {
    await t.test(operation, async t => {
      const directory = await scratch(t), path = `${directory}/input.json`;
      await saveImmutable(directory, 'input.json', { original: true });
      await saveImmutable(directory, 'replacement.json', { unchecked: true });
      const held = await interleavePrivateStat(t, path, async (info, handle) => {
        if (operation === 'replace') { await rename(path, `${directory}/old.json`); await rename(`${directory}/replacement.json`, path); }
        if (operation === 'symlink') { await rm(path); await symlink('replacement.json', path); }
        if (operation === 'hardlink') await link(path, `${directory}/extra.json`);
        if (operation === 'chmod') await chmod(path, 0o644);
        if (operation === 'rewrite') await writeFile(path, '{"unchecked":true}');
        // Keep real OS identity APIs untouched; unit-test the owner mismatch returned by fstat.
        if (operation === 'foreign-owner-stat') info.uid += 1n;
        if (operation === 'read-failure') t.mock.method(handle, 'read', async () => { throw Object.assign(new Error('private-path'), { code: 'ENOENT' }); });
        if (operation === 'parse-failure') await writeFile(path, 'invalid-json');
      });
      if (operation === 'replace') {
        try { assert.deepEqual(await load(directory, 'input.json'), { original: true }); }
        catch (error) { assert.match(error.message, /^PRIVATE_FILE_CHANGED$/u); }
      } else if (operation === 'success') assert.deepEqual(await load(directory, 'input.json'), { original: true });
      else await assert.rejects(load(directory, 'input.json', true), /^Error: PRIVATE_(FILE_REQUIRED|FILE_CHANGED|FILE_READ_FAILED)$/u);
      assert.equal(held().fd, -1);
    });
  }
});
test('private artifact limits cover exact boundary, oversize and growth during the held-handle read', async t => {
  const directory = await scratch(t), path = `${directory}/bounded.json`;
  const data = Buffer.alloc(MAX_PRIVATE_ARTIFACT_BYTES, 32); data.write('{}');
  await writeFile(path, data, { mode: 0o600 });
  assert.deepEqual(await load(directory, 'bounded.json'), {});
  await truncate(path, MAX_PRIVATE_ARTIFACT_BYTES + 1);
  await assert.rejects(load(directory, 'bounded.json'), /PRIVATE_FILE_TOO_LARGE/);
  await writeFile(path, '{}');
  const held = await interleavePrivateStat(t, path, () => truncate(path, MAX_PRIVATE_ARTIFACT_BYTES + 1));
  await assert.rejects(load(directory, 'bounded.json'), /PRIVATE_FILE_TOO_LARGE/);
  assert.equal(held().fd, -1);
});
test('private parse and close failures close the held object and do not expose private values', async t => {
  const directory = await scratch(t), path = `${directory}/input.json`;
  await writeFile(path, '{"sensitive":', { mode: 0o600 });
  const held = await interleavePrivateStat(t, path, () => {});
  await assert.rejects(load(directory, 'input.json'), { message: 'PRIVATE_JSON_INVALID' });
  assert.equal(held().fd, -1);
  await t.test('close failure remains a failure', async t => {
    await writeFile(path, '{}');
    const getHandle = await interleavePrivateStat(t, path, (_info, handle) => {
      const close = handle.close.bind(handle);
      t.mock.method(handle, 'close', async () => { await close(); throw new Error('private-path'); });
    });
    await assert.rejects(load(directory, 'input.json'), { message: 'PRIVATE_FILE_CLOSE_FAILED' });
    assert.equal(getHandle().fd, -1);
  });
});
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
  assert.equal(env.infrastructureResourceGroup, undefined);
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
  const receipts = fixtureReceipts(), p = buildPhase(c, 'disabled-app', contract, receipts), d = p.resources[0];
  const actual = { ...structuredClone(d.expected), id: d.id };
  actual.properties.configuration.ingress.fqdn = 'missionspec-test.australiaeast.azurecontainerapps.io';
  for (const id of [r.ingestIdentity, r.pullIdentity]) {
    const { clientId, principalId } = receipts.core.resources[id].properties;
    actual.identity.userAssignedIdentities[id] = { clientId, principalId };
  }
  const context = { identities: receipts.core.resources, publication: receipts.publication };
  verifyResource(c, p, d, actual, context);
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
    assert.throws(() => verifyResource(c, p, d, bad, context));
  }
});
test('actual app defaults qualify only as bounded readback equivalences with independent identity and image proof', () => {
  const f = fixtureReconciliation(), phase = f.origins.records[6].phase, descriptor = phase.resources[0];
  const actual = f.proposal.results['disabled-app'].resources[r.app];
  const context = { identities: f.proposal.identities, publication: f.origins.imagePublication.receipt };
  verifyResource(c, phase, descriptor, actual, context);
  for (const transport of ['http', 'Http']) {
    const value = structuredClone(actual); value.properties.configuration.ingress.transport = transport;
    value.properties.template.containers[0].probes.reverse();
    verifyResource(c, phase, descriptor, value, context);
  }
  assert.equal(actual.properties.template.containers[0].resources.ephemeralStorage, '1Gi');
  for (const change of [
    v => { v.properties.template.containers[0].resources.ephemeralStorage = '2Gi'; },
    v => { v.properties.template.containers[0].resources.ephemeralStorage = 1; },
    v => { v.properties.template.containers[0].resources.ephemeralStorage = null; },
    v => { v.properties.template.containers[0].resources.cpu = 0.5; },
    v => { v.properties.template.containers[0].resources.memory = '1Gi'; },
    v => { v.properties.template.containers[0].resources.gpu = 1; },
    v => { v.properties.configuration.ingress.transport = 'HTTP'; },
    v => { v.properties.configuration.ingress.transport = 'http2'; },
    v => { v.properties.template.containers[0].probes.push(v.properties.template.containers[0].probes[0]); },
    v => { v.properties.template.containers[0].probes.pop(); },
    v => { v.properties.template.containers[0].probes[0].type = 'Other'; },
    v => { v.properties.template.containers[0].probes[0].httpGet.path = '/other'; },
    v => { v.properties.template.containers[0].probes[0].httpGet.httpHeaders = [{ name: 'Authorization', value: 'other' }]; },
    v => { v.properties.template.containers[0].probes[0].periodSeconds = 99; },
    v => { v.properties.template.containers[0].probes[0].failureThreshold = 99; },
    v => { v.properties.template.containers[0].probes[0].command = ['other']; },
    v => { v.properties.configuration.registries[0].username = 'user'; },
    v => { v.properties.configuration.registries[0].passwordSecretRef = 'password'; },
    v => { v.properties.configuration.registries[0].username = null; },
    v => { v.properties.configuration.registries[0].passwordSecretRef = false; },
    v => { v.properties.configuration.registries.push(v.properties.configuration.registries[0]); },
    v => { v.properties.configuration.registries[0].extra = true; },
    v => { v.properties.configuration.registries[0].identity = r.ingestIdentity; },
    v => { v.properties.configuration.identitySettings.push({ ...v.properties.configuration.identitySettings[0], identity: r.ingestIdentity.toUpperCase() }); },
    v => { const [key, value] = Object.entries(v.identity.userAssignedIdentities)[0]; v.identity.userAssignedIdentities[key.toUpperCase()] = value; },
    v => { v.identity.userAssignedIdentities[r.ingestIdentity.toLowerCase()].clientId = c.operatorPrincipalId; },
    v => { v.identity.userAssignedIdentities[r.pullIdentity.toLowerCase()].principalId = c.operatorPrincipalId; },
    v => { v.identity.userAssignedIdentities[r.ingestIdentity.toLowerCase()].unknown = true; },
    v => { v.identity.userAssignedIdentities[r.workspace] = { clientId: c.runId, principalId: c.operatorPrincipalId }; },
    v => { v.properties.configuration.identitySettings[1].lifecycle = 'All'; },
    v => { v.properties.configuration.identitySettings[0].extra = true; },
    v => { v.properties.configuration.runtime = { java: { enableMetrics: true } }; },
    v => { v.properties.configuration.secrets = [{ name: 'new' }]; },
    v => { v.properties.configuration.dapr = { enabled: false }; },
    v => { v.properties.configuration.service = {}; },
    v => { v.properties.template.containers[0].securityContext = { privileged: true }; },
    v => { v.properties.template.containers[0].securityContext = null; },
    v => { v.properties.template.containers[0].volumeMounts = [{ mountPath: '/data', volumeName: 'extra' }]; },
    v => { v.properties.template.volumes = [{ name: 'extra', storageType: 'EmptyDir' }]; },
    v => { v.properties.template.serviceBinds = [{ name: 'other' }]; },
    v => { v.properties.template.initContainers = [{ name: 'init', image: 'other' }]; },
    v => { v.properties.template.containers.push(structuredClone(v.properties.template.containers[0])); },
    v => { v.properties.template.containers[0].command = ['other']; },
    v => { v.properties.template.containers[0].args = ['--inspect']; },
    v => { v.properties.template.containers[0].env.push({ name: 'NODE_OPTIONS', value: '--inspect' }); },
    v => { v.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; },
    v => { v.properties.template.scale.cooldownPeriod = 301; },
    v => { v.properties.template.scale.pollingInterval = 31; },
    v => { v.properties.template.revisionSuffix = 'changed'; },
    v => { v.properties.configuration.ingress.exposedPort = 80; },
    v => { v.properties.configuration.ingress.additionalPortMappings = [{ external: true, targetPort: 9090 }]; },
    v => { v.properties.configuration.ingress.corsPolicy = {}; },
    v => { v.properties.delegatedIdentities = [r.ingestIdentity]; },
    v => { v.properties.configuration.unknown = null; },
    v => { v.properties.unknown = null; },
  ]) {
    const bad = structuredClone(actual); change(bad);
    assert.throws(() => verifyResource(c, phase, descriptor, bad, context), /^Error: APP_/);
  }
  assert.throws(() => verifyResource(c, phase, descriptor, actual, { publication: context.publication }), /APP_IDENTITY_READBACK_REQUIRED/);
  assert.throws(() => verifyResource(c, phase, descriptor, actual, { identities: context.identities }), /APP_PUBLICATION_READBACK_REQUIRED/);
  const falseIdentity = structuredClone(context);
  falseIdentity.identities[r.ingestIdentity].properties.principalId = c.operatorPrincipalId;
  assert.throws(() => verifyResource(c, phase, descriptor, actual, falseIdentity), /APP_IDENTITY_DRIFT/);
});
test('separate publication origin verifies exact bytes, original single-copy authority and retained qualification conditions', () => {
  const image = fixtureImagePublication();
  verifyImagePublication(c, image);
  for (const change of [
    v => { v.version = 2; }, v => { v.release.publicationBindingSha256 = digest('different'); },
    v => { v.release.applicationDeploymentAuthorized = true; }, v => { v.release.maximumNewImageDigests = 2; },
    v => { v.journal.intentAt = v.release.expiresAt; }, v => { v.journal.copyInvocations = 2; },
    v => { v.journal.outcome = 'submission-possible'; }, v => { v.journal.copySucceeded = false; },
    v => { v.manifestJson += '\n'; }, v => { v.configJson += '\n'; },
    v => { v.receipt.configUser = '0:0'; }, v => { v.receipt.command = ['other']; },
    v => { v.receipt.recentDigestCount = 2; }, v => { v.receipt.configSha256 = v.receipt.digest; },
    v => { v.receipt.independentlyVerifiedRemoteGraph.blobs.pop(); },
    v => { v.receipt.correspondingSource.boundToVerifiedRemoteLayerBytes = false; },
    v => { v.receipt.securityQualification.suppressedFindings = 1; },
    v => { v.receipt.securityQualification.nativeV8ConditionsRetained = false; },
    v => { v.receipt.securityQualification.patchedOrCompleteNativeCoverageClaimed = true; },
    v => { v.receipt.securityQualification.counts.UNKNOWN = 0; },
  ]) {
    const bad = structuredClone(image); change(bad);
    assert.throws(() => verifyImagePublication(c, bad), /^Error: PUBLICATION_/);
  }
  const f = fixtureReconciliation();
  verifyPublicationReadback(c, image, f.proposal.imagePublication);
  for (const change of [
    v => { v.repositories.push('extra'); }, v => { v.manifests.push({ digest: 'other' }); },
    v => { v.manifests[0].digest = 'other'; }, v => { v.manifest.config.digest = 'other'; },
    v => { v.registry.properties.adminUserEnabled = true; }, v => { v.registry.properties.anonymousPullEnabled = true; },
  ]) {
    const bad = structuredClone(f.proposal.imagePublication); change(bad);
    assert.throws(() => verifyPublicationReadback(c, image, bad), /PUBLICATION_READBACK_CHANGED/);
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
function fixtureImagePublication(config = c) {
  const r = ids(config), manifest = JSON.parse(manifestJson), imageConfig = JSON.parse(configJson);
  assert.equal('sha256:' + digest(manifestJson), config.receiverDigest);
  assert.equal('sha256:' + digest(configJson), manifest.config.digest);
  const target = { subscriptionId: config.subscriptionId, registryResourceId: r.registry, registry: `${config.registryName}.azurecr.io`,
    repository: 'missionspec/telemetry-ingest', tag: 'receiver-91c72962bdb2', manifestDigest: config.receiverDigest,
    configDigest: manifest.config.digest, maximumNewImageDigests: 1 };
  const currentScan = { reportSha256: digest('scan'), databaseSha256: digest('db'),
    databaseUpdatedAt: '2026-09-23T00:00:00.000Z', databaseNextUpdate: '2026-09-24T00:00:00.000Z', counts: { MEDIUM: 13, LOW: 7, UNKNOWN: 2 } };
  const binding = { target, currentScan };
  const release = { version: 1, action: 'publish-one-receiver-digest', publicationBindingSha256: digest(json(binding)),
    ...Object.fromEntries(['registry', 'repository', 'tag', 'manifestDigest', 'configDigest', 'maximumNewImageDigests'].map(k => [k, target[k]])),
    approvedAt: '2026-09-23T00:27:00.000Z', expiresAt: '2026-09-23T00:57:00.000Z',
    runtimeQualification: 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY',
    retainedAdvisories: ['CVE-2026-95818', 'CVE-2026-86805', 'CVE-2026-91745', 'CVE-2026-93377', 'CVE-2026-91728'],
    applicationDeploymentAuthorized: false, ingestionAuthorized: false, clientActivationAuthorized: false, repushOrDeletionAuthorized: false };
  const blobs = [manifest.config, ...manifest.layers].map(({ digest, size }) => ({ digest, size }));
  const receipt = { ...fixtureReceipts(config).publication, manifest, checkedAt: '2026-09-23T00:29:00.000Z',
    nativeV8Clearance: release.runtimeQualification, publicationReleaseSha256: digest(json(release)), publicationBindingSha256: release.publicationBindingSha256,
    copyInvocations: 1, copySucceeded: true,
    independentlyVerifiedRemoteGraph: { manifestDigest: target.manifestDigest, configDigest: target.configDigest, blobs, platform: 'linux/amd64',
      user: imageConfig.config.User, command: imageConfig.config.Cmd },
    correspondingSource: { archiveSha256: digest('source archive'), manifestSha256: digest('source manifest'), boundToVerifiedRemoteLayerBytes: true },
    securityQualification: { scanReportSha256: currentScan.reportSha256, databaseSha256: currentScan.databaseSha256,
      databaseUpdatedAt: currentScan.databaseUpdatedAt, databaseNextUpdate: currentScan.databaseNextUpdate, counts: currentScan.counts,
      suppressedFindings: 0, nativeV8ConditionsRetained: true, patchedOrCompleteNativeCoverageClaimed: false,
      runtimeQualification: release.runtimeQualification, retainedAdvisories: release.retainedAdvisories },
    applicationDeploymentAuthorized: false, ingestionAuthorized: false, clientActivationAuthorized: false };
  return { version: 1, receipt, release, binding, manifestJson, configJson,
    journal: { version: 1, action: release.action, target, bindingSha256: release.publicationBindingSha256, releaseSha256: digest(json(release)),
      publicationReceiptSha256: digest(json(receipt)), outcome: 'published-readback-qualified', maximumCopyInvocations: 1,
      copyInvocations: 1, copySucceeded: true, verifiedRemoteBlobCount: blobs.length, intentAt: '2026-09-23T00:28:00.000Z' },
    qualification: { checkedAt: '2026-09-23T00:29:30.000Z', publicationReceiptSha256: digest(json(receipt)),
      copyInvocations: 1, copySucceeded: true, remoteBlobCount: blobs.length, credentialDirectoriesRemoved: true } };
}
function fixtureReconciliation(config = c, baseline = digest('baseline'), count = 7) {
  const f = fixtureFoundation(config), r = ids(config), source = digest('current policy');
  const records = [], inventory = { value: [] }, base = Date.parse('2026-09-23T00:00:00.000Z');
  const iso = offset => new Date(base + offset).toISOString();
  const imagePublication = count === 7 ? fixtureImagePublication(config) : null;
  for (const [index, name] of PHASES.slice(0, count).entries()) {
    const oldSource = digest(index >= 5 ? 'executed grants and app source' : index < 2 || index === 4 ? `executed source ${name}` : 'executed workspace and data source');
    const intent = (index * 5 + 1) * 60000, prerequisiteReceipts = {};
    for (const prior of records) {
      const priorName = prior.phase.phase;
      if ((index >= 5 && prior.phase.phase !== 'assignments') || index === 4 || (index >= 2 && ['project-budget', 'core'].includes(priorName))) {
        prerequisiteReceipts[priorName] = { qualificationKind: 'reviewed-read-only-reconciliation', qualified: true, phase: priorName,
          configSha256: digest(json(config)), phaseSha256: digest(json(prior.phase)), sourceSha256: prior.publication.sourceSha256,
          deployment: structuredClone(prior.firstReadback.deployment), resources: structuredClone(prior.firstReadback.resources),
          reconciliation: { proposalSha256: digest('historical proposal'), reviewSha256: digest('historical review'),
            executionOriginSha256: digest(json(prior)), policySourceSha256: oldSource,
            checkedAt: iso((index >= 5 ? 23 : index === 4 ? 18 : 8) * 60000), reviewedAt: iso((index >= 5 ? 24 : index === 4 ? 19 : 9) * 60000),
            originalJournalOutcome: prior.journal.outcome, originalReceiptQualified: prior.originalReceipt?.qualified === true } };
      } else prerequisiteReceipts[priorName] = structuredClone(prior.originalReceipt);
    }
    if (name === 'disabled-app') prerequisiteReceipts.publication = imagePublication.receipt;
    const phase = buildPhase(config, name, contract, prerequisiteReceipts, f);
    if (name === 'core') {
      phase.resources.find(v => v.id === r.environment).expected.properties.infrastructureResourceGroup = `${config.namePrefix}-managed`;
    }
    const resources = {};
    for (const descriptor of phase.resources) {
      const v = name === 'workspace-access' ? structuredClone(prerequisiteReceipts.core.resources[r.workspace])
        : { ...structuredClone(descriptor.expected), id: descriptor.id };
      v.properties.provisioningState = 'Succeeded';
      if (descriptor.id === r.registry) Object.assign(v.properties, { loginServer: `${config.registryName}.azurecr.io`, creationDate: iso(intent + 2000) });
      if (descriptor.id === r.ingestIdentity || descriptor.id === r.pullIdentity) {
        const ids = fixtureReceipts(config).core.resources[descriptor.id].properties;
        Object.assign(v.properties, ids, { tenantId: config.tenantId });
      }
      if (descriptor.id === r.workspace && name === 'core') Object.assign(v.properties, { customerId: '00000000-0000-4000-8000-000000000009', createdDate: iso(intent + 2000) });
      if (descriptor.id === r.environment) {
        Object.assign(v.properties, { infrastructureResourceGroup: null, vnetConfiguration: null,
          defaultDomain: 'fixture.australiaeast.azurecontainerapps.io', customDomainConfiguration: { customDomainVerificationId: 'fixture-verification' } });
        // The provider stamp is pinned, not reinterpreted as the ARM inventory's creation time.
        v.systemData = { createdAt: iso(intent + 2000 - 8 * 3600000) };
      }
      if (descriptor.type === 'Microsoft.Consumption/budgets') delete v.properties.provisioningState;
      if (descriptor.type === 'Microsoft.Authorization/roleDefinitions') {
        delete v.properties.provisioningState;
        v.properties.createdOn = iso(intent + 2000);
      }
      if (descriptor.type === 'Microsoft.Authorization/roleAssignments') {
        delete v.properties.provisioningState;
        v.properties.scope = descriptor.expected.scope;
        v.properties.createdOn = iso(intent + 2000);
      }
      if (descriptor.id === r.table) {
        delete v.type;
        v.systemData = { createdAt: iso(intent + 2000) };
        v.properties.archiveRetentionInDays = 0;
        Object.assign(v.properties.schema, { tableType: 'CustomLog', tableSubType: 'DataCollectionRuleBased', solutions: ['LogManagement'],
          isTroubleshootingAllowed: true, standardColumns: [{ name: 'TenantId', type: 'guid', isDefaultDisplay: false, isHidden: false }] });
        v.properties.schema.columns = v.properties.schema.columns.map(column => ({ ...column, isDefaultDisplay: false, isHidden: false }));
      }
      if (descriptor.id === r.dcr) {
        v.systemData = { createdAt: iso(intent + 2000) };
        Object.assign(v.properties, { immutableId: 'dcr-' + 'a'.repeat(32), endpoints: { logsIngestion: 'https://fixture.australiaeast-1.ingest.monitor.azure.com' } });
        v.properties.destinations.logAnalytics[0].workspaceId = prerequisiteReceipts['workspace-access'].resources[r.workspace].properties.customerId;
      }
      if (descriptor.id === r.app) {
        v.systemData = { createdAt: iso(intent + 2000) };
        const p = v.properties, container = p.template.containers[0];
        p.configuration.ingress.fqdn = 'fixture.australiaeast.azurecontainerapps.io';
        p.configuration.ingress.transport = 'Http'; p.configuration.ingress.exposedPort = 0;
        p.delegatedIdentities = []; p.template.volumes = null; p.template.initContainers = null; p.template.serviceBinds = null;
        p.template.revisionSuffix = ''; p.template.scale.cooldownPeriod = 300; p.template.scale.pollingInterval = 30;
        container.resources.ephemeralStorage = '1Gi'; container.probes.reverse();
        p.configuration.registries[0].username = ''; p.configuration.registries[0].passwordSecretRef = '';
        v.identity.userAssignedIdentities = Object.fromEntries([r.ingestIdentity, r.pullIdentity].map(id => {
          const { clientId, principalId } = prerequisiteReceipts.core.resources[id].properties;
          return [id.toLowerCase(), { clientId, principalId }];
        }));
        p.configuration.identitySettings = p.configuration.identitySettings.map(v => ({ ...v, identity: v.identity.toLowerCase() }));
      }
      resources[descriptor.id] = v;
      if (!['Microsoft.Consumption/budgets', 'Microsoft.Authorization/roleDefinitions', 'Microsoft.Authorization/roleAssignments'].includes(descriptor.type) &&
          descriptor.id !== r.table && !inventory.value.some(v => v.id === descriptor.id)) {
        inventory.value.push({ id: descriptor.id, type: descriptor.type, createdTime: iso(intent + 2000) });
      }
    }
    const deployment = { id: phase.deploymentId, properties: { provisioningState: 'Succeeded', mode: 'Incremental',
      correlationId: `${name}-correlation`, timestamp: iso(intent + 60000), templateHash: `${name}-template` } };
    const whatIf = { status: 'Succeeded', changes: phase.resources.map(d => name === 'project-budget'
      ? { resourceId: d.id, changeType: 'Modify', before: f.project, after: d.expected }
      : { resourceId: d.id, changeType: name === 'workspace-access' ? 'NoChange' : 'Create' }) };
    if (index >= 2 && index !== 4) for (const descriptor of records[1].phase.resources) {
      if (descriptor.type !== 'Microsoft.Consumption/budgets' && !phase.resources.some(v => v.id === descriptor.id)) {
        whatIf.changes.push({ resourceId: descriptor.id, changeType: 'Ignore' });
      }
    }
    const bindings = { sourceSha256: oldSource, phaseSha256: digest(json(phase)), configSha256: digest(json(config)),
      originSha256: config.originSha256, whatIfSha256: digest(json(whatIf)), baselineSha256: baseline, receiptsSha256: digest(json(prerequisiteReceipts)) };
    let roleDefinitions = null;
    if (name === 'assignments') {
      const readbacks = assignmentRoleTargets(config).map(target => ({ scope: target.scope,
        resource: target.roleType === 'CustomRole' ? structuredClone(prerequisiteReceipts['upload-role'].resources[r.uploadRole]) : {
          id: target.roleDefinitionId, name: target.roleDefinitionId.split('/').at(-1), type: 'Microsoft.Authorization/roleDefinitions',
          properties: { roleName: target.roleName, type: target.roleType, createdOn: '2015-01-01T00:00:00.000Z',
            permissions: [{ actions: ['*/read'], notActions: [], dataActions: [], notDataActions: [] }], assignableScopes: ['/'] } } }));
      const roles = assignmentRoleTargets(config).map((target, i) => roleDefinitionSignature(config, target, readbacks[i].resource));
      roleDefinitions = { checkedAt: iso(intent - 30000), roles, readbacks, roleDefinitionsSha256: digest(json(roles)) };
      bindings.foundationBaselineSha256 = baseline;
      bindings.roleDefinitionsSha256 = roleDefinitions.roleDefinitionsSha256;
      bindings.baselineSha256 = digest(json({ foundationBaselineSha256: baseline, roleDefinitionsSha256: roleDefinitions.roleDefinitionsSha256 }));
    }
    const held = ['core', 'data', 'disabled-app'].includes(name);
    const originalReceipt = held ? null : { qualified: true, phase: name, configSha256: bindings.configSha256,
      phaseSha256: bindings.phaseSha256, sourceSha256: oldSource, deployment, resources, completedAt: iso(intent + 61000) };
    const { roleDefinitionsSha256, foundationBaselineSha256, ...approvalBindings } = bindings;
    records.push({ version: 3, publication: { commitSha: String(index + 1).repeat(40), sourceSha256: oldSource }, phase, prerequisiteReceipts, roleDefinitions,
      approval: { action: `direct-arm-${name}`, ...approvalBindings, approvedAt: iso(intent - 60000), expiresAt: iso(intent + 29 * 60000) },
      journal: { phase: name, phaseSha256: bindings.phaseSha256, intentAt: iso(intent),
        outcome: held ? 'reconciliation-required' : 'readback-qualified',
        ...(held ? { failureCode: name === 'core' ? 'ENVIRONMENT_PRIVACY_DRIFT' : name === 'data' ? 'TABLE_RETENTION_SCHEMA_DRIFT' : 'APP_PRIVACY_RUNTIME_DRIFT' } : {}) },
      preflight: { ...bindings, qualified: true, cost: firstReleaseCost(), startedAt: base + intent - 40000, completedAt: base + intent - 20000 },
      validation: { properties: { provisioningState: 'Succeeded', templateHash: deployment.properties.templateHash } }, whatIf,
      firstReadback: { checkedAt: iso(intent + 61000), deployment, resources }, originalReceipt });
  }
  const origins = { version: 3, records, imagePublication };
  const proposal = { version: 3, kind: 'read-only-completed-phases', sourceSha256: source,
    configSha256: digest(json(config)), executionOriginsSha256: digest(json(origins)), baselineSha256: baseline,
    checkedAt: iso(40 * 60000), results: Object.fromEntries(records.map(record => [record.phase.phase, {
      executionOriginSha256: digest(json(record)), deployment: structuredClone(record.firstReadback.deployment),
      resources: structuredClone(record.firstReadback.resources),
      identityPins: Object.fromEntries(record.phase.resources.map(descriptor => [descriptor.id, executionIdentity(record.firstReadback.resources[descriptor.id], descriptor.type)])),
      diagnostics: Object.fromEntries(record.phase.resources.filter(v => [r.workspace, r.environment, r.app].includes(v.id)).map(v => [v.id, { value: [] }])),
      exports: ['core', 'workspace-access', 'data', 'assignments', 'disabled-app'].includes(record.phase.phase) ? { value: [] } : null }])),
    stateBudget: f.state, workspace: structuredClone(records[2].firstReadback.resources[r.workspace]),
    identities: count === 7 ? Object.fromEntries([r.ingestIdentity, r.pullIdentity].map(id => [id, structuredClone(records[1].firstReadback.resources[id])])) : null,
    imagePublication: imagePublication ? { registry: structuredClone(records[1].firstReadback.resources[r.registry]), repositories: ['missionspec/telemetry-ingest'],
      manifests: [{ digest: config.receiverDigest }], manifest: imagePublication.receipt.manifest } : null,
    roleDefinitions: records[5]?.roleDefinitions ?? null, inventory, managedGroup: null };
  const review = { version: 3, action: 'accept-exact-arm-reconciliation', sourceSha256: source,
    proposalSha256: digest(json(proposal)), reviewedAt: iso(41 * 60000) };
  const lookup = async commit => records.find(v => v.publication.commitSha === commit)?.publication.sourceSha256;
  return { config, foundation: f, origins, proposal, review, source, lookup };
}
function fixtureAssignmentRoleReads(config = c) {
  const f = fixtureReconciliation(config, digest('baseline'), 5), rr = ids(config), uploadReceipt = f.origins.records[4].originalReceipt;
  const phase = buildPhase(config, 'assignments', contract, fixtureReceipts(config)), resources = new Map();
  for (const target of assignmentRoleTargets(config)) {
    const resource = target.roleType === 'CustomRole' ? structuredClone(uploadReceipt.resources[rr.uploadRole]) : {
      id: target.roleDefinitionId, name: target.roleDefinitionId.split('/').at(-1), type: 'Microsoft.Authorization/roleDefinitions',
      properties: { type: 'BuiltInRole', roleName: target.roleName, createdOn: '2015-01-01T00:00:00.000Z',
        permissions: [{ actions: target.roleName === 'AcrPull' ? ['Microsoft.ContainerRegistry/registries/pull/read'] : ['*/read'],
          notActions: target.roleName === 'AcrPull' ? [] : ['Microsoft.OperationalInsights/workspaces/sharedKeys/read'], dataActions: [], notDataActions: [] }],
        assignableScopes: ['/'] },
    };
    resources.set(`${target.scope}/providers/Microsoft.Authorization/roleDefinitions/${target.roleDefinitionId.split('/').at(-1)}`, resource);
  }
  const read = async (method, id, api) => {
    assert.equal(method, 'GET'); assert.equal(api, '2022-04-01'); assert(resources.has(id));
    return structuredClone(resources.get(id));
  };
  return { phase, resources, uploadReceipt, read };
}
test('assignment role definitions are read at their exact scopes with the mutable custom role last', async () => {
  const f = fixtureAssignmentRoleReads(), calls = [];
  const values = await readAssignmentRoleDefinitions(c, f.phase, async (...args) => { calls.push(args); return f.read(...args); }, f.uploadReceipt);
  assert.deepEqual(values.roles.map(v => v.scope), [r.registry, r.workspace, r.dcr]);
  assert.deepEqual(values.roles.map(v => v.roleType), ['BuiltInRole', 'BuiltInRole', 'CustomRole']);
  assert(calls.at(-1)[1].startsWith(r.dcr + '/providers/Microsoft.Authorization/roleDefinitions/'));
  assert.equal(values.roles[2].permissions[0].dataActions[0], 'Microsoft.Insights/Telemetry/Write');
  for (const change of [
    value => { value.id = r.workspace; }, value => { value.name = c.runId; },
    value => { value.properties.type = 'CustomRole'; }, value => { value.properties.roleName = 'Reader'; },
    value => { delete value.properties.permissions[0].notDataActions; }, value => { value.properties.createdOn = 'NaN'; },
    value => { value.properties.assignableScopes = ['']; }, value => { value.properties.assignableScopes = ['/subscriptions/other']; },
  ]) {
    const target = assignmentRoleTargets(c)[0], actual = structuredClone(values.readbacks[0].resource);
    change(actual); assert.throws(() => roleDefinitionSignature(c, target, actual));
  }
  for (const change of [
    value => { value.properties.permissions[0].actions = ['*']; },
    value => { value.properties.assignableScopes = [r.sub]; },
    value => { value.properties.createdOn = '2026-09-23T00:22:00.000Z'; },
  ]) {
    const current = fixtureAssignmentRoleReads(), id = [...current.resources.keys()].at(-1);
    change(current.resources.get(id));
    await assert.rejects(readAssignmentRoleDefinitions(c, current.phase, current.read, current.uploadReceipt));
  }
  const badScope = structuredClone(f.phase); badScope.resources[0].expected.scope = r.sub;
  await assert.rejects(readAssignmentRoleDefinitions(c, badScope, f.read, f.uploadReceipt), /EXACT_ASSIGNMENT_SCOPES_REQUIRED/);
  await assert.rejects(readAssignmentRoleDefinitions(c, f.phase, f.read, null), /UPLOAD_ROLE_RECEIPT_REQUIRED/);
});
test('assignment PUT requires post-body role reads bound to approval and a final synchronous time guard', async t => {
  for (const scenario of ['success', 'custom-role-drift', 'builtin-drift', 'expired-during-read', 'stale-during-read']) await t.test(scenario, async t => {
    const directory = await scratch(t), f = executionFixture('assignments'), definitions = fixtureAssignmentRoleReads();
    const before = await readAssignmentRoleDefinitions(c, f.p, definitions.read, definitions.uploadReceipt);
    f.proof.foundationBaselineSha256 = digest('foundation policy');
    f.proof.roleDefinitionsSha256 = digest(json(before.roles));
    f.proof.baselineSha256 = digest(json({ foundationBaselineSha256: f.proof.foundationBaselineSha256, roleDefinitionsSha256: f.proof.roleDefinitionsSha256 }));
    f.approval.baselineSha256 = f.proof.baselineSha256;
    if (scenario === 'expired-during-read') f.approval.expiresAt = new Date(f.io.now() + 60000).toISOString();
    let writes = 0, prepared = false, roleReads = 0;
    const arm = transport(c, f.p, directory, async args => {
      const method = args[args.indexOf('--method') + 1], id = new URL(args[args.indexOf('--url') + 1]).pathname;
      if (method === 'PUT') {
        assert.equal(prepared, true); assert.equal(roleReads, 3);
        assert.equal(f.journal.outcome, 'submission-possible');
        writes++; return {};
      }
      if (definitions.resources.has(id)) {
        assert.equal(prepared, true); roleReads++;
        if (roleReads === 3 && scenario === 'expired-during-read') f.advance(60000);
        if (roleReads === 3 && scenario === 'stale-during-read') f.advance(300001);
        return structuredClone(definitions.resources.get(id));
      }
      if (id === f.p.deploymentId) return writes ? { id, properties: { provisioningState: 'Succeeded' } } : null;
      const descriptor = f.p.resources.find(v => v.id === id); assert(descriptor);
      return { id, properties: { ...descriptor.expected.properties, scope: descriptor.expected.scope } };
    });
    f.io.assignmentRoleDefinitions = () => readAssignmentRoleDefinitions(c, f.p, arm, definitions.uploadReceipt);
    f.io.arm = (method, id, api, body, filter, guard, roleGate) => arm(method, id, api, method === 'PUT' ? {
      toJSON() {
        prepared = true;
        if (scenario === 'custom-role-drift') definitions.resources.get([...definitions.resources.keys()].at(-1)).properties.permissions[0].actions.push('*');
        if (scenario === 'builtin-drift') definitions.resources.get([...definitions.resources.keys()][0]).properties.permissions[0].actions.push('Microsoft.Authorization/roleAssignments/write');
        return body;
      },
    } : body, filter, guard, roleGate);
    const controller = new CollectorController(c, f.p, f.io);
    if (scenario === 'success') {
      await controller.execute(f.approval);
      assert.equal(writes, 1); assert.equal(f.receipt.qualified, true);
    } else {
      await assert.rejects(controller.execute(f.approval), /OWNED_RESOURCES_PRESERVED/);
      assert.equal(writes, 0); assert.equal(f.receipt, null); assert.equal(f.journal.outcome, 'reconciliation-required');
      assert.match(f.journal.failureCode, /^(UPLOAD_ROLE_SCOPE_DRIFT|ASSIGNMENT_ROLE_DEFINITION_DRIFT|FRESH_REVIEW_MISMATCH)$/u);
    }
    assert.deepEqual(await readdir(directory), []);
  });
  const f = executionFixture('assignments');
  await assert.rejects(new CollectorController(c, f.p, f.io).execute(f.approval), /FRESH_ROLE_REVIEW_MISMATCH/);
  assert.equal(f.journal, null); assert.equal(f.writes, 0);
  const directory = await scratch(t), arm = transport(c, f.p, directory, async () => { assert.fail('must not dispatch'); });
  await assert.rejects(arm('PUT', f.p.deploymentId, '2022-09-01', {}, undefined, () => {}), /ASSIGNMENT_ROLE_READBACK_REQUIRED/);
});
test('default-network Consumption readback admits null infrastructure group but rejects other networking or telemetry', () => {
  const f = fixtureReconciliation(), p = f.origins.records[1].phase, descriptor = p.resources.find(v => v.id === r.environment);
  const actual = f.proposal.results.core.resources[r.environment];
  verifyResource(c, p, descriptor, actual);
  for (const change of [
    v => { v.properties.infrastructureResourceGroup = `${c.namePrefix}-managed`; },
    v => { delete v.properties.infrastructureResourceGroup; },
    v => { v.properties.vnetConfiguration = { infrastructureSubnetId: '/other/subnet' }; },
    v => { v.properties.vnetConfiguration = {}; }, v => { v.properties.publicNetworkAccess = 'Disabled'; },
    v => { v.properties.zoneRedundant = true; }, v => { v.properties.workloadProfiles[0].maximumCount = 1; },
    v => { v.properties.appLogsConfiguration = { destination: 'azure-monitor' }; },
    v => { v.properties.appLogsConfiguration = { destination: 'log-analytics' }; },
    v => { v.properties.openTelemetryConfiguration = {}; }, v => { v.properties.appInsightsConfiguration = {}; },
    v => { v.properties.ingressConfiguration = {}; }, v => { v.properties.customDomainConfiguration.dnsSuffix = 'other.invalid'; },
  ]) { const bad = structuredClone(actual); change(bad); assert.throws(() => verifyResource(c, p, descriptor, bad), /ENVIRONMENT_PRIVACY_DRIFT/); }
  const custom = structuredClone(descriptor); custom.expected.properties.vnetConfiguration = { infrastructureSubnetId: '/other/subnet' };
  assert.throws(() => verifyResource(c, p, custom, actual), /ENVIRONMENT_PRIVACY_DRIFT/);
  assert.equal(firstReleaseCost().total, 301.66);
});
test('Table GET accepts only the documented boolean column display flags without changing the data contract', () => {
  const f = fixtureReconciliation(), p = f.origins.records[3].phase, descriptor = p.resources.find(v => v.id === r.table);
  const actual = f.proposal.results.data.resources[r.table];
  assert.equal(actual.type, undefined);
  verifyResource(c, p, descriptor, actual);
  for (const key of ['isDefaultDisplay', 'isHidden']) {
    const allowed = structuredClone(actual); allowed.properties.schema.columns[0][key] = true;
    verifyResource(c, p, descriptor, allowed);
    delete allowed.properties.schema.columns[0][key];
    verifyResource(c, p, descriptor, allowed);
    for (const value of [null, 0, 'false', [], {}]) {
      const bad = structuredClone(actual); bad.properties.schema.columns[0][key] = value;
      assert.throws(() => verifyResource(c, p, descriptor, bad), /TABLE_RETENTION_SCHEMA_DRIFT/);
    }
  }
  for (const change of [
    v => { v.properties.schema.columns.reverse(); }, v => { v.properties.schema.columns[1].type = 'string'; },
    v => { v.properties.schema.columns[1].name = 'other'; }, v => { v.properties.schema.columns.push({ name: 'clientId', type: 'string' }); },
    v => { v.properties.schema.columns.pop(); }, v => { v.properties.schema.columns[0].dataTypeHint = 'armPath'; },
    v => { v.properties.schema.columns[0].description = 'unreviewed'; }, v => { v.properties.schema.extra = true; },
    v => { v.properties.schema.name = 'Other_CL'; }, v => { v.properties.schema.tableType = 'SearchResults'; },
    v => { v.properties.schema.tableSubType = 'Classic'; },
    v => { v.properties.schema.standardColumns.push({ name: 'clientAddress', type: 'string' }); },
    v => { v.properties.schema.isTroubleshootingAllowed = 'true'; }, v => { v.properties.schema.solutions = ['Other']; },
    v => { v.properties.retentionInDays = 30; }, v => { v.properties.totalRetentionInDays = 365; },
    v => { v.properties.archiveRetentionInDays = 1; }, v => { v.properties.plan = 'Basic'; },
  ]) { const bad = structuredClone(actual); change(bad); assert.throws(() => verifyResource(c, p, descriptor, bad), /TABLE_RETENTION_SCHEMA_DRIFT/); }
});
test('DCR GET must bind its computed workspaceId to a separate owned workspace read and retain exact streams and routing', () => {
  const f = fixtureReconciliation(), p = f.origins.records[3].phase, descriptor = p.resources.find(v => v.id === r.dcr);
  const actual = f.proposal.results.data.resources[r.dcr], context = { workspace: f.proposal.workspace };
  verifyResource(c, p, descriptor, actual, context);
  assert.throws(() => verifyResource(c, p, descriptor, actual), /DCR_WORKSPACE_READBACK_REQUIRED/);
  const wrongWorkspace = structuredClone(context.workspace); wrongWorkspace.id = r.table;
  assert.throws(() => verifyResource(c, p, descriptor, actual, { workspace: wrongWorkspace }), /DCR_WORKSPACE_READBACK_REQUIRED/);
  for (const change of [
    v => { delete v.properties.destinations.logAnalytics[0].workspaceId; },
    v => { v.properties.destinations.logAnalytics[0].workspaceId = c.operatorPrincipalId; },
    v => { v.properties.destinations.logAnalytics[0].workspaceId = 123; },
    v => { v.properties.destinations.logAnalytics[0].workspaceResourceId = r.table; },
    v => { v.properties.destinations.logAnalytics[0].name = 'other'; },
    v => { v.properties.destinations.logAnalytics[0].extra = true; },
    v => { v.properties.destinations.logAnalytics.push(v.properties.destinations.logAnalytics[0]); },
    v => { v.properties.streamDeclarations['Custom-MissionSpecTelemetry'].columns.push({ name: 'raw', type: 'string' }); },
    v => { v.properties.streamDeclarations['Custom-MissionSpecTelemetry'].columns[0].isHidden = false; },
    v => { v.properties.dataFlows[0].transformKql = 'source'; },
    v => { v.properties.dataFlows[0].outputStream = 'Custom_Other_CL'; },
    v => { v.properties.dataFlows[0].streams = ['Custom-Other']; },
    v => { v.properties.immutableId = 'not-an-immutable-id'; },
    v => { v.kind = 'Linux'; },
  ]) { const bad = structuredClone(actual); change(bad); assert.throws(() => verifyResource(c, p, descriptor, bad, context), /DCR_READBACK_FAILED/); }
  for (const endpoint of ['not-a-url', 'http://fixture.ingest.monitor.azure.com', 'https://other.invalid',
    'https://fixture.ingest.monitor.azure.com/path', 'https://fixture.ingest.monitor.azure.com?token=value',
    'https://user:password@fixture.ingest.monitor.azure.com', 'https://fixture.ingest.monitor.azure.com:8443']) {
    const bad = structuredClone(actual); bad.properties.endpoints.logsIngestion = endpoint;
    assert.throws(() => verifyResource(c, p, descriptor, bad, context), /DCR_ENDPOINT_INVALID/);
  }
});
test('shared reconciliation requires exact current review and preserves both executed sources and failed legacy outcome', async () => {
  const f = fixtureReconciliation(), before = json(f.origins);
  verifyExecutionOrigins(c, f.foundation, f.origins, contract);
  verifyReconciliation(c, f.foundation, f.origins, f.proposal, f.source, null, contract);
  await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, { ...f, review: null }, f.source, f.lookup), /RECONCILIATION_REVIEW_REQUIRED/);
  const receipts = await reviewedReconciliationReceipts(c, f.foundation, f, f.source, f.lookup);
  assert.equal(json(f.origins), before);
  assert.equal(receipts.core.sourceSha256, f.origins.records[1].publication.sourceSha256);
  assert.equal(receipts.core.qualified, true);
  assert.equal(receipts.core.reconciliation.originalReceiptQualified, false);
  assert.equal(receipts.core.reconciliation.originalJournalOutcome, 'reconciliation-required');
  assert.equal(receipts['project-budget'].reconciliation.originalReceiptQualified, true);
  assert.equal(receipts['workspace-access'].reconciliation.originalReceiptQualified, true);
  assert.equal(receipts.data.reconciliation.originalReceiptQualified, false);
  assert.equal(receipts.data.reconciliation.originalJournalOutcome, 'reconciliation-required');
  assert.equal(receipts.data.sourceSha256, f.origins.records[3].publication.sourceSha256);
  assert.equal(receipts['upload-role'].reconciliation.originalReceiptQualified, true);
  verifyProjectBudgetReceipt(c, receipts['project-budget'], f.foundation, f.source, receipts);
  assert.throws(() => verifyProjectBudgetReceipt(c, receipts['project-budget'], f.foundation, f.source), /RECONCILIATION_REVIEW_REQUIRED/);
  const next = buildPhase(c, 'workspace-access', contract, receipts, f.foundation, f);
  assert.equal(next.reconciliation.reviewSha256, digest(json(f.review)));
  assert.notEqual(digest(json(next)), digest(json(buildPhase(c, 'workspace-access', contract, receipts, f.foundation, { ...f, review: null }))));
  await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, f, f.source, async () => digest('other source')), /PUBLISHED_SOURCE_MISMATCH/);
});
test('four-phase origins bind the actual prior receipt maps, their sources, approvals and immutable identities', async () => {
  for (const change of [
    record => { record.prerequisiteReceipts = {}; },
    record => { delete record.prerequisiteReceipts['workspace-access']; },
    record => { record.prerequisiteReceipts.core.sourceSha256 = digest('forged old source'); },
    record => { record.prerequisiteReceipts.core.resources[r.ingestIdentity].properties.principalId = c.operatorPrincipalId; },
    record => { record.prerequisiteReceipts['workspace-access'].resources[r.workspace].properties.customerId = c.operatorPrincipalId; },
    record => { record.prerequisiteReceipts.core.reconciliation.policySourceSha256 = digest('another policy'); },
    record => { record.prerequisiteReceipts.core.reconciliation.reviewedAt = '2099-09-23T00:00:00.000Z'; },
    record => { record.prerequisiteReceipts['project-budget'].phaseSha256 = digest('wrong phase'); },
    record => { record.prerequisiteReceipts.data = record.prerequisiteReceipts['workspace-access']; },
  ]) {
    const f = fixtureReconciliation(), record = f.origins.records[3];
    change(record);
    assert.throws(() => verifyExecutionOrigins(c, f.foundation, f.origins, contract));
    record.approval.receiptsSha256 = digest(json(record.prerequisiteReceipts));
    record.preflight.receiptsSha256 = record.approval.receiptsSha256;
    assert.throws(() => verifyExecutionOrigins(c, f.foundation, f.origins, contract));
  }
  for (const change of [
    f => { f.origins.records[3].publication.sourceSha256 = digest('another source'); },
    f => { f.origins.records[3].approval.phaseSha256 = digest('wrong phase'); },
    f => { f.origins.records[3].journal.intentAt = f.origins.records[3].approval.expiresAt; },
    f => { f.origins.records[3].validation.properties.templateHash = 'wrong'; },
    f => { f.origins.records[4].publication.sourceSha256 = digest('forged executed role source'); },
    f => { f.origins.records[4].prerequisiteReceipts.data.sourceSha256 = digest('forged data source'); },
    f => { f.proposal.results['upload-role'].resources[r.uploadRole].properties.permissions[0].actions = ['*']; },
    f => { f.proposal.results['upload-role'].resources[r.uploadRole].properties.createdOn = '2026-09-23T00:22:00.000Z'; },
    f => { f.origins.records[2].firstReadback.checkedAt = '2099-01-01T00:00:00.000Z'; },
    f => { f.proposal.results.data.resources[r.table].properties.schema.columns[0].name = 'extraEventField'; },
    f => { f.proposal.results.data.resources[r.dcr].properties.immutableId = 'dcr-' + 'b'.repeat(32); },
    f => { f.proposal.workspace.properties.customerId = c.operatorPrincipalId;
      f.proposal.results.data.resources[r.dcr].properties.destinations.logAnalytics[0].workspaceId = c.operatorPrincipalId; },
    f => { f.proposal.inventory.value.push({ id: r.app, createdTime: f.proposal.checkedAt }); },
  ]) {
    const f = fixtureReconciliation(); change(f);
    f.proposal.executionOriginsSha256 = digest(json(f.origins)); f.review.proposalSha256 = digest(json(f.proposal));
    await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, f, f.source, f.lookup));
  }
});
test('assignment compound baseline and app publication/identity history remain separate mandatory reconciliation gates', async () => {
  const valid = fixtureReconciliation();
  verifyExecutionOrigins(c, valid.foundation, valid.origins, contract);
  assert.notEqual(valid.origins.records[5].preflight.baselineSha256, valid.proposal.baselineSha256);
  assert.equal(valid.origins.records[5].preflight.foundationBaselineSha256, valid.proposal.baselineSha256);
  verifyReconciliation(c, valid.foundation, valid.origins, valid.proposal, valid.source, null, contract);
  for (const change of [
    f => { f.origins.records[5].preflight.baselineSha256 = f.proposal.baselineSha256; f.origins.records[5].approval.baselineSha256 = f.proposal.baselineSha256; },
    f => { f.origins.records[5].roleDefinitions.roles[0].permissions[0].actions.push('*'); },
    f => { f.origins.records[5].roleDefinitions.checkedAt = f.origins.records[6].journal.intentAt; },
    f => { f.origins.records[6].roleDefinitions = f.origins.records[5].roleDefinitions; },
    f => { f.origins.records[6].prerequisiteReceipts.publication.copySucceeded = false; },
    f => { delete f.origins.records[6].prerequisiteReceipts.publication; },
    f => { f.origins.records[6].prerequisiteReceipts.assignments.sourceSha256 = digest('other'); },
    f => { f.origins.records[6].journal.intentAt = f.origins.records[6].approval.expiresAt; },
    f => { f.origins.imagePublication.journal.intentAt = f.origins.imagePublication.release.expiresAt; },
    f => { f.origins.imagePublication = null; },
    f => { f.proposal.roleDefinitions.readbacks[0].resource.properties.permissions[0].actions.push('*'); },
    f => { f.proposal.results.assignments.resources[f.origins.records[5].phase.resources[0].id].properties.scope = r.sub; },
    f => { f.proposal.results.assignments.resources[f.origins.records[5].phase.resources[0].id].properties.condition = 'new'; },
    f => { f.proposal.results['disabled-app'].resources[r.app].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; },
    f => { f.proposal.identities[r.ingestIdentity].properties.principalId = c.operatorPrincipalId;
      f.proposal.results['disabled-app'].resources[r.app].identity.userAssignedIdentities[r.ingestIdentity.toLowerCase()].principalId = c.operatorPrincipalId; },
    f => { f.proposal.imagePublication.manifests.push({ digest: 'another' }); },
    f => { f.proposal.results['disabled-app'].diagnostics[r.app].value.push({ name: 'export' }); },
    f => { f.proposal.results['disabled-app'].exports.value.push({ name: 'export' }); },
    f => { f.proposal.results['disabled-app'].resources[r.app].systemData.createdAt = '2020-01-01T00:00:00.000Z'; },
  ]) {
    const f = fixtureReconciliation(); change(f);
    f.proposal.executionOriginsSha256 = digest(json(f.origins));
    f.review.proposalSha256 = digest(json(f.proposal));
    await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, f, f.source, f.lookup));
  }
  const receipts = await reviewedReconciliationReceipts(c, valid.foundation, valid, valid.source, valid.lookup);
  assert.equal(receipts.assignments.sourceSha256, valid.origins.records[5].publication.sourceSha256);
  assert.equal(receipts['disabled-app'].reconciliation.originalJournalOutcome, 'reconciliation-required');
  assert.equal(receipts['disabled-app'].reconciliation.originalReceiptQualified, false);
  assert.equal(receipts.publication, undefined);
});
test('reconciliation rejects expired original intent, changed template or deployment, identities, routes, inventory and review', async () => {
  for (const change of [
    f => { f.origins.records[1].journal.intentAt = f.origins.records[1].approval.expiresAt; },
    f => { f.origins.records[1].journal.intentAt = 'NaN'; },
    f => { f.origins.records[1].approval.expiresAt = 'not-a-date'; },
    f => { f.origins.records[1].journal.outcome = 'submission-possible'; },
    f => { f.origins.records[1].journal.extra = true; },
    f => { f.origins.records[1].validation.properties.templateHash = 'different'; },
    f => { f.origins.records[1].phase.template.resources[0].properties.adminUserEnabled = true; },
    f => { f.origins.records[0].originalReceipt.sourceSha256 = digest('forged'); },
    f => { f.origins.records[1].firstReadback.deployment.properties.provisioningState = 'Failed'; },
    f => { f.proposal.results.core.deployment.properties.provisioningState = 'Running'; },
    f => { f.proposal.results.core.deployment.properties.correlationId = 'different'; },
    f => { f.proposal.results.core.deployment.properties.templateHash = 'different'; },
    f => { f.proposal.results.core.deployment.properties.mode = 'Complete'; },
    f => { f.proposal.results.core.resources[r.ingestIdentity].properties.principalId = c.operatorPrincipalId; },
    f => { f.proposal.results.core.resources[r.pullIdentity].properties.clientId = c.operatorPrincipalId; },
    f => { f.proposal.results.core.resources[r.workspace].properties.customerId = c.operatorPrincipalId; },
    f => { f.proposal.results.core.resources[r.environment].systemData.createdAt = '2026-09-23T00:01:03.000Z'; },
    f => { f.proposal.results.core.resources[r.registry].properties.resourceGuid = c.runId; },
    f => { f.proposal.results.core.resources[r.registry].properties.creationDate = null; },
    f => { f.proposal.results.core.resources[r.environment].properties.infrastructureResourceGroup = 'other'; },
    f => { f.proposal.results.core.diagnostics[r.workspace].value.push({ id: 'route' }); },
    f => { f.proposal.results.core.diagnostics[r.environment].nextLink = 'more'; },
    f => { f.proposal.results.core.exports.value.push({ id: 'export' }); },
    f => { f.proposal.results.core.exports.nextLink = 'more'; },
    f => { f.proposal.results.core.identityPins[r.workspace].customerId = 'forged'; },
    f => { delete f.proposal.results.core.resources[r.workspace]; },
    f => { f.proposal.stateBudget.properties.amount = 0; },
    f => { f.proposal.results['project-budget'].resources[r.projectBudget].properties.amount = 250; },
    f => { f.proposal.inventory.value.push({ id: r.dcr }); },
    f => { f.proposal.inventory.value[0].createdTime = '2020-01-01T00:00:00.000Z'; },
    f => { f.proposal.inventory.nextLink = 'more'; },
    f => { f.proposal.managedGroup = { id: r.managedGroup }; },
    f => { f.proposal.extra = true; },
    f => { f.proposal.sourceSha256 = digest('other'); },
    f => { f.proposal.baselineSha256 = digest('other'); },
  ]) {
    const f = fixtureReconciliation(); change(f);
    f.proposal.executionOriginsSha256 = digest(json(f.origins));
    f.review.proposalSha256 = digest(json(f.proposal));
    await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, f, f.source, f.lookup));
  }
  for (const change of [
    v => { v.action = 'accept-any-source'; }, v => { v.proposalSha256 = digest('other'); }, v => { v.sourceSha256 = digest('other'); },
    v => { v.reviewedAt = '2026-09-23T00:00:00.000Z'; }, v => { v.reviewedAt = '2099-09-23T00:00:00.000Z'; },
    v => { v.reviewedAt = 'NaN'; }, v => { v.force = true; },
  ]) {
    const f = fixtureReconciliation(); change(f.review);
    await assert.rejects(reviewedReconciliationReceipts(c, f.foundation, f, f.source, f.lookup));
  }
});
function fixtureAdoption() {
  const config = structuredClone(c), storageId = `${r.stateGroup}/providers/Microsoft.Storage/storageAccounts/fixturestate`;
  const snapshot = { id: storageId, properties: { publicNetworkAccess: 'Disabled', allowSharedKeyAccess: false,
    networkAcls: { bypass: 'None', defaultAction: 'Deny', ipRules: [], ipv6Rules: [], virtualNetworkRules: [], resourceAccessRules: [] } } };
  const ledger = { sessions: [] };
  const origin = { version: 1, adoptionDecision: { accepted: true, opaqueTagIsUTC: false }, latestLedger: ledger, latestLedgerSha256: digest(json(ledger)),
    policyBaselineSha256: digest(json({ policies: { value: [] }, defender: { value: [] } })),
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
test('published source lookup uses immutable commit blobs and never evaluates historical code or accepts arbitrary refs', async () => {
  const sourceFiles = Object.fromEntries(['definition.mjs', 'policy.mjs', 'controller.mjs'].map(name => [`infrastructure/arm/telemetry/${name}`, `historical ${name}`]));
  const files = { ...sourceFiles, 'assets/schemas/telemetry-event.schema.json': JSON.stringify(contract.schema),
    'services/telemetry-ingest/schema/storage-columns.json': JSON.stringify(contract.columns) };
  const commit = 'a'.repeat(40), commands = [], expected = createHash('sha256');
  for (const [path, body] of Object.entries(sourceFiles)) expected.update(path.split('/').at(-1)).update(body);
  expected.update(json(contract));
  const run = async (command, args) => {
    assert.equal(command, 'git'); commands.push(args);
    if (args[0] === 'merge-base') { assert.deepEqual(args, ['merge-base', '--is-ancestor', commit, 'HEAD']); return { stdout: Buffer.alloc(0) }; }
    assert.deepEqual(args.slice(0, 2), ['--no-pager', 'show']);
    assert(args[2].startsWith(commit + ':'));
    const path = args[2].slice(41); assert(Object.hasOwn(files, path));
    return { stdout: Buffer.from(files[path]) };
  };
  assert.equal(await publishedSourceDigest(commit, run), expected.digest('hex'));
  assert.equal(commands.length, 6);
  for (const ref of ['HEAD', '--all', 'a'.repeat(39), 'g'.repeat(40)]) await assert.rejects(publishedSourceDigest(ref, run), /PUBLISHED_ORIGIN_INVALID/);
  assert.equal(commands.length, 6);
  await assert.rejects(publishedSourceDigest(commit, async () => { throw new Error('private git failure'); }), { message: 'PUBLISHED_ORIGIN_UNAVAILABLE' });
});
test('reconciliation and fresh qualification read only the exact deployed resources and supported privacy routes', async t => {
 for (const count of [5, 7]) await t.test(`${count} recorded phases`, async t => {
  const a = fixtureAdoption(), f = fixtureReconciliation(a.config, a.origin.policyBaselineSha256, count), directory = await scratch(t), rr = ids(a.config);
  const evidence = { scannerAdoption: a.adoption, foundationBudgets: f.foundation, reconciliation: f };
  const responses = new Map([
    [a.adoption.resourceId, a.adoption.after],
    [a.origin.bootstrap.id, { id: a.origin.bootstrap.id, properties: { ...a.origin.bootstrap, provisioningState: 'Succeeded' } }],
    [`${rr.sub}/providers/Microsoft.Authorization/policyAssignments`, { value: [] }],
    [`${rr.sub}/providers/Microsoft.Security/pricings`, { value: [] }],
    [`${rr.sub}/providers/Microsoft.Insights`, { registrationState: 'Registered', resourceTypes: [{ resourceType: 'diagnosticSettings', apiVersions: [DIAGNOSTIC_API] }] }],
    [rr.stateBudget, f.foundation.state], [rr.managedGroup, null], [`${rr.group}/resources`, f.proposal.inventory],
    [rr.workspace + '/dataExports', { value: [] }],
  ]);
  for (const record of f.origins.records) {
    responses.set(record.phase.deploymentId, record.firstReadback.deployment);
    for (const [id, value] of Object.entries(record.firstReadback.resources)) responses.set(id, value);
  }
  for (const id of [rr.workspace, rr.environment, rr.app]) responses.set(id + '/providers/Microsoft.Insights/diagnosticSettings', { value: [] });
  if (count === 7) for (const [i, target] of assignmentRoleTargets(a.config).entries()) {
    responses.set(`${target.scope}/providers/Microsoft.Authorization/roleDefinitions/${target.roleDefinitionId.split('/').at(-1)}`, f.proposal.roleDefinitions.readbacks[i].resource);
  }
  const calls = [];
  let assignmentPhase;
  const invoke = async args => {
    calls.push(args);
    assert.equal(args[args.indexOf('--subscription') + 1], a.config.subscriptionId);
    if (args[0] === 'account') return { id: a.config.subscriptionId, tenantId: a.config.tenantId, state: 'Enabled', environmentName: 'AzureCloud' };
    if (args[0] === 'acr') {
      assert.equal(count, 7);
      if (args[1] === 'repository' && args[2] === 'list') return ['missionspec/telemetry-ingest'];
      if (args[1] === 'manifest' && args[2] === 'list-metadata') return [{ digest: a.config.receiverDigest }];
      assert.deepEqual(args.slice(0, 3), ['acr', 'manifest', 'show']); return f.origins.imagePublication.receipt.manifest;
    }
    if (args[0] === 'deployment') {
      assert(assignmentPhase);
      if (args[2] === 'validate') return { properties: { provisioningState: 'Succeeded' } };
      assert.equal(args[2], 'what-if');
      return { status: 'Succeeded', changes: assignmentPhase.resources.map(v => ({ resourceId: v.id, changeType: 'Create' })) };
    }
    assert.equal(args[0], 'rest'); assert.equal(args[args.indexOf('--method') + 1], 'GET');
    const url = new URL(args[args.indexOf('--url') + 1]); assert(responses.has(url.pathname), url.pathname);
    if (url.pathname.endsWith('/diagnosticSettings')) assert.equal(url.searchParams.get('api-version'), DIAGNOSTIC_API);
    return structuredClone(responses.get(url.pathname));
  };
  const proposal = await collectReconciliation(a.config, a.origin, directory, evidence, invoke, f.lookup);
  verifyReconciliation(a.config, f.foundation, f.origins, proposal, await sourceDigest(), null, contract);
  assert.equal(proposal.results.core.deployment.properties.provisioningState, 'Succeeded');
  assert.equal(f.origins.records[1].originalReceipt, null);
  assert.equal((await readdir(directory)).length, 0);
  const current = { ...f, proposal };
  await verifyFreshReconciliation(a.config, directory, current, invoke);
  if (count === 5) await t.test('assignment preflight binds freshly read role signatures into the approval baseline', async () => {
    current.review = { version: 3, action: 'accept-exact-arm-reconciliation', sourceSha256: proposal.sourceSha256,
      proposalSha256: digest(json(proposal)), reviewedAt: new Date().toISOString() };
    const receipts = await reviewedReconciliationReceipts(a.config, f.foundation, current, proposal.sourceSha256, f.lookup);
    assignmentPhase = buildPhase(a.config, 'assignments', contract, receipts, f.foundation, current);
    for (const descriptor of assignmentPhase.resources) responses.set(descriptor.id, null);
    const definitions = fixtureAssignmentRoleReads(a.config);
    for (const [id, value] of definitions.resources) responses.set(id, value);
    const providerTypes = {
      'Microsoft.App': ['managedEnvironments', 'containerApps'], 'Microsoft.ContainerRegistry': ['registries'],
      'Microsoft.ManagedIdentity': [], 'Microsoft.OperationalInsights': ['workspaces'], 'Microsoft.Insights': ['dataCollectionRules'],
      'Microsoft.Consumption': [], 'Microsoft.Authorization': [],
    };
    responses.set(`${rr.sub}/providers`, { value: Object.entries(providerTypes).map(([namespace, types]) =>
      ({ namespace, registrationState: 'Registered', resourceTypes: types.map(resourceType => ({ resourceType, locations: ['Australia East'] })) })) });
    responses.set(`${rr.sub}/providers/Microsoft.Authorization/permissions`, { value: [{ actions: ['*'], notActions: [] }] });
    responses.set(`${rr.sub}/providers/Microsoft.Authorization/denyAssignments`, { value: [] });
    responses.set(`${rr.sub}/providers/Microsoft.App/locations/${a.config.location}/usages`, { value: [] });
    const proof = await checkReadOnly(a.config, assignmentPhase, a.origin, receipts, directory,
      { ...evidence, reconciliation: current }, invoke, f.lookup);
    const saved = await load(directory, 'assignments-role-definitions.json');
    assert.equal(proof.roleDefinitionsSha256, digest(json(saved.roles)));
    assert.equal(proof.foundationBaselineSha256, a.origin.policyBaselineSha256);
    assert.equal(proof.baselineSha256, digest(json({ foundationBaselineSha256: proof.foundationBaselineSha256, roleDefinitionsSha256: proof.roleDefinitionsSha256 })));
    assert.notEqual(proof.baselineSha256, a.origin.policyBaselineSha256);
  });
  responses.get(rr.workspace).properties.customerId = a.config.operatorPrincipalId;
  await assert.rejects(verifyFreshReconciliation(a.config, directory, current, invoke), /RESOURCE_IDENTITY_CHANGED/);
  assert(calls.every(args => ['account', 'deployment', 'acr'].includes(args[0]) || args[args.indexOf('--method') + 1] === 'GET'));
  verifyDeploymentIdentity(f.origins.records[1].firstReadback.deployment, proposal.results.core.deployment);
 });
});
test('CLI refuses to prepare, preview or execute already-deployed phases before any Azure call', async t => {
  const a = fixtureAdoption(), f = fixtureReconciliation(a.config, a.origin.policyBaselineSha256);
  const directory = `infrastructure/arm/telemetry/.operator-private/revision-20260923-test-${randomUUID().replaceAll('-', '').slice(0, 12)}`;
  await privateDirectory(directory);
  t.after(() => rm(directory, { recursive: true }));
  for (const [name, value] of Object.entries({ 'config.json': a.config, 'origin.json': a.origin, 'scanner-adoption.json': a.adoption,
    'foundation-budgets.json': f.foundation, 'receipts.json': {}, 'execution-origins-v3.json': f.origins })) await saveImmutable(directory, name, value);
  const untrusted = Object.entries(process.env).some(([key, value]) => value && /^(CI$|GITHUB_|ACTIONS_|RUNNER_)/u.test(key));
  for (const operation of ['prepare', 'check', 'validate-preview', 'execute']) {
    for (const phase of ['core', 'project-budget', 'workspace-access', 'data', 'upload-role', 'assignments', 'disabled-app']) await assert.rejects(
      promisify(execFile)(process.execPath, ['infrastructure/arm/telemetry/controller.mjs', operation, phase, directory]),
      error => error.code === 1 && error.stderr.trim() === (untrusted ? 'UNTRUSTED_RUNNER_FORBIDDEN' : 'COMPLETED_PHASE_REQUIRES_RECONCILIATION'));
  }
  await assert.rejects(promisify(execFile)(process.execPath, ['infrastructure/arm/telemetry/controller.mjs', 'qualify-reconciliation', 'disabled-app', directory]),
    error => error.code === 1 && error.stderr.trim() === (untrusted ? 'UNTRUSTED_RUNNER_FORBIDDEN' : 'RECONCILIATION_REVIEW_REQUIRED'));
  assert.equal(await load(directory, 'reconciliation-receipts.json', true), null);
  assert.equal(await load(directory, 'core-journal.json', true), null);
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
  const roleArgs = [...args, '--url', `https://management.azure.com${r.uploadRole}?api-version=2022-04-01`];
  const roleAbsent = 'ERROR: Not Found({"error":{"code":"RoleDefinitionDoesNotExist"}})';
  assert.equal(await az(roleArgs, 10, error(roleAbsent)), null);
  for (const changed of [
    ['rest', '--method', 'PUT', ...roleArgs.slice(3)],
    [...args, '--url', `https://management.azure.com${r.registry}?api-version=2022-04-01`],
    [...args, '--url', `https://management.azure.com${r.uploadRole}?api-version=2024-08-01`],
  ]) await assert.rejects(az(changed, 10, error(roleAbsent)), /ARM_OPERATION_FAILED/);
  await assert.rejects(az(roleArgs, 10, error('ERROR: Forbidden({"error":{"code":"RoleDefinitionDoesNotExist"}})')), /ARM_OPERATION_FAILED/);
  await assert.rejects(az(roleArgs, 10, error('ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})')), /ARM_OPERATION_FAILED/);
  const p = buildPhase(c, 'core', contract), arm = transport(c, p, 'unused', async () => ({}));
  await assert.rejects(arm('PUT', r.workspace, '2023-09-01'), /FIXED_PHASE/);
  await assert.rejects(arm('POST', r.registry + '/listCredentials', '2023-07-01'), /NONMUTATING/);
  await assert.rejects(arm('DELETE', r.group, '2024-03-01'), /FORBIDDEN/);
});
test('RoleAssignmentNotFound is absence only for exact GET scoped UUID resources in the selected subscription', async () => {
  const error = stderr => async () => { throw Object.assign(new Error('private failure'), { stderr }); };
  const absent = 'ERROR: Not Found({"error":{"code":"RoleAssignmentNotFound","message":"The role assignment was not found."}})';
  const path = `${r.registry}/providers/Microsoft.Authorization/roleAssignments/${c.runId}`;
  const args = (url, method = 'GET', subscription = c.subscriptionId) =>
    ['rest', '--method', method, '--url', url, '--subscription', subscription];
  for (const scope of [r.registry, r.dcr, r.workspace]) {
    assert.equal(await az(args(`https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignments/${c.runId}?api-version=2022-04-01`), 10, error(absent)), null);
  }
  const url = `https://management.azure.com${path}?api-version=2022-04-01`;
  for (const method of ['PUT', 'POST', 'DELETE']) await assert.rejects(az(args(url, method), 10, error(absent)), /ARM_OPERATION_FAILED/);
  for (const badUrl of [
    `https://management.azure.com${r.sub}/providers/Microsoft.Authorization/roleAssignments/${c.runId}?api-version=2022-04-01`,
    `https://management.azure.com${r.group}/providers/Microsoft.Authorization/roleAssignments/${c.runId}?api-version=2022-04-01`,
    `https://management.azure.com${r.group}/providers/Microsoft.Storage/storageAccounts/example/providers/Microsoft.Authorization/roleAssignments/${c.runId}?api-version=2022-04-01`,
    url.replace(c.runId, '-'.repeat(36)), url.replace(c.runId, 'not-a-guid'), url + '&other=value',
    url.replace('2022-04-01', '2024-08-01'), url.replace('2022-04-01', '2022-04-01-preview'),
    url.replace('https:', 'http:'), url.replace('/providers/Microsoft.Authorization/roleAssignments/', '/providers/Microsoft.Authorization/roleDefinitions/'),
  ]) await assert.rejects(az(args(badUrl), 10, error(absent)), /ARM_OPERATION_FAILED/);
  await assert.rejects(az(args(url, 'GET', c.tenantId), 10, error(absent)), /ARM_OPERATION_FAILED/);
  await assert.rejects(az(args(url).slice(0, 5), 10, error(absent)), /ARM_OPERATION_FAILED/);
  for (const text of [
    'ERROR: Forbidden({"error":{"code":"RoleAssignmentNotFound"}})', 'ERROR: Unauthorized({"error":{"code":"RoleAssignmentNotFound"}})',
    'ERROR: Too Many Requests({"error":{"code":"RoleAssignmentNotFound"}})', 'ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})',
    'ERROR: RoleAssignmentNotFound', 'ERROR: {"error":{"code":"RoleAssignmentNotFound"}}',
  ]) await assert.rejects(az(args(url), 10, error(text)), /ARM_OPERATION_FAILED/);
});
test('forbidden ARM operations match complete components in every position without precedence gaps', async () => {
  let calls = 0;
  const p = buildPhase(c, 'core', contract), arm = transport(c, p, 'unused', async () => { calls++; return {}; });
  for (const operation of ['listKeys', 'listSecrets', 'listAccountSas', 'listServiceSas', 'regenerateKey', 'register']) {
    for (const component of [operation, operation.toUpperCase(), operation.toLowerCase()]) {
      for (const id of [`${r.registry}/${component}`, `${r.registry}/${component}/`, `${r.registry}/${component}/nested`,
        `${r.sub}/providers/${component}/resource`]) {
        await assert.rejects(arm('GET', id, '2024-08-01'), /ARM_SCOPE_FORBIDDEN/);
      }
    }
    assert.equal(calls, 0);
  }
  for (const name of ['allowlistKeys', 'listKeysBackup', 'register-helper', 'deregistered']) await arm('GET', `${r.group}/providers/Microsoft.Example/items/${name}`, '2024-08-01');
  assert.equal(calls, 4);
  await assert.rejects(arm('POST', `${r.registry}/allowlistKeys`, '2024-08-01'), /NONMUTATING_POST_ONLY/);
  await assert.rejects(arm('PUT', `${r.registry}/register-helper`, '2024-08-01'), /FIXED_PHASE_PUT_ONLY/);
  assert.equal(calls, 4);
});
test('only exact diagnostic GET routes admit the reviewed preview API and production privacy checks use it', async () => {
  const phase = buildPhase(c, 'core', contract), calls = [];
  const arm = transport(c, phase, 'unused', async args => { calls.push(args); return { value: [] }; });
  for (const target of [r.workspace, r.environment, r.app]) await arm('GET', target + '/providers/Microsoft.Insights/diagnosticSettings', DIAGNOSTIC_API);
  assert.equal(calls.length, 3);
  const path = r.workspace + '/providers/Microsoft.Insights/diagnosticSettings';
  for (const args of [
    ['GET', path, '2021-05-01'], ['GET', path, '2020-01-01-preview'], ['GET', path + '/other', DIAGNOSTIC_API],
    ['GET', r.registry + '/providers/Microsoft.Insights/diagnosticSettings', DIAGNOSTIC_API],
    ['GET', r.workspace, DIAGNOSTIC_API], ['POST', path, DIAGNOSTIC_API], ['PUT', phase.deploymentId, DIAGNOSTIC_API],
    ['GET', path, DIAGNOSTIC_API, {}], ['GET', path, DIAGNOSTIC_API, undefined, '$filter=anything'],
  ]) await assert.rejects(arm(...args), /ARM_SCOPE_FORBIDDEN/);
  assert.equal(calls.length, 3);
  const result = await readPrivacy(c, phase, arm);
  assert.deepEqual(Object.keys(result.diagnostics).sort(), [r.workspace, r.environment].sort());
  assert.deepEqual(result.exports, { value: [] });
  assert.equal(calls.filter(args => args[args.indexOf('--url') + 1].includes('diagnosticSettings')).length, 5);
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
test('data controller reads the workspace independently before validating real computed DCR fields', async () => {
  const f = executionFixture('data'), observed = fixtureReconciliation();
  let submitted = false, workspaceRead = false, writes = 0;
  f.io.arm = async (method, id, _api, body, _filter, guard) => {
    if (method === 'PUT') {
      guard(); assert.equal(id, f.p.deploymentId); assert.deepEqual(body.properties.template, f.p.template);
      writes++; submitted = true; return {};
    }
    if (id === f.p.deploymentId) return submitted ? { id, properties: { provisioningState: 'Succeeded' } } : null;
    if (id === r.workspace) { workspaceRead = true; return observed.proposal.workspace; }
    if (id === r.dcr) assert.equal(workspaceRead, true);
    assert([r.table, r.dcr].includes(id));
    return observed.proposal.results.data.resources[id];
  };
  await new CollectorController(c, f.p, f.io).execute(f.approval);
  assert.equal(writes, 1);
  assert.equal(workspaceRead, true);
  assert.equal(f.receipt.qualified, true);
  assert.equal(f.receipt.resources[r.dcr].properties.immutableId, 'dcr-' + 'a'.repeat(32));
  assert.equal(f.journal.outcome, 'readback-qualified');
});
test('app controller uses fresh independent UAMI reads and real publication context without health or ingestion requests', async () => {
  const f = executionFixture('disabled-app'), observed = fixtureReconciliation();
  observed.proposal.results['disabled-app'].resources[r.app].properties.template.containers[0].env =
    structuredClone(f.p.resources[0].expected.properties.template.containers[0].env);
  let submitted = false;
  const reads = [];
  f.io.publicationReceipt = observed.origins.imagePublication.receipt;
  f.io.arm = async (method, id, _api, _body, _filter, guard) => {
    if (method === 'PUT') { guard(); assert.equal(id, f.p.deploymentId); submitted = true; return {}; }
    reads.push(id);
    if (id === f.p.deploymentId) return submitted ? { id, properties: { provisioningState: 'Succeeded' } } : null;
    if ([r.ingestIdentity, r.pullIdentity].includes(id)) return observed.proposal.identities[id];
    assert.equal(id, r.app);
    assert(reads.includes(r.ingestIdentity) && reads.includes(r.pullIdentity));
    return observed.proposal.results['disabled-app'].resources[r.app];
  };
  await new CollectorController(c, f.p, f.io).execute(f.approval);
  assert.equal(f.receipt.qualified, true);
  assert.equal(f.receipt.resources[r.app].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value, 'false');
  assert.equal(f.journal.outcome, 'readback-qualified');
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
