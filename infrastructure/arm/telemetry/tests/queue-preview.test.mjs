import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { digest, json } from '../definition.mjs';
import { verifyWhatIf } from '../policy.mjs';
import { validateReadOnly, whatIfRequestContext } from '../controller.mjs';
import { queuePostCreateRequirements, queuePostCreateEvidence, queuePreflightBaseline, verifyQueuePreflight,
  verifyQueueWhatIf, verifyQueueResource, verifyQueueRecord } from '../durable-queue.mjs';
import { baseFixture, queuePhaseFixture } from './durable-queue.fixture.mjs';
import { capturedQueueWhatIf } from './queue-whatif.fixture.mjs';

function fixture() {
  const f = baseFixture(), q = queuePhaseFixture(f, 'queue-storage'), raw = capturedQueueWhatIf(f);
  const result = { status: raw.status, changes: raw.properties.changes };
  const preserved = result.changes.filter(v => v.changeType === 'Ignore').map(v => v.resourceId);
  const review = value => verifyQueueWhatIf(f.c, q.phase, f.topology, value, preserved);
  const bind = () => {
    q.whatIf.changes = structuredClone(result.changes);
    q.proof.preservedIds = preserved;
    q.proof.whatIfSha256 = digest(json(q.whatIf));
    q.proof.queuePreview = review(q.whatIf);
    q.proof.queuePreviewSha256 = digest(json(q.proof.queuePreview));
    q.proof.requiredPostCreateReadbacksSha256 = q.proof.queuePreview.requiredPostCreateReadbacksSha256;
    q.proof.baselineSha256 = queuePreflightBaseline(q.proof);
    q.approval.whatIfSha256 = q.proof.whatIfSha256; q.approval.baselineSha256 = q.proof.baselineSha256;
  };
  return { f, q, raw, result, preserved, review, bind };
}
const created = result => result.changes.filter(v => v.changeType === 'Create');

test('captured three-Create/seven-Ignore payload retains six unknown predictions and eight strict postconditions', () => {
  const x = fixture(), before = json(x.raw), preview = x.review(x.result);
  assert.equal(x.result.changes.length, 10);
  assert.equal(created(x.result).length, 3);
  assert.equal(preview.requestedButNotPredicted.length, 6);
  assert.deepEqual(preview.requestedButNotPredicted.map(v => [v.type, v.path]).sort(), [
    ['Microsoft.Storage/storageAccounts', 'properties.encryption.services'],
    ['Microsoft.Storage/storageAccounts', 'properties.networkAcls.ipRules'],
    ['Microsoft.Storage/storageAccounts', 'properties.networkAcls.resourceAccessRules'],
    ['Microsoft.Storage/storageAccounts', 'properties.networkAcls.virtualNetworkRules'],
    ['Microsoft.Storage/storageAccounts/queueServices', 'properties'],
    ['Microsoft.Storage/storageAccounts/queueServices/queues', 'properties'],
  ].sort());
  assert.equal(preview.omittedFieldsVerified, false);
  assert.equal(preview.actualPostCreateReadbackVerified, false);
  assert.equal(preview.returnedFieldsMatchTemplate, true);
  assert.equal(preview.qualified, false);
  assert.equal(preview.executionAuthorized, false);
  assert.equal(preview.armTemplateValidationRequired, true);
  assert.deepEqual(preview.requiredPostCreateReadbacks, queuePostCreateRequirements(x.f.c, x.f.topology));
  assert.equal(preview.requiredPostCreateReadbacks.length, 8);
  assert.equal(preview.whatIfSha256, digest(json(x.result)));
  assert.equal(verifyWhatIf(x.q.phase, x.result, x.preserved, { config: x.f.c, queueTopology: x.f.topology }), preview.whatIfSha256);
  assert.equal(json(x.raw), before);
  assert.equal(created(x.result)[0].after.properties.encryption.services, undefined);
  assert.equal(created(x.result)[1].after.properties, undefined);
  assert.equal(created(x.result)[2].after.properties, undefined);
});

test('CREATE omission allowlist rejects contradictory predictions and every unreviewed security omission', async t => {
  const cases = [
    ['shared key enabled', a => { a[0].after.properties.allowSharedKeyAccess = true; }],
    ['blob public access', a => { a[0].after.properties.allowBlobPublicAccess = true; }],
    ['TLS downgrade', a => { a[0].after.properties.minimumTlsVersion = 'TLS1_0'; }],
    ['insecure traffic', a => { a[0].after.properties.supportsHttpsTrafficOnly = false; }],
    ['OAuth default changed', a => { a[0].after.properties.defaultToOAuthAuthentication = false; }],
    ['cross tenant replication', a => { a[0].after.properties.allowCrossTenantReplication = true; }],
    ['local user enabled', a => { a[0].after.properties.isLocalUserEnabled = true; }],
    ['SFTP enabled', a => { a[0].after.properties.isSftpEnabled = true; }],
    ['hierarchical namespace', a => { a[0].after.properties.isHnsEnabled = true; }],
    ['network access changed', a => { a[0].after.properties.publicNetworkAccess = 'Disabled'; }],
    ['ACL bypass', a => { a[0].after.properties.networkAcls.bypass = 'AzureServices'; }],
    ['ACL action', a => { a[0].after.properties.networkAcls.defaultAction = 'Deny'; }],
    ['subnet', a => { a[0].after.properties.networkAcls.virtualNetworkRules = [{ id: 'unreviewed-subnet' }]; }],
    ['IP rule', a => { a[0].after.properties.networkAcls.ipRules = [{ value: '192.0.2.1' }]; }],
    ['resource access rule', a => { a[0].after.properties.networkAcls.resourceAccessRules = [{ resourceId: 'unreviewed' }]; }],
    ['ACL null instead of omitted', a => { a[0].after.properties.networkAcls.ipRules = null; }],
    ['encryption source', a => { a[0].after.properties.encryption.keySource = 'Microsoft.Keyvault'; }],
    ['queue encryption disabled', a => { a[0].after.properties.encryption.services = { queue: { enabled: false, keyType: 'Account' } }; }],
    ['service scoped queue key', a => { a[0].after.properties.encryption.services = { queue: { enabled: true, keyType: 'Service' } }; }],
    ['partial queue encryption', a => { a[0].after.properties.encryption.services = { queue: { enabled: true } }; }],
    ['empty present services', a => { a[0].after.properties.encryption.services = {}; }],
    ['null present services', a => { a[0].after.properties.encryption.services = null; }],
    ['unexpected encryption service', a => { a[0].after.properties.encryption.services = { queue: { enabled: true, keyType: 'Account' }, blob: { enabled: false } }; }],
    ['nonempty CORS', a => { a[1].after.properties = { cors: { corsRules: [{ allowedOrigins: ['*'] }] } }; }],
    ['null CORS properties', a => { a[1].after.properties = null; }],
    ['unknown partial CORS omission', a => { a[1].after.properties = {}; }],
    ['nonempty metadata', a => { a[2].after.properties = { metadata: { retention: 'forever' } }; }],
    ['null metadata', a => { a[2].after.properties = { metadata: null }; }],
    ['unknown partial metadata omission', a => { a[2].after.properties = {}; }],
    ['unknown extra account property', a => { a[0].after.properties.customDomain = { name: 'unreviewed' }; }],
    ['wrong SKU', a => { a[0].after.sku.name = 'Standard_GRS'; }],
    ['wrong type', a => { a[2].after.type = 'Microsoft.Storage/storageAccounts/blobServices/containers'; }],
    ['unknown top-level security property', a => { a[0].after.identity = { type: 'SystemAssigned' }; }],
  ];
  for (const name of ['allowSharedKeyAccess', 'allowBlobPublicAccess', 'minimumTlsVersion', 'supportsHttpsTrafficOnly',
    'publicNetworkAccess', 'defaultToOAuthAuthentication', 'allowCrossTenantReplication', 'isLocalUserEnabled', 'isSftpEnabled', 'isHnsEnabled', 'encryption', 'networkAcls']) {
    cases.push([`missing ${name}`, a => { delete a[0].after.properties[name]; }]);
  }
  cases.push(['missing encryption source', a => { delete a[0].after.properties.encryption.keySource; }]);
  cases.push(['missing ACL bypass', a => { delete a[0].after.properties.networkAcls.bypass; }]);
  cases.push(['missing ACL action', a => { delete a[0].after.properties.networkAcls.defaultAction; }]);
  for (const [name, mutate] of cases) await t.test(name, () => {
    const x = fixture(); mutate(created(x.result));
    assert.throws(() => x.review(x.result));
  });
});

test('fully returned requested fields are checked without manufacturing omitted values', () => {
  const x = fixture(), account = created(x.result)[0].after;
  account.properties.encryption.services = { queue: { enabled: true, keyType: 'Account' } };
  const preview = x.review(x.result);
  assert.equal(preview.requestedButNotPredicted.length, 5);
  assert.equal(preview.actualPostCreateReadbackVerified, false);
  assert.equal(preview.requiredPostCreateReadbacks.length, 8);
});

test('only new exact resources qualify for preview; error, pagination and phase/template bypasses fail closed', async t => {
  for (const [name, mutate] of [
    ['Modify', x => { created(x.result)[0].changeType = 'Modify'; }],
    ['NoChange', x => { created(x.result)[0].changeType = 'NoChange'; }],
    ['existing preimage', x => { created(x.result)[0].before = {}; }],
    ['unknown Create', x => x.result.changes.push({ resourceId: x.f.topology.ids.account + '-other', changeType: 'Create', after: {} })],
    ['unknown Ignore', x => x.result.changes.push({ resourceId: x.f.topology.ids.account + '-other', changeType: 'Ignore' })],
    ['duplicate resource', x => x.result.changes.push(x.result.changes[0])],
    ['missing resource', x => x.result.changes.pop()],
    ['root error', x => { x.result.error = { code: 'Denied' }; }],
    ['root pagination', x => { x.result.nextLink = 'more'; }],
    ['change error', x => { created(x.result)[0].error = { code: 'Denied' }; }],
    ['change pagination', x => { created(x.result)[0].nextLink = 'more'; }],
    ['failed status', x => { x.result.status = 'Failed'; }],
    ['removed postconditions', x => { x.q.phase.computedReadbacksRequired = []; }],
    ['changed template', x => { x.q.phase.template.resources[0].properties.allowSharedKeyAccess = true; }],
    ['parent scope', x => { x.q.phase.resources[0].id = x.f.r.stateGroup + '/other'; }],
  ]) await t.test(name, () => {
    const x = fixture(); mutate(x);
    assert.throws(() => x.review(x.result));
  });
});

test('preview uncertainty and mandatory readbacks are bound to phase, preflight and approval baseline', () => {
  const x = fixture(); x.bind();
  verifyQueuePreflight(x.f.c, x.q.phase, x.f.topology, x.q.proof);
  assert.equal(x.q.proof.computedValuesReviewed, false);
  assert.equal(x.q.approval.phaseSha256, digest(json(x.q.phase)));
  assert.equal(x.q.approval.baselineSha256, queuePreflightBaseline(x.q.proof));
  for (const mutate of [
    p => { p.queuePreview.omittedFieldsVerified = true; },
    p => { p.queuePreview.actualPostCreateReadbackVerified = true; },
    p => { p.queuePreview.requiredPostCreateReadbacks = []; },
    p => { p.queuePreview.requestedButNotPredicted[0].requested = {}; },
    p => { p.requiredPostCreateReadbacksSha256 = digest(json([])); },
    p => { p.computedValuesReviewed = true; },
    p => { p.validatedTemplateSha256 = digest('unreviewed template'); },
  ]) {
    const proof = structuredClone(x.q.proof); mutate(proof);
    proof.queuePreviewSha256 = digest(json(proof.queuePreview)); proof.baselineSha256 = queuePreflightBaseline(proof);
    assert.throws(() => verifyQueuePreflight(x.f.c, x.q.phase, x.f.topology, proof));
  }
  const refreshed = { ...x.q.proof, armValidationSha256: digest('new validated response with fresh correlation ID') };
  assert.equal(queuePreflightBaseline(refreshed), x.q.proof.baselineSha256);
});

test('actual GET verification never inherits preview omissions; incomplete postcreate data produces no qualified receipt', async t => {
  for (const field of ['services', 'queue-key-type', 'queue-disabled', 'key-source', 'shared-key',
    'ipRules', 'cors', 'metadata']) await t.test(field, async () => {
    const x = fixture(); x.bind();
    const q = x.f.topology.ids;
    if (field === 'services') delete x.q.resources[q.account].properties.encryption.services;
    if (field === 'queue-key-type') x.q.resources[q.account].properties.encryption.services.queue.keyType = 'Service';
    if (field === 'queue-disabled') x.q.resources[q.account].properties.encryption.services.queue.enabled = false;
    if (field === 'key-source') x.q.resources[q.account].properties.encryption.keySource = 'Microsoft.Keyvault';
    if (field === 'shared-key') x.q.resources[q.account].properties.allowSharedKeyAccess = true;
    if (field === 'ipRules') delete x.q.resources[q.account].properties.networkAcls.ipRules;
    if (field === 'cors') delete x.q.resources[q.service].properties;
    if (field === 'metadata') delete x.q.resources[q.queue].properties;
    assert.throws(() => queuePostCreateEvidence(x.f.c, x.q.phase, x.f.topology, x.q.resources));
    await assert.rejects(x.q.controller.execute(x.q.approval), /QUEUE_CHANGE_STOPPED_RESOURCES_PRESERVED/);
    assert.equal(x.q.record().receipt, null);
    assert.equal(x.q.record().journal.outcome, 'reconciliation-required');
  });
  const x = fixture(); x.bind();
  for (const change of created(x.result)) {
    const descriptor = x.q.phase.resources.find(v => v.id === change.resourceId);
    assert.throws(() => verifyQueueResource(x.f.c, x.f.topology, descriptor, change.after));
  }
  await x.q.controller.execute(x.q.approval);
  const record = x.q.record(); verifyQueueRecord(x.f.c, record);
  assert.equal(record.preflight.queuePreview.omittedFieldsVerified, false);
  assert.equal(record.receipt.postCreateReadbacks.complete, true);
  assert.equal(record.receipt.postCreateReadbacks.observations.length, 8);
  assert(record.receipt.postCreateReadbacks.observations.every(v => Object.hasOwn(v, 'actual')));
  const forged = structuredClone(record);
  forged.receipt.postCreateReadbacks.observations.pop();
  forged.journal.receiptSha256 = digest(json(forged.receipt));
  assert.throws(() => verifyQueueRecord(x.f.c, forged), /QUEUE_POSTCREATE_READBACK_REQUIRED/);
  const invalidValidation = structuredClone(record);
  invalidValidation.validation.properties.provisioningState = 'Failed';
  invalidValidation.preflight.armValidationSha256 = digest(json(invalidValidation.validation));
  assert.throws(() => verifyQueueRecord(x.f.c, invalidValidation), /QUEUE_RECORD_EXECUTION_INVALID/);
});

test('read-only validation preserves the full raw payload and returns explicit unqualified omission evidence', async t => {
  const x = fixture(), directory = `infrastructure/arm/telemetry/tests/.queue-preview-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  const context = whatIfRequestContext(x.f.c, x.q.phase), rawBytes = json(x.raw);
  const receipts = structuredClone(x.f.receipts);
  receipts.core.resources[x.f.r.environment] = { id: x.f.r.environment };
  let validations = 0, requests = 0;
  const result = await validateReadOnly(x.f.c, x.q.phase, receipts, directory, async (args, timeout) => {
    assert.deepEqual(args.slice(0, 3), ['deployment', 'group', 'validate']);
    assert(timeout <= 15000); validations++;
    return x.q.record().validation;
  }, undefined, { queueTopology: x.f.topology, request: async operation => {
    operation.beforeDispatch(); requests++;
    return { version: 1, statusCode: 200, headers: {}, body: x.raw, bodyParseError: false,
      contextSha256: context.contextSha256, responseFile: `whatif-response-${randomUUID()}.json`,
      step: 'what-if.start', verifiedRegion: x.f.c.location };
  } });
  assert.equal(validations, 1); assert.equal(requests, 1);
  assert.equal(result.queuePreview.requestedButNotPredicted.length, 6);
  assert.equal(result.queuePreview.actualPostCreateReadbackVerified, false);
  assert.equal(result.validatedTemplateSha256, digest(json(x.q.phase.template)));
  assert.equal(result.armValidationSha256, digest(json(x.q.record().validation)));
  assert.equal(await readFile(`${directory}/queue-storage-what-if-raw.json`, 'utf8'), rawBytes);
  assert.equal(json(x.raw), rawBytes);
});

test('queued validation rejects failed/error validation and error/paginated raw what-if before omission review', async t => {
  for (const mode of ['validation-failed', 'validation-error', 'validation-properties-error', 'validation-pagination',
    'whatif-error', 'whatif-properties-error', 'whatif-pagination', 'whatif-properties-pagination']) await t.test(mode, async t => {
    const x = fixture(), directory = `infrastructure/arm/telemetry/tests/.queue-preview-negative-${randomUUID()}`;
    await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
    const validation = structuredClone(x.q.record().validation), raw = structuredClone(x.raw);
    if (mode === 'validation-failed') validation.properties.provisioningState = 'Failed';
    if (mode === 'validation-error') validation.error = { code: 'Denied' };
    if (mode === 'validation-properties-error') validation.properties.error = { code: 'Denied' };
    if (mode === 'validation-pagination') validation.nextLink = 'more';
    if (mode === 'whatif-error') raw.error = { code: 'Denied' };
    if (mode === 'whatif-properties-error') raw.properties.error = { code: 'Denied' };
    if (mode === 'whatif-pagination') raw.nextLink = 'more';
    if (mode === 'whatif-properties-pagination') raw.properties.nextLink = 'more';
    const context = whatIfRequestContext(x.f.c, x.q.phase);
    await assert.rejects(validateReadOnly(x.f.c, x.q.phase, x.f.receipts, directory, async () => validation, undefined, {
      queueTopology: x.f.topology, request: async operation => {
        operation.beforeDispatch();
        return { version: 1, statusCode: 200, headers: {}, body: raw, bodyParseError: false,
          contextSha256: context.contextSha256, responseFile: `whatif-response-${randomUUID()}.json`,
          step: 'what-if.start', verifiedRegion: x.f.c.location };
      },
    }));
  });
});
