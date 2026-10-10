import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { digest, json, storageContract } from '../definition.mjs';
import { collectQueueAdoption, verifyQueueAdoptionOrigin, verifyQueueAdoptionRecord, verifyAdoptedQueueStorage } from '../queue-adoption.mjs';
import { queuePostCreateRequirements } from '../durable-queue.mjs';
import { collectQueueDefender, queueDefenderInventory, verifyQueueDefenderEvidence, verifyCurrentQueueDefender } from '../queue-defender.mjs';
import { knownResourceIds, readQueueRecords, sourceDigest, publishedSourceDigest } from '../controller.mjs';
import { queueAdoptionFixture, rebindAdoption } from './queue-adoption.fixture.mjs';
import { queueDefenderFixture, unitGuid, rehashActivity } from './queue-defender.fixture.mjs';

const hash = value => digest(json(value));
const f = await queueDefenderFixture();
const changedRecord = change => {
  const record = structuredClone(f.adoption);
  change(record);
  record.observation = structuredClone(record.proposal.observation);
  record.review.proposalSha256 = hash(record.proposal);
  return record;
};

test('exact v3 adoption retains history, independently reviewed destination AAD and no functional clearance', () => {
  const before = json(f.adoption), origin = json(f.origin);
  verifyQueueAdoptionOrigin(f.c, f.origin);
  verifyQueueAdoptionRecord(f.c, f.adoption);
  assert.equal(f.adoption.version, 3);
  assert.equal(f.proposal.version, 2);
  assert.equal(f.proposal.observation.version, 2);
  assert.equal(f.reads.length, 24);
  assert.equal(queuePostCreateRequirements(f.c, f.topology).length, 8);
  assert.deepEqual(queuePostCreateRequirements(f.c, f.topology)[2].expected, []);
  assert.deepEqual(f.origin.firstReadback.resources[f.topology.ids.account].properties.networkAcls.resourceAccessRules, []);
  assert.equal(f.proposal.observation.postconditions.version, 2);
  assert.equal(f.proposal.observation.postconditions.historicalRequirementsSha256,
    hash(queuePostCreateRequirements(f.c, f.topology)));
  assert.notEqual(f.evidence.snapshot.subscription.properties.destination.properties.azureActiveDirectoryTenantId, f.c.tenantId);
  assert.equal(f.evidence.assurance.scannerFunctionalityProven, false);
  assert.equal(f.evidence.assurance.enforcedNspCompatibility, 'unverified');
  assert.equal(f.evidence.assurance.uninterruptedTopicGenerationProven, false);
  assert.equal(json(f.adoption), before); assert.equal(json(f.origin), origin);
  assert(Object.values(f.adoption.authority).every(value => value === false));
});

test('old v2 record and original eight empty-ACL requirements are not broadened', async () => {
  const legacy = await queueAdoptionFixture(), record = structuredClone(legacy.adoption);
  record.proposal.observation.resources[legacy.topology.ids.account].properties.networkAcls.resourceAccessRules =
    structuredClone(f.proposal.observation.resources[f.topology.ids.account].properties.networkAcls.resourceAccessRules);
  rebindAdoption(record);
  assert.throws(() => verifyQueueAdoptionRecord(legacy.c, record), /QUEUE_/);
  assert.throws(() => verifyQueueAdoptionRecord(f.c, { ...f.adoption, version: 2 }), /CLOSED_/);
  verifyQueueAdoptionRecord(legacy.c, legacy.adoption);
});

test('rehashed new records cannot replace an independent exact preservation review', async t => {
  const cases = [
    ['missing review', record => { delete record.review.defender; }],
    ['legacy review', record => { record.review.version = 1; }],
    ['generic approval', record => { record.review.defender.action = 'allow-scanner'; }],
    ['instruction hash', record => { record.review.defender.userInstruction += ' changed'; }],
    ['new principal with same name', record => { record.proposal.defender.actors.topic.id = unitGuid(999); }],
    ['new Microsoft owner tenant', record => {
      record.proposal.defender.actors.topic.appOwnerOrganizationId = unitGuid(998);
      record.proposal.defender.actors.subscription.appOwnerOrganizationId = unitGuid(998);
    }],
    ['different destination AAD app', record => {
      record.proposal.defender.snapshot.subscription.properties.destination.properties.azureActiveDirectoryApplicationIdOrUri = unitGuid(997);
    }],
    ['different destination AAD tenant', record => {
      record.proposal.defender.snapshot.subscription.properties.destination.properties.azureActiveDirectoryTenantId = unitGuid(997);
    }],
    ['invented compatibility', record => { record.proposal.defender.assurance.enforcedNspCompatibility = 'compatible'; }],
    ['rewritten historical empty ACL', record => {
      record.origin.firstReadback.resources[f.topology.ids.account].properties.networkAcls.resourceAccessRules = [{ tenantId: f.c.tenantId }];
    }],
    ['changed source', record => { record.publication.sourceSha256 = digest('new source'); }],
    ['future provenance', record => { record.proposal.defender.activity.account.receipt.completedAt = '2099-01-01T00:00:00.000Z'; }],
    ['late review', record => { record.review.reviewedAt = record.review.expiresAt; }],
    ['unknown new authority', record => { record.authority.securityChanges = true; }],
  ];
  for (const [name, change] of cases) await t.test(name, () => {
    assert.throws(() => verifyQueueAdoptionRecord(f.c, changedRecord(change)), /(?:QUEUE_|CLOSED_)/);
  });
});

test('exact current integration rejects destinations, scopes, settings, filters, exports, identities and unknown fields', async t => {
  const cases = [
    ['settings disabled', v => { v.settings.properties.isEnabled = false; }],
    ['scan cap changed', v => { v.settings.properties.malwareScanning.onUpload.capGBPerMonth = 1; }],
    ['scan disabled', v => { v.settings.properties.malwareScanning.onUpload.isEnabled = false; }],
    ['discovery disabled', v => { v.settings.properties.sensitiveDataDiscovery.isEnabled = false; }],
    ['override', v => { v.settings.properties.overrideSubscriptionLevelSettings = true; }],
    ['results export', v => { v.settings.properties.malwareScanning.scanResultsEventGridTopicResourceId = f.topology.ids.account; }],
    ['scanner destination scope', v => { v.settings.properties.dataScannerResourceId = f.topology.ids.account; }],
    ['topic metric generation', v => { v.topic.properties.metricResourceId = unitGuid(999); }],
    ['foreign topic', v => { v.topic.id += '-other'; }],
    ['topic source', v => { v.topic.properties.source = f.topology.ids.service; }],
    ['topic type', v => { v.topic.properties.topicType = 'custom'; }],
    ['invented topic creation', v => { v.topic.systemData = { createdAt: new Date(f.at).toISOString() }; }],
    ['topic tags', v => { v.topic.tags = {}; }],
    ['extra topic', v => { v.topics.value.push(structuredClone(v.topic)); }],
    ['missing topic', v => { v.topics.value = []; }],
    ['extra subscription', v => { v.subscriptions.value.push(structuredClone(v.subscription)); }],
    ['missing subscription', v => { v.subscriptions.value = []; }],
    ['topic list pagination', v => { v.topics.nextLink = 'https://example.invalid/next'; }],
    ['subscription list pagination', v => { v.subscriptions.nextLink = ''; }],
    ['forged tenant', v => { v.subscription.properties.destination.properties.azureActiveDirectoryTenantId = f.c.tenantId; }],
    ['forged audience', v => { v.subscription.properties.destination.properties.azureActiveDirectoryApplicationIdOrUri = unitGuid(999); }],
    ['customer webhook', v => { v.subscription.properties.destination.properties.endpointBaseUrl = 'https://example.invalid/hook'; }],
    ['alternate region', v => { v.subscription.properties.destination.properties.endpointBaseUrl =
      v.subscription.properties.destination.properties.endpointBaseUrl.replace('australiaeast', 'westus'); }],
    ['URL query', v => { v.subscription.properties.destination.properties.endpointBaseUrl += '?target=other'; }],
    ['URL fragment', v => { v.subscription.properties.destination.properties.endpointBaseUrl += '#other'; }],
    ['URL credentials', v => { v.subscription.properties.destination.properties.endpointBaseUrl =
      v.subscription.properties.destination.properties.endpointBaseUrl.replace('https://', 'https://actor@'); }],
    ['URL encoded path', v => { v.subscription.properties.destination.properties.endpointBaseUrl =
      v.subscription.properties.destination.properties.endpointBaseUrl.replace('/EventCapture/', '/%45ventCapture/'); }],
    ['hidden endpoint', v => { v.subscription.properties.destination.properties.endpointUrl = 'https://example.invalid'; }],
    ['batch count', v => { v.subscription.properties.destination.properties.maxEventsPerBatch = 2; }],
    ['batch size', v => { v.subscription.properties.destination.properties.preferredBatchSizeInKilobytes = 1; }],
    ['event schema', v => { v.subscription.properties.eventDeliverySchema = 'CloudEventSchemaV1_0'; }],
    ['event types', v => { v.subscription.properties.filter.includedEventTypes.push('Microsoft.Storage.BlobDeleted'); }],
    ['filter operator', v => { v.subscription.properties.filter.advancedFilters[0].operatorType = 'StringNotContains'; }],
    ['filter values', v => { v.subscription.properties.filter.advancedFilters[0].values = ['*']; }],
    ['subject filter', v => { v.subscription.properties.filter.subjectBeginsWith = 'private'; }],
    ['unknown filter', v => { v.subscription.properties.filter.extra = false; }],
    ['deadletter', v => { v.subscription.properties.deadLetterDestination = {}; }],
    ['retry time', v => { v.subscription.properties.retryPolicy.eventTimeToLiveInMinutes = 1; }],
    ['retry count', v => { v.subscription.properties.retryPolicy.maxDeliveryAttempts = 31; }],
    ['topic diagnostics', v => { v.topicDiagnostics.value = [{ id: 'export' }]; }],
    ['settings diagnostics', v => { v.settingsDiagnostics.value = [{ id: 'export' }]; }],
    ['missing diagnostic proof', v => { delete v.settingsDiagnostics; }],
    ['scanner principal', v => { v.scanner.identity.principalId = unitGuid(999); }],
    ['scanner tenant', v => { v.scanner.identity.tenantId = unitGuid(999); }],
    ['role widened', v => { v.role.properties.permissions[0].actions.push('*'); }],
    ['role data access', v => { v.role.properties.permissions[0].dataActions.push('*'); }],
    ['role scoped elsewhere', v => { v.role.properties.assignableScopes = [f.topology.ids.account]; }],
    ['assignment scoped elsewhere', v => { v.assignment.properties.scope = f.topology.ids.account; }],
    ['assignment condition', v => { v.assignment.properties.condition = 'true'; }],
    ['assignment principal', v => { v.assignment.properties.principalId = unitGuid(999); }],
    ['unknown setting', v => { v.settings.properties.newBehavior = true; }],
  ];
  for (const [name, change] of cases) await t.test(name, () => {
    const snapshot = structuredClone(f.evidence.snapshot); change(snapshot);
    assert.throws(() => verifyCurrentQueueDefender(f.c, f.origin, f.evidence, snapshot), /(?:QUEUE_|CLOSED_)/);
  });
});

test('new storage branch still rejects extra rules, network bypass and changed creation identity', async t => {
  for (const [name, change] of [
    ['extra rule', p => { p.networkAcls.resourceAccessRules.push(structuredClone(p.networkAcls.resourceAccessRules[0])); }],
    ['wrong tenant', p => { p.networkAcls.resourceAccessRules[0].tenantId = unitGuid(999); }],
    ['wrong scanner', p => { p.networkAcls.resourceAccessRules[0].resourceId = f.topology.ids.queue; }],
    ['bypass', p => { p.networkAcls.bypass = 'AzureServices'; }],
    ['missing rule', p => { p.networkAcls.resourceAccessRules = []; }],
    ['creation precision', p => { p.creationTime = p.creationTime.replace('5000001', '5000002'); }],
    ['shared key', p => { p.allowSharedKeyAccess = true; }],
    ['public network', p => { p.publicNetworkAccess = 'Enabled'; }],
  ]) await t.test(name, () => {
    const resources = structuredClone(f.adoption.observation.resources); change(resources[f.topology.ids.account].properties);
    assert.throws(() => verifyAdoptedQueueStorage(f.c, f.adoption, resources, 'Disabled'), /QUEUE_/);
  });
});

test('complete scoped activity requires canonical page/projection binding, terminal bounds and exact attributed actors', async t => {
  const cases = [
    ['incomplete', e => { e.activity.account.receipt.paginationComplete = false; }],
    ['extra pages', e => { e.activity.account.receipt.maxPages = 9; }],
    ['extra bytes', e => { e.activity.account.receipt.maxBytes++; }],
    ['extra events', e => { e.activity.account.receipt.maxEvents++; }],
    ['unbounded request', e => { e.activity.account.receipt.requestDeadlineMs++; }],
    ['unbounded collection', e => { e.activity.account.receipt.collectionDeadlineMs++; }],
    ['wrong API', e => { e.activity.account.receipt.apiVersion = '2021-04-01'; }],
    ['wrong target', e => { e.activity.account.receipt.targetResource = f.topology.ids.queue; }],
    ['wrong filter', e => { e.activity.account.receipt.filter += ' or true'; }],
    ['foreign request', e => { e.activity.account.receipt.pages[0].request =
      e.activity.account.receipt.pages[0].request.replace('management.azure.com', 'example.invalid'); }],
    ['duplicate query', e => { e.activity.account.receipt.pages[0].request += '&api-version=2015-04-01'; }],
    ['wrong page digest', e => { e.activity.account.receipt.pages[0].canonicalResponseSha256 = digest('other'); }],
    ['missing page', e => { e.activity.account.pages = []; }],
    ['nonterminal', e => { rehashActivity(e.activity.account, page => { page.nextLink = 'https://example.invalid/next'; }); }],
    ['unknown resource scope', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].resourceId = f.topology.ids.queue; p.events[0].resourceId = f.topology.ids.queue;
    }); }],
    ['duplicate event', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value.push(structuredClone(page.value[0])); p.events.push(structuredClone(p.events[0]));
    }); }],
    ['cross-query event collision', e => { rehashActivity(e.activity.topic, (page, p) => {
      page.value[0].eventDataId = unitGuid(100); p.events[0].eventDataId = unitGuid(100);
    }); }],
    ['projection mismatch', e => { rehashActivity(e.activity.account, (_page, p) => { p.events[0].caller = unitGuid(999); }); }],
    ['rehashed forged caller', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].caller = unitGuid(999); p.events[0].caller = unitGuid(999);
    }); }],
    ['rehashed wrong tenant', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].claims['http://schemas.microsoft.com/identity/claims/tenantid'] = unitGuid(999); p.events[0].claimTenant = unitGuid(999);
    }); }],
    ['rehashed wrong scanner identity', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].claims.xms_mirid = f.topology.ids.account; p.events[0].claimResourceId = f.topology.ids.account;
    }); }],
    ['failed account write', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].status.value = 'Failed'; p.events[0].status.value = 'Failed';
    }); }],
    ['event after query', e => { rehashActivity(e.activity.account, (page, p) => {
      page.value[0].eventTimestamp = '2099-01-01T00:00:00.000Z'; p.events[0].eventTimestamp = page.value[0].eventTimestamp;
    }); }],
    ['new prior scanner baseline', e => { e.priorScannerAdoption.evidence.roleDefinition.properties.permissions[0].actions.push('*'); }],
    ['same-name third actor', e => { e.actors.subscription.id = unitGuid(999); }],
    ['same-name topic actor', e => { e.actors.topic.appId = unitGuid(999); }],
    ['claimed full wire', e => { e.assurance.fullWireAttestation = true; }],
  ];
  for (const [name, change] of cases) await t.test(name, () => {
    const evidence = structuredClone(f.evidence); change(evidence);
    assert.throws(() => verifyQueueDefenderEvidence(f.c, f.origin, evidence), /(?:QUEUE_|CLOSED_)/);
  });
});

test('bounded adoption and current reads fail closed at every extra descriptor with immutable inputs', async t => {
  const before = json(f.evidence);
  for (const [key, target] of Object.entries(f.requests)) await t.test(key, async () => {
    let returned = false;
    const io = { ...f.io, read: async (request, deadline) => {
      if (request.id === target.id) throw new Error('UNIT_READ_FAILED');
      return f.io.read(request, deadline);
    } };
    await assert.rejects(collectQueueAdoption(f.c, f.origin, io, f.evidence).then(value => { returned = true; return value; }), /UNIT_READ_FAILED/);
    assert.equal(returned, false);
    await assert.rejects(collectQueueDefender(f.c, f.origin, f.evidence, io, f.at + 120000), /UNIT_READ_FAILED/);
  });

  await t.test('known original and exact legacy activity scopes are retention only, not identity or current-state authority', () => {
    const evidence = structuredClone(f.evidence);
    rehashActivity(evidence.activity.account, (page, projection) => {
      for (const [index, target] of [f.topology.ids.service, f.topology.ids.queue,
        `${f.topology.ids.account}/providers/Microsoft.Security/advancedThreatProtectionSettings/current`].entries()) {
        const event = structuredClone(page.value[0]), projected = structuredClone(projection.events[0]);
        for (const value of [event, projected]) {
          value.resourceId = target; value.eventDataId = unitGuid(800 + index); value.caller = unitGuid(850);
          value.operationName.value = 'UNIT retained non-attribution operation';
        }
        page.value.push(event); projection.events.push(projected);
      }
    });
    verifyQueueDefenderEvidence(f.c, f.origin, evidence);
    assert.equal(Object.keys(queueDefenderInventory(f.c, f.origin, evidence)).length, 2);
    assert.equal(Object.values(f.requests).some(request => request.id.includes('advancedThreatProtectionSettings')), false);
    const foreign = structuredClone(evidence);
    rehashActivity(foreign.activity.account, (page, p) => {
      page.value.at(-1).resourceId += '/unreviewed';
      p.events.at(-1).resourceId += '/unreviewed';
    });
    assert.throws(() => verifyQueueDefenderEvidence(f.c, f.origin, foreign), /ACTIVITY_EVENT_INVALID/);
  });
  assert.equal(json(f.evidence), before);
  for (const value of [NaN, f.at, Infinity]) await assert.rejects(collectQueueDefender(f.c, f.origin, f.evidence, f.io, value), /READ_DEADLINE/);
  const tooDeep = structuredClone(f.evidence); let current = tooDeep;
  for (let index = 0; index < 40; index++) current = current.deep = {};
  assert.throws(() => verifyQueueDefenderEvidence(f.c, f.origin, tooDeep), /INPUT_LIMIT/);
  const cycle = structuredClone(f.evidence); cycle.self = cycle;
  assert.throws(() => verifyQueueDefenderEvidence(f.c, f.origin, cycle), /JSON_REQUIRED/);
  const oversized = structuredClone(f.evidence); oversized.large = 'x'.repeat(2 * 1024 * 1024 + 1);
  assert.throws(() => verifyQueueDefenderEvidence(f.c, f.origin, oversized), /INPUT_LIMIT/);
});

test('source and deadline changes during fresh new reads do not yield an adoption', async () => {
  for (const mode of ['source', 'deadline']) {
    const local = await queueDefenderFixture();
    const io = { ...local.io, read: async (request, deadline) => {
      const result = await local.io.read(request, deadline);
      if (request.id === local.requests.topic.id) {
        if (mode === 'source') local.setSource(digest('changed source'));
        else local.advance(120000);
      }
      return result;
    } };
    await assert.rejects(collectQueueAdoption(local.c, local.origin, io, local.evidence), /SOURCE_CHANGED|DEADLINE/);
  }
});

test('a caller cannot rewrite an in-flight preservation snapshot or use nonfinite clocks', async () => {
  const evidence = structuredClone(f.evidence);
  const io = { ...f.io, read: async (request, deadline) => {
    if (request.id === f.requests.topic.id) evidence.snapshot.topic.properties.metricResourceId = unitGuid(999);
    return f.io.read(request, deadline);
  } };
  const snapshot = await collectQueueDefender(f.c, f.origin, evidence, io, f.at + 120000);
  assert.equal(snapshot.topic.properties.metricResourceId, f.evidence.snapshot.topic.properties.metricResourceId);
  await assert.rejects(collectQueueDefender(f.c, f.origin, f.evidence, { ...f.io, now: () => NaN }, f.at + 120000), /READ_DEADLINE/);
});

test('inventory admits only the reviewed topic/subcontract and queue readback requires fresh integration', async () => {
  const records = { 'queue-storage': f.adoption };
  const inventory = queueDefenderInventory(f.c, f.origin, f.evidence);
  assert.deepEqual(Object.keys(inventory), [f.evidence.snapshot.topic.id, f.evidence.snapshot.subscription.id]);
  assert.deepEqual(new Set(knownResourceIds(f.c, { queueRecords: records })),
    new Set([...Object.keys(f.adoption.observation.resources), ...Object.keys(inventory)]));
  const arm = async (_method, id) => structuredClone(f.responses[id]);
  await assert.rejects(readQueueRecords(f.c, f.topology, records, arm), /READ_PORT_REQUIRED/);
  await readQueueRecords(f.c, f.topology, records, arm, f.io, f.at + 120000);
  await assert.rejects(readQueueRecords(f.c, f.topology, records, arm,
    { ...f.io, read: async () => { throw new Error('UNIT_BACKEND_DOWN'); } }, f.at + 120000), /UNIT_BACKEND_DOWN/);
});

test('published source includes Defender only for controllers importing it and preserves historical algorithms', async () => {
  const prefix = 'infrastructure/arm/telemetry/', contract = await storageContract();
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs', 'arm-whatif.py', 'receiver-upgrade.mjs',
    'durable-queue.mjs', 'effective-policy.mjs', 'queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs'];
  for (const modern of [false, true]) {
    const selected = [...names, ...(modern ? ['queue-defender.mjs'] : [])];
    const files = Object.fromEntries(selected.map(name => [prefix + name, `UNIT ${name}`]));
    files[prefix + 'controller.mjs'] = selected.slice(6).map(name => `import {} from './${name}';`).join('\n');
    files['assets/schemas/telemetry-event.schema.json'] = json(contract.schema);
    files['services/telemetry-ingest/schema/storage-columns.json'] = json(contract.columns);
    const expected = createHash('sha256');
    for (const name of selected) expected.update(name).update(files[prefix + name]);
    expected.update(json(contract));
    const run = async (_command, args) => {
      if (args[0] === 'merge-base') return { stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { stdout: Buffer.from(Object.hasOwn(files, args.at(-1)) ? args.at(-1) : '') };
      const path = args.at(-1).slice(41); assert(Object.hasOwn(files, path));
      return { stdout: Buffer.from(files[path]) };
    };
    assert.equal(await publishedSourceDigest('a'.repeat(40), run), expected.digest('hex'));
  }
  const current = createHash('sha256');
  for (const name of [...names, 'queue-defender.mjs']) current.update(name).update(await readFile(prefix + name));
  current.update(json(contract));
  assert.equal(await sourceDigest(), current.digest('hex'));
});
