import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';
import { digest, json, storageContract } from '../definition.mjs';
import { NSP_API, NSP_STORAGE_API, NSP_SETUP_PHASES, NSP_LIMITS, NSP_CHILD_TYPES, nspTopology, emptyNspEvidence, buildNspPhase,
  verifyNspObservation, verifyNspEvidence, verifyNspAdmission, verifyNspBilling, verifyNspPreview,
  verifyNspQueuePreflight, nspReadinessBinding, nspLineageHead, nspResourceInventory,
  verifyNspReconciliation, verifyNspPermissions, nspState, verifyNspTransition,
  nspTargetKey, nspIntentKey, nspIntentFence, verifyNspApiCatalog, nspConfigurationId } from '../nsp.mjs';
import { nspTransport, nspNextPage, nspReadRequests, checkNspReadOnly, collectNspObservation } from '../nsp-controller.mjs';
import { readNspHead, transport, sourceDigest, publishedSourceDigest, readBatch, nspReadIO,
  captureQueuedPublication, whatIfRequestContext, az, load, reserveNspIntent } from '../controller.mjs';
import { queueAdoptionFixture } from './queue-adoption.fixture.mjs';
import { adoptQueueStorage } from '../queue-adoption.mjs';
import { queueUpgradeFixture } from './durable-queue.fixture.mjs';
import { effectivePolicyFixture } from './effective-policy.fixture.mjs';
import { nspAdmissionFixture, nspPhaseFixture, nspBillingFixture } from './nsp.fixture.mjs';
const hash = value => digest(json(value));
const initial = async () => {
  const f = await queueAdoptionFixture(), evidence = emptyNspEvidence(nspTopology(f.c, f.topology, f.adoption));
  return { f, evidence, q: nspPhaseFixture(f, f.adoption, evidence, NSP_SETUP_PHASES[0]) };
};
const admission = async () => {
  const f = await queueAdoptionFixture(), evidence = await nspAdmissionFixture(f, f.adoption);
  return { f, evidence, receipt: evidence.records.at(-1).receipt };
};
const instance = (evidence, suffix) => ({ version: 1, id: `00000000-0000-4000-8000-0000000000${suffix}`,
  predecessorSha256: hash(evidence.records.at(-1)),
  previousInstanceIds: evidence.records.map(record => record.phase.instance?.id).filter(Boolean) });
function unitIntent(q) {
  return { version: 1, phaseSha256: hash(q.phase), approvalSha256: hash(q.approval), requestSha256: hash(q.phase.request),
    predecessorSha256: q.phase.predecessorSha256, intentAt: new Date(q.proof.startedAt).toISOString(),
    outcome: 'submission-possible', transportDispatchAttempted: false };
}
function memoryNspStore() {
  const files = new Map(), writes = [];
  const store = { read: async (_root, name) => structuredClone(files.get(name) ?? null),
    save: async (_root, name, value) => { writes.push(name); files.set(name, structuredClone(value)); },
    saveImmutable: async (_root, name, value) => {
      if (files.has(name)) throw new Error('UNIT_CREATE_EXCLUSIVE_FAILED');
      writes.push(name); files.set(name, structuredClone(value));
    } };
  return { store, files, writes };
}

test('NSP NotFound means absence only for the exact association or rule GET in the selected subscription', async () => {
  const { f, evidence } = await initial(), n = evidence.topology.ids;
  const absent = 'ERROR: Not Found({"error":{"code":"NotFound","message":"The requested NSP child does not exist."}})';
  const error = stderr => async () => { throw Object.assign(new Error('unit response'), { stderr }); };
  const args = (url, method = 'GET', subscription = f.c.subscriptionId) =>
    ['rest', '--method', method, '--url', url, '--subscription', subscription];
  for (const id of [n.association, n.rule]) {
    const url = `https://management.azure.com${id}?api-version=${NSP_API}`;
    assert.equal(await az(args(url), 10, error(absent)), null);
    for (const method of ['PUT', 'PATCH', 'POST', 'DELETE']) {
      await assert.rejects(az(args(url, method), 10, error(absent)), /ARM_OPERATION_FAILED/);
    }
    for (const badUrl of [
      url.replace('https:', 'http:'), url.replace(NSP_API, '2024-07-01'), url + '&extra=true',
      url.replace('queue-storage-v1', 'unreviewed-profile'),
      url.replace(`/resourceGroups/${f.c.namePrefix}-telemetry/`, '/resourceGroups/missionspec-other-telemetry/'),
      url.replace('/Microsoft.Network/', '/Microsoft.Storage/'),
      `https://management.azure.com${id.slice(0, id.lastIndexOf('/'))}?api-version=${NSP_API}`,
      `https://management.azure.com${n.perimeter}?api-version=${NSP_API}`,
      `https://management.azure.com${n.profile}?api-version=${NSP_API}`,
      `https://management.azure.com${n.account}?api-version=${NSP_API}`,
    ]) await assert.rejects(az(args(badUrl), 10, error(absent)), /ARM_OPERATION_FAILED/);
    await assert.rejects(az(args(url, 'GET', f.c.tenantId), 10, error(absent)), /ARM_OPERATION_FAILED/);
    await assert.rejects(az(args(url).slice(0, 5), 10, error(absent)), /ARM_OPERATION_FAILED/);
    for (const text of [
      'ERROR: Forbidden({"error":{"code":"NotFound"}})', 'ERROR: Unauthorized({"error":{"code":"NotFound"}})',
      'ERROR: Too Many Requests({"error":{"code":"NotFound"}})', 'ERROR: Not Found({"error":{"code":"AuthorizationFailed"}})',
      'ERROR: {"error":{"code":"NotFound"}}', 'ERROR: NotFound', '',
    ]) await assert.rejects(az(args(url), 10, error(text)), /ARM_OPERATION_FAILED/);
  }
});

test('empty-boundary readback composes NSP child 404s with complete empty inventories', async () => {
  const { f, evidence, q } = await initial(), n = evidence.topology.ids;
  const requests = nspReadRequests(evidence.topology), values = new Map(Object.entries(q.after.resources));
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues']) {
    values.set(requests[key].id, q.after[key]);
  }
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences']) {
    values.set(requests[key].id, { ...values.get(requests[key].id), nextLink: '' });
  }
  for (const [id, request] of Object.entries(requests.diagnostics)) values.set(request.id, q.after.diagnostics[id]);
  const retained = [], now = () => q.after.completedAt;
  const port = nspTransport(f.c, null, { now, retainRead: async (...value) => { retained.push(value); },
    invoke: (args, timeout) => az(args, timeout, async (_command, argv) => {
      assert.equal(argv[argv.indexOf('--method') + 1], 'GET');
      const id = new URL(argv[argv.indexOf('--url') + 1]).pathname;
      assert(values.has(id));
      if (values.get(id) === null) throw Object.assign(new Error('unit absent child'), {
        stderr: 'ERROR: Not Found({"error":{"code":"NotFound"}})',
      });
      return { stdout: json(values.get(id)) };
    }) });
  const collect = () => collectNspObservation(evidence.topology, { ...port, now, batch: readBatch }, now() + 120000);
  const observation = await collect();
  verifyNspObservation(f.c, evidence.topology, f.adoption, observation, 'empty-boundary');
  verifyNspTransition(f.c, evidence.topology, f.adoption, q.phase, q.proof.observation, observation);
  assert(retained.every(([, , outcome]) => outcome.complete));
  assert.equal(retained.find(([request]) => request.id === requests.profiles.id)[1][0].response.nextLink, '');
  assert.equal(observation.resources[n.association], null);
  assert.equal(observation.resources[n.rule], null);
  values.set(requests.rules.id, { value: [{ id: n.rule }] });
  assert.throws(() => verifyNspObservation(f.c, evidence.topology, f.adoption, {
    ...observation, rules: values.get(requests.rules.id),
  }, 'empty-boundary'), /NSP_INVENTORY_DRIFT/);
  values.set(requests.rules.id, null);
  await assert.rejects(collect(), /ARM_OPERATION_FAILED/);
});

test('four fixed setup phases lock existing storage and add one subscription rule last', async () => {
  const { f, evidence, receipt } = await admission();
  assert.deepEqual(evidence.records.map(v => v.phase.phase), NSP_SETUP_PHASES);
  assert.deepEqual(evidence.records.map(v => v.phase.request.method), ['PUT', 'PATCH', 'PUT', 'PUT']);
  assert.deepEqual(evidence.records.map(v => v.phase.resources.length), [2, 1, 1, 1]);
  assert.deepEqual(evidence.records[1].phase.request.body, { properties: { publicNetworkAccess: 'SecuredByPerimeter' } });
  const association = evidence.records[2].phase.resources[0].expected.properties;
  assert.equal(association.accessMode, 'Enforced');
  assert.equal(association.privateLinkResource.id, f.topology.ids.account);
  assert.deepEqual(evidence.records[3].phase.resources[0].expected.properties,
    { direction: 'Inbound', subscriptions: [{ id: f.r.sub }] });
  assert.equal(verifyNspAdmission(f.c, evidence, f.topology, f.adoption), receipt);
  assert.equal(receipt.runtimeQualified, false);
  assert.equal(receipt.queueGrantsAuthorized, false);
  assert.equal(receipt.ingestionEnabled, false);
  assert.equal(Object.keys(nspResourceInventory(f.c, evidence, f.adoption)).length, 7);
  assert.throws(() => verifyNspAdmission(f.c, { ...evidence, records: [] }, f.topology, f.adoption));
});

test('deny and reviewed fresh-instance readmit are separate non-replayed transitions', async () => {
  const { f, evidence } = await admission(), old = structuredClone(evidence);
  const deny = nspPhaseFixture(f, f.adoption, evidence, 'nsp-network-deny', instance(evidence, '91'));
  assert.equal(deny.phase.request.method, 'DELETE');
  assert.equal(deny.phase.request.id, evidence.topology.ids.rule);
  assert.equal(deny.phase.request.body, null);
  await deny.controller.execute(deny.approval);
  evidence.records.push(deny.record());
  assert.throws(() => verifyNspAdmission(f.c, evidence, f.topology, f.adoption), /CURRENT_ADMISSION/);
  assert.equal(verifyNspEvidence(f.c, evidence, f.topology, f.adoption).stage, 'deny-control-plane-converged');
  const head = nspLineageHead(evidence);
  await assert.rejects(readNspHead(old, null, async () => head), /CANONICAL_HEAD_CHANGED/);
  assert.throws(() => buildNspPhase(f.c, 'nsp-subscription-admission', f.topology, f.adoption, evidence));
  const readmit = nspPhaseFixture(f, f.adoption, evidence, 'nsp-subscription-readmit', instance(evidence, '92'));
  await readmit.controller.execute(readmit.approval);
  evidence.records.push(readmit.record());
  assert.equal(verifyNspAdmission(f.c, evidence, f.topology, f.adoption).stage, 'subscription-readmission-converged');
  assert.deepEqual(readmit.phase.resources, old.records.at(-1).phase.resources);
  assert.notEqual(readmit.phase.deploymentId, old.records.at(-1).phase.deploymentId);
  assert.throws(() => buildNspPhase(f.c, 'nsp-subscription-readmit', f.topology, f.adoption, evidence, instance(evidence, '93')));
  const full = { ...evidence, records: Array.from({ length: NSP_LIMITS.records - 1 },
    () => ({ receipt: { stage: 'deny-control-plane-converged' } })) };
  assert.throws(() => buildNspPhase(f.c, 'nsp-subscription-readmit', f.topology, f.adoption, full),
    /DENY_RESERVE_REQUIRED/);
});

test('readback requires documented types, complete versions, both provider copies and no alternative paths', async t => {
  const { f, evidence, receipt } = await admission(), n = evidence.topology.ids;
  const cases = [
    ['Learning', o => { o.resources[n.association].properties.accessMode = 'Learning'; }],
    ['Audit', o => { o.resources[n.association].properties.accessMode = 'Audit'; }],
    ['Transition prose', o => { o.resources[n.association].properties.accessMode = 'Transition'; }],
    ['Boolean issue indicator', o => { o.resources[n.association].properties.hasProvisioningIssues = false; }],
    ['missing issue indicator', o => { delete o.resources[n.association].properties.hasProvisioningIssues; }],
    ['queue not account association', o => { o.resources[n.association].properties.privateLinkResource.id = n.queue; }],
    ['Disabled does not revoke association', o => { o.resources[n.account].properties.publicNetworkAccess = 'Disabled'; }],
    ['trusted services', o => { o.resources[n.account].properties.networkAcls.bypass = 'AzureServices'; }],
    ['private endpoint', o => { o.privateEndpoints.value.push({ id: n.account + '/privateEndpointConnections/other' }); }],
    ['extra profile', o => { o.profiles.value.push({ id: n.perimeter + '/profiles/other' }); }],
    ['extra association', o => { o.associations.value.push({ id: n.perimeter + '/resourceAssociations/other' }); }],
    ['link', o => { o.links.value.push({ id: n.perimeter + '/links/other' }); }],
    ['link reference', o => { o.linkReferences.value.push({ id: n.perimeter + '/linkReferences/other' }); }],
    ['missing effective copy', o => { o.configuration = null; }],
    ['missing rule version', o => { delete o.configuration.properties.profile.accessRulesVersion; }],
    ['string Storage version', o => { o.configuration.properties.profile.accessRulesVersion = '1'; }],
    ['numeric Network version', o => { o.resources[n.profile].properties.accessRulesVersion = 1; }],
    ['unsafe Network version', o => { o.resources[n.profile].properties.accessRulesVersion = '9007199254740992'; }],
    ['stale copy version', o => { o.configuration.properties.profile.accessRulesVersion = 0; }],
    ['stale diagnostic version', o => { o.configuration.properties.profile.diagnosticSettingsVersion = 1; }],
    ['missing effective diagnostic categories', o => { delete o.configuration.properties.profile.enabledLogCategories; }],
    ['diagnostic export', o => { o.diagnostics[n.perimeter].value.push({ id: 'UNIT unwanted diagnostic' }); }],
    ['missing issues', o => { delete o.configuration.properties.provisioningIssues; }],
    ['propagation issue', o => { o.configuration.properties.provisioningIssues.push({ name: 'ConfigurationPropagationFailure' }); }],
    ['wrong subscription', o => { o.configuration.properties.profile.accessRules[0].properties.subscriptions[0].id += '0'; }],
    ['outbound rule', o => { o.configuration.properties.profile.accessRules[0].properties.direction = 'Outbound'; }],
    ['service tag selector', o => { o.configuration.properties.profile.accessRules[0].properties.serviceTags = ['AzureCloud']; }],
    ['rule missing from copy', o => { o.configuration.properties.profile.accessRules = []; }],
  ];
  for (const [name, mutate] of cases) await t.test(name, () => {
    const o = structuredClone(receipt.observation); mutate(o);
    assert.throws(() => verifyNspObservation(f.c, evidence.topology, f.adoption, o, receipt.stage));
  });
});

test('explicit disclosed billing uncertainty is not zero-price proof or a budget mutation', async () => {
  const { f, evidence } = await initial(), b = nspBillingFixture(f, evidence.topology);
  assert.equal(verifyNspBilling(f.c, evidence.topology, b.review, b.evidence, f.source, f.at).total, 359.37);
  assert.equal(b.review.cost.feeVerified, false);
  assert.equal(b.review.cost.planningLimit, 375);
  assert.equal(b.review.budgets.projectAmount, 350);
  for (const mutate of [
    b => { b.review.cost.zeroFeeProven = true; }, b => { b.review.cost.explicitUncertaintyAccepted = false; },
    b => { b.review.cost.total = 349.37; }, b => { b.review.cost.isHardCap = true; },
    b => { b.review.budgets.projectAmount = 375; }, b => { b.review.sourceSha256 = digest('changed'); },
    b => { b.evidence.acknowledgment.userInstruction = ''; },
    b => { b.evidence.priceSheet.httpStatus = 200; },
    b => { b.review.expiresAt = new Date(f.at).toISOString(); },
  ]) {
    const changed = structuredClone(b); mutate(changed);
    assert.throws(() => verifyNspBilling(f.c, evidence.topology, changed.review, changed.evidence, f.source, f.at));
  }
});

test('unbound preflight hashes and changed current admission never grant queue authority', async () => {
  const { f, evidence, receipt } = await admission(), at = Date.parse(receipt.completedAt);
  const context = { adoption: f.adoption, admission: evidence }, b = nspBillingFixture(f, evidence.topology, at);
  const observation = structuredClone(receipt.observation), head = nspLineageHead(evidence);
  const proof = { sourceSha256: f.source, networkObservation: observation, networkLineageHead: head,
    networkBillingReview: b.review, networkBillingEvidence: b.evidence,
    ...nspReadinessBinding(context, head, b.review, observation) };
  verifyNspQueuePreflight(f.c, context, proof, at);
  for (const mutate of [
    p => { p.networkLineageHead.recordSha256 = digest('stale'); },
    p => { p.networkPreflight.observationSha256 = digest('unretained'); },
    p => { p.networkBillingReview.cost.total = 349.37; },
    p => { delete p.networkObservation.configuration.properties.profile.accessRulesVersion; },
    p => { p.networkObservation.startedAt = at - 300001; },
  ]) {
    const changed = structuredClone(proof); mutate(changed);
    assert.throws(() => verifyNspQueuePreflight(f.c, context, changed, at));
  }
});

test('approval expiry, changed fixed requests, missing effective policy and final-guard races dispatch nothing', async t => {
  for (const kind of ['expiry', 'request', 'policy', 'source', 'final-race']) await t.test(kind, async () => {
    const { q, f } = await initial();
    if (kind === 'expiry') q.advance(NSP_LIMITS.reviewMs);
    if (kind === 'request') q.phase.request.body.properties.template.resources.push({ type: 'UNIT forbidden' });
    if (kind === 'policy') delete q.proof.effectivePolicyVersion;
    if (kind === 'source') q.io.sourceDigest = async () => digest('UNIT changed source');
    if (kind === 'final-race') q.io.write = async (_request, guard, current, deadline) => {
      await current(deadline); q.advance(NSP_LIMITS.reviewMs); guard();
    };
    await assert.rejects(q.controller.execute(q.approval));
    assert.equal(q.writes, 0);
    assert.notEqual(f.source, digest('UNIT changed source'));
  });
});

test('one ambiguous mutation quarantines intent and cannot be replayed', async () => {
  const { q } = await initial();
  let writes = 0;
  q.io.write = async (_request, guard, current, deadline) => {
    await current(deadline); guard(); writes++;
    throw new Error('UNIT_AMBIGUOUS_DISPATCH');
  };
  await assert.rejects(q.controller.execute(q.approval), /STOPPED_RESOURCES_PRESERVED/);
  assert.equal(q.record().journal.outcome, 'reconciliation-required');
  await assert.rejects(q.controller.execute(q.approval), /INTENT_REPLAY_FORBIDDEN/);
  assert.equal(writes, 1);
});

test('pending propagation uses bounded reads without mutation replay', async () => {
  const { q } = await initial(), observe = q.io.observe;
  let reads = 0;
  q.io.observe = async deadline => {
    reads++;
    const value = await observe(deadline);
    return reads === 1 ? { ...value, observation: q.proof.observation } : value;
  };
  await q.controller.execute(q.approval);
  assert.equal(q.writes, 1); assert.equal(reads, 2);
});

test('Network-only rule removal cannot qualify deny while Storage retains copied rule', async () => {
  const { f, evidence, receipt } = await admission();
  const q = nspPhaseFixture(f, f.adoption, evidence, 'nsp-network-deny', instance(evidence, '94'));
  q.after.configuration = structuredClone(receipt.observation.configuration);
  q.after.configurations.value = [q.after.configuration];
  await assert.rejects(q.controller.execute(q.approval), /STOPPED_RESOURCES_PRESERVED/);
  assert.equal(q.writes, 1);
  assert.equal(q.record().receipt, null);
});

test('NSP previews reject every mutation outside the exact fixed phase', async () => {
  const { q } = await initial();
  verifyNspPreview(q.phase, q.preview);
  for (const mutate of [
    p => { p.changes[0].changeType = 'Modify'; },
    p => { p.changes[0].after.tags.exemption = 'yes'; },
    p => { p.changes.push({ resourceId: 'UNIT unknown', changeType: 'Ignore' }); },
    p => { p.changes.push({ resourceId: 'UNIT extra', changeType: 'Create', after: {} }); },
    p => { p.changes[0].after.properties.accessMode = 'Learning'; },
    p => { p.nextLink = 'UNIT continuation'; },
  ]) {
    const changed = structuredClone(q.preview); mutate(changed);
    assert.throws(() => verifyNspPreview(q.phase, changed));
  }
});

test('empty NSP boundary preview permits only omitted empty properties and the exact child leaf name', async () => {
  const { q } = await initial();
  const preview = structuredClone(q.preview);
  for (const change of preview.changes) delete change.after.properties;
  preview.changes[1].after.name = q.phase.resources[1].id.split('/').at(-1);
  const before = structuredClone(preview);
  assert.equal(verifyNspPreview(q.phase, preview), hash(preview));
  assert.deepEqual(preview, before);
  for (const mutate of [
    p => { p.changes[0].after.properties = null; },
    p => { p.changes[1].after.properties = { accessRulesVersion: '0' }; },
    p => { p.changes[1].after.name = 'unreviewed-profile'; },
    p => { delete p.changes[0].after.location; },
    p => { delete p.changes[0].after.tags; },
  ]) {
    const changed = structuredClone(preview); mutate(changed);
    assert.throws(() => verifyNspPreview(q.phase, changed), /NSP_WHATIF_RESOURCE_CHANGED/);
  }
  const changedPhase = structuredClone(q.phase);
  changedPhase.resources[1].expected.properties = { unreviewed: true };
  assert.throws(() => verifyNspPreview(changedPhase, preview), /NSP_WHATIF_RESOURCE_CHANGED/);
  const { evidence } = await admission();
  for (const record of evidence.records.slice(2, 4)) {
    const omitted = structuredClone(record.preview);
    for (const change of omitted.changes) delete change.after.properties;
    assert.throws(() => verifyNspPreview(record.phase, omitted), /NSP_WHATIF_RESOURCE_CHANGED/);
  }
});

test('NSP preview version and dependency omissions never excuse contradictory returned values', async t => {
  const { q } = await initial(), raw = structuredClone(q.preview);
  verifyNspPreview(q.phase, q.preview);
  assert.deepEqual(q.preview, raw);
  const omitted = structuredClone(q.preview);
  for (const change of omitted.changes) {
    delete change.after.apiVersion; delete change.after.dependsOn;
  }
  const omittedRaw = structuredClone(omitted);
  verifyNspPreview(q.phase, omitted);
  assert.deepEqual(omitted, omittedRaw);
  for (const [name, mutate] of [
    ['wrong API version', p => { p.changes[0].after.apiVersion = NSP_STORAGE_API; }],
    ['null API version', p => { p.changes[0].after.apiVersion = null; }],
    ['undefined API version', p => { p.changes[0].after.apiVersion = undefined; }],
    ['foreign dependency', p => { p.changes[1].after.dependsOn = ['/subscriptions/foreign/resourceGroups/foreign']; }],
    ['missing requested dependency in present array', p => { p.changes[1].after.dependsOn = []; }],
    ['null dependencies', p => { p.changes[1].after.dependsOn = null; }],
    ['undefined dependencies', p => { p.changes[1].after.dependsOn = undefined; }],
    ['dependency where none was requested', p => { p.changes[0].after.dependsOn = [q.phase.resources[1].id]; }],
    ['empty dependency field where none was requested', p => { p.changes[0].after.dependsOn = []; }],
  ]) await t.test(name, () => {
    const changed = structuredClone(q.preview); mutate(changed);
    const before = structuredClone(changed);
    assert.throws(() => verifyNspPreview(q.phase, changed), /NSP_WHATIF_RESOURCE_CHANGED/);
    assert.deepEqual(changed, before);
  });
});

test('NSP explicit readback API versions must match their pinned provider', async t => {
  const { f, evidence, receipt } = await admission(), n = evidence.topology.ids;
  const setters = [
    ['perimeter', (o, api) => { o.resources[n.perimeter].apiVersion = api; }, NSP_API],
    ...[['profile', n.profile, 'profiles'], ['association', n.association, 'associations'], ['rule', n.rule, 'rules']]
      .map(([name, id, list]) => [name, (o, api) => {
        o.resources[id].apiVersion = api; o[list].value[0].apiVersion = api;
      }, NSP_API]),
    ['Storage effective configuration', (o, api) => {
      o.configuration.apiVersion = api; o.configurations.value[0].apiVersion = api;
    }, NSP_STORAGE_API],
  ];
  for (const [name, set, expected] of setters) await t.test(name, () => {
    const valid = structuredClone(receipt.observation); set(valid, expected);
    const original = structuredClone(valid);
    verifyNspObservation(f.c, evidence.topology, f.adoption, valid, receipt.stage);
    assert.deepEqual(valid, original);
    for (const api of [expected === NSP_API ? NSP_STORAGE_API : NSP_API, null, undefined]) {
      const changed = structuredClone(receipt.observation); set(changed, api);
      assert.throws(() => verifyNspObservation(f.c, evidence.topology, f.adoption, changed, receipt.stage),
        /NSP_RESOURCE_DRIFT/);
    }
  });
});

test('NSP ARM references and effective-config scopes accept casing only, preserving all other fields', async () => {
  const { f, evidence, receipt } = await admission(), n = evidence.topology.ids;
  const value = structuredClone(receipt.observation), prefix = `${n.account}/networkSecurityPerimeterConfigurations/`;
  value.resources[n.association].properties.privateLinkResource.id = n.account.toUpperCase();
  value.resources[n.association].properties.profile.id = n.profile.toUpperCase();
  value.configuration.id = prefix.toUpperCase() + value.configuration.id.slice(prefix.length);
  value.configuration.properties.networkSecurityPerimeter.id = n.perimeter.toUpperCase();
  const original = structuredClone(value);
  verifyNspObservation(f.c, evidence.topology, f.adoption, value, receipt.stage);
  assert.deepEqual(nspState(value), nspState(receipt.observation));
  assert.deepEqual(value, original);
  for (const mutate of [
    o => { o.resources[n.association].properties.privateLinkResource.id = n.queue; },
    o => { o.resources[n.association].properties.profile.id += '-other'; },
    o => { o.resources[n.association].properties.profile.extra = 'unreviewed'; },
    o => { o.resources[n.association].properties.accessMode = 'enforced'; },
    o => { o.configuration.id = o.configuration.id.replace(f.c.subscriptionId, f.c.tenantId); },
    o => { o.configuration.id = o.configuration.id.replace('/NETWORKSECURITYPERIMETERCONFIGURATIONS/', '/networkSecurityPerimeterConfigurations/%2e%2e/'); },
  ]) {
    const changed = structuredClone(value); mutate(changed);
    assert.throws(() => verifyNspObservation(f.c, evidence.topology, f.adoption, changed, receipt.stage));
  }
  for (const id of [prefix + '..', prefix + '%61', prefix + 'leaf/extra', prefix + 'leaf?api-version=other', prefix + 'leaf#fragment']) {
    assert.throws(() => nspConfigurationId(evidence.topology, id), /CONFIGURATION_SCOPE_CHANGED/);
  }
  const requests = nspReadRequests(evidence.topology), responses = new Map(Object.entries(value.resources));
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues']) {
    responses.set(requests[key].id, value[key]);
  }
  for (const [id, request] of Object.entries(requests.diagnostics)) responses.set(request.id, value.diagnostics[id]);
  value.configurations.value[0].id = value.configuration.id;
  responses.set(value.configuration.id, value.configuration);
  const calls = [], port = nspTransport(f.c, null, { now: () => value.completedAt, retainRead: async () => {},
    invoke: async args => {
      const url = new URL(args[args.indexOf('--url') + 1]); calls.push(url.pathname);
      assert(responses.has(url.pathname), url.pathname);
      return structuredClone(responses.get(url.pathname));
    } });
  const observed = await collectNspObservation(evidence.topology, { ...port, now: () => value.completedAt, batch: readBatch }, value.completedAt + 120000);
  verifyNspObservation(f.c, evidence.topology, f.adoption, observed, receipt.stage);
  assert(calls.includes(value.configuration.id));
});

test('captured NSP catalog structure permits only the three documented missing children as explicit uncertainty', async t => {
  const { q } = await initial(), provider = q.proof.providerCatalog, raw = structuredClone(provider);
  const proof = verifyNspApiCatalog(provider);
  assert.deepEqual(proof.omittedChildTypes, NSP_CHILD_TYPES);
  assert.equal(proof.rootApiAndRegionVerified, true);
  assert.equal(proof.omittedChildApisVerified, false);
  assert.equal(proof.nativeTemplateValidationRequired, true);
  assert.equal(proof.exactPostReadbacksRequired, true);
  assert.equal(proof.qualified, false);
  assert.equal(proof.providerSha256, hash(provider));
  assert.deepEqual(provider, raw);
  const complete = structuredClone(provider);
  complete.resourceTypes.push(...NSP_CHILD_TYPES.map(resourceType => ({ resourceType, apiVersions: [NSP_API] })));
  assert.deepEqual(verifyNspApiCatalog(complete).omittedChildTypes, []);
  for (const [name, mutate] of [
    ['unregistered', p => { p.registrationState = 'Registering'; }],
    ['foreign namespace', p => { p.namespace = 'Microsoft.Storage'; }],
    ['missing root', p => { p.resourceTypes = []; }],
    ['root wrong API', p => { p.resourceTypes[0].apiVersions = [NSP_STORAGE_API]; }],
    ['missing region', p => { p.resourceTypes[0].locations = []; }],
    ['duplicate root', p => { p.resourceTypes.push(structuredClone(p.resourceTypes[0])); }],
    ['returned child wrong API', p => { p.resourceTypes.push({ resourceType: NSP_CHILD_TYPES[0], apiVersions: [NSP_STORAGE_API] }); }],
    ['returned child missing API list', p => { p.resourceTypes.push({ resourceType: NSP_CHILD_TYPES[0] }); }],
    ['duplicate inconsistent child', p => {
      p.resourceTypes.push({ resourceType: NSP_CHILD_TYPES[0], apiVersions: [NSP_API] },
        { resourceType: NSP_CHILD_TYPES[0].toUpperCase(), apiVersions: [NSP_STORAGE_API] });
    }],
    ['foreign child classification', p => { p.resourceTypes.push({ resourceType: NSP_CHILD_TYPES[0], namespace: 'Microsoft.Storage', apiVersions: [NSP_API] }); }],
    ['qualified instead of relative type', p => { p.resourceTypes.push({ resourceType: 'Microsoft.Network/' + NSP_CHILD_TYPES[0], apiVersions: [NSP_API] }); }],
    ['malformed returned classification', p => { p.resourceTypes.push({ resourceType: NSP_CHILD_TYPES[0] + ' ', apiVersions: [NSP_API] }); }],
  ]) await t.test(name, () => {
    const changed = structuredClone(provider); mutate(changed);
    assert.throws(() => verifyNspApiCatalog(changed));
  });
});

test('NSP state normalization is limited to observation times and exact resource metadata paths', async () => {
  const { evidence, receipt } = await admission(), n = evidence.topology.ids;
  const raw = structuredClone(receipt.observation), allowed = structuredClone(raw);
  allowed.startedAt++; allowed.completedAt++;
  for (const value of Object.values(allowed.resources)) if (value) value.etag = 'UNIT mutable etag';
  allowed.resources[n.perimeter].systemData.lastModifiedAt = new Date(allowed.completedAt).toISOString();
  allowed.resources[n.perimeter].systemData.lastModifiedBy = 'UNIT reviewed operator';
  allowed.resources[n.perimeter].systemData.lastModifiedByType = 'User';
  allowed.resources[n.queue].properties.approximateMessageCount = 17;
  allowed.queues.value[0].properties.approximateMessageCount = 18;
  const untouched = structuredClone(allowed);
  assert.deepEqual(nspState(allowed), nspState(raw));
  assert.deepEqual(allowed, untouched);
  for (const key of ['etag', 'startedAt', 'completedAt', 'approximateMessageCount']) {
    const changed = structuredClone(raw);
    changed.resources[n.account].properties.primaryEndpoints[key] = 'UNIT unrelated state';
    assert.notDeepEqual(nspState(changed), nspState(raw), key);
  }
  const nested = structuredClone(raw), changedNested = structuredClone(raw);
  nested.resources[n.account].properties.primaryEndpoints.systemData = { lastModifiedBy: 'UNIT one' };
  changedNested.resources[n.account].properties.primaryEndpoints.systemData = { lastModifiedBy: 'UNIT two' };
  assert.notDeepEqual(nspState(nested), nspState(changedNested));
  const accountCount = structuredClone(raw);
  accountCount.resources[n.account].properties.approximateMessageCount = 19;
  assert.notDeepEqual(nspState(accountCount), nspState(raw));
  const wrapperTag = structuredClone(raw); wrapperTag.etag = 'UNIT not a resource etag';
  assert.notDeepEqual(nspState(wrapperTag), nspState(raw));
  for (const mutate of [
    o => { o.resources[n.perimeter].etag = {}; },
    o => { o.resources[n.perimeter].systemData.lastModifiedAt = 'invalid'; },
    o => { o.resources[n.perimeter].systemData.unreviewed = true; },
    o => { o.resources[n.queue].properties.approximateMessageCount = null; },
  ]) {
    const invalid = structuredClone(raw); mutate(invalid);
    assert.throws(() => nspState(invalid));
  }
});

test('NSP nested state drift cannot disappear from an otherwise authorized account transition', async () => {
  const { f, evidence } = await admission(), record = evidence.records[1];
  const before = record.preflight.observation, after = structuredClone(record.receipt.observation);
  after.resources[f.topology.ids.account].properties.primaryEndpoints.etag = 'UNIT unexpected endpoint field';
  const original = structuredClone(after);
  assert.throws(() => verifyNspTransition(f.c, evidence.topology, f.adoption, record.phase, before, after),
    /NSP_UNRELATED_STORAGE_CHANGE/);
  assert.deepEqual(after, original);
});

test('NSP pagination stays on exact list/API and rejects hostile cursors, loops and duplicate IDs', async () => {
  const { f, q, evidence } = await initial(), request = { id: `${evidence.topology.ids.perimeter}/profiles`, apiVersion: NSP_API, filter: null };
  const initialUrl = `https://management.azure.com${request.id}?api-version=${NSP_API}`;
  const next = initialUrl + '&$skiptoken=opaque%2Bpage';
  assert.equal(nspNextPage(initialUrl, next), next);
  for (const link of [
    next.replace('management.azure.com', 'example.invalid'), next.replace('/profiles?', '/links?'),
    next.replace(NSP_API, '2024-01-01'), next + '&extra=true', next + '#fragment',
    next.replace('https://', 'https://user:password@'), next + '&$skiptoken=duplicate',
  ]) assert.throws(() => nspNextPage(initialUrl, link));
  let calls = 0;
  const io = { now: () => f.at, retainRead: async () => {},
    invoke: async () => ++calls === 1 ? { value: [{ id: request.id + '/one' }], nextLink: next }
      : { value: [{ id: request.id + '/two' }] } };
  const port = nspTransport(f.c, q.phase, io);
  assert.equal((await port.read(request, f.at + 120000, true)).value.length, 2);
  assert.equal(calls, 2);
  io.invoke = async () => ({ value: [{ id: request.id + '/same' }], nextLink: next });
  await assert.rejects(port.read(request, f.at + 120000, true), /DUPLICATE|LOOP/);
});

test('empty terminal nextLink is accepted only for the five fixed Network inventories with raw pages retained', async () => {
  const { f, evidence } = await initial(), requests = nspReadRequests(evidence.topology), retained = [];
  let nextLink = '';
  const port = nspTransport(f.c, null, { now: () => f.at,
    retainRead: async (...args) => { retained.push(args); }, invoke: async () => ({ value: [], nextLink }) });
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences']) {
    assert.deepEqual(await port.read(requests[key], f.at + 120000, true), { value: [] });
    assert.equal(retained.at(-1)[1][0].response.nextLink, '');
    assert.equal(retained.at(-1)[2].complete, true);
  }
  for (const request of [
    requests.queues, requests.configurations, requests.privateEndpoints, Object.values(requests.diagnostics)[0],
    { ...requests.profiles, apiVersion: '2024-07-01' },
    { ...requests.profiles, filter: '$filter=anything' },
    { ...requests.profiles, id: requests.profiles.id + '/unknown' },
    { ...requests.profiles, id: requests.profiles.id.replace(f.c.namePrefix + '-queue-', 'missionspec-other-queue-') },
  ]) await assert.rejects(port.read(request, f.at + 120000, true), /NSP_LIST_INCOMPLETE/);
  for (const value of [false, 0, {}, ' ', 'https://example.invalid/next']) {
    nextLink = value;
    await assert.rejects(port.read(requests.profiles, f.at + 120000, true));
  }
});

test('canonical target and initial intent keys survive a second valid adoption or changed review context', async () => {
  const { f, q, evidence } = await initial(), at = f.at + 1000, source = digest('UNIT second adoption source');
  const proposal = structuredClone(f.proposal);
  proposal.sourceSha256 = source; proposal.observation.sourceSha256 = source;
  proposal.observation.startedAt = proposal.observation.completedAt = new Date(at).toISOString();
  const review = { ...f.review, sourceSha256: source, proposalSha256: hash(proposal),
    reviewedAt: new Date(at).toISOString(), expiresAt: new Date(at + 1800000).toISOString() };
  const secondAdoption = adoptQueueStorage(f.c, proposal, f.origin, review, { commitSha: 'f'.repeat(40), sourceSha256: source }, at);
  const second = emptyNspEvidence(nspTopology(f.c, f.topology, secondAdoption));
  assert.notEqual(hash(evidence.topology), hash(second.topology));
  assert.equal(nspTargetKey(evidence.topology), nspTargetKey(second.topology));
  const nextPhase = buildNspPhase(f.c, q.phase.phase, f.topology, secondAdoption, second);
  assert.equal(nspIntentKey(evidence, q.phase), nspIntentKey(second, nextPhase));
  const changedContext = { ...evidence, topology: { ...evidence.topology, configSha256: digest('UNIT changed context') } };
  assert.equal(nspTargetKey(changedContext.topology), nspTargetKey(evidence.topology));
  assert.equal(nspIntentKey(changedContext, q.phase), nspIntentKey(evidence, q.phase));
  assert.equal(nspTargetKey({ ids: {
    account: evidence.topology.ids.account.toUpperCase(), perimeter: evidence.topology.ids.perimeter.toUpperCase(),
  } }), nspTargetKey(evidence.topology));
  const m = memoryNspStore();
  const pending = await reserveNspIntent(evidence, q.phase, unitIntent(q), m.store);
  assert.deepEqual(await readNspHead(evidence, pending, m.store.read), nspLineageHead(evidence));
  await assert.rejects(readNspHead(second, null, m.store.read), /CANONICAL_HEAD_CHANGED/);
  await assert.rejects(readNspHead(changedContext, null, m.store.read), /CANONICAL_HEAD_CHANGED/);
  await assert.rejects(reserveNspIntent(second, nextPhase, unitIntent(q), m.store), /CANONICAL_HEAD_CHANGED/);
  assert.equal(m.writes.length, 3);
});

test('an archived initial intent fences a failed head write, including a new same-target wrapper', async () => {
  const { q, evidence } = await initial(), m = memoryNspStore(), save = m.store.save;
  m.store.save = async (root, name, value) => {
    if (name.startsWith('nsp-head-')) throw new Error('UNIT_HEAD_WRITE_FAILED');
    return save(root, name, value);
  };
  await assert.rejects(reserveNspIntent(evidence, q.phase, unitIntent(q), m.store), /HEAD_WRITE_FAILED/);
  assert.equal(m.writes.length, 2);
  assert(m.writes[0].startsWith('nsp-intent-fence-'));
  assert(m.files.has(`nsp-intent-${nspIntentKey(evidence, q.phase)}.json`));
  const rewrapped = { ...evidence, topology: { ...evidence.topology, adoptionSha256: digest('UNIT alternate adoption') } };
  await assert.rejects(readNspHead(rewrapped, null, m.store.read), /UNRESOLVED_GLOBAL_INTENT/);
  await assert.rejects(reserveNspIntent(rewrapped, q.phase, unitIntent(q), m.store), /UNRESOLVED_GLOBAL_INTENT/);
  m.files.delete(m.writes[0]);
  await assert.rejects(readNspHead(evidence, null, m.store.read), /UNRESOLVED_GLOBAL_INTENT/);
  assert.equal(m.writes.length, 2);
});

test('a lifecycle head-write failure cannot be escaped with a fresh instance nonce', async () => {
  const { f, evidence } = await admission(), last = evidence.records.at(-1), m = memoryNspStore();
  const reserved = { phase: last.phase, approvalSha256: hash(last.approval), journal: unitIntent({
    phase: last.phase, approval: last.approval, proof: { startedAt: Date.parse(last.journal.intentAt) },
  }) };
  const key = nspTargetKey(evidence.topology), fence = nspIntentFence(evidence, reserved);
  m.files.set(`nsp-head-${key}.json`, nspLineageHead(evidence));
  m.files.set(`nsp-intent-fence-${key}.json`, fence);
  m.files.set(`nsp-intent-${fence.intentKey}.json`, reserved);
  assert.deepEqual(await readNspHead(evidence, null, m.store.read), nspLineageHead(evidence));
  const deny = nspPhaseFixture(f, f.adoption, evidence, 'nsp-network-deny', instance(evidence, '91'));
  const save = m.store.save;
  m.store.save = async (root, name, value) => {
    if (name.startsWith('nsp-head-')) throw new Error('UNIT_HEAD_WRITE_FAILED');
    return save(root, name, value);
  };
  await assert.rejects(reserveNspIntent(evidence, deny.phase, unitIntent(deny), m.store), /HEAD_WRITE_FAILED/);
  const next = nspPhaseFixture(f, f.adoption, evidence, 'nsp-network-deny', instance(evidence, '92'));
  assert.notEqual(nspIntentKey(evidence, deny.phase), nspIntentKey(evidence, next.phase));
  await assert.rejects(reserveNspIntent(evidence, next.phase, unitIntent(next), m.store), /UNRESOLVED_GLOBAL_INTENT/);
  assert.equal(m.writes.length, 2);
});

test('failed or rejected reads retain bounded collected pages without partial success or leaked error text', async t => {
  const { f, evidence } = await initial();
  const request = { id: `${evidence.topology.ids.perimeter}/profiles`, apiVersion: NSP_API, filter: null };
  const url = `https://management.azure.com${request.id}?api-version=${NSP_API}`, next = url + '&$skiptoken=unit-next';
  for (const mode of ['second-page-error', 'rejected-next-link', 'late-response', 'oversized-page']) await t.test(mode, async () => {
    let now = f.at, calls = 0;
    const retained = [], failure = new Error('UNIT secret token must not enter safe error context');
    const first = { value: [{ id: request.id + '/one' }], nextLink: next };
    const io = { now: () => now, retainRead: async (...args) => { retained.push(structuredClone(args)); },
      invoke: async () => {
        calls++;
        if (mode === 'rejected-next-link') return { ...first, nextLink: 'https://foreign.invalid/not-allowed' };
        if (mode === 'late-response') { now += 120000; return { value: [] }; }
        if (calls === 1) return structuredClone(first);
        if (mode === 'oversized-page') return { value: [{ id: request.id + '/two', unreviewed: 'x'.repeat(NSP_LIMITS.bytes) }] };
        throw failure;
      } };
    const port = nspTransport(f.c, null, io);
    await assert.rejects(port.read(request, f.at + 120000, true),
      mode === 'second-page-error' ? error => error === failure : /NSP_/);
    assert.equal(retained.length, 1);
    const [retainedRequest, pages, outcome] = retained[0];
    assert.deepEqual(retainedRequest, request);
    assert.equal(pages.length, 1);
    assert.equal(outcome.complete, false);
    assert(outcome.bytes <= NSP_LIMITS.bytes);
    assert.equal(outcome.invocations, calls);
    assert(!JSON.stringify(outcome).includes('secret token'));
    if (mode === 'oversized-page') {
      assert(outcome.omittedPage.bytes > NSP_LIMITS.bytes);
      assert.match(outcome.omittedPage.sha256, /^[0-9a-f]{64}$/u);
    }
  });
});

test('read-evidence retention errors propagate exactly once on success and failure paths', async () => {
  const { f, evidence } = await initial(), request = { id: evidence.topology.ids.perimeter, apiVersion: NSP_API, filter: null };
  for (const readFails of [false, true]) {
    let retained = 0;
    const persistenceFailure = new Error('UNIT_RETENTION_FAILED');
    const port = nspTransport(f.c, null, { now: () => f.at,
      invoke: async () => { if (readFails) throw new Error('UNIT_READ_FAILED'); return { id: request.id }; },
      retainRead: async () => { retained++; throw persistenceFailure; } });
    await assert.rejects(port.read(request, f.at + 120000), error => error === persistenceFailure);
    assert.equal(retained, 1);
  }
});

test('dedicated transport requires exact bound phase and guards after body preparation', async () => {
  const { f, q, evidence } = await initial(), events = [];
  const io = { now: () => f.at, binding: { topology: f.topology, adoption: f.adoption, evidence },
    prepareBody: async () => { events.push('body'); return { path: '/unit/body.json' }; },
    removeBody: async () => { events.push('cleanup'); }, retainRead: async () => {},
    invoke: async args => { events.push(args[args.indexOf('--method') + 1]); return {}; } };
  const port = nspTransport(f.c, q.phase, io);
  await port.write(q.phase.request, () => { events.push('guard'); }, async () => { events.push('current'); }, f.at + 120000);
  assert.deepEqual(events, ['body', 'current', 'guard', 'PUT', 'cleanup']);
  await assert.rejects(port.write({ ...q.phase.request, method: 'DELETE' }, () => {}, async () => {}, f.at + 120000));
  const unbound = nspTransport(f.c, q.phase, { ...io, binding: null });
  await assert.rejects(unbound.write(q.phase.request, () => {}, async () => {}, f.at + 120000), /FIXED_REQUEST_REQUIRED/);
  for (const method of ['PATCH', 'DELETE']) {
    await assert.rejects(transport(f.c, q.phase, '/unit', async () => assert.fail('general transport dispatched'))(
      method, f.topology.ids.account, '2025-01-01', {}), /ARM_SCOPE_FORBIDDEN/);
  }
});

test('historical source digest survives NSP additions without requiring checkout history', async t => {
  const directory = path.resolve(`infrastructure/arm/telemetry/tests/.nsp-history-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true }));
  const execute = promisify(execFile);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull });
  const git = (...args) => execute('git', ['-c', `core.hooksPath=${os.devNull}`, '-c', 'commit.gpgsign=false',
    '-c', 'user.name=MissionSpec fixture', '-c', 'user.email=fixture@example.invalid', ...args],
  { cwd: directory, env, timeout: 10000, maxBuffer: 1_048_576 });
  const prefix = 'infrastructure/arm/telemetry/';
  const names = ['definition.mjs', 'policy.mjs', 'controller.mjs', 'arm-whatif.py',
    'receiver-upgrade.mjs', 'durable-queue.mjs', 'effective-policy.mjs'];
  const contract = await storageContract();
  const files = Object.fromEntries(names.map(name => [prefix + name, name === 'controller.mjs'
    ? "import {} from './effective-policy.mjs';\n" : `// Synthetic historical ${name}\n`]));
  files['assets/schemas/telemetry-event.schema.json'] = json(contract.schema);
  files['services/telemetry-ingest/schema/storage-columns.json'] = json(contract.columns);
  for (const [name, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(directory, name)), { recursive: true });
    await writeFile(path.join(directory, name), content);
  }
  await git('init', '--quiet');
  await git('add', '.');
  await git('commit', '--quiet', '-m', 'Synthetic pre-NSP history');
  const historicalCommit = (await git('rev-parse', 'HEAD')).stdout.trim();
  const expected = createHash('sha256');
  for (const name of names) expected.update(name).update(files[prefix + name]);
  expected.update(json(contract));
  for (const name of ['queue-adoption.mjs', 'nsp.mjs', 'nsp-controller.mjs', 'nsp-reconciliation.mjs']) {
    await writeFile(path.join(directory, prefix + name), `// Synthetic new ${name}\n`);
    files[prefix + 'controller.mjs'] += `import {} from './${name}';\n`;
  }
  await writeFile(path.join(directory, prefix + 'controller.mjs'), files[prefix + 'controller.mjs']);
  await git('add', '.');
  await git('commit', '--quiet', '-m', 'Synthetic NSP additions');
  const run = (command, args, options) => {
    assert.equal(command, 'git');
    return execute(command, args, { ...options, cwd: directory, env, timeout: 10000 });
  };
  assert.equal(await publishedSourceDigest(historicalCommit, run), expected.digest('hex'));
  assert.match(await sourceDigest(), /^[0-9a-f]{64}$/u);
});

test('real NSP preflight assembles exact GET evidence, permissions and effective policy before preview', async () => {
  const { f, evidence, q } = await initial(), requests = nspReadRequests(evidence.topology);
  const values = new Map(Object.entries(q.proof.observation.resources));
  for (const key of ['profiles', 'associations', 'rules', 'links', 'linkReferences', 'configurations', 'privateEndpoints', 'queues']) {
    values.set(requests[key].id, q.proof.observation[key]);
  }
  for (const [id, request] of Object.entries(requests.diagnostics)) values.set(request.id, q.proof.observation.diagnostics[id]);
  for (const [scope, value] of Object.entries(q.proof.permissions)) {
    values.set(`${scope}/providers/Microsoft.Authorization/permissions`, value.permissions);
    values.set(`${scope}/providers/Microsoft.Authorization/denyAssignments`, value.denies);
  }
  const policy = effectivePolicyFixture(), retained = [], calls = [];
  const foundationEntered = Promise.withResolvers(), releaseFoundation = Promise.withResolvers();
  let deny = false, saved = null, previewCalls = 0;
  const io = { now: () => q.proof.startedAt, sourceDigest: async () => f.source, batch: readBatch,
    foundation: async () => {
      foundationEntered.resolve();
      await releaseFoundation.promise;
      return { known: [], baselineSha256: q.proof.foundationBaselineSha256, binding: q.proof.foundationBinding,
        providerCatalog: q.proof.providerCatalog };
    },
    readHead: async () => nspLineageHead(evidence), allowPolicyRead: () => {},
    retainPolicy: async snapshot => { retained.push(snapshot); },
    read: async (request, deadline) => {
      calls.push(request);
      assert.equal(deadline, q.proof.startedAt + 120000);
      if (values.has(request.id)) return structuredClone(values.get(request.id));
      if (deny && policy.responses.has(request.id)) return structuredClone(policy.responses.get(request.id));
      if (request.id.endsWith('/policyAssignments') || request.id.endsWith('/policyExemptions')) return { value: [] };
      assert.fail('Unexpected unit preflight request: ' + request.id);
    },
    topologyReview: q.proof.topologyReview, billingReview: q.proof.networkBillingReview, billingEvidence: q.proof.networkBillingEvidence,
    preview: async () => { previewCalls++; return { validation: q.validation, preview: q.preview }; },
    saveCheck: async proof => { saved = proof; } };
  const checking = checkNspReadOnly(f.c, q.phase, f.topology, f.adoption, evidence, io);
  try {
    await foundationEntered.promise;
    await new Promise(resolve => setImmediate(resolve));
    assert(calls.some(request => request.id.endsWith('/policyAssignments')),
      'Independent effective-policy reads must not wait for foundation collection');
    assert.equal(previewCalls, 0, 'Preview still requires all prerequisite evidence');
    assert.equal(saved, null);
  } finally {
    releaseFoundation.resolve();
    await checking;
  }
  const proof = await checking;
  assert.equal(proof, saved);
  assert.equal(proof.effectivePolicyVersion, 1); assert.equal(proof.qualified, true);
  assert(calls.length > 10); assert.equal(previewCalls, 1); assert(retained.length);
  deny = true;
  policy.definition.properties.policyRule = {
    if: { field: 'type', equals: 'Microsoft.Network/networkSecurityPerimeters' }, then: { effect: 'deny' },
  };
  await assert.rejects(checkNspReadOnly(f.c, q.phase, f.topology, f.adoption, evidence, io), /EFFECTIVE_POLICY_CONFLICT/);
  assert.equal(previewCalls, 1);
  policy.definition.properties.policyRule.if = { field: 'Microsoft.Network/unsupportedAlias', equals: 'unverified' };
  await assert.rejects(checkNspReadOnly(f.c, q.phase, f.topology, f.adoption, evidence, io), /EFFECTIVE_POLICY_CONFLICT/);
});

test('scoped operator permission evidence never substitutes RG rights for subscription join', async () => {
  const { f, evidence } = await admission(), record = evidence.records.at(-1);
  verifyNspPermissions(f.c, record.phase, evidence.topology, record.preflight.permissions);
  const missing = structuredClone(record.preflight.permissions);
  delete missing[f.r.sub];
  assert.throws(() => verifyNspPermissions(f.c, record.phase, evidence.topology, missing));
  const denied = structuredClone(record.preflight.permissions);
  denied[f.r.sub].permissions.value[0].notActions = ['Microsoft.Resources/subscriptions/joinPerimeterRule/action'];
  assert.throws(() => verifyNspPermissions(f.c, record.phase, evidence.topology, denied));
  const conditional = structuredClone(record.preflight.permissions);
  conditional[f.r.sub].permissions.value[0].condition = 'UNIT unsupported condition';
  assert.throws(() => verifyNspPermissions(f.c, record.phase, evidence.topology, conditional), /CONDITIONAL_PERMISSION_UNVERIFIED/);
});

test('v6 reconciliation requires current retained dual-provider state and terminal head, not merely known IDs', async () => {
  const { f, evidence, receipt } = await admission(), at = Date.parse(receipt.completedAt);
  const head = nspLineageHead(evidence);
  assert.equal(Object.keys(verifyNspReconciliation(f.c, evidence, f.adoption, receipt.observation, head, at)).length, 7);
  const changed = structuredClone(receipt.observation);
  changed.configuration.properties.profile.accessRulesVersion++;
  assert.throws(() => verifyNspReconciliation(f.c, evidence, f.adoption, changed, head, at));
  assert.throws(() => verifyNspReconciliation(f.c, evidence, f.adoption, receipt.observation,
    { ...head, recordSha256: digest('old') }, at));
  const generation = structuredClone(receipt.observation);
  generation.resources[evidence.topology.ids.perimeter].systemData.createdAt = new Date(f.at - 1000).toISOString();
  assert.throws(() => verifyNspReconciliation(f.c, evidence, f.adoption, generation, head, at));
});

test('scope drift stops immediately instead of being retried as propagation', async () => {
  const { q, evidence } = await initial(), observe = q.io.observe;
  let reads = 0;
  q.io.observe = async deadline => {
    reads++;
    const value = await observe(deadline);
    value.observation.profiles.value.push({ id: evidence.topology.ids.perimeter + '/profiles/foreign' });
    return value;
  };
  await assert.rejects(q.controller.execute(q.approval), /STOPPED_RESOURCES_PRESERVED/);
  assert.equal(reads, 1); assert.equal(q.writes, 1);
});

test('queued reads consume the same absolute deadline before actual dispatch', async () => {
  const { f } = await initial(), directory = `infrastructure/arm/telemetry/tests/.nsp-io-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  let now = f.at, calls = 0;
  const releases = [];
  try {
    const io = nspReadIO(f.c, directory, async (_args, timeout) => {
      calls++; assert.equal(timeout, 20);
      return new Promise(resolve => { releases.push(() => resolve({ id: 'UNIT read' })); });
    }, { now: () => now });
    const request = { id: f.topology.ids.account, apiVersion: '2025-01-01', filter: null };
    const pending = Promise.allSettled(Array.from({ length: 5 }, () => io.read(request, f.at + 20)));
    assert.equal(calls, 4);
    now += 20;
    for (const release of releases) release();
    const result = await pending;
    assert.equal(calls, 4);
    assert(result.every(value => value.status === 'rejected'));
  } finally { await rm(directory, { recursive: true }); }
});

test('post-push capture remains read-only and retains outcome even without current network admission', async () => {
  const f = await queueUpgradeFixture(), directory = `infrastructure/arm/telemetry/tests/.nsp-publication-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  const calls = [];
  try {
    const observed = await captureQueuedPublication(f.c, f.candidate, directory, async args => {
      calls.push(args);
      return args[2] === 'show' ? JSON.parse(f.candidate.profile.manifestJson) : f.candidate.publication.manifests;
    }, { now: () => f.at });
    assert.equal(observed.networkAdmissionQualified, false);
    assert.equal(observed.qualified, false); assert.equal(observed.replayAuthorized, false);
    assert.equal(calls.length, 2);
    assert(calls.every(args => args[0] === 'acr' && args[1] === 'manifest' && ['show', 'list-metadata'].includes(args[2])));
    assert.deepEqual(await load(directory, 'queued-publication-observation.json'), observed);
  } finally { await rm(directory, { recursive: true }); }
});

test('first post-copy capture accepts a null publication receipt without relaxing published receipt validation', async () => {
  const f = await queueUpgradeFixture(), directory = `infrastructure/arm/telemetry/tests/.nsp-pending-publication-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  const pending = structuredClone(f.candidate); pending.publication = null;
  let calls = 0;
  const invoke = async args => {
    calls++;
    return args[2] === 'show' ? JSON.parse(pending.profile.manifestJson) : f.candidate.publication.manifests;
  };
  try {
    const observed = await captureQueuedPublication(f.c, pending, directory, invoke,
      { now: () => Date.parse(pending.review.expiresAt) + 100000 });
    assert.equal(calls, 2);
    assert.equal(observed.qualified, false); assert.equal(observed.replayAuthorized, false);
    assert.equal(pending.publication, null);
    const bad = structuredClone(pending); bad.publication = {};
    await assert.rejects(captureQueuedPublication(f.c, bad, directory, invoke));
    assert.equal(calls, 2);
  } finally { await rm(directory, { recursive: true }); }
});

test('JavaScript and Python what-if names agree for NSP setup and fresh readmit, never direct PATCH/DELETE', async () => {
  const { f, evidence } = await admission();
  const deny = nspPhaseFixture(f, f.adoption, evidence, 'nsp-network-deny', instance(evidence, '95'));
  await deny.controller.execute(deny.approval); evidence.records.push(deny.record());
  const restore = nspPhaseFixture(f, f.adoption, evidence, 'nsp-subscription-readmit', instance(evidence, '96'));
  const phases = [...evidence.records.map(value => value.phase), restore.phase];
  const puts = phases.filter(value => value.request.method === 'PUT'), contexts = puts.map(phase => whatIfRequestContext(f.c, phase));
  const script = "import importlib.util,json,sys; s=importlib.util.spec_from_file_location('unit_bridge','infrastructure/arm/telemetry/arm-whatif.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps([m.fixed_deployment_name(v) for v in json.loads(sys.argv[1])]))";
  const { stdout } = await promisify(execFile)('python3', ['-c', script, JSON.stringify(contexts)],
    { timeout: 15000, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.deepEqual(JSON.parse(stdout), puts.map(phase => phase.deploymentId.split('/').at(-1)));
  for (const phase of phases.filter(value => value.request.method !== 'PUT')) assert.throws(() => whatIfRequestContext(f.c, phase));
});

test('successful empty GET output cannot be fabricated as absent-resource evidence', async () => {
  const { f } = await initial();
  const args = ['rest', '--method', 'GET', '--url', `https://management.azure.com${f.topology.ids.account}?api-version=2025-01-01`];
  for (const stdout of ['', 'null', '\n']) await assert.rejects(az(args, 15000, async () => ({ stdout })), /ARM_OPERATION_FAILED/);
});
