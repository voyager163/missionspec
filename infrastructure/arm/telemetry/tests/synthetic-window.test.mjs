import assert from 'node:assert/strict';
import test from 'node:test';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { mkdir, readdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { buildPhase, digest, json, ids, ownerTags, RECEIVER_DIGEST, RECEIVER_COMMAND, SYNTHETIC_FIXTURES, SYNTHETIC_LIMITS, deploymentName, validateWindowInstance, firstReleaseCost } from '../definition.mjs';
import { admissionFlag, verifyWhatIf, resourceContext, verifySyntheticWindow, verifyWindowState, verifySyntheticRows, verifyWindowPredecessor, verifyWindowInstancePredecessor } from '../policy.mjs';
import { buildSyntheticWindow, SyntheticToggleController, SyntheticWindowDriver, latestRevisionReady, syntheticHttp, syntheticQuery, readSyntheticQuery, syntheticWindowIO, transport,
  verifyPublishedWindowPredecessor, whatIfRequestContext, reserveWindowInstance, verifyReceiverSource, emptyAcrReferrers } from '../controller.mjs';
import { candidateFixture } from './receiver-upgrade.fixture.mjs';
import { verifyReceiverProfile, verifyReceiverCandidate, verifyReceiverInventory, prepareReceiverPublication, RECEIVER_SOURCE_INPUTS, receiverDatabaseInstant,
  buildDisabledImagePhase, verifyDisabledImageRecord, ReceiverUpgradeController } from '../receiver-upgrade.mjs';

test('ACR referrer readback accepts the exact empty manifest envelope, never missing or incomplete inventory', () => {
  assert.deepEqual(emptyAcrReferrers({ manifests: [] }), []);
  assert.deepEqual(emptyAcrReferrers([]), []);
  for (const value of [undefined, null, {}, { manifests: null }, { manifests: [] , nextLink: 'next' },
    { manifests: [], error: 'unavailable' }, { manifests: [{ digest: 'sha256:' + 'a'.repeat(64) }] },
    [{ digest: 'sha256:' + 'a'.repeat(64) }]]) assert.throws(() => emptyAcrReferrers(value));
});

function fixture() {
  const origin = { policyBaselineSha256: digest('baseline') };
  const c = { version: 2, subscriptionId: '00000000-0000-4000-8000-000000000001',
    tenantId: '00000000-0000-4000-8000-000000000002', operatorPrincipalId: '00000000-0000-4000-8000-000000000003',
    runId: '00000000-0000-4000-8000-000000000004', namePrefix: 'missionspec-test', registryName: 'missionspectest',
    location: 'australiaeast', budgetEmail: 'operator@example.invalid', budgetStart: '2026-09-01T00:00:00Z', budgetEnd: '2027-09-01T00:00:00Z',
    queryPrincipalIds: ['00000000-0000-4000-8000-000000000003'], receiverDigest: RECEIVER_DIGEST,
    budget: { currency: 'USD', previousProjectAmount: 250, projectAmount: 350, stateAmount: 50, telemetryAmount: 300 },
    originSha256: digest(json(origin)), scannerAdoptionSha256: digest('scanner'), foundationBudgetsSha256: digest('budgets') };
  const r = ids(c), configSha256 = digest(json(c)), own = (id, properties) => ({ id, tags: ownerTags(c), properties });
  const core = { qualified: true, configSha256, resources: {
    [r.ingestIdentity]: own(r.ingestIdentity, { clientId: '00000000-0000-4000-8000-000000000005', principalId: '00000000-0000-4000-8000-000000000006', tenantId: c.tenantId }),
    [r.pullIdentity]: own(r.pullIdentity, { clientId: '00000000-0000-4000-8000-000000000007', principalId: '00000000-0000-4000-8000-000000000008', tenantId: c.tenantId }),
    [r.workspace]: own(r.workspace, { features: { disableLocalAuth: true, enableLogAccessUsingOnlyResourcePermissions: false } }),
    [r.registry]: own(r.registry, { loginServer: `${c.registryName}.azurecr.io` }),
  } };
  const receipts = { core, 'workspace-access': core,
    data: { qualified: true, configSha256, resources: { [r.dcr]: own(r.dcr, { immutableId: 'dcr-' + 'a'.repeat(32),
      endpoints: { logsIngestion: 'https://fixture.australiaeast-1.ingest.monitor.azure.com' } }) } },
    assignments: { qualified: true, configSha256 },
    publication: { qualified: true, digest: RECEIVER_DIGEST, registryId: r.registry, recentDigestCount: 1,
      configUser: '65532:65532', configSha256: 'sha256:46e59e2d089b1869fb3737444fa4d1cbf380bc5ed3eb27318508dafad4c08204',
      configSha256Inputs: configSha256, command: RECEIVER_COMMAND } };
  const descriptor = buildPhase(c, 'disabled-app', null, receipts).resources[0];
  let app = { ...structuredClone(descriptor.expected), id: r.app, systemData: { createdAt: '2026-09-23T00:00:00.000Z' } };
  Object.assign(app.properties, { provisioningState: 'Succeeded', runningStatus: 'Running', latestRevisionName: 'missionspec-test-ingest--initial',
    latestReadyRevisionName: 'missionspec-test-ingest--initial' });
  app.properties.configuration.ingress.fqdn = 'fixture.australiaeast.azurecontainerapps.io';
  for (const id of [r.ingestIdentity, r.pullIdentity]) {
    const { clientId, principalId } = core.resources[id].properties;
    app.identity.userAssignedIdentities[id] = { clientId, principalId };
  }
  receipts['disabled-app'] = { qualified: true, configSha256, resources: { [r.app]: structuredClone(app) } };
  const instance = { version: 1, id: '00000000-0000-4000-8000-000000000099', predecessorSha256: digest('predecessor'), previousInstanceIds: [] };
  const phases = Object.fromEntries(['synthetic-admission', 'synthetic-disable'].map(name => [name, buildPhase(c, name, null, receipts, undefined, undefined, instance)]));
  const whatifs = {
    'synthetic-admission': { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'Modify',
      before: structuredClone(app), after: { ...structuredClone(phases['synthetic-admission'].resources[0].expected), id: r.app } }] },
    'synthetic-disable': { status: 'Succeeded', changes: [{ resourceId: r.app, changeType: 'NoChange' }] },
  };
  const source = digest('test source'), window = buildSyntheticWindow(c, phases, receipts, origin, source, whatifs);
  let now = Date.parse('2026-09-23T09:00:00.000Z');
  const approvals = Object.fromEntries(Object.entries(phases).map(([name, phase]) => [name, {
    version: 2, windowInstanceId: instance.id, predecessorSha256: instance.predecessorSha256,
    action: `synthetic-window-${name}`, windowSha256: digest(json(window)), phaseSha256: digest(json(phase)),
    configSha256, sourceSha256: source, originSha256: window.originSha256, receiptsSha256: window.receiptsSha256,
    baselineSha256: window.baselineSha256, reviewedWhatIfSha256: window.phases[name].reviewedWhatIfSha256,
    transitionSha256: window.phases[name].transitionSha256, approvedAt: new Date(now - 60000).toISOString(),
    expiresAt: new Date(now + 3540000).toISOString(),
  }]));
  const context = resourceContext(c, receipts), journals = {}, savedReceipts = {}, deployments = {}, writes = [], http = [], queries = [];
  const timers = new Map(), incidents = [];
  const advance = ms => {
    const end = now + ms;
    for (;;) {
      const due = [...timers.entries()].filter(([, v]) => v.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      now = due[1].at; timers.delete(due[0]); due[1].callback();
    }
    now = end;
  };
  let run = null, oldReady = false, badRevisionTemplate = false, unknownEnable = false, mutateBody, readDelay = 0, cancelled = false;
  const observe = () => ({ app: structuredClone(app), context });
  const io = {
    now: () => now, sourceDigest: async () => source, sleep: async ms => { advance(ms); }, cancelled: () => cancelled,
    setTimer: (callback, ms) => { const id = {}; timers.set(id, { at: now + ms, callback }); return id; },
    clearTimer: id => timers.delete(id),
    recordWindowIncident: async value => { incidents.push({ ...structuredClone(value), persistedAt: now }); },
    loadJournal: async name => journals[name] ? structuredClone(journals[name]) : null,
    saveJournal: async (name, value) => { journals[name] = structuredClone(value); },
    saveReceipt: async (name, value) => { savedReceipts[name] = structuredClone(value); },
    check: async phase => ({ qualified: true, configSha256, phaseSha256: digest(json(phase)), sourceSha256: source,
      originSha256: window.originSha256, receiptsSha256: window.receiptsSha256, baselineSha256: window.baselineSha256,
      whatIfSha256: digest(`fresh ${phase.phase} ${admissionFlag(app)}`), transitionSha256: window.phases[phase.phase].transitionSha256,
      observedFlag: admissionFlag(app), startedAt: now, completedAt: now, cost: { withinEstimate: true, estimateLimit: 350, total: 301.66 } }),
    observe: async () => { advance(readDelay); return observe(); },
    deployment: async name => structuredClone(deployments[name] ?? null),
    arm: phase => async (method, id, api, body, filter, guard, roleGuard, toggleGuard) => {
      assert.equal(method, 'PUT'); assert.equal(id, phase.deploymentId); assert.equal(api, '2022-09-01');
      assert.equal(journals[phase.phase].outcome, 'submission-possible');
      if (mutateBody) mutateBody(phase);
      await toggleGuard(); guard(); writes.push(phase.phase);
      const previous = app.properties.latestReadyRevisionName;
      const properties = structuredClone(body.properties.template.resources[0].properties);
      app.properties = { ...app.properties, ...properties };
      app.properties.configuration.ingress.fqdn = window.anchorApp.properties.configuration.ingress.fqdn;
      app.properties.latestRevisionName = 'missionspec-test-ingest--' + (phase.transition.to === 'true' ? 'enabled' : 'disabled');
      app.properties.latestReadyRevisionName = oldReady && phase.transition.to === 'true' ? previous : app.properties.latestRevisionName;
      deployments[phase.phase] = { id, properties: { provisioningState: 'Succeeded', mode: 'Incremental', correlationId: phase.phase,
        timestamp: new Date(now).toISOString(), templateHash: digest(json(phase.template)) } };
      if (unknownEnable && phase.phase === 'synthetic-admission') throw new Error('UNKNOWN_TRANSPORT_RESULT');
      return {};
    },
    rollout: async () => {
      const value = observe(), name = app.properties.latestRevisionName;
      const template = structuredClone(app.properties.template);
      template.revisionSuffix = null; template.scale.cooldownPeriod = null; template.scale.pollingInterval = null;
      if (badRevisionTemplate && admissionFlag(app) === 'true') template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'false';
      return { ...value, revisions: { value: [{ id: r.app + '/revisions/' + name, name,
        properties: { active: true, provisioningState: 'Provisioned', runningState: 'RunningAtMaxScale',
          healthState: 'Healthy', replicas: 1, trafficWeight: 100, template } }] } };
    },
    privacy: async () => {},
    loadRun: async () => run,
    saveRun: async value => { run = structuredClone(value); },
    http: async (method, path, fixture, guard) => {
      guard?.();
      advance(20); http.push({ method, path, fixture, flag: admissionFlag(app) });
      return { status: method === 'POST' && admissionFlag(app) === 'false' ? 503 : 204,
        bodyBytes: 0, tlsVerified: true, errorCode: null, durationMs: 20, headerPolicy: { noStore: true } };
    },
    query: async (start, end, guard, deadline, onDispatch) => {
      guard?.();
      onDispatch?.();
      queries.push({ start, end });
      return queryRows(SYNTHETIC_FIXTURES, new Date(Date.parse(start) + 1).toISOString());
    },
  };
  const toggle = new SyntheticToggleController(c, phases, window, approvals, io);
  return { c, r, receipts, phases, window, approvals, source, context, whatifs, instance, io, toggle, journals, savedReceipts, deployments, writes, http, queries, incidents, timers,
    get app() { return app; }, get run() { return run; }, get now() { return now; }, advance,
    set oldReady(v) { oldReady = v; }, set badRevisionTemplate(v) { badRevisionTemplate = v; },
    set unknownEnable(v) { unknownEnable = v; }, set mutateBody(v) { mutateBody = v; },
    set readDelay(v) { readDelay = v; }, set cancelled(v) { cancelled = v; } };
}
function queryRows(fixtures, time) {
  const names = ['TimeGenerated', 'schemaVersion', 'event', 'operation', 'cliVersion', 'outcome', 'host', 'os', 'durationBucket'];
  return { tables: [{ columns: names.map((name, i) => ({ name, type: i === 0 ? 'datetime' : i === 1 ? 'long' : 'string' })),
    rows: fixtures.map(v => [time, ...names.slice(1).map(name => v[name])]) }] };
}

test('toggle what-if canonicalizes reviewed representations only and rejects all effective configuration drift', () => {
  const f = fixture(), p = f.phases['synthetic-admission'], context = { config: f.c, ...f.context, app: f.app };
  const w = structuredClone(f.whatifs['synthetic-admission']);
  for (const side of ['before', 'after']) {
    const value = w.changes[0][side];
    value.identity.userAssignedIdentities = Object.fromEntries(Object.keys(value.identity.userAssignedIdentities).map(id => [id.toLowerCase(), {}]));
    delete value.properties.configuration.ingress.fqdn;
    value.properties.configuration.identitySettings.forEach(v => { v.identity = v.identity.toLowerCase(); });
  }
  w.changes[0].before.properties.configuration.ingress.exposedPort = 0;
  w.changes[0].before.properties.configuration.ingress.transport = 'Http';
  w.changes[0].before.location = 'Australia East';
  w.changes[0].before.properties.template.scale.cooldownPeriod = 300;
  w.changes[0].before.properties.template.scale.pollingInterval = 30;
  w.changes[0].before.properties.template.containers[0].probes.reverse();
  delete w.changes[0].after.properties.configuration.ingress.exposedPort;
  delete w.changes[0].after.properties.template.scale.cooldownPeriod;
  delete w.changes[0].after.properties.template.scale.pollingInterval;
  verifyWhatIf(p, w, [], context);
  for (const mutate of [
    v => { v.properties.template.containers[0].image = 'other'; },
    v => { v.location = 'westus'; },
    v => { v.properties.template.containers[0].resources.cpu = 0.5; },
    v => { v.properties.template.containers[0].resources.ephemeralStorage = '4Gi'; },
    v => { v.properties.template.containers[0].command = ['sh']; },
    v => { v.properties.template.containers[0].volumeMounts = [{ mountPath: '/data' }]; },
    v => { v.properties.template.containers[0].securityContext = {}; },
    v => { v.properties.template.volumes = [{ name: 'extra' }]; },
    v => { v.properties.configuration.ingress.targetPort = 9090; },
    v => { v.properties.configuration.ingress.exposedPort = 443; },
    v => { v.properties.configuration.ingress.transport = 'HTTP'; },
    v => { v.properties.configuration.identitySettings[1].lifecycle = 'All'; },
    v => { v.properties.configuration.registries[0].identity = f.r.ingestIdentity; },
    v => { v.properties.template.containers[0].probes.push(v.properties.template.containers[0].probes[0]); },
    v => { v.properties.template.containers[0].probes[0].periodSeconds = 99; },
    v => { v.properties.template.containers[0].probes[0].httpGet.httpHeaders = [{ name: 'x', value: 'y' }]; },
    v => { v.properties.template.scale.cooldownPeriod = 301; },
    v => { v.properties.template.scale.pollingInterval = 31; },
    v => { v.properties.configuration.unknown = null; },
    v => { v.tags.extra = 'changed'; },
  ]) for (const side of ['before', 'after']) {
    const bad = structuredClone(w); mutate(bad.changes[0][side]);
    assert.throws(() => verifyWhatIf(p, bad, [], context));
  }
  assert.throws(() => verifyWhatIf(p, w));
});

test('fixed disable has no future computed receipt dependency and both scopes need separate exact approvals', () => {
  const f = fixture();
  assert.deepEqual(f.phases['synthetic-disable'].transition.from, ['true', 'false']);
  assert.equal(f.phases['synthetic-disable'].transition.to, 'false');
  verifySyntheticWindow(f.c, f.phases, f.window, f.approvals, f.source, f.now, true);
  for (const mutate of [
    a => { delete a['synthetic-disable']; }, a => { a['synthetic-disable'].windowSha256 = digest('other'); },
    a => { a['synthetic-disable'].phaseSha256 = digest('other'); }, a => { a['synthetic-disable'].transitionSha256 = digest('other'); },
    a => { a['synthetic-disable'].reviewedWhatIfSha256 = digest('future fiction'); },
    a => { a['synthetic-admission'].expiresAt = new Date(f.now).toISOString(); },
    a => { a['synthetic-disable'].expiresAt = new Date(f.now + 700000).toISOString(); },
    a => { a['synthetic-admission'].force = true; },
  ]) { const a = structuredClone(f.approvals); mutate(a); assert.throws(() => verifySyntheticWindow(f.c, f.phases, f.window, a, f.source, f.now, true)); }
});

test('enable then disable changes only the flag, preserves intent history and proves the latest desired revision ready', async () => {
  const f = fixture();
  const enabled = await f.toggle.execute('synthetic-admission');
  assert.equal(enabled.qualified, true); assert.equal(admissionFlag(f.app), 'true');
  const oldIntent = json(f.journals['synthetic-admission']);
  const disabled = await f.toggle.execute('synthetic-disable');
  assert.equal(disabled.qualified, true); assert.equal(admissionFlag(f.app), 'false');
  assert.deepEqual(f.writes, ['synthetic-admission', 'synthetic-disable']);
  assert.equal(json(f.journals['synthetic-admission']), oldIntent);
  await assert.rejects(f.toggle.execute('synthetic-admission'), /EXISTING_TOGGLE_INTENT/);
  await assert.rejects(f.toggle.execute('synthetic-disable'), /EXISTING_TOGGLE_INTENT/);
});

test('old healthy revision and wrong revision template are not rollout readiness', async () => {
  for (const mode of ['oldReady', 'badRevisionTemplate']) {
    const f = fixture(); f[mode] = true;
    await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
    assert.equal(f.savedReceipts['synthetic-admission'], undefined);
    assert.equal(f.journals['synthetic-admission'].outcome, 'reconciliation-required');
    const disabled = await f.toggle.execute('synthetic-disable');
    assert.equal(disabled.qualified, true); assert.equal(admissionFlag(f.app), 'false');
    assert.equal(f.http.length, 0);
  }
});

test('uncertain enable can be disabled after its recorded deployment settles, never resubmitted', async () => {
  const f = fixture(); f.unknownEnable = true;
  await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
  assert.equal(admissionFlag(f.app), 'true');
  const disabled = await f.toggle.execute('synthetic-disable');
  assert.equal(disabled.qualified, true);
  assert.deepEqual(f.writes, ['synthetic-admission', 'synthetic-disable']);
  const unresolved = fixture(); unresolved.unknownEnable = true;
  await assert.rejects(unresolved.toggle.execute('synthetic-admission'));
  delete unresolved.deployments['synthetic-admission'];
  await assert.rejects(unresolved.toggle.execute('synthetic-disable'), /ENABLE_SUBMISSION_UNRESOLVED_NO_REPLAY/);
  assert.deepEqual(unresolved.writes, ['synthetic-admission']);
  assert.equal(unresolved.savedReceipts['synthetic-disable'], undefined);
  unresolved.app.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'false';
  await assert.rejects(unresolved.toggle.execute('synthetic-disable'), /ENABLE_SUBMISSION_UNRESOLVED_NO_REPLAY/);
  assert.equal(unresolved.savedReceipts['synthetic-disable'], undefined, 'An in-flight enable could still turn a currently false app true.');
  const partial = fixture(); partial.unknownEnable = true;
  await assert.rejects(partial.toggle.execute('synthetic-admission'));
  partial.deployments['synthetic-admission'].properties.provisioningState = 'Failed';
  await partial.toggle.execute('synthetic-disable');
  assert.equal(admissionFlag(partial.app), 'false');
});

test('already false is read-only terminal qualification even after expiry, but true cannot use an expired grant', async () => {
  const f = fixture(); f.advance(3600000);
  const receipt = await f.toggle.execute('synthetic-disable');
  assert.equal(receipt.noCloudWrite, true); assert.equal(receipt.deployment, null);
  assert.equal(f.journals['synthetic-disable'].outcome, 'read-only-already-disabled');
  assert.deepEqual(f.writes, []);
  const enabled = fixture(); await enabled.toggle.execute('synthetic-admission'); enabled.advance(3600000);
  await assert.rejects(enabled.toggle.execute('synthetic-disable'), /WINDOW_APPROVAL_EXPIRED_OR_INVALID/);
  assert.equal(admissionFlag(enabled.app), 'true'); assert.equal(enabled.savedReceipts['synthetic-disable'], undefined);
});

test('post-preflight/body drift or expiry cannot dispatch a toggle and does not erase its intent', async () => {
  for (const mode of ['expiry', 'drift', 'stale']) {
    const f = fixture();
    f.mutateBody = () => {
      if (mode === 'expiry') f.advance(3600000);
      else if (mode === 'stale') f.advance(300001);
      else f.app.properties.template.containers[0].resources.cpu = 0.5;
    };
    await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
    assert.deepEqual(f.writes, []);
    assert.equal(f.journals['synthetic-admission'].transportDispatchAttempted, false);
    assert.equal(f.journals['synthetic-admission'].outcome, 'reconciliation-required');
  }
});

test('enabled state without a matching original approval and intent is not an adopted baseline', () => {
  const f = fixture(); f.app.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true';
  assert.throws(() => verifyWindowState(f.c, f.phases, f.window, f.approvals, {}, f.app, f.context, f.source), /UNREVIEWED_ENABLED_APP_STATE/);
  const fake = { 'synthetic-admission': { phase: 'synthetic-admission', outcome: 'submission-possible',
    phaseSha256: digest(json(f.phases['synthetic-admission'])), approvalSha256: digest(json(f.approvals['synthetic-admission'])),
    windowInstanceId: f.instance.id, predecessorSha256: f.instance.predecessorSha256,
    windowSha256: digest(json(f.window)), intentAt: f.approvals['synthetic-admission'].expiresAt } };
  assert.throws(() => verifyWindowState(f.c, f.phases, f.window, f.approvals, fake, f.app, f.context, f.source), /WINDOW_APPROVAL_EXPIRED/);
  fake['synthetic-admission'].intentAt = f.approvals['synthetic-admission'].approvedAt;
  fake['synthetic-admission'].approvalSha256 = digest('different approval');
  assert.throws(() => verifyWindowState(f.c, f.phases, f.window, f.approvals, fake, f.app, f.context, f.source), /WINDOW_INTENT_BINDING_CHANGED/);
  fake['synthetic-admission'].approvalSha256 = digest(json(f.approvals['synthetic-admission']));
  fake['synthetic-admission'].transportDispatchAttempted = false;
  assert.throws(() => verifyWindowState(f.c, f.phases, f.window, f.approvals, fake, f.app, f.context, f.source), /UNREVIEWED_ENABLED_APP_STATE/);
});

test('staged success uses exactly two events and finishes disabled with an empty 503 proof', async () => {
  const f = fixture();
  const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  assert.equal(result.outcome, 'qualified-and-disabled'); assert.equal(result.terminalFalseVerified, true);
  assert.equal(result.terminalDisabled503Verified, true);
  assert.equal(f.http.filter(v => v.method === 'POST' && v.flag === 'true').length, 2);
  assert.equal(f.http.filter(v => v.method === 'POST' && v.flag === 'false').length, 1);
  assert(f.http.length <= 11); assert(f.queries.length <= 3); assert.equal(admissionFlag(f.app), 'false');
  await assert.rejects(new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run(), /HISTORY_REQUIRES_RECONCILIATION/);
});

test('POST failure, query ambiguity, delayed rollout and counter/deadline failures stop requests and attempt only disable', async () => {
  for (const scenario of ['post-timeout', 'ambiguous-query', 'no-rows', 'unknown-enable', 'old-ready', 'journal-failure', 'cancelled']) {
    const f = fixture(), originalHttp = f.io.http, originalSave = f.io.saveRun;
    if (scenario === 'post-timeout') f.io.http = async (...args) => {
      const result = await originalHttp(...args); return args[0] === 'POST' && admissionFlag(f.app) === 'true'
        ? { ...result, status: null, errorCode: 'TIMEOUT', durationMs: 1000 } : result;
    };
    if (scenario === 'ambiguous-query') f.io.query = async start => queryRows([SYNTHETIC_FIXTURES[0], SYNTHETIC_FIXTURES[0]], start);
    if (scenario === 'no-rows') f.io.query = async () => queryRows([], '');
    if (scenario === 'unknown-enable') f.unknownEnable = true;
    if (scenario === 'old-ready') f.oldReady = true;
    if (scenario === 'journal-failure') {
      let failed = false;
      f.io.saveRun = async value => { if (!failed && value.stage === 'two-fixed-events') { failed = true; throw new Error('DISK_FAILURE'); } return originalSave(value); };
    }
    if (scenario === 'cancelled') f.io.http = async (...args) => { const response = await originalHttp(...args); f.cancelled = true; return response; };
    const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
    assert.equal(result.outcome, 'stopped-disabled', scenario);
    assert.equal(result.terminalFalseVerified, true, scenario);
    assert.equal(admissionFlag(f.app), 'false', scenario);
    assert(f.writes.filter(v => v === 'synthetic-admission').length <= 1);
    assert(f.writes.filter(v => v === 'synthetic-disable').length <= 1);
    assert(f.http.length <= 11);
    if (scenario === 'post-timeout') assert.equal(f.http.filter(v => v.method === 'POST' && v.flag === 'true').length, 1);
  }
});

test('rollback blocked by expiry or configuration drift reports an unproven terminal state rather than success', async () => {
  for (const mode of ['expiry', 'drift']) {
    const f = fixture(), original = f.io.http;
    f.io.http = async (...args) => {
      const result = await original(...args);
      if (args[0] === 'POST' && admissionFlag(f.app) === 'true') {
        if (mode === 'expiry') f.advance(3600000);
        else f.app.properties.template.containers[0].resources.cpu = 0.5;
        return { ...result, status: 503 };
      }
      return result;
    };
    const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
    assert.equal(result.outcome, 'held-terminal-state-or-http-unproven');
    assert.equal(result.terminalFalseVerified, false);
    assert.equal(admissionFlag(f.app), 'true');
    assert.deepEqual(f.writes, ['synthetic-admission']);
  }
});
test('deployment delay beyond the request window does not permit late events or expired rollback writes', async () => {
  const f = fixture(), original = f.io.deployment;
  let delayed = false;
  f.io.deployment = async (...args) => {
    const value = await original(...args);
    if (!delayed && args[0] === 'synthetic-admission' && value) { delayed = true; f.advance(3600000); }
    return value;
  };
  const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  assert.equal(result.outcome, 'held-terminal-state-or-http-unproven');
  assert.equal(result.enabledWindowExceeded, true);
  assert.equal(f.http.filter(v => v.method === 'POST').length, 0);
  assert.deepEqual(f.writes, ['synthetic-admission']);
});

test('query validation rejects duplicates, extra columns/rows and out-of-window values without expanding privileges', () => {
  const start = '2026-09-23T09:00:00.000Z', end = '2026-09-23T09:01:00.000Z';
  const good = queryRows(SYNTHETIC_FIXTURES, start);
  assert.equal(verifySyntheticRows(good, start, end).complete, true);
  assert.equal(verifySyntheticRows(queryRows([], start), start, end).complete, false);
  for (const mutate of [
    v => { v.tables[0].rows.push(v.tables[0].rows[0]); },
    v => { v.tables[0].rows[1] = v.tables[0].rows[0]; },
    v => { v.tables[0].columns.push({ name: 'clientId', type: 'string' }); },
    v => { v.tables[0].rows[0][0] = '2020-01-01T00:00:00.000Z'; },
    v => { v.tables[0].rows[0][0] = [start]; },
    v => { v.tables[0].rows[0][1] = '1'; }, v => { v.tables[0].rows[0][7] = 'private-host'; },
  ]) { const bad = structuredClone(good); mutate(bad); assert.throws(() => verifySyntheticRows(bad, start, end)); }
  assert.throws(() => syntheticQuery(start, '2026-09-23T10:00:00.000Z'));
  assert(syntheticQuery(start, end).endsWith('\n| take 3'));
});

test('real transport cannot write toggle without its paired final-read gate and bounded HTTP cannot use arbitrary targets', async t => {
  const f = fixture(), directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  let calls = 0;
  const arm = transport(f.c, f.phases['synthetic-admission'], directory, async () => { calls++; return {}; });
  await assert.rejects(arm('PUT', f.phases['synthetic-admission'].deploymentId, '2022-09-01', {}, undefined, () => {}), /PAIRED_TOGGLE_GUARD_REQUIRED/);
  let prepared = false, checked = false;
  await arm('PUT', f.phases['synthetic-admission'].deploymentId, '2022-09-01', { toJSON() { prepared = true; return {}; } },
    undefined, () => { assert(checked); }, undefined, async () => { assert(prepared); checked = true; });
  assert.equal(calls, 1); assert.deepEqual(await readdir(directory), []);
  await assert.rejects(syntheticHttp('other.invalid', 'GET', '/health/live'), /FIXED_SYNTHETIC_REQUEST_REQUIRED/);
  await assert.rejects(syntheticHttp('fixture.azurecontainerapps.io', 'POST', '/other', SYNTHETIC_FIXTURES[0]), /FIXED_SYNTHETIC_REQUEST_REQUIRED/);
  await assert.rejects(syntheticHttp('fixture.azurecontainerapps.io', 'POST', '/v1/events', { private: true }), /FIXED_SYNTHETIC_REQUEST_REQUIRED/);
});
test('bounded HTTPS uses verified TLS and never follows redirects or retains unallowlisted headers/body', async t => {
  let calls = 0;
  t.mock.method(https, 'request', (options, callback) => {
    calls++;
    assert.equal(options.rejectUnauthorized, true); assert.equal(options.agent, false);
    assert.equal(options.protocol, 'https:'); assert.equal(options.hostname, options.servername);
    const request = new EventEmitter(); request.destroy = () => {};
    request.end = () => queueMicrotask(() => {
      const socket = new EventEmitter(); socket.authorized = true;
      request.emit('socket', socket); socket.emit('secureConnect');
      const response = new EventEmitter();
      response.statusCode = 302; response.headers = { location: 'https://other.invalid', 'set-cookie': 'private-value', 'content-length': '0' };
      callback(response); response.emit('end');
    });
    return request;
  });
  const response = await syntheticHttp('fixture.azurecontainerapps.io', 'GET', '/health/live', undefined, () => {});
  assert.equal(calls, 1); assert.equal(response.status, 302); assert.equal(response.tlsVerified, true);
  assert.deepEqual(response.headerPolicy, { noStore: false, zeroContentLength: true, connectionClose: false });
  assert(!JSON.stringify(response).includes('private-value'));
});
test('cancel or cutoff during source hashing or intent persistence never dispatches the reserved enabled POST', async () => {
  for (const boundary of ['source', 'persist-cancel', 'persist-cutoff']) {
    const f = fixture(), source = f.io.sourceDigest, save = f.io.saveRun;
    if (boundary === 'source') f.io.sourceDigest = async () => {
      const value = await source();
      if (f.run?.stage === 'two-fixed-events') f.cancelled = true;
      return value;
    };
    else f.io.saveRun = async value => {
      await save(value);
      if (value.stage === 'two-fixed-events' && value.requests.at(-1)?.method === 'POST' && !value.requests.at(-1)?.response) {
        if (boundary === 'persist-cancel') f.cancelled = true;
        else {
          const intent = Date.parse(f.journals['synthetic-admission'].intentAt);
          if (f.now <= intent + 420000) f.advance(intent + 420001 - f.now);
        }
      }
    };
    const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
    assert.equal(f.http.filter(v => v.method === 'POST' && v.flag === 'true').length, 0, boundary);
    assert.equal(result.enabledPosts, 1, 'The reserved attempt is retained, not refunded.');
    assert.equal(result.outcome, 'stopped-disabled', boundary);
  }
});
test('query cancellation while persisting its intent cannot dispatch or report a successful window', async () => {
  const f = fixture(), save = f.io.saveRun;
  f.io.saveRun = async value => {
    await save(value);
    if (value.stage === 'bounded-read-queries' && value.queries.length) f.cancelled = true;
  };
  const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  assert.equal(f.queries.length, 0);
  assert.equal(result.queries.length, 1);
  assert.equal(result.outcome, 'stopped-disabled');
});
test('one absolute rollout deadline rejects 117 seconds deployment plus 117 seconds readiness', async () => {
  const f = fixture(), deployment = f.io.deployment, rollout = f.io.rollout;
  let delayedDeployment = false, delayedReady = false;
  f.io.deployment = async (...args) => {
    const value = await deployment(...args);
    if (args[0] === 'synthetic-admission' && value && !delayedDeployment) { delayedDeployment = true; f.advance(117000); }
    return value;
  };
  f.io.rollout = async (...args) => {
    const value = await rollout(...args);
    if (admissionFlag(f.app) === 'true' && !delayedReady) { delayedReady = true; f.advance(117000); }
    return value;
  };
  await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
  assert.equal(f.savedReceipts['synthetic-admission'], undefined);
  assert.equal(f.journals['synthetic-admission'].outcome, 'reconciliation-required');
});
test('a ready observation arriving after the 120-second deadline does not qualify', async () => {
  const f = fixture(), rollout = f.io.rollout;
  f.io.rollout = async (...args) => { const value = await rollout(...args); f.advance(120001); return value; };
  await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
  assert.equal(f.savedReceipts['synthetic-admission'], undefined);
});

test('the real query IO checks cancellation and deadline again after workspace and source reads', async () => {
  for (const boundary of ['workspace-cancel', 'workspace-deadline', 'source-cancel', 'source-deadline']) {
    const f = fixture(), workspace = structuredClone(f.receipts['workspace-access'].resources[f.r.workspace]);
    workspace.type = 'Microsoft.OperationalInsights/workspaces';
    workspace.location = 'australiaeast';
    workspace.properties.customerId = '00000000-0000-4000-8000-000000000009';
    workspace.properties.createdDate = '2026-09-23T00:00:00.000Z';
    let queryCalls = 0, workspaceCalls = 0;
    f.io.query = (start, end, guard, deadline, onDispatch) => readSyntheticQuery(f.c, workspace, f.source, start, end, guard, deadline,
      async (args, timeout) => {
        assert(timeout > 0 && timeout <= deadline - f.now);
        if (args[args.indexOf('--url') + 1].startsWith('https://management.azure.com/')) {
          workspaceCalls++;
          if (boundary === 'workspace-cancel') f.cancelled = true;
          if (boundary === 'workspace-deadline') f.advance(deadline + 1 - f.now);
          return workspace;
        }
        queryCalls++; return queryRows(SYNTHETIC_FIXTURES, start);
      },
      async () => {
        if (boundary === 'source-cancel') f.cancelled = true;
        if (boundary === 'source-deadline') f.advance(deadline + 1 - f.now);
        return f.source;
      }, f.io.now, onDispatch);
    const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
    assert.equal(workspaceCalls, 1, boundary);
    assert.equal(queryCalls, 0, boundary);
    assert.equal(result.queries.length, 1, boundary);
    assert.equal(result.queries[0].transportDispatchAttempted, false, boundary);
    assert.equal(result.outcome, 'stopped-disabled', boundary);
  }
});

test('production IO carries the same remaining deadline through workspace reads, rollout and privacy calls', async t => {
  const f = fixture(), calls = [], directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  t.mock.method(Date, 'now', f.io.now);
  const deadline = f.now + 5000;
  const io = syntheticWindowIO(f.c, f.phases, f.window, f.approvals, f.receipts, {}, {}, {}, directory, () => false,
    async (args, timeout) => {
      calls.push({ args, timeout, remaining: deadline - f.now });
      assert(timeout > 0 && timeout <= deadline - f.now);
      f.advance(1000);
      const url = new URL(args[args.indexOf('--url') + 1]);
      if (url.pathname.endsWith('/revisions')) return { value: [] };
      if (url.pathname.includes('/userAssignedIdentities/')) {
        return f.receipts.core.resources[url.pathname];
      }
      if (url.pathname === f.r.app) return f.app;
      return { value: [] };
    });
  await io.rollout(deadline);
  assert.deepEqual(calls.map(v => v.timeout), [5000, 4000, 3000, 2000]);
  f.advance(1000);
  await assert.rejects(io.privacy(f.phases['synthetic-disable'], deadline), /WINDOW_READ_DEADLINE/);
  assert.equal(calls.length, 4);
});

function slowRollback(f, deadlineObservations) {
  const base = { deployment: f.io.deployment, check: f.io.check, observe: f.io.observe, saveJournal: f.io.saveJournal,
    arm: f.io.arm, rollout: f.io.rollout, privacy: f.io.privacy };
  let active = false, observations = 0;
  const note = (stage, deadline) => {
    const enable = Date.parse(f.journals['synthetic-admission'].intentAt);
    assert(Number.isSafeInteger(deadline), stage);
    assert(deadline <= Math.min(Date.parse(f.approvals['synthetic-disable'].expiresAt), enable + 780000), stage);
    deadlineObservations.push({ stage, deadline, now: f.now });
  };
  f.io.deployment = async (name, deadline) => {
    if (active) {
      note('deployment-' + name, deadline);
      f.advance(name === 'synthetic-admission' ? 14900 : f.deployments[name] ? 2000 : 14700);
    }
    return base.deployment(name, deadline);
  };
  f.io.check = async (phase, transition, deadline) => {
    if (phase.phase === 'synthetic-disable') { note('preflight', deadline); f.advance(120000); }
    return base.check(phase, transition, deadline);
  };
  f.io.observe = async deadline => {
    if (active) { note('final-read', deadline); f.advance(observations++ === 0 ? 14000 : 3000); }
    return base.observe(deadline);
  };
  f.io.saveJournal = async (name, value) => {
    await base.saveJournal(name, value);
    if (name === 'synthetic-disable' && value.outcome === 'submission-possible') f.advance(12000);
  };
  f.io.arm = (phase, deadline) => async (...args) => {
    if (phase.phase === 'synthetic-disable') note('dispatch', deadline);
    const result = await base.arm(phase, deadline)(...args);
    if (phase.phase === 'synthetic-disable') f.advance(10000);
    return result;
  };
  f.io.rollout = async deadline => {
    if (active) { note('ready', deadline); f.advance(14960); }
    return base.rollout(deadline);
  };
  f.io.privacy = async (phase, deadline) => {
    if (phase.phase === 'synthetic-disable') { note('privacy', deadline); f.advance(6000); }
    return base.privacy(phase, deadline);
  };
  return () => { active = true; };
}

test('full rollback records expiry at 600 seconds and separates a 630.44-second recovery from in-window success', async () => {
  const f = fixture(), bounds = [], startSlow = slowRollback(f, bounds);
  await f.toggle.execute('synthetic-admission');
  const enabledAt = Date.parse(f.journals['synthetic-admission'].intentAt);
  f.advance(enabledAt + 418880 - f.now); startSlow();
  const receipt = await f.toggle.execute('synthetic-disable');
  assert.equal(f.now - enabledAt, 630440);
  assert.equal(receipt.qualified, true);
  assert.equal(receipt.lateRecovery, true);
  assert.equal(receipt.withinEnabledWindow, false);
  assert.equal(receipt.deadlines.incident.code, 'ENABLED_WINDOW_EXCEEDED');
  assert.equal(f.incidents.length, 1);
  assert.equal(f.incidents[0].persistedAt, enabledAt + 600000);
  assert.equal(f.journals['synthetic-disable'].outcome, 'readback-qualified-late-recovery');
  assert.equal(receipt.rolloutDeadline, Date.parse(f.journals['synthetic-disable'].intentAt) + 120000);
  assert(bounds.some(v => v.stage === 'preflight'));
  assert(bounds.some(v => v.stage === 'privacy'));
  assert.deepEqual(f.writes, ['synthetic-admission', 'synthetic-disable']);
  assert.equal(admissionFlag(f.app), 'false');
});

test('the complete driver cannot report qualified-and-disabled after the reserve is consumed before disable', async () => {
  const f = fixture(), bounds = [], originalDeployment = f.io.deployment;
  let delayedEnable = false, queryCount = 0, slowStarted = false;
  f.io.deployment = async (name, deadline) => {
    const value = await originalDeployment(name, deadline);
    if (name === 'synthetic-admission' && value && !delayedEnable) { delayedEnable = true; f.advance(117000); }
    return value;
  };
  const startSlow = slowRollback(f, bounds), saveRun = f.io.saveRun;
  f.io.saveRun = async value => {
    await saveRun(value);
    if (value.stage === 'disabling' && !slowStarted) { slowStarted = true; startSlow(); }
  };
  f.io.query = async (start, end, guard, deadline, onDispatch) => {
    guard(); onDispatch(); queryCount++;
    if (queryCount < 3) { f.advance(14930); return queryRows([], start); }
    const enabledAt = Date.parse(f.journals['synthetic-admission'].intentAt), remaining = enabledAt + 418880 - f.now;
    assert(remaining > 0 && remaining < 15000);
    f.advance(remaining);
    return queryRows(SYNTHETIC_FIXTURES, start);
  };
  const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  assert.equal(result.outcome, 'stopped-disabled-late-recovery');
  assert.equal(result.terminalFalseVerified, true);
  assert.equal(result.terminalDisabled503Verified, true);
  assert.equal(result.enabledWindowExceeded, true);
  assert.equal(result.expiryIncident.deadlineAt, new Date(Date.parse(result.enabledIntentAt) + 600000).toISOString());
  assert.equal(f.incidents.length, 1);
  assert.equal(f.incidents[0].persistedAt, Date.parse(result.enabledIntentAt) + 600000);
  assert.equal(f.http.filter(v => v.method === 'POST' && v.flag === 'true').length, 2);
  assert(f.http.length <= 11);
  assert.equal(queryCount, 3);
  assert.equal(f.timers.size, 0);
});

test('late disable recovery is bounded by the original intent and its own approval rather than a fresh per-call budget', async () => {
  const f = fixture();
  await f.toggle.execute('synthetic-admission');
  const enabledAt = Date.parse(f.journals['synthetic-admission'].intentAt);
  f.advance(enabledAt + 610000 - f.now);
  const before = f.io.check, deadlines = [];
  f.io.check = async (phase, transition, deadline) => {
    if (phase.phase === 'synthetic-disable') { deadlines.push(deadline); f.advance(100000); }
    return before(phase, transition, deadline);
  };
  const receipt = await f.toggle.execute('synthetic-disable');
  assert.equal(deadlines[0], enabledAt + 780000);
  assert.equal(receipt.operationDeadline, enabledAt + 780000);
  assert.equal(receipt.lateRecovery, true);
  assert.deepEqual(f.writes, ['synthetic-admission', 'synthetic-disable']);
  const exhausted = fixture(); await exhausted.toggle.execute('synthetic-admission');
  const original = exhausted.io.check, intent = Date.parse(exhausted.journals['synthetic-admission'].intentAt);
  exhausted.advance(intent + 760000 - exhausted.now);
  exhausted.io.check = async (...args) => { exhausted.advance(20001); return original(...args); };
  await assert.rejects(exhausted.toggle.execute('synthetic-disable'), /SYNTHETIC_OPERATION_DEADLINE/);
  assert.deepEqual(exhausted.writes, ['synthetic-admission']);
  assert.equal(exhausted.savedReceipts['synthetic-disable'], undefined);
  exhausted.toggle.deadlines.dispose();
});

test('submission and privacy latency consume the same rollout deadline instead of starting another allowance', async () => {
  for (const stage of ['submission', 'privacy']) {
    const f = fixture(), arm = f.io.arm, deployment = f.io.deployment, privacy = f.io.privacy;
    let delayed = false;
    if (stage === 'submission') f.io.arm = (phase, deadline) => async (...args) => {
      const result = await arm(phase, deadline)(...args);
      f.advance(120001); return result;
    };
    else {
      f.io.deployment = async (...args) => {
        const value = await deployment(...args);
        if (value && !delayed) { delayed = true; f.advance(117000); }
        return value;
      };
      f.io.privacy = async (...args) => { await privacy(...args); f.advance(3001); };
    }
    await assert.rejects(f.toggle.execute('synthetic-admission'), /TOGGLE_STOPPED/);
    assert.equal(f.savedReceipts['synthetic-admission'], undefined);
    assert.equal(f.journals['synthetic-admission'].outcome, 'reconciliation-required');
    assert.equal(f.journals['synthetic-admission'].transportDispatchAttempted, true);
    assert.deepEqual(f.writes, ['synthetic-admission']);
    f.toggle.deadlines.dispose();
  }
});

test('cancellation while persisting a completed query cannot turn a stopped window into a successful one', async () => {
  const f = fixture(), save = f.io.saveRun;
  f.io.saveRun = async value => {
    await save(value);
    if (value.stage === 'bounded-read-queries' && value.queries[0]?.result) f.cancelled = true;
  };
  const result = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  assert.equal(f.queries.length, 1);
  assert.equal(result.queries.length, 1);
  assert.equal(result.outcome, 'stopped-disabled');
  assert.equal(result.terminalFalseVerified, true);
  assert.equal(result.terminalDisabled503Verified, true);
});

async function completedPredecessor() {
  const f = fixture(), http = f.io.http;
  f.io.http = async (...args) => {
    const result = await http(...args);
    return args[0] === 'POST' && admissionFlag(f.app) === 'true'
      ? { ...result, status: null, errorCode: 'TOTAL_TIMEOUT_1000MS', durationMs: 1003.3 } : result;
  };
  const run = await new SyntheticWindowDriver(f.c, f.phases, f.window, f.approvals, f.toggle, f.io).run();
  const observation = await f.io.rollout();
  const predecessor = { version: 1, kind: 'terminal-disabled-window', publication: { commitSha: 'a'.repeat(40), sourceSha256: f.source },
    window: f.window, phases: f.phases, approvals: f.approvals, journals: f.journals, receipts: f.savedReceipts,
    prerequisiteReceipts: f.receipts, run,
    readback: { checkedAt: new Date(f.now).toISOString(), sourceSha256: f.source,
      deployments: f.deployments, app: f.app, identities: f.context.identities, revisions: observation.revisions,
      privacy: { diagnostics: { [f.r.app]: { value: [] } }, exports: { value: [] } } } };
  return { f, predecessor };
}
test('window UUIDs preserve full entropy and collector ownership while deriving unique bounded toggle names', () => {
  const f = fixture(), originalConfig = json(f.c), idsBefore = json(ids(f.c));
  const instances = Array.from({ length: 24 }, () => ({ ...f.instance, id: randomUUID() }));
  const names = new Set();
  for (const length of [2, 10]) {
    const c = { ...f.c, namePrefix: 'missionspec-' + 'a'.repeat(length), registryName: 'missionspec' + 'a'.repeat(length) };
    for (const instance of instances) for (const name of ['synthetic-admission', 'synthetic-disable']) {
      const value = deploymentName(c, name, instance);
      assert(value.length <= 64); assert(value.includes('w' + instance.id.replaceAll('-', '')));
      assert.notEqual(value, deploymentName(c, name)); assert(!names.has(value)); names.add(value);
    }
  }
  assert.equal(json(f.c), originalConfig); assert.equal(json(ids(f.c)), idsBefore);
  for (const mutate of [
    x => { x.id = f.c.runId; }, x => { x.previousInstanceIds = [x.id]; }, x => { x.previousInstanceIds = [f.c.runId]; },
    x => { x.id = 'aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa'; }, x => { x.id = 'bad'; }, x => { x.force = true; },
    x => { x.id = [x.id]; }, x => { x.previousInstanceIds = [[randomUUID()]]; },
  ]) { const value = structuredClone(f.instance); mutate(value); assert.throws(() => validateWindowInstance(f.c, value)); }
  assert.throws(() => deploymentName(f.c, 'core', f.instance), /TOGGLE_ONLY/);
});
test('a new instance requires a settled predecessor and retains its unknown first POST as a failure', async () => {
  const { f, predecessor } = await completedPredecessor();
  const summary = verifyWindowPredecessor(f.c, predecessor);
  assert.equal(summary.outcome, 'stopped-disabled'); assert.equal(summary.unknownFirstPost, true);
  await verifyPublishedWindowPredecessor(f.c, predecessor, async () => f.source);
  const instance = { version: 1, id: randomUUID(), predecessorSha256: digest(json(predecessor)), previousInstanceIds: [f.instance.id] };
  verifyWindowInstancePredecessor(f.c, instance, predecessor);
  const next = buildPhase(f.c, 'synthetic-admission', null, f.receipts, undefined, undefined, instance);
  assert.notEqual(next.deploymentId, f.phases['synthetic-admission'].deploymentId);
  assert.deepEqual(next.template, f.phases['synthetic-admission'].template);
  assert.deepEqual(next.template.resources[0].tags, ownerTags(f.c));
  for (const change of [
    p => { p.run.outcome = 'qualified-and-disabled'; p.run.failureCode = null; },
    p => { p.run.outcome = 'held-terminal-state-or-http-unproven'; },
    p => { p.journals['synthetic-admission'].outcome = 'submission-possible'; },
    p => { p.readback.deployments['synthetic-admission'].properties.provisioningState = 'Running'; },
    p => { p.readback.deployments['synthetic-disable'].properties.templateHash = 'other'; },
    p => { p.receipts['synthetic-disable'].qualified = false; },
    p => { p.run.terminalFalseVerified = false; },
    p => { p.run.requests.at(-1).response.status = 204; },
    p => { p.run.requests.at(-1).response.durationMs = 1001; },
    p => { p.approvals['synthetic-disable'].expiresAt = p.journals['synthetic-disable'].intentAt; },
    p => { p.readback.app.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; },
    p => { p.readback.app.properties.latestRevisionName = 'unexpected'; },
    p => { p.readback.identities[f.r.ingestIdentity].properties.principalId = f.c.operatorPrincipalId; },
    p => { p.readback.privacy.exports.value.push({ name: 'unexpected' }); },
  ]) {
    const value = structuredClone(predecessor); change(value);
    assert.throws(() => verifyWindowPredecessor(f.c, value));
  }
  await assert.rejects(verifyPublishedWindowPredecessor(f.c, predecessor, async () => digest('unknown source')), /PUBLISHED_SOURCE_MISMATCH/);
  assert.throws(() => verifyWindowInstancePredecessor(f.c, { ...instance, id: f.instance.id }, predecessor), /REUSED/);
  assert.throws(() => verifyWindowInstancePredecessor(f.c, { ...instance, previousInstanceIds: [] }, predecessor), /BINDING_CHANGED/);
});
test('window, phase and approvals all bind the same new instance and reject legacy execution authority', () => {
  const f = fixture();
  for (const mutate of [
    a => { a['synthetic-admission'].windowInstanceId = randomUUID(); },
    a => { a['synthetic-disable'].predecessorSha256 = digest('other predecessor'); },
    a => { delete a['synthetic-admission'].windowInstanceId; },
    a => { a['synthetic-disable'].version = 1; },
  ]) { const approvals = structuredClone(f.approvals); mutate(approvals); assert.throws(() => verifySyntheticWindow(f.c, f.phases, f.window, approvals, f.source, f.now, true)); }
  const legacy = structuredClone(f.window); legacy.version = 1; delete legacy.windowInstance;
  assert.throws(() => verifySyntheticWindow(f.c, f.phases, legacy, f.approvals, f.source, f.now, true), /NEW_WINDOW_INSTANCE_REQUIRED/);
  const altered = structuredClone(f.phases); altered['synthetic-disable'].windowInstance.id = randomUUID();
  assert.throws(() => verifySyntheticWindow(f.c, altered, f.window, f.approvals, f.source, f.now, true));
  assert.throws(() => whatIfRequestContext(f.c, { ...f.phases['synthetic-admission'], deploymentId: `${f.r.group}/providers/Microsoft.Resources/deployments/${deploymentName(f.c, 'synthetic-admission')}` }), /FIXED_WHAT_IF_PHASE_REQUIRED/);
  const request = whatIfRequestContext(f.c, f.phases['synthetic-admission']);
  assert.equal(request.windowInstanceId, f.instance.id);
  assert.equal(request.predecessorSha256, f.instance.predecessorSha256);
});

test('a durable instance reservation rejects the same UUID even if a caller copies or changes local window files', async t => {
  const f = fixture(), directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 }); t.after(() => rm(directory, { recursive: true }));
  await reserveWindowInstance(f.c, directory, f.window);
  await assert.rejects(reserveWindowInstance(f.c, directory, f.window), /WINDOW_INSTANCE_REPLAY_FORBIDDEN/);
  const altered = structuredClone(f.window); altered.sourceSha256 = digest('changed source');
  await assert.rejects(reserveWindowInstance(f.c, directory, altered), /WINDOW_INSTANCE_REPLAY_FORBIDDEN/);
  assert.equal((await readdir(directory)).length, 1);
});

async function upgradeFixture(preservedIgnores = false) {
  const { f, predecessor } = await completedPredecessor();
  if (preservedIgnores) {
    f.receipts = structuredClone(f.receipts);
    f.receipts.core.resources[f.r.environment] = { id: f.r.environment, tags: ownerTags(f.c), properties: {} };
  }
  const candidate = candidateFixture(f.c, f.receipts.publication), source = digest('upgrade-policy');
  const instance = { version: 1, id: randomUUID(), predecessorSha256: digest(json(predecessor)),
    previousInstanceIds: [f.instance.id] };
  const phase = buildDisabledImagePhase(f.c, 'disabled-image-upgrade', f.receipts, candidate, predecessor, instance);
  let now = f.now + 1000, journal = null, receipt = null, deployment = null, writes = 0, reservations = 0;
  let app = structuredClone(predecessor.readback.app);
  const context = { ...resourceContext(f.c, f.receipts), receiverCandidate: candidate };
  const whatIf = { status: 'Succeeded', changes: [{ resourceId: f.r.app, changeType: 'Modify',
    before: structuredClone(app), after: { ...structuredClone(phase.resources[0].expected), id: f.r.app } },
  ...(preservedIgnores ? [f.r.registry, f.r.ingestIdentity, f.r.pullIdentity, f.r.workspace, f.r.environment, f.r.dcr]
    .map(resourceId => ({ resourceId, changeType: 'Ignore' })) : [])] };
  verifyWhatIf(phase, whatIf, Object.values(f.receipts).flatMap(v => Object.keys(v.resources ?? {})), { ...context, config: f.c, app });
  const approval = { action: 'direct-arm-disabled-image-upgrade', configSha256: digest(json(f.c)), phaseSha256: digest(json(phase)),
    sourceSha256: source, originSha256: f.c.originSha256, receiptsSha256: digest(json(f.receipts)),
    baselineSha256: f.window.baselineSha256, whatIfSha256: digest(json(whatIf)),
    approvedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 1800000).toISOString() };
  const proof = { ...Object.fromEntries(Object.entries(approval).filter(([k]) => k.endsWith('Sha256'))),
    qualified: true, startedAt: now, completedAt: now, cost: firstReleaseCost(2) };
  const privacy = { diagnostics: { [f.r.app]: { value: [] } }, exports: { value: [] } };
  const revisions = () => ({ value: [{ id: `${f.r.app}/revisions/${app.properties.latestRevisionName}`, name: app.properties.latestRevisionName,
    properties: { active: true, provisioningState: 'Provisioned', runningState: 'Running', healthState: 'Healthy',
      replicas: 1, trafficWeight: 100, template: structuredClone(app.properties.template) } }] });
  const io = { now: () => now, sourceDigest: async () => source,
    loadJournal: async () => journal, saveJournal: async value => { journal = structuredClone(value); },
    saveReceipt: async value => { receipt = structuredClone(value); }, check: async () => proof,
    observe: async () => ({ app: structuredClone(app), context, revisions: revisions() }),
    privacy: async () => privacy, security: async () => {}, reserve: async () => { reservations++; },
    sleep: async ms => { now += ms; }, deployment: async () => deployment,
    arm: async (method, id, api, body, _filter, guard, _role, current) => {
      assert.equal(method, 'PUT'); assert.equal(id, phase.deploymentId); assert.equal(api, '2022-09-01');
      assert.equal(journal.outcome, 'submission-possible'); assert.equal(reservations, 1);
      await current(); guard(); writes++;
      const previous = structuredClone(app);
      app = { ...structuredClone(body.properties.template.resources[0]), id: f.r.app, systemData: previous.systemData, identity: previous.identity };
      app.properties.configuration.ingress.fqdn = previous.properties.configuration.ingress.fqdn;
      Object.assign(app.properties, { latestRevisionName: 'missionspec-test-ingest--upgraded',
        latestReadyRevisionName: 'missionspec-test-ingest--upgraded', provisioningState: 'Succeeded', runningStatus: 'Running' });
      deployment = { id, properties: { provisioningState: 'Succeeded', mode: 'Incremental', correlationId: 'fixture-image-change',
        timestamp: new Date(now).toISOString(), templateHash: digest(json(phase.template)) } };
    },
  };
  const controller = new ReceiverUpgradeController(f.c, phase, candidate, predecessor.readback.app, io);
  const record = () => ({ version: 1, kind: 'reviewed-disabled-image-change', publication: { commitSha: 'c'.repeat(40), sourceSha256: source },
    candidate, predecessor, prerequisiteReceipts: f.receipts, phase, approval, preflight: proof, whatIf, journal, receipt });
  return { f, candidate, phase, context, whatIf, approval, proof, io, controller, predecessor, record,
    advance: ms => { now += ms; }, get writes() { return writes; }, get journal() { return journal; },
    get app() { return app; }, get receipt() { return receipt; } };
}

test('receiver upgrade profile binds full immutable artifacts, source, notices and retained conditional native limitations', async t => {
  const f = fixture(), candidate = candidateFixture(f.c, f.receipts.publication);
  assert.equal(verifyReceiverCandidate(f.c, candidate).digest, candidate.profile.manifestDigest);
  assert.equal(candidate.profile.nativeClearance, 'CONDITIONAL_DISABLED_OR_SYNTHETIC_ONLY');
  for (const [label, mutate] of [
    ['manifest bytes', x => { x.profile.manifestJson += ' '; }],
    ['config bytes', x => { x.profile.configJson += ' '; }],
    ['arbitrary qualified digest', x => { x.profile = { qualified: true, manifestDigest: 'sha256:' + 'f'.repeat(64) }; }],
    ['unknown profile', x => { x.profile.kind = 'arbitrary-image'; }],
    ['source archive', x => { x.profile.source.archiveSha256 = digest('other'); }],
    ['notices', x => { x.profile.notices.bytes += ' changed'; }],
    ['scan bytes', x => { x.profile.scan.reportJson += ' '; }],
    ['counts', x => { x.profile.scan.counts.MEDIUM = 0; }],
    ['high advisory', x => { x.profile.scan.counts.HIGH = 1; }],
    ['suppression', x => { x.profile.scan.suppressedFindings = 1; }],
    ['native cleared', x => { x.profile.nativeClearance = 'CLEARED'; }],
    ['native conditions omitted', x => { x.profile.retainedAdvisories.pop(); }],
    ['glibc caveat waived', x => { x.profile.priorUnknownGlibcCaveatWaived = true; }],
    ['qualification bytes', x => { x.profile.qualification.reportJson += ' '; }],
    ['prepared identity contract', x => { x.profile.runtime.storageTimeoutMs = 20000; }],
    ['production authority', x => { x.profile.authority.productionClearance = true; }],
    ['old execution rewritten', x => { x.legacyPublication.receipt.configSha256Inputs = digest('new-config'); }],
    ['old source rewritten', x => { x.review.legacyPublicationSha256 = digest('other-history'); }],
    ['publication source not reviewed', x => { x.review.sourceSha256 = 'unknown'; }],
    ['publication evidence absent', x => { x.publication = { qualified: true }; }],
    ['publication cost reserve reduced', x => { x.review.cost.items.requests = 0; }],
    ['image index', x => { const m = JSON.parse(x.profile.manifestJson); m.mediaType = 'application/vnd.oci.image.index.v1+json'; x.profile.manifestJson = json(m); }],
  ]) await t.test(label, () => {
    const value = structuredClone(candidate); mutate(value);
    assert.throws(() => verifyReceiverCandidate(f.c, value));
  });
  const scanExpired = structuredClone(candidate); scanExpired.publication.intentAt = candidate.profile.scan.databaseNextUpdate;
  assert.throws(() => verifyReceiverCandidate(f.c, scanExpired), /EXPIRED/);
  const wrongUser = structuredClone(candidate.profile), config = JSON.parse(wrongUser.configJson);
  config.config.User = '0'; wrongUser.configJson = json(config); wrongUser.configDigest = 'sha256:' + digest(wrongUser.configJson);
  assert.throws(() => verifyReceiverProfile(wrongUser), /INVALID/);
});

test('candidate publication admits exactly the owned old tag and one reviewed new manifest, never a push', async () => {
  const f = fixture(), candidate = candidateFixture(f.c, f.receipts.publication), inventory = structuredClone(candidate.publication);
  verifyReceiverInventory(f.c, candidate, inventory, true);
  for (const change of [
    x => x.manifests.push({ digest: 'sha256:' + 'f'.repeat(64), tags: ['extra'] }),
    x => { x.manifests[1].tags.push('latest'); }, x => { x.manifests[0].tags = ['changed']; },
    x => { x.repositories.push('other/repository'); }, x => { x.referrers.push({ digest: 'sha256:' + 'f'.repeat(64) }); },
    x => { x.manifests[1].digest = x.manifests[0].digest; },
  ]) { const value = structuredClone(inventory); change(value); assert.throws(() => verifyReceiverInventory(f.c, candidate, value, true), /INVENTORY/); }
  const before = { repositories: inventory.repositories, manifests: inventory.manifests.slice(0, 1), referrers: [] };
  candidate.publication = null;
  const preview = prepareReceiverPublication(f.c, candidate, before, Date.parse('2026-09-23T08:01:00.000Z'));
  assert.equal(preview.qualified, false); assert.equal(preview.pushExecuted, false);
  assert.equal(preview.cost.total, 311.23); assert.equal(preview.cost.items.requests, firstReleaseCost(1).items.requests);
  assert.equal(preview.cost.items.defenderCspmTwoFullNodes, firstReleaseCost(1).items.defenderCspmTwoFullNodes);
  assert.throws(() => prepareReceiverPublication(f.c, candidate, before, Date.parse(candidate.review.expiresAt)), /EXPIRED/);
});

test('source qualification binds the exact 35 build inputs, not unrelated tracked/editor files', async () => {
  const f = fixture(), candidate = candidateFixture(f.c, f.receipts.publication);
  const contents = { ...Object.fromEntries(RECEIVER_SOURCE_INPUTS.map(path => [path, `fixture ${path}`])),
    'services/telemetry-ingest/src/identity-readiness.ts': 'fixture readiness', 'services/telemetry-ingest/Dockerfile': 'fixture Dockerfile' };
  assert.equal(RECEIVER_SOURCE_INPUTS.length, 35);
  assert(!RECEIVER_SOURCE_INPUTS.includes('services/telemetry-ingest/.gitignore'));
  const run = async (command, args) => {
    assert.equal(command, 'git');
    if (args[0] === 'merge-base') return { stdout: Buffer.alloc(0) };
    assert.notEqual(args[0], 'ls-tree', 'Unrelated Git directory entries are not build inputs.');
    assert.deepEqual(args.slice(0, 2), ['--no-pager', 'show']);
    return { stdout: Buffer.from(contents[args[2].slice(41)]) };
  };
  await verifyReceiverSource(candidate, run, async () => candidate.review.sourceSha256);
  const unrelated = structuredClone(candidate);
  unrelated.profile.source.files['services/telemetry-ingest/.gitignore'] = digest('unrelated');
  assert.throws(() => verifyReceiverProfile(unrelated.profile), /CLOSED_INPUT_REQUIRED/);
  await assert.rejects(verifyReceiverSource(unrelated, run, async () => candidate.review.sourceSha256), /SOURCE_UNAVAILABLE/);
  await assert.rejects(verifyReceiverSource(candidate, run, async () => digest('unreviewed policy')), /SOURCE_UNAVAILABLE/);
  delete candidate.profile.source.files['services/telemetry-ingest/Dockerfile'];
  await assert.rejects(verifyReceiverSource(candidate, run, async () => candidate.review.sourceSha256), { message: 'RECEIVER_SOURCE_UNAVAILABLE' });
});

test('scanner database nanoseconds remain hash-bound while expiry comparisons fail closed at millisecond boundaries', () => {
  assert.equal(receiverDatabaseInstant('2026-09-25T06:44:41.940723189Z'), Date.parse('2026-09-25T06:44:41.940Z'));
  assert.equal(receiverDatabaseInstant('2026-09-24T06:44:41.94072344Z'), Date.parse('2026-09-24T06:44:41.940Z'));
  for (const value of ['2026-02-30T06:44:41.94072344Z', '2026-09-24T06:44:41Z', '2026-09-24T06:44:41.9407234411Z',
    '2026-09-24T06:44:41.940+00:00', null, 1]) assert.throws(() => receiverDatabaseInstant(value), /DATABASE_TIME_INVALID/);
  const f = fixture(), candidate = candidateFixture(f.c, f.receipts.publication);
  candidate.profile.scan.databaseUpdatedAt = '2026-09-23T08:00:00.000123456Z';
  candidate.profile.scan.databaseNextUpdate = '2026-09-24T08:00:00.000123456Z';
  const qualification = JSON.parse(candidate.profile.qualification.reportJson);
  qualification.scanner.dbMetadata.UpdatedAt = candidate.profile.scan.databaseUpdatedAt;
  qualification.scanner.dbMetadata.NextUpdate = candidate.profile.scan.databaseNextUpdate;
  candidate.profile.qualification.reportJson = json(qualification);
  candidate.profile.qualification.reportSha256 = digest(candidate.profile.qualification.reportJson);
  verifyReceiverProfile(candidate.profile);
  candidate.review.profileSha256 = digest(json(candidate.profile));
  candidate.publication = null;
  assert.throws(() => verifyReceiverCandidate(f.c, candidate, Date.parse('2026-09-24T08:00:00.000Z'), false), /EXPIRED/);
});

test('content hashes do not substitute for matching local image qualification, complete notices or native caveats', () => {
  const f = fixture(), original = candidateFixture(f.c, f.receipts.publication).profile;
  for (const mutate of [
    q => { q.artifact.config = 'sha256:' + 'f'.repeat(64); },
    q => { q.productionAzureQualification = true; },
    q => { q.nativeCoverage = 'all native advisories cleared'; },
    q => { q.runtimeConstraints.memoryMaxBytes *= 2; },
    q => { q.resourceFixtures['disabled-main'].identityRequests = 1; },
    q => { q.resourceFixtures['slow-identity'].firstEvent.elapsedMs = 1001; },
    q => { q.resourceFixtures['failed-identity'].ingestionRequests = 1; },
  ]) {
    const profile = structuredClone(original), report = JSON.parse(profile.qualification.reportJson);
    mutate(report); profile.qualification.reportJson = json(report); profile.qualification.reportSha256 = digest(profile.qualification.reportJson);
    assert.throws(() => verifyReceiverProfile(profile), /QUALIFICATION_INVALID/);
  }
  for (const mutate of [
    b => { b.files[0].base64 = Buffer.from('different notice').toString('base64'); },
    b => { b.files[0].base64 += '\\n'; },
    b => { b.files.length = 0; },
  ]) {
    const profile = structuredClone(original), bundle = JSON.parse(profile.notices.bytes);
    mutate(bundle); profile.notices.bytes = json(bundle); profile.notices.sha256 = digest(profile.notices.bytes);
    assert.throws(() => verifyReceiverProfile(profile), /NOTICES_INVALID/);
  }
});

test('full disabled image what-if rejects flag, defaults, identity and every other mutable app delta', async t => {
  const u = await upgradeFixture(), context = { ...u.context, config: u.f.c, app: u.predecessor.readback.app };
  assert.equal(u.phase.transition.fromDigest, RECEIVER_DIGEST);
  assert.equal(u.phase.transition.toDigest, u.candidate.profile.manifestDigest);
  assert.equal(u.phase.configSha256, digest(json(u.f.c)));
  assert.equal(whatIfRequestContext(u.f.c, u.phase).windowInstanceId, u.phase.windowInstance.id);
  for (const [label, mutate] of [
    ['flag', v => { v.properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value = 'true'; }],
    ['cpu', v => { v.properties.template.containers[0].resources.cpu = 0.5; }],
    ['env', v => { v.properties.template.containers[0].env.push({ name: 'EXTRA', value: '1' }); }],
    ['command', v => { v.properties.template.containers[0].command = ['sh']; }],
    ['volume', v => { v.properties.template.volumes = [{ name: 'extra' }]; }],
    ['probe', v => { v.properties.template.containers[0].probes[0].periodSeconds = 2; }],
    ['identity', v => { v.identity.userAssignedIdentities = {}; }],
    ['lifecycle', v => { v.properties.configuration.identitySettings[0].lifecycle = 'All'; }],
    ['ingress', v => { v.properties.configuration.ingress.allowInsecure = true; }],
    ['scale', v => { v.properties.template.scale.maxReplicas = 2; }],
    ['unreviewed default', v => { v.properties.template.scale.cooldownPeriod = 600; }],
    ['registry credentials', v => { v.properties.configuration.registries[0].username = 'admin'; }],
  ]) await t.test(label, () => {
    const value = structuredClone(u.whatIf); mutate(value.changes[0].after);
    assert.throws(() => verifyWhatIf(u.phase, value, [], context));
  });

  await t.test('seven-entry Azure image what-if preserves six known Ignores in both review and completed record', async () => {
    const u = await upgradeFixture(true), raw = json(u.whatIf), known = Object.values(u.f.receipts).flatMap(v => Object.keys(v.resources ?? {}));
    assert.equal(u.whatIf.changes.length, 7);
    const context = { ...u.context, config: u.f.c, app: u.predecessor.readback.app };
    verifyWhatIf(u.phase, u.whatIf, known, context);
    await u.controller.execute(u.approval);
    verifyDisabledImageRecord(u.f.c, u.record());
    assert.equal(json(u.whatIf), raw, 'The complete payload, not a filtered rewrite, remains bound.');
    const rejectRecorded = whatIf => {
      const record = structuredClone(u.record());
      record.whatIf = whatIf;
      record.approval.whatIfSha256 = digest(json(whatIf));
      record.preflight.whatIfSha256 = record.approval.whatIfSha256;
      record.receipt.approvalSha256 = digest(json(record.approval));
      record.journal.approvalSha256 = record.receipt.approvalSha256;
      record.journal.receiptSha256 = digest(json(record.receipt));
      assert.throws(() => verifyDisabledImageRecord(u.f.c, record), /UNREVIEWED_RESOURCE_CHANGE/);
    };
    for (const changeType of ['Modify', 'Create', 'Delete', 'NoChange']) {
      const value = structuredClone(u.whatIf); value.changes[1].changeType = changeType;
      assert.throws(() => verifyWhatIf(u.phase, value, known, context), /UNREVIEWED_RESOURCE_CHANGE/);
      rejectRecorded(value);
    }
    const unknown = structuredClone(u.whatIf); unknown.changes[1].resourceId += '-unknown';
    assert.throws(() => verifyWhatIf(u.phase, unknown, known, context), /UNREVIEWED_RESOURCE_CHANGE/);
    rejectRecorded(unknown);
    const duplicate = structuredClone(u.whatIf); duplicate.changes.push(structuredClone(duplicate.changes[0]));
    assert.throws(() => verifyWhatIf(u.phase, duplicate, known, context), /WHAT_IF_ID_INVALID/);
    const missing = structuredClone(u.whatIf); missing.changes.shift();
    assert.throws(() => verifyWhatIf(u.phase, missing, known, context), /WHAT_IF_INCOMPLETE/);
  });
  for (const type of ['Create', 'Delete', 'NoChange', 'Ignore']) {
    const value = structuredClone(u.whatIf); value.changes[0].changeType = type;
    assert.throws(() => verifyWhatIf(u.phase, value, [], context), /DISABLED_IMAGE_ONLY/);
  }
});

test('reviewed disabled image execution journals once, preserves history, and becomes the next standard-window anchor', async () => {
  const u = await upgradeFixture(), before = json(u.predecessor), oldConfig = json(u.f.c), oldReceipts = json(u.f.receipts);
  await u.controller.execute(u.approval);
  assert.equal(u.writes, 1); assert.equal(u.receipt.ingestionEnabled, false); assert.equal(u.receipt.noOtherChange, true);
  const record = u.record(), summary = verifyDisabledImageRecord(u.f.c, record);
  assert.equal(verifyWindowPredecessor(u.f.c, record).outcome, 'reviewed-disabled-image-change');
  assert.equal(summary.usedInstanceIds.length, 2);
  assert.equal(json(u.predecessor), before); assert.equal(json(u.f.c), oldConfig); assert.equal(json(u.f.receipts), oldReceipts);
  const instance = { version: 1, id: randomUUID(), predecessorSha256: digest(json(record)), previousInstanceIds: summary.usedInstanceIds };
  verifyWindowInstancePredecessor(u.f.c, instance, record);
  const receipts = { ...u.f.receipts, receiverUpgrade: record };
  const phases = Object.fromEntries(['synthetic-admission', 'synthetic-disable'].map(name =>
    [name, buildPhase(u.f.c, name, null, receipts, undefined, undefined, instance)]));
  for (const p of Object.values(phases)) {
    assert.equal(p.resources[0].expected.properties.template.containers[0].image.endsWith(u.candidate.profile.manifestDigest), true);
    assert.equal(p.transition.anchorAppSha256, digest(json(u.receipt.resources[u.f.r.app])));
  }
  const whatifs = { 'synthetic-admission': { status: 'Succeeded', changes: [{ resourceId: u.f.r.app, changeType: 'Modify',
    before: u.receipt.resources[u.f.r.app], after: { ...structuredClone(phases['synthetic-admission'].resources[0].expected), id: u.f.r.app } }] },
  'synthetic-disable': { status: 'Succeeded', changes: [{ resourceId: u.f.r.app, changeType: 'NoChange' }] } };
  const window = buildSyntheticWindow(u.f.c, phases, receipts, { policyBaselineSha256: u.f.window.baselineSha256 }, u.f.source, whatifs);
  assert.equal(window.anchorApp.properties.template.containers[0].image.endsWith(u.candidate.profile.manifestDigest), true);
  const rollback = buildDisabledImagePhase(u.f.c, 'disabled-image-rollback', receipts, u.candidate, record, instance);
  assert.equal(rollback.transition.toDigest, RECEIVER_DIGEST);
  assert.equal(rollback.ingestEnabled, false);
  assert.notEqual(rollback.deploymentId, u.phase.deploymentId);
  const rollbackWhatIf = { status: 'Succeeded', changes: [{ resourceId: u.f.r.app, changeType: 'Modify',
    before: u.receipt.resources[u.f.r.app], after: { ...structuredClone(rollback.resources[0].expected), id: u.f.r.app } }] };
  verifyWhatIf(rollback, rollbackWhatIf, [], { ...u.context, config: u.f.c, app: u.receipt.resources[u.f.r.app] });
  const restore = new ReceiverUpgradeController(u.f.c, rollback, u.candidate, u.receipt.resources[u.f.r.app], u.io);
  await assert.rejects(restore.execute(u.approval), /EXACT_PHASE_RELEASE_REQUIRED/);
  assert.throws(() => buildPhase(u.f.c, 'disabled-app', null, receipts), /HISTORICAL_DISABLED_APP_PROFILE_IMMUTABLE/);
  await assert.rejects(u.controller.execute(u.approval), /REPLAY/);
  assert.equal(u.writes, 1);
});

test('upgrade rejects expiry, source/role/identity drift and unknown submissions without a blind retry', async t => {
  for (const mode of ['expired', 'source', 'role', 'identity', 'unknown', 'old-ready', 'privacy']) await t.test(mode, async () => {
    const u = await upgradeFixture(), observe = u.io.observe, arm = u.io.arm;
    if (mode === 'expired') u.advance(1800000);
    if (mode === 'source') u.io.sourceDigest = async () => digest('changed source');
    if (mode === 'role') u.io.security = async () => { throw new Error('ASSIGNMENT_ROLE_DEFINITION_DRIFT'); };
    if (mode === 'identity') u.io.observe = async () => {
      const value = await observe(); value.app.identity.userAssignedIdentities[u.f.r.ingestIdentity].principalId = u.f.c.operatorPrincipalId; return value;
    };
    if (mode === 'unknown') u.io.arm = async (...args) => { await arm(...args); throw new Error('private URL token and path'); };
    if (mode === 'old-ready') u.io.observe = async () => {
      const value = await observe(); if (u.writes) value.app.properties.latestReadyRevisionName = u.predecessor.readback.app.properties.latestReadyRevisionName; return value;
    };
    if (mode === 'privacy') u.io.privacy = async () => ({ diagnostics: { [u.f.r.app]: { value: [{ name: 'route' }] } }, exports: { value: [] } });
    await assert.rejects(u.controller.execute(u.approval));
    assert.equal(u.receipt, null);
    assert.equal(u.writes, ['unknown', 'old-ready', 'privacy'].includes(mode) ? 1 : 0);
    if (u.journal) {
      assert.equal(u.journal.outcome, 'reconciliation-required');
      assert.match(u.journal.failureCode, /^[A-Z_]+$/u);
      assert(!json(u.journal).includes('private URL'));
      await assert.rejects(u.controller.execute(u.approval));
      assert.equal(u.writes, 1);
    }
  });
});

test('upgrade predecessor cannot fabricate old window success, change approvals, or erase image execution uncertainty', async () => {
  const u = await upgradeFixture(); await u.controller.execute(u.approval);
  for (const mutate of [
    x => { x.predecessor.run.outcome = 'qualified-and-disabled'; },
    x => { x.predecessor.run.terminalFalseVerified = false; },
    x => { x.journal.transportDispatchAttempted = false; },
    x => { x.journal.outcome = 'reconciliation-required'; },
    x => { x.receipt.qualified = true; x.receipt.noOtherChange = false; },
    x => { x.approval.sourceSha256 = digest('unreviewed source'); },
    x => { x.receipt.resources[u.f.r.app].properties.template.containers[0].image = 'unknown'; },
    x => { x.phase.windowInstance.id = u.f.instance.id; },
    x => { x.receipt.revisions.value[0].properties.healthState = 'Unhealthy'; },
    x => { x.receipt.privacy.exports.value = [{}]; },
  ]) { const record = structuredClone(u.record()); mutate(record); assert.throws(() => verifyWindowPredecessor(u.f.c, record)); }
});

test('image guards run after body preparation and asynchronous reads; no late qualification or raced deployment', async t => {
  for (const mode of ['body-expiry', 'body-phase-drift', 'body-role-drift', 'deployment-race', 'late-final']) await t.test(mode, async () => {
    const u = await upgradeFixture(), arm = u.io.arm, observe = u.io.observe, deployment = u.io.deployment;
    if (mode.startsWith('body-')) u.io.arm = async (...args) => {
      if (mode === 'body-expiry') u.advance(1800000);
      if (mode === 'body-phase-drift') u.phase.template.resources[0].properties.template.containers[0].env.push({ name: 'EXTRA', value: '1' });
      if (mode === 'body-role-drift') u.io.security = async () => { throw new Error('ASSIGNMENT_ROLE_DEFINITION_DRIFT'); };
      return arm(...args);
    };
    if (mode === 'deployment-race') {
      let reads = 0;
      u.io.deployment = async (...args) => ++reads >= 2 ? { id: u.phase.deploymentId } : deployment(...args);
    }
    if (mode === 'late-final') {
      let readyReads = 0;
      u.io.observe = async (...args) => {
        const value = await observe(...args);
        if (u.writes && ++readyReads === 2) u.advance(120001);
        return value;
      };
    }
    await assert.rejects(u.controller.execute(u.approval));
    assert.equal(u.writes, mode === 'late-final' ? 1 : 0);
    assert.equal(u.receipt, null);
    assert.equal(u.journal.outcome, 'reconciliation-required');
  });
});
