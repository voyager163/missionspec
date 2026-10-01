import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { digest, ids, json, SYNTHETIC_FIXTURES } from '../definition.mjs';
import { PRIVATE_RUNTIME_LIMITS, privateLinkRuntimeTarget, privateRuntimePhase, verifyPrivateLinkApp,
  verifyPrivateQueueProbe, privateQueueProbeCode, qualifyPrivateLinkDelivery, verifyPrivateLinkRuntimeCompletion,
  createPrivateLinkReceiver, privateLinkRuntimeIO, publishPrivateLinkImage, preparePrivateLinkDisableRecovery,
  recoverPrivateLinkDisabled, reconcilePrivateLinkReceiver, privateWindowFence, verifyPrivateRuntimePreview,
  privateLinkWindowBinding, runPrivateLinkRuntime, preparePublicControlCleanup, recoverPublicControlCleanup,
  reconcilePublicControl, privateRuntimeIncarnation, verifyCreationDeployment, verifyRuntimeReview,
  privateLinkRuntimeBinding } from '../private-link-runtime.mjs';
import { QUEUE_RUNTIME } from '../durable-queue.mjs';
import { privateLinkCost } from '../private-link.mjs';
import { privateCostFixture } from './private-link.fixture.mjs';
import { runtimeFixture, runtimeProbeFixture } from './private-link-runtime.fixture.mjs';

const hash = value => digest(json(value));
function windowFixture() {
  const f = runtimeFixture();
  let now = f.at, flag = 'false', posted = 0, publicPresent = false, publicCreatedAt = f.at;
  const events = [], files = new Map();
  const transport = { pythonPath: '/fixed/python', pythonSha256: 'd'.repeat(64), bridgeSha256: 'e'.repeat(64) };
  const binding = privateLinkWindowBinding(f.c, f.context, f.evidence, f.candidate, f.disabled, f.instanceId, transport);
  const approvals = { enable: f.approval('private-link-bounded-enable', binding),
    disable: f.approval('private-link-false-only-disable', binding),
    publicCreate: f.approval('private-link-create-public-control', binding),
    publicDelete: f.approval('private-link-delete-public-control', binding) };
  const io = {
    now: () => now, sleep: async ms => { now += ms; }, sourceDigest: async () => f.source,
    verifyPrerequisites: () => f.prerequisites,
    published: async () => {}, verifySource: async () => {}, inventory: async () => f.candidate.publication,
    load: async name => files.get(name) ?? null,
    save: async (name, value) => files.set(name, structuredClone(value)),
    immutable: async (name, value) => { if (files.has(name)) throw new Error('UNIT_HISTORY_EXISTS'); files.set(name, structuredClone(value)); },
    reserve: async (kind, key, value) => { const name = `fence-${kind}-${key}`; if (files.has(name)) throw new Error('PRIVATE_RUNTIME_PHYSICAL_FENCE_NO_RETRY');
      files.set(name, structuredClone(value)); },
    windowHead: async intent => files.get(`fence-window-${intent.physicalKey}`),
    current: async () => ({ sourceSha256: f.source, headSha256: 'a'.repeat(64), prerequisites: f.prerequisites,
      preservedResourceIds: [ids(f.c).app, ids(f.c).environment, f.prerequisites.environment.id,
        ids(f.c).registry, ids(f.c).ingestIdentity, ids(f.c).pullIdentity] }),
    identities: async () => f.observation(flag).identities,
    observe: async target => ({ ...(target.appId === f.r.app ? f.oldObservation() :
      target.appId === f.publicTarget.appId ? f.publicObservation(publicCreatedAt) : f.observation(flag)), observedAt: new Date(now).toISOString() }),
    preview: async phase => ({ validation: { properties: { provisioningState: 'Succeeded' } },
      whatIf: { status: 'Succeeded', changes: [{ resourceId: phase.action === 'create-public-probe' ? f.publicTarget.appId : f.target.appId,
        changeType: phase.action === 'create-public-probe' ? 'Create' : 'Modify',
        ...(phase.action === 'create-public-probe' ? {} : { before: f.observation(flag).app }),
        after: phase.request.body.properties.template.resources[0] }] } }),
    deploy: async (request, guard, until, check, intent) => {
      await check(until); guard(); await intent(); guard();
      if (request.id.endsWith('-p')) { publicPresent = true; publicCreatedAt = now; events.push('create:public'); return; }
      flag = request.body.properties.template.resources[0].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value;
      events.push(`write:${flag}`);
    },
    deletePublic: async (_target, guard, until, check, intent) => {
      await check(until); guard(); await intent(); guard(); publicPresent = false; events.push('delete:public');
    },
    probe: async (_target, _observation, _candidate, _prereq, _transport, _until, guard, mode) => {
      guard(); events.push(mode === 'public-deny' ? 'public-probe' : 'probe');
      return runtimeProbeFixture(f.c, _target, _observation, _candidate, _prereq, f.source, 'a'.repeat(64), now, mode ?? 'private');
    },
    http: async (host, method, path, fixture, guard) => {
      guard(); assert.equal(host, f.target.fqdn); assert.equal(method, 'POST'); assert.equal(path, '/v1/events');
      if (flag === 'true') { posted++; events.push('post:true'); } else events.push('post:false');
      return f.http(flag === 'true' ? 202 : 503);
    },
    query: async (_workspace, _source, start, end, guard) => { guard(); events.push('query'); return f.rows(start, end); },
    read: async id => id === f.target.appId ? f.observation(flag).app :
      id === f.publicTarget.appId ? publicPresent ? f.publicObservation(publicCreatedAt).app : null :
        id.endsWith('-p/operations') ? { value: [{ properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded',
          targetResource: { id: f.publicTarget.appId } } }] } :
          id.endsWith('-p') ? { id, properties: { mode: 'Incremental', provisioningState: 'Succeeded', timestamp: new Date(publicCreatedAt).toISOString() } } :
            ({ id, properties: { approximateMessageCount: 0 } }),
  };
  const run = () => qualifyPrivateLinkDelivery(f.c, f.context, f.evidence, f.candidate, f.disabled, f.instanceId,
    approvals, transport, '/UNIT/inert', { io });
  return { ...f, io, approvals, events, files, transport, run, advance: ms => { now += ms; },
    setFlag: value => { flag = value; }, setPublic: value => { publicPresent = value; }, get posted() { return posted; } };
}

test('Private Link replacement retains original config and runtime while binding only new app/environment/FQDN', () => {
  const f = runtimeFixture(), before = structuredClone(f.c);
  const target = privateLinkRuntimeTarget(f.c, f.context, f.candidate, f.prerequisites);
  assert.notEqual(target.appId, ids(f.c).app);
  assert.notEqual(target.environmentId, ids(f.c).environment);
  verifyPrivateLinkApp(f.c, target, f.candidate, f.observation('false').app, f.observation('false').identities, 'false');
  assert.deepEqual(f.c, before);
  for (const mutate of [
    value => { value.id = ids(f.c).app; },
    value => { value.properties.managedEnvironmentId = ids(f.c).environment; },
    value => { value.properties.configuration.ingress.fqdn = 'unreviewed.azurecontainerapps.io'; },
    value => { value.properties.template.containers[0].resources.cpu = 1; },
    value => { value.properties.template.containers[0].env.push({ name: 'UNREVIEWED', value: 'true' }); },
    value => { value.properties.template.containers[0].probes = []; },
  ]) {
    const changed = f.observation('false').app; mutate(changed);
    assert.throws(() => verifyPrivateLinkApp(f.c, target, f.candidate, changed, f.observation('false').identities, 'false'));
  }
  const unpublished = structuredClone(f.candidate); unpublished.publication = null;
  assert.throws(() => privateLinkRuntimeTarget(f.c, f.context, unpublished, f.prerequisites));
});

test('fixed same-runtime queue metadata code binds identity/hostname/IP and never enqueues or prints tokens', () => {
  const f = runtimeFixture();
  const code = privateQueueProbeCode({ clientId: f.prerequisites.identity.properties.clientId,
    principalId: f.prerequisites.identity.properties.principalId, tenantId: f.c.tenantId,
    queueUrl: f.topology.ids.queueUrl, privateIp: f.target.privateIp, enabled: 'false', mode: 'private' });
  assert.match(code, /dns\.lookup/);
  assert.match(code, /rejectUnauthorized: true/);
  assert.match(code, /metadataRequests\+\+/);
  assert(!/sendMessage|\/messages|console\.|JSON\.stringify\(token/.test(code));
  verifyPrivateQueueProbe(f.probe.result, f.target, f.prerequisites.identity);
  for (const change of [
    { queueHost: 'other.queue.core.windows.net' }, { privateIp: '8.8.8.8' }, { clientId: 'wrong' },
    { tlsVerified: false }, { metadataStatus: 403 }, { enqueues: 1 }, { failureCode: 'UNKNOWN' }, { rawToken: 'secret' },
  ]) assert.throws(() => verifyPrivateQueueProbe({ ...f.probe.result, ...change }, f.target, f.prerequisites.identity));
});

test('complete bounded offline fixture requires two durable ACKs, Logs rows, drain and final disabled 503', async () => {
  const f = windowFixture();
  const result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled', JSON.stringify(result.failure));
  assert.equal(f.posted, 2);
  assert.deepEqual(f.events, ['probe', 'create:public', 'public-probe', 'write:true', 'post:true', 'post:true', 'query', 'write:false', 'post:false', 'delete:public']);
  assert.equal(result.terminalFalse, true);
  assert.equal(result.terminal503, true);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now());
  await assert.rejects(f.run(), /HISTORY_NO_RETRY/);
});

test('backend denial and ambiguous enqueue stop before a second event but still perform false-only rollback', async () => {
  for (const reason of ['probe', 'post']) {
    const f = windowFixture();
    if (reason === 'probe') f.io.probe = async () => { throw new Error('PRIVATE_QUEUE_ROUTE_UNQUALIFIED'); };
    else {
      const http = f.io.http;
      f.io.http = async (...args) => {
        const value = await http(...args);
        return value.status === 202 ? { ...value, status: null, errorCode: 'TOTAL_TIMEOUT_1000MS' } : value;
      };
    }
    const result = await f.run();
    assert.equal(result.outcome, 'stopped-disabled-unqualified');
    assert.equal(result.terminalFalse, true);
    assert.equal(result.terminal503, true);
    assert(f.posted <= 1);
    assert(f.events.includes('write:false'));
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now()));
  }
});

test('deadline after last asynchronous read stops dispatch and storage illness cannot veto rollback', async () => {
  const f = windowFixture();
  const current = f.io.current;
  let calls = 0;
  f.io.current = async () => {
    if (++calls >= 3) { f.advance(420001); throw new Error('PRIVATE_STORAGE_UNAVAILABLE'); }
    return current();
  };
  const result = await f.run();
  assert.equal(f.posted, 0);
  assert.equal(result.outcome, 'stopped-disabled-unqualified');
  assert(f.events.includes('write:false'));
  assert.equal(result.terminal503, true);
});

test('a late window still takes its separately approved false-only recovery but can never qualify', async () => {
  const f = windowFixture();
  const current = f.io.current;
  f.io.current = async () => {
    if (f.events.includes('write:true')) { f.advance(610000); throw new Error('PRIVATE_STORAGE_UNAVAILABLE'); }
    return current();
  };
  const result = await f.run();
  assert.equal(result.enabledWindowExceeded, true);
  assert.equal(result.terminalFalse, true);
  assert.equal(result.terminal503, true);
  assert.equal(result.outcome, 'stopped-disabled-unqualified');
  assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now()));
});

test('expired reviews and source drift never permit enable, and failed rollback remains unknown', async () => {
  const expired = windowFixture();
  expired.approvals.enable.expiresAt = new Date(expired.at).toISOString();
  await assert.rejects(expired.run(), /REVIEW_EXPIRED/);
  assert.deepEqual(expired.events, []);
  const drift = windowFixture();
  drift.io.published = async () => { throw new Error('PRIVATE_RUNTIME_SOURCE_CHANGED'); };
  await assert.rejects(drift.run(), /SOURCE_CHANGED/);
  const rollback = windowFixture();
  const deploy = rollback.io.deploy;
  rollback.io.deploy = async (...args) => {
    if (args[0].body.properties.template.resources[0].properties.template.containers[0].env.find(v => v.name === 'MSR_INGESTION_ENABLED').value === 'false') {
      throw new Error('PRIVATE_DISABLE_OUTCOME_UNKNOWN');
    }
    return deploy(...args);
  };
  const result = await rollback.run();
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  assert.equal(result.terminalFalse, false);
  assert.throws(() => verifyPrivateLinkRuntimeCompletion(rollback.c, rollback.context, result, rollback.io.now()));
});

test('completion evidence rejects target, request-count, producer, row, drain and extra-field changes', async () => {
  const f = windowFixture(), result = await f.run();
  for (const mutate of [
    value => { value.binding.planSha256 = '0'.repeat(64); },
    value => { value.requests.push(structuredClone(value.requests[0])); },
    value => { value.requests[0].response.status = 204; },
    value => { value.queries = []; },
    value => { value.drain.approximateMessageCount = 1; },
    value => { value.probe.result.clientId = 'unauthorized-principal'; },
    value => { value.secret = 'UNIT-secret'; },
  ]) {
    const changed = structuredClone(result); mutate(changed);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, changed, f.io.now()));
  }
});

test('production runtime adapter invokes the concrete current control proof and preserves source/deadline guards', async () => {
  const f = runtimeFixture(), calls = [];
  let now = f.at;
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    now: () => now, sourceDigest: async () => f.source, lookup: async () => f.source,
    control: {
      verifyPrivateLinkRuntimePrerequisites: () => f.prerequisites,
      currentPrivateLinkRuntimeProof: async (...args) => { calls.push(args); now += 2;
        return { sourceSha256: f.source, planSha256: hash(f.context.plan), head: { unit: true }, headSha256: hash({ unit: true }),
          prerequisites: { ...f.prerequisites, controlHeadSha256: hash({ unit: true }) }, checkedAt: new Date(now).toISOString() }; },
    },
    invoke: async () => { throw new Error('UNIT_CLOUD_MUST_NOT_RUN'); },
  });
  assert.equal((await io.current(f.at + 5)).checkedAt, new Date(f.at + 2).toISOString());
  assert.equal(calls.length, 1);
  await assert.rejects(io.current(f.at + 3), /DEADLINE/);
});

test('production dispatch checks source and deadline after asynchronous body preparation without logging secrets', async context => {
  const f = runtimeFixture(), directory = await mkdtemp(path.join(os.tmpdir(), 'msr-runtime-guard-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  f.context.plan.sourceSha256 = f.source;
  const phase = privateRuntimePhase(f.c, f.target, f.instanceId, 'enable', hash(f.disabled));
  let invoked = 0, now = f.at;
  const options = { now: () => now, control: { currentPrivateLinkRuntimeProof: async () => ({
    sourceSha256: f.source, planSha256: hash(f.context.plan), head: { unit: true }, headSha256: hash({ unit: true }),
    prerequisites: { controlHeadSha256: hash({ unit: true }) }, checkedAt: new Date(now).toISOString(),
  }) }, sourceDigest: async () => { now = f.at + 101; return f.source; },
    invoke: async () => { invoked++; throw new Error('UNIT-secret'); } };
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, directory, options);
  await assert.rejects(io.deploy(phase.request, () => {}, f.at + 100, async until => io.current(until), async () => f.at + 100), /PRIVATE_RUNTIME_DEADLINE/);
  assert.equal(invoked, 0);
  assert.deepEqual(await readdir(directory), []);
  now = f.at;
  const drift = await privateLinkRuntimeIO(f.c, f.context, f.evidence, directory,
    { ...options, sourceDigest: async () => digest('changed') });
  await assert.rejects(drift.deploy(phase.request, () => {}, f.at + 100,
    async until => drift.current(until), async () => f.at + 100), /PRIVATE_CURRENT_PROOF_CHANGED|PRIVATE_RUNTIME_SOURCE_CHANGED/);
  assert.equal(invoked, 0);
});

test('public negative control requires the same authorized identity, public DNS/TLS and network-specific denial', async () => {
  for (const change of [
    { metadataStatus: 200 }, { storageErrorCode: 'AuthenticationFailed' },
    { storageErrorCode: 'AuthorizationPermissionMismatch' }, { tokenIdentityMatched: false },
    { dnsPublic: false }, { remotePrivate: true }, { tlsVerified: false },
  ]) {
    const f = windowFixture(), probe = f.io.probe;
    f.io.probe = async (...args) => {
      const result = await probe(...args);
      if (args.at(-1) === 'public-deny') Object.assign(result.result, change);
      return result;
    };
    const result = await f.run();
    assert.equal(result.outcome, 'stopped-disabled-unqualified');
    assert.equal(f.posted, 0);
    assert(!f.events.includes('write:true'));
    assert(f.events.includes('write:false'));
  }
});

test('disabled replacement creation writes only the new app and preserves unknown outcomes without retry', async () => {
  for (const mode of ['success', 'created-between-previews', 'unknown-write']) {
    const f = windowFixture();
    let reads = 0, writes = 0;
    f.io.read = async () => ++reads === 1 || mode !== 'created-between-previews' ? null : f.observation('false').app;
    f.io.preview = async phase => ({ validation: { properties: { provisioningState: 'Succeeded' } },
      whatIf: { status: 'Succeeded', changes: [{ resourceId: f.target.appId, changeType: 'Create',
        after: phase.request.body.properties.template.resources[0] }] } });
    f.io.deploy = async (request, guard, until, check, intent) => {
      await check(until); guard(); await intent(); guard(); writes++;
      assert.match(request.id, /-plr-[a-f0-9]+-c$/);
      assert.equal(request.body.properties.template.resources[0].name, 'missionspec-test-private-ingest');
      if (mode === 'unknown-write') throw new Error('PRIVATE_WRITE_OUTCOME_UNKNOWN');
    };
    const call = () => createPrivateLinkReceiver(f.c, f.context, f.evidence, f.candidate, f.instanceId,
      f.disabled.approval, '/UNIT', { io: f.io });
    if (mode === 'success') {
      const receipt = await call();
      assert.equal(receipt.ingestionEnabled, false);
      assert.equal(receipt.target.appId, f.target.appId);
      assert.equal(writes, 1);
    } else {
      await assert.rejects(call());
      assert.equal(writes, mode === 'unknown-write' ? 1 : 0);
    }
    await assert.rejects(call(), mode === 'created-between-previews' ? /PREIMAGE|UNIT_HISTORY_EXISTS/ : /HISTORY_NO_RETRY/);
  }
});

test('real app what-if normalization accepts only known UAMI metadata and rejects policy-added identities before enable', async () => {
  for (const mutate of [
    value => { value.identity.type = 'SystemAssigned'; },
    value => { value.identity.userAssignedIdentities['/unreviewed/identity'] = {}; },
    value => { value.properties.configuration.secrets = [{ name: 'unreviewed', value: 'UNIT-sensitive' }]; },
    value => { value.properties.template.containers[0].resources.cpu = 1; },
  ]) {
    const f = windowFixture(), original = f.io.preview;
    f.io.preview = async (...args) => {
      const preview = structuredClone(await original(...args));
      mutate(preview.whatIf.changes[0].after);
      return preview;
    };
    await assert.rejects(f.run());
    assert.deepEqual(f.events, []);
  }
});

async function publicationFixture(context) {
  const f = runtimeFixture(), candidate = structuredClone(f.candidate);
  const directory = await mkdtemp(path.join(os.tmpdir(), 'msr-private-image-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const orasPath = path.join(directory, 'oras'), layoutPath = path.join(directory, 'layout');
  await writeFile(orasPath, 'UNIT reviewed uploader');
  await mkdir(path.join(layoutPath, 'blobs', 'sha256'), { recursive: true, mode: 0o700 });
  const profile = candidate.profile, manifest = JSON.parse(profile.manifestJson), layer = Buffer.from('UNIT image layer');
  manifest.layers = [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: 'sha256:' + digest(layer), size: layer.length }];
  profile.source.remoteLayerDigests = manifest.layers.map(value => value.digest);
  profile.manifestJson = json(manifest); profile.manifestDigest = 'sha256:' + digest(profile.manifestJson);
  const scan = JSON.parse(profile.scan.reportJson); scan.ArtifactName = profile.manifestDigest;
  profile.scan.reportJson = json(scan); profile.scan.reportSha256 = digest(profile.scan.reportJson);
  const qualification = JSON.parse(profile.qualification.reportJson);
  qualification.artifact.manifest = profile.manifestDigest;
  profile.qualification.reportJson = json(qualification); profile.qualification.reportSha256 = digest(profile.qualification.reportJson);
  f.context.origin.queueProfile = profile;
  candidate.review.profileSha256 = hash(profile);
  candidate.review.tag = 'receiver-' + profile.manifestDigest.slice(7, 19);
  candidate.publication = null;
  const blobs = new Map([[profile.manifestDigest, profile.manifestJson], [profile.configDigest, profile.configJson],
    [manifest.layers[0].digest, layer]]);
  for (const [sum, value] of blobs) await writeFile(path.join(layoutPath, 'blobs', 'sha256', sum.slice(7)), value);
  const local = { orasPath, orasSha256: digest('UNIT reviewed uploader'), layoutPath };
  const binding = { version: 1, configSha256: hash(f.c), planSha256: hash(f.context.plan), originSha256: hash(f.context.origin),
    controlEvidenceSha256: hash(f.evidence), candidateSha256: hash(candidate), local };
  const approval = { ...f.approval('private-link-publish-one-queued-image', binding),
    sourceSha256: candidate.review.sourceSha256, policyCommitSha: candidate.review.policyCommitSha };
  const files = new Map(), calls = [];
  let copied = false, failCopy = false, now = f.at;
  const io = {
    now: () => now, verifyPrerequisites: () => f.prerequisites, published: async () => {}, verifySource: async () => {},
    load: async name => files.get(name) ?? null,
    immutable: async (name, value) => { assert(!files.has(name)); files.set(name, structuredClone(value)); },
    reserve: async (kind, key, value) => { const name = `fence-${kind}-${key}`; if (files.has(name)) throw new Error('PRIVATE_RUNTIME_PHYSICAL_FENCE_NO_RETRY');
      files.set(name, structuredClone(value)); },
    current: async () => ({ headSha256: 'a'.repeat(64) }),
    inventory: async (_candidate, _until, published) => {
      assert.equal(published, copied);
      return { repositories: ['missionspec/telemetry-ingest'], referrers: [],
        manifests: [...candidate.priorCandidate.publication.manifests, ...(copied ? [{ digest: profile.manifestDigest, tags: [candidate.review.tag] }] : [])] };
    },
    run: async (command, args, options) => {
      calls.push([path.basename(command), ...args.slice(0, 2)]);
      if (command === 'docker') return { stdout: 'unix:///UNIT/docker.sock\n' };
      assert.equal(options.env.DOCKER_AUTH_CONFIG, undefined);
      if (command === 'az') {
        const config = path.join(options.env.DOCKER_CONFIG, 'config.json');
        await writeFile(config, json({ auths: { [`${f.c.registryName}.azurecr.io`]: { auth: 'UNIT-secret-must-not-be-logged' } } }));
        await chmod(config, 0o600);
        return { stdout: '' };
      }
      if (args[0] === 'repo') return { stdout: 'missionspec/telemetry-ingest\n' };
      if (args[0] === 'copy') {
        copied = true;
        if (failCopy) throw Object.assign(new Error('raw UNIT-secret-must-not-be-logged'), { stdout: 'UNIT-secret-must-not-be-logged' });
        return { stdout: '' };
      }
      if (args[0] === 'manifest') {
        const sum = args.at(-1).split('@')[1];
        const value = sum === candidate.legacyPublication.release.manifestDigest ? candidate.legacyPublication.manifestJson :
          sum === candidate.priorCandidate.profile.manifestDigest ? candidate.priorCandidate.profile.manifestJson : blobs.get(sum);
        return { stdout: value };
      }
      if (args[0] === 'blob') {
        await writeFile(args[args.indexOf('--output') + 1], blobs.get(args.at(-1).split('@')[1]));
        return { stdout: '' };
      }
      throw new Error('UNIT_UNEXPECTED_PROCESS');
    },
  };
  return { ...f, candidate, directory, io, local, approval, files, calls, advance: ms => { now += ms; },
    failCopy: () => { failCopy = true; },
    run: () => publishPrivateLinkImage(f.c, f.context, f.evidence, candidate, approval, local, directory, { io }) };
}

test('one reviewed third-image publication verifies graph, preserves both old images and removes isolated credentials', async context => {
  const f = await publicationFixture(context);
  const candidate = await f.run();
  assert.equal(candidate.publication.copyInvocations, 1);
  assert.equal(candidate.publication.manifests.length, 3);
  assert.equal(candidate.publication.credentialDirectoriesRemoved, true);
  assert.equal(f.calls.filter(value => value[1] === 'copy').length, 1);
  assert(!(await readdir(f.directory)).some(value => value.startsWith('image-auth-')));
  assert(!JSON.stringify([...f.files]).includes('UNIT-secret-must-not-be-logged'));
  await assert.rejects(f.run(), /HISTORY_NO_RETRY/);
});

test('unknown image copy remains held and cannot be retried, and fresh source/expiry gates precede dispatch', async context => {
  const unknown = await publicationFixture(context);
  unknown.failCopy();
  await assert.rejects(unknown.run(), /PUBLICATION_HELD/);
  assert.equal(unknown.calls.filter(value => value[1] === 'copy').length, 1);
  assert.equal(unknown.files.get('private-image-result.json').outcome, 'held-no-automatic-retry');
  assert(!JSON.stringify([...unknown.files]).includes('UNIT-secret-must-not-be-logged'));
  await assert.rejects(unknown.run(), /HISTORY_NO_RETRY/);
  const stale = await publicationFixture(context);
  stale.io.current = async () => { stale.advance(1800001); return {}; };
  await assert.rejects(stale.run(), /PUBLICATION_HELD/);
  assert.equal(stale.calls.filter(value => value[1] === 'copy').length, 0);
});

test('realistic 60s current proofs and 30s previews do not consume create or enable rollout clocks', async () => {
  const f = windowFixture();
  const current = f.io.current, preview = f.io.preview, probe = f.io.probe, deploy = f.io.deploy;
  f.io.current = async until => { f.advance(60000); assert(f.io.now() < until); return current(until); };
  f.io.preview = async (...args) => { f.advance(30000); return preview(...args); };
  f.io.probe = async (...args) => {
    // Two independently bounded 60s control reads surround a 2s remote process, while still disabled.
    f.advance(60000);
    const result = await probe(...args);
    f.advance(2000);
    result.processCompletedAt = new Date(f.io.now()).toISOString();
    f.advance(60000);
    result.after.observedAt = result.after.control.checkedAt = result.observedAt = new Date(f.io.now()).toISOString();
    assert(f.io.now() < args[5]);
    return result;
  };
  f.io.deploy = async (...args) => { await deploy(...args); f.advance(10000); };
  const start = f.io.now(), result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled', JSON.stringify(result.failure));
  assert(Date.parse(result.enableIntentAt) - start >= 394000);
  assert.equal(result.enableIntent.effectDeadline - Date.parse(result.enableIntentAt), 120000);
  assert(Date.parse(result.disable.completedAt) - Date.parse(result.enableIntentAt) < 420000);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now());

  const created = windowFixture();
  const creationCurrent = created.io.current;
  let present = false;
  created.io.read = async id => id === created.target.appId ? present ? created.observation('false').app : null : {};
  created.io.current = async until => { created.advance(60000); assert(created.io.now() < until); return creationCurrent(); };
  created.io.preview = async phase => {
    created.advance(30000);
    return { validation: { properties: { provisioningState: 'Succeeded' } }, whatIf: { status: 'Succeeded', changes: [
      { resourceId: created.target.appId, changeType: 'Create', after: phase.request.body.properties.template.resources[0] },
    ] } };
  };
  created.io.deploy = async (request, guard, until, check, intent) => {
    await check(until); guard(); await intent(); guard(); present = true; created.advance(10000);
  };
  const receipt = await createPrivateLinkReceiver(created.c, created.context, created.evidence, created.candidate,
    created.instanceId, created.disabled.approval, '/UNIT', { io: created.io });
  assert.equal(Date.parse(receipt.intent.intentAt) - created.at, 150000);
  assert.equal(receipt.intent.effectDeadline - Date.parse(receipt.intent.intentAt), 120000);
});

test('publication binds both exact plan profile and original prepared candidate before any process or read', async context => {
  for (const altered of ['profile', 'priorCandidate']) {
    const f = await publicationFixture(context);
    if (altered === 'profile') f.context.origin.queueProfile = { ...f.candidate.profile, nativeClearance: 'unreviewed' };
    else f.context.origin.receiver.candidate = { ...f.candidate.priorCandidate, version: 99 };
    await assert.rejects(f.run(), /PRIVATE_PLAN_/);
    assert.equal(f.calls.length, 0);
  }
});

test('every concrete ARM invocation including PUT is limited to 15s and no callback omission bypasses dispatch checks', async context => {
  const f = runtimeFixture(), directory = await mkdtemp(path.join(os.tmpdir(), 'private-arm-deadlines-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const calls = [];
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, directory, {
    control: {}, now: () => f.at, invoke: async (args, timeout) => { calls.push({ args, timeout }); return {}; },
  });
  await io.read(f.target.appId, '2025-07-01', f.at + 120000);
  await io.call(['rest', '--method', 'POST'], f.at + 120000, 60000);
  const request = privateRuntimePhase(f.c, f.target, f.instanceId, 'disable', hash(f.disabled)).request;
  await io.deploy(request, () => {}, f.at + 120000, async () => {}, async () => f.at + 120000);
  assert.deepEqual(calls.map(value => value.timeout), [15000, 15000, 15000]);
  await assert.rejects(io.deploy(request, () => {}, f.at + 120000), /DISPATCH_PROTOCOL_REQUIRED/);
});

test('what-if errors, incomplete pages and a changed returned Modify preimage cannot reach enable', async () => {
  for (const mutate of [
    value => { value.validation.error = { code: 'Denied' }; },
    value => { value.validation.properties.error = { code: 'Denied' }; },
    value => { value.whatIf.error = { code: 'Denied' }; },
    value => { value.whatIf.nextLink = 'more'; },
    value => { value.whatIf.changes[0].before.identity.userAssignedIdentities = {}; },
    value => { value.whatIf.changes[0].before.properties.latestRevisionName = 'changed'; },
  ]) {
    const f = windowFixture(), preview = f.io.preview;
    f.io.preview = async (...args) => { const result = structuredClone(await preview(...args)); mutate(result); return result; };
    await assert.rejects(f.run());
    assert.deepEqual(f.events, []);
  }
});

test('app changes between preview and prepared-body dispatch prevent writes including false-only drift', async () => {
  const f = windowFixture(), observe = f.io.observe;
  let reads = 0;
  f.io.observe = async (...args) => {
    const value = await observe(...args);
    if (++reads >= 3) value.app.properties.template.containers[0].resources.cpu = 2;
    return value;
  };
  const result = await f.run();
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  assert(!f.events.includes('write:true'));
  assert(!f.events.includes('write:false'));
});

test('physical incarnation fence cannot be reset by another directory, window UUID or changed review wrappers', async () => {
  const first = windowFixture();
  const result = await first.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled');
  const head = first.files.get(`fence-window-${result.intent.physicalKey}`);
  assert.deepEqual(head, privateWindowFence(result.intent));
  const second = windowFixture();
  const local = second.io.reserve;
  second.io.reserve = async (kind, key, value) => {
    if (kind === 'window' && first.files.has(`fence-window-${key}`)) throw new Error('PRIVATE_RUNTIME_PHYSICAL_FENCE_NO_RETRY');
    return local(kind, key, value);
  };
  const instanceId = '00000000-0000-4000-8000-000000000089';
  const candidate = structuredClone(second.candidate);
  candidate.review.expiresAt = '2026-09-23T08:58:00.000Z';
  candidate.publication.reviewSha256 = hash(candidate.review);
  const disabled = structuredClone(second.disabled);
  disabled.candidate = candidate;
  disabled.binding.candidateSha256 = hash(candidate);
  disabled.approval = second.approval('private-link-create-disabled-receiver', disabled.binding);
  disabled.intent.candidate = candidate; disabled.intent.binding = disabled.binding; disabled.intent.approval = disabled.approval;
  const freshBinding = privateLinkWindowBinding(second.c, second.context, second.evidence, candidate, disabled, instanceId, second.transport);
  await assert.rejects(qualifyPrivateLinkDelivery(second.c, second.context, second.evidence, candidate, disabled, instanceId,
    { enable: second.approval('private-link-bounded-enable', freshBinding), disable: second.approval('private-link-false-only-disable', freshBinding),
      publicCreate: second.approval('private-link-create-public-control', freshBinding), publicDelete: second.approval('private-link-delete-public-control', freshBinding) },
    second.transport, '/UNIT/other', { io: second.io }), /PHYSICAL_FENCE_NO_RETRY/);
  assert.equal(second.posted, 0);
});

test('restart recovery uses immutable intent and frozen published disable source with no healthy storage dependency', async () => {
  const f = windowFixture(), deploy = f.io.deploy;
  f.io.deploy = async (...args) => {
    if (args[0].id.endsWith('-d')) throw new Error('UNIT_PROCESS_INTERRUPTED');
    return deploy(...args);
  };
  const failed = await f.run();
  assert.equal(failed.outcome, 'held-terminal-state-unproven');
  const original = structuredClone([...f.files]);
  f.advance(1800001); // The old approval and original preflight have expired.
  f.io.current = async () => { throw new Error('UNIT_STORAGE_UNHEALTHY'); };
  f.io.verifyPrerequisites = () => { throw new Error('UNIT_BACKEND_MUST_NOT_GATE_FALSE'); };
  const publications = [];
  f.io.published = async (approval, frozen) => { assert.equal(frozen, true); publications.push(approval.sourceSha256); };
  f.io.deploy = deploy;
  const recoveryId = '00000000-0000-4000-8000-000000000099';
  const preparation = await preparePrivateLinkDisableRecovery(f.c, f.context, f.evidence, recoveryId, '/UNIT/restarted', { io: f.io });
  const approval = { ...f.approval('private-link-recover-frozen-false', preparation.binding),
    approvedAt: new Date(f.io.now() - 1).toISOString(), expiresAt: new Date(f.io.now() + 600000).toISOString() };
  const result = await recoverPrivateLinkDisabled(f.c, f.context, f.evidence, recoveryId, approval, '/UNIT/restarted', { io: f.io });
  assert.equal(result.outcome, 'recovered-disabled-original-outcome-retained', JSON.stringify(result.failure));
  assert.equal(result.qualification, false);
  assert.equal(f.events.filter(value => value === 'write:true').length, 1);
  assert.equal(f.events.at(-2), 'write:false');
  assert(publications.length >= 6);
  for (const [name, value] of original) assert.deepEqual(f.files.get(name), value, `Historical ${name} changed`);
  await assert.rejects(recoverPrivateLinkDisabled(f.c, f.context, f.evidence, recoveryId, approval, '/UNIT', { io: f.io }), /FENCE_NO_RETRY/);
});

test('unpublished disable authority or a replaced physical head cannot pass standalone recovery', async () => {
  for (const fault of ['source', 'head', 'request']) {
    const f = windowFixture();
    await f.run();
    if (fault === 'source') f.io.published = async () => { throw new Error('PRIVATE_RUNTIME_UNPUBLISHED_SOURCE'); };
    if (fault === 'head') f.io.windowHead = async () => ({ replaced: true });
    if (fault === 'request') f.files.get('private-window-intent.json').rollbackRequest.body.properties.template.resources[0]
      .properties.template.containers[0].env.find(value => value.name === 'MSR_INGESTION_ENABLED').value = 'true';
    const before = f.events.length;
    await assert.rejects(preparePrivateLinkDisableRecovery(f.c, f.context, f.evidence, '00000000-0000-4000-8000-000000000099', '/UNIT', { io: f.io }));
    assert.equal(f.events.length, before);
  }
});

test('frozen publication lookup is real verification, not a disable-path source bypass', async () => {
  const f = runtimeFixture(), reads = [];
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    control: {}, sourceDigest: async () => { throw new Error('UNIT_CURRENT_CHECKOUT_UNAVAILABLE'); },
    lookup: async commit => { reads.push(commit); return f.source; },
    run: async () => { throw new Error('UNIT_NO_HEAD_NEEDED_FOR_FROZEN_SOURCE'); },
    invoke: async () => { throw new Error('UNIT_BACKEND_MUST_NOT_BE_READ'); },
  });
  await io.published(f.disabled.approval, true);
  assert.deepEqual(reads, [f.disabled.approval.policyCommitSha]);
  await assert.rejects(io.published({ ...f.disabled.approval, sourceSha256: '0'.repeat(64) }, true), /UNPUBLISHED_SOURCE/);
  await assert.rejects(io.published({ ...f.disabled.approval, policyCommitSha: 'arbitrary' }, true), /UNPUBLISHED_SOURCE/);
});

test('a crash after the atomic physical reservation leaves the complete frozen intent recoverable', async () => {
  const f = windowFixture(), reserve = f.io.reserve;
  f.io.reserve = async (...args) => {
    await reserve(...args);
    if (args[0] === 'window') throw new Error('UNIT_CRASH_AFTER_GLOBAL_HEAD');
  };
  await assert.rejects(f.run(), /CRASH_AFTER_GLOBAL_HEAD/);
  const intent = f.files.get('private-window-intent.json');
  assert.deepEqual(await f.io.windowHead(intent), privateWindowFence(intent));
  assert(!f.events.includes('write:true'));
  const recoveryId = '00000000-0000-4000-8000-000000000099';
  f.io.reserve = reserve;
  const preparation = await preparePrivateLinkDisableRecovery(f.c, f.context, f.evidence, recoveryId, '/UNIT', { io: f.io });
  const result = await recoverPrivateLinkDisabled(f.c, f.context, f.evidence, recoveryId,
    f.approval('private-link-recover-frozen-false', preparation.binding), '/UNIT', { io: f.io });
  assert.equal(result.outcome, 'recovered-disabled-original-outcome-retained');
  assert.equal(f.events.filter(value => value === 'write:true').length, 0);
});

test('read-only creation reconciliation observes late success without overwriting failure history or repeating create', async () => {
  const f = windowFixture();
  f.io.read = async () => null;
  f.io.preview = async phase => ({ validation: { properties: { provisioningState: 'Succeeded' } },
    whatIf: { status: 'Succeeded', changes: [{ resourceId: f.target.appId, changeType: 'Create',
      after: phase.request.body.properties.template.resources[0] }] } });
  let writes = 0;
  f.io.deploy = async (_request, guard, until, check, intent) => {
    await check(until); guard(); await intent(); writes++;
    throw new Error('UNIT_CREATE_OUTCOME_UNKNOWN');
  };
  await assert.rejects(createPrivateLinkReceiver(f.c, f.context, f.evidence, f.candidate, f.instanceId,
    f.disabled.approval, '/UNIT', { io: f.io }), /OUTCOME_UNKNOWN/);
  const originalIntent = structuredClone(f.files.get('private-receiver-intent.json'));
  const originalFailure = structuredClone(f.files.get('private-receiver-failure.json'));
  f.advance(300000);
  f.io.read = async id => id.endsWith('/operations') ? { value: [{ properties: { provisioningOperation: 'Create',
    provisioningState: 'Succeeded', targetResource: { id: f.target.appId } } }] } :
    { id, properties: { provisioningState: 'Succeeded', mode: 'Incremental', timestamp: new Date(f.io.now()).toISOString() } };
  f.io.published = async (_approval, frozen) => assert.equal(frozen, true);
  f.io.http = async () => { throw new Error('UNIT_RECONCILIATION_MUST_NOT_POST'); };
  const result = await reconcilePrivateLinkReceiver(f.c, f.context, f.evidence,
    '00000000-0000-4000-8000-000000000098', '/UNIT', { io: f.io });
  assert.equal(result.kind, 'private-link-reconciled-disabled-receiver');
  assert.equal(result.ingestionEnabled, false);
  assert.equal(writes, 1);
  assert.deepEqual(f.files.get('private-receiver-intent.json'), originalIntent);
  assert.deepEqual(f.files.get('private-receiver-failure.json'), originalFailure);
  await assert.rejects(createPrivateLinkReceiver(f.c, f.context, f.evidence, f.candidate, f.instanceId,
    f.disabled.approval, '/UNIT', { io: f.io }), /HISTORY_NO_RETRY/);
});

test('completion binds probe Node version, revision, replica, exact code and observation times', async () => {
  const f = windowFixture(), result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled');
  for (const change of [
    value => { value.probe.result.nodeVersion = '24.0.0'; },
    value => { value.probe.revision = 'wrong'; },
    value => { value.probe.replica = 'wrong'; },
    value => { value.probe.payloadSha256 = '0'.repeat(64); },
    value => { value.probe.commandSha256 = '0'.repeat(64); },
    value => { value.probe.before.observedAt = new Date(f.at - 121000).toISOString(); },
    value => { value.probe.after.app.systemData.createdAt = new Date(f.at + 1).toISOString(); },
    value => { value.probe.processCompletedAt = new Date(f.at + 30001).toISOString(); },
    value => { value.publicProbe.before.control.sourceSha256 = '0'.repeat(64); },
  ]) {
    const changed = structuredClone(result); change(changed);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, changed, f.io.now()));
  }
});

test('patched public control is disabled, same image and identity, never receives a POST, and is absent before completion', async () => {
  const f = windowFixture(), probe = f.io.probe;
  f.io.probe = async (...args) => {
    assert.equal(args[2].profile.manifestDigest, f.candidate.profile.manifestDigest);
    assert.notEqual(args[0].appId, f.r.app);
    return probe(...args);
  };
  const result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled', JSON.stringify(result.failure));
  assert.equal(result.publicControl.intent.target.appId, f.publicTarget.appId);
  assert.equal(result.publicControl.observation.app.properties.template.containers[0].image,
    result.enabled.app.properties.template.containers[0].image);
  assert.equal(result.publicCleanup.absent, true);
  assert.equal(result.publicCleanup.absence.app, null);
  assert.equal(result.publicCleanup.deleteIntent.request.method, 'DELETE');
  assert.equal(await f.io.read(f.publicTarget.appId), null);
  assert.equal(f.events.filter(value => value === 'create:public').length, 1);
  assert.equal(f.events.filter(value => value === 'delete:public').length, 1);
  assert(Date.parse(result.publicCleanup.completedAt) - Date.parse(result.publicControl.intent.intentAt) <= 900000);
});

test('unknown public creation requires a separately reviewed generation before cleanup, never automatic delete or enable', async () => {
  const f = windowFixture(), deploy = f.io.deploy;
  f.io.deploy = async (...args) => {
    await deploy(...args);
    if (args[0].id.endsWith('-p')) throw new Error('PRIVATE_PUBLIC_CREATE_UNKNOWN');
  };
  const result = await f.run();
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  assert.equal(result.publicCleanupFailure.code, 'PRIVATE_PUBLIC_GENERATION_REVIEW_REQUIRED');
  assert(!f.events.includes('delete:public'));
  assert.equal(f.posted, 0);
  assert.equal(f.events.filter(value => value === 'create:public').length, 1);
  assert(!f.events.includes('write:true'));
  assert(f.files.has('private-public-create-intent.json'));
  assert(!f.files.has('private-public-create-receipt.json'));
  await assert.rejects(f.run(), /HISTORY_NO_RETRY/);
  const recoveryId = '00000000-0000-4000-8000-000000000091';
  const prepared = await preparePublicControlCleanup(f.c, f.context, f.evidence, recoveryId, '/UNIT', { io: f.io });
  assert.equal(prepared.generation.createReceiptSha256, null);
  assert.equal(prepared.binding.generationSha256, hash(prepared.generation));
  const recovered = await recoverPublicControlCleanup(f.c, f.context, f.evidence, recoveryId,
    f.approval('private-link-recover-public-cleanup', prepared.binding), '/UNIT', { io: f.io });
  assert.equal(recovered.receipt.absent, true);
  assert.equal(recovered.qualification, false);
  assert(!f.files.has('private-public-create-receipt.json'));
});

test('unknown public deletion supports read-only absence reconciliation without reissuing delete or rewriting history', async () => {
  const f = windowFixture(), remove = f.io.deletePublic;
  f.io.deletePublic = async (...args) => { await remove(...args); throw new Error('PRIVATE_PUBLIC_DELETE_UNKNOWN'); };
  const result = await f.run();
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  const original = structuredClone(f.files.get('private-window-result.json')), writes = f.events.length;
  const observed = await reconcilePublicControl(f.c, f.context, f.evidence,
    '00000000-0000-4000-8000-000000000096', '/UNIT', { io: f.io });
  assert.equal(observed.absent, true);
  assert.equal(observed.qualified, false);
  assert.equal(f.events.length, writes);
  assert.deepEqual(f.files.get('private-window-result.json'), original);
});

test('restart-safe public cleanup deletes only its frozen disabled app without a healthy backend or enable authority', async () => {
  const f = windowFixture(), remove = f.io.deletePublic;
  f.io.deletePublic = async () => { throw new Error('UNIT_PROCESS_STOPPED_BEFORE_DELETE'); };
  const result = await f.run();
  assert.equal(result.terminalFalse, true);
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  const original = structuredClone([...f.files]);
  f.advance(1800001);
  f.io.current = async () => { throw new Error('UNIT_NO_NETWORK_PROOF_FOR_CLEANUP'); };
  f.io.deletePublic = remove;
  f.io.published = async (_approval, frozen) => assert.equal(frozen, true);
  const recoveryId = '00000000-0000-4000-8000-000000000095';
  const prepared = await preparePublicControlCleanup(f.c, f.context, f.evidence, recoveryId, '/UNIT/restart', { io: f.io });
  const approval = { ...f.approval('private-link-recover-public-cleanup', prepared.binding),
    approvedAt: new Date(f.io.now() - 1).toISOString(), expiresAt: new Date(f.io.now() + 600000).toISOString() };
  const recovered = await recoverPublicControlCleanup(f.c, f.context, f.evidence, recoveryId, approval, '/UNIT/restart', { io: f.io });
  assert.equal(recovered.outcome, 'public-control-absent-original-history-retained', JSON.stringify(recovered.failure));
  assert.equal(recovered.qualification, false);
  assert.equal(f.events.filter(value => value === 'write:true').length, 1);
  assert.equal(await f.io.read(f.publicTarget.appId), null);
  for (const [name, value] of original) assert.deepEqual(f.files.get(name), value);
  await assert.rejects(recoverPublicControlCleanup(f.c, f.context, f.evidence, recoveryId, approval, '/UNIT', { io: f.io }), /FENCE_NO_RETRY/);
});

test('public control cannot use an old plan, a widened target or enable-shaped phase', () => {
  const f = windowFixture();
  const old = structuredClone(f.context); old.plan.version = 2;
  assert.throws(() => privateLinkWindowBinding(f.c, old, f.evidence, f.candidate, f.disabled, f.instanceId, f.transport),
    /PUBLIC_CONTROL_PLAN_REQUIRED/);
  assert.throws(() => privateRuntimePhase(f.c, f.publicTarget, f.instanceId, 'enable', hash(f.disabled)), /PHASE_TARGET/);
  assert.throws(() => privateRuntimePhase(f.c, f.target, f.instanceId, 'create-public-probe', hash(f.disabled)), /PHASE_TARGET/);
});

test('expired temporary lifetime still cleans up under valid delete authority but permanently fails qualification', async () => {
  const f = windowFixture(), current = f.io.current;
  let delayed = false;
  f.io.current = async (...args) => {
    if (!delayed && f.events.includes('write:true')) { delayed = true; f.advance(910000); throw new Error('UNIT_LATE_STORAGE_READ'); }
    return current(...args);
  };
  const result = await f.run();
  assert.equal(result.publicLifetimeExceeded, true);
  assert.equal(result.publicCleanup.absent, true);
  assert.equal(result.terminalFalse, true);
  assert.equal(result.outcome, 'stopped-disabled-unqualified');
  assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now()));
});

test('failed recovery attempts throw after retaining explicit failure results for nonzero operator exit', async () => {
  const f = windowFixture();
  await f.run();
  const recoveryId = '00000000-0000-4000-8000-000000000094';
  const prepared = await preparePrivateLinkDisableRecovery(f.c, f.context, f.evidence, recoveryId, '/UNIT', { io: f.io });
  f.io.deploy = async () => { throw new Error('UNIT_ARM_UNAVAILABLE'); };
  await assert.rejects(recoverPrivateLinkDisabled(f.c, f.context, f.evidence, recoveryId,
    f.approval('private-link-recover-frozen-false', prepared.binding), '/UNIT', { io: f.io }), /PRIVATE_DISABLE_RECOVERY_HELD/);
  const saved = f.files.get(`private-recovery-${recoveryId}-result.json`);
  assert.equal(saved.outcome, 'held-terminal-state-unproven');
  assert.equal(saved.receipt, null);
  assert.equal(saved.qualification, false);

  const g = windowFixture();
  g.io.deletePublic = async () => { throw new Error('UNIT_DELETE_UNKNOWN'); };
  await g.run();
  const preparation = await preparePublicControlCleanup(g.c, g.context, g.evidence, recoveryId, '/UNIT', { io: g.io });
  await assert.rejects(recoverPublicControlCleanup(g.c, g.context, g.evidence, recoveryId,
    g.approval('private-link-recover-public-cleanup', preparation.binding), '/UNIT', { io: g.io }), /PRIVATE_PUBLIC_CLEANUP_RECOVERY_HELD/);
  assert.equal(g.files.get(`private-public-recovery-${recoveryId}-result.json`).outcome, 'held-public-control-state-unproven');
});

test('a claimed absent public control without exact create/delete evidence or within-life timing cannot qualify', async () => {
  const f = windowFixture(), result = await f.run();
  for (const change of [
    value => { value.publicCleanup.absence.app = value.publicControl.observation.app; },
    value => { value.publicCleanup.deleteIntent.request.id = f.r.app; },
    value => { value.publicCleanup.creation.operations.value = []; },
    value => { value.publicCleanup.creation.app.systemData.createdAt = new Date(f.at - 1000).toISOString(); },
    value => { value.publicCleanup.completedAt = new Date(f.at + 900001).toISOString(); },
    value => { value.publicProbe.imageDigest = f.candidate.priorCandidate.profile.manifestDigest; },
    value => { value.publicControl.intent.approval.sourceSha256 = 'f'.repeat(64); },
  ]) {
    const value = structuredClone(result); change(value);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(f.c, f.context, value, f.io.now()));
  }
});

test('private and public app previews preserve only independently current known resources', async () => {
  const f = windowFixture(), preview = f.io.preview, actions = [];
  f.io.preview = async phase => {
    const value = await preview(phase);
    actions.push(phase.action);
    value.whatIf.changes.unshift(
      { resourceId: ids(f.c).app, changeType: 'Ignore' },
      { resourceId: ids(f.c).environment, changeType: 'NoChange' },
      { resourceId: f.prerequisites.environment.id, changeType: 'Ignore' });
    return value;
  };
  const result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled');
  assert.deepEqual(actions, ['enable', 'create-public-probe']);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now());
  for (const change of [
    value => { value.resourceId += '-unknown'; },
    value => { value.changeType = 'Modify'; },
    value => { value.error = { code: 'UNIT uncertainty' }; },
    value => { value.nextLink = 'https://unit.invalid/next'; },
  ]) {
    const negative = windowFixture(), originalPreview = negative.io.preview;
    negative.io.preview = async phase => {
      const value = await originalPreview(phase), ignored = { resourceId: ids(negative.c).app, changeType: 'Ignore' };
      change(ignored); value.whatIf.changes.push(ignored);
      return value;
    };
    await assert.rejects(negative.run(), /PRIVATE_RUNTIME_PREVIEW_SCOPE/);
    assert(!negative.events.some(value => value.startsWith('write:') || value === 'create:public'));
  }
});

test('all seven concurrent observe reads share four slots and recalculate remaining timeout after admission', async () => {
  const f = runtimeFixture(), pending = [], calls = [];
  let active = 0, maximum = 0, now = f.at;
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    control: {}, now: () => now, invoke: (args, timeout) => {
      calls.push({ args, timeout }); active++; maximum = Math.max(maximum, active);
      return new Promise(resolve => pending.push(() => { active--; resolve({}); }));
    },
  });
  const observation = io.observe(f.target, f.at + 10000);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 4);
  assert.equal(maximum, 4);
  now += 9500;
  pending.shift()();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 5);
  assert.equal(calls[4].timeout, 500);
  while (pending.length) {
    pending.splice(0).forEach(resolve => resolve());
    await new Promise(resolve => setImmediate(resolve));
  }
  await observation;
  assert.equal(calls.length, 7);
  assert.equal(maximum, 4);
});

test('queued expired or failed reads never dispatch and false recovery drains the failed epoch before restarting reads', async () => {
  for (const expired of [false, true]) {
    const f = runtimeFixture(), pending = [];
    let now = f.at, calls = 0, active = 0, maximum = 0;
    const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
      control: {}, now: () => now, invoke: () => {
        calls++; active++; maximum = Math.max(maximum, active);
        return new Promise((resolve, reject) => pending.push({
          resolve: () => { active--; resolve({}); }, reject: () => { active--; reject(new Error('UNIT_READ_FAILED')); },
        }));
      },
    });
    const observation = io.observe(f.target, f.at + 1000);
    const rejected = assert.rejects(observation, expired ? /DEADLINE/ : /UNIT_READ_FAILED/);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls, 4);
    if (expired) { now += 1001; pending.shift().resolve(); } else pending.shift().reject();
    await rejected;
    assert.equal(calls, 4);
    await assert.rejects(io.read(f.target.appId, '2025-07-01', f.at + 10000));
    const recovered = io.beginRecoveryReads(f.at + 10000);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(calls, 4);
    pending.splice(0).forEach(value => value.resolve());
    await recovered;
    const read = io.read(f.target.appId, '2025-07-01', f.at + 10000);
    assert.equal(calls, 5);
    pending.shift().resolve();
    await read;
    assert.equal(maximum, 4);
  }
});

test('mutation dispatch bypasses the occupied read queue instead of becoming a deferred guarded effect', async () => {
  const f = runtimeFixture(), pending = [], writes = [];
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    control: {}, now: () => f.at, invoke: (args, timeout) => {
      if (args[args.indexOf('--method') + 1] === 'PUT') { writes.push(timeout); return Promise.resolve({}); }
      return new Promise(resolve => pending.push(resolve));
    },
  });
  const reads = Array.from({ length: 4 }, () => io.read(f.target.appId, '2025-07-01', f.at + 20000));
  await io.call(['rest', '--method', 'PUT'], f.at + 20000);
  assert.deepEqual(writes, [15000]);
  pending.forEach(resolve => resolve({}));
  await Promise.all(reads);
});

test('provider 100ns UTC deployment times are causal while timezone-less ACA creation stays opaque', () => {
  const f = runtimeFixture(), intent = f.disabled.intent, app = f.observation('false').app;
  app.systemData.createdAt = '2026-09-23T08:09:25.4679184';
  const pin = privateRuntimeIncarnation(app);
  assert.equal(pin.createdAt, '2026-09-23T08:09:25.4679184');
  assert.equal(pin.identity.createdAtKind, 'opaque-aca');
  assert.equal(pin.identity.createdAtTicks, null);
  const deployment = { id: intent.phase.request.id, properties: { mode: 'Incremental', provisioningState: 'Succeeded',
    timestamp: '2026-09-23T16:15:06.8971817Z' } };
  const operations = { value: [{ properties: { provisioningOperation: 'Create', provisioningState: 'Succeeded',
    targetResource: { id: intent.target.appId } } }] };
  verifyCreationDeployment(intent, deployment, operations, app, '2026-09-23T16:16:00.000Z');
  assert.throws(() => verifyCreationDeployment(intent, { ...deployment, properties: { ...deployment.properties,
    timestamp: '2026-09-23T08:09:59.9999999Z' } }, operations, app, '2026-09-23T16:16:00.000Z'));
  assert.throws(() => verifyCreationDeployment(intent, { ...deployment, properties: { ...deployment.properties,
    timestamp: '2026-09-23T16:15:06.8971817' } }, operations, app, '2026-09-23T16:16:00.000Z'));
  app.systemData.createdAt = '2026-09-23T08:09:25.4679185';
  assert.notDeepEqual(privateRuntimeIncarnation(app), pin);
});

test('normal public cleanup pins the immutable created incarnation before any DELETE', async () => {
  const f = windowFixture(), read = f.io.read;
  let deletes = 0;
  f.io.deletePublic = async () => { deletes++; throw new Error('UNIT_WRONG_GENERATION_DELETE'); };
  f.io.read = async (...args) => {
    const value = await read(...args);
    if (args[0] === f.publicTarget.appId && value && f.events.includes('post:false')) {
      value.systemData.createdAt = '2026-09-23T08:09:25.4679184';
    }
    return value;
  };
  const result = await f.run();
  assert.equal(result.outcome, 'held-terminal-state-unproven');
  assert.equal(result.publicCleanupFailure.code, 'PRIVATE_PUBLIC_CLEANUP_GENERATION_CHANGED');
  assert.equal(deletes, 0);
  assert.equal(f.files.get('private-public-create-receipt.json').observation.app.systemData.createdAt, new Date(f.at).toISOString());
});

test('recovery refuses a recreated public app even with fresh cleanup approval and leaves its original receipt intact', async () => {
  const f = windowFixture(), read = f.io.read;
  f.io.deletePublic = async () => { throw new Error('UNIT_INTERRUPTED_BEFORE_DELETE'); };
  await f.run();
  const original = structuredClone(f.files.get('private-public-create-receipt.json'));
  const recoveryId = '00000000-0000-4000-8000-000000000092';
  const prepared = await preparePublicControlCleanup(f.c, f.context, f.evidence, recoveryId, '/UNIT', { io: f.io });
  assert.equal(prepared.generation.createReceiptSha256, hash(original));
  f.io.read = async (...args) => {
    const value = await read(...args);
    if (args[0] === f.publicTarget.appId && value) value.systemData.createdAt = '2026-09-23T08:09:25.4679184';
    return value;
  };
  let deletes = 0;
  f.io.deletePublic = async () => { deletes++; };
  await assert.rejects(recoverPublicControlCleanup(f.c, f.context, f.evidence, recoveryId,
    f.approval('private-link-recover-public-cleanup', prepared.binding), '/UNIT', { io: f.io }), /CLEANUP_RECOVERY_HELD/);
  assert.equal(deletes, 0);
  assert.deepEqual(f.files.get('private-public-create-receipt.json'), original);
  await assert.rejects(preparePublicControlCleanup(f.c, f.context, f.evidence,
    '00000000-0000-4000-8000-000000000093', '/UNIT', { io: f.io }), /CLEANUP_GENERATION_CHANGED/);
  assert.equal(deletes, 0);
});

function runtimeReviewFixture() {
  const f = runtimeFixture();
  f.context.plan.sourceSha256 = digest('UNIT original source');
  f.context.plan.input.overlapDays = 7;
  f.context.plan.topology.ids.managedGroup = `${f.r.sub}/resourceGroups/${f.c.namePrefix}-private-managed`;
  f.context.plan.topology.cost = privateLinkCost(7, true);
  f.context.plan.planSha256 = hash(f.context.plan);
  const cost = privateCostFixture(f, f.at);
  const revision = { version: 1, action: 'review-identical-private-link-plan-under-new-policy-source',
    configSha256: hash(f.c), planSha256: f.context.plan.planSha256, originSha256: hash(f.context.origin),
    originalSourceSha256: f.context.plan.sourceSha256, sourceSha256: f.source,
    publication: { commitSha: 'c'.repeat(40), sourceSha256: f.source },
    userInstruction: 'UNIT reviewed source refresh, never live authority',
    approvedAt: new Date(f.at - 1000).toISOString(), expiresAt: new Date(f.at + 120000).toISOString() };
  revision.userInstructionSha256 = digest(revision.userInstruction);
  return { ...f, runtimeReview: { policyRevision: revision, costReview: cost.review, costEvidence: cost.evidence } };
}

test('typed runtime review binds fresh policy, cost review and price evidence without accepting arbitrary options', () => {
  const f = runtimeReviewFixture();
  assert.equal(verifyRuntimeReview(f.c, f.context, f.runtimeReview, f.at), f.source);
  const binding = privateLinkRuntimeBinding(f.c, f.context, f.evidence, f.candidate, f.runtimeReview);
  assert.deepEqual(binding.runtimeReview, f.runtimeReview);
  for (const change of [
    value => { value.options = { invoke: 'untrusted' }; },
    value => { delete value.costEvidence; },
    value => { value.costReview.sourceSha256 = '0'.repeat(64); },
    value => { value.policyRevision.originalSourceSha256 = '0'.repeat(64); },
    value => { value.costEvidence.queries[0].response.Items[0].unitPrice = 999; },
  ]) {
    const data = structuredClone(f.runtimeReview); change(data);
    assert.throws(() => verifyRuntimeReview(f.c, f.context, data, f.at));
  }
  assert.throws(() => verifyRuntimeReview(f.c, f.context, f.runtimeReview, f.at + 120001));
});

test('closed operator JSON carries runtimeReview into preparation and exact current-proof data', async context => {
  const f = runtimeReviewFixture(), saved = new Map();
  const relative = `infrastructure/arm/telemetry/.operator-private/revision-20260930-runtime-review-${randomUUID().slice(0, 8)}`;
  context.after(() => rm(path.resolve(relative), { recursive: true, force: true }));
  const candidate = structuredClone(f.candidate); candidate.publication = null;
  const inputs = { candidate, local: { orasPath: '/UNIT/oras', orasSha256: 'a'.repeat(64), layoutPath: '/UNIT/layout' },
    runtimeReview: f.runtimeReview };
  const prepared = await runPrivateLinkRuntime(f.c, f.context, f.evidence, 'prepare-image', relative, inputs,
    { now: () => f.at, io: { verifyPrerequisites: () => f.prerequisites, now: () => f.at,
      immutable: async (name, value) => saved.set(name, value) } });
  assert.deepEqual(prepared.binding.runtimeReview, f.runtimeReview);
  assert.deepEqual(saved.get('private-image-preparation.json'), prepared);
  assert(inputs.runtimeReview, 'The explicit JSON input must not be mutated');
  await assert.rejects(runPrivateLinkRuntime(f.c, f.context, f.evidence, 'recover-disable', relative,
    { recoveryId: f.instanceId, approval: {}, runtimeReview: f.runtimeReview }, { now: () => f.at }), /REVIEW_DATA_SCOPE/);
  let selected;
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    now: () => f.at, runtimeReview: f.runtimeReview, sourceDigest: async () => f.source,
    control: { currentPrivateLinkRuntimeProof: async (_c, _context, _evidence, _directory, _invoke, options) => {
      selected = options;
      return { sourceSha256: f.source, planSha256: f.context.plan.planSha256, head: { unit: true }, headSha256: hash({ unit: true }),
        prerequisites: { controlHeadSha256: hash({ unit: true }) }, checkedAt: new Date(f.at).toISOString(),
        policyRevision: options.policyRevision, billingReview: options.costReview, costEvidence: options.costEvidence };
    } }, invoke: async () => { throw new Error('UNIT_NO_CLOUD'); },
  });
  await io.current(f.at + 1000);
  assert.deepEqual(selected.policyRevision, f.runtimeReview.policyRevision);
  assert.deepEqual(selected.costReview, f.runtimeReview.costReview);
  assert.deepEqual(selected.costEvidence, f.runtimeReview.costEvidence);
});

test('current control proof and direct observations share one four-read admission limit', async () => {
  const f = runtimeFixture(), pending = [];
  let calls = 0, active = 0, maximum = 0;
  const io = await privateLinkRuntimeIO(f.c, f.context, f.evidence, '/UNIT', {
    now: () => f.at, sourceDigest: async () => f.source,
    invoke: () => {
      calls++; active++; maximum = Math.max(maximum, active);
      return new Promise(resolve => pending.push(() => { active--; resolve({}); }));
    },
    control: { currentPrivateLinkRuntimeProof: async (_c, _context, _evidence, _directory, invoke) => {
      await Promise.all(Array.from({ length: 6 }, () => invoke(['rest', '--method', 'GET'], 15000)));
      return { sourceSha256: f.source, planSha256: hash(f.context.plan), head: { unit: true }, headSha256: hash({ unit: true }),
        prerequisites: { controlHeadSha256: hash({ unit: true }) }, checkedAt: new Date(f.at).toISOString() };
    } },
  });
  const work = Promise.all([io.observe(f.target, f.at + 120000), io.current(f.at + 120000)]);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 4);
  while (pending.length) {
    pending.splice(0).forEach(resolve => resolve());
    await new Promise(resolve => setImmediate(resolve));
  }
  await work;
  assert.equal(calls, 13);
  assert.equal(maximum, 4);
});

test('normal cleanup accepts 100ns ARM timestamps and exact opaque ACA generation without timezone inference', async () => {
  const f = windowFixture(), read = f.io.read, observe = f.io.observe;
  const opaque = '2026-09-23T08:09:25.4679184';
  f.io.observe = async (...args) => {
    const value = await observe(...args);
    if (args[0].appId === f.publicTarget.appId) value.app.systemData.createdAt = opaque;
    return value;
  };
  f.io.read = async (...args) => {
    const value = await read(...args);
    if (args[0] === f.publicTarget.appId && value) value.systemData.createdAt = opaque;
    if (args[0].endsWith('-p') && value?.properties?.timestamp) value.properties.timestamp = value.properties.timestamp.replace('.000Z', '.0000000Z');
    return value;
  };
  const result = await f.run();
  assert.equal(result.outcome, 'qualified-private-delivery-disabled', JSON.stringify(result.publicCleanupFailure));
  assert.equal(result.publicControl.observation.app.systemData.createdAt, opaque);
  assert.equal(result.publicCleanup.creation.app.systemData.createdAt, opaque);
  assert.equal(result.publicCleanup.absence.app, null);
  verifyPrivateLinkRuntimeCompletion(f.c, f.context, result, f.io.now());
});
