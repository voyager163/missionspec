import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { ManagedIdentityCredential } from '@azure/identity';
import { LogsIngestionClient } from '@azure/monitor-ingestion';
import { createDefaultHttpClient, createHttpHeaders } from '@azure/core-rest-pipeline';
import { AzureLogger, setLogLevel } from '@azure/logger';
import { createStorageAdapter, azureClientOptions } from '../dist/azure-storage.js';
import { createIdentityReadiness, IDENTITY_PREPARATION_TIMEOUT_MS, IDENTITY_REFRESH_MARGIN_MS } from '../dist/identity-readiness.js';
import { createTelemetryServer } from '../dist/server.js';
import { event, post as receiverRequest, assertEmpty } from './helpers.mjs';

const limits = { headersTimeoutMs: 150, bodyTimeoutMs: 150, storageTimeoutMs: 650,
  maxConnections: 128, maxConcurrentRequests: 32, maxConcurrentIngestions: 8,
  requestsPerMinute: 3000, eventsPerDay: 100000 };
const tokenMarker = 'SYNTHETIC_NONCREDENTIAL_NOT_FOR_LOGGING';
const identityHeaderMarker = 'SYNTHETIC_IDENTITY_HEADER_NOT_FOR_LOGGING';
const evidence = [];
const cases = ['fast-control', 'slow-token', 'slow-upload', 'disconnect-token', 'disconnect-upload', 'eight-slot-quarantine',
  'prepared-disabled', 'prepared-slow-token', 'prepared-token-failure', 'prepared-token-deadline', 'prepared-expiry',
  'prepared-refresh-after', 'prepared-slow-upload', 'prepared-disconnect-upload'];

async function waitFor(condition, maximumMs = 1800) {
  const deadline = performance.now() + maximumMs;
  while (!condition()) {
    if (performance.now() >= deadline) throw new Error('LOCAL_SDK_FAULT_WAIT_EXCEEDED');
    await delay(5);
  }
}
async function scenario(t, cert, key, name, {
  tokenDelayMs = 0, uploadDelayMs = 0, prepared = false, enabled = true, tokenStatus = 200, tokenLifetimeSeconds = 3600,
} = {}) {
  const started = performance.now(), observations = [], sockets = new Set(), timers = new Set();
  const stats = { identityRequests: 0, identityAbortEvents: 0, credentialStarts: 0, credentialEnds: 0,
    ingestionTransportEntries: 0, ingestionEntriesAlreadyAborted: 0, ingestionAbortEvents: 0,
    ingestionServerPosts: 0, ingestionServiceWorkCompleted: 0, adapterStarts: 0, adapterSettled: 0, unresolved: 0, maxUnresolved: 0, clientRequests: 0 };
  let clockOffset = 0, receiver;
  let tokenClockMocked = false;
  const mark = (stage, fields = {}) => {
    const value = { stage, elapsedMs: performance.now() - started, ...fields }; observations.push(value); return value;
  };
  const sink = https.createServer({ cert, key }, (request, response) => {
    assert.equal(request.method, 'POST');
    stats.ingestionServerPosts++; mark('ingestion-server-request');
    request.resume();
    response.once('close', () => mark('ingestion-server-close', { writableFinished: response.writableFinished }));
    const finish = () => {
      stats.ingestionServiceWorkCompleted++;
      mark('ingestion-service-work-complete', { connectionDestroyed: response.destroyed });
      if (response.destroyed) { mark('ingestion-server-response-skipped-destroyed'); return; }
      response.writeHead(204, { 'Content-Length': '0' }); response.end(); mark('ingestion-server-response');
    };
    if (uploadDelayMs) timers.add(setTimeout(finish, uploadDelayMs));
    else finish();
  });
  const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); };
  sink.on('connection', track); sink.on('tlsClientError', () => {});
  sink.listen(0, '127.0.0.1'); await once(sink, 'listening');
  const actualTransport = createDefaultHttpClient(), tlsSettings = { ca: cert };
  const clientId = randomUUID();
  const credential = new ManagedIdentityCredential({ clientId, retryOptions: { maxRetries: 0 }, loggingOptions: azureClientOptions.loggingOptions,
    httpClient: {
      async sendRequest(request) {
        const url = new URL(request.url);
        assert.equal(url.hostname, '127.0.0.1'); assert.equal(url.port, '9');
        assert.equal(request.method, 'GET');
        assert.equal(url.searchParams.get('client_id'), clientId);
        assert.equal(request.headers.get('X-IDENTITY-HEADER'), identityHeaderMarker);
        stats.identityRequests++; mark('identity-transport-start', { signalPresent: Boolean(request.abortSignal), signalAborted: request.abortSignal?.aborted === true });
        request.abortSignal?.addEventListener('abort', () => { stats.identityAbortEvents++; mark('identity-transport-abort'); }, { once: true });
        await delay(tokenDelayMs);
        mark('identity-transport-resolve', { signalAborted: request.abortSignal?.aborted === true });
        return { request, status: tokenStatus, headers: createHttpHeaders(),
          bodyAsText: tokenStatus !== 200 ? '{"error":"fixture_identity_failure"}' : JSON.stringify({ access_token: tokenMarker, expires_on: String(Math.floor(Date.now() / 1000) + tokenLifetimeSeconds),
            resource: 'https://monitor.azure.com', token_type: 'Bearer' }) };
      },
    },
  });
  const getToken = credential.getToken.bind(credential);
  credential.getToken = async (scopes, options) => {
    stats.credentialStarts++; mark('credential-start', { callerSignalPresent: Boolean(options?.abortSignal) });
    options?.abortSignal?.addEventListener('abort', () => mark('credential-caller-abort'), { once: true });
    try { return await getToken(scopes, options); }
    finally { stats.credentialEnds++; mark('credential-end'); }
  };
  const identity = prepared ? createIdentityReadiness(credential) : undefined;
  const client = new LogsIngestionClient(`https://127.0.0.1:${sink.address().port}`, identity?.credential ?? credential, {
    ...azureClientOptions,
    httpClient: {
      async sendRequest(request) {
        const url = new URL(request.url);
        assert.equal(url.hostname, '127.0.0.1'); assert.equal(url.port, String(sink.address().port));
        stats.ingestionTransportEntries++;
        if (request.abortSignal?.aborted) stats.ingestionEntriesAlreadyAborted++;
        mark('ingestion-transport-entry', { signalAborted: request.abortSignal?.aborted === true });
        request.abortSignal?.addEventListener('abort', () => { stats.ingestionAbortEvents++; mark('ingestion-transport-abort'); }, { once: true });
        request.tlsSettings = tlsSettings;
        try { return await actualTransport.sendRequest(request); }
        finally { mark('ingestion-transport-settled'); }
      },
    },
  });
  client.pipeline.removePolicy({ name: 'logPolicy' });
  client.pipeline.removePolicy({ name: 'tracingPolicy' });
  const adapter = createStorageAdapter(client, 'dcr-' + 'a'.repeat(32), identity?.readiness);
  receiver = createTelemetryServer({
    enabled, limits, monotonicNow: () => performance.now() + clockOffset,
    storage: {
      ...(identity ? { readiness: identity.readiness } : {}),
      async ingest(record, signal) {
        stats.adapterStarts++; stats.unresolved++; stats.maxUnresolved = Math.max(stats.maxUnresolved, stats.unresolved);
        mark('adapter-start');
        signal.addEventListener('abort', () => mark('adapter-caller-abort'), { once: true });
        try { return await adapter.ingest(record, signal); }
        finally { stats.unresolved--; stats.adapterSettled++; mark('adapter-settled'); }
      },
    },
  });
  receiver.server.on('connection', track);
  receiver.server.on('request', (_request, response) => {
    const writeHead = response.writeHead;
    response.writeHead = function (status, ...rest) {
      mark('receiver-response-write', { status }); return writeHead.call(this, status, ...rest);
    };
    response.once('finish', () => mark('receiver-response-finish', { status: response.statusCode }));
    response.once('close', () => mark('receiver-response-close', { writableFinished: response.writableFinished }));
  });
  receiver.server.listen(0, '127.0.0.1'); await once(receiver.server, 'listening');
  async function post({ disconnectWhen } = {}) {
    stats.clientRequests++;
    const begin = performance.now();
    return new Promise((resolve, reject) => {
      let done = false, count = 0;
      const finish = value => {
        if (done) return; done = true; clearTimeout(timeout);
        const elapsedMs = performance.now() - begin; mark('local-client-result', { ...value, clientElapsedMs: elapsedMs });
        resolve({ ...value, elapsedMs });
      };
      const request = http.request({ hostname: '127.0.0.1', port: receiver.server.address().port, method: 'POST', path: '/v1/events',
        agent: false, headers: { 'content-type': 'application/json', connection: 'close' } }, response => {
        response.on('data', bytes => { count += bytes.length; if (count > 1024) { request.destroy(); reject(new Error('LOCAL_RESPONSE_BODY_BOUND')); } });
        response.once('end', () => finish({ status: response.statusCode, bodyBytes: count, noStore: response.headers['cache-control'] === 'no-store' }));
      });
      request.on('error', () => { if (disconnectWhen) finish({ disconnected: true }); else { clearTimeout(timeout); reject(new Error('LOCAL_RECEIVER_REQUEST_FAILED')); } });
      const timeout = setTimeout(() => { request.destroy(); finish({ clientTimeout: true }); }, 1000);
      request.end(JSON.stringify(event));
      if (disconnectWhen) void waitFor(disconnectWhen).then(() => {
        mark('client-disconnect'); request.destroy(); finish({ disconnected: true });
      }, () => { request.destroy(); reject(new Error('LOCAL_DISCONNECT_STAGE_NOT_REACHED')); });
    });
  }
  t.after(async () => {
    receiver.stop();
    if (tokenClockMocked) t.mock.timers.reset();
    for (const timer of timers) clearTimeout(timer);
    await waitFor(() => stats.unresolved === 0);
    await waitFor(() => stats.credentialStarts === stats.credentialEnds);
    const close = server => new Promise(resolve => {
      if (!server.listening) { resolve(); return; }
      server.close(resolve); server.closeAllConnections();
    });
    const closing = [close(receiver.server), close(sink)];
    for (const socket of sockets) socket.destroy();
    await Promise.all(closing);
    const summary = { name, prepared, tokenDelayMs, uploadDelayMs, limits, stats: { ...stats }, counters: receiver.snapshot(),
      observations, maximumClientWallMs: 1000, cleanupComplete: true, network: 'MSI simulated in-memory; ingestion transport is real SDK over loopback TLS only' };
    const text = JSON.stringify(summary);
    for (const forbidden of [tokenMarker, identityHeaderMarker, clientId, '127.0.0.1', 'Authorization']) assert(!text.includes(forbidden));
    evidence.push(summary);
  });
  return { stats, observations, receiver, post, mark, untilSettled: () => waitFor(() => stats.unresolved === 0),
    health: kind => receiverRequest(receiver.server.address().port, '', { method: 'GET', path: `/health/${kind ?? 'ready'}` }),
    untilIdentitySettled: () => waitFor(() => stats.credentialStarts === stats.credentialEnds),
    advanceTokenClock: ms => {
      t.mock.timers.enable({ apis: ['Date'], now: Date.now() + ms });
      tokenClockMocked = true;
    },
    advanceQuarantine: () => { clockOffset += 5001; } };
}

test('pinned production SDK readiness, deadline, cancellation and drain faults stay local and bounded', { timeout: 90000 }, async t => {
  const selected = process.env.MSR_LOCAL_FAULT_CASE;
  if (!selected) {
    for (const [name, expected] of [['@azure/identity', '4.13.3'], ['@azure/monitor-ingestion', '1.2.0'],
      ['@azure/core-rest-pipeline', '1.25.0'], ['@azure/msal-node', '6.0.1']]) {
      const manifest = JSON.parse(await readFile(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'));
      assert.equal(manifest.version, expected, 'PINNED_SDK_VERSION_REVIEW_REQUIRED');
    }
    const collected = [];
    for (const name of cases) await t.test(name, async () => {
      const output = process.env.MSR_LOCAL_FAULT_EVIDENCE?.replace(/sdk-fault-evidence\.json$/u, `sdk-fault-${name}.json`);
      // MSAL caches its selected identity source; isolate cases without modifying SDK internals.
      const env = { ...process.env, MSR_LOCAL_FAULT_CASE: name, ...(output ? { MSR_LOCAL_FAULT_EVIDENCE: output } : {}) };
      for (const key of Object.keys(env)) if (key.startsWith('NODE_TEST_')) delete env[key];
      try {
        const result = await promisify(execFile)(process.execPath,
          ['--no-turbofan', '--no-maglev', '--disable-sigusr1', '--test', '--test-reporter=spec', fileURLToPath(import.meta.url)],
          { env, timeout: name === 'prepared-token-deadline' ? 28000 : 6000, maxBuffer: 65536 });
        if (output) {
          await writeFile(output.replace(/\.json$/u, '.log'), result.stdout + result.stderr, { mode: 0o600, flag: 'wx' });
          collected.push(...JSON.parse(await readFile(output, 'utf8')).cases);
        }
      } catch (error) {
        if (output) await writeFile(output.replace(/\.json$/u, '.log'), String(error.stdout ?? '') + String(error.stderr ?? ''), { mode: 0o600, flag: 'wx' });
        throw new Error(`PINNED_SDK_FAULT_${name.toUpperCase().replaceAll('-', '_')}_FAILED`);
      }
    });
    if (process.env.MSR_LOCAL_FAULT_EVIDENCE) await writeFile(process.env.MSR_LOCAL_FAULT_EVIDENCE,
      JSON.stringify({ localOnly: true, separateProcessesForMsalStaticSourceIsolation: true, cases: collected }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    return;
  }
  assert(cases.includes(selected));
  const run = (name, title, callback) => name === selected ? t.test(title, callback) : Promise.resolve();
  const variables = ['IDENTITY_ENDPOINT', 'IDENTITY_HEADER', 'MSI_ENDPOINT', 'MSI_SECRET', 'IMDS_ENDPOINT',
    'IDENTITY_SERVER_THUMBPRINT', 'AZURE_FEDERATED_TOKEN_FILE', 'AZURE_CLIENT_ID', 'AZURE_TENANT_ID',
    'AZURE_AUTHORITY_HOST', 'AZURE_LOG_LEVEL', 'DEBUG'];
  const originalEnv = Object.fromEntries(variables.map(name => [name, process.env[name]]));
  for (const name of variables) delete process.env[name];
  process.env.IDENTITY_ENDPOINT = 'http://127.0.0.1:9/identity';
  process.env.IDENTITY_HEADER = identityHeaderMarker;
  setLogLevel(undefined); AzureLogger.log = () => {};
  t.after(async () => {
    for (const [name, value] of Object.entries(originalEnv)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    if (process.env.MSR_LOCAL_FAULT_EVIDENCE) {
      assert.match(process.env.MSR_LOCAL_FAULT_EVIDENCE, /^(?:infrastructure\/arm\/telemetry\/\.operator-private\/revision-[a-z0-9-]+|services\/telemetry-ingest\/\.build-cache\/readiness-[a-z0-9-]+)\/sdk-fault-[a-z-]+\.json$/u);
      await writeFile(process.env.MSR_LOCAL_FAULT_EVIDENCE, JSON.stringify({ localOnly: true, cases: evidence }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    }
  });
  // Public test-only material avoids requiring the OpenSSL CLI in the pinned slim builder.
  const { key, cert } = JSON.parse(await readFile(new URL('loopback-tls.json', import.meta.url), 'utf8'));
  await run('fast-control', 'fast token and upload control uses the actual identity, bearer, ingestion and HTTP layers', async t => {
    const f = await scenario(t, cert, key, 'fast-control');
    const response = await f.post();
    assert.equal(response.status, 204); assert.equal(response.bodyBytes, 0); assert.equal(response.noStore, true);
    await f.untilSettled();
    assert.equal(f.stats.identityRequests, 1); assert.equal(f.stats.ingestionServerPosts, 1);
    const stage = name => f.observations.find(v => v.stage === name).elapsedMs;
    assert(stage('credential-end') <= stage('ingestion-transport-entry'));
    assert(stage('ingestion-transport-entry') <= stage('ingestion-server-request'));
  });
  await run('slow-token', 'slow first token returns650ms503 while uncancelled MI work settles later without a late ingestion POST', async t => {
    const f = await scenario(t, cert, key, 'slow-token', { tokenDelayMs: 900 });
    const response = await f.post();
    assert.equal(response.status, 503); assert.equal(response.noStore, true); assert.equal(response.bodyBytes, 0);
    assert(response.elapsedMs >= 640 && response.elapsedMs < 1000);
    assert.equal(f.receiver.snapshot().storage_timeout, 1);
    assert.equal(f.stats.unresolved, 1);
    assert.equal(f.stats.identityAbortEvents, 0);
    assert.equal(f.stats.ingestionServerPosts, 0);
    assert.equal(f.receiver.ready(), false);
    f.mark('after650-response', { unresolved: f.stats.unresolved, ready: f.receiver.ready() });
    await f.untilSettled();
    assert.equal(f.stats.ingestionServerPosts, 0);
    assert.equal(f.stats.ingestionEntriesAlreadyAborted, f.stats.ingestionTransportEntries);
    assert.equal(f.receiver.snapshot().accepted, undefined);
  });
  await run('slow-upload', 'slow ingestion send is aborted by650ms and returns503 without a retry', async t => {
    const f = await scenario(t, cert, key, 'slow-upload', { uploadDelayMs: 900 });
    const response = await f.post();
    assert.equal(response.status, 503); assert.equal(response.bodyBytes, 0); assert.equal(response.noStore, true);
    assert(response.elapsedMs >= 640 && response.elapsedMs < 1000);
    await f.untilSettled();
    assert.equal(f.stats.identityRequests, 1); assert.equal(f.stats.ingestionServerPosts, 1);
    assert.equal(f.stats.ingestionAbortEvents, 1); assert.equal(f.stats.ingestionTransportEntries, 1);
    assert.equal(f.receiver.snapshot().accepted, undefined);
    await waitFor(() => f.stats.ingestionServiceWorkCompleted === 1);
    assert(f.observations.find(v => v.stage === 'ingestion-service-work-complete').connectionDestroyed);
  });
  for (const phase of ['token', 'upload']) await run('disconnect-' + phase, `client disconnect during${phase} aborts local request without pretending provider work stopped`, async t => {
    const f = await scenario(t, cert, key, 'disconnect-' + phase, phase === 'token' ? { tokenDelayMs: 900 } : { uploadDelayMs: 900 });
    const response = await f.post({ disconnectWhen: () => phase === 'token' ? f.stats.identityRequests === 1 : f.stats.ingestionServerPosts === 1 });
    assert.equal(response.disconnected, true);
    await f.untilSettled();
    assert.equal(f.receiver.snapshot().accepted, undefined);
    assert.equal(f.receiver.snapshot().cancelled, 1);
    assert.equal(f.stats.ingestionServerPosts, phase === 'token' ? 0 : 1);
    assert.equal(f.observations.filter(v => v.stage === 'receiver-response-finish').length, 0);
    if (phase === 'upload') {
      await waitFor(() => f.stats.ingestionServiceWorkCompleted === 1);
      assert(f.observations.find(v => v.stage === 'ingestion-service-work-complete').connectionDestroyed);
    }
  });
  await run('eight-slot-quarantine', 'all8 unresolved production slots remain bounded after timeout and release only after SDK settlement', async t => {
    const f = await scenario(t, cert, key, 'eight-slot-quarantine', { tokenDelayMs: 1200 });
    const requests = Array.from({ length: 8 }, () => f.post());
    await waitFor(() => f.stats.adapterStarts === 8);
    const ninth = await f.post();
    assert.equal(ninth.status, 503); assert.equal(f.stats.adapterStarts, 8);
    const responses = await Promise.all(requests);
    assert(responses.every(v => v.status === 503 && v.bodyBytes === 0));
    assert.equal(f.stats.unresolved, 8); assert.equal(f.stats.maxUnresolved, 8);
    const tenth = await f.post();
    assert.equal(tenth.status, 503); assert.equal(f.stats.adapterStarts, 8);
    assert.equal(f.receiver.ready(), false);
    f.mark('quarantined-after-responses', { unresolved: f.stats.unresolved, maxUnresolved: f.stats.maxUnresolved });
    await f.untilSettled();
    assert.equal(f.stats.ingestionServerPosts, 0);
    assert.equal(f.stats.ingestionEntriesAlreadyAborted, f.stats.ingestionTransportEntries);
    f.advanceQuarantine();
    const recovered = await f.post();
    assert.equal(recovered.status, 204); assert.equal(f.stats.ingestionServerPosts, 1);
    assert.equal(f.stats.maxUnresolved, 8);
    assert.equal(f.receiver.snapshot().storage_timeout, 8); assert.equal(f.receiver.snapshot().busy, 2);
    assert.equal(f.receiver.snapshot().accepted, 1);
  });
  await run('prepared-disabled', 'disabled receiver and real SDK constructors make zero token or upload requests', async t => {
    const f = await scenario(t, cert, key, 'prepared-disabled', { prepared: true, enabled: false });
    assertEmpty(assert, await f.health(), 204);
    assertEmpty(assert, await f.health('live'), 204);
    assert.equal((await f.post()).status, 503);
    await delay(50);
    assert.equal(f.stats.credentialStarts, 0);
    assert.equal(f.stats.identityRequests, 0);
    assert.equal(f.stats.ingestionTransportEntries, 0);
  });
  await run('prepared-slow-token', 'slow first identity acquisition is outside admission and the first event uses the prepared SDK token', async t => {
    const f = await scenario(t, cert, key, 'prepared-slow-token', { prepared: true, tokenDelayMs: 900 });
    assertEmpty(assert, await f.health(), 503);
    assertEmpty(assert, await f.health('live'), 204);
    for (let index = 0; index < 8; index++) assert.equal((await f.post()).status, 503);
    assert.equal(f.stats.identityRequests, 1);
    assert.equal(f.stats.adapterStarts, 0);
    assert.equal(f.receiver.snapshot().storage_timeout, undefined);
    await waitFor(() => f.receiver.ready());
    f.mark('identity-prepared-ready');
    assertEmpty(assert, await f.health(), 204);
    const response = await f.post();
    assert.equal(response.status, 204);
    assert(response.elapsedMs < 650);
    assert.equal(f.stats.credentialStarts, 1);
    assert.equal(f.stats.identityRequests, 1);
    assert.equal(f.stats.ingestionServerPosts, 1);
    assert.equal(f.receiver.snapshot().accepted, 1);
  });
  await run('prepared-token-failure', 'actual SDK token failure remains unready without retries or uploads', async t => {
    const f = await scenario(t, cert, key, 'prepared-token-failure', { prepared: true, tokenStatus: 400 });
    await f.untilIdentitySettled();
    for (let index = 0; index < 8; index++) {
      assertEmpty(assert, await f.health(), 503);
      assert.equal((await f.post()).status, 503);
      f.receiver.setEnabled(true);
    }
    assertEmpty(assert, await f.health('live'), 204);
    assert.equal(f.stats.identityRequests, 1);
    assert.equal(f.stats.credentialStarts, 1);
    assert.equal(f.stats.ingestionServerPosts, 0);
  });
  await run('prepared-token-deadline', '20s preparation deadline quarantines uncancelled MI work and ignores late token success', async t => {
    const f = await scenario(t, cert, key, 'prepared-token-deadline',
      { prepared: true, tokenDelayMs: IDENTITY_PREPARATION_TIMEOUT_MS + 1000 });
    await waitFor(() => f.observations.some(v => v.stage === 'credential-caller-abort'), IDENTITY_PREPARATION_TIMEOUT_MS + 800);
    f.mark('preparation-deadline-observed');
    assert.equal(f.stats.credentialEnds, 0);
    assert.equal(f.stats.identityAbortEvents, 0);
    for (let index = 0; index < 8; index++) {
      assertEmpty(assert, await f.health(), 503);
      assert.equal((await f.post()).status, 503);
      f.receiver.setEnabled(true);
    }
    await f.untilIdentitySettled();
    assertEmpty(assert, await f.health(), 503);
    assertEmpty(assert, await f.health('live'), 204);
    assert.equal(f.stats.credentialStarts, 1);
    assert.equal(f.stats.identityRequests, 1);
    assert.equal(f.stats.ingestionServerPosts, 0);
    assert.equal(f.receiver.snapshot().accepted, undefined);
  });
  for (const mode of ['expiry', 'refresh-after']) await run('prepared-' + mode, `SDK ${mode} metadata renews once outside admission and reuses the actual fresh result`, async t => {
    const lifetime = mode === 'expiry' ? 3600 : 14400;
    const f = await scenario(t, cert, key, 'prepared-' + mode,
      { prepared: true, tokenDelayMs: 50, tokenLifetimeSeconds: lifetime });
    await waitFor(() => f.receiver.ready());
    assert.equal((await f.post()).status, 204);
    assert.equal(f.stats.identityRequests, 1);
    // MSAL derives refreshOn at half-life for MI tokens whose lifetime exceeds two hours.
    f.advanceTokenClock(mode === 'expiry' ? lifetime * 1000 - IDENTITY_REFRESH_MARGIN_MS + 1000 : lifetime * 500 + 1000);
    for (let index = 0; index < 20; index++) assert.equal(f.receiver.ready(), false);
    assert.equal((await f.post()).status, 503);
    assert.equal(f.stats.identityRequests, 2);
    await waitFor(() => f.receiver.ready());
    f.mark('identity-renewed-ready');
    assert.equal((await f.post()).status, 204);
    assert.equal(f.stats.identityRequests, 2);
    assert.equal(f.stats.credentialStarts, mode === 'expiry' ? 2 : 3);
    assert.equal(f.stats.ingestionServerPosts, 2);
  });
  for (const disconnect of [false, true]) {
    const name = disconnect ? 'prepared-disconnect-upload' : 'prepared-slow-upload';
    await run(name, 'prepared identity preserves upload deadline/disconnect cancellation without retry or a provider-stop claim', async t => {
      const f = await scenario(t, cert, key, name, { prepared: true, uploadDelayMs: 900 });
      await waitFor(() => f.receiver.ready());
      const response = await f.post(disconnect ? { disconnectWhen: () => f.stats.ingestionServerPosts === 1 } : {});
      if (disconnect) assert.equal(response.disconnected, true);
      else {
        assert.equal(response.status, 503);
        assert(response.elapsedMs >= 640 && response.elapsedMs < 1000);
      }
      await f.untilSettled();
      await waitFor(() => f.stats.ingestionServiceWorkCompleted === 1);
      assert.equal(f.stats.identityRequests, 1);
      assert.equal(f.stats.ingestionServerPosts, 1);
      assert.equal(f.stats.ingestionAbortEvents, 1);
      assert.equal(f.receiver.snapshot().accepted, undefined);
      assert(f.observations.find(v => v.stage === 'ingestion-service-work-complete').connectionDestroyed);
    });
  }
});
