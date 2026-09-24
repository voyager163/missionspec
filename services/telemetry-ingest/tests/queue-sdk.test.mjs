import assert from 'node:assert/strict';
import test from 'node:test';
import https from 'node:https';
import http from 'node:http';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { gunzipSync } from 'node:zlib';
import { QueueClient } from '@azure/storage-queue';
import { LogsIngestionClient } from '@azure/monitor-ingestion';
import { createDefaultHttpClient, createPipelineRequest, createHttpHeaders } from '@azure/core-rest-pipeline';
import { toCompatResponse } from '@azure/core-http-compat';
import { AzureLogger, setLogLevel } from '@azure/logger';
import { createIdentityReadiness, STORAGE_SCOPE, INGESTION_SCOPE } from '../dist/identity-readiness.js';
import { createQueueStorage } from '../dist/queue-storage.js';
import { azureClientOptions, queueClientOptions } from '../dist/azure-storage.js';
import { createTelemetryServer } from '../dist/server.js';
import { event, post, assertEmpty } from './helpers.mjs';

const limits = { headersTimeoutMs: 150, bodyTimeoutMs: 150, storageTimeoutMs: 650,
  maxConnections: 128, maxConcurrentRequests: 32, maxConcurrentIngestions: 8,
  requestsPerMinute: 3000, eventsPerDay: 100000 };
const xmlEscape = text => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const xmlDecode = text => text.replaceAll('&quot;', '"').replaceAll('&gt;', '>').replaceAll('&lt;', '<').replaceAll('&amp;', '&');
async function until(condition, maximum = 5000) {
  const deadline = performance.now() + maximum;
  while (!condition()) { assert(performance.now() < deadline, 'LOCAL_QUEUE_FIXTURE_WAIT'); await delay(5); }
}
const evidence = [];
async function fixture(t, { enabled = true, sendStatus = 201, sendDelay = 0, uploadDelay = 0, metadataCount, monitorFail = false } = {}) {
  setLogLevel(undefined); AzureLogger.log = () => {};
  const { key, cert } = JSON.parse(await readFile(new URL('loopback-tls.json', import.meta.url), 'utf8'));
  const items = [], stats = { metadata: 0, send: 0, receive: 0, deletes: 0, upload: 0, completedUpload: 0, tokens: [] };
  const timers = new Set(), sockets = new Set();
  const later = (callback, ms) => {
    const timer = setTimeout(() => { timers.delete(timer); callback(); }, ms);
    timers.add(timer);
  };
  const itemXml = item => `<QueueMessage><MessageId>${item.id}</MessageId><InsertionTime>${item.inserted.toUTCString()}</InsertionTime><ExpirationTime>${item.expires.toUTCString()}</ExpirationTime><PopReceipt>${item.receipt}</PopReceipt><TimeNextVisible>${item.visible.toUTCString()}</TimeNextVisible><DequeueCount>${item.attempts}</DequeueCount><MessageText>${xmlEscape(item.text)}</MessageText></QueueMessage>`;
  const sink = https.createServer({ key, cert }, async (request, response) => {
    const url = new URL(request.url, 'https://localhost');
    const buffers = [];
    for await (const buffer of request) buffers.push(buffer);
    const body = Buffer.concat(buffers);
    const reply = (status, value = '', headers = {}) => {
      if (!response.destroyed) { response.writeHead(status, { 'content-type': 'application/xml', ...headers }); response.end(value); }
    };
    if (url.pathname.startsWith('/dataCollectionRules/')) {
      assert.equal(request.headers.authorization, 'Bearer fixture-monitor-token');
      assert.equal(request.method, 'POST');
      stats.upload++;
      const batch = JSON.parse(gunzipSync(body).toString());
      assert(batch.length >= 1 && batch.length <= 32);
      stats.lastBatch = batch;
      later(() => { stats.completedUpload++; reply(204); }, uploadDelay);
    } else {
      assert.equal(request.headers.authorization, 'Bearer fixture-storage-token');
      assert(url.pathname === '/account/events' || url.pathname.startsWith('/account/events/messages'));
      assert.equal(url.searchParams.get('timeout'), '5');
      if (url.searchParams.get('comp') === 'metadata') {
        assert.equal(request.method, 'GET');
        stats.metadata++;
        reply(200, '', { 'x-ms-approximate-messages-count': String(metadataCount ?? items.length) });
      } else if (request.method === 'POST') {
        stats.send++;
        assert.equal(url.searchParams.get('messagettl'), '3600');
        assert.equal(url.searchParams.get('visibilitytimeout'), '0');
        assert.equal(request.headers['content-type'], 'application/xml');
        const text = xmlDecode(/<MessageText>([\s\S]*?)<\/MessageText>/.exec(body.toString())[1]);
        assert(Buffer.byteLength(text) <= 1024);
        const item = { id: `message-${stats.send}`, receipt: 'receipt', inserted: new Date(),
          expires: new Date(Date.now() + 3600000), visible: new Date(), attempts: 0, text };
        // Persistence occurs before replying; a lost reply leaves an uncertain but durable message.
        if (sendStatus === 201) items.push(item);
        later(() => reply(sendStatus, sendStatus === 201 ? `<QueueMessagesList>${itemXml(item)}</QueueMessagesList>` :
          '<Error><Code>FixtureFailure</Code></Error>', { location: `https://127.0.0.1:${sink.address().port}/must-not-follow` }), sendDelay);
      } else if (request.method === 'GET') {
        stats.receive++;
        assert.equal(url.searchParams.get('numofmessages'), '32');
        assert.equal(url.searchParams.get('visibilitytimeout'), '60');
        const visible = items.filter(item => item.visible <= new Date()).slice(0, 32);
        for (const item of visible) { item.attempts++; item.visible = new Date(Date.now() + 60000); item.receipt = `receipt-${item.attempts}`; }
        reply(200, `<QueueMessagesList>${visible.map(itemXml).join('')}</QueueMessagesList>`);
      } else if (request.method === 'DELETE') {
        stats.deletes++;
        const index = items.findIndex(item => item.id === url.pathname.split('/').at(-1));
        assert(index >= 0);
        assert.equal(url.searchParams.get('popreceipt'), items[index].receipt);
        items.splice(index, 1);
        reply(204);
      } else assert.fail('NO_CREATE_UPDATE_OR_UNEXPECTED_QUEUE_OPERATION');
    }
  });
  sink.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  sink.on('tlsClientError', () => {});
  sink.listen(0, '127.0.0.1'); await once(sink, 'listening');
  let receiver;
  t.after(async () => {
    receiver?.stop();
    for (const timer of timers) clearTimeout(timer);
    sink.closeAllConnections();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => sink.close(resolve));
  });
  const endpoint = `https://127.0.0.1:${sink.address().port}`;
  const transport = createDefaultHttpClient();
  const storageIdentity = createIdentityReadiness({ async getToken(scope) {
    assert.equal(scope, STORAGE_SCOPE); stats.tokens.push('storage');
    return { token: 'fixture-storage-token', expiresOnTimestamp: Date.now() + 3600000 };
  } }, STORAGE_SCOPE);
  const monitorIdentity = createIdentityReadiness({ async getToken(scope) {
    assert.equal(scope, INGESTION_SCOPE); stats.tokens.push('monitor');
    if (monitorFail) throw new Error('PRIVATE_MONITOR_FAILURE');
    return { token: 'fixture-monitor-token', expiresOnTimestamp: Date.now() + 3600000 };
  } });
  const queue = new QueueClient(`${endpoint}/account/events`, storageIdentity.credential, {
    ...queueClientOptions, httpClient: { async sendRequest(request) {
      assert.equal(new URL(request.url).origin, endpoint);
      const core = createPipelineRequest({ url: request.url, method: request.method,
        headers: createHttpHeaders(request.headers.toJson()), body: request.body, abortSignal: request.abortSignal });
      core.tlsSettings = { ca: cert };
      return toCompatResponse(await transport.sendRequest(core));
    } },
  });
  const upload = new LogsIngestionClient(endpoint, monitorIdentity.credential, {
    ...azureClientOptions, httpClient: { sendRequest(request) {
      assert.equal(new URL(request.url).origin, endpoint);
      request.tlsSettings = { ca: cert };
      return transport.sendRequest(request);
    } },
  });
  upload.pipeline.removePolicy({ name: 'logPolicy' }); upload.pipeline.removePolicy({ name: 'tracingPolicy' });
  const storage = createQueueStorage({ queue, upload, ruleId: `dcr-${'a'.repeat(32)}`,
    producerIdentity: storageIdentity.readiness, consumerIdentity: monitorIdentity.readiness });
  receiver = createTelemetryServer({ storage, enabled, limits });
  receiver.server.listen(0, '127.0.0.1'); await once(receiver.server, 'listening');
  const port = receiver.server.address().port;
  return { port, receiver, storage, stats, items,
    ready: () => until(() => receiver.ready()),
    health: () => post(port, '', { path: '/health/ready', method: 'GET' }),
    post: async () => {
      const start = performance.now(), response = await post(port);
      return { ...response, elapsedMs: performance.now() - start };
    } };
}

test('actual pinned Queue SDK: durable XML send/TTL/auth ACK yields 202; >4.8s Logs ACK is independent', { timeout: 16000 }, async t => {
  assert.equal(JSON.parse(await readFile(new URL('../node_modules/@azure/storage-queue/package.json', import.meta.url))).version, '12.32.0');
  const f = await fixture(t, { uploadDelay: 5200 });
  assertEmpty(assert, await f.health(), 503);
  await f.ready();
  const response = await f.post();
  assertEmpty(assert, response, 202);
  assert(response.elapsedMs < 1000);
  assert.equal(f.stats.send, 1);
  assert.equal(f.items.length, 1);
  assert.equal(f.storage.snapshot().queued, 1);
  assert.equal(f.storage.snapshot().logs_delivered, undefined);
  const persisted = JSON.parse(f.items[0].text);
  assert.deepEqual(Object.keys(persisted).sort(), [...Object.keys(event), 'TimeGenerated'].sort());
  await until(() => f.stats.upload === 1);
  assert.equal(f.stats.deletes, 0);
  assertEmpty(assert, await f.health(), 204);
  await until(() => f.stats.deletes === 1, 6500);
  assert.equal(f.items.length, 0);
  assert.deepEqual(f.stats.lastBatch, [persisted]);
  assert.equal(f.storage.snapshot().logs_delivered, 1);
  assert.deepEqual(f.stats.tokens.sort(), ['monitor', 'storage']);
  evidence.push({ case: 'slow-logs', enqueueMs: response.elapsedMs, logsDelayMs: 5200,
    queued: f.storage.snapshot().queued, delivered: f.storage.snapshot().logs_delivered, sendRequests: f.stats.send, uploads: f.stats.upload });
});

test('actual Queue SDK never retries failed/redirected sends; timeout after persistence stays unknown', { timeout: 16000 }, async t => {
  for (const status of [500, 429, 307, 201]) await t.test(`send-${status}`, async t => {
    const f = await fixture(t, { sendStatus: status, sendDelay: status === 201 ? 900 : 0, monitorFail: true });
    await f.ready();
    const result = await f.post();
    assertEmpty(assert, result, 503);
    assert(result.elapsedMs < 1000);
    await delay(status === 201 ? 300 : 50);
    assert.equal(f.stats.send, 1);
    assert.equal(f.stats.receive, 0);
    assert.equal(f.items.length, status === 201 ? 1 : 0);
    assert.equal(f.storage.snapshot().queued, undefined);
    assert.equal(f.receiver.snapshot().queued, undefined);
    evidence.push({ case: `send-${status}`, responseMs: result.elapsedMs, queued: 0,
      durableButAckUnknown: status === 201, sendRequests: f.stats.send });
  });
});

test('disabled actual SDK wiring makes no network; full queue backpressure and invalid input make no writes', { timeout: 8000 }, async t => {
  const disabled = await fixture(t, { enabled: false });
  assertEmpty(assert, await disabled.health(), 204);
  assertEmpty(assert, await disabled.post(), 503);
  await delay(1100);
  assert.deepEqual(disabled.stats, { metadata: 0, send: 0, receive: 0, deletes: 0, upload: 0, completedUpload: 0, tokens: [] });
  const full = await fixture(t, { metadataCount: 10000, monitorFail: true });
  await until(() => full.stats.metadata === 1);
  assertEmpty(assert, await full.health(), 503);
  assertEmpty(assert, await full.post(), 503);
  assert.equal(full.stats.send, 0);
  const healthy = await fixture(t, { monitorFail: true });
  await healthy.ready();
  assertEmpty(assert, await post(healthy.port, JSON.stringify({ ...event, ip: 'forbidden' })), 400);
  assert.equal(healthy.stats.send, 0);
  assertEmpty(assert, await healthy.post(), 202);
  assert.equal(healthy.stats.receive, 0);
});

test('client disconnect after Queue persistence aborts local ACK wait without replay or delivery claims', { timeout: 5000 }, async t => {
  const f = await fixture(t, { sendDelay: 900, monitorFail: true });
  await f.ready();
  const request = http.request({ hostname: '127.0.0.1', port: f.port, path: '/v1/events', method: 'POST',
    headers: { 'content-type': 'application/json' } });
  request.on('error', () => {});
  request.end(JSON.stringify(event));
  await until(() => f.items.length === 1);
  request.destroy();
  await delay(1000);
  assert.equal(f.stats.send, 1);
  assert.equal(f.items.length, 1);
  assert.equal(f.stats.upload, 0);
  assert.equal(f.receiver.snapshot().queued, undefined);
  assert.equal(f.storage.snapshot().queued, undefined);
  assert.equal(f.storage.snapshot().queue_send_unknown, 1);
});

test.after(async () => {
  if (process.env.MSR_LOCAL_QUEUE_EVIDENCE) {
    assert.match(process.env.MSR_LOCAL_QUEUE_EVIDENCE, /^services\/telemetry-ingest\/\.build-cache\/[a-z0-9-]+\/queue-evidence\.json$/);
    await writeFile(new URL(`../../../${process.env.MSR_LOCAL_QUEUE_EVIDENCE}`, import.meta.url), JSON.stringify({ localOnly: true,
      pinnedQueueSdk: '12.32.0', transport: 'actual SDK serialization/bearer policies over loopback TLS', evidence }, null, 2) + '\n',
    { flag: 'wx', mode: 0o600 });
  }
});
