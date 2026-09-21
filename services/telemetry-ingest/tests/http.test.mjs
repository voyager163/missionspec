import assert from 'node:assert/strict';
import test from 'node:test';
import { request } from 'node:http';
import { connect } from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { assertEmpty, event, limits, post, start } from './helpers.mjs';

test('valid HTTP event is projected once with server receipt time only', async t => {
  const receiver = await start(t, { now: () => new Date('2026-01-02T03:04:05.000Z') });
  assertEmpty(assert, await post(receiver.port), 204);
  assert.deepEqual(receiver.records, [{ ...event, TimeGenerated: '2026-01-02T03:04:05.000Z' }]);
  assert(Object.isFrozen(receiver.records[0]));
  assert.deepEqual(receiver.snapshot(), { accepted: 1 });
});

test('unknown route, method, media type, encoding, and query are status-only', async t => {
  const { port, records } = await start(t);
  for (const [options, status] of [
    [{ path: '/secret/path?token=not-a-secret' }, 404],
    [{ path: '/v1/events?ignored=true' }, 404],
    [{ method: 'GET' }, 405],
    [{ headers: { 'content-type': 'text/plain' } }, 415],
    [{ headers: { 'content-type': 'application/json; charset=utf-8' } }, 415],
    [{ headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' } }, 415],
    [{ headers: { 'content-type': 'application/json', expect: '100-continue' } }, 417],
  ]) assertEmpty(assert, await post(port, JSON.stringify(event), options), status);
  assert.equal(records.length, 0);
});

test('closed schema rejects malformed, unknown, bulk, nested, type, version, enum, and extra fields', async t => {
  const { port, records } = await start(t);
  const payloads = [
    '', '{', 'null', '42', '"event"', '[]', JSON.stringify([event]), '{}',
    JSON.stringify({ ...event, schemaVersion: '1' }),
    JSON.stringify({ ...event, schemaVersion: 2 }),
    JSON.stringify({ ...event, event: 'unknown' }),
    JSON.stringify({ ...event, operation: 'discover' }),
    JSON.stringify({ ...event, outcome: 'success' }),
    JSON.stringify({ ...event, host: { name: 'copilot' } }),
    JSON.stringify({ ...event, os: 'darwin' }),
    JSON.stringify({ ...event, durationBucket: 1 }),
    JSON.stringify({ ...event, cliVersion: '1.2.3+user-path' }),
    JSON.stringify({ ...event, cliVersion: '1.2.3\n' }),
    JSON.stringify({ ...event, timestamp: '2026-01-02' }),
    JSON.stringify({ ...event, ip: 'forbidden' }),
    JSON.stringify({ ...event, __proto__: null, path: '/never-echo-me' }),
    Buffer.from([0xff, 0xfe]),
  ];
  for (const payload of payloads) assertEmpty(assert, await post(port, payload), 400);
  assert.equal(records.length, 0);
});

test('1 KiB cap applies to Content-Length and streamed chunked data before parse', async t => {
  const { port, records } = await start(t);
  assertEmpty(assert, await post(port, 'x'.repeat(1025)), 413);
  const response = await new Promise((resolve, reject) => {
    const req = request({
      hostname: '127.0.0.1', port, path: '/v1/events', method: 'POST',
      headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' },
    }, res => {
      const chunks = [];
      res.on('data', data => chunks.push(data));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.write(' '.repeat(600));
    req.write(' '.repeat(425));
    // No terminating chunk: rejection must not wait for the sender to finish.
  });
  assertEmpty(assert, response, 413);
  assert.equal(records.length, 0);
  const exact = JSON.stringify(event).padEnd(1024);
  assertEmpty(assert, await post(port, exact), 204);
});

test('body deadline bounds a slow chunked request', async t => {
  const { port, records } = await start(t, { limits: { ...limits, bodyTimeoutMs: 30 } });
  const status = await new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path: '/v1/events', method: 'POST',
      headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' } }, res => {
      res.resume(); res.once('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.write('{');
  });
  assert.equal(status, 408);
  assert.equal(records.length, 0);
});

test('storage outage is 503, with safe counters and unavailable readiness', async t => {
  let instant = 0;
  const receiver = await start(t, {
    monotonicNow: () => instant,
    storage: { async ingest() { throw new Error('sensitive body/path/credential'); } },
  });
  assertEmpty(assert, await post(receiver.port), 503);
  assert.deepEqual(receiver.snapshot(), { storage_failure: 1 });
  assertEmpty(assert, await post(receiver.port, '', { method: 'GET', path: '/health/ready' }), 503);
  assertEmpty(assert, await post(receiver.port, '', { method: 'GET', path: '/health/live' }), 204);
  instant = 5000;
  assertEmpty(assert, await post(receiver.port, '', { method: 'GET', path: '/health/ready' }), 204);
  assert.equal(receiver.snapshot().accepted, undefined);
});

test('disabled startup is ready to reject, without calling storage', async t => {
  const receiver = await start(t, { enabled: false });
  assertEmpty(assert, await post(receiver.port), 503);
  assertEmpty(assert, await post(receiver.port, '', { method: 'GET', path: '/health/ready' }), 204);
  assert.equal(receiver.records.length, 0);
});

test('timeout aborts upload and bounds unfinished work even if an adapter ignores cancellation', async t => {
  let finish;
  let signal;
  let calls = 0;
  const receiver = await start(t, {
    limits: { ...limits, storageTimeoutMs: 30, maxConcurrentIngestions: 1 },
    storage: { ingest(_record, value) {
      calls++; signal = value;
      return new Promise(resolve => { finish = resolve; });
    } },
  });
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(signal.aborted, true);
  assert.deepEqual(receiver.snapshot(), { storage_timeout: 1 });
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(calls, 1);
  finish();
  await delay(0);
});

test('client disconnect cancels in-flight storage without a success claim', async t => {
  let started;
  const began = new Promise(resolve => { started = resolve; });
  let cancelled;
  const aborted = new Promise(resolve => { cancelled = resolve; });
  const receiver = await start(t, { storage: { ingest(_record, signal) {
    started();
    return new Promise((_resolve, reject) => signal.addEventListener('abort', () => {
      cancelled(); reject(new Error('cancelled'));
    }, { once: true }));
  } } });
  const req = request({ hostname: '127.0.0.1', port: receiver.port, path: '/v1/events', method: 'POST',
    headers: { 'content-type': 'application/json' } });
  req.on('error', () => {});
  req.end(JSON.stringify(event));
  await began;
  req.destroy();
  await aborted;
  await delay(0);
  assert.equal(receiver.snapshot().accepted, undefined);
});

test('global quotas cover all clients; invalid requests consume rate budget, not upload budget', async t => {
  let instant = 0;
  const receiver = await start(t, {
    limits: { ...limits, requestsPerMinute: 2, eventsPerDay: 1 }, monotonicNow: () => instant,
  });
  assertEmpty(assert, await post(receiver.port, '{}'), 400);
  assertEmpty(assert, await post(receiver.port), 204);
  assertEmpty(assert, await post(receiver.port), 429);
  instant = 60000;
  assertEmpty(assert, await post(receiver.port), 429);
  instant = 86400000;
  assertEmpty(assert, await post(receiver.port), 204);
  assert.equal(receiver.records.length, 2);
});

test('kill switch and request concurrency are enforced without identifiers', async t => {
  const receiver = await start(t, { limits: { ...limits, maxConcurrentRequests: 1, maxConcurrentIngestions: 1 } });
  const socket = connect(receiver.port, '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  socket.write('POST /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n');
  await delay(15);
  assertEmpty(assert, await post(receiver.port), 503);
  receiver.setEnabled(false);
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(receiver.records.length, 0);
});

test('header parser and header deadline are bounded without body/header echo', async t => {
  const receiver = await start(t, { limits: { ...limits, headersTimeoutMs: 30 } });
  for (const data of [
    `POST /v1/events HTTP/1.1\r\nHost: localhost\r\nX-Private: ${'s'.repeat(5000)}\r\n\r\n`,
    `POST /v1/events HTTP/1.1\r\nHost: localhost\r\n${Array.from({ length: 25 }, (_, i) => `X-${i}: value\r\n`).join('')}\r\n`,
    'POST /v1/events HTTP/1.1\r\nHost: local',
  ]) {
    const socket = connect(receiver.port, '127.0.0.1');
    t.after(() => socket.destroy());
    let result = '';
    socket.on('data', chunk => { result += chunk; });
    await once(socket, 'connect');
    socket.write(data);
    await once(socket, 'close');
    assert.match(result, /^HTTP\/1\.1 (400|431)/);
    assert.match(result, /Cache-Control: no-store/i);
    assert.equal(result.split('\r\n\r\n')[1], '');
  }
  assert.equal(receiver.records.length, 0);
});

test('pipelined requests cannot bypass one-request sockets or get an automatic response body', async t => {
  const receiver = await start(t);
  const socket = connect(receiver.port, '127.0.0.1');
  t.after(() => socket.destroy());
  let output = '';
  socket.on('data', chunk => { output += chunk; });
  await once(socket, 'connect');
  const body = JSON.stringify(event);
  const frame = `POST /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  socket.write(frame + frame);
  await once(socket, 'close');
  await delay(0);
  assert(receiver.records.length <= 1);
  if (output) {
    assert.match(output, /Cache-Control: no-store/i);
    assert.equal(output.split('\r\n\r\n')[1], '');
  }
});
