import assert from 'node:assert/strict';
import test from 'node:test';
import https from 'node:https';
import { EventEmitter, once } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { syntheticHttp } from '../controller.mjs';
import { SYNTHETIC_FIXTURES } from '../definition.mjs';

const host = 'fixture.azurecontainerapps.io';
const secret = 'DO_NOT_RECORD_HEADER_BODY_OR_CERTIFICATE';
const keys = ['dnsCompleteMs', 'tcpConnectMs', 'tlsVerifiedMs', 'requestFinishMs', 'firstByteMs', 'responseEndMs', 'timeoutMs'];
function assertPrivate(result) {
  assert.deepEqual(Object.keys(result.timingsMs), keys);
  for (const value of Object.values(result.timingsMs)) assert(value === null || (Number.isFinite(value) && value >= 0 && value <= result.durationMs));
  const text = JSON.stringify(result);
  for (const value of [secret, host, '127.0.0.1', 'localhost', 'Authorization', 'set-cookie', 'fixture-cookie']) assert(!text.includes(value), value);
  assert.equal(result.safeHeaders, undefined);
}
async function tlsFixture(t) {
  const directory = `infrastructure/arm/telemetry/tests/.scratch-${randomUUID()}`;
  await mkdir(directory, { mode: 0o700 });
  const keyFile = `${directory}/key.pem`, certFile = `${directory}/cert.pem`;
  try {
    await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile,
      '-out', certFile, '-days', '1', '-subj', `/CN=${secret}`, '-addext', `subjectAltName=DNS:${host}`],
    { timeout: 15000, maxBuffer: 16384 });
  } catch { await rm(directory, { recursive: true }); throw new Error('LOCAL_TLS_FIXTURE_SETUP_FAILED'); }
  const [key, cert] = await Promise.all([readFile(keyFile), readFile(certFile)]);
  const sockets = new Set(), timers = new Set();
  let mode = 'complete', requests = 0;
  const server = https.createServer({ key, cert }, (request, response) => {
    requests++; request.resume();
    if (mode === 'no-response') return;
    if (mode === 'partial-headers') {
      request.socket.write('HTTP/1.1 204 No Content\r\nX-Private: ' + secret);
      return;
    }
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', secret);
    response.setHeader('Set-Cookie', 'fixture-cookie=public-test-value; Secure; HttpOnly; SameSite=Strict');
    response.setHeader('X-Private', secret);
    response.setHeader('Connection', 'close');
    if (mode === 'partial-body') {
      response.writeHead(200, { 'Content-Length': '100' }); response.write(secret.slice(0, 1)); return;
    }
    if (mode === 'oversized') {
      const body = secret.repeat(100);
      response.writeHead(200, { 'Content-Length': String(Buffer.byteLength(body)) }); response.end(body); return;
    }
    response.writeHead(204, { 'Content-Length': '0' }); response.end();
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const timer of timers) clearTimeout(timer);
    const closed = new Promise(resolve => server.close(resolve));
    server.closeAllConnections(); for (const socket of sockets) socket.destroy();
    await closed; await rm(directory, { recursive: true });
  });
  const realRequest = https.request;
  function route(t, { trust = true, dnsDelayMs = 0, responseHook = () => {} } = {}) {
    t.mock.method(https, 'request', (options, callback) => {
      assert.equal(options.hostname, host); assert.equal(options.servername, host);
      assert.equal(options.protocol, 'https:'); assert.equal(options.rejectUnauthorized, true);
      assert.equal(options.agent, false);
      return realRequest({
        ...options, port: server.address().port, ca: trust ? cert : undefined,
        lookup: (_hostname, lookupOptions, done) => {
          const finish = () => lookupOptions.all ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4);
          if (dnsDelayMs) { const timer = setTimeout(finish, dnsDelayMs); timers.add(timer); }
          else queueMicrotask(finish);
        },
      }, response => { responseHook(); callback(response); });
    });
  }
  return { route, get requests() { return requests; }, set mode(value) { mode = value; } };
}

test('actual local HTTPS records only monotonic numeric transport stages and policy booleans', async t => {
  const fixture = await tlsFixture(t);
  await t.test('complete content-free POST observes DNS/TCP/TLS/finish/first-byte/end once', async t => {
    fixture.route(t, { dnsDelayMs: 15 });
    const before = fixture.requests;
    const result = await syntheticHttp(host, 'POST', '/v1/events', SYNTHETIC_FIXTURES[0], () => {});
    assert.equal(fixture.requests - before, 1);
    assert.equal(result.status, 204); assert.equal(result.errorCode, null); assert.equal(result.bodyBytes, 0);
    assert.equal(result.headerPolicy.noStore, true); assert.equal(result.tlsVerified, true);
    assert.equal(result.failureCategory, null); assert.equal(result.failurePhase, null);
    for (const key of keys.filter(v => v !== 'timeoutMs')) assert(Number.isFinite(result.timingsMs[key]), key);
    assert.equal(result.timingsMs.timeoutMs, null);
    assert(result.timingsMs.dnsCompleteMs <= result.timingsMs.tcpConnectMs);
    assert(result.timingsMs.tcpConnectMs <= result.timingsMs.tlsVerifiedMs);
    assert(result.timingsMs.firstByteMs <= result.timingsMs.responseEndMs);
    assert(result.durationMs < 1000);
    assertPrivate(result);
  });
  await t.test('real wait for response times out at the existing maximum, without a retry', async t => {
    fixture.mode = 'no-response'; fixture.route(t);
    const before = fixture.requests;
    const result = await syntheticHttp(host, 'POST', '/v1/events', SYNTHETIC_FIXTURES[0], () => {});
    assert.equal(fixture.requests - before, 1);
    assert.equal(result.errorCode, 'TOTAL_TIMEOUT_1000MS');
    assert.equal(result.failureCategory, 'deadline');
    assert.equal(result.failurePhase, 'waiting-for-response');
    assert.equal(result.tlsVerified, true);
    assert(result.timingsMs.requestFinishMs !== null);
    assert.equal(result.timingsMs.firstByteMs, null); assert.equal(result.timingsMs.responseEndMs, null);
    assert(result.timingsMs.timeoutMs !== null && result.timingsMs.timeoutMs < 1500);
    assertPrivate(result);
    fixture.mode = 'complete';
  });
  await t.test('an earlier absolute deadline is not reset while DNS is pending', async t => {
    fixture.route(t, { dnsDelayMs: 250 });
    const before = fixture.requests;
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {}, Date.now() + 50);
    assert.equal(fixture.requests, before);
    assert.equal(result.errorCode, 'TOTAL_TIMEOUT_1000MS'); assert.equal(result.failurePhase, 'socket-or-dns');
    assert.equal(result.timingsMs.dnsCompleteMs, null); assert.equal(result.timingsMs.tlsVerifiedMs, null);
    assert(result.timingsMs.timeoutMs !== null && result.durationMs < 1000);
    const recorded = JSON.stringify(result);
    await new Promise(resolve => setTimeout(resolve, 280));
    assert.equal(JSON.stringify(result), recorded, 'Late socket callbacks cannot rewrite a finished timing record.');
    assertPrivate(result);
  });
  await t.test('untrusted TLS returns a static classification without certificate or hostname data', async t => {
    fixture.route(t, { trust: false });
    const before = fixture.requests;
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {});
    assert.equal(fixture.requests, before);
    assert.equal(result.errorCode, 'HTTPS_REQUEST_FAILED'); assert.equal(result.failureCategory, 'tls-validation');
    assert.equal(result.failurePhase, 'tls-handshake');
    assert.equal(result.tlsVerified, false); assert.equal(result.timingsMs.tlsVerifiedMs, null);
    assert.equal(result.timingsMs.firstByteMs, null);
    assertPrivate(result);
  });
  await t.test('partial response timeout is distinguished from waiting for response headers', async t => {
    fixture.mode = 'partial-body'; fixture.route(t);
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {}, Date.now() + 150);
    assert.equal(result.errorCode, 'TOTAL_TIMEOUT_1000MS');
    assert.equal(result.failurePhase, 'response-body');
    assert(result.timingsMs.firstByteMs !== null);
    assert.equal(result.timingsMs.responseEndMs, null); assert.equal(result.bodyBytes, 1);
    assertPrivate(result);
    fixture.mode = 'complete';
  });
  await t.test('first response bytes are observed without retaining incomplete header values', async t => {
    fixture.mode = 'partial-headers'; fixture.route(t);
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {}, Date.now() + 150);
    assert.equal(result.errorCode, 'TOTAL_TIMEOUT_1000MS');
    assert.equal(result.failurePhase, 'response-headers');
    assert(result.timingsMs.firstByteMs !== null);
    assert.equal(result.timingsMs.responseEndMs, null); assert.equal(result.bodyBytes, 0);
    assert.equal(result.headerPolicy, undefined);
    assertPrivate(result);
    fixture.mode = 'complete';
  });
  await t.test('body limits retain only byte counts and do not record response content', async t => {
    fixture.mode = 'oversized'; fixture.route(t);
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {});
    assert.equal(result.errorCode, 'BODY_LIMIT'); assert.equal(result.failureCategory, 'body-limit');
    assert(result.bodyBytes > 1024); assertPrivate(result);
    fixture.mode = 'complete';
  });
  await t.test('cancellation before dispatch opens no socket and produces no successful partial result', async t => {
    fixture.route(t);
    const before = fixture.requests;
    await assert.rejects(syntheticHttp(host, 'GET', '/health/live', undefined, () => { throw new Error('SYNTHETIC_CANCELLED'); }), /SYNTHETIC_CANCELLED/);
    assert.equal(fixture.requests, before);
  });
  await t.test('a late end observation never reports success even when the timeout callback has not run', async t => {
    const originalNow = performance.now.bind(performance);
    let offset = 0;
    t.mock.method(performance, 'now', () => originalNow() + offset);
    fixture.route(t, { responseHook: () => { offset = 1001; } });
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {});
    assert.equal(result.errorCode, 'TOTAL_TIMEOUT_1000MS');
    assert.equal(result.failureCategory, 'deadline');
    assert.equal(result.failurePhase, 'response-end');
    assert(result.durationMs > 1000); assert(result.timingsMs.timeoutMs >= 1000);
    assertPrivate(result);
  });
});

test('DNS and TLS error objects cannot leak messages, tokens, addresses or certificate fields', async t => {
  for (const [code, category] of [['ENOTFOUND', 'dns'], ['ERR_TLS_CERT_ALTNAME_INVALID', 'tls-validation'], ['ECONNRESET', 'transport']]) {
    await t.test(code, async t => {
      t.mock.method(https, 'request', () => {
        const request = new EventEmitter();
        request.destroy = () => {};
        request.end = () => queueMicrotask(() => request.emit('error', Object.assign(new Error(secret), {
          code, hostname: host, address: '127.0.0.1', token: secret, cert: { subject: { CN: secret } },
        })));
        return request;
      });
      const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {});
      assert.equal(result.errorCode, 'HTTPS_REQUEST_FAILED'); assert.equal(result.failureCategory, category);
      assertPrivate(result);
    });
  }
  await t.test('synchronous transport setup errors are sanitized too', async t => {
    t.mock.method(https, 'request', () => { throw Object.assign(new Error(secret), { code: 'ERR_TLS_CERT_ALTNAME_INVALID', host }); });
    const result = await syntheticHttp(host, 'GET', '/health/live', undefined, () => {});
    assert.equal(result.failureCategory, 'tls-validation'); assertPrivate(result);
  });
});
