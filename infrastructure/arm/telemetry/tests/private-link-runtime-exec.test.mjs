import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';
import { privateQueueProbeCode, verifyPrivateQueueProbe, privateLinkExecEndpoint, runPrivateLinkProbe } from '../private-link-runtime.mjs';
import { digest } from '../definition.mjs';
import { runtimeFixture } from './private-link-runtime.fixture.mjs';

async function remoteFixture(mode, changes = {}) {
  const f = runtimeFixture(), requests = [], lookups = [], output = [];
  const expected = { clientId: f.prerequisites.identity.properties.clientId,
    principalId: f.prerequisites.identity.properties.principalId, tenantId: f.c.tenantId,
    queueUrl: f.topology.ids.queueUrl, privateIp: f.target.privateIp, enabled: 'false', mode };
  const claims = { oid: expected.principalId, appid: expected.clientId, tid: expected.tenantId,
    aud: 'https://storage.azure.com', exp: Math.floor(Date.now() / 1000) + 3600, ...(changes.claims ?? {}) };
  const token = 'unit.' + Buffer.from(JSON.stringify(claims)).toString('base64url') + '.unit-secret';
  const remoteIp = mode === 'private' ? f.target.privateIp : '20.60.1.2';
  const api = { request(url, options, callback) {
    requests.push({ hostname: url.hostname, path: url.pathname, query: url.search, options });
    assert.equal(options.lookup, undefined, 'The probe must not replace DNS lookup');
    assert.equal(options.rejectUnauthorized, true);
    const request = new EventEmitter();
    request.destroy = () => {};
    request.setTimeout = () => {};
    request.end = () => queueMicrotask(() => {
      const socket = new EventEmitter();
      socket.authorized = changes.tls !== false;
      socket.remoteAddress = changes.remoteIp ?? remoteIp;
      request.emit('socket', socket);
      socket.emit('secureConnect');
      const identity = url.hostname === '127.0.0.1';
      const response = new EventEmitter();
      response.statusCode = identity ? 200 : changes.status ?? (mode === 'private' ? 200 : 403);
      response.headers = identity || mode === 'private' ? {} : { 'x-ms-error-code': changes.storageError ?? 'AuthorizationFailure' };
      response.destroy = () => {};
      callback(response);
      response.emit('data', Buffer.from(identity ? JSON.stringify({ access_token: token }) : '<opaque-storage-response/>'));
      response.emit('end');
    });
    return request;
  } };
  const sandbox = { Buffer, URL, performance, setTimeout, clearTimeout,
    require: name => {
      if (name === 'node:fs') return { writeSync: (_fd, bytes) => { output.push(bytes); } };
      if (name === 'node:dns') return { promises: { lookup: async (name, options) => {
        lookups.push([name, options]); return [{ address: changes.dnsIp ?? remoteIp, family: 4 }];
      } } };
      if (['node:http', 'node:https'].includes(name)) return api;
      throw new Error('Unexpected generated probe dependency');
    },
    process: { env: { AZURE_CLIENT_ID: expected.clientId, AZURE_TENANT_ID: expected.tenantId,
      AZURE_QUEUE_URL: expected.queueUrl,
      MSR_INGESTION_ENABLED: 'false', IDENTITY_ENDPOINT: 'http://127.0.0.1:4234/msi/token',
      IDENTITY_HEADER: 'UNIT-sensitive-identity-header' },
    versions: { node: '24.21.0' }, getuid: () => 65532, cwd: () => '/app/services/telemetry-ingest',
    stdout: { write() {} }, stderr: { write() {} }, on() {}, exit() {} },
  };
  await vm.runInNewContext(privateQueueProbeCode(expected), sandbox, { timeout: 1000 });
  assert.equal(output.length, 1);
  assert(!output[0].includes(token));
  assert(!output[0].includes('UNIT-sensitive-identity-header'));
  return { f, requests, lookups, result: JSON.parse(output[0]) };
}

test('fixed diagnostic executes private success and natural public denial without overridden DNS, extra events or secret output', async () => {
  for (const mode of ['private', 'public-deny']) {
    const { f, requests, lookups, result } = await remoteFixture(mode);
    assert.equal(lookups.length, 1);
    assert.equal(lookups[0][0], f.target.queueHost);
    assert.equal(requests.length, 2);
    assert.equal(requests[0].hostname, '127.0.0.1');
    assert.equal(requests[1].hostname, f.target.queueHost);
    assert.equal(requests[1].query, '?comp=metadata');
    assert(requests.every(value => value.options.method === 'GET'));
    verifyPrivateQueueProbe(result, f.target, f.prerequisites.identity, mode);
  }
});

test('wrong token identity, public access success, private-path DNS drift and auth failures never qualify network denial', async () => {
  for (const [mode, changes] of [
    ['public-deny', { claims: { oid: 'other-principal' } }],
    ['public-deny', { status: 200 }],
    ['public-deny', { storageError: 'AuthenticationFailed' }],
    ['public-deny', { storageError: 'AuthorizationPermissionMismatch' }],
    ['private', { dnsIp: '20.60.1.2' }],
  ]) {
    const { f, result } = await remoteFixture(mode, changes);
    assert.notEqual(result.failureCode, null);
    assert.throws(() => verifyPrivateQueueProbe(result, f.target, f.prerequisites.identity, mode));
  }
});

test('fresh server exec endpoints bind the exact region/subscription/app/revision/replica path, not a domain suffix', () => {
  const f = runtimeFixture();
  const endpoint = privateLinkExecEndpoint(f.c, f.target, 'unit-revision', 'unit-replica');
  assert.equal(endpoint, `wss://australiaeast.azurecontainerapps.dev/subscriptions/${f.c.subscriptionId}/resourceGroups/${f.c.namePrefix}-telemetry/containerApps/${f.c.namePrefix}-private-ingest/revisions/unit-revision/replicas/unit-replica/containers/telemetry-ingest/exec`);
  assert(!endpoint.includes('/providers/Microsoft.App'));
  assert.throws(() => privateLinkExecEndpoint(f.c, f.target, '../other', 'replica'));
  assert.throws(() => privateLinkExecEndpoint(f.c, { ...f.target, appId: f.target.appId + '-other' }, 'revision', 'replica'));
});

test('real fixed Python bridge filters frames and credentials with a local inert WebSocket replacement', async () => {
  const helper = fileURLToPath(new URL('../private-link-exec.py', import.meta.url));
  const source = `
import contextlib, hashlib, importlib.metadata, io, json, runpy, sys, types
mode = sys.argv[2]
result = {"version":1,"kind":"same-container-private-queue-metadata","nodeVersion":"24.21.0","queueHost":"msrtqunittest.queue.core.windows.net",
"privateIp":"10.0.0.4","clientId":"00000000-0000-4000-8000-000000000005","principalId":"00000000-0000-4000-8000-000000000006",
"mode":"private","dnsPrivate":True,"dnsPublic":False,"tlsVerified":True,"remotePrivate":True,"remotePublic":False,
"tokenIdentityMatched":True,"metadataStatus":200,"storageErrorCode":None,"tokenRequests":1,"metadataRequests":1,
"enqueues":0,"elapsedMs":100,"failureCode":None}
if mode == "extra": result["rawToken"] = "UNIT-secret"
payload = "UNIT inert payload"
data = {"version":1,"endpoint":"wss://australiaeast.azurecontainerapps.dev/UNIT",
"token":"UNIT-secret-session-token-not-output","command":"/usr/local/bin/node --no-turbofan --no-maglev --disable-sigusr1 --max-old-space-size=64 --eval UNIT",
"payload":payload,"payloadSha256":hashlib.sha256(payload.encode()).hexdigest(),"remainingMs":30000}
calls = []
class Socket:
    def __init__(self, **kwargs):
        assert kwargs["sslopt"]["check_hostname"] is True
        self.handshake_response = types.SimpleNamespace(status=101)
        self.frames = [bytes([0,1]) + b"MSP_PRIVATE_READY" + bytes([10]), bytes([0,1]) + json.dumps(result).encode() + bytes([10])]
        if mode == "frame": self.frames[1] = bytes([0,2]) + b"UNIT-secret"
    def connect(self, url, **kwargs):
        assert kwargs["redirect_limit"] == 0
        assert kwargs["header"] == ["Authorization: Bearer " + data["token"]]
        calls.append("connect")
    def send_binary(self, value):
        assert value.startswith(bytes([0,4])) or value == bytes([0,0]) + payload.encode()
        calls.append("send")
    def recv(self): return self.frames.pop(0)
    def settimeout(self, value): assert 0 < value <= 30
    def close(self, **kwargs): calls.append("close")
sys.modules["websocket"] = types.SimpleNamespace(WebSocket=Socket, enableTrace=lambda value: None)
importlib.metadata.version = lambda name: "1.8.0"
sys.stdin = io.TextIOWrapper(io.BytesIO(json.dumps(data).encode()))
bridge = runpy.run_path(sys.argv[1])
output = io.StringIO()
with contextlib.redirect_stdout(output):
    try: bridge["main"]()
    except ValueError: print('{"status":"PRIVATE_EXEC_UNCONFIRMED"}')
assert "UNIT-secret" not in output.getvalue()
assert calls.count("connect") == 1 and calls[-1] == "close"
parsed = json.loads(output.getvalue())
assert (parsed.get("sessionClosed") is True) if mode == "valid" else (parsed.get("status") == "PRIVATE_EXEC_UNCONFIRMED")
print("offline-bridge-fixture-passed")
`;
  for (const mode of ['valid', 'frame', 'extra']) {
    const { stdout, stderr } = await promisify(execFile)('python3', ['-I', '-c', source, helper, mode],
      { timeout: 10000, maxBuffer: 4096 });
    assert.equal(stdout.trim(), 'offline-bridge-fixture-passed');
    assert.equal(stderr, '');
  }
});

test('concrete probe keeps each 60s control proof outside the 30s process budget and rechecks after final await', async context => {
  const f = runtimeFixture(), directory = await mkdtemp(path.join(os.tmpdir(), 'msr-probe-clock-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const pythonPath = path.join(directory, 'pinned-python');
  await writeFile(pythonPath, 'UNIT pinned bridge interpreter');
  const bridge = fileURLToPath(new URL('../private-link-exec.py', import.meta.url));
  const transport = { pythonPath, pythonSha256: digest('UNIT pinned bridge interpreter'), bridgeSha256: digest(await readFile(bridge)) };
  let now = f.at, proofs = 0, processBudget, late = false;
  const observation = f.observation('false'), revision = observation.app.properties.latestRevisionName;
  const replicas = { value: [{ name: 'unit-replica', properties: { containers: [{ name: 'telemetry-ingest', ready: true,
    started: true, runningState: 'Running', restartCount: 0, execEndpoint: privateLinkExecEndpoint(f.c, f.target, revision, 'unit-replica') }] } }] };
  const io = {
    now: () => now,
    current: async until => {
      now += 60000; proofs++;
      assert(now < until);
      return { sourceSha256: f.source, headSha256: 'a'.repeat(64), checkedAt: new Date(now).toISOString() };
    },
    read: async id => {
      if (late && proofs === 2) now += 600000;
      return id.endsWith('/replicas') ? structuredClone(replicas) : structuredClone(observation.app);
    },
    call: async (_args, until) => { now += 1000; assert(now < until); return { properties: { token: 'UNIT-secret-token-for-exec' } }; },
    run: (_command, _args, options) => {
      processBudget = options.timeout;
      let settle;
      const promise = new Promise(resolve => { settle = resolve; });
      promise.child = { stdin: { end: bytes => {
        const input = JSON.parse(bytes);
        assert(input.token.startsWith('UNIT-secret'));
        now += 2000;
        settle({ stdout: JSON.stringify({ version: 1, kind: 'bounded-private-queue-exec', sessions: 1,
          payloadFrames: 1, sessionClosed: true, result: f.probe.result }) });
      } } };
      return promise;
    },
  };
  const cap = f.at + 600000, guard = () => { if (now >= cap) throw new Error('UNIT_REVIEW_EXPIRED'); };
  const probe = await runPrivateLinkProbe(f.c, f.target, observation, f.candidate, f.prerequisites, transport, io, cap, guard);
  assert.equal(proofs, 2);
  assert.equal(processBudget, 30000);
  assert.equal(Date.parse(probe.processCompletedAt) - Date.parse(probe.processStartedAt), 2000);
  assert(now - f.at > 120000);
  now = f.at; proofs = 0; late = true;
  await assert.rejects(runPrivateLinkProbe(f.c, f.target, observation, f.candidate, f.prerequisites, transport, io, cap, guard),
    /UNIT_REVIEW_EXPIRED|PRIVATE_RUNTIME_DEADLINE/);
});
