import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { LogsIngestionClient } from '@azure/monitor-ingestion';
import { createHttpHeaders } from '@azure/core-rest-pipeline';
import { parseConfig, limitEnvironment, STREAM_NAME, validateRuntimeArguments } from '../dist/config.js';
import { createStorageAdapter, azureClientOptions, queueXmlSafetyPolicy, MAX_QUEUE_XML_BYTES,
  MAX_QUEUE_XML_ENTITIES } from '../dist/azure-storage.js';
import { createProjector } from '../dist/contract.js';
import { event, limits } from './helpers.mjs';

const guid = '00000000-0000-4000-8000-000000000000';
const environment = {
  MSR_BIND_HOST: '127.0.0.1', PORT: '8080', MSR_INGESTION_ENABLED: 'false',
  AZURE_SUBSCRIPTION_ID: guid, AZURE_TENANT_ID: guid, AZURE_CLIENT_ID: guid,
  MSR_RESOURCE_GROUP: 'missionspec-test',
  AZURE_DCR_RESOURCE_ID: `/subscriptions/${guid}/resourceGroups/missionspec-test/providers/Microsoft.Insights/dataCollectionRules/test`,
  AZURE_DCR_IMMUTABLE_ID: `dcr-${'0'.repeat(32)}`,
  AZURE_LOGS_ENDPOINT: 'https://synthetic.invalid.ingest.monitor.azure.com',
  AZURE_QUEUE_RESOURCE_ID: `/subscriptions/${guid}/resourceGroups/missionspec-test/providers/Microsoft.Storage/storageAccounts/msrqueuetest/queueServices/default/queues/events`,
  AZURE_QUEUE_URL: 'https://msrqueuetest.queue.core.windows.net/events',
  ...Object.fromEntries(Object.entries(limitEnvironment).map(([key, name]) => [name, String(limits[key])])),
};

test('operator config has no credential/destination/limit defaults and rejects unsafe overrides', () => {
  assert.equal(parseConfig(environment).enabled, false);
  for (const key of Object.keys(environment)) {
    assert.throws(() => parseConfig({ ...environment, [key]: undefined }), /CONFIG_MISSING/);
  }
  for (const [key, value] of [
    ['AZURE_LOGS_ENDPOINT', 'http://synthetic.invalid.ingest.monitor.azure.com'],
    ['AZURE_LOGS_ENDPOINT', 'https://ingest.monitor.azure.com.attacker.invalid'],
    ['AZURE_LOGS_ENDPOINT', 'https://user:pass@synthetic.ingest.monitor.azure.com'],
    ['AZURE_LOGS_ENDPOINT', 'https://synthetic.ingest.monitor.azure.com/path'],
    ['AZURE_LOGS_ENDPOINT', 'https://synthetic.ingest.monitor.azure.com?token=secret'],
    ['AZURE_DCR_RESOURCE_ID', environment.AZURE_DCR_RESOURCE_ID.replace('missionspec-test', 'other')],
    ['AZURE_DCR_IMMUTABLE_ID', 'arbitrary'],
    ['AZURE_QUEUE_URL', 'http://msrqueuetest.queue.core.windows.net/events'],
    ['AZURE_QUEUE_URL', 'https://msrqueuetest.queue.core.windows.net/events?sig=forbidden'],
    ['AZURE_QUEUE_URL', 'https://other.queue.core.windows.net/events'],
    ['AZURE_QUEUE_URL', 'https://msrqueuetest.queue.core.windows.net:443/events'],
    ['AZURE_QUEUE_URL', 'https://msrqueuetest.queue.core.windows.net/events/'],
    ['AZURE_QUEUE_RESOURCE_ID', environment.AZURE_QUEUE_RESOURCE_ID.replace('missionspec-test', 'foreign')],
    ['AZURE_QUEUE_RESOURCE_ID', environment.AZURE_QUEUE_RESOURCE_ID.replace('/events', '/bad--queue')],
    ['MSR_STORAGE_TIMEOUT_MS', '651'],
    ['MSR_MAX_CONCURRENT_INGESTIONS', '9'],
    ['MSR_STORAGE_TIMEOUT_MS', 'NaN'],
    ['MSR_EVENTS_PER_DAY', '1000001'],
    ['MSR_INGESTION_ENABLED', 'TRUE'],
    ['AZURE_LOG_LEVEL', 'verbose'],
    ['DEBUG', '*'],
    ['NODE_OPTIONS', '--import=not-allowed'],
    ['NODE_TLS_REJECT_UNAUTHORIZED', '0'],
    ['NODE_EXTRA_CA_CERTS', '/unreviewed/ca.pem'],
    ['APPLICATIONINSIGHTS_CONNECTION_STRING', 'private'],
    ['OTEL_EXPORTER_OTLP_ENDPOINT', 'http://invalid'],
    ['HTTPS_PROXY', 'http://invalid'],
  ]) assert.throws(() => parseConfig({ ...environment, [key]: value }), /^Error: CONFIG_/);
});

test('production startup rejects debugger and inspector runtime flags', () => {
  validateRuntimeArguments([]);
  validateRuntimeArguments(['--disable-sigusr1']);
  validateRuntimeArguments(['--no-turbofan', '--no-maglev', '--disable-sigusr1']);
  for (const argument of ['--inspect', '--inspect-brk=127.0.0.1:9229', '--inspect-wait', '--inspect-port=9229',
    '--debug', '--experimental-network-inspection', '--experimental-storage-inspection', '--experimental-worker-inspection',
    '--experimental-inspector-network-resource']) {
    assert.throws(() => validateRuntimeArguments([argument]), { code: 'CONFIG_UNSAFE_RUNTIME' });
  }
});
test('SDK transport uses a single projected record, no retry or redirect, and propagates failure', async () => {
  const record = createProjector()(event, new Date('2026-01-01T00:00:00Z'));
  for (const status of [204, 500, 429, 307]) {
    let calls = 0;
    const client = new LogsIngestionClient(environment.AZURE_LOGS_ENDPOINT, {
      async getToken() { return { token: 'synthetic-offline-token', expiresOnTimestamp: Date.now() + 60000 }; },
    }, {
      ...azureClientOptions,
      httpClient: { async sendRequest(req) {
        calls++;
        assert.deepEqual(JSON.parse(gunzipSync(req.body).toString()), [record]);
        assert.match(req.url, new RegExp(`/dataCollectionRules/${environment.AZURE_DCR_IMMUTABLE_ID}/streams/${STREAM_NAME}`));
        return { request: req, status, headers: createHttpHeaders({ location: 'https://must-not-follow.invalid' }), bodyAsText: '' };
      } },
    });
    const adapter = createStorageAdapter(client, environment.AZURE_DCR_IMMUTABLE_ID);
    const operation = adapter.ingest(record, new AbortController().signal);
    if (status === 204) await operation;
    else await assert.rejects(operation);
    assert.equal(calls, 1);
  }
});

test('adapter cancellation is checked before and after the injected uploader', async () => {
  let calls = 0;
  const controller = new AbortController();
  const storage = createStorageAdapter({ async upload(_rule, _stream, _records, options) {
    assert.equal(options.maxConcurrency, 1);
    assert.equal(options.abortSignal, controller.signal);
    calls++;
    controller.abort();
  } }, environment.AZURE_DCR_IMMUTABLE_ID);
  await assert.rejects(storage.ingest({ ...event, TimeGenerated: new Date().toISOString() }, controller.signal));
  await assert.rejects(storage.ingest({ ...event, TimeGenerated: new Date().toISOString() }, controller.signal));
  assert.equal(calls, 1);
});

test('patched parser/builder prevents the CVE-2026-41650 comment and CDATA delimiter breakout witnesses', () => {
  const requireQueue = createRequire(new URL('../node_modules/@azure/storage-queue/package.json', import.meta.url));
  const { XMLBuilder, XMLParser, XMLValidator } = requireQueue('fast-xml-parser');
  const parserManifest = new URL('../package.json', pathToFileURL(requireQueue.resolve('fast-xml-parser')));
  assert.equal(JSON.parse(readFileSync(parserManifest, 'utf8')).version, '5.7.0');
  for (const [field, payload, prefix, suffix, options] of [
    ['#comment', '--><unexpected/> <!--', '<!--', '-->', { commentPropName: '#comment' }],
    ['#cdata', ']]><unexpected/><![CDATA[', '<![CDATA[', ']]>', { cdataPropName: '#cdata' }],
  ]) {
    // This is the unsafe delimiter-interpolation witness, not a claim about old-image exploitability.
    const unsafe = `<root>${prefix}${payload}${suffix}</root>`;
    assert.equal(XMLValidator.validate(unsafe), true);
    assert(Object.hasOwn(new XMLParser().parse(unsafe).root, 'unexpected'));
    const protectedXml = new XMLBuilder(options).build({ root: { [field]: payload } });
    assert.equal(XMLValidator.validate(protectedXml), true);
    const root = new XMLParser().parse(protectedXml).root;
    assert(typeof root !== 'object' || !Object.hasOwn(root, 'unexpected'));
  }
});

test('Queue XML safety retains finite reference/byte limits and forbids DTDs without disabling entity parsing', async () => {
  assert.equal(MAX_QUEUE_XML_ENTITIES, 1000);
  assert.equal(MAX_QUEUE_XML_BYTES, 100000);
  const policy = bodyAsText => queueXmlSafetyPolicy.create({
    async sendRequest() { return { bodyAsText }; },
  });
  for (const body of ['', `<root>${'&quot;'.repeat(1000)}</root>`, 'x'.repeat(100000)]) {
    assert.equal((await policy(body).sendRequest({})).bodyAsText, body);
  }
  for (const body of [`<root>${'&quot;'.repeat(1001)}</root>`, 'x'.repeat(100001),
    '<!DOCTYPE root [<!ENTITY value "text">]><root>&value;</root>']) {
    await assert.rejects(policy(body).sendRequest({}), /QUEUE_XML_UNSAFE/);
  }
});

test('module imports are inert and startup fails with only a safe code', () => {
  const imported = spawnSync(process.execPath, ['--input-type=module', '-e',
    "await import('./dist/main.js'); await import('./dist/server.js'); await import('./dist/azure-storage.js');"],
  { cwd: new URL('../', import.meta.url), env: {}, encoding: 'utf8', timeout: 3000 });
  assert.equal(imported.status, 0, imported.stderr);
  assert.equal(imported.stdout + imported.stderr, '');
  const started = spawnSync(process.execPath, ['dist/main.js'], {
    cwd: new URL('../', import.meta.url), env: {}, encoding: 'utf8', timeout: 3000,
  });
  assert.equal(started.status, 1);
  assert.equal(started.stdout, '');
  assert.equal(started.stderr, 'CONFIG_MISSING\n');
});

test('production storage wiring stays inert while disabled and identity failures expose no raw errors', () => {
  const setupTimeoutMs = 10000;
  const executionTimeoutMs = 5000;
  const script = `
    import assert from 'node:assert/strict';
    import { once } from 'node:events';
    import { writeSync } from 'node:fs';
    import { request } from 'node:http';
    import { setImmediate as turn } from 'node:timers/promises';
    let receiver, timer, phase;
    const stage = (name, budget) => {
      phase = name;
      writeSync(3, name + '\\n');
      if (budget !== undefined) {
        clearTimeout(timer);
        timer = setTimeout(() => {
          writeSync(3, phase + '_TIMEOUT\\n');
          process.exit(1);
        }, budget);
      }
    };
    // Own and drain each test connection instead of leaving a global fetch dispatcher to settle.
    async function status(port, path, method = 'GET') {
      let req, socketClosed = Promise.resolve();
      const response = new Promise((resolve, reject) => {
        req = request({ hostname: '127.0.0.1', port, path, method, agent: false }, res => {
          res.once('error', () => reject(new Error('FIXTURE_HTTP_FAILED')));
          res.resume();
          res.once('end', () => resolve(res.statusCode));
        });
        req.once('socket', socket => { socketClosed = new Promise(resolve => socket.once('close', resolve)); });
        req.once('error', () => reject(new Error('FIXTURE_HTTP_FAILED')));
        req.end();
      });
      const timeout = setTimeout(() => req.destroy(new Error('FIXTURE_HTTP_TIMEOUT')), 1000);
      try {
        const code = await response;
        await socketClosed;
        return code;
      } finally {
        req.destroy();
        await socketClosed;
        clearTimeout(timeout);
      }
    }
    stage('SETUP', ${setupTimeoutMs});
    try {
      const { ManagedIdentityCredential } = await import('@azure/identity');
      const { createAzureStorage } = await import('./dist/azure-storage.js');
      const { createTelemetryServer } = await import('./dist/server.js');
      let tokens = 0;
      ManagedIdentityCredential.prototype.getToken = async function () {
        assert.equal(this.clientId, ${JSON.stringify(guid)});
        tokens++;
        throw new Error('PRIVATE_IDENTITY_TOKEN_ENV_RAW_ERROR');
      };
      const storage = await createAzureStorage(${JSON.stringify(parseConfig(environment).azure)});
      assert.equal(tokens, 0);
      receiver = createTelemetryServer({ storage, enabled: false, limits: ${JSON.stringify(limits)} });
      assert.equal(tokens, 0);
      receiver.server.listen(0, '127.0.0.1');
      await once(receiver.server, 'listening');
      stage('ASSERTIONS', ${executionTimeoutMs});
      const port = receiver.server.address().port;
      assert.equal(await status(port, '/health/ready'), 204);
      assert.equal(await status(port, '/v1/events', 'POST'), 503);
      assert.equal(tokens, 0);
      receiver.setEnabled(true);
      await turn();
      assert.equal(await status(port, '/health/ready'), 503);
      assert.equal(await status(port, '/health/live'), 204);
      assert.equal(await status(port, '/v1/events', 'POST'), 503);
      assert.equal(tokens, 2);
    } finally {
      stage('CLEANUP');
      if (receiver) {
        const closed = receiver.server.listening ? once(receiver.server, 'close') : Promise.resolve();
        receiver.stop();
        await closed;
        await turn();
      }
      clearTimeout(timer);
    }
    stage('COMPLETE');
  `;
  // Only import/listener setup gets extra headroom. Assertions/cleanup keep the original 5s bound.
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: new URL('../', import.meta.url), env: {}, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe', 'pipe'], maxBuffer: 65536,
    timeout: setupTimeoutMs + executionTimeoutMs + 1000,
  });
  const phases = String(child.output?.[3] ?? '').trim().split('\n').filter(value =>
    ['SETUP', 'ASSERTIONS', 'CLEANUP', 'COMPLETE', 'SETUP_TIMEOUT', 'ASSERTIONS_TIMEOUT', 'CLEANUP_TIMEOUT'].includes(value));
  const diagnostic = JSON.stringify({
    code: 'STORAGE_WIRING_FIXTURE_FAILED', status: child.status, signal: child.signal,
    errorCode: child.error?.code ?? null, phase: phases.at(-1) ?? 'NOT_STARTED',
    stdoutBytes: Buffer.byteLength(child.stdout ?? ''), stderrBytes: Buffer.byteLength(child.stderr ?? ''),
  });
  assert.equal(child.error === undefined, true, diagnostic);
  assert.equal(child.status, 0, diagnostic);
  assert.equal(phases.at(-1), 'COMPLETE', diagnostic);
  assert.equal((child.stdout ?? '').length + (child.stderr ?? '').length, 0, diagnostic);
});

test('malformed requests and SDK failures cannot appear in service stdout/stderr', () => {
  const script = `
    import assert from 'node:assert/strict';
    import { once } from 'node:events';
    import { createTelemetryServer } from './dist/server.js';
    const receiver = createTelemetryServer({
      enabled: true, limits: ${JSON.stringify(limits)},
      storage: { async ingest() { throw new Error('PRIVATE_SDK_ERROR'); } },
    });
    try {
      receiver.server.listen(0, '127.0.0.1');
      await once(receiver.server, 'listening');
      const endpoint = 'http://127.0.0.1:' + receiver.server.address().port + '/v1/events';
      const invalid = await fetch(endpoint, {
        method: 'POST', headers: { 'content-type': 'application/json', 'X-Private': 'PRIVATE_HEADER' },
        body: JSON.stringify({ ...${JSON.stringify(event)}, path: 'PRIVATE_BODY' }),
      });
      assert.equal(invalid.status, 400);
      const failed = await fetch(endpoint, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify(${JSON.stringify(event)}),
      });
      assert.equal(failed.status, 503);
    } finally { receiver.stop(); }
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: new URL('../', import.meta.url), env: {}, encoding: 'utf8', timeout: 5000,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout + child.stderr, '');
});
