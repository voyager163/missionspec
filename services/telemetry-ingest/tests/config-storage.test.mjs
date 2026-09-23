import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { LogsIngestionClient } from '@azure/monitor-ingestion';
import { createHttpHeaders } from '@azure/core-rest-pipeline';
import { parseConfig, limitEnvironment, STREAM_NAME, validateRuntimeArguments } from '../dist/config.js';
import { createStorageAdapter, azureClientOptions } from '../dist/azure-storage.js';
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
