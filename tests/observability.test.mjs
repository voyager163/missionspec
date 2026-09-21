import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { chmod, mkdir, open, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { createServer, request } from 'node:https';
import { EventEmitter, once } from 'node:events';
import { Ajv2020 } from 'ajv/dist/2020.js';
import {
  DISCLOSURE_VERSION, DURATION_BUCKETS, MAX_EVENT_BYTES, TELEMETRY_OPERATIONS,
  createTelemetryClient, durationBucket, hardDisabled, parseDiagnosticEvent, parsePreference,
  parseTelemetryEvent, parseTelemetrySummary, serializeTelemetryEvent, telemetryEvent,
} from '../dist/observability/index.js';
import { VERSION_PATTERN } from '../dist/observability/events.js';
import { createHttpsTelemetryTransport } from '../dist/adapters/telemetry/https.js';
import {
  createUserTelemetryPreferenceStore, MAX_PREFERENCE_STORE_BYTES, PREFERENCE_BUSY_TIMEOUT_MS, saveTelemetryPreference,
} from '../dist/adapters/telemetry/preferences.js';
import {
  createDiagnostics, serializeDiagnosticEvent,
} from '../dist/adapters/logging/diagnostics.js';
import { createAuthorizedJsonlSink, MAX_LOG_BYTES } from '../dist/adapters/logging/jsonl.js';
import { createObservabilityLifecycle } from '../dist/composition/observability.js';

const secret = 'SENSITIVE-path-prompt-token-stack-DO-NOT-LOG';
const scratch = resolve('src/observability', `.local-tests-${process.pid}`);
const clock = { wallTime: () => '2026-09-20T18:00:00.000Z' };
const summary = {
  operation: 'draft', access: 'stateful', distributedVersion: '0.0.0',
  outcome: 'completed', host: 'none', os: 'macos', monotonicDurationMs: null,
};
const diagnostic = {
  contractVersion: 1, severity: 'information', code: 'operation-stopped',
  operation: 'draft', engine: 'specification', errorCode: null, elapsedMilliseconds: null,
};
const policy = { channel: 'unattended', environment: {} };
const event = () => telemetryEvent(summary);
const ownedPreferences = (path, options = {}) => createUserTelemetryPreferenceStore(path, {
  ownership: 'missionspec-telemetry-only', ...options,
});
before(() => mkdir(scratch, { recursive: false }));
after(() => rm(scratch, { recursive: true, force: true }));

function harness(overrides = {}) {
  const calls = { reads: 0, saves: [], notices: [], requests: [], diagnostics: [] };
  const options = {
    policy,
    preferences: {
      async read() { calls.reads += 1; return { state: 'ready', value: { disclosureVersion: DISCLOSURE_VERSION } }; },
      async save(value) { calls.saves.push(value); return { state: 'saved' }; },
    },
    sink: {
      endpoint: 'https://telemetry.invalid/v1/events',
      transport: { async send(value) { calls.requests.push(value); return { state: 'delivered' }; } },
    },
    diagnostics: {
      async emit(value, persistence) {
        calls.diagnostics.push({ value, persistence });
        return { state: 'emitted', destination: 'console' };
      },
    },
    async writeNotice(text) { calls.notices.push(text); },
    ...overrides,
  };
  return { calls, options, client: createTelemetryClient(options) };
}

test('policy strings are trimmed/case-insensitive; malformed and higher-priority denial win', () => {
  for (const value of ['0', 'false', ' NO ', 'Off']) {
    assert.equal(hardDisabled({ ...policy, environment: { MISSIONSPEC_TELEMETRY: value } }), true);
  }
  for (const name of ['CI', 'DO_NOT_TRACK']) {
    for (const value of ['1', 'TRUE', ' yes ', 'On']) {
      assert.equal(hardDisabled({ ...policy, environment: { [name]: value, MISSIONSPEC_TELEMETRY: '1' } }), true);
    }
    for (const value of ['0', 'false', ' NO ', 'off']) {
      assert.equal(hardDisabled({ ...policy, environment: { [name]: value } }), false);
    }
  }
  for (const name of ['CI', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY']) {
    for (const value of ['', ' ', 'maybe', secret, false, null]) {
      assert.equal(hardDisabled({ ...policy, environment: { [name]: value } }), true);
    }
  }
  for (const value of ['1', 'true', ' YES ', 'On']) {
    assert.equal(hardDisabled({ ...policy, environment: { MISSIONSPEC_TELEMETRY: value } }), false);
  }
  for (const environment of [
    { NODE_ENV: 'test' }, { NODE_ENV: '' }, { NODE_ENV: secret }, { NODE_TEST_CONTEXT: '' },
  ]) assert.equal(hardDisabled({ ...policy, environment }), true);
  for (const NODE_ENV of ['production', ' DEVELOPMENT ']) {
    assert.equal(hardDisabled({ ...policy, environment: { NODE_ENV } }), false);
  }
  for (const disabled of [true, 'false', 0, null]) assert.equal(hardDisabled({ ...policy, disabled }), true);
  assert.equal(hardDisabled({ ...policy, tests: true }), true);
  assert.equal(hardDisabled({ ...policy, channel: secret }), true);
  for (const environment of [null, secret, []]) assert.equal(hardDisabled({ ...policy, environment }), true);
});

test('denials, read-only helpers, read-only summaries, and default sink do no configuration or network work', async () => {
  for (const input of [
    { policy: { ...policy, disabled: true } },
    { policy: { ...policy, tests: true } },
    { policy: { ...policy, environment: { CI: 'yes' } } },
    { policy: { ...policy, environment: { MISSIONSPEC_TELEMETRY: '0' } } },
    { policy: { ...policy, environment: { DO_NOT_TRACK: '1' } } },
    { policy: { ...policy, environment: { NODE_ENV: 'test' } } },
    { sink: undefined },
  ]) {
    const { client, calls } = harness(input);
    assert.equal((await client.recordCompletion(summary)).state, 'suppressed');
    assert.deepEqual(calls, { reads: 0, saves: [], notices: [], requests: [], diagnostics: [] });
  }
  for (const operation of ['discover', 'clarify', 'analyze', 'onboard', 'draft']) {
    const { client, calls } = harness();
    assert.deepEqual(await client.recordCompletion({
      ...summary, operation, access: operation === 'draft' ? 'read-only' : 'stateful',
    }), { state: 'suppressed', reason: 'read-only' });
    assert.deepEqual(calls, { reads: 0, saves: [], notices: [], requests: [], diagnostics: [] });
  }
  const throwingOptions = {
    policy: { ...policy, disabled: true },
    get sink() { throw new Error(secret); },
    get preferences() { throw new Error(secret); },
  };
  assert.deepEqual(await createTelemetryClient(throwingOptions).recordCompletion(summary), {
    state: 'suppressed', reason: 'opted-out',
  });
});

test('module imports initialize no telemetry, logging, environment changes, or output', () => {
  const program = `
    import assert from 'node:assert/strict';
    import fs from 'node:fs/promises';
    import https from 'node:https';
    import { syncBuiltinESMExports } from 'node:module';
    const environment = JSON.stringify(process.env);
    fs.open = async () => { throw new Error('Unexpected filesystem adapter initialization'); };
    https.request = () => { throw new Error('Unexpected network initialization'); };
    syncBuiltinESMExports();
    await import('./dist/observability/index.js');
    await import('./dist/adapters/telemetry/https.js');
    await import('./dist/adapters/telemetry/preferences.js');
    await import('./dist/adapters/logging/diagnostics.js');
    await import('./dist/adapters/logging/jsonl.js');
    await import('./dist/composition/observability.js');
    assert.equal(JSON.stringify(process.env), environment);
  `;
  assert.equal(execFileSync(process.execPath, ['--input-type=module', '-e', program], {
    cwd: resolve('.'), encoding: 'utf8', timeout: 10_000,
  }), '');
});

test('canonical schema and runtime agree on exact fields, enums, bounds and versions', async () => {
  const schema = JSON.parse(await readFile(new URL('../assets/schemas/telemetry-event.schema.json', import.meta.url), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.deepEqual(schema.properties.operation.enum, TELEMETRY_OPERATIONS);
  assert.deepEqual(schema.properties.durationBucket.enum, [...DURATION_BUCKETS, null]);
  assert.equal(schema.properties.cliVersion.pattern, VERSION_PATTERN);
  assert.deepEqual(Object.keys(event()), schema.required);
  assert.equal(validate(event()), true);
  assert.ok(Buffer.byteLength(serializeTelemetryEvent(event())) < MAX_EVENT_BYTES);
  for (const key of schema.required) {
    const missing = { ...event() };
    delete missing[key];
    assert.equal(validate(missing), false);
    assert.throws(() => parseTelemetryEvent(missing));
  }
  for (const [field, values] of Object.entries({
    schemaVersion: [0, 2, '1'], event: ['started', secret],
    operation: ['discover', 'clarify', 'analyze', 'onboard', 'help', secret],
    cliVersion: ['', 'v1.0.0', '01.0.0', '1.2', '1.2.3+private', '1.2.3-local', '1.2.3\n', secret, '1'.repeat(1025)],
    outcome: ['success', secret], host: ['gpt-5', secret], os: ['darwin', secret],
    durationBucket: [0, 'unknown', secret],
  })) {
    for (const value of values) {
      const invalid = { ...event(), [field]: value };
      assert.equal(validate(invalid), false, `${field} should reject`);
      assert.throws(() => parseTelemetryEvent(invalid));
    }
  }
  for (const field of ['path', 'args', 'timestamp', 'sessionId', '__proto__']) {
    const invalid = JSON.parse(JSON.stringify(event()).slice(0, -1) + `,"${field}":"${secret}"}`);
    assert.equal(validate(invalid), false);
    assert.throws(() => parseTelemetryEvent(invalid));
  }
  for (const cliVersion of ['0.0.0', '1.2.3', '123456.0.999999', '1.2.3-alpha.0', '1.2.3-beta.12', '1.2.3-rc.1']) {
    assert.equal(validate({ ...event(), cliVersion }), true);
    assert.equal(parseTelemetryEvent({ ...event(), cliVersion }).cliVersion, cliVersion);
  }
  for (const [field, property] of Object.entries(schema.properties)) {
    for (const value of property.enum ?? []) assert.doesNotThrow(() => parseTelemetryEvent({ ...event(), [field]: value }));
  }
  const accessor = { ...event() };
  Object.defineProperty(accessor, 'outcome', { get() { throw new Error(secret); } });
  assert.throws(() => parseTelemetryEvent(accessor), /accessors/);
  assert.throws(() => parseTelemetryEvent(Object.assign(Object.create({}), event())));
});

test('duration boundaries preserve unknown, allow zero, and reject nonfinite/negative/unbounded input', () => {
  assert.equal(durationBucket(null), null);
  for (const [value, expected] of [
    [0, 'under-1s'], [999.999, 'under-1s'], [1000, '1s-to-10s'], [9999.999, '1s-to-10s'],
    [10_000, '10s-to-1m'], [59_999.999, '10s-to-1m'], [60_000, '1m-to-10m'],
    [599_999.999, '1m-to-10m'], [600_000, '10m-to-1h'], [3_599_999.999, '10m-to-1h'],
    [3_600_000, '1h-or-more'], [Number.MAX_SAFE_INTEGER, '1h-or-more'],
  ]) assert.equal(durationBucket(value), expected);
  for (const value of [undefined, -1, NaN, Infinity, -Infinity, '0', false, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => durationBucket(value));
    assert.throws(() => parseTelemetrySummary({ ...summary, monotonicDurationMs: value }));
  }
  assert.throws(() => telemetryEvent({ ...summary, access: 'read-only' }));
  assert.throws(() => telemetryEvent({ ...summary, operation: 'discover' }));
  assert.throws(() => parseTelemetrySummary({ ...summary, args: secret }));
});

test('prior disclosure and saved opt-out gate delivery; first machine call never writes', async () => {
  for (const channel of ['json', 'mcp', 'unattended']) {
    const { client, calls } = harness({
      policy: { ...policy, channel },
      preferences: { async read() { return { state: 'ready', value: {} }; }, async save() { throw new Error(secret); } },
    });
    assert.deepEqual(await client.recordCompletion(summary), { state: 'suppressed', reason: 'notice-required' });
    assert.equal(calls.notices.length + calls.requests.length, 0);
  }
  for (const preference of [
    { preference: 'disabled', disclosureVersion: 1 }, { preference: 'disabled' },
  ]) {
    const { client, calls } = harness({
      preferences: { async read() { return { state: 'ready', value: preference }; }, async save() { throw new Error(secret); } },
    });
    assert.deepEqual(await client.recordCompletion(summary), { state: 'suppressed', reason: 'opted-out' });
    assert.equal(calls.notices.length + calls.requests.length + calls.diagnostics.length, 0);
  }
  const { client, calls } = harness({ policy: { ...policy, channel: 'json' } });
  assert.deepEqual(await client.recordCompletion(summary), { state: 'delivered' });
  assert.equal(calls.requests.length, 1);
  assert.deepEqual(JSON.parse(calls.requests[0].body), event());
  assert.equal(calls.notices.length + calls.saves.length, 0);
});

test('interactive first notice is disclosure, not consent; completed first operation is skipped', async () => {
  const saves = [];
  const { client, calls } = harness({
    policy: { ...policy, channel: 'interactive' },
    preferences: {
      async read() { return { state: 'ready', value: { preference: 'enabled' } }; },
      async save(value) { saves.push(value); return { state: 'saved' }; },
    },
  });
  assert.deepEqual(await client.recordCompletion(summary), { state: 'suppressed', reason: 'notice-required' });
  assert.deepEqual(saves, [{ disclosureVersion: 1 }]);
  assert.equal(calls.requests.length, 0);
  for (const text of ['not affirmative consent', '180 days', 'MISSIONSPEC_TELEMETRY=0', 'DO_NOT_TRACK=1', 'https://telemetry.invalid/v1/events']) {
    assert.ok(calls.notices[0].includes(text));
  }
});

test('invalid preferences, persistence failures and exceptions fail safely without sensitive leakage', async () => {
  for (const preferences of [
    { async read() { return { state: 'unavailable' }; } },
    { async read() { throw new Error(secret); } },
    { async read() { return { state: 'ready', value: { preference: secret } }; } },
    { async read() { return { state: 'ready', value: { disclosureVersion: 2 } }; } },
    { async read() { return { state: 'ready', value: {} }; }, async save() { return { state: 'unavailable', reason: 'conflict' }; } },
    { async read() { return { state: 'ready', value: {} }; }, async save() { throw new Error(secret); } },
  ]) {
    const { client, calls } = harness({ policy: { ...policy, channel: 'interactive' }, preferences });
    assert.deepEqual(await client.recordCompletion(summary), { state: 'unavailable' });
    assert.equal(calls.requests.length, 0);
    assert.equal(calls.diagnostics.length, 1);
    assert.equal(calls.diagnostics[0].persistence, 'console-only');
    assert.equal(JSON.stringify(calls).includes(secret), false);
  }
  for (const invalid of [{ ...summary, outcome: secret }, { ...summary, rawError: secret }]) {
    const { client, calls } = harness();
    assert.deepEqual(await client.recordCompletion(invalid), { state: 'unavailable' });
    assert.equal(calls.reads + calls.requests.length, 0);
    assert.equal(JSON.stringify(calls).includes(secret), false);
  }
});

test('one client owns one root completion and concurrent duplicate completions cannot double send', async () => {
  const { client, calls } = harness();
  const results = await Promise.all([client.recordCompletion(summary), client.recordCompletion(summary)]);
  assert.deepEqual(results.map((value) => value.state).sort(), ['delivered', 'unavailable']);
  assert.equal(calls.requests.length, 1);
  assert.equal(calls.diagnostics.length, 1);
});

test('transport exceptions and cancellation are explicit, isolated, and bounded to one second', async () => {
  for (const send of [
    async () => { throw new Error(secret); },
    async () => ({ state: 'unavailable', error: secret }),
    async () => ({ state: 'unexpected', error: secret }),
  ]) {
    const { client, calls } = harness({ sink: { endpoint: 'https://telemetry.invalid/', transport: { send } } });
    assert.deepEqual(await client.recordCompletion(summary), { state: 'unavailable' });
    assert.equal(JSON.stringify(calls).includes(secret), false);
  }
  let signal;
  const { client, calls } = harness({
    sink: { endpoint: 'https://telemetry.invalid/', transport: { send(input) { signal = input.signal; return new Promise(() => {}); } } },
  });
  const start = performance.now();
  assert.deepEqual(await client.recordCompletion(summary), { state: 'unavailable' });
  assert.ok(performance.now() - start < 1600);
  assert.equal(signal.aborted, true);
  assert.equal(calls.diagnostics.length, 1);
  const controller = new AbortController();
  controller.abort(new Error(secret));
  const aborted = harness({ signal: controller.signal });
  assert.deepEqual(await aborted.client.recordCompletion(summary), { state: 'unavailable' });
  assert.equal(aborted.calls.requests.length, 0);
  const during = new AbortController();
  let observedAbort = false;
  const active = harness({
    signal: during.signal,
    sink: {
      endpoint: 'https://telemetry.invalid/',
      transport: {
        send(input) {
          input.signal.addEventListener('abort', () => { observedAbort = true; });
          during.abort(new Error(secret));
          return new Promise(() => {});
        },
      },
    },
  });
  assert.deepEqual(await active.client.recordCompletion(summary), { state: 'unavailable' });
  assert.equal(observedAbort, true);
  const throwingDiagnostic = harness({
    diagnostics: { async emit() { throw new Error(secret); } },
    sink: { endpoint: 'http://telemetry.invalid/', transport: { async send() { throw new Error('must not send'); } } },
  });
  assert.deepEqual(await throwingDiagnostic.client.recordCompletion(summary), { state: 'unavailable' });
  const stalledDiagnostic = harness({
    diagnostics: { emit() { return new Promise(() => {}); } },
    sink: { endpoint: 'http://telemetry.invalid/', transport: { async send() { throw new Error('must not send'); } } },
  });
  assert.deepEqual(await stalledDiagnostic.client.recordCompletion(summary), { state: 'unavailable' });
});

test('native sender refuses invalid endpoints/bodies without constructing a request', async () => {
  let requests = 0;
  const native = createHttpsTelemetryTransport(() => { requests += 1; throw new Error(secret); });
  for (const endpoint of [
    'http://localhost/', 'https://name:secret@example.invalid/', 'https://example.invalid/?secret=x',
    'https://example.invalid/#secret', 'file:///x', secret, 'https://example.invalid',
  ]) {
    assert.deepEqual(await native.send({ endpoint, body: serializeTelemetryEvent(event()), signal: new AbortController().signal }), { state: 'unavailable' });
  }
  for (const body of [
    '', secret, 'x'.repeat(1025), JSON.stringify({ ...event(), raw: secret }),
    `{"outcome":"${secret}",${serializeTelemetryEvent(event()).slice(1)}`,
    JSON.stringify(event(), null, 2),
  ]) {
    assert.deepEqual(await native.send({ endpoint: 'https://telemetry.invalid/', body, signal: new AbortController().signal }), { state: 'unavailable' });
  }
  assert.equal(requests, 0);
});

test('native sender disposes response bodies, refuses redirects, and sanitizes DNS-style failures', async () => {
  for (const statusCode of [200, 204, 301, 302, 307, 400, 429, 500]) {
    let disposed = 0;
    let requestCount = 0;
    const sender = createHttpsTelemetryTransport((_url, options, callback) => {
      requestCount += 1;
      assert.equal(options.method, 'POST');
      assert.equal(options.agent, false);
      assert.equal(options.headers.connection, 'close');
      assert.equal(options.maxHeaderSize, 4096);
      const req = new EventEmitter();
      req.destroy = () => {};
      req.end = () => queueMicrotask(() => {
        const res = new EventEmitter();
        res.statusCode = statusCode;
        res.headers = { location: 'https://external.invalid/' };
        res.destroy = () => { disposed += 1; };
        callback(res);
      });
      return req;
    });
    assert.deepEqual(await sender.send({
      endpoint: 'https://telemetry.invalid/', body: serializeTelemetryEvent(event()), signal: new AbortController().signal,
    }), { state: statusCode < 300 ? 'delivered' : 'unavailable' });
    assert.equal(disposed, 1);
    assert.equal(requestCount, 1);
  }
  const failed = createHttpsTelemetryTransport(() => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => req.emit('error', Object.assign(new Error(secret), { code: 'ENOTFOUND' })));
    return req;
  });
  assert.deepEqual(await failed.send({
    endpoint: 'https://telemetry.invalid/', body: serializeTelemetryEvent(event()), signal: new AbortController().signal,
  }), { state: 'unavailable' });
});

test('dedicated preference store refuses legacy JSON, malformed data and foreign databases without modifying them', async () => {
  for (const [name, content] of [
    ['malformed', `{ "${secret}":`],
    ['oversized', ' '.repeat(MAX_PREFERENCE_STORE_BYTES + 1)],
    ['empty', ''],
    ['array', '[]'],
    ['null', 'null'],
    ['unknown-field', JSON.stringify({ missionspecTelemetry: { identity: secret } })],
    ['unsupported', JSON.stringify({ missionspecTelemetry: { disclosureVersion: 999 } })],
  ]) {
    const path = join(scratch, `${name}.json`);
    await writeFile(path, content);
    const store = ownedPreferences(path);
    assert.equal((await store.read()).state, 'unavailable');
    assert.equal((await store.save({ preference: 'disabled' })).state, 'unavailable');
    assert.equal(await readFile(path, 'utf8'), content);
  }
  const existingPath = join(scratch, 'unrelated.json');
  const original = `{"user":{"value":"${secret}"},"missionspecTelemetry":{"preference":"enabled","disclosureVersion":1}}\n`;
  await writeFile(existingPath, original);
  const existing = ownedPreferences(existingPath);
  assert.equal((await existing.read()).reason, 'unrecognized-store');
  assert.equal((await saveTelemetryPreference(existing, 'disabled')).reason, 'unrecognized-store');
  assert.equal(await readFile(existingPath, 'utf8'), original);
  const foreignPath = join(scratch, 'foreign.sqlite');
  const foreign = new DatabaseSync(foreignPath);
  foreign.exec('CREATE TABLE unrelated (setting TEXT) STRICT');
  foreign.prepare('INSERT INTO unrelated VALUES (?)').run(secret);
  foreign.close();
  const originalDatabase = await readFile(foreignPath);
  assert.equal((await ownedPreferences(foreignPath).save({ preference: 'disabled' })).reason, 'unrecognized-store');
  assert.deepEqual(await readFile(foreignPath), originalDatabase);
  assert.equal((await ownedPreferences('relative.sqlite').read()).reason, 'invalid');
  assert.equal((await createUserTelemetryPreferenceStore(join(scratch, 'no-ownership.sqlite')).read()).reason, 'invalid');
  await assert.rejects(stat(join(scratch, 'no-ownership.sqlite')), { code: 'ENOENT' });
  const invalidRowPath = join(scratch, 'invalid-row.sqlite');
  const invalidRowStore = ownedPreferences(invalidRowPath);
  await invalidRowStore.save({ preference: 'disabled' });
  const invalidRowDatabase = new DatabaseSync(invalidRowPath);
  invalidRowDatabase.exec('UPDATE missionspec_telemetry_preferences SET disclosure_version = 999');
  invalidRowDatabase.close();
  const invalidRowBytes = await readFile(invalidRowPath);
  assert.equal((await invalidRowStore.read()).state, 'unavailable');
  assert.equal((await invalidRowStore.save({ preference: 'enabled' })).state, 'unavailable');
  assert.deepEqual(await readFile(invalidRowPath), invalidRowBytes);
  const walPath = join(scratch, 'unsupported-wal.sqlite');
  const walStore = ownedPreferences(walPath);
  await walStore.save({ preference: 'disabled' });
  const walDatabase = new DatabaseSync(walPath);
  walDatabase.exec('PRAGMA journal_mode = WAL');
  walDatabase.close();
  const beforeFiles = (await readdir(scratch)).sort();
  const beforeWal = await readFile(walPath);
  assert.equal((await walStore.read()).reason, 'unrecognized-store');
  assert.equal((await walStore.save({ preference: 'enabled' })).reason, 'unrecognized-store');
  assert.deepEqual((await readdir(scratch)).sort(), beforeFiles);
  assert.deepEqual(await readFile(walPath), beforeWal);
});

test('persistent controls disable, re-enable and update disclosure as atomic patches without extra telemetry', async () => {
  const path = join(scratch, 'preferences.sqlite');
  const store = ownedPreferences(path);
  assert.deepEqual(await store.read(), { state: 'ready', value: {} });
  await assert.rejects(stat(path), { code: 'ENOENT' });
  assert.deepEqual(await saveTelemetryPreference(store, 'disabled'), { state: 'saved' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled' } });
  assert.deepEqual(await store.save({ disclosureVersion: 1 }), { state: 'saved' });
  assert.deepEqual(await ownedPreferences(path).read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  assert.deepEqual(await saveTelemetryPreference(ownedPreferences(path), 'enabled'), { state: 'saved' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'enabled', disclosureVersion: 1 } });
  const sending = harness({ preferences: store });
  assert.deepEqual(await sending.client.recordCompletion(summary), { state: 'delivered' });
  assert.deepEqual(await saveTelemetryPreference(store, 'disabled'), { state: 'saved' });
  const disabled = harness({ preferences: store });
  assert.deepEqual(await disabled.client.recordCompletion(summary), { state: 'suppressed', reason: 'opted-out' });
  assert.equal(disabled.calls.requests.length + disabled.calls.notices.length, 0);
  assert.deepEqual(await store.save({ disclosureVersion: 1 }), { state: 'saved' });
  assert.deepEqual(await saveTelemetryPreference(store, 'disabled'), { state: 'saved' });
  if (process.platform !== 'win32') assert.equal((await stat(path)).mode & 0o077, 0);
  const patches = [];
  assert.deepEqual(await saveTelemetryPreference({
    async read() { throw new Error('Controls must not perform a stale read-modify-write'); },
    async save(patch) { patches.push(patch); return { state: 'saved' }; },
  }, 'enabled'), { state: 'saved' });
  assert.deepEqual(patches, [{ preference: 'enabled' }]);
  assert.throws(() => parsePreference({ preference: undefined }));
  assert.throws(() => parsePreference({ disclosureVersion: null }));
  assert.equal((await store.save({})).reason, 'invalid');
  assert.equal((await store.save({ disclosureVersion: 999 })).reason, 'invalid');
  const before = await readFile(path);
  assert.equal((await store.save({ preference: secret })).reason, 'invalid');
  assert.deepEqual(await readFile(path), before);
});

test('concurrent initialization and symlinks fail explicitly rather than replacing an existing authority', async () => {
  const path = join(scratch, 'race.sqlite');
  const stores = [ownedPreferences(path), ownedPreferences(path)];
  const results = await Promise.all(stores.map((store, index) => store.save({ preference: index === 0 ? 'enabled' : 'disabled' })));
  assert.ok(results.some((result) => result.state === 'saved'));
  assert.ok(results.every((result) => result.state === 'saved' || result.state === 'unavailable'));
  assert.equal((await stores[0].read()).state, 'ready');
  assert.deepEqual(await saveTelemetryPreference(stores[0], 'disabled'), { state: 'saved' });
  const target = join(scratch, 'symlink-target.json');
  await writeFile(target, '{"unrelated":"preserve"}');
  const alias = join(scratch, 'alias.json');
  await symlink(target, alias);
  assert.equal((await ownedPreferences(alias).read()).state, 'unavailable');
  assert.equal((await ownedPreferences(alias).save({ preference: 'disabled' })).state, 'unavailable');
  assert.equal(await readFile(target, 'utf8'), '{"unrelated":"preserve"}');
});

test('disclosure persistence cannot undo an opt-out made while an interactive notice is displayed', async () => {
  const path = join(scratch, 'notice-race.sqlite');
  const store = ownedPreferences(path);
  await store.save({ preference: 'enabled' });
  const { client, calls } = harness({
    policy: { ...policy, channel: 'interactive' }, preferences: store,
    async writeNotice() {
      assert.deepEqual(await saveTelemetryPreference(ownedPreferences(path), 'disabled'), { state: 'saved' });
    },
  });
  assert.deepEqual(await client.recordCompletion(summary), { state: 'suppressed', reason: 'notice-required' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  assert.equal(calls.requests.length, 0);
});

function preferenceWorker(path, action) {
  const program = `
    import { DatabaseSync } from 'node:sqlite';
    import { createUserTelemetryPreferenceStore } from './dist/adapters/telemetry/preferences.js';
    const path = process.argv[1];
    const action = process.argv[2];
    const store = createUserTelemetryPreferenceStore(path, { ownership: 'missionspec-telemetry-only' });
    if (action === 'lock' || action === 'crash') {
      const db = new DatabaseSync(path);
      db.exec('BEGIN EXCLUSIVE');
      db.prepare('UPDATE missionspec_telemetry_preferences SET preference = ?').run('enabled');
      if (action === 'crash') {
        process.send({ state: 'ready' }, () => process.exit(9));
      } else {
        process.send({ state: 'ready' });
        process.once('message', () => { db.exec('ROLLBACK'); db.close(); process.disconnect(); });
      }
    } else {
      process.send({ state: 'ready' });
      process.once('message', async () => {
        const results = [];
        for (let i = 0; i < 24; i += 1) {
          results.push(action === 'read' ? await store.read() :
            await store.save(action === 'disable' ? { preference: 'disabled' } : { disclosureVersion: 1 }));
        }
        process.send({ state: 'done', results }, () => process.disconnect());
      });
    }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', program, path, action], {
    cwd: resolve('.'), stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let errors = '';
  child.stderr.on('data', (chunk) => { errors += chunk; });
  const ready = new Promise((resolveReady, reject) => {
    child.once('error', reject);
    child.on('message', (value) => { if (value.state === 'ready') resolveReady(); });
    child.once('exit', () => { if (errors) reject(new Error('Preference worker failed')); });
  });
  const done = new Promise((resolveDone) => {
    child.on('message', (value) => { if (value.state === 'done') resolveDone(value.results); });
  });
  const exited = once(child, 'exit');
  return { child, ready, done, exited };
}

test('separate processes atomically merge disclosure/disable patches; concurrent readers never default on', { timeout: 15_000 }, async () => {
  const path = join(scratch, 'multiprocess.sqlite');
  const store = ownedPreferences(path);
  await store.save({ preference: 'disabled' });
  const workers = ['disable', 'disclosure', 'read'].map((action) => preferenceWorker(path, action));
  try {
    await Promise.all(workers.map((worker) => worker.ready));
    workers.forEach((worker) => worker.child.send('go'));
    const [disabled, disclosed, observed] = await Promise.all(workers.map((worker) => worker.done));
    assert.ok(disabled.every((value) => value.state === 'saved'));
    assert.ok(disclosed.every((value) => value.state === 'saved'));
    assert.ok(observed.every((value) => value.state === 'ready' && value.value.preference === 'disabled'));
    assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
    await Promise.all(workers.map((worker) => worker.exited));
  } finally {
    for (const { child } of workers) if (child.exitCode === null) child.kill();
  }
});

test('a real exclusive transaction causes bounded unavailable results, never a transient enabled default', { timeout: 10_000 }, async (context) => {
  const path = join(scratch, 'locked.sqlite');
  const configuredTimeouts = [];
  const store = ownedPreferences(path, {
    openDatabase: injectedDatabase((stage, sql, database, proceed) => {
      const result = proceed();
      if (stage === 'exec' && sql.startsWith('PRAGMA busy_timeout =')) {
        configuredTimeouts.push(database.prepare('PRAGMA busy_timeout').get().timeout);
      }
      return result;
    }),
  });
  await store.save({ preference: 'disabled', disclosureVersion: 1 });
  const worker = preferenceWorker(path, 'lock');
  try {
    await worker.ready;
    const start = performance.now();
    const read = await store.read();
    const write = await store.save({ preference: 'enabled' });
    assert.equal(read.state, 'unavailable');
    assert.equal(write.state, 'unavailable');
    assert.equal(read.reason, 'busy');
    assert.equal(write.reason, 'busy');
    assert.equal(write.persistence, 'unchanged');
    assert.equal(PREFERENCE_BUSY_TIMEOUT_MS, 250);
    assert.ok(configuredTimeouts.length >= 3);
    assert.ok(configuredTimeouts.every((timeout) => timeout === 250));
    context.diagnostic(`Busy read/write wall time including filesystem and runner scheduling: ${Math.round(performance.now() - start)} ms; SQLite busy timeout: 250 ms per connection.`);
    worker.child.send('release');
    await worker.exited;
    assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  } finally {
    if (worker.child.exitCode === null) worker.child.kill();
  }
});

test('process exit before commit preserves the prior disabled state or explicitly requires recovery', { timeout: 10_000 }, async () => {
  const path = join(scratch, 'crash.sqlite');
  const store = ownedPreferences(path);
  await store.save({ preference: 'disabled', disclosureVersion: 1 });
  const worker = preferenceWorker(path, 'crash');
  await worker.exited;
  const read = await store.read();
  assert.ok(read.state === 'unavailable' || read.value.preference === 'disabled');
  assert.deepEqual(await store.save({ preference: 'disabled' }), { state: 'saved' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
});

function injectedDatabase(intercept) {
  return (path, readOnly) => {
    const database = new DatabaseSync(path, { readOnly });
    return {
      get isTransaction() { return database.isTransaction; },
      prepare: database.prepare.bind(database),
      exec(sql) { return intercept('exec', sql, database, () => database.exec(sql)); },
      close() { return intercept('close', '', database, () => database.close()); },
    };
  };
}

test('write/commit/rollback/close failures expose unchanged, unknown or committed state without raw errors', async () => {
  const path = join(scratch, 'failures.sqlite');
  const store = ownedPreferences(path);
  await store.save({ preference: 'disabled' });
  const beforeCommit = ownedPreferences(path, {
    openDatabase: injectedDatabase((method, sql, _database, proceed) => {
      if (method === 'exec' && sql === 'COMMIT') throw new Error(secret);
      return proceed();
    }),
  });
  const rolledBack = await beforeCommit.save({ preference: 'enabled' });
  assert.deepEqual(rolledBack, { state: 'unavailable', reason: 'io', persistence: 'unchanged', cleanup: 'complete' });
  assert.equal((await store.read()).value.preference, 'disabled');
  const afterCommit = ownedPreferences(path, {
    openDatabase: injectedDatabase((method, sql, _database, proceed) => {
      const result = proceed();
      if (method === 'exec' && sql === 'COMMIT') throw new Error(secret);
      return result;
    }),
  });
  const unknown = await afterCommit.save({ preference: 'enabled' });
  assert.deepEqual(unknown, { state: 'unavailable', reason: 'io', persistence: 'unknown', cleanup: 'complete' });
  assert.equal((await store.read()).value.preference, 'enabled');
  const failedClose = ownedPreferences(path, {
    openDatabase: injectedDatabase((method, _sql, _database, proceed) => {
      const result = proceed();
      if (method === 'close') throw new Error(secret);
      return result;
    }),
  });
  const partial = await failedClose.save({ preference: 'disabled' });
  assert.deepEqual(partial, { state: 'unavailable', reason: 'cleanup-failed', persistence: 'committed', cleanup: 'incomplete' });
  assert.equal((await store.read()).value.preference, 'disabled');
  assert.equal((await failedClose.read()).state, 'unavailable');
  const failedRollback = ownedPreferences(path, {
    openDatabase: injectedDatabase((method, sql, _database, proceed) => {
      if (method === 'exec' && ['COMMIT', 'ROLLBACK'].includes(sql)) throw new Error(secret);
      return proceed();
    }),
  });
  const rollback = await failedRollback.save({ preference: 'enabled' });
  assert.deepEqual(rollback, { state: 'unavailable', reason: 'io', persistence: 'unknown', cleanup: 'incomplete' });
  assert.equal((await store.read()).value.preference, 'disabled');
  assert.equal(JSON.stringify([rolledBack, unknown, partial, rollback]).includes(secret), false);
});

test('file-close and interrupted initialization failures are explicit and cannot become missing-policy defaults', async () => {
  const path = join(scratch, 'file-close.sqlite');
  const store = ownedPreferences(path);
  await store.save({ preference: 'disabled' });
  const closeFailure = ownedPreferences(path, {
    async openFile(...args) {
      const file = await open(...args);
      return {
        stat: file.stat.bind(file),
        read: file.read.bind(file),
        async close() { await file.close(); throw new Error(secret); },
      };
    },
  });
  assert.deepEqual(await closeFailure.save({ preference: 'enabled' }), {
    state: 'unavailable', reason: 'cleanup-failed', persistence: 'unchanged', cleanup: 'incomplete',
  });
  assert.equal((await store.read()).value.preference, 'disabled');
  const incompletePath = join(scratch, 'interrupted-initialization.sqlite');
  const initialization = ownedPreferences(incompletePath, { openDatabase() { throw new Error(secret); } });
  assert.deepEqual(await initialization.save({ preference: 'disabled' }), {
    state: 'unavailable', reason: 'io', persistence: 'unchanged', cleanup: 'incomplete',
  });
  assert.equal((await ownedPreferences(incompletePath).read()).reason, 'unrecognized-store');
  assert.equal((await stat(incompletePath)).size, 0);
});

test('disabled/read-only/unconfigured calls and absent preference reads never create a database', async () => {
  for (const [index, options, value] of [
    [0, { policy: { ...policy, disabled: true } }, summary],
    [1, {}, { ...summary, access: 'read-only' }],
    [2, { sink: undefined }, summary],
  ]) {
    const path = join(scratch, `no-write-${index}.sqlite`);
    const store = ownedPreferences(path);
    assert.deepEqual(await store.read(), { state: 'ready', value: {} });
    const { client } = harness({ ...options, preferences: store });
    assert.equal((await client.recordCompletion(value)).state, 'suppressed');
    await assert.rejects(stat(path), { code: 'ENOENT' });
  }
  assert.deepEqual((await readdir(scratch)).filter((name) => name.endsWith('.new')), []);
});

test('diagnostic serialization is bounded, closed, clock-injected and console-only never creates a file', async () => {
  const lines = [];
  const path = join(scratch, 'must-not-exist', 'console.jsonl');
  const logger = createDiagnostics({
    clock, stderr: { async write(line) { lines.push(line); } }, localLog: createAuthorizedJsonlSink(path),
  });
  assert.deepEqual(await logger.emit(diagnostic, 'console-only'), { state: 'emitted', destination: 'console' });
  await assert.rejects(stat(path), { code: 'ENOENT' });
  assert.ok(Buffer.byteLength(lines[0]) <= MAX_EVENT_BYTES);
  assert.equal(JSON.parse(lines[0]).recordedAt, clock.wallTime());
  assert.deepEqual(parseDiagnosticEvent(diagnostic), diagnostic);
  assert.throws(() => serializeDiagnosticEvent(diagnostic, '2026-02-30T00:00:00.000Z'));
  for (const invalid of [
    { ...diagnostic, message: secret }, { ...diagnostic, operation: secret }, { ...diagnostic, severity: '\nerror' },
    { ...diagnostic, engine: secret }, { ...diagnostic, errorCode: secret }, { ...diagnostic, contractVersion: 2 },
    { ...diagnostic, elapsedMilliseconds: Infinity }, { ...diagnostic, stack: secret.repeat(4096) },
  ]) {
    assert.deepEqual(await logger.emit(invalid, 'authorized-local-log'), { state: 'unavailable', consoleFallback: 'emitted' });
  }
  assert.equal(lines.join('').includes(secret), false);
  assert.equal(lines.length, 9);
  for (const operation of ['discover', 'clarify', 'analyze', 'onboard']) {
    assert.deepEqual(await logger.emit({ ...diagnostic, operation }, 'authorized-local-log'), {
      state: 'unavailable', consoleFallback: 'emitted',
    });
  }
  await assert.rejects(stat(path), { code: 'ENOENT' });
});

test('authorized JSONL appends private bounded records, serializes writers and prunes only explicitly', async () => {
  if (process.platform === 'win32') return;
  const path = join(scratch, 'authorized.jsonl');
  const sink = createAuthorizedJsonlSink(path);
  const lines = [];
  const logger = createDiagnostics({ clock, stderr: { async write(line) { lines.push(line); } }, localLog: sink });
  const results = await Promise.all(Array.from({ length: 8 }, () => logger.emit(diagnostic, 'authorized-local-log')));
  assert.ok(results.every((result) => result.state === 'emitted' && result.destination === 'local-log'));
  const before = await readFile(path, 'utf8');
  assert.equal(before.trim().split('\n').length, 8);
  assert.equal((await stat(path)).mode & 0o077, 0);
  assert.equal(lines.length, 0);
  await assert.rejects(sink.write(`{"raw":"${secret}"}\n`), /persistence unavailable/);
  assert.equal(await readFile(path, 'utf8'), before);
  await writeFile(`${path}.lock`, '');
  assert.deepEqual(await logger.emit(diagnostic, 'authorized-local-log'), { state: 'unavailable', consoleFallback: 'emitted' });
  await rm(`${path}.lock`);
  const record = serializeDiagnosticEvent(diagnostic, clock.wallTime());
  const full = record.repeat(Math.floor(MAX_LOG_BYTES / Buffer.byteLength(record)));
  await writeFile(path, full, { mode: 0o600 });
  assert.deepEqual(await logger.emit(diagnostic, 'authorized-local-log'), { state: 'unavailable', consoleFallback: 'emitted' });
  assert.equal((await stat(path)).size, Buffer.byteLength(full));
  const reviewed = await sink.previewPrune();
  assert.equal(reviewed.state, 'ready');
  assert.deepEqual(await sink.prune(reviewed), { state: 'pruned' });
  assert.equal(await readFile(path, 'utf8'), '');
  assert.equal(lines.every((line) => !line.includes(secret)), true);
});

test('file errors and stderr errors never claim persistence or emit raw errors', async () => {
  const lines = [];
  for (const sink of [
    createAuthorizedJsonlSink(join(scratch, 'absent-parent', 'log.jsonl')),
    { async write() { throw new Error(secret); } },
    undefined,
  ]) {
    const logger = createDiagnostics({ clock, stderr: { async write(line) { lines.push(line); } }, localLog: sink });
    assert.deepEqual(await logger.emit(diagnostic, 'authorized-local-log'), { state: 'unavailable', consoleFallback: 'emitted' });
  }
  const broken = createDiagnostics({
    clock, stderr: { async write() { throw new Error(secret); } }, localLog: { async write() { throw new Error(secret); } },
  });

  for (const persistence of ['console-only', 'authorized-local-log']) {
    assert.deepEqual(await broken.emit(diagnostic, persistence), { state: 'unavailable', consoleFallback: 'unavailable' });
  }
  if (process.platform !== 'win32') {
    const path = join(scratch, 'public.jsonl');
    await writeFile(path, '', { mode: 0o644 });
    await chmod(path, 0o644);
    await assert.rejects(createAuthorizedJsonlSink(path).write(serializeDiagnosticEvent(diagnostic, clock.wallTime())));
    assert.equal(await readFile(path, 'utf8'), '');
  }
  assert.equal(lines.join('').includes(secret), false);
});

function lifecycleHarness(overrides = {}) {
  const { calls, options } = harness();
  const lines = [];
  const reports = [];
  let ticks = 500;
  const lifecycle = createObservabilityLifecycle({
    policy, distributedVersion: '0.0.0', os: 'macos',
    clock: { ...clock, monotonicMilliseconds() { const value = ticks; ticks += 1000; return value; } },
    stderr: { async write(line) { lines.push(line); } },
    preferences: options.preferences, sink: options.sink,
    onCompletion(value) { reports.push(value); },
    ...overrides,
  });
  return { lifecycle, lines, reports, calls };
}

const observedDraft = {
  operation: 'draft', access: 'stateful', scope: 'root', host: 'copilot', engine: 'specification',
};
const completed = () => ({ outcome: 'completed' });

test('lifecycle emits real typed diagnostics and one root completion, suppressing nested wrappers across instances', async () => {
  const { lifecycle, lines, reports, calls } = lifecycleHarness();
  const child = lifecycleHarness();
  const original = { result: secret };
  let actions = 0;
  const result = await lifecycle.run(observedDraft, async () => {
    actions += 1;
    await lifecycle.run(observedDraft, async () => { actions += 1; }, () => { throw new Error('Nested classification must not run'); });
    await child.lifecycle.run(observedDraft, async () => { actions += 1; }, completed);
    return original;
  }, completed);
  assert.equal(result, original);
  assert.equal(actions, 3);
  assert.equal(lines.length, 2);
  assert.deepEqual(lines.map((line) => JSON.parse(line).code), ['operation-started', 'operation-stopped']);
  assert.equal(JSON.parse(lines[1]).elapsedMilliseconds, 1000);
  assert.equal(calls.requests.length, 1);
  assert.equal(reports.length, 1);
  assert.deepEqual(reports[0].telemetry, { state: 'delivered' });
  const payload = JSON.parse(calls.requests[0].body);
  assert.equal(payload.durationBucket, '1s-to-10s');
  assert.equal(payload.host, 'copilot');
  assert.equal(child.calls.requests.length + child.lines.length + child.reports.length, 0);
  assert.equal(JSON.stringify({ lines, reports, payload }).includes(secret), false);
  await Promise.all([
    lifecycle.run(observedDraft, async () => 1, completed),
    lifecycle.run({ ...observedDraft, operation: 'revise' }, async () => 2, completed),
  ]);
  assert.equal(calls.requests.length, 3, 'Independent concurrent roots each own exactly one aggregate');
});

test('read-only/preview/helper/child lifecycle contexts bypass all observation and preserve work results', async () => {
  let touched = 0;
  const logPath = join(scratch, 'readonly-lifecycle.jsonl');
  const { lifecycle, calls, lines, reports } = lifecycleHarness({
    localLogPath: logPath,
    clock: { wallTime() { touched += 1; throw new Error(secret); }, monotonicMilliseconds() { touched += 1; return 0; } },
  });
  for (const context of [
    ...['discover', 'clarify', 'analyze', 'onboard'].map((operation) => ({ ...observedDraft, operation })),
    { ...observedDraft, access: 'read-only' }, { ...observedDraft, scope: 'child' },
  ]) {
    const value = { context: 'original' };
    assert.equal(await lifecycle.run({ ...context, persistence: 'authorized-local-log' }, async () => {
      await lifecycle.run(observedDraft, async () => undefined, completed);
      return value;
    }, () => { throw new Error('Excluded classification must not run'); }), value);
  }
  assert.equal(touched + calls.reads + calls.requests.length + lines.length + reports.length, 0);
  await assert.rejects(stat(logPath), { code: 'ENOENT' });
  await assert.rejects(stat(`${logPath}.lock`), { code: 'ENOENT' });
});

test('mandatory audit and functional failures remain original; optional observer failures cannot replace them', async () => {
  const error = Object.assign(new Error(secret), { code: 'persistence-failed' });
  const { lifecycle, lines, calls } = lifecycleHarness({
    onCompletion: async () => { throw new Error(secret); },
  });
  await assert.rejects(lifecycle.run(observedDraft, async () => { throw error; }, completed,
    () => ({ outcome: 'blocked', errorCode: 'persistence-failed' })), (actual) => actual === error);
  assert.equal(JSON.parse(calls.requests[0].body).outcome, 'blocked');
  const stopped = JSON.parse(lines[1]);
  assert.equal(stopped.errorCode, 'persistence-failed');
  assert.equal(stopped.severity, 'warning');
  assert.equal(lines.join('').includes(secret), false);
  await new Promise((resolveTurn) => setImmediate(resolveTurn));
  const unavailable = lifecycleHarness({
    localLogPath: join(scratch, 'missing-directory', 'cannot-log.jsonl'),
    sink: { endpoint: 'https://telemetry.invalid/', transport: { async send() { throw new Error(secret); } } },
  });
  const original = { completedDespiteOptionalDiagnostics: true };
  assert.equal(await unavailable.lifecycle.run({
    ...observedDraft, persistence: 'authorized-local-log',
  }, async () => original, completed), original);
  assert.equal(unavailable.reports[0].started.state, 'unavailable');
  assert.equal(unavailable.reports[0].stopped.state, 'unavailable');
  assert.deepEqual(unavailable.reports[0].telemetry, { state: 'unavailable' });
  assert.equal(JSON.stringify(unavailable.reports).includes(secret), false);
});

test('no-telemetry and default unconfigured composition retain diagnostics but perform no analytics initialization', async () => {
  for (const overrides of [{ policy: { ...policy, disabled: true } }, { sink: undefined }]) {
    const { lifecycle, calls, lines, reports } = lifecycleHarness(overrides);
    assert.equal(await lifecycle.run(observedDraft, async () => 42, completed), 42);
    assert.equal(lines.length, 2);
    assert.equal(calls.reads + calls.requests.length + calls.saves.length + calls.notices.length, 0);
    assert.deepEqual(reports[0].telemetry, {
      state: 'suppressed', reason: overrides.policy ? 'opted-out' : 'not-configured',
    });
  }
});

test('invalid classification does not fabricate success, and invalid monotonic clocks remain unknown', async () => {
  const invalid = lifecycleHarness();
  assert.equal(await invalid.lifecycle.run(observedDraft, async () => 7, () => ({ outcome: secret })), 7);
  assert.equal(invalid.calls.requests.length, 0);
  assert.equal(JSON.parse(invalid.lines[1]).code, 'boundary-rejected');
  assert.deepEqual(invalid.reports[0].telemetry, { state: 'unavailable' });
  assert.equal(invalid.reports[0].classification, 'unavailable');
  const failure = new Error(secret);
  await assert.rejects(invalid.lifecycle.run(observedDraft, async () => { throw failure; }, completed, completed),
    (error) => error === failure);
  assert.equal(invalid.calls.requests.length, 0, 'A throwing operation cannot be labeled completed');
  let tick = 10;
  const clockFailure = lifecycleHarness({
    clock: { ...clock, monotonicMilliseconds() { tick -= 10; return tick; } },
  });
  await clockFailure.lifecycle.run(observedDraft, async () => undefined, () => ({ outcome: 'unknown' }));
  assert.equal(JSON.parse(clockFailure.calls.requests[0].body).durationBucket, null);
  assert.equal(JSON.parse(clockFailure.calls.requests[0].body).outcome, 'unknown');
});

test('completion observer failures and stalls produce one bounded explicit diagnostic without recursion', async () => {
  for (const fail of [
    () => { throw new Error(secret); },
    async () => { throw new Error(secret); },
    () => new Promise(() => {}),
  ]) {
    let notifications = 0;
    const { lifecycle, lines } = lifecycleHarness({
      sink: undefined, onCompletion() { notifications += 1; return fail(); },
    });
    const original = { result: secret };
    const start = performance.now();
    assert.equal(await lifecycle.run(observedDraft, async () => original, completed), original);
    assert.ok(performance.now() - start < 700);
    assert.equal(notifications, 1);
    const failures = lines.map((line) => JSON.parse(line)).filter((line) => line.code === 'boundary-rejected');
    assert.equal(failures.length, 1);
    assert.equal(failures[0].errorCode, 'provider-unavailable');
    assert.equal(lines.join('').includes(secret), false);
  }
});

test('cancellation setup and cleanup failures are explicit unavailable observations, never functional failures', async () => {
  for (const method of ['addEventListener', 'removeEventListener']) {
    const controller = new AbortController();
    const originalMethod = controller.signal[method].bind(controller.signal);
    Object.defineProperty(controller.signal, method, {
      value(...args) {
        if (method === 'removeEventListener') originalMethod(...args);
        throw new Error(secret);
      },
    });
    const { lifecycle, calls, lines, reports } = lifecycleHarness({ signal: controller.signal });
    const value = { result: 'preserved' };
    assert.equal(await lifecycle.run(observedDraft, async () => value, completed), value);
    assert.deepEqual(reports[0].telemetry, { state: 'unavailable' });
    assert.ok(lines.some((line) => JSON.parse(line).code === 'telemetry-unavailable'));
    assert.equal(lines.join('').includes(secret), false);
    assert.equal(calls.requests.length, method === 'addEventListener' ? 0 : 1);
  }
});

test('stalled optional diagnostic sinks are bounded rather than blocking the original result', async () => {
  const { lifecycle, reports } = lifecycleHarness({
    sink: undefined, stderr: { write() { return new Promise(() => {}); } },
  });
  const start = performance.now();
  assert.equal(await lifecycle.run(observedDraft, async () => 'preserved', completed), 'preserved');
  assert.ok(performance.now() - start < 700);
  assert.equal(reports[0].started.state, 'unavailable');
  assert.equal(reports[0].stopped.state, 'unavailable');
});

test('lifecycle bounds stalled telemetry preparation and prevents a late read from displaying or saving a notice', async () => {
  let release;
  let saves = 0;
  const { lifecycle, reports, calls, lines } = lifecycleHarness({
    policy: { ...policy, channel: 'interactive' },
    preferences: {
      read() { return new Promise((resolveRead) => { release = resolveRead; }); },
      async save() { saves += 1; return { state: 'saved' }; },
    },
  });
  const start = performance.now();
  assert.equal(await lifecycle.run(observedDraft, async () => 'original', completed), 'original');
  assert.ok(performance.now() - start < 1500);
  assert.deepEqual(reports[0].telemetry, { state: 'unavailable' });
  release({ state: 'ready', value: {} });
  await new Promise((resolveTurn) => setImmediate(resolveTurn));
  assert.equal(saves + calls.requests.length, 0);
  assert.equal(lines.some((line) => line.includes('not affirmative consent')), false);
});

test('composed telemetry controls use the single explicit store and never emit analytics or diagnostic logs', async () => {
  const preferencePath = join(scratch, 'lifecycle-preferences.sqlite');
  const logPath = join(scratch, 'controls-must-not-log.jsonl');
  const { lifecycle, calls, lines } = lifecycleHarness({
    preferences: undefined, preferencePath, localLogPath: logPath, sink: undefined,
  });
  assert.deepEqual(await lifecycle.telemetryStatus(), {
    state: 'ready', configured: false, eligibleAfterNotice: false, reason: 'not-configured',
    preference: 'default', disclosureVersion: null,
  });
  const preview = lifecycle.previewTelemetry(summary);
  assert.deepEqual(preview, { state: 'ready', event: event(), delivery: 'not-attempted' });
  assert.equal(lifecycle.previewTelemetry({ ...summary, args: secret }).state, 'unavailable');
  assert.deepEqual(lifecycle.previewTelemetry({ ...summary, operation: 'discover' }), { state: 'suppressed', reason: 'read-only' });
  await assert.rejects(stat(preferencePath), { code: 'ENOENT' });
  assert.deepEqual(await lifecycle.setTelemetryPreference('disabled'), { state: 'saved' });
  assert.equal((await lifecycle.telemetryStatus()).reason, 'opted-out');
  assert.deepEqual(await lifecycle.setTelemetryPreference('enabled'), { state: 'saved' });
  assert.equal((await lifecycle.telemetryStatus()).preference, 'enabled');
  assert.equal((await lifecycle.telemetryStatus()).disclosureVersion, null);
  assert.equal(lines.length + calls.requests.length, 0);
  await assert.rejects(stat(logPath), { code: 'ENOENT' });
  const disabled = lifecycleHarness({
    policy: { ...policy, disabled: true }, preferences: { async read() { throw new Error('Hard disable must precede preference read'); } },
  });
  assert.equal((await disabled.lifecycle.telemetryStatus()).preference, 'not-read');
  const missing = lifecycleHarness({ preferences: undefined });
  assert.deepEqual(await missing.lifecycle.setTelemetryPreference('disabled'), { state: 'unavailable', reason: 'not-configured' });
});

test('composed interactive notice skips the first operation and later sends only after persisted disclosure', async () => {
  const preferencePath = join(scratch, 'lifecycle-disclosure.sqlite');
  const { lifecycle, calls, reports, lines } = lifecycleHarness({
    preferences: undefined, preferencePath, policy: { ...policy, channel: 'interactive' },
  });
  assert.equal((await lifecycle.telemetryStatus()).reason, 'notice-required');
  await lifecycle.run(observedDraft, async () => 0, completed);
  assert.deepEqual(reports[0].telemetry, { state: 'suppressed', reason: 'notice-required' });
  assert.equal(calls.requests.length, 0);
  assert.ok(lines.some((line) => line.includes('not affirmative consent')));
  assert.equal((await lifecycle.telemetryStatus()).reason, 'ready');
  await lifecycle.run(observedDraft, async () => 0, completed);
  assert.deepEqual(reports[1].telemetry, { state: 'delivered' });
  assert.equal(calls.requests.length, 1);
});

test('reviewed manual log pruning requires trusted exact-scope reference authorization and rejects booleans/stale snapshots', async () => {
  if (process.platform === 'win32') return;
  const logPath = join(scratch, 'reviewed-prune.jsonl');
  const grants = new Map();
  const authorizations = [];
  const { lifecycle, calls } = lifecycleHarness({
    localLogPath: logPath, sink: undefined,
    logPruneAuthorization: {
      async authorize(input) {
        assert.equal(Object.isFrozen(input), true);
        assert.equal(Object.isFrozen(input.preview), true);
        assert.equal(Object.isFrozen(input.approval), true);
        authorizations.push(input);
        return {
          state: JSON.stringify(grants.get(input.approval.id)) === JSON.stringify(input.preview) ? 'authorized' : 'rejected',
        };
      },
    },
  });
  assert.deepEqual(await lifecycle.previewLogPrune(), { state: 'absent' });
  await assert.rejects(stat(logPath), { code: 'ENOENT' });
  await lifecycle.run({ ...observedDraft, persistence: 'authorized-local-log' }, async () => 0, completed);
  const files = (await readdir(scratch)).sort();
  const preview = await lifecycle.previewLogPrune();
  const original = await readFile(logPath);
  assert.equal(preview.state, 'ready');
  assert.equal(preview.scope, 'local-diagnostics-only');
  assert.equal(preview.bytes, original.length);
  assert.equal(preview.path, logPath);
  assert.deepEqual((await readdir(scratch)).sort(), files);
  const approval = { id: 'APR-prune-reviewed' };
  grants.set(approval.id, preview);
  for (const invalidReference of [true, false, { confirmed: true }, { confirmed: false }, { id: approval.id, confirmed: true }]) {
    assert.deepEqual(await lifecycle.pruneLog(preview, invalidReference), {
      state: 'unavailable', reason: 'authorization-required', effect: 'unchanged',
    });
  }
  assert.equal(authorizations.length, 0);
  const noAuthorization = lifecycleHarness({ localLogPath: logPath, sink: undefined });
  assert.deepEqual(await noAuthorization.lifecycle.pruneLog(preview, approval), {
    state: 'unavailable', reason: 'authorization-unavailable', effect: 'unchanged',
  });
  assert.deepEqual(await lifecycle.pruneLog(preview, { id: 'APR-unrecognized' }), {
    state: 'unavailable', reason: 'authorization-rejected', effect: 'unchanged',
  });
  assert.deepEqual(await lifecycle.pruneLog({ ...preview, bytes: preview.bytes + 1 }, approval), {
    state: 'unavailable', reason: 'authorization-rejected', effect: 'unchanged',
  });
  assert.deepEqual(await lifecycle.pruneLog({ ...preview, path: join(scratch, 'other.jsonl') }, approval), {
    state: 'unavailable', reason: 'invalid-preview', effect: 'unchanged',
  });
  assert.deepEqual(await readFile(logPath), original);
  await lifecycle.run({ ...observedDraft, persistence: 'authorized-local-log' }, async () => 0, completed);
  const appended = await readFile(logPath);
  assert.deepEqual(await lifecycle.pruneLog(preview, approval), {
    state: 'unavailable', reason: 'stale-preview', effect: 'unchanged',
  });
  assert.deepEqual(await readFile(logPath), appended);
  const current = await lifecycle.previewLogPrune();
  assert.deepEqual(await lifecycle.pruneLog(current, approval), {
    state: 'unavailable', reason: 'authorization-rejected', effect: 'unchanged',
  });
  const nextApproval = { id: 'APR-prune-next-review' };
  grants.set(nextApproval.id, current);
  const mutablePreview = { ...current };
  const mutableReference = { ...nextApproval };
  const pending = lifecycle.pruneLog(mutablePreview, mutableReference);
  mutablePreview.path = join(scratch, 'other.jsonl');
  mutableReference.id = 'APR-unrecognized';
  assert.deepEqual(await pending, { state: 'pruned' });
  assert.deepEqual(authorizations.at(-1), { preview: current, approval: nextApproval });
  assert.equal((await stat(logPath)).size, 0);
  assert.deepEqual(await lifecycle.pruneLog(current, nextApproval), {
    state: 'unavailable', reason: 'stale-preview', effect: 'unchanged',
  });
  assert.equal(calls.requests.length + calls.reads, 0);
  const sink = createAuthorizedJsonlSink(logPath);
  assert.deepEqual(await sink.prune(undefined), { state: 'unavailable', reason: 'invalid-preview', effect: 'unchanged' });
  const unrelated = join(scratch, 'not-diagnostics.jsonl');
  await writeFile(unrelated, `{"private":"${secret}"}\n`, { mode: 0o600 });
  const unrelatedSink = createAuthorizedJsonlSink(unrelated);
  assert.equal((await unrelatedSink.previewPrune()).state, 'unavailable');
  await assert.rejects(unrelatedSink.write(serializeDiagnosticEvent(diagnostic, clock.wallTime())));
  assert.equal(await readFile(unrelated, 'utf8'), `{"private":"${secret}"}\n`);
});

test('unavailable, malformed, throwing and stalled prune authorization never truncates the reviewed file', async () => {
  if (process.platform === 'win32') return;
  const path = join(scratch, 'authorization-failures.jsonl');
  const initial = lifecycleHarness({ localLogPath: path, sink: undefined });
  await initial.lifecycle.run({ ...observedDraft, persistence: 'authorized-local-log' }, async () => 0, completed);
  const preview = await initial.lifecycle.previewLogPrune();
  const original = await readFile(path);
  for (const authorize of [
    async () => ({ state: 'unavailable' }), async () => true,
    async () => ({ state: 'authorized', rawError: secret }),
    async () => { throw new Error(secret); }, () => new Promise(() => {}),
  ]) {
    const { lifecycle } = lifecycleHarness({ localLogPath: path, sink: undefined, logPruneAuthorization: { authorize } });
    const result = await lifecycle.pruneLog(preview, { id: 'APR-existing-reference' });
    assert.deepEqual(result, { state: 'unavailable', reason: 'authorization-unavailable', effect: 'unchanged' });
    assert.deepEqual(await readFile(path), original);
    assert.equal(JSON.stringify(result).includes(secret), false);
  }
});

test('a closed native stderr pipe returns unavailable without an uncaught stream error', { timeout: 5_000 }, async (context) => {
  const moduleUrl = pathToFileURL(resolve('dist/adapters/logging/diagnostics.js')).href;
  const script = `
    import { createDiagnostics, createStderrDiagnosticSink } from ${JSON.stringify(moduleUrl)};
    await new Promise(resolve => process.stdin.once('data', resolve));
    const diagnostics = createDiagnostics({
      clock: { wallTime: () => '2026-09-20T18:00:00.000Z' },
      stderr: createStderrDiagnosticSink()
    });
    const results = [];
    for (let i = 0; i < 2; i += 1) results.push(await diagnostics.emit(${JSON.stringify(diagnostic)}, 'console-only'));
    process.stdout.write(JSON.stringify(results));
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], { stdio: ['pipe', 'pipe', 'pipe'] });
  context.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });
  const exited = once(child, 'close');
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  const closed = once(child.stderr, 'close');
  child.stderr.destroy();
  await closed;
  child.stdin.end('start');
  const [code, signal] = await exited;
  assert.equal(signal, null);
  assert.equal(code, 0);
  assert.deepEqual(JSON.parse(output), [
    { state: 'unavailable', consoleFallback: 'unavailable' },
    { state: 'unavailable', consoleFallback: 'unavailable' },
  ]);
});

test('native transport controlled loopback TLS proves status, redirect, body disposal and timeout without external calls', { timeout: 15_000 }, async (t) => {
  const keyPath = join(scratch, 'loopback-key.pem');
  const certPath = join(scratch, 'loopback-cert.pem');
  try {
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], { stdio: 'ignore', timeout: 10_000 });
  } catch {
    t.skip('Local OpenSSL with subjectAltName support is unavailable; mocked native transport cases still run');
    return;
  }
  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  const observations = [];
  let resolveBodyClosed;
  const bodyClosed = new Promise((resolveClose) => { resolveBodyClosed = resolveClose; });
  let mode = 'ok';
  const server = createServer({ key, cert }, (req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      observations.push({ body, headers: req.headers });
      if (mode === 'stall') return;
      if (mode === 'redirect') {
        res.writeHead(307, { location: 'https://external.invalid/never' });
        res.end();
      } else if (mode === 'body') {
        res.on('close', resolveBodyClosed);
        res.writeHead(200);
        res.write('x'.repeat(4096));
      } else {
        res.writeHead(204);
        res.end();
      }
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const endpoint = `https://127.0.0.1:${server.address().port}/v1/events`;
  const transport = createHttpsTelemetryTransport((url, options, callback) => request(url, { ...options, ca: cert }, callback));
  try {
    assert.deepEqual(await transport.send({ endpoint, body: serializeTelemetryEvent(event()), signal: new AbortController().signal }), { state: 'delivered' });
    assert.deepEqual(JSON.parse(observations[0].body), event());
    assert.equal(observations[0].headers['user-agent'], undefined);
    mode = 'redirect';
    assert.deepEqual(await transport.send({ endpoint, body: serializeTelemetryEvent(event()), signal: new AbortController().signal }), { state: 'unavailable' });
    assert.equal(observations.length, 2);
    mode = 'body';
    assert.deepEqual(await transport.send({ endpoint, body: serializeTelemetryEvent(event()), signal: new AbortController().signal }), { state: 'delivered' });
    await bodyClosed;
    mode = 'stall';
    const start = performance.now();
    assert.deepEqual(await transport.send({ endpoint, body: serializeTelemetryEvent(event()), signal: new AbortController().signal }), { state: 'unavailable' });
    assert.ok(performance.now() - start < 1600);
    const controller = new AbortController();
    const pending = transport.send({ endpoint, body: serializeTelemetryEvent(event()), signal: controller.signal });
    controller.abort(new Error(secret));
    assert.deepEqual(await pending, { state: 'unavailable' });
  } finally {
    server.closeAllConnections();
    await new Promise((resolveClose) => server.close(resolveClose));
  }
});
