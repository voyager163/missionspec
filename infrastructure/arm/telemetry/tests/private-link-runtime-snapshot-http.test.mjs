import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import https from 'node:https';
import { registerHooks } from 'node:module';
import test from 'node:test';

const runtimeUrl = new URL('../private-link-runtime.mjs?owned-snapshot-http-test', import.meta.url).href;
const hooks = registerHooks({
  load(url, context, next) {
    const loaded = next(url, context);
    if (url !== runtimeUrl) return loaded;
    return { ...loaded, source: loaded.source.toString() +
      '\nexport { forwardRuntime as testForwardRuntime, runtimeScopes as testRuntimeScopes,' +
      ' immutableRuntime as testImmutableRuntime, runtimeSnapshotShape as testRuntimeSnapshotShape };\n' };
  },
});
let runtime;
try { runtime = await import(runtimeUrl); }
finally { hooks.deregister(); }

async function scope(value, use) {
  const state = { immutable: new WeakSet(), owned: new WeakSet(), hashes: new WeakMap(), candidates: new WeakMap() };
  const owned = runtime.testImmutableRuntime(structuredClone(value), state.immutable);
  if (runtime.testRuntimeSnapshotShape(owned)) runtime.testImmutableRuntime(owned, state.owned);
  runtime.testRuntimeScopes.add(state);
  try { return await runtime.testForwardRuntime.run(state, () => use(owned, state)); }
  finally { runtime.testRuntimeScopes.delete(state); }
}
function objects(value, result = new Set()) {
  if (value === null || typeof value !== 'object' || result.has(value)) return result;
  result.add(value);
  Object.values(value).forEach(child => objects(child, result));
  return result;
}

test('forward snapshots retain operation-owned JSON without cloning repeated history', async () => {
  const history = { records: Array.from({ length: 2000 }, (_, index) => ({ index })) };
  await scope(history, async owned => {
    await Promise.resolve();
    const copies = Array.from({ length: 3 }, () => runtime.privateLinkValidationCopy({ history: owned }));
    for (const copy of copies) {
      assert.equal(copy.history, owned);
      assert(Object.isFrozen(copy));
    }
    assert(objects(copies).size <= 2010, 'three snapshots must retain one 2000-record graph, not three graphs');
    assert.notEqual(owned, history);
    assert.equal(Object.isFrozen(history), false);
    history.records[0].index = -1;
    assert.equal(owned.records[0].index, 0);
  });
});

test('caller-frozen hash membership is not owned snapshot provenance', async () => {
  const caller = Object.freeze({ nested: Object.freeze({ value: 1 }) });
  await scope({ local: true }, async (_owned, state) => {
    runtime.privateLinkValidationHash(caller);
    assert(state.immutable.has(caller));
    assert(!state.owned.has(caller));
    const copy = runtime.privateLinkValidationCopy({ caller });
    assert.notEqual(copy.caller, caller);
    assert.notEqual(copy.caller.nested, caller.nested);
    assert(state.owned.has(copy.caller));
    assert.deepEqual(copy.caller, caller);
  });
});

test('forward snapshots preserve aliases, array holes, key order and safe own __proto__ properties', async () => {
  const shared = { value: 1 }, emptyPrototype = Object.create(null);
  emptyPrototype.first = shared;
  const array = new Array(4);
  array[2] = shared; array.extra = emptyPrototype;
  const input = { array, shared, emptyPrototype };
  Object.defineProperty(input, '__proto__', { value: { own: true }, enumerable: true });
  await scope({ local: true }, async () => {
    const copy = runtime.privateLinkValidationCopy(input);
    assert.deepEqual(copy, structuredClone(input));
    assert.deepEqual(Object.keys(copy), Object.keys(input));
    assert.equal(copy.array[2], copy.shared);
    assert.equal(copy.array.extra, copy.emptyPrototype);
    assert.equal(copy.emptyPrototype.first, copy.shared);
    assert.equal(Object.hasOwn(copy.array, 0), false);
    assert.equal(copy.array.length, 4);
    assert.equal(Object.getPrototypeOf(copy), Object.prototype);
    assert.equal(Object.hasOwn(copy, '__proto__'), true);
    for (const value of objects(copy)) assert(Object.isFrozen(value));
  });
});

test('unsupported fast-path values retain structured-clone behavior instead of caller aliases', async () => {
  const values = [
    { value: new Date('2026-01-01T00:00:00Z') },
    { value: new Map([['key', { nested: true }]]) },
    { value: new Set([{ nested: true }]) },
    { value: Infinity }, { value: 1n },
    Object.defineProperty({}, 'value', { enumerable: true, get: () => ({ nested: true }) }),
  ];
  await scope({ local: true }, async () => {
    for (const value of values) {
      const copy = runtime.privateLinkValidationCopy(value);
      assert.deepEqual(copy, structuredClone(value));
      if (typeof value.value === 'object') assert.notEqual(copy.value, value.value);
    }
    const cyclic = {}; cyclic.self = cyclic;
    const copy = runtime.privateLinkValidationCopy(cyclic);
    assert.notEqual(copy, cyclic); assert.equal(copy.self, copy);
    assert.throws(() => runtime.privateLinkValidationCopy(new Proxy({}, {})), { name: 'DataCloneError' });
  });
});

test('snapshot ownership cannot leak across concurrent or closed forward scopes', async () => {
  let first;
  await Promise.all([
    scope({ value: 1 }, async owned => { first = owned; await Promise.resolve(); }),
    scope({ value: 2 }, async (_owned, state) => {
      await Promise.resolve();
      assert(first);
      const copy = runtime.privateLinkValidationCopy(first);
      assert.notEqual(copy, first);
      assert(state.owned.has(copy));
    }),
  ]);
  const outside = runtime.privateLinkValidationCopy(first);
  assert.notEqual(outside, first);
  let savedState, savedOwned;
  await scope({ value: 3 }, async (owned, state) => { savedState = state; savedOwned = owned; });
  runtime.testForwardRuntime.run(savedState, () => {
    assert(!runtime.testRuntimeScopes.has(savedState));
    assert.notEqual(runtime.privateLinkValidationCopy(savedOwned), savedOwned);
  });
});

async function httpAdapter(options = {}) {
  const io = await runtime.privateLinkRuntimeIO({}, {}, {}, '/UNIT/inert', { control: {}, ...options });
  const rows = [];
  io.immutable = async (name, value) => rows.push({ name, value: structuredClone(value) });
  return { io, rows };
}
function successfulRequest(options, receive) {
  assert.equal(options.rejectUnauthorized, true);
  const request = new EventEmitter();
  request.destroy = () => {};
  request.end = () => queueMicrotask(() => {
    const socket = new EventEmitter(); socket.authorized = true;
    request.emit('socket', socket);
    socket.emit('lookup', null); socket.emit('connect'); socket.emit('secureConnect');
    request.emit('finish');
    const response = new EventEmitter();
    response.statusCode = 503;
    response.headers = { 'cache-control': 'no-store', 'content-length': '0', connection: 'close' };
    response.destroy = () => {};
    receive(response); response.emit('end');
  });
  return request;
}
const host = 'unit.australiaeast.azurecontainerapps.io';

test('default HTTP retains complete success observations with distinct immutable names', async t => {
  t.mock.method(https, 'request', successfulRequest);
  const { io, rows } = await httpAdapter();
  const responses = await Promise.all(Array.from({ length: 2 }, () =>
    io.http(host, 'GET', '/health/ready', undefined, () => {}, Date.now() + 1000)));
  assert.equal(rows.length, 2); assert.equal(new Set(rows.map(row => row.name)).size, 2);
  for (let i = 0; i < rows.length; i++) {
    assert.match(rows[i].name, /^private-runtime-http-[a-f0-9-]{36}\.json$/u);
    assert.equal(rows[i].value.kind, 'private-runtime-http-observation');
    assert.equal(rows[i].value.failure, null);
    assert.equal(rows[i].value.response.status, 503);
    assert.equal(rows[i].value.response.tlsVerified, true);
    assert(Date.parse(rows[i].value.completedAt) >= Date.parse(rows[i].value.startedAt));
  }
  responses[0].status = 200;
  assert(rows.every(row => row.value.response.status === 503));
});

test('default HTTP retains transport-error responses without inventing a thrown failure', async t => {
  t.mock.method(https, 'request', () => { throw Object.assign(new Error('unit-secret'), { code: 'ENOTFOUND' }); });
  const { io, rows } = await httpAdapter();
  const response = await io.http(host, 'GET', '/health/ready', undefined, () => {}, Date.now() + 1000);
  assert.equal(response.errorCode, 'HTTPS_REQUEST_FAILED');
  assert.equal(response.failureCategory, 'dns');
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].value.response, response);
  assert.equal(rows[0].value.failure, null);
  assert(!JSON.stringify(rows).includes('unit-secret'));
});

test('default HTTP retains sanitized guard failure and rethrows the original error without dispatch', async t => {
  let dispatched = 0;
  t.mock.method(https, 'request', () => { dispatched++; assert.fail('guard must reject first'); });
  const { io, rows } = await httpAdapter(), error = new Error('unit-secret: forbidden');
  await assert.rejects(io.http(host, 'GET', '/health/ready', undefined, () => { throw error; }, Date.now() + 1000),
    actual => actual === error);
  assert.equal(dispatched, 0); assert.equal(rows.length, 1);
  assert.equal(rows[0].value.response, null);
  assert.equal(rows[0].value.failure.code, 'OPERATION_FAILED');
  assert(!JSON.stringify(rows).includes('unit-secret'));
});

test('default HTTP cannot report success when immutable observation retention fails', async t => {
  t.mock.method(https, 'request', successfulRequest);
  const { io } = await httpAdapter(), error = new Error('UNIT_RETENTION_FAILED');
  let attempts = 0;
  io.immutable = async () => { attempts++; throw error; };
  await assert.rejects(io.http(host, 'GET', '/health/ready', undefined, () => {}, Date.now() + 1000),
    actual => actual === error);
  assert.equal(attempts, 1);
});

test('an explicit custom HTTP port keeps its existing behavior without default observation writes', async () => {
  const response = { status: 503 };
  let calls = 0;
  const custom = async () => { calls++; return response; };
  const { io, rows } = await httpAdapter({ http: custom });
  assert.equal(io.http, custom);
  assert.equal(await io.http(), response);
  assert.equal(calls, 1); assert.equal(rows.length, 0);
});
