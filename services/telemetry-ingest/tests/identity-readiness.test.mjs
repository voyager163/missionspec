import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate as turn } from 'node:timers/promises';
import { createIdentityReadiness, INGESTION_SCOPE, STORAGE_SCOPE, IDENTITY_PREPARATION_TIMEOUT_MS,
  IDENTITY_REFRESH_MARGIN_MS } from '../dist/identity-readiness.js';
import { createStorageAdapter } from '../dist/azure-storage.js';
import { createTelemetryServer } from '../dist/server.js';
import { assertEmpty, limits, post, start } from './helpers.mjs';

const accessToken = (fields = {}) => ({
  token: 'in-memory-noncredential',
  expiresOnTimestamp: Date.now() + 3600000,
  ...fields,
});
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const health = (receiver, kind = 'ready') => post(receiver.port, '', { method: 'GET', path: `/health/${kind}` });

test('storage and monitor identities are separately scoped and never return a token for the other audience', async t => {
  for (const scope of [STORAGE_SCOPE, INGESTION_SCOPE]) {
    const other = scope === STORAGE_SCOPE ? INGESTION_SCOPE : STORAGE_SCOPE;
    const identity = createIdentityReadiness({ async getToken(requested) {
      assert.equal(requested, scope);
      return accessToken();
    } }, scope);
    t.after(() => identity.readiness.stop());
    identity.readiness.setEnabled(true);
    await turn();
    assert.equal(identity.readiness.ready(), true);
    assert(await identity.credential.getToken(scope));
    await assert.rejects(identity.credential.getToken(other), /IDENTITY_NOT_READY/);
    await assert.rejects(identity.credential.getToken(scope, { tenantId: 'challenge' }), /IDENTITY_NOT_READY/);
  }
});
test('constructors and disabled listening receiver do no identity/upload work; enabling prepares once', async t => {
  let calls = 0, uploads = 0;
  const pending = deferred();
  const prepared = createIdentityReadiness({ getToken(scopes) {
    assert.equal(scopes, INGESTION_SCOPE);
    calls++;
    return pending.promise;
  } });
  const storage = createStorageAdapter({ async upload() { uploads++; } }, 'unused', prepared.readiness);
  const inert = createTelemetryServer({ storage, limits, enabled: true });
  assert.equal(calls, 0);
  assert.equal(inert.ready(), false);
  assert.equal(calls, 0);
  const receiver = await start(t, { storage, enabled: false });
  assertEmpty(assert, await health(receiver), 204);
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(calls, 0);
  receiver.setEnabled(true);
  receiver.setEnabled(true);
  assertEmpty(assert, await health(receiver), 503);
  assertEmpty(assert, await health(receiver, 'live'), 204);
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(calls, 1);
  pending.resolve(accessToken());
  await turn();
  assertEmpty(assert, await health(receiver), 204);
  assertEmpty(assert, await post(receiver.port), 204);
  assert.equal(calls, 1);
  assert.equal(uploads, 1);
  assert.equal(receiver.snapshot().storage_timeout, undefined);
});

test('initialization deadline quarantines the real task; repeated enable/probes cannot release it or revive late success', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let calls = 0, signal;
  const pending = deferred();
  const { credential, readiness } = createIdentityReadiness({ getToken(_scopes, options) {
    calls++;
    signal = options.abortSignal;
    return pending.promise;
  } });
  t.after(() => readiness.stop());
  readiness.setEnabled(true);
  await turn();
  t.mock.timers.tick(IDENTITY_PREPARATION_TIMEOUT_MS - 1);
  assert.equal(signal.aborted, false);
  assert.equal(readiness.ready(), false);
  t.mock.timers.tick(1);
  assert.equal(signal.aborted, true);
  for (let index = 0; index < 20; index++) {
    readiness.setEnabled(true);
    assert.equal(readiness.ready(), false);
  }
  assert.equal(calls, 1);
  pending.resolve(accessToken());
  await turn();
  assert.equal(readiness.ready(), false);
  await assert.rejects(credential.getToken(INGESTION_SCOPE), /IDENTITY_NOT_READY/);
  readiness.setEnabled(false);
  readiness.setEnabled(true);
  await turn();
  assert.equal(calls, 1);
  assert.equal(readiness.ready(), false);
});

test('deadline is checked on settlement even before a delayed timer gets to run', async t => {
  let monotonic = 0;
  t.mock.method(performance, 'now', () => monotonic);
  const pending = deferred();
  const { readiness } = createIdentityReadiness({ getToken() { return pending.promise; } });
  t.after(() => readiness.stop());
  readiness.setEnabled(true);
  await turn();
  monotonic = IDENTITY_PREPARATION_TIMEOUT_MS;
  pending.resolve(accessToken());
  await turn();
  assert.equal(readiness.ready(), false);
});

test('failures, missing/short/invalid tokens and stale refresh readbacks fail closed without retry', async t => {
  for (const result of [
    () => { throw new Error('PRIVATE_TOKEN_FAILURE'); },
    () => Promise.reject(new Error('PRIVATE_ASYNC_TOKEN_FAILURE')),
    () => null,
    () => accessToken({ token: '' }),
    () => accessToken({ token: 1 }),
    () => accessToken({ expiresOnTimestamp: Date.now() + IDENTITY_REFRESH_MARGIN_MS }),
    () => accessToken({ expiresOnTimestamp: NaN }),
    () => accessToken({ expiresOnTimestamp: Infinity, refreshAfterTimestamp: Date.now() + 10000 }),
    () => accessToken({ refreshAfterTimestamp: NaN }),
    () => accessToken({ refreshAfterTimestamp: Date.now() - 1 }),
  ]) {
    let calls = 0;
    const { readiness } = createIdentityReadiness({ async getToken() { calls++; return result(); } });
    t.after(() => readiness.stop());
    readiness.setEnabled(true);
    await turn();
    assert.equal(readiness.ready(), false);
    const settledCalls = calls;
    assert(settledCalls >= 1 && settledCalls <= 2);
    for (let index = 0; index < 10; index++) readiness.setEnabled(true);
    await turn();
    assert.equal(calls, settledCalls);
  }
});

test('expiry margin and SDK refreshAfter each close admission and renew singleflight, not on a timer poller', async t => {
  for (const useRefreshAfter of [false, true]) {
    let instant = 1800000000000, calls = 0;
    const originalNow = Date.now;
    Date.now = () => instant;
    const renewal = deferred();
    const initial = accessToken(useRefreshAfter ? { refreshAfterTimestamp: instant + 10000 } : {});
    const { credential, readiness } = createIdentityReadiness({ async getToken() {
      calls++;
      return calls === 1 ? initial : renewal.promise;
    } });
    try {
      readiness.setEnabled(true);
      await turn();
      assert.equal(readiness.ready(), true);
      assert.equal(await credential.getToken(INGESTION_SCOPE), initial);
      const due = useRefreshAfter ? initial.refreshAfterTimestamp : initial.expiresOnTimestamp - IDENTITY_REFRESH_MARGIN_MS;
      instant = due - 1;
      assert.equal(readiness.ready(), true);
      instant = due;
      for (let index = 0; index < 20; index++) assert.equal(readiness.ready(), false);
      await turn();
      assert.equal(calls, 2);
      const renewed = accessToken();
      renewal.resolve(renewed);
      await turn();
      assert.equal(readiness.ready(), true);
      assert.equal(await credential.getToken(INGESTION_SCOPE), renewed);
      assert.equal(calls, 2);
      await assert.rejects(credential.getToken('https://other.invalid/.default'), /IDENTITY_NOT_READY/);
      await assert.rejects(credential.getToken(INGESTION_SCOPE, { claims: 'challenge' }), /IDENTITY_NOT_READY/);
    } finally {
      readiness.stop();
      Date.now = originalNow;
    }
  }
});

test('MSAL refreshOn old-result behavior requires one actual fresh cache readback, never a fabricated ready timestamp', async t => {
  let calls = 0;
  const stale = accessToken({ refreshAfterTimestamp: Date.now() - 1 });
  const fresh = accessToken();
  const { credential, readiness } = createIdentityReadiness({ async getToken() {
    calls++;
    return calls === 1 ? stale : fresh;
  } });
  t.after(() => readiness.stop());
  readiness.setEnabled(true);
  await turn();
  assert.equal(calls, 2);
  assert.equal(readiness.ready(), true);
  assert.equal(await credential.getToken(INGESTION_SCOPE), fresh);
});

test('renewal failure stays unready past expiry and disabled/stop interrupts cannot revive late work', async t => {
  for (const action of ['fail-renewal', 'disable', 'stop']) {
    let instant = 1800000000000, calls = 0, signal;
    const originalNow = Date.now;
    Date.now = () => instant;
    const pending = deferred();
    const { credential, readiness } = createIdentityReadiness({ async getToken(_scopes, options) {
      calls++;
      signal = options.abortSignal;
      if (action === 'fail-renewal' && calls === 1) return accessToken();
      return pending.promise;
    } });
    try {
      readiness.setEnabled(true);
      await turn();
      if (action === 'fail-renewal') {
        instant += 3600000 - IDENTITY_REFRESH_MARGIN_MS;
        assert.equal(readiness.ready(), false);
        await turn();
        pending.reject(new Error('PRIVATE_RENEWAL_FAILURE'));
      } else {
        if (action === 'disable') readiness.setEnabled(false);
        else readiness.stop();
        assert.equal(signal.aborted, true);
        pending.resolve(accessToken());
      }
      await turn();
      readiness.setEnabled(true);
      instant += 3600000;
      assert.equal(readiness.ready(), false);
      await assert.rejects(credential.getToken(INGESTION_SCOPE), /IDENTITY_NOT_READY/);
      assert.equal(calls, action === 'fail-renewal' ? 2 : 1);
    } finally {
      readiness.stop();
      Date.now = originalNow;
    }
  }
});

test('identity readiness never bypasses real storage failure/cooldown', async t => {
  let instant = 0;
  const prepared = createIdentityReadiness({ async getToken() { return accessToken(); } });
  const receiver = await start(t, {
    monotonicNow: () => instant,
    storage: createStorageAdapter({ async upload() { throw new Error('PRIVATE_STORAGE_FAILURE'); } }, 'unused', prepared.readiness),
  });
  await turn();
  assertEmpty(assert, await health(receiver), 204);
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(prepared.readiness.ready(), true);
  assertEmpty(assert, await health(receiver), 503);
  instant = 5000;
  assertEmpty(assert, await health(receiver), 204);
  assert.equal(receiver.snapshot().accepted, undefined);
});
