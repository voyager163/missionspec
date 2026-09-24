import assert from 'node:assert/strict';
import test from 'node:test';
import { setImmediate as turn } from 'node:timers/promises';
import { createQueueStorage, QUEUE_CAPACITY, QUEUE_TTL_SECONDS, QUEUE_PROPERTIES_INTERVAL_MS,
  WORKER_UPLOAD_TIMEOUT_MS, QUEUE_TRANSACTION_TIMEOUT_MS } from '../dist/queue-storage.js';
import { createProjector, createQueuedRecordValidator } from '../dist/contract.js';
import { assertEmpty, event, post, start } from './helpers.mjs';

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { resolve, reject, promise };
};
const response = status => ({ _response: { status } });
function fixture(t, overrides = {}) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let clock = 0;
  const epoch = Date.parse('2026-09-24T00:00:00.000Z');
  const now = () => epoch + clock;
  const record = createProjector()(event, new Date(now()));
  const calls = { properties: 0, sends: 0, receive: 0, upload: 0, deletes: 0 };
  const identity = () => ({ enabled: false, available: true, setEnabled(v) { this.enabled = v; },
    ready() { return this.enabled && this.available; }, stop() { this.enabled = false; } });
  const producer = identity(), consumer = identity();
  const messages = [];
  const queue = {
    async getProperties() { calls.properties++; return { ...response(200), approximateMessagesCount: messages.length }; },
    async sendMessage(text, options) {
      calls.sends++;
      assert.equal(options.messageTimeToLive, 3600);
      assert.equal(options.visibilityTimeout, 0);
      assert(Buffer.byteLength(text) <= 1024);
      messages.push({ messageId: `message-${calls.sends}`, popReceipt: 'receipt', messageText: text,
        insertedOn: new Date(now()), expiresOn: new Date(now() + 3600000), dequeueCount: 1, nextVisibleOn: new Date(now() + 60000) });
      return { ...response(201), messageId: 'accepted', popReceipt: 'receipt' };
    },
    async receiveMessages(options) {
      calls.receive++;
      assert.equal(options.numberOfMessages, 32);
      assert.equal(options.visibilityTimeout, 60);
      return { ...response(200), receivedMessageItems: messages.slice(0, 32) };
    },
    async deleteMessage(id) { calls.deletes++; messages.splice(messages.findIndex(m => m.messageId === id), 1); return response(204); },
    ...overrides,
  };
  const batches = [];
  const upload = { async upload(_rule, stream, rows, options) {
    calls.upload++;
    assert.equal(stream, 'Custom-MissionSpecTelemetry');
    assert.equal(options.maxConcurrency, 1);
    assert(rows.length <= 32);
    batches.push(rows);
  } };
  const storage = createQueueStorage({ queue, upload, ruleId: 'test', producerIdentity: producer, consumerIdentity: consumer,
    now, monotonicNow: () => clock });
  t.after(() => storage.readiness.stop());
  const step = async ms => { clock += ms; t.mock.timers.tick(ms); await turn(); };
  const enable = async () => { storage.readiness.setEnabled(true); await step(1000); };
  const send = () => storage.ingest(record, new AbortController().signal);
  return { storage, calls, queue, upload, producer, consumer, messages, batches, record, enable, step, now, send };
}

const queueOperations = [
  { method: 'getProperties', call: 'properties', code: 'queue_properties_failed', status: 200 },
  { method: 'sendMessage', call: 'sends', code: 'queue_send_unknown', status: 201 },
  { method: 'receiveMessages', call: 'receive', code: 'queue_receive_unknown', status: 200 },
  { method: 'deleteMessage', call: 'deletes', code: 'queue_delete_unknown', status: 204 },
];

for (const operation of queueOperations) {
  test(`malformed ${operation.method} results record ${operation.code} and stop further work`, async t => {
    const fields = { approximateMessagesCount: 0, messageId: 'message', popReceipt: 'receipt', receivedMessageItems: [] };
    const cases = [
      ['undefined', () => undefined],
      ['null', () => null],
      ['missing-response', () => ({ ...fields })],
      ['missing-status', () => ({ ...fields, _response: {} })],
      ['wrong-status', () => ({ ...fields, ...response(299) })],
    ];
    if (operation.method !== 'deleteMessage') cases.push(['missing-result-fields', () => response(operation.status)]);
    if (operation.method === 'receiveMessages') cases.push(['throwing-items-getter', () => ({
      ...response(200),
      get receivedMessageItems() { throw new Error('PRIVATE_RESPONSE_GETTER'); },
    })]);
    for (const [name, result] of cases) await t.test(name, async t => {
      const f = fixture(t);
      const malformed = async () => { f.calls[operation.call]++; return result(); };
      if (operation.method === 'getProperties') f.queue.getProperties = malformed;
      if (operation.method === 'sendMessage') f.consumer.available = false;
      await f.enable();
      if (operation.method === 'sendMessage') {
        f.queue.sendMessage = malformed;
        await assert.rejects(f.send(), /QUEUE_OUTCOME_UNKNOWN/);
      } else if (operation.method === 'receiveMessages') {
        f.queue.receiveMessages = malformed;
        await f.step(1000);
      } else if (operation.method === 'deleteMessage') {
        await f.send(); await f.send();
        for (const message of f.messages) message.messageText = '{}';
        f.queue.deleteMessage = malformed;
        await f.step(1000);
        assert.equal(f.messages.length, 2);
        assert.equal(f.storage.snapshot().dropped_invalid, undefined);
      }
      assert.equal(f.calls[operation.call], 1);
      assert.equal(f.storage.snapshot()[operation.code], 1);
      assert.equal(f.storage.readiness.ready(), false);
      assert.equal(f.calls.upload, 0);
      assert.equal(f.storage.snapshot().logs_delivered, undefined);
      if (operation.method !== 'deleteMessage') {
        assert.equal(f.calls.deletes, 0);
        assert.equal(f.storage.snapshot().queued, undefined);
      }
      await f.step(1000);
      assert.equal(f.calls[operation.call], 1);
      assert(!JSON.stringify(f.storage.snapshot()).includes('PRIVATE_RESPONSE_GETTER'));
    });
  });
}

test('malformed enqueue success is HTTP 503, never optimistic 202', async t => {
  const f = fixture(t);
  f.consumer.available = false;
  await f.enable();
  f.queue.sendMessage = async () => { f.calls.sends++; return undefined; };
  const receiver = await start(t, { storage: f.storage });
  assertEmpty(assert, await post(receiver.port), 503);
  assert.equal(f.calls.sends, 1);
  assert.equal(f.storage.snapshot().queue_send_unknown, 1);
  assert.equal(f.storage.snapshot().queued, undefined);
  assert.equal(receiver.snapshot().queued, undefined);
});

test('malformed late worker results cannot replace unresolved receive/delete work or acknowledge disposal', async t => {
  for (const method of ['receiveMessages', 'deleteMessage']) await t.test(method, async t => {
    const pending = deferred();
    const f = fixture(t);
    await f.enable();
    await f.send(); await f.send();
    const operation = queueOperations.find(value => value.method === method);
    f.queue[method] = async () => { f.calls[operation.call]++; return pending.promise; };
    await f.step(1000);
    assert.equal(f.calls[operation.call], 1);
    await f.step(QUEUE_TRANSACTION_TIMEOUT_MS);
    assert.equal(f.storage.snapshot()[operation.code], 1);
    await f.step(60000);
    assert.equal(f.calls[operation.call], 1);
    assert.equal(f.calls.receive, 1);
    pending.resolve(undefined);
    await turn();
    assert.equal(f.storage.snapshot()[operation.code], 1);
    assert.equal(f.calls[operation.call], 1);
    assert.equal(f.messages.length, 2);
    assert.equal(f.storage.snapshot().dropped_invalid, undefined);
    if (method === 'receiveMessages') {
      assert.equal(f.calls.upload, 0);
      assert.equal(f.calls.deletes, 0);
    }
  });
});

test('queue TTL, payload and original TimeGenerated survive validation without re-projection', async t => {
  const f = fixture(t);
  const validate = createQueuedRecordValidator();
  assert.deepEqual(validate(JSON.stringify(f.record)), f.record);
  for (const bad of [{ ...f.record, ip: 'forbidden' }, { ...f.record, TimeGenerated: 'invalid' },
    { ...f.record, TimeGenerated: '2026-09-24' }, { ...f.record, host: null }]) assert.equal(validate(JSON.stringify(bad)), undefined);
  assert.equal(validate(' '.repeat(1025)), undefined);
  await f.enable();
  await f.send();
  assert.equal(f.storage.acknowledgement, 'queued');
  assert.equal(f.storage.snapshot().queued, 1);
  assert.deepEqual(JSON.parse(f.messages[0].messageText), f.record);
  await f.step(1000);
  assert.equal(f.messages.length, 0);
  assert.deepEqual(f.batches[0], [f.record]);
  assert.equal(f.storage.snapshot().logs_delivered, 1);
});

test('disabled constructors/start have no token/queue/worker operations; Monitor failure does not block producer', async t => {
  const f = fixture(t);
  f.storage.readiness.setEnabled(false);
  await f.step(60000);
  assert.deepEqual(Object.values(f.calls), [0, 0, 0, 0, 0]);
  f.consumer.available = false;
  await f.enable();
  assert.equal(f.storage.readiness.ready(), true);
  await f.send();
  await f.step(1000);
  assert.equal(f.calls.sends, 1);
  assert.equal(f.calls.receive, 0);
  assert.equal(f.calls.upload, 0);
  f.producer.available = false;
  assert.equal(f.storage.readiness.ready(), false);
  await assert.rejects(f.send());
});

test('capacity threshold, local reservations and stale metadata close admission until a fresh properties result', async t => {
  const f = fixture(t);
  f.consumer.available = false;
  f.queue.getProperties = async () => { f.calls.properties++; return { ...response(200), approximateMessagesCount: QUEUE_CAPACITY }; };
  await f.enable();
  assert.equal(f.storage.readiness.ready(), false);
  await assert.rejects(f.send());
  assert.equal(f.calls.sends, 0);
  f.queue.getProperties = async () => { f.calls.properties++; return { ...response(200), approximateMessagesCount: QUEUE_CAPACITY - 1 }; };
  await f.step(QUEUE_PROPERTIES_INTERVAL_MS);
  assert.equal(f.storage.readiness.ready(), true);
  await f.send();
  assert.equal(f.storage.readiness.ready(), false);
  await assert.rejects(f.send());
  const pending = deferred();
  f.queue.getProperties = () => { f.calls.properties++; return pending.promise; };
  await f.step(QUEUE_PROPERTIES_INTERVAL_MS);
  assert.equal(f.storage.readiness.ready(), false);
  await f.step(1000);
  assert.equal(f.calls.properties, 3);
  pending.resolve({ ...response(200), approximateMessagesCount: 0 });
  await turn();
  assert.equal(f.storage.readiness.ready(), true);
});

test('unresolved metadata keeps one slot quarantined through deadline and cannot revive on late success', async t => {
  const pending = deferred();
  const f = fixture(t, { getProperties() { f.calls.properties++; return pending.promise; } });
  await f.enable();
  await f.step(QUEUE_TRANSACTION_TIMEOUT_MS);
  assert.equal(f.storage.readiness.ready(), false);
  await f.step(60000);
  assert.equal(f.calls.properties, 1);
  pending.resolve({ ...response(200), approximateMessagesCount: 0 });
  await turn();
  assert.equal(f.storage.readiness.ready(), false);
  assert(f.storage.snapshot().queue_properties_failed >= 1);
});

test('eight uncancellable enqueue slots stay occupied after deadline; no late success or automatic resend', async t => {
  const pending = deferred(), signals = [];
  const f = fixture(t, { sendMessage(_text, options) {
    f.calls.sends++; signals.push(options.abortSignal); return pending.promise;
  } });
  f.consumer.available = false;
  await f.enable();
  const sends = Array.from({ length: 8 }, () => f.send());
  const settled = Promise.allSettled(sends);
  await assert.rejects(f.send());
  assert.equal(f.calls.sends, 8);
  await f.step(650);
  assert(signals.every(signal => signal.aborted));
  await f.step(60000);
  await assert.rejects(f.send());
  assert.equal(f.calls.sends, 8);
  pending.resolve({ ...response(201), messageId: 'late', popReceipt: 'receipt' });
  assert((await settled).every(result => result.status === 'rejected'));
  assert.equal(f.storage.snapshot().queued, undefined);
  assert.equal(f.storage.snapshot().queue_send_unknown, 8);
  assert.equal(f.calls.sends, 8);
});

test('one batch is at most 32, no optimistic delete, and late Logs success after timeout does not delete', async t => {
  const pending = deferred();
  const f = fixture(t);
  await f.enable();
  for (let index = 0; index < 33; index++) await f.send();
  f.upload.upload = async (_rule, _stream, records, options) => {
    f.calls.upload++;
    assert.equal(records.length, 32);
    f.signal = options.abortSignal;
    return pending.promise;
  };
  await f.step(1000);
  assert.equal(f.calls.upload, 1);
  assert.equal(f.calls.deletes, 0);
  // Independent producer remains ready while Logs is slow; it is not holding an HTTP request.
  assert.equal(f.storage.readiness.ready(), true);
  await f.step(WORKER_UPLOAD_TIMEOUT_MS);
  assert.equal(f.signal.aborted, true);
  assert.equal(f.storage.snapshot().logs_upload_unknown, 1);
  await f.step(60000);
  assert.equal(f.calls.upload, 1);
  assert.equal(f.calls.receive, 1);
  pending.resolve();
  await turn();
  assert.equal(f.calls.deletes, 0);
  assert.equal(f.storage.snapshot().logs_delivered, undefined);
  assert.equal(f.messages.length, 33);
});

test('visibility controls redelivery; only three upload attempts, duplicates possible after delete uncertainty', async t => {
  const f = fixture(t);
  await f.enable();
  await f.send();
  f.upload.upload = async () => { f.calls.upload++; throw new Error('PRIVATE_UPSTREAM_FAILURE'); };
  const originalReceive = f.queue.receiveMessages;
  let visibility = 0, dequeues = 0;
  f.queue.receiveMessages = async options => {
    if (f.now() < visibility) { f.calls.receive++; return { ...response(200), receivedMessageItems: [] }; }
    const result = await originalReceive(options);
    if (result.receivedMessageItems.length) {
      visibility = f.now() + 60000;
      result.receivedMessageItems[0].dequeueCount = ++dequeues;
    }
    return result;
  };
  await f.step(1000);
  for (let attempt = 1; attempt < 5; attempt++) { await f.step(60001); await f.step(1000); }
  assert.equal(f.calls.upload, 3);
  assert.equal(f.messages.length, 0);
  assert.equal(f.storage.snapshot().dropped_attempts, 1);
  assert.equal(f.storage.snapshot().logs_delivered, undefined);
});

test('invalid, expired and exhausted messages are disposed without upload or dead-letter retention', async t => {
  const f = fixture(t);
  await f.enable();
  for (let index = 0; index < 3; index++) await f.send();
  f.messages[0].messageText = '{"extra":"PRIVATE_INVALID"}';
  f.messages[1].messageText = JSON.stringify({ ...f.record, TimeGenerated: new Date(f.now() - QUEUE_TTL_SECONDS * 1000).toISOString() });
  f.messages[2].dequeueCount = 4;
  await f.step(1000);
  assert.equal(f.calls.upload, 0);
  assert.equal(f.messages.length, 0);
  assert.equal(f.storage.snapshot().dropped_invalid, 1);
  assert.equal(f.storage.snapshot().dropped_expired, 1);
  assert.equal(f.storage.snapshot().dropped_attempts, 1);
  assert(!JSON.stringify(f.storage.snapshot()).includes('PRIVATE'));
});

test('delete failure stops batch and opens queue circuit rather than repeated deletes or assumed removal', async t => {
  const f = fixture(t);
  await f.enable();
  await f.send(); await f.send();
  f.queue.deleteMessage = async () => { f.calls.deletes++; throw new Error('PRIVATE_DELETE_FAILURE'); };
  await f.step(1000);
  assert.equal(f.calls.upload, 1);
  assert.equal(f.calls.deletes, 1);
  assert.equal(f.messages.length, 2);
  assert.equal(f.storage.snapshot().logs_delivered, 2);
  assert.equal(f.storage.snapshot().queue_delete_unknown, 1);
  assert.equal(f.storage.readiness.ready(), false);
  await f.step(1000);
  assert.equal(f.calls.deletes, 1);
  // On a later lease, the same acknowledged records can be delivered again: not exactly once.
  f.queue.deleteMessage = async id => {
    f.calls.deletes++;
    f.messages.splice(f.messages.findIndex(message => message.messageId === id), 1);
    return response(204);
  };
  for (const message of f.messages) message.dequeueCount = 2;
  await f.step(60000); await f.step(1000);
  assert.equal(f.storage.snapshot().logs_delivered, 4);
  assert.equal(f.messages.length, 0);
});

test('queue receive failures are circuit-broken and do not produce uploads or spin', async t => {
  const f = fixture(t, { async receiveMessages() { f.calls.receive++; throw new Error('PRIVATE_QUEUE_RECEIVE_FAILURE'); } });
  await f.enable();
  await f.step(1000);
  assert.equal(f.calls.receive, 1);
  assert.equal(f.calls.upload, 0);
  assert.equal(f.storage.snapshot().queue_receive_unknown, 1);
  assert.equal(f.storage.readiness.ready(), false);
  await f.step(1000);
  assert.equal(f.calls.receive, 1);
  assert.equal(f.calls.properties, 1);
});

test('malformed operational lease metadata closes the circuit rather than being logged or repeatedly polled', async t => {
  const f = fixture(t, { async receiveMessages() {
    f.calls.receive++;
    return { ...response(200), receivedMessageItems: [null] };
  } });
  await f.enable();
  await f.step(1000);
  assert.equal(f.storage.snapshot().queue_receive_unknown, 1);
  assert.equal(f.storage.readiness.ready(), false);
  await f.step(1000);
  assert.equal(f.calls.receive, 1);
  assert.equal(f.calls.upload, 0);
  assert.equal(f.calls.deletes, 0);
});

test('Monitor freshness is rechecked after dequeue; no upload waits on identity while holding a lease', async t => {
  const pending = deferred();
  const f = fixture(t, { receiveMessages() { f.calls.receive++; return pending.promise; } });
  await f.enable();
  await f.send();
  await f.step(1000);
  f.consumer.available = false;
  pending.resolve({ ...response(200), receivedMessageItems: f.messages });
  await turn();
  assert.equal(f.calls.upload, 0);
  assert.equal(f.calls.deletes, 0);
  assert.equal(f.storage.readiness.ready(), true);
  await f.step(1000);
  assert.equal(f.calls.receive, 1);
});

test('lease and payload TTL can shorten upload time, never extend its 15-second budget', async t => {
  const pending = deferred();
  const f = fixture(t);
  await f.enable();
  await f.send();
  f.messages[0].expiresOn = new Date(f.now() + 2000);
  f.upload.upload = async (_rule, _stream, _records, options) => {
    f.calls.upload++; f.signal = options.abortSignal; return pending.promise;
  };
  await f.step(1000);
  assert.equal(f.calls.upload, 1);
  await f.step(1000);
  assert.equal(f.signal.aborted, true);
  pending.resolve();
  await turn();
  assert.equal(f.calls.deletes, 0);
  assert.equal(f.storage.snapshot().logs_delivered, undefined);
});

test('all batch deletions share a deadline shorter than visibility, not 32 fresh five-second budgets', async t => {
  const f = fixture(t);
  await f.enable();
  for (let index = 0; index < 32; index++) await f.send();
  const deletes = [];
  f.queue.deleteMessage = async (_id, _receipt, options) => {
    f.calls.deletes++;
    const pending = deferred();
    deletes.push({ ...pending, signal: options.abortSignal });
    return pending.promise;
  };
  await f.step(1000);
  for (let index = 0; index < 11; index++) {
    const current = deletes.at(-1);
    await f.step(4000);
    current.resolve(response(204));
    await turn();
  }
  assert.equal(f.calls.deletes, 12);
  const last = deletes.at(-1);
  await f.step(1000);
  assert.equal(last.signal.aborted, true);
  last.resolve(response(204));
  await turn();
  assert.equal(f.calls.deletes, 12);
  assert.equal(f.storage.snapshot().queue_delete_unknown, 1);
});

test('queue properties and sends disabled mid-flight cannot revive readiness or report durable ACK', async t => {
  const pending = deferred();
  const f = fixture(t, { sendMessage() { f.calls.sends++; return pending.promise; } });
  await f.enable();
  const operation = f.send();
  const rejected = assert.rejects(operation, /QUEUE_OUTCOME_UNKNOWN/);
  f.storage.readiness.setEnabled(false);
  await f.step(60000);
  pending.resolve({ ...response(201), messageId: 'unknown', popReceipt: 'receipt' });
  await rejected;
  assert.equal(f.storage.snapshot().queued, undefined);
  assert.equal(f.calls.sends, 1);
  assert.equal(f.calls.receive, 0);
  assert.equal(f.storage.readiness.ready(), false);
});

test('disabling during upload aborts but does not claim provider stop, start new work or delete on late ACK', async t => {
  const pending = deferred();
  const f = fixture(t);
  await f.enable();
  await f.send();
  f.upload.upload = async (_rule, _stream, _records, options) => {
    f.calls.upload++; f.signal = options.abortSignal; return pending.promise;
  };
  await f.step(1000);
  f.storage.readiness.setEnabled(false);
  assert.equal(f.signal.aborted, true);
  const calls = { ...f.calls };
  await f.step(120000);
  pending.resolve();
  await turn();
  assert.deepEqual(f.calls, calls);
  assert.equal(f.calls.deletes, 0);
  assert.equal(f.storage.snapshot().logs_delivered, undefined);
  assert.equal(f.messages.length, 1);
});
