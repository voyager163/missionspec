import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { constants } from 'node:buffer';
import test from 'node:test';
import { digest, digestJson, json } from '../definition.mjs';

test('streamed canonical hashes exactly preserve legacy JSON bytes for accepted artifact values', () => {
  const shared = { nested: [false, null, 1, 'value'] };
  const values = [null, true, false, '', 0, -0, 1.2e30, 1e-10, [], {}, [1, [], {}],
    { b: 1, a: 2, '10': 'ten', '2': 'two', '01': 'one' },
    { a: shared, b: shared }, Object.assign(Object.create(null), { value: 'private' }),
    { string: '\ud800 \udc00 \u{1f680}\u2028\u2029\n\t"\\' },
    { unicode: '\u{1f680}'.repeat(40000), after: 'boundary' },
    Object.fromEntries([['__proto__', { value: true }], ['constructor', 'data']])];
  for (const value of values) assert.equal(digestJson(value), digest(json(value)));
  let seed = 31;
  const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; };
  function generate(depth) {
    if (!depth) return [null, true, false, random() / 17, `s${random()}`][random() % 5];
    if (random() % 2) return Array.from({ length: random() % 5 }, () => generate(depth - 1));
    return Object.fromEntries(Array.from({ length: random() % 5 }, (_, i) => [`key${i}`, generate(depth - 1)]));
  }
  for (let index = 0; index < 100; index++) {
    const value = generate(4);
    assert.equal(digestJson(value), digest(json(value)));
  }
});

test('canonical hashing handles a logical document above Node string limits without constructing it', () => {
  const text = 'x'.repeat(4 * 1024 * 1024), value = Array.from({ length: 129 }, () => ({ text }));
  const element = JSON.stringify({ text }, null, 2).replaceAll('\n', '\n  ');
  const expected = createHash('sha256');
  let bytes = 0;
  const emit = text => { expected.update(text); bytes += Buffer.byteLength(text); };
  emit('[\n');
  for (let index = 0; index < value.length; index++) {
    if (index) emit(',\n');
    emit('  '); emit(element);
  }
  emit('\n]\n');
  assert(bytes > constants.MAX_STRING_LENGTH);
  assert.equal(digestJson(value), expected.digest('hex'));
});

test('non-JSON data, cycles and excessive nesting never become successful canonical bindings', () => {
  const cyclic = {}; cyclic.self = cyclic;
  let deep = null;
  for (let index = 0; index < 130; index++) deep = { child: deep };
  for (const value of [undefined, { missing: undefined }, NaN, Infinity, 1n, new Date(),
    { call() {} }, Symbol('unbound'), cyclic, deep, Array(3)]) {
    assert.throws(() => digestJson(value), /CANONICAL_JSON_(DATA_REQUIRED|DEPTH_LIMIT)/);
  }
});
