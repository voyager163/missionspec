import assert from 'node:assert/strict';
import test from 'node:test';
import { digestJson } from '../definition.mjs';
import { privateLinkValidationCopy, privateLinkValidationHash, withPrivateLinkCompletionValidation,
  assertPrivateLinkCompletionInputs, verifyPrivateLinkRuntimeCompletion } from '../private-link-runtime.mjs';
import { runtimeFixture, privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';

test('immutable canonical segments preserve digestJson bytes, key order and depth/domain rejection', () => {
  const strings = ['ordinary', '"quoted"\\\n\t', '\ud800', 'cafe\u0301', 'queue-\ud83d\ude80', '\u2028\u2029', 'x'.repeat(90000)];
  withPrivateLinkCompletionValidation({}, {}, () => {
    const values = [null, true, false, -0, 1e-7, 1e21, [], {}, strings,
      { z: strings, 2: ['a'], a: { nested: ['b', { x: 1 }] } }];
    const shared = { x: strings, y: [0, 1.25, -9] };
    values.push({ first: shared, second: [shared, { deeper: shared }] });
    values.push(Object.fromEntries(Array.from({ length: 350 }, (_, i) => [`key-${i}`, { v: strings[i % strings.length] }])));
    for (const value of values) {
      const copy = privateLinkValidationCopy(value);
      assert.equal(privateLinkValidationHash(copy), digestJson(value));
      assert.equal(privateLinkValidationHash(copy), digestJson(value));
    }
    const a = privateLinkValidationCopy({ a: 1, b: 2 }), b = privateLinkValidationCopy({ b: 2, a: 1 });
    assert.notEqual(privateLinkValidationHash(a), privateLinkValidationHash(b));
    const mutable = { wrapper: shared, ordering: [1, 2] };
    assert.equal(privateLinkValidationHash(mutable), digestJson(mutable));
    mutable.wrapper.x[0] = 'changed after hashing';
    mutable.ordering.reverse();
    assert.equal(privateLinkValidationHash(mutable), digestJson(mutable));
    const previous = mutable.wrapper;
    mutable.wrapper = { replacement: true };
    assert.equal(privateLinkValidationHash(mutable), digestJson(mutable));
    mutable.wrapper = previous;
    assert.equal(privateLinkValidationHash(mutable), digestJson(mutable));
    let deep = 0;
    for (let i = 0; i < 128; i++) deep = { child: deep };
    assert.equal(privateLinkValidationHash(privateLinkValidationCopy(deep)), digestJson(deep));
    assert.throws(() => privateLinkValidationHash(privateLinkValidationCopy({ child: deep })), /DEPTH_LIMIT/);
    const cycle = {}; cycle.x = cycle;
    for (const value of [{ x: undefined }, [undefined], [NaN], { n: Infinity }, cycle]) {
      assert.throws(() => privateLinkValidationHash(privateLinkValidationCopy(value)), /CANONICAL_JSON/);
    }
  });
});

test('completion cache is operation-local, configuration-bound, time-checked and preserves caller mutability', async () => {
  const f = runtimeFixture(); f.prerequisites.controlHeadSha256 = 'a'.repeat(64);
  const { completion, at } = await privateRuntimeCompletionFixture(f, f.evidence, f.prerequisites);
  const c = structuredClone(f.c), context = structuredClone(f.context), record = structuredClone(completion);
  const frozen = new Map();
  function capture(value) {
    if (value === null || typeof value !== 'object' || frozen.has(value)) return;
    frozen.set(value, Object.isFrozen(value)); Object.values(value).forEach(capture);
  }
  capture({ c, context, record });
  let late;
  await withPrivateLinkCompletionValidation(c, context, async () => {
    const first = verifyPrivateLinkRuntimeCompletion(c, context, record, at);
    assert.deepEqual(verifyPrivateLinkRuntimeCompletion(c, context, record, at + 1), first);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(c, context, record, Date.parse(record.completedAt) - 1), /UNQUALIFIED/);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion({ ...c, budgetEmail: 'changed@example.invalid' }, context, record, at));
    await Promise.resolve();
    for (const [value, before] of frozen) assert.equal(Object.isFrozen(value), before);
    record.requests[0].dispatched = false;
    assert.equal(record.requests[0].dispatched, false);
    assert.throws(() => assertPrivateLinkCompletionInputs(c, context), /INPUT_CHANGED/);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion(c, context, record, at), /INPUT_CHANGED/);
    record.requests[0].dispatched = true;
    late = new Promise(resolve => setTimeout(() => {
      try { verifyPrivateLinkRuntimeCompletion(c, context, record, at); resolve(null); }
      catch (error) { resolve(error); }
    }, 20));
  });
  assert.match((await late).message, /SCOPE_CLOSED/);
  assert.equal(verifyPrivateLinkRuntimeCompletion(c, context, record, at).terminalDisabled, true);
  record.requests[0].dispatched = false;
  assert.throws(() => verifyPrivateLinkRuntimeCompletion(c, context, record, at), /DISPATCH_UNPROVEN/);
});

test('ordered caller comparisons reject key reorder and immutable alias substitution after an await', async () => {
  const f = runtimeFixture(); f.prerequisites.controlHeadSha256 = 'a'.repeat(64);
  const { completion, at } = await privateRuntimeCompletionFixture(f, f.evidence, f.prerequisites);
  for (const target of ['config', 'context', 'record']) {
    const c = structuredClone(f.c), context = structuredClone(f.context), record = structuredClone(completion);
    await withPrivateLinkCompletionValidation(c, context, async () => {
      verifyPrivateLinkRuntimeCompletion(c, context, record, at);
      await Promise.resolve();
      const value = target === 'config' ? c : target === 'context' ? context : record;
      const key = Object.keys(value)[0], entry = value[key];
      delete value[key]; value[key] = entry;
      assert.throws(() => assertPrivateLinkCompletionInputs(c, context), /INPUT_CHANGED/);
    });

  }
});

test('private ancestry interning shares only exact ordered copies and never grants semantic authority', () => {
  const a = { version: 3, kind: 'private-link-window-intent', incomplete: true };
  const b = structuredClone(a);
  const reordered = { kind: a.kind, version: a.version, incomplete: true };
  const source = { a, b, reordered }, before = digestJson(source);
  withPrivateLinkCompletionValidation({}, {}, () => {
    const copy = privateLinkValidationCopy(source);
    assert.equal(copy.a, copy.b);
    assert.notEqual(copy.a, copy.reordered);
    assert.equal(privateLinkValidationHash(copy), before);
    assert.throws(() => verifyPrivateLinkRuntimeCompletion({}, {}, copy.a, 0));
    assert.equal(Object.isFrozen(a), false);
    a.incomplete = false;
    assert.equal(copy.a.incomplete, true);
    assert.equal(privateLinkValidationHash(copy), before);
  });
});
