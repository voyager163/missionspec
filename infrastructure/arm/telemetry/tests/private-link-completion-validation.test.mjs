import assert from 'node:assert/strict';
import test from 'node:test';
import { digestJson } from '../definition.mjs';
import { privateLinkValidationCopy, privateLinkValidationHash, withPrivateLinkCompletionValidation,
  assertPrivateLinkCompletionInputs, verifyPrivateLinkRuntimeCompletion } from '../private-link-runtime.mjs';
import { runtimeFixture, privateRuntimeCompletionFixture } from './private-link-runtime.fixture.mjs';
import { privateLinkFixture } from './private-link.fixture.mjs';
import { withPrivateLinkImmutableControlValidation, withPrivateLinkControlValidation,
  verifyPrivateLinkControlContext } from '../private-link.mjs';

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

test('canonical bytes agree across UTF-8, scalar, chunk and saturated operation-cache boundaries', () => {
    const scalars = ['\ud83d\ude80', '\ud800', '\udfff', '\ude80\ud83d', '\\\"\b\f\n\r\t\u0000\u001f',
      '\u2028\u2029', '\u00e9', 'e\u0301', 0, -0, Number.MIN_VALUE, Number.MAX_VALUE,
      Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, 1e-7, 1e-6, 1e20, 1e21, null, false, true];
    const verify = value => assert.equal(privateLinkValidationHash(value), digestJson(value));
    const copied = scalars.map(value => privateLinkValidationCopy({ value }));
    withPrivateLinkCompletionValidation({}, {}, () => {
      for (const value of copied) verify(value);
      for (const length of [65533, 65534, 65535, 65536, 65537]) {
        for (const suffix of scalars.filter(value => typeof value === 'string')) {
          verify(privateLinkValidationCopy({ first: 'a'.repeat(length), value: suffix,
            ['key-' + suffix]: ['b'.repeat(length), suffix] }));
        }
      }
      // More than 16 MiB of distinct encodings must still hash correctly after
      // cache admission stops, including values first encountered before saturation.
      for (let index = 0; index < 270; index++) {
        verify(privateLinkValidationCopy({ index, value: `${index}:` + 'x'.repeat(65536) }));
      }
      for (const value of copied) verify(value);
      const domains = [null, 'null', false, 'false', 1, '1', [], {}, [1], { 0: 1 },
        { a: 1, b: 2 }, { b: 2, a: 1 }];
      assert.equal(new Set(domains.map(value => privateLinkValidationHash(privateLinkValidationCopy(value)))).size, domains.length);
      assert.equal(privateLinkValidationHash(-0), privateLinkValidationHash(0));
      const ordered = { z: '\ud800', 2: 'two', 1: 'one', a: '\ud83d\ude80' };
      verify(privateLinkValidationCopy(ordered));
      const mutable = { first: { value: 'before' }, second: { value: 'before' } };
      verify(mutable);
      mutable.second.value = 'after';
      verify(mutable);
      mutable.first = structuredClone(mutable.second);
      verify(mutable);
    });
    withPrivateLinkCompletionValidation({}, {}, () => {
      for (const value of copied) verify(value);
      for (const value of [undefined, 1n, NaN, Infinity, new Date(), new Uint8Array([1]), [, 1],
        new Proxy({}, {}), { get value() { throw new Error('getter must not run'); } }]) {
        assert.throws(() => privateLinkValidationHash(value), /CANONICAL_JSON_DATA_REQUIRED/);
      }
      let deep = 0;
      for (let depth = 0; depth < 128; depth++) deep = [deep];
      verify(privateLinkValidationCopy(deep));
      assert.throws(() => privateLinkValidationHash(privateLinkValidationCopy([deep])), /CANONICAL_JSON_DEPTH_LIMIT/);
    });
});

test('immutable context proofs are owned, exact, isolated and closed on success or failure', async () => {
  const f = await privateLinkFixture(), c = structuredClone(f.c), context = structuredClone(f.context);
  assert.throws(() => withPrivateLinkImmutableControlValidation(c, context, () => {}), /IMMUTABLE_CONTEXT_REQUIRED/);
  for (const value of [
    Object.freeze({ get plan() { throw new Error('accessor must not run'); } }),
    new Proxy(Object.freeze({}), {}),
    Object.freeze({ value: () => 1 }),
  ]) {
    assert.throws(() => withPrivateLinkImmutableControlValidation(Object.freeze({}), value, () => {}),
      /IMMUTABLE_CONTEXT_REQUIRED/);
  }
  let release, late;
  await withPrivateLinkCompletionValidation(c, context, async (ownedC, ownedContext) => {
    assert.notEqual(ownedC, c); assert.notEqual(ownedContext, context);
    assert.equal(verifyPrivateLinkControlContext(ownedC, ownedContext), ownedContext);
    await Promise.resolve();
    assert.equal(verifyPrivateLinkControlContext(ownedC, ownedContext), ownedContext);
    assert.throws(() => withPrivateLinkControlValidation(ownedC, ownedContext, () => Promise.resolve()),
      /SYNCHRONOUS_VALIDATION_REQUIRED/);
    const changed = structuredClone(ownedContext); changed.plan.sourceSha256 = '0'.repeat(64);
    assert.throws(() => verifyPrivateLinkControlContext(ownedC, changed));
    await assert.rejects(withPrivateLinkCompletionValidation(ownedC, changed, async (foreignC, foreignContext) => {
      await Promise.resolve();
      verifyPrivateLinkControlContext(foreignC, foreignContext);
    }));
    assert.equal(verifyPrivateLinkControlContext(ownedC, ownedContext), ownedContext);
    const wait = new Promise(resolve => { release = resolve; });
    late = wait.then(() => verifyPrivateLinkControlContext(ownedC, ownedContext));
    assert.equal(Object.isFrozen(c), false); assert.equal(Object.isFrozen(context), false);
  });
  release();
  await assert.rejects(late, /CONTEXT_VALIDATION_SCOPE_CLOSED/);
  const stop = new Error('intentional scope failure');
  await assert.rejects(withPrivateLinkCompletionValidation(c, context, async (ownedC, ownedContext) => {
    verifyPrivateLinkControlContext(ownedC, ownedContext);
    const wait = new Promise(resolve => { release = resolve; });
    late = wait.then(() => verifyPrivateLinkControlContext(ownedC, ownedContext));
    throw stop;
  }), error => error === stop);
  release();
  await assert.rejects(late, /CONTEXT_VALIDATION_SCOPE_CLOSED/);
  const copies = [];
  await Promise.all([0, 1].map(index => withPrivateLinkCompletionValidation(c, context, async (ownedC, ownedContext) => {
    copies[index] = ownedContext;
    await Promise.resolve();
    assert.equal(verifyPrivateLinkControlContext(ownedC, ownedContext), ownedContext);
    const foreign = structuredClone(ownedContext); foreign.plan.sourceSha256 = String(index).repeat(64);
    assert.throws(() => verifyPrivateLinkControlContext(ownedC, foreign));
  })));
  assert.notEqual(copies[0], copies[1]);
  await withPrivateLinkCompletionValidation(c, context, async (ownedC, ownedContext) => {
    verifyPrivateLinkControlContext(ownedC, ownedContext);
    await Promise.resolve();
    context.plan.sourceSha256 = '0'.repeat(64);
    assert.throws(() => assertPrivateLinkCompletionInputs(ownedC, ownedContext), /INPUT_CHANGED/);
  });
  assert.equal(Object.isFrozen(c), false); assert.equal(Object.isFrozen(context), false);
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
