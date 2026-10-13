import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { digestJson } from '../definition.mjs';
import { privateLinkValidationCopy } from '../private-link-runtime.mjs';
import { privateLinkFixture } from './private-link.fixture.mjs';

const entries = ['private-link-artifacts.mjs', 'private-link.mjs', 'private-link-runtime.mjs',
  'private-link-controller.mjs', 'controller.mjs', 'definition.mjs'];

test('fresh ESM entrypoints and differing import orders initialize without new cycles', async t => {
  const orders = entries.map((entry, index) => [...entries.slice(index), ...entries.slice(0, index)]);
  orders.push(...orders.map(order => [...order].reverse()));
  for (const order of orders) {
    await t.test(order.join(' -> '), () => {
      const urls = order.map(name => new URL(`../${name}`, import.meta.url).href);
      const script = `for (const url of ${JSON.stringify(urls)}) await import(url);`;
      execFileSync(process.execPath, ['--input-type=module', '--eval', script],
        { timeout: 30000, stdio: 'pipe' });
    });
  }
  await t.test('concurrent entrypoint imports', () => {
    const urls = entries.map(name => new URL(`../${name}`, import.meta.url).href);
    execFileSync(process.execPath, ['--input-type=module', '--eval',
      `await Promise.all(${JSON.stringify(urls)}.map(url => import(url)));`],
    { timeout: 30000, stdio: 'pipe' });
  });
});

async function inspectableHelper() {
  const url = new URL('../private-link.mjs?context-digest-test', import.meta.url).href;
  // Expose counters only in a test-local module instance. Production source and
  // normal entrypoint imports above are unchanged.
  const hooks = registerHooks({
    load(current, context, next) {
      const loaded = next(current, context);
      if (current !== url) return loaded;
      return { ...loaded, source: loaded.source.toString() +
        '\nexport { hash as testDigest }; export const testScope = () => immutableContextProofs.getStore();\n' };
    },
  });
  try { return await import(url); }
  finally { hooks.deregister(); }
}

function objects(root) {
  const seen = new Set(), result = [];
  function visit(value) {
    if (value === null || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    Object.values(value).forEach(visit);
    result.push(value);
  }
  visit(root);
  return result;
}

test('only fully verified owned graph members consume the bounded digest memo', async () => {
  const helper = await inspectableHelper(), fixture = await privateLinkFixture();
  const owned = privateLinkValidationCopy({ c: fixture.c, context: fixture.context });
  const members = objects(owned).filter(value =>
    Object.values(value).every(child => child === null || typeof child !== 'object'));
  assert(members.length > 512, 'fixture must exercise the complete64KiB retained-hex boundary');
  let captured;
  await helper.withPrivateLinkImmutableControlValidation(owned.c, owned.context, async () => {
    captured = helper.testScope();
    assert.equal(captured.verified, false);
    assert.equal(helper.testDigest(owned.context.origin), digestJson(owned.context.origin));
    assert.equal(captured.digestBytes, 0, 'initial full plan validation cannot use the memo');
    helper.verifyPrivateLinkControlContext(owned.c, owned.context);
    assert.equal(captured.verified, true);
    assert.equal(captured.digestBytes, 0);
    const selected = members.slice(0, 514);
    for (const [index, member] of selected.entries()) {
      assert.equal(helper.testDigest(member), digestJson(member));
      assert.equal(captured.digestBytes, Math.min(index + 1, 512) * 64 * 2);
      assert.equal(captured.digests.has(member), index < 512);
    }
    await Promise.resolve();
    for (const member of [selected[0], selected[511], selected[512], selected[513]]) {
      assert.equal(helper.testDigest(member), digestJson(member));
      assert.equal(captured.digestBytes, 65536);
    }
    const foreign = { value: 'before' }, frozenForeign = Object.freeze({ ...selected[0] });
    for (const value of [foreign, frozenForeign, { origin: owned.context.origin }]) {
      assert.equal(helper.testDigest(value), digestJson(value));
      assert.equal(captured.digests.has(value), false);
    }
    foreign.value = 'after';
    assert.equal(helper.testDigest(foreign), digestJson(foreign));
  });
  assert.equal(captured.active, false);
  assert.equal(captured.digests, null);
  assert.equal(captured.digestBytes, 0);
  assert.equal(helper.testDigest(owned.context.origin), digestJson(owned.context.origin));
});

test('helper digest remains canonical and preserves rejection before and after saturation', async () => {
  const helper = await inspectableHelper(), fixture = await privateLinkFixture();
  const owned = privateLinkValidationCopy({ c: fixture.c, context: fixture.context });
  const values = [null, 'null', false, 'false', 1, '1', 0, -0, 1e-7, 1e21,
    Number.MIN_VALUE, Number.MAX_VALUE, [], {}, [1], { 0: 1 }, '\ud800', '\udfff', '\ud83d\ude80',
    '\ude80\ud83d', '\u2028\u2029', '"\\\b\f\n\r\t\u0000\u001f', 'a'.repeat(65535) + '\ud83d\ude80',
    { a: 1, b: 2 }, { b: 2, a: 1 }];
  const verify = () => {
    for (const value of values) assert.equal(helper.testDigest(value), digestJson(value));
    assert.notEqual(helper.testDigest({ a: 1, b: 2 }), helper.testDigest({ b: 2, a: 1 }));
    assert.notEqual(helper.testDigest(1), helper.testDigest('1'));
    assert.notEqual(helper.testDigest([]), helper.testDigest({}));
    let deep = 0;
    for (let level = 0; level < 128; level++) deep = { child: deep };
    assert.equal(helper.testDigest(deep), digestJson(deep));
    assert.throws(() => helper.testDigest({ child: deep }), /CANONICAL_JSON_DEPTH_LIMIT/);
    const cycle = {}; cycle.self = cycle;
    for (const value of [undefined, NaN, Infinity, 1n, new Date(), { x: undefined }, [undefined], cycle]) {
      assert.throws(() => helper.testDigest(value), /CANONICAL_JSON_DATA_REQUIRED/);
    }
  };
  verify();
  await helper.withPrivateLinkImmutableControlValidation(owned.c, owned.context, async () => {
    helper.verifyPrivateLinkControlContext(owned.c, owned.context);
    verify();
    for (const value of objects(owned).slice(0, 520)) helper.testDigest(value);
    assert.equal(helper.testScope().digestBytes, 65536);
    await Promise.resolve();
    verify();
  });
  verify();
});

test('helper digest membership and memo close on nested, concurrent and failed scopes', async () => {
  const helper = await inspectableHelper(), fixture = await privateLinkFixture();
  const one = privateLinkValidationCopy({ c: fixture.c, context: fixture.context });
  const two = privateLinkValidationCopy({ c: fixture.c, context: fixture.context });
  let outer, inner, release, late;
  const failure = new Error('intentional test failure');
  await helper.withPrivateLinkImmutableControlValidation(one.c, one.context, async () => {
    helper.verifyPrivateLinkControlContext(one.c, one.context);
    outer = helper.testScope();
    helper.testDigest(one.context.origin);
    assert.equal(outer.digestBytes, 128);
    await assert.rejects(helper.withPrivateLinkImmutableControlValidation(two.c, two.context, async () => {
      helper.verifyPrivateLinkControlContext(two.c, two.context);
      inner = helper.testScope();
      helper.testDigest(one.context.origin);
      assert.equal(inner.digestBytes, 0, 'foreign equal graph is not a member of this scope');
      helper.testDigest(two.context.origin);
      assert.equal(inner.digestBytes, 128);
      const wait = new Promise(resolve => { release = resolve; });
      late = wait.then(() => helper.verifyPrivateLinkControlContext(two.c, two.context));
      throw failure;
    }), error => error === failure);
    assert.equal(helper.testScope(), outer);
    assert.equal(outer.digestBytes, 128);
    release();
    await assert.rejects(late, /CONTEXT_VALIDATION_SCOPE_CLOSED/);
  });
  for (const scope of [outer, inner]) {
    assert.equal(scope.active, false);
    assert.equal(scope.digests, null);
    assert.equal(scope.digestBytes, 0);
  }
  const scopes = [];
  await Promise.all([one, two].map((value, index) =>
    helper.withPrivateLinkImmutableControlValidation(value.c, value.context, async () => {
      helper.verifyPrivateLinkControlContext(value.c, value.context);
      scopes[index] = helper.testScope();
      helper.testDigest(value.context.origin);
      await Promise.resolve();
      assert.equal(helper.testScope(), scopes[index]);
      assert.equal(scopes[index].digestBytes, 128);
    })));
  assert.notEqual(scopes[0], scopes[1]);
  for (const scope of scopes) assert.equal(scope.digests, null);
  for (const context of [
    Object.freeze({ get plan() { throw new Error('accessor must not run'); } }),
    new Proxy(Object.freeze({}), {}), Object.freeze({ value: () => 1 }),
  ]) {
    assert.throws(() => helper.withPrivateLinkImmutableControlValidation(Object.freeze({}), context, () => {}),
      /IMMUTABLE_CONTEXT_REQUIRED/);
  }
});
