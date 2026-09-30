import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync, spawn } from 'node:child_process';
import { access, chmod, lstat, mkdir, readFile, readdir, rm, rmdir, symlink, unlink, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest, json } from '../definition.mjs';
import { privateLinkCachedFixture, privateLinkFixtureCacheStats, verifyPrivateLinkCacheAncestors,
  verifyPrivateLinkCacheContention } from './private-link-cache.fixture.mjs';
import { privateLinkFixture, privateInput, privateControlChain, privateControlHarness } from './private-link.fixture.mjs';

test('test cache deduplicates one exact concurrent build and isolates every clone without freezing its inputs', async () => {
  const input = { namespace: 'UNIT cache', source: digest('UNIT source'), context: { version: 1 } };
  let builds = 0;
  const build = async () => { builds++; return { input, nested: { values: [1, 2] } }; };
  const [a, b] = await Promise.all([
    privateLinkCachedFixture('unit-cache-isolation', input, build),
    privateLinkCachedFixture('unit-cache-isolation', structuredClone(input), build),
  ]);
  assert.equal(builds, 1);
  assert.deepEqual(a, b);
  a.nested.values.push(3); a.input.context.version = 99;
  assert.deepEqual(b.nested.values, [1, 2]); assert.equal(b.input.context.version, 1);
  assert.equal(Object.isFrozen(input), false); assert.equal(Object.isFrozen(input.context), false);
  assert.deepEqual(await privateLinkCachedFixture('unit-cache-isolation', input, build), b);
});

test('different source, configuration, topology, time and previous evidence cannot reuse a test prefix', async () => {
  const input = { source: 'one', config: { subscription: 'unit' }, topology: { subnet: 'unit' }, at: 1,
    evidence: { records: ['one'] } };
  let builds = 0;
  const build = async () => ({ ordinal: ++builds });
  assert.equal((await privateLinkCachedFixture('unit-cache-key', input, build)).ordinal, 1);
  for (const change of [
    value => { value.source = 'two'; }, value => { value.config.subscription = 'changed'; },
    value => { value.topology.subnet = 'changed'; }, value => { value.at++; }, value => { value.evidence.records.push('two'); },
  ]) {
    const different = structuredClone(input); change(different);
    await privateLinkCachedFixture('unit-cache-key', different, build);
  }
  assert.equal(builds, 6);
  assert.equal((await privateLinkCachedFixture('unit-cache-key', input, build)).ordinal, 1);
  for (const invalid of [{ ...input, omitted: undefined }, { ...input, at: NaN }, { ...input, callback() {} }]) {
    await assert.rejects(privateLinkCachedFixture('unit-cache-key', invalid, build), /lossless generated JSON/);
  }
  assert.equal(builds, 6);
  let failures = 0;
  await assert.rejects(privateLinkCachedFixture('unit-cache-failure', {}, async () => {
    failures++; throw new Error('UNIT setup failed');
  }), /setup failed/);
  assert.equal((await privateLinkCachedFixture('unit-cache-failure', {}, async () => ({ failures }))).failures, 1);
});

test('cached real prefixes equal uncached execution and later-stage harnesses get fresh IO and journals', async () => {
  const f = await privateLinkFixture({ ...privateInput, version: 2 }), before = json(f.context);
  const uncached = await privateControlChain({ ...f }, 'set-project-migration-budget', { uncached: true });
  const first = await privateControlChain({ ...f }, 'set-project-migration-budget');
  const cached = await privateControlChain({ ...f }, 'set-project-migration-budget');
  assert.deepEqual(first, uncached); assert.deepEqual(cached, uncached);
  first.records[0].authority.originalNspExecutionQualified = true;
  assert.equal(cached.records[0].authority.originalNspExecutionQualified, false);
  assert.deepEqual(await privateControlChain({ ...f }, 'set-project-migration-budget'), uncached);
  const at = f.at + 2000, evidence = cached, phase = 'set-telemetry-migration-budget';
  const a = await privateControlHarness({ ...f, at }, evidence, phase);
  const b = await privateControlHarness({ ...f, at }, evidence, phase);
  const fresh = await privateControlHarness({ ...f, at }, evidence, phase, { uncached: true });
  assert.deepEqual(a.phase, fresh.phase); assert.deepEqual(a.proof, fresh.proof);
  assert.deepEqual(a.before, fresh.before); assert.deepEqual(a.after, fresh.after);
  a.proof.sourceSha256 = digest('UNIT changed consumer');
  a.before.resources[Object.keys(a.before.resources)[0]] = null;
  a.advance(1800000);
  assert.equal(b.io.now(), at); assert.equal(b.journal, null); assert.equal(b.writes, 0);
  assert.deepEqual(b.proof, fresh.proof); assert.deepEqual(b.before, fresh.before);
  await b.execute();
  assert.equal(fresh.journal, null); assert.equal(fresh.writes, 0); assert.equal(a.journal, null);
  assert.equal(json(f.context), before);
  const stats = privateLinkFixtureCacheStats();
  assert(stats.hits > 0 && stats.builds > 0);
});

test('sibling workers share one same-run setup and the last worker removes its entire cache', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const module = new URL('./private-link-cache.fixture.mjs', import.meta.url).href;
  const script = `import {privateLinkCachedFixture,privateLinkFixtureCacheDirectory} from ${JSON.stringify(module)};
    const value=await privateLinkCachedFixture('unit-worker-sharing',{source:'exact',config:1},async()=>{
      await new Promise(resolve=>setTimeout(resolve,50));return {builder:process.pid,nested:{value:1}};
    });
    process.send({root:await privateLinkFixtureCacheDirectory(),value});
    process.on('message',()=>process.disconnect());`;
  const children = [];
  const start = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script],
      { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    children.push(child);
    let stderr = '';
    child.stderr.on('data', value => { stderr += value; });
    child.once('error', reject);
    child.once('message', message => resolve({ child, ...message }));
    child.once('exit', code => { if (code !== 0) reject(new Error(stderr || `Unit worker exited ${code}`)); });
  });
  t.after(() => { for (const child of children) if (child.exitCode === null) child.kill(); });
  const [a, b] = await Promise.all([start(), start()]);
  assert.deepEqual(a.value, b.value); assert.equal(a.root, b.root);
  const protectedParent = join(dirname(dirname(fileURLToPath(import.meta.url))), '.operator-private', 'private-link-test-cache');
  assert.equal(dirname(a.root), protectedParent);
  const info = await lstat(protectedParent);
  assert.equal(info.mode & 0o777, 0o700); assert.equal(info.uid, process.getuid());
  const source = createHash('sha256'), here = dirname(fileURLToPath(import.meta.url));
  for (const directory of [dirname(here), here]) {
    for (const name of (await readdir(directory)).sort()) if (/\.(?:mjs|py)$/u.test(name)) {
      source.update(name).update(await readFile(join(directory, name)));
    }
  }
  for (const path of ['assets/schemas/telemetry-event.schema.json', 'services/telemetry-ingest/schema/storage-columns.json']) {
    source.update(path).update(await readFile(new URL(`../../../../${path}`, import.meta.url)));
  }
  const started = execFileSync('ps', ['-p', String(process.pid), '-o', 'lstart='], { encoding: 'utf8', timeout: 1000 }).trim();
  assert.equal(basename(a.root), `run-${digest(JSON.stringify({
    parent: process.pid, started, source: source.digest('hex'), node: process.version,
  }))}`);
  a.value.nested.value = 2; assert.equal(b.value.nested.value, 1);
  const ended = children.map(child => new Promise(resolve => child.once('exit', resolve)));
  for (const child of children) child.send('finish');
  assert.deepEqual(await Promise.all(ended), [0, 0]);
  await assert.rejects(access(a.root), error => error.code === 'ENOENT');
});

test('cache access rejects writable ancestors, a nonprivate leaf and symlinked directory boundaries', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = join(here, `.cache-safety-${randomUUID()}`), ancestor = join(root, 'ancestor'), leaf = join(ancestor, 'cache');
  await mkdir(root, { mode: 0o700 });
  await mkdir(ancestor, { mode: 0o700 }); await mkdir(leaf, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true }));
  assert.equal(await verifyPrivateLinkCacheAncestors(leaf, true), leaf);
  for (const mode of [0o720, 0o702, 0o777]) {
    await chmod(ancestor, mode);
    await assert.rejects(verifyPrivateLinkCacheAncestors(leaf, true), /unsafe/);
  }
  await chmod(ancestor, 0o700);
  await chmod(leaf, 0o755);
  await assert.rejects(verifyPrivateLinkCacheAncestors(leaf, true), /unsafe/);
  await chmod(leaf, 0o700);
  const alias = join(root, 'alias');
  await symlink(ancestor, alias, 'dir');
  await assert.rejects(verifyPrivateLinkCacheAncestors(join(alias, 'cache'), true),
    error => ['ELOOP', 'ENOTDIR'].includes(error.code) || /unsafe/.test(error.message));
  assert.equal(await verifyPrivateLinkCacheAncestors(leaf, true), leaf);
});

test('a contended lock released before inspection retries without admitting an unsafe directory', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const root = join(dirname(fileURLToPath(import.meta.url)), `.cache-contention-${randomUUID()}`);
  const lock = join(root, 'lock'), unsafe = join(root, 'unsafe');
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true }));
  await mkdir(lock, { mode: 0o700 });
  await assert.rejects(mkdir(lock), error => error.code === 'EEXIST');
  await rmdir(lock);
  assert.equal(await verifyPrivateLinkCacheContention(lock), false);
  await assert.rejects(access(lock), error => error.code === 'ENOENT');
  await mkdir(lock, { mode: 0o700 });
  assert.equal(await verifyPrivateLinkCacheContention(lock), true);
  await chmod(lock, 0o777);
  await assert.rejects(verifyPrivateLinkCacheContention(lock), /unsafe/);
  await chmod(lock, 0o700);
  await symlink(lock, unsafe, 'dir');
  await assert.rejects(verifyPrivateLinkCacheContention(unsafe),
    error => ['ELOOP', 'ENOTDIR'].includes(error.code) || /unsafe/.test(error.message));
});

test('a precreated lifecycle symlink is rejected without following its target or losing existing cache evidence', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const module = new URL('./private-link-cache.fixture.mjs', import.meta.url).href;
  const source = `import {privateLinkCachedFixture,privateLinkFixtureCacheDirectory} from ${JSON.stringify(module)};
    await privateLinkCachedFixture('unit-hostile-lifecycle',{source:'exact'},async()=>({valid:true}));
    process.send(await privateLinkFixtureCacheDirectory());process.on('message',()=>process.disconnect());`;
  const first = spawn(process.execPath, ['--input-type=module', '-e', source],
    { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (first.exitCode === null) first.kill(); });
  const root = await new Promise((resolve, reject) => { first.once('message', resolve); first.once('error', reject); });
  const destination = join(root, 'untrusted-lifecycle-target');
  await writeFile(destination, 'UNIT sentinel remains unchanged', { mode: 0o600, flag: 'wx' });
  await symlink(destination, root + '.lifecycle');
  try {
    const second = spawn(process.execPath, ['--input-type=module', '-e', source],
      { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    t.after(() => { if (second.exitCode === null) second.kill(); });
    let output = ''; second.stderr.on('data', value => { output += value; });
    assert.notEqual(await new Promise(resolve => second.once('exit', resolve)), 0);
    assert.match(output, /ELOOP|ENOTDIR|unsafe/);
    assert.equal(await readFile(destination, 'utf8'), 'UNIT sentinel remains unchanged');
  } finally {
    await unlink(root + '.lifecycle'); await unlink(destination);
    const ended = new Promise(resolve => first.once('exit', resolve)); first.send('finish');
    assert.equal(await ended, 0);
  }
  await assert.rejects(access(root), error => error.code === 'ENOENT');
});

test('symlinked cache entries remain rejected by descriptor-based no-follow admission', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const module = new URL('./private-link-cache.fixture.mjs', import.meta.url).href;
  const input = { source: 'unit-symlink', config: 1 };
  const source = `import {privateLinkCachedFixture,privateLinkFixtureCacheDirectory} from ${JSON.stringify(module)};
    await privateLinkCachedFixture('unit-cache-symlink',${JSON.stringify(input)},async()=>({valid:true}));
    process.send(await privateLinkFixtureCacheDirectory());process.on('message',()=>process.disconnect());`;
  const first = spawn(process.execPath, ['--input-type=module', '-e', source],
    { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (first.exitCode === null) first.kill(); });
  const root = await new Promise((resolve, reject) => { first.once('message', resolve); first.once('error', reject); });
  const path = join(root, `${digest(JSON.stringify({ namespace: 'unit-cache-symlink', input }))}.json`);
  const bytes = await readFile(path), destination = join(root, 'sentinel');
  await writeFile(destination, bytes, { mode: 0o600, flag: 'wx' });
  await unlink(path); await symlink(destination, path);
  try {
    const second = spawn(process.execPath, ['--input-type=module', '-e', source],
      { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    t.after(() => { if (second.exitCode === null) second.kill(); });
    let output = ''; second.stderr.on('data', value => { output += value; });
    assert.notEqual(await new Promise(resolve => second.once('exit', resolve)), 0);
    assert.match(output, /ELOOP|unsafe/);
    assert.deepEqual(await readFile(destination), bytes);
  } finally {
    await unlink(path); await unlink(destination);
    const ended = new Promise(resolve => first.once('exit', resolve)); first.send('finish'); await ended;
  }
  await assert.rejects(access(root), error => error.code === 'ENOENT');
});

test('a corrupted worker cache is rejected rather than reused as a valid fixture', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const module = new URL('./private-link-cache.fixture.mjs', import.meta.url).href;
  const input = { source: 'unit-corruption', config: 1 };
  const source = `import {privateLinkCachedFixture,privateLinkFixtureCacheDirectory} from ${JSON.stringify(module)};
    await privateLinkCachedFixture('unit-worker-corruption',${JSON.stringify(input)},async()=>({valid:true}));
    process.send(await privateLinkFixtureCacheDirectory());process.on('message',()=>process.disconnect());`;
  const first = spawn(process.execPath, ['--input-type=module', '-e', source],
    { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (first.exitCode === null) first.kill(); });
  const root = await new Promise((resolve, reject) => { first.once('message', resolve); first.once('error', reject); });
  const key = digest(JSON.stringify({ namespace: 'unit-worker-corruption', input }));
  await writeFile(join(root, `${key}.json`), JSON.stringify({ key, sha256: digest('wrong payload'), payload: JSON.stringify({ valid: false }) }), { mode: 0o600 });
  const second = spawn(process.execPath, ['--input-type=module', '-e', source],
    { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  t.after(() => { if (second.exitCode === null) second.kill(); });
  let error = '';
  second.stderr.on('data', value => { error += value; });
  assert.notEqual(await new Promise(resolve => second.once('exit', resolve)), 0);
  assert.match(error, /AssertionError/);
  const ended = new Promise(resolve => first.once('exit', resolve)); first.send('finish'); await ended;
  await assert.rejects(access(root), value => value.code === 'ENOENT');
});

test('staggered workers may regenerate cleaned setup but never lose files beneath a new reader', {
  skip: !['darwin', 'linux'].includes(process.platform),
}, async t => {
  const module = new URL('./private-link-cache.fixture.mjs', import.meta.url).href;
  const source = `import {privateLinkCachedFixture,privateLinkFixtureCacheDirectory} from ${JSON.stringify(module)};
    const value=await privateLinkCachedFixture('unit-staggered-workers',{source:'same-run'},async()=>({values:[1,2,3]}));
    process.send({root:await privateLinkFixtureCacheDirectory(),value});process.on('message',()=>process.disconnect());`;
  const children = [];
  function start() {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source],
      { env: { ...process.env, NODE_TEST_CONTEXT: 'child-v8' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    children.push(child);
    let stderr = '';
    child.stderr.on('data', data => { stderr += data; });
    const ended = new Promise(resolve => child.once('exit', resolve));
    const ready = new Promise((resolve, reject) => {
      child.once('message', resolve); child.once('error', reject);
      ended.then(code => { if (code !== 0) reject(new Error(stderr)); });
    });
    return { child, ready, ended };
  }
  t.after(() => { for (const child of children) if (child.exitCode === null) child.kill(); });
  let previous = start(), observed = await previous.ready;
  for (let i = 0; i < 6; i++) {
    const next = start();
    previous.child.send('finish');
    assert.equal(await previous.ended, 0);
    const value = await next.ready;
    assert.equal(value.root, observed.root); assert.deepEqual(value.value, { values: [1, 2, 3] });
    previous = next; observed = value;
  }
  previous.child.send('finish'); assert.equal(await previous.ended, 0);
  await assert.rejects(access(observed.root), error => error.code === 'ENOENT');
  const later = start(), rebuilt = await later.ready;
  assert.equal(rebuilt.root, observed.root); assert.deepEqual(rebuilt.value, { values: [1, 2, 3] });
  later.child.send('finish'); assert.equal(await later.ended, 0);
  await assert.rejects(access(rebuilt.root), error => error.code === 'ENOENT');
});
