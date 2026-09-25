import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { acquirePosixWriterMutex } from '../dist/adapters/persistence/writer-mutex.js';

const posix = { skip: !['darwin', 'linux'].includes(process.platform), timeout: 30_000 };
const require = createRequire(import.meta.url);
const integrity = 'sha512-abjiHKkYdcH5M9ikBEJb0MKb/fEpPtZx/yfLHzTptvUAoiFayX0tIe0BTLBU4SAoRyjZLzA0dP1Rn2p0+QRyVg==';
const prebuilds = {
  'darwin-arm64': '1e93b74e556b7d1767d57fabb197d9d1df5641453967170537278f72ed46f018',
  'darwin-x64': '973e4b2addf30901b955c75626ac153d3a37cebcfa621375bcd490f199884c8e',
  'linux-arm64': '895dd0dca09438454f28bba250bcafa3e69c937fe97ea46b1b6212dc3a81315c',
  'linux-x64': '13657db7ce92f823ee8066cc7244f3a475340707fc065fd4f5aceeebbfa898c3',
};

async function fixture(t) {
  const root = path.join(process.cwd(), `.native-lock-contract-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const files = await LocalWorkspace.open(root);
  return { root, files, directory: path.join(root, '.missionspec') };
}

test('the actual Node native target matches the pinned audited prebuild and package contract', posix, (t) => {
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url)));
  assert.equal(manifest.dependencies['fs-native-extensions'], '1.5.1');
  assert.equal(lock.packages['node_modules/fs-native-extensions'].integrity, integrity);
  const native = require('fs-native-extensions');
  assert.equal(typeof native.tryLock, 'function');
  assert.equal(typeof native.unlock, 'function');
  const packageRoot = path.dirname(require.resolve('fs-native-extensions'));
  const target = path.join(packageRoot, 'prebuilds', `${process.platform}-${process.arch}`, 'fs-native-extensions.node');
  assert.ok(require.cache[target], 'The shipped Node prebuild must actually have loaded');
  assert.equal(createHash('sha256').update(readFileSync(target)).digest('hex'), prebuilds[`${process.platform}-${process.arch}`]);
  const metadata = JSON.parse(readFileSync(path.join(packageRoot, 'package.json')));
  for (const script of ['preinstall', 'install', 'postinstall']) assert.equal(metadata.scripts[script], undefined);
  assert.equal(metadata.license, 'Apache-2.0');
  t.diagnostic(`Loaded ${process.platform}-${process.arch} Node prebuild; no source-build/install script.`);
});

test('legacy experimental SQLite mutexes are preserved, not migrated or shadowed by native locks', posix, async (t) => {
  const { root, files, directory } = await fixture(t);
  mkdirSync(directory, { mode: 0o700 });
  const old = path.join(directory, 'writer-mutex.sqlite');
  const db = new DatabaseSync(old);
  db.exec('CREATE TABLE mutex(root TEXT, version INTEGER); INSERT INTO mutex VALUES (\'old experimental state\', 1)');
  db.close();
  const bytes = readFileSync(old);
  const identity = lstatSync(old, { bigint: true });
  assert.throws(() => acquirePosixWriterMutex(root, files.rootDigest), { code: 'conflict' });
  assert.deepEqual(readFileSync(old), bytes);
  assert.equal(lstatSync(old, { bigint: true }).ino, identity.ino);
  assert.equal(existsSync(path.join(directory, 'writer-mutex.lock')), false);
  assert.equal(existsSync(path.join(directory, 'writer-mutex.bootstrap')), false);
});

test('actual bootstrap process exits preserve partial and two-link states without reset', posix, async (t) => {
  for (const phase of ['partial', 'published']) {
    await t.test(phase, async (t) => {
      const { root, files, directory } = await fixture(t);
      const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
        import fs from 'node:fs';
        import {syncBuiltinESMExports} from 'node:module';
        import {acquirePosixWriterMutex} from './dist/adapters/persistence/writer-mutex.js';
        const c=JSON.parse(process.argv[1]), original={...fs};
        let descriptor;
        fs.openSync=(p,...args)=>{
          const fd=original.openSync(p,...args);
          if(String(p).endsWith('/writer-mutex.bootstrap')) descriptor=fd;
          return fd;
        };
        fs.writeFileSync=(fd,...args)=>{
          if(fd===descriptor && c.phase==='partial') {
            original.writeFileSync(fd,'{');original.fsyncSync(fd);process.exit(74);
          }
          return original.writeFileSync(fd,...args);
        };
        fs.unlinkSync=(p)=>{
          if(String(p).endsWith('/writer-mutex.bootstrap') && c.phase==='published') process.exit(74);
          return original.unlinkSync(p);
        };
        syncBuiltinESMExports();
        acquirePosixWriterMutex(c.root,c.rootDigest);
      `, JSON.stringify({ root, rootDigest: files.rootDigest, phase })], {
        cwd: process.cwd(), encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384,
      });
      assert.equal(child.status, 74, child.stderr);
      const bootstrap = path.join(directory, 'writer-mutex.bootstrap');
      const before = readFileSync(bootstrap);
      if (phase === 'published') {
        assert.equal(lstatSync(bootstrap).nlink, 2);
        assert.equal(lstatSync(bootstrap).ino, lstatSync(path.join(directory, 'writer-mutex.lock')).ino);
      } else assert.equal(before.toString(), '{');
      assert.throws(() => acquirePosixWriterMutex(root, files.rootDigest), { code: 'conflict' });
      assert.deepEqual(readFileSync(bootstrap), before);
      assert.equal(existsSync(path.join(directory, 'writer-mutex.lock')), phase === 'published');
    });
  }
});

test('a stale bootstrap absence observation never replaces the completed mutex or strands a new bootstrap', posix, async (t) => {
  const { root, files, directory } = await fixture(t);
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import fs from 'node:fs';
    import {syncBuiltinESMExports} from 'node:module';
    import {acquirePosixWriterMutex} from './dist/adapters/persistence/writer-mutex.js';
    const c=JSON.parse(process.argv[1]), original={...fs};
    fs.openSync=(p,...args)=>{
      if(String(p).endsWith('/writer-mutex.bootstrap')) {
        original.writeSync(1,'ready\\n');original.readSync(0,Buffer.alloc(1),0,1,null);
      }
      return original.openSync(p,...args);
    };
    syncBuiltinESMExports();
    const release=acquirePosixWriterMutex(c.root,c.rootDigest);
    release();
    original.writeSync(1,'done\\n');
  `, JSON.stringify({ root, rootDigest: files.rootDigest })], { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const closed = once(child, 'close');
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  assert.equal((await lines.next()).value, 'ready');
  acquirePosixWriterMutex(root, files.rootDigest)();
  const filename = path.join(directory, 'writer-mutex.lock');
  const identity = lstatSync(filename, { bigint: true });
  child.stdin.end('c');
  assert.equal((await lines.next()).value, 'done', stderr);
  assert.equal((await closed)[0], 0, stderr);
  assert.equal(lstatSync(filename, { bigint: true }).ino, identity.ino);
  assert.equal(existsSync(path.join(directory, 'writer-mutex.bootstrap')), false);
});

test('native loading is lazy and its absence blocks POSIX effects before bootstrap, not read-only imports', posix, async (t) => {
  const { root } = await fixture(t);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import {registerHooks} from 'node:module';
    import {readdirSync} from 'node:fs';
    let attempted=0;
    const hooks=registerHooks({resolve(specifier,context,next){
      if(specifier==='fs-native-extensions') {attempted++;throw new Error('Test-only missing native dependency');}
      return next(specifier,context);
    }});
    await import('./dist/api/index.js');
    const {LocalWorkspace}=await import('./dist/adapters/filesystem/local-workspace.js');
    const {acquirePosixWriterMutex}=await import('./dist/adapters/persistence/writer-mutex.js');
    const root=process.argv[1], files=await LocalWorkspace.open(root);
    assert.equal(await files.read('.missionspec/workspace.json'),null);
    assert.equal(attempted,0);
    assert.throws(()=>acquirePosixWriterMutex(root,files.rootDigest),{code:'capability-unavailable'});
    assert.equal(attempted,1);
    assert.deepEqual(readdirSync(root),[]);
    Object.defineProperty(process,'platform',{value:'win32'});
    acquirePosixWriterMutex(root,files.rootDigest)();
    assert.equal(attempted,1,'Windows dispatch must not load or call the POSIX addon');
    hooks.deregister();
  `, root], { cwd: process.cwd(), encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384 });
  assert.equal(child.status, 0, child.stderr);
});
