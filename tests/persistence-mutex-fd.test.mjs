import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, rmSync } from 'node:fs';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { acquirePosixWriterMutex } from '../dist/adapters/persistence/writer-mutex.js';
import { readPrivateBytes } from '../dist/adapters/persistence/private-reader.js';
import { fixtureTreeSnapshot } from './fixtures/filesystem-snapshot.mjs';

const posix = { skip: !['darwin', 'linux'].includes(process.platform), timeout: 30_000 };
const competitor = `
  import {acquirePosixWriterMutex} from './dist/adapters/persistence/writer-mutex.js';
  const {root,rootDigest}=JSON.parse(process.argv[1]);
  try {
    const release=acquirePosixWriterMutex(root,rootDigest);
    try { console.log(JSON.stringify({state:'acquired',pid:process.pid})); }
    finally { release(); }
  } catch(error) {
    console.log(JSON.stringify({state:'blocked',code:error.code,pid:process.pid}));
  }
`;

function contend(root, rootDigest) {
  const child = spawnSync(process.execPath,
    ['--input-type=module', '-e', competitor, JSON.stringify({ root, rootDigest })],
    { cwd: process.cwd(), encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384 });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.notEqual(result.pid, process.pid);
  return result;
}

async function fixture(t) {
  const root = path.join(process.cwd(), `.mutex-fd-proof-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const files = await LocalWorkspace.open(root);
  return { root, files, filename: path.join(root, '.missionspec/writer-mutex.lock') };
}

test('the held writer mutex must survive unrelated same-process descriptor closes', posix, async (t) => {
  for (const observer of ['direct descriptor', 'production bounded reader', 'whole private-state fixture snapshot', 'worker descriptor', 'worker acquire']) {
    await t.test(observer, async (t) => {
      const { root, files, filename } = await fixture(t);
      const release = acquirePosixWriterMutex(root, files.rootDigest);
      try {
        const before = lstatSync(filename, { bigint: true });
        assert.equal(contend(root, files.rootDigest).state, 'blocked', 'Control competitor must see the original kernel lock');
        if (observer === 'direct descriptor') {
          const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
          try {
            assert.equal(fstatSync(fd, { bigint: true }).ino, before.ino);
            assert.equal(readSync(fd, Buffer.alloc(100), 0, 100, 0), 100);
          } finally { closeSync(fd); }
        } else if (observer === 'production bounded reader') {
          assert.equal(readPrivateBytes(filename, 100, { expected: before, prefix: true }).length, 100);
        } else if (observer === 'whole private-state fixture snapshot') {
          const snapshot = fixtureTreeSnapshot(path.join(root, '.missionspec'));
          assert.equal(snapshot.entries['writer-mutex.lock'].stat.ino, before.ino);
        } else if (observer === 'worker descriptor') {
          const worker = new Worker(`
            const fs=require('node:fs');
            const {parentPort,workerData}=require('node:worker_threads');
            const fd=fs.openSync(workerData,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
            let inode;
            try { inode=String(fs.fstatSync(fd,{bigint:true}).ino); fs.readSync(fd,Buffer.alloc(100),0,100,0); }
            finally { fs.closeSync(fd); }
            parentPort.postMessage({pid:process.pid,inode});
          `, { eval: true, workerData: filename, execArgv: [] });
          const exited = once(worker, 'exit');
          const [message] = await once(worker, 'message');
          assert.equal(message.pid, process.pid, 'Worker must share the owner process');
          assert.equal(message.inode, String(before.ino));
          assert.equal((await exited)[0], 0);
        } else {
          const worker = new Worker(`
            const {parentPort,workerData}=require('node:worker_threads');
            (async()=>{
              const {acquirePosixWriterMutex}=await import(workerData.module);
              try {
                const release=acquirePosixWriterMutex(workerData.root,workerData.rootDigest);
                release();
                parentPort.postMessage({pid:process.pid,state:'acquired'});
              } catch(error) {
                parentPort.postMessage({pid:process.pid,state:'blocked',code:error.code});
              }
            })();
          `, { eval: true, execArgv: [], workerData: {
            root, rootDigest: files.rootDigest,
            module: new URL('../dist/adapters/persistence/writer-mutex.js', import.meta.url).href,
          } });
          const exited = once(worker, 'exit');
          const [message] = await once(worker, 'message');
          assert.equal(message.pid, process.pid);
          assert.equal((await exited)[0], 0);
          assert.equal(message.state, 'blocked', 'A second isolate must not acquire the owner mutex');
        }
        const after = lstatSync(filename, { bigint: true });
        assert.equal(after.dev, before.dev);
        assert.equal(after.ino, before.ino);
        assert.equal(after.nlink, 1n);
        const result = contend(root, files.rootDigest);
        assert.equal(result.state, 'blocked',
          `${observer}: a different child acquired the same inode before the owner's release()`);
      } finally { release(); }
      assert.equal(contend(root, files.rootDigest).state, 'acquired', 'The successor must be admitted after descriptor release');
      release();
    });
  }
});

test('reserved LocalWorkspace text reads refuse the mutex without weakening the kernel lock', posix, async (t) => {
  const { root, files } = await fixture(t);
  const release = acquirePosixWriterMutex(root, files.rootDigest);
  try {
    await assert.rejects(files.read('.missionspec/writer-mutex.lock'), { code: 'scope-exceeded' });
    assert.equal(contend(root, files.rootDigest).state, 'blocked');
  } finally { release(); }
});
