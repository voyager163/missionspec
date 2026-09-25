import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import {
  chmodSync, existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync,
  renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { acquirePosixWriterMutex } from '../dist/adapters/persistence/writer-mutex.js';
import { withEvidencePruneLock, removePreparedEvidence } from '../dist/adapters/persistence/evidence-files.js';
import { digestContent } from '../dist/kernel/revisions.js';

const posix = { skip: !['darwin', 'linux'].includes(process.platform), timeout: 30_000 };
const childSource = String.raw`
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {createRequire} from 'node:module';
const native=createRequire(import.meta.url)('fs-native-extensions');
import {LocalWorkspace,makeFilePlan,writeMutation} from './dist/adapters/filesystem/local-workspace.js';
import {digestApprovalRequest} from './dist/kernel/authority.js';
import {digestContent} from './dist/kernel/revisions.js';
import {withEvidencePruneLock,withStateLifecycleLock,removePreparedEvidence,inspectPrunableEvidence} from './dist/adapters/persistence/evidence-files.js';
import {readPrivateStateFile} from './dist/adapters/persistence/lifecycle-files.js';
import {readPrivateBytes} from './dist/adapters/persistence/private-reader.js';
import {acquirePosixWriterMutex} from './dist/adapters/persistence/writer-mutex.js';
const c=JSON.parse(process.argv[1]);
const original={...fs};
const signal=(phase,detail={})=>original.writeSync(1,JSON.stringify({phase,...detail})+'\n');
const gate=(phase)=>{signal(phase);original.readSync(0,Buffer.alloc(1),0,1,null);};
let stopped=false, reads=0, kernelHeld=false;
const tryLock=native.tryLock;
native.tryLock=function(fd) {
  const result=tryLock(fd);
  if(result) kernelHeld=true;
  return result;
};
const monitored=new Set();
fs.readSync=(fd,...args)=>{if(monitored.has(fd)) reads++; return original.readSync(fd,...args);};
fs.openSync=(p,...args)=>{
  if(c.mode==='reader' && String(p)===c.source && !stopped) { stopped=true;gate('pre-open'); }
  const fd=original.openSync(p,...args);
  if(String(p)===c.source) monitored.add(fd);
  return fd;
};
fs.closeSync=(fd)=>{monitored.delete(fd);return original.closeSync(fd);};
fs.lstatSync=(p,...args)=>{
  const result=original.lstatSync(p,...args);
  if(c.mode==='reclaim' && kernelHeld && String(p)===c.root+'/.missionspec/transaction.lock' && !stopped) {
    stopped=true;gate('reclaim-final-stat');
  }
  return result;
};
fs.renameSync=(from,to)=>{
  if(String(from)===c.source && String(to).endsWith('/captured')) {
    if(c.mode==='before-move') gate('before-move');
    if(c.mode==='crash-intent') process.exit(73);
    original.renameSync(from,to);
    if(c.mode==='crash-move') process.exit(73);
    return;
  }
  return original.renameSync(from,to);
};
fs.unlinkSync=(p)=>{
  if(String(p).endsWith('/captured')) {
    if(c.mode==='after-verify') gate('after-verify');
    if(c.mode==='crash-verified') process.exit(73);
    original.unlinkSync(p);
    if(c.mode==='crash-delete') process.exit(73);
    return;
  }
  return original.unlinkSync(p);
};
syncBuiltinESMExports();
try {
  const files=await LocalWorkspace.open(c.root);
  if(c.mode==='reader') {
    if(c.reader==='evidence') await inspectPrunableEvidence(files,c.workspace,c.item);
    else if(c.reader==='workspace') await files.read(c.item.path);
    else if(c.reader==='header') readPrivateBytes(c.source,100,{expected:{dev:BigInt(c.expected.dev),ino:BigInt(c.expected.ino)},prefix:true});
    else readPrivateStateFile(c.source,16384);
  } else if(c.mode==='mutex-probe') {
    const release=acquirePosixWriterMutex(c.root,files.rootDigest);
    try {signal('entered');} finally {release();}
  } else if(c.mode==='runtime' || c.mode==='runtime-held') {
    await files.withRuntimeLock(async()=>c.mode==='runtime-held'?gate('owned'):signal('entered'));
  } else if(c.mode==='transaction-held') {
    const plan=makeFilePlan({workspace:c.workspace,guards:[{path:'fixture-output.md',digest:'absent'}],
      mutations:[writeMutation('fixture-output.md','absent','fixture output','artifact')],operation:'onboard',purpose:'integration'});
    const now=new Date().toISOString();
    const reference={id:'APR-test-only-kernel-mutex'};
    const issued={contractVersion:1,state:'trusted-issued',reference,
      assurance:{kind:'local-user',channel:'qualified-host-callback',qualificationEvidence:digestContent('TEST ONLY')},
      request:plan.request,requestDigest:digestApprovalRequest(plan.request),issuedAt:now,
      expiresAt:new Date(Date.parse(now)+3600000).toISOString()};
    const writer=await LocalWorkspace.open(c.root,{now:()=>now,beforeEffects:async()=>gate('owned'),
      authority:{resolve:async()=>({status:'ok',value:{state:'current',approval:issued}}),
      requestConfirmation:async()=>({status:'ok',value:{state:'unavailable',reason:'no-local-user'}})}});
    await writer.commit(plan,reference);
  } else {
    const lock=c.mode.startsWith('lifecycle')?withStateLifecycleLock:withEvidencePruneLock;
    await lock(files,c.workspace,c.job,async()=>{
      if(c.mode==='reclaim' || c.mode==='lifecycle-held') {gate('owned');return;}
      if(c.mode==='competitor' || c.mode==='lifecycle') {signal('entered');return;}
      signal('result',{value:await removePreparedEvidence(files,c.workspace,c.item)});
      if(c.mode==='crash-receipt') process.exit(73);
    });
  }
  signal('done',{reads});
} catch(error) {
  signal('error',{code:error.code,reference:error.retainedPath,message:error.message,reads});
}
`;

async function fixture(t) {
  const root = path.join(process.cwd(), `.persistence-race-${randomUUID()}`);
  mkdirSync(root, { mode: 0o700 });
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(path.join(root, '.missionspec'), { mode: 0o700 });
  mkdirSync(path.join(root, '.missionspec/evidence'), { mode: 0o700 });
  const files = await LocalWorkspace.open(root);
  const workspace = { workspaceId: `WSP-${randomUUID()}`, rootDigest: files.rootDigest };
  writeFileSync(path.join(root, '.missionspec/workspace.json'), JSON.stringify(workspace), { mode: 0o600 });
  const content = JSON.stringify({ schemaVersion: 1, evidenceId: 'EVD-race', basis: 'executed', result: 'passed', output: 'original raw bytes' });
  const item = {
    id: 'EVD-race', runId: 'RUN-race', runRevision: digestContent('run'), evidenceDigest: digestContent('reference'),
    path: '.missionspec/evidence/EVD-race.json', rawDigest: digestContent(content),
  };
  const source = path.join(root, item.path);
  writeFileSync(source, content, { mode: 0o600 });
  const job = digestContent(JSON.stringify({ workspace, item }));
  const release = acquirePosixWriterMutex(root, files.rootDigest);
  release();
  return { root, files, workspace, content, item, source, job };
}

function start(t, f, mode, extras = {}) {
  const config = { root: f.root, workspace: f.workspace, item: f.item, source: f.source, job: f.job, mode, ...extras };
  const child = spawn(process.execPath, ['--input-type=module', '-e', childSource, JSON.stringify(config)],
    { cwd: process.cwd(), stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const lines = createInterface({ input: child.stdout });
  const iterator = lines[Symbol.asyncIterator]();
  const closed = once(child, 'close');
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return {
    child,
    async next() {
      const { value, done } = await iterator.next();
      assert.equal(done, false, stderr);
      return JSON.parse(value);
    },
    async finish() {
      const [code, signal] = await closed;
      assert.equal(signal, null, stderr);
      return code;
    },
    resume() { child.stdin.write('c'); },
  };
}

function captures(f) {
  const directory = path.join(f.root, '.missionspec/prune-quarantine', f.job.slice(7));
  if (!existsSync(directory)) return [];
  return readdirSync(directory).filter((name) => /^[a-f0-9-]{36}$/u.test(name))
    .map((name) => path.join(directory, name, 'captured')).filter(existsSync);
}

async function recover(f) {
  return withEvidencePruneLock(f.files, f.workspace, f.job,
    () => removePreparedEvidence(f.files, f.workspace, f.item));
}

test('real recoverers cannot cross a paused final-stat/unlink boundary or steal the successor lock', posix, async (t) => {
  const f = await fixture(t);
  const dead = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
  assert.equal(dead.status, 0);
  const metadata = path.join(f.root, '.missionspec/transaction.lock');
  writeFileSync(metadata, JSON.stringify({ schemaVersion: 1, kind: 'evidence-prune', id: f.job, pid: dead.pid, nonce: randomUUID() }), { mode: 0o600 });
  const mutexBefore = lstatSync(path.join(f.root, '.missionspec/writer-mutex.lock'), { bigint: true });
  const a = start(t, f, 'reclaim');
  assert.equal((await a.next()).phase, 'reclaim-final-stat');
  for (const mode of ['competitor', 'runtime', 'lifecycle']) {
    const b = start(t, f, mode);
    const result = await b.next();
    assert.equal(result.phase, 'error', JSON.stringify(result));
    assert.equal(result.code, 'conflict');
    assert.equal(await b.finish(), 0);
    assert.equal(JSON.parse(readFileSync(metadata)).pid, dead.pid);
  }
  a.resume();
  assert.equal((await a.next()).phase, 'owned');
  const b = start(t, f, 'competitor');
  assert.equal((await b.next()).code, 'conflict');
  assert.equal(await b.finish(), 0);
  assert.equal(JSON.parse(readFileSync(metadata)).pid, a.child.pid);
  a.resume();
  assert.equal((await a.next()).phase, 'done');
  assert.equal(await a.finish(), 0);
  const mutexAfter = lstatSync(path.join(f.root, '.missionspec/writer-mutex.lock'), { bigint: true });
  assert.equal(mutexAfter.ino, mutexBefore.ino);
  assert.equal(mutexAfter.nlink, 1n);
  assert.equal(existsSync(metadata), false);
});

test('same-process mutex nesting fails closed and malformed/bootstrap files are never initialized', posix, async (t) => {
  const f = await fixture(t);
  const release = acquirePosixWriterMutex(f.root, f.files.rootDigest);
  try { assert.throws(() => acquirePosixWriterMutex(f.root, f.files.rootDigest), { code: 'conflict' }); }
  finally { release(); }
  const filename = path.join(f.root, '.missionspec/writer-mutex.lock');
  // Deliberate fixture corruption, not the production protocol.
  writeFileSync(filename, '');
  assert.throws(() => acquirePosixWriterMutex(f.root, f.files.rootDigest));
  assert.equal(readFileSync(filename).length, 0);
  writeFileSync(filename, 'foreign mutex contents');
  assert.throws(() => acquirePosixWriterMutex(f.root, f.files.rootDigest));
  assert.equal(readFileSync(filename, 'utf8'), 'foreign mutex contents');
  rmSync(filename);
  const bootstrap = path.join(f.root, '.missionspec/writer-mutex.bootstrap');
  writeFileSync(bootstrap, '', { mode: 0o600 });
  assert.throws(() => acquirePosixWriterMutex(f.root, f.files.rootDigest), { code: 'conflict' });
  assert.equal(readFileSync(bootstrap).length, 0);
  assert.equal(existsSync(filename), false);
});

test('runtime, transaction and lifecycle effects really hold the same kernel mutex', posix, async (t) => {
  for (const mode of ['runtime-held', 'transaction-held', 'lifecycle-held']) {
    await t.test(mode, async (t) => {
      const f = await fixture(t);
      const owner = start(t, f, mode);
      assert.equal((await owner.next()).phase, 'owned');
      const contender = start(t, f, 'mutex-probe');
      assert.equal((await contender.next()).code, 'conflict');
      assert.equal(await contender.finish(), 0);
      owner.resume();
      assert.equal((await owner.next()).phase, 'done');
      assert.equal(await owner.finish(), 0);
      const successor = start(t, f, 'mutex-probe');
      assert.equal((await successor.next()).phase, 'entered');
      assert.equal((await successor.next()).phase, 'done');
      assert.equal(await successor.finish(), 0);
    });
  }
});

test('live legacy metadata blocks bootstrap before any new mutex or quarantine effects', posix, async (t) => {
  const f = await fixture(t);
  const mutex = path.join(f.root, '.missionspec/writer-mutex.lock');
  rmSync(mutex);
  const metadata = path.join(f.root, '.missionspec/transaction.lock');
  const content = JSON.stringify({ schemaVersion: 1, kind: 'evidence-prune', id: f.job, pid: process.pid, nonce: randomUUID() });
  writeFileSync(metadata, content, { mode: 0o600 });
  await assert.rejects(recover(f), { code: 'conflict' });
  assert.equal(readFileSync(metadata, 'utf8'), content);
  assert.equal(existsSync(mutex), false);
  assert.equal(existsSync(path.join(f.root, '.missionspec/writer-mutex.bootstrap')), false);
  assert.equal(existsSync(path.join(f.root, '.missionspec/prune-quarantine')), false);
});

test('source replacement immediately before native rename is captured, retained and explicitly referenced', posix, async (t) => {
  for (const replacement of ['different-bytes', 'identical-bytes', 'hard-link', 'symlink', 'mode']) {
    await t.test(replacement, async (t) => {
      const f = await fixture(t);
      const actor = start(t, f, 'before-move');
      assert.equal((await actor.next()).phase, 'before-move');
      const saved = `${f.source}.original`;
      renameSync(f.source, saved);
      const user = path.join(f.root, 'user-owned');
      writeFileSync(user, 'unrelated user source', { mode: 0o600 });
      if (replacement === 'hard-link') linkSync(user, f.source);
      else if (replacement === 'symlink') symlinkSync(user, f.source);
      else writeFileSync(f.source, replacement === 'identical-bytes' ? f.content : 'replacement bytes', { mode: replacement === 'mode' ? 0o644 : 0o600 });
      actor.resume();
      const result = await actor.next();
      assert.equal(result.phase, 'error', JSON.stringify(result));
      assert.equal(result.code, 'effect-outcome-unknown');
      assert.equal(await actor.finish(), 0);
      assert.equal(readFileSync(saved, 'utf8'), f.content);
      assert.equal(readFileSync(user, 'utf8'), 'unrelated user source');
      const retained = captures(f);
      assert.equal(retained.length, 1);
      assert.equal(result.reference, retained[0]);
      if (replacement === 'symlink') assert.equal(lstatSync(retained[0]).isSymbolicLink(), true);
      else assert.equal(readFileSync(retained[0], 'utf8'), replacement === 'hard-link' ? 'unrelated user source' :
        replacement === 'identical-bytes' ? f.content : 'replacement bytes');
      await assert.rejects(recover(f), { code: 'effect-outcome-unknown' });
      assert.equal(existsSync(retained[0]), true);
    });
  }
});

test('a new occupant of the source name after quarantine verification is never unlinked', posix, async (t) => {
  const f = await fixture(t);
  const actor = start(t, f, 'after-verify');
  assert.equal((await actor.next()).phase, 'after-verify');
  assert.equal(existsSync(f.source), false);
  writeFileSync(f.source, 'new user occupant', { mode: 0o600 });
  actor.resume();
  assert.equal((await actor.next()).value, 'removed');
  assert.equal((await actor.next()).phase, 'done');
  assert.equal(await actor.finish(), 0);
  assert.equal(readFileSync(f.source, 'utf8'), 'new user occupant');
  await assert.rejects(recover(f), { code: 'effect-outcome-unknown' });
  assert.equal(readFileSync(f.source, 'utf8'), 'new user occupant');
});

test('real process interruption preserves intent/move/delete distinctions without inferring success from absence', posix, async (t) => {
  for (const mode of ['crash-intent', 'crash-move', 'crash-verified', 'crash-delete', 'crash-receipt']) {
    await t.test(mode, async (t) => {
      const f = await fixture(t);
      const actor = start(t, f, mode);
      assert.equal(await actor.finish(), 73);
      if (mode === 'crash-delete') {
        assert.equal(existsSync(f.source), false);
        assert.equal(captures(f).length, 0);
        await assert.rejects(recover(f), { code: 'effect-outcome-unknown' });
        await assert.rejects(recover(f), { code: 'effect-outcome-unknown' });
      } else {
        assert.equal(await recover(f), mode === 'crash-receipt' ? 'already-absent' : 'removed');
        assert.equal(existsSync(f.source), false);
        assert.equal(await recover(f), 'already-absent');
      }
    });
  }
});

test('captured content, permissions, links and foreign job identity are preserved on recovery', posix, async (t) => {
  for (const change of ['content', 'mode', 'links', 'job', 'empty']) {
    await t.test(change, async (t) => {
      const f = await fixture(t);
      const actor = start(t, f, 'crash-move');
      assert.equal(await actor.finish(), 73);
      const [captured] = captures(f);
      assert.ok(captured);
      if (change === 'content') writeFileSync(captured, 'edited captured bytes');
      if (change === 'mode') chmodSync(captured, 0o644);
      if (change === 'links') linkSync(captured, path.join(f.root, 'user-alias'));
      if (change === 'empty') rmSync(captured);
      if (change === 'job') {
        const intent = path.join(path.dirname(path.dirname(captured)), `${f.item.id}.intent.json`);
        const value = JSON.parse(readFileSync(intent));
        value.job = digestContent('another reviewed job');
        writeFileSync(intent, JSON.stringify(value));
      }
      await assert.rejects(recover(f), { code: 'effect-outcome-unknown' });
      assert.equal(existsSync(captured), change !== 'empty');
    });
  }
});

test('held readers reject pre-open privacy/type/identity substitutions before reading bytes', posix, async (t) => {
  for (const reader of ['lifecycle', 'header', 'evidence', 'workspace']) {
    for (const mutation of ['mode', 'links', 'identical', 'fifo']) {
      await t.test(`${reader}-${mutation}`, async (t) => {
        const f = await fixture(t);
        const expected = lstatSync(f.source, { bigint: true });
        const actor = start(t, f, 'reader', { reader, expected: { dev: String(expected.dev), ino: String(expected.ino) } });
        assert.equal((await actor.next()).phase, 'pre-open');
        renameSync(f.source, `${f.source}.original`);
        if (mutation === 'links') {
          writeFileSync(f.source, f.content, { mode: 0o600 });
          linkSync(f.source, path.join(f.root, 'alias'));
        } else if (mutation === 'fifo') {
          const fifo = spawnSync('mkfifo', ['-m', '600', f.source], { encoding: 'utf8' });
          assert.equal(fifo.status, 0, fifo.stderr);
        } else writeFileSync(f.source, f.content, { mode: mutation === 'mode' ? 0o644 : 0o600 });
        actor.resume();
        const result = await actor.next();
        assert.equal(result.phase, 'error', JSON.stringify(result));
        assert.equal(result.reads, 0);
        assert.equal(await actor.finish(), 0);
        assert.equal(readFileSync(`${f.source}.original`, 'utf8'), f.content);
      });
    }
  }
});
