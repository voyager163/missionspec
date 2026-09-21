import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  ensureWindowsPrivateDirectories, removeWindowsPrivateFile, windowsPublication, writeWindowsPrivateFile,
} from '../dist/adapters/platform/windows-private-state.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { createPrivateFixtureRoot, removeFixtureRoot } from './fixtures/windows-private-state.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 240_000 };
const helper = fileURLToPath(new URL('../assets/platform/windows-private-state.ps1', import.meta.url));
const holders = new WeakMap();
function fixture(t) {
  const f = createPrivateFixtureRoot();
  holders.set(t, []);
  t.after(async () => {
    for (const stop of holders.get(t)) await stop();
    removeFixtureRoot(f.root, f.identity);
  });
  const scope = { root: f.root, dev: f.identity.dev, ino: f.identity.ino };
  const wire = { root: f.root, rootIdentity: { device: String(scope.dev), inode: String(scope.ino) } };
  return { ...f, scope, wire };
}

function controlled(t, operation) {
  const child = spawn('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper],
    { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
  const frames = [];
  const waiting = [];
  let stderr = '';
  let ended = false;
  child.stderr.setEncoding('utf8').on('data', (value) => { stderr += value.slice(0, 4096); });
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const frame = JSON.parse(line);
    const resolve = waiting.shift();
    if (resolve) resolve(frame); else frames.push(frame);
  });
  const exit = once(child, 'close').then(([code, signal]) => {
    ended = true;
    for (const resolve of waiting.splice(0)) resolve({ closed: true, code, signal });
    return { code, signal };
  });
  const timer = setTimeout(() => child.kill(), 45_000);
  const stop = async () => {
    clearTimeout(timer);
    if (!ended) { child.stdin.destroy(); child.kill(); }
    await exit;
    lines.close();
  };
  holders.get(t).push(stop);
  t.after(stop);
  child.stdin.write(`${JSON.stringify({ operation })}\n`);
  return {
    async next() {
      if (frames.length) return frames.shift();
      if (ended) throw new Error(`Native helper exited before the next checkpoint: ${stderr}`);
      return new Promise((resolve) => waiting.push(resolve));
    },
    ack() { child.stdin.write('continue\n'); },
    async finish(code = 0) {
      child.stdin.end('continue\n'.repeat(32));
      const result = await exit;
      assert.equal(result.code, code, stderr || JSON.stringify(frames));
      return frames.findLast((frame) => Object.hasOwn(frame, 'ok'));
    },
    async cancel() {
      child.stdin.end();
      const result = await exit;
      assert.equal(result.code, 1, stderr);
    },
  };
}

function adversary(input) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import fs from 'node:fs';
    const input = JSON.parse(fs.readFileSync(0,'utf8'));
    const result = {};
    for (const [name, from, to, kind] of input) {
      try {
        if (kind === 'write') fs.writeFileSync(from, 'unreviewed replacement', {flag:'w'});
        else if (kind === 'create') fs.writeFileSync(from, 'new destination winner', {flag:'wx'});
        else fs.renameSync(from, to);
        result[name] = 'changed';
      } catch (error) {
        if (!['EPERM','EACCES','EBUSY','EEXIST'].includes(error.code)) throw error;
        result[name] = 'blocked';
      }
    }
    fs.writeFileSync(1,JSON.stringify(result));
  `], { input: JSON.stringify(input), encoding: 'utf8', timeout: 15_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('held CREATE_NEW allocation prevents file and ancestor substitution before content write', windows, async (t) => {
  const f = fixture(t);
  const target = path.join(f.root, 'new-record.json');
  const foreign = path.join(f.root, 'foreign.txt');
  writeWindowsPrivateFile(f.scope, foreign, 'foreign bytes retained');
  const op = controlled(t, { ...f.wire, kind: 'create', path: target, content: 'reviewed private bytes' });
  assert.deepEqual(await op.next(), { phase: 'created-held' });
  assert.deepEqual(adversary([
    ['rename', target, `${target}.moved`, 'rename'],
    ['write', target, null, 'write'],
    ['substitute', foreign, target, 'rename'],
    ['ancestor', f.root, `${f.root}.moved`, 'rename'],
  ]), { rename: 'blocked', write: 'blocked', substitute: 'blocked', ancestor: 'blocked' });
  const result = await op.finish();
  assert.equal(result.ok, true);
  assert.equal(readFileSync(target, 'utf8'), 'reviewed private bytes');
  assert.equal(readFileSync(foreign, 'utf8'), 'foreign bytes retained');
});

test('held lock deletion excludes concurrent recoverers and preserves a later replacement lock', windows, async (t) => {
  const f = fixture(t);
  ensureWindowsPrivateDirectories(f.scope, path.join(f.root, '.missionspec'));
  const lock = path.join(f.root, '.missionspec', 'transaction.lock');
  const exited = spawnSync(process.execPath, ['-e', 'process.exit(0)']);
  assert.equal(exited.status, 0);
  const body = JSON.stringify({ transactionId: randomUUID(), pid: exited.pid });
  const reference = writeWindowsPrivateFile(f.scope, lock, body);
  const op = controlled(t, { ...f.wire, kind: 'delete', path: lock, digest: reference.digest, reference, absentProcess: exited.pid });
  assert.deepEqual(await op.next(), { phase: 'delete-held' });
  assert.throws(() => removeWindowsPrivateFile(f.scope, lock, reference.digest, reference, exited.pid));
  assert.deepEqual(adversary([
    ['rename', lock, `${lock}.moved`, 'rename'], ['write', lock, null, 'write'],
  ]), { rename: 'blocked', write: 'blocked' });
  assert.equal(readFileSync(lock, 'utf8'), body);
  assert.equal((await op.finish()).ok, true);
  assert.equal(existsSync(lock), false);
  const next = writeWindowsPrivateFile(f.scope, lock, 'replacement writer lock');
  assert.throws(() => removeWindowsPrivateFile(f.scope, lock, reference.digest, reference, exited.pid));
  assert.equal(readFileSync(lock, 'utf8'), 'replacement writer lock');
  removeWindowsPrivateFile(f.scope, lock, next.digest, next);
});

function publicationFixture(t, present = true) {
  const f = fixture(t);
  ensureWindowsPrivateDirectories(f.scope, path.join(f.root, '.missionspec', 'transactions'));
  const transactionId = randomUUID();
  const lock = path.join(f.root, '.missionspec', 'transaction.lock');
  const lockRef = writeWindowsPrivateFile(f.scope, lock, JSON.stringify({ transactionId, pid: process.pid }));
  const lease = { path: lock, dev: BigInt(lockRef.device), ino: BigInt(lockRef.inode), digest: lockRef.digest };
  const scope = { ...f.scope, lease };
  const target = path.join(f.root, 'source.txt');
  if (present) writeWindowsPrivateFile(scope, target, 'original preimage');
  const stage = `${target}.msn-${transactionId}`;
  const stageRef = writeWindowsPrivateFile(scope, stage, 'reviewed replacement', present ? target : undefined);
  const publication = {
    relative: 'source.txt', transactionId, index: 0, plan: digestContent('TEST ONLY filesystem publication'),
    expected: present ? digestContent('original preimage') : 'absent', proposed: digestContent('reviewed replacement'),
    stageIdentity: { dev: BigInt(stageRef.device), ino: BigInt(stageRef.inode) },
  };
  const operation = {
    ...f.wire, kind: 'publish', path: target, stage, backup: `${stage}.before`,
    intent: path.join(f.root, '.missionspec', 'transactions', `${transactionId}.win-0.json`),
    relative: publication.relative, plan: publication.plan, expected: publication.expected, proposed: publication.proposed,
    stageIdentity: { device: stageRef.device, inode: stageRef.inode },
    lease: { path: lock, device: lockRef.device, inode: lockRef.inode, digest: lockRef.digest },
  };
  return { ...f, scope, target, stage, publication, operation };
}

test('held publication blocks stale stage/destination writes and never overwrites a gap winner', windows, async (t) => {
  const f = publicationFixture(t);
  const op = controlled(t, f.operation);
  assert.deepEqual(await op.next(), { phase: 'publication-held' });
  assert.deepEqual(adversary([
    ['stage', f.stage, `${f.stage}.moved`, 'rename'],
    ['stage-write', f.stage, null, 'write'],
    ['target', f.target, `${f.target}.moved`, 'rename'],
    ['target-write', f.target, null, 'write'],
  ]), { stage: 'blocked', 'stage-write': 'blocked', target: 'blocked', 'target-write': 'blocked' });
  op.ack();
  while (true) {
    const frame = await op.next();
    if (frame.phase === 'preimage-retained') break;
    assert.ok(frame.phase, JSON.stringify(frame));
    op.ack();
  }
  assert.equal(existsSync(f.target), false);
  assert.deepEqual(adversary([['winner', f.target, null, 'create']]), { winner: 'changed' });
  assert.equal((await op.finish(1)).ok, false);
  assert.equal(readFileSync(f.target, 'utf8'), 'new destination winner');
  assert.equal(readFileSync(f.operation.backup, 'utf8'), 'original preimage');
  assert.equal(readFileSync(f.stage, 'utf8'), 'reviewed replacement');
  assert.throws(() => windowsPublication(f.scope, f.publication));
  unlinkSync(f.target);
  assert.equal(windowsPublication(f.scope, f.publication), 'published');
  assert.equal(readFileSync(f.target, 'utf8'), 'reviewed replacement');
  assert.equal(existsSync(f.operation.backup), false);
});

test('native preimage interruption is recoverable and cleanup cannot delete a reused stage name', windows, async (t) => {
  const f = publicationFixture(t);
  const op = controlled(t, f.operation);
  while (true) {
    const frame = await op.next();
    assert.ok(frame.phase, JSON.stringify(frame));
    if (frame.phase === 'preimage-retained') break;
    op.ack();
  }
  await op.cancel();
  assert.equal(windowsPublication(f.scope, f.publication, true), 'preimage-retained');
  const recovered = controlled(t, { ...f.operation, stageIdentity: undefined });
  while (true) {
    const frame = await recovered.next();
    assert.ok(frame.phase, JSON.stringify(frame));
    if (frame.phase === 'publication-durable') break;
    recovered.ack();
  }
  writeFileSync(f.stage, 'new unrelated stage-path occupant', { flag: 'wx' });
  assert.equal((await recovered.finish()).ok, true);
  assert.equal(readFileSync(f.stage, 'utf8'), 'new unrelated stage-path occupant');
  assert.equal(readFileSync(f.target, 'utf8'), 'reviewed replacement');
});
