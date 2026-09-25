import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { linkSync, lstatSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { readPrivateStateFile } from '../dist/adapters/persistence/lifecycle-files.js';
import { readPrivateBytes } from '../dist/adapters/persistence/private-reader.js';
import { readWindowsPrivateFile, windowsPrivateEntries } from '../dist/adapters/platform/windows-private-state.js';
import { windowsFileSecurity } from './fixtures/windows-file-security.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 180_000 };
const helper = fileURLToPath(new URL('../assets/platform/windows-private-state.ps1', import.meta.url));
const powerShell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

function fixture(t) {
  const root = path.join(process.cwd(), `.held-read-${randomUUID()}`);
  windowsPrivateEntries([{ path: root, directory: true, writable: true, create: true }]);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const filename = path.join(root, 'private.json');
  windowsPrivateEntries([{ path: filename, directory: false, writable: true, create: true }]);
  const content = JSON.stringify({ marker: 'bounded private UTF-8 \u2603', payload: 'x'.repeat(20_000) });
  writeFileSync(filename, content);
  return { root, filename, content };
}

test('Windows persistence reader returns bounded bytes from the ACL-validated native handle', windows, (t) => {
  const f = fixture(t);
  const before = lstatSync(f.filename, { bigint: true });
  assert.equal(readPrivateStateFile(f.filename, 30_000), f.content);
  assert.deepEqual(readPrivateBytes(f.filename, 100, { expected: before, prefix: true }), Buffer.from(f.content).subarray(0, 100));
  assert.throws(() => readPrivateStateFile(f.filename, 100));
  const replacement = path.join(f.root, 'replacement.json');
  renameSync(f.filename, replacement);
  windowsPrivateEntries([{ path: f.filename, directory: false, writable: true, create: true }]);
  writeFileSync(f.filename, f.content);
  assert.throws(() => readWindowsPrivateFile(f.filename, before, 30_000));
  assert.equal(readFileSync(replacement, 'utf8'), f.content);
  windowsFileSecurity({ path: f.filename, publicRead: true });
  assert.throws(() => readPrivateStateFile(f.filename, 30_000));
});

test('Windows held read excludes competing replacement/writes and rechecks ACL and link admission before bytes', windows, async (t) => {
  for (const mutation of ['rename', 'write', 'links', 'acl']) {
    await t.test(mutation, async (t) => {
      const f = fixture(t);
      const root = lstatSync(f.root, { bigint: true });
      const identity = lstatSync(f.filename, { bigint: true });
      const operation = {
        kind: 'read', root: f.root, rootIdentity: { device: String(root.dev), inode: String(root.ino) },
        path: f.filename, expected: { device: String(identity.dev), inode: String(identity.ino) },
        maxBytes: 30_000, prefix: false,
      };
      const child = spawn(powerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper],
        { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
      t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill(); });
      let stderr = '';
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      const closed = once(child, 'close');
      const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
      child.stdin.write(`${JSON.stringify({ operation })}\n`);
      const first = await lines.next();
      assert.equal(first.done, false, stderr);
      assert.deepEqual(JSON.parse(first.value), { phase: 'read-held' });
      let changed = false;
      try {
        if (mutation === 'rename') renameSync(f.filename, `${f.filename}.moved`);
        if (mutation === 'write') writeFileSync(f.filename, 'competing writer');
        if (mutation === 'links') linkSync(f.filename, `${f.filename}.alias`);
        if (mutation === 'acl') windowsFileSecurity({ path: f.filename, publicRead: true });
        changed = true;
      } catch (error) {
        if (mutation === 'acl') throw error;
        assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code), error.message);
      }
      if (mutation === 'rename' || mutation === 'write') assert.equal(changed, false);
      child.stdin.end('continue\n');
      const last = await lines.next();
      assert.equal(last.done, false, stderr);
      const result = JSON.parse(last.value);
      const [code] = await closed;
      if (changed) {
        assert.equal(result.ok, false);
        assert.notEqual(code, 0);
        assert.equal(Object.hasOwn(result, 'value'), false);
      } else {
        assert.equal(code, 0, stderr);
        assert.equal(result.ok, true);
        assert.equal(Buffer.from(result.value.contentBase64, 'base64').toString(), f.content);
      }
      assert.equal(readFileSync(f.filename, 'utf8'), f.content);
    });
  }
});
