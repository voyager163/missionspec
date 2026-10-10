import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import {
  closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync,
  renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  syncWindowsPrivateDirectory, WindowsDirectoryDurabilityError,
} from '../dist/adapters/platform/windows-private-state.js';
import { observeWorkspaceRoot } from '../dist/adapters/filesystem/local-workspace.js';
import {
  createPrivateFixtureRoot, removeFixtureRoot, windows, privateEntry, powershell,
} from './fixtures/windows-private-state.mjs';
import {
  afterSource, beforeSource, rawContent, journalName, completionName, writePrivateFile,
} from './fixtures/windows-directory-protocol.mjs';

const worker = fileURLToPath(new URL('./fixtures/windows-directory-protocol.mjs', import.meta.url));
const identity = (target) => lstatSync(target, { bigint: true });
const unconfirmed = (operation) => assert.throws(operation, (error) =>
  error instanceof WindowsDirectoryDurabilityError && error.code === 'EIO' && error.durability === 'unconfirmed');

async function fixture(t, seed = false) {
  const f = createPrivateFixtureRoot();
  t.after(() => removeFixtureRoot(f.root, f.identity));
  const observed = await observeWorkspaceRoot(f.root);
  const input = {
    root: f.root, workspace: { workspaceId: `WSP-${randomUUID()}`, rootDigest: observed.rootDigest },
    identity: { dev: String(f.identity.dev), ino: String(f.identity.ino) },
  };
  if (seed) {
    writePrivateFile(path.join(f.root, 'source.txt'), beforeSource);
    writePrivateFile(path.join(f.root, 'raw.txt'), rawContent);
    syncWindowsPrivateDirectory(f.root, f.identity);
  }
  return { ...f, input };
}

function execute(f, stop, expectedStatus = 0, override = {}) {
  const result = spawnSync(process.execPath, [worker], {
    input: JSON.stringify({ ...f.input, stop, ...override }), encoding: 'utf8', timeout: 90_000, maxBuffer: 65_536,
  });
  assert.equal(result.status, expectedStatus, result.stdout || result.stderr || result.error?.message);
  return JSON.parse(result.stdout);
}

function replaceContent(filename, content) {
  const descriptor = openSync(filename, 'w');
  try { writeFileSync(descriptor, content); fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

test('directory barrier rejects invalid identities and cannot become a portable no-op', () => {
  for (const expected of [null, {}, { dev: 1, ino: 1 }, { dev: -1n, ino: 1n },
    { dev: 0x1_0000_0000n, ino: 1n }, { dev: 1n, ino: 0n }, { dev: 1n, ino: 0x1_0000_0000_0000_0000n }]) {
    unconfirmed(() => syncWindowsPrivateDirectory('C:\\unused', expected));
  }
  if (process.platform !== 'win32') unconfirmed(() => syncWindowsPrivateDirectory('C:\\unused', { dev: 1n, ino: 1n }));
});

test('native barrier matches Node device/inode, rejects replaced identities and closes handles', windows, async (t) => {
  const f = await fixture(t);
  syncWindowsPrivateDirectory(f.root, f.identity);
  unconfirmed(() => syncWindowsPrivateDirectory(f.root, { dev: f.identity.dev, ino: f.identity.ino + 1n }));
  const directory = path.join(f.root, 'directory');
  privateEntry(directory, true, true);
  const original = identity(directory);
  syncWindowsPrivateDirectory(directory, original);
  renameSync(directory, `${directory}.old`);
  privateEntry(directory, true, true);
  unconfirmed(() => syncWindowsPrivateDirectory(directory, original));
  syncWindowsPrivateDirectory(directory, identity(directory));
  renameSync(directory, `${directory}.closed`);
  assert.equal(existsSync(`${directory}.closed`), true);
});

test('barrier refuses aliases, files, public ACLs and foreign owners without repair', windows, async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, 'guarded');
  privateEntry(target, true, true);
  const originalIdentity = identity(target);
  const link = path.join(f.root, 'junction');
  symlinkSync(target, link, 'junction');
  unconfirmed(() => syncWindowsPrivateDirectory(link, originalIdentity));
  rmSync(link);
  const file = path.join(f.root, 'regular');
  writePrivateFile(file, 'not a directory');
  unconfirmed(() => syncWindowsPrivateDirectory(file, identity(file)));
  unconfirmed(() => syncWindowsPrivateDirectory(path.join(f.root, 'GUARDED'), originalIdentity));
  const mutate = String.raw`
$ErrorActionPreference = 'Stop'
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
$sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
$acl = [IO.Directory]::GetAccessControl($v.path, $sections)
$before = $acl.GetSecurityDescriptorSddlForm($sections)
if ($v.action -eq 'public') {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow'))
} elseif ($v.action -eq 'owner') {
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
} elseif ($v.action -eq 'restore') { $acl.SetSecurityDescriptorSddlForm($v.sddl, $sections) }
if ($null -ne $v.action) { [IO.Directory]::SetAccessControl($v.path, $acl) }
$after = [IO.Directory]::GetAccessControl($v.path, $sections).GetSecurityDescriptorSddlForm($sections)
[Console]::Out.Write((@{before=$before;after=$after} | ConvertTo-Json -Compress))
`;
  for (const action of ['public', 'owner']) {
    const changed = powershell(mutate, { path: target, action });
    try {
      unconfirmed(() => syncWindowsPrivateDirectory(target, originalIdentity));
      assert.equal(powershell(mutate, { path: target }).after, changed.after);
    } finally { powershell(mutate, { path: target, action: 'restore', sddl: changed.before }); }
  }
  syncWindowsPrivateDirectory(target, originalIdentity);
});

test('a real incompatible directory handle blocks the barrier until explicitly closed', windows, async (t) => {
  const f = await fixture(t);
  const source = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)
$p = [Console]::In.ReadLine()
$a = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
  [Reflection.AssemblyName]::new('MissionSpec.DirectoryLock'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
$t = $a.DefineDynamicModule('Native').DefineType('Native', 'Public, Sealed, Abstract')
$m = $t.DefinePInvokeMethod('CreateFileW', 'kernel32.dll', 'Public, Static, PinvokeImpl',
  [Reflection.CallingConventions]::Standard, [IntPtr],
  [Type[]]@([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr]),
  [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
$m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
$m = $t.DefinePInvokeMethod('CloseHandle', 'kernel32.dll', 'Public, Static, PinvokeImpl',
  [Reflection.CallingConventions]::Standard, [bool], [Type[]]@([IntPtr]),
  [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
$m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
$n = $t.CreateType()
$h = $n::CreateFileW($p, [uint32]2147483648, 1, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
if ($h -eq [IntPtr](-1)) { throw 'Directory lock unavailable' }
try {
  [Console]::Out.WriteLine('locked')
  [void][Console]::In.ReadLine()
} finally { if (!$n::CloseHandle($h)) { throw 'Directory lock close failed' } }
`;
  const child = spawn('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64'),
  ], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false });
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const exited = once(child, 'exit');
  const timer = setTimeout(() => child.kill(), 30_000);
  try {
    child.stdin.write(`${f.root}\n`);
    const ready = await Promise.race([
      once(child.stdout, 'data').then(([bytes]) => bytes.toString()),
      exited.then(() => { throw new Error(`Directory holder exited before readiness: ${stderr}`); }),
    ]);
    assert.equal(ready.trim(), 'locked', stderr);
    unconfirmed(() => syncWindowsPrivateDirectory(f.root, f.identity));
    child.stdin.end('\n');
    assert.deepEqual(await exited, [0, null], stderr);
  } finally {
    clearTimeout(timer);
    child.stdin.destroy();
    if (child.exitCode === null && child.signalCode === null) { child.kill(); await exited; }
  }
  syncWindowsPrivateDirectory(f.root, f.identity);
});

test('real journal/rename/unlink completion follows all successful file and directory barriers', windows, async (t) => {
  const f = await fixture(t, true);
  const result = execute(f);
  assert.deepEqual(result, {
    state: 'complete-test-worker',
    events: ['journal-file-sync', 'journal-directory-sync', 'stage-directory-sync', 'source-renamed',
      'source-directory-sync', 'raw-unlinked', 'removal-directory-sync', 'completion-file-sync', 'completion-directory-sync'],
  });
  assert.equal(readFileSync(path.join(f.root, 'source.txt'), 'utf8'), afterSource);
  assert.equal(existsSync(path.join(f.root, 'raw.txt')), false);
  const done = readFileSync(path.join(f.root, completionName));
  writePrivateFile(path.join(f.root, 'raw.txt'), 'new user-retained replacement');
  replaceContent(path.join(f.root, 'source.txt'), 'new user edit');
  assert.deepEqual(execute(f), { state: 'already-complete-test-worker', events: ['completion-directory-sync'] });
  assert.equal(readFileSync(path.join(f.root, 'raw.txt'), 'utf8'), 'new user-retained replacement');
  assert.equal(readFileSync(path.join(f.root, 'source.txt'), 'utf8'), 'new user edit');
  assert.deepEqual(readFileSync(path.join(f.root, completionName)), done);
});

test('actual child exits preserve prepared journals and resume rename/removal before completion', windows, async (t) => {
  for (const stop of ['journal-file-sync', 'prepared', 'staged', 'rename-before-barrier', 'replaced', 'unlink-before-barrier', 'removed', 'completion-file-sync']) {
    const f = await fixture(t, true);
    const interrupted = execute(f, stop, 77);
    assert.equal(interrupted.state, 'interrupted-test-worker');
    assert.equal(interrupted.phase, stop);
    assert.equal(existsSync(path.join(f.root, completionName)), stop === 'completion-file-sync');
    const journal = readFileSync(path.join(f.root, journalName));
    if (['journal-file-sync', 'prepared', 'staged'].includes(stop)) {
      assert.equal(readFileSync(path.join(f.root, 'source.txt'), 'utf8'), beforeSource);
      assert.equal(readFileSync(path.join(f.root, 'raw.txt'), 'utf8'), rawContent);
    }
    const recovered = execute(f);
    if (stop === 'completion-file-sync') {
      assert.deepEqual(recovered, { state: 'already-complete-test-worker', events: ['completion-directory-sync'] });
    } else {
      assert.equal(recovered.state, 'complete-test-worker');
      assert.ok(recovered.events.indexOf('journal-directory-sync') < recovered.events.indexOf('source-directory-sync'));
      assert.ok(recovered.events.indexOf('removal-directory-sync') < recovered.events.indexOf('completion-file-sync'));
    }
    assert.equal(readFileSync(path.join(f.root, 'source.txt'), 'utf8'), afterSource);
    assert.equal(existsSync(path.join(f.root, 'raw.txt')), false);
    assert.deepEqual(readFileSync(path.join(f.root, journalName)), journal);
  }
});

test('recovery preserves changed preimages and rejects a copied journal at another bound root', windows, async (t) => {
  for (const [stop, edited] of [['prepared', 'source.txt'], ['replaced', 'raw.txt']]) {
    const f = await fixture(t, true);
    execute(f, stop, 77);
    replaceContent(path.join(f.root, edited), 'unreviewed user edit');
    assert.equal(execute(f, undefined, 78).reason, 'stale-preimage');
    assert.equal(readFileSync(path.join(f.root, edited), 'utf8'), 'unreviewed user edit');
    assert.equal(existsSync(path.join(f.root, completionName)), false);
  }
  const original = await fixture(t, true);
  execute(original, 'prepared', 77);
  const other = await fixture(t, true);
  writePrivateFile(path.join(other.root, journalName), readFileSync(path.join(original.root, journalName)));
  assert.equal(execute(other, undefined, 78).reason, 'journal-scope');
  assert.equal(readFileSync(path.join(other.root, 'source.txt'), 'utf8'), beforeSource);
  assert.equal(readFileSync(path.join(other.root, 'raw.txt'), 'utf8'), rawContent);
  assert.equal(existsSync(path.join(other.root, completionName)), false);
});

test('a stale barrier identity cannot acknowledge a journal or run following effects', windows, async (t) => {
  const f = await fixture(t, true);
  const staleIdentity = { ...f.input.identity, ino: String(BigInt(f.input.identity.ino) + 1n) };
  const result = execute(f, undefined, 78, { identity: staleIdentity });
  assert.equal(result.reason, 'durability-unconfirmed');
  assert.equal(existsSync(path.join(f.root, journalName)), true);
  assert.equal(existsSync(path.join(f.root, completionName)), false);
  assert.equal(readFileSync(path.join(f.root, 'source.txt'), 'utf8'), beforeSource);
  assert.equal(readFileSync(path.join(f.root, 'raw.txt'), 'utf8'), rawContent);
  assert.ok(!readdirSync(f.root).includes('.namespace-stage'));
});
