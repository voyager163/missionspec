import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmdirSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import {
  validateWindowsStatePath, windowsFailureDiagnostic, windowsPrivateEntries, WindowsPrivateStateError,
} from '../dist/adapters/platform/windows-private-state.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { LocalWorkspace, makeFilePlan, writeMutation } from '../dist/adapters/filesystem/local-workspace.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { createUserTelemetryPreferenceStore } from '../dist/adapters/telemetry/preferences.js';
import { createAuthorizedJsonlSink } from '../dist/adapters/logging/jsonl.js';
import { serializeDiagnosticEvent } from '../dist/adapters/logging/diagnostics.js';
import { openLocalAuthority } from '../dist/adapters/authority/local-authority.js';
import { TerminalAuthority } from '../dist/adapters/authority/terminal.js';
import { digestContent } from '../dist/kernel/revisions.js';

const windows = { skip: process.platform !== 'win32', timeout: 240_000 };
const ok = (result) => { assert.equal(result.status, 'ok', JSON.stringify(result)); return result.value; };
const blocked = (result, reason) => {
  assert.notEqual(result.status, 'ok', JSON.stringify(result));
  if (reason) assert.ok(result.error.fields.includes(reason), JSON.stringify(result));
};
const privateEntry = (target, directory = false, create = false) =>
  windowsPrivateEntries([{ path: target, directory, writable: true, create }]);
const powershell = (source, value) => {
  const script = "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)\n" +
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false, $true)\n" +
    "Import-Module -Name 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1' -ErrorAction Stop\n" + source;
  const result = spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
  ], { input: JSON.stringify(value), encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536, windowsHide: true, shell: false });
  assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
  return JSON.parse(result.stdout);
};
const aclScript = String.raw`
$ErrorActionPreference = 'Stop'
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
$directory = [IO.Directory]::Exists($v.path)
$sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
function ReadFixtureAcl {
  if ($directory) { return [IO.Directory]::GetAccessControl($v.path, $sections) }
  return [IO.File]::GetAccessControl($v.path, $sections)
}
$acl = ReadFixtureAcl
$before = $acl.GetSecurityDescriptorSddlForm($sections)
$changed = $true
if ($v.action -eq 'public') {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow')
  $acl.AddAccessRule($rule)
} elseif ($v.action -eq 'ancestor-write') {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'DeleteSubdirectoriesAndFiles', 'Allow')
  $acl.AddAccessRule($rule)
} elseif ($v.action -eq 'owner') {
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
} elseif ($v.action -eq 'restore') {
  $acl.SetSecurityDescriptorSddlForm($v.sddl, $sections)
} else { $changed = $false }
if ($changed) {
  if ($directory) { [IO.Directory]::SetAccessControl($v.path, $acl) }
  else { [IO.File]::SetAccessControl($v.path, $acl) }
}
$afterAcl = ReadFixtureAcl
$after = $afterAcl.GetSecurityDescriptorSddlForm($sections)
$owner = $afterAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
[Console]::Out.Write((@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;owner=$owner;before=$before;after=$after} | ConvertTo-Json -Compress))
`;

let knownUserFolders;
function fixtureEntry(target) {
  try { return lstatSync(target, { bigint: true }); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function safeFixtureFailure(error) {
  if (error instanceof WindowsPrivateStateError) return error.message;
  return ['EPERM', 'EACCES', 'ENOENT', 'EEXIST', 'ENOTDIR', 'ENOTEMPTY', 'EIO', 'EBUSY'].includes(error?.code)
    ? `filesystem-${error.code}` : 'fixture-operation-unavailable';
}

function removeFixtureRoot(root, identity, emptyOnly = false) {
  const current = fixtureEntry(root);
  if (current === null) return;
  if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== identity.dev || current.ino !== identity.ino) {
    throw new Error('Fixture root identity changed; cleanup refused');
  }
  privateEntry(root, true);
  const verified = fixtureEntry(root);
  if (verified === null || verified.dev !== identity.dev || verified.ino !== identity.ino) {
    throw new Error('Fixture root changed during cleanup validation');
  }
  if (emptyOnly) rmdirSync(root);
  else rmSync(root, { recursive: true });
}

function createPrivateFixtureRoot() {
  knownUserFolders ??= powershell(String.raw`
$ErrorActionPreference = 'Stop'
[Console]::Out.Write((@{
  profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
  localAppData=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
} | ConvertTo-Json -Compress))
`, null);
  const { profile, localAppData } = knownUserFolders;
  validateWindowsStatePath(profile);
  validateWindowsStatePath(localAppData);
  const relative = path.relative(profile, localAppData);
  assert.ok(relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative), 'Local application data must lie inside the current OS-reported user profile');
  const failures = [];
  for (const [kind, candidate] of [['local-app-data', localAppData], ['profile', profile]]) {
    const root = path.join(candidate, `.windows-state-${randomUUID()}`);
    let before;
    try { before = fixtureEntry(root); } catch (error) {
      failures.push(`${kind}: no creation attempted because the exclusive path could not be inspected: ${safeFixtureFailure(error)}`);
      continue;
    }
    if (before !== null) throw new Error('Exclusive fixture UUID path already exists; no cleanup attempted');
    try {
      // The existing container is an ancestor, not a private leaf. The helper
      // checks its ancestry before atomically securing this new child.
      privateEntry(root, true, true);
    } catch (error) {
      const reason = safeFixtureFailure(error);
      let partial;
      try { partial = fixtureEntry(root); } catch (inspectionError) {
        throw new Error(`${kind}: ${reason}; creation state cannot be inspected: ${safeFixtureFailure(inspectionError)}`);
      }
      if (partial !== null) {
        try { removeFixtureRoot(root, partial, true); } catch (cleanupError) {
          throw new Error(`${kind}: ${reason}; partial creation retained because safe empty-root cleanup failed: ${safeFixtureFailure(cleanupError)}`);
        }
        throw new Error(`${kind}: ${reason}; partial creation occurred and its verified empty UUID root was removed; no fallback attempted`);
      }
      failures.push(`${kind}: ${reason}`);
      continue;
    }
    let identity;
    try { identity = fixtureEntry(root); } catch (error) {
      throw new Error(`${kind}: successful creation could not be identity-checked; qualification stopped: ${safeFixtureFailure(error)}`);
    }
    if (identity === null) throw new Error(`${kind}: successfully created fixture disappeared; qualification stopped`);
    if (!identity.isDirectory() || identity.isSymbolicLink()) {
      throw new Error(`${kind}: successfully created fixture changed type; qualification stopped without cleanup`);
    }
    return { root, identity, kind };
  }
  throw new Error(`No private NTFS fixture root could be created under the OS-reported profile containers. ${failures.join(' | ')}`);
}

async function fixture(t) {
  const { root, identity, kind } = createPrivateFixtureRoot();
  const stores = [];
  t.after(() => {
    try { for (const store of stores) ok(store.close()); }
    finally {
      try { removeFixtureRoot(root, identity); } catch (error) {
        throw new Error(`Exact UUID fixture cleanup failed: ${safeFixtureFailure(error)}`);
      }
    }
  });
  t.diagnostic(`Private fixture container: ${kind}; new protected current-user-owned UUID root`);
  const runtime = path.join(root, '.missionspec');
  privateEntry(runtime, true, true);
  const files = await LocalWorkspace.open(root);
  const workspace = { workspaceId: `WSP-${randomUUID()}`, rootDigest: files.rootDigest };
  const directory = path.join(runtime, 'state');
  const filename = path.join(directory, 'ledger.sqlite');
  const openStore = async (mode = 'create', expectedWorkspace = workspace) => {
    const store = ok(await openRuntimeStore({ directory, mode, expectedWorkspace, busyTimeoutMs: 25 }));
    stores.push(store);
    return store;
  };
  const revisions = {
    workspace, changeId: 'CHG-windows', specification: digestContent('spec'), tasks: digestContent('tasks'),
    workflow: digestContent('workflow'), effects: digestContent('effects'), source: digestContent('source'),
  };
  const snapshot = {
    contractVersion: 1, id: 'RUN-windows', revisions, state: 'pending', activeTask: null,
    pendingTasks: ['TSK-windows'], attempts: [], quiescence: 'confirmed',
  };
  return { root, runtime, files, workspace, directory, filename, openStore, revisions, snapshot };
}

function inventory(root) {
  return readdirSync(root).sort().map((name) => {
    const target = path.join(root, name);
    const stat = lstatSync(target, { bigint: true });
    return [name, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs,
      stat.isDirectory() ? inventory(target) : readFileSync(target).toString('base64')];
  });
}

test('Windows path grammar rejects namespaces, alternate streams, aliases and devices on every platform', () => {
  for (const target of [
    String.raw`\\server\share\state`, String.raw`\\?\C:\state`, String.raw`\\.\C:\state`,
    String.raw`C:state`, String.raw`c:\state`, String.raw`C:\a\..\state`, String.raw`C:\state:stream`,
    String.raw`C:\state.`, 'C:\\state ', String.raw`C:\NUL.txt`, String.raw`C:\COM¹`,
    String.raw`C:\a\\state`, 'C:\\state\\', 'C:\\state\u0000',
  ]) assert.throws(() => validateWindowsStatePath(target), target);
  validateWindowsStatePath(String.raw`C:\private\literal '$()[]; folder\ledger.sqlite`);
  const resource = new URL('../assets/platform/windows-private-state.ps1', import.meta.url);
  const helperSource = readFileSync(resource, 'utf8');
  assert.ok(helperSource.startsWith("$ErrorActionPreference = 'Stop'"));
  assert.doesNotMatch(helperSource, /\.AceFlags\s+-band/u, 'PowerShell enum flags require an explicit numeric conversion');
  assert.ok(readFileSync(new URL('../assets/platform/windows-access-policy.ps1', import.meta.url), 'utf8')
    .startsWith('function Test-MissionSpecUntrustedMutation'));
});

test('Windows helper diagnostics expose only fixed phases, exception categories and bounded line numbers', () => {
  assert.equal(windowsFailureDiagnostic(null), 'unavailable');
  assert.equal(windowsFailureDiagnostic({ reason: 'PRIVATE path SID ACL secret' }), 'unavailable');
  assert.equal(windowsFailureDiagnostic({
    reason: 'entry-acl-read', phase: 'entry-acl-read', boundary: 'system',
    exceptionType: 'MethodInvocationException', innerType: 'UnauthorizedAccessException', line: 61,
    message: 'PRIVATE path SID ACL secret',
  }), 'entry-acl-read; phase=entry-acl-read; boundary=system; exceptionType=MethodInvocationException; innerType=UnauthorizedAccessException; line=61');
  assert.equal(windowsFailureDiagnostic({
    reason: 'owner', phase: 'PRIVATE path', boundary: 'PRIVATE SID',
    exceptionType: 'PRIVATE ACL', innerType: 'PRIVATE secret', line: Infinity,
  }), 'owner');
});

test('untrusted create-child ACE rights never become write/append grants to an OS file', windows, () => {
  const cases = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$policy = [Console]::In.ReadToEnd() | ConvertFrom-Json
. $policy
$results = @()
foreach ($right in @(1, 2, 4, 6, 8, 16, 32, 64, 128, 256, 65536, 131072, 262144, 524288, 1048576, 268435456, 1073741824)) {
  $results += @{
    right=$right
    directory=(Test-MissionSpecUntrustedMutation $right $true)
    file=(Test-MissionSpecUntrustedMutation $right $false)
  }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`, fileURLToPath(new URL('../assets/platform/windows-access-policy.ps1', import.meta.url)));
  for (const result of cases) {
    if ([2, 4, 6].includes(result.right)) {
      assert.equal(result.directory, false);
      assert.equal(result.file, true);
    } else {
      const allowedRead = [1, 8, 32, 128, 131072, 1048576].includes(result.right);
      assert.equal(result.directory, !allowedRead);
      assert.equal(result.file, !allowedRead);
    }
  }
  assert.equal(cases.length, 17);
});

test('PowerShell 5.1 CommonAce inheritance enums retain exact numeric flag predicates', windows, () => {
  const cases = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$results = @()
$inheritOnly = [int][Security.AccessControl.AceFlags]::InheritOnly
$sid = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
foreach ($bits in 0..31) {
  $ace = [Security.AccessControl.CommonAce]::new(
    [Security.AccessControl.AceFlags]$bits, [Security.AccessControl.AceQualifier]::AccessAllowed,
    0x1F01FF, $sid, $false, $null)
  $flags = [int]$ace.AceFlags
  $results += @{
    bits=$bits; inheritOnly=(($flags -band $inheritOnly) -ne 0)
    hasInheritance=(($flags -band 3) -ne 0)
    noPropagate=(($flags -band 4) -ne 0)
    inheritsBoth=(($flags -band 3) -eq 3)
  }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`, null);
  assert.equal(cases.length, 32);
  for (const { bits, ...flags } of cases) {
    assert.deepEqual(flags, {
      inheritOnly: (bits & 8) !== 0, hasInheritance: (bits & 3) !== 0,
      noPropagate: (bits & 4) !== 0, inheritsBoth: (bits & 3) === 3,
    });
  }
});

test('project cwd/PATH cannot select PowerShell and SystemRoot cannot redirect its fixed OS path', windows, async (t) => {
  const f = await fixture(t);
  const shim = path.join(f.root, 'powershell.exe');
  privateEntry(shim, false, true);
  writeFileSync(shim, 'not an executable: a project shim must never be selected');
  const source = `
    import {readFileSync} from 'node:fs';
    import {windowsPrivateEntries,WindowsPrivateStateError} from ${JSON.stringify(new URL('../dist/adapters/platform/windows-private-state.js', import.meta.url).href)};
    const {path,redirect} = JSON.parse(readFileSync(0, 'utf8'));
    if (redirect) {
      process.env.SystemRoot = path;
      try {
        windowsPrivateEntries([{path,directory:true,writable:true}]);
        throw new Error('SystemRoot redirection was not rejected');
      } catch (error) {
        if (!(error instanceof WindowsPrivateStateError) || error.code !== 'EPERM' ||
            !error.message.endsWith('(system-executable).')) throw error;
        process.stdout.write('blocked-system-executable');
      }
    } else {
      windowsPrivateEntries([{path,directory:true,writable:true}]);
      process.stdout.write('checked');
    }
  `;
  const before = inventory(f.root);
  const accepted = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: f.root, env: { ...process.env, PATH: f.root },
    input: JSON.stringify({ path: f.root, redirect: false }), encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout, 'checked');
  const rejected = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: f.root, env: { ...process.env, PATH: f.root },
    input: JSON.stringify({ path: f.root, redirect: true }), encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(rejected.status, 0, rejected.stderr);
  assert.equal(rejected.stdout, 'blocked-system-executable');
  assert.deepEqual(inventory(f.root), before);
});

test('real SID ACLs secure new empty entries and reject unsafe/foreign existing entries without repair', windows, async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, "literal '$()[]; ü file");
  privateEntry(target, false, true);
  writeFileSync(target, 'private');
  const acl = powershell(aclScript, { path: target });
  assert.equal(acl.owner, acl.sid);
  assert.throws(() => privateEntry(target, false, true));
  for (const action of ['public', 'owner']) {
    const changed = powershell(aclScript, { path: target, action });
    const unsafe = powershell(aclScript, { path: target }).after;
    try {
      if (action === 'owner') assert.notEqual(changed.owner, acl.sid);
      assert.throws(() => privateEntry(target));
      assert.equal(powershell(aclScript, { path: target }).after, unsafe);
      assert.equal(readFileSync(target, 'utf8'), 'private');
    } finally { powershell(aclScript, { path: target, action: 'restore', sddl: acl.before }); }
  }
  privateEntry(target);
});

test('real NTFS SQLite preserves schema, CAS/ABA, immutable evidence, workspace binding and read-only reopen', windows, async (t) => {
  const f = await fixture(t);
  const first = await f.openStore();
  const second = await f.openStore('read-write');
  const initial = ok(await first.commitRun({ expectedRevision: 'absent', snapshot: f.snapshot, attempts: [], evidence: [] }));
  blocked(await second.commitRun({ expectedRevision: 'absent', snapshot: f.snapshot, attempts: [], evidence: [] }), 'stale-revision');
  const raw = { schemaVersion: 1, evidenceId: 'EVD-windows', basis: 'static-inspection', result: 'failed', output: 'private raw retention sentinel' };
  const evidenceDirectory = path.join(f.runtime, 'evidence');
  privateEntry(evidenceDirectory, true, true);
  const rawFile = path.join(evidenceDirectory, 'EVD-windows.json');
  privateEntry(rawFile, false, true);
  writeFileSync(rawFile, JSON.stringify(raw));
  const evidence = {
    contractVersion: 1, id: raw.evidenceId, revisions: f.revisions, source: f.revisions.source,
    checkId: 'CHK-windows', checkDefinition: digestContent('check'), attemptId: null,
    storage: { state: 'retained', path: '.missionspec/evidence/EVD-windows.json', digest: digestContent(JSON.stringify(raw)) },
  };
  const next = ok(await second.commitRun({ expectedRevision: initial.revision, snapshot: f.snapshot, attempts: [], evidence: [evidence] }));
  assert.notEqual(next.revision, initial.revision);
  blocked(await first.commitRun({ expectedRevision: initial.revision, snapshot: f.snapshot, attempts: [], evidence: [] }), 'stale-revision');
  blocked(await first.commitRun({
    expectedRevision: next.revision, snapshot: f.snapshot, attempts: [], evidence: [{ ...evidence, checkDefinition: digestContent('substituted') }],
  }), 'conflict');
  const changed = ok(await first.commitRun({
    expectedRevision: next.revision, snapshot: { ...f.snapshot, state: 'quiesced', pendingTasks: [] }, attempts: [], evidence: [],
  }));
  const returned = ok(await second.commitRun({
    expectedRevision: changed.revision, snapshot: f.snapshot, attempts: [], evidence: [],
  }));
  assert.notEqual(returned.revision, next.revision);
  ok(first.close()); ok(second.close());
  const before = inventory(f.root);
  blocked(await openRuntimeStore({
    directory: f.directory, mode: 'read-write', expectedWorkspace: { ...f.workspace, rootDigest: digestContent('foreign') },
  }), 'workspace-mismatch');
  const readOnly = await f.openStore('read-only');
  assert.equal(ok(await readOnly.readRun('RUN-windows')).revision, returned.revision);
  assert.deepEqual(ok(await readOnly.readEvidence('EVD-windows')), evidence);
  blocked(await readOnly.commitRun({ expectedRevision: next.revision, snapshot: f.snapshot, attempts: [], evidence: [] }), 'read-only');
  ok(readOnly.close());
  assert.deepEqual(inventory(f.root), before);
  assert.equal(readFileSync(rawFile, 'utf8'), JSON.stringify(raw));
});

test('SQLite locks, retained journal sidecars and replacement of an open path fail closed', windows, async (t) => {
  const f = await fixture(t);
  const store = await f.openStore();
  const database = new DatabaseSync(f.filename);
  try {
    database.exec('BEGIN EXCLUSIVE');
    blocked(await store.commitRun({ expectedRevision: 'absent', snapshot: f.snapshot, attempts: [], evidence: [] }), 'busy');
    database.exec('ROLLBACK');
  } finally { database.close(); }
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot: f.snapshot, attempts: [], evidence: [] }));
  ok(store.close());
  for (const suffix of ['-journal', '-wal', '-shm']) {
    const sidecar = `${f.filename}${suffix}`;
    privateEntry(sidecar, false, true);
    writeFileSync(sidecar, 'retained interrupted state');
    const before = inventory(f.root);
    blocked(await openRuntimeStore({ directory: f.directory, mode: 'read-only', expectedWorkspace: f.workspace }), 'busy');
    assert.deepEqual(inventory(f.root), before);
    rmSync(sidecar);
  }
  const reopened = await f.openStore('read-write');
  try { renameSync(f.filename, `${f.filename}.old`); } catch (error) {
    assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(error.code));
    t.diagnostic(`SQLite's native Windows handle refused rename: ${error.code}`);
    assert.ok(ok(await reopened.readRun('RUN-windows')));
    return;
  }
  privateEntry(f.filename, false, true);
  writeFileSync(f.filename, readFileSync(`${f.filename}.old`));
  blocked(await reopened.readRun('RUN-windows'), 'unavailable');
});

test('real child exit retains uncommitted SQLite work as explicitly unreconciled, without automatic recovery', windows, async (t) => {
  const f = await fixture(t);
  const store = await f.openStore();
  ok(await store.commitRun({ expectedRevision: 'absent', snapshot: f.snapshot, attempts: [], evidence: [] }));
  ok(store.close());
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import {readFileSync} from 'node:fs';
    import {DatabaseSync} from 'node:sqlite';
    const db = new DatabaseSync(JSON.parse(readFileSync(0, 'utf8')));
    db.exec("BEGIN IMMEDIATE; UPDATE runs SET payload = 'interrupted'");
    process.exit(73);
  `], { input: JSON.stringify(f.filename), encoding: 'utf8', timeout: 30_000 });
  assert.equal(result.status, 73, result.stderr);
  assert.ok(existsSync(`${f.filename}-journal`));
  const before = inventory(f.root);
  blocked(await openRuntimeStore({ directory: f.directory, mode: 'read-write', expectedWorkspace: f.workspace }), 'busy');
  assert.deepEqual(inventory(f.root), before);
});

test('unsafe file/directory ACLs, hardlinks and junction/case aliases cannot open a ledger', windows, async (t) => {
  const f = await fixture(t);
  ok((await f.openStore()).close());
  for (const target of [f.runtime, f.directory, f.filename]) {
    const original = powershell(aclScript, { path: target, action: 'public' });
    try {
      const unsafe = powershell(aclScript, { path: target }).after;
      blocked(await openRuntimeStore({ directory: f.directory, mode: 'read-write', expectedWorkspace: f.workspace }), 'unavailable');
      assert.equal(powershell(aclScript, { path: target }).after, unsafe);
    } finally { powershell(aclScript, { path: target, action: 'restore', sddl: original.before }); }
  }
  const alias = path.join(f.root, 'hardlink');
  linkSync(f.filename, alias);
  blocked(await openRuntimeStore({ directory: f.directory, mode: 'read-only', expectedWorkspace: f.workspace }), 'unavailable');
  rmSync(alias);
  const junction = path.join(f.root, 'junction');
  symlinkSync(f.runtime, junction, 'junction');
  assert.throws(() => privateEntry(path.join(junction, 'state'), true));
  rmSync(junction);
  assert.throws(() => privateEntry(f.filename.replace('ledger.sqlite', 'LEDGER.sqlite')));
});

test('an unsafe test-owned ancestor blocks private creation and ledger reopen without ACL repair', windows, async (t) => {
  const f = await fixture(t);
  ok((await f.openStore()).close());
  const target = path.join(f.root, `blocked-${randomUUID()}`);
  const original = powershell(aclScript, { path: f.root, action: 'ancestor-write' });
  try {
    const before = inventory(f.root);
    assert.throws(() => privateEntry(target, true, true), /public-access.*boundary=ancestor/u);
    blocked(await openRuntimeStore({
      directory: f.directory, mode: 'read-write', expectedWorkspace: f.workspace,
    }), 'unavailable');
    assert.equal(existsSync(target), false);
    assert.deepEqual(inventory(f.root), before);
    assert.equal(powershell(aclScript, { path: f.root }).after, original.after);
  } finally {
    powershell(aclScript, { path: f.root, action: 'restore', sddl: original.before });
  }
  privateEntry(f.root, true);
});

test('preferences and JSONL use SID ACLs, real SQLite reopen and bounded explicit pruning', windows, async (t) => {
  const f = await fixture(t);
  const filename = path.join(f.root, 'preferences.sqlite');
  const preferences = () => createUserTelemetryPreferenceStore(filename, { ownership: 'missionspec-telemetry-only' });
  assert.deepEqual(await preferences().read(), { state: 'ready', value: {} });
  assert.equal(existsSync(filename), false);
  assert.deepEqual(await preferences().save({ preference: 'disabled' }), { state: 'saved' });
  assert.deepEqual(await preferences().save({ disclosureVersion: 1 }), { state: 'saved' });
  assert.deepEqual(await preferences().read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  const publicAcl = powershell(aclScript, { path: filename, action: 'public' });
  const before = readFileSync(filename);
  assert.equal((await preferences().save({ preference: 'enabled' })).state, 'unavailable');
  assert.deepEqual(readFileSync(filename), before);
  powershell(aclScript, { path: filename, action: 'restore', sddl: publicAcl.before });
  const logPath = path.join(f.root, 'diagnostics.jsonl');
  const sink = createAuthorizedJsonlSink(logPath);
  const line = serializeDiagnosticEvent({
    contractVersion: 1, severity: 'information', code: 'operation-stopped',
    operation: 'draft', engine: 'specification', errorCode: null, elapsedMilliseconds: null,
  }, '2026-09-21T00:00:00.000Z');
  await sink.write(line);
  privateEntry(logPath);
  const stale = await sink.previewPrune();
  await sink.write(line);
  assert.equal((await sink.prune(stale)).reason, 'stale-preview');
  privateEntry(`${logPath}.lock`, false, true);
  await assert.rejects(sink.write(line));
  assert.equal(readFileSync(logPath, 'utf8'), line + line);
  rmSync(`${logPath}.lock`);
  assert.deepEqual(await sink.prune(await sink.previewPrune()), { state: 'pruned' });
  assert.equal(readFileSync(logPath).length, 0);
});

test('unapproved file effects, journal recovery and terminal confirmation refuse without writes', windows, async (t) => {
  const f = await fixture(t);
  const identity = path.join(f.runtime, 'workspace.json');
  privateEntry(identity, false, true);
  writeFileSync(identity, JSON.stringify(f.workspace));
  const target = path.join(f.root, 'source.txt');
  privateEntry(target, false, true);
  writeFileSync(target, 'preimage');
  const plan = makeFilePlan({
    workspace: f.workspace, guards: [{ path: 'source.txt', digest: digestContent('preimage') }],
    mutations: [writeMutation('source.txt', digestContent('preimage'), 'replacement', 'configuration')],
    operation: 'onboard', purpose: 'integration',
  });
  const candidate = {
    kind: 'inert-proposal', host: 'copilot', summary: 'TEST ONLY: no host process or authority',
    changes: [{ path: 'source.txt', expected: digestContent('preimage'), content: 'replacement' }],
  };
  const sourcePlan = makeFilePlan({
    workspace: f.workspace, guards: plan.guards,
    mutations: [writeMutation('source.txt', digestContent('preimage'), 'replacement', 'source')],
    operation: 'implement', purpose: 'source-apply', revisions: f.revisions,
    sourcePatch: {
      slug: 'windows', task: {
        contractVersion: 1, id: 'TSK-windows', title: 'Windows fixture', dependsOn: [],
        requirements: [], scenarios: [], checks: [], writeScope: ['source.txt'],
      },
      proposal: { kind: candidate.kind, host: candidate.host, summary: candidate.summary, digest: digestContent(JSON.stringify(candidate)) },
      dependencies: null,
    },
  });
  const evidenceDirectory = path.join(f.runtime, 'evidence');
  privateEntry(evidenceDirectory, true, true);
  const rawFile = path.join(evidenceDirectory, 'EVD-retained.json');
  privateEntry(rawFile, false, true);
  writeFileSync(rawFile, 'private raw bytes retained through denied pruning');
  const transactions = path.join(f.runtime, 'transactions');
  privateEntry(transactions, true, true);
  const id = randomUUID();
  const journal = path.join(transactions, `${id}.json`);
  privateEntry(journal, false, true);
  writeFileSync(journal, JSON.stringify({ schemaVersion: 1, plan, approval: { id: 'APR-no-authority' } }));
  assert.deepEqual(await f.files.identity(), f.workspace);
  assert.deepEqual(await f.files.pending(), [id]);
  const before = inventory(f.root);
  await assert.rejects(f.files.commit(plan, { id: 'APR-no-authority' }), { code: 'authority-required' });
  await assert.rejects(f.files.commit(sourcePlan, { id: 'APR-no-authority' }), { code: 'authority-required' });
  await assert.rejects(f.files.recover(id, { id: 'APR-no-authority' }), { code: 'authority-required' });
  const authority = await openLocalAuthority({ directory: f.root });
  assert.equal(ok(await authority.requestConfirmation(plan.request)).state, 'unavailable');
  await assert.rejects(authority.requestConfirmation({ ...plan.request, approved: true }));
  assert.equal(ok(await (await TerminalAuthority.open(f.root)).requestConfirmation(plan.request)).state, 'unavailable');
  assert.deepEqual(inventory(f.root), before);
  writeFileSync(target, 'user edit');
  await assert.rejects(f.files.recoveryPlan(id), { code: 'stale-revision' });
  assert.equal(readFileSync(target, 'utf8'), 'user edit');
});

test('unapproved workspace setup is denied before runtime directories or receipts are created', windows, async (t) => {
  const f = await fixture(t);
  rmdirSync(f.runtime);
  const workflow = await LocalWorkflow.open(f.root);
  const plan = await workflow.previewSetup();
  const before = inventory(f.root);
  await assert.rejects(workflow.files.commit(plan, { id: 'APR-caller-json' }), { code: 'authority-required' });
  assert.deepEqual(inventory(f.root), before);
});

test('actual Windows directory fsync result is retained as a capability probe, not treated as file durability', windows, async (t) => {
  // The empty, nonsensitive primitive probe must run even if ACL qualification fails.
  const root = path.join(realpathSync(process.cwd()), `.windows-directory-probe-${randomUUID()}`);
  mkdirSync(root);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  let handle;
  let api = 'open';
  let result = 'unexpected-success';
  try {
    handle = await open(root, 'r');
    api = 'sync';
    await handle.sync();
  } catch (error) { result = error.code; } finally { await handle?.close(); }
  const native = powershell(String.raw`
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$a = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
  [Reflection.AssemblyName]::new('MissionSpec.DirectoryProbe'), [Reflection.Emit.AssemblyBuilderAccess]::Run)
$t = $a.DefineDynamicModule('Native').DefineType('Native', 'Public, Sealed, Abstract')
function Bind($name, $result, [Type[]]$parameters, [string]$dll = 'kernel32.dll') {
  $m = $t.DefinePInvokeMethod($name, $dll, 'Public, Static, PinvokeImpl',
    [Reflection.CallingConventions]::Standard, $result, $parameters,
    [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
  $m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
  $d = [Runtime.InteropServices.DllImportAttribute]
  $m.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
    $d.GetConstructor([Type[]]@([string])), [object[]]@($dll),
    [Reflection.FieldInfo[]]@($d.GetField('SetLastError'), $d.GetField('CharSet'), $d.GetField('ExactSpelling')),
    [object[]]@($true, [Runtime.InteropServices.CharSet]::Unicode, $true)))
  return $m
}
$create = Bind 'CreateFileW' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
$flush = Bind 'FlushFileBuffers' ([bool]) @([IntPtr])
$close = Bind 'CloseHandle' ([bool]) @([IntPtr])
$restrict = Bind 'CreateRestrictedToken' ([bool]) @([IntPtr], [uint32], [uint32], [IntPtr], [uint32], [IntPtr], [uint32], [IntPtr], [IntPtr].MakeByRefType()) 'advapi32.dll'
$sidConvert = Bind 'ConvertStringSidToSidW' ([bool]) @([string], [IntPtr].MakeByRefType()) 'advapi32.dll'
$localFree = Bind 'LocalFree' ([IntPtr]) @([IntPtr])
$tokenInfo = Bind 'GetTokenInformation' ([bool]) @([IntPtr], [int], [IntPtr], [uint32], [uint32].MakeByRefType()) 'advapi32.dll'
$lookup = Bind 'LookupPrivilegeValueW' ([bool]) @([string], [string], [IntPtr]) 'advapi32.dll'
# Capture the marshaler's last error inside the same managed method. Returning
# through PowerShell before reading it allows intervening runtime calls to reset it.
$openResult = $t.DefineMethod('OpenResult', 'Public, Static', [IntPtr],
  [Type[]]@([string], [uint32], [uint32], [int].MakeByRefType()))
$il = $openResult.GetILGenerator()
$handleLocal = $il.DeclareLocal([IntPtr])
$zero = [IntPtr].GetField('Zero')
$lastError = [Runtime.InteropServices.Marshal].GetMethod('GetLastWin32Error')
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_1)
$il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_7)
$il.Emit([Reflection.Emit.OpCodes]::Ldsfld, $zero)
$il.Emit([Reflection.Emit.OpCodes]::Ldc_I4_3)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_2)
$il.Emit([Reflection.Emit.OpCodes]::Ldsfld, $zero)
$il.Emit([Reflection.Emit.OpCodes]::Call, $create)
$il.Emit([Reflection.Emit.OpCodes]::Stloc, $handleLocal)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_3)
$il.Emit([Reflection.Emit.OpCodes]::Call, $lastError)
$il.Emit([Reflection.Emit.OpCodes]::Stind_I4)
$il.Emit([Reflection.Emit.OpCodes]::Ldloc, $handleLocal)
$il.Emit([Reflection.Emit.OpCodes]::Ret)
$flushResult = $t.DefineMethod('FlushResult', 'Public, Static', [bool], [Type[]]@([IntPtr], [int].MakeByRefType()))
$il = $flushResult.GetILGenerator()
$booleanLocal = $il.DeclareLocal([bool])
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
$il.Emit([Reflection.Emit.OpCodes]::Call, $flush)
$il.Emit([Reflection.Emit.OpCodes]::Stloc, $booleanLocal)
$il.Emit([Reflection.Emit.OpCodes]::Ldarg_1)
$il.Emit([Reflection.Emit.OpCodes]::Call, $lastError)
$il.Emit([Reflection.Emit.OpCodes]::Stind_I4)
$il.Emit([Reflection.Emit.OpCodes]::Ldloc, $booleanLocal)
$il.Emit([Reflection.Emit.OpCodes]::Ret)
$n = $t.CreateType()
function ObserveFlush {
  $results = @()
  foreach ($access in @([uint32]2147483648, [uint32]1073741824)) {
    foreach ($flags in @([uint32]33554432, [uint32]2181038080)) {
      $openError = [int]0
      $h = $n::OpenResult($p, $access, $flags, [ref]$openError)
      $opened = $h -ne [IntPtr](-1)
      if ($opened) { $openError = 0 }
      $flushed = $false
      $flushError = $null
      if ($opened) {
        try {
          $flushError = [int]0
          $flushed = $n::FlushResult($h, [ref]$flushError)
          if ($flushed) { $flushError = 0 }
        } finally { if (!$n::CloseHandle($h)) { throw 'CloseHandle failed' } }
      }
      $results += @{access=$access;flags=$flags;opened=$opened;openError=$openError;flushed=$flushed;flushError=$flushError}
    }
  }
  return $results
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent([Security.Principal.TokenAccessLevels]'Query, Duplicate, Impersonate')
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
# Only this newly created empty probe directory is changed, never a project root.
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($identity.User)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
  $identity.User, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
[IO.Directory]::SetAccessControl($p, $acl)
$results = @(ObserveFlush)
$token = @{
  administratorEnabled = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  currentUserOwnsDirectory = [IO.Directory]::GetAccessControl($p).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $identity.User.Value
}
$admin = [IntPtr]::Zero
$restricted = [IntPtr]::Zero
$sidEntry = [Runtime.InteropServices.Marshal]::AllocHGlobal(2 * [IntPtr]::Size)
$privileges = [Runtime.InteropServices.Marshal]::AllocHGlobal(4096)
$changeNotify = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
$context = $null
try {
  if (!$n::ConvertStringSidToSidW('S-1-5-32-544', [ref]$admin)) { throw 'SID conversion failed' }
  [Runtime.InteropServices.Marshal]::WriteIntPtr($sidEntry, 0, $admin)
  [Runtime.InteropServices.Marshal]::WriteInt32($sidEntry, [IntPtr]::Size, 0)
  if (!$n::CreateRestrictedToken($identity.Token, 1, 1, $sidEntry, 0, [IntPtr]::Zero, 0, [IntPtr]::Zero, [ref]$restricted)) { throw 'Token reduction failed' }
  $size = [uint32]0
  if (!$n::GetTokenInformation($restricted, 3, $privileges, 4096, [ref]$size) -or
      !$n::LookupPrivilegeValueW($null, 'SeChangeNotifyPrivilege', $changeNotify)) { throw 'Privilege observation failed' }
  $count = [Runtime.InteropServices.Marshal]::ReadInt32($privileges)
  if ($count -lt 0 -or $count -gt 128 -or $size -lt 4 + 12 * $count) { throw 'Invalid privilege buffer' }
  $privilegesDisabled = $true
  for ($index = 0; $index -lt $count; $index++) {
    $offset = 4 + 12 * $index
    if (([Runtime.InteropServices.Marshal]::ReadInt32($privileges, $offset + 8) -band 2) -ne 0 -and
        [Runtime.InteropServices.Marshal]::ReadInt64($privileges, $offset) -ne [Runtime.InteropServices.Marshal]::ReadInt64($changeNotify)) {
      $privilegesDisabled = $false
    }
  }
  $context = [Security.Principal.WindowsIdentity]::Impersonate($restricted)
  $restrictedIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    $restrictedPrincipal = [Security.Principal.WindowsPrincipal]::new($restrictedIdentity)
    $restrictedToken = @{
      administratorEnabled = $restrictedPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
      currentUserOwnsDirectory = [IO.Directory]::GetAccessControl($p).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $restrictedIdentity.User.Value
      privilegesDisabledExceptTraverse = $privilegesDisabled
    }
    $restrictedResults = @(ObserveFlush)
  } finally { $restrictedIdentity.Dispose() }
} finally {
  if ($null -ne $context) { $context.Undo(); $context.Dispose() }
  if ($restricted -ne [IntPtr]::Zero -and !$n::CloseHandle($restricted)) { throw 'Token close failed' }
  [void]$n::LocalFree($admin)
  [Runtime.InteropServices.Marshal]::FreeHGlobal($sidEntry)
  [Runtime.InteropServices.Marshal]::FreeHGlobal($privileges)
  [Runtime.InteropServices.Marshal]::FreeHGlobal($changeNotify)
  $identity.Dispose()
}
[Console]::Out.Write((ConvertTo-Json -Depth 5 -InputObject @{
  results=$results;token=$token;restricted=@{results=$restrictedResults;token=$restrictedToken}
} -Compress))
`, root);
  t.diagnostic(JSON.stringify({ platform: process.platform, node: process.version, nodeDirectory: { api, result }, nativeDirectory: native }));
  assert.equal(native.results.length, 4);
  assert.equal(typeof native.token.administratorEnabled, 'boolean');
  assert.equal(native.token.currentUserOwnsDirectory, true);
  assert.equal(native.restricted.results.length, 4);
  assert.deepEqual(native.restricted.token, {
    administratorEnabled: false, currentUserOwnsDirectory: true, privilegesDisabledExceptTraverse: true,
  });
  assert.notEqual(result, 'unexpected-success', 'If Node adds directory barriers, requalify the native semantics; do not silently enable effects.');
});
