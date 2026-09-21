import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  existsSync, linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import {
  validateWindowsStatePath, windowsPrivateEntries,
} from '../dist/adapters/platform/windows-private-state.js';
import { openRuntimeStore } from '../dist/adapters/persistence/index.js';
import { LocalWorkspace, makeFilePlan, writeMutation } from '../dist/adapters/filesystem/local-workspace.js';
import { LocalWorkflow } from '../dist/application/local-workflow.js';
import { removePreparedEvidence, withEvidencePruneLock } from '../dist/adapters/persistence/evidence-files.js';
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
  const script = "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false, $true)\n" + source;
  const result = spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
  ], { input: JSON.stringify(value), encoding: 'utf8', timeout: 30_000, maxBuffer: 65_536, windowsHide: true, shell: false });
  assert.equal(result.status, 0, result.stderr || result.error?.message || result.stdout);
  return JSON.parse(result.stdout);
};
const aclScript = String.raw`
$ErrorActionPreference = 'Stop'
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
$acl = Get-Acl -LiteralPath $v.path
$before = $acl.Sddl
if ($v.action -eq 'public') {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow')
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $v.path -AclObject $acl
} elseif ($v.action -eq 'owner') {
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  Set-Acl -LiteralPath $v.path -AclObject $acl
} elseif ($v.action -eq 'restore') {
  $acl.SetSecurityDescriptorSddlForm($v.sddl)
  Set-Acl -LiteralPath $v.path -AclObject $acl
}
[Console]::Out.Write((@{sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;before=$before;after=(Get-Acl -LiteralPath $v.path).Sddl} | ConvertTo-Json -Compress))
`;

async function fixture(t) {
  const root = path.join(realpathSync(process.cwd()), `.windows-state-${randomUUID()}`);
  const stores = [];
  assert.equal(existsSync(root), false);
  t.after(() => {
    try { for (const store of stores) ok(store.close()); }
    finally { rmSync(root, { recursive: true, force: true }); }
  });
  privateEntry(root, true, true);
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
  assert.ok(readFileSync(resource, 'utf8').startsWith("$ErrorActionPreference = 'Stop'"));
});

test('project cwd/PATH cannot select PowerShell and SystemRoot cannot redirect its fixed OS path', windows, async (t) => {
  const f = await fixture(t);
  const shim = path.join(f.root, 'powershell.exe');
  privateEntry(shim, false, true);
  writeFileSync(shim, 'not an executable: a project shim must never be selected');
  const source = `
    import {readFileSync} from 'node:fs';
    import {windowsPrivateEntries} from ${JSON.stringify(new URL('../dist/adapters/platform/windows-private-state.js', import.meta.url).href)};
    const path = JSON.parse(readFileSync(0, 'utf8'));
    windowsPrivateEntries([{path,directory:true,writable:true}]);
    process.stdout.write('checked');
  `;
  const before = inventory(f.root);
  const accepted = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: f.root, env: { ...process.env, PATH: f.root }, input: JSON.stringify(f.root), encoding: 'utf8', timeout: 30_000,
  });
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout, 'checked');
  const rejected = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
    cwd: f.root, env: { ...process.env, SystemRoot: f.root, PATH: f.root },
    input: JSON.stringify(f.root), encoding: 'utf8', timeout: 30_000,
  });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /system-executable/u);
  assert.deepEqual(inventory(f.root), before);
});

test('real SID ACLs secure new empty entries and reject unsafe/foreign existing entries without repair', windows, async (t) => {
  const f = await fixture(t);
  const target = path.join(f.root, "literal '$()[]; ü file");
  privateEntry(target, false, true);
  writeFileSync(target, 'private');
  const acl = powershell(aclScript, { path: target });
  assert.match(acl.after, new RegExp(`^O:${acl.sid.replaceAll('-', '\\-')}`));
  assert.throws(() => privateEntry(target, false, true));
  for (const action of ['public', 'owner']) {
    powershell(aclScript, { path: target, action });
    const unsafe = powershell(aclScript, { path: target }).after;
    try {
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

test('source effects, runtime records, authority, prune deletion and journal recovery stay unavailable without writes', windows, async (t) => {
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
  const pruneTarget = {
    id: 'EVD-retained', runId: 'RUN-windows', runRevision: digestContent('revision'),
    evidenceDigest: digestContent('evidence'), path: '.missionspec/evidence/EVD-retained.json',
    rawDigest: digestContent(readFileSync(rawFile)),
  };
  const transactions = path.join(f.runtime, 'transactions');
  privateEntry(transactions, true, true);
  const id = randomUUID();
  const journal = path.join(transactions, `${id}.json`);
  privateEntry(journal, false, true);
  writeFileSync(journal, JSON.stringify({ schemaVersion: 1, plan, approval: { id: 'APR-no-authority' } }));
  assert.deepEqual(await f.files.identity(), f.workspace);
  assert.deepEqual(await f.files.pending(), [id]);
  const before = inventory(f.root);
  await assert.rejects(f.files.commit(plan, { id: 'APR-no-authority' }), { code: 'capability-unavailable' });
  await assert.rejects(f.files.commit(sourcePlan, { id: 'APR-no-authority' }), { code: 'capability-unavailable' });
  await assert.rejects(f.files.recover(id, { id: 'APR-no-authority' }), { code: 'capability-unavailable' });
  await assert.rejects(f.files.recordRuntime('evidence', 'EVD-blocked', { sensitive: 'must not write' }), { code: 'capability-unavailable' });
  let entered = false;
  await assert.rejects(f.files.withRuntimeLock(async () => { entered = true; }), { code: 'capability-unavailable' });
  await assert.rejects(withEvidencePruneLock(f.files, f.workspace, digestContent('plan'), async () => { entered = true; }), { code: 'capability-unavailable' });
  await assert.rejects(removePreparedEvidence(f.files, f.workspace, pruneTarget), { code: 'capability-unavailable' });
  assert.equal(entered, false);
  let confirmed = false;
  const authority = await openLocalAuthority({ directory: f.root, transport: {
    channel: 'trusted-callback', protocolIdentity: { id: 'test-only', version: '1' },
    async confirm() { confirmed = true; return 'accept'; },
  } });
  assert.equal(ok(await authority.requestConfirmation(plan.request)).state, 'unavailable');
  assert.equal(ok(await (await TerminalAuthority.open(f.root)).requestConfirmation(plan.request)).state, 'unavailable');
  assert.equal(confirmed, false);
  assert.deepEqual(inventory(f.root), before);
  writeFileSync(target, 'user edit');
  await assert.rejects(f.files.recoveryPlan(id), { code: 'stale-revision' });
  assert.equal(readFileSync(target, 'utf8'), 'user edit');
});

test('new workspace setup is denied before runtime directories or approval receipts are created', windows, async (t) => {
  const f = await fixture(t);
  rmSync(f.runtime);
  const workflow = await LocalWorkflow.open(f.root);
  const plan = await workflow.previewSetup();
  const before = inventory(f.root);
  await assert.rejects(workflow.files.commit(plan, { id: 'APR-caller-json' }), { code: 'capability-unavailable' });
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
function Bind($name, $result, [Type[]]$parameters) {
  $m = $t.DefinePInvokeMethod($name, 'kernel32.dll', 'Public, Static, PinvokeImpl',
    [Reflection.CallingConventions]::Standard, $result, $parameters,
    [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
  $m.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
  $d = [Runtime.InteropServices.DllImportAttribute]
  $m.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new(
    $d.GetConstructor([Type[]]@([string])), [object[]]@('kernel32.dll'),
    [Reflection.FieldInfo[]]@($d.GetField('SetLastError'), $d.GetField('CharSet'), $d.GetField('ExactSpelling')),
    [object[]]@($true, [Runtime.InteropServices.CharSet]::Unicode, $true)))
}
Bind 'CreateFileW' ([IntPtr]) @([string], [uint32], [uint32], [IntPtr], [uint32], [uint32], [IntPtr])
Bind 'FlushFileBuffers' ([bool]) @([IntPtr])
Bind 'CloseHandle' ([bool]) @([IntPtr])
$n = $t.CreateType()
$results = @()
foreach ($access in @([uint32]2147483648, [uint32]1073741824)) {
  foreach ($flags in @([uint32]33554432, [uint32]2181038080)) {
    $h = $n::CreateFileW($p, $access, 7, [IntPtr]::Zero, 3, $flags, [IntPtr]::Zero)
    $opened = $h -ne [IntPtr](-1)
    $openError = if ($opened) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
    $flushed = $false
    $flushError = $null
    if ($opened) {
      try {
        $flushed = $n::FlushFileBuffers($h)
        $flushError = if ($flushed) { 0 } else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
      } finally { if (!$n::CloseHandle($h)) { throw 'CloseHandle failed' } }
    }
    $results += @{access=$access;flags=$flags;opened=$opened;openError=$openError;flushed=$flushed;flushError=$flushError}
  }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`, root);
  t.diagnostic(JSON.stringify({ platform: process.platform, node: process.version, nodeDirectory: { api, result }, nativeDirectory: native }));
  assert.equal(native.length, 4);
  assert.notEqual(result, 'unexpected-success', 'If Node adds directory barriers, requalify the native semantics; do not silently enable effects.');
});
