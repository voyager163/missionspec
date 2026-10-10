import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { linkSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { createAuthorizedJsonlSink } from '../dist/adapters/logging/jsonl.js';
import { serializeDiagnosticEvent } from '../dist/adapters/logging/diagnostics.js';
import { createUserTelemetryPreferenceStore } from '../dist/adapters/telemetry/preferences.js';
import { windowsExecutionAsset, windowsPowerShell } from '../dist/adapters/platform/windows-execution.js';
import { windowsPrivateEntries } from '../dist/adapters/platform/windows-private-state.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { conptyDiagnostic, parseConptyChild, parseConptyDriver } from './fixtures/windows-conpty-protocol.mjs';
import { createPrivateFixtureRoot, powershell, privateEntry, removeFixtureRoot } from './fixtures/windows-private-state.mjs';
import { checkCliProcess, cliControlDiagnostic, cliProcessDiagnostic, networkGuardSpecifier, parseCliEnvelope } from './fixtures/cli-observability-process.mjs';
import { observabilityFixtureSnapshot as tree } from './fixtures/cli-observability-files.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
const cli = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
const guard = networkGuardSpecifier();
const nativeDiagnostics = new URL('./fixtures/cli-observability-native-diagnostics.mjs', import.meta.url).href;
const consoleDriver = fileURLToPath(new URL('./fixtures/windows-conpty.ps1', import.meta.url));
const terminalUrl = new URL('../dist/adapters/authority/terminal.js', import.meta.url).href;
const privateStateUrl = new URL('../dist/adapters/platform/windows-private-state.js', import.meta.url).href;
const optOuts = ['NODE_TEST_CONTEXT', 'NODE_ENV', 'CI', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY'];
const configVariables = ['MISSIONSPEC_CONFIG_HOME', 'XDG_CONFIG_HOME', 'HOME', 'USERPROFILE', 'HOMEDRIVE',
  'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'NODE_OPTIONS'];
const reservedPaths = [
  'os-profile/AppData/Local/MissionSpec/telemetry.sqlite-journal',
  'os-profile/AppData/Local/Microsoft/Windows/PowerShell/StartupProfileData-NonInteractive',
  'project/.missionspec/approvals/APR-00000000-0000-0000-0000-000000000000.revoked.json',
];

function childEnvironment(profile, user, preferences) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (configVariables.includes(key.toUpperCase()) || preferences && optOuts.includes(key.toUpperCase())) delete env[key];
  }
  return Object.assign(env, {
    HOME: profile, USERPROFILE: profile, HOMEDRIVE: path.parse(profile).root.slice(0, 2), HOMEPATH: profile.slice(2),
    APPDATA: path.join(profile, 'AppData', 'Roaming'), LOCALAPPDATA: path.join(profile, 'AppData', 'Local'),
    MISSIONSPEC_CONFIG_HOME: path.join(user, 'preferences'),
  });
}

function fixture(t, preferences = false) {
  const sandbox = createPrivateFixtureRoot(reservedPaths);
  const root = path.join(sandbox.root, 'project');
  const user = path.join(sandbox.root, 'user');
  const profile = path.join(sandbox.root, 'os-profile');
  const foreign = new Map();
  t.after(() => {
    try { for (const [filename, before] of foreign) assert.deepEqual(tree(filename), before); }
    finally { removeFixtureRoot(sandbox.root, sandbox.identity); }
  });
  const directories = ['project', 'user', 'os-profile', 'os-profile/AppData', 'os-profile/AppData/Local',
    'os-profile/AppData/Roaming', 'os-profile/AppData/Local/Microsoft', 'os-profile/AppData/Local/Microsoft/Windows',
    'os-profile/AppData/Local/Microsoft/Windows/PowerShell', 'os-profile/AppData/Local/Microsoft/Windows/Caches'];
  for (let index = 0; index < directories.length; index += 8) {
    windowsPrivateEntries(directories.slice(index, index + 8).map((relative) => ({
      path: path.join(sandbox.root, relative), directory: true, writable: true, create: true,
    })));
  }
  const consoleCaches = path.join(profile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Caches');
  const emptyCaches = tree(consoleCaches);
  assert.deepEqual(emptyCaches.entries, {});
  foreign.set(consoleCaches, emptyCaches);
  for (const container of [user, profile]) {
    const filename = path.join(container, 'foreign-settings.json');
    privateFile(filename, '{"unrelated":"retain-exactly"}\n');
    foreign.set(filename, tree(filename));
  }
  const env = childEnvironment(profile, user, preferences);
  const spawn = (argv) => {
    const result = spawnSync(process.execPath, ['--import', guard, '--import', nativeDiagnostics, ...argv], {
      cwd: root, env, encoding: 'utf8', shell: false, windowsHide: true, timeout: 150_000, maxBuffer: 1_048_576,
    });
    checkCliProcess(result);
    if (/optional usage analytics|operation-started|operation-stopped/u.test(result.stderr)) {
      throw new Error(`Unexpected control observation; ${cliProcessDiagnostic(result)}`);
    }
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  const home = spawn(['--input-type=module', '-e', `
    import { homedir } from 'node:os';
    console.log(homedir() === process.env.USERPROFILE ? 'ISOLATED_PROFILE' : 'PROFILE_MISMATCH');
  `]);
  if (home.code !== 0 || home.stdout.trim() !== 'ISOLATED_PROFILE') throw new Error('Node did not select the isolated OS profile');
  const warmup = spawn(['--input-type=module', '-e', `
    const { windowsPrivateEntries } = await import(${JSON.stringify(privateStateUrl)});
    windowsPrivateEntries([{ path: process.env.USERPROFILE, directory: true, writable: true }]);
    console.log('OS_RUNTIME_READY');
  `]);
  if (warmup.code !== 0 || warmup.stdout.trim() !== 'OS_RUNTIME_READY') {
    throw new Error(`Isolated OS runtime warmup failed; ${cliControlDiagnostic(warmup)}`);
  }
  const snapshot = () => tree(sandbox.root, { profile });
  snapshot();
  t.diagnostic('Isolated project/user state and warmed disposable OS profile; only the exact 64-byte PowerShell startup-cache content/mtime may change.');
  return {
    root, user, profile, env, spawn, snapshot, preferencePath: path.join(user, 'preferences', 'telemetry.sqlite'),
    fallbackPreferencePath: path.join(profile, 'AppData', 'Local', 'MissionSpec', 'telemetry.sqlite'),
    cli(args) {
      const result = spawn([cli, ...args, '--json']);
      return { ...result, value: parseCliEnvelope(result) };
    },
    conpty(argv, responses) {
      windowsExecutionAsset('windows-console.ps1');
      const result = spawnSync(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', consoleDriver], {
        input: JSON.stringify({
          program: process.execPath, argv: ['--import', guard, '--import', nativeDiagnostics, ...argv], cwd: root, responses, timeoutMs: 200_000,
        }),
        cwd: root, env, encoding: 'utf8', shell: false, windowsHide: true, timeout: 220_000, maxBuffer: 12_000_000,
      });
      const response = parseConptyDriver(result);
      checkCliProcess(response);
      assert.equal(response.parentKilled, false);
      if (argv[0] === cli) parseCliEnvelope(response, true);
      else {
        if (response.code !== 0) throw new Error(`CLI receipt child failed; ${cliProcessDiagnostic(response)}`);
        parseConptyChild(response);
      }
      return response;
    },
  };
}

function saved(result, location = 'explicit-preference') {
  const diagnostic = `${location}: ${cliControlDiagnostic(result)}`;
  assert.equal(result.code, 0, diagnostic);
  assert.equal(result.value.status, 'ok', diagnostic);
  assert.deepEqual(result.value.value, { state: 'saved' }, diagnostic);
}

function unavailable(result, reason) {
  const diagnostic = cliControlDiagnostic(result);
  assert.equal(result.code, 2, diagnostic);
  assert.equal(result.value.status, 'blocked', diagnostic);
  assert.equal(result.value.error.code, 'capability-unavailable', diagnostic);
  assert.equal(result.value.value.state, 'unavailable', diagnostic);
  if (reason) assert.equal(result.value.value.reason, reason, diagnostic);
}

function privateFile(filename, content) {
  privateEntry(filename, false, true);
  writeFileSync(filename, content);
}

function directoryAcl(filename, publicRights) {
  return powershell(String.raw`
$ErrorActionPreference = 'Stop'
$v = [Console]::In.ReadToEnd() | ConvertFrom-Json
$sections = [Security.AccessControl.AccessControlSections]'Owner, Group, Access'
if ($null -ne $v.publicRights) {
  if ([IO.Directory]::Exists($v.path) -or [IO.File]::Exists($v.path)) { throw 'Fixture creation must be exclusive' }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-1-0'), $v.publicRights, 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
  [void][IO.Directory]::CreateDirectory($v.path, $acl)
}
$sddl = [IO.Directory]::GetAccessControl($v.path, $sections).GetSecurityDescriptorSddlForm($sections)
[Console]::Out.Write((@{sddl=$sddl} | ConvertTo-Json -Compress))
`, { path: filename, ...(publicRights === undefined ? {} : { publicRights }) }).sddl;
}

test('Windows native CLI read-only controls, help and capabilities create no preferences, project state or notice', windows, (t) => {
  const f = fixture(t, true);
  const before = f.snapshot();
  const status = f.cli(['telemetry', 'status']);
  assert.equal(status.code, 0);
  assert.equal(status.value.value.preference, 'default');
  assert.equal(status.value.value.reason, 'not-configured');
  assert.equal(status.value.value.configured, false);
  const preview = f.cli(['telemetry', 'preview']);
  assert.equal(preview.code, 0);
  assert.equal(preview.value.value.delivery, 'not-attempted');
  assert.equal(preview.value.value.event.os, 'windows');
  assert.deepEqual(Object.keys(preview.value.value.event), [
    'schemaVersion', 'event', 'operation', 'cliVersion', 'outcome', 'host', 'os', 'durationBucket',
  ]);
  assert.deepEqual(f.cli(['logs', 'prune', '--preview']).value.value, { state: 'absent' });
  assert.equal(f.cli(['capabilities']).code, 0);
  assert.equal(f.spawn([cli, '--help']).code, 0);
  assert.equal(f.spawn([cli, '--version']).code, 0);
  assert.deepEqual(f.snapshot(), before);
});

test('Windows native CLI on/off reopen the dedicated SQLite, preserve disclosure and never migrate mixed settings', windows, async (t) => {
  const f = fixture(t, true);
  const profileBefore = tree(f.profile, { profile: f.profile });
  privateFile(path.join(f.root, 'settings.json'), '{"telemetry":false,"unrelated":"keep"}');
  const settings = tree(path.join(f.root, 'settings.json'));
  f.env.XDG_CONFIG_HOME = 'invalid-lower-precedence';
  f.env.LOCALAPPDATA = 'also-invalid';
  saved(f.cli(['telemetry', 'off']));
  assert.equal(readFileSync(f.preferencePath).subarray(0, 16).toString('binary'), 'SQLite format 3\0');
  privateEntry(path.dirname(f.preferencePath), true);
  privateEntry(f.preferencePath);
  const reopen = () => createUserTelemetryPreferenceStore(f.preferencePath, { ownership: 'missionspec-telemetry-only' });
  assert.deepEqual(await reopen().read(), { state: 'ready', value: { preference: 'disabled' } });
  assert.deepEqual(await reopen().save({ disclosureVersion: 1 }), { state: 'saved' });
  saved(f.cli(['telemetry', 'on', '--no-telemetry']));
  assert.deepEqual(await reopen().read(), { state: 'ready', value: { preference: 'enabled', disclosureVersion: 1 } });
  const before = f.snapshot();
  const status = f.cli(['telemetry', 'status']).value.value;
  assert.equal(status.preference, 'enabled');
  assert.equal(status.disclosureVersion, 1);
  assert.equal(status.configured, false);
  assert.equal(status.eligibleAfterNotice, false);
  assert.equal(f.cli(['telemetry', 'preview']).value.value.delivery, 'not-attempted');
  assert.deepEqual(f.snapshot(), before);
  saved(f.cli(['telemetry', 'off']));
  assert.deepEqual(await reopen().read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  assert.equal(f.cli(['telemetry', 'status']).value.value.reason, 'opted-out');
  assert.deepEqual(tree(path.join(f.root, 'settings.json')), settings);
  assert.deepEqual(readdirSync(f.root), ['settings.json']);
  assert.deepEqual(readdirSync(f.user).sort(), ['foreign-settings.json', 'preferences']);
  assert.deepEqual(readdirSync(path.dirname(f.preferencePath)), ['telemetry.sqlite']);
  assert.deepEqual(tree(f.profile, { profile: f.profile }), profileBefore);
});

test('Windows native CLI uses LOCALAPPDATA, isolated profile fallback and explicit XDG without re-ACLing containers', windows, (t) => {
  const f = fixture(t, true);
  const profileBefore = tree(f.profile, { profile: f.profile });
  delete f.env.MISSIONSPEC_CONFIG_HOME;
  const container = path.join(f.user, 'Local');
  const originalAcl = directoryAcl(container, 'ReadAndExecute');
  f.env.LOCALAPPDATA = container;
  saved(f.cli(['telemetry', 'off']), 'local-app-data');
  const local = path.join(container, 'MissionSpec', 'telemetry.sqlite');
  privateEntry(local);
  assert.equal(directoryAcl(container), originalAcl);
  assert.deepEqual(readdirSync(container), ['MissionSpec']);
  f.env.XDG_CONFIG_HOME = path.join(f.user, 'xdg');
  saved(f.cli(['telemetry', 'off']), 'xdg');
  privateEntry(path.join(f.env.XDG_CONFIG_HOME, 'missionspec', 'telemetry.sqlite'));
  assert.deepEqual(tree(f.profile, { profile: f.profile }), profileBefore);
  delete f.env.XDG_CONFIG_HOME;
  delete f.env.LOCALAPPDATA;
  privateEntry(path.join(f.profile, 'AppData', 'Local'), true);
  const before = f.snapshot();
  const absent = f.cli(['telemetry', 'status']);
  assert.equal(absent.code, 0, cliControlDiagnostic(absent));
  assert.equal(absent.value.value.preference, 'default');
  assert.deepEqual(f.snapshot(), before);
  saved(f.cli(['telemetry', 'off']), 'profile-fallback');
  privateEntry(f.fallbackPreferencePath);
  const savedFallback = f.snapshot();
  assert.equal(f.cli(['telemetry', 'status']).value.value.preference, 'disabled');
  assert.deepEqual(f.snapshot(), savedFallback);
  assert.deepEqual(readdirSync(path.dirname(f.fallbackPreferencePath)), ['telemetry.sqlite']);
  assert.deepEqual(readdirSync(f.root), []);
  assert.deepEqual(readdirSync(f.user).sort(), ['Local', 'foreign-settings.json', 'xdg']);
});

test('Windows native CLI rejects explicit aliases, junctions and unsafe ACLs without fallback, repair or preference writes', windows, (t) => {
  const f = fixture(t, true);
  const before = f.snapshot();
  for (const value of ['', 'relative', 'C:relative', '\\\\server\\share\\preferences', `\\\\?\\${f.root}`,
    `${f.root}\\parent\\..\\preferences`, `${f.root}\\preferences.`, `${f.root}\\preferences `,
    `${f.root}\\preferences:stream`, `${f.root[0].toLowerCase()}${f.root.slice(1)}\\preferences`]) {
    f.env.MISSIONSPEC_CONFIG_HOME = value;
    unavailable(f.cli(['telemetry', 'on']), 'io');
  }
  delete f.env.MISSIONSPEC_CONFIG_HOME;
  f.env.XDG_CONFIG_HOME = 'relative-xdg';
  unavailable(f.cli(['telemetry', 'off']), 'io');
  delete f.env.XDG_CONFIG_HOME;
  f.env.LOCALAPPDATA = '';
  unavailable(f.cli(['telemetry', 'off']), 'io');
  assert.deepEqual(f.snapshot(), before);
  const target = path.join(f.root, 'target');
  privateEntry(target, true, true);
  const junction = path.join(f.root, 'junction');
  symlinkSync(target, junction, 'junction');
  f.env.MISSIONSPEC_CONFIG_HOME = path.join(junction, 'child');
  unavailable(f.cli(['telemetry', 'off']), 'io');
  assert.deepEqual(readdirSync(target), []);
  for (const [name, rights, child] of [['public-leaf', 'ReadAndExecute', false], ['unsafe-parent', 'Modify', true]]) {
    const directory = path.join(f.root, name);
    const acl = directoryAcl(directory, rights);
    const original = f.snapshot();
    f.env.MISSIONSPEC_CONFIG_HOME = child ? path.join(directory, 'MissionSpec') : directory;
    unavailable(f.cli(['telemetry', 'on']), 'io');
    if (!child) unavailable(f.cli(['telemetry', 'status']), 'preference-read-failed');
    assert.equal(directoryAcl(directory), acl);
    assert.deepEqual(f.snapshot(), original);
  }
});

test('Windows native CLI preserves foreign databases and hard-linked bytes; hard opt-outs precede invalid-store reads', windows, (t) => {
  const f = fixture(t, true);
  privateEntry(path.dirname(f.preferencePath), true, true);
  privateEntry(f.preferencePath, false, true);
  const database = new DatabaseSync(f.preferencePath);
  try { database.exec("CREATE TABLE unrelated (keep TEXT); INSERT INTO unrelated VALUES ('unchanged')"); }
  finally { database.close(); }
  let before = f.snapshot();
  unavailable(f.cli(['telemetry', 'on']), 'unrecognized-store');
  assert.deepEqual(f.snapshot(), before);
  writeFileSync(f.preferencePath, '{"preference":"disabled","keep":"unrecognized"}');
  before = f.snapshot();
  unavailable(f.cli(['telemetry', 'off']), 'unrecognized-store');
  unavailable(f.cli(['telemetry', 'status']), 'preference-read-failed');
  for (const [variable, value] of [['MISSIONSPEC_TELEMETRY', '0'], ['DO_NOT_TRACK', '1'], ['CI', 'true'],
    ['NODE_TEST_CONTEXT', 'child-v8'], ['NODE_ENV', 'test']]) {
    f.env[variable] = value;
    const status = f.cli(['telemetry', 'status']);
    assert.equal(status.code, 0);
    assert.equal(status.value.value.preference, 'not-read');
    assert.equal(status.value.value.reason, 'opted-out');
    delete f.env[variable];
  }
  assert.equal(f.cli(['telemetry', 'status', '--no-telemetry']).value.value.preference, 'not-read');
  assert.deepEqual(f.snapshot(), before);
  linkSync(f.preferencePath, path.join(f.root, 'linked.sqlite'));
  before = f.snapshot();
  unavailable(f.cli(['telemetry', 'on']), 'io');
  assert.deepEqual(f.snapshot(), before);
});

async function diagnosticFixture(f) {
  const runtime = path.join(f.root, '.missionspec');
  privateEntry(runtime, true, true);
  privateEntry(path.join(runtime, 'logs'), true, true);
  const files = await LocalWorkspace.open(f.root);
  privateFile(path.join(runtime, 'workspace.json'), JSON.stringify({
    workspaceId: `WSP-${randomUUID()}`, rootDigest: files.rootDigest,
  }));
  for (const name of ['ledger.sqlite', 'evidence.jsonl', 'grants.json']) privateFile(path.join(runtime, name), `retained-${name}\n`);
  const file = path.join(runtime, 'logs', 'diagnostics.jsonl');
  const sink = createAuthorizedJsonlSink(file);
  const line = serializeDiagnosticEvent({
    contractVersion: 1, operation: 'draft', engine: 'specification',
    severity: 'information', code: 'operation-stopped', errorCode: null, elapsedMilliseconds: 3,
  }, '2026-09-20T00:00:00.000Z');
  await sink.write(line);
  return { runtime, file, sink, line };
}

function cliConsole(response) {
  return parseCliEnvelope(response, true);
}

test('Windows native CLI diagnostic preview and rejected non-TTY pruning preserve every file and mtime', windows, async (t) => {
  const f = fixture(t);
  const { file } = await diagnosticFixture(f);
  const before = f.snapshot();
  const preview = f.cli(['logs', 'prune', '--preview']);
  assert.equal(preview.code, 0);
  assert.equal(preview.value.value.path, file);
  assert.equal(preview.value.value.scope, 'local-diagnostics-only');
  assert.equal(preview.value.value.bytes, readFileSync(file).length);
  assert.doesNotMatch(preview.stdout, /operation-stopped|retained-/u);
  const unapproved = f.cli(['logs', 'prune']);
  assert.notEqual(unapproved.code, 0);
  assert.equal(unapproved.value.error.code, 'authority-required');
  unavailable(f.cli(['logs', 'prune', '--approval', 'APR-client-claim']), 'authorization-rejected');
  assert.notEqual(f.cli(['logs', 'prune', '--approved']).code, 0);
  assert.deepEqual(f.snapshot(), before);
  writeFileSync(file, '{"rawEvidence":"never-prune"}\n');
  const noncanonical = f.snapshot();
  unavailable(f.cli(['logs', 'prune', '--preview']), 'io');
  unavailable(f.cli(['logs', 'prune']), 'io');
  assert.deepEqual(f.snapshot(), noncanonical);
});

test('Windows native CLI ConPTY pruning binds the exact terminal review and accepts only its current persisted reference', windows, async (t) => {
  const f = fixture(t);
  const { runtime, file, sink, line } = await diagnosticFixture(f);
  const before = f.snapshot();
  const declined = f.conpty([cli, 'logs', 'prune', '--json'], ['decline']);
  assert.equal(declined.challenges, 1);
  assert.notEqual(declined.code, 0);
  assert.equal(cliConsole(declined).error.code, 'authority-required');
  assert.deepEqual(f.snapshot(), before);
  const preview = f.cli(['logs', 'prune', '--preview']).value.value;
  const accepted = f.conpty([cli, 'logs', 'prune', '--json'], ['accept']);
  assert.equal(accepted.code, 0, conptyDiagnostic(accepted));
  assert.equal(accepted.challenges, 1);
  assert.deepEqual(cliConsole(accepted).value, { state: 'pruned' });
  assert.match(accepted.output, /no organization or tamper-proof assurance/u);
  assert.equal(readFileSync(file).length, 0);
  const approvals = path.join(runtime, 'approvals');
  assert.equal(readdirSync(approvals).length, 1);
  const receipt = JSON.parse(readFileSync(path.join(approvals, readdirSync(approvals)[0]), 'utf8'));
  assert.equal(receipt.approval.assurance.channel, 'terminal-confirmation');
  assert.equal(receipt.approval.assurance.humanPresence, 'not-attested');
  assert.deepEqual(receipt.display.detail.preview, preview);
  assert.deepEqual(receipt.display.detail.excludes, ['runtime-ledger', 'approvals', 'evidence']);
  assert.deepEqual(receipt.approval.request.effects, [{
    kind: 'file-write', purpose: 'configuration', path: '.missionspec/logs/diagnostics.jsonl',
    expected: digestContent(line), proposed: digestContent(''),
  }]);
  await sink.write(line);
  const changed = f.snapshot();
  unavailable(f.cli(['logs', 'prune', '--approval', receipt.approval.reference.id]), 'authorization-rejected');
  assert.deepEqual(f.snapshot(), changed);
  const current = f.cli(['logs', 'prune', '--preview']).value.value;
  const request = {
    ...receipt.approval.request,
    binding: { ...receipt.approval.request.binding,
      revision: digestContent(JSON.stringify({ action: 'prune-local-diagnostics', preview: current })) },
  };
  const issued = f.conpty(['--input-type=module', '-e', `
    const { TerminalAuthority } = await import(${JSON.stringify(terminalUrl)});
    const authority = await TerminalAuthority.open(process.cwd());
    const result = await authority.requestConfirmation(JSON.parse(process.argv[1]), {
      action: 'prune-local-diagnostics', preview: JSON.parse(process.argv[2]), effect: 'truncate-to-empty',
      excludes: ['runtime-ledger', 'approvals', 'evidence'],
    });
    if (result.status !== 'ok' || result.value.state !== 'issued') throw new Error('Terminal receipt was not issued');
    console.log('\\nWINDOWS_CONSOLE_RESULT:' + JSON.stringify({
      state: result.value.state, reference: result.value.approval.reference,
      channel: result.value.approval.assurance.channel,
    }));
  `, JSON.stringify(request), JSON.stringify(current)], ['accept']);
  assert.equal(issued.challenges, 1);
  const approval = parseConptyChild(issued);
  assert.equal(approval.state, 'issued');
  assert.equal(approval.channel, 'terminal-confirmation');
  const persisted = f.cli(['logs', 'prune', '--approval', approval.reference.id]);
  assert.equal(persisted.code, 0);
  assert.deepEqual(persisted.value.value, { state: 'pruned' });
  assert.equal(readFileSync(file).length, 0);
  for (const name of ['workspace.json', 'ledger.sqlite', 'evidence.jsonl', 'grants.json']) {
    assert.deepEqual(tree(path.join(runtime, name)), before.entries.project.entries['.missionspec'].entries[name]);
  }
  assert.deepEqual(readdirSync(f.root), ['.missionspec']);
  assert.deepEqual(readdirSync(path.dirname(file)), ['diagnostics.jsonl']);
  const after = f.snapshot();
  assert.deepEqual(Object.keys(after.entries), Object.keys(before.entries));
  for (const name of ['user', 'os-profile']) assert.deepEqual(after.entries[name], before.entries[name]);
});
