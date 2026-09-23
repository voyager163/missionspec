import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { linkSync, lstatSync, readFileSync, readdirSync, readlinkSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { LocalWorkspace } from '../dist/adapters/filesystem/local-workspace.js';
import { createAuthorizedJsonlSink } from '../dist/adapters/logging/jsonl.js';
import { serializeDiagnosticEvent } from '../dist/adapters/logging/diagnostics.js';
import { createUserTelemetryPreferenceStore } from '../dist/adapters/telemetry/preferences.js';
import { windowsExecutionAsset, windowsPowerShell } from '../dist/adapters/platform/windows-execution.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { conptyDiagnostic, parseConptyChild, parseConptyDriver } from './fixtures/windows-conpty-protocol.mjs';
import { createPrivateFixtureRoot, powershell, privateEntry, removeFixtureRoot } from './fixtures/windows-private-state.mjs';
import { checkCliProcess, cliProcessDiagnostic, networkGuardSpecifier, parseCliEnvelope } from './fixtures/cli-observability-process.mjs';

const windows = { skip: process.platform !== 'win32', timeout: 720_000 };
const cli = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
const guard = networkGuardSpecifier();
const consoleDriver = fileURLToPath(new URL('./fixtures/windows-conpty.ps1', import.meta.url));
const terminalUrl = new URL('../dist/adapters/authority/terminal.js', import.meta.url).href;
const optOuts = ['NODE_TEST_CONTEXT', 'NODE_ENV', 'CI', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY'];
const configVariables = ['MISSIONSPEC_CONFIG_HOME', 'XDG_CONFIG_HOME', 'HOME', 'USERPROFILE', 'HOMEDRIVE',
  'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'NODE_OPTIONS'];
const reservedPaths = [
  'AppData/Local/MissionSpec/telemetry.sqlite-journal',
  '.missionspec/approvals/APR-00000000-0000-0000-0000-000000000000.revoked.json',
];

function childEnvironment(root, preferences) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (configVariables.includes(key.toUpperCase()) || preferences && optOuts.includes(key.toUpperCase())) delete env[key];
  }
  return Object.assign(env, {
    HOME: root, USERPROFILE: root, HOMEDRIVE: path.parse(root).root.slice(0, 2), HOMEPATH: root.slice(2),
    APPDATA: path.join(root, 'Roaming'), LOCALAPPDATA: path.join(root, 'Local'),
    MISSIONSPEC_CONFIG_HOME: path.join(root, 'preferences'),
  });
}

function fixture(t, preferences = false) {
  const { root, identity } = createPrivateFixtureRoot(reservedPaths);
  t.after(() => removeFixtureRoot(root, identity));
  const env = childEnvironment(root, preferences);
  const spawn = (argv) => {
    const result = spawnSync(process.execPath, ['--import', guard, ...argv], {
      cwd: root, env, encoding: 'utf8', shell: false, windowsHide: true, timeout: 150_000, maxBuffer: 1_048_576,
    });
    checkCliProcess(result);
    if (/optional usage analytics|operation-started|operation-stopped/u.test(result.stderr)) {
      throw new Error(`Unexpected control observation; ${cliProcessDiagnostic(result)}`);
    }
    return { code: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  return {
    root, env, spawn, preferencePath: path.join(root, 'preferences', 'telemetry.sqlite'),
    cli(args) {
      const result = spawn([cli, ...args, '--json']);
      return { ...result, value: parseCliEnvelope(result) };
    },
    conpty(argv, responses) {
      windowsExecutionAsset('windows-console.ps1');
      const result = spawnSync(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', consoleDriver], {
        input: JSON.stringify({
          program: process.execPath, argv: ['--import', guard, ...argv], cwd: root, responses, timeoutMs: 200_000,
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

function tree(root) {
  const info = lstatSync(root, { bigint: true });
  if (info.isSymbolicLink()) return { link: readlinkSync(root), mtime: String(info.mtimeNs) };
  if (!info.isDirectory()) return { bytes: readFileSync(root).toString('base64'), mtime: String(info.mtimeNs) };
  return { mtime: String(info.mtimeNs), entries: Object.fromEntries(
    readdirSync(root).sort().map((name) => [name, tree(path.join(root, name))]),
  ) };
}

function saved(result) {
  assert.equal(result.code, 0);
  assert.equal(result.value.status, 'ok');
  assert.deepEqual(result.value.value, { state: 'saved' });
}

function unavailable(result, reason) {
  assert.equal(result.code, 2);
  assert.equal(result.value.status, 'blocked');
  assert.equal(result.value.error.code, 'capability-unavailable');
  assert.equal(result.value.value.state, 'unavailable');
  if (reason) assert.equal(result.value.value.reason, reason);
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
  const before = tree(f.root);
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
  assert.deepEqual(tree(f.root), before);
});

test('Windows native CLI on/off reopen the dedicated SQLite, preserve disclosure and never migrate mixed settings', windows, async (t) => {
  const f = fixture(t, true);
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
  const before = tree(f.root);
  const status = f.cli(['telemetry', 'status']).value.value;
  assert.equal(status.preference, 'enabled');
  assert.equal(status.disclosureVersion, 1);
  assert.equal(status.configured, false);
  assert.equal(status.eligibleAfterNotice, false);
  assert.equal(f.cli(['telemetry', 'preview']).value.value.delivery, 'not-attempted');
  assert.deepEqual(tree(f.root), before);
  saved(f.cli(['telemetry', 'off']));
  assert.deepEqual(await reopen().read(), { state: 'ready', value: { preference: 'disabled', disclosureVersion: 1 } });
  assert.equal(f.cli(['telemetry', 'status']).value.value.reason, 'opted-out');
  assert.deepEqual(tree(path.join(f.root, 'settings.json')), settings);
  assert.deepEqual(readdirSync(f.root).sort(), ['preferences', 'settings.json']);
  assert.deepEqual(readdirSync(path.dirname(f.preferencePath)), ['telemetry.sqlite']);
});

test('Windows native CLI uses LOCALAPPDATA, isolated profile fallback and explicit XDG without re-ACLing containers', windows, (t) => {
  const f = fixture(t, true);
  delete f.env.MISSIONSPEC_CONFIG_HOME;
  const container = f.env.LOCALAPPDATA;
  const originalAcl = directoryAcl(container, 'ReadAndExecute');
  saved(f.cli(['telemetry', 'off']));
  const local = path.join(container, 'MissionSpec', 'telemetry.sqlite');
  privateEntry(local);
  assert.equal(directoryAcl(container), originalAcl);
  assert.deepEqual(readdirSync(container), ['MissionSpec']);
  f.env.XDG_CONFIG_HOME = path.join(f.root, 'xdg');
  saved(f.cli(['telemetry', 'off']));
  privateEntry(path.join(f.env.XDG_CONFIG_HOME, 'missionspec', 'telemetry.sqlite'));
  delete f.env.XDG_CONFIG_HOME;
  delete f.env.LOCALAPPDATA;
  saved(f.cli(['telemetry', 'off']));
  privateEntry(path.join(f.root, 'AppData', 'Local', 'MissionSpec', 'telemetry.sqlite'));
  assert.deepEqual(readdirSync(f.root).sort(), ['AppData', 'Local', 'xdg']);
});

test('Windows native CLI rejects explicit aliases, junctions and unsafe ACLs without fallback, repair or preference writes', windows, (t) => {
  const f = fixture(t, true);
  const before = tree(f.root);
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
  assert.deepEqual(tree(f.root), before);
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
    const original = tree(f.root);
    f.env.MISSIONSPEC_CONFIG_HOME = child ? path.join(directory, 'MissionSpec') : directory;
    unavailable(f.cli(['telemetry', 'on']), 'io');
    if (!child) unavailable(f.cli(['telemetry', 'status']), 'preference-read-failed');
    assert.equal(directoryAcl(directory), acl);
    assert.deepEqual(tree(f.root), original);
  }
});

test('Windows native CLI preserves foreign databases and hard-linked bytes; hard opt-outs precede invalid-store reads', windows, (t) => {
  const f = fixture(t, true);
  privateEntry(path.dirname(f.preferencePath), true, true);
  privateEntry(f.preferencePath, false, true);
  const database = new DatabaseSync(f.preferencePath);
  try { database.exec("CREATE TABLE unrelated (keep TEXT); INSERT INTO unrelated VALUES ('unchanged')"); }
  finally { database.close(); }
  let before = tree(f.root);
  unavailable(f.cli(['telemetry', 'on']), 'unrecognized-store');
  assert.deepEqual(tree(f.root), before);
  writeFileSync(f.preferencePath, '{"preference":"disabled","keep":"unrecognized"}');
  before = tree(f.root);
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
  assert.deepEqual(tree(f.root), before);
  linkSync(f.preferencePath, path.join(f.root, 'linked.sqlite'));
  before = tree(f.root);
  unavailable(f.cli(['telemetry', 'on']), 'io');
  assert.deepEqual(tree(f.root), before);
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
  const before = tree(f.root);
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
  assert.deepEqual(tree(f.root), before);
  writeFileSync(file, '{"rawEvidence":"never-prune"}\n');
  const noncanonical = tree(f.root);
  unavailable(f.cli(['logs', 'prune', '--preview']), 'io');
  unavailable(f.cli(['logs', 'prune']), 'io');
  assert.deepEqual(tree(f.root), noncanonical);
});

test('Windows native CLI ConPTY pruning binds the exact terminal review and accepts only its current persisted reference', windows, async (t) => {
  const f = fixture(t);
  const { runtime, file, sink, line } = await diagnosticFixture(f);
  const before = tree(f.root);
  const declined = f.conpty([cli, 'logs', 'prune', '--json'], ['decline']);
  assert.equal(declined.challenges, 1);
  assert.notEqual(declined.code, 0);
  assert.equal(cliConsole(declined).error.code, 'authority-required');
  assert.deepEqual(tree(f.root), before);
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
  const changed = tree(f.root);
  unavailable(f.cli(['logs', 'prune', '--approval', receipt.approval.reference.id]), 'authorization-rejected');
  assert.deepEqual(tree(f.root), changed);
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
    assert.deepEqual(tree(path.join(runtime, name)), before.entries['.missionspec'].entries[name]);
  }
  assert.deepEqual(readdirSync(f.root), ['.missionspec']);
  assert.deepEqual(readdirSync(path.dirname(file)), ['diagnostics.jsonl']);
});
