import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, link, lstat, mkdir, readFile, readdir, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { promisify } from 'node:util';
import test from 'node:test';
import { createAuthorizedJsonlSink } from '../dist/adapters/logging/jsonl.js';
import { serializeDiagnosticEvent } from '../dist/adapters/logging/diagnostics.js';
import { createUserTelemetryPreferenceStore } from '../dist/adapters/telemetry/preferences.js';
import { digestContent } from '../dist/kernel/revisions.js';
import { checkCliProcess, cliControlDiagnostic, cliProcessDiagnostic, networkGuardSpecifier, parseCliEnvelope } from './fixtures/cli-observability-process.mjs';
import { observabilityFixtureSnapshot, powerShellStartupCache } from './fixtures/cli-observability-files.mjs';

const exec = promisify(execFile);
const moduleUrl = new URL('../dist/cli/observability.js', import.meta.url).href;
const errorsUrl = new URL('../dist/application/errors.js', import.meta.url).href;
const authorityUrl = new URL('../dist/adapters/authority/terminal.js', import.meta.url).href;
const localAuthorityUrl = new URL('../dist/adapters/authority/local-authority.js', import.meta.url).href;
const driver = path.resolve('tests/fixtures/terminal-driver.py');
const networkGuard = networkGuardSpecifier();
const nativeDiagnostics = new URL('./fixtures/cli-observability-native-diagnostics.mjs', import.meta.url).href;
const cli = path.resolve('dist/cli/main.js');
const commandSource = `
  const { runObservabilityCommand } = await import(${JSON.stringify(moduleUrl)});
  try {
    const result = await runObservabilityCommand(JSON.parse(process.argv[1]), JSON.parse(process.argv[2]));
    console.log('OBS:' + JSON.stringify({ result }));
  } catch (error) { console.log('OBS:' + JSON.stringify({ error: { code: error.code, name: error.name, message: error.message } })); }
`;
const posix = ['darwin', 'linux'].includes(process.platform);
const options = { skip: !posix && 'POSIX CLI fixtures; Windows has a separate native suite.' };

test('CLI preload specifiers stay file URLs and the real guard blocks caught HTTP, HTTPS and fetch attempts', () => {
  assert.equal(new URL(networkGuard).protocol, 'file:');
  assert.equal(networkGuardSpecifier('file:///D:/a/check%20out/tests/fixtures/process.mjs'),
    'file:///D:/a/check%20out/tests/fixtures/cli-observability-network-guard.mjs');
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.toUpperCase() === 'NODE_OPTIONS') delete env[key];
  const launch = (specifier, source) => spawnSync(process.execPath,
    ['--import', specifier, '--import', nativeDiagnostics, '--input-type=module', '-e', source],
    { env, encoding: 'utf8', shell: false, timeout: 15_000, maxBuffer: 65_536 });
  const ready = launch(networkGuard, 'console.log(JSON.stringify({ contractVersion: 1, status: "ok", value: "guard-loaded" }))');
  assert.equal(parseCliEnvelope(ready).value, 'guard-loaded');
  for (const source of [
    "import { request } from 'node:http'; try { request('http://telemetry.invalid'); } catch {}",
    "import { request } from 'node:https'; try { request('https://telemetry.invalid'); } catch {}",
    "try { await fetch('https://telemetry.invalid'); } catch {}",
  ]) {
    const blocked = launch(networkGuard, source);
    assert.equal(blocked.status, 98, cliProcessDiagnostic(blocked));
    assert.throws(() => checkCliProcess(blocked), /CLI child network-attempt; exit=98/u);
  }
  const rawDrivePath = launch(String.raw`D:\not-a-user\cli-observability-network-guard.mjs`, 'console.log("must-not-run")');
  assert.match(cliProcessDiagnostic(rawDrivePath), /exit=1; node=ERR_UNSUPPORTED_ESM_URL_SCHEME/u);
  assert.throws(() => parseCliEnvelope(rawDrivePath), /startup-or-exit-failure.*ERR_UNSUPPORTED_ESM_URL_SCHEME/u);
});

test('CLI startup diagnostics precede envelope parsing and console assertions without exposing raw output', () => {
  const sentinel = 'PRIVATE_ENV_PATH_MUST_NOT_LEAK';
  const cases = [
    { code: 1, stdout: '', stderr: `Error [ERR_UNSUPPORTED_ESM_URL_SCHEME]: ${sentinel}` },
    { code: 1, challenges: 0, output: `Error [ERR_MODULE_NOT_FOUND]: ${sentinel}` },
    { code: 1, stdout: sentinel, stderr: sentinel },
    { code: 0, stdout: JSON.stringify({ status: 'ok', value: sentinel }) },
    { status: null, stdout: '', error: { code: 'ETIMEDOUT', message: sentinel } },
    { code: 98, stdout: '', stderr: sentinel },
  ];
  for (const result of cases) {
    assert.throws(() => parseCliEnvelope(result, result.output !== undefined), (error) => {
      assert.match(error.message, /^CLI child /u);
      assert.doesNotMatch(error.message, new RegExp(sentinel, 'u'));
      assert(error.message.length < 512);
      return true;
    });
  }
  const envelope = { contractVersion: 1, status: 'blocked', error: { code: 'authority-required' } };
  const serialized = JSON.stringify(envelope);
  assert.deepEqual(parseCliEnvelope({
    code: 2, challenges: 1, output: `Exact console review\n${serialized.slice(0, 45)}\r\n${serialized.slice(45)}\r\n`,
  }, true), envelope);
  assert.throws(() => parseCliEnvelope({ code: 0, stdout: serialized }), /invalid-envelope/u);
  const failure = cliControlDiagnostic({
    code: 2, stdout: '', stderr: `CLI_NATIVE_FAILURE:${JSON.stringify({
      native: `create; phase=creation; boundary=ancestor; line=331; unrelated=${sentinel}`,
    })}\n`,
    value: { status: 'blocked', value: { state: 'unavailable', reason: 'io', persistence: 'unchanged', cleanup: 'complete', secret: sentinel } },
  });
  assert.match(failure, /state=unavailable; reason=io; persistence=unchanged; cleanup=complete/u);
  assert.match(failure, /native=create; phase=creation; boundary=ancestor; line=331/u);
  assert.doesNotMatch(failure, new RegExp(sentinel, 'u'));
});

test('isolated profile snapshots exempt only the exact bounded OS cache, never user files or other metadata', async (t) => {
  const f = await fixture(t);
  const profile = path.join(f.root, 'os-profile');
  const cache = powerShellStartupCache(profile);
  await mkdir(path.dirname(cache), { recursive: true, mode: 0o700 });
  await writeFile(cache, Buffer.alloc(64, 1), { mode: 0o600 });
  const foreign = path.join(profile, 'foreign-settings.json');
  await writeFile(foreign, '{"keep":true}', { mode: 0o600 });
  const snapshot = () => observabilityFixtureSnapshot(f.root, { profile });
  const before = snapshot();
  await writeFile(cache, Buffer.alloc(64, 2));
  await utimes(cache, new Date('2020-01-01T00:00:00Z'), new Date('2020-01-01T00:00:00Z'));
  assert.deepEqual(snapshot(), before);
  await writeFile(foreign, '{"keep":false}');
  assert.notDeepEqual(snapshot(), before);
  const changed = snapshot();
  await chmod(foreign, 0o444);
  assert.notDeepEqual(snapshot(), changed);
  await chmod(foreign, 0o600);
  const withMode = snapshot();
  await writeFile(path.join(path.dirname(cache), 'unexpected-state'), 'must be detected');
  assert.notDeepEqual(snapshot(), withMode);
  await writeFile(cache, Buffer.alloc(65));
  assert.throws(snapshot, /Unexpected PowerShell startup-cache type, links or size/u);
  await rm(cache);
  await link(foreign, cache);
  assert.throws(snapshot, /Unexpected PowerShell startup-cache type, links or size/u);
});

async function fixture(t, extraEnv = {}) {
  const root = path.resolve(`.cli-observability-test-${randomUUID()}`);
  await mkdir(root, { mode: 0o700 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const env = { ...process.env };
  for (const name of ['NODE_TEST_CONTEXT', 'NODE_ENV', 'CI', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY',
    'MISSIONSPEC_CONFIG_HOME', 'XDG_CONFIG_HOME']) delete env[name];
  Object.assign(env, { HOME: root, MISSIONSPEC_CONFIG_HOME: path.join(root, 'preferences') }, extraEnv);
  const run = async (source, args = [], tty) => {
    const invocation = ['--import', networkGuard, '--input-type=module', '-e', source, ...args];
    const output = tty === undefined
      ? await exec(process.execPath, invocation, { cwd: root, env, maxBuffer: 10_000_000 })
      : await exec('python3', [driver, tty, root, process.execPath, ...invocation], { env, maxBuffer: 10_000_000 });
    if (tty !== undefined) return JSON.parse(output.stdout);
    return output;
  };
  const decode = (text) => JSON.parse(text.split(/\r?\n/u).findLast((line) => line.startsWith('OBS:')).slice(4));
  return {
    root, env, run, decode,
    preferencePath: path.join(root, 'preferences/telemetry.sqlite'),
    async command(positionals, values = {}, tty) {
      const result = await run(commandSource, [JSON.stringify(positionals), JSON.stringify(values)], tty);
      return tty === undefined ? { ...decode(result.stdout), stderr: result.stderr } : { ...result, ...decode(result.output) };
    },
    async initialize() {
      const { stdout } = await exec('python3', [driver, 'confirm', root, process.execPath, '--import', networkGuard, cli, 'init', '--json'],
        { env, maxBuffer: 10_000_000 });
      const result = JSON.parse(stdout);
      assert.equal(result.code, 0, result.output);
      assert.equal(result.confirmations, 1);
    },
  };
}

async function tree(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const result = {};
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(root, entry.name);
    const info = await lstat(full);
    result[entry.name] = entry.isDirectory() ? await tree(full) :
      { content: (await readFile(full)).toString('base64'), mtime: info.mtimeMs, mode: info.mode };
  }
  return result;
}

async function log(f) {
  const directory = path.join(f.root, '.missionspec/logs');
  await mkdir(directory, { mode: 0o700 });
  const file = path.join(directory, 'diagnostics.jsonl');
  const sink = createAuthorizedJsonlSink(file);
  await sink.write(serializeDiagnosticEvent({
    contractVersion: 1, operation: 'draft', engine: 'specification',
    severity: 'information', code: 'operation-stopped', errorCode: null, elapsedMilliseconds: 3,
  }, '2026-09-20T00:00:00.000Z'));
  return { file, sink };
}

test('status, representative preview and absent log preview do not initialize any state or log', options, async (t) => {
  const f = await fixture(t);
  const before = await tree(f.root);
  const status = await f.command(['telemetry', 'status']);
  assert.equal(status.result.reason, 'not-configured');
  assert.equal(status.result.preference, 'default');
  assert.equal(status.result.configured, false);
  const preview = await f.command(['telemetry', 'preview']);
  assert.equal(preview.result.delivery, 'not-attempted');
  assert.deepEqual(Object.keys(preview.result.event), [
    'schemaVersion', 'event', 'operation', 'cliVersion', 'outcome', 'host', 'os', 'durationBucket',
  ]);
  assert.equal(preview.result.event.outcome, 'unknown');
  assert.deepEqual((await f.command(['logs', 'prune'], { preview: true })).result, { state: 'absent' });
  assert.deepEqual(await tree(f.root), before);
  for (const output of [status.stderr, preview.stderr]) assert.doesNotMatch(output, /operation-started|operation-stopped/u);
});

test('the CLI child network guard cannot hide a caught delivery attempt', options, async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.run(`
    import { request } from 'node:https';
    try { request('https://telemetry.invalid'); } catch {}
  `), (error) => error.code === 98 && error.stdout === '' && error.stderr === '');
  assert.deepEqual(await readdir(f.root), []);
});

test('explicit on/off persist real dedicated SQLite without touching mixed settings or acknowledging disclosure', options, async (t) => {
  const f = await fixture(t);
  await writeFile(path.join(f.root, 'settings.json'), '{"telemetry":false,"unrelated":"keep"}');
  const original = await readFile(path.join(f.root, 'settings.json'));
  assert.deepEqual((await f.command(['telemetry', 'off'])).result, { state: 'saved' });
  assert.equal((await readFile(f.preferencePath)).subarray(0, 16).toString('binary'), 'SQLite format 3\0');
  assert.equal((await lstat(f.preferencePath)).mode & 0o777, 0o600);
  const store = createUserTelemetryPreferenceStore(f.preferencePath, { ownership: 'missionspec-telemetry-only' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'disabled' } });
  assert.equal((await f.command(['telemetry', 'status'])).result.reason, 'opted-out');
  assert.deepEqual(await store.save({ disclosureVersion: 1 }), { state: 'saved' });
  assert.deepEqual((await f.command(['telemetry', 'on'])).result, { state: 'saved' });
  assert.deepEqual(await store.read(), { state: 'ready', value: { preference: 'enabled', disclosureVersion: 1 } });
  const status = (await f.command(['telemetry', 'status'])).result;
  assert.equal(status.reason, 'not-configured');
  assert.equal(status.eligibleAfterNotice, false);
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'saved');
  assert.deepEqual(await readFile(path.join(f.root, 'settings.json')), original);
  assert.deepEqual((await store.read()).value, { preference: 'disabled', disclosureVersion: 1 });
  assert.equal((await readdir(f.root)).includes('.missionspec'), false);
});

test('default user-local location is stable and respects explicit XDG ownership', options, async (t) => {
  const f = await fixture(t);
  delete f.env.MISSIONSPEC_CONFIG_HOME;
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'saved');
  const defaultPath = process.platform === 'darwin' ? 'Library/Application Support/MissionSpec/telemetry.sqlite' :
    '.config/missionspec/telemetry.sqlite';
  assert.equal((await readFile(path.join(f.root, defaultPath))).subarray(0, 6).toString(), 'SQLite');
  f.env.XDG_CONFIG_HOME = path.join(f.root, 'xdg');
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'saved');
  assert.equal((await readFile(path.join(f.root, 'xdg/missionspec/telemetry.sqlite'))).subarray(0, 6).toString(), 'SQLite');
  assert.equal((await readdir(f.root)).includes('telemetry.sqlite'), false);
});

test('hard opt-outs precede preference reads and never initialize state', options, async (t) => {
  const f = await fixture(t);
  await mkdir(path.dirname(f.preferencePath), { mode: 0o700 });
  await writeFile(f.preferencePath, 'sentinel: not a preference database');
  const before = await tree(f.root);
  for (const [variable, value] of [['MISSIONSPEC_TELEMETRY', '0'], ['DO_NOT_TRACK', '1'], ['CI', 'true']]) {
    f.env[variable] = value;
    assert.equal((await f.command(['telemetry', 'status'])).result.preference, 'not-read');
    delete f.env[variable];
  }
  assert.equal((await f.command(['telemetry', 'status'], { 'no-telemetry': true })).result.preference, 'not-read');
  assert.deepEqual(await tree(f.root), before);
  assert.equal((await f.command(['telemetry', 'status'])).result.state, 'unavailable');
});

test('unrelated databases, JSON, unsafe configuration and symlinked preference parents fail closed', options, async (t) => {
  const f = await fixture(t);
  await mkdir(path.dirname(f.preferencePath), { mode: 0o700 });
  const foreign = new DatabaseSync(f.preferencePath);
  foreign.exec('CREATE TABLE unrelated (keep TEXT); INSERT INTO unrelated VALUES (\'unchanged\')');
  foreign.close();
  await chmod(f.preferencePath, 0o600);
  let before = await readFile(f.preferencePath);
  assert.equal((await f.command(['telemetry', 'on'])).result.state, 'unavailable');
  assert.deepEqual(await readFile(f.preferencePath), before);
  await writeFile(f.preferencePath, '{"preference":"disabled"}');
  before = await readFile(f.preferencePath);
  const failed = await f.command(['telemetry', 'on']);
  assert.deepEqual(failed.result, {
    state: 'unavailable', reason: 'unrecognized-store', persistence: 'unchanged', cleanup: 'complete',
  });
  assert.deepEqual(await readFile(f.preferencePath), before);
  await symlink(path.dirname(f.preferencePath), path.join(f.root, 'linked'));
  f.env.MISSIONSPEC_CONFIG_HOME = path.join(f.root, 'linked/child');
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'unavailable');
  assert.deepEqual(await readdir(path.dirname(f.preferencePath)), ['telemetry.sqlite']);
  f.env.MISSIONSPEC_CONFIG_HOME = 'relative-config';
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'unavailable');
});

test('control grammar rejects generic approval flags, ambiguous previews and unrelated arguments without writes', options, async (t) => {
  const f = await fixture(t);
  for (const [positionals, values] of [
    [['telemetry', 'on'], { approved: true }],
    [['telemetry', 'off'], { preview: true }],
    [['telemetry', 'preview'], { operation: 'draft' }],
    [['logs', 'prune'], { preview: true, approval: 'APR-client' }],
    [['logs', 'prune'], { confirmed: true }],
    [['logs', 'prune'], { file: 'evidence.jsonl' }],
    [['logs', 'prune', 'other'], {}],
  ]) assert.equal((await f.command(positionals, values)).error.code, 'invalid-input');
  assert.deepEqual(await readdir(f.root), []);
});

test('native CLI failures are blocked and invalid explicit paths never fall back or initialize state', options, async (t) => {
  const f = await fixture(t);
  f.env.XDG_CONFIG_HOME = path.join(f.root, 'xdg');
  for (const directory of ['', 'relative-config', '/invalid\npath']) {
    f.env.MISSIONSPEC_CONFIG_HOME = directory;
    for (const action of ['on', 'off', 'status']) {
      await assert.rejects(exec(process.execPath, ['--import', networkGuard, cli, 'telemetry', action, '--json'], { cwd: f.root, env: f.env }),
        (error) => {
          assert.equal(error.code, 2);
          const result = JSON.parse(error.stdout);
          assert.equal(result.status, 'blocked');
          assert.equal(result.value.state, 'unavailable');
          return true;
        });
    }
  }
  delete f.env.MISSIONSPEC_CONFIG_HOME;
  f.env.XDG_CONFIG_HOME = 'relative-xdg';
  assert.equal((await f.command(['telemetry', 'off'])).result.state, 'unavailable');
  assert.deepEqual(await readdir(f.root), []);
});

test('read-only helpers, retained-evidence verification, controls, utilities and previews bypass observation', options, async (t) => {
  const f = await fixture(t);
  const commands = [
    [['status', 'private-change'], {}], [['skills', 'list'], {}], [['skills', 'render'], {}],
    [['validate', 'private.md'], {}], [['analyze', 'private-change'], {}],
    [['verify', 'private-change'], { run: 'RUN-private' }],
    [['telemetry', 'on'], {}], [['logs', 'prune'], {}],
    [['init'], {}], [['convergence', 'private-change'], {}],
    [['capture', 'private-change'], { preview: true }], [['patch', 'private-change'], { preview: true }],
    [['collect', 'private-change'], { preview: true }],
    [['convergence', 'private-change'], { file: 'review.json', preview: true }],
    [['draft', 'private-change'], { preview: true }], [['archive', 'private-change'], { preview: true }],
    [['draft'], { help: true }], [['draft'], { version: true }],
  ];
  const output = await f.run(`
    import assert from 'node:assert/strict';
    const { observeCliOperation } = await import(${JSON.stringify(moduleUrl)});
    for (const [args, values] of ${JSON.stringify(commands)}) {
      const result = { state: 'sentinel' };
      assert.equal(await observeCliOperation(args, values, '0.0.0', async () => result), result);
    }
  `);
  assert.doesNotMatch(output.stderr, /operation-started|operation-stopped|boundary-rejected/u);
  assert.deepEqual(await readdir(f.root), []);
});

test('stateful capture, patch, collection and convergence map canonical operations without completing proposals', options, async (t) => {
  const f = await fixture(t);
  const output = await f.run(`
    import assert from 'node:assert/strict';
    const { observeCliOperation } = await import(${JSON.stringify(moduleUrl)});
    const preview = {
      request: { operation: 'verify', purpose: 'verification' }, review: {},
      implementationStarted: false, testsExecuted: false, proposedRepairs: [],
    };
    const cases = [
      ['capture', { state: 'committed', transactionId: 'private-transaction' }],
      ['capture', { mutations: [], request: { operation: 'draft' } }],
      ['patch', { state: 'committed', transactionId: 'private-transaction' }],
      ['patch', { kind: 'inert-proposal', changes: [] }],
      ['collect', { state: 'collected', runId: 'RUN-private', evidence: ['EVD-private'] }],
      ['collect', { request: { operation: 'verify' }, checks: [] }],
      ['convergence', { id: 'convergence-00000000-0000-4000-8000-000000000000', ...preview }],
      ['convergence', preview],
    ];
    for (const [command, result] of cases) {
      const values = { 'no-telemetry': true, ...(command === 'convergence' ? { file: 'private.json' } : {}) };
      assert.equal(await observeCliOperation([command, 'private-change'], values, '0.0.0', async () => result), result);
    }
  `);
  const lines = output.stderr.split('\n').filter((line) => line.startsWith('{"contractVersion":')).map(JSON.parse);
  const stopped = lines.filter((line) => line.code === 'operation-stopped');
  assert.equal(lines.filter((line) => line.code === 'operation-started').length, 8);
  assert.deepEqual(stopped.map((line) => [line.operation, line.engine, line.severity]), [
    ['draft', 'specification', 'information'], ['draft', 'specification', 'warning'],
    ['implement', 'execution', 'information'], ['implement', 'execution', 'warning'],
    ['verify', 'verification', 'information'], ['verify', 'verification', 'warning'],
    ['verify', 'verification', 'information'], ['verify', 'verification', 'warning'],
  ]);
  assert.doesNotMatch(output.stderr, /private-change|private-transaction|RUN-private|EVD-private|private.json/u);
  assert.deepEqual(await readdir(f.root), []);
});

test('stateful wrappers emit actual typed completion, preserve results/errors and suppress nested double-counting', options, async (t) => {
  const f = await fixture(t);
  const output = await f.run(`
    import assert from 'node:assert/strict';
    const { observeCliOperation } = await import(${JSON.stringify(moduleUrl)});
    const { WorkflowError } = await import(${JSON.stringify(errorsUrl)});
    const values = { 'no-telemetry': true };
    const result = { state: 'committed', transactionId: 'private-transaction', private: 'NEVER_SERIALIZE' };
    assert.equal(await observeCliOperation(['draft', 'private-change'], values, '0.0.0', async () =>
      observeCliOperation(['revise', 'private-change'], values, '0.0.0', async () => result)), result);
    const blocked = { status: 'blocked', error: { code: 'authority-required', message: 'NEVER_SERIALIZE' } };
    assert.equal(await observeCliOperation(['draft'], values, '0.0.0', async () => blocked), blocked);
    const failed = { status: 'failed', error: { code: 'persistence-failed' } };
    assert.equal(await observeCliOperation(['draft'], values, '0.0.0', async () => failed), failed);
    await observeCliOperation(['draft-all'], values, '0.0.0', async () => ({ stop: 'review-blocker', plan: null }));
    await observeCliOperation(['draft'], values, '0.0.0', async () => ({ status: 'ok', value: { approved: true } }));
    const unknown = new WorkflowError('effect-outcome-unknown', 'NEVER_SERIALIZE');
    await assert.rejects(observeCliOperation(['archive'], values, '0.0.0', async () => { throw unknown; }),
      (error) => error === unknown);
    const fatal = new Error('NEVER_SERIALIZE');
    await assert.rejects(observeCliOperation(['draft'], values, '0.0.0', async () => { throw fatal; }),
      (error) => error === fatal);
  `);
  const lines = output.stderr.split('\n').filter((line) => line.startsWith('{"contractVersion":')).map(JSON.parse);
  assert.equal(lines.filter((line) => line.code === 'operation-started').length, 7);
  const stopped = lines.filter((line) => line.code === 'operation-stopped');
  assert.deepEqual(stopped.map((line) => line.severity), [
    'information', 'warning', 'error', 'warning', 'warning', 'warning', 'error',
  ]);
  assert.deepEqual(stopped.map((line) => line.errorCode), [
    null, 'authority-required', 'persistence-failed', null, null, 'effect-outcome-unknown', null,
  ]);
  assert.doesNotMatch(output.stderr, /NEVER_SERIALIZE|private-change|private-transaction/u);
  assert.deepEqual(await readdir(f.root), []);
});

test('default stateful observation has no transport, notice, persisted preferences or local log', options, async (t) => {
  const f = await fixture(t);
  const output = await f.run(`
    const { observeCliOperation } = await import(${JSON.stringify(moduleUrl)});
    await observeCliOperation(['sync', 'private-change'], {}, '0.0.0', async () => ({ state: 'synced' }));
  `);
  assert.match(output.stderr, /operation-started/u);
  assert.match(output.stderr, /operation-stopped/u);
  assert.doesNotMatch(output.stderr, /optional usage analytics|telemetry-unavailable/u);
  assert.deepEqual(await readdir(f.root), []);
});

test('log preview and non-TTY pruning preserve exact private bytes, approvals and evidence', options, async (t) => {
  const f = await fixture(t);
  await f.initialize();
  const { file } = await log(f);
  const before = await tree(f.root);
  const preview = await f.command(['logs', 'prune'], { preview: true });
  assert.equal(preview.result.scope, 'local-diagnostics-only');
  assert.equal(preview.result.path, file);
  assert.equal(preview.result.bytes, (await readFile(file)).length);
  assert.equal((await f.command(['logs', 'prune'])).error.code, 'authority-required');
  const claimed = await f.command(['logs', 'prune'], { approval: 'APR-client-claim' });
  assert.deepEqual(claimed.result, { state: 'unavailable', reason: 'authorization-rejected', effect: 'unchanged' });
  assert.deepEqual(await tree(f.root), before);
});

test('real controlled TTY pruning persists exact review, rejects wrong-scope references, and changes only the diagnostic log', options, async (t) => {
  const f = await fixture(t);
  await f.initialize();
  const { file, sink } = await log(f);
  const approvalsDirectory = path.join(f.root, '.missionspec/approvals');
  const setup = JSON.parse(await readFile(path.join(approvalsDirectory, (await readdir(approvalsDirectory))[0]), 'utf8'));
  assert.equal((await f.command(['logs', 'prune'], { approval: setup.approval.reference.id })).result.reason, 'authorization-rejected');
  const before = await readFile(file);
  const decline = await f.command(['logs', 'prune'], {}, 'decline');
  assert.equal(decline.confirmations, 1);
  assert.equal(decline.error.code, 'authority-required');
  assert.deepEqual(await readFile(file), before);
  const preview = (await f.command(['logs', 'prune'], { preview: true })).result;
  const approved = await f.command(['logs', 'prune'], {}, 'confirm');
  assert.equal(approved.confirmations, 1, approved.output);
  assert.equal(approved.result.state, 'pruned', approved.output);
  assert.equal((await readFile(file)).length, 0);
  const receipts = await Promise.all((await readdir(approvalsDirectory)).map(async (name) =>
    JSON.parse(await readFile(path.join(approvalsDirectory, name), 'utf8'))));
  const receipt = receipts.find((value) => value.display.detail.action === 'prune-local-diagnostics');
  assert(receipt);
  assert.equal(receipt.approval.assurance.channel, 'terminal-confirmation');
  assert.deepEqual(receipt.display.detail.preview, preview);
  assert.equal(receipt.approval.request.effects.length, 1);
  assert.equal(receipt.approval.request.effects[0].path, '.missionspec/logs/diagnostics.jsonl');
  assert.equal(receipt.approval.request.effects[0].kind, 'file-write');
  assert.deepEqual(receipt.display.detail.excludes, ['runtime-ledger', 'approvals', 'evidence']);
  await sink.write(before.toString());
  const changed = await readFile(file);
  assert.equal((await f.command(['logs', 'prune'], { approval: receipt.approval.reference.id })).result.reason, 'authorization-rejected');
  assert.deepEqual(await readFile(file), changed);
  const currentPreview = (await f.command(['logs', 'prune'], { preview: true })).result;
  const request = {
    ...receipt.approval.request,
    binding: { ...receipt.approval.request.binding,
      revision: digestContent(JSON.stringify({ action: 'prune-local-diagnostics', preview: currentPreview })) },
  };
  const callback = await f.run(`
    const { openLocalAuthority } = await import(${JSON.stringify(localAuthorityUrl)});
    const authority = await openLocalAuthority({ directory: process.cwd(), transport: {
      channel: 'trusted-callback', protocolIdentity: { id: 'cli-prune-component-test', version: '1' },
      async confirm() { return 'accept'; },
    } });
    console.log('OBS:' + JSON.stringify(await authority.requestConfirmation(JSON.parse(process.argv[1]))));
  `, [JSON.stringify(request)]);
  const callbackReference = f.decode(callback.stdout).value.approval.reference;
  assert.equal((await f.command(['logs', 'prune'], { approval: callbackReference.id })).result.reason, 'authorization-rejected');
  assert.deepEqual(await readFile(file), changed);
  const issued = await f.run(`
    const { TerminalAuthority } = await import(${JSON.stringify(authorityUrl)});
    const authority = await TerminalAuthority.open(process.cwd());
    const result = await authority.requestConfirmation(JSON.parse(process.argv[1]), {
      action: 'prune-local-diagnostics', preview: JSON.parse(process.argv[2]), effect: 'truncate-to-empty',
      excludes: ['runtime-ledger', 'approvals', 'evidence'],
    });
    console.log('OBS:' + JSON.stringify(result));
  `, [JSON.stringify(request), JSON.stringify(currentPreview)], 'confirm');
  assert.equal(issued.confirmations, 1, issued.output);
  const reference = f.decode(issued.output).value.approval.reference;
  const delayed = await f.run(`
    const { TerminalAuthority } = await import(${JSON.stringify(authorityUrl)});
    const resolve = TerminalAuthority.prototype.resolve;
    TerminalAuthority.prototype.resolve = async function (...args) {
      await new Promise((done) => setTimeout(done, 1100));
      return resolve.apply(this, args);
    };
    ${commandSource}
  `, [JSON.stringify(['logs', 'prune']), JSON.stringify({ approval: reference.id })]);
  assert.equal(f.decode(delayed.stdout).result.state, 'pruned');
  assert.equal((await readFile(file)).length, 0);
  const revoked = await f.run(`
    const { TerminalAuthority } = await import(${JSON.stringify(authorityUrl)});
    await (await TerminalAuthority.open(process.cwd())).revoke(JSON.parse(process.argv[1]));
  `, [JSON.stringify(reference)], 'confirm');
  assert.equal(revoked.confirmations, 1, revoked.output);
  assert.equal((await f.command(['logs', 'prune'], { approval: reference.id })).result.reason, 'authorization-rejected');
  assert.equal((await readdir(f.root)).includes('preferences'), false);
});

test('uninitialized workspace and noncanonical or linked diagnostics never grant pruning authority', options, async (t) => {
  const f = await fixture(t);
  await mkdir(path.join(f.root, '.missionspec'), { mode: 0o700 });
  const { file } = await log(f);
  let before = await tree(f.root);
  assert.equal((await f.command(['logs', 'prune'])).error.code, 'authority-required');
  assert.deepEqual(await tree(f.root), before);
  await writeFile(file, '{"rawEvidence":"NEVER_PRUNE"}\n');
  before = await tree(f.root);
  assert.equal((await f.command(['logs', 'prune'], { preview: true })).result.state, 'unavailable');
  assert.equal((await f.command(['logs', 'prune'])).result.state, 'unavailable');
  assert.deepEqual(await tree(f.root), before);
  await rm(file);
  const target = path.join(f.root, 'unrelated.jsonl');
  await writeFile(target, 'unrelated evidence\n', { mode: 0o600 });
  await symlink(target, file);
  assert.equal((await f.command(['logs', 'prune'], { preview: true })).error.code, 'scope-exceeded');
  assert.equal(await readFile(target, 'utf8'), 'unrelated evidence\n');
});
