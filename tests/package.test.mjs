import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fsPromises, { chmod, link, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import {
  assertInstallHomeUnchanged, createInstallFixture, createInstallWorkspace, executePackageCommand, installSmokeEnvironment, installSmokeGuard,
  packageLinkProblems, packageManifestProblems, packageProblems, packageProcessFailure,
  parsePackPreview, requiredPackageFiles, snapshotInstallHome, windowsInterpreterBaseline, windowsShimInvocation,
} from '../scripts/check-package.mjs';

const name = '@msn-control/missionspec';
const files = requiredPackageFiles.map((path) => ({ path }));
const manifest = {
  name, version: '0.0.0', private: true, type: 'module', license: 'Apache-2.0',
  bin: { missionspec: 'dist/cli/main.js' }, types: './dist/api/index.d.ts',
  exports: {
    '.': { types: './dist/api/index.d.ts', import: './dist/api/index.js' },
    './package.json': './package.json',
  },
};

test('package preview supports actual npm 12 keyed output and prior array output explicitly', () => {
  const value = { name, files };
  assert.deepEqual(parsePackPreview(JSON.stringify({ [name]: value })), value);
  assert.deepEqual(parsePackPreview(JSON.stringify([value])), value);
  for (const invalid of [{}, [], [value, value], { unrelated: value }, { [name]: { name, files: null } }]) {
    assert.throws(() => parsePackPreview(JSON.stringify(invalid)), /Unrecognized/);
  }
});

test('package requires exact named operation bodies, not merely a matching count', () => {
  assert.deepEqual(packageProblems({ name, files }), []);
  const replaced = files.map((file) => file.path === 'assets/operations/verify.md'
    ? { path: 'assets/operations/unplanned.md' } : file);
  assert(packageProblems({ name, files: replaced }).some((problem) => problem.includes('verify.md')));
});

test('state, credentials, unbuilt source and operator packages must not be shipped in the CLI', () => {
  for (const forbidden of [
    '.missionspec/state/ledger.sqlite', '.env.production', 'services/telemetry-ingest/package.json',
    'infrastructure/main.tf', 'src/private.ts', 'node_modules/a/index.js', 'licenses/telemetry-runtime.json',
    'licenses/TELEMETRY_THIRD_PARTY_NOTICES', '.operator-private/deployment.json',
    'dist/.missionspec/approval.json', 'docs/.operator-private/credentials.json',
    'assets/build-cache/native.node', 'dist/.build-cache/output', 'dist/compile.tsbuildinfo',
    'assets/secrets/token.json', 'assets/secrets.json', 'docs/.npmrc', 'assets/credentials/private.key',
    'dist/services/telemetry-ingest/index.js', 'unreviewed.txt',
  ]) {
    assert(packageProblems({ name, files: [...files, { path: forbidden }] }).some((problem) => problem.includes('Unintended')));
  }
});

test('preview parsing rejects duplicate and escaping paths instead of hiding them in a set', () => {
  for (const bad of [
    ...['', '../secret', '/secret', 'C:/secret', 'C:secret', 'a\\b', 'a/./b', 'a//b', 'a\0b'].map((path) => [{ path }]),
    [{ path: 'a' }, { path: 'a' }],
  ]) {
    assert.throws(() => parsePackPreview(JSON.stringify({ [name]: { name, files: bad } })), /Invalid/);
  }
});

test('package requires non-skill runtime assets including platform helpers and workflow examples', () => {
  for (const required of [
    'assets/schemas/telemetry-event.schema.json', 'assets/platform/windows-access-policy.ps1',
    'assets/platform/windows-file-operations.ps1', 'assets/platform/windows-execution-native.ps1',
    'assets/workflows/compact/workflow.yaml', 'assets/workflows/standard/workflow.yaml',
    'assets/workflows/standard/examples/specs/filters.md',
  ]) {
    assert(packageProblems({ name, files: files.filter((file) => file.path !== required) })
      .some((problem) => problem === `Missing packaged file: ${required}`));
  }
});

test('pre-release package manifest preserves public exports, bin, privacy and no install hooks', () => {
  assert.deepEqual(packageManifestProblems(manifest), []);
  for (const change of [
    { private: false }, { version: '1.0.0' }, { bin: { unexpected: 'dist/cli/main.js' } },
    { exports: { '.': './src/api/index.ts' } }, { types: './missing.d.ts' },
    { bundledDependencies: ['fs-native-extensions'] },
    ...['preinstall', 'install', 'postinstall', 'prepare'].map((hook) => ({ scripts: { [hook]: 'unexpected' } })),
  ]) {
    assert(packageManifestProblems({ ...manifest, ...change }).length > 0);
  }
});

test('offline install fixture preserves the exact reviewed runtime closure, not fresh semver resolution', () => {
  const source = { ...manifest, dependencies: { runtime: '1.0.0' } };
  const integrity = `sha512-${Buffer.alloc(64).toString('base64')}`;
  const record = { version: '1.0.0', resolved: 'https://registry.npmjs.org/runtime/-/runtime-1.0.0.tgz', integrity,
    dependencies: { transitive: '^2.0.0' } };
  const lock = { lockfileVersion: 3, packages: {
    '': source, 'node_modules/runtime': record,
    'node_modules/transitive': { version: '2.0.3', resolved: 'https://registry.npmjs.org/transitive/-/transitive-2.0.3.tgz', integrity },
    'node_modules/development': { dev: true, version: '9.0.0' },
  } };
  const fixture = createInstallFixture(source, lock, { integrity });
  assert.deepEqual(fixture.locations, ['node_modules/runtime', 'node_modules/transitive']);
  assert.deepEqual(fixture.lock.packages['node_modules/runtime'], record);
  assert.equal(fixture.lock.packages['node_modules/transitive'].version, '2.0.3');
  assert.equal(fixture.lock.packages[`node_modules/${name}`].integrity, integrity);
  assert.equal(fixture.manifest.dependencies[name], 'file:../candidate.tgz');
  assert(!Object.hasOwn(fixture.lock.packages, 'node_modules/development'));
  for (const change of [
    { hasInstallScript: true }, { link: true }, { inBundle: true },
    { resolved: 'https://unexpected.invalid/package.tgz' }, { integrity: undefined },
  ]) {
    assert.throws(() => createInstallFixture(source,
      { ...lock, packages: { ...lock.packages, 'node_modules/runtime': { ...record, ...change } } }, { integrity }));
  }
  assert.throws(() => createInstallFixture({ ...source, dependencies: { runtime: '2.0.0' } }, lock, { integrity }), /disagree/);
});

test('offline smoke guard fails even swallowed network, subprocess or optional model SDK attempts', async () => {
  const execute = promisify(execFile);
  const guard = `await (${installSmokeGuard.toString()})();\n`;
  await execute(process.execPath, ['--input-type=module', '--eval', `${guard}console.log("inert");`]);
  for (const attempt of [
    'await fetch("https://example.invalid")',
    '(await import("node:https")).get("https://example.invalid")',
    '(await import("node:child_process")).spawn("not-a-real-host")',
    'await import("@github/copilot-sdk")',
    'await import("@anthropic-ai/claude-agent-sdk")',
  ]) {
    await assert.rejects(execute(process.execPath, ['--input-type=module', '--eval',
      `${guard}try { ${attempt}; } catch { /* A swallowed activation must still fail the smoke. */ }`]),
    (error) => error.code === 1 && /forbidden activation attempt/.test(error.stderr));
  }
});

test('Windows shim invocations preserve spaced paths and arguments with fixed noninteractive OS executables', () => {
  const bin = "C:\\Users\\O'Brien\\package with spaces\\node_modules\\.bin\\missionspec";
  const args = ['validate', 'proposal with spaces.md', '--json'];
  const cmd = windowsShimInvocation('cmd', bin, args, 'C:\\WINDOWS');
  assert.equal(cmd.command, 'C:\\Windows\\System32\\cmd.exe');
  assert.deepEqual(cmd.args, ['/d', '/v:off', '/s', '/c',
    `""${bin}.cmd" "validate" "proposal with spaces.md" "--json""`]);
  assert.deepEqual(cmd.options, { shell: false, windowsVerbatimArguments: true });
  const powershell = windowsShimInvocation('powershell', bin, args, 'C:\\Windows');
  assert.equal(powershell.command, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(powershell.args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', `${bin}.ps1`, ...args]);
  assert.deepEqual(powershell.options, { shell: false });
  assert(!powershell.args.some((arg) => /ExecutionPolicy|Bypass|EncodedCommand/i.test(arg)));
});

test('Windows shim launcher rejects shell expansion, noncanonical paths and redirected system hosts', () => {
  const bin = 'C:\\temporary\\node_modules\\.bin\\missionspec';
  for (const kind of ['cmd', 'powershell']) {
    for (const arg of ['', '"quoted"', '%PATH%', '!name!', 'a&b', 'a|b', '^escape', '<input', '>output',
      'a\nb', 'a\0b', '$(unexpected)', '`unexpected`']) {
      assert.throws(() => windowsShimInvocation(kind, bin, [arg], 'C:\\Windows'), /Unsafe Windows shim argument/);
    }
    for (const invalid of ['missionspec', 'C:missionspec', '\\\\server\\share\\missionspec',
      'C:\\temporary\\..\\missionspec', 'C:\\temporary.\\missionspec', 'C:\\AUX\\missionspec',
      'C:\\%TEMP%\\missionspec', 'C:\\a!b\\missionspec', 'C:\\a&b\\missionspec', 'C:\\a"b\\missionspec',
      'C:\\a?b\\missionspec', 'C:\\a:b\\missionspec', 'C:\\a\nb\\missionspec', 'C:\\other-command']) {
      assert.throws(() => windowsShimInvocation(kind, invalid, ['--version'], 'C:\\Windows'), /Unsafe Windows shim path/);
    }
    assert.throws(() => windowsShimInvocation(kind, bin, ['--version'], 'D:\\redirected'), /fixed C:\\Windows/);
  }
  assert.throws(() => windowsShimInvocation('arbitrary-shell', bin, [], 'C:\\Windows'), /Unrecognized Windows shim/);
});

test('installed smoke replaces case-insensitive PATH/preloads and does not hide normal behavior behind CI opt-outs', () => {
  const env = installSmokeEnvironment('/owned/home', '/owned/guard with spaces.mjs', {
    PATH: '/untrusted-one', Path: '/untrusted-two', NODE_OPTIONS: '--require=untrusted', node_path: '/untrusted',
    HOME: '/real-home', APPDATA: '/real-data', missionspec_config_home: '/real-config',
    CI: 'true', NODE_ENV: 'test', NODE_TEST_CONTEXT: 'child', DO_NOT_TRACK: '1', MISSIONSPEC_TELEMETRY: '0',
    ComSpec: 'untrusted.exe', PSModulePath: '/untrusted-modules', PSExecutionPolicyPreference: 'Bypass', SystemRoot: 'C:\\Windows',
  });
  assert.equal(env.PATH, path.dirname(process.execPath));
  assert.equal(Object.keys(env).filter((key) => key.toLowerCase() === 'path').length, 1);
  assert.equal(env.HOME, '/owned/home');
  assert.equal(env.APPDATA, '/owned/home');
  assert.equal(env.MISSIONSPEC_CONFIG_HOME, path.join('/owned/home', 'missionspec'));
  assert.match(env.NODE_OPTIONS, /^--import=file:.*guard%20with%20spaces\.mjs$/);
  for (const key of ['CI', 'NODE_ENV', 'NODE_TEST_CONTEXT', 'DO_NOT_TRACK', 'MISSIONSPEC_TELEMETRY', 'node_path', 'PSExecutionPolicyPreference']) {
    assert(!Object.hasOwn(env, key));
  }
  assert(!Object.values(env).some((value) => value.includes('untrusted')));
});

test('install fixture uses private owned checkout directories even with a permissive child umask', async () => {
  const checker = new URL('../scripts/check-package.mjs', import.meta.url).href;
  const source = `
    import assert from 'node:assert/strict';
    import { stat, rm } from 'node:fs/promises';
    import path from 'node:path';
    import { createInstallWorkspace } from ${JSON.stringify(checker)};
    if (process.platform !== 'win32') process.umask(0);
    const fixture = await createInstallWorkspace();
    try {
      assert.equal(path.dirname(fixture.consumer), fixture.temporary);
      assert.equal(path.dirname(fixture.home), fixture.temporary);
      for (const directory of Object.values(fixture)) {
        const info = await stat(directory);
        assert(info.isDirectory());
        if (process.platform !== 'win32') assert.equal(info.mode & 0o777, 0o700);
      }
      process.stdout.write(JSON.stringify(fixture));
    } finally { await rm(fixture.temporary, { recursive: true, force: true }); }
  `;
  const { stdout } = await executePackageCommand(process.execPath, ['--input-type=module', '--eval', source], { timeout: 10_000 });
  const fixture = JSON.parse(stdout);
  const root = await realpath(fileURLToPath(new URL('../', import.meta.url)));
  assert.equal(path.dirname(fixture.temporary), root);
  assert.match(path.basename(fixture.temporary), /^\.package-install-/);
  assert.match(fixture.consumer, /consumer with spaces$/);
  assert.match(fixture.home, /home with spaces$/);
  await assert.rejects(readdir(fixture.temporary), { code: 'ENOENT' });
});

test('owned home snapshots compare exact names, types and bytes without exposing contents or accepting AppData writes', async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  await assert.rejects(snapshotInstallHome({ ...fixture }), /checker-owned/);
  assert.deepEqual(await snapshotInstallHome(fixture), []);
  await mkdir(path.join(fixture.home, 'AppData'), { mode: 0o700 });
  const filename = path.join(fixture.home, 'AppData', 'cache.fixture');
  const content = 'private-fixture-content';
  await writeFile(filename, content);
  const baseline = await snapshotInstallHome(fixture);
  assert.deepEqual(baseline, [
    { path: 'AppData', type: 'directory' },
    { path: 'AppData/cache.fixture', type: 'file', bytes: Buffer.byteLength(content),
      digest: `sha256:${createHash('sha256').update(content).digest('hex')}` },
  ]);
  await assertInstallHomeUnchanged(fixture, baseline, 'powershell');
  await writeFile(filename, 'changed-fixture-content');
  await assert.rejects(assertInstallHomeUnchanged(fixture, baseline, 'powershell'), (error) => {
    assert.match(error.message, /"phase":"powershell"/);
    assert.match(error.message, /AppData\/cache\.fixture/);
    assert(!error.message.includes('private-fixture-content'));
    assert(!error.message.includes('changed-fixture-content'));
    assert(!error.message.includes(fixture.home));
    return true;
  });
  await writeFile(filename, content);
  await mkdir(path.join(fixture.home, 'AppData', 'missionspec'));
  await assert.rejects(assertInstallHomeUnchanged(fixture, baseline, 'api'), /AppData\/missionspec/);
  await rm(path.join(fixture.home, 'AppData', 'missionspec'), { recursive: true });
  await rm(filename);
  await assert.rejects(assertInstallHomeUnchanged(fixture, baseline, 'final'), /Read-only smoke changed/);
});

test('home inventory rejects links, oversized files and unbounded entry counts inside the owned fixture', async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  const sentinel = path.join(fixture.consumer, 'not-home.fixture');
  await writeFile(sentinel, 'must-not-be-hashed-through-a-link');
  const linked = path.join(fixture.home, 'linked');
  await symlink(fixture.consumer, linked, 'junction');
  await assert.rejects(snapshotInstallHome(fixture), /non-regular entry/);
  await rm(linked);
  await link(sentinel, linked);
  await assert.rejects(snapshotInstallHome(fixture), /linked, non-regular or oversized/);
  await rm(linked);
  await writeFile(linked, Buffer.alloc(1_000_001));
  await assert.rejects(snapshotInstallHome(fixture), /oversized/);
  await rm(linked);
  for (let index = 0; index < 65; index += 1) await writeFile(path.join(fixture.home, `file-${index}`), '');
  await assert.rejects(snapshotInstallHome(fixture), /diagnostic bounds/);
});

test('guard completion does not exempt a successful child that writes product home state', async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  const receipt = path.join(fixture.temporary, 'guard-receipt');
  const guard = path.join(fixture.consumer, 'guard.mjs');
  await writeFile(guard, `await (${installSmokeGuard.toString()})(${JSON.stringify(receipt)});\n`);
  await executePackageCommand(process.execPath, ['--input-type=module', '--eval',
    `await (await import('node:fs/promises')).writeFile(${JSON.stringify(path.join(fixture.home, 'product-write.fixture'))}, 'fixture');`],
  { cwd: fixture.consumer, env: installSmokeEnvironment(fixture.home, guard), timeout: 5_000 });
  assert.equal(await readFile(receipt, 'utf8'), '0');
  await assert.rejects(assertInstallHomeUnchanged(fixture, [], 'api'), /product-write\.fixture/);
});

test('owned home inventory rejects a replaced filename before hashing any bytes', async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  const filename = path.join(fixture.home, 'observed.fixture');
  await writeFile(filename, 'original');
  const originalOpen = fsPromises.open;
  let reads = 0;
  const mocked = context.mock.method(fsPromises, 'open', async (...args) => {
    const handle = await originalOpen(...args);
    if (args[0] === filename) {
      const read = handle.read.bind(handle);
      handle.read = (...input) => { reads += 1; return read(...input); };
      await rename(filename, path.join(fixture.consumer, 'retained-original.fixture'));
      await writeFile(filename, 'replacement');
    }
    return handle;
  });
  syncBuiltinESMExports();
  context.after(() => { mocked.mock.restore(); syncBuiltinESMExports(); });
  await assert.rejects(snapshotInstallHome(fixture), /changed before reading/);
  assert.equal(reads, 0);
});

test('actual fixed Windows interpreter baseline is independently observed and must remain stable before product launch', {
  skip: process.platform !== 'win32' ? 'Requires actual fixed Windows PowerShell; not qualified by POSIX fixtures' : false,
}, async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  const guard = path.join(fixture.consumer, 'guard.mjs');
  const receipt = path.join(fixture.temporary, 'guard-receipt');
  await writeFile(guard, `await (${installSmokeGuard.toString()})(${JSON.stringify(receipt)});\n`);
  assert.deepEqual(await snapshotInstallHome(fixture), []);
  const baseline = await windowsInterpreterBaseline(fixture, installSmokeEnvironment(fixture.home, guard));
  context.diagnostic(`Independent Windows interpreter home baseline: ${JSON.stringify(baseline)}`);
  await assert.rejects(readFile(receipt), { code: 'ENOENT' });
  await assertInstallHomeUnchanged(fixture, baseline, 'final');
  await writeFile(path.join(fixture.home, 'product-write.fixture'), 'fixture');
  await assert.rejects(assertInstallHomeUnchanged(fixture, baseline, 'powershell'), /product-write\.fixture/);
});

test('read-only preferences reject a public ancestor even with a 0700 home, and accept the private install fixture', {
  skip: process.platform === 'win32' ? 'POSIX mode/ancestor regression; Windows keeps its native ACL gate' : false,
}, async (context) => {
  const fixture = await createInstallWorkspace();
  context.after(() => rm(fixture.temporary, { recursive: true, force: true }));
  const publicAncestor = path.join(fixture.temporary, 'public ancestor');
  const privateHome = path.join(publicAncestor, 'private home');
  await mkdir(publicAncestor, { mode: 0o700 });
  await mkdir(privateHome, { mode: 0o700 });
  await chmod(publicAncestor, 0o1777);
  const guard = path.join(fixture.consumer, 'guard.mjs');
  await writeFile(guard, `await (${installSmokeGuard.toString()})();\n`);
  const entry = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
  const call = (home) => executePackageCommand(process.execPath, [entry, 'telemetry', 'status', '--json'], {
    cwd: fixture.consumer, env: installSmokeEnvironment(home, guard), timeout: 10_000,
  });
  await assert.rejects(call(privateHome), (error) =>
    error.code === 2 && JSON.parse(error.stdout).value.reason === 'preference-read-failed');
  const output = JSON.parse((await call(fixture.home)).stdout);
  assert.equal(output.status, 'ok');
  assert.equal(output.value.configured, false);
  assert.equal(output.value.preference, 'default');
  assert.deepEqual(await readdir(fixture.home), []);
  assert.deepEqual(await readdir(privateHome), []);
});

test('bounded package commands close redirected stdin instead of waiting indefinitely for input', async () => {
  const { stdout } = await executePackageCommand(process.execPath, ['--input-type=module', '--eval', `
    let bytes = 0;
    for await (const chunk of process.stdin) bytes += chunk.length;
    process.stdout.write(JSON.stringify({ eof: true, bytes }));
  `], { timeout: 5_000 });
  assert.deepEqual(JSON.parse(stdout), { eof: true, bytes: 0 });
  await assert.rejects(executePackageCommand(process.execPath, ['--eval', 'process.exitCode = 2;'], { timeout: 5_000 }),
    (error) => error.code === 2 && !error.packageExecution.timedOut);
});

test('package process diagnostics distinguish deadline, output limit, launch, exit and signal without child output', async () => {
  await assert.rejects(executePackageCommand(process.execPath, ['--eval', 'setInterval(() => {}, 1000);'], { timeout: 100 }),
    (error) => {
      const details = packageProcessFailure(error);
      assert.equal(details.kind, 'timeout');
      assert.equal(details.timedOut, true);
      assert.equal(details.timeoutMs, 100);
      assert.equal(details.killed, true);
      return true;
    });
  await assert.rejects(executePackageCommand(`${process.execPath}.missing`, [], { timeout: 5_000 }),
    (error) => packageProcessFailure(error).kind === 'launch-or-io' && packageProcessFailure(error).code === 'ENOENT');
  await assert.rejects(executePackageCommand(process.execPath, ['--eval', 'process.stdout.write("x".repeat(10000));'],
    { timeout: 5_000, maxBuffer: 64 }), (error) => packageProcessFailure(error).kind === 'output-limit' &&
      !packageProcessFailure(error).timedOut);
  for (const [error, kind] of [
    [{ code: 2 }, 'exit'],
    [{ signal: 'SIGTERM', killed: true }, 'signal'],
    [{ code: 'secret-fixture-marker', signal: 'secret-fixture-marker' }, 'signal'],
  ]) {
    const details = packageProcessFailure({ ...error, stdout: 'secret-fixture-marker', stderr: 'secret-fixture-marker',
      message: 'secret-fixture-marker', cmd: 'secret-fixture-marker', env: { TOKEN: 'secret-fixture-marker' } });
    assert.equal(details.kind, kind);
    assert.equal(details.stdoutBytes, 21);
    assert.equal(details.stderrBytes, 21);
    assert(!JSON.stringify(details).includes('secret-fixture-marker'));
  }
  for (const timeout of [0, -1, Infinity, 120_001]) {
    await assert.rejects(executePackageCommand(process.execPath, [], { timeout }), /bounded package command deadline/);
  }
});

test('smoke guard writes completion evidence even for expected nonzero CLI exits', async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'missionspec-guard-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const receipt = path.join(temporary, 'receipt');
  const execute = promisify(execFile);
  const guard = `await (${installSmokeGuard.toString()})(${JSON.stringify(receipt)});\n`;
  await assert.rejects(execute(process.execPath, ['--input-type=module', '--eval', `${guard}process.exitCode = 2;`]),
    (error) => error.code === 2);
  assert.equal(await readFile(receipt, 'utf8'), '0');
  await rm(receipt);
  await assert.rejects(execute(process.execPath, ['--input-type=module', '--eval',
    `${guard}try { await fetch('https://example.invalid'); } catch {}`]), (error) => error.code === 1);
  assert.equal(await readFile(receipt, 'utf8'), '1');
});

test('packaged documentation cannot link to excluded operator or source files', async () => {
  const preview = { name, files: [{ path: 'README.md' }, { path: 'docs/guide.md' }] };
  const content = new Map([
    ['README.md', '# Overview\n[Guide](docs/guide.md#intro)\n[Service](services/telemetry-ingest/)\n'],
    ['docs/guide.md', '# Intro\n[Home](../README.md#overview)\n']
  ]);
  const problems = await packageLinkProblems(preview, async (file) => content.get(file));
  assert.equal(problems.length, 1);
  assert.match(problems[0], /not packaged.*services/);
  content.set('README.md', '# Overview\n[Guide](docs/guide.md#missing)\n');
  assert.match((await packageLinkProblems(preview, async (file) => content.get(file)))[0], /heading anchor/);
});
