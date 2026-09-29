import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual, promisify } from 'node:util';
import { OPERATION_IDS } from '../dist/kernel/registry.js';
import { runtimeGraph } from './check-licenses.mjs';
import { localLinkTarget, markdownInfo } from './check-repository.mjs';

const packageName = '@msn-control/missionspec';
const root = fileURLToPath(new URL('../', import.meta.url));
const execute = promisify(execFile);
const installHooks = ['preinstall', 'install', 'postinstall'];
const windowsInterpreters = {
  cmd: 'C:\\Windows\\System32\\cmd.exe',
  powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
};

export const requiredPackageFiles = [
  'package.json', 'LICENSE', 'THIRD_PARTY_NOTICES', 'licenses/cli-runtime.json',
  'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
  'dist/cli/main.js', 'dist/api/index.js', 'dist/api/index.d.ts',
  'assets/operations/manifest.yaml', 'assets/schemas/operation-manifest.schema.json',
  'assets/schemas/telemetry-event.schema.json',
  ...OPERATION_IDS.map((id) => `assets/operations/${id}.md`),
  ...['access-policy', 'check-process', 'console', 'execution-native', 'file-operations', 'private-state']
    .map((name) => `assets/platform/windows-${name}.ps1`),
  ...['compact', 'standard'].flatMap((profile) => [
    `assets/workflows/${profile}/workflow.yaml`,
    ...['proposal.md', 'tasks.md', ...(profile === 'compact' ? ['specs/summary.md'] :
      ['design.md', 'specs/filters.md', 'specs/reset.md'])]
      .map((file) => `assets/workflows/${profile}/examples/${file}`),
  ]),
];

export function parsePackPreview(content) {
  const parsed = JSON.parse(content);
  const entries = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Object.keys(parsed).length === 1 && Object.hasOwn(parsed, packageName)
      ? [parsed[packageName]]
      : [];
  if (entries.length !== 1 || entries[0]?.name !== packageName || !Array.isArray(entries[0].files)) {
    throw new Error('Unrecognized npm package preview; expected one MissionSpec package');
  }
  const seen = new Set();
  for (const file of entries[0].files) {
    if (typeof file?.path !== 'string' || !file.path || path.win32.isAbsolute(file.path) || file.path.includes(':') ||
        /[\\\u0000-\u001f\u007f]/u.test(file.path) || file.path.split('/').some((part) => !part || part === '.' || part === '..') ||
        seen.has(file.path)) throw new Error('Invalid or duplicate packaged file path');
    seen.add(file.path);
  }
  return entries[0];
}

export function packageProblems(preview) {
  const files = new Set(preview.files.map((file) => file.path));
  const problems = requiredPackageFiles.filter((file) => !files.has(file)).map((file) => `Missing packaged file: ${file}`);
  const bodies = [...files].filter((file) => /^assets\/operations\/[^/]+\.md$/.test(file));
  if (bodies.length !== OPERATION_IDS.length) problems.push('Unexpected operation instruction files in package');
  for (const file of files) {
    if ((!requiredPackageFiles.includes(file) && !/^(dist|assets|docs)\//.test(file)) ||
        /(^|\/)(?:\.[^/]+|node_modules|build-cache|coverage|services|infrastructure|tests|scripts|src)(?:\/|$)/i.test(file) ||
        /(^|\/)(?:secrets?|credentials)(?:[./]|$)/i.test(file) ||
        /\.(?:tsbuildinfo|tgz|log|pem|key|p12|pfx)$/i.test(file)) {
      problems.push(`Unintended package content: ${file}`);
    }
  }
  return problems;
}

export function packageManifestProblems(manifest) {
  const problems = [];
  const expected = {
    name: packageName, version: '0.0.0', private: true, type: 'module', license: 'Apache-2.0',
    bin: { missionspec: 'dist/cli/main.js' },
    types: './dist/api/index.d.ts',
    exports: {
      '.': { types: './dist/api/index.d.ts', import: './dist/api/index.js' },
      './package.json': './package.json',
    },
  };
  for (const [key, value] of Object.entries(expected)) {
    if (!isDeepStrictEqual(manifest[key], value)) problems.push(`Unexpected pre-release package manifest: ${key}`);
  }
  for (const hook of [...installHooks, 'prepare']) {
    if (Object.hasOwn(manifest.scripts ?? {}, hook)) problems.push(`Unreviewed package lifecycle script: ${hook}`);
  }
  if (manifest.bundleDependencies || manifest.bundledDependencies) problems.push('Runtime dependencies must not be bundled');
  return problems;
}

export async function packageLinkProblems(preview, readMarkdown) {
  const files = new Set(preview.files.map((file) => file.path));
  const problems = [];
  const documents = new Map();
  for (const file of files) {
    if (file.endsWith('.md')) documents.set(file, markdownInfo(await readMarkdown(file)));
  }
  for (const [source, document] of documents) {
    for (const link of document.links) {
      let target;
      try {
        target = localLinkTarget(source, link);
      } catch (error) {
        problems.push(`${source}: ${error.message}`);
        continue;
      }
      if (!target) continue;
      const directory = target.path.endsWith('/') ? target.path : `${target.path}/`;
      if (!files.has(target.path) && ![...files].some((file) => file.startsWith(directory))) {
        problems.push(`${source}: link target is not packaged: ${link}`);
      } else if (target.fragment && documents.has(target.path) &&
          !documents.get(target.path).anchors.has(target.fragment)) {
        problems.push(`${source}: packaged heading anchor is missing: ${link}`);
      }
    }
  }
  return problems;
}

export function createInstallFixture(manifest, lock, preview) {
  assert.equal(lock.lockfileVersion, 3, 'Expected the reviewed version-3 lockfile');
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies, 'Manifest and reviewed lock disagree');
  assert.match(preview.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
  const graph = runtimeGraph(lock.packages);
  const dependencies = Object.fromEntries([...graph.keys()].filter(Boolean).map((location) => {
    const record = lock.packages[location];
    assert(!record.hasInstallScript && !record.link && !record.inBundle, `Unreviewed dependency install behavior: ${location}`);
    assert.match(record.resolved, /^https:\/\/registry\.npmjs\.org\/[^?#]+\.tgz$/);
    assert.match(record.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    return [location, record];
  }));
  const consumer = { name: 'missionspec-install-check', version: '0.0.0', private: true,
    type: 'module', dependencies: { [packageName]: 'file:../candidate.tgz' } };
  return {
    manifest: consumer,
    lock: { name: consumer.name, version: consumer.version, lockfileVersion: 3, requires: true, packages: {
      '': consumer,
      ...dependencies,
      [`node_modules/${packageName}`]: {
        version: manifest.version, resolved: 'file:../candidate.tgz', integrity: preview.integrity,
        license: manifest.license, dependencies: manifest.dependencies, bin: manifest.bin, engines: manifest.engines,
      },
    } },
    locations: Object.keys(dependencies),
  };
}

// Serialized into the disposable consumer and preloaded before any installed code.
export async function installSmokeGuard(receipt) {
  const { createRequire, syncBuiltinESMExports, registerHooks } = await import('node:module');
  const require = createRequire(import.meta.url);
  let attempts = 0;
  const deny = () => {
    attempts += 1;
    throw new Error('Offline install smoke forbids network and subprocess activation');
  };
  for (const [name, methods] of [
    ['node:net', ['connect', 'createConnection']],
    ['node:tls', ['connect']], ['node:http', ['request', 'get']],
    ['node:https', ['request', 'get']], ['node:http2', ['connect']],
    ['node:child_process', ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']],
  ]) {
    const module = require(name);
    for (const method of methods) module[method] = deny;
  }
  require('node:net').Socket.prototype.connect = deny;
  globalThis.fetch = deny;
  globalThis.WebSocket = class { constructor() { deny(); } };
  syncBuiltinESMExports();
  registerHooks({ resolve(specifier, context, nextResolve) {
    if (/^(?:@anthropic-ai\/|@github\/copilot|@openai\/|openai(?:\/|$))/.test(specifier)) deny();
    return nextResolve(specifier, context);
  } });
  process.on('exit', () => {
    if (receipt !== undefined) require('node:fs').writeFileSync(receipt, String(attempts), { flag: 'wx', mode: 0o600 });
    if (attempts) {
      process.stderr.write(`Offline install smoke observed ${attempts} forbidden activation attempt(s).\n`);
      process.exitCode = 1;
    }
  });
}

export function windowsShimInvocation(kind, bin, args, systemRoot = process.env.SystemRoot) {
  assert(['cmd', 'powershell'].includes(kind), 'Unrecognized Windows shim');
  assert.equal(systemRoot?.toLowerCase(), 'c:\\windows', 'Windows shim smoke requires the fixed C:\\Windows system host');
  assert(typeof bin === 'string' && /^[A-Za-z]:\\/u.test(bin) && path.win32.normalize(bin) === bin &&
    path.win32.basename(bin) === 'missionspec' && bin.slice(3).split('\\').every((part) =>
      !/[%!^"&|<>:?*/\u0000-\u001f\u007f]/u.test(part) && !/[. ]$/u.test(part) &&
      !/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part)),
  'Unsafe Windows shim path');
  // This harness accepts only its bounded smoke arguments, not arbitrary shell input.
  assert(Array.isArray(args) && args.every((arg) => typeof arg === 'string' && /^[A-Za-z0-9_./ -]+$/u.test(arg)),
    'Unsafe Windows shim argument');
  if (kind === 'powershell') {
    return { command: windowsInterpreters.powershell,
      args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', `${bin}.ps1`, ...args], options: { shell: false } };
  }
  return { command: windowsInterpreters.cmd,
    args: ['/d', '/v:off', '/s', '/c', `"${[`${bin}.cmd`, ...args].map((arg) => `"${arg}"`).join(' ')}"`],
    options: { shell: false, windowsVerbatimArguments: true } };
}

export function installSmokeEnvironment(home, guard, inherited = process.env) {
  const replaced = new Set(['path', 'node_options', 'node_path', 'home', 'userprofile', 'xdg_config_home',
    'appdata', 'localappdata', 'missionspec_config_home', 'comspec', 'psmodulepath', 'psexecutionpolicypreference',
    'ci', 'node_env', 'node_test_context', 'do_not_track', 'missionspec_telemetry']);
  return {
    ...Object.fromEntries(Object.entries(inherited).filter(([key]) => !replaced.has(key.toLowerCase()))),
    HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: home, APPDATA: home, LOCALAPPDATA: home,
    MISSIONSPEC_CONFIG_HOME: path.join(home, 'missionspec'), PATH: path.dirname(process.execPath),
    NODE_OPTIONS: `--import=${pathToFileURL(guard).href}`,
    ...(process.platform === 'win32' ? { ComSpec: windowsInterpreters.cmd,
      PSModulePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules' } : {}),
  };
}

export async function createInstallWorkspace() {
  // Linux /tmp is world-writable, which the unchanged preference ancestor policy rejects.
  const temporary = await realpath(await mkdtemp(path.join(root, '.package-install-')));
  const consumer = path.join(temporary, 'consumer with spaces');
  const home = path.join(temporary, 'home with spaces');
  try {
    await Promise.all([mkdir(consumer, { mode: 0o700 }), mkdir(home, { mode: 0o700 })]);
    return { temporary, consumer, home };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

export async function executePackageCommand(command, args, { timeout, ...options }) {
  assert(Number.isSafeInteger(timeout) && timeout > 0 && timeout <= 120_000, 'A bounded package command deadline is required');
  const execution = execute(command, args, { ...options, timeout: 0 });
  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    execution.child.kill();
  }, timeout);
  // npm PowerShell shims can enumerate redirected $input; noninteractive commands need EOF.
  execution.child.stdin?.end();
  try {
    return await execution;
  } catch (error) {
    error.packageExecution = { timedOut, timeoutMs: timeout };
    throw error;
  } finally {
    clearTimeout(deadline);
  }
}

export function packageProcessFailure(error) {
  const timeoutMs = error.packageExecution?.timeoutMs;
  const timedOut = error.packageExecution?.timedOut === true;
  const signal = ['SIGTERM', 'SIGKILL', 'SIGINT'].includes(error.signal) ? error.signal : error.signal ? 'other' : null;
  const code = Number.isInteger(error.code) || [
    'ENOENT', 'EACCES', 'EPERM', 'ENOBUFS', 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', 'ABORT_ERR',
  ].includes(error.code) ? error.code : null;
  return {
    kind: timedOut ? 'timeout' : error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ? 'output-limit' :
      signal ? 'signal' : Number.isInteger(code) ? 'exit' : 'launch-or-io',
    code, signal, killed: error.killed === true, timedOut,
    timeoutMs: Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120_000 ? timeoutMs : null,
    stdoutBytes: typeof error.stdout === 'string' ? Buffer.byteLength(error.stdout) : 0,
    stderrBytes: typeof error.stderr === 'string' ? Buffer.byteLength(error.stderr) : 0,
  };
}

async function checkWindowsInterpreters() {
  for (const filename of Object.values(windowsInterpreters)) {
    let current = path.parse(filename).root;
    for (const component of filename.slice(current.length).split(path.sep)) {
      current = path.join(current, component);
      const entry = await lstat(current);
      assert(!entry.isSymbolicLink() && (current === filename ? entry.isFile() : entry.isDirectory()) &&
        (await realpath(current)).toLowerCase() === current.toLowerCase(),
      'Windows shim smoke requires canonical fixed system executables');
    }
  }
}

// Resolve via the public export in the installed consumer, never via checkout dist/.
export async function installedApiSmoke() {
  const { default: assert } = await import('node:assert/strict');
  const { createRequire } = await import('node:module');
  const { open, readFile } = await import('node:fs/promises');
  const api = await import('@msn-control/missionspec');
  const manifestUrl = import.meta.resolve('@msn-control/missionspec/package.json');
  const manifest = JSON.parse(await readFile(new URL(manifestUrl), 'utf8'));
  assert.equal(api.ENGINE_IDS.length, 6);
  assert.equal(api.OPERATION_IDS.length, 12);
  const catalog = await api.loadPackagedSkillCatalog();
  assert.deepEqual(Object.keys(catalog.manifest.operations), api.OPERATION_IDS);
  const skills = api.renderSkillSet(catalog, ['copilot', 'codex', 'claude'], manifest.version);
  assert.equal(skills.length, 36);
  assert.equal(new Set(skills.map((skill) => skill.path)).size, 36);
  assert(skills.every((skill) => skill.content.includes('missionspec-') && !skill.content.includes('{{')));
  await assert.rejects(import('@msn-control/missionspec/dist/cli/main.js'), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' });
  const require = createRequire(manifestUrl);
  const native = require('fs-native-extensions');
  const addon = Object.keys(require.cache).filter((file) => file.endsWith('.node') && file.includes('fs-native-extensions'));
  assert.equal(addon.length, 1, 'Installed native addon was not loaded');
  if (process.platform !== 'win32') {
    const handle = await open('native-lock.fixture', 'wx', 0o600);
    try {
      assert.equal(native.tryLock(handle.fd), true);
      native.unlock(handle.fd);
    } finally { await handle.close(); }
  }
  const drafts = Object.fromEntries(skills.filter((skill) => skill.operation === 'draft')
    .map((skill) => [skill.host, { path: skill.path, digest: api.digestContent(skill.content) }]));
  process.stdout.write(`${JSON.stringify({ engines: api.ENGINE_IDS.length, skills: skills.length, drafts,
    nativeAddon: addon[0].replaceAll('\\', '/').split('fs-native-extensions/').pop(),
    nativeLock: process.platform === 'win32' ? 'not-exercised; POSIX mutex only' : 'descriptor-lock-unlock',
    platform: process.platform, arch: process.arch })}\n`);
}

async function installedFiles(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = `${prefix}${entry.name}`;
    if (entry.isDirectory()) files.push(...await installedFiles(path.join(directory, entry.name), `${relative}/`));
    else {
      assert(entry.isFile(), `Unexpected non-regular installed package file: ${relative}`);
      files.push(relative);
    }
  }
  return files.sort();
}

export async function checkInstalledPackage(npmPath) {
  const { temporary, consumer, home } = await createInstallWorkspace();
  try {
    const npm = (args, cwd) => executePackageCommand(process.execPath, [npmPath, ...args], {
      cwd, maxBuffer: 4 * 1024 * 1024, timeout: 120_000,
    });
    const { stdout } = await npm(['pack', '--offline', '--ignore-scripts', '--json', '--pack-destination', temporary], root);
    const preview = parsePackPreview(stdout);
    assert.equal(path.basename(preview.filename), preview.filename, 'Invalid archive filename');
    const archive = await readFile(path.join(temporary, preview.filename));
    assert.equal(`sha512-${createHash('sha512').update(archive).digest('base64')}`, preview.integrity);
    await writeFile(path.join(temporary, 'candidate.tgz'), archive);
    const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
    assert.deepEqual([...packageProblems(preview), ...packageManifestProblems(manifest)], []);
    const fixture = createInstallFixture(manifest, JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8')), preview);
    await Promise.all([
      writeFile(path.join(consumer, 'package.json'), JSON.stringify(fixture.manifest)),
      writeFile(path.join(consumer, 'package-lock.json'), JSON.stringify(fixture.lock)),
    ]);
    try {
      await npm(['ci', '--offline', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', '--engine-strict'], consumer);
    } catch (error) {
      if (/ENOTCACHED|cache mode is ['"]only-if-cached['"]/.test(error.stderr ?? '')) {
        throw new Error('Offline install blocked: reviewed dependency tarballs are missing from the npm cache. Restore the existing lock with npm ci --ignore-scripts --no-audit --no-fund, then retry; no registry fallback was attempted.');
      }
      throw error;
    }
    const installedRoot = path.join(consumer, 'node_modules', packageName);
    assert.deepEqual(await installedFiles(installedRoot), preview.files.map((file) => file.path).sort(),
      'Installed package tree differs from the real archive inventory');
    for (const file of preview.files) {
      assert.equal((await stat(path.join(installedRoot, file.path))).size, file.size, `Installed file size: ${file.path}`);
    }
    const installedManifest = JSON.parse(await readFile(path.join(installedRoot, 'package.json'), 'utf8'));
    assert.deepEqual(installedManifest, manifest);
    assert.deepEqual(await packageLinkProblems(preview, (file) => readFile(path.join(installedRoot, file), 'utf8')), []);
    const actualLock = JSON.parse(await readFile(path.join(consumer, 'node_modules/.package-lock.json'), 'utf8'));
    assert.deepEqual(Object.keys(actualLock.packages).sort(), Object.keys(fixture.lock.packages).filter(Boolean).sort());
    for (const location of fixture.locations) {
      for (const key of ['version', 'resolved', 'integrity']) {
        assert.equal(actualLock.packages[location][key], fixture.lock.packages[location][key], `${location}: ${key}`);
      }
      const dependency = JSON.parse(await readFile(path.join(consumer, location, 'package.json'), 'utf8'));
      assert.equal(dependency.version, fixture.lock.packages[location].version, location);
      assert(!installHooks.some((hook) => Object.hasOwn(dependency.scripts ?? {}, hook)), `Install lifecycle script: ${location}`);
      assert(!await stat(path.join(consumer, location, 'binding.gyp')).then(() => true, (error) => {
        if (error.code === 'ENOENT') return false;
        throw error;
      }), `Implicit node-gyp install: ${location}`);
    }
    const guard = path.join(consumer, 'guard.mjs');
    const smoke = path.join(consumer, 'smoke.mjs');
    const receipt = path.join(temporary, 'guard-receipt');
    const proposal = 'proposal with spaces.md';
    await Promise.all([
      writeFile(guard, `await (${installSmokeGuard.toString()})(${JSON.stringify(receipt)});\n`),
      writeFile(smoke, `await (${installedApiSmoke.toString()})();\n`),
      readFile(path.join(installedRoot, 'assets/workflows/compact/examples/proposal.md'))
        .then((content) => writeFile(path.join(consumer, proposal), content)),
    ]);
    const options = { cwd: consumer, env: installSmokeEnvironment(home, guard), timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024, shell: false, windowsHide: true };
    const run = async ({ command, args, options: launchOptions = {} }, expectedCode = 0) => {
      let output;
      let code = 0;
      try {
        output = await executePackageCommand(command, args, { ...options, ...launchOptions });
      } catch (error) {
        if (!Number.isInteger(error.code) || error.killed || error.signal || error.packageExecution?.timedOut) {
          throw new Error(`Installed smoke process failed: ${JSON.stringify(packageProcessFailure(error))}`);
        }
        output = error;
        code = error.code;
      }
      assert.equal(code, expectedCode,
        `Installed smoke process failed: ${JSON.stringify(packageProcessFailure({ ...output, code }))}`);
      assert.equal(await readFile(receipt, 'utf8'), '0', 'Installed process did not complete with its inert smoke guard');
      await rm(receipt);
      return JSON.parse(output.stdout);
    };
    const { drafts, ...api } = await run({ command: process.execPath, args: [smoke] });
    const bin = path.join(consumer, 'node_modules/.bin/missionspec');
    const surfaces = process.platform === 'win32' ? ['cmd', 'powershell'] : ['posix'];
    if (process.platform === 'win32') {
      await checkWindowsInterpreters();
      for (const extension of ['cmd', 'ps1']) {
        const shim = await lstat(`${bin}.${extension}`);
        assert(shim.isFile() && !shim.isSymbolicLink(), `Missing regular npm ${extension} shim`);
      }
    } else {
      assert.equal(await realpath(bin), await realpath(path.join(installedRoot, manifest.bin.missionspec)));
      assert((await stat(bin)).mode & 0o111, 'Installed bin must be executable');
    }
    for (const surface of surfaces) {
      const invoke = (args, code = 0) => run(surface === 'posix' ? { command: bin, args: [...args, '--json'] } :
        windowsShimInvocation(surface, bin, [...args, '--json']), code);
      const cli = async (args) => {
        const result = await invoke(args);
        assert.equal(result.status, 'ok');
        return result.value;
      };
      assert.equal((await cli(['--version'])).version, manifest.version);
      const capabilities = await cli(['capabilities']);
      assert.equal(capabilities.executionAvailable, false);
      assert(capabilities.hosts.every((host) => host.qualifiedVersions.length === 0));
      assert.equal((await cli(['skills', 'list'])).skills.length, 12);
      for (const host of ['copilot', 'codex', 'claude']) {
        const skill = await cli(['skills', 'render', '--host', host, '--operation', 'draft']);
        assert.equal(skill.installed, false);
        assert.equal(skill.hostQualified, false);
        assert.equal(skill.path, drafts[host].path);
        assert.equal(`sha256:${createHash('sha256').update(skill.content).digest('hex')}`, drafts[host].digest,
          `${surface} changed the ${host} rendered skill content`);
      }
      const validated = await cli(['validate', proposal]);
      assert.equal(validated.state, 'valid');
      assert.deepEqual(validated.documents.map((document) => document.path), [proposal]);
      assert.equal(validated.authorityIssued, false);
      assert.equal((await cli(['telemetry', 'status'])).configured, false);
      const invalid = await invoke(['--unrecognized-option'], 1);
      assert.equal(invalid.status, 'failed');
      assert.equal(invalid.error.code, 'invalid-input');
      const blocked = await invoke(['run', 'CHG-install-smoke'], 2);
      assert.equal(blocked.status, 'blocked');
      assert.equal(blocked.error.code, 'host-unqualified');
    }
    assert.deepEqual(await readdir(home), [], 'Read-only smoke created user state');
    const expected = ['guard.mjs', 'node_modules', 'package-lock.json', 'package.json', 'smoke.mjs', proposal,
      ...(process.platform === 'win32' ? [] : ['native-lock.fixture'])].sort();
    assert.deepEqual((await readdir(consumer)).sort(), expected, 'Read-only smoke created project state');
    return { ...api, runtimeDependencies: fixture.locations.length, archiveFiles: preview.files.length,
      integrity: preview.integrity, bin: process.platform === 'win32' ? 'npm .cmd and PowerShell .ps1 shims' : 'npm executable link',
      cliSurfaces: surfaces };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  try {
    const npmPath = process.env.npm_execpath;
    if (!npmPath || !path.isAbsolute(npmPath)) throw new Error('Run this check through npm run check:package');
    if (process.argv.slice(2).some((arg) => arg !== '--install')) throw new Error('Only --install is supported');
    if (process.argv.includes('--install')) {
      const result = await checkInstalledPackage(npmPath);
      process.stdout.write(`Offline packed install passed: ${JSON.stringify(result)}\n`);
    } else {
      const { stdout } = await execute(process.execPath, [
        npmPath, 'pack', '--dry-run', '--ignore-scripts', '--json',
      ], {
        cwd: root,
        maxBuffer: 4 * 1024 * 1024,
        timeout: 60_000,
      });
      const preview = parsePackPreview(stdout);
      const problems = [
        ...packageProblems(preview),
        ...packageManifestProblems(JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'))),
        ...await packageLinkProblems(preview, (file) => readFile(path.join(root, file), 'utf8')),
      ];
      if (problems.length) {
        process.stderr.write(`${problems.join('\n')}\n`);
        process.exitCode = 1;
      } else {
        process.stdout.write(`Package boundary passed: ${OPERATION_IDS.length} canonical skill bodies; no project state or operator service.\n`);
      }
    }
  } catch (error) {
    process.stderr.write(`Package check could not complete: ${
      error.packageExecution ? JSON.stringify(packageProcessFailure(error)) : error.message}\n`);
    process.exitCode = 1;
  }
}
