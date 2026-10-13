import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { inspectCopilotSubscription } from '../../dist/adapters/hosts/copilot-subscription-preflight.js';
import { startNativeProcess, stopNativeProcess } from '../../dist/adapters/hosts/process.js';

export const METADATA_METHODS = Object.freeze([
  'connect', 'status.get', 'auth.getStatus', 'user.settings.get', 'models.list', 'account.getQuota',
]);
const MAX_BYTES = 2_000_000;
const TIMEOUT_MS = 30_000;

export function metadataLimits({ timeoutMs = TIMEOUT_MS, maxOutputBytes = MAX_BYTES } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > TIMEOUT_MS ||
      !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 128 || maxOutputBytes > MAX_BYTES) {
    throw new Error('Metadata limits may be tightened, not expanded.');
  }
  return Object.freeze({ timeoutMs, maxOutputBytes });
}

export function metadataArguments(host, logs) {
  if (host === 'copilot') return ['--headless', '--stdio', '--no-auto-update', '--log-level', 'none', '--log-dir', logs];
  if (host === 'claude') return ['auth', 'status', '--json'];
  throw new Error('Only Copilot and Claude non-generating metadata are supported; Codex qualification is deferred.');
}

function sandboxPolicy({ executable, home, nativeHome, work, logs, host = 'copilot' }, offline = false) {
  const systemRoots = ['/System', '/usr', '/bin', '/sbin', '/Library', '/opt/homebrew', '/private/var/db', '/dev'];
  const roots = [...new Set([...systemRoots, path.dirname(executable), work, logs])];
  const literalReads = [
    '/', // dyld needs a root-directory handle, not recursive access beneath it.
    process.execPath,
    path.join(nativeHome, 'settings.json'),
    ...(host === 'claude' ? [path.join(home, '.claude.json')] : [path.join(nativeHome, 'config.json')]),
  ];
  return `(version 1)
(allow default)
(deny file-read-data (require-not (require-any ${roots.map(root => `(subpath ${JSON.stringify(root)})`).join(' ')}
  ${literalReads.map(file => `(literal ${JSON.stringify(file)})`).join(' ')})))
(deny file-write* (require-not (require-any (subpath ${JSON.stringify(work)}) (subpath ${JSON.stringify(logs)}) (literal "/dev/null"))))
${offline ? '(deny network*)' : ''}`;
}

async function workspace() {
  const root = await mkdtemp(path.join(process.cwd(), '.native-metadata-qualification-'));
  const work = path.join(root, 'work'), logs = path.join(root, 'logs'), blocked = path.join(root, 'blocked');
  await mkdir(work, { mode: 0o700 });
  await mkdir(logs, { mode: 0o700 });
  await mkdir(blocked, { mode: 0o700 });
  await writeFile(path.join(work, 'package.json'), '{"type":"module"}\n', { mode: 0o600 });
  return { root, work, logs, blocked };
}

function launch(launchOptions, framed = false, syntheticDiagnostics = false, limits = metadataLimits()) {
  const child = startNativeProcess(launchOptions);
  const pending = new Map(), methods = [];
  const diagnosticKinds = new Set();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let buffer = Buffer.alloc(0), stdout = '', diagnostic = '', bytes = 0, failure, sequence = 0, closing = false;
  function fail(reason) {
    if (failure) return;
    failure = new Error(reason);
    for (const call of pending.values()) call.reject(failure);
    pending.clear();
    stopNativeProcess(child);
  }
  const deadline = setTimeout(() => fail('Metadata deadline exceeded; remote quiescence is not established.'), limits.timeoutMs);
  const done = new Promise(resolve => child.once('close', (code, signal) => {
    clearTimeout(deadline);
    try { if (!framed) stdout += decoder.decode(); } catch { fail('Invalid UTF-8 metadata output.'); }
    if (framed && buffer.length) fail('Incomplete metadata frame.');
    if (pending.size) fail('Metadata process exited before responding.');
    resolve({ code, signal, pid: child.pid, stdout, bytes, diagnosticKinds: [...diagnosticKinds], diagnostic });
  }));
  child.on('error', () => fail('Metadata process could not start.'));
  child.stdin.on('error', () => { if (!closing) fail('Metadata input closed.'); });
  child.stderr.on('data', chunk => {
    bytes += chunk.length;
    if (syntheticDiagnostics) diagnostic = `${diagnostic}${chunk.toString('utf8')}`.slice(0, 4096);
    for (const kind of chunk.toString('utf8').match(/ERR_[A-Z_]+|\b(?:EPERM|EACCES|ENOENT|Permission denied|Operation not permitted|sandbox-exec|uv_cwd|package\.json)\b/gu) ?? []) diagnosticKinds.add(kind);
    for (const resource of ['.copilot', '.claude', 'resolv.conf', 'localtime', 'cert.pem', 'settings.json', 'config.json', 'hosts.yml', 'Keychains', 'plugins', 'skills']) {
      if (chunk.toString('utf8').includes(resource)) diagnosticKinds.add(resource);
    }
    if (bytes > limits.maxOutputBytes) fail('Metadata byte limit exceeded.');
  });
  child.stdout.on('data', chunk => {
    if (failure) return;
    try {
      bytes += chunk.length;
      if (bytes > limits.maxOutputBytes) { fail('Metadata byte limit exceeded.'); return; }
      if (!framed) { stdout += decoder.decode(chunk, { stream: true }); return; }
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const match = /^Content-Length: (\d+)$/im.exec(buffer.subarray(0, end).toString('ascii'));
        if (!match) throw new Error();
        const length = Number(match[1]);
        if (!Number.isSafeInteger(length) || length > limits.maxOutputBytes) throw new Error();
        if (buffer.length < end + 4 + length) return;
        const message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(end + 4, end + 4 + length)));
        buffer = buffer.subarray(end + 4 + length);
        if (typeof message !== 'object' || message === null || Array.isArray(message) ||
            message.method !== undefined || message.params !== undefined ||
            (message.jsonrpc !== undefined && message.jsonrpc !== '2.0') ||
            Object.keys(message).some(key => !['jsonrpc', 'id', 'result', 'error'].includes(key)) ||
            ('result' in message) === ('error' in message)) throw new Error();
        const call = pending.get(message.id);
        if (!call) throw new Error();
        if (message.error !== undefined) { pending.delete(message.id); call.reject(new Error('Native metadata request rejected.')); continue; }
        if (call.method === 'user.settings.get') {
          const settings = message.result?.settings;
          if (typeof settings !== 'object' || settings === null || Array.isArray(settings)) throw new Error();
          pending.delete(message.id);
          call.resolve({ settings: { model: settings.model } });
        } else { pending.delete(message.id); call.resolve(message.result); }
      }
    } catch { fail('Unexpected or malformed metadata protocol output.'); }
  });
  return {
    methods,
    get failureReason() { return failure?.message; },
    get diagnosticKinds() { return [...diagnosticKinds]; },
    request(method, params = {}) {
      if (failure || closing) return Promise.reject(failure ?? new Error('Metadata transport closed.'));
      if (!framed || !METADATA_METHODS.includes(method)) return Promise.reject(new Error('Non-metadata method refused.'));
      const id = `metadata-${++sequence}`;
      return new Promise((resolve, reject) => {
        pending.set(id, { method, resolve, reject });
        methods.push(method);
        const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        child.stdin.write(Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`), body]));
      });
    },
    endInput() { child.stdin.end(); },
    async result() {
      const result = await done;
      if (failure) throw failure;
      return result;
    },
    async close() { closing = true; stopNativeProcess(child); await done; },
  };
}

function requireMacOS() {
  if (process.platform !== 'darwin') throw new Error('This qualification harness is macOS-only; no other-platform confinement is claimed.');
}

function environment(home, work) {
  const env = {
    HOME: home, PATH: '/opt/homebrew/bin:/usr/bin:/bin', TMPDIR: work, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
    DO_NOT_TRACK: '1', DISABLE_AUTOUPDATER: '1', GIT_CEILING_DIRECTORIES: work,
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
  };
  for (const key of ['USER', 'LOGNAME']) if (process.env[key]) env[key] = process.env[key];
  return env;
}

async function readMetadata(host, { executable, confirmedLoginDigest, homeDirectory, limits: requestedLimits } = {}, sourceConfined) {
  requireMacOS();
  metadataArguments(host, '');
  const limits = metadataLimits(requestedLimits);
  const files = await workspace();
  let connection, phase = 'setup';
  try {
    const home = await realpath(homeDirectory ?? os.homedir());
    const nativeHome = await realpath((homeDirectory === undefined ? process.env[host === 'copilot' ? 'COPILOT_HOME' : 'CLAUDE_CONFIG_DIR'] : undefined) ?? path.join(home, `.${host}`));
    const native = await realpath(executable ?? `/opt/homebrew/bin/${host}`);
    const env = environment(home, files.work);
    env[host === 'copilot' ? 'COPILOT_HOME' : 'CLAUDE_CONFIG_DIR'] = nativeHome;
    const policy = sourceConfined
      ? sandboxPolicy({ executable: native, home, nativeHome, host, ...files })
      : `(version 1)(allow default)(deny file-write* (subpath ${JSON.stringify(nativeHome)}) (literal ${JSON.stringify(path.join(home, '.claude.json'))}))`;
    if (host === 'claude') {
      phase = 'version';
      connection = launch({ executable: '/usr/bin/sandbox-exec', argv: ['-p', policy, native, '--version'], cwd: files.work, environment: env }, false, false, limits);
      connection.endInput();
      const version = await connection.result();
      if (version.code !== 0 || version.stdout.trim() !== '2.1.267 (Claude Code)') throw new Error('Unreviewed Claude metadata CLI version.');
      await connection.close();
    }
    phase = 'metadata-read';
    connection = launch({
      executable: '/usr/bin/sandbox-exec',
      argv: ['-p', policy, native, ...metadataArguments(host, files.logs)],
      cwd: files.work, environment: env,
    }, host === 'copilot', false, limits);
    let observation;
    if (host === 'copilot') {
      phase = 'connect';
      const connected = await connection.request('connect', { supportedTaskKinds: [] });
      if (connected.protocolVersion !== 3) throw new Error('Unreviewed Copilot metadata protocol.');
      phase = 'account-model-quota';
      observation = await inspectCopilotSubscription(connection, confirmedLoginDigest);
    } else {
      connection.endInput();
      const result = await connection.result();
      const auth = JSON.parse(result.stdout);
      if (![0, 1].includes(result.code) || typeof auth.loggedIn !== 'boolean' ||
          typeof auth.authMethod !== 'string' || typeof auth.apiProvider !== 'string') {
        throw new Error('Unsupported Claude authentication status output.');
      }
      observation = {
        cliVersion: '2.1.267', exitCode: result.code, loggedIn: auth.loggedIn, authMethod: auth.authMethod, apiProvider: auth.apiProvider,
        subscriptionType: typeof auth.subscriptionType === 'string' ? auth.subscriptionType : null,
        identityDigest: typeof auth.email === 'string' ? `sha256:${createHash('sha256').update(auth.email.trim().toLowerCase()).digest('hex')}` : null,
        resolvedDefaultModel: null,
      };
    }
    await connection.close();
    await connection.result();
    return {
      host, observedAt: new Date().toISOString(), status: 'metadata-read-completed', observation,
      methods: connection.methods, modelCalls: 0, sessionsCreated: 0,
      confinement: sourceConfined ? 'macOS-metadata-filesystem-profile' : 'explicit-baseline-native-home-write-protection-only',
      network: 'permitted-not-endpoint-confined',
      limits: { timeoutMsPerProcess: limits.timeoutMs, maxOutputBytesPerProcess: limits.maxOutputBytes },
      pilotAdmission: 'required', timeoutProvesRemoteQuiescence: false,
    };
  } catch (error) {
    return {
      host, observedAt: new Date().toISOString(), status: 'blocked', phase,
      code: ['invalid-input', 'unsupported-version', 'capability-unavailable', 'scope-exceeded', 'authority-required', 'limit-reached'].includes(error?.code) ? error.code : 'metadata-read-failed',
      reason: connection?.failureReason ?? 'Native metadata inspection failed.',
      diagnosticKinds: connection?.diagnosticKinds ?? [], methods: connection?.methods ?? [],
      modelCalls: 0, sessionsCreated: 0, pilotAdmission: 'required',
      limits: { timeoutMsPerProcess: limits.timeoutMs, maxOutputBytesPerProcess: limits.maxOutputBytes },
      timeoutProvesRemoteQuiescence: false,
      confinement: sourceConfined ? 'macOS-metadata-filesystem-profile' : 'explicit-baseline-native-home-write-protection-only',
      message: 'Metadata inspection failed; no automatic fallback was attempted.',
    };
  } finally {
    await connection?.close();
    await rm(files.root, { recursive: true, force: true });
  }
}

export function readConfinedMetadata(host, options) { return readMetadata(host, options, true); }
export function readNormalMetadata(host, options) { return readMetadata(host, options, false); }

export async function probeMetadataConfinement() {
  requireMacOS();
  const files = await workspace();
  const executable = await realpath(process.execPath);
  const home = await realpath(os.homedir());
  const context = { executable, home, nativeHome: path.join(home, '.copilot'), ...files };
  const server = createServer(socket => socket.end());
  let child;
  try {
    await writeFile(path.join(files.work, 'allowed.txt'), 'synthetic allowed content');
    await writeFile(path.join(files.blocked, 'private.txt'), 'synthetic outside content');
    await symlink(path.join(files.blocked, 'private.txt'), path.join(files.work, 'escape.txt'));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const port = server.address().port;
    const networkProbe = `import net from 'node:net'; const s=net.connect(${port},'127.0.0.1'); s.on('connect',()=>{s.end();console.log('connected');}); s.on('error',e=>{console.log(e.code);process.exitCode=2;}); setTimeout(()=>process.exit(3),2000).unref();`;
    child = launch({ executable, argv: ['--input-type=module', '-e', networkProbe], cwd: files.work, environment: environment(home, files.work) });
    child.endInput();
    const control = await child.result();
    if (control.code !== 0 || control.stdout.trim() !== 'connected') throw new Error('Network positive control failed.');
    const fileProbe = `import fs from 'node:fs';
const denied=(fn)=>{try{fn();return false;}catch(e){return ['EPERM','EACCES'].includes(e.code);}};
const report={
 insideRead:fs.readFileSync('allowed.txt','utf8')==='synthetic allowed content',
 insideWrite:(fs.writeFileSync('allowed-write.txt','synthetic'),true),
 outsideReadDenied:denied(()=>fs.readFileSync(${JSON.stringify(path.join(files.blocked, 'private.txt'))})),
 symlinkReadDenied:denied(()=>fs.readFileSync('escape.txt')),
 outsideWriteDenied:denied(()=>fs.writeFileSync(${JSON.stringify(path.join(files.blocked, 'write.txt'))},'forbidden')),
}; console.log(JSON.stringify(report));`;
    child = launch({ executable: '/usr/bin/sandbox-exec', argv: ['-p', sandboxPolicy(context), executable, '--input-type=module', '-e', fileProbe], cwd: files.work, environment: environment(home, files.work) }, false, true);
    child.endInput();
    const fileResult = await child.result();
    if (fileResult.code !== 0) throw new Error(`Filesystem confinement probe failed (${fileResult.code}; ${fileResult.signal}; pid ${fileResult.pid}): ${fileResult.diagnostic}`);
    const checks = JSON.parse(fileResult.stdout);
    if (Object.values(checks).some(value => value !== true)) throw new Error('Filesystem confinement did not enforce the expected boundary.');
    if (await readFile(path.join(files.blocked, 'private.txt'), 'utf8') !== 'synthetic outside content') throw new Error('Outside sentinel changed.');
    if (JSON.stringify(await readdir(files.blocked)) !== JSON.stringify(['private.txt'])) throw new Error('Unexpected outside write.');
    child = launch({ executable: '/usr/bin/sandbox-exec', argv: ['-p', sandboxPolicy(context, true), executable, '--input-type=module', '-e', networkProbe], cwd: files.work, environment: environment(home, files.work) });
    child.endInput();
    const network = await child.result();
    if (network.code !== 2 || !['EPERM', 'EACCES'].includes(network.stdout.trim())) throw new Error('Offline network denial was not established.');
    return { observedAt: new Date().toISOString(), ...checks, networkPositiveControl: true, offlineNetworkDenied: true, onlineMetadataNetworkConfined: false, modelCalls: 0, sessionsCreated: 0, remoteQuiescenceEstablished: false };
  } finally {
    await child?.close();
    if (server.listening) await new Promise(resolve => server.close(resolve));
    await rm(files.root, { recursive: true, force: true });
  }
}
