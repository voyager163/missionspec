import { constants } from 'node:fs';
import { lstat, open, readdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { digestContent } from '../../kernel/revisions.js';
import type { NativeHost } from '../../kernel/identifiers.js';
import { NativeBridgeError, NATIVE_PROPOSAL_PINS, type ExternalSdkIdentity, type NativeHostSetup } from './contracts.js';

export async function boundedFile(file: string, maximum: number): Promise<Buffer> {
  if (!path.isAbsolute(file) || await realpath(file) !== file) {
    throw new NativeBridgeError('invalid-input', 'Use a real absolute path without symlink traversal.');
  }
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(maximum)) {
      throw new NativeBridgeError('limit-reached', 'Native installation identity must be a bounded regular file.');
    }
    const bytes = await handle.readFile();
    const after = await lstat(file, { bigint: true });
    if (bytes.length > maximum || before.ino !== after.ino || before.dev !== after.dev ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      throw new NativeBridgeError('unsupported-version', 'Native installation changed during inspection.');
    }
    return bytes;
  } finally { await handle.close(); }
}

export async function inspectSdk(host: 'copilot' | 'claude', sdk: ExternalSdkIdentity) {
  const bytes = await boundedFile(sdk.packageJsonPath, 256_000);
  const manifest: unknown = JSON.parse(bytes.toString('utf8'));
  const pin = NATIVE_PROPOSAL_PINS[host];
  if (typeof manifest !== 'object' || manifest === null ||
      !('name' in manifest) || manifest.name !== pin.sdk ||
      !('version' in manifest) || manifest.version !== pin.sdkVersion ||
      ('gitHead' in manifest && manifest.gitHead !== pin.sourceRevision)) {
    throw new NativeBridgeError('unsupported-version', 'The selected external SDK does not match the reviewed exact pin.');
  }
  return Object.freeze({ name: pin.sdk, version: pin.sdkVersion, manifestDigest: digestContent(bytes) });
}

const credentials: Readonly<Record<NativeHost, readonly string[]>> = Object.freeze({
  copilot: ['COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'],
  codex: ['OPENAI_API_KEY', 'CODEX_API_KEY'],
  claude: ['ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'],
});

async function emptyDirectory(directory: string) {
  if (!path.isAbsolute(directory) || await realpath(directory) !== directory ||
      !(await lstat(directory)).isDirectory() || (await readdir(directory)).length !== 0) {
    throw new NativeBridgeError('invalid-input', 'Native launches require fresh empty real directories, not a source checkout or ambient home.');
  }
}

export async function inspectSetup(host: NativeHost, setup: NativeHostSetup) {
  if (typeof setup.authorizeNativeStart !== 'function' ||
      typeof setup.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/u.test(setup.model)) {
    throw new NativeBridgeError('invalid-input', 'Select an explicit model and trusted external native-start gate.');
  }
  await Promise.all([emptyDirectory(setup.workingDirectory), emptyDirectory(setup.homeDirectory)]);
  if (setup.workingDirectory === setup.homeDirectory ||
      setup.workingDirectory.startsWith(`${setup.homeDirectory}${path.sep}`) ||
      setup.homeDirectory.startsWith(`${setup.workingDirectory}${path.sep}`)) {
    throw new NativeBridgeError('invalid-input', 'The empty working directory and home must be separate.');
  }
  const environment: Record<string, string> = {
    PATH: [path.dirname(process.execPath), '/usr/bin', '/bin'].join(path.delimiter),
    LANG: 'C', LC_ALL: 'C', HOME: setup.homeDirectory, USERPROFILE: setup.homeDirectory,
    XDG_CONFIG_HOME: path.join(setup.homeDirectory, 'config'),
    XDG_CACHE_HOME: path.join(setup.homeDirectory, 'cache'),
    XDG_DATA_HOME: path.join(setup.homeDirectory, 'data'),
  };
  if (Object.keys(setup.environment).length !== 1) {
    throw new NativeBridgeError('authority-required', 'Supply exactly one explicit native authentication variable; ambient login and account selection are not permitted.');
  }
  for (const [key, value] of Object.entries(setup.environment)) {
    if (!credentials[host].includes(key) || typeof value !== 'string' || value.trim().length === 0 ||
        value.length > 16_384 || /[\r\n\0]/u.test(value)) {
      throw new NativeBridgeError('invalid-input', 'Only explicit native authentication variables may be supplied; ambient configuration is refused.');
    }
    environment[key] = value;
  }
  if (host === 'codex') environment.CODEX_HOME = path.join(setup.homeDirectory, 'codex');
  if (host === 'claude') environment.CLAUDE_CONFIG_DIR = path.join(setup.homeDirectory, 'claude');
  return {
    executableDigest: digestContent(await boundedFile(setup.executable, 256_000_000)),
    environment: Object.freeze(environment),
  };
}
