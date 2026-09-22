import { spawn } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WorkflowError } from '../../application/errors.js';
import { requireWindowsPrivateState, windowsPrivateEntries } from './windows-private-state.js';

export const windowsPowerShell = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

/** Uses the already-qualified fixed OS executable/ACL check, never PATH or an override. */
export function windowsExecutionAsset(name: 'windows-check-process.ps1' | 'windows-console.ps1'): string {
  requireWindowsPrivateState();
  windowsPrivateEntries([]);
  const filename = fileURLToPath(new URL(`../../../assets/platform/${name}`, import.meta.url));
  for (const resource of [filename, fileURLToPath(new URL('../../../assets/platform/windows-execution-native.ps1', import.meta.url))]) {
    const entry = lstatSync(resource);
    if (!entry.isFile() || entry.isSymbolicLink() || realpathSync.native(resource) !== resource) {
      throw new WorkflowError('check-unqualified', 'A packaged Windows execution resource is not a canonical regular file.');
    }
  }
  return filename;
}

export function windowsExecutionFailure(value: unknown): string {
  if (typeof value !== 'object' || value === null) return 'invalid-response';
  const phase: unknown = Reflect.get(value, 'phase');
  const line: unknown = Reflect.get(value, 'line');
  const phases = ['bootstrap', 'input', 'console', 'pipe', 'display', 'challenge', 'path', 'executable',
    'job', 'pipes', 'attributes', 'create', 'membership', 'resume', 'capture', 'accounting', 'cancel', 'close'];
  return `${typeof phase === 'string' && phases.includes(phase) ? phase : 'native-failure'}${
    typeof line === 'number' && Number.isSafeInteger(line) && line > 0 && line < 10_000 ? `; line=${line}` : ''}`;
}

export interface WindowsCheckLaunch {
  readonly program: string;
  readonly programDigest: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
}

export interface WindowsCheckObservation {
  readonly exitCode: number | null;
  readonly signal: null;
  readonly interrupted: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly quiescence: 'confirmed' | 'unconfirmed';
}

export function parseWindowsCheckObservation(value: unknown): WindowsCheckObservation {
  const fail = (): never => { throw new WorkflowError('effect-outcome-unknown', 'The owned Windows job did not supply a complete bounded observation.'); };
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'exitCode,interrupted,ok,quiescence,stderr,stdout' || Reflect.get(value, 'ok') !== true) return fail();
  const exitCode: unknown = Reflect.get(value, 'exitCode');
  const interrupted: unknown = Reflect.get(value, 'interrupted');
  const quiescence: unknown = Reflect.get(value, 'quiescence');
  const stdout: unknown = Reflect.get(value, 'stdout');
  const stderr: unknown = Reflect.get(value, 'stderr');
  if ((exitCode !== null && (typeof exitCode !== 'number' || !Number.isInteger(exitCode) || exitCode < 0 || exitCode > 0xffff_ffff)) ||
      typeof interrupted !== 'boolean' || !['confirmed', 'unconfirmed'].includes(String(quiescence)) ||
      (!interrupted && (exitCode === null || quiescence !== 'confirmed')) ||
      typeof stdout !== 'string' || typeof stderr !== 'string') return fail();
  const decode = (data: string): Buffer => {
    const bytes = Buffer.from(data, 'base64');
    if (bytes.toString('base64') !== data) return fail();
    return bytes;
  };
  const out = decode(stdout);
  const err = decode(stderr);
  if (out.length + err.length > 1_000_000) return fail();
  return { exitCode, signal: null, interrupted, quiescence: quiescence === 'confirmed' ? 'confirmed' : 'unconfirmed',
    stdout: out.toString('utf8'), stderr: err.toString('utf8') };
}

export async function executeWindowsCheck(input: WindowsCheckLaunch, signal?: AbortSignal): Promise<WindowsCheckObservation> {
  const helper = windowsExecutionAsset('windows-check-process.ps1');
  if (signal?.aborted) throw new WorkflowError('effect-outcome-unknown', 'Windows check execution was cancelled before launch.');
  if (!Number.isSafeInteger(input.timeoutMs) || input.timeoutMs < 1 || input.timeoutMs > 300_000 ||
      !/^sha256:[a-f0-9]{64}$/u.test(input.programDigest) ||
      input.argv.some((arg) => typeof arg !== 'string' || arg.includes('\0'))) {
    throw new WorkflowError('check-unqualified', 'Windows checks require bounded exact executable, arguments and timeout.');
  }
  const cwd = lstatSync(input.cwd, { bigint: true });
  windowsPrivateEntries([{ path: input.cwd, directory: true, writable: true }]);
  return new Promise((resolve, reject) => {
    const child = spawn(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper], {
      shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    let invalid = false;
    const stop = () => { invalid = true; child.kill(); };
    // Native execution keeps its own unchanged check deadline and a 1s cancellation observation.
    // This outer bound also covers helper startup; it never turns a killed helper into evidence.
    const timer = setTimeout(stop, input.timeoutMs + 30_000);
    signal?.addEventListener('abort', stop, { once: true });
    const finish = () => { clearTimeout(timer); signal?.removeEventListener('abort', stop); };
    child.stdout.setEncoding('utf8');
    child.stdout.on('error', stop);
    child.stdout.on('data', (chunk: string) => {
      output += chunk;
      if (output.length > 1_400_000) stop();
    });
    child.stderr.on('data', () => { invalid = true; });
    child.stderr.on('error', stop);
    child.stdin.on('error', () => { invalid = true; });
    child.once('error', () => {
      finish();
      reject(new WorkflowError('effect-outcome-unknown', 'The Windows job supervisor could not be started.'));
    });
    child.once('close', (code) => {
      finish();
      let response: unknown;
      try { response = JSON.parse(output); } catch { invalid = true; }
      if (invalid || code !== 0) {
        reject(new WorkflowError('effect-outcome-unknown', `Windows job supervision was not established (${windowsExecutionFailure(response)}).`));
      } else {
        try { resolve(parseWindowsCheckObservation(response)); } catch (error) { reject(error); }
      }
    });
    child.stdin.end(JSON.stringify({ ...input, parent: process.pid, cwdIdentity: { device: String(cwd.dev), inode: String(cwd.ino) } }));
  });
}
