import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { NativeBridgeError, type NativeHostSetup } from './contracts.js';
import type { NativeHost } from '../../kernel/identifiers.js';

export interface NativeProcessLaunch {
  readonly executable: string;
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
}

export function startNativeProcess(launch: NativeProcessLaunch): ChildProcessWithoutNullStreams {
  return spawn(launch.executable, [...launch.argv], {
    cwd: launch.cwd, env: { ...launch.environment }, shell: false,
    stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  });
}

/** Killing this child is best effort. It is not a descendant or paid-usage fence. */
export function stopNativeProcess(child: ChildProcessWithoutNullStreams) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.stdin.end();
  child.kill('SIGTERM');
  const timer = setTimeout(() => { child.kill('SIGKILL'); }, 200);
  timer.unref();
  child.once('close', () => clearTimeout(timer));
}

export async function inspectCliVersion(
  host: NativeHost, setup: NativeHostSetup, environment: Readonly<Record<string, string>>, signal: AbortSignal,
): Promise<string> {
  if (signal.aborted) throw new NativeBridgeError('effect-outcome-unknown', 'Native startup was interrupted.');
  const child = startNativeProcess({
    executable: setup.executable, argv: ['--version'], cwd: setup.workingDirectory, environment,
  });
  return new Promise<string>((resolve, reject) => {
    let output = '';
    let bytes = 0;
    let settled = false;
    const finish = (error: NativeBridgeError | null, value = '') => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      if (error === null) resolve(value);
      else { stopNativeProcess(child); reject(error); }
    };
    const abort = () => finish(new NativeBridgeError('effect-outcome-unknown', 'Native version inspection was interrupted.'));
    const timer = setTimeout(() => finish(new NativeBridgeError('capability-unavailable', 'Native version inspection timed out.')), 5_000);
    signal.addEventListener('abort', abort, { once: true });
    child.on('error', () => finish(new NativeBridgeError('capability-unavailable', 'The selected native executable could not start.')));
    child.stdin.on('error', () => finish(new NativeBridgeError('capability-unavailable', 'Native version input closed unexpectedly.')));
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 4_096) finish(new NativeBridgeError('unsupported-version', 'Native version output exceeds its limit.'));
      else output += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 4_096) finish(new NativeBridgeError('unsupported-version', 'Native version diagnostics exceed their limit.'));
    });
    child.on('close', (code) => {
      const expressions: Readonly<Record<NativeHost, RegExp>> = {
        copilot: /^(?:GitHub Copilot CLI |copilot )?([0-9]+\.[0-9]+\.[0-9]+)(?:\r?\n)?$/u,
        codex: /^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)(?:\r?\n)?$/u,
        claude: /^([0-9]+\.[0-9]+\.[0-9]+) \(Claude Code\)(?:\r?\n)?$/u,
      };
      const version = expressions[host].exec(output)?.[1];
      if (code !== 0 || version === undefined) {
        finish(new NativeBridgeError('unsupported-version', 'Unrecognized native version output; no inference or fallback is permitted.'));
      } else finish(null, version);
    });
    child.stdin.end();
    if (signal.aborted) abort();
  });
}
