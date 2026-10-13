import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { connect, type Socket } from 'node:net';
import { WorkflowError } from '../../application/errors.js';
import type { LocalConfirmationDecision, LocalConfirmationReview } from '../authority/local-authority.js';
import { windowsExecutionAsset, windowsExecutionFailure, windowsPowerShell } from './windows-execution.js';

/** No file, environment variable, isTTY bit or caller-supplied decision grants authority. */
export async function confirmWindowsConsole(review: LocalConfirmationReview, signal: AbortSignal): Promise<LocalConfirmationDecision> {
  if (signal.aborted) return 'cancel';
  const remaining = Math.min(Date.parse(review.deadlineAt), Date.parse(review.expiresAt)) - Date.now();
  if (!Number.isFinite(remaining) || remaining <= 0 || remaining > 120_000) return 'cancel';
  const helper = windowsExecutionAsset('windows-console.ps1');
  if (signal.aborted || Date.now() >= Date.parse(review.deadlineAt)) return 'cancel';
  const name = `missionspec-console-${randomBytes(32).toString('hex')}`;
  const correlation = randomBytes(32).toString('hex');
  const request = Buffer.from(JSON.stringify({
    correlation, challenge: `confirm ${randomBytes(16).toString('hex')}`,
    display: review.renderedDisplay, action: review.action, expires: review.expiresAt, deadline: review.deadlineAt,
  }));
  if (request.length > 6_000_000) return 'unavailable';
  const length = Buffer.alloc(4);
  length.writeUInt32LE(request.length);
  return new Promise((resolve, reject) => {
    const child = spawn(windowsPowerShell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', helper,
      '-PipeName', name, '-ParentProcess', String(process.pid)], {
      shell: false, windowsHide: false, stdio: ['inherit', 'pipe', 'inherit'],
    });
    let socket: Socket | undefined;
    let buffer = '';
    let ready = false;
    let invalid = false;
    let cancelled = false;
    let terminal: LocalConfirmationDecision | undefined;
    let nativeFailure: string | undefined;
    const cancel = () => { cancelled = true; child.kill(); socket?.destroy(); };
    const fail = () => { invalid = true; child.kill(); socket?.destroy(); };
    const timer = setTimeout(cancel, Math.max(0, Date.parse(review.deadlineAt) - Date.now()));
    signal.addEventListener('abort', cancel, { once: true });
    const finish = (decision: LocalConfirmationDecision) => {
      clearTimeout(timer);
      signal.removeEventListener('abort', cancel);
      socket?.destroy();
      resolve(decision);
    };
    child.stdout.setEncoding('utf8');
    child.stdout.on('error', fail);
    child.stdout.on('data', (chunk: string) => {
      buffer += chunk;
      if (buffer.length > 4096) { fail(); return; }
      while (buffer.includes('\n')) {
        const end = buffer.indexOf('\n');
        const line = buffer.slice(0, end);
        buffer = buffer.slice(end + 1);
        try {
          const frame: unknown = JSON.parse(line);
          if (typeof frame !== 'object' || frame === null || terminal !== undefined) { fail(); return; }
          if (!ready && Object.keys(frame).length === 1 && Reflect.get(frame, 'phase') === 'ready') {
            ready = true;
            socket = connect(`\\\\.\\pipe\\${name}`);
            socket.on('error', fail);
            socket.on('connect', () => socket?.end(Buffer.concat([length, request])));
          } else if (ready && Object.keys(frame).sort().join(',') === 'correlation,decision,ok' &&
              Reflect.get(frame, 'ok') === true && Reflect.get(frame, 'correlation') === correlation) {
            const decision: unknown = Reflect.get(frame, 'decision');
            if (decision !== 'accept' && decision !== 'decline' && decision !== 'cancel') { fail(); return; }
            terminal = decision;
          } else {
            if (Reflect.get(frame, 'ok') === false && Reflect.get(frame, 'phase') !== 'console') {
              nativeFailure = windowsExecutionFailure(frame);
            }
            fail(); return;
          }
        } catch { fail(); return; }
      }
    });
    child.once('error', () => finish('unavailable'));
    child.once('close', (code) => {
      if (!cancelled && nativeFailure !== undefined) {
        clearTimeout(timer);
        signal.removeEventListener('abort', cancel);
        socket?.destroy();
        reject(new WorkflowError('capability-unavailable', `Windows console confirmation was not established (${nativeFailure}).`));
        return;
      }
      finish(cancelled || signal.aborted || Date.now() >= Date.parse(review.deadlineAt) || Date.now() >= Date.parse(review.expiresAt)
        ? 'cancel' : invalid || code !== 0 || buffer.trim() !== '' ? 'unavailable' : terminal ?? 'unavailable');
    });
    if (signal.aborted) cancel();
  });
}
