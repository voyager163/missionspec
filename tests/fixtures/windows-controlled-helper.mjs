import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { windowsFailureDiagnostic } from '../../dist/adapters/platform/windows-private-state.js';

const phases = new Set(['created-held', 'file-written', 'delete-held', 'publication-held', 'intent-durable',
  'preimage-renamed', 'preimage-retained', 'source-published', 'publication-durable', 'preimage-delete-held']);
const transportCodes = new Set(['EPIPE', 'ERR_STREAM_DESTROYED', 'ERR_STREAM_WRITE_AFTER_END', 'ENOENT', 'ETIMEDOUT']);

/** Test protocol only. A terminal error also has a phase, but is never an acknowledgement request. */
export function controlHelper(child, request, timeoutMs = 45_000) {
  const queue = [];
  const waiting = [];
  let terminal;
  let exitResult;
  let protocolError;
  let transportError;
  let pending;
  const recordTransport = (error) => { transportError = transportCodes.has(error?.code) ? error.code : 'transport-failed'; };
  child.stdin.on('error', recordTransport);
  child.on('error', recordTransport);
  child.stderr.resume();
  const notify = (frame) => {
    const resolve = waiting.shift();
    if (resolve) resolve(frame); else queue.push(frame);
  };
  const lines = createInterface({ input: child.stdout });
  lines.on('error', () => { protocolError = 'output-read-failed'; });
  lines.on('line', (line) => {
    try {
      const frame = JSON.parse(line);
      if (typeof frame !== 'object' || frame === null || Array.isArray(frame)) throw new Error();
      if (Object.hasOwn(frame, 'ok')) {
        if (terminal !== undefined || typeof frame.ok !== 'boolean') throw new Error();
        terminal = frame;
      } else if (terminal !== undefined || Object.keys(frame).length !== 1 || !phases.has(frame.phase)) throw new Error();
      notify(frame);
    } catch {
      protocolError = 'invalid-helper-frame';
      notify({ protocolError });
    }
  });
  const exited = new Promise((resolve) => child.once('close', (code, signal) => {
    exitResult = { code, signal };
    for (const wake of waiting.splice(0)) wake({ closed: true });
    resolve(exitResult);
  }));
  const timer = setTimeout(() => child.kill(), timeoutMs);
  const diagnostic = (context) => [
    context,
    terminal?.ok === false ? `native: ${windowsFailureDiagnostic(terminal)}` : terminal?.ok === true ? 'unexpected native success' : 'no native terminal response',
    protocolError,
    transportError ? `transport: ${transportError}` : undefined,
    exitResult ? `exit: ${exitResult.code}; signal: ${exitResult.signal}` : undefined,
  ].filter(Boolean).join('; ');
  const send = async (text, end = false) => {
    if (exitResult !== undefined || child.stdin.destroyed || child.stdin.writableEnded) {
      await exited;
      throw new Error(diagnostic('helper input is closed'));
    }
    const error = await new Promise((resolve) => {
      if (end) child.stdin.end(text, (failure) => resolve(failure));
      else child.stdin.write(text, (failure) => resolve(failure));
    });
    if (error != null || transportError !== undefined) {
      if (error != null) recordTransport(error);
      await exited;
      throw new Error(diagnostic('helper acknowledgement failed'));
    }
  };
  const initial = send(`${JSON.stringify(request)}\n`).then(() => undefined, (error) => error);
  const next = async () => {
    const failed = await initial;
    if (failed) throw failed;
    if (protocolError) throw new Error(diagnostic('invalid helper protocol'));
    if (queue.length) return queue.shift();
    if (terminal !== undefined) return terminal;
    if (exitResult !== undefined) throw new Error(diagnostic('helper closed before the expected frame'));
    return new Promise((resolve) => waiting.push(resolve));
  };
  const checkpoint = async (expected) => {
    if (pending !== undefined) throw new Error('Previous checkpoint was not acknowledged');
    const frame = await next();
    if (Object.hasOwn(frame, 'ok') || frame.closed || frame.protocolError || terminal?.ok === false) {
      await exited;
      throw new Error(diagnostic(`expected checkpoint ${expected}`));
    }
    assert.deepEqual(frame, { phase: expected }, diagnostic(`unexpected checkpoint; expected ${expected}`));
    pending = expected;
    return frame;
  };
  const ack = async () => {
    if (terminal !== undefined) {
      await exited;
      throw new Error(diagnostic('terminal responses cannot be acknowledged'));
    }
    if (pending === undefined) throw new Error('No asserted checkpoint is awaiting acknowledgement');
    pending = undefined;
    await send('continue\n');
  };
  const completion = async (code, reason) => {
    const frame = await next();
    if (!Object.hasOwn(frame, 'ok')) throw new Error(diagnostic('expected a terminal response, not another checkpoint'));
    const result = await exited;
    assert.equal(protocolError, undefined, diagnostic('invalid helper protocol'));
    assert.equal(transportError, undefined, diagnostic('helper transport failed'));
    assert.equal(result.signal, null, diagnostic('helper was terminated'));
    assert.equal(result.code, code, diagnostic('unexpected native exit'));
    assert.equal(frame.ok, code === 0, diagnostic('unexpected native outcome'));
    if (code !== 0) {
      assert.equal(typeof reason, 'string', 'Expected native failures require an exact reason');
      assert.equal(frame.reason, reason, diagnostic('unexpected native failure'));
    }
    return frame;
  };
  return {
    checkpoint, ack,
    async through(expected) {
      for (let index = 0; index < expected.length; index++) {
        await checkpoint(expected[index]);
        if (index < expected.length - 1) await ack();
      }
    },
    async finish(code = 0, remaining = [], reason) {
      await ack();
      for (const phase of remaining) { await checkpoint(phase); await ack(); }
      return completion(code, reason);
    },
    async cancel() {
      if (pending === undefined || terminal !== undefined) throw new Error(diagnostic('cancellation requires an asserted live checkpoint'));
      pending = undefined;
      await send('', true);
      return completion(1, 'effect-cancelled');
    },
    async stop() {
      clearTimeout(timer);
      if (exitResult === undefined) { child.stdin.destroy(); child.kill(); }
      await exited;
      lines.close();
    },
  };
}
