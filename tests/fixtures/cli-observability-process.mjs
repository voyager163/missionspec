import { windowsFailureDiagnostic } from '../../dist/adapters/platform/windows-private-state.js';

export function networkGuardSpecifier(moduleUrl = import.meta.url) {
  return new URL('./cli-observability-network-guard.mjs', moduleUrl).href;
}

const nodeCodes = [
  'ERR_UNSUPPORTED_ESM_URL_SCHEME', 'ERR_MODULE_NOT_FOUND', 'ERR_INVALID_MODULE_SPECIFIER',
  'ERR_UNKNOWN_FILE_EXTENSION', 'ERR_INPUT_TYPE_NOT_ALLOWED', 'ERR_INVALID_ARG_VALUE',
  'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_URL', 'MODULE_NOT_FOUND',
];
const spawnCodes = ['ENOENT', 'EACCES', 'EPERM', 'ETIMEDOUT', 'ENOBUFS'];
const signals = ['SIGTERM', 'SIGKILL', 'SIGABRT', 'SIGSEGV', 'SIGINT'];
const uint = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
const exitCode = (result) => result.status ?? result.code;
const startupCodes = (result) => nodeCodes.filter((code) => [result.stderr, result.output]
  .some((stream) => typeof stream === 'string' && new RegExp(`\\b${code}\\b`, 'u').test(stream.slice(0, 65_536))));

export function cliProcessDiagnostic(result) {
  const code = exitCode(result);
  const parts = [`exit=${uint(code) ? code : 'unknown'}`, `node=${startupCodes(result).join(',') || 'none'}`];
  if (result.error !== undefined) parts.push(`spawn=${spawnCodes.includes(result.error?.code) ? result.error.code : 'other'}`);
  if (result.signal != null) parts.push(`signal=${signals.includes(result.signal) ? result.signal : 'other'}`);
  if (uint(result.challenges) && result.challenges <= 64) parts.push(`challenges=${result.challenges}`);
  if (typeof result.stdout === 'string') parts.push(`stdout=${result.stdout.trim() === '' ? 'empty' : 'present'}`);
  return parts.join('; ');
}

export function cliControlDiagnostic(result) {
  const envelope = result.value;
  const control = envelope?.value;
  const parts = [cliProcessDiagnostic(result)];
  for (const [label, value, allowed] of [
    ['status', envelope?.status, ['ok', 'blocked', 'failed', 'outcome-unknown']],
    ['state', control?.state, ['ready', 'saved', 'unavailable', 'absent', 'pruned']],
    ['reason', control?.reason, ['invalid', 'io', 'conflict', 'busy', 'unrecognized-store', 'cleanup-failed',
      'preference-read-failed', 'authorization-rejected', 'authorization-unavailable', 'stale-preview']],
    ['persistence', control?.persistence, ['unchanged', 'committed', 'unknown']],
    ['cleanup', control?.cleanup, ['complete', 'incomplete']],
  ]) if (allowed.includes(value)) parts.push(`${label}=${value}`);
  for (const line of (typeof result.stderr === 'string' ? result.stderr.slice(0, 16_384) : '').split(/\r?\n/u)) {
    if (!line.startsWith('CLI_NATIVE_FAILURE:')) continue;
    try {
      const { native } = JSON.parse(line.slice('CLI_NATIVE_FAILURE:'.length));
      if (typeof native !== 'string' || native.length > 512) continue;
      const [reason, ...details] = native.split('; ');
      const fields = Object.fromEntries(details.map((detail) => detail.split('=')));
      for (const name of ['line', 'nativeStatus']) if (fields[name] !== undefined) fields[name] = Number(fields[name]);
      parts.push(`native=${windowsFailureDiagnostic({ ...fields, reason })}`);
      break;
    } catch { /* Diagnostics accept only the native formatter's closed fields. */ }
  }
  return parts.join('; ');
}

function fail(reason, result) {
  throw new Error(`CLI child ${reason}; ${cliProcessDiagnostic(result)}`);
}

export function checkCliProcess(result) {
  if (result.error !== undefined || result.signal != null) fail('process-unavailable', result);
  if (exitCode(result) === 98) fail('network-attempt', result);
  if (![0, 1, 2].includes(exitCode(result)) || startupCodes(result).length !== 0) fail('startup-or-exit-failure', result);
}

export function parseCliEnvelope(result, console = false) {
  checkCliProcess(result);
  let text = result.stdout;
  if (console) {
    const marker = '{"contractVersion":1,"status":';
    const output = typeof result.output === 'string' ? result.output : '';
    const start = output.indexOf(marker);
    if (start === -1 || output.indexOf(marker, start + marker.length) !== -1) fail('missing-or-duplicate-envelope', result);
    // The real CLI writes one JSON line; ConPTY may wrap at its column bound.
    text = output.slice(start).replaceAll('\r', '').replaceAll('\n', '');
  }
  if (typeof text !== 'string' || text.trim() === '') fail('missing-envelope', result);
  let value;
  try { value = JSON.parse(text); } catch { fail('invalid-envelope-json', result); }
  if (value === null || typeof value !== 'object' || Array.isArray(value) || value.contractVersion !== 1 ||
      !['ok', 'blocked', 'failed', 'outcome-unknown'].includes(value.status) ||
      (value.status === 'ok') !== (exitCode(result) === 0)) fail('invalid-envelope', result);
  return value;
}
