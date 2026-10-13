const driverMarker = 'MISSIONSPEC_CONPTY_DRIVER:';
const resultMarker = 'WINDOWS_CONSOLE_RESULT:';
const failureMarker = 'WINDOWS_CONSOLE_FAILURE:';
const phases = new Set(['bootstrap', 'pipes', 'console', 'job', 'attributes', 'create', 'capture', 'parent-death',
  'close-console', 'close', 'input', 'pipe', 'display', 'challenge', 'path', 'executable', 'membership', 'resume',
  'accounting', 'cancel', 'stdio-probe', 'redirect', 'authority-open', 'setup-preview', 'confirmation',
  'receipt', 'reopen', 'revocation', 'component']);
const reasons = new Set(['native-call', 'bootstrap', 'pipes', 'console', 'job', 'attributes', 'create', 'stdio-clear',
  'stdio-restore', 'timeout', 'output-bound', 'response', 'parent-kill', 'late-confirmation-still-active',
  'input-write', 'accounting', 'console-helper-outlived-parent', 'early-eof', 'console-close-incomplete', 'exit', 'close']);
const codes = new Set(['ERR_ASSERTION', 'EPERM', 'capability-unavailable', 'effect-outcome-unknown', 'ETIMEDOUT', 'ENOENT', 'other']);
const values = new Set(['accept', 'decline', 'cancel', 'unavailable', 'declined', 'issued', 'current', 'revoked', 'ok', 'other']);
const uint = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

export function conptyText(value) {
  return String(value ?? '').replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/gu, '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/gu, '').replace(/\r/gu, '');
}

export function conptyDiagnostic(context) {
  const parts = [];
  const fields = (value) => {
    if (!object(value)) return;
    for (const key of ['phase', 'stage']) if (phases.has(value[key])) parts.push(`${key}=${value[key]}`);
    if (reasons.has(value.reason)) parts.push(`reason=${value.reason}`);
    if (codes.has(value.code)) parts.push(`code=${value.code}`);
    if (uint(value.line) && value.line > 0 && value.line < 10_000) parts.push(`line=${value.line}`);
    for (const key of ['actual', 'expected', 'inputType', 'outputType', 'inputMode', 'outputMode', 'inputConsole', 'outputConsole']) {
      if (typeof value[key] === 'boolean' || uint(value[key]) || values.has(value[key])) parts.push(`${key}=${value[key]}`);
    }
    if (typeof value.native === 'string' && /^[a-z-]+(?:; line=[1-9][0-9]{0,3})?$/u.test(value.native) &&
        phases.has(value.native.split(';')[0])) parts.push(`native=${value.native}`);
  };
  fields(context);
  if (codes.has(context.error?.code)) parts.push(`spawn=${context.error.code}`);
  for (const stream of [context.stdout, context.stderr, context.output]) {
    for (const line of conptyText(stream).split('\n')) {
      if (!line.startsWith(failureMarker)) continue;
      try { fields(JSON.parse(line.slice(failureMarker.length))); }
      catch { parts.push('invalid-child-failure-frame'); }
    }
  }
  return parts.length === 0 ? 'no-structured-native-diagnostic' : [...new Set(parts)].join('; ');
}

function fail(reason, context) {
  throw new Error(`ConPTY ${reason}; ${conptyDiagnostic(context)}`);
}

export function parseConptyDriver(result) {
  const stdout = typeof result.stdout === 'string' ? result.stdout : '';
  const lines = stdout.trim().split(/\r?\n/u);
  const frames = lines.filter((line) => line.startsWith(driverMarker));
  let response;
  if (frames.length === 1) {
    try { response = JSON.parse(frames[0].slice(driverMarker.length)); }
    catch { fail('invalid-driver-json', result); }
  }
  const context = { ...result, ...(object(response) ? response : {}) };
  if (frames.length !== 1 || lines.length !== 1) fail('driver-protocol-contamination', context);
  if (!object(response) || typeof response.ok !== 'boolean') fail('invalid-driver-frame', context);
  if (response.ok === false) fail('native-driver-failure', context);
  if (result.error || result.status !== 0 || result.signal || String(result.stderr ?? '').trim() !== '') fail('driver-exit-or-stderr', context);
  if (Object.keys(response).sort().join(',') !== 'challenges,code,jobEmpty,ok,output,parentKilled' ||
      !uint(response.code) || !uint(response.challenges) || response.challenges > 64 ||
      typeof response.parentKilled !== 'boolean' || typeof response.jobEmpty !== 'boolean' ||
      typeof response.output !== 'string' || Buffer.byteLength(response.output) > 8_000_000) fail('invalid-driver-frame', context);
  return { ...response, output: conptyText(response.output) };
}

export function parseConptyChild(response) {
  if (response.code !== 0) fail('child-exit', response);
  const lines = response.output.split('\n');
  if (lines.some((line) => line.startsWith(failureMarker))) fail('child-failure', response);
  const frames = lines.filter((line) => line.startsWith(resultMarker));
  if (frames.length !== 1) fail('missing-or-duplicate-child-result', response);
  let value;
  try { value = JSON.parse(frames[0].slice(resultMarker.length)); }
  catch { fail('invalid-child-json', response); }
  if (!object(value)) fail('invalid-child-result', response);
  return value;
}
