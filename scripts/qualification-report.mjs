import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const LIMITS = Object.freeze({ bytes: 1_000_000, tasks: 100, segments: 1_000,
  segmentsPerTask: 100, durationMs: 31 * 24 * 60 * 60 * 1_000, quantity: 1_000_000_000_000, depth: 12 });
const phases = ['setup', 'attempt', 'retry', 'repair'];
const outcomes = ['completed', 'failed', 'cancelled', 'incomplete'];
const quantities = ['inputTokens', 'outputTokens', 'costUsdMicros'];
const prices = ['inputUsdMicrosPerMillion', 'outputUsdMicrosPerMillion'];
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

export class QualificationInputError extends Error {}

function requireInput(condition, code) {
  if (!condition) throw new QualificationInputError(code);
}

function object(value, allowed, required = allowed) {
  requireInput(value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype, 'expected-closed-object');
  requireInput(Object.keys(value).every((key) => allowed.includes(key)), 'unknown-field');
  requireInput(required.every((key) => Object.hasOwn(value, key)), 'missing-required-field');
  return value;
}

function choice(value, allowed) {
  requireInput(allowed.includes(value), 'invalid-enumeration');
  return value;
}

function text(value, pattern, max = 80) {
  requireInput(typeof value === 'string' && value.length <= max && pattern.test(value), 'invalid-identifier');
  return value;
}

function opaqueId(value, prefix) {
  return text(value, new RegExp(`^${prefix}-[a-f0-9]{16}$`));
}

function unique(value, seen, code) {
  requireInput(!seen.has(value), code);
  seen.add(value);
  return value;
}

function version(value) {
  return text(value, /^\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[a-z0-9.-]{1,32})?$/, 48);
}

function modelLabel(value) {
  text(value, /^[a-z0-9][a-z0-9.-]{0,63}$/, 64);
  requireInput(!/(?:^|[.-])(?:auto|latest|default|unknown|unresolved)(?:$|[.-])/.test(value) &&
    !/^(?:sk-|sk\.|api-key|bearer)/.test(value), 'unresolved-or-unsafe-model-binding');
  return value;
}

function timestamp(value) {
  if (value === undefined || value === null) return null;
  text(value, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, 24);
  const milliseconds = Date.parse(value);
  requireInput(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, 'invalid-timestamp');
  return value;
}

function window(value) {
  const startedAt = timestamp(value.startedAt);
  const stoppedAt = timestamp(value.stoppedAt);
  const durationMs = startedAt === null || stoppedAt === null ? null : Date.parse(stoppedAt) - Date.parse(startedAt);
  requireInput(durationMs === null || durationMs >= 0 && durationMs <= LIMITS.durationMs, 'invalid-duration');
  return { startedAt, stoppedAt, durationMs };
}

function quantity(value) {
  if (value === undefined || value === null) return null;
  requireInput(Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0 && value <= LIMITS.quantity,
    'invalid-quantity');
  return value;
}

function evidence(value, seen) {
  object(value, ['recordId', 'digest', 'reviewed']);
  requireInput(value.reviewed === true, 'unreviewed-evidence');
  return { recordId: unique(opaqueId(value.recordId, 'REC'), seen, 'reused-source-record'),
    digest: text(value.digest, digestPattern), reviewed: true };
}

function binding(value) {
  object(value, ['source', 'host', 'model', 'candidate']);
  object(value.source, ['id', 'version', 'digest']);
  object(value.host, ['name', 'version']);
  object(value.model, ['id', 'version']);
  object(value.candidate, ['revision', 'digest']);
  return {
    source: { id: opaqueId(value.source.id, 'SRC'), version: version(value.source.version),
      digest: text(value.source.digest, digestPattern) },
    host: { name: choice(value.host.name, ['copilot', 'codex', 'claude']), version: version(value.host.version) },
    model: { id: modelLabel(value.model.id), version: modelLabel(value.model.version) },
    candidate: { revision: text(value.candidate.revision, /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/),
      digest: text(value.candidate.digest, digestPattern) },
  };
}

function measure(values, scopeComplete = true) {
  const known = values.filter((value) => value !== null);
  const knownSubtotal = known.reduce((sum, value) => sum + value, 0);
  requireInput(Number.isSafeInteger(knownSubtotal), 'aggregate-overflow');
  return { total: scopeComplete && known.length === values.length ? knownSubtotal : null,
    knownSubtotal, knownCount: known.length, unknownCount: values.length - known.length, scopeComplete };
}

function usageSummary(segments, scopeComplete) {
  return Object.fromEntries(quantities.map((key) => [key, measure(segments.map((segment) => segment.usage[key]), scopeComplete)]));
}

function pricingCoverage(segments) {
  return Object.fromEntries(prices.map((key) => [key, {
    knownCount: segments.filter((segment) => segment.usage[key] !== null).length,
    unknownCount: segments.filter((segment) => segment.usage[key] === null).length,
  }]));
}

function task(value, basis, ids, sourceRecords) {
  object(value, ['id', 'basis', 'outcome', 'startedAt', 'stoppedAt', 'phaseCoverage', 'evidence', 'segments'],
    ['id', 'basis', 'outcome', 'phaseCoverage', 'evidence', 'segments']);
  const id = unique(opaqueId(value.id, 'TASK'), ids, 'duplicate-id');
  requireInput(value.basis === basis, 'mixed-measurement-basis');
  const outcome = choice(value.outcome, outcomes);
  object(value.phaseCoverage, phases);
  const phaseCoverage = Object.fromEntries(phases.map((phase) =>
    [phase, choice(value.phaseCoverage[phase], ['complete', 'partial', 'unknown'])]));
  const taskEvidence = evidence(value.evidence, sourceRecords);
  const taskWindow = window(value);
  requireInput(Array.isArray(value.segments) && value.segments.length <= LIMITS.segmentsPerTask, 'segment-limit');
  const segments = value.segments.map((segment) => {
    object(segment, ['id', 'phase', 'startedAt', 'stoppedAt', 'usage', 'evidence'],
      ['id', 'phase', 'usage', 'evidence']);
    const segmentId = unique(opaqueId(segment.id, 'SEG'), ids, 'duplicate-id');
    const phase = choice(segment.phase, phases);
    object(segment.usage, ['scope', ...quantities, ...prices], ['scope']);
    requireInput(segment.usage.scope === 'exclusive-delta', 'nonexclusive-usage');
    const segmentWindow = window(segment);
    for (const boundary of [segmentWindow.startedAt, segmentWindow.stoppedAt].filter((at) => at !== null)) {
      requireInput((taskWindow.startedAt === null || boundary >= taskWindow.startedAt) &&
        (taskWindow.stoppedAt === null || boundary <= taskWindow.stoppedAt), 'segment-outside-task-window');
    }
    return { id: segmentId, phase, ...segmentWindow, evidence: evidence(segment.evidence, sourceRecords),
      usage: { scope: 'exclusive-delta', ...Object.fromEntries([...quantities, ...prices].map((key) =>
        [key, quantity(segment.usage[key])])) } };
  });
  requireInput(segments.filter((segment) => segment.phase === 'attempt').length <= 1 &&
    (!segments.some((segment) => segment.phase === 'retry') || segments.some((segment) => segment.phase === 'attempt')),
  'invalid-attempt-sequence');
  const timed = segments.filter((segment) => segment.durationMs !== null)
    .sort((left, right) => compare(left.startedAt, right.startedAt));
  for (let index = 1; index < timed.length; index += 1) {
    requireInput(timed[index].startedAt >= timed[index - 1].stoppedAt, 'overlapping-segments');
  }
  const scopeComplete = outcome !== 'incomplete' && phases.every((phase) => phaseCoverage[phase] === 'complete') &&
    timed.length === segments.length && taskWindow.durationMs !== null;
  return { id, basis, outcome, ...taskWindow, phaseCoverage, evidence: taskEvidence,
    accountingScopeComplete: scopeComplete, fullTaskWallMs: scopeComplete ? taskWindow.durationMs : null,
    segments: segments.sort((left, right) => compare(left.id, right.id)),
    usage: usageSummary(segments, scopeComplete), pricingCoverage: pricingCoverage(segments) };
}

export function createQualificationReport(input) {
  object(input, ['schemaVersion', 'basis', 'binding', 'tasks']);
  requireInput(input.schemaVersion === 1, 'unsupported-schema-version');
  const basis = choice(input.basis, ['synthetic', 'observed']);
  const selectedBinding = binding(input.binding);
  requireInput(Array.isArray(input.tasks) && input.tasks.length > 0 && input.tasks.length <= LIMITS.tasks, 'task-limit');
  requireInput(input.tasks.reduce((count, value) => count + (Array.isArray(value?.segments) ? value.segments.length : 0), 0) <=
    LIMITS.segments, 'segment-limit');
  const ids = new Set();
  const sourceRecords = new Set();
  const tasks = input.tasks.map((value) => task(value, basis, ids, sourceRecords))
    .sort((left, right) => compare(left.id, right.id));
  const segments = tasks.flatMap((value) => value.segments);
  const complete = tasks.every((value) => value.accountingScopeComplete);
  return {
    schemaVersion: 1, kind: 'descriptive-complete-task-measurements', basis, binding: selectedBinding,
    assurance: 'supplied-observations-not-authenticated',
    claims: { comparison: 'not-performed', benchmark: 'not-assessed', hostQualification: 'not-established',
      releaseQualification: 'not-established', authority: 'none' },
    population: { tasks: tasks.length, segments: segments.length,
      outcomes: Object.fromEntries(outcomes.map((outcome) => [outcome, tasks.filter((value) => value.outcome === outcome).length])) },
    coverage: { completeTaskScopes: tasks.filter((value) => value.accountingScopeComplete).length,
      incompleteTaskScopes: tasks.filter((value) => !value.accountingScopeComplete).length,
      knownTaskWindows: tasks.filter((value) => value.durationMs !== null).length,
      unknownTaskWindows: tasks.filter((value) => value.durationMs === null).length,
      knownSegmentWindows: segments.filter((value) => value.durationMs !== null).length,
      unknownSegmentWindows: segments.filter((value) => value.durationMs === null).length },
    fullTaskWallMs: measure(tasks.map((value) => value.fullTaskWallMs), complete),
    observedWindowMs: measure(tasks.map((value) => value.durationMs)),
    usage: usageSummary(segments, complete), pricingCoverage: pricingCoverage(segments),
    phases: Object.fromEntries(phases.map((phase) => {
      const selected = segments.filter((value) => value.phase === phase);
      return [phase, { segments: selected.length,
        coverage: Object.fromEntries(['complete', 'partial', 'unknown'].map((state) =>
          [state, tasks.filter((value) => value.phaseCoverage[phase] === state).length])),
        segmentWallMs: measure(selected.map((value) => value.durationMs), complete),
        usage: usageSummary(selected, complete), pricingCoverage: pricingCoverage(selected) }];
    })),
    tasks,
  };
}

export function parseQualificationRecords(content) {
  requireInput(typeof content === 'string' && Buffer.byteLength(content) <= LIMITS.bytes, 'input-byte-limit');
  let parsed;
  try { parsed = JSON.parse(content); } catch { throw new QualificationInputError('invalid-json'); }
  // JSON.parse alone discards duplicate keys, including escaped spellings of a key.
  const stack = [];
  for (const [token] of content.matchAll(/"(?:\\[\s\S]|[^"\\])*"|[{}[\],:]|[^\s{}[\],:"]+/g)) {
    if (token === '{' || token === '[') {
      requireInput(stack.length < LIMITS.depth, 'input-depth-limit');
      stack.push(token === '{' ? { keys: new Set(), expectingKey: true } : null);
    } else if (token === '}' || token === ']') {
      stack.pop();
    } else if (token === ',') {
      if (stack.at(-1)) stack.at(-1).expectingKey = true;
    } else if (token.startsWith('"') && stack.at(-1)?.expectingKey) {
      const frame = stack.at(-1);
      unique(JSON.parse(token), frame.keys, 'duplicate-json-key');
      frame.expectingKey = false;
    }
  }
  return parsed;
}

export async function readQualificationReport(filename) {
  const before = await lstat(filename, { bigint: true });
  requireInput(before.isFile() && !before.isSymbolicLink(), 'input-not-regular-file');
  requireInput(before.size <= BigInt(LIMITS.bytes), 'input-byte-limit');
  const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = await handle.stat({ bigint: true });
    requireInput(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino, 'input-changed');
    const bytes = Buffer.alloc(LIMITS.bytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await handle.read(bytes, length, bytes.length - length, null);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    requireInput(length <= LIMITS.bytes, 'input-byte-limit');
    const after = await handle.stat({ bigint: true });
    const current = await lstat(filename, { bigint: true });
    requireInput(current.isFile() && !current.isSymbolicLink() && current.dev === after.dev && current.ino === after.ino &&
      before.size === after.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs &&
      current.size === after.size && current.mtimeNs === after.mtimeNs && current.ctimeNs === after.ctimeNs, 'input-changed');
    let content;
    try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)); }
    catch { throw new QualificationInputError('invalid-utf8'); }
    const report = createQualificationReport(parseQualificationRecords(content));
    return { ...report, inputDigest: `sha256:${createHash('sha256').update(bytes.subarray(0, length)).digest('hex')}` };
  } finally {
    await handle.close();
  }
}

export async function runQualificationReport(args, io) {
  try {
    requireInput(args.length === 2 && args[0] === '--file' && typeof args[1] === 'string' &&
      args[1].length > 0 && args[1].length <= 4_000 && !/[\u0000-\u001f\u007f]/u.test(args[1]), 'use-explicit-file');
    io.stdout(`${JSON.stringify(await readQualificationReport(args[1]), null, 2)}\n`);
    return 0;
  } catch (error) {
    io.stderr(`${JSON.stringify({ status: 'rejected',
      code: error instanceof QualificationInputError ? error.message : 'input-read-failed' })}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runQualificationReport(process.argv.slice(2), {
    stdout: (value) => process.stdout.write(value), stderr: (value) => process.stderr.write(value),
  });
}
