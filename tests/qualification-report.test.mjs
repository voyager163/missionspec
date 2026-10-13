import assert from 'node:assert/strict';
import fsPromises, { mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createQualificationReport, LIMITS, parseQualificationRecords, readQualificationReport, runQualificationReport,
} from '../scripts/qualification-report.mjs';

const hex = (number) => number.toString(16).padStart(16, '0');
const at = (milliseconds) => new Date(Date.UTC(2026, 0, 1) + milliseconds).toISOString();
const evidence = (number) => ({ recordId: `REC-${hex(number)}`, digest: `sha256:${'e'.repeat(64)}`, reviewed: true });

// Invented unit-test measurements only; no live host, model, price or bill was observed.
function syntheticInput() {
  return {
    schemaVersion: 1, basis: 'synthetic',
    binding: {
      source: { id: `SRC-${hex(1)}`, version: '1.0.0', digest: `sha256:${'a'.repeat(64)}` },
      host: { name: 'copilot', version: '1.0.85' },
      model: { id: 'fixture-model', version: '1.0.0' },
      candidate: { revision: 'c'.repeat(40), digest: `sha256:${'d'.repeat(64)}` },
    },
    tasks: [{
      id: `TASK-${hex(1)}`, basis: 'synthetic', outcome: 'completed', startedAt: at(0), stoppedAt: at(10_000),
      phaseCoverage: { setup: 'complete', attempt: 'complete', retry: 'complete', repair: 'complete' },
      evidence: evidence(1),
      segments: ['setup', 'attempt', 'retry', 'repair'].map((phase, index) => ({
        id: `SEG-${hex(index + 1)}`, phase, startedAt: at(index * 2_000), stoppedAt: at(index * 2_000 + 1_000),
        evidence: evidence(index + 2),
        usage: { scope: 'exclusive-delta', inputTokens: 10, outputTokens: 2, costUsdMicros: 100,
          inputUsdMicrosPerMillion: 1_000, outputUsdMicrosPerMillion: 2_000 },
      })),
    }],
  };
}

async function fixture(context, content) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'missionspec-measurements-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'synthetic-input.json');
  await writeFile(file, content);
  return { directory, file };
}

test('synthetic complete-task accounting includes setup, retries, repairs and wall-clock gaps without inferred prices', () => {
  const report = createQualificationReport(syntheticInput());
  assert.equal(report.basis, 'synthetic');
  assert.equal(report.fullTaskWallMs.total, 10_000);
  assert.equal(report.observedWindowMs.total, 10_000);
  assert.equal(Object.values(report.phases).reduce((sum, phase) => sum + phase.segmentWallMs.total, 0), 4_000);
  assert.equal(report.usage.inputTokens.total, 40);
  assert.equal(report.usage.outputTokens.total, 8);
  assert.equal(report.usage.costUsdMicros.total, 400);
  for (const phase of ['setup', 'attempt', 'retry', 'repair']) {
    assert.equal(report.phases[phase].usage.inputTokens.total, 10);
    assert.equal(report.phases[phase].usage.costUsdMicros.total, 100);
  }
  assert.equal(report.assurance, 'supplied-observations-not-authenticated');
  assert.deepEqual(report.claims, { comparison: 'not-performed', benchmark: 'not-assessed',
    hostQualification: 'not-established', releaseQualification: 'not-established', authority: 'none' });
});

test('failed, cancelled and incomplete synthetic tasks remain in the denominator and incomplete totals stay unknown', () => {
  const input = syntheticInput();
  const original = input.tasks[0];
  input.tasks = ['completed', 'failed', 'cancelled', 'incomplete'].map((outcome, index) => ({
    ...structuredClone(original), id: `TASK-${hex(index + 1)}`, outcome, evidence: evidence(index * 10 + 1),
    segments: original.segments.map((segment, slot) => ({
      ...structuredClone(segment), id: `SEG-${hex(index * 10 + slot + 1)}`, evidence: evidence(index * 10 + slot + 2),
    })),
  }));
  const report = createQualificationReport(input);
  assert.deepEqual(report.population.outcomes, { completed: 1, failed: 1, cancelled: 1, incomplete: 1 });
  assert.equal(report.population.tasks, 4);
  assert.equal(report.fullTaskWallMs.total, null);
  assert.equal(report.fullTaskWallMs.knownSubtotal, 30_000);
  assert.equal(report.fullTaskWallMs.knownCount, 3);
  assert.equal(report.fullTaskWallMs.unknownCount, 1);
  assert.equal(report.fullTaskWallMs.scopeComplete, false);
  assert.equal(report.observedWindowMs.total, 40_000);
  assert.equal(report.usage.costUsdMicros.total, null);
  assert.equal(report.usage.costUsdMicros.knownSubtotal, 1_600);
  assert.equal(report.usage.costUsdMicros.scopeComplete, false);
  assert.equal(report.coverage.incompleteTaskScopes, 1);
});

test('missing tokens, prices, costs and timing normalize to unknown rather than zero', () => {
  const input = syntheticInput();
  const segment = input.tasks[0].segments[0];
  delete segment.usage.inputTokens;
  segment.usage.costUsdMicros = null;
  delete segment.usage.inputUsdMicrosPerMillion;
  segment.usage.outputUsdMicrosPerMillion = null;
  const report = createQualificationReport(input);
  assert.equal(report.usage.inputTokens.total, null);
  assert.equal(report.usage.inputTokens.knownSubtotal, 30);
  assert.equal(report.usage.inputTokens.unknownCount, 1);
  assert.equal(report.usage.costUsdMicros.total, null);
  assert.equal(report.tasks[0].segments[0].usage.inputTokens, null);
  assert.deepEqual(report.pricingCoverage.inputUsdMicrosPerMillion, { knownCount: 3, unknownCount: 1 });
  assert.deepEqual(report.pricingCoverage.outputUsdMicrosPerMillion, { knownCount: 3, unknownCount: 1 });
  delete segment.stoppedAt;
  const untimed = createQualificationReport(input);
  assert.equal(untimed.coverage.unknownSegmentWindows, 1);
  assert.equal(untimed.fullTaskWallMs.total, null);
  assert.equal(untimed.observedWindowMs.total, 10_000);
  assert.equal(untimed.phases.setup.segmentWallMs.total, null);
  assert.equal(untimed.usage.outputTokens.total, null, 'Unknown exclusivity cannot produce a full-task usage total');
  delete input.tasks[0].startedAt;
  assert.equal(createQualificationReport(input).observedWindowMs.total, null);
});

test('unknown phase coverage cannot turn an absent overhead phase into a measured zero', () => {
  const input = syntheticInput();
  input.tasks[0].segments.shift();
  input.tasks[0].phaseCoverage.setup = 'unknown';
  const report = createQualificationReport(input);
  assert.equal(report.fullTaskWallMs.total, null);
  assert.equal(report.usage.inputTokens.total, null);
  assert.equal(report.phases.setup.usage.inputTokens.total, null);
  assert.equal(report.phases.setup.usage.inputTokens.knownSubtotal, 0);
  assert.deepEqual(report.phases.setup.coverage, { complete: 0, partial: 0, unknown: 1 });
  input.tasks[0].phaseCoverage.setup = 'complete';
  assert.equal(createQualificationReport(input).phases.setup.usage.inputTokens.total, 0,
    'An explicitly reviewed complete empty phase is distinct from missing coverage');
});

test('supplied monetary costs and prices remain independent and known zero requires a supplied value', () => {
  const input = syntheticInput();
  for (const segment of input.tasks[0].segments) {
    segment.usage.costUsdMicros = 0;
    segment.usage.inputUsdMicrosPerMillion = null;
    segment.usage.outputUsdMicrosPerMillion = null;
  }
  const report = createQualificationReport(input);
  assert.equal(report.usage.costUsdMicros.total, 0);
  assert.deepEqual(report.pricingCoverage.inputUsdMicrosPerMillion, { knownCount: 0, unknownCount: 4 });
  for (const segment of input.tasks[0].segments) {
    segment.usage.costUsdMicros = null;
    segment.usage.inputUsdMicrosPerMillion = 0;
    segment.usage.outputUsdMicrosPerMillion = 0;
  }
  assert.equal(createQualificationReport(input).usage.costUsdMicros.total, null,
    'A supplied zero rate does not establish a zero bill');
});

test('synthetic and observed labels cannot be mixed or relabeled by an individual task', () => {
  for (const basis of ['observed', 'unknown', undefined]) {
    const input = syntheticInput();
    input.tasks[0].basis = basis;
    assert.throws(() => createQualificationReport(input), /mixed-measurement-basis/);
  }
  const input = syntheticInput();
  input.basis = 'observed';
  assert.throws(() => createQualificationReport(input), /mixed-measurement-basis/);
});

test('exact binding, reviewed evidence and closed fields reject logs, credentials and comparison requests', () => {
  const changes = [
    (input) => { input.schemaVersion = 2; },
    (input) => { input.binding.host.version = 'latest'; },
    (input) => { input.binding.host.name = 'unknown-host'; },
    (input) => { input.binding.model.id = 'auto'; },
    (input) => { input.binding.model.version = 'unknown'; },
    (input) => { input.binding.model.id = 'sk-private-fixture-marker'; },
    (input) => { input.binding.candidate.revision = 'main'; },
    (input) => { input.binding.source.digest = 'missing'; },
    (input) => { input.tasks[0].evidence.reviewed = false; },
    (input) => { input.tasks[0].segments[0].evidence.digest = 'invalid'; },
    (input) => { input.tasks[0].id = 'email@example.invalid'; },
    (input) => { input.prompts = ['private-fixture-marker']; },
    (input) => { input.tasks[0].source = 'private-fixture-marker'; },
    (input) => { input.tasks[0].segments[0].rawOutput = 'private-fixture-marker'; },
    (input) => { input.binding.apiKey = 'private-fixture-marker'; },
    (input) => { input.tasks[0].segments[0].usage.credentials = 'private-fixture-marker'; },
    (input) => { input.baseline = syntheticInput(); },
    (input) => { input.tasks[0].binding = input.binding; },
    (input) => { delete input.tasks[0].phaseCoverage.setup; },
  ];
  for (const change of changes) {
    const input = syntheticInput();
    change(input);
    assert.throws(() => createQualificationReport(input), (error) => !error.message.includes('private-fixture-marker'));
  }
});

test('duplicate IDs, recycled source records, cumulative usage and overlapping attempts cannot double count', () => {
  const changes = [
    [(input) => { input.tasks.push(structuredClone(input.tasks[0])); }, /duplicate-id/],
    [(input) => { input.tasks[0].segments[1].id = input.tasks[0].segments[0].id; }, /duplicate-id/],
    [(input) => { input.tasks[0].segments[1].evidence.recordId = input.tasks[0].segments[0].evidence.recordId; }, /reused-source-record/],
    [(input) => { input.tasks[0].segments[0].usage.scope = 'cumulative'; }, /nonexclusive-usage/],
    [(input) => { input.tasks[0].usage = { inputTokens: 100 }; }, /unknown-field/],
    [(input) => { input.tasks[0].segments[2].startedAt = at(2_500); }, /overlapping-segments/],
    [(input) => { input.tasks[0].segments[2].phase = 'attempt'; }, /invalid-attempt-sequence/],
    [(input) => { input.tasks[0].segments = input.tasks[0].segments.filter((segment) => segment.phase !== 'attempt'); }, /invalid-attempt-sequence/],
  ];
  for (const [change, error] of changes) {
    const input = syntheticInput();
    change(input);
    assert.throws(() => createQualificationReport(input), error);
  }
});

test('invalid dates, reversed/oversized windows and work outside full-task boundaries are rejected', () => {
  for (const value of ['2026-02-30T00:00:00.000Z', '2026-01-01', '2026-01-01T00:00:00+00:00', 0, '']) {
    const input = syntheticInput();
    input.tasks[0].startedAt = value;
    assert.throws(() => createQualificationReport(input));
  }
  for (const change of [
    (input) => { input.tasks[0].stoppedAt = at(-1); },
    (input) => { input.tasks[0].stoppedAt = at(LIMITS.durationMs + 1); },
    (input) => { input.tasks[0].segments[0].startedAt = at(-1); },
    (input) => { input.tasks[0].segments[0].stoppedAt = at(20_000); },
    (input) => { input.tasks[0].segments[1].stoppedAt = at(0); },
  ]) {
    const input = syntheticInput();
    change(input);
    assert.throws(() => createQualificationReport(input), /invalid-duration|segment-outside-task-window/);
  }
});

test('all usage and price quantities reject nonfinite, fractional, negative and unsafe values', () => {
  for (const key of ['inputTokens', 'outputTokens', 'costUsdMicros', 'inputUsdMicrosPerMillion', 'outputUsdMicrosPerMillion']) {
    for (const value of [NaN, Infinity, -Infinity, -1, -0, 0.1, Number.MAX_SAFE_INTEGER + 1, LIMITS.quantity + 1, '10', true]) {
      const input = syntheticInput();
      input.tasks[0].segments[0].usage[key] = value;
      assert.throws(() => createQualificationReport(input), /invalid-quantity/);
    }
  }
});

test('bounded JSON rejects duplicate escaped keys, deep inputs, oversized strings and oversized record sets', () => {
  assert.throws(() => parseQualificationRecords('{"basis":"synthetic","b\\u0061sis":"observed"}'), /duplicate-json-key/);
  assert.throws(() => parseQualificationRecords('{"nested":{"inputTokens":99,"inputTokens":0}}'), /duplicate-json-key/);
  assert.throws(() => parseQualificationRecords('['.repeat(LIMITS.depth + 1) + '0' + ']'.repeat(LIMITS.depth + 1)), /input-depth-limit/);
  assert.throws(() => parseQualificationRecords(' '.repeat(LIMITS.bytes + 1)), /input-byte-limit/);
  assert.throws(() => parseQualificationRecords('{"prompt":"private-fixture-marker",'), /invalid-json/);
  assert.deepEqual(parseQualificationRecords('{"first":{"id":"a"},"second":{"id":"b"},"text":"{\\\\\\"}"}'),
    JSON.parse('{"first":{"id":"a"},"second":{"id":"b"},"text":"{\\\\\\"}"}'));
  const input = syntheticInput();
  input.tasks = Array(LIMITS.tasks + 1).fill(input.tasks[0]);
  assert.throws(() => createQualificationReport(input), /task-limit/);
  input.tasks = [];
  assert.throws(() => createQualificationReport(input), /task-limit/);
  const long = syntheticInput();
  long.tasks[0].segments = Array(LIMITS.segmentsPerTask + 1).fill(long.tasks[0].segments[0]);
  assert.throws(() => createQualificationReport(long), /segment-limit/);
  long.tasks = Array(11).fill(long.tasks[0]);
  assert.throws(() => createQualificationReport(long), /segment-limit/);
});

test('maximum accepted segment counts and quantities sum exactly without dropping overhead records', () => {
  const input = syntheticInput();
  const original = input.tasks[0];
  input.tasks = Array.from({ length: 10 }, (_, taskIndex) => ({
    ...structuredClone(original), id: `TASK-${hex(taskIndex + 1)}`, evidence: evidence(taskIndex * 101 + 1),
    segments: Array.from({ length: 100 }, (_, index) => ({
      id: `SEG-${hex(taskIndex * 100 + index + 1)}`, phase: index === 0 ? 'attempt' : 'repair',
      startedAt: at(index), stoppedAt: at(index + 1), evidence: evidence(taskIndex * 101 + index + 2),
      usage: { scope: 'exclusive-delta', inputTokens: LIMITS.quantity, outputTokens: LIMITS.quantity,
        costUsdMicros: LIMITS.quantity },
    })),
  }));
  const report = createQualificationReport(parseQualificationRecords(JSON.stringify(input)));
  assert.equal(report.population.segments, LIMITS.segments);
  for (const metric of Object.values(report.usage)) {
    assert.equal(metric.total, LIMITS.segments * LIMITS.quantity);
    assert.equal(metric.unknownCount, 0);
    assert.equal(metric.knownCount, LIMITS.segments);
  }
  assert.equal(report.phases.repair.usage.inputTokens.knownCount, 990);
});

test('explicit file reporting is deterministic, binds the input digest and creates no incidental files', async (context) => {
  const { directory, file } = await fixture(context, JSON.stringify(syntheticInput()));
  const first = await readQualificationReport(file);
  assert.deepEqual(await readQualificationReport(file), first);
  assert.match(first.inputDigest, /^sha256:[a-f0-9]{64}$/);
  let stdout = '';
  let stderr = '';
  const code = await runQualificationReport(['--file', file], {
    stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; },
  });
  assert.equal(code, 0);
  assert.equal(stderr, '');
  assert.deepEqual(JSON.parse(stdout), first);
  assert.deepEqual(await readdir(directory), ['synthetic-input.json']);
  assert.equal(first.claims.benchmark, 'not-assessed', 'One synthetic task is not a benchmark pass');
});

test('explicit input failures are sanitized, and directories, links, invalid UTF-8 and oversized files are rejected', async (context) => {
  const { directory, file } = await fixture(context, JSON.stringify(syntheticInput()));
  await assert.rejects(readQualificationReport(directory), /input-not-regular-file/);
  const link = path.join(directory, 'input-link.json');
  await symlink(file, link);
  await assert.rejects(readQualificationReport(link), /input-not-regular-file/);
  await writeFile(file, Buffer.from([0xff]));
  await assert.rejects(readQualificationReport(file), /invalid-utf8/);
  await writeFile(file, Buffer.alloc(LIMITS.bytes + 1, ' '));
  await assert.rejects(readQualificationReport(file), /input-byte-limit/);
  await writeFile(file, '{"private-fixture-marker":');
  for (const args of [[], ['--file', file], ['--file', path.join(directory, 'private-fixture-marker')], ['--auto-discover']]) {
    let stdout = '';
    let stderr = '';
    assert.equal(await runQualificationReport(args, {
      stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; },
    }), 1);
    assert.equal(stdout, '');
    assert.equal(JSON.parse(stderr).status, 'rejected');
    assert(!stderr.includes('private-fixture-marker'));
    assert(!stderr.includes(directory));
  }
});

test('a pathname replaced during open is rejected before reading the held descriptor', async (context) => {
  const { file } = await fixture(context, JSON.stringify(syntheticInput()));
  const originalOpen = fsPromises.open;
  let reads = 0;
  const mocked = context.mock.method(fsPromises, 'open', async (...args) => {
    const handle = await originalOpen(...args);
    if (args[0] === file) {
      const read = handle.read.bind(handle);
      handle.read = (...input) => { reads += 1; return read(...input); };
      await rename(file, `${file}.original`);
      await writeFile(file, JSON.stringify(syntheticInput()));
    }
    return handle;
  });
  syncBuiltinESMExports();
  context.after(() => { mocked.mock.restore(); syncBuiltinESMExports(); });
  await assert.rejects(readQualificationReport(file), /input-changed/);
  assert.equal(reads, 0);
});

test('helper imports only inert Node file/format primitives and has no runner, network or session discovery surface', async () => {
  const source = await readFile(new URL('../scripts/qualification-report.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^import .* from '([^']+)';$/gm)].map((match) => match[1]);
  assert.deepEqual(imports, ['node:crypto', 'node:fs', 'node:fs/promises', 'node:path', 'node:url']);
  assert(!/\b(?:fetch|eval|execFile|spawn|Worker)\s*\(|\bimport\s*\(|process\.env|Date\.now\(/.test(source));
});
