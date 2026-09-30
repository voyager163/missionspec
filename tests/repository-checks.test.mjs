import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { parse } from '@babel/parser';
import {
  checkIssueForm, checkLocalLink, checkRepository, checkWorkflow, markdownInfo, parseYaml
} from '../scripts/check-repository.mjs';

function validWorkflow() {
  return {
    on: { pull_request: null },
    permissions: { contents: 'read' },
    concurrency: { group: 'checks-${{ github.ref }}', 'cancel-in-progress': true },
    env: { DO_NOT_TRACK: '1', MISSIONSPEC_TELEMETRY: '0' },
    jobs: { check: {
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 10,
      steps: [
        { uses: `actions/checkout@${'a'.repeat(40)}`, with: { 'persist-credentials': false } },
        { run: 'npm run check' }
      ]
    } }
  };
}

test('installed tarballs run once per OS behind the existing required contexts after locked restore', async () => {
  const file = '.github/workflows/repository.yml';
  const workflow = parseYaml(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'), file);
  assert.deepEqual(checkWorkflow(workflow, file), []);
  const install = 'npm run check:package -- --install';
  const jobs = Object.entries(workflow.jobs).filter(([, job]) => job.steps.some((step) => step.run === install));
  assert.deepEqual(jobs.map(([id]) => id), ['repository-contracts', 'windows-read-only']);
  const mutations = [
    (value) => { value.jobs['repository-contracts'].steps = value.jobs['repository-contracts'].steps.filter((step) => step.run !== install); },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run === install).run = 'npm run check:package'; },
    (value) => { value.jobs['windows-read-only'].steps.unshift({ run: install }); },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run?.startsWith('npm ci')).run = 'npm ci'; },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run === 'npm run check:portable').run = 'npm run build'; },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run === install).if = 'false'; },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run === install)['continue-on-error'] = true; },
    (value) => { value.jobs['windows-read-only'].steps.find((step) => step.run === install)['working-directory'] = 'different'; },
    (value) => { value.jobs['windows-read-only'].name = 'Renamed check'; },
    (value) => { value.jobs['windows-read-only']['runs-on'] = 'ubuntu-latest'; },
    (value) => { value.jobs['repository-checks'].strategy.matrix.os = ['ubuntu-latest']; },
    (value) => { value.jobs['repository-checks'].strategy.matrix.exclude = [{ os: 'macos-latest' }]; },
    (value) => { value.jobs['windows-private-state'].steps.push({ run: install }); },
    (value) => { value.jobs['windows-private-state'].steps = 'malformed'; },
    (value) => { delete value.jobs['windows-read-only']; },
    (value) => { value.defaults = { run: { 'working-directory': 'different' } }; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(workflow);
    mutate(changed);
    assert.notEqual(checkWorkflow(changed, file).length, 0, mutate.toString());
  }
});

test('Windows workflow selectors cover every application scenario exactly once without matching the whole suite', async () => {
  const source = await readFile(new URL('./windows-local-runtime.test.mjs', import.meta.url), 'utf8');
  const tree = parse(source, { sourceType: 'module' });
  const names = [];
  function visit(node) {
    if (node === null || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'test') {
      assert.equal(node.arguments[0]?.type, 'StringLiteral', 'Windows scenarios require stable literal names.');
      names.push(node.arguments[0].value);
    }
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value !== null && typeof value === 'object') visit(value);
    }
  }
  visit(tree);
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  assert.equal(workflow.jobs['windows-workflow'].needs, 'windows-file-races');
  const races = workflow.jobs['windows-file-races'];
  assert.equal(races['runs-on'], 'windows-latest');
  assert(races.steps.some((step) => step.run === 'node --test --test-concurrency=1 tests/windows-file-races.test.mjs'));
  const raceIndex = races.steps.findIndex((step) => step.run === 'node --test --test-concurrency=1 tests/windows-file-races.test.mjs');
  const profileIndex = races.steps.findIndex((step) => step.run === 'node --test --test-concurrency=1 tests/windows-profile-conversion.test.mjs');
  assert(profileIndex > raceIndex, 'Native profile conversion runs only after held-handle race qualification');
  assert.deepEqual(Object.keys(races.steps[profileIndex]).sort(), ['name', 'run']);
  const matrix = workflow.jobs['windows-workflow'].strategy.matrix.include;
  assert.equal(matrix.length, names.length);
  assert(names.length > 0);
  const covered = new Set();
  for (const { pattern } of matrix) {
    const selector = new RegExp(pattern, 'u');
    assert.equal(selector.test('Windows real application integration'), false, 'Matching a parent suite runs all its children.');
    const matches = names.filter((name) => selector.test(name));
    assert.equal(matches.length, 1);
    assert.equal(covered.has(matches[0]), false);
    covered.add(matches[0]);
  }
});

test('Windows lifecycle qualification runs the complete native suite behind the race gate', async () => {
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  const lifecycle = workflow.jobs['windows-runtime-lifecycle'];
  assert.equal(lifecycle['runs-on'], 'windows-latest');
  assert.equal(lifecycle.needs, 'windows-file-races');
  assert(lifecycle['timeout-minutes'] > 0 && lifecycle['timeout-minutes'] <= 15);
  assert(lifecycle.steps.some((step) => step.run === 'node --test --test-concurrency=1 tests/windows-runtime-lifecycle.test.mjs'));
});

test('telemetry CI checks only the canonical ARM definition without executing cloud operations', async () => {
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  const steps = workflow.jobs['telemetry-arm'].steps;
  const telemetry = steps.find((step) => step.name === 'Check telemetry infrastructure policy without cloud access');
  assert.equal(telemetry.run, 'node --test infrastructure/arm/telemetry/tests/*.test.mjs');
  assert(steps.every((step) => !step.run?.includes('infrastructure/opentofu/telemetry')));
});

test('required repository contexts fail closed over both complete OS workload matrices', async () => {
  const file = '.github/workflows/repository.yml';
  const workflow = parseYaml(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'), file);
  assert.deepEqual(checkWorkflow(workflow, file), []);
  assert.deepEqual(workflow.jobs['repository-checks'].needs, ['repository-contracts', 'telemetry-arm']);
  for (const id of ['repository-contracts', 'telemetry-arm', 'repository-checks']) {
    assert.equal(workflow.jobs[id]['timeout-minutes'], 10);
    assert.deepEqual(workflow.jobs[id].strategy.matrix.os, ['ubuntu-latest', 'macos-latest']);
  }
  const mutations = [
    value => { delete value.jobs['repository-checks'].if; },
    value => { value.jobs['repository-checks'].if = '${{ success() }}'; },
    value => { value.jobs['repository-checks'].needs = ['repository-contracts']; },
    value => { value.jobs['repository-checks'].steps[0].run = 'exit 0'; },
    value => { value.jobs['repository-checks'].steps[0].run = value.jobs['repository-checks'].steps[0].run.replace('&&', '||'); },
    value => { value.jobs['repository-checks'].steps[0].env.ARM_RESULT = 'success'; },
    value => { value.jobs['repository-checks'].steps[0]['continue-on-error'] = true; },
    value => { value.jobs['repository-checks'].steps[0].if = '${{ success() }}'; },
    value => { value.jobs['repository-checks'].defaults = { run: { shell: 'bash' } }; },
    value => { value.jobs['telemetry-arm']['timeout-minutes'] = 15; },
    value => { value.jobs['telemetry-arm'].needs = 'repository-contracts'; },
    value => { value.jobs['telemetry-arm'].strategy.matrix.os = ['ubuntu-latest']; },
    value => { value.jobs['telemetry-arm'].strategy['fail-fast'] = true; },
    value => { value.jobs['telemetry-arm'].steps.at(-1).run = 'node --test infrastructure/arm/telemetry/tests/private-link.test.mjs'; },
    value => { value.jobs['telemetry-arm'].steps.at(-1)['working-directory'] = 'different'; },
    value => { value.jobs['telemetry-arm'].steps[0].with.ref = 'develop'; },
    value => { value.jobs['repository-contracts'].steps.pop(); },
    value => { value.jobs['repository-contracts'].steps[0].with.ref = 'develop'; },
    value => { value.jobs['repository-contracts'].strategy.matrix.exclude = [{ os: 'macos-latest' }]; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(workflow); mutate(changed);
    assert.notEqual(checkWorkflow(changed, file).length, 0, mutate.toString());
  }
});

test('the POSIX aggregate command rejects failure, cancellation, skipped and missing dependency results', {
  skip: process.platform === 'win32',
}, async () => {
  const file = '.github/workflows/repository.yml';
  const workflow = parseYaml(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'), file);
  assert.deepEqual(checkWorkflow(workflow, file), []);
  const command = workflow.jobs['repository-checks'].steps[0].run;
  for (const contracts of ['success', 'failure', 'cancelled', 'skipped', 'timed_out', '']) {
    for (const arm of ['success', 'failure', 'cancelled', 'skipped', 'timed_out', '']) {
      const result = spawnSync('/bin/sh', ['-c', command], {
        env: { CONTRACTS_RESULT: contracts, ARM_RESULT: arm }, encoding: 'utf8',
      });
      assert.ifError(result.error);
      assert.equal(result.status === 0, contracts === 'success' && arm === 'success');
    }
  }
});

test('Windows CLI observability runs its complete native suite within a bounded job', async () => {
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  const job = workflow.jobs['windows-cli-observability'];
  assert.equal(job['runs-on'], 'windows-latest');
  assert(job['timeout-minutes'] > 0 && job['timeout-minutes'] <= 15);
  assert(job.steps.some((step) => step.run === 'node --test --test-concurrency=1 tests/windows-cli-observability.test.mjs'));
});

test('Windows writer instances run real native identity checks within a bounded job', async () => {
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  const job = workflow.jobs['windows-writer-instance'];
  assert.equal(job['runs-on'], 'windows-latest');
  assert(job['timeout-minutes'] > 0 && job['timeout-minutes'] <= 15);
  assert(job.steps.some((step) => step.run === 'node --test --test-concurrency=1 tests/windows-writer-instance.test.mjs'));
});

test('Windows execution matrix covers each console and registered-check case once and the complete process suite', async () => {
  const workflow = parseYaml(await readFile(new URL('../.github/workflows/repository.yml', import.meta.url), 'utf8'), 'repository workflow');
  const job = workflow.jobs['windows-execution'];
  assert.equal(job['runs-on'], 'windows-latest');
  assert(job['timeout-minutes'] > 0 && job['timeout-minutes'] <= 15);
  const entries = job.strategy.matrix.include;
  assert.equal(new Set(entries.map((entry) => entry.scenario)).size, entries.length);
  const commands = entries.map((entry) => entry.command);
  assert.equal(commands.filter((command) => command === 'node --test --test-concurrency=1 tests/windows-check-process.test.mjs').length, 1);
  let scenarios = 1;
  for (const file of ['windows-console', 'windows-checks-integration']) {
    const source = await readFile(new URL(`./${file}.test.mjs`, import.meta.url), 'utf8');
    const tree = parse(source, { sourceType: 'module' });
    const names = tree.program.body.filter((node) => node.type === 'ExpressionStatement' &&
      node.expression.type === 'CallExpression' && node.expression.callee.type === 'Identifier' &&
      node.expression.callee.name === 'test').map((node) => node.expression.arguments[0].value);
    assert(names.length > 0);
    scenarios += names.length;
    const covered = new Set();
    for (const command of commands.filter((command) => command.endsWith(` tests/${file}.test.mjs`))) {
      const pattern = /^node --test --test-concurrency=1 --test-name-pattern="([^"]+)" tests\/[a-z-]+\.test\.mjs$/u.exec(command)?.[1];
      assert(pattern);
      const matches = names.filter((name) => new RegExp(pattern, 'u').test(name));
      assert.equal(matches.length, 1);
      assert.equal(covered.has(matches[0]), false);
      covered.add(matches[0]);
    }
    assert.deepEqual([...covered].sort(), names.sort());
  }
  assert.equal(entries.length, scenarios);
  assert(job.steps.some((step) => step.run === '${{ matrix.command }}'));
});

test('Markdown parser handles reference links, code fences and duplicate GitHub headings', () => {
  const info = markdownInfo('# Overview\n# Overview\n[Guide][ref]\n\n[ref]: docs/guide.md#intro\n\n```\n[fake](missing.md)\n```\n');
  assert.deepEqual([...info.anchors], ['overview', 'overview-1']);
  assert.deepEqual(info.links, ['docs/guide.md#intro']);
});

test('YAML rejects duplicate keys and invalid input instead of treating them as empty configuration', () => {
  assert.throws(() => parseYaml('name: one\nname: two\n', 'fixture'), /invalid YAML/);
  assert.throws(() => parseYaml('body: [\n', 'fixture'), /invalid YAML/);
  assert.deepEqual(parseYaml('on:\n  pull_request:\n', 'fixture'), { on: { pull_request: null } });
});

test('issue forms require meaningful fields and unique IDs', () => {
  const field = { type: 'textarea', id: 'reproduction', attributes: { label: 'Reproduction' }, validations: { required: true } };
  const form = { name: 'Bug', description: 'Report a reproducible bug', body: [field] };
  assert.deepEqual(checkIssueForm(form), []);
  assert.match(checkIssueForm({ ...form, body: [field, field] }).join('\n'), /duplicate/);
  assert.notEqual(checkIssueForm({ ...form, body: [] }).length, 0);
  assert.notEqual(checkIssueForm({ ...form, body: [{ ...field, type: 'dropdown' }] }).length, 0);
});

test('seed workflow accepts only the qualified unprivileged shape', () => {
  assert.deepEqual(checkWorkflow(validWorkflow()), []);
  const mutations = [
    (value) => { value.on = { pull_request_target: null }; },
    (value) => { value.permissions.contents = 'write'; },
    (value) => { value.jobs.check['runs-on'] = 'self-hosted'; },
    (value) => { value.jobs.check['timeout-minutes'] = 0; },
    (value) => { value.jobs.check.steps[0].uses = 'actions/checkout@v6'; },
    (value) => { value.jobs.check.steps[0].with['persist-credentials'] = true; },
    (value) => { value.jobs.check['continue-on-error'] = true; },
    (value) => { value.jobs.check.steps[1]['continue-on-error'] = true; },
    (value) => { value.jobs.check.steps[1].if = 'false'; },
    (value) => { value.jobs.check.if = 'false'; },
    (value) => { value.jobs.check.environment = 'production'; },
    (value) => { value.env.MISSIONSPEC_TELEMETRY = '1'; },
    (value) => { value.jobs.check.steps[1].env = { TOKEN: '${{ secrets.TOKEN }}' }; },
    (value) => { value.jobs.check.steps[1].env = { TOKEN: "${{ secrets['TOKEN'] }}" }; },
    (value) => { value.jobs.check.steps[1].env = { TOKEN: '${{ toJSON(secrets) }}' }; }
  ];
  for (const mutate of mutations) {
    const workflow = validWorkflow();
    mutate(workflow);
    assert.notEqual(checkWorkflow(workflow).length, 0, mutate.toString());
  }
});

test('CodeQL reporting permissions are narrow and cannot authorize a project build step', () => {
  const workflow = validWorkflow();
  workflow.jobs.check.permissions = { contents: 'read', actions: 'read', 'security-events': 'write' };
  workflow.jobs.check.strategy = { matrix: { language: ['javascript-typescript', 'actions'] } };
  workflow.jobs.check.steps[1] = {
    uses: `github/codeql-action/init@${'b'.repeat(40)}`,
    with: { languages: '${{ matrix.language }}', 'build-mode': 'none', queries: 'security-extended' }
  };
  workflow.jobs.check.steps.push({
    uses: `github/codeql-action/analyze@${'b'.repeat(40)}`,
    with: { category: '/language:${{ matrix.language }}' }
  });
  assert.deepEqual(checkWorkflow(workflow, '.github/workflows/codeql.yml'), []);
  assert.notEqual(checkWorkflow(workflow, '.github/workflows/repository.yml').length, 0);
  const noUpload = structuredClone(workflow);
  noUpload.jobs.check.steps[2].with.upload = false;
  assert.match(checkWorkflow(noUpload, '.github/workflows/codeql.yml').join('\n'), /analyze and upload/);
  workflow.jobs.check.steps.push({ run: 'npm run build' });
  assert.match(checkWorkflow(workflow, '.github/workflows/codeql.yml').join('\n'), /must not execute/);
  workflow.jobs.check.permissions.contents = 'write';
  assert.match(checkWorkflow(workflow, '.github/workflows/codeql.yml').join('\n'), /permissions/);
});

test('dependency review permits only the separately pinned metadata discrepancy, never broad license exceptions', () => {
  const workflow = validWorkflow();
  workflow.jobs.check.steps = [{
    uses: `actions/dependency-review-action@${'a'.repeat(40)}`,
    with: {
      'fail-on-severity': 'high', 'comment-summary-in-pr': 'never', 'license-check': true,
      'allow-licenses': 'Apache-2.0, MIT, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD, CC0-1.0, Unlicense, Zlib',
      'allow-dependencies-licenses': 'pkg:npm/json-schema-typed',
    },
  }];
  assert.deepEqual(checkWorkflow(workflow, '.github/workflows/dependency-review.yml'), []);
  workflow.jobs.check.steps[0].with['allow-dependencies-licenses'] += ', pkg:npm/unreviewed';
  assert.notEqual(checkWorkflow(workflow, '.github/workflows/dependency-review.yml').length, 0);
});

test('local links validate real targets, heading anchors, and repository containment', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-links-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'docs'));
  await writeFile(path.join(root, 'README.md'), '# MissionSpec\n');
  await writeFile(path.join(root, 'docs', 'guide.md'), '# Getting started\n');
  assert.equal(await checkLocalLink(root, 'README.md', 'docs/guide.md#getting-started'), undefined);
  assert.equal(await checkLocalLink(root, 'README.md', 'https://example.com/private'), undefined);
  assert.match(await checkLocalLink(root, 'README.md', 'docs/guide.md#absent'), /missing heading/);
  assert.match(await checkLocalLink(root, 'README.md', 'missing.md'), /missing local/);
  assert.match(await checkLocalLink(root, 'README.md', '../outside.md'), /escapes/);
  assert.match(await checkLocalLink(root, 'README.md', '%ZZ'), /encoding/);
  assert.match(await checkLocalLink(root, 'README.md', 'javascript:alert(1)'), /protocol/);
});

test('missing required repository inputs cannot pass', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'missionspec-empty-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  const problems = await checkRepository(root);
  assert(problems.some((problem) => problem.startsWith('LICENSE:')));
  assert(problems.some((problem) => problem.startsWith('.github/workflows/repository.yml:')));
});

test('links and required inputs cannot read through an escaping directory symlink', async (context) => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'missionspec-symlink-'));
  context.after(() => rm(fixture, { recursive: true, force: true }));
  const root = path.join(fixture, 'project');
  const outside = path.join(fixture, 'outside');
  await mkdir(root);
  await mkdir(outside);
  await writeFile(path.join(outside, 'maintainer-setup.md'), '# Outside\n');
  await symlink(outside, path.join(root, 'docs'), 'junction');
  assert.match(await checkLocalLink(root, 'README.md', 'docs/maintainer-setup.md'), /escapes/);
  assert((await checkRepository(root)).some((problem) => problem.includes('resolves outside')));
});
