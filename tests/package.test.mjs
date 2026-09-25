import assert from 'node:assert/strict';
import test from 'node:test';
import { packageLinkProblems, packageProblems, parsePackPreview } from '../scripts/check-package.mjs';
import { OPERATION_IDS } from '../dist/kernel/registry.js';

const name = '@msn-control/missionspec';
const files = [
  'package.json', 'LICENSE', 'THIRD_PARTY_NOTICES', 'licenses/cli-runtime.json',
  'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
  'dist/cli/main.js', 'dist/api/index.js', 'dist/api/index.d.ts',
  'assets/operations/manifest.yaml', 'assets/schemas/operation-manifest.schema.json',
  ...OPERATION_IDS.map((id) => `assets/operations/${id}.md`)
].map((path) => ({ path }));

test('package preview supports actual npm 12 keyed output and prior array output explicitly', () => {
  const value = { name, files };
  assert.deepEqual(parsePackPreview(JSON.stringify({ [name]: value })), value);
  assert.deepEqual(parsePackPreview(JSON.stringify([value])), value);
  for (const invalid of [{}, [], [value, value], { unrelated: value }, { [name]: { name, files: null } }]) {
    assert.throws(() => parsePackPreview(JSON.stringify(invalid)), /Unrecognized/);
  }
});

test('package requires exact named operation bodies, not merely a matching count', () => {
  assert.deepEqual(packageProblems({ name, files }), []);
  const replaced = files.map((file) => file.path === 'assets/operations/verify.md'
    ? { path: 'assets/operations/unplanned.md' } : file);
  assert(packageProblems({ name, files: replaced }).some((problem) => problem.includes('verify.md')));
});

test('state, credentials, unbuilt source and operator packages must not be shipped in the CLI', () => {
  for (const forbidden of ['.missionspec/state/ledger.sqlite', '.env.production', 'services/telemetry-ingest/package.json', 'infrastructure/main.tf', 'src/private.ts', 'node_modules/a/index.js', 'licenses/telemetry-runtime.json', 'licenses/TELEMETRY_THIRD_PARTY_NOTICES']) {
    assert(packageProblems({ name, files: [...files, { path: forbidden }] }).some((problem) => problem.includes('Unintended')));
  }
});

test('preview parsing rejects duplicate and escaping paths instead of hiding them in a set', () => {
  for (const bad of [[{ path: '../secret' }], [{ path: '/secret' }], [{ path: 'a\\b' }], [{ path: 'a' }, { path: 'a' }]]) {
    assert.throws(() => parsePackPreview(JSON.stringify({ [name]: { name, files: bad } })), /Invalid/);
  }
});

test('packaged documentation cannot link to excluded operator or source files', async () => {
  const preview = { name, files: [{ path: 'README.md' }, { path: 'docs/guide.md' }] };
  const content = new Map([
    ['README.md', '# Overview\n[Guide](docs/guide.md#intro)\n[Service](services/telemetry-ingest/)\n'],
    ['docs/guide.md', '# Intro\n[Home](../README.md#overview)\n']
  ]);
  const problems = await packageLinkProblems(preview, async (file) => content.get(file));
  assert.equal(problems.length, 1);
  assert.match(problems[0], /not packaged.*services/);
  content.set('README.md', '# Overview\n[Guide](docs/guide.md#missing)\n');
  assert.match((await packageLinkProblems(preview, async (file) => content.get(file)))[0], /heading anchor/);
});
