import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import {
  mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  assertLicenseEvidence, collectScope, packageNoticeProblems, runLicenseCheck, runtimeGraph,
  verifyOutputs,
} from '../scripts/check-licenses.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const mit = readFileSync(path.join(repository, 'node_modules/zod/LICENSE'), 'utf8');
const integrity = `sha512-${Buffer.alloc(64, 1).toString('base64')}`;
const writeJson = (file, value) => writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

function fixture(t, { scope = 'cli', name = 'alpha', version = '1.0.0', license = 'MIT' } = {}) {
  const root = path.join(repository, 'tests', `.license-fixture-${randomUUID()}`);
  const base = scope === 'cli' ? root : path.join(root, 'services/telemetry-ingest');
  mkdirSync(base, { recursive: true });
  mkdirSync(path.join(root, 'licenses'), { recursive: true });
  writeFileSync(path.join(root, 'licenses/reviewed-texts.json'), readFileSync(path.join(repository, 'licenses/reviewed-texts.json')));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const manifest = {
    name: `@missionspec-test/${scope}`, version: '0.0.0', private: true,
    dependencies: { [name]: version }, devDependencies: {},
  };
  const lock = { name: manifest.name, version: manifest.version, lockfileVersion: 3, packages: { '': { ...manifest } } };
  const state = {
    root, base, scope, manifest, lock,
    save() {
      writeJson(path.join(base, 'package.json'), manifest);
      lock.packages[''] = { ...manifest };
      writeJson(path.join(base, 'package-lock.json'), lock);
    },
    approveText(text, licenseExpression = 'MIT') {
      const catalogPath = path.join(root, 'licenses/reviewed-texts.json');
      const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
      catalog.reviewedFiles.push({
        licenseExpression,
        retainedSha256: createHash('sha256').update(text.replace(/\r\n?/g, '\n')).digest('hex'),
        observedAt: ['synthetic test-only attribution'],
      });
      writeJson(catalogPath, catalog);
    },
    add(location, options = {}) {
      const packageName = location.slice(location.lastIndexOf('node_modules/') + 13);
      const record = {
        version: '1.0.0', license: 'MIT',
        resolved: `https://registry.npmjs.org/${packageName}/-/${packageName.split('/').at(-1)}-1.0.0.tgz`,
        integrity, ...options,
      };
      lock.packages[location] = record;
      const directory = path.join(base, location);
      mkdirSync(directory, { recursive: true });
      const installed = { name: packageName, version: record.version, license: record.license };
      for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta']) {
        if (record[field]) installed[field] = record[field];
      }
      writeJson(path.join(directory, 'package.json'), installed);
      writeFileSync(path.join(directory, 'LICENSE'), mit);
      return record;
    },
  };
  state.add(`node_modules/${name}`, {
    version, license,
    resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`,
  });
  state.save();
  return state;
}

test('runtime inventory is deterministic, retains exact legal content, and detects drift', (t) => {
  const state = fixture(t);
  writeFileSync(path.join(state.base, 'node_modules/alpha/NOTICE'), 'Retain this attribution.\r\n');
  state.approveText('Retain this attribution.\n');
  const first = collectScope(state.root, 'cli');
  const second = collectScope(state.root, 'cli');
  assert.deepEqual(first, second);
  assert.equal(first.inventory.runtimePackages.length, 1);
  assert.equal(first.inventory.runtimePackages[0].legalFiles.length, 2);
  assert.ok(first.outputs.get('THIRD_PARTY_NOTICES').includes(mit.replace(/\r\n?/g, '\n')));
  assert.ok(first.outputs.get('THIRD_PARTY_NOTICES').includes('Retain this attribution.\n'));
  assert.equal(first.inventory.runtimePackages[0].resolved, state.lock.packages['node_modules/alpha'].resolved);
  assert.equal(first.inventory.runtimePackages[0].integrity, integrity);
  assert.equal(verifyOutputs(state.root, first.outputs).length, 2);
  runLicenseCheck(state.root, { scope: 'cli', write: true });
  assert.deepEqual(runLicenseCheck(state.root, { scope: 'cli' }), [{ scope: 'cli', runtime: 1, developmentOnly: 0 }]);
  writeFileSync(path.join(state.root, 'THIRD_PARTY_NOTICES'), 'removed attribution\n');
  assert.throws(() => runLicenseCheck(state.root, { scope: 'cli' }), /Stale licensing artifact/);
});

test('canonical lock hash does not change for formatting or key-order differences', (t) => {
  const state = fixture(t);
  const first = collectScope(state.root, 'cli').inventory.lockfileDataSha256;
  writeJson(path.join(state.base, 'package-lock.json'), Object.fromEntries(Object.entries(state.lock).reverse()));
  assert.equal(collectScope(state.root, 'cli').inventory.lockfileDataSha256, first);
});

test('includes nested versions and peers, classifies dev-only separately, and audits shared dependencies', (t) => {
  const state = fixture(t);
  state.manifest.devDependencies = { shared: '1.0.0', tooling: '1.0.0' };
  state.add('node_modules/alpha', {
    dependencies: { leaf: '^2.0.0' },
    peerDependencies: { shared: '^1.0.0', absent: '^1.0.0' },
    peerDependenciesMeta: { absent: { optional: true } },
  });
  state.add('node_modules/alpha/node_modules/leaf', { version: '2.0.0' });
  state.add('node_modules/shared');
  state.add('node_modules/tooling', { dev: true, license: 'GPL-3.0-only' });
  rmSync(path.join(state.base, 'node_modules/tooling'), { recursive: true });
  state.save();
  const { inventory } = collectScope(state.root, 'cli');
  assert.equal(inventory.runtimePackages.length, 3);
  assert.deepEqual(inventory.runtimePackages.find((p) => p.name === 'alpha').omittedOptional, ['absent']);
  const shared = inventory.runtimePackages.find((p) => p.name === 'shared');
  assert.equal(shared.relationship, 'transitive');
  assert.equal(shared.alsoDirectDevelopmentDependency, true);
  assert.equal(inventory.developmentOnly.length, 1);
  assert.match(inventory.developmentOnly[0].audit, /not reviewed/);
});

test('fails closed on missing dependency edges and incorrect development classification', () => {
  assert.throws(() => runtimeGraph({ '': { dependencies: { missing: '1.0.0' } } }), /Unresolved runtime/);
  assert.throws(() => runtimeGraph({
    '': { dependencies: { alpha: '1.0.0' } }, 'node_modules/alpha': { dev: true },
  }), /incorrectly marked/);
  assert.throws(() => runtimeGraph({ '': {}, 'node_modules/unexpected': {} }), /Unclassified/);
});

test('rejects missing, unreviewed, and GPL license expressions before regeneration', (t) => {
  for (const license of [undefined, 'UNLICENSED', 'GPL-3.0-only', '(MIT OR GPL-3.0-only)']) {
    const state = fixture(t);
    state.add('node_modules/alpha', { license });
    state.save();
    assert.throws(() => runLicenseCheck(state.root, { scope: 'cli', write: true }), /Unreviewed or disallowed license/);
  }
});

test('detects conflicting text and missing evidence even when metadata declares an allowed license', (t) => {
  const state = fixture(t);
  const legal = path.join(state.base, 'node_modules/alpha/LICENSE');
  writeFileSync(legal, `${mit}\nGNU GENERAL PUBLIC LICENSE\n`);
  assert.throws(() => collectScope(state.root, 'cli'), /Conflicting license terms/);
  writeFileSync(legal, 'MIT\n');
  assert.throws(() => collectScope(state.root, 'cli'), /Missing license-text evidence/);
  rmSync(legal);
  assert.throws(() => collectScope(state.root, 'cli'), /No retained license file/);
});

test('regeneration cannot silently approve new legal terms with an allowed SPDX label', (t) => {
  const state = fixture(t);
  writeFileSync(path.join(state.base, 'node_modules/alpha/LICENSE'), `${mit}\nAdditional noncommercial restriction.\n`);
  assert.throws(() => runLicenseCheck(state.root, { scope: 'cli', write: true }), /Unreviewed legal-file fingerprint/);
});

test('rejects stale manifest, installed identity, and installed dependency metadata', (t) => {
  const state = fixture(t);
  state.manifest.dependencies.alpha = '2.0.0';
  writeJson(path.join(state.base, 'package.json'), state.manifest);
  assert.throws(() => collectScope(state.root, 'cli'), /Manifest\/lock dependencies mismatch/);
  state.manifest.dependencies.alpha = '1.0.0';
  state.save();
  const file = path.join(state.base, 'node_modules/alpha/package.json');
  writeJson(file, { name: 'alpha', version: '9.0.0', license: 'MIT' });
  assert.throws(() => collectScope(state.root, 'cli'), /Installed identity/);
  writeJson(file, { name: 'alpha', version: '1.0.0', license: 'MIT', dependencies: { unexpected: '1.0.0' } });
  assert.throws(() => collectScope(state.root, 'cli'), /Installed dependencies differ/);
});

test('rejects unpinned direct dependencies, unknown sources, and missing integrity', (t) => {
  const state = fixture(t);
  state.manifest.dependencies.alpha = '^1.0.0';
  state.save();
  assert.throws(() => collectScope(state.root, 'cli'), /exactly pinned/);
  state.manifest.dependencies.alpha = '1.0.0';
  state.lock.packages['node_modules/alpha'].resolved = 'https://example.invalid/alpha.tgz';
  state.save();
  assert.throws(() => collectScope(state.root, 'cli'), /Unreviewed package source/);
  state.lock.packages['node_modules/alpha'].resolved = 'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz';
  delete state.lock.packages['node_modules/alpha'].integrity;
  state.save();
  assert.throws(() => collectScope(state.root, 'cli'), /integrity/);
});

test('does not silently omit a locked optional runtime dependency whose installation is missing', (t) => {
  const state = fixture(t);
  state.lock.packages['node_modules/alpha'].optional = true;
  state.save();
  rmSync(path.join(state.base, 'node_modules/alpha'), { recursive: true });
  assert.throws(() => collectScope(state.root, 'cli'), /ENOENT/);
});

test('blocks commercial Claude packages independently of declared license', (t) => {
  const state = fixture(t, { name: '@anthropic-ai/claude-agent-sdk' });
  assert.throws(() => collectScope(state.root, 'cli'), /Excluded commercial Claude package/);
});

test('service output is distinct and retains the supplemental pako zlib notice', (t) => {
  const state = fixture(t, { scope: 'service', name: 'pako', version: '2.2.0', license: '(MIT AND Zlib)' });
  assert.throws(() => collectScope(state.root, 'service'), /ENOENT/);
  const checkedNotices = readFileSync(path.join(repository, 'licenses/TELEMETRY_THIRD_PARTY_NOTICES'), 'utf8');
  const pakoNotices = checkedNotices.split('\npako@2.2.0\n')[1];
  const primary = pakoNotices.match(/--- LICENSE \(retained SHA-256: [a-f0-9]+\) ---\n([\s\S]*?)--- End LICENSE ---/)[1];
  const supplemental = checkedNotices.match(/--- lib\/zlib\/README \(retained SHA-256: [a-f0-9]+\) ---\n([\s\S]*?)--- End lib\/zlib\/README ---/)[1];
  writeFileSync(path.join(state.base, 'node_modules/pako/LICENSE'), primary);
  mkdirSync(path.join(state.base, 'node_modules/pako/lib/zlib'), { recursive: true });
  writeFileSync(path.join(state.base, 'node_modules/pako/lib/zlib/README'), supplemental);
  const result = collectScope(state.root, 'service');
  assert.ok(!result.outputs.has('THIRD_PARTY_NOTICES'));
  assert.ok(result.outputs.get('licenses/TELEMETRY_THIRD_PARTY_NOTICES').includes(supplemental));
  assert.equal(result.inventory.runtimePackages[0].legalFiles.length, 2);
  assert.throws(() => assertLicenseEvidence('(MIT AND Zlib)', [{ text: mit }], 'pako'), /Missing license-text evidence/);
});

test('retains copyright notices in addition to license files', (t) => {
  const state = fixture(t);
  writeFileSync(path.join(state.base, 'node_modules/alpha/CopyrightNotice.txt'), 'Additional copyright attribution.\n');
  state.approveText('Additional copyright attribution.\n');
  assert.equal(collectScope(state.root, 'cli').inventory.runtimePackages[0].legalFiles.length, 2);
});

test('rejects path escapes and dangling output symlinks', (t) => {
  assert.throws(() => runtimeGraph({ '': {}, '../node_modules/alpha': {} }), /Unsupported locked package location/);
  const state = fixture(t);
  const output = path.join(state.root, 'THIRD_PARTY_NOTICES');
  try {
    symlinkSync(path.join(state.root, 'missing-notices'), output);
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      t.diagnostic('Windows runner disallows symlink creation; path-escape assertion still exercised.');
      return;
    }
    throw error;
  }
  assert.throws(() => runLicenseCheck(state.root, { scope: 'cli', write: true }), /Refusing symlink/);
});

test('npm preview must ship checked notices and must exclude service material', () => {
  const name = '@missionspec-test/cli';
  const files = [
    { path: 'LICENSE', size: 1 },
    { path: 'docs/licensing.md', size: 1 },
    { path: 'THIRD_PARTY_NOTICES', size: 42 },
  ];
  assert.deepEqual(packageNoticeProblems([{ name, files }], name, 42), []);
  assert.deepEqual(packageNoticeProblems({ [name]: { name, files } }, name, 42), []);
  assert.match(packageNoticeProblems([{ name, files: files.slice(0, 2) }], name, 42).join(), /not shipped/);
  assert.match(packageNoticeProblems([{ name, files }], name, 43).join(), /byte|size/);
  for (const path of ['licenses/telemetry-runtime.json', 'licenses/TELEMETRY_THIRD_PARTY_NOTICES', 'services/telemetry-ingest/package.json']) {
    assert.match(packageNoticeProblems([{ name, files: [...files, { path, size: 1 }] }], name, 42).join(), /leaked/);
  }
  assert.match(packageNoticeProblems([{ name, files: [{ path: '../THIRD_PARTY_NOTICES' }] }], name, 42).join(), /Unsafe/);
  assert.match(packageNoticeProblems([{ name, files: [...files, files[0]] }], name, 42).join(), /Duplicate/);
});
