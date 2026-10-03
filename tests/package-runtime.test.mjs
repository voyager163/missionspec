import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readdir, rename, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { parsePackPreview, packageProblems } from '../scripts/check-package.mjs';

const execute = promisify(execFile);
const repository = fileURLToPath(new URL('../', import.meta.url));

test('actual local package retains notices and loads every projection without a checkout asset fallback', { timeout: 60_000 }, async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), 'missionspec-packaged-runtime-'));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const npm = process.env.npm_execpath;
  assert(npm && path.isAbsolute(npm), 'Run this package smoke through npm test so the selected npm executable is explicit.');
  const { stdout } = await execute(process.execPath, [
    npm, 'pack', '--ignore-scripts', '--json', '--pack-destination', temporary,
  ], { cwd: repository, timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
  const packed = parsePackPreview(stdout);
  assert.deepEqual(packageProblems(packed), []);
  assert.equal(path.basename(packed.filename), packed.filename);
  await execute('tar', ['-xzf', path.join(temporary, packed.filename), '-C', temporary], { timeout: 10_000 });
  const distribution = path.join(temporary, 'package');
  assert.equal(await readFile(path.join(distribution, 'THIRD_PARTY_NOTICES'), 'utf8'),
    await readFile(path.join(repository, 'THIRD_PARTY_NOTICES'), 'utf8'));
  assert.equal(await readFile(path.join(distribution, 'licenses/cli-runtime.json'), 'utf8'),
    await readFile(path.join(repository, 'licenses/cli-runtime.json'), 'utf8'));
  assert.deepEqual(await readdir(path.join(distribution, 'licenses')), ['cli-runtime.json']);
  // Reuse the already restored locked dependencies; this is not a registry-install proof.
  await symlink(path.join(repository, 'node_modules'), path.join(distribution, 'node_modules'),
    process.platform === 'win32' ? 'junction' : 'dir');
  const project = path.join(temporary, 'empty-project');
  await mkdir(project);
  const cli = path.join(distribution, 'dist/cli/main.js');
  const invoke = (args) => execute(process.execPath, [cli, ...args, '--json'], {
    cwd: project, timeout: 10_000, maxBuffer: 1_048_576,
    env: { ...process.env, MISSIONSPEC_TELEMETRY: '0', DO_NOT_TRACK: '1' },
  });
  const catalog = JSON.parse((await invoke(['skills', 'list'])).stdout);
  assert.equal(catalog.status, 'ok');
  const renderingProgram = `
    const { loadPackagedSkillCatalog, renderSkillSet } = await import(process.argv[1]);
    const catalog = await loadPackagedSkillCatalog();
    const hosts = ['copilot', 'codex', 'claude'];
    const rendered = renderSkillSet(catalog, hosts, '0.0.0');
    console.log(JSON.stringify({ count: rendered.length, paths: rendered.map(file => file.path) }));
  `;
  const rendered = await execute(process.execPath, [
    '--input-type=module', '-e', renderingProgram,
    pathToFileURL(path.join(distribution, 'dist/api/index.js')).href,
  ], { cwd: project, timeout: 10_000, maxBuffer: 1_048_576 });
  const projections = JSON.parse(rendered.stdout);
  assert.equal(projections.count, 36);
  assert.equal(new Set(projections.paths).size, 36);
  assert.deepEqual(await readdir(project), []);
  await rename(path.join(distribution, 'assets'), path.join(distribution, 'assets-unavailable'));
  await assert.rejects(invoke(['skills', 'list']), (error) => {
    const result = JSON.parse(error.stdout);
    assert.notEqual(result.status, 'ok');
    return true;
  });
  assert.deepEqual(await readdir(project), []);
});
