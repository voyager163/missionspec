import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { readMarkdownSources } from '../dist/adapters/filesystem/artifacts.js';

const proposal = `---
schemaVersion: 1
id: ART-proposal
kind: proposal
changeId: CHG-example
---
# Example

## Problem
An explicit problem.

## Outcome
A measurable outcome.

## Scope
A bounded change.

## Acceptance
Review the intended behavior.
`;

async function fixture(context) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'missionspec-read-'));
  context.after(() => rm(directory, { recursive: true, force: true }));
  const root = path.join(directory, 'project');
  await mkdir(root);
  return { directory, root };
}

test('explicit Markdown reads preserve bytes without creating runtime or telemetry state', async (context) => {
  const { root } = await fixture(context);
  await writeFile(path.join(root, 'proposal.md'), proposal);
  const sources = await readMarkdownSources(root, ['proposal.md']);
  assert.equal(sources[0].content, proposal);
  assert.deepEqual(await readdir(root), ['proposal.md']);
  assert(Object.isFrozen(sources));
  await assert.rejects(readMarkdownSources(root, ['../outside.md']));
  await assert.rejects(readMarkdownSources(root, ['.env']));
  await assert.rejects(readMarkdownSources(root, ['proposal.md', 'proposal.md']));
});

test('reader rejects symlinks, oversize/invalid UTF-8 and non-file inputs explicitly', async (context) => {
  const { directory, root } = await fixture(context);
  await writeFile(path.join(directory, 'outside.md'), proposal);
  await symlink(directory, path.join(root, 'link'), 'junction');
  await assert.rejects(readMarkdownSources(root, ['link/outside.md']), /symbolic links/);
  await writeFile(path.join(root, 'large.md'), Buffer.alloc(1_000_001, 65));
  await assert.rejects(readMarkdownSources(root, ['large.md']), /byte limit/);
  await writeFile(path.join(root, 'invalid.md'), Buffer.from([0xc3, 0x28]));
  await assert.rejects(readMarkdownSources(root, ['invalid.md']), /UTF-8/);
  await mkdir(path.join(root, 'directory.md'));
  await assert.rejects(readMarkdownSources(root, ['directory.md']), /regular file|safely/);
});

test('CLI validation reports only supplied-set structure, never execution or approval', async (context) => {
  const { root } = await fixture(context);
  await writeFile(path.join(root, 'proposal.md'), proposal);
  const entry = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
  const { stdout, stderr } = await promisify(execFile)(process.execPath, [entry, 'validate', 'proposal.md', '--json'], { cwd: root });
  const result = JSON.parse(stdout);
  assert.equal(result.status, 'ok');
  assert.equal(result.value.scope, 'supplied-document-set');
  assert.equal(result.value.implementationVerified, false);
  assert.equal(result.value.authorityIssued, false);
  assert(!stdout.includes('An explicit problem.'));
  assert.equal(stderr, '');
  assert.equal(await readFile(path.join(root, 'proposal.md'), 'utf8'), proposal);
  assert.deepEqual(await readdir(root), ['proposal.md']);
  await writeFile(path.join(root, 'proposal.md'), proposal.replace('schemaVersion: 1', 'schemaVersion: 99'));
  await assert.rejects(
    promisify(execFile)(process.execPath, [entry, 'validate', 'proposal.md', '--json'], { cwd: root }),
    (error) => error.code === 1 && JSON.parse(error.stdout).value.state === 'invalid',
  );
});

test('UTF-8 BOM bytes are preserved rather than silently changing revision-bound content', async (context) => {
  const { root } = await fixture(context);
  const original = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(proposal)]);
  await writeFile(path.join(root, 'proposal.md'), original);
  const sources = await readMarkdownSources(root, ['proposal.md']);
  assert.equal(sources[0].content.charCodeAt(0), 0xfeff);
  assert.deepEqual(Buffer.from(sources[0].content, 'utf8'), original);
  const entry = fileURLToPath(new URL('../dist/cli/main.js', import.meta.url));
  await assert.rejects(
    promisify(execFile)(process.execPath, [entry, 'validate', 'proposal.md', '--json'], { cwd: root }),
    (error) => error.code === 1 && JSON.parse(error.stdout).value.state === 'invalid',
  );
});
