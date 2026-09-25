import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { OPERATION_IDS } from '../dist/kernel/registry.js';
import { localLinkTarget, markdownInfo } from './check-repository.mjs';

const packageName = '@msn-control/missionspec';

export function parsePackPreview(content) {
  const parsed = JSON.parse(content);
  const entries = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Object.keys(parsed).length === 1 && Object.hasOwn(parsed, packageName)
      ? [parsed[packageName]]
      : [];
  if (entries.length !== 1 || entries[0]?.name !== packageName || !Array.isArray(entries[0].files)) {
    throw new Error('Unrecognized npm package preview; expected one MissionSpec package');
  }
  const seen = new Set();
  for (const file of entries[0].files) {
    if (typeof file?.path !== 'string' || file.path.startsWith('/') ||
        file.path.includes('\\') || file.path.split('/').includes('..') ||
        seen.has(file.path)) throw new Error('Invalid or duplicate packaged file path');
    seen.add(file.path);
  }
  return entries[0];
}

export function packageProblems(preview) {
  const files = new Set(preview.files.map((file) => file.path));
  const required = [
    'package.json', 'LICENSE', 'THIRD_PARTY_NOTICES', 'licenses/cli-runtime.json',
    'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
    'dist/cli/main.js', 'dist/api/index.js', 'dist/api/index.d.ts',
    'assets/operations/manifest.yaml', 'assets/schemas/operation-manifest.schema.json',
    ...OPERATION_IDS.map((id) => `assets/operations/${id}.md`)
  ];
  const problems = required.filter((file) => !files.has(file)).map((file) => `Missing packaged file: ${file}`);
  const bodies = [...files].filter((file) => /^assets\/operations\/[^/]+\.md$/.test(file));
  if (bodies.length !== OPERATION_IDS.length) problems.push('Unexpected operation instruction files in package');
  for (const file of files) {
    if (/^(node_modules|\.missionspec|infrastructure|services|tests|scripts|src)\//.test(file) ||
        /(^|\/)\.env(?:\.|$)/.test(file) || /(^|\/)(?:\.git|\.terraform)(?:\/|$)/.test(file) ||
        /^licenses\//.test(file) && file !== 'licenses/cli-runtime.json') {
      problems.push(`Unintended package content: ${file}`);
    }
  }
  return problems;
}

export async function packageLinkProblems(preview, readMarkdown) {
  const files = new Set(preview.files.map((file) => file.path));
  const problems = [];
  const documents = new Map();
  for (const file of files) {
    if (file.endsWith('.md')) documents.set(file, markdownInfo(await readMarkdown(file)));
  }
  for (const [source, document] of documents) {
    for (const link of document.links) {
      let target;
      try {
        target = localLinkTarget(source, link);
      } catch (error) {
        problems.push(`${source}: ${error.message}`);
        continue;
      }
      if (!target) continue;
      const directory = target.path.endsWith('/') ? target.path : `${target.path}/`;
      if (!files.has(target.path) && ![...files].some((file) => file.startsWith(directory))) {
        problems.push(`${source}: link target is not packaged: ${link}`);
      } else if (target.fragment && documents.has(target.path) &&
          !documents.get(target.path).anchors.has(target.fragment)) {
        problems.push(`${source}: packaged heading anchor is missing: ${link}`);
      }
    }
  }
  return problems;
}

if (import.meta.main) {
  try {
    const npmPath = process.env.npm_execpath;
    if (!npmPath || !path.isAbsolute(npmPath)) throw new Error('Run this check through npm run check:package');
    const { stdout } = await promisify(execFile)(process.execPath, [
      npmPath, 'pack', '--dry-run', '--ignore-scripts', '--json',
    ], {
      cwd: fileURLToPath(new URL('../', import.meta.url)),
      maxBuffer: 4 * 1024 * 1024,
      timeout: 60_000,
    });
    const preview = parsePackPreview(stdout);
    const root = fileURLToPath(new URL('../', import.meta.url));
    const problems = [
      ...packageProblems(preview),
      ...await packageLinkProblems(preview, (file) => readFile(path.join(root, file), 'utf8')),
    ];
    if (problems.length) {
      process.stderr.write(`${problems.join('\n')}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write(`Package boundary passed: ${OPERATION_IDS.length} canonical skill bodies; no project state or operator service.\n`);
    }
  } catch (error) {
    process.stderr.write(`Package check could not complete: ${error.message}\n`);
    process.exitCode = 1;
  }
}
