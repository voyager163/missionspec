import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from '@babel/parser';

const engineNames = new Set(['discovery', 'specification', 'planning', 'execution', 'verification', 'integration']);
const pureImports = new Set(['node:crypto', 'node:path', 'yaml', 'mdast-util-from-markdown', 'ajv/dist/2020.js']);
const forbiddenEngineLayers = new Set(['adapters', 'application', 'cli', 'mcp', 'api', 'composition']);
const normalize = (value) => value.replaceAll('\\', '/');

export function importProblem(source, specifier) {
  const from = normalize(source);
  const engine = /^engines\/([^/]+)\//.exec(from)?.[1];
  if (engine && !engineNames.has(engine)) return `${from}: undeclared engine ${engine}`;
  if (!specifier.startsWith('.')) {
    if ((engine || from.startsWith('kernel/')) && !pureImports.has(specifier)) {
      return `${from}: pure engine/kernel boundary cannot import ${specifier}`;
    }
    return undefined;
  }
  const target = path.posix.normalize(path.posix.join(path.posix.dirname(from), specifier));
  if (target.startsWith('../')) return `${from}: source import escapes src: ${specifier}`;
  if (from.startsWith('kernel/') && !target.startsWith('kernel/')) {
    return `${from}: kernel cannot depend on another application layer`;
  }
  if (engine && forbiddenEngineLayers.has(target.split('/')[0])) {
    return `${from}: engine cannot depend on ${target.split('/')[0]}`;
  }
  const targetEngine = /^engines\/([^/]+)\/(.+)$/.exec(target);
  if (targetEngine && engine !== targetEngine[1] &&
      !/^(index|contracts)\.(js|ts)$/.test(targetEngine[2])) {
    return `${from}: private cross-engine import ${specifier}`;
  }
  return undefined;
}

export function sourceImports(content, file) {
  const source = parse(content, {
    sourceType: 'module',
    sourceFilename: file,
    plugins: ['typescript'],
    createImportExpressions: true
  });
  const imports = [];
  const unsupported = [];
  const record = (argument) => {
    if (argument?.type === 'StringLiteral') imports.push(argument.value);
    else unsupported.push(`${file}: dynamic module path cannot be architecture-checked`);
  };
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type) && node.source) {
      record(node.source);
    } else if (node.type === 'TSImportType') {
      record(node.argument);
    } else if (node.type === 'ImportExpression') {
      record(node.source);
    } else if (node.type === 'TSImportEqualsDeclaration' && node.moduleReference?.type === 'TSExternalModuleReference') {
      record(node.moduleReference.expression);
    } else if (node.type === 'CallExpression' &&
        node.callee?.type === 'Identifier' && node.callee.name === 'require') {
      record(node.arguments[0]);
    }
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  }
  visit(source);
  return { imports, unsupported };
}

export function cycleProblems(edges) {
  const visiting = new Set();
  const visited = new Set();
  const problems = [];
  function visit(node, trail) {
    if (visiting.has(node)) {
      problems.push(`Cyclic engine dependency: ${[...trail, node].join(' -> ')}`);
      return;
    }
    if (visited.has(node)) return;
    visiting.add(node);
    for (const dependency of edges.get(node) ?? []) visit(dependency, [...trail, node]);
    visiting.delete(node);
    visited.add(node);
  }
  for (const node of edges.keys()) visit(node, []);
  return problems;
}

async function sourceFiles(root, prefix = '') {
  const result = [];
  for (const entry of await readdir(path.join(root, prefix), { withFileTypes: true })) {
    const file = path.posix.join(prefix, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Source symlinks are not supported: ${file}`);
    if (entry.isDirectory()) result.push(...await sourceFiles(root, file));
    else if (entry.name.endsWith('.ts')) result.push(file);
  }
  return result;
}

export async function checkArchitecture(root) {
  const files = await sourceFiles(root);
  if (files.length === 0) return ['No TypeScript source found; architecture cannot be qualified'];
  const edges = new Map();
  const problems = [];
  for (const file of files) {
    const { imports, unsupported } = sourceImports(await readFile(path.join(root, file), 'utf8'), file);
    problems.push(...unsupported);
    const engine = /^engines\/([^/]+)\//.exec(file)?.[1];
    if (engine && !engineNames.has(engine)) problems.push(`${file}: undeclared engine ${engine}`);
    for (const specifier of imports) {
      const problem = importProblem(file, specifier);
      if (problem) problems.push(problem);
      if (!engine || !specifier.startsWith('.')) continue;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
      const other = /^engines\/([^/]+)\//.exec(target)?.[1];
      if (other && engine !== other) {
        if (!edges.has(engine)) edges.set(engine, new Set());
        edges.get(engine).add(other);
      }
    }
  }
  return [...problems, ...cycleProblems(edges)];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const problems = await checkArchitecture(fileURLToPath(new URL('../src/', import.meta.url)));
    if (problems.length) {
      process.stderr.write(`${problems.join('\n')}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write('Engine import boundaries passed.\n');
    }
  } catch (error) {
    process.stderr.write(`Architecture check could not complete: ${error.message}\n`);
    process.exitCode = 1;
  }
}
