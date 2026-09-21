import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCOPES = Object.freeze({
  cli: {
    directory: '.',
    inventory: 'licenses/cli-runtime.json',
    notices: 'THIRD_PARTY_NOTICES',
  },
  service: {
    directory: 'services/telemetry-ingest',
    inventory: 'licenses/telemetry-runtime.json',
    notices: 'licenses/TELEMETRY_THIRD_PARTY_NOTICES',
  },
});

const approvedExpressions = new Set([
  'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', '(MIT AND Zlib)',
]);
const excludedPackages = new Set([
  '@anthropic-ai/claude-agent-sdk', '@anthropic-ai/claude-code',
]);
const legalFilename = /^(?:(?:licen[cs]e|copying|notice|copyright(?:notice)?)(?:$|[._-])|third[-_. ]?party[-_. ]?notices?(?:$|[._-]))/i;
const primaryLicense = /^(?:licen[cs]e|copying)(?:$|[._-])/i;
const packageLocation = /^(?:node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)(?:\/node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)*$/;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const normalize = (value) => value.replace(/\r\n?/g, '\n');
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;

export function assertMetadataExceptionPin(source, expression, documents) {
  if (source.name !== 'json-schema-typed') return;
  if (source.version !== '8.0.2' || expression !== 'BSD-2-Clause' ||
      source.resolved !== 'https://registry.npmjs.org/json-schema-typed/-/json-schema-typed-8.0.2.tgz' ||
      source.integrity !== 'sha512-fQhoXdcvc3V28x7C7BMs4P5+kNlgUURe2jmUT1T//oBRMDrqy1QPelJimwZGo7Hg9VPV3EQV5Bnq4hbFy2vetA==' ||
      documents.length !== 1 || documents[0].path !== 'LICENSE.md' ||
      documents[0].sourceSha256 !== 'bbe87b573c12bda5baf18742117330efa177e0886b3b0a278dacf8f236e1e129' ||
      documents[0].retainedSha256 !== '2701eb669226473bb7df25dff5abcd3b7f73589091dce6dea1ca50919a138c73') {
    throw new Error('The json-schema-typed Dependency Graph metadata exception requires its exact reviewed tarball and legal text; review any change before widening it.');
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort(compare).map((key) => [key, canonical(value[key])]));
  }
  return value;
}

const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const equivalent = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));

function relativePath(value) {
  if (typeof value !== 'string' || !value || path.posix.isAbsolute(value) || path.win32.isAbsolute(value) ||
      value.includes('\\') || value.includes('\0') ||
      value.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error(`Unsafe relative path: ${value}`);
  }
  return value;
}

function inside(root, relative) {
  relativePath(relative);
  let result = realpathSync(root);
  for (const part of relative.split('/')) {
    result = path.join(result, part);
    if (lstatSync(result, { throwIfNoEntry: false })?.isSymbolicLink()) {
      throw new Error(`Refusing symlink in license input/output: ${relative}`);
    }
  }
  return result;
}

function readJson(root, relative) {
  return JSON.parse(readFileSync(inside(root, relative), 'utf8'));
}

function reviewedTexts(root) {
  const policy = readJson(root, 'licenses/reviewed-texts.json');
  if (policy.schemaVersion !== 1 || !Array.isArray(policy.reviewedFiles)) {
    throw new Error('Invalid reviewed legal-text catalog');
  }
  const fingerprints = new Set();
  for (const entry of policy.reviewedFiles) {
    if (!approvedExpressions.has(entry.licenseExpression) ||
        !/^[a-f0-9]{64}$/.test(entry.retainedSha256) ||
        !Array.isArray(entry.observedAt) || !entry.observedAt.length ||
        entry.observedAt.some((source) => typeof source !== 'string' || !source)) {
      throw new Error('Invalid reviewed legal-text entry');
    }
    const key = `${entry.licenseExpression}:${entry.retainedSha256}`;
    if (fingerprints.has(key)) throw new Error(`Duplicate reviewed legal-text fingerprint: ${key}`);
    fingerprints.add(key);
  }
  return fingerprints;
}

function nameAt(location) {
  if (!packageLocation.test(location)) throw new Error(`Unsupported locked package location: ${location}`);
  relativePath(location);
  return location.slice(location.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

function resolveDependency(packages, from, name) {
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(name) ||
      name.split('/').some((part) => part === '.' || part === '..')) {
    throw new Error(`Invalid dependency name: ${name}`);
  }
  let at = from;
  while (true) {
    if (path.posix.basename(at) !== 'node_modules') {
      const candidate = path.posix.join(at, 'node_modules', name);
      if (Object.hasOwn(packages, candidate)) return candidate;
    }
    if (!at || at === '.') return undefined;
    at = path.posix.dirname(at);
  }
}

export function runtimeGraph(packages) {
  if (!packages?.['']) throw new Error('Lockfile has no root package');
  for (const location of Object.keys(packages)) if (location) nameAt(location);
  const graph = new Map();
  const pending = [''];
  while (pending.length) {
    const from = pending.pop();
    if (graph.has(from)) continue;
    const record = packages[from];
    const names = new Set([
      ...Object.keys(record.dependencies ?? {}),
      ...Object.keys(record.optionalDependencies ?? {}),
      ...Object.keys(record.peerDependencies ?? {}),
    ]);
    const dependencies = {};
    const omittedOptional = [];
    for (const name of [...names].sort(compare)) {
      const target = resolveDependency(packages, from, name);
      if (!target) {
        if (Object.hasOwn(record.optionalDependencies ?? {}, name) ||
            (!Object.hasOwn(record.dependencies ?? {}, name) && record.peerDependenciesMeta?.[name]?.optional)) {
          omittedOptional.push(name);
          continue;
        }
        throw new Error(`Unresolved runtime dependency ${name} from ${from || '<root>'}`);
      }
      if (packages[target].dev === true) {
        throw new Error(`Reachable runtime package incorrectly marked development-only: ${target}`);
      }
      dependencies[name] = target;
      pending.push(target);
    }
    graph.set(from, { dependencies, omittedOptional });
  }
  for (const [location, record] of Object.entries(packages)) {
    if (location && record.dev !== true && !graph.has(location)) {
      throw new Error(`Unclassified non-development package: ${location}`);
    }
  }
  return graph;
}

function sourceRecord(location, record) {
  const name = nameAt(location);
  if (typeof record.version !== 'string' || !record.version || record.link ||
      record.inBundle || record.bundled) {
    throw new Error(`Unsupported linked or bundled package: ${location}`);
  }
  let source;
  try { source = new URL(record.resolved); } catch { /* Rejected below. */ }
  if (!source || source.origin !== 'https://registry.npmjs.org' ||
      source.username || source.password || source.search || source.hash ||
      !source.pathname.endsWith('.tgz')) {
    throw new Error(`Unreviewed package source for ${location}: ${record.resolved}`);
  }
  if (typeof record.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(record.integrity) ||
      Buffer.from(record.integrity.slice(7), 'base64').length !== 64 ||
      Buffer.from(record.integrity.slice(7), 'base64').toString('base64') !== record.integrity.slice(7)) {
    throw new Error(`Missing or unsupported tarball integrity: ${location}`);
  }
  return { location, name, version: record.version, resolved: record.resolved, integrity: record.integrity };
}

function discoverLegalFiles(packageRoot, prefix = '') {
  const found = [];
  for (const entry of readdirSync(packageRoot, { withFileTypes: true }).sort((a, b) => compare(a.name, b.name))) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const relative = `${prefix}${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`Unreviewed symlink in package: ${relative}`);
    if (entry.isDirectory()) {
      found.push(...discoverLegalFiles(path.join(packageRoot, entry.name), `${relative}/`));
    } else if (entry.isFile() && legalFilename.test(entry.name)) {
      found.push(relative);
    }
  }
  return found;
}

export function assertLicenseEvidence(expression, documents, identity) {
  if (!approvedExpressions.has(expression)) {
    throw new Error(`Unreviewed or disallowed license expression for ${identity}: ${expression}`);
  }
  const text = documents.map((document) => document.text).join('\n').replace(/\s+/g, ' ');
  if (/GNU (?:LESSER |AFFERO )?GENERAL PUBLIC LICENSE|BUSINESS SOURCE LICENSE|Commons Clause/i.test(text)) {
    throw new Error(`Conflicting license terms in ${identity}; manual review required`);
  }
  const mit = /Permission is hereby granted, free of charge/i.test(text) &&
    /copyright notice and this permission notice shall be included/i.test(text);
  const isc = /Permission to use, copy, modify,? and\/or distribute/i.test(text);
  const bsd = /Redistribution and use in source and binary forms/i.test(text) &&
    /Redistributions in binary form must reproduce/i.test(text);
  const evidence = {
    MIT: mit,
    ISC: isc && /provided that the above copyright notice/i.test(text),
    '0BSD': isc && /with or without fee is hereby granted/i.test(text),
    'BSD-2-Clause': bsd,
    'BSD-3-Clause': bsd && /endorse or promote/i.test(text),
    'Apache-2.0': /Apache License Version 2\.0/i.test(text) && /Grant of Patent License/i.test(text),
    '(MIT AND Zlib)': mit && /Altered source versions must be plainly marked/i.test(text) &&
      /This notice may not be removed or altered from any source distribution/i.test(text),
  };
  if (!evidence[expression]) {
    throw new Error(`Missing license-text evidence for ${identity} (${expression})`);
  }
}

function legalDocuments(scopeRoot, location, name, version, expression, reviewed) {
  const packageRoot = inside(scopeRoot, location);
  const paths = discoverLegalFiles(packageRoot);
  // Pako's MIT file does not contain its separately applicable zlib terms.
  if (name === 'pako') {
    if (version !== '2.2.0' || expression !== '(MIT AND Zlib)') {
      throw new Error('Pako supplemental notice selection needs review for this version/license');
    }
    paths.push('lib/zlib/README');
  }
  if (!paths.some((file) => primaryLicense.test(path.posix.basename(file)))) {
    throw new Error(`No retained license file in ${location}`);
  }
  const documents = [...new Set(paths)].sort(compare).map((file) => {
    const source = readFileSync(inside(packageRoot, file));
    if (source.length === 0 || source.length > 1024 * 1024) throw new Error(`Invalid legal file size: ${location}/${file}`);
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(source);
    const text = normalize(decoded);
    if (!text.trim()) throw new Error(`Empty license text: ${location}/${file}`);
    return { path: file, sourceSha256: sha256(source), retainedSha256: sha256(text), text };
  });
  assertLicenseEvidence(expression, documents, `${name}@${version}`);
  for (const document of documents) {
    if (!reviewed.has(`${expression}:${document.retainedSha256}`)) {
      throw new Error(
        `Unreviewed legal-file fingerprint: ${name}@${version}/${document.path} (${expression}, ${document.retainedSha256}). ` +
        'Inspect its full terms and explicitly update licenses/reviewed-texts.json; --write cannot approve legal text.',
      );
    }
  }
  return documents;
}

function noticesFor(scope, packages, documentSets) {
  let output = [
    'MissionSpec third-party notices',
    `Scope: ${scope === 'cli' ? 'CLI locked runtime dependencies' : 'Isolated telemetry ingestion service locked runtime dependencies'}`,
    '',
    'Generated by scripts/check-licenses.mjs from installed, locked packages.',
    'Package license and notice text is retained below, with line endings normalized to LF.',
    'These packages keep their own licenses; MissionSpec does not relicense them.',
    'Runtime dependencies may be installed separately by npm rather than embedded in the CLI tarball.',
    scope === 'cli'
      ? 'Operator-service and development-only dependencies are not part of this CLI notice set.'
      : 'This is the service notice set, not part of the CLI distribution.',
    'This inventory is evidence for review, not legal advice or a release authorization.',
    '',
  ].join('\n');
  for (const record of packages) {
    output += [
      '\n================================================================================',
      `${record.name}@${record.version}`,
      `Locked location: ${record.location}`,
      `Source: ${record.resolved}`,
      `Integrity: ${record.integrity}`,
      `Declared license: ${record.licenseExpression}`,
      '',
    ].join('\n');
    for (const document of documentSets.get(record.location)) {
      output += `\n--- ${document.path} (retained SHA-256: ${document.retainedSha256}) ---\n`;
      output += document.text;
      if (!document.text.endsWith('\n')) output += '\n';
      output += `--- End ${document.path} ---\n`;
    }
  }
  return output;
}

export function collectScope(repositoryRoot, scope) {
  if (!Object.hasOwn(SCOPES, scope)) throw new Error(`Unknown license scope: ${scope}`);
  const config = SCOPES[scope];
  const root = realpathSync(repositoryRoot);
  const reviewed = reviewedTexts(root);
  const scopeRoot = config.directory === '.' ? root : inside(root, config.directory);
  const manifest = readJson(scopeRoot, 'package.json');
  const lock = readJson(scopeRoot, 'package-lock.json');
  if (lock.lockfileVersion !== 3 || lock.packages?.['']?.name !== manifest.name ||
      lock.packages[''].version !== manifest.version) {
    throw new Error(`Unrecognized or stale ${scope} lockfile; require lockfileVersion 3 and matching root identity`);
  }
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'devDependencies']) {
    if (!equivalent(manifest[field] ?? {}, lock.packages[''][field] ?? {})) {
      throw new Error(`Manifest/lock ${field} mismatch in ${scope}`);
    }
  }
  for (const [name, version] of Object.entries({ ...manifest.dependencies, ...manifest.optionalDependencies })) {
    if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
      throw new Error(`Direct runtime dependency must be exactly pinned: ${name}@${version}`);
    }
  }
  const graph = runtimeGraph(lock.packages);
  const documents = new Map();
  const runtimePackages = [...graph.keys()].filter(Boolean).sort(compare).map((location) => {
    const locked = lock.packages[location];
    const source = sourceRecord(location, locked);
    if (excludedPackages.has(source.name)) throw new Error(`Excluded commercial Claude package: ${source.name}`);
    const installed = readJson(scopeRoot, `${location}/package.json`);
    if (installed.name !== source.name || installed.version !== source.version ||
        installed.license !== locked.license) {
      throw new Error(`Installed identity/license differs from lockfile: ${location}`);
    }
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta']) {
      if (!equivalent(installed[field] ?? {}, locked[field] ?? {})) {
        throw new Error(`Installed ${field} differ from lockfile: ${location}`);
      }
    }
    if ((installed.bundleDependencies?.length ?? 0) || (installed.bundledDependencies?.length ?? 0)) {
      throw new Error(`Unreviewed bundled dependencies in ${location}`);
    }
    const retained = legalDocuments(scopeRoot, location, source.name, source.version, locked.license, reviewed);
    assertMetadataExceptionPin(source, locked.license, retained);
    documents.set(location, retained);
    return {
      ...source,
      relationship: Object.values(graph.get('').dependencies).includes(location) ? 'direct' : 'transitive',
      alsoDirectDevelopmentDependency: Object.hasOwn(manifest.devDependencies ?? {}, source.name) &&
        resolveDependency(lock.packages, '', source.name) === location,
      licenseExpression: locked.license,
      optional: locked.optional === true,
      dependencies: graph.get(location).dependencies,
      omittedOptional: graph.get(location).omittedOptional,
      legalFiles: retained.map(({ text, ...document }) => document),
    };
  });
  const developmentOnly = Object.entries(lock.packages)
    .filter(([location]) => location && !graph.has(location))
    .sort(([a], [b]) => compare(a, b))
    .map(([location, record]) => ({
      location,
      name: nameAt(location),
      version: record.version,
      declaredLicense: record.license ?? null,
      optional: record.optional === true,
      audit: 'excluded-development-only; license text not reviewed',
    }));
  const inventory = {
    schemaVersion: 1,
    scope,
    packageName: manifest.name,
    packageVersion: manifest.version,
    lockfile: path.posix.join(config.directory, 'package-lock.json'),
    lockfileDataSha256: sha256(JSON.stringify(canonical(lock))),
    selection: 'Complete locked runtime dependency/optional/peer closure; not a bundle or reachability analysis of executable code.',
    provenanceLimit: 'Tarball integrity is recorded from the lockfile; trust restoration via npm ci. This check does not independently authenticate installed source bytes.',
    directDependencies: graph.get('').dependencies,
    omittedOptional: graph.get('').omittedOptional,
    runtimePackages,
    developmentOnly,
  };
  return {
    inventory,
    outputs: new Map([
      [config.inventory, json(inventory)],
      [config.notices, noticesFor(scope, runtimePackages, documents)],
    ]),
  };
}

export function verifyOutputs(root, outputs) {
  const problems = [];
  for (const [file, expected] of outputs) {
    const target = inside(root, file);
    if (!existsSync(target)) problems.push(`Missing generated licensing artifact: ${file}`);
    else if (normalize(readFileSync(target, 'utf8')) !== expected) problems.push(`Stale licensing artifact: ${file}`);
  }
  return problems;
}

export function packageNoticeProblems(preview, packageName, noticeBytes) {
  const entries = Array.isArray(preview) ? preview : preview && typeof preview === 'object' ? Object.values(preview) : [];
  if (entries.length !== 1 || entries[0]?.name !== packageName || !Array.isArray(entries[0]?.files)) {
    return ['Unrecognized npm dry-run preview for notice qualification'];
  }
  const files = new Map();
  for (const file of entries[0].files) {
    try { relativePath(file.path); } catch { return ['Unsafe npm preview path']; }
    if (files.has(file.path)) return ['Duplicate npm preview path'];
    files.set(file.path, file);
  }
  const problems = [];
  for (const file of ['THIRD_PARTY_NOTICES', 'LICENSE', 'docs/licensing.md']) {
    if (!files.has(file)) problems.push(`Required licensing file is not shipped: ${file}`);
  }
  if (files.has('THIRD_PARTY_NOTICES') && files.get('THIRD_PARTY_NOTICES').size !== noticeBytes) {
    problems.push('Shipped notice size differs from the checked THIRD_PARTY_NOTICES');
  }
  for (const file of files.keys()) {
    if (file.startsWith('services/') || file === SCOPES.service.inventory || file === SCOPES.service.notices) {
      problems.push(`Service-only licensing/source asset leaked into CLI package: ${file}`);
    }
  }
  return problems;
}

export function runLicenseCheck(root, { scope = 'all', write = false, packageCheck = false } = {}) {
  if (write && packageCheck) throw new Error('--write and --package must run separately');
  const scopes = scope === 'all' ? Object.keys(SCOPES) : [scope];
  const results = scopes.map((selected) => collectScope(root, selected));
  const outputs = new Map(results.flatMap((result) => [...result.outputs]));
  if (write) {
    for (const [file, content] of outputs) {
      const target = inside(root, file);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, content, 'utf8');
    }
  }
  const problems = verifyOutputs(root, outputs);
  if (packageCheck) {
    if (!scopes.includes('cli')) throw new Error('--package requires cli or all scope');
    const npmCli = process.env.npm_execpath;
    if (!npmCli || !path.isAbsolute(npmCli)) throw new Error('Run --package through an npm script so npm_execpath identifies npm');
    const preview = JSON.parse(execFileSync(process.execPath, [
      npmCli, 'pack', '--dry-run', '--ignore-scripts', '--json',
    ], { cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024 }));
    problems.push(...packageNoticeProblems(
      preview, readJson(root, 'package.json').name, readFileSync(inside(root, 'THIRD_PARTY_NOTICES')).length,
    ));
  }
  if (problems.length) throw new Error(`${problems.join('\n')}\nReview dependency/license changes before regenerating with --write.`);
  return results.map(({ inventory }) => ({
    scope: inventory.scope,
    runtime: inventory.runtimePackages.length,
    developmentOnly: inventory.developmentOnly.length,
  }));
}

if (import.meta.main) {
  try {
    const options = {};
    const args = process.argv.slice(2);
    for (let index = 0; index < args.length; index += 1) {
      if (args[index] === '--write') options.write = true;
      else if (args[index] === '--package') options.packageCheck = true;
      else if (args[index] === '--scope' && ['all', ...Object.keys(SCOPES)].includes(args[index + 1])) {
        options.scope = args[++index];
      } else throw new Error(`Unknown/incomplete option: ${args[index]}`);
    }
    const results = runLicenseCheck(fileURLToPath(new URL('../', import.meta.url)), options);
    for (const result of results) {
      console.log(`${result.scope}: ${result.runtime} runtime packages; ${result.developmentOnly} development-only packages classified, not license-reviewed.`);
    }
    console.log(options.write ? 'Generated licensing artifacts; review their diff before accepting.' : 'Locked inventories and retained notices match.');
  } catch (error) {
    console.error(`License check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
