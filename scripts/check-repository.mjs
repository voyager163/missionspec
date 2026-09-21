import { readFile, readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import GithubSlugger from 'github-slugger';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { parseDocument } from 'yaml';

export const requiredFiles = [
  'README.md', 'LICENSE', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
  'docs/maintainer-setup.md', '.github/PULL_REQUEST_TEMPLATE.md',
  '.github/ISSUE_TEMPLATE/bug_report.yml', '.github/ISSUE_TEMPLATE/feature_request.yml',
  '.github/ISSUE_TEMPLATE/config.yml', '.github/workflows/repository.yml',
  '.github/workflows/codeql.yml', '.github/workflows/dependency-review.yml',
  '.github/dependabot.yml', 'package.json', 'package-lock.json'
];

const approvedActions = new Set(['actions/checkout', 'actions/setup-node']);
const approvedLicenses = 'Apache-2.0, MIT, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD, CC0-1.0, Unlicense, Zlib';
const hostedRunners = new Set(['ubuntu-latest', 'macos-latest', 'windows-latest']);
const fieldTypes = new Set(['input', 'textarea', 'dropdown', 'checkboxes']);
const isRecord = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = (value) => typeof value === 'string' && value.trim().length > 0;

function visit(node, callback) {
  callback(node);
  for (const child of node.children ?? []) visit(child, callback);
}

function nodeText(node) {
  return node.value ?? node.alt ?? (node.children ?? []).map(nodeText).join('');
}

export function markdownInfo(content) {
  const tree = fromMarkdown(content);
  const slugger = new GithubSlugger();
  const anchors = new Set();
  const links = [];
  const references = [];
  const definitions = new Map();
  visit(tree, (node) => {
    if (node.type === 'heading') anchors.add(slugger.slug(nodeText(node)));
    if (node.type === 'link' || node.type === 'image') links.push(node.url);
    if (node.type === 'definition') definitions.set(node.identifier, node.url);
    if (node.type === 'linkReference' || node.type === 'imageReference') references.push(node.identifier);
  });
  for (const reference of references) {
    if (definitions.has(reference)) links.push(definitions.get(reference));
  }
  return { anchors, links };
}

export function parseYaml(content, file) {
  const document = parseDocument(content, { uniqueKeys: true });
  if (document.errors.length || document.warnings.length) {
    throw new Error(`${file}: invalid YAML: ${[...document.errors, ...document.warnings].map((error) => error.message).join('; ')}`);
  }
  return document.toJS({ maxAliasCount: 50 });
}

export function checkIssueForm(form, file = 'issue form') {
  const problems = [];
  if (!isRecord(form) || !nonempty(form.name) || !nonempty(form.description) || !Array.isArray(form.body) || form.body.length === 0) {
    return [`${file}: name, description and a nonempty body are required`];
  }
  const ids = new Set();
  for (const field of form.body) {
    if (!isRecord(field) || !isRecord(field.attributes)) {
      problems.push(`${file}: every field needs attributes`);
      continue;
    }
    if (field.type === 'markdown') {
      if (!nonempty(field.attributes.value)) problems.push(`${file}: markdown needs a value`);
      continue;
    }
    if (!fieldTypes.has(field.type) || !nonempty(field.attributes.label)) {
      problems.push(`${file}: unsupported field type or missing label`);
    }
    if (typeof field.id !== 'string' || !/^[a-z][a-z0-9_-]*$/.test(field.id) || ids.has(field.id)) {
      problems.push(`${file}: invalid or duplicate field id`);
    }
    ids.add(field.id);
    if (field.validations !== undefined &&
        (!isRecord(field.validations) || typeof field.validations.required !== 'boolean')) {
      problems.push(`${file}: validations.required must be a boolean`);
    }
    if (field.type === 'dropdown' && (!Array.isArray(field.attributes.options) ||
        field.attributes.options.length === 0 || !field.attributes.options.every(nonempty))) {
      problems.push(`${file}: dropdown needs nonempty string options`);
    }
    if (field.type === 'checkboxes' && (!Array.isArray(field.attributes.options) ||
        field.attributes.options.length === 0 ||
        !field.attributes.options.every((option) => isRecord(option) && nonempty(option.label)))) {
      problems.push(`${file}: checkboxes need labeled options`);
    }
  }
  return problems;
}

export function checkWorkflow(workflow, file = 'workflow') {
  const problems = [];
  const isCodeql = file === '.github/workflows/codeql.yml';
  const isDependencyReview = file === '.github/workflows/dependency-review.yml';
  const allowed = new Set(approvedActions);
  if (isCodeql) {
    allowed.add('github/codeql-action/init');
    allowed.add('github/codeql-action/analyze');
  }
  if (isDependencyReview) allowed.add('actions/dependency-review-action');
  if (!isRecord(workflow) || !isRecord(workflow.on) || !isRecord(workflow.jobs)) {
    return [`${file}: explicit events and jobs are required`];
  }
  if (!isRecord(workflow.permissions) ||
      Object.keys(workflow.permissions).length !== 1 || workflow.permissions.contents !== 'read') {
    problems.push(`${file}: default permissions must be contents: read only`);
  }
  const events = Object.keys(workflow.on);
  if (events.length === 0 || events.some((event) => !['pull_request', 'push', 'workflow_dispatch'].includes(event))) {
    problems.push(`${file}: unsupported or privileged event`);
  }
  if (workflow.env?.DO_NOT_TRACK !== '1' || workflow.env?.MISSIONSPEC_TELEMETRY !== '0') {
    problems.push(`${file}: CI telemetry must be explicitly disabled`);
  }
  if (!isRecord(workflow.concurrency) || !nonempty(workflow.concurrency.group) ||
      workflow.concurrency['cancel-in-progress'] !== true) {
    problems.push(`${file}: bounded PR concurrency is required`);
  }
  if (/\$\{\{[^}]*\bsecrets\b[^}]*\}\}/.test(JSON.stringify(workflow))) {
    problems.push(`${file}: contributor checks must not access secrets`);
  }
  if (Object.keys(workflow.jobs).length === 0) problems.push(`${file}: no jobs configured`);
  for (const [name, job] of Object.entries(workflow.jobs)) {
    if (!isRecord(job)) {
      problems.push(`${file}: ${name} is not a job object`);
      continue;
    }
    const codeqlPermissions = isCodeql && isRecord(job.permissions) &&
      Object.keys(job.permissions).length === 3 &&
      job.permissions.contents === 'read' && job.permissions.actions === 'read' &&
      job.permissions['security-events'] === 'write';
    if ((job.permissions !== undefined && !codeqlPermissions) || job.environment !== undefined || job.if !== undefined ||
        job['continue-on-error'] !== undefined) {
      problems.push(`${file}: ${name} must not elevate, use environments, skip, or mask failures`);
    }
    if (isCodeql && !codeqlPermissions) problems.push(`${file}: CodeQL requires its exact reporting permissions`);
    if (!Number.isInteger(job['timeout-minutes']) || job['timeout-minutes'] <= 0 || job['timeout-minutes'] > 15) {
      problems.push(`${file}: ${name} requires a timeout of 1-15 minutes`);
    }
    const runner = job['runs-on'];
    const matrix = job.strategy?.matrix?.os;
    if (!hostedRunners.has(runner) &&
        !(runner === '${{ matrix.os }}' && Array.isArray(matrix) &&
          matrix.length > 0 && matrix.every((os) => hostedRunners.has(os)))) {
      problems.push(`${file}: ${name} must use approved hosted runners`);
    }
    if (!Array.isArray(job.steps) || job.steps.length === 0) {
      problems.push(`${file}: ${name} has no executable steps`);
      continue;
    }
    for (const step of job.steps) {
      if (!isRecord(step)) {
        problems.push(`${file}: ${name} contains a malformed step`);
        continue;
      }
      if (step['continue-on-error'] !== undefined || step.if !== undefined) {
        problems.push(`${file}: seed steps must not skip checks or mask failures`);
      }
      if (step.uses !== undefined) {
        const match = typeof step.uses === 'string' && /^([^@]+)@([a-f0-9]{40})$/.exec(step.uses);
        if (!match || !allowed.has(match[1])) problems.push(`${file}: action must be approved and full-SHA pinned`);
        if (match && match[1] === 'actions/checkout' && step.with?.['persist-credentials'] !== false) {
          problems.push(`${file}: checkout must not persist credentials`);
        }
      } else if (!nonempty(step.run)) {
        problems.push(`${file}: step needs a run command or pinned action`);
      }
      if (isCodeql && step.run !== undefined) problems.push(`${file}: source-analysis job must not execute project build scripts`);
    }
    if (isCodeql) {
      const languages = job.strategy?.matrix?.language;
      if (!Array.isArray(languages) || languages.length !== 2 ||
          !['javascript-typescript', 'actions'].every((language) => languages.includes(language))) {
        problems.push(`${file}: CodeQL must cover TypeScript/JavaScript and Actions`);
      }
      if (!job.steps.some((step) => isRecord(step) &&
          typeof step.uses === 'string' && step.uses.startsWith('github/codeql-action/init@') &&
          step.with?.languages === '${{ matrix.language }}' &&
          step.with?.['build-mode'] === 'none' && step.with?.queries === 'security-extended')) {
        problems.push(`${file}: missing bounded source-only CodeQL initialization`);
      }
      if (!job.steps.some((step) => isRecord(step) &&
          typeof step.uses === 'string' && step.uses.startsWith('github/codeql-action/analyze@') &&
          isRecord(step.with) && Object.keys(step.with).length === 1 &&
          step.with.category === '/language:${{ matrix.language }}')) {
        problems.push(`${file}: CodeQL must analyze and upload both declared categories`);
      }
    }
    if (isDependencyReview && !job.steps.some((step) => isRecord(step) &&
      typeof step.uses === 'string' && step.uses.startsWith('actions/dependency-review-action@') &&
      isRecord(step.with) && Object.keys(step.with).length === 5 &&
      step.with?.['fail-on-severity'] === 'high' && step.with?.['comment-summary-in-pr'] === 'never' &&
      step.with?.['license-check'] === true && step.with?.['allow-licenses'] === approvedLicenses &&
      step.with?.['allow-dependencies-licenses'] === 'pkg:npm/json-schema-typed')) {
      problems.push(`${file}: dependency severity, license and no-comment policy must be explicit`);
    }
  }
  return problems;
}

function inside(root, target) {
  const relative = path.relative(root, target);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

export function localLinkTarget(source, link) {
  if (/^(https?:|mailto:)/i.test(link)) return undefined;
  if (/^[a-z][a-z0-9+.-]*:/i.test(link) || link.startsWith('//')) throw new Error('unsupported link protocol');
  const hashIndex = link.indexOf('#');
  const pathname = (hashIndex < 0 ? link : link.slice(0, hashIndex)).split('?', 1)[0];
  let decodedPath;
  let fragment;
  try {
    decodedPath = decodeURIComponent(pathname);
    fragment = hashIndex < 0 ? '' : decodeURIComponent(link.slice(hashIndex + 1));
  } catch {
    throw new Error('invalid URL encoding');
  }
  const normalizedSource = source.replaceAll('\\', '/');
  const target = decodedPath
    ? path.posix.normalize(path.posix.join(path.posix.dirname(normalizedSource), decodedPath))
    : normalizedSource;
  if (decodedPath.startsWith('/') || decodedPath.includes('\\') || decodedPath.includes(':') ||
      target === '..' || target.startsWith('../')) {
    throw new Error('local link escapes the repository or uses a nonportable path');
  }
  return { path: target, fragment };
}

export async function checkLocalLink(root, source, link) {
  let reference;
  try {
    reference = localLinkTarget(source, link);
  } catch (error) {
    return `${source}: ${error.message}: ${link}`;
  }
  if (reference === undefined) return undefined;
  const target = path.resolve(root, reference.path);
  if (!inside(root, target)) return `${source}: local link escapes the repository: ${link}`;
  try {
    const resolved = await realpath(target);
    if (!inside(await realpath(root), resolved)) return `${source}: symlink link escapes the repository: ${link}`;
    if (reference.fragment && target.endsWith('.md') &&
        !markdownInfo(await readFile(target, 'utf8')).anchors.has(reference.fragment)) {
      return `${source}: missing heading anchor: ${link}`;
    }
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return `${source}: missing local target: ${link}`;
    throw error;
  }
  return undefined;
}

async function markdownFiles(directory, prefix = '') {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) files.push(...await markdownFiles(path.join(directory, entry.name), relative));
    else if (entry.isFile() && entry.name.endsWith('.md')) files.push(relative);
  }
  return files;
}

export async function checkRepository(root) {
  const problems = [];
  const resolvedRoot = await realpath(root);
  for (const file of requiredFiles) {
    try {
      const target = path.join(root, file);
      if (!inside(resolvedRoot, await realpath(target))) {
        problems.push(`${file}: required input resolves outside the repository`);
      } else if (!(await stat(target)).isFile()) {
        problems.push(`${file}: expected a file`);
      }
    } catch (error) {
      if (error.code === 'ENOENT') problems.push(`${file}: required file missing`);
      else throw error;
    }
  }
  if (problems.length) return problems;
  const files = [
    'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
    '.github/PULL_REQUEST_TEMPLATE.md',
    ...(await markdownFiles(path.join(root, 'docs'))).map((file) => path.join('docs', file))
  ];
  for (const file of files) {
    for (const link of markdownInfo(await readFile(path.join(root, file), 'utf8')).links) {
      const problem = await checkLocalLink(root, file, link);
      if (problem) problems.push(problem);
    }
  }
  for (const name of ['bug_report.yml', 'feature_request.yml']) {
    const file = `.github/ISSUE_TEMPLATE/${name}`;
    problems.push(...checkIssueForm(parseYaml(await readFile(path.join(root, file), 'utf8'), file), file));
  }
  const chooser = parseYaml(await readFile(path.join(root, '.github/ISSUE_TEMPLATE/config.yml'), 'utf8'), 'issue chooser');
  if (!isRecord(chooser) || chooser.blank_issues_enabled !== true) problems.push('Issue chooser must retain general issues');
  for (const entry of await readdir(path.join(root, '.github/workflows'), { withFileTypes: true })) {
    if (!/\.ya?ml$/.test(entry.name)) continue;
    const name = `.github/workflows/${entry.name}`;
    if (!entry.isFile()) {
      problems.push(`${name}: workflow must be a regular file, not a symlink or directory`);
      continue;
    }
    problems.push(...checkWorkflow(parseYaml(await readFile(path.join(root, name), 'utf8'), name), name));
  }
  const dependabot = parseYaml(await readFile(path.join(root, '.github/dependabot.yml'), 'utf8'), 'dependabot');
  if (dependabot?.version !== 2 || !Array.isArray(dependabot.updates) ||
      !['npm', 'github-actions'].every((ecosystem) => dependabot.updates.some((update) =>
        update['package-ecosystem'] === ecosystem && update.directory === '/' &&
        update['target-branch'] === 'develop' && update.schedule?.interval === 'weekly'))) {
    problems.push('Dependabot must cover npm and Actions on develop weekly');
  }
  const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  if (manifest.license !== 'Apache-2.0' || manifest.private !== true) {
    problems.push('Seed package must preserve Apache-2.0 and remain private until release authorization');
  }
  return problems;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const problems = await checkRepository(fileURLToPath(new URL('../', import.meta.url)));
    if (problems.length) {
      process.stderr.write(`${problems.join('\n')}\n`);
      process.exitCode = 1;
    } else {
      process.stdout.write('Repository documentation, forms, and seed workflow policies passed.\n');
    }
  } catch (error) {
    process.stderr.write(`Repository check could not complete: ${error.message}\n`);
    process.exitCode = 1;
  }
}
