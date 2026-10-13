import { fromMarkdown } from 'mdast-util-from-markdown';
import { parseId, parseProjectPath, type ProjectPath } from '../../../kernel/identifiers.js';
import { digestContent } from '../../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../../kernel/validation.js';
import {
  DOCUMENT_KINDS, type DocumentDeclaration, type DocumentDiagnostic, type DocumentDiagnosticCode,
  type DocumentKind, type DocumentParseResult, type DocumentSection, type SourceLocation,
} from './types.js';
import { MetadataSyntaxError, readMetadata } from './yaml.js';

type Block = ReturnType<typeof fromMarkdown>['children'][number];
type Heading = Extract<Block, { type: 'heading' }>;

const SECTIONS: Readonly<Record<DocumentKind, {
  readonly required: readonly string[];
  readonly optional: readonly string[];
}>> = Object.freeze({
  proposal: { required: ['Problem', 'Outcome', 'Scope', 'Acceptance'], optional: ['Notes'] },
  specs: { required: ['Requirements'], optional: ['Notes'] },
  baseline: { required: ['Requirements'], optional: ['Notes'] },
  design: { required: ['Approach', 'Risks'], optional: ['Notes'] },
  tasks: { required: ['Tasks', 'Checks'], optional: ['Design', 'Notes'] },
  verification: { required: ['Checks'], optional: ['Notes'] },
  discovery: { required: ['Findings', 'Questions'], optional: ['Notes'] },
  principles: { required: ['Principles'], optional: ['Notes'] },
});

function location(source: string, path: ProjectPath | null, offset: number): SourceLocation {
  const preceding = source.slice(0, offset);
  return Object.freeze({
    path, offset, line: preceding.split('\n').length,
    column: offset - preceding.lastIndexOf('\n'),
  });
}

function diagnostic(
  source: string, path: ProjectPath | null, offset: number,
  code: DocumentDiagnosticCode, message: string,
): DocumentDiagnostic {
  return Object.freeze({ code, message, location: location(source, path, offset) });
}

function invalid(diagnostics: readonly DocumentDiagnostic[]): DocumentParseResult {
  return Object.freeze({ state: 'invalid', diagnostics: Object.freeze([...diagnostics]) });
}

function headingText(source: string, heading: Heading): string | null {
  const raw = source.slice(heading.position?.start.offset, heading.position?.end.offset);
  const prefix = `${'#'.repeat(heading.depth)} `;
  if (!raw.startsWith(prefix) || /[\r\n]/u.test(raw) || /^[ \t]/u.test(raw.slice(prefix.length))) return null;
  return raw.slice(prefix.length).replace(/ +#+ *$/u, '').trim();
}

function parseDeclaration(
  heading: string,
  metadata: unknown,
  prose: string,
  rawDeclaration: string,
  sourceLocation: SourceLocation,
  baseline: boolean,
): DocumentDeclaration {
  const match = /^(?:\[([ xX])\] )?((REQ|SCN|TSK|CHK)-[A-Za-z0-9-]+): (.+)$/u.exec(heading);
  if (match === null) throw new ContractError('declaration', 'expected a typed identity and title');
  const [, progress, identity, prefix, title] = match;
  const base = {
    title: text(title, 'declaration.title', 240),
    prose,
    location: sourceLocation,
    intentRevision: digestContent(prefix === 'TSK' ? rawDeclaration.replace(/^(### \[)[xX](\] )/u, '$1 $2') : rawDeclaration),
  };
  if (prefix !== 'TSK' && progress !== undefined) {
    throw new ContractError('declaration', 'only task headings have progress claims');
  }
  if (prefix === 'REQ') {
    const data = record(metadata, 'requirement', baseline ? [] : ['operation']);
    return Object.freeze({
      ...base, kind: 'requirement', id: parseId('requirement', identity),
      operation: baseline ? 'retain' : oneOf(data.operation, ['add', 'modify', 'remove'], 'requirement.operation'),
    });
  }
  if (prefix === 'SCN') {
    const data = record(metadata, 'scenario', baseline ? ['requirement'] : ['operation', 'requirement']);
    return Object.freeze({
      ...base, kind: 'scenario', id: parseId('scenario', identity),
      operation: baseline ? 'retain' : oneOf(data.operation, ['add', 'modify', 'remove'], 'scenario.operation'),
      requirement: parseId('requirement', data.requirement),
    });
  }
  if (prefix === 'TSK') {
    if (progress === undefined) throw new ContractError('task', 'expected an explicit progress claim');
    const data = record(metadata, 'task', ['dependsOn', 'requirements', 'scenarios', 'checks', 'writeScope']);
    const id = parseId('task', identity);
    const dependsOn = unique(array(data.dependsOn, 'task.dependsOn', (entry) => parseId('task', entry)), 'task.dependsOn');
    if (dependsOn.includes(id)) throw new ContractError('task.dependsOn', 'self dependency');
    return Object.freeze({
      ...base, kind: 'task', id, progressClaim: progress === ' ' ? 'unchecked' : 'checked',
      dependsOn,
      requirements: unique(array(data.requirements, 'task.requirements', (entry) => parseId('requirement', entry)), 'task.requirements'),
      scenarios: unique(array(data.scenarios, 'task.scenarios', (entry) => parseId('scenario', entry)), 'task.scenarios'),
      checks: unique(array(data.checks, 'task.checks', (entry) => parseId('check', entry)), 'task.checks'),
      writeScope: unique(array(data.writeScope, 'task.writeScope', parseProjectPath), 'task.writeScope'),
    });
  }
  const data = record(metadata, 'check', ['method', 'requirements', 'scenarios']);
  return Object.freeze({
    ...base, kind: 'check', id: parseId('check', identity),
    method: oneOf(data.method, ['executed', 'static-inspection', 'agent-review'], 'check.method'),
    requirements: unique(array(data.requirements, 'check.requirements', (entry) => parseId('requirement', entry)), 'check.requirements'),
    scenarios: unique(array(data.scenarios, 'check.scenarios', (entry) => parseId('scenario', entry)), 'check.scenarios'),
  });
}

function permitted(section: string, kind: DocumentDeclaration['kind']): boolean {
  return (section === 'Requirements' && (kind === 'requirement' || kind === 'scenario')) ||
    (section === 'Tasks' && kind === 'task') || (section === 'Checks' && kind === 'check');
}

export function parseMarkdownDocument(value: unknown): DocumentParseResult {
  let source = '';
  let path: ProjectPath | null = null;
  try {
    const input = record(value, 'document', ['path', 'content']);
    try {
      path = parseProjectPath(input.path);
    } catch {
      return invalid([diagnostic('', null, 0, 'invalid-path', 'Supply a safe project-relative document path.')]);
    }
    source = text(input.content, 'document.content', 1_000_000);
  } catch {
    return invalid([diagnostic(source, path, 0, 'invalid-source', 'Supply a nonempty Markdown document of at most 1,000,000 characters.')]);
  }
  const opening = /^---\r?\n/u.exec(source);
  const closing = opening === null ? null : /^---(?:\r?\n|$)/mu.exec(source.slice(opening[0].length));
  if (opening === null || closing === null) {
    return invalid([diagnostic(source, path, 0, 'missing-frontmatter', 'Begin with a closed YAML frontmatter block.')]);
  }
  const metadataStart = opening[0].length;
  const bodyStart = metadataStart + closing.index + closing[0].length;
  let metadata;
  try {
    const raw = readMetadata(source.slice(metadataStart, metadataStart + closing.index));
    metadata = record(raw, 'frontmatter', ['schemaVersion', 'id', 'kind', 'changeId', 'checks']);
  } catch (error) {
    const offset = metadataStart + (error instanceof MetadataSyntaxError ? error.offset : 0);
    return invalid([diagnostic(source, path, offset, 'invalid-yaml', 'Frontmatter must be a closed, unambiguous mapping without tags, aliases or extra fields.')]);
  }
  if (metadata.schemaVersion !== 1) {
    return invalid([diagnostic(source, path, metadataStart, 'unsupported-version', 'Only Markdown schemaVersion 1 is supported.')]);
  }
  let id;
  let kind;
  let changeId;
  try {
    id = parseId('artifact', metadata.id);
    kind = oneOf(metadata.kind, DOCUMENT_KINDS, 'frontmatter.kind');
    if (Object.hasOwn(metadata, 'checks') && (kind !== 'tasks' || metadata.checks !== 'verification.md')) {
      throw new ContractError('frontmatter.checks', 'only tasks may explicitly select sibling verification.md');
    }
    changeId = kind === 'principles' || kind === 'baseline' ? null : parseId('change', metadata.changeId);
    if ((kind === 'principles' || kind === 'baseline') && Object.hasOwn(metadata, 'changeId')) {
      throw new ContractError('frontmatter.changeId', 'this document is project-wide');
    }
  } catch {
    return invalid([diagnostic(source, path, metadataStart, 'invalid-metadata', 'Document identity, kind or change scope is invalid.')]);
  }
  const body = source.slice(bodyStart);
  const blocks = fromMarkdown(body).children;
  const diagnostics: DocumentDiagnostic[] = [];
  const declarations: DocumentDeclaration[] = [];
  const sections: DocumentSection[] = [];
  const sectionNames = new Set<string>();
  const identities = new Set<string>();
  const consumedMetadata = new Set<number>();
  const progressOffsets: number[] = [];
  let sectionName = '';
  let title = '';
  const allowed = SECTIONS[kind];
  const add = (block: Block, code: DocumentDiagnosticCode, message: string): void => {
    diagnostics.push(diagnostic(source, path, bodyStart + (block.position?.start.offset ?? 0), code, message));
  };
  if (blocks[0]?.type !== 'heading' || blocks[0].depth !== 1) {
    diagnostics.push(diagnostic(source, path, bodyStart, 'invalid-title', 'The document body must start with one level-one ATX title.'));
  }
  for (let index = 0; index < blocks.length; index += 1) {
    const block = blocks[index];
    if (block === undefined) continue;
    if (block.type === 'code' && block.lang === 'missionspec' && !consumedMetadata.has(index)) {
      add(block, 'unexpected-metadata', 'Declaration metadata must immediately follow a typed level-three heading.');
      continue;
    }
    if (block.type !== 'heading') continue;
    const heading = headingText(body, block);
    if (heading === null || heading === '') {
      add(block, 'invalid-section', 'Use a nonempty ATX heading with a single space after its prefix.');
      continue;
    }
    if (block.depth === 1) {
      if (index !== 0 || title !== '') add(block, 'invalid-title', 'Exactly one document title is permitted.');
      else title = heading;
      continue;
    }
    if (block.depth === 2) {
      sectionName = heading;
      if (sectionNames.has(heading)) add(block, 'duplicate-section', 'A section may be declared only once.');
      sectionNames.add(heading);
      if (![...allowed.required, ...allowed.optional].includes(heading)) {
        add(block, 'invalid-section', 'This section is not supported for the document kind.');
      }
      const next = blocks.slice(index + 1).find((entry) => entry.type === 'heading' && entry.depth <= 2);
      const end = next?.position?.start.offset ?? body.length;
      const content = body.slice(block.position?.end.offset ?? 0, end);
      if (content.trim() === '') add(block, 'empty-section', 'Sections require content, not just a heading.');
      sections.push(Object.freeze({
        name: heading, content,
        location: location(source, path, bodyStart + (block.position?.start.offset ?? 0)),
      }));
      continue;
    }
    const declarationSection = ['Requirements', 'Tasks', 'Checks'].includes(sectionName);
    const looksLikeIdentity = /^(?:\[[^\]]*\] )?(?:REQ|SCN|TSK|CHK)-/u.test(heading);
    if (block.depth !== 3) {
      if (looksLikeIdentity) add(block, 'invalid-declaration', 'Typed declarations must use level-three headings.');
      continue;
    }
    if (!declarationSection && !looksLikeIdentity) continue;
    const metadataBlock = blocks[index + 1];
    if (metadataBlock?.type !== 'code' || metadataBlock.lang !== 'missionspec' || metadataBlock.meta !== null) {
      add(block, 'missing-declaration-metadata', 'A typed heading requires one immediate missionspec YAML fence.');
      continue;
    }
    consumedMetadata.add(index + 1);
    const next = blocks.slice(index + 2).find((entry) => entry.type === 'heading' && entry.depth <= 3);
    const end = next?.position?.start.offset ?? body.length;
    const prose = body.slice(metadataBlock.position?.end.offset ?? 0, end);
    if (prose.trim() === '') {
      add(block, 'empty-declaration', 'Each declaration requires prose; removals require a reason.');
      continue;
    }
    try {
      const declaration = parseDeclaration(
        heading, readMetadata(metadataBlock.value), prose,
        body.slice(block.position?.start.offset ?? 0, end),
        location(source, path, bodyStart + (block.position?.start.offset ?? 0)),
        kind === 'baseline',
      );
      if (!permitted(sectionName, declaration.kind)) {
        add(block, 'invalid-declaration', 'The declaration type does not belong in this section.');
        continue;
      }
      if (identities.has(declaration.id)) add(block, 'duplicate-identity', 'Every fact must have exactly one canonical definition.');
      identities.add(declaration.id);
      declarations.push(declaration);
      if (declaration.kind === 'task') progressOffsets.push(bodyStart + (block.position?.start.offset ?? 0) + 5);
    } catch (error) {
      add(metadataBlock, error instanceof MetadataSyntaxError ? 'invalid-yaml' : 'invalid-declaration',
        'Declaration metadata, identity or typed references are invalid; tags, aliases and extra fields are not supported.');
    }
  }
  for (const required of allowed.required) {
    if (!sectionNames.has(required)) {
      diagnostics.push(diagnostic(source, path, bodyStart, 'missing-section', `Required section "${required}" is missing.`));
    }
  }
  for (const section of ['Requirements', 'Tasks', 'Checks']) {
    if (section === 'Checks' && kind === 'tasks' && metadata.checks === 'verification.md') continue;
    if (sectionNames.has(section) && !declarations.some((entry) => permitted(section, entry.kind))) {
      diagnostics.push(diagnostic(source, path, bodyStart, 'empty-section', `Section "${section}" requires at least one typed declaration.`));
    }
  }
  if (diagnostics.length > 0) return invalid(diagnostics);
  let intent = source;
  for (const offset of progressOffsets) intent = `${intent.slice(0, offset)} ${intent.slice(offset + 1)}`;
  return Object.freeze({
    state: 'parsed',
    document: Object.freeze({
      schemaVersion: 1, id, kind, changeId, path, title, source,
      ...(metadata.checks === 'verification.md' ? { checks: 'verification.md' as const } : {}),
      rawRevision: digestContent(source), intentRevision: digestContent(intent),
      sections: Object.freeze(sections), declarations: Object.freeze(declarations),
    }),
  });
}
