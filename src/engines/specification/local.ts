import { isReservedSourcePath, parseChangeSlug, parseId, parseProjectPath, type ChangeId, type ChangeSlug, type ProjectPath } from '../../kernel/identifiers.js';
import { digestContent, parseDigest, type ContentDigest } from '../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';
import { parseMarkdownDocument } from './documents/index.js';
import { readMetadata } from './documents/yaml.js';
import { fromMarkdown } from 'mdast-util-from-markdown';
import type { MarkdownDocument, RequirementDeclaration, ScenarioDeclaration } from './documents/types.js';
import { parseArtifactNodeId, type ArtifactDependency, type ArtifactNodeId, type WorkflowProfile } from './contracts.js';

export interface NodeCapture {
  readonly node: ArtifactNodeId;
  readonly artifactId: ReturnType<typeof parseId<'artifact'>>;
  readonly outputs: readonly ProjectPath[];
  readonly applicability?: {
    readonly state: 'not-applicable'; readonly reason: string; readonly sourceRevision: ContentDigest;
    readonly dependencies: readonly ArtifactDependency[];
  };
  readonly captured: null | {
    readonly files: readonly { readonly path: ProjectPath; readonly digest: ContentDigest }[];
    readonly dependencies: readonly ArtifactDependency[];
  };
}

export interface LocalQuestion {
  readonly id: ReturnType<typeof parseId<'question'>>;
  readonly question: string;
  readonly blocking: boolean;
  readonly artifactRevision: ContentDigest;
  readonly response: null | { readonly answer: string; readonly source: 'user' | 'proposed-assumption' };
}

export interface ChangeMetadata {
  readonly schemaVersion: 1;
  readonly id: ChangeId;
  readonly slug: ChangeSlug;
  readonly profile: WorkflowProfile;
  readonly workflowRevision: ContentDigest;
  readonly sourcePaths: readonly ProjectPath[];
  readonly nodes: readonly NodeCapture[];
  readonly baseline: readonly { readonly path: ProjectPath; readonly digest: ContentDigest | 'absent' }[];
  readonly questions: readonly LocalQuestion[];
  readonly promotedContent: ContentDigest | null;
}

export const ARTIFACT_TEMPLATE_VERSION = 1 as const;

export function parseCapabilityName(value: unknown): ProjectPath {
  const path = parseProjectPath(value);
  if (path.split('/').length > 32 || !/^[a-z0-9]+(?:-[a-z0-9]+)*(?:\/[a-z0-9]+(?:-[a-z0-9]+)*)*$/u.test(path)) {
    throw new ContractError('capability', 'expected a safe lowercase capability path');
  }
  return path;
}

export function parseProjectMetadata(source: string): unknown {
  try {
    return readMetadata(source);
  } catch {
    throw new ContractError('metadata', 'invalid declarative YAML');
  }
}

export function parseChangeMetadata(value: unknown): ChangeMetadata {
  const data = record(value, 'change', ['schemaVersion', 'id', 'slug', 'profile', 'workflowRevision', 'sourcePaths', 'nodes', 'baseline', 'questions', 'promotedContent']);
  if (data.schemaVersion !== 1) throw new ContractError('change.schemaVersion', 'unsupported change metadata; no migration attempted');
  const slug = parseChangeSlug(data.slug);
  const prefix = `missionspec/changes/${slug}/`;
  const nodes = array(data.nodes, 'change.nodes', (entry): NodeCapture => {
    const node = record(entry, 'node', ['node', 'artifactId', 'outputs', 'captured', 'applicability']);
    const outputs = unique(array(node.outputs, 'node.outputs', parseProjectPath, 1), 'node.outputs');
    if (outputs.some((output) => !output.startsWith(prefix) || !output.endsWith('.md'))) throw new ContractError('node.outputs', 'outputs must be Markdown inside this change');
    let captured: NodeCapture['captured'] = null;
    if (node.captured !== null) {
      const capture = record(node.captured, 'capture', ['files', 'dependencies']);
      captured = Object.freeze({
        files: array(capture.files, 'capture.files', (item) => {
          const file = record(item, 'capture.file', ['path', 'digest']);
          return Object.freeze({ path: parseProjectPath(file.path), digest: parseDigest(file.digest) });
        }, 1),
        dependencies: array(capture.dependencies, 'capture.dependencies', (item) => {
          const dependency = record(item, 'dependency', ['artifactId', 'revision']);
          return Object.freeze({ artifactId: parseId('artifact', dependency.artifactId), revision: parseDigest(dependency.revision) });
        }),
      });
      unique(captured.files.map((file) => file.path), 'capture.files');
      unique(captured.dependencies.map((dependency) => dependency.artifactId), 'capture.dependencies');
      const capturedPaths = captured.files.map((file) => file.path);
      if (captured.files.length !== outputs.length || outputs.some((output) => !capturedPaths.includes(output))) {
        throw new ContractError('capture.files', 'capture must record the entire declared output set');
      }
    }
    let applicability: NodeCapture['applicability'];
    if (node.applicability !== undefined) {
      const value = record(node.applicability, 'applicability', ['state', 'reason', 'sourceRevision', 'dependencies']);
      if (value.state !== 'not-applicable' || node.node !== 'design' || data.profile !== 'compact' || captured !== null) {
        throw new ContractError('applicability', 'only uncaptured Compact design supports explicit not-applicable');
      }
      applicability = {
        state: 'not-applicable', reason: text(value.reason, 'applicability.reason'), sourceRevision: parseDigest(value.sourceRevision),
        dependencies: array(value.dependencies, 'applicability.dependencies', (item) => {
          const dependency = record(item, 'dependency', ['artifactId', 'revision']);
          return { artifactId: parseId('artifact', dependency.artifactId), revision: parseDigest(dependency.revision) };
        }),
      };
    }
    return Object.freeze({ node: parseArtifactNodeId(node.node), artifactId: parseId('artifact', node.artifactId), outputs, captured,
      ...(applicability === undefined ? {} : { applicability }) });
  }, 4);
  unique(nodes.map((node) => node.node), 'change.nodes');
  unique(nodes.map((node) => node.artifactId), 'change.artifactIds');
  unique(nodes.flatMap((node) => node.outputs).map((output) => output.toLowerCase()), 'change.outputs');
  if (nodes.length !== 4 || !['proposal', 'specs', 'design', 'tasks'].every((name) => nodes.some((node) => node.node === name)) ||
      nodes.some((node) => node.node !== 'specs' && node.node !== 'tasks' && node.outputs.length !== 1) ||
      nodes.some((node) => node.node === 'tasks' && (
        node.outputs[0] !== `${prefix}tasks.md` ||
        node.outputs.length > 2 || node.outputs.length === 2 && node.outputs[1] !== `${prefix}verification.md`
      ))) {
    throw new ContractError('change.nodes', 'declare exactly the built-in nodes and their output sets');
  }
  const sourcePaths = unique(array(data.sourcePaths, 'change.sourcePaths', parseProjectPath), 'change.sourcePaths');
  if (sourcePaths.some(isReservedSourcePath)) {
    throw new ContractError('change.sourcePaths', 'source observations cannot alias workflow, runtime or Git metadata');
  }
  const baseline = array(data.baseline, 'change.baseline', (entry) => {
    const file = record(entry, 'baseline', ['path', 'digest']);
    const path = parseProjectPath(file.path);
    if (!path.startsWith('missionspec/specs/') || !path.endsWith('/spec.md')) {
      throw new ContractError('baseline.path', 'expected specs/<capability>/spec.md');
    }
    parseCapabilityName(path.slice('missionspec/specs/'.length, -'/spec.md'.length));
    return Object.freeze({ path, digest: file.digest === 'absent' ? 'absent' as const : parseDigest(file.digest) });
  }, 1);
  unique(baseline.map((file) => file.path), 'change.baseline');
  const specs = nodes.find((node) => node.node === 'specs')!;
  if (specs.outputs.length !== baseline.length ||
      specs.outputs.some((file, index) => file !== `${prefix}specs/${baseline[index]!.path.slice('missionspec/specs/'.length)}`)) {
    throw new ContractError('change.baseline', 'baseline targets must map exactly to the declared specs set');
  }
  const questions = array(data.questions, 'change.questions', (entry): LocalQuestion => {
    const question = record(entry, 'question', ['id', 'question', 'blocking', 'artifactRevision', 'response']);
    if (typeof question.blocking !== 'boolean') throw new ContractError('question.blocking', 'expected a boolean');
    let response: LocalQuestion['response'] = null;
    if (question.response !== null) {
      const answer = record(question.response, 'question.response', ['answer', 'source']);
      response = Object.freeze({ answer: text(answer.answer, 'answer'), source: oneOf(answer.source, ['user', 'proposed-assumption'], 'answer.source') });
    }
    return Object.freeze({
      id: parseId('question', question.id), question: text(question.question, 'question'),
      blocking: question.blocking, artifactRevision: parseDigest(question.artifactRevision), response,
    });
  });
  unique(questions.map((question) => question.id), 'questions');
  return Object.freeze({
    schemaVersion: 1, id: parseId('change', data.id), slug,
    profile: oneOf(data.profile, ['standard', 'compact'], 'profile'),
    workflowRevision: parseDigest(data.workflowRevision), sourcePaths, nodes, baseline, questions,
    promotedContent: data.promotedContent === null ? null : parseDigest(data.promotedContent),
  });
}

export function renderArtifactTemplate(input: {
  readonly kind: 'proposal' | 'specs' | 'design' | 'tasks' | 'verification' | 'discovery' | 'principles';
  readonly id: string; readonly changeId?: string; readonly compact?: boolean; readonly externalChecks?: boolean;
}): string {
  const id = parseId('artifact', input.id);
  const change = input.kind === 'principles' ? '' : `changeId: ${parseId('change', input.changeId)}\n`;
  const checks = input.kind === 'tasks' && input.externalChecks ? 'checks: verification.md\n' : '';
  const sections: Record<typeof input.kind, readonly string[]> = {
    proposal: ['Problem', 'Outcome', 'Scope', 'Acceptance'], specs: ['Requirements'],
    design: ['Approach', 'Risks'], tasks: input.compact ? ['Design', 'Tasks', 'Checks'] : ['Tasks', 'Checks'],
    verification: ['Checks'], discovery: ['Findings', 'Questions'], principles: ['Principles'],
  };
  // Intentionally incomplete: a generated skeleton is never captured as a ready artifact.
  return `---\nschemaVersion: 1\nid: ${id}\nkind: ${input.kind}\n${change}${checks}---\n# ${input.kind}\n\n${sections[input.kind].map((section) => `## ${section}\n\n`).join('')}`;
}

type Fact = RequirementDeclaration | ScenarioDeclaration;

function baselineLayout(document: MarkdownDocument) {
  const frontmatter = /^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/u.exec(document.source);
  const requirements = document.sections.find((section) => section.name === 'Requirements');
  const facts = document.declarations.filter((entry): entry is Fact =>
    entry.kind === 'requirement' || entry.kind === 'scenario');
  if (frontmatter === null || requirements === undefined || facts.length === 0) {
    throw new ContractError('baseline', 'a parsed specification with declarations is required');
  }
  const nextSection = document.sections.find((section) => section.location.offset > requirements.location.offset);
  const end = nextSection?.location.offset ?? document.source.length;
  const ordered = [...facts].sort((left, right) => left.location.offset - right.location.offset);
  const first = ordered[0]!.location.offset;
  const blocks = new Map<string, string>();
  for (let index = 0; index < ordered.length; index += 1) {
    const fact = ordered[index]!;
    blocks.set(fact.id, document.source.slice(fact.location.offset, ordered[index + 1]?.location.offset ?? end));
  }
  return {
    header: frontmatter[0],
    prefix: document.source.slice(frontmatter[0].length, first),
    suffix: document.source.slice(end),
    blocks,
  };
}

export function promoteBaseline(input: {
  readonly baseline: MarkdownDocument | null; readonly delta: MarkdownDocument; readonly path: ProjectPath;
}): { readonly content: string | null; readonly conflicts: readonly string[] } {
  const { baseline, delta, path } = input;
  if (delta.kind !== 'specs' || (baseline !== null && baseline.kind !== 'baseline')) {
    throw new ContractError('baseline', 'promotion requires a change spec and a project baseline');
  }
  const facts = new Map<string, Fact>();
  for (const fact of baseline?.declarations ?? []) {
    if (fact.kind === 'requirement' || fact.kind === 'scenario') facts.set(fact.id, fact);
  }
  const conflicts: string[] = [];
  for (const fact of delta.declarations) {
    if (fact.kind !== 'requirement' && fact.kind !== 'scenario') continue;
    const existing = facts.get(fact.id);
    if ((fact.operation === 'add' && existing !== undefined) ||
        (fact.operation !== 'add' && (existing === undefined || existing.kind !== fact.kind))) {
      conflicts.push(`Identity operation conflicts with the accepted baseline: ${fact.id}`);
      continue;
    }
    if (fact.operation === 'remove') facts.delete(fact.id);
    else facts.set(fact.id, fact);
  }
  for (const fact of facts.values()) {
    if (fact.kind === 'scenario' && facts.get(fact.requirement)?.kind !== 'requirement') conflicts.push(`Scenario requires a retained requirement: ${fact.id}`);
  }
  if (conflicts.length > 0) return { content: null, conflicts };
  const layout = baselineLayout(baseline ?? delta);
  if (facts.size === 0) {
    const preserved = fromMarkdown(`${layout.prefix}${layout.suffix}`);
    return {
      content: null,
      conflicts: preserved.children.some((node) => node.type !== 'heading' && node.type !== 'thematicBreak')
        ? ['Removing the final facts would discard baseline prose or Notes; review an explicit retirement first.'] : [],
    };
  }
  const original = new Map((baseline?.declarations ?? []).map((fact) => [fact.id, fact]));
  const declarations = [...facts.values()].map((fact) => {
    if (original.get(fact.id) === fact) {
      const block = layout.blocks.get(fact.id);
      if (block === undefined) throw new ContractError('baseline', 'retained declaration location is unavailable');
      return block;
    }
    const block = `### ${fact.id}: ${fact.title}\n\n\`\`\`missionspec\n${fact.kind === 'scenario' ? `requirement: ${fact.requirement}` : '{}'}\n\`\`\`${fact.prose}`;
    return block.endsWith('\n') ? block : `${block}\n`;
  }).join('');
  const header = baseline === null
    ? `---\nschemaVersion: 1\nid: ${parseId('artifact', `ART-base-${digestContent(path).slice(7, 27)}`)}\nkind: baseline\n---\n`
    : layout.header;
  const content = `${header}${layout.prefix}${declarations}${layout.suffix}`;
  const result = parseMarkdownDocument({ path, content });
  if (result.state !== 'parsed') {
    throw new ContractError('baseline', 'promoted baseline is structurally invalid');
  }
  return { content, conflicts: [] };
}
