import {
  parseChangeSlug, parseId, parseProjectPath, type ChangeId, type ProjectPath,
  type RequirementId, type ScenarioId, type TaskId, type CheckId,
} from '../../../kernel/identifiers.js';
import { digestContent, type ContentDigest } from '../../../kernel/revisions.js';
import { array, ContractError, integer, oneOf, record, text, unique } from '../../../kernel/validation.js';
import { parseMarkdownSet } from '../documents/index.js';
import type { MarkdownDocument, MarkdownSource } from '../documents/types.js';

export interface UpstreamDocument {
  readonly id: string;
  readonly system: 'openspec' | 'spec-kit';
  readonly path: ProjectPath;
  readonly content: string;
}

export interface AdoptionMapping {
  readonly sourceId: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly kind: 'requirement' | 'scenario' | 'task' | 'check';
  readonly targetId: RequirementId | ScenarioId | TaskId | CheckId;
}

export interface AdoptionMaterial {
  readonly sources: readonly UpstreamDocument[];
  readonly artifacts: readonly MarkdownSource[];
  readonly mappings: readonly AdoptionMapping[];
}

export interface AdoptionManifest {
  readonly schemaVersion: 1;
  readonly kind: 'upstream-adoption';
  readonly changeId: ChangeId;
  readonly trust: 'untrusted-source-material';
  readonly claims: 'not-imported-as-authority-or-evidence';
  readonly licensing: 'not-established-by-copying';
  readonly mode: 'provenance-only' | 'explicitly-mapped-artifacts';
  readonly sources: readonly {
    readonly id: string;
    readonly system: UpstreamDocument['system'];
    readonly sourcePath: ProjectPath;
    readonly capturedPath: ProjectPath;
    readonly digest: ContentDigest;
    readonly utf8Bytes: number;
  }[];
  readonly mappings: readonly AdoptionMapping[];
  readonly artifacts: readonly { readonly path: ProjectPath; readonly digest: ContentDigest }[];
}

function sourceId(value: unknown): string {
  const id = text(value, 'source.id', 80);
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u.test(id)) {
    throw new ContractError('source.id', 'expected a safe lowercase source identifier');
  }
  return id;
}

function documentText(value: unknown): string {
  const content = text(value, 'source.content', 500_000);
  if (!content.isWellFormed() || Buffer.byteLength(content, 'utf8') > 500_000) {
    throw new ContractError('source.content', 'expected bounded well-formed UTF-8 text');
  }
  return content;
}

export function parseAdoptionMaterial(value: unknown): AdoptionMaterial {
  const input = record(value, 'adoption.material', ['sources', 'artifacts', 'mappings']);
  const sources = array(input.sources, 'adoption.sources', (entry): UpstreamDocument => {
    const source = record(entry, 'source', ['id', 'system', 'path', 'content']);
    const system = oneOf(source.system, ['openspec', 'spec-kit'], 'source.system');
    const path = parseProjectPath(source.path);
    if (!path.endsWith('.md') || (system === 'openspec' ? !path.startsWith('openspec/') :
      !path.startsWith('.specify/') && !path.startsWith('specs/'))) {
      throw new ContractError('source.path', 'select upstream Markdown inside its explicit document roots');
    }
    return Object.freeze({ id: sourceId(source.id), system, path, content: documentText(source.content) });
  }, 1);
  if (sources.length > 32) throw new ContractError('adoption.sources', 'at most 32 supplied documents may be adopted together');
  unique(sources.map((source) => source.id), 'source.ids');
  unique(sources.map((source) => source.path.toLowerCase()), 'source.paths');
  const artifacts = array(input.artifacts === undefined ? [] : input.artifacts, 'adoption.artifacts', (entry): MarkdownSource => {
    const artifact = record(entry, 'artifact', ['path', 'content']);
    return Object.freeze({ path: parseProjectPath(artifact.path), content: documentText(artifact.content) });
  });
  unique(artifacts.map((artifact) => artifact.path.toLowerCase()), 'artifact.paths');
  const mappings = array(input.mappings === undefined ? [] : input.mappings, 'adoption.mappings', (entry): AdoptionMapping => {
    const mapping = record(entry, 'mapping', ['sourceId', 'startLine', 'endLine', 'kind', 'targetId']);
    const kind = oneOf(mapping.kind, ['requirement', 'scenario', 'task', 'check'], 'mapping.kind');
    const selected = sourceId(mapping.sourceId);
    const source = sources.find((document) => document.id === selected);
    if (source === undefined) throw new ContractError('mapping.sourceId', 'source is not in the supplied set');
    const lines = source.content.split(/\r\n|\n|\r/u).length;
    const startLine = integer(mapping.startLine, 'mapping.startLine', 1, lines);
    const endLine = integer(mapping.endLine, 'mapping.endLine', startLine, lines);
    const span = source.content.split(/\r\n|\n|\r/u).slice(startLine - 1, endLine).join('\n');
    if (span.trim() === '') throw new ContractError('mapping', 'a source span must contain material for review');
    return Object.freeze({ sourceId: selected, startLine, endLine, kind, targetId: parseId(kind, mapping.targetId) });
  });
  unique(mappings.map((mapping) => mapping.targetId), 'mapping.targets');
  if (mappings.length > 2048 ||
    [...sources, ...artifacts].reduce((size, item) => size + Buffer.byteLength(item.content), 0) > 2_000_000) {
    throw new ContractError('adoption.material', 'the reviewed adoption payload exceeds its bounded local scope');
  }
  if (artifacts.length === 0 && mappings.length > 0) {
    throw new ContractError('adoption.mappings', 'mapping targets require explicit corresponding native artifacts');
  }
  return Object.freeze({ sources, artifacts, mappings });
}

export function validateAdoptionMappings(
  materialValue: unknown, changeIdValue: unknown,
): readonly MarkdownDocument[] {
  const material = parseAdoptionMaterial(materialValue);
  const changeId = parseId('change', changeIdValue);
  if (material.artifacts.length === 0) return Object.freeze([]);
  const parsed = parseMarkdownSet(material.artifacts);
  if (parsed.state !== 'valid' || parsed.documents.some((document) =>
    document.changeId !== changeId || !['proposal', 'specs', 'design', 'tasks', 'verification'].includes(document.kind))) {
    throw new ContractError('adoption.artifacts', 'supply a structurally valid native document set for the explicit new change');
  }
  const facts = parsed.documents.flatMap((document) => document.declarations);
  if (facts.some((fact) => fact.kind === 'task' && fact.progressClaim !== 'unchecked')) {
    throw new ContractError('adoption.artifacts', 'native task definitions must start unchecked; upstream completion claims stay in provenance');
  }
  if (facts.length !== material.mappings.length || facts.some((fact) =>
    !material.mappings.some((mapping) => mapping.kind === fact.kind && mapping.targetId === fact.id))) {
    throw new ContractError('adoption.mappings', 'every native fact requires exactly one explicit typed source-span mapping');
  }
  return parsed.documents;
}

export function prepareAdoptionMaterial(input: {
  readonly slug: string; readonly changeId: string; readonly material: unknown;
}): {
  readonly manifest: AdoptionManifest;
  readonly manifestPath: ProjectPath;
  readonly files: readonly MarkdownSource[];
  readonly documents: readonly MarkdownDocument[];
} {
  const slug = parseChangeSlug(input.slug);
  const changeId = parseId('change', input.changeId);
  const material = parseAdoptionMaterial(input.material);
  const documents = validateAdoptionMappings(material, changeId);
  const prefix = `missionspec/changes/${slug}/`;
  if (material.artifacts.some((artifact) => !artifact.path.startsWith(prefix) ||
    artifact.path.startsWith(`${prefix}imports/`) || !artifact.path.endsWith('.md'))) {
    throw new ContractError('adoption.artifacts', 'native artifacts must be Markdown inside the new change and outside provenance');
  }
  const captured = material.sources.map((source) => Object.freeze({
    id: source.id, system: source.system, sourcePath: source.path,
    capturedPath: parseProjectPath(`${prefix}imports/sources/${source.id}.md`),
    digest: digestContent(source.content), utf8Bytes: Buffer.byteLength(source.content),
  }));
  const manifest: AdoptionManifest = Object.freeze({
    schemaVersion: 1, kind: 'upstream-adoption', changeId,
    trust: 'untrusted-source-material', claims: 'not-imported-as-authority-or-evidence',
    licensing: 'not-established-by-copying',
    mode: material.artifacts.length === 0 ? 'provenance-only' : 'explicitly-mapped-artifacts',
    sources: Object.freeze(captured), mappings: material.mappings,
    artifacts: Object.freeze(material.artifacts.map((artifact) => Object.freeze({
      path: artifact.path, digest: digestContent(artifact.content),
    }))),
  });
  return Object.freeze({
    manifest, manifestPath: parseProjectPath(`${prefix}imports/provenance.json`),
    files: Object.freeze([
      ...captured.map((source, index) => Object.freeze({ path: source.capturedPath, content: material.sources[index]!.content })),
      ...material.artifacts,
    ]),
    documents,
  });
}
