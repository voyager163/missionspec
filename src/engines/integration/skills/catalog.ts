import { Ajv2020 } from 'ajv/dist/2020.js';
import { parseDocument, stringify } from 'yaml';
import { parseNativeHost, parseProjectPath, type NativeHost, type ProjectPath } from '../../../kernel/identifiers.js';
import { OPERATION_IDS, OPERATIONS, parseOperationId, type EngineId, type OperationClass, type OperationId } from '../../../kernel/registry.js';
import { digestContent, type ContentDigest } from '../../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../../kernel/validation.js';

export interface SkillMetadata {
  readonly body: string;
  readonly description: string;
  readonly category: OperationClass;
  readonly engineOwner: EngineId;
  readonly inputs: { readonly required: readonly string[]; readonly optional: readonly string[] };
  readonly outputs: readonly string[];
  readonly effects: { readonly default: readonly string[]; readonly conditional: readonly string[] };
  readonly prerequisites: readonly string[];
  readonly approvalRules: readonly string[];
  readonly stopRules: readonly string[];
  readonly handoffs: readonly OperationId[];
  readonly telemetryClass: 'none' | 'stateful-top-level';
}

export interface SkillManifest {
  readonly schemaVersion: 1;
  readonly defaultInstall: true;
  readonly hosts: readonly NativeHost[];
  readonly rendering: { readonly invocationPlaceholder: '{{invocation}}' };
  readonly operations: Readonly<Record<OperationId, SkillMetadata>>;
}

export interface RenderedSkill {
  readonly host: NativeHost;
  readonly operation: OperationId;
  readonly path: ProjectPath;
  readonly content: string;
  readonly digest: ContentDigest;
  readonly catalogRevision: ContentDigest;
}

const roots: Readonly<Record<NativeHost, string>> = Object.freeze({
  copilot: '.github/skills',
  codex: '.agents/skills',
  claude: '.claude/skills',
});
const constructionToken = Symbol('validated skill catalog');
const sourceLimit = 1_000_000;
const bodyLimit = 131_072;

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function boundedText(value: unknown, field: string, limit: number): string {
  const result = text(value, field, limit);
  if (Buffer.byteLength(result, 'utf8') > limit) throw new ContractError(field, 'UTF-8 byte limit exceeded');
  return result;
}

export class SkillCatalog {
  readonly manifest: SkillManifest;
  readonly revision: ContentDigest;
  readonly #bodies: ReadonlyMap<OperationId, string>;

  private constructor(
    token: typeof constructionToken,
    manifest: SkillManifest,
    bodies: ReadonlyMap<OperationId, string>,
    revision: ContentDigest,
  ) {
    if (token !== constructionToken) throw new ContractError('catalog', 'use validated source loading');
    this.manifest = freeze(manifest);
    this.#bodies = new Map(bodies);
    this.revision = revision;
    Object.freeze(this);
  }

  static parse(manifestSource: unknown, schemaSource: unknown, bodySources: unknown): SkillCatalog {
    const manifestText = boundedText(manifestSource, 'catalog.manifest', sourceLimit);
    const schemaText = boundedText(schemaSource, 'catalog.schema', sourceLimit);
    const document = parseDocument(manifestText, { uniqueKeys: true });
    if (document.errors.length || document.warnings.length) {
      throw new ContractError('catalog.manifest', 'invalid or unsupported YAML');
    }
    let parsed: unknown;
    let schema: unknown;
    try {
      parsed = document.toJS({ maxAliasCount: 50 });
      schema = JSON.parse(schemaText);
    } catch {
      throw new ContractError('catalog.source', 'invalid structured source');
    }
    if (typeof schema !== 'object' || schema === null || Array.isArray(schema)) {
      throw new ContractError('catalog.schema', 'expected a JSON schema object');
    }
    const validator = new Ajv2020({ strict: true, allErrors: false }).compile<SkillManifest>(schema);
    if (!validator(parsed)) throw new ContractError('catalog.manifest', 'does not match the declared source schema');
    const sources = record(bodySources, 'catalog.bodies', OPERATION_IDS);
    const bodies = new Map<OperationId, string>();
    for (const id of OPERATION_IDS) {
      const metadata = parsed.operations[id];
      if (metadata.category !== OPERATIONS[id].class || !OPERATIONS[id].engines.includes(metadata.engineOwner)) {
        throw new ContractError('catalog.operation', 'registry ownership or category mismatch');
      }
      if (metadata.body !== `${id}.md`) throw new ContractError('catalog.body', 'noncanonical source filename');
      const description = text(metadata.description, 'catalog.description', 1024);
      if (/[\r\n]/u.test(description)) throw new ContractError('catalog.description', 'expected a single line');
      const body = boundedText(sources[id], 'catalog.body', bodyLimit);
      const tokens = body.match(/\{\{[^{}]*\}\}/gu) ?? [];
      if (tokens.length === 0 || tokens.some((token) => token !== parsed.rendering.invocationPlaceholder)) {
        throw new ContractError('catalog.body', 'missing or unsupported rendering token');
      }
      if (metadata.inputs.required.some((input) => metadata.inputs.optional.includes(input))) {
        throw new ContractError('catalog.inputs', 'required and optional inputs overlap');
      }
      for (const handoff of metadata.handoffs) parseOperationId(handoff);
      bodies.set(id, body);
    }
    const revision = digestContent(JSON.stringify({
      manifest: parsed,
      schema,
      bodies: OPERATION_IDS.map((id) => {
        const body = bodies.get(id);
        if (body === undefined) throw new ContractError('catalog.body', 'source unavailable');
        return { id, digest: digestContent(body) };
      }),
    }));
    return new SkillCatalog(constructionToken, parsed, bodies, revision);
  }

  body(operation: unknown): string {
    const body = this.#bodies.get(parseOperationId(operation));
    if (body === undefined) throw new ContractError('catalog.body', 'source unavailable');
    return body;
  }
}

export function skillInvocation(hostValue: unknown, operationValue: unknown): string {
  const host = parseNativeHost(hostValue);
  const operation = parseOperationId(operationValue);
  return `${host === 'codex' ? '$' : '/'}${OPERATIONS[operation].nativeName}`;
}

export function renderSkill(
  catalog: SkillCatalog,
  hostValue: unknown,
  operationValue: unknown,
  generatorVersion: string,
): RenderedSkill {
  const host = parseNativeHost(hostValue);
  const operation = parseOperationId(operationValue);
  const version = text(generatorVersion, 'generator.version', 80);
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u.test(version)) {
    throw new ContractError('generator.version', 'expected a distributed semantic version');
  }
  const metadata = catalog.manifest.operations[operation];
  const name = OPERATIONS[operation].nativeName;
  const header = {
    name,
    description: metadata.description,
    license: 'Apache-2.0',
    compatibility: 'Requires advertised MissionSpec runtime capabilities; generated files do not establish host qualification.',
    metadata: {
      author: 'MissionSpec contributors',
      version: String(catalog.manifest.schemaVersion),
      generatedBy: `@msn-control/missionspec@${version}`,
      source: `assets/operations/${metadata.body}`,
      catalogRevision: catalog.revision,
    },
    ...(host === 'claude' ? { 'user-invocable': true } : {}),
  };
  const body = catalog.body(operation).replaceAll(catalog.manifest.rendering.invocationPlaceholder, skillInvocation(host, operation));
  const handoffs = metadata.handoffs.map((id) => `- \`${skillInvocation(host, id)}\``).join('\n');
  const content = `---\n${stringify(header, { lineWidth: 0 })}---\n\n${body.trimEnd()}\n\n## Native handoffs\n\nThese are suggestions, not automatic execution or approval:\n\n${handoffs}\n`;
  return Object.freeze({
    host,
    operation,
    path: parseProjectPath(`${roots[host]}/${name}/SKILL.md`),
    content,
    digest: digestContent(content),
    catalogRevision: catalog.revision,
  });
}

export function renderSkillSet(catalog: SkillCatalog, hostsValue: unknown, generatorVersion: string): readonly RenderedSkill[] {
  const hosts = unique(array(hostsValue, 'hosts', parseNativeHost), 'hosts');
  return Object.freeze(hosts.flatMap((host) => OPERATION_IDS.map((id) => renderSkill(catalog, host, id, generatorVersion))));
}
