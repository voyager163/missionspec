import { NATIVE_HOSTS, parseNativeHost, parseProjectPath, type NativeHost, type ProjectPath } from '../../../kernel/identifiers.js';
import { OPERATION_IDS, parseOperationId, type OperationId } from '../../../kernel/registry.js';
import { digestContent, parseDigest, parseWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../../kernel/validation.js';
import { renderSkillSet, type RenderedSkill, type SkillCatalog } from '../skills/catalog.js';

export const INSTALLATION_PATH = parseProjectPath('.missionspec/installation.json');
export const INSTALLATION_OWNER = '@msn-control/missionspec';

export interface OwnedSkill {
  readonly host: NativeHost;
  readonly operation: OperationId;
  readonly path: ProjectPath;
  readonly digest: ContentDigest;
  readonly sourceRevision: ContentDigest;
  readonly templateRevision: ContentDigest;
  readonly generatorVersion: string;
  readonly catalogRevision: ContentDigest;
}

export interface InstallationRecord {
  readonly schemaVersion: 1;
  readonly owner: typeof INSTALLATION_OWNER;
  readonly workspace: WorkspaceBinding;
  readonly files: readonly OwnedSkill[];
}

export function selectedHosts(value: unknown): readonly NativeHost[] {
  const selected = unique(array(value, 'installation.hosts', parseNativeHost, 1), 'installation.hosts');
  return Object.freeze(NATIVE_HOSTS.filter((host) => selected.includes(host)));
}

export function nativeSkillPath(host: NativeHost, operation: OperationId): ProjectPath {
  const roots = { copilot: '.github/skills', codex: '.agents/skills', claude: '.claude/skills' };
  return parseProjectPath(`${roots[parseNativeHost(host)]}/missionspec-${parseOperationId(operation)}/SKILL.md`);
}

export function parseGeneratorVersion(value: unknown): string {
  const version = text(value, 'installation.generatorVersion', 80);
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/u.test(version)) {
    throw new ContractError('installation.generatorVersion', 'expected a distributed semantic version');
  }
  return version;
}

export function parseOwnedSkill(value: unknown): OwnedSkill {
  const entry = record(value, 'installation.file', [
    'host', 'operation', 'path', 'digest', 'sourceRevision', 'templateRevision', 'generatorVersion', 'catalogRevision',
  ]);
  const host = parseNativeHost(entry.host);
  const operation = parseOperationId(entry.operation);
  const path = parseProjectPath(entry.path);
  if (path !== nativeSkillPath(host, operation)) throw new ContractError('installation.file.path', 'not the canonical native skill destination');
  return Object.freeze({
    host, operation, path, digest: parseDigest(entry.digest),
    sourceRevision: parseDigest(entry.sourceRevision), templateRevision: parseDigest(entry.templateRevision),
    generatorVersion: parseGeneratorVersion(entry.generatorVersion), catalogRevision: parseDigest(entry.catalogRevision),
  });
}

export function parseInstallationRecord(value: unknown): InstallationRecord {
  const input = record(value, 'installation', ['schemaVersion', 'owner', 'workspace', 'files']);
  if (input.schemaVersion !== 1 || input.owner !== INSTALLATION_OWNER) {
    throw new ContractError('installation', 'unsupported ownership schema or owner; no automatic adoption or migration');
  }
  const files = array(input.files, 'installation.files', parseOwnedSkill);
  if (files.length > NATIVE_HOSTS.length * OPERATION_IDS.length) throw new ContractError('installation.files', 'catalog ownership limit exceeded');
  unique(files.map((file) => file.path), 'installation.files.paths');
  unique(files.map((file) => `${file.host}:${file.operation}`), 'installation.files.keys');
  return Object.freeze({
    schemaVersion: 1, owner: INSTALLATION_OWNER, workspace: parseWorkspaceBinding(input.workspace),
    files: Object.freeze([...files].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)),
  });
}

export function serializeInstallation(record: InstallationRecord): string {
  return `${JSON.stringify(parseInstallationRecord(record), null, 2)}\n`;
}

export function desiredSkills(catalog: SkillCatalog, hosts: unknown, generatorVersion: string): readonly {
  readonly rendered: RenderedSkill; readonly ownership: OwnedSkill;
}[] {
  const version = parseGeneratorVersion(generatorVersion);
  return Object.freeze(renderSkillSet(catalog, selectedHosts(hosts), version).map((rendered) => {
    if (rendered.path !== nativeSkillPath(rendered.host, rendered.operation)) {
      throw new ContractError('installation.renderer', 'renderer destination differs from the owned native layout');
    }
    return Object.freeze({
      rendered,
      ownership: parseOwnedSkill({
        host: rendered.host, operation: rendered.operation, path: rendered.path, digest: rendered.digest,
        sourceRevision: digestContent(catalog.body(rendered.operation)),
        templateRevision: digestContent(JSON.stringify({
          schemaVersion: catalog.manifest.schemaVersion, rendering: catalog.manifest.rendering,
          metadata: catalog.manifest.operations[rendered.operation],
        })),
        generatorVersion: version, catalogRevision: rendered.catalogRevision,
      }),
    });
  }));
}

export type InstalledSkillState = 'absent' | 'unowned' | 'current' | 'outdated' | 'modified' | 'missing';

export function installedSkillState(owned: OwnedSkill | undefined, desired: OwnedSkill, actual: ContentDigest | 'absent'): InstalledSkillState {
  if (owned === undefined) return actual === 'absent' ? 'absent' : 'unowned';
  if (actual === 'absent') return 'missing';
  if (owned.digest !== actual) return 'modified';
  return JSON.stringify(owned) === JSON.stringify(desired) ? 'current' : 'outdated';
}
