import { ContractError, oneOf } from './validation.js';

declare const idBrand: unique symbol;
declare const slugBrand: unique symbol;
declare const pathBrand: unique symbol;

export const ID_PREFIXES = Object.freeze({
  workspace: 'WSP',
  change: 'CHG',
  artifact: 'ART',
  requirement: 'REQ',
  scenario: 'SCN',
  task: 'TSK',
  check: 'CHK',
  run: 'RUN',
  attempt: 'ATT',
  evidence: 'EVD',
  approval: 'APR',
  workOrder: 'WRK',
  question: 'QST',
  finding: 'FND',
  provider: 'CTX',
});

export type IdKind = keyof typeof ID_PREFIXES;
export type StableId<K extends IdKind> = string & { readonly [idBrand]: K };
export type WorkspaceId = StableId<'workspace'>;
export type ChangeId = StableId<'change'>;
export type ArtifactId = StableId<'artifact'>;
export type RequirementId = StableId<'requirement'>;
export type ScenarioId = StableId<'scenario'>;
export type TaskId = StableId<'task'>;
export type CheckId = StableId<'check'>;
export type RunId = StableId<'run'>;
export type AttemptId = StableId<'attempt'>;
export type EvidenceId = StableId<'evidence'>;
export type ApprovalId = StableId<'approval'>;
export type WorkOrderId = StableId<'workOrder'>;
export type ChangeSlug = string & { readonly [slugBrand]: true };
export type ProjectPath = string & { readonly [pathBrand]: true };

const reservedName = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;

export function parseId<K extends IdKind>(kind: K, value: unknown): StableId<K> {
  if (!Object.hasOwn(ID_PREFIXES, kind)) {
    throw new ContractError('id.kind', 'unrecognized identity kind');
  }
  const prefix = `${ID_PREFIXES[kind]}-`;
  if (
    typeof value !== 'string' ||
    value.length > 80 ||
    !value.startsWith(prefix) ||
    !/^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/u.test(value.slice(prefix.length))
  ) {
    throw new ContractError('id', `expected ${prefix} followed by an alphanumeric, hyphen-separated identity`);
  }
  return value as StableId<K>;
}

export function parseChangeSlug(value: unknown): ChangeSlug {
  if (
    typeof value !== 'string' ||
    value.length > 80 ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value) ||
    value === 'archive' ||
    reservedName.test(value)
  ) {
    throw new ContractError('changeSlug', 'expected a safe, nonreserved flat lowercase slug');
  }
  return value as ChangeSlug;
}

export function parseProjectPath(value: unknown): ProjectPath {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 1024 ||
    /[\\:%?*"<>|\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new ContractError('path', 'expected a portable project-relative path');
  }
  for (const segment of value.split('/')) {
    if (
      segment === '' ||
      segment === '.' ||
      segment === '..' ||
      segment.length > 255 ||
      /[. ]$/u.test(segment) ||
      reservedName.test(segment)
    ) {
      throw new ContractError('path', 'unsafe or nonportable path segment');
    }
  }
  return value as ProjectPath;
}

export const NATIVE_HOSTS = Object.freeze(['copilot', 'codex', 'claude'] as const);

export function isReservedSourcePath(path: ProjectPath): boolean {
  const segments = path.split('/').map((segment) => segment.normalize('NFKC').toLowerCase());
  return segments[0] === 'missionspec' || segments.some((segment) => segment === '.git' || segment === '.missionspec');
}

export type NativeHost = (typeof NATIVE_HOSTS)[number];

export function parseNativeHost(value: unknown): NativeHost {
  return oneOf(value, NATIVE_HOSTS, 'host');
}
