import { LocalWorkspace, makeFilePlan, parseFilePlan, writeMutation, type FileGuard, type FilePlan } from '../adapters/filesystem/local-workspace.js';
import {
  INSTALLATION_OWNER, INSTALLATION_PATH, desiredSkills, installedSkillState, nativeSkillPath,
  parseGeneratorVersion, parseInstallationRecord, selectedHosts, serializeInstallation,
  type InstallationRecord, type InstalledSkillState, type OwnedSkill, type SkillCatalog,
} from '../engines/integration/index.js';
import type { ApprovalReference } from '../kernel/authority.js';
import { NATIVE_HOSTS, parseProjectPath, type NativeHost, type ProjectPath } from '../kernel/identifiers.js';
import { OPERATION_IDS, type OperationId } from '../kernel/registry.js';
import { parseWorkspaceBinding, sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../kernel/revisions.js';
import type { FileMutation, FileSnapshot } from '../ports/contracts.js';
import { WorkflowError } from './errors.js';

const identityPath = parseProjectPath('.missionspec/workspace.json');
const configPath = parseProjectPath('missionspec/config.yaml');
const gitignorePath = parseProjectPath('.gitignore');
const setupPaths = new Set([identityPath, configPath, gitignorePath]);

export interface SkillInspection {
  readonly host: NativeHost;
  readonly operation: OperationId;
  readonly path: ProjectPath;
  readonly state: InstalledSkillState;
  readonly actualDigest: ContentDigest | 'absent';
  readonly ownedDigest: ContentDigest | null;
  readonly desiredDigest: ContentDigest;
}

export interface InstallationInspection {
  readonly schemaVersion: 1;
  readonly workspace: WorkspaceBinding | null;
  readonly hosts: readonly NativeHost[];
  readonly sourceFormat: 'supported';
  readonly runtimeQualification: 'not-established';
  readonly ownership: InstallationRecord | null;
  readonly files: readonly SkillInspection[];
  readonly pendingTransactions: readonly string[];
}

export interface InstallationDiff {
  readonly path: ProjectPath;
  readonly kind: 'create' | 'update' | 'remove';
  readonly beforeDigest: ContentDigest | 'absent';
  readonly afterDigest: ContentDigest | 'absent';
  readonly before: string | null;
  readonly after: string | null;
  readonly diff: string;
}

export interface InstallationConflict {
  readonly path: ProjectPath;
  readonly reason: 'unowned' | 'modified' | 'missing' | 'update-required' | 'not-installed';
}

export interface InstallationPreview {
  readonly schemaVersion: 1;
  readonly action: 'install' | 'update' | 'remove';
  readonly state: 'ready' | 'unchanged' | 'conflicted';
  readonly inspection: InstallationInspection;
  readonly conflicts: readonly InstallationConflict[];
  readonly changes: readonly InstallationDiff[];
  readonly plan: FilePlan | null;
}

function fullDiff(path: ProjectPath, before: string | null, after: string | null): string {
  const lines = (content: string | null): string[] => content === null || content === '' ? [] : content.replace(/\n$/u, '').split('\n');
  const oldLines = lines(before);
  const newLines = lines(after);
  const side = (content: string | null, values: string[], prefix: string) => [
    ...values.map((line) => `${prefix}${line}`),
    ...(content !== null && content !== '' && !content.endsWith('\n') ? ['\\ No newline at end of file'] : []),
  ];
  return [
    `--- ${before === null ? '/dev/null' : `a/${path}`}`,
    `+++ ${after === null ? '/dev/null' : `b/${path}`}`,
    `@@ -${oldLines.length ? 1 : 0},${oldLines.length} +${newLines.length ? 1 : 0},${newLines.length} @@`,
    ...side(before, oldLines, '-'), ...side(after, newLines, '+'), '',
  ].join('\n');
}

/** Compose with LocalWorkflow.files to retain its quiescence and journal guards. */
export class SkillInstallation {
  readonly generatorVersion: string;

  constructor(readonly files: LocalWorkspace, readonly catalog: SkillCatalog, generatorVersion: string) {
    this.generatorVersion = parseGeneratorVersion(generatorVersion);
  }

  private async observe(hostsValue: unknown) {
    const hosts = selectedHosts(hostsValue);
    const workspace = await this.files.identity();
    const metadata = await this.files.read(INSTALLATION_PATH);
    const ownership = metadata === null ? null : parseInstallationRecord(JSON.parse(metadata.content) as unknown);
    if (ownership !== null && (workspace === null || !sameWorkspaceBinding(workspace, ownership.workspace))) {
      throw new WorkflowError('scope-exceeded', 'Installation ownership belongs to a different or missing workspace identity.');
    }
    const desired = desiredSkills(this.catalog, hosts, this.generatorVersion);
    const snapshots = new Map<ProjectPath, FileSnapshot | null>();
    const inspected: SkillInspection[] = [];
    for (const entry of desired) {
      const actual = await this.files.read(entry.rendered.path);
      snapshots.set(entry.rendered.path, actual);
      const owned = ownership?.files.find((file) => file.path === entry.rendered.path);
      inspected.push(Object.freeze({
        host: entry.rendered.host, operation: entry.rendered.operation, path: entry.rendered.path,
        state: installedSkillState(owned, entry.ownership, actual?.digest ?? 'absent'),
        actualDigest: actual?.digest ?? 'absent', ownedDigest: owned?.digest ?? null, desiredDigest: entry.rendered.digest,
      }));
    }
    const inspection: InstallationInspection = Object.freeze({
      schemaVersion: 1, workspace, hosts, sourceFormat: 'supported', runtimeQualification: 'not-established',
      ownership, files: Object.freeze(inspected), pendingTransactions: await this.files.pending(),
    });
    return { inspection, metadata, desired, snapshots };
  }

  async inspect(hosts: unknown = NATIVE_HOSTS): Promise<InstallationInspection> {
    return (await this.observe(hosts)).inspection;
  }

  async previewInstall(hosts: unknown, bootstrap?: FilePlan): Promise<InstallationPreview> {
    return this.preview('install', hosts, bootstrap);
  }

  async previewUpdate(hosts: unknown): Promise<InstallationPreview> {
    return this.preview('update', hosts);
  }

  async previewRemove(hosts: unknown): Promise<InstallationPreview> {
    return this.preview('remove', hosts);
  }

  private async preview(action: InstallationPreview['action'], hosts: unknown, bootstrap?: FilePlan): Promise<InstallationPreview> {
    const { inspection, metadata, desired, snapshots } = await this.observe(hosts);
    if (inspection.pendingTransactions.length) throw new WorkflowError('conflict', 'Recover pending transactions before changing installation ownership.');
    let workspace = inspection.workspace;
    const guards = new Map<ProjectPath, FileGuard>();
    const mutations: FileMutation[] = [];
    if (bootstrap !== undefined) {
      const setup = parseFilePlan(bootstrap);
      if (action !== 'install' || workspace !== null || setup.workspace.rootDigest !== this.files.rootDigest ||
          setup.request.operation !== 'onboard' || setup.request.purpose !== 'integration' ||
          setup.mutations.some((mutation) => !setupPaths.has(mutation.effect.path) || mutation.effect.kind !== 'file-write' || mutation.effect.purpose !== 'configuration')) {
        throw new WorkflowError('scope-exceeded', 'Installation bootstrap must be an explicit setup-only preview for this uninitialized workspace.');
      }
      const identity = setup.mutations.find((mutation) => mutation.effect.path === identityPath);
      const config = setup.mutations.find((mutation) => mutation.effect.path === configPath);
      if (identity?.effect.expected !== 'absent' || !('content' in identity) ||
          config?.effect.expected !== 'absent' ||
          !sameWorkspaceBinding(parseWorkspaceBinding(JSON.parse(identity.content) as unknown), setup.workspace)) {
        throw new WorkflowError('scope-exceeded', 'Bootstrap must create the reviewed prospective identity and project configuration.');
      }
      workspace = setup.workspace;
      for (const guard of setup.guards) guards.set(guard.path, guard);
      mutations.push(...setup.mutations);
    }
    if (workspace === null) {
      throw new WorkflowError('authority-required', 'Preview explicit workspace setup before installation; inspection never creates an identity.');
    }
    const identity = await this.files.read(identityPath);
    guards.set(identityPath, { path: identityPath, digest: identity?.digest ?? 'absent' });
    guards.set(INSTALLATION_PATH, { path: INSTALLATION_PATH, digest: metadata?.digest ?? 'absent' });
    const conflicts: InstallationConflict[] = [];
    const next = new Map<ProjectPath, OwnedSkill>(inspection.ownership?.files.map((file) => [file.path, file]) ?? []);
    for (const entry of desired) {
      const observed = inspection.files.find((file) => file.path === entry.rendered.path)!;
      guards.set(observed.path, { path: observed.path, digest: observed.actualDigest });
      if (['unowned', 'modified', 'missing'].includes(observed.state)) {
        conflicts.push({ path: observed.path, reason: observed.state as 'unowned' | 'modified' | 'missing' });
        continue;
      }
      if (action === 'install' && observed.state === 'outdated') {
        conflicts.push({ path: observed.path, reason: 'update-required' });
        continue;
      }
      if (action === 'update' && observed.state === 'absent') {
        conflicts.push({ path: observed.path, reason: 'not-installed' });
        continue;
      }
      if (action === 'remove') {
        if (observed.state === 'absent') continue;
        mutations.push({ effect: { kind: 'file-remove', purpose: 'configuration', path: observed.path, expected: observed.actualDigest as ContentDigest } });
        next.delete(observed.path);
      } else {
        if (observed.actualDigest !== entry.rendered.digest) {
          mutations.push(writeMutation(observed.path, observed.actualDigest, entry.rendered.content, 'configuration'));
        }
        next.set(observed.path, entry.ownership);
      }
    }
    if (conflicts.length) return Object.freeze({
      schemaVersion: 1, action, state: 'conflicted', inspection, conflicts: Object.freeze(conflicts), changes: Object.freeze([]), plan: null,
    });
    const nextRecord = parseInstallationRecord({
      schemaVersion: 1, owner: INSTALLATION_OWNER, workspace, files: [...next.values()],
    });
    // Do not create an empty record for a remove of an already-absent installation.
    if ((metadata !== null || next.size > 0) &&
        (inspection.ownership === null || serializeInstallation(nextRecord) !== serializeInstallation(inspection.ownership))) {
      mutations.push(writeMutation(INSTALLATION_PATH, metadata?.digest ?? 'absent', serializeInstallation(nextRecord), 'configuration'));
    }
    if (mutations.length === 0) return Object.freeze({
      schemaVersion: 1, action, state: 'unchanged', inspection, conflicts: Object.freeze([]), changes: Object.freeze([]), plan: null,
    });
    const changes: InstallationDiff[] = [];
    for (const mutation of mutations) {
      const before = mutation.effect.path === INSTALLATION_PATH ? metadata
        : snapshots.has(mutation.effect.path) ? snapshots.get(mutation.effect.path)! : await this.files.read(mutation.effect.path);
      const after = 'content' in mutation ? mutation.content : null;
      changes.push(Object.freeze({
        path: mutation.effect.path, kind: after === null ? 'remove' : before === null ? 'create' : 'update',
        beforeDigest: before?.digest ?? 'absent',
        afterDigest: mutation.effect.kind === 'file-write' ? mutation.effect.proposed : 'absent',
        before: before?.content ?? null, after, diff: fullDiff(mutation.effect.path, before?.content ?? null, after),
      }));
    }
    const plan = makeFilePlan({ workspace, guards: [...guards.values()], mutations, operation: 'onboard', purpose: 'integration' });
    return Object.freeze({
      schemaVersion: 1, action, state: 'ready', inspection, conflicts: Object.freeze([]), changes: Object.freeze(changes), plan,
    });
  }

  async apply(value: FilePlan, approval: ApprovalReference): Promise<{ transactionId: string; state: 'committed' }> {
    const plan = parseFilePlan(value);
    if (plan.request.operation !== 'onboard' || plan.request.purpose !== 'integration') {
      throw new WorkflowError('scope-exceeded', 'Installation applies integration-purpose file plans only.');
    }
    const supported = new Set(NATIVE_HOSTS.flatMap((host) => OPERATION_IDS.map((operation) => nativeSkillPath(host, operation))));
    const bootstrap = plan.mutations.some((mutation) => mutation.effect.path === identityPath && mutation.effect.expected === 'absent');
    for (const mutation of plan.mutations) {
      if (mutation.effect.purpose !== 'configuration' ||
          (!supported.has(mutation.effect.path) && mutation.effect.path !== INSTALLATION_PATH && !(bootstrap && setupPaths.has(mutation.effect.path)))) {
        throw new WorkflowError('scope-exceeded', 'Installation cannot write unrelated files or host configuration.');
      }
    }
    const metadata = plan.mutations.find((mutation) => mutation.effect.path === INSTALLATION_PATH);
    if (metadata === undefined || !('content' in metadata)) {
      throw new WorkflowError('scope-exceeded', 'Installation effects require a reviewed ownership-record write, not record deletion.');
    }
    const next = parseInstallationRecord(JSON.parse(metadata.content) as unknown);
    if (!sameWorkspaceBinding(next.workspace, plan.workspace)) {
      throw new WorkflowError('scope-exceeded', 'Ownership metadata must bind the reviewed workspace.');
    }
    const prior = await this.files.read(INSTALLATION_PATH);
    const previous = prior === null ? null : parseInstallationRecord(JSON.parse(prior.content) as unknown);
    if (previous !== null && !sameWorkspaceBinding(previous.workspace, plan.workspace)) {
      throw new WorkflowError('scope-exceeded', 'Existing ownership belongs to another workspace.');
    }
    const generated = desiredSkills(this.catalog, NATIVE_HOSTS, this.generatorVersion);
    for (const file of generated) {
      const mutation = plan.mutations.find((item) => item.effect.path === file.rendered.path);
      const old = previous?.files.find((item) => item.path === file.rendered.path);
      const updated = next.files.find((item) => item.path === file.rendered.path);
      if (mutation === undefined) {
        // Metadata-only refresh is safe only for still-owned exact generated bytes.
        if (JSON.stringify(old) !== JSON.stringify(updated) &&
            (old === undefined || old.digest !== file.rendered.digest ||
             JSON.stringify(updated) !== JSON.stringify(file.ownership) ||
             !plan.guards.some((guard) => guard.path === old.path && guard.digest === old.digest))) {
          throw new WorkflowError('scope-exceeded', 'Ownership of untouched files cannot be added, dropped, or silently reassigned.');
        }
        continue;
      }
      if ((old?.digest ?? 'absent') !== mutation.effect.expected) {
        throw new WorkflowError('scope-exceeded', 'Installation cannot adopt unowned files or replace drifted owned files.');
      }
      if ('content' in mutation) {
        if (mutation.content !== file.rendered.content || JSON.stringify(updated) !== JSON.stringify(file.ownership)) {
          throw new WorkflowError('scope-exceeded', 'Installation writes must match the current canonical rendered catalog and ownership.');
        }
      } else if (old === undefined || updated !== undefined) {
        throw new WorkflowError('scope-exceeded', 'Removal requires the exact prior owned file and reviewed ownership removal.');
      }
    }
    return this.files.commit(plan, approval);
  }
}
