import { readFile } from 'node:fs/promises';
import { stringify } from 'yaml';
import {
  makeFilePlan, parseFilePlan, writeMutation, type FileGuard, type FilePlan,
} from '../adapters/filesystem/local-workspace.js';
import type { ApprovalReference } from '../kernel/authority.js';
import { parseChangeSlug, parseId, parseProjectPath, type ChangeId, type ChangeSlug, type ProjectPath } from '../kernel/identifiers.js';
import { digestContent, sameWorkspaceBinding } from '../kernel/revisions.js';
import { array, ContractError, record, unique } from '../kernel/validation.js';
import {
  captureArtifactSnapshot, parseCapabilityName, parseChangeMetadata, parseProjectMetadata,
  type ArtifactSnapshot, type ChangeMetadata,
  parseAdoptionMaterial, prepareAdoptionMaterial, type AdoptionManifest, type AdoptionMaterial,
} from '../engines/specification/contracts.js';
import { assessArtifactReadiness, parseArtifactWorkflow, parseWorkflowProfile } from '../engines/planning/contracts.js';
import type { LocalWorkflow } from './local-workflow.js';
import { WorkflowError } from './errors.js';

export interface AdoptionPreview {
  readonly schemaVersion: 1;
  readonly slug: ChangeSlug;
  readonly changeId: ChangeId;
  readonly mode: AdoptionManifest['mode'];
  readonly creation: FilePlan;
  readonly material: AdoptionMaterial;
  readonly plan: FilePlan;
}

const configPath = parseProjectPath('missionspec/config.yaml');
const workspacePath = parseProjectPath('.missionspec/workspace.json');
const yaml = (value: unknown): string => stringify(value, { lineWidth: 0, aliasDuplicateObjects: false });

function creationMetadata(creation: FilePlan): ChangeMetadata {
  if (creation.request.operation !== 'draft' || creation.request.purpose !== 'artifact-edit' ||
    creation.request.binding.kind !== 'project' || creation.mutations.length !== 1) {
    throw new ContractError('adoption.creation', 'expected an explicit new-change creation preview');
  }
  const mutation = creation.mutations[0]!;
  if (!('content' in mutation) || mutation.effect.kind !== 'file-write' ||
    mutation.effect.expected !== 'absent' || mutation.effect.purpose !== 'configuration') {
    throw new ContractError('adoption.creation', 'new-change metadata must be an absent-target configuration write');
  }
  const metadata = parseChangeMetadata(parseProjectMetadata(mutation.content));
  const path = parseProjectPath(`missionspec/changes/${metadata.slug}/change.yaml`);
  if (mutation.effect.path !== path || metadata.questions.length !== 0 || metadata.promotedContent !== null ||
    metadata.nodes.some((node) => node.captured !== null || node.applicability !== undefined)) {
    throw new ContractError('adoption.creation', 'only untouched new-change metadata can seed adoption');
  }
  const expected = [path, configPath, workspacePath, ...metadata.baseline.map((file) => file.path)];
  if (creation.guards.length !== expected.length || expected.some((file) => !creation.guards.some((guard) => guard.path === file)) ||
    metadata.baseline.some((file) => !creation.guards.some((guard) => guard.path === file.path && guard.digest === file.digest))) {
    throw new ContractError('adoption.creation', 'new-change creation must retain its project and baseline observations');
  }
  return metadata;
}

function buildPreview(
  creation: FilePlan, material: AdoptionMaterial, workflowSource: string, observations: readonly FileGuard[],
): AdoptionPreview {
  const seed = creationMetadata(creation);
  const bundle = prepareAdoptionMaterial({ slug: seed.slug, changeId: seed.id, material });
  const workflow = parseArtifactWorkflow(workflowSource);
  if (workflow.profile !== seed.profile || workflow.revision !== seed.workflowRevision) {
    throw new WorkflowError('stale-revision', 'The pinned workflow changed before adoption.');
  }
  let metadata = seed;
  if (material.artifacts.length > 0) {
    const outputs = seed.nodes.flatMap((node) => node.outputs);
    if (outputs.length !== material.artifacts.length || outputs.some((output) => !material.artifacts.some((file) => file.path === output))) {
      throw new WorkflowError('invalid-input', 'Explicit adoption artifacts must cover the whole declared native output set.');
    }
    const snapshots = new Map<string, ArtifactSnapshot>();
    for (const id of workflow.order) {
      const node = seed.nodes.find((entry) => entry.node === id)!;
      const definition = workflow.nodes.find((entry) => entry.id === id)!;
      snapshots.set(id, captureArtifactSnapshot({
        contractVersion: 1, id: node.artifactId, node: id,
        files: node.outputs.map((path) => material.artifacts.find((file) => file.path === path)!),
        dependencies: definition.dependsOn.map((dependency) => {
          const predecessor = snapshots.get(dependency)!;
          return { artifactId: predecessor.id, revision: predecessor.revision };
        }),
      }));
    }
    const report = assessArtifactReadiness({
      changeId: seed.id, workflowSource, expectedWorkflow: seed.workflowRevision,
      sourceRevision: digestContent(JSON.stringify(seed.sourcePaths.map((path) =>
        observations.find((observation) => observation.path === path)))),
      bindings: seed.nodes.map((node) => ({
        node: node.node, artifactId: node.artifactId, declaredOutputs: node.outputs, applicability: { state: 'required' },
      })),
      snapshots: [...snapshots.values()],
    });
    if (report.next.state !== 'all-current') {
      throw new WorkflowError('invalid-input', 'Mapped artifacts do not satisfy the pinned structural workflow.');
    }
    metadata = parseChangeMetadata({
      ...seed,
      nodes: seed.nodes.map((node) => {
        const snapshot = snapshots.get(node.node)!;
        return { ...node, captured: {
          files: snapshot.files.map(({ path, digest }) => ({ path, digest })),
          dependencies: snapshot.dependencies,
        } };
      }),
    });
  }
  const metadataPath = parseProjectPath(`missionspec/changes/${seed.slug}/change.yaml`);
  const mutations = [
    ...bundle.files.map((file) => writeMutation(file.path, 'absent', file.content, 'artifact')),
    writeMutation(bundle.manifestPath, 'absent', `${JSON.stringify(bundle.manifest, null, 2)}\n`, 'artifact'),
    writeMutation(metadataPath, 'absent', yaml(metadata), 'configuration'),
  ];
  const guards = new Map<ProjectPath, FileGuard>();
  for (const guard of [...creation.guards, ...observations,
    ...mutations.map((mutation) => ({ path: mutation.effect.path, digest: mutation.effect.expected }))]) {
    const previous = guards.get(guard.path);
    if (previous !== undefined && previous.digest !== guard.digest) {
      throw new WorkflowError('conflict', 'Adoption observations conflict with another reviewed path.');
    }
    guards.set(guard.path, guard);
  }
  const plan = makeFilePlan({
    workspace: creation.workspace, operation: 'onboard', purpose: 'artifact-edit',
    guards: [...guards.values()], mutations,
  });
  return Object.freeze({
    schemaVersion: 1, slug: seed.slug, changeId: seed.id, mode: bundle.manifest.mode,
    creation, material, plan,
  });
}

/** Compose with the existing workflow so authority, quiescence and journal rules remain shared. */
export class AdoptionService {
  constructor(readonly workflow: LocalWorkflow) {}

  private async workflowSource(metadata: ChangeMetadata): Promise<string> {
    return readFile(new URL(`../../assets/workflows/${metadata.profile}/workflow.yaml`, import.meta.url), 'utf8');
  }

  private async observe(material: AdoptionMaterial, metadata: ChangeMetadata): Promise<readonly FileGuard[]> {
    const guards = new Map<ProjectPath, FileGuard>();
    for (const source of material.sources) {
      const current = await this.workflow.files.read(source.path);
      if (current === null || current.content !== source.content || current.digest !== digestContent(source.content)) {
        throw new WorkflowError('stale-revision', 'An explicitly supplied upstream document is missing or no longer matches its reviewed bytes.');
      }
      guards.set(source.path, { path: source.path, digest: current.digest });
    }
    for (const path of metadata.sourcePaths) {
      const current = await this.workflow.files.read(path);
      const digest = current?.digest ?? 'absent';
      if (guards.has(path) && guards.get(path)!.digest !== digest) {
        throw new WorkflowError('stale-revision', 'A selected upstream source changed during source-scope observation.');
      }
      guards.set(path, { path, digest });
    }
    return Object.freeze([...guards.values()]);
  }

  async preview(value: unknown): Promise<AdoptionPreview> {
    const input = record(value, 'adoption', ['slug', 'id', 'profile', 'specs', 'sourcePaths', 'sources', 'artifacts', 'mappings', 'verificationPlan']);
    if (input.verificationPlan !== undefined && typeof input.verificationPlan !== 'boolean') throw new ContractError('verificationPlan', 'expected an explicit boolean');
    const material = parseAdoptionMaterial({ sources: input.sources, artifacts: input.artifacts, mappings: input.mappings });
    const creation = await this.workflow.previewNewChange({
      slug: parseChangeSlug(input.slug),
      specs: unique(array(input.specs, 'adoption.specs', parseCapabilityName, 1), 'adoption.specs'),
      ...(input.id === undefined ? {} : { id: parseId('change', input.id) }),
      ...(input.profile === undefined ? {} : { profile: parseWorkflowProfile(input.profile) }),
      sourcePaths: input.sourcePaths === undefined ? [] : unique(array(input.sourcePaths, 'adoption.sourcePaths', parseProjectPath), 'adoption.sourcePaths'),
      ...(input.verificationPlan === undefined ? {} : { verificationPlan: input.verificationPlan }),
    });
    const metadata = creationMetadata(creation);
    const observations = await this.observe(material, metadata);
    return buildPreview(creation, material, await this.workflowSource(metadata), observations);
  }

  private async revalidate(value: unknown): Promise<AdoptionPreview> {
    const input = record(value, 'adoption.preview', ['schemaVersion', 'slug', 'changeId', 'mode', 'creation', 'material', 'plan']);
    if (input.schemaVersion !== 1) throw new ContractError('adoption.preview', 'unsupported preview version');
    const creation = parseFilePlan(input.creation);
    const suppliedPlan = parseFilePlan(input.plan);
    const metadata = creationMetadata(creation);
    if (parseChangeSlug(input.slug) !== metadata.slug || parseId('change', input.changeId) !== metadata.id) {
      throw new ContractError('adoption.preview', 'preview labels do not match the new change');
    }
    const currentCreation = await this.workflow.previewNewChange({
      slug: metadata.slug, id: metadata.id, profile: metadata.profile, sourcePaths: metadata.sourcePaths,
      verificationPlan: metadata.nodes.find((node) => node.node === 'tasks')!.outputs.length === 2,
      specs: metadata.baseline.map((file) => file.path.slice('missionspec/specs/'.length, -'/spec.md'.length)),
    });
    if (!sameWorkspaceBinding(currentCreation.workspace, creation.workspace) ||
      JSON.stringify(currentCreation.guards) !== JSON.stringify(creation.guards)) {
      throw new WorkflowError('stale-revision', 'Project identity or baseline inputs changed since the adoption preview.');
    }
    const material = parseAdoptionMaterial(input.material);
    const rebuilt = buildPreview(creation, material, await this.workflowSource(metadata), await this.observe(material, metadata));
    if (input.mode !== rebuilt.mode || suppliedPlan.digest !== rebuilt.plan.digest) {
      throw new WorkflowError('scope-exceeded', 'Adoption content, mapping or effects changed after preview.');
    }
    return rebuilt;
  }

  async confirm(preview: AdoptionPreview) {
    const current = await this.revalidate(preview);
    return this.workflow.confirm(current.plan);
  }

  async apply(preview: AdoptionPreview, approval: ApprovalReference) {
    const current = await this.revalidate(preview);
    return this.workflow.apply(current.plan, approval);
  }
}
