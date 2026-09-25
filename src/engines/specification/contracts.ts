import type { ApprovalReference } from '../../kernel/authority.js';
import type { RequestedEffect } from '../../kernel/effects.js';
import {
  parseId, parseProjectPath, type ArtifactId, type ChangeId, type ChangeSlug,
  type EvidenceId, type ProjectPath,
} from '../../kernel/identifiers.js';
import type { ArtifactReadiness, ChangeOutcome, Outcome } from '../../kernel/outcomes.js';
import { CONTRACT_VERSION, parseContractVersion, type Versioned } from '../../kernel/protocol.js';
import { digestContent, parseDigest, type ContentDigest, type RevisionBinding } from '../../kernel/revisions.js';
import { array, ContractError, record, text, unique } from '../../kernel/validation.js';

export * from './documents/index.js';
export * from './local.js';
export * from './import/index.js';

export const STANDARD_ARTIFACT_NODES = Object.freeze(['proposal', 'specs', 'design', 'tasks'] as const);
export const DEFAULT_WORKFLOW_PROFILE = 'standard' as const;
export type WorkflowProfile = 'standard' | 'compact';

declare const nodeBrand: unique symbol;
export type ArtifactNodeId = string & { readonly [nodeBrand]: true };

export function parseArtifactNodeId(value: unknown): ArtifactNodeId {
  if (typeof value !== 'string' || value.length > 80 || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u.test(value)) {
    throw new ContractError('artifact.node', 'expected a lowercase workflow node identifier');
  }
  return value as ArtifactNodeId;
}

export interface ArtifactFile {
  readonly path: ProjectPath;
  readonly content: string;
  readonly digest: ContentDigest;
}

export interface ArtifactDependency {
  readonly artifactId: ArtifactId;
  readonly revision: ContentDigest;
}

export interface ArtifactSnapshot extends Versioned {
  readonly id: ArtifactId;
  readonly node: ArtifactNodeId;
  readonly files: readonly ArtifactFile[];
  readonly dependencies: readonly ArtifactDependency[];
  readonly revision: ContentDigest;
}

export function captureArtifactSnapshot(value: unknown): ArtifactSnapshot {
  const input = record(value, 'artifact', ['contractVersion', 'id', 'node', 'files', 'dependencies']);
  const id = parseId('artifact', input.id);
  const node = parseArtifactNodeId(input.node);
  const files = array(input.files, 'artifact.files', (entry) => {
    const file = record(entry, 'artifact.file', ['path', 'content']);
    const content = text(file.content, 'artifact.file.content', 1_000_000);
    return Object.freeze({ path: parseProjectPath(file.path), content, digest: digestContent(content) });
  }, 1);
  unique(files.map((file) => file.path), 'artifact.files');
  const dependencies = array(input.dependencies, 'artifact.dependencies', (entry) => {
    const dependency = record(entry, 'artifact.dependency', ['artifactId', 'revision']);
    return Object.freeze({
      artifactId: parseId('artifact', dependency.artifactId),
      revision: parseDigest(dependency.revision),
    });
  });
  unique(dependencies.map((dependency) => dependency.artifactId), 'artifact.dependencies');
  if (dependencies.some((dependency) => dependency.artifactId === id)) {
    throw new ContractError('artifact.dependencies', 'an artifact cannot depend on itself');
  }
  const revision = digestContent(JSON.stringify({
    contractVersion: CONTRACT_VERSION,
    id,
    node,
    files: files.map(({ path, digest }) => ({ path, digest })).sort((a, b) => compare(a.path, b.path)),
    dependencies: [...dependencies].sort((a, b) => compare(a.artifactId, b.artifactId)),
  }));
  return Object.freeze({
    contractVersion: parseContractVersion(input.contractVersion), id, node, files, dependencies, revision,
  });
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export interface ArtifactAssessment {
  readonly artifactId: ArtifactId;
  readonly revision: ContentDigest | null;
  readonly readiness: ArtifactReadiness;
  readonly reasons: readonly string[];
}

export interface ChangeSnapshot extends Versioned {
  readonly id: ChangeId;
  readonly slug: ChangeSlug;
  readonly baseline: ContentDigest;
  readonly workflow: { readonly profile: WorkflowProfile; readonly version: string; readonly digest: ContentDigest };
  readonly artifacts: readonly ArtifactSnapshot[];
}

export interface RevisionPatch {
  readonly expected: RevisionBinding;
  readonly effects: readonly RequestedEffect[];
  readonly invalidatedArtifacts: readonly ArtifactId[];
  readonly invalidatedApprovalReferences: readonly ApprovalReference[];
  readonly staleEvidence: readonly EvidenceId[];
}

export interface SyncPreview extends Versioned {
  readonly revisions: RevisionBinding;
  readonly originalBaseline: ContentDigest;
  readonly currentBaseline: ContentDigest;
  readonly proposedBaseline: ContentDigest;
  readonly effects: readonly RequestedEffect[];
  readonly conflicts: readonly { readonly path: ProjectPath; readonly reason: string }[];
}

export type ArchiveDecision =
  | {
    readonly outcome: 'accepted';
    readonly acceptance: ApprovalReference;
    readonly promotion: { readonly state: 'not-required'; readonly reason: string } |
      { readonly state: 'recorded'; readonly baseline: ContentDigest; readonly approval: ApprovalReference };
  }
  | { readonly outcome: Exclude<ChangeOutcome, 'accepted' | 'not-accepted'> };

export interface ArchiveRequest {
  readonly revisions: RevisionBinding;
  readonly destination: ProjectPath;
  readonly decision: ArchiveDecision;
  readonly closureApproval: ApprovalReference;
  readonly evidence: readonly EvidenceId[];
}

export interface SpecificationOperations {
  readChange(changeId: ChangeId): Promise<Outcome<ChangeSnapshot>>;
  previewRevision(changeId: ChangeId, artifacts: readonly ArtifactSnapshot[]): Promise<Outcome<RevisionPatch>>;
  applyRevision(patch: RevisionPatch, approval: ApprovalReference): Promise<Outcome<ChangeSnapshot>>;
  previewSync(revisions: RevisionBinding): Promise<Outcome<SyncPreview>>;
  commitSync(preview: SyncPreview, acceptance: ApprovalReference, promotion: ApprovalReference): Promise<Outcome<ContentDigest>>;
  archive(request: ArchiveRequest): Promise<Outcome<{ readonly destination: ProjectPath; readonly outcome: ArchiveDecision['outcome'] }>>;
}
