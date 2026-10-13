import type { ArtifactId, ChangeId, ProjectPath } from '../../../kernel/identifiers.js';
import type { ContentDigest } from '../../../kernel/revisions.js';
import type {
  ArtifactDependency, ArtifactNodeId, ArtifactSnapshot, DocumentDiagnostic, WorkflowProfile,
} from '../../specification/contracts.js';

export type ArtifactApplicability =
  | { readonly state: 'required' }
  | {
    readonly state: 'not-applicable';
    readonly reason: string;
    readonly sourceRevision: ContentDigest;
    readonly dependencies: readonly ArtifactDependency[];
  };

export interface ArtifactBinding {
  readonly node: ArtifactNodeId;
  readonly artifactId: ArtifactId;
  readonly declaredOutputs: readonly ProjectPath[];
  readonly applicability: ArtifactApplicability;
}

export interface ArtifactReadinessRequest {
  readonly changeId: ChangeId;
  readonly workflowSource: string;
  readonly expectedWorkflow: ContentDigest;
  readonly sourceRevision: ContentDigest;
  readonly bindings: readonly ArtifactBinding[];
  readonly snapshots: readonly ArtifactSnapshot[];
  readonly selected?: ArtifactNodeId | null;
  readonly targets?: readonly ArtifactNodeId[];
}

export interface ReadinessDiagnostic {
  readonly code:
    | 'missing-snapshot' | 'invalid-snapshot' | 'output-set-mismatch' | 'invalid-document'
    | 'document-kind-mismatch' | 'document-change-mismatch' | 'additional-section-missing' | 'dependency-set-mismatch'
    | 'dependency-revision-mismatch' | 'dependency-not-current' | 'skip-stale'
    | 'skip-has-content' | 'selection-not-actionable';
  readonly node: ArtifactNodeId;
  readonly message: string;
  readonly document: DocumentDiagnostic | null;
}

export interface ArtifactReadinessAssessment {
  readonly node: ArtifactNodeId;
  readonly artifactId: ArtifactId;
  readonly readiness: 'missing' | 'valid' | 'stale' | 'not-applicable' | 'blocked';
  readonly revision: ContentDigest | null;
  readonly diagnostics: readonly ReadinessDiagnostic[];
}

export interface ArtifactReadinessReport {
  readonly profile: WorkflowProfile;
  readonly workflowRevision: ContentDigest;
  readonly assessments: readonly ArtifactReadinessAssessment[];
  readonly requiredClosure: readonly ArtifactNodeId[];
  readonly remainingClosure: readonly ArtifactNodeId[];
  readonly next:
    | { readonly state: 'ready'; readonly node: ArtifactNodeId }
    | { readonly state: 'selection-required'; readonly candidates: readonly ArtifactNodeId[] }
    | { readonly state: 'all-current' }
    | { readonly state: 'blocked' };
  readonly diagnostics: readonly ReadinessDiagnostic[];
}
