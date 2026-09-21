import type { ApprovalReference, ExecutionRequest } from '../kernel/authority.js';
import type { ChangeId, NativeHost, ProjectPath } from '../kernel/identifiers.js';
import type { Outcome } from '../kernel/outcomes.js';
import type { Versioned } from '../kernel/protocol.js';
import type { OperationId, StopBoundary } from '../kernel/registry.js';
import type { ContentDigest, RevisionBinding } from '../kernel/revisions.js';
import type { DiscoveryReport } from '../engines/discovery/contracts.js';
import type { RunSnapshot } from '../engines/execution/contracts.js';
import type { IntegrationPreview } from '../engines/integration/contracts.js';
import type { PlanningReport } from '../engines/planning/contracts.js';
import type { ArchiveDecision, ArtifactNodeId, ArtifactSnapshot, ChangeSnapshot, RevisionPatch, SyncPreview } from '../engines/specification/contracts.js';
import type { AcceptanceRecord, VerificationReport } from '../engines/verification/contracts.js';

export interface ChangeSelection {
  readonly changeId: ChangeId;
  readonly expectedRevision: ContentDigest;
}

export interface AuthorizedChange {
  readonly revisions: RevisionBinding;
  readonly approval: ApprovalReference;
}

export type OperationRequest = Versioned & (
  | { readonly operation: 'discover'; readonly problem: string; readonly change: ChangeSelection | null }
  | {
    readonly operation: 'draft';
    readonly change: ChangeSelection;
    readonly selectedArtifact: ArtifactNodeId | null;
    readonly approval: ApprovalReference;
  }
  | {
    readonly operation: 'draft-all';
    readonly change: ChangeSelection;
    readonly approval: ApprovalReference;
  }
  | { readonly operation: 'implement'; readonly change: AuthorizedChange; readonly execution: ExecutionRequest }
  | { readonly operation: 'verify'; readonly change: AuthorizedChange }
  | {
    readonly operation: 'archive';
    readonly change: AuthorizedChange;
    readonly decision: ArchiveDecision;
    readonly destination: ProjectPath;
  }
  | { readonly operation: 'revise'; readonly change: AuthorizedChange; readonly patch: RevisionPatch }
  | { readonly operation: 'clarify'; readonly change: ChangeSelection; readonly ambiguity: string }
  | { readonly operation: 'analyze'; readonly change: ChangeSelection }
  | {
    readonly operation: 'principles';
    readonly expected: ContentDigest | 'absent';
    readonly proposedMarkdown: string;
    readonly approval: ApprovalReference;
  }
  | {
    readonly operation: 'sync';
    readonly preview: SyncPreview;
    readonly acceptance: ApprovalReference;
    readonly promotion: ApprovalReference;
  }
  | { readonly operation: 'onboard'; readonly selectedHosts: readonly NativeHost[] }
);

export interface OperationValues {
  readonly discover: DiscoveryReport;
  readonly draft: { readonly artifact: ArtifactSnapshot | null; readonly report: PlanningReport };
  readonly 'draft-all': { readonly artifacts: readonly ArtifactSnapshot[]; readonly report: PlanningReport };
  readonly implement: RunSnapshot;
  readonly verify: VerificationReport;
  readonly archive: { readonly destination: ProjectPath; readonly outcome: ArchiveDecision['outcome'] };
  readonly revise: ChangeSnapshot;
  readonly clarify: DiscoveryReport;
  readonly analyze: PlanningReport;
  readonly principles: { readonly revision: ContentDigest; readonly affectedChanges: readonly ChangeId[] };
  readonly sync: { readonly baseline: ContentDigest; readonly changeState: 'open' };
  readonly onboard: { readonly guidance: readonly string[]; readonly installationPreview: IntegrationPreview | null };
}

export type OperationResult<K extends OperationId> = Versioned & {
  readonly operation: K;
  readonly stop: StopBoundary;
  readonly outcome: Outcome<OperationValues[K]>;
};

export interface MissionSpecOperations {
  invoke<K extends OperationId>(request: Extract<OperationRequest, { readonly operation: K }>):
    Promise<OperationResult<K>>;
  accept(report: VerificationReport, approval: ApprovalReference): Promise<Outcome<AcceptanceRecord>>;
}
