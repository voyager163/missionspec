import type { ApprovalReference } from '../../kernel/authority.js';
import type { AttemptId, CheckId, EvidenceId, ProjectPath, RequirementId, TaskId } from '../../kernel/identifiers.js';
import type { Finding, Outcome } from '../../kernel/outcomes.js';
import type { Versioned } from '../../kernel/protocol.js';
import type { ContentDigest, RevisionBinding } from '../../kernel/revisions.js';
import type { PlannedCheck, TaskDefinition } from '../planning/contracts.js';

export * from './assessment.js';
export * from './convergence.js';
export * from './lessons/index.js';

export interface EvidenceReference extends Versioned {
  readonly id: EvidenceId;
  readonly revisions: RevisionBinding;
  readonly source: ContentDigest;
  readonly checkId: CheckId;
  readonly checkDefinition: ContentDigest;
  readonly attemptId: AttemptId | null;
  readonly storage:
    | { readonly state: 'retained'; readonly path: ProjectPath; readonly digest: ContentDigest }
    | { readonly state: 'pruned'; readonly prunedAt: string; readonly approval: ApprovalReference }
    | { readonly state: 'unavailable'; readonly reason: string };
}

export type CheckObservation =
  | {
    readonly state: 'observed';
    readonly checkId: CheckId;
    readonly basis: 'executed' | 'static-inspection' | 'agent-review';
    readonly result: 'passed' | 'failed';
    readonly evidence: EvidenceReference;
  }
  | {
    readonly state: 'missing' | 'skipped' | 'unavailable' | 'stale';
    readonly checkId: CheckId;
    readonly reason: string;
  };

export interface GapFinding extends Finding {
  readonly gap: 'missing' | 'partial' | 'contradictory' | 'unrequested';
  readonly requirements: readonly RequirementId[];
  readonly tasks: readonly TaskId[];
  readonly evidence: readonly EvidenceId[];
}

export interface VerificationReport extends Versioned {
  readonly revisions: RevisionBinding;
  readonly source: ContentDigest;
  readonly observations: readonly CheckObservation[];
  readonly completeness: readonly GapFinding[];
  readonly correctness: readonly GapFinding[];
  readonly coherence: readonly GapFinding[];
  readonly proposedRepairs: readonly TaskDefinition[];
  readonly acceptanceEligibility:
    | { readonly state: 'eligible-for-human-review'; readonly evidence: readonly EvidenceId[] }
    | { readonly state: 'ineligible'; readonly reasons: readonly string[] };
}

export interface AcceptanceRecord extends Versioned {
  readonly state: 'accepted';
  readonly revisions: RevisionBinding;
  readonly source: ContentDigest;
  readonly evidence: readonly EvidenceId[];
  readonly approval: ApprovalReference;
}

export interface VerificationOperations {
  verify(input: {
    readonly revisions: RevisionBinding;
    readonly source: ContentDigest;
    readonly checks: readonly PlannedCheck[];
    readonly approval: ApprovalReference;
  }): Promise<Outcome<VerificationReport>>;
  assessAcceptance(report: VerificationReport): Outcome<VerificationReport['acceptanceEligibility']>;
  recordAcceptance(report: VerificationReport, approval: ApprovalReference): Promise<Outcome<AcceptanceRecord>>;
}
