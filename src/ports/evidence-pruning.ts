import type { ApprovalReference, ApprovalRequest } from '../kernel/authority.js';
import type { EvidenceId, ProjectPath, RunId } from '../kernel/identifiers.js';
import type { Outcome } from '../kernel/outcomes.js';
import type { ContentDigest, WorkspaceBinding } from '../kernel/revisions.js';

export interface EvidencePruneTarget {
  readonly id: EvidenceId;
  readonly runId: RunId;
  readonly runRevision: ContentDigest;
  readonly evidenceDigest: ContentDigest;
  readonly path: ProjectPath;
  readonly rawDigest: ContentDigest;
}

export interface EvidencePruneInventory {
  readonly schemaVersion: 1;
  readonly workspace: WorkspaceBinding;
  readonly items: readonly EvidencePruneTarget[];
  readonly acceptances: readonly {
    readonly approval: ApprovalReference;
    readonly revision: ContentDigest;
    readonly affectedEvidence: readonly EvidenceId[];
  }[];
  readonly digest: ContentDigest;
}

export interface EvidencePruneObservation {
  readonly evidenceId: EvidenceId;
  readonly basis: 'executed' | 'static-inspection' | 'agent-review';
  readonly result: 'passed' | 'failed';
  readonly outputDigest: ContentDigest;
}

export interface EvidencePrunePlan {
  readonly schemaVersion: 1;
  readonly inventory: EvidencePruneInventory;
  readonly observations: readonly EvidencePruneObservation[];
  readonly digest: ContentDigest;
}

export interface EvidencePrunePrepared {
  readonly schemaVersion: 1;
  readonly id: ContentDigest;
  readonly plan: EvidencePrunePlan;
  readonly request: ApprovalRequest;
  readonly approval: ApprovalReference;
  readonly preparedAt: string;
}

export interface EvidencePruneCompletion {
  readonly schemaVersion: 1;
  readonly id: ContentDigest;
  readonly preparedDigest: ContentDigest;
  readonly approval: ApprovalReference;
  readonly completedAt: string;
}

export type EvidencePruneState =
  | { readonly state: 'prepared'; readonly prepared: EvidencePrunePrepared; readonly revision: ContentDigest }
  | {
    readonly state: 'pruned'; readonly prepared: EvidencePrunePrepared;
    readonly completion: EvidencePruneCompletion; readonly revision: ContentDigest;
  };

/** Trusted local composition only. These methods do not issue authority or delete files. */
export interface EvidencePruningStorePort {
  readonly access: 'read-only' | 'read-write';
  inspectEvidencePrune(ids: readonly EvidenceId[]): Promise<Outcome<EvidencePruneInventory>>;
  prepareEvidencePrune(record: EvidencePrunePrepared): Promise<Outcome<EvidencePruneState>>;
  readEvidencePrune(id: ContentDigest): Promise<Outcome<EvidencePruneState | null>>;
  listEvidencePrunes(): Promise<Outcome<readonly EvidencePruneState[]>>;
  completeEvidencePrune(record: EvidencePruneCompletion): Promise<Outcome<EvidencePruneState>>;
}
