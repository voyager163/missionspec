import type { ApprovalReference } from '../../kernel/authority.js';
import type { ArtifactId, ChangeId, ProjectPath, StableId } from '../../kernel/identifiers.js';
import type { Outcome } from '../../kernel/outcomes.js';
import type { Versioned } from '../../kernel/protocol.js';
import type { ContentDigest } from '../../kernel/revisions.js';

export * from './clarification.js';

export type ObservationSource =
  | { readonly kind: 'user-statement'; readonly statement: string }
  | { readonly kind: 'repository'; readonly path: ProjectPath; readonly digest: ContentDigest }
  | {
    readonly kind: 'external-context';
    readonly providerId: StableId<'provider'>;
    readonly reference: string;
    readonly freshness: 'current' | 'stale' | 'unknown';
  };

export interface DiscoveryObservation {
  readonly summary: string;
  readonly provenance: ObservationSource;
  readonly confidence: 'observed' | 'reported' | 'hypothesis';
}

export interface ClarificationQuestion {
  readonly id: StableId<'question'>;
  readonly question: string;
  readonly materiality: 'blocking' | 'minor';
  readonly affectedArtifacts: readonly ArtifactId[];
  readonly response:
    | { readonly state: 'unresolved' }
    | { readonly state: 'answered'; readonly answer: string; readonly source: 'user' | 'proposed-assumption' };
}

export interface DiscoveryReport extends Versioned {
  readonly observations: readonly DiscoveryObservation[];
  readonly options: readonly string[];
  readonly questions: readonly ClarificationQuestion[];
  readonly context: 'not-requested' | 'absent' | 'disabled' | 'partial' | 'incompatible' | 'unavailable' | 'available';
}

export interface DiscoveryOperations {
  discover(input: {
    readonly problem: string;
    readonly changeId: ChangeId | null;
    readonly observations: readonly DiscoveryObservation[];
  }): Promise<Outcome<DiscoveryReport>>;
  clarify(input: {
    readonly changeId: ChangeId;
    readonly artifactRevision: ContentDigest;
    readonly questions: readonly ClarificationQuestion[];
  }): Promise<Outcome<readonly ClarificationQuestion[]>>;
  capture(input: {
    readonly changeId: ChangeId;
    readonly report: DiscoveryReport;
    readonly approval: ApprovalReference;
    readonly expectedDiscovery: ContentDigest | 'absent';
  }): Promise<Outcome<ContentDigest>>;
}
