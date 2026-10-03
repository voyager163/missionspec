import type { ApprovalReference } from '../../kernel/authority.js';
import type { RequestedEffect } from '../../kernel/effects.js';
import type { NativeHost, ProjectPath, StableId } from '../../kernel/identifiers.js';
import type { Outcome } from '../../kernel/outcomes.js';
import type { Versioned } from '../../kernel/protocol.js';
import type { OperationId } from '../../kernel/registry.js';
import type { ContentDigest } from '../../kernel/revisions.js';

export interface HostProjection extends Versioned {
  readonly host: NativeHost;
  readonly operation: OperationId;
  readonly path: ProjectPath;
  readonly generatedDigest: ContentDigest;
  readonly previouslyOwnedDigest: ContentDigest | null;
}

export interface IntegrationPreview extends Versioned {
  readonly selectedHosts: readonly NativeHost[];
  readonly catalogRevision: ContentDigest;
  readonly projections: readonly HostProjection[];
  readonly effects: readonly RequestedEffect[];
  readonly conflicts: readonly { readonly path: ProjectPath; readonly reason: string }[];
}

export interface ContextConnection {
  readonly providerId: StableId<'provider'>;
  readonly connectionReference: string;
  readonly state: 'disabled' | 'configured';
  readonly consumptionScope: readonly ProjectPath[];
}

export interface IntegrationOperations {
  preview(hosts: readonly NativeHost[]): Promise<Outcome<IntegrationPreview>>;
  reconcile(preview: IntegrationPreview, approval: ApprovalReference): Promise<Outcome<readonly HostProjection[]>>;
  inspectContext(connection: ContextConnection): Promise<Outcome<
    | { readonly state: 'absent' | 'disabled' | 'incompatible' | 'unavailable'; readonly reason: string }
    | { readonly state: 'available' | 'partial'; readonly providerId: StableId<'provider'>; readonly capabilities: readonly ('search' | 'retrieve')[] }
  >>;
}
