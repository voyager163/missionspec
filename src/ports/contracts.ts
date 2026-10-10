import type { ApprovalReference, ApprovalRequest, ApprovalResolution, ExecutionLimits, TrustedIssuedApproval } from '../kernel/authority.js';
import type { RequestedEffect } from '../kernel/effects.js';
import type { EvidenceId, NativeHost, ProjectPath, RunId, StableId, WorkOrderId } from '../kernel/identifiers.js';
import type { ErrorCode, Outcome } from '../kernel/outcomes.js';
import type { Versioned } from '../kernel/protocol.js';
import type { EngineId, OperationId } from '../kernel/registry.js';
import type { ContentDigest } from '../kernel/revisions.js';
import type { AttemptRecord, RunSnapshot, WorkOrder } from '../engines/execution/contracts.js';
import type { AcceptanceRecord, EvidenceReference } from '../engines/verification/contracts.js';
import type { EvidencePruningStorePort } from './evidence-pruning.js';

export type * from './evidence-pruning.js';

export interface FileSnapshot {
  readonly path: ProjectPath;
  readonly content: string;
  readonly digest: ContentDigest;
}

/** Inert request data, not authority to spend, share data, dispatch work or write files. */
export interface ProposalRequest {
  readonly prompt: string;
  readonly files: readonly FileSnapshot[];
  readonly allowedPaths: readonly ProjectPath[];
  readonly limits: {
    readonly maxInputBytes: number; readonly maxOutputBytes: number;
    readonly maxFiles: number; readonly timeoutMs: number;
  };
  readonly consent: {
    readonly host: NativeHost; readonly dataSharing: true; readonly modelSpending: true;
  };
}

export interface BoundedProposal {
  readonly kind: 'inert-proposal';
  readonly host: NativeHost;
  readonly summary: string;
  readonly changes: readonly {
    readonly path: ProjectPath; readonly expected: ContentDigest | 'absent'; readonly content: string;
  }[];
}

/** Trusted composition must separately admit native startup; this is not CodingHostPort qualification. */
export interface RestrictedProposalHostPort {
  readonly host: NativeHost;
  propose(request: ProposalRequest, signal?: AbortSignal): Promise<Outcome<BoundedProposal>>;
}

export type FileMutation =
  | {
    readonly effect: Extract<RequestedEffect, { kind: 'file-write' }>;
    readonly content: string;
  }
  | { readonly effect: Extract<RequestedEffect, { kind: 'file-remove' }> };

export interface ProjectFileSystemPort {
  readText(path: ProjectPath): Promise<Outcome<FileSnapshot | null>>;
  list(directory: ProjectPath): Promise<Outcome<readonly ProjectPath[]>>;
  commit(input: {
    readonly mutations: readonly FileMutation[];
    readonly approval: ApprovalReference;
    readonly journalReference: ContentDigest;
  }): Promise<Outcome<{ readonly files: readonly { readonly path: ProjectPath; readonly digest: ContentDigest | 'absent' }[] }>>;
}

export interface RuntimeStorePort {
  readonly evidencePruning?: EvidencePruningStorePort;
  listRuns(): Promise<Outcome<readonly RunSnapshot[]>>;
  readRun(runId: RunId): Promise<Outcome<{
    readonly revision: ContentDigest;
    readonly snapshot: RunSnapshot;
  } | null>>;
  commitRun(input: {
    readonly expectedRevision: ContentDigest | 'absent';
    readonly snapshot: RunSnapshot;
    readonly attempts: readonly AttemptRecord[];
    readonly evidence: readonly EvidenceReference[];
  }): Promise<Outcome<{ readonly revision: ContentDigest }>>;
  readEvidence(id: EvidenceId): Promise<Outcome<EvidenceReference | null>>;
  readRunEvidence(runId: RunId): Promise<Outcome<readonly EvidenceId[]>>;
  readAcceptance(reference: ApprovalReference): Promise<Outcome<AcceptanceRecord | null>>;
  recordAcceptance(record: AcceptanceRecord): Promise<Outcome<{ readonly revision: ContentDigest }>>;
}

export interface LocalAuthorityPort {
  resolve(reference: ApprovalReference): Promise<Outcome<ApprovalResolution>>;
  requestConfirmation(request: ApprovalRequest, detail?: Readonly<Record<string, unknown>>): Promise<Outcome<
    | { readonly state: 'issued'; readonly approval: TrustedIssuedApproval }
    | { readonly state: 'declined' }
    | { readonly state: 'unavailable'; readonly reason: 'unqualified-channel' | 'no-local-user' }
  >>;
}

export type LimitSupport = 'hard' | 'advisory' | 'unavailable';
export type HostQualification =
  | { readonly state: 'unqualified'; readonly host: NativeHost; readonly reason: string }
  | {
    readonly state: 'qualified';
    readonly host: NativeHost;
    readonly exactVersion: string;
    readonly operatingSystem: 'macos' | 'windows' | 'linux';
    readonly evidence: ContentDigest;
    readonly permissions: 'exact-effect-scope' | 'advisory' | 'unavailable';
    readonly limits: Readonly<Record<keyof ExecutionLimits, LimitSupport>>;
    readonly cancellation: 'confirmed-quiescence' | 'unknown-outcome-possible';
    readonly dispatchFencing: 'durable-admission-token';
  };

export interface CodingHostPort {
  inspect(host: NativeHost): Promise<Outcome<HostQualification>>;
  dispatch(workOrder: WorkOrder, dispatchToken: ContentDigest): Promise<Outcome<AttemptRecord>>;
  requestStop(workOrderId: WorkOrderId, dispatchToken: ContentDigest): Promise<Outcome<
    | { readonly state: 'quiesced'; readonly evidence: ContentDigest; readonly dispatchToken: ContentDigest }
    | { readonly state: 'outcome-unknown'; readonly reason: string }
  >>;
  inspectDispatch?(workOrder: WorkOrder, dispatchToken: ContentDigest): Promise<Outcome<
    | { readonly state: 'unknown' }
    | { readonly state: 'fenced-terminal'; readonly dispatchToken: ContentDigest; readonly evidence: ContentDigest; readonly attempt: AttemptRecord }
  >>;
}

export interface ClockPort {
  wallTime(): string;
  monotonicMilliseconds(): number;
}

export interface ContextObservation {
  readonly trust: 'untrusted-context';
  readonly text: string;
  readonly providerId: StableId<'provider'>;
  readonly reference: string;
  readonly contentDigest: ContentDigest;
  readonly freshness: 'current' | 'stale' | 'unknown';
}

export type ContextAvailability =
  | { readonly state: 'absent' | 'disabled' | 'incompatible' | 'unavailable'; readonly reason: string }
  | {
    readonly state: 'available' | 'partial';
    readonly providerId: StableId<'provider'>;
    readonly adapterContractVersion: Versioned['contractVersion'];
    readonly capabilities: readonly ('search' | 'retrieve')[];
  };

export interface ContextProviderPort {
  inspect(): Promise<Outcome<ContextAvailability>>;
  query(input: {
    readonly query: string;
    readonly sourceScope: readonly ProjectPath[];
    readonly approval: ApprovalReference;
  }): Promise<Outcome<{
    readonly availability: ContextAvailability;
    readonly observations: readonly ContextObservation[];
  }>>;
}

export interface DiagnosticEvent extends Versioned {
  readonly severity: 'debug' | 'information' | 'warning' | 'error';
  readonly code: 'operation-started' | 'operation-stopped' | 'boundary-rejected' | 'storage-failed' | 'telemetry-unavailable';
  readonly operation: OperationId;
  readonly engine: EngineId | null;
  readonly errorCode: ErrorCode | null;
  readonly elapsedMilliseconds: number | null;
}

export interface DiagnosticsPort {
  emit(event: DiagnosticEvent, persistence: 'console-only' | 'authorized-local-log'): Promise<
    | { readonly state: 'emitted'; readonly destination: 'console' | 'local-log' }
    | { readonly state: 'unavailable'; readonly consoleFallback: 'emitted' | 'unavailable' }
  >;
}

export interface OperationTelemetrySummary {
  readonly operation: OperationId;
  readonly access: 'read-only' | 'stateful';
  readonly distributedVersion: string;
  readonly outcome: 'completed' | 'blocked' | 'failed' | 'cancelled' | 'unknown';
  readonly host: NativeHost | 'none' | 'multiple' | 'unknown';
  readonly os: 'macos' | 'windows' | 'linux' | 'other';
  readonly monotonicDurationMs: number | null;
}

export interface TelemetryPort {
  recordCompletion(summary: OperationTelemetrySummary): Promise<
    | { readonly state: 'suppressed'; readonly reason: 'read-only' | 'opted-out' | 'notice-required' | 'not-configured' }
    | { readonly state: 'delivered' }
    | { readonly state: 'unavailable' }
  >;
}
