import { requireApproval } from './authority.js';
import { WorkflowError } from './errors.js';
import type { LocalWorkflow } from './local-workflow.js';
import type { LocalAuthorityPort, RuntimeStorePort } from '../ports/contracts.js';
import type {
  EvidencePruneCompletion, EvidencePrunePlan, EvidencePrunePrepared, EvidencePruneState, EvidencePruningStorePort,
} from '../ports/evidence-pruning.js';
import { digestApprovalRequest, parseApprovalReference, type ApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { parseId, type EvidenceId } from '../kernel/identifiers.js';
import { digestContent, parseDigest, sameWorkspaceBinding, type ContentDigest } from '../kernel/revisions.js';
import type { Outcome } from '../kernel/outcomes.js';
import { array, unique } from '../kernel/validation.js';
import { evidencePruneRequest, makePrunePlan, parsePrunePlan, parsePrunePrepared } from '../adapters/persistence/pruning.js';
import { inspectPrunableEvidence, removePreparedEvidence, withEvidencePruneLock } from '../adapters/persistence/evidence-files.js';

export interface EvidencePrunePreview {
  readonly id: ContentDigest;
  readonly plan: EvidencePrunePlan;
  readonly request: ApprovalRequest;
  readonly impact: 'accepted-history-preserved-current-evidence-becomes-unavailable';
}

function value<T>(outcome: Outcome<T>): T {
  if (outcome.status !== 'ok') throw new WorkflowError(outcome.error.code, outcome.error.message);
  return outcome.value;
}

/** Explicit private evidence retention only; never an age-based cleaner or an authority issuer. */
export class LocalEvidencePruning {
  private readonly now: () => string;

  constructor(
    private readonly workflow: LocalWorkflow, private readonly store: RuntimeStorePort,
    private readonly authority: LocalAuthorityPort, options: { readonly now?: () => string } = {},
  ) {
    this.now = options.now ?? (() => new Date().toISOString());
  }

  private capability(write = false): EvidencePruningStorePort {
    const capability = this.store.evidencePruning;
    if (capability === undefined || !['read-only', 'read-write'].includes(capability.access) ||
        ['inspectEvidencePrune', 'prepareEvidencePrune', 'readEvidencePrune',
      'listEvidencePrunes', 'completeEvidencePrune'].some((name) => typeof Reflect.get(capability, name) !== 'function')) {
      throw new WorkflowError('capability-unavailable', 'This runtime store has no qualified recoverable evidence-pruning capability.');
    }
    if (write && capability.access !== 'read-write') {
      throw new WorkflowError('capability-unavailable', 'Prune commit/recovery requires an explicitly writable runtime store before any file effect.');
    }
    return capability;
  }

  private async scope(plan?: EvidencePrunePlan): Promise<void> {
    const project = await this.workflow.project();
    if (project.state !== 'initialized') throw new WorkflowError('not-found', 'An initialized local workspace is required.');
    if (project.pendingTransactions.length !== 0) throw new WorkflowError('conflict', 'Pending file recovery blocks evidence pruning.');
    if (plan !== undefined && !sameWorkspaceBinding(project.workspace, plan.inventory.workspace)) {
      throw new WorkflowError('scope-exceeded', 'Prune plan belongs to another independently observed workspace.');
    }
  }

  private async quiescent(): Promise<void> {
    const runs = value(await this.store.listRuns());
    if (runs.some((run) => run.quiescence !== 'confirmed' || ['running', 'outcome-unknown'].includes(run.state))) {
      throw new WorkflowError('conflict', 'Active or unreconciled runs block evidence pruning and its recovery.');
    }
  }

  async preview(evidenceIds: readonly EvidenceId[]): Promise<EvidencePrunePreview> {
    const ids = unique(array(evidenceIds, 'prune.evidence', (id) => parseId('evidence', id), 1), 'prune.evidence');
    await this.scope();
    const inventory = value(await this.capability().inspectEvidencePrune(ids));
    const observations = [];
    for (const item of inventory.items) {
      const observation = await inspectPrunableEvidence(this.workflow.files, inventory.workspace, item);
      if (observation === null) throw new WorkflowError('evidence-unavailable', 'A newly selected evidence file is absent.');
      observations.push(observation);
    }
    const plan = makePrunePlan(inventory, observations);
    await this.scope(plan);
    return {
      id: plan.digest, plan, request: evidencePruneRequest(plan),
      impact: 'accepted-history-preserved-current-evidence-becomes-unavailable',
    };
  }

  async confirm(preview: EvidencePrunePreview): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    const plan = parsePrunePlan(preview.plan);
    const request = evidencePruneRequest(plan);
    if (preview.id !== plan.digest || digestApprovalRequest(preview.request) !== digestApprovalRequest(request)) {
      throw new WorkflowError('scope-exceeded', 'Displayed pruning preview differs from the exact removal request.');
    }
    await this.scope(plan);
    return this.authority.requestConfirmation(request, {
      evidencePruning: { id: plan.digest, plan, impact: 'accepted-history-preserved-current-evidence-becomes-unavailable' },
    });
  }

  async status(id: ContentDigest): Promise<EvidencePruneState | null> {
    await this.scope();
    const state = value(await this.capability().readEvidencePrune(parseDigest(id)));
    if (state !== null) await this.scope(state.prepared.plan);
    return state;
  }

  async pending(): Promise<readonly EvidencePruneState[]> {
    await this.scope();
    const states = value(await this.capability().listEvidencePrunes());
    for (const state of states) await this.scope(state.prepared.plan);
    return states.filter((entry) => entry.state === 'prepared');
  }

  async previewRecovery(id: ContentDigest) {
    const state = await this.status(parseDigest(id));
    if (state === null) throw new WorkflowError('not-found', 'No durable prune preparation exists for recovery.');
    const plan = state.prepared.plan;
    const remaining = [];
    if (state.state === 'prepared') {
      for (const item of plan.inventory.items) {
        const observation = await inspectPrunableEvidence(this.workflow.files, plan.inventory.workspace, item, true);
        remaining.push({ id: item.id, path: item.path, rawDigest: item.rawDigest,
          state: observation === null ? 'already-absent' as const : 'retained' as const });
      }
    }
    return {
      id: plan.digest, plan, request: state.prepared.request,
      impact: 'accepted-history-preserved-current-evidence-becomes-unavailable' as const,
      state: state.state, remaining,
    };
  }

  async commit(preview: EvidencePrunePreview, approval: ApprovalReference): Promise<EvidencePruneState> {
    this.capability(true);
    const plan = parsePrunePlan(preview.plan);
    const request = evidencePruneRequest(plan);
    const reference = parseApprovalReference(approval);
    if (preview.id !== plan.digest || digestApprovalRequest(preview.request) !== digestApprovalRequest(request)) {
      throw new WorkflowError('scope-exceeded', 'Pruning preview identity/request was modified.');
    }
    await this.scope(plan);
    await requireApproval(this.authority, reference, request, this.now());
    return withEvidencePruneLock(this.workflow.files, plan.inventory.workspace, plan.digest, async () => {
      await this.scope(plan);
      const capability = this.capability();
      const previous = value(await capability.readEvidencePrune(plan.digest));
      if (previous !== null) {
        throw new WorkflowError('conflict', 'This prune is already prepared or completed. Use explicit status/recovery; do not replay deletion.');
      }
      await this.quiescent();
      const current = await this.preview(plan.inventory.items.map((item) => item.id));
      if (current.plan.digest !== plan.digest) throw new WorkflowError('stale-revision', 'Evidence or accepted-history impact changed after review.');
      await requireApproval(this.authority, reference, request, this.now());
      const prepared = parsePrunePrepared({
        schemaVersion: 1, id: plan.digest, plan, request, approval: reference, preparedAt: this.now(),
      });
      const state = value(await capability.prepareEvidencePrune(prepared));
      if (state.state !== 'prepared') throw new WorkflowError('conflict', 'The preparation is already completed; no deletion is replayed.');
      return this.finish(state, reference);
    });
  }

  async recover(id: ContentDigest, approval: ApprovalReference): Promise<EvidencePruneState> {
    const identity = parseDigest(id);
    const reference = parseApprovalReference(approval);
    const current = await this.status(identity);
    if (current === null) throw new WorkflowError('not-found', 'No durable prune preparation exists for recovery.');
    if (current.state === 'pruned') return current;
    this.capability(true);
    await this.scope(current.prepared.plan);
    await requireApproval(this.authority, reference, current.prepared.request, this.now());
    return withEvidencePruneLock(this.workflow.files, current.prepared.plan.inventory.workspace, identity, async () => {
      const state = value(await this.capability().readEvidencePrune(identity));
      if (state === null) throw new WorkflowError('persistence-failed', 'Prune preparation disappeared during recovery.');
      if (state.state === 'pruned') return state;
      await this.scope(state.prepared.plan);
      await this.quiescent();
      await requireApproval(this.authority, reference, state.prepared.request, this.now());
      return this.finish(state, reference);
    });
  }

  private async finish(state: Extract<EvidencePruneState, { state: 'prepared' }>, approval: ApprovalReference): Promise<EvidencePruneState> {
    const prepared: EvidencePrunePrepared = state.prepared;
    const { plan } = prepared;
    try {
      await this.quiescent();
      for (const item of plan.inventory.items) {
        const observation = await inspectPrunableEvidence(this.workflow.files, plan.inventory.workspace, item, true);
        if (observation !== null && JSON.stringify(observation) !==
            JSON.stringify(plan.observations.find((entry) => entry.evidenceId === item.id))) {
          throw new WorkflowError('stale-revision', 'The retained observation no longer matches the approved compact history.');
        }
      }
      for (const item of plan.inventory.items) {
        await requireApproval(this.authority, approval, prepared.request, this.now());
        await removePreparedEvidence(this.workflow.files, plan.inventory.workspace, item);
      }
      await requireApproval(this.authority, approval, prepared.request, this.now());
      for (const item of plan.inventory.items) {
        if (await inspectPrunableEvidence(this.workflow.files, plan.inventory.workspace, item, true) !== null) {
          throw new WorkflowError('stale-revision', 'A raw evidence path reappeared; completion is blocked without deleting it again.');
        }
      }
      const completion: EvidencePruneCompletion = {
        schemaVersion: 1, id: prepared.id, preparedDigest: digestContent(JSON.stringify(prepared)),
        approval, completedAt: this.now(),
      };
      return value(await this.capability().completeEvidencePrune(completion));
    } catch (error) {
      const code = error instanceof WorkflowError ? error.code : 'effect-outcome-unknown';
      throw new WorkflowError(code, `Prune ${prepared.id} remains prepared until status confirms completion; preserve edited bytes and explicitly recover with current approval.`);
    }
  }
}
