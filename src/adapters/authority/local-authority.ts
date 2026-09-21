import { randomUUID } from 'node:crypto';
import { LocalWorkspace, parseFilePlan, type FilePlan } from '../filesystem/local-workspace.js';
import {
  digestApprovalRequest, parseApprovalReference, parseApprovalRequest,
  type ApprovalReference, type ApprovalRequest, type LocalUserAssurance, type TrustedIssuedApproval,
} from '../../kernel/authority.js';
import { digestContent, sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../../kernel/revisions.js';
import { NATIVE_HOSTS, parseId, parseProjectPath } from '../../kernel/identifiers.js';
import { OPERATION_IDS } from '../../kernel/registry.js';
import { nativeSkillPath } from '../../engines/integration/index.js';
import type { LocalAuthorityPort } from '../../ports/contracts.js';
import { WorkflowError } from '../../application/errors.js';
import { confirmationProtocol } from '../../application/approval-validation.js';
import { oneOf, record } from '../../kernel/validation.js';
import {
  approvalReceipt as parseApprovalReceipt, renderConfirmationDisplay, reviewDetail, revocationRecord,
  type ApprovalReceipt,
} from './records.js';

export type LocalConfirmationDecision = 'accept' | 'decline' | 'cancel' | 'unavailable';

export interface LocalConfirmationReview {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly action: 'issue' | 'revoke';
  readonly approval: ApprovalReference | null;
  readonly request: ApprovalRequest;
  readonly requestDigest: ContentDigest;
  readonly workspace: WorkspaceBinding;
  readonly display: Readonly<Record<string, unknown>>;
  readonly displayDigest: ContentDigest;
  readonly renderedDisplay: string;
  readonly expiresAt: string;
  readonly deadlineAt: string;
}

/** Install only in trusted composition, never from tool arguments, clientInfo, environment, or model output. */
export interface TrustedConfirmationTransport {
  readonly channel: LocalUserAssurance['channel'];
  readonly protocolIdentity: LocalUserAssurance['protocolIdentity'];
  /** Accept only the correlated explicit confirmation of this complete review; a generic form submission is insufficient. */
  confirm(review: LocalConfirmationReview, signal: AbortSignal): Promise<LocalConfirmationDecision>;
}

export interface LocalConfirmationAuthority extends LocalAuthorityPort {
  confirmPlan(plan: FilePlan): ReturnType<LocalAuthorityPort['requestConfirmation']>;
  revoke(reference: ApprovalReference): Promise<void>;
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value)) freeze(entry);
    Object.freeze(value);
  }
  return value;
}

class PersistentAuthority implements LocalConfirmationAuthority {
  constructor(private readonly files: LocalWorkspace, private readonly transport: TrustedConfirmationTransport | undefined) {}

  async confirmPlan(value: FilePlan): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    const plan = parseFilePlan(value);
    const identity = await this.files.identity();
    const bootstrapPaths = new Set(['.missionspec/workspace.json', 'missionspec/config.yaml', '.gitignore',
      '.missionspec/installation.json', ...NATIVE_HOSTS.flatMap((host) => OPERATION_IDS.map((operation) => nativeSkillPath(host, operation)))]);
    const bootstrap = identity === null && plan.request.operation === 'onboard' &&
      plan.request.purpose === 'integration' && plan.mutations.some((mutation) =>
        mutation.effect.kind === 'file-write' && mutation.effect.path === '.missionspec/workspace.json' &&
        mutation.effect.expected === 'absent' && 'content' in mutation &&
        sameWorkspaceBinding(JSON.parse(mutation.content), plan.workspace)) &&
      plan.mutations.some((mutation) => mutation.effect.path === 'missionspec/config.yaml' && mutation.effect.kind === 'file-write' && mutation.effect.expected === 'absent') &&
      plan.mutations.every((mutation) => mutation.effect.kind === 'file-write' &&
        mutation.effect.purpose === 'configuration' && bootstrapPaths.has(mutation.effect.path));
    const previous = await Promise.all(plan.mutations.map(async (mutation) => ({
      path: mutation.effect.path, before: (await this.files.read(mutation.effect.path))?.content ?? null,
    })));
    return this.issue(plan.request, { filePlan: plan, previous }, bootstrap);
  }

  async requestConfirmation(request: ApprovalRequest, detail: Readonly<Record<string, unknown>> = {}): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    const actualRequest = parseApprovalRequest(request);
    const data = reviewDetail(detail);
    if (data.filePlan !== undefined) {
      const plan = parseFilePlan(data.filePlan);
      if (plan.digest !== digestApprovalRequest(actualRequest)) throw new WorkflowError('scope-exceeded', 'Displayed file plan differs from the requested confirmation.');
      return this.confirmPlan(plan);
    }
    return this.issue(actualRequest, data, false);
  }

  private async scope(request: ApprovalRequest, bootstrap: boolean): Promise<WorkspaceBinding> {
    const workspace = request.binding.kind === 'project' ? request.binding.workspace : request.binding.revisions.workspace;
    const current = await this.files.identity();
    if (workspace.rootDigest !== this.files.rootDigest || (current === null ? !bootstrap : !sameWorkspaceBinding(current, workspace))) {
      throw new WorkflowError('scope-exceeded', 'Confirmation must bind the observed workspace; only exact setup can bootstrap local state.');
    }
    return workspace;
  }

  private review(requestValue: ApprovalRequest, detail: object, action: LocalConfirmationReview['action'], approval: ApprovalReference | null): LocalConfirmationReview {
    const request = parseApprovalRequest(requestValue);
    const now = Date.now();
    const expiresAt = new Date(now + 30 * 60_000).toISOString();
    const deadlineAt = new Date(now + 120_000).toISOString();
    // Detach the exact displayed data before crossing an asynchronous transport boundary.
    const display = reviewDetail({
      request, detail: reviewDetail(detail), action, approval, expiresAt, deadlineAt,
      assurance: this.assurance(),
    });
    const renderedDisplay = renderConfirmationDisplay(display);
    if (Buffer.byteLength(JSON.stringify({ request, display, renderedDisplay })) > 5_500_000) {
      throw new WorkflowError('limit-reached', 'Split this review into smaller plans so its exact approval audit can be durably retained.');
    }
    const immutableRequest = parseApprovalRequest(request);
    return freeze({
      schemaVersion: 1, id: `confirmation-${randomUUID()}`, action, approval,
      request: immutableRequest, requestDigest: digestApprovalRequest(immutableRequest),
      workspace: immutableRequest.binding.kind === 'project' ? immutableRequest.binding.workspace : immutableRequest.binding.revisions.workspace,
      display, displayDigest: digestContent(JSON.stringify(display)), renderedDisplay, expiresAt, deadlineAt,
    });
  }

  private assurance(): LocalUserAssurance {
    if (this.transport === undefined) throw new WorkflowError('authority-required', 'No trusted confirmation transport is installed.');
    return freeze({
      kind: 'local-user', channel: this.transport.channel, protocolIdentity: this.transport.protocolIdentity,
      qualification: { state: 'not-established' }, humanPresence: 'not-attested', organizationIdentity: 'not-attested',
    });
  }

  private async exchange(review: LocalConfirmationReview): Promise<LocalConfirmationDecision> {
    if (this.transport === undefined || !['darwin', 'linux'].includes(process.platform)) return 'unavailable';
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let accepted = false;
    try {
      const deadline = new Promise<LocalConfirmationDecision>((resolve) => {
        timer = setTimeout(() => { abort.abort(); resolve('cancel'); }, Math.min(120_000, Math.max(0, Date.parse(review.deadlineAt) - Date.now())));
      });
      const answer = await Promise.race([this.transport.confirm(review, abort.signal), deadline]);
      if (Date.now() < Date.parse(review.expiresAt) - 30 * 60_000 ||
          Date.now() >= Date.parse(review.deadlineAt) || Date.now() >= Date.parse(review.expiresAt)) return 'cancel';
      accepted = answer === 'accept';
      return ['accept', 'decline', 'cancel', 'unavailable'].includes(answer) ? answer : 'unavailable';
    } catch {
      return 'unavailable';
    } finally {
      clearTimeout(timer);
      if (!accepted) abort.abort();
    }
  }

  private async issue(input: ApprovalRequest, detail: object, bootstrap: boolean): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    const request = parseApprovalRequest(input);
    await this.scope(request, bootstrap);
    if (this.transport === undefined) return { status: 'ok', value: { state: 'unavailable', reason: 'unqualified-channel' } };
    const review = this.review(request, detail, 'issue', null);
    const answer = await this.exchange(review);
    if (answer === 'unavailable') return { status: 'ok', value: { state: 'unavailable', reason: 'unqualified-channel' } };
    if (answer !== 'accept') return { status: 'ok', value: { state: 'declined' } };
    await this.scope(review.request, bootstrap);
    if (Date.now() < Date.parse(review.expiresAt) - 30 * 60_000 ||
        Date.now() >= Date.parse(review.deadlineAt) || Date.now() >= Date.parse(review.expiresAt)) {
      return { status: 'ok', value: { state: 'declined' } };
    }
    const approval: TrustedIssuedApproval = freeze({
      contractVersion: 1, state: 'trusted-issued', reference: { id: parseId('approval', `APR-${randomUUID()}`) },
      assurance: this.assurance(),
      request: review.request, requestDigest: review.requestDigest,
      issuedAt: new Date().toISOString(), expiresAt: review.expiresAt,
    });
    const receipt = parseApprovalReceipt({
      schemaVersion: 2, approval, display: review.display, displayDigest: review.displayDigest,
      renderedDisplay: review.renderedDisplay,
      confirmation: { id: review.id, action: 'issue', deadlineAt: review.deadlineAt, expiresAt: review.expiresAt },
    });
    // Only a genuinely confirmed exact setup may bootstrap this owned audit state.
    await this.files.recordRuntime('approvals', approval.reference.id, receipt);
    return { status: 'ok', value: { state: 'issued', approval } };
  }

  private async receipt(reference: ApprovalReference): Promise<ApprovalReceipt | null> {
    try {
      const file = await this.files.read(parseProjectPath(`.missionspec/approvals/${reference.id}.json`));
      if (file === null) return null;
      const untrusted: unknown = JSON.parse(file.content);
      const receipt = parseApprovalReceipt(untrusted);
      const approval = receipt.approval;
      const request = parseApprovalRequest(approval.request);
      const workspace = request.binding.kind === 'project' ? request.binding.workspace : request.binding.revisions.workspace;
      const identity = await this.files.identity();
      if (approval.reference.id !== reference.id || Date.parse(approval.issuedAt) > Date.now() ||
          workspace.rootDigest !== this.files.rootDigest || (identity !== null && !sameWorkspaceBinding(identity, workspace))) {
        throw new WorkflowError('persistence-failed', 'Local approval record is invalid.');
      }
      return freeze(receipt);
    } catch (error) {
      if (error instanceof WorkflowError) throw error;
      throw new WorkflowError('persistence-failed', 'Local approval storage is invalid or unreadable.');
    }
  }

  async resolve(input: ApprovalReference): ReturnType<LocalAuthorityPort['resolve']> {
    const reference = parseApprovalReference(input);
    const receipt = await this.receipt(reference);
    if (receipt === null) return { status: 'ok', value: { state: 'absent', reference } };
    const revoked = await this.files.read(parseProjectPath(`.missionspec/approvals/${reference.id}.revoked.json`));
    if (revoked !== null) {
      try {
        const value: unknown = JSON.parse(revoked.content);
        const validated = revocationRecord(value, receipt.approval);
        return { status: 'ok', value: { state: 'revoked', reference, recordedAt: validated.recordedAt } };
      } catch {
        throw new WorkflowError('persistence-failed', 'Revocation record is invalid.');
      }
    }
    if (Date.parse(receipt.approval.expiresAt) <= Date.now()) {
      return { status: 'ok', value: { state: 'expired', reference, recordedAt: receipt.approval.expiresAt } };
    }
    return { status: 'ok', value: { state: 'current', approval: receipt.approval } };
  }

  async revoke(input: ApprovalReference): Promise<void> {
    const reference = parseApprovalReference(input);
    const receipt = await this.receipt(reference);
    if (receipt === null) throw new WorkflowError('authority-required', 'Only an existing local approval can be revoked.');
    const current = await this.resolve(reference);
    if (current.status === 'ok' && current.value.state === 'revoked') return;
    const review = this.review(receipt.approval.request, { issuedApproval: receipt.approval }, 'revoke', reference);
    // A pre-setup approval can be revoked without granting any setup/file effects.
    if (await this.exchange(review) !== 'accept') throw new WorkflowError('authority-required', 'Revocation requires genuine confirmation through the trusted channel.');
    const after = await this.receipt(reference);
    if (after === null || JSON.stringify(after) !== JSON.stringify(receipt)) throw new WorkflowError('persistence-failed', 'Approval changed during revocation review.');
    const latest = await this.resolve(reference);
    if (latest.status === 'ok' && latest.value.state === 'revoked') return;
    const revocation = { schemaVersion: 2, reference, recordedAt: new Date().toISOString(), review };
    try { revocationRecord(revocation, receipt.approval); } catch {
      throw new WorkflowError('authority-expired', 'The exact revocation review expired or changed before persistence.');
    }
    await this.files.recordRuntime('approvals', `${reference.id}.revoked`, revocation);
  }
}

/** This factory installs a trusted transport capability; it is not an untrusted tool/request handler. */
export async function openLocalAuthority(options: {
  readonly directory: string;
  readonly transport?: TrustedConfirmationTransport;
}): Promise<LocalConfirmationAuthority> {
  const supplied = options.transport;
  if (supplied !== undefined) {
    record(supplied, 'transport', ['channel', 'protocolIdentity', 'confirm']);
    if (typeof supplied.confirm !== 'function') throw new WorkflowError('authority-required', 'A trusted confirmation callback must be installed by application composition.');
  }
  const transport = supplied === undefined ? undefined : Object.freeze({
    channel: oneOf(supplied.channel, ['terminal-confirmation', 'mcp-elicitation', 'trusted-callback'], 'transport.channel'),
    protocolIdentity: confirmationProtocol(supplied.protocolIdentity), confirm: supplied.confirm.bind(supplied),
  });
  return new PersistentAuthority(await LocalWorkspace.open(options.directory), transport);
}
