import {
  digestApprovalRequest, parseApprovalReference, parseApprovalRequest,
  type ApprovalReference, type ApprovalRequest, type TrustedIssuedApproval,
} from '../kernel/authority.js';
import type { LocalAuthorityPort } from '../ports/contracts.js';
import { WorkflowError } from './errors.js';
import { issuedApprovalData } from './approval-validation.js';

export const unavailableAuthority: LocalAuthorityPort = Object.freeze({
  async resolve(reference: ApprovalReference) {
    return { status: 'ok' as const, value: { state: 'absent' as const, reference } };
  },
  async requestConfirmation() {
    return { status: 'ok' as const, value: { state: 'unavailable' as const, reason: 'unqualified-channel' as const } };
  },
});

export async function requireApproval(
  authority: LocalAuthorityPort, reference: ApprovalReference, request: ApprovalRequest, now: string,
): Promise<TrustedIssuedApproval> {
  const expected = parseApprovalRequest(request);
  const ref = parseApprovalReference(reference);
  const resolution = await authority.resolve(ref);
  if (resolution.status !== 'ok' || resolution.value.state !== 'current') {
    throw new WorkflowError('authority-required', 'A current trusted local confirmation is required.');
  }
  let approval: TrustedIssuedApproval;
  try { approval = issuedApprovalData(resolution.value.approval, true); } catch {
    throw new WorkflowError('authority-required', 'The trusted authority returned an invalid approval record.');
  }
  if (approval.state !== 'trusted-issued' || approval.contractVersion !== 1 ||
      approval.reference.id !== ref.id || approval.assurance.kind !== 'local-user' ||
      !Number.isFinite(Date.parse(now)) || !Number.isFinite(Date.parse(approval.issuedAt)) ||
      !Number.isFinite(Date.parse(approval.expiresAt)) ||
      Date.parse(approval.issuedAt) > Date.parse(now) || Date.parse(approval.expiresAt) <= Date.parse(now)) {
    throw new WorkflowError('authority-expired', 'The trusted confirmation is invalid or expired.');
  }
  if (approval.requestDigest !== digestApprovalRequest(expected) ||
      digestApprovalRequest(approval.request) !== approval.requestDigest) {
    throw new WorkflowError('scope-exceeded', 'Confirmation does not bind this exact operation, subject and effect scope.');
  }
  return approval;
}
