import {
  digestApprovalRequest, parseApprovalReference, parseApprovalRequest,
  type ApprovalReference, type ApprovalRequest, type TrustedIssuedApproval,
} from '../../kernel/authority.js';
import { digestContent, parseDigest, parseWorkspaceBinding, sameWorkspaceBinding, type ContentDigest } from '../../kernel/revisions.js';
import { parseProjectPath } from '../../kernel/identifiers.js';
import { ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';
import { approvalTimestamp, issuedApprovalData, localUserAssurance } from '../../application/approval-validation.js';
import { parseFilePlan } from '../filesystem/local-workspace.js';

type JsonData = null | boolean | number | string | readonly JsonData[] | { readonly [key: string]: JsonData };
export type ReviewDetail = Readonly<Record<string, JsonData>>;

function jsonData(value: unknown, depth = 0): JsonData {
  if (depth > 40) throw new ContractError('detail', 'review data is too deeply nested');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 10_000 ||
        Reflect.ownKeys(value).some((key) => key !== 'length' && (typeof key !== 'string' || !/^(0|[1-9]\d*)$/u.test(key) || Number(key) >= value.length))) {
      throw new ContractError('detail', 'expected a bounded ordinary JSON array');
    }
    return Object.freeze(Array.from({ length: value.length }, (_, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !('value' in descriptor)) throw new ContractError('detail', 'sparse arrays and accessors are not JSON data');
      return jsonData(descriptor.value, depth + 1);
    }));
  }
  if (typeof value !== 'object' || value === null) throw new ContractError('detail', 'review details must contain only JSON data');
  const input = record(value, 'detail', Object.keys(value));
  return Object.freeze(Object.fromEntries(Object.entries(input).map(([key, entry]) => [key, jsonData(entry, depth + 1)])));
}

export function reviewDetail(value: unknown): ReviewDetail {
  const parsed = jsonData(value);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new ContractError('detail', 'expected a JSON object');
  // jsonData constructed this plain record and rejected non-data values recursively.
  return record(parsed, 'detail', Object.keys(parsed)) as ReviewDetail;
}

export function renderConfirmationDisplay(display: unknown): string {
  return JSON.stringify(display, null, 2).replace(/[\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function sameRequest(left: unknown, right: ApprovalRequest): void {
  if (JSON.stringify(parseApprovalRequest(left)) !== JSON.stringify(right)) {
    throw new ContractError('display.request', 'the displayed and issued requests must be identical');
  }
}

function confirmationId(value: unknown): string {
  const result = text(value, 'confirmation.id', 49);
  if (!/^confirmation-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(result)) {
    throw new ContractError('confirmation.id', 'invalid local review correlation identity');
  }
  return result;
}

function validateFileDetail(detail: Readonly<Record<string, unknown>>, request: ApprovalRequest, legacy: boolean): void {
  const filePlan = legacy ? detail.plan : detail.filePlan;
  if (filePlan !== undefined) {
    const plan = parseFilePlan(filePlan);
    sameRequest(plan.request, request);
    if (!legacy && detail.previous === undefined) throw new ContractError('display.detail.previous', 'exact file review requires its displayed preimages');
    if (detail.previous !== undefined) {
      if (!Array.isArray(detail.previous)) throw new ContractError('display.detail.previous', 'expected file preimages');
      const paths = detail.previous.map((entry: unknown) => {
        const previous = record(entry, 'previous', ['path', 'before']);
        if (previous.before !== null && typeof previous.before !== 'string') throw new ContractError('previous.before', 'expected text or absence');
        return parseProjectPath(previous.path);
      });
      unique(paths, 'previous.paths');
      if (paths.length !== plan.mutations.length || plan.mutations.some((mutation) => !paths.includes(mutation.effect.path))) {
        throw new ContractError('previous.paths', 'preimages must display the entire mutation set');
      }
    }
  } else if (legacy && detail.previous !== undefined) {
    throw new ContractError('display.detail.previous', 'preimages require their exact file plan');
  }
}

function validatedDisplay(value: unknown, request: ApprovalRequest, legacy: boolean): ReviewDetail {
  const input = record(value, 'display', legacy
    ? ['request', 'plan', 'previous', 'detail', 'action', 'approval', 'expiresAt', 'deadlineAt', 'assurance', 'expiresAfterMinutes', 'issuedApproval']
    : ['request', 'detail', 'action', 'approval', 'expiresAt', 'deadlineAt', 'assurance']);
  sameRequest(input.request, request);
  if (legacy) {
    oneOf(input.assurance, [
      'local-user only', 'local-user only; not organization identity, human-presence proof or same-UID tamper protection',
    ], 'legacyDisplay.assurance');
    if (input.action === undefined) {
      record(input, 'legacyDisplay', ['request', 'plan', 'previous', 'detail', 'assurance', 'expiresAfterMinutes']);
      if (input.expiresAfterMinutes !== 30) throw new ContractError('display.expiresAfterMinutes', 'unsupported legacy duration');
    } else if (input.expiresAfterMinutes !== undefined) {
      throw new ContractError('display.expiresAfterMinutes', 'legacy display formats cannot be mixed');
    }
    validateFileDetail(input, request, true);
    if (input.detail !== undefined) reviewDetail(input.detail);
  } else {
    localUserAssurance(input.assurance);
    validateFileDetail(reviewDetail(input.detail), request, false);
  }
  if (!legacy || input.action !== undefined) oneOf(input.action, ['issue', 'revoke'], 'display.action');
  if (!legacy || input.action !== undefined) {
    if (input.action === 'issue' && input.approval !== null) throw new ContractError('display.approval', 'issuance cannot choose its own approval identity');
    if (input.action === 'revoke') parseApprovalReference(input.approval);
  }
  if (!legacy || input.action !== undefined) approvalTimestamp(input.expiresAt, 'display.expiresAt');
  if (!legacy || input.action !== undefined) approvalTimestamp(input.deadlineAt, 'display.deadlineAt');
  if (legacy && input.issuedApproval !== undefined) issuedApprovalData(input.issuedApproval, true);
  return reviewDetail(input);
}

export interface ApprovalReceipt {
  readonly schemaVersion: 1 | 2;
  readonly approval: TrustedIssuedApproval;
  readonly display: ReviewDetail;
  readonly displayDigest: ContentDigest;
  readonly renderedDisplay: string;
  readonly confirmation?: {
    readonly id: string; readonly action: 'issue'; readonly deadlineAt: string; readonly expiresAt: string;
  };
}

export function approvalReceipt(value: unknown): ApprovalReceipt {
  const input = record(value, 'approvalReceipt', ['schemaVersion', 'approval', 'display', 'displayDigest', 'renderedDisplay', 'confirmation']);
  if (input.schemaVersion !== 1 && input.schemaVersion !== 2) throw new ContractError('approvalReceipt.schemaVersion', 'unsupported receipt version');
  const legacy = input.schemaVersion === 1;
  const approval = issuedApprovalData(input.approval, legacy);
  const display = validatedDisplay(input.display, approval.request, legacy);
  const displayDigest = parseDigest(input.displayDigest);
  const renderedDisplay = text(input.renderedDisplay, 'renderedDisplay', 7_000_000);
  if (digestContent(JSON.stringify(display)) !== displayDigest || renderConfirmationDisplay(display) !== renderedDisplay ||
      (!legacy && (JSON.stringify(localUserAssurance(display.assurance)) !== JSON.stringify(approval.assurance) ||
        display.action !== 'issue' || display.approval !== null))) {
    throw new ContractError('approvalReceipt', 'the exact displayed request and assurance must match the issued record');
  }
  if (display.action !== undefined && display.action !== 'issue') throw new ContractError('display.action', 'a revocation display cannot issue an approval');
  let confirmation: ApprovalReceipt['confirmation'];
  if (input.confirmation !== undefined || !legacy || display.action !== undefined) {
    const metadata = record(input.confirmation, 'confirmation', ['id', 'action', 'deadlineAt', 'expiresAt']);
    if (metadata.action !== 'issue') throw new ContractError('confirmation.action', 'expected an issuance review');
    confirmation = {
      id: confirmationId(metadata.id), action: 'issue',
      deadlineAt: approvalTimestamp(metadata.deadlineAt, 'confirmation.deadlineAt'),
      expiresAt: approvalTimestamp(metadata.expiresAt, 'confirmation.expiresAt'),
    };
    if (confirmation.expiresAt !== approval.expiresAt || display.expiresAt !== approval.expiresAt ||
        display.deadlineAt !== confirmation.deadlineAt || display.action !== 'issue' || display.approval !== null ||
        Date.parse(approval.issuedAt) >= Date.parse(confirmation.deadlineAt) ||
        Date.parse(approval.issuedAt) < Date.parse(approval.expiresAt) - 1_800_000 ||
        Date.parse(approval.expiresAt) - Date.parse(confirmation.deadlineAt) !== 1_680_000) {
      throw new ContractError('confirmation', 'review timing or issued subject does not match the display');
    }
  }
  return {
    schemaVersion: input.schemaVersion, approval, display, displayDigest, renderedDisplay,
    ...(confirmation === undefined ? {} : { confirmation }),
  };
}

export function revocationRecord(value: unknown, target: TrustedIssuedApproval): { readonly reference: ApprovalReference; readonly recordedAt: string } {
  const input = record(value, 'revocation', ['schemaVersion', 'reference', 'recordedAt', 'review']);
  const legacy = input.schemaVersion === undefined || input.schemaVersion === 1;
  if (!legacy && input.schemaVersion !== 2) throw new ContractError('revocation.schemaVersion', 'unsupported revocation version');
  const reference = parseApprovalReference(input.reference);
  const recordedAt = approvalTimestamp(input.recordedAt, 'revocation.recordedAt');
  if (reference.id !== target.reference.id || Date.parse(recordedAt) < Date.parse(target.issuedAt)) {
    throw new ContractError('revocation', 'reference or chronology differs from the issued approval');
  }
  if (input.review !== undefined || !legacy) {
    const review = record(input.review, 'revocation.review', [
      'schemaVersion', 'id', 'action', 'approval', 'request', 'requestDigest', 'workspace',
      'display', 'displayDigest', 'renderedDisplay', 'expiresAt', 'deadlineAt',
    ]);
    if (review.schemaVersion !== 1 || review.action !== 'revoke') throw new ContractError('revocation.review', 'expected a revocation review');
    confirmationId(review.id);
    if (parseApprovalReference(review.approval).id !== reference.id) throw new ContractError('revocation.review.approval', 'review targets a different approval');
    sameRequest(review.request, target.request);
    if (parseDigest(review.requestDigest) !== digestApprovalRequest(target.request)) throw new ContractError('revocation.review.requestDigest', 'request digest differs');
    const workspace = parseWorkspaceBinding(review.workspace);
    const expectedWorkspace = target.request.binding.kind === 'project' ? target.request.binding.workspace : target.request.binding.revisions.workspace;
    if (!sameWorkspaceBinding(workspace, expectedWorkspace)) throw new ContractError('revocation.review.workspace', 'workspace differs');
    const display = validatedDisplay(review.display, target.request, legacy);
    const expiresAt = approvalTimestamp(review.expiresAt, 'revocation.review.expiresAt');
    const deadlineAt = approvalTimestamp(review.deadlineAt, 'revocation.review.deadlineAt');
    if (display.action !== 'revoke' || parseApprovalReference(display.approval).id !== reference.id ||
        display.expiresAt !== expiresAt || display.deadlineAt !== deadlineAt ||
        Date.parse(expiresAt) - Date.parse(deadlineAt) !== 1_680_000 ||
        Date.parse(recordedAt) < Date.parse(expiresAt) - 1_800_000 ||
        Date.parse(recordedAt) >= Date.parse(deadlineAt) ||
        parseDigest(review.displayDigest) !== digestContent(JSON.stringify(display)) ||
        review.renderedDisplay !== renderConfirmationDisplay(display)) {
      throw new ContractError('revocation.review', 'display, timing or review digest differs');
    }
    const issued = legacy ? display.issuedApproval : reviewDetail(display.detail).issuedApproval;
    if (JSON.stringify(issuedApprovalData(issued, legacy)) !== JSON.stringify(target)) {
      throw new ContractError('revocation.review', 'the displayed issued record differs from the revoked record');
    }
  }
  return { reference, recordedAt };
}
