import {
  digestApprovalRequest, parseApprovalReference, parseApprovalRequest,
  type LocalUserAssurance, type TrustedIssuedApproval,
} from '../kernel/authority.js';
import { parseDigest } from '../kernel/revisions.js';
import { ContractError, oneOf, record, text } from '../kernel/validation.js';

// Pure validation of data from an already trusted store/port. This does not issue authority.
export function approvalTimestamp(value: unknown, field: string): string {
  const result = text(value, field, 24);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(result)) {
    throw new ContractError(field, 'expected a UTC ISO timestamp');
  }
  const normalized = result.length === 20 ? result.replace(/Z$/u, '.000Z') : result;
  const date = new Date(result);
  if (!Number.isFinite(date.valueOf()) || date.toISOString() !== normalized) {
    throw new ContractError(field, 'expected a real calendar timestamp');
  }
  return result;
}

export function confirmationProtocol(value: unknown): LocalUserAssurance['protocolIdentity'] {
  const input = record(value, 'protocolIdentity', ['id', 'version']);
  const id = text(input.id, 'protocolIdentity.id', 128);
  const version = text(input.version, 'protocolIdentity.version', 64);
  if (!/^[a-z0-9][a-z0-9.@/_-]*$/u.test(id) || !/^[0-9A-Za-z][0-9A-Za-z.+_-]*$/u.test(version)) {
    throw new ContractError('protocolIdentity', 'expected bounded protocol identifiers, not an attestation or narrative');
  }
  return Object.freeze({ id, version });
}

export function localUserAssurance(value: unknown, allowLegacy = false): LocalUserAssurance {
  const input = record(value, 'assurance', [
    'kind', 'channel', 'protocolIdentity', 'qualification', 'humanPresence', 'organizationIdentity',
    ...(allowLegacy ? ['qualificationEvidence'] : []),
  ]);
  if (input.kind !== 'local-user') throw new ContractError('assurance.kind', 'only local-user assurance is supported');
  if (allowLegacy && Object.hasOwn(input, 'qualificationEvidence')) {
    record(value, 'legacyAssurance', ['kind', 'channel', 'qualificationEvidence']);
    const oldChannel = oneOf(input.channel, ['terminal-confirmation', 'qualified-host-callback'], 'legacyAssurance.channel');
    // Historical descriptive hashes are validated as data, discarded, and never interpreted as measured qualification.
    parseDigest(input.qualificationEvidence);
    return Object.freeze({
      kind: 'local-user', channel: oldChannel === 'terminal-confirmation' ? 'terminal-confirmation' : 'trusted-callback',
      protocolIdentity: Object.freeze({ id: oldChannel === 'terminal-confirmation' ? 'missionspec.legacy-terminal' : 'missionspec.legacy-callback', version: '1' }),
      qualification: Object.freeze({ state: 'not-established' }),
      humanPresence: 'not-attested', organizationIdentity: 'not-attested',
    });
  }
  const qualification = record(input.qualification, 'assurance.qualification', ['state']);
  if (qualification.state !== 'not-established' || input.humanPresence !== 'not-attested' || input.organizationIdentity !== 'not-attested') {
    throw new ContractError('assurance', 'implemented local protocols do not establish measured qualification, human presence or organization identity');
  }
  return Object.freeze({
    kind: 'local-user',
    channel: oneOf(input.channel, ['terminal-confirmation', 'mcp-elicitation', 'trusted-callback'], 'assurance.channel'),
    protocolIdentity: confirmationProtocol(input.protocolIdentity),
    qualification: Object.freeze({ state: 'not-established' }),
    humanPresence: 'not-attested', organizationIdentity: 'not-attested',
  });
}

export function issuedApprovalData(value: unknown, allowLegacy = false): TrustedIssuedApproval {
  const input = record(value, 'issuedApproval', [
    'contractVersion', 'state', 'reference', 'assurance', 'request', 'requestDigest', 'issuedAt', 'expiresAt',
  ]);
  if (input.contractVersion !== 1 || input.state !== 'trusted-issued') throw new ContractError('issuedApproval', 'unsupported issued approval record');
  const request = parseApprovalRequest(input.request);
  const requestDigest = parseDigest(input.requestDigest);
  const issuedAt = approvalTimestamp(input.issuedAt, 'issuedApproval.issuedAt');
  const expiresAt = approvalTimestamp(input.expiresAt, 'issuedApproval.expiresAt');
  if (digestApprovalRequest(request) !== requestDigest || Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new ContractError('issuedApproval', 'request digest or expiry ordering is invalid');
  }
  return Object.freeze({
    contractVersion: 1, state: 'trusted-issued', reference: parseApprovalReference(input.reference),
    assurance: localUserAssurance(input.assurance, allowLegacy), request, requestDigest, issuedAt, expiresAt,
  });
}
