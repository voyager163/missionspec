import { parseApprovalReference, parseApprovalRequest, digestApprovalRequest, type ApprovalReference, type ApprovalRequest } from '../../../kernel/authority.js';
import { digestEffectScope } from '../../../kernel/effects.js';
import { parseChangeSlug, parseId, parseProjectPath, type ChangeId, type EvidenceId, type ProjectPath } from '../../../kernel/identifiers.js';
import { parseOperationId, type OperationId } from '../../../kernel/registry.js';
import {
  digestContent, parseDigest, parseRevisionBinding, parseWorkspaceBinding, sameRevisionBinding, sameWorkspaceBinding,
  type ContentDigest, type RevisionBinding, type WorkspaceBinding,
} from '../../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../../kernel/validation.js';

export interface LessonCandidate {
  readonly schemaVersion: 1;
  readonly lessonId: string;
  readonly title: string;
  readonly advice: string;
  readonly provenance: {
    readonly kind: 'human-observation' | 'agent-proposal';
    readonly rationale: string;
    readonly evidence: readonly EvidenceId[];
  };
  readonly applicability: {
    readonly changeId: ChangeId;
    readonly operations: readonly OperationId[];
    readonly sourcePaths: readonly ProjectPath[];
  };
}

export interface LessonGuard {
  readonly path: ProjectPath;
  readonly digest: ContentDigest | 'absent';
}

export interface LessonEvidence {
  readonly id: EvidenceId;
  readonly recordDigest: ContentDigest;
  readonly rawPath: ProjectPath;
  readonly rawDigest: ContentDigest;
  readonly basis: 'executed' | 'static-inspection' | 'agent-review';
  readonly result: 'passed' | 'failed';
}

export interface LessonVersion {
  readonly digest: ContentDigest;
  readonly candidate: LessonCandidate;
  readonly revisions: RevisionBinding;
  readonly guards: readonly LessonGuard[];
  readonly evidence: readonly LessonEvidence[];
}

export interface LessonEvaluation {
  readonly schemaVersion: 1;
  readonly mode: 'evidence-review';
  readonly version: ContentDigest;
  readonly state: 'ready-for-human-review';
  readonly observations: readonly LessonEvidence[];
  readonly semanticAssessment: 'unavailable';
  readonly acceptance: 'not-assessed';
  readonly benchmark: 'not-performed';
}

export type LessonTransition =
  | { readonly action: 'activate' | 'rollback'; readonly version: ContentDigest; readonly reason: string }
  | { readonly action: 'retire'; readonly reason: string };

export type LessonEvent =
  | { readonly kind: 'candidate-captured'; readonly version: LessonVersion }
  | { readonly kind: 'evaluated'; readonly evaluation: LessonEvaluation }
  | { readonly kind: 'activated' | 'retired' | 'rolled-back'; readonly version: ContentDigest; readonly reason: string };

export interface LessonHead {
  readonly id: string;
  readonly digest: ContentDigest;
}

export interface LessonAuditBody {
  readonly schemaVersion: 1;
  readonly lessonId: string;
  readonly workspace: WorkspaceBinding;
  readonly previous: LessonHead | null;
  readonly revisions: RevisionBinding;
  readonly guards: readonly LessonGuard[];
  readonly event: LessonEvent;
}

export interface LessonRecord {
  readonly schemaVersion: 1;
  readonly id: string;
  readonly body: LessonAuditBody;
  readonly request: ApprovalRequest;
  readonly approval: ApprovalReference;
  readonly recordedAt: string;
}

export interface LessonHistory {
  readonly lessonId: string;
  readonly head: LessonHead | null;
  readonly state: 'empty' | 'inactive' | 'active' | 'retired';
  readonly active: ContentDigest | null;
  readonly versions: readonly LessonVersion[];
  readonly evaluations: readonly LessonEvaluation[];
  readonly reviewedVersions: readonly ContentDigest[];
  readonly records: readonly LessonRecord[];
}

function bounded(value: unknown, limit: number, field: string): void {
  if (Buffer.byteLength(JSON.stringify(value)) > limit) throw new ContractError(field, 'bounded lesson payload exceeded');
}

export function parseLessonCandidate(value: unknown): LessonCandidate {
  const input = record(value, 'lesson', ['schemaVersion', 'lessonId', 'title', 'advice', 'provenance', 'applicability']);
  if (input.schemaVersion !== 1) throw new ContractError('lesson.schemaVersion', 'unsupported version');
  const provenance = record(input.provenance, 'lesson.provenance', ['kind', 'rationale', 'evidence']);
  const applicability = record(input.applicability, 'lesson.applicability', ['changeId', 'operations', 'sourcePaths']);
  const result: LessonCandidate = {
    schemaVersion: 1,
    lessonId: parseChangeSlug(input.lessonId),
    title: text(input.title, 'lesson.title', 240),
    advice: text(input.advice, 'lesson.advice', 16_384),
    provenance: {
      kind: oneOf(provenance.kind, ['human-observation', 'agent-proposal'], 'lesson.provenance.kind'),
      rationale: text(provenance.rationale, 'lesson.rationale', 4096),
      evidence: unique(array(provenance.evidence, 'lesson.evidence', (id) => parseId('evidence', id), 1), 'lesson.evidence'),
    },
    applicability: {
      changeId: parseId('change', applicability.changeId),
      operations: unique(array(applicability.operations, 'lesson.operations', parseOperationId, 1), 'lesson.operations'),
      sourcePaths: unique(array(applicability.sourcePaths, 'lesson.sourcePaths', parseProjectPath, 1), 'lesson.sourcePaths'),
    },
  };
  if (result.provenance.evidence.length > 128 || result.applicability.sourcePaths.length > 128) {
    throw new ContractError('lesson', 'at most 128 evidence references and source paths are supported');
  }
  bounded(result, 64_000, 'lesson');
  return Object.freeze(result);
}

export function parseLessonGuards(value: unknown): readonly LessonGuard[] {
  const guards = array(value, 'lesson.guards', (entry): LessonGuard => {
    const item = record(entry, 'lesson.guard', ['path', 'digest']);
    return { path: parseProjectPath(item.path), digest: item.digest === 'absent' ? 'absent' : parseDigest(item.digest) };
  }, 1);
  unique(guards.map((guard) => guard.path.toLowerCase()), 'lesson.guards');
  if (guards.length > 1024) throw new ContractError('lesson.guards', 'at most 1024 observations are supported');
  return Object.freeze([...guards].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function parseEvidence(value: unknown): LessonEvidence {
  const input = record(value, 'lesson.evidenceObservation', ['id', 'recordDigest', 'rawPath', 'rawDigest', 'basis', 'result']);
  return {
    id: parseId('evidence', input.id),
    recordDigest: parseDigest(input.recordDigest),
    rawPath: parseProjectPath(input.rawPath),
    rawDigest: parseDigest(input.rawDigest),
    basis: oneOf(input.basis, ['executed', 'static-inspection', 'agent-review'], 'lesson.evidence.basis'),
    result: oneOf(input.result, ['passed', 'failed'], 'lesson.evidence.result'),
  };
}

export function makeLessonVersion(value: {
  candidate: LessonCandidate; revisions: RevisionBinding; guards: readonly LessonGuard[]; evidence: readonly LessonEvidence[];
}): LessonVersion {
  const candidate = parseLessonCandidate(value.candidate);
  const revisions = parseRevisionBinding(value.revisions);
  const guards = parseLessonGuards(value.guards);
  const evidence = array(value.evidence, 'lesson.evidenceObservations', parseEvidence, 1);
  unique(evidence.map((item) => item.id), 'lesson.evidenceObservations');
  if (candidate.applicability.changeId !== revisions.changeId ||
      JSON.stringify(candidate.provenance.evidence) !== JSON.stringify(evidence.map((item) => item.id)) ||
      evidence.some((item) => !guards.some((guard) => guard.path === item.rawPath && guard.digest === item.rawDigest)) ||
      candidate.applicability.sourcePaths.some((path) => !guards.some((guard) => guard.path === path))) {
    throw new ContractError('lesson.version', 'candidate scope, evidence and exact observations must agree');
  }
  const material = { candidate, revisions, guards, evidence };
  bounded(material, 1_000_000, 'lesson.version');
  return { digest: digestContent(JSON.stringify(material)), ...material };
}

export function parseLessonVersion(value: unknown): LessonVersion {
  const input = record(value, 'lesson.version', ['digest', 'candidate', 'revisions', 'guards', 'evidence']);
  const version = makeLessonVersion({
    candidate: parseLessonCandidate(input.candidate), revisions: parseRevisionBinding(input.revisions),
    guards: parseLessonGuards(input.guards), evidence: array(input.evidence, 'lesson.evidence', parseEvidence),
  });
  if (version.digest !== parseDigest(input.digest)) throw new ContractError('lesson.version.digest', 'content does not match');
  return version;
}

export function evaluateLessonEvidence(version: LessonVersion): LessonEvaluation {
  const parsed = parseLessonVersion(version);
  return {
    schemaVersion: 1, mode: 'evidence-review', version: parsed.digest,
    state: 'ready-for-human-review', observations: parsed.evidence,
    semanticAssessment: 'unavailable', acceptance: 'not-assessed', benchmark: 'not-performed',
  };
}

function parseEvaluation(value: unknown): LessonEvaluation {
  const input = record(value, 'lesson.evaluation', [
    'schemaVersion', 'mode', 'version', 'state', 'observations', 'semanticAssessment', 'acceptance', 'benchmark',
  ]);
  if (input.schemaVersion !== 1 || input.mode !== 'evidence-review' || input.state !== 'ready-for-human-review' ||
      input.semanticAssessment !== 'unavailable' || input.acceptance !== 'not-assessed' || input.benchmark !== 'not-performed') {
    throw new ContractError('lesson.evaluation', 'only observed evidence review is supported; semantic and benchmark evaluation are unavailable');
  }
  return {
    schemaVersion: 1, mode: 'evidence-review', version: parseDigest(input.version), state: 'ready-for-human-review',
    observations: array(input.observations, 'lesson.evaluation.observations', parseEvidence, 1),
    semanticAssessment: 'unavailable', acceptance: 'not-assessed', benchmark: 'not-performed',
  };
}

export function parseLessonTransition(value: unknown): LessonTransition {
  const input = record(value, 'lesson.transition', ['action', 'version', 'reason']);
  const reason = text(input.reason, 'lesson.transition.reason', 4096);
  if (input.action === 'retire') {
    record(value, 'lesson.transition', ['action', 'reason']);
    return { action: 'retire', reason };
  }
  return { action: oneOf(input.action, ['activate', 'rollback'], 'lesson.transition.action'), version: parseDigest(input.version), reason };
}

function auditId(value: unknown): string {
  const id = text(value, 'lesson.auditId', 80);
  if (!/^lesson-[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(id)) {
    throw new ContractError('lesson.auditId', 'expected an immutable lesson audit identity');
  }
  return id;
}

function parseEvent(value: unknown): LessonEvent {
  const input = record(value, 'lesson.event', ['kind', 'version', 'evaluation', 'reason']);
  if (input.kind === 'candidate-captured') {
    record(value, 'lesson.event', ['kind', 'version']);
    return { kind: 'candidate-captured', version: parseLessonVersion(input.version) };
  }
  if (input.kind === 'evaluated') {
    record(value, 'lesson.event', ['kind', 'evaluation']);
    return { kind: 'evaluated', evaluation: parseEvaluation(input.evaluation) };
  }
  record(value, 'lesson.event', ['kind', 'version', 'reason']);
  return {
    kind: oneOf(input.kind, ['activated', 'retired', 'rolled-back'], 'lesson.event.kind'),
    version: parseDigest(input.version), reason: text(input.reason, 'lesson.event.reason', 4096),
  };
}

export function parseLessonAuditBody(value: unknown): LessonAuditBody {
  const input = record(value, 'lesson.audit', ['schemaVersion', 'lessonId', 'workspace', 'previous', 'revisions', 'guards', 'event']);
  if (input.schemaVersion !== 1) throw new ContractError('lesson.audit', 'unsupported version');
  const workspace = parseWorkspaceBinding(input.workspace);
  const revisions = parseRevisionBinding(input.revisions);
  if (!sameWorkspaceBinding(workspace, revisions.workspace)) throw new ContractError('lesson.audit.workspace', 'scope differs');
  const previous = input.previous === null ? null : record(input.previous, 'lesson.previous', ['id', 'digest']);
  const result: LessonAuditBody = {
    schemaVersion: 1, lessonId: parseChangeSlug(input.lessonId), workspace,
    previous: previous === null ? null : { id: auditId(previous.id), digest: parseDigest(previous.digest) },
    revisions, guards: parseLessonGuards(input.guards), event: parseEvent(input.event),
  };
  bounded(result, 2_000_000, 'lesson.audit');
  return result;
}

export function lessonApprovalRequest(value: LessonAuditBody): ApprovalRequest {
  const body = parseLessonAuditBody(value);
  return parseApprovalRequest({
    contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'verification', effects: [],
    binding: { kind: 'review', revisions: body.revisions, subject: digestContent(JSON.stringify(body)), effects: digestEffectScope([]) },
  });
}

export function parseLessonRecord(value: unknown): LessonRecord {
  const input = record(value, 'lesson.record', ['schemaVersion', 'id', 'body', 'request', 'approval', 'recordedAt']);
  if (input.schemaVersion !== 1) throw new ContractError('lesson.record', 'unsupported version');
  const body = parseLessonAuditBody(input.body);
  const request = parseApprovalRequest(input.request);
  if (digestApprovalRequest(request) !== digestApprovalRequest(lessonApprovalRequest(body))) {
    throw new ContractError('lesson.record.request', 'review subject or scope differs');
  }
  const recordedAt = text(input.recordedAt, 'lesson.recordedAt', 24);
  if (!Number.isFinite(Date.parse(recordedAt)) || new Date(recordedAt).toISOString() !== recordedAt) {
    throw new ContractError('lesson.recordedAt', 'expected a canonical UTC timestamp');
  }
  return {
    schemaVersion: 1, id: auditId(input.id), body, request,
    approval: parseApprovalReference(input.approval), recordedAt,
  };
}

export function sameLessonInputs(left: RevisionBinding, right: RevisionBinding): boolean {
  return sameRevisionBinding({ ...left, effects: right.effects }, right);
}

export function reduceLessonHistory(lessonId: string, entries: readonly { record: LessonRecord; digest: ContentDigest }[]): LessonHistory {
  const selectedId = parseChangeSlug(lessonId);
  const items = new Map(entries.map((entry) => [entry.record.id, entry]));
  unique(entries.map((entry) => entry.record.id), 'lesson.history');
  if (entries.length === 0) {
    return { lessonId: selectedId, head: null, state: 'empty', active: null, versions: [], evaluations: [], reviewedVersions: [], records: [] };
  }
  const predecessors = new Set<string>();
  for (const entry of entries) {
    if (entry.record.body.lessonId !== selectedId) throw new ContractError('lesson.history', 'mixed lesson identities');
    const previous = entry.record.body.previous;
    if (previous !== null) {
      if (items.get(previous.id)?.digest !== previous.digest) throw new ContractError('lesson.history', 'missing or changed predecessor');
      if (predecessors.has(previous.id)) throw new ContractError('lesson.history', 'branched history is not admitted');
      predecessors.add(previous.id);
    }
  }
  const heads = entries.filter((entry) => !predecessors.has(entry.record.id));
  if (heads.length !== 1) throw new ContractError('lesson.history', 'expected exactly one history head');
  const head = heads[0]!;
  const records: LessonRecord[] = [];
  let cursor: typeof head | undefined = head;
  const seen = new Set<string>();
  while (cursor !== undefined) {
    if (seen.has(cursor.record.id)) throw new ContractError('lesson.history', 'cycle');
    seen.add(cursor.record.id);
    records.unshift(cursor.record);
    cursor = cursor.record.body.previous === null ? undefined : items.get(cursor.record.body.previous.id);
  }
  if (records.length !== entries.length) throw new ContractError('lesson.history', 'disconnected records');
  const versions = new Map<ContentDigest, LessonVersion>();
  const evaluations = new Map<ContentDigest, LessonEvaluation>();
  const reviewed = new Set<ContentDigest>();
  let active: ContentDigest | null = null;
  let state: LessonHistory['state'] = 'inactive';
  for (const record of records) {
    const { event, revisions, guards } = record.body;
    if (event.kind === 'candidate-captured') {
      if (event.version.candidate.lessonId !== selectedId || versions.has(event.version.digest) ||
          !sameLessonInputs(event.version.revisions, revisions) || JSON.stringify(event.version.guards) !== JSON.stringify(guards)) {
        throw new ContractError('lesson.history', 'invalid or duplicate candidate version');
      }
      versions.set(event.version.digest, event.version);
      continue;
    }
    const digest = event.kind === 'evaluated' ? event.evaluation.version : event.version;
    const version = versions.get(digest);
    if (version === undefined) throw new ContractError('lesson.history', 'unknown candidate version');
    if (event.kind !== 'retired' && (!sameLessonInputs(version.revisions, revisions) ||
        JSON.stringify(version.guards) !== JSON.stringify(guards))) {
      throw new ContractError('lesson.history', 'review does not bind the exact captured inputs');
    }
    if (event.kind === 'evaluated') {
      if (JSON.stringify(event.evaluation) !== JSON.stringify(evaluateLessonEvidence(version))) {
        throw new ContractError('lesson.history', 'evaluation differs from captured evidence observations');
      }
      evaluations.set(digest, event.evaluation);
    } else if (event.kind === 'retired') {
      if (active !== digest) throw new ContractError('lesson.history', 'only the active version can be retired');
      active = null;
      state = 'retired';
    } else {
      if (!evaluations.has(digest) || active === digest ||
          (event.kind === 'activated' ? reviewed.has(digest) : !reviewed.has(digest))) {
        throw new ContractError('lesson.history', 'activation requires evaluation; rollback requires a previously reviewed version');
      }
      reviewed.add(digest);
      active = digest;
      state = 'active';
    }
  }
  return {
    lessonId: selectedId, head: { id: head.record.id, digest: head.digest }, state, active,
    versions: [...versions.values()], evaluations: [...evaluations.values()], reviewedVersions: [...reviewed], records,
  };
}

export function lessonApplies(candidate: LessonCandidate, context: {
  readonly changeId: ChangeId; readonly operation: OperationId; readonly paths: readonly ProjectPath[];
}): boolean {
  return candidate.applicability.changeId === context.changeId &&
    candidate.applicability.operations.includes(context.operation) && context.paths.length > 0 &&
    context.paths.every((path) => candidate.applicability.sourcePaths.includes(path));
}
