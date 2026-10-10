import { randomUUID } from 'node:crypto';
import type { LocalWorkflow } from './local-workflow.js';
import { requireApproval } from './authority.js';
import { WorkflowError } from './errors.js';
import type { LocalAuthorityPort, RuntimeStorePort } from '../ports/contracts.js';
import { digestApprovalRequest, parseApprovalReference, type ApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { parseChangeSlug, parseProjectPath } from '../kernel/identifiers.js';
import { parseOperationId } from '../kernel/registry.js';
import { digestContent, parseDigest, sameWorkspaceBinding, type ContentDigest } from '../kernel/revisions.js';
import { array, ContractError, oneOf, record, unique } from '../kernel/validation.js';
import {
  evaluateLessonEvidence, lessonApplies, lessonApprovalRequest, makeLessonVersion, parseLessonAuditBody,
  parseLessonCandidate, parseLessonGuards, parseLessonRecord, parseLessonTransition, reduceLessonHistory,
  sameLessonInputs, type LessonAuditBody, type LessonCandidate, type LessonEvidence, type LessonGuard,
  type LessonHistory, type LessonRecord, type LessonVersion,
} from '../engines/verification/contracts.js';

export interface LessonPreview {
  readonly body: LessonAuditBody;
  readonly request: ApprovalRequest;
  readonly trust: 'untrusted-advice';
  readonly permissions: 'unchanged';
  readonly requirements: 'unchanged';
  readonly acceptanceCriteria: 'unchanged';
}

/** Private audit composition; none of these records issue authority or alter workflow requirements. */
export class LocalLessons {
  private readonly now: () => string;

  constructor(
    private readonly workflow: LocalWorkflow,
    private readonly authority: LocalAuthorityPort,
    private readonly store: RuntimeStorePort,
    options: { readonly now?: () => string } = {},
  ) {
    this.now = options.now ?? (() => new Date().toISOString());
  }

  private async records(): Promise<readonly { record: LessonRecord; digest: ContentDigest }[]> {
    const project = await this.workflow.project();
    if (project.state !== 'initialized') throw new WorkflowError('not-found', 'Initialize a local workspace before using lessons.');
    if (project.pendingTransactions.length !== 0) throw new WorkflowError('conflict', 'Pending file recovery blocks lesson use.');
    const entries = [];
    for (const path of await this.workflow.files.list(parseProjectPath('.missionspec/audit'))) {
      if (!path.split('/').at(-1)!.startsWith('lesson-')) continue;
      const file = await this.workflow.files.read(path);
      if (file === null) throw new WorkflowError('persistence-failed', 'Lesson history changed while being read.');
      try {
        const parsed = parseLessonRecord(JSON.parse(file.content) as unknown);
        if (path !== `.missionspec/audit/${parsed.id}.json` || JSON.stringify(parsed) !== file.content ||
            !sameWorkspaceBinding(parsed.body.workspace, project.workspace)) {
          throw new ContractError('lesson.history', 'record identity, canonical payload or workspace differs');
        }
        entries.push({ record: parsed, digest: file.digest });
      } catch {
        throw new WorkflowError('persistence-failed', 'Lesson history is malformed or belongs to another workspace; no repair is performed.');
      }
    }
    return entries;
  }

  async history(lessonId: string): Promise<LessonHistory> {
    const id = parseChangeSlug(lessonId);
    try {
      return reduceLessonHistory(id, (await this.records()).filter((entry) => entry.record.body.lessonId === id));
    } catch (error) {
      if (error instanceof ContractError) throw new WorkflowError('persistence-failed', 'Lesson history is not a complete immutable lifecycle.');
      throw error;
    }
  }

  private async quiescent(): Promise<void> {
    const runs = await this.store.listRuns();
    if (runs.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot establish runtime quiescence for lesson review.');
    if (runs.value.some((run) => run.quiescence !== 'confirmed' || run.state === 'running' || run.state === 'outcome-unknown')) {
      throw new WorkflowError('conflict', 'Active or unreconciled runs block lesson lifecycle writes and selection.');
    }
  }

  private async compare(guards: readonly LessonGuard[]): Promise<void> {
    for (const guard of guards) {
      if (((await this.workflow.files.read(guard.path))?.digest ?? 'absent') !== guard.digest) {
        throw new WorkflowError('stale-revision', 'A lesson input, declared source, or retained evidence file changed.');
      }
    }
  }

  private async observeVersion(slug: string, candidate: LessonCandidate): Promise<LessonVersion> {
    const change = await this.workflow.loadChange(slug);
    if (candidate.applicability.changeId !== change.metadata.id ||
        candidate.applicability.sourcePaths.some((path) => !change.metadata.sourcePaths.includes(path))) {
      throw new WorkflowError('scope-exceeded', 'Lesson applicability must use this exact change and its declared source paths.');
    }
    const guards = new Map(change.guards.map((guard) => [guard.path, guard.digest]));
    const evidence: LessonEvidence[] = [];
    for (const id of candidate.provenance.evidence) {
      const observation = await this.workflow.readObservation(id);
      if (observation.state !== 'observed' || observation.evidence.storage.state !== 'retained') {
        throw new WorkflowError('evidence-unavailable', 'Lesson provenance requires retained, observed evidence, not a claimed result.');
      }
      const item = observation.evidence;
      const storage = observation.evidence.storage;
      const check = change.analysis.checks.find((check) => check.id === item.checkId);
      if (!sameLessonInputs(item.revisions, change.revisions) || item.source !== change.revisions.source ||
          check?.definition !== item.checkDefinition) {
        throw new WorkflowError('stale-revision', 'Lesson evidence must match current intent, source and the declared check definition.');
      }
      if (storage.path !== `.missionspec/evidence/${id}.json`) {
        throw new WorkflowError('scope-exceeded', 'Lesson evidence must use the existing private immutable evidence area.');
      }
      const previous = guards.get(storage.path);
      if (previous !== undefined && previous !== storage.digest) throw new WorkflowError('stale-revision', 'Conflicting evidence observations.');
      guards.set(storage.path, storage.digest);
      evidence.push({
        id, recordDigest: digestContent(JSON.stringify(item)), rawPath: storage.path, rawDigest: storage.digest,
        basis: observation.basis, result: observation.result,
      });
    }
    const observed = parseLessonGuards([...guards].map(([path, digest]) => ({ path, digest })));
    await this.compare(observed);
    return makeLessonVersion({ candidate, revisions: change.revisions, guards: observed, evidence });
  }

  private async currentVersion(slug: string, history: LessonHistory, digest: ContentDigest): Promise<LessonVersion> {
    const version = history.versions.find((version) => version.digest === digest);
    if (version === undefined) throw new WorkflowError('not-found', 'The lesson candidate version is not in immutable history.');
    const current = await this.observeVersion(slug, version.candidate);
    if (current.digest !== version.digest) {
      throw new WorkflowError('stale-revision', 'This lesson version is stale; capture and review a new version instead of rebinding history.');
    }
    return current;
  }

  private preview(body: LessonAuditBody): LessonPreview {
    const parsed = parseLessonAuditBody(body);
    return {
      body: parsed, request: lessonApprovalRequest(parsed), trust: 'untrusted-advice',
      permissions: 'unchanged', requirements: 'unchanged', acceptanceCriteria: 'unchanged',
    };
  }

  async previewCapture(slug: string, input: unknown): Promise<LessonPreview & { readonly version: ContentDigest }> {
    const candidate = parseLessonCandidate(input);
    const version = await this.observeVersion(slug, candidate);
    const history = await this.history(candidate.lessonId);
    if (history.versions.some((entry) => entry.digest === version.digest)) {
      throw new WorkflowError('conflict', 'This immutable candidate version is already captured.');
    }
    return {
      ...this.preview({
        schemaVersion: 1, lessonId: candidate.lessonId, workspace: version.revisions.workspace,
        previous: history.head, revisions: version.revisions, guards: version.guards,
        event: { kind: 'candidate-captured', version },
      }),
      version: version.digest,
    };
  }

  async confirm(preview: LessonPreview): ReturnType<LocalAuthorityPort['requestConfirmation']> {
    const expected = lessonApprovalRequest(preview.body);
    if (digestApprovalRequest(expected) !== digestApprovalRequest(preview.request)) {
      throw new WorkflowError('scope-exceeded', 'Displayed lesson details do not match the confirmation request.');
    }
    return this.authority.requestConfirmation(expected, { lesson: this.preview(preview.body) });
  }

  private async commit(makePreview: () => Promise<LessonPreview>, approval: ApprovalReference) {
    const reference = parseApprovalReference(approval);
    const preview = await makePreview();
    await requireApproval(this.authority, reference, preview.request, this.now());
    return this.workflow.files.withRuntimeLock(async () => {
      await this.quiescent();
      const fresh = await makePreview();
      await requireApproval(this.authority, reference, fresh.request, this.now());
      await this.compare(fresh.body.guards);
      await requireApproval(this.authority, reference, fresh.request, this.now());
      await this.compare(fresh.body.guards);
      const id = `lesson-${randomUUID()}`;
      const record = parseLessonRecord({
        schemaVersion: 1, id, body: fresh.body, request: fresh.request, approval: reference, recordedAt: this.now(),
      });
      try {
        await this.workflow.files.recordRuntime('audit', id, record);
      } catch {
        throw new WorkflowError('effect-outcome-unknown', 'Lesson audit write could not be confirmed. Inspect immutable history before retrying.');
      }
      return { record, history: await this.history(fresh.body.lessonId) };
    });
  }

  async capture(slug: string, input: unknown, approval: ApprovalReference) {
    return this.commit(() => this.previewCapture(slug, input), approval);
  }

  async previewEvaluation(slug: string, lessonId: string, version: ContentDigest, mode: 'evidence-review' | 'semantic' = 'evidence-review') {
    if (oneOf(mode, ['evidence-review', 'semantic'], 'lesson.evaluation.mode') === 'semantic') {
      throw new WorkflowError('capability-unavailable', 'No qualified semantic lesson evaluator is configured; no benchmark or semantic success is fabricated.');
    }
    const history = await this.history(lessonId);
    const current = await this.currentVersion(slug, history, parseDigest(version));
    const evaluation = evaluateLessonEvidence(current);
    return {
      ...this.preview({
        schemaVersion: 1, lessonId: history.lessonId, workspace: current.revisions.workspace,
        previous: history.head, revisions: current.revisions, guards: current.guards,
        event: { kind: 'evaluated', evaluation },
      }),
      evaluation,
    };
  }

  async evaluate(slug: string, lessonId: string, version: ContentDigest, approval: ApprovalReference,
    mode: 'evidence-review' | 'semantic' = 'evidence-review') {
    return this.commit(() => this.previewEvaluation(slug, lessonId, version, mode), approval);
  }

  async previewTransition(slug: string, lessonId: string, input: unknown): Promise<LessonPreview> {
    const transition = parseLessonTransition(input);
    const history = await this.history(lessonId);
    if (transition.action === 'retire') {
      if (history.active === null) throw new WorkflowError('conflict', 'Only an active lesson can be retired.');
      const change = await this.workflow.loadChange(slug);
      const active = history.versions.find((version) => version.digest === history.active)!;
      if (active.candidate.applicability.changeId !== change.metadata.id) {
        throw new WorkflowError('scope-exceeded', 'Retirement must name the original change.');
      }
      return this.preview({
        schemaVersion: 1, lessonId: history.lessonId, workspace: change.workspace,
        previous: history.head, revisions: change.revisions, guards: change.guards,
        event: { kind: 'retired', version: history.active, reason: transition.reason },
      });
    }
    const version = await this.currentVersion(slug, history, transition.version);
    if (!history.evaluations.some((evaluation) => evaluation.version === version.digest)) {
      throw new WorkflowError('evidence-unavailable', 'Evaluate the captured evidence before requesting separate human activation review.');
    }
    if (history.active === version.digest || (transition.action === 'activate'
      ? history.reviewedVersions.includes(version.digest) : !history.reviewedVersions.includes(version.digest))) {
      throw new WorkflowError('conflict', 'Activation selects a new version; rollback explicitly selects a previously human-reviewed version.');
    }
    return this.preview({
      schemaVersion: 1, lessonId: history.lessonId, workspace: version.revisions.workspace,
      previous: history.head, revisions: version.revisions, guards: version.guards,
      event: {
        kind: transition.action === 'activate' ? 'activated' : 'rolled-back',
        version: version.digest, reason: transition.reason,
      },
    });
  }

  async transition(slug: string, lessonId: string, input: unknown, approval: ApprovalReference) {
    return this.commit(() => this.previewTransition(slug, lessonId, input), approval);
  }

  async select(slug: string, value: unknown) {
    const input = record(value, 'lesson.selection', ['operation', 'paths']);
    const operation = parseOperationId(input.operation);
    const paths = unique(array(input.paths, 'lesson.selection.paths', parseProjectPath, 1), 'lesson.selection.paths');
    if (paths.length > 128) throw new ContractError('lesson.selection.paths', 'at most 128 source paths are supported');
    await this.quiescent();
    const change = await this.workflow.loadChange(slug);
    if (paths.some((path) => !change.metadata.sourcePaths.includes(path))) {
      throw new WorkflowError('scope-exceeded', 'Lesson selection must name declared source paths only.');
    }
    const entries = await this.records();
    const lessons = [];
    const selectedGuards = new Map(change.guards.map((guard) => [guard.path, guard.digest]));
    const excluded: { lessonId: string; reason: 'inactive' | 'not-applicable' | 'stale' | 'evidence-unavailable' }[] = [];
    for (const id of new Set(entries.map((entry) => entry.record.body.lessonId))) {
      let history: LessonHistory;
      try { history = reduceLessonHistory(id, entries.filter((entry) => entry.record.body.lessonId === id)); } catch {
        throw new WorkflowError('persistence-failed', 'Lesson history is not a complete immutable lifecycle.');
      }
      if (history.active === null) { excluded.push({ lessonId: id, reason: 'inactive' }); continue; }
      const version = history.versions.find((item) => item.digest === history.active)!;
      if (!lessonApplies(version.candidate, { changeId: change.metadata.id, operation, paths })) {
        excluded.push({ lessonId: id, reason: 'not-applicable' });
        continue;
      }
      try {
        const current = await this.currentVersion(slug, history, version.digest);
        for (const guard of current.guards) {
          const previous = selectedGuards.get(guard.path);
          if (previous !== undefined && previous !== guard.digest) {
            throw new WorkflowError('stale-revision', 'Lesson selection contains conflicting current observations.');
          }
          selectedGuards.set(guard.path, guard.digest);
        }
        lessons.push({
          lessonId: id, version: current.digest, title: current.candidate.title, advice: current.candidate.advice,
          provenance: current.candidate.provenance, applicability: current.candidate.applicability,
          trust: 'untrusted-advice' as const,
        });
      } catch (error) {
        if (error instanceof WorkflowError && (error.code === 'stale-revision' || error.code === 'evidence-unavailable')) {
          excluded.push({ lessonId: id, reason: error.code === 'stale-revision' ? 'stale' : 'evidence-unavailable' });
        } else throw error;
      }
    }
    await this.compare([...selectedGuards].map(([path, digest]) => ({ path, digest })));
    const latest = await this.records();
    if (JSON.stringify(entries.map((entry) => [entry.record.id, entry.digest])) !==
        JSON.stringify(latest.map((entry) => [entry.record.id, entry.digest]))) {
      throw new WorkflowError('stale-revision', 'Lesson history changed during read-only selection; select again.');
    }
    return {
      trust: 'untrusted-advice' as const, lessons, excluded,
      permissions: 'unchanged' as const, requirements: 'unchanged' as const, acceptanceCriteria: 'unchanged' as const,
    };
  }
}
