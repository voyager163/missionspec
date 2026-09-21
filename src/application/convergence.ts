import { randomUUID } from 'node:crypto';
import { WorkflowError } from './errors.js';
import { requireApproval } from './authority.js';
import type { LocalWorkflow } from './local-workflow.js';
import type { LocalAuthorityPort } from '../ports/contracts.js';
import type { DocumentAnalysis } from '../engines/planning/contracts.js';
import {
  includeConvergence, parseConvergenceReview, proposedConvergenceRepairs, sameConvergenceInputs,
  validateConvergenceReferences, type ConvergenceReview, type VerificationReport,
} from '../engines/verification/contracts.js';
import { parseApprovalReference, parseApprovalRequest, type ApprovalReference } from '../kernel/authority.js';
import { digestEffectScope } from '../kernel/effects.js';
import { parseProjectPath } from '../kernel/identifiers.js';
import { digestContent } from '../kernel/revisions.js';
import { record, text } from '../kernel/validation.js';

export class LocalConvergence {
  constructor(private readonly workflow: LocalWorkflow, private readonly authority: LocalAuthorityPort) {}

  async preview(slug: string, value: unknown) {
    const review = parseConvergenceReview(value);
    const change = await this.workflow.loadChange(slug);
    if (!sameConvergenceInputs(review, change.revisions)) throw new WorkflowError('stale-revision', 'Convergence review must bind current intent and declared source.');
    validateConvergenceReferences(review, change.analysis);
    const sourceFiles = await Promise.all(change.metadata.sourcePaths.map(async (path) => ({
      path, digest: (await this.workflow.files.read(path))?.digest ?? 'absent',
    })));
    if (review.sourceFiles.length !== sourceFiles.length ||
        sourceFiles.some((file) => !review.sourceFiles.some((observed) => observed.path === file.path && observed.digest === file.digest))) {
      throw new WorkflowError('stale-revision', 'Review must observe the exact complete declared source-file inventory.');
    }
    for (const id of new Set(review.findings.flatMap((finding) => finding.evidence))) {
      const observation = await this.workflow.readObservation(id);
      if (observation.state !== 'observed' || !sameConvergenceInputs(review, observation.evidence.revisions) ||
          observation.evidence.source !== review.revisions.source) {
        throw new WorkflowError('evidence-unavailable', 'Convergence check references require retained, current, applicable evidence.');
      }
    }
    const previous = await this.current(slug);
    const subject = digestContent(JSON.stringify({ review, supersedes: previous?.id ?? null }));
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'verification', effects: [],
      binding: { kind: 'review', revisions: change.revisions, subject, effects: digestEffectScope([]) },
    });
    return {
      review, request, supersedes: previous?.id ?? null,
      proposedRepairs: proposedConvergenceRepairs(review, change.analysis),
      implementationStarted: false, testsExecuted: false, authorityIssued: false,
    };
  }

  async capture(slug: string, value: unknown, approval: ApprovalReference) {
    const preview = await this.preview(slug, value);
    await requireApproval(this.authority, approval, preview.request, new Date().toISOString());
    return this.workflow.files.withRuntimeLock(async () => {
      const fresh = await this.preview(slug, value);
      await requireApproval(this.authority, approval, fresh.request, new Date().toISOString());
      const id = `convergence-${randomUUID()}`;
      await this.workflow.files.recordRuntime('audit', id, {
        schemaVersion: 1, id, review: fresh.review, request: fresh.request,
        supersedes: fresh.supersedes, approval,
      });
      return { id, ...fresh };
    });
  }

  async current(slug: string): Promise<{ id: string; review: ConvergenceReview } | null> {
    const change = await this.workflow.loadChange(slug);
    const candidates = new Map<string, { id: string; review: ConvergenceReview; supersedes: string | null }>();
    for (const path of await this.workflow.files.list(parseProjectPath('.missionspec/audit'))) {
      if (!/\/convergence-[a-f0-9-]{36}\.json$/u.test(path)) continue;
      if (candidates.size >= 1024) throw new WorkflowError('limit-reached', 'Convergence history exceeds the bounded review inventory.');
      const file = await this.workflow.files.read(path);
      if (file === null) throw new WorkflowError('persistence-failed', 'Convergence history changed while reading.');
      const item = record(JSON.parse(file.content) as unknown, 'convergenceRecord', ['schemaVersion', 'id', 'review', 'request', 'supersedes', 'approval']);
      const id = text(item.id, 'convergenceRecord.id', 80);
      if (item.schemaVersion !== 1 || path !== `.missionspec/audit/${id}.json`) throw new WorkflowError('persistence-failed', 'Invalid convergence history identity.');
      const review = parseConvergenceReview(item.review);
      const request = parseApprovalRequest(item.request);
      parseApprovalReference(item.approval);
      const supersedes = item.supersedes === null ? null : text(item.supersedes, 'convergenceRecord.supersedes', 80);
      if (request.operation !== 'verify' || request.purpose !== 'verification' || request.effects.length !== 0 ||
          request.binding.kind !== 'review' || !sameConvergenceInputs(review, request.binding.revisions) ||
          request.binding.subject !== digestContent(JSON.stringify({ review, supersedes }))) {
        throw new WorkflowError('persistence-failed', 'Convergence history does not match its reviewed subject.');
      }
      if (review.revisions.changeId !== change.metadata.id) continue;
      candidates.set(id, { id, review, supersedes });
    }
    if (candidates.size === 0) return null;
    const superseded = new Set([...candidates.values()].flatMap((candidate) => candidate.supersedes === null ? [] : [candidate.supersedes]));
    if ([...superseded].some((id) => !candidates.has(id))) throw new WorkflowError('persistence-failed', 'Convergence review history is incomplete.');
    const heads = [...candidates.values()].filter((candidate) => !superseded.has(candidate.id));
    if (heads.length !== 1) throw new WorkflowError('conflict', 'Convergence review history has no unique current revision.');
    const seen = new Set<string>();
    let selected = heads[0];
    while (selected !== undefined) {
      if (seen.has(selected.id)) throw new WorkflowError('persistence-failed', 'Convergence history contains a cycle.');
      seen.add(selected.id);
      selected = selected.supersedes === null ? undefined : candidates.get(selected.supersedes);
    }
    if (seen.size !== candidates.size) throw new WorkflowError('persistence-failed', 'Convergence history is not one complete review chain.');
    return heads[0]!;
  }

  async include(slug: string, report: VerificationReport, analysis: DocumentAnalysis): Promise<VerificationReport> {
    const current = await this.current(slug);
    if (current === null) return report;
    if (!sameConvergenceInputs(current.review, report.revisions)) {
      return {
        ...report,
        acceptanceEligibility: {
          state: 'ineligible',
          reasons: [
            ...(report.acceptanceEligibility.state === 'ineligible' ? report.acceptanceEligibility.reasons : []),
            'A captured convergence review is stale; explicitly review current source before acceptance.',
          ],
        },
      };
    }
    return includeConvergence(report, current.review, analysis);
  }
}
