import { parseId, parseProjectPath, type ProjectPath } from '../../kernel/identifiers.js';
import { array, ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';
import { digestContent, parseDigest, parseRevisionBinding, sameRevisionBinding, type ContentDigest, type RevisionBinding } from '../../kernel/revisions.js';
import { parseTaskDefinition, type DocumentAnalysis, type TaskDefinition } from '../planning/contracts.js';
import type { GapFinding, VerificationReport } from './contracts.js';

export interface InspectedSource {
  readonly path: ProjectPath;
  readonly digest: ContentDigest | 'absent';
}

export interface ConvergenceFinding extends GapFinding {
  readonly basis: 'static-inspection' | 'agent-judgment';
  readonly observations: readonly InspectedSource[];
}

export interface ConvergenceReview {
  readonly schemaVersion: 1;
  readonly revisions: RevisionBinding;
  readonly sourceFiles: readonly InspectedSource[];
  readonly findings: readonly ConvergenceFinding[];
  readonly scope: 'declared-source-files-only';
}

function source(value: unknown): InspectedSource {
  const input = record(value, 'sourceObservation', ['path', 'digest']);
  return Object.freeze({ path: parseProjectPath(input.path), digest: input.digest === 'absent' ? 'absent' : parseDigest(input.digest) });
}

export function parseConvergenceReview(value: unknown): ConvergenceReview {
  const input = record(value, 'convergence', ['schemaVersion', 'revisions', 'sourceFiles', 'findings', 'scope']);
  if (input.schemaVersion !== 1 || input.scope !== 'declared-source-files-only') {
    throw new ContractError('convergence', 'unsupported review schema or source scope');
  }
  const sourceFiles = array(input.sourceFiles, 'sourceFiles', source, 1);
  unique(sourceFiles.map((file) => file.path), 'sourceFiles');
  const findings = array(input.findings, 'findings', (value): ConvergenceFinding => {
    const finding = record(value, 'finding', ['id', 'basis', 'severity', 'summary', 'paths', 'gap', 'requirements', 'tasks', 'evidence', 'observations']);
    const observations = array(finding.observations, 'finding.observations', source, 1);
    unique(observations.map((file) => file.path), 'finding.observations');
    const paths = unique(array(finding.paths, 'finding.paths', parseProjectPath, 1), 'finding.paths');
    if (paths.length !== observations.length || paths.some((path) => !observations.some((file) => file.path === path))) {
      throw new ContractError('finding.paths', 'every finding path requires an exact source observation');
    }
    for (const observation of observations) {
      if (!sourceFiles.some((file) => file.path === observation.path && file.digest === observation.digest)) {
        throw new ContractError('finding.observations', 'finding observations must match the declared review source inventory');
      }
    }
    return Object.freeze({
      id: parseId('finding', finding.id),
      basis: oneOf(finding.basis, ['static-inspection', 'agent-judgment'], 'finding.basis'),
      severity: oneOf(finding.severity, ['information', 'warning', 'blocking'], 'finding.severity'),
      summary: text(finding.summary, 'finding.summary', 4096),
      paths,
      gap: oneOf(finding.gap, ['missing', 'partial', 'contradictory', 'unrequested'], 'finding.gap'),
      requirements: unique(array(finding.requirements, 'finding.requirements', (id) => parseId('requirement', id)), 'finding.requirements'),
      tasks: unique(array(finding.tasks, 'finding.tasks', (id) => parseId('task', id)), 'finding.tasks'),
      evidence: unique(array(finding.evidence, 'finding.evidence', (id) => parseId('evidence', id)), 'finding.evidence'),
      observations,
    });
  });
  unique(findings.map((finding) => finding.id), 'findings');
  if (findings.length > 128 || sourceFiles.length > 128 || Buffer.byteLength(JSON.stringify(input)) > 1_000_000) {
    throw new ContractError('convergence', 'review exceeds its bounded inventory or payload');
  }
  return Object.freeze({
    schemaVersion: 1, revisions: parseRevisionBinding(input.revisions), sourceFiles,
    findings, scope: 'declared-source-files-only',
  });
}

export function sameConvergenceInputs(review: ConvergenceReview, current: RevisionBinding): boolean {
  // Review observations grant no effects; only the evidence-producing run owns that dimension.
  return sameRevisionBinding({ ...review.revisions, effects: current.effects }, current);
}

export function validateConvergenceReferences(review: ConvergenceReview, analysis: DocumentAnalysis): void {
  const requirements = new Set(analysis.tasks.flatMap((task) => task.requirements));
  for (const check of analysis.checks) for (const requirement of check.requirements) requirements.add(requirement);
  for (const finding of review.findings) {
    if (finding.requirements.some((id) => !requirements.has(id)) ||
        finding.tasks.some((id) => !analysis.tasks.some((task) => task.id === id))) {
      throw new ContractError('finding', 'finding references must resolve in the current requirement/task graph');
    }
    if (finding.gap !== 'unrequested' && finding.requirements.length === 0) {
      throw new ContractError('finding.requirements', 'behavior gaps must identify affected declared requirements');
    }
  }
}

export function proposedConvergenceRepairs(review: ConvergenceReview, analysis: DocumentAnalysis): readonly TaskDefinition[] {
  validateConvergenceReferences(review, analysis);
  return review.findings.filter((finding) => finding.severity !== 'information').map((finding) => {
    const related = analysis.tasks.filter((task) => finding.tasks.includes(task.id));
    const suffix = digestContent(JSON.stringify({ revisions: review.revisions, finding })).slice(7, 31);
    return parseTaskDefinition({
      contractVersion: 1, id: `TSK-repair-${suffix}`, title: `Review ${finding.gap}: ${finding.summary}`.slice(0, 240),
      dependsOn: [], requirements: finding.requirements,
      scenarios: [...new Set(related.flatMap((task) => task.scenarios))],
      checks: [...new Set(related.flatMap((task) => task.checks))], writeScope: finding.paths,
    });
  });
}

export function includeConvergence(
  report: VerificationReport,
  value: ConvergenceReview,
  analysis: DocumentAnalysis,
): VerificationReport {
  const review = parseConvergenceReview(value);
  if (!sameConvergenceInputs(review, report.revisions)) {
    throw new ContractError('convergence.revisions', 'source or intent changed; this review cannot clear or describe the current result');
  }
  validateConvergenceReferences(review, analysis);
  const evidence = new Set(report.observations.flatMap((observation) => observation.state === 'observed' ? [observation.evidence.id] : []));
  if (review.findings.some((finding) => finding.evidence.some((id) => !evidence.has(id)))) {
    throw new ContractError('finding.evidence', 'referenced check evidence must be present in this verification report');
  }
  const blockers = review.findings.filter((finding) => finding.severity === 'blocking');
  return {
    ...report,
    completeness: [...report.completeness, ...review.findings.filter((finding) => finding.gap === 'missing' || finding.gap === 'partial')],
    correctness: [...report.correctness, ...review.findings.filter((finding) => finding.gap === 'contradictory')],
    coherence: [...report.coherence, ...review.findings.filter((finding) => finding.gap === 'unrequested')],
    proposedRepairs: [...report.proposedRepairs, ...proposedConvergenceRepairs(review, analysis)],
    acceptanceEligibility: blockers.length === 0 ? report.acceptanceEligibility : {
      state: 'ineligible',
      reasons: [
        ...(report.acceptanceEligibility.state === 'ineligible' ? report.acceptanceEligibility.reasons : []),
        ...blockers.map((finding) => `Convergence review ${finding.id} remains blocking: ${finding.gap}.`),
      ],
    },
  };
}
