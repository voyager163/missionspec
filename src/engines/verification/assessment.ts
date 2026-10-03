import { parseId } from '../../kernel/identifiers.js';
import { parseRevisionBinding, sameRevisionBinding, type RevisionBinding } from '../../kernel/revisions.js';
import type { DocumentAnalysis } from '../planning/contracts.js';
import type { CheckObservation, GapFinding, VerificationReport } from './contracts.js';

export function assessVerification(input: {
  readonly revisions: RevisionBinding; readonly analysis: DocumentAnalysis;
  readonly structurallyReady: boolean; readonly observations: readonly CheckObservation[];
}): VerificationReport {
  const revisions = parseRevisionBinding(input.revisions);
  const reasons: string[] = [];
  const completeness: GapFinding[] = [];
  const correctness: GapFinding[] = [];
  const failedChecks = new Set<string>();
  const gap = (summary: string): void => {
    reasons.push(summary);
    completeness.push({
      id: parseId('finding', `FND-gap-${completeness.length + 1}`), basis: 'structural-validation', severity: 'blocking',
      summary, paths: [], gap: 'missing', requirements: [], tasks: [], evidence: [],
    });
  };
  if (!input.structurallyReady) gap('Required artifacts are missing, stale or invalid.');
  if (input.analysis.coverage.length > 0) gap('Requirement, scenario, task or check coverage is incomplete.');
  if (input.analysis.clarificationBlockers.length > 0) gap('Blocking clarification is unresolved, assumed or stale.');
  if (input.analysis.checks.length === 0) gap('No planned checks are available.');
  const observations: CheckObservation[] = input.analysis.checks.map((check) => {
    const candidates = input.observations.filter((observation) => observation.checkId === check.id);
    const observation = candidates[0];
    if (candidates.length !== 1 || observation === undefined) {
      gap('A planned check has no unique recorded observation.');
      return { state: 'missing', checkId: check.id, reason: 'No unique retained check observation.' };
    }
    if (observation.state !== 'observed') {
      gap('A planned check lacks applicable evidence.');
      return observation;
    }
    const evidence = observation.evidence;
    if (!sameRevisionBinding(evidence.revisions, revisions) || evidence.source !== revisions.source ||
        evidence.checkId !== check.id || evidence.checkDefinition !== check.definition ||
        evidence.storage.state !== 'retained' || observation.basis !== check.kind) {
      gap('A check observation is stale, unavailable or bound to a different method.');
      return { state: 'stale', checkId: check.id, reason: 'Check definition, source, scope, basis or retained evidence differs.' };
    }
    if (observation.result !== 'passed') {
      reasons.push('A recorded check failed.');
      failedChecks.add(check.id);
      correctness.push({
        id: parseId('finding', `FND-check-${correctness.length + 1}`),
        basis: check.kind === 'executed' ? 'executed-check' : check.kind === 'static-inspection' ? 'static-inspection' : 'agent-judgment',
        severity: 'blocking', summary: 'A recorded check failed; review its retained output before proposing scoped repairs.',
        paths: [], gap: 'contradictory', requirements: check.requirements,
        tasks: input.analysis.tasks.filter((task) => task.checks.includes(check.id)).map((task) => task.id),
        evidence: [evidence.id],
      });
    }
    return observation;
  });
  if (input.observations.some((observation) => !input.analysis.checks.some((check) => check.id === observation.checkId))) {
    gap('The observation set contains an unplanned check.');
  }
  const evidence = observations.flatMap((observation) => observation.state === 'observed' ? [observation.evidence.id] : []);
  if (new Set(evidence).size !== evidence.length) gap('Evidence cannot stand in for multiple independent check observations.');
  return {
    contractVersion: 1, revisions, source: revisions.source, observations,
    completeness, correctness, coherence: [],
    proposedRepairs: input.analysis.tasks.filter((task) => task.checks.some((id) => failedChecks.has(id))),
    acceptanceEligibility: reasons.length === 0
      ? { state: 'eligible-for-human-review', evidence }
      : { state: 'ineligible', reasons },
  };
}
