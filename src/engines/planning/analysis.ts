import { digestContent, type ContentDigest } from '../../kernel/revisions.js';
import type { MarkdownDocument, LocalQuestion } from '../specification/contracts.js';
import { orderTaskDefinitions, type CoverageGap, type PlannedCheck, type TaskDefinition } from './contracts.js';
import { assessClarifications } from '../discovery/contracts.js';

export interface DocumentAnalysis {
  readonly tasks: readonly TaskDefinition[];
  readonly checks: readonly PlannedCheck[];
  readonly coverage: readonly CoverageGap[];
  readonly clarificationBlockers: readonly string[];
  readonly artifactRevision: ContentDigest;
}

export function analyzeDocuments(documents: readonly MarkdownDocument[], questions: readonly LocalQuestion[] = []): DocumentAnalysis {
  const declarations = documents.flatMap((document) => document.declarations);
  const tasks = orderTaskDefinitions(declarations.filter((entry) => entry.kind === 'task').map((entry) => ({
    contractVersion: 1, id: entry.id, title: entry.title, dependsOn: entry.dependsOn,
    requirements: entry.requirements, scenarios: entry.scenarios, checks: entry.checks, writeScope: entry.writeScope,
  })));
  const checks: readonly PlannedCheck[] = declarations.filter((entry) => entry.kind === 'check').map((entry) => ({
    contractVersion: 1, id: entry.id, kind: entry.method, description: entry.title,
    definition: entry.intentRevision, requirements: entry.requirements, scenarios: entry.scenarios,
  }));
  const coverage: CoverageGap[] = [];
  for (const declaration of declarations) {
    if (declaration.kind === 'requirement' && declaration.operation !== 'remove') {
      if (!tasks.some((task) => task.requirements.includes(declaration.id))) coverage.push({ kind: 'unmapped-requirement', identity: declaration.id });
      if (!checks.some((check) => check.requirements.includes(declaration.id))) coverage.push({ kind: 'missing-check', identity: declaration.id });
    }
    if (declaration.kind === 'scenario' && declaration.operation !== 'remove') {
      if (!tasks.some((task) => task.scenarios.includes(declaration.id))) coverage.push({ kind: 'unmapped-scenario', identity: declaration.id });
      if (!checks.some((check) => check.scenarios.includes(declaration.id))) coverage.push({ kind: 'missing-check', identity: declaration.id });
    }
  }
  for (const task of tasks) {
    const mapped = checks.filter((check) => task.checks.includes(check.id));
    if (mapped.length === 0 ||
        task.requirements.some((id) => !mapped.some((check) => check.requirements.includes(id))) ||
        task.scenarios.some((id) => !mapped.some((check) => check.scenarios.includes(id)))) {
      coverage.push({ kind: 'missing-check', identity: task.id });
    }
  }
  const artifactRevision = digestContent(JSON.stringify(documents.map((document) => ({ path: document.path, digest: document.rawRevision })).sort((a, b) => a.path.localeCompare(b.path, 'en'))));
  const clarificationBlockers = assessClarifications(questions, artifactRevision).blockers;
  return { tasks, checks, coverage, artifactRevision, clarificationBlockers };
}
