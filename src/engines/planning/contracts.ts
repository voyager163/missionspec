import {
  parseId, parseProjectPath, type CheckId, type ProjectPath, type RequirementId, type ScenarioId, type TaskId,
} from '../../kernel/identifiers.js';
import type { Finding, Outcome } from '../../kernel/outcomes.js';
import { parseContractVersion, type Versioned } from '../../kernel/protocol.js';
import { parseDigest, type ContentDigest, type RevisionBinding } from '../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../kernel/validation.js';
import type { ArtifactAssessment, ArtifactNodeId, ChangeSnapshot } from '../specification/contracts.js';

export * from './artifacts/index.js';
export * from './analysis.js';

export interface TaskDefinition extends Versioned {
  readonly id: TaskId;
  readonly title: string;
  readonly dependsOn: readonly TaskId[];
  readonly requirements: readonly RequirementId[];
  readonly scenarios: readonly ScenarioId[];
  readonly checks: readonly CheckId[];
  readonly writeScope: readonly ProjectPath[];
}

export function parseTaskDefinition(value: unknown): TaskDefinition {
  const input = record(value, 'task', [
    'contractVersion', 'id', 'title', 'dependsOn', 'requirements', 'scenarios', 'checks', 'writeScope',
  ]);
  const id = parseId('task', input.id);
  const dependsOn = unique(array(input.dependsOn, 'task.dependsOn', (entry) => parseId('task', entry)), 'task.dependsOn');
  if (dependsOn.includes(id)) {
    throw new ContractError('task.dependsOn', 'a task cannot depend on itself');
  }
  return Object.freeze({
    contractVersion: parseContractVersion(input.contractVersion),
    id,
    title: text(input.title, 'task.title', 240),
    dependsOn,
    requirements: unique(array(input.requirements, 'task.requirements', (entry) => parseId('requirement', entry)), 'task.requirements'),
    scenarios: unique(array(input.scenarios, 'task.scenarios', (entry) => parseId('scenario', entry)), 'task.scenarios'),
    checks: unique(array(input.checks, 'task.checks', (entry) => parseId('check', entry)), 'task.checks'),
    writeScope: unique(array(input.writeScope, 'task.writeScope', parseProjectPath), 'task.writeScope'),
  });
}

export function orderTaskDefinitions(value: unknown): readonly TaskDefinition[] {
  const tasks = array(value, 'tasks', parseTaskDefinition);
  unique(tasks.map((task) => task.id), 'tasks');
  const byId = new Map(tasks.map((task) => [task.id, task]));
  const dependents = new Map<TaskId, TaskId[]>();
  const remaining = new Map<TaskId, number>();
  for (const task of tasks) {
    remaining.set(task.id, task.dependsOn.length);
    for (const dependency of task.dependsOn) {
      if (!byId.has(dependency)) {
        throw new ContractError('task.dependsOn', 'dependency does not exist in the supplied task set');
      }
      const list = dependents.get(dependency) ?? [];
      list.push(task.id);
      dependents.set(dependency, list);
    }
  }
  const ready = tasks.filter((task) => task.dependsOn.length === 0);
  const ordered: TaskDefinition[] = [];
  for (let index = 0; index < ready.length; index += 1) {
    const task = ready[index];
    if (task === undefined) {
      throw new ContractError('tasks', 'invalid task queue');
    }
    ordered.push(task);
    for (const id of dependents.get(task.id) ?? []) {
      const count = remaining.get(id);
      const dependent = byId.get(id);
      if (count === undefined || dependent === undefined) {
        throw new ContractError('tasks', 'invalid task dependency');
      }
      remaining.set(id, count - 1);
      if (count === 1) {
        ready.push(dependent);
      }
    }
  }
  if (ordered.length !== tasks.length) {
    throw new ContractError('tasks', 'dependency cycle');
  }
  return Object.freeze(ordered);
}

export interface PlannedCheck extends Versioned {
  readonly id: CheckId;
  readonly kind: 'executed' | 'static-inspection' | 'agent-review';
  readonly description: string;
  readonly definition: ContentDigest;
  readonly requirements: readonly RequirementId[];
  readonly scenarios: readonly ScenarioId[];
}

export function parsePlannedCheck(value: unknown): PlannedCheck {
  const input = record(value, 'check', [
    'contractVersion', 'id', 'kind', 'description', 'definition', 'requirements', 'scenarios',
  ]);
  return Object.freeze({
    contractVersion: parseContractVersion(input.contractVersion),
    id: parseId('check', input.id),
    kind: oneOf(input.kind, ['executed', 'static-inspection', 'agent-review'], 'check.kind'),
    description: text(input.description, 'check.description'),
    definition: parseDigest(input.definition),
    requirements: unique(array(input.requirements, 'check.requirements', (id) => parseId('requirement', id)), 'check.requirements'),
    scenarios: unique(array(input.scenarios, 'check.scenarios', (id) => parseId('scenario', id)), 'check.scenarios'),
  });
}

export interface ArtifactNode {
  readonly id: ArtifactNodeId;
  readonly dependsOn: readonly ArtifactNodeId[];
  readonly applicability:
    | { readonly state: 'required' }
    | { readonly state: 'not-applicable'; readonly reason: string; readonly sourceRevision: ContentDigest };
  readonly declaredOutputs: readonly ProjectPath[];
}

export interface CoverageGap {
  readonly kind: 'unmapped-requirement' | 'unmapped-scenario' | 'missing-check' | 'unknown-reference';
  readonly identity: RequirementId | ScenarioId | TaskId | CheckId;
}

export interface PlanningReport extends Versioned {
  readonly revisions: RevisionBinding;
  readonly artifacts: readonly ArtifactAssessment[];
  readonly coverage: readonly CoverageGap[];
  readonly structuralFindings: readonly Finding[];
  readonly semanticFindings: readonly Finding[];
  readonly readiness: 'blocked' | 'ready-for-implementation-review';
}

export interface PlanningOperations {
  analyze(snapshot: ChangeSnapshot): Promise<Outcome<PlanningReport>>;
  selectNextArtifact(input: {
    readonly snapshot: ChangeSnapshot;
    readonly graph: readonly ArtifactNode[];
    readonly selected: ArtifactNodeId | null;
  }): Outcome<
    | { readonly state: 'ready'; readonly node: ArtifactNode }
    | { readonly state: 'selection-required'; readonly candidates: readonly ArtifactNodeId[] }
    | { readonly state: 'all-current' }
    | { readonly state: 'blocked'; readonly reasons: readonly string[] }
  >;
}
