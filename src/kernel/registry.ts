import { oneOf } from './validation.js';

export const ENGINE_IDS = Object.freeze([
  'discovery', 'specification', 'planning', 'execution', 'verification', 'integration',
] as const);
export type EngineId = (typeof ENGINE_IDS)[number];

export const OPERATION_IDS = Object.freeze([
  'discover', 'draft', 'draft-all', 'implement', 'verify', 'archive',
  'revise', 'clarify', 'analyze', 'principles', 'sync', 'onboard',
] as const);
export type OperationId = (typeof OPERATION_IDS)[number];
export type OperationClass = 'primary' | 'supporting';
export type StopBoundary =
  | 'findings-or-authorized-capture'
  | 'one-ready-artifact'
  | 'required-drafts-or-review-blocker'
  | 'bounded-execution-or-pause'
  | 'evidence-and-gaps'
  | 'confirmed-closure'
  | 'reviewed-revision'
  | 'answers-or-unresolved-questions'
  | 'analysis-report'
  | 'reviewed-project-principles'
  | 'confirmed-promotion-change-open'
  | 'guidance-or-selected-handoff';

export interface OperationDescriptor {
  readonly id: OperationId;
  readonly nativeName: `missionspec-${OperationId}`;
  readonly class: OperationClass;
  readonly engines: readonly EngineId[];
  readonly installedByDefault: true;
  readonly defaultAccess: 'read-only' | 'authorization-required';
  readonly stop: StopBoundary;
}

function operation(
  id: OperationId,
  category: OperationClass,
  engines: readonly EngineId[],
  defaultAccess: OperationDescriptor['defaultAccess'],
  stop: StopBoundary,
): OperationDescriptor {
  return Object.freeze({
    id, nativeName: `missionspec-${id}`, class: category,
    engines: Object.freeze([...engines]), installedByDefault: true, defaultAccess, stop,
  });
}

export const OPERATIONS: Readonly<Record<OperationId, OperationDescriptor>> = Object.freeze({
  discover: operation('discover', 'primary', ['discovery'], 'read-only', 'findings-or-authorized-capture'),
  draft: operation('draft', 'primary', ['specification', 'planning'], 'authorization-required', 'one-ready-artifact'),
  'draft-all': operation('draft-all', 'primary', ['specification', 'planning'], 'authorization-required', 'required-drafts-or-review-blocker'),
  implement: operation('implement', 'primary', ['execution'], 'authorization-required', 'bounded-execution-or-pause'),
  verify: operation('verify', 'primary', ['verification'], 'authorization-required', 'evidence-and-gaps'),
  archive: operation('archive', 'primary', ['specification'], 'authorization-required', 'confirmed-closure'),
  revise: operation('revise', 'supporting', ['specification', 'planning'], 'authorization-required', 'reviewed-revision'),
  clarify: operation('clarify', 'supporting', ['discovery', 'specification'], 'read-only', 'answers-or-unresolved-questions'),
  analyze: operation('analyze', 'supporting', ['planning'], 'read-only', 'analysis-report'),
  principles: operation('principles', 'supporting', ['specification'], 'authorization-required', 'reviewed-project-principles'),
  sync: operation('sync', 'supporting', ['specification'], 'authorization-required', 'confirmed-promotion-change-open'),
  onboard: operation('onboard', 'supporting', ['integration'], 'read-only', 'guidance-or-selected-handoff'),
});

export interface EngineDescriptor {
  readonly id: EngineId;
  readonly operations: readonly OperationId[];
}

export const ENGINES: readonly EngineDescriptor[] = Object.freeze(ENGINE_IDS.map((id) =>
  Object.freeze({
    id,
    operations: Object.freeze(OPERATION_IDS.filter((operationId) => OPERATIONS[operationId].engines.includes(id))),
  }),
));

export function parseOperationId(value: unknown): OperationId {
  return oneOf(value, OPERATION_IDS, 'operation');
}

export function parseEngineId(value: unknown): EngineId {
  return oneOf(value, ENGINE_IDS, 'engine');
}

export function getOperation(value: unknown): OperationDescriptor {
  return OPERATIONS[parseOperationId(value)];
}
