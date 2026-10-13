import { isAlias, parseDocument, visit } from 'yaml';
import { digestContent, type ContentDigest } from '../../../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../../../kernel/validation.js';
import {
  parseArtifactNodeId, type ArtifactNodeId, type DocumentKind, type WorkflowProfile,
} from '../../specification/contracts.js';
import { graphOrder } from './graph.js';

export interface ArtifactWorkflowNode {
  readonly id: ArtifactNodeId;
  readonly kind: Extract<DocumentKind, 'proposal' | 'specs' | 'design' | 'tasks'>;
  readonly dependsOn: readonly ArtifactNodeId[];
  readonly outputMode: 'single' | 'declared-set' | 'task-set';
  readonly skip: 'never' | 'explicit';
  readonly additionalSections: readonly 'Design'[];
}

export interface ArtifactWorkflow {
  readonly schemaVersion: 1;
  readonly profile: WorkflowProfile;
  readonly source: string;
  readonly revision: ContentDigest;
  readonly nodes: readonly ArtifactWorkflowNode[];
  readonly order: readonly ArtifactNodeId[];
  readonly targets: readonly ArtifactNodeId[];
}

export function parseWorkflowProfile(value: unknown = undefined): WorkflowProfile {
  return value === undefined ? 'standard' : oneOf(value, ['standard', 'compact'], 'workflow.profile');
}

function yaml(source: string): unknown {
  try {
    const document = parseDocument(source, { strict: true, uniqueKeys: true, version: '1.2' });
    if (document.errors.length > 0 || document.warnings.length > 0) {
      throw new ContractError('workflow', 'invalid YAML');
    }
    visit(document, {
      Node(_key, node) {
        if (isAlias(node) || ('anchor' in node && node.anchor) || ('tag' in node && node.tag)) {
          throw new ContractError('workflow', 'tags and aliases are unsupported');
        }
      },
    });
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    return value;
  } catch {
    throw new ContractError('workflow', 'expected declarative YAML without duplicate keys, tags or aliases');
  }
}

export function parseArtifactWorkflow(value: unknown): ArtifactWorkflow {
  const source = text(value, 'workflow.source', 64_000);
  const input = record(yaml(source), 'workflow', ['schemaVersion', 'profile', 'nodes', 'targets']);
  if (input.schemaVersion !== 1) throw new ContractError('workflow.schemaVersion', 'unsupported workflow version');
  const profile = oneOf(input.profile, ['standard', 'compact'], 'workflow.profile');
  const nodes = array(input.nodes, 'workflow.nodes', (entry): ArtifactWorkflowNode => {
    const node = record(entry, 'workflow.node', ['id', 'kind', 'dependsOn', 'outputMode', 'skip', 'additionalSections']);
    return Object.freeze({
      id: parseArtifactNodeId(node.id),
      kind: oneOf(node.kind, ['proposal', 'specs', 'design', 'tasks'], 'workflow.node.kind'),
      dependsOn: unique(array(node.dependsOn, 'workflow.node.dependsOn', parseArtifactNodeId), 'workflow.node.dependsOn'),
      outputMode: oneOf(node.outputMode, ['single', 'declared-set', 'task-set'], 'workflow.node.outputMode'),
      skip: oneOf(node.skip, ['never', 'explicit'], 'workflow.node.skip'),
      additionalSections: unique(array(node.additionalSections, 'workflow.node.additionalSections',
        (section) => oneOf(section, ['Design'], 'workflow.node.additionalSections')), 'workflow.node.additionalSections'),
    });
  }, 1);
  const order = graphOrder(nodes);
  const targets = unique(array(input.targets, 'workflow.targets', parseArtifactNodeId, 1), 'workflow.targets');
  if (targets.some((target) => !order.includes(target))) throw new ContractError('workflow.targets', 'target is not a workflow node');
  const expectedDependencies: Readonly<Record<string, readonly string[]>> = {
    proposal: [], specs: ['proposal'], design: ['proposal'], tasks: ['specs', 'design'],
  };
  if (nodes.length !== 4 || !['proposal', 'specs', 'design', 'tasks'].every((id) => nodes.some((node) => node.id === id))) {
    throw new ContractError('workflow.nodes', 'version 1 supports the four declared Standard/Compact artifact nodes');
  }
  for (const node of nodes) {
    const expected = expectedDependencies[node.id];
    if (expected === undefined || node.kind !== node.id ||
      node.dependsOn.length !== expected.length || expected.some((id) => !node.dependsOn.includes(parseArtifactNodeId(id))) ||
      node.outputMode !== (node.id === 'specs' ? 'declared-set' : node.id === 'tasks' ? 'task-set' : 'single') ||
      node.skip !== (node.id === 'design' ? 'explicit' : 'never')) {
      throw new ContractError('workflow.node', 'built-in artifact semantics cannot be weakened');
    }
    const needsDesign = profile === 'compact' && node.id === 'tasks';
    if (node.additionalSections.length !== (needsDesign ? 1 : 0) ||
      (needsDesign && node.additionalSections[0] !== 'Design')) {
      throw new ContractError('workflow.node.additionalSections', 'Compact task artifacts include the combined Design section');
    }
  }
  if (targets.length !== 1 || targets[0] !== 'tasks') throw new ContractError('workflow.targets', 'the built-in required closure ends at tasks');
  return Object.freeze({
    schemaVersion: 1, profile, source, revision: digestContent(source), nodes, order, targets,
  });
}

export function dependencyClosure(workflow: ArtifactWorkflow, targets: readonly ArtifactNodeId[]): readonly ArtifactNodeId[] {
  const byId = new Map(workflow.nodes.map((node) => [node.id, node]));
  const required = new Set<ArtifactNodeId>();
  const pending = [...targets];
  for (let index = 0; index < pending.length; index += 1) {
    const id = pending[index];
    if (id === undefined || required.has(id)) continue;
    const node = byId.get(id);
    if (node === undefined) throw new ContractError('targets', 'unknown artifact target');
    required.add(id);
    pending.push(...node.dependsOn);
  }
  return Object.freeze(workflow.order.filter((id) => required.has(id)));
}

export function artifactDependencyClosure(
  workflowSource: unknown, targets: unknown = undefined,
): readonly ArtifactNodeId[] {
  const workflow = parseArtifactWorkflow(workflowSource);
  const selected = targets === undefined ? workflow.targets :
    unique(array(targets, 'targets', parseArtifactNodeId, 1), 'targets');
  return dependencyClosure(workflow, selected);
}
