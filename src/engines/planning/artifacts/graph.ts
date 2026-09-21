import { ContractError } from '../../../kernel/validation.js';

export function graphOrder<T extends string>(
  nodes: readonly { readonly id: T; readonly dependsOn: readonly T[] }[],
): readonly T[] {
  const ids = new Set(nodes.map((node) => node.id));
  if (ids.size !== nodes.length) throw new ContractError('graph', 'duplicate node identity');
  const indegree = new Map<T, number>();
  const dependents = new Map<T, T[]>();
  for (const node of nodes) {
    indegree.set(node.id, node.dependsOn.length);
    for (const dependency of node.dependsOn) {
      if (!ids.has(dependency)) throw new ContractError('graph', 'missing dependency');
      if (dependency === node.id) throw new ContractError('graph', 'self dependency');
      const list = dependents.get(dependency) ?? [];
      list.push(node.id);
      dependents.set(dependency, list);
    }
  }
  const order = nodes.filter((node) => node.dependsOn.length === 0).map((node) => node.id);
  for (let index = 0; index < order.length; index += 1) {
    const id = order[index];
    if (id === undefined) continue;
    for (const dependent of dependents.get(id) ?? []) {
      const remaining = indegree.get(dependent);
      if (remaining === undefined) throw new ContractError('graph', 'invalid dependency');
      indegree.set(dependent, remaining - 1);
      if (remaining === 1) order.push(dependent);
    }
  }
  if (order.length !== nodes.length) throw new ContractError('graph', 'dependency cycle');
  return Object.freeze(order);
}
