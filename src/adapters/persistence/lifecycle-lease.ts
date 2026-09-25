import { sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../../kernel/revisions.js';
import { WorkflowError } from '../../application/errors.js';

export interface RuntimeLifecycleLease {
  readonly kind: 'runtime-lifecycle-lease';
  readonly workspace: WorkspaceBinding;
  readonly snapshot: ContentDigest;
}
const active = new WeakSet<RuntimeLifecycleLease>();

/** Internal store composition: issued only while its validated exclusive SQLite transaction is held. */
export async function withRuntimeLifecycleLease<T>(
  workspace: WorkspaceBinding, snapshot: ContentDigest, operation: (lease: RuntimeLifecycleLease) => Promise<T>,
): Promise<T> {
  const lease: RuntimeLifecycleLease = Object.freeze({ kind: 'runtime-lifecycle-lease', workspace, snapshot });
  active.add(lease);
  try { return await operation(lease); } finally { active.delete(lease); }
}

export function requireRuntimeLifecycleLease(lease: RuntimeLifecycleLease | undefined, workspace: WorkspaceBinding): void {
  if (lease === undefined || !active.has(lease) || !sameWorkspaceBinding(lease.workspace, workspace)) {
    throw new WorkflowError('conflict', 'Runtime selection requires a live store-issued lifecycle lease, not a serialized claim.');
  }
}
