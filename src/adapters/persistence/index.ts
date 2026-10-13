export { openRuntimeStore } from './sqlite-runtime-store.js';
export type { RuntimeStoreOptions, SqliteRuntimeStore, RuntimeStateInspection } from './sqlite-runtime-store.js';
export { resolveRuntimeState, runtimeStateExists } from './selection.js';
export type { RuntimeStateSelection } from './selection.js';
export { validateRuntimeSnapshot } from './sqlite-runtime-store.js';
export type { RuntimeSnapshot, RuntimeSnapshotInspection } from './sqlite-runtime-store.js';
export type { RuntimeLifecycleLease } from './lifecycle-lease.js';

import { openRuntimeStore } from './sqlite-runtime-store.js';
import { resolveRuntimeState } from './selection.js';
import { failure } from './failures.js';
import type { RuntimeStoreOptions } from './filesystem.js';
import type { SqliteRuntimeStore } from './sqlite-runtime-store.js';
import type { Outcome } from '../../kernel/outcomes.js';

export async function openWorkspaceRuntimeStore(
  options: Omit<RuntimeStoreOptions, 'directory' | 'workspaceRoot'> & { readonly workspaceRoot: string },
): Promise<Outcome<SqliteRuntimeStore>> {
  try {
    const selected = resolveRuntimeState(options.workspaceRoot, options.expectedWorkspace);
    return await openRuntimeStore({ ...options, directory: selected.directory });
  } catch (error) { return failure(error); }
}
