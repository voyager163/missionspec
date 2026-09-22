import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { digestContent, parseDigest, parseWorkspaceBinding, sameWorkspaceBinding, type ContentDigest, type WorkspaceBinding } from '../../kernel/revisions.js';
import { record, text } from '../../kernel/validation.js';
import { checkPrivatePath, parseOptions } from './filesystem.js';
import { StoreFailure } from './failures.js';
import { readPrivateStateFile } from './lifecycle-files.js';

export const runtimeSelectionPath = '.missionspec/runtime-selection.json';

export interface RuntimeStateSelection {
  readonly directory: string;
  readonly workspaceRoot: string;
  readonly revision: ContentDigest | 'absent';
  readonly kind: 'default' | 'external';
}

function checkSelectionHistory(root: string, workspace: WorkspaceBinding, revision: ContentDigest, directory: string, generation: ContentDigest): void {
  const history = path.join(root, '.missionspec/recovery');
  let entries: string[];
  try { entries = readdirSync(history).filter((name) => /^selection-generation-[a-f0-9]{64}\.json$/u.test(name)); }
  catch (error) {
    if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') entries = [];
    else throw error;
  }
  const successors = new Map<ContentDigest | 'absent', ContentDigest>();
  for (const name of entries) {
    const item = record(JSON.parse(readPrivateStateFile(path.join(history, name), 16_384)) as unknown,
      'selectionHistory', ['schemaVersion', 'workspace', 'before', 'after', 'generation']);
    if (item.schemaVersion !== 1 || !sameWorkspaceBinding(parseWorkspaceBinding(item.workspace), workspace) ||
        name !== `selection-generation-${parseDigest(item.generation).slice(7)}.json`) {
      throw new StoreFailure('corrupt', 'Runtime selection history is foreign or malformed.');
    }
    const before = item.before === 'absent' ? 'absent' : parseDigest(item.before);
    if (successors.has(before)) throw new StoreFailure('corrupt', 'Runtime selection history contains competing activations.');
    successors.set(before, parseDigest(item.after));
  }
  let head: ContentDigest | 'absent' = 'absent';
  const visited = new Set<string>();
  while (successors.has(head)) {
    if (visited.has(head)) throw new StoreFailure('corrupt', 'Runtime selection history is cyclic.');
    visited.add(head);
    head = successors.get(head)!;
  }
  if (visited.size !== successors.size) throw new StoreFailure('corrupt', 'Runtime selection history is disconnected.');
  if (revision === head) return;
  // Publication precedes its completion receipt. Only its exact prepared successor is admissible.
  const prepared = record(JSON.parse(readPrivateStateFile(path.join(history, `selection-${generation.slice(7)}.json`), 16_384)) as unknown,
    'selectionStage', ['schemaVersion', 'workspace', 'sourceSelection', 'sourceDirectory', 'directory', 'snapshot', 'id']);
  if (prepared.schemaVersion !== 1 || prepared.sourceSelection !== head || prepared.id !== generation ||
      prepared.directory !== directory || !sameWorkspaceBinding(parseWorkspaceBinding(prepared.workspace), workspace)) {
    throw new StoreFailure('stale-revision', 'Runtime selector was rolled back or diverges from preserved activation history.');
  }
}

export function resolveRuntimeState(workspaceRoot: string, workspace: WorkspaceBinding): RuntimeStateSelection {
  const canonical = path.join(workspaceRoot, '.missionspec', 'state');
  parseOptions({ directory: canonical, expectedWorkspace: workspace, mode: 'read-only' });
  const filename = path.join(workspaceRoot, runtimeSelectionPath);
  let descriptor: number;
  try {
    lstatSync(filename);
    checkPrivatePath(filename, false);
    descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') {
      try {
        lstatSync(path.join(workspaceRoot, '.missionspec/recovery/selection-established.json'));
        throw new StoreFailure('missing', 'Runtime selection is missing after explicit activation; automatic fallback to an older ledger is forbidden.');
      } catch (markerError) {
        if (typeof markerError !== 'object' || markerError === null || Reflect.get(markerError, 'code') !== 'ENOENT') throw markerError;
      }
      return { directory: canonical, workspaceRoot, revision: 'absent', kind: 'default' };
    }
    throw error;
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (before.size > 16_384n) throw new StoreFailure('corrupt', 'Runtime selection exceeds its bounded format.');
    const bytes = Buffer.alloc(Number(before.size) + 1);
    const size = readSync(descriptor, bytes, 0, bytes.length, 0);
    const after = lstatSync(filename, { bigint: true });
    if (BigInt(size) !== before.size || after.ino !== before.ino || after.dev !== before.dev ||
        after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
      throw new StoreFailure('stale-revision', 'Runtime selection changed while being observed.');
    }
    const content = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size));
    const selected = record(JSON.parse(content) as unknown, 'runtimeSelection', ['schemaVersion', 'workspace', 'directory', 'generation']);
    if (selected.schemaVersion !== 1 || !sameWorkspaceBinding(parseWorkspaceBinding(selected.workspace), workspace)) {
      throw new StoreFailure('workspace-mismatch', 'Runtime selection has an unsupported or foreign workspace binding.');
    }
    const generation = parseDigest(selected.generation);
    const directory = text(selected.directory, 'runtimeSelection.directory', 4096);
    parseOptions({ directory, expectedWorkspace: workspace, mode: 'read-only' });
    const revision = digestContent(content);
    checkSelectionHistory(workspaceRoot, workspace, revision, directory, generation);
    return { directory, workspaceRoot, revision, kind: directory === canonical ? 'default' : 'external' };
  } finally { closeSync(descriptor); }
}

/** A missing selected external ledger is an error, never a fallback to a stale local copy. */
export async function runtimeStateExists(workspaceRoot: string, workspace: WorkspaceBinding | null): Promise<boolean> {
  if (workspace === null) {
    for (const relative of [runtimeSelectionPath, '.missionspec/state/ledger.sqlite', '.missionspec/recovery/selection-established.json']) {
      try { lstatSync(path.join(workspaceRoot, relative)); }
      catch (error) {
        if (typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') continue;
        throw error;
      }
      throw new StoreFailure('workspace-mismatch', 'Existing runtime state cannot be ignored or adopted without its independent workspace identity.');
    }
    return false;
  }
  const selection = resolveRuntimeState(workspaceRoot, workspace);
  try { lstatSync(path.join(selection.directory, 'ledger.sqlite')); return true; }
  catch (error) {
    if (selection.revision === 'absent' && typeof error === 'object' && error !== null && Reflect.get(error, 'code') === 'ENOENT') return false;
    throw new StoreFailure('missing', 'The explicitly selected runtime store is missing; no fallback or recreation is allowed.');
  }
}
