// TEST ONLY namespace ordering driver: no workflow, approval, host or lock-recovery capability.
import {
  closeSync, constants, existsSync, fsyncSync, lstatSync, openSync, readFileSync,
  renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { syncWindowsPrivateDirectory, windowsPrivateEntries, WindowsDirectoryDurabilityError } from '../../dist/adapters/platform/windows-private-state.js';
import { observeWorkspaceRoot } from '../../dist/adapters/filesystem/local-workspace.js';
import { digestContent, parseWorkspaceBinding, sameWorkspaceBinding } from '../../dist/kernel/revisions.js';
import { fixtureFileSnapshot, FixtureSnapshotChangedError } from './filesystem-snapshot.mjs';

export const beforeSource = 'original source; namespace fixture only\n';
export const afterSource = 'reviewed replacement; namespace fixture only\n';
export const rawContent = 'retained raw bytes; namespace fixture only\n';
export const journalName = '.namespace-journal.json';
export const completionName = '.namespace-done.json';
const stageName = '.namespace-stage';

class ProtocolBlocked extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}

export function writePrivateFile(filename, content) {
  windowsPrivateEntries([{ path: filename, directory: false, writable: true, create: true }]);
  const descriptor = openSync(filename, constants.O_WRONLY | constants.O_NOFOLLOW);
  try {
    writeFileSync(descriptor, content);
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
}

function readOwned(filename, optional = false) {
  let entry;
  try { entry = lstatSync(filename, { bigint: true }); } catch (error) {
    if (optional && error.code === 'ENOENT') return null;
    throw error;
  }
  if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1n || entry.size > 100_000n) {
    throw new ProtocolBlocked('unsafe-file');
  }
  windowsPrivateEntries([{ path: filename, directory: false, writable: true }]);
  try {
    return fixtureFileSnapshot(filename, { maxBytes: 100_000, expected: entry }).bytes.toString('utf8');
  } catch (error) {
    if (error instanceof FixtureSnapshotChangedError) throw new ProtocolBlocked('stale-file');
    throw error;
  }
}

export async function runDirectoryProtocol(input) {
  const events = [];
  const root = input.root;
  const workspace = parseWorkspaceBinding(input.workspace);
  const identity = { dev: BigInt(input.identity.dev), ino: BigInt(input.identity.ino) };
  windowsPrivateEntries([{ path: root, directory: true, writable: true }]);
  const observed = await observeWorkspaceRoot(root);
  if (observed.root !== root || observed.rootDigest !== workspace.rootDigest) throw new ProtocolBlocked('workspace-mismatch');
  const scope = { workspaceId: workspace.workspaceId, rootDigest: observed.rootDigest };
  const checkRoot = async () => {
    if ((await observeWorkspaceRoot(root)).rootDigest !== workspace.rootDigest) throw new ProtocolBlocked('workspace-mismatch');
  };
  const barrier = (event) => {
    syncWindowsPrivateDirectory(root, identity);
    events.push(event);
  };
  const interrupt = (phase) => {
    if (input.stop === phase) {
      writeFileSync(1, JSON.stringify({ state: 'interrupted-test-worker', phase, events }));
      process.exit(77);
    }
  };
  const source = path.join(root, 'source.txt');
  const raw = path.join(root, 'raw.txt');
  const stage = path.join(root, stageName);
  const journal = path.join(root, journalName);
  const completion = path.join(root, completionName);
  const plan = {
    schemaVersion: 1, kind: 'test-only-namespace-ordering', workspace: scope,
    sourceBefore: digestContent(beforeSource), sourceAfter: digestContent(afterSource),
    rawBefore: digestContent(rawContent), sourceContent: afterSource,
  };
  const encoded = JSON.stringify(plan);
  const existing = readOwned(journal, true);
  if (existing !== null && (existing !== encoded || !sameWorkspaceBinding(JSON.parse(existing).workspace, scope))) {
    throw new ProtocolBlocked('journal-scope');
  }
  const done = readOwned(completion, true);
  const receipt = JSON.stringify({ kind: 'test-only-namespace-completion', workspace: scope, journal: digestContent(encoded) });
  if (done !== null) {
    if (existing === null || done !== receipt) throw new ProtocolBlocked('completion-scope');
    barrier('completion-directory-sync');
    return { state: 'already-complete-test-worker', events };
  }
  if (existing === null) {
    if (digestContent(readOwned(source)) !== plan.sourceBefore || digestContent(readOwned(raw)) !== plan.rawBefore) {
      throw new ProtocolBlocked('stale-preimage');
    }
    writePrivateFile(journal, encoded);
    events.push('journal-file-sync');
    interrupt('journal-file-sync');
  }
  await checkRoot();
  barrier('journal-directory-sync');
  interrupt('prepared');

  const sourceDigest = digestContent(readOwned(source));
  const retainedRaw = readOwned(raw, true);
  if (![plan.sourceBefore, plan.sourceAfter].includes(sourceDigest) ||
      (retainedRaw !== null && digestContent(retainedRaw) !== plan.rawBefore)) throw new ProtocolBlocked('stale-preimage');
  if (sourceDigest === plan.sourceBefore) {
    const oldStage = readOwned(stage, true);
    if (oldStage !== null && oldStage !== afterSource) throw new ProtocolBlocked('stale-stage');
    if (oldStage === null) writePrivateFile(stage, afterSource);
    barrier('stage-directory-sync');
    interrupt('staged');
    if (digestContent(readOwned(source)) !== plan.sourceBefore) throw new ProtocolBlocked('stale-preimage');
    renameSync(stage, source);
    events.push('source-renamed');
    interrupt('rename-before-barrier');
  }
  barrier('source-directory-sync');
  interrupt('replaced');
  const currentRaw = readOwned(raw, true);
  if (currentRaw !== null) {
    if (digestContent(currentRaw) !== plan.rawBefore) throw new ProtocolBlocked('stale-preimage');
    unlinkSync(raw);
    events.push('raw-unlinked');
    interrupt('unlink-before-barrier');
  }
  barrier('removal-directory-sync');
  interrupt('removed');
  await checkRoot();
  if (digestContent(readOwned(source)) !== plan.sourceAfter || existsSync(raw)) throw new ProtocolBlocked('stale-output');
  writePrivateFile(completion, receipt);
  events.push('completion-file-sync');
  interrupt('completion-file-sync');
  barrier('completion-directory-sync');
  return { state: 'complete-test-worker', events };
}

if (import.meta.main) {
  try {
    const input = JSON.parse(readFileSync(0, 'utf8'));
    process.stdout.write(JSON.stringify(await runDirectoryProtocol(input)));
  } catch (error) {
    process.stdout.write(JSON.stringify({
      state: 'blocked-test-worker',
      reason: error instanceof ProtocolBlocked ? error.reason
        : error instanceof WindowsDirectoryDurabilityError ? 'durability-unconfirmed' : 'fixture-io',
      detail: error instanceof WindowsDirectoryDurabilityError ? error.message : null,
    }));
    process.exitCode = 78;
  }
}
