// TEST ONLY fault boundaries around the real application and real filesystem/SQLite operations.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { windowsPrivateEntries } from '../../dist/adapters/platform/windows-private-state.js';

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let replacedStage = false;
if (['file-exit', 'stage-exit', 'journal-sync-failure', 'prune-delete-exit'].includes(input.mode)) {
  const spawn = childProcess.spawnSync;
  childProcess.spawnSync = (program, args, options) => {
    let operation;
    try { operation = JSON.parse(String(options?.input).split('\n')[0]).operation; } catch { /* Not a native operation request. */ }
    if (input.mode === 'journal-sync-failure' && operation?.kind === 'create' &&
        /[\\/]transactions[\\/][a-f0-9-]{36}\.json$/u.test(operation.path)) {
      // Cancel after the real write, before the native file-flush acknowledgement.
      return spawn(program, args, { ...options, input: `${JSON.stringify({ operation })}\ncontinue\n` });
    }
    const result = spawn(program, args, options);
    if (result.status === 0 && input.mode === 'file-exit' && operation?.kind === 'publish') process.exit(74);
    if (result.status === 0 && input.mode === 'stage-exit' && operation?.kind === 'create' &&
        /\.msn-[a-f0-9-]{36}$/u.test(operation.path)) process.exit(74);
    if (result.status === 0 && input.mode === 'prune-delete-exit' && operation?.kind === 'delete' &&
        /[\\/]evidence[\\/]EVD-[^\\/]+\.json$/u.test(operation.path)) process.exit(75);
    return result;
  };
} else if (input.mode === 'recovery-stage-replace') {
  const open = fsp.open;
  fsp.open = async (filename, ...args) => {
    const handle = await open(filename, ...args);
    if (String(filename) === input.stage && !replacedStage) {
      const close = handle.close.bind(handle);
      handle.close = async () => {
        await close();
        if (replacedStage) return;
        replacedStage = true;
        fs.renameSync(input.stage, `${input.stage}.saved`);
        windowsPrivateEntries([{ path: input.stage, directory: false, writable: true, create: true }]);
        fs.writeFileSync(input.stage, input.stageContent);
      };
    }
    return handle;
  };
}
syncBuiltinESMExports();

const { LocalWorkflow } = await import('../../dist/application/local-workflow.js');
const { openLocalAuthority } = await import('../../dist/adapters/authority/local-authority.js');
const authority = await openLocalAuthority({ directory: input.root });

if (input.mode.startsWith('prune-')) {
  const { openRuntimeStore } = await import('../../dist/adapters/persistence/index.js');
  const { LocalEvidencePruning } = await import('../../dist/application/evidence-pruning.js');
  const opened = await openRuntimeStore({
    directory: path.join(input.root, '.missionspec', 'state'), mode: 'read-write',
    expectedWorkspace: input.preview.plan.inventory.workspace,
  });
  if (opened.status !== 'ok') throw new Error(JSON.stringify(opened));
  const store = opened.value;
  const capability = Object.freeze({
    ...store.evidencePruning,
    async prepareEvidencePrune(record) {
      const result = await store.evidencePruning.prepareEvidencePrune(record);
      if (input.mode === 'prune-prepare-exit' && result.status === 'ok') process.exit(75);
      return result;
    },
  });
  const injectedStore = new Proxy(store, {
    get(target, key) {
      if (key === 'evidencePruning') return capability;
      const member = Reflect.get(target, key);
      return typeof member === 'function' ? member.bind(target) : member;
    },
  });
  const workflow = await LocalWorkflow.open(input.root, { authority, store: injectedStore });
  const pruning = new LocalEvidencePruning(workflow, injectedStore, authority);
  try { await pruning.commit(input.preview, input.approval); } finally { store.close(); }
  throw new Error('Expected application interruption was not reached');
}

const workflow = await LocalWorkflow.open(input.root, { authority });
try {
  if (input.mode === 'recovery-stage-replace') await workflow.files.recover(input.transactionId, input.approval);
  else await workflow.apply(input.plan, input.approval);
  throw new Error('Expected application interruption was not reached');
} catch (error) {
  if (!['journal-sync-failure', 'recovery-stage-replace'].includes(input.mode) || error.code !== 'effect-outcome-unknown') throw error;
  fs.writeFileSync(1, JSON.stringify({ code: error.code, replacedStage }));
}
