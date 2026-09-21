// TEST ONLY fault boundaries around the real application and real filesystem/SQLite operations.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { windowsPrivateEntries } from '../../dist/adapters/platform/windows-private-state.js';

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let replacedStage = false;
if (input.mode === 'file-exit') {
  const unlink = fs.unlinkSync;
  fs.unlinkSync = (filename, ...args) => {
    const result = unlink(filename, ...args);
    if (/\.msn-[a-f0-9-]{36}$/u.test(String(filename))) process.exit(74);
    return result;
  };
} else if (['journal-sync-failure', 'stage-exit', 'recovery-stage-replace'].includes(input.mode)) {
  const open = fsp.open;
  fsp.open = async (filename, ...args) => {
    const handle = await open(filename, ...args);
    if (input.mode === 'journal-sync-failure' && /[\\/]transactions[\\/][a-f0-9-]{36}\.json$/u.test(String(filename)) &&
        (args[0] & fs.constants.O_WRONLY) !== 0) {
      const sync = handle.sync.bind(handle);
      handle.sync = async () => { await handle.close(); return sync(); };
    } else if (input.mode === 'stage-exit' && /\.msn-[a-f0-9-]{36}$/u.test(String(filename)) &&
        (args[0] & fs.constants.O_WRONLY) !== 0) {
      const close = handle.close.bind(handle);
      handle.close = async () => { await close(); process.exit(74); };
    } else if (input.mode === 'recovery-stage-replace' && String(filename) === input.stage && !replacedStage) {
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
} else if (input.mode === 'prune-delete-exit') {
  const unlink = fs.unlinkSync;
  fs.unlinkSync = (filename, ...args) => {
    const result = unlink(filename, ...args);
    if (/[\\/]evidence[\\/]EVD-[^\\/]+\.json$/u.test(String(filename))) process.exit(75);
    return result;
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
