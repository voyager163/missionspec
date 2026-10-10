import { LocalRuntimeState } from '../application/runtime-state.js';
import { WorkflowError } from '../application/errors.js';
import { TerminalAuthority } from '../adapters/authority/terminal.js';
import { parseApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { parseDigest } from '../kernel/revisions.js';
import { text } from '../kernel/validation.js';

export async function runStateCommand(
  positionals: readonly string[], values: Readonly<Record<string, unknown>>,
): Promise<unknown> {
  const action = positionals[1];
  const readonly = action === 'status' || action === 'migrate' && values.file === undefined;
  const permitted = readonly ? ['json', 'no-telemetry', ...(action === 'migrate' ? ['preview'] : [])]
    : ['json', 'no-telemetry', 'preview', 'approval', ...(['stage', 'restore', 'migrate'].includes(action ?? '') ? ['file'] : [])];
  if (Object.keys(values).some((key) => !permitted.includes(key)) ||
      !['status', 'backup', 'stage', 'restore', 'select', 'activate', 'recover', 'migrate'].includes(action ?? '') ||
      positionals.length !== (action === 'recover' ? 4 : ['select', 'activate'].includes(action ?? '') || action === 'migrate' && values.file !== undefined ? 3 : 2)) {
    throw new WorkflowError('invalid-input', 'Use state status|backup|migrate, state stage|restore --file <private-backup>, or state select <absolute-directory> / activate <stage-id>.');
  }
  const authority = await TerminalAuthority.open(process.cwd());
  const service = await LocalRuntimeState.open(process.cwd(), { authority });
  if (action === 'status') return service.status();
  if (action === 'migrate' && values.file === undefined) return service.migrationPolicy();
  const confirm = async (request: ApprovalRequest, detail: Readonly<Record<string, unknown>>) => {
    if (values.approval !== undefined) return parseApprovalReference({ id: values.approval });
    const response = await authority.requestConfirmation(request, detail);
    if (response.status !== 'ok' || response.value.state !== 'issued') throw new WorkflowError('authority-required', 'State lifecycle effects require current exact local confirmation.');
    return response.value.approval.reference;
  };
  if (action === 'recover') {
    const id = parseDigest(positionals[2]);
    const transaction = text(positionals[3], 'state.transaction', 80);
    const plan = await service.previewActivationRecovery(id, transaction);
    if (values.preview) return plan;
    return service.recoverActivation(id, transaction, await confirm(plan.request, { plan }));
  }
  if (action === 'activate') {
    const id = parseDigest(positionals[2]);
    const plan = await service.previewActivation(id);
    if (values.preview) return plan;
    return service.activate(id, plan, await confirm(plan.request, { plan }));
  }
  if (action === 'select') {
    const preview = await service.previewSelection(text(positionals[2], 'state.directory', 4096));
    if (values.preview) return preview;
    return service.prepareSelection(preview, await confirm(preview.request, { preview }));
  }
  if (action === 'backup') {
    const preview = await service.previewBackup();
    if (values.preview) return preview;
    return service.backup(preview, await confirm(preview.request, { preview }));
  }
  const backup = await service.readBackup(text(values.file, 'state.file', 4096));
  if (action === 'migrate') {
    const preview = await service.previewMigration(backup, text(positionals[2], 'state.directory', 4096));
    if (values.preview) return preview;
    return service.migrate(backup, preview, await confirm(preview.request, { preview }));
  }
  const preview = action === 'stage' ? await service.previewStage(backup) : await service.previewRestore(backup);
  if (values.preview) return preview;
  const approval = await confirm(preview.request, { preview });
  return action === 'stage' ? service.stage(backup, preview, approval) : service.restore(backup, preview, approval);
}
