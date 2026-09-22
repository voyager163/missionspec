import { LocalWorkflow } from '../application/local-workflow.js';
import { SkillInstallation } from '../application/installation.js';
import { TerminalAuthority } from '../adapters/authority/terminal.js';
import { openWorkspaceRuntimeStore, runtimeStateExists, type SqliteRuntimeStore } from '../adapters/persistence/index.js';
import { loadPackagedSkillCatalog } from '../adapters/packaged-assets/skills.js';
import { NATIVE_HOSTS } from '../kernel/identifiers.js';
import { requireApproval } from '../application/authority.js';
import { parseApprovalReference } from '../kernel/authority.js';
import { WorkflowError } from '../application/errors.js';

export async function runSkillInstallation(action: string, values: {
  readonly host?: string | undefined; readonly hosts?: readonly string[] | undefined;
  readonly preview?: boolean | undefined; readonly approval?: string | undefined;
}, version: string) {
  if (!['inspect', 'install', 'update', 'remove'].includes(action) ||
      values.host !== undefined && values.hosts !== undefined ||
      action === 'inspect' && (values.preview !== undefined || values.approval !== undefined)) {
    throw new WorkflowError('invalid-input', 'Use skills inspect|install|update|remove with selected host(s).');
  }
  const hosts = values.host === undefined ? values.hosts ?? (action === 'inspect' ? NATIVE_HOSTS : []) : [values.host];
  if (hosts.length === 0) throw new WorkflowError('invalid-input', 'Choose --host <one> or repeat --hosts <host>; no host selection is implicit for effects.');
  const authority = await TerminalAuthority.open(process.cwd());
  let workflow = await LocalWorkflow.open(process.cwd(), { authority });
  let store: SqliteRuntimeStore | undefined;
  try {
    const workspace = await workflow.files.identity();
    if (workspace !== null && await runtimeStateExists(workflow.files.root, workspace)) {
      const result = await openWorkspaceRuntimeStore({ workspaceRoot: workflow.files.root,
        mode: values.preview || action === 'inspect' ? 'read-only' : 'read-write', expectedWorkspace: workspace });
      if (result.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot establish runtime quiescence for skill installation.');
      store = result.value;
      workflow = await LocalWorkflow.open(process.cwd(), { authority, store });
    }
    const installer = new SkillInstallation(workflow.files, await loadPackagedSkillCatalog(), version);
    if (action === 'inspect') return await installer.inspect(hosts);
    const preview = action === 'install' ? await installer.previewInstall(hosts, workspace === null ? await workflow.previewSetup() : undefined)
      : action === 'update' ? await installer.previewUpdate(hosts) : await installer.previewRemove(hosts);
    if (values.preview || preview.state === 'unchanged') return preview;
    if (preview.plan === null) throw new WorkflowError('conflict', 'Skill files are modified, missing or unowned. Inspect the preview; no files were overwritten or removed.');
    let approval;
    if (values.approval !== undefined) {
      approval = parseApprovalReference({ id: values.approval });
      await requireApproval(authority, approval, preview.plan.request, new Date().toISOString());
    } else {
      const result = await authority.confirmPlan(preview.plan);
      if (result.status !== 'ok' || result.value.state !== 'issued') throw new WorkflowError('authority-required', 'Skill installation requires genuine local terminal confirmation.');
      approval = result.value.approval.reference;
    }
    return await installer.apply(preview.plan, approval);
  } finally {
    if (store !== undefined && store.close().status !== 'ok') throw new WorkflowError('persistence-failed', 'Runtime ledger could not close safely.');
  }
}
