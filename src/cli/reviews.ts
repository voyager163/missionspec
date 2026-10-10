import { AdoptionService } from '../application/import.js';
import { ContextService } from '../application/context.js';
import { LocalConvergence } from '../application/convergence.js';
import { LocalLessons } from '../application/lessons.js';
import { LocalEvidencePruning } from '../application/evidence-pruning.js';
import { LocalWorkflow } from '../application/local-workflow.js';
import { WorkflowError } from '../application/errors.js';
import { requireApproval } from '../application/authority.js';
import { TerminalAuthority } from '../adapters/authority/terminal.js';
import { openWorkspaceRuntimeStore, runtimeStateExists, type SqliteRuntimeStore } from '../adapters/persistence/index.js';
import { parseApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { parseId, parseProjectPath } from '../kernel/identifiers.js';
import { parseDigest } from '../kernel/revisions.js';
import { record, oneOf, text } from '../kernel/validation.js';
import { type LocalCliOptions } from './local.js';

export const reviewCommands = ['adopt', 'context', 'convergence', 'lessons', 'evidence'] as const;

export async function runReviewCommand(args: readonly string[], options: LocalCliOptions): Promise<unknown> {
  const [command, action, subject] = args;
  const readonly = command === 'context' || command === 'convergence' && options.file === undefined ||
    command === 'lessons' && ['history', 'select'].includes(action ?? '') ||
    command === 'evidence' && ['status', 'pending'].includes(action ?? '');
  const permitted = command === 'adopt' ? ['file']
    : command === 'convergence' ? ['file']
      : command === 'lessons' ? ['file']
        : command === 'evidence' && action === 'prune' ? ['evidence'] : [];
  const common = readonly ? ['json', 'no-telemetry'] : ['json', 'no-telemetry', 'preview', 'approval'];
  if (Object.keys(options).some((key) => ![...common, ...permitted].includes(key))) {
    throw new WorkflowError('invalid-input', 'An option does not apply to this review command.');
  }
  const authority = await TerminalAuthority.open(process.cwd());
  let workflow = await LocalWorkflow.open(process.cwd(), { authority });
  let store: SqliteRuntimeStore | undefined;
  const count = (expected: number) => {
    if (args.length !== expected) throw new WorkflowError('invalid-input', 'Unexpected review arguments; use --help for the explicit command grammar.');
  };
  const input = async (): Promise<unknown> => {
    if (options.file === undefined) throw new WorkflowError('invalid-input', 'Select a workspace-relative JSON input with --file.');
    const file = await workflow.files.read(parseProjectPath(options.file));
    if (file === null) throw new WorkflowError('not-found', 'The review input file is absent.');
    try { return JSON.parse(file.content) as unknown; } catch {
      throw new WorkflowError('invalid-input', 'The review input must be valid JSON.');
    }
  };
  const confirm = async (request: ApprovalRequest, detail: Readonly<Record<string, unknown>>) => {
    if (options.approval !== undefined) {
      const reference = parseApprovalReference({ id: options.approval });
      await requireApproval(authority, reference, request, new Date().toISOString());
      return reference;
    }
    const response = await authority.requestConfirmation(request, detail);
    if (response.status !== 'ok' || response.value.state !== 'issued') throw new WorkflowError('authority-required', 'Current genuine local review is required; no planned effects were applied.');
    return response.value.approval.reference;
  };
  try {
    if (command === 'context') {
      count(2);
      if (action !== 'status') throw new WorkflowError('capability-unavailable', 'No external context adapter is configured in this CLI. Use context status; provider composition is an explicit library integration.');
      return await new ContextService(workflow, authority, null, { enabled: false, processing: 'local-only' }).inspect();
    }
    const identity = await workflow.files.identity();
    if (identity !== null &&
        await runtimeStateExists(workflow.files.root, identity)) {
      const opened = await openWorkspaceRuntimeStore({
        workspaceRoot: workflow.files.root, expectedWorkspace: identity,
        mode: readonly || options.preview ? 'read-only' : 'read-write',
      });
      if (opened.status !== 'ok') throw new WorkflowError('persistence-failed', 'The existing runtime ledger is unavailable; it will not be recreated.');
      store = opened.value;
      workflow = await LocalWorkflow.open(process.cwd(), { authority, store });
    }
    if (command === 'adopt') {
      count(1);
      const service = new AdoptionService(workflow);
      const preview = await service.preview(await input());
      if (options.preview) return preview;
      return await service.apply(preview, await confirm(preview.plan.request, { filePlan: preview.plan }));
    }
    if (command === 'convergence') {
      count(2);
      const service = new LocalConvergence(workflow, authority);
      if (readonly) return await service.current(action!);
      const review = await input();
      const preview = await service.preview(action!, review);
      if (options.preview) return preview;
      return await service.capture(action!, review, await confirm(preview.request, preview));
    }
    if (store === undefined) throw new WorkflowError('evidence-unavailable', 'An existing workspace runtime ledger is required; this command does not invent evidence.');
    if (command === 'lessons') {
      const service = new LocalLessons(workflow, authority, store);
      count(3);
      if (action === 'history') return await service.history(subject!);
      if (action === 'select') return await service.select(subject!, await input());
      const value = await input();
      if (action === 'capture') {
        const preview = await service.previewCapture(subject!, value);
        if (options.preview) return preview;
        return await service.capture(subject!, value, await confirm(preview.request, { lesson: preview }));
      }
      // The closed input below distinguishes evaluation from activation; neither is a capture shortcut.
      if (action === 'evaluate') {
        const selected = record(value, 'lessonEvaluation', ['lesson', 'version', 'mode']);
        const id = text(selected.lesson, 'lesson', 80);
        const version = parseDigest(selected.version);
        const mode = selected.mode === undefined ? 'evidence-review' : oneOf(selected.mode, ['evidence-review', 'semantic'], 'mode');
        const preview = await service.previewEvaluation(subject!, id, version, mode);
        if (options.preview) return preview;
        return await service.evaluate(subject!, id, version, await confirm(preview.request, { lesson: preview }), mode);
      }
      if (action === 'transition') {
        const selected = record(value, 'lessonTransition', ['lesson', 'transition']);
        const id = text(selected.lesson, 'lesson', 80);
        const preview = await service.previewTransition(subject!, id, selected.transition);
        if (options.preview) return preview;
        return await service.transition(subject!, id, selected.transition, await confirm(preview.request, { lesson: preview }));
      }
    }
    if (command === 'evidence') {
      const service = new LocalEvidencePruning(workflow, store, authority);
      if (action === 'pending') { count(2); return await service.pending(); }
      if (action === 'status') { count(3); return await service.status(parseDigest(subject)); }
      if (action === 'prune') {
        count(2);
        const preview = await service.preview((options.evidence ?? []).map((id) => parseId('evidence', id)));
        if (options.preview) return preview;
        return await service.commit(preview, await confirm(preview.request, { evidencePruning: preview }));
      }
      if (action === 'recover') {
        count(3);
        const preview = await service.previewRecovery(parseDigest(subject));
        if (options.preview || preview.state === 'pruned') return preview;
        return await service.recover(preview.id, await confirm(preview.request, { evidencePruning: preview }));
      }
    }
    throw new WorkflowError('invalid-input', 'Unsupported review command. Use --help.');
  } finally {
    if (store !== undefined && store.close().status !== 'ok') throw new WorkflowError('persistence-failed', 'The review ledger could not close safely.');
  }
}
