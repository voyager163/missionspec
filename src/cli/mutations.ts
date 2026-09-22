import { randomUUID } from 'node:crypto';
import { LocalWorkflow } from '../application/local-workflow.js';
import { TerminalAuthority } from '../adapters/authority/terminal.js';
import { LocalChecks, type LocalCheckInput } from '../adapters/authority/local-checks.js';
import { openWorkspaceRuntimeStore, runtimeStateExists, type SqliteRuntimeStore } from '../adapters/persistence/index.js';
import { parseId, parseProjectPath } from '../kernel/identifiers.js';
import { parseApprovalReference, type ApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { requireApproval } from '../application/authority.js';
import { WorkflowError } from '../application/errors.js';
import { oneOf } from '../kernel/validation.js';
import { parseFilePlan, type FilePlan } from '../adapters/filesystem/local-workspace.js';
import type { LocalCliOptions } from './local.js';
import type { LocalQuestion } from '../engines/specification/contracts.js';
import type { BoundedProposal } from '../ports/contracts.js';

export async function runMutation(
  positionals: readonly string[], values: LocalCliOptions,
  previewCommand: (positionals: readonly string[], values: LocalCliOptions) => Promise<unknown>,
): Promise<unknown> {
  const [command, slug] = positionals;
  const permitted: Readonly<Record<string, readonly string[]>> = {
    init: ['profile'], change: ['profile', 'spec', 'source', 'verification-plan'], draft: ['artifact'], capture: ['artifact'], revise: ['artifact'],
    'draft-all': [], recover: [], applicability: ['reason', 'required'], approval: [], discover: ['file'], principles: ['file'], clarify: ['file'],
    check: ['file'], collect: ['registration', 'run'], accept: ['run', 'evidence'],
    patch: ['file', 'task', 'run', 'evidence'],
    sync: ['run', 'evidence', 'acceptance'], archive: ['run', 'evidence', 'acceptance', 'outcome'],
  };
  if (Object.keys(values).some((key) => !['json', 'no-telemetry', 'preview', 'approval', ...(permitted[command ?? ''] ?? [])].includes(key))) {
    throw new WorkflowError('invalid-input', 'An option does not apply to this local operation.');
  }
  const authority = await TerminalAuthority.open(process.cwd());
  let workflow = await LocalWorkflow.open(process.cwd(), { authority });
  let store: SqliteRuntimeStore | undefined;
  const openStore = async (create: boolean) => {
    if (store !== undefined) return;
    const workspace = await workflow.files.identity();
    if (workspace === null) throw new WorkflowError('not-found', 'Initialize this workspace first.');
    const exists = await runtimeStateExists(workflow.files.root, workspace);
    if (!exists && !create) return;
    const result = await openWorkspaceRuntimeStore({ workspaceRoot: workflow.files.root, mode: exists ? (values.preview ? 'read-only' : 'read-write') : 'create', expectedWorkspace: workspace });
    if (result.status !== 'ok') throw new WorkflowError('persistence-failed', 'The workspace ledger is unavailable; no success can be recorded.');
    store = result.value;
    workflow = await LocalWorkflow.open(process.cwd(), { authority, store });
  };
  const confirm = async (request: ApprovalRequest, detail: Readonly<Record<string, unknown>>, plan?: FilePlan): Promise<ApprovalReference> => {
    if (values.approval !== undefined) {
      const reference = parseApprovalReference({ id: values.approval });
      await requireApproval(authority, reference, request, new Date().toISOString());
      return reference;
    }
    const result = plan === undefined ? await authority.requestConfirmation(request, detail) : await authority.confirmPlan(plan);
    if (result.status !== 'ok' || result.value.state !== 'issued') throw new WorkflowError('authority-required', 'A genuine local terminal confirmation is required; noninteractive inputs cannot approve.');
    return result.value.approval.reference;
  };
  try {
    if (command !== 'init') await openStore(false);
    if (command === 'approval') {
      if (positionals.length !== 3 || !['show', 'revoke'].includes(slug ?? '') || values.preview !== undefined) throw new WorkflowError('invalid-input', 'Use approval show|revoke <APR-id>.');
      const reference = parseApprovalReference({ id: positionals[2] });
      if (slug === 'show') return await authority.resolve(reference);
      await authority.revoke(reference);
      return { state: 'revoked', reference };
    }
    if (slug === undefined && !['init', 'principles'].includes(command ?? '')) throw new WorkflowError('invalid-input', 'Select an explicit change or transaction.');
    if (command === 'patch') {
      if (positionals.length !== 2 || values.file === undefined || values.task === undefined ||
          values.run === undefined && values.evidence !== undefined) throw new WorkflowError('invalid-input', 'Use patch <slug> --task <TSK-id> --file <inert-proposal.json>; predecessor evidence also requires --run.');
      const file = await workflow.files.read(parseProjectPath(values.file));
      if (file === null) throw new WorkflowError('not-found', 'The inert proposal file was not found.');
      let proposal: BoundedProposal;
      try { proposal = JSON.parse(file.content) as BoundedProposal; } catch { throw new WorkflowError('invalid-input', 'The inert proposal must be valid JSON.'); }
      const dependencies = values.run === undefined ? undefined : { runId: parseId('run', values.run),
        evidence: (values.evidence ?? []).map((id) => parseId('evidence', id)) };
      const plan = await workflow.previewSourcePatch(slug!, values.task, proposal, dependencies);
      if (values.preview) return plan;
      const approval = await confirm(plan.request, { plan }, plan);
      return await workflow.commitSourcePatch(slug!, values.task, proposal, plan, approval, dependencies);
    }
    if (['discover', 'principles', 'clarify'].includes(command ?? '')) {
      if (positionals.length !== (command === 'principles' ? 1 : 2) || values.file === undefined) throw new WorkflowError('invalid-input', 'Select an explicit input file for the reviewed content.');
      const file = await workflow.files.read(parseProjectPath(values.file));
      if (file === null) throw new WorkflowError('not-found', 'Review input file was not found.');
      const plan = command === 'principles' ? (await workflow.previewPrinciples(file.content)).plan
        : command === 'clarify' ? await workflow.previewClarification(slug!, JSON.parse(file.content) as readonly LocalQuestion[])
        : await workflow.previewCapture(slug!, 'discovery', file.content);
      if (values.preview) return plan;
      return await workflow.apply(plan, await confirm(plan.request, { plan }, plan));
    }
    if (command === 'applicability') {
      if (positionals.length !== 2 || (values.reason === undefined) === (values.required !== true)) throw new WorkflowError('invalid-input', 'Use applicability <slug> --reason <text> or --required.');
      const plan = await workflow.previewApplicability(slug!, values.required ? null : values.reason!);
      if (values.preview) return plan;
      return await workflow.apply(plan, await confirm(plan.request, { plan }, plan));
    }
    if (command === 'check') {
      if (positionals.length !== 3 || slug !== 'register' || values.file === undefined) throw new WorkflowError('invalid-input', 'Use check register <slug> --file <registration.json> [--preview].');
      const file = await workflow.files.read(parseProjectPath(values.file));
      if (file === null) throw new WorkflowError('not-found', 'Registration input is missing.');
      const input = JSON.parse(file.content) as LocalCheckInput;
      let checks = new LocalChecks(workflow, store, authority);
      const preview = await checks.previewRegistration(positionals[2]!, input);
      if (values.preview) return preview;
      const approval = await confirm(preview.request, preview);
      await openStore(true);
      checks = new LocalChecks(workflow, store, authority);
      return await checks.register(positionals[2]!, input, approval);
    }
    if (command === 'collect') {
      if (positionals.length !== 2) throw new WorkflowError('invalid-input', 'Use collect <slug> --registration <check-id> [--run <RUN-id>].');
      const runId = parseId('run', values.run ?? `RUN-${randomUUID()}`);
      const checks = new LocalChecks(workflow, store, authority);
      const preview = await checks.previewCollection(slug!, runId, values.registration ?? []);
      if (values.preview) return preview;
      const approval = await confirm(preview.request, preview);
      await openStore(true);
      return await new LocalChecks(workflow, store, authority).collect(slug!, runId, values.registration ?? [], approval);
    }
    if (command === 'accept' || command === 'sync' || command === 'archive') {
      if (positionals.length !== 2) throw new WorkflowError('invalid-input', 'Select one change.');
      const outcome = oneOf(values.outcome ?? 'accepted', ['accepted', 'rejected', 'cancelled', 'incomplete'], 'outcome');
      let acceptance = values.acceptance === undefined ? undefined : parseApprovalReference({ id: values.acceptance });
      if (outcome === 'accepted' && acceptance === undefined) {
        const runId = parseId('run', values.run);
        const evidence = (values.evidence ?? []).map((id) => parseId('evidence', id));
        const review = await workflow.previewAcceptance(slug!, runId, evidence);
        if (values.preview) return { next: 'acceptance', ...review, following: command === 'archive' ? ['promotion', 'closure'] : command === 'sync' ? ['promotion'] : [] };
        const approval = await confirm(review.request, review);
        await workflow.accept(slug!, runId, evidence, approval);
        acceptance = approval;
      }
      if (command === 'accept') return { state: 'accepted', acceptance };
      if (outcome === 'accepted') {
        const promotion = await workflow.previewPromotion(slug!, acceptance!);
        if (promotion.state === 'conflict') throw new WorkflowError('conflict', 'Baseline conflicts must be resolved before guided promotion or closure.');
        if (values.preview) return promotion;
        if (promotion.plan !== null) {
          await workflow.commitPromotion(slug!, acceptance!, promotion.plan, await confirm(promotion.plan.request, promotion, promotion.plan));
        }
        if (command === 'sync') return { state: 'synced', acceptance };
      }
      const closure = await workflow.previewArchive(slug!, outcome, acceptance);
      if (values.preview) return closure;
      return await workflow.commitArchive(slug!, outcome, closure, await confirm(closure.request, { closure }, closure), acceptance);
    }
    const previewValues = { ...values, preview: true };
    // Approval is not part of the preview grammar or the previewed material.
    delete (previewValues as { approval?: string }).approval;
    const preview = await previewCommand(positionals, previewValues);
    const planValue = command === 'draft-all' ? (preview as { plan: FilePlan | null }).plan :
      command === 'recover' ? (preview as { plan: FilePlan }).plan : preview;
    if (planValue === null) return preview;
    const plan = parseFilePlan(planValue);
    const approval = await confirm(plan.request, { plan }, plan);
    return command === 'recover' ? await workflow.files.recover(slug!, approval) : await workflow.apply(plan, approval);
  } finally {
    if (store !== undefined && store.close().status !== 'ok') throw new WorkflowError('persistence-failed', 'The runtime ledger could not close safely.');
  }
}
