import { LocalWorkflow } from '../application/local-workflow.js';
import { WorkflowError } from '../application/errors.js';
import { parseId, parseProjectPath } from '../kernel/identifiers.js';
import { oneOf } from '../kernel/validation.js';
import path from 'node:path';
import { openRuntimeStore } from '../adapters/persistence/index.js';
import { renderArtifactTemplate, type MarkdownSource } from '../engines/specification/contracts.js';
import { runMutation } from './mutations.js';
import { assessClarifications } from '../engines/discovery/contracts.js';

export const localCommands = ['project', 'init', 'change', 'status', 'instructions', 'analyze', 'draft', 'draft-all', 'capture', 'revise', 'clarify', 'verify', 'sync', 'archive', 'recover', 'onboard', 'applicability', 'approval', 'check', 'collect', 'accept', 'discover', 'principles', 'run-status', 'patch'] as const;

export interface LocalCliOptions {
  readonly preview?: boolean | undefined;
  readonly artifact?: string | undefined;
  readonly profile?: string | undefined;
  readonly spec?: readonly string[] | undefined;
  readonly source?: readonly string[] | undefined;
  readonly run?: string | undefined;
  readonly evidence?: readonly string[] | undefined;
  readonly acceptance?: string | undefined;
  readonly outcome?: string | undefined;
  readonly approval?: string | undefined;
  readonly reason?: string | undefined;
  readonly required?: boolean | undefined;
  readonly file?: string | undefined;
  readonly registration?: readonly string[] | undefined;
  readonly task?: string | undefined;
  readonly 'verification-plan'?: boolean | undefined;
}

export async function runLocalCommand(positionals: readonly string[], values: LocalCliOptions): Promise<unknown> {
  const [command, subject] = positionals;
  const special = ['applicability', 'approval', 'check', 'collect', 'accept', 'discover', 'principles', 'patch'].includes(command ?? '') ||
    command === 'clarify' && values.file !== undefined;
  const mutation = ['init', 'draft', 'draft-all', 'capture', 'revise', 'sync', 'archive'].includes(command ?? '') ||
    command === 'change' && subject === 'new' || command === 'recover' && subject !== undefined;
  if (special || mutation && !values.preview || ['sync', 'archive'].includes(command ?? '') && values.run !== undefined) {
    return runMutation(positionals, values, runLocalPreview);
  }
  if (['approval', 'reason', 'required', 'file', 'registration', 'task'].some((key) => Object.hasOwn(values, key))) {
    throw new WorkflowError('invalid-input', 'An option does not apply to this read-only command.');
  }
  return runLocalPreview(positionals, values);
}

async function runLocalPreview(positionals: readonly string[], values: LocalCliOptions): Promise<unknown> {
  const [command, subject, extra] = positionals;
  const permitted: Readonly<Record<string, readonly string[]>> = {
    project: [], onboard: [], init: ['preview', 'profile'],
    change: subject === 'new' ? ['preview', 'profile', 'spec', 'source', 'verification-plan'] : [],
    status: [], analyze: [], clarify: [], instructions: ['artifact'], 'run-status': [],
    draft: ['preview', 'artifact'], capture: ['preview', 'artifact'], revise: ['preview', 'artifact'], 'draft-all': ['preview'],
    recover: ['preview'], verify: ['run', 'evidence'], sync: ['preview', 'acceptance'], archive: ['preview', 'acceptance', 'outcome'],
  };
  const localFlags = ['preview', 'artifact', 'profile', 'spec', 'source', 'run', 'evidence', 'acceptance', 'outcome', 'verification-plan'];
  if (localFlags.some((key) => Object.hasOwn(values, key) && !(permitted[command ?? ''] ?? []).includes(key)) ||
      (command === 'verify' && values.evidence !== undefined && values.run === undefined)) {
    throw new WorkflowError('invalid-input', 'An option does not apply to the selected local operation.');
  }
  let workflow = await LocalWorkflow.open(process.cwd());
  const assertCount = (count: number): void => {
    if (positionals.length !== count) throw new WorkflowError('invalid-input', 'Unexpected local command arguments.');
  };
  const preview = (): void => {
    if (values.preview !== true) throw new WorkflowError('capability-unavailable', 'Production mutation is blocked: no qualified local confirmation channel is installed. Use --preview; request flags and model text cannot approve effects.');
  };
  const selected = (): string => {
    if (subject === undefined) throw new WorkflowError('invalid-input', 'Select an explicit change slug.');
    return subject;
  };
  if (command === 'init') { assertCount(1); preview(); return workflow.previewSetup(values.profile); }
  if (command === 'project') {
    assertCount(2);
    if (subject !== 'status') throw new WorkflowError('invalid-input', 'Use project status.');
    return workflow.project();
  }
  if (command === 'onboard') {
    assertCount(1);
    return {
      project: await workflow.project(),
      guidance: [
        'Use init --preview, then init to confirm exact setup on your local terminal.',
        'Create a change with explicit spec names and source paths; draft one artifact or a bounded draft-all batch.',
        'Review capture, edits, execution, check execution, acceptance, promotion and closure as separate effect purposes.',
        'Register trusted checks explicitly; collect real evidence, then archive guides separate acceptance, promotion and closure reviews.',
        'Native host dispatch remains unavailable until a real exact-version adapter qualifies hard controls and durable fencing.',
      ],
    };
  }
  if (command === 'change') {
    if (subject === 'list') { assertCount(2); return workflow.project(); }
    if (subject !== 'new' || extra === undefined) throw new WorkflowError('invalid-input', 'Use change list or change new <slug> --spec <name> --preview.');
    assertCount(3); preview();
    return workflow.previewNewChange({ slug: extra, specs: values.spec ?? [], sourcePaths: values.source ?? [], profile: values.profile,
      ...(values['verification-plan'] === undefined ? {} : { verificationPlan: values['verification-plan'] }) });
  }
  if (command === 'recover') {
    if (subject === undefined) { assertCount(1); return { pending: await workflow.files.pending(), writesPerformed: false }; }
    preview();
    assertCount(2);
    return { transactionId: subject, plan: await workflow.files.recoveryPlan(subject), writesPerformed: false };
  }
  assertCount(2);
  const slug = selected();
  if (command === 'status' || command === 'analyze') {
    const change = await workflow.loadChange(slug);
    return {
      id: change.metadata.id, slug: change.metadata.slug, revisions: change.revisions, sourceScope: change.sourceScope,
      readiness: change.readiness, analysis: change.analysis, uncaptured: change.uncaptured,
      implementationReady: change.implementationReady,
      diagnostics: change.validation.state === 'invalid' ? change.validation.diagnostics : [],
      implementationVerified: false, authorityIssued: false,
    };
  }
  if (command === 'instructions') return workflow.instructions(slug, values.artifact);
  if (command === 'clarify') {
    const change = await workflow.loadChange(slug);
    return { questions: change.metadata.questions, ...assessClarifications(change.metadata.questions, change.analysis.artifactRevision) };
  }
  if (command === 'draft' || command === 'capture' || command === 'revise' || command === 'draft-all') {
    preview();
    const change = await workflow.loadChange(slug);
    const content = async (paths: readonly string[]): Promise<readonly MarkdownSource[]> => Promise.all(paths.map(async (path) => {
      const file = await workflow.files.read(parseProjectPath(path));
      if (file === null) throw new WorkflowError('not-found', 'Edit all declared Markdown outputs before previewing capture.');
      return { path: file.path, content: file.content };
    }));
    if (command === 'draft-all') {
      const drafts: Record<string, readonly MarkdownSource[]> = {};
      for (const node of change.metadata.nodes) {
        if ((await Promise.all(node.outputs.map((path) => workflow.files.read(path)))).every((file) => file !== null)) drafts[node.node] = await content(node.outputs);
      }
      return workflow.previewDraftAll(slug, drafts);
    }
    const selectedNode = values.artifact ?? (change.readiness.next.state === 'ready' ? change.readiness.next.node : null);
    const node = change.metadata.nodes.find((entry) => entry.node === selectedNode);
    if (node === undefined) throw new WorkflowError('invalid-input', 'Select one ready artifact with --artifact; inspect instructions for candidates.');
    const files = command === 'draft'
      ? node.outputs.map((path, index) => ({
        path, content: renderArtifactTemplate({
          kind: path.endsWith('/verification.md') ? 'verification' : node.node as 'proposal' | 'specs' | 'design' | 'tasks',
          id: `ART-template-${node.node}-${index + 1}`, changeId: change.metadata.id, compact: change.metadata.profile === 'compact',
          externalChecks: node.node === 'tasks' && node.outputs.length === 2,
        }),
      }))
      : await content(node.outputs);
    return workflow.previewArtifact(slug, node.node, files, { mode: command === 'draft' ? 'draft' : command === 'revise' ? 'revise' : 'capture' });
  }
  if (command === 'verify' && values.run === undefined) return workflow.verificationGaps(slug);
  if (command === 'archive' && values.outcome !== 'accepted') {
    preview();
    const outcome = oneOf(values.outcome, ['rejected', 'cancelled', 'incomplete'], 'outcome');
    if (!(await workflow.files.list(parseProjectPath('.missionspec/state'))).includes(parseProjectPath('.missionspec/state/ledger.sqlite'))) {
      return workflow.previewArchive(slug, outcome);
    }
  }
  const workspace = await workflow.files.identity();
  if (workspace === null) throw new WorkflowError('not-found', 'No explicit workspace identity exists.');
  const store = await openRuntimeStore({ directory: path.join(process.cwd(), '.missionspec/state'), mode: 'read-only', expectedWorkspace: workspace });
  if (store.status !== 'ok') throw new WorkflowError('evidence-unavailable', 'An existing readable runtime ledger is required for this review.');
  try {
    workflow = await LocalWorkflow.open(process.cwd(), { store: store.value });
    if (command === 'run-status') {
      const result = await store.value.readRun(parseId('run', slug));
      if (result.status !== 'ok' || result.value === null) throw new WorkflowError('not-found', 'The durable run is unavailable.');
      return result.value;
    }
    if (command === 'verify' && values.run !== undefined) {
      return await workflow.verify(slug, parseId('run', values.run), (values.evidence ?? []).map((id) => parseId('evidence', id)));
    }
    if (command === 'sync') {
      preview();
      return await workflow.previewPromotion(slug, { id: parseId('approval', values.acceptance) });
    }
    if (command === 'archive') {
      preview();
      const outcome = oneOf(values.outcome, ['accepted', 'rejected', 'cancelled', 'incomplete'], 'outcome');
      return await workflow.previewArchive(slug, outcome, values.acceptance === undefined ? undefined : { id: parseId('approval', values.acceptance) });
    }
    throw new WorkflowError('invalid-input', 'Unsupported local operation.');
  } finally {
    const closed = store.value.close();
    if (closed.status !== 'ok') throw new WorkflowError('persistence-failed', 'The read-only ledger could not be closed safely.');
  }
}
