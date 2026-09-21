import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { SkillInstallation } from '../application/installation.js';
import { WorkflowError } from '../application/errors.js';
import type { LocalWorkflow } from '../application/local-workflow.js';
import type { FilePlan } from '../adapters/filesystem/local-workspace.js';
import type { ContextProviderPort, LocalAuthorityPort, RuntimeStorePort } from '../ports/contracts.js';
import type { ApprovalReference, ApprovalRequest } from '../kernel/authority.js';
import { parseId, parseProjectPath, NATIVE_HOSTS } from '../kernel/identifiers.js';
import type { SkillCatalog } from '../engines/integration/index.js';
import { parseChangeMetadata } from '../engines/specification/contracts.js';
import { LocalConvergence } from '../application/convergence.js';
import { unavailableAuthority } from '../application/authority.js';
import { AdoptionService } from '../application/import.js';
import { ContextService } from '../application/context.js';
import { LocalLessons } from '../application/lessons.js';
import { parseDigest } from '../kernel/revisions.js';
import { LocalEvidencePruning } from '../application/evidence-pruning.js';

const change = z.string().min(1).max(80).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
const path = z.string().min(1).max(1024);
const document = z.object({ path, content: z.string().max(131_072) }).strict();
const artifact = z.enum(['proposal', 'specs', 'design', 'tasks']);
const evidence = z.array(z.string().min(1).max(80)).max(128);
const hosts = z.array(z.enum(NATIVE_HOSTS)).min(1).max(3);
const reference = (id: string): ApprovalReference => ({ id: parseId('approval', id) });

export const previewSchema = z.object({
  action: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('setup'), profile: z.enum(['standard', 'compact']).optional(), hosts: hosts.optional() }).strict(),
    z.object({
      kind: z.literal('new-change'), change, profile: z.enum(['standard', 'compact']).optional(),
      specs: z.array(path).min(1).max(128), sourcePaths: z.array(path).max(128).optional(),
      verificationPlan: z.boolean().optional(),
    }).strict(),
    z.object({
      kind: z.literal('artifact'), change, artifact, mode: z.enum(['draft', 'capture', 'revise']),
      files: z.array(document).min(1).max(128),
    }).strict(),
    z.object({
      kind: z.literal('draft-all'), change,
      drafts: z.object({
        proposal: z.array(document).min(1).max(1).optional(),
        specs: z.array(document).min(1).max(128).optional(),
        design: z.array(document).min(1).max(1).optional(),
        tasks: z.array(document).min(1).max(2).optional(),
      }).strict(),
    }).strict(),
    z.object({ kind: z.literal('discovery'), change, content: z.string().max(131_072) }).strict(),
    z.object({ kind: z.literal('principles'), content: z.string().max(131_072) }).strict(),
    z.object({ kind: z.literal('applicability'), change, reason: z.string().min(1).max(4096).nullable() }).strict(),
    z.object({
      kind: z.literal('clarification'), change,
      questions: z.array(z.object({
        id: z.string().min(1).max(80),
        question: z.string().min(1).max(4096), blocking: z.boolean(),
        artifactRevision: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
        response: z.object({
          answer: z.string().min(1).max(4096), source: z.enum(['user', 'proposed-assumption']),
        }).strict().nullable(),
      }).strict()).max(128),
    }).strict(),
    z.object({ kind: z.literal('acceptance'), change, run: z.string().min(1).max(80), evidence }).strict(),
    z.object({ kind: z.literal('sync'), change, acceptance: z.string().min(1).max(80) }).strict(),
    z.object({
      kind: z.literal('archive'), change,
      outcome: z.enum(['accepted', 'rejected', 'cancelled', 'incomplete']),
      acceptance: z.string().min(1).max(80).optional(),
    }).strict(),
    z.object({ kind: z.literal('skills'), action: z.enum(['install', 'update', 'remove']), hosts }).strict(),
    z.object({ kind: z.literal('convergence'), change, review: z.record(z.string(), z.unknown()) }).strict(),
    z.object({ kind: z.literal('adopt'), adoption: z.record(z.string(), z.unknown()) }).strict(),
    z.object({
      kind: z.literal('context'), query: z.string().min(1).max(4096),
      paths: z.array(path).min(1).max(64), allowRemoteProcessing: z.boolean(),
    }).strict(),
    z.object({ kind: z.literal('lesson-capture'), change, candidate: z.record(z.string(), z.unknown()) }).strict(),
    z.object({
      kind: z.literal('lesson-evaluate'), change, lesson: change,
      version: z.string().regex(/^sha256:[a-f0-9]{64}$/u), mode: z.enum(['evidence-review', 'semantic']).optional(),
    }).strict(),
    z.object({ kind: z.literal('lesson-transition'), change, lesson: change, transition: z.record(z.string(), z.unknown()) }).strict(),
    z.object({ kind: z.literal('evidence-prune'), evidence: evidence.min(1).max(64) }).strict(),
    z.object({ kind: z.literal('evidence-prune-recover'), id: z.string().regex(/^sha256:[a-f0-9]{64}$/u) }).strict(),
    z.object({
      kind: z.literal('source-patch'), change, task: z.string().min(1).max(80),
      proposal: z.record(z.string(), z.unknown()),
      dependencies: z.object({ run: z.string().min(1).max(80), evidence }).strict().optional(),
    }).strict(),
  ]),
}).strict();

export const applySchema = z.object({ preview: z.string().regex(/^[a-f0-9]{48}$/u) }).strict();

/** Trusted process composition supplies this channel; MCP accept is not an issuer. */
export interface McpWorkflowAuthority extends LocalAuthorityPort {
  confirmPlan(plan: FilePlan): ReturnType<LocalAuthorityPort['requestConfirmation']>;
  requestConfirmation(request: ApprovalRequest, detail?: object): ReturnType<LocalAuthorityPort['requestConfirmation']>;
}

export interface McpContextOptions {
  readonly provider: ContextProviderPort | null;
  readonly enabled: boolean;
  readonly processing: 'local-only' | 'remote';
}

interface Prepared {
  readonly createdAt: number;
  readonly review: () => ReturnType<LocalAuthorityPort['requestConfirmation']>;
  readonly commit: (approval: ApprovalReference) => Promise<unknown>;
}

export function createMcpWorkflows(
  workflow: LocalWorkflow,
  catalog: SkillCatalog,
  version: string,
  authority?: McpWorkflowAuthority,
  contextOptions?: McpContextOptions,
  store?: RuntimeStorePort,
) {
  const installation = new SkillInstallation(workflow.files, catalog, version);
  const convergence = new LocalConvergence(workflow, authority ?? unavailableAuthority);
  const adoption = new AdoptionService(workflow);
  const context = new ContextService(workflow, authority ?? unavailableAuthority,
    contextOptions?.provider ?? null, {
      enabled: contextOptions?.enabled ?? false, processing: contextOptions?.processing ?? 'local-only',
    });
  const lessons = store === undefined ? null : new LocalLessons(workflow, authority ?? unavailableAuthority, store);
  const pruning = store?.evidencePruning === undefined ? null : new LocalEvidencePruning(workflow, store, authority ?? unavailableAuthority);
  const pending = new Map<string, Prepared>();
  const prune = () => {
    for (const [key, value] of pending) if (performance.now() - value.createdAt > 10 * 60_000) pending.delete(key);
  };
  const prepare = (
    value: unknown,
    plan: FilePlan | null,
    commit?: Prepared['commit'],
    explicitReview?: Prepared['review'],
  ) => {
    if (Buffer.byteLength(JSON.stringify(value), 'utf8') > 240_000) {
      throw new WorkflowError('limit-reached', 'The review exceeds the bounded MCP response size. Use a smaller artifact or the local terminal review.');
    }
    if (plan === null && explicitReview === undefined) return { review: value, preview: null, authorityIssued: false };
    prune();
    if (pending.size >= 16) throw new WorkflowError('limit-reached', 'There are too many pending previews. Apply or discard an existing preview before preparing more.');
    const key = randomBytes(24).toString('hex');
    pending.set(key, {
      createdAt: performance.now(),
      review: explicitReview ?? (() => {
        if (authority === undefined || plan === null) throw new WorkflowError('authority-required', 'No trusted local review channel is configured. An MCP form response cannot issue authority.');
        return authority.confirmPlan(plan);
      }),
      commit: commit ?? ((approval) => {
        if (plan === null) throw new WorkflowError('invalid-input', 'The preview has no file plan.');
        return workflow.apply(plan, approval);
      }),
    });
    return { review: value, preview: key, expiresAfterSeconds: 600, authorityIssued: false };
  };
  return {
    installation,
    convergence,
    context,
    lessons,
    pruning,
    async preview({ action }: z.infer<typeof previewSchema>) {
      const documents = (files: readonly z.infer<typeof document>[]) =>
        files.map((file) => ({ path: parseProjectPath(file.path), content: file.content }));
      switch (action.kind) {
        case 'setup': {
          const setup = await workflow.previewSetup(action.profile);
          if (action.hosts === undefined) return prepare(setup, setup);
          const value = await installation.previewInstall(action.hosts, setup);
          return prepare(value, value.plan, (approval) => installation.apply(value.plan!, approval));
        }
        case 'new-change': {
          const value = await workflow.previewNewChange({
            slug: action.change, specs: action.specs,
            ...(action.profile === undefined ? {} : { profile: action.profile }),
            ...(action.sourcePaths === undefined ? {} : { sourcePaths: action.sourcePaths }),
            ...(action.verificationPlan === undefined ? {} : { verificationPlan: action.verificationPlan }),
          });
          return prepare(value, value);
        }
        case 'artifact': {
          const value = await workflow.previewArtifact(action.change, action.artifact, documents(action.files), { mode: action.mode });
          return prepare(value, value);
        }
        case 'draft-all': {
          const drafts: Record<string, ReturnType<typeof documents>> = {};
          for (const [node, files] of Object.entries(action.drafts)) if (files !== undefined) drafts[node] = documents(files);
          const value = await workflow.previewDraftAll(action.change, drafts);
          return prepare(value, value.plan);
        }
        case 'discovery': {
          const value = await workflow.previewCapture(action.change, 'discovery', action.content);
          return prepare(value, value);
        }
        case 'principles': {
          const value = await workflow.previewPrinciples(action.content);
          return prepare(value, value.plan);
        }
        case 'applicability': {
          const value = await workflow.previewApplicability(action.change, action.reason);
          return prepare(value, value);
        }
        case 'clarification': {
          const loaded = await workflow.loadChange(action.change);
          const questions = parseChangeMetadata({ ...loaded.metadata, questions: action.questions }).questions;
          const value = await workflow.previewClarification(action.change, questions);
          return prepare(value, value);
        }
        case 'acceptance': {
          const run = parseId('run', action.run);
          const ids = action.evidence.map((id) => parseId('evidence', id));
          const value = await workflow.previewAcceptance(action.change, run, ids);
          return prepare(value, null, (approval) => workflow.accept(action.change, run, ids, approval), () => {
            if (authority === undefined) throw new WorkflowError('authority-required', 'Acceptance requires an independently trusted local review channel.');
            return authority.requestConfirmation(value.request, { report: value.report });
          });
        }
        case 'sync': {
          const acceptance = reference(action.acceptance);
          const value = await workflow.previewPromotion(action.change, acceptance);
          return prepare(value, value.plan, (approval) => workflow.commitPromotion(action.change, acceptance, value.plan!, approval));
        }
        case 'archive': {
          const acceptance = action.acceptance === undefined ? undefined : reference(action.acceptance);
          const value = await workflow.previewArchive(action.change, action.outcome, acceptance);
          return prepare(value, value, (approval) => workflow.commitArchive(action.change, action.outcome, value, approval, acceptance));
        }
        case 'skills': {
          const value = action.action === 'install' ? await installation.previewInstall(action.hosts)
            : action.action === 'update' ? await installation.previewUpdate(action.hosts)
              : await installation.previewRemove(action.hosts);
          return prepare(value, value.plan, (approval) => installation.apply(value.plan!, approval));
        }
        case 'convergence': {
          const value = await convergence.preview(action.change, action.review);
          return prepare(value, null, (approval) => convergence.capture(action.change, value.review, approval), () => {
            if (authority === undefined) throw new WorkflowError('authority-required', 'Capturing a convergence review requires an independently trusted local review channel.');
            return authority.requestConfirmation(value.request, value);
          });
        }
        case 'adopt': {
          const value = await adoption.preview(action.adoption);
          return prepare(value, value.plan, (approval) => adoption.apply(value, approval));
        }
        case 'context': {
          const value = await context.preview({
            query: action.query, paths: action.paths, allowRemoteProcessing: action.allowRemoteProcessing,
          });
          if (value.state !== 'ready') return prepare(value, null);
          return prepare(value, null, (approval) => context.consume(value, approval), () => {
            if (authority === undefined) throw new WorkflowError('authority-required', 'Context consumption requires an independently trusted local review channel.');
            return authority.requestConfirmation(value.request, {
              query: value.query, scope: value.scope, availability: value.availability, processing: value.processing,
            });
          });
        }
        case 'lesson-capture': {
          if (lessons === null) throw new WorkflowError('capability-unavailable', 'Lesson review requires the workspace-bound runtime ledger.');
          const value = await lessons.previewCapture(action.change, action.candidate);
          return prepare(value, null, (approval) => lessons.capture(action.change, action.candidate, approval), () => lessons.confirm(value));
        }
        case 'lesson-evaluate': {
          if (lessons === null) throw new WorkflowError('capability-unavailable', 'Lesson evaluation requires the workspace-bound runtime ledger.');
          const version = parseDigest(action.version);
          const value = await lessons.previewEvaluation(action.change, action.lesson, version, action.mode);
          return prepare(value, null, (approval) => lessons.evaluate(action.change, action.lesson, version, approval, action.mode), () => lessons.confirm(value));
        }
        case 'lesson-transition': {
          if (lessons === null) throw new WorkflowError('capability-unavailable', 'Lesson transitions require the workspace-bound runtime ledger.');
          const value = await lessons.previewTransition(action.change, action.lesson, action.transition);
          return prepare(value, null, (approval) => lessons.transition(action.change, action.lesson, action.transition, approval), () => lessons.confirm(value));
        }
        case 'evidence-prune': {
          if (pruning === null) throw new WorkflowError('capability-unavailable', 'The runtime has no recoverable evidence-pruning capability.');
          const value = await pruning.preview(action.evidence.map((id) => parseId('evidence', id)));
          return prepare(value, null, (approval) => pruning.commit(value, approval), () => pruning.confirm(value));
        }
        case 'evidence-prune-recover': {
          if (pruning === null) throw new WorkflowError('capability-unavailable', 'The runtime has no recoverable evidence-pruning capability.');
          const id = parseDigest(action.id);
          const value = await pruning.previewRecovery(id);
          if (value.state === 'pruned') return prepare(value, null);
          return prepare(value, null, (approval) => pruning.recover(id, approval), () => pruning.confirm(value));
        }
        case 'source-patch': {
          const dependencies = action.dependencies === undefined ? undefined : {
            runId: parseId('run', action.dependencies.run),
            evidence: action.dependencies.evidence.map((id) => parseId('evidence', id)),
          };
          const value = await workflow.previewSourcePatch(action.change, action.task, action.proposal, dependencies);
          return prepare(value, value, (approval) =>
            workflow.commitSourcePatch(action.change, action.task, action.proposal, value, approval, dependencies));
        }
      }
    },
    discard({ preview }: z.infer<typeof applySchema>) {
      return { discarded: pending.delete(preview), authorityIssued: false };
    },
    async apply({ preview }: z.infer<typeof applySchema>, signal?: AbortSignal) {
      prune();
      const selected = pending.get(preview);
      if (selected === undefined) throw new WorkflowError('not-found', 'The preview is absent, expired, consumed, or belongs to another connection.');
      // Consume before awaiting a channel: concurrent/replayed calls cannot reuse a decision.
      pending.delete(preview);
      if (signal?.aborted) throw new WorkflowError('authority-required', 'The review request was cancelled before any planned effects.');
      const confirmation = await selected.review();
      if (signal?.aborted) throw new WorkflowError('authority-required', 'The review request was cancelled. No planned effects were applied.');
      if (confirmation.status !== 'ok') throw new WorkflowError(confirmation.error.code, confirmation.error.message);
      if (confirmation.value.state !== 'issued') throw new WorkflowError('authority-required', 'The trusted channel did not issue an approval. No planned effects were applied.');
      return selected.commit(confirmation.value.approval.reference);
    },
  };
}
