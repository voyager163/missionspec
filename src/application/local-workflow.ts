import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { stringify } from 'yaml';
import { LocalWorkspace, makeFilePlan, writeMutation, type FileGuard, type FilePlan, type SourcePatchDependencies } from '../adapters/filesystem/local-workspace.js';
import { parseApprovalRequest, type ApprovalReference } from '../kernel/authority.js';
import { digestEffectScope, type RequestedEffect } from '../kernel/effects.js';
import { isReservedSourcePath, parseChangeSlug, parseId, parseNativeHost, parseProjectPath, type EvidenceId, type ProjectPath, type RunId } from '../kernel/identifiers.js';
import { digestContent, parseDigest, sameRevisionBinding, type ContentDigest, type RevisionBinding, type WorkspaceBinding } from '../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../kernel/validation.js';
import {
  ARTIFACT_TEMPLATE_VERSION, captureArtifactSnapshot, parseArtifactNodeId, parseChangeMetadata, parseMarkdownDocument, parseMarkdownSet,
  parseCapabilityName, parseProjectMetadata, promoteBaseline, renderArtifactTemplate, type ArtifactNodeId, type ArtifactSnapshot, type ChangeMetadata, type LocalQuestion, type MarkdownSource,
} from '../engines/specification/contracts.js';
import { analyzeDocuments, assessArtifactReadiness, parseArtifactWorkflow, parseWorkflowProfile } from '../engines/planning/contracts.js';
import { assessVerification, type AcceptanceRecord, type CheckObservation } from '../engines/verification/contracts.js';
import type { BoundedProposal, FileMutation, FileSnapshot, LocalAuthorityPort, RuntimeStorePort } from '../ports/contracts.js';
import type { WorkOrder } from '../engines/execution/contracts.js';
import { requireApproval, unavailableAuthority } from './authority.js';
import { WorkflowError } from './errors.js';
import { LocalConvergence } from './convergence.js';
import { runtimeStateExists } from '../adapters/persistence/index.js';

const configPath = parseProjectPath('missionspec/config.yaml');
const identityPath = parseProjectPath('.missionspec/workspace.json');
const principlesPath = parseProjectPath('missionspec/principles.md');
const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
const yaml = (value: unknown): string => stringify(value, { lineWidth: 0, aliasDuplicateObjects: false });
const metadataPath = (slug: string): ProjectPath => parseProjectPath(`missionspec/changes/${parseChangeSlug(slug)}/change.yaml`);

export class LocalWorkflow {
  private constructor(
    readonly files: LocalWorkspace, private readonly authority: LocalAuthorityPort,
    private readonly store: RuntimeStorePort | undefined, private readonly now: () => string,
  ) {}

  static async open(directory: string, options: {
    readonly authority?: LocalAuthorityPort; readonly store?: RuntimeStorePort; readonly now?: () => string;
  } = {}): Promise<LocalWorkflow> {
    const authority = options.authority ?? unavailableAuthority;
    const now = options.now ?? (() => new Date().toISOString());
    let application: LocalWorkflow;
    const files = await LocalWorkspace.open(directory, {
      authority, now, beforeEffects: async (plan) => {
        await application.assertNoActiveRuns();
        if (plan.request.purpose === 'promotion') {
          const observed = await application.baselinePaths();
          const expected = plan.guards.filter((guard) =>
            guard.path.startsWith('missionspec/specs/') && guard.path.endsWith('/spec.md') && guard.digest !== 'absent')
            .map((guard) => guard.path).sort();
          if (JSON.stringify(observed) !== JSON.stringify(expected)) {
            throw new WorkflowError('stale-revision', 'Accepted baseline inventory changed before the publication transaction.');
          }
        }
        if (plan.request.purpose === 'closure') {
          const removed = plan.mutations.filter((mutation) => mutation.effect.kind === 'file-remove').map((mutation) => mutation.effect.path);
          const source = removed.find((path) => /^missionspec\/changes\/[^/]+\/change\.yaml$/u.test(path));
          const closure = plan.mutations.find((mutation) => mutation.effect.path.endsWith('/closure.json'));
          if (source === undefined || closure === undefined) throw new WorkflowError('invalid-input', 'Closure lacks its exact source and destination inventory.');
          const destinations = plan.mutations.filter((mutation) => mutation.effect.kind === 'file-write').map((mutation) => mutation.effect.path);
          const observedSource = await application.fileTree(parseProjectPath(source.slice(0, -'/change.yaml'.length)));
          const observedDestination = await application.fileTree(parseProjectPath(closure.effect.path.slice(0, -'/closure.json'.length)));
          if (observedSource.some((path) => !removed.includes(path)) || observedDestination.some((path) => !destinations.includes(path))) {
            throw new WorkflowError('stale-revision', 'Change or archive inventory gained unreviewed files before closure.');
          }
        }
      },
    });
    application = new LocalWorkflow(files, authority, options.store, now);
    return application;
  }

  private async assertNoActiveRuns(): Promise<void> {
    if (this.store === undefined) {
      if (await runtimeStateExists(this.files.root, await this.files.identity())) {
        throw new WorkflowError('capability-unavailable', 'Compose the existing runtime store so local mutations can establish execution quiescence.');
      }
      return;
    }
    const runs = await this.store.listRuns();
    if (runs.status !== 'ok') throw new WorkflowError('persistence-failed', 'Runtime quiescence cannot be established.');
    if (runs.value.some((run) => run.quiescence !== 'confirmed' || run.state === 'running' || run.state === 'outcome-unknown')) {
      throw new WorkflowError('conflict', 'A workspace run is active or unreconciled; local file effects are blocked.');
    }
  }

  private async baselinePaths(): Promise<readonly ProjectPath[]> {
    const directories: ProjectPath[] = [parseProjectPath('missionspec/specs')];
    const result: ProjectPath[] = [];
    for (let index = 0; index < directories.length; index += 1) {
      const directory = directories[index]!;
      if (directories.length > 1024 || directory.split('/').length > 34) {
        throw new WorkflowError('limit-reached', 'Accepted baseline directory inventory exceeds its bounded scope.');
      }
      const children = await this.files.list(directory);
      const nested = await this.files.directories(directory);
      directories.push(...nested);
      for (const file of children) {
        if (nested.includes(file) || !file.endsWith('/spec.md')) continue;
        parseCapabilityName(file.slice('missionspec/specs/'.length, -'/spec.md'.length));
        result.push(file);
      }
    }
    return result.sort();
  }

  private async fileTree(root: ProjectPath): Promise<readonly ProjectPath[]> {
    const directories = [root];
    const result: ProjectPath[] = [];
    for (let index = 0; index < directories.length; index += 1) {
      const directory = directories[index]!;
      if (directories.length > 128 || directory.split('/').length > 40) throw new WorkflowError('limit-reached', 'Archive directory inventory exceeds the bounded transaction scope.');
      const children = await this.files.list(directory);
      const nested = await this.files.directories(directory);
      directories.push(...nested);
      for (const file of children) if (!nested.includes(file)) {
        result.push(file);
        if (result.length > 63) throw new WorkflowError('limit-reached', 'Archive supports at most 63 files in one reviewed transaction.');
      }
    }
    return result.sort();
  }

  async project() {
    if (await this.files.read(parseProjectPath('missionspec/config.json')) !== null ||
        (await this.files.directories(parseProjectPath('missionspec/archive'))).length > 0) {
      throw new WorkflowError('unsupported-version', 'Legacy prototype metadata/layout requires explicit migration; it is not adopted automatically.');
    }
    const workspace = await this.files.identity();
    const config = await this.files.read(configPath);
    if (workspace === null && config === null) return { state: 'not-initialized' as const, rootDigest: this.files.rootDigest };
    if (workspace === null || config === null) throw new WorkflowError('conflict', 'Project setup is incomplete; inspect transaction recovery before continuing.');
    const value = record(parseProjectMetadata(config.content), 'project', ['schemaVersion', 'defaultProfile']);
    if (value.schemaVersion !== 1) throw new ContractError('project', 'unsupported project schema; no migration attempted');
    const defaultProfile = parseWorkflowProfile(value.defaultProfile);
    const changes: string[] = [];
    for (const directory of await this.files.directories(parseProjectPath('missionspec/changes'))) {
      const name = directory.split('/').at(-1)!;
      try { parseChangeSlug(name); } catch { continue; }
      if (await this.files.read(parseProjectPath(`${directory}/change.json`)) !== null) {
        throw new WorkflowError('unsupported-version', 'Legacy change metadata is not silently ignored or migrated.');
      }
      if (await this.files.read(metadataPath(name)) !== null) changes.push(name);
    }
    return {
      state: 'initialized' as const, workspace, defaultProfile,
      changes,
      pendingTransactions: await this.files.pending(),
    };
  }

  private async initialized(): Promise<WorkspaceBinding> {
    const project = await this.project();
    if (project.state !== 'initialized') throw new WorkflowError('not-found', 'Project is not initialized. Preview explicit setup first.');
    if (project.pendingTransactions.length > 0) throw new WorkflowError('conflict', 'Recover the unfinished transaction before using the workflow.');
    return project.workspace;
  }

  async previewSetup(profile: unknown = undefined): Promise<FilePlan> {
    await this.project();
    if (await this.files.identity() !== null || await this.files.read(configPath) !== null) {
      throw new WorkflowError('conflict', 'Setup never overwrites or migrates an existing project.');
    }
    const workspace = { workspaceId: parseId('workspace', `WSP-${randomUUID()}`), rootDigest: this.files.rootDigest };
    const gitignorePath = parseProjectPath('.gitignore');
    const gitignore = await this.files.read(gitignorePath);
    const content = gitignore?.content ?? '';
    const mutations = [
      writeMutation(identityPath, 'absent', json(workspace), 'configuration'),
      writeMutation(configPath, 'absent', yaml({ schemaVersion: 1, defaultProfile: parseWorkflowProfile(profile) }), 'configuration'),
      ...(/^(?:\/)?\.missionspec\/\r?$/mu.test(content) ? [] : [
        writeMutation(gitignorePath, gitignore?.digest ?? 'absent', `${content}${content === '' || content.endsWith('\n') ? '' : '\n'}.missionspec/\n`, 'configuration'),
      ]),
    ];
    return makeFilePlan({
      workspace, operation: 'onboard', purpose: 'integration', mutations,
      guards: mutations.map((mutation) => ({ path: mutation.effect.path, digest: mutation.effect.expected })),
    });
  }

  async confirm(plan: FilePlan) {
    return this.authority.requestConfirmation(plan.request, { filePlan: plan });
  }

  async apply(plan: FilePlan, approval: ApprovalReference) {
    if (['promotion', 'closure', 'source-apply'].includes(plan.request.purpose)) {
      throw new WorkflowError('invalid-input', 'Use the dedicated promotion, archive or source-patch commit operation.');
    }
    return this.files.commit(plan, approval);
  }

  async previewSourcePatch(
    slug: string, taskId: string, proposalValue: unknown, dependencyValue?: SourcePatchDependencies,
  ): Promise<FilePlan> {
    await this.assertNoActiveRuns();
    const change = await this.loadChange(slug);
    if (!change.implementationReady) throw new WorkflowError('conflict', 'Current captured artifacts, coverage and clarification are required before source-patch review.');
    const selected = parseId('task', taskId);
    const task = change.analysis.tasks.find((task) => task.id === selected);
    if (task === undefined || task.writeScope.some((path) => !change.metadata.sourcePaths.includes(path))) {
      throw new WorkflowError('scope-exceeded', 'Select a declared task with an explicitly observed source-file scope.');
    }
    const guards = [...change.guards];
    let dependencies: SourcePatchDependencies | null = null;
    if (task.dependsOn.length > 0) {
      if (dependencyValue === undefined) throw new WorkflowError('evidence-unavailable', 'Dependent source patches require retained verification evidence for their predecessor tasks.');
      const proof = record(dependencyValue, 'dependencies', ['runId', 'evidence']);
      dependencies = { runId: parseId('run', proof.runId),
        evidence: unique(array(proof.evidence, 'dependency.evidence', (id) => parseId('evidence', id), 1), 'dependency.evidence') };
      const run = await this.runtime().readRun(dependencies.runId);
      if (run.status !== 'ok' || run.value === null || run.value.snapshot.quiescence !== 'confirmed' ||
          !['paused', 'quiesced'].includes(run.value.snapshot.state) ||
          !sameRevisionBinding({ ...change.revisions, effects: run.value.snapshot.revisions.effects }, run.value.snapshot.revisions)) {
        throw new WorkflowError('evidence-unavailable', 'Dependency evidence must belong to a quiescent run at this exact live source and intent.');
      }
      const recorded = await this.runtime().readRunEvidence(dependencies.runId);
      if (recorded.status !== 'ok' || dependencies.evidence.some((id) => !recorded.value.includes(id))) {
        throw new WorkflowError('evidence-unavailable', 'Selected dependency evidence is not recorded in this run.');
      }
      const predecessors = new Set(task.dependsOn);
      for (const id of predecessors) {
        const predecessor = change.analysis.tasks.find((task) => task.id === id);
        if (predecessor === undefined || predecessor.checks.length === 0) throw new WorkflowError('evidence-unavailable', 'Every predecessor needs declared qualifying checks.');
        for (const parent of predecessor.dependsOn) predecessors.add(parent);
      }
      const required = new Set(change.analysis.tasks.filter((task) => predecessors.has(task.id)).flatMap((task) => task.checks));
      const observed = await Promise.all(dependencies.evidence.map((id) => this.readObservation(id)));
      if (observed.length !== required.size || new Set(observed.map((entry) => entry.checkId)).size !== required.size) {
        throw new WorkflowError('evidence-unavailable', 'Provide exactly one retained observation for every predecessor check.');
      }
      for (const observation of observed) {
        const check = change.analysis.checks.find((check) => check.id === observation.checkId);
        if (!required.has(observation.checkId) || observation.state !== 'observed' || observation.result !== 'passed' ||
            check?.kind !== observation.basis || check.definition !== observation.evidence.checkDefinition ||
            observation.evidence.source !== change.revisions.source ||
            !sameRevisionBinding(observation.evidence.revisions, run.value.snapshot.revisions) ||
            observation.evidence.storage.state !== 'retained') {
          throw new WorkflowError('evidence-unavailable', 'A predecessor check is failed, stale, unavailable or bound to a different definition.');
        }
        guards.push({ path: observation.evidence.storage.path, digest: observation.evidence.storage.digest });
      }
    } else if (dependencyValue !== undefined) {
      throw new WorkflowError('invalid-input', 'This task has no predecessor-evidence input.');
    }
    const raw = record(proposalValue, 'proposal', ['kind', 'host', 'summary', 'changes']);
    if (raw.kind !== 'inert-proposal') throw new WorkflowError('invalid-input', 'Only an inert, untrusted proposal can enter source-patch review.');
    if (!Array.isArray(raw.changes) || raw.changes.length > 128) throw new WorkflowError('limit-reached', 'A source proposal is limited to 128 exact replacement files.');
    let proposedBytes = 0;
    const proposal: BoundedProposal = {
      kind: 'inert-proposal', host: parseNativeHost(raw.host), summary: text(raw.summary, 'proposal.summary', 4096),
      changes: array(raw.changes, 'proposal.changes', (value) => {
        const input = record(value, 'proposal.change', ['path', 'expected', 'content']);
        const path = parseProjectPath(input.path);
        if (!task.writeScope.includes(path) || !change.metadata.sourcePaths.includes(path) ||
            isReservedSourcePath(path)) {
          throw new WorkflowError('scope-exceeded', 'An inert proposal cannot widen the selected task scope or edit workflow, runtime or Git controls.');
        }
        const expected = input.expected === 'absent' ? 'absent' : parseDigest(input.expected);
        if (expected !== change.guards.find((guard) => guard.path === path)?.digest) {
          throw new WorkflowError('stale-revision', 'The proposed source preimage differs from the live observed file.');
        }
        if (typeof input.content !== 'string' || input.content.includes('\0') || Buffer.byteLength(input.content) > 1_000_000) {
          throw new WorkflowError('invalid-input', 'Source proposals require bounded UTF-8 replacement text, not commands or deletion sentinels.');
        }
        proposedBytes += Buffer.byteLength(input.content);
        if (proposedBytes > 4_000_000) throw new WorkflowError('limit-reached', 'A source proposal exceeds the bounded replacement payload.');
        return { path, expected, content: input.content };
      }, 1),
    };
    return makeFilePlan({
      workspace: change.workspace, operation: 'implement', purpose: 'source-apply', revisions: change.revisions, guards,
      mutations: proposal.changes.map((file) => writeMutation(file.path, file.expected, file.content, 'source')),
      sourcePatch: { slug: change.metadata.slug, task, proposal: {
        kind: 'inert-proposal', host: proposal.host, summary: proposal.summary, digest: digestContent(JSON.stringify(proposal)),
      }, dependencies },
    });
  }

  async commitSourcePatch(
    slug: string, taskId: string, proposal: unknown, preview: FilePlan, approval: ApprovalReference,
    dependencies?: SourcePatchDependencies,
  ) {
    const current = await this.previewSourcePatch(slug, taskId, proposal, dependencies);
    if (current.digest !== preview.digest) throw new WorkflowError('stale-revision', 'The exact source patch, task, dependencies or observations changed; review a new candidate.');
    return this.files.commit(current, approval);
  }

  async previewNewChange(input: {
    readonly slug: string; readonly id?: string; readonly profile?: unknown;
    readonly specs: readonly string[]; readonly sourcePaths?: readonly string[];
    readonly verificationPlan?: boolean;
  }): Promise<FilePlan> {
    if (input.verificationPlan !== undefined && typeof input.verificationPlan !== 'boolean') throw new ContractError('verificationPlan', 'expected an explicit boolean');
    const workspace = await this.initialized();
    const project = await this.project();
    if (project.state !== 'initialized') throw new WorkflowError('not-found', 'Project is unavailable.');
    const slug = parseChangeSlug(input.slug);
    const path = metadataPath(slug);
    if (await this.files.read(path) !== null || (await this.files.list(parseProjectPath(`missionspec/changes/${slug}`))).length > 0) {
      throw new WorkflowError('conflict', 'The change destination already contains files.');
    }
    const profile = parseWorkflowProfile(input.profile ?? project.defaultProfile);
    const workflow = parseArtifactWorkflow(await this.workflowSource(profile));
    const names = unique(array(input.specs, 'specs', parseCapabilityName, 1), 'specs');
    const id = input.id === undefined ? parseId('change', `CHG-${randomUUID()}`) : parseId('change', input.id);
    for (const existing of project.changes) {
      const metadata = await this.files.read(metadataPath(existing));
      if (metadata !== null && parseChangeMetadata(parseProjectMetadata(metadata.content)).id === id) {
        throw new WorkflowError('conflict', 'Change identity already exists in this workspace.');
      }
    }
    for (const directory of await this.files.directories(parseProjectPath('missionspec/changes/archive'))) {
      const closure = await this.files.read(parseProjectPath(`${directory}/closure.json`));
      if (closure === null) continue;
      const value = record(JSON.parse(closure.content) as unknown, 'closure', ['schemaVersion', 'changeId', 'outcome', 'acceptance', 'notice']);
      if (value.schemaVersion !== 1) throw new WorkflowError('unsupported-version', 'Unknown archive metadata is not migrated.');
      if (value.changeId === id) throw new WorkflowError('conflict', 'Change identity already exists in the archive.');
    }
    const prefix = `missionspec/changes/${slug}`;
    const baseline = await Promise.all(names.map(async (name) => {
      const path = parseProjectPath(`missionspec/specs/${name}/spec.md`);
      return { path, digest: (await this.files.read(path))?.digest ?? 'absent' as const };
    }));
    const metadata = parseChangeMetadata({
      schemaVersion: 1, id, slug, profile, workflowRevision: workflow.revision,
      sourcePaths: input.sourcePaths ?? [], baseline, questions: [], promotedContent: null,
      nodes: workflow.nodes.map((node) => ({
        node: node.id, artifactId: parseId('artifact', `ART-${randomUUID()}`),
        outputs: node.id === 'specs' ? names.map((name) => `${prefix}/specs/${name}/spec.md`)
          : node.id === 'tasks' && input.verificationPlan ? [`${prefix}/tasks.md`, `${prefix}/verification.md`] : [`${prefix}/${node.id}.md`],
        captured: null,
      })),
    });
    const config = (await this.files.read(configPath))!;
    const identity = (await this.files.read(identityPath))!;
    return makeFilePlan({
      workspace, operation: 'draft', purpose: 'artifact-edit',
      guards: [{ path, digest: 'absent' }, { path: configPath, digest: config.digest }, { path: identityPath, digest: identity.digest }, ...baseline],
      mutations: [writeMutation(path, 'absent', yaml(metadata), 'configuration')],
    });
  }

  private async workflowSource(profile: 'standard' | 'compact'): Promise<string> {
    return readFile(new URL(`../../assets/workflows/${profile}/workflow.yaml`, import.meta.url), 'utf8');
  }

  async loadChange(slug: string, effects: readonly RequestedEffect[] = [], overlay: ReadonlyMap<ProjectPath, string> = new Map()) {
    return this.observeChange(slug, effects, overlay);
  }

  private async observeChange(slug: string, effects: readonly RequestedEffect[], overlay: ReadonlyMap<ProjectPath, string>, admittedSource?: ContentDigest) {
    const workspace = await this.initialized();
    const observations = new Map<ProjectPath, FileSnapshot | null>();
    const read = async (path: ProjectPath): Promise<FileSnapshot | null> => {
      if (observations.has(path)) return observations.get(path)!;
      const content = overlay.get(path);
      const file = content === undefined ? await this.files.read(path) : { path, content, digest: digestContent(content) };
      observations.set(path, file);
      return file;
    };
    await read(configPath);
    await read(identityPath);
    const metadataFile = await read(metadataPath(slug));
    if (metadataFile === null) throw new WorkflowError('not-found', 'Change metadata was not found.');
    const metadata = parseChangeMetadata(parseProjectMetadata(metadataFile.content));
    if (metadata.slug !== slug) throw new WorkflowError('conflict', 'Change metadata does not match its selected directory.');
    const workflowSource = await this.workflowSource(metadata.profile);
    const workflow = parseArtifactWorkflow(workflowSource);
    const sources = await Promise.all(metadata.sourcePaths.map(async (path) => ({ path, digest: (await read(path))?.digest ?? 'absent' })));
    const sourceRevision = digestContent(JSON.stringify(sources));
    const principles = await read(principlesPath);
    const documents: MarkdownSource[] = [];
    const snapshots: ArtifactSnapshot[] = [];
    const uncaptured: ArtifactNodeId[] = [];
    for (const node of metadata.nodes) {
      const files = (await Promise.all(node.outputs.map(read))).filter((file): file is FileSnapshot => file !== null);
      documents.push(...files.map(({ path, content }) => ({ path, content })));
      if (node.captured === null) {
        if (files.length > 0) uncaptured.push(node.node);
        continue;
      }
      if (files.length === 0) continue;
      const snapshot = captureArtifactSnapshot({ contractVersion: 1, id: node.artifactId, node: node.node, files: files.map(({ path, content }) => ({ path, content })), dependencies: node.captured.dependencies });
      snapshots.push({ ...snapshot, files: snapshot.files.map((file) => ({ ...file, digest: node.captured?.files.find((entry) => entry.path === file.path)?.digest ?? file.digest })) });
    }
    const validation = parseMarkdownSet([...documents, ...(principles === null ? [] : [{ path: principles.path, content: principles.content }])]);
    const parsed = validation.state === 'valid' ? validation.documents : validation.parsedDocuments;
    const analysis = analyzeDocuments(validation.state === 'valid' ? parsed : [], metadata.questions);
    const assess = (source: ContentDigest) => assessArtifactReadiness({
      changeId: metadata.id, workflowSource, expectedWorkflow: metadata.workflowRevision, sourceRevision: source,
      bindings: metadata.nodes.map((node) => ({ node: node.node, artifactId: node.artifactId, declaredOutputs: node.outputs, applicability: node.applicability ?? { state: 'required' } })),
      snapshots,
    });
    const revisions: RevisionBinding = {
      workspace, changeId: metadata.id, source: sourceRevision, effects: digestEffectScope(effects),
      specification: digestContent(JSON.stringify(parsed.filter((document) => document.kind !== 'tasks').map((document) => ({ path: document.path, digest: document.rawRevision })))),
      tasks: digestContent(JSON.stringify(parsed.filter((document) => document.kind === 'tasks').map((document) => ({ path: document.path, digest: document.rawRevision })))),
      workflow: digestContent(JSON.stringify({
        workflow: workflow.revision, id: metadata.id, nodes: metadata.nodes, sourcePaths: metadata.sourcePaths,
        questions: metadata.questions, principles: principles?.digest ?? 'absent',
      })),
    };
    const origins = new Set<ContentDigest>([admittedSource ?? sourceRevision]);
    const applicabilitySource = metadata.nodes.find((node) => node.applicability !== undefined)?.applicability?.sourceRevision;
    if (applicabilitySource !== undefined && !origins.has(applicabilitySource) && this.store !== undefined) {
      const runs = await this.store.listRuns();
      if (runs.status !== 'ok') throw new WorkflowError('persistence-failed', 'Cannot establish admitted source-evolution provenance.');
      const matching = runs.value.filter((run) => run.quiescence === 'confirmed' && ['paused', 'quiesced'].includes(run.state) &&
        sameRevisionBinding({ ...revisions, effects: run.revisions.effects }, run.revisions));
      for (const run of matching) {
        const original = run.admissions?.[0]?.workOrder.sourceBefore;
        if (original !== undefined) origins.add(original);
      }
    }
    if (applicabilitySource !== undefined && !origins.has(applicabilitySource)) {
      const transitions: { before: ContentDigest; after: ContentDigest }[] = [];
      for (const plan of await this.files.committedFilePlans()) {
        if (plan.request.purpose !== 'source-apply' || plan.request.binding.kind !== 'review' ||
            plan.sourcePatch?.slug !== metadata.slug ||
            !sameRevisionBinding({ ...plan.request.binding.revisions, source: revisions.source, effects: revisions.effects }, revisions)) continue;
        const before = metadata.sourcePaths.map((path) => {
          const guard = plan.guards.find((guard) => guard.path === path);
          if (guard === undefined) throw new WorkflowError('persistence-failed', 'Source-apply provenance is missing an observed source path.');
          return { path, digest: guard.digest };
        });
        if (digestContent(JSON.stringify(before)) !== plan.request.binding.revisions.source) {
          throw new WorkflowError('persistence-failed', 'Source-apply provenance has inconsistent source observations.');
        }
        const after = before.map((file) => {
          const mutation = plan.mutations.find((mutation) => mutation.effect.path === file.path);
          return { path: file.path, digest: mutation?.effect.kind === 'file-write' ? mutation.effect.proposed : file.digest };
        });
        transitions.push({ before: plan.request.binding.revisions.source, after: digestContent(JSON.stringify(after)) });
      }
      for (let step = 0; step < transitions.length; step += 1) {
        const count = origins.size;
        for (const transition of transitions) if (origins.has(transition.after)) origins.add(transition.before);
        if (origins.size === count) break;
      }
    }
    const readiness = assess(applicabilitySource !== undefined && origins.has(applicabilitySource)
      ? applicabilitySource : admittedSource ?? sourceRevision);
    return {
      metadata, metadataFile, workspace, documents, validation, analysis, readiness, revisions, uncaptured,
      guards: [...observations].map(([path, file]): FileGuard => ({ path, digest: file?.digest ?? 'absent' })),
      implementationReady: validation.state === 'valid' && readiness.next.state === 'all-current' &&
        analysis.coverage.length === 0 && analysis.clarificationBlockers.length === 0,
      sourceScope: { kind: 'explicit-file-set' as const, paths: metadata.sourcePaths },
    };
  }

  async instructions(slug: string, selected?: string) {
    const change = await this.loadChange(slug);
    const node = selected === undefined
      ? (change.readiness.next.state === 'ready' ? change.readiness.next.node : null) : parseArtifactNodeId(selected);
    const definition = change.metadata.nodes.find((entry) => entry.node === node);
    if (selected !== undefined && definition === undefined) throw new ContractError('node', 'unknown artifact node');
    return {
      next: change.readiness.next, selected: definition?.node ?? null, stop: 'one-ready-artifact', templateVersion: ARTIFACT_TEMPLATE_VERSION,
      authorityIssued: false, implementationStarted: false,
      templates: definition?.outputs.map((path) => ({
        path, content: renderArtifactTemplate({
          kind: path.endsWith('/verification.md') ? 'verification' : definition.node as 'proposal' | 'specs' | 'design' | 'tasks',
          id: `ART-${randomUUID()}`, changeId: change.metadata.id, compact: change.metadata.profile === 'compact',
          externalChecks: definition.node === 'tasks' && definition.outputs.length === 2,
        }),
      })) ?? [],
      guidance: 'Edit the complete declared output set, then preview capture. Templates remain structurally incomplete and confer no approval.',
    };
  }

  async observeExecution(slug: string, work: WorkOrder, phase: 'before' | 'after') {
    if (await this.files.read(parseProjectPath('.missionspec/transaction.lock')) !== null) {
      throw new WorkflowError('conflict', 'A local file transaction is holding the workspace writer lock.');
    }
    const durable = this.store === undefined ? undefined : await this.store.readRun(work.runId);
    if (durable !== undefined && durable.status !== 'ok') throw new WorkflowError('persistence-failed', 'Execution applicability provenance is unavailable.');
    const originalSource = durable?.status === 'ok' ? durable.value?.snapshot.admissions?.[0]?.workOrder.sourceBefore : undefined;
    const change = await this.observeChange(slug, work.effects, new Map(), originalSource ?? (phase === 'after' ? work.sourceBefore : undefined));
    const task = change.analysis.tasks.find((entry) => entry.id === work.task.id);
    if (task === undefined || task.writeScope.some((path) => !change.metadata.sourcePaths.includes(path))) {
      throw new WorkflowError('scope-exceeded', 'Execution requires a declared task and an explicit live observation of every writable source path.');
    }
    for (const effect of work.effects) {
      if (effect.kind === 'check-execute') {
        const check = change.analysis.checks.find((entry) => entry.id === effect.checkId);
        if (check?.kind !== 'executed' || check.definition !== effect.definition || !task.checks.includes(effect.checkId)) {
          throw new WorkflowError('check-unqualified', 'The requested executed check does not match this task and its current definition.');
        }
      } else if (effect.kind === 'file-write' || effect.kind === 'file-remove') {
        if (effect.purpose !== 'source' || !task.writeScope.includes(effect.path)) throw new WorkflowError('scope-exceeded', 'A requested file effect is outside the task source scope.');
        const actual = (await this.files.read(effect.path))?.digest ?? 'absent';
        const proposed = effect.kind === 'file-write' ? effect.proposed : 'absent';
        if (actual !== effect.expected && !(phase === 'after' && actual === proposed)) {
          throw new WorkflowError('scope-exceeded', 'Observed file bytes are outside the exact approved before/after effect scope.');
        }
      }
    }
    const reconstructedBefore = digestContent(JSON.stringify(change.metadata.sourcePaths.map((path) => {
      const effect = work.effects.find((effect) => (effect.kind === 'file-write' || effect.kind === 'file-remove') && effect.path === path);
      return { path, digest: effect?.kind === 'file-write' || effect?.kind === 'file-remove'
        ? effect.expected : change.guards.find((guard) => guard.path === path)!.digest };
    })));
    if (reconstructedBefore !== work.sourceBefore) {
      throw new WorkflowError('scope-exceeded', 'A selected source outside the admitted exact file effects changed.');
    }
    return { revisions: change.revisions, task, ready: change.implementationReady, checks: change.analysis.checks };
  }

  async verificationGaps(slug: string) {
    const change = await this.loadChange(slug);
    return assessVerification({
      revisions: change.revisions, analysis: change.analysis,
      structurallyReady: change.implementationReady, observations: [],
    });
  }

  async previewArtifact(slug: string, selected: string, files: readonly MarkdownSource[], options: {
    readonly mode?: 'draft' | 'capture' | 'revise'; readonly overlay?: ReadonlyMap<ProjectPath, string>;
  } = {}): Promise<FilePlan> {
    const change = await this.loadChange(slug, [], options.overlay);
    const node = change.metadata.nodes.find((entry) => entry.node === parseArtifactNodeId(selected));
    if (node === undefined) throw new ContractError('node', 'unknown artifact node');
    const mode = options.mode ?? 'capture';
    const workflow = parseArtifactWorkflow(await this.workflowSource(change.metadata.profile));
    const predecessors = workflow.nodes.find((entry) => entry.id === node.node)!.dependsOn;
    const dependencies = predecessors.map((id) => {
      const assessment = change.readiness.assessments.find((entry) => entry.node === id)!;
      if (!['valid', 'not-applicable'].includes(assessment.readiness) || assessment.revision === null) throw new WorkflowError('conflict', 'Required predecessors must be captured and current before drafting or revision.');
      return { artifactId: assessment.artifactId, revision: assessment.revision };
    });
    if (files.length !== node.outputs.length || unique(files.map((file) => file.path), 'files').some((file) => !node.outputs.includes(file))) {
      throw new ContractError('files', 'supply the exact complete output set of one artifact');
    }
    if (node.applicability !== undefined) throw new WorkflowError('conflict', 'Review design as required before capturing content.');
    if (mode === 'draft' && node.outputs.some((path) => change.guards.find((guard) => guard.path === path)?.digest !== 'absent')) {
      throw new WorkflowError('conflict', 'Draft creation does not overwrite existing files; explicitly preview capture or revise.');
    }
    if (mode !== 'draft') {
      const retained = change.documents.filter((document) => !node.outputs.includes(document.path) &&
        change.metadata.nodes.some((entry) => entry.captured !== null && entry.outputs.includes(document.path)));
      const validation = parseMarkdownSet([...retained, ...files]);
      if (validation.state !== 'valid') throw new WorkflowError('invalid-input', 'Artifact content or typed references are invalid. Validate the proposed document set.');
      for (const file of files) {
        const parsed = validation.documents.find((document) => document.path === file.path)!;
        const expectedKind = node.node === 'tasks' && file.path.endsWith('/verification.md') ? 'verification' : node.node;
        if (parsed.kind !== expectedKind || parsed.changeId !== change.metadata.id) throw new WorkflowError('scope-exceeded', 'Artifact kind or change identity differs from its declared scope.');
        if (parsed.kind === 'tasks' && change.metadata.profile === 'compact' && !parsed.sections.some((section) => section.name === 'Design')) {
          throw new WorkflowError('invalid-input', 'Compact tasks require the combined Design section.');
        }
      }
    }
    const metadata = parseChangeMetadata({
      ...change.metadata, promotedContent: null,
      nodes: change.metadata.nodes.map((entry) => entry.node === node.node ? {
        ...entry, captured: mode === 'draft' ? null : {
          files: files.map((file) => ({ path: file.path, digest: digestContent(file.content) })), dependencies,
        },
      } : entry),
    });
    const mutations = [
      ...files.map((file) => writeMutation(file.path, change.guards.find((guard) => guard.path === file.path)!.digest, file.content, 'artifact')),
      writeMutation(change.metadataFile.path, change.metadataFile.digest, yaml(metadata), 'configuration'),
    ];
    return makeFilePlan({ workspace: change.workspace, guards: change.guards, mutations, operation: mode === 'revise' ? 'revise' : 'draft', purpose: 'artifact-edit' });
  }

  async previewDraftAll(slug: string, drafts: Readonly<Record<string, readonly MarkdownSource[]>>) {
    const initial = await this.loadChange(slug);
    const overlay = new Map<ProjectPath, string>();
    const mutations = new Map<ProjectPath, FileMutation>();
    const completed: string[] = [];
    let stop = 'required-drafts-complete';
    for (let step = 0; step < 4; step += 1) {
      const current = await this.loadChange(slug, [], overlay);
      if (current.readiness.next.state === 'all-current') break;
      const candidates = current.readiness.next.state === 'ready' ? [current.readiness.next.node]
        : current.readiness.next.state === 'selection-required' ? current.readiness.next.candidates : [];
      const node = candidates.find((candidate) => Object.hasOwn(drafts, candidate));
      if (node === undefined) { stop = 'review-blocker'; break; }
      const plan = await this.previewArtifact(slug, node, drafts[node]!, { mode: 'capture', overlay });
      for (const mutation of plan.mutations) {
        if (mutation.effect.kind !== 'file-write' || !('content' in mutation)) throw new ContractError('draft-all', 'unexpected removal');
        overlay.set(mutation.effect.path, mutation.content);
        const original = initial.guards.find((guard) => guard.path === mutation.effect.path)!.digest;
        mutations.set(mutation.effect.path, writeMutation(mutation.effect.path, original, mutation.content, mutation.effect.purpose));
      }
      completed.push(node);
    }
    return {
      stop, completed, implementationStarted: false,
      plan: mutations.size === 0 ? null : makeFilePlan({
        workspace: initial.workspace, guards: initial.guards, mutations: [...mutations.values()],
        operation: 'draft-all', purpose: 'artifact-edit',
      }),
    };
  }

  async previewClarification(slug: string, questions: readonly LocalQuestion[]): Promise<FilePlan> {
    const change = await this.loadChange(slug);
    const metadata = parseChangeMetadata({ ...change.metadata, questions });
    return makeFilePlan({
      workspace: change.workspace, guards: change.guards, operation: 'clarify', purpose: 'artifact-edit',
      mutations: [writeMutation(change.metadataFile.path, change.metadataFile.digest, yaml(metadata), 'configuration')],
    });
  }

  async previewApplicability(slug: string, reason: string | null): Promise<FilePlan> {
    const change = await this.loadChange(slug);
    if (change.metadata.profile !== 'compact') throw new WorkflowError('invalid-input', 'Only Compact permits an explicit separate-design applicability decision.');
    const design = change.metadata.nodes.find((node) => node.node === 'design')!;
    if (design.outputs.some((path) => change.guards.find((guard) => guard.path === path)?.digest !== 'absent')) {
      throw new WorkflowError('conflict', 'Existing design content must be preserved; it cannot be silently skipped.');
    }
    const workflow = parseArtifactWorkflow(await this.workflowSource('compact'));
    const dependencies = workflow.nodes.find((node) => node.id === 'design')!.dependsOn.map((id) => {
      const assessment = change.readiness.assessments.find((node) => node.node === id)!;
      if (assessment.readiness !== 'valid' || assessment.revision === null) throw new WorkflowError('conflict', 'Capture current design predecessors first.');
      return { artifactId: assessment.artifactId, revision: assessment.revision };
    });
    const metadata = parseChangeMetadata({ ...change.metadata, promotedContent: null, nodes: change.metadata.nodes.map((node) => {
      if (node.node !== 'design') return node;
      const { applicability: _old, ...base } = node;
      return { ...base, ...(reason === null ? {} : { applicability: {
        state: 'not-applicable', reason, sourceRevision: change.revisions.source, dependencies,
      } }) };
    }) });
    return makeFilePlan({ workspace: change.workspace, guards: change.guards, operation: 'revise', purpose: 'artifact-edit',
      mutations: [writeMutation(change.metadataFile.path, change.metadataFile.digest, yaml(metadata), 'configuration')] });
  }

  async previewCapture(slug: string, kind: 'discovery' | 'principles', content: string): Promise<FilePlan> {
    if (kind === 'principles') return (await this.previewPrinciples(content)).plan;
    const change = await this.loadChange(slug);
    const path = parseProjectPath(`missionspec/changes/${change.metadata.slug}/discovery.md`);
    const parsed = parseMarkdownDocument({ path, content });
    if (parsed.state !== 'parsed' || parsed.document.kind !== kind || parsed.document.changeId !== change.metadata.id) {
      throw new WorkflowError('invalid-input', 'Capture requires valid Markdown in the exact project or change scope.');
    }
    const file = await this.files.read(path);
    const guards = change.guards.filter((guard) => guard.path !== path);
    guards.push({ path, digest: file?.digest ?? 'absent' });
    return makeFilePlan({
      workspace: change.workspace, guards, operation: 'discover', purpose: 'artifact-edit',
      mutations: [writeMutation(path, file?.digest ?? 'absent', content, 'artifact')],
    });
  }

  async previewPrinciples(content: string) {
    const workspace = await this.initialized();
    const parsed = parseMarkdownDocument({ path: principlesPath, content });
    if (parsed.state !== 'parsed' || parsed.document.kind !== 'principles') {
      throw new WorkflowError('invalid-input', 'Project principles require valid project-wide Markdown, with no runtime grants.');
    }
    const current = await this.files.read(principlesPath);
    const guards: FileGuard[] = [{ path: principlesPath, digest: current?.digest ?? 'absent' }];
    for (const path of [configPath, identityPath]) guards.push({ path, digest: (await this.files.read(path))!.digest });
    const project = await this.project();
    return {
      affectedChanges: project.state === 'initialized' ? project.changes : [],
      plan: makeFilePlan({
        workspace, guards, operation: 'principles', purpose: 'artifact-edit',
        mutations: [writeMutation(principlesPath, current?.digest ?? 'absent', content, 'artifact')],
      }),
    };
  }

  private runtime(): RuntimeStorePort {
    if (this.store === undefined) throw new WorkflowError('capability-unavailable', 'Compose a workspace-bound runtime store explicitly for evidence and acceptance.');
    return this.store;
  }

  async readObservation(id: EvidenceId): Promise<CheckObservation> {
    const result = await this.runtime().readEvidence(parseId('evidence', id));
    if (result.status !== 'ok' || result.value === null) throw new WorkflowError('evidence-unavailable', 'Referenced evidence is unavailable.');
    const evidence = result.value;
    if (evidence.storage.state !== 'retained') return { state: 'unavailable', checkId: evidence.checkId, reason: 'Raw evidence is not retained.' };
    const raw = await this.files.read(evidence.storage.path);
    if (raw === null || raw.digest !== evidence.storage.digest) throw new WorkflowError('evidence-unavailable', 'Retained evidence bytes are absent or do not match their stored digest.');
    const envelope = record(JSON.parse(raw.content) as unknown, 'evidenceOutput', ['schemaVersion', 'evidenceId', 'basis', 'result', 'output']);
    if (envelope.schemaVersion !== 1 || envelope.evidenceId !== evidence.id || typeof envelope.output !== 'string') {
      throw new WorkflowError('evidence-unavailable', 'Retained check observation has an invalid envelope.');
    }
    return { state: 'observed', checkId: evidence.checkId, evidence,
      basis: oneOf(envelope.basis, ['executed', 'static-inspection', 'agent-review'], 'evidence.basis'),
      result: oneOf(envelope.result, ['passed', 'failed'], 'evidence.result') };
  }

  async verify(slug: string, runId: RunId, evidenceIds: readonly EvidenceId[]) {
    const store = this.runtime();
    const run = await store.readRun(parseId('run', runId));
    if (run.status !== 'ok' || run.value === null) throw new WorkflowError('evidence-unavailable', 'The selected durable run is unavailable.');
    const change = await this.observeChange(slug, [], new Map(), run.value.snapshot.admissions?.[0]?.workOrder.sourceBefore);
    const revisions = { ...change.revisions, effects: run.value.snapshot.revisions.effects };
    if (!sameRevisionBinding(revisions, run.value.snapshot.revisions) || run.value.snapshot.quiescence !== 'confirmed') {
      throw new WorkflowError('stale-revision', 'Run is not quiescent or no longer matches the live change and scoped source.');
    }
    unique(evidenceIds, 'evidenceIds');
    const recorded = await store.readRunEvidence(runId);
    if (recorded.status !== 'ok' || evidenceIds.some((id) => !recorded.value.includes(id))) {
      throw new WorkflowError('evidence-unavailable', 'The selected run does not contain the requested evidence references.');
    }
    const observations: CheckObservation[] = [];
    for (const id of evidenceIds) {
      observations.push(await this.readObservation(id));
    }
    const report = assessVerification({ revisions, analysis: change.analysis, structurallyReady: change.implementationReady, observations });
    return new LocalConvergence(this, this.authority).include(slug, report, change.analysis);
  }

  async previewAcceptance(slug: string, runId: RunId, evidenceIds: readonly EvidenceId[]) {
    const report = await this.verify(slug, runId, evidenceIds);
    if (report.acceptanceEligibility.state !== 'eligible-for-human-review') throw new WorkflowError('evidence-unavailable', 'Verification has blocking gaps; acceptance is unavailable.');
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'verify', purpose: 'acceptance', effects: [],
      binding: { kind: 'review', revisions: report.revisions, subject: digestContent(JSON.stringify({ runId, report })), effects: digestEffectScope([]) },
    });
    return { report, request };
  }

  async accept(slug: string, runId: RunId, evidenceIds: readonly EvidenceId[], approval: ApprovalReference): Promise<AcceptanceRecord> {
    const preview = await this.previewAcceptance(slug, runId, evidenceIds);
    await requireApproval(this.authority, approval, preview.request, this.now());
    return this.files.withRuntimeLock(async () => {
      await this.assertNoActiveRuns();
      const { report, request } = await this.previewAcceptance(slug, runId, evidenceIds);
      await requireApproval(this.authority, approval, request, this.now());
      if (report.acceptanceEligibility.state !== 'eligible-for-human-review') throw new WorkflowError('evidence-unavailable', 'Acceptance became ineligible.');
      const acceptance: AcceptanceRecord = {
        contractVersion: 1, state: 'accepted', revisions: report.revisions, source: report.source,
        evidence: report.acceptanceEligibility.evidence, approval,
      };
      await this.files.recordRuntime('audit', `acceptance-${randomUUID()}`, { request, approval, acceptance });
      const stored = await this.runtime().recordAcceptance(acceptance);
      if (stored.status !== 'ok') throw new WorkflowError('persistence-failed', 'Acceptance could not be durably recorded.');
      return acceptance;
    });
  }

  private async accepted(slug: string, reference: ApprovalReference) {
    const result = await this.runtime().readAcceptance(reference);
    if (result.status !== 'ok' || result.value === null) throw new WorkflowError('authority-required', 'A durable acceptance record is required.');
    const acceptance = result.value;
    const change = await this.loadChange(slug);
    if (!sameRevisionBinding({ ...change.revisions, effects: acceptance.revisions.effects }, acceptance.revisions)) {
      throw new WorkflowError('stale-revision', 'Acceptance no longer matches this workspace, change or source.');
    }
    for (const id of acceptance.evidence) {
      const evidence = await this.runtime().readEvidence(id);
      if (evidence.status !== 'ok' || evidence.value?.storage.state !== 'retained' ||
          (await this.files.read(evidence.value.storage.path))?.digest !== evidence.value.storage.digest) {
        throw new WorkflowError('evidence-unavailable', 'Accepted evidence must still be retained and intact for promotion.');
      }
      change.guards.push({ path: evidence.value.storage.path, digest: evidence.value.storage.digest });
    }
    const observations = await Promise.all(acceptance.evidence.map((id) => this.readObservation(id)));
    const report = assessVerification({ revisions: acceptance.revisions, analysis: change.analysis, structurallyReady: change.implementationReady, observations });
    const current = await new LocalConvergence(this, this.authority).include(slug, report, change.analysis);
    if (current.acceptanceEligibility.state !== 'eligible-for-human-review') {
      throw new WorkflowError('evidence-unavailable', 'Current verification or convergence blockers prevent promotion; historical acceptance is preserved.');
    }
    return { acceptance, change };
  }

  async previewPromotion(slug: string, acceptanceReference: ApprovalReference) {
    const { acceptance, change } = await this.accepted(slug, acceptanceReference);
    const mutations: FileMutation[] = [];
    const guards = [...change.guards];
    const conflicts: string[] = [];
    const baseline = [];
    const fullBaseline = new Map<ProjectPath, MarkdownSource>();
    for (const original of change.metadata.baseline) {
      if (((await this.files.read(original.path))?.digest ?? 'absent') !== original.digest) {
        conflicts.push(`Accepted baseline changed since the change was prepared: ${original.path}`);
      }
    }
    if (conflicts.length > 0) return { state: 'conflict' as const, conflicts, plan: null };
    for (const path of await this.baselinePaths()) {
      const file = await this.files.read(path);
      if (file === null) throw new WorkflowError('stale-revision', 'Baseline inventory changed while observing it.');
      const parsed = parseMarkdownDocument({ path, content: file.content });
      if (parsed.state !== 'parsed' || parsed.document.kind !== 'baseline') {
        throw new WorkflowError('invalid-input', 'Accepted baseline inventory contains an invalid project baseline document.');
      }
      fullBaseline.set(path, { path, content: file.content });
      if (!guards.some((guard) => guard.path === path)) guards.push({ path, digest: file.digest });
    }
    const contentRevision = digestContent(JSON.stringify(change.documents.filter((document) => document.path.includes('/specs/'))));
    for (const original of change.metadata.baseline) {
      const current = await this.files.read(original.path);
      if (!guards.some((guard) => guard.path === original.path)) guards.push({ path: original.path, digest: current?.digest ?? 'absent' });
      if ((current?.digest ?? 'absent') !== original.digest) {
        conflicts.push(`Accepted baseline changed since the change was prepared: ${original.path}`);
        continue;
      }
      if (change.metadata.promotedContent === contentRevision) { baseline.push(original); continue; }
      const deltaPath = original.path.replace('missionspec/specs/', `missionspec/changes/${change.metadata.slug}/specs/`);
      const source = change.documents.find((file) => file.path === deltaPath);
      if (source === undefined) throw new WorkflowError('conflict', 'The complete declared specs set is required for promotion.');
      const delta = parseMarkdownDocument(source);
      const existing = current === null ? null : parseMarkdownDocument({ path: current.path, content: current.content });
      if (delta.state !== 'parsed' || (existing !== null && existing.state !== 'parsed')) {
        throw new WorkflowError('invalid-input', 'Baseline or delta Markdown is invalid.');
      }
      const promotion = promoteBaseline({ path: original.path, delta: delta.document, baseline: existing?.document ?? null });
      conflicts.push(...promotion.conflicts);
      if (promotion.conflicts.length > 0) continue;
      if (promotion.content === null) {
        fullBaseline.delete(original.path);
        if (current !== null) mutations.push({ effect: { kind: 'file-remove', path: original.path, purpose: 'baseline', expected: current.digest } });
        baseline.push({ path: original.path, digest: 'absent' as const });
      } else {
        fullBaseline.set(original.path, { path: original.path, content: promotion.content });
        if (promotion.content !== current?.content) mutations.push(writeMutation(original.path, current?.digest ?? 'absent', promotion.content, 'baseline'));
        baseline.push({ path: original.path, digest: digestContent(promotion.content) });
      }
    }
    if (conflicts.length > 0) return { state: 'conflict' as const, conflicts, plan: null };
    if (parseMarkdownSet([...fullBaseline.values()]).state !== 'valid') {
      return { state: 'conflict' as const, conflicts: ['The promoted baseline set has duplicate identities or unresolved references.'], plan: null };
    }
    const metadata = { ...change.metadata, baseline, promotedContent: contentRevision };
    if (yaml(metadata) !== change.metadataFile.content) mutations.push(writeMutation(change.metadataFile.path, change.metadataFile.digest, yaml(metadata), 'configuration'));
    return {
      state: mutations.length === 0 ? 'already-synced' as const : 'ready' as const, conflicts: [],
      plan: mutations.length === 0 ? null : makeFilePlan({
        workspace: change.workspace, guards, mutations, operation: 'sync', purpose: 'promotion', revisions: acceptance.revisions,
      }),
    };
  }

  async commitPromotion(slug: string, acceptance: ApprovalReference, preview: FilePlan, approval: ApprovalReference) {
    const current = await this.previewPromotion(slug, acceptance);
    if (current.plan === null || current.plan.digest !== preview.digest) throw new WorkflowError('stale-revision', 'Promotion preview changed; review it again.');
    return this.files.commit(current.plan, approval);
  }

  async previewArchive(slug: string, outcome: 'accepted' | 'rejected' | 'cancelled' | 'incomplete', acceptance?: ApprovalReference) {
    oneOf(outcome, ['accepted', 'rejected', 'cancelled', 'incomplete'], 'outcome');
    await this.assertNoActiveRuns();
    let change = await this.loadChange(slug);
    let closureRevisions = change.revisions;
    if (outcome === 'accepted') {
      if (acceptance === undefined) throw new WorkflowError('authority-required', 'Accepted closure requires durable acceptance and separate promotion.');
      const promotion = await this.previewPromotion(slug, acceptance);
      if (promotion.state !== 'already-synced') throw new WorkflowError('conflict', 'Use the shared promotion preview and commit first; archive cannot bypass baseline conflicts.');
      const accepted = await this.accepted(slug, acceptance);
      change = accepted.change;
      closureRevisions = accepted.acceptance.revisions;
    }
    const timestamp = this.now();
    if (!/^\d{4}-\d{2}-\d{2}T/u.test(timestamp) || !Number.isFinite(Date.parse(timestamp))) {
      throw new WorkflowError('invalid-input', 'Archive requires a valid clock observation.');
    }
    const destination = `missionspec/changes/archive/${timestamp.slice(0, 10)}-${change.metadata.slug}`;
    if ((await this.files.list(parseProjectPath(destination))).length > 0) throw new WorkflowError('conflict', 'Archive destination is not empty.');
    const known = await this.fileTree(parseProjectPath(`missionspec/changes/${slug}`));
    if (known.includes(parseProjectPath(`missionspec/changes/${slug}/closure.json`))) {
      throw new WorkflowError('conflict', 'A user-owned closure.json would collide with the archive receipt; preserve it under another explicit name first.');
    }
    const guards = [...change.guards];
    const mutations: FileMutation[] = [];
    for (const path of known) {
      const file = await this.files.read(path);
      if (!guards.some((guard) => guard.path === path)) guards.push({ path, digest: file?.digest ?? 'absent' });
      if (file === null) continue;
      const target = parseProjectPath(`${destination}/${path.slice(`missionspec/changes/${slug}/`.length)}`);
      if (await this.files.read(target) !== null) throw new WorkflowError('conflict', 'Archive never overwrites files.');
      guards.push({ path: target, digest: 'absent' });
      mutations.push(writeMutation(target, 'absent', file.content, 'closure'), { effect: { kind: 'file-remove', purpose: 'closure', path, expected: file.digest } });
    }
    const manifest = parseProjectPath(`${destination}/closure.json`);
    guards.push({ path: manifest, digest: 'absent' });
    mutations.push(writeMutation(manifest, 'absent', json({
      schemaVersion: 1, changeId: change.metadata.id, outcome, acceptance: acceptance ?? null,
      notice: 'Preserved change documents are historical intent, not proof of execution.',
    }), 'closure'));
    return makeFilePlan({ workspace: change.workspace, guards, mutations, operation: 'archive', purpose: 'closure', revisions: closureRevisions });
  }

  async commitArchive(slug: string, outcome: 'accepted' | 'rejected' | 'cancelled' | 'incomplete', preview: FilePlan, approval: ApprovalReference, acceptance?: ApprovalReference) {
    const current = await this.previewArchive(slug, outcome, acceptance);
    if (current.digest !== preview.digest) throw new WorkflowError('stale-revision', 'Archive preview changed; review it again.');
    return this.files.commit(current, approval);
  }
}
