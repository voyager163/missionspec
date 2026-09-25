import { digestApprovalRequest, parseApprovalRequest, type ApprovalReference, type ApprovalRequest } from '../kernel/authority.js';
import { digestEffectScope } from '../kernel/effects.js';
import { parseId, parseProjectPath, type ProjectPath } from '../kernel/identifiers.js';
import { digestContent, parseDigest, sameWorkspaceBinding, type ContentDigest } from '../kernel/revisions.js';
import { array, ContractError, oneOf, record, text, unique } from '../kernel/validation.js';
import type { ContextAvailability, ContextObservation, ContextProviderPort, LocalAuthorityPort } from '../ports/contracts.js';
import { requireApproval } from './authority.js';
import { WorkflowError } from './errors.js';
import type { LocalWorkflow } from './local-workflow.js';

type AvailableContext = Extract<ContextAvailability, { state: 'available' | 'partial' }>;
type UnavailableContext = Exclude<ContextAvailability, AvailableContext>;

export interface ContextPreview {
  readonly schemaVersion: 1;
  readonly state: 'ready';
  readonly availability: AvailableContext;
  readonly query: string;
  readonly scope: readonly { readonly path: ProjectPath; readonly digest: ContentDigest }[];
  readonly allowRemoteProcessing: boolean;
  readonly processing: 'local-only' | 'remote';
  readonly request: ApprovalRequest;
}

export type ContextPreviewResult = ContextPreview | {
  readonly state: 'not-ready'; readonly availability: UnavailableContext;
};

export interface ContextConsumptionResult {
  readonly availability: ContextAvailability;
  readonly observations: readonly ContextObservation[];
}

function unavailable(state: UnavailableContext['state']): UnavailableContext {
  const messages = {
    absent: 'No optional context provider is connected.',
    disabled: 'Optional context consumption is disabled.',
    incompatible: 'The optional provider does not satisfy the local consumption contract.',
    unavailable: 'Optional context is unavailable; no fallback or indexing was started.',
  };
  return Object.freeze({ state, reason: messages[state] });
}

function parseAvailability(value: unknown): ContextAvailability {
  const input = record(value, 'context.availability', ['state', 'reason', 'providerId', 'adapterContractVersion', 'capabilities']);
  const state = oneOf(input.state, ['absent', 'disabled', 'incompatible', 'unavailable', 'available', 'partial'], 'context.state');
  if (state !== 'available' && state !== 'partial') {
    record(value, 'context.availability', ['state', 'reason']);
    text(input.reason, 'context.reason');
    return unavailable(state);
  }
  record(value, 'context.availability', ['state', 'providerId', 'adapterContractVersion', 'capabilities']);
  if (input.adapterContractVersion !== 1) return unavailable('incompatible');
  const capabilities = unique(array(input.capabilities, 'context.capabilities',
    (capability) => oneOf(capability, ['search', 'retrieve'], 'context.capability')), 'context.capabilities');
  if (!capabilities.includes('search')) return unavailable('incompatible');
  return Object.freeze({
    state, providerId: parseId('provider', input.providerId), adapterContractVersion: 1, capabilities,
  });
}

export class ContextService {
  private readonly enabled: boolean;
  private readonly processing: 'local-only' | 'remote';
  private readonly now: () => string;

  constructor(
    readonly workflow: LocalWorkflow,
    private readonly authority: LocalAuthorityPort,
    private readonly provider: ContextProviderPort | null,
    options: { readonly enabled: boolean; readonly processing: 'local-only' | 'remote'; readonly now?: () => string },
  ) {
    if (typeof options.enabled !== 'boolean') throw new ContractError('context.enabled', 'expected an explicit boolean');
    this.enabled = options.enabled;
    this.processing = oneOf(options.processing, ['local-only', 'remote'], 'context.processing');
    this.now = options.now ?? (() => new Date().toISOString());
  }

  async inspect(): Promise<ContextAvailability> {
    if (this.provider === null) return unavailable('absent');
    if (!this.enabled) return unavailable('disabled');
    try {
      const result = record(await this.provider.inspect(), 'context.inspection', ['status', 'value', 'error', 'reconciliationRequired']);
      if (result.status !== 'ok') return unavailable('unavailable');
      record(result, 'context.inspection', ['status', 'value']);
      return parseAvailability(result.value);
    } catch {
      return unavailable('unavailable');
    }
  }

  private async observe(paths: readonly ProjectPath[]) {
    const scope = [];
    for (const path of paths) {
      const file = await this.workflow.files.read(path);
      if (file === null) throw new WorkflowError('not-found', 'Every selected context path must be an observed existing file.');
      scope.push(Object.freeze({ path, digest: file.digest }));
    }
    return Object.freeze(scope);
  }

  async preview(value: unknown): Promise<ContextPreviewResult> {
    const input = record(value, 'context', ['query', 'paths', 'allowRemoteProcessing']);
    const query = text(input.query, 'context.query', 4096);
    if (!query.isWellFormed()) throw new ContractError('context.query', 'expected well-formed UTF-8 text');
    const paths = unique(array(input.paths, 'context.paths', parseProjectPath, 1), 'context.paths');
    unique(paths.map((path) => path.toLowerCase()), 'context.paths');
    if (paths.length > 64 || paths.some((path) =>
      path.startsWith('.missionspec/') || path.startsWith('.git/') || path === '.git')) {
      throw new ContractError('context.paths', 'select at most 64 exact non-runtime, non-Git source paths');
    }
    if (typeof input.allowRemoteProcessing !== 'boolean') {
      throw new ContractError('context.allowRemoteProcessing', 'explicit processing permission is required');
    }
    const availability = await this.inspect();
    if (availability.state !== 'available' && availability.state !== 'partial') {
      return Object.freeze({ state: 'not-ready', availability: unavailable(availability.state) });
    }
    if (this.processing === 'remote' && !input.allowRemoteProcessing) {
      throw new WorkflowError('scope-exceeded', 'This configured adapter uses remote processing; it cannot consume a local-only scope.');
    }
    const project = await this.workflow.project();
    if (project.state !== 'initialized' || project.pendingTransactions.length > 0) {
      throw new WorkflowError('conflict', 'Context consumption requires an initialized workspace without unfinished file transactions.');
    }
    const scope = await this.observe(paths);
    const effects = [{
      kind: 'context-consume' as const, providerId: availability.providerId, paths,
      allowRemoteProcessing: input.allowRemoteProcessing,
    }];
    const request = parseApprovalRequest({
      contractVersion: 1, state: 'untrusted-request', operation: 'discover', purpose: 'context-consumption',
      binding: {
        kind: 'project', workspace: project.workspace, effects: digestEffectScope(effects),
        revision: digestContent(JSON.stringify({ query, scope, availability, processing: this.processing })),
      },
      effects,
    });
    return Object.freeze({
      schemaVersion: 1, state: 'ready', availability, query, scope,
      allowRemoteProcessing: input.allowRemoteProcessing, processing: this.processing, request,
    });
  }

  private async revalidate(value: unknown): Promise<ContextPreview> {
    const input = record(value, 'context.preview', [
      'schemaVersion', 'state', 'availability', 'query', 'scope', 'allowRemoteProcessing', 'processing', 'request',
    ]);
    if (input.schemaVersion !== 1 || input.state !== 'ready' || input.processing !== this.processing) {
      throw new ContractError('context.preview', 'unsupported or mismatched consumption preview');
    }
    const availability = parseAvailability(input.availability);
    const request = parseApprovalRequest(input.request);
    const scope = array(input.scope, 'context.scope', (entry) => {
      const observed = record(entry, 'context.scope.file', ['path', 'digest']);
      return { path: parseProjectPath(observed.path), digest: parseDigest(observed.digest) };
    }, 1);
    const current = await this.preview({
      query: input.query, paths: scope.map((file) => file.path), allowRemoteProcessing: input.allowRemoteProcessing,
    });
    if (current.state !== 'ready') throw new WorkflowError('provider-unavailable', 'The optional provider is no longer available.');
    if (JSON.stringify(current.scope) !== JSON.stringify(scope) ||
      JSON.stringify(current.availability) !== JSON.stringify(availability) ||
      digestApprovalRequest(current.request) !== digestApprovalRequest(request)) {
      throw new WorkflowError('stale-revision', 'Query, source content, provider compatibility or workspace changed after preview.');
    }
    return current;
  }

  async confirm(preview: ContextPreview) {
    const current = await this.revalidate(preview);
    return this.authority.requestConfirmation(current.request, {
      context: { query: current.query, scope: current.scope, provider: current.availability.providerId,
        processing: current.processing, allowRemoteProcessing: current.allowRemoteProcessing },
    });
  }

  async consume(preview: ContextPreview, approval: ApprovalReference): Promise<ContextConsumptionResult> {
    const current = await this.revalidate(preview);
    await requireApproval(this.authority, approval, current.request, this.now());
    const workspace = await this.workflow.files.identity();
    if (workspace === null || current.request.binding.kind !== 'project' ||
      !sameWorkspaceBinding(workspace, current.request.binding.workspace) ||
      JSON.stringify(await this.observe(current.scope.map((file) => file.path))) !== JSON.stringify(current.scope)) {
      throw new WorkflowError('stale-revision', 'The observed context scope changed during admission.');
    }
    let result: ContextConsumptionResult;
    try {
      if (this.provider === null) throw new ContractError('context.provider', 'provider disappeared');
      const outcome = record(await this.provider.query({
        query: current.query, sourceScope: current.scope.map((file) => file.path), approval,
      }), 'context.result', ['status', 'value', 'error', 'reconciliationRequired']);
      if (outcome.status !== 'ok') throw new ContractError('context.result', 'provider did not supply a successful response');
      record(outcome, 'context.result', ['status', 'value']);
      const value = record(outcome.value, 'context.result.value', ['availability', 'observations']);
      const availability = parseAvailability(value.availability);
      if (availability.state !== 'available' && availability.state !== 'partial') {
        result = Object.freeze({ availability, observations: Object.freeze([]) });
      } else {
        if (availability.providerId !== current.availability.providerId) throw new ContractError('context.provider', 'provider identity changed');
        if (!Array.isArray(value.observations) || value.observations.length > 64) {
          throw new ContractError('context.observations', 'provider response exceeds the bounded observation count');
        }
        const observations = array(value.observations, 'context.observations', (entry): ContextObservation => {
          const observation = record(entry, 'context.observation', ['trust', 'text', 'providerId', 'reference', 'contentDigest', 'freshness']);
          const body = text(observation.text, 'context.observation.text', 64_000);
          if (observation.trust !== 'untrusted-context' || !body.isWellFormed() ||
            parseId('provider', observation.providerId) !== availability.providerId ||
            parseDigest(observation.contentDigest) !== digestContent(body)) {
            throw new ContractError('context.observation', 'untrusted provenance and exact observation integrity are required');
          }
          return Object.freeze({
            trust: 'untrusted-context', text: body, providerId: availability.providerId,
            reference: text(observation.reference, 'context.reference', 1024), contentDigest: digestContent(body),
            freshness: oneOf(observation.freshness, ['current', 'stale', 'unknown'], 'context.freshness'),
          });
        });
        if (observations.length > 64 || observations.reduce((bytes, observation) =>
          bytes + Buffer.byteLength(observation.text), 0) > 256_000) {
          throw new ContractError('context.observations', 'provider response exceeds the bounded consumption limit');
        }
        result = Object.freeze({ availability, observations });
      }
    } catch {
      result = Object.freeze({ availability: unavailable('unavailable'), observations: Object.freeze([]) });
    }
    const afterWorkspace = await this.workflow.files.identity();
    if (afterWorkspace === null || !sameWorkspaceBinding(afterWorkspace, workspace) ||
      JSON.stringify(await this.observe(current.scope.map((file) => file.path))) !== JSON.stringify(current.scope)) {
      throw new WorkflowError('stale-revision', 'Source content changed while optional context was consumed.');
    }
    return result;
  }
}
