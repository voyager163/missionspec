import type { ProposalRequest, RestrictedProposalHostPort } from '../../ports/contracts.js';
import { NativeBridgeError, NATIVE_PROPOSAL_PINS, type ExternalSdkIdentity, type NativeHostSetup } from './contracts.js';
import { proposalPrompt, runNativeProposal } from './proposal.js';

export interface CopilotClientOptions {
  readonly connection: { readonly kind: 'stdio'; readonly path: string; readonly env: Record<string, string> };
  readonly mode: 'empty';
  readonly workingDirectory: string;
  readonly baseDirectory: string;
  readonly builtinPluginDirectories: [];
  readonly logLevel: 'none';
  readonly useLoggedInUser: false;
  readonly enableRemoteSessions: false;
  readonly gitHubToken: string;
}

export interface CopilotSessionOptions {
  readonly model: string;
  readonly workingDirectory: string;
  readonly availableTools: [];
  readonly tools: [];
  readonly mcpServers: Record<string, never>;
  readonly customAgents: [];
  readonly skillDirectories: [];
  readonly pluginDirectories: [];
  readonly instructionDirectories: [];
  readonly additionalDirectories: [];
  readonly enableConfigDiscovery: false;
  readonly enableManagedSettings: false;
  readonly enableFileHooks: false;
  readonly enableHostGitOperations: false;
  readonly enableSessionStore: false;
  readonly enableSkills: false;
  readonly enableOnDemandInstructionDiscovery: false;
  readonly enableSessionTelemetry: false;
  readonly skipCustomInstructions: true;
  readonly skipEmbeddingRetrieval: true;
  readonly requestExtensions: false;
  readonly requestCanvasRenderer: false;
  readonly enableMcpApps: false;
  readonly manageScheduleEnabled: false;
  readonly streaming: false;
  readonly onPermissionRequest: (request: unknown, invocation: unknown) => { readonly kind: 'reject' };
  readonly onEvent: (event: unknown) => void;
}

export interface ExternalCopilotSession {
  sendAndWait(input: { readonly prompt: string }, timeout?: number): Promise<unknown>;
  abort(): Promise<void>;
  disconnect(): Promise<void>;
}

export interface ExternalCopilotClient {
  start(): Promise<void>;
  getStatus(): Promise<{ readonly version: string; readonly protocolVersion: number }>;
  createSession(options: CopilotSessionOptions): Promise<ExternalCopilotSession>;
  stop(): Promise<unknown>;
  forceStop(): Promise<void>;
}

export interface ExternalCopilotSdk extends ExternalSdkIdentity {
  readonly createClient: (options: CopilotClientOptions) => ExternalCopilotClient;
}

const restrictions = Object.freeze({
  mode: 'empty', availableTools: [], tools: [], mcpServers: {}, customAgents: [], plugins: [],
  configDiscovery: false, managedSettings: false, hooks: false, git: false, sessionStore: false,
  skills: false, memory: false, embedding: false, resume: false, continuePendingWork: false,
});

const passiveEvents = new Set([
  'session.start', 'session.idle', 'session.info', 'session.usage_info', 'session.model_change',
  'session.context_changed', 'user.message', 'system.message',
  'assistant.turn_start', 'assistant.turn_end', 'assistant.message', 'assistant.message_delta',
  'assistant.reasoning', 'assistant.reasoning_delta', 'assistant.usage',
]);

export class CopilotProposalHost implements RestrictedProposalHostPort {
  readonly host = 'copilot' as const;
  private readonly setup: NativeHostSetup;

  constructor(setup: NativeHostSetup, private readonly sdk: ExternalCopilotSdk) {
    this.setup = Object.freeze({ ...setup, environment: Object.freeze({ ...setup.environment }) });
  }

  propose(input: ProposalRequest, signal?: AbortSignal) {
    const setup = this.setup;
    return runNativeProposal(this.host, setup, this.sdk, input, signal, restrictions, async (request, operation, environment) => {
      const token = environment.COPILOT_GITHUB_TOKEN ?? environment.GH_TOKEN ?? environment.GITHUB_TOKEN;
      if (token === undefined) throw new NativeBridgeError('authority-required', 'An explicit Copilot authentication token is required.');
      const client = this.sdk.createClient({
        connection: { kind: 'stdio', path: setup.executable, env: { ...environment } },
        mode: 'empty', workingDirectory: setup.workingDirectory, baseDirectory: setup.homeDirectory,
        builtinPluginDirectories: [], logLevel: 'none', useLoggedInUser: false, enableRemoteSessions: false,
        gitHubToken: token,
      });
      let activeSession: ExternalCopilotSession | undefined;
      operation.onStop(() => activeSession?.abort());
      operation.onStop(() => activeSession?.disconnect());
      operation.onStop(() => client.forceStop());
      await client.start();
      if (operation.signal.aborted) operation.onStop(() => client.forceStop());
      operation.guard();
      const status = await client.getStatus();
      operation.observe(status);
      if (status.version !== NATIVE_PROPOSAL_PINS.copilot.cli || status.protocolVersion !== NATIVE_PROPOSAL_PINS.copilot.protocolVersion) {
        throw new NativeBridgeError('unsupported-version', 'The connected Copilot runtime does not match the pinned executable contract.');
      }
      operation.guard();
      const session = await client.createSession({
        model: setup.model, workingDirectory: setup.workingDirectory,
        availableTools: [], tools: [], mcpServers: {}, customAgents: [], skillDirectories: [],
        pluginDirectories: [], instructionDirectories: [], additionalDirectories: [],
        enableConfigDiscovery: false, enableManagedSettings: false, enableFileHooks: false,
        enableHostGitOperations: false, enableSessionStore: false, enableSkills: false,
        enableOnDemandInstructionDiscovery: false, enableSessionTelemetry: false,
        skipCustomInstructions: true, skipEmbeddingRetrieval: true, requestExtensions: false,
        requestCanvasRenderer: false, enableMcpApps: false, manageScheduleEnabled: false, streaming: false,
        onPermissionRequest: () => {
          operation.fail(new NativeBridgeError('scope-exceeded', 'Copilot requested an unexpected permission; it was rejected.'));
          return { kind: 'reject' };
        },
        onEvent: (event) => {
          try {
            operation.observe(event);
            if (typeof event !== 'object' || event === null || !('type' in event) ||
                typeof event.type !== 'string' || !passiveEvents.has(event.type)) {
              throw new NativeBridgeError('scope-exceeded', 'Unexpected Copilot request, tool, or lifecycle event; no proposal was accepted.');
            }
            if (event.type === 'assistant.message' && 'data' in event) {
              const data = event.data;
              if (typeof data !== 'object' || data === null ||
                  ('toolRequests' in data && (!Array.isArray(data.toolRequests) || data.toolRequests.length > 0))) {
                throw new NativeBridgeError('scope-exceeded', 'Copilot assistant output requested tools.');
              }
            }
          } catch (error) {
            operation.fail(error instanceof NativeBridgeError ? error : new NativeBridgeError('invalid-input', 'Malformed Copilot event.'));
          }
        },
      });
      activeSession = session;
      if (operation.signal.aborted) {
        operation.onStop(() => session.abort());
        operation.onStop(() => session.disconnect());
        operation.onStop(() => client.forceStop());
      }
      operation.guard();
      // This SDK timeout alone is not an abort. The outer operation separately interrupts and fences output.
      const response = await session.sendAndWait({ prompt: proposalPrompt(request) }, request.limits.timeoutMs);
      operation.observe(response);
      if (typeof response !== 'object' || response === null || !('type' in response) ||
          response.type !== 'assistant.message' || !('data' in response) ||
          typeof response.data !== 'object' || response.data === null ||
          !('content' in response.data) || typeof response.data.content !== 'string' ||
          ('toolRequests' in response.data && (!Array.isArray(response.data.toolRequests) || response.data.toolRequests.length > 0))) {
        throw new NativeBridgeError('invalid-input', 'Copilot did not return one bounded text-only assistant message.');
      }
      return response.data.content;
    });
  }
}
