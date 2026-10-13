import type { ProposalRequest, RestrictedProposalHostPort } from '../../ports/contracts.js';
import type { ExternalSdkIdentity, NativeHostSetup } from './contracts.js';
import { NativeBridgeError, NATIVE_PROPOSAL_PINS } from './contracts.js';
import { proposalPrompt, runNativeProposal } from './proposal.js';

export interface ClaudeQueryOptions {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly pathToClaudeCodeExecutable: string;
  readonly model: string;
  readonly tools: [];
  readonly settingSources: [];
  readonly strictMcpConfig: true;
  readonly mcpServers: Readonly<Record<string, never>>;
  readonly permissionMode: 'default';
  readonly persistSession: false;
  readonly maxTurns: 1;
  readonly plugins: [];
  readonly hooks: Readonly<Record<string, never>>;
  readonly abortController: AbortController;
  readonly canUseTool: (name: string, input: unknown, options: unknown) => Promise<{ readonly behavior: 'deny'; readonly message: string }>;
  readonly stderr: (data: string) => void;
}

export interface ExternalClaudeQuery extends AsyncIterable<unknown> {
  interrupt(): Promise<unknown>;
  close(): void;
}

/** Bind this factory to the independently installed, exact pinned SDK. Never cast a module to this type. */
export interface ExternalClaudeSdk extends ExternalSdkIdentity {
  readonly query: (input: { readonly prompt: string; readonly options: ClaudeQueryOptions }) => ExternalClaudeQuery;
}

const restrictions = Object.freeze({
  tools: [], settingSources: [], strictMcpConfig: true, mcpServers: {}, permissionMode: 'default',
  persistSession: false, maxTurns: 1, plugins: [], hooks: {}, nativeOutputFormat: false,
});

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new NativeBridgeError('invalid-input', 'Malformed Claude protocol message.');
  return value as Record<string, unknown>;
}

function empty(value: unknown) { return Array.isArray(value) && value.length === 0; }

export class ClaudeProposalHost implements RestrictedProposalHostPort {
  readonly host = 'claude' as const;
  private readonly setup: NativeHostSetup;

  constructor(setup: NativeHostSetup, private readonly sdk: ExternalClaudeSdk) {
    this.setup = Object.freeze({ ...setup, environment: Object.freeze({ ...setup.environment }) });
  }

  propose(input: ProposalRequest, signal?: AbortSignal) {
    const setup = this.setup;
    return runNativeProposal(this.host, setup, this.sdk, input, signal, restrictions, async (request, operation, environment) => {
      const query = this.sdk.query({
        prompt: proposalPrompt(request),
        options: {
          cwd: setup.workingDirectory, env: Object.freeze({ ...environment }),
          pathToClaudeCodeExecutable: setup.executable, model: setup.model,
          tools: [], settingSources: [], strictMcpConfig: true, mcpServers: {},
          permissionMode: 'default', persistSession: false, maxTurns: 1, plugins: [], hooks: {},
          abortController: operation.controller,
          canUseTool: async () => {
            operation.fail(new NativeBridgeError('scope-exceeded', 'Claude requested an unexpected tool; it was denied.'));
            return { behavior: 'deny', message: 'MissionSpec permits inert text proposals only.' };
          },
          stderr: (data) => {
            try { operation.observe(data); }
            catch (error) { operation.fail(error instanceof NativeBridgeError ? error : new NativeBridgeError('invalid-input', 'Malformed Claude diagnostics.')); }
          },
        },
      });
      operation.onStop(() => query.interrupt());
      operation.onStop(() => query.close());
      let initialized = false;
      let result: string | undefined;
      for await (const raw of query) {
        operation.observe(raw);
        const message = object(raw);
        if (result !== undefined) throw new NativeBridgeError('invalid-input', 'Claude sent data after its terminal result.');
        if (message.type === 'system' && message.subtype === 'init') {
          if (initialized || message.claude_code_version !== NATIVE_PROPOSAL_PINS.claude.cli ||
              message.cwd !== setup.workingDirectory || message.permissionMode !== 'default' ||
              message.model !== setup.model ||
              !empty(message.tools) || !empty(message.mcp_servers) || !empty(message.plugins) || !empty(message.skills)) {
            throw new NativeBridgeError('scope-exceeded', 'Claude startup capabilities differ from the restricted configuration; managed or ambient policy must be reviewed externally.');
          }
          initialized = true;
        } else if (!initialized) {
          throw new NativeBridgeError('invalid-input', 'Claude must declare restricted startup capabilities before producing output.');
        } else if (message.type === 'assistant') {
          const assistant = object(message.message);
          if (!Array.isArray(assistant.content)) throw new NativeBridgeError('invalid-input', 'Malformed Claude assistant content.');
          for (const rawBlock of assistant.content) {
            const block = object(rawBlock);
            if (!['text', 'thinking', 'redacted_thinking'].includes(String(block.type))) {
              throw new NativeBridgeError('scope-exceeded', 'Claude emitted an unexpected tool or nontext content block.');
            }
            const value = block.type === 'text' ? block.text : block.type === 'thinking' ? block.thinking : block.data;
            if (typeof value !== 'string') throw new NativeBridgeError('invalid-input', 'Malformed Claude assistant text block.');
          }
        } else if (message.type === 'result' && message.subtype === 'success' && message.is_error === false &&
            message.num_turns === 1 && typeof message.result === 'string') {
          result = message.result;
        } else {
          throw new NativeBridgeError('scope-exceeded', 'Unexpected Claude request, event, or unsuccessful result; no proposal was accepted.');
        }
      }
      if (result === undefined) throw new NativeBridgeError('invalid-input', 'Claude ended without one successful terminal text result.');
      return result;
    });
  }
}
