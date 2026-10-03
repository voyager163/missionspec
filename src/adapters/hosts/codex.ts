import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import type { ProposalRequest, RestrictedProposalHostPort } from '../../ports/contracts.js';
import { NativeBridgeError, type NativeHostSetup } from './contracts.js';
import { ProposalOperation, PROPOSAL_INSTRUCTION, proposalPrompt, runNativeProposal } from './proposal.js';
import { startNativeProcess, stopNativeProcess } from './process.js';

const disabledFeatures = [
  'apps', 'connectors', 'enable_mcp_apps', 'codex_apps_mcp_2026_07_28',
  'shell_tool', 'unified_exec', 'experimental_use_unified_exec_tool', 'apply_patch_freeform',
  'browser_use', 'browser_use_external', 'computer_use', 'image_generation', 'imagegenext',
  'view_image', 'js_repl', 'code_mode', 'code_mode_host', 'code_mode_only',
  'multi_agent', 'multi_agent_v2', 'collab', 'collaboration_modes', 'multi_agent_mode',
  'send_async_message', 'enable_fanout', 'hooks', 'codex_hooks', 'plugin_hooks',
  'plugins', 'remote_plugin', 'recommended_plugins', 'plugin_sharing',
  'memories', 'memory_tool', 'external_agent_memory_import', 'external_migration',
  'skill_search', 'skill_mcp_dependency_install', 'skill_env_var_dependency_prompt',
  'web_search', 'web_search_cached', 'web_search_request', 'standalone_web_search',
  'search_tool', 'tool_search', 'tool_suggest', 'request_permissions', 'request_permissions_tool',
  'request_rule', 'default_mode_request_user_input', 'tool_call_mcp_elicitation',
  'auth_elicitation', 'remote_control', 'realtime_conversation', 'goals', 'worktrees',
  'shell_snapshot', 'shell_snapshot_v2', 'respect_system_proxy', 'unbounded_connection_retries',
  'deferred_executor', 'executor_capability_discovery', 'unavailable_dummy_tools', 'sleep_tool',
  'api_key_model_discovery', 'token_budget', 'context_management', 'current_time_reminder',
] as const;

const reviewedModels = Object.freeze(['gpt-5.4', 'gpt-5.5']);
// ToolsToml implements these gates, but the pinned ToolsV2 projection omits them.
const layerOnlyControls = Object.freeze(['tools.update_plan.enabled', 'tools.experimental_request_user_input.enabled']);
const reviewedProfile = Object.freeze({
  name: 'codex-0.155.1-api-catalog-no-tools-v1',
  nativeHome: 'isolated-home-directory',
  models: reviewedModels, layerOnlyControls, allowedNativeTools: Object.freeze([]),
});

/** Every control requires readback; the two ToolsV2 omissions require the active session layer. */
export const CODEX_RESTRICTED_CONFIG: Readonly<Record<string, unknown>> = Object.freeze({
  approval_policy: 'never', approvals_reviewer: 'user', sandbox_mode: 'read-only',
  web_search: 'disabled', mcp_servers: Object.freeze({}), plugins: Object.freeze({}), hooks: Object.freeze({}),
  cli_auth_credentials_store: 'ephemeral', model_provider: 'openai', model_providers: Object.freeze({}),
  'features.skip_host_skill_discovery': true,
  ...Object.fromEntries(disabledFeatures.map((feature) => [`features.${feature}`, false])),
  'skills.bundled.enabled': false, 'skills.include_instructions': false,
  'memories.generate_memories': false, 'memories.use_memories': false, 'memories.dedicated_tools': false,
  'apps._default.enabled': false, 'tools.update_plan.enabled': false,
  'tools.experimental_request_user_input.enabled': false,
  'shell_environment_policy.inherit': 'none',
  project_doc_max_bytes: 0, project_doc_fallback_filenames: Object.freeze([]),
  include_apps_instructions: false, include_collaboration_mode_instructions: false,
  check_for_update_on_startup: false, 'analytics.enabled': false, 'history.persistence': 'none',
});

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new NativeBridgeError('invalid-input', 'Malformed Codex protocol object.');
  return value as Record<string, unknown>;
}

function id(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) throw new NativeBridgeError('invalid-input', 'Malformed Codex thread or turn identity.');
  return value;
}

function configValue(config: Record<string, unknown>, key: string): unknown {
  if (Object.hasOwn(config, key)) return config[key];
  let value: unknown = config;
  for (const segment of key.split('.')) {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

function validateEffectiveConfig(config: Record<string, unknown>) {
  for (const [key, expected] of Object.entries(CODEX_RESTRICTED_CONFIG)) {
    const observed = configValue(config, key);
    if (observed === undefined && layerOnlyControls.includes(key)) continue;
    if (observed === undefined) {
      throw new NativeBridgeError('capability-unavailable', 'Codex does not expose a required effective no-tools control; this profile is not qualified.');
    }
    if (key === 'hooks' && typeof observed === 'object' && observed !== null && !Array.isArray(observed)) {
      const knownHooks = new Set([
        'PreToolUse', 'PermissionRequest', 'PostToolUse', 'PreCompact', 'PostCompact',
        'SessionStart', 'SessionEnd', 'UserPromptSubmit', 'SubagentStart', 'SubagentStop', 'Stop', 'Interrupt',
      ]);
      if (Object.entries(observed).every(([name, entries]) =>
        knownHooks.has(name) && Array.isArray(entries) && entries.length === 0)) continue;
    }
    if (JSON.stringify(observed) !== JSON.stringify(expected)) {
      throw new NativeBridgeError('scope-exceeded', 'Codex effective configuration differs from the reviewed no-tools policy.');
    }
  }
  for (const key of ['instructions', 'developer_instructions', 'model_instructions_file', 'experimental_compact_prompt_file', 'notify', 'model_catalog_json']) {
    const value = config[key];
    if (value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && value.length === 0)) {
      throw new NativeBridgeError('scope-exceeded', 'Codex loaded unexpected ambient instructions, notifications, or model metadata.');
    }
  }
}

function validateConfigLayers(layers: unknown) {
  if (!Array.isArray(layers)) throw new NativeBridgeError('invalid-input', 'Codex must disclose effective configuration layers.');
  let sessionFlags = false;
  for (const raw of layers) {
    const layer = object(raw);
    const kind = object(layer.name).type;
    if (!['packagedDefaults', 'sessionFlags', 'user', 'project', 'system', 'mdm', 'enterpriseManaged',
      'legacyManagedConfigTomlFromFile', 'legacyManagedConfigTomlFromMdm'].includes(String(kind))) {
      throw new NativeBridgeError('scope-exceeded', 'Unknown Codex configuration provenance.');
    }
    if (kind === 'sessionFlags') {
      if (sessionFlags || layer.disabledReason != null) throw new NativeBridgeError('scope-exceeded', 'Codex must disclose exactly one active session configuration layer.');
      sessionFlags = true;
      for (const key of layerOnlyControls) {
        const observed = configValue(object(layer.config), key);
        if (observed === undefined) throw new NativeBridgeError('capability-unavailable', 'Codex omitted a required session-layer tool control.');
        if (observed !== CODEX_RESTRICTED_CONFIG[key]) throw new NativeBridgeError('scope-exceeded', 'Codex session-layer tool controls differ from the reviewed policy.');
      }
    }
    if (layer.disabledReason !== undefined && layer.disabledReason !== null) {
      if (typeof layer.disabledReason !== 'string' || layer.disabledReason.length === 0) {
        throw new NativeBridgeError('invalid-input', 'Malformed Codex configuration-layer state.');
      }
      continue;
    }
    const config = object(layer.config);
    if (kind !== 'packagedDefaults' && kind !== 'sessionFlags' && Object.keys(config).length > 0) {
      throw new NativeBridgeError('scope-exceeded', 'Codex loaded an active ambient or managed configuration layer.');
    }
  }
  if (!sessionFlags) throw new NativeBridgeError('scope-exceeded', 'Codex did not disclose the explicit session configuration layer.');
}

function toml(value: unknown): string {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || Array.isArray(value)) return JSON.stringify(value);
  if (typeof value === 'object' && value !== null && Object.keys(value).length === 0) return '{}';
  throw new NativeBridgeError('invalid-input', 'Unsupported internal Codex configuration value.');
}

class CodexConnection {
  private sequence = 0;
  private pending = new Map<string, {
    resolve: (value: unknown) => void; reject: (error: NativeBridgeError) => void;
    acknowledge?: (value: unknown) => void;
  }>();
  private buffer = '';
  private readonly decoder = new TextDecoder('utf-8', { fatal: true });

  constructor(
    private readonly child: ChildProcessWithoutNullStreams,
    private readonly operation: ProposalOperation,
    private readonly notification: (method: string, params: Record<string, unknown>) => void,
  ) {
    operation.onStop(() => {
      for (const waiting of this.pending.values()) waiting.reject(new NativeBridgeError('effect-outcome-unknown', 'Codex request interrupted.'));
      this.pending.clear();
      stopNativeProcess(child);
    });
    child.stdout.on('data', (chunk: Buffer) => this.receive(chunk));
    child.stderr.on('data', (chunk: Buffer) => {
      try { operation.observeBytes(chunk); } catch (error) { this.fail(error); }
    });
    child.on('error', () => this.fail(new NativeBridgeError('capability-unavailable', 'Codex app-server could not start.')));
    child.stdin.on('error', () => this.fail(new NativeBridgeError('capability-unavailable', 'Codex protocol input closed unexpectedly.')));
    child.on('close', () => this.fail(new NativeBridgeError('effect-outcome-unknown', 'Codex exited before the proposal operation finished.')));
  }

  request(method: string, params: Readonly<Record<string, unknown>>, acknowledge?: (value: unknown) => void): Promise<unknown> {
    this.operation.guard();
    const requestId = `missionspec-${++this.sequence}`;
    const response = new Promise<unknown>((resolve, reject) => {
      this.pending.set(requestId, { resolve, reject, ...(acknowledge === undefined ? {} : { acknowledge }) });
    });
    try { this.write({ id: requestId, method, params }); }
    catch { this.fail(new NativeBridgeError('capability-unavailable', 'Codex protocol input could not accept the request.')); }
    return response;
  }

  notify(method: string) { this.write({ method, params: {} }); }

  interrupt(threadId: string, turnId: string) {
    if (this.child.stdin.writable) this.write({ id: `missionspec-stop-${++this.sequence}`, method: 'turn/interrupt', params: { threadId, turnId } });
  }

  private write(value: unknown) { this.child.stdin.write(`${JSON.stringify(value)}\n`); }

  private fail(error: unknown) {
    this.operation.fail(error instanceof NativeBridgeError ? error : new NativeBridgeError('invalid-input', 'Malformed Codex protocol output.'));
  }

  private receive(chunk: Buffer) {
    try {
      this.operation.observeBytes(chunk);
      this.buffer += this.decoder.decode(chunk, { stream: true });
      let newline: number;
      while ((newline = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        const message = object(JSON.parse(line));
        if (message.jsonrpc !== undefined && message.jsonrpc !== '2.0') throw new NativeBridgeError('invalid-input', 'Unsupported Codex JSON-RPC version.');
        if (Object.keys(message).some((key) => !['id', 'jsonrpc', 'method', 'params', 'result', 'error'].includes(key))) {
          throw new NativeBridgeError('invalid-input', 'Unknown Codex JSON-RPC envelope field.');
        }
        if (typeof message.method === 'string') {
          if ('result' in message || 'error' in message) throw new NativeBridgeError('invalid-input', 'Mixed Codex JSON-RPC request/response.');
          if ('id' in message) {
            if (typeof message.id !== 'string' && !Number.isSafeInteger(message.id)) throw new NativeBridgeError('invalid-input', 'Malformed Codex request identity.');
            if (['item/commandExecution/requestApproval', 'item/fileChange/requestApproval'].includes(message.method)) {
              this.write({ id: message.id, result: { decision: 'cancel' } });
            } else if (message.method === 'item/permissions/requestApproval') {
              this.write({ id: message.id, result: { permissions: {}, scope: 'turn' } });
            } else if (message.method === 'item/tool/call') {
              this.write({ id: message.id, result: { contentItems: [{ type: 'inputText', text: 'Denied' }], success: false } });
            } else if (message.method === 'mcpServer/elicitation/request') {
              this.write({ id: message.id, result: { action: 'cancel', content: null, _meta: null } });
            } else {
              this.write({ id: message.id, error: { code: -32601, message: 'MissionSpec denies all native tool, approval, and user-input requests.' } });
            }
            throw new NativeBridgeError('scope-exceeded', 'Codex made an unexpected bidirectional request; it was denied.');
          }
          this.notification(message.method, object(message.params));
        } else {
          if ('method' in message || typeof message.id !== 'string' ||
              ('result' in message) === ('error' in message) || 'params' in message) {
            throw new NativeBridgeError('invalid-input', 'Malformed Codex JSON-RPC response.');
          }
          const pending = this.pending.get(message.id);
          if (pending === undefined) throw new NativeBridgeError('invalid-input', 'Unsolicited, duplicate, or late Codex response.');
          this.pending.delete(message.id);
          if ('error' in message) {
            const failure = new NativeBridgeError('capability-unavailable', 'Codex rejected the pinned restricted protocol request.');
            pending.reject(failure);
            throw failure;
          }
          try { pending.acknowledge?.(message.result); } catch (error) {
            const failure = error instanceof NativeBridgeError ? error : new NativeBridgeError('invalid-input', 'Invalid Codex acknowledgement.');
            pending.reject(failure);
            throw failure;
          }
          pending.resolve(message.result);
        }
      }
    } catch (error) { this.fail(error); }
  }
}

export class CodexProposalHost implements RestrictedProposalHostPort {
  readonly host = 'codex' as const;
  private readonly setup: NativeHostSetup;

  constructor(setup: NativeHostSetup) {
    this.setup = Object.freeze({ ...setup, environment: Object.freeze({ ...setup.environment }) });
  }

  propose(input: ProposalRequest, signal?: AbortSignal) {
    const setup = this.setup;
    return runNativeProposal(this.host, setup, null, input, signal, {
      profile: reviewedProfile, config: CODEX_RESTRICTED_CONFIG, environments: [], dynamicTools: [],
      sandboxPolicy: { type: 'readOnly', networkAccess: false },
    }, async (request, operation, environment) => {
      if (!reviewedModels.includes(setup.model)) {
        throw new NativeBridgeError('capability-unavailable', 'Codex model tool metadata is outside the reviewed no-tools profile.');
      }
      // This pin requires an existing CODEX_HOME; the caller's verified empty home already exists.
      const nativeEnvironment = Object.freeze({ ...environment, CODEX_HOME: setup.homeDirectory });
      const argv = [...Object.entries(CODEX_RESTRICTED_CONFIG).flatMap(([key, value]) => ['-c', `${key}=${toml(value)}`]), 'app-server', '--listen', 'stdio://'];
      const child = startNativeProcess({ executable: setup.executable, argv, cwd: setup.workingDirectory, environment: nativeEnvironment });
      let threadId: string | undefined;
      let turnId: string | undefined;
      let output: string | undefined;
      let threadRequested = false;
      let turnRequested = false;
      let turnAcknowledged = false;
      let turnStarted = false;
      let completionObserved = false;
      let complete = false;
      let finish!: () => void;
      const terminal = new Promise<void>((resolve) => { finish = resolve; });
      operation.onStop(() => {
        if (!complete && threadId !== undefined && turnId !== undefined) connection.interrupt(threadId, turnId);
      });
      const connection = new CodexConnection(child, operation, (method, params) => {
        if (method === 'remoteControl/status/changed') {
          if (Object.keys(params).some((key) => !['status', 'installationId', 'serverName', 'environmentId'].includes(key)) ||
              typeof params.installationId !== 'string' || params.installationId.length === 0 || params.installationId.length > 256 ||
              typeof params.serverName !== 'string' || params.serverName.length === 0 || params.serverName.length > 256) {
            throw new NativeBridgeError('invalid-input', 'Malformed Codex remote-control status.');
          }
          if (params.status !== 'disabled' || params.environmentId !== null) {
            throw new NativeBridgeError('scope-exceeded', 'Codex remote control is not disabled.');
          }
          return;
        }
        if (method === 'account/rateLimits/updated') return;
        if (method === 'account/updated') {
          if (params.authMode !== 'apikey' && params.authMode !== null) {
            throw new NativeBridgeError('scope-exceeded', 'Codex selected an unexpected authentication mode.');
          }
          return;
        }
        if (method === 'thread/status/changed' || method === 'thread/tokenUsage/updated') {
          if (params.threadId !== threadId || threadId === undefined) throw new NativeBridgeError('invalid-input', 'Uncorrelated Codex lifecycle event.');
          if (method === 'thread/status/changed' && !['idle', 'active'].includes(String(object(params.status).type))) {
            throw new NativeBridgeError('scope-exceeded', 'Unexpected Codex lifecycle state.');
          }
          return;
        }
        if (completionObserved) throw new NativeBridgeError('invalid-input', 'Codex sent data after turn completion.');
        if (method === 'thread/started') {
          if (!threadRequested || turnRequested) throw new NativeBridgeError('invalid-input', 'Codex started a thread outside the requested protocol phase.');
          const observed = id(object(params.thread).id);
          if (threadId !== undefined && threadId !== observed) throw new NativeBridgeError('invalid-input', 'Unexpected Codex thread.');
          threadId = observed;
          return;
        }
        if (params.threadId !== threadId || threadId === undefined) throw new NativeBridgeError('invalid-input', 'Uncorrelated Codex event.');
        if (!turnRequested || !turnAcknowledged) throw new NativeBridgeError('invalid-input', 'Codex sent turn data before the corresponding acknowledged turn request.');
        if (method === 'turn/started' || method === 'turn/completed') {
          const turn = object(params.turn);
          const observed = id(turn.id);
          if (turnId !== undefined && turnId !== observed) throw new NativeBridgeError('invalid-input', 'Unexpected Codex turn.');
          turnId = observed;
          if (method === 'turn/started') {
            if (turnStarted || turn.status !== 'inProgress') throw new NativeBridgeError('invalid-input', 'Codex sent a duplicate or invalid turn-start event.');
            turnStarted = true;
          } else {
            if (!turnStarted || turn.status !== 'completed' || turn.error != null || output === undefined) throw new NativeBridgeError('invalid-input', 'Codex turn ended without a successful text proposal.');
            completionObserved = true;
            finish();
          }
          return;
        }
        if (!turnStarted || params.turnId !== turnId || turnId === undefined) throw new NativeBridgeError('invalid-input', 'Uncorrelated Codex turn event.');
        if (method === 'item/started' || method === 'item/completed') {
          const item = object(params.item);
          if (!['userMessage', 'agentMessage', 'reasoning'].includes(String(item.type))) throw new NativeBridgeError('scope-exceeded', 'Codex emitted an unexpected tool or effect item.');
          if (item.type === 'agentMessage' && (item.delivery != null || item.questions != null || item.memoryCitation != null)) {
            throw new NativeBridgeError('scope-exceeded', 'Codex emitted unexpected asynchronous input or memory content.');
          }
          if (method === 'item/completed' && item.type === 'agentMessage') {
            if (output !== undefined || typeof item.text !== 'string') throw new NativeBridgeError('invalid-input', 'Codex must return exactly one final text item.');
            output = item.text;
          }
          return;
        }
        if (['item/agentMessage/delta', 'item/reasoning/textDelta', 'item/reasoning/summaryTextDelta', 'item/reasoning/summaryPartAdded'].includes(method)) return;
        throw new NativeBridgeError('scope-exceeded', 'Unexpected Codex notification or tool event.');
      });
      const initialized = object(await connection.request('initialize', {
        clientInfo: { name: 'missionspec', version: '0.0.0' }, capabilities: { experimentalApi: true },
      }));
      const initializationFields = ['userAgent', 'codexHome', 'platformFamily', 'platformOs'];
      if (Object.keys(initialized).some((key) => !initializationFields.includes(key)) ||
          initializationFields.some((key) => typeof initialized[key] !== 'string' ||
            String(initialized[key]).length === 0 || String(initialized[key]).length > 4_096)) {
        throw new NativeBridgeError('invalid-input', 'Codex returned an unsupported initialization shape.');
      }
      if (initialized.codexHome !== nativeEnvironment.CODEX_HOME) {
        throw new NativeBridgeError('scope-exceeded', 'Codex did not acknowledge the isolated native home.');
      }
      operation.guard();
      connection.notify('initialized');
      const effective = object(await connection.request('config/read', { includeLayers: true, cwd: setup.workingDirectory }));
      validateConfigLayers(effective.layers);
      validateEffectiveConfig(object(effective.config));
      const apiKey = environment.OPENAI_API_KEY ?? environment.CODEX_API_KEY;
      if (apiKey === undefined) throw new NativeBridgeError('authority-required', 'An explicit Codex API key is required.');
      const authenticated = object(await connection.request('account/login/start', { type: 'apiKey', apiKey }));
      if (authenticated.type !== 'apiKey') throw new NativeBridgeError('scope-exceeded', 'Codex did not acknowledge explicit API-key authentication.');
      threadRequested = true;
      const started = object(await connection.request('thread/start', {
        model: setup.model, cwd: setup.workingDirectory, approvalPolicy: 'never', approvalsReviewer: 'user',
        sandbox: 'read-only', config: CODEX_RESTRICTED_CONFIG, ephemeral: true,
        allowProviderModelFallback: false,
        environments: [], dynamicTools: [], selectedCapabilityRoots: [],
        baseInstructions: PROPOSAL_INSTRUCTION, developerInstructions: PROPOSAL_INSTRUCTION,
      }));
      const thread = object(started.thread);
      const startedThread = id(thread.id);
      if (threadId !== undefined && threadId !== startedThread) throw new NativeBridgeError('invalid-input', 'Codex thread response/event mismatch.');
      threadId = startedThread;
      if (started.approvalPolicy !== 'never' || object(started.sandbox).type !== 'readOnly' ||
          object(started.sandbox).networkAccess !== false || started.cwd !== setup.workingDirectory ||
          started.model !== setup.model || started.modelProvider !== 'openai' || started.approvalsReviewer !== 'user' ||
          !Array.isArray(thread.environments) || thread.environments.length !== 0 || thread.ephemeral !== true ||
          !Array.isArray(started.instructionSources) || started.instructionSources.length !== 0) {
        throw new NativeBridgeError('scope-exceeded', 'Codex thread did not acknowledge the restricted policy.');
      }
      turnRequested = true;
      await connection.request('turn/start', {
        threadId, model: setup.model, cwd: setup.workingDirectory,
        input: [{ type: 'text', text: proposalPrompt(request), text_elements: [] }],
        environments: [], approvalPolicy: 'never', approvalsReviewer: 'user',
        sandboxPolicy: { type: 'readOnly', networkAccess: false },
      }, (value) => {
        const turn = object(object(value).turn);
        if (turn.status !== 'inProgress' || turn.error != null) throw new NativeBridgeError('invalid-input', 'Codex did not acknowledge a fresh in-progress turn.');
        turnId = id(turn.id);
        turnAcknowledged = true;
      });
      await terminal;
      operation.guard();
      if (output === undefined) throw new NativeBridgeError('invalid-input', 'Codex did not return text.');
      complete = true;
      return output;
    });
  }
}
