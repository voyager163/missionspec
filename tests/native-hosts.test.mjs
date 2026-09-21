import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { ClaudeProposalHost, CodexProposalHost, CopilotProposalHost, CODEX_RESTRICTED_CONFIG, NATIVE_PROPOSAL_PINS } from '../dist/adapters/hosts/index.js';
import { digestContent } from '../dist/kernel/revisions.js';

const source = 'export const answer = 41;\n';
const result = { summary: 'Propose one bounded edit.', changes: [{ path: 'src/answer.ts', expected: digestContent(source), content: 'export const answer = 42;\n' }] };
const response = JSON.stringify(result);
const nativeDenials = {
  approval: { method:'item/commandExecution/requestApproval', result:{decision:'cancel'} },
  'file-approval': { method:'item/fileChange/requestApproval', result:{decision:'cancel'} },
  'permission-request': { method:'item/permissions/requestApproval', result:{permissions:{},scope:'turn'} },
  'tool-call': { method:'item/tool/call', result:{contentItems:[{type:'inputText',text:'Denied'}],success:false} },
  elicitation: { method:'mcpServer/elicitation/request', result:{action:'cancel',content:null,_meta:null} },
};
async function waitFor(condition) {
  const deadline = Date.now() + 10_000;
  while (!(await condition())) {
    assert.ok(Date.now() < deadline, 'Synthetic transport did not reach the expected state.');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
const request = (host, overrides = {}) => ({
  prompt: 'Propose the answer correction, without using tools.',
  files: [{ path: 'src/answer.ts', content: source, digest: digestContent(source) }],
  allowedPaths: ['src/answer.ts'],
  limits: { maxInputBytes: 32_768, maxOutputBytes: 65_536, maxFiles: 2, timeoutMs: 10_000 },
  consent: { host, dataSharing: true, modelSpending: true },
  ...overrides,
});

// Original synthetic local process. This is not native-host or live-model qualification.
async function fixture(t, host, behavior = 'success', version = NATIVE_PROPOSAL_PINS[host].cli) {
  const root = path.join(process.cwd(), `.native-host-test-${randomUUID()}`);
  const workingDirectory = path.join(root, 'work');
  const homeDirectory = path.join(root, 'home');
  await mkdir(workingDirectory, { recursive: true, mode: 0o700 });
  await mkdir(homeDirectory, { mode: 0o700 });
  t.after(async () => { await new Promise((resolve) => setTimeout(resolve, 30)); await rm(root, { recursive: true, force: true }); });
  const executable = path.join(root, 'native-fixture.mjs');
  const transcript = path.join(root, 'transcript.jsonl');
  const model = host === 'codex' ? behavior === 'alternate-model' ? 'gpt-5.5' : 'gpt-5.4' : 'test-model-not-real';
  const versionText = host === 'copilot' ? `GitHub Copilot CLI ${version}\n` : host === 'codex' ? `codex-cli ${version}\n` : `${version} (Claude Code)\n`;
  await writeFile(executable, `#!${process.execPath}
import { appendFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
const behavior = ${JSON.stringify(behavior)};
const nativeDenial = ${JSON.stringify(nativeDenials[behavior] ?? null)};
const transcript = ${JSON.stringify(transcript)};
if (process.argv.includes('--version')) {
  process.stdout.write(${JSON.stringify(versionText)});
} else {
  process.on('SIGTERM', () => setTimeout(() => process.exit(0), behavior === 'late' ? 150 : 10));
  appendFileSync(transcript, JSON.stringify({ argv: process.argv.slice(2), env: process.env })+'\\n');
  const send = (message) => process.stdout.write(JSON.stringify(message)+'\\n');
  const event = (method, params) => send({ method, params });
  const answer = (id, result) => send({ id, result });
  const config = ${JSON.stringify(CODEX_RESTRICTED_CONFIG)};
  createInterface({input:process.stdin}).on('line', line => {
    const message = JSON.parse(line);
    appendFileSync(transcript, JSON.stringify(message)+'\\n');
    if (!message.method) return;
    if (message.method === 'initialize') {
      if (['disabled-remote-control', 'enabled-remote-control', 'malformed-remote-control', 'missing-remote-environment', 'unexpected-remote-environment', 'extra-remote-field'].includes(behavior)) {
        const remote = {status:behavior === 'enabled-remote-control' ? 'connected' : 'disabled',installationId:'TEST-installation',serverName:'TEST-server',environmentId:null};
        if (behavior === 'missing-remote-environment') delete remote.environmentId;
        if (behavior === 'unexpected-remote-environment') remote.environmentId = 'NOT-ISOLATED';
        if (behavior === 'extra-remote-field') remote.extra = true;
        event('remoteControl/status/changed', behavior === 'malformed-remote-control' ? {status:'disabled'} : remote);
      }
      if (behavior === 'stdout-noise') { process.stdout.write('not protocol\\n'); return; }
      if (behavior === 'oversize') { process.stdout.write('x'.repeat(100000)); return; }
      if (behavior === 'stderr-oversize') { process.stderr.write('x'.repeat(100000)); return; }
      if (behavior === 'invalid-utf8') { process.stdout.write(Buffer.from([0xff, 0x0a])); return; }
      if (behavior === 'unknown-id') { answer('foreign-id', {}); return; }
      if (behavior === 'malformed-initialize') { answer(message.id, {serverInfo:{version:'0.155.1'}}); return; }
      answer(message.id, { userAgent: 'synthetic-test-only',codexHome:behavior==='wrong-home'?'/unreviewed-home':process.env.CODEX_HOME,platformFamily:'unix',platformOs:'macos' });
    } else if (message.method === 'config/read') {
      const layerConfig = structuredClone(config);
      layerConfig.tools = {update_plan:{enabled:false},experimental_request_user_input:{enabled:false}};
      delete layerConfig['tools.update_plan.enabled'];
      delete layerConfig['tools.experimental_request_user_input.enabled'];
      delete config['tools.update_plan.enabled'];
      delete config['tools.experimental_request_user_input.enabled'];
      config.tools = {web_search:null};
      if (behavior === 'ambient-config') config.mcp_servers = { forbidden: {} };
      if (behavior === 'model-catalog-override') config.model_catalog_json = '/unreviewed-models.json';
      if (behavior === 'normalized-empty-hooks' || behavior === 'active-normalized-hook') {
        config.hooks = {PreToolUse:[],PermissionRequest:[],PostToolUse:[],PreCompact:[],PostCompact:[],SessionStart:[],SessionEnd:[],UserPromptSubmit:[],SubagentStart:[],SubagentStop:[],Stop:[],Interrupt:[]};
        if (behavior === 'active-normalized-hook') config.hooks.SessionStart.push({command:'NOT-EXECUTED-test-only'});
      }
      if (behavior === 'unknown-normalized-hook') config.hooks = {UnknownHook:[]};
      if (behavior === 'missing-effective-tool-config') delete layerConfig.tools.update_plan;
      if (behavior === 'missing-input-tool-control') delete layerConfig.tools.experimental_request_user_input;
      if (behavior === 'enabled-plan-control') layerConfig.tools.update_plan.enabled = true;
      if (behavior === 'enabled-input-control') layerConfig.tools.experimental_request_user_input.enabled = true;
      if (behavior === 'contradictory-tool-projection') config.tools.update_plan = {enabled:true};
      if (behavior === 'missing-effective-feature') delete config['features.default_mode_request_user_input'];
      if (behavior === 'enabled-catalog-discovery') config['features.api_key_model_discovery'] = true;
      if (behavior === 'enabled-token-budget') config['features.token_budget'] = true;
      if (behavior === 'enabled-current-time') config['features.current_time_reminder'] = true;
      const layers=[{name:{type:'sessionFlags'},version:'synthetic',config:layerConfig}];
      if (behavior === 'duplicate-session-layer') layers.push(structuredClone(layers[0]));
      if (behavior === 'disabled-session-layer') layers[0].disabledReason = 'synthetic disabled layer';
      if (behavior === 'missing-session-layer') layers.length = 0;
      if (behavior === 'ambient-layer') layers.push({name:{type:'system',file:'/synthetic/config.toml'},version:'synthetic',config:{unreviewed_field:true}});
      answer(message.id, { config, layers });
    } else if (message.method === 'account/login/start') {
      event('account/updated', {authMode:'apikey',planType:null});
      answer(message.id, {type:'apiKey'});
    } else if (message.method === 'thread/start') {
      event('thread/started', { thread: { id: 'thread-test' } });
      answer(message.id, { thread: { id: 'thread-test', environments:behavior === 'thread-environment' ? [{}] : [], ephemeral:true }, approvalPolicy: 'never', approvalsReviewer:'user', instructionSources:[], model:${JSON.stringify(model)}, modelProvider:'openai', sandbox: { type: 'readOnly', networkAccess: false }, cwd: ${JSON.stringify(workingDirectory)} });
      if (behavior === 'unsolicited-turn') {
        event('turn/started', {threadId:'thread-test',turn:{id:'turn-test',status:'inProgress'}});
        event('item/completed', {threadId:'thread-test',turnId:'turn-test',item:{type:'agentMessage',id:'unsolicited',text:${JSON.stringify(response)}}});
        event('turn/completed', {threadId:'thread-test',turn:{id:'turn-test',status:'completed',error:null}});
      }
    } else if (message.method === 'turn/start') {
      if (behavior !== 'events-before-turn-ack') answer(message.id, { turn: { id: 'turn-test', status: 'inProgress' } });
      if (behavior === 'unsolicited-turn') return;
      event('turn/started', { threadId: 'thread-test', turn: { id: 'turn-test', status: 'inProgress' } });
      event('thread/status/changed', {threadId:'thread-test',status:{type:'active',activeFlags:[]}});
      if (behavior === 'hang') return;
      if (nativeDenial) { send({id: 'native-denied', method:nativeDenial.method, params:{}}); return; }
      if (behavior === 'user-input-request') { send({id:'native-tool',method:'item/tool/requestUserInput',params:{}}); return; }
      if (behavior === 'unknown-request') { send({id:'native-tool',method:'unknown/native/tool',params:{}}); return; }
      if (behavior === 'tool-event') { event('item/started',{threadId:'thread-test',turnId:'turn-test',item:{type:'commandExecution',id:'forbidden'}}); return; }
      const forbiddenItems = {'file-event':'fileChange','mcp-event':'mcpToolCall','web-event':'webSearch','image-event':'imageGeneration','collab-event':'collabAgentToolCall','plan-item':'plan'};
      if (forbiddenItems[behavior]) { event('item/completed',{threadId:'thread-test',turnId:'turn-test',item:{type:forbiddenItems[behavior],id:'forbidden'}}); return; }
      if (behavior === 'plan-event') { event('turn/plan/updated',{threadId:'thread-test',turnId:'turn-test',explanation:'NOT-EVIDENCE',plan:[{step:'NOT-AUTHORITY',status:'completed'}]}); return; }
      if (behavior === 'unknown-notification') { event('unknown/notification',{threadId:'thread-test',turnId:'turn-test'}); return; }
      const finish = () => {
        if (behavior === 'late') appendFileSync(transcript, JSON.stringify({lateOutput:true})+'\\n');
        process.stderr.write('SYNTHETIC diagnostics are never proposal content\\n');
        const item = {type:'agentMessage',id:'message-test',text:${JSON.stringify(response)}};
        if (behavior === 'async-message') item.delivery = 'async';
        if (behavior === 'async-questions') item.questions = [{title:'NOT-AUTHORITY'}];
        if (behavior === 'memory-citation') item.memoryCitation = {};
        event('item/completed', { threadId:'thread-test', turnId: behavior === 'wrong-turn' ? 'foreign-turn' : 'turn-test', item });
        event('turn/completed', { threadId:'thread-test', turn:{id:'turn-test',status:'completed',error:null} });
        event('thread/status/changed', {threadId:'thread-test',status:{type:'idle'}});
        if (behavior === 'events-before-turn-ack') answer(message.id, {turn:{id:'turn-test',status:'inProgress'}});
      };
      if (behavior === 'late') setTimeout(finish, 100); else finish();
    }
  });
}
`, { mode: 0o700 });
  await chmod(executable, 0o700);
  const reviews = [];
  const setup = {
    executable, workingDirectory, homeDirectory,
    environment: { [host === 'copilot' ? 'COPILOT_GITHUB_TOKEN' : host === 'codex' ? 'OPENAI_API_KEY' : 'ANTHROPIC_API_KEY']:'SYNTHETIC-not-a-real-credential' },
    model,
    async authorizeNativeStart(review) { reviews.push(review); return { status: 'ok', value: { allowed: true } }; },
  };
  const sdk = NATIVE_PROPOSAL_PINS[host];
  const packageJsonPath = path.join(root, 'package.json');
  if (host !== 'codex') await writeFile(packageJsonPath, JSON.stringify({ name: sdk.sdk, version: sdk.sdkVersion, gitHead: sdk.sourceRevision }));
  return { root, setup, packageJsonPath, reviews, transcript, readTranscript: async () => (await readFile(transcript, 'utf8')).trim().split('\n').map(JSON.parse) };
}

function copilotSdk(f, behavior = async () => ({ type: 'assistant.message', data: { content: response } })) {
  const calls = { clients: [], sessions: [], sends: [], stopped: 0, aborted: 0, disconnected: 0, cleanup:[] };
  return {
    calls,
    packageJsonPath: f.packageJsonPath,
    createClient(options) {
      calls.clients.push(options);
      return {
        async start() {},
        async getStatus() { return { version: '1.0.85', protocolVersion: 3 }; },
        async stop() { calls.stopped++; return []; },
        async forceStop() { calls.stopped++; calls.cleanup.push('forceStop'); },
        async createSession(sessionOptions) {
          calls.sessions.push(sessionOptions);
          sessionOptions.onEvent({ type: 'session.start', data: {} });
          return {
            async sendAndWait(input, timeout) { calls.sends.push({ input, timeout }); return behavior(sessionOptions); },
            async abort() { calls.aborted++; calls.cleanup.push('abort'); },
            async disconnect() { calls.disconnected++; calls.cleanup.push('disconnect'); },
          };
        },
      };
    },
  };
}

function claudeSdk(f, behavior) {
  const calls = { queries: [], interrupted: 0, closed: 0 };
  const init = {
    type: 'system', subtype: 'init', claude_code_version: '2.1.278', cwd: f.setup.workingDirectory,
    permissionMode: 'default', model:'test-model-not-real', tools: [], mcp_servers: [], plugins: [], skills: [],
  };
  return {
    calls, packageJsonPath: f.packageJsonPath,
    query(input) {
      calls.queries.push(input);
      return {
        async *[Symbol.asyncIterator]() {
          yield init;
          if (behavior) yield* behavior(input.options, init);
          else {
            yield { type: 'assistant', message: { content: [{ type: 'text', text: response }] } };
            yield { type: 'result', subtype: 'success', is_error: false, num_turns:1, result: response };
          }
        },
        async interrupt() { calls.interrupted++; },
        close() { calls.closed++; },
      };
    },
  };
}

test('Copilot uses the pinned stdio empty-mode API and reasserts no tools/config on every new session', async (t) => {
  const f = await fixture(t, 'copilot');
  const sdk = copilotSdk(f);
  const host = new CopilotProposalHost(f.setup, sdk);
  for (let turn = 0; turn < 2; turn++) {
    const outcome = await host.propose(request('copilot'));
    assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
    assert.deepEqual(outcome.value, { kind: 'inert-proposal', host: 'copilot', ...result });
    assert.equal('inspect' in host, false);
    assert.equal('dispatch' in host, false);
    assert.equal('qualification' in outcome.value, false);
  }
  assert.equal(sdk.calls.clients.length, 2);
  for (const options of sdk.calls.clients) {
    assert.equal(options.mode, 'empty');
    assert.equal(options.connection.kind, 'stdio');
    assert.equal(options.connection.path, f.setup.executable);
    assert.equal(options.useLoggedInUser, false);
    assert.equal(options.gitHubToken, 'SYNTHETIC-not-a-real-credential');
    assert.equal(options.connection.env.NODE_OPTIONS, undefined);
    assert.equal(options.connection.env.HOME, f.setup.homeDirectory);
  }
  for (const options of sdk.calls.sessions) {
    assert.deepEqual(options.availableTools, []);
    assert.deepEqual(options.tools, []);
    assert.deepEqual(options.mcpServers, {});
    assert.equal(options.enableConfigDiscovery, false);
    assert.equal(options.enableManagedSettings, false);
    assert.equal(options.enableFileHooks, false);
    assert.equal(options.enableHostGitOperations, false);
    assert.equal(options.enableSessionStore, false);
    assert.equal(options.enableSkills, false);
    assert.equal(options.skipCustomInstructions, true);
  }
  assert.equal(sdk.calls.sends.length, 2);
  assert.equal(sdk.calls.stopped, 2);
  assert.deepEqual(sdk.calls.cleanup, ['abort','disconnect','forceStop','abort','disconnect','forceStop']);
  assert.equal(f.reviews[0].guarantees, 'restricted-proposals-only');
  assert.equal(f.reviews[0].sdk.version, '1.0.14');
  assert.match(f.reviews[0].executableDigest, /^sha256:/);
  assert.deepEqual(await readdir(f.setup.workingDirectory), []);
});

test('Claude uses tools:[] not allowedTools, suppresses ambient configuration and does not request retrying outputFormat', async (t) => {
  const f = await fixture(t, 'claude');
  const sdk = claudeSdk(f);
  const host = new ClaudeProposalHost(f.setup, sdk);
  for (let turn = 0; turn < 2; turn++) assert.equal((await host.propose(request('claude'))).status, 'ok');
  for (const { options } of sdk.calls.queries) {
    assert.deepEqual(options.tools, []);
    assert.deepEqual(options.settingSources, []);
    assert.deepEqual(options.mcpServers, {});
    assert.deepEqual(options.plugins, []);
    assert.deepEqual(options.hooks, {});
    assert.equal(options.strictMcpConfig, true);
    assert.equal(options.permissionMode, 'default');
    assert.equal(options.persistSession, false);
    assert.equal(options.maxTurns, 1);
    assert.equal('outputFormat' in options, false);
    assert.equal('allowedTools' in options, false);
    assert.deepEqual(Object.keys(options.env).sort(), [
      'ANTHROPIC_API_KEY','CLAUDE_CONFIG_DIR','HOME','LANG','LC_ALL','PATH','USERPROFILE',
      'XDG_CACHE_HOME','XDG_CONFIG_HOME','XDG_DATA_HOME',
    ]);
    for (const key of Object.keys(process.env).filter((key) => !['PATH', 'HOME', 'USERPROFILE', 'LANG', 'LC_ALL', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'CLAUDE_CONFIG_DIR', 'ANTHROPIC_API_KEY'].includes(key))) {
      assert.equal(options.env[key], undefined, key);
    }
  }
  assert.equal(sdk.calls.interrupted, 2);
  assert.equal(sdk.calls.closed, 2);
});

test('Codex performs original JSONL app-server integration with per-thread and per-turn environment removal', async (t) => {
  assert.equal(Object.isFrozen(CODEX_RESTRICTED_CONFIG), true);
  assert.equal(Object.isFrozen(CODEX_RESTRICTED_CONFIG.mcp_servers), true);
  const f = await fixture(t, 'codex');
  const host = new CodexProposalHost(f.setup);
  for (let turn = 0; turn < 2; turn++) {
    const outcome = await host.propose(request('codex'));
    assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
    assert.deepEqual(outcome.value.changes, result.changes);
  }
  const messages = await f.readTranscript();
  const starts = messages.filter((message) => message.argv);
  assert.equal(starts.length, 2);
  assert.deepEqual(starts[0].argv.slice(-3), ['app-server', '--listen', 'stdio://']);
  assert.equal(starts[0].argv[0], '-c');
  assert.equal(starts[0].env.NODE_OPTIONS, undefined);
  assert.equal(starts[0].env.CODEX_HOME, f.setup.homeDirectory);
  assert.equal(CODEX_RESTRICTED_CONFIG.cli_auth_credentials_store, 'ephemeral');
  assert.equal(CODEX_RESTRICTED_CONFIG['tools.update_plan.enabled'], false);
  assert.equal(CODEX_RESTRICTED_CONFIG['tools.experimental_request_user_input.enabled'], false);
  for (const feature of ['api_key_model_discovery', 'token_budget', 'context_management', 'current_time_reminder']) {
    assert.equal(CODEX_RESTRICTED_CONFIG[`features.${feature}`], false);
  }
  const profile = {
    name:'codex-0.155.1-api-catalog-no-tools-v1', nativeHome:'isolated-home-directory', models:['gpt-5.4','gpt-5.5'],
    layerOnlyControls:['tools.update_plan.enabled','tools.experimental_request_user_input.enabled'], allowedNativeTools:[],
  };
  assert.equal(f.reviews[0].configurationDigest, digestContent(JSON.stringify({
    profile, config:CODEX_RESTRICTED_CONFIG, environments:[], dynamicTools:[],
    sandboxPolicy:{type:'readOnly',networkAccess:false}, model:f.setup.model,
    cwd:f.setup.workingDirectory, home:f.setup.homeDirectory, authentication:f.setup.environment,
  })));
  for (const method of ['initialize', 'account/login/start', 'thread/start', 'turn/start']) assert.equal(messages.filter((message) => message.method === method).length, 2);
  assert.deepEqual(messages.find((message) => message.method === 'account/login/start').params, {type:'apiKey',apiKey:'SYNTHETIC-not-a-real-credential'});
  assert.equal(messages.find((message) => message.method === 'initialize').params.capabilities.experimentalApi, true);
  for (const message of messages.filter((message) => ['thread/start', 'turn/start'].includes(message.method))) {
    assert.deepEqual(message.params.environments, []);
    assert.equal(message.params.approvalPolicy, 'never');
    if (message.method === 'turn/start') assert.deepEqual(message.params.sandboxPolicy, { type: 'readOnly', networkAccess: false });
    else {
      assert.deepEqual(message.params.dynamicTools, []);
      assert.equal(message.params.ephemeral, true);
      assert.equal(message.params.allowProviderModelFallback, false);
    }
  }
});

test('sharing/spending opt-in, external gate, version and package pins are independent fail-closed checks', async (t) => {
  const f = await fixture(t, 'copilot');
  const sdk = copilotSdk(f);
  for (const consent of [
    { host: 'claude', dataSharing: true, modelSpending: true },
    { host: 'copilot', dataSharing: false, modelSpending: true },
    { host: 'copilot', dataSharing: true, modelSpending: false },
  ]) {
    assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot', { consent }))).error.code, 'authority-required');
  }
  assert.equal(f.reviews.length, 0);
  const denied = new CopilotProposalHost({ ...f.setup, authorizeNativeStart: async () => ({ status: 'ok', value: { allowed: false } }) }, sdk);
  assert.equal((await denied.propose(request('copilot'))).error.code, 'authority-required');
  await writeFile(f.packageJsonPath, JSON.stringify({ name: '@github/copilot-sdk', version: '1.0.15' }));
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'))).error.code, 'unsupported-version');
  await writeFile(f.packageJsonPath, JSON.stringify({ name: '@github/copilot-sdk', version: '1.0.14', gitHead: 'wrong-revision' }));
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'))).error.code, 'unsupported-version');
  assert.equal(sdk.calls.clients.length, 0);
  const drift = await fixture(t, 'claude', 'success', '2.1.279');
  const claude = claudeSdk(drift);
  assert.equal((await new ClaudeProposalHost(drift.setup, claude).propose(request('claude'))).error.code, 'unsupported-version');
  assert.equal(claude.calls.queries.length, 0);
});

test('nonempty launch directories, ambient env flags, and altered input digests are refused before native startup', async (t) => {
  const f = await fixture(t, 'copilot');
  const sdk = copilotSdk(f);
  await writeFile(path.join(f.setup.workingDirectory, 'AGENTS.md'), 'Untrusted ambient instructions');
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'))).status, 'blocked');
  await rm(path.join(f.setup.workingDirectory, 'AGENTS.md'));
  assert.equal((await new CopilotProposalHost({ ...f.setup, environment: { NODE_OPTIONS: '--import=ambient.mjs' } }, sdk).propose(request('copilot'))).error.code, 'invalid-input');
  const files = [{ path: 'src/answer.ts', content: 'changed', digest: digestContent(source) }];
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot', { files }))).error.code, 'invalid-input');
  assert.equal(sdk.calls.clients.length, 0);
  assert.equal((await new CopilotProposalHost({ ...f.setup, environment: {} }, sdk).propose(request('copilot'))).error.code, 'authority-required');
  assert.equal((await new CopilotProposalHost({ ...f.setup, environment: {COPILOT_GITHUB_TOKEN:'first-synthetic',GH_TOKEN:'second-synthetic'} }, sdk).propose(request('copilot'))).error.code, 'authority-required');
});

test('connected Copilot protocol/version drift and Codex executable drift cannot fall back to broader APIs', async (t) => {
  const f = await fixture(t, 'copilot');
  for (const status of [{ version:'1.0.86',protocolVersion:3 }, { version:'1.0.85',protocolVersion:4 }]) {
    const sdk = copilotSdk(f);
    const createClient = sdk.createClient;
    sdk.createClient = (options) => ({ ...createClient(options), async getStatus() { return status; } });
    assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'))).error.code, 'unsupported-version');
    assert.equal(sdk.calls.sessions.length, 0);
  }
  const drift = await fixture(t, 'codex', 'success', '0.155.2');
  assert.equal((await new CodexProposalHost(drift.setup).propose(request('codex'))).error.code, 'unsupported-version');
  await assert.rejects(() => readFile(drift.transcript), { code:'ENOENT' });
});

test('malformed, extra-field, out-of-scope, duplicate and wrong-preimage proposals never become effects', async (t) => {
  const f = await fixture(t, 'copilot');
  for (const invalid of [
    '```json\n{}\n```', '{"summary":"x","changes":[],"commands":["touch owned"]}',
    JSON.stringify({ ...result, changes: [{ ...result.changes[0], path: '../escape' }] }),
    JSON.stringify({ ...result, changes: [{ ...result.changes[0], path: 'src/unrequested.ts' }] }),
    JSON.stringify({ ...result, changes: [{ ...result.changes[0], expected: 'absent' }] }),
    JSON.stringify({ ...result, changes: [...result.changes, ...result.changes] }),
    JSON.stringify({ ...result, changes: [{ ...result.changes[0], content: '\0' }] }),
  ]) {
    const sdk = copilotSdk(f, async () => ({ type: 'assistant.message', data: { content: invalid } }));
    const outcome = await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'));
    assert.notEqual(outcome.status, 'ok', invalid);
    assert.equal(sdk.calls.sends.length, 1, 'No automatic repair calls');
  }
});

test('new artifact proposals use explicit absent preconditions and remain unwritten', async (t) => {
  const f = await fixture(t, 'copilot');
  const artifact = { summary:'Draft an artifact.',changes:[{path:'docs/proposal.md',expected:'absent',content:'# Unreviewed draft\n'}] };
  const sdk = copilotSdk(f, async () => ({type:'assistant.message',data:{content:JSON.stringify(artifact)}}));
  const outcome = await new CopilotProposalHost(f.setup, sdk).propose(request('copilot', {
    files:[],allowedPaths:['docs/proposal.md'],
  }));
  assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
  assert.deepEqual(outcome.value.changes, artifact.changes);
  assert.deepEqual(await readdir(f.setup.workingDirectory), []);
});

test('Copilot permission and unexpected tool events are denied even if a later valid proposal arrives', async (t) => {
  const f = await fixture(t, 'copilot');
  for (const trigger of [
    (options) => assert.deepEqual(options.onPermissionRequest({ kind: 'write' }, {}), { kind: 'reject' }),
    (options) => options.onEvent({ type: 'tool.execution_start', data: { name: 'shell' } }),
    (options) => options.onEvent({ type: 'assistant.message', data: { content: response, toolRequests: [{}] } }),
    (options) => options.onEvent({ type: 'unknown.new.event', data: {} }),
  ]) {
    const sdk = copilotSdk(f, async (options) => { trigger(options); return { type: 'assistant.message', data: { content: response } }; });
    const outcome = await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'));
    assert.equal(outcome.error.code, 'scope-exceeded');
    assert.ok(sdk.calls.stopped > 0);
  }
});

test('Claude rejects managed startup capabilities, tools, unknown messages and implicit native repair results', async (t) => {
  const f = await fixture(t, 'claude');
  for (const behavior of [
    async function* (_options, init) { yield { ...init, tools: ['Bash'] }; },
    async function* () { yield { type: 'assistant', message: { content: [{ type: 'tool_use', name: 'Bash' }] } }; },
    async function* () { yield { type: 'assistant', message: { content: [{ type: 'text', text: 4 }] } }; },
    async function* () { yield { type: 'control_request', request: { subtype: 'can_use_tool' } }; },
    async function* () { yield { type: 'result', subtype: 'error_max_turns', is_error: true }; },
    async function* () { yield { type: 'result', subtype: 'success', is_error: false, num_turns:3, result:response }; },
    async function* (options) { assert.equal((await options.canUseTool('Bash', {}, {})).behavior, 'deny'); },
  ]) {
    const sdk = claudeSdk(f, behavior);
    const outcome = await new ClaudeProposalHost(f.setup, sdk).propose(request('claude'));
    assert.notEqual(outcome.status, 'ok');
    assert.equal(sdk.calls.queries.length, 1);
    assert.equal(sdk.calls.closed, 1);
  }
});

for (const [behavior, code] of [
  ['stdout-noise', 'invalid-input'], ['oversize', 'limit-reached'], ['stderr-oversize', 'limit-reached'],
  ['unknown-id', 'invalid-input'], ['ambient-config', 'scope-exceeded'], ['approval', 'scope-exceeded'],
  ['unknown-request', 'scope-exceeded'], ['tool-event', 'scope-exceeded'], ['wrong-turn', 'invalid-input'],
  ['invalid-utf8', 'invalid-input'],
  ['ambient-layer', 'scope-exceeded'],
  ['file-approval','scope-exceeded'], ['permission-request','scope-exceeded'],
  ['tool-call','scope-exceeded'], ['elicitation','scope-exceeded'],
  ['wrong-home','scope-exceeded'], ['malformed-initialize','invalid-input'],
  ['unsolicited-turn','invalid-input'],
  ['missing-effective-tool-config', 'capability-unavailable'],
  ['missing-input-tool-control', 'capability-unavailable'],
  ['enabled-plan-control', 'scope-exceeded'], ['enabled-input-control', 'scope-exceeded'],
  ['contradictory-tool-projection', 'scope-exceeded'],
  ['missing-effective-feature', 'capability-unavailable'],
  ['enabled-catalog-discovery', 'scope-exceeded'], ['enabled-token-budget', 'scope-exceeded'],
  ['enabled-current-time', 'scope-exceeded'], ['model-catalog-override', 'scope-exceeded'],
  ['duplicate-session-layer', 'scope-exceeded'], ['disabled-session-layer', 'scope-exceeded'],
  ['missing-session-layer', 'scope-exceeded'], ['thread-environment', 'scope-exceeded'],
  ['user-input-request', 'scope-exceeded'],
  ['file-event', 'scope-exceeded'], ['mcp-event', 'scope-exceeded'], ['web-event', 'scope-exceeded'],
  ['image-event', 'scope-exceeded'], ['collab-event', 'scope-exceeded'],
  ['plan-event', 'scope-exceeded'], ['plan-item', 'scope-exceeded'], ['unknown-notification', 'scope-exceeded'],
  ['async-message', 'scope-exceeded'], ['async-questions', 'scope-exceeded'], ['memory-citation', 'scope-exceeded'],
  ['enabled-remote-control', 'scope-exceeded'],
  ['malformed-remote-control', 'invalid-input'],
  ['missing-remote-environment', 'scope-exceeded'], ['unexpected-remote-environment', 'scope-exceeded'],
  ['extra-remote-field', 'invalid-input'],
  ['active-normalized-hook', 'scope-exceeded'],
  ['unknown-normalized-hook', 'scope-exceeded'],
]) {
  test(`Codex fails closed for ${behavior}`, async (t) => {
    const f = await fixture(t, 'codex', behavior);
    const outcome = await new CodexProposalHost(f.setup).propose(request('codex'));
    assert.notEqual(outcome.status, 'ok');
    assert.equal(outcome.error.code, code, JSON.stringify(outcome));
    if ([
      'ambient-config', 'ambient-layer', 'missing-effective-tool-config', 'missing-input-tool-control',
      'enabled-plan-control', 'enabled-input-control', 'contradictory-tool-projection', 'missing-effective-feature',
      'enabled-catalog-discovery', 'enabled-token-budget', 'enabled-current-time', 'model-catalog-override',
      'duplicate-session-layer', 'disabled-session-layer', 'missing-session-layer',
      'enabled-remote-control', 'malformed-remote-control', 'active-normalized-hook', 'unknown-normalized-hook',
      'missing-remote-environment', 'unexpected-remote-environment', 'extra-remote-field',
    ].includes(behavior)) assert.equal((await f.readTranscript()).some((message) => ['account/login/start','thread/start','turn/start'].includes(message.method)), false);
    // Unsolicited bytes can arrive after the outbound request; rejection, not read timing, is the invariant.
    if (behavior === 'thread-environment') assert.equal((await f.readTranscript()).some((message) => message.method === 'turn/start'), false);
    if (nativeDenials[behavior] || ['unknown-request','user-input-request'].includes(behavior)) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      const denied = (await f.readTranscript()).find((message) => message.id === (nativeDenials[behavior] ? 'native-denied' : 'native-tool') && !message.method);
      if (nativeDenials[behavior]) assert.deepEqual(denied.result, nativeDenials[behavior].result);
      else assert.equal(denied.error.code, -32601);
    }
  });
}

test('Codex refuses completion that precedes its turn acknowledgement instead of guessing causality', async (t) => {
  const f = await fixture(t, 'codex', 'events-before-turn-ack');
  const outcome = await new CodexProposalHost(f.setup).propose(request('codex'));
  assert.equal(outcome.status, 'blocked', JSON.stringify(outcome));
  assert.equal(outcome.error.code, 'invalid-input');
  assert.equal((await f.readTranscript()).filter((message) => message.method === 'turn/start').length, 1);
});

test('Codex refuses unreviewed model tool metadata before app-server startup', async (t) => {
  for (const model of ['gpt-6-astra', 'gpt-5.6-sol', 'codex-auto-review', 'unknown-model', 'gpt-5.4-suffix']) {
    const f = await fixture(t, 'codex');
    const outcome = await new CodexProposalHost({...f.setup, model}).propose(request('codex'));
    assert.equal(outcome.status, 'blocked', JSON.stringify(outcome));
    assert.equal(outcome.error.code, 'capability-unavailable');
    assert.equal((await readdir(f.root)).includes('transcript.jsonl'), false);
  }
});

test('Codex admits the other reviewed bundled model without falling back to model metadata', async (t) => {
  const f = await fixture(t, 'codex', 'alternate-model');
  const outcome = await new CodexProposalHost(f.setup).propose(request('codex'));
  assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
  assert.equal((await f.readTranscript()).find((message) => message.method === 'thread/start').params.model, 'gpt-5.5');
});

test('Codex permits only the observed disabled remote-control lifecycle shape without retaining its identifiers', async (t) => {
  const f = await fixture(t, 'codex', 'disabled-remote-control');
  const outcome = await new CodexProposalHost(f.setup).propose(request('codex'));
  assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
  assert(!JSON.stringify(outcome).includes('TEST-installation'));
  assert(!JSON.stringify(outcome).includes('TEST-server'));
});

test('Codex recognizes actual empty normalized hooks without accepting an executable hook', async (t) => {
  const f = await fixture(t, 'codex', 'normalized-empty-hooks');
  const outcome = await new CodexProposalHost(f.setup).propose(request('codex'));
  assert.equal(outcome.status, 'ok', JSON.stringify(outcome));
});

test('total event bytes are bounded and UTF-8 bytes rather than characters govern input/output', async (t) => {
  const f = await fixture(t, 'copilot');
  const sdk = copilotSdk(f, async (options) => {
    options.onEvent({ type: 'assistant.message_delta', data: { deltaContent: '😀'.repeat(30_000) } });
    return { type: 'assistant.message', data: { content: response } };
  });
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'))).error.code, 'limit-reached');
  const input = request('copilot', { prompt: '😀'.repeat(16_000) });
  assert.equal((await new CopilotProposalHost(f.setup, sdk).propose(input)).error.code, 'limit-reached');
  assert.equal(sdk.calls.sends.length, 1);
  const claude = await fixture(t, 'claude');
  const noisy = claudeSdk(claude, async function* (options) {
    options.stderr('do not leak native credentials or diagnostics\n'.repeat(3_000));
    yield {type:'result',subtype:'success',is_error:false,num_turns:1,result:response};
  });
  assert.equal((await new ClaudeProposalHost(claude.setup, noisy).propose(request('claude'))).error.code, 'limit-reached');
});

test('timeouts and caller cancellation fence late SDK replies without claiming native or paid-usage quiescence', async (t) => {
  const f = await fixture(t, 'copilot');
  let complete;
  const sdk = copilotSdk(f, () => new Promise((resolve) => { complete = resolve; }));
  const controller = new AbortController();
  const pending = new CopilotProposalHost(f.setup, sdk).propose(request('copilot'), controller.signal);
  await waitFor(() => sdk.calls.sends.length > 0);
  controller.abort();
  const outcome = await pending;
  assert.equal(outcome.status, 'outcome-unknown');
  assert.equal(outcome.reconciliationRequired, true);
  assert.match(outcome.error.message, /paid usage may continue/);
  complete({ type: 'assistant.message', data: { content: response } });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(sdk.calls.aborted, 1);
  assert.equal(sdk.calls.disconnected, 1);
  const timeout = copilotSdk(f, () => new Promise(() => {}));
  const timed = await new CopilotProposalHost(f.setup, timeout).propose(request('copilot', {
    limits: { ...request('copilot').limits, timeoutMs: 100 },
  }));
  assert.equal(timed.status, 'outcome-unknown');
  assert.match(timed.error.message, /billing are not confirmed/);
});

test('already cancelled requests and a gate that resolves after the deadline never start a native SDK', async (t) => {
  const f = await fixture(t, 'copilot');
  const sdk = copilotSdk(f);
  const controller = new AbortController();
  controller.abort();
  const before = await new CopilotProposalHost(f.setup, sdk).propose(request('copilot'), controller.signal);
  assert.equal(before.error.code, 'authority-required');
  assert.equal(f.reviews.length, 0);
  let admit;
  const waiting = new CopilotProposalHost({
    ...f.setup, authorizeNativeStart: () => new Promise((resolve) => { admit = resolve; }),
  }, sdk).propose(request('copilot', { limits:{...request('copilot').limits,timeoutMs:100} }));
  await waitFor(() => admit !== undefined);
  assert.equal((await waiting).status, 'outcome-unknown');
  admit({status:'ok',value:{allowed:true}});
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(sdk.calls.clients.length, 0);
});

test('Claude cancellation closes transport even if interrupt never resolves and does not return a late result', async (t) => {
  const f = await fixture(t, 'claude');
  let resolveLate;
  const sdk = claudeSdk(f, async function* () {
    await new Promise((resolve) => { resolveLate = resolve; });
    yield { type: 'result', subtype: 'success', is_error: false, num_turns:1, result: response };
  });
  const query = sdk.query;
  sdk.query = (input) => ({ ...query(input), interrupt: () => new Promise(() => {}) });
  const controller = new AbortController();
  const pending = new ClaudeProposalHost(f.setup, sdk).propose(request('claude'), controller.signal);
  await waitFor(() => resolveLate !== undefined);
  controller.abort();
  assert.equal((await pending).status, 'outcome-unknown');
  assert.equal(sdk.calls.closed, 1);
  resolveLate();
  await new Promise((resolve) => setTimeout(resolve, 10));
});

test('Claude queued-message interrupt receipts never become cancellation evidence', async (t) => {
  const f = await fixture(t, 'claude');
  let release;
  const sdk = claudeSdk(f, async function* () {
    await new Promise((resolve) => { release = resolve; });
    yield {type:'result',subtype:'success',is_error:false,num_turns:1,result:response};
  });
  const query = sdk.query;
  sdk.query = (input) => ({
    ...query(input),
    async interrupt() { return {still_queued:['TEST-queued-id'],cancelled:[]}; },
  });
  const controller = new AbortController();
  const pending = new ClaudeProposalHost(f.setup, sdk).propose(request('claude'), controller.signal);
  await waitFor(() => release !== undefined);
  controller.abort();
  const outcome = await pending;
  assert.equal(outcome.status,'outcome-unknown');
  assert.equal('evidence' in outcome,false);
  assert.equal(sdk.calls.closed,1);
  release();
  await new Promise((resolve) => setTimeout(resolve,10));
});

test('Codex cancellation and timeout stop local consumption without synthesizing fenced host evidence', async (t) => {
  const f = await fixture(t, 'codex', 'hang');
  const controller = new AbortController();
  const pending = new CodexProposalHost(f.setup).propose(request('codex'), controller.signal);
  await waitFor(async () => { try { return (await f.readTranscript()).some((message) => message.method === 'turn/start'); } catch { return false; } });
  controller.abort();
  const outcome = await pending;
  assert.equal(outcome.status, 'outcome-unknown');
  assert.equal('evidence' in outcome, false);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual((await f.readTranscript()).find((message) => message.method === 'turn/interrupt').params, { threadId:'thread-test',turnId:'turn-test' });
  const late = await fixture(t, 'codex', 'late');
  const lateController = new AbortController();
  const latePending = new CodexProposalHost(late.setup).propose(request('codex'), lateController.signal);
  await waitFor(async () => { try { return (await late.readTranscript()).some((message) => message.method === 'turn/start'); } catch { return false; } });
  lateController.abort();
  assert.equal((await latePending).status, 'outcome-unknown');
  await waitFor(async () => (await late.readTranscript()).some((message) => message.lateOutput));
  await new Promise((resolve) => setTimeout(resolve, 75));
  const timedFixture = await fixture(t, 'codex', 'hang');
  const timed = await new CodexProposalHost(timedFixture.setup).propose(request('codex', { limits: { ...request('codex').limits, timeoutMs: 1_500 } }));
  assert.equal(timed.status, 'outcome-unknown');
  assert.equal((await timedFixture.readTranscript()).some((message) => message.method === 'turn/start'), true);
});
