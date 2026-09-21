# Restricted native proposal bridges

MissionSpec has original, programmatic adapters for three **user-installed**
native interfaces. These adapters implement `RestrictedProposalHostPort`, **not**
`CodingHostPort`. They neither dispatch implementation work orders nor issue
qualification, approval, passing-check, acceptance, or cancellation evidence.
No native SDK or executable is bundled or downloaded by these adapters.

### Installed-tool observations on 2026-09-21

The local macOS installation reports Copilot CLI `1.0.85`, Codex `0.155.1`,
and Claude Code `2.1.267`. Claude does not match the reviewed `2.1.278` pin;
it was not updated or invoked with a model.

The actual pinned Copilot SDK `1.0.14` was installed only in private qualification
scratch, without installation scripts or optional native bundles. MissionSpec's
external factory type-checked against its actual published types. SDK startup
and `getStatus()` then passed under the same network-denying OS policy:
CLI `1.0.85`, protocol `3`, empty-mode isolated home/workspace, no credentials,
no created session and no model request. This qualifies that narrow local
transport seam only, not skill invocation, generation, permissions or Auto.

Codex generated its actual experimental JSON schemas and completed
`initialize` / `initialized` / `config/read` in an isolated empty home/workspace,
with no credentials supplied and OS-level network access denied. No login,
thread or model turn was requested. That is protocol/configuration evidence,
not live model or autonomous execution qualification.

The initial effective-config response did **not** expose
`tools.update_plan.enabled` and `tools.experimental_request_user_input.enabled`.
Pinned-source review established that these are real `ToolsToml` controls:
the runtime resolves them and conditionally registers the two handlers.
The app-server converts that configuration to the narrower `ToolsV2`, which
contains only `web_search`. This is a readback projection mismatch, not proof
that the switches are unsupported. The adapter now requires both `false`
values in exactly one **active session-flags layer**, even if the typed
projection contains them. Missing, enabled, contradictory or ambiguous controls
still block; arbitrary missing settings are not excused.

A second configuration-only probe passed the production layer/effective-config
validators under OS-level network denial, with no credentials, login, thread
or model request. Its typed projection was `{ "web_search": null }`; the
session layer contained `{ "enabled": false }` for both tool controls.
API-key catalog discovery, token-budget tools, context management and
current-time reminders all read back `false`. The user and system layers were
empty. Hooks normalize to twelve named empty arrays; these are accepted, but
any nonempty or unknown hook is rejected. Scratch homes were removed afterward.

The probe also confirmed that this pin requires an existing `CODEX_HOME`.
The app-server therefore uses the caller's already-verified empty
`homeDirectory`, not a nonexistent child directory. This is a narrow local
configuration-compatibility result, **not live no-tools qualification**.

The native process also emits `remoteControl/status/changed` even while remote
control is disabled. The adapter now validates and discards that precise
disabled notification; active, malformed or unexpected remote-control states
still block. Installation/server identifiers are not returned in proposals.

| Adapter | Required installation | Reviewed source revision |
| --- | --- | --- |
| `CopilotProposalHost` | `@github/copilot-sdk` **1.0.14**, Copilot CLI **1.0.85** | SDK `e60d9037353249ef16b349eb4012e8c1d113fda5` |
| `CodexProposalHost` | Codex CLI **0.155.1**, `app-server` stdio interface | `be2951ea34f0d295ed0becf97079f92fa5f6950e` |
| `ClaudeProposalHost` | `@anthropic-ai/claude-agent-sdk` **0.3.278**, Claude Code **2.1.278** | SDK `18661edde4498f76ff5599b17ee4ca81d98409b2` |

The Copilot SDK is MIT-licensed; its CLI has separate proprietary terms. Codex is
Apache-2.0-licensed. The Claude Agent SDK and Claude Code have commercial terms.
Installing, approving terms for, or redistributing these dependencies is an
operator/legal decision, not an implicit part of installing MissionSpec.

## Two independent boundaries

1. **Native model/data admission:** each proposal request explicitly opts into
   `dataSharing` and `modelSpending` for one host. Trusted composition must also
   supply `authorizeNativeStart`. There is no default permit. This gate reviews
   the request/configuration digests, installed SDK manifest identity, executable
   digest and **required**, not yet observed, CLI version before any executable
   is started. A bounded `--version` probe subsequently checks the exact version.
   The executable and SDK manifest are rechecked before model invocation.
2. **Implementation effects:** a successful result is only an
   `inert-proposal`: a summary and complete replacement texts with exact
   project-relative paths and expected source digests (or `absent`). MissionSpec
   must independently revalidate current source, preview effects, obtain its
   normal approval, journal writes, apply files, and execute registered checks.
   Proposal consent cannot grant any of those effects.

The caller supplies content snapshots. Adapters do not read source files, apply
patches, run checks, or translate native tool calls into MissionSpec tools. A
proposal cannot add commands, removals, hidden paths, permissions, tools, or
unknown fields to its schema. An allowed path without a supplied snapshot can
only have `expected: "absent"`; this remains an inert precondition, not proof that
the file is currently absent.

## Setup boundary

`NativeHostSetup` requires:

- A real absolute executable path, with symlink traversal refused.
- Two separate, fresh, empty, real directories: `workingDirectory` and
  `homeDirectory`. **Never use a source checkout or the user's normal home.**
  The operator provisions them and handles native-generated state under the
  applicable retention policy. A native launch may populate these directories;
  the next invocation must receive fresh ones rather than silently reuse state.
- An explicit model and exactly one explicit authentication variable. Copilot
  accepts `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, or `GITHUB_TOKEN`; Codex accepts
  `OPENAI_API_KEY` or `CODEX_API_KEY`; Claude accepts `ANTHROPIC_API_KEY` or
  `CLAUDE_CODE_OAUTH_TOKEN`. Credential availability and provider-specific
  authentication are operator responsibilities. Empty credentials, multiple
  credentials and ambient logged-in-account fallback are refused.
- A trusted external `authorizeNativeStart(review)` returning
  `Outcome<{ allowed: boolean }>`. `allowed: true` is an invocation admission,
  **not qualification evidence**. The gate must fail closed when external
  installation, platform, managed-policy, source-isolation, or account/spending
  prerequisites have not been independently established.

There is no shell command interpolation and no inherited environment. The
adapters set isolated home/config locations and a minimal executable search
path. The configuration digest includes the selected authentication binding,
but neither credentials nor native diagnostics are exposed in review/result
objects. Native version output, executable changes, wrong SDK names/versions, and
an SDK `gitHead` that disagrees with the reviewed revision are refused. Package
manifests without `gitHead` must still match exact name/version; a manifest is
not cryptographic proof of the entire dependency tree. The external installation
gate owns package-lock/integrity, supply-chain, executable provenance, transitive
dependencies, and platform qualification.

### Externally installed SDK factories

Copilot and Claude receive a factory bound to a module installed and reviewed
**outside MissionSpec's dependency tree**. `packageJsonPath` must identify that
very module, resolved to its real absolute path. Factory code is trusted
composition, not untrusted model input. Do not accept a factory or manifest path
from MCP arguments, source files, skills, or a model.

The following is original integration wiring, not vendored SDK implementation.
It belongs in the operator's separately reviewed integration package, where
the exact external dependencies have already been installed:

```ts
import { CopilotClient } from '@github/copilot-sdk';
import { query } from '@anthropic-ai/claude-agent-sdk';
import {
  CopilotProposalHost, ClaudeProposalHost,
  type ExternalCopilotSdk, type ExternalClaudeSdk,
} from '@msn-control/missionspec';

const copilotSdk: ExternalCopilotSdk = {
  packageJsonPath: realCopilotPackageJsonPath,
  createClient: (options) => new CopilotClient(options),
};
const claudeSdk: ExternalClaudeSdk = {
  packageJsonPath: realClaudePackageJsonPath,
  query: (input) => query(input),
};

const copilot = new CopilotProposalHost(reviewedCopilotSetup, copilotSdk);
const claude = new ClaudeProposalHost(reviewedClaudeSetup, claudeSdk);
```

The paths and reviewed setup values above are supplied by trusted composition,
not inferred or automatically installed. The factories are structurally typed:
no `as any`, fake version, fabricated qualification, or module-shape cast is
needed. An SDK whose API is incompatible requires review, not an assertion.
Codex needs no SDK factory: `new CodexProposalHost(reviewedCodexSetup)` owns the
original JSON-lines app-server transport directly.

## Protocol restrictions

**Copilot:** the pinned SDK client uses
`connection: { kind: "stdio", path, env }`, `mode: "empty"`, explicit
`workingDirectory`/`baseDirectory`, no built-in plugin directories, no remote
sessions, and no logged-in-user fallback. Each invocation creates a fresh
session with `availableTools: []`, no custom tools/MCP/agents/skills/plugins,
no config discovery, no managed settings, no filesystem hooks, no host Git,
no session store, no instruction discovery, and no embedding retrieval. Empty
mode also disables memory and other CLI defaults. Every permission request
returns `{ kind: "reject" }` and fails the operation. No session is resumed;
`continuePendingWork` is a resume-only option in this pin and is never enabled.
The connected runtime's `getStatus()` must also report the pinned CLI version.
The selected explicit token is passed as the SDK's `gitHubToken`, not a shell
argument or an implicit user-login lookup.

**Codex:** launches `codex app-server --listen stdio://` with fixed command-line
configuration overrides. `initialize` declares `experimentalApi: true`.
Its response must match the pinned initialization shape and isolated
`codexHome`; `userAgent` and application `clientInfo.version` are not binary
version evidence. Provider-model fallback is explicitly disabled.
`config/read` must confirm the restrictive settings, with the two source-verified
`ToolsV2` omissions checked in the disclosed active session layer; unexpected
ambient instructions, MCP servers, hooks, plugins, or enabled capabilities
fail before a thread/turn is started. Configuration provenance is requested:
active nonempty system, user, project, MDM and managed layers are refused, not
merely overridden. Only the reviewed package defaults and explicit session
flags may contribute settings. The OpenAI model provider is explicit; custom
provider configuration is empty.

The reviewed profile is `codex-0.155.1-api-catalog-no-tools-v1`. It accepts only
the exact `gpt-5.4` and `gpt-5.5` model names. Their descriptors in the pinned
bundled catalog have no `experimental_supported_tools`, `tool_mode` override
or `multi_agent_version` override. This is important: other bundled models can
select code mode or multi-agent tools **despite disabled feature flags**, and
can add asynchronous user-input, clock or test tools independently of the
environment list. Unknown models and aliases are not accepted via fallback
metadata. API-key model discovery is explicitly disabled (the pinned manager
gates both remote refresh and cache loading), custom catalog paths are rejected,
and the native home starts empty. This pins the reviewed native tool-selection
metadata, not provider model weights, availability or paid behavior.

Both `thread/start` **and every**
`turn/start` set `environments: []`. Threads have no dynamic tools/capability
roots and must acknowledge an empty environment list and ephemeral state.
Separate hosted search, MCP configuration, apps,
collaboration, hooks, plugins, skills, memory, permission tools, and other tool
feature paths are disabled rather than relying on the environment list alone.
The pinned registry omits shell/stdin, file patching, image viewing and
permission-request tools without environments; empty MCP sources remove
MCP/resource tools. Disabled hosted search/image generation and extension
features close the separate tool sources. Token-budget/context-management,
clock-reminder, sleep and deferred-executor paths are also disabled.
`update_plan` and synchronous `request_user_input` remain explicitly disabled:
no planning exception is needed. The planning handler itself only emits a
native plan update and returns `"Plan updated"`, but this profile still rejects
plan notifications/items. Native plan text or `"completed"` steps never become
MissionSpec completion, evidence or permission.
The admission configuration digest binds the profile identity, model allowlist,
two source-reviewed projection omissions, native-home policy and empty native
tool allowance, as well as the configuration and requested model.
The pinned read-only policy is exactly
`{ type: "readOnly", networkAccess: false }`, **not** the old
`readOnly.access` shape. Thread acknowledgement must match the working
directory, model, policy and empty instruction-source list. Bidirectional
command/file approvals receive `cancel` (which interrupts rather than merely
continuing after a decline). Permission requests receive an empty turn-scoped
grant; dynamic tool calls return `success: false`; MCP elicitation receives
`action: "cancel"`. Unknown requests receive a JSON-RPC error. Every such
unexpected request terminates proposal processing. Tool/effect item events,
uncorrelated messages and unknown protocol shapes are refused. Asynchronous
agent-message delivery, embedded questions and memory citations are refused
rather than being interpreted as final proposal output.
The restricted profile requires the fresh `turn/start` acknowledgement before
turn/output notifications. A response and following notifications in one stream
chunk are handled in order; pre-acknowledgement completion is rejected rather
than guessed to belong to the request. Live qualification must confirm this
ordering for the exact pinned server. A version/profile with different ordering
needs an independently verified correlation design, not a permissive fallback.
After effective configuration is checked, `account/login/start` supplies the
explicit API key to the isolated app-server and must acknowledge API-key
authentication. No browser/device login, existing user auth, or external
ChatGPT-token mode is enabled. `cli_auth_credentials_store: "ephemeral"` keeps
that native authentication in process memory instead of an ambient keychain or
saved login. The external gate must still review native state and retention.

**Claude:** each `query` supplies `tools: []`, `settingSources: []`,
`strictMcpConfig: true`, `mcpServers: {}`, `permissionMode: "default"`, empty
hooks/plugins, `persistSession: false`, and `maxTurns: 1`. The adapter supplies
an explicit replacement environment; the pinned SDK does not merge it with
`process.env`.
`allowedTools` is deliberately not treated as an allowlist. Unexpected startup
tools, MCP servers, plugins, skills, model, version or permission mode fail
closed; assistant tool-use blocks and tool permission callbacks are rejected.
Managed policy still applies inside Claude Code. Startup observation is not
proof that managed policy could not act before initialization; the external
gate must independently review that deployment. No native `outputFormat` is
requested because its automatic repair loop could bypass MissionSpec's repair
budget.

All three send one proposal turn, never invoke repair themselves, and validate
the response locally. MissionSpec owns its independent maximum-two-repair
policy. Transport/network retries and native internal model behavior are not
represented as a guaranteed one-billable-call cap.

## Limits and interruption are not native guarantees

- Input, proposal, and observed protocol-output budgets are UTF-8 byte limits.
  Input/output limits are at most 4 MiB, context/allowed-file lists at most 128,
  and local deadlines at most five minutes. Unknown fields and native requests
  are rejected. These are **local** admission/consumption limits, not provider
  token, memory, network, task, or monetary caps.
- Codex stdout is protocol-only; malformed framing is rejected. Bounded stderr
  is discarded, never forwarded as proposal text or MCP stdout. Claude stderr
  is also counted and discarded. SDK event limits act **after SDK
  deserialization**. Copilot's SDK owns its raw protocol/stderr handling; its
  `logLevel: "none"` is not a raw-byte or SDK-memory fence. External transport
  qualification must cover those remaining native/SDK resource surfaces.
- Deadlines and caller aborts fence local result acceptance and attempt native
  cleanup. Copilot calls abort/disconnect/force-stop; Codex requests
  `turn/interrupt` and terminates its child best-effort; Claude interrupts and
  closes even when interruption does not settle.
- A `sendAndWait` timeout, process exit, interrupt acknowledgement, disconnect,
  or SDK close is **not** durable quiescence, descendant termination, admission
  fencing, or a paid-usage guarantee. Interrupted invocations return
  `outcome-unknown`, never applicable proposals or synthetic fenced evidence.
  Late messages are discarded, and there is no automatic retry.
- Claude's high-level `interrupt()` does not send `cancel_queued`. Its receipt,
  including an empty `still_queued` list, is not evidence that queued work is
  impossible. This adapter never enqueues or reuses a query: it uses one string
  prompt, fences local output, and closes the query. The interrupt result is
  intentionally opaque to the proposal contract.
- Empty directories, environment cleaning, no tools and a read-only native
  policy are not OS-level source isolation. Native executable/SDK code runs
  with the invoking user's privileges. External isolation and managed-policy
  gates remain necessary; do not advertise these adapters as exact-effect
  executors.

## Local verification and remaining gates

`tests/native-hosts.test.mjs` uses original synthetic SDK objects and synthetic
local executable/JSONL fixtures. It does not invoke installed native models,
contact providers, consume paid model usage, or generate qualification evidence.
It covers every-turn restrictions, wrong pins, malformed/oversized responses,
ambient configuration, unexpected tool requests and approvals, stdout/stderr
discipline, source-preimage/path scope, deadlines, cancellation and late replies.

```sh
npm run build
node --test tests/native-hosts.test.mjs
npm run check:architecture
```

Live CLI/SDK compatibility, credentials/account consent, installation provenance,
licensing, all supported operating systems, effective managed/system policies,
SDK raw transport bounds, and independent source confinement remain externally
gated. No live qualification has been claimed. Any version change requires a new
review, protocol fixtures and independently collected qualification evidence.

Protocol references: [Copilot SDK pinned API][copilot], [Codex pinned
thread/turn protocol][codex], and [Claude Agent SDK reference][claude].

[copilot]: https://github.com/github/copilot-sdk/tree/e60d9037353249ef16b349eb4012e8c1d113fda5/nodejs
[codex]: https://github.com/openai/codex/tree/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/app-server-protocol
[claude]: https://code.claude.com/docs/en/agent-sdk/typescript

Codex profile source evidence at the reviewed revision:

- [Real TOML tool controls][codex-tool-config], [runtime resolution][codex-tool-resolution],
  [narrow protocol projection][codex-tool-projection] and [config/read conversion][codex-config-read].
- [Tool registration and environment gates][codex-tool-registry],
  [upstream registration regressions][codex-tool-tests] and [planning handler][codex-plan-handler].
- [Bundled model descriptors][codex-model-catalog],
  [model tool-mode precedence][codex-tool-mode] and [API-key refresh/cache gate][codex-model-discovery].
- [Memory extension gates][codex-memory-tools] and [history/notes extension gates][codex-history-tools].

[codex-tool-config]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/config/src/config_toml.rs#L622-L646
[codex-tool-resolution]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/core/src/config/mod.rs#L2664-L2678
[codex-tool-projection]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/app-server-protocol/src/protocol/v2/config.rs#L157-L162
[codex-config-read]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/app-server/src/config_manager_service.rs#L137-L177
[codex-tool-registry]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/core/src/tools/spec_plan.rs#L973-L1282
[codex-tool-tests]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/core/src/tools/spec_plan_tests.rs#L1217-L1243
[codex-plan-handler]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/core/src/tools/handlers/plan.rs#L65-L111
[codex-model-catalog]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/models-manager/models.json
[codex-tool-mode]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/core/src/tools/mod.rs#L68-L90
[codex-model-discovery]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/models-manager/src/manager.rs#L434-L477
[codex-memory-tools]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/ext/memories/src/extension.rs#L45-L52
[codex-history-tools]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/ext/history-notes/src/extension.rs#L45-L63
