# Restricted native proposal bridges

MissionSpec has original, programmatic adapters for three **user-installed**
native interfaces. These adapters implement `RestrictedProposalHostPort`, **not**
`CodingHostPort`. They neither dispatch implementation work orders nor issue
qualification, approval, passing-check, acceptance, or cancellation evidence.
No native SDK or executable is bundled or downloaded by these adapters.

The first-release Claude route is **SDK-free native skills/CLI/MCP**. Its optional
SDK-managed proposal bridge is deferred, not a prerequisite for that route.
Subscription-native skill qualification is also distinct from the restricted
proposal bridges described below; an API-key-only bridge must not be repurposed
by silently substituting credentials, models or permissions.

### Subscription-native metadata preflight on 2026-09-22

Follow-up checks permitted first-party authentication, quota and model-metadata
network reads, without inference or session allocation. Child environments
excluded inherited GitHub-token and provider/API-key overrides; parent/global
authentication and configuration were not changed. Credential-bearing
`account.getCurrentAuth` / `account.getAllUsers` Copilot responses were
deliberately not requested. No Claude SDK was installed or used.

**Current scope (2026-09-22T07:55Z):** the user explicitly deferred both Claude
and Codex live pilots. Claude login, context, billing and model probes and
follow-up fact requests are stopped. Existing SDK-free Claude skills/CLI/MCP
work remains implemented but not live-qualified. Any further bounded native
preflight is Copilot-only; no new conversation or model call is authorized.
All pilot admissions remain zero.

| Installed host | Actual non-generating evidence | Remaining admission prerequisite |
| --- | --- | --- |
| Copilot `1.0.85` | At `2026-09-22T07:47:05Z`, pinned stdio metadata matches the previously confirmed stored personal account, stable across the read. Included allowance is `80.1%`, with recorded overage `0`; both exhausted-quota flags remain `true`. `user.settings.get` still reports null effective/registered model defaults and `isDefault: true`. | Verify the applicable personal billing budget's enforced stop policy and resolve the exact existing default. Quota overage eligibility is **not** effective budget policy; its `true` value does not disprove the operator's settings change. Catalog order does not resolve a default. |
| Codex `0.155.1` | Earlier subscription metadata reported configured/default `gpt-6-astra`. No Codex command or fresh account read was performed after restart. | **Explicitly deferred by the user.** No account confirmation, read or pilot admission is requested for this phase. |
| Claude Code `2.1.267` | The completed `2026-09-22T07:46:44Z` check reported `loggedIn: false`, `authMethod: none`, `apiProvider: firstParty`, with no permission/network diagnostic, while the user's terminal reported `loggedIn: true`. This historical context mismatch remains unresolved. | **Explicitly deferred by the user.** No further login, context, billing or model probes, fact requests or conversation allocation. Preserve prior evidence and user-confirmed billing protection without claiming live qualification. |

Copilot remains **blocked before central pilot admission**; Claude and Codex
are deferred. No model calls or conversation sessions were started. Earlier
network-denied diagnostics alone were not treated as account or billing evidence. Codex initialization initially
could not create runtime state under a blanket native-home write denial;
allowing runtime state while protecting its auth/config files enabled the
successful metadata reads. That failure was not evidence of missing login.
The installed Copilot `--version` command prints a period after the version and
a fixed update hint on stdout. Version inspection now recognizes that exact
two-line banner as well as the prior single-line form. Extra output, altered
hints and version drift remain rejected; this parsing compatibility is not
model or billing qualification.

Copilot quota reads before and after restart, after the operator reported
disabling paid overages, remained bound to the same stored account and still
returned a true overage-eligibility flag. That field cannot verify or refute an
independent enforced zero-dollar budget. Protection remains **unverified**
because the applicable budget/stop policy has not been observed, not because
the user must have failed to disable paid usage. `inspectCopilotSubscription`
makes quota observation repeatable using only status, authentication, quota,
model-list and
[user-model settings metadata][copilot-settings-metadata] reads. It retains
only the model setting, preserves null defaults, records observation time,
checks a previously confirmed login digest when supplied, and rechecks identity
after the reads. Missing or malformed quota flags never become `false`.
User-settings metadata excludes session and managed overrides; the helper does
not allocate a session to discover a model or treat available models as an
implicit default. Entitlement amounts retain the server's field names/units,
not an inferred dollar or token budget. The helper exposes
`billingPolicyScope: quota-entitlement-only` and
`noAdditionalChargeProtection: unverified`, and always retains the separate
billing-review and central-admission gates. It no longer derives a misleading
`paidOveragesDisabled` attestation from either value of the quota flag.

GitHub's [budget concepts][copilot-budget-concepts] and
[personal-account budget instructions][copilot-budget-stop] describe an
independent **Stop usage when budget limit is reached** control. Required
evidence is the current applicable personal Copilot metered AI-credit or
bundled AI-credit budget, zero additional-usage allowance, and enforced stop
usage—not merely an alert, a license-only budget, or an unrelated organization
budget. The reviewed [budget REST API][copilot-budget-api] exposes organization
budgets; its user-scoped organization budgets are not personal-account budgets.
No documented personal-budget read endpoint was established. No guessed
endpoint, organization-budget read or billing mutation was attempted.

The installed non-generating `copilot help config` / `help billing` and the
[CLI command reference][copilot-cli-commands] provide interactive `/model` and
`/config model` views, but no sessionless effective-model resolver was
established. Null metadata therefore remains null. The parent can request the
exact current model shown in an **already-open** instance of the same authorized
Copilot CLI, without changing it or opening another session. Session/managed
overrides still need review before that observation can establish a new
session's default. Neither a documented generic default, the first catalog model
nor an Auto routing preference establishes this
account's actual selected model. Session credit limits are post-response soft
caps, not billing protection.

The operator subsequently confirmed that paid Claude extra usage, usage-credit
purchases and automatic credit reload are off or unavailable. This is recorded
as **user-confirmed billing protection**, not a fabricated server attestation.
It does not make the still-unobserved Claude login, subscription or default
model verified. Claude and Codex live qualification are explicitly deferred for
this pilot; improving metadata must not admit either host.

The post-restart Claude check used `/opt/homebrew/bin/claude`, resolving to the
installed `2.1.267` executable, with uid/effective uid `501`, matching `HOME` and
OS home, and the standard `.claude` config root. No `CLAUDE_CONFIG_DIR`,
`XDG_CONFIG_HOME`, model selector, alternate-provider, bare/safe-mode or SSH
selector was present. Only inherited `GH_TOKEN` was present among the checked
credential/provider overrides and was removed from the child environment;
parent configuration was untouched. The check had **no filesystem denial or
network sandbox**; its result is not attributed to a sandbox restriction.
It did not read credential files, keychain password items or raw debug logs.
The proposed terminal binary-path comparison was not performed and is no longer
requested following the explicit Claude deferral.

### Prepared metadata launcher and confinement evidence

`tests/helpers/native-metadata-preflight.mjs` is an operator/test qualification
harness, not a pilot or inference launcher. It exposes only pinned Copilot
sessionless metadata methods and Claude `--version` / `auth status --json`.
There is no prompt, conversation creation, login mutation or Codex launch
route. Each child has a 30-second deadline and a combined 2 MB stdout/stderr
budget; callers may only tighten these. Unknown callbacks, malformed framing,
oversized output and deadlines block without an automatic fallback. Native
credentials stay inside the installed CLI, and inherited provider/API-key
overrides are excluded from the child environment.

The prepared macOS profile permits data reads from the synthetic workspace,
installed/runtime system locations and explicit native settings paths. Writes
are limited to synthetic work/log directories and `/dev/null`. The root
directory itself is readable for dyld bootstrap, **not recursively**. Actual
synthetic probes established allowed workspace reads/writes, denied outside
reads/writes, denied symlink escapes, and unchanged outside sentinels. A
separate offline variant denied a live loopback connection after an unrestricted
positive control succeeded.

This is bounded filesystem evidence, **not complete native-host confinement**:
online metadata reads permit networking without endpoint-level enforcement;
system/runtime reads, filesystem metadata and OS brokers are not a hostile-code
or IPC isolation guarantee. No model execution, tool/MCP effect scope, Windows
or Linux confinement, descendant quiescence or billing fence is qualified.
The corresponding test is explicitly macOS-only.

Actual Claude status reads completed under the prepared profile but remained
signed out. Actual Copilot startup exited with `EPERM` before `connect` replied.
That is a **confined-launch compatibility blocker**, not proof of missing
Copilot authentication. The separately and explicitly invoked
`readNormalMetadata` baseline completed using the confirmed account and still
reported quota overage eligibility, not effective billing-budget policy.
The baseline is only native-home write
protection, not a substitute for the source-read profile. The stricter profile
was not widened to make Copilot pass. Neither route can admit a pilot, and
local timeout/process termination never establishes remote quiescence.

```sh
npm run build
node --test tests/native-metadata-confinement.test.mjs
```

The original `inspectCodexSubscription` helper in
`src/adapters/hosts/codex-subscription-preflight.ts` operates on an already
initialized, bounded transport. Its only requests are `account/read` with
`refreshToken: false`, paginated `model/list`, and `account/rateLimits/read`
with reserve fallback and separate reset-credit detail lookup disabled.
It rechecks account identity, bounds pages/buckets, strips identity strings and
unrelated metadata, preserves unknown quota/credit states, and always reports
that spending protection and central admission remain outstanding. It never
logs in, consumes a reset credit, creates a thread, submits a turn, or grants
`CodingHostPort` qualification. A missing `ordinaryUsageAllowed` is **unknown**,
not permission inferred from usage percentages.
Trusted composition can supply the previously confirmed account digest to
avoid redundant confirmation. A different identity is rejected; an unavailable
identity is reported as unavailable rather than falsely labeled an account
conflict. Confirmation does not waive billing or central-admission gates, and
Codex quota must be read again before any admitted prompt instead of reusing an
older near-exhaustion snapshot.
The pinned [account handlers][codex-account-metadata] establish these
non-generating read semantics and validate the account binding of
`ordinaryUsageAllowed`. Copilot's [quota RPC][copilot-quota-metadata] supplies
explicit quota/overage eligibility flags, not the independently enforced
personal-account budget or stop-usage policy.

This accepts `gpt-6-astra` as **subscription-native metadata**, not as a new
member of the API-key no-tools allowlist. The pinned model descriptor selects
code mode, multi-agent V2, asynchronous user questions and clock tools. Native
skills/CLI/MCP need their own synthetic-workspace/tool/approval review; disabled
feature flags from the proposal bridge cannot establish their isolation.
Actual skill discovery, MCP interaction, effects and cancellation still require
separately admitted execution evidence.

Before a bounded pilot, trusted composition must supply the actual isolated
synthetic project, verify the default-model/account snapshot, obtain an explicit
per-session admission, restrict the native tool/MCP scope, and record model,
usage, timing and file-preimage observations. No inference launcher or
automatic pilot is wired by the metadata helper. The initial envelope remains
at most three single-prompt sessions per host, serial across hosts, with no new
work after fifteen minutes per host and no automatic expansion. Local timeout
or process exit is not remote quiescence or a spending fence.
This envelope does not override the subsequent Claude and Codex deferrals or
authorize any Copilot conversation allocation during metadata preflight.

Minimal operator prerequisites are documented by the vendors: Copilot
[additional-usage budgets][copilot-individual-billing] and the native `/model`
or `/config model` view (inspect without submitting a prompt);
Codex [Settings > Usage / Usage & Billing][codex-credits] for credit balance and
automatic reload (not requested while deferred); and Claude's
[personal subscription login][claude-auth] with
[Settings > Usage, usage credits disabled][claude-credits]. The operator has
already confirmed the latter Claude login and billing settings. These are
preserved reference facts, not requests for further Claude checks while deferred. Claude's
documentation states that disabling usage credits leaves only included usage.
Copilot's installed `help limits` explicitly describes `--max-ai-credits` as a
post-response soft cap; Claude's `--max-budget-usd` describes API spending.
Neither is substituted for the account-level subscription-only prerequisite.

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
[copilot-individual-billing]: https://docs.github.com/en/copilot/concepts/billing-and-usage/individuals/billing
[codex-credits]: https://help.openai.com/en/articles/12642688-using-credits-for-flexible-usage-in-chatgpt-freegopluspro-sora
[claude-auth]: https://code.claude.com/docs/en/authentication
[claude-credits]: https://support.claude.com/en/articles/12429409-manage-usage-credits-for-paid-claude-plans
[codex-account-metadata]: https://github.com/openai/codex/blob/be2951ea34f0d295ed0becf97079f92fa5f6950e/codex-rs/app-server/src/request_processors/account_processor.rs#L1106-L1230
[copilot-quota-metadata]: https://github.com/github/copilot-sdk/blob/e60d9037353249ef16b349eb4012e8c1d113fda5/nodejs/src/generated/rpc.ts#L4975-L5047
[copilot-settings-metadata]: https://github.com/github/copilot-sdk/blob/e60d9037353249ef16b349eb4012e8c1d113fda5/nodejs/src/generated/rpc.ts#L23844-L23872
[copilot-budget-concepts]: https://docs.github.com/en/billing/concepts/budgets-and-alerts
[copilot-budget-stop]: https://docs.github.com/en/billing/how-tos/set-up-budgets#managing-budgets-for-your-personal-account
[copilot-budget-api]: https://docs.github.com/en/rest/billing/budgets
[copilot-cli-commands]: https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference

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
