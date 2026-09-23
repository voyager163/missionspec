# Optional usage telemetry

**The development composition has no active production endpoint.** Importing
or constructing these modules neither contacts a service nor probes endpoint
health. A separate receiver has been deployed with ingestion disabled; bounded
synthetic qualification is still pending. Its control-plane retention settings
were read back, not proved as exact physical deletion timing. Production client
delivery and real coding-host execution remain unqualified.

This component implements the existing `TelemetryPort` as a caller-owned,
one-root-operation client. It is not an SDK with auto-capture, an audit ledger,
or an execution permission system. Analytics eligibility never grants permission
to run a host, modify a project, persist diagnostic logs, or collect evidence.
See [logging.md](logging.md) for the separate local diagnostics boundary.

## Composed operation and controls

`createObservabilityLifecycle` in `src/composition/observability.ts` is the
application composition, rather than a global pre-action hook. Its `run`
method wraps one explicitly selected canonical top-level stateful operation,
emits typed start/stop diagnostics, measures monotonic elapsed time, and
classifies the actual functional result before requesting one aggregate.
It preserves the original result/error, including mandatory runtime audit
failures. Read-only/preview and child scopes do no observational state/network
work; nested wrappers share in-process duplicate suppression.

The CLI/application supplies `policy.disabled` from `--no-telemetry`, its channel,
the distributed version, and explicit optional `preferencePath` and
`localLogPath`. Paths are trusted user-owned destinations, never a project
endpoint source. No directory, preference store or log is created by composition
construction. The production sink remains absent by default.

The same composition exposes controls, none of which emits an analytics event:

| Method | Behavior |
| --- | --- |
| `telemetryStatus()` | Read-only policy/configuration status; hard disables precede preference reads, absent stores remain absent |
| `setTelemetryPreference("enabled" \| "disabled")` | Transactional explicit user-preference update; reports unconfigured storage or partial/unknown failure honestly |
| `previewTelemetry(summary)` | Pure validated canonical event preview with `delivery: "not-attempted"`; no store read, disclosure write or request |
| `previewLogPrune()` | No-write snapshot of the explicitly selected local diagnostic file |
| `pruneLog(preview, approvalReference)` | Requires trusted exact-scope persisted-reference authorization, then revision-checked truncation; not audit/evidence pruning |

Controls must be routed separately from `run`, not counted as workflow
operations. Utilities outside the canonical eligible registry must not be
renamed into synthetic operation IDs to manufacture telemetry; CLI commands
performing a canonical operation use that operation (`capture` → `draft`,
`patch` → `implement`, `collect` and stateful convergence capture → `verify`).
A fulfilled
operation returning a blocked/failed domain result must be classified according
to that result, not automatically as completed.

### CLI control handler

`runObservabilityCommand(positionals, values)` in `src/cli/observability.ts`
implements the canonical `telemetry status|on|off|preview` grammar for the main
entry point to route separately from workflow observation:

- `status` reads the dedicated user preference without creating a directory,
  database, log or first-use marker. Invocation/environment hard opt-outs
  return `preference: "not-read"` before accessing storage.
- `on` and `off` are explicit preference writes. They initialize only the
  dedicated private user directory/database when needed, merge the preference,
  and preserve the disclosure version. They do not acknowledge disclosure or
  activate any sink. A failed write retains the adapter's structured unavailable
  result, including safe reason, persistence and cleanup. The main entry point
  returns a blocked envelope and nonzero exit status while preserving that
  result. Unknown persistence is never a successful enable/disable response.
- `preview` returns a representative closed `draft` event with the distributed
  package version, current OS, unknown outcome/duration and no selected host.
  It is not a report of an executed operation. Delivery is `not-attempted`; it
  neither reads preferences nor writes a notice, log, approval or event.

No additional control flags are needed beyond existing `--json`,
`--no-telemetry`, `--preview` and `--approval`. `--preview`/`--approval` apply
only to `logs prune`, not telemetry controls. A hard opt-out suppresses
observation without initialization; explicitly invoking a preference write is
still a request to save that setting, even under `--no-telemetry`.

`observeCliOperation(positionals, values, version, work)` preserves the exact
domain result/error and uses the existing lifecycle; see [logging.md](logging.md)
for selected operations and read-only bypasses. No production sink is supplied,
including after `telemetry on`. Controls never report analytics about
themselves. The current CLI boundary is console-only and does not automatically
initialize workspace logging.

For tests/embedders, an explicit `preferences` port may substitute for
`preferencePath`, never coexist with it. `sink` injection remains trusted
embedding code. `onCompletion` receives closed local delivery/diagnostic
results and cannot alter the functional result. Callback failure/timeout and
classification/cancellation failure produce bounded explicit unavailable
diagnostics/results, without recursive observation.

Pruning is unavailable unless the trusted embedding supplies
`logPruneAuthorization.authorize({ preview, approval })`. It must validate a
genuine current persisted approval for the exact local diagnostic target,
revision, byte count and prune purpose. The CLI obtains genuine terminal
confirmation separately and supplies its reference, never a `confirmed`
boolean. See [logging.md](logging.md) for this gate and the physical stale-preview
check; telemetry preference controls do not grant pruning authority.

## Policy and side effects

The selected product policy is default-on **after prior disclosure and endpoint
qualification**, with hard opt-outs. A notice is disclosure, not affirmative
consent. The default client without a trusted injected sink returns
`{ state: "suppressed", reason: "not-configured" }` and does no preference,
notice, log or network I/O.

`createTelemetryClient({ policy, ... })` is exported by
`src/observability/index.ts`. `policy.channel` must be `interactive`, `json`,
`mcp`, or `unattended`. A trusted caller can inject an environment snapshot;
otherwise policy reads the process environment at invocation time, never import
time. It does not mutate the environment or serialize its values.

Policy is deny-first:

1. A per-invocation `disabled: true` (the caller's `--no-telemetry` mapping),
   `tests: true`, environment opt-out, CI/test detection, or malformed policy
   disables before reading configuration or constructing a request.
2. `discover`, `clarify`, `analyze`, `onboard`, and **every** summary marked
   `access: "read-only"` are excluded before config, notice or logging work.
   Telemetry controls, help/version/status/instructions/validation/diff and
   other queries must not create a root telemetry client invocation.
3. Without a sink, return `not-configured`; no spontaneous endpoint check.
4. A malformed/unreadable saved policy fails closed as `unavailable`.
   A saved disabled preference wins over every enabling setting.
5. Without the current disclosure version, JSON/MCP/unattended invocations
   return `notice-required` and never prompt or save a first-use marker.

Boolean environment parsing trims whitespace and ignores ASCII case:

| Variable | Disabled when |
| --- | --- |
| `MISSIONSPEC_TELEMETRY` | `0`, `false`, `no`, `off`, or any malformed value |
| `DO_NOT_TRACK` | `1`, `true`, `yes`, `on`, or any malformed value |
| `CI` | `1`, `true`, `yes`, `on`, or any malformed value |
| `NODE_TEST_CONTEXT` | Present, even empty |
| `NODE_ENV` | Present and neither `production` nor `development`; this includes `test` and malformed values |

The complementary boolean strings are recognized but never override another
denial. Absent variables impose no denial; an empty/whitespace-only value is
malformed, not absent. Unexpected non-boolean invocation flags also deny.
Tests deliberately inject an empty environment with a synthetic sink; ordinary
test execution is detected and suppressed. No project setting can enable
collection over an opt-out; project endpoint configuration is never read.

### First-use disclosure

An eligible interactive call may explicitly inject `writeNotice`, wired to
stderr, and a preference store. If no current disclosure exists, it writes the
versioned notice describing fields, destination, opt-outs, lack of IDs, network
metadata, and the planned 180-day analytics/total retention policy. It then
attempts to save the disclosure version. **That already-completed first
operation is still skipped**, so a notice shown after its completion is not
misrepresented as prior notice. A later eligible invocation can send.

The absence of an injected notice writer/store never prompts via another route.
Notice/persistence errors return `unavailable` and send nothing. Future
production activation must publish and qualify the operator, actual destination,
region/residency, privacy and retention policy, updating the disclosure version
when its meaning changes. Today's test-injectable sink is not that approval.

## The closed wire event

The single canonical wire JSON Schema is
[`assets/schemas/telemetry-event.schema.json`](../assets/schemas/telemetry-event.schema.json).
Producer runtime validators are pure and covered by schema-conformance tests;
they do not load files during import. A future receiver must consume that same
schema and apply the 1 KiB UTF-8 body limit, not accept a broader mirror schema.

| Key | Exact allowed values |
| --- | --- |
| `schemaVersion` | `1` |
| `event` | `operation-completed` |
| `operation` | `draft`, `draft-all`, `implement`, `verify`, `archive`, `revise`, `principles`, `sync` |
| `cliVersion` | Bounded numeric `major.minor.patch`, optionally `-alpha.N`, `-beta.N`, `-rc.N`; each number 0–999999 without leading zeros, at most 48 characters |
| `outcome` | `completed`, `blocked`, `failed`, `cancelled`, `unknown` |
| `host` | `copilot`, `codex`, `claude`, `none`, `multiple`, `unknown` |
| `os` | `macos`, `windows`, `linux`, `other` |
| `durationBucket` | The buckets below, or JSON `null` when unknown |

All eight keys are required; all other keys and unsupported versions are
rejected. Builds with arbitrary labels/build metadata are not collection-eligible
versions. Host is the selected enum, not detected executable output. Outcome is
a coarse caller-reported completion class, not proof of verified or accepted work.

Duration uses elapsed monotonic milliseconds supplied by the caller:

| Range | Bucket |
| --- | --- |
| 0 inclusive to 1 second exclusive | `under-1s` |
| 1 second inclusive to 10 seconds exclusive | `1s-to-10s` |
| 10 seconds inclusive to 1 minute exclusive | `10s-to-1m` |
| 1 minute inclusive to 10 minutes exclusive | `1m-to-10m` |
| 10 minutes inclusive to 1 hour exclusive | `10m-to-1h` |
| 1 hour or more | `1h-or-more` |
| Unknown | `null` |

Negative, nonfinite, nonnumeric, missing, or larger-than-safe-integer durations
are invalid. `null` is not zero. Elapsed operation time may include user waiting;
it is not an inference-performance benchmark. No client timestamp is sent.

Explicit exclusions: persistent/user/device/session/run identifiers, repository
URLs, project/change names, paths, arguments, prompts, source/spec contents,
environment/config values, raw errors/stacks, subprocess/test output, model
names, tokens, architecture and runtime-version details. There is no automatic
collection or arbitrary string metadata bag.

## Preference storage and controls

The client accepts `TelemetryPreferenceStore`. `read()` returns a committed
snapshot or explicit unavailability. **`save(patch)` atomically merges only the
supplied fields into the current committed state**; it is not a replacement of
an earlier read. This patch requirement also applies to injected stores.

`saveTelemetryPreference(store, "enabled" | "disabled")` is a separate control
that emits **no** analytics event and changes only `preference`. The client's
notice path saves only `disclosureVersion`. Consequently a concurrent notice
cannot undo an opt-out, and disabling/re-enabling cannot erase a disclosure
update. Enabling is not acknowledgement of a notice.

### Explicitly owned dedicated store

The built-in adapter now uses Node's built-in SQLite, without a new dependency:

```ts
const store = createUserTelemetryPreferenceStore(absoluteUserPreferencePath, {
  ownership: 'missionspec-telemetry-only',
});
await saveTelemetryPreference(store, 'disabled');
```

The required ownership declaration selects a **dedicated SQLite file as the
sole user-preference authority**, shared by every MissionSpec surface. It is
not runtime execution approval. The trusted application supplies the same
absolute path inside an existing private, user-controlled directory. The
adapter neither discovers project configuration nor creates directories.
Factories/imports do no I/O; `read()` on an absent path creates nothing.
Hard-disabled, read-only and unconfigured telemetry invocations never open
this store.

The CLI owns a deterministic user-local `telemetry.sqlite`, not a workspace
database or a mixed settings file. With no explicit configuration directory:

| Platform | Dedicated file |
| --- | --- |
| macOS | `~/Library/Application Support/MissionSpec/telemetry.sqlite` |
| Linux | `~/.config/missionspec/telemetry.sqlite` |
| Windows | `%LOCALAPPDATA%\MissionSpec\telemetry.sqlite`; when `LOCALAPPDATA` is absent, the home directory reported by the OS plus `AppData\Local\MissionSpec\telemetry.sqlite` |

An explicitly supplied absolute `XDG_CONFIG_HOME` selects
`$XDG_CONFIG_HOME/missionspec/telemetry.sqlite` on all three platforms.
An explicit absolute `MISSIONSPEC_CONFIG_HOME` takes precedence and declares an
exclusively MissionSpec-owned configuration directory; the file is
`$MISSIONSPEC_CONFIG_HOME/telemetry.sqlite`. Invalid or relative configuration
does not silently fall back elsewhere, including an explicitly empty or invalid
Windows `LOCALAPPDATA`. None of these variables selects an endpoint.
The CLI rejects symlinked or unsafe writable ancestors. On POSIX the selected
MissionSpec directory must be current-user-owned and private (`0700`).
On Windows, native validation requires canonical, absolute local NTFS paths,
current-user SID ownership and restrictive inheritable DACLs for private
entries; aliases, alternate streams and reparse points are rejected before
storage access. Existing profile/application-data containers are validated as
ancestors, not incorrectly required to be private leaves. Only new children
receive a private security descriptor atomically at creation. The CLI never
changes existing directory permissions or repairs an unsafe ACL.
Missing directories are created **only for explicit `on`/`off` saves**.

There is no automatic migration from general settings JSON, discovery of random
root databases, or workspace-local telemetry preference. Existing unrecognized
content at the dedicated filename fails closed without replacement. The
Windows CLI uses the same dedicated SQLite adapter with native private-state
validation, not a Windows `chmod` or UID approximation.
Ordinary hard-opted-out and unconfigured workflow invocations never initialize
the preference store. The standalone adapter still requires an existing parent;
directory initialization is the CLI control's responsibility, not hidden adapter
I/O.

Only preference and disclosure version are stored as user data in one
constrained singleton row. SQLite application/schema markers establish the
owned format, not an analytics identity. There is no endpoint, event queue,
identifier, timestamp or analytics history. The database is bounded to 64 KiB
(16 pages of 4 KiB); journals are SQLite's transient preference-transaction
recovery data, not telemetry queues. SQLite temporary storage stays in memory.
New POSIX files use mode `0600`; regular-file, final-symlink, owner and POSIX
group/world-write checks reject unsafe destinations. Windows files are created
with private SID ACLs, with private parent and single-link checks before SQLite
access. No platform falls back to a JSON mirror or another user's settings.

`tests/windows-cli-observability.test.mjs` is the separate native CLI
qualification candidate. Run
`npm run build && node --test --test-concurrency=1 tests/windows-cli-observability.test.mjs`
on Windows. Its actual CLI subprocesses isolate all user/configuration paths
under private OS-profile UUID fixtures and guard HTTP/HTTPS/fetch against any
network attempt. Coverage includes SQLite reopen/on/off, disclosure preservation,
path precedence, unchanged inspection mtimes, hard opt-outs, foreign-database
preservation and unsafe path/ACL refusal. The no-write guarantee concerns
MissionSpec preferences, notices, logs and project/foreign user state, not all
OS-runtime activity: Windows PowerShell's `-NoProfile` does not disable its
startup cache. Native fixtures keep a separate warmed disposable OS profile,
track every entry, and permit content/mtime updates only to its exact bounded
`StartupProfileData-NonInteractive` cache; see [logging.md](logging.md).
They do not repair existing ACLs or write MissionSpec state into the real user
profile. POSIX tests or a non-Windows skip do
not qualify this Windows CLI glue; a passing native run is required.

Existing JSON—valid or malformed—and unrelated SQLite databases are rejected
**without conversion, replacement, or clearing**. Unrelated general settings
remain untouched. Missing tables/rows, unknown schema/version, corruption,
unsupported disclosure versions, unsafe paths and lock contention never become
an empty/default-enabled preference.

There is no JSON mirror or fallback between authorities. In particular, an
application must not silently move an existing JSON-backed user to an empty
database and forget their opt-out. Before explicitly adopting the dedicated
authority, transfer and verify the user's existing choice through the store
controls, keeping telemetry disabled if that choice or migration is unresolved.
Then select this one authority for all surfaces. The old file remains untouched;
it is not subsequently consulted as a competing setting. No automatic migration
or independent settings-discovery mechanism is claimed here.

### Transactions, failures and recovery

- Saves use `BEGIN IMMEDIATE`, read/validate the current row, merge the patch,
  and commit. Competing successful updates are serialized by SQLite; independent
  fields are not lost to stale read-modify-write. Explicit changes to the same
  field take effect in commit order.
- Reads use a read-only connection and a snapshot transaction. They see a
  committed value or `unavailable`, never an intermediate empty row. They cannot
  initialize a database or perform write-required crash recovery. WAL-format
  files are rejected from their bounded header before opening SQLite, avoiding
  shared-memory sidecar initialization on a supposedly read-only read.
- Rollback-journal mode, `synchronous=EXTRA` and full filesystem synchronization
  are requested. Busy waits are bounded to 250 ms per SQLite operation; busy
  failures are explicit, with no retry loop.
- Exclusive file creation protects initialization. If another process sees
  incomplete initialization, it returns unavailable; it does not rewrite or
  default-enable the file. An explicitly requested later save can succeed after
  successful initialization.
- No general JSON file is renamed/replaced, and no advisory `.lock` is presented
  as protection against arbitrary editors. The dedicated file and directory
  must be exclusively managed by cooperating store users. Do not edit, replace,
  unlink or copy a live database or its journal. Malicious/noncooperating
  same-UID editors, untrusted ancestors, unsupported network filesystems, and
  actual hardware power-loss durability are outside this local qualification.

The built-in adapter returns `saved` only after successful commit **and close**.
Every built-in failure includes a safe `reason`, `persistence`
(`unchanged`, `committed`, or `unknown`) and `cleanup` (`complete` or
`incomplete`). A failed commit acknowledgement is not reported as success;
an acknowledged commit followed by failed close says `committed` with incomplete
cleanup. Rollback/file-close/database-close failures are surfaced, not swallowed.
No raw error message or path is included.

For `unknown` or incomplete cleanup, first retain an environment/per-invocation
opt-out, stop the owning processes, and reconcile with a fresh read before
assuming the setting changed. Do not blindly retry an enable operation or delete
a journal. An explicit save through the owned store can perform SQLite recovery
when safe. Interrupted first initialization may leave an empty/unrecognized
file; it is deliberately retained and fails closed. After all users are stopped,
the operator must inspect/restore a known backup or explicitly remove a confirmed
empty initialization artifact before creating the store again. Malformed or
unrecognized nonempty files are never automatically repaired or discarded.

`MISSIONSPEC_TELEMETRY=0`, `DO_NOT_TRACK=1` and the per-invocation disabled flag
remain immediate no-I/O opt-outs even if persistence is unavailable.

## Delivery and results

Trusted embedding code supplies a sink with a fixed, canonical HTTPS URL and a
transport. There is **no built-in production URL** and no acceptance of
credentials, query strings, fragments or project-controlled destinations.
Synthetic tests use a mock or a controlled loopback endpoint.

`createHttpsTelemetryTransport()` in `src/adapters/telemetry/https.ts` uses
native Node HTTPS with normal certificate verification, a 4 KiB response-header
bound, no pooled connection, and no SDK auto-capture. Its optional request
factory is a trusted test seam; tests use it to trust only their short-lived
loopback certificate, never disable certificate verification globally.

- At most one request per client instance/root completion; concurrent duplicate
  completion attempts return `unavailable` without a second send.
- The caller must create one client for each top-level operation, not each task,
  nested probe, tool call or child invocation. Manual file edits generate nothing.
- One-second delivery budget, propagated abort signal, no retry, durable queue,
  delayed replay, background flush or process-exit hook.
- Redirects and non-2xx status are unavailable, not followed or retried.
- Response bodies are destroyed rather than accumulated/drained; only status
  matters. The canonical request body must be at most 1 KiB.
- Serialization reconstructs allowlisted fields. Even direct transport calls
  reject noncanonical/duplicate-key bodies instead of forwarding hidden text.
- Transport errors never enter payloads, logs or result objects.

Results are exactly `suppressed` with `read-only`, `opted-out`,
`notice-required`, or `not-configured`; `delivered`; or `unavailable`.
`delivered` means only an endpoint's 2xx acknowledgement, not verified downstream
ingestion, retention or storage. Optional failure must never replace the
functional operation's outcome or exit code.

An injected `DiagnosticsPort` receives at most one safe, console-only failure
code per client. No diagnostic exception propagates and the sender does not wait
for a stalled optional diagnostic sink; required ledger durability is not
emulated. The standalone client bounds network delivery; the composed lifecycle
also bounds preference/notice preparation and delivery together to one second.
Cancellation after a stalled read/notice prevents subsequent saves or requests.
Already-started store writes are not falsely claimed cancellable or rolled back.

## Qualification and remaining boundaries

Run `npm run build && node --test tests/observability.test.mjs`. Tests cover
deny-first/no-I/O policy, first-use gating, schema parity, exact bucket edges,
legacy/malformed data preservation, real multiprocess preference/disclosure
updates, disable/re-enable, SQLite contention and pre-commit process exit,
explicit commit/rollback/close failure states, concurrent initialization, one-request ownership,
abort/timeout/redirect/failure behavior, sensitive sentinel exclusion, composed
controls, nested/root/read-only isolation, original-result preservation,
reviewed log pruning and the native closed-stderr-pipe regression.
The separate `tests/cli-observability.test.mjs` suite exercises the CLI handler
directly with actual dedicated SQLite preference changes, deterministic paths,
legacy/foreign-file preservation, hard-opt-out no-initialization behavior,
typed diagnostics, no-write queries and genuine controlled terminal pruning.
Main entry point routing is a separate integration responsibility.
With local OpenSSL available, the suite creates and removes a short-lived
synthetic loopback certificate and exercises native TLS, redirects, response
disposal, abort and timeout without external connections. If that tool is
unavailable, the test explicitly reports skipped rather than claiming proof.

The future MissionSpec-operated Azure ingestion service is a separate actor.
Its planned analytics **and total retention are 180 days**, without extra
archive/export retention. This client neither enforces nor proves that cloud
policy. Disabling stops future sends; it does not promise immediate deletion of
previously accepted aggregates. Network/cloud infrastructure necessarily sees
connection metadata; omitting identifiers is not an anonymity guarantee.

Not implemented here: production endpoint activation, actual Azure resources,
operator identity/region qualification, service retention readback,
automatic legacy-settings migration,
or live-host/OS qualification. Offline/unconfigured operation remains valid.
