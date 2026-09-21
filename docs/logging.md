# Local diagnostics

MissionSpec's diagnostics and lifecycle composition are optional observation.
Mandatory approval/audit/evidence recording belongs to the runtime/application,
not this component. These are different records:

| Record | Purpose | Failure behavior |
| --- | --- | --- |
| Authoritative runtime ledger | Approval, revision, effect, attempt and evidence integrity | Required failures remain blocking/reconciliation outcomes; optional observation never substitutes for them |
| Local diagnostics | Bounded troubleshooting codes on stderr or an explicitly authorized JSONL path | Return `unavailable`; safe stderr fallback does not claim file persistence |
| Optional analytics | The closed aggregate described in [telemetry.md](telemetry.md) | Best effort; never upload diagnostic files |

No diagnostic entry grants approval, proves execution, replaces evidence, or
records acceptance. There is no fabricated audit issuer or ledger fallback.

## Lifecycle composition

`createObservabilityLifecycle` in `src/composition/observability.ts` composes
real diagnostics, the optional client, explicit preference controls and reviewed
log pruning. It does not load project endpoint configuration or create
directories. The default sink is unconfigured, so no production request is made.

The application wraps an eligible operation once:

```ts
const result = await observability.run(
  { operation: 'draft', access: 'stateful', scope: 'root', engine: 'specification' },
  performReviewedDraft,
  () => ({ outcome: 'completed' }),
  () => ({ outcome: 'failed' }),
);
```

Classifiers must describe the actual result: typed blocked/failed/unknown domain
outcomes must not be relabeled completed merely because a promise fulfilled.
They return only an allowlisted outcome and optional error code, never messages,
paths or exception objects. Invalid classifiers generate a fixed rejection
diagnostic and no analytics aggregate.

The wrapper emits typed start/stop diagnostics and at most one completion
aggregate. It preserves the **identical functional return value or thrown
value**, including required audit-write failures. It does not alter exit codes,
approve effects, catch-and-replace a ledger failure, or write fake ledger rows.
`onCompletion`, when injected, reports only bounded observation results,
including explicit `classification: 'available' | 'unavailable'`. Its callback
is bounded to 100 ms. Throwing, rejecting or stalled callbacks produce a fixed
console-only unavailable diagnostic, never a recursive callback. Classification
and telemetry cancellation/setup/cleanup failures are likewise explicit safe
diagnostics/results; they do not silently become successful observations or
replace the functional result. If the fallback diagnostic sink also fails,
there is no recursive reporting loop.

Read-only invocation/preview contexts, known read-only helper IDs and explicit
child contexts bypass all observation, including clocks and file sinks. Async
context also suppresses nested wrappers across composition instances; concurrent
independent roots remain independent. Nested in-process detection is not a
cross-process identifier: separately launched children must be marked `child`
or not wrapped. No ID is persisted or sent to perform this bookkeeping.

Console-only is the default. Authorized local logging additionally requires the
trusted caller's explicit absolute `localLogPath` and
`persistence: 'authorized-local-log'` on that stateful invocation. Telemetry
disablement does not disable required audit or an explicitly authorized local
diagnostic destination. Neither the operation ID nor a log path grants runtime
authority.

### CLI boundary

`src/cli/observability.ts` exports `observeCliOperation(positionals, values,
version, work)` and `runObservabilityCommand(positionals, values)`. The main
entry point must route controls separately and wrap the **domain call**, before
formatting its result or converting it to an exit code.

The wrapper selects canonical stateful `draft`, `draft-all`, `revise`,
`principles`, `sync`, `archive` and `implement` invocations. Stateful `capture`
maps to `draft`, exact source `patch` to `implement`, and `collect` or
`convergence --file` to `verify`. It recognizes actual committed/synced results,
completed evidence collection, persisted convergence capture, draft-all's
no-plan stop reason, typed blocked/failed outcomes and thrown errors.
Uncommitted proposals and other unrecognized fulfilled results are `unknown`,
not success. Completed collection/capture is not a claim that checks passed or
proposed repairs executed. Unrelated utilities are not aliased into analytics
operations. All previews,
help/version, status, skills, validation, analysis, and current CLI `verify`
(including `--run`, which only reads retained evidence), plus convergence
inspection without `--file`, bypass observation.
Nested composition already prevents duplicate start/stop and completion events.

This boundary is **console-only**: it does not create `.missionspec`, a logs
directory, or a log file, including when telemetry is opted out. File diagnostics
remain an explicitly authorized embedding configuration, not a hidden side
effect of initializing or operating on a workspace.

The control handler accepts `logs prune [--preview | --approval <APR-id>]`.
It selects only `.missionspec/logs/diagnostics.jsonl` under the observed current
workspace, checks private ownership and rejects linked ancestors/targets.
`--preview` performs no writes and exposes only path, bytes and revision, not
contents. The default action requires an initialized workspace and a genuine
`TerminalAuthority` challenge; non-TTY answers cannot approve. `--approval`
resolves an already-persisted current terminal reference, not a caller boolean.

The existing project integration approval contract binds a single write of the
exact current diagnostic bytes to empty content. Its review revision additionally
binds the `prune-local-diagnostics` purpose, absolute path, byte count and
identity/content/metadata revision. The persisted display identifies the
truncation and explicitly excludes the runtime ledger, approvals and evidence.
The injected `logPruneAuthorization` callback rechecks private workspace/log
scope and resolves that exact request through `requireApproval` before the
JSONL adapter's locked stale-preview check. A changed snapshot needs a fresh
review. This control does not invoke the separate evidence pruner, emit
diagnostics about itself, or enable subsequent file logging.
The handler preserves structured unavailable results, including the safe
failure reason and whether the effect is unchanged or unknown. The main entry
point renders those results in a blocked envelope and exits nonzero rather
than fabricating a successful prune. Grammar and confirmation failures remain
typed `WorkflowError`s.

Writes through this CLI boundary are supported only on macOS/Linux. Windows
reports an explicit unsupported-platform result, never a POSIX-permission
success claim.

Each optional diagnostic attempt is bounded to 100 ms; a timeout is unavailable,
not a claim of persistence. Already-started filesystem work can settle later.
The composed telemetry preparation/delivery phase is bounded to one second with
cancellation; late preference reads cannot initiate notice, save or sending.
Mandatory functional work is outside these optional-observation deadlines.

## Embedding

`createDiagnostics` in `src/adapters/logging/diagnostics.ts` implements the existing
`DiagnosticsPort`. It requires an injected wall clock and stderr sink, and accepts
an optional local-log sink. Factory construction and module imports perform no
filesystem/network I/O or environment mutation. The supplied clock must return a
valid canonical UTC ISO timestamp with milliseconds.

Each `emit` explicitly selects `console-only` or `authorized-local-log`.
Console-only never calls the local-file sink or creates directories/files.
Applications must choose console-only for all read-only operations, including
inspection queries. The adapter also rejects file persistence for the known
read-only operation IDs `discover`, `clarify`, `analyze` and `onboard`, even if a
caller selects it. For other operations the logger cannot infer authorization
or invocation access from an operation ID; selecting file logging is the trusted
caller's responsibility, not a permission grant.

The local record contains only:

- `contractVersion: 1`;
- severity: `debug`, `information`, `warning` or `error`;
- code: `operation-started`, `operation-stopped`, `boundary-rejected`,
  `storage-failed` or `telemetry-unavailable`;
- a registered operation, registered engine or `null`, and registered error
  code or `null`;
- nonnegative finite elapsed milliseconds up to `Number.MAX_SAFE_INTEGER`,
  or `null` for unknown;
- an injected `recordedAt` timestamp.

Current port contracts have **no correlation-ID field**. Do not add one through
an extra property. Severity is caller-selected, not a global environment switch;
debug records require an explicit caller emission and obey identical field
limits. There is no arbitrary message/exception/output field at any level.

Input is validated before serialization. Unknown fields, accessors, unsupported
versions, invalid timestamps, unrecognized enum values and invalid durations
are rejected. Each UTF-8 JSONL record is at most 1 KiB including its newline.
Known fields are reconstructed before serialization; raw input objects and
exception messages/stacks never reach a sink. This allowlist is stronger than
best-effort masking of an arbitrary error string.

Invalid input returns `unavailable` with a fixed `boundary-rejected` stderr
fallback. Failed file persistence returns `unavailable` with a fixed
`storage-failed` fallback; `consoleFallback` reports whether that write succeeded.
If stderr itself fails, the result says `consoleFallback: unavailable`. Only a
successful append, synchronization and close returns destination `local-log`.
Neither failure changes an application's functional result automatically.

## Authorized JSONL adapter

`createAuthorizedJsonlSink(absolutePath)` in
`src/adapters/logging/jsonl.ts` is opt-in. The trusted embedding code supplies a
file path inside a private, user-controlled directory; the adapter does not
search project settings, create directories, or derive paths from operation
arguments. Parent directories must be trusted: final-component symlink
protection is not a sandbox for attacker-controlled ancestor directories.

- Creates files with mode `0600`; rejects final symlinks, nonregular files,
  multiple hard links, another owner's file, or group/other permissions.
- Requires a `.jsonl` target. Existing content must be bounded canonical
  diagnostic records, not arbitrary JSONL, raw evidence or a runtime database.
  Unrecognized content is neither appended to nor pruned.
- This built-in file sink fails closed on Windows because POSIX mode bits
  do not establish a private Windows ACL. Stderr remains available; a
  separately qualified Windows sink may implement `DiagnosticSink`.
- Appends one validated bounded record per write, synchronizes it, and closes.
  In-process pending writes are serialized, with at most 64 pending operations.
- An exclusive adjacent `.lock` coordinates independent instances/processes.
  Busy, stale or inaccessible locks fail explicitly rather than spinning.
  A crashed process can leave a lock; an operator must verify no writer remains
  before removing it. The lock does not coordinate arbitrary external editors.
- Each file is capped at 1 MiB. A full file reports unavailable; there is no
  automatic rotation, age deletion, queue on disk or success-shaped fallback.
  Caller-controlled filesystems and ordinary cooperating writers are assumed;
  unsupported filesystem semantics have not been qualified.

### Explicit reviewed pruning

`previewLogPrune()` on the composition (or `sink.previewPrune()`) opens an
existing file read-only and returns `absent`, `unavailable`, or a preview with
`scope: 'local-diagnostics-only'`, the target path, byte count and revision.
The revision binds content, file identity and modification metadata. Preview
creates no log, lock, preference, analytics event or ledger record, and returns
no log contents.

After genuine local confirmation has issued a persisted approval reference, the
application calls `pruneLog(preview, approvalReference)`. A caller boolean,
`{ confirmed: true }`, or a syntactically valid reference alone is **not**
authority. The composition requires an injected trusted
`logPruneAuthorization.authorize({ preview, approval })` port; without it,
pruning is unavailable.

That port must resolve persisted authority, reject absent/expired/revoked or
superseded grants, and validate the exact local-diagnostic prune purpose, path,
byte count and revision. It returns only `authorized`, `rejected` or
`unavailable`. It must not issue an approval, prompt, or turn a caller flag into
authorization. Reference syntax and immutable closed preview/reference copies
are validated before invoking the port. Authority lookup is bounded to one
second; exceptions, malformed responses and timeouts fail closed without
truncation. This composition creates no approval issuer or fake ledger record.

The low-level `sink.prune(preview)` is a raw trusted I/O adapter, not an
authorization controller. Only after the composition's trusted authorization
gate succeeds does it invoke that primitive. Under the writer lock the adapter
rechecks current content and identity before truncating. A changed file returns
`stale-preview` without deletion, even if an older preview was approved.
Unrecognized references, wrong-scope grants and invalid previews do nothing.

Successful prune returns `pruned`; failures state whether the effect was
`unchanged` or `unknown`. A failure after truncation/synchronization/cleanup is
not reported as a clean success. No automatic age deletion, missing-file
creation, audit pruning or evidence pruning occurs. Unrecognized/noncanonical
files require separate operator inspection, not an automatic destructive repair.

## Output and qualification

`createStderrDiagnosticSink()` writes only to stderr. The adapter never writes
stdout, keeping JSON and stdio-MCP result channels separate. Functional result
formatting, read-only invocation policy and shutdown behavior belong to the
calling application.

Run `npm run build && node --test tests/observability.test.mjs`. The tests cover
closed serialization, malicious sentinel exclusion, import-time inactivity,
private file creation, busy/full/error cases, console-only isolation and explicit
revision-checked pruning. Lifecycle tests cover original-result preservation,
mandatory-audit failure propagation, root/child/read-only isolation, controls,
bounded stalls, and the native closed-stderr-pipe regression. These local
observation tests do not themselves qualify a ledger, raw
evidence storage, real coding-host behavior, or OS/filesystem-wide qualification.

`node --test tests/cli-observability.test.mjs` additionally exercises the CLI
boundary directly, including no-write controls, result/error preservation,
typed stderr diagnostics and real controlled pseudo-terminal confirmation,
persisted-reference validation and diagnostic-only pruning. These tests do not
substitute for the main entry point's routing tests.
