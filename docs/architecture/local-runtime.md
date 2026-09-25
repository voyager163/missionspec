# Local workflow runtime, version 1

This phase implements real local project/file/ledger workflows, not a complete
released product or a qualified coding-host integration. The CLI can commit
reviewed local effects through `TerminalAuthority`: an actual OS terminal,
complete escaped review display, and fresh challenge response. Noninteractive
channels refuse. The library still defaults to unavailable authority/host ports;
embedding applications must explicitly compose trusted ports. Test host fixtures
are **TEST ONLY**, never qualified native-host bindings.

No coding-host subprocess, model, Git operation, telemetry transport or deployment
is invoked. Explicitly registered and separately authorized local checks can run
real subprocesses. They are trusted local programs, not sandboxed code.
The separate telemetry service and infrastructure are not prerequisites.

## Commands

Except the stdio MCP entrypoint, commands support `--json` and `--no-telemetry`. JSON stdout contains one
result object; controlled errors omit raw filesystem/JSON exceptions.
`spec`, `source` and `evidence` options may be repeated. Paths are relative to the
selected current directory; a change selector is its flat slug, not a guessed ID.

| Command | Implemented behavior |
| --- | --- |
| `project status`, `change list` | Read explicit project identity/configuration and open-change inventory |
| `init [--preview] [--profile standard\|compact]` | Review identity, configuration and additive ignore entry; bootstrap state only after terminal confirmation |
| `change new <slug> --spec <name> [--source <path>] [--preview]` | Review change metadata, complete spec output set and baseline observations |
| `status <slug>`, `analyze <slug>` | Read live scoped files; report DAG readiness, stale captures, typed coverage and clarification blockers |
| `instructions <slug> [--artifact <node>]` | Emit version-1 skeletons and next-node guidance without writing or generating claims |
| `draft <slug> [--artifact <node>] [--preview]` | Review one missing skeleton; it remains incomplete and uncaptured |
| `capture <slug> --artifact <node> [--preview]` | Validate and review capture of all edited outputs of one node |
| `revise <slug> --artifact <node> [--preview]` | Review recapture; descendants become stale |
| `draft-all <slug> [--preview]` | Review a bounded capture batch of already supplied Markdown; never implement |
| `discover <slug> --file <markdown> [--preview]` | Review saved discovery in the selected change |
| `principles --file <markdown> [--preview]` | Review project principles without a change |
| `clarify <slug> --file <questions.json> [--preview]` | Review explicit question/answer records; JSON is input, not authority |
| `applicability <slug> --reason <text>` | Explicit Compact separate-design decision, bound to source and captured predecessors; `--required` reverses it without deleting content |
| `patch <slug> --task <TSK-id> --file <inert-proposal.json> [--preview]` | Derive exact candidate source writes from untrusted output and separately review their application; dependent tasks require `--run` and `--evidence` |
| `clarify <slug>` | Read questions, responses, artifact binding and unresolved/stale blockers |
| `verify <slug>` | Report structural/coverage gaps and missing evidence; never run checks |
| `verify <slug> --run <RUN-id> --evidence <EVD-id>` | Review retained digest-checked evidence recorded in that exact run |
| `run status <RUN-id>` | Read the durable run, admitted scope, attempts, dependency evidence and reconciliation history without dispatch |
| `mcp [--no-telemetry]` | Serve the MCP stdio protocol in the process's fixed working directory, without banners or CLI JSON output |
| `check register <slug> --file <registration.json> [--preview]` | Independently review an immutable program/argv/cwd/definition/source-scope registration |
| `collect <slug> --registration <check-id> [--run <RUN-id>] [--preview]` | Separately authorize checks and retain observed subprocess results in an existing or new verification run |
| `accept\|sync\|archive <slug> --run <RUN-id> --evidence <EVD-id>` | Guided separate acceptance, promotion and closure confirmations; stop on refusal or any blocker |
| `sync <slug> --acceptance <APR-id> [--preview]` | Review accepted, conflict-aware promotion without closing |
| `archive <slug> --outcome <accepted\|rejected\|cancelled\|incomplete> [--acceptance <APR-id>] [--preview]` | Exact known-file historical copies and closure; unrelated files survive |
| `recover [transaction-id] [--preview]` | Read pending journals or explicitly confirm roll-forward; never recover on status |
| `approval show\|revoke <APR-id>` | Inspect persistent authority or revoke through a fresh terminal exchange |
| `skills inspect [--host <host>]` | Inspect native skill ownership and drift; no setup, grants or host invocation |
| `skills install\|update\|remove --host <host> [--preview]` | Review selected native skill files and installation ownership; repeat `--hosts` for multiple targets |
| `onboard` | Read project status and guidance with setup, editing, execution, evidence, acceptance, promotion and closure separately gated |
| `adopt --file <adoption.json> [--preview]` | Review new-change-only upstream source preservation and explicit native mappings |
| `context status` | Explicitly report the absent standalone provider; compatible providers require trusted library composition |
| `convergence <slug> [--file <review.json>] [--preview]` | Inspect or review source-bound semantic/static gap findings; blocking or stale reviews prevent acceptance and promotion |
| `lessons history <id>`, `lessons select <slug> --file <selection.json>` | Inspect history or select current applicable untrusted advice |
| `lessons capture\|evaluate\|transition <slug> --file <input.json> [--preview]` | Separately review candidate, evidence evaluation and human activation/retirement/rollback |
| `evidence prune --evidence <EVD-id> [--preview]` | Review exact raw removal and historical-acceptance impact; preserve immutable compact history |
| `evidence pending`, `evidence status <sha256-id>`, `evidence recover <sha256-id> [--preview]` | Inspect or explicitly recover a prepared prune without replaying completed deletion |
| `telemetry status\|on\|off\|preview` | Inspect/change the dedicated local preference or preview an illustrative aggregate; never activate a production endpoint |
| `logs prune [--preview\|--approval <APR-id>]` | Review and truncate only the dedicated diagnostic log; never delete evidence or ledger history |
| `state status [--json]` | Inspect an existing ledger, record counts and point-in-time capacity without initialization, writes or telemetry |
| `state backup\|stage\|restore` | Review bounded logical/raw-evidence backup and non-destructive recovery; never roll back authority or current ledger facts |
| `state select\|activate\|recover` | Prepare a private replica, separately activate the central ledger selection, or recover its journal under a current-ledger lease |
| `state migrate` | Inspect the explicit version policy or review conversion of a backup into a nonactive native recovery replica |

See [runtime state lifecycle](runtime-state-lifecycle.md) for exact command syntax,
external selection semantics, retained evidence, migration limits and
missing/corrupt-current-state reconciliation.

Existing `capabilities`, `skills list`, `skills render`, `validate` and `--version`
remain supported. Native execution CLI entrypoints explicitly report
`host-unqualified`. `--auto` never bypasses this gate. The injected controller
defaults to Interactive; Auto requires explicit mode and hard bounded limits.
`--approval` can resolve an existing exact current grant, not create one.
`--yes`, arbitrary request fields, JSON/stdin answers and environment flags do
not issue authority. `--preview` is always read-only.

## MCP CLI entrypoint

Launch `missionspec mcp` (or `node dist/cli/main.js mcp` in a source checkout)
with the intended workspace as the process working directory. The CLI supplies
that fixed root and the distributed package version to `serveMissionSpecStdio`.
Tool arguments, `clientInfo`, and environment approval/root hints do not select
another root or grant authority.

Stdout belongs exclusively to the SDK's MCP protocol transport. Startup failures
and invalid CLI arguments go to stderr; `--json`, `--help`, `--version`, host and
approval flags are rejected for this command. Use the global CLI help before
starting a protocol connection. The server retains its 1 MiB inbound transport
limit and bounded tool results.
An existing workspace-bound evidence store is opened read-only and closed on
transport shutdown. MCP does not create or migrate a ledger on startup.

The CLI does not compose terminal confirmation into MCP stdin or implicitly
install a reviewer. The server owns tool advertisement and any explicitly
composed elicitation callback. With no reviewer supplied, read/preview tools
cannot apply changes. Library callers can import `createMissionSpecMcpServer`,
`serveMissionSpecStdio`, and `MissionSpecMcpOptions` from the root package; an
MCP review/resolution composition must use the same trusted broker instance.

## Local terminal authority

`TerminalAuthority.open(root)` performs no writes. `confirmPlan(plan)` displays
the exact current and proposed file content, guards, root/workspace identity,
purpose and effects. `requestConfirmation(request, detail)` also displays the
canonical request; the optional detail is review material, never an approval
boolean. A random 128-bit challenge must be answered through OS-backed terminal
stdin/stderr within two minutes. Approvals expire after 30 minutes.

Before any authorized effect, the adapter fsyncs an exclusive owner-only receipt
in `.missionspec/approvals/`, binding the canonical request, exact displayed
material, issue/expiry times and local protocol identity. Revocation is a separate
immutable record. Only genuinely confirmed setup may create this owned audit
state before workspace identity exists. No generic `approved: true` issuer is
shipped. Content digests are integrity checks, not signatures or qualification
artifacts. Implemented protocol identity is a separate `{ id, version }` field.

This is **local-user assurance**, not an organization account, proof that a
person rather than same-UID terminal automation typed the response, or
tamper-proof protection against the local account. Controlled pseudo-terminal
tests exercise the real protocol; they do not establish those stronger claims.

### Shared backend for trusted elicitation transports

`openLocalAuthority({ directory, transport? })` is the production persistence
factory shared by `TerminalAuthority` and trusted embedding transports. Opening
it does not write. Omitting the transport permits receipt resolution, not
issuance. The return type is `LocalConfirmationAuthority`, with
`requestConfirmation`, `confirmPlan`, `resolve` and `revoke`.

The exported `TrustedConfirmationTransport` contract is:

```ts
interface TrustedConfirmationTransport {
  readonly channel: 'terminal-confirmation' | 'mcp-elicitation' | 'trusted-callback';
  readonly protocolIdentity: { readonly id: string; readonly version: string };
  confirm(
    review: LocalConfirmationReview,
    signal: AbortSignal,
  ): Promise<'accept' | 'decline' | 'cancel' | 'unavailable'>;
}
```

For a server-composed MCP hook:

```ts
const authority = await openLocalAuthority({
  directory: registeredRoot,
  transport: {
    channel: 'mcp-elicitation',
    protocolIdentity: { id: 'missionspec.mcp-form', version: '1' },
    confirm: confirmViaCorrelatedSdkResponse,
  },
});
```

`confirmViaCorrelatedSdkResponse` is an application-installed function, never a
tool argument. Unsupported elicitation returns `unavailable`; it does not fall
back to terminal identity or an approval flag.

The backend supplies a detached, deeply frozen `LocalConfirmationReview`:
`id`, `action` (`issue` or `revoke`), optional subject approval (`null` for
issuance), complete parsed `request`, `requestDigest`, observed `workspace`,
exact `display`, `displayDigest`, escaped `renderedDisplay`, `expiresAt`, and
`deadlineAt`. Show the exact review without silently truncating or substituting
scope. If a client cannot safely present it, return `unavailable`. The form asks
only for a non-secret confirmation decision, never credentials.
All supplemental data is nested under `display.detail`, including
`detail.filePlan` and `detail.previous` for exact file reviews. A caller's
`detail.request`, `detail.action`, `detail.assurance` or expiry fields cannot
replace the canonical displayed request or issuer-controlled metadata.

New version-2 receipts and revocations are parsed with closed runtime schemas:
every field, reference, channel, protocol identity, calendar timestamp, review
deadline, request digest and display digest is validated. The parsed
`display.request` must equal the issued request field-for-field; recomputing a
display hash cannot make a substituted request applicable.

A stdio MCP composition may install a callback that capability-negotiates form
elicitation and maps only the SDK's correlated user response to a decision.
An SDK `action: "accept"` alone is insufficient unless the expected explicit
confirmation field also validates; submitting an unrelated/default-valued form
must not become consent.
Missing elicitation, transport errors, malformed responses and late acceptance
deny issuance. The backend aborts the callback after at most two minutes, ignores
late responses, re-observes root/identity, and fsyncs the exact review receipt
before returning a grant. Both decline and cancel map to a non-issued `declined`
result. An approval expires at the displayed absolute time, 30 minutes after
review creation; an expired historical approval can still be explicitly revoked.

The transport is a **trusted composition capability**, not a tool argument or
generic JSON issuer. Do not expose transport construction, approval records, or
arbitrary runtime writes as MCP tools. `clientInfo`, host environment, model text,
`approved: true`, and request-carried consent are not authentication. A registered
root and isolated stdio session define the embedding boundary; the callback must
preserve that boundary and its response correlation. Issued assurance explicitly
records `qualification: { state: 'not-established' }`,
`humanPresence: 'not-attested'`, and `organizationIdentity: 'not-attested'`.
Protocol identity describes the implemented adapter; it is not measured
qualification evidence. No descriptive-word hash is accepted as a qualification
artifact. Actual qualification would require independent retained artifacts and
validation, which this broker does not claim. No MCP SDK/network call is made by
the backend itself.

An arbitrary MCP client can synthesize an elicitation response. The example
callback is appropriate only inside an independently trusted UI integration;
simply wiring `requestMcpReview` to a generic client's accept response does not
create that trust. The standalone CLI deliberately does not install it.

Terminal and callback receipts use the same owner-only store and can be resolved
or revoked across those transports. Existing version-1 terminal receipts remain
readable through closed legacy validation, without rewriting their bytes. Legacy
descriptive hashes are discarded from resolved assurance rather than treated as
measured evidence. A legacy callback is reported as `trusted-callback`, not
silently relabeled as terminal or MCP. Newly issued MCP and terminal receipts
retain their own distinct channel/protocol identities when resolved through the
shared backend. Cross-root/workspace requests remain rejected.

## Public library composition

The root package exports `LocalWorkflow`, `LocalWorkspace`, `ExecutionController`,
`TerminalAuthority`, `openLocalAuthority`, `LocalChecks`, `executionApprovalRequest`,
`executionPlanApprovalRequest`, `openRuntimeStore`, effect/revision/identity helpers
and the relevant port/record types. These are lower-level APIs, not an assertion
that every method of the earlier twelve-operation `MissionSpecOperations`
interface is implemented.
The root also exposes the six public engine contracts as named namespaces:
`discovery`, `specification`, `planning`, `execution`, `verification`, and
`integration`. Consumers can reuse their pure parsers/assessments without
importing private engine paths or inventing another core.

`LocalWorkflow.open(directory, { authority?, store?, now? })` does not write.
Its implemented methods are:

- Reads: `project`, `loadChange`, `instructions`, `verificationGaps`, `verify`.
- Previews: `previewSetup`, `previewNewChange`, `previewArtifact`,
  `previewDraftAll`, `previewClarification`, `previewCapture`,
  `previewPrinciples`, `previewApplicability`, `previewSourcePatch`, `previewAcceptance`, `previewPromotion`, `previewArchive`.
- Effects: `confirm`, `apply`, `commitSourcePatch`, `accept`, `commitPromotion`, `commitArchive`.
- Host/check composition: `observeExecution(slug, workOrder, phase)`, `readObservation(evidenceId)`.
- Recovery through `files`: `pending`, `recoveryPlan`, `recover`.

`confirm` delegates an **untrusted request** to the injected authority. Its default
result is unavailable. Terminal applications use `confirmPlan` for complete file
review and `requestConfirmation` for acceptance/execution requests. JSON, a
previously unissued approval ID, client metadata,
an environment variable, skill text, a progress marker and process exit are not
authority. A callback installed by trusted composition is not an untrusted
request field. Never install a fixture authority in a real integration.

`apply(plan, reference)` accepts local editing/setup previews, not source patches,
promotion or closure. Their dedicated commit methods recompute the exact preview.
Every file transaction re-resolves current authority, expiry,
request digest, workspace/root scope, operation, purpose and effects. Raw storage
ports remain trusted-composition facilities; do not expose them as arbitrary
agent/MCP write tools.

Project principles can be previewed without any change. They participate in
every open change's revision/clarification binding but confer no runtime grant.
Saved discovery is `discovery.md` inside the change. A question's `user` response
is a reviewed assertion, not authenticated organization identity; a
`proposed-assumption`, missing answer or stale artifact binding blocks a material
question. Its persistence still requires an exact artifact-edit confirmation.

## Canonical layout and observations

```text
missionspec/config.yaml
missionspec/principles.md
missionspec/specs/<capability>/spec.md
missionspec/changes/<slug>/change.yaml
missionspec/changes/<slug>/{proposal,design,tasks,discovery}.md
missionspec/changes/<slug>/specs/<capability>/spec.md
missionspec/changes/archive/<closed-date>-<slug>/...
.missionspec/workspace.json
.missionspec/state/ledger.sqlite
.missionspec/transactions/<transaction-id>.json
.missionspec/transactions/<transaction-id>.done.json
.missionspec/evidence/...
.missionspec/approvals/...
.missionspec/checks/...
.missionspec/audit/...
```

Project/change metadata uses declarative YAML, schema version 1, closed fields and explicit output
inventories. Change metadata contains stable identities, pinned workflow bytes,
selected source paths, captured file/dependency digests, baseline observations,
clarification state and promotion provenance. It contains **no editable mirror
of requirements/tasks/checks** and no private workspace identity. Markdown is
canonical; parsed task/check graphs are derived.

`change new ... --verification-plan` explicitly declares `verification.md`
alongside `tasks.md` as one task/check artifact. Default changes keep check
definitions in tasks. Expanded tasks frontmatter may set
`checks: verification.md`; the complete sibling document is then required
when validating/capturing the set. Check IDs must still have one canonical
definition. `draft`, `capture`, `revise` and `draft-all` include both declared
outputs; changing either invalidates their shared captured revision.

Archive previews include every bounded regular file below the selected change,
including imported provenance and personal notes, and preserve their relative
paths. Newly added files invalidate closure at the cooperative writer boundary.
Unknown or oversized content is not silently orphaned. A conflicting
`closure.json`, unsafe file or oversized transaction blocks the archive.

Setup alone proposes a random `WSP-` identity. Its root digest covers the resolved
local root, device and inode. The identity is stored only after confirmation,
outside portable Markdown. A moved/copied root fails binding checks; there is no
automatic rebinding or migration.

Source identity covers only the **explicit source-file set**, including absence,
not the whole repository. An empty set is not proof of source-tree stability.
Execution admission requires every writable task path to be in that observed set.
Supplied snapshots/digests are not live filesystem observations. File collection
checks regular files, symlinks, hard links, byte limits and changes during reads.
Status performs no logging, state initialization, telemetry or recovery.

Standard is default. Compact is explicit and its task artifact includes Design.
Its separate design node remains required until a reviewed not-applicable
decision records a reason, source and exact predecessor revisions. Existing
design content cannot be silently skipped or deleted. Expected admitted source
evolution preserves that intent decision during execution/evidence review while
still observing every selected source and checking exact file effects.
The entire declared spec set is one node. Manual edits do not silently recapture
dependency provenance. Templates never become structurally ready by existing.

## File transactions and assurance limits

The POSIX-oriented adapter uses an exclusive cooperative workspace writer lock,
owner-only runtime files/directories, exact guards and same-directory staged
writes. New files default to `0600`; ordinary existing file modes are preserved
on replacement. Other-owner and special-mode targets are refused, not silently
reowned or stripped of permissions. Before artifact effects it fsyncs an immutable prepared journal containing
the complete plan and resolved approval receipt. It rechecks guards and authority
during the transaction, validates final outputs, then fsyncs a separate completion
receipt. Journal payloads are bounded so recovery can read what was written.

This is **not a multi-file atomic filesystem operation** and not a claim that
SQLite commits artifact files. A failed prepared transaction is outcome-unknown;
it blocks further file plans. `recoveryPlan` accepts only original or exactly
proposed bytes at mutation targets, with unchanged read guards. `recover` requires
a current trusted confirmation for the same exact plan and rolls forward.
Unknown edits are preserved and block recovery. No automatic rollback, broad
directory deletion, migration, age-based evidence pruning or hidden conflict
resolution is performed.

The only additional hidden file allowed in ordinary artifact transactions is
`.missionspec/installation.json`, and only for `onboard` + `integration` with
configuration-file purpose. Approvals, journals, checks and ledgers cannot be
edited through that allowance. Immutable runtime record APIs are trusted adapter
composition facilities, not arbitrary agent write tools.

The application checks durable execution quiescence inside the file writer lock.
Its execution observer refuses that lock, and the controller re-observes after
durable admission before dispatch. SQLite serializes admission against other
active/unreconciled workspace runs. A trusted integration must use both sides of
this composition; a custom observer that omits the lock/root/source checks does
not inherit them.

A process crash can leave the cooperative lock or a staging file. There is no
automatic PID-based stale-lock deletion. Establish writer quiescence and inspect
the retained journal before an operator removes an abandoned lock/stage; then
use reviewed recovery. Corrupt journals/receipts require explicit investigation,
not success or destructive cleanup.

Same-UID adversarial confinement is **not provided**. Portable Node filesystem
APIs do not supply race-proof directory-relative compare-and-swap. Keep the
workspace private and trust its local composition. Windows now has a separate
[qualified real application integration](windows-state.md) over the qualified
SID/ACL and directory-barrier primitives. It restricts writes to private
current-user NTFS roots, preserves supported source security, and still requires
exact current grants. Independent
[console/ConPTY and owned-job check qualification](windows-execution.md) also
passed on actual Windows. Native AI-host execution remains gated. Local macOS or
Linux tests do not substitute for Windows evidence or native-host qualification.
Network filesystems are not qualified.

## Execution, verification and acceptance

`ExecutionController({ store, observe, authority?, host?, clock?, verifyTask?,
readEvidence? })` implements single-work `dispatch`, `runPlan`, `reapprovePlan`,
`reconcile`, `status` and `control(runId, 'pause' | 'cancel', reference)`.
`observe` is trusted composition, normally `LocalWorkflow.observeExecution`.
Native host ports remain unavailable by default.

Admission requires current authority, an exact host/version/OS qualification
with exact-effect-scope permission enforcement, hard controls and confirmed cancellation, live task/scope matching, and
durable CAS state **before** dispatch. Its approval request additionally binds
run/work-order identities. Full work orders, request digests, qualification
references and admission times are append-only in run history. Optional admission
payloads extend schema-2 rows without migrating existing rows or tables.

Admission also carries a persisted per-attempt dispatch token. A host is not
qualified merely because it can stop an already running process: it must enforce
`durable-admission-token` fencing. `requestStop(workOrderId, token)` may report
confirmed quiescence only after the token is durably cancelled, all its effects
are stopped, and any delayed or replayed dispatch for that token will be rejected.
The receipt must identify that exact token. This property must survive the host
adapter's relevant process/restart boundaries; test-only in-memory tombstones do
not qualify a real host.

The controller rechecks durable admission after asynchronous observation and
before hand-off. That check alone cannot close a cross-process hand-off race,
which is why receiver-side fencing is required. Controls use the persisted token
and matching qualification; old admissions without a fence or wrong receipts
cannot become confirmed quiescence. The default host still implements none of
these guarantees and remains unavailable.

One bounded, topologically ordered **exact-effect** plan can contain multiple tasks. Its full
material digest is approved once, while the original plan, each work order,
per-attempt fence, limits and verified task/evidence mappings are persisted.
Interactive pauses after one verified task; Auto advances serially only after
trusted verification and retained-byte dependency checks. Exit zero, host claims,
checkboxes and removed pending IDs cannot establish completion.

Every order has exact reviewed before/after file scope and observed source
identity, including predicted in-plan evolution. The controller reduces each
host hand-off's duration to the remaining original wall/consumed-monotonic budget;
consumed duration is persisted and cannot decrease, and observed clock rollback
blocks continuation. Reapproval
cannot reset that budget, task limit, or maximum two repairs per task. A failed
task can be explicitly resubmitted within those bounds. Reapproved remaining
source effects are append-only plan versions; changed task/artifact intent
requires a new reviewed run. No-progress and unknown outcomes stop earlier.

Restart uses durable admissions, completions and retained evidence, not progress
claims. Unknown attempts require the originally qualified host's token-specific
`inspectDispatch` receipt with fenced terminal result, observed source and exact
attempt sequence. No inspection capability means refusal, not retry. Pause/cancel
resolve the admission's persisted authority and fence. Emergency stop grants no
new effects. Scheduling completion is not final verification or acceptance.

### Generated source is an inert proposal, not an approved effect

`WorkOrder.effects` still requires each proposed content digest **before**
dispatch. This controller therefore schedules already-known byte transitions;
it does not authorize an ordinary coding model to invent source bytes under a
once-approved task plan. A task's `writeScope` is a bound for candidate validation,
not a filesystem permission grant. There is no wildcard/directory-write effect,
unbounded shell fallback or implicit approval of model output.

The implemented alternative is patch-only output followed by reviewed local
application:

1. A separately authorized `RestrictedProposalHostPort` may return a
   `BoundedProposal`. Its host label, summary and content remain untrusted data.
   Proposal generation/data sharing/spending are not source-write authority.
2. `previewSourcePatch(slug, taskId, proposal, dependencies?)` reads the live
   workspace, current captured intent, selected source files and exact task.
   It rejects stale preimages, undeclared paths, control-file aliases, extra
   fields, ambiguous duplicate paths and oversized output. It derives each
   proposed digest from the actual replacement bytes; a model cannot supply
   the trusted effect digest or a `passed`/`approved` claim.
3. The resulting `FilePlan` uses operation `implement` with distinct purpose
   `source-apply`. Its review subject binds the complete task, proposal digest,
   dependency evidence, source observations and exact source-file writes.
   It grants no host dispatch, checks, shell, model spending or execution limits.
   Obtain a genuine confirmation of that complete candidate through `confirm`
   or `confirmPlan`.
4. `commitSourcePatch(slug, taskId, proposal, preview, approval, dependencies?)`
   recomputes the candidate and commits it through the same guarded, journaled
   filesystem transaction. Source-apply grants cannot be replaced by earlier
   execution, artifact-edit, verification or acceptance grants.

For dependent tasks, `dependencies` is `{ runId, evidence }`. All transitive
predecessor checks must have unique retained passing observations with the
current source, method, definition, workspace and intent. Verification-only runs
are valid evidence producers; a host exit or completion checkbox is not needed
or sufficient. Evidence bytes become read guards of the patch transaction.
Applying a patch creates no fictitious host attempt, task completion or check
result. Verify the resulting source separately before acceptance or further
dependent patches.

The initial format supports full UTF-8 file replacements/creation only, with at
most 128 files, 1 MB per replacement and 4 MB total replacement content. Empty
text means an empty file, not deletion. Workflow/runtime/Git metadata are excluded,
including case/compatibility aliases. Unknown/deletion payloads are refused.
Artifact editing retains its existing exact-byte approval path.

Completed exact source-apply journals can preserve Compact applicability across
the observed before/after source chain without recapturing or rewriting intent.
Unknown edits, incomplete journals, changed artifacts or unrelated source hashes
cannot establish that provenance. Recovery still requires the original exact
plan and current confirmation; it never reruns a model.

**Generative Auto does not silently cross this boundary.** New candidate bytes
pause for source-apply review. The exact-effect Auto controller and its durable
admission tokens, cancellation, inspection, dependency checks and budgets are
unchanged. A patch transaction is not an Auto admission or a way to reset a run's
repair/duration limits. Fully autonomous generation under a broader write-scope
grant would require a separately designed and qualified effect-enforcement
contract; it is not claimed here.

Verification reads evidence IDs recorded in the selected run, the immutable
reference, and actual retained bytes. The digest-checked raw envelope is:

```json
{
  "schemaVersion": 1,
  "evidenceId": "EVD-example",
  "basis": "executed",
  "result": "passed",
  "output": "Actual retained output from the trusted evidence producer"
}
```

This is a **trusted producer's evidence format**, not an arbitrary client success
claim. `LocalChecks` supplies actual registered local subprocess observations;
trusted embeddings can supply other explicitly qualified methods. Injecting a
store of fabricated observations does not qualify checks. Evidence must match the exact
workspace, run, source, check definition and declared method; missing/pruned,
stale, failed and altered bytes block acceptance. Raw outputs remain retained.
Failed checks identify already scoped tasks as repair proposals, not auto-fixes.

### Explicit local checks

A registration file contains `checkId`, absolute real `program`, `argv` (array,
never shell prose), workspace-relative `cwd` (`.` for root), `controlFiles`,
`timeoutMs` (1–300000), and `guarantees: "trusted-local-process"`. Registration
binds the workspace/root, check definition, executable bytes, selected control
file bytes and explicit source scope. Its own terminal confirmation is separate
from execution authority. Changing those inputs requires new registration.
Revocation disables future use; expiry of the original one-time registration
approval does not erase an already recorded registration.

Collection requires a fresh verification-purpose confirmation, a cooperative
writer lock, workspace quiescence and a durable running admission before spawn.
The program receives no shell, no stdin and a fixed minimal environment. Actual
stdout/stderr, exit/signal, timing, registration and before/after source bindings
are retained. Output is bounded to 1 MB; timeout/output overflow triggers
best-effort process-group cancellation, marks the run outcome-unknown and cannot
produce accepted evidence. Escaped descendants cannot be proven stopped.
Mandatory filesystem/network confinement or hard process-tree quiescence is
therefore **refused**, not claimed. Only run trusted programs whose local effects
the reviewer understands; selected file observations are not a whole-tree sandbox.

Ledger/retention failures block verification and acceptance. Acceptance rechecks
source/evidence and workspace quiescence under the writer lock, records its audit
before the durable acceptance, and never grants host effects.

`previewAcceptance` recomputes verification, binds the report and selected run as
a review subject, and asks for separate acceptance authority. `accept` recomputes
again, resolves that authority and persists the actual evidence IDs.
`ReviewBinding.kind = 'review'` preserves the **complete original revision
binding**, adds a subject digest and separately binds review effects. Acceptance
does not grant the execution effects recorded in the subject run. Full revision
equality was not weakened; operation/purpose/workspace replay is rejected.

## Shared promotion and closure

Accepted baseline specs use explicit project-wide `kind: baseline`, no fabricated
change ID and no delta operation fields. Requirement metadata is `{}`; scenario
metadata contains its requirement reference. Parsed retained facts have the
derived operation `retain`. There is one editable baseline, not a parallel JSON
specification.

Promotion applies explicit add/modify/remove operations to stable facts, preserves
retained prose/title/notes, including introduction and Requirements preamble,
validates every baseline in nested capability directories, and previews the
deterministic rendered bytes. Concurrent modifications to a targeted baseline
file conflict even if a heuristic could merge them. Untargeted files are never
rewritten. Removing the final facts cannot implicitly discard baseline Notes.
The complete baseline inventory is rechecked while holding the cooperative file
writer lock, so another participating writer cannot insert an unobserved
capability between preview and publication. Same-UID noncooperating races remain
outside the filesystem assurance boundary described above.
Same-content repeat sync is a no-op when recorded promotion provenance still
matches. New deltas require fresh capture/acceptance.

The accepted-archive library primitive requires existing shared promotion.
The CLI guides acceptance, that same promotion, and then closure within one
invocation; it never hides conflicts in a second merge path. Acceptance, promotion and
closure are separate approvals. Other closure outcomes remain explicitly
rejected/cancelled/incomplete. Known change files are copied exactly; unrelated
files/edits remain in place, and nonempty archive destinations block.

External capability gates remain for exact native AI-host
permission/limit/cancellation/fencing qualification and mandatory adversarial
check confinement. Windows storage, namespace, console and trusted owned-process
evidence are documented separately above. No model or live paid host calls were made. Unknown local
process outcomes cannot be auto-cleared without inspection evidence that the
portable process adapter cannot supply.

Reviewed skill installation composes `SkillInstallation` with the same
`LocalWorkflow.files` guards and terminal authority. A combined first install
can explicitly review setup plus only the known native skill destinations.
It never grants native host execution or changes host configuration. Updates
and removal preserve unowned/modified files and require ownership comparison.

Reviewed lesson capture, evidence evaluation, activation, retirement and rollback
are implemented; model-backed semantic effectiveness is not established.
Semantic/model qualification and cloud deployment remain separate workstreams.
Cross-file fact relocation/rebase assistance is not an implicit feature of
conflict-aware sync. The whole approved product is not claimed complete.
