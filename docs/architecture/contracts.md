# MissionSpec contract foundation

This is the bounded, local MSR01 contract foundation for one TypeScript package,
`@msn-control/missionspec`, targeting Node.js 24 LTS and NodeNext ESM. It is not a
complete product implementation or coding-host/approval-channel qualification.
The separate [Markdown](markdown-format.md), [SQLite](runtime-store.md) and
[local runtime](local-runtime.md) references describe implemented components.
No host/version combination is qualified by these contracts or their unit tests.

## Entry points and ownership

| Source entry point | Responsibility |
| --- | --- |
| `src/kernel/index.ts` | Validated identities, paths, versions, revisions, requested effects, approval requests, structured outcomes, registries |
| `src/engines/discovery/contracts.ts` | Findings, provenance, focused questions and explicitly authorized capture |
| `src/engines/specification/contracts.ts` | Markdown artifact snapshots, revisions, shared promotion and accurate closure contracts |
| `src/engines/planning/contracts.ts` | Artifact applicability, immutable task/check definitions, task DAG validation and analysis reports |
| `src/engines/execution/contracts.ts` | Revision-bound work orders, attempts, bounded execution and truthful control-state contracts |
| `src/engines/verification/contracts.ts` | Actual check observations, evidence availability, gap reports and distinct acceptance records |
| `src/engines/integration/contracts.ts` | Selected-host projections, reconciliation and optional provider connection metadata |
| `src/ports/index.ts` | Narrow injected filesystem, ledger, authority, host, clock, context, diagnostics and telemetry interfaces |
| `src/api/contracts.ts` | Twelve public workflow request/result shapes and the separate acceptance operation |

These interfaces specify future implementations; they do not implement their
methods. Engine contracts depend only on the kernel and other public contract
files, never adapters or CLI parsing. Application workflows coordinate engines;
they must not bypass verification/authority policy by calling a lower-level
publication or execution method.

The implemented runtime helpers are pure apart from local CPU/memory use:
parsers, SHA-256 hashing, immutable snapshots, task ordering and registry lookup.
Imports do not read projects, create state, inspect environment settings, start
processes, contact hosts, or send telemetry. Callers inject effectful ports.

## Closed identifiers and immutable values

Internal contract version `1` is a literal integer. Parsers reject unknown
versions, fields, discriminants and identity kinds rather than coercing values
or producing success-shaped defaults. A `ContractError` identifies a field and
expected shape without echoing the rejected input. Parsed data is copied into
frozen objects/arrays; readonly interfaces alone do not validate external data.

Stable IDs use the kernel's explicit prefix catalog: for example `CHG-login`,
`REQ-login`, `SCN-login`, `TSK-login` and `CHK-login`. The suffix is alphanumeric
with single hyphen separators; total length is at most 80 characters. Identity
is case-sensitive and never derived from a heading, array index, slug or date.
Brands are produced only after validation. This is the internal identity
grammar, not a finalized Markdown metadata notation.

Change slugs are flat lowercase alphanumeric/hyphen labels of at most 80
characters. `archive` and Windows device names are reserved. Project paths are
relative slash-separated paths: no absolute/drive/UNC paths, traversal, empty
segments, backslashes, glob characters, encoded-path ambiguity, control
characters, trailing dots/spaces or reserved device segments. Capability paths
may be nested; change slugs may not.

Path validation is **lexical**, not filesystem containment. A filesystem adapter
must separately handle symlinks, case aliases, root confinement, race conditions,
permissions and portable collision checks. A branded path is not authorization.

`WorkspaceBinding` combines a validated `WSP-` identity with a digest of the
observed admitted workspace root. It is required in change revision bindings
and project-wide review bindings. Matching content in another worktree must not
produce an interchangeable approval request. A trusted workspace adapter still
has to establish/revalidate the actual root; parsing caller-supplied strings
does not prove an observation or grant authority. This local runtime binding is
not added to portable committed Markdown or change metadata.

`ContentDigest` is lowercase `sha256:` plus 64 hex digits. `digestContent` hashes
exact supplied UTF-8 text or bytes without newline normalization. A revision
binding includes workspace scope, change identity, and specification, tasks,
workflow, effects and source digests; comparison checks every dimension. Git is not required.
Snapshot collection and source-tree digest production remain adapter/parser
work; a caller-provided digest is not proof that the corresponding data exists.

## Catalog and stop boundaries

All twelve operations are installed by default for each selected native host.
`copilot`, `codex` and `claude` are the exact host identifiers. Registry ownership
is not a statement that the host files or their behavior have been qualified.

| Operation | Class | Engines | Stop |
| --- | --- | --- | --- |
| `discover` | Primary | Discovery | Findings; capture only when explicitly authorized |
| `draft` | Primary | Specification, planning | One ready artifact node |
| `draft-all` | Primary | Specification, planning | Remaining required drafts or a review blocker; never implementation |
| `implement` | Primary | Execution | Current bounded work or an explicit pause |
| `verify` | Primary | Verification | Evidence and gaps, not repairs or acceptance |
| `archive` | Primary | Specification, with application coordination | Confirmed closure with the true outcome |
| `revise` | Supporting | Specification, planning | Reviewed revision of existing artifacts |
| `clarify` | Supporting | Discovery, specification | Answers or unresolved questions, not execution authority |
| `analyze` | Supporting | Planning | Read-only analysis by default |
| `principles` | Supporting | Specification | Reviewed project-document revision |
| `sync` | Supporting | Specification, with application coordination | Confirmed promotion while the change remains open |
| `onboard` | Supporting | Integration, with application coordination | Guidance or an explicitly selected handoff |

No aliases, hidden implementation stage, context engine, telemetry engine, or
generic plugin engine are registered. A registry's `defaultAccess` describes
the operation's default boundary, not a permission grant. Read-only discovery,
clarification, analysis and onboarding do not implicitly permit report capture
or setup.

## Canonical documents and planning

Markdown remains canonical editable project knowledge. Task definitions and
planned checks belong in `tasks.md` by default, with one canonical definition
per check. A checkbox is a user/agent claim, not an attempt or acceptance record.
The runtime store contract is for the separate SQLite ledger and evidence
metadata, not another editable specification or task graph.

Standard is the default workflow profile; Compact must be selected explicitly.
The standard artifact nodes are proposal, the complete declared specs set,
applicable design and tasks. Applicability exceptions carry a reason and source
revision. The `ArtifactNode` contract records exact output paths, including the
multi-file specs set, and dependencies. The pure readiness evaluator and local applicability capture
are implemented separately; a type declaration alone grants neither readiness
nor permission.

`captureArtifactSnapshot` copies supplied Markdown and dependency revisions,
rejects duplicate paths/dependencies and self-dependencies, and computes a
content identity independent of file/dependency presentation order. It does not
parse Markdown, establish readiness, approve anything or write files. Changes
to upstream dependencies also change the snapshot identity. Readiness is a
separate assessment.

`parseTaskDefinition` validates task/requirement/scenario/check identity kinds,
explicit write paths, unique references and self-dependency rejection.
`orderTaskDefinitions` additionally rejects duplicate task IDs, dangling task
dependencies and cycles, returning a deterministic topological order.
These helpers do not establish requirement coverage, execute tasks or qualify
checks. `parsePlannedCheck` validates a definition reference and traceability;
the `executed` check kind means a planned execution strategy, not a completed
test. Structural findings and semantic judgments remain distinguishable.

## Effects and approval are not prose

Requested effects are explicit file writes/removals, check execution, host
dispatch or optional external-context consumption. File writes bind exact
paths, expected content or explicit absence, and proposed content. Check effects
bind the check definition. Host effects bind native host and task IDs. Context
requests distinguish local consumption from requested remote processing.
Duplicate targets are rejected. Effect digests cover the normalized **ordered**
list; reordering effects requires a new revision.

An `ApprovalRequest` has `state: "untrusted-request"`, a purpose, operation,
review binding and exact requested effects. Its bound effect digest must match
those effects. Project-wide principles can use a project binding without
inventing a change; implementation requires a full change binding. Acceptance,
promotion and closure are distinct purposes, even when one human interaction
reviews several requests.

There is deliberately **no public synthetic approval issuer**, trusted-record
parser, `approved: true` shortcut, model-text confirmation parser or in-memory
fake approval provider. `parseApprovalReference` validates only an ID: resolving
that reference may still return absent, expired, revoked or superseded.

`TrustedIssuedApproval` describes the record a trusted
`LocalAuthorityPort` must supply after genuine local-user confirmation and
durable recording. Its assurance identifies local-user scope and the implemented
terminal, MCP-elicitation or trusted-callback protocol. Protocol `{ id, version }`
is metadata, not qualification evidence. Current records explicitly mark
qualification as not established and human/organization identity as not attested.
A hash of descriptive wording cannot substitute for measured qualification
artifacts. An arbitrary object with `state: "trusted-issued"` is not
proof of identity or approval; TypeScript structural types are not a security
boundary. Adapters and application workflows must resolve authority from the
trusted local ledger/channel and revalidate scope, revision, expiry, revocation
and request digest before every admitted effect. The local application enforces
those comparisons through injected authority. `TerminalAuthority` implements
real local-terminal challenge confirmation with persistent review records and
revocation; it does not attest organization identity or exclude same-UID terminal
automation. Native host callback bindings remain unqualified.

`source-apply` is a distinct implementation purpose for a reviewed inert patch.
It requires a review binding and exact source-file write effects, and rejects
host dispatch, checks, execution controls and approval-by-write-scope. The local
application derives candidate digests from validated bytes, then requires fresh
confirmation; it never treats model output as approved. Existing native execution
admission remains an exact-effect, durably fenced contract.

Review-purpose bindings preserve the complete subject revisions while separately
binding a report/preview subject digest and the effects of that review. This
allows acceptance/promotion/closure without granting execution effects or
weakening revision equality. Implement requests used by the controller additionally
bind run and work-order identities; a legacy request lacking them is insufficient
for controller admission.

Interactive is the default request mode. Auto requires the explicit `auto`
value, a selected native host and confirmed bounded limits. Every parsed
execution request requires a positive task count, positive duration and an
explicit repair allowance from zero through two. Concurrency defaults to one;
parallel execution is rejected until separately qualified. The initial attempt
is not a repair. The request contains limits, not claims that a host can enforce
them: host qualification separately reports hard, advisory or unavailable
controls. No cost/token hard cap is invented.

## Evidence, outcomes and recovery

Do not collapse the following into a `done` flag:

- artifact readiness;
- current/absent/expired/revoked/superseded authority;
- pending/running/paused/blocked/outcome-unknown/quiesced execution;
- missing/applicable/failed/stale/unavailable evidence;
- accepted/rejected/cancelled/incomplete outcome.

`Outcome<T>` distinguishes successful operation return, blocking, failure and
unknown effect outcome. The last requires reconciliation; it is not a safe
automatic retry. Success means the described operation returned, not that code
is accepted or an entire change is complete.

Work orders bind task, revisions, source, authority reference, effects, host and
limits. Attempt records retain host exits and completion claims without
translating them into verification or acceptance. Pausing/cancelling reports
quiescence separately; requesting stop is not proof a child has stopped.

Verification evidence binds source, check definition, relevant revisions and
optional attempt. Executed checks, static inspection and agent review are
different bases. Skipped, missing, unavailable, stale and failed evidence remain
visible. Pruning retains an explicit unavailable/pruned reference and its
authorization; no age-based deletion is implied.

Gap reports distinguish missing, partial, contradictory and unrequested
behavior. Proposed repairs are task proposals, not automatic code changes.
Acceptance eligibility is not acceptance; `recordAcceptance`/the public
`accept` operation require separate current human authority. A standalone
verify operation never repairs, promotes or archives.

Sync previews bind original/current/proposed baseline digests and expose
conflicts. Commit requires distinct acceptance/promotion references and current
inputs. Accepted archive requires acceptance and recorded or explicitly
unnecessary promotion; rejected, cancelled and incomplete archive retain their
actual outcome without promotion. The adapter must refuse destination
collisions. Partial filesystem/ledger effects require truthful unknown/recovery
state rather than a fabricated successful closure.

## Injected boundaries

- **Filesystem:** Reads and explicitly journaled, expected-content mutations.
  Implementations must compare before writing and verify proposed content
  digests. No interface promises that multiple filesystem writes are inherently
  atomic.
- **Runtime store:** Transactional run/attempt/evidence updates with expected
  ledger revisions and separate acceptance records. Required durable recording
  failure must block or reconcile effects, not be downgraded to diagnostics.
- **Authority and host:** Injected, independently qualified adapters. Host
  dispatch cannot bypass the host's own permissions. No live host is invoked by
  the foundation.
- **Clock:** Wall time and monotonic elapsed time are separate. Implementations
  must return valid UTC timestamps and finite monotonic measurements; wall-clock
  changes must not extend a run's monotonic budget.
- **Context:** Optional consumption only. Availability explicitly includes
  absent, disabled, partial, incompatible and unavailable. Supplied observations
  are marked untrusted context. There is no bundled provider, installer, index,
  enrichment job or fallback model.
- **Diagnostics:** Closed local event codes, severities and fields; no arbitrary
  exception/request dump. Console-only emission is expressible for strict
  read-only operations. Diagnostics do not prove an audit transition.
- **Telemetry:** A minimal internal completion summary, not a remote wire event.
  The implemented adapter suppresses read-only, opted-out and undisclosed events;
  delivery failure cannot change the operation result. Exact local monotonic
  timing must be projected to approved coarse buckets before transmission,
  never uploaded directly. Sender, disclosure and transactional preferences live
  in the separate observability modules, with no production sink enabled.

## Contract scope versus component implementations

The following list records boundaries not settled by the types alone. Some now
have bounded local implementations documented in the linked component references;
it is not a claim that the repository still consists only of interfaces.

These are qualification work, not claims made by the types:

1. Markdown metadata grammar, task/check notation, delta/section rules,
   round-tripping, collection hashing, migrations and complete artifact DAG
   scheduling. Internal contract version `1` does not finalize those formats.
2. SQLite binding/schema/migrations, transactions, locking, durable journaling,
   backup consistency, capacity handling and crash reconciliation.
3. Exact host versions and argument transport; genuine terminal and host
   callback confirmation; local-user presence and assurance; cancellation,
   quiescence and measurable execution-limit enforcement.
4. Public API/CLI routing, controller state transitions, adapters, package export
   qualification, host projection installation and behavior parity.
5. External context provider protocol/installer and provider-specific freshness
   semantics. The internal port version is not a claimed external protocol.
6. Canonical remote-event schema, release-version validation and timing buckets;
   notice/opt-out state, redaction, log bounds/permissions and retention.
   `OperationTelemetrySummary` is not that schema and is not approved for direct
   serialization.    The client and isolated service share the canonical schema with checked
   equality and provenance, rather than independent drifting copies.

Focused tests import the compiled modules and exercise actual validators,
immutable snapshots, revision checks, registries and DAG behavior. They do not
use empty-engine snapshots or claim controller, security-channel, SQLite or
live-host qualification.
