# Local SQLite runtime store

`src/adapters/persistence/index.ts` exports `openRuntimeStore`. The implementation
uses the built-in `node:sqlite` `DatabaseSync` API, loaded dynamically only by this
explicit factory. Importing the adapter performs no filesystem or database I/O.
There is no native-addon fallback, installation, host dispatch, model call or
authority implementation in this adapter. The separate
[local application](local-runtime.md) composes this store with reviewed file
transactions and injected execution control.

## Composition and lifecycle

```ts
import { openRuntimeStore } from '../../adapters/persistence/index.js';

const opened = await openRuntimeStore({
  directory: '/absolute/project/.missionspec/state',
  expectedWorkspace, // Independently supplied WorkspaceBinding from trusted composition.
  mode: 'create',
  busyTimeoutMs: 100,
});
if (opened.status !== 'ok') return opened;
const store = opened.value; // RuntimeStorePort plus close()
try {
  // Pass store to trusted application composition; never expose arbitrary SQL.
  // listRuns, readRun, readRunEvidence, commitRun, readEvidence,
  // readAcceptance and recordAcceptance return Outcome values.
} finally {
  const closed = store.close();
  // A caller must handle a non-ok close outcome rather than assuming success.
}
```

The approved layout is **`.missionspec/state/ledger.sqlite`**. The absolute
`directory` option must end in `.missionspec/state`; the fixed filename is
`ledger.sqlite`. `create` creates at
most one missing directory level with mode `0700`, then reserves the database
exclusively (`O_EXCL | O_NOFOLLOW`, mode `0600`). The `.missionspec` parent must
already exist.
An existing database is never initialized, reset, migrated, or overwritten by
creation. Failure can leave the explicitly created directory or incomplete file;
there is no automatic destructive cleanup or recovery.

`expectedWorkspace` is **required** for every open/create and has the closed
kernel shape `{ workspaceId: 'WSP-…', rootDigest: ContentDigest }`. The adapter
uses `parseWorkspaceBinding` and `sameWorkspaceBinding`, not a separate
interpretation. Schema v3 persists a singleton, canonical, SHA-256-checked
workspace metadata record. Both identity and root digest must match the
independently expected binding on reopen and every operation. Every incoming and
persisted run, historical revision, evidence, and acceptance must bind to that
same workspace. Attempt ownership follows its run. Identical specification,
source, task, effect, or check hashes cannot bypass a workspace mismatch.

Trusted composition is responsible for independently resolving the actual local
workspace identity/root binding; **do not take the expected binding from a copied
database or untrusted request**. This adapter does not issue a workspace identity
or define a new root-digest algorithm. Copying a ledger into another worktree and
opening it with that worktree's expected binding is rejected without writes.
Concrete workspace IDs and root digests belong in private runtime state and
requests, not committed specification/planning Markdown; schema documentation
and synthetic test fixtures are not current-root observations.

No prototype database has been released. Schemas v1 and v2, direct prototype directories,
the former `.missionspec-runtime` directory beside `.missionspec`, and
`runtime.sqlite` or its sidecars inside the state directory fail explicitly as
incompatible. There is no silent path fallback, schema migration, reset, or
parallel creation beside these prototype artifacts.

The [state lifecycle application](runtime-state-lifecycle.md) adds reviewed
logical backup/recovery, explicit versioned format conversion and private
external selection. `openWorkspaceRuntimeStore({ workspaceRoot,
expectedWorkspace, mode })` resolves that selection centrally. Direct opens also
honor it; external replicas require their original `workspaceRoot`. None of
these operations makes an unsupported prototype a supported upgrade source.

Use `read-write` to open an existing store, or `read-only` for status. Neither
creates a missing file or directory. The returned object exposes no database
handle or authority methods. All values are validated again at the runtime
boundary; TypeScript types are not treated as validation. `close()` is
idempotent, and subsequent operations report a closed capability.

Node **24.21.0** with built-in SQLite **3.53.4** was exercised locally on macOS
and Linux/arm64 (Alpine, native Docker volume). All 30 focused tests passed on
macOS, Linux as root, and Linux as UID 1000 beneath a root-owned `01777` ancestor.
The Linux tests used the already-local immutable image
`node:24-alpine@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81`,
with no network, no image pull, and a read-only container root filesystem.
The factory accepts the Node 24 line starting at 24.21; qualification is not a
claim that every future patch or filesystem behaves identically.
Windows has qualified, narrowly scoped SID/ACL-validated local-NTFS storage;
see [Windows state and its independent qualification command](windows-state.md).
The recorded Windows qualification includes private storage, held-handle source
and runtime-record effects, callback-backed receipts, recovery and pruning.
Storage evidence does not qualify console authority or native execution.
Separate [console/check-process evidence](windows-execution.md) covers the
local terminal and trusted-check paths, not native AI hosts. A mocked-platform
subprocess test is not a Windows platform-readiness claim. Other non-POSIX models
fail explicitly.
Network filesystems and Docker Desktop
host bind mounts are not qualified: a bind-mount probe exposed remapped ownership
and asynchronous active-WAL shared-memory timestamps. The native Linux-volume
run passed the actual ownership-change rejection and read-only assertions.
Composition must select a qualified local filesystem.

## Capacity inspection

`missionspec state status --json` opens an existing ledger read-only and reports
its schema/workspace binding, record counts, recorded run quiescence and storage
accounting. Missing identity or storage is an explicit error, not initialization.
The library equivalent is `SqliteRuntimeStore.inspectState()`.

Database size, allocated pages, reusable pages and filesystem-available bytes
are exact integer strings, avoiding JSON number precision loss. The filesystem
observation is point-in-time and explicitly reserves **no** capacity; other
writers and quotas can affect a later allocation. Recorded run quiescence is
not independent proof that an external host or descendant process has stopped.
Inspection does not prune, migrate, collect telemetry or write a marker.

SQLite `SQLITE_FULL`, filesystem `ENOSPC` and quota `EDQUOT` failures report
`limit-reached` with a capacity reason. A confirmed rollback preserves existing
history; an uncertain commit/rollback retains the existing reconciliation
requirement. Capacity failures never trigger automatic evidence deletion.

## Transactions, identities, and digests

- Every operation reads a consistent explicit transaction. Writes use
  `BEGIN IMMEDIATE`, foreign-key constraints, `synchronous=FULL`, and
  rollback/DELETE journaling. Lock waiting is bounded by `busyTimeoutMs`
  (0–1000, default 100); there is no application retry loop.
- Workspace metadata is checked inside the transaction, including for
  idempotent mutations. Cross-workspace records are not admitted just because
  their IDs and other hashes match existing data. Persisted row/workspace
  disagreement is corruption; a healthy ledger opened for a different expected
  workspace is a scope mismatch.
- `commitRun` compares `expectedRevision` while holding the writer transaction.
  A new run requires `absent`. Existing runs require the exact revision from
  `readRun`. A revision hashes a canonical envelope containing the snapshot,
  sorted immutable evidence identities/digests, and preceding revision. Thus
  evidence-only changes advance CAS, and returning to an earlier snapshot cannot
  produce an ABA revision reuse.
- Identical submissions with the **current** expected revision are idempotent.
  A replay with an old expected revision still fails stale, even if its content
  was previously committed. Immutable revision history links back to `absent`.
- Snapshot attempts are a complete append-only ordered list. Every new attempt
  must also be supplied in `commitRun.attempts`; already stored identical
  attempts may be supplied again. Attempt IDs and evidence IDs are globally
  unique and immutable. Reusing an identity with different content or another
  run fails. Work-order identities cannot span runs. Repairs must refer to a
  prior attempt of the same work order with the preceding sequence number.
  Only one initial observation and one each of repairs 1 and 2 are stored.
- Optional snapshot admissions are append-only full work orders, request digests,
  qualification references and admission timestamps, bound to the same workspace,
  change and run. A new admission must first persist running/unconfirmed state.
  The writer transaction rejects admission while another workspace run is active
  or unreconciled. Current schema-3 records without optional admissions remain
  readable; no inferred historical authority is performed.
- New evidence binds to the committed run revisions and, when supplied, an
  attempt in that run. A returned attempt's `sourceAfter` must equal the evidence
  source. Evidence without an attempt must match its binding's source. Evidence
  bound to earlier revisions remains in the cumulative history after a run
  advances. An unavailable/unknown observation is preserved, not upgraded.
- Acceptance is append-only, keyed by `approval.id`; the returned revision is
  its canonical content digest. An identical record is idempotent. Its nonempty,
  unique evidence list must refer to one run and one recorded revision containing
  all evidence, with matching revisions/source. The current contract has no run
  ID or separate acceptance ID, so empty-evidence acceptance cannot establish a
  relationship and is rejected.
- The optional `evidencePruning` capability adds immutable prepare/item/completion
  sidecars, not edits to original evidence or acceptance rows. Prepared evidence
  reads as unavailable; completed evidence reads as pruned. `readRunEvidence`
  excludes both while original run history and evidence digests remain intact.
  A pending prune fences run writes, and new acceptance/task-completion records
  cannot consume pruned evidence. See [the reviewed pruning protocol](evidence-pruning.md).
- Canonical JSON payloads are limited to 16 Mi characters. SHA-256 digests,
  row identities, all nested closed contract fields, foreign keys, ordered
  attempts, source bindings, and history links are checked on every operation.
  Persisted JSON is parsed as unknown and reconstructed, never cast to a
  contract. Noncanonical JSON, unknown fields/versions, sparse input arrays,
  invalid IDs, malformed digests, invalid union tags, and inconsistent records
  are rejected. Timestamps use valid UTC ISO seconds or millisecond precision;
  exit codes use signed 32-bit integers or null.

A failed multi-record write rolls back all its rows. If rollback or a commit
outcome cannot be confirmed, the outcome explicitly requires reconciliation; it
is not reported as success. An uncertain write commit blocks further writes on
that handle until it is explicitly closed and reopened; reads can aid
reconciliation. A failed rollback makes the handle unusable, and a failed close
is never marked successful. The adapter revalidates schema/rows inside each
transaction, uses prepared parameters for all caller data, and never invokes SQL
from callers. Full-store integrity scans favor correctness over scale in this
initial implementation; large histories need a separately designed optimization.

## Read-only and filesystem boundary

Only the expected application ID, schema version 3, exact strict table
definitions, and DELETE journal mode are supported. Extra schema objects,
including triggers, are rejected. SQLite integrity and foreign-key checks are
required. Opening/status never performs migration, pruning, recovery, journal
mode changes, logs, telemetry, or notice-file writes.

Before SQLite opens an existing file, the adapter checks the SQLite header and
rejects WAL format. Existing `-journal`, `-wal`, or `-shm` entries are treated as
busy/unreconciled, even if empty. They are not deleted. Read-only opens use
SQLite's actual read-only connection plus `query_only`; **`immutable=1` is never
used**, so an active WAL cannot be silently ignored. Recovery must be an explicit
separate reviewed operation, not status. A transient sidecar can conservatively
make even a readable database unavailable.

On POSIX, the root and file must be owned by the current UID and inaccessible to group or
others. The database must be a regular single-link file, and the root must be a
real directory. Required owner read/search permissions (and owner write
permissions for writable handles) are checked; read-only files can be opened by
read-only handles. Ancestor symlinks are rejected. Group/world-writable
ancestors have one narrow exception: they must have the POSIX sticky bit and be
owned by root or the current UID, and their next path component must also be
owned by root or the current UID. Otherwise they are rejected. This permits the
usual real Linux root-owned sticky temporary-directory layout and current-user
owned equivalents without accepting arbitrary writable or other-user-owned
ancestors. The **state directory itself is never exempt** from owner-only
permissions. Symlink aliases remain unsupported.

The sticky rule was tested using owned project-local `01777` directories on
macOS and native Linux; the root-run Linux test also changes ancestor/child
ownership to another UID and verifies rejection. A separate non-root Linux run
uses a root-owned sticky volume root with a UID-1000-owned project child, matching
the ownership rules of a safe shared temporary ancestor without accessing a
system temporary directory. No system temporary directory is accessed or
modified by these tests.

On Windows the equivalent boundary uses actual owner SIDs, restrictive DACLs,
local NTFS/Win32 identity and reparse/alias checks, never UID/mode emulation;
the precise supported and rejected ACL forms are documented in [Windows state](windows-state.md).
The adapter rechecks device/inode identity and permissions before operations.
SQLite cannot open an already-verified file descriptor through this Node API;
these checks are **not** a race-proof defense against a malicious same-UID process
or machine owner. Use a private directory and trusted local composition.

Read-only tests compare entries, bytes, size, mode, inode, modification time, and
change time before/after. Filesystem-managed access times may change on a normal
read according to mount policy; the adapter cannot promise OS-level atime
suppression. SQLite creates no database, directory, journal, WAL, shared-memory,
notice, or log files on these qualified read-only paths.

## Error mapping

`Outcome` is unchanged. Specific adapter conditions appear in
`error.fields` as `['runtimeStore', reason]`:

| Reason | Status / code |
| --- | --- |
| `missing` | blocked / `not-found` |
| `busy` | blocked / `conflict`, bounded retry after reconciliation |
| `corrupt` | failed / `persistence-failed` |
| `incompatible` | blocked / `unsupported-version` |
| `unavailable`, `read-only`, `closed` | blocked / `capability-unavailable` |
| `conflict` | blocked / `conflict` |
| `stale-revision` | blocked / `stale-revision` |
| `workspace-mismatch` | blocked / `scope-exceeded` |
| `io` | failed / `persistence-failed` |
| `unknown` | outcome-unknown / `effect-outcome-unknown`, reconciliation required |

Invalid caller contracts return `invalid-input` (unsupported contract versions
return `unsupported-version`) with the relevant field. Missing run/evidence IDs
inside an existing healthy store return `ok: null`, distinct from a missing
database.

## Integrity is not authority

**This store is not an approval issuer, acceptance assessor, or trusted ledger.**
It stores supplied `ApprovalReference` values only as references. A persisted
`state: accepted`, a syntactically valid approval ID, a `claimed-complete` host
status, or a digest does not establish human confirmation, check success,
completion, host qualification, or authority to admit an effect. No JSON boolean
or checkbox can create such authority. Native host qualification and
`LocalAuthorityPort` remain unimplemented here.

The methods are intended for trusted application composition after caller
engines resolve actual authority and check effect scope/current revisions. They
are not safe arbitrary database tools for an untrusted agent. Acceptance storage
checks reference integrity only; it deliberately does not invent eligibility
from unavailable/pruned evidence, nor re-resolve old approval references.
Workspace metadata is likewise a scope-integrity binding, not a local authority
credential or proof of human confirmation.

Evidence storage paths/digests are references: the adapter neither reads their
files nor verifies those external bytes. Retained does not mean available now,
and unavailable/pruned states survive reads. Attempt/evidence observations cannot
be rewritten in place. The explicit pruning application and its narrow filesystem
adapter independently verify raw bytes before deletion; the SQLite capability
only records its immutable lifecycle. This is trusted application composition,
not a general database tool capable of issuing deletion authority.

These hashes detect accidental content inconsistency, not tampering by a machine
owner who can rewrite records and recompute hashes. There is no cryptographic
authority root, append-only hardware, or tamper-proof history claim. Runtime
contents remain local; no raw code/specification, error text, evidence, secrets,
or approval data are copied into analytics by this adapter.

## Validation

```sh
npm run build
node --test tests/runtime-store.test.mjs
```

Tests use exclusive, owned directories beneath the repository and clean only
those directories. They exercise real SQLite durability, two-handle CAS and ABA,
rollback after earlier inserts, bounded lock contention, immutable/idempotent
identities, repair/reference rejection, strict persisted-input validation,
unknown/unavailable preservation, read-only no-write comparisons, permissions,
symlinks/hard links, path replacement, schema incompatibility, and active WAL
refusal. Workspace tests cover required bindings, changed IDs/root digests,
copied ledgers, replayed records with otherwise identical hashes, metadata
changes after open, and prototype rejection without migration. SQLite-disabled
child-process tests verify explicit capability failure;
fault injection around real SQLite transactions checks unconfirmed commit,
rollback, and shutdown outcomes. These are storage tests, not evidence of run,
host, or approval authority.
