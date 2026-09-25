# Explicit, recoverable raw-evidence pruning

`LocalEvidencePruning` in `src/application/evidence-pruning.ts` implements a
reviewed local retention lifecycle. It uses the real SQLite runtime store,
existing local workspace/authority composition, and a narrowly scoped filesystem
adapter. It performs no model call, Git operation, cloud action, age-based cleanup,
or automatic approval.

## Native descriptor-lock qualification

The rejected SQLite mutex prototype is **not** a fallback. Real macOS tests
proved that independent descriptor closes released its process-associated
record locks while SQLite still reported an active exclusive transaction.
Restricting one text-reader API or hiding the mutex from inventories did not
solve that failure.

The approved replacement pins `fs-native-extensions@1.5.1`: its Darwin backend
uses nonblocking exclusive `flock`, and Linux uses `F_OFD_SETLK`, associated with
the **open file description**, not ordinary process-associated `F_SETLK`.
One private descriptor stays open throughout each writer's critical section.
Module-local exclusion maps are not the lock mechanism. A same-process or
worker reentrant acquisition opens a different descriptor and is refused by
the kernel.

`tests/persistence-mutex-fd.test.mjs` requires continued exclusion after a raw
descriptor read/close, the production bounded reader, a whole `.missionspec`
fixture snapshot, a worker descriptor read/close, and a rejected worker
acquisition. Every competing child remains blocked until explicit release,
then succeeds. The fixture observer is unchanged and does read the mutex.
`tests/posix-native-lock.test.mjs` additionally verifies the actually loaded Node
prebuild hash, lazy/unavailable loading, legacy refusal, real bootstrap exits
and concurrent initialization.

Native loading is limited to Node >=24.21.0 <25 and POSIX arm64/x64 candidates.
Missing/incompatible prebuilds or unsupported filesystem lock operations fail
closed before writer effects; there is no system executable, rebuild/install
script, SQLite, PID-only, mkdir, or lock-holder-process fallback. Read-only
imports do not load the addon. Windows continues using its existing native
protocol and never calls this POSIX adapter.
See [native provenance and platform constraints](../licensing.md#native-descriptor-lock-dependency)
for actual qualification results, binary hashes and licensing evidence.

## Public library surface

```ts
const pruning = new LocalEvidencePruning(workflow, store, authority, { now });
const preview = await pruning.preview(evidenceIds);
const confirmation = await pruning.confirm(preview);
if (confirmation.status === 'ok' && confirmation.value.state === 'issued') {
  await pruning.commit(preview, confirmation.value.approval.reference);
}
```

The runtime owner wires this library into the CLI/API. No second CLI,
`LocalWorkflow`, authority issuer, or generic private-file mutation tool is
introduced.

| Method | Behavior |
| --- | --- |
| `preview(evidenceIds)` | Read-only exact IDs, private paths, hashes, source/run/evidence references, compact outcomes, and affected accepted history |
| `confirm(preview)` | Existing genuine local-human confirmation of that exact request |
| `commit(preview, approval)` | Explicit writable-store preparation, guarded removal, immutable completion |
| `status(pruneId)` | Read-only immutable lifecycle state, or null |
| `pending()` | Read-only prepared jobs requiring recovery |
| `previewRecovery(pruneId)` | Original exact request plus retained/already-absent path observations |
| `recover(pruneId, approval)` | Resume only the prepared job under a current approval for its original request |

`pruneId` is the canonical plan's SHA-256 content digest. There is no
`confirmed: true`, approval-shaped JSON shortcut, wildcard path, or retention
timer. A preview/evaluation is data, not an approval. Absence of a qualified
authority channel or of the optional real store capability blocks mutation.
Read-only store handles cannot perform file deletion during commit/recovery.

## Exact preview and preserved history

Preview accepts 1–64 unique existing evidence IDs. Each must still have its
original retained reference and have never entered a pruning lifecycle.
Only `.missionspec/evidence/<exact-evidence-id>.json` is eligible. The adapter
reads and hashes the actual bounded raw file, validates its observation envelope,
and retains a compact summary of:

- actual check basis and passed/failed result;
- original evidence ID, immutable evidence-row digest, owning run and run revision;
- exact private path and raw-file digest;
- digest of the original output string, without copying the output;
- affected acceptance IDs, immutable acceptance digests, and the selected
  evidence each acceptance depends on.

The review explicitly states that **historical acceptance is preserved, but
current evidence-dependent use becomes unavailable**. It is not permission to
rewrite an accepted result or claim new verification. Failed observations remain
failed. Original evidence rows, original run revisions, acceptance rows, approval
references, and compact outcome summaries survive raw deletion unchanged.
Raw output, source/specification text, and secrets are not copied into analytics
or the compact prune record.

The persisted target digest does not contain a historical inode. Descriptor
checks bind each read to its own pre-open observation; the quarantine intent
records the object observed for that move, not a fabricated creation-time or
preview-time identity.

New accepted-history references or changed run revisions invalidate an earlier
preview. The current application observes the actual workspace identity/root
independently and rejects foreign-workspace plans.

## Two-phase protocol

1. **Admit the exact operation.** Resolve genuine current authority for the
   plan-bound request and exact private `file-remove` effects. Acquire the same
   cooperative workspace lock used by file transactions and execution.
2. **Prepare durably first.** In one SQLite writer transaction, revalidate
   workspace scope, every current retained evidence reference/run revision,
   dependent accepted-history impact, and absence of any active/unreconciled run.
   Append an immutable preparation plus its complete evidence membership set.
3. **Publish unavailability immediately.** Once preparation commits,
   `readEvidence` returns an unavailable overlay and `readRunEvidence` excludes
   every selected ID, even while raw bytes remain. All `commitRun` writes are
   fenced until recovery/completion. New acceptance records and task-completion
   records cannot use prepared/pruned evidence.
4. **Capture before POSIX removal.** Recheck current authority and workspace
   scope. Validate owner-only real directories, a regular single-link raw file,
   its digest, and the pre-open observation against its actual descriptor.
   Durably record a version-1 move intent binding the exact approved job digest,
   workspace, complete target, original observed object and a private UUID
   directory. Atomically rename the source into that same-volume quarantine.
   Open and validate the **actual moved object**, including its identity,
   ownership, permissions, link count and complete digest, before unlinking
   inside the private namespace. Flush both rename directories, and the deletion
   directory, then write an immutable deletion receipt bound to the intent.
   An unexpected moved object is retained and its exact quarantine reference
   reported, without logging its content or automatically restoring over another
   file. Windows retains its existing native held-object deletion protocol.
5. **Complete durably.** Recheck authority and observe every selected path absent,
   then append an immutable completion linked to the preparation digest.
   `readEvidence` now derives `storage.state: pruned` with the completion time
   and approval reference. It never overwrites the original evidence payload.

The file-effect category uses the existing retention/closure file purpose under
a verification review request. This neither closes a change nor grants execution,
acceptance, or artifact-edit authority.

## Crash and retry semantics

| Interruption | Durable meaning | Explicit continuation |
| --- | --- | --- |
| Before preparation | No pruning availability transition; raw bytes untouched | Re-preview/commit; only a matching dead prune lock can be reclaimed |
| After preparation, before move intent | All selected evidence unavailable; raw bytes must still exist for a new POSIX intent | Current approval for the original exact request, then `recover` |
| After durable intent, before move | Original object identity and UUID destination are retained | Resume only if the source still matches the intent |
| After move, before deletion | Actual captured object remains in the private quarantine | Re-admit the captured object against the same intent; never delete a new source-name occupant |
| After unlink, before durable deletion receipt | Empty quarantine is ambiguous, not proof of deletion | Fail closed for explicit reconciliation; do not fabricate completion |
| After durable deletion receipt, before ledger completion | Evidence unavailable; per-target receipt binds the original intent | Recheck the receipt, capture/source absence and current authority; append completion |
| After completion | Immutable pruned state and original history retained | `recover` returns existing completion without deleting anything |

Recovery never reconstructs a new scope from caller booleans. A new current
approval may replace an expired/revoked approval **only for the same original
request**; the preparation's original approval remains in history and the
completion records the current one. Changed remaining raw bytes block recovery
and are preserved. There is no force-delete, silent abandon, or automatic reset.
An unknown commit outcome requires reopening/reconciliation, not assumed success.

Completion records **observed absence under this protocol**, not tamper-proof
proof that this process removed bytes. POSIX recovery now requires a matching
durable deletion receipt; an absent source and empty/missing capture are not
enough. Legacy prepared jobs whose raw files are already absent without such a
receipt remain unavailable and require explicit reconciliation; no receipt or
historical inode is invented. A replacement file created after completed pruning is never removed
by replaying `recover` or `commit`; preparing the same evidence identity again is
rejected.

## Cooperative writer-lock recovery

The owner metadata remains `.missionspec/transaction.lock`, interoperating with
`LocalWorkspace` and the execution controller. A pruning writer stores a
prune-specific schema, exact plan digest, PID and nonce, and fsyncs that lock
before preparing SQLite state. **Every compatible transaction, runtime,
selection/lifecycle and prune writer** holds the same native descriptor lock on
`.missionspec/writer-mutex.lock` throughout metadata reclaim, creation, effects
and release. This stable inode is never unlinked or replaced, and contains no
owner metadata. PID/stat rechecks alone cannot prevent competing recoverers
from deleting each other's new owner records.

The mutex contains the exact version-1 `missionspec-posix-descriptor-mutex`
JSON format and observed root digest, not a SQLite database or ledger schema.
Initial provisioning exclusively creates `writer-mutex.bootstrap`, durably
writes the complete content and publishes it by a no-overwrite hard link,
followed by bootstrap unlink and directory flush. If another initializer
finished after an earlier absence check, only the new initializer's unused
bootstrap is removed; the existing mutex is not replaced. Admission validates
the actual owner-private, single-link read/write descriptor before reading,
takes its native lock, verifies exact content plus descriptor/path/parent
identity, and flushes the descriptor and directory before writer effects.
That final barrier also covers observing another initializer just after
publication. Release unlocks and closes only the held descriptor.

An interrupted bootstrap, partial/foreign stable file or multi-link object
fails closed. Existing experimental `writer-mutex.sqlite` and its sidecars
also block admission: they are preserved, never converted, reset or silently
shadowed by the native mutex. Nothing initializes an arbitrary existing file.
Read-only inspection never provisions a mutex.

Only an explicit, currently approved operation for the **same plan** may reclaim
that lock. POSIX retains signal-zero process inspection requiring `ESRCH`
(the recorded local PID is gone). New Windows schema-2 locks additionally bind
the OS-reported process creation FILETIME; a matching live instance blocks,
while an observed different birth at that PID proves the original writer ended
without touching the successor. Legacy Windows locks still require actual PID
absence. Unknown or inaccessible process identity, changed lock identity,
another plan, ordinary runtime lock, or file-transaction lock blocks prune recovery.
No read/status operation steals a lock. An interrupted partial lock
write that cannot be validated likewise requires separate manual reconciliation.

Existing POSIX owner-record formats are unchanged and are not reinterpreted.
Upgrade requires quiescing older binaries: concurrent old writers that do not
hold the new kernel mutex are not compatible participants. A live or malformed
legacy owner blocks even initial mutex provisioning. Private ledger format 3,
preparations, original evidence and acceptance rows are not reset or rewritten.

This is a cooperative local-process protocol, not a distributed lease or a
same-UID adversarial guarantee. PID reuse can conservatively block legacy/POSIX recovery.
Current-user ownership, real paths, no symlinks/hard links, root binding and
identity checks reduce accidental misuse. Windows reclamation retains the
native lock handle and exact identity/digest through deletion and directory
flush; new leases also revalidate the process tuple. POSIX Node does not provide
atomic compare-and-unlink, including via `unlinkat`. The POSIX guarantee depends
on compatible writers respecting the stable mutex and the private UUID capture
namespace. A source-path replacement racing the rename is captured and checked,
not silently destroyed. A noncooperator modifying an already-open descriptor,
private quarantine names, ACLs/extended metadata outside the qualified POSIX
mode/ownership policy, or the mutex inode can defeat advisory exclusion.
No guarantee against that actor, administrator, or storage failure is claimed.
Intent and receipt files are retained; there is no automatic restoration,
quarantine garbage collection, or overwrite-recovery operation. See the
[Windows process-instance boundary](windows-state.md) for qualification limits.

## Store capability and schema

`RuntimeStorePort.evidencePruning` is optional so existing implementations/test
fixtures are not silently called pruning-capable. Its typed
`EvidencePruningStorePort` exposes:

- `access: read-only | read-write`;
- `inspectEvidencePrune`;
- `prepareEvidencePrune`;
- `readEvidencePrune`;
- `listEvidencePrunes`;
- `completeEvidencePrune`.

The actual SQLite adapter supplies these operations with parameterized SQL,
bounded lock handling, closed persisted-data parsers, content-digest validation,
foreign keys and full relationship validation. Structural method presence in an
injected test double is **not** production capability qualification. These are
trusted composition methods, not arbitrary database tools and not approval
issuers. Only the application coordinates actual filesystem absence with
completion.

Schema **v3** adds `evidence_prune_prepared`, `evidence_prune_items`, and
`evidence_prune_completed`. Every record/membership is immutable. Missing item
references, dangling preparation/completion links, modified digests, foreign
workspaces, inconsistent acceptance impact, and active runs alongside a prepared
job fail integrity validation.

Prototype schemas v1 and v2 are explicitly unsupported. They are not migrated,
reset, or silently recreated; the existing database is preserved for reviewed
handling. The approved path remains `.missionspec/state/ledger.sqlite`.

## Verification and limits

```sh
npm run build
node --test tests/evidence-pruning.test.mjs tests/runtime-store.test.mjs tests/lessons.test.mjs
node --test tests/persistence-posix-races.test.mjs tests/persistence-mutex-fd.test.mjs tests/posix-native-lock.test.mjs
```

Focused tests use real SQLite databases and owned project-local directories.
`persistence-posix-races.test.mjs` drives actual child processes and native
filesystem calls, pausing a recoverer after its final stat while competing
prune/runtime/lifecycle writers try admission. It also interleaves source
replacement immediately before rename and after quarantine verification,
checks retained identical/different bytes, modes, links and symlinks, and exits
after intent/move/verification/unlink/receipt. Empty quarantine without a receipt
is deliberately unresolved. These are not in-memory filesystem schedules.
The native mutex/quarantine/held-reader implementation passed 174 selected tests
on macOS arm64 / Node 24.21.0: the three native/POSIX suites plus evidence pruning,
runtime lifecycle/store, local workflow and source patches, with zero skips.
The isolated Linux qualification and exact artifact/platform limits are recorded
in [licensing](../licensing.md#native-descriptor-lock-dependency).
Native Windows held-read selectors in [Windows state](windows-state.md#persistence-held-read-candidate)
still need their separate qualification; historical Windows results do not
qualify the new held-reader changes.
Actual child-process exits exercise before-prepare, after-prepare and
after-partial-delete durability, including retained dead writer locks and
reopening/recovery. Other cases cover user edits, immediate pre-unlink hash
checks, hard links, dangling symlinks, unavailable stores, foreign workspaces,
active runs, accepted-history changes, read-only zero-write queries, completed
replay, dangling rows, schema rejection and completion failures.

The historical 16 pruning tests passed on macOS and Linux/arm64 with Node 24.21.0 and SQLite
3.53.4. Linux validation used the already-cached immutable Node Alpine image
documented in the runtime-store qualification, with networking disabled, no pull,
a read-only container root, and native-volume test storage. The historical macOS combined
pruning/runtime-store/lessons/local-workflow run passed all 86 tests.

Authority responses used in tests are explicitly test-only; they do not qualify
a genuine human channel. Production uses the existing actual local authority.
Windows raw removal and exact-job lock recovery are now an integration candidate
using the same application, qualified private-state/barrier primitives and bounded
local-writer absence inspection. It awaits real application qualification and
does not establish native-host/process-tree quiescence. See the separate
[Windows capability boundary and end-to-end command](windows-state.md).
The previously documented
SQLite/local-filesystem qualification limits still apply. No age-based or
unreviewed pruning, paid semantic evaluation, native-host authority, or
tamper-proof history is claimed.
