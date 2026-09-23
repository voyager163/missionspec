# Explicit, recoverable raw-evidence pruning

`LocalEvidencePruning` in `src/application/evidence-pruning.ts` implements a
reviewed local retention lifecycle. It uses the real SQLite runtime store,
existing local workspace/authority composition, and a narrowly scoped filesystem
adapter. It performs no model call, Git operation, cloud action, age-based cleanup,
or automatic approval.

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
4. **Remove exact bytes only.** Recheck current authority and observed workspace
   scope. Validate owner-only real directories, a regular single-link raw file,
   its current digest, and stable descriptor/path identity. No callback or
   `await` occurs between the synchronous hash/identity checks and `unlink`.
   Fsync the evidence directory after removal. No sibling, parent, arbitrary
   runtime file, or user replacement with different bytes is removed.
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
| After preparation, before deletion | All selected evidence unavailable; raw bytes may still exist | Current approval for the original exact request, then `recover` |
| After some/all deletions, before completion | Evidence unavailable; absence is not falsely recorded as a completed job | Observe missing paths without unlinking again; hash-check any remaining bytes; complete |
| After completion | Immutable pruned state and original history retained | `recover` returns existing completion without deleting anything |

Recovery never reconstructs a new scope from caller booleans. A new current
approval may replace an expired/revoked approval **only for the same original
request**; the preparation's original approval remains in history and the
completion records the current one. Changed remaining raw bytes block recovery
and are preserved. There is no force-delete, silent abandon, or automatic reset.
An unknown commit outcome requires reopening/reconciliation, not assumed success.

Completion records **observed absence under this protocol**, not tamper-proof
proof that this process removed bytes. A path may already be absent on recovery.
Conversely, a replacement file created after completed pruning is never removed
by replaying `recover` or `commit`; preparing the same evidence identity again is
rejected.

## Cooperative writer-lock recovery

The fixed lock remains `.missionspec/transaction.lock`, interoperating with
`LocalWorkspace` and the execution controller. A pruning writer stores a
prune-specific schema, exact plan digest, PID and nonce, and fsyncs that lock
before preparing SQLite state.

Only an explicit, currently approved operation for the **same plan** may reclaim
that lock. POSIX retains signal-zero process inspection requiring `ESRCH`
(the recorded local PID is gone). New Windows schema-2 locks additionally bind
the OS-reported process creation FILETIME; a matching live instance blocks,
while an observed different birth at that PID proves the original writer ended
without touching the successor. Legacy Windows locks still require actual PID
absence. Unknown or inaccessible process identity, changed lock identity,
another plan, ordinary runtime lock, or file-transaction lock blocks recovery.
No read/status operation steals a lock. An interrupted partial lock
write that cannot be validated likewise requires separate manual reconciliation.

This is a cooperative local-process protocol, not a distributed lease or a
same-UID adversarial guarantee. PID reuse can conservatively block legacy/POSIX recovery.
Current-user ownership, real paths, no symlinks/hard links, root binding and
identity checks reduce accidental misuse. Windows reclamation retains the
native lock handle and exact identity/digest through deletion and directory
flush; new leases also revalidate the process tuple. POSIX Node does not provide
a race-proof unlink-by-verified-file-descriptor API. The machine owner can still
defeat ordinary filesystem/database controls. See the
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
```

Focused tests use real SQLite databases and owned project-local directories.
Actual child-process exits exercise before-prepare, after-prepare and
after-partial-delete durability, including retained dead writer locks and
reopening/recovery. Other cases cover user edits, immediate pre-unlink hash
checks, hard links, dangling symlinks, unavailable stores, foreign workspaces,
active runs, accepted-history changes, read-only zero-write queries, completed
replay, dangling rows, schema rejection and completion failures.

The 16 pruning tests pass on macOS and Linux/arm64 with Node 24.21.0 and SQLite
3.53.4. Linux validation used the already-cached immutable Node Alpine image
documented in the runtime-store qualification, with networking disabled, no pull,
a read-only container root, and native-volume test storage. The macOS combined
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
