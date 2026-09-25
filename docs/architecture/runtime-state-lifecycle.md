# Runtime state lifecycle

The `LocalRuntimeState` public application API and `missionspec state` commands
provide explicit backup, recovery staging, bounded restoration, versioned format
conversion, external ledger selection and capacity inspection. Imports,
`status`, migration policy inspection and `--preview` create nothing and do not
collect telemetry. Mutations use exact persisted local authority; a flag, JSON
answer or model statement is not approval.

## Backup and recovery

```text
missionspec state status --json
missionspec state backup --preview
missionspec state backup
missionspec state stage --file .missionspec/backups/<digest>.json --preview
missionspec state stage --file .missionspec/backups/<digest>.json
missionspec state restore --file .missionspec/backups/<digest>.json --preview
missionspec state restore --file .missionspec/backups/<digest>.json
```

Backup uses validated **logical rows from one SQLite transaction**, never a copy
of an open database. A writable, exclusive source-ledger lease and the workspace
writer lock protect the committed capture. Every current run must have recorded
confirmed quiescence; running/outcome-unknown records and pending evidence prunes
block it. This is a necessary recorded-state check, **not proof that an external
host has stopped**. A host whose outcome is unknown still needs real
reconciliation; approval cannot replace that evidence.

Format 1 includes schema-3 rows, a workspace identity/root binding, canonical
content digests and an entry for **every effective evidence record**. Retained
raw files must exist at their canonical private paths, match their digests and
contain supported original observation envelopes; their exact canonical bytes
are included. Pruned/unavailable evidence is explicitly accounted for without
inventing raw content. Missing or edited retained evidence blocks backup rather
than producing a deceptively complete ledger-only archive. The logical ledger
limit is 4 MB and the complete package limit is 6 MB. An oversized package is
refused, not truncated.

The manifest expressly excludes independent approval/revocation records, host
admission fences, canonical project documents and telemetry/preferences.
**This is not a whole-workspace or disaster-recovery authority backup.**
Canonical specs/tasks remain Markdown; the runtime backup is not an editable
second task source. Packages are private sensitive files, not suitable for a
public repository or telemetry.

Untrusted packages are fully parsed, digest-checked and reconstructed in an
in-memory SQLite database with the exact known schema, foreign keys and existing
contract/relationship checks before persistent effects. No SQL from a package
is executed. A different workspace/root, unknown version, missing table/row,
invalid raw inventory or inconsistent history is rejected without initialization
or rebinding.

`stage` saves an immutable validated recovery package without activating it. It
also works when the current ledger is missing or corrupt. Inspection of this
package is available through `readBackup` and `validateRuntimeBackup`.

`restore` deliberately **does not replace the current ledger**. A healthy,
quiescent current ledger must contain the backup's immutable history; a newer
current head may extend the backup head. Restore fills missing raw evidence only
where that current history still marks it retained. Current pruning tombstones
win, edited replacement files are preserved, newer ledger facts remain
byte-for-byte unchanged, and no run resumes. Independent authority and admission
records are neither exported nor rewritten. A prepared restore journal and
immutable input permit the same reviewed operation to resume after process exit;
an exact already-restored file is not rewritten.

If the current ledger is missing, corrupt, divergent, or lacks backup history,
activation remains blocked after staging. A historical backup cannot prove that
later admissions stopped, grants were not revoked, or evidence was not pruned.
There is intentionally no force-reset, guessed quiescence, automatic merge or
success-shaped rollback. Reconciliation of that lost independent history is an
operator task, not a checkbox that this tool treats as proof.

## External ledger selection

```text
# First provision a qualified private local destination parent, ending in .missionspec.
missionspec state select /private/other-volume/.missionspec/state --preview
missionspec state select /private/other-volume/.missionspec/state
# The previous command returns a stage id; review activation separately.
missionspec state activate <sha256-stage-id> --preview
missionspec state activate <sha256-stage-id>
```

Selection is a two-review operation. Preparation materializes and validates a
closed exact replica in a previously unused destination. A create-only origin
binding makes the replica unusable as a parallel active store. Activation checks
the current source snapshot again under an exclusive SQLite lease and publishes
the private workspace selector, its exact generation receipt and the retained
selection marker through **one** durable file-transaction journal and writer
lease. The transaction is not complete until all required records are durable.
Quota or I/O failure after selector publication leaves that same transaction
pending, reports an unknown outcome and fences later relocations until explicit
recovery finishes it; there are no post-completion activation-record writes.
Advancing the source invalidates an old stage; the tool will not overwrite the
prepared destination to catch up. Both originals and failed/partial destinations
are preserved.

All CLI compositions, MCP's existing-ledger reader, `LocalWorkflow` quiescence
checks and the public `openWorkspaceRuntimeStore` factory resolve the same
`.missionspec/runtime-selection.json`. Existing handles check that selection
before **and after** transaction admission and become stale on a switch. Passing
the old directory to `openRuntimeStore` does not bypass the selector. An external
store also requires its bound `workspaceRoot`; a missing selected database is
not recreated or replaced by a local fallback. A retained activation marker
blocks default fallback if the selector subsequently goes missing. Immutable
generation receipts form a checked predecessor chain, rejecting a rollback to
an older otherwise-valid selector. Do not delete the selector, generation
history, markers, origin binding or journals as a recovery technique.

Only the ledger is relocated: raw evidence, workspace identity, approvals,
revocations, host fences and file journals remain rooted in the original
workspace. Evidence paths therefore stay project-relative and pruning/acceptance
continue to use the same private files. Public project metadata never gains
private locations or identity observations. There is no environment-variable or
per-command silent override that could split the workspace between two stores.

Directories must be normalized absolute paths ending in `.missionspec/state`,
with a pre-existing private `.missionspec` parent. The existing POSIX or qualified
Windows SID/DACL/local-NTFS checks apply, including ancestor, symlink, reparse,
hard-link, sidecar and identity checks. There is no UNC/network or alias fallback.
On Windows, the 240-character qualified path bound also includes the publication
stage and retained `.before` preimage, not just the final filename. A path-length
preflight failure is distinct from an injected quota failure during publication.
Runtime-store errors retain only the allowlisted Windows reason/phase, exception
category, bounded helper line and native status; arbitrary OS messages, paths,
SIDs and ACLs remain excluded.
These controls are not protection against an adversarial machine owner or
same-user process rewriting all private state.

Selector, lifecycle journal/backup and SQLite-header reads now share held-object
admission. POSIX readers validate the actual descriptor's regular type, UID,
owner-only readable mode and single-link count **before reading**, bind it to
the pre-open identity, use `O_NOFOLLOW | O_NONBLOCK`, bound all bytes, and recheck
descriptor, pathname and real ancestor observations. A permissive, linked,
special or identical-content replacement cannot be silently treated as the
original observation. Windows reads use the separately qualified native
directory-relative held reader described in [Windows state](windows-state.md);
a completed external ACL check is not attributed to a later Node descriptor.

An interrupted preparation can be retried with the same selection review. Its
own demonstrably dead writer lock may be reclaimed; live, unrelated or replaced
locks cannot. An incomplete SQLite file is not erased: preserve it and use a new
destination after investigation. For an activation file journal:

```text
missionspec recover --preview
missionspec state recover <sha256-stage-id> <transaction-id> --preview
missionspec state recover <sha256-stage-id> <transaction-id>
```

Generic file recovery cannot publish a runtime selector without the exclusive
current-ledger lifecycle lease. The publisher requires a live, workspace-bound
store-issued capability; serialized or expired lease claims are rejected.
Recovery can complete a published selector's
receipt without rolling back the selected ledger. Filesystem publication or
durability errors are not reported as completed activation.

On POSIX, recovery reuses an exact retained `.msn-<transaction-id>` stage after
checking its owner, permissions, single-link regular-file identity and complete
content through a held handle. It flushes and rechecks that handle before
publication instead of attempting exclusive recreation. Mismatched, linked,
insecure or replaced stages are preserved, not overwritten or removed. Already
published outputs are revalidated and flushed before a recovered transaction
can record completion.

All compatible POSIX workspace writers, including selection recovery, now hold
the native descriptor lock described in [evidence pruning](evidence-pruning.md#cooperative-writer-lock-recovery)
before reclaiming, publishing or releasing `transaction.lock` owner metadata.
The rejected SQLite mutex prototype is not a fallback. The replacement retains
one OS descriptor on `writer-mutex.lock` and uses Darwin `flock` or Linux
`F_OFD_SETLK`; unrelated same-process/worker descriptor closes cannot release it.
This is a separate version-1 filesystem protocol, not a ledger migration.
Read-only resolution creates no mutex and does not load the addon. Interrupted
bootstrap, invalid mutex content and experimental SQLite mutex files fail
closed; older binaries must be quiesced before upgrading.

## Version policy and migration tooling

```text
missionspec state migrate --preview
missionspec state migrate /private/recovery/.missionspec/state \
  --file .missionspec/backups/<digest>.json --preview
missionspec state migrate /private/recovery/.missionspec/state \
  --file .missionspec/backups/<digest>.json
```

`planRuntimeMigration` is the versioned, closed policy boundary. Its implemented
edges export SQLite schema 3 to logical backup format 1 and import format 1 into
a **nonactive native schema-3 recovery replica**. Import independently validates
every source fact, retains the original package/raw evidence, uses create-only
storage, verifies the rebuilt snapshot digest and journals the conversion for
retry. It grants no activation or execution authority.

Inspection reports `current` and no applicable numeric schema upgrade for a
current schema-3 ledger. Repository history contains no previously released
runtime schema: versions 1 and 2 and the old prototype paths are unreleased
formats without a verified supported upgrade edge. The implementation does not
invent their schema, create a new production version to simulate an upgrade, or
call rejecting them a migration. A future numerical upgrade must add an explicit
source parser/converter and fixtures proving preservation of recorded facts and
independent authority. Opening a ledger never invokes that converter implicitly.
Project Markdown/YAML migration is a separate format boundary, not claimed by
this runtime policy.

## Capacity and qualification

`state status` reports exact integer-string database/page/free-space accounting
with no reservation. SQLite `FULL`, POSIX `ENOSPC` and quota `EDQUOT` report
capacity exhaustion where those codes are observable. Partial recovery files
remain available for diagnosis; no capacity failure triggers pruning or reset.

The lifecycle suite exercises actual SQLite, private POSIX files, changed
authority/state, malformed/foreign backups, stale selection, read-only previews,
prune suppression, real page exhaustion, and actual child exits during restore,
replica creation and activation. Independent real Windows qualification also
passed at `924f383` in
[run 35710089600](https://github.com/voyager163/missionspec/actions/runs/35710089600),
including backup/raw restore, nonactive native conversion, external selection,
quota failure after selector publication and journal recovery. POSIX tests and
locally skipped Windows cases are not substitutes for that hosted evidence.
