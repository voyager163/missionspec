# Windows private-state boundary

Windows private storage and Windows effect execution are separate capabilities.
The narrow storage and directory-barrier components at **`d684dbb` passed 23/23
actual Windows tests with zero skips** in
[run 35583798870, job 106282370371](https://github.com/voyager163/missionspec/actions/runs/35583798870/job/106282370371).
The real application integration below is a **new qualification candidate**;
that earlier success does not qualify it, a console channel, or native execution.
POSIX success or mocked `process.platform` results are not Windows qualification.

## Capability matrix

| Surface | Windows candidate behavior |
| --- | --- |
| SQLite runtime ledger | Explicit create/read/write on validated private local NTFS; existing schema-3 validation, exact workspace binding, CAS, rollback, immutable history and sidecar refusal remain unchanged |
| Dedicated telemetry preferences | SID/ACL-checked parent and file, real SQLite patches/reopen, no permissive Windows ownership exception; existing journals/WAL/shared memory require reconciliation |
| Dedicated diagnostic JSONL | Private parent/file, exclusive cooperative lock, bounded canonical append and digest-bound explicit truncation, file flush |
| Private workspace reads | SID/ACL checks instead of meaningless POSIX UID/mode checks; existing root digest, inode/device checks and content checks remain |
| Private directory metadata barrier | Qualified at the revision/run above: stable identity, writable directory handles, sharing contention, and eight interruption/recovery boundaries |
| Workspace setup, source/artifact writes, immutable runtime records, file journals/recovery | Candidate integration in the existing `LocalWorkspace`; restricted private current-user NTFS roots, atomic private allocation and mandatory namespace barriers |
| Raw-evidence removal and dead-prune-lock recovery | Candidate integration in the existing pruning application and filesystem adapter; no change to SQLite prepare/complete or exact-grant requirements |
| Trusted callback/MCP receipt issuance and revocation | Candidate integration in the existing broker; callbacks remain independently trusted composition and human presence remains **not attested** |
| Terminal confirmation | **Blocked** on Windows regardless of TTY booleans; actual console/ConPTY challenge behavior remains unqualified |
| Real registered checks / native-host execution and cancellation | Unchanged, independently blocked; storage capability never establishes execution, completion or quiescence |

This does not qualify interactive Windows CLI setup: terminal issuance is still
unavailable, and native checks/hosts remain independently gated. The candidate
application operations require trusted library composition and exact current
grants, not `approved` input or an environment switch. SQLite's pruning
tables can store supplied immutable lifecycle records; that is **not** a new
filesystem-deletion capability or an authority issuer.

## SID, ACL and path enforcement

`src/adapters/platform/windows-private-state.ts` is a shared narrow adapter, not
another engine or a native addon. It launches only the fixed OS binary
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, with no profile,
no interaction, no shell, bounded output and a 20-second timeout. Systems with a
different Windows installation location, missing PowerShell, or policy blocking
the required APIs fail closed. `PATH`, executable overrides, approval environment
flags and caller permission booleans cannot select an alternate implementation.
Trusted installation of Node, the application and the OS binary remains part
of the local-machine boundary.

Before launch, the adapter checks the fixed installation's real path and each
component's file/directory type, rejecting symlink/junction executable aliases.
`SystemRoot` can only restrict execution to that fixed installation, never
select another binary. Before inspecting input or creating state, the helper
also checks the actual OS system directory, executing process image, PowerShell
home, and OS path/binary ACLs. OS ownership and mutating rights must belong to
SYSTEM, Administrators or TrustedInstaller, not an ordinary current-user shim.
The create-child exception applies only to ancestor **directories**. On OS
**files**, untrusted `FILE_WRITE_DATA` and `FILE_APPEND_DATA` grants are rejected
as well as delete, metadata and security-descriptor mutation rights. The shared
pure mask decision is exercised on synthetic ACE masks; tests never modify
an actual OS executable or its ACL. This self-inspection remains an OS-trust
boundary, not cryptographic binary attestation.

The fixed helper lives at **`assets/platform/windows-private-state.ps1`**, included
with its pure **`assets/platform/windows-access-policy.ps1`** policy function
by the existing package `assets` rule. Their paths are resolved relative to the
installed module, not the project working directory. It runs with `-File`,
without `-ExecutionPolicy`, `Set-ExecutionPolicy`, elevation or an inline-command
fallback. Machine policy that disallows the script is a capability blocker.
Paths arrive as UTF-8 JSON on stdin, never executable PowerShell expressions.
The JSON utility module is imported from its fixed OS path, not project/PATH
or arbitrary module search. ACL reads use the framework API. Native declarations
use in-memory `Reflection.Emit`, not `Add-Type`/a compiler, generated assemblies
on disk, downloaded code, a native addon or temporary compiler files.

Checks use the actual token user's SID, raw Windows security descriptors and
Win32 handles. They require:

- A normalized, exact-case, fully qualified DOS path of at most 240 characters.
  UNC, device/extended namespaces, drive-relative paths, alternate data streams,
  reserved device names, dot/trailing-space aliases and control characters fail.
- A fixed local **NTFS** volume. `GetDriveTypeW`, `DriveInfo.DriveFormat` and
  `QueryDosDeviceW` reject network/removable volumes, SUBST aliases and unknown
  device mappings. ReFS, FAT, SMB and cloud-provider reparse storage are not
  qualified.
- `CreateFileW(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)`,
  `GetFileInformationByHandle` and `GetFinalPathNameByHandleW` validation of
  every component. Reparse points (not just symlinks), junctions, short/case aliases
  and multi-link regular files fail.
- The private entry's **owner SID equals the current user**, with effective
  required permissions for that SID. A writable private directory must have
  inheritable full control for that user, so SQLite sidecars remain private.
- Only current-user, `SYSTEM` and local `Administrators` allow ACEs in private
  state. Null DACLs, foreign grants (including read grants), deny/conditional/object
  ACEs and unsupported inheritance fail conservatively. This is deliberately
  narrower than all safe ACLs Windows can represent.
- Ancestors owned by the current user, SYSTEM, Administrators or the fixed
  Windows TrustedInstaller service SID. Other principals may traverse/read and
  create new ancestor children, but cannot delete/replace children, change
  ancestor metadata, write its DACL, or take ownership. Existing project roots
  are never re-permissioned to satisfy this rule.

Creation supplies an owner and protected inheritable DACL atomically to
`CreateDirectoryW` or `CreateFileW(CREATE_NEW)`, before sensitive content is
written. Only the selected **new** private entry is created; existing entries
are checked, never repaired or ACL-reset. The SQLite factory still requires
the existing `.missionspec` parent and exact `.missionspec/state/ledger.sqlite`
layout. Log/preference factories require an already-private dedicated parent.
No adapter silently secures or changes a user project root.

Administrators and SYSTEM are trusted machine principals, **not excluded
attackers**. An administrator can take ownership, bypass normal controls, debug
the process or replace the OS. The current account can also rewrite records and
recompute hashes. As on POSIX, descriptor/path rechecks do not defend against a
malicious same-account process between a check and SQLite's pathname open.
These are privacy/integrity checks for trusted local composition, not cryptographic
history, organization authentication or tamper-proof human presence.

## Why directory effects remain blocked

The existing file-transaction and pruning contracts order durable journal
creation, source replacement/removal, directory fsync and completion receipts.
Dropping the parent-directory barrier would allow a completed receipt to survive
while an earlier namespace change is lost. File flushing alone is not permission
to make that claim.

Relevant Microsoft API contracts:

1. [`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers)
   requires a writable file handle. Its documented volume-wide alternative
   requires administrative privileges. The adapter never requests elevation,
   opens a volume for flushing or depends on the hosted runner's elevated token.
2. [`ReplaceFileW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)
   explicitly marks `REPLACEFILE_WRITE_THROUGH` **unsupported**.
3. [`MoveFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw)
   documents `MOVEFILE_WRITE_THROUGH` and a copy/delete flush. This is not a
   demonstrated barrier for all of the existing same-volume create/link/rename/
   unlink operations, and cannot be substituted for directory fsync by assertion.

The first genuine hosted run, [35573315470 / job 106249457486](https://github.com/voyager163/missionspec/actions/runs/35573315470/job/106249457486),
on Node 24.21.0 established that opening a directory through Node succeeded,
but `FileHandle.sync()` returned `EPERM`. **Native `CreateFileW` with
`GENERIC_WRITE` followed by `FlushFileBuffers` succeeded**, both with and without
`FILE_FLAG_WRITE_THROUGH`. Read-handle flushing failed. The original probe read
the cached Win32 error after returning through PowerShell; its error 203 may be
stale and must not be used to identify the native failure.

These results do **not** establish a Windows platform impossibility. The
documented [`CreateFileW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
directory handle (`FILE_FLAG_BACKUP_SEMANTICS`) and writable-file flush are a
viable implementation path to qualify. Microsoft's
[file caching contract](https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching)
explicitly directs callers to `FlushFileBuffers` for cached metadata;
[`IRP_MJ_FLUSH_BUFFERS`](https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-flush-buffers)
requires the filesystem to flush important data and metadata associated with
the file object. Node's read-only directory descriptor is not equivalent to
that writable Win32 handle.

The updated probe captures error codes within a single emitted managed method,
before returning to PowerShell. It repeats the
read/write and write-through matrix using a **restricted version of the same
user's token**: Administrators is deny-only and `DISABLE_MAX_PRIVILEGE` removes
all enabled privileges except directory-traverse notification. It verifies these
conditions and uses only a newly created empty test directory with an explicit
current-user owner/full-control DACL. This neither creates an account nor enables
privileges or bypasses machine policy. See
[`CreateRestrictedToken`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken).
The [second hosted run, 35575442548](https://github.com/voyager163/missionspec/actions/runs/35575442548),
confirmed `currentUserOwnsDirectory: true`,
`privilegesDisabledExceptTraverse: true` and `administratorEnabled: false`.
Both writable directory-handle variants still opened and flushed successfully
under that restricted token. Thus this primitive did not require administrator
grants or enabled backup/restore privileges on the observed NTFS filesystem.
That is not a substitute for qualifying a separate ordinary-user installation
or the complete journal/effect ordering protocol. Read-handle flushing still
returned false with error 203 even after immediate capture; no capability or
failure classification depends on interpreting that code.

Before the general protocol can be enabled, qualification still needs current-user
directory handles without backup/restore privilege bypass, stable native identity
checks around flushes, create/link/rename/unlink ordering, interrupted journal and
recovery cases, and propagation of failed/unknown flush outcomes. Authority and
process/console checks have their own remaining gates. Failed probes never fall
back to reporting durability success.

### Qualified identity-guarded native barrier

`syncWindowsPrivateDirectory(directory, expected)` is an internal platform
adapter, not an API-barrel export, general file-write port or authority issuer.
`expected` contains the previously observed Node bigint `dev` and `ino`.
Those numbers are only an identity guard: the fixed shared helper independently
repeats its local-NTFS, path/reparse, owner-SID, private-DACL and ancestor checks.
Neither a caller boolean nor a supplied identity can waive any check.

For this operation only, the helper:

1. Opens the existing directory with `GENERIC_WRITE`, metadata-read access,
   `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, and read/write
   sharing **without delete sharing**. The leaf cannot ordinarily be renamed or
   deleted while its verified handle is held.
2. Validates the directory type, canonical final path and ACL. It compares the
   handle's volume serial and 64-bit file index with the expected device/inode.
   This matches the NTFS identity fields used by
   [Node 24.21's Windows stat implementation](https://github.com/nodejs/node/blob/v24.21.0/deps/uv/src/win/fs.c);
   POSIX UID/mode fields are never used as Windows proof.
3. Calls `FlushFileBuffers` on **that same handle**, then rechecks its directory
   attributes, device/inode and final path.
4. Frees native memory and closes the handle in nested `finally` handling.
   A failed close, flush, identity check, helper timeout or uncertain helper result
   is an error, never durability success. No Win32 error-number interpretation
   (including the probe's 203) is necessary.

It does not create an entry, change ACLs, open/flush a volume, enable privileges,
invoke an addon or fall back to Node directory `sync()`. Unsupported identities
and options fail before the flush. Failure throws
`WindowsDirectoryDurabilityError` with `durability: 'unconfirmed'`; a caller
that already mutated data must preserve its journal and report an unconfirmed
effect rather than infer rollback or proceed to completion.

`tests/windows-directory-durability.test.mjs` qualifies this candidate separately:
real handle-sharing contention, wrong/replaced identities, junction/case aliases,
ordinary-file rejection, public/foreign ACL rejection without repair, and exact
handle closure behavior. Its test-only namespace driver uses actual private files,
file `fsync`, native directory barriers, rename, unlink and separate child exits.
It checks the ordering:

```text
prepared journal file sync → journal directory barrier
→ staged replacement file sync → stage directory barrier
→ rename → source directory barrier
→ exact retained-byte unlink → removal directory barrier
→ completion file sync → completion directory barrier
```

Actual child exits cover preparation, staging, immediately before and after
rename/unlink barriers, and a written completion whose directory barrier has not
yet returned. Explicit test recovery re-establishes those barriers, preserves
changed preimages, rejects a copied cross-root journal, and never deletes a raw
replacement after completion. A stale barrier identity cannot acknowledge the
journal or permit following effects.

This driver is **test-only**, excluded from the package, and does not use or grant
production source-apply, approval, evidence-pruning or host authority. Its parent
observes the actual child termination before resuming; it does not reclaim a
persisted PID lock or establish general process quiescence. Process exits are not
physical power-cut/storage-controller tests. No native close-failure injection or
adversarial same-account confinement is claimed.

The native primitive and this isolated ordering protocol passed the hosted run
above. Production integration uses the existing `LocalWorkspace.syncDirectory`
and evidence-file barriers—not the test-only protocol driver or a replacement
workflow engine. The separate application suite below must now qualify those
real paths. No terminal or native-host gate is opened by a directory flush.

### Real application integration candidate

The same `LocalWorkspace` validates plans, resolves actual authority, checks all
guards, writes immutable journals and performs explicit recovery. Windows changes
are platform branches in that adapter, not a second controller:

- The **workspace root, mutating parent directories and files must be private,
  current-user-owned NTFS entries**. Existing unsafe roots/state are rejected,
  never re-owned, re-ACL'd or silently adopted. Source/configuration directories
  are intentionally narrower than public-readable POSIX project layouts.
- New empty directories/files receive their SID descriptor atomically. Every
  newly created parent entry is followed by the existing parent's native
  directory barrier **before** any descendant sensitive content is written.
- Mutable files must have only the unnamed `::$DATA` stream and ordinary
  normal/archive attributes. Read-only, hidden/system, encrypted/compressed,
  reparse/special and extra-stream files are refused, not normalized or discarded.
  The volume must advertise `FILE_SUPPORTS_POSIX_UNLINK_RENAME`; this prevents
  relying on Node's legacy delete-pending/attribute-clearing fallback.
- A replacement stage is created with the existing file's owner/group/DACL,
  then checked for exact owner/group/DACL and access-affecting label/resource/
  central-policy/filter equivalence.
  Because Windows creation can process inheritance/control state, the copied
  descriptor is explicitly applied while the `CREATE_NEW` stage is still empty
  and held by a non-shared handle. Size and link count are checked before and
  after this step. This affects only that newly reserved stage; an existing stage
  or the source is never repaired, and no sensitive bytes are written before
  privacy and permission equivalence succeed.
  Comparison parses SDDL into binary descriptors, so SID spelling is not identity.
  The sole control normalization removes the `SE_DACL_AUTO_INHERITED` history bit
  **only when that descriptor is protected**: inheritance is blocked and every
  ordered ACE byte, ACE flag, owner/group SID, protection bit and auto-inherit
  request remains compared. Unprotected inheritance-control differences are
  rejected. Access-policy equality remains a separate strict check.
  The helper never changes the existing file's descriptor. If the descriptor
  cannot be preserved by creation/inheritance, the empty stage is retained as
  an explicit uncertain outcome; no sensitive stage bytes or source replacement
  are performed. Unsupported access policy is refused rather than dropped.
  This is not a general auditing-SACL or extended-metadata cloning facility.
- Existing-file replacement uses the same staged rename protocol; absent-file
  publication uses the same exclusive hard-link publication followed immediately
  by stage unlink, synchronously on Windows. Unexpected hard links always fail.
  An abrupt exit between those two syscalls can retain an internal linked pair:
  it is **not** silently normalized or treated as completion. Establish writer
  quiescence and review that retained stage before manual reconciliation.
- Recovery re-fsyncs the retained journal and any reused exact-content stage,
  and re-establishes directory barriers for already-applied outputs. Changed
  source/stage bytes remain blockers, never overwritten. Windows stage rejection
  performs no automatic cleanup: ADS, unsafe/changed security and replacement
  stages remain available for reconciliation. Stage identity/version and bytes
  are checked again before publication. Successful exclusive publication removes
  only its verified same-inode linked candidate; a rename consumes its stage
  without subsequently unlinking a potentially reused stage pathname. Failed write, flush,
  close or lock release reports an unknown effect rather than success.

The persistent authority backend allows independently installed
`trusted-callback`/`mcp-elicitation` transports on this private scope, retaining
closed receipts, exact review/request binding, deadlines, expiry, revocation and
`humanPresence: 'not-attested'`. It still refuses terminal-channel issuance on
Windows. Test callbacks are explicitly **TEST ONLY**, not genuine human evidence.

Pruning uses the same real `LocalEvidencePruning` application: durable SQLite
preparation fences availability before deletion; the existing descriptor/hash/
identity checks precede synchronous unlink; a native directory barrier also
confirms already-absent recovery paths before completion. Existing evidence/run
history is retained and completed pruning never deletes a replacement raw file.

Cooperative lock recovery uses a bounded **complete** `K32EnumProcesses` snapshot,
including a self-presence sanity check. A live/reused PID, unknown/truncated
inspection, wrong transaction/prune identity or changed lock blocks reclaim.
This checks the one local filesystem writer only: it is not host cancellation
or descendant-process quiescence. Node performs source rename/link/unlink itself.
Its creation helpers additionally hold a non-delete-shared native handle to the
exact writer-lock inode and digest, so a delayed helper cannot create entries
under a replaced lock and recovery cannot steal a lock still leased by that
helper. Read-only status never reclaims a lock. Partial/unparseable locks require
manual reconciliation; no force flag or caller assertion grants quiescence.

The actual-application cases retain stable unique names and are selected into
separate **at most 15-minute** Windows jobs; do not add their runtimes together
under the suite's 13-minute aggregate timer:

```sh
npm run build
node --test --test-concurrency=1 --test-name-pattern="^real Windows setup, callback receipts," tests/windows-local-runtime.test.mjs
node --test --test-concurrency=1 --test-name-pattern="^real Windows file journals recover" tests/windows-local-runtime.test.mjs
node --test --test-concurrency=1 --test-name-pattern="^real Windows evidence-pruning application" tests/windows-local-runtime.test.mjs
```

Each command above is a separate job, not sequential steps within one 15-minute
budget. Run this quick, direct security-copy regression first:

```sh
node --test --test-concurrency=1 --test-name-pattern="^(security-copy diagnostics|Windows security comparison|Windows direct stage copy|Windows ordinary files)" tests/windows-private-state.test.mjs
```

It covers canonical and explicitly edited protected DACLs, rejects real access
changes, and tests the limited control normalization independently of workflow
setup. Failures identify only the differing component
(`owner`, `group`, `control`, `dacl`, `descriptor`, or `policy`); assertions compare
bounded permission fingerprints, not raw ACLs, SIDs or paths. Actual differences
still stop publication and preserve the empty/retained stage. The initial
application run at `c54ad89` stopped at this comparison after 551 seconds and
then exhausted its aggregate timeout; it did not qualify source or pruning
integration. A passing quick rerun and the three actual-application jobs are
still required; the representation fix is not itself hosted qualification.

At `b05ede8`, the component suite and actual pruning scenario passed, and source
ACL preservation, callback receipts/revocation and initial journal recovery also
completed. Source/recovery then exposed a control-flow defect: ordinary-file
stream/attribute validation was nested inside the directory-inheritance branch.
It now runs for private ordinary files independently of directory inheritance.
The quick component suite covers both source ADS and the exact retained-stage
guard, proving that rejection preserves default and named-stream bytes and never
creates a copied stage from an ADS-bearing source. The affected application
negatives still require a hosted rerun; no metadata predicate was relaxed.

The application suite exercises real `LocalWorkflow`, `openLocalAuthority` and
`LocalEvidencePruning` APIs: declined/malformed and approved setup, persistent
receipt reopen/revocation, draft and batched capture, replacement/new source
patches, exact-grant and stale-edit rejection, source DACL preservation, actual
child exit with pending file journals, live-lock refusal and reviewed recovery,
a real closed-handle sync failure, retained-stage ADS/ACL and identity-replacement
preservation, SQLite pruning preparation and partial-delete
exits, changed raw preservation, current reapproval and no replay. Fault
boundaries wrap real operations in test workers; no production fault/approval
boolean is introduced. These tests are not yet hosted qualification evidence.

SQLite continues using its built-in Windows VFS, rollback/DELETE journaling and
the existing `synchronous=FULL` contract (preferences use `EXTRA`). JSONL continues
its existing regular-file `sync()` contract. Neither is advertised as the missing
general directory barrier. Reopen/process-exit tests are not physical power-cut,
storage-controller or every-filesystem qualification.

## Independent hosted validation

With Node **24.21.0** and dependencies already restored, run this command from the
checkout. The helper remains loaded from the built package; sensitive generated
fixtures use separately validated current-user profile storage:

```sh
npm run build
node --test --test-concurrency=1 tests/windows-private-state.test.mjs tests/windows-directory-durability.test.mjs
```

Do not combine this with the POSIX-specific legacy suites or infer that skipped
Windows tests on macOS qualify anything. For sensitive fixtures, the test asks
the OS for the current user's `LocalApplicationData` and `UserProfile` known
folders—not unchecked environment paths, `RUNNER_TEMP` or `os.tmpdir()`.
Local application data must be inside that profile. The test attempts exclusive
creation of a fresh UUID directory beneath local application data, then beneath
the profile only if the first attempt created nothing. The unchanged production
`create: true` operation validates the existing container and every ancestor
using **ancestor policy**, then atomically supplies the new leaf's current-user
owner and protected DACL. A readable or SYSTEM-owned existing container can be
safe ancestry; it is not required to satisfy private-leaf ownership/inheritance
rules. No profile/checkout ACL is changed or ancestor predicate relaxed.

If both candidates fail without creating anything, the failure identifies the
`local-app-data` and `profile` candidates using only sanitized helper reasons and
phases, never their paths, ACLs or SIDs. Any partial or uninspectable creation
stops qualification rather than falling back. Only a verified current-user-owned,
identity-stable, empty partial UUID directory can be removed; otherwise it is
retained and the failure is explicit.

Every successful fixture is an exclusively created UUID directory, and cleanup
rechecks that exact root's device/inode identity and private ACL after its SQLite
handles close. It never removes the selected profile container. A controlled
negative case grants delete-child access to
Everyone **only on a newly created test-owned parent**, proves private creation
and ledger reopening fail without ACL repair or database changes, then restores
that test parent's original descriptor for cleanup. No OS/profile/checkout ACL
is modified. The independent primitive probe may still use a new empty,
nonsensitive checkout directory; its directory contents are not private state.

The first hosted run passed the path grammar and native primitive probe, but all
nine ACL/storage cases failed before private fixture creation with an unexpected
helper exception. The second run isolated it to PowerShell 5.1's bitwise handling
of typed `AceFlags` at the `InheritOnly` predicate. The helper now explicitly
converts both ACE flags and the enum mask to integers, including all subsequent
inheritance predicates, without changing their values or ACL decisions. A
32-case synthetic `CommonAce` regression exercises the actual enum representation.
The [third run, 35576039457](https://github.com/voyager163/missionspec/actions/runs/35576039457),
passed that regression and advanced to an intentional `public-access` rejection
in the shared `D:\a` checkout ancestry. **That checkout was not a qualified private
state location.** Moving only generated fixtures to independently validated
profile storage does not qualify the public checkout, weaken ancestor policy,
or enable CLI/workspace mutations there. Storage qualification now targets the
selected profile-local NTFS directories and remains pending a passing hosted
rerun. The [fourth run, 35577218133](https://github.com/voyager163/missionspec/actions/runs/35577218133),
also rejected an overly strict **test-only** precheck that treated existing
profile containers as private leaves. Fixture selection now uses the unchanged
production creation contract described above. Follow-up
diagnostics report only allowlisted operation phases, helper/system/ancestor/private
boundary categories, exception type categories and bounded script line numbers.
They never copy native exception messages, filesystem paths, ACLs, SIDs, raw
records or secrets into an error.

The [fifth run, 35578139448](https://github.com/voyager163/missionspec/actions/runs/35578139448),
successfully created protected roots under `local-app-data` and passed real NTFS
SQLite CAS/ABA/reopen, lock/sidecar/path-replacement checks, child-exit journal
retention, blocked-effects no-write checks and the restricted-token directory
probe. Six remaining failures were isolated to test-harness behavior: changing
`SystemRoot` before Node startup crashed Node's cryptographic initialization;
Windows PowerShell 5.1 ACL cmdlet autoload followed an inherited PowerShell 7
module path; and `rmSync` was used on an empty directory. The tests now change
`SystemRoot` only inside an already-started child and require the helper's exact
controlled rejection, use framework ACL methods with the JSON utility explicitly
loaded from its OS path, and remove the exact empty directory with `rmdirSync`.
No production predicate or fixture placement changed. Full qualification still
requires the remaining positive and negative cases to pass together.

Coverage includes genuine SID/DACL creation, foreign owner and public-read
rejection without repair, literal Unicode/metacharacter paths, SQLite schema-3
reopen, two-handle CAS/ABA, immutable evidence, foreign root binding, read-only
inventory comparisons, real writer contention, actual child exit with a retained
journal, explicit sidecar refusal, open-path replacement refusal/detection,
hardlinks and junction/case aliases, preference persistence, log lock/stale-prune
handling, raw retention, and no-write assertions for source plans, runtime locks,
pending-journal recovery, setup and callback/terminal issuance. Test-only record
fixtures never establish actual host execution or human authority.
