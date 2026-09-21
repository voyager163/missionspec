# Windows private-state boundary

Windows private storage and Windows effect execution are separate capabilities.
The implementation below is a **qualification candidate** until the genuine
`windows-latest` test job passes. POSIX success or mocked `process.platform`
results are not Windows qualification.

## Capability matrix

| Surface | Windows candidate behavior |
| --- | --- |
| SQLite runtime ledger | Explicit create/read/write on validated private local NTFS; existing schema-3 validation, exact workspace binding, CAS, rollback, immutable history and sidecar refusal remain unchanged |
| Dedicated telemetry preferences | SID/ACL-checked parent and file, real SQLite patches/reopen, no permissive Windows ownership exception; existing journals/WAL/shared memory require reconciliation |
| Dedicated diagnostic JSONL | Private parent/file, exclusive cooperative lock, bounded canonical append and digest-bound explicit truncation, file flush |
| Private workspace reads | SID/ACL checks instead of meaningless POSIX UID/mode checks; existing root digest, inode/device checks and content checks remain |
| Workspace setup, source/artifact writes, immutable runtime records, file journals/recovery | **Blocked before mutation**: no qualified durable directory-entry barrier |
| Raw-evidence removal and dead-prune-lock recovery | **Blocked**, including after SQLite preparation: directory durability and Windows local-process death inspection are independently unqualified |
| Terminal confirmation, callback/MCP receipt issuance and revocation | **Blocked**: receipts require the blocked immutable-record persistence; Windows terminal/ConPTY challenge behavior is independently unqualified |
| Real registered checks / native-host execution and cancellation | Unchanged, independently blocked; storage capability never establishes execution, completion or quiescence |

The CLI's existing Windows mutation gates are intentionally unchanged. The
candidate storage operations are library-level capabilities for trusted
composition, not a claim that CLI setup or execution now works. SQLite's pruning
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

The fixed helper lives at **`assets/platform/windows-private-state.ps1`**, included
by the existing package `assets` rule. Its path is resolved relative to the
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

The Windows test emits actual Node directory-open/sync errors and an independent
four-case Win32 `CreateFileW`/`FlushFileBuffers` probe (read/write access, with/
without write-through). This is evidence to investigate, **not a claim that every
Windows namespace primitive is impossible**. A successful individual native call
would still need its directory-ordering contract and interrupted-operation
qualification before enabling the whole protocol. Unsupported probes never
fall back to returning durability success.

SQLite continues using its built-in Windows VFS, rollback/DELETE journaling and
the existing `synchronous=FULL` contract (preferences use `EXTRA`). JSONL continues
its existing regular-file `sync()` contract. Neither is advertised as the missing
general directory barrier. Reopen/process-exit tests are not physical power-cut,
storage-controller or every-filesystem qualification.

## Independent hosted validation

With Node **24.21.0**, dependencies already restored and an ACL-safe local NTFS
checkout, the dedicated command is:

```sh
npm run build
node --test --test-concurrency=1 tests/windows-private-state.test.mjs
```

Do not combine this with the POSIX-specific legacy suites or infer that skipped
Windows tests on macOS qualify anything. The test creates only exclusive fixture
directories beneath its working directory, never changes the checkout's ACLs,
and removes only its fixtures. An unsafe runner ancestor must fail, not be
silently changed by the adapter or disguised as a skipped success.

Coverage includes genuine SID/DACL creation, foreign owner and public-read
rejection without repair, literal Unicode/metacharacter paths, SQLite schema-3
reopen, two-handle CAS/ABA, immutable evidence, foreign root binding, read-only
inventory comparisons, real writer contention, actual child exit with a retained
journal, explicit sidecar refusal, open-path replacement refusal/detection,
hardlinks and junction/case aliases, preference persistence, log lock/stale-prune
handling, raw retention, and no-write assertions for source plans, runtime locks,
pending-journal recovery, setup and callback/terminal issuance. Test-only record
fixtures never establish actual host execution or human authority.
