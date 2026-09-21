# Windows held-handle file effects

This is the replacement candidate for CodeQL `js/file-system-race` alerts
**4–9**, not a suppression or a claim that private ACLs make all same-account
processes harmless. The earlier Windows application tests did not exercise the
final check/use interleavings identified by that query.

## Mapping the six findings

| Finding | Former check/use gap | New operation |
| --- | --- | --- |
| 4: exclusive write | Native `CREATE_NEW` closed, then Node adopted a later pathname identity and reopened it for writing | One native invocation creates, validates, writes, flushes and closes the **same allocation handle**, returning its actual identity |
| 5: runtime-lock release | Identity/content checks followed by pathname unlink | Native read/delete handle, restrictive sharing, exact saved reference and digest, handle disposition, close and directory flush |
| 6: source publication | Stage/destination checked, then pathname link/replace | Held stage and destination handles; directory-relative no-replace rename; durable retained-preimage intent for replacement |
| 7: stage cleanup | Validated stage name could be reused before unlink | Stage rename consumes the held object; there is no post-publication unlink of the stage pathname |
| 8: transaction-lock release | Checked lock could be replaced before unlink | Same identity-bound native delete as runtime-lock release |
| 9: dead-lock reclaim | Two recoverers could check the same old lock and one delete the other's replacement | Destructive handle acquired before checking identity/content and PID absence; conflicting recoverers cannot simultaneously hold it; deletion affects only that handle |

The JavaScript adapter still performs read-only planning/freshness observations.
Those observations are **not** the protection for mutation: the native operation
revalidates the actual opened object and retains it throughout the effect.
The corresponding Windows pruning lock/deletion paths use the same held-handle
operations rather than retaining an adjacent instance of the same race.

## Native lifetime and directory binding

`assets/platform/windows-file-operations.ps1` is loaded only by the fixed,
validated packaged PowerShell helper. It is original adapter code using OS
APIs, not a native addon, external executable shim or a second workflow engine.

- Every ancestor is opened and retained, starting at the verified fixed local
  NTFS drive. Opened directories reject reparses and noncanonical final paths.
  The independently expected workspace device/inode must match the held root.
- Below the workspace, directories must retain current-user private ACLs.
  Ancestors keep the existing trusted-owner/mutation restrictions.
- Handles request real directory/file data access, not just metadata access,
  with sharing that excludes directory/leaf deletion and unwanted writers.
- Child opens/creation use `NtCreateFile` **relative to a held parent handle**.
  Renames use `NtSetInformationFile(FileRenameInformation)` on the held source,
  with **replacement disabled**. Only a simple leaf name in that source's same
  pinned parent is accepted; no full-path rename fallback exists.
- Owner, group, DACL and supported access policy are obtained from the **actual
  handle** using `GetSecurityInfo`. Data hashes and stream/attribute checks
  likewise use that handle.
- A new file receives its private descriptor at allocation. Any copied source
  descriptor is compared immediately on that newly allocated handle. If creation
  already assigned the exact supported security, there is no redundant ownership
  setter. Otherwise only differing owner/group components and the required DACL
  are applied to that handle, never to a reopened pathname. Exact owner, group,
  protected-DACL/control, ordered-ACE and access-policy comparisons still gate
  content writing, and the held source is checked again for security drift.
  Content is written and flushed through the same handle.
- Deletion uses `SetFileInformationByHandle(FileDispositionInfoEx)` on the
  verified read/delete handle. No read-only-attribute override or legacy
  pathname-unlink fallback is used.
- File and held-directory flushes and handle closes are checked. A helper error,
  cancellation, failed close or incomplete response is not success.

Returned identities/digests are references, **not transferable OS handles**.
The helper does not return a handle number and pretend it remains held after
process exit. A bounded line protocol reports fixed operation phases and
requires transport continuation while the handles remain held. Normal trusted
composition supplies those continuations; they are not human approvals and do
not replace the application's exact authority checks. The tests can withhold a
continuation and race a separate process against the held objects.

## Recoverable replacement, not an atomic exchange

Windows source replacement now has a deliberately visible, recoverable
intermediate state:

1. Hold and verify the stage and current destination, including expected bytes,
   identity, privacy and security equivalence. Exclude competing data writers and
   deletion while those handles are held.
2. Durably create the immutable
   `.missionspec/transactions/<id>.win-<index>.json` intent. It binds the original
   plan digest, relative target, root identity, expected/proposed digests and
   native stage/preimage references.
3. Rename the verified destination handle to the unique internal
   `<target>.msn-<id>.before` name, without replacement, and flush the directory.
4. Rename the verified stage handle into the now-empty destination, also without
   replacement. If another entry wins that name, **do not overwrite it**: retain
   the preimage, stage and journal for explicit reconciliation.
5. Flush the published data and directory. Delete the retained preimage only via
   its verified handle after checking the published object and exact original
   preimage reference. Flush that removal before returning.

Existing main journals remain immutable. Recovery recognizes source absence
**only** when a matching native intent and retained preimage prove this
intermediate state. It rechecks every saved identity/digest/security reference.
A missing/unrecognized intent, changed preimage, foreign target, unexpected stage
occupant, partial sidecar or changed root blocks recovery and preserves bytes.
It never treats arbitrary user deletion as permission to replace a file.

### Same-directory rename ABI and sharing

The actual `cb9c0b2` run exposed the first preimage rename failure. The prior
Win32 `FileRenameInfo` call supplied our write-denying parent pin as
`RootDirectory`. The native
[`FILE_RENAME_INFORMATION` contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
distinguishes that case: a non-null root invokes `IopOpenLinkOrRenameTarget`,
whose relative directory open requests `FILE_WRITE_DATA | SYNCHRONIZE`.
That conflicts with the existing pin's sharing. For a same-directory rename,
the documented form is instead a **simple leaf name and null `RootDirectory`**.

All publication/preimage moves are already within one parent. The adapter
checks that the source's recorded parent is the exact held parent object, keeps
that parent and all ancestors pinned, and uses the source-relative form of
[`NtSetInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile),
native information class **10**, not Win32 class **3**. Source handles retain
`DELETE` access; source/target data-sharing restrictions and directory pins are
unchanged. `ReplaceIfExists` remains false. The operation cannot use a caller's
working directory, a different parent, a full path, or an ADS name.

The native structure layout is explicit:

| Pointer size | Root handle offset | Name-length offset | Name offset | Aligned structure size |
| --- | --- | --- | --- | --- |
| 4 bytes | 4 | 8 | 12 | 16 |
| 8 bytes | 8 | 16 | 20 | 24 |

The zeroed buffer includes the aligned structure size plus the UTF-16 name bytes,
including spare terminator/padding space; `FileNameLength` excludes that padding.
A correctly sized `IO_STATUS_BLOCK` is supplied. Nonzero returned NTSTATUS is
reported numerically with `phase=effect-rename`; no cached Win32 last-error value
or unsafe pathname fallback is used.

This is not a single atomic exchange: observers can see the destination absent
between steps 3 and 4. The recovery protocol, rather than a false atomicity claim,
handles that state. Absent-target publication needs no retained preimage and uses
the no-replace held-stage rename directly; the old internal hard-link pair is no
longer created.

## Bounds and remaining trust assumptions

The protections address ordinary concurrent writers, pathname replacements and
competing recoverers without relying on a preceding pathname `stat`. They do
**not** establish unconditional hostile-same-SID or administrator confinement.
Windows sharing does not freeze every security-descriptor operation and is
maintained per stream. The adapter rechecks supported metadata and rejects extra
streams, but the current account/machine administrators can change policy,
tamper with journals, interfere with handles or bypass normal controls. No
tamper-proof history, secure erasure, process-tree cancellation or human presence
is claimed.

The lower-level SQLite path API and the broader documented machine-owner trust
boundary are unchanged. These changes are not a blanket statement that every
filesystem operation in the product is race-proof.

## Verification

Run the focused held-handle regression first on actual Windows:

```sh
npm run build
node --test --test-concurrency=1 tests/windows-file-races.test.mjs
```

The focused rename case runs without retained-preimage/recovery complexity:

```sh
node --test --test-concurrency=1 --test-name-pattern="^held same-directory rename" tests/windows-file-races.test.mjs
```

It verifies that held-source rename preserves file identity and bytes, consumes
only the admitted stage name and creates no backup for an absent target. The
full publication cases continue to require no-replace rejection of a real
destination winner and recovery of the exact retained preimage.

For a quick check of the source-security-copy path specifically:

```sh
node --test --test-concurrency=1 --test-name-pattern="^held creation copies exact" tests/windows-file-races.test.mjs
```

The first hosted held-handle run at `406ef73` passed allocation/ancestor
substitution and competing lock deletion, then failed the combined security
setter before publication. The correction avoids re-requesting unchanged
ownership and distinguishes descriptor extraction, setter status and actual
security drift. A setter failure reports its directly returned numeric Windows
status; it does not interpret a cached `GetLastError`, dump ACLs/SIDs/paths, or
relax fingerprint equality. Canonical and explicitly edited private descriptors
are both tested directly before the longer publication scenarios. Fresh Windows
evidence is still required.

Separate processes attempt file writes, renames, ancestor replacement and
competing lock reclamation at held-handle checkpoints. Further cases create a
destination during the retained-preimage gap, interrupt native publication, and
reuse the stage pathname after publication. Assertions require unrelated bytes
and later locks to survive—not merely an unknown outcome.

The controlled test transport asserts each exact expected checkpoint before
acknowledging it. Native failure objects also contain a diagnostic `phase`, but
are terminal responses, never continuation requests. Stdin errors are observed
and any subsequent native terminal diagnostic is retained; EPIPE, missing
checkpoints, unexpected success/failure, malformed output and signal termination
cannot count as a passing operation. Expected failures require an exact native
reason. Portable process-based protocol regressions run with:

```sh
node --test tests/windows-helper-protocol.test.mjs
```

At `e28deb8`, held allocation, held deletion and exact canonical/edited source
security copying passed on actual Windows. Publication remains unqualified: the
prior harness acknowledged a terminal error's `phase` and then emitted an
unhandled EPIPE, obscuring the native failure. The corrected transport preserves
that failure for the next hosted diagnosis without changing native policy or
treating pipe closure as success.

Then rerun the existing Windows component suite and the three separately selected
application scenarios documented in [Windows state](windows-state.md), plus the
unchanged CodeQL query. Local skipped Windows cases and previous passing Windows
runs do not qualify this new native protocol.
