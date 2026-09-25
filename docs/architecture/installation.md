# Reviewed native skill installation

The local installation library projects the single canonical twelve-operation
catalog into explicitly selected host directories. This implements local file
maintenance; it does **not** qualify a coding host, invoke a model, issue execution
authority, or establish that a host has discovered the files.

## Terminal commands

The implemented maintenance surface is `skills`, separate from the `revise`
artifact operation:

```text
missionspec skills inspect --host codex
missionspec skills install --host codex --preview
missionspec skills install --host codex
missionspec skills update --hosts copilot --hosts codex --preview
missionspec skills remove --host codex --preview
```

Mutations require a genuine local-terminal review or an exact, still-current
persisted approval. Remove `--preview` only when intending to review and apply
the displayed operation. Installing into an uninitialized project includes the
explicit setup scope in that same reviewed plan. No command installs or invokes
the host executable itself.

## Library composition

Compose `SkillInstallation` from `src/application/installation.ts` with
`LocalWorkflow.files`, the validated packaged `SkillCatalog`, and the distributed
generator version. Reusing that workspace preserves its execution-quiescence,
path-containment, private-state, and journal checks.

```ts
const installation = new SkillInstallation(workflow.files, catalog, version);
const preview = await installation.previewInstall(['copilot', 'codex']);
if (preview.state === 'ready' && preview.plan !== null) {
  // Present preview.changes and obtain trusted confirmation for preview.plan.request.
  // approval is the exact issued ApprovalReference, not a caller boolean.
  await installation.apply(preview.plan, approval);
}
```

The caller must narrow `preview.state === 'ready'` and `preview.plan !== null`
before the apply call. A preview is an untrusted request, not a permission grant.
Use the composed workflow's trusted confirmation channel; caller booleans cannot
stand in for an issued approval.

| Method | Contract |
| --- | --- |
| `inspect(hosts?)` | Read-only observations; defaults to all three source-format hosts and never initializes a workspace |
| `previewInstall(hosts, bootstrap?)` | All twelve operations for each explicit host; create only absent files without prior ownership, or no-op for current owned files |
| `previewUpdate(hosts)` | Refresh only installed, unchanged owned files from the current catalog/generator; an absent installation requires install |
| `previewRemove(hosts)` | Remove only the selected hosts' exact still-owned files, retaining other hosts and all unrelated files |
| `apply(plan, approval)` | Revalidate integration scope and canonical ownership, then use `LocalWorkspace.commit` |

Existing unowned content is always a conflict, even if its bytes happen to equal
the renderer's output.

Host arrays are nonempty, unique, and closed to `copilot`, `codex`, and `claude`.
Selection is explicit for every mutation preview. They map to
`.github/skills/missionspec-<operation>/SKILL.md`,
`.agents/skills/missionspec-<operation>/SKILL.md`, and
`.claude/skills/missionspec-<operation>/SKILL.md` respectively. There are twelve
files per selected host, not a primary-only installation profile. There are no
global hooks, whole-directory replacement, host configuration rewrites, or
upstream executable dependencies.

## Exact previews and conflicts

Previews return `ready`, `unchanged`, or `conflicted`. A ready preview contains a
revision-bound `FilePlan` and exact before/after text, SHA-256 digests, and a
whole-file unified diff for every mutation, including the ownership record and
any explicitly composed bootstrap effects. The displayed diff is intentionally
not a minimal-edit algorithm.

Unowned files, modified owned files, and missing previously owned files are
conflicts. An install encountering outdated owned files requests update instead.
A conflicting selected host set has no applicable plan; no subset is silently
applied. User edits and stale ownership remain untouched. There is no force,
automatic adoption, lost-file resurrection, or ownership-forgetting shortcut.
Resolve the discrepancy deliberately before previewing again, or select
unaffected hosts. Unselected hosts are neither changed nor reconciled.

Repeated current install/update, or removal of already-absent files, yields
`unchanged`, `plan: null`, and no writes—not even timestamp, ownership, log,
approval, or journal refreshes. Inspection also has no persistent effects.

## Ownership and revisions

`.missionspec/installation.json` is a closed version-1 record containing:

- `owner: "@msn-control/missionspec"` and the exact workspace/root binding;
- one unique entry per owned host/operation and canonical path;
- `digest`, the actual last generated/owned UTF-8 byte digest;
- `sourceRevision`, the canonical operation body digest;
- `templateRevision`, the digest of catalog schema version, rendering metadata,
  and that operation's metadata;
- `generatorVersion`, the distributed semantic version identifying renderer code;
- `catalogRevision`, the validated entire-catalog revision.

The template revision describes template inputs, not a claim that the executable
renderer was independently attested. Renderer implementation changes require the
corresponding generator-version change. Per-entry provenance permits one selected
host to update while others retain an older known generation.

Unknown versions/owners/fields, duplicate ownership, noncanonical paths, malformed
digests, and foreign workspace bindings fail closed; they are never migrated or
merged blindly. The record owns whole generated files, not unrelated config keys
or other consumers' files. Empty ownership records are retained after removal;
directories and runtime history are never broadly deleted.

## Authorization, bootstrap and interruption

Installation plans use operation `onboard`, approval purpose `integration`, and
configuration file effects. The workspace adapter explicitly permits the single
internal ownership destination only for this combination. The installer does
not bypass protected runtime paths or write metadata outside reviewed file
transactions.

For a new workspace, explicitly obtain `LocalWorkflow.previewSetup()` and pass
that plan to `previewInstall(hosts, bootstrap)`. The combined plan retains its
prospective identity and setup guards. It needs a **new confirmation of the
combined effects**; approving setup alone does not approve installation.
Inspection never creates an identity, and arbitrary bootstrap writes are rejected.

All selected projections and ownership updates use the existing prepared journal,
local lock, freshness checks, authority rechecks, and durable receipt. This is
recoverable multi-file execution, **not an atomic directory installation**.
Ownership is written after skill mutations. Failure after journal preparation is
reported as outcome unknown; pending transactions block new installation plans.
Partial files may therefore appear unowned during inspection, accompanied by the
pending transaction IDs.

Review `LocalWorkspace.recoveryPlan(transactionId)`, obtain current confirmation,
and use `LocalWorkspace.recover(transactionId, approval)`. Already-applied exact
effects are not repeated. New user edits block recovery instead of being
overwritten. Never erase a journal or lock merely to retry.

## Qualification and limitations

Results report `sourceFormat: "supported"` and
`runtimeQualification: "not-established"`. Generated, installed, discoverable,
invoked, permission-approved, executed, and verified are separate milestones.
The installer neither probes a live host nor upgrades any of these claims.

Current writes inherit the workspace adapter's qualified POSIX local-filesystem
restrictions, ownership checks, no-link policy, transaction size limits, and
recovery limitations. Windows native file effects remain unavailable until that
adapter is qualified. Filesystem/authority fixture tests are not demonstrations
of live-host behavior or model compliance.

`tests/installation.test.mjs` exercises actual local repositories, all 36 files,
selected subsets, no-write queries and repeated operations, drift and unowned
collisions, generator/source updates, exact removal, bootstrap authority,
interruption/recovery, stale previews, and symlink/hard-link refusal without
model or host execution.
