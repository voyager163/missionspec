# Explicit adoption and optional context consumption

These are bounded, callable local application services. They do not install
another product, invoke a model, index sources, migrate an existing directory,
create Git branches or manufacture approval/evidence. CLI and MCP transports
can call the same services without implementing another importer.

## Adoption entry point

`src/application/import.ts` exports `AdoptionService`, composed with the existing
`LocalWorkflow` instance:

```typescript
const adoption = new AdoptionService(workflow);
const preview = await adoption.preview(input);
const confirmation = await adoption.confirm(preview);
if (confirmation.status === 'ok' && confirmation.value.state === 'issued') {
  await adoption.apply(preview, confirmation.value.approval.reference);
}
```

A declined or unavailable confirmation stops the flow. There is no `approved`
boolean, imported approval parser or model-text authority shortcut.

`preview` accepts a closed object:

| Field | Meaning |
| --- | --- |
| `slug` | Explicit new, safe flat MissionSpec change name |
| `id` | Optional explicit `CHG-` identity; required in practice when supplying already-authored native documents |
| `profile` | Optional explicit Standard/Compact selection; otherwise preserve the project's configured default |
| `specs` | Complete selected capability-name set for the new change |
| `sourcePaths` | Optional exact implementation-source observation scope for the new change |
| `verificationPlan` | Optional explicit boolean declaring expanded `verification.md` with tasks |
| `sources` | Nonempty supplied upstream document set, described below |
| `artifacts` | Optional complete, independently authored native Markdown closure |
| `mappings` | Explicit typed source-span mapping for every native fact, if artifacts are supplied |

Each source has `{ id, system, path, content }`:

- `id` is a unique safe lowercase source label.
- `system` is exactly `openspec` or `spec-kit`.
- OpenSpec documents are explicitly selected `.md` files under `openspec/`.
- Spec Kit documents are explicitly selected `.md` files under `.specify/` or
  `specs/`.
- `content` is the complete supplied UTF-8 text, not a summary or template.

The source must already exist in the selected workspace and match the supplied
bytes. This is not a URL downloader or arbitrary external-root reader. Paths
are checked by the existing root-confined filesystem adapter, including its
symlink/special-file restrictions. There is no recursive autodiscovery.

Up to 32 source documents may be supplied, each at most 500,000 UTF-8 bytes,
with at most 2,000,000 bytes across source and native documents. The shared
`FilePlan` transaction bounds also apply.

## Default: provenance, not reconstructed truth

Without native `artifacts`, the reviewed plan creates only new-change metadata
and:

```text
missionspec/changes/<new-slug>/imports/
  provenance.json
  sources/<explicit-source-id>.md
```

Source copies preserve the supplied bytes, including line endings. The
provenance manifest records:

- format version and new change identity;
- upstream system, original path, capture path, SHA-256 digest and UTF-8 size;
- any explicit mapping and the hashes of separately supplied native artifacts;
- explicit `untrusted-source-material`,
  `not-imported-as-authority-or-evidence` and
  `not-established-by-copying` labels.

The manifest is provenance, not a second editable requirement/task definition.
Legacy checkboxes, success narratives and approval sentences remain ordinary
untrusted text in those copies. They do not become captured workflow artifacts,
executed checks, accepted results or runtime approvals. All workflow nodes
remain uncaptured, so the ordinary next step is to draft the proposal.

Import does not claim source licensing clearance. The user must review their
right to copy supplied material and preserve required notices. No upstream
implementation, template repository or community plugin is fetched or bundled
by this service; tests use original MissionSpec-authored fixtures.

## Optional explicitly mapped native closure

Mechanical conversion cannot safely discover stable requirement/task identity,
intent, evidence or acceptance. Consequently, the importer never guesses IDs,
rewrites old headings into requirements, or turns source checkboxes into native
completion claims.

For an initially structurally ready change, the caller must instead supply:

1. A complete native Markdown document set at **exactly** the new change's
   declared output paths. This includes the entire multi-file specs set.
2. A mapping for every requirement, scenario, task and check declaration:

   ```json
   {
     "sourceId": "legacy-tasks",
     "startLine": 3,
     "endLine": 5,
     "kind": "task",
     "targetId": "TSK-filter"
   }
   ```

3. Explicit review of that complete artifact/mapping write plan through the
   existing genuine authority channel.

Line ranges are one-based, inclusive and checked against the exact supplied
source. They must contain material, reference a known source and match the
target identity's type. Every native fact must have exactly one mapping; extra,
missing and duplicate target mappings are rejected. All native documents must
refer to the explicit new change, pass native syntax/reference validation, and
cover the declared Standard/Compact closure. Native task markers must begin
unchecked.

The service validates structure and mapping completeness, not semantic
equivalence between the two documents. The human reviews that relationship.
It calculates captured snapshot/dependency records using the existing artifact
contracts; it does not synthesize a second task graph. Compact's separate
design skip is not inferred during adoption: a complete supplied closure
includes design, with the combined task Design section still required.

Structurally current artifacts are not implemented, verified or accepted.
Implementation and verification retain their own revision-bound authority.
The provenance manifest remains untrusted editable project data even after
capture; a fresh clone must never reconstruct trusted approval from it.

## Exact review, drift and non-destructive application

The serialized `AdoptionPreview` contains the original new-change `creation`
plan, normalized `material`, displayed mode and final `plan`. Its `FilePlan`
shows every exact path, expected absence, complete proposed content and digest.
Authority uses the existing `onboard` / `artifact-edit` scope; this does not
register a thirteenth native skill.

Before confirmation and application, the service:

- revalidates the closed preview rather than trusting labels or arbitrary file
  mutations;
- verifies that the destination is still a new change and its identity is
  unused, including the normal archive identity check;
- reobserves upstream bytes, selected source files, project/workspace identity,
  accepted baseline guards and the pinned workflow;
- rebuilds the same deterministic capture from the retained metadata seed and
  rejects a changed plan digest.

The final transaction includes original-source guards and absent-target guards.
It reuses `LocalWorkflow.apply`, so genuine approval checks, execution-quiescence
checks, the local writer lock, durable journal, prewrite drift checks and
explicit partial-failure recovery are shared with other local effects.
Change metadata is written last. A partially completed transaction must be
recovered through the existing journal; it is not retried as a fresh import.

All writes are inside the new MissionSpec change. Existing `openspec/`,
`.specify/`, `specs/`, host files, project default profile, baseline specs and
source code are preserved. Unexpected existing destination content is refused,
not merged or overwritten. Reapplying an already committed new-change preview
is a collision, not an idempotent overwrite.

The source guards protect the explicitly selected source files; they are not a
claim of atomic observation of every file in the entire upstream repository.
The filesystem adapter's documented concurrent-editor and platform limitations
remain applicable.

## Optional context entry point

`src/application/context.ts` exports:

```typescript
new ContextService(workflow, authority, providerOrNull, {
  enabled: false,
  processing: 'local-only'
});
```

Composition must explicitly declare whether an injected provider adapter uses
local-only or remote processing. This declaration is an adapter obligation,
not a claim that an arbitrary external program is sandboxed or qualified.
No real Mission Context adapter, installer, index, storage, migration,
enrichment job or background model is supplied here.

Methods:

| Method | Behavior |
| --- | --- |
| `inspect()` | Explicit absent/disabled/partial/available/incompatible/unavailable capability result |
| `preview({ query, paths, allowRemoteProcessing })` | Read-only exact consumption scope, or `not-ready` with availability |
| `confirm(readyPreview)` | Ask the injected genuine authority channel to review that exact request |
| `consume(readyPreview, approval)` | Reobserve scope, resolve approval, then query the configured provider once |

Absent and disabled paths do not call the provider or create state.
Compatibility inspection must be metadata-only: it receives no query, file
contents or workspace scope. Query consumption requires adapter contract
version 1 and the `search` capability. Missing/incompatible context is not
replaced with fabricated findings or a hidden fallback.

The request binds the exact query, native provider identity, capabilities,
processing declaration, workspace and observed source digests. Select at most
64 exact existing source files; no globs, traversal, runtime evidence or Git
metadata are permitted. A remote adapter cannot consume a local-only grant.
Installing/configuring a provider or passing a consent-looking string is not
authority to export source, spend model tokens or index anything.

The provider receives only the approved query, exact source-scope paths and
approval reference through `ContextProviderPort.query`. Its adapter must honor
the admitted processing/effect scope; the port does not authorize enrichment,
index creation, arbitrary tool execution or additional data export.

Returned observations are closed, bounded records with
`trust: "untrusted-context"`, the expected provider ID, an exact text digest,
provenance reference and an explicit current/stale/unknown freshness claim.
Freshness is provider-reported, not implementation evidence or human approval.
Partial availability remains partial. Malformed responses, exceptions and
unavailable providers yield controlled unavailable diagnostics without raw
errors or automatic retries. Source drift during consumption is reported
instead of returning the observations as current.

The service stores no provider index, raw transcript or preference state.
Provider transport deadlines/cancellation and actual local/remote processing
qualification belong to the eventual adapter; no enforceable deadline or
network confinement is invented by this boundary.
