# Structured Markdown and artifact readiness, version 1

This local MSR03 foundation implements **pure parsing and structural readiness**.
It accepts supplied strings/snapshots and returns immutable values or controlled
diagnostics. It does not read files, run checks, issue approvals, execute tasks,
call a model, synchronize specs or persist runtime state.

The implementation is original MissionSpec code and examples. Markdown is the
canonical editable document: there is no separately editable JSON mirror of
requirements, task definitions or planned checks. The separate
[local runtime layer](local-runtime.md) now collects live project files and
coordinates reviewed capture, evidence review, promotion and closure.

## Public entry points

The specification contract exports:

- `parseMarkdownDocument({ path, content })`: parse one document's syntax and
  declarations. `parsed` does not claim external references have been resolved.
- `parseMarkdownSet(sources)`: parse a supplied set, reject duplicate document
  paths/identities and fact identities, resolve typed references, reject mixed
  changes and task cycles. Its invalid result includes diagnostics and explicitly
  named `parsedDocuments`, not a valid partial change.

The planning contract exports:

- `parseWorkflowProfile(value?)`: Standard by default; Compact only explicitly.
- `parseArtifactWorkflow(yamlSource)`: validate a versioned built-in workflow.
- `artifactDependencyClosure(yamlSource, targets?)`: compute a deterministic
  topological dependency closure.
- `notApplicableArtifactRevision(...)`: identity of an explicit skip decision.
- `assessArtifactReadiness(request)`: validate supplied snapshots and report
  readiness, required/remaining closure and next-node selection.

These exports live in the public specification/planning `contracts.ts` files.
They do not import adapters, application workflows or CLI code. YAML and
CommonMark parsing only construct data; no frontmatter, declaration or fenced
code is executed.

## Document envelope

Start at the first character with a YAML frontmatter block:

```markdown
---
schemaVersion: 1
id: ART-filter-spec
kind: specs
changeId: CHG-remember-filter
---
# Saved filters

## Requirements

### REQ-filter: Restore a saved filter

```

The example above shows the envelope and headings; a real requirement also
needs its declaration metadata and prose, shown below.

Frontmatter permits `schemaVersion`, `id`, `kind`, and `changeId`, plus the
tasks-only optional `checks: verification.md` declaration.
`schemaVersion` must parse to the integer `1`. `id` uses the existing validated
`ART-` identity grammar. Supported kinds are `proposal`, `specs`, `design`,
`tasks`, `verification`, `discovery`, `principles` and project `baseline`.

Every change document requires a `CHG-` change identity. Project-wide
`principles` and accepted `baseline` documents must omit `changeId`; supplying a
change ID there is rejected.
The supplied source path must be a safe project-relative path, validated with
the kernel's portable path rules. Parsing never claims that this path exists.

Each document has its own stable frontmatter identity. A workflow snapshot has
a separate logical artifact identity that groups its exact output set; the
multi-file specs node is still **one workflow artifact**, not one draft per
file. The caller supplies that grouping explicitly rather than inferring it
from directory discovery or a document title.

Unknown fields/kinds/versions, duplicate YAML keys, explicit tags, anchors and
aliases are rejected. A small closed grammar is intentional: `approved`,
`completed`, command-execution switches and extension fields are not silently
accepted. YAML parse errors are translated to controlled messages, without
echoing rejected keys, scalar values or parser source snippets.

Documents are limited to 1,000,000 characters. LF and CRLF are supported and
remain distinct raw revisions. There must be exactly one level-one ATX title.
Use a single space after the heading prefix; setext headings are not supported.

## Sections

Sections are level-two headings with exact, case-sensitive names. Required
sections cannot be empty. Every section name may occur only once.

| Kind | Required sections | Optional sections |
| --- | --- | --- |
| `proposal` | Problem, Outcome, Scope, Acceptance | Notes |
| `specs` | Requirements | Notes |
| `baseline` | Requirements | Notes |
| `design` | Approach, Risks | Notes |
| `tasks` | Tasks, Checks | Design, Notes |
| `verification` | Checks | Notes |
| `discovery` | Findings, Questions | Notes |
| `principles` | Principles | Notes |

Requirements, Tasks and Checks sections need at least one correctly typed
declaration. The explicit tasks-only `checks: verification.md` form instead
allows Checks prose pointing to the sibling verification document; full-set
validation requires that sibling with its canonical check declarations.
No arbitrary path or implicit external-file discovery is permitted.
Narrative sections may contain ordinary Markdown, subsections,
links, lists and code examples. Prose is retained exactly, including comments
and formatting; the parser does not summarize or semantically verify it.

Only top-level document headings declare facts. Headings shown inside ordinary
code fences or quoted examples are prose, not hidden declarations.

## Typed declarations

A declaration is a level-three heading containing a stable ID and title,
immediately followed by one `missionspec` YAML fence, then nonempty Markdown
prose. Another level-three or level-two heading ends that prose.

Metadata is attached to exactly one definition. IDs are not duplicated in
metadata, inferred from titles, or regenerated on rename.

### Requirements and scenarios

````markdown
## Requirements

### REQ-filter: Restore a saved filter

```missionspec
operation: add
```

Restore a supported saved filter key. An unknown key uses the default filter.

### SCN-filter-reload: Reload after selecting a filter

```missionspec
operation: add
requirement: REQ-filter
```

Given a supported selected filter, when the list reloads, then that filter
is restored without changing permission checks.
````

Requirement metadata has only `operation`. Scenario metadata has `operation`
and its typed `requirement` reference. Operations are explicitly `add`, `modify`
or `remove`; omission never means deletion. Every removal retains prose
explaining the change. An active fact cannot reference a removed definition.
A removed scenario may name its removed requirement.

These declarations do not establish whether a baseline actually contains the
identity being modified or removed. The separate local promotion implementation
performs that comparison. A `baseline` document represents retained facts:
requirement metadata is `{}`, scenario metadata has only `requirement`, and no
`operation` or change identity is allowed. The parser exposes their derived
operation as `retain`. Baseline and change documents are validated as separate
canonical sets, not concatenated mirrors of the same identities.

### Tasks and planned checks

````markdown
## Tasks

### [ ] TSK-filter: Store and restore the selected filter

```missionspec
dependsOn: []
requirements: [REQ-filter]
scenarios: [SCN-filter-reload]
checks: [CHK-filter]
writeScope: [src/filter-preference.ts, tests/filter-preference.test.ts]
```

Implement validated restoration and preserve the existing permission checks.

## Checks

### CHK-filter: Check restoration and fallback

```missionspec
method: executed
requirements: [REQ-filter]
scenarios: [SCN-filter-reload]
```

With separate verification authorization, run the scoped preference checks.
Retain actual observations outside this Markdown plan.
````

All five task metadata fields above are required arrays, including explicit
empty arrays where no reference applies. References must have the appropriate
`TSK-`, `REQ-`, `SCN-` or `CHK-` prefix, contain no duplicates and resolve in the
supplied document set. Write scope contains exact portable paths, not globs,
absolute paths or traversal. The parser rejects self-links and the set validator
rejects dangling task dependencies and cycles.

A check definition has only `method`, `requirements` and `scenarios`. Methods
are `executed`, `static-inspection` and `agent-review`. The first means a
**planned execution method**, not a result. Definition prose does not become a
shell command. Executable check qualification and evidence collection require
separate runtime contracts and authorization.

Define a check once, then reference its ID. Duplicate check definitions across
`tasks` and `verification` documents are invalid. This version's built-in
readiness graph uses the normal `tasks.md` check location; optional expanded
verification documents can be parsed as supplied document sets, but scheduling
them as extra outputs/nodes is outside this built-in graph version.

Every definition has a path, line, column and character offset for actionable
diagnostics. Validation messages use controlled text; they do not dump rejected
YAML, document prose or secrets. A validated source path is present in local
diagnostics, so diagnostics are not a remote telemetry payload.

## Progress claims and revision identity

Only task headings accept `[ ]`, `[x]` or `[X]`. They produce an
`unchecked`/`checked` **progress claim**. No boolean execution fact, successful
attempt, approval or acceptance is created.

Each parsed document exposes:

- `source`: the complete original string;
- `rawRevision`: SHA-256 of the exact supplied UTF-8 content;
- `intentRevision`: SHA-256 of that same content with only recognized
  task-heading marker characters normalized to a space.

Each declaration likewise exposes its intent identity and exact prose.
Changing a task heading from unchecked to checked changes the raw revision but
not intent identity. Every other byte remains relevant, including arbitrary
prose, metadata, titles, comments, examples, formatting and line endings.
Checkboxes in prose or ordinary code examples are **not** normalized.

The existing artifact snapshot contract continues to bind **raw** file
revisions and frozen dependency revisions. Readiness therefore conservatively
notices all upstream byte changes. It does not substitute an intent digest for
a previously approved revision. Choosing intent identities for a future
authority/evidence policy requires an explicit application decision, not a
silent parser shortcut.

## Original workflows and examples

The authored workflow declarations and complete examples are:

- [Standard workflow](../../assets/workflows/standard/workflow.yaml):
  [proposal](../../assets/workflows/standard/examples/proposal.md),
  [filter spec](../../assets/workflows/standard/examples/specs/filters.md),
  [reset spec](../../assets/workflows/standard/examples/specs/reset.md),
  [design](../../assets/workflows/standard/examples/design.md),
  [tasks and checks](../../assets/workflows/standard/examples/tasks.md).
- [Compact workflow](../../assets/workflows/compact/workflow.yaml):
  [proposal](../../assets/workflows/compact/examples/proposal.md),
  [spec](../../assets/workflows/compact/examples/specs/summary.md),
  [combined design/tasks/checks](../../assets/workflows/compact/examples/tasks.md).

Both workflow schema-version-1 declarations use:

```text
             +-> specs --+
proposal ----|           +-> tasks
             +-> design -+
```

Standard is the default profile. Compact is explicit and requires a `Design`
section in tasks for its combined documentation. Compact does not automatically
skip design, remove prerequisites, waive identity validation or grant effects.
The separate design node can be skipped in either profile only with an explicit
nonempty reason, a source revision and its frozen predecessor revisions.

The workflow parser rejects unknown fields, duplicate nodes/dependencies,
missing dependencies, cycles, unknown targets and attempts to weaken this
built-in DAG. This version is not a general workflow-extension language.
Proposal, specs and tasks remain required. A docs-only no-delta applicability
declaration and custom nodes require a later schema extension, not a guessed
empty specs set.

## Supplied-snapshot readiness

The readiness request contains:

1. The selected `changeId`.
2. The workflow YAML source and its `expectedWorkflow` digest, pinned by the
   caller. A mismatch is rejected, not adopted as a workflow upgrade.
3. A caller-supplied `sourceRevision` against which applicability was reviewed.
4. One binding per workflow node: logical `artifactId`, exact `declaredOutputs`
   and applicability.
5. Zero or one captured `ArtifactSnapshot` per node, with content, digests and
   exact frozen dependency identities/revisions.
6. Optional targets and an explicit next-artifact selector.

This function never discovers files or assumes current filesystem facts.
Paths and artifact identities must be unique across bindings. A single-output
node needs one exact output. `specs` needs its **entire nonempty declared set**;
one matching file or a wildcard cannot establish readiness. Unexpected outputs,
wrong document kinds and documents belonging to another change are blocked.
Snapshot content hashes and aggregate revisions are independently recomputed.
The `task-set` output mode requires `tasks.md` and optionally its declared sibling
`verification.md`, as one captured artifact. Both files share the task artifact's
dependencies and invalidation. The default remains checks inside tasks.

For a skip, `notApplicableArtifactRevision` hashes the node, logical artifact
ID, reason, relevant source revision, exact predecessor revisions and pinned
workflow revision. A downstream
snapshot records that digest just as it records an authored predecessor's
revision. This makes applicability changes visible without inventing a file.
Skipped content cannot also be supplied. Changed source or proposal revisions
make the skip stale, even when no design file exists. The digest is a pure
decision identity, not proof of human approval.

Assessments distinguish:

| State | Meaning |
| --- | --- |
| `missing` | A required snapshot is absent and its predecessors are current |
| `valid` | The supplied content, exact outputs, references and dependency revisions pass structural checks |
| `stale` | A supplied predecessor revision or applicability source changed |
| `not-applicable` | An allowed explicit skip matches the supplied source |
| `blocked` | Invalid content/identity/output/dependency declaration, conflicting skip, or unavailable predecessor |

Staleness propagates to descendants. Missing or invalid predecessor content
blocks dependent drafts. Missing dependency records do not reconstruct
historical freshness. Editing a valid proposal leaves that proposal structurally
valid but makes prepared specs/design stale, then affects tasks.

`requiredClosure` lists active required nodes in dependency order;
`remainingClosure` excludes those already structurally valid. An eligible
missing/stale node can be a next draft/review candidate. If multiple independent
nodes are eligible, `next` returns `selection-required` with deterministic
candidates rather than silently picking one. An explicit selector never
bypasses dependencies or repairs malformed content. `all-current` means only
the requested structural closure is current.

None of these states is approval, task execution, successful verification,
semantic correctness, complete requirement coverage or implementation
acceptance. There is no automatic regeneration or permission to overwrite
existing edits. The local application now supplies filesystem observation, typed coverage,
durable execution admission and conservative baseline promotion separately from
these pure functions. The local terminal adapter now supports explicit reviewed
approval issuance; registered local checks collect actual subprocess evidence.
Native coding-host qualification remains unavailable. See the
[local runtime reference](local-runtime.md) for assurance and confinement limits.
