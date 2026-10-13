# Define project principles

Use `{{invocation}}` to propose or amend MissionSpec's optional project-wide
constraints in `missionspec/principles.md`. This document is not Mission Context
and does not configure an external provider.

## Readiness and authority

Read the current workspace instructions, existing canonical project principles,
and authoritative core instructions and engine result contracts. Preserve the
selected workspace/worktree and user edits. Skills and allowed-tools metadata
never grant authority. Use only advertised runtime capabilities. If document
revision, impact analysis, or required invalidation is absent, report
`missing-runtime` and the needed capability; discuss the proposed wording
without applying an untracked substitute.

## Workflow

1. Confirm that the request is project-wide policy authoring, not merely reading
   rules or deciding one change's design. Read the existing optional document
   and relevant active changes before proposing constraints.
2. Establish explicit document scope and intended outcomes. Write concrete,
   reviewable constraints with rationale and applicability. Distinguish durable
   rules, preferences, and unresolved questions; avoid turning a suggestion into
   an unconditional mandate.
3. Preview a scoped patch to the canonical principles document, including
   creation only when explicitly requested. Preserve unrelated content. Do not
   create a principles file simply because it is absent.
4. Analyze the impact on active changes and their saved requirements/design/task
   revisions. Explain conflicts and re-review needs without silently rewriting
   those artifacts or changing approved success criteria.
5. Obtain explicit review of the project-wide patch, recheck freshness, and
   apply it through the specification contract. Preserve historical revisions.
   Flag affected changes for re-review and use the engine's applicable
   invalidation rules for downstream readiness, grants, and evidence.
6. Confirm the resulting document revision and remaining impact decisions.
   References to canonical principles are preferable to copied or automatically
   propagated instruction text.

## Stop boundary

Principles grant no runtime permissions and cannot expand execution grants.
Do not edit code, run project tests, install or invoke Mission Context, or
blindly rewrite shared templates, generated skills, or host configuration.
Project-wide policy edits are not acceptance of an individual change. Follow-up
document changes require their own reviewed scope.

## Report and handoff

Report `state`, `document`, `old-revision`, `new-revision`, `principles-patch`,
`effects`, `affected-changes`, `conflicts`, `invalidation`, and `review-needed`.
Distinguish a proposed patch from an applied revision and an unresolved impact
from completed re-review.
Offer stable handoff IDs: `analyze`, `revise`, `discover`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Keep banners and child output off
stdout. This skill never sends telemetry itself. Only a centrally eligible
stateful top-level outcome may yield one aggregate after disclosure, opt-out
checks, and backend qualification. Read-only previews and nested probes emit
none and create no log files. Never send source, specs, prompts, raw errors,
arguments, paths, or tool output as telemetry.
