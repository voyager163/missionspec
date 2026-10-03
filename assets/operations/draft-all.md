# Draft the remaining prerequisites

Use `{{invocation}}` to prepare the remaining required artifact dependency
closure for a selected change. This batches drafting, not approval or execution.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Preserve the current workspace/worktree and user edits. Skills and allowed-tools
metadata never grant authority. Use only advertised runtime capabilities; if
the scheduler, authoring, or validation operation is absent, report
`missing-runtime` with the needed capability and stop. Do not write a substitute
workflow or claim that planned commands already exist.

## Workflow

1. Resolve the explicit stable change identity and requested scope. Creation
   requires a separate explicit creation scope and the advertised change-new
   capability; resuming an existing change must not recreate it. Ambiguous
   change selection is a blocker, not a reason to pick the newest directory.
2. Read status and core instructions for the pinned workflow. Standard is the
   default; Compact is explicit opt-in. Obtain the required prerequisite closure
   from the same scheduler used by `draft`. Do not assume a fixed proposal,
   design, specs, tasks ordering when the graph allows alternatives.
3. Preview required nodes, dependencies, declared output sets, current/stale
   artifacts, and review gates. Reuse current valid artifacts. Preserve user
   edits and explain proposed material revisions rather than overwriting
   everything to make the batch uniform.
4. For each eligible node, read its current authoritative dependency documents,
   confirm the output set, and draft within the authorized closure scope. A
   declared multi-file specs set remains one artifact. Use the same focused
   clarification, task breakdown, and consistency services as `draft`; batching
   cannot bypass a quality check.
5. Link requirements and scenarios to meaningful stable task IDs and planned
   check IDs. Define checks canonically in `tasks.md`, or explicitly link an
   expanded verification plan when declared. A checked box is a claim, not
   evidence that the check ran.
6. Validate each node before advancing. Re-read dependency digests at the next
   step; drift, invalid graphs, missing coverage, unqualified checks, and
   unresolved conflicts remain blockers. Stop for material questions or required
   human review instead of inventing answers to finish the batch.
7. Record optional omissions with a reason and relevant source revision through
   the workflow contract. A docs-only/no-behavior-change route can omit deltas
   only through an explicit validated applicability declaration; it still needs
   scoped tasks and appropriate planned checks.
8. Recompute closure readiness and present the result. Distinguish deterministic
   validation from semantic assessment and unverified assumptions.

## Stop boundary

Stop when the required prerequisite closure is prepared, or earlier at a
blocker/review gate. Do not continue to optional artifacts merely to fill a
directory. The destination is ready for implementation review, not execution
approval. Do not install dependencies, run project tests, edit source, or begin
implementation. Requirements-quality checklists are not test evidence.

## Report and handoff

Report `state`, `change`, `workflow-revision`, `completed-nodes`,
`reused-nodes`, `omitted-nodes` with reasons, `dependency-revisions`, `effects`,
`validation-findings`, `blockers`, and `remaining-nodes`. Preserve partial
progress truthfully: an interrupted batch is not complete preparation.
Offer stable handoff IDs: `draft`, `clarify`, `revise`, `analyze`, `implement`.
Do not invoke `implement` without its separate request and current grant.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. No banners or child output go to
stdout. A centrally eligible stateful top-level outcome may produce at most one
aggregate after disclosure, opt-out checks, and backend qualification, never one
event per node or nested probe. This skill never sends telemetry itself.
Read-only queries create no telemetry or log files. Never send source, specs,
prompts, raw errors, arguments, paths, or tool output as telemetry.
