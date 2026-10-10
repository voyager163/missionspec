# Draft one next artifact

Use `{{invocation}}` for one incremental drafting step. The unit is one declared
workflow node, not one file and not the whole plan.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Respect the selected workspace/worktree and existing user edits. Skills and
allowed-tools metadata never grant authority. Use only advertised runtime
capabilities. If the operation, scheduler, or validation capability is absent,
report `missing-runtime`, name what is needed, and stop without fabricating
readiness or writing an engine substitute.

## Workflow

1. Resolve the stable change identity from an explicit selection. A new change
   needs an explicit creation request and scope; use only the advertised
   change-new API for minimal metadata. Do not infer selection from timestamps
   or silently initialize a project.
2. Read status and instructions for the pinned workflow. Standard is the
   default; Compact requires explicit selection and does not weaken authority
   or evidence rules. Load the node's canonical template, declared outputs,
   dependency IDs, and current dependency revisions from the core, not a
   hardcoded sequence in this skill.
3. Select exactly one next ready artifact. A validated artifact selector may
   choose among eligible nodes but cannot bypass dependencies. If independent
   nodes or changes remain ambiguous, stop for selection. If every draft is
   current, report that condition and stop.
4. Read all declared dependency documents before authoring. Preview the complete
   output set. A `specs` node may write several declared capability-delta files;
   that entire specs set is one artifact. It must not also produce design or
   tasks in this invocation. Missing change metadata is scaffolding, not a
   second authored artifact.
5. Draft only the selected node within its authorized artifact scope. For a
   proposal, cover the problem, intended outcome, scope/non-goals, affected
   capabilities, constraints, assumptions, and acceptance outline. For deltas,
   preserve stable requirement/scenario IDs and make additions, modifications,
   and removals explicit. Do not infer deletion from omitted prose.
6. For tasks, use planning-engine breakdown: meaningful outcomes, stable task
   IDs, typed dependencies, requirement/scenario links, and planned check IDs
   with one canonical definition each. Keep task definitions in `tasks.md`,
   not a second editable JSON graph. Checkbox state is not executed evidence.
7. Stop on material ambiguity and use focused clarification. Label minor
   assumptions for review. Preserve existing valid work; route a requested
   revision of an already authored artifact to `revise`.
8. Validate the selected output set and rerun structural consistency and
   coverage analysis against its current dependencies. Distinguish deterministic
   diagnostics from semantic judgments. Missing coverage, cycles, or changed
   dependency digests block readiness; file existence alone does not clear them.

## Stop boundary

Stop after one artifact, even when another node is obviously next. Report at most
ready for implementation review, never approved or implemented. Do not install
dependencies, run project tests, edit product source, or start implementation.
A requirements-quality checklist is planning review, not test evidence or
approval. Any additional effect requires a separate authorized scope.

## Report and handoff

Report `state`, `change`, `workflow-revision`, `artifact`, `declared-outputs`,
`dependency-revisions`, `effects`, `validation-findings`, `assumptions`,
`blockers`, and `next-ready-nodes`. On failure, identify incomplete outputs and
their validation state without marking the node ready. Offer stable handoff IDs
only as choices: `draft`, `draft-all`, `clarify`, `revise`, `analyze`, `implement`.
The last requires a separate implementation request and current grant.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Keep banners and child output off
stdout. Only a centrally eligible stateful top-level outcome may produce one
aggregate after disclosure, opt-out checks, and backend qualification; this
skill never sends telemetry itself. Nested status/instructions/validation and
read-only previews create no telemetry or log files. Never send source, specs,
prompts, raw errors, arguments, paths, or tool output as telemetry.
