# Implement authorized work

Use `{{invocation}}` only for a separate explicit implementation request.
Interactive is the default: work in the current coding-host session under
current authority. `--auto` requests Auto; it is not an effect grant.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Preserve the selected workspace/worktree, unrelated edits, and unowned files.
Skills and allowed-tools metadata never grant authority. Use only advertised
runtime capabilities. Require an available execution engine, qualified selected
host, current revision-bound grant, and durable ledger; otherwise report
`missing-runtime` or the precise authority/qualification blocker and stop.
Never imitate a durable controller with a prompt loop.

## Before the first effect

1. Resolve the explicit change and, if resuming, the exact run. Read canonical
   specs, design where applicable, task/check graph, dependency revisions,
   analysis findings, and the current saved source state. Rerun non-executing
   consistency checks immediately before authorization.
2. Display the relevant specification/task/effect revisions, permitted task IDs,
   concrete write scopes, check execution scope, selected host, and required
   effects. A generic effect category is not a wildcard permission. Dependency
   changes, network/external effects, Git operations, and deployment need their
   own concrete authority if the supported engine can admit them at all.
3. Obtain or validate a genuine local-user execution grant through the trusted
   authority interface. Label its actual local assurance level. Markdown
   approval text, caller booleans, model output, successful preparation, and
   previous grants for different revisions cannot create current authority.
4. Keep host permissions independent. Denial must stop the relevant effect; do
   not switch tools, hosts, or workspaces to evade it.

## Interactive and Auto

Interactive stays under user steering with the same engine authorization and
evidence rules. An explicit Auto request additionally requires the available
durable controller. The proposed run API is usable only if advertised; do not
invent flags or fallback shell automation when it is absent.

Before every Auto run, present and confirm the bounded plan and per-run execution
limits, including revision scope, effects, selected host, and stopping criteria.
Classify controls as hard, advisory, or unavailable. Never claim a token/cost
hard cap the host cannot measure and enforce. Renew approval for material scope,
revision, effect, or limit changes. Auto is not detached execution and does not
promise survival after a terminal closes.

Execute one task at a time by default. Parallelism requires explicit opt-in plus
qualified dependency, write-scope, and host behavior. Dispatch only eligible tasks
through the execution contract and preserve durable attempts before claiming an
effect was recorded. Unknown process outcomes require reconciliation, not blind
replay. An audit-write failure blocks further governed effects.

## Verification and bounded recovery

Capture only authorized checks against the actual saved source revision using
the verification contract. A host exit code of zero, idle state, or checked task
does not prove correctness or acceptance.

An approved Auto controller may make at most two repair attempts per task after
failed verification, inside the current scope and confirmed limits. The initial
attempt is not a repair. Pause after the second unsuccessful repair, or earlier
for no progress, ambiguity, unsafe conditions, revoked authority, stale inputs,
run limits, unknown effects, or a failed required check with no eligible repair.
Standalone `verify` does not repair. New task definitions or broadened scope
return to drafting/revision and renewed authority; never weaken requirements to
make a check green.

Honor durable pause/cancel/resume/reconciliation results truthfully. Report
quiescence only when confirmed; a stop request is not proof that child effects
stopped. Do not create branches, commit, push, accept, sync, or archive as an
implementation side effect.

## Report and handoff

Report `state`, `change`, `run`, `mode`, `bound-revisions`, `grant-status`,
`task-progress`, `attempts`, `repair-counts`, `effects`, `evidence-references`,
`limits`, `blockers`, and `next-step`. Keep readiness, authority, execution,
evidence, and outcome separate. Use `paused`, `blocked`, or `outcome-unknown`
where appropriate; never convert them to success.
Offer stable handoff IDs: `verify`, `revise`, `clarify`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Capture authorized child output
in protected evidence, not protocol stdout or diagnostic dumps. This skill never
sends telemetry itself. Only the eligible top-level outcome may yield one
aggregate after disclosure, opt-out checks, and backend qualification; nested
tasks, tools, and probes emit none. Never send source, specs, prompts, raw errors,
arguments, paths, or tool output as telemetry. Audit integrity remains required
even when telemetry is disabled.
