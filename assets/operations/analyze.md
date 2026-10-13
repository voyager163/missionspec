# Analyze planning quality

Use `{{invocation}}` for a read-only consistency, coverage, and
requirements-quality review. Analysis examines the plan; it does not execute the
project or approve it.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts
when available. Respect the current workspace/worktree and user edits. Skills
and allowed-tools metadata never grant authority. Use only advertised runtime
capabilities. If deterministic analysis is unavailable, report `missing-runtime`
for that capability; a manual semantic review may continue but must not claim
engine validation. Missing capture capability blocks report writes.

## Workflow

1. Resolve the explicit change and snapshot the relevant document identities and
   revisions: optional principles, proposal, declared capability deltas, design,
   tasks, and the pinned workflow. Read declared dependencies. Report missing
   documents; do not create them merely to obtain a complete review set.
2. Use available deterministic validation for unique stable IDs, typed
   references, required sections, delta declarations, dependency cycles, and
   declared output coverage. Cite diagnostics as structural findings only when
   the engine actually returned them.
3. Map requirements/scenarios to tasks and planned checks. Identify uncovered
   behavior, orphan tasks, missing checks, duplicate check definitions, and
   unsupported not-applicable claims. Planned verification normally belongs in
   `tasks.md`; the analysis must not invent a second canonical check plan.
4. Review clarity, testability, consistency, constraints, and design alignment.
   Separate semantic judgments from deterministic findings. Every finding
   carries affected stable IDs, source references, relevant input revisions,
   rationale, severity, and a proposed next action.
5. Explain uncertainty and competing interpretations rather than treating
   plausible language as proof. A report based on old input revisions cannot
   clear a newly edited graph.
6. Return the report in conversation by default. If a report or quality checklist
   is requested as a file, require explicit capture scope and destination,
   preserve existing reviewer content, and use the available authorized capture
   contract. Introduce no mandatory checklist directory or new lifecycle stage.

## Stop boundary

Do not run project tests or any project-code execution. Do not install
dependencies, fix artifacts, edit source, create missing plan files, or grant
authority. Never auto-check or approve reviewer-owned checklist items.
Requirements-quality checklists are not executed-test evidence and cannot prove
implementation correctness. Suggested remediation is not permission to apply it.

## Report and handoff

Report `state`, `change`, `input-revisions`, `structural-findings`,
`semantic-findings`, `coverage`, `quality-findings`, `uncertainty`,
`proposed-remediation`, and `effects` (none unless explicit report capture).
Distinguish unavailable analysis from a clean report.
Offer stable handoff IDs: `clarify`, `revise`, `draft`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. No banners or child output may
contaminate stdout. This operation emits no telemetry, including explicit
report capture. Read-only analysis creates no log files, ledger rows, or
telemetry preferences. Never send source, specs, prompts, raw errors, arguments,
paths, or tool output as telemetry.
