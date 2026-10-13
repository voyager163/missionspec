# Clarify consequential ambiguities

Use `{{invocation}}` to resolve focused questions in an existing change.
Questions and answers can remain conversational; capture is separately scoped.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts
when available. Preserve the selected workspace/worktree and user edits. Skills
and allowed-tools metadata never grant authority. Use only advertised runtime
capabilities. If a required capture/revision capability is absent, report
`missing-runtime`, identify it, and retain answers in the conversation without
pretending to update artifacts, grants, or readiness.

## Workflow

1. Resolve the explicit change, existing artifact revisions, and ambiguity
   scope. Read relevant dependency documents and open findings before asking
   questions that the saved intent already answers.
2. Rank unknowns by their effect on observable behavior, scope, constraints,
   compatibility, or acceptance. Separate contradictions from missing details.
   Ask a bounded set of consequential questions, stating the invocation's
   question bound rather than repeatedly extending it.
3. For each question, explain the decision it blocks and offer meaningful
   options when useful. Recommendations remain recommendations; do not supply
   your preferred answer as the user's choice. Stop for material unanswered
   questions, the agreed bound, or a user request to stop.
4. Preserve unresolved questions explicitly. An omitted answer, elapsed wait,
   or request to continue does not silently resolve an ambiguity.
5. When the user authorizes answer capture, confirm exactly which answers and
   existing artifact sections may change. Present the patch and implications.
   Apply only those authorized answers through the specification contract;
   never capture assumptions as confirmed decisions.
6. For edits to previously approved intent, use the same revision/invalidation
   safeguards as `revise`. Check freshness, mark affected descendants stale,
   invalidate affected grants, and reassess evidence applicability without
   rewriting history. Reanalyze consistency and coverage after capture.

## Stop boundary

Answers are not implementation approval, acceptance, or a runtime permission
grant. Clarification cannot broaden a running Auto grant. New scope requiring a
coherent wider amendment goes to `revise`; missing artifacts go to `draft`.
Do not run project tests, implement code, create a mandatory questionnaire
document, or silently approve a requirements-quality checklist.

## Report and handoff

Report `state`, `change`, `input-revisions`, `questions`, `confirmed-answers`,
`unresolved-questions`, `authorized-capture`, `effects`, `impact`,
`analysis-findings`, and `next-step`. If capture failed, distinguish answered
conversation from unchanged or partially updated documents.
Offer stable handoff IDs: `revise`, `draft`, `analyze`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. No banners or child output may
contaminate stdout. This operation emits no telemetry, including answer
capture. Read-only clarification creates no log files, ledger rows, or telemetry
preferences. Never send source, specs, prompts, raw errors, arguments, paths,
answers, or tool output as telemetry.
