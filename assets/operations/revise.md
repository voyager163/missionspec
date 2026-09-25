# Revise existing artifacts

Use `{{invocation}}` to make a coherent, scoped amendment to existing change
documents. This is document revision, not implementation or integration update.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Respect the current workspace/worktree and preserve user edits. Skills and
allowed-tools metadata never grant authority. Use only advertised runtime
capabilities. If revision, invalidation, or validation is unavailable, report
`missing-runtime` and the missing capability; propose a patch in conversation
without applying it or claiming affected approvals were updated.

## Workflow

1. Resolve the selected change, amendment request, and exact existing artifact
   set. Read the current proposal, affected specs/design/tasks, their dependency
   revisions, and related findings. Do not choose a change by modification time.
2. Explain the requested behavioral difference and scope. Preserve stable
   requirement/scenario/task/check identities. Keep an explicit removal distinct
   from omission, and preserve the original reason for acceptance criteria.
3. Produce a reviewable patch. Several existing artifacts may change when their
   coherent update is explicitly in scope. If a new artifact type or undeclared
   output is needed, stop that portion and hand it to `draft`; do not silently
   create missing documents.
4. Show the diff and impact before applying it: changed requirements, dependent
   artifacts/tasks, affected runs, grants, checks, and acceptance eligibility.
   Obtain confirmation for the exact document patch through the supported
   authority path. A request to change intent is not permission to edit source.
5. Recheck input digests, then apply only the reviewed patch through the
   specification/planning contract. On concurrent edits, stop for a refreshed
   diff rather than overwriting. Preserve historical revisions.
6. Mark affected downstream artifacts stale, invalidate affected grants, and
   reassess evidence applicability through the engine. Do not mutate frozen
   approvals or historical observations. Running work remains bound to its
   approved snapshots; material drift requires pause/reconciliation and renewed
   implementation authority, not an expanded live grant.
7. Revalidate IDs, deltas, dependencies, task/check coverage, and consistency.
   Separate deterministic diagnostics from semantic findings and report the
   impact that still requires human review.

## Stop boundary

Stop after the scoped document patch and impact report. No code edits, project
tests, dependency installation, silent baseline promotion, or implementation.
Do not reset checkboxes or fabricate fresh evidence to hide invalidation.
Requirements-quality checklists are planning review, not test evidence.

## Report and handoff

Report `state`, `change`, `old-revisions`, `new-revisions`, `artifact-patch`,
`effects`, `stale-descendants`, `affected-grants`, `evidence-applicability`,
`validation-findings`, `blockers`, and `review-needed`. A failed invalidation
must remain a blocker rather than a completed revision claim.
Offer stable handoff IDs: `draft`, `clarify`, `analyze`, `implement`, `verify`.
Implementation and check execution still need separate current authority.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Keep banners and child output off
stdout. This skill never sends telemetry itself. Only a centrally eligible
stateful top-level outcome may yield one aggregate after disclosure, opt-out
checks, and backend qualification; read-only previews and nested validation emit
none and create no log files. Never send source, specs, prompts, raw errors,
arguments, paths, or tool output as telemetry.
