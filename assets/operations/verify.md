# Verify actual outcomes

Use `{{invocation}}` to compare current intent with saved implementation and
real evidence. Verification reports observations and gaps; it is not code
repair, acceptance, or closure.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Preserve the selected workspace/worktree and user edits. Skills and allowed-tools
metadata never grant authority. Use only advertised runtime capabilities. If
source binding, verification, or required durable recording is unavailable,
report `missing-runtime` and the missing capability; do not invent check results
or substitute Markdown for authoritative evidence.

## Workflow

1. Resolve the explicit change. Load its current approved requirements, scenario
   IDs, task/check mapping, acceptance criteria, and relevant dependency
   revisions. Read the actual saved source revision, including applicable
   uncommitted changes; a Git commit alone may not identify the tested content.
2. Ask the verification engine for check applicability and existing evidence.
   Bind observations to exact intent and source revisions. If inputs drift
   during checking, mark affected evidence stale instead of attaching it to the
   new source. Copied reports and fresh clones cannot reconstruct trusted
   historical results.
3. Separate structural validation, static code inspection, semantic judgment,
   and executed checks. Requirements-quality checklists and task checkboxes are
   not test evidence. Explain the basis and uncertainty of each claim.
4. Preview the applicable checks and their effects. Run only checks covered by
   current verification authority and independent host permissions. Tests
   execute project code and are not intrinsically read-only. Missing test tools
   or dependencies are unavailable checks, not permission to install software or
   quietly reduce the check set. Do not turn command availability into consent.
5. Record actual start/result/source bindings and protected evidence through the
   supported engine. Distinguish failed, unavailable, skipped, missing, stale,
   and applicable evidence; include exit status only when observed. If durable
   capture fails, stop recording success claims and report the failure.
6. Build a gap report tied to stable requirement/scenario/task/check IDs.
   Evaluate completeness, correctness, and coherence separately. Classify
   missing, partial, contradictory, and unrequested behavior and cite the
   source/evidence for each. Include uncertain judgments as judgments, not
   deterministic proof.
7. Propose scoped repair tasks linked to finding IDs where useful, but keep them
   proposals in the report. A separately reviewed drafting patch is required to
   change task definitions.

## Stop boundary

Standalone verify never repairs code. Do not rewrite tasks or requirements,
weaken criteria, approve new scope, accept, sync, or archive. Bounded repairs
inside an authorized Auto run belong to the execution controller, not this
verification operation. An unavailable or unauthorized required check remains a
visible gap; other independent authorized checks may still be reported.

## Report and handoff

Report `state`, `change`, `intent-revisions`, `source-revision`,
`check-applicability`, `check-observations`, `evidence-references`, `completeness`,
`correctness`, `coherence`, `gap-findings`, `proposed-repairs`, `effects`, and
`blockers`. Keep partial results and failures rather than flattening the report
into a pass. Offer stable handoff IDs: `implement`, `revise`, `analyze`, `archive`.
Each next step retains its own authorization and eligibility checks.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. No child test output or banners
may leak into protocol stdout. Store authorized raw output only in protected
evidence, not remote analytics. This skill never sends telemetry itself; only a
centrally eligible stateful top-level outcome may yield one aggregate after
disclosure, opt-out checks, and backend qualification. Nested probes and
read-only previews emit none. Never send source, specs, prompts, raw errors,
arguments, paths, or tool output as telemetry.
