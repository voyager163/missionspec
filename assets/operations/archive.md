# Close and preserve a change

Use `{{invocation}}` for guided single-change closure. Archive preserves the
actual outcome; it does not turn unfinished work into success.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Respect the selected workspace/worktree and user edits. Skills and allowed-tools
metadata never grant authority. Use only advertised runtime capabilities. If
acceptance, shared sync, durable closure, or a required recovery capability is
absent, report `missing-runtime` with the missing capability and stop before the
dependent effect. Do not manually move a directory to imitate engine closure.

## Workflow

1. Resolve the explicit stable change identity. Inspect current draft revisions,
   execution state, unresolved effects, verification applicability, acceptance,
   and prior synchronization. An active or outcome-unknown run is not quiesced
   merely because the host appears idle.
2. Present the truthful candidate outcome with evidence and remaining gaps:
   accepted, rejected, cancelled, or incomplete as applicable. Missing or stale
   evidence remains visible. Checkboxes, resolved review comments, and the
   existence of an archive directory do not establish acceptance.
3. For eligible completed work, guide acceptance through the trusted application
   interface using the verification engine's eligibility result. Obtain explicit
   acceptance of the exact presented revision. Execution permission is not
   acceptance. The user need not run a separate utility first.
4. When accepted deltas need promotion, obtain a shared sync-engine preview of
   original baseline, current baseline, and accepted delta revisions by stable
   identity. Show the exact proposed baseline diff and conflict findings. An
   agent-proposed conflict resolution is not permission to overwrite work.
5. Obtain explicit confirmation for the presented promotion and closure scope.
   Acceptance, promotion, and closure remain separately typed records even when
   one clear interaction confirms all displayed actions. Do not infer any
   omitted action from a generic instruction to finish.
6. Immediately before promotion, revalidate accepted input digests, current
   baseline freshness, evidence applicability, and conflicts through the same
   sync engine used by `sync`. Use its journaled multi-file commit/recovery
   contract, never ad hoc file copies. Stop on drift or conflict.
7. Preview the archive destination and refuse collisions. Close only after all
   required prior effects are confirmed. Preserve canonical artifacts, outcome,
   and appropriate evidence references, not confidential raw transcripts.

## Incomplete outcomes and recovery

Rejected, cancelled, or incomplete changes can be archived only with explicit
confirmation of that outcome. They are not accepted successes and must not
automatically promote baseline specs. Explain unresolved effects and unavailable
evidence without hiding them.

If required promotion or closure partially fails, stop and report recoverable
partial state, durable effect references, and the runtime's supported recovery
step. Do not move the directory anyway, retry unknown effects blindly, roll back
unrelated user edits, or claim closure succeeded. Never manufacture acceptance
records or successful evidence from documents.

## Report and handoff

Report `state`, `change`, `input-revisions`, `outcome`, `acceptance-status`,
`sync-status`, `closure-status`, `archive-destination`, `effects`,
`evidence-references`, `unresolved-effects`, and `recovery-or-next-step`.
Distinguish preserved incomplete work from accepted/synchronized closure.
Offer stable handoff IDs: `verify`, `sync`, `revise`. Batch archive is not
provided by this operation.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Keep banners and child output off
stdout. This skill never sends telemetry itself. A centrally eligible stateful
top-level outcome may yield at most one aggregate after disclosure, opt-out
checks, and backend qualification, not separate nested acceptance/sync events.
Read-only previews create no telemetry or log files. Never send source, specs,
prompts, raw errors, arguments, paths, or tool output as telemetry.
