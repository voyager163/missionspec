# Synchronize accepted behavior

Use `{{invocation}}` to promote eligible accepted deltas into baseline specs
while leaving the change open. This is the same synchronization used by
`archive`, not a weaker shortcut.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts.
Respect the selected workspace/worktree and user edits. Skills and allowed-tools
metadata never grant authority. Use only advertised runtime capabilities. If
the shared sync engine, acceptance eligibility, or durable journal/recovery
contract is absent, report `missing-runtime` and the missing capability; never
copy files manually and label that an engine synchronization.

## Workflow

1. Resolve the explicit stable change identity. Read the original baseline,
   current baseline, proposed delta documents, accepted revision record, and
   required evidence applicability. File existence or an agent's assertion does
   not establish accepted intent.
2. Require current acceptance for the exact eligible deltas. Execution grants,
   checked tasks, and locally edited published specs are not acceptance. If
   absent or stale, stop and explain the missing trusted acceptance/review step;
   do not mint a record from Markdown.
3. Request a preview from the same sync engine used by archive. Compare
   original/current/accepted delta revisions by stable requirement/scenario
   identity, including explicit removals, renamed labels, and untouched
   concurrent changes.
4. Present the exact baseline-spec diff, input digests, conflict findings,
   evidence references, and intended effects. Obtain explicit confirmation for
   that preview. A proposed conflict resolution needs review and a refreshed
   preview; it cannot silently overwrite current work.
5. Immediately before confirmed commit, revalidate freshness, acceptance,
   evidence policy, and conflicts. A changed input invalidates the preview;
   stop for a new preview and confirmation rather than applying a stale patch.
6. Use the shared journaled multi-file mutation and recovery contract. Preserve
   all archive-equivalent freshness, approval, and conflict safeguards. If some
   effects completed before failure, report their durable references and
   recoverable partial state; never claim atomic success or blindly replay an
   unknown write.
7. Report the new baseline references or an accurately observed no-op. Leave the
   change open; do not create a closure record or move the change directory.

## Stop boundary

Do not promote unaccepted proposals, repair implementation, change requirements
to match code, or archive. Synchronization updates accepted intent, not proof
that the current source conforms. Failed, unavailable, or stale evidence stays
visible under the same policy as archive. Closing later needs explicit outcome
and closure authorization.

## Report and handoff

Report `state`, `change`, `input-revisions`, `acceptance-status`,
`evidence-applicability`, `preview-reference`, `conflicts`, `confirmed-effects`,
`baseline-revisions`, `partial-state`, `recovery-or-next-step`, and
`change-status: open`. Do not flatten partial promotion into success.
Offer stable handoff IDs: `verify`, `revise`, `archive`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. Keep banners and child output off
stdout. This skill never sends telemetry itself. Only a centrally eligible
stateful top-level outcome may yield one aggregate after disclosure, opt-out
checks, and backend qualification; invocation within archive and other nested
probes emit none. Read-only previews create no telemetry or log files. Never
send source, specs, prompts, raw errors, arguments, paths, or tool output as
telemetry.
