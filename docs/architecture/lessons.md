# Human-reviewed local lessons

`LocalLessons` in `src/application/lessons.ts` composes the existing
`LocalWorkflow`, `LocalAuthorityPort`, `RuntimeStorePort`, and private
`LocalWorkspace` audit writer. Pure parsers, evidence-review reports, applicability
matching, and immutable lifecycle reduction live under the existing verification
engine in `src/engines/verification/lessons/`. There is no seventh engine,
replacement database, editable lessons cache, model call, or automatic promotion.

## Library surface for CLI composition

```ts
const lessons = new LocalLessons(workflow, authority, store, { now });
const preview = await lessons.previewCapture(slug, candidate);
const confirmation = await lessons.confirm(preview);
// Continue only for a genuinely issued confirmation from trusted composition.
// No boolean, model response, or caller-supplied receipt can replace this exchange.
if (confirmation.status === 'ok' && confirmation.value.state === 'issued') {
  await lessons.capture(slug, candidate, confirmation.value.approval.reference);
}
```

The API uses the application's existing exception/`WorkflowError` convention.
The runtime CLI/API owner composes and exposes this library; the lessons module
does not create a second controller or terminal authority.

| Read-only preview or query | Explicit admitted write |
| --- | --- |
| `previewCapture(slug, candidate)` | `capture(slug, candidate, approval)` |
| `previewEvaluation(slug, lessonId, version, mode?)` | `evaluate(slug, lessonId, version, approval, mode?)` |
| `previewTransition(slug, lessonId, transition)` | `transition(slug, lessonId, transition, approval)` |
| `history(lessonId)` | None |
| `select(slug, { operation, paths })` | None |

`confirm(preview)` delegates the exact request and complete structured lesson
display to the existing authority implementation. It does not issue an approval
itself. CLI wiring must stop when confirmation is declined/unavailable, and must
not introduce an `approved`, `yes`, or fabricated success option.

Every preview contains a digest-bound review request plus
`trust: untrusted-advice`, `permissions: unchanged`, `requirements: unchanged`,
and `acceptanceCriteria: unchanged`. Write methods independently resolve actual
current authority again; retaining a preview does not authorize its effects.

## Candidate and provenance

A candidate is closed, bounded data:

```json
{
  "schemaVersion": 1,
  "lessonId": "review-current-source",
  "title": "Review current source before reusing an observation",
  "advice": "Prior observations are context, not permission or current proof.",
  "provenance": {
    "kind": "agent-proposal",
    "rationale": "Describe the observation that motivated this suggestion.",
    "evidence": ["EVD-example-reference"]
  },
  "applicability": {
    "changeId": "CHG-example",
    "operations": ["implement", "verify"],
    "sourcePaths": ["src/example.ts"]
  }
}
```

These are synthetic documentation identities, not usable evidence. `lessonId`
is a portable flat slug; evidence/change IDs use the current kernel parsers.
Unknown fields, caller approval flags, wildcard source paths, duplicate IDs,
unbounded payloads, and permission-like schema additions are rejected. The
provenance kind is explicitly a supplied attribution claim, not proof that a
human authored or reviewed the candidate.

Actual candidate capture requires existing SQLite evidence references whose
raw bytes are retained in the private immutable evidence area. The application
checks the real observation envelope, raw digest, current declared check
definition, current change/workspace/source binding, and each declared
applicability path. A failed check can legitimately motivate advice; its failure
is preserved rather than rewritten as a success.

The initial applicability model is deliberately narrow: an exact change,
declared source paths, and selected registered operations. It does not silently
generalize a lesson to another project, change, host, or arbitrary glob. Reuse
outside that scope requires a separately captured and reviewed version.

## Evaluation and human activation

Capture creates an **inactive immutable candidate version**, not an accepted
lesson. Its content digest covers the candidate, complete revision binding,
exact file guards, evidence identities and observation summaries. Modifying
advice creates a different version; history is never overwritten.

The available evaluation mode is `evidence-review`. It reobserves current inputs
and records the actual retained check observations:

- `state: ready-for-human-review`, never automatically active;
- `semanticAssessment: unavailable`;
- `acceptance: not-assessed`;
- `benchmark: not-performed`.

This is an integrity/freshness report for human consideration, **not** an
effectiveness evaluation, benchmark result, acceptance report, or proof of check
qualification beyond the existing evidence mechanism. Explicitly requesting
`semantic` evaluation is blocked with `capability-unavailable`; there is no
paid/elevated fallback or invented semantic result.

After evaluation, activation requires its **own** exact human confirmation.
Candidate-capture and evaluation approvals cannot be reused because the action,
version, evidence/guards, and current audit-history head bind a different request.
Model success, a claimed-complete task, a checkbox, or an approval-shaped JSON
object cannot activate a lesson.

Transitions are closed data:

- `{ action: 'activate', version, reason }`: activate a newly evaluated version;
- `{ action: 'retire', reason }`: stop selecting the active version;
- `{ action: 'rollback', version, reason }`: explicitly restore a previously
  activated/reviewed version, with another current human confirmation.

Rollback cannot select a never-activated candidate or silently rebind old
evidence. The earlier version must still have current source, evidence, and file
guards. If it is stale, capture and review a new version instead. Retirement may
remove stale advice without claiming its old evidence is fresh, but still binds
current workspace/change guards and requires authority and runtime quiescence.

## Immutable storage and freshness

Each admitted mutation appends one exclusively created, fsynced
`.missionspec/audit/lesson-<uuid>.json` record using `LocalWorkspace.recordRuntime`.
The record includes its exact review request/reference, bounded lesson event,
current workspace/revisions, observed guards, and the previous record's identity
and byte digest. The complete history must be one connected, unbranched chain.
Missing/changed predecessors, cycles, forked heads, inconsistent evaluations,
unknown records, copied workspace bindings, and malformed canonical data fail
closed. No mutable active-pointer file or separate lesson store is introduced.

SQLite remains the source of evidence/run reference integrity. The audit records
hold compact evidence summaries and digests, not copies of raw check output or
source files. Concrete workspace/root bindings remain private runtime data, not
committed specification/planning Markdown or analytics.

Mutations use the existing shared runtime/file-transaction lock. Inside the lock
they establish run quiescence, rebuild the preview against the current audit
head, resolve real authority, and recheck every guard immediately before append.
Approval expiry/revocation, edited source, replaced raw evidence, or a concurrent
history append prevents use of an earlier approval. Active and outcome-unknown
runs block lesson writes/selection rather than assuming a settled source.
An unconfirmed audit write reports `effect-outcome-unknown`; it is not silently
retried or reported as committed.

## Selection is untrusted context

`select` is read-only, including when the audit directory is absent. It returns
only active versions whose exact operation/path applicability matches and whose
current source, guards, retained evidence, and history remain consistent.
Inactive, inapplicable, stale, or unavailable-evidence lessons are excluded with
explicit reasons. Corrupt history is an error, not an invitation to choose a
convenient record.

Returned text is **UNTRUSTED ADVICE**. It cannot:

- grant authority, broaden effect scopes, or select a native host;
- rewrite requirements, checks, acceptance criteria, or project principles;
- resolve blocked verification, classify a task complete, or approve acceptance;
- authorize another file/database/model/network operation.

Advice can become stale after a read, like any snapshot; calling composition
must preserve these boundaries and revalidate before any actual effect. The
private local history is not tamper-proof against its machine owner. A persisted
approval reference is not itself a trusted approval issuer or reusable
confirmation token.

## Raw evidence pruning boundary

This module does **not** remove raw evidence. The separate
[`LocalEvidencePruning` protocol](evidence-pruning.md) provides exact previews,
independent human approval, durable preparation before removal, active-run
fencing, immutable compact observation history, and explicit crash recovery.
The original evidence payloads and lesson audit records remain immutable.

As soon as pruning is durably prepared, affected evidence becomes unavailable
even if its raw bytes still exist. Lessons referencing it are therefore excluded
by the ordinary freshness/availability checks; no activation or semantic report
is rewritten to hide the loss. There is no age-based cleanup or automatic
retirement/promotion of lessons. Restoring raw bytes alone does not clear a
prepared/completed pruning record or reactivate advice.

## Validation

```sh
npm run build
node --test tests/lessons.test.mjs
```

Tests use owned project-local directories, real SQLite, real `LocalWorkspace`
audit files, and a real registered local Node subprocess to produce retained
failed-check evidence. Controlled authority fixtures are **test-only** admission
responses, never a claim of real human confirmation. A separate test verifies
that the actual terminal authority stays unavailable without a TTY.

Coverage includes capture/evaluation inactivity, distinct activation review,
immutable replacement, retirement, reviewed-version rollback, unavailable
semantic evaluation, exact applicability, stale source/evidence/approvals,
concurrent history changes, active runs, read-only selection, corrupt/forked
history, and copied-workspace rejection. No paid evaluation, cloud request,
native coding-host qualification, or automated promotion is performed.
