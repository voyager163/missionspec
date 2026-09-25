# MCP transport

MissionSpec's stdio server fixes the workspace root at process construction.
Tool arguments cannot replace it. Standard output contains only MCP messages;
the server does not initialize a project, recover transactions, execute a model,
or enable telemetry when it starts.

The default server exposes project/change inspection, instructions, structural
analysis, retained-evidence review, selected-document validation, skill rendering
and installation inspection. `missionspec_preview` also prepares bounded
workflow changes without writing files. Supported previews cover setup,
change creation, one-artifact drafting/capture/revision, draft-all, discovery
capture, principles, clarification, Compact design applicability, acceptance,
sync, archive, selected-host skill installation/update/removal, and explicit
new-change adoption of supplied upstream documents.

`source-patch` previews accept only inert proposals for one declared task.
MissionSpec reobserves source preimages, resolves predecessor evidence where
needed, and derives the exact file effects. Applying the preview requires
distinct source-application review; it neither starts a native host nor creates
an execution attempt or passing evidence.

Drafting previews consume explicitly supplied Markdown. They do not invoke a
model or turn template scaffolds into completed solution artifacts. An archive
preview cannot skip acceptance or required spec promotion: use the displayed
acceptance, sync, and archive steps with their separate review scopes.

## Review and effects

A preview returns its exact proposed effects and an unpredictable, one-use
handle. The handle expires after ten minutes and is scoped to this server
instance. At most sixteen pending previews are retained; discard an unused
one with `missionspec_discard_preview`. Neither a handle nor a returned plan is
execution authority. Large previews fail explicitly rather than being truncated.

`missionspec_apply` is advertised only when trusted process composition supplies
an independent review/resolution broker implementing `McpWorkflowAuthority`.
The broker receives the full file plan or acceptance report, obtains genuine
review through its qualified channel, and persists the resulting scoped grant.
The application then resolves that grant again and rechecks file/source guards
through the same journaled operations as the CLI. A declined, expired, changed,
or replayed preview cannot authorize effects. Simultaneous calls cannot reuse
one pending decision.

Cancellation while review is pending prevents the later response from starting
effects. Once a journaled file commit has begun, MCP cancellation is not a
rollback or proof of quiescence; inspect the transaction outcome/recovery state
instead of blindly replaying the request.

The standalone server does **not** treat an arbitrary MCP client as a trusted
human UI. No tool accepts `approved`, user identity, raw grant contents, or a
replacement workspace root. `clientInfo`, environment flags, model messages,
and an MCP elicitation `accept` response do not establish human identity.
Consequently an ordinary stdio client receives previews, not a mutation issuer.
Use the genuine local terminal workflow for changes unless an independently
qualified embedding supplies the broker.

Optional context reports `absent` by default. Trusted composition may inject a
provider with explicit local-only/remote processing declarations.
`missionspec_context` only inspects availability; a context consumption preview
binds the exact query, observed file scope and processing request. Applying it
still requires independent authority. No provider installer, indexer or plugin
loader is invoked. See [adoption and context](adoption.md).

When composition supplies a workspace-bound runtime store, `missionspec_lessons`
exposes immutable history and read-only selection of current, human-activated
advice. Candidate capture, evidence evaluation and activation/retirement/rollback
are separate preview actions, each retaining its own review scope. No MCP
response automatically promotes a candidate, and lesson advice cannot weaken
verification. See [lessons](lessons.md).

A store with the qualified pruning capability also exposes
`missionspec_evidence_pruning` for read-only status/pending recovery.
`evidence-prune` and `evidence-prune-recover` are distinct reviewed preview
actions. A completed prune is not replayed; raw removal cannot occur without
the writable store capability and current exact authority. See
[recoverable evidence pruning](evidence-pruning.md).

The form-elicitation helper negotiates client capabilities, defaults to decline,
binds the exact request digest, and handles cancellation and timeout. It returns
only a transport observation. This is intentionally different from issuing a
persisted approval or claiming organization-authenticated identity.

## Protocol boundaries

Inputs have closed schemas and bounded paths, document sizes, collections and
response sizes. Unknown arguments and rejected input content are not echoed.
Missing evidence, invalid documents, unavailable stores and unsafe operations
produce explicit tool errors rather than empty successful results.

Tests use the actual MCP SDK client/server protocol with original in-memory
fixtures. Synthetic authority fixtures prove routing and guard enforcement,
not native-host discovery, human confirmation, paid-model behavior or a
qualified host permission boundary.
