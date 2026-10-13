# Learn the workflow

Use `{{invocation}}` for explanation and a user-selected walkthrough.
Explanation comes first; invoking onboarding is not repository adoption.

## Readiness and authority

Read the current workspace instructions, applicable canonical project
principles, and authoritative core instructions and engine result contracts
when available. Preserve the selected workspace/worktree and user edits. Skills
and allowed-tools metadata never grant authority. Use only advertised runtime
capabilities. An absent runtime or operation is `missing-runtime`, not a reason
to claim a successful installation or build a prompt-only replacement.

## Explain, then inspect

1. Explain the primary flow: `discover` investigates, `draft` authors one ready
   node, `draft-all` optionally prepares the remaining prerequisites, `implement`
   executes separately authorized work, `verify` reports actual evidence, and
   `archive` records the true accepted/rejected/cancelled/incomplete outcome.
2. Explain the six default supporting operations: `revise` updates existing
   documents; `clarify` asks focused questions and captures authorized answers;
   `analyze` reviews planning quality; `principles` manages optional project
   constraints; `sync` promotes accepted deltas without closing; `onboard`
   explains and guides. They are conveniences, not six compulsory stages.
3. Describe proposed versus accepted specs, task claims versus executed
   evidence, and separate document review, execution authority, verification
   authority, and final acceptance. Requirements-quality checklists are not
   test evidence. Interactive is the default; Auto needs explicit request,
   qualified runtime/host, a bounded grant, and confirmed per-run limits.
4. Inspect existing configuration, workspace layout, and advertised host/runtime
   readiness without writing files or launching project tests. Selected
   qualified Copilot CLI, Codex CLI, and Claude Code hosts each receive the full
   twelve-skill catalog; source assets alone do not prove installation,
   discoverability, invocation, execution, or verification.
5. Explain missing capabilities honestly. Available deterministic interfaces may
   include init, change-new, status, instructions, validate, diff, and run; these
   names are not proof of availability. Use the installed interface's advertised
   grammar rather than inventing commands. If setup is absent, describe the
   reviewed setup step and stop before changing anything.

## A selected walkthrough is not blanket permission

Offer a small next step and wait for explicit selection. A real example change
requires its own identity, scope, and creation authorization. Proposed init or
host installation is a separately reviewed action, not an onboarding side
effect. Missing engines block their actions; conversation-only explanation and
authorized repository reading can still be useful.

Every action stays separately authorized under its owning operation. Do not
auto-initialize, create Git branches, commit, push, install dependencies, launch
background model spending, run implementation, accept, synchronize, or archive.
Do not chain `draft-all` into implementation. Hand off rather than reimplementing
another operation's workflow. Respect its stop point before proposing another
step; learning mode is not a permission bypass.

Mission Context is an optional separately installed provider, not a prerequisite
or a bundled installer. A connection setting does not authorize indexing,
semantic processing, source export, or model spending.

## Report and handoff

Report `state`, `workspace`, `readiness`, `available-capabilities`,
`missing-capabilities`, `explanation`, `selected-next-step`, `effects: none`,
and `authorization-needed`. Do not report an entire walkthrough complete because
one explanation or step succeeded.
Offer only stable handoff IDs: `discover`, `draft`, `draft-all`, `implement`,
`verify`, `archive`, `revise`, `clarify`, `analyze`, `principles`, `sync`.

## Output and privacy

In JSON or stdio-MCP mode, stdout contains only the promised result/protocol
messages; human diagnostics belong on stderr. No banners or child output may
contaminate stdout. Onboard emits no umbrella telemetry event. Its read-only
inspection creates no log files, ledger rows, or telemetry preferences.
Separately authorized downstream operations follow their own centralized
eligibility policy without double counting. Never send source, specs, prompts,
raw errors, arguments, paths, or tool output as telemetry.
