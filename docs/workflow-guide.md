# The MissionSpec workflow

**Discover the problem. Draft the solution. Implement it. Verify it. Archive the
change.** MissionSpec uses one change folder for the work and a separate accepted
specification baseline. It does not require a discovery document before every
proposal.

This is a local development implementation, not a published product release.
Use the built CLI's `--help` and `capabilities --json` for the available surface.
Native skill rendering and installation do not establish that a particular host
version is qualified for governed execution.

## Six primary operations

| Operation | What it does | Where it stops |
| --- | --- | --- |
| `discover` | Discuss the problem, inspect permitted context, compare approaches and identify questions | No writes by default; explicitly saved notes belong to the selected change |
| `draft` | Author one next ready artifact using its current dependencies | One workflow node, not necessarily one physical file |
| `draft-all` | Batch the remaining required drafts with the same scheduler | Before implementation; ambiguity and invalid dependencies still block |
| `implement` | Work on separately authorized tasks | Approved effects and limits; Interactive by default, Auto only when explicitly requested |
| `verify` | Review current source and actual evidence; report gaps | No automatic repair, acceptance, sync or archive |
| `archive` | Preserve the change and its true outcome | Accepted closure requires the separately reviewed acceptance and spec-promotion steps |

`proposal.md` is an artifact, not another command. The complete declared
`specs/<capability>/spec.md` delta set is one artifact even when it contains
multiple files. `draft` cannot also create design and tasks in that invocation.
`draft-all` accelerates drafting, not permissions, checks or implementation.

## Six default helpers

All six helpers are installed alongside the primary six for every selected host.
They are not extra mandatory stages.

| Helper | Use it when | Boundary |
| --- | --- | --- |
| `revise` | Existing authored artifacts need a coherent amendment | Preserve user content; invalidate affected descendants and grants |
| `clarify` | A consequential question remains unresolved | Capture answers only in reviewed scope; an answer is not execution approval |
| `analyze` | You want another consistency and coverage review | Read-only; no project tests or repairs |
| `principles` | Project-wide constraints need creating or amending | Optional `missionspec/principles.md`; no permission changes |
| `sync` | Accepted deltas should update the baseline while the change stays open | Same conflict and evidence checks as archive |
| `onboard` | You want an explanation or a selected walkthrough | No silent setup, Git operations, paid model activity or implementation |

Focused clarification belongs to the discovery engine, including during
drafting. Traceable task breakdown and cross-artifact consistency belong to
planning. Convergence-style missing, partial, contradictory and unrequested
behavior reports belong to verification. See the
[convergence reference](architecture/convergence.md).

## Project files versus local state

```text
missionspec/
  config.yaml
  principles.md                         # optional shared constraints
  specs/<capability>/spec.md             # accepted behavior baseline
  changes/<change>/
    change.yaml                         # identity, workflow, declared scope
    discovery.md                        # optional saved investigation
    proposal.md
    specs/<capability>/spec.md           # proposed behavior changes
    design.md
    tasks.md                            # task graph and planned checks
    verification.md                     # explicitly declared expanded checks
  changes/archive/<date>-<change>/       # historical artifacts and outcome

.missionspec/                           # ignored local machine state
  workspace.json
  installation.json
  state/ledger.sqlite
  approvals/
  audit/
  checks/
  evidence/
  transactions/
  logs/
```

The top-level specs are accepted **intent**, not proof that the current code
conforms. Change-local specs are proposed amendments. Discovery belongs inside
its change, not in a competing top-level discovery folder. Capability paths can
be nested; change slugs are flat.

Markdown is the editable source of truth. The ledger holds execution and
evidence records, not a second editable task graph. A fresh clone can read the
documents but cannot reconstruct trusted approvals or successful execution from
checkboxes, prose or an archive directory.

Standard is the default profile. Compact is explicit opt-in and can place a
short design section in tasks after a reviewed not-applicable decision for the
separate design artifact. Compact does not weaken authorization or evidence.

Select `--verification-plan` when creating a change to split detailed check
definitions into `verification.md`. It and `tasks.md` remain one task/check
artifact, captured and revised together. The tasks frontmatter can explicitly
point to its sibling with `checks: verification.md`; omitting the sibling or
defining a check twice fails validation.

## Starting from a source build

Build MissionSpec using the repository's documented development commands.
Run the built executable **from the project you intend to use**, not from the
MissionSpec source checkout. The path below is a placeholder for that build:

```sh
node /absolute/path/to/missionspec/dist/cli/main.js init --preview --json
node /absolute/path/to/missionspec/dist/cli/main.js init
```

The preview writes nothing. Applying setup displays exact changes and requires
the local terminal's fresh challenge response. A piped response, `--yes`,
`approved: true`, or a skill's instructions cannot substitute for the trusted
confirmation channel. See [local runtime assurance](architecture/local-runtime.md).

Create an explicitly scoped change, including the files whose implementation
revisions will be observed:

```text
missionspec change new remember-filter --spec filters --source src/filter.ts --source tests/filter.test.ts --preview
missionspec change new remember-filter --spec filters --source src/filter.ts --source tests/filter.test.ts
missionspec instructions remember-filter --artifact proposal
```

Here and below, `missionspec` denotes the built executable. These examples do not
choose or promise a package-manager installation channel.

The deterministic terminal `draft` writes an **incomplete scaffold**, not an
AI-authored solution. Author the actual Markdown in the coding host or editor,
then use `capture` to validate and record its preparation:

```text
missionspec draft remember-filter --artifact proposal --preview
missionspec draft remember-filter --artifact proposal
missionspec capture remember-filter --artifact proposal --preview
missionspec capture remember-filter --artifact proposal
missionspec status remember-filter --json
```

Complete the scaffold before capture. The native `missionspec-draft` skill adds
agent-assisted authoring over the same one-artifact boundary; it must not claim
that merely generating a template finished the proposal. Reuse the same process
for eligible specs, design and tasks. `draft-all` validates supplied authored
outputs as a batch; it does not secretly call a model or start implementation.

## Installing the native instructions

```text
missionspec skills inspect --host codex
missionspec skills install --host codex --preview
missionspec skills install --host codex
```

Use repeated `--hosts` for an explicit multi-host selection. Each selected host
receives exactly twelve owned skill files. Generated locations and intended
explicit invocation syntax are:

| Host | Location | Example |
| --- | --- | --- |
| Copilot CLI | `.github/skills/missionspec-*/SKILL.md` | `/missionspec-draft` |
| Codex CLI | `.agents/skills/missionspec-*/SKILL.md` | `$missionspec-draft` |
| Claude Code | `.claude/skills/missionspec-*/SKILL.md` | `/missionspec-draft` |

Installation records ownership and hashes. Updates/removals preview their exact
scope and refuse conflicting user edits; they do not overwrite unrelated
OpenSpec, Spec Kit or host files. A rendered or installed instruction is not
proof of native discovery, invocation, tool permission, execution or verified
results. See [installation behavior](architecture/installation.md).

## Evidence and closure

`validate` checks supplied Markdown; `analyze` checks the current planning
graph; neither runs project tests. `verify` reviews missing or retained evidence.
Executing a check requires explicit registration of a trusted local program,
review of its concrete invocation, and separate collection authority. That
local process adapter is not a filesystem/network sandbox.

Implementation claims, executed checks, static observations, agent judgments,
human acceptance and baseline publication are different records. Missing,
failed, stale, skipped or unavailable evidence must remain visible. Raw evidence
is not automatically deleted by age.

Archive can guide acceptance, baseline promotion and closure through separate
reviews. You do not have to run separate accept and sync commands first.
Rejected, cancelled or incomplete work may be preserved with its actual outcome,
without pretending it was verified or promoting its proposed behavior.

## Adding Mission Context later

MissionSpec works without Mission Context. Install Mission Context separately
using that project's documented installer, then explicitly connect a compatible
provider or use its supported coding-host integration. MissionSpec does not
bundle it, own its indexes, or provide a generic plugin marketplace.

The Mission Context repository owns its installation commands and protocol.
Do not assume a `missionspec plugin install` command exists. Saving connection
metadata does not authorize indexing, remote processing, source export or model
spending. Missing, disabled, incompatible and partially available context must
be reported explicitly.

Local diagnostics and audit records are separate from optional usage analytics.
See [logging](logging.md) and [telemetry](telemetry.md) for controls and privacy
boundaries. The development build has no active production telemetry endpoint.
