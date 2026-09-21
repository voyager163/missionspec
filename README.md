# MissionSpec

MissionSpec is a pre-release project for specification-driven, agent-assisted
software development. Its **local development CLI** supports reviewed setup,
artifact drafting/capture, exact source-patch application, registered check
execution, verification, and guided acceptance/sync/archive. Markdown remains
canonical; SQLite retains execution and evidence separately.

Twelve original skills can be installed, updated, inspected and removed for
explicitly selected Copilot CLI, Codex CLI and Claude Code projects. Installation
preserves ownership and user edits. Local terminal confirmation controls writes;
no model text or `approved: true` field grants authority.

The library includes a durable dependency-aware execution controller, restricted
native proposal bridges, MCP transport, focused clarification, consistency/gap
reports, reviewed lessons, explicit import and recoverable evidence pruning.
**Native autonomous execution remains unqualified and disabled in the CLI.**
Synthetic protocol tests and installed skills are not live-host qualification.
Windows private-state APIs have dedicated native qualification; interactive
Windows terminal confirmation remains disabled. The current held-handle file
protocol must pass its own race and recovery gates before it is qualified.
See the [Windows capability boundary](docs/architecture/windows-state.md).
Live native execution and production telemetry deployment remain separate
release gates. Ordinary Claude Code skills and CLI/MCP integration do not
require the optional programmatic Claude SDK bridge.

The root package manifest is private at version `0.0.0` for local development;
it does not represent a product release.

## Direction and skill sources

The intended product is one TypeScript/Node.js package,
`@msn-control/missionspec`, with six internal engines. The three planned agent
hosts are **Copilot CLI**, **Codex CLI**, and **Claude Code**.

The canonical skill sources cover:

| Role | Operation sources |
| --- | --- |
| Primary workflow | `discover`, `draft`, `draft-all`, `implement`, `verify`, `archive` |
| Helpers | `revise`, `clarify`, `analyze`, `principles`, `sync`, `onboard` |

MissionSpec is intended to work standalone. Mission Context would be an optional,
externally installed integration, not a bundled dependency. Artifact Server
integration is deferred; Liftoff distribution is out of scope.

Start with the [workflow guide](docs/workflow-guide.md). Detailed references cover
[local runtime](docs/architecture/local-runtime.md),
[MCP](docs/architecture/mcp.md), [native proposal boundaries](docs/architecture/native-hosts.md),
[lessons](docs/architecture/lessons.md) and
[evidence retention](docs/architecture/evidence-pruning.md).

## Check this repository

Use Node.js **24 LTS**, within the supported range **`>=24.21.0 <25`**.
The current local validation baseline is **24.21.0**. From a checkout, run:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check
```

These commands install the repository's locked development dependencies without
installation scripts. `check` builds TypeScript as part of the tests, runs the
tests, checks architecture import boundaries and repository policies, then
checks npm dry-run package boundaries and packaged links. The repository
checker validates local Markdown links and heading anchors, issue form YAML,
required documents, and workflow policies. It does not contact external links or
prove GitHub enforcement. The check also verifies locked dependency provenance
and retained third-party notices. Package checks do not publish anything.

The full effectful suite targets macOS/Linux. `npm run check:portable` exercises
the explicitly bounded Windows read-only/contract surface without pretending
that POSIX persistence or pseudo-terminal tests qualify Windows writes.
Separate Windows jobs exercise private storage, concurrent file replacement
and the actual setup/source, recovery and pruning APIs. Application scenarios
run only after the held-handle race regressions pass.

These are source-checkout development commands, not product installation.
Compilation and static import checks do not demonstrate complete engines,
runtime isolation, or native host qualification. Passing checks is not a product
release or a security certification. See the
[development check reference](CONTRIBUTING.md#development-checks) for individual
commands.

## Inspect the development CLI

After restoring dependencies in a source checkout as above, build and inspect:

```sh
npm run build
node dist/cli/main.js capabilities --json
node dist/cli/main.js skills list --json
node dist/cli/main.js skills render --host codex --operation draft --json
```

These commands inspect capabilities and emit skill data. The render example
does not install a skill into Codex CLI or invoke that host. For read-only local
workflow inspection, use:

```sh
node dist/cli/main.js project status --json
node dist/cli/main.js init --preview --json
node dist/cli/main.js onboard --json
```

In an explicitly initialized project, `status <slug>`, `instructions <slug>`,
`analyze <slug>` and `verify <slug>` provide read-only guidance. Artifact
creation/capture and lifecycle paths support `--preview` for read-only review.
Without it, exact changes require a genuine local terminal challenge response.
The CLI also supports separately reviewed local check registration/collection
and guided acceptance, baseline promotion and archive.
Library composition, exact command/API syntax, assurance limits and remaining
gaps are documented in the [local runtime reference](docs/architecture/local-runtime.md).
No `--yes`, JSON field, environment flag or skill text issues authority. Reviewed
`skills install|update|remove --host <host>` operations manage only owned native
skill files; they do not install the product, qualify a coding host, or publish
a release.

For existing MissionSpec-format documents, run
`node dist/cli/main.js validate path/to/proposal.md path/to/spec.md --json`
with paths relative to the current project. This checks only the supplied
document set; it does not establish change completeness, execution approval,
or implementation correctness. See the
[Markdown format reference](docs/architecture/markdown-format.md).

Operator sources are intentionally outside the CLI package. Work with
checkout-only paths such as `services/`, `infrastructure/`, `src/`, and `scripts/`
in the [source repository](https://github.com/voyager163/missionspec), not as
relative navigation targets inside a package.

## Participate

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before making a change. Pull requests
  target `develop`.
- Use [Issues](https://github.com/voyager163/missionspec/issues) for public
  project questions, bug reports, and feature requests. The issue chooser also
  allows a general issue.
- Keep privacy questions general and sanitized. Never put personal data,
  credentials, private source, `.env` files, or raw diagnostics in an issue.
  Sensitive security or privacy findings belong under the
  [security reporting policy](SECURITY.md), not in public discussion.
- Report conduct concerns through the [Code of Conduct](CODE_OF_CONDUCT.md),
  separately from technical support and vulnerability reporting.

**Private vulnerability reporting is enabled.** Use the private GitHub route in
[SECURITY.md](SECURITY.md); never publish sensitive findings in public issues.
PR-only, conversation-resolution, force-push and deletion protections are active
for `develop` and `main`. Required Linux/macOS, Windows read-only/private-state,
native race and application, dependency-review and CodeQL checks are bound to
their verified GitHub Apps. A passing scanner cannot bypass a failing Windows
application check.

The [maintainer setup guide](docs/maintainer-setup.md) distinguishes local checks
from GitHub controls that still require authorization, configuration, and
verification.

## License

MissionSpec is licensed under the [Apache License 2.0](LICENSE). Contributions
must have appropriate rights and preserve applicable third-party notices.
The [licensing guide](docs/licensing.md) documents original-work boundaries,
runtime inventories and retained notices.
