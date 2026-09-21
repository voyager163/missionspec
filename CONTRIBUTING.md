# Contributing to MissionSpec

MissionSpec is pre-release. Its development CLI performs explicitly reviewed
local workflow changes, installs twelve original native skills per selected host,
collects authorized check evidence and guides closure. The journaled library and
injected-host controller require independently trusted authority/host composition;
test fixtures are never production channels. Native autonomous execution is
unqualified; there is no production telemetry endpoint, deployment or supported
product release. The
[README](README.md) separates current capabilities from the intended product.

## Choose the right channel

- Use [Issues](https://github.com/voyager163/missionspec/issues) for public
  questions and proposals. Bug and feature forms are available; general issues
  remain welcome.
- For a bug, provide the revision, pre-release status, a minimal sanitized
  reproduction, and expected and actual behavior. Include Node.js and operating
  system versions when reporting a local check failure.
- For a feature, describe the problem, current behavior, and desired outcome.
  A proposal is not a commitment to implement or ship it.
- Ask general privacy questions without identifying anyone or disclosing
  sensitive material. Follow [SECURITY.md](SECURITY.md) for sensitive security
  or privacy findings. GitHub private reporting is enabled; do not publish a
  finding if you cannot access that private route.
- Send conduct concerns through [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), not
  through bug reports.

There is no guaranteed response or review time. For substantial changes, discuss
the direction in an issue first so you do not have to guess at project scope.

## Make a focused change

1. Start a working branch from `develop`, in a fork if needed.
2. Keep the change limited to a clear problem. Explain any behavior or policy
   change, and update directly affected documentation and tests.
3. With Node.js 24 LTS (`>=24.21.0 <25`), run the local checks from the repository
   root:

   ```sh
   npm ci --ignore-scripts --no-audit --no-fund
   npm run check
   ```

   The current local validation baseline is Node.js 24.21.0. These are repository
   maintenance commands, not product installation. Do not enable dependency
   installation scripts just to get past a failure; report the sanitized failure
   and investigate the cause.

4. Open a pull request targeting **`develop`**, not `main`. Describe the change,
   how you checked it, any remaining limitations, and related issues. If you
   could not run a check, say so rather than marking it passed.

Changes must go through a pull request, including maintainer-authored
changes. An active branch ruleset enforces this for `develop` and `main`.
The project currently has one maintainer and requires **zero external
approving reviews**. The maintainer may review and merge their own pull request
after checking its content and validation results. Conversation resolution,
force-push and deletion restrictions are active. Required CI checks are not yet
configured: they must use actual observed successful hosted check identities.

Changes to workflows, validation controls, release configuration, and security
policy need deliberate maintainer review. A green check or an automated
suggestion is not sufficient reason to blindly auto-merge them. Changing hosted
settings, pushing branches, or publishing packages requires separate, explicit
authority; editing local files does not grant it.

## Development checks

`npm run check` runs tests, architecture import checks, repository policy checks,
and package boundary/link and locked-license checks. Tests include the
TypeScript build. For a focused local iteration, the individual commands are:

| Command | Scope |
| --- | --- |
| `npm run build` | Compile TypeScript with `tsc -p tsconfig.json`. |
| `npm test` | Run the build, then `node --test tests/*.test.mjs`. |
| `npm run check:architecture` | Check static TypeScript import boundaries. |
| `npm run check:repository` | Validate local documentation links and anchors, issue forms, required documents, and workflow policies. |
| `npm run check:package` | Check npm dry-run package contents, exclusion boundaries, and packaged links without publishing. |
| `npm run check:licenses` | Verify locked CLI runtime provenance and shipped legal notices. |
| `npm run check:portable` | Compile and test the bounded portable/read-only surface; not Windows private-write qualification. |

Run the full `npm run check` on macOS/Linux before reporting a change as fully checked.
Architecture analysis uses Babel's TypeScript parser; compilation uses the
TypeScript compiler. Passing static import checks does not prove runtime
isolation, and compiling domain contracts does not establish complete engine
behavior.

For CLI changes, use the [development examples](README.md#inspect-the-development-cli)
after building. Preserve genuine local review and the explicit block on
unqualified host runs; preview is not application. Listing or rendering
canonical skills is not installation into Copilot CLI, Codex CLI, or Claude Code,
and does not establish native host compatibility. Report pure projection tests
separately from any explicitly authorized host testing. Do not run hosted agents
or model calls to make a local check appear more complete.

The workflow also restores the isolated ingestion service's own dependencies,
runs its local tests, and runs static infrastructure-as-code tests, without Azure
authentication or deployment. These are separate checks; the root command does
not substitute for their results when changing operator components.

Operator sources are excluded from the CLI package. Access checkout-only
`services/`, `infrastructure/`, `src/`, and `scripts/` paths through a source
checkout or the [repository](https://github.com/voyager163/missionspec).
Documentation included in the package must use links to included files or
repository URLs, not relative links into excluded source directories. Use code
spans when referring to checkout-only paths.

## Rights, provenance, and privacy

Submit only work you created or have permission to contribute under this
repository's [Apache-2.0 license](LICENSE). Identify third-party material and its
license, and preserve required notices. Do not copy code or prose from another
project merely because it is publicly readable; compatibility and permission
still matter.

There is no mandatory CLA, DCO sign-off, or signed-commit requirement.
Contributions are offered under the repository's Apache-2.0 license.

AI-assisted contributions are welcome on the same terms. You are responsible
for reviewing the output, checking its behavior, and verifying that you have
the necessary rights. Explain material AI assistance when it affects provenance,
verification, or how the change should be reviewed. Do not submit private
prompts or transcripts as proof.

Use small synthetic examples rather than private repositories or real customer
data. Do not include credentials, `.env` files, personal data, private source, or
raw agent or tool diagnostics in issues, pull requests, commits, or attachments.
Inspect even shortened logs before sharing them; redaction by a tool is not a
guarantee that the result is safe. Do not send someone else's confidential
material to an AI service without permission.

If a credential has already been exposed, revoke or rotate it with its provider.
Removing a public post or commit does not remove copies others may have retained.
