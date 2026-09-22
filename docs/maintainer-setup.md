# Maintainer setup

This guide accompanies the MSR00 local repository foundation and subsequent
development checks. It is a staged checklist, **not authorization** to push,
change GitHub settings, execute hosted workflows or agent/model calls, or publish
anything. The reviewed local workflow CLI is usable, but is not a supported
release or evidence of hosted activation or native execution qualification.

## Observed baseline

The following is the read-only baseline recorded during MSR00 preparation, not a
promise that settings cannot change. Read settings back before making a hosted
change and after it is applied.

| Area | Observed state |
| --- | --- |
| Repository | Public; Apache-2.0; default branch `develop` |
| Branch controls | `main` and `develop` unprotected; no rulesets |
| Actions permissions | Read-only default workflow token; workflows cannot approve pull requests |
| Action sources | All actions allowed; full-SHA enforcement off |
| Fork workflow approval | Approval required for first-time contributors |
| Secret scanning and push protection | Enabled |
| Dependabot security updates | Enabled |
| CodeQL | Not configured |
| Community channels | Issues on; Discussions off |
| Private vulnerability reporting | **Disabled: private intake remains an operational blocker** |

### Activated controls, 2026-09-21

The subsequent request to complete outstanding repository setup activated and
read back these hosted controls:

- GitHub private vulnerability reporting: enabled.
- Ruleset `23748370`, **MissionSpec protected branches**: active for `develop`
  and `main`, with no configured bypass actors.
- Pull requests and resolved review conversations required; zero approving
  reviewers, no last-push approval, no code-owner approval, and no extra approval
  for unattributed changes.
- Force pushes and branch deletion prohibited.

The effective branch-rules API confirms both branches inherit these rules.
The implementation has been committed and published through a pull request.
After observing successful hosted runs, twelve required check contexts were bound
to their actual GitHub Apps, with strict up-to-date-branch enforcement:

| Required context | GitHub App ID |
| --- | --- |
| Repository checks (ubuntu-latest) | 15368 (`github-actions`) |
| Repository checks (macos-latest) | 15368 (`github-actions`) |
| Windows read-only compatibility | 15368 (`github-actions`) |
| Windows private-state qualification | 15368 (`github-actions`) |
| Windows held-handle race qualification | 15368 (`github-actions`) |
| Windows workflow (source) | 15368 (`github-actions`) |
| Windows workflow (recovery) | 15368 (`github-actions`) |
| Windows workflow (pruning) | 15368 (`github-actions`) |
| Dependency review | 15368 (`github-actions`) |
| CodeQL (javascript-typescript) | 15368 (`github-actions`) |
| CodeQL (actions) | 15368 (`github-actions`) |
| CodeQL | 57789 (`github-advanced-security`) |

Initial qualification revision: `2f92429cf508912eeae89a7aa964d5708aeb97dd`, with
GitHub's tested merge revision `4f1db30b1eba870612ed1d10b397e81e68cd4223`.
[Repository checks](https://github.com/voyager163/missionspec/actions/runs/35570034629),
[CodeQL analysis](https://github.com/voyager163/missionspec/actions/runs/35570034539)
and [dependency review](https://github.com/voyager163/missionspec/actions/runs/35570034657)
passed. Both CodeQL categories reported successful analysis and no open alerts
on that PR merge revision. GitHub reported the PR mergeable and clean after
enforcement, without requiring another person's approval. No administrative
merge bypass was used.

The initial runs correctly failed on a macOS scheduling-dependent test
assertion and a Dependency Graph licensing discrepancy; both were addressed
before requiring the check identities. The
[exact-version license guard](licensing.md#reviewed-dependency-graph-metadata-discrepancy)
documents the latter. Successful scans are not a security certification or proof
of native-model behavior.

Subsequent Windows private-storage and directory-barrier qualification passed
at `d684dbb`; the source, recovery and pruning application scenarios passed at
`bbd2f97`. That application revision also produced six CodeQL filesystem-race
findings, correctly blocking merge. The replacement
[held-handle protocol](architecture/windows-file-races.md) cleared all six
findings with the query unchanged. At `8c2e3f0`, all six native
race/security/rename/recovery cases passed on Windows with zero skips, while
application reruns caught an initial-creation regression.

The four additional Windows contexts were bound only after verifying their
successful reports and exact App identities: application contexts at `bbd2f97`
and the native race context at `8c2e3f0`. Failures block
merge; historical success establishes a check identity, not qualification of
later code. Readback confirmed all twelve effective contexts on both protected
branches and a blocked draft PR during the regression.

The corrected implementation at `e4e5b13ebf224d81490e02eab1dbe7427dd7ca87`
passed all twelve required checks. In
[run 35636916251](https://github.com/voyager163/missionspec/actions/runs/35636916251),
eight native race/setup cases passed with zero skips, followed by the full
source, recovery and pruning jobs. Both CodeQL categories and the native CodeQL
check passed with zero open alerts on the PR merge ref. GitHub reported the
revision clean under the active protections, without a merge bypass. Windows
terminal/ConPTY confirmation and native execution remain separate disabled
capabilities; this is development qualification, not a product release.

## 1. Validate locally

Use Node.js 24 LTS (`>=24.21.0 <25`); the current local validation baseline is
24.21.0:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check
```

`check` runs tests, architecture import checks, repository policy checks, and npm
package boundary/link and locked-license checks. Tests first build TypeScript
using `tsc -p tsconfig.json`.
Architecture checks use static TypeScript import analysis; the repository
checker validates local Markdown links and heading anchors, issue form YAML,
required documents, and workflow policies. It does not fetch external
links, run hosted checks, or prove that GitHub enforces any control. Individual
commands are listed in the
[development check reference](../CONTRIBUTING.md#development-checks).
`npm run check:package` inspects the npm dry-run package boundary and included
links; it is not a publish step.

The CLI supports read-only inspection and separately reviewed setup, editing,
installation, check collection and closure; see the
[checkout examples](../README.md#inspect-the-development-cli).
Twelve canonical sources and 36 native-format projections have local
integration coverage, not native host qualification. Autonomous host execution
remains disabled without real qualification. Local telemetry controls do not
activate an operational production endpoint or deployment.

The workflow separately restores isolated service dependencies, runs local
service tests, and runs static infrastructure-as-code tests without Azure
authentication. Record those results separately from root checks; none is
authorization to deploy or run a host or model.

Operator sources are intentionally excluded from the CLI package. Refer to
checkout-only `services/`, `infrastructure/`, `src/`, and `scripts/` paths as code
or use the [source repository](https://github.com/voyager163/missionspec).
Do not add relative documentation links into excluded directories: navigation
must also work within the dry-run package.

Record what revision was checked and any limitations. These are repository
checks, not product CLI commands. Inspect the actual changes, including
dependency and workflow changes, rather than treating a successful check as
proof of safety.

Keep the Apache-2.0 `LICENSE` intact. Review provenance and required notices for
new material, including AI-assisted contributions. Publicly available code or
documentation is not automatically compatible with the project's license.

## 2. Obtain separate authority for hosted work

Before remote work, obtain explicit authority for the specific push, pull
request, settings change, workflow execution, or publication. Approval of local
implementation is not approval of these actions. Do not infer permission to run
cloud agents, external agent hosts, or model services from this checklist.

Use a working branch and a pull request targeting `develop` for repository
changes. Do not silently bypass the PR process to bootstrap controls. If a
workflow needs to exist on the default branch before an event can run, explain
that dependency and obtain approval for the minimal PR-based bootstrap path.

Review workflows, validation scripts, branch controls, release configuration,
and security policy deliberately. **Do not blindly auto-merge control changes**,
even when automation proposes them and all checks are green.

## 3. Qualify checks before requiring them

The workflow is named `Repository checks`. Its job display template is
`Repository checks (${{ matrix.os }})`, configured for `ubuntu-latest`,
and `macos-latest`. A separate `Windows read-only compatibility` job runs
`check:portable` on `windows-latest`, rather than running unsupported POSIX
write/TTY tests or implying Windows ACL qualification. The observed required
identities above are specific to the qualified revision. Matrix expansion and
workflow revisions can alter the names; coordinate any rename with the ruleset.

`Windows private-state qualification` exercises actual NTFS/SID/ACL storage and
directory barriers. `Windows held-handle race qualification` exercises concurrent
file/ancestor replacement and recoverable publication; it is a prerequisite for
the three `Windows workflow (source|recovery|pruning)` jobs. Each native job has
its own 15-minute bound. Add new contexts to required checks only after observing
their actual successful reports and GitHub App identities; never substitute
local Windows skips or an older protocol's results.

The local definition uses full-SHA-pinned actions and a read-only token, without
secrets or caches. Its isolated service and static infrastructure checks do not
authenticate to Azure or deploy anything. This definition does not change
repository-wide action settings or establish that a hosted run has succeeded.

Two additional hosted definitions are present:

- `CodeQL analysis` covers JavaScript/TypeScript and GitHub Actions without
  running project build scripts. Its analysis job has only the extra reporting
  permissions `actions: read` and `security-events: write`. No broader write
  permission or privileged PR trigger is allowed.
- `Dependency review` checks changed dependency graphs for high/critical
  findings and the explicit license allowlist, without writing PR comments.

These definitions passed the recorded GitHub runs. A successful CodeQL analysis/upload
does not mean it found no vulnerabilities. Qualify actual finding behavior,
dependency graph coverage (including the isolated service), fork behavior, and
any native code-scanning merge protection separately. License metadata checks
are assistance, not blanket legal clearance. Do not widen privileges or silently
waive unknown coverage to make a required check pass.

After authorized publication of the workflow:

1. Observe real push and pull-request runs on the intended matrix. Confirm that
   the expected jobs run, finish, and report both success and failure correctly.
2. Confirm the workflow uses the intended Node.js version and locked dependency
   installation, and runs the same repository check as local validation.
3. Verify fork behavior and the approval path with an appropriately authorized
   test. Treat contributor code as untrusted: do not expose secrets or elevate
   token permissions to make fork checks work, and do not run untrusted PR code
   in a privileged `pull_request_target` workflow.
4. Record the exact check identifiers observed in GitHub, along with the
   workflow revision and event types. Resolve missing, skipped, or perpetually
   pending checks before making any of them mandatory.

Only then propose required checks. Do not copy a guessed workflow or matrix job
name into protection settings. Renaming or splitting a required job later needs
a coordinated settings update and a fresh readback.

## 4. Introduce branch controls without lockout

With separate approval, configure the approved PR-only ruleset or branch
protection for both `develop` and `main`.
Check the account's available features rather than assuming every control can
be enabled.

- Require pull requests, with **zero required approving reviewers** for the
  sole-maintainer workflow. Maintainer-authored PRs are valid; do not create a
  second-person approval deadlock.
- Require only qualified, observed checks. Do not add a mandatory CLA, DCO,
  signed-commit, or code-owner-approval gate as part of this baseline.
- Consider force-push and deletion restrictions in the approved configuration.
  Do **not** enable a whole-branch “Restrict updates” lock that prevents the
  maintainer from merging ordinary PRs.
- Read the effective configuration back. Verify a normal PR can merge when it
  satisfies the controls and that a failing required check prevents the intended
  merge path. Document any bypass or recovery route.

These controls cannot provide an owner-immutable guarantee. A repository owner
may retain the ability to change controls or use configured exceptions. State
the actual enforcement and trust boundary rather than claiming otherwise.

## Private-reporting publication gate

Private vulnerability reporting was enabled and API readback verified on
2026-09-21. The standard advisory-report route redirects anonymous visitors to
GitHub sign-in; no sensitive report was submitted as a configuration test.
The conduct email remains **conduct-only**.

For later changes to the reporting configuration:

1. Obtain explicit approval to enable GitHub private vulnerability reporting.
2. Enable it only under that authority, then read the setting back.
3. Verify that the repository presents the intended private reporting route to
   eligible reporters. Do not submit real sensitive findings as a configuration
   test.
4. Only after successful verification, update `SECURITY.md`, the README, and
   contributor and issue guidance to describe the actual available route.

Keep the documented state aligned with verified API readback. Never invent a
fallback address or reuse the conduct contact. The policy and issue forms are included in the publication PR; hosted enablement
does not itself merge these document edits into the default branch.

## Further controls and publication

Repository-wide action allowlists, full-SHA enforcement, and code-scanning merge
controls are not activated by these local workflow files or this guide. Propose
them separately, review the needed permissions and trusted
dependencies, qualify new checks before requiring them, and verify the resulting
settings. Preserve least privilege and the inability of workflow tokens to
approve PRs unless a separately approved design explicitly changes that policy.
Existing secret scanning, push protection, and Dependabot security updates are
useful controls, not comprehensive guarantees.

A push is not a release. Tags, GitHub releases, npm publication, announcements,
and any hosted execution require their own explicit authority. The planned
`@msn-control/missionspec` package has no usable product release yet. Do not
present the project as release-ready while native/platform/cloud qualification remains incomplete,
or turn planned hosts and skills into advertised working features.

### npm release preparation

The selected distribution is `@msn-control/missionspec` on the public npm
registry. Keep the development manifest private until a release is explicitly
approved. Selecting the npm channel or approving an Azure deployment is not
permission to publish a package or merge a pull request.

Before requesting final publication approval:

1. Verify the local publishing identity with
   `npm whoami --registry=https://registry.npmjs.org`. An `ENEEDAUTH` result
   requires the maintainer to authenticate locally; never request a token,
   password, recovery code or one-time password in an issue or chat.
2. Verify that identity's organization and exact package permissions. Scope
   ownership stated in a plan is not a successful authentication/access check.
   An unauthenticated package lookup returning `E404` does not establish scope
   ownership, name availability or the absence of a private package.
3. Select an unused release version after an authenticated registry read.
   Identify the exact candidate commit, supported host/platform combinations and
   remaining limitations. Preserve the distinction between rendered skills,
   real host behavior and native autonomous execution.
4. Build and inspect the actual packed archive, including executable/export
   paths, resource loading, dependency closure, notices and absence of private
   state. Bind the archive digest and applicable qualification evidence to the
   release candidate; a dry-run package listing alone is not an installation
   or provenance demonstration.
5. Obtain final approval for the named version and artifact before changing
   release metadata or publishing. Use scoped publishing credentials or a
   separately configured trusted publisher; do not introduce a long-lived npm
   token into source, logs or workflow definitions.

Registry authentication and membership output are operator information. Do not
commit them or substitute a different account when the selected identity lacks
access. No release-preparation command should silently publish, tag or announce
a release.

Before closing a setup milestone, distinguish:

- **Local evidence:** reviewed files and recorded build, test, static import,
  repository policy, and dry-run package check results; separate service and
  static infrastructure test results, without implying native host qualification
  or deployment.
- **Hosted evidence:** approved changes, observed workflow runs, exact required
  check identifiers, settings readbacks, and a usable sole-maintainer PR path.
- **Outstanding work:** disabled or unverified controls, especially private
  security reporting, and any publication that has not been separately approved.
