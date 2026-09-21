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
Source publication and the first hosted workflow runs are being prepared.
Required status checks remain intentionally unset until actual hosted runs
establish their identities and behavior. Do not describe the repository as fully
hardened or claim the normal/failing PR merge paths have been exercised.

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

The local workflow is named `Repository checks`. Its job display template is
`Repository checks (${{ matrix.os }})`, configured for `ubuntu-latest`,
and `macos-latest`. A separate `Windows read-only compatibility` job runs
`check:portable` on `windows-latest`, rather than running unsupported POSIX
write/TTY tests or implying Windows ACL qualification. These labels are **not verified
required status identifiers**. Matrix expansion and workflow revisions can alter
the check names GitHub presents.

The local definition uses full-SHA-pinned actions and a read-only token, without
secrets or caches. Its isolated service and static infrastructure checks do not
authenticate to Azure or deploy anything. This definition does not change
repository-wide action settings or establish that a hosted run has succeeded.

Two additional local definitions are present:

- `CodeQL analysis` covers JavaScript/TypeScript and GitHub Actions without
  running project build scripts. Its analysis job has only the extra reporting
  permissions `actions: read` and `security-events: write`. No broader write
  permission or privileged PR trigger is allowed.
- `Dependency review` checks changed dependency graphs for high/critical
  findings and the explicit license allowlist, without writing PR comments.

These definitions have not run on GitHub. A successful CodeQL analysis/upload
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
fallback address or reuse the conduct contact. The updated policy and issue forms
remain local until the separately authorized publication step; hosted enablement
does not itself publish these document edits.

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
present the project as release-ready while required hosted checks remain unqualified,
or turn planned hosts and skills into advertised working features.

Before closing a setup milestone, distinguish:

- **Local evidence:** reviewed files and recorded build, test, static import,
  repository policy, and dry-run package check results; separate service and
  static infrastructure test results, without implying native host qualification
  or deployment.
- **Hosted evidence:** approved changes, observed workflow runs, exact required
  check identifiers, settings readbacks, and a usable sole-maintainer PR path.
- **Outstanding work:** disabled or unverified controls, especially private
  security reporting, and any publication that has not been separately approved.
