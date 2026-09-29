# Offline package and release handoff

MissionSpec is **not published or approved for release**. The manifest remains
`private: true` at `0.0.0`; no release version or tag has been selected. A local
tarball can be installed with those values. That does not establish a registry
identity, scope ownership, package-name availability or publication authority.

## Reproduce the bounded install check

From the source checkout, use Node.js `>=24.21.0 <25`:

```sh
npm run check:package
npm run check:package -- --install
node --test tests/package.test.mjs tests/repository-checks.test.mjs tests/skill-rendering.test.mjs tests/cli.test.mjs
npm run check:licenses
npm run check:repository
```

The first command builds and checks a dry-run file inventory, public manifest,
required assets and packaged documentation links. It neither installs a consumer
nor accesses a registry. Ordinary `npm test`, `npm run check` and
`npm run check:portable` do not implicitly enable the separate install check.

If compilation fails because checkout dependencies are missing, or the explicit
install check reports missing cached dependency tarballs, restore **only the
existing reviewed lockfile**, then retry:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run check:package -- --install
```

That restore may download the locked public dependencies; it is not part of the
offline qualification. The install checker itself never retries online, runs
`npm login` or probes registry identity or availability. A cold-cache failure is
an unmet prerequisite, not a successful install or evidence of a package defect.

The explicit `--install` mode reuses `scripts/check-package.mjs` and the
license checker's runtime dependency graph. In an owned temporary directory it:

1. Runs `npm pack --offline --ignore-scripts --json --pack-destination <temporary>`,
   checks the real archive inventory and SHA-512 integrity, and prepares a
   disposable consumer lockfile from the exact reviewed runtime closure.
2. Runs `npm ci --offline --ignore-scripts --omit=dev --no-audit --no-fund --engine-strict`
   in that consumer. This installs the local tarball, not a symlink to the
   checkout, and does not freshly resolve transitive version ranges.
3. Compares the installed package tree and file sizes with the archive inventory,
   reads its manifest and documentation links, and verifies installed dependency
   versions, resolved sources and integrity against the reviewed lock.
4. Imports the public ESM API and package metadata from the consumer, checks the
   private-subpath export boundary, loads twelve packaged skill bodies and
   renders all 36 host projections. It exercises the installed POSIX npm
   executable link, or **both actual npm `.cmd` and PowerShell `.ps1` shims**
   on Windows. Every executable surface runs `--version`, `capabilities`,
   `skills list`, one `skills render` per host, `telemetry status`, and
   `validate "proposal with spaces.md"`, using JSON output. Rendered skill
   paths and content digests must match the installed API exactly. Both the
   install and home paths contain spaces. A rejected option and blocked
   native-host operation must retain their exact JSON errors and exit codes
   1 and 2, rather than becoming successful shell exits.
5. Loads the installed `fs-native-extensions` prebuild on the actual machine and
   exercises descriptor lock/unlock on a disposable file on POSIX. It verifies
   that the read-only commands leave no user or project state, then removes only
   its own temporary directory, including the archive and consumer.

The CLI smoke deliberately does not rely on `--no-telemetry`, inherited CI/test
mode or telemetry opt-out environment variables: the normal read-only commands
must remain inert and report no configured endpoint. These overrides are removed
only from the disposable guarded child environment; no user setting is changed. A
preloaded guard fails on exercised Node HTTP/socket/fetch requests, subprocess
starts and optional model-SDK imports, even if application code catches the
failure. Every process must leave a guard-completion receipt, including expected
nonzero exits, so a shim cannot silently drop the preload. Only the harness
launches the OS shim interpreter and Node; the CLI itself cannot spawn a host.
This is a regression check for the exercised paths, **not an OS network
sandbox, native-host qualification or proof about every possible API call**.
It does not install skills into a real host, launch a coding host, obtain
authority, call a model or exercise a production telemetry endpoint.

### Hosted install coverage

The existing repository workflow now runs the explicit install command after
its locked, lifecycle-script-disabled restore and normal checks:

| Existing required context | Runner | Installed executable surface |
| --- | --- | --- |
| `Repository checks (ubuntu-latest)` | `ubuntu-latest` | POSIX npm executable link |
| `Repository checks (macos-latest)` | `macos-latest` | POSIX npm executable link |
| `Windows read-only compatibility` | `windows-latest` | npm `.cmd` and PowerShell `.ps1` shims |

This adds no job or required context, does not rename any of the 22 required
contexts, and does not repeat installs across the independent Windows
private-state/console/execution jobs. It uses the existing restore's npm cache;
no new dependency, lifecycle script, registry/authentication probe or online
fallback is enabled. Missing-cache, missing-shim, guard, exit-code or content
failures fail the existing job. Workflow regression checks require the ordered
restore/check/install steps and all three runners without skipped or masked
install steps.

On Windows the checker uses only the fixed, canonical
`C:\Windows\System32\cmd.exe` and
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, not a `PATH` or
`ComSpec` override. Cmd AutoRun and delayed expansion are disabled for that
invocation; controlled paths and arguments are validated and quoted.
PowerShell uses `-NoLogo -NoProfile -NonInteractive -File` to run the installed
shim directly. It retains the machine's execution policy: **no
`ExecutionPolicy` override, bypass, profile edit or global setting change**.
A host shell's process-scoped `PSExecutionPolicyPreference` is not inherited.
A policy refusal is an explicit qualification failure, not a reason to
silently fall back to the Node entry point.

Native-addon load is asserted on each actual runner. POSIX additionally
exercises the descriptor-associated mutex. Windows reports that POSIX mutex
check as **not exercised**; npm shim/addon-load qualification does not substitute
for the separate Windows private-state, terminal or native-host guarantees.

## What is distributed

The MissionSpec archive contains compiled CLI/library declarations and code,
canonical skill bodies and schemas, workflow profiles/examples, Windows
PowerShell runtime assets, documentation and legal notices. The checker rejects
project state, `.operator-private`, hidden files, build caches, secret/credential
paths, operator service sources, infrastructure, tests, scripts and uncompiled
sources outside the declared package surfaces. Filename checks do not replace
review for secrets embedded in otherwise allowed files.

The **133 reviewed CLI runtime dependency packages are installed separately**;
they are not 133 embedded packages inside the MissionSpec archive.
`fs-native-extensions@1.5.1` and its prebuilt native binary are among those
installed dependencies. Presence of Windows helper scripts or another platform's
prebuild in a package is not evidence that it works on that platform.
The isolated ingestion service's **63 dependency packages**, operator files and
service license inventory are not part of this CLI installation.

MissionSpec has no `preinstall`, `install`, `postinstall` or `prepare` hook.
The reviewed installed runtime closure has no `preinstall`, `install` or
`postinstall` hooks or implicit `binding.gyp` install step. Some dependency
manifests contain development `prepare` scripts; those are not executed by this
tarball-based, `--ignore-scripts` installation. The check never enables scripts
to compile or download an addon.

## Recorded local evidence

The offline install was exercised on **2026-09-27**, in a worktree based on
`b5772fb415cface3b5e7b1b786a30832b28d8e43`, with the package-check changes in this
workstream, **Node.js 24.21.0, npm 12.0.2, macOS arm64**. The command was:

```sh
npm run check:package -- --install
```

It installed the exact 133-package runtime closure, imported the six-engine API,
rendered 36 projections, used the real npm executable link, reported no
configured telemetry endpoint, and loaded
`prebuilds/darwin-arm64/fs-native-extensions.node` with successful local
descriptor lock/unlock. A separate run with an empty owned npm cache failed
explicitly as a missing-cache prerequisite without registry fallback.

Each successful run prints the archive integrity, file count, dependency count
and tested platform. Those are per-candidate evidence, not an immutable release
attestation: documentation and code edits change the archive. Preserve that
output alongside the exact final revision when preparing a real candidate.
No archive is retained or published by the checker.

On **2026-09-29**, the extended checker was exercised locally on the same
Node.js/npm/macOS arm64 baseline with spaced install and home paths, exact
API/CLI render comparisons, argument preservation, guard receipts and exit codes
0, 1 and 2. Its owned file baselines were compared with published parent revision
`ff86bc3c90dcacf5d897afc5aa70345a9d6ba0b2`; the isolated worktree's product code
remained based on `b5772fb415cface3b5e7b1b786a30832b28d8e43`.

**Hosted results for this extended checker are pending.** This workstream has
not run the installed-tarball smoke on Linux, Windows, macOS x64 or other
architectures. Windows shim construction tests on macOS and the new workflow
steps are implementation evidence, not actual Windows execution evidence.
Publish the reviewed candidate through the separately authorized parent
workflow and record its runner platform/architecture, candidate revision,
archive integrity and `cliSurfaces` output before claiming those platforms.
Existing hosted source-checkout qualification remains separate evidence.

## Remaining maintainer gates

| Gate | Current boundary and required decision |
| --- | --- |
| Publishing identity and scope | Prior `npm whoami` returned `ENEEDAUTH`; unauthenticated `npm view` returned `E404`. Neither establishes who may publish, whether the scope is available, or that the package is unclaimed. The maintainer must separately authorize and establish registry identity, scope/name control and publishing rights. Do not publish to discover availability. |
| Release metadata and authority | Select a version, release/tag policy, distribution/access policy and supported platform matrix explicitly. Review corresponding manifest/check changes in a PR; keep `private: true` and `0.0.0` until that decision. Publication, tags and pushes require separate authority. |
| Final candidate qualification | Rerun the normal repository/license checks and explicit offline install on the exact candidate. Qualify every advertised OS/architecture, native-addon load and package-manager executable surface, including Windows shims. A local macOS pass and earlier hosted source checks are not interchangeable. |
| Native hosts and billing | Claude Code and Codex live pilots are deferred. Copilot default-model/zero-extra-charge evidence remains unresolved. No paid model calls are admitted by this checklist. Rendered skills and installed package smoke do not qualify live hosts or enable autonomous execution. |
| Telemetry operations | Normal CLI composition has no production endpoint. Enforced NSP and bounded live qualification are selected, but control-plane deployment and actual delivery remain unqualified until separately reviewed operator execution succeeds. The created queue storage's original failed qualification is preserved. Do not weaken inherited policy or probe endpoints as an install test. |
| Claims and provenance | Review the final archive and retained CLI notices, state tested platforms and remaining limitations, and keep the operator/service closure separate. Liftoff package-manager migration, Mission Context implementation and Artifact Server remain out of scope. |

See [maintainer setup](maintainer-setup.md) for hosted controls and authority,
[licensing](licensing.md) for the reviewed dependency evidence, and
[native skill installation](architecture/installation.md) for the separate
reviewed skill-file maintenance surface.
