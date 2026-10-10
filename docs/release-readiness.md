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
license checker's runtime dependency graph. Its owned `.package-install-*`
temporary directory is created beneath the checkout, outside the declared
package surfaces, with explicitly private `0700` consumer/home directories on
POSIX. A general Linux `/tmp` parent is unsuitable: the unchanged preference
reader refuses world-writable ancestors even when the temporary leaf is private.
The checker neither changes ancestor permissions nor relaxes that policy.
Within this disposable directory it:

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
   that read-only commands leave the independently established fixture-home
   baseline unchanged and create no project state, then removes only its own
   temporary directory, including the archive and consumer.

The CLI smoke deliberately does not rely on `--no-telemetry`, inherited CI/test
mode or telemetry opt-out environment variables: the normal read-only commands
must remain inert and report no configured endpoint. These overrides are removed
only from the disposable guarded child environment; no user setting is changed. A
preloaded guard fails on exercised Node HTTP/socket/fetch requests, subprocess
starts and optional model-SDK imports, even if application code catches the
failure. Every process must leave a guard-completion receipt, including expected
nonzero exits, so a shim cannot silently drop the preload. Only the harness
launches the OS shim interpreter and Node; the CLI itself cannot spawn a host.
The harness explicitly ends each noninteractive child's stdin. A PowerShell
shim forwarding redirected `$input` must receive EOF rather than wait for
interactive input. Smoke deadlines remain 30 seconds (pack/install: 120 seconds).
Process failures report bounded exit/signal/killed/timeout metadata and output
byte counts, not commands, environment values or captured child output.
This is a regression check for the exercised paths, **not an OS network
sandbox, native-host qualification or proof about every possible API call**.
It does not install skills into a real host, launch a coding host, obtain
authority, call a model or exercise a production telemetry endpoint.

### Hosted install coverage

The repository workflow runs the explicit install command after its locked,
lifecycle-script-disabled restore and normal checks. Linux/macOS perform it
once in each `Repository contracts` worker; the existing required contexts
aggregate those workers with the complete independent ARM matrix:

| Existing required context | Runner | Installed executable surface |
| --- | --- | --- |
| `Repository checks (ubuntu-latest)` | `ubuntu-latest` | POSIX npm executable link |
| `Repository checks (macos-latest)` | `macos-latest` | POSIX npm executable link |
| `Windows read-only compatibility` | `windows-latest` | npm `.cmd` and PowerShell `.ps1` shims |

All 22 required context names remain unchanged. The aggregate gates explicitly
fail if either workload matrix fails, is cancelled or skipped, or has no
successful result. Repository/service workers and aggregate gates keep their
ten-minute job limits; only ARM shard jobs use the explicitly approved
fifteen-minute CI limit. Test coverage and production deadlines are unchanged.
Installs are not repeated across
the independent Windows
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

Before importing the installed API or running either Windows shim, the checker
starts the fixed Windows PowerShell executable against a small owned script
that only exercises `Split-Path` and `Test-Path`, the OS cmdlets used by the npm
shim. This independent baseline starts with an empty disposable home and does
not load Node, MissionSpec, profiles or model hosts. A second invocation must
leave the **same exact home inventory**. A changing or unreadable interpreter
baseline fails; there is no retry-until-stable or wildcard allowance.

After that, every installed API/CLI process must complete its Node preload
receipt and leave the same relative paths, entry types, file sizes and SHA-256
digests in that home. This detects added, removed and modified state, including
writes under interpreter-created directories. It does not simply permit
`AppData` or known-looking cache names. POSIX retains an empty baseline.
Successful Windows output includes `interpreterHomeBaseline` so the observed
OS startup effects remain separate from product read-only evidence.

Home inventory diagnostics are restricted to fixtures created by this checker:
at most 64 entries, 8 directory levels, 256 characters per relative path and
1,000,000 total file bytes for hashing. Symlinks, hard-linked files, other
nonregular entries, unstable reads and exceeded limits fail. Files are read
through held descriptors; diagnostics include names/types/sizes/digests, never
file contents, link targets or real-user home data. An unchanged baseline is a
bounded before/after observation, not proof against transient writes or a
hostile process and not a filesystem sandbox.

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

### Initial hosted failures and fixture correction

The parent published candidate
`ee973e1ec09d9ec22afa2149a8bdf1ae3bc4684c`; the supplied hosted logs identify tested
merge revision `ce4eda893e85d82774f1be30ef24c3a33477eff4`. The parent reported the
full macOS job and actual installed smoke passing. Original Linux and Windows
source/portable checks passed, but their added installed smoke **failed**:

| Job | Retained failure | Follow-up boundary |
| --- | --- | --- |
| Linux `109266015335` | `telemetry status` returned `capability-unavailable` / `preference-read-failed` beneath `/tmp`. | The reader rejects `/tmp`'s writable ancestor mode before reaching the private leaf. A local regression reproduces this with an owned `1777` ancestor and a `0700` home. Move only the fixture beneath the checkout and create private directories; do not weaken the production checks or add telemetry opt-outs. |
| Windows read-only `109266015143` | The actual npm PowerShell shim's first `--version --json` invocation failed with no captured diagnostics. The old runner did not record whether the child was killed or timed out. | Node `execFile` leaves piped stdin open; the inspected npm PowerShell shim generator supports forwarding `$input`. An EOF-waiting child reproduces the hang locally and completes when stdin is ended. Close the pipe and retain the original deadline; native Windows confirmation still requires a hosted rerun. |

The inspected local npm version was `12.0.2` (`cmd-shim` `9.0.2`); supplied
hosted logs report npm `11.19.0`. Local shim source inspection and the portable
EOF regression do not authenticate the exact hosted shim bytes or establish an
actual Windows pass. The original failures are retained, not reclassified as
successful qualification. No timeout increase, execution-policy bypass, skip,
Node-entry fallback or production privacy change is made.

### Remaining Windows home-state attribution

The parent published fixture corrections with the separate descriptor-first
report-input fix as `4e06ac952657f7849d4b13d52db5958124446a57`. It reported actual
Linux and macOS installed-smoke passes and a native CodeQL pass. The retained
Windows job `109409264632` progressed through all actual `.cmd` and `.ps1`
invocations and their receipt/output/exit checks, then failed the final
empty-home assertion with **`AppData`**. That is still a failed qualification,
not a passing Windows installation.

The log does not contain `AppData`'s descendants, hashes or creator. It is
therefore insufficient to call that directory a PowerShell analysis cache or
to excuse its contents. The new product-free interpreter baseline and native
regression above establish whether the fixed OS interpreter creates that state
on the actual runner. Only independently observed, repeatably unchanged entries
can precede the product smoke. Any further state from a shim or product command
fails at that command's `api`, `cmd` or `powershell` phase with bounded baseline
and actual inventories. No cache deletion, execution-policy change, preload
relaxation, deadline extension or Node-entry fallback is used.

### Actual hosted installed-package qualification

On 2026-09-29, candidate `ea2344d9b1a50825906bebcffae4524b852165b1`
passed the three installed-package surfaces in repository run `36570852865`.
The Windows checkout recorded merge revision
`30dd3af`, based on that exact candidate. All three installed 133 runtime
dependencies and 379 archive files, imported six engines and rendered 36 skills.

| Job | Actual platform | Executable surfaces and native result |
| --- | --- | --- |
| `109414186170` | Linux x64 | POSIX npm executable; `linux-x64` addon and descriptor lock/unlock |
| `109414186251` | macOS arm64 | POSIX npm executable; `darwin-arm64` addon and descriptor lock/unlock |
| `109414186326` | Windows x64 | Both npm `.cmd` and `.ps1`; `win32-x64` addon loaded, POSIX mutex not exercised |

The independent Windows PowerShell regression observed exactly two empty
directories, `AppData` and `AppData/Roaming`, before any product launch.
Both baseline invocations agreed, and every guarded installed API/shim
invocation preserved that inventory. No file or cache-content exception was
needed. The original failed candidates remain failures.

The retained archive integrities were:

```text
Linux/macOS: sha512-4iroQPlEbYKAFEmi/ovV6pLmQMWxihi6uTBmPy7NcYKVFBnNUzkDm1x0x19irj6YvcJ7Ua/qQemw0yUDanL51Q==
Windows:     sha512-KlrRuz9cqyFylRvhwwFZQzX8R5oULMNdn7agY+3R5Wq12AMcd2S5/EqH3+rjkZMKOFoZIEkEOCtMJagLPQ2Myg==
```

These are platform-specific candidate artifacts, not a published release or
proof of one byte-identical cross-platform archive. Future candidates must run
the same checks again. Other architectures remain untested; installed package,
source-checkout execution and native AI-host qualification remain distinct.

## UAT maintainer handoff

UAT deployment is a maintainer action, separate from the repository merge.
For local CLI UAT, use the bounded install procedure above on the exact accepted
candidate; a successful source build alone is not an installed-package check.
The normal CLI must continue to report no configured production telemetry
endpoint, and native autonomous execution must remain disabled unless its
independent host qualification is established.

The cleaned-successor changes update the reviewed collector operator protocol,
not its ARM topology. They do not require new resource templates or define dev,
staging or UAT resource aliases. Any separate UAT collector needs an explicit
private target configuration and its own cost, source, current-state and phase
approvals. Do not deploy the existing migration's intents or copy its authority
to another environment. Follow the [operator procedure](telemetry-operator.md);
an install smoke must never enable a collector or send events to Azure.
The source checkout's `infrastructure/arm/telemetry/README.md` documents the
collector UAT boundary; infrastructure is deliberately not packaged with the CLI.

## Interpreting qualification evidence

Keep retained read artifacts separate from observed command invocations. A
bounded reader can reject unstarted queued requests with the first command's
failure and retain a failed artifact for each request. Multiple artifacts carrying
a timeout code therefore do not establish that the same number of commands were
admitted or exceeded their deadlines. Establish command counts from actual
admission, start, end, deadline and outcome observations; do not invent an
artifact-to-command binding when those records are absent.

Report authentication/setup, driver preparation, CHECK duration, actual read
span and post-operation custody separately. Whole-process wall time is not a
substitute for CHECK or command timing. Missing measurements remain unavailable,
not zero or inferred successes. Preserve the original failure alongside separate
reconciliation, custody and persistence failures. Source-free helper regressions
and metadata review do not establish a genuine production CHECK or qualify an
unchanged deadline.

Finalize process logs and mutable-world custody only after the owned process
group is quiescent. Authenticate retained bytes and the original observed file
identities where available; byte-identical replacement is not original custody.
Keep failed attempts and consumed grants immutable. A new attempt requires its
own current review, genuinely valid facts and distinct authority. Reauthenticating
old evidence does not renew its retrieval time or expiry, and a passed fixture
does not authorize a scan, download, replay, publication or infrastructure effect.

## Remaining maintainer gates

| Gate | Current boundary and required decision |
| --- | --- |
| Publishing identity and scope | Browser-based npm login was completed on 2026-10-10; `npm whoami --registry=https://registry.npmjs.org/` returned `voyager164`. This establishes that laptop's CLI identity only, not verified package/scope publishing rights or publication authority. Earlier `ENEEDAUTH` and unauthenticated `E404` observations remain historical; they do not establish name availability. Reauthenticate independently on a new laptop and verify the maintainer-asserted scope control. Never commit credentials or publish to discover availability. |
| Release metadata and authority | Select a version, release/tag policy, distribution/access policy and supported platform matrix explicitly. Review corresponding manifest/check changes in a PR; keep `private: true` and `0.0.0` until that decision. Publication, tags and pushes require separate authority. |
| Final candidate qualification | Rerun the normal repository/license checks and explicit offline install on the exact candidate. Qualify every advertised OS/architecture, native-addon load and package-manager executable surface, including Windows shims. A local macOS pass and earlier hosted source checks are not interchangeable. |
| Native hosts and billing | Claude Code and Codex live pilots are deferred. Copilot default-model/zero-extra-charge evidence remains unresolved. No paid model calls are admitted by this checklist. Rendered skills and installed package smoke do not qualify live hosts or enable autonomous execution. |
| Telemetry operations | Normal CLI composition has no production endpoint. The replacement Queue Private Link control-plane path is implemented; actual private delivery, bounded runtime qualification and ordered retirement remain separate operator gates. Historical failed windows and cleanup outcomes stay immutable. Do not weaken inherited policy or probe endpoints as an install test. |
| Claims and provenance | Review the final archive and retained CLI notices, state tested platforms and remaining limitations, and keep the operator/service closure separate. Liftoff package-manager migration, Mission Context implementation and Artifact Server remain out of scope. |

See [maintainer setup](maintainer-setup.md) for hosted controls and authority,
[licensing](licensing.md) for the reviewed dependency evidence, and
[native skill installation](architecture/installation.md) for the separate
reviewed skill-file maintenance surface.
