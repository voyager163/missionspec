# MissionSpec cross-laptop handoff

Prepared after the user's 2026-10-11 01:00 +08:00 handoff request.
This is a continuation guide, not a release approval or execution receipt.

## Start here

**Product and cloud qualification are incomplete. Work was paused by the user
on 2026-10-10. The new request authorizes writing this handoff and committing/
pushing source backups, not restarting scans, native CHECKs, cloud actions or
model pilots. Ask for an explicit resume before those activities.**

Use `missionspec-foundation` as the primary continuation branch. PR
[#1](https://github.com/voyager163/missionspec/pull/1) targets `develop` and was
OPEN/unmerged when independently checked for this handoff. Refresh GitHub before
relying on its current state. Do not merge the archival WIP branches wholesale.

```sh
git clone https://github.com/voyager163/missionspec.git
cd missionspec
git fetch origin
git switch missionspec-foundation
git status --short
git log -5 --oneline
```

Install a supported Node.js 24 version: **`>=24.21.0 <25`**. The previous macOS
arm64 baseline was Node.js 24.21.0; its Homebrew absolute executable path is not
a portable requirement. Restore dependencies only when needed on the new clone:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node dist/cli/main.js capabilities --json
```

A fresh clone can read specifications and build source, but it cannot recreate
trusted approvals, ledger facts or native qualification from this document.
Do not run any old `.copilot` diagnostic entrypoint merely to resume the session.

## Repository and backup map

Repository: `voyager163/missionspec`, public, Apache-2.0.
Default/PR target branch: `develop`. Main integration branch:
`missionspec-foundation`. Before this handoff its HEAD was
`0ecf219f79cf2884a68aa7bdb629693e2e275d85`.
The handoff commit adds this document and the pending release-evidence guidance.
Its exact revision is discoverable with `git log` after checkout; this document
does not attempt to embed its own commit hash.

The user explicitly approved committing and pushing each old worktree's source
on its **existing branch**, separately from the main handoff. These are archival
WIP snapshots, not newly integrated or end-to-end-qualified candidates:

| Existing branch | Exact snapshot commit | Saved source files | Identical to main / different or absent |
| --- | --- | ---: | ---: |
| `voyager163-effective-policy-preflight` | `38c19f34775b7ab78bcf26dfeec282e0edf8b714` | 4 | 1 / 3 |
| `voyager163-patched-telemetry-runtime` | `49599fdf6e9ef1c25c9624078b9b6ca20267c83c` | 5 | 5 / 0 |
| `voyager163-queue-storage-adoption` | `5eb2bd84f15813edb8b672a5f30ffd53ee26160d` | 9 | 3 / 6 |
| `voyager163-release-install-readiness` | `0a834cb0ded41cf8b00b7212549c6894a27f85ee` | 80 | 64 / 16 |
| `voyager163-queue-defender-preservation` | `cca08cd0f576e89bfa8d721794fca13a12e54f8b` | 12 | 6 / 6 |
| `voyager163-queue-readback-hardening` | `a4b6fe76cf1e47e7329a866d8ad1b6819289afb8` | 5 | 3 / 2 |
| `voyager163-enforced-nsp-rollout` | `e415f9ad6c8b24ce1fedbfae97ab2c4ef203f943` | 66 | 58 / 8 |

Counts compare saved file bytes with main before this handoff, **not entire
branch contents**. Branches have older, divergent bases. Many changes were
previously integrated into main; a different file is not necessarily a missing
improvement. Inspect the exact delta and provenance before adopting anything.
The `voyager163-nsp-readiness-and-billing` worktree had no uncommitted changes.

All selected WIP JavaScript/Python sources received syntax checks; JSON files
were parsed, and committed blobs were compared with the saved byte hashes.
These checks do not establish behavior. Full suites were not rerun for the WIP
snapshots. One pre-existing trailing-whitespace line in
`private-link-runtime.mjs` was deliberately preserved on the release-install
branch rather than changing archived bytes.

Temporary `.v7-working/` and the hidden
`tests/.private-link-nsg-runtime-77317a75-0753-49cb-b40d-855311f1375a/` directory
remain on the old machine and were not committed or deleted. Build caches,
operator-private state, raw diagnostics, tokens, `.npmrc` and session databases
are not part of these backups.

## Background and settled product decisions

The user prefers OpenSpec's incremental change workflow and asked for deeper
comparison with Spec Kit, clear replacement names, a maintainable folder layout,
core verify/archive operations, and research on plannotator/artifact-server.
MissionSpec is an independently authored implementation, not a source/template
fork of those projects.

### Workflow and artifact behavior

| Operation | Confirmed behavior |
| --- | --- |
| `discover` | Discover the problem. Read/discuss by default; save requested findings only inside the selected change. |
| `draft` | Draft exactly one next ready artifact node, then stop. A node can be a declared multi-file spec set. |
| `draft-all` | Fast-forward remaining required drafts using the same graph and validation; stop before implementation. |
| `implement` | Work only within separately authorized current scope; Interactive is default, Auto is explicit opt-in. |
| `verify` | Core workflow, not optional. Report actual evidence and gaps; no automatic repair or acceptance. |
| `archive` | Core guided closure, preserving the true accepted/rejected/cancelled/incomplete outcome. |

Six default helper skills: `revise`, `clarify`, `analyze`, `principles`, `sync`,
`onboard`. There are **12 canonical skills and 36 projections** for Copilot CLI,
Codex CLI and Claude Code. Do not create a skill for every deterministic CLI
verb. `proposal`, `design`, `specs` and `tasks` are artifact names, not additional
mandatory lifecycle commands. `draft-all` replaces the proposed fast-forward
name; no required `ff` alias or duplicate `propose`/`prepare` workflow.

Discovery creates nothing by default. First draft may scaffold change metadata,
but must not also author the remaining artifacts. Both drafting modes preserve
user edits and block on material questions, missing declared outputs, staleness
or invalid dependencies. Standard is default; Compact is explicitly selected
and does not weaken authority or evidence. Tasks/check plans normally live in
`tasks.md`; an explicitly declared `verification.md` is a jointly captured
expanded plan, not executed results.

Archive guides separate acceptance, conflict-aware sync and closure rather than
requiring three manual commands first. Those records and confirmations remain
distinct. Advanced `accept`/`sync` utilities are still available. Incomplete
archive is not acceptance or baseline promotion.

### Architecture and storage

One TypeScript/Node ESM package, **`@msn-control/missionspec`**, executable
**`missionspec`**, with six internal engines:

| Engine | Ownership |
| --- | --- |
| Discovery | Problem framing, observations, focused clarification |
| Specification | Canonical Markdown, revisions/deltas, sync/archive |
| Planning | Artifact/task DAGs, applicability, coverage and consistency |
| Execution | Current grants, durable work/attempts, limits and recovery |
| Verification | Actual checks/evidence, convergence gaps and lesson evaluation |
| Integration | Owned skill projections, host configuration and optional provider connections |

These are not six services or six published packages. Application workflows
coordinate public engine APIs. Narrow kernel/ports/adapters separate policy from
filesystem, authority, host and transport effects. See
[contracts](docs/architecture/contracts.md),
[local runtime](docs/architecture/local-runtime.md) and
[workflow guide](docs/workflow-guide.md) for actual implemented syntax. Intended
skill/run examples in older plans must not be presented as working CLI commands.

Source layout: `src/{engines,application,kernel,ports,adapters,composition,cli,mcp,api,observability}`,
`assets/`, `tests/`, `scripts/`, `docs/`, `licenses/`, `.github/`.
Checkout-only telemetry/operator code is in `services/` and `infrastructure/`,
not distributed inside the CLI package.

User-project layout:

```text
missionspec/
  config.yaml
  principles.md
  specs/<capability>/spec.md
  changes/<flat-change-slug>/
    change.yaml
    discovery.md
    proposal.md
    specs/<capability>/spec.md
    design.md
    tasks.md
    verification.md
  changes/archive/<date>-<slug>/
  workflows/
.missionspec/                   # ignored local runtime state
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

This is a mature layout, not an instruction to populate empty ceremonial files.
Markdown is canonical editable intent. SQLite records runtime, approvals, audit
and evidence, not a second editable task graph. A change is the editing unit;
multiple runs may implement it. Stable identity is not inferred from dates,
directory names, task checkboxes or Git remotes.

Raw evidence is retained until explicit reviewed pruning. No age-based automatic
deletion, silent disk-pressure cleanup or restoration of old authority.
External state selection, backup/staging/restore are explicit and non-destructive;
workspace binding and independent current authority still matter.
See [state lifecycle](docs/architecture/runtime-state-lifecycle.md).

### Authority, host and quality decisions

Local terminal confirmation is sufficient for the initial local-user assurance
level. It is not organization authentication, human-presence certification or a
subprocess sandbox. JSON, stdin prose, `--yes`, `approved: true`, model text,
skills, successful exits and copied receipts cannot issue fresh authority.
Preview and status must remain inert.

Auto is opt-in, serial by default, with explicitly confirmed bounded limits and
at most two automatic repairs per task after the initial attempt. Material scope
changes, no progress, revoked/stale grants or unknown effects stop earlier.
Hard, advisory and unavailable host controls must be reported honestly.
**Native autonomous AI-host execution remains unqualified/disabled in the CLI.**
Local registered trusted checks are a separate implemented capability.

Correctness/reliability are first-release gates. Complete-task latency/token/cost
measurements must include setup, failures, retries and repairs, with unknown
coverage explicit. Numerical performance improvement is not a release
prerequisite and must never be claimed from synthetic reporting tests.
Human-reviewed lessons cannot change permissions or success criteria.

Copilot/Codex/Claude use the user's personal accounts, not an unrelated work
profile. Only included subscription allowances were authorized, with no paid
overages/API charges. The original bounded pilot proposal was at most three
sequential single-prompt sessions per host, no new work after 15 minutes per
host. **Codex and Claude live pilots were later deferred.** Copilot billing,
default-model enforcement and real cancellation/isolation remain unresolved.
First-release Claude integration is SDK-free skills/CLI/MCP; SDK-managed sessions
and commercial SDK installation/terms acceptance were not authorized.

### Optional integrations, licenses and distribution

Mission Context is separately installed and optionally connected through a
narrow `ContextProvider` port. It owns its installer, indexes, state, resources
and enrichment. No bundled engine, mandatory plugin, arbitrary plugin loader,
auto-install/indexing or fabricated fallback context. MissionSpec must work
standalone, including Git-less projects.

Artifact Server/plannotator integration remains deferred. Research does not
authorize copying its source or templates, adding a dependency or claiming a
working integration. Recheck file-level licenses for any future inclusion.

MissionSpec retains Apache-2.0. OpenSpec and Spec Kit were conceptual MIT-licensed
references (historically inspected at OpenSpec v1.13.1 and Spec Kit v1.0.8).
Original code, instructions, templates and fixtures were chosen; third-party
inclusion needs exact provenance and retained terms, not just a root SPDX label.
No Liftoff GPL implementation is imported/relicensed. CLI and telemetry service
have separate locked runtime inventories/notices. See
[licensing](docs/licensing.md). Current `package.json` pins MCP SDK **1.31.0**;
older prose listing 1.30.0 is stale and must not override manifest/lockfile.

**MissionSpec distributes through npm. Liftoff's move to Homebrew/WinGet is owned
by another session and is explicitly excluded here.** The user reconfirmed that
distinction on October 10. The user previously asserted control of
`@msn-control` and publishing permission; actual registry rights still need
verification. Browser login succeeded locally as `voyager164` on October 10.
That credential is machine-local, is not committed, and will not authenticate
the new laptop. Login is not permission to publish.

Package remains **`private: true`, version `0.0.0`**. No release version/tag/
access policy or actual publication was approved. Prepare the candidate, then
obtain final user publication approval. Do not publish to discover name/scope
availability. See [release readiness](docs/release-readiness.md).

## Telemetry and cloud decisions

Normal CLI use does not require the telemetry service. No qualified production
endpoint is enabled. Local diagnostics, required durable audit, retained check
evidence and optional remote analytics are different data surfaces.

Telemetry design: disclosed default-on only after endpoint/privacy qualification,
hard opt-outs, CI/read-only exclusions, strict allowlisted aggregate schema,
one bounded request, no retry/redirect/offline event queue. No persistent user/
device/session/project identifiers, prompts, paths, source, raw errors or model
output. Logs analytics and total retention are both **180 days**, with no extra
archive. Preferences are user-wide; project restrictions cannot override opt-out.
See [telemetry](docs/telemetry.md) and [operator procedure](docs/telemetry-operator.md).

The backend's **durable server-side queue** is not a client telemetry queue.
Preserve the reviewed queue schema, managed identities, data roles, producer/
worker bounds, durable ACK/drain and storage/logging privacy conditions.

Only dedicated MissionSpec Azure resources in Australia East were in scope.
Exact account/subscription/resource coordinates and notification contacts belong
in private operator configuration, not this public handoff. UAT deployment is
user-owned: supply an exact reviewed handoff, not invented dev/staging/UAT targets.

The earlier private VM/ACA operator/broker/toolchain route was superseded by
**Azure-native ARM with full local what-if review**, after real toolchain/scanner
findings. Preserve the failed attempts; do not restart that route.
Enforced NSP was initially selected, but an undocumented wildcard `appliesTo`
selector blocked qualification. Do not normalize/accept it by guesswork.
The replacement path became **Queue Private Link**, dedicated VNet-integrated
Consumption ACA environment, queue private endpoint/DNS and ordinary TLS queue
hostname. No implied NAT/Firewall/Front Door/Blob widening.

Preserve Storage public access Disabled, shared keys false, default Deny,
bypass None, and the exact reviewed Defender scanner resource-instance
exception. Governance-generated NSG/tag changes were adopted only as observed
versioned deltas, not blanket permission for future drift.

Historical cost decisions progressed from USD350/month to Private Link planning
envelopes USD375 steady-state and USD425 migration month, with at most seven
days overlap. Models included USD359.71 steady-state and USD410.75 seven-day
migration. These are **old estimates, not current rates, hard caps or proof of
resource-budget changes**. Reprice and review scope before effects. Original
overlap expired `2026-10-09T16:39:47.323Z`; do not extend it by editing history.

Historical live attempts failed before qualified enablement/delivery. A reviewed
DELETE plus separate terminal activity/read-only reconciliation established
absence of a temporary public resource. Original failed windows/fences remained
immutable. The user approved one reviewed cleaned successor after proven cleanup,
not an unlimited retry loop or recreation of the old receiver/image. Last known
disabled receiver/no-public-resource observations are historical, not current
cloud truth on this laptop.

## Latest actual diagnostic and pending qualification

Do not confuse the following **native CHECK-only preparation V6** with older
full-window versions also named v6. Full-stage producer remains paused.
Original accepted14 is immutable input-only. No accepted15, successful stage15
storage, later ordered acceptance, native source upgrade or release is established.

### Genuine October 9 V5 CHECK diagnostic

One exact parent-supervised, fresh one-use invocation ran
`2026-10-09T18:48:39.194Z` through `18:56:55.123Z`, exited 1, and was proven
quiescent before final logs/world custody. The grant/namespace is permanently
consumed. Never replay it or use its stale process IDs.

| Measurement | Actual observed duration |
| --- | ---: |
| Whole native process | 495,925.68125 ms |
| Authentication/materialization/import | 641.2855 ms |
| Driver preparation | 400,096.305417 ms |
| CHECK operation | 94,309.179792 ms |
| CHECK start to first command | 81,410 ms |
| Observed command read span | 12,570 ms |
| Tail after last command | 330 ms |

Primary failure: production `ReferenceError: method is not defined`.
Four raw command records failed at about 12,557-12,570 ms, below 15 seconds;
they were **not timeout failures**. Adapter reconciliation/custody diagnostics
were secondary; parent post-quiescence custody passed independently.

There were **60 retained failed-read artifacts but only 4 raw observed command
records**. All 60 writes were during CHECK and at/after the first command; none
were after CHECK. Arithmetic difference 56 is not 56 late writes, invocations
or additionally admitted commands. The concurrency limiter starts at most four;
first failure rejects unstarted queued jobs, whose read-finally path can retain
failed artifacts. Static trace is mechanism-consistent, not per-artifact receipts.
Historical V3's 53 timeout-coded retained artifacts likewise do **not** prove
53 admitted/timed-out commands; its real command count/timing is unknown.

### Independently reviewed V6 correction

The sealed CHECK-only V6 packet fixes:

1. `prepareCheckOnlyInvocationBody(args)` captures exact validated GET and carries
   it through real response resolution.
2. `runScopedObservedCheckOperation(...)` puts the full work, reconciliation,
   provenance, custody and failure-persistence lifecycle under the exact
   AsyncLocalStorage operation metric, not only the inner work callback.

Actual production-helper GET/ALS tests and independent metadata review passed.
Non-GET methods reject before continuation; writes bind exactly to zero.
Frozen primary failures use a WeakMap channel; attachment/persistence failures
remain secondary. **No actual V6 CHECK qualification has run.** Native source21
and source/candidate/transition pins were unchanged by this correction.
`accepted: true` in the parent review means code/metadata review only, not
execution, source-upgrade, full-stage or live authority.

Conditional performance blocker: if the genuine 81.410 s pre-read cost persists,
adding the required 50 s read span cannot fit the unchanged 115 s driver ceiling.
V6's future timing has not been measured. Attribute genuine cold work before
optimizing; do not warm caches, move deadline starts or call setup CHECK time.

### Hard boundaries to preserve

| Boundary | Existing limit |
| --- | --- |
| Native supervisor / admission runway | 900 s / strictly more than 930,000 ms genuine validity |
| Product CHECK / driver / headroom | 120 s / at most 115 s / at least 5 s |
| Required observed read span | At least 50 s |
| Command deadline / concurrency | At most 15 s / 4 |
| Native observation logs | 4,096 bytes per line, 64 records, 131,072 combined bytes |
| Runtime work / enabled / public / cleanup | 420 / 600 / 900 / 180 s |
| Artifact wire/distinct storage | 64 MiB bounds; retain existing exact structural rules |
| Reference / blob caps | 64 references / 8 blobs |

These are not tunable conveniences for making failures pass. Authenticate exact
plans, sources, facts, parity, guardian self-pin and one-use grant before each
new admitted invocation. Confirm current exclusive heavy-slot ownership.
Quiescence must precede final log/world custody. Timeout provenance comes from
the actual admitted command boundary, not outer process wall time.

### October 10 scan refresh: prepared, not executed

User approved one bounded official DB transfer and zero-or-one full unsuppressed
scan of the same published image, then separately reviewed fresh input lineage.
The later pause suspends execution. No heavy-slot transfer was issued.
Driver preparation finished before pause; parent review was only partially read.
Do not label it independently accepted or run it as-is on a different laptop.

Parent made three bounded metadata GETs at
`2026-10-10T08:32:29.577Z`-`08:32:30.793Z`, without DB download/scan.
Official manifest: `10b911fec8e9a579313dcd43917ceab7742351ff0fd95f33f95eef17fa7047ea`,
616 bytes. Layer: `6d0e3ec381542db578535ce80068a3ff0b80d90d1f8cdcb261e6ab228162ce24`,
126,499,832 bytes. This tuple is **historical metadata now**, not current
raw-DB freshness or permission to follow latest silently.

Same immutable local image/scanner inputs:

| Input | SHA-256 / identity | Bytes |
| --- | --- | ---: |
| OCI archive | `850669f77166c970cea693b366f3618b2a2b56826ac35e5d584b04d90a10d097` | 360,749,056 |
| Trivy 0.74.0 binary | `0ed07c205ca9ecc1065dc57b9f9f77adc79393bb469d9d1de9ec90c8c94ffc2f` | 161,425,922 |
| Published image manifest | `sha256:7970ab33ed2928dd156d6db212edccc7c556df87a6a0b1ba2361d6df7beab291` | Not asserted here |
| Image config | `sha256:42e4e6828b06c65203207d3f16f394a19b769be6ef45317f7a2ff1aa4a30fac5` | Not asserted here |
| Image source | `eab1a82b5b99f70cdc38ec1f5b695935db286e07` | Not applicable |

Direct historical published anchors, not chronological substitute predecessors:
candidate `0e456268ce77bed283e7b52e527810b6bc77b2e3993af4c8fcd4110d2cdf8894`,
profile `dacf5c27a6607171e710d8f55e237a8e3d9496af63520af586c413628aa4d5c5`,
previousRefresh `55830c38503ba091ca5e23e6536e5c215cc1f3c43404a2b01e351b114ad718e5`.

One official DB transfer only; no mirror/retry/follow-latest. Keep tokens,
response headers/body hashes transient where secret-bearing and never forward
bearer credentials to CDN. Stop with zero scans on digest/size/identity mismatch,
nonadvancing/stale/future-invalid raw metadata or less than 45 minutes genuine
DB runway. Download time does not renew validity. If eligible, scan the existing
archive once, unsuppressed. Critical/High/Unknown/suppressed findings or target
identity mismatch block acceptance, while preserving all evidence.
Complete wrapper inventories follow quiescence and do not replace core inventories.

Last accepted historical scan's raw DB UpdatedAt:
`2026-10-08T19:05:21.721409049Z`; NextUpdate:
`2026-10-09T19:05:21.721408648Z` (conservative expiry
`2026-10-09T19:05:21.721Z`). It is expired.
October 9 prices also expired after their 24-hour window. A pricing refresh is
**separate** from scan authorization; no fresh pricing was obtained on October 10.

## Private evidence and session-only code: transfer boundary

**Git makes repository source portable, not the entire prior execution world.**
Native diagnostic adapters, guardians, sealed packets, original read files,
scan databases/image archives and some qualification helpers exist only under
the old laptop's `.copilot/session-state/` or private worktree caches. They are
not committed by this handoff. A source-only clone can continue product
development, but cannot complete the old native/retirement evidence chain.

Do not bulk-add the session folders to this public repository. Ask the user for
an authorized **private, reviewed transfer** of the necessary packet closures and
their recursively referenced original evidence. Never transfer `.npmrc`, tokens,
unrelated account data or secret-bearing operator files as public source.
The old host is `/Users/jonathan/Documents/GitHub/missionspec`; paths below are
locators on that laptop, not runnable paths on the new one.

| Old session owner | ID under `~/.copilot/session-state/<id>/files/` |
| --- | --- |
| Parent coordinator | `05da9c2b-1ab7-48cc-b0c5-7369980ee87b` |
| Runtime / Release install readiness | `96477a37-ab24-4182-981a-62b6d788cffc` |
| Scanner / Patched telemetry runtime | `9b57fd53-c576-4fa8-b7b9-2f9644e20040` |
| Codec / typed source transition | `7876c8ba-4fb0-4f12-923b-446e11cfedac` |

Key immutable entry points (authenticate the full member closure, not just the
manifest; hashes here are historical pins, not trusted new approvals):

| Owner / relative entry | SHA-256 | Bytes |
| --- | --- | ---: |
| Runtime: `ordered-native-source-transition-check-only-preparation-20261010-v6/manifest.json` | `c850f92ed9f7516bacaff8472a11980c19d904c9fb648e4bddfb4399a7c25c5d` | 11,901 |
| Runtime: V6 `check-v5-to-v6-runtime-boundary-correction.patch` | `5e8dfa17b9d2a5b424d15ad65425e38a0bdcea5d5e21a256a4b8ab22d9de50d4` | 72,247 |
| Runtime: `ordered-native-check-diagnostic-terminology-amendment-20261010-v1/manifest.json` | `338564eb72d6d23f223118b8b67228323605be3c45893f71a5d078836a37eebe` | 1,334 |
| Parent: `native-check-v6-parent-independent-review.json` | `2b188480bb6cc03a6d9e0bca74a737a534e380a109dd9c9d53f915ec252477fb` | 2,911 |
| Parent: `native-cold-check-parent-batch-v5-raw-observation-outcome-summary.json` | `10bbd19534936b1a20c5d71938aec3387b1fc62de0df73ed97486665c7fa9513` | 16,314 |
| Parent: `native-v5-retained-read-classification.json` | `2f3864b91198230cfd5600b6ccd624f2f660b9598923cbd7dd0b9dc6219ca118` | 40,856 |
| Parent: `native-v5-authenticated-timing-analysis.json` | `a83d9ab4cee659b30b732e33a04cf815dc5f7366612aea17f97a0645a676a10f` | 3,190 |
| Scanner: `same-image-scan-20261010-approved-driver-preparation/preparation-inventory.json` | `c554f7ebe0287205b6efa44dedd4c7650a068ecda52eed1ddb365f2d408d105c` | 2,555 |
| Scanner: same preparation's `refresh-once.py` | `97501e1fc18a730a4006c885719b892f2665e3debcbb69ac047977d297a9eaf2` | 17,341 |
| Scanner: same preparation's `generated-core.preview.py` | `5b590abe241becfbb50dbf851089dadbf3eb86052ea5702099132f16877e83d7` | 38,170 |
| Scanner: same preparation's `handoff.json` | `8c65c7ec26a8af394a3b60f182db633c8432fc3dbe4fd839b4747f0b65224569` | 6,865 |
| Codec: `typed-source-transition-preparation-v3/manifest.json` | `6f4ca858dec7565c710580aadde0c5553e6007c35ebad3df93edda85825080df` | 3,224 |

V6 has 51 manifest members / 1,981,041 member bytes; terminology amendment
5 / 21,982; scanner preparation 18 members, excluding its own inventory.
V1-V5 historical packets must remain unchanged. V6 includes original-source21,
adapter/driver/entrypoint, test, contract, templates and patches, not a permission
to materialize them over main.

Additional parent helpers/evidence locators:
`run-reviewed-native-cold-check-next.mjs`,
`bounded-native-check-process-v2.mjs`,
`native-cold-check-next-plan.test.mjs`,
`audit-native-cold-check-v5.mjs`,
`audit-native-v5-retained-read-classification.mjs`,
`native-check-v6-parent-{packet-authentication,production-boundary-test,verifier}.json`,
`native-check-terminology-amendment-parent-{authentication,verifier}.json`.
Old V5 plan `native-cold-check-parent-v5-diagnostic-plan.json` is consumed,
not a next-run plan. Amendment verifier is `verify-amendment.mjs`; V6 verifier
is `verify-packet.mjs`. Do not run entrypoints, regenerate sealed manifests or
hydrate referenced evidence while merely authenticating copies.

Native source pins: map
`ac422669d29ac1855fac4fcf60e2012f7cf65fc8efd13b21f53a7e63412ce03a` / 2,020 bytes;
candidate `eb6bdadbcf149ac73914983d22f5d7ffacd0d58a18566d174ab91c868fc9c637` /
5,527; transition
`6cb9072c821d524c0a204159d3c1d571b12582555aea838c65b268c1b6fd1e16` / 7,309.
Preparation inventories are not actual producing-stage physical inventories.
The common controller digest is distinct from the private-controller digest.

The previous scanner's raw/derivative complete inventories are
`8355be79504f4741c14d8d81318d1702f3b71608cf81b1bd60531de288255b17` and
`b0a32cc09f9eae2c8068e13965d7050c1e4e376b5e4ca2875ca2294823a8c4e0`.
Finalized-v2 derivative inventory:
`bac16321628f4c7fd149fce74489e00fb3a3bd3d835159ca2fe0e213291bf0b2`.
New preparation pins before/after custody of those packets, prior failed packets,
parent validation and exact public metadata. They too must be available privately.

Copying files changes physical identity. Original seven-stat observations
(`dev`, `ino`, `size`, `mtimeNs`, `ctimeNs`, `nlink`, `mode`) cannot be claimed
as current custody on another filesystem. Keep original receipts immutable,
record copied-byte authentication separately, and design/review a new
machine/path-bound invocation with fresh facts/expiry and a distinct one-use
grant. Missing old evidence means blocked/unknown, not reconstructed success.

Old coordinator session-state keys worth consulting privately:
`native-check-v5-actual-diagnostic`, `native-v5-authenticated-timing-analysis`,
`native-v6-parent-review-sealed`, `retained-artifact-versus-admission-correction`,
`v6-heavy-slot-current`, `native-check-freshness-authorization`,
`npm-publisher-authentication-20261010`, `user-work-pause-20261010`.
Older authorization/status keys conflict chronologically; the latest pause and
this handoff scope prevail. Session IDs and database keys do not restore sessions
or grants on a different laptop.

The runtime session reported repeated errors after the pause. Its metadata was
inspected for this handoff, but the tool supplied no diagnostic cause or proof
of task completion. Do not restart it to suppress notifications or assume sealed
evidence is corrupted solely from a session error. No new heavy work was launched
by the coordinator after pause.

## Pending work in dependency order

1. **Resume and establish the new machine's scope.** Remain paused until user
   authorizes continued qualification. Authenticate source and any privately
   transferred evidence; inspect current GitHub/account state. Preserve older
   WIP branches rather than overwriting main with their older snapshots.
2. **Finish independent scan-driver review and freshness.** Historical Oct10
   metadata/root bindings are not automatically current/portable. Review a new
   exact path-bound preparation/current official tuple, authenticate immutable
   input/closure, reserve an actually exclusive slot, then admit only the
   authorized bounded attempt. Preserve failure and complete custody. No scan
   can alter old profile/publication timestamps.
3. **Obtain distinct pricing-refresh authorization** and retain genuine current
   official rates/cost scope. Do not infer it from scan approval. Any new live
   admission needs real current-state observations, not copied historical GETs.
4. **Profile/qualify native CHECK-only V6.** Preserve genuine cold timing, GET/
   zero-write/ALS boundaries, raw primary/secondary observations and fixed caps.
   Use exact reviewed current plan/guardian/parity, new grant/namespace and parent
   supervision. A fixture or metadata review is not the positive native CHECK.
5. **Only then resume full-stage producer.** Obtain real stage15 producing
   record/storage, raw CHECK/admission clocks and the actual materialized 21-file
   physical inventory. Qualify nine-helper semantic supervision/roles/custody,
   unaccepted assembly, separate issuance, accepted15 and correctly bound
   successors16-18. No shortcut from old accepted14 or source-free positive fixtures.
6. **Complete separately admitted live qualifications.** Private delivery,
   TLS/UAMI, refusal/drain/privacy/retention, bounded cancellation/isolation,
   real host skill behavior/default-model/billing and benchmark/lesson effectiveness
   remain gaps. User-owned UAT requires a reviewed operator handoff. Do not revive
   deferred Claude/Codex pilots or incur additional charges.
7. **Final integration/release.** Select only actually supported platform/
   architecture claims, refresh exact-candidate checks/notices/package evidence,
   update PR using its repository template and current base. Prior merge authority
   was conditional on genuine qualification and is suspended by the pause.
   Obtain explicit final npm version/access/tag/publication approval. No release
   or automatic merge is part of the cross-laptop backup.

## Validation references and reading order

For this handoff, `node scripts/check-repository.mjs` passed and
`npm run check:package` passed, including the TypeScript build and package
boundary check. The main documentation diff passed `git diff --check`.
Central V6/amendment/review/outcome/classification/scanner-inventory pins were
reauthenticated from exact local bytes without source imports or execution.
The full product/ARM/service/native qualification suites were not rerun for
this documentation and archival task; it does not replace their pending gates.

Main development checks, when implementing again:

```sh
npm run check
npm run check:package -- --install
node --test tests/package.test.mjs tests/repository-checks.test.mjs tests/skill-rendering.test.mjs tests/cli.test.mjs
```

The explicit install check is offline and needs reviewed dependency tarballs in
cache. A cold-cache failure is an unmet prerequisite, not permission for its
runner to retry online or bypass lifecycle-script restrictions. Root checks do
not cover all service/operator tests:

```sh
npm ci --prefix services/telemetry-ingest --ignore-scripts --no-audit --no-fund
npm test --prefix services/telemetry-ingest
node --test infrastructure/arm/telemetry/tests/*.test.mjs
node scripts/check-licenses.mjs
```

Use targeted selectors during iteration; do not run expensive frozen native/
codec batches for simple documentation work. Full candidate validation and
actual required GitHub contexts remain necessary before integration. Historical
Linux x64/macOS arm64/Windows x64 tarball/shim results are candidate-specific;
they are not a blanket cross-platform archive or AI-host qualification.
Windows held-handle private-state, console/ConPTY and owned-job local-check
results have their documented narrower scope, not human presence or AI confinement.

Read in order:
[README](README.md), [workflow](docs/workflow-guide.md),
[local runtime](docs/architecture/local-runtime.md),
[release readiness](docs/release-readiness.md),
[native hosts](docs/architecture/native-hosts.md),
[Windows scope](docs/architecture/windows-state.md),
[operator procedure](docs/telemetry-operator.md),
[measurements](docs/qualification-measurements.md), [licenses](docs/licensing.md).
Old private `plan.md` and `queue-network-design.md` preserve broad history but
contain superseded statuses. This handoff's latest state and exact evidence
boundaries take precedence; technical facts still require independent checks.

**Do not report the original product task complete from this source backup.
Do not recreate success, reuse consumed grants, extend historical expiry,
drop failed evidence, weaken deadlines/storage limits, copy credentials or
publish private plans/logs to GitHub.**
