# Licensing, provenance, and release qualification

MissionSpec's original project code and documentation use the
[Apache License 2.0](../LICENSE). Dependencies keep their own licenses. A
successful automated check is evidence of a specific, reviewed dependency set,
not a legal opinion, a security audit, or permission to publish.

## Original work and conceptual references

MissionSpec's project-specific implementation, skill instruction sources,
templates, and prose are original work, rather than copied upstream templates.
OpenSpec and Spec Kit are conceptual MIT-licensed references, not dependencies
or copied instruction/template distributions. Their influence is on workflow
ideas, not a claim of code ownership, affiliation, or compatibility.

Liftoff's GPL distribution is not included. The commercial Claude Agent SDK and
Claude Code package are not bundled or declared as runtime dependencies. The
checker rejects `@anthropic-ai/claude-agent-sdk` and `@anthropic-ai/claude-code`
in either runtime graph. A separately installed host is not a bundled SDK.

The MIT-licensed `@modelcontextprotocol/sdk` is a distinct protocol dependency.
Its Anthropic copyright notice is retained as supplied; that does not turn it
into the commercial Claude SDK or establish native host qualification.

Third-party license and notice texts are reproduced from installed dependency
packages, plus the narrowly reviewed upstream service supplement described below,
for attribution and compliance. This is the exception to the
project-original prose declaration, not copied implementation source.
Contributors must disclose any new incorporated material and preserve its terms;
the current inventory is not permission to copy other upstream work.

## Two independent runtime inventories

| Scope | Locked source | Checked inventory | Retained notices |
| --- | --- | --- | --- |
| CLI | Root `package-lock.json` | `licenses/cli-runtime.json` | [THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES) |
| Isolated telemetry service | `services/telemetry-ingest/package-lock.json` | `licenses/telemetry-runtime.json` | `licenses/TELEMETRY_THIRD_PARTY_NOTICES` |

Inventory and service paths above are source-checkout paths, not relative links
into a CLI package. Use the
[source repository](https://github.com/voyager163/missionspec) for those files.
The CLI package ships its notices, `licenses/cli-runtime.json` and this guide,
not operator sources or the service inventory/notices. The service Docker build
checks its own inventory and includes its notices and `runtime-inventory.json`
in the separate image.

The current direct CLI pins include `@modelcontextprotocol/sdk@1.30.0`,
`ajv@8.20.0`, `fs-native-extensions@1.5.1`, `mdast-util-from-markdown@2.0.3`,
`yaml@2.9.1`, and `zod@4.6.5`.
The isolated service pins `@azure/identity@4.13.3`, `@azure/logger@1.3.0`,
`@azure/monitor-ingestion@1.2.0`, `@azure/storage-queue@12.32.0`, and `ajv@8.20.0`.
Its Queue-scoped overrides select `fast-xml-parser@5.7.0` and
`@nodable/entities@2.1.0`.

The inventories cover the entire locked runtime dependency, optional-dependency,
and peer-dependency graph, including nested versions. They do not list only the
direct imports or pretend unused runtime branches disappear through tree
shaking. npm may install these dependencies separately; “runtime inventory”
does not mean every package is embedded in the MissionSpec tarball.

Every runtime entry records its package location, identity, exact version,
registry tarball URL, npm integrity value, declared license expression, resolved
dependency edges, and source/retained hashes for its legal files. The lockfile
data hash uses canonical JSON, independent of formatting and key order. There
are no timestamps, machine paths, or registry lookups in generated output.
The external service notice's legal-file record additionally has explicit
`provenance`, including `origin`, `shippedInPackage: false`, upstream commit/blob
and URL, and `pathBase: "repository"`. Ordinary packaged legal-file records retain
their existing package-relative paths and hashes.
These are project-specific machine-readable inventories, not a claim of
CycloneDX or SPDX document-format conformance.

Development-only lock entries are listed separately and explicitly **not
license-reviewed**. A package shared with the runtime graph is audited as
runtime even if it is also a direct development dependency: the service's
`@azure/core-rest-pipeline@1.25.0` is such a case. Platform-specific development
packages need not be installed to classify them.

Node.js, npm, operating systems, external hosts, and any third-party material
copied into generated build output are outside this npm runtime inventory.
Redistributing those components would need separate review and notices.

## Reproduce and review the evidence

Use the supported Node.js 24 toolchain in a source checkout. Restore both
lockfiles without dependency installation scripts:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm ci --prefix services/telemetry-ingest --ignore-scripts --no-audit --no-fund
node scripts/check-licenses.mjs
```

The default command checks both scopes. `--scope cli` checks only the CLI;
`--scope service` checks only the isolated service. Missing runtime packages
fail the check rather than silently reducing coverage. This includes a locked
optional runtime package whose legal files are unavailable locally. An optional
peer that is absent from the lockfile is recorded as omitted, not fabricated
as an installed package.

After intentionally updating a dependency, inspect the locked source and the
installed package's actual license and notice files. Then regenerate:

```sh
node scripts/check-licenses.mjs --write
node scripts/check-licenses.mjs
node --test tests/check-licenses.test.mjs
```

Review the generated diff before accepting it. `--write` is not automatic
license approval. Every retained file must also match a license-expression/text
fingerprint in `licenses/reviewed-texts.json`. That separate catalog records the
inspected initial texts and their package origins; the generator never updates
it. An added or changed text requires inspection of the full terms and an
explicit catalog edit, even if its package still declares `MIT`. Do not approve
a new fingerprint merely because the error prints it.

Both modes have the same source, identity, dependency-graph, license expression,
and license-text guards. Neither mode installs packages, runs package code,
contacts a registry, or publishes.
The check records npm's tarball integrity rather than independently
authenticating all installed source bytes; a trusted `npm ci` restoration is
part of the evidence.

The current expression policy admits only `MIT`, `ISC`, `BSD-2-Clause`,
`BSD-3-Clause`, `Apache-2.0`, `0BSD`, and the specifically handled
`(MIT AND Zlib)` combination. Unknown expressions, missing license files,
conflicting obvious copyleft/commercial terms, unrecognized text fingerprints,
changed snapshots, unreviewed sources, and inconsistent lock/installed metadata
fail. An unsupported license
is a review blocker, not necessarily a conclusion that its use is unlawful.
Do not weaken the policy or re-label a dependency to make it pass.

The checker retains discovered license, notice, copyright, and third-party
notice files, including nested files, without substituting summaries. Only
line endings are normalized to LF. Two important service details are:

- `pako@2.2.0` has an MIT `LICENSE` **and** applicable zlib terms in
  `lib/zlib/README`; both are retained. Its supplemental selection is pinned to
  the reviewed version and must be revisited on upgrade.
- `tslib` supplies both `LICENSE.txt` and `CopyrightNotice.txt`; both are
  retained. Apache and BSD texts and any included attribution clauses are
  retained in full as well.

Text evidence checks are guardrails, not a general legal-text classifier.
Review newly added packages for supplemental or embedded notices that filename
discovery cannot establish. A distribution change, vendored source, new license
expression, or unusual license location requires deliberate review.

### Native descriptor-lock dependency

The user-approved native POSIX lock dependency is exactly
`fs-native-extensions@1.5.1`, declared Apache-2.0. The approved published artifact is:

- Registry tarball: `https://registry.npmjs.org/fs-native-extensions/-/fs-native-extensions-1.5.1.tgz`
- Size: **467,359 bytes**
- SHA-512 integrity: `sha512-abjiHKkYdcH5M9ikBEJb0MKb/fEpPtZx/yfLHzTptvUAoiFayX0tIe0BTLBU4SAoRyjZLzA0dP1Rn2p0+QRyVg==`
- Published `gitHead`: `d67c02bf2abe79fa9f277035d4f14da5aa3c4007`
- Source: [holepunchto/fs-native-extensions at that commit](https://github.com/holepunchto/fs-native-extensions/tree/d67c02bf2abe79fa9f277035d4f14da5aa3c4007)

The downloaded tarball hash/size and registry metadata were checked, and all
**38** installed files were compared byte-for-byte with that tarball. Its
`src/apple.c` calls exclusive nonblocking `flock`; `src/linux.c` calls
`F_OFD_SETLK`, not process-associated `F_SETLK`. The package supplies source and
prebuilt Node (`.node`) and Bare (`.bare`) modules. MissionSpec uses the Node
prebuild, N-API 9 according to the supplied CMake configuration, and does not
compile native code or run an install script. This is provenance of a pinned
publisher artifact, **not a reproducible-build attestation** for its binaries.

The locked new CLI closure is:

| Package | Version | Published gitHead |
| --- | --- | --- |
| `fs-native-extensions` | `1.5.1` | `d67c02bf2abe79fa9f277035d4f14da5aa3c4007` |
| `require-addon` | `1.3.0` | `b4e29ff008cf5c90d810a7fd7ff23fb4acb4e492` |
| `which-runtime` | `1.4.0` | `d4732d849da866990f532de53d7d0a02847ea374` |
| `bare-addon-resolve` | `1.10.1` | `ed517fb0d5a09621828ff1d929934f6b55144550` |
| `bare-module-resolve` | `1.12.5` | `7eb9db6c56af688e15c790cff460eb59794aa9ad` |
| `bare-semver` | `1.1.0` | `25db5754521e65ccf1a32eff55a4e53f663744a9` |

Each new tarball's SHA-512 was independently checked against its lock entry and
registry metadata. All six installed `LICENSE` files match their tarballs and
contain the same full Apache-2.0 text, SHA-256
`c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`.
The supplemental `src/win32/nt.h` says its API declarations are mostly taken from
`winternl.h` and Windows SDK documentation and retains
**Copyright (c) Microsoft Corp. All rights reserved.**
The notice generator retains that entire unmodified header (SHA-256
`8c92b0e378a2a1614b3793b6dcef37435a5567d89448941b5ebf76fc37f4d2d2`)
under an exact CLI version/tarball/header pin. This preserves attribution; it is
not a new license grant or a generic exception for missing/conflicting licenses.

The CLI inventory now has **133 runtime packages** (six added) and 28
development-only classifications. The independent service remains **63**
runtime packages; its lock, inventory, notices and exact external-entities
provenance are unchanged.

Audited Node prebuild SHA-256 values:

| Target | SHA-256 | Qualification in this change |
| --- | --- | --- |
| `darwin-arm64` | `1e93b74e556b7d1767d57fabb197d9d1df5641453967170537278f72ed46f018` | Real macOS arm64, Node 24.21.0 |
| `linux-arm64` | `895dd0dca09438454f28bba250bcafa3e69c937fe97ea46b1b6212dc3a81315c` | Actual local Linux Docker volume, Node 24.21.0 / glibc 2.36 |
| `darwin-x64` | `973e4b2addf30901b955c75626ac153d3a37cebcfa621375bcd490f199884c8e` | Artifact checked; native execution pending |
| `linux-x64` | `13657db7ce92f823ee8066cc7244f3a475340707fc065fd4f5aceeebbfa898c3` | Artifact checked; native execution pending |

The Linux qualification uses already-cached
`node@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6`
with `--pull=never`, networking disabled, a read-only container root and
owned native-volume test storage. No source, credentials or artifacts are
uploaded. The loaded Linux target is the table's `linux-arm64` Node prebuild.
The corresponding mutex FD-close/worker, competing recovery, quarantine
interruption, lifecycle, store, workflow and source-patch selectors are:

```sh
npm run build
node --test tests/posix-native-lock.test.mjs tests/persistence-mutex-fd.test.mjs tests/persistence-posix-races.test.mjs tests/evidence-pruning.test.mjs tests/runtime-lifecycle.test.mjs tests/runtime-store.test.mjs tests/local-workflow.test.mjs tests/source-patch.test.mjs
```

This exact selection passed **174/174 with zero skips** on both macOS arm64
and the Linux/glibc arm64 volume. The macOS run including license-checker
regressions passed **197/197**. The actual Alpine adapter probe separately
confirmed read-only import succeeds and writer admission fails before creating
any mutex/bootstrap state; that negative check is not native-lock qualification.

**Packaging/platform constraints:** install the committed root lock with
`npm ci --ignore-scripts`; new transitive resolutions require a renewed audit.
The MissionSpec tarball ships these notices, inventory, adapter and provenance
documentation; npm installs the original dependency tarballs separately, with
their native prebuilds/source/legal files intact. No binaries are copied into
MissionSpec's `dist`, no host compiler is required, and there is no system
`flock`, SQLite-lock, mkdir/PID or native-rebuild fallback.
The adapter lazily validates/loads only the pinned package on POSIX arm64/x64
with Node >=24.21.0 <25. Read-only imports and Windows dispatch do not load it.

**Alpine/musl is unsupported for native writer effects with this pin.**
Actual Node 24.21.0 Alpine arm64 inspection found that `require-addon@1.3.0`
requests `linux-arm64-musl`, which this tarball does not ship. Admission fails
closed; the loader is not bypassed by directly loading a glibc binary.
The upstream tarball's other targets, including Windows/Android and Bare, do
not establish MissionSpec qualification. Existing Windows native write/lock
handling is unchanged; the separate Windows held-read candidate still requires
its own [native selectors](architecture/windows-state.md#persistence-held-read-candidate).

### Exact upstream service notice: entities 2.1.0

The published `@nodable/entities@2.1.0` npm tarball declares MIT but contains **no
license file**. Its eight distributed files were compared byte-for-byte with
`Entity/` at the npm metadata's exact published `gitHead`,
`f1c61a65e7b967c17b13822ef71e91bd25f17ce2`, in `nodable/val-parsers`.
The repository-root
[LICENSE at that commit](https://github.com/nodable/val-parsers/blob/f1c61a65e7b967c17b13822ef71e91bd25f17ce2/LICENSE)
is MIT and retains **Copyright (c) 2026 Nodable**.

The source checkout retains those original 1,064 bytes in
`licenses/external/nodable-entities-2.1.0/LICENSE.md`; the `.md` suffix uses the
existing LF checkout rule without altering the upstream text. Its Git blob SHA-1
is `561468f111a66df52cc0f1934642bb9fdd22a212`; source and retained SHA-256 are both
`750cb3fb6362804957ef52caaf9b5c824015be44d494637330d7cd8834d31d40`.
`licenses/external-service-licenses.json` records the exact package, registry URL,
npm SHA-512 integrity, upstream repository/commit/path, artifact hashes and
retained location.

This is an **upstream-commit supplement, not a file shipped in the npm tarball**.
The generated service notices label that distinction and reproduce the complete
license and copyright. No file is inserted into `node_modules`. The source archive
includes the catalog and retained artifact, and the runtime's service notice file
contains the full text and attribution. They remain outside the CLI package.

The checker permits only this exact service-scoped name/version/tarball, commit,
source blob and retained artifact. The catalog must match the checker’s reviewed
pin, not a caller-selected URL or version range. Wrong scope, version, integrity,
source hash, extra catalog fields, missing/changed/symlinked text, unreviewed text
fingerprints, and a newly injected package-local license fail closed. Checks and
`--write` are offline and never fetch an upstream file or approve new terms.
All other missing-license cases and the separate JSON-schema metadata exception
retain their original policy.

The original package/commit correspondence is review evidence, not a signed
publisher attestation. Normal package-source trust still relies on the locked
`npm ci`; the default checker independently verifies the retained legal artifact,
not a newly downloaded Git checkout. A different entities version needs its own
package and legal-source review and an intentional pin change.

## Shipped notices and check integration

### Reviewed Dependency Graph metadata discrepancy

The first hosted dependency review reported `json-schema-typed@8.0.2` as
`BSD-2-Clause AND JSON`. The exact published npm tarball, its package metadata,
`LICENSE.md`, source headers and the upstream release commit
[`613f3ab84c8e1b14de492534bfcb81d1499610a3`](https://github.com/RemyRylan/json-schema-typed/blob/613f3ab84c8e1b14de492534bfcb81d1499610a3/LICENSE.md)
declare BSD-2-Clause, including the schema-documentation attribution. The shipped
package contains no JSON-license restriction. The complete notice is retained.

The action therefore has one explicit package-name metadata exception, **not**
an allowance for the JSON license. The pinned action matches exception package
names without versions, so a version suffix would falsely imply a narrower
match. The separate required local/hosted `check:licenses` enforces version
`8.0.2`, the exact registry URL/tarball integrity and both source and retained
legal-file hashes. A version, tarball, declared license, added legal file or text
change fails that guard. Moving that package name into the otherwise unaudited
development-only closure also fails, rather than bypassing the pin. Do not
broaden or remove the guard to make a future
upgrade pass; reassess the discrepancy and remove the exception when corrected.

The root package's `files` allowlist includes `THIRD_PARTY_NOTICES` and the CLI
runtime inventory. `docs/licensing.md` is included through `docs`. Do not add the service notice
set, service source, or service inventory to the CLI package.

Run `node scripts/check-licenses.mjs --scope cli --package` through an npm script
after the normal build. The `--package` option uses npm's local
`pack --dry-run --ignore-scripts --json` preview; it checks that the root license,
CLI notices, and this guide are selected, that the selected notice byte count
matches the checked file, and that service artifacts are absent. It creates no
tarball and is not a publish step.

The root check runs the CLI license/notice check. CI additionally
runs `node scripts/check-licenses.mjs --scope service` after restoring the
isolated service dependencies. The service's own tests are not a substitute for
that inventory check. A separately distributed service image or archive must
also be inspected to confirm its service notices actually ship.

## Release qualification matrix

These gates are independent. Local inventory success alone does not qualify a
release, install a host skill, activate GitHub controls, or authorize deployment.

| Gate | Required evidence | Limit or outstanding action |
| --- | --- | --- |
| Locked dependency provenance | Clean lockfile restores; matching CLI and service inventories; reviewed source URLs, integrity fields, license texts, and supplemental notices | Installed source authentication relies on the restore; development-only licenses and external runtimes are not audited here. |
| CLI notices and package boundary | Built package preview with `--scope cli --package`, plus the existing package/link checks | Must be rerun on the final candidate; no registry publication is implied. |
| Service distribution | Service inventory passes and the operator artifact retains `licenses/TELEMETRY_THIRD_PARTY_NOTICES` content | An npm CLI preview does not inspect a service image; no deployed endpoint is established. |
| Original work and attribution | Review confirms any incorporated source or assets are disclosed with compatible terms and required notices | Conceptual references are not authorization to copy templates or bundle GPL/commercial code. |
| Functional and host qualification | Applicable build, tests, workflow tests, and separately authorized real-host qualification | Pure rendering, a typecheck, or an inventory is not native host qualification or proof of complete lifecycle behavior. |
| Hosted repository controls | Qualified workflow runs, exact observed required-check names, approved settings changes, and readbacks | Local files do not enforce GitHub settings; use the [maintainer guide](maintainer-setup.md). |
| Private security intake | Enabled and repository-API readback verified on 2026-09-21 | Reporting requires GitHub sign-in; no sensitive report was submitted as a test. Do not post findings publicly; see [SECURITY.md](../SECURITY.md). |
| Publication or deployment | Explicit authority for the specific artifact and target, plus all applicable evidence above | The private `0.0.0` development package is not a supported release. No push, publication, or cloud deployment is authorized by these checks. |
