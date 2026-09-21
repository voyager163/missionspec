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
packages for attribution and compliance. This is the exception to the
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
`ajv@8.20.0`, `mdast-util-from-markdown@2.0.3`, `yaml@2.9.1`, and `zod@4.6.5`.
The isolated service pins `@azure/identity@4.13.3`, `@azure/logger@1.3.0`,
`@azure/monitor-ingestion@1.2.0`, and `ajv@8.20.0`.

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
