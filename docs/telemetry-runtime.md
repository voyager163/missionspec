# Minimal telemetry runtime and source handoff

The telemetry receiver is an operator image, not part of the CLI package.
Building or scanning it does not authorize publication, Azure bootstrap or
client endpoint activation. [Operations](telemetry-operations.md) and the
[operator MSI profile](telemetry-operator.md) retain their separate gates.

## Runtime closure

The original multi-stage Dockerfile uses a pinned Node 24 build image for
installation, compilation and tests. Its final stage is pinned
`gcr.io/distroless/cc-debian13:nonroot` for Linux AMD64. It copies only the verified
Node executable/license and service production dependencies, compiled code,
schema and notices. npm, Corepack, Yarn, Perl, mount, shells, package managers and
the old bookworm utility closure are not copied into the runtime.

This is a maintained minimal base, not an in-place purge of essential packages.
Its original package metadata remains intact. The initial lock covers 14 Debian
runtime packages, their 10 exact source versions, and the existing 51-package
service runtime dependency graph. It is not a claim of file-by-file minimality
within every maintained base package. Development packages and verification-only
Node distribution archives do not enter the executable runtime.

The process runs as UID/GID `65532:65532`, with direct Node invocation and
`--no-turbofan --no-maglev --disable-sigusr1`. The normal JavaScript optimizing
compiler paths are disabled; this is a reviewed runtime mitigation, not an
upstream security patch or elimination of all WebAssembly/native compilation.
Service startup rejects inspector/debugger flags, tracing,
proxy and TLS-verification override environments. The image retains CA roots.
Managed identity still uses the existing explicit UAMI credential, not a CLI,
default-credential, key or secret fallback.

Do not override the reviewed image command, enable an inspector, inject startup
agents or treat a non-root process as a sandbox for untrusted JavaScript.
Node can process some native startup flags before application validation; the
reviewed image/configuration boundary remains essential.

## Sources and notices accompany the same image

`services/telemetry-ingest/runtime-sources.lock.json` records the actual runtime
package metadata, exact Debian source versions, content-addressed public source
URLs, sizes and SHA-256 values. It also pins the official Node source/distribution
checksums, original notices and immutable base OCI metadata.

The build runs `scripts/runtime-sources.mjs` to verify complete `.dsc` source
component sets, the exact official Node binary and license, package/source
coverage, and an allowlisted service/build-source snapshot. It produces:

| Image path under `/usr/share/doc/telemetry-runtime/` | Content |
| --- | --- |
| `runtime-corresponding-source.tar.gz` | Actual versioned source archives, Debian packaging/patches/build scripts, original notices and service/build sources |
| `runtime-source-manifest.json` | Package-to-source mapping, file lengths/hashes, verification scope and provenance limitations |
| `runtime-source-receipt.json` | Exact final source archive size/hash and manifest hash |
| `runtime-notices/` | Immediately readable original runtime copyrights/common licenses, Node/distroless/service licenses and source instructions |

Recipients receive the source bytes with the **same one image**. This is not a
homepage link, invented written offer or promise of a later source publication.
No second hosted source service, public operator configuration or new vendor
runtime agreement is introduced. The roughly 296 MB source archive contains
upstream source/build tooling as source data, not installed runtime executables.

Use normal container-copy tooling to obtain these files from a stopped container;
no shell, package manager, cloud credential or private installation key is needed
inside the image. For a locally available reviewed image, create a stopped
container, copy `/usr/share/doc/telemetry-runtime/` to a recipient-owned directory,
then remove that specific stopped container. Check the copied archive/manifest
against the receipt before extracting. Keep source and notices with subsequent
redistribution.

The artifact preserves relevant GPL/LGPL texts, GCC Runtime Library Exception,
Debian copyright/source instructions, Node's full bundled-license text and the
service dependency notices. Shared libraries remain separate and replaceable
in a locally rebuilt image; no extra reverse-engineering restriction is imposed
on LGPL-covered portions. Original license terms govern. Delivering source and
notices is technical evidence, not a blanket legal certification.

### Reproducibility and provenance limits

Generation is offline by default from a verified cache; `--download` explicitly
allows only locked credential-free HTTPS source URLs. Redirects, mutable refs,
wrong lengths/hashes, missing/surplus source components, corrupt cache entries
and symlink/private snapshot inputs fail closed. The archive uses fixed ordering,
timestamps, ownership and encoding; it does not record host paths or operator
environment data.

The lock's candidate image identity records the original runtime-inventory
capture, not the final source-bearing image's self-referential digest. Each final
image receives its own manifest digest and source receipt. Verify its actual
package metadata and Node executable against that receipt/manifest.

Official Node checksum equality and source/version correspondence are checked.
Upstream signatures are retained but are not represented as independently
authenticated unless that separate verification occurs. The included distroless
Git revision is supporting assembly source with matching package locks, not a
claimed authenticated build-to-Git attestation. This is not a bit-identical
compiler/sysroot rebuild proof; appropriate build dependencies are still needed.

## Local qualification, without a hosted scanner

After building on a verified local builder, run the service tests and both
container checks with external networking disabled, read-only root, dropped
capabilities and no-new-privileges:

- `container-smoke.mjs` verifies health and a validated event with in-memory
  storage.
- `container-qualification.mjs` verifies non-root/AMD64/Node identity, exact
  retained package metadata, absent unused executables, delivered source hashes,
  CA availability, the **real managed-identity SDK against a loopback fixture**,
  and native TLS accepting a locally trusted test certificate while rejecting
  it without that trust. Supply a generated localhost-only certificate/key
  directory through `MSR_TEST_TLS_DIR`; never use an operator credential.

These are compatibility checks, not production Azure qualification. Preserve
the final immutable image manifest/config IDs, source receipt and scanner report.
Run a non-uploading scanner on the saved exact image without suppressions,
`ignore-unfixed`, skipped runtime paths or removed package metadata. Record the
scanner/database versions and all remaining findings, not merely a zero exit
code. Source archives are not a reason to conceal the real runtime inventory.

### Local SDK deadline and cancellation faults

`services/telemetry-ingest/tests/sdk-deadline.test.mjs` runs the installed pinned
identity/ingestion SDKs with the production storage adapter and receiver. Token
HTTP responses are synthetic and in-memory; ingestion uses the real SDK HTTP
transport against loopback TLS. Each case runs in a separate process because
MSAL caches its selected identity source. No Azure credential, token acquisition,
remote ingestion, or receiver image build is performed.
The loopback-only certificate/key in `tests/loopback-tls.json` is public test
material, never an operator credential or a production trust root. It avoids an
OpenSSL CLI dependency in the pinned slim build stage; tests still use the real
SDK TLS transport with verification enabled and explicit fixture trust.

The bounded cases retain fast success, slow first token on the unprepared adapter,
slow ingestion, disconnect during either stage, and all eight unresolved work slots.
They retain the 650 ms storage timer and 1,000 ms local client ceiling. Timings
include ordinary event-loop scheduling delay; they are not a claim that a
JavaScript timer creates an atomic 650 ms provider stop.

In the current pinned MI/MSAL path, caller cancellation does not interrupt the
synthetic token request: that SDK task can outlive the receiver's 503 or client
disconnect. The receiver keeps its work slot until settlement, and the real
ingestion HTTP transport rejects an already-aborted request before a late token
can cause an ingestion POST. Once an ingestion request was already sent,
cancellation is not proof of non-commit by a remote provider. These fault tests
verify local safety/cleanup behavior, not the cause of a historical Azure timeout
or a proof that Azure ingestion did not commit.

### Durable queue candidate (local source only)

The prepared-identity image did not make synchronous Logs ACKs fit the one-second
client contract. The approved next design moves persistence to one dedicated
Standard LRS Azure Queue in Australia East, not the private runtime-state account.
This source change is **not** a rollout or permission to reopen ingestion.

Production replies empty/no-store **202 only after Queue ACK**, with a maximum
650 ms enqueue budget. The same closed projection, including original receipt
`TimeGenerated`, is persisted as at most 1 KiB UTF-8 JSON with explicit 3,600-second
TTL. A timed-out enqueue can already exist remotely; no automatic resend or
optimistic acceptance occurs. Eight unresolved sends remain bounded.

Producer readiness depends on its explicit Storage token, fresh queue properties
and approximate capacity below 10,000—not on Logs health. Monitor and Storage have
separate explicit-UAMI, 20-second singleflight preparation for their exact scopes.
SDK refresh/expiry metadata controls renewal; failed/late preparation remains
failed until restart. Disabled construction/startup performs no token, queue or
worker requests. The existing 30-second startup probe and one-second client limit
are unchanged, not guaranteed by a nominal preparation budget.

One worker in the existing singleton receives at most 32 messages with 60-second
visibility, after Monitor preparation, and sends one Logs batch under a separate
15-second deadline. The batch disposition bound is 45 seconds, individual Queue
transactions at most five seconds, and no leases are renewed. Delete follows a
confirmed Logs ACK, or explicit invalid/expired/over-three-dequeues discard.
Unknown uploads/deletes wait for visibility/TTL, with capped backoff, not immediate
replays. At-least-once attempted delivery can duplicate analytics and can discard
after attempts/TTL; it is neither FIFO nor exactly-once nor a no-loss guarantee.
Operational queue IDs/pop receipts are never analytics fields or logs.

`queue-sdk.test.mjs` exercises the real pinned Queue SDK's XML serialization,
bearer policies, TTL, metadata, visibility and delete receipts through actual
loopback TLS. A 5.2-second Logs ACK does not delay the HTTP 202. Failure, redirect,
late durable send/unknown ACK, full queue, invalid input and disabled zero-network
cases are covered. `queue-storage.test.mjs` additionally checks all eight stalled
enqueue slots, a single 32-message batch, late-upload quarantine, bounded attempts,
expiry/discards, freshness, circuit backoff and disable behavior. The original
identity/upload deadline regression fixtures remain; they are not the production
direct-delivery route. All use synthetic local data without Azure calls.

The exact new runtime dependency is `@azure/storage-queue@12.32.0`, selected from
public package metadata. Its compatible XML parser is explicitly pinned by an
override scoped only to `@azure/storage-queue` to `fast-xml-parser@5.5.9`: the initially selected newer parser brought a
transitive package with no shipped license file and failed the existing gate.
No missing-notice waiver or JSON-schema license exception was broadened.
The new locked closure contains **62 runtime packages** (previously 51), with full
MIT/other existing notices and a narrowly updated reviewed-text catalog. Existing
Node, Identity, MSAL, Monitor Ingestion and Core Pipeline versions did not change.
No service SDK enters the root CLI package. This compatibility/license pin still
requires the parent's new exact-image vulnerability review; it is not scanner
clearance or a native patch claim.

A fresh source-bearing image must include this code, lockfile and updated
service notices. Existing images, original archives, source pins and approvals
remain historical evidence, not authority for the queue topology. Parent-owned
ARM account/queue/RBAC, client acceptance semantics, third-image qualification,
source/native/scanner review and explicit rollout remain separate gates.
The approved conservative **USD 349.37/month** model includes three retained images,
queue operations/storage/security and retry reserves within the USD 350 estimate;
it is **not a bill cap or permission for extra resources**. No image build,
publication or Azure operation is performed by these local tests. Detailed API,
health, queue bounds and delivery semantics are in [operations](telemetry-operations.md).

### Native/bundled Node coverage is separate

An empty High/Critical package result does not establish coverage of the copied
Node executable, V8 or statically embedded libraries. Record `process.versions`,
verify the executable against the official distribution and inspect relevant
upstream/Node backports and service prerequisites separately.

During the initial remediation, a second maintained Node 24 distroless base
carried the **same Node/V8 binary**, so switching packagers did not resolve
native advisory questions. A `--jitless` trial broke Node's fetch/Undici
WebAssembly dependency and was rejected rather than silently degrading behavior
or changing the test to manufacture success. The narrower optimization-disabled
profile preserves the required WebAssembly/fetch behavior and is tested explicitly.

Browser V8 advisory patch gaps must remain visible where Node-specific
applicability is unresolved. This service has no public JS/Wasm/plugin execution
interface and does not intentionally activate a debugger, but that observation
is not a general proof that every JIT/compiler defect is unreachable. Do not
relabel upstream fixes as installed or claim complete native vulnerability
coverage from package metadata. Preserve the bounded advisory review with the
candidate and require the release gate to assess unresolved native findings.

## Size and publication boundary

Including sources increases image-transfer size, not event size or event
retention. Recalculate registry occupancy using the final manifest's actual
compressed layers and the bounded retained-digest count; do not assume all layers
deduplicate. Confirm Basic ACR's included storage still covers the planned
occupancy and measure deployment pull/startup time separately from the client's
one-second operation budget.

No source archive, runtime image or server dependency tree is added to the CLI
package. The initial image publication limit remains one reviewed immutable AMD64
digest. Future-build counts are cost assumptions, not advance push permission.
