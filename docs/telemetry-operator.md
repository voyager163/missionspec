# Direct ARM telemetry operator

The **only supported deployment definition** is
`infrastructure/arm/telemetry` in the
[source repository](https://github.com/voyager163/missionspec).
It generates fixed, scoped ARM phases from the canonical event schema and
requires full local what-if review. It is not a general shell/ARM executor.

The private-runner OpenTofu, VM, Container Apps Job, authentication broker and
encrypted-relay route is retired. Its complete uncommitted source/diff,
qualifications, original approvals, ledger and receipts were preserved privately
before the inactive public definitions were removed. No existing foundation
resource, image, state blob, permission or governance NSG was deleted or retagged.
Retired-route approvals are terminal; none authorizes the direct ARM route.

## Local review and authority

### Durable queue design: separate topology and third-image review

The approved architecture keeps the CLI's **1,000 ms** request deadline and
places a bounded **durable Azure Storage queue** ahead of the asynchronous
Logs upload. The design/cost approval is not permission to deploy, publish,
send a receiver request, acquire a token, query data, or configure the root CLI
transport. Those remain exact-preflight-gated parent/operator actions.

The new `durable-queue.mjs` contract preserves configuration v2, collector
run/ownership IDs, all original seven execution origins and the original
publication. Both the original and prepared-identity images/tags remain.
Failed terminal windows retain their failure result; image/profile wiring
never converts a failed POST to success or changes the admission flag.

**Topology and identity.** `queue-topology.json` is derived from the unchanged
base configuration and a separately reviewed, explicit 8–16-character
lowercase alphanumeric namespace. The account name is `msrtq<namespace>`; the
only queue is `telemetry-events-v1`, in the existing telemetry group in
Australia East. This is a **new** StorageV2 / Standard_LRS account, not reuse
of private runtime-state storage. HTTPS/TLS1_2, `allowSharedKeyAccess: false`,
`allowBlobPublicAccess: false` and OAuth defaults are explicit. Its public
endpoint accommodates the existing no-VNet Container App using Entra; it
does not introduce a VM, VNet, private endpoint, firewall/security exception,
SAS, key, connection string or anonymous queue access. Inherited Defender
and subscription policy stay unchanged. CORS, diagnostics and exports stay
empty; the worker cannot create/delete a queue or manage service properties.

The existing ingest UAMI keeps `Main` lifecycle; registry pull keeps `None`.
The custom role is assignable and assigned **only at that exact queue**:

| Classification | Exact provider operation | Use |
| --- | --- | --- |
| Action | `Microsoft.Storage/storageAccounts/queueServices/queues/read` | Queue metadata |
| DataAction | `Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action` | Send a new message |
| DataAction | `Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action` | Receive and delete an individual message |

The [official operation mapping](https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory#permissions-for-queue-service-operations)
and [provider catalog](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/storage#microsoftstorage)
are authoritative. The settled worker makes **zero visibility-update calls**,
so Sender `add/action` suffices; `messages/write` would add unused update
access. Processor `messages/read` would add unused peek access, and
`messages/delete` would add clear-all access. None is granted. No account
Contributor, broad Queue Data Contributor, wildcard, alternative principal or
new identity is accepted. Registry, DCR and workspace grants remain unchanged.
Azure documents [resource-instance assignable scopes](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions#assignablescopes)
as possible but generally discouraged for role-count reasons. This one
dedicated role deliberately retains the tighter queue-only bound; review must
not silently replace it with an account/group assignment.
Fresh preflight also validates the exact three operations' `isDataAction`
classifications from the fixed Storage provider catalog read; no keys/SAS
operations are available.
The actual catalog repeats metadata-read entries with the same classification.
Every matching entry must agree; a missing or contradictory classification
still fails. The registered account and queue-service API versions are required.
The provider listing can omit the nested queue type documented in the
[2025-01-01 queue resource contract](https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/2025-01-01/storageaccounts/queueservices/queues);
full template validation and exact child-resource what-if/readback remain
mandatory. An advertised incompatible child API is not ignored.

**Runtime binding.** The queued image receives only two additional values:
`AZURE_QUEUE_URL` and `AZURE_QUEUE_RESOURCE_ID`. They must match the reviewed
account/queue IDs exactly. There is no runtime-configurable arbitrary endpoint
or fallback to direct Logs admission. Its source-bound profile pins the
20-second Storage credential preparation, separate Monitor consumer scope,
650 ms enqueue, 1 KiB record, 3,600-second per-message TTL, approximate-count
10,000 admission threshold, eight concurrent enqueues, batch size 32, one
15-second Logs upload at a time, 60-second visibility and three deliveries.
The bounded implementation additionally records five-second queue operations,
a 45-second total leased-batch budget, 30-second metadata/idle polling and
5–60-second backoff, zero visibility renewals, one Queue SDK try, zero Logs
SDK retries/redirects, at most 32 deletes per batch and ten-second shutdown.
These distinct budgets are explicit review inputs, not
extensions of the CLI timeout. Disabled operation makes zero network requests.
Counters reset on restart and queue count is approximate: neither is an exact
global backlog limit or a spend meter.

**Local and live phases.** `preview-queue queue-storage <private-revision>`
requires only `config.json` and `queue-namespace.json` (`{"namespace":"..."}`).
It creates an unapproved preview and makes no cloud calls. `prepare-queue`
prepares one fixed template locally; the fixed order is:

1. `queue-storage`: one account, its default service, and one queue, created
   together with exact ARM dependencies; no implicit SDK creation.
2. `queue-role`: only the minimal custom role definition.
3. `queue-assignment`: only the existing ingest UAMI at the queue scope.
4. `disabled-queue-upgrade`: only the separately published third image and
   the two queue environment values, with `MSR_INGESTION_ENABLED=false`.

`queue-review.json` is a closed `accept-exact-durable-queue-topology` review
binding config, topology and current policy source, canonical approval/expiry
(at most one hour), and all-false `QUEUE_AUTHORITY`. `check-queue` repeats the
original history, foundation/security, exact resources, account, provider and
role reads and full validate/what-if. `execute-queue` separately requires
`queue-policy-publication.json` and the exact phase approval. As with image
changes, independent reads are limited to four in flight, each request to
15 seconds and preflight to 120 seconds. A durable intent permits one PUT and
a bounded 120-second rollout; uncertainty requires reconciliation, never retry.

Each successful queue phase writes a new immutable `<phase>-record.json`.
For the next private revision, retain those full records under their exact
phase names in `queue-records.json`; do not replace old receipts. The new
account becomes known inventory **only** through validated execution,
approval, source, what-if, deployment identity and readback records. Any other
account/queue/resource remains an error. Role definitions and assignments,
diagnostics, account encryption/network settings and queue inventory are read
again at dispatch, including after request-body preparation.

The new receiver candidate is **version 2**, with
`kind: reviewed-durable-queue-receiver`, the complete `priorCandidate`, original
`legacyPublication`, exact topology and an independent
`publish-one-reviewed-queue-receiver` review. Its exact third manifest/config
must be supplied by the future real build; null/placeholders/`qualified: true`
are not publishable evidence. It retains notices, scan/database freshness,
source archive, Linux/amd64/UID/command restrictions and native caveats. Only
this kind adds `src/queue-storage.ts`, `tests/queue-storage.test.mjs`, and
`tests/queue-sdk.test.mjs` to the original 35-file closure (38 total). Typed
SDK proof binds the source file map and runtime-source manifest, explicit
fixture pass/fail counts, zero-network disabled behavior, durable ACK,
restart/TTL/overflow/retry/visibility/worker bounds and no implicit creation.
Unit-generated artifacts are not real publication or qualification evidence.

Publication preview requires exactly the two existing manifests/tags and empty
referrers. After the one separately reviewed copy, all three full manifests
and empty referrers must be read back. No fourth digest, retag, deletion, repush,
index or registry-admin exception is admitted. Existing image-only upgrade/
rollback behavior remains available only for its original direct profile.

Version-5 reconciliation binds `receiverUpgradeSha256`, `queueRecordsSha256`
and the exact receiver candidate. This allows a current prepared/queued
runtime observation and additional *qualified* account inventory without
rewriting the original seven phases, old two-image inventory, version-3/4
reviews, receipts or source hashes. Each new proposal needs its own exact
version-5 review. The disabled queue image upgrade requires the recorded
failed prepared-identity window as a terminal false/503 predecessor, all three
queue records and a fresh instance/phase approval. Only image + queue env
changes are accepted; identity, flags, ports, probes, resources, lifecycle,
network and schema remain unchanged.

**Cost and verification.** Official evidence remains in private
`revision-20260924-durable-queue-design/{official-queue-prices.json,cost-review.json}`.
The 31-day model uses 100,000 accepted messages/day, Queues v2 Standard LRS
Australia East Class 1/2 at USD 0.004/10K and storage at USD 0.045/GB-month:
311.23 existing + 9.57 third image + 10 extra storage security + 6.20 normal
operations + 2.14272 conservative idle operations + 0.225 storage + 10 retry
reserve = **USD 349.36772**, rounded once to **USD 349.37**. All existing
HTTP/rejected-request, ambiguous-environment, load-balancer, IP and security
reserves remain; there is no free-grant deduction. The USD 0.63 headroom is
small and **not a billing cap**.

Queued POST expects **202 = durably admitted, not Logs persisted**; direct
profiles/history still expect 204. A newly approved paired window requires
both owned bounded Logs rows, then observed approximate queue drain, followed
by terminal false/503. A missing count never defaults to zero; ACK/counters
alone never qualify a window or activate the CLI.

### Disabled receiver image upgrade (local candidate, no implicit release)

The version-1 `receiver-upgrade.mjs` overlay leaves configuration v2, its
`receiverDigest`, run ID, ownership tags, all seven original ARM execution
origins, original publication, and completed/failed synthetic windows unchanged.
It is a separate reviewed transition, not a migration or reinterpretation of
the historical ledger. The new receiver is **conditional disabled/synthetic
only**: optimization-disabled CVE-2026-91745, debugger-disabled CVE-2026-93377,
and unproven CVE-2026-91728 applicability are retained. Neither scan counts nor
prepared managed-identity readiness constitute native or production clearance.

In a fresh private revision, `receiver-candidate.json` contains a closed profile:
exact OCI manifest/config **bytes** and digests; Linux/amd64, UID/GID
`65532:65532`, the unchanged Node command and all image runtime defaults;
the exact 35-file build-source closure and immutable Git commit; corresponding-source
archive/manifest and notices bytes/hashes; complete scanner JSON, database hash,
validity and unsuppressed severity counts; and the explicit 20-second,
single-flight prepared-UAMI contract. Disabled start acquires no token,
readiness/POST admission requires a prepared token, expiry triggers refresh,
and failed initialization requires restart. Server 650 ms and client 1,000 ms
deadlines remain unchanged. A fresh upgrade or synthetic admission requires a
still-current scan database; expiry does not block the fixed disable or a
separately approved rollback to the original disabled image.
Source verification also binds the fixed root build/license inputs and receiver
operations/runtime documentation in that closure. It does not enumerate every
tracked service-directory file or require unrelated `.gitignore`/editor files
inside the source archive. Missing or extra profile inputs fail closed.
The notices bundle contains the complete
hashed inventory and canonical base64 for every file, preserving compressed
Debian notices without UTF-8 conversion. Scanner database timestamps retain
their original 3–9 fractional digits; deadline checks conservatively use
millisecond precision. The complete local qualification report is independently
hash-bound to the same image/config/source, scanner database, severity counts,
resource limits, and disabled/slow-identity/failed-identity results. Its local
success explicitly carries no cloud, publication or production authority.

The candidate includes the **complete original publication record** plus a
separate `publish-one-reviewed-receiver-upgrade` review. That review binds the
profile, base config, immutable published policy source, registry, repository,
one digest-derived tag, exactly two retained digests, and the entire cost
object. Source verification reads Git blobs; historical code is never executed.
The original receipt is not changed to say two images existed historically.
The publication record must independently retain the single-copy intent/time,
exact remote graph/config bytes, source/notices bindings and closed inventories.
It is supplied only after the separately approved publication actually happens.

With `publication: null`, the local-only
`preview-image-publication disabled-image-upgrade <private-revision>` reads
`receiver-publication-inventory.json` and writes an unqualified preview.
Inventory must contain only the original repository, original digest/tag and
no referrers. After publication, reads require that same old manifest/tag and
exactly one reviewed candidate/tag, no third image, index, referrer, retag,
deletion, repush, registry admin authentication or unknown-inventory exception.
`firstReleaseCost(2)` is **USD 311.23 / 31 days**, retaining the complete
request/security/environment/network reserves under USD 350. The parent must
review this changed count and cost **before** a push. No command here pushes.

`prepare-image disabled-image-upgrade <private-revision>` is also local-only.
It requires real candidate publication evidence and the closed terminal
false/503 predecessor, and creates a fresh `image-instance.json`, plan and
template. `check-image` repeats the account, foundation, budgets, providers,
permissions, role definitions/assignments, identities, privacy, image inventory,
and full bounded asynchronous ARM validate/what-if gates. The only permitted
effective delta is old image → reviewed image while ingestion stays `false`;
ports, probes, resources, environment, scale, UAMI scopes/lifecycles, containers,
volumes, runtime defaults and resource identity remain exact.
Full what-if may contain the one app `Modify` plus known preserved resources
marked `Ignore`, as Azure returns for this group. The complete seven-entry
payload remains hashed and retained. Unknown IDs, a second `Modify`, duplicate
IDs, or preserved-resource `Create`/`Delete`/`NoChange` entries are rejected.

`execute-image` is a **separate parent-approved action** requiring the exact
fresh phase approval and `image-policy-publication.json`. It uses a unique
owned deployment name, shared lock and global durable UUID reservation, records
intent before one PUT, and repeats source/security/current-app checks after
request-body preparation. Unknown submission is terminal for replay purposes.
Deployment plus new latest-ready healthy revision and final image/identity/
privacy/security reads must complete within the same 120-second rollout bound.
The full preflight has its own unchanged 120-second deadline. Only after it
returns does the controller establish a final-check deadline, capped at
120 seconds and by both approval expiry and the proof's five-minute freshness.
Final checks re-read mutable governance/budgets, workspace/environment/DCR
privacy, registry/image inventory, exact role definitions/grants and app/UAMI
identity; independent reads are batched. They do not traverse historical
deployments or the foundation again after the full fresh preflight.
After durable intent, one absolute 120-second rollout deadline covers body
preparation, the repeated final dispatch checks, PUT, polling, privacy/security
and final app/revision reads. Every cloud call receives that remaining bound
(at most 15 seconds); neither reservation nor an individual read renews it.
Approval/proof expiry can shorten either stage. Late responses cannot authorize
a dispatch or qualify a readback.
The preflight now batches independent reads through one four-command limit.
Foundation snapshots/absences, deployment and resource identity checks, privacy
reads, registry inventory and permissions/provider/quota evidence retain every
previous read and validation. Workspace identity is checked before dependent
DCR validation; role-definition ordering retains the custom role last.
Queue wait consumes the original deadline, and each command receives at most
15 seconds of its remaining time when actually dispatched. Command errors stop
their shared queue and validation errors stop their batch; in-flight read-only
commands remain bounded. There is no hidden retry or fallback to incomplete evidence.
No ingestion request, toggle, deletion or app recreation is included.
An explicit `disabled-image-rollback` has its own fresh approval, instance and
exact new-image preimage; it does not overwrite drift or borrow enable authority.
It requires a settled reviewed image-change predecessor, not an invented
success after an unknown or unready upgrade. Unresolved upgrades remain a
readback/review hold; do not retry them blindly.

On success, `disabled-image-record.json` is a new immutable execution record.
For the next normal synthetic window, supply that exact record as
`receiver-upgrade.json` and `window-predecessor.json` in a fresh revision.
The runtime uses its new disabled anchor and candidate profile while keeping
the original disabled-app/publication receipts as historical prerequisites.
Both paired window approvals still bind the complete prerequisite set, new
UUID, full what-ifs and source; the image transition's UUID remains in the
global predecessor/replay chain. No preview is a qualified receipt, and no
fixture in the tests is an approved or published receiver.

After the separately approved image copy succeeds, use a **new** private
revision for current-source reconciliation. The actual `receiver-candidate.json`
still carries its original publication review/source/commit and single-copy
receipt. `reconcile disabled-app` emits a version-4 proposal with
`receiverCandidateSha256`, verifies the full candidate publication, and reads
exactly the preserved old manifest plus that candidate (including empty
referrers). It keeps all seven original execution origins and the old
publication record intact; a version-3 proposal cannot serve as implicit
two-image proof. Only an exact version-4 review of the new proposal under the
current policy source permits adoption. The resulting read-only receipts retain
each original phase's source/deployment and add the explicit candidate binding.
A changed/missing publication, changed legacy record, unknown digest/tag or
referrer still fails. The current profile/source files and the publication's
original source are not changed merely because controller policy is updated.

Use the existing authorized operator Azure CLI for control-plane authentication
over TLS, with the exact subscription specified on every request. Do not switch
the global default account, request/print tokens, enable registry admin login,
retrieve workspace/storage keys, use SAS or introduce client secrets.

Generated configuration, full templates, **full what-if JSON**, current
readbacks, receipts and approval records stay under the ignored
`infrastructure/arm/telemetry/.operator-private/` directory or a new
`revision-YYYYMMDD-<label>` child: directories `0700`,
regular files `0600`, encrypted operator workstation. No private contact,
subscription or principal is an example in public source.

Private JSON loading is qualified only on the local Linux/macOS POSIX operator:
real/effective UIDs must agree. Each file is opened once with `O_NOFOLLOW`, then
read through that held descriptor, not reopened by pathname. Before/after
`fstat` requires a regular, single-link, current-owner file with exactly `0600`,
unchanged identity/metadata and at most 64 MiB; reading itself is bounded.
Symlinks, hard links, changed files and malformed JSON fail closed without
printing file contents. Only an absent optional file becomes `null`.
Canonical private directories require current ownership and exactly `0700`.
This does not prove global secrecy or defend against arbitrary replacement of
trusted ancestor directories. Azure CLI still opens generated request/template
paths, so the local operator and private directory remain part of the trust boundary.

```sh
node --test infrastructure/arm/telemetry/tests/*.test.mjs
node infrastructure/arm/telemetry/controller.mjs reconcile disabled-app infrastructure/arm/telemetry/.operator-private/revision-20260923-app-readback
```

`prepare` is local. `check` rechecks account/permissions/providers/region/quota,
the exact preserved foundation, budgets/security policy, ownership and names,
then runs nonmutating ARM validate/what-if. An optional `validate-preview`
performs only template/what-if validation and writes `qualified=false`; it cannot
waive a failed foundation/account/cost gate.

### Bounded asynchronous ARM what-if

The failed historical window is preserved: it sent two initial health GETs and
no event POST, query or toggle PUT. Both preflights stopped when the old
15-second subprocess limit killed the **entire** blocking CLI what-if poller.
That is not an authorization/absence result or evidence of a deployment.
Its approvals and run journal must not be reset or reused.

What-if now uses the documented
[2025-04-01 deployment what-if protocol](https://learn.microsoft.com/rest/api/resources/deployments/what-if?view=rest-resources-2025-04-01):
one nonmutating POST for the exact generated deployment/template, followed by
GETs of the returned operation handle. Results remain `FullResourcePayloads`
and undergo the same closed resource/delta policy. Inline templates are static;
external template links and ARM expression strings (including list-key/SAS
functions) are rejected. Deployment PUT is not available in this adapter.

The request helper uses the **existing Azure CLI's own Python environment**
and subscription/tenant-selected user credential through Azure Core's
authenticated pipeline. No exposed-token command, new identity SDK, default-
credential fallback, registry/storage secret or global account/config change
is introduced. The qualified local layout is Homebrew Azure CLI 2.90.0 with
Azure Core 1.39.0 and requests 2.33.0; other runtimes fail pending qualification.
Redirects, automatic request/auth-challenge retries and insecure TLS are disabled.
Body/results go through private bounded files, never stdout or debug logs.
`arm-whatif.py` is included in the canonical source hash. Historical commits
without that file retain their original three-file hash; Git blob existence is
checked, not inferred or rewritten.

Azure's actual Location is an opaque, subscription-scoped
`/operationresults/<opaque-id>` URI with `api-version,t,c,s,h` context fields.
These sensitive server-issued fields are kept private, never decoded as a
region or substituted with caller values. The only accepted alternatives are
the explicitly scoped region-bearing Microsoft.Resources result paths.
All handles require HTTPS `management.azure.com`, the exact subscription/API,
no URL userinfo/port/fragment/encoding ambiguity, a closed query shape and the
same immutable handle returned by the one start. The Python helper independently
binds every poll to the saved authenticated start response and request fingerprint.
Foreign, changed, missing or malformed handles are not followed.

Resource-group what-if rejects a request `location`, even though the shared
schema lists it: the helper first GETs that exact group's real location and
requires Australia East. Subscription-scope starts bind the supported
`location: australiaeast` field. The operation ticket is not a storage SAS or
an authentication fallback; the normal ARM bearer context remains mandatory.
The adapter does not claim to infer Azure's internal routing region from
opaque ticket bytes.

Each request/process is bounded by **15 seconds and the remaining shared
deadline**; the complete phase check remains at most **120 seconds**. No
polling stage restarts the budget. Integer Retry-After is respected; a delay
that cannot fit stops the check rather than polling early or extending time.
At most 40 start/poll requests are permitted, with no second start after
uncertainty. Failed/cancelled/unknown states, redirects, malformed JSON,
unreviewed async headers and incomplete/paginated results all fail closed.
Cancellation is checked again immediately before dispatch.

Private traces retain only bounded step labels, elapsed/configured time,
process timeout/killed/signal/code and sanitized ARM code/status. The opaque
handle is represented in traces by a hash; full service replies remain separate
private artifacts. Process-budget exhaustion is distinguished from HTTP errors,
and the window journal retains these typed details without raw args, URLs,
tokens, stderr or template contents. Receiver 1,000 ms HTTP, 120-second rollout,
600-second objective, recovery reserve and approval limits are unchanged.

Version 2 configuration is closed and binds the unchanged original origin,
the immutable scanner-adoption delta and the actual pre-update foundation
budget snapshots by SHA-256. Its closed budget object permits only USD,
previous project amount 250, reviewed project amount 350, state amount 50 and
new telemetry amount 300. A revision uses new private files; do not overwrite
historical origins, approvals, plans or ledgers, or reuse old source/config hashes.
Neither the scanner-adoption decision nor the budget decision is phase execution
approval.

Budget comparisons normalize notification **key casing only**, while preserving
values and rejecting collisions. Budget GET comparisons exclude only
server-generated spend/forecast and ETag fields; writable fields remain exact.
Full ARM what-if additionally omits the known empty `contactGroups` and
`contactRoles` arrays: only those omissions are normalized to empty arrays.
Nulls, nonempty contacts, changed recipients and unknown writable fields fail;
actual GET readbacks still require the arrays.

### Completed deployments and read-only reconciliation

The budget-only deployment succeeded under `39fa4f8`. Core was subsequently
released under `9a498d9` after the unchanged native CodeQL check passed. ARM
reported core `Succeeded`, but the old readback predicate stopped qualification:
the default-network environment returned a null infrastructure group. The old
core journal remains `reconciliation-required`; there is no invented legacy
success receipt. Neither deployment may be resubmitted or deleted to resolve
that readback hold. After the reviewed core reconciliation, workspace-access
succeeded under `fa92e9b` with a qualified receipt. Data then reached ARM
`Succeeded` under the same source, but its strict readback stopped on Table
display metadata and the DCR's computed workspace ID. Its original
`reconciliation-required` journal and absent success receipt remain unchanged.
The custom upload-role definition later succeeded and qualified under `4ee9324`.
Its original source, approval, journal and receipt remain unchanged. No role
assignment is implied by defining that role.
The three scoped assignments subsequently succeeded under `9e07fb3`, followed
by a separately released, verified single-image publication. The disabled app
also reached ARM `Succeeded` under that source, but its legacy readback stopped
on the provider representations described below. Its original failed journal
and absent qualified receipt remain historical facts. Platform `Running` or
`Healthy` status is not an independently performed HTTP health/disabled-503 test.

One versioned contract now covers these **seven existing ARM phases**, rather than
adding per-source trust exceptions:

1. `execution-origins-v3.json` contains immutable records of the original
   publication commit/source, exact phase/template, approval, intent journal,
   preflight, validation, what-if, first readbacks and original receipt (null
   when legacy qualification failed), plus the **recorded prerequisite receipt
   map**. Its digest must equal the original approval and preflight receipt
   digest, with the same serialization order. Each prerequisite must match an
   earlier scoped execution's source, phase, deployment and immutable resource
   identity; reconciled prerequisites retain their original review links.
   Templates are rebuilt from these real prerequisites and the canonical
   schema, never from fabricated empty receipts. Original files are preserved separately,
   byte-for-byte. Fixed Git blob reads verify each declared source hash and its
   ancestry in the repository; historical code is never executed. The parent
   independently confirms publication and scanner results.
   The assignment record separately retains its scoped role-definition reads
   and compound approval baseline; other phases retain their foundation-only
   baseline. Neither is substituted for the other.
2. `reconcile disabled-app` uses only scoped GETs and authenticated registry
   inventory/manifest reads for all recorded completed phases.
   The command names the latest phase in the recorded sequence. It verifies the original approval's
   validity **at intent time**, full phase/config/preflight bindings, validated
   ARM template hash and successful deployment identity. It rereads the exact
   existing resources, generated IDs, creation identity, budgets, foundation,
   security baseline, inventory, diagnostic routes and exports. No PUT,
   deployment resubmission or next-phase preparation is available in this path.
   The immutable `reconciliation-proposal.json` is **not qualified authority**.
3. The parent must separately author `reconciliation-review.json`, with exactly
   `version: 3`, `action: "accept-exact-arm-reconciliation"`, `proposalSha256`,
   `sourceSha256` and canonical UTC `reviewedAt`. Review must bind the exact
   current source/proposal and cannot predate the snapshot or lie in the future.
   There is no force flag, inferred approval, or automatic historical-source
   exception.
4. Only then may `qualify-reconciliation disabled-app` repeat the live read-only checks
   and write **new** `reconciliation-receipts.json` and a qualification record.
   These explicitly identify a reviewed read-only reconciliation, retain the
   original executed source and journal outcome, and distinguish legacy receipt
   qualification from current readback qualification. The original approvals,
   receipts and journals are not rewritten. Their expiry never authorizes a new
   write.

Subsequent phase plans bind the proposal/review hashes and the new qualified
receipt set. Fresh preflight rereads immutable identities and privacy settings;
each actual effect still requires full what-if review and its own unexpired
phase approval. Completed phases are refused by `prepare`, `check`,
`validate-preview` and `execute`. A later source change requires a fresh
read-only proposal/review, **not replay of any completed phase**. Old budget-only
lineage and version-1/version-2 reconciliation artifacts remain historical evidence, not
an active parallel authority path or a substitute for the new review.

Image publication is **not an ARM execution**. The origin bundle's separate
`imagePublication` record binds the original one-copy release and validity at
intent, publication binding, journal, qualification record, exact manifest/config
bytes and the unmodified publication receipt. Manifest and config hashes are
verified independently, including the source/notices graph and retained scanner
and native conditions. Current registry reads must still show exactly the one
reviewed repository/digest/config with admin and anonymous access disabled.
No publication is repeated, promoted into a fictitious ARM deployment, or
rewritten as execution by the new policy source.

Review full private JSON on this machine. SHA-256 binds bytes, not human
authority. Only a separately authorized exact phase approval can invoke
`execute`. The approval binds action, config/source/phase/origin/prior-receipt/
policy/what-if hashes and a validity interval of at most one hour. The approval
is a closed object: `action`, `configSha256`, `sourceSha256`, `phaseSha256`,
`originSha256`, `receiptsSha256`, `baselineSha256`, `whatIfSha256`, `approvedAt`,
and `expiresAt` are all required; additional fields are rejected. Hashes are
64 lowercase hexadecimal characters. Both dates must be canonical UTC
`YYYY-MM-DDTHH:mm:ss.sssZ`, with approval no later than the current time and
expiry strictly later. Fresh preflight must match every binding, start during
the current check and remain at most five minutes old.
The original shared controller lock is used; it is not auto-broken.

An intent is persisted before a deployment PUT. Approval expiry and preflight
freshness are rechecked after the final existence read, intent persistence and
request-body file preparation, immediately before local transport dispatch.
This is not an atomic server-side expiry/cancellation guarantee. If the guard
stops dispatch after intent persistence, that journal still requires
reconciliation; it is not removed, reset or recorded as a completed action.
An uncertain/failed/timed-out
write is **never replayed**, nor repaired by deleting a resource group. Preserve
its journal and exact owned resources for read-only reconciliation and a new
reviewed decision. ARM operations can outlive the local request; budget alerts
are not cancellation or a hard cap.

### Assignment absence and mutable role definitions

`RoleAssignmentNotFound` is treated as absence only when Azure returns HTTP 404
for GET API `2022-04-01`, the URL has a canonical role-assignment UUID beneath a
registry, DCR or workspace resource, and its subscription matches the explicitly
selected subscription. Wrong methods, APIs, paths, subscription, auth failures
and throttling remain failures. This is an absence read, not authority to grant.

Before assignment review, the controller reads the actual `AcrPull` definition
at the registry, `Log Analytics Reader` at the workspace, and the custom upload
definition at the DCR. Built-in GUID, name, type and scope availability must
match; the custom role must still have its recorded creation identity, the sole
`Microsoft.Insights/Telemetry/Write` data action, empty other permission arrays
and only the owned telemetry-group assignable scope. A prior success receipt
alone cannot establish that a mutable role still has the intended permissions.

`assignments-role-definitions.json` preserves these scoped reads and canonical
permission signatures. Assignment preflight records `roleDefinitionsSha256`
and `foundationBaselineSha256`; its approval-bound `baselineSha256` hashes
both, rather than reusing the foundation-only baseline. Full built-in permission
lists are included, including any export-job capability in Log Analytics Reader.
Their definition-wide assignable scope does not expand the three resource-scoped
assignments, nor remove the operator's independently inherited Owner access.

After intent persistence and request-body preparation, assignment dispatch
requires another live read of all three definitions. The mutable custom role
is read last. Any identity, permission or assignable-scope drift stops before
PUT, leaving the intent for reconciliation. The existing synchronous
expiry/preflight-freshness guard runs again after these awaited reads,
immediately before transport invocation. These checks are not an atomic Azure
role-version lock: an external administrator can still change a role after the
last read, so concurrent role administration must remain controlled.

## Explicit phases

| Phase | Allowed operation and required evidence |
| --- | --- |
| `project-budget` | Update only the dedicated combined-project budget amount from USD 250 to USD 350, using its actual immutable pre-update snapshot. Preserve dates, exact group filter, notification thresholds and recipients. No resource creation or state-budget change. |
| `core` | After the qualified USD 350 budget deployment receipt and fresh readback, create six new named resources in the already-owned empty telemetry group: Basic ACR, separate upload/pull UAMIs, workspace, Consumption environment and USD 300 telemetry-group budget. Never recreate/retag the existing group or rebuild the foundation budget. Read generated identity/workspace/environment values privately. |
| `workspace-access` | Only the newly owned workspace's two access flags may change. Explicitly verify disabled local authentication and disabled resource-only query authorization. A creation-time override is quarantined, not called compliant. |
| `data` | After access qualification, create the Analytics table with **180-day Analytics and total retention**, and one Direct DCR with exactly the canonical eight fields plus server `TimeGenerated`. No extra archive/export. |
| `upload-role` | Create a custom role definition with only `Microsoft.Insights/Telemetry/Write`, assignable only in the telemetry group. No subscription-wide assignment or management rights. |
| `assignments` | After literal generated-ID readback, assign upload at the exact DCR, AcrPull at the exact registry, and Log Analytics Reader at the workspace for the explicit operator. No guessed future principal IDs. |
| `disabled-app` | After separately authorized publication and inventory/config binding, create one disabled HTTPS receiver from the exact immutable digest. Preserve the qualified image command/user, 0.25 vCPU/0.5 GiB, warm min=max=1, fixed limits and explicit runtime/pull identities. |
| `synthetic-admission` | Only the paired, bounded window controller may change `MSR_INGESTION_ENABLED` from false to true. A separately reviewed valid disable release must already exist. No CLI endpoint/client activation. |
| `synthetic-disable` | The fixed inverse changes only true to false under its own valid release. An already-false, latest-ready app can receive an explicitly read-only completion; this is not a deployment or permission to replay a previous submission. |

Later phases cannot be prepared by pretending server-generated values are
known. Their fixed templates are generated only after the relevant private
receipt exists and has the same config/ownership. Unknown Modify/Delete,
unexpected resource IDs, unowned targets and nonempty new names fail closed.
Only explicitly listed workspace-access fields or the exact synthetic flag
change can be modified; image, command, quota or role changes are not hidden
inside that allowance.

Original collector deployment names keep the full 32-hex-character run ID and explicit unique
two-letter phase codes (`pb`, `co`, `wa`, `da`, `ur`, `ra`, `di`, `sy`, `sd` in table order).
New synthetic windows use `w` plus the full 32-hex-character **window-instance
UUID** instead of reusing the original `sy`/`sd` names. This is a new bounded
test instance, not a new collector/run ID or a resource retag.
Every allowed prefix/phase fits ARM's 64-character limit; characters and length
are checked locally. Nonmutating validate/what-if uses that exact execution
name, not a separate shorter preview name.

No container command/args override is emitted. The separately qualified receiver
config must remain nonroot `65532:65532` with
`--no-turbofan --no-maglev --disable-sigusr1`. Its three native V8 uncertainties
remain conditional disabled/synthetic-stage findings, not patched-CVE or blanket
native clearance claims. The quarantined operator image is never used.

### Paired synthetic window and fixed disable

The completed disabled-state HTTP check is historical evidence, not reusable
HTTP authority. Preparation and reconciliation never send receiver requests or
query event rows. The following preparation is **read-only** and requires the
current source's accepted reconciliation and real prerequisite receipts:

```sh
node infrastructure/arm/telemetry/controller.mjs prepare-window synthetic-admission infrastructure/arm/telemetry/.operator-private/revision-20260923-instrumented-window
```

It writes two fixed templates/full ARM what-ifs, an immutable
`synthetic-window-plan.json`, and the exact pre-window receipt snapshot.
The disable template depends on the already-qualified app and real identities,
not a fabricated future enable receipt. Both templates preserve the reviewed
writable defaults (`exposedPort: 0`, cooldown 300, polling 30) and unique probe
ordering to make the actual delta easier to review.

Before preparing a successor, `window-predecessor.json` must bind the original
window, both actual toggle phases/deployments, paired approvals, intent journals,
qualified readbacks, pre-window receipts and full run outcome. It also contains
a new read-only observation of the exact false/latest-ready app, UAMI identities,
privacy routes and both settled deployment identities. Published source hashes
are checked against immutable Git blobs. A stopped window with an unknown
first POST remains **stopped-disabled**, not a retroactively successful test.
The terminal disabled 503 must already have been recorded under that old run;
preparation does not repeat HTTP requests or reset any old allowance.

`window-instance.json` is a closed object: `version: 1`, a cryptographically
random v4 `id`, `predecessorSha256`, and `previousInstanceIds`. The new UUID
must differ from the collector run ID and every prior instance ID; the prior-ID
list must exactly extend the predecessor's bound list. The same instance is
embedded in both phase hashes and the version-2 window. Both Node and the
Python async what-if bridge derive the actual names from that UUID; neither
falls back to the collector run ID for new toggle requests. Name checks and
live absence reads reject already-created instance deployments.

The first `run-window` also reserves the UUID once in the canonical private
operator directory before any receiver request. This durable reservation blocks
same-ID reuse even if local window files are copied elsewhere. It never replaces
the existing controller lock, old run journal or cloud no-replay checks.
An unreviewed enabled app, unresolved prior deployment, missing terminal proof
or changed latest revision blocks a successor. The old seven ARM phases,
publication, `f89` failure and `4da` stopped run remain byte-preserved history.
Only a newly approved instance starts new counters. Copying historical active
toggle receipts into the new writable ledger is forbidden; their original
bytes live in the predecessor/history records instead.

Toggle what-if comparison validates **both full app configurations** before
normalizing only the previously reviewed representations: exact `Http`/`http`,
unique-type probe order, case-insensitive ARM IDs without collisions,
credential-free optional registry strings, known empty optional collections,
the specified KEDA/ingress defaults and read-only ephemeral storage. What-if's
omitted generated UAMI client/principal IDs and FQDN are checked against
independent real readbacks; raw evidence is not rewritten as a fabricated GET.
The canonical before side must also match the current validated observation.
The sole effective writable difference is the one admission flag. Unknown
properties, altered images, environments, identities, credentials, volumes,
ports, probes, limits or security contexts still fail. The region check retains
the existing exact `australiaeast` / `Australia East` mapping used by provider
qualification; no other region, arbitrary whitespace removal or generic
location-name folding is accepted.

There must be two separate parent-authored approvals:
`synthetic-admission-approval.json` and `synthetic-disable-approval.json`. Their
closed shape is `version: 2`, `action` (`synthetic-window-synthetic-admission` or
`synthetic-window-synthetic-disable`), `windowSha256`, `phaseSha256`,
`configSha256`, `sourceSha256`, `originSha256`, `receiptsSha256`, `baselineSha256`,
`reviewedWhatIfSha256`, `transitionSha256`, `windowInstanceId`,
`predecessorSha256`, `approvedAt`, and `expiresAt`.
Both approvals bind the same immutable window, fixtures, request limits and
pre-window receipt set. They retain the original full what-if in the window.
The reviewed disable what-if can correctly be **NoChange while currently
disabled**; it is not represented as a future true-state observation. Its
explicit transition contract authorizes only true→false or read-only
already-false completion. A fresh runtime what-if must still pass the full
semantic gate; no raw-hash equality is falsely claimed for that future state.
Legacy version-1 windows/approvals are accepted only as closed predecessor
evidence, never as current execution authority.

Only after both approvals and the parent source/native CodeQL gates may the
operator use `run-window synthetic-admission`. Direct `execute` of either
toggle is rejected. `execute-disable synthetic-disable` is the same fixed
disable path for an interrupted window, not a force command. It loads the
recorded window/approvals/intents and cannot invent new source authority.
Enable is refused unless disable authority remains valid for at least the
10-minute window plus a 3-minute recovery reserve. Every write rechecks its own
expiry and five-minute preflight freshness after body preparation and the last
awaited exact-app read, immediately before transport dispatch.

Each phase records its intent before its sole possible PUT. Unknown enable
submission is never retried: disable first waits, within a bounded read-only
poll, for that specific deployment to settle. An absent/in-flight deployment
after possible submission is unresolved—not proof that a currently false app
will remain false. Once settled, an exactly owned true app can be disabled only
under the independent, unexpired disable release. If it is already false,
readiness/identity/privacy verification can produce a **read-only**
`read-only-already-disabled` journal even after expiry; no expired grant
authorizes a PUT. Existing intent journals are never reset or resubmitted.

The original disabled-app receipt always remains false historically. During an
authorized window, only the matching source/window/enable-approval/intent can
explain a live true flag. Full immutable app configuration and identity still
match the original anchor. A later terminal disable forbids adopting a new true
flag. This transition-aware preflight avoids treating legitimate rollback as
unowned drift while preserving the original history.

### Readiness, bounded requests and failure outcomes

`Succeeded` alone is insufficient. Each mutating toggle has **one absolute
120-second rollout deadline starting at its recorded submission intent**. It
includes body preparation, PUT/submission, deployment settling, latest-ready
observation and privacy checks; deployment polling does not start a second
readiness budget. At most 40 combined deployment/readiness polls at 3-second
intervals require:

- `latestReadyRevisionName === latestRevisionName`;
- exactly one active latest revision, 100% traffic, one replica, `Provisioned`
  and `Healthy`, with the exact wanted template and admission flag;
- unchanged identity/image/runtime/privacy policy and empty diagnostic/export
  routes.

An old healthy revision, a not-yet-ready revision or a different template never
permits test POSTs. Backend readiness remains distinct from storage proof.
The immutable revision GET returns the unset revision suffix and KEDA defaults
as null even when the live app returns the reviewed values. Only those three
null optional fields are treated as absent in the revision-template comparison,
after the independent live-app check; changed numeric defaults still fail.
A response received after the absolute deadline cannot qualify, even if it
reports a healthy revision. The possible-submission journal is retained.

The deterministic driver preserves the reviewed ceilings: **11 receiver HTTP
requests**, at most **8 health GETs**, **2 enabled event POSTs**, **1 final
disabled POST**, and **3 owned-table read queries**. TLS verification is required,
redirects are not followed, response bodies are capped at 1 KiB, and each HTTP
request has an unchanged **1,000 ms total wall timeout**. The server limits remain
150/150/650 ms and 128/32/8 work bounds, 3,000 requests/minute and 100,000 events/day.
There are no event POST retries, including on ambiguous timeouts.
The private HTTP result includes `timingsMs` with numeric monotonic offsets
from the start of that request: `dnsCompleteMs`, `tcpConnectMs`,
`tlsVerifiedMs`, `requestFinishMs`, `firstByteMs`, `responseEndMs` and
`timeoutMs`. An unobserved event stays **null**, not zero or an inferred
duration. DNS/socket callbacks do not retain addresses or hostnames, and TLS
errors are mapped to static categories without messages, certificate details,
SNI or token data. Response headers are represented only by
`headerPolicy.noStore`, `zeroContentLength` and `connectionClose` booleans;
no raw response-header or response-body values are retained in the new result.
Historical results are not rewritten.

These offsets are observations of Node's event callbacks, not kernel packet
timestamps. `requestFinishMs` means the request was flushed to its local
transport, not that the service accepted it. `firstByteMs` is the first observed
decrypted response-data notification (or the parsed-response callback if
observed first), without reading or retaining that data. A response observed
after either the absolute deadline or the monotonic 1,000 ms maximum is
classified as a timeout even if the timeout callback was delayed; it cannot
become a passing 204. Finished records are not changed by later socket events.
Cancellation before dispatch still rejects without opening a connection.

The timings may separate connection setup from waiting for a response, but
cannot distinguish managed-identity token latency from upload/ingestion latency
inside the receiver. They do not justify changing the 650 ms storage limit,
prewarming credentials, retrying POSTs or rebuilding an image without additional
evidence and a separate parent release. A partial or timed-out first POST still
stops the standard window before any second enabled POST.
Every request/query first reserves its durable intent and count. Cancellation,
source and absolute admission deadlines are checked synchronously again after
the final awaited persistence/source operation and immediately before transport.
Query IO repeats that check **after** the independent workspace GET and source
read, before the query request itself. Refused dispatches retain their reserved
attempt; they are neither refunded nor retried. Returned results are also checked
before they can establish success. Terminal-disabled health/503 checks and
disable recovery ignore synthetic cancellation, but retain their own remaining
deadline, exact scope/source and request-count bounds.

The two content-free fixtures use `cliVersion: 0.0.0`, `host: none`, `os: linux`,
`outcome: completed`; they differ only in operation/duration labels
(`draft`/`under-1s` and `verify`/`1s-to-10s`). These are synthetic labels, not
observed user activity. Each accepted response must be empty/no-store 204. The
fixed query projects exactly the nine intended columns, within a finite
absolute time window, and takes at most three rows. It rejects extra/duplicate
rows, changed values/types and out-of-window timestamps; it never uploads using
operator credentials, exports data or crosses workspaces. Time/value matching
is not a unique event identifier and cannot prove causation in indistinguishable
concurrent traffic.

Three absolute boundaries derive from the **same enable intent**: synthetic
work stops at 7 minutes (or enable-authority expiry, if earlier); the enabled
window objective expires at 10 minutes; permitted late recovery ends at the
earlier of the disable approval's expiry and enable intent + 13 minutes.
None is restarted by a workspace read, deployment response, query, preflight or
new polling stage. All IO receives the remaining deadline; 15/30-second call
caps can only shorten it. Enable's pre-submission preparation is independently
bounded before there is an enable intent.

The driver refuses waits and final dispatches that consume the 3-minute disable
reserve. A disable that no longer has a full rollout allowance before the
objective is explicitly marked as recovery work. At window expiry, an owned
local timer records `synthetic-window-expiry.json` immediately (or at the first
observable opportunity if the process cannot run), instead of discovering it
only after cleanup finishes. Timer/incident state is tied to the original
intent/window hash and is not reset by later reads.

Failures and catchable cancellation trigger only the preauthorized disable
attempt. Crossing the work or window boundary does **not** waive disable scope
or stop an otherwise permitted safe disable within its fixed recovery bound.
A late disable readback is marked `lateRecovery`, the window reports
`stopped-disabled-late-recovery`, and the expiry/reserve incident remains;
it cannot become `qualified-and-disabled`. An expired write grant or exhausted
recovery bound cannot authorize a new PUT. A separately bounded already-false
read-only completion remains distinguishable from any write.

Successful in-window completion requires actual terminal false, latest
readiness, empty/no-store 204 health and one empty/no-store disabled 503.
An unavailable/expired disable grant, ownership drift, unresolved deployment,
provider delay or process/host loss can prevent that proof: the result is a
**hold**, not a manufactured safe state. Exceeding the 10-minute objective is a
failure even if recovery later succeeds. The one rollout deadline is never
renewed for late recovery, and an unknown PUT is never replayed. Azure does not provide an atomic
server-side expiry/rollback guarantee; retained intents and locks require
explicit operator reconciliation after process death.

Runtime counters reset, inherited operator privileges are not receiver identity
proof, and neither counters nor synthetic rows establish human/model activity,
retention enforcement over 180 days, production readiness or client activation.

## Privacy and readback

The workspace is managed using explicit ARM resource interfaces, not the
AzureRM resource that unnecessarily retrieved shared keys. That avoids the
specific retrieval, not a universal secret-free-state/configuration claim.
Public ingestion/query endpoints use Entra identity and scoped access; local
workspace auth and resource-only query access remain disabled.

The environment has no Log Analytics destination, diagnostic routes, Dapr,
Application Insights or OpenTelemetry configuration. The application admits
only the closed generated environment list, fixed probes, quotas and identities.
Runtime identity access is limited to the upload identity; the pull identity
is for image pull. Readbacks check retention, schema, stream transform, access,
image/config, single revision/replica bounds and no diagnostics/exports before
calling a phase qualified. Azure platform/security processing still exists.

### Default-network environment and diagnostic API

This collector uses the public **Consumption workload profile with no customer
VNet**, not the legacy Consumption-only environment type. Microsoft documents
customer-visible [managed infrastructure resources for customer-VNet
deployments](https://learn.microsoft.com/azure/container-apps/custom-virtual-networks#managed-resources).
The [official Azure CLI implementation](https://github.com/Azure/azure-cli-extensions/blob/main/src/containerapp/azext_containerapp/containerapp_env_decorator.py)
rejects a custom infrastructure-group name without an infrastructure subnet.
The [2025-07-01 ARM contract](https://learn.microsoft.com/azure/templates/microsoft.app/2025-07-01/managedenvironments)
describes this creation-time field. The previous template supplied it without a
subnet; the actual provider returned null. New templates omit the inapplicable
field; historical approved templates are preserved unchanged.

Readback accepts **null infrastructure group and null VNet configuration only**
for this fixed public/default-network model. Custom subnets, any other group,
zone redundancy, additional workload capacity, custom ingress/domain settings,
log destinations, Application Insights or OpenTelemetry fail. The expected
reserved managed-group name must remain absent. Fresh subscription inventory
and correlated activity showed only the intended new resources; that is not a
guarantee of absent platform infrastructure or charges.

Generated identity values, workspace customer ID, DCR immutable ID/endpoint, environment domain, resource
GUID when returned, and provider creation metadata are pinned to the original
readbacks. ARM inventory `createdTime` supplies the execution-window check
against each resource's original **Create**, not a later NoChange access update.
The Table API's own creation stamp covers the child table when it is absent
from generic ARM inventory; the subscription-level custom role's `createdOn`
and role GUID are similarly pinned to its original readback. Inventory membership derives from recorded resource
IDs across all completed phases; it is not a fixed five-resource assumption.
The environment's provider `systemData.createdAt` differed from ARM inventory
time in the observed response: it is retained exactly as an opaque immutable
stamp, **not corrected by adding a timezone offset**. Missing resource GUIDs are
recorded as absent, not fabricated.

[Diagnostic Settings List](https://learn.microsoft.com/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview)
uses **2021-05-01-preview**, confirmed by registered provider versions. The
transport permits that preview version only for GET on the exact intended
workspace/environment/app diagnostic-settings collection, without a body or
filter. Other preview APIs, targets and mutation methods remain forbidden.
Production qualification requires empty diagnostic and workspace-export lists;
an independent diagnostic read does not by itself qualify a deployment.

### Table and DCR response metadata

The [Table 2022-10-01 response schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/operationalinsights/resource-manager/Microsoft.OperationalInsights/OperationalInsights/stable/2022-10-01/Tables.json)
marks `isDefaultDisplay` and `isHidden` as read-only booleans. Readback permits
only these two optional additions to each canonical custom-column definition.
Column count, order, names and types remain exact; wrong flag types, additional
event columns and other column properties fail. The table must remain
`MissionSpecTelemetry_CL`, Analytics, 180-day Analytics/180-day total retention
with zero extra archive. The known standard `TenantId` column is Azure-added
workspace metadata, not another client event field. Other schema changes are
not silently stripped.

The [DCR 2024-03-11 response schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/monitor/resource-manager/Microsoft.Insights/Insights/stable/2024-03-11/dataCollection.json)
defines destination `workspaceId` as the read-only **Customer ID of the Log
Analytics workspace**. It must equal a separate GET of the exact owned,
access-qualified workspace; it is never defaulted from the DCR itself or simply
discarded. Destination name/resource ID, declared stream, projection,
output stream, Direct kind, actual immutable ID and HTTPS ingestion endpoint
remain mandatory. These documented metadata fields are not classified as
secrets merely because they are read-only; complete operator records still
contain scoped account/resource identifiers and stay in the private directory.

### Disabled-app provider representations and security defaults

The [2025-07-01 common schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/app/resource-manager/Microsoft.App/ContainerApps/stable/2025-07-01/CommonDefinitions.json)
marks `ephemeralStorage` read-only and identifies probes by `type`.
[Microsoft's storage limits](https://learn.microsoft.com/azure/container-apps/storage-mounts#ephemeral-storage)
provide **1 GiB at 0.25 vCPU or lower**. Readback permits only `"1Gi"` for the
reviewed **0.25 vCPU/0.5 GiB** profile; other values or types fail. This is
provider-allocated temporary storage, not a newly requested volume, durable
archive, or proof of a read-only production filesystem.

The [Container Apps schema](https://github.com/Azure/azure-rest-api-specs/blob/main/specification/app/resource-manager/Microsoft.App/ContainerApps/stable/2025-07-01/ContainerApps.json)
defines HTTP transport and optional registry username/secret-reference strings.
The observed GET returned `Http` rather than the template's `http`; only that
exact pair is equivalent, not arbitrary enum/string case folding. Registry
`username` and `passwordSecretRef` may be absent or empty strings in this
identity-only route. Null, nonempty credentials, extra registries or unknown
registry properties fail. These optional strings are not misrepresented as
globally read-only properties.

Probes compare by **unique exact type**, not array order. Their entire reviewed
definitions still match: missing/duplicate/extra probes or changed paths,
headers, periods, thresholds or commands fail. ARM resource-ID casing alone is
ignored for the two UAMI attachments, lifecycle settings and registry identity,
with case-folded duplicate detection. The actual attached client/principal IDs
must match independent reads of the exact owned UAMIs. GUID values and lifecycle
names are not case-folded: ingest remains `Main`, pull remains `None`.

Known service representations remain tightly bounded: empty revision suffix,
KEDA cooldown **300 seconds**, polling **30 seconds**, and unused HTTP
`exposedPort: 0`. Null/absent/empty optional container, volume and service-bind
lists mean no extra components. Nonempty init containers, additional containers,
mounts, volumes, delegated identities, service binds, Dapr, runtime
instrumentation, secrets, custom ingress or any container security-context
property are rejected. Unknown fields in these reviewed configuration sections
are rejected rather than globally stripped.

The actual image stays pinned to manifest `91c72962…`, config `46e59e2d…`,
nonroot `65532:65532` and the unchanged optimizing-compiler/debugger restrictions.
No command/argument override or extra environment variable is allowed. HTTPS
8080, the complete probe/scaler definitions, min=max=1, all request/work limits
and **`MSR_INGESTION_ENABLED=false`** remain mandatory for this phase.
No sandbox guarantee, CVE patch claim, HTTP qualification or admission enablement
follows from accepting these provider representations.

Preserved state remains private Blob/PE/DNS with shared-key/public access
disabled. The explicitly reviewed Lighthouse NSG/association and opaque
expiry-tag representation are retained as an immutable delta, not interpreted
as UTC or a first-party endorsement. **Future unexpected drift still fails.**
The separately reviewed single StorageDataScanner resource-instance exception
is preserved in an immutable delta binding the prior origin hash, exact
before/after snapshot, attributed Defender security-operator identity, built-in
role, activity correlation and explicit user decision. The original origin and
approved Lighthouse delta remain unchanged. Only that exact exception is
accepted; another exception, public networking, shared keys, IP/VNet rule or
`AzureServices` bypass fails. The historical transient broader bypass was not
adopted. Inherited Defender remains enabled, not reconfigured by this candidate.

## One-image publication and cost

The controller cannot push an image. `image-before-push disabled-app` requires
an empty registry and returns only a separate-publication-review receipt.
`image-readback disabled-app` inventories repositories/manifests and binds
the one intended digest to the already reviewed receiver config.
No image is deleted to make a budget or inventory check pass. Any extra or
historically retained digest/repository blocks a new publication decision.

The first-release estimate is rebuilt from actual components, not the former
operator-runner envelope. It reserves the uncertain environment-management
meter even for the collector, plus warm singleton compute, requests, ingestion
at the daily cap, all 180 retention days, ACR, preserved private state/PE/DNS,
possible managed LB/two public IPs, Defender Storage/CSPM and one initial image's
initial/daily/pull scan allowance. No free grants or free rescans are assumed.
A contingency is retained. The first image is not permission for future digests.

Current static inputs estimate **USD 301.66 for a 31-day month**, within the
explicitly reviewed **USD 350 estimate** (USD 48.34 margin). HTTP request volume is independent of the
100,000 accepted-events/day quota: sustaining the configured 3,000 requests/minute
for 31 days means **133,920,000 HTTP requests**, or **USD 53.568** at USD 0.40/million.
Disabled, invalid and rejected requests can still be billed without consuming
the event quota. Requests beyond the receiver rate limit can also be billed;
this sustained-rate assumption is **not a billing hard cap**.
All traffic settings and other reserves are unchanged. The new USD 350
decision supersedes the former USD 250 estimate; it does not authorize a cloud
write. The actual combined-project budget is now USD 350; the existing state
budget remains USD 50, and the created telemetry budget is USD 300. The combined
filter still includes telemetry, state and the reserved managed-group name.
The default-network readback correction does not remove the uncertain
environment-management, load-balancer or public-IP reserves, or assert that
platform infrastructure is free.
No lower forecast or weaker privacy, Defender or environment reserves are used.
Fresh rate, meter applicability, actual managed-resource and image-count
readback are required. Unexpected billed resources/features or another digest
require a new cost review.
The new route creates no operator VM/Job/environment/registry and has no
operator-environment orphan charge.

## CI/source boundary migration

The replacement targeted CI command is:

```sh
node --test infrastructure/arm/telemetry/tests/*.test.mjs
```

The parent owns workflow command/path edits. Remove old OpenTofu module
fmt/init/validate commands from the supported collector gate when updating CI;
there is no second live deployment definition to validate. Receiver service,
image/source/license and package-boundary tests remain separate and unchanged.
Never package the operator's private directory or historical source archive.
