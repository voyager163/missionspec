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
node infrastructure/arm/telemetry/controller.mjs reconcile core infrastructure/arm/telemetry/.operator-private/revision-20260923-core-reconcile
```

`prepare` is local. `check` rechecks account/permissions/providers/region/quota,
the exact preserved foundation, budgets/security policy, ownership and names,
then runs nonmutating ARM validate/what-if. An optional `validate-preview`
performs only template/what-if validation and writes `qualified=false`; it cannot
waive a failed foundation/account/cost gate.

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
that readback hold.

One versioned contract now covers these **two existing phases**, rather than
adding per-source trust exceptions:

1. `execution-origins-v1.json` contains immutable records of the original
   publication commit/source, exact phase/template, approval, intent journal,
   preflight, validation, what-if, first readbacks and original receipt (null
   when legacy qualification failed). Original files are preserved separately,
   byte-for-byte. Fixed Git blob reads verify each declared source hash and its
   ancestry in the repository; historical code is never executed. The parent
   independently confirms publication and scanner results.
2. `reconcile core` uses only scoped GETs. It verifies the original approval's
   validity **at intent time**, full phase/config/preflight bindings, validated
   ARM template hash and successful deployment identity. It rereads the exact
   existing resources, generated IDs, creation identity, budgets, foundation,
   security baseline, inventory, diagnostic routes and exports. No PUT,
   deployment resubmission or next-phase preparation is available in this path.
   The immutable `reconciliation-proposal.json` is **not qualified authority**.
3. The parent must separately author `reconciliation-review.json`, with exactly
   `version: 1`, `action: "accept-exact-arm-reconciliation"`, `proposalSha256`,
   `sourceSha256` and canonical UTC `reviewedAt`. Review must bind the exact
   current source/proposal and cannot predate the snapshot or lie in the future.
   There is no force flag, inferred approval, or automatic historical-source
   exception.
4. Only then may `qualify-reconciliation core` repeat the live read-only checks
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
read-only proposal/review, **not budget or core replay**. Old budget-only lineage
artifacts remain historical evidence, not an active parallel authority path.

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
| `synthetic-admission` | A separate approval may change only `MSR_INGESTION_ENABLED` from false to true for controlled synthetic qualification. It does not activate any CLI endpoint/client collection. |

Later phases cannot be prepared by pretending server-generated values are
known. Their fixed templates are generated only after the relevant private
receipt exists and has the same config/ownership. Unknown Modify/Delete,
unexpected resource IDs, unowned targets and nonempty new names fail closed.
Only explicitly listed workspace-access fields or the exact synthetic flag
change can be modified; image, command, quota or role changes are not hidden
inside that allowance.

Deployment names keep the full 32-hex-character run ID and explicit unique
two-letter phase codes (`pb`, `co`, `wa`, `da`, `ur`, `ra`, `di`, `sy` in table order).
Every allowed prefix/phase fits ARM's 64-character limit; characters and length
are checked locally. Nonmutating validate/what-if uses that exact execution
name, not a separate shorter preview name.

No container command/args override is emitted. The separately qualified receiver
config must remain nonroot `65532:65532` with
`--no-turbofan --no-maglev --disable-sigusr1`. Its three native V8 uncertainties
remain conditional disabled/synthetic-stage findings, not patched-CVE or blanket
native clearance claims. The quarantined operator image is never used.

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

Generated identity values, workspace customer ID, environment domain, resource
GUID when returned, and provider creation metadata are pinned to the original
readbacks. ARM inventory `createdTime` supplies the execution-window check.
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
