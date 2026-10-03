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

### Private Link replacement

The alternative to the held NSP rule is a new VNet-integrated external
Container Apps receiver and a Queue private endpoint, with ordinary queue DNS
and unchanged TLS/UAMI authentication. The existing environment cannot change
network type in place. This design does not make the public receiver, registry
or Monitor upload paths private. It does not qualify the undocumented NSP
`appliesTo` field.

The checkout-only `private-link.mjs` planner provides two fixed operator
operations:

```sh
node infrastructure/arm/telemetry/controller.mjs preview-private-link private-link-migration <private-revision>
node infrastructure/arm/telemetry/controller.mjs check-private-link-plan private-link-migration <private-revision>
```

These two planning commands are local-only, require no cloud credentials and make no Azure calls.
They use the existing private-directory/file rules. Preview writes one
create-exclusive `private-link-plan.json`; check revalidates that same plan
without overwriting it. Both recheck the existing unresolved NSP physical-target
head and historical source digests. A changed source, original attempt, pending
head, input or proposed resource invalidates the plan. No approval file, grant,
new execution receipt, resolved intent or enabled runtime is produced.

Supply unchanged `config.json`, plus these two closed inputs:

- `private-link-input.json`: `version: 2`, `addresses` and `overlapDays` (1-7)
  for the current version-3 plan with a patched temporary public-control app.
  Input version 1 still reproduces the historical version-2 plan without that
  app; it cannot qualify the current paired runtime workflow.
  `addresses` has explicit canonical RFC1918 IPv4 `vnet` (/24), `apps` (/26)
  and `endpoint` (/28) CIDRs plus `knownAddressSpaces` (at most 512).
  Subnets must be contained and disjoint; known overlaps and documented ACA
  reserved ranges are rejected. No CIDRs are chosen automatically. An empty
  known-address list is **not** verified absence of corporate/peered networks;
  complete current address review remains mandatory before deployment.
- `private-link-context.json`: complete `adoption`, `network`, `original`,
  `pendingHead`, `receiver` and `queueProfile` objects. These are the existing
  storage adoption, three-record Enforced-empty NSP history, the dispatched
  sole-rule attempt stopped with `NSP_RULE_DRIFT`, its exact pending head, the
  qualified historical disabled prepared-image receiver record, and the
  source/notices/fixture-bound queued image profile. No scalar `qualified` flag
  or replacement history is accepted. The current Defender-preserving adoption
  and historical versions retain their original schemas.

The plan keeps the stopped rule attempt and original journals unmodified.
Its proposed rule deletion binds the exact old rule ID; it explicitly requires
fresh raw preimage/generation review **without** treating its undocumented
selector as semantically accepted. The fixed order is:

| Stage group | Proposed scope and required boundary |
| --- | --- |
| Review migration | Separate address, cost, inherited-policy, permissions and retirement decisions; exact new names absent; old receiver disabled |
| Migration budgets | Separate project/telemetry budget phases set 425/375 USD, preserve the 50 USD state budget and exact notifications/periods, and include the new managed group |
| Retire NSP rule | Exact rule DELETE only after new approval; Network absence and empty/converged Storage rules; no deployment replay or inferred data-plane denial |
| Network and endpoint | One dedicated VNet with two subnets; apps subnet delegated to `Microsoft.App/environments`; one `queue` private endpoint, private DNS zone/link and zone group |
| Replacement environment | Consumption workload profile with external HTTPS ingress; explicit platform-managed group and budget-filter coverage review |
| Retire association | Set Storage public networking to `Disabled` while association remains Enforced and rule-free, then delete only the association and verify effective configuration removal |
| Retire empty NSP | Profile then perimeter, only after exact inventories show no remaining associations, rules or links |
| Queue role/assignment | Reuse the existing minimal metadata/add/process permissions and exact queue scope; no new identity or broad account grant |
| Image and receiver | Separately reviewed one-copy publication of the existing qualified queued digest; new app stays disabled and retains the old app's identity, limits, probes and privacy contract |
| Qualification | Actual private DNS/IP/TLS/UAMI path, intended success and unintended denial, bounded durable ACK/worker/Logs evidence, final disabled/503; no Blob test or production endpoint |
| Old-resource retirement | Separately reviewed old disabled app/environment deletion only after replacement qualification; never directly delete platform-managed resources or evidence |
| Steady budgets | Separate project/telemetry phases set 375/325 USD only after old-environment retirement; state budget stays 50 USD |
| Migration record | Append-only retirement/migration receipt with exact physical-target compare-and-swap; original NSP execution stays failed and cannot be replayed |

The proposed app name/FQDN is new. Registry/DCR/workspace, original identities,
storage account/queue, image history and raw evidence are preserved. No NAT,
Firewall, VPN/peering, Front Door, DNS Private Resolver, Blob endpoint, extra
subscription rule or production CLI activation is generated by the planner.
The ordinary queue URL is preserved; never use a `privatelink` hostname as the
SDK endpoint.

**Reviewed runtime names.** Container App names must be 2-32 lowercase
alphanumeric/hyphen characters, start with a letter, end with a letter/digit,
and contain no double hyphens. New forward preparation rejects an overlong
name before native validation; historical plans and records are not rewritten.
For a version-3 plan, an explicit `runtimeReview.nameProjection` can select only
the fixed `-private-ingest` to `-pl-ingest` and `-public-probe` to `-pub-probe`
mapping in the same owned resource group. There is no automatic shortening or
arbitrary name override, and the mapping cannot collide with the old receiver.

The closed version-1 review has action `use-reviewed-private-link-runtime-names`,
decision `use-two-shortened-runtime-names`, `configSha256`, `planSha256`,
`originSha256`, `controlEvidenceSha256`, `original` and `projected` objects
containing only `app`/`publicProbe` IDs, `sourceSha256`, the published
`publication` pair, and `approvedAt`/`expiresAt` bounded to one hour.
It binds the complete original thirteen-stage assigned-queue prefix and current
operator source. The image candidate and its publication remain unchanged;
name correction never requires another image copy.

Projected targets and runtime phases use version 2 with a stable `nameBinding`.
That binding includes the config/plan/origin/prefix and exact mapping, but not
review times or operator publication. A later operation may renew its review
for the same mapping and prefix without recreating the receiver or modifying
the original review. Within an operation, changing even review metadata is
rejected. Frozen false/delete recovery validates the original admitted mapping;
it cannot substitute a newly named target.

Current readbacks carry the complete name review and use projected app IDs,
while independently requiring both original planned runtime IDs absent.
Original history is still validated against the unchanged context. Current
policy, diagnostics, inventory, identity, generation, private/public probes,
physical fences and cleanup use the explicit projected targets. The native
bridge retains its existing context format and binds the new phase/body hashes.
Standalone current-proof callers pass `options.nameProjection` and receive
both the review and stable binding; an old unprojected proof does not qualify
a projected operation.

Only the five post-runtime control stages (`retire-old-receiver`,
`retire-old-environment`, the two steady-budget stages and `record-migration`)
accept top-level `inputs.nameProjection`, across the existing six control
verbs. The review must match the mapping and prefix admitted in the actual
runtime completion. Reconciliation/recovery keeps original intent/review A
and uses fresh same-mapping review B for current reads, binding B to its current
publication. Earlier control stages and NSG operations reject that field;
runtime commands use it only inside `runtimeReview`.

Costs retain the existing USD349.37 conservative base, plus USD10.34 modeled
Private Link/DNS/data allowances: USD359.71 steady state, USD367.01 with one
day overlap, or USD410.75 with seven days in the historical plan. The current
plan adds a USD1 reserve for one temporary public-control app: USD368.01 for
one day or USD411.75 for seven days, with steady state unchanged. Its planned
15-minute lifetime is enforced for qualification, not an automatic Azure
expiry; unresolved cleanup remains a recovery and cost obligation.
USD375 steady and USD425 migration are **planning allowances**, not hard caps
or approvals embedded in a generated plan. The base is
not freshly repriced, and residual unverified NSP charges, taxes and new
policy-mandated infrastructure are excluded. The new managed resource group
must be explicitly included in budget coverage; neither filter nor amount is
silently changed. Steady-state cost requires confirmed old-resource retirement.

**Local preparation is not live execution.** The control-plane driver exposes
`prepare-private-link`, `check-private-link`, `execute-private-link`,
`reconcile-private-link`, `recover-private-link` and `retire-private-link`,
with one fixed control stage and a private revision directory. The router reads
`private-link-control-context.json` (`plan` and original `origin`),
`private-link-control-evidence.json`, and closed
`private-link-control-inputs.json`. It never accepts a replacement transport or
test options from JSON. Checks retain exact preimages, policy, permissions,
providers, cost evidence and native previews before an independently bound
phase approval permits the one recorded effect.

Permission preflight queries deny assignments with the documented
[`$filter=atScope()`](https://learn.microsoft.com/en-us/rest/api/authorization/deny-assignments/list-for-scope?view=rest-authorization-2022-04-01)
filter, retaining all denies at or above each requested scope. Every returned
deny still blocks the operation. Unrelated descendant protections, such as
ACA's system-protected managed-group/load-balancer/public-IP denies, are not
mistaken for subscription-wide denials and are never removed or bypassed.
The read allowlist requires that exact filter; unfiltered or principal-filtered
deny queries cannot substitute for the scope check.

Native ARM Create preview may omit the queue role's two empty permission
exclusion arrays, `notActions` and `notDataActions`. Only that exact fixed role
and those absent empty fields have an equivalent preview representation.
Null/nonempty exclusions, missing or changed grants, additional permission
blocks and broader assignable scopes remain contradictions. The submitted
template and subsequent role readback checks are unchanged.
The exact queue-assignment Create preview may similarly omit its top-level
scope when the resource ID already contains that identical queue scope, and
omit `principalType: ServicePrincipal` only when the unchanged principal ID
matches an independently read user-assigned managed identity. Conflicting or
null fields, missing identity evidence, different roles/principals and added
conditions remain blocking. The request and actual assignment readback still
require the original principal type and exact queue scope.

Control dispatch journals distinguish known non-submission, possible
submission, and an invocation that was reached. A durable version-3
`dispatchAttempted: null` marker and rollout deadline are saved before the
HTTP call; a crash cannot turn a possibly submitted request into a safe retry.
The first request uses that fresh rollout deadline, not time left over from
the final preflight. Legacy false markers remain ambiguous. Resource absence
alone cannot downgrade either kind of unknown outcome. A reviewed
known-not-submitted resolution records no phase success and does not itself
authorize another attempt.

An adopted history may reuse fully verified history and proof bindings only
within one check, execution, read-only recovery or runtime-prerequisite
verification, using private immutable copies and a separate unforgeable
in-memory token for each operation. This includes ordinary phases following
an earlier continuation. Each candidate is fully verified before
current reads or reservation; caller and adapter inputs are compared again
after awaited work. Tokens are discarded when their operation settles and
cannot be supplied through JSON or reused by another operation.
Synchronous source/history verification finishes before bounded read processes
start. Public preflight timing includes candidate construction, adapter setup
and final proof persistence; it does not begin a new budget at collection.
Current source/head, NSG/privacy, policy, permissions, cost, expiry and
cancellation checks still run. The 120-second preflight/final-check deadlines
and 300-second proof-age limit are unchanged; local validation time does not
renew any budget.

Read-only reconciliation and recovery also include adapter setup,
`originalDirectory` verification and result persistence in their original
120-second budget. They recheck the original journal, physical head, source,
current reviews, input bindings and cancellation after awaited work. A
no-submission resolution still preserves the failed journal and physical fence;
it records no successful phase and grants no replay authority.
Runtime prerequisites require the actual assigned-queue prefix. Synthetic
13-stage coverage cannot establish that a future live prefix and its fresh
reads meet the runtime deadline; that measurement remains a separate gate
before runtime effects.
Within a single operation, a fully frozen private evidence copy may also reuse
its canonical assigned-prefix digest. This avoids repeatedly hashing the same
large prefix for name bindings, not verifying it less often. Shallow-frozen or
mutable inputs do not receive this reuse; entries disappear when the operation
settles, and current source/review/expiry checks still run.
The runtime policy target for the exact owned telemetry table uses its fixed
`Microsoft.OperationalInsights/workspaces/tables` type when the table GET
omits that field. Its resource ID must still match; explicit null, empty or
contradictory types are rejected. Raw readback bytes are preserved and the
table's schema, retention and policy checks remain mandatory.
If concurrent runtime policy or state collection fails, the reader settles the
other admitted reads and their private evidence writes before returning the
original error. Failure does not reset the read limiter, extend any admission
deadline or produce a current proof; no background capture may race later
cleanup or a separately reviewed operation.

Runtime current-state policy collection explicitly uses version 3 evidence.
It groups observations only when all facts except the target resource hash
are identical, retaining ordered target membership and the uncompressed
observation count. Duplicate operation occurrences remain distinct. Every
target, false rule, nonmutating result, unknown, blocker and raw policy read
is retained and independently recomputed. The 4,096-group, 32-target,
512-read/item, 8 MiB snapshot, depth and wave bounds are unchanged. Ordinary
control checks and historical version-1/2 evidence keep their existing format
and interpretation; neither API silently promotes an older record.

Version 3 also supports the pinned `2023-09-01` workspace capacity-reservation
alias and numeric `greater` comparison. The exact `PerGB2018` omission against
`greater: 100` was checked using Azure's
[non-deploying Policy Restrictions API](https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-restrictions/check-at-resource-group-scope?view=rest-policyinsights-2024-10-01):
the retained pay-as-you-go content and a hypothetical 100 GB commitment had no
deny, while a hypothetical 200 GB commitment returned the matching deny and
`200 Greater 100` expression result. No resource, SKU, assignment or exemption
was changed. The local subset does not infer a zero value or general absent/null
semantics: null/string/invalid levels, other APIs/aliases/SKUs and unqualified
missing-value thresholds remain unknown and blocking. Historical evaluators
retain their conservative unsupported result for this predicate.

Successful control append persists both the revision record and its complete
aggregate evidence before the canonical resolution and successful head.
Source, pending-head, review, input and cancellation guards run again after
those awaited writes. An aggregate storage failure cannot advance the
successful head; a submitted request still requires read-only recovery, never
replay. Immutable validation reuse also binds canonical key order, not just
equivalent property values.

Provider metadata stays byte-preserved. An explicit `+00:00` UTC suffix, as
returned by ACR, is equivalent to `Z` for 100ns identity comparisons; other
offsets or an absent zone are not inferred to be UTC. The separately scoped
timezone-less ACA creation format remains an opaque recorded identity rather
than a reconstructed timestamp.

An HTTP 404 with ARM code `NotFound` is absence only for GETs of the fixed owned
NSP perimeter/profile/association/rule at the pinned Network API, or the exact
owned Storage effective-configuration child at its pinned Storage API.
The URL subscription must match the selected subscription. Collections,
foreign targets, other statuses/codes and mutating requests are not normalized.
A stale effective-configuration listing still blocks retirement qualification
until the complete listing and individual reads converge.

External governance changes are not folded into the original plan or treated
as effects of a stopped deployment. `observe-private-link-nsg-adoption` and
`adopt-private-link-nsg` use the fixed selector `private-link-nsg-adoption`
and a new private revision directory. Their closed
`private-link-nsg-adoption-inputs.json` supplies the complete original attempt,
its canonical `originalDirectory`, current publication/policy/cost/migration
reviews, and either provenance for observation or the exact proposal and
review for adoption. These operations perform reads only; they cannot create,
edit, attach, detach or delete an NSG.

A verified adoption is a separate record on a version-2 control-evidence
wrapper. The original six records and failed environment journal stay intact.
Adoption does not qualify that environment attempt or permit another one.
Reconciliation and recovery under the adopted wrapper require the old
`originalDirectory` while writing their new records elsewhere. A distinct
no-submission resolution and a fresh continuation review remain necessary.
The exact NSG identities, rules, approved attachment mode, writer provenance
and complete regional flow-log/diagnostic observations must match; unknown
resources, changed attachments and exports remain blocking.

NSG contract version 2 retains the original endpoint-attached/Apps-unattached
interpretation. Version 3 requires the explicit
`attachmentMode: "both-corresponding-subnets"` in provenance, proposal,
review, adoption and current NSG observations. It verifies both exact NSGs
attached only to their corresponding subnets; there is no automatic promotion
from the older review. Its separately retained Apps-attachment activity must
prove the later settled write by the pinned governance actor, while the
original overlapping write captures remain unchanged. The version-3 review
action is `preserve-both-exact-private-link-nsg-attachments-readonly`.

Both variants require no custom security rules, the six reviewed default
rules, no diagnostics and no target-bound regional flow logs. Apps-subnet
compatibility checks cover the exact Consumption environment, address,
delegation, no route/NAT changes and default-only NSG configuration. They
explicitly do **not** qualify platform traffic: environment provisioning,
image pull, DNS and paired runtime delivery still need their own evidence.
Neither variant authorizes changing, attaching or deleting an NSG.

Explicit continuation is limited to a conclusively never-invoked version-3
attempt. Use a **new private revision directory**, preserving the original
artifacts, context and successful chain. Forward control inputs may include
`continuation` with exactly `version: 1`,
`kind: "reviewed-private-link-no-submission-continuation"`, a new UUIDv4
`attemptId`, the complete no-submission `resolution`, and its exact `review`.
The review binds the resolution, prior intent and pending head, unchanged
fixed phase/request, current source, new attempt ID and expiry. Both fresh
preflight and the final check must establish deployment absence and repeat
the normal permission, policy, price, source and target-state checks.
Admission atomically checks the prior physical head and creates a distinct
immutable attempt; it does not overwrite the old stage archive or grant
automatic retries. Legacy false, durable unknown and attempted markers cannot
use this path. Reconciliation/recovery instead consume any continuation from
their original recorded phase, not an additional outer input.

Runtime has separate `prepare-private-link-image` / `publish-private-link-image`,
`prepare-private-link-receiver` / `create-private-link-receiver`, and
`prepare-private-link-window` / `qualify-private-link-window` commands, with
the fixed selector `private-link-runtime`. Their closed
`private-link-runtime-inputs.json` references the exact candidate, local uploader
or fixed diagnostic transport, current control evidence and action-specific
approval. Publication preserves both original manifests and separately records
the returned third-image candidate as `private-link-published-candidate.json`.
Preparation never implies publication, deployment or enabled ingestion.

The six forward runtime commands accept an optional `runtimeReview` containing
`policyRevision`, `costReview`, and `costEvidence`, plus the optional typed
`imageProfileRevision` described below. This supports a
freshly reviewed policy source or renewed cost evidence without rewriting the
original plan, candidate, successful control records, or failed attempts.
`policyRevision` is null only when retaining the original policy source;
otherwise it is the explicit identical-plan/new-source review. The complete
three-record object is included in the runtime approval binding. Current proof
must echo it exactly and all forward-dispatch source, price and review-expiry
checks still apply. Recovery and reconciliation commands reject `runtimeReview`
and retain their frozen-source, backend-independent scope. Arbitrary `options`,
IO adapters and transport replacements are never accepted from JSON.

When the frozen plan's scan expires, a separately reviewed
`review-same-image-private-link-scan-refresh` revision may bind a new scan
profile for the exact same manifest, config, source and notice bytes. Only
the scan, scan counts, scanner database metadata and a closed
`same-image-scan-refresh` chain entry may change. Scanner identity, runtime
measurements, SDK fixtures, native-overlay evidence and caveats stay exact.
The new record binds the original profile and previous refresh hashes;
neither historical profile nor the plan is overwritten.

The revision is included in the full runtime approval binding, expires within
one hour and no later than the new database deadline, and must match the
current published policy source. Its scan must still report zero Critical
and High findings with no suppression, and its actual report timestamp must
fall within the recorded scan window. Wrong image/source, changed qualifiers,
unknown fields and expired reviews fail before effects. Frozen false-only
disable and public cleanup retain their original admission-time checks, so
safe cleanup is not vetoed by a subsequently expired scan.

Versioned native what-if contexts distinguish the new fixed control phases
and UUID-bound replacement-app phases from historical collector requests.
The same authenticated request bounds, no-redirect/no-retry transport and
full static payload review apply. Direct budget/PATCH/DELETE previews bind
their precise request and preimage rather than pretending they are ARM what-if.
Network CREATE previews may repeat the two explicitly declared subnet
properties inside the parent VNet and return leaf names on the separately
identified subnet resources. Both nested definitions and both separate
CREATE entries must exactly match the fixed plan; no extra subnet or property
is allowed, and raw what-if bytes remain retained unchanged.
Private DNS link and zone-group previews also use exact child leaf names.
Only the empty private DNS zone property bag may be omitted; nonempty,
null or missing endpoint/link/zone-group properties are not waived. Preserved
Defender Event Grid resources may appear only as `Ignore`, and only after
their existing full current-inventory validator proves the exact IDs and
configuration. An unverified resource or any mutation of those resources
still blocks the phase.
The provider-created endpoint NIC enters this same preserved inventory only
after the full endpoint/NIC/DNS validator proves its ownership, private IP,
queue-only connection and privacy settings. Later control and runtime
previews may ignore that exact NIC, never create, modify or delete it.
The current environment execution phase is version 2: it projects the
immutable plan's no-export intent to
`appLogsConfiguration: { destination: null, logAnalyticsConfiguration: null }`,
the wire representation used by the official Azure CLI. Its closed
`wireProjection` binds the original planned request hash; original plans and
version-1 phase records are not rewritten. Azure's native preview may omit
that exact null bag, but actual GET must report an explicit null destination
and absent-or-null analytics configuration. Missing actual configuration,
logging destinations, customer IDs, keys and diagnostics remain blocking.

Provider-added endpoint metadata is separately constrained: `purpose` may be
`PrivateEndpoints` only on the endpoint subnet once that endpoint exists;
IPv6 stays false. The NIC must point to the owned endpoint, with the exact
reviewed feature defaults, no custom/applied DNS servers, no taps and no
hosted workloads. Returned DNS configuration IDs/types and provisioning
states are verified rather than discarded. Unknown fields, foreign owners
or routes, and enabled unreviewed features still block reconciliation.
The provisioned ACA environment may expose explicit null Application Insights,
OpenTelemetry and custom ingress configurations and `enableFips: false` on
its Consumption profile. Non-null or enabled variants are not inferred safe.
Its `legionservicelink` is admitted only on the exact Apps subnet, with the
returned subnet-form link, exact provider flags, and an independently
succeeded environment bound to that subnet. The managed ingress IP's
`FirstPartyUsage: /Unprivileged` marker is permitted only on the fixed ACA
public IP with its exact environment tag, ingress address and frontend
reference. These checks preserve raw readbacks and do not authorize unrelated
subnet associations, platform features or public IPs.
Budget changes are separately enumerated: migration project/telemetry/state
425/375/50 USD, then steady 375/325/50 after old-environment retirement, with
exact notification/period preservation and the new managed group in coverage.
Budget alerts do not impose a hard spending cap.

Private-path qualification uses the replacement receiver and a temporary,
always-disabled `-public-probe` app in the existing non-VNet environment as
separate probes with the **same authorized ingest identity and patched image**.
The old receiver stays disabled and unchanged; its expired historical scan is
not refreshed by rewriting the original candidate. A separate current scan
found two High-severity Debian OpenSSL findings in that old image, so it is not
used to execute the diagnostic. Normal DNS and verified TLS must resolve/reach the private
endpoint successfully from the replacement and deny the original public path.
No DNS override, IP-address URL, disabled certificate validation, or unrelated
principal's authentication failure is accepted as network-denial evidence.
The two bounded event requests still belong to the product receiver, not the
metadata probes. Unqualified or unknown delivery produces a failed operator
result with retained evidence, never a success-shaped CLI response.
The temporary app has no enable action or synthetic event requests. Its exact
creation and cleanup are reviewed and journaled separately; confirmed absence
is required before qualification and retirement of the old environment.
The window approval object has exactly `enable`, `disable`, `publicCreate`
and `publicDelete` reviews. Preparation binds both the fixed
`create-public-probe` phase and the exact bodyless app DELETE; the immutable
window intent retains both before creation.

Interrupted enabled windows have separate
`prepare-private-link-disable-recovery` and `recover-private-link-disable`
routes, using the fixed original intent and preplanned false request rather
than a caller-supplied ARM body. An expired approval requires a fresh,
exactly bound false-only recovery review. Recovery cannot enable ingestion or
rewrite the original failed result. `reconcile-private-link-receiver` performs
read-only reconciliation of an unknown create outcome; it cannot submit that
creation again.

Temporary-app recovery is separate from disabling the replacement receiver:
`prepare-private-link-public-cleanup` takes only `recoveryId`,
`recover-private-link-public-cleanup` takes `recoveryId` and an exact
`private-link-recover-public-cleanup` approval, and
`reconcile-private-link-public-probe` takes only `reconciliationId`.
These use `private-link-runtime` and the original private revision directory.
The driver loads the fixed retained intent, physical target and creation
generation; none accepts an arbitrary resource ID, request body or transport.
Cleanup does not require healthy queue delivery and cannot enable either app.
An unknown create/delete outcome stays recorded as unknown unless separately
reconciled; a new recovery receipt never rewrites the failed attempt.
Before DELETE, both normal cleanup and recovery compare the current app's
creation identity against the immutable creation receipt. A deleted and
recreated app at the same ID is not the original cleanup target. If the initial
create produced no receipt, the original delete authority cannot be used:
read-only cleanup preparation must retain the exact observed generation and
a new cleanup approval must bind its hash. That review authorizes only the
fixed observed public-probe generation; it neither proves original creation
nor grants generic resource adoption.

Large control, runtime and retirement artifacts use lossless, versioned storage
envelopes. Fixed runtime record kinds can reference their exact thirteen-stage
prefix through `assign-queue-role` and version-2 receiver candidate under
distinct immutable content-addressed filenames in the private operator root.
Continued, pre-runtime recovery records in a control chain can also be stored
separately. Their duplicated `phase` and `preflight` members are reconstructed
only from byte-identical members of the retained `recovery.original`, preserving
property order and the complete original canonical digest. Unequal members are
rejected, not repaired or replaced.

Version-2 evidence blobs may contain only those narrowly typed recovery-record
references; no general recursive graph or caller-selected path is accepted.
References cannot cross types or move to unapproved fields. Each load checks
held-file ownership, mode, size and content hashes and fully hydrates the logical
evidence before ordinary source, history, authority and drift validation.
A content hash or storage projection never substitutes for semantic validation.

Every file remains bounded by 64 MiB, as does the total distinct referenced
content for one artifact. The unchanged 64-reference and eight-blob limits
include the permitted nested evidence references. Cycles, other nesting,
unknown positions, corrupt or aliased blobs and missing evidence fail closed.
Only a single load may share identical frozen evidence objects in memory;
there is no cross-operation validation cache. Historical plain JSON files
remain readable and are never rewritten. Streaming canonical hashing
preserves the existing JSON-plus-newline digests while avoiding Node's
single-string limit for large restored records.

The existing NSP failure remains an original failure. Supersession and
retirement records are appended separately, bound to its physical target and
pending intent. No generic NSP rule-shape waiver or repeated original PUT is
introduced. Live resource and runtime evidence, not the planner's requirement
strings, determines whether each phase is qualified.

References: [Storage private endpoints](https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints),
[ACA network immutability](https://learn.microsoft.com/en-us/azure/container-apps/networking),
[ACA VNet requirements](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks),
[Storage NSP precedence](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security-perimeter).

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
endpoint was intended to accommodate the existing no-VNet Container App using
Entra; the original topology does not introduce a VM, VNet, private endpoint, firewall/security exception,
SAS, key, connection string or anonymous queue access. Inherited Defender
and subscription policy stay unchanged. CORS, diagnostics and exports stay
empty; the worker cannot create/delete a queue or manage service properties.

**Current deployment hold.** The storage-only deployment created its account,
service and queue, but the inherited storage public-network policy rewrote the
requested `Enabled` value to `Disabled`. All eight explicit post-create fields
matched; the full-resource check still correctly refused qualification. A
successful ARM deployment or partial checklist is not a qualified queue receipt.
The failed intent remains immutable, and neither creation replay nor subsequent
queue permissions/image deployment is authorized by that result.

Later read-only preparation observed another inherited change: Defender for
Storage added one `StorageDataScanner` resource-instance rule and a generated
Event Grid system topic with its managed Blob event subscription. The original
empty-rule postcondition therefore no longer matches. This is not a harmless
response default or permission to remove the protection. The exact integration
requires a separately reviewed preservation record, provenance and fresh
settings/destination/diagnostic checks; old empty-ACL evidence remains unchanged.
Until that contract is qualified, neither the new rule nor the topic is accepted
as arbitrary known inventory.

Preserving the Defender configuration is not proof of uninterrupted scanning
under enforced NSP. Firewall resource-instance rules do not establish NSP
access, and empty-rule or deny phases may affect the managed scanner path.
Its BlobCreated/BlobRenamed subscription does not imply that Queue messages are
scanned or exported. The user selected queue-only NSP qualification with explicit
acceptance of the disclosed scanner uncertainty and possible interruption.
Functional Blob scanning and Sensitive Data Discovery remain unqualified;
that decision does not authorize Blob uploads, a canary, extra Blob permissions
or a new executor. Its acknowledgment must be source-, topology- and
current-state-bound, not an implicit compatibility waiver. No scanner
disablement, general bypass or extra perimeter rule is implicit.

The existing receiver environment has no VNet integration. Enforced Network
Security Perimeter (NSP) has been selected and its local implementation is
available; deployment and runtime qualification remain separate gates. No
Private Link migration is selected. Do not add an exemption, exclusion tag or
policy change to make the original topology pass. An account
flag of `Disabled` alone must not be described as denying all traffic: active
perimeter associations and rules can still allow access. Receiver admission
shutdown, queue network revocation and their propagation evidence are distinct.

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
650 ms enqueue, 1 KiB encoded message and 1 KiB decoded JSON bounds,
3,600-second per-message TTL, approximate-count
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

The new queued contract explicitly pins `messageEncoding: "base64-json-v1"`,
`maxEncodedMessageBytes: 1024`, `canonicalBase64: true`, and
`plaintextFallback: false`; `maxPayloadBytes: 1024` bounds decoded JSON.
The service constant `QUEUE_MESSAGE_CODEC` maps to this one profile field;
`messageCodec` is not a second accepted profile alias.
The queue wire contains canonical Base64 of the unchanged compact UTF-8 JSON:
the original eight event fields plus the original server `TimeGenerated`.
Both byte bounds apply independently. Base64 is transport encoding, **not
encryption**, and adds no analytics field or environment selector. Consumers
reject plaintext/noncanonical encodings rather than migrate or fall back.
There is no deployed plaintext queue data to preserve or convert.

This prevents structural JSON quotes from multiplying XML entities in a
32-message response. The batch remains 32 and parser entity limits remain
unchanged; the fix does not waive a parser failure or a fixable dependency
advisory. A previously rejected plaintext local image cannot qualify by
editing its reported runtime marker. A new source-bound image and measured
codec qualification are required. The new queued profile also rejects the
unfixed `CVE-2026-41650` finding explicitly; patched dependency/license/source
provenance and a fresh unsuppressed scan remain required.

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

**Requested fields that ARM does not predict.** A full CREATE what-if may
omit exactly these requested fields:

| Exact new resource type | Permitted omitted path |
| --- | --- |
| `Microsoft.Storage/storageAccounts` | `properties.networkAcls.ipRules` |
| `Microsoft.Storage/storageAccounts` | `properties.networkAcls.virtualNetworkRules` |
| `Microsoft.Storage/storageAccounts` | `properties.networkAcls.resourceAccessRules` |
| `Microsoft.Storage/storageAccounts` | `properties.encryption.services` |
| `Microsoft.Storage/storageAccounts/queueServices` | `properties` (requested empty CORS configuration) |
| `Microsoft.Storage/storageAccounts/queueServices/queues` | `properties` (requested empty metadata) |

This is a fixed **CREATE-preview omission contract**, not normalization of
resource state. The raw `after` is never filled with the requested values.
`queue-storage-preview-uncertainty.json` returns
`requestedButNotPredicted`, with `omittedFieldsVerified: false` and
`actualPostCreateReadbackVerified: false`. An omitted nonempty
`encryption.services` prediction does **not** establish queue encryption.
If services are returned, they must include the requested queue
`enabled: true` / `keyType: Account` without contradiction. A returned
nonempty ACL, subnet/IP/resource-access rule, CORS rule or metadata, any
unlisted security omission or changed field, errors/pagination, unknown
resource or existing-resource modification still fails closed. Entire
account ACL/encryption objects and encryption `keySource` are not omittable.

`queue-storage.computedReadbacksRequired` is generated from the fixed topology,
not a user-controlled waiver. Its eight actual-GET requirements are the three
empty ACL arrays, encryption `keySource: Microsoft.Storage`, queue encryption
`enabled: true` and `keyType: Account`, empty `cors.corsRules` and empty
metadata. The phase hash binds this list; preflight additionally binds the
full preview-uncertainty hash, requirement hash and validated-template hash
into the existing parent approval's `baselineSha256`. The raw validation
response/hash is preserved, but its transient correlation ID is not treated
as a stable approval input. Full ARM validation and exact fixed-template
matching remain mandatory before a preview can be accepted.

Actual GET verification is **not relaxed**. All requested security/resource
settings remain strict, including those absent from the prediction. A
qualified queue receipt must contain the actual post-create observations;
missing/contradictory actual values stop qualification and preserve the
resource for review. Subsequent role/receiver phases require that qualified
record, so omission acceptance cannot authorize enqueue or bypass the
postcondition. The earlier failed preview/read-only evidence stays immutable;
new policy requires a fresh reviewed-source context rather than resetting it.

Actual readback handling permits only two optional provider defaults:
`networkAcls.ipv6Rules: []` and queue-service
`logging: { delete: false, read: false, write: false, version: "1.0",
retentionPolicy: { enabled: false } }`. Each must match that exact shape, without
extra fields; inputs are not stripped or modified. These allowances do not
apply to CREATE previews, remove any of the eight postconditions, or change
authentication, TLS, RBAC or network requirements. A network mismatch still
reports `QUEUE_NETWORK_POLICY_MISMATCH`; unknown readback fields report
`QUEUE_READBACK_SHAPE_UNREVIEWED`, without copying their names or values into
the journal. A later corrected readback cannot replay a failed intent or
rewrite it as a successful execution.

`queue-review.json` is a closed `accept-exact-durable-queue-topology` review
binding config, topology and current policy source, canonical approval/expiry
(at most one hour), and all-false `QUEUE_AUTHORITY`. `check-queue` repeats the
original history, foundation/security, exact resources, account, provider and
role reads and full validate/what-if. `execute-queue` separately requires
`queue-policy-publication.json` and the exact phase approval. As with image
changes, independent reads are limited to four in flight, each request to
15 seconds and preflight to 120 seconds. A durable intent permits one PUT and
a bounded 120-second rollout; uncertainty requires reconciliation, never retry.

**Effective-policy binding.** The preflight hardening
adds an explicit effective-policy binding for new queue execution, rather than
relying only on assignment hashes and what-if. Its proof binds
`effectivePolicyVersion`, `effectivePolicySha256` and the retained
`effectivePolicy` analysis/read evidence into the approval baseline. An
incomplete or mismatched binding cannot authorize dispatch. The previous
baseline algorithm remains available only to verify historical records;
historical verification does not admit a new operation without the new proof.

Current analysis evidence is version 2. An explicit major/minor wildcard
(`1.*.*` or `1.2.*`, including its preview annotation) auto-ingests the newest
numeric matching version from a complete, retained catalog, as documented in
[Azure Policy assignment versioning](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure#policy-definition-id-and-version)
and [initiative definition references](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/initiative-definition-structure).
This prevents a new initiative parameter from being incorrectly applied to
obsolete child schemas. Unknown parameters in the selected version still
fail; no parameter is dropped. Numeric preview/GA ties remain conservatively
evaluated together. Exact effective/version pins are unchanged, and missing
selectors retain the conservative all-version behavior. Historical version-1
analysis is recomputed with its original all-matching algorithm, not upgraded
or rewritten. Both algorithms retain complete catalog bytes in the evidence
hash, so catalog/content changes still require fresh review.

This is a conservative evaluator for the exact phase, not a general Azure
Policy interpreter. Effective scopes, definition versions and parameter
bindings must be established; unsupported potentially applicable mutations,
incomplete listings and unverified exemptions stop execution. An unknown
tag/exemption condition is not permission to ignore a policy. Exact policy
evidence must also be refreshed before dispatch. Evaluating a supported
`SecuredByPerimeter` condition does not establish NSP association, reachability,
propagation or data authorization. Each further policy-source change still
requires its own published-source and required-check qualification.

Array parameter `allowedValues` applies to each selected element; assignment
validation is case-sensitive even when subsequent policy string comparisons
are not. Existing preview-version annotations remain recorded while every
matching numeric version is examined, including promotion to GA; the evaluator
never chooses an optimistic latest version. Complete rule documents already
returned by a bounded version catalog are evaluated directly. Summary-only
catalog entries still require exact version GETs; retained GETs must agree with
the catalog's rule-bearing properties. Known logical/condition key casing
returned by ARM is interpreted without rewriting retained bytes. Conflicting
case variants and unknown operators remain unresolved, not a reason to skip
policy enforcement.

Each successful queue phase writes a new immutable `<phase>-record.json`.
For the next private revision, retain those full records under their exact
phase names in `queue-records.json`; do not replace old receipts. The new
account becomes known inventory **only** through validated execution,
approval, source, what-if, deployment identity and readback records. Any other
account/queue/resource remains an error. Role definitions and assignments,
diagnostics, account encryption/network settings and queue inventory are read
again at dispatch, including after request-body preparation.

#### Read-only storage adoption and enforced NSP

The created-but-unqualified storage follows a distinct, closed version-2
`reviewed-queue-storage-adoption` record. It has no legacy successful `phase` or
`receipt`; its observation explicitly remains `qualified: false` and
`operationallyQualified: false`. The old phase, source, approvals, stopped
journals and raw artifact hashes remain under its immutable origin.

`observe-queue-adoption queue-storage <private-revision>` performs only bounded
GETs and writes an immutable proposal. A separately supplied exact review and
current source publication are required by `adopt-queue-storage queue-storage`
to write the local adoption record. Adoption establishes reviewed inventory,
not queue grants, image publication, network admission or runtime success.
Its evidence pins the original validated/deployed template hash, deployment and
successful Create operations, account creation time and fresh resource settings.
ARM instants retain 100ns precision. Missing original wire bytes and service/queue
generation markers are not invented; there is no full-wire or uninterrupted
child-generation attestation. Assignment inventories do not prove role-definition
or transitive-group access. Only originally observed system creation fields are
pinned; schema-validated modification metadata may change without pretending a
new generation was created.

An inherited Defender delta uses adoption **version 3**, with
proposal/observation/review version 2. Supply private
`queue-defender-evidence.json` only for the exact separately reviewed scanner
integration. Omitting it retains the original version-2 empty-rule behavior,
not a silent scanner exception. The new observation records a versioned current
postcondition delta and the hash of the eight unchanged historical requirements.
Its `review.defender` binds the full evidence, exact destination/AAD identifiers,
three independently identified actors, prior scanner adoption and explicit
preservation instruction. A name, standalone hash or truthy qualification flag
is not an alternate admission route.

The evidence retains complete bounded resource/time-window Activity Log pages,
canonical parsed-response hashes and independently checked attribution
projections; it is not raw-wire attestation. Only exact historical account,
service, queue, Defender-setting, managed-subscription and legacy
`advancedThreatProtectionSettings/current` event scopes are retained. Legacy
events confer no current-state or actor trust.

The current collector adds ten fixed GETs to the fourteen storage-adoption reads:
Defender settings, exact topic/subscription, complete scoped topic/subscription
inventories, scanner operator, exact role/assignment, and topic/settings
diagnostics. No cloud mutation, Graph client or new runtime permission is
introduced. These exact current objects are rechecked in NSP observations,
transitions, reconciliation and downstream role/image/window admission.
Only the verified topic/subscription inventory is recognized, including before
the first NSP receipt. Earlier adoption/NSP versions retain their closed schemas.

For this branch, NSP topology/observation/review version 2 binds an explicit
`queueOnlyRisk` acknowledgment to the current observation state, source,
configuration, topology and expiry. It requires
`functionalBlobProtectionQualified: false`, `blobUploadsAuthorized: false` and
`explicitInterruptionRiskAccepted: true`. Changing phase state requires a new
matching review. This permits the specifically approved queue-only qualification;
it neither certifies malware scanning/Sensitive Data Discovery nor authorizes
Blob tests, extra rules or disabled Defender. Paired false-only disable and
read-only image capture remain independent of these backend reads.

Parallel observation reads are assembled in the declared request order, not
completion order, so unchanged response values retain the same state hash.
This does not normalize resource values or reinterpret previously stored
observations and reviews. A source change requires fresh review binding;
earlier failed checks and their original hashes remain immutable.
Independent foundation, current-state, permission, lineage and effective-policy
collection share the existing four-read concurrency limit and 120-second
preflight deadline. Preview and qualification still wait for all prerequisites;
overlap does not reuse stale policy evidence or expand a timeout.

Network's HTTP 404 `NotFound` is an absence result only for the fixed
association and access-rule GET paths, pinned API version and explicitly
selected subscription. Parent resources, list operations, other paths and
authorization failures do not use that exception. Complete independent
inventories must still agree with the phase's expected absence. A deployment
stopped by the earlier response parser is not retried or rewritten as success;
it requires separate reviewed current-state reconciliation.
The five fixed Network inventories (profiles, associations, access rules,
links and link references) may terminate with `nextLink: ""` at the pinned API
version. Raw pages retain that value; other endpoints, malformed cursors and
incomplete lists do not gain this allowance.

Storage's pinned effective-configuration schema declares `provisioningIssues`
as an optional list of issues, if any. Actual issue-free responses may omit it.
That omission is accepted only alongside `Succeeded`, the independently verified
Network association's explicit `hasProvisioningIssues: "no"`, matching list/GET
responses and fully converged copied profile/rule/diagnostic versions. A present
value must be exactly `[]`; null, malformed or reported issues still fail.
Other missing fields do not gain an allowance. Raw observations and state hashes
preserve the omission rather than inserting an empty array.
See the [pinned Storage NSP schema](https://github.com/Azure/azure-rest-api-specs/blob/260ed6a52537921f53a18ffaf4020e3b4d510367/specification/storage/resource-manager/Microsoft.Storage/stable/2025-01-01/networkSecurityPerimeter.json).

NSP uses the existing receiver and queue account, one dedicated perimeter, one
profile, one explicitly `Enforced` account association and one inbound rule for
the specified subscription. Network admission is account-wide from that
subscription, not app-, identity- or queue-specific. Host and ingest identity
remain bound to the same intended subscription/tenant. Runtime queue RBAC stays
separate and narrow. No VM, VNet, private endpoint, new identity, policy exception,
extra member/link/outbound rule or diagnostic export is implicit.

| Fixed phase | Only permitted mutation |
| --- | --- |
| `nsp-empty-boundary` | One deployment PUT creating the perimeter and empty profile |
| `nsp-storage-lock` | One account PATCH changing only `publicNetworkAccess` to `SecuredByPerimeter` |
| `nsp-enforced-association` | One deployment PUT creating the exact `Enforced` association, with empty rules |
| `nsp-subscription-admission` | One deployment PUT creating the sole subscription rule last |
| `nsp-network-deny` | One DELETE of that exact rule, retaining the locked account and association |
| `nsp-subscription-readmit` | One independently approved fresh-instance PUT restoring the unchanged rule after verified terminal deny |

`preview-nsp` and `prepare-nsp` are local-only. `check-nsp` obtains bounded
read-only evidence; `execute-nsp` requires published source and the exact
phase's external approval. PATCH/DELETE previews bind their exact request and
preimage; they are not falsely labeled native ARM what-if. PUT phases require
full native template validation and what-if. Explicit contradictory returned
API versions/dependencies fail rather than being stripped away.

For `nsp-empty-boundary` only, ARM may omit the requested empty `properties`
objects on the new perimeter and profile. The preview may also use the exact
child leaf name already bound by its resource ID. These specific representations
do not establish computed state: the raw preview is retained and actual
perimeter/profile/rule inventories and versions still require readback.
Null, nonempty or unknown properties are not treated as an empty omission;
nonempty association or access-rule settings are never omittable.

The pinned APIs are Network `2025-09-01` and Storage `2025-01-01`.
The provider catalog can omit only the three documented NSP child types;
the registered root API/region and any advertised child versions are checked.
Raw catalog evidence and explicit unverified omissions are approval-bound.
Missing catalog entries do not establish API support or waive actual readbacks.
The association wire value is `Enforced`, never prose-only `Transition`,
`Learning`, `Audit` or an omitted default.

Readback independently checks Network resources and Storage's effective NSP
configuration: exact membership/rules, association mode, propagation status/issues,
copied rule and diagnostic versions, and empty enabled log categories. Network
version strings and Storage safe-integer versions are compared without rounding;
the association issue indicator is a string, not Boolean. Missing optional
fields remain unverified. ARM IDs use case-insensitive identity comparison with
strict object/path shapes; settings and URLs are not broadly normalized.
Comparison ignores only documented metadata at known paths, not arbitrary nested
fields named `etag` or `completedAt`. Failed reads retain bounded partial evidence,
never success-shaped incomplete lists.

Canonical lineage and unresolved-intent fences are keyed to physical target
identities, not a replaceable adoption/review hash. A fresh directory, wrapper,
source or nonce cannot reset a pending effect, including after a failed head
write. A later deny fences previous admission evidence. Current head and both
provider views are rechecked before new grants, publication/deployment and
enabled synthetic dispatch. Historical valid receipts alone are not current
authority. Version-2 operational queue records retain the entire network proof;
reconciliation v6 binds the new inventory without weakening versions 3-5.

The explicit NSP price-uncertainty review records the user's **USD 375/month
planning limit** and accepted uncertainty: prior USD 349.37 estimate plus a
USD 10 discretionary allowance gives USD 359.37 provisional total. The
contract price-sheet request returned 401; no matching public retail rows is
not proof of a zero fee. The exact disclosure, acknowledgment, evidence hashes,
source/topology and expiry are bound. Unacknowledged uncertainty is not a
fallback. Existing budget alerts remain USD 350/50/300; this review changes
neither budget resources nor prices, and provides no hard spending cap.

`reconcile-nsp` only captures uncertain state. A separate
`prepare-nsp-reconciliation` proposal and externally reviewed
`qualify-nsp-reconciliation` operation can append a version-2
`reviewed-nsp-reconciliation` after fresh complete evidence and pending-head
comparison. Its receipt qualifies current control-plane state only:
`originalExecutionQualified: false` and `originalHistoryModified: false`.
Original failed journals, reservations and the 120-second execution bound stay
unchanged. Missing dispatch/provenance, incomplete state, stale review/head or
changed generation remain blocked; there is no retry or fabricated original
success.

Control-plane rule removal is not proof of data-plane revocation. `Disabled`
alone can still permit NSP-allowed traffic when an association/rule exists.
The same otherwise-authorized identity needs separately bounded denial and
delivery qualification. Neither a different unauthorized principal's 403 nor
receiver 503 proves NSP denial. Optional diagnostics stay off; Azure's default
control-plane Activity Log is not claimed absent.

The paired false-only receiver-disable path deliberately does not require live
Storage/NSP or foundation availability. It still verifies frozen published
history, exact current app/UAMI/image/config, paired approvals and native
app validation/what-if. It cannot enable ingestion or alter another setting.
Publication observation is similarly separate from admission: an unpublished
candidate's first-copy readback remains available after network denial/expiry,
but is unqualified and grants neither retry nor deployment authority.

The new receiver candidate is **version 2**, with
`kind: reviewed-durable-queue-receiver`, the complete `priorCandidate`, original
`legacyPublication`, exact topology and an independent
`publish-one-reviewed-queue-receiver` review. Its exact third manifest/config
must be supplied by the future real build; null/placeholders/`qualified: true`
are not publishable evidence. It retains notices, scan/database freshness,
source archive, Linux/amd64/UID/command restrictions and native caveats. Only
this kind adds `src/queue-storage.ts`, `tests/queue-storage.test.mjs`, and
`tests/queue-sdk.test.mjs` plus the queued-only build/source inputs
`licenses/external-service-licenses.json` and
`licenses/external/nodable-entities-2.1.0/LICENSE.md` to the original 35-file
closure (**40 total**). These two root license inputs bind the exact service-only
upstream supplement and its public provenance; they are not inserted into
legacy source archives or a generic license exception. Typed
SDK proof binds the source file map and runtime-source manifest, explicit
fixture pass/fail counts, zero-network disabled behavior, durable ACK,
restart/TTL/overflow/retry/visibility/worker bounds and no implicit creation.
Its closed `encoding` evidence contains `version: 1`,
`kind: "base64-json-v1"`, the actually observed `encodedMessage` and
`decodedJson`, and measured integer `encodedBytes`/`decodedBytes`. The verifier
checks canonical Base64 re-encoding, exact UTF-8 roundtrip, both byte limits,
compact JSON and the unchanged closed nine-field record schema (including
nullable `durationBucket`). The exported `QUEUE_SDK_FIXTURES` list now requires
the original eleven groups plus `canonical-base64-wire`, `base64-size-bounds`,
`base64-no-plaintext-fallback`, and `base64-entity-heavy-batch`. Each group must
bind an actual retained case report and actual pass/fail counts. Source-only
tests or a claimed encoding flag cannot replace exact-image SDK evidence.
The batch case exercises 32 records whose plaintext JSON quotes would expand
into excessive XML entities; their actual Base64 wire avoids that expansion.
It does not waive the parser's limits for arbitrary entity-expanded XML.
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
