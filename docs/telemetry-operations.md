# Telemetry ingestion operations

**Status: local implementation and local qualification only.** No Azure resources,
production endpoint, permission grants, deployed retention guarantees, or publication
are established by these files. Cloud authentication, planning/readback, apply,
image publication, synthetic ingestion, and CLI endpoint activation each require
separate operator authorization. Normal MissionSpec use never depends on this service.
An authorized read-only account preflight is not evidence that resources were
deployed. Keep its account inventory, identities, budget recipients, private
configuration, and cost report outside versioned/public source. The controller's
ignored, access-restricted `.operator-private/` directory is local operator data,
not a repository artifact to publish.

The [direct ARM operator](telemetry-operator.md) is the supported deployment
route: fixed phases, full local private what-if review, explicit subscription,
ownership and readback gates. The private-runner OpenTofu/VM/Job route is retired.
Its source/diff and all private receipts remain archived; its foundation remains
preserved. No runner, operator image, authentication broker or encrypted relay is
needed for ARM control-plane review. Image publication, disabled receiver,
synthetic admission and client activation remain separate authority boundaries.

The private package at `services/telemetry-ingest/` in a source checkout is an
original Apache-2.0 operator artifact, not a CLI dependency or business engine.
The canonical ARM definition at `infrastructure/arm/telemetry/` provisions only
the explicitly reviewed new/owned MissionSpec resources. Operator sources are intentionally excluded from the
CLI package; use the [source repository](https://github.com/voyager163/missionspec)
for these files. The implementation does not import another product's source, endpoints,
identities, or infrastructure. The client remains unconfigured until release qualification.

## Wire contract and privacy boundary

The sole editable schema is
[`assets/schemas/telemetry-event.schema.json`](../assets/schemas/telemetry-event.schema.json).
Run `npm --prefix services/telemetry-ingest run schema:generate` after an approved
schema change. The service copy is byte-identical; its provenance records the source,
generator, and SHA-256. Both service tests and container builds fail on drift.
Azure columns derive from that schema; never edit generated copies independently.

`POST /v1/events` accepts exactly `Content-Type: application/json`, without parameters,
content encoding, query strings, bulk envelopes, or extra fields. Requests are at most
1,024 **streamed bytes**, checked before JSON parsing, including chunked requests.
UTF-8, field types, version, enums, and the closed object are validated with Ajv2020.
Only these fields are projected to storage:

| Field | Wire values |
| --- | --- |
| `schemaVersion` | `1` |
| `event` | `operation-completed` |
| `operation` | `draft`, `draft-all`, `implement`, `verify`, `archive`, `revise`, `principles`, `sync` |
| `cliVersion` | Numeric release or `alpha`/`beta`/`rc` version allowed by the schema, not arbitrary build metadata |
| `outcome` | `completed`, `blocked`, `failed`, `cancelled`, `unknown` |
| `host` | `copilot`, `codex`, `claude`, `none`, `multiple`, `unknown` |
| `os` | `macos`, `windows`, `linux`, `other` |
| `durationBucket` | `under-1s`, `1s-to-10s`, `10s-to-1m`, `1m-to-10m`, `10m-to-1h`, `1h-or-more`, or `null` |

The receiver alone adds UTC `TimeGenerated` at receipt. No persistent client IDs,
client timestamps, IP/geolocation, arguments, paths, source, prompts, raw errors,
headers, or request metadata are stored in the custom event columns. The Analytics
table uses strings for enum columns; Azure may represent a null duration as an empty
string. Both mean unknown, never zero elapsed time. Duration includes possible user
waiting; it is not a model benchmark.

Azure additionally processes connection metadata and adds platform/system table
metadata (for example ingestion/billing fields). SDK requests may carry transient
platform correlation headers. Absence of an IP property is **not an anonymity
guarantee**. Rare field combinations may also be distinctive. The service neither
logs raw requests nor enables Application Insights/OpenTelemetry capture. The module
omits Container Apps log persistence and diagnostic settings; organization policy or
manual changes can override that. Deployed settings must be inspected before launch.

The public endpoint has no client credential: events can be forged. Counts are
directional usage indicators, **not billing, security, unique-user, or correctness
evidence**. Do not add a shared secret to the distributed CLI.

## Local checks (no Azure credentials)

Use Node.js **24.21.0 or newer on the 24.x LTS line**. The service owns its
own lockfile and dependencies; direct ARM requires no OpenTofu/provider install:

```sh
npm --prefix services/telemetry-ingest ci --ignore-scripts --no-audit --no-fund
npm --prefix services/telemetry-ingest test
node --test infrastructure/arm/telemetry/tests/*.test.mjs
```

The Node infrastructure tests make no Azure calls. The separately invoked
operator `check` performs scoped reads and nonmutating ARM validation/what-if;
it is not permission to create resources. Full what-if/readback JSON remains
private on this machine. Unit tests are not deployed integration evidence.

HTTP tests bind ephemeral **loopback** listeners with injected storage. Azure SDK
transport tests inject an in-memory HTTP transport and synthetic credential object:
they do not contact Azure or request tokens. Imports start no listener, load no
operator environment, create no credentials, and perform no network activity.

Recorded local checks on 2026-09-21: Node 24.21.0 schema/type/service suite **18/18**,
IaC static policy suite **4/4**, OpenTofu 1.12.6 formatting and provider-schema
validation passed. The final Linux AMD64 image built on a verified local Docker
Desktop daemon, passed the same 18 service tests, and passed the non-root,
read-only-filesystem, external-network-disabled smoke check. Unconfigured container
startup returned `CONFIG_MISSING` and exit 1 as expected. No deployed/cloud behavior
was tested.

### Container qualification

The Dockerfile pins Node 24.21.0 bookworm-slim for the build stage and a maintained
Debian 13 distroless C++ runtime by immutable AMD64 manifest digest. It performs
schema/type/HTTP tests, prunes development dependencies, and copies only Node and
the service production closure into the non-root `65532:65532` runtime.
The root `.dockerignore` allowlists only the required service and canonical
schema files; local configuration, state, unrelated source trees, and caches are not submitted.
Review the digest and dependency notices again before releasing. A successful local
build is not an image vulnerability/license audit or a signature/publication.
The same image carries a verified versioned corresponding-source archive and
readable runtime notices; see [minimal runtime qualification](telemetry-runtime.md).

First inspect the Docker context and builder: both must resolve to a trusted local
daemon, not a remote builder. Do not install Docker or send repository context to a
remote service to work around a missing local daemon. For an already verified local
builder, replacing `LOCAL_BUILDER` with its actual name:

```sh
docker buildx build --builder LOCAL_BUILDER --platform linux/amd64 --load \
  --provenance=false -t missionspec-telemetry-ingest:local-qualification \
  -f services/telemetry-ingest/Dockerfile .
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges -i missionspec-telemetry-ingest:local-qualification \
  /usr/local/bin/node --no-turbofan --no-maglev --disable-sigusr1 --input-type=module < services/telemetry-ingest/scripts/container-smoke.mjs
```

The smoke test checks non-root execution, health, and one synthetic in-memory event
inside the container's loopback network; it has no external network or Azure adapter.
Running the unconfigured default entrypoint must exit `1` with only `CONFIG_MISSING`.
The mutable local test tag is never an acceptable deployment image reference.
Inspect the selected image's actual architecture and shipped license/notices,
not its tag name or a prior build report. A previously built AMD64 image may
predate the notice-copying stage. Rebuild the current Dockerfile on the explicitly
verified local builder and repeat the offline checks before publication; do not
silently publish an older image or treat a local config digest as a registry
manifest readback.

## Explicit service startup

`npm --prefix services/telemetry-ingest start` runs the production entrypoint after
`build`. **Do not start an Azure-connected instance before authorization.** There is
no development-to-production destination fallback and no `.env` autoload. The
embedding API is `createTelemetryServer({ storage, limits, enabled })`; local tests
must inject storage rather than starting the production entrypoint with real Azure
settings. No events are sent just by starting a configured service.

Required environment:

| Name | Constraint |
| --- | --- |
| `MSR_BIND_HOST` | Explicit `127.0.0.1` locally or `0.0.0.0` behind Container Apps ingress |
| `PORT` | Integer 1024–65535; IaC uses 8080 |
| `MSR_INGESTION_ENABLED` | Exactly `true` or `false`; IaC defaults to false |
| `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` | Operator subscription/tenant and ingestion identity UUIDs |
| `MSR_RESOURCE_GROUP` | Exact intended MissionSpec resource group |
| `AZURE_DCR_RESOURCE_ID` | DCR resource ID in that exact subscription and resource group |
| `AZURE_DCR_IMMUTABLE_ID` | DCR's actual `dcr-` plus 32 hexadecimal characters |
| `AZURE_LOGS_ENDPOINT` | DCR-generated HTTPS `*.ingest.monitor.azure.com` origin; no credentials, port override, path, query, or fragment |
| `MSR_HEADERS_TIMEOUT_MS`, `MSR_BODY_TIMEOUT_MS`, `MSR_STORAGE_TIMEOUT_MS` | Each integer 10–5000; choose limits consistent with the client's one-second total budget |
| `MSR_MAX_CONNECTIONS` | 1–1024 |
| `MSR_MAX_CONCURRENT_REQUESTS` | 1–256 and no greater than max connections |
| `MSR_MAX_CONCURRENT_INGESTIONS` | 1–64 and no greater than max concurrent requests |
| `MSR_REQUESTS_PER_MINUTE` | 1–60000 all-client request attempts |
| `MSR_EVENTS_PER_DAY` | 1–1000000 validated upload attempts |

The stream name is fixed to `Custom-MissionSpecTelemetry`. The module wires the
resource ID, immutable ID, and generated endpoint from the **same DCR**, with only
that DCR granting the ingestion identity `Microsoft.Insights/Telemetry/Write`.
Offline configuration validation cannot prove resource ownership or that independently
entered IDs match: those are deployed readback gates. Only public Azure is supported;
sovereign clouds/private-link require a separately reviewed configuration.

The adapter uses only `ManagedIdentityCredential`, not default-credential fallback,
interactive sign-in, CLI credentials, tokens, or shared keys. Upload retry and
redirect counts are zero; one upload contains one record. SDK logging is silenced and
request logging/tracing policies removed. Nonempty debug/auto-instrumentation
variables, `NODE_OPTIONS`, Azure authority overrides, and outbound proxy overrides
are rejected rather than leaking payloads or silently changing destination behavior.
Container Apps' platform-managed identity endpoint variables remain platform-owned.
Do not inject tracing agents, startup wrappers, or payload-capturing sidecars.

Missing/invalid/unsafe configuration exits visibly with `CONFIG_MISSING`,
`CONFIG_INVALID`, `CONFIG_UNSAFE_ENVIRONMENT` or `CONFIG_UNSAFE_RUNTIME`, without
application-supplied values or exceptions. The image disables SIGUSR1 inspector
activation and rejects inspector/debugger arguments and TLS trust overrides.
Do not override the image command or inject native startup options; Node itself
can process such options before the application's validation runs.
Other startup/listener failures expose only `SERVICE_START_FAILED` or
`SERVICE_LISTENER_FAILED`. There are no access logs, raw error dumps, or environment
logging. The library's `snapshot()` returns only fixed aggregate counters; there is
no public counter/admin endpoint and no periodic diagnostic exporter.

## Admission, responses, and health

All application responses have zero body bytes, `Cache-Control: no-store`,
`Content-Length: 0`, and connection-close semantics. Header parsing is limited to
4 KiB and 24 fields; sockets, header/body deadlines, request concurrency, and upload
work are bounded. Unsupported expectations/upgrades are rejected without reflection.

| Status | Meaning |
| --- | --- |
| 204 | Event upload completed successfully, or a passing health check; not proof of query visibility |
| 400 | Invalid JSON, UTF-8, schema, or HTTP framing |
| 404 / 405 / 415 / 417 | Unknown route, wrong method, unsupported media/encoding, or expectation |
| 408 / 413 / 431 | Body deadline, oversized body, or excessive header count |
| 429 | Global in-memory request/upload-attempt budget exhausted |
| 503 | Disabled admission, capacity exhausted, storage failure/timeout, or cancellation |

Some parser, connection-limit, or disconnect conditions close the connection without
a response. No error response echoes data, path, headers, or error details.

Storage timeouts abort the request and return unavailable, **never 204**. If a storage
adapter ignores cancellation, its work slot stays occupied until it really settles:
new uploads cannot create an unbounded hidden queue. Socket disconnect, shutdown,
and the in-process kill switch abort outstanding operations. SIGTERM/SIGINT close
listeners/connections and bound process exit. A timeout can occur after Azure
accepted a record: delivery is uncertain, not exactly-once. Neither sender nor server
retries, queues, or replays it; do not manually resend uncertain events as a repair.

`GET /health/live` is a status-only process check. `GET /health/ready` checks local
admission capacity, not Azure authentication or stored-event visibility. A recent
storage failure closes readiness for five seconds, then permits recovery without
sending a synthetic probe. Stuck work stays unavailable. Disabled instances are
**ready to reject events** so a disabled revision can deploy; events still get 503.
Health endpoints perform no ingestion and are exempt from request quotas, but retain
connection/header bounds. An initial 204 readiness result is not backend qualification.

The quotas apply across **all clients of one process**, without IP/user tracking.
The module enforces one maximum replica and Single revision mode. Fixed windows are
process-relative, not a durable calendar ledger: restarts reset them, adjacent windows
can burst, and revision handover can briefly overlap old/new instances. These are
bounded admission controls, not a distributed hard spend ceiling or DDoS service.
Do not raise maximum replicas without redesigning aggregate quotas. Workspace daily
caps may overshoot or lag, and budget alerts do not stop spending. Review cold starts,
one warm replica versus zero, workload limits, and handover costs explicitly; do not
silently extend the CLI's one-second budget to mask slow startup.

## Infrastructure and deployment prerequisites

The one canonical direct ARM definition uses explicit resource interfaces,
including the custom table and a `kind = Direct` DCR with its own ingestion
endpoint; a DCE is unnecessary for this public-endpoint design. It does not
retrieve workspace or storage login keys. The resources are:

- MissionSpec resource group, Consumption Container Apps environment/app, and
  **authenticated private-pull** ACR repository. ACR's network endpoint remains
  public in this design; “private” means no anonymous/admin-key pull, not Private Link.
  The environment's platform-managed infrastructure group is explicitly named
  `${name_prefix}-managed`, so its ownership and any separately billed resources
  can be included in the deployment inventory and cost review.
- Separate user-assigned pull and upload identities: ACR-scoped `AcrPull`, and a
  custom upload-only data action assigned at the one intended DCR.
- Dedicated Log Analytics workspace and `MissionSpecTelemetry_CL` Analytics table,
  schema-derived DCR projection, and workspace-scoped `Log Analytics Reader` grants
  to operator-selected Entra principals. No client query permission.
- Explicit Consumption CPU/memory/concurrency bounds, singleton replica policy,
  workspace ingestion cap, monthly resource-group budget and alert contacts.
- HTTPS public ingress with insecure connections disabled; no Dapr, Application
  Insights, diagnostic routes, raw console/request persistence, export, or archive.

**Every deployment needs operator decisions**, supplied privately, never real values
committed as deployment configuration:

1. Subscription, Entra tenant, explicit authorized local operator principal, role-grant authority,
   and registered `Microsoft.App`, `Microsoft.ContainerRegistry`,
   `Microsoft.ManagedIdentity`, `Microsoft.OperationalInsights`,
   `Microsoft.Insights`, and `Microsoft.Consumption` providers. Registration is not
   performed automatically. Review custom-role and budget creation permissions.
2. Region/data residency/capacity, globally unique `missionspec-…` resource prefix
   and ACR name, and the named query operator.
3. Domain decision: the definition uses the explicit Azure-managed hostname choice and
   outputs an **unqualified candidate** hostname only. If a branded/custom hostname
   is required, stop and separately authorize DNS ownership verification and TLS
   binding work; this module does not pretend to provision them.
4. Approved Linux AMD64 image manifest digest in this new registry, provenance,
   license/notices and vulnerability review, and image build/publish authority.
   No `latest` or mutable deployment tag; no substitution from another registry.
5. All service limits, warm/cold scaling decision, supported bounded CPU/memory pair,
   cost-policy review, daily workspace quota, monthly budget/currency and active
   first-of-month start/end dates, and monitored budget email contacts.
6. **Preserved foundation and history**: the existing private Blob/PE/DNS
   foundation and all former state/approval/ledger/source receipts stay intact.
   Direct ARM does not initialize or use a Terraform backend. The approved
   governance delta is exact; a newly observed change still blocks deployment
   until separately reviewed. Full local templates/what-if/readbacks remain
   potentially sensitive private operator data.

### Read-only prerequisite and cost review

Before authorizing creation, pin every account-specific CLI/ARM read to the
approved subscription. Verify its tenant and enabled state, effective/inherited
RBAC and deny assignments, provider registration, regional resource types and
quotas, inherited policies, and the resource inventory. Name-availability checks
do not reserve names. A supported SKU and unused quota do not guarantee capacity.
Do not reuse another product's registry, identities, workspace, storage, network,
or state merely because they are visible to the current operator.

The authorized local operator makes only fixed ARM requests and separately
reviewed role assignments. Existing owned groups are verified, not imported,
retagged or recreated. There is no runner registration, remote initializer,
CLI-token transfer to a guest, shared-key/SAS fallback or public state change.

Price the complete incremental deployment with current regional retail meters,
including preserved private state endpoints/DNS/storage/recovery, registry,
ingestion/retention, possible managed LB/IP, inherited security and the uncertain
environment-management meter. The conservative model charges all 180 retention
days rather than relying on included retention. Do not assume subscription/billing-account
free allowances remain available. Include billing-month length, enforced image
digest count, initial/daily scanning, and a fully active warm-replica scenario. A resource-group
budget does not cover a separate state/runner group: allocate budgets across
every new billed group, or explicitly filter a dedicated combined budget to those
groups. Do not change an unrelated subscription-wide budget. The reviewed
direct ARM revision permits only the dedicated project-filtered budget's
USD 250-to-350 amount change, preserving its dates/filter/notifications. The
state budget stays USD 50; the planned telemetry budget is USD 300. The complete
31-day estimate is USD 301.66 with unchanged traffic and security reserves.
The combined budget still covers the separately named managed group.

Inspect inherited Defender pricing and extensions as well as Azure Policy:
subscription-enabled plans can automatically cover new resources without an
explicit resource in this module. Paid CSPM can count Container Apps and blob
storage accounts; storage protection, registry-image scanning and temporary VM
protection have separate billing semantics. Do not assume daily image rescans
are free from a legacy registry-plan statement. Carry an explicit reserve until
the applicable plan's assessment counting is verified, and do not disable global
security protections to make an estimate fit.

Private state networking does not exclude authorized platform security scanning.
Malware scanning can read state blob bytes and write scan-result tags; sensitive
data discovery can sample contents and retain classified metadata; agentless VM
scanning can inspect runner disks. These are separate processing boundaries from
the eight-field analytics event. Minimize credential collection, but do not claim
state is secret-free or that private endpoints prevent all platform access. No raw telemetry
payload, state copy, or scanner output becomes an analytics export.

Record the current prices, uncertainties, selected caps and stop conditions in
the private gate report. App quotas reset on restart, workspace caps can
overshoot, and rejected public requests can still incur ingress request charges.
Neither these controls nor budget alerts establish a monetary hard cap.

Deployment is explicitly phased: the separately approved exact project-budget
amount update and qualified USD 350 readback **before** core creation/readback, workspace access,
data schema/DCR, role definition/assignments, separately authorized image
publication, disabled app, then separately authorized synthetic admission.
Generated IDs/endpoints are literal reviewed inputs only after their readbacks;
the controller does not pretend unknown values have been reviewed.
No arbitrary ARM/shell execution or automatic image push is exposed.
Initial publication authority is limited to **one reviewed immutable AMD64
digest**. A future-build count in a cost estimate is not advance publication
permission for those builds.

## Retention and activation gates

Workspace retention is 180 days. The custom table explicitly sets **Analytics
retention = 180** and **total retention = 180**, with no additional archive period,
data export, or Event Hub/storage destination. These are desired settings, not
evidence of deployed behavior or instant physical deletion at a particular second.
Azure retention enforcement has platform semantics/lag; validate documented and
observed behavior before making a user-facing retention guarantee. Client opt-out
stops future sends; it does not immediately erase accepted aggregates.

After separate authorization, operators must:

1. Inspect the applied resource IDs, region, identities and exact RBAC scopes,
   immutable image digest/architecture, provider state and DCR endpoint ownership.
2. Read back workspace and table Analytics/total retention and DCR projection.
   Verify no extra destination/export/archive, diagnostic settings, policy-added
   console/ingress persistence, Application Insights, or raw payload capture exists.
3. Explicitly enable **synthetic qualification only**. Send approved content-free
   synthetic events, query only the intended table, and check exact product columns,
   unknown-duration representation, UTC receipt time, and platform-added columns.
   Observe real ingestion errors/visibility and deletion/retention behavior over the
   appropriate horizon; a locally passing fixture cannot prove retention.
4. Exercise capacity/rate rejection, unavailable Azure/identity permissions, cold/
   warm latency, timeout ambiguity, readiness recovery, kill switch, and image
   rollback. Verify no payload-bearing logs appear during each case.
5. Approve operator identity/contact, exact TLS endpoint/domain, region and privacy
   disclosure, cost/runbook readiness, and backend qualification before separately
   approving client endpoint compilation/activation. No development build acquires a
   production destination from this module merely because an output exists.

Cloud availability, identity behavior, actual diagnostic settings, retention
enforcement, quotas, custom domains, and release publication remain unqualified.
The local checks above did not authenticate to Azure, query/control its resources,
deploy, publish, sign, push, or contact a production telemetry collector.
Any later authorized read-only preflight is separate evidence; it must not be
reported as successful deployment, enforced retention or client activation.

## Kill switch, rollback, and recovery

- **Immediate admission stop:** with incident authority, disable external ingress
  or stop the app through the approved operator channel; use the client hard-disable
  policy independently. The library has `setEnabled(false)` for embedded control,
  but deliberately exposes no unauthenticated HTTP admin route.
- **Durable service stop:** review/apply `ingestion_enabled=false` to roll out an
  instance that returns 503 without uploading. Existing in-flight calls may already
  have reached Azure; this is not a data deletion operation. Reconcile any emergency
  control-plane changes into IaC rather than leaving drift.
- **Rollback:** disable admission first if privacy/cost is uncertain, select the
  previous reviewed digest from the same registry, review the plan, and deploy one
  revision. The image must still match the active schema/DCR/table. Recheck health,
  synthetic behavior under authorization, and diagnostic settings before enabling.
  Do not replay failed requests. Old inactive revisions are bounded to three.
- **Recovery:** correct config/RBAC/outage or replace a stuck process; do not loosen
  validation, enable verbose SDK logging, lengthen the client deadline, or add
  retries as an expedient repair. Restarts reset in-memory quotas; review attack and
  spend conditions before restarting repeatedly. Keep operator diagnostics separate
  from usage analytics. Deletion/purge and retention changes need their own approval.

## Platform references

These documents informed the original implementation, not a claim of deployed state:

- [Logs Ingestion API, direct DCR endpoints and DCE conditions](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [Container Apps log destinations](https://learn.microsoft.com/en-us/azure/container-apps/log-options)
- [Analytics and total retention](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure)
- [ARM workspace properties](https://learn.microsoft.com/azure/templates/microsoft.operationalinsights/workspaces)
- [ARM Container Apps environment properties](https://learn.microsoft.com/azure/templates/microsoft.app/managedenvironments)
- [AzAPI 2.12.0 provider](https://github.com/Azure/terraform-provider-azapi/tree/v2.12.0)
