# MissionSpec collector: canonical direct ARM definition

This is the single supported collector deployment definition. See
[`docs/telemetry-operator.md`](../../../docs/telemetry-operator.md) for phase
boundaries, local private review, ownership, budget and publication gates.

```sh
node --test infrastructure/arm/telemetry/tests/*.test.mjs
```

No Azure credentials are needed for these tests. The CLI accepts only fixed
collector phases; `prepare` makes no cloud calls, and `check`/`validate-preview`
perform only nonmutating reads and ARM validation/what-if. No checked-in file
contains deployment authority or account-specific configuration.
What-if uses a fixed authenticated async start/poll adapter, not a blocking
CLI long-running poller. Requests remain at most 15 seconds within the same
120-second phase-check deadline; response handles and full results stay private.
The qualified local Azure CLI Python bridge is part of the source hash.

The completed budget/core/workspace-access/data/upload-role/assignments/disabled-app
sequence uses `reconcile disabled-app` for a read-only, unapproved version-3 proposal.
The one-image publication is independently verified history, not an ARM phase.
`qualify-reconciliation disabled-app` requires a separate exact
parent review and repeats live reads before issuing new read-only receipts.
Neither command deploys resources or rewrites original execution history.
Assignment grants additionally require fresh scoped role-definition checks
bound to the approval and repeated after request-body preparation.

`prepare-window synthetic-admission` performs read-only preparation of paired
enable/disable transitions with a new cryptographic instance UUID and a closed,
settled predecessor record. Collector IDs/tags and old deployments never change.
The Python what-if bridge derives the same new instance names as execution.
Separate exact version-2 approvals are required before
`run-window synthetic-admission`; direct toggle `execute` is forbidden.
The fixed `execute-disable synthetic-disable` recovery path never replays an
uncertain submission. New-revision readiness and terminal disabled proof are
required; no preparation operation sends HTTP fixtures or enables ingestion.
Final HTTP/query dispatch guards run after the last awaited operation. One
120-second submission-to-ready deadline and intent-anchored work/window/recovery
deadlines distinguish safe late disable recovery from successful qualification.

## Reviewed disabled receiver image overlay

`receiver-upgrade.mjs` defines the closed version-1 receiver profile/publication
and disabled-image execution record. It does **not** change configuration v2,
the seven historical phases, their prerequisites, or the original one-image
publication. No candidate image is built, pushed, or production-cleared by this
module. A `qualified: true` flag is not candidate evidence.

The fixed commands are `preview-image-publication disabled-image-upgrade`,
`prepare-image disabled-image-upgrade`, `check-image disabled-image-upgrade`,
and `execute-image disabled-image-upgrade`. The independent
`disabled-image-rollback` phase has its own instance, exact before-image, fresh
review and approval. The first two commands are local-only; execution remains
an explicit parent/operator action. See the operator guide for private input
artifacts and the publication/deployment authority boundary.

Image what-if retains the app `Modify` plus known preserved `Ignore` entries,
without rewriting the full payload. A full 120-second preflight is followed by
separately bounded final checks; one new absolute 120-second rollout deadline
starts at durable intent. Approval expiry and five-minute proof freshness still
apply, and each request is bounded by 15 seconds and its stage's remaining time.

Only the original digest plus one explicitly reviewed candidate/tag may exist.
The two-image estimate is **USD 311.23 / 31 days**, below the reviewed USD 350
project estimate; rejected-request, full security, environment and network
reserves remain included. This is neither a hard billing cap nor publication
permission. Fresh digest-count/cost approval is required before the one push.

After a successful reviewed disabled-image change, preserve
`disabled-image-record.json` unchanged. A later revision supplies it as
`receiver-upgrade.json` and as its `window-predecessor.json`; it does not replace
`receipts.publication` or `receipts["disabled-app"]`. Standard paired window
approvals, durable UUID reservation, timeouts and terminal false/503 proof
remain mandatory.
