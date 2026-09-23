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
