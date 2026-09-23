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

The completed budget/core/workspace-access/data sequence uses `reconcile data`
for a read-only, unapproved version-2 proposal. `qualify-reconciliation data` requires a separate exact
parent review and repeats live reads before issuing new read-only receipts.
Neither command deploys resources or rewrites original execution history.
