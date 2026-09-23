# Retired operator route

This path is **not a supported deployment definition**. The private-runner
OpenTofu/VM/Container Apps Job route was retired in favor of the fixed-purpose
direct ARM collector at [`../../arm/telemetry`](../../arm/telemetry).

Before retirement, the complete uncommitted cloud source, binary diff and
related documents were preserved with hashes in the ignored private
`.operator-private/retired-operator-route/` archive. Existing state resources,
private receipts, approval history, ledger chains and local audit artifacts
were not deleted, reset or retagged. Historical approvals do not authorize the
new ARM route. The unpushed operator image remains quarantined.

There is no Terraform module or operator executable here to run. Do not restore
it as a second live definition. The one supported check is now:

```sh
node --test infrastructure/arm/telemetry/tests/*.test.mjs
```
