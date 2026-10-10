---
schemaVersion: 1
id: ART-filter-tasks
kind: tasks
changeId: CHG-remember-filter
---
# Filter implementation plan

## Tasks

### [ ] TSK-filter: Store and restore the selected filter

```missionspec
dependsOn: []
requirements: [REQ-filter]
scenarios: [SCN-filter-reload]
checks: [CHK-filter]
writeScope: [src/filter-preference.ts, tests/filter-preference.test.ts]
```

Implement validated restoration and a default fallback for unknown values.
Keep the existing permission checks unchanged.

### [ ] TSK-reset: Add preference reset

```missionspec
dependsOn: [TSK-filter]
requirements: [REQ-reset]
scenarios: [SCN-filter-reset]
checks: [CHK-reset]
writeScope: [src/filter-preference.ts, tests/filter-preference.test.ts]
```

Remove the preference on reset and preserve the default across a later reload.

## Checks

### CHK-filter: Check restoration and fallback

```missionspec
method: executed
requirements: [REQ-filter]
scenarios: [SCN-filter-reload]
```

After separate verification authorization, run the scoped preference tests for
a supported value, an unknown value and unavailable storage. This definition is
not an executed result.

### CHK-reset: Check reset persistence

```missionspec
method: executed
requirements: [REQ-reset]
scenarios: [SCN-filter-reset]
```

After separate verification authorization, exercise selection, reset and reload.
Retain the actual result and source revision as evidence outside this document.
