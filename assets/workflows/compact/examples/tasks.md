---
schemaVersion: 1
id: ART-summary-tasks
kind: tasks
changeId: CHG-count-summary
---
# Summary text plan

## Design

Keep the existing count calculation. Choose the explicit empty-state label when
that count is zero. A separate design artifact may be marked not applicable only
with a reviewed reason and the relevant source revision; this paragraph does not
perform that state transition.

## Tasks

### [ ] TSK-summary: Render the empty-result label

```missionspec
dependsOn: []
requirements: [REQ-summary]
scenarios: [SCN-summary]
checks: [CHK-summary]
writeScope: [src/list-summary.ts, tests/list-summary.test.ts]
```

Update the zero-count label while preserving nonzero counts and permission checks.

## Checks

### CHK-summary: Check the zero-count label

```missionspec
method: executed
requirements: [REQ-summary]
scenarios: [SCN-summary]
```

With separate verification authorization, exercise zero and nonzero visible
counts. The task checkbox and this plan are not evidence that the check ran.
