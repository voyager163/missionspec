---
schemaVersion: 1
id: ART-summary-spec
kind: specs
changeId: CHG-count-summary
---
# Empty-result summary

## Requirements

### REQ-summary: Explain an empty result set

```missionspec
operation: add
```

The list summary must display "No results" when there are no visible entries.

### SCN-summary: Open an empty list

```missionspec
operation: add
requirement: REQ-summary
```

Given no visible entries, when the list finishes loading, then its summary
displays "No results".
