---
schemaVersion: 1
id: ART-reset-spec
kind: specs
changeId: CHG-remember-filter
---
# Resetting a saved filter

## Requirements

### REQ-reset: Clear a saved preference

```missionspec
operation: add
```

The reset action must remove the saved filter preference and show the default list.

### SCN-filter-reset: Reset a previously saved filter

```missionspec
operation: add
requirement: REQ-reset
```

Given a saved filter, when the user resets the list and reloads, then the default
filter remains selected and the saved preference is absent.
