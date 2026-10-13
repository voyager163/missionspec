---
schemaVersion: 1
id: ART-filter-spec
kind: specs
changeId: CHG-remember-filter
---
# Saved filters

## Requirements

### REQ-filter: Restore a saved filter

```missionspec
operation: add
```

The list must restore a previously selected, currently supported filter key.
An unrecognized key must fall back to the default filter without changing access.

### SCN-filter-reload: Reload after selecting a filter

```missionspec
operation: add
requirement: REQ-filter
```

Given a supported selected filter, when the user reloads the list, then the
selected filter is restored and only permitted entries are displayed.
