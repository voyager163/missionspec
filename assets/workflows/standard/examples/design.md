---
schemaVersion: 1
id: ART-filter-design
kind: design
changeId: CHG-remember-filter
---
# Local filter preference

## Approach

Use one local preference key containing a supported filter identifier. Validate
the value against the current list's allowlist before restoring it. Reset removes
that key. Keep preference handling separate from permission-based list filtering.

## Risks

Storage can be unavailable. In that case retain the existing default behavior
and report the preference as unsaved without implying the list operation failed.
