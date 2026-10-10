---
schemaVersion: 1
id: ART-filter-proposal
kind: proposal
changeId: CHG-remember-filter
---
# Remember the selected filter

## Problem

Returning to the list resets the user's filter and interrupts comparison work.

## Outcome

Remember the last selected filter in this browser, with a visible reset action.

## Scope

Store only the selected filter key locally. Do not synchronize it to an account,
collect usage data, or change the list's permission checks.

## Acceptance

Reloading restores a valid saved filter. Resetting removes that preference and
returns to the default list. Unrecognized stored values use the default.
