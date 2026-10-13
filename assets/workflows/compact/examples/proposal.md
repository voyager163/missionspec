---
schemaVersion: 1
id: ART-summary-proposal
kind: proposal
changeId: CHG-count-summary
---
# Clarify the result count

## Problem

An empty count label is ambiguous when the list has no results.

## Outcome

Display an explicit zero-result summary.

## Scope

Change only the summary text. Do not change filtering, permissions or data loading.

## Acceptance

A list with no visible entries displays "No results" rather than an empty label.
