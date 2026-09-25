# Convergence review

Verification distinguishes actual check results from code-inspection and agent
judgments. Convergence adds source-bound findings in four categories:
**missing**, **partial**, **contradictory**, and **unrequested** behavior.
It does not infer correctness from checked tasks or a successful host exit.

A review supplies schema version 1, the current revision binding, the exact
declared source-file inventory with hashes (or `absent`), and typed findings.
Each finding identifies its basis (`static-inspection` or `agent-judgment`),
severity, affected requirement/task IDs, source observations and any referenced
retained check evidence. The scope is explicitly
`declared-source-files-only`; this is not a claim of whole-repository inspection
or a deterministic semantic proof.

`LocalConvergence.preview` validates references and reobserves the complete
declared source inventory. A separate verification-purpose local approval
permits `capture` to persist the review in the private immutable audit history.
The recorded review does not execute tests, edit tasks/source, approve
implementation, accept work, promote specs, or archive.

New reviewed revisions explicitly supersede the previous review. History must
have one complete unambiguous chain. A captured blocking finding makes
acceptance ineligible. Source/intent drift makes a captured review stale and
requires an explicit current review rather than silently forgetting its
blockers. An empty reviewed finding set remains a bounded human/agent judgment;
it never turns missing or failed executed checks into passing evidence.

Proposed repair tasks have stable identities derived from the finding and
review revision. They retain requirement/check/source links, but are only
proposals. Saving them requires reviewed task-artifact revision; executing them
requires current implementation authority. In particular, an unrequested-work
finding cannot silently broaden the original approved task or file scope.

The MCP transport offers `missionspec_convergence` inspection and a
`convergence` action through its guarded preview/apply protocol. See the
[MCP authority boundary](mcp.md). Local tests use original source and review
fixtures; no model-generated assertion is relabeled as an executed test.
