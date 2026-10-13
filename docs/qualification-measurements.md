# Offline qualification measurements

`scripts/qualification-report.mjs` formats explicitly supplied, reviewed
measurement records. It is **not a model runner, benchmark pass, statistical
comparison, release gate or grant of authority**. It starts no subprocess,
native host, model, network/API request, account/billing probe or session
discovery. It never consumes host logs, prompts, source code or raw model output.
Live complete-task benchmarks and semantic-effectiveness qualification remain
pending separately approved trials.

## Invocation

From a source checkout with Node.js `>=24.21.0 <25`:

```sh
node scripts/qualification-report.mjs --file /explicit/path/reviewed-measurements.json
node --test tests/qualification-report.test.mjs
```

The helper has no package dependencies and does not require a build. It reads
only the named UTF-8 JSON file, emits descriptive JSON to stdout and writes no
files. Redirect stdout only to an explicitly chosen destination when retaining
a report. A rejected input exits with code 1 and a bounded JSON error code on
stderr, without echoing its path, contents or rejected values. There is no
auto-discovery, remote input, repair, partial-success or best-effort fallback.

The input must be a regular file, not a final-component symlink, and must remain
unchanged while read. The helper opens a read-only, nonblocking descriptor
before checking its type and size, then checks the named path against that
held descriptor before consuming bytes. It does not reopen a checked pathname.
The helper bounds the read to 1,000,000 bytes, JSON depth
to 12, tasks to 100, segments to 100 per task and 1,000 per file. Duplicate JSON
keys, including escaped spellings, are rejected before they can hide data.
All record objects are closed: unknown fields are errors, not ignored metadata.

## Version 1 input contract

One file describes **one exact binding and one measurement basis**. Multiple
hosts, models, source versions or candidates require separate files. The root
has exactly `schemaVersion: 1`, `basis`, `binding` and `tasks`.

| Field | Required content |
| --- | --- |
| `basis` | `synthetic` or `observed`; every task must repeat the same value. Unit fixtures are synthetic, never live evidence. |
| `binding.source` | `id`, `version`, `digest`: opaque `SRC-` plus 16 lowercase hexadecimal digits, exact semantic version, and `sha256:` plus 64 lowercase hexadecimal digits. This identifies the reviewed measurement source/export format, not a source-code payload or URL. |
| `binding.host` | `name` (`copilot`, `codex` or `claude`) and exact semantic `version`. No host is invoked or verified. |
| `binding.model` | Exact `id` and exact `version`/snapshot label, each 1-64 lowercase letters, digits, dots or hyphens. Mutable or unresolved labels such as `auto`, `latest`, `default` and `unknown` are rejected. If the exact model/version is not established, do not present an observed binding as established. |
| `binding.candidate` | Full 40- or 64-character lowercase hexadecimal `revision` and a reviewed candidate artifact `digest` in `sha256:` form. Branch names, URLs and paths are not candidate bindings. |
| `tasks` | Nonempty array containing every included task, including failed, cancelled and incomplete tasks. There is no success-only filter. |

Source and host semantic versions use three numeric components, each at most
four digits, with an optional bounded lowercase prerelease label. Identifiers
are opaque: do not substitute usernames, repository names, emails or account
identifiers. Closed fields and syntax checks are not a general secret scanner;
the supplier must review the data before passing it to the helper.

Each task has these fields:

| Field | Contract |
| --- | --- |
| `id` | `TASK-` plus 16 lowercase hexadecimal digits; unique in the file. |
| `basis` | Must equal the root basis. Synthetic and observed records cannot be combined. |
| `outcome` | `completed`, `failed`, `cancelled` or `incomplete`. This is a supplied outcome, not an independently verified quality result. |
| `startedAt`, `stoppedAt` | Optional/null or exact UTC `YYYY-MM-DDTHH:mm:ss.sssZ` timestamps. Start must include the earliest task-associated setup; stop follows all task work, retries and repairs. For an incomplete task, stop is only the observation cutoff, not task completion. |
| `phaseCoverage` | Exactly `setup`, `attempt`, `retry`, `repair`, each `complete`, `partial` or `unknown`. This is an explicit supplier assertion about enumeration, not an inferred property of a nonempty log. |
| `evidence` | Reviewed digest-only reference as described below, covering the task outcome/window/coverage. |
| `segments` | Array of bounded exclusive work intervals. A complete empty phase explicitly asserts no work in that phase; an empty phase with partial/unknown coverage does **not** establish zero usage or cost. |

Each segment has `id` (`SEG-` plus 16 lowercase hexadecimal digits), `phase`,
optional/null `startedAt` and `stoppedAt`, `usage` and `evidence`. Phase is one of
the four coverage keys. There is at most one primary `attempt`; `retry` requires
a primary attempt. A segment is a disjoint interval, not a nested wrapper around
other segments. Setup, retry and repair work must not also be counted inside the
primary attempt.

Known segment windows must fit inside known task boundaries and must not
overlap. Reversed windows, impossible dates and durations over 31 days are
rejected. Unknown segment timing prevents establishing exclusive complete-task
accounting; it is not silently treated as zero-duration work. Timestamp precision
and clock consistency must be reviewed by the supplier; the helper cannot
authenticate clocks or detect omitted work.

Every task and segment evidence reference has exactly `recordId` (`REC-` plus
16 lowercase hexadecimal digits), `digest` (`sha256:` plus 64 lowercase
hexadecimal digits) and `reviewed: true`. Source record IDs cannot be reused,
even under different segment/task IDs or digests. Multiple distinct records may
reference the same reviewed document digest. The helper does not open evidence
documents or verify the review assertion, digest provenance or host authenticity.
Evidence must not be pasted into this file as prompts, source, credentials,
URLs, paths, raw output or free-form annotations.

### Usage and monetary observations

Each segment's `usage` requires `scope: "exclusive-delta"`. Cumulative counters,
task totals mixed with segment totals, nested retries, shared setup charged to
multiple tasks, or repeated source records are not accepted accounting inputs.
Convert a cumulative measurement into independently reviewed non-overlapping
deltas **before** supplying it; the helper does not guess or subtract counters.
Do not allocate shared overhead speculatively: leave the affected task/phase
coverage unknown until an explicit, nonduplicating measurement is available.

The following usage fields are optional/null or nonnegative safe integers no
greater than 1,000,000,000,000:

| Field | Unit and meaning |
| --- | --- |
| `inputTokens` | All input tokens attributed exclusively to this segment, including cached input counted once. Do not add another cached-token total. |
| `outputTokens` | All generated output tokens attributed exclusively to this segment. |
| `costUsdMicros` | Separately measured monetary cost in millionths of USD. A supplied zero is different from missing cost. No currency conversion is performed. |
| `inputUsdMicrosPerMillion` | Supplied applicable input-token price in millionths of USD per million input tokens, or unknown. |
| `outputUsdMicrosPerMillion` | Supplied applicable output-token price in millionths of USD per million output tokens, or unknown. |

Fractional, negative, nonfinite and unsafe values are rejected, not rounded.
If caching, credits, tiered rates or other billing rules make a single rate
unknown or inapplicable, leave it null. Prices are reported with coverage counts,
never summed or used to infer a monetary cost. Known tokens plus known prices
do not establish a bill; known monetary cost does not establish a price.
Unknown costs or subscription billing allocations must remain unknown.

## Reading the report

The output preserves the exact basis, binding, task outcomes, evidence
references and per-segment observations. A file report also includes the SHA-256
of the actual input bytes. It has no generated timestamp or live lookup, so the
same file produces the same output. Changing whitespace changes the input-byte
digest; it does not change the arithmetic.

`fullTaskWallMs` is available only for terminal tasks with complete phase
coverage and known, bounded, nonoverlapping segment/task windows. It measures
the **whole task window**, not just the main attempt or a sum of segments:
setup, retries, repairs, waiting and gaps remain included. `observedWindowMs`
retains known observation windows even for incomplete tasks. Aggregate window
values are sums across task observations, not elapsed batch duration when
independent tasks run concurrently.

Every additive metric has `total`, `knownSubtotal`, `knownCount`, `unknownCount`
and `scopeComplete`. **A subtotal of known records is never presented as a
complete total.** Missing values keep `total: null`; incomplete enumeration,
unknown exclusivity or an incomplete task also prevent a full-task usage/cost
total. Coverage separately counts incomplete task scopes, unknown task/segment
windows and complete/partial/unknown coverage for each phase. Unknown omitted
segments cannot be assigned a fabricated missing-record count. Their incomplete
scope is reported explicitly even when every enumerated value is known.

Per-phase reports separate setup, primary attempts, retries and repairs.
Population counts retain all four outcomes. There are no inferred prices,
known-only averages labeled as totals, improvement percentages, matched-pair
claims, minimum-sample waivers, benchmark thresholds or passing flags. A single
synthetic task is still synthetic descriptive data.

## Future real trials

Real trials require separate human approval of host/model use, effects,
privacy, billing limits, candidate versions and measurement scope. This helper
grants none of those permissions. An approved trial's operator would collect
and sanitize its observations externally, bind every task to the exact candidate
and host/model/source versions, review digest-only evidence references, mark
missing measurements and overhead coverage honestly, and supply a file with
`basis: "observed"`. Do not relabel unit fixtures to fill missing live evidence.

The report still says `supplied-observations-not-authenticated` and retains
`comparison: "not-performed"`, `benchmark: "not-assessed"`,
`hostQualification: "not-established"`, `releaseQualification: "not-established"`
and `authority: "none"`. Matching, sampling, semantic correctness and comparative
effectiveness need separately designed, approved evaluation. No live benchmark
or semantic-effectiveness result is supplied by this workstream.
