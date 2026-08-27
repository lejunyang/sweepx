# SweepX Schemas

This directory contains the P0 contract baseline for SweepX:

- `sweepx.output/v1`: bounded command result envelope, including the strict output-only
  `plan.result` review projection
- `sweepx.event/v1`: bounded event envelope plus a separate durable-stream validator
- `sweepx.capability-record/v1`: capability qualification record
- `sweepx.fixture-manifest/v1`: deterministic fixture input contract
- `sweepx.receipt/v1`: deterministic creation and verification receipt
- `sweepx.policy.state-transitions/v1`: executable state-transition policy contract
- `common.v1.schema.json`: shared tagged values, states, phases, and message definitions

Examples live under `schemas/examples/`.

Deterministic fixture contracts live under `fixtures/contracts/`.

The executable transition policy artifact lives at `policy/state-transitions.json`.

## Validation

This package uses Bun and AJV.

Install dependencies with:

```sh
/data00/home/lejunyang/.bun/bin/bun install
```

Run validation with:

```sh
/data00/home/lejunyang/.bun/bin/bun run validate
```

The validation script checks:

- example output envelope
- exact `status.result.data` and `cancel.result.data` branches, including positive examples and rejection of unknown or disposition-inconsistent fields
- exact `plan.result.data` review-only branch, including rejection of unknown fields, authority-shaped fields, translated machine enums, and numeric/leading-zero counts
- live `scan.result` entry identity, native locator lineage, and directory-aggregate identity structure
- legacy imported scan entries without identity or native locator, which remain readable but untrusted
- malformed or path-derived values cannot enter trusted `scan-entry:v1` IDs or lossless native-name components
- example event envelope and the durable NDJSON stream golden
- event conditional negatives (`terminal` iff `operation.terminal`, strict durable terminal payload)
- non-zero contiguous stream sequence, stable stream/operation identity, started-first and one
  terminal-last semantics
- durable checkpoint history, opaque `sxcur1` cursors, monotonic times, bounded IDs/cursors/payloads,
  and terminal status/exit/kind/snapshot-digest consistency
- example capability record
- deterministic minimal fixture manifest
- deterministic expected receipt
- executable transition policy

P0 keeps the contracts additive-friendly, but strict enough to reject state, enum, and invariant drift in the core safety model.

The event JSON Schema validates one bounded envelope. It intentionally continues to accept the
legacy cursor used by the current in-memory scan-event builder; this does not enable the NDJSON
capability. Before an event can enter or leave a durable replay journal, consumers must also run
the durable-stream validator. That validator requires an opaque `sxcur1.<token>` cursor, sequence
starting at one with no gaps, one stream and operation identity, a durable `operation.started`
first, and exactly one durable `operation.terminal` last. Non-durable events repeat the preceding
`lastDurableSequence`; durable events checkpoint their own sequence. Wall-clock timestamps are
RFC 3339 UTC and nondecreasing, while `monotonicOffsetNs` must not regress.

`operation.terminal` has an exact payload of `status`, `exitCode`, `kind`, and the lowercase
SHA-256 `snapshotDigest`. The Rust and JavaScript stream validators compare those fields with the
owner-supplied final snapshot facts and reject an exit code weaker than the status. JSON Schema
cannot compare sequence/checkpoint values, serialized payload byte length, or terminal facts with
an external snapshot, so those remain mandatory semantic-validator checks. At-least-once transport
duplicates must be byte/semantic-identical and deduplicated by `(streamId, sequence)` before the
canonical stream validator runs.

`plan.result.data` uses `schema=sweepx.plan-review/v1` and is a presentation projection only. It
always says `reviewOnly=true`, `approvalState=not_granted`, and
`executionState=not_authorized`. It is never accepted as a canonical plan, approval record,
execution authorization, or permit; `planId` can only be used to ask Core for its separately
persisted immutable plan. Byte/count fields are decimal strings, protocol enums and reason codes
are never translated, and all review objects reject unknown fields.

`ScannedEntry.identity` is present on new live scanner output and may be absent only for legacy or
imported records. A `DirectoryAggregate.directoryIdentity` matching `scan-entry:v1` is the current
trusted shape. Non-prefixed strings are accepted solely for legacy wire compatibility and must not
be treated as identity or synthesized from `displayPath`. Cross-field scan membership (the encoded
scan component matching `scanId`) remains a consumer validation requirement because JSON Schema
cannot decode and compare the base64url component.

New live entries also include `ScannedEntry.nativeLocator`. It binds lossless native-name components
for the scan root and entry to a complete `parentReopenRecipe` chain, and carries the exact admitted
root in `scanRootAbsolutePath` as tagged Unix bytes or Windows UTF-16LE. The decoded absolute root is
bounded to 64 KiB, rejects NUL and Windows namespace forms, and must match the executing platform.
The root itself has no `parentId` and an empty recipe; every non-root component carries its direct
`parentId`, and every child recipe starts with the scan-root component and proceeds through a
contiguous ancestor chain to the immediate parent. Legacy or imported v1 records may omit the
whole block or only `scanRootAbsolutePath`; both remain viewable, but missing or foreign-platform
absolute-root evidence is never execution-eligible and must never be reconstructed from
`displayPath`. JSON Schema validates component shapes and wire encoding. Consumers must additionally
verify canonical decoding, absolute-path grammar, component order and parent links, locator IDs,
native basenames, the final parent, and current-platform compatibility before execution. Every
root, ancestor, parent, and target component must have known object, filesystem-domain, and
mount/volume identity evidence plus a non-empty metadata fingerprint before it is executable.
