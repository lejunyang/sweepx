# SweepX Schemas

This directory contains the P0 contract baseline for SweepX:

- `sweepx.output/v1`: bounded command result envelope
- `sweepx.event/v1`: NDJSON event envelope
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
- live `scan.result` entry identity, native locator lineage, and directory-aggregate identity structure
- legacy imported scan entries without identity or native locator, which remain readable but untrusted
- malformed or path-derived values cannot enter trusted `scan-entry:v1` IDs or lossless native-name components
- example event envelope
- example capability record
- deterministic minimal fixture manifest
- deterministic expected receipt
- executable transition policy

P0 keeps the contracts additive-friendly, but strict enough to reject state, enum, and invariant drift in the core safety model.

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
