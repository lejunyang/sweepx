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
for the scan root and entry to a complete `parentReopenRecipe` chain. The root itself has an empty
recipe; every child recipe starts with the scan-root component and proceeds in ancestor order through
the immediate parent. Legacy or imported records may omit the block, but consumers must never
rebuild it from `displayPath`. JSON Schema validates every component's `scan-entry:v1` shape, native
name encoding, and root-versus-child recipe cardinality. Consumers must also verify component order,
locator IDs, native basenames, and the final parent against the entry's validated identity.
