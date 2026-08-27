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
- live `scan.result` entry identity and directory-aggregate identity structure
- legacy imported scan entries without identity, which remain readable but untrusted
- malformed or path-derived values cannot enter the trusted `scan-entry:v1` identity branch
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
