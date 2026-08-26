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
- example event envelope
- example capability record
- deterministic minimal fixture manifest
- deterministic expected receipt
- executable transition policy

P0 keeps the contracts additive-friendly, but strict enough to reject state, enum, and invariant drift in the core safety model.
