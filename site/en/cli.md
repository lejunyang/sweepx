---
title: CLI and read-only scanning
---

# CLI and read-only scanning

The current `sweepx` binary is a runnable development-grade read-only CLI. It exposes `scan`, `explain`, `status`, `cancel`, `cleaner`, `tui`, and `capabilities`; it exposes no mutation subcommand.

> [!CAUTION]
> `plan`, `approve`, `execute`, Trash, Permanent, and `--dangerously-delete` are not part of the current CLI. Treat those names as roadmap proposals wherever they appear.

## Build and inspect capabilities

Run from the repository root:

```bash
cargo build -p sweepx-cli -p sweepx-tui
cargo run -p sweepx-cli -- --locale en-US capabilities
```

Global options:

| Option | Meaning |
|---|---|
| `--format human|json|ndjson` | Select display or machine output; default is `human` |
| `--locale zh-CN|en-US` | Override the auto-detected display locale |
| `--state-dir ABSOLUTE_DIR` | Select durable snapshot storage for scan/status/cancel |

Locale resolution considers the explicit override, locale environment, and system locale; an unrecognized result falls back to `en-US`. Machine keys and values are not translated.

## Read-only Linux scan

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  scan /absolute/path/to/root > /absolute/path/to/scan.json
```

- You may provide multiple roots, but every root must be absolute.
- The scan runs synchronously, is metadata-only and no-follow, and reports mount/link/resource boundaries and errors.
- The current Linux capability is `degraded`, not release qualification.
- macOS and Windows backends are unsupported stubs; compilation is not scanning support.
- `ndjson` emits an event stream ending in a terminal event; it does not imply a background daemon.

## Status snapshots and cancellation

After reading `operationId` from scan output:

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cancel --operation-id <OPERATION_ID>
```

`status` only reads a persisted snapshot. There is no live in-process registry, so output reports `canCancel: false` and cancellation capability is `disabled`. The cancel command exists to distinguish `not_found`, `already_terminal`, and `unsupported` honestly, not to pretend it can interrupt the synchronous scan.

## Explain from scan JSON

```bash
cargo run -p sweepx-cli -- \
  --format json \
  explain \
  --scan-json /absolute/path/to/scan.json \
  --candidate-id <OPTIONAL_CANDIDATE_ID> \
  --max-input-bytes 8388608
```

Input must be an absolute path, conform to the `scan.result` contract, and stay within the byte limit. On import, Core:

1. changes provenance to stale preview;
2. marks coverage incomplete/not revalidated;
3. produces an explanation while forcing the candidate non-executable/report-only.

The result is useful for understanding, not for planning or execution.

## Cleaner metadata

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show org.sweepx.cargo-target
```

`list` reports packages and compatibility. `show` exposes full manifest/rule metadata only when the Core version range matches; incompatibility uses a dedicated fail-closed exit. Neither command performs a file action described by a rule. See [Cleaner concepts](/en/cleaners).

## Bounded read-only TUI

The CLI can validate input and pagination first:

```bash
cargo run -p sweepx-cli -- \
  --format json \
  tui \
  --scan-json /absolute/path/to/scan.json \
  --page-index 0 \
  --max-input-bytes 8388608 \
  --max-total-rows 100000
```

The separate binary provides the interactive view:

```bash
cargo run -p sweepx-tui -- /absolute/path/to/scan.json --locale en-US
```

Keys include `Tab` / `Shift-Tab` for panes, arrows or `j`/`k` for rows, `PageUp`/`PageDown` for pages, and `q` to quit. Its action type contains navigation only and is marked non-destructive in code.

## Commands that do not exist today

```text
PROPOSED ONLY — NOT IMPLEMENTED
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

P3 has library models and fake-execution tests for related concepts, but no CLI wiring and no native filesystem mutation.
