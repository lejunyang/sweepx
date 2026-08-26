---
title: CLI and read-only scanning
---

# CLI and read-only scanning

The current `sweepx` binary is the sole executable entry point. It exposes `scan`, `explain`, `status`, `cancel`, `cleaner`, and `capabilities`; `scan --tui` enters the interactive browser after scanning. There is no separate TUI command or binary and no mutation subcommand.

> [!CAUTION]
> `plan`, `approve`, `execute`, Trash, Permanent, and `--dangerously-delete` are not part of the current CLI. Treat those names as roadmap proposals wherever they appear.

## Build and inspect capabilities

Run from the repository root:

```bash
cargo build -p sweepx-cli
cargo run -p sweepx-cli -- --locale en-US capabilities
```

Global options:

| Option | Meaning |
|---|---|
| `--format human|json|ndjson` | Select display or machine output; default is `human` |
| `--locale zh-CN|en-US` | Override the auto-detected display locale |
| `--state-dir ABSOLUTE_DIR` | Select durable snapshot storage for scan/status/cancel |

Locale resolution considers the explicit override, locale environment, and system locale; an unrecognized result falls back to `en-US`. Machine keys and values are not translated.

### P4a.2 qualification records are not a new command

The protocol can now express one exact capability/platform tuple and its evidence as a typed, validated record. Mutation does not use a broad delete flag: it is split into `trash.local.file`, `trash.local.directory`, `permanent.local.file`, `permanent.local.directory`, and `permanent.local.link`. All five cells are currently `disabled` on Linux, macOS, and Windows.

These records are only a fail-closed qualification-registry substrate; they give `sweepx capabilities` no mutation authority and add no live registry service. `fixture_conformance_only`, `fake`, `stale`, `incomplete`, `placeholder`, or `mismatched` evidence can never qualify mutation. A cell could become `qualified` later only if current `real_os_qualification` evidence completely matches its exact tuple. No such record, native adapter, mutation command, or approval UI exists today.

## Install

A release produces archives plus one `SHA256SUMS` for Linux x86_64/aarch64, macOS Intel/Apple Silicon, and Windows x86_64. The installers verify the checksum and require the archive to contain only a root-level `sweepx` or `sweepx.exe`.

```bash
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/lejunyang/sweepx/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/lejunyang/sweepx/main/install.ps1 | iex
```

Release infrastructure does not mean a stable release already exists. Check GitHub Releases and `sweepx capabilities` before installing.

Normal pushes and pull requests run Rust, schema, site, installer, and native-CLI CI. GitHub Pages deploys independently when `main` changes. Binary and crates.io publication run only when the HEAD commit message contains the literal `[publish]` marker. GitHub Release and Pages need no extra token; crates.io requires `CARGO_REGISTRY_TOKEN` in a protected `crates-io` environment.

## Read-only Linux scan

```bash
cargo run -p sweepx-cli -- \
  --state-dir /absolute/path/to/sweepx-state \
  scan /absolute/path/to/root
```

- You may provide multiple roots, but every root must be absolute.
- The default writes a bounded 40-row file table directly to the terminal; no JSON file is required.
- The scan runs synchronously, is metadata-only and no-follow, and reports mount/link/resource boundaries and errors.
- The current Linux capability is `degraded`, not release qualification.
- macOS and Windows backends are unsupported stubs; compilation is not scanning support.
- `ndjson` emits an event stream ending in a terminal event; it does not imply a background daemon.

Request machine output explicitly for scripts and integrations:

```bash
sweepx --format json scan /absolute/path/to/root > scan.json
sweepx --format ndjson scan /absolute/path/to/root > events.ndjson
```

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

## File-manager-style read-only TUI

```bash
cargo run -p sweepx-cli -- --locale en-US \
  scan --tui /absolute/path/to/root [/another/absolute/root]
```

The TUI consumes the typed result of this live scan without an intermediate JSON file. It starts with one or more virtual roots. Use `Enter` / `Right` / `l` to enter a directory, `Esc` / `Backspace` / `Left` / `h` to go back, arrows or `j`/`k` to move, and `q` or `Ctrl-C` to quit. Symlinks and reparse points are visible but cannot be entered.

`--tui` requires terminal stdin and stdout and cannot be combined with `--format json|ndjson`. Those conditions are checked before state creation or scanning. Untrusted terminal control characters are replaced instead of being emitted as raw ANSI sequences.

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
