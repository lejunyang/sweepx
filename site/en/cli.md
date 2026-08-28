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
| `--format human|json|ndjson` | Select display or machine output; default is `human`; scan currently rejects `ndjson` |
| `--locale zh-CN|en-US` | Override the auto-detected display locale |
| `--state-dir ABSOLUTE_DIR` | Select the SQLite journal directory on Linux or legacy snapshot directory on macOS; Windows durable state is disabled, `state_dir` defaults to `None`, and explicitly setting it fails closed |
| `scan --no-state` | Skip Linux journal or macOS legacy-snapshot writes when later status/operation state is unnecessary or the state filesystem does not support the journal; conflicts with `--state-dir` |

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

## Development-grade read-only scans on all three platforms

```bash
cargo run -p sweepx-cli -- scan /absolute/path/to/root
# Explicitly skip writes when later operation state is unnecessary
cargo run -p sweepx-cli -- scan --no-state /absolute/path/to/root
```

- You may provide multiple roots, but every root must be absolute.
- The default writes a bounded 40-row file table directly to the terminal; no JSON file is required.
- The scan runs synchronously, is metadata-only and no-follow, and reports mount/link/resource boundaries and errors.
- The current Linux capability is `degraded`, not release qualification.
- The macOS backend now exposes a handle-bound degraded scanner through the same `scan` / `scan --tui` path; that is not release qualification.
- The Windows backend now provides a handle-relative degraded read-only scanner through `scan` / `scan --tui`; that is not release qualification.
- Linux may explicitly select a SQLite journal directory; macOS may select a legacy snapshot directory; do not pass `--state-dir` on Windows.
- `scan --format ndjson` currently returns unsupported before scanning. Linux has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, journal-first status, and degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`: it performs one same-snapshot full validation, then reads pages of at most 1024 events from a completed, persisted stream; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, that replay is not live streaming, does not wait for new events, does not create a background operation, and does not support cancel, so `scan --format ndjson` remains disabled.

Request machine output explicitly for scripts and integrations:

```bash
sweepx --format json scan /absolute/path/to/root > scan.json
# Currently returns unsupported; it does not scan
sweepx --format ndjson scan /absolute/path/to/root
```

## Status snapshots and cancellation

On Linux or macOS, after reading `operationId` from scan output, the corresponding terminal snapshot can be queried:

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID>

cargo run -p sweepx-cli -- \
  --format ndjson \
  --state-dir /absolute/path/to/sweepx-state \
  status --operation-id <OPERATION_ID> --watch [--after SXCUR1_CURSOR]

cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cancel --operation-id <OPERATION_ID>
```

`status` reads persisted terminal state journal-first on Linux and supports degraded completed replay through `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1]`: it covers only completed, persisted streams, performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. It does not wait for new events, does not create a background operation, and does not support cancel, so it is not live progress. macOS reads from the legacy snapshot and still has no replay/watch surface. On Windows, `state_dir` defaults to `None`, scan persists no terminal snapshot, and explicit `--state-dir` fails closed. There is no live in-process registry, so output reports `canCancel: false` and cancellation remains `disabled`. The cancel command exists to distinguish `not_found`, `already_terminal`, and `unsupported` honestly, not to pretend it can interrupt the synchronous scan.

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

`--tui` requires terminal stdin and stdout and cannot be combined with `--format json|ndjson`. Those conditions are checked before state creation or scanning. Windows creates no default state and rejects explicit `--state-dir`. Untrusted terminal control characters are replaced instead of being emitted as raw ANSI sequences. Directory detail rescans run as a single-flight background task with a 2 s query deadline; navigation or quit does not wait for a non-cooperative worker, late results are discarded, and a process-wide cap of 32 bounds stuck workers.

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
