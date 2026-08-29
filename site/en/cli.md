---
title: CLI and read-only scanning
---

# CLI and read-only scanning

The current `sweepx` binary is the sole executable entry point. It exposes `scan`, `junk`, `explain`, `status`, `cancel`, `cache`, `cleaner`, `trash`, and `capabilities`; `scan --tui` enters after root admission and scans progressively in the background.

> [!CAUTION]
> `trash` is a development preview: it only moves an item to the operating-system Trash, confirms by default, and revalidates before submission. It never falls back to Permanent deletion. `plan`, `approve`, `execute`, Permanent, and `--dangerously-delete` remain roadmap proposals.

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
| `--unit auto|b|kib|mib|gib|tib` | Human/TUI size unit; `kb/mb/gb/tb` are accepted aliases |
| `--sort size|path` | Human/TUI ordering; size descending by default |
| `--state-dir ABSOLUTE_DIR` | Select the SQLite journal directory on Linux or legacy snapshot directory on macOS; Windows durable state is disabled, `state_dir` defaults to `None`, and explicitly setting it fails closed |
| `scan --no-state` | Skip Linux journal or macOS legacy-snapshot writes when later status/operation state is unnecessary or the state filesystem does not support the journal; conflicts with `--state-dir` |

Locale resolution considers the explicit override, locale environment, and system locale; an unrecognized result falls back to `en-US`. Machine keys and values are not translated.

### P4a.2 qualification records are not a new command

The protocol can now express one exact capability/platform tuple and its evidence as a typed, validated record. Mutation does not use a broad delete flag: it is split into `trash.local.file`, `trash.local.directory`, `permanent.local.file`, `permanent.local.directory`, and `permanent.local.link`. The current host's two Trash cells are reported as a `degraded` preview; other platforms and every Permanent cell remain `disabled`.

These records remain a fail-closed qualification-registry substrate; a `degraded` preview is not `qualified`. `fixture_conformance_only`, `fake`, `stale`, `incomplete`, `placeholder`, or `mismatched` evidence can never qualify mutation. A cell could become `qualified` later only if current `real_os_qualification` evidence completely matches its exact tuple. There is still no plan/approval UI or Permanent adapter.

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

- With no roots, `scan` selects the current platform filesystem root; you may instead provide relative paths, `~`, or one or more absolute roots.
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

## Read-only preview-cache diagnostics

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cache status
```

- Linux and macOS support `cache status`; Windows currently returns unsupported.
- It supports `human` and `json` only; `--format ndjson` fails with a usage error before any state/cache directory is created or read.
- If default or explicit state/cache is missing, the result returns `disposition=absent` with exit 0 and does not create `state_dir`, `preview-cache/`, `current.json`, or any generation/quarantine directory.
- Inspection is strictly bounded to `preview-cache/current.json`, the pointer-selected current generation file, and the flat `generations/` and `quarantine/` directories.
- The output kind is `cache.status.result`, reporting `exists`, `currentGeneration`, `generationCount`, `quarantineCount`, `approxBytes`, `approxBytesComplete`, `storedSchema`, `currentHealth`, `schemaHealth`, and typed `warnings[]` / `errors[]`.
- The command does not trigger a scan, repair, quarantine, rebuild, or reveal cached entries, display paths, preview contents, or live filesystem facts.
- `available` means only that bounded cache structure and validation are readable; any warning, error, or quarantine presence degrades the result to exit 4.

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

A unified junk-discovery entry point is available:

```bash
sweepx junk ~/Projects
sweepx --format json junk .
sweepx --format json junk --system
```

Explicit roots continue to discover clearly rebuildable project artifacts: Rust `target`, Node `node_modules`, Python `__pycache__/.pytest_cache/.mypy_cache/.ruff_cache`, and common `dist/build/out/.next/.turbo` outputs. With no explicit root, `--system` reports individual application-cache children below an absolute `XDG_CACHE_HOME` (or `~/.cache`) on Linux and `~/Library/Caches` on macOS; on Windows it admits only depth-2 `LocalCache` / `TempState` directories below `%LOCALAPPDATA%/Packages`. `--system` conflicts with explicit roots. Every result remains report-only and includes the rule ID, risk, source-review date, first-party references, and reclaimable estimate; Linux `/tmp`/`/var/tmp`, Windows system cleanup, and package-manager/container shared stores are not admitted by directory-name matching.

## File-manager-style TUI and Trash preview

```bash
cargo run -p sweepx-cli -- --locale en-US \
  scan --tui /absolute/path/to/root [/another/absolute/root]
cargo run -p sweepx-cli -- trash /absolute/path/to/item
```

The TUI consumes the typed result of this live scan without an intermediate JSON file. It auto-enters a single root; multiple roots first appear in a virtual-root view. Use `Enter` / `Right` / `l` to enter a directory, `Esc` / `Backspace` / `Left` / `h` to go back, arrows or `j`/`k` to move, `d` / `Delete` to select an item for Trash, and `q` or `Ctrl-C` to quit. Trash exits the full-screen view, asks for confirmation, and revalidates the live scan identity; symlinks and reparse points cannot be mutated.

`--tui` requires terminal stdin and stdout and cannot be combined with `--format json|ndjson`. The TUI enters after root admission and auto-opens a single root. Direct children appear first; while the background scan runs, recursive directory totals are merged and resorted as explicit lower bounds (`>=`) at roughly 120 ms intervals. The final result then converges to exact or explicitly incomplete evidence, without retaining descendants as list rows. A one-slot progress channel drops superseded intermediate snapshots instead of applying terminal backpressure. Detail rescans are single-flight; 30 seconds is a no-progress deadline renewed by valid updates, and navigation or quit does not wait for a non-cooperative worker.

See [MangoDisk adoption decisions](https://github.com/lejunyang/sweepx/blob/main/docs/research/mangodisk-adoption.md) for acceleration findings, rule provenance, the GPL boundary, and the Linux policy.

## Commands that do not exist today

```text
PROPOSED ONLY — NOT IMPLEMENTED
sweepx plan create ...
sweepx plan show ...
sweepx approve ...
sweepx execute ...
sweepx execute ... --dangerously-delete
```

P3 has library models and fake-execution tests for related concepts, but there is still no plan/approve/execute CLI or Permanent mutation.
