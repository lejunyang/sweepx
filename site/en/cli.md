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
| `--state-dir ABSOLUTE_DIR` | Select the SQLite journal directory on Linux or legacy snapshot directory on macOS; Windows defaults to `%LOCALAPPDATA%\sweepx\state`; the directory must be reachable only by the current user or the command fails closed |
| `--elevate` | Windows-only in effect, off by default. If the current process is not elevated, request one UAC consent and relaunch itself elevated before doing anything else; the parent then returns the child's exit code unchanged. An already-elevated process never relaunches; a declined prompt or an unsupported platform continues at the current privilege level without changing scan results. The flag is not forwarded to the relaunched child, so a second elevation is structurally impossible |
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
- Linux may explicitly select a SQLite journal directory; macOS may select a legacy snapshot directory; Windows may select a durable state directory, which must be reachable only by the current user.
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

`status` reads persisted terminal state journal-first on Linux and supports degraded completed replay through `sweepx --format ndjson status --operation-id <OPERATION_ID> --watch [--after SXCUR1]`: it covers only completed, persisted streams, performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. It does not wait for new events, does not create a background operation, and does not support cancel, so it is not live progress. macOS reads from the legacy snapshot and still has no replay/watch surface. On Windows, `state_dir` defaults to `%LOCALAPPDATA%\sweepx\state` and durable snapshots are written there; a state directory reachable by other users fails closed. There is no live in-process registry, so output reports `canCancel: false` and cancellation remains `disabled`. The cancel command exists to distinguish `not_found`, `already_terminal`, and `unsupported` honestly, not to pretend it can interrupt the synchronous scan.

## Read-only preview-cache diagnostics

```bash
cargo run -p sweepx-cli -- \
  --format json \
  --state-dir /absolute/path/to/sweepx-state \
  cache status
```

- Linux, macOS and Windows all support `cache status`.
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

## Windows scan acceleration and privilege

Windows has an accelerated scan path built on native NTFS metadata. Every scan root is qualified read-only before traversal, and **a refusal never affects correctness**: the portable handle-relative traversal stays authoritative and its totals remain exact.

Acceleration needs a `GENERIC_READ` volume handle. Measured on this host on 2026-09-02, against both `C:` and `E:`:

| Requested access | Not elevated | Elevated |
|---|---|---|
| `0` / `FILE_READ_ATTRIBUTES` / `+SYNCHRONIZE` | handle opens, but both FSCTLs return `ERROR_INVALID_FUNCTION (1)` | **identical; still `1`** |
| `GENERIC_READ` | open is refused with `ERROR_ACCESS_DENIED (5)` | open succeeds and `FSCTL_QUERY_USN_JOURNAL` works |

The decisive point is that the lower access levels still report the control codes as absent **even when elevated**. That is not "insufficient rights" but "the function does not exist at that handle level", so there is no reduced-privilege access level to trade down to. Acceleration being unavailable without elevation is a platform property, not an implementation gap.

A refusal appears as one `scan.progress` event carrying `accelerationRefusalReason` (a stable machine code, never localized) and `elevationMightHelp`. Its `coverageEffect` is `observed` rather than `incomplete`: declining an optimization loses no coverage, and an ordinary unelevated scan must not be reported as partial because of it. `elevationMightHelp` is `true` only when privilege is genuinely the cause, so the user is not sent to a UAC prompt that cannot fix the problem — elevation does not help when, for example, the volume is not NTFS.

Pass `--elevate` to request acceleration explicitly; it asks for one UAC consent and relaunches the process elevated. Destructive operations remain hard-refused in an elevated session by design and are not relaxed just because privilege is higher.

When acceleration does qualify, one bulk read of the volume's NTFS metadata produces a **preview** of each scan root, reported in the scan summary under `acceleration`:

```json
"acceleration": {
  "used": true,
  "preview": {
    "entryCount": "37371",
    "logicalBytes": "14812812602",
    "elapsedMicros": "1058065",
    "exact": true,
    "authoritative": false
  }
}
```

A refusal is reported in the same place as `{"used": false, "reason": "not_elevated", "elevationMightHelp": true}`.

Two properties of a preview matter:

- `authoritative` is always `false`. Preview numbers come from a metadata snapshot and carry **no reopen recipe**, which is what a delete revalidates against. They exist so a large tree can show a total quickly; nothing may be removed on their strength, and the traversal's results supersede them.
- `exact` is `false` when any record under the root could not be resolved. The size is then a lower bound and must never be displayed as precise.

Measured on this host on 2026-09-02 against `E:\Projects\sweepx` (14.5 GB, 36,531 objects): the preview completed in **1.06 s** where the full authoritative scan took **133 s**, roughly **126x faster to a first answer**. The authoritative scan itself is not made faster — the preview is additive, and its whole-volume read is a fixed cost of about a second, so it only pays off on large trees.

Preview output is verified against an ordinary directory walk, which reaches the filesystem through a completely different code path; the path set and the summed bytes must match exactly.

### Reusing a preview across runs

A stored preview is only useful if something can say it is still true. When a scan writes a preview
it also records, inside the same generation, the position of each covered volume's NTFS change
journal. The next run re-reads that position: if the volume has not moved, the preview describes
the filesystem as it is now and the scan reports `loadStatus: "verified_preview"` instead of
`stale_preview`.

Verification only ever upgrades a load. No recorded evidence, an unreadable journal, or a volume
that did move all keep the previous behavior and add a warning naming the reason, for example
`cache.preview.unverified.no_evidence`. Reuse also requires *every* covered volume to be unchanged,
because a half-valid preview would show correct sizes for one part of a tree and stale sizes for
another while looking correct.

Reading the journal needs the same elevated volume handle acceleration needs, so an unelevated run
records no evidence and behaves exactly as it did before this existed. Evidence is stored inside the
checksummed generation payload, so editing a token on disk invalidates the whole generation rather
than buying a false "unchanged".

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
