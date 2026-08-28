# SweepX implementation handoff

Updated: 2026-08-27
Branch: `main`

## Product constraints

- Keep one executable entry point: `sweepx`; enter the interactive browser with `sweepx scan --tui`.
- Human-readable terminal output is the default. JSON and NDJSON are explicit machine formats.
- CLI output supports `zh-CN` and `en-US`, auto-detects the environment, and accepts `--locale`. Stable machine keys and enums are never translated.
- Documentation lives in `site/` and uses VitePress with Bun.
- Binary and crates.io publication require literal `[publish]` in the HEAD commit message. crates.io uses `CARGO_REGISTRY_TOKEN`; GitHub Releases and Pages use `GITHUB_TOKEN`.
- Work directly on `main`. Keep coherent agent-authored milestones atomic and include exactly one trailer: `Co-authored-by: TRAE CLI <noreply@bytedance.com>`.
- Native mutation remains disabled unless OS Trash is proven. Never fall back from Trash failure to Permanent deletion. Human approval work stays last.
- `displayPath` is never authority.

## Implemented baseline

- Single `sweepx` CLI with human/JSON output, locale detection/override, and interactive file-manager-style TUI navigation.
- Read-only scanners and bounded caches across Linux, macOS, and Windows, with platform-specific handle-bound/handle-relative safety checks.
- Bounded locator file reads and typed Cargo evidence for `cleaner cargo-detect`; the public detector remains hint/report-only and cannot plan, approve, or execute.
- Linux bounded SQLite event journal with one-transaction complete-stream plus terminal-snapshot persistence.
- CI, Pages, `[publish]`-gated binary/crates publication, install scripts, and bilingual VitePress site are present.

## Current milestone: Linux completed-stream replay

This milestone is committed in `1483246` (`feat(status): replay completed Linux journals`), with replay contract cleanup in `b2e93bd` (`fix(status): tighten replay contracts`) and the matching documentation record in `d4a90bb` (`docs: record completed journal replay milestone`). It adds:

```text
sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1_CURSOR]
```

Exact boundaries:

- Linux only. It replays an already-completed, persisted journal stream.
- It is not a live scan stream, does not wait for new events, does not create a background operation, and does not enable cancellation.
- `scan --format ndjson` remains disabled before scan/root/state admission.
- Journal replay opens existing state without creating missing state roots or legacy directories.
- A replay session performs one complete verification inside one SQLite read transaction, then freezes events, cursor index, integrity facts, and final snapshot.
- Owned replay is emitted in pages of at most 1024 events without cloning event payloads.
- Valid known cursor resumes strictly after that event. The terminal cursor yields empty output.
- A malformed cursor is usage error/exit 2. A syntactically valid unknown cursor emits one separate non-durable `stream.reset_required` delivery-control event with `requestedCursor`, `availableFromSequence=1`, `snapshotRef.operationId`, and the journal high-water `resumeAfter`.
- Missing operation is exit 8; legacy-snapshot-only replay is unsupported/exit 3; journal corruption is fail-closed with empty stdout/exit 11.
- Normal replay exits with the frozen terminal exit code; reset delivery exits 0.
- Capability `operation.event.completed_replay` is degraded on Linux and disabled on macOS/Windows. `scan.ndjson.stream` remains disabled with the live-sink-unqualified reason.
- Replay admission has a conservative 192 MiB decoded-memory estimate aligned across append and replay; it is not an allocator-exact RSS measurement.

## Verification for the current milestone

- `cargo test --workspace --all-targets --all-features --locked` passes.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` passes.
- Windows GNU checks and Clippy pass for protocol, event-journal, Core, and CLI.
- `cargo fmt --all -- --check`, docs lint, and `git diff --check` pass.
- VitePress site build passes with `/data00/home/lejunyang/.bun/bin/bun run docs:build` from `site/`.
- macOS cross-check remains blocked on this Linux host because the host C compiler rejects Apple `-arch` and `-mmacosx-version-min` flags while compiling bundled SQLite; this is a toolchain/environment limitation.

## Next work

The replay implementation and documentation are committed through `b2e93bd`. The next active non-human-approval read-only milestone is an independent `sweepx cache status` preview-cache diagnostics surface. The cache crate now has an uncommitted inspection API that must be reviewed and wired into Core/CLI. It should inspect existing cache state without creating, repairing, quarantining, or scanning anything, and report bounded stable facts such as current generation, generation/quarantine counts, approximate state bytes, schema/current-pointer health, and warnings. A second candidate is Cargo config-scope closure; keep it behind typed evidence and report-only behavior until global/ancestor/env overrides can be proven absent. Keep all mutation capability cells disabled.
