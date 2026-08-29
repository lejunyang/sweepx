---
title: Introduction
---

# Introduction

SweepX is a safety-first Rust disk-analysis project. The current repository has a runnable development-grade scanner/TUI plus an explicitly confirmed, live-revalidated operating-system Trash preview. Permanent deletion still does not exist.

> [!WARNING]
> The only real mutation is the single-item Trash preview. There is no Permanent adapter and no `plan`, `approve`, or `execute` CLI. Trash failure never falls back to permanent deletion.

## Current status

- The Linux scanner performs a synchronous, read-only scan under user-selected absolute roots and reports `degraded`.
- The macOS scanner now exposes a handle-bound synchronous, read-only live scan and still reports only `degraded`, not release qualification.
- The Windows scanner now provides a handle-relative synchronous read-only live scan through `scan` / `scan --tui`. It remains development-grade/degraded, not release-qualified.
- On Linux, `status` reads terminal state journal-first; macOS reads the legacy operation snapshot. Windows durable state is disabled: `state_dir` defaults to `None`, no terminal snapshot is persisted, and explicit `--state-dir` fails closed. `cancel` remains `disabled` because there is no live operation registry.
- Linux has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, and degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`: it performs one same-snapshot full validation, then reads pages of at most 1024 events from a completed, persisted stream; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, this is not live streaming, does not wait for new events, does not create a background operation, and does not support cancel; current machine scan output therefore stays JSON and `scan --format ndjson` remains disabled.
- `explain` analyzes bounded `scan.result` JSON, but imported data is downgraded to stale/incomplete provenance and candidates remain report-only.
- `cache status` provides read-only preview-cache diagnostics on Linux and macOS, with output kind `cache.status.result`; Windows is currently disabled. It supports human/JSON only, treats NDJSON as a usage error, and returns `absent` without creating directories when state/cache is missing. Inspection is bounded to `preview-cache/current.json`, the current generation file, and the flat `generations/` / `quarantine/` directories, reporting approximate bytes and health only; it does not scan, repair, quarantine, or reveal cached entries or path contents. `available` means only that bounded cache structure and validation are readable, not that any live/current filesystem fact is true.
- Built-in Cleaners support metadata-only list/show and fail closed on Core-version incompatibility.
- `sweepx scan --tui` opens a file-manager-style browser in the same binary after scanning. It enters and leaves directories without an intermediate JSON file, and `d`/`Delete` selects one item for Trash. Confirmation happens after leaving the full-screen view, followed by live scan-identity revalidation. Directory detail rescans remain single-flight and deadline-bounded.
- P3 implements immutable plans, simulation-only authorization, Unix audit/recovery, and a sealed deterministic simulated executor as library APIs. Even with degraded Linux completed-stream replay, the overall journal path is neither live, runtime-qualified, nor cross-platform, and there is still no trusted HumanApproval broker.

Those are code- and test-backed development capabilities. The repository now has cross-platform archives, installers, and release automation, but no stable release, production support, or three-platform scan qualification.

## Product position

SweepX sits between a general disk analyzer and an application-specific Cleaner:

- The Scanner answers where visible space is while preserving permission errors, links, mount boundaries, and size uncertainty.
- The Analyzer separates facts, inferences, heuristics, and unknowns instead of treating a directory name or age as proof of safe deletion.
- A Cleaner carries domain knowledge in a versioned manifest and declarative rules. The current surface reports metadata and runs no script.
- CLI, TUI, and future Agent workflows share one Core contract; no surface receives extra mutation authority.

## Why “development-grade” matters

`degraded`, `qualified`, `report_only`, `unsupported`, and `disabled` describe capability cells, not marketing tiers. For example:

- Linux scan exists but has not met every roadmap benchmark, fault-injection, and cross-platform release gate.
- Explain and TUI work within their contract tests, but imported JSON cannot become live execution evidence.
- Cleaner metadata being readable does not mean a Cleaner can execute.
- Tests around a P3 fake executor prove nothing about a real filesystem adapter.

## Suggested reading order

1. [CLI and read-only scanning](/en/cli) for the commands that exist today.
2. [Safety model](/en/safety) for imported/report-only and mutation boundaries.
3. [Cleaner concepts](/en/cleaners) and [Agent boundaries](/en/agents) for the two commonly misunderstood extension surfaces.
4. [Architecture](/en/architecture) and [Roadmap](/en/roadmap) for crate layers and the next gates.
