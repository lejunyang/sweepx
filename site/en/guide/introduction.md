---
title: Introduction
---

# Introduction

SweepX is a safety-first Rust disk-analysis project. The current repository has a runnable development-grade read-only CLI/TUI; it is no longer documentation-only. At the same time, it has no real cleanup capability.

> [!WARNING]
> “Runnable” applies only to read-only or simulated surfaces. There is no native Trash or Permanent adapter, no `plan`, `approve`, or `execute` CLI, and no adapter that deletes or moves target files.

## Current status

- The Linux scanner performs a synchronous, read-only scan under user-selected absolute roots and reports `degraded`.
- The macOS scanner now exposes a handle-bound synchronous, read-only live scan and still reports only `degraded`, not release qualification.
- The Windows scanner now provides a handle-relative synchronous read-only live scan through `scan` / `scan --tui`. It remains development-grade/degraded, not release-qualified.
- On Unix, `status` reads a persisted terminal snapshot. Windows durable state is disabled: `state_dir` defaults to `None`, no terminal snapshot is persisted, and explicit `--state-dir` fails closed. `cancel` remains `disabled` because there is no live operation registry.
- The protocol layer now has durable event envelope/stream validators, opaque durable-cursor constraints, and schema/golden coverage; SQLite journaling/replay and atomic terminal persistence are still incomplete, so scan NDJSON remains disabled and current machine output stays JSON.
- `explain` analyzes bounded `scan.result` JSON, but imported data is downgraded to stale/incomplete provenance and candidates remain report-only.
- Built-in Cleaners support metadata-only list/show and fail closed on Core-version incompatibility.
- `sweepx scan --tui` opens a file-manager-style, read-only browser in the same binary after scanning. It enters and leaves directories without an intermediate JSON file. Directory detail rescans now run as a single-flight background task with a 2 s deadline; navigation and quit do not wait for a non-cooperative worker, late completions are discarded, and a process-wide cap of 32 bounds stuck workers.
- P3 implements immutable plans, simulation-only authorization, Unix audit/recovery, and a sealed deterministic simulated executor as library APIs. Durable event validation and schema/golden coverage now exist at the protocol layer, while SQLite journaling/replay and atomic terminal persistence remain incomplete; there is still no trusted HumanApproval broker.

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
