---
title: Architecture
---

# Architecture

SweepX centers shared protocols and safety types while keeping the runnable read-only path separate from the mutation model that still exists only as library simulation.

## Current data flow

```text
absolute roots
  -> platform backend
  -> scanner + model aggregates/boundaries
  -> Core output envelope
  -> bounded human table | explicit JSON
  -> optional in-process file-manager TUI
  -> Linux bounded SQLite journal + terminal snapshot (unless scan --no-state)
  -> macOS legacy terminal snapshot (unless scan --no-state)
  -> Windows no durable state (state_dir defaults to None)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation
```

Linux, macOS, and Windows connect real development-grade/degraded read-only scanner backends. macOS traversal is handle-bound and Windows traversal is handle-relative; all three are exposed through `sweepx scan` / `scan --tui`.

## Crate responsibilities

| Layer | Representative crates | Current responsibility |
|---|---|---|
| Model and protocol | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | Tagged evidence, stable envelopes/canonical digests, bilingual rendering |
| Platform and scan | `sweepx-platform*`, `sweepx-scanner`, `sweepx-cache`, `sweepx-event-journal` | Platform boundaries and read-only traversal/aggregation on all three platforms; the Linux bounded SQLite journal; the macOS legacy snapshot |
| Analysis and Cleaner | `sweepx-analysis`, `sweepx-cleaner-*`, `sweepx-catalog` | Candidates/explanations, declarative rules, built-in packages |
| User surfaces | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | Command orchestration, human/machine output, bounded read-only views |
| P3 simulated safety | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | Immutable binding, durable audit/recovery, sealed fake execution |

## State and cancellation

CLI scan completes synchronously. On Linux, events are constructed as a batch after scanning, then the complete stream and terminal snapshot are committed to a bounded SQLite journal in one transaction; Core `status` is journal-first. The event-journal crate retains a Linux-test-only bounded cursor replay/reset substrate that is not wired into Core or the CLI. macOS still writes the legacy operation snapshot. `scan --no-state` skips the corresponding operation-state writes for read-only scans that do not need later status/operation state or whose state filesystem does not support the journal, and it conflicts with `--state-dir`. Windows durable state is disabled: `state_dir` defaults to `None`, and explicit `--state-dir` fails closed. There is no live sink, runtime qualification, or public `status --watch`/NDJSON surface; live cancellation also remains disabled. `cancel` returns an honest disposition, which is why its capability is disabled.

## Import is an explicit trust boundary

Core does not preserve live authority merely because scan JSON uses the project schema. After parsing, entry/aggregate provenance becomes stale preview and coverage becomes incomplete/not revalidated. Analyzer may explain it but cannot promote it to an executable candidate. The current TUI does not import that JSON; it browses the typed summary from the current live scan.

## Why P3 is not a real executor

The P3 library layering deliberately leaves nowhere to plug in native mutation:

- a canonical digest freezes plan content;
- authorization binds the exact plan and action set;
- the audit store owns durable claims, intents, outcomes, and reconciliation;
- permits and the revalidation observer are simulation-specific;
- executor requests contain no native path;
- the adapter trait is sealed and its only implementation is deterministic and fake.
- audit persistence is currently Unix-only; the separate Linux scan event-state path has a bounded SQLite journal and one-transaction complete-stream/terminal persistence. The event-journal crate replay/reset substrate is Linux-test-only and not wired into Core or the CLI; this is not live, public, cross-platform, runtime-qualified native-mutation storage.

That supports state-machine and crash-semantics tests without deleting a target. The audit library performs filesystem I/O for its own state files; that is not mutation of scanned targets.

## Future architecture direction

The complete roadmap lifecycle remains:

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

The public surface currently covers the first two steps and read-only views. P3 simulates later states inside libraries. Native platform actions, an approval broker, and CLI wiring are not implemented.
