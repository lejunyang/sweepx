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
  -> durable terminal snapshot on Unix (optional state directory)
  -> no durable terminal snapshot on Windows (state_dir defaults to None)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation
```

Linux, macOS, and Windows connect real development-grade/degraded read-only scanner backends. macOS traversal is handle-bound and Windows traversal is handle-relative; all three are exposed through `sweepx scan` / `scan --tui`.

## Crate responsibilities

| Layer | Representative crates | Current responsibility |
|---|---|---|
| Model and protocol | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | Tagged evidence, stable envelopes/canonical digests, bilingual rendering |
| Platform and scan | `sweepx-platform*`, `sweepx-scanner`, `sweepx-cache` | Platform boundaries, Linux read-only traversal, macOS handle-bound traversal, Windows handle-relative traversal, aggregation, and Unix-only durable state |
| Analysis and Cleaner | `sweepx-analysis`, `sweepx-cleaner-*`, `sweepx-catalog` | Candidates/explanations, declarative rules, built-in packages |
| User surfaces | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | Command orchestration, human/machine output, bounded read-only views |
| P3 simulated safety | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | Immutable binding, durable audit/recovery, sealed fake execution |

## State and cancellation

CLI scan completes synchronously and saves a terminal snapshot when a state directory is enabled on Unix. Windows durable state is disabled: `state_dir` defaults to `None`, no terminal snapshot is persisted, and explicit `--state-dir` fails closed. `status` is not connected to a background worker; scan NDJSON and live cancellation also remain disabled. `cancel` returns an honest disposition; that is why its capability is disabled.

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
- audit persistence is currently Unix-only; it now uses bundled SQLite WAL atomic transactions plus event replay to manage durable claim, intent, outcome, and reconciliation state. It is still not release-grade native-mutation storage.

That supports state-machine and crash-semantics tests without deleting a target. The audit library performs filesystem I/O for its own state files; that is not mutation of scanned targets.

## Future architecture direction

The complete roadmap lifecycle remains:

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

The public surface currently covers the first two steps and read-only views. P3 simulates later states inside libraries. Native platform actions, an approval broker, and CLI wiring are not implemented.
