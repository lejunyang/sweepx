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
  -> durable terminal snapshot (optional state directory)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation
```

Linux connects a real scanner backend. macOS now exposes a handle-bound degraded scanner through the same `sweepx scan` / `scan --tui` path. Windows remains fail-closed unsupported, so Core returns unsupported scan output there instead of simulating success.

## Crate responsibilities

| Layer | Representative crates | Current responsibility |
|---|---|---|
| Model and protocol | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | Tagged evidence, stable envelopes/canonical digests, bilingual rendering |
| Platform and scan | `sweepx-platform*`, `sweepx-scanner`, `sweepx-cache` | Platform boundaries, Linux/macOS read-only traversal, Windows fail-closed unsupported behavior, aggregation and state |
| Analysis and Cleaner | `sweepx-analysis`, `sweepx-cleaner-*`, `sweepx-catalog` | Candidates/explanations, declarative rules, built-in packages |
| User surfaces | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | Command orchestration, human/machine output, bounded read-only views |
| P3 simulated safety | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | Immutable binding, durable audit/recovery, sealed fake execution |

## State and cancellation

CLI scan currently completes synchronously and saves a terminal snapshot when a state directory is enabled on Unix. Windows durable state fails closed because current-user-private DACL enforcement and reparse-point checks are not implemented. `status` is snapshot lookup, not a connection to a background worker. Scan NDJSON also fails closed until durable journaling and replay exist. `cancel` has no live registry to act on and therefore returns an honest disposition; that is why its capability is disabled.

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
