---
title: Architecture
---

# Architecture

SweepX centers shared protocols and safety types while separating runnable scan/preview paths, the narrow Linux bounded file/directory Permanent path, and the general mutation model that still exists only as library simulation.

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
  -> Windows durable state under %LOCALAPPDATA%\sweepx\state (private DACL enforced)

bounded scan.result JSON
  -> imported provenance downgrade
  -> report-only explanation

preview-cache/current.json + current generation + flat generations/quarantine dirs
  -> bounded read-only cache inspection
  -> cache.status.result
```

Linux, macOS, and Windows connect real development-grade/degraded read-only scanner backends. macOS traversal is handle-bound and Windows traversal is handle-relative; all three are exposed through `sweepx scan` / `scan --tui`.

The Scanner also now exposes a bounded locator batch reader so read-only upper layers can perform fixed file reads along already-admitted locators. Its first direct consumer is the Cargo detector: it reads `Cargo.toml` and `.cargo/config*` to project typed evidence, but those reads do not promote the result into candidate or execution authority.

`sweepx-cache` now also exposes a read-only inspection API for the preview cache, used by `cache status`. It reads only `current.json`, the pointer-selected current generation file, and the flat `generations/` / `quarantine/` directories, reporting existence, counts, approximate bytes, and health state. It does not create, repair, quarantine, rebuild, or reveal preview entries or path contents.

## Crate responsibilities

The workspace has 17 crates. Native implementations live in `sweepx-platform::{linux,macos,windows}`, selected with `backend-linux`, `backend-macos` and `backend-windows`; the default supplies contracts only. Scanner retains its `platform-*` features and forwards them to the backends. Native dependencies remain target-gated; pure Windows parsers can still be enabled and tested on other hosts.

Cleaner types and validation live in `sweepx-catalog::schema`, deterministic evaluation in `sweepx-catalog::vm`, and built-in resources and package admission in the same crate. The standalone schema/VM packages have left the workspace; machine schema IDs, rule bytes and risk values remain unchanged.

| Layer | Representative crates | Current responsibility |
|---|---|---|
| Model and protocol | `sweepx-model`, `sweepx-protocol`, `sweepx-canonical`, `sweepx-i18n` | Tagged evidence, stable envelopes/canonical digests, bilingual rendering |
| Platform and scan | `sweepx-platform`, `sweepx-scanner`, `sweepx-cache`, `sweepx-event-journal` | Platform boundaries and read-only traversal/aggregation on all three platforms; the Linux bounded SQLite journal; the macOS legacy snapshot |
| Analysis and Cleaner | `sweepx-analysis`, `sweepx-catalog` | Candidates/explanations, declarative rules, built-in packages |
| User surfaces | `sweepx-core`, `sweepx-cli`, `sweepx-tui` | Command orchestration, human/machine output, bounded read-only views |
| P3 simulated safety | `sweepx-safety`, `sweepx-audit`, `sweepx-executor` | Immutable binding, durable audit/recovery, sealed fake execution |

`sweepx-core` does not depend on `sweepx-tui`, ratatui or crossterm. The CLI's `tui_adapter` module connects browser detail requests to the scanner's native identity revalidation; no-follow, mount, cancellation and resource limits remain scanner-owned. The core JSON-browser wrapper had no command or callers and has been removed. Read-only JSON views remain available in the TUI library; `scan --tui` consumes the current typed summary.

macOS detail scans use `inspect_bound_child_with_mount_identity` to observe each file/link's own filesystem identity. A transient metadata descriptor is opened relative to the retained parent, object identity and the current basename binding are checked, and `fstatfs` observes fsid. Links are observed themselves; no payload is read and no parent mount is copied. Ordinary bulk scans retain their existing path; only identity-bound details incur the extra calls. Denial, changes and missing evidence still fail the refresh. Allocation/reclaimable bytes remain unknown, and pre-deletion identity revalidation runs independently.

Linux `delete` reuses `sweepx-audit` exact authorization, claim, intent, outcome, and fencing, but does not make the general P3 executor native. The CLI constructs and persists one closed R4 plan of at most 256 actions. A file uses one exact-basename `unlinkat`; a directory runs manifest-bound `unlinkat`/nonrecursive `rmdir` actions in postorder. That adapter does not exist in non-Linux builds.

## State and cancellation

`sweepx-core::junk::session` provides a background junk scan for explicit directory roots, connected to `junk --tui` through a CLI adapter. Phases, candidates, boundaries, errors and completion use a bounded queue with backpressure; progress and directory statistics coalesce. Stable candidate keys are separate from revisions. Selected refresh revalidates native bindings and removes old rows only after complete observation; cancellation or partial scans retain unconfirmed old evidence. The TUI formats only visible rows and keeps selection separate from scanning; background Trash reuses native binding checks and the existing Trash adapter. Historical caches and automatic system-root discovery remain pending. Refresh still traverses original roots to preserve classification context. Session cancellation is independent of the persisted `cancel` command below.

CLI scan completes synchronously. On Linux, events are constructed as a batch after scanning, then the complete stream and terminal snapshot are committed to a bounded SQLite journal in one transaction; Core `status` is journal-first and supports degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`: it performs one same-snapshot full validation, then reads pages of at most 1024 events from a completed, persisted stream; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, this surface is not a live sink, does not wait for new events, does not create a background operation, and does not support cancel. macOS and Windows still write legacy operation snapshots; the Windows state directory is protected by a current-user-private DACL, an ownership check, and per-component reparse-point rejection. `scan --no-state` skips the corresponding operation-state writes for read-only scans that do not need later status/operation state or whose state filesystem does not support the journal, and it conflicts with `--state-dir`. Live cancellation remains disabled. `cancel` returns an honest disposition, which is why its capability is disabled.

Separate from scan/status, `cache status` reads only existing preview-cache state. Linux, macOS, and Windows support human/JSON output; NDJSON is a usage error. Missing state/cache returns `absent` without creating directories. `available` means only that bounded cache structure and validation are readable, not that any live/current filesystem fact is true; warnings, errors, or quarantine presence degrade the result.

## Import is an explicit trust boundary

Core does not preserve live authority merely because scan JSON uses the project schema. After parsing, entry/aggregate provenance becomes stale preview and coverage becomes incomplete/not revalidated. Analyzer may explain it but cannot promote it to an executable candidate. The current TUI does not import that JSON; it browses the typed summary from the current live scan.

The same trust boundary applies to the current Cargo detector. It now has a handle-bound fixed-input collector and can produce `known` workspace evidence when manifest binding holds, but `targetDir` remains `not_checked` because the global override scope is unresolved, and `targetShape` remains `unknown`. CLI output therefore stays hint/report-only rather than any plan/approval/execution authority.

## Why P3 is still not a general real executor

The P3 library layering deliberately leaves nowhere to plug in native mutation:

- a canonical digest freezes plan content;
- authorization binds the exact plan and action set;
- the audit store owns durable claims, intents, outcomes, and reconciliation;
- permits and the revalidation observer are simulation-specific;
- executor requests contain no native path;
- the adapter trait is sealed and its only implementation is deterministic and fake.
- audit persistence is currently Unix-only; the separate Linux scan event-state path has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, and degraded completed-stream replay. Because that replay covers only completed, persisted streams and events are still constructed after scanning, this is still not live, cross-platform, or runtime-qualified native-mutation storage.

The P3 executor itself supports state-machine and crash-semantics tests without deleting a target. Real Linux file/directory `delete` is a separate constrained CLI path; it exposes no native adapter trait or unbounded/cross-target batch execution.

## Future architecture direction

The complete roadmap lifecycle remains:

```text
scan -> explain -> immutable plan -> explicit authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

Beyond the first two steps and read-only views, the public surface now has only the Linux bounded file/directory local closed-plan/challenge/per-action-intent/unlink/outcome path. General native platform actions, an approval broker, and plan/execute CLI wiring remain unimplemented.
