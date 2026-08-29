---
title: Roadmap
---

# Roadmap

The roadmap defines capability and evidence gates, not dates. Code may land before a phase is complete because cross-platform, benchmark, fault-injection, or safety evidence is still missing.

> [!CAUTION]
> The current implementation spans portions of P1/P2 read-only work and P3 library-only simulation, but contains no native mutation. “A crate/test exists” must not be rewritten as “the phase is qualified.”

## Current position

| Track | Current evidence | Open boundary |
|---|---|---|
| P0 contracts/models | Workspace, schemas, fixtures, safety types, and extensive tests exist | The complete evidence bundle and every acceptance gate have not been declared complete |
| P1 scanner CLI | Linux read-only scan is degraded and has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, journal-first status, and degraded completed replay through `status --watch --format ndjson`; macOS retains the legacy snapshot; Windows scan is handle-relative degraded | Linux replay covers only completed, persisted streams: it performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown-valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. It is still non-live, does not wait for new events, does not create a background operation, and does not support cancel; `scan --no-state` explicitly skips operation-state writes and conflicts with `--state-dir`; Windows durable state is disabled; the live sink, runtime qualification, `scan --format ndjson`, and three-platform/resource gates remain open |
| P2 analysis/TUI/Cleaner | Bounded explain, progressive directory browsing through `scan --tui`, metadata-only Cleaner and report-only `junk` rules, plus read-only preview-cache diagnostics | Imported explain input is report-only; TUI enters after root admission, lists the current level first, then aggregates direct-directory sizes with a single-flight 30 s background rescan, late-result discard, and a 32-worker stuck cap; `cache status` remains bounded and read-only; Cargo detection and `junk` remain report-only; signing/sandbox/full cross-surface qualification open |
| P3 plan/audit/simulation | Immutable plans, simulation-only authorization, Unix audit/recovery, and a sealed fake executor are implemented; Linux bounded journaling, one-transaction complete-stream/terminal persistence, and degraded completed replay exist | Replay is still non-live, not runtime-qualified, and Linux-only for completed persisted streams; there is no trusted HumanApproval broker, native path, real revalidation, live event sink, `scan --format ndjson`, non-Linux journal parity, or platform adapter; the phase is not qualified |
| P4a qualification substrate | Linux `cfg(test)` disposable fixture; P4a.2 typed/validated qualification records and five independent mutation cells | Every cell is disabled on Linux/macOS/Windows; no native adapter, mutation command, approval UI, or product mutation capability |
| P4+ mutation | No public capability | Trash, Permanent, and release qualification remain future work |
| Release engineering | CI, Pages, five target archives/checksums, Unix/Windows installers, and ordered crates.io publication exist | No stable release yet; signing, SBOM, and provenance gates remain open |

## Phase targets

| Phase | Target increment | Explicitly excluded |
|---|---|---|
| P0 | Contracts, schemas, safety policy, fixture/oracle baseline | Mutation and performance claims |
| P1 | Qualified read-only scanner CLI on all three platforms | Cleaner execution, plans, Trash/Permanent |
| P2 | Explainable analysis, bounded TUI, read-only Agent, catalog reporting | Approval or real execution |
| P3 | Immutable plan/authorization, durable audit, deterministic simulation | Native Trash/Permanent, execution against user files, public execution CLI |
| P4 | Native Trash beta on exact qualified tuples only | Permanent and cross-filesystem/remote/provider/system mutation |
| P5 | Stable ordinary-user product on all three platforms | Unqualified capabilities, elevated cleanup, broad manager mutation |
| P6 | Post-v1 tracks with separate threat models | Expansion without independent evidence |

## P3 completion criteria

The nearest active work is P3 libraries. They converge only while model and fault-injection tests continue to prove that:

- plan digests and exact authorization binding cannot mismatch;
- nonce, TTL, claim, fence, and permit cannot replay;
- durable intent precedes simulated submission;
- ambiguous outcomes enter reconciliation;
- cancellation cannot become success;
- a Trash branch cannot transition to Permanent;
- the sealed fake adapter remains the executor's only adapter;
- native mutation of user files remains impossible.

Even completing those items does not automatically create a `sweepx plan/approve/execute` CLI. Public API design, trusted local approval, real live revalidation, and native adapters are separate later work.

## Hard stop before P4

Before the first native Trash test, the project needs at least:

1. an exact OS/architecture/filesystem/provider capability tuple;
2. disposable fixtures and an independent oracle;
3. target, parent, ancestor, mount, and descendant-swap adversarial tests;
4. native-result ambiguity and crash reconciliation;
5. proof that every Trash failure path avoids Permanent;
6. consistent identity, risk, and outcome semantics across CLI, TUI, Agent, and Cleaner.

The project has not entered that step.

P4a.2 completes only the fail-closed qualification-registry contract. `trash.local.file`, `trash.local.directory`, `permanent.local.file`, `permanent.local.directory`, and `permanent.local.link` remain disabled on all three OS families. `fixture_conformance_only`, `fake`, `stale`, `incomplete`, `placeholder`, and `mismatched` evidence can never qualify mutation; a single cell could qualify later only with current `real_os_qualification` evidence that completely matches its exact tuple.

## Future commands remain proposals

`plan create/show`, trusted approval, `execute`, and every Permanent flag are absent from the current command tree. Documentation may promote them from “proposal” to “runnable” only after real CLI wiring and corresponding capability qualification exist.

## Newly recorded milestone

| Commit | Milestone | Accurate current state |
|---|---|---|
| `1483246` | Linux completed-stream replay/watch for `status` | Linux now exposes degraded `operation.event.completed_replay` through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`. It replays only completed, persisted journal streams, performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown-valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. The replay does not wait for new events, does not create a background operation, does not support cancel, and remains non-live and not runtime-qualified. `scan --format ndjson` stays disabled; macOS remains on the legacy snapshot; Windows durable state remains disabled. |
| `933921b` | Read-only `cache status` diagnostics | Linux and macOS now expose degraded `cache.preview.inspect` through `cache status`, with output kind `cache.status.result`. The command supports human/JSON only, treats NDJSON as a usage error, and remains disabled on Windows. Missing state/cache returns `absent` with exit 0 and does not create default or explicit state/cache directories. Inspection is bounded to `preview-cache/current.json`, the current generation file, and the flat `generations/` and `quarantine/` directories; it does not scan, repair, quarantine, or reveal cached entries or path contents. `available` means only that bounded cache structure and validation are readable; warnings, errors, or quarantine presence degrade the result to exit 4. |
