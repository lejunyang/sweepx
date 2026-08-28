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
| P1 scanner CLI | Linux read-only scan is degraded and has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, and journal-first status; the event-journal crate retains a Linux-test-only bounded cursor replay/reset substrate; macOS retains the legacy snapshot; Windows scan is handle-relative degraded | Replay/reset is not wired into Core or the CLI; `scan --no-state` explicitly skips operation-state writes and conflicts with `--state-dir`; Windows durable state is disabled; live cancel, the live sink, runtime qualification, public `status --watch`/NDJSON, and three-platform/resource gates remain open |
| P2 analysis/TUI/Cleaner | Bounded explain, live directory browsing through `scan --tui`, and metadata-only Cleaner run | Imported explain input is report-only; TUI detail expansion is now single-flight background rescan with a 2 s deadline, late-result discard, and a 32-worker stuck cap; signing/sandbox/full cross-surface qualification open |
| P3 plan/audit/simulation | Immutable plans, simulation-only authorization, Unix audit/recovery, and a sealed fake executor are implemented; Linux bounded journaling and one-transaction complete-stream/terminal persistence exist, while the event-journal crate retains a Linux-test-only replay/reset substrate | Replay/reset is not wired into Core or the CLI; there is no trusted HumanApproval broker, native path, real revalidation, live event sink, runtime qualification, public watch/NDJSON, non-Linux journal parity, or platform adapter; the phase is not qualified |
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
