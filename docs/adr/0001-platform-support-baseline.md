# ADR 0001: Platform Support Baseline

Status: Accepted

Date: 2026-08-26

## Context

SweepX is intended to be a first-class product on Windows, macOS, and Linux. The current repository state is still contract-first and pre-implementation. The roadmap and architecture require explicit support language before runtime qualification, CI image selection, filesystem qualification, and later native adapter work can proceed.

The current design also draws a hard line between read-only phases and later mutation-capable phases:

- P0 is schema, policy, fixture, and documentation baseline work.
- P1 is read-only scanning.
- P2 is explainable analysis, TUI, and read-only Agent work.
- P3 is immutable planning, approval, simulated execution, audit, and recovery against fake adapters.
- Native mutation is deferred until later capability qualification.

## Decision

SweepX treats Windows, macOS, and Linux as first-class platforms from P0 onward.

The minimum supported OS versions remain intentionally unqualified and TBD at P0. They are not frozen by this ADR, and no implementation or release artifact may claim a concrete minimum version until later qualification work records the supporting evidence.

Planned first qualified local filesystem baselines are:

- Windows: NTFS
- macOS: APFS
- Linux: ext4

Those filesystem baselines are planned for P1 qualification work and are not treated as already qualified by this ADR.

P0, P1, P2, and P3 do not permit native mutation. During those phases, the product may define schemas, state machines, plans, approvals, simulated execution, and deterministic receipts, but it may not advertise or execute native Trash or permanent deletion against real user files.

## Consequences

- Capability records for mutation-related features remain `report_only`, `unsupported`, or `disabled` until P4 or later qualification proves otherwise.
- Contract and policy artifacts must encode the no-native-mutation-through-P3 invariant explicitly.
- Future platform support ADRs must replace `TBD` language with evidence-backed minimum version statements before release claims are made.
- Filesystem qualification work must treat NTFS, APFS, and ext4 as the planned first local baselines, while still allowing other filesystems to remain degraded, report-only, unsupported, or disabled.
