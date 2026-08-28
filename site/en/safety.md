---
title: Safety model
---

# Safety model

SweepX safety currently starts with absent capabilities and explicit type boundaries: runnable surfaces are read-only, the simulated execution surface is sealed, and a real mutation surface does not exist. Future safety goals must not be written as deletion guarantees that exist today.

> [!CAUTION]
> There is no native Trash or Permanent implementation, platform mutation adapter, or destructive CLI. P3 tests cover deterministic simulation only and prove nothing about real file operations.

## Implemented read-only boundaries

| Boundary | Current behavior |
|---|---|
| User-selected roots | `scan` accepts explicit absolute paths only |
| Traversal | Linux uses metadata/no-follow semantics, macOS uses handle-bound traversal, and Windows uses handle-relative traversal; all record boundaries |
| Errors and incompleteness | Permission, mount, link, and resource limits do not masquerade as empty or complete |
| Imported input | `scan.result` JSON must use an absolute path and stay within byte/row bounds |
| Imported trust | Provenance becomes stale preview and coverage is forced incomplete/not revalidated |
| TUI | Actions contain navigation only; there is no select-and-execute mutation |
| Cleaner | Metadata only, with fail-closed compatibility checks |
| Capability language | unsupported, degraded, report_only, and disabled remain distinct |

The current executable does not request elevation, invoke cleanup managers, or expand scope after a read error. Linux may write a bounded SQLite event journal under the SweepX state directory and persist the complete stream plus terminal snapshot in one transaction; macOS writes only the legacy terminal snapshot. Windows durable operation state is disabled: `state_dir` defaults to `None`, and explicit `--state-dir` fails closed. `scan --no-state` explicitly skips Linux/macOS operation-state writes and conflicts with `--state-dir`. Linux Core status is journal-first and supports degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`: it replays only completed, persisted streams, performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, that replay is not live, does not wait for new events, does not create a background operation, and does not support cancel. None of this provides a live sink, runtime qualification, mutation qualification, or any change to a scanned target.

## Why imported reports are report-only

A JSON file records an earlier observation; it cannot prove that a path still names the same object. `explain` and TUI deliberately discard live authority on import:

```text
scan.result JSON
  -> bounded parse
  -> stale preview provenance
  -> incomplete + not revalidated coverage
  -> explanation / view only
  -> no executable candidate
```

That blocks `old report -> current delete`. Even JSON written by a just-finished local scan crosses the import boundary as untrusted execution input.

## P3 library-only safety model

The P3 libraries keep these simulation-only objects as separate types:

1. an immutable `DeletionPlan` and canonical digest;
2. `ExecutionAuthorization` bound to the exact plan, mode, action set, user, host, and TTL;
3. durable intent, fence, outcome, and reconciliation state;
4. a one-shot simulated preflight permit;
5. a deterministic simulated receipt.

The critical restrictions are:

- executor requests contain identifiers and digests, not native paths;
- the revalidation observer and fake adapter are sealed by their crates;
- the only adapter makes no operating-system file mutation;
- simulated Trash/Permanent are model branches and audit labels only;
- no CLI connects user input to these library APIs.

P3 can therefore test replay, binding, fencing, audit, and fault-handling logic. It cannot validate real Trash behavior, recoverability, reclaimed capacity, or closure of native TOCTOU windows.

## P4a.2 fail-closed qualification records

P4a.2 adds a typed, validated capability-qualification record contract, not a mutation implementation. It separates mutation into five independent cells:

| Capability cell | Linux | macOS | Windows |
|---|---|---|---|
| `trash.local.file` | disabled | disabled | disabled |
| `trash.local.directory` | disabled | disabled | disabled |
| `permanent.local.file` | disabled | disabled | disabled |
| `permanent.local.directory` | disabled | disabled | disabled |
| `permanent.local.link` | disabled | disabled | disabled |

Validation rejects `fixture_conformance_only`, `fake`, `stale`, `incomplete`, `placeholder`, or `mismatched` evidence as mutation qualification. A single cell could qualify later only when the evidence class is `real_os_qualification`, validity is `current`, and the complete tuple exactly matches Core/version, policy and adapter digests, OS build, architecture, filesystem/version, volume, provider/backend, ordinary-user profile, and capability.

This is only a fail-closed registry substrate, not a live registry service. There is no qualified mutation record, native adapter, mutation command, or approval UI today.

## Non-negotiable gates for future mutation

The following are future release gates, not present capability claims:

- Ordinary-user operation without widening scope through UAC, `sudo`, polkit, or permission changes.
- Candidate, Explanation, Plan, Authorization, Permit, Outcome, and Audit stay separate types.
- Authorization binds the complete immutable plan; target, mode, risk, or action changes require new authorization.
- Every action receives live no-follow revalidation before the platform call.
- Roots, system areas, home/profile roots, SweepX state, and protected anchors remain non-approvable.
- Trash failure, denial, cancellation, or ambiguity never falls through to Permanent.
- Intent persists before submission; ambiguous submission enters reconciliation instead of guessed replay.
- `unknown` never renders as `0`, and potentially reclaimable never becomes guaranteed freed space.

## About the future Permanent proposal

Design material discusses a separate Permanent R4 authorization and explicit dangerous source. That remains a model and roadmap item: the current CLI has no `--dangerously-delete` and there is no Permanent adapter. If ever introduced, it must bind an existing exact plan, cannot select extra targets or bypass protections, and cannot become a Trash fallback. It is not secure erase.
