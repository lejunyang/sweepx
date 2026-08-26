---
name: sweepx
description: >-
  Design and validate the operating protocol for the planned SweepX CLI, and
  operate SweepX only when an installed binary advertises the required compatible
  capabilities. Use for SweepX agent integration, storage scans, candidate
  explanations, immutable cleanup plans, trusted human approval, Trash or
  Permanent execution, reconciliation, recovery, cleaner rules, developer caches,
  browser storage, toolchains, containers, and build artifacts. This skill does
  not imply that the CLI or destructive capabilities exist; enforce ordinary-user
  execution, Trash-first Agent behavior, live revalidation, and
  non-bypassable protections.
---

# Operate SweepX safely

Treat every command in this skill as a contract for a planned product until an installed `sweepx` binary proves otherwise. Writing, reviewing, or invoking this skill performs no scan or mutation by itself. Never infer that a documented command, adapter, or destructive mode has shipped.

## Apply the availability gate

Before scanning, and again before execution if the process, installation, policy, or adapter set may have changed, run only these read-only checks:

```sh
sweepx status --format json
sweepx capabilities --format json
```

Proceed only when the binary exists, returns `schema=sweepx.output/v1`, and advertises the required command, adapter, mode, platform release qualification, policy, protected-anchor snapshot, and healthy approval/audit stores. If any requirement is absent, incompatible, unreadable, or unqualified, stop and report the capability as unavailable. Never emulate SweepX with `rm`, `unlink`, PowerShell removal, direct Trash APIs, package-manager commands, browser-internal edits, or another cleanup tool.

Read [Structured output and state](references/structured-output-and-state.md) before consuming JSON/NDJSON. Malformed, incomplete, contradictory, unknown safety-relevant, or prose-only output fails closed; an exit code alone never proves success.

## Preserve the lifecycle

Follow this sequence without skipping or merging stages:

```text
scan -> explain -> immutable plan -> trusted human approval
     -> live revalidation -> execute -> reconcile/audit
```

Keep `live observation != explanation != candidate != plan != approval != permit`. A changed or stale object, plan, policy, capability, cleaner result, or protected anchor restarts at `scan`; prior approval cannot carry forward.

1. **Scan read-only.** Default every request to inventory and explanation; words such as “clean,” “free space,” or “remove old files” do not grant mutation authority. Normalize explicit human-selected roots; scan metadata-only, no-follow, same-mount/volume, streaming, and memory-first. Preserve every boundary, error, unknown, and incomplete subtree. Treat sparse preview rows as display state, not retained file inventory; use prioritized live rescan for omitted TUI detail. Read [Scanning and evidence](references/scanning-and-evidence.md) before forming candidates.
2. **Explain before selecting.** Bind each explanation to a current live candidate and separate facts, manager evidence, rule inferences, heuristics, unknowns, and recovery consequences. Missing evidence can only hold or raise risk.
3. **Create an immutable plan.** Select explained candidate IDs, never raw paths, globs, recursive selectors, sparse preview rows, or `Others`. If selected detail was discarded, require Core to build the exact closed target manifest through a targeted live enumeration before planning. Default to a Trash plan. Read [Plans, authorization, and protections](references/plans-approval-and-protections.md) before creating or reviewing a plan. Any edit creates a new plan and full canonical digest.
4. **Pause for trusted human approval.** Show the exact plan, full canonical digest, and short attention fingerprint, then ask the human to use SweepX's local foreground approval surface. The first-party native dialog is preferred; a trusted foreground typed challenge is the fallback, with optional non-elevating OS verification where supported. The Agent must never invoke, open, drive, click, type into, provide input to, or automate `sweepx approve`, a native dialog, Windows Hello/`UserConsentVerifier`, macOS `LocalAuthentication`, a terminal/TUI challenge, or another approval surface. It must not treat chat assent as approval. Resume only with the opaque Broker-issued `approvalId`.
5. **Execute only the approved internal plan.** Read [Execution and recovery](references/execution-and-recovery.md), then invoke only `sweepx execute` with the persisted `planId` and opaque `approvalId`. Require live core revalidation and one-shot permits for every action.
6. **Reconcile every submitted or ambiguous action.** Consume the durable terminal event and action outcomes. Use `recover`; never blindly rerun execution, guess from a missing source, or automatically roll back successful actions.

Read [Cleaner and domain rules](references/cleaner-and-domain-rules.md) before using any cleaner, manager/browser evidence, official GC, developer artifact, or browser-storage candidate. A cleaner is evidence interpreted by Core, not authority and not a deletion primitive.

## Keep authority with the right actor

- Run as the current ordinary user. Never request or use `sudo`, UAC, `runas`, polkit, setuid, backup/restore privilege, Linux capabilities, ownership takeover, ACL/TCC changes, immutable/read-only flag changes, process termination, or system-setting changes. Block mutation if execution is elevated or has effective, permitted, or ambient capabilities.
- Let the Agent use `status`, `capabilities`, `scan`, `explain`, `plan create/show`, `execute`, `cancel`, `recover`, read-only cleaner inspection, and audit/status queries. These calls do not let the Agent grant approval.
- Let only the trusted Human Approval Broker construct and privately validate `ApprovalRecord`. The authenticated record's binding to the full canonical plan digest is the security boundary; a displayed or typed short fingerprint is only an attention check. The Agent requires a structured Core attestation that the private record was validated for the exact plan; it must not request, inspect, copy, edit, import, fabricate, or validate that record itself.
- Treat approval only as exact, short-lived, single-use proof of human intent. It is not evidence that an object is safe or unchanged. Core live revalidation decides whether an action may proceed.
- Mutate only through `sweepx execute` using an internal immutable plan ID and opaque broker-issued approval ID. Never invoke an adapter, cleaner, manager mutation, browser cleanup, platform Trash operation, or filesystem deletion primitive directly.

## Keep Trash and Permanent separate

Use platform Trash by default. If Trash is unsupported, denied, full, cancelled, or ambiguous, do not fall back to Permanent and do not empty Trash. Describe success only as the platform reporting that an item moved to Trash; do not promise recovery or capacity gain.

Permanent requires a new `--mode permanent` plan, a separate batch, `R4` for every action and every non-empty directory, explicit execution authorization, and manifest-bounded nonrecursive postorder actions. The product also specifies a noninteractive-capable `--dangerously-delete` authorization that skips confirmation; Core records it separately and does not pretend it proves human identity. **An Agent must never pass, suggest automating, or proxy this flag**; use only a Broker-issued opaque `approvalId`. Never convert a Trash plan at execution, infer Permanent authority from Trash failure, or describe Permanent as secure erase or guaranteed unrecoverable. Newly appeared children remain untouched.

## Enforce hard protections

The following are non-approvable at planning, approval, revalidation, Core, and adapter boundaries:

- filesystem, volume, mount, bind, mounted-folder, automount, and UNC share roots or aliases;
- OS boot, recovery, system, device, and virtual-filesystem anchors;
- the home/profile root and the parent containing all profiles;
- Trash/Recycle Bin internals and SweepX executable, install, active cwd, config, cache/spill, plan, lock, approval, and audit stores;
- protected objects and any ancestor whose whole-object action would contain one;
- device, socket, FIFO, Windows device namespace, unmodeled ADS, and special or unknown object/reparse types;
- anything outside the admitted scan root, with unverified identity/parent/type/mount/containment, or containing new, unreadable, or unapproved descendants;
- anything under a `.sweepx-protect` entry of any type on the real no-follow ancestor chain. Inability to check for the marker is blocked.

Also protect authoritative package-manager state anchors: databases, configuration, locks, receipts, transaction state, and rollback state. This term does **not** include separately modeled cache artifacts merely because a package manager owns them; an owner-supported GC may act on such cache artifacts only through a fixed, qualified Core adapter and the full plan/authorization/revalidation lifecycle.

Reject empty, relative, malformed, wildcard/glob, device-namespace, lossy, or noncanonical targets. Resolve aliases by native identity and mount/volume APIs, never string prefix. No flag, including `--dangerously-delete`, may weaken protection, follow links, cross mounts, ignore identity/policy, elevate, widen targets, convert unknown to success, or convert a Trash plan to Permanent. Treat `--yes`, `--force`, `--recursive`, execution-time `--permanent`, `ignore-safety`, and `delete-any-path` as unsupported.

Users and policy may add protection but may never weaken built-ins. If a human removes `.sweepx-protect` outside SweepX, require a new scan, explanation, plan, and approval.

## Report conservatively

Before approval, report the full canonical plan digest, short attention-only fingerprint, mode, exact item/action counts, per-action risks, potentially reclaimable range and its uncertainty, incomplete/unknown evidence, boundaries, blockers, recovery expectations, and expiry.

After execution or recovery, report every item/action outcome, native errors, actual platform operation, Trash locator when available, source/destination reconciliation, partial/cancelled/indeterminate results, and audit/batch ID. Capacity is only an optional same-volume before/after observation. Never call an estimate guaranteed freed space, Trash guaranteed recovery, or Permanent secure erase.
