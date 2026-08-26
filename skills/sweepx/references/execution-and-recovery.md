# Execution and recovery

Use this contract only after Core has persisted an immutable plan and the human has approved that exact plan through the trusted Broker.

## Contents

- [Execute through Core](#execute-through-core)
- [Per-action safety sequence](#per-action-safety-sequence)
- [Trash behavior](#trash-behavior)
- [Permanent R4 behavior](#permanent-r4-behavior)
- [Cancellation](#cancellation)
- [Outcomes and recovery](#outcomes-and-recovery)
- [Conservative error handling](#conservative-error-handling)

## Execute through Core

Use the opaque references only:

```sh
sweepx execute --plan-id "<plan-id>" --approval-id "<broker-issued-approval-id>" --format ndjson
```

Never pass a displayed/native path or approval record. Never call a deletion adapter, platform Trash API, cleaner, official manager mutation, package manager, browser cleanup, `rm`, `unlink`, or PowerShell removal directly.

This Agent protocol never uses the product's noninteractive-capable `--dangerously-delete` authorization. Core records that path as explicit flag intent for an existing Permanent R4 plan; it cannot authenticate whether the caller was a human. The Agent-level prohibition is therefore a required behavior policy, while Core safety rests on immutable targets, R4 mode, hard protections, preflight, intent/outcome audit, and reconciliation.

Before any action, require Core to verify ordinary-user runtime with no effective/permitted/ambient capability, writable durable audit storage, an exclusive non-expiring OS batch lock, atomic single-use authorization claim, same host/user/workflow, and exact plan/policy/anchor/adapter/cleaner/capability digests. Any integrity failure, unexpected elevation, broad identity anomaly, or digest mismatch stops the batch.

Execution is serial in v1 and non-transactional. Only all proven-successful actions produce `COMPLETED`; definite failures/skips produce `PARTIAL`, and any ambiguous submitted call produces `NEEDS_RECONCILIATION`. Never automatically roll back successful actions.

## Per-action safety sequence

Require Core to perform each action in this order:

1. Reopen the live root, ancestors, parent, and exact native basename without following links.
2. Recheck root containment; parent/object/object-domain/type/mount/link identity; metadata fingerprint; runtime policy; protected anchors; `.sweepx-protect` marker chain; descendant manifest; cleaner/official evidence; and best-effort holder state.
3. Recalculate action risk. Stop when it exceeds this action's approved risk. A negative holder observation is non-authoritative.
4. Durably append and sync a distinct `ACTION_INTENT` containing plan/item/action/attempt/fence and a reserved nonce; the intent explicitly does not prove platform submission.
5. Perform the final no-follow parent+basename and safety check. Do no UI, network, cache, cleaner, holder, or extra log wait after this check.
6. Issue a private memory-only `PreflightPermit` lasting at most two seconds. The permit is non-serializable/non-cloneable and binds the exact basename/action/mode/policy/lock/fence/nonce.
7. Let the adapter accept that permit only once and invoke exactly one bounded platform action—never an arbitrary path or recursive target.
8. Reconcile source, destination, and native platform facts; durably store `ActionOutcome` before advancing.

`Candidate != DeletionPlan != ExecutionAuthorization != PreflightPermit`; none can be cast, imported, edited, or substituted for another. HumanApproval or ExplicitDangerousDelete proves only its corresponding exact-plan intent; only current preflight allows the adapter call.

## Trash behavior

Use platform Trash by default. Treat a Trash directory as one top-level platform action only after its entire closed descendant manifest has been revalidated.

If Trash is absent, denied, full, cancelled, or returns an ambiguous result, do not fall back to Permanent and do not try a different deletion mechanism. Reconcile submitted calls. Describe success only as `TRASH_SUCCEEDED_PLATFORM_REPORTED` or, when available, `TRASH_SUCCEEDED_LOCATION_REPORTED`. Never promise recoverability, restoration, or reclaimed capacity, and never empty Trash.

## Permanent R4 behavior

Permanent is allowed only from a separate persisted `mode=Permanent` plan and trusted irreversible approval. Every action and non-empty directory is at least `R4`. Never mix with Trash, add an execution-time `--permanent`, reuse Trash approval, or infer authority after Trash failure.

Expand an approved permanent directory into its closed manifest. Process every descendant in postorder and the root last. For each descendant, repeat the full reopen, prepared checks, durable intent, final check, fresh nonce/permit, exactly one nonrecursive primitive, and outcome. Never use recursive deletion.

Preserve every newly appeared or unauthorized child. If the authorized children are gone but the directory is non-empty, return `FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN`. Preserve individual descendant outcomes and mark the top-level item/batch partial as appropriate. “Permanent” means bypassing Trash for authorized directory entries; it is not secure erase or guaranteed irrecoverability.

## Cancellation

Request cancellation only through `sweepx cancel`. Cancellation stops the next action that has not been submitted. It cannot undo a completed action.

If an intent exists but the nonce/adapter fence proves no submission, Core may record `CANCELLED_BEFORE_ACTION` with source-unchanged evidence. If submission occurred or cannot be excluded, reconcile it; never relabel it cancelled or retry it. `accepted` and `already_requested` mean keep consuming status. `already_terminal` refers to the existing terminal result. `too_late_platform_submitted` requires reconciliation.

## Outcomes and recovery

Require each durable outcome to retain plan, authorization source/ID, item, action, attempt, and batch IDs; requested mode; actual platform operation; risk and version/digest snapshot; timestamps; preflight digest; native result/error; cancellation/abortion facts; Trash locator when available; source/destination postchecks; recovery state; optional same-volume capacity observations; stable detailed status; and notes.

Run recovery for every interrupted or ambiguous batch instead of rerunning `execute`:

```sh
sweepx recover --batch-id "<batch-id>" --format ndjson
```

Recover under a newly acquired exclusive OS lock and higher fence only after the OS proves the old executor exited and released its lock. Reserved nonces are never replayed. Apply these decisions:

- Same identity remains at source: require a complete new preflight. Retry only a proven-not-submitted, still-approved, explicitly transient failure with a new attempt and nonce.
- Same identity confirmed in Trash: record reconciled success.
- Source missing and destination unconfirmed: record `INDETERMINATE`; never infer success or retry automatically.
- Source holds another identity: record `STALE_IDENTITY`; never touch it.
- Source and destination both exist, or cross-volume residue remains: record `PARTIAL` or `INDETERMINATE` for human review.
- Resume only actions proven `PENDING` with no reserved nonce. Reconcile every `RESERVED`, stale, submitted, or indeterminate action first.

Keep the batch `NEEDS_RECONCILIATION` until each ambiguous intent is resolved or explicitly remains indeterminate. Missing, vanished-before-action, denied, unknown, unsupported, malformed, or absent outcomes are not success.

## Conservative error handling

- On stale object/plan/evidence/policy/capability, discard the plan and approval and restart with a live scan.
- On approval rejection, mismatch, expiry, replay, or consumption, show the exact plan again and obtain a fresh trusted approval; never alter or synthesize an approval.
- Expected sparse-preview omission is not current plan evidence: return to a targeted live enumeration and create a new exact closed manifest before planning. On incomplete scan, lost correctness detail/event evidence, unsupported layout, unknown identity, failed manifest join, or changed capability, do not plan the affected object.
- On audit-store failure, runtime elevation, protection uncertainty, digest mismatch, lock/fence anomaly, or broad identity anomaly, stop all mutation.
- On platform error after submission, preserve the native error and reconcile. Do not infer that source is unchanged unless a no-submit record or live identity postcheck proves it.
- On `NEEDS_RECONCILIATION`, recover before any new execution that overlaps the same targets.
- A future retry option may cover only an already-approved transient failure after full revalidation and a fresh attempt nonce. It must never widen scope, bypass safety, or repeat an ambiguous submission.
