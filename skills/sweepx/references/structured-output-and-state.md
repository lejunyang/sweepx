# Structured output and state

Use this contract for every SweepX machine response. Reject prose as machine state and never infer success from a process exit alone.

## Contents

- [Bounded JSON](#bounded-json)
- [Streaming NDJSON](#streaming-ndjson)
- [Event vocabulary](#event-vocabulary)
- [Exit codes](#exit-codes)
- [Tagged values and errors](#tagged-values-and-errors)
- [State machines](#state-machines)

## Bounded JSON

Accept exactly one JSON object on stdout for a bounded command:

```json
{
  "schema": "sweepx.output/v1",
  "kind": "scan.result",
  "requestId": "<id>",
  "operationId": "<id>",
  "generatedAt": "<RFC3339>",
  "status": "ok",
  "exitCode": 0,
  "compat": {
    "coreVersion": "<version>",
    "scannerSemanticsVersion": 1,
    "safetyPolicyVersion": 1,
    "requiredFeatures": [],
    "extensions": []
  },
  "summary": {},
  "data": {},
  "warnings": [],
  "errors": []
}
```

Allow these v1 `kind` values: `scan.result`, `explanation.result`, `plan.result`, `execution.result`, `recovery.result`, `cancel.result`, `status.result`, `capabilities.result`, `cleaner.result`, and `audit.result`. `approval.result` is an internal typed Broker response after trusted foreground input; it is not a JSON/NDJSON mode for `approve`. Allow these statuses: `ok`, `partial`, `blocked`, `authorization_required`, `stale`, `failed`, `needs_reconciliation`, `cancelled`, and `unsupported`.

Validate `status.result.data` and `cancel.result.data` against their exact published branches. Status data is the complete public operation view. Cancel data contains `operationId`, `disposition`, `canCancel=false`, and nullable `operation`; `not_found` and `unsupported` require null, while `already_terminal` requires the complete view. Reject unknown data fields.

Treat `/v1` as an additive-only major family. Allow unknown optional fields and preserve them when relaying signed/canonical artifacts. Reject an unknown required feature, schema major, or enum affecting identity, scope, risk, completeness, protection, action, or outcome. Never silently rewrite an immutable artifact. JSON output is not an executable plan import. Agent execution accepts only Core's internal `planId` and the Broker's opaque `approvalId`; although the product's separate `--dangerously-delete` authorization may run noninteractively, this Skill never invokes it.

Record CLI/Core version, host instance, current user, scanner semantics, safety-policy version/digest, protected-anchor snapshot digest, adapter versions/capability digest, cleaner-set digest, supported output schemas/features, destructive-mode qualification, and approval/audit-store health. A missing or unreadable required value blocks mutation.

## Streaming NDJSON

This section is the required consumer contract for a future durable stream. The current CLI rejects `scan --format ndjson` before scanning because it has no durable event journal or replay path. Do not consume, emulate, or reinterpret the Core's internal in-memory progress vector as NDJSON. Use bounded `--format json` for current scans.

Accept one complete JSON object per line:

```json
{
  "schema": "sweepx.event/v1",
  "streamId": "<id>",
  "operationId": "<id>",
  "sequence": "42",
  "cursor": "<opaque-signed-cursor>",
  "emittedAt": "<RFC3339>",
  "monotonicOffsetNs": "123456",
  "type": "scan.progress",
  "phase": "detect",
  "payload": {},
  "terminal": false,
  "checkpoint": {"durable": true, "lastDurableSequence": "42"}
}
```

Accept a phase only from `detect|analyze|plan|authorize|revalidate|execute|reconcile|audit`. Compatibility is fixed by `operation.started.payload.compat` or the event's equivalent snapshot. `approve` remains a command name for the HumanApproval path, not the phase enum.

Delivery is at least once. Deduplicate only byte/semantic-identical events by `(streamId, sequence)`, then require strictly increasing decimal-string sequences. Reject conflicting duplicates, unexplained gaps/regressions, malformed JSON, schema mismatch, early EOF, incompatible terminal envelopes, or a stream without exactly one durable `operation.terminal`. On `stream.reset_required`, read the referenced status snapshot and continue from its returned cursor; never interpret the missing interval as empty. Resume a watch only with the last verified durable opaque cursor; never construct one. Keep stderr diagnostic-only.

Any incomplete or contradictory stream means effects are unknown: stop new mutation and query `status` or `recover`.

## Event vocabulary

Recognize the exact v1 types below; an unrecognized safety-relevant type fails closed. Progress events marked coalescible may be replaced by a newer equivalent, but error, boundary, incomplete-reason, intent, outcome, and terminal events may not be dropped.

| Type | Required meaning | Coalescible |
|---|---|---|
| `operation.started` | command, request digest, compatibility, root/item counts | No |
| `phase.changed` | previous phase if any and next valid phase | No |
| `scan.root.admitted` | root ID, display path, live root/mount identity, policy digest | No |
| `scan.progress` | complete `ScanProgress` contract | Yes, at most 10 Hz/key |
| `scan.aggregate.revised` | directory ID, revision, four size views, coverage, provenance | Intermediate only |
| `scan.boundary.observed` | boundary class, root/directory, native code, coverage effect | No |
| `scan.error.observed` | stable class, operation, retryability, native code, coverage effect | No |
| `scan.root.completed` | final root aggregate, completeness, quarantined calls | No |
| `candidate.detected` | live candidate ID/digest, rule IDs, risk floor | Pagination reference only |
| `analysis.completed` | candidate ID, explanation digest, eligibility/report-only reason | No |
| `plan.created` / `plan.rejected` | plan ID/digest/mode/action count/risk or rejection | No |
| `approval.requested` | full canonical plan digest, short attention-only fingerprint, mode, item/action counts, and qualified human channel; fingerprint is never the authorization binding | No |
| `approval.granted` / `approval.rejected` / `approval.expired` | opaque ID only when granted, plan digest, result | No |
| `authorization.explicit_dangerous_delete` | authorization ID, exact Permanent plan digest, item/action counts, risk/policy/anchor/cleaner digests; no nonce | No |
| `revalidation.started` | item/action/attempt IDs | No |
| `revalidation.passed` / `revalidation.stale` | revalidation digest or stable stale reason | No |
| `preflight.ready` | action ID and permit expiry; never permit/nonce/handle | No |
| `hard_protection.blocked` | item/action, protection class, policy/anchor digest | No |
| `operation.cancel.requested` / `operation.cancel.accepted` / `operation.cancel.already_requested` / `operation.cancel.already_terminal` / `operation.cancel.too_late` | requester, operation state, terminal reference or submitted/quarantine counts as applicable | No |
| `action.intent.durable` | action/attempt/fence, mode, prepared digest; submission not yet proven | No |
| `action.platform.completed` | actual operation, native result/error, aborted/cancelled facts | No |
| `action.skipped` / `action.failed_before_submit` | stable reason and source-unchanged evidence; no platform call | No |
| `action.permit.consumed` | action/attempt and adapter acceptance; no permit disclosure | No |
| `action.reconciled` / `action.indeterminate` | source/destination postchecks and recovery state | No |
| `item.completed` | ordered action summary and item status | No |
| `batch.completed` / `batch.partial` / `batch.cancelled` / `batch.needs_reconciliation` | totals and durable audit sequence range | No |
| `recovery.started` / `recovery.completed` | batch/fence and reconciled/pending/indeterminate totals | No |
| `audit.started` / `audit.batch.committed` / `audit.failed` | batch, durable sequence/digest or integrity error | No |
| `detail.persistence.failed` | lost counts/classes, affected roots, emergency record state | No |
| `stream.reset_required` | cursor gap and snapshot reference | No |
| `operation.terminal` | output status, exit code, final snapshot digest | No; exactly one durable |

`ScanProgress` retains `scanId`, `rootId`, `volumeOrMountId`, `aggregateRevision`, `phase`, `discovered`, `queued`, `inFlight`, `processed`, `skippedEntries`, `skippedSubtrees`, `errors`, `boundaries`, `logicalKnown`, `allocatedKnown`, `reclaimableKnown`, `unknownEntries`, `queueDepthsAndBytes`, `activeWorkers`, `entriesPerSecond`, `metadataOpsPerSecond`, `elapsed`, and `completeState`. Do not fabricate a percentage when total entries are unknown.

Emit `operation.terminal` only after the required audit record and terminal snapshot are durable. If that persistence fails, emit the integrity failure/exit 11 rather than upgrading an earlier action result to audited success.

## Exit codes

Interpret the exit together with the terminal envelope. Prefer the more conservative meaning if they disagree.

| Exit | Meaning | Required response |
|---:|---|---|
| 0 | Completed as reported | Verify terminal status and all outcomes. |
| 2 | Usage error | Correct arguments without broadening scope. |
| 3 | Unsupported | Report missing capability; do not emulate. |
| 4 | Partial | Report every state; reconcile ambiguous actions. |
| 5 | Safety blocked | Stop; do not override. |
| 6 | Authorization required, invalid, rejected, expired, consumed, or variant/mode mismatch | For Agent use, return to HumanApproval; never fabricate an authorization or invoke the danger flag. |
| 7 | Stale | Restart scan, explain, plan, and authorization. |
| 8 | Failed | Preserve structured/native errors; retry only explicitly safe retryable work. |
| 9 | Needs reconciliation | Recover before overlapping execution. |
| 10 | Cancelled | Report completed/pending actions; reconcile submissions. |
| 11 | State/audit integrity unavailable | Stop all mutation until restored. |
| 12 | Cleaner/plugin trust or compatibility failure | Keep rule report-only; do not bypass/load fallback. |
| 13 | Official external command failed | Preserve its structured result; never raw-delete fallback. |

Treat every undocumented exit as failure with unknown effects.

## Tagged values and errors

Keep these variants distinct; absence, `null`, `-1`, and zero are not substitutes:

```json
{"state": "known", "value": "0"}
{"state": "lower_bound", "value": "4096", "reason": "incomplete_stream_coverage"}
{"state": "unknown", "reason": "not_revalidated"}
{"state": "unsupported", "reason": "adapter_capability_absent"}
{"state": "not_checked", "reason": "strict_read_only"}
```

Retain potentially large byte/count/sequence values as decimal strings or lossless integers. Never coerce `u128` to floating point. Checked-arithmetic overflow produces `unknown` plus `arithmeticState=overflowed`, not saturation. Keep logical, apparent logical, identity-deduplicated logical, filesystem-reported allocated, potentially reclaimable, and post-action caller-visible capacity delta separate.

Retain structured error `code`, `class`, `messageKey`, parameters, phase/operation, native domain/code, retryability, observation time, affected IDs/identity/path when available, recovery disposition, and detail. Preserve denied, vanished, timeout, unsupported, offline, interrupted, unentered, and lost-detail coverage; never convert them into empty results.

## State machines

Track batch state exactly:

```text
DISCOVERED -> EXPLAINED -> PLANNED -> AUTHORIZATION_PENDING -> AUTHORIZED
  -> REVALIDATING -> READY -> EXECUTING
  -> { COMPLETED | PARTIAL | CANCELLED | NEEDS_RECONCILIATION }
any applicable nonterminal state -> { REJECTED | HARD_BLOCKED }
each terminal outcome T -> AUDITED(terminalOutcome=T)
```

Track item state exactly:

```text
CANDIDATE -> EXPLAINED -> IN_PLAN -> AUTHORIZED -> REVALIDATING
  -> PREFLIGHT_READY -> TRASHING | PERMANENT_DELETING
  -> { SUCCEEDED | FAILED | SKIPPED | STALE | CANCELLED | INDETERMINATE }
any applicable nonterminal state -> { REJECTED | HARD_BLOCKED }
each terminal outcome T -> AUDITED(terminalOutcome=T)
```

`AUDITED` wraps and retains the substantive terminal outcome. Audit failure never upgrades a result; it returns exit 11 and preserves failure or reconciliation need. All actions must be proven successful for `COMPLETED`. Definite mixed/failure/skip results without ambiguity are `PARTIAL`; any unproved submitted result is `NEEDS_RECONCILIATION` with an `INDETERMINATE` item. `STALE` restarts the full lifecycle.

Recognize detailed outcomes at least: `TRASH_SUCCEEDED_PLATFORM_REPORTED`, `TRASH_SUCCEEDED_LOCATION_REPORTED`, `PERMANENT_DELETE_SUCCEEDED`, `SKIPPED_PROTECTED`, `SKIPPED_RISK_NOT_APPROVED`, `SKIPPED_INCOMPLETE_SUBTREE`, `STALE_PARENT`, `STALE_IDENTITY`, `STALE_TYPE`, `STALE_MOUNT`, `STALE_LINK`, `STALE_DESCENDANTS`, `BLOCKED_UNKNOWN_REPARSE`, `BLOCKED_OUTSIDE_SCAN_ROOT`, `BLOCKED_RUNTIME_PRIVILEGE`, `FAILED_PERMISSION`, `FAILED_READ_ONLY`, `FAILED_SHARING_VIOLATION`, `FAILED_TRASH_UNSUPPORTED`, `FAILED_TRASH_NO_SPACE`, `FAILED_NOT_EMPTY_AFTER_APPROVED_CHILDREN`, `FAILED_PLATFORM_ERROR`, `FAILED_CANCELLED_BY_PLATFORM`, `VANISHED_BEFORE_ACTION`, `CANCELLED_BEFORE_ACTION`, `INDETERMINATE_AFTER_CRASH`, and `INDETERMINATE_PLATFORM_RESULT`. Missing/not found is never success.
