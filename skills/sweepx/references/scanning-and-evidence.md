# Scanning and evidence

Use these contracts for request normalization, live scanning, aggregation, cancellation, candidate admission, and explanation. None of them authorizes mutation.

## Contents

- [Normalize explicit scope](#normalize-explicit-scope)
- [Run a live scan](#run-a-live-scan)
- [Enforce memory and state budgets](#enforce-memory-and-state-budgets)
- [Scanned entry contract](#scanned-entry-contract)
- [Directory aggregates](#directory-aggregates)
- [Links, mounts, and sizes](#links-mounts-and-sizes)
- [Errors and cancellation](#errors-and-cancellation)
- [Explain candidates](#explain-candidates)

## Normalize explicit scope

Represent requested intent before calling the CLI. This object is not authorization:

```json
{
  "roots": [{"display_path": "<absolute human-selected root>", "reason": "<why in scope>"}],
  "requested_outcome": "report|trash|permanent",
  "selectors": {"candidate_ids": [], "rule_ids": [], "ecosystems": []},
  "constraints": {
    "metadata_only": true,
    "follow_links": false,
    "same_mount_or_volume": true,
    "allow_stateful_probes": false
  }
}
```

Resolve ambiguity with the human before planning. Admit every additional root separately. Never derive a root through a glob, shell expansion, environment substitution, or traversal across a boundary. Preserve native Unix path bytes or Windows UTF-16 in Core artifacts; `display_path` is communication only and never an execution key.

## Run a live scan

Invoke a metadata-only scan without shell-interpolated selectors:

```sh
sweepx scan "/absolute/user-selected/root" --format json
```

Current scan NDJSON is disabled until SweepX has a durable event journal, cursor replay, and durable terminal events. Do not retry with NDJSON or synthesize a stream from human output.

Run as the current ordinary user. Do not read or hash contents, hydrate a cloud placeholder, follow a symlink/reparse point, enter an unrequested mount, acquire privilege, alter ACL/TCC/flags, kill a process, or change system settings.

Only data admitted as current in this live generation may form an aggregate or candidate. Cached/imported/remote data begins as `StalePreview`. It becomes current only field-by-field after required live validation; no v1 token validates an entire cross-platform record. Allocation, provider/offline state, and link count require live queries in v1. Cache-only or stale data can never create a candidate, plan item, approval, or permit.

Scanning is a streaming, memory-first aggregation process, not a promise to retain a row for every file. The default preview cache stores sparse directory summaries, roots/necessary ancestors, each parent's exact top-64 heavy children, leaves at least 32 MiB, candidates, and error/boundary evidence; it does not persist ordinary small-file details. A synthetic `Others` row summarizes evicted or non-retained children but is never selectable or plannable. Expanding a directory whose details were not retained schedules a prioritized live rescan and publishes a new aggregate revision; stale preview detail does not become current merely because it was displayed.

## Enforce memory and state budgets

Treat every limit below as a hard admission budget, not a target to exceed and repair later. MiB means 2^20 bytes. Preserve errors, boundaries, incompleteness, authorization, audit, and recovery integrity when a quota is exhausted; return visible `ResourceLimit`/partial or reject the operation instead of truncating silently or claiming completeness.

- Charge at most `B_scan = 128 MiB` of tree-dependent scan memory per operation. Keep aggregate parent plus helper private RSS at or below 384 MiB and TUI tree-dependent memory at or below 48 MiB.
- Compact and evict disposable in-memory detail before spilling. After that pass, do not create spill while charged scan memory is below 75% of `B_scan` (96 MiB). If charge remains at or above that threshold and spill is needed, keep ephemeral spill at or below 192 MiB for the operation and 256 MiB globally.
- Keep the sparse preview cache at or below both 64 MiB and 100,000 summaries. Retain roots and necessary ancestors, candidates, error/boundary evidence, each parent's exact top-64 heavy children, and leaf summaries for leaves at least 32 MiB. Coalesce the remainder into nonselectable `Others`; never persist ordinary small-file details.
- Keep the global content-addressed selection store at or below 16 MiB and the global exact descendant-manifest store at or below 64 MiB. If selected detail was discarded, perform a targeted live enumeration to construct the exact deletion-plan target manifest. Reject rather than truncate, approximate, or silently evict an active record; reject planning on incomplete, stale, over-budget, or preview-only detail.
- Keep the entire SweepX state directory at or below 512 MiB, including preview, spill, selection, manifest, plan, cursor, approval, audit, and recovery state. Reserve integrity-critical state and stop admitting work before the cap; evict only explicitly disposable preview/spill state.

## Scanned entry contract

Require each current `ScannedEntry` to retain at least:

```text
schema_version, scanner_semantics_version, adapter_version
scan_id, scan_root_identity, scan_timestamp
provenance{admission=Live, fields{...}}
display_path, parent_identity, native_basename
object_type, platform_file_identity?
filesystem_object_domain_identity?, volume_or_mount_identity?
link_or_reparse_kind?, link_payload_digest?, hard_link_count?
cloud_or_offline_state?
logical_bytes, allocated_bytes, reclaimable_estimate, confidence
metadata_fingerprint, boundary?, errors[]
```

Field provenance is exactly one of:

- `LiveObservation`: observed now through the named no-follow method.
- `ValidatedCache`: cached field checked against an approved current change token/method.
- `DerivedFromCurrent`: derived only from named current inputs and a versioned algorithm.
- `StalePreview`: display-only historical information.
- `Unknown`: unavailable with a reason.

Admission, parent/basename, identity, object type, mount, and link kind must come from the current no-follow observation. Keep filesystem object-domain identity separate from traversal mount identity and path identity. An identity is not permanent across time; interpret it only with the current root, mount snapshot, parent, and metadata fingerprint.

Require the scan's structured errors to preserve stable class, operation, native domain/code, retryability, observation time, affected identity/path when available, and detail. Stable classes cover at least access/TCC/ACL/LSM denial, sharing violation, vanished race, symlink loop, cross-device, read-only, unsupported reparse/filesystem, provider offline, recall avoided, timeout, transient/permanent I/O, interruption, and cache corruption.

## Directory aggregates

Require every `DirectoryAggregate` to retain:

```text
scan_id, directory_identity, revision
apparent_logical_bytes, unique_logical_bytes
filesystem_reported_allocated_bytes: Exact | LowerBound | Unknown
potentially_reclaimable_bytes
unknown_size_entries, entries_seen, entries_accounted, directories_closed
skipped_entries, skipped_subtrees, error_count
boundaries[], complete, incomplete_reasons[]
provenance_summary, arithmetic_state: Exact | Overflowed
```

Admit a directory candidate only from the joined final revision. Set `complete=true` only after normal enumeration closure, every admitted child reaches terminal state, no unentered boundary/error/cancellation/resource degradation remains, and every used cached field was validated in this generation. A missing child result, permission error, lost detail, cancellation, boundary, timeout, or unknown subtree makes the applicable aggregate incomplete and usually lower-bound or unknown.

A shallow pre-enumeration can report exact direct-child count and an exact sum for observations already settled, but it cannot know recursive size. Until admitted descendants close, display recursive totals as a growing lower bound with pending coverage. Each parent's exact top-64 retained children plus `Others` must reconcile to the parent aggregate; dropping individual presentation rows never permits dropping aggregate deltas. If discarded detail is later selected for deletion, require a targeted live enumeration and use only its exact closed descendant manifest as the deletion-plan target manifest.

Sum only compatible `known` values using checked `u128`. Any unbounded unknown prevents an exact aggregate. Overflow produces `unknown` and `arithmeticState=overflowed`, never a saturated number.

## Links, mounts, and sizes

Treat every symlink and Windows directory reparse point as a visible non-followed entry/boundary. Keep nested mounts, bind mounts, mounted folders, network/FUSE/automount/pseudo/container volumes, providers, removable media, and read-only/system volumes as visible boundaries unless separately admitted as explicit roots. Never infer boundary equivalence from a path string.

Deduplicate hard links only within an aggregate scope where object-domain identities are comparable. If identities cannot be compared, unique and reclaimable values are unknown. When links survive outside scope, the data may reclaim zero or an unknown amount; do not count shared logical size as exclusive reclaimable space. Clone/reflink, snapshot, dedup, overlay, shared extent, quota, purgeable, provider, and delayed-allocation ambiguity likewise prevent an exclusive reclaim claim.

Keep these measurements separate:

1. main-stream logical bytes;
2. apparent directory logical bytes;
3. identity-deduplicated unique logical bytes;
4. filesystem-reported allocated bytes;
5. potentially reclaimable estimate and confidence;
6. post-action caller-visible same-volume capacity delta.

Never say “exact disk usage,” “will free,” “unused,” or “safe to delete” from v1 scan evidence.

## Errors and cancellation

Continue safe siblings only when the terminal contract says the scan remains valid. Keep every denial, race, provider error, timeout, resource limit, cache failure, boundary, skip, and incomplete reason visible. A cache write/corruption/lock/quota failure may cause SweepX to quarantine its cache and perform a cold live scan, but must not weaken scanning semantics. Lost correctness details make affected roots incomplete.

Retry only explicitly transient I/O/provider errors, at most twice inside the original deadline, using 50 ms then 200 ms exponential backoff plus 0–25% jitter. Do not retry permissions, protection, unsupported, read-only, boundary, or stable vanished errors.

Request cancellation only through the structured control path:

```sh
sweepx cancel --operation-id "<operation-id>" --format json
sweepx status --operation-id "<operation-id>" --watch --format ndjson
```

For a resumed watch, add `--after "<last-verified-durable-cursor>"`; omit it initially. `accepted` and `already_requested` are acknowledgements, not terminal cancellation, so keep consuming the same operation. On `already_terminal`, read the existing terminal snapshot/event and do not fabricate a new cancelled terminal. On `too_late_platform_submitted`, reconcile the action; never retry or label it cancelled without postcheck evidence.

After a cancellation request, target stopping new root and directory admission within 250 ms; workers still obey their original bounded calls and checkpoints. A cancelled scan is logically terminal but incomplete. Include quarantined platform-call counts and never claim all resources stopped until the OS confirms it. Discard late results detached from the cancelled generation.

## Explain candidates

Explain each current candidate before planning:

```sh
sweepx explain --scan-id "<scan-id>" --candidate-id "<candidate-id>" --format json
```

Require the candidate to bind its current scan and retain:

```text
candidate_id, source, schema/scanner/adapter/cleaner versions and digests
lossless parent-reopen recipe, native basename
root, parent, object, object-domain, mount, type, and link identities/facts
metadata fingerprint, logical/allocated/reclaimable tagged values
risk floor, confidence, scan timestamp, aggregate revision
subtree completeness, coverage, rules, evidence, boundaries, errors, uncertainties
supported actions and recovery conditions
```

Every non-root locator component records its direct parent identity. Before executable eligibility,
verify that the recipe is a contiguous root-to-immediate-parent chain and that every component has
known no-follow object, filesystem-domain, and mount/volume identity plus type and metadata
fingerprint evidence. Validate relative native-basename grammar for every non-root component; the
scan root is instead anchored by its lossless absolute native path and root identity.

Require the explanation to bind the candidate digest and distinguish current observed facts, manager/browser/native facts, rule-derived inferences, heuristics, and unknown/unsupported/not-checked/stale/incomplete/skipped evidence. Explain why the rule matched, why action is unavailable when applicable, sharing/references/activity/official state, size semantics, risk changes, cold-start/download effects, recovery needs, and human actions. It must not alter identity, scope, mode, or risk floor.

Treat timestamps as weak signals unless the owning manager defines their semantics. Treat a negative holder/process observation only as “not observed at that time,” never as authorization. Require owner, canonical object identity and granularity, references, activity/activation, official state, recovery requirements, sharing/concurrency, and blockers. Missing evidence may only preserve/raise risk or force report/skip. No query proves absence of references across every user, project, container, VM, CI worker, remote host, or offline medium.
