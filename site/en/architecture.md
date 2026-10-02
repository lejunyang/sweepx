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

Project-rule JSON supports `requiredOwnMarkers` (empty by default, at most 64 safe filenames): every declared ordinary file must occur directly inside the captured directory. `requiredParentMarkers` still requires at least one parent marker. `JunkService` consumes identity-keyed facts from the same traversal through the existing VM, with no classification I/O. Loaded-byte digests bind cache validity. Structural markers establish neither parsed formats, activity nor mutation permission. Shared version/user-data fixtures live in the existing fixtures crate's development-only `project_junk` module.

`LocatorReader::read_captured_regular_file` supplies bounded complete-file reads for format interpretation. It reuses captured root/lineage validation and the provider-safe native content stream. A zero-payload probe establishes current identity, mount, size and change stamp; oversized files deliver no content, and the full read must match that probe. Display paths grant no authority, prefixes are not complete files, and failures prove no atomic absence. Each call bounds file bytes, names, components and stages; consumers still need cumulative budgets, cancellation and worker ownership. The API is independently callable; junk format interpretation and cleanup admission have not yet connected it.

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

Core's `GitEvidenceSession` supplies current Git evidence to both reports and junk sessions. Each candidate uses one bounded `rev-parse` call to observe the worktree and `.git` locations, followed by separate native identity, filesystem/mount and change-fingerprint checks. Scope is not cached across candidates; environment redirection is still removed and external configuration changes require fresh answers. Unix paths containing newlines keep two independently framed queries. Other combined output must contain exactly two complete absolute paths; truncation, extra records or query failure cannot establish scope. Current tracked/ignore queries, resource deadlines and project execution guards remain independent.

## State and cancellation

`sweepx-core::tools::ProbeRunner` drains complete bounded answers on the calling worker without background pipe-reader threads. On macOS, pipe readiness and an exit notification for the owned, unreaped child avoid fixed polling delays after output or EOF. Notifications only wake checks: they cannot substitute for `Child` exit status or establish inactivity/ownership. Each probe adds at most one owned exit-observation descriptor; unavailable notifications fall back to bounded polling. Individual/batch deadlines, output limits, cancellation and process-group cleanup retain their contracts; native launch/reaping remain subject to host scheduling. Linux/Windows retain their existing polling.

Large-file analysis uses bounded top-K in the existing `sweepx-analysis` crate. Core's `scan_large_files_with_store` shares one scanner traversal and output envelope with ordinary scan. The observer's `on_entry` delivers native observations before optional row retention/classification; `on_directory_coverage` delivers coverage before optional aggregate/index retention. Analyses requesting file facts fall back from logical-length cache reuse to current file observation, without inventing allocation or mount evidence. Ordinary junk scanning keeps its existing cache path. Only admitted ranked entries are copied; classifiers, junk candidates and execution authorization do not determine size ranking.

Explicit content analysis can use platform’s `stream_bound_regular_file` to read a requested range under a retained parent, with a fixed 64 KiB buffer and native identity, mount, size and change-stamp checks across stages and after reading. Chunks are provisional on any failure and cannot establish a complete hash. macOS prohibits dataless materialization on the issuing thread; Windows checks no-recall/provider/reparse boundaries; Linux admits only ext4, Btrfs and tmpfs. Callers still need a worker and cumulative IO, metadata and concurrency budgets; synchronous native reads use cooperative cancellation. Duplicate analysis now uses analysis’s DuplicateCollector and core’s scan_duplicates_with_store through explicit scan --duplicates. It shares current traversal facts, excludes hard-link aliases in a bounded size index, and performs full hashes only after sampling. Each stage and final check bind native identity, size and change stamps. Cumulative read/range-request/file-count/retention budgets are shared; cancellation/deadlines stop subsequent content stages. Failed chunks cannot establish digests, and unknown/provider/resource gaps remain partial. Content hashes are not persistently cached, and results grant no deletion authority.

`sweepx-core::junk::session` provides a background junk scan for explicit directory roots or automatic system discovery, connected to `junk --tui` through a CLI adapter. Phases, candidates, boundaries, errors and completion use a bounded queue with backpressure; progress and directory statistics coalesce. Stable candidate keys are separate from revisions. Selected refresh revalidates native bindings and removes old rows only after complete observation; cancellation or partial scans retain unconfirmed old evidence. The TUI formats only visible rows and keeps selection separate from scanning; background Trash reuses native binding checks and the existing Trash adapter. The shared macOS cache and file-reuse implementation now lives in core. Sessions emit explicitly historical previews, then rebuild current directory identities, classification and Git evidence; only complete observation can remove old keys. Cache failures fall back to fresh scanning. Full system refresh rediscovers roots, and macOS caches bind to that scope. System history is previewed after discovery, but the change cursor is captured before it. Linux temporary objects retain independent measurement facts and session identities, never fabricated directory aggregates or generic Trash identities. Refreshing them refreshes the full system scope; `x` now connects an independent quarantine preview, exact digest confirmation and result state; full native execution still needs Linux-host validation. Selected directory refresh retains the original root and native identity chain, recurses only into selected subtrees, and shallowly enumerates required ancestor rule and Git markers. Old ancestor statistics become historical while their native bindings remain available for another selected refresh. Complete marker enumeration is distinct from recursive coverage: truncated parent markers cannot produce negative classifications, and every selected directory needs complete coverage before old rows can be replaced. On macOS, complete local scans merge fresh selected file indexes with unchanged sibling directories validated against complete history. Old selected descendants, shallow ancestors and changed outside listings are omitted; nested roots retain their original attribution. The new cursor is captured before the history query and traversal, preserving racing changes for the next validation. Candidate fragments merge into v9 historical previews only: mixed scan identities and old ancestor totals cannot become whole-root hits. A later complete scan restores a whole-root record. Missing history, cancellation or partial observation does not advance the local generation. Each bounded cache file publishes atomically, without a cross-file transaction; omitted optional facts still require live inspection. Custom root-wide classifiers cannot use this local interface. Session cancellation is independent of the persisted `cancel` command below.

The Linux temporary-object service shares invocation budgets and cooperative cancellation across directory names, recursive fingerprints, process enumeration and mount/socket input. Resource failure cannot recover into a complete negative claim within that invocation. Reporting and cleanup revalidation use the same implementation with independent budgets and current reference observations.

Built-in local rules call the same classifier once a subtree is complete and its own and parent marker enumeration finish, emitting base candidates early; Git enrichment still runs afterward. Custom classifiers wait for root completion by default, and may explicitly declare uses_only_local_markers when all decisions, including negative predicates and rule precedence, use only own/parent markers. Closure uses flags and subtree counts, not copied hard-link sets; bytes have already been folded into ancestors, and delivered subtree state is released.

`junk::quarantine` separates native Linux temporary-object preview/execution from CLI rendering and stdin confirmation. Its opaque preview retains captured identities and execution bounds; serialized display plans cannot recreate it. Execution consumes it once and revalidates current native facts, while the digest binds loaded rule bytes. Path work, directory enumeration and content I/O are cooperatively cancellable and bounded. Pending siblings share a parent-directory fd instead of duplicating handles per name. Failures after removal begins can leave a partial source and a complete recovery copy, with no atomic rollback or permanent-deletion fallback. The TUI receives a display plan and final result through one-slot channels, while the worker retains the native preview awaiting full-digest confirmation. Trash and quarantine share one mutation-worker slot. Closing does not join, and native phases check cooperative cancellation. Both actions reuse confirmed-move reconciliation, removing descendants and marking ancestor accounting historical. Temporary measurements are shared through Arc instead of deep-copied during UI selection. Plans bind recovery-base native bytes; extra hex renders ambiguous non-UTF-8 paths, and equal lossy spellings cannot alias plan digests.

The retained progress log is bounded. Omitting progress detail alone does not make a complete scan partial. Error counts, cancellation and actual resource limits remain available independently; live sessions still receive reliable errors and completion.

CLI scan completes synchronously. On Linux, events are constructed as a batch after scanning, then the complete stream and terminal snapshot are committed to a bounded SQLite journal in one transaction; Core `status` is journal-first and supports degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`: it performs one same-snapshot full validation, then reads pages of at most 1024 events from a completed, persisted stream; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, this surface is not a live sink, does not wait for new events, does not create a background operation, and does not support cancel. macOS and Windows still write legacy operation snapshots; the Windows state directory is protected by a current-user-private DACL, an ownership check, and per-component reparse-point rejection. `scan --no-state` skips the corresponding operation-state writes for read-only scans that do not need later status/operation state or whose state filesystem does not support the journal, and it conflicts with `--state-dir`. Live cancellation remains disabled. `cancel` returns an honest disposition, which is why its capability is disabled.

Separate from scan/status, `cache status` reads only existing preview-cache state. Linux, macOS, and Windows support human/JSON output; NDJSON is a usage error. Missing state/cache returns `absent` without creating directories. `available` means only that bounded cache structure and validation are readable, not that any live/current filesystem fact is true; warnings, errors, or quarantine presence degrade the result.

`junk::format::ProjectFormatSession` performs serial content observation independently of the pure rule VM. The Dart profile uses bounded complete native reads under captured directories to recognize a self-declared pub v2 map and parent-project root reference. It never opens package URIs, parses pubspec YAML or runs the SDK. Every invocation/session revision rebuilds observations; filesystem caches omit format answers and historical/Base rows are `not_checked`. Defaults allow 256 KiB per file, 128 distinct candidates and 32 MiB of payload reservations. Failed attempts also charge worst-case requested work; per-attempt lineage/enumeration limits together with the attempt cap bound cumulative metadata work. The 5-second deadline is cooperative and cannot interrupt blocking kernel calls. Invalid contents, provider/permission/identity failures, resource limits and cancellation remain explicit. Even recognized shapes retain `project_ownership_not_verified`; Git cannot override it and CLI/TUI/background Trash refuse the profile. The legacy SvelteKit profile reuses this pipeline: it reads `tsconfig.json` and `ambient.d.ts`, then rereads each, comparing native identity, change stamps and payload. Inter-file changes become unknown; this is still not an atomic snapshot or proof of arbitrary TypeScript validity. It reserves four reads before the first I/O, allowing at most 32 SvelteKit-only observations within the shared 32 MiB requested-payload budget. Maximum attempts times four also bounds cumulative read/metadata work. Ambient contents are not persisted and JS configuration, aliases or globs are never evaluated or opened. Exclusive ownership, activity and broader actual-tool-version evidence remain unfinished.

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


Project-rule JSON `executionPolicy` accepts only `report_only` or `require_ownership_and_activity`; omission defaults to the latter and cannot inherit legacy deletion access. Generic `dist/build/out/.next/.turbo` and Dart/SvelteKit rules explicitly allow reporting only. Rust/Node/Python/Maven still lack independent exclusive-ownership and inactivity proof, so all current project candidates are refused by `junk --trash`, the TUI and background workers. Names, risk tiers, complete coverage, recognized formats or Git `ignored/high` cannot substitute for that proof. Reports add a locale-stable `executionPolicy`: project values are `report_only` or `require_project_ownership_and_activity`. Restored cache facts start as `not_checked`, then rebuild interpretation from current rules; old access is never persisted. Platform rows use `native_revalidation_required` and still need every existing native-identity, coverage and platform-boundary check; the label supplies no execution authority. Explicit standalone `trash PATH` operations retain their existing checks.

SvelteKit 1.0.0/2.0.0 format regressions include raw output from actual SDK sync runs, frozen dependency locks and per-file byte receipts, separately from authored structural fixtures. Normal tests consume them offline. Genuine generated directories containing personal files still refuse Trash, and macOS cache round trips reobserve current formats. Broader versions/configurations remain open; actual Dart SDK recordings for the selected versions have since been added below. These recordings prove neither ownership, inactivity nor the installed version on a scanned machine.

Actual offline pub recordings from Dart 2.18.0/3.6.0 cover standalone projects, member-invoked shared workspaces and Unicode/space member paths. The format profile recognizes their percent-encoded UTF-8 filename signatures, retaining an allocation-free ordinary ASCII check. Invalid encodings, controls, encoded separators/dots and unsupported URI syntax remain unknown. It does not parse YAML, resolve general URI semantics or open URI locations. Ordinary reads verify preserved sources, locks and member notes; a recognized root map proves neither exclusive ownership nor inactivity.

Rust target candidates read parent Cargo.toml through captured native lineage and display current package/workspace declarations in CLI/TUI. The additive JSON projectContext field uses observed / invalid / unknown / not_checked; memberPatterns counts declared strings rather than resolved workspace members. Current .cargo/config and .cargo/config.toml below that parent are also observed, with supported target-dir declarations reported separately in cargoConfig. The additive pathKind field describes host lexical absolute / parent_relative / relative spellings (also drive_relative / root_relative on Windows). Absolute and parent paths can be reported without opening or normalizing them, or expanding tilde/environment references; raw path values are not retained. Enumeration absence remains unknown, observations are non_atomic, and precedenceComplete stays false: this does not select an effective config file or output directory. No Cargo process, glob expansion or complete precedence resolution runs. Context and generated-format observations share bounded invocation budgets; filesystem caches retain no declaration answers, and each invocation/revision reobserves them. Declarations do not establish exclusive ownership or inactivity, so project Trash restrictions remain.

Core also exposes `scan_file_analysis_with_observer` and worker-local `FileAnalysisSink`. Provisional rankings may coalesce; final rankings and verified duplicate cohorts precede the enclosing terminal return. Only the scan return proves successful scope completion, including state persistence. Duplicate live stamps stay out of JSON. CLI owns bounded queues, stable native keys, keeper choices, rehash preflight and shared Trash-worker admission; TUI reuses the existing list/event/terminal mechanics and never reconstructs filesystem authority from displayed paths.
