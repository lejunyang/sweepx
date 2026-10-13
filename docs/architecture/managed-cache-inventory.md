# Managed cache items

`pnpm-store` and `osdk-cache` are independent analyses over the native scanner and loaded
platform rule bytes. `tool.pnpm-store` and `tool.osdk-data` carry `itemInventory` and cannot
be moved wholesale by `junk --trash` or the generic junk TUI. Their child classification IDs
are `tool.pnpm-package`, `tool.osdk-model`, and `tool.osdk-download`. The report and selection
IDs bind the SHA-256 of admitted rule bytes. No hand-maintained digest is needed.

```sh
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects --tui
sweepx pnpm-store --root /absolute/pnpm/store/v10 --project-root /absolute/projects --max-links 1 --unobserved --format json
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects --trash
sweepx osdk-cache --project-root /absolute/projects --tui
sweepx osdk-cache --project-root /absolute/projects --entry CURRENT_DOWNLOAD_ID --trash
sweepx osdk-cache --project-root /absolute/projects --entry CURRENT_MODEL_ID --remove-models
```

Global options such as `--format json` may be placed before the command when using a parser
that does not accept trailing global options. Without an action flag, selection is a preview.
`pnpm-store` accepts an optional version root/container, or discovers stores from installed YAML/JSON metadata, environment, a bounded manager query and platform defaults. Discovery never creates a store or probes hard-link support. OSDK defaults come from its bounded `--offline config list`
answer, or `OSDK_DATA_DIR`/`OSDK_CACHE_DIR`; redirected locations can be supplied explicitly.

## pnpm

Supported layouts are v3/v10 JSON indexes and the v11 `package_index` SQLite table with
self-contained msgpackr records. Unknown extensions, malformed records, unreadable content,
SQLite WAL/journal sidecars and resource limits produce partial evidence and block cleanup.
Checkpointed WAL-mode main files are supported only when no WAL/journal is observed; the private copy's header is normalized for in-memory use without touching the source. SQLite bytes are read through the existing identity-bound native streaming reader and deserialized into an in-memory,
query-only connection; the database is never opened using a display path. Legacy indexes without
identity are resolved from their indexed native `package.json`. Unidentified rows retain all
content ownership and cannot be cleaned. Selection IDs also bind the resolved package name/version;
a changed legacy manifest refuses a previous selection even when the index bytes stay identical.
Full v3 side-effect maps and v10/v11 added/deleted
build deltas retain content ownership across platforms; unsupported shapes and fallback indexes
fail closed. Package totals include those indexed build objects.
Legacy JSON uses a streaming ownership projection. Small records use bounded native bytes; records over 8 MiB stream through an identity-bound native reader into an automatically removed private spool (768 MiB per record, 1 GiB cumulative native index bytes). Only compact binary CAS hashes are retained; platform side-effect owners are unioned. Per-record bounds include 4,000,000 file records, 2,000,000 unique digests, 8,000,000 projected fields and 64 KiB JSON string tokens. Cancellation and a 900-second deadline remain active during parsing. Total retained package metadata is capped at 256 MiB, with at most 2,000,000 content references and 65,536 package rows. Bounds are component reservations, not process RSS claims. Malformed/unsupported/over-budget records report their location and block store cleanup; other records can still receive read-only accounting.

Large legacy stores use a 900-second native-observation worker budget, exposed as
`timeBudgetSeconds`; queues, indexes, bytes and calls remain bounded. A project total has
a separate bounded native walk. Cancellation still stops observations; exceeding any bound
produces partial evidence and refuses cleanup.

File hard-link minimum/maximum and single-link counts are separate from installed project
references. On APFS, clone/copy imports can leave a store file with one link while a project
still uses that package. Project references match observed installed `.pnpm` package/version
layout labels and conservatively include the same version even across store generations.
They are usage hints, not exact inode linkage or proof of an active runtime. Lock-only,
custom virtual stores, global virtual-store links, unsearched projects and other users are
not inferred. `storeDir` is read from YAML or JSON `.modules.yaml`; missing declared stores remain discovery issues. Project `storeStatus` reports advisory directory admission as `observed`, `unavailable` (missing/linked/denied) or `not_checked`; it does not validate the store index or authorize cleanup.

Reference roots are reported explicitly. Defaults protect the current directory and existing common home project locations; project cleanup protects its parent directory. Optional `--project-root` overrides/extends the scope with the selected project always included. Discovery skips node_modules, Git internals and named build/cache trees. A retained-handle depth-first walk uses native bound-child inspection, 128-entry/64 KiB pages, at most 64 ancestor handles, 2,000,000 entries, 1,024 projects, 64 MiB of cumulative captured project-root metadata reservations and 900 seconds. No-follow, mount, permission, provider and cancellation failures keep coverage incomplete. Candidate paths are hints only: each installed project is reobserved through the existing native adapter before metadata/labels are read.

pnpm project totals cover only installed `.pnpm` virtual stores, aggregate workspace children and deduplicate hard links by native identity/filesystem domain within the project. Ordinary file mount evidence can remain unknown, as in ordinary scanner logical totals; no parent mount is inferred and no execution authority is supplied. Directory traversal still checks exact mount identity and file observations reject a different native filesystem domain. The identity set is bounded by 2,000,000 entries and a conservative 128 MiB reservation. Incomplete sizes remain lower bounds/unknown. OSDK retains whole-project logical totals. Nested project rows overlap; neither size is reclaimable space.

A cleanup plan re-inventories current indexes, native content and the original search scope.
Changed selection IDs or incomplete coverage refuse execution. Content referenced by any
unselected package index remains, as do files with multiple, lower-bound or unknown native links;
only an exact one-link observation admits a file. Observed
project references block that package's cleanup. Automatic CLI cleanup selects admitted entries without user IDs. Up to 65,536 package indexes share one ownership decision, then native file observations are emitted in batches of 128. The content planner reserves one bound-child call per unique digest plus 512 setup/shard calls, with the two-million reference cap and 900-second deadline unchanged. CLI output retains at most 256 successful path samples plus exact operation counts and failures. The compatibility collected-plan API retains its 256-item/8,192-file limit. Every moved ordinary file is revalidated through the
existing native Trash adapter; failures stop the batch and never cause a permanent fallback.
Package indexes remain: pnpm detects missing content and downloads it when required again.
Verified absence from a complete CAS enumeration is reported as `missingFiles`; the current
bytes of absent files are not unknown observations. Subsequent selections can still remove
remaining exclusive content, while missing/refused enumeration produces partial evidence.
A selected package may retain shared bytes; cleanup is not a claim that the index disappeared.

## pnpm project retirement

Project/dependency scope is an independent plan over the same pnpm index/reference inventory,
not a second classifier. `pnpm_project_inventory` omits unrelated whole-project totals. Explicit
search roots are supplied internally; project-side native dependency trees are walked without following links.
Captured native project identities and lossless paths, never display labels, select and reopen target dependency directories. Replaced project/workspace roots refuse before mutation. A selected package version must have an installed declaration of this exact store and no observed
outside-project reference. All unselected index content ownership is retained. A CAS path can enter
the plan only when its exact native link count equals one store path plus the counted occurrences
in selected dependency directories. Unexplained extra links stay. Copy/clone references outside the
selected subtree block package selection even with a single CAS link.

The digest binds rules, all index tokens, reference labels/store declarations, the selected marker,
native target identities and an order-independent dependency-entry digest plus entry count. Execution
builds the current plan internally; an optional hidden legacy `--plan` can additionally require digest equality; directory and file identities are checked
again immediately before native Trash. Trash keeps project-side links alive, so the original counted
links remain relevant. Added/removed links or changed CAS metadata refuse that file. Directory moves
precede file moves; every successful outcome survives a later refusal. No rollback or permanent
fallback is attempted. Activity probes are current-user, time-local evidence, not an exclusive lock.
A shared store contained inside a whole-project target is refused. Custom/linked layouts remain
unsupported; nested source projects without exact store declarations do not grant CAS authority.

The admitted plan retains at most 65,536 CAS rows/64 MiB, 256 dependency roots, a 4,096-directory/
64 MiB frontier and a 2,000,000-entry/identity-set bound. Index limits continue to apply. This does
not waive a malformed/oversized index or claim an unbounded whole-machine reference search. The
TUI exposes scoped preview commands; project execution is CLI-only. See both CLI language pages.

Dated host and fixture evidence is recorded in
[the original project cleanup verification](../development/pnpm-project-cleanup-2026-10-13.md) and
[automatic cleanup verification](../development/pnpm-automatic-cleanup-2026-10-13.md).

## osdk

The supported local format contract was checked against OSDK 0.0.5 on 2026-10-07: offline
`config list` reports `data_dir`/`cache_dir`; model aliases contain `current.json`, native
`snapshots`, and schema-1 `.osdk-model.json` metadata. This repository-owned contract is
referenced by the OSDK platform rule because the installed tool's CLI and schema are the
primary evidence available to this integration. It does not treat arbitrary model names or
file sizes as disposability evidence. Unsupported formats fail closed.

The model row is an alias and includes all its snapshots. Project declarations are observed
from native `osdk.toml`/`.osdk.toml` `[models]` tables, without running project tasks. A declaration
does not establish recent use; an absent declaration in the search scope does not prove disuse.
Download rows are separate cache units, with model downloads split by provider/namespace/repo.

Selected downloads use recoverable native Trash. Model rows cannot be Trashed by the TUI's
`d` action. `--remove-models` is a separate, explicit tool operation: after a fresh inventory,
current-user process check and native alias/manifest revalidation, SweepX invokes
`osdk --offline --yes model remove -- NAME` with the captured native data directory. It is not
recoverable Trash. The manager preserves declarations and locks and handles snapshot/view
state. The installed 0.0.5 manager can reclaim unreferenced model CAS objects during removal;
CAS objects still used by another alias remain. SweepX does not additionally invoke global
`prune`. Future sync can download declared models again.
A timeout or failure is reported as uncertain tool state, without automatic retry or fallback.

## Execution and UI bounds

Native no-follow, mount, provider and permission boundaries are inherited from the scanner.
Link counts are optional native scan facts; legacy and length-only cached rows omit them.
Filesystem facts never cache project activity or configuration claims. The cache TUI uses one
cancellable worker, a one-result bounded channel, and worker-prepared row text. It retains at
most 16,384 visible rows and 64 MiB of presentation data. `Enter` opens a bounded, scrollable
reference/size detail view; truncated text is labelled, while JSON keeps the full bounded
inventory. Cancellation and unexpected worker exit have explicit terminal states.

Cache/model execution currently requires the macOS/Linux current-user process/open-file
activity guard; Windows has no equivalent guard and refuses execution. Read-only native
inventories remain available. Runtime verification on macOS does not establish Linux/Windows runtime behavior. Cross-target
lint checks the corresponding native branches; tool-specific schemas and fixture behavior
are tested independently of the machine's real user data.

## Verification on 2026-10-07

macOS arm64, Rust 1.98.0 and installed OSDK 0.0.5; no real user cache/model was removed.
Controlled native fixtures verified pnpm exclusive-file Trash while preserving shared/multi-link
content and indexes, and fresh inventory after removal. OSDK fixtures imported two aliases
sharing one object and removed only one through SweepX: the other alias, shared object, source
and project declaration remained. A separate single-alias fixture observed the manager reclaim
an unreferenced CAS object; a blanket “CAS remains” claim would therefore be incorrect.
The TUI was exercised in an interactive terminal, and a rendered-buffer regression checks that
project references retain separate lines in the detail view.

Sandboxed native Trash/FSEvents tests initially failed because the host denied those system
operations. Those tests passed with normal permissions; failed attempts were not treated as
passing evidence. Cross-target lint checks Linux GNU and Windows GNU configuration branches,
not their runtime behavior.

Index and manifest reads use the scanner's fixed child inspection plus existing zero/full
native stream, retaining no-follow/provider/mount and file-stamp checks while avoiding repeated
ancestor sibling enumeration. Invalid UTF-8 directory fixtures are Linux-only because APFS
rejects their creation; the lossless native locator/path representation is tested on Unix hosts.
