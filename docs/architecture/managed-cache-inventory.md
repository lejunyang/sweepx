# Managed cache items

`pnpm-store` and `osdk-cache` are independent analyses over the native scanner and loaded
platform rule bytes. `tool.pnpm-store` and `tool.osdk-data` carry `itemInventory` and cannot
be moved wholesale by `junk --trash` or the generic junk TUI. Their child classification IDs
are `tool.pnpm-package`, `tool.osdk-model`, and `tool.osdk-download`. The report and selection
IDs bind the SHA-256 of admitted rule bytes. No hand-maintained digest is needed.

```sh
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects --tui
sweepx pnpm-store --root /absolute/pnpm/store/v10 --project-root /absolute/projects --max-links 1 --unobserved --format json
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects --entry CURRENT_ID
sweepx pnpm-store --root /absolute/pnpm/store/v11 --project-root /absolute/projects --entry CURRENT_ID --trash
sweepx osdk-cache --project-root /absolute/projects --tui
sweepx osdk-cache --project-root /absolute/projects --entry CURRENT_DOWNLOAD_ID --trash
sweepx osdk-cache --project-root /absolute/projects --entry CURRENT_MODEL_ID --remove-models
```

Global options such as `--format json` may be placed before the command when using a parser
that does not accept trailing global options. Without an action flag, selection is a preview.
`pnpm-store` requires the exact versioned root; it does not guess a store generation or create
one by probing hard-link support. OSDK defaults come from its bounded `--offline config list`
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
An oversized or malformed JSON record reports its native index location and blocks cleanup for
the entire store; other bounded records still receive read-only link and byte accounting.

Large legacy stores use a 900-second native-observation worker budget, exposed as
`timeBudgetSeconds`; queues, indexes, bytes and calls remain bounded. A project total has
a separate 60-second bound. Cancellation still stops observations; exceeding any bound
produces partial evidence and refuses cleanup.

File hard-link minimum/maximum and single-link counts are separate from installed project
references. On APFS, clone/copy imports can leave a store file with one link while a project
still uses that package. Project references match observed installed `.pnpm` package/version
layout labels and conservatively include the same version even across store generations.
They are usage hints, not exact inode linkage or proof of an active runtime. Lock-only,
custom virtual stores, global virtual-store links, unsearched projects and other users are
not inferred. `storeDir` is reported when present in `.modules.yaml`.

The chosen search roots are explicit; the default is the current directory. Discovery skips
node_modules, Git internals, common build/environment trees and generated `.omem`/`.cache`/`.next` child trees. The machine report lists `projectExcludedNames`; adding an excluded directory as an explicit root searches it. Limits include 32 search
roots, 20,000 searched directories, depth 32, 1,024 observed projects and a bounded frontier (shallow siblings first, then depth-first source traversal).
Project references are discovered before measuring totals; an isolated size deadline never cancels
reference discovery. Whole-project logical totals come from a separate native traversal, including dependencies
and build outputs; partial totals stay lower bounds or unknown. Project sizes can overlap
when projects are nested. Neither package sums nor project totals are reclaimable bytes.

A cleanup plan re-inventories current indexes, native content and the original search scope.
Changed selection IDs or incomplete coverage refuse execution. Content referenced by any
unselected package index remains, as do files with multiple, lower-bound or unknown native links;
only an exact one-link observation admits a file. Observed
project references block that package's cleanup. At most 256 package IDs and 8,192 exclusive
content files are admitted per batch. Every moved ordinary file is revalidated through the
existing native Trash adapter; failures stop the batch and never cause a permanent fallback.
Package indexes remain: pnpm detects missing content and downloads it when required again.
Verified absence from a complete CAS enumeration is reported as `missingFiles`; the current
bytes of absent files are not unknown observations. Subsequent selections can still remove
remaining exclusive content, while missing/refused enumeration produces partial evidence.
A selected package may retain shared bytes; cleanup is not a claim that the index disappeared.

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
