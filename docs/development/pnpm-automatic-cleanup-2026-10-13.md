# Automatic pnpm cleanup verification, 2026-10-13

This slice supersedes the mandatory user selection/preview digest described in
[the earlier project-cleanup verification](pnpm-project-cleanup-2026-10-13.md).
[The CLI contract](../../site/en/cli.md#pnpm-store--osdk-cache) and
[the native inventory design](../architecture/managed-cache-inventory.md) describe the
current behavior.

```sh
sweepx pnpm-store --project /absolute/project
sweepx pnpm-store --project /absolute/project --trash
sweepx pnpm-store --root /absolute/store --trash
sweepx pnpm-store --trash
```

Stores are discovered from installed YAML/JSON declarations, project-local `.pnpm-store`
containers (including projects whose dependencies were already removed), environment,
a bounded manager query and defaults. Explicit roots accept version roots or containers.
Ordinary cleanup requires neither `entry` nor `plan`; the old advanced flags remain hidden
for compatibility. Project cleanup preserves sources unless whole-project scope is explicit.
There is no external pnpm prune invocation or permanent deletion fallback.

## Program and native fixture checks

Host: macOS arm64, pinned Rust 1.98.0. Functional execution checks use temporary fixtures;
no real user project dependencies were retired in this implementation slice.

- Core/CLI tests with all features passed, including CLI integration tests and native
  resource-authority integration tests. Default ignored cases remain separate.
- Managed-cache regressions cover discovery beyond 20,000 source directories, a JSON
  index over the former 8 MiB bound, YAML/JSON markers, absent declared stores, local
  orphaned stores, workspace hard-link deduplication, source/build exclusion, 300 shared
  package owners, and 8,250 exclusive files delivered in batches of at most 128.
- Native project identities/paths, rather than editable display labels, select and reopen
  dependency targets. Replaced project directories refuse before mutation.
- A saved invocation observation cannot authorize cleanup after a new installed reference;
  fresh execution discovery refuses before the callback runs. Unknown identity/index
  formats, changed objects and unaccounted links remain protected.
- Legacy side-effect files named `added`/`deleted` stay valid; a delta's `package.json`
  cannot supply the base package identity. The large JSON fixture demonstrates bounded
  streaming and shared ownership, not replay of the former 484 MiB host record: that
  original record was removed by the preceding official-manager cleanup and is unavailable.
- Four explicitly enabled macOS native Trash scenarios passed: project-only automatic
  dependency cleanup, explicit whole-project scope, preservation of another project's
  copy/store object, and automatic global selection of 270 shared index owners without
  `entry`. Independent device/inode checks verify native Trash and preservation of
  source/lockfiles, shared content and package indexes.
- `cargo fmt --all --check` and host workspace Clippy with all targets/features passed.
  Linux GNU and Windows GNU workspace cross-target Clippy passed with Zig 0.16.0 and
  task-private caches/wrappers. These are configuration checks, not target runtime evidence.
  Windows execution still refuses the unavailable activity guard; Linux execution was not run.
- Documentation lint and whitespace checks passed. The optimized CLI build passed; the
  existing local `sweepx` symlink points at this workspace's release binary.

The new batch planner reserves native calls from the already bounded ownership graph,
retaining its deadline, cancellation and per-file checks. It does not merely split selected
IDs and accidentally retain content shared across those batches. Reports retain bounded
path samples and exact operation counts; cleanup logical bytes deduplicate shared owners.
Directory traversal uses retained native handles, no-follow inspection and mount checks.
Logical file totals use ordinary scanner metadata: native file identity/filesystem domain
are sufficient to deduplicate hard links; missing file mount evidence remains unclaimed
and cannot authorize execution.

## Real read-only observations

The release CLI inventoried the v10 store with reference root
`/Users/bytedance/Desktop/Projects`. Discovery completed with 16 pnpm installations,
no inventory issues and exact completed package totals. Nested rows overlap; excluding
children already included in a parent gives these largest project package footprints:

| Project | Logical pnpm package bytes | GiB |
| --- | ---: | ---: |
| account_fe | 5,610,924,538 | 5.23 |
| temp/temp_merchant_mono | 3,354,435,849 | 3.12 |
| merchant_center_mono | 3,304,946,131 | 3.08 |
| temp/codeInspectorPlugin | 2,699,985,161 | 2.51 |
| account_center_cooperate | 2,328,045,046 | 2.17 |

Separate current ordinary no-follow walks matched account_fe exactly (526,563 unique
regular files) and omem exactly (738,057,873 bytes; 23,200 unique regular files).
Totals measure `node_modules/.pnpm`, include nested installations and count a hard-linked
object once within each project. They exclude project sources, build output and global
stores. They do not prove physical allocation, APFS clone extent uniqueness or reclaimable
space. No real store/project cleanup was executed during these observations.

These scoped completed observations do not establish whole-machine or other-user disuse.
Native process/open-file checks are time-local evidence, not exclusive locks. Package
indexes remain for refetch, and recoverable Trash does not immediately release capacity.
