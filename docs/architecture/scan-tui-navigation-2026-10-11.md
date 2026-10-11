# Scan TUI navigation reuse — 2026-10-11

The progressive browser always started a listing followed by recursive aggregation when entering
a directory. Its scanner already visited descendants but discarded their completed sizes. Returning
to a parent retained its direct rows, yet entering that parent or a visited child still requested a
new scan. A finished incomplete total also kept the same “Scanned size” caption as active work.

## Delivered behavior

- The header's **Scanned size / 已扫描大小** is the active directory's accumulated file bytes.
  It becomes **Total size / 总大小** when complete, or **Counted size (partial) /
  已统计大小（有遗漏）** when finished with gaps. A row's **Complete / 已完成** describes that
  row's size observation. Active lower-bound rows say **Counting / 统计中**.
- Recursive logical traversal can emit completed per-directory size/count/coverage observations
  during the existing DFS. Per-frame state stores lengths and counts, not descendant file rows or
  hard-link ledgers. Allocation, uniqueness and reclaimability remain unknown for length-only
  descendant observations, including an empty directory.
- The ordinary CLI adapter stages at most 16,384 directory sizes and an estimated 16 MiB per
  generation. It publishes them only after the enclosing native traversal succeeds. Keys include
  scan-root scope, device/file identity, filesystem domain and native mount identity. No executable
  descendant locator, classification or cleanup permission is cached. Live and staged generations
  can coexist; the estimates are retention admission limits, not process RSS limits.
- First opening a measured child performs a current, identity-bound direct listing. It rebinds the
  recorded aggregate to the new directory ID/revision and uses recorded child-directory sizes.
  A changed immediate child count refuses the target-size hit. Missing snapshots fall back to
  normal recursive measurement. The UI calls this phase **Opening directory / 正在读取目录**.
- Already browsed directories retain their lists and recursive-completion state. Back and repeated
  entry need no scanner request. Selection returns to the directory by identity even after live
  size sorting. The existing 16,384-entry/48 MiB estimated browser index remains bounded; under
  pressure it evicts off-breadcrumb lists in one pass, preserving directory rows/native recipes.
  A revisit can list those children again and still reuse available sizes. If the current list and
  required navigation chain themselves cannot fit, the existing resource-limit failure remains.
- The footer explicitly labels **Scan-time results / 本次扫描结果**. Press **r** to rescan the
  current ordinary directory. Refresh clears the provider's size generation and invalidates old
  directory totals/list reuse in the model. Old totals become not-checked, not lower bounds on a
  changing filesystem. Native bindings, no-follow admission, mount checks, cancellation, bounded
  event delivery and pre-Trash revalidation remain independent of display reuse.

These are historical observations within one interactive session. They do not establish that an
unchanged inode still has unchanged descendants; deep edits require explicit refresh. This is not
a fresh filesystem-fact cache hit or an inference from empty change history. Junk breakdowns retain
their full-fact accounting and do not consume ordinary size snapshots.

## Native evidence

Host: macOS 26.5.2 arm64, pinned/active Rust 1.98.0, debug executable based on `ff10de1` with this
change. Read-only terminal runs used 160×32 cells, `scan --tui --no-state`, and no cleanup action.
OS caches were not cleared. Each final workload/locale has one recorded repetition. Timings below
are end-to-end observations of the terminal reaching Finished, including polling floors (200 ms
for initial/open/refresh, 100 ms for back/reopen); a further 150 ms stability window precedes the
next action. They are functional observations, not scanner CPU time, p95/p99 or a before/after
speed comparison. Earlier diagnostic runs are not combined into these timings.

| Final run | Initial root | First child listing | Back | Reopen retained child |
| --- | ---: | ---: | ---: | ---: |
| Controlled fixture, English | 0.278 s | 1.104 s | 0.118 s | 0.117 s |
| Controlled fixture, Chinese | 0.243 s | 1.106 s | 0.108 s | 0.109 s |
| `dev-flow`, English | 1.068 s | 0.232 s | 0.114 s | 0.113 s |

The fixture contains 5,002 files in three directories, with an independently walked total of
81,037 bytes; child `a` contains 81,000 bytes and `a/deep` 68,000 bytes. Both languages verify
those totals across navigation, explicit refresh and normal exit. The dev-flow run opened
`node_modules` after the root finished: 170,183,004 bytes remained the same on repeated entry.
An independent no-follow ordinary walk counted 12,903 files, 2,428 directories and 414 links,
with no errors, and matched the root's 224,451,068 bytes exactly. Its 22.544 s duration measures
the separate oracle path and is not an old SweepX benchmark. The measurements are dated host
observations; they are not current size guarantees for those paths.

One diagnostic driver's exact oracle assertion failed when two drivers concurrently rewrote the
same controlled fixture during the oracle walk. The driver now writes fixtures only for fixture
runs, and those runs are sequential. The exact assertions were retained; the final captures use
that isolated driver. No product assertion was relaxed to obtain matching totals.

[Terminal captures and oracle evidence](scan-tui-navigation-validation-2026-10-11.json) contain
bounded screens for each phase. Controlled protocol tests independently count provider requests:
root listing plus root aggregation, then one cached child listing; repeated child/root navigation
adds no requests. Explicit refresh adds a listing and aggregation. Additional tests cover partial
result reuse/captions, bounded history eviction, native key isolation, retention caps, per-directory
sizes/counts against an ordinary walk, and cancellation in the final directory callback.

## Checks and limits

- `cargo fmt --all --check` and workspace Clippy with all targets/features: passed.
- `cargo test --workspace --all-targets --all-features -- --test-threads=1`: passed; five existing
  opt-in benchmarks remained ignored. Scanner: 108 unit tests plus three native integrations;
  CLI: 71 unit tests, three browser-bridge integrations, 78 CLI contracts and one elevation
  contract; core: 399 unit tests, three opt-in benchmarks ignored; TUI: 104 tests.
- After the final TUI-only bounded-eviction, reading-directory labels/placeholders and rendering
  assertions, all 104 TUI tests passed again. The final TUI also passed host/Linux/Windows Clippy
  with all targets/features. Unchanged workspace-crate results were reused. No failed test was
  excluded.
- Final workspace Clippy for `x86_64-unknown-linux-gnu` through `scripts/cross-lint.sh`, and
  `x86_64-pc-windows-gnu` using the existing Zig wrappers: passed, including test cfg branches.

The implementation is shared across desktop Linux/macOS/Windows. Actual terminal/filesystem
acceptance here is macOS evidence; Linux/Windows runtime remains unverified. Single-threaded
test success does not establish success under parallel test scheduling.
