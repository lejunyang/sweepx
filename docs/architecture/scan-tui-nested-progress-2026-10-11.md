# Scan TUI nested live sizes — 2026-10-11

[Concurrent navigation](scan-tui-concurrent-navigation-2026-10-11.md) made lists immediately
available, but recursive progress still projected only onto the scan target's direct rows. Opening
an inner directory therefore showed unmeasured folder zeros until the enclosing scan committed its
size snapshots. This change streams the existing traversal's nested presentation facts as well.

## Behavior and boundaries

- Ordinary progressive browsing marks unmeasured directory rows NotChecked (Waiting / 等待扫描),
  rather than displaying an assumed zero. Direct files retain their native observed lengths.
- Every periodic recursive progress update includes lower-bound sizes from the active DFS chain.
  Each frame already includes its own files and finished children; a leaf-to-ancestor fold adds
  only the unfinished child chain. The fold never mutates those accumulators, so later child pops
  do not count provisional bytes twice. Frame snapshots are bounded by the existing handle/frontier
  budget. Full-fact inspection paths without directory callbacks retain their existing behavior.
- The CLI keeps a separate advisory progress index, with at most 16,384 native directory keys and
  an estimated 16 MiB including both indexes and owned root keys. Updates replace existing keys;
  oldest observations are evicted to admit later progress. Completed sibling subtrees enter this
  index immediately, so coalesced/dropped queue messages do not leave them at zero. Older partial
  samples cannot decrease a newer value. This index never populates the completed reuse cache.
- UI polls sample only their current directory header and direct folder identities from memory;
  a contended lock omits the sample instead of blocking the UI. Sampling performs no filesystem
  I/O and starts no additional traversal. Native root, file, filesystem-domain and mount identity
  keys match scanner facts across independently allocated row IDs. The response is rebound to
  the requested identity, and the browser validates the complete response before updating rows.
- Values remain lower bounds while the enclosing traversal runs, including completed siblings.
  Detail-loss markers stay intact; provisional aggregates remain incomplete. On any actual size
  change, sorting includes all direct rows, allowing previously off-screen folders to rise into
  view, while selection remains bound to the same entry. Counting / 统计中 reflects an active
  ancestor scan even when the current list has finished loading.
- Root completion retains the existing reliable results and committed-snapshot update. Refresh
  resets advisory progress for the new recursive generation. Native lineage/no-follow, mounts,
  permissions, row/handle limits, cancellation and completion gates remain in force. These are
  display observations, never freshness, allocation, reclaimable bytes or mutation authority.

## Controlled verification

A native fixture slows two file observations under `child/deep`, each delayed by an independently
specified 200 ms, exceeding the presentation interval. Before that child completes, both its active directory and ancestor report
the same positive byte lower bound. Final recursive bytes and entry counts match an ordinary walk,
proving that streamed active contributions are not counted again when frames complete.

A synchronized TUI provider holds root aggregation closed while returning the inner folder list.
Samples first give `a=10`, `z=5`, then `z=50`. The visible order changes from `a,file,z` to
`z,a,file`; the selected `a` stays selected, rows show Counting, detail-loss coverage stays intact,
and the original root is still pending with exactly three requests and no cancellation. Back/Enter
retains the updated list. A separate contract rejects an entire sample batch with a foreign/unknown
native mount identity, preserving all original values. Advisory-index tests cover native ID rebinding,
no exact publication, nondecreasing sizes, both retention caps, replacement without index growth,
and continued admission after eviction.

## Native acceptance and checks

Host: macOS 26.5.2 arm64, Rust 1.98.0, debug CLI in a 160 × 32 PTY. Both locales use new
`scan --no-state --tui /` invocations, with OS caches uncleared. Build/check activity and earlier
acceptance runs can warm the host. Captured timings are functional observations, not isolated
throughput comparisons or percentile estimates. No cleanup was selected during navigation.

The native driver enters `/System` during the original root traversal, checks displayed names
against independent `os.scandir`, then observes `Library` growing across two updates while the
root entry count advances. Visible measured sizes stay descending and unvisited folders show
Waiting / 等待扫描. Returning/reentering retains the updated list. Deeper `/System/Library`
acceptance checks a direct folder growing while root work remains active.

- en-US: `/System/Library` grew from 1,639,795,159 to 1,679,862,469 B on the `/System` page.
  Inside `/System/Library`, `CoreServices` grew from 328,220,239 to
  339,888,575 B. Both observations preceded root completion, retained descending order
  and exited normally after navigation.
- zh-CN: `/System/Library` grew from 1,679,879,376 to 1,698,197,524 B on the `/System` page.
  Inside `/System/Library`, `CoreServices` grew from 247,883,035 to
  250,503,881 B. Both observations preceded root completion, retained descending order
  and exited normally after navigation.

One deep-view diagnostic initially observed a viewport containing already measured small folders,
while the current directory's header continued to grow. The selected initial file had been retained
through sorting; the driver now moves the viewport to the largest rows before observing growth.
A subsequent attempt flooded the PTY with 512 Up keys without draining output. Host sampling showed
the Python driver blocked in `os_write`, the CLI UI blocked in stdout `write`, and both detail
workers idle on their bounded request receivers. Only those task-owned processes were stopped.
The corrected driver alternates individual key writes with output reads, preserving the name,
nondecreasing-size and descending-order assertions. No product assertion was weakened or skipped.

Validation:

- Focused native scanner progress, TUI held-root sorting/selection/identity, and advisory-index
  resource/identity tests passed.
- `cargo test --workspace --all-targets --all-features -- --test-threads=1` passed: scanner 112
  unit tests and three native tests, CLI 73 unit and 78 command-contract tests, TUI 112 tests,
  plus the remaining workspace/integration suites. Five existing opt-in benchmarks remain ignored.
  The final TUI 112-test suite was rerun after preserving detail-loss coverage in live updates;
  unchanged workspace results were reused.
- An earlier restricted affected-crate run passed CLI units/browser tests but failed the ordinary
  machine-invocation Trash contract because macOS denied the fixture's native Trash operation.
  Later steps of that command were untested. The same preserved contract passed in the full
  native-permission workspace run; this was an execution-environment change, not a suppressed test.
- Final workspace `cargo clippy --workspace --all-targets --all-features -- -D warnings` passed,
  covering the affected crates and tests. Workspace Linux GNU and Windows GNU cross-target Clippy
  passed with the configured Zig wrappers. Those are source/target checks; native Linux/Windows
  interactive runtime remains unverified on this macOS host.
- `cargo fmt --all --check`, `git diff --check`, repository documentation lint and the final CLI
  build passed. The installed `~/.local/bin/sweepx` points at this checkout's rebuilt debug binary.

Final native values and localized terminal captures are recorded in
[the validation artifact](scan-tui-nested-progress-validation-2026-10-11.json).
