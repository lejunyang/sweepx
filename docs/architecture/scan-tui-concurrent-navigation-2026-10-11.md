# Concurrent Scan TUI navigation — 2026-10-11

This supersedes the child-list waiting limit in [active navigation](scan-tui-active-navigation-2026-10-11.md).
That implementation preserved the root request, but its single worker still serialized an unvisited
child's direct listing behind the entire root traversal. The CLI also held its shared detail-ID
allocator lock for all native I/O, so merely adding a thread would still have blocked listings.

Opened-directory rows now also update during the root traversal; see
[nested live progress](scan-tui-nested-progress-2026-10-11.md).

## Delivered behavior and contracts

- Progressive browsing retains one recursive worker and lazily admits one independent direct-list
  worker. Each lane has one pending request, capacity-one request/completion/progress channels and
  its own cooperative cancellation token. The listing adapter does not replace the recursive
  progress sink. Both workers consume the existing process-wide 32-worker admission limit; failed
  secondary admission reports a resource failure without cancelling the original traversal.
- First opening a child starts a current, identity-bound direct listing immediately. Existing lists
  remain available immediately. Returning or switching pages cancels only an unfinished listing;
  the same bounded lane serves the current page when its cancelled job returns. Abandoned visits
  never form an unbounded queue. Native I/O can still fail or take time; this does not make an OS
  call synchronous or promise a hard real-time deadline.
- The detail allocator reserves an independent range for each native query under a short lock and
  releases it before scanning. Every range admits at most `usize::MAX` newly allocated IDs, covering
  the scanner's maximum representable visit count. Query ranges cannot overlap; exhaustion fails
  closed, and a failed reservation does not advance the pool. Manual allocator clones remain
  copies of the same range, not concurrent namespaces.
- Results in either lane may rebuild browser indexes. Before accepting progress/completion, each
  pending request resolves its index again through its original scan/native-directory binding.
  Recursive completion preserves unchanged browsing IDs, loaded descendant lists and pending
  listing revisions. Replaced/disappeared children still collapse to the nearest retained ancestor.
  Legacy selection-bound previews keep their original single-flight behavior.
- A listing read before recursive completion can carry only direct-file sizes. The recursive
  traversal still commits its bounded per-directory snapshots only after success. Completion marks
  already opened descendant lists for a direct size-snapshot update; the current page absorbs those
  sizes without rescanning the root. A cache miss can still need a fresh recursive observation.
  Intermediate ancestor byte updates also advance an opened direct child's size header and sorting.
  Nested directory snapshots now count admitted immediate rows, matching direct listings: excluded
  mounts and denied children retain incomplete coverage and traversal-attempt counts, but do not
  cause a false size-snapshot inventory mismatch. Lists/sizes remain historical display observations,
  not cleanup authorization.
- Opening a directory while recursive work is active shows both the opening phase and continued
  background scan. Once its list arrives the page displays the root's ongoing path/counters; Enter,
  Back and Quit remain responsive. Refresh waits for idle lanes. No-follow, native lineage/mount
  checks, existing directory/row/handle budgets, and worker quarantine remain in force.

## Controlled evidence

A synchronized provider holds root aggregation until explicitly released. Its independent listing
returns a child file while that root gate remains closed, without cancelling or restarting the root.
The test accepts root progress after the child listing rebuilds indexes, returns/reenters the loaded
child without requests, then releases the root. Only one cached-size direct listing follows, and the
open child survives the root's fresh direct-row IDs. Further visits issue no requests.

Other contracts cover the reversed completion order (root finishing while the child listing is
held), cancelling/retrying only the abandoned listing, worker-capacity refusal without disrupting
the root, legacy selection behavior, and both localized opening labels. Scanner tests allocate
independent ranges on two threads and check literal expected IDs, exhaustion, out-of-range old-ID
reservations and failure preserving the pool. Native CLI adapter tests cancel/reset both tokens in
both orders, proving neither lane's preparation clears or cancels the other. A native fixture injects
mount and permission boundaries under an admitted child, compares the snapshot inventory with a
separate direct listing and ordinary filesystem metadata, and retains the incomplete byte evidence.

## Native evidence and validation

Host: macOS 26.5.2 arm64, pinned/active Rust 1.98.0, debug binary. The native PTY driver ran
`scan --no-state --tui /` in a 160 × 32 terminal. Each locale used one new invocation; OS caches
were not cleared. Compilation/checks ran concurrently, so these are functional terminal-response
observations, not an isolated throughput benchmark or p95/p99 estimate.

The final English run opened `/usr` while `/` aggregation remained active. Enter-to-list visibility
took 0.112 s. An independent `os.scandir('/usr')` returned nine names; all eight admitted UI names
matched that set. `/usr/local` remained excluded at the mount boundary. Over six seconds on the
child page, root entries advanced from 2,903 to 23,584. Three Back/Enter cycles retained that list.
At completion the current page was still `/usr`, with 485,975 root entries and its recorded partial
size of 1,665,842,660 B; the last root path remained under `/System/DriverKit`. The counters did not
reset to a child traversal. Returning showed the same root partial size of 20,375,437,179 B. This
checks navigation/result preservation, not the complete physical or reclaimable size of `/`.

The Chinese final run opened the same child in 0.109 s, with root entries
advancing from 940 to 15,740 while that page remained open, then passed three Back/Enter
cycles and exited normally while root work was still active.

The first full native diagnostic exposed a real inventory mismatch: a nested snapshot counted an
excluded mount but a direct listing did not, causing a redundant `/usr` traversal after root
completion. The admitted-row count fix and independent boundary regression above precede the final
run. Separately, an early terminal driver read a partially painted frame (old table with a new
breadcrumb). The driver now waits for a valid completed-list phase before its independent name
comparison; no production coverage or identity checks were weakened.

Validation:

- `cargo fmt --all --check`, `git diff --check` and `python3 scripts/lint_docs.py`: passed.
- `cargo test --workspace --all-targets --all-features -- --test-threads=1`: passed, with the five
  existing explicitly ignored opt-in native benchmarks retained. This workspace run preceded the
  final admitted-row count correction; unchanged results were reused. After that correction,
  `cargo test -p sweepx-scanner --all-targets --all-features` passed 111 unit and three native tests
  (one existing benchmark ignored), and all seven native/contract CLI adapter tests passed.
- TUI's final implementation passed all 110 tests, including synchronized concurrent navigation,
  reversed completion order, cancellation, resource admission and legacy contracts.
- Affected-crate and final workspace `cargo clippy --workspace --all-targets --all-features --
  -D warnings`: passed. Final workspace cross-target Clippy also passed for
  `x86_64-unknown-linux-gnu` using `scripts/cross-lint.sh ... all`, and `x86_64-pc-windows-gnu`
  using Zig C/archive wrappers. These check target-specific source/tests; Linux/Windows native
  interactive runtime remains unverified on this macOS host.
- The debug CLI rebuilt successfully; the installed `~/.local/bin/sweepx` symlink resolves to this
  checkout's debug binary. No cleanup was selected during the root-navigation acceptance.

Compact captured terminal evidence, both locales and exact response times are saved in
[the native validation artifact](scan-tui-concurrent-navigation-validation-2026-10-11.json).
