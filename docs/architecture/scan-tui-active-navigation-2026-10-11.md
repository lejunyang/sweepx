# Scan TUI navigation during active work — 2026-10-11

This fixes active navigation separately from [finished-result reuse](scan-tui-navigation-2026-10-11.md).
Previously, the reducer ignored every Enter while a worker was pending. Returning to the roots
page cleared activity, offscreen completion was discarded, and listing-to-aggregation continuation
looked up the foreground directory rather than the original target. Those behaviors made the scan
appear stopped and repeated entry unavailable.

## Behavior and bounds

- Enter and Back remain available throughout progressive scanning. Navigation changes only the
  page; its identity-bound worker continues. Offscreen progress renews the inactivity deadline and
  final results apply to their original native directory. After a listing completes, aggregation
  targets that same directory even when the user has returned to the virtual roots page.
- The header reports **Scanning in background / 后台扫描中** when the task is offscreen, and
  retains its current path and counters. Entering the active root returns immediately to its live
  rows. Opening a retained child list also changes the page immediately.
- The existing single worker, one request and capacity-one coalesced progress channel remain.
  Opening an unlisted child changes the breadcrumb immediately and explicitly reports that its
  list will be read after the background scan. Completion schedules only the directory still on
  screen; abandoned visits do not become queued requests. This fix does not add concurrent child
  listing, pause the root traversal, or restart it on navigation. Refresh is available when idle.
- The recursive pass allocates fresh direct-row IDs. For native children that still match scan
  scope, parent, basename, type, device/file identity, filesystem domain and mount, the model
  retains browsing IDs and their visited descendants while updating direct rows and native
  locators. A bounded borrowed-key index avoids quadratic completion matching. If a child is
  replaced or disappears, its breadcrumb collapses to the nearest retained ancestor rather than
  opening the replacement under the old identity. Explicit fresh listings discard old subtrees.
- Native result validation, listing/size retention admission and non-cooperative worker quarantine
  remain. Legacy selection-bound detail previews still discard results after selection changes;
  this change applies to progressive browsing. Cached display rows remain historical observations
  and do not authorize cleanup.

## Controlled evidence

Synchronized providers hold both listing and aggregation until the test explicitly releases each
phase. Tests assert four Back/Enter cycles during the held listing issue one request, and listing
completion on the roots page still starts aggregation against the root. Root aggregation completing
offscreen remains available for repeated entry without another request.

A second test opens an unlisted child while root aggregation is held, returns to the roots page,
accepts progress there and verifies the inactivity deadline renews. It reenters the root and child,
then completes the root using a fresh scan row ID for the same native child. The child remains open,
its deferred direct listing is bound to the retained identity, and three further visits issue no
additional requests. A replaced-child test verifies safe breadcrumb collapse. Existing legacy
single-flight, stale completion, deadlines, cancellation, resource limits and retained-list tests
remain in the suite.

## Native evidence and checks

Host: macOS 26.5.2 arm64, pinned and active Rust 1.98.0, debug build based on `15edee5`
with this change. One read-only `scan --no-state --tui /` terminal run used English, byte units and
160×32 cells. OS caches were not cleared; SweepX started a new session without persisted state.
Other compilation/tests ran during the scan, so this is functional acceptance, not an isolated
performance comparison or a p95/p99 estimate.

At 2.209 seconds the root was actively scanning. Three Back/Enter cycles returned to the roots
page and reopened the active root. An unlisted child opened at 2.380 seconds with the explicit
waiting message; returning at 2.383 seconds showed the root still scanning. Its count subsequently
grew from 506 to 485,975 entries, completing at 117.576 terminal seconds with 20,375,437,179 counted
bytes and partial coverage. Returning to roots and reopening the completed root retained those
results and exited normally. Permission/mount omissions remain visible; this is not a complete
whole-disk or independently recomputed byte total. The final row count agrees with the earlier
root-run inventory, but that agreement alone is not a new filesystem-accounting oracle.

[Bounded terminal captures](scan-tui-active-navigation-validation-2026-10-11.json) record every
navigation phase and completion. Controlled tests cover completion while offscreen or inside the
child and both English/Chinese waiting labels; the actual root terminal run is English only.

- Formatting, 107 TUI tests with all targets/features, and workspace host Clippy: passed.
- CLI: 71 unit tests and three browser-bridge tests passed. The first sandboxed CLI-contract run
  passed 77 tests and failed the existing native Trash fixture because macOS denied the sandbox
  access to the system Trash. Its output explicitly reported permission denial; no test was
  removed. Rerunning all 78 CLI contracts under normal host permissions passed, then the previously
  unexecuted elevation-relay test passed. The initial sandbox failure is recorded separately from
  host acceptance.
- Workspace Linux GNU and Windows GNU Clippy, including test cfg branches: passed using the
  existing Zig wrappers. These are cross-compilation checks, not native Linux/Windows runtime.
- Unchanged scanner/core/platform workspace test results from the immediately preceding completed
  validation were reused. This turn reran the changed TUI and its CLI consumers/integrations;
  it did not rerun the whole workspace matrix or claim parallel-test acceptance.
- The added Chinese rendering assertion initially failed because the test flattened wide-glyph
  placeholder cells into artificial spaces (the diagnostic showed `后 台 扫 描 中`). The screen
  helper now reconstructs columns using glyph width; the exact label assertions remain. This was
  a test-reader defect, and the full TUI suite was rerun after that correction.
- Documentation lint passed after restoring the existing `pnpm-store--osdk-cache` heading anchor
  in both language variants. No displayed heading changed.
