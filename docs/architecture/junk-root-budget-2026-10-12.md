# Junk root traversal budgets — 2026-10-12

`junk --tui /` exhausted its 128 MiB per-root classified metadata allowance and then the
131,072-directory traversal allowance on the macOS validation host. Ordinary directories
accumulated coverage and child-lineage indexes even though the report only needed candidates.
The earlier ordinary size-browser repair did not change this separate junk analysis.

Local junk scans now retain candidate coverage and sparse native `.git` directory/gitfile
rows. Git interpretation reconstructs repository ancestry from their validated locators;
missing or invalid lineage cannot establish repository absence. Completed local subtrees
release their file markers only after postorder classification has consumed child and parent
context. Incomplete subtrees retain those markers because root-end delivery can be parent-first.
Global custom evaluators keep the full index, even when compact retention is requested.

The default junk traversal allowance is 4,194,304 directories. Candidate, metadata, queue,
handle, per-directory and aggregate limits are unchanged. This is a finite work allowance,
not a memory or physical-space guarantee. Ordinary scans and junk detail inventories keep
their separate limits. See the maintained [scanner design](scanner-and-cache.md).

## Native observations

Host: macOS arm64; pinned and active Rust 1.98.0; release build. No cleanup was invoked.
The terminal used 160 columns and 32 rows, `--locale en-US junk --tui /`, native notifications,
and an automatic quit after the observation window. OS caches were not cleared. This is a
functional check, not a timing comparison.

- Before: classified metadata exhaustion followed by visited-directory limit boundaries.
- After: a session drain reached approximately 470,000 observed entries and ended `Partial`
  with no resource-limit boundary. This is an observation counter, not an exact file inventory.
- The real terminal ended `Junk candidates · Partial · candidates 0`; the final diagnostic was
  `/Users: entry crosses the initial mount boundary`. Its initial System mount contains no
  admitted junk candidate on this host. User data needs explicit roots or system cache discovery.
- Permissions, symlinks and other mounts remain explicit exclusions. Junk does not inherit the
  ordinary size browser's System + Data presentation scope or cross-volume execution authority.

A native controlled binary directory tree compares complete filesystem totals from an ordinary
no-follow walk with compact candidate aggregates under a 2 MiB metadata allowance. The full
index exhausts that allowance; compact mode retains the exact candidate total. Other regressions
exercise delayed parent markers, negative predicates, cancellation, global evaluators and deep
`.git` directory/gitfile ancestry.

## Validation

- Formatting, diff checks and documentation lint: passed.
- Scanner all-feature tests: 119 unit tests and three native integrations passed; one opt-in
  benchmark remained ignored. Linux-only integration code did not execute on the macOS host.
- Core all-feature unit tests: 400 passed, three opt-in benchmarks ignored. The sandbox initially
  prevented FSEventStreamStart in two listener tests; the native, unsandboxed run passed all tests
  with one test thread. No tests were excluded to obtain that result.
- CLI all-target/all-feature tests: 74 unit tests, three browser-bridge integrations, 78 CLI
  contracts and one elevation contract passed with one test thread.
- Workspace all-target/all-feature Clippy on macOS, Linux GNU and Windows GNU: passed.
  Cross-target lint includes test cfg branches; Linux/Windows native runtime was not verified.
- Release executable rebuilt and the command's existing local link points to that build.

These are affected-crate and integration checks plus workspace lint, not a new full-workspace
runtime test run or whole-disk cleanup qualification.

The host's additional global hardcoded-secret commit hook exceeded its two-second deadline
and returned success after reporting the timeout. That extra scan did not finish for the
functional staged changes; this is a separate validation gap, not a passed security scan.
