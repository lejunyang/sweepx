# Root-directory TUI boundary handling — 2026-10-11

Historical boundary-only repair: the System-only `/` scope below is superseded for ordinary macOS TUI browsing by [System + Data admission and verified alias deduplication](scan-tui-volumes-2026-10-11.md).

`scan --tui /` could fail before displaying any children. Detail traversal treated a newly
observed child on another mount as a change to the captured target. macOS APFS paths such as
`/Library` and `/Users` can share the reported device with `/` while having a different native
mount identity. The root's `/.file` also returned a native permission-denied inspection error;
propagating that error discarded readable siblings. After these errors were corrected, a real
root scan reached the full-fact inventory's global 131,072-entry work cutoff.

Detail browsing now excludes newly encountered mount boundaries and permission-denied or
vanished children, including a descendant whose directory enumeration is denied. Their ancestors
keep incomplete coverage and lower-bound size totals. Direct-child counts still correspond to
retained, identity-bound rows. Strict direct inventories still reject these gaps. Captured root
or ancestor identity/mount changes, unknown mount evidence, malformed bound tokens, cancellation
and resource failures remain failures; the requested directory's own enumeration denial remains
a failure. Other volumes need separate root admission; this does not grant cross-mount traversal.

The ordinary size browser streams descendant file lengths without the global visited-entry
cutoff used by full-fact inventories. Visible rows, batch storage, per-directory consumption and
ancestor handles keep their existing bounds. Cooperative cancellation remains available between
native observations. Even fallback full file inspections contribute only length in this mode:
no descendant hard-link ledger grows with the file count, and allocation, unique-file totals and
reclaimable-byte claims stay unknown. Evicted/non-progressive ordinary details use the same size
mode. Junk directory breakdowns retain full facts and their original work allowance.

## Native reproduction and scope

Host: macOS 26.5.2, arm64; pinned and active Rust 1.98.0; debug executable based on `3e069b4`
with this change. Functional observations used a real 160×32 terminal, outside the sandbox,
and never invoked cleanup. The final end-to-end run used `--locale en-US scan --tui --no-state /`
and exited after the TUI reached `Finished`. OS caches were not cleared. This is functional
validation, not a speed comparison or a distribution estimate.

- Initial `scan --tui /`, with state enabled and disabled: `Scan failed`, `mount_changed`.
- Native direct-child inspection: `/Library` and `/Users` had a different mount identity;
  `/.file` returned `PermissionDenied`; `/dev` already produced an explicit boundary.
- Intermediate boundary-only repair: approximately 131,000 entries, then `resource_limit`.
- Streamed size repair: 392,480 entries still updating after 53.8 seconds; deliberately quit.
- Final terminal run: `Finished`, 485,975 entries, 68.1 seconds shown, scanned size 19.0 GiB.
  These are the TUI's observed counters and rounded lower-bound size, not independently verified
  whole-disk bytes. Excluded mounts, permissions and links prevent complete disk coverage.

The [captured terminal evidence](root-tui-validation-2026-10-11.json) includes the final screen
and bounded progress snapshots. Controlled native fixtures cross-check admitted file sizes and
row sets with ordinary filesystem metadata; they exercise direct and nested mount boundaries,
inspection/enumeration denials, vanished entries, strict inventory refusal, target mount changes,
uncertain mount comparison, fallback size observations and released directory capabilities.
A separate native CLI regression streams beyond a controlled small work limit with only one
retained row, while the full-fact mode still rejects that limit.

## Checks

- `cargo fmt --all --check`: passed.
- `cargo test --workspace --all-targets --all-features -- --test-threads=1`: passed;
  five opt-in native benchmarks remained ignored (three core, one macOS platform, one scanner).
  Scanner: 106 unit tests and three native integrations passed. Core: 399 unit tests passed.
  TUI: 102 tests passed. No tests were excluded to make this run pass.
- After the final CLI-only adjustment for non-progressive size details,
  `cargo test -p sweepx-cli --all-targets --all-features -- --test-threads=1`: passed
  (69 unit tests, three browser-bridge integrations, 78 CLI contracts and one elevation contract).
  Passing unchanged workspace-crate results were reused.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- Workspace Clippy with all targets/features for `x86_64-unknown-linux-gnu` through
  `scripts/cross-lint.sh`, and `x86_64-pc-windows-gnu` with Zig C wrappers: passed.

Cross-target lint covers production and test `cfg` branches; desktop Linux/Windows runtime
was not validated here. The real root terminal run is macOS evidence. Single-threaded test
success does not establish success under parallel test scheduling.
