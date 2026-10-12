# pnpm project cleanup verification, 2026-10-13

This slice adds two explicit, preview-bound modes to `pnpm-store`: `dependencies`
preserves project sources and configuration while retiring observed dependency directories;
`project` retires the selected project. Both subsequently retire only admitted exclusive
store content. All moves use native recoverable Trash; package indexes remain for refetch.
See [the CLI contract](../../site/en/cli.md#pnpm-project-cleanup) and
[the inventory design](../architecture/managed-cache-inventory.md#pnpm-project-retirement).

## Controlled verification

Host: macOS arm64, pinned Rust 1.98.0. No real user project or store content was removed.

- `cargo fmt --all --check` passed.
- `cargo test -p sweepx-core -p sweepx-cli --all-features -- --test-threads=4` passed
  with normal host permissions, including the relevant CLI integration suites. Default
  ignored tests remain ignored; this result does not promote them to passing evidence.
- The focused managed-cache core suite passed 21 tests. Project regressions cover shared
  index ownership, outside-project copy references, unexplained native links, preview
  mutation, workspace children and project-local store overlap.
- `cargo test -p sweepx-cli --test pnpm_project -- --ignored --test-threads=1` explicitly
  passed all three new macOS native execution tests. Independent device/inode checks
  verified dependency and project directory moves, exclusive CAS file moves, preservation
  of source/lockfiles in dependency mode, and preservation of another project's copied
  installation and store object. These are temporary fixtures, not real-user cleanup.
- Affected-crate and workspace Clippy with `--all-targets --all-features -- -D warnings`
  passed on the host. Linux GNU and Windows GNU workspace cross-target Clippy also passed.
  Cross-target lint covers selected configuration branches, not runtime behavior. Windows
  execution still refuses the unavailable activity guard; Linux execution was not run.
- The optimized CLI build passed. The local `sweepx` executable links to this workspace's
  release binary and therefore receives the feature without replacing user configuration.

The initial cross-target attempt used an OSDK Zig selector with no active version; the
next attempt could not write Zig's default cache under sandbox permissions. Validation
then used the existing Zig 0.16.0 executable with a task-private writable temporary cache.
The Linux run used `scripts/cross-lint.sh x86_64-unknown-linux-gnu all`; the Windows run
used temporary C/archiver wrappers with Zig's `x86_64-windows-gnu` target. No project pins,
production platform gates, global tool selection or user tool installations were changed.

## Real read-only observation

A debug CLI preview against the host's pnpm v10 store and the `chrome-plugin` project
completed with `inventoryComplete: true`, no issues and no mutation. Its reference scope
was only that project, so this is not whole-machine usage or global exclusivity evidence.
The preview reported:

- two observed dependency directories;
- 848,141,939 logical dependency bytes, deduplicated by native file identity;
- 91 selected package index tokens and 951 admitted CAS paths;
- 942 retained candidate CAS paths;
- 83,096,701 logical bytes across admitted CAS paths, measured independently afterward.

An ordinary no-follow directory walk independently obtained the same dependency-byte
total. For every admitted CAS file, native metadata independently matched exactly one
store link plus the occurrences found in the two dependency trees. This does not prove
physical allocation, APFS extent uniqueness, or reclaimable space; Trash preserves links
and does not release capacity immediately. The preview was not executed.

The previously inspected host v3 store includes an approximately 484.18 MiB JSON index,
which exceeds the existing per-record bound. This slice does not widen that bound: an
oversized/malformed record continues to block execution for its store. Real v3 project
cleanup acceptance and large-record parsing remain unverified. TUI details currently
provide scoped project preview commands; project execution is CLI-only. Generic `junk`
never automatically invokes these project modes.
