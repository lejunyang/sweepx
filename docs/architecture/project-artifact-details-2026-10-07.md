# Project artifact details

The project catalog now recognizes conventional Cargo artifact subdirectories, Python virtual
environments and Vite dependency bundles. Classification, native observation and execution remain
independent. The rules apply to Linux, macOS and Windows; native runtime observations below cover
only the macOS host. A matching layout is never permission to remove it.

## Admitted evidence

| Rule | Captured layout | Limit and recovery impact |
| --- | --- | --- |
| `rust.incremental` | `target/{debug,release}/incremental`, including a target-name level | Ordinary `.cargo-lock` in the profile; rebuilding loses incremental speed |
| `rust.dependencies` | Corresponding `deps` | Recompile dependencies and tests |
| `rust.build-script-output` | Corresponding `build` | Build scripts may execute or download again |
| `rust.fingerprints` | Corresponding `.fingerprint` | Removing fingerprints may force rebuilding |
| `rust.examples` | Corresponding `examples` | Generated executables may be used directly |
| `rust.target-platform` | Target-named direct child of native `target` | Ordinary parent `.rustc_info.json` and own `CACHEDIR.TAG`; `--target` does not prove a different host architecture |
| `python.virtualenv` | `.venv` or `venv` with ordinary `pyvenv.cfg` | Current bounded CPython/uv signature; dependency recovery inputs remain unverified |
| `node.vite-deps` | `deps` with native `.vite` parent and ordinary `_metadata.json` | Current bounded prebundle signature; referenced dependency paths are not opened |

`parentNames`, `pathProfile` and `namePattern` are admitted catalog fields, evaluated using the
existing predicate VM. The bounded name shape is not a regular expression or effective Cargo
target resolution. `cargo_profile_artifact` checks a validated native lineage inside the admitted
root. A missing ancestor cannot be manufactured from a display path. Conventional debug/release
profiles are covered; custom profile names, relocated build roots, custom target JSON stems and
effective tool configuration are not resolved. Cargo considers intermediate layout internal and
subject to change: unsupported layouts may be absent rather than guessed.

Only own/direct-parent ordinary-file markers are used. The native ancestry signature needs no
ancestor file index, preserving local-marker classification, bounded closed-subtree publication
and selected refresh. Exact-name lookup remains borrowed; target-pattern merging allocates only
when the captured parent has a compiler-info marker. All source bytes still contribute to the rule
digest, so edits invalidate cached classification interpretation. Format answers remain current,
invocation-bounded observations, not persisted filesystem facts.

Every new rule explicitly has `report_only` execution policy. Generated signatures, ignored paths,
size or risk do not establish exclusive ownership, inactivity, dependency recovery or lack of
personal files. Virtual environments are installed software environments, not automatically stale
caches. Browser testing profiles contain browser data and do not receive a universal name rule.

## Viewing and accounting

`sweepx junk --details ROOT` retains nested artifact candidates in human, JSON and NDJSON reports.
Without the flag the existing outer-candidate view is preserved. JSON adds scan-scoped `entryId`
and `parentCandidateEntryId` grouping, `detailsIncluded`, `topLevelCandidateCount` and
`sizeSummaryScope=non_overlapping_top_level_candidates`. These IDs have no native execution
authority. The nearest displayed native ancestor supplies the grouping; display-prefix guessing
and independently observed temporary objects do not establish a parent.

Summary bytes and incomplete-size counts use only non-overlapping outer candidates in both modes.
Child sizes must not be added to their parent's size. Existing machine fields retain their names;
`sizeIsLogical`, unknown and lower-bound evidence remain explicit. Neither logical length nor
filesystem-reported allocation proves unique physical/reclaimable space: shared hard links, APFS
clones/snapshots, compression and Trash retention are independent questions. `--details` conflicts
with cleanup flags. TUI already publishes nested candidates and now renders localized category
labels; the underlying stable IDs and report-only action guards are unchanged. Enter still opens
the shared read-only native directory inspection.

## Verification

Controlled native CLI tests exercise both locales, nested Cargo/target groups, virtual environments,
Vite signatures and wrong-parent counterexamples. An ordinary independent metadata walk checks
outer byte accounting, including any host-created ordinary files. Detailed/plain totals agree and
personal payloads survive unchanged. Catalog admission refuses unsafe parents, unknown patterns
and target patterns without required markers. Format tests decline duplicate/incomplete Python
configuration and invalid/over-limit bundle records. TUI rendering checks localized labels while
stable IDs and action restrictions remain intact.

On 2026-10-07, Rust 1.98.0 on the arm64 macOS host passed `cargo fmt --all --check`,
`python3 scripts/lint_docs.py`, `cargo test --workspace --all-features --locked` and workspace
Clippy with all targets/features and warnings denied. Five existing opt-in performance tests
remained ignored by the normal suite. Restricted native watch/Trash runs initially failed at host
permission boundaries; the complete host-authorized suite subsequently passed without exclusions
or weakened tests. A release build and read-only PTY directory drill-down also passed.

Workspace cross-target Clippy passed for `x86_64-unknown-linux-gnu` through `scripts/cross-lint.sh`
and `x86_64-pc-windows-gnu`, using the existing Zig 0.16.0 toolchain with task-local cache and
target C/archiver wrappers. Neither cross-compilation proves Linux/Windows runtime acceptance.
An actual read-only four-project report recognized all eight new rule IDs, including four Python
environments and three Vite prebundles with recognized current signatures. Larger classified
project/system reports retained their partial status; candidate totals do not establish complete
disk coverage.

Primary layout references: [Cargo build cache](https://doc.rust-lang.org/cargo/reference/build-cache.html),
[Python venv](https://docs.python.org/3/library/venv.html),
[Vite dependency prebundling](https://vite.dev/guide/dep-pre-bundling.html).

## Whole-disk research boundary

On 2026-10-07 this macOS host received a read-only metadata survey of accessible internal volumes,
then separate observations of large project, application, package-store and tool directories.
Permissions left gaps. macOS firmlinks expose the Data volume through `/`; a duplicate root walk
was stopped, and alias rows are not added to the Data observation. Reported per-directory blocks
can exceed physically used volume bytes because shared allocation is not deduplicated as unique
physical ownership. Private paths and observations are retained outside Git.

Findings support further tool-cache subdivision and per-version package-store presentation, but
do not justify sweeping Application Support, model weights, Agent sessions, copied databases,
development workspaces or operating-system VM/Preboot files. These require distinct data/retention,
configuration or tool-managed recovery contracts. Existing system cache and tool-store rules plus
directory inspection remain useful before those more specific rules are admitted.

Concrete next contracts are configured pnpm store versions, osdk download archives distinct from
CAS/install/model directories, Playwright browser packages distinct from browser profiles, and Go
module/download caches distinct from installed tools. Root configuration, version signatures,
current activity and recovery/reference evidence must be bounded observations before any new
execution authority is considered. [Playwright's browser management](https://playwright.dev/docs/browsers#managing-browser-binaries),
[Go's module cache](https://go.dev/ref/mod#module-cache) and
[pnpm's configured store](https://pnpm.io/settings#storedir) supply layout references, not proof that
a particular observed version is unused. These are research proposals; this change implements
the eight project rules above.
