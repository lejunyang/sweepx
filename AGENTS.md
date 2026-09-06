# SweepX contributor guidance

## Product-focused delivery

- Prefer one user-visible vertical slice over many narrow internal milestones.
- During implementation, run focused crate tests. Run broad matrices once at the delivery boundary.

## Comments and documentation

- Add rustdoc to every new public type, function, trait, enum, and non-obvious field.
- Add short comments around concurrency, unsafe code, filesystem authority, resource bounds,
  cancellation, cache validity, and destructive-operation guards.
- Comments should explain invariants, trade-offs, failure behavior, and why a tempting shortcut is
  unsafe. Do not merely restate the next line of code.
- Keep CLI help, README, and both `site/` language variants aligned with behavior changes.
- Preserve stable machine field names and enum values across locales.

## Commit discipline

- Commit each coherent functional unit as soon as it builds, passes its own tests, and is
  self-consistent. Do not accumulate several features in one working tree: a large mixed diff
  cannot be reviewed, bisected, or reverted independently.
- One commit answers one question. Split a feature from a refactor, a fix from a rename, and code
  from unrelated documentation. Documentation that *describes the same change* belongs in that
  change.
- Conventional-commit subjects with a scope, imperative mood, no trailing period, for example
  `feat(scan): …`, `fix(scanner): …`, `docs(research): …`, `test(platform): …`, `chore: …`.
- Explain **why** in the body — the constraint discovered, the alternative rejected, the measured
  number. What changed is already in the diff.
- Every commit must leave the tree green: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, and the tests for the crates it touches.
- Never use `git reset --hard`, `git checkout -- .`, or any other command that discards
  uncommitted work in this repository. Committing early is what makes that unnecessary.

## Working on Windows

- Prefer the pinned toolchain; it matches CI. When the configured mirror cannot serve it, set
  `$env:RUSTUP_TOOLCHAIN="stable"` for the session rather than editing `rust-toolchain.toml` — but
  check first, because the fallback is not equivalent: as of 2026-09-06 the `stable` toolchain on
  this host has no `rustfmt` or `clippy` component, so `cargo fmt`/`cargo clippy` fail outright
  under it while the pinned 1.98.0 runs both. A missing component is not a code defect; confirm
  which toolchain is active before believing a formatting or lint failure.
- `.gitattributes` normalizes to LF. Keep it that way: line endings leaking into a commit make the
  real change unreviewable.
- Cleaner rule JSON is freely editable — packages ship unsigned, and no digest has to be refreshed
  by hand. What must stay true is that an edit is never silent: `content_digest` is computed from
  the loaded bytes and binds a clean authorization to the rules that produced the scan. Do not
  reintroduce a check that compares a hand-maintained digest field against the bytes.
- Case sensitivity is a property of the host and volume, not of the code. Probe the actual
  behavior and assert the matching invariant instead of hardcoding either expectation.
- Directory enumeration order is likewise the volume's, not the code's. No backend sorts and the
  `PlatformScanner` contract promises no order, so an assertion comparing enumerated names against a
  sorted list passes only where the filesystem happens to agree — it tests the volume. A macOS CI
  runner returned insertion order `[z, a, m]` where the local disk gave `[a, m, z]`. Assert the set:
  sort a copy, or compare membership. Comparing two enumerations *of the same directory in one run*
  (paged against unpaged) is fine, because the order is consistent within a run.
- A green Windows tree does not mean a green CI. `cargo clippy` only lints the `cfg` branches
  selected for the host, so a `use` that serves a `cfg(windows)` block alone is invisible here and
  fails `-D warnings` on the linux runner. Before pushing, lint at least one non-Windows
  configuration:

  ```pwsh
  cargo clippy -p <crate> --all-targets --all-features --target x86_64-unknown-linux-gnu -- -D warnings
  cargo clippy -p <crate> --all-targets --all-features --target aarch64-apple-darwin -- -D warnings
  ```

  Both are installed for the pinned toolchain, and with the C cross-compiler below **all 22 crates
  lint cleanly on all three** of linux, arm64 macOS and x86_64 macOS — measured 2026-09-06. Sweep
  every crate before pushing; two separate rounds of CI-only failures (a dead-code report in
  `sweepx-core`, an unused import and dead helper in `sweepx-cli`'s tests) would each have been
  caught by it.

  `rusqlite` with the `bundled` feature makes a C compiler for the target mandatory, and
  `sweepx-core` depends on it unconditionally through `sweepx-audit` and `sweepx-event-journal`, so
  six crates were unbuildable off Windows until one was supplied. This host's `clang` is the Android
  NDK's, targeting `x86_64-w64-windows-gnu` with no libc headers for either family. `zig cc` carries
  its own libc for every target and needs no sysroot; it lives at
  `%LOCALAPPDATA%\zig\zig-x86_64-windows-0.16.0\zig.exe` with shims in `%LOCALAPPDATA%\zig\shims`:

  ```pwsh
  $shim = "$env:LOCALAPPDATA\zig\shims"
  $env:CC_x86_64_unknown_linux_gnu = "$shim\cc-x86_64-unknown-linux-gnu.cmd"
  $env:AR_x86_64_unknown_linux_gnu = "$shim\ar-x86_64-unknown-linux-gnu.cmd"
  ```

  The shim must **strip the `--target` cc-rs appends** and pin zig's own spelling — cc-rs passes the
  Rust triple, which zig rejects as `UnknownOperatingSystem`, and the last flag wins. A plain `.cmd`
  wrapper that only prepends `--target` therefore fails; the shim delegates to a Python filter that
  drops the caller's value. zig spells targets differently: `x86_64-linux-gnu`, `aarch64-macos`,
  `x86_64-macos`.

  When a Rust target is genuinely missing, install it rather than concluding it is unavailable. The
  configured mirror 404s on `rust-std-*-apple-darwin` while `static.rust-lang.org` serves it — that
  was verified with a HEAD request (HTTP 200, ~29 MB each) before touching any configuration. osdk's
  `--source`/`source pin` do not change the outcome, because rustup reads `RUSTUP_DIST_SERVER` from
  the injected process environment; set it for the one command instead:

  ```pwsh
  $env:RUSTUP_DIST_SERVER = "https://static.rust-lang.org"
  rustup target add aarch64-apple-darwin --toolchain 1.98.0
  ```

  Do **not** substitute `x86_64-linux-android` for either of the above. It was the fallback while no
  real target was installable, and it lies in both directions: `sweepx-scanner` and `trash` are
  declared only for linux/macos/windows, so their absence there cascades into unresolved-import and
  unused-variable reports CI never sees, and the crate dies at import resolution *before* dead-code
  analysis runs — so it cannot observe a dead-code failure at all. That is precisely how a linux-only
  dead-code defect reached CI once already.
- `cfg`-gated enum variants and functions need a dead-code exemption on the platforms that cannot
  construct them, in *both* directions. A variant built only by the `cfg(windows)` arm of a function
  is dead on linux, and vice versa; `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]` is
  the counterpart to the `target_os = "windows"` form. Locate a variant's construction sites and the
  cfg block enclosing each before deciding — that classification is decisive and takes seconds,
  whereas isolated reproductions of a dead-code report reliably lie: stubbing imports turns public
  matches into uses, rewriting `cfg` trips clippy on the substitute attributes, and neither reaches
  the analysis that failed.
- Test code behind `cfg(all(test, target_os = "…"))` is compiled by `--all-targets` on that target,
  so lint it there before pushing — `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` are both
  installed and cover the macOS and linux gates. Only when no such target can be had is the fallback
  warranted: temporarily widen the gate to `cfg(test)`, `cargo check --tests` against a target of the
  right family, then restore the file and confirm the restoration by hash, reading only the
  diagnostics inside the edited line ranges. Note what neither approach proves — cross-compiled test
  binaries cannot run here, so a *runtime* assertion or panic is still only observable in CI.
- A symlinked ancestor is a real host condition, not an exotic one: macOS `TMPDIR` is
  `/var/folders/…` and `/var` links to `/private/var`, so any fixture rooted at an unresolved
  `env::temp_dir()` is refused by the paths that reject linked ancestors. Reproduce it here without
  elevation — `mklink /J` needs no privilege and Rust classifies a junction as a symlink, so
  pointing `TMP` through one stands in for `/var`. Resolve such a root under `#[cfg(unix)]` only:
  `canonicalize` on Windows yields a `\\?\` verbatim path, which the state-write path rejects with
  `ERROR_INVALID_FUNCTION`.
- A green step proves only that step. When an early step in a matrix job fails, everything after it
  is skipped, so its result is unknown rather than passing — do not read a job's first failure as
  its only failure.

## Evidence before claims

- Verify through a path independent of the one that produced the result. A reader that agrees with
  itself proves nothing; an ordinary directory walk cross-checking a native metadata read does.
- When a cross-check disagrees, find the cause before adjusting the check. Two silent
  under-reporting defects in the accelerated source were found exactly this way, and both looked
  like exact totals.
- Do not tune a guess. If a constant or flag meaning is uncertain, print the real distribution and
  read it. A regression test should pin the *measured* value, not reference the constant it is
  meant to protect.
- Record measured numbers with their subject and date, and state what they do not cover.
- A test that fails after a fix is not automatically a test to relax. Classify it first: it may have
  been pinning the defect, or it may be the only thing covering a real contract. Three tests broke
  when a mistyped `requires.core` range was corrected; two were describing the defect, but the third
  was the sole cover for "an incompatible package is refused". Relaxing all three would have removed
  the guarantee along with the noise. Where the honest fixture no longer exists at that layer, build
  it one layer down — `sweepx_catalog::load_package_bytes` constructs an incompatible package from
  bytes, so the gate stays tested no matter how the shipped manifests are versioned.
- An assertion can describe behavior the code does not have, and then it is the assertion that is
  wrong. A macOS test called `enumerate_children` twice on one handle and expected the second call to
  raise `ResourceLimit`; an exhausted handle returns `Ok(complete)` instead, so `unwrap_err` panicked.
  Read the branch that would have to produce the expected error before assuming the host is at fault
  — here the reachable refusal was the retained-byte cap on a fresh handle.
- Totals over a real directory are host-dependent in the same way ordering is. macOS writes
  `.DS_Store` into directories at moments a test does not control, so assert that the fixture's names
  are present rather than that the count equals the number written.

## Releasing to crates.io

- Publication is irreversible per name and version. As of 2026-09-06 ten crates hold `0.0.1`:
  `sweepx-audit`, `sweepx-cache`, `sweepx-canonical`, `sweepx-catalog`, `sweepx-cleaner-schema`,
  `sweepx-fixtures`, `sweepx-i18n`, `sweepx-model`, `sweepx-platform` and `sweepx-protocol`. Twelve
  names are still free. A partially completed release is resumed, never re-cut.
- **crates.io meters publishes and a first release is entirely on the strict limit.** A brand-new
  crate *name* allows a burst of 5 and then refills at one per **10 minutes**; a new *version* of an
  existing crate allows 30 and refills at one per minute. Every name in a first release is new, so 22
  crates cost roughly three hours of mandated waiting and no amount of retry tuning avoids it. Two
  runs failed here reporting "could not publish … after 5 attempts" when the release was only waiting
  its turn — a generic 15s-doubling-to-120s ladder over five attempts gives up in under four minutes.
  The 429 response states the exact instant the next publish is allowed; sleep past that and do not
  consume an attempt, and pace successive crates by `PUBLISH_NEW_CRATE_INTERVAL_SECONDS` (600) so the
  refusal is not needed to discover the bucket is empty.
- Piping `cargo publish` through `tee` to inspect its output makes `$?` the status of `tee`, which is
  almost always 0. Take the status from `PIPESTATUS[0]`, or every failed publish reads as a success.
- Cargo writes `.cargo_vcs_info.json` into every archive, recording the HEAD sha of the commit that
  produced it. It is generated rather than read from the tree, so `include`/`exclude` cannot drop it
  and no flag suppresses it. **Every commit after a publish therefore changes the archive checksum of
  every crate, with no source change at all.** Any "already published, identical bytes" check must
  compare contents with that file excluded, or a resumed release fails on its first crate forever —
  which is exactly what blocked this one. Diff the two archives member by member before believing a
  checksum mismatch means a source difference.
- `cargo package` without `--no-verify` builds the extracted archive, where path dependencies are
  gone and only the registry versions remain. Confirm this by reading the packaged `Cargo.toml`: it
  carries `version = "0.0.1"` and no `path`. So packaging a dependent crate requires its SweepX
  dependencies to be on crates.io and visible in the index already; the ordering in
  `scripts/publish-crates.sh` exists for that reason, and locally this step can pass for the wrong
  reason once the dependency is published.
- A green step proves only that step, and this applies to the release too: `crates-io` failing part
  way leaves `release` skipped and the tag uncreated, while the crates it did upload stay uploaded.
  Check the registry itself rather than the workflow conclusion.

## Filesystem safety

- Display paths are never execution authority. Revalidate native identity immediately before a
  Trash operation.
- Trash failure, denial, cancellation, or ambiguity must never fall back to permanent deletion.
- Preserve explicit incomplete/lower-bound evidence; never render it as exact.
