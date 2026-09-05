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
- A green Windows tree does not mean a green CI. `cargo clippy` only lints the `cfg` branches
  selected for the host, so a `use` that serves a `cfg(windows)` block alone is invisible here and
  fails `-D warnings` on the linux runner. Before pushing, lint at least one non-Windows
  configuration:

  ```pwsh
  cargo clippy -p <crate> --all-features --target aarch64-linux-android -- -D warnings
  ```

  Read its output with the target's limits in mind. `sweepx-scanner` and `trash` are declared only
  for linux/macos/windows, so on Android their absence cascades into unresolved-import and
  unused-variable reports that CI never sees. Findings inside a `cfg(any(linux, macos, windows))`
  block are artefacts of the probe; unconditional ones are real. `x86_64-unknown-linux-gnu` is the
  honest target for this, but the configured mirror returned 404 for it.

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

## Filesystem safety

- Display paths are never execution authority. Revalidate native identity immediately before a
  Trash operation.
- Trash failure, denial, cancellation, or ambiguity must never fall back to permanent deletion.
- Preserve explicit incomplete/lower-bound evidence; never render it as exact.
