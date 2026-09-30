# SweepX contributor guidance

## Product and architecture

- Deliver one user-visible vertical slice at a time, including its evidence and relevant docs.
- Prefer modules within existing crates. Add or merge crates only for a concrete ownership,
  dependency, portability, or independently tested contract benefit; crate count is not a goal.
- Keep scanning, classification and execution callable independently of CLI/TUI rendering.
  Reuse existing rule evaluators and scan facts instead of adding a second implementation.
- Treat junk candidates, large files and duplicate-content groups as different analyses.
  File size, a matching name, or Git ignore status alone does not establish disposability.
- Keep work off the UI thread. Scan sessions need cancellation, bounded event queues and explicit
  completion/error states. Coalesce progress updates without losing final results or failures.

## Filesystem and cache safety

- Display paths are never execution authority. Revalidate native identity immediately before a
  Trash operation. Failure, denial, cancellation or ambiguity must never trigger permanent deletion.
- Preserve no-follow, mount/volume and permission boundaries in accelerated and cached paths.
- Keep unknown, not-checked, lower-bound and exact values distinct. Logical length does not prove
  physical allocation, hard-link uniqueness or reclaimable space. Missing evidence is not zero.
- Cache reuse needs explicit identity, coverage, policy/rule and change-history validity. Capture
  change cursors before validation/traversal; retain racing changes for the next validation.
  Incomplete history, gaps or uncertain coverage must fall back to fresh observations.
- Reuse must preserve current scan identities, classification markers and ancestor accounting.
  Old candidate rows alone cannot justify skipping a subtree. Carry validated data into the next
  cache generation rather than making cache hits disappear on the following scan.
- Cache filesystem facts separately from environment-dependent activity or classification claims.
  A filesystem cache hit does not prove that tool configuration or process activity is unchanged.
- Cleaner rule JSON is editable. Compute digests from loaded bytes; bind cached classifications
  and clean authorization to the rules that produced them. Do not require hand-maintained hashes.
- Bound queues, retained metadata, cache indexes, subprocess output and open handles. Tool probes
  need deadlines and cancellation; deduplicate them within an invocation rather than persisting
  unvalidated answers. An optimization must not trade missing evidence for apparent speed.

## Implementation and verification

- Read `rust-toolchain.toml` and verify the active toolchain before diagnosing build failures.
  Prefer installing the pinned toolchain/components over changing the repository pin. A fallback
  toolchain is diagnostic only unless explicitly accepted; record any validation it cannot cover.
- During implementation, run focused tests and lint for the changed crates. Tests should cover a
  real contract, failure mode or independent oracle, not merely repeat the implementation.
- Before each functional commit, run `cargo fmt --all --check`, affected-crate tests and
  `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` for affected crates.
- At the delivery boundary, run `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  and the relevant integration/workspace tests. Reuse passing results for unchanged code; broaden
  or repeat checks when later changes or failures justify it. Do not rerun the full matrix per commit.
- Documentation-only changes need diff, link and content checks, not a Rust rebuild. Changes to
  scripts, manifests, generated schemas or executable examples need their applicable validation.
- For platform-specific changes, check the relevant `cfg` branches, including test code. Before
  pushing code changes, run the workspace cross-target lint appropriate to the affected platforms;
  inspect `scripts/cross-lint.sh` and CI for supported configurations. Host lint alone is not
  cross-platform evidence; cross-compilation does not verify runtime behavior.
- Missing targets or C toolchains are environment gaps: attempt the appropriate setup, or report
  the specific blocker. Do not substitute Android for desktop Linux/macOS. Do not widen production
  `cfg` gates merely to make a local check pass. Prefer correct gating to suppressing dead code;
  use a narrow exemption only when shared structure intentionally remains unused on a platform.
- Investigate a failed or hung test before excluding it. Bound diagnostic runs, stop only processes
  started for this task, and distinguish a product defect from a host/service/permission blocker.
  If an independent environment blocker remains, preserve the test, complete unaffected checks,
  and record the excluded command, reason and unverified behavior in the commit and final report.
  Such a commit has a documented validation gap; do not describe it as fully green.
- A failed early matrix step leaves later steps untested. Skipped, ignored, blocked and passed
  checks must be reported separately. Do not retry a failure until it happens to pass and call it fixed.

## Evidence and portable tests

- Verify results through an independent path: e.g. an ordinary directory walk cross-checking native
  metadata. When checks disagree, identify the cause before changing expected values.
- Measure uncertain constants and flag behavior. A regression should pin observed behavior, not
  use the same implementation constant to manufacture its expected value.
- Diagnose whether a broken test exposes a regression or pins an old defect. Preserve the actual
  contract, using a lower-layer fixture when the shipped data can no longer exercise it.
- Case sensitivity and enumeration order belong to the host/volume. Compare sets unless order is
  part of the API contract; even repeated enumeration needs controlled mutations and an explicit
  ordering guarantee before order equality is a valid assertion.
- Prefer isolated, controlled fixtures. Account explicitly for host-created files such as
  `.DS_Store`; do not weaken an exact-total regression into a membership check without an
  independent check of its accounting contract.
- macOS temporary paths can have symlinked ancestors. Canonicalize Unix fixture roots when testing
  paths that reject linked ancestors; retain deliberate symlink fixtures. Do not apply the same
  workaround blindly on Windows, where canonicalization can produce verbatim paths.
- Asynchronous event tests need explicit synchronization and bounded waits. Fixture setup may
  generate delayed events; do not ignore those events in production to obtain an immediate hit.
- Performance claims must name the date, host/build, workload, cache state, repetitions and measured
  phase. Assert equivalent results before comparing timings. Distinguish OS cache from SweepX
  cache, and microbenchmarks from end-to-end scans; do not infer p95/p99 from a few runs.

## Comments and documentation

- Add rustdoc to new public types, functions, traits, enums and non-obvious fields.
- Explain invariants, trade-offs and failure behavior around concurrency, unsafe code, filesystem
  authority, resource bounds, cancellation, cache validity and destructive-operation guards.
  Do not merely restate the next line of code.
- Keep affected CLI help, README and both `site/` language variants aligned with behavior changes.
  Preserve stable machine field names and enum values across locales.
- Keep this file focused on durable contributor rules. Put dated measurements, host-specific paths,
  incident narratives and release inventories in linked documentation; do not present them as
  current facts. Update relevant design docs when behavior supersedes their assumptions.

## Commit discipline

- Commit each coherent, self-consistent functional unit after its applicable checks. Avoid
  accumulating unrelated features; keep related docs with their behavior change.
- One commit answers one question. Separate unrelated refactors, renames and fixes. Use scoped
  conventional subjects in imperative mood without a trailing period, e.g. `fix(scanner): …` or
  `docs(architecture): …`. Explain the constraint or reason in the body.
- Preserve LF normalization and unrelated user work. Never use `git reset --hard`,
  `git checkout -- .` or equivalent commands to discard uncommitted work.

## Releases and operational references

- Publishing is irreversible per name/version. Inspect registry state before starting or resuming
  a release; a failed workflow can leave successfully published crates behind. Preserve the
  dependency order and resume a partial release instead of assuming nothing was published.
- Use `scripts/publish-crates.sh`; honor actual rate-limit responses and preserve the publisher's
  exit status through logging pipelines. A rate-limit wait is not a transient retry-budget failure.
- For resumed-release comparisons, inspect archive contents. Generated `.cargo_vcs_info.json` can
  change with HEAD without a source change; never waive differences in source/package metadata.
  Verify packaged dependencies against the registry, not only the workspace's path dependencies.
- Historical setup commands and incidents: [host/release notes](docs/development/historical-host-notes.md).
- Current design review and measured cache work: [2026-10-01 review](docs/architecture/design-review-2026-10-01.md).
