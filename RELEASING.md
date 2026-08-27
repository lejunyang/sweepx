# Releasing SweepX

SweepX releases are deliberately explicit. A push to `main` starts release
work only when the pushed HEAD commit message contains the literal,
case-sensitive marker `[publish]`. The marker is checked on every release job
and again by the metadata helper. A marker in an earlier commit in the push is
not sufficient. This gate applies to binary and crates.io publication only. The
independent GitHub Pages workflow deploys documentation on every push to `main`
and does not require `[publish]`.

## One-time repository setup

1. Enable GitHub Pages with **GitHub Actions** as its source. Documentation
   changes under `site/` deploy independently of product releases.
2. Create a protected GitHub environment named `crates-io`. Require reviewer
   approval if desired, and add `CARGO_REGISTRY_TOKEN` as an environment secret.
   Use a least-privilege crates.io token scoped to the SweepX crates.
3. Keep the default `GITHUB_TOKEN` permission policy enabled. The release job
   elevates only its own token to `contents: write`; every other job is read-only.

All GitHub Actions dependencies are pinned to immutable commit SHAs. The nearby
comments record the reviewed upstream version. Bun is also fixed to `1.4.0` in
CI so lockfile behavior cannot drift silently. Update those pins intentionally
and review upstream release notes before changing them.

## Prepare a release

1. Update `[workspace.package].version` in `Cargo.toml`. All workspace crates
   inherit this version. Update every internal dependency requirement to that
   same release version and refresh `Cargo.lock`.
2. Update the changelog and user-facing release notes. Confirm that capability
   claims still match the executable. Linux, macOS, and Windows scanning are all
   development-grade/degraded and read-only. macOS traversal is handle-bound and
   Windows traversal is handle-relative; building a binary still does not qualify
   scanning for release.
3. Run the release-equivalent checks from a clean checkout:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo test --workspace --all-features --locked
   (cd schemas && bun install --frozen-lockfile && bun run validate)
   (cd site && bun install --frozen-lockfile && bun run docs:build)
   bash scripts/test-installers.sh
   pwsh -NoLogo -NoProfile -File scripts/test-installers.ps1
   scripts/check-release-metadata.sh
   scripts/publish-crates.sh --check
   ```

   The installer test command applies once `scripts/test-installers.sh` is
   present. CI detects and runs it automatically.
4. Confirm that `v<VERSION>` does not exist locally, on GitHub, or as an
   existing release. `scripts/check-release-metadata.sh` validates the local and
   remote tag checks. Never move or reuse a release tag.
5. Put `[publish]` in the final commit message that will become HEAD of `main`,
   for example `release: SweepX 0.2.0 [publish]`, then push that commit to
   `main`. If the change is squash-merged, the squash commit message must retain
   the marker.

Do not add the marker merely to test the workflow. A marker-bearing push is an
authorization to publish irreversible crates.io versions and a GitHub Release.

## What the publish workflow does

The workflow validates a shared SemVer version and an unpublished
`v<VERSION>` tag, then completes all test gates before publication. It builds
one native `sweepx` executable for each target:

| Target | Archive | Current scan capability |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `.tar.gz` | degraded, development-grade |
| `aarch64-unknown-linux-gnu` | `.tar.gz` | degraded, development-grade |
| `x86_64-apple-darwin` | `.tar.gz` | development-grade/degraded read-only scan |
| `aarch64-apple-darwin` | `.tar.gz` | development-grade/degraded read-only scan |
| `x86_64-pc-windows-msvc` | `.zip` | development-grade/degraded handle-relative read-only scan |

Each archive contains exactly one root-level file: `sweepx` on Unix or
`sweepx.exe` on Windows. Archive names are
`sweepx-v<VERSION>-<TARGET>.tar.gz` or `.zip`. `SHA256SUMS` covers all five
archives.

Before creating the Git tag, `scripts/publish-crates.sh` publishes the crates in
this dependency order:

```text
sweepx-canonical
sweepx-i18n
sweepx-model
sweepx-cache
sweepx-cleaner-schema
sweepx-fixtures
sweepx-platform
sweepx-protocol
sweepx-audit
sweepx-catalog
sweepx-cleaner-vm
sweepx-event-journal
sweepx-platform-linux
sweepx-platform-macos
sweepx-platform-windows
sweepx-tui
sweepx-scanner
sweepx-analysis
sweepx-core
sweepx-safety
sweepx-cli
sweepx-executor
```

The helper verifies that this list exactly covers the workspace, that every
internal dependency appears earlier, and that every internal version requirement
admits the current workspace dependency version. It packages the workspace
locally and records each `.crate` SHA-256. During a real publish it packages
each crate again in dependency order with Cargo's normal package verification;
`--check` also runs that exact per-crate command for any version already present
on crates.io before comparing it. An exact version already present on crates.io
is skipped only when the checksum returned by the crates.io API equals the local
archive checksum; any mismatch fails closed. New packages use the same locally
verified packaging target, and the helper verifies that `cargo publish`
regenerated identical bytes before accepting the upload. Packaging and
publication use bounded exponential retries for publication or index-propagation
failures. This makes a pre-tag retry safe after a partial crates.io publication
without treating a reused version as equivalent.

Only after every crate is available does the final job create `v<VERSION>` and
the GitHub Release with the five archives and `SHA256SUMS`, using the scoped
`GITHUB_TOKEN`.

## Failure handling

- If tests, schema validation, the site build, installer tests, or a native
  build fails, fix the issue and create a new marker-bearing HEAD commit. No tag
  or GitHub Release has been created at that point.
- If crate publication stops partway through without a source fix, rerun the
  failed workflow at the same commit. This preserves the `.crate` bytes; the
  helper verifies and skips only byte-identical exact versions, then resumes in
  dependency order. If any packaged source or release metadata must change, use
  a new version rather than trying to reuse partially published version numbers.
- If the final GitHub Release step fails after the tag or release was created,
  inspect the remote release before doing anything. Do not delete, move, or
  overwrite a published tag automatically. Repair that release manually only
  after confirming its commit and assets.
- Crates.io versions are immutable. Never attempt to replace a published crate;
  prepare a new workspace version instead.
