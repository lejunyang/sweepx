# SweepX implementation handoff

Updated: 2026-08-27
Branch: `main`

## Product constraints

- Keep one executable entry point: `sweepx`; enter the interactive browser with `sweepx scan --tui`.
- Human-readable terminal output is the default. JSON and NDJSON are explicit machine formats.
- CLI output supports `zh-CN` and `en-US`, auto-detects the environment, and accepts `--locale`. Stable machine keys and enums are never translated.
- Documentation lives in `site/` and uses VitePress with Bun.
- Binary and crates.io publication require literal `[publish]` in the HEAD commit message. crates.io uses `CARGO_REGISTRY_TOKEN`; GitHub Releases and Pages use `GITHUB_TOKEN`.
- Work directly on `main`. Keep coherent agent-authored milestones atomic and include exactly one trailer: `Co-authored-by: TRAE CLI <noreply@bytedance.com>`.
- Native mutation remains disabled unless OS Trash is proven. Never fall back from Trash failure to Permanent deletion. Human approval work stays last.
- `displayPath` is never authority.

## Implemented baseline

- Single `sweepx` CLI with human/JSON output, locale detection/override, and interactive file-manager-style TUI navigation.
- Read-only scanners and bounded caches across Linux, macOS, and Windows, with platform-specific handle-bound/handle-relative safety checks.
- Bounded locator file reads and typed Cargo evidence for `cleaner cargo-detect`; the public detector remains hint/report-only and cannot plan, approve, or execute.
- Linux bounded SQLite event journal with one-transaction complete-stream plus terminal-snapshot persistence.
- CI, Pages, `[publish]`-gated binary/crates publication, install scripts, and bilingual VitePress site are present.

## Completed milestone: read-only preview-cache diagnostics

The implementation is committed in `933921b` (`feat(cache): expose read-only status diagnostics`). It adds:

```text
sweepx cache status
sweepx --format json cache status
```

Exact boundaries:

- Linux and macOS support human and JSON output; Windows is disabled.
- NDJSON is rejected as a usage error before state/cache access.
- Missing state/cache returns `disposition=absent`, exit 0, and creates nothing.
- Existing preview state is inspected through held directory FDs, per-component no-follow opens, bounded flat directory enumeration, and bounded no-follow file reads.
- Generation IDs are bounded and validated before projection or path construction. Invalid cache payloads are represented by typed diagnostics without exposing stored paths, entry IDs, or malformed schema values.
- `available` means only that bounded cache structure, checksum, schema, and provenance are readable; it does not make live filesystem claims. Warnings, errors, incomplete byte accounting, or quarantine presence produce `degraded`/exit 4.
- Machine usage, unsupported-platform, and inspection-integrity failures use a `cache.status.result` envelope with generic redacted details.
- All mutation capability cells remain disabled.

## Verification for the current milestone

- `cargo test --workspace --all-targets --all-features --locked` passes.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` passes.
- Windows GNU checks and Clippy pass for the native CI package set; macOS cache all-target cross-check and Clippy pass.
- Cache inspection has 31 unit tests and cache-status CLI has 11 contract tests.
- JSON Schema includes a cache-status example plus shape, status/exit, disposition, degradation-witness, and privacy-negative cases.
- `cargo fmt --all -- --check`, docs lint, and `git diff --check` pass.
- VitePress site build passes with `/data00/home/lejunyang/.bun/bin/bun run docs:build` from `site/`.
- macOS cross-check remains blocked on this Linux host because the host C compiler rejects Apple `-arch` and `-mmacosx-version-min` flags while compiling bundled SQLite; this is a toolchain/environment limitation.

## Current milestone: Cargo config-scope source ledger

`cleaner cargo-detect` now projects a strict `cargo.config-scope.v1` ledger at `data.hints[].evidence.cargo.configScope`. It records the workspace config pair, ancestor/Cargo-home/CLI/cwd source states, and presence-only observations for `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, and `CARGO_HOME`. Environment values and workspace `build.target-dir` values are never exposed. The public result explicitly sets `candidateAllowed=false`, `planAllowed=false`, `approvalAllowed=false`, and `executionAllowed=false`.

The production collector now observes `.cargo/config` and `.cargo/config.toml` through one retained `.cargo` handle and one bounded enumeration cursor, and rejects ASCII case aliases and duplicate names. Exact entries are inspected and read while their enumeration batch is current, then enumeration continues to EOF. It intentionally keeps `workspace.pairSnapshot=not_checked` because directory enumeration cannot exclude concurrent ABA; time-local absence is therefore `not_checked`, never a stable absence claim. Consequently `precedenceComplete=false`, `targetDir=NotChecked(config_scope_not_checked)`, and `targetShape=Unknown(config_scope_not_checked)`. A global cap of 16 Cargo layouts plus existing fixed-input read budgets bounds the post-scan work. The JSON Schema freezes tagged states, exact environment names, blocker codes, redaction rules, non-atomic pair constraints, and the report-only authority boundary; the golden and negative tests reject raw environment/config values and authority drift.

Verification for this milestone includes the full workspace test suite, workspace Clippy with warnings denied, Windows GNU Core/CLI check and Clippy, schema validation, docs lint, VitePress build with Bun, formatting, and diff checks. Native macOS runtime coverage remains a CI responsibility; Linux-host cross-linking of the complete workspace to macOS is still limited by bundled SQLite's host C compiler flags.

## Next work

Continue with the next bounded, non-human-approval read-only milestone selected from `DESIGN.md` and `docs/ROADMAP.md`. Keep all mutation capability cells disabled. For Cargo scope specifically, do not promote effective `targetDir` until workspace-pair atomicity/case-fold evidence plus ancestor, Cargo-home, environment, CLI override, and invocation-cwd precedence are all proven without display-path authority. A caller-owned cancellation token for post-scan Cargo collection remains a small follow-up.
