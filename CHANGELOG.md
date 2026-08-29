# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial multi-crate Rust workspace and versioned protocol and schema contracts.
- Development-grade, bounded, read-only Linux directory scanning.
- Read-only CLI workflows for scanning, capabilities, status, explanation,
  Cleaner metadata, and the terminal interface.
- Read-only `cache status` diagnostics with human/JSON output on Linux and
  macOS, bounded aggregate cache health, and a stable `cache.status.result`
  schema; Windows and NDJSON fail closed before cache access.
- Progressive TUI directory totals with throttled lower-bound snapshots, bounded lossy UI
  backpressure, and final exact/incomplete convergence.
- Evidence-bearing, report-only platform cache discovery through `junk --system` for narrow Linux,
  macOS, and Windows user-cache roots.
- A reproducible, non-copying MangoDisk rule-reference audit and a native qualification matrix for
  NTFS layout, USN change tokens, macOS bulk enumeration, and device-aware concurrency.
- Chinese and English human-facing output with stable machine-readable output.
- Built-in Cleaner schema, deterministic rule VM, catalog, compatibility
  checks, and initial Cargo-target and Chromium cache metadata.
- Immutable plan and simulation-only authorization models.
- Durable audit and recovery state plus deterministic simulated execution.
- Bilingual documentation site, architecture documents, and release roadmap.

### Security

- Windows durable snapshot state now fails closed until private DACL and reparse-point checks exist.
- Scan NDJSON is rejected until a durable journal and replay path can satisfy the published terminal-event contract.
- `status.result.data` and `cancel.result.data` now have exact published schema branches and examples.
- Preview-cache inspection rejects redirected, non-private, hard-linked,
  oversized, malformed, or unbounded generation state without repair or
  quarantine side effects.
- Imported scan data is forced to stale, incomplete, report-only status.
- Native filesystem mutation, Trash, permanent deletion, elevation, and
  destructive CLI commands remain unavailable.
- Simulation accepts no native target paths and uses only a sealed fake adapter.
[Unreleased]: https://github.com/lejunyang/sweepx/commits/main
