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
- Chinese and English human-facing output with stable machine-readable output.
- Built-in Cleaner schema, deterministic rule VM, catalog, compatibility
  checks, and initial Cargo-target and Chromium cache metadata.
- Immutable plan and simulation-only authorization models.
- Durable audit and recovery state plus deterministic simulated execution.
- Bilingual documentation site, architecture documents, and release roadmap.

### Security

- Imported scan data is forced to stale, incomplete, report-only status.
- Native filesystem mutation, Trash, permanent deletion, elevation, and
  destructive CLI commands remain unavailable.
- Simulation accepts no native target paths and uses only a sealed fake adapter.
[Unreleased]: https://github.com/lejunyang/sweepx/commits/main
