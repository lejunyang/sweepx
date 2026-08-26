---
title: Introduction
---

# Introduction

SweepX is described as a proposed cross-platform Rust CLI/TUI/Agent-safe disk analysis and safe-cleanup product for Windows, macOS, and Linux, but the repository currently ships a design and research snapshot only.

> [!WARNING]
> There is no runnable SweepX today. No built artifact, real scanner, Trash executor, or permanent deletion implementation is available in the current tree.

## Current status

The README establishes a strict baseline:

- The deliverable is a design and research snapshot, not product implementation.
- Runnable CLI, TUI, installation packages, and cleanup capabilities are not provided.
- Windows, macOS, and Linux are proposed first-class platforms, not released support claims.
- Any "must" or "guarantee" language describes future acceptance criteria, not current functionality.

## Product position

SweepX is intended to sit between a general disk analyzer and an app-specific cleaner:

- A general scanning core answers where space exists and keeps uncertainty visible.
- Typed cleaners explain why something may be reclaimable instead of relying on folder names alone.
- CLI, TUI, and Agent flows share one safety core rather than separate mutation paths.
- Human approval and execution authorization stay separate from chat confirmation or automation.

## Why the site repeats "not runnable"

That is the easiest failure mode for a documentation site: letting a design snapshot read like product documentation. The current documents already say:

- Scanning, Trash, and permanent deletion are not implemented.
- Even a future Trash-first path would not guarantee recoverability or reclaimed capacity.
- Permanent is a separate, high-risk mode, not a normal extension of the standard approval flow.

## Suggested reading order

1. Start with [Safety](/en/safety) to understand which constraints are non-negotiable.
2. Continue with [CLI](/en/cli) to see how the future command surface is supposed to express those constraints.
3. Finish with [Roadmap](/en/roadmap) to see which phases remain read-only or simulated.
