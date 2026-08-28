---
layout: home

hero:
  name: "SweepX"
  text: "See clearly before acting"
  tagline: "A runnable development-grade, read-only disk-analysis CLI/TUI. Real cleanup does not exist yet."
  image:
    src: /mark.svg
    alt: SweepX
  actions:
    - theme: brand
      text: Get Oriented
      link: /en/guide/introduction
    - theme: alt
      text: Run a Read-only Scan
      link: /en/cli
    - theme: alt
      text: 中文
      link: /

features:
  - title: Runnable, but read-only
    details: Linux, macOS, and Windows now have degraded development-grade read-only scanners exposed through the same `sweepx scan` / `scan --tui` entry points. macOS traversal is handle-bound and Windows traversal is handle-relative.
  - title: Evidence never becomes authority
    details: Imported scan JSON is forced to stale, incomplete, report-only provenance. `cache status` is also read-only preview-cache diagnostics; `available` means only that bounded cache structure and validation are readable, not that any live/current filesystem fact is true.
  - title: Mutation remains sealed off
    details: There is no plan, approve, or execute CLI, no native Trash/Permanent adapter, and no implementation that deletes target files.
---

> [!CAUTION]
> **SweepX has no cleanup capability today.** P3 plan, authorization, durable-audit, and executor work is library-only deterministic simulation. The simulator accepts no native path and uses only a sealed fake adapter. Linux has a bounded SQLite journal, one-transaction complete-stream/terminal persistence, and degraded `status --watch` completed replay for persisted completed journal streams; none of that is live, runtime-qualified, or real-execution qualification.

## What works now

| Capability | Current state |
|---|---|
| Linux directory scan | development-grade, read-only, degraded |
| macOS directory scan | development-grade, read-only, handle-bound degraded |
| Windows directory scan | development-grade, read-only, handle-relative degraded |
| `status` | reads terminal state journal-first on Linux and supports degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`; macOS reads the legacy snapshot; Windows durable state is disabled, `state_dir` defaults to `None`, and explicit `--state-dir` fails closed |
| `cancel` | command exists; live cancellation is disabled |
| `explain` | report-only analysis from bounded scan JSON |
| `cache status` | read-only preview-cache diagnostics on Linux/macOS; disabled on Windows |
| Cleaner | read-only metadata list/show with compatibility gates; `cargo-detect` has fixed-input reads and typed evidence but remains hint/report-only |
| CLI/TUI | one `sweepx` entry point; terminal table by default, directory browser via `scan --tui`; detail rescans run as single-flight background work with a 2 s deadline and responsive navigation/quit |
| Trash / Permanent | absent |

The CLI and TUI auto-detect `zh-CN` / `en-US` and accept an explicit `--locale` override. Current machine scan output stays JSON, and `scan --format ndjson` remains disabled. `cache status` supports human/JSON only; NDJSON is a usage error. Missing state/cache returns `absent` without creating directories, and inspection is bounded to `preview-cache/current.json`, the current generation file, and the flat `generations/` / `quarantine/` directories; it does not scan, repair, quarantine, or reveal cached entries or path contents. Linux `status --watch --format ndjson` replays only a completed, persisted stream: it performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, this is not live streaming, does not wait for new events, does not create a background operation, and does not support cancel.
Release automation builds five target archives, checksums, installers, and this GitHub Pages site. No stable release has been published yet.

## Read by question

| What you want to know | Page |
|---|---|
| What is actually implemented | [Introduction](/en/guide/introduction) |
| How to run current read-only commands | [CLI and read-only scanning](/en/cli) |
| Why imported reports cannot execute | [Safety model](/en/safety) |
| Whether a Cleaner is a rule or a script | [Cleaner concepts](/en/cleaners) |
| What an Agent may do | [Agent boundaries](/en/agents) |
| How the crates are layered | [Architecture](/en/architecture) |
| Where P3 ends and future mutation begins | [Roadmap](/en/roadmap) |

## One-sentence status

SweepX has moved beyond pure design into a **runnable read-only development stage**, but it has not entered real cleanup. Any `plan`, `approve`, `execute`, Trash, or Permanent interface remains a future proposal, not a current command.
