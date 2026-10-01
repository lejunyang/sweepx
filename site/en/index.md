---
layout: home

hero:
  name: "SweepX"
  text: "See clearly before acting"
  tagline: "A runnable development disk-analysis CLI/TUI with guarded Trash, Linux quarantine, and bounded-directory Permanent previews."
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
  - title: Recoverable cleanup previews
    details: CLI/TUI support explicitly confirmed, live-revalidated single-item Trash. Linux also has full-digest-confirmed, per-item-revalidated off-filesystem quarantine for arbitrary-name stale direct children of /tmp. There is no Permanent fallback, and general plan/approve/execute remain unavailable.
  - title: Linux file/directory Permanent preview
    details: Only a resolved absolute regular-file or bounded real-directory path is accepted; a full-digest challenge, closed manifest, per-action durable intent, and parent-relative unlinkat/rmdir form a separate R4 path. Links, over-limit trees, and cross-platform Permanent remain disabled.
---

> [!CAUTION]
> **SweepX also has a Linux bounded file/directory Permanent development preview.** It requires the ordinary user to type a full digest at a foreground terminal, persists a closed plan, then writes intent, revalidates, and runs each `unlinkat`/`rmdir` action in postorder. It is not secure erase and does not cover links, over-limit trees, or other platforms; Trash failure never invokes it. General P3 plan/execution remains library-only simulation.

## What works now

| Capability | Current state |
|---|---|
| Linux directory scan | development-grade, read-only, degraded |
| macOS directory scan | development-grade, read-only, handle-bound degraded |
| Windows directory scan | development-grade, read-only, handle-relative degraded |
| `status` | reads terminal state journal-first on Linux and supports degraded completed replay through `sweepx --format ndjson status --operation-id ID --watch [--after SXCUR1]`; macOS and Windows read legacy snapshots, with a current-user-private state directory enforced on Windows |
| `cancel` | command exists; live cancellation is disabled |
| `explain` | report-only analysis from bounded scan JSON |
| `cache status` | read-only preview-cache diagnostics on Linux/macOS/Windows |
| Cleaner | read-only metadata list/show with compatibility gates; `cargo-detect` has fixed-input reads and typed evidence but remains hint/report-only |
| CLI/TUI | one `sweepx` entry point; terminal table by default; `scan --tui` enters first and scans progressively, retaining bounded current-level rows while a single-flight 30 s background pass aggregates recursive sizes |
| Trash / Permanent | single-item Trash preview, plus Linux `/tmp` quarantine and a bounded file/directory Permanent preview; link/over-limit/cross-platform Permanent is absent |

The CLI and TUI auto-detect `zh-CN` / `en-US` and accept an explicit `--locale` override. Current machine scan output stays JSON, and `scan --format ndjson` remains disabled. `cache status` supports human/JSON only; NDJSON is a usage error. Missing state/cache returns `absent` without creating directories, and inspection is bounded to `preview-cache/current.json`, the current generation file, and the flat `generations/` / `quarantine/` directories; it does not scan, repair, quarantine, or reveal cached entries or path contents. Linux `status --watch --format ndjson` replays only a completed, persisted stream: it performs one same-snapshot full validation, then returns pages of at most 1024 events; an unknown but syntactically valid cursor yields `stream.reset_required`, while malformed cursor usage remains a usage error. Because events are still constructed after the scan, this is not live streaming, does not wait for new events, does not create a background operation, and does not support cancel.
Release automation builds five target archives, checksums, installers, and this GitHub Pages site. The v0.0.1 development release is published; no stable release has been published yet.


Browser and known-cache discovery in `junk --system` shares a bounded invocation snapshot with classification, avoiding profile enumeration for each candidate. Permission, observation or resource failures set `layoutDiscovery.complete` to false with an `incompleteReason`, report partial and return exit code 4. Confirmed results remain visible; an empty list does not prove there is no junk. The native deadline is cooperative between calls and cannot interrupt blocking OS access. Non-interactive cleanup/Trash requests are rejected before discovery.

Whole-root candidate records bind the currently enabled rules and discovery scope, triggering fresh classification when they change. File-length caches are validated independently, so an old empty candidate report cannot hide results introduced by newly enabled rules.

## Read by question

| What you want to know | Page |
|---|---|
| What is actually implemented | [Introduction](/en/guide/introduction) |
| How to run current commands | [CLI and guarded cleanup previews](/en/cli) |
| Why imported reports cannot execute | [Safety model](/en/safety) |
| Whether a Cleaner is a rule or a script | [Cleaner concepts](/en/cleaners) |
| What an Agent may do | [Agent boundaries](/en/agents) |
| How the crates are layered | [Architecture](/en/architecture) |
| Where P3 ends and future mutation begins | [Roadmap](/en/roadmap) |

## One-sentence status

SweepX is now a **runnable development preview**: scanning, TUI browsing, single-item Trash, Linux stale-temp quarantine, and Linux bounded file/directory Permanent can be exercised. General `plan`, `approve`, `execute`, and broader Permanent remain future work.
