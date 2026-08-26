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
    details: Linux has a degraded development scanner. Explanation, status snapshots, Cleaner metadata, and bounded TUI views run today. macOS and Windows scanning remains an unsupported stub.
  - title: Evidence never becomes authority
    details: Imported scan JSON is forced to stale, incomplete, report-only provenance. Viewing a report, explanation, or TUI never creates deletion authority.
  - title: Mutation remains sealed off
    details: There is no plan, approve, or execute CLI, no native Trash/Permanent adapter, and no implementation that deletes target files.
---

> [!CAUTION]
> **SweepX has no cleanup capability today.** P3 plan, authorization, durable-audit, and executor work is library-only deterministic simulation. The simulator accepts no native path and uses only a sealed fake adapter.

## What works now

| Capability | Current state |
|---|---|
| Linux directory scan | development-grade, read-only, degraded |
| macOS / Windows scan | unsupported compilation stub |
| `status` | reads a persisted terminal snapshot |
| `cancel` | command exists; live cancellation is disabled |
| `explain` | report-only analysis from bounded scan JSON |
| Cleaner | read-only metadata list/show with compatibility gates |
| CLI/TUI | bounded input and read-only viewing |
| Trash / Permanent | absent |

The CLI and TUI auto-detect `zh-CN` / `en-US` and accept an explicit `--locale` override. JSON and NDJSON machine fields do not change with the display language.

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
