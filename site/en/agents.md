---
title: Agent boundaries
---

# Agent boundaries

Agent-safe does not mean “an Agent may clean automatically.” It means automation receives a narrower, auditable capability set than a local user.

## Currently allowed

After the user provides an explicit scope, an Agent may:

- run `capabilities` and report degraded/report-only/unsupported/disabled states;
- run the development-grade/degraded read-only scanner on user-selected absolute roots on Linux, macOS, or Windows; explicitly use `scan --no-state` when later status/operation state is unnecessary or the state filesystem does not support the journal, but never combine it with `--state-dir`;
- read current JSON and explain errors, boundaries, coverage, and tagged sizes; scan NDJSON is currently disabled;
- run report-only `explain` over bounded scan JSON;
- list or show Cleaner metadata;
- open or summarize read-only TUI input.

The Agent must preserve uncertainty from machine output. It may not rewrite partial as complete, unknown as zero, or potentially reclaimable as guaranteed freed space.

## Currently forbidden

The current CLI has no mutation command, and an Agent must not route around that fact:

- do not treat chat confirmation as HumanApproval;
- do not call safety/audit/executor libraries directly to fabricate a workflow;
- do not create, forge, or consume plans, authorizations, permits, or audit tokens;
- do not run package-manager, browser, or shell cleanup commands;
- do not invoke unimplemented `plan`, `approve`, `execute`, or `--dangerously-delete` interfaces;
- do not describe a fake-executor receipt as a real cleanup result.

## Structured output and language

Current scan automation should use bounded JSON. Linux has the durable journal; the event-journal crate retains a Linux-test-only bounded cursor replay/reset substrate that is not wired into Core or the CLI. Events are still constructed after the scan, and the live sink, runtime qualification, and public `status --watch`/NDJSON surface remain incomplete. `--locale` changes human-facing text only; it does not change schema keys, status values, reason codes, or capability states. An Agent should preserve those stable fields through translation and summary.

## The future boundary remains narrower

The roadmap may eventually let an Agent assist with scan, explain, and plan display, but it may not drive a native dialog, OS verifier, trusted terminal challenge, or dangerous switch. Even if a user says “approved” in chat, a future Core must verify an opaque approval from a trusted local surface and perform fresh live revalidation. No such CLI workflow exists today.
