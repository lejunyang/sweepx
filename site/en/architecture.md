---
title: Architecture
---

# Architecture

The architecture story already has one clear spine in the README: one safety core serves CLI, TUI, and Agent workflows. No frontend gets a looser mutation path.

## A constrained state flow

The design is summarized with a single lifecycle:

```text
scan -> explain -> immutable plan -> explicit execution authorization -> live revalidation
     -> platform action -> reconcile -> audit
```

That flow matters because it turns each step into a separate, auditable state rather than a vague “cleanup started” operation. It implies:

- observation is not authorization;
- stale cache is not the current filesystem;
- a platform call result is not the same thing as guaranteed recovery or guaranteed free space.

## Core layers

Based on the current design texts, the architecture can be read as four layers:

| Layer | Responsibility |
|---|---|
| Scanner | Gather read-only directory facts and boundaries with no-follow traversal and sparse state retention. |
| Analyzer | Produce Candidate and Explanation while separating facts, inferences, heuristics, and unknowns. |
| Planner / Authorization | Create immutable plans and bind HumanApproval or ExplicitDangerousDelete to that exact plan. |
| Execution / Audit | Perform live revalidation, call the platform action, and persist intent, result, reconciliation, and audit. |

## Why the Agent must remain constrained

Agent-safe does not mean agent-driven deletion. It means the Agent is deliberately limited:

- the Agent works through structured Core APIs only;
- it may help with read-only scan, explanation, and plan preparation;
- it may not approve a plan, type confirmations, or use the danger flag.

That requirement makes the product architecture Core-centric by definition.

## Sparse state rather than full file inventories

The README also emphasizes sparse scanning state:

- directory aggregation and in-memory queues come first;
- bounded spill appears only after high-water pressure;
- persistent cache avoids storing huge lists of ordinary small files;
- the TUI shows top-K plus `Others` and expands via prioritized live rescans.

This keeps the design focused on large trees without letting state growth become its own risk.

## What can be stated honestly today

The site only claims what the documents already support, so the current architecture conclusion is narrow and explicit:

- the target architecture is one unified safety core;
- destructive features remain under development;
- real platform adapters, approval brokers, Trash executors, and crash reconciliation are not shipped implementation today.
