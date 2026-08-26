---
title: Roadmap
---

# Roadmap

Section 4 of the roadmap is not a release calendar. It is a staged capability boundary that says which features still cannot ship without evidence.

> [!CAUTION]
> SweepX remains a design-stage project today. Phases P0 through P3 exclude real platform mutation, so destructive capability is not currently available.

## Phase progression

| Phase | Visible increment | What still stays out of scope |
|---|---|---|
| P0 | Contract, schemas, safety policy, fixture and oracle baseline | Any runnable cleaner or platform mutation |
| P1 | 0.1 read-only scanner CLI | Cleaner recommendations, planning, approval, Trash, Permanent |
| P2 | 0.2 explainable analysis, TUI, read-only Agent workflow | Plan approval, real execution, browser-state deletion, policy changes |
| P3 | 0.3 immutable planning and simulated execution | Any native Trash or Permanent call |
| P4 | 0.9 native Trash beta on qualified tuples only | Permanent, cross-filesystem Trash, remote/provider/system paths |
| P5 | 1.0 stable ordinary-user product | Any unqualified capability, elevated cleaning, broad manager mutation |
| P6 | Post-v1 capability tracks | Any expansion without a new threat model and independent evidence |

## What this means right now

This phase model directly controls how the site must talk about the product:

- SweepX has not reached the qualified native Trash beta described for P4.
- Destructive features therefore cannot be described as beta-ready, much less available.
- Permanent comes later and only after an independently qualified capability cell.

## How Sections 2 and 4 reinforce each other

Section 2 defines the safety floor. Section 4 defines the stage boundary. Together they mean:

1. Every phase inherits the ordinary-user boundary, exact-plan binding, and fail-closed behavior.
2. A team cannot justify weaker safety by saying a feature will be “fixed later”.
3. Even if a prototype can run, the public docs must still say unavailable or unqualified until the required evidence exists.

## Stop-ship rules

The roadmap also lists conditions that block release, especially when:

- any hard protection, approval, intent, permit, or reconciliation invariant can be bypassed;
- CLI, TUI, Cleaner API, and Skill disagree on identity, risk, plan digest, or outcome semantics;
- errors, unknowns, or incomplete subtrees are rendered as if they were complete or zero;
- an adapter cannot prove that Trash failure never falls through to Permanent.

That makes the roadmap closer to a release gate document than a generic feature backlog.

## Honest current status

Based on the current documents, the narrow and accurate statement is:

- SweepX is a design snapshot with strong safety framing.
- Read-only and simulated phases are documented more clearly than destructive execution.
- Destructive features remain under development and are not available for use today.
