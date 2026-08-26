---
title: Safety
---

# Safety

Section 2 of the roadmap defines the safety floor as a requirement inherited by every phase, frontend, cleaner, and platform adapter. A delivery phase cannot waive it just to hit a date.

> [!CAUTION]
> The implementation is still under development. The constraints below describe what a future release must satisfy; they do not mean destructive features exist today.

## Non-negotiable floor

| Constraint | Meaning on this site |
|---|---|
| Ordinary-user boundary | SweepX runs as the current ordinary user and does not legitimize an elevated destructive runtime. |
| Read-only scanning | Scanning is metadata-only, no-follow, same-mount/volume, streaming, and error-visible. |
| Type separation | Candidate, Explanation, DeletionPlan, ExecutionAuthorization, PreflightPermit, platform result, and audit record stay distinct. |
| Exact-plan binding | Old cache, directory age, imported data, or negative process observations cannot become deletion permission. |
| Trash-first policy | Trash failure, denial, cancellation, or ambiguity must never silently degrade to Permanent. |
| Hard protections | Roots, system areas, home/profile roots, SweepX state, and protected anchors remain non-approvable. |

## Why destructive features must be marked unavailable

The roadmap combines two facts:

- The safety floor cannot be weakened in any phase.
- P0 through P3 explicitly exclude real platform mutation, and P4 is only a capability-gated native Trash beta.

So the honest public statement today is:

- The implementation is under development.
- Destructive workflow is unavailable.
- Permanent mode is not yet qualified and cannot be implied by docs.

## Approval must stay separate from execution

The roadmap breaks one executable action into distinct objects:

1. Read-only observation produces Candidate and Explanation.
2. Planning produces an immutable plan.
3. Human approval or explicit dangerous authorization binds that exact plan.
4. Execution still performs live revalidation.
5. Platform outcomes and audit records are persisted separately.

That structure rules out two shortcuts by design: there is no `scan -> execute` path, and there is no `Trash failed -> Permanent` fallback.

## Authorization semantics

Even if a future release offers HumanApproval or `--dangerously-delete`, both must obey exact-plan binding:

- HumanApproval binds the full canonical plan digest, mode, item set, risks, and TTL.
- `--dangerously-delete` authorizes an existing Permanent plan only and is not proof of human identity.
- Agents may prepare a plan but may not drive approval surfaces or invoke the danger flag.

## Communication rules

All product surfaces should preserve the same distinctions:

- Facts, inferences, recommendations, and unknowns remain visibly separate.
- `unknown` must not be rendered as `0`.
- “potentially reclaimable” is not “guaranteed freed space”.
- Missing qualification evidence means fail closed.
