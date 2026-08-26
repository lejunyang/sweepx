---
title: CLI
---

# CLI

The README labels the command surface as a future interface sketch. That means the docs can explain semantics, but they must not present the commands as something users can run today.

> [!WARNING]
> The command lines below are proposed interface only. The current repository does not ship a runnable `sweepx` binary, and no destructive action is available.

## Read-only scan and explanation

```text
sweepx scan <ABSOLUTE_USER_SELECTED_ROOT> --format ndjson
sweepx explain --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --format json
```

The key point is the split in meaning:

- `scan` produces facts, boundaries, and candidates for the current live generation.
- `explain` binds a single candidate and shows facts, inferences, unknowns, risks, and recovery expectations.
- Neither command creates deletion authority.

## Planning, approval, and execution

```text
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode trash --format json
sweepx plan show --plan-id <PLAN_ID> --format json
sweepx approve --plan-id <PLAN_ID>
sweepx execute --plan-id <PLAN_ID> --approval-id <APPROVAL_ID> --format ndjson
```

The design only allows users to move through a fixed state machine:

1. Create an immutable plan from live data.
2. Review that exact plan in a trusted local surface.
3. Receive and validate an opaque approval id.
4. Revalidate each action again before platform mutation.

So the CLI proposal carries two hard positions:

- chat confirmation, pipe input, or configuration defaults do not count as approval;
- old plans cannot bypass live revalidation.

## Permanent is a separate mode, not a convenience switch

The README also shows a separate Permanent sketch:

```text
sweepx plan create --scan-id <SCAN_ID> --candidate-id <CANDIDATE_ID> --mode permanent --format json
sweepx execute --plan-id <PERMANENT_PLAN_ID> --dangerously-delete
```

This section needs careful interpretation:

- Permanent plans are fully separate from Trash plans.
- `--dangerously-delete` can only authorize an existing Permanent plan.
- The flag records explicit dangerous intent, not human identity.
- AI Agents are explicitly forbidden from invoking it.

## How to read these commands today

The most important takeaway is not the flag list. It is the current status:

- these commands are not runnable today;
- destructive features are unavailable or unqualified;
- the documentation exists to define the future safety protocol, not to claim a current implementation.
