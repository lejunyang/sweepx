# Plans, authorization, and protections

Use this contract to create and review immutable plans, obtain the Agent-safe HumanApproval path, understand the separate ExplicitDangerousDelete product path, apply risk tiers, and enforce non-bypassable protection.

## Contents

- [Create an immutable plan](#create-an-immutable-plan)
- [Review risk and consequences](#review-risk-and-consequences)
- [Obtain trusted human approval](#obtain-trusted-human-approval)
- [Approval attestation boundary](#approval-attestation-boundary)
- [Apply hard protections](#apply-hard-protections)

## Create an immutable plan

Default to Trash. Select only current explained candidate IDs, never arbitrary paths, globs, recursive selectors, displayed paths, or imported JSON:

```sh
sweepx plan create --scan-id "<scan-id>" --candidate-id "<candidate-id>" --mode trash --format json
sweepx plan show --plan-id "<plan-id>" --format json
```

Capture `planId` from `plan.result`. `--output` may save a result for human review, but never creates an importable executable plan. The global content-addressed selection store is limited to 16 MiB. A sparse preview row, synthetic `Others`, or discarded detail is not selectable plan evidence; Core must perform a targeted current live enumeration before planning such detail. Require Core's persisted logical envelope to use `schema=sweepx.plan/v1` and retain:

```text
DeletionPlan {
  planId, nonce, createdAt, expiresAt, hostInstanceId, userIdentity,
  scanId, scanRootIdentity, mode: Trash | Permanent,
  candidateSchemaVersion, scannerSemanticsVersion,
  safetyPolicyVersion, safetyPolicyDigest, protectedAnchorSnapshotDigest,
  adapterCapabilitiesDigest, cleanerSetDigest, items[], aggregateRisk,
  canonicalDigest
}

PlanItem {
  itemId, candidateId, explanationDigest, actionKind, topLevelActionId,
  parentReopenRecipe, nativeBasename,
  expected parent/object/object-domain/type/mount/link identities,
  expectedMetadataFingerprint, subtreeComplete, descendantManifest?,
  cleanerEvidenceDigest?, officialActionDigest?,
  riskTier, riskFactors[], recoveryExpectation
}
```

Require a closed descendant manifest with stable identities and postorder action IDs for every directory. Limit the global exact descendant-manifest store to 64 MiB; reject rather than truncate, approximate, or silently evict an active manifest when the store is full. When scan/preview detail was discarded, only the targeted live enumeration's exact closed manifest may define deletion targets. Reject a directory plan if its final aggregate is missing, revision-mismatched, incomplete, stale, or preview-only. Changing any target, order, mode, risk, rule/adapter/policy/anchor/cleaner digest, or descendant manifest creates a new plan ID/full canonical digest and invalidates prior authorization. Never edit a plan artifact. Keep Trash and Permanent in separate batches.

## Review risk and consequences

Show the human exact mode, item/action counts, display paths/types, full canonical plan digest, short attention fingerprint, expiry, every item/action risk, size variants and uncertainty, boundaries, blockers, recovery expectation, cold-start/download/recreation impact, and irreversible consequences. Label the short fingerprint as an attention check only; it is never an authorization key and never substitutes for the full digest bound into the sealed `ApprovalRecord`.

Use these floors:

- `R1`: complete, local, rebuildable ordinary object; Trash may use normal exact-plan confirmation.
- `R2`: directory, batch, recent/user content, hard-link/reclaim uncertainty, or shared cache; Trash requires expanded review.
- `R3`: executable/app, database, VM/container/package state, observed-open, provider/network/removable, or material unknown; default skip, and allow only a policy-supported Trash action with individual enhanced confirmation.
- `R4`: every Permanent action and every non-empty permanent directory; require a separate Permanent plan and either an irreversible HumanApproval challenge or the product's explicit dangerous authorization. The Agent path always uses the former.
- `BLOCKED`: expose no action and no approval path.

Risk may rise during revalidation but may never exceed that action's exact authorized ceiling. A batch maximum is informational only and never substitutes for per-action authorization.

## Obtain trusted human approval

Pause and ask the human to start the trusted local foreground interaction for the persisted plan:

```sh
sweepx approve --plan-id "<plan-id>"
```

The command requests the Broker's approval surface; it is not itself proof of approval. Prefer a native first-party SweepX dialog in the current local foreground session. If a trustworthy native surface is unavailable, allow a trusted foreground terminal/TUI typed challenge as the fallback. The typed challenge may use the short plan fingerprint only as an attention check; the Broker still seals the full canonical digest and exact plan fields. Reject background, redirected, piped, synthetic, remote-controlled, wrong-user, or wrong-session input for the typed fallback.

Windows may optionally use non-elevating Windows Hello through `UserConsentVerifier`, and macOS may optionally use non-elevating `LocalAuthentication`, as local presence/consent evidence inside the Broker flow. Neither mechanism grants privilege, widens authority, replaces plan review, or replaces the full-digest `ApprovalRecord`. Linux has no universal equivalent in v1; use the trusted foreground typed fallback when no qualified native dialog exists. Never invoke UAC, `sudo`, polkit, or another elevation mechanism merely to confirm approval.

The Agent must not run `sweepx approve`; launch, open, click, or drive a native dialog; invoke an OS verifier; supply, type, paste, pipe, or prefill challenge input; automate a terminal/TUI or accessibility interface; or use a remote plugin to approve. Conversational assent, `--yes`, `--force`, config, environment, API/RPC token, JSON body, standing approval, or another plan's approval is invalid. The Broker returns only an opaque short-lived `approvalId`.

Resume only after the human reports completion and the supported structured interface exposes the opaque ID. Inspect only normal read-only `plan show`/`status` data. Never request a broad or reusable approval, and never let one action borrow another action's approved risk.

## Approval attestation boundary

Private `ApprovalRecord` validation belongs exclusively to the trusted Broker/Core. The Agent must **not** request, inspect, copy, edit, import, construct, decode, authenticate, or independently validate the private record. It requires only a structured Core attestation from `execute` or supported read-only status that the private approval was validated for this exact plan.

Core's private `schema=sweepx.approval/v1` record must be authenticated/sealed and bind, at minimum, the opaque approval ID, plan ID and full canonical plan digest, exact mode, exact item/action identities and counts, `approvedRiskByAction`, descendant-manifest digests, policy/anchor/cleaner/adapter digests, plan schema, approving user, host, trusted foreground channel, workflow session, approval/expiry time (at most five minutes), confirmation kind/evidence, nonce, and single-use claim/consumed state. This complete record is the security binding. A displayed or typed short fingerprint is only an attention check; equality or collision of that short value cannot validate a different full digest. Raw record, keys, confirmation evidence, and nonce never leave Broker/Core.

Stop if the observable attestation reports edited, expired, non-local, unauthenticated, replayed, reused, already claimed/consumed, wrong user/host/session, or any plan/mode/item/action/risk/digest mismatch. Approval is evidence of intent only; live Core preflight must still pass.

The product also defines noninteractive-capable `execute --plan-id ID --dangerously-delete` as a separate explicit authorization for an existing Permanent R4 plan. Core creates, seals, and atomically claims a single-use `DangerousDeleteRecord` bound to the same exact plan/mode/items/actions/risk/digests/user/host/session before any action intent. It records only that the caller supplied the explicit flag; it does not claim the caller was human. Trash/stale/expired plans and simultaneous `--approval-id` are rejected. **Agents must never call or automate this path**; they always pause for the normal Broker and resume with its opaque `approvalId`.

## Apply hard protections

Block these at plan, approval, revalidation, Core, and adapter layers with no approval path:

- filesystem, volume, mount, bind, mounted-folder, automount, and UNC share roots or aliases;
- OS boot/recovery/system/device/virtual-filesystem anchors;
- the home/profile root and the parent containing all profiles;
- Trash/Recycle Bin internals;
- SweepX executable, installation, active cwd, config, cache/spill, plan, lock, approval, and audit stores;
- protected files/paths/identities and any ancestor whose whole-object action contains one;
- device/socket/FIFO, Windows device namespace, unmodeled alternate data streams, and special/unknown objects or reparse types;
- targets outside the admitted scan root, with unverified identity/parent/type/mount/containment, or with unapproved/new/unreadable descendants;
- anything under a real no-follow ancestor containing a `.sweepx-protect` directory entry of any type. Never open/follow the marker; inability to check it is blocked. If a human removes it outside SweepX, restart scan, explain, plan, and approval.

Protect package-manager **authoritative state anchors**: authoritative databases, configuration, locks, receipts, transaction records, and rollback state. This definition intentionally excludes separately modeled cache artifacts managed by an owner-supported GC. Such cache artifacts are not automatically safe: they remain eligible only through a fixed, version-qualified Core adapter with exact evidence, immutable planning, human approval, revalidation, intent/outcome audit, and reconciliation. Raw deletion of manager-owned state or caches remains forbidden.

Reject empty, relative, malformed, wildcard/glob, device-namespace, lossy, or noncanonical target input. Resolve alias equivalence through native identities and mount/volume APIs, not string prefixes. Never expose or use `ignore-safety` or `delete-any-path`. Treat `--yes`, `--force`, `--recursive`, and execution-time `--permanent` as usage errors. No accepted option, including `--dangerously-delete`, policy, config, environment, plugin, or UI may disable protections, follow links, cross mounts, ignore identity/plan/policy, elevate, expand targets, turn unknown into success, or change a Trash plan into Permanent.
