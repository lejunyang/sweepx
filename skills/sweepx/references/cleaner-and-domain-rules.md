# Cleaner and domain rules

Use this contract before accepting cleaner evidence, manager/native probes, official cleanup actions, developer artifacts, or browser data. A rule can identify and explain an object; it cannot mint authority or bypass Core.

## Contents

- [Inspect cleaner packages](#inspect-cleaner-packages)
- [Constrain probes and commands](#constrain-probes-and-commands)
- [Handle trust and drift](#handle-trust-and-drift)
- [Developer artifacts](#developer-artifacts)
- [Package-manager state and GC](#package-manager-state-and-gc)
- [Browser storage](#browser-storage)

## Inspect cleaner packages

Use only read-only inspection before selecting a rule-driven candidate:

```sh
sweepx cleaner list --format json
sweepx cleaner show "<cleaner-id>[@<version>]" --format json
sweepx cleaner verify "<package>" --format json
```

Require every manifest to declare schema, cleaner ID/version, supported platforms and exact target-version/layout ranges, rule kind, discovery method, evidence requirements, risk floor, target granularity, supported action, probe/official command, mutation classification, capabilities, unknown-version behavior, publisher, digest, signature, expiry, and trust/revocation metadata.

Treat a rule as typed data interpreted by the shared Core state machine. It may never add a path outside scope, lower Core risk, label an object inherently safe/deletable, mint approval or a permit, weaken protection, follow a link, cross a mount, invoke an adapter directly, or create a plugin-only candidate model. Rule output maps back to the standard Candidate and Explanation contracts. Missing evidence is explicit `unknown`, `unsupported`, or `not_checked`, never an omitted false value.

## Constrain probes and commands

Allow only a small audited native-probe set where declarative matching cannot establish semantics, such as browser profile/storage-key decoding or manager reachability. Invoke a fixed executable identity with a fixed argv template—never a shell—with scrubbed environment, explicit cwd, ordinary-user credentials, no stdin, and strict time/output/network/write limits. Pin command, version, output schema, and declared capabilities.

Classify each call:

- `Z0`: strict filesystem read-only; default discovery level.
- `Z1`: guarded semantic query; run only in the declared isolated/offline/no-update/no-daemon environment with write auditing.
- `Z2`: potentially stateful query; never run automatically in strict discovery. Report that it needs a separate explicit human-authorized workflow and do not use it for plan eligibility.
- `M`: mutation; never run during scan, explain, or plan.

Track `semanticReadOnly` and `zeroWriteVerified` independently. A query-like name, dry-run, or help text does not prove zero writes. Never request credentials, network access, daemon startup, process termination, lock removal, privilege, or state repair to make a probe succeed.

An official external dry-run is evidence only; a changed result makes the plan stale. An official mutation may run only if a first-party fixed Core adapter explicitly supports its versioned capability, exact structured dry-run/object-set/scope digest, and reconciliation semantics. Treat a manager mutation that bypasses Trash as a separately planned Permanent R4 action. Revalidate the evidence after durable intent. Never invoke the command directly. If it exits, times out, or emits unparsable/contradictory output, preserve the structured/native evidence, return exit 13, and never fall back to raw deletion.

## Handle trust and drift

Require a signed built-in/vendor rule or an explicitly trusted local publisher. On missing, invalid, expired, or revoked signature; same-version digest collision; incompatible schema/Core/probe ABI; undeclared capability; executable drift; unsupported target/layout version; stale evidence; or sandbox/write-audit failure, return exit 12 and keep the rule report-only. Installation or trust changes the cleaner-set digest and makes old plans stale; it never grants execution authority.

Run only capabilities advertised and currently qualified for the exact platform, filesystem/provider, manager/browser/tool version, adapter, policy, and cleaner digest. Unknown or out-of-range versions are report-only. Never extrapolate from a nearby version or another operating system.

## Developer artifacts

Classify developer data by owner and semantic object, not by directory name alone:

- project-local rebuildable output;
- shared/content-addressed cache or store;
- installed dependencies/environments;
- SDK/toolchain/runtime;
- user/runtime/source/local-only state;
- container, VM, volume, image, emulator, or device state.

Require owning manager, canonical identity, object class/granularity, references, activity/activation and official state, sharing/concurrency, recovery/redownload/rebuild requirements, versioned facts, blockers, and unknowns. Prefer an owner-supported object-level action or GC. Never replace an available manager action with raw filesystem deletion of the same semantic object.

The sole v1 raw-filesystem distinction is a first-party versioned rule for a complete project-local regenerable output root, such as an exact Cargo `target` tree. Core may propose only that closed directory for platform Trash, with risk at least R2, after proving it is not a shared manager store; no manager command runs, and all ordinary plan/authorization/revalidation gates apply. This exception never covers package stores, installed environments, toolchains, system runtimes, credentials/signing material, source, archives, volumes, local-only artifacts, or container/VM/device state.

Do not force manager locks, stop daemons/processes, reset stores/volumes, mutate global/shared state, or uninstall an SDK/toolchain through a generic cleaner. Require a separately designed, advertised, version-qualified high-risk capability and exact approval; otherwise report unsupported. No query establishes absence of references across all users, projects, containers, VMs, CI workers, remote hosts, or offline media.

## Package-manager state and GC

Interpret a protected package-manager state anchor narrowly and authoritatively: it means the manager's databases, configuration, locks, receipts, transaction records, and rollback state. These objects are non-approvable and never subject to raw deletion or generic cleanup.

Do **not** treat separately modeled manager cache artifacts as protected state merely because they are stored under a manager-owned hierarchy. They may be considered only when the owning manager provides a supported GC/action that precisely models those cache objects, scope, references, and result. The fixed Core adapter must be signed/version-qualified, use no shell, bind the exact structured dry-run/object-set/scope digest into the plan, apply Permanent R4 semantics where the action bypasses Trash, obtain exact execution authorization, rerun evidence at preflight, write per-action durable intent/outcome, and reconcile uncertainty. Any scope drift is stale. A manager cache that lacks this complete supported GC path remains report-only; it never becomes eligible for raw deletion.

## Browser storage

Identify exact browser product, full version, channel, profile, running/quiescent state, and version-matched layout/parser. Preserve the engine's full serialized storage identity. For Chromium include origin, top-level schemeful site, ancestor-chain state, nonce or opaque precursor when present, bucket, and actual `StoragePartition` identity. For other engines preserve the complete container/privacy/partition identity. Simplified domain/origin/site tuples are display-only and hostname alone is never a destructive key.

Separate HTTP/code/startup cache from Cache Storage, IndexedDB, Local Storage, cookies, Service Worker state, history/session data, and model/application assets. Prefer browser-supported UI/API/policy. Treat a running or unresolved profile, opaque partition, unsupported/unknown layout, incomplete consistency group, missing WAL/journal/blob/body/script/salt metadata, unresolved Safari mapping, lock file, application-state store, site-level raw files, or model asset as skipped/report-only. The Agent never edits browser databases, directories, or locks directly.

The only v1 filesystem exception is a first-party, version-qualified Cleaner proposal for an exact, quiescent, complete whole HTTP/code/startup-cache root. It must explicitly exclude application state, bind the full version/profile/layout/manifest evidence, carry risk at least R2, and still use immutable planning, trusted human approval, live manifest revalidation, and platform Trash. Unknown versions or any missing consistency evidence disable the action.
