---
title: Cleaner concepts
---

# Cleaner concepts

A Cleaner is a versioned domain-rule package with evidence and compatibility constraints. It is not an arbitrary shell script and is not an executable cleanup plugin today.

## Current built-ins

The repository contains two example packages:

| Cleaner ID | Description | Current surface |
|---|---|---|
| `org.sweepx.cargo-target` | Cargo workspace target build outputs | metadata/report-only |
| `org.sweepx.chromium-rebuildable-cache` | Chromium HTTP and Code Cache, separated from application state | metadata/report-only |

A package carries a manifest, rules, and evidence documentation. Rules use a constrained declarative VM. The current CLI gives them no I/O, external-command, or native-mutation path.

## `list` versus `show`

```bash
cargo run -p sweepx-cli -- --format json cleaner list
cargo run -p sweepx-cli -- --format json cleaner show <CLEANER_REF>
```

- `list` summarizes every built-in package and reports `compatible` / `incompatible` plus `reportOnly`.
- `show` accepts `id` or `id@version`, but fails with a compatibility error when the current Core does not satisfy `requires.core`.
- No flag bypasses the compatibility gate, and visibility in list never makes a package executable.

The current Core is `0.1.0`, while both built-in manifests require `>=1.0.0, <2.0.0`. List therefore returns partial honestly, and show fails closed. That is expected.

## Current `cargo-detect` boundary

Beyond metadata, `org.sweepx.cargo-target` now also has the experimental read-only `cleaner cargo-detect` surface:

- The Scanner now provides a bounded locator batch reader for fixed file reads along already-admitted locators; all three backends share that bounded contract.
- The workspace fixed-input collector reads only `Cargo.toml`, `.cargo/config`, and `.cargo/config.toml`, and fails closed on replacement, symlink/reparse, mount changes, resource limits, and cancellation.
- When manifest binding is valid, typed workspace evidence can become `known`.
- `data.hints[].evidence.cargo.configScope` now exposes the `cargo.config-scope.v1` wire contract. Its top-level fields are `schema`, `decoderId`, `workspace`, `ancestorConfigs`, `cargoHomeConfig`, `environment`, `cli`, `invocationCwd`, `precedenceComplete`, and `blockers[]`.
- `workspace.pairSnapshot` uses `stable_snapshot|not_checked|failed`; the contract for `workspace.config` / `workspace.configToml` allows `present|verified_absent|not_checked|failed`, but the current production projection downgrades time-local absence to `not_checked` whenever the pair is not stable; `workspace.selected` uses `config|config_toml|none|not_checked`; and `workspace.targetDirDeclaration` uses `known|verified_absent|not_checked|unknown`.
- `environment` records presence only for `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, and `CARGO_HOME`: each entry is `present_redacted|verified_absent`. `valueRedacted` is always present and is `true` for the former and `false` for the latter; no environment value is retained or serialized.
- The workspace `build.target-dir` declaration is redacted in the same way. When `targetDirDeclaration.state=known`, the projection returns only `source=config|config_toml` plus `valueRedacted=true`, never the raw relative-path value.
- Only an explicitly set, absolute `CARGO_HOME` is captured privately after the Cleaner compatibility gate and revalidated after the scan. The collector observes only whether direct-child `config` / `config.toml` files exist under that home: a hit projects only `cargoHomeConfig.state=present_redacted`, and the observation remains non-atomic. A miss, an unset `CARGO_HOME`, or use of Cargo's default home remains `not_checked` and is never promoted to `verified_absent`. The scanner performs bounded, no-follow, handle-bound metadata inspection of matched files; it never reads, parses, uses, or serializes config contents or `target-dir` values, and no environment value or home/config path enters the output.
- The SweepX `cargo-detect` CLI surface has no Cargo passthrough `--target-dir` or `--config`, so that entry point records `cli.targetDir` and `cli.configOverrides` as structurally `verified_absent`. Plain Core calls remain `not_checked` unless they explicitly use the no-overrides invocation contract.
- The process cwd is captured privately together with an identity snapshot only after the Cleaner compatibility gate passes. Exact native-path and identity equality with a revalidated workspace root yields only `path_matches_revalidated_workspace_root`; because no cwd handle is retained across phases, `invocation_cwd_identity_not_bound` remains. The cwd path itself is never serialized.
- `blockers[]` is a sorted, deduplicated stable vocabulary. An explicit Cargo-home config hit uses `cargo_home_config_present_redacted`; unchecked and failed observations use `cargo_home_config_not_checked|cargo_home_config_failed`. Other blockers continue to cover unresolved ancestor configs, environment overrides, CLI inputs, invocation cwd, and workspace config state.
- `.cargo/config` and `.cargo/config.toml` are now observed through one retained `.cargo` handle and one bounded enumeration cursor; ASCII case aliases and duplicate names fail closed. Directory enumeration still cannot exclude concurrent ABA, so the observation remains non-atomic: an unseen member stays `not_checked` and cannot become `verified_absent` or a stable selection.
- The Cargo-home presence ledger uses only bounded, no-follow, handle-bound metadata inspection; config contents are not read, parsed, used, or serialized. Ancestor configs and the workspace pair are still unresolved, so `precedenceComplete` remains `false`; `targetDir` remains `not_checked(config_scope_not_checked)` and `targetShape` remains `unknown(config_scope_not_checked)`.
- Core library callers can use `cleaner_cargo_detect_with_cancel(..., &CancellationToken)` to cooperatively cancel fixed-input/evidence collection after the scan. This token does not own the synchronous filesystem scan; that scan uses a separate internal token, so cancellation requested during the scan is first observed when post-scan collection begins.
- If collection observes cancellation, the affected typed evidence fails closed as `unknown(cancelled)`, and the terminal envelope uses `status=cancelled`, exit 10, and `reasonCode=cancelled`. Cancellation does not promote an existing observation to a candidate and grants no plan, approval, execution, or mutation authority.
- The current CLI only constructs a local token that is not connected to signals. There is no Ctrl-C handler, and neither `sweepx cancel` nor a live in-process operation registry is wired to it. The caller-owned token is therefore a library integration seam, not a user-triggerable CLI cancellation capability today.
- The result therefore remains `hint` / `report-only`: it does not create a candidate and does not open plan, approval, or execution. Top-level `candidateAllowed`, `planAllowed`, `approvalAllowed`, and `executionAllowed` all remain `false`.

## Rule output is not a cleanup action

Rule evaluation may express known/unknown state, evidence, risk, and report-only status. It cannot:

- invent a raw path not supported by scan evidence;
- lower risk when evidence is unknown;
- run Cargo, browser, or operating-system commands;
- delete, move, or trash a file;
- create a plan, authorization, or permit.

Even if a future Cleaner can produce candidates, stale/incomplete provenance from imported scan JSON still forces them non-executable.

## Future qualification gates

Moving from “describable” to “eligible to participate in execution” requires, at minimum, package canonicalization, signing and revocation, Core/version compatibility, deterministic rules, platform and application-version evidence, reference/activity/recovery fixtures, complete live identity, and the common Safety Core plan/authorization flow. Those gates are not all complete, so the current promise is metadata/report-only.
