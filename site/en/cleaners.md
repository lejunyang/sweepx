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
- The Cargo fixed-input collector reads only `Cargo.toml`, `.cargo/config`, and `.cargo/config.toml`, and fails closed on replacement, symlink/reparse, mount changes, resource limits, and cancellation.
- When manifest binding is valid, typed workspace evidence can become `known`.
- `data.hints[].evidence.cargo.configScope` now exposes the `cargo.config-scope.v1` wire contract. Its top-level fields are `schema`, `decoderId`, `workspace`, `ancestorConfigs`, `cargoHomeConfig`, `environment`, `cli`, `invocationCwd`, `precedenceComplete`, and `blockers[]`.
- `workspace.pairSnapshot` uses `stable_snapshot|not_checked|failed`; the contract for `workspace.config` / `workspace.configToml` allows `present|verified_absent|not_checked|failed`, but the current production projection downgrades time-local absence to `not_checked` whenever the pair is not stable; `workspace.selected` uses `config|config_toml|none|not_checked`; and `workspace.targetDirDeclaration` uses `known|verified_absent|not_checked|unknown`.
- `environment` records presence only for `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR`, and `CARGO_HOME`: each entry is `present_redacted|verified_absent`. `valueRedacted` is always present and is `true` for the former and `false` for the latter; no environment value is retained or serialized.
- The workspace `build.target-dir` declaration is redacted in the same way. When `targetDirDeclaration.state=known`, the projection returns only `source=config|config_toml` plus `valueRedacted=true`, never the raw relative-path value.
- `blockers[]` is a sorted, deduplicated stable vocabulary. The current implementation exposes `ancestor_configs_failed|ancestor_configs_not_checked|cargo_build_target_dir_present_redacted|cargo_home_config_failed|cargo_home_config_not_checked|cargo_home_present_redacted|cargo_target_dir_present_redacted|cli_config_overrides_failed|cli_config_overrides_not_checked|cli_target_dir_failed|cli_target_dir_not_checked|invocation_cwd_binding_failed|invocation_cwd_not_bound|workspace_config_duplicate_key|workspace_config_include_unsupported|workspace_config_malformed|workspace_config_not_checked|workspace_config_pair_failed|workspace_config_pair_not_stable|workspace_config_read_failed|workspace_config_resource_limit|workspace_config_shape_unsupported|workspace_target_dir_invalid`.
- Because `.cargo/config` and `.cargo/config.toml` are read through separate bounded requests, their joint presence/absence cannot be promoted into a stable selection without an atomic `pairSnapshot`; on case-insensitive platforms, that also means the result cannot prove an alternate-casing variant is absent.
- `precedenceComplete` therefore remains `false`. The home/env/ancestor/CLI/cwd precedence chain is still intentionally open, so `targetDir` remains `not_checked(config_scope_not_checked)` and `targetShape` remains `unknown(config_scope_not_checked)`.
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
