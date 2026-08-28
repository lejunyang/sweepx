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
- Because the global `CARGO_TARGET_DIR` override scope across home/env/ancestor/CLI sources is still unresolved, `targetDir` remains `not_checked(config_scope_not_checked)` and `targetShape` remains `unknown(config_scope_not_checked)`.
- The result therefore remains `hint` / `report-only`: it does not create a candidate and does not open plan, approval, or execution.

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
