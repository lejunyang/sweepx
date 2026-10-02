//! Bounded legacy sync signatures, without evaluating configuration or parsing TypeScript.
//!
//! Source shapes: tagged SvelteKit 1.0.0/2.0.0 `core/sync/write_tsconfig.js`,
//! `write_ambient.js`, `core/env.js` and `constants.js`. Compiler config hooks can change these
//! shapes; unsupported output remains unknown. File signatures are forgeable and non-atomic.

use super::{ProjectFormatEvidence, ProjectFormatStatus, exceeds_json_depth, outcome};
use serde::Deserialize;
use std::collections::BTreeMap;
use sweepx_catalog::junk::ProjectContentFormat;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncConfig {
    compiler_options: CompilerOptions,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompilerOptions {
    #[serde(default)]
    root_dirs: Vec<String>,
    paths: Option<BTreeMap<String, Vec<String>>>,
    isolated_modules: Option<bool>,
    module: Option<String>,
    target: Option<String>,
    module_resolution: Option<String>,
    base_url: Option<String>,
    imports_not_used_as_values: Option<String>,
    preserve_value_imports: Option<bool>,
    verbatim_module_syntax: Option<bool>,
    no_emit: Option<bool>,
}

/// Recognizes the bounded JSON and generated ambient signatures of legacy SvelteKit sync output.
/// It does not evaluate `svelte.config.js`, follow aliases/globs, establish a tool version or parse
/// arbitrary TypeScript/JSONC. Even recognized files are forgeable, non-atomic and report-only.
pub fn inspect_sveltekit_sync(config: &[u8], ambient: &[u8]) -> ProjectFormatEvidence {
    let profile = ProjectContentFormat::SvelteKitLegacySync;
    if config.len() > 256 * 1024 || ambient.len() > 256 * 1024 || exceeds_json_depth(config) {
        return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
    }
    let config: SyncConfig = match serde_json::from_slice(config) {
        Ok(config) => config,
        Err(error) => {
            let (status, reason) = if error.to_string().starts_with("recursion limit exceeded") {
                (ProjectFormatStatus::Unknown, "resource_limit")
            } else {
                (ProjectFormatStatus::Invalid, "invalid_json_or_fields")
            };
            return outcome(profile, status, reason);
        }
    };
    let options = &config.compiler_options;
    let lists = [&config.include, &config.exclude, &options.root_dirs];
    if lists
        .iter()
        .any(|list| list.len() > 256 || list.iter().any(|value| value.len() > 4096))
        || options.paths.as_ref().is_some_and(|paths| {
            paths.len() > 256
                || paths.iter().any(|(key, values)| {
                    key.len() > 256 || values.len() > 16 || values.iter().any(|v| v.len() > 4096)
                })
        })
    {
        return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
    }
    let has = |list: &[String], value: &str| list.iter().any(|item| item == value);
    let common = options.root_dirs.len() == 2
        && has(&options.root_dirs, "..")
        && has(&options.root_dirs, "./types")
        && options.paths.is_some()
        && options.isolated_modules == Some(true)
        && options.module.as_deref() == Some("esnext")
        && options.target.as_deref() == Some("esnext")
        && has(&config.include, "ambient.d.ts")
        && has(&config.include, "./types/**/$types.d.ts")
        && has(&config.exclude, "../node_modules/**");
    let legacy_node = options.module_resolution.as_deref() == Some("node")
        && options.base_url.as_deref() == Some("..")
        && options.imports_not_used_as_values.as_deref() == Some("error")
        && options.preserve_value_imports == Some(true);
    let legacy_bundler = options.module_resolution.as_deref() == Some("bundler")
        && options.verbatim_module_syntax == Some(true)
        && options.no_emit == Some(true)
        && has(&config.include, "non-ambient.d.ts");
    if !common || !(legacy_node || legacy_bundler) {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "unsupported_sync_config_shape",
        );
    }
    let ambient = match std::str::from_utf8(ambient) {
        Ok(ambient) => ambient,
        Err(_) => {
            return outcome(
                profile,
                ProjectFormatStatus::Invalid,
                "invalid_ambient_encoding",
            );
        }
    };
    // Only generated signatures are recognized. We deliberately do not claim TS grammar or
    // activity/ownership from environment declarations, and never retain/serialize their values.
    let mut lines = ambient
        .strip_prefix('\u{feff}')
        .unwrap_or(ambient)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let header = lines.next() == Some("// this file is generated — do not edit it")
        && lines.next() == Some("/// <reference types=\"@sveltejs/kit\" />");
    let declarations = [
        "declare module '$env/static/private' {",
        "declare module '$env/static/public' {",
        "declare module '$env/dynamic/private' {",
        "declare module '$env/dynamic/public' {",
    ];
    if !header
        || !declarations
            .iter()
            .all(|signature| ambient.lines().any(|line| line.trim() == *signature))
    {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "ambient_signature_not_established",
        );
    }
    outcome(
        profile,
        ProjectFormatStatus::Recognized,
        if legacy_node {
            "sveltekit_legacy_node_non_atomic_signatures"
        } else {
            "sveltekit_legacy_bundler_non_atomic_signatures"
        },
    )
}
