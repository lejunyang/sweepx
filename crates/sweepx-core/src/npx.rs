//! npx installations are explicit user selections, separate from automatic junk rules.
//! A cache slot contains a dependency graph: sizes and Trash selections cover the entire slot,
//! never an individual transitive package. Version ordering is not disposability evidence.
use crate::storage_inventory::{entry_bytes, observe_directories};
use semver::Version;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sweepx_model::{NativeName, ScannedEntry};
use sweepx_platform::CancellationToken;
use sweepx_scanner::{
    CargoConfigMemberObservation, HostPlatformScanner, LocatorReadLimits, LocatorReader,
};

const MAX_SLOTS: usize = 1024;
const MAX_MANIFEST: usize = 1024 * 1024;
const MAX_METADATA: usize = 64 * 1024 * 1024;

/// One directly requested package, with its installed version read from its own manifest.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpxPackage {
    /// Exact package name, including scope.
    pub name: String,
    /// Requested range or specifier; not the resolved version.
    pub requested: String,
    /// Actual installed version, absent when native manifest validation fails.
    pub version: Option<String>,
}

/// One complete npx installation slot, including all its dependencies.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpxEntry {
    /// npm's cache slot basename, used only to select a row in the current inventory.
    pub id: String,
    /// Display path only; native authority is retained separately and never serialized.
    pub path: PathBuf,
    /// Logical size including transitive dependencies; not exclusive reclaimable space.
    pub bytes: Option<String>,
    /// Whether size coverage and package observations completed.
    pub complete: bool,
    /// Top-level requested packages; a multi-package slot cannot be split safely.
    pub packages: Vec<NpxPackage>,
    /// A strictly lower installed semantic version of a single-package slot.
    /// This is only a suggested selection and does not prove inactivity.
    pub older_version: bool,
    /// Why this row cannot be selected automatically.
    pub issues: Vec<String>,
    #[serde(skip)]
    source: ScannedEntry,
    #[serde(skip)]
    manifests: Vec<(Vec<String>, [u8; 32])>,
}
impl NpxEntry {
    /// Current scanner observation used by a separate platform Trash adapter.
    pub fn source_entry(&self) -> &ScannedEntry {
        &self.source
    }

    /// Re-read every captured package manifest through native no-follow lineage before mutation.
    /// This checks identity and content, not process inactivity or an atomic filesystem snapshot.
    pub fn revalidate(&self, cancel: &CancellationToken) -> Result<(), String> {
        if !self.complete || self.manifests.is_empty() {
            return Err("incomplete_installation".into());
        }
        crate::storage_inventory::revalidate_directory(&self.source, cancel)?;
        let mut used = 0;
        for (parts, expected) in &self.manifests {
            let bytes = read_manifest(&self.source, parts, cancel, &mut used)?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            if &digest != expected {
                return Err("manifest_changed".into());
            }
        }
        Ok(())
    }
}

/// Bounded native inventory; unknown entries remain visible and cannot become old-version plans.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NpxInventory {
    /// Root selected by the caller, never inferred from a serialized report during deletion.
    pub root: PathBuf,
    /// Current installation slots, sorted by logical size.
    pub entries: Vec<NpxEntry>,
    /// Complete observed root total, including unattributed files and unknown directories.
    pub bytes: Option<String>,
    /// Coverage and manifest availability for the complete inventory.
    pub complete: bool,
    /// Root-level failures, separate from per-slot failures.
    pub issues: Vec<String>,
}

/// Conventional location only. Callers may supply npm's configured cache parent explicitly.
pub fn default_root() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".npm").join("_npx"))
}

/// Scans the cache once with the same native totals used by browser reports, then reads bounded
/// manifest bytes. No npm subprocess is executed and no cached activity claims are accepted.
pub fn inventory(root: &Path, cancel: &CancellationToken) -> NpxInventory {
    let mut out = NpxInventory {
        root: root.into(),
        entries: Vec::new(),
        bytes: None,
        complete: false,
        issues: Vec::new(),
    };
    let scan = match observe_directories(root, cancel, Instant::now() + Duration::from_secs(120)) {
        Ok(s) => s,
        Err(e) => {
            out.issues.push(e);
            return out;
        }
    };
    let Some(base) = scan.roots.first() else {
        out.issues.push("root_not_observed".into());
        return out;
    };
    let (bytes, complete) = entry_bytes(&scan, base);
    out.bytes = bytes.map(|b| b.to_string());
    out.complete = complete
        && scan.error_count() == 0
        && !scan.progress_retention.resource_limited
        && !scan.progress_retention.cancelled;
    let native_complete = out.complete;
    let mut used = 0;
    for source in scan.entries {
        let Some(identity) = &source.identity else {
            continue;
        };
        if identity.parent_id.as_ref() != Some(&identity.scan_root_id) {
            continue;
        }
        if out.entries.len() == MAX_SLOTS {
            out.complete = false;
            out.issues.push("slot_limit".into());
            break;
        }
        let id = crate::junk::native_rule_name(&source.native_basename).unwrap_or_default();
        // Aggregates remain available after moving the rows out of the summary.
        let bytes = scan
            .aggregates
            .iter()
            .find(|a| a.directory_identity == identity.entry_id.as_str());
        let (size, coverage) = bytes
            .map(|a| match &a.apparent_logical_bytes {
                sweepx_model::EvidenceValue::Known { value } => (
                    Some(value.0.to_string()),
                    a.coverage.complete && !a.coverage.details_lost,
                ),
                sweepx_model::EvidenceValue::LowerBound { value, .. } => {
                    (Some(value.0.to_string()), false)
                }
                _ => (None, false),
            })
            .unwrap_or((None, false));
        let mut row = NpxEntry {
            id: id.clone(),
            path: source.display_path.clone().into(),
            bytes: size,
            complete: coverage,
            packages: Vec::new(),
            older_version: false,
            issues: Vec::new(),
            source,
            manifests: Vec::new(),
        };
        let parsed = (|| {
            if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("unknown_slot_name".into());
            }
            let parts = vec!["package.json".into()];
            let bytes = read_manifest(&row.source, &parts, cancel, &mut used)?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_slot_manifest")?;
            let deps = manifest
                .get("dependencies")
                .and_then(|v| v.as_object())
                .ok_or("missing_requested_packages")?;
            if deps.is_empty() || deps.len() > 32 {
                return Err("package_count_limit".into());
            }
            row.manifests.push((parts, Sha256::digest(&bytes).into()));
            // Retain all direct names before following any package directory. A linked local
            // package cannot hide which version groups must be excluded from the old-version plan.
            for (name, spec) in deps {
                let requested = spec
                    .as_str()
                    .filter(|s| s.len() <= 4096)
                    .ok_or("invalid_requested_version")?;
                package_parts(name).ok_or("invalid_package_name")?;
                row.packages.push(NpxPackage {
                    name: name.clone(),
                    requested: requested.into(),
                    version: None,
                });
            }
            for package in &mut row.packages {
                let parts = package_parts(&package.name).ok_or("invalid_package_name")?;
                let bytes = read_manifest(&row.source, &parts, cancel, &mut used)?;
                let installed: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid_package_manifest")?;
                if installed["name"].as_str() != Some(&package.name) {
                    return Err("installed_name_mismatch".into());
                }
                let version = installed["version"]
                    .as_str()
                    .filter(|v| v.len() < 256)
                    .ok_or("missing_installed_version")?;
                package.version = Some(version.into());
                row.manifests.push((parts, Sha256::digest(&bytes).into()));
            }
            Ok::<(), String>(())
        })();
        if let Err(e) = parsed {
            row.complete = false;
            row.issues.push(e);
        }
        out.complete &= row.complete;
        out.entries.push(row);
    }
    if native_complete
        && out.issues.is_empty()
        && out.entries.iter().all(|r| !r.packages.is_empty())
    {
        mark_older(&mut out.entries);
    }
    out.entries.sort_by_key(|r| {
        std::cmp::Reverse(
            r.bytes
                .as_ref()
                .and_then(|b| b.parse::<u128>().ok())
                .unwrap_or(0),
        )
    });
    out
}
fn package_parts(name: &str) -> Option<Vec<String>> {
    let parts: Vec<_> = name.split('/').collect();
    if name.len() > 214
        || parts.is_empty()
        || parts.len() > 2
        || (parts.len() == 2 && !parts[0].starts_with('@'))
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || p.contains('\\')
                || p.contains('\0')
                || p.contains(':')
        })
    {
        return None;
    }
    Some(
        std::iter::once("node_modules")
            .chain(parts)
            .chain(std::iter::once("package.json"))
            .map(str::to_string)
            .collect(),
    )
}
fn read_manifest(
    source: &ScannedEntry,
    parts: &[String],
    cancel: &CancellationToken,
    used: &mut usize,
) -> Result<Vec<u8>, String> {
    if *used > MAX_METADATA - MAX_MANIFEST {
        return Err("metadata_limit".into());
    }
    *used += MAX_MANIFEST; // Charge a failed stream fully; complete reads refund the unused allowance.
    let parts: Vec<_> = parts
        .iter()
        .map(|s| {
            #[cfg(unix)]
            {
                NativeName::UnixBytes(s.as_bytes().to_vec())
            }
            #[cfg(windows)]
            {
                NativeName::WindowsUtf16(s.encode_utf16().collect())
            }
        })
        .collect();
    let reader = LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 128,
            max_file_bytes: MAX_MANIFEST,
            max_total_bytes: MAX_MANIFEST,
            ..Default::default()
        },
    );
    let mut directory = reader
        .capture_scanned_ancestor_directory(source, 0, cancel)
        .map_err(|e| e.to_string())?;
    let (name, parents) = parts.split_last().ok_or("empty_manifest_path")?;
    for parent in parents {
        directory = reader
            .capture_child_directory(&directory, parent, cancel)
            .map_err(|e| e.to_string())?;
    }
    // This existing generic fixed-name input reader also serves Cargo includes; no Cargo parsing
    // or path expansion is involved here. Its native/provider boundary applies unchanged.
    match reader.read_cargo_config_include_in_captured_directory(&directory, name, cancel) {
        CargoConfigMemberObservation::Present(file) => {
            reader
                .capture_scanned_ancestor_directory(source, 0, cancel)
                .map_err(|e| e.to_string())?;
            *used -= MAX_MANIFEST - file.bytes.len();
            Ok(file.bytes)
        }
        other => Err(format!("native_manifest_unavailable: {other:?}")),
    }
}
fn mark_older(rows: &mut [NpxEntry]) {
    let excluded: std::collections::BTreeSet<_> = rows
        .iter()
        .filter(|r| {
            !r.complete
                || r.packages.len() != 1
                || r.packages[0]
                    .version
                    .as_deref()
                    .and_then(|v| Version::parse(v).ok())
                    .is_none()
        })
        .flat_map(|r| r.packages.iter().map(|p| p.name.clone()))
        .collect();
    let mut highest = BTreeMap::<String, Version>::new();
    for row in rows
        .iter()
        .filter(|r| r.complete && r.packages.len() == 1 && !excluded.contains(&r.packages[0].name))
    {
        let p = &row.packages[0];
        if let Some(v) = p.version.as_deref().and_then(|v| Version::parse(v).ok()) {
            highest
                .entry(p.name.clone())
                .and_modify(|old| {
                    if v.cmp_precedence(old).is_gt() {
                        *old = v.clone();
                    }
                })
                .or_insert(v);
        }
    }
    for row in rows
        .iter_mut()
        .filter(|r| r.complete && r.packages.len() == 1 && !excluded.contains(&r.packages[0].name))
    {
        let p = &row.packages[0];
        row.older_version = p
            .version
            .as_deref()
            .and_then(|v| Version::parse(v).ok())
            .zip(highest.get(&p.name))
            .is_some_and(|(v, h)| v.cmp_precedence(h).is_lt());
    }
}

#[cfg(test)]
#[path = "npx_tests.rs"]
mod tests;
