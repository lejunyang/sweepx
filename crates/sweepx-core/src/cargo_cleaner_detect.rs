use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::json;
use sweepx_analysis::{Candidate, build_candidates_from_summary_with_links};
use sweepx_cleaner_schema::RiskTier;
use sweepx_cleaner_vm::{EvalState, EvaluationContext, VmValue, evaluate_rule};
use sweepx_model::{
    DecimalU128, FieldProvenance, NativeName, ObjectType, ScanEntryId, ScannedEntry,
};
use sweepx_scanner::ScanSummary;

use crate::{CoreError, LoadedBuiltInCleaner, directory_links};

const CARGO_CLEANER_ID: &str = "org.sweepx.cargo-target";
const CARGO_RULE_ID: &str = "cargo-target-v1";
const BUILTIN_MANIFEST_INCOMPATIBLE: &str = "builtin_manifest_incompatible";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentalCargoDetectDisposition {
    ReportOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExperimentalCargoRuleMatch {
    pub candidate_id: String,
    pub cleaner_id: String,
    pub cleaner_version: String,
    pub rule_id: String,
    pub display_path: String,
    pub workspace_root: String,
    pub target_dir: String,
    pub disposition: ExperimentalCargoDetectDisposition,
    pub reason_code: String,
    pub executable: bool,
    pub fact_state: String,
    pub inference_state: String,
    pub resolved_risk: String,
    pub rule_report_only: bool,
    pub candidate: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ExperimentalCargoDetectResult {
    pub matches: Vec<ExperimentalCargoRuleMatch>,
    pub incompatible_builtin: bool,
}

#[derive(Debug, Clone, Copy)]
struct AdmittedWorkspace<'a> {
    root: &'a ScannedEntry,
    target: &'a ScannedEntry,
}

pub fn detect_live_cargo_cleaner_candidates(
    summary: &ScanSummary,
    cleaners: &[LoadedBuiltInCleaner],
) -> Result<ExperimentalCargoDetectResult, CoreError> {
    let cleaner = cleaners
        .iter()
        .find(|cleaner| cleaner.package.manifest.id == CARGO_CLEANER_ID)
        .ok_or_else(|| CoreError::InvalidCleanerRef(CARGO_CLEANER_ID.to_string()))?;
    let rule = cleaner
        .package
        .rules
        .iter()
        .find_map(|(_, rule)| (rule.id == CARGO_RULE_ID).then_some(rule))
        .ok_or_else(|| {
            CoreError::InvalidCleanerRef(format!("{CARGO_CLEANER_ID}@{CARGO_RULE_ID}"))
        })?;

    let links = directory_links(summary);
    let candidates = build_candidates_from_summary_with_links(summary, &links, true)?;
    let admitted_targets = admitted_workspace_targets(summary);

    let mut matches = Vec::new();
    for candidate in candidates {
        if candidate.object_type != ObjectType::Directory || !candidate.source_state.is_live() {
            continue;
        }
        let Some((workspace_root, target_entry)) =
            candidate_target_context(&candidate, &admitted_targets)
        else {
            continue;
        };
        let evaluation = evaluate_rule(rule, &build_rule_context(&candidate, workspace_root))?;
        matches.push(ExperimentalCargoRuleMatch {
            candidate_id: candidate.candidate_id.to_string(),
            cleaner_id: cleaner.package.manifest.id.clone(),
            cleaner_version: cleaner.package.manifest.version.clone(),
            rule_id: rule.id.clone(),
            display_path: candidate.path.display_path.clone(),
            workspace_root: workspace_root.display_path.clone(),
            target_dir: target_entry.display_path.clone(),
            disposition: ExperimentalCargoDetectDisposition::ReportOnly,
            reason_code: BUILTIN_MANIFEST_INCOMPATIBLE.to_string(),
            executable: false,
            fact_state: eval_state_label(evaluation.fact_state).to_string(),
            inference_state: eval_state_label(evaluation.inference_state).to_string(),
            resolved_risk: risk_label(evaluation.resolved_risk).to_string(),
            rule_report_only: true,
            candidate: serde_json::to_value(&candidate)
                .expect("candidate must serialize for experimental report"),
        });
    }

    Ok(ExperimentalCargoDetectResult {
        matches,
        incompatible_builtin: !cleaner.compatible,
    })
}

fn admitted_workspace_targets<'a>(
    summary: &'a ScanSummary,
) -> BTreeMap<ScanEntryId, AdmittedWorkspace<'a>> {
    let root_entries: BTreeMap<ScanEntryId, &'a ScannedEntry> = summary
        .roots
        .iter()
        .filter_map(valid_live_identity_entry)
        .filter_map(|entry| {
            let identity = entry.validated_identity().ok().flatten()?;
            (identity.parent_id.is_none()).then_some((identity.entry_id.clone(), entry))
        })
        .collect();

    let mut cargo_toml_roots = BTreeSet::new();
    let mut target_dirs = BTreeMap::new();
    for entry in &summary.entries {
        let Some(entry) = valid_live_identity_entry(entry) else {
            continue;
        };
        let Some(identity) = entry.validated_identity().ok().flatten() else {
            continue;
        };
        let Some(parent_id) = &identity.parent_id else {
            continue;
        };
        if !root_entries.contains_key(parent_id) {
            continue;
        }
        match entry.object_type {
            ObjectType::File if native_name_eq(&entry.native_basename, "Cargo.toml") => {
                cargo_toml_roots.insert(parent_id.clone());
            }
            ObjectType::Directory if native_name_eq(&entry.native_basename, "target") => {
                target_dirs.insert(parent_id.clone(), entry);
            }
            _ => {}
        }
    }

    let mut admitted = BTreeMap::new();
    for (root_id, target) in target_dirs {
        if !cargo_toml_roots.contains(&root_id) {
            continue;
        }
        let Some(root) = root_entries.get(&root_id).copied() else {
            continue;
        };
        let Some(target_identity) = target.validated_identity().ok().flatten() else {
            continue;
        };
        admitted.insert(
            target_identity.entry_id.clone(),
            AdmittedWorkspace { root, target },
        );
    }
    admitted
}

fn valid_live_identity_entry(entry: &ScannedEntry) -> Option<&ScannedEntry> {
    if !matches!(entry.provenance, FieldProvenance::LiveObservation { .. }) {
        return None;
    }
    entry.validated_identity().ok().flatten()?;
    Some(entry)
}

fn native_name_eq(name: &NativeName, expected: &str) -> bool {
    #[cfg(unix)]
    {
        matches!(name, NativeName::UnixBytes(bytes) if bytes.as_slice() == expected.as_bytes())
    }
    #[cfg(windows)]
    {
        let expected_utf16: Vec<u16> = expected.encode_utf16().collect();
        matches!(name, NativeName::WindowsUtf16(units) if units.as_slice() == expected_utf16.as_slice())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (name, expected);
        false
    }
}

fn candidate_target_context<'a>(
    candidate: &Candidate,
    admitted_targets: &'a BTreeMap<ScanEntryId, AdmittedWorkspace<'a>>,
) -> Option<(&'a ScannedEntry, &'a ScannedEntry)> {
    let target_id = candidate
        .locator
        .scan_object_identity
        .as_ref()?
        .entry_id
        .clone();
    admitted_targets
        .get(&target_id)
        .map(|workspace| (workspace.root, workspace.target))
}

fn build_rule_context(candidate: &Candidate, workspace_root: &ScannedEntry) -> EvaluationContext {
    let reclaimable_known = matches!(
        candidate.reclaimable_estimate,
        sweepx_model::EvidenceValue::Known { .. }
    );
    let workspace_id = workspace_root
        .validated_identity()
        .ok()
        .flatten()
        .map(|identity| identity.entry_id.to_string())
        .unwrap_or_else(|| workspace_root.display_path.clone());
    EvaluationContext::new()
        .insert(
            "candidate.relativePath",
            VmValue::String("target".to_string()),
        )
        .insert(
            "coverage.complete",
            VmValue::Bool(candidate.coverage.complete),
        )
        .insert("cargo.targetDir", VmValue::String("target".to_string()))
        .insert("cargo.targetShape", VmValue::String("unknown".to_string()))
        .insert("cargo.workspaceId", VmValue::String(workspace_id))
        .insert(
            "exclusiveReclaimableBytes",
            VmValue::String(
                if reclaimable_known {
                    "known"
                } else {
                    "unknown"
                }
                .to_string(),
            ),
        )
        .insert(
            "objectType",
            VmValue::String(
                match candidate.object_type {
                    ObjectType::Directory => "Directory",
                    ObjectType::File => "File",
                    ObjectType::Symlink => "Symlink",
                    ObjectType::ReparsePoint => "ReparsePoint",
                    ObjectType::Other => "Other",
                }
                .to_string(),
            ),
        )
        .insert("sharing.state", VmValue::String("shared".to_string()))
        .insert("activity.state", VmValue::String("inactive".to_string()))
}

fn eval_state_label(state: EvalState) -> &'static str {
    match state {
        EvalState::Known(true) => "known_true",
        EvalState::Known(false) => "known_false",
        EvalState::Unknown => "unknown",
    }
}

fn risk_label(risk: RiskTier) -> &'static str {
    match risk {
        RiskTier::R1 => "R1",
        RiskTier::R2 => "R2",
        RiskTier::R3 => "R3",
        RiskTier::R4 => "R4",
        RiskTier::Blocked => "BLOCKED",
    }
}

pub fn experimental_cargo_detect_json(result: &ExperimentalCargoDetectResult) -> serde_json::Value {
    json!({
        "command": "cleaner.cargo-detect",
        "experimental": true,
        "liveOnly": true,
        "builtinManifestCompatible": !result.incompatible_builtin,
        "matchCount": DecimalU128::new(result.matches.len() as u128),
        "matches": result.matches,
        "reasons": [BUILTIN_MANIFEST_INCOMPATIBLE],
        "readOnly": true,
        "planAllowed": false,
        "approvalAllowed": false,
        "executionAllowed": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use sweepx_model::{
        Coverage, CoverageState, EvidenceValue, FilesystemObjectDomainIdentity, IdentityEvidence,
        MethodId, NativeAbsolutePath, NativeLocatorEvidence, NativePathComponent,
        PlatformFileIdentity, ScanId, ScanObjectIdentity, VolumeOrMountIdentity,
    };

    #[test]
    fn experimental_json_is_read_only_and_report_only() {
        let payload = experimental_cargo_detect_json(&ExperimentalCargoDetectResult {
            matches: Vec::new(),
            incompatible_builtin: true,
        });
        assert_eq!(payload["command"], "cleaner.cargo-detect");
        assert_eq!(payload["experimental"], true);
        assert_eq!(payload["liveOnly"], true);
        assert_eq!(payload["builtinManifestCompatible"], false);
        assert_eq!(payload["readOnly"], true);
        assert_eq!(payload["planAllowed"], false);
        assert_eq!(payload["approvalAllowed"], false);
        assert_eq!(payload["executionAllowed"], false);
        assert_eq!(payload["reasons"][0], BUILTIN_MANIFEST_INCOMPATIBLE);
    }

    #[test]
    fn metadata_only_detection_requires_live_root_with_direct_cargo_toml_and_target() {
        let summary = summary_with_entries(
            vec![root_entry(1, "/scan/root", live_provenance(), "workspace")],
            vec![
                child_entry(
                    2,
                    1,
                    "/scan/root/Cargo.toml",
                    ObjectType::File,
                    live_provenance(),
                    "Cargo.toml",
                ),
                child_entry(
                    3,
                    1,
                    "/scan/root/target",
                    ObjectType::Directory,
                    live_provenance(),
                    "target",
                ),
            ],
        );

        let admitted = admitted_workspace_targets(&summary);
        assert_eq!(admitted.len(), 1);
        let workspace = admitted.values().next().unwrap();
        assert_eq!(workspace.root.display_path, "/scan/root");
        assert_eq!(workspace.target.display_path, "/scan/root/target");
    }

    #[test]
    fn stale_entries_are_refused() {
        let summary = summary_with_entries(
            vec![root_entry(1, "/scan/root", stale_provenance(), "workspace")],
            vec![
                child_entry(
                    2,
                    1,
                    "/scan/root/Cargo.toml",
                    ObjectType::File,
                    stale_provenance(),
                    "Cargo.toml",
                ),
                child_entry(
                    3,
                    1,
                    "/scan/root/target",
                    ObjectType::Directory,
                    stale_provenance(),
                    "target",
                ),
            ],
        );
        assert!(admitted_workspace_targets(&summary).is_empty());
    }

    #[test]
    fn imported_like_entries_without_identity_are_refused() {
        let summary = summary_with_entries(
            vec![legacy_root_entry(
                "/scan/root",
                live_provenance(),
                "workspace",
            )],
            vec![
                child_entry(
                    2,
                    1,
                    "/scan/root/Cargo.toml",
                    ObjectType::File,
                    live_provenance(),
                    "Cargo.toml",
                ),
                child_entry(
                    3,
                    1,
                    "/scan/root/target",
                    ObjectType::Directory,
                    live_provenance(),
                    "target",
                ),
            ],
        );
        assert!(admitted_workspace_targets(&summary).is_empty());
    }

    #[test]
    fn path_text_alone_is_insufficient() {
        let summary = summary_with_entries(
            vec![
                root_entry(1, "/scan/root", live_provenance(), "workspace"),
                root_entry(9, "/scan/other", live_provenance(), "other"),
            ],
            vec![
                child_entry(
                    2,
                    1,
                    "/scan/root/Cargo.toml",
                    ObjectType::File,
                    live_provenance(),
                    "Cargo.toml",
                ),
                child_entry(
                    3,
                    9,
                    "/scan/root/target",
                    ObjectType::Directory,
                    live_provenance(),
                    "target",
                ),
            ],
        );
        assert!(admitted_workspace_targets(&summary).is_empty());
    }

    #[test]
    fn correct_direct_parent_identity_is_required() {
        let summary = summary_with_entries(
            vec![root_entry(1, "/scan/root", live_provenance(), "workspace")],
            vec![
                child_entry(
                    2,
                    1,
                    "/scan/root/nested",
                    ObjectType::Directory,
                    live_provenance(),
                    "nested",
                ),
                entry(
                    4,
                    1,
                    Some(2),
                    "/scan/root/nested/Cargo.toml",
                    ObjectType::File,
                    live_provenance(),
                    "Cargo.toml",
                ),
                child_entry(
                    3,
                    1,
                    "/scan/root/target",
                    ObjectType::Directory,
                    live_provenance(),
                    "target",
                ),
            ],
        );
        assert!(admitted_workspace_targets(&summary).is_empty());
    }

    fn summary_with_entries(roots: Vec<ScannedEntry>, entries: Vec<ScannedEntry>) -> ScanSummary {
        ScanSummary {
            roots,
            entries,
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        }
    }

    fn live_provenance() -> FieldProvenance {
        FieldProvenance::LiveObservation {
            observed_at: "2026-08-27T00:00:00Z".to_string(),
            method: MethodId::NativeApi,
        }
    }

    fn stale_provenance() -> FieldProvenance {
        FieldProvenance::StalePreview {
            observed_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }

    fn complete_coverage(provenance: FieldProvenance) -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance,
        }
    }

    fn root_entry(
        ordinal: u128,
        display_path: &str,
        provenance: FieldProvenance,
        basename: &str,
    ) -> ScannedEntry {
        entry(
            ordinal,
            ordinal,
            None,
            display_path,
            ObjectType::Directory,
            provenance,
            basename,
        )
    }

    fn legacy_root_entry(
        display_path: &str,
        provenance: FieldProvenance,
        basename: &str,
    ) -> ScannedEntry {
        let mut entry = root_entry(1, display_path, provenance, basename);
        entry.identity = None;
        entry.native_locator = None;
        entry
    }

    fn child_entry(
        ordinal: u128,
        root_ordinal: u128,
        display_path: &str,
        object_type: ObjectType,
        provenance: FieldProvenance,
        basename: &str,
    ) -> ScannedEntry {
        entry(
            ordinal,
            root_ordinal,
            Some(root_ordinal),
            display_path,
            object_type,
            provenance,
            basename,
        )
    }

    fn entry(
        ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
        display_path: &str,
        object_type: ObjectType,
        provenance: FieldProvenance,
        basename: &str,
    ) -> ScannedEntry {
        let identity = scan_identity(ordinal, root_ordinal, parent_ordinal);
        let native_basename = native_name(basename);
        ScannedEntry {
            scan_id: ScanId::new("scan-cargo-detect"),
            identity: Some(identity.clone()),
            native_locator: Some(native_locator(
                &identity,
                native_basename.clone(),
                object_type.clone(),
                "fingerprint",
            )),
            display_path: display_path.to_string(),
            native_basename,
            object_type,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(10),
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(10),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::new(5),
            },
            metadata_fingerprint: "fingerprint".to_string(),
            coverage: complete_coverage(provenance.clone()),
            provenance,
        }
    }

    fn scan_identity(
        ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
    ) -> ScanObjectIdentity {
        ScanObjectIdentity {
            entry_id: scan_entry_id(ordinal),
            scan_root_id: scan_entry_id(root_ordinal),
            parent_id: parent_ordinal.map(scan_entry_id),
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        }
    }

    fn scan_entry_id(ordinal: u128) -> ScanEntryId {
        ScanEntryId::for_scan_ordinal(&ScanId::new("scan-cargo-detect"), ordinal).unwrap()
    }

    fn native_name(name: &str) -> NativeName {
        #[cfg(unix)]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
    }

    fn native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/scan/root".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(r"C:\scan\root".encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/scan/root".to_vec())
        }
    }

    fn native_locator(
        identity: &ScanObjectIdentity,
        entry_native_basename: NativeName,
        entry_object_type: ObjectType,
        entry_metadata_fingerprint: &str,
    ) -> NativeLocatorEvidence {
        let root_component = NativePathComponent {
            entry_id: identity.scan_root_id.clone(),
            parent_id: None,
            native_basename: native_name("workspace"),
            object_type: ObjectType::Directory,
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: "root-fingerprint".to_string(),
        };
        let mut parent_reopen_recipe = Vec::new();
        if identity.parent_id.is_some() {
            parent_reopen_recipe.push(root_component.clone());
        }
        if let Some(parent_id) = &identity.parent_id
            && parent_id != &identity.scan_root_id
        {
            parent_reopen_recipe.push(NativePathComponent {
                entry_id: parent_id.clone(),
                parent_id: Some(identity.scan_root_id.clone()),
                native_basename: native_name("nested"),
                object_type: ObjectType::Directory,
                platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                    device: DecimalU128::new(1),
                    inode: DecimalU128::new(2),
                }),
                filesystem_object_domain_identity: IdentityEvidence::known(
                    FilesystemObjectDomainIdentity {
                        device: DecimalU128::new(1),
                    },
                ),
                volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                    value: DecimalU128::new(1),
                }),
                metadata_fingerprint: "nested-fingerprint".to_string(),
            });
        }
        NativeLocatorEvidence {
            scan_root: root_component,
            scan_root_absolute_path: Some(native_absolute_root()),
            parent_reopen_recipe,
            entry: NativePathComponent {
                entry_id: identity.entry_id.clone(),
                parent_id: identity.parent_id.clone(),
                native_basename: entry_native_basename,
                object_type: entry_object_type,
                platform_file_identity: identity.platform_file_identity.clone(),
                filesystem_object_domain_identity: identity
                    .filesystem_object_domain_identity
                    .clone(),
                volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
                metadata_fingerprint: entry_metadata_fingerprint.to_string(),
            },
        }
    }
}
