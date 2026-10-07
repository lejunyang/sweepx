//! Project artifact rules admitted through the catalog, independent of CLI rendering.

/// Platform rule types and bounded admission.
pub mod platform;

use serde::Deserialize;
use std::collections::BTreeSet;

/// Built-in project rule bytes; consumers use these exact bytes when binding cache validity.
pub const PROJECT_RULES_JSON: &str = include_str!("../resources/project-junk-rules.json");

/// Report-only project artifact rule. Matching never grants mutation authority.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectJunkRule {
    /// Stable machine identifier, preserved across locales.
    pub id: String,
    /// Native basename alternatives for the artifact directory.
    pub names: Vec<String>,
    /// Optional bounded native-name shape, combined with exact names. This is layout evidence,
    /// never a resolved compiler target or an assertion about the host architecture.
    #[serde(default)]
    pub name_pattern: Option<ProjectNamePattern>,
    /// Optional direct-parent native basename filter. The captured locator supplies this name;
    /// a display path, linked ancestor or missing lineage cannot satisfy the filter.
    #[serde(default)]
    pub parent_names: Vec<String>,
    /// Optional conventional layout signature over the captured native directory lineage.
    /// This does not read or resolve configuration outside the admitted scan root.
    #[serde(default)]
    pub path_profile: Option<ProjectPathProfile>,
    /// Stable risk tier (`R1`, `R2` or `R3`).
    pub risk: String,
    /// At least one must occur among the observed parent's files; empty means no parent filter.
    pub required_parent_markers: Vec<String>,
    /// All must be ordinary files directly inside this captured directory. These are structural
    /// layout markers, not parsed contents or proof of exclusive ownership/deletion authority.
    /// Empty preserves catalogs that only use parent context.
    #[serde(default)]
    pub required_own_markers: Vec<String>,
    /// Optional bounded content observation. A recognized format is report evidence only;
    /// exclusive ownership and inactivity are independent, unverified conditions.
    #[serde(default)]
    pub content_format: Option<ProjectContentFormat>,
    /// Optional current project-manifest observation, independent of generated-content signatures
    /// and ownership. A fixed-input profile never resolves or executes project configuration.
    #[serde(default)]
    pub context_profile: Option<ProjectContextProfile>,
    /// Intent declared by the rule, never proof of ownership or inactivity. Omitted policies
    /// require independent ownership/activity evidence and cannot inherit legacy deletion access.
    #[serde(default)]
    pub execution_policy: ProjectExecutionPolicy,
    /// Human-readable explanation of the rebuild/disposability evidence.
    pub evidence: String,
    /// Source review date in YYYY-MM-DD notation.
    pub source_reviewed_at: String,
    /// HTTPS primary-source references supporting the rule.
    pub references: Vec<String>,
}

/// Project-rule execution constraint. No admitted value turns a layout match into deletion authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectExecutionPolicy {
    /// Always display only, even if future independent evidence becomes available.
    ReportOnly,
    /// Future execution requires current, independently established exclusive ownership and
    /// inactivity. Neither condition is implemented by the current layout/content/Git stages.
    #[default]
    RequireOwnershipAndActivity,
}

/// Supported project content profiles; unknown profile names fail catalog admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectContentFormat {
    /// Pub's v2 package map and self-declared generator, without following package URIs.
    DartPubPackageConfigV2,
    /// Legacy SvelteKit sync configuration plus generated ambient signatures; non-atomic and
    /// report-only, without evaluating JS configuration or proving TypeScript correctness.
    SvelteKitLegacySync,
    /// Python/uv virtual-environment configuration; no dependency recovery is inferred.
    PythonVenvConfig,
    /// Vite's dependency prebundle metadata; source and cache paths are not followed.
    ViteDependencyMetadata,
}

/// Admitted native basename shapes. No arbitrary regular expression runs during a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectNamePattern {
    /// A bounded hyphen-separated target name inside a marked Cargo target directory.
    CargoTargetName,
}

/// Bounded native directory-lineage signatures; unknown profile names fail admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectPathProfile {
    /// A child of target/{debug,release} or target/<target-name>/{debug,release}.
    CargoProfileArtifact,
}

/// Supported fixed-input context observations. Unknown profiles fail catalog admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectContextProfile {
    /// Declaration projection from the captured parent directory's Cargo.toml, not effective Cargo
    /// configuration, resolved workspace membership, exclusive ownership or inactivity.
    CargoManifest,
}

/// Admission failure for the project-artifact catalog.
#[derive(Debug, thiserror::Error)]
pub enum ProjectRuleError {
    /// Invalid JSON or an unknown/missing field.
    #[error("invalid project rule JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Input exceeded the catalog's byte, rule or list count limit.
    #[error("project rule catalog exceeds its resource limit")]
    ResourceLimit,
    /// A rule has invalid names, risk, references or review metadata, or a duplicate identifier.
    #[error("invalid or duplicate project junk rule: {0}")]
    InvalidRule(String),
}

/// Loads the built-in rules through the same admission path as caller-supplied bytes.
pub fn load_project_rules() -> Result<Vec<ProjectJunkRule>, ProjectRuleError> {
    load_project_rule_bytes(PROJECT_RULES_JSON.as_bytes())
}

/// Admits bounded, strict project-rule JSON. No paths are inspected and no tools are executed.
pub fn load_project_rule_bytes(bytes: &[u8]) -> Result<Vec<ProjectJunkRule>, ProjectRuleError> {
    // Admission bounds allocation before parsing. Catalog rules are small data; an arbitrary
    // rule stream must not become another unbounded scan-time index.
    if bytes.len() > 32 * 1024 {
        return Err(ProjectRuleError::ResourceLimit);
    }
    let rules: Vec<ProjectJunkRule> = serde_json::from_slice(bytes)?;
    if rules.is_empty() || rules.len() > 64 {
        return Err(ProjectRuleError::ResourceLimit);
    }
    let mut ids = BTreeSet::new();
    for rule in &rules {
        if rule.names.len() > 64
            || rule.parent_names.len() > 64
            || rule.required_parent_markers.len() > 64
            || rule.required_own_markers.len() > 64
            || rule.references.len() > 64
        {
            return Err(ProjectRuleError::ResourceLimit);
        }
        let date = &rule.source_reviewed_at;
        let valid_date = date.len() == 10
            && date.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 7) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit()
                }
            });
        if rule.id.trim().is_empty()
            || rule.context_profile.is_some_and(|profile| match profile {
                ProjectContextProfile::CargoManifest => !rule
                    .required_parent_markers
                    .iter()
                    .any(|name| name == "Cargo.toml"),
            })
            || rule.content_format.is_some_and(|profile| {
                let required: &[&str] = match profile {
                    ProjectContentFormat::DartPubPackageConfigV2 => &["package_config.json"],
                    ProjectContentFormat::SvelteKitLegacySync => &["tsconfig.json", "ambient.d.ts"],
                    ProjectContentFormat::PythonVenvConfig => &["pyvenv.cfg"],
                    ProjectContentFormat::ViteDependencyMetadata => &["_metadata.json"],
                };
                required.iter().any(|name| {
                    !rule
                        .required_own_markers
                        .iter()
                        .any(|marker| marker == name)
                })
            })
            || !ids.insert(&rule.id)
            || !matches!(rule.risk.as_str(), "R1" | "R2" | "R3")
            || (rule.names.is_empty() && rule.name_pattern.is_none())
            || rule.name_pattern.is_some_and(|_| {
                !rule.parent_names.iter().any(|name| name == "target")
                    || !rule
                        .required_parent_markers
                        .iter()
                        .any(|name| name == ".rustc_info.json")
                    || !rule
                        .required_own_markers
                        .iter()
                        .any(|name| name == "CACHEDIR.TAG")
            })
            || rule.path_profile.is_some_and(|_| {
                !rule
                    .required_parent_markers
                    .iter()
                    .any(|name| name == ".cargo-lock")
                    || rule.parent_names.is_empty()
                    || rule
                        .parent_names
                        .iter()
                        .any(|name| !matches!(name.as_str(), "debug" | "release"))
            })
            || rule.evidence.trim().is_empty()
            || !valid_date
            || rule.references.is_empty()
            || !rule
                .references
                .iter()
                .all(|reference| reference.starts_with("https://"))
            || !rule
                .names
                .iter()
                .chain(&rule.parent_names)
                .chain(&rule.required_parent_markers)
                .chain(&rule.required_own_markers)
                .all(|name| is_safe_rule_component(name))
        {
            return Err(ProjectRuleError::InvalidRule(rule.id.clone()));
        }
    }
    Ok(rules)
}

/// Checks that a rule name is one component, never traversal or a path separator.
pub fn is_safe_rule_component(value: &str) -> bool {
    !value.is_empty() && !matches!(value, "." | "..") && !value.contains(['/', '\\', '\0'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_parent_filters_and_target_patterns_have_strict_admission() {
        let mut rules: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        rules[0]["parentNames"] = serde_json::json!(["../debug"]);
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
        rules[0]["parentNames"] = serde_json::json!(["debug"]);
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_ok());
        rules[0]["namePattern"] = serde_json::json!("cargo_target_name");
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
        rules[0]["namePattern"] = serde_json::json!("arbitrary_regex");
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
    }

    #[test]
    fn invalid_rules_cannot_enter_through_the_byte_loader() {
        let original: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        for (field, value) in [
            ("names", serde_json::json!(["../target"])),
            ("risk", serde_json::json!("safe")),
            ("references", serde_json::json!([])),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut edited = original.clone();
            edited[0][field] = value;
            assert!(
                load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut duplicate = original;
        duplicate[1]["id"] = duplicate[0]["id"].clone();
        assert!(matches!(
            load_project_rule_bytes(&serde_json::to_vec(&duplicate).unwrap()),
            Err(ProjectRuleError::InvalidRule(_))
        ));
        assert!(matches!(
            load_project_rule_bytes(&vec![b' '; 32769]),
            Err(ProjectRuleError::ResourceLimit)
        ));
    }

    #[test]
    fn execution_policy_cannot_enable_layout_only_mutation() {
        let mut rules: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        assert_eq!(
            load_project_rules().unwrap()[3].execution_policy,
            ProjectExecutionPolicy::ReportOnly
        );
        rules[0].as_object_mut().unwrap().remove("executionPolicy");
        assert_eq!(
            load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap()[0]
                .execution_policy,
            ProjectExecutionPolicy::RequireOwnershipAndActivity
        );
        for value in [
            serde_json::json!("allow"),
            serde_json::json!("native_revalidation_required"),
            serde_json::json!(false),
            serde_json::Value::Null,
        ] {
            rules[0]["executionPolicy"] = value;
            assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
        }
    }

    #[test]
    fn context_profile_requires_its_fixed_parent_marker() {
        let mut rules: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        assert_eq!(
            load_project_rules().unwrap()[0].context_profile,
            Some(ProjectContextProfile::CargoManifest)
        );
        rules[0]["contextProfile"] = serde_json::json!("arbitrary_config_execution");
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
        rules[0]["contextProfile"] = serde_json::json!("cargo_manifest");
        rules[0]["requiredParentMarkers"] = serde_json::json!(["package.json"]);
        assert!(load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).is_err());
        rules[0].as_object_mut().unwrap().remove("contextProfile");
        assert!(
            load_project_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap()[0]
                .context_profile
                .is_none()
        );
    }

    #[test]
    fn own_markers_are_optional_bounded_file_components() {
        let original: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        assert!(
            load_project_rules().unwrap()[0]
                .required_own_markers
                .is_empty()
        );
        let mut edited = original.clone();
        edited[0]["requiredOwnMarkers"] = serde_json::json!(["generated.json", "stamp"]);
        assert_eq!(
            load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()).unwrap()[0]
                .required_own_markers,
            ["generated.json", "stamp"]
        );
        for value in [
            serde_json::json!(["../stamp"]),
            serde_json::json!(["a/b"]),
            serde_json::json!(["a\\b"]),
            serde_json::json!([""]),
            serde_json::json!(["."]),
            serde_json::json!([".."]),
            serde_json::json!(["a\u{0000}b"]),
            serde_json::json!(true),
        ] {
            edited[0]["requiredOwnMarkers"] = value;
            assert!(load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err());
        }
        edited[0]["requiredOwnMarkers"] = serde_json::json!(vec!["marker"; 65]);
        assert!(matches!(
            load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()),
            Err(ProjectRuleError::ResourceLimit)
        ));
    }

    #[test]
    fn content_profiles_require_their_declared_input_and_reject_unknown_profiles() {
        let original: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        let mut edited = original.clone();
        edited[5]["contentFormat"] = serde_json::json!("future_profile");
        assert!(load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err());
        edited = original;
        edited[5]["requiredOwnMarkers"] = serde_json::json!(["other.json"]);
        assert!(matches!(
            load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()),
            Err(ProjectRuleError::InvalidRule(_))
        ));
        edited[5]["contentFormat"] = serde_json::Value::Null;
        assert!(load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_ok());
        for markers in [
            serde_json::json!(["tsconfig.json"]),
            serde_json::json!(["ambient.d.ts"]),
        ] {
            edited[6]["requiredOwnMarkers"] = markers;
            assert!(matches!(
                load_project_rule_bytes(&serde_json::to_vec(&edited).unwrap()),
                Err(ProjectRuleError::InvalidRule(_))
            ));
        }
    }
}
