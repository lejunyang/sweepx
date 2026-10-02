//! Project junk classification over captured scan facts, shared by CLI and future TUI sessions.
//!
//! Rules live in the catalog and their predicates use the existing cleaner VM. The service does
//! no filesystem I/O and starts no subprocesses. Platform root discovery remains a separate input.

/// Bounded macOS filesystem caches; cached reports never grant execution authority.
#[cfg(target_os = "macos")]
pub mod cache;
/// Candidate report types and interpretation over captured facts.
pub mod candidate;
mod context;
/// Current bounded project-content observations, independent of filesystem cache and execution.
pub mod format;
/// Current Git interpretation shared by fresh scans and validated candidate-cache hits.
pub mod git;
mod layout;
/// Native Linux temporary-object discovery shared with cleanup preparation.
#[cfg(target_os = "linux")]
pub mod linux_temp;
/// Independent preview and recoverable execution for explicitly confirmed Linux temporary objects.
#[cfg(target_os = "linux")]
pub mod quarantine;
// Exercise portable byte/count/cancellation contracts on Unix hosts without compiling Linux
// production traversal or claiming that a macOS run verifies procfs/O_NOATIME runtime behavior.
#[cfg(all(test, unix, not(target_os = "linux")))]
#[path = "junk/linux_temp/observation.rs"]
mod linux_temp_observation_tests;
/// Platform rule discovery and interpretation.
pub mod platform;
#[cfg(all(test, unix, not(target_os = "linux")))]
#[path = "junk/quarantine/operation.rs"]
mod quarantine_operation_tests;
/// Worker-owned junk scans with bounded events and identity-bound refresh.
pub mod session;

use std::collections::{BTreeMap, BTreeSet};
use sweepx_catalog::schema::{Predicate, PredicateArg, PredicateOp};
use sweepx_catalog::vm::{EvaluationContext, VmValue, evaluate_predicate};
use sweepx_model::{NativeName, ObjectType, ScanEntryId, ScannedEntry};

pub use sweepx_catalog::junk::{
    PROJECT_RULES_JSON, ProjectJunkRule, ProjectRuleError, is_safe_rule_component,
    load_project_rules,
};

/// Read-only project classification using one validated catalog and compiled predicates.
pub struct JunkService {
    // Digest the admitted source bytes, including edits that preserve the parsed predicates.
    rule_bytes_digest: [u8; 32],
    rules: Vec<ProjectJunkRule>,
    predicates: Vec<Predicate>,
    // Immutable indexes preserve catalog order for overlapping names while avoiding repeated
    // normalization/allocation on every ordinary directory in a large traversal.
    by_name: BTreeMap<String, Vec<usize>>,
    parent_markers: Vec<Vec<String>>,
    own_markers: Vec<Vec<String>>,
    marker_names: BTreeSet<String>,
}

impl JunkService {
    /// Combines this admitted project catalog with platform rules and invocation-scoped evidence.
    pub fn with_platform<'a>(
        &'a self,
        rules: &'a [platform::PlatformJunkRule],
        evidence: &'a platform::PlatformJunkEvidence,
    ) -> platform::CombinedJunkClassifier<'a> {
        platform::CombinedJunkClassifier {
            project: self,
            platform_rules: rules,
            evidence,
        }
    }

    /// Interprets a walk-time decision through the same admitted catalogs used by classification.
    /// Unknown decisions or invalid native facts decline; no rendering or execution is performed.
    pub fn interpret(
        &self,
        decision: &str,
        entry: &ScannedEntry,
        aggregates: &BTreeMap<&str, &sweepx_model::DirectoryAggregate>,
        rules: &[platform::PlatformJunkRule],
        evidence: &platform::PlatformJunkEvidence,
    ) -> Option<candidate::JunkCandidate> {
        if let Some(id) = decision.strip_prefix("project:") {
            let rule = self.rules.iter().find(|rule| rule.id == id)?;
            candidate::assemble_project_candidate(rule, entry, aggregates)
        } else {
            let id = decision.strip_prefix("platform:")?;
            let rule = rules.iter().find(|rule| rule.id == id)?;
            candidate::assemble_platform_candidate(rule, entry, aggregates, evidence)
        }
    }

    /// Loads and compiles the shipped project rules once for the scan invocation.
    pub fn built_in() -> Result<Self, ProjectRuleError> {
        Self::from_rule_bytes(PROJECT_RULES_JSON.as_bytes())
    }

    /// Admits explicit bounded rule bytes through catalog validation before compiling predicates.
    pub fn from_rule_bytes(bytes: &[u8]) -> Result<Self, ProjectRuleError> {
        let rules = sweepx_catalog::junk::load_project_rule_bytes(bytes)?;
        let predicates = rules
            .iter()
            .map(|rule| {
                let name = Predicate::Call {
                    op: PredicateOp::In,
                    args: vec![
                        PredicateArg::FieldRef {
                            field: "entry.name".into(),
                        },
                        PredicateArg::StringList(
                            rule.names
                                .iter()
                                .map(|name| normalize_rule_name(name))
                                .collect(),
                        ),
                    ],
                };
                if rule.required_parent_markers.is_empty() && rule.required_own_markers.is_empty() {
                    return name;
                }
                let mut terms = vec![PredicateArg::Predicate(Box::new(name))];
                for (required, field) in [
                    (
                        !rule.required_parent_markers.is_empty(),
                        "parent.marker_matches",
                    ),
                    (
                        !rule.required_own_markers.is_empty(),
                        "entry.marker_matches",
                    ),
                ] {
                    if required {
                        terms.push(PredicateArg::Predicate(Box::new(Predicate::Call {
                            op: PredicateOp::Eq,
                            args: vec![
                                PredicateArg::FieldRef {
                                    field: field.into(),
                                },
                                PredicateArg::Bool(true),
                            ],
                        })));
                    }
                }
                Predicate::Call {
                    op: PredicateOp::And,
                    args: terms,
                }
            })
            .collect();
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, rule) in rules.iter().enumerate() {
            for name in &rule.names {
                let indexes = by_name.entry(normalize_rule_name(name)).or_default();
                if indexes.last() != Some(&index) {
                    indexes.push(index);
                }
            }
        }
        let parent_markers = rules
            .iter()
            .map(|rule| {
                rule.required_parent_markers
                    .iter()
                    .map(|name| normalize_rule_name(name))
                    .collect()
            })
            .collect();
        let own_markers = rules
            .iter()
            .map(|rule| {
                rule.required_own_markers
                    .iter()
                    .map(|name| normalize_rule_name(name))
                    .collect()
            })
            .collect();
        let marker_names = rules
            .iter()
            .flat_map(|rule| {
                rule.required_parent_markers
                    .iter()
                    .chain(&rule.required_own_markers)
            })
            .map(|name| normalize_rule_name(name))
            .collect();
        Ok(Self {
            rule_bytes_digest: {
                use sha2::Digest;
                sha2::Sha256::digest(bytes).into()
            },
            rules,
            predicates,
            by_name,
            parent_markers,
            own_markers,
            marker_names,
        })
    }

    /// Returns admitted rules for rendering their existing risk and evidence fields.
    pub fn project_rules(&self) -> &[ProjectJunkRule] {
        &self.rules
    }

    /// Whether an observed file name supplies evidence needed by the loaded project rules.
    pub fn needs_project_marker(&self, name: &NativeName) -> bool {
        if !cfg!(windows)
            && let NativeName::UnixBytes(bytes) = name
        {
            return std::str::from_utf8(bytes).is_ok_and(|name| self.marker_names.contains(name));
        }
        native_rule_name(name).is_some_and(|name| self.marker_names.contains(&name))
    }

    /// Matches lossless observed names and identity-keyed parent markers, never display paths.
    ///
    /// `None` parent evidence cannot satisfy a marker-dependent rule. This method consumes scan
    /// facts only; callers must use directory observations and perform independent execution checks.
    /// Rules requiring own markers also decline here: use `match_project_entry` with a captured ID.
    pub fn match_project(
        &self,
        name: &NativeName,
        parent: Option<&ScanEntryId>,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<&ProjectJunkRule> {
        self.match_project_context(name, None, parent, markers)
    }

    /// Matches an ordinary captured directory's own and parent structural markers by scan ID.
    /// All own markers and at least one declared parent marker must match. Linked markers,
    /// filenames from other directories and display paths cannot supply this evidence.
    /// This observes structural layout only; file contents, tool activity and deletion authority
    /// need separate evidence. Missing marker observations never satisfy a required predicate.
    pub fn match_project_entry(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<&ProjectJunkRule> {
        if entry.object_type != ObjectType::Directory {
            return None;
        }
        let identity = entry.identity.as_ref()?;
        self.match_project_context(
            &entry.native_basename,
            Some(&identity.entry_id),
            identity.parent_id.as_ref(),
            markers,
        )
    }

    fn match_project_context(
        &self,
        name: &NativeName,
        own: Option<&ScanEntryId>,
        parent: Option<&ScanEntryId>,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<&ProjectJunkRule> {
        let name = native_rule_name(name)?;
        let indices = self.by_name.get(&name)?;
        let observed_parent = parent.and_then(|id| markers.get(id));
        for &index in indices {
            let rule = &self.rules[index];
            let predicate = &self.predicates[index];
            // Only matching names reach the VM. Marker sets stay borrowed and identity-bound;
            // no subtree-sized facts are cloned into the per-candidate context.
            let parent_match = observed_parent.map(|observed| {
                self.parent_markers[index]
                    .iter()
                    .any(|marker| observed.contains(marker))
            });
            let mut context =
                EvaluationContext::new().insert("entry.name", VmValue::String(name.clone()));
            if let Some(matches) = parent_match {
                context = context.insert("parent.marker_matches", VmValue::Bool(matches));
            }
            // Avoid an extra marker-map lookup/context field for the existing parent-only rules.
            if !self.own_markers[index].is_empty()
                && let Some(observed) = own.and_then(|id| markers.get(id))
            {
                context = context.insert(
                    "entry.marker_matches",
                    VmValue::Bool(
                        self.own_markers[index]
                            .iter()
                            .all(|marker| observed.contains(marker)),
                    ),
                );
            }
            if evaluate_predicate(predicate, &context).is_ok_and(|result| result.is_true()) {
                return Some(rule);
            }
        }
        None
    }
}

impl crate::JunkClassifier for JunkService {
    fn needs_file_marker(&self, name: &NativeName) -> bool {
        self.needs_project_marker(name)
    }

    fn uses_only_local_markers(&self) -> bool {
        true
    }

    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        self.match_project_entry(entry, markers)
            .map(|rule| format!("project:{}", rule.id))
    }
}

/// Decodes lossless scanner basenames using the existing native-name rule conventions.
pub fn native_rule_name(name: &NativeName) -> Option<String> {
    match name {
        NativeName::UnixBytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        NativeName::WindowsUtf16(units) => String::from_utf16(units)
            .ok()
            .map(|name| name.to_ascii_lowercase()),
    }
}

/// Normalizes catalog names using the existing host rule convention.
pub fn normalize_rule_name(name: &str) -> String {
    if cfg!(windows) {
        name.to_ascii_lowercase()
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> NativeName {
        if cfg!(windows) {
            NativeName::WindowsUtf16(text.encode_utf16().collect())
        } else {
            NativeName::UnixBytes(text.as_bytes().to_vec())
        }
    }

    #[test]
    fn target_requires_markers_from_the_captured_parent() {
        let service = JunkService::built_in().unwrap();
        let parent =
            ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("junk-test"), 1).unwrap();
        let other =
            ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("junk-test"), 2).unwrap();
        let mut markers =
            BTreeMap::from([(other, BTreeSet::from([normalize_rule_name("Cargo.toml")]))]);
        assert!(
            service
                .match_project(&name("target"), Some(&parent), &markers)
                .is_none()
        );
        markers.insert(
            parent.clone(),
            BTreeSet::from([normalize_rule_name("pom.xml")]),
        );
        assert_eq!(
            service
                .match_project(&name("target"), Some(&parent), &markers)
                .unwrap()
                .id,
            "maven.target"
        );
        markers.insert(
            parent.clone(),
            BTreeSet::from([normalize_rule_name("Cargo.toml")]),
        );
        assert_eq!(
            service
                .match_project(&name("target"), Some(&parent), &markers)
                .unwrap()
                .id,
            "rust.target"
        );
        assert!(
            service
                .match_project(&name("target"), None, &markers)
                .is_none()
        );
    }

    #[test]
    fn overlapping_names_keep_catalog_priority() {
        let mut rules: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        rules[1]["names"] = serde_json::json!(["target", "target"]);
        rules[1]["requiredParentMarkers"] = serde_json::json!(["Cargo.toml"]);
        let parent =
            ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("priority"), 1).unwrap();
        let markers = BTreeMap::from([(
            parent.clone(),
            BTreeSet::from([normalize_rule_name("Cargo.toml")]),
        )]);
        let service = JunkService::from_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap();
        assert_eq!(
            service
                .match_project(&name("target"), Some(&parent), &markers)
                .unwrap()
                .id,
            "rust.target"
        );
        rules.as_array_mut().unwrap().swap(0, 1);
        let service = JunkService::from_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap();
        assert_eq!(
            service
                .match_project(&name("target"), Some(&parent), &markers)
                .unwrap()
                .id,
            "node.modules"
        );
    }

    #[test]
    fn missing_evidence_and_user_state_are_not_promoted() {
        let service = JunkService::built_in().unwrap();
        for entry in ["dist", "build", ".env.local", "my-cache"] {
            assert!(
                service
                    .match_project(&name(entry), None, &BTreeMap::new())
                    .is_none()
            );
        }
        assert_eq!(
            service
                .match_project(&name("__pycache__"), None, &BTreeMap::new())
                .unwrap()
                .id,
            "python.cache"
        );
        assert!(
            service
                .match_project(&NativeName::UnixBytes(vec![255]), None, &BTreeMap::new())
                .is_none()
        );
    }

    #[test]
    fn marker_selection_follows_loaded_rules_not_a_hand_maintained_list() {
        let service = JunkService::built_in().unwrap();
        assert!(service.needs_project_marker(&name("Cargo.toml")));
        assert!(!service.needs_project_marker(&name("ordinary-payload.bin")));
        let mut rules: serde_json::Value = serde_json::from_str(PROJECT_RULES_JSON).unwrap();
        rules[0]["requiredParentMarkers"] = serde_json::json!(["custom.marker"]);
        let service = JunkService::from_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap();
        assert!(service.needs_project_marker(&name("custom.marker")));
        assert!(!service.needs_project_marker(&name("Cargo.toml")));
        assert!(service.needs_project_marker(&name("package_config.json")));
        rules[5]["requiredOwnMarkers"] = serde_json::json!(["replacement.json"]);
        // Exercise an editable structural rule, without claiming the fixed content profile still
        // has its required package_config.json input.
        rules[5]["contentFormat"] = serde_json::Value::Null;
        let edited = JunkService::from_rule_bytes(&serde_json::to_vec(&rules).unwrap()).unwrap();
        assert!(edited.needs_project_marker(&name("replacement.json")));
        assert!(!edited.needs_project_marker(&name("package_config.json")));
        assert_ne!(service.rule_bytes_digest, edited.rule_bytes_digest);
    }

    #[test]
    fn own_markers_require_captured_id_and_all_declared_files() {
        let service = JunkService::built_in().unwrap();
        let scan = sweepx_model::ScanId::new("own-markers");
        let parent = ScanEntryId::for_scan_ordinal(&scan, 1).unwrap();
        let own = ScanEntryId::for_scan_ordinal(&scan, 2).unwrap();
        let other = ScanEntryId::for_scan_ordinal(&scan, 3).unwrap();
        let files = |names: &[&str]| {
            names
                .iter()
                .map(|name| normalize_rule_name(name))
                .collect::<BTreeSet<_>>()
        };
        let mut markers = BTreeMap::from([
            (
                parent.clone(),
                files(&["svelte.config.js", "tsconfig.json", "ambient.d.ts"]),
            ),
            (other, files(&["tsconfig.json", "ambient.d.ts"])),
        ]);
        assert!(
            service
                .match_project_context(&name(".svelte-kit"), Some(&own), Some(&parent), &markers)
                .is_none()
        );
        markers.insert(own.clone(), files(&["tsconfig.json"]));
        assert!(
            service
                .match_project_context(&name(".svelte-kit"), Some(&own), Some(&parent), &markers)
                .is_none()
        );
        markers.insert(own.clone(), files(&["tsconfig.json", "ambient.d.ts"]));
        assert_eq!(
            service
                .match_project_context(&name(".svelte-kit"), Some(&own), Some(&parent), &markers)
                .unwrap()
                .id,
            "node.sveltekit-output"
        );
        assert!(
            service
                .match_project(&name(".svelte-kit"), Some(&parent), &markers)
                .is_none()
        );
        assert!(
            service
                .match_project_context(&name(".svelte-kit"), Some(&own), None, &markers)
                .is_none()
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn native_project_layout_corpus_matches_exact_candidates_without_cli() {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = fixture.path().canonicalize().unwrap();
        #[cfg(not(unix))]
        let root = fixture.path().to_path_buf();
        let cases = sweepx_fixtures::project_junk::generate(&root).unwrap();
        let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let service = JunkService::built_in().unwrap();
        for (case, case_root) in cases {
            let result = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
                &context,
                &crate::ScanRequest {
                    roots: vec![case_root.clone()],
                    state_dir: None,
                },
                None,
                &service,
                None,
            )
            .unwrap();
            assert_eq!(
                result.scan.output.status,
                sweepx_protocol::OutputStatus::Ok,
                "{}",
                case.version
            );
            let observed = result
                .scan
                .summary
                .roots
                .iter()
                .chain(&result.scan.summary.entries)
                .filter_map(|entry| {
                    let id = &entry.identity.as_ref()?.entry_id;
                    let decision = result.decisions.get(id)?;
                    assert!(entry.validated_native_locator().unwrap().is_some());
                    Some((
                        std::path::PathBuf::from(&entry.display_path),
                        decision.strip_prefix("project:").unwrap().to_string(),
                    ))
                })
                .collect::<BTreeSet<_>>();
            let expected = case
                .candidates
                .iter()
                .map(|(path, rule)| (case_root.join(path), (*rule).to_string()))
                .collect::<BTreeSet<_>>();
            assert_eq!(observed, expected, "{}", case.version);
        }
    }
}
