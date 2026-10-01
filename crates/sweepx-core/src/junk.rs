//! Project junk classification over captured scan facts, shared by CLI and future TUI sessions.
//!
//! Rules live in the catalog and their predicates use the existing cleaner VM. The service does
//! no filesystem I/O and starts no subprocesses. Platform root discovery remains a separate input.

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
    rules: Vec<ProjectJunkRule>,
    predicates: Vec<Predicate>,
    // Immutable indexes preserve catalog order for overlapping names while avoiding repeated
    // normalization/allocation on every ordinary directory in a large traversal.
    by_name: BTreeMap<String, Vec<usize>>,
    parent_markers: Vec<Vec<String>>,
}

impl JunkService {
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
                if rule.required_parent_markers.is_empty() {
                    name
                } else {
                    Predicate::Call {
                        op: PredicateOp::And,
                        args: vec![
                            PredicateArg::Predicate(Box::new(name)),
                            PredicateArg::Predicate(Box::new(Predicate::Call {
                                op: PredicateOp::Eq,
                                args: vec![
                                    PredicateArg::FieldRef {
                                        field: "parent.marker_matches".into(),
                                    },
                                    PredicateArg::Bool(true),
                                ],
                            })),
                        ],
                    }
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
        Ok(Self {
            rules,
            predicates,
            by_name,
            parent_markers,
        })
    }

    /// Returns admitted rules for rendering their existing risk and evidence fields.
    pub fn project_rules(&self) -> &[ProjectJunkRule] {
        &self.rules
    }

    /// Matches lossless observed names and identity-keyed parent markers, never display paths.
    ///
    /// `None` parent evidence cannot satisfy a marker-dependent rule. This method consumes scan
    /// facts only; callers must use directory observations and perform independent execution checks.
    pub fn match_project(
        &self,
        name: &NativeName,
        parent: Option<&ScanEntryId>,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<&ProjectJunkRule> {
        let name = native_rule_name(name)?;
        let observed_parent = parent.and_then(|id| markers.get(id));
        for &index in self.by_name.get(&name)? {
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
            if evaluate_predicate(predicate, &context).is_ok_and(|result| result.is_true()) {
                return Some(rule);
            }
        }
        None
    }
}

impl crate::JunkClassifier for JunkService {
    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        if entry.object_type != ObjectType::Directory {
            return None;
        }
        let identity = entry.identity.as_ref()?;
        self.match_project(&entry.native_basename, identity.parent_id.as_ref(), markers)
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
}
