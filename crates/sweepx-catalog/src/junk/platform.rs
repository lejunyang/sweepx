//! Platform junk rule admission, independent of host discovery and rendering.

use super::is_safe_rule_component;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Exact built-in bytes used by classification and cache digests.
pub const PLATFORM_JUNK_RULES_JSON: &str = include_str!("../../resources/platform-junk-rules.json");

/// A fixed, well-known filesystem location a rule can select without a tool reporting it.
///
/// The location is expressed relative to a resolved `base` rather than as a literal absolute
/// string, so a rule stays portable across users and volumes. Only documented, vendor-published
/// roots belong here; a directory name guessed from an upstream catalog is not evidence by
/// itself.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnownRoot {
    /// Anchor the components are joined onto. `home` resolves to the current user's home
    /// directory and must be absolute; unknown bases are rejected.
    pub base: String,
    /// Path components appended to `base`, in order. Every component must be a single non-empty
    /// name with no separators or parent traversal.
    pub components: Vec<String>,
}

/// Declarative layout of one Chromium-family browser's derived GPU/network caches.
///
/// A browser keeps caches in two places: shared directories sitting beside the profiles, and one
/// directory per enumerated profile. Encoding this in the rule data lets SweepX discover caches
/// for any browser without a code branch per browser or a hardcoded profile-name list (profiles
/// are expanded from disk). Only derived cache directory names belong in the lists; cookies,
/// history, passwords, bookmarks, Local Storage and IndexedDB are never named.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserCacheSpec {
    /// Anchor `userData` is resolved against: `application_support` (`~/Library/Application
    /// Support`), `local_app_data` (`%LOCALAPPDATA%`), or `home`.
    pub base: String,
    /// Components from `base` to the browser's user-data directory.
    pub user_data: Vec<String>,
    /// Cache directories that live directly under the user-data directory, shared by all
    /// profiles, for example `GrShaderCache`.
    #[serde(default)]
    pub shared_caches: Vec<String>,
    /// Cache directories that live inside each profile, for example `GPUCache`.
    #[serde(default)]
    pub profile_caches: Vec<String>,
    /// Multi-component `/`-separated paths relative to user-data for non-derived-cache state,
    /// for example `Crashpad/reports` or `Shared Dictionary/cache`.
    #[serde(default)]
    pub shared_paths: Vec<String>,
    /// Multi-component `/`-separated paths relative to each profile, for example
    /// `Service Worker/CacheStorage`.
    #[serde(default)]
    pub profile_paths: Vec<String>,
    /// Explicit profile directory names directly under user-data, for example `IronDefault`.
    /// Use this when a product does not follow the `Default`/`Profile N` convention.
    #[serde(default)]
    pub profile_names: Vec<String>,
    /// When true (the default), profiles named `Default` and `Profile N` are enumerated from
    /// user-data. Set false for products whose only profiles are those in `profileNames` or
    /// `partition_containers`.
    #[serde(default = "default_true")]
    pub enumerate_named_profiles: bool,
    /// Directories under user-data whose every real-directory child is a profile/partition. Use
    /// for products such as Postman that name partitions with UUIDs under `Partitions`.
    #[serde(default)]
    pub partition_containers: Vec<String>,
}

const fn default_true() -> bool {
    true
}

/// Admitted report-only platform rule. Matching never grants deletion authority.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformJunkRule {
    /// Stable machine rule identifier.
    pub id: String,
    /// Supported target platform, or `any` for a tool-reported root.
    pub platform: String,
    /// Discovery contract associated with this rule.
    pub root_kind: String,
    /// Matching contract validated together with platform, root kind and depth.
    pub match_kind: String,
    /// Native basename alternatives for a named descendant.
    pub names: Vec<String>,
    /// Child names that must exist inside the root before it is reported.
    ///
    /// For tool-reported roots this is the structural check that the directory really is the
    /// cache the tool described, rather than whatever else now sits at that path.
    pub required_markers: Vec<String>,
    /// Fixed locations a `verified_known_root` rule selects. Empty for every other match kind,
    /// which keeps location knowledge in the rule data instead of in code keyed on rule id.
    #[serde(default)]
    pub known_roots: Vec<KnownRoot>,
    /// Browser-cache layouts a `verified_browser_cache` rule expands. One entry per browser;
    /// discovery walks shared and per-profile cache directories from each, in the rule data.
    #[serde(default)]
    pub browser_caches: Vec<BrowserCacheSpec>,
    /// Required depth below the admitted scan root for depth-based matching.
    pub depth: usize,
    /// Stable risk tier (`R1`, `R2` or `R3`); never mutation authority.
    pub risk: String,
    /// Explanation of the rule's ownership and rebuild or state evidence.
    pub evidence: String,
    /// Primary-source review date in YYYY-MM-DD notation.
    pub source_reviewed_at: String,
    /// HTTPS primary-source references for this rule.
    pub references: Vec<String>,
}

/// Admission failure for platform-rule JSON.
#[derive(Debug, thiserror::Error)]
pub enum PlatformRuleError {
    /// Malformed JSON, including unknown or missing fields.
    #[error("invalid platform rule JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Input exceeds byte, rule or nested-list resource limits.
    #[error("platform rule catalog exceeds its resource limit")]
    ResourceLimit,
    /// A rule violates its discovery or evidence contract.
    #[error("{0}")]
    InvalidRule(String),
}

/// Loads built-in rules through the same bounded admission path as caller-supplied JSON.
pub fn load_platform_junk_rules() -> Result<Vec<PlatformJunkRule>, PlatformRuleError> {
    load_platform_rule_bytes(PLATFORM_JUNK_RULES_JSON.as_bytes())
}

/// Admits strict, bounded rules without touching the filesystem or executing tools.
pub fn load_platform_rule_bytes(bytes: &[u8]) -> Result<Vec<PlatformJunkRule>, PlatformRuleError> {
    if bytes.len() > 128 * 1024 {
        return Err(PlatformRuleError::ResourceLimit);
    }
    let rules: Vec<PlatformJunkRule> = serde_json::from_slice(bytes)?;
    if rules.is_empty() || rules.len() > 64 {
        return Err(PlatformRuleError::ResourceLimit);
    }
    for rule in &rules {
        if rule.names.len() > 64
            || rule.required_markers.len() > 64
            || rule.references.len() > 64
            || rule.known_roots.len() > 64
            || rule.browser_caches.len() > 64
            || rule
                .known_roots
                .iter()
                .any(|known| known.components.len() > 64)
            || rule.browser_caches.iter().any(|spec| {
                [
                    &spec.user_data,
                    &spec.shared_caches,
                    &spec.profile_caches,
                    &spec.shared_paths,
                    &spec.profile_paths,
                    &spec.profile_names,
                    &spec.partition_containers,
                ]
                .iter()
                .any(|list| list.len() > 64)
            })
        {
            return Err(PlatformRuleError::ResourceLimit);
        }
    }
    validate_platform_rules(rules).map_err(PlatformRuleError::InvalidRule)
}

fn validate_platform_rules(rules: Vec<PlatformJunkRule>) -> Result<Vec<PlatformJunkRule>, String> {
    let mut ids = BTreeSet::new();
    for rule in &rules {
        let expected = match rule.platform.as_str() {
            "linux" => match rule.root_kind.as_str() {
                "xdg_cache_home" => ("xdg_cache_home", "direct_children", 1),
                "linux_tmp" => ("linux_tmp", "stale_inactive_direct_child", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
            "macos" => match rule.root_kind.as_str() {
                "macos_user_caches" => ("macos_user_caches", "direct_children", 1),
                "macos_developer_cache" => ("macos_developer_cache", "verified_known_root", 0),
                "macos_browser_cache" => ("macos_browser_cache", "verified_known_root", 0),
                // Derived GPU/shader caches that live in Application Support, outside the
                // ~/Library/Caches tree; expanded from the rule's declarative browser layouts.
                "macos_browser_derived_cache" => {
                    ("macos_browser_derived_cache", "verified_browser_cache", 0)
                }
                // R3 application/site state and diagnostics expanded through the same layout.
                "macos_browser_state" => ("macos_browser_state", "verified_browser_cache", 0),
                "macos_app_cache" => ("macos_app_cache", "verified_known_root", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
            // A platform can host more than one root kind, so the shape is keyed on the root
            // kind rather than on the platform. Keying it on the platform alone made the first
            // root kind the only one that platform could ever express.
            "windows" => match rule.root_kind.as_str() {
                "windows_packages" => ("windows_packages", "named_descendant", 2),
                // Browser render caches sit one level below a profile directory, and the
                // browser-level shader caches sit directly below the user-data root. Discovery
                // yields both as scan roots, so the rule matches the root itself.
                "chromium_render_cache" => ("chromium_render_cache", "verified_cache_root", 0),
                _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
            },
            // A tool-reported root is the scan root itself, so its depth is 0 and its
            // `rootKind` must be one the discovery table actually knows how to resolve.
            // Otherwise a rule could name a root that is silently never produced.
            "any" => {
                if !matches!(
                    rule.root_kind.as_str(),
                    "npm_reported_cache" | "pnpm_reported_store" | "pip_reported_cache"
                ) {
                    return Err(format!(
                        "platform junk rule {} names an unresolvable root kind: {}",
                        rule.id, rule.root_kind
                    ));
                }
                (rule.root_kind.as_str(), "verified_tool_root", 0)
            }
            _ => return Err(format!("invalid platform junk rule: {}", rule.id)),
        };
        let id_prefix = if rule.platform == "any" {
            "tool."
        } else {
            &format!("{}.", rule.platform)
        };
        if !ids.insert(rule.id.as_str())
            || !rule.id.starts_with(id_prefix)
            || (
                rule.root_kind.as_str(),
                rule.match_kind.as_str(),
                rule.depth,
            ) != expected
            || !matches!(rule.risk.as_str(), "R1" | "R2" | "R3")
            || rule.evidence.trim().is_empty()
            || !valid_verification_date(&rule.source_reviewed_at)
            || rule.references.is_empty()
            || !rule
                .references
                .iter()
                .all(|reference| reference.starts_with("https://"))
            || !rule
                .names
                .iter()
                .chain(rule.required_markers.iter())
                .all(|name| is_safe_rule_component(name))
            || (rule.match_kind == "direct_children" && !rule.names.is_empty())
            || (rule.match_kind == "stale_inactive_direct_child"
                && (rule.root_kind != "linux_tmp"
                    || !rule.names.is_empty()
                    || !rule.required_markers.is_empty()
                    || rule.risk != "R3"))
            || (rule.match_kind == "named_descendant" && rule.names.is_empty())
            // A tool-reported root is admitted on the tool's word alone, so it must carry at
            // least one structural marker; without one the rule would report whatever now
            // occupies that path.
            || (rule.match_kind == "verified_tool_root"
                && (!rule.names.is_empty() || rule.required_markers.is_empty()))
            // A cache root is admitted because discovery walked a known browser layout, but the
            // directory still has to prove it is a cache. Chromium writes a backend marker into
            // every one; requiring it keeps the rule from reporting a same-named directory that
            // happens to sit at that path.
            || (rule.match_kind == "verified_cache_root"
                && (!rule.names.is_empty() || rule.required_markers.is_empty()))
            || (rule.match_kind == "verified_known_root"
                && (!rule.names.is_empty() || rule.known_roots.is_empty()))
            || (rule.match_kind != "verified_known_root" && !rule.known_roots.is_empty())
            // A verified_browser_cache rule must declare at least one browser spec, and no other
            // kind may carry them.
            || (rule.match_kind == "verified_browser_cache"
                && (!rule.names.is_empty()
                    || rule.browser_caches.is_empty()
                    || !rule.required_markers.is_empty()))
            || (rule.match_kind != "verified_browser_cache" && !rule.browser_caches.is_empty())
            || !rule
                .known_roots
                .iter()
                .all(|known| {
                    known.base == "home"
                        && !known.components.is_empty()
                        && known
                            .components
                            .iter()
                            .all(|component| is_safe_rule_component(component))
                })
            || !rule
                .browser_caches
                .iter()
                .all(|spec| {
                    let valid_anchor =
                        matches!(spec.base.as_str(), "application_support" | "local_app_data" | "home");
                    let has_any_target = !spec.shared_caches.is_empty()
                        || !spec.profile_caches.is_empty()
                        || !spec.shared_paths.is_empty()
                        || !spec.profile_paths.is_empty();
                    let can_find_profiles = spec.enumerate_named_profiles
                        || !spec.profile_names.is_empty()
                        || !spec.partition_containers.is_empty();
                    // A profile-scoped target with no way to locate a profile would be inert.
                    let profile_discovery_is_possible =
                        (spec.profile_caches.is_empty() && spec.profile_paths.is_empty())
                            || can_find_profiles;
                    let safe_single_components = spec
                        .user_data
                        .iter()
                        .chain(spec.shared_caches.iter())
                        .chain(spec.profile_caches.iter())
                        .chain(spec.profile_names.iter())
                        .chain(spec.partition_containers.iter())
                        .all(|component| is_safe_rule_component(component));
                    // Every segment of a multi-component path must also be a safe component.
                    let safe_path_segments = spec
                        .shared_paths
                        .iter()
                        .chain(spec.profile_paths.iter())
                        .all(|relative| {
                            !relative.is_empty()
                                && relative
                                    .split('/')
                                    .all(is_safe_rule_component)
                        });
                    valid_anchor
                        && !spec.user_data.is_empty()
                        && has_any_target
                        && profile_discovery_is_possible
                        && safe_single_components
                        && safe_path_segments
                })
        {
            return Err(format!("invalid platform junk rule: {}", rule.id));
        }
    }
    Ok(rules)
}
fn valid_verification_date(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7) && byte == b'-'
                || !matches!(index, 4 | 7) && byte.is_ascii_digit()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edited_platform_rules_use_strict_bounded_admission() {
        let original: serde_json::Value = serde_json::from_str(PLATFORM_JUNK_RULES_JSON).unwrap();
        for (field, value) in [
            ("rootKind", serde_json::json!("unknown_root")),
            ("depth", serde_json::json!(0)),
            ("names", serde_json::json!(["../data"])),
            ("risk", serde_json::json!("safe")),
            ("sourceReviewedAt", serde_json::json!("undated")),
            ("references", serde_json::json!([])),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut edited = original.clone();
            edited[0][field] = value;
            assert!(
                load_platform_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err(),
                "{field}"
            );
        }
        let mut duplicate = original.clone();
        duplicate[1]["id"] = duplicate[0]["id"].clone();
        assert!(load_platform_rule_bytes(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let mut oversized_list = original;
        oversized_list[0]["requiredMarkers"] = serde_json::json!(vec!["marker"; 65]);
        assert!(matches!(
            load_platform_rule_bytes(&serde_json::to_vec(&oversized_list).unwrap()),
            Err(PlatformRuleError::ResourceLimit)
        ));
        assert!(matches!(
            load_platform_rule_bytes(&vec![b' '; 131073]),
            Err(PlatformRuleError::ResourceLimit)
        ));
        assert!(matches!(
            load_platform_rule_bytes(b"[]"),
            Err(PlatformRuleError::ResourceLimit)
        ));
    }

    #[test]
    fn browser_paths_and_known_roots_cannot_escape_the_declared_anchor() {
        let original: serde_json::Value = serde_json::from_str(PLATFORM_JUNK_RULES_JSON).unwrap();
        let rules = original.as_array().unwrap();
        let browser = rules
            .iter()
            .position(|rule| rule["id"] == "macos.browser-derived-cache")
            .unwrap();
        let known = rules
            .iter()
            .position(|rule| rule["id"] == "macos.xcode-derived-data")
            .unwrap();
        for escaped in [
            "../data",
            "Cache/../Cookies",
            "/Cache",
            "Cache//data",
            "Cache\\data",
        ] {
            let mut edited = original.clone();
            edited[browser]["browserCaches"][0]["profilePaths"] = serde_json::json!([escaped]);
            assert!(
                load_platform_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err(),
                "{escaped}"
            );
        }
        let mut edited = original;
        edited[known]["knownRoots"][0]["components"] =
            serde_json::json!(["Library", "..", "Documents"]);
        assert!(load_platform_rule_bytes(&serde_json::to_vec(&edited).unwrap()).is_err());
    }
}
