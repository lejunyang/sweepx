//! Presentation-only organization of admitted candidates. Names never confer cleanup authority.

use super::candidate::JunkCandidate;
use serde::Serialize;
use std::path::Path;
use sweepx_i18n::Locale;

/// Stable top-level cleanup categories, independent of localized labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JunkCategory {
    /// Application cache roots with an admitted cache rule.
    Applications,
    /// Browser caches; persistent browser data is a separate review category.
    Browsers,
    /// Tool-managed downloads and generated caches.
    DeveloperTools,
    /// Project build products, environments and dependencies.
    Projects,
    /// Temporary objects admitted by the platform-specific evaluator.
    Temporary,
    /// User data or an unknown rule requiring separate review.
    Review,
}
impl JunkCategory {
    /// Stable grouping identifier; never localized in machine output.
    pub fn id(self) -> &'static str {
        match self {
            Self::Applications => "applications",
            Self::Browsers => "browsers",
            Self::DeveloperTools => "developer_tools",
            Self::Projects => "projects",
            Self::Temporary => "temporary",
            Self::Review => "review",
        }
    }
    /// User-facing category name.
    pub fn label(self, locale: Locale) -> &'static str {
        let (zh, en) = match self {
            Self::Applications => ("应用缓存", "Application caches"),
            Self::Browsers => ("浏览器缓存", "Browser caches"),
            Self::DeveloperTools => ("开发工具缓存", "Developer tool caches"),
            Self::Projects => ("项目构建与依赖", "Project builds and dependencies"),
            Self::Temporary => ("临时文件", "Temporary files"),
            Self::Review => ("待单独核验", "Separate review required"),
        };
        if locale == Locale::ZhCn { zh } else { en }
    }
}

/// Display grouping derived from an already admitted rule and its display location.
/// `owner_key` only distinguishes groups; it must never be used for filesystem operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JunkOrganization {
    /// Top-level category.
    pub category: JunkCategory,
    /// Stable display group key, including the full location for project/source groups.
    pub owner_key: String,
    /// Application/tool name or source-directory label.
    pub owner_label: String,
    /// False means a source location, not a resolved application or project ownership claim.
    pub named_application: bool,
}

/// Organizes a candidate without reading the filesystem or altering its evidence or blockers.
pub fn organize(candidate: &JunkCandidate) -> JunkOrganization {
    organize_location(&candidate.rule_id, &candidate.path)
}

/// Pure location projection shared by interactive and report presentations.
/// Unknown rules remain review-only in the presentation; no path is a deletion authority.
pub fn organize_location(rule: &str, path: &str) -> JunkOrganization {
    use JunkCategory::*;
    let named = |category, name: &str| JunkOrganization {
        category,
        owner_key: name.into(),
        owner_label: name.into(),
        named_application: true,
    };
    let location = |category, path: &Path| JunkOrganization {
        category,
        owner_key: path.to_string_lossy().into_owned(),
        owner_label: path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned(),
        named_application: false,
    };
    let source = Path::new(path);
    match rule {
        "macos.browser-state-diagnostics" | "tool.osdk-data" => location(Review, source),
        "linux.stale-temp-object" => location(Temporary, source.parent().unwrap_or(source)),
        "macos.user-caches" | "linux.xdg-user-cache" | "windows.packaged-app-cache" => {
            location(Applications, source)
        }
        "macos.tencent-meeting-cache" => named(Applications, "Tencent Meeting"),
        "macos.jetbrains-cache" => named(DeveloperTools, "JetBrains"),
        "macos.xcode-derived-data" => named(DeveloperTools, "Xcode"),
        "macos.cargo-registry-cache" => named(DeveloperTools, "Cargo"),
        "macos.homebrew-cache" => named(DeveloperTools, "Homebrew"),
        "macos.go-cache" => named(DeveloperTools, "Go"),
        "macos.uv-cache" => named(DeveloperTools, "uv"),
        "macos.bun-cache" => named(DeveloperTools, "Bun"),
        "macos.yarn-cache" => named(DeveloperTools, "Yarn"),
        "macos.gradle-cache" => named(DeveloperTools, "Gradle"),
        "macos.deno-cache" => named(DeveloperTools, "Deno"),
        "tool.npm-other-data" => named(Review, "npm"),
        "tool.npm-cache" | "tool.npm-logs" | "tool.npm-npx" => named(DeveloperTools, "npm"),
        "tool.pnpm-store" => named(DeveloperTools, "pnpm"),
        "tool.pip-cache" => named(DeveloperTools, "pip"),
        "macos.firefox-cache" => named(Browsers, "Firefox"),
        "macos.safari-cache" => named(Browsers, "Safari"),
        "macos.chromium-cache"
        | "macos.browser-derived-cache"
        | "windows.chromium-http-cache"
        | "windows.chromium-code-cache"
        | "windows.chromium-shader-cache" => {
            // Match complete components within a rule-validated browser location, never a
            // substring that could make an unrelated directory look like a named application.
            let name = source
                .components()
                .find_map(|part| match part.as_os_str().to_str()? {
                    "Google Chrome" | "Chrome" => Some("Google Chrome"),
                    "Microsoft Edge" | "Edge" => Some("Microsoft Edge"),
                    "BraveSoftware" | "Brave-Browser" => Some("Brave"),
                    "Chromium" => Some("Chromium"),
                    "com.apple.Safari" => Some("Safari"),
                    _ => None,
                });
            name.map_or_else(|| location(Browsers, source), |name| named(Browsers, name))
        }
        "rust.target"
        | "rust.incremental"
        | "rust.dependencies"
        | "rust.build-script-output"
        | "rust.fingerprints"
        | "rust.examples"
        | "rust.target-platform"
        | "maven.target"
        | "node.modules"
        | "node.vite-deps"
        | "node.sveltekit-output"
        | "dart.tool-state"
        | "python.cache"
        | "python.virtualenv"
        | "project.build-output" => {
            let anchor = if rule.starts_with("rust.") || rule == "maven.target" {
                "target"
            } else if matches!(rule, "node.modules" | "node.vite-deps") {
                "node_modules"
            } else {
                ""
            };
            let base = source
                .ancestors()
                .find(|p| !anchor.is_empty() && p.file_name().is_some_and(|n| n == anchor))
                .unwrap_or(source);
            location(Projects, base.parent().unwrap_or(base))
        }
        _ => location(Review, source),
    }
}

/// Projects nested rows into the outer candidate's group using captured scan identities.
/// This keeps categories additive without double-counting a child in another category.
pub fn organize_candidates(candidates: &[JunkCandidate]) -> Vec<JunkOrganization> {
    let identities: std::collections::BTreeMap<_, _> =
        candidates.iter().map(|row| (&row.entry_id, row)).collect();
    candidates
        .iter()
        .map(|row| {
            let outer = row
                .ancestor_ids
                .iter()
                .filter_map(|id| identities.get(id).copied())
                .min_by_key(|parent| parent.ancestor_ids.len())
                .unwrap_or(row);
            organize(outer)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_nesting_and_duplicate_basenames_preserve_location_identity() {
        let root = organize_location("rust.target", "/a/app/target");
        let nested = organize_location("rust.incremental", "/a/app/target/debug/incremental");
        assert_eq!(root, nested);
        let other = organize_location("rust.target", "/b/app/target");
        assert_eq!(root.owner_label, other.owner_label);
        assert_ne!(root.owner_key, other.owner_key);
        assert!(!root.named_application);
    }
    #[test]
    fn unknown_sources_and_persistent_data_are_not_claimed_as_browser_caches() {
        assert_eq!(
            organize_location("macos.browser-state-diagnostics", "/Chrome/data").category,
            JunkCategory::Review
        );
        assert_eq!(
            organize_location("custom.rule", "/Chrome/cache").category,
            JunkCategory::Review
        );
        assert!(!organize_location("macos.user-caches", "/Caches/Chrome-ish").named_application);
        assert!(!organize_location("macos.chromium-cache", "/Caches/Chrome-ish").named_application);
        assert_eq!(
            organize_location(
                "macos.chromium-cache",
                "/Caches/Google/Chrome/Default/Cache"
            )
            .owner_label,
            "Google Chrome"
        );
    }
}
