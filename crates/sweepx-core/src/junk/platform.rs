//! Platform junk discovery and interpretation independent of terminal rendering.
//!
//! Discovery is invocation-scoped and read-only; matching consumes captured native facts.
//! Tool answers share a bounded runner and must not be persisted as filesystem evidence.

use super::{
    JunkService, native_rule_name as native_name_for_rule,
    normalize_rule_name as normalized_rule_name,
};
use crate::tools::{self as tool_installations, ProbeLimits, ProbeRunner};
use crate::{CancellationToken, JunkClassifier};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
pub use sweepx_catalog::junk::platform::{
    PLATFORM_JUNK_RULES_JSON, PlatformJunkRule, load_platform_junk_rules,
};
use sweepx_model::ScanEntryId;

/// Expensive, rule-derived evidence computed once and shared by every classification.
///
/// Tool discovery shells out to the developer tool — for npm it additionally enumerates
/// every installation and asks each copy for its cache. Version queries belong only to inventory. These values depend only on the rule and the host
/// environment, never on a scanned entry, so asking for them on every `verified_tool_root` check
/// during the walk turned one scan into hundreds of sequential tool launches. Measured on this
/// host 2026-09-29: the walk sat blocked in `poll` on tool output for more than six minutes while
/// using under twenty seconds of CPU. Capturing the answers here once is what keeps the
/// accelerated walk I/O-bound instead of subprocess-bound.
pub struct PlatformRuleEvidence {
    /// Verified cache locations (markers and structural fingerprint already checked).
    pub cache_candidates: Vec<PathBuf>,
    /// Cache the tool itself currently names, after resolution; `None` for non-tool-reported
    /// rules or when the tool could not be asked (then liveness is `Unknown`, never `Stale`).
    pub reported_root: Option<PathBuf>,
}

/// Owned, rule-id-keyed table of precomputed platform evidence.
#[derive(Default)]
pub struct PlatformJunkEvidence {
    /// Installation facts shared with inventory rendering.
    pub npm_installations: Vec<tool_installations::ToolInstallation>,
    by_rule: BTreeMap<String, PlatformRuleEvidence>,
}

impl PlatformJunkEvidence {
    /// Resolves the expensive inputs for every rule once, before the walk begins.
    pub fn precompute(rules: &[PlatformJunkRule]) -> Self {
        Self::precompute_with_cancel(rules, CancellationToken::new())
    }

    /// Uses the caller's cancellation token for all tool probes in this invocation.
    /// Filesystem discovery remains read-only and is subject to host filesystem call latency.
    pub fn precompute_with_cancel(rules: &[PlatformJunkRule], cancel: CancellationToken) -> Self {
        let mut runner = ProbeRunner::new(ProbeLimits::default(), cancel);
        let mut reported = BTreeMap::new();
        // Resolve non-npm roots first. npm's multi-installation inventory consumes the rest of
        // the same budget, and supplies both its cache candidates and the PATH default answer.
        for rule in rules
            .iter()
            .filter(|rule| rule.root_kind != "npm_reported_cache")
        {
            if let Some(tool) = tool_reported_root_for(&rule.root_kind) {
                reported.insert(rule.id.clone(), tool.resolve(&mut runner));
            }
        }
        let npm_installations = if rules
            .iter()
            .any(|rule| rule.root_kind == "npm_reported_cache")
        {
            tool_installations::discover_npm_installations(&mut runner)
        } else {
            Vec::new()
        };
        let npm_root = npm_installations
            .iter()
            .find(|installation| installation.is_path_default)
            .and_then(|installation| installation.cache.clone());
        Self::precompute_with(
            rules,
            |rule| {
                if rule.root_kind == "npm_reported_cache" {
                    npm_root.clone()
                } else {
                    reported.get(&rule.id).cloned().flatten()
                }
            },
            npm_installations,
        )
    }

    /// Captures rule-derived locations using an invocation-local resolver snapshot.
    /// Missing answers remain unknown. This performs read-only marker/layout discovery.
    pub fn precompute_with(
        rules: &[PlatformJunkRule],
        mut resolve: impl FnMut(&PlatformJunkRule) -> Option<PathBuf>,
        npm_installations: Vec<tool_installations::ToolInstallation>,
    ) -> Self {
        let mut by_rule = BTreeMap::new();
        for rule in rules {
            let reported_root = resolve(rule);
            let cache_candidates =
                tool_cache_candidates_with_root(rule, reported_root.as_deref(), &npm_installations);
            by_rule.insert(
                rule.id.clone(),
                PlatformRuleEvidence {
                    cache_candidates,
                    reported_root,
                },
            );
        }
        Self {
            by_rule,
            npm_installations,
        }
    }

    /// Precomputed evidence for one rule, or `None` if the rule set this snapshot was built from
    /// did not include it (treated as "cannot classify").
    pub fn for_rule(&self, rule: &PlatformJunkRule) -> Option<&PlatformRuleEvidence> {
        self.by_rule.get(&rule.id)
    }
}

/// Shared classifier over admitted project/platform rules and this invocation's evidence.
///
/// It is handed to the scanner, which invokes it while the walk runs so non-candidate rows are
/// never buffered. Decisions are namespaced (`project:` / `platform:`) because the two sets
/// have separate id namespaces.
pub struct CombinedJunkClassifier<'a> {
    /// Validated project classifier.
    pub project: &'a JunkService,
    /// Admitted platform rules for this invocation.
    pub platform_rules: &'a [PlatformJunkRule],
    /// Precomputed tool evidence shared across all walk-time classifications.
    pub evidence: &'a PlatformJunkEvidence,
}

impl JunkClassifier for CombinedJunkClassifier<'_> {
    fn needs_file_marker(&self, name: &sweepx_model::NativeName) -> bool {
        self.project.needs_project_marker(name)
    }

    fn classify(
        &self,
        entry: &sweepx_model::ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        if entry.object_type != sweepx_model::ObjectType::Directory
            || entry.validated_native_locator().ok().flatten().is_none()
        {
            return None;
        }
        if let Some(decision) = self.project.classify(entry, markers) {
            return Some(decision);
        }
        let platform = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "unsupported"
        };
        // Specific, root-identifying rules win over generic catch-all rules when several
        // match one directory; ties keep file order. Measured: without this, the earlier
        // `macos.user-caches` (direct_children) shadowed `macos.homebrew-cache`/`yarn-cache`
        // and the directory lost its specific attribution.
        let mut best: Option<(u8, &PlatformJunkRule)> = None;
        for rule in self
            .platform_rules
            .iter()
            .filter(|rule| rule.platform == platform || rule.platform == "any")
        {
            if platform_rule_classifies(rule, entry, self.evidence) {
                let rank = platform_rule_specificity(rule);
                if best.is_none_or(|(best_rank, _)| rank < best_rank) {
                    best = Some((rank, rule));
                }
            }
        }
        best.map(|(_, rule)| format!("platform:{}", rule.id))
    }
}

/// Specificity rank of a platform rule's match kind; lower wins.
///
/// Rules that identify an exact root (tool-reported, known layout or declared known root) are
/// the most specific. `named_descendant` pins name and depth; `direct_children` is a generic
/// depth bucket that merely inherits everything underneath.
fn platform_rule_specificity(rule: &PlatformJunkRule) -> u8 {
    match rule.match_kind.as_str() {
        "verified_tool_root"
        | "verified_cache_root"
        | "verified_browser_cache"
        | "verified_known_root" => 0,
        "named_descendant" => 1,
        "direct_children" => 2,
        _ => 3,
    }
}

/// Whether a platform rule matches an observed directory, evaluated at walk time.
///
/// Depth is read from the entry's captured locator. The depth-zero match kinds behave exactly
/// as before: those directories are still their own scan roots except known roots, which may
/// legitimately be nested inside a wider root.
fn platform_rule_classifies(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let depth = locator.parent_reopen_recipe.len();
    match rule.match_kind.as_str() {
        "direct_children" => depth == rule.depth,
        "named_descendant" => {
            depth == rule.depth
                && native_name_for_rule(&entry.native_basename).is_some_and(|name| {
                    rule.names
                        .iter()
                        .any(|candidate| normalized_rule_name(candidate) == name)
                })
        }
        "verified_tool_root" => depth == 0 && tool_reported_root_matches(rule, entry, evidence),
        "verified_cache_root" => depth == 0 && render_cache_root_matches(rule, entry),
        "verified_browser_cache" => depth == 0 && browser_cache_root_matches(rule, entry),
        "verified_known_root" => known_macos_root_matches(rule, entry),
        #[cfg(target_os = "linux")]
        "stale_inactive_direct_child" => false,
        _ => false,
    }
}

/// Confirms a scanned root is the one this rule's tool reported.
///
/// Root discovery and candidate classification are separate passes, and the user may also name
/// roots explicitly, so a depth-0 directory is not automatically this rule's cache. Without
/// re-checking, scanning an unrelated directory would be labelled "npm cache".
///
/// The comparison uses the captured lossless native path, not `display_path`: display paths are
/// presentation data and are never execution or classification authority in this codebase. The
/// markers are then re-checked so a rule only reports a directory that still has the cache's
/// shape. This is report-only classification and grants no deletion authority; the scanner's
/// no-follow identity checks remain the authority over what was traversed.
fn tool_reported_root_matches(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> bool {
    classify_tool_root(rule, entry, evidence).is_some()
}

/// Whether a matched cache root is the one the tool is currently using.
///
/// These machine values describe the tool's reported configuration, not process liveness or
/// disposability. No value grants deletion authority or preselects a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRootActivity {
    /// The tool itself named this path.
    Live,
    /// A verified cache path differing from the tool's current answer; it may still be in use.
    Stale,
    /// A real cache of this tool, but the tool could not be asked which copy it uses.
    ///
    /// Distinct from `Stale` because absence of an answer is not evidence of abandonment. Measured:
    /// on this host `npm` is a `.ps1`/`.cmd` shim, and `Command::new("npm")` does not apply
    /// `PATHEXT`, so the resolver returns nothing and the *live* cache would otherwise be labelled
    /// stale — the exact false claim this whole mechanism exists to avoid.
    Unknown,
}

impl ToolRootActivity {
    /// Stable machine value; never localized.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

/// Decides whether a scanned root is one of this rule's caches, and whether it is live.
///
/// Compares against every candidate location rather than only the resolver's answer, because an
/// abandoned cache is never the one the resolver names. Comparison uses the captured lossless
/// native path, not `display_path`: display paths are presentation data and are never execution or
/// classification authority in this codebase.
pub fn classify_tool_root(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> Option<ToolRootActivity> {
    let locator = entry.native_locator.as_ref()?;
    // Without a captured native path there is nothing trustworthy to compare against, so the rule
    // declines rather than falling back to the display string.
    let captured = locator.scan_root_absolute_path.as_ref()?;
    // Must be one of the candidates discovery itself verified, which means its markers and
    // structural fingerprint were already checked against real bytes. Re-deriving the check from
    // `display_path` would be wrong twice over: display paths are not classification authority, and
    // the same directory reached through a differently-cased path would be judged a second time.
    //
    // Candidates and the live resolver are precomputed once (see `PlatformJunkEvidence`) rather
    // than launched here: doing this per walk entry was the source of the multi-minute stall.
    let rule_evidence = evidence.for_rule(rule)?;
    let matched = rule_evidence
        .cache_candidates
        .iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))?;
    // Liveness compares directory identity, not spelling. The resolver and an environment override
    // routinely name one directory with different casing, and comparing the resolver's raw string
    // against the deduplicated candidate reported that single cache as both stale and live at once.
    //
    // No answer means `Unknown`, never `Stale`: a tool that cannot be asked has not told us this
    // copy is abandoned, and claiming otherwise about a live cache is the worst outcome available.
    Some(match rule_evidence.reported_root {
        Some(ref reported) if same_directory(matched, reported) => ToolRootActivity::Live,
        Some(_) => ToolRootActivity::Stale,
        None => ToolRootActivity::Unknown,
    })
}

/// One Chromium-family browser installation whose caches SweepX knows how to find.
///
/// Listed explicitly rather than by scanning for anything resembling a browser: a directory named
/// `User Data` is not authority to treat its contents as disposable.
pub struct ChromiumInstall {
    /// Path below `%LOCALAPPDATA%`, `/`-separated so the platform separator is applied once, by
    /// `push`. Writing a `\`-containing literal produced a mixed-separator path that passed every
    /// local check yet never matched the native path the scanner captured.
    pub relative_user_data: &'static str,
}

/// The installations probed on Windows.
///
/// Measured on this host 2026-09-05: all three exist, and Edge Dev held the single largest
/// reclaimable directory (611.7 MB of code cache). Assuming one browser would have missed it.
pub const CHROMIUM_INSTALLS: &[ChromiumInstall] = &[
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge Dev/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Microsoft/Edge Beta/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome Beta/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Google/Chrome Dev/User Data",
    },
    ChromiumInstall {
        relative_user_data: "BraveSoftware/Brave-Browser/User Data",
    },
    ChromiumInstall {
        relative_user_data: "Vivaldi/User Data",
    },
];

/// Cache directories that live inside a profile, and so exist once per profile.
const PROFILE_RENDER_CACHES: &[&str] = &[
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "Media Cache",
];

/// Cache directories that live beside the profiles, shared by the whole installation.
///
/// Easy to miss: they are not under any profile, so a profile-only walk finds none of them. They
/// held about 40 MB across three installations here.
const INSTALL_RENDER_CACHES: &[&str] = &[
    "ShaderCache",
    "GrShaderCache",
    "GraphiteDawnCache",
    "GraphiteCache",
];

/// Every render-cache directory of every discovered Chromium installation.
///
/// Returns scan roots, not candidates: which rule claims each one is decided by that rule's marker,
/// because the three backends have three different layouts. Nothing is filtered on size here — an
/// empty blockfile cache still occupies its scaffolding, and hiding it would misreport the disk.
fn chromium_render_cache_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let Some(local_app_data) = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    else {
        return roots;
    };
    for install in CHROMIUM_INSTALLS {
        let mut user_data = local_app_data.clone();
        for component in install.relative_user_data.split('/') {
            user_data.push(component);
        }
        if !is_existing_real_directory(&user_data) {
            continue;
        }
        for name in INSTALL_RENDER_CACHES {
            let candidate = user_data.join(name);
            if is_existing_real_directory(&candidate) {
                roots.push(candidate);
            }
        }
        // Profiles are enumerated from disk. Their names are a user-facing product concept
        // (`Default`, `Profile 1`, …) and a hardcoded list would silently skip the rest.
        let Ok(entries) = std::fs::read_dir(&user_data) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name != "Default" && !name.starts_with("Profile ") {
                continue;
            }
            let profile = user_data.join(name);
            if !is_existing_real_directory(&profile) {
                continue;
            }
            for cache in PROFILE_RENDER_CACHES {
                let candidate = profile.join(cache);
                if is_existing_real_directory(&candidate) {
                    roots.push(candidate);
                }
            }
        }
    }
    roots
}

/// Whether this scan root is the cache the rule describes.
///
/// Discovery yields every render cache of every installation, so a root reaching this point is some
/// browser cache but not necessarily *this* rule's. The marker decides, and the three backends are
/// told apart by it: the HTTP cache keeps entries under `Cache_Data`, the code cache under `js`, and
/// the shader caches are blockfile roots holding `data_1`. An index file is not a usable
/// discriminator — measured 2026-09-05, two of the three carry none at the root.
fn render_cache_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    // Same rule as everywhere else in this file: the captured native path is authority, the display
    // path is presentation.
    let Some(captured) = locator.scan_root_absolute_path.as_ref() else {
        return false;
    };
    let Some(root) = chromium_render_cache_roots()
        .into_iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))
    else {
        return false;
    };
    rule.required_markers
        .iter()
        .all(|marker| root.join(marker).exists())
}

#[cfg(target_os = "macos")]
fn known_macos_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let Some(entry_path) = entry_native_absolute_path(locator) else {
        return false;
    };
    // Exact, full-length match against each declared known root. The components are taken from
    // the captured native chain, never from `display_path`, and an exact component count is
    // required so a directory *inside* a known root (for example a Homebrew download) is not
    // promoted.
    known_macos_roots(rule)
        .into_iter()
        .find(|root| entry_path.equals_path(root).unwrap_or(false))
        .is_some_and(|root| root_has_required_markers(&root, &rule.required_markers))
}

/// Reconstructs an entry's own absolute native path from its locator chain.
///
/// The locator stores only the scan root as an absolute path; intermediate and entry components
/// are retained natively. `parent_reopen_recipe` starts with a component duplicating the scan
/// root (the locator invariant), so it is skipped; every remaining intermediate basename and
/// the entry basename are appended byte-for-byte without normalization. This is what lets a
/// known root nested inside a wider scan root (Homebrew/Yarn under `~/Library/Caches`) be
/// classified at its real depth instead of only when it is a depth-0 root.
#[cfg(target_os = "macos")]
fn entry_native_absolute_path(
    locator: &sweepx_model::NativeLocatorEvidence,
) -> Option<sweepx_model::NativeAbsolutePath> {
    let sweepx_model::NativeAbsolutePath::UnixBytes(root) =
        locator.scan_root_absolute_path.as_ref()?
    else {
        return None;
    };
    let mut bytes = root.clone();
    let append = |bytes: &mut Vec<u8>, name: &sweepx_model::NativeName| {
        let sweepx_model::NativeName::UnixBytes(component) = name else {
            return false;
        };
        bytes.push(b'/');
        bytes.extend_from_slice(component);
        true
    };
    for component in locator.parent_reopen_recipe.iter().skip(1) {
        if !append(&mut bytes, &component.native_basename) {
            return None;
        }
    }
    if !append(&mut bytes, &locator.entry.native_basename) {
        return None;
    }
    Some(sweepx_model::NativeAbsolutePath::unix(bytes))
}

#[cfg(not(target_os = "macos"))]
fn known_macos_root_matches(_rule: &PlatformJunkRule, _entry: &sweepx_model::ScannedEntry) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn known_macos_roots(rule: &PlatformJunkRule) -> Vec<PathBuf> {
    let Some(home) = user_home_dir().filter(|home| home.is_absolute()) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for known in &rule.known_roots {
        // Only a home-relative anchor is currently defined. A literal absolute base is refused
        // rather than trusted, because rules must not encode one machine's layout.
        if known.base != "home" {
            continue;
        }
        let mut path: PathBuf = home.clone();
        for component in &known.components {
            path.push(component);
        }
        if is_existing_real_directory(&path)
            && !paths.iter().any(|existing| same_directory(existing, &path))
        {
            paths.push(path);
        }
    }
    paths
}

/// Resolves a browser-cache spec's anchor to an absolute base directory.
///
/// `application_support` is the macOS `~/Library/Application Support`, `local_app_data` is the
/// Windows `%LOCALAPPDATA%`, and `home` is the user home. An unknown or unresolvable anchor
/// yields `None` rather than a guessed path.
fn browser_base_dir(base: &str) -> Option<PathBuf> {
    let home = user_home_dir()?;
    match base {
        "home" => Some(home),
        "application_support" => Some(home.join("Library").join("Application Support")),
        "local_app_data" => std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute()),
        _ => None,
    }
}

/// Every derived cache directory a rule's browser specs expand to.
///
/// Walks each browser's shared caches beside the profiles and the profile caches inside every
/// `Default`/`Profile N` directory enumerated from disk, so no browser needs a code branch and no
/// profile name is assumed. Only existing real directories are returned and duplicates are folded
/// by filesystem identity, because two browsers (or an injected config) can resolve to one path.
fn browser_cache_roots(rule: &PlatformJunkRule) -> Vec<PathBuf> {
    browser_cache_roots_with_base(rule, browser_base_dir)
}

// Injecting the anchor makes layout tests independent of installed browsers and HOME changes.
fn browser_cache_roots_with_base(
    rule: &PlatformJunkRule,
    mut resolve_base: impl FnMut(&str) -> Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for spec in &rule.browser_caches {
        let Some(base) = resolve_base(&spec.base) else {
            continue;
        };
        let mut user_data = base;
        for component in &spec.user_data {
            user_data.push(component);
        }
        if !is_existing_real_directory(&user_data) {
            continue;
        }
        for name in &spec.shared_caches {
            let candidate = user_data.join(name);
            push_browser_root(&candidate, &mut roots);
        }
        // Non-derived state paths resolved relative to user-data, split on `/` so the platform
        // separator is applied consistently.
        for relative in &spec.shared_paths {
            let mut candidate = user_data.clone();
            for component in relative.split('/') {
                candidate.push(component);
            }
            push_browser_root(&candidate, &mut roots);
        }
        // Gather every directory that holds a profile/partition, then select its derived caches.
        let mut profile_dirs: Vec<PathBuf> = Vec::new();
        for name in &spec.profile_names {
            profile_dirs.push(user_data.join(name));
        }
        if spec.enumerate_named_profiles {
            // Read from disk: a fixed list would silently miss extra Default/Profile N entries.
            if let Ok(entries) = std::fs::read_dir(&user_data) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name();
                    if let Some(name) = file_name.to_str()
                        && (name == "Default" || name.starts_with("Profile "))
                    {
                        profile_dirs.push(entry.path());
                    }
                }
            }
        }
        for container in &spec.partition_containers {
            let dir = user_data.join(container);
            if let Ok(entries) = std::fs::read_dir(&dir) {
                // Every real-directory child is treated as a partition (UUIDs, hashes, …), so the
                // product's naming scheme does not need to be encoded.
                for entry in entries.flatten() {
                    profile_dirs.push(entry.path());
                }
            }
        }
        for profile in profile_dirs {
            if !is_existing_real_directory(&profile) {
                continue;
            }
            for cache in &spec.profile_caches {
                push_browser_root(&profile.join(cache), &mut roots);
            }
            // Profile-relative multi-component state paths.
            for relative in &spec.profile_paths {
                let mut candidate = profile.clone();
                for component in relative.split('/') {
                    candidate.push(component);
                }
                push_browser_root(&candidate, &mut roots);
            }
        }
    }
    roots
}

fn push_browser_root(candidate: &Path, roots: &mut Vec<PathBuf>) {
    if is_existing_real_directory(candidate)
        && !roots
            .iter()
            .any(|existing| same_directory(existing, candidate))
    {
        roots.push(candidate.to_path_buf());
    }
}

/// Whether a scanned root is one of the derived caches this rule's browser specs expand to.
///
/// Comparison uses the captured native path, never the display string: display paths are not
/// classification authority in this codebase. The directory's position inside a known browser
/// user-data tree, together with its derived-cache name, is the evidence; the marker-bearing
/// network caches elsewhere are a different rule.
fn browser_cache_root_matches(rule: &PlatformJunkRule, entry: &sweepx_model::ScannedEntry) -> bool {
    let Some(locator) = entry.native_locator.as_ref() else {
        return false;
    };
    let Some(captured) = locator.scan_root_absolute_path.as_ref() else {
        return false;
    };
    browser_cache_roots(rule)
        .iter()
        .any(|root| captured.equals_path(root).unwrap_or(false))
}

/// One invocation's discovery facts, shared by root selection and classification. Keeping this
/// scoped to the invocation avoids persistent tool-configuration caches with stale live roots.
#[derive(Default)]
pub struct PlatformJunkSetup {
    /// Admitted rules used by both root discovery and classification.
    pub rules: Vec<PlatformJunkRule>,
    /// Environment-dependent observations from this invocation only.
    pub evidence: PlatformJunkEvidence,
}

impl PlatformJunkSetup {
    /// Discovers the shipped platform roots and tool evidence once for this invocation.
    pub fn discover() -> Result<Self, String> {
        let rules = load_platform_junk_rules().map_err(|error| error.to_string())?;
        let evidence = PlatformJunkEvidence::precompute(&rules);
        Ok(Self { rules, evidence })
    }
}

/// Selects platform scan roots from this invocation's shared discovery evidence.
pub fn default_platform_junk_roots(platform: &PlatformJunkSetup) -> Vec<PathBuf> {
    let rules = &platform.rules;
    let mut roots = Vec::new();
    // Tool-reported roots come first because they are platform-independent. Every plausible
    // location is enumerated, not just the one the tool named: an abandoned cache at a documented
    // default is exactly what a resolver-only pass misses, and on this host it was the larger copy.
    // Each candidate is verified by markers and structural fingerprint before admission.
    for rule in rules {
        if tool_reported_root_for(&rule.root_kind).is_none() {
            continue;
        }
        for root in platform
            .evidence
            .for_rule(rule)
            .into_iter()
            .flat_map(|evidence| evidence.cache_candidates.iter().cloned())
        {
            // Identity, not spelling: two rules can name one directory, and a scan given the same
            // directory twice reports it twice.
            if !roots
                .iter()
                .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
            {
                roots.push(root);
            }
        }
    }
    // Browser derived caches are declared in rule data (one spec per browser) and expanded here,
    // so the same mechanism serves any platform whose spec anchor resolves.
    for rule in rules {
        for root in browser_cache_roots(rule) {
            if !roots
                .iter()
                .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
            {
                roots.push(root);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        // XDG_CACHE_HOME is valid only as an absolute path. Falling back to ~/.cache follows the
        // XDG Base Directory specification; data/config homes are intentionally excluded.
        if rules.iter().any(|rule| rule.platform == "linux")
            && let Some(cache) = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .or_else(|| {
                    user_home_dir()
                        .filter(|home| home.is_absolute())
                        .map(|home| home.join(".cache"))
                })
            && is_existing_real_directory(&cache)
        {
            roots.push(cache);
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Apple defines Library/Caches as discardable, but candidate classification remains
        // report-only and no broader Library/Application Support root is admitted here.
        if rules.iter().any(|rule| rule.platform == "macos") {
            if let Some(cache) = user_home_dir()
                .filter(|home| home.is_absolute())
                .map(|home| home.join("Library/Caches"))
                .filter(|cache| is_existing_real_directory(cache))
            {
                roots.push(cache);
            }
            for rule in rules.iter().filter(|rule| rule.platform == "macos") {
                for root in known_macos_roots(rule) {
                    if !roots.iter().any(|existing: &PathBuf| {
                        same_directory(existing.as_path(), root.as_path())
                    }) {
                        roots.push(root);
                    }
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // LocalCache is narrower than LocalAppData. SweepX does not classify an application's
        // LocalFolder or the whole LocalAppData tree as disposable.
        if rules.iter().any(|rule| rule.platform == "windows")
            && let Some(packages) = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join("Packages"))
            && is_existing_real_directory(&packages)
        {
            roots.push(packages);
        }
        // Browser render caches are separate roots, one per cache directory, because each is an
        // independent aggregate the user may keep or reclaim on its own. They are added only when a
        // rule asks for them, so an installation nobody has a rule for is never walked.
        if rules
            .iter()
            .any(|rule| rule.root_kind == "chromium_render_cache")
        {
            for root in chromium_render_cache_roots() {
                if !roots
                    .iter()
                    .any(|existing: &PathBuf| same_directory(existing.as_path(), root.as_path()))
                {
                    roots.push(root);
                }
            }
        }
    }
    roots
}

pub fn is_existing_real_directory(path: &Path) -> bool {
    // Root discovery is convenience only, but it still avoids following a symlink before the
    // platform scanner performs the authoritative no-follow admission and identity checks.
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// One tool-reported cache root, as the tool itself describes it.
///
/// Measured on Windows on 2026-09-01: for npm, pnpm, and pip the location reported by the tool
/// differed from the documented platform default *and both paths existed*.
///
/// The first reading of that measurement — that defaults must therefore not be shipped — was wrong,
/// and re-measuring on 2026-09-05 established the opposite. A resolver answers "which cache is
/// live", and the live one is precisely the one that must **not** be reclaimed. The abandoned copy
/// at the documented default is the junk, and on this host it was the larger of the two: a pnpm
/// store of 146.8 MB last written 2024-10-26, against 127.5 MB in the store actually in use. A
/// resolver-only rule cannot see it at all.
///
/// So discovery enumerates every plausible location and the resolver is retained for a different
/// purpose: to mark which candidate is live, as a guard rather than as the discovery mechanism.
pub struct ToolReportedRoot {
    /// Program to run. Resolved through the platform's normal executable search.
    program: &'static str,
    /// Arguments that make the tool print exactly one path on stdout.
    arguments: &'static [&'static str],
}

impl ToolReportedRoot {
    /// Returns the tool's own answer, or `None` when the tool is absent or unhelpful.
    ///
    /// A missing tool, a nonzero exit, empty output, or a relative path all yield `None`: this
    /// is discovery, so an unusable answer must drop the rule rather than fall back to a guess.
    /// Only the first line is used, because a tool may add warnings after it.
    pub fn resolve(&self, runner: &mut ProbeRunner) -> Option<PathBuf> {
        // On Windows many of these tools ship only as a `.cmd`/`.bat` shim, and `Command::new` does
        // not apply `PATHEXT`, so the bare name fails even though the shell finds it. Measured: npm
        // on this host is `npm.ps1` plus `npm.cmd`, and without this the live npm cache was reported
        // as abandoned. `.ps1` is deliberately not attempted: it is not directly executable and
        // running it would mean invoking a shell.
        #[cfg(target_os = "windows")]
        let spellings: Vec<String> = vec![
            format!("{}.cmd", self.program),
            format!("{}.bat", self.program),
            format!("{}.exe", self.program),
            self.program.to_string(),
        ];
        #[cfg(not(target_os = "windows"))]
        let spellings: Vec<String> = vec![self.program.to_string()];

        for spelling in spellings {
            let mut command = std::process::Command::new(&spelling);
            let Ok(output) = runner.run(command.args(self.arguments)) else {
                continue;
            };
            if !output.status.success() {
                continue;
            }
            let Ok(text) = String::from_utf8(output.stdout) else {
                continue;
            };
            let Some(line) = text.lines().next() else {
                continue;
            };
            let path = PathBuf::from(line.trim());
            // A relative path cannot be admitted as a scan root, and resolving one here against the
            // current directory would invent a location the tool never reported.
            if path.is_absolute() {
                return Some(path);
            }
        }
        None
    }
}

/// Where a tool's cache may sit besides the location the tool itself reports.
///
/// Each entry is an environment variable holding an absolute path, or a path relative to a known
/// base. Enumerating these is what finds an abandoned cache: the resolver only ever names the live
/// one, and a stale copy is indistinguishable from it by path shape.
struct CandidateSources {
    /// Environment variables that, when set to an absolute path, name the cache root directly.
    env_overrides: &'static [&'static str],
    /// Paths relative to `%LOCALAPPDATA%` (Windows) or `$HOME` (elsewhere).
    relative_defaults: &'static [&'static str],
    /// When set, a candidate from the list above is a *container* of versioned store directories,
    /// and each child matching this prefix is the actual root.
    ///
    /// Measured: `pnpm store path` reports `…\.pnpm-store\v3`, one level below the configured store
    /// directory. A default written without the version level therefore fails the marker check and
    /// silently yields no candidate — which is how the stale store was first missed. The version is
    /// discovered from the directory rather than hardcoded, because the same name (`v3`) is used by
    /// both a current pnpm and a store abandoned two years ago, so it cannot indicate freshness.
    versioned_child_prefix: Option<&'static str>,
}

/// Structural evidence that a directory really is the kind of cache a rule claims.
///
/// A path alone proves nothing, and two caches of the same tool at different locations look
/// identical from the outside. The fingerprint is read from the directory's own contents, so it
/// holds regardless of where the cache lives or which tool reported it.
struct StructuralFingerprint {
    /// Additional children that must exist directly under the root.
    required_children: &'static [&'static str],
    /// A child that must exist directly under the root, for example `files` for a pnpm store.
    required_child: &'static str,
    /// Optional shard layout: this many children of `required_child`, all directories whose names
    /// are lowercase two-digit hex. Measured on a real pnpm store: exactly 256 such shards.
    ///
    /// `None` skips the check for caches with no such layout.
    hex_shard_count: Option<usize>,
}

/// One generation of a cache format, used to spot a superseded layout inside a live root.
///
/// Measured on this host: pip's cache held `http` at 73.1 MB last written 2023-12-09 next to the
/// current `http-v2` at 0 MB. The old format was 99.9% of the bytes and no longer written to, and
/// no rule keyed to the root alone can distinguish the two.
struct FormatGeneration {
    /// Child directory holding this generation, for example `http` or `http-v2`.
    directory: &'static str,
    /// `true` when a current tool still writes this generation.
    current: bool,
}

/// Everything discovery knows about one tool's cache beyond the resolver.
struct ToolCacheProfile {
    sources: CandidateSources,
    fingerprint: StructuralFingerprint,
    /// Format generations within a single root, oldest first. Empty when the cache has only one.
    generations: &'static [FormatGeneration],
}

/// Maps a `rootKind` to the additional locations and content checks for that tool.
///
/// Returning `None` means the kind has no profile and only the resolver's answer is used, which
/// keeps a rule working before its profile is measured on a real host.
fn tool_cache_profile(root_kind: &str) -> Option<ToolCacheProfile> {
    match root_kind {
        "pnpm_reported_store" => Some(ToolCacheProfile {
            sources: CandidateSources {
                // `PNPM_HOME` names the install dir, not the store; the store honors this one.
                env_overrides: &["PNPM_STORE_DIR"],
                relative_defaults: &["pnpm/store", ".pnpm-store"],
                versioned_child_prefix: Some("v"),
            },
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "files",
                hex_shard_count: Some(256),
            },
            generations: &[],
        }),
        "pip_reported_cache" => Some(ToolCacheProfile {
            sources: CandidateSources {
                env_overrides: &["PIP_CACHE_DIR"],
                relative_defaults: &["pip/Cache", "pip/cache"],
                versioned_child_prefix: None,
            },
            // The root itself has no shard layout; the generations below carry the evidence.
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "",
                hex_shard_count: None,
            },
            generations: &[
                FormatGeneration {
                    directory: "http",
                    current: false,
                },
                FormatGeneration {
                    directory: "http-v2",
                    current: true,
                },
            ],
        }),
        "npm_reported_cache" => Some(ToolCacheProfile {
            sources: CandidateSources {
                env_overrides: &["NPM_CONFIG_CACHE"],
                relative_defaults: &["npm-cache"],
                versioned_child_prefix: None,
            },
            fingerprint: StructuralFingerprint {
                required_children: &[],
                required_child: "_cacache",
                hex_shard_count: None,
            },
            generations: &[],
        }),
        _ => None,
    }
}

/// Whether two paths name the same directory on this host.
///
/// Resolved through the filesystem rather than by comparing strings, because whether two spellings
/// are the same directory depends on the volume, not on the text. Falls back to an exact comparison
/// when canonicalization fails, which keeps a genuinely distinct path from being folded away on the
/// strength of a failed probe.
pub fn same_directory(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Confirms a directory's own contents match the cache layout the rule claims.
///
/// This is what lets a rule report a cache at a location no tool named. Every check is read-only
/// and uses `symlink_metadata`, so a symlink cannot impersonate the structure; the scanner's
/// no-follow admission remains the authority over what is actually traversed.
fn matches_structural_fingerprint(root: &Path, fingerprint: &StructuralFingerprint) -> bool {
    if fingerprint.required_child.is_empty() {
        return true;
    }
    if !root_has_named_children(root, fingerprint.required_children.iter().copied()) {
        return false;
    }
    let child = root.join(fingerprint.required_child);
    if !std::fs::symlink_metadata(&child).is_ok_and(|metadata| metadata.file_type().is_dir()) {
        return false;
    }
    let Some(expected) = fingerprint.hex_shard_count else {
        return true;
    };
    // Counting shards is bounded by the directory's own size and reads no file contents. A wrong
    // count means this is not the layout claimed, so the rule must decline rather than guess.
    let Ok(entries) = std::fs::read_dir(&child) else {
        return false;
    };
    let mut shards = 0usize;
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            return false;
        };
        if !metadata.is_dir() {
            return false;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if name.len() != 2
            || !name
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return false;
        }
        shards += 1;
        if shards > expected {
            return false;
        }
    }
    shards == expected
}

/// Every location this tool's cache might occupy, live or abandoned.
///
/// The resolver's answer comes first when available, then environment overrides, then documented
/// defaults. Each candidate must exist, be a real directory, and carry both the rule's markers and
/// the profile's structural fingerprint before it is admitted — otherwise a rule keyed to a default
/// would report whatever unrelated directory now sits there.
fn tool_cache_candidates_with_root(
    rule: &PlatformJunkRule,
    reported_root: Option<&Path>,
    installations: &[tool_installations::ToolInstallation],
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    // Deduplication asks the filesystem, not the string. `%LOCALAPPDATA%\pip\Cache` and
    // `…\pip\cache` are one directory on a case-insensitive volume and two on a case-sensitive one,
    // and the resolver may name the same directory with different casing again. Comparing spellings
    // reported that single cache three times. Case sensitivity is a property of the host and volume,
    // so the identity is probed rather than assumed either way.
    let push = |path: PathBuf, out: &mut Vec<PathBuf>| {
        if !path.is_absolute()
            || !is_existing_real_directory(&path)
            || !root_has_required_markers(&path, &rule.required_markers)
        {
            return;
        }
        let already = out.iter().any(|existing| same_directory(existing, &path));
        if !already {
            out.push(path);
        }
    };
    if let Some(reported) = reported_root {
        push(reported.to_path_buf(), &mut candidates);
    }
    let Some(profile) = tool_cache_profile(&rule.root_kind) else {
        return candidates;
    };
    for name in profile.sources.env_overrides {
        if let Some(value) = std::env::var_os(name) {
            push(PathBuf::from(value), &mut candidates);
        }
    }
    // npm is commonly installed several times (Homebrew plus one copy per Node version under
    // nvm/fnm/volta). The resolver above only asks whichever npm is first on PATH, so a cache a
    // non-default npm was explicitly configured to use would be missed. Ask every discovered
    // installation for its own cache; the marker/fingerprint checks below still verify each.
    if rule.root_kind == "npm_reported_cache" {
        for installation in installations {
            if let Some(cache) = &installation.cache {
                push(cache.clone(), &mut candidates);
            }
        }
    }
    // Defaults are relative to the platform's per-user cache base. On Windows that is
    // %LOCALAPPDATA%; elsewhere the home directory, where these tools use dotted names.
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        user_home_dir()
    };
    if let Some(base) = base.filter(|path| path.is_absolute()) {
        for relative in profile.sources.relative_defaults {
            // Join component by component so the result uses the platform separator throughout. A
            // literal "a/b" on Windows produces a mixed-separator path that passes every local
            // check here yet fails to line up with the scanner's captured native path, so the
            // candidate is discovered and then silently never classified.
            let mut path = base.clone();
            for component in relative.split('/') {
                path.push(component);
            }
            match profile.sources.versioned_child_prefix {
                // The default names a container of versioned stores; the roots are one level down.
                // Enumerated rather than guessed, and each is still verified below.
                Some(prefix) => {
                    if let Ok(entries) = std::fs::read_dir(&path) {
                        for entry in entries.flatten() {
                            if entry
                                .file_name()
                                .to_str()
                                .is_some_and(|name| name.starts_with(prefix))
                            {
                                push(entry.path(), &mut candidates);
                            }
                        }
                    }
                }
                None => push(path, &mut candidates),
            }
        }
    }
    candidates.retain(|path| matches_structural_fingerprint(path, &profile.fingerprint));
    candidates
}

/// Names the superseded cache-format directories present inside a matched root.
///
/// A cache root can be live while most of its bytes sit in a format no current tool writes. On this
/// host pip held `http` at 73.1 MB last written 2023-12-09 beside the current `http-v2` at 0 MB, so
/// a rule keyed only to the root would describe 99.9% inert bytes as an active cache.
///
/// Reported only when a current generation is also present. Without that evidence the tool is
/// simply an older version whose only format is the one on disk, and calling it superseded would be
/// wrong. Read-only, `symlink_metadata`, and a marker rather than deletion authority.
pub fn superseded_format_generations(
    rule: &PlatformJunkRule,
    entry: &sweepx_model::ScannedEntry,
    evidence: &PlatformJunkEvidence,
) -> Vec<String> {
    let Some(profile) = tool_cache_profile(&rule.root_kind) else {
        return Vec::new();
    };
    if profile.generations.is_empty() {
        return Vec::new();
    }
    // `NativeAbsolutePath` can only be compared, not converted back to a `PathBuf` — deliberately,
    // since a display string is not reopenable. So the root used for these reads is the verified
    // candidate that the captured path matches, never a string rebuilt from the report.
    let Some(captured) = entry
        .native_locator
        .as_ref()
        .and_then(|locator| locator.scan_root_absolute_path.as_ref())
    else {
        return Vec::new();
    };
    let rule_evidence = match evidence.for_rule(rule) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let Some(root) = rule_evidence
        .cache_candidates
        .iter()
        .find(|candidate| captured.equals_path(candidate).unwrap_or(false))
    else {
        return Vec::new();
    };
    let present = |generation: &FormatGeneration| {
        std::fs::symlink_metadata(root.join(generation.directory))
            .is_ok_and(|metadata| metadata.file_type().is_dir())
    };
    let has_current = profile
        .generations
        .iter()
        .any(|generation| generation.current && present(generation));
    if !has_current {
        return Vec::new();
    }
    profile
        .generations
        .iter()
        .filter(|generation| !generation.current && present(generation))
        .map(|generation| generation.directory.to_string())
        .collect()
}

/// Maps a `rootKind` to the tool that reports it.
///
/// Returning `None` means the kind is not tool-reported and is discovered from platform
/// conventions instead.
pub fn tool_reported_root_for(root_kind: &str) -> Option<ToolReportedRoot> {
    match root_kind {
        "npm_reported_cache" => Some(ToolReportedRoot {
            program: "npm",
            arguments: &["config", "get", "cache"],
        }),
        "pnpm_reported_store" => Some(ToolReportedRoot {
            program: "pnpm",
            arguments: &["store", "path"],
        }),
        "pip_reported_cache" => Some(ToolReportedRoot {
            program: "pip",
            arguments: &["cache", "dir"],
        }),
        _ => None,
    }
}

/// Confirms a directory has the shape the rule expects before it is reported.
///
/// Without this a rule would report whatever now occupies the path the tool named. The check is
/// read-only and uses `symlink_metadata` so a symlinked marker cannot stand in for a real child;
/// the scanner still performs the authoritative no-follow admission afterwards.
fn root_has_required_markers(root: &Path, markers: &[String]) -> bool {
    root_has_named_children_display(root, markers)
}

fn root_has_named_children<'a>(root: &Path, names: impl IntoIterator<Item = &'a str>) -> bool {
    names.into_iter().all(|marker| {
        std::fs::symlink_metadata(root.join(marker)).is_ok_and(|metadata| {
            let file_type = metadata.file_type();
            file_type.is_dir() || file_type.is_file()
        })
    })
}

fn root_has_named_children_display<'a>(
    root: &Path,
    names: impl IntoIterator<Item = &'a String>,
) -> bool {
    root_has_named_children(root, names.into_iter().map(String::as_str))
}

/// Resolves the current user home without deriving authority from a report path.
pub fn user_home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::super::candidate::junk_size_for;
    use super::*;
    use sweepx_model::{ByteValue, ReasonCode};

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn shared_service_classifies_and_interprets_native_facts_without_cli() {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let base = fixture.path().canonicalize().unwrap();
        #[cfg(windows)]
        let base = fixture.path().to_path_buf();
        let project_root = base.join("project");
        let target = project_root.join("target");
        let cache = base.join("pip-cache");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(
            project_root.join("Cargo.toml"),
            b"[package]\nname='fixture'\n",
        )
        .unwrap();
        std::fs::write(target.join("artifact"), b"123456789").unwrap();
        std::fs::create_dir_all(cache.join("wheels")).unwrap();
        std::fs::write(cache.join("wheels/payload"), b"12345").unwrap();
        let project = JunkService::built_in().unwrap();
        let rules = load_platform_junk_rules()
            .unwrap()
            .into_iter()
            .filter(|rule| rule.id == "tool.pip-cache")
            .collect::<Vec<_>>();
        let mut probes = 0;
        let evidence = PlatformJunkEvidence::precompute_with(
            &rules,
            |_| {
                probes += 1;
                Some(cache.clone())
            },
            Vec::new(),
        );
        let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
            &context,
            &crate::ScanRequest {
                roots: vec![project_root, cache.clone()],
                state_dir: None,
            },
            None,
            &project.with_platform(&rules, &evidence),
            None,
        )
        .unwrap();
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect::<BTreeMap<_, _>>();
        let mut candidates = BTreeMap::new();
        for entry in scan
            .scan
            .summary
            .roots
            .iter()
            .chain(&scan.scan.summary.entries)
        {
            let Some(id) = entry.identity.as_ref().map(|identity| &identity.entry_id) else {
                continue;
            };
            let Some(decision) = scan.decisions.get(id) else {
                continue;
            };
            let candidate = project
                .interpret(decision, entry, &aggregates, &rules, &evidence)
                .unwrap();
            assert_eq!(&candidate.entry_id, id);
            candidates.insert(candidate.rule_id.clone(), candidate);
        }
        assert_eq!(probes, 1);
        assert_eq!(
            candidates
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["rust.target", "tool.pip-cache"])
        );
        let generated = &candidates["rust.target"];
        let expected_logical = std::fs::read_dir(&target)
            .unwrap()
            .map(|entry| {
                let metadata = std::fs::symlink_metadata(entry.unwrap().path()).unwrap();
                assert!(metadata.is_file());
                metadata.len() as u128
            })
            .sum::<u128>();
        // macOS/Windows decline allocation here; the fallback must equal an ordinary stat oracle.
        if generated.size_is_logical {
            assert_eq!(
                generated.reclaimable,
                sweepx_platform::known_u128(expected_logical)
            );
        }
        assert_eq!(generated.classification.as_deref(), Some("known_generated"));
        assert_eq!(generated.confidence.as_deref(), Some("medium"));
        assert_eq!(
            candidates["tool.pip-cache"].activity.as_deref(),
            Some("live")
        );
        assert!(
            candidates
                .values()
                .all(|candidate| candidate.source_entry.is_some())
        );
        let entry = generated.source_entry.as_ref().unwrap();
        assert!(
            project
                .interpret("platform:unknown", entry, &aggregates, &rules, &evidence)
                .is_none()
        );
        for kind in [
            sweepx_model::ObjectType::File,
            sweepx_model::ObjectType::Symlink,
        ] {
            let mut invalid = entry.clone();
            invalid.object_type = kind;
            assert!(
                project
                    .with_platform(&rules, &evidence)
                    .classify(&invalid, &BTreeMap::new())
                    .is_none()
            );
            assert!(
                project
                    .interpret(
                        "project:rust.target",
                        &invalid,
                        &aggregates,
                        &rules,
                        &evidence
                    )
                    .is_none()
            );
        }
        let mut missing = entry.clone();
        missing.native_locator = None;
        assert!(
            project
                .with_platform(&rules, &evidence)
                .classify(&missing, &BTreeMap::new())
                .is_none()
        );
        assert!(
            project
                .interpret(
                    "project:rust.target",
                    &missing,
                    &aggregates,
                    &rules,
                    &evidence
                )
                .is_none()
        );
    }
    fn valid_verification_date(value: &str) -> bool {
        value.len() == 10
            && value.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 4 | 7) && byte == b'-'
                    || !matches!(index, 4 | 7) && byte.is_ascii_digit()
            })
    }
    #[test]
    fn system_root_selection_reuses_the_classifiers_tool_probe() {
        let fixture = tempfile::tempdir().unwrap();
        let cache = fixture.path().canonicalize().unwrap();
        std::fs::create_dir(cache.join("wheels")).unwrap();
        let rule = load_platform_junk_rules()
            .unwrap()
            .into_iter()
            .find(|rule| rule.root_kind == "pip_reported_cache")
            .unwrap();
        let rules = vec![rule];
        let mut probes = 0;
        let evidence = PlatformJunkEvidence::precompute_with(
            &rules,
            |_| {
                probes += 1;
                Some(cache.clone())
            },
            Vec::new(),
        );
        let platform = PlatformJunkSetup { rules, evidence };
        let roots = default_platform_junk_roots(&platform);
        assert_eq!(probes, 1);
        // This synthetic resolver root cannot be discovered by the host's actual pip. If root
        // discovery probes again instead of using the snapshot, it will omit this directory.
        assert!(roots.contains(&cache));
        let observed = platform.evidence.for_rule(&platform.rules[0]).unwrap();
        assert_eq!(observed.reported_root.as_ref(), Some(&cache));
        assert!(observed.cache_candidates.contains(&cache));
    }

    #[test]
    fn embedded_platform_junk_rules_are_narrow_and_evidence_bearing() {
        let rules = load_platform_junk_rules().unwrap();
        assert_eq!(rules.len(), 26);
        assert!(rules.iter().all(|rule| !rule.references.is_empty()));
        assert!(
            rules
                .iter()
                .all(|rule| valid_verification_date(&rule.source_reviewed_at))
        );
        let linux = rules
            .iter()
            .find(|rule| rule.id == "linux.xdg-user-cache")
            .unwrap();
        assert_eq!(linux.root_kind, "xdg_cache_home");
        assert_eq!(linux.match_kind, "direct_children");
        let linux_tmp = rules
            .iter()
            .find(|rule| rule.id == "linux.stale-temp-object")
            .unwrap();
        assert_eq!(linux_tmp.root_kind, "linux_tmp");
        assert_eq!(linux_tmp.match_kind, "stale_inactive_direct_child");
        assert_eq!(linux_tmp.risk, "R3");
        // Found by id, not by platform: Windows now carries browser cache rules too, and matching
        // on the platform alone silently returned whichever rule happened to be first.
        let macos_rules: Vec<_> = rules
            .iter()
            .filter(|rule| rule.platform == "macos")
            .collect();
        assert_eq!(macos_rules.len(), 17);
        let integrated_macos_ids = [
            "macos.xcode-derived-data",
            "macos.cargo-registry-cache",
            "macos.firefox-cache",
            "macos.chromium-cache",
            "macos.safari-cache",
            "macos.tencent-meeting-cache",
            "macos.homebrew-cache",
            "macos.go-cache",
            "macos.uv-cache",
            "macos.bun-cache",
            "macos.yarn-cache",
            "macos.gradle-cache",
            "macos.jetbrains-cache",
            "macos.deno-cache",
            "macos.browser-derived-cache",
        ];
        for id in integrated_macos_ids {
            assert!(rules.iter().any(|rule| rule.id == id), "missing {id}");
        }
        // Location knowledge must live in the rule data, not in code matched on rule id. Every
        // verified_known_root rule therefore declares at least one home-relative root, and no
        // other kind does.
        for rule in &rules {
            if rule.match_kind == "verified_known_root" {
                assert!(
                    !rule.known_roots.is_empty(),
                    "rule {} declares no known roots",
                    rule.id
                );
                assert!(
                    rule.known_roots
                        .iter()
                        .all(|known| known.base == "home" && !known.components.is_empty()),
                    "rule {} uses an unsupported known-root anchor",
                    rule.id
                );
            } else {
                assert!(
                    rule.known_roots.is_empty(),
                    "rule {} must not declare known roots",
                    rule.id
                );
            }
        }

        let windows = rules
            .iter()
            .find(|rule| rule.id == "windows.packaged-app-cache")
            .unwrap();
        assert_eq!(windows.names, ["LocalCache", "TempState"]);
        assert_eq!(windows.depth, 2);

        // The derived browser rule must describe several browsers purely in data, and no spec
        // may name durable profile storage.
        let derived = rules
            .iter()
            .find(|rule| rule.id == "macos.browser-derived-cache")
            .unwrap();
        assert_eq!(derived.match_kind, "verified_browser_cache");
        assert!(derived.browser_caches.len() >= 5);
        let forbidden = [
            "Cookies",
            "History",
            "Login Data",
            "Bookmarks",
            "Local Storage",
            "IndexedDB",
        ];
        for spec in &derived.browser_caches {
            assert!(spec.base == "application_support");
            assert!(!spec.user_data.is_empty());
            assert!(!spec.shared_caches.is_empty() || !spec.profile_caches.is_empty());
            for name in spec.shared_caches.iter().chain(spec.profile_caches.iter()) {
                assert!(
                    !forbidden.contains(&name.as_str()),
                    "rule selects durable {name}"
                );
            }
        }
        // On this host Postman and LarkShell are installed. Expansion must reach Postman's UUID
        // partitions through the container and LarkShell's IronDefault/profile tree, proving the
        // non-Default discovery forms work rather than only the Default/Profile convention.
        let mut expanded: Vec<String> = browser_cache_roots(derived)
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let home = user_home_dir().unwrap();
        let postman_partitions = home.join("Library/Application Support/Postman/Partitions");
        let mut found_partition_cache = 0;
        if is_existing_real_directory(&postman_partitions) {
            for entry in std::fs::read_dir(&postman_partitions).unwrap().flatten() {
                if entry.path().join("Cache").is_dir() {
                    found_partition_cache += 1;
                }
            }
        }
        for path in &expanded {
            assert!(!path.contains("/Cookies"));
        }
        let counted = expanded
            .iter()
            .filter(|path| path.contains("/Postman/Partitions/") && path.ends_with("/Cache"))
            .count();
        assert_eq!(counted, found_partition_cache);
        let lark_shared = home.join("Library/Application Support/LarkShell/GrShaderCache");
        if is_existing_real_directory(&lark_shared) {
            assert!(
                expanded
                    .iter()
                    .any(|path| path == lark_shared.to_str().unwrap())
            );
        }
        expanded.sort();
        let before = expanded.len();
        expanded.dedup();
        assert_eq!(
            before,
            expanded.len(),
            "expanded roots must be deduplicated"
        );
    }

    #[test]
    fn browser_state_rule_reports_offline_state_and_diagnostics_at_r3() {
        let rules = load_platform_junk_rules().unwrap();
        let state = rules
            .iter()
            .find(|rule| rule.id == "macos.browser-state-diagnostics")
            .unwrap();
        assert_eq!(state.root_kind, "macos_browser_state");
        assert_eq!(state.match_kind, "verified_browser_cache");
        assert_eq!(state.risk, "R3");
        // Every expanded path must exist and be one of the documented state/diagnostic kinds;
        // durable browsing data is still excluded.
        let forbidden = [
            "Cookies",
            "History",
            "Login Data",
            "Bookmarks",
            "Local Storage",
            "IndexedDB",
        ];
        let fixture = tempfile::tempdir().unwrap();
        let base = fixture.path().to_path_buf();
        let must_exist = [
            base.join("Google/Chrome/Default/Service Worker/CacheStorage"),
            base.join("Microsoft Edge/Default/Service Worker/CacheStorage"),
            base.join("Postman/logs"),
        ];
        for path in &must_exist {
            std::fs::create_dir_all(path).unwrap();
        }
        // Persistent profile data is present too; the rule must still return exactly the chosen state.
        for name in forbidden {
            std::fs::create_dir_all(base.join("Google/Chrome/Default").join(name)).unwrap();
        }
        let expanded = browser_cache_roots_with_base(state, |anchor| {
            (anchor == "application_support").then(|| base.clone())
        });
        assert_eq!(
            expanded.iter().cloned().collect::<BTreeSet<_>>(),
            must_exist.iter().cloned().collect::<BTreeSet<_>>()
        );
        for path in &expanded {
            assert!(path.is_dir(), "reports a missing path {path:?}");
            let rendered = path.to_string_lossy();
            for name in forbidden {
                assert!(
                    !rendered.contains(&format!("/{name}")),
                    "state rule selects durable {name}"
                );
            }
        }
        for expected in must_exist {
            assert!(
                expanded.iter().any(|path| same_directory(path, &expected)),
                "missing {expected:?}"
            );
        }
    }

    /// Every tool-reported rule must be resolvable and structurally guarded.
    ///
    /// Measured on Windows on 2026-09-01: npm, pnpm, and pip each reported a cache location that
    /// differed from the documented platform default while *both* paths existed. A rule that
    /// hardcoded the default would have reported a stale cache and missed the live one. So each
    /// such rule must name a root kind the discovery table can resolve, and must carry at least
    /// one marker so the tool's answer is verified rather than trusted outright.
    #[test]
    fn tool_reported_rules_are_resolvable_and_marker_guarded() {
        let rules = load_platform_junk_rules().unwrap();
        let tool_rules: Vec<_> = rules
            .iter()
            .filter(|rule| rule.match_kind == "verified_tool_root")
            .collect();

        assert_eq!(tool_rules.len(), 3, "expected the npm, pnpm, and pip rules");
        for rule in tool_rules {
            assert!(
                tool_reported_root_for(&rule.root_kind).is_some(),
                "rule {} names a root kind nothing can resolve, so it would never be produced",
                rule.id
            );
            assert!(
                !rule.required_markers.is_empty(),
                "rule {} would report whatever now occupies the reported path",
                rule.id
            );
            // The reported directory is itself the candidate, so it must not also try to match
            // child names.
            assert_eq!(rule.depth, 0, "rule {} must match the root itself", rule.id);
            assert!(rule.names.is_empty());
            assert_eq!(rule.platform, "any");
        }
    }

    /// A rule naming an unresolvable tool root must be rejected outright.
    ///
    /// Such a rule would silently never produce a candidate, which looks like "nothing to clean"
    /// rather than like a broken rule.
    #[test]
    fn a_tool_rule_with_an_unknown_root_kind_is_refused() {
        assert!(tool_reported_root_for("npm_reported_cache").is_some());
        assert!(tool_reported_root_for("definitely_not_a_known_tool").is_none());
    }

    /// Markers must be verified against the real filesystem, not assumed.
    #[test]
    fn required_markers_are_checked_against_the_filesystem() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();

        // No markers yet: the directory must not qualify.
        assert!(!root_has_required_markers(root, &["_cacache".to_string()]));
        // An empty marker list is vacuously satisfied, which is why the validator forbids it
        // for tool-reported rules.
        assert!(root_has_required_markers(root, &[]));

        std::fs::create_dir(root.join("_cacache")).unwrap();
        assert!(root_has_required_markers(root, &["_cacache".to_string()]));
        // Every marker must be present, not merely one of them.
        assert!(!root_has_required_markers(
            root,
            &["_cacache".to_string(), "index-v5".to_string()]
        ));
    }

    /// Every tool profile must be self-consistent and usable by discovery.
    ///
    /// A profile whose fingerprint or defaults are wrong fails silently: the candidate is simply
    /// never produced, which is exactly how the stale pnpm store was missed on the first attempt.
    #[test]
    fn tool_cache_profiles_are_well_formed() {
        let rules = load_platform_junk_rules().expect("rules must load");
        for rule in rules
            .iter()
            .filter(|rule| rule.match_kind == "verified_tool_root")
        {
            let Some(profile) = tool_cache_profile(&rule.root_kind) else {
                continue;
            };
            assert!(
                !profile.sources.relative_defaults.is_empty()
                    || !profile.sources.env_overrides.is_empty(),
                "{} has a profile that adds no candidate location",
                rule.id
            );
            for relative in profile.sources.relative_defaults {
                assert!(
                    !relative.starts_with('/') && !relative.contains('\\'),
                    "{}: relative default {relative:?} must be '/'-separated and relative",
                    rule.id
                );
            }
            // A generation list is only meaningful if it can distinguish old from current.
            if !profile.generations.is_empty() {
                assert!(
                    profile.generations.iter().any(|g| g.current),
                    "{} lists format generations but none is current",
                    rule.id
                );
                assert!(
                    profile.generations.iter().any(|g| !g.current),
                    "{} lists format generations but none is superseded",
                    rule.id
                );
            }
        }
    }

    /// The structural fingerprint accepts a real store layout and rejects a lookalike.
    ///
    /// Pins the measured shape of a pnpm store: `files/` holding exactly 256 two-hex-digit shard
    /// directories. The count is asserted against the number actually observed on disk rather than
    /// against the constant it is meant to protect, so a change to either side is caught.
    #[test]
    fn the_store_fingerprint_needs_the_measured_shard_layout() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join("store");
        let files = root.join("files");
        std::fs::create_dir_all(&files).expect("create files");
        let fingerprint = StructuralFingerprint {
            required_children: &[],
            required_child: "files",
            hex_shard_count: Some(256),
        };

        // Empty: the child exists but the layout does not match.
        assert!(!matches_structural_fingerprint(&root, &fingerprint));

        for shard in 0..256u32 {
            std::fs::create_dir(files.join(format!("{shard:02x}"))).expect("create shard");
        }
        assert!(
            matches_structural_fingerprint(&root, &fingerprint),
            "256 lowercase two-hex-digit shards is the layout measured on a real pnpm store"
        );

        // One extra child breaks it: a directory that merely contains hex-named folders is not a
        // store, and admitting it would let the rule name an unrelated tree a pnpm store.
        std::fs::create_dir(files.join("zz")).expect("create intruder");
        assert!(!matches_structural_fingerprint(&root, &fingerprint));

        // A missing required child is refused even when nothing else is wrong.
        let bare = temp.path().join("bare");
        std::fs::create_dir(&bare).expect("create bare");
        assert!(!matches_structural_fingerprint(&bare, &fingerprint));
    }

    /// A fingerprint with no required child imposes no structural condition.
    ///
    /// pip's root has no shard layout; its evidence is the format generations instead. The empty
    /// marker must therefore pass rather than reject everything.
    #[test]
    fn an_empty_fingerprint_accepts_any_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let fingerprint = StructuralFingerprint {
            required_children: &[],
            required_child: "",
            hex_shard_count: None,
        };
        assert!(matches_structural_fingerprint(temp.path(), &fingerprint));
    }

    /// Activity codes are distinct, stable and machine-safe.
    ///
    /// `unknown` exists because a resolver that cannot run is not evidence of abandonment: npm on
    /// this host is a `.cmd`/`.ps1` shim, and treating "no answer" as `stale` labelled the live
    /// cache as junk.
    #[test]
    fn activity_codes_are_distinct_and_machine_safe() {
        let all = [
            ToolRootActivity::Live,
            ToolRootActivity::Stale,
            ToolRootActivity::Unknown,
        ];
        let mut codes: Vec<&str> = all.iter().map(|activity| activity.code()).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "activity codes must be distinct");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase())),
            "codes must stay lowercase ASCII for machine consumers"
        );
    }

    /// Two spellings of one directory are the same directory; two real directories are not.
    ///
    /// Case sensitivity is a property of the host and volume, so the behavior is probed rather than
    /// assumed. Comparing spellings reported a single pip cache three times.
    #[test]
    fn directory_identity_is_resolved_not_string_compared() {
        let temp = tempfile::tempdir().expect("temp dir");
        let one = temp.path().join("Cache");
        std::fs::create_dir(&one).expect("create dir");
        let other = temp.path().join("other");
        std::fs::create_dir(&other).expect("create other");

        assert!(same_directory(&one, &one));
        assert!(
            !same_directory(&one, &other),
            "genuinely different directories must never be folded together"
        );

        // Whether the folded spelling is the same directory depends on the volume. Assert whichever
        // invariant this host actually exhibits instead of hardcoding either expectation.
        let folded = temp.path().join("cache");
        if folded.exists() {
            assert!(
                same_directory(&one, &folded),
                "a case-insensitive volume resolves both spellings to one directory"
            );
        } else {
            assert!(
                !same_directory(&one, &folded),
                "a case-sensitive volume must not treat the folded spelling as the same directory"
            );
        }
    }

    #[test]
    fn render_cache_rules_are_marker_guarded() {
        let rules = load_platform_junk_rules().expect("rules must load");
        let render: Vec<_> = rules
            .iter()
            .filter(|rule| rule.root_kind == "chromium_render_cache")
            .collect();
        assert!(
            !render.is_empty(),
            "the browser cache rules must survive in the shipped catalog"
        );
        for rule in render {
            assert_eq!(rule.match_kind, "verified_cache_root");
            assert_eq!(rule.depth, 0);
            assert_eq!(
                rule.risk, "R2",
                "{}: render caches are rebuildable",
                rule.id
            );
            assert!(
                rule.names.is_empty(),
                "{}: the root itself matches",
                rule.id
            );
            // Without a marker the rule would claim whatever now sits at that path.
            assert!(
                !rule.required_markers.is_empty(),
                "{}: a cache root must prove it is a cache",
                rule.id
            );
        }
        // The markers must tell the three backends apart. If two rules shared a marker set they
        // would both claim the same directory, and the same cache would be reported twice.
        let mut marker_sets: Vec<&Vec<String>> = render_cache_marker_sets(&rules);
        let total = marker_sets.len();
        marker_sets.sort();
        marker_sets.dedup();
        assert_eq!(
            marker_sets.len(),
            total,
            "two render cache rules share a marker set and would both claim one directory"
        );
    }

    /// A minimal aggregate carrying just the two byte fields `junk_size_for` reads.
    ///
    /// The remaining fields are filled with complete, exact values so they cannot influence the
    /// outcome: the test is about which of the two sizes is chosen, nothing else.
    fn aggregate_with(
        reclaimable: ByteValue,
        apparent: ByteValue,
    ) -> sweepx_model::DirectoryAggregate {
        sweepx_model::DirectoryAggregate {
            scan_id: sweepx_model::ScanId::new("scan-size-fallback".to_string()),
            directory_identity: "scan-entry:v1:dGVzdA:1".to_string(),
            revision: sweepx_model::DecimalU128::new(1),
            apparent_logical_bytes: apparent,
            unique_logical_bytes: ByteValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            filesystem_reported_allocated_bytes: ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            potentially_reclaimable_bytes: reclaimable,
            direct_child_count: sweepx_model::CountValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            recursive_entry_count: sweepx_model::CountValue::Known {
                value: sweepx_model::DecimalU128::new(0),
            },
            coverage: sweepx_model::Coverage {
                state: sweepx_model::CoverageState::Complete,
                complete: true,
                incomplete_reasons: Vec::new(),
                details_lost: false,
                provenance: sweepx_model::FieldProvenance::LiveObservation {
                    observed_at: "2026-09-05T00:00:00Z".to_string(),
                    method: sweepx_model::MethodId::NativeApi,
                },
            },
            arithmetic_state: sweepx_model::ArithmeticState::Exact,
        }
    }

    fn render_cache_marker_sets(rules: &[PlatformJunkRule]) -> Vec<&Vec<String>> {
        rules
            .iter()
            .filter(|rule| rule.root_kind == "chromium_render_cache")
            .map(|rule| &rule.required_markers)
            .collect()
    }

    /// Discovery must not invent roots, and must produce only real directories.
    ///
    /// Deliberately tolerant about *which* browsers exist: that is a property of the host. What is
    /// asserted is that whatever comes back is a real directory reachable below LOCALAPPDATA.
    #[test]
    fn render_cache_discovery_yields_only_real_directories() {
        for root in chromium_render_cache_roots() {
            assert!(
                root.is_absolute(),
                "{root:?} must be absolute to be a scan root"
            );
            assert!(
                is_existing_real_directory(&root),
                "{root:?} was reported but is not a directory"
            );
            // A mixed-separator path passes local checks yet never matches the native path the
            // scanner captures, so the candidate is found and then silently never classified.
            if cfg!(windows) {
                assert!(
                    !root.to_string_lossy().contains('/'),
                    "{root:?} mixes separators and would never match a captured native path"
                );
            }
        }
    }

    /// Discovery must not report one directory twice.
    #[test]
    fn render_cache_discovery_does_not_repeat_a_directory() {
        let roots = chromium_render_cache_roots();
        for (index, root) in roots.iter().enumerate() {
            for other in &roots[index + 1..] {
                assert!(
                    !same_directory(root, other),
                    "{root:?} and {other:?} are the same directory reported twice"
                );
            }
        }
    }

    /// An exactly known allocation is preferred; logical size stands in when it is not available.
    ///
    /// This is the difference between reporting 1.8 GB of browser caches and reporting nothing:
    /// Windows declines to claim allocation because `FILE_STANDARD_INFO` covers only the unnamed
    /// stream, and measured 2026-09-05 that left 30 of 30 candidates sizeless.
    #[test]
    fn a_missing_allocation_falls_back_to_logical_size_and_says_so() {
        let exact = junk_size_for(Some(&aggregate_with(
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(64),
            },
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99),
            },
        )));
        assert!(
            !exact.is_logical_fallback,
            "a known allocation must be used as-is"
        );
        assert_eq!(
            exact.value,
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(64)
            }
        );

        let fell_back = junk_size_for(Some(&aggregate_with(
            ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99),
            },
        )));
        assert!(
            fell_back.is_logical_fallback,
            "the substitution must be visible to the caller, not silent"
        );
        assert_eq!(
            fell_back.value,
            ByteValue::Known {
                value: sweepx_model::DecimalU128::new(99)
            }
        );

        // Neither exact: keep the allocation evidence, whose reason explains the absence. Swapping
        // in an equally inexact logical value would discard that explanation for nothing.
        let neither = junk_size_for(Some(&aggregate_with(
            ByteValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            ByteValue::LowerBound {
                value: sweepx_model::DecimalU128::new(5),
                reason: ReasonCode::IncompleteStreamCoverage,
            },
        )));
        assert!(!neither.is_logical_fallback);
        assert!(matches!(neither.value, ByteValue::Unknown { .. }));

        // No aggregate at all is not a size of zero.
        let missing = junk_size_for(None);
        assert!(!missing.is_logical_fallback);
        assert!(matches!(missing.value, ByteValue::NotChecked { .. }));
    }
}
