//! Managed caches are independent inventories, never blanket junk classification.
//! pnpm links are time-local file facts; project/version matches are bounded usage hints.
mod msgpack;
mod native;
mod osdk;
mod pnpm;
mod projects;
#[cfg(test)]
mod tests;
use native::Native;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;
use sweepx_model::{ByteValue, EvidenceValue, ReasonCode, ScannedEntry};
use sweepx_platform::CancellationToken;
/// One observed project. Logical totals include dependencies/build outputs; allocation is unknown.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    /// Display-only project directory.
    pub directory: String,
    /// Whole-project apparent logical total, with explicit incomplete evidence.
    pub logical_bytes: ByteValue,
    /// Whether the total's native traversal completed.
    pub size_complete: bool,
    /// Store directory declared by the installed pnpm layout, when available.
    pub store_dir: Option<String>,
    #[serde(skip)]
    packages: BTreeSet<(String, String)>,
    #[serde(skip)]
    models: BTreeSet<String>,
}
/// Explicit action for an inventory item; names and sizes never grant execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Move selected exclusive, single-link CAS files to OS Trash; shared files stay.
    PnpmContent,
    /// Move a selected download-cache directory to OS Trash.
    TrashDirectory,
    /// Tool-managed local model removal; preserves project declarations and lock files.
    OsdkModelRemove,
}
/// One package version, model alias, or download-cache unit.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    /// Invocation selection token bound to the native root and index identity.
    pub id: String,
    /// Stable classification rule ID, distinct from cleanup eligibility.
    pub rule_id: String,
    /// Package name or model/cache label.
    pub name: String,
    /// Package version or immutable model revision when known.
    pub version: Option<String>,
    /// Display-only location, never reopening authority.
    pub path: String,
    /// Observed lengths per unique index content key; keys do not prove native object uniqueness.
    /// Different items can share these bytes.
    pub logical_bytes: ByteValue,
    /// File-system-reported allocation; APFS clones and external links still prevent a free-space claim.
    pub allocated_bytes: ByteValue,
    /// Unique indexed pnpm content keys, including verified absent files, or current model manifest files.
    pub files: usize,
    /// Lowest observed native link count; unknown if any selected file lacks a count.
    pub min_links: Option<u128>,
    /// Highest observed native link count; unknown if any selected file lacks a count.
    pub max_links: Option<u128>,
    /// Count of observed content files with exactly one native hard link.
    pub single_link_files: usize,
    /// Indexed content absent from a complete current CAS enumeration. Refusal makes the inventory partial.
    pub missing_files: usize,
    /// Indices into the report's observed project list. Empty means not observed in this scope.
    pub projects: Vec<usize>,
    /// Cleanup contract for this unit.
    pub action: Action,
    /// Current report eligibility; execution still needs a fresh plan and revalidation.
    pub eligible: bool,
    /// Evidence gaps or reasons selected content must stay.
    pub issues: Vec<String>,
    #[serde(skip)]
    pub(crate) source: Option<ScannedEntry>,
    #[serde(skip)]
    content: Vec<String>,
    #[serde(skip)]
    snapshot_digest: Option<String>,
}
/// Completed or partial invocation. Coverage is scoped, never a global unused-package proof.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inventory {
    /// Managed tool name.
    pub tool: String,
    /// SHA-256 of the admitted platform rule bytes; selection IDs bind this interpretation.
    pub rules_digest: String,
    /// Display-only admitted root.
    pub root: String,
    /// Whether index/content/project discovery completed within the declared bounds.
    pub complete: bool,
    /// Native observation wall-clock budget; checked between calls. One total has a separate 60s bound.
    pub time_budget_seconds: u64,
    /// Complete package index coverage; partial indexes prohibit content removal.
    pub index_complete: bool,
    /// Explicit search roots for observed installed-project references.
    pub project_roots: Vec<String>,
    /// Named child trees skipped by project discovery; an explicit root can inspect one.
    pub project_excluded_names: Vec<String>,
    /// Whether project discovery completed within these roots.
    pub project_discovery_complete: bool,
    /// Project totals and tool-declared store references.
    pub projects: Vec<Project>,
    /// Individually selectable units.
    pub entries: Vec<Item>,
    /// Non-fatal coverage or format limitations.
    pub issues: Vec<String>,
    #[serde(skip)]
    root_entry: Option<ScannedEntry>,
    #[serde(skip)]
    project_inputs: Vec<PathBuf>,
    #[serde(skip)]
    absent_cas: BTreeSet<String>,
}
impl Inventory {
    fn empty(tool: &str, root: &Path, projects: &[PathBuf]) -> Self {
        Self {
            tool: tool.into(),
            rules_digest: rules_digest(),
            root: root.display().to_string(),
            complete: false,
            time_budget_seconds: 900,
            index_complete: false,
            project_roots: projects.iter().map(|p| p.display().to_string()).collect(),
            project_excluded_names: projects::EXCLUSIONS.iter().map(|s| (*s).into()).collect(),
            project_discovery_complete: false,
            projects: Vec::new(),
            entries: Vec::new(),
            issues: Vec::new(),
            root_entry: None,
            project_inputs: projects.to_vec(),
            absent_cas: BTreeSet::new(),
        }
    }
    /// Current native root behind this inventory; display paths cannot supply it.
    pub fn source_root(&self) -> Option<&ScannedEntry> {
        self.root_entry.as_ref()
    }
    /// Revalidate the captured directory and derive its lossless native path for a tool operation.
    /// This accepts an inventory root; the Trash adapter deliberately refuses scan-root entries.
    /// A display-only replacement path cannot change the returned operation target.
    pub fn revalidated_root_path(&self, cancel: &CancellationToken) -> Result<PathBuf, String> {
        let root = self.root_entry.as_ref().ok_or("missing_root_identity")?;
        crate::storage_inventory::revalidate_directory(root, cancel)?;
        native::path(root)
    }
}
/// Inventory pnpm v3/v10 JSON indexes or v11 SQLite/msgpackr indexes and bounded installed projects.
pub fn pnpm_inventory(
    root: &Path,
    project_roots: &[PathBuf],
    cancel: &CancellationToken,
) -> Inventory {
    if project_roots.len() > 32 {
        let mut report = Inventory::empty("pnpm", root, &project_roots[..32]);
        report.issues.push("project_root_budget_exceeded".into());
        return report;
    }
    pnpm::inventory(root, project_roots, cancel)
}
/// Inventory osdk model aliases/snapshots and independently selectable download cache units.
pub fn osdk_inventory(
    data: &Path,
    cache: &Path,
    project_roots: &[PathBuf],
    cancel: &CancellationToken,
) -> Inventory {
    if project_roots.len() > 32 {
        let mut report = Inventory::empty("osdk", data, &project_roots[..32]);
        report.issues.push("project_root_budget_exceeded".into());
        return report;
    }
    osdk::inventory(data, cache, project_roots, cancel)
}
/// Build a current native, bounded plan for selected pnpm content. Indexes remain in the store;
/// pnpm detects missing content and refetches it on future installations.
pub fn pnpm_cleanup_plan(
    inventory: &Inventory,
    selected: &[String],
    cancel: &CancellationToken,
) -> Result<Vec<ScannedEntry>, String> {
    if selected.len() > 256 {
        return Err("selected_item_batch_budget_exceeded".into());
    }
    if !inventory.complete {
        return Err("complete_previous_inventory_required".into());
    }
    let root = inventory
        .root_entry
        .as_ref()
        .ok_or("missing_root_identity")?;
    let path = native::path(root)?;
    let fresh = pnpm::inventory(&path, &inventory.project_inputs, cancel);
    if !fresh
        .root_entry
        .as_ref()
        .is_some_and(|r| native::same_object(root, r))
    {
        return Err("store_root_replaced".into());
    }
    pnpm::plan(&fresh, selected, cancel)
}
/// Reobserve one selected CAS file through its captured parent immediately before native Trash.
/// Changed identity, links, no-follow/mount boundaries and cancellation refuse the operation.
pub fn revalidate_pnpm_file(
    file: &ScannedEntry,
    cancel: &CancellationToken,
) -> Result<ScannedEntry, String> {
    if file.object_type != sweepx_model::ObjectType::File
        || !file.coverage.complete
        || file.coverage.details_lost
    {
        return Err("ordinary_current_file_required".into());
    }
    let parent = native::captured_parent(file)?;
    let name = native::basename(file).ok_or("non_unicode_cas_file")?;
    let fresh = Native::new(cancel).child(&parent, &name)?;
    if !native::same_object(file, &fresh)
        || fresh.hard_link_count.as_ref().and_then(exact) != Some(1)
    {
        return Err("cas_identity_or_link_count_changed".into());
    }
    Ok(fresh)
}
impl Item {
    /// Current captured native unit, absent for package rows whose contents require a separate plan.
    pub fn source_entry(&self) -> Option<&ScannedEntry> {
        self.source.as_ref()
    }
    /// Recheck selected model state before a tool-managed operation.
    pub fn revalidate_model(&self, cancel: &CancellationToken) -> Result<(), String> {
        if self.action != Action::OsdkModelRemove {
            return Err("not_model_item".into());
        }
        osdk::revalidate_model(self, cancel)
    }
}
fn bytes(value: Option<u128>, complete: bool) -> ByteValue {
    match value {
        Some(v) if complete => sweepx_platform::known_u128(v),
        Some(v) => sweepx_platform::lower_bound_u128(v, ReasonCode::ResourceLimit),
        None => sweepx_platform::unknown_u128(ReasonCode::UnknownIdentity),
    }
}
fn known(value: &ByteValue) -> Option<u128> {
    match value {
        EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}
// Bounds can be used for display/sorting, but cannot become exact accounting or link authority.
fn exact(value: &ByteValue) -> Option<u128> {
    match value {
        EvidenceValue::Known { value } => Some(value.0),
        _ => None,
    }
}
fn token(root: &ScannedEntry, label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sweepx.managed-item/v1\0");
    h.update(rules_digest().as_bytes());
    if let Some(l) = &root.native_locator {
        h.update(serde_json::to_vec(&l.scan_root_absolute_path).unwrap_or_default());
        h.update(serde_json::to_vec(&l.entry.platform_file_identity).unwrap_or_default());
    }
    h.update(label.as_bytes());
    format!("{:x}", h.finalize())
}

fn rules_digest() -> String {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(compute_rules_digest).clone()
}
fn compute_rules_digest() -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(sweepx_catalog::junk::platform::PLATFORM_JUNK_RULES_JSON.as_bytes())
    )
}

fn admit_rules(report: &mut Inventory) -> bool {
    match sweepx_catalog::junk::platform::load_platform_junk_rules() {
        Ok(rules)
            if rules
                .iter()
                .any(|r| r.item_inventory.as_deref() == Some(report.tool.as_str())) =>
        {
            true
        }
        Ok(_) => {
            report.issues.push("managed_inventory_rule_missing".into());
            false
        }
        Err(e) => {
            report.issues.push(format!("managed_rule_admission: {e}"));
            false
        }
    }
}
