//! Project selection retires dependency directories and only their observed exclusive CAS paths.
//! Hard links held by recoverable Trash remain live: authority comes from a closed dependency
//! walk, not an assumed link-count decrease after moving a project. Unknown external links stay.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use sweepx_model::{IdentityEvidence, ObjectType};

const MAX_CAS_FILES: usize = 65_536;
const MAX_WALK_ENTRIES: usize = 2_000_000;
const MAX_PLAN_BYTES: usize = 64 * 1024 * 1024;
type FileKey = (u128, u128);

/// Explicit scope of the project-side recoverable operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PnpmProjectMode {
    /// Preserve source/configuration and retire observed installed dependency directories.
    Dependencies,
    /// Retire the entire selected project directory, including its source and local state.
    Project,
}
/// A reviewable, invocation-local project cleanup plan. Paths are labels, never IO authority.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PnpmProjectPlan {
    /// Digest binding native targets, package indexes, dependency facts and reference scope.
    pub id: String,
    /// Display-only selected project root.
    pub project: String,
    /// User-selected project-side scope.
    pub mode: PnpmProjectMode,
    /// Search roots whose installed references were observed; no global disuse claim.
    pub project_roots: Vec<String>,
    /// Dependency roots or the project root that will enter recoverable Trash first.
    pub directory_paths: Vec<String>,
    /// Package selection tokens observed only inside the selected project subtree.
    pub package_ids: Vec<String>,
    /// Store paths proven exclusive to those selected package indexes and accounted links.
    pub content_paths: Vec<String>,
    /// Package versions retained because another observed project uses them.
    pub shared_packages: Vec<String>,
    /// CAS paths retained because another index owns them or external native links remain.
    pub retained_content_files: usize,
    /// Logical dependency-file lengths, counted by unique native identity; not reclaimable bytes.
    pub dependency_logical_bytes: ByteValue,
    #[serde(skip)]
    directories: Vec<ScannedEntry>,
    #[serde(skip)]
    content: Vec<ScannedEntry>,
}
impl PnpmProjectPlan {
    /// Identity-bound directory targets; callers must revalidate before each Trash submission.
    pub fn directories(&self) -> &[ScannedEntry] {
        &self.directories
    }
    /// Identity-bound CAS targets; link counts must still match their captured observations.
    pub fn content(&self) -> &[ScannedEntry] {
        &self.content
    }
}
fn key(entry: &ScannedEntry) -> Result<FileKey, String> {
    let identity = entry
        .validated_identity()
        .map_err(|e| e.to_string())?
        .ok_or("project_file_identity_missing")?;
    match &identity.platform_file_identity {
        IdentityEvidence::Known { value } => Ok((value.device.0, value.inode.0)),
        _ => Err("project_file_identity_unknown".into()),
    }
}
fn entry_digest(entry: &ScannedEntry) -> Result<[u8; 32], String> {
    let data = serde_json::to_vec(&(
        native::path(entry)?,
        key(entry)?,
        &entry.metadata_fingerprint,
        &entry.object_type,
        &entry.logical_bytes,
        &entry.hard_link_count,
    ))
    .map_err(|e| e.to_string())?;
    Ok(Sha256::digest(data).into())
}
/// Construct a closed project-side plan from complete native pnpm index/reference observations.
/// Clones are protected by package references; hard links additionally need exact in-scope
/// occurrence counts. Shared indexes, outside links and unknown facts never authorize CAS moves.
/// No project contents are modified, and arbitrary workspace/custom virtual stores are refused.
pub fn pnpm_project_plan(
    inventory: &Inventory,
    project: &Path,
    mode: PnpmProjectMode,
    cancel: &CancellationToken,
) -> Result<PnpmProjectPlan, String> {
    if inventory.tool != "pnpm" || !inventory.complete || !project.is_absolute() {
        return Err("complete_pnpm_inventory_and_absolute_project_required".into());
    }
    let root = inventory.source_root().ok_or("store_identity_missing")?;
    let store_path = native::path(root)?;
    if project == store_path
        || (mode == PnpmProjectMode::Project && store_path.starts_with(project))
    {
        return Err("store_inside_selected_project_refused".into());
    }
    let selected: BTreeSet<usize> = inventory
        .projects
        .iter()
        .enumerate()
        .filter(|(_, p)| Path::new(&p.directory).starts_with(project))
        .map(|(i, _)| i)
        .collect();
    if !inventory
        .projects
        .iter()
        .any(|p| Path::new(&p.directory) == project)
    {
        return Err("selected_project_not_observed".into());
    }
    let mut native = Native::new(cancel);
    let parent = native.root(project.parent().ok_or("project_parent_required")?)?;
    let name = project
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("unicode_project_component_required")?;
    let project_entry = native.child(&parent, name)?;
    let modules = native.child(&project_entry, "node_modules")?;
    if modules.object_type != ObjectType::Directory {
        return Err("ordinary_node_modules_required".into());
    }
    let marker = native.read(&modules, ".modules.yaml", 1024 * 1024)?;
    let marker_text = std::str::from_utf8(&marker).map_err(|_| "pnpm_marker_utf8")?;
    let declared = marker_text
        .lines()
        .find_map(|l| {
            l.strip_prefix("storeDir:")
                .map(|v| v.trim().trim_matches(['\'', '"']))
        })
        .ok_or("pnpm_store_declaration_required")?;
    if Path::new(declared) != store_path {
        return Err("selected_project_uses_another_store".into());
    }
    if let Some(virtual_store) = marker_text
        .lines()
        .find_map(|l| l.strip_prefix("virtualStoreDir:"))
        && virtual_store.trim().trim_matches(['\'', '"']) != ".pnpm"
    {
        return Err("custom_virtual_store_refused".into());
    }
    let mut dependency_roots = Vec::new();
    for &i in &selected {
        let p = Path::new(&inventory.projects[i].directory);
        let parent = native.root(p)?;
        let children = native.children(&parent)?;
        if let Some(m) = children
            .into_iter()
            .find(|e| native::basename(e).as_deref() == Some("node_modules"))
        {
            if m.object_type != ObjectType::Directory {
                return Err("linked_dependency_root_refused".into());
            }
            if native::path(&m)?.starts_with(&store_path)
                || store_path.starts_with(native::path(&m)?)
            {
                return Err("store_and_dependencies_overlap".into());
            }
            dependency_roots.push(m);
        }
    }
    if dependency_roots.is_empty() || dependency_roots.len() > 256 {
        return Err("dependency_root_budget_or_absence".into());
    }
    let packages: BTreeSet<_> = selected
        .iter()
        .filter(|&&i| {
            inventory.projects[i]
                .store_dir
                .as_deref()
                .is_some_and(|p| Path::new(p) == store_path)
        })
        .flat_map(|&i| inventory.projects[i].packages.iter().cloned())
        .collect();
    let mut chosen = BTreeSet::new();
    let mut shared = BTreeSet::new();
    for item in &inventory.entries {
        if packages.contains(&(item.name.clone(), item.version.clone().unwrap_or_default())) {
            if item.projects.iter().any(|i| !selected.contains(i)) {
                shared.insert(format!(
                    "{}@{}",
                    item.name,
                    item.version.as_deref().unwrap_or("?")
                ));
            } else if item.version.is_some() {
                chosen.insert(item.id.clone());
            }
        }
    }
    let retained: BTreeSet<_> = inventory
        .entries
        .iter()
        .filter(|e| !chosen.contains(&e.id))
        .flat_map(|e| e.content.iter())
        .collect();
    let all_content: BTreeSet<_> = inventory
        .entries
        .iter()
        .filter(|e| chosen.contains(&e.id))
        .flat_map(|e| e.content.iter())
        .filter(|d| !inventory.absent_cas.contains(*d))
        .collect();
    let mut retained_count = all_content
        .iter()
        .filter(|d| retained.contains(**d))
        .count();
    let digests: Vec<_> = all_content
        .into_iter()
        .filter(|d| !retained.contains(*d))
        .collect();
    if digests.len() > MAX_CAS_FILES {
        return Err("project_content_file_budget_exceeded".into());
    }
    let files = native.child(root, "files")?;
    let mut shards = BTreeMap::new();
    let mut candidates = Vec::new();
    let mut wanted = BTreeSet::new();
    let mut charged = 0usize;
    for digest in digests {
        let (prefix, name) = digest.split_once('/').ok_or("invalid_content_key")?;
        if !shards.contains_key(prefix) {
            shards.insert(prefix.to_owned(), native.child(&files, prefix)?);
        }
        let file = native.child(&shards[prefix], name)?;
        if file.object_type != ObjectType::File {
            return Err("ordinary_cas_file_required".into());
        }
        charged = charged.saturating_add(file.estimated_retained_bytes());
        if charged > MAX_PLAN_BYTES {
            return Err("project_plan_metadata_budget_exceeded".into());
        }
        wanted.insert(key(&file)?);
        candidates.push(file);
    }
    let mut counts: BTreeMap<FileKey, u128> = BTreeMap::new();
    let mut unique_files = BTreeSet::new();
    let mut logical = 0u128;
    let mut snapshot = [0u8; 32];
    let mut visited = 0usize;
    let mut frontier = dependency_roots.clone();
    let mut frontier_bytes: usize = frontier
        .iter()
        .map(ScannedEntry::estimated_retained_bytes)
        .sum();
    while let Some(dir) = frontier.pop() {
        frontier_bytes = frontier_bytes.saturating_sub(dir.estimated_retained_bytes());
        for entry in native.children(&dir)? {
            visited += 1;
            if visited > MAX_WALK_ENTRIES || unique_files.len() > MAX_WALK_ENTRIES {
                return Err("dependency_walk_budget_exceeded".into());
            }
            // An unordered set digest avoids interpreting host enumeration order as an API contract.
            for (sum, byte) in snapshot.iter_mut().zip(entry_digest(&entry)?) {
                *sum ^= byte;
            }
            match entry.object_type {
                ObjectType::Directory => {
                    frontier_bytes =
                        frontier_bytes.saturating_add(entry.estimated_retained_bytes());
                    if frontier.len() >= 4096 || frontier_bytes > MAX_PLAN_BYTES {
                        return Err("dependency_frontier_budget_exceeded".into());
                    }
                    frontier.push(entry);
                }
                ObjectType::File => {
                    let identity = key(&entry)?;
                    if wanted.contains(&identity) {
                        *counts.entry(identity).or_default() += 1;
                    }
                    if unique_files.insert(identity) {
                        logical = logical
                            .checked_add(
                                exact(&entry.logical_bytes).ok_or("dependency_length_unknown")?,
                            )
                            .ok_or("dependency_size_overflow")?;
                    }
                }
                ObjectType::Symlink => {} // pnpm package links are observed but never followed.
                _ => return Err("unsupported_dependency_object".into()),
            }
        }
    }
    let mut content = Vec::new();
    for file in candidates {
        if file.hard_link_count.as_ref().and_then(exact)
            == Some(1 + counts.get(&key(&file)?).copied().unwrap_or(0))
        {
            content.push(file);
        } else {
            retained_count += 1;
        }
    }
    let directories = match mode {
        PnpmProjectMode::Dependencies => dependency_roots,
        PnpmProjectMode::Project => vec![project_entry],
    };
    let mut digest = Sha256::new();
    digest.update(b"sweepx.pnpm-project-plan/v1\0");
    digest.update(inventory.rules_digest.as_bytes());
    digest.update(&marker);
    digest.update(snapshot);
    digest.update(visited.to_le_bytes());
    digest.update(
        serde_json::to_vec(&(project, mode, &inventory.project_roots))
            .map_err(|e| e.to_string())?,
    );
    // All indexes and project labels bind outside-project copy/clone ownership too.
    for item in &inventory.entries {
        digest.update(item.id.as_bytes());
    }
    for p in &inventory.projects {
        digest.update(
            serde_json::to_vec(&(&p.directory, &p.store_dir, &p.packages))
                .map_err(|e| e.to_string())?,
        );
    }
    for entry in directories.iter().chain(content.iter()) {
        digest.update(entry_digest(entry)?);
    }
    Ok(PnpmProjectPlan {
        id: format!("{:x}", digest.finalize()),
        project: project.display().to_string(),
        mode,
        project_roots: inventory.project_roots.clone(),
        directory_paths: directories.iter().map(|e| e.display_path.clone()).collect(),
        package_ids: chosen.into_iter().collect(),
        content_paths: content.iter().map(|e| e.display_path.clone()).collect(),
        shared_packages: shared.into_iter().collect(),
        retained_content_files: retained_count,
        dependency_logical_bytes: bytes(Some(logical), true),
        directories,
        content,
    })
}
/// Reobserve native CAS identity, content metadata and exact link count immediately before Trash.
/// Project-side Trash moves preserve links; any added/removed link invalidates this observation.
pub fn revalidate_project_content(
    file: &ScannedEntry,
    cancel: &CancellationToken,
) -> Result<ScannedEntry, String> {
    let expected = file
        .hard_link_count
        .as_ref()
        .and_then(exact)
        .ok_or("cas_link_count_unknown")?;
    let parent = native::captured_parent(file)?;
    let name = native::basename(file).ok_or("non_unicode_cas_name")?;
    let current = Native::new(cancel).child(&parent, &name)?;
    if current.object_type != ObjectType::File
        || !native::same_object(file, &current)
        || current.metadata_fingerprint != file.metadata_fingerprint
        || current.hard_link_count.as_ref().and_then(exact) != Some(expected)
    {
        return Err("project_cas_identity_content_or_links_changed".into());
    }
    Ok(current)
}

/// Verify a plan's directory identity and no-follow lineage immediately before recoverable Trash.
pub fn revalidate_project_directory(
    entry: &ScannedEntry,
    cancel: &CancellationToken,
) -> Result<(), String> {
    if entry.object_type != ObjectType::Directory {
        return Err("ordinary_project_directory_required".into());
    }
    crate::storage_inventory::revalidate_directory(entry, cancel)
}
