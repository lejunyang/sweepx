use super::*;
use native::{basename, path};

use sweepx_model::ObjectType;
pub(super) const EXCLUSIONS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".pnpm-store",
    ".Trash",
    ".omem",
    ".cache",
    ".next",
];
/// Search is explicit and bounded. Ignored build/cache trees are not proof of global absence.
pub(super) fn discover(
    roots: &[PathBuf],
    native: &mut Native<'_>,
) -> (Vec<Project>, bool, Vec<String>) {
    discover_with_sizes(roots, native, true)
}
pub(super) fn discover_with_sizes(
    roots: &[PathBuf],
    native: &mut Native<'_>,
    measure_sizes: bool,
) -> (Vec<Project>, bool, Vec<String>) {
    discover_measured(roots, native, measure_sizes, false)
}
pub(super) fn discover_measured(
    roots: &[PathBuf],
    native: &mut Native<'_>,
    measure_sizes: bool,
    pnpm: bool,
) -> (Vec<Project>, bool, Vec<String>) {
    discover_impl(roots, native, measure_sizes, pnpm, &mut Vec::new())
}
pub(super) fn discover_store_hints(
    roots: &[PathBuf],
    native: &mut Native<'_>,
) -> (Vec<Project>, bool, Vec<String>, Vec<PathBuf>) {
    let mut hints = Vec::new();
    let (projects, complete, issues) = discover_impl(roots, native, false, true, &mut hints);
    (projects, complete, issues, hints)
}
fn discover_impl(
    roots: &[PathBuf],
    native: &mut Native<'_>,
    measure_sizes: bool,
    pnpm: bool,
    store_hints: &mut Vec<PathBuf>,
) -> (Vec<Project>, bool, Vec<String>) {
    let mut out = Vec::new();
    let mut project_dirs = Vec::new();
    let mut issues = Vec::new();
    let mut installed_packages = 0usize;
    let mut project_metadata_bytes = 0usize;
    let mut store_statuses = std::collections::BTreeMap::new();
    let mut candidates = BTreeSet::new();
    for root in roots {
        if let Err(e) = super::walk::walk(root, native.cancel, EXCLUSIONS, |entry| {
            let name = entry.path.file_name().and_then(|n| n.to_str());
            if pnpm
                && name == Some(".pnpm-store")
                && entry.kind == sweepx_platform::EntryKind::Directory
            {
                if store_hints.len() >= 128 {
                    return Err("project_store_hint_budget".into());
                }
                store_hints.push(entry.path.clone());
            }
            if matches!(name, Some("node_modules" | "osdk.toml" | ".osdk.toml")) {
                if name == Some("node_modules")
                    && entry.kind != sweepx_platform::EntryKind::Directory
                {
                    return Err(format!(
                        "linked_node_modules_unresolved {}",
                        entry.path.display()
                    ));
                }
                if candidates.len() >= 1024 {
                    return Err("project_count_budget".into());
                }
                if let Some(parent) = entry.path.parent() {
                    candidates.insert(parent.to_path_buf());
                }
            }
            Ok(())
        }) {
            issues.push(e);
        }
    }
    for candidate in candidates {
        let dir = match native.root(&candidate) {
            Ok(dir) => dir,
            Err(e) => {
                issues.push(format!(
                    "project_reobservation {}: {e}",
                    candidate.display()
                ));
                continue;
            }
        };
        let children = match native.children(&dir) {
            Ok(r) => r,
            Err(e) => {
                issues.push(format!("project_discovery {}: {e}", dir.display_path));
                continue;
            }
        };
        let has_config = children
            .iter()
            .any(|e| matches!(basename(e).as_deref(), Some("osdk.toml" | ".osdk.toml")));
        if children.iter().any(|e| {
            basename(e).as_deref() == Some("node_modules") && e.object_type != ObjectType::Directory
        }) {
            // A redirected installed layout is unresolved usage evidence, not an empty project.
            // Following it would cross the native boundary; suppress cleanup for this scope.
            issues.push(format!(
                "linked_node_modules_unresolved {}",
                dir.display_path
            ));
        }
        let modules = children.iter().find(|e| {
            e.object_type == ObjectType::Directory && basename(e).as_deref() == Some("node_modules")
        });
        if modules.is_some() || has_config {
            // Reserve both retained root observations before cloning their native locators.
            project_metadata_bytes = project_metadata_bytes
                .saturating_add(dir.estimated_retained_bytes().saturating_mul(2));
            if project_metadata_bytes > 64 * 1024 * 1024 {
                issues.push("project_native_metadata_budget".into());
                break;
            }
            let mut project = Project {
                directory: dir.display_path.clone(),
                logical_bytes: bytes(None, false),
                size_complete: false,
                store_dir: None,
                store_status: "not_checked",
                packages: BTreeSet::new(),
                models: BTreeSet::new(),
                virtual_stores: Vec::new(),
                source: dir.clone(),
            };
            if let Some(m) = modules {
                match native.children(m) {
                    Err(e) => issues.push(format!("installed_layout {}: {e}", project.directory)),
                    Ok(layout) => {
                        let yaml = layout
                            .iter()
                            .any(|e| basename(e).as_deref() == Some(".modules.yaml"));
                        if yaml {
                            match native.read(m, ".modules.yaml", 1024 * 1024) {
                                Ok(bytes) => match super::locations::modules_metadata(&bytes) {
                                    Ok(meta) => {
                                        if meta
                                            .virtual_store
                                            .as_deref()
                                            .is_some_and(|v| v != ".pnpm")
                                        {
                                            issues.push(format!(
                                                "custom_virtual_store_unresolved {}",
                                                project.directory
                                            ));
                                        }
                                        project.store_dir = meta.store;
                                    }
                                    Err(e) => issues
                                        .push(format!("pnpm_marker {}: {e}", project.directory)),
                                },
                                Err(e) => {
                                    issues.push(format!("pnpm_marker {}: {e}", project.directory))
                                }
                            }
                        }
                        if let Some(pnpm) = layout
                            .iter()
                            .find(|e| basename(e).as_deref() == Some(".pnpm"))
                        {
                            if pnpm.object_type != ObjectType::Directory {
                                issues.push(format!(
                                    "linked_or_custom_virtual_store {}",
                                    project.directory
                                ));
                            } else {
                                match path(pnpm) {
                                    Ok(path) => project.virtual_stores.push(path),
                                    Err(e) => {
                                        issues.push(format!("virtual_store_native_path: {e}"))
                                    }
                                }
                                match native.children(pnpm) {
                                    Ok(slots) => {
                                        for slot in slots {
                                            if let Some(label) =
                                                basename(&slot).and_then(|n| package_label(&n))
                                            {
                                                if slot.object_type == ObjectType::Directory {
                                                    project.packages.insert(label);
                                                } else {
                                                    issues.push(format!(
                                                        "unresolved_virtual_package {}",
                                                        project.directory
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => issues.push(format!(
                                        "installed_packages {}: {e}",
                                        project.directory
                                    )),
                                }
                            }
                        } else if yaml {
                            issues.push(format!(
                                "custom_or_hoisted_virtual_store_unobserved {}",
                                project.directory
                            ));
                        }
                    }
                }
            }
            for name in ["osdk.toml", ".osdk.toml"] {
                if children
                    .iter()
                    .any(|e| basename(e).as_deref() == Some(name))
                {
                    match native
                        .read(&dir, name, 1024 * 1024)
                        .and_then(|b| String::from_utf8(b).map_err(|e| e.to_string()))
                        .and_then(|s| s.parse::<toml::Value>().map_err(|e| e.to_string()))
                    {
                        Ok(v) => {
                            if let Some(m) = v.get("models").and_then(toml::Value::as_table) {
                                project.models.extend(m.keys().cloned());
                            }
                        }
                        Err(e) => {
                            issues.push(format!("model_declarations {}: {e}", project.directory))
                        }
                    }
                }
            }
            if pnpm && project.store_dir.is_none() && project.virtual_stores.is_empty() {
                continue;
            }
            if let Some(store) = &project.store_dir {
                project.store_status = *store_statuses.entry(store.clone()).or_insert_with(|| {
                    if native.root(Path::new(store)).is_ok() {
                        "observed"
                    } else {
                        "unavailable"
                    }
                });
            }
            installed_packages += project.packages.len();
            project_dirs.push(dir.clone());
            if installed_packages > 500_000 || project.models.len() > 4096 {
                issues.push("project_reference_budget_exceeded".into());
                out.push(project);
                break;
            }
            out.push(project);
        }
    }
    // Find references first so one large project's size cannot hide sibling projects. Totals
    // have their own cancellation deadline and explicit lower-bound/unknown evidence; exhausting
    // the invocation's size budget leaves remaining totals unknown, never observed as zero.
    let virtual_stores: Vec<_> = out
        .iter()
        .filter_map(|p| {
            path(&p.source)
                .ok()
                .map(|root| (root, p.virtual_stores.clone()))
        })
        .collect();
    for (project, dir) in out.iter_mut().zip(project_dirs).filter(|_| measure_sizes) {
        if native.cancel.is_cancelled() {
            issues.push("project_totals_cancelled".into());
            break;
        }
        if native.check().is_err() {
            break;
        }
        if pnpm {
            let (size, complete) = super::walk::footprint(
                &virtual_stores
                    .iter()
                    .filter(|(p, _)| path(&project.source).is_ok_and(|root| p.starts_with(root)))
                    .flat_map(|(_, stores)| stores.iter().cloned())
                    .collect::<Vec<_>>(),
                native.cancel,
            );
            project.logical_bytes = size;
            project.size_complete = complete;
            continue;
        }
        if let Ok(p) = path(&dir)
            && let Ok(scan) = crate::storage_inventory::observe_directories_isolated_deadline(
                &p,
                native.cancel,
                Instant::now() + std::time::Duration::from_secs(60),
            )
            && let Some(root) = scan.roots.first().filter(|r| native::same_object(&dir, r))
        {
            let (size, complete) = crate::storage_inventory::entry_bytes(&scan, root);
            project.logical_bytes = bytes(size, complete);
            project.size_complete = complete;
        }
    }
    if native.cancel.is_cancelled() && !issues.iter().any(|s| s.contains("cancelled")) {
        issues.push("project_observation_cancelled".into());
    }
    out.sort_by(|a, b| a.directory.cmp(&b.directory));
    let complete = issues.is_empty();
    (out, complete, issues)
}
fn package_label(name: &str) -> Option<(String, String)> {
    // Skip the scope marker only; a non-ASCII label must not split a UTF-8 code point.
    let offset = usize::from(name.starts_with('@'));
    let sep = name[offset..].find('@')? + offset;
    let rest = &name[sep + 1..];
    let end = rest.find(['(', '_']).unwrap_or(rest.len());
    let label = &name[..sep + 1 + end];
    let package = label[..sep].replacen('+', "/", 1);
    let version = &label[sep + 1..];
    if version.is_empty() || package.is_empty() {
        return None;
    }
    Some((package, version.into()))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_labels_are_usage_hints() {
        assert_eq!(package_label(""), None);
        assert_eq!(package_label("中文"), None);
        assert_eq!(
            package_label("中文@1.0.0"),
            Some(("中文".into(), "1.0.0".into()))
        );
        assert_eq!(
            package_label("@scope+pkg@1.2.3(peer@4.0.0)"),
            Some(("@scope/pkg".into(), "1.2.3".into()))
        );
        assert_eq!(
            package_label("foo@1.0.0_peer@2"),
            Some(("foo".into(), "1.0.0".into()))
        );
        assert_eq!(package_label("node_modules"), None);
        assert_eq!(
            package_label("my_pkg@1.0.0_peer@2"),
            Some(("my_pkg".into(), "1.0.0".into()))
        );
    }
}
