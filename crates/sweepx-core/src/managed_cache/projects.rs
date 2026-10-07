use super::*;
use native::{basename, path};
use std::collections::VecDeque;
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
    let mut out = Vec::new();
    let mut project_dirs = Vec::new();
    let mut issues = Vec::new();
    let mut visited = 0;
    // Prioritize shallow sibling projects, then walk deep trees depth first so broad generated
    // source trees cannot exhaust the frontier. Any lost coverage still prohibits cleanup.
    let mut queue = VecDeque::new();
    let mut seen = BTreeSet::new();
    let mut retained = 0usize;
    let mut installed_packages = 0usize;
    let mut seen_bytes = 0usize;
    for p in roots {
        match native.root(p) {
            Ok(e) => {
                if seen.insert(p.clone()) {
                    retained += e.estimated_retained_bytes();
                    queue.push_back((e, 0));
                }
            }
            Err(e) => issues.push(format!("project_root {}: {e}", p.display())),
        }
    }
    while let Some((dir, depth)) = queue.pop_front() {
        retained = retained.saturating_sub(dir.estimated_retained_bytes());
        visited += 1;
        if issues.len() > 256 {
            issues.truncate(256);
            issues.push("project_issue_budget_exceeded".into());
            break;
        }
        if visited > 20_000 || out.len() >= 1024 {
            issues.push(format!(
                "project_discovery_budget_exceeded: visited={visited}, projects={}, pending={}",
                out.len(),
                queue.len()
            ));
            break;
        }
        if let Err(reason) = native.check() {
            issues.push(format!(
                "project_discovery_stopped: {reason}; visited={visited}, projects={}",
                out.len()
            ));
            break;
        }
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
            let mut project = Project {
                directory: dir.display_path.clone(),
                logical_bytes: bytes(None, false),
                size_complete: false,
                store_dir: None,
                packages: BTreeSet::new(),
                models: BTreeSet::new(),
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
                                Ok(bytes) => {
                                    project.store_dir =
                                        String::from_utf8_lossy(&bytes).lines().find_map(|l| {
                                            l.strip_prefix("storeDir:").map(|v| {
                                                v.trim().trim_matches(['\'', '"']).to_owned()
                                            })
                                        })
                                }
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
            installed_packages += project.packages.len();
            project_dirs.push(dir.clone());
            if installed_packages > 500_000 || project.models.len() > 4096 {
                issues.push("project_reference_budget_exceeded".into());
                out.push(project);
                break;
            }
            out.push(project);
        }
        for child in children {
            if child.object_type != ObjectType::Directory {
                continue;
            }
            let Some(name) = basename(&child) else {
                issues.push("non_unicode_project_component".into());
                continue;
            };
            if EXCLUSIONS.contains(&name.as_str()) {
                continue;
            }
            if depth >= 32
                || queue.len() >= 4096
                || retained.saturating_add(child.estimated_retained_bytes()) > 32 * 1024 * 1024
            {
                issues.push(format!("project_frontier_budget_exceeded: depth={depth}, pending={}, bytes={}, path={}",queue.len(),retained,child.display_path));
                continue;
            }
            if seen_bytes.saturating_add(child.display_path.len()) > 32 * 1024 * 1024 {
                issues.push("project_path_budget_exceeded".into());
                break;
            }
            let child_path = match path(&child) {
                Ok(p) => p,
                Err(e) => {
                    issues.push(format!("project_native_path_unavailable: {e}"));
                    continue;
                }
            };
            if seen.insert(child_path) {
                seen_bytes += child.display_path.len();
                retained += child.estimated_retained_bytes();
                if depth < 3 {
                    queue.push_back((child, depth + 1));
                } else {
                    queue.push_front((child, depth + 1));
                }
            }
        }
    }
    // Find references first so one large project's size cannot hide sibling projects. Totals
    // have their own cancellation deadline and explicit lower-bound/unknown evidence; exhausting
    // the invocation's size budget leaves remaining totals unknown, never observed as zero.
    for (project, dir) in out.iter_mut().zip(project_dirs) {
        if native.cancel.is_cancelled() {
            issues.push("project_totals_cancelled".into());
            break;
        }
        if native.check().is_err() {
            break;
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
