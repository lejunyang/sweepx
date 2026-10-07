use super::*;
use native::{basename, path};
use serde_json::Value;
use sweepx_model::ObjectType;
fn total(entry: &ScannedEntry, native: &mut Native<'_>) -> (ByteValue, bool) {
    let result = path(entry).and_then(|p| {
        crate::storage_inventory::observe_directories_isolated_deadline(
            &p,
            native.cancel,
            Instant::now() + std::time::Duration::from_secs(60),
        )
    });
    match result {
        Ok(scan) => match scan.roots.first().filter(|r| native::same_object(entry, r)) {
            Some(root) => {
                let (v, c) = crate::storage_inventory::entry_bytes(&scan, root);
                (bytes(v, c), c)
            }
            None => (bytes(None, false), false),
        },
        Err(_) => (bytes(None, false), false),
    }
}
pub(super) fn inventory(
    data: &Path,
    cache: &Path,
    roots: &[PathBuf],
    cancel: &CancellationToken,
) -> Inventory {
    use sha2::{Digest, Sha256};
    let mut report = Inventory::empty("osdk", data, roots);
    if !admit_rules(&mut report) {
        return report;
    }
    let mut native = Native::new(cancel);
    let result = (|| -> Result<(), String> {
        let root = native.root(data)?;
        report.root_entry = Some(root.clone());
        let models = native.child(&root, "models")?;
        for alias in native.children(&models)? {
            if alias.object_type != ObjectType::Directory {
                continue;
            }
            let name = basename(&alias).ok_or("non_unicode_model_alias")?;
            if name.starts_with('.') {
                continue;
            }
            let current = native.read(&alias, "current.json", 1024 * 1024)?;
            let value: Value = serde_json::from_slice(&current).map_err(|e| e.to_string())?;
            let snapshot = value
                .get("snapshot")
                .and_then(Value::as_str)
                .ok_or("osdk_current_snapshot_missing")?;
            let snapshots = native.child(&alias, "snapshots")?;
            let snapshot_dir = native.child(&snapshots, snapshot)?;
            let metadata = native.read(&snapshot_dir, ".osdk-model.json", 8 * 1024 * 1024)?;
            let model: Value = serde_json::from_slice(&metadata).map_err(|e| e.to_string())?;
            if model["schema"] != 1 || model["name"].as_str() != Some(&name) {
                return Err("unsupported_osdk_model_manifest".into());
            }
            let revision = model
                .get("revision")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let (logical, complete) = total(&alias, &mut native);
            let digest = format!(
                "{:x}",
                Sha256::digest([current.as_slice(), metadata.as_slice()].concat())
            );
            report.entries.push(Item {
                id: token(&alias, &digest),
                rule_id: "tool.osdk-model".into(),
                name,
                version: revision,
                path: alias.display_path.clone(),
                logical_bytes: logical,
                allocated_bytes: bytes(None, false),
                files: model
                    .get("files")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                min_links: None,
                max_links: None,
                single_link_files: 0,
                missing_files: 0,
                projects: Vec::new(),
                action: Action::OsdkModelRemove,
                eligible: complete,
                issues: if complete {
                    Vec::new()
                } else {
                    vec!["model_size_incomplete".into()]
                },
                source: Some(alias),
                content: Vec::new(),
                snapshot_digest: Some(digest),
            });
            if report.entries.len() >= 1024 {
                return Err("osdk_model_budget_exceeded".into());
            }
        }
        let cache_root = native.root(cache)?;
        let downloads = native.child(&cache_root, "downloads")?;
        // Generic archives are individually selectable; model downloads split by provider/namespace/repo.
        for dir in native.children(&downloads)? {
            if dir.object_type != ObjectType::Directory {
                continue;
            }
            if basename(&dir).as_deref() == Some("models") {
                for provider in native.children(&dir)? {
                    if provider.object_type != ObjectType::Directory {
                        continue;
                    }
                    for namespace in native.children(&provider)? {
                        if namespace.object_type != ObjectType::Directory {
                            continue;
                        }
                        for repo in native.children(&namespace)? {
                            if repo.object_type != ObjectType::Directory {
                                continue;
                            }
                            let label = format!(
                                "{}/{}/{}",
                                basename(&provider).unwrap_or_default(),
                                basename(&namespace).unwrap_or_default(),
                                basename(&repo).unwrap_or_default()
                            );
                            add_download(&mut report, repo, label, &mut native)?;
                        }
                    }
                }
            } else {
                let label = basename(&dir).unwrap_or_default();
                add_download(&mut report, dir, label, &mut native)?;
            }
        }
        Ok(())
    })();
    report.index_complete = result.is_ok();
    if let Err(e) = result {
        report.issues.push(e)
    }
    let (p, complete, issues) = projects::discover(roots, &mut native);
    report.projects = p;
    report.project_discovery_complete = complete;
    report.issues.extend(issues);
    for item in &mut report.entries {
        if item.action == Action::OsdkModelRemove {
            item.projects = report
                .projects
                .iter()
                .enumerate()
                .filter(|(_, p)| p.models.contains(&item.name))
                .map(|(i, _)| i)
                .collect();
            if !item.projects.is_empty() {
                item.issues
                    .push("declared_model_may_download_again_on_sync".into());
            }
        }
    }
    report.complete =
        report.index_complete && report.project_discovery_complete && report.issues.is_empty();
    for item in &mut report.entries {
        item.eligible &= report.complete;
    }
    report.entries.sort_by(|a, b| {
        known(&b.logical_bytes)
            .cmp(&known(&a.logical_bytes))
            .then(a.id.cmp(&b.id))
    });
    report
}
fn add_download(
    report: &mut Inventory,
    dir: ScannedEntry,
    label: String,
    native: &mut Native<'_>,
) -> Result<(), String> {
    if report.entries.len() >= 4096 {
        return Err("osdk_download_unit_budget".into());
    }
    let (logical, complete) = total(&dir, native);
    report.entries.push(Item {
        id: token(&dir, &label),
        rule_id: "tool.osdk-download".into(),
        name: label,
        version: None,
        path: dir.display_path.clone(),
        logical_bytes: logical,
        allocated_bytes: bytes(None, false),
        files: 0,
        min_links: None,
        max_links: None,
        single_link_files: 0,
        missing_files: 0,
        projects: Vec::new(),
        action: Action::TrashDirectory,
        eligible: complete,
        issues: if complete {
            Vec::new()
        } else {
            vec!["download_size_incomplete".into()]
        },
        source: Some(dir),
        content: Vec::new(),
        snapshot_digest: None,
    });
    Ok(())
}
/// Verify the current alias and manifest immediately before invoking the manager.
pub(super) fn revalidate_model(item: &Item, cancel: &CancellationToken) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let alias = item.source.as_ref().ok_or("missing_model_identity")?;
    crate::storage_inventory::revalidate_directory(alias, cancel)?;
    let mut native = Native::new(cancel);
    let current = native.read(alias, "current.json", 1024 * 1024)?;
    let v: Value = serde_json::from_slice(&current).map_err(|e| e.to_string())?;
    let snapshot = v
        .get("snapshot")
        .and_then(Value::as_str)
        .ok_or("missing_snapshot")?;
    let snapshots = native.child(alias, "snapshots")?;
    let dir = native.child(&snapshots, snapshot)?;
    let metadata = native.read(&dir, ".osdk-model.json", 8 * 1024 * 1024)?;
    let digest = format!(
        "{:x}",
        Sha256::digest([current.as_slice(), metadata.as_slice()].concat())
    );
    if item.snapshot_digest.as_deref() != Some(&digest) {
        return Err("model_manifest_changed".into());
    }
    Ok(())
}
