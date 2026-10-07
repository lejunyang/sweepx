use super::*;
use base64::Engine;
use native::basename;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::BTreeMap;
use sweepx_model::ObjectType;
struct Stats {
    size: Option<u128>,
    allocated: Option<u128>,
    min: Option<u128>,
    max: Option<u128>,
    single: usize,
    observed: usize,
    links_known: bool,
}
impl Default for Stats {
    fn default() -> Self {
        Self {
            size: Some(0),
            allocated: Some(0),
            min: None,
            max: None,
            single: 0,
            observed: 0,
            links_known: true,
        }
    }
}
pub(super) fn inventory(path: &Path, roots: &[PathBuf], cancel: &CancellationToken) -> Inventory {
    let mut report = Inventory::empty("pnpm", path, roots);
    if !admit_rules(&mut report) {
        return report;
    }
    let mut native = Native::new(cancel);
    let root = match native.root(path) {
        Ok(r) => r,
        Err(e) => {
            report.issues.push(e);
            return report;
        }
    };
    report.root_entry = Some(root.clone());
    let mut retained_package_bytes = 0usize;
    let result = (|| -> Result<(), String> {
        let children = native.children(&root)?;
        if children
            .iter()
            .any(|e| basename(e).as_deref() == Some("index.fallback"))
        {
            return Err("pnpm_fallback_index_unresolved".into());
        }
        let files = children
            .iter()
            .find(|e| {
                e.object_type == ObjectType::Directory && basename(e).as_deref() == Some("files")
            })
            .ok_or("pnpm_files_directory_missing")?
            .clone();
        if children
            .iter()
            .any(|e| basename(e).as_deref() == Some("index.db"))
        {
            // Refuse live sidecars rather than opening SQLite by a display path or omitting pending writes.
            if children.iter().any(|e| {
                matches!(
                    basename(e).as_deref(),
                    Some("index.db-wal" | "index.db-journal")
                )
            }) {
                return Err("pnpm_sqlite_sidecar_present".into());
            }
            let mut bytes = native.read(&root, "index.db", 64 * 1024 * 1024)?;
            if !bytes.starts_with(b"SQLite format 3\0") || bytes.len() < 100 {
                return Err("invalid_sqlite_header".into());
            }
            match (bytes[18], bytes[19]) {
                (1, 1) => {}
                (2, 2) => {
                    // No WAL/journal was observed above. The complete checkpointed main-file copy
                    // must use rollback headers in an in-memory database, without native sidecar IO.
                    // This modifies only our private bytes, never the source database.
                    bytes[18] = 1;
                    bytes[19] = 1;
                }
                _ => return Err("unsupported_sqlite_journal_header".into()),
            }
            let mut db = Connection::open_in_memory().map_err(|e| e.to_string())?;
            db.deserialize_read_exact("main", bytes.as_slice(), bytes.len(), true)
                .map_err(|e| e.to_string())?;
            db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
                .map_err(|e| e.to_string())?;
            let schema: (String, String) = db
                .query_row(
                    "SELECT type,sql FROM sqlite_schema WHERE name='package_index'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| e.to_string())?;
            if schema.0 != "table"
                || !schema
                    .1
                    .trim_start()
                    .to_ascii_uppercase()
                    .starts_with("CREATE TABLE")
            {
                return Err("unsupported_pnpm_sqlite_schema".into());
            }
            let mut columns = db
                .prepare("PRAGMA table_xinfo(package_index)")
                .map_err(|e| e.to_string())?;
            let columns = columns
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i32>(6)?)))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            if columns != vec![("key".into(), 0), ("data".into(), 0)] {
                return Err("unsupported_pnpm_sqlite_columns".into());
            }

            let mut stmt = db
                .prepare("SELECT key,data FROM package_index LIMIT 65537")
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                native.check()?;
                if report.entries.len() >= 65536 {
                    return Err("package_index_row_budget".into());
                }
                let key: String = row.get(0).map_err(|e| e.to_string())?;
                let data: Vec<u8> = row.get(1).map_err(|e| e.to_string())?;
                if data.len() > 8 * 1024 * 1024 {
                    return Err("package_index_record_budget".into());
                }
                let value = msgpack::decode(&data)?;
                retain_package(
                    &mut report,
                    package(&root, &key, &value, &data, true)?,
                    &mut retained_package_bytes,
                )?;
            }
        } else {
            let index = children
                .iter()
                .find(|e| {
                    e.object_type == ObjectType::Directory
                        && basename(e).as_deref() == Some("index")
                })
                .unwrap_or(&files)
                .clone();
            for shard in native.children(&index)? {
                if basename(&shard).as_deref() == Some(".DS_Store")
                    && shard.object_type == ObjectType::File
                {
                    continue;
                }
                if shard.object_type != ObjectType::Directory
                    || !basename(&shard).is_some_and(|n| hex(&n, 2))
                {
                    return Err("pnpm_index_shard_layout".into());
                }
                for entry in native.children(&shard)? {
                    let Some(name) = basename(&entry) else {
                        return Err("non_unicode_index_name".into());
                    };
                    if !name.ends_with(".json") {
                        continue;
                    }
                    if entry.object_type != ObjectType::File {
                        return Err("linked_or_special_package_index".into());
                    }
                    if report.entries.len() >= 65536 {
                        return Err("package_index_row_budget".into());
                    }
                    let item = (|| -> Result<Item, String> {
                        let data = native.read(&shard, &name, 8 * 1024 * 1024)?;
                        let mut value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
                        fill_json_identity(&mut value, &files, &mut native);
                        package(
                            &root,
                            &format!("{}/{}", basename(&shard).unwrap_or_default(), name),
                            &value,
                            &data,
                            false,
                        )
                    })();
                    match item {
                        Ok(item) => retain_package(&mut report, item, &mut retained_package_bytes)?,
                        Err(e) => {
                            // An unreadable index has unknown owners: all cleanup stays blocked.
                            // Continue read-only accounting for the other bounded index rows instead
                            // of losing every package total because one legacy record is oversized.
                            report
                                .issues
                                .push(format!("package_index {}: {e}", entry.display_path));
                            if report.issues.len() >= 256 || cancel.is_cancelled() {
                                return Err("package_index_issue_budget_or_cancellation".into());
                            }
                        }
                    }
                }
            }
        }
        report.index_complete = report.issues.is_empty();
        if children
            .iter()
            .any(|e| basename(e).as_deref() == Some("links"))
        {
            report
                .issues
                .push("global_virtual_store_links_not_resolved".into());
        }
        let references: usize = report.entries.iter().map(|e| e.content.len()).sum();
        if references > 2_000_000 {
            return Err("package_content_reference_budget".into());
        }
        let mut owners: BTreeMap<&str, (Vec<usize>, bool)> = BTreeMap::new();
        for (i, item) in report.entries.iter().enumerate() {
            for digest in &item.content {
                owners.entry(digest.as_str()).or_default().0.push(i);
            }
        }
        let mut stats: Vec<Stats> = (0..report.entries.len())
            .map(|_| Stats::default())
            .collect();
        for shard in native.children(&files)? {
            if basename(&shard).as_deref() == Some(".DS_Store")
                && shard.object_type == ObjectType::File
            {
                continue;
            }
            let Some(prefix) = basename(&shard).filter(|n| hex(n, 2)) else {
                return Err("pnpm_content_shard_layout".into());
            };
            if shard.object_type != ObjectType::Directory {
                return Err("pnpm_content_shard_not_directory".into());
            }
            for entry in native.children(&shard)? {
                let Some(name) = basename(&entry) else {
                    continue;
                };
                let key = format!("{prefix}/{name}");
                let Some((indices, seen)) = owners.get_mut(key.as_str()) else {
                    continue;
                };
                if entry.object_type != ObjectType::File {
                    return Err("linked_or_special_cas_file".into());
                }
                *seen = true;
                for &i in indices.iter() {
                    let stat = &mut stats[i];
                    stat.observed += 1;
                    stat.size = stat
                        .size
                        .zip(exact(&entry.logical_bytes))
                        .and_then(|(a, b)| a.checked_add(b));
                    stat.allocated = stat
                        .allocated
                        .zip(exact(&entry.allocated_bytes))
                        .and_then(|(a, b)| a.checked_add(b));
                    if let Some(n) = entry.hard_link_count.as_ref().and_then(exact) {
                        stat.min = Some(stat.min.map_or(n, |m| m.min(n)));
                        stat.max = Some(stat.max.map_or(n, |m| m.max(n)));
                        if n == 1 {
                            stat.single += 1
                        }
                    } else {
                        stat.links_known = false
                    }
                }
            }
        }
        report.absent_cas = owners
            .iter()
            .filter(|(_, (_, seen))| !*seen)
            .map(|(key, _)| (*key).to_owned())
            .collect();
        drop(owners);
        for (item, stat) in report.entries.iter_mut().zip(stats) {
            item.missing_files = item.content.len().saturating_sub(stat.observed);
            let complete = item.missing_files == 0;
            item.logical_bytes = bytes(stat.size, true);
            item.allocated_bytes = bytes(stat.allocated, true);
            item.min_links = stat.min.filter(|_| stat.links_known);
            item.max_links = stat.max.filter(|_| stat.links_known);
            item.single_link_files = stat.single;
            if !complete {
                item.issues.push("indexed_content_absent".into())
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        report.issues.push(e);
    }
    let (projects, complete, issues) = projects::discover(roots, &mut native);
    report.projects = projects;
    report.project_discovery_complete = complete;
    report.issues.extend(issues);
    for item in &mut report.entries {
        item.projects = report
            .projects
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.packages
                    .contains(&(item.name.clone(), item.version.clone().unwrap_or_default()))
            })
            .map(|(i, _)| i)
            .collect();
        item.eligible = report.index_complete
            && report.project_discovery_complete
            && item.projects.is_empty()
            && item.version.is_some()
            && item.single_link_files > 0
            && result_is_complete(&report.issues);
        if !item.projects.is_empty() {
            item.issues
                .push("observed_installed_project_reference".into());
        }
    }
    report.complete =
        report.index_complete && report.project_discovery_complete && report.issues.is_empty();
    report.entries.sort_by(|a, b| {
        known(&b.logical_bytes)
            .cmp(&known(&a.logical_bytes))
            .then(a.id.cmp(&b.id))
    });
    report
}
fn result_is_complete(issues: &[String]) -> bool {
    issues.is_empty()
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn package(
    root: &ScannedEntry,
    key: &str,
    value: &Value,
    data: &[u8],
    v11: bool,
) -> Result<Item, String> {
    use sha2::{Digest, Sha256};
    let manifest = if v11 {
        value.get("manifest").ok_or("pnpm_manifest_missing")?
    } else {
        value
    };
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let identified = name.is_some() && version.is_some();
    let name = name.unwrap_or("unidentified package").to_owned();
    let version = version.filter(|_| identified).map(str::to_owned);
    if name.len() > 512 || version.as_ref().is_some_and(|v| v.len() > 256) {
        return Err("package_label_budget".into());
    }
    let files = value
        .get("files")
        .and_then(Value::as_object)
        .ok_or("pnpm_files_index_missing")?;
    if files.len() > 100_000 {
        return Err("package_file_budget".into());
    }
    let mut content = BTreeSet::new();
    let mut add = |files: &serde_json::Map<String, Value>| -> Result<(), String> {
        for file in files.values() {
            content.insert(content_key(file, value, v11)?);
            if content.len() > 100_000 {
                return Err("package_file_budget".into());
            }
        }
        Ok(())
    };
    add(files)?;
    if let Some(side_effects) = value.get("sideEffects") {
        for effect in side_effects
            .as_object()
            .ok_or("unsupported_side_effects")?
            .values()
        {
            let effect = effect.as_object().ok_or("unsupported_side_effects")?;
            // v3 stores a full file map; v10/v11 store added/deleted deltas. Keep base
            // ownership across every platform even when a delta deletes a base file.
            if effect.get("deleted").is_some_and(Value::is_array)
                || effect
                    .get("added")
                    .is_some_and(|v| v.get("integrity").is_none())
            {
                if effect
                    .keys()
                    .any(|k| !matches!(k.as_str(), "added" | "deleted"))
                {
                    return Err("unsupported_side_effects_delta".into());
                }
                if let Some(added) = effect.get("added") {
                    add(added.as_object().ok_or("unsupported_side_effects_added")?)?;
                }
            } else {
                add(effect)?;
            }
        }
    }
    let digest = format!("{:x}", Sha256::digest(data));
    // Legacy identity can come from a separate CAS package.json rather than these index bytes.
    // Bind the interpreted label as well, so a changed identity refuses a previously selected ID.
    let selection =
        serde_json::to_string(&(key, &digest, &name, &version)).map_err(|e| e.to_string())?;
    Ok(Item {
        id: token(root, &selection),
        rule_id: "tool.pnpm-package".into(),
        name,
        version,
        path: root.display_path.clone(),
        logical_bytes: bytes(None, false),
        allocated_bytes: bytes(None, false),
        files: content.len(),
        min_links: None,
        max_links: None,
        single_link_files: 0,
        missing_files: 0,
        projects: Vec::new(),
        action: Action::PnpmContent,
        eligible: false,
        issues: if identified {
            Vec::new()
        } else {
            vec!["package_identity_unresolved".into()]
        },
        source: None,
        content: content.into_iter().collect(),
        snapshot_digest: Some(digest),
    })
}
fn content_key(file: &Value, value: &Value, v11: bool) -> Result<String, String> {
    let hash = if v11 {
        let algo = value
            .get("algo")
            .and_then(Value::as_str)
            .ok_or("pnpm_hash_algorithm_missing")?;
        let len = match algo {
            "sha512" => 128,
            "sha256" => 64,
            _ => return Err("pnpm_unsupported_hash".into()),
        };
        let h = file
            .get("digest")
            .and_then(Value::as_str)
            .ok_or("pnpm_digest_missing")?;
        if !hex(h, len) {
            return Err("pnpm_invalid_digest".into());
        }
        h.into()
    } else {
        let integrity = file
            .get("integrity")
            .and_then(Value::as_str)
            .ok_or("pnpm_integrity_missing")?;
        let b = base64::engine::general_purpose::STANDARD
            .decode(
                integrity
                    .strip_prefix("sha512-")
                    .ok_or("pnpm_unsupported_integrity")?,
            )
            .map_err(|e| e.to_string())?;
        if b.len() != 64 {
            return Err("pnpm_digest_length".into());
        }
        b.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    let suffix = if file.get("mode").and_then(Value::as_u64).unwrap_or(0) & 0o111 != 0 {
        "-exec"
    } else {
        ""
    };
    Ok(format!("{}/{}{}", &hash[..2], &hash[2..], suffix))
}
// Old v3 indexes can omit package identity. Resolve it from the indexed native package.json;
// an unresolved row still protects its content references and can never be selected for cleanup.
fn fill_json_identity(value: &mut Value, files: &ScannedEntry, native: &mut Native<'_>) {
    if value.get("name").and_then(Value::as_str).is_some()
        && value.get("version").and_then(Value::as_str).is_some()
    {
        return;
    }
    let metadata = (|| -> Result<Value, String> {
        let key = content_key(&value["files"]["package.json"], value, false)?;
        let (prefix, name) = key.split_once('/').ok_or("invalid_content_key")?;
        let shard = native.child(files, prefix)?;
        let data = native.read(&shard, name, 1024 * 1024)?;
        serde_json::from_slice(&data).map_err(|e| e.to_string())
    })();
    if let Ok(metadata) = metadata
        && let Some(object) = value.as_object_mut()
    {
        for field in ["name", "version"] {
            if let Some(label) = metadata.get(field).and_then(Value::as_str) {
                object.insert(field.into(), Value::String(label.into()));
            }
        }
    }
}

/// Selected single-link content exclusive to the selected package indexes. Other content stays.
pub(super) fn plan(
    report: &Inventory,
    selected: &[String],
    cancel: &CancellationToken,
) -> Result<Vec<ScannedEntry>, String> {
    if !report.complete {
        return Err("complete_inventory_required".into());
    }
    let selected: BTreeSet<_> = selected.iter().collect();
    if selected.is_empty() {
        return Err("explicit_item_selection_required".into());
    }
    let chosen: Vec<_> = report
        .entries
        .iter()
        .filter(|e| selected.contains(&e.id))
        .collect();
    if chosen.len() != selected.len() || chosen.iter().any(|e| !e.eligible) {
        return Err("selected_item_missing_or_ineligible".into());
    }
    let retained: BTreeSet<_> = report
        .entries
        .iter()
        .filter(|e| !selected.contains(&e.id))
        .flat_map(|e| e.content.iter())
        .collect();
    let digests: BTreeSet<_> = chosen
        .iter()
        .flat_map(|e| e.content.iter())
        .filter(|d| !retained.contains(d) && !report.absent_cas.contains(*d))
        .collect();
    if digests.len() > 8192 {
        return Err("selected_file_batch_budget_exceeded".into());
    }
    let root = report.root_entry.as_ref().ok_or("missing_root_identity")?;
    let mut native = Native::new(cancel);
    let files = native.child(root, "files")?;
    let mut shards = BTreeMap::new();
    let mut out = Vec::new();
    for digest in digests {
        let (prefix, name) = digest.split_once('/').ok_or("invalid_content_key")?;
        if !shards.contains_key(prefix) {
            shards.insert(prefix.to_owned(), native.child(&files, prefix)?);
        }
        let file = native.child(&shards[prefix], name)?;
        if file.hard_link_count.as_ref().and_then(exact) == Some(1) {
            out.push(file);
        }
    }
    if out.is_empty() {
        return Err("no_exclusive_single_link_content".into());
    }
    Ok(out)
}

fn retain_package(report: &mut Inventory, item: Item, retained: &mut usize) -> Result<(), String> {
    let bytes = item.content.iter().fold(
        std::mem::size_of::<Item>()
            + item.name.capacity()
            + item.id.capacity()
            + item.path.capacity()
            + item.content.capacity() * std::mem::size_of::<String>(),
        |sum, d| sum.saturating_add(d.capacity()),
    );
    *retained = retained.saturating_add(bytes);
    if *retained > 256 * 1024 * 1024 {
        return Err("package_index_retention_budget".into());
    }
    report.entries.push(item);
    Ok(())
}
