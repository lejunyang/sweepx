use super::*;
use base64::Engine;
use serde_json::json;
use std::fs;
fn fixture() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
fn root(temp: &tempfile::TempDir) -> PathBuf {
    #[cfg(unix)]
    {
        temp.path().canonicalize().unwrap()
    }
    #[cfg(windows)]
    {
        temp.path().to_path_buf()
    }
}
fn content(store: &Path, byte: u8, data: &[u8]) -> String {
    let digest = vec![byte; 64];
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let shard = store.join("files").join(&hex[..2]);
    fs::create_dir_all(&shard).unwrap();
    fs::write(shard.join(&hex[2..]), data).unwrap();
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}
fn index(store: &Path, name: &str, files: &[String]) {
    let dir = store.join("index/00");
    fs::create_dir_all(&dir).unwrap();
    let files = files
        .iter()
        .enumerate()
        .map(|(i, integrity)| {
            (
                format!("file-{i}"),
                json!({"integrity":integrity,"size":3,"mode":420}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    fs::write(
        dir.join(format!("{name}.json")),
        serde_json::to_vec(&json!({"name":name,"version":"1.0.0","files":files})).unwrap(),
    )
    .unwrap();
}
#[test]
fn a_single_link_lower_bound_is_not_single_link_authority() {
    let lower = sweepx_platform::lower_bound_u128(1, ReasonCode::ResourceLimit);
    assert_eq!(
        known(&lower),
        Some(1),
        "display can retain an observed bound"
    );
    assert_eq!(
        exact(&lower),
        None,
        "one observed link can hide another link"
    );
    assert_eq!(
        exact(&sweepx_platform::unknown_u128(ReasonCode::Unknown)),
        None
    );
    assert_eq!(exact(&sweepx_platform::known_u128(1)), Some(1));
}
#[test]
fn native_link_facts_shared_indexes_and_project_sizes() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("project");
    fs::create_dir_all(project.join("node_modules/.pnpm/b@1.0.0")).unwrap();
    fs::write(
        project.join("node_modules/.modules.yaml"),
        b"storeDir: /some/store\n",
    )
    .unwrap();
    fs::write(project.join("source.txt"), b"12345").unwrap();
    let a = content(&store, 1, b"abc");
    let shared = content(&store, 2, b"abcde");
    let linked = content(&store, 3, b"xyz");
    fs::hard_link(
        store.join("files/03").join("03".repeat(63)),
        base.join("outside-link"),
    )
    .unwrap();
    index(&store, "a", &[a, shared.clone(), linked]);
    index(&store, "b", &[shared]);
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[project], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    let a = report.entries.iter().find(|e| e.name == "a").unwrap();
    assert_eq!(
        (a.min_links, a.max_links, a.single_link_files),
        (Some(1), Some(2), 2)
    );
    assert_eq!(known(&a.logical_bytes), Some(11));
    assert!(a.eligible);
    let b = report.entries.iter().find(|e| e.name == "b").unwrap();
    assert_eq!(b.max_links, Some(1));
    assert!(
        !b.eligible,
        "copy/clone layout reference must block a single-link package"
    );
    assert_eq!(b.projects, vec![0]);
    assert_eq!(
        known(&report.projects[0].logical_bytes),
        Some(ordinary_total(&base.join("project")))
    );
    assert!(report.projects[0].size_complete);
    let plan = pnpm_cleanup_plan(&report, std::slice::from_ref(&a.id), &cancel).unwrap();
    assert_eq!(
        plan.len(),
        1,
        "shared index content and multi-link content stay"
    );
    assert_eq!(known(&plan[0].logical_bytes), Some(3));
    assert_eq!(plan[0].hard_link_count.as_ref().and_then(known), Some(1));
    revalidate_pnpm_file(&plan[0], &cancel).unwrap();
    let selected_path = store.join("files/01").join("01".repeat(63));
    fs::hard_link(&selected_path, base.join("new-link")).unwrap();
    assert!(revalidate_pnpm_file(&plan[0], &cancel).is_err());
    fs::remove_file(base.join("new-link")).unwrap();
    // An independently written new index acquires the formerly exclusive file after inventory.
    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(vec![1; 64])
    );
    index(&store, "new-owner", &[integrity]);
    assert!(pnpm_cleanup_plan(&report, std::slice::from_ref(&a.id), &cancel).is_err());
}
#[test]
fn oversized_index_preserves_read_only_accounting_but_blocks_all_cleanup() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let file = content(&store, 1, b"abc");
    index(&store, "supported", &[file]);
    fs::File::create(store.join("index/00/oversized.json"))
        .unwrap()
        .set_len(9 * 1024 * 1024)
        .unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(!report.complete && !report.index_complete);
    assert!(report.issues.iter().any(|s| s.contains("oversized.json")));
    let supported = report
        .entries
        .iter()
        .find(|e| e.name == "supported")
        .unwrap();
    assert_eq!(known(&supported.logical_bytes), Some(3));
    assert_eq!(supported.max_links, Some(1));
    assert!(!supported.eligible);
    assert!(pnpm_cleanup_plan(&report, std::slice::from_ref(&supported.id), &cancel).is_err());
}
#[test]
fn malformed_index_and_cancel_never_supply_cleanup_authority() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    fs::create_dir_all(store.join("files/00")).unwrap();
    fs::create_dir_all(store.join("index/00")).unwrap();
    fs::write(store.join("index/00/broken.json"), b"{}").unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(!report.complete);
    assert!(!report.index_complete);
    assert!(pnpm_cleanup_plan(&report, &["anything".into()], &cancel).is_err());
    cancel.cancel();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(!report.complete);
    assert!(report.entries.is_empty());
}
#[test]
fn verified_missing_content_keeps_shared_files_and_supports_later_selections() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let exclusive = content(&store, 1, b"abc");
    let shared = content(&store, 2, b"abcde");
    index(&store, "a", &[exclusive, shared.clone()]);
    index(&store, "b", &[shared]);
    let cancel = CancellationToken::new();
    let before = pnpm_inventory(&store, &[], &cancel);
    let a_id = before
        .entries
        .iter()
        .find(|e| e.name == "a")
        .unwrap()
        .id
        .clone();
    fs::remove_file(store.join("files/01").join("01".repeat(63))).unwrap();
    let after = pnpm_inventory(&store, &[], &cancel);
    assert!(after.complete, "{:?}", after.issues);
    let a = after.entries.iter().find(|e| e.name == "a").unwrap();
    assert_eq!(a.id, a_id);
    assert_eq!(a.missing_files, 1);
    assert_eq!(a.files, 2);
    assert_eq!(known(&a.logical_bytes), Some(5));
    assert!(pnpm_cleanup_plan(&after, std::slice::from_ref(&a.id), &cancel).is_err());
    let both: Vec<_> = after.entries.iter().map(|e| e.id.clone()).collect();
    let plan = pnpm_cleanup_plan(&after, &both, &cancel).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(known(&plan[0].logical_bytes), Some(5));
}
#[test]
fn excessive_project_roots_refuse_before_observation() {
    let roots = vec![PathBuf::from("not-an-admitted-path"); 33];
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(Path::new("also-invalid"), &roots, &cancel);
    assert!(!report.complete);
    assert!(report.entries.is_empty());
    assert!(report.source_root().is_none());
    assert_eq!(report.issues, ["project_root_budget_exceeded"]);
}
#[test]
fn a_size_deadline_does_not_cancel_later_reference_observations() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let a = content(&store, 1, b"abc");
    index(&store, "a", &[a]);
    let cancel = CancellationToken::new();
    let _ = crate::storage_inventory::observe_directories_isolated_deadline(
        &store,
        &cancel,
        Instant::now(),
    );
    assert!(!cancel.is_cancelled());
    assert!(pnpm_inventory(&store, &[], &cancel).complete);
}
#[test]
fn legacy_identity_comes_from_native_package_json_and_unknown_indexes_keep_ownership() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let manifest = content(&store, 1, br#"{"name":"legacy","version":"2.0.0"}"#);
    let shared = content(&store, 2, b"weight");
    let shard = store.join("files/00");
    fs::create_dir_all(&shard).unwrap();
    fs::write(
        shard.join("legacy-index.json"),
        serde_json::to_vec(&json!({
            "files":{"package.json":{"integrity":manifest},"other":{"integrity":shared}}
        }))
        .unwrap(),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.entries[0].name, "legacy");
    assert_eq!(report.entries[0].version.as_deref(), Some("2.0.0"));
    let old_id = report.entries[0].id.clone();
    fs::write(
        store.join("files/01").join("01".repeat(63)),
        br#"{"name":"changed","version":"3.0.0"}"#,
    )
    .unwrap();
    let changed = pnpm_inventory(&store, &[], &cancel);
    assert!(changed.complete, "{:?}", changed.issues);
    assert_eq!(changed.entries[0].name, "changed");
    assert_ne!(changed.entries[0].id, old_id);
    assert!(pnpm_cleanup_plan(&report, &[old_id], &cancel).is_err());
    fs::remove_file(store.join("files/01").join("01".repeat(63))).unwrap();
    let exclusive = content(&store, 3, b"exclusive");
    // A second v3 index has a known identity but shares data with the now unidentifiable index.
    fs::write(
        shard.join("known-index.json"),
        serde_json::to_vec(&json!({
            "name":"known","version":"1.0.0","files":{
                "shared":{"integrity":shared},"exclusive":{"integrity":exclusive}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    let unknown = report.entries.iter().find(|e| e.version.is_none()).unwrap();
    assert!(!unknown.eligible);
    let known = report.entries.iter().find(|e| e.name == "known").unwrap();
    let plan = pnpm_cleanup_plan(&report, std::slice::from_ref(&known.id), &cancel).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(super::known(&plan[0].logical_bytes), Some(9));
}
#[test]
fn cross_platform_build_indexes_protect_shared_base_content() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let shared = content(&store, 1, b"abc");
    let exclusive = content(&store, 2, b"xy");
    let other = content(&store, 3, b"data");
    index(&store, "selected", &[shared.clone(), exclusive]);
    let index = store.join("index/00/unselected.json");
    let cancel = CancellationToken::new();
    for effects in [
        json!({"darwin-arm64":{"native.node":{"integrity":shared.clone()}}}),
        json!({"linux-x64":{"added":{"native.node":{"integrity":shared.clone()}},"deleted":["base"]}}),
    ] {
        fs::write(&index,serde_json::to_vec(&json!({
            "name":"unselected","version":"1.0.0","files":{"base":{"integrity":other}},"sideEffects":effects
        })).unwrap()).unwrap();
        let report = pnpm_inventory(&store, &[], &cancel);
        assert!(report.complete, "{:?}", report.issues);
        let selected = report
            .entries
            .iter()
            .find(|e| e.name == "selected")
            .unwrap();
        let unselected = report
            .entries
            .iter()
            .find(|e| e.name == "unselected")
            .unwrap();
        assert_eq!(unselected.files, 2);
        assert_eq!(known(&unselected.logical_bytes), Some(7));
        let plan = pnpm_cleanup_plan(&report, std::slice::from_ref(&selected.id), &cancel).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(known(&plan[0].logical_bytes), Some(2));
    }
}
#[cfg(unix)]
#[test]
fn linked_content_is_not_admitted() {
    use std::os::unix::fs::symlink;
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let a = content(&store, 1, b"abc");
    index(&store, "a", &[a]);
    let file = store.join("files/01").join("01".repeat(63));
    fs::remove_file(&file).unwrap();
    fs::write(base.join("outside"), b"abc").unwrap();
    symlink(base.join("outside"), file).unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(!report.complete);
    assert!(report.entries.iter().all(|e| !e.eligible));
}
#[cfg(unix)]
#[test]
fn redirected_installed_layout_cannot_become_absent_usage_evidence() {
    use std::os::unix::fs::symlink;
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("project");
    let outside = base.join("outside-modules");
    fs::create_dir_all(outside.join(".pnpm/a@1.0.0")).unwrap();
    fs::create_dir_all(&project).unwrap();
    symlink(&outside, project.join("node_modules")).unwrap();
    let a = content(&store, 1, b"abc");
    index(&store, "a", &[a]);
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[project], &cancel);
    assert!(!report.complete);
    assert!(!report.project_discovery_complete);
    assert!(report.entries.iter().all(|e| !e.eligible));
    assert!(
        report
            .issues
            .iter()
            .any(|e| e.starts_with("linked_node_modules_unresolved"))
    );
}
// APFS refuses these filenames; Linux exercises the native directory discovery contract.
#[cfg(target_os = "linux")]
#[test]
fn lossy_display_paths_cannot_merge_distinct_project_roots() {
    use std::os::unix::ffi::OsStringExt;
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let mut projects = Vec::new();
    for (byte, name) in [(0xff, "a"), (0xfe, "b")] {
        let project = base.join(std::ffi::OsString::from_vec(vec![byte]));
        fs::create_dir_all(project.join(format!("node_modules/.pnpm/{name}@1.0.0"))).unwrap();
        let integrity = content(&store, byte, b"abc");
        index(&store, name, &[integrity]);
        projects.push(project);
    }
    assert_eq!(
        projects[0].display().to_string(),
        projects[1].display().to_string()
    );
    let report = pnpm_inventory(&store, &projects, &CancellationToken::new());
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.projects.len(), 2);
    assert!(
        report
            .entries
            .iter()
            .all(|e| e.projects.len() == 1 && !e.eligible)
    );
}
#[cfg(unix)]
#[test]
fn native_locator_paths_preserve_bytes_even_when_display_paths_collide() {
    use std::os::unix::ffi::OsStringExt;
    let temp = fixture();
    let base = root(&temp);
    let cancel = CancellationToken::new();
    let mut native = Native::new(&cancel);
    let captured = native.root(&base).unwrap();
    let mut paths = Vec::new();
    for byte in [0xff, 0xfe] {
        let name = sweepx_model::NativeName::unix(vec![byte]);
        let expected = base.join(std::ffi::OsString::from_vec(vec![byte]));
        let mut entry = captured.clone();
        entry.native_basename = name.clone();
        entry.display_path = expected.display().to_string();
        let locator = entry.native_locator.as_mut().unwrap();
        locator.scan_root.native_basename = name.clone();
        locator.entry.native_basename = name;
        locator.scan_root_absolute_path = Some(sweepx_model::NativeAbsolutePath::UnixBytes(
            expected.clone().into_os_string().into_vec(),
        ));
        assert_eq!(native::path(&entry).unwrap(), expected);
        let path = native::path(&entry).unwrap();
        paths.push((entry.display_path, path));
    }
    assert_eq!(paths[0].0, paths[1].0);
    assert_ne!(paths[0].1, paths[1].1);
}
#[test]
fn osdk_model_alias_and_download_units_are_separate() {
    let temp = fixture();
    let base = root(&temp);
    let data = base.join("data");
    let cache = base.join("cache");
    let alias = data.join("models/demo");
    let snapshot = alias.join("snapshots/abcd");
    fs::create_dir_all(&snapshot).unwrap();
    let metadata = serde_json::to_vec(
        &json!({"schema":1,"name":"demo","revision":"r1","files":[{"path":"weight","size":4}]}),
    )
    .unwrap();
    fs::write(snapshot.join(".osdk-model.json"), &metadata).unwrap();
    fs::write(snapshot.join("weight"), b"1234").unwrap();
    fs::write(alias.join("current.json"), b"{\"snapshot\":\"abcd\"}").unwrap();
    let download = cache.join("downloads/models/huggingface/owner/repo");
    fs::create_dir_all(&download).unwrap();
    fs::write(download.join("archive"), b"123456").unwrap();
    let project = base.join("project");
    fs::create_dir_all(&project).unwrap();
    fs::write(
        project.join("osdk.toml"),
        b"[models]\ndemo = 'hf:owner/repo@main'\n",
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let report = osdk_inventory(&data, &cache, &[project], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.revalidated_root_path(&cancel).unwrap(), data);
    let mut display_only = report.clone();
    display_only.root = "unrelated display path".into();
    display_only.root_entry.as_mut().unwrap().display_path = "unrelated display path".into();
    assert_eq!(display_only.revalidated_root_path(&cancel).unwrap(), data);
    assert_eq!(report.entries.len(), 2);
    let model = report
        .entries
        .iter()
        .find(|e| e.action == Action::OsdkModelRemove)
        .unwrap();
    assert_eq!(model.projects, vec![0]);
    model.revalidate_model(&cancel).unwrap();
    let dl = report
        .entries
        .iter()
        .find(|e| e.action == Action::TrashDirectory)
        .unwrap();
    assert_eq!(known(&dl.logical_bytes), Some(6));
    assert!(dl.projects.is_empty());
    fs::write(alias.join("current.json"), b"{\"snapshot\":\"changed\"}").unwrap();
    assert!(model.revalidate_model(&cancel).is_err());
    fs::rename(&data, base.join("old-data")).unwrap();
    fs::create_dir(&data).unwrap();
    assert!(display_only.revalidated_root_path(&cancel).is_err());
}

fn ordinary_total(path: &Path) -> u128 {
    fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let m = fs::symlink_metadata(e.path()).unwrap();
            if m.is_dir() {
                ordinary_total(&e.path())
            } else if m.is_file() {
                u128::from(m.len())
            } else {
                0
            }
        })
        .sum()
}
#[test]
fn v11_native_packr_fixture_and_sqlite_layout() {
    let bytes = include_bytes!("fixtures/pnpm-v11-record.msgpack");
    let value = msgpack::decode(bytes).unwrap();
    assert_eq!(value["manifest"]["name"], "get-tsconfig");
    assert_eq!(value["manifest"]["version"], "4.14.3");
    assert_eq!(value["files"].as_object().unwrap().len(), 7);
    assert_eq!(value["files"]["LICENSE"]["size"], 1089);
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    fs::create_dir_all(store.join("files")).unwrap();
    for info in value["files"].as_object().unwrap().values() {
        let hash = info["digest"].as_str().unwrap();
        let shard = store.join("files").join(&hash[..2]);
        fs::create_dir_all(&shard).unwrap();
        let suffix = if info["mode"].as_u64().unwrap() & 0o111 != 0 {
            "-exec"
        } else {
            ""
        };
        fs::write(shard.join(format!("{}{suffix}", &hash[2..])), b"abc").unwrap();
    }
    let db = rusqlite::Connection::open(store.join("index.db")).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=WAL; CREATE TABLE package_index(key TEXT PRIMARY KEY,data BLOB NOT NULL) WITHOUT ROWID;",
    )
    .unwrap();
    db.execute(
        "INSERT INTO package_index VALUES(?1,?2)",
        rusqlite::params!["fixture-key", bytes.as_slice()],
    )
    .unwrap();
    drop(db);
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].single_link_files, 6);
    assert_eq!(known(&report.entries[0].logical_bytes), Some(18));
    let plan = pnpm_cleanup_plan(&report, &[report.entries[0].id.clone()], &cancel).unwrap();
    assert_eq!(plan.len(), 6);
    fs::write(store.join("index.db-wal"), b"pending").unwrap();
    assert!(pnpm_cleanup_plan(&report, &[report.entries[0].id.clone()], &cancel).is_err());
}
