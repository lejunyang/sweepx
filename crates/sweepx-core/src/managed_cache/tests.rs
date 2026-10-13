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
        Some(ordinary_total(&base.join("project/node_modules/.pnpm")))
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

fn project_layout(project: &Path, store: &Path, name: &str) -> PathBuf {
    let slot = project.join(format!("node_modules/.pnpm/{name}@1.0.0"));
    fs::create_dir_all(&slot).unwrap();
    fs::write(
        project.join("node_modules/.modules.yaml"),
        format!("storeDir: {}\nvirtualStoreDir: .pnpm\n", store.display()),
    )
    .unwrap();
    fs::write(project.join("package.json"), b"{\"private\":true}").unwrap();
    slot
}
#[test]
fn project_plan_accounts_links_and_preserves_other_project_and_index_owners() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("projects/a");
    let other = base.join("projects/b");
    let a = content(&store, 1, b"one");
    let b = content(&store, 2, b"two");
    let common = content(&store, 3, b"shared");
    index(&store, "a", &[a, common.clone()]);
    index(&store, "b", &[b, common]);
    let slot = project_layout(&project, &store, "a");
    fs::hard_link(
        store.join("files/01").join("01".repeat(63)),
        slot.join("one"),
    )
    .unwrap();
    project_layout(&other, &store, "b");
    let cancel = CancellationToken::new();
    let report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert!(
        report.projects.iter().all(|p| !p.size_complete),
        "unrelated project totals are not traversed"
    );
    let plan =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    assert_eq!(
        plan.directory_paths,
        vec![project.join("node_modules").display().to_string()]
    );
    assert_eq!(plan.content().len(), 1);
    assert_eq!(
        plan.content()[0].hard_link_count.as_ref().and_then(exact),
        Some(2)
    );
    assert_eq!(
        plan.retained_content_files, 1,
        "another package index protects shared CAS content"
    );
    let again = pnpm_project_plan(
        &pnpm_project_inventory(&store, &[base.join("projects")], &cancel),
        &project,
        PnpmProjectMode::Dependencies,
        &cancel,
    )
    .unwrap();
    assert_eq!(
        plan.id, again.id,
        "fresh invocation and enumeration ordering must not change a stable preview"
    );
    fs::rename(
        project.join("node_modules"),
        base.join("recoverable-dependencies"),
    )
    .unwrap();
    assert!(
        revalidate_project_content(&plan.content()[0], &cancel).is_ok(),
        "moving dependency directory preserves accounted hard links"
    );
    assert!(project.join("package.json").exists());
    fs::hard_link(
        store.join("files/01").join("01".repeat(63)),
        base.join("racing-link"),
    )
    .unwrap();
    assert!(revalidate_project_content(&plan.content()[0], &cancel).is_err());
}
#[test]
fn copied_project_reference_and_unknown_external_links_keep_store_content() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("projects/a");
    let other = base.join("projects/b");
    let a = content(&store, 1, b"one");
    index(&store, "a", &[a]);
    let slot = project_layout(&project, &store, "a");
    fs::write(slot.join("copied"), b"one").unwrap();
    project_layout(&other, &store, "a");
    let cancel = CancellationToken::new();
    let report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    let plan =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    assert_eq!(plan.shared_packages, vec!["a@1.0.0"]);
    assert!(plan.content().is_empty());
    fs::remove_dir_all(other).unwrap();
    fs::hard_link(
        store.join("files/01").join("01".repeat(63)),
        base.join("unknown-user"),
    )
    .unwrap();
    let report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    let plan = pnpm_project_plan(&report, &project, PnpmProjectMode::Project, &cancel).unwrap();
    assert_eq!(plan.directory_paths, vec![project.display().to_string()]);
    assert!(plan.content().is_empty());
    assert_eq!(plan.retained_content_files, 1);
}
#[test]
fn project_preview_changes_on_install_mutation_and_refuses_store_overlap() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("projects/a");
    let a = content(&store, 1, b"one");
    index(&store, "a", &[a]);
    let slot = project_layout(&project, &store, "a");
    let cancel = CancellationToken::new();
    let report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    let first =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    fs::write(slot.join("racing-install"), b"new").unwrap();
    let second =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    assert_ne!(first.id, second.id);
    let local = project.join(".pnpm-store/v10");
    let a = content(&local, 2, b"two");
    index(&local, "a", &[a]);
    project_layout(&project, &local, "a");
    let report = pnpm_project_inventory(&local, std::slice::from_ref(&project), &cancel);
    assert!(
        pnpm_project_plan(&report, &project, PnpmProjectMode::Project, &cancel)
            .unwrap_err()
            .contains("store_inside")
    );
    assert!(pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).is_ok());
}
#[test]
fn project_dependencies_include_workspace_children_and_bind_marker_changes() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("projects/a");
    let a = content(&store, 1, b"one");
    index(&store, "a", &[a]);
    project_layout(&project, &store, "a");
    project_layout(&project.join("packages/app"), &store, "a");
    let cancel = CancellationToken::new();
    let report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    let plan =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    assert_eq!(plan.directories().len(), 2);
    assert_eq!(plan.content().len(), 1);
    fs::write(
        project.join("node_modules/.modules.yaml"),
        b"storeDir: /changed\n",
    )
    .unwrap();
    assert!(pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).is_err());
}

#[test]
fn project_package_totals_exclude_sources_and_deduplicate_workspace_hard_links() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("workspace");
    let child = project.join("packages/child");
    for p in [&project, &child] {
        fs::create_dir_all(p.join("node_modules/.pnpm/pkg@1.0.0")).unwrap();
        fs::write(
            p.join("node_modules/.modules.yaml"),
            serde_json::to_vec(&json!({"storeDir":store,"virtualStoreDir":".pnpm"})).unwrap(),
        )
        .unwrap();
        fs::write(p.join("source"), vec![0; 100_000]).unwrap();
    }
    let file = project.join("node_modules/.pnpm/pkg@1.0.0/file");
    fs::write(&file, b"1234567").unwrap();
    fs::hard_link(&file, child.join("node_modules/.pnpm/pkg@1.0.0/link")).unwrap();
    fs::write(child.join("node_modules/.pnpm/pkg@1.0.0/own"), b"abc").unwrap();
    let (projects, complete, issues) =
        pnpm_projects(std::slice::from_ref(&project), &CancellationToken::new());
    assert!(complete, "{issues:?}");
    assert_eq!(
        known(
            &projects
                .iter()
                .find(|p| p.directory == project.display().to_string())
                .unwrap()
                .logical_bytes
        ),
        Some(10)
    );
    assert_eq!(
        known(
            &projects
                .iter()
                .find(|p| p.directory == child.display().to_string())
                .unwrap()
                .logical_bytes
        ),
        Some(10)
    );
    assert!(
        projects
            .iter()
            .all(|p| p.size_complete && p.store_dir.as_deref() == store.to_str())
    );
}
#[test]
fn reference_discovery_completes_after_twenty_thousand_source_directories() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let projects = base.join("projects");
    fs::create_dir_all(&projects).unwrap();
    for i in 0..20_050 {
        fs::create_dir(projects.join(format!("source-{i}"))).unwrap();
    }
    let project = projects.join("installed");
    fs::create_dir_all(project.join("node_modules/.pnpm/used@1.0.0")).unwrap();
    let digest = content(&store, 1, b"used");
    index(&store, "used", &[digest]);
    let report = pnpm_inventory(&store, &[projects], &CancellationToken::new());
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.entries[0].projects.len(), 1);
    assert!(!report.entries[0].eligible);
}
#[test]
fn large_streamed_json_preserves_side_effect_ownership() {
    use std::io::Write;
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let shared = content(&store, 1, b"shared");
    let only = content(&store, 2, b"only");
    index(&store, "selected", &[shared.clone(), only]);
    let path = store.join("index/00/large.json");
    let mut file = std::io::BufWriter::new(fs::File::create(&path).unwrap());
    write!(
        file,
        "{{\"name\":\"large\",\"version\":\"1.0.0\",\"files\":{{}},\"metadata\":["
    )
    .unwrap();
    for _ in 0..2_000_000 {
        file.write_all(b"null,").unwrap();
    }
    write!(file,"null],\"sideEffects\":{{\"linux\":{{\"added\":{{\"addon\":{{\"integrity\":\"{shared}\"}}}},\"deleted\":[\"base\"]}}}}}}").unwrap();
    file.flush().unwrap();
    drop(file);
    assert!(fs::metadata(path).unwrap().len() > 8 * 1024 * 1024);
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    let selected = report
        .entries
        .iter()
        .find(|e| e.name == "selected")
        .unwrap();
    let plan = pnpm_cleanup_plan(&report, std::slice::from_ref(&selected.id), &cancel).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(known(&plan[0].logical_bytes), Some(4));
}
#[test]
fn bulk_selection_accounts_shared_owners_across_the_old_selection_limit() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let digest = content(&store, 1, b"shared");
    for i in 0..300 {
        index(&store, &format!("pkg{i}"), std::slice::from_ref(&digest));
    }
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    let selected = report
        .entries
        .iter()
        .map(|e| e.id.clone())
        .collect::<Vec<_>>();
    let mut observed = Vec::new();
    pnpm_cleanup_batches(&report, &selected, &cancel, &mut |batch| {
        assert!(batch.len() <= 128);
        observed.extend_from_slice(batch);
        Ok(())
    })
    .unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(known(&observed[0].logical_bytes), Some(6));
}

#[test]
fn invocation_project_observations_never_authorize_cleanup_after_a_new_reference() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let projects = base.join("projects");
    fs::create_dir(&projects).unwrap();
    let digest = content(&store, 1, b"used");
    index(&store, "pkg", &[digest]);
    let cancel = CancellationToken::new();
    let observations = pnpm_observe_projects(std::slice::from_ref(&projects), &cancel);
    fs::create_dir_all(projects.join("new/node_modules/.pnpm/pkg@1.0.0")).unwrap();
    let report = pnpm_inventory_observed(&store, &observations, &cancel);
    assert!(report.entries[0].eligible, "{:?}", report.issues);
    let mut called = false;
    let result = pnpm_cleanup_batches(
        &report,
        std::slice::from_ref(&report.entries[0].id),
        &cancel,
        &mut |_| {
            called = true;
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(!called);
}
#[test]
fn native_batches_cover_more_than_eight_thousand_exclusive_files() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    fs::create_dir_all(store.join("index/00")).unwrap();
    let mut records = serde_json::Map::new();
    for i in 0..8_250u64 {
        let mut hash = [0u8; 64];
        hash[..8].copy_from_slice(&i.to_le_bytes());
        let hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let path = store.join("files").join(&hex[..2]).join(&hex[2..]);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"x").unwrap();
        records.insert(format!("file-{i}"),json!({"integrity":format!("sha512-{}",base64::engine::general_purpose::STANDARD.encode(hash))}));
    }
    fs::write(
        store.join("index/00/pkg.json"),
        serde_json::to_vec(&json!({"name":"pkg","version":"1.0.0","files":records})).unwrap(),
    )
    .unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(known(&report.cleanup_logical_bytes), Some(8_250));
    let mut count = 0usize;
    pnpm_cleanup_batches(
        &report,
        std::slice::from_ref(&report.entries[0].id),
        &cancel,
        &mut |batch| {
            assert!(batch.len() <= 128);
            count += batch.len();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(count, 8_250);
}

#[test]
fn legacy_effect_filenames_and_delta_manifests_do_not_change_base_identity() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let digest = content(&store, 1, b"effect");
    index(&store, "pkg", std::slice::from_ref(&digest));
    let path = store.join("index/00/pkg.json");
    fs::write(&path,serde_json::to_vec(&json!({"name":"pkg","version":"1.0.0","files":{},"sideEffects":{"darwin":{"added":{"integrity":digest,"mode":493},"deleted":{"integrity":digest}}}})).unwrap()).unwrap();
    let cancel = CancellationToken::new();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert_eq!(report.entries[0].files, 2);
    let manifest = content(&store, 2, br#"{"name":"effect-only","version":"2.0.0"}"#);
    fs::write(&path,serde_json::to_vec(&json!({"files":{},"sideEffects":{"linux":{"added":{"package.json":{"integrity":manifest}},"deleted":[]}}})).unwrap()).unwrap();
    let report = pnpm_inventory(&store, &[], &cancel);
    assert!(report.complete, "{:?}", report.issues);
    assert!(report.entries[0].version.is_none());
    assert!(!report.entries[0].eligible);
}

#[test]
fn automatic_discovery_finds_project_local_store_without_installed_dependencies() {
    let temp = fixture();
    let base = root(&temp);
    let local = base.join("retired/.pnpm-store/v3");
    fs::create_dir_all(local.join("files")).unwrap();
    let cancel = CancellationToken::new();
    let (_, complete, issues, hints) =
        projects::discover_store_hints(std::slice::from_ref(&base), &mut Native::new(&cancel));
    assert!(complete, "{issues:?}");
    assert!(
        hints.contains(&base.join("retired/.pnpm-store")),
        "{hints:?}"
    );
    let container = pnpm_locations(
        Some(&base.join("retired/.pnpm-store")),
        &[],
        &CancellationToken::new(),
    );
    assert_eq!(container.stores, vec![local]);
    assert!(container.issues.is_empty());
}

#[test]
fn project_display_labels_cannot_redirect_native_cleanup_targets() {
    let temp = fixture();
    let base = root(&temp);
    let store = base.join("store");
    let project = base.join("projects/selected");
    let digest = content(&store, 1, b"dependency");
    index(&store, "pkg", &[digest]);
    project_layout(&project, &store, "pkg");
    let cancel = CancellationToken::new();
    let mut report = pnpm_project_inventory(&store, &[base.join("projects")], &cancel);
    report.projects[0].directory = base.join("unrelated").display().to_string();
    let plan =
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap();
    assert_eq!(
        plan.directory_paths,
        vec![project.join("node_modules").display().to_string()]
    );
    fs::rename(&project, base.join("replaced")).unwrap();
    project_layout(&project, &store, "pkg");
    assert_eq!(
        pnpm_project_plan(&report, &project, PnpmProjectMode::Dependencies, &cancel).unwrap_err(),
        "selected_project_identity_changed"
    );
}

#[test]
fn missing_virtual_store_is_unknown_rather_than_a_zero_package_total() {
    let temp = fixture();
    let base = root(&temp);
    let project = base.join("project");
    fs::create_dir_all(project.join("node_modules")).unwrap();
    fs::write(
        project.join("node_modules/.modules.yaml"),
        b"storeDir: /missing/store\nvirtualStoreDir: custom\n",
    )
    .unwrap();
    let (projects, complete, issues) = pnpm_projects(&[project], &CancellationToken::new());
    assert!(!complete);
    assert!(!issues.is_empty());
    assert_eq!(projects.len(), 1);
    assert!(matches!(
        projects[0].logical_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert!(!projects[0].size_complete);
}
