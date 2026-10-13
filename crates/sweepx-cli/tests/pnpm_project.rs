//! Independent CLI contracts use real layouts and preserve unrelated reference owners.
use assert_cmd::Command;
use serde_json::{Value, json};
use std::fs;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;

struct Fixture {
    _temp: tempfile::TempDir,
    base: PathBuf,
    store: PathBuf,
    project: PathBuf,
    content: PathBuf,
}
fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let base = temp.path().canonicalize().unwrap();
    #[cfg(not(unix))]
    let base = temp.path().to_path_buf();
    let store = base.join("store");
    let project = base.join("projects/selected");
    let content = store.join("files/01").join("01".repeat(63));
    fs::create_dir_all(content.parent().unwrap()).unwrap();
    fs::write(&content, b"dependency").unwrap();
    fs::create_dir_all(store.join("index/00")).unwrap();
    let integrity = "sha512-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==";
    fs::write(store.join("index/00/pkg.json"), serde_json::to_vec(&json!({"name":"pkg","version":"1.0.0","files":{"file":{"integrity":integrity,"mode":420,"size":10}}})).unwrap()).unwrap();
    let slot = project.join("node_modules/.pnpm/pkg@1.0.0");
    fs::create_dir_all(&slot).unwrap();
    fs::hard_link(&content, slot.join("file")).unwrap();
    fs::write(
        project.join("node_modules/.modules.yaml"),
        format!("storeDir: {}\nvirtualStoreDir: .pnpm\n", store.display()),
    )
    .unwrap();
    fs::write(project.join("source.ts"), b"source").unwrap();
    fs::write(project.join("pnpm-lock.yaml"), b"lockfileVersion: '9.0'\n").unwrap();
    Fixture {
        _temp: temp,
        base,
        store,
        project,
        content,
    }
}
fn call(f: &Fixture, mode: &str, plan: Option<&str>, trash: bool) -> (i32, Value) {
    let mut cmd = Command::cargo_bin("sweepx").unwrap();
    cmd.timeout(std::time::Duration::from_secs(45))
        .args(["--format", "json", "pnpm-store", "--root"])
        .arg(&f.store)
        .arg("--project-root")
        .arg(f.base.join("projects"))
        .arg("--project")
        .arg(&f.project)
        .args(["--project-mode", mode]);
    if let Some(id) = plan {
        cmd.args(["--plan", id]);
    }
    if trash {
        cmd.arg("--trash");
    }
    let out = cmd.output().unwrap();
    let report = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code().unwrap(), report)
}
#[test]
fn preview_is_stable_and_replaced_plan_refuses_before_any_move() {
    let f = fixture();
    let (code, p) = call(&f, "dependencies", None, false);
    assert_eq!(code, 0, "{p}");
    assert_eq!(p["schema"], "sweepx.pnpm_project.result/v1");
    assert_eq!(p["readOnly"], true);
    assert_eq!(
        p["plan"]["directoryPaths"],
        json!([f.project.join("node_modules")])
    );
    assert_eq!(p["plan"]["contentPaths"], json!([f.content]));
    let id = p["plan"]["id"].as_str().unwrap();
    let (_, next) = call(&f, "dependencies", None, false);
    assert_eq!(next["plan"]["id"], id);
    fs::write(f.project.join("node_modules/changed"), b"new").unwrap();
    let (code, blocked) = call(&f, "dependencies", Some(id), true);
    assert_eq!(code, 8);
    assert_eq!(blocked["blocked"], "project_plan_changed_refresh_preview");
    assert!(blocked["results"].as_array().unwrap().is_empty());
    assert!(f.content.exists());
    assert!(f.project.join("source.ts").exists());
}
#[test]
fn both_modes_preview_and_shared_copy_references_preserve_store() {
    let f = fixture();
    let other = f.base.join("projects/other/node_modules/.pnpm/pkg@1.0.0");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("file"), b"dependency").unwrap();
    for mode in ["dependencies", "project"] {
        let (code, p) = call(&f, mode, None, false);
        assert_eq!(code, 0, "{p}");
        assert_eq!(p["plan"]["contentPaths"], json!([]));
        assert_eq!(p["plan"]["sharedPackages"], json!(["pkg@1.0.0"]));
    }
    let (code, p) = call(&f, "dependencies", Some("obsolete-preview"), true);
    assert_eq!(code, 8);
    assert_eq!(p["blocked"], "project_plan_changed_refresh_preview");
    assert!(f.content.exists());
}
#[cfg(target_os = "macos")]
fn trash_identity(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let s = fs::symlink_metadata(path).unwrap();
    (s.dev(), s.ino())
}
#[cfg(target_os = "macos")]
fn in_native_trash(identity: (u64, u64)) -> bool {
    let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(".Trash");
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|p| trash_identity(&p.path()) == identity)
}
#[test]
#[cfg(target_os = "macos")]
#[ignore = "requires normal macOS process/open-file and native Trash permissions"]
fn native_dependencies_retire_only_deps_and_accounted_cas_links() {
    let f = fixture();
    let directory = trash_identity(&f.project.join("node_modules"));
    let file = trash_identity(&f.content);
    let mut command = Command::cargo_bin("sweepx").unwrap();
    let out = command
        .args(["--format", "json", "pnpm-store", "--project"])
        .arg(&f.project)
        .arg("--trash")
        .output()
        .unwrap();
    let code = out.status.code().unwrap();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(code, 0, "{result}");
    assert!(!f.project.join("node_modules").exists());
    assert!(f.project.join("source.ts").exists());
    assert!(f.project.join("pnpm-lock.yaml").exists());
    assert!(!f.content.exists());
    assert!(in_native_trash(directory));
    assert!(in_native_trash(file));
    assert!(f.store.join("index/00/pkg.json").exists());
}
#[test]
#[cfg(target_os = "macos")]
#[ignore = "requires normal macOS process/open-file and native Trash permissions"]
fn native_whole_project_retires_project_and_exclusive_store_content() {
    let f = fixture();
    let directory = trash_identity(&f.project);
    let file = trash_identity(&f.content);
    let (_, p) = call(&f, "project", None, false);
    let (code, result) = call(&f, "project", p["plan"]["id"].as_str(), true);
    assert_eq!(code, 0, "{result}");
    assert!(!f.project.exists());
    assert!(!f.content.exists());
    assert!(in_native_trash(directory));
    assert!(in_native_trash(file));
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "requires normal macOS process/open-file and native Trash permissions"]
fn native_project_retirement_preserves_another_projects_copy_and_store_object() {
    let f = fixture();
    let other = f.base.join("projects/other/node_modules/.pnpm/pkg@1.0.0");
    fs::create_dir_all(&other).unwrap();
    let copy = other.join("file");
    fs::write(&copy, b"dependency").unwrap();
    let copy_identity = trash_identity(&copy);
    let store_identity = trash_identity(&f.content);
    let (_, p) = call(&f, "project", None, false);
    let (code, result) = call(&f, "project", p["plan"]["id"].as_str(), true);
    assert_eq!(code, 0, "{result}");
    assert!(!f.project.exists());
    assert_eq!(trash_identity(&copy), copy_identity);
    assert_eq!(fs::read(&copy).unwrap(), b"dependency");
    assert_eq!(trash_identity(&f.content), store_identity);
}

#[test]
fn project_only_reports_package_bytes_with_a_json_marker_and_missing_store() {
    let f = fixture();
    fs::write(
        f.project.join("node_modules/.modules.yaml"),
        serde_json::to_vec(
            &json!({"storeDir": f.base.join("absent/v11"), "virtualStoreDir":".pnpm"}),
        )
        .unwrap(),
    )
    .unwrap();
    fs::write(f.project.join("source.ts"), vec![0; 100_000]).unwrap();
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .args(["--format", "json", "pnpm-store", "--project"])
        .arg(&f.project)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["projects"][0]["logicalBytes"]["value"], "10");
    assert_eq!(report["sizeScope"], "installed_pnpm_virtual_stores");
    assert_eq!(report["projects"][0]["storeStatus"], "unavailable");
    assert!(f.project.join("source.ts").exists());
}
#[test]
fn pnpm_help_exposes_automatic_workflows_without_osdk_flags() {
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .args(["pnpm-store", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    for flag in ["--cache-root", "--remove-models", "--plan", "--entry"] {
        assert!(!help.contains(flag), "{help}");
    }
    assert!(help.contains("--project"));
    assert!(help.contains("discovers"));
}
#[test]
fn global_trash_needs_no_selection_when_every_package_is_installed() {
    let f = fixture();
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .args(["--format", "json", "pnpm-store", "--root"])
        .arg(&f.store)
        .arg("--project-root")
        .arg(f.base.join("projects"))
        .arg("--trash")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["selection"], json!([]));
    assert_eq!(report["results"], json!([]));
    assert!(f.content.exists());
}

#[test]
fn automatic_store_discovery_uses_installed_metadata_without_manager_or_home_defaults() {
    let f = fixture();
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .env("HOME", &f.base)
        .env("USERPROFILE", &f.base)
        .env("LOCALAPPDATA", &f.base)
        .env("PATH", f.base.join("absent-bin"))
        .env_remove("PNPM_STORE_DIR")
        .args(["--format", "json", "pnpm-store", "--project-root"])
        .arg(f.base.join("projects"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["stores"].as_array().unwrap().len(), 1);
    assert_eq!(report["inventory"]["root"], f.store.display().to_string());
    assert!(f.content.exists());
}
#[test]
#[cfg(target_os = "macos")]
#[ignore = "requires normal macOS process/open-file and native Trash permissions"]
fn native_bulk_store_trash_selects_all_owners_without_entry() {
    let f = fixture();
    let cas = f.store.join("files/02").join("02".repeat(63));
    fs::create_dir_all(cas.parent().unwrap()).unwrap();
    fs::write(&cas, b"unused content").unwrap();
    let integrity = "sha512-AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg==";
    for i in 0..270 {
        fs::write(f.store.join(format!("index/00/unused-{i}.json")), serde_json::to_vec(&json!({"name":format!("unused-{i}"),"version":"1.0.0","files":{"file":{"integrity":integrity}}})).unwrap()).unwrap();
    }
    let file_identity = trash_identity(&cas);
    let installed_identity = trash_identity(&f.content);
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .args(["--format", "json", "pnpm-store", "--root"])
        .arg(&f.store)
        .arg("--project-root")
        .arg(f.base.join("projects"))
        .arg("--trash")
        .output()
        .unwrap();
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(out.status.success(), "{result}");
    assert_eq!(result["selection"].as_array().unwrap().len(), 270);
    assert!(!cas.exists());
    assert!(in_native_trash(file_identity));
    assert_eq!(trash_identity(&f.content), installed_identity);
    assert_eq!(
        result["results"].as_array().unwrap().last().unwrap()["completedMoves"],
        1
    );
    assert!(f.store.join("index/00/unused-0.json").exists());
}

#[test]
fn automatic_discovery_finds_orphaned_project_local_store() {
    let f = fixture();
    fs::remove_dir_all(f.project.join("node_modules")).unwrap();
    let local = f.project.join(".pnpm-store/v3");
    fs::create_dir_all(local.join("files")).unwrap();
    let out = Command::cargo_bin("sweepx")
        .unwrap()
        .env("HOME", &f.base)
        .env("USERPROFILE", &f.base)
        .env("LOCALAPPDATA", &f.base)
        .env("PATH", f.base.join("absent-bin"))
        .env_remove("PNPM_STORE_DIR")
        .args(["--format", "json", "pnpm-store", "--project-root"])
        .arg(f.base.join("projects"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["inventory"]["root"], local.display().to_string());
}
