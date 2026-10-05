use super::*;
use std::fs;

fn fixture() -> (tempfile::TempDir, BrowserInstallation, PathBuf) {
    #[cfg(target_os = "linux")]
    let temp = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = temp.path().to_path_buf();
    let profile = root.join("Default");
    fs::create_dir(&profile).unwrap();
    (
        temp,
        BrowserInstallation {
            browser: "test-browser".into(),
            user_data: root,
            cache_data: None,
        },
        profile,
    )
}
fn field(number: u8, value: &[u8]) -> Vec<u8> {
    let mut result = vec![(number << 3) | 2];
    let mut length = value.len();
    while length >= 128 {
        result.push((length as u8 & 127) | 128);
        length >>= 7;
    }
    result.push(length as u8);
    result.extend(value);
    result
}
fn quota(path: &Path, keys: &[(i64, &str)]) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE buckets(id INTEGER PRIMARY KEY,storage_key TEXT,name TEXT)")
        .unwrap();
    for (id, key) in keys {
        db.execute(
            "INSERT INTO buckets VALUES (?1,?2,'_default')",
            rusqlite::params![id, key],
        )
        .unwrap();
    }
}
// Ordinary fixture walk is an independent accounting oracle, not the production classifier.
fn ordinary_bytes(path: &Path) -> u128 {
    fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let metadata = fs::symlink_metadata(&p).unwrap();
            if metadata.is_dir() {
                ordinary_bytes(&p)
            } else if metadata.is_file() {
                u128::from(metadata.len())
            } else {
                0
            }
        })
        .sum()
}

#[test]
fn protobuf_fields_keep_long_partition_keys_and_ignore_cache_name_urls() {
    let mut index = field(1, &field(1, b"workbox-https://wrong.example/"));
    index.extend(field(2, b"https://real.example/"));
    let partitioned = format!(
        "https://real.example:8443/^0https://{}.example/",
        "x".repeat(180)
    );
    index.extend(field(3, partitioned.as_bytes()));
    assert_eq!(
        cache_storage_key(&index).as_deref(),
        Some(partitioned.as_str())
    );
    assert_eq!(
        storage_key_domain(&partitioned).as_deref(),
        Some("real.example")
    );
    let mut conflicting = index.clone();
    conflicting.extend(field(3, b"https://other.example/"));
    assert!(cache_storage_key(&conflicting).is_none());
    assert!(cache_storage_key(&index[..index.len() - 1]).is_none());
    assert!(cache_storage_key(&field(1, b"https://wrong.example/")).is_none());
}

#[test]
fn legacy_indexed_db_pairs_share_key_but_ports_are_distinct() {
    assert_eq!(
        indexed_db_key("https_example.com_0.indexeddb.leveldb").as_deref(),
        Some("https://example.com")
    );
    assert_eq!(
        indexed_db_key("https_example.com_8443.indexeddb.blob").as_deref(),
        Some("https://example.com:8443")
    );
    assert_eq!(
        indexed_db_key("https_example.com_8443.indexeddb.leveldb"),
        indexed_db_key("https_example.com_8443.indexeddb.blob")
    );
    assert!(indexed_db_key("https_example.com_x.indexeddb.blob").is_none());
    assert!(indexed_db_key("https_example.com_65536.indexeddb.blob").is_none());
    assert_eq!(
        storage_key_domain("https://[::1]:8443/^0https://example.com/").as_deref(),
        Some("::1")
    );
}

#[test]
fn native_reports_reconcile_buckets_legacy_pairs_and_unknown_bytes() {
    let (_temp, install, profile) = fixture();
    let web = profile.join("WebStorage");
    for id in [1, 2, 999] {
        fs::create_dir_all(web.join(id.to_string()).join("IndexedDB")).unwrap();
        fs::write(
            web.join(id.to_string()).join("IndexedDB").join("payload"),
            vec![0; id as usize],
        )
        .unwrap();
    }
    quota(
        &web.join("QuotaManager"),
        &[
            (1, "https://same.example/^0https://first.example/"),
            (2, "https://same.example/^0https://second.example/"),
        ],
    );
    let legacy = profile.join("IndexedDB");
    for (suffix, length) in [("leveldb", 7), ("blob", 11)] {
        let dir = legacy.join(format!("https_same.example_8443.indexeddb.{suffix}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("payload"), vec![0; length]).unwrap();
    }
    let cache = profile.join("Service Worker").join("CacheStorage");
    let hash = cache.join("hash");
    fs::create_dir_all(&hash).unwrap();
    fs::write(hash.join("index.txt"), field(3, b"https://same.example/")).unwrap();
    fs::write(hash.join("payload"), [1; 13]).unwrap();
    let analysis = analyze_site_storage(&[install], None, &CancellationToken::new());
    assert!(analysis.complete, "{analysis:?}");
    let web_report = analysis
        .profiles
        .iter()
        .find(|r| r.subsystem == "web_storage")
        .unwrap();
    assert_eq!(
        web_report
            .subsystem_bytes
            .as_ref()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        ordinary_bytes(&web)
    );
    assert!(web_report.size_complete);
    assert_eq!(web_report.origins.len(), 2);
    assert_ne!(
        web_report.origins[0].storage_key,
        web_report.origins[1].storage_key
    );
    assert!(
        web_report
            .origins
            .iter()
            .all(|o| o.domain == "same.example")
    );
    assert_eq!(
        web_report
            .origins
            .iter()
            .map(|o| o.bytes.as_ref().unwrap().parse::<u128>().unwrap())
            .sum::<u128>(),
        3
    );
    assert_eq!(
        web_report
            .unattributed_bytes
            .as_ref()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        ordinary_bytes(&web) - 3
    );
    assert!(!web_report.fully_attributed);
    let legacy_report = analysis
        .profiles
        .iter()
        .find(|r| r.subsystem == "indexed_db")
        .unwrap();
    assert!(legacy_report.fully_attributed);
    assert_eq!(legacy_report.origins[0].directory_count, 2);
    assert_eq!(legacy_report.origins[0].bytes.as_deref(), Some("18"));
    let cache_report = analysis
        .profiles
        .iter()
        .find(|r| r.subsystem == "service_worker_cache_storage")
        .unwrap();
    assert!(cache_report.fully_attributed);
    assert_eq!(
        cache_report
            .subsystem_bytes
            .as_ref()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        ordinary_bytes(&cache)
    );
}

#[test]
fn corrupt_quota_mapping_preserves_size_and_reports_failure() {
    let (_temp, install, profile) = fixture();
    let web = profile.join("WebStorage");
    fs::create_dir_all(web.join("1")).unwrap();
    fs::write(web.join("1").join("payload"), [0; 123]).unwrap();
    fs::write(web.join("QuotaManager"), b"not SQLite").unwrap();
    let analysis = analyze_site_storage(&[install], None, &CancellationToken::new());
    assert!(!analysis.complete);
    let report = &analysis.profiles[0];
    assert!(report.size_complete);
    assert!(report.origins.is_empty());
    assert_eq!(
        report
            .subsystem_bytes
            .as_ref()
            .unwrap()
            .parse::<u128>()
            .unwrap(),
        ordinary_bytes(&web)
    );
    assert!(!report.issues.is_empty());
}

#[cfg(unix)]
#[test]
fn linked_index_cannot_attribute_an_external_sites_data() {
    let (temp, install, profile) = fixture();
    let index = temp.path().join("external-index");
    fs::write(&index, field(3, b"https://external.example/")).unwrap();
    let bucket = profile
        .join("Service Worker")
        .join("CacheStorage")
        .join("bucket");
    fs::create_dir_all(&bucket).unwrap();
    fs::write(bucket.join("payload"), [0; 17]).unwrap();
    std::os::unix::fs::symlink(index, bucket.join("index.txt")).unwrap();
    let analysis = analyze_site_storage(&[install], None, &CancellationToken::new());
    assert!(!analysis.complete);
    assert!(analysis.profiles[0].origins.is_empty());
    assert_eq!(
        analysis.profiles[0].unattributed_bytes.as_deref(),
        Some("17")
    );
}

#[test]
fn cancelled_discovery_is_explicit_not_successful_empty() {
    let (_temp, install, _profile) = fixture();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let analysis = analyze_site_storage(&[install], None, &cancel);
    assert!(!analysis.complete);
    assert!(analysis.profiles.is_empty());
}

#[test]
fn oversized_quota_metadata_is_refused_without_losing_known_size() {
    let (_temp, install, profile) = fixture();
    let web = profile.join("WebStorage");
    fs::create_dir_all(web.join("1")).unwrap();
    fs::write(web.join("1/payload"), [0; 37]).unwrap();
    fs::File::create(web.join("QuotaManager"))
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    let analysis = analyze_site_storage(&[install], None, &CancellationToken::new());
    assert!(!analysis.complete);
    let report = &analysis.profiles[0];
    assert!(report.size_complete);
    assert!(report.origins.is_empty());
    assert_eq!(report.subsystem_bytes.as_deref(), Some("16777254"));
}

#[test]
fn exact_profile_filter_avoids_other_profiles_and_cache_alias_is_not_recounted() {
    let (_temp, mut install, profile) = fixture();
    fs::create_dir_all(profile.join("IndexedDB/https_chosen.example_0.indexeddb.blob")).unwrap();
    fs::write(
        profile.join("IndexedDB/https_chosen.example_0.indexeddb.blob/payload"),
        [0; 19],
    )
    .unwrap();
    fs::create_dir_all(install.user_data.join("Profile 1/WebStorage")).unwrap();
    fs::write(
        install.user_data.join("Profile 1/WebStorage/QuotaManager"),
        b"invalid",
    )
    .unwrap();
    install.cache_data = Some(install.user_data.clone());
    let analysis = analyze_site_storage(&[install], Some("Default"), &CancellationToken::new());
    assert!(analysis.complete, "{analysis:?}");
    assert_eq!(analysis.profiles.len(), 1);
    assert_eq!(analysis.profiles[0].subsystem_bytes.as_deref(), Some("19"));
}

#[test]
fn installation_model_is_visible_without_becoming_a_domain_or_junk_candidate() {
    let (_temp, install, _profile) = fixture();
    let model = install.user_data.join("OptGuideOnDeviceModel/version");
    fs::create_dir_all(&model).unwrap();
    fs::write(model.join("weights.bin"), [0; 41]).unwrap();
    let analysis = analyze_site_storage(&[install], None, &CancellationToken::new());
    assert!(analysis.complete);
    assert_eq!(analysis.profiles.len(), 1);
    let report = &analysis.profiles[0];
    assert_eq!(report.profile_name, "@installation");
    assert_eq!(report.subsystem, "on_device_model_shared");
    assert_eq!(report.subsystem_bytes.as_deref(), Some("41"));
    assert_eq!(report.unattributed_bytes.as_deref(), Some("41"));
    assert!(report.origins.is_empty());
}

#[test]
fn browser_managed_plan_has_exact_origins_without_paths_or_cookie_authority() {
    let (_temp, mut install, profile) = fixture();
    install.browser = "edge".into();
    let storage = profile.join("IndexedDB");
    fs::create_dir_all(storage.join("https_chosen.example_443.indexeddb.leveldb")).unwrap();
    fs::create_dir_all(storage.join("https_chosen.example_8443.indexeddb.blob")).unwrap();
    fs::create_dir_all(storage.join("https_other.example_0.indexeddb.leveldb")).unwrap();
    let analysis = analyze_site_storage(&[install], Some("Default"), &CancellationToken::new());
    let plan = cleanup_plan(&analysis, "edge", "Default", "CHOSEN.EXAMPLE").unwrap();
    assert_eq!(
        plan.origins,
        vec!["https://chosen.example", "https://chosen.example:8443"]
    );
    assert!(!plan.recoverable);
    assert_eq!(
        plan.profile_binding,
        "explicit_user_confirmation_in_browser"
    );
    assert!(
        !serde_json::to_string(&plan)
            .unwrap()
            .contains("subsystemPath")
    );
    assert!(cleanup_plan(&analysis, "edge", "Default", "absent.example").is_err());
    assert!(cleanup_plan(&analysis, "edge", "../Default", "chosen.example").is_err());
}

#[test]
fn model_versions_bind_component_metadata_and_preserve_unknown_assets() {
    let (_temp, mut install, _profile) = fixture();
    install.browser = "chrome".into();
    let path = install
        .user_data
        .join("OptGuideOnDeviceModel/2025.8.8.1141");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("manifest.json"),r#"{"name":"Optimization Guide On Device Model","version":"2025.8.8.1141","manifest_version":2}"#).unwrap();
    fs::write(path.join("on_device_model_execution_config.pb"), [1u8, 2]).unwrap();
    fs::write(path.join("weights.bin"), [3u8; 17]).unwrap();
    let inventory = models::inventory(&install, &CancellationToken::new());
    assert!(inventory.complete);
    assert_eq!(inventory.versions.len(), 1);
    let row = &inventory.versions[0];
    assert_eq!(
        row.bytes.as_ref().unwrap().parse::<u128>().unwrap(),
        ordinary_bytes(&path)
    );
    row.revalidate(&CancellationToken::new()).unwrap();
    fs::write(
        path.join("manifest.json"),
        r#"{"name":"Another model","version":"2025.8.8.1141","manifest_version":2}"#,
    )
    .unwrap();
    assert!(row.revalidate(&CancellationToken::new()).is_err());
    let inventory = models::inventory(&install, &CancellationToken::new());
    assert!(!inventory.versions[0].complete);
    let prediction = install.user_data.join("OptimizationGuidePredictionModels");
    fs::create_dir(&prediction).unwrap();
    fs::write(prediction.join("keep"), [9u8; 100]).unwrap();
    assert_eq!(
        models::inventory(&install, &CancellationToken::new())
            .versions
            .len(),
        1
    );
    assert!(prediction.join("keep").exists());
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(row.revalidate(&cancel).is_err());
}
