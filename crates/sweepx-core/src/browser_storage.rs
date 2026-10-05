//! Browser application data is a separate, read-only analysis, never generic junk.
//!
//! Sizes reuse the native scanner. Attribution reads only bounded, identity-bound metadata;
//! paths in this report are display information, not authority to remove a directory. Chromium's
//! on-disk formats are internal: unknown directories and unsupported metadata stay visible.

/// Positively identified Chrome foundation-model versions and policy export.
#[path = "browser_storage_models.rs"]
pub mod models;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::storage_inventory::{entry_bytes, observe_directories};
use rusqlite::Connection;
use serde::Serialize;
use sweepx_model::{NativeName, ScannedEntry};
use sweepx_platform::CancellationToken;
use sweepx_scanner::{HostPlatformScanner, LocatorReadLimits, LocatorReader};

use crate::junk::layout::{LayoutDiscovery, LayoutDiscoveryLimits};
use crate::junk::native_rule_name;

const MAX_PROFILES: usize = 32;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_QUOTA_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUCKETS: usize = 16_384;
const MAX_KEY_BYTES: usize = 4096;
const MAX_REPORT_ORIGIN_BYTES: usize = 16 * 1024 * 1024;
const MAX_ORIGIN_ROWS: usize = 4096;

#[derive(Default)]
struct MetadataBudget {
    bytes: usize,
    requests: usize,
    origin_bytes: usize,
    origin_rows: usize,
}

/// Explicit installation root. Custom locations can be supplied without changing discovery.
#[derive(Debug, Clone)]
pub struct BrowserInstallation {
    /// Stable browser/channel label, independent of locale.
    pub browser: String,
    /// User Data root, containing Default and/or Profile directories.
    pub user_data: PathBuf,
    /// Optional mirrored profile cache root on platforms that separate cache and user data.
    pub cache_data: Option<PathBuf>,
}

/// Conservative default locations; redirected and non-default StoragePartitions are not inferred.
pub fn default_installations() -> Vec<BrowserInstallation> {
    #[cfg(target_os = "windows")]
    let locations = std::env::var_os("LOCALAPPDATA").map(|base| {
        crate::junk::platform::CHROMIUM_INSTALLS
            .iter()
            .zip([
                "edge",
                "edge-dev",
                "edge-beta",
                "chrome",
                "chrome-beta",
                "chrome-dev",
                "brave",
                "vivaldi",
            ])
            .map(|(install, label)| (label, install.relative_user_data))
            .map(|(label, relative)| BrowserInstallation {
                browser: label.to_string(),
                user_data: relative
                    .split('/')
                    .fold(PathBuf::from(&base), |p, c| p.join(c)),
                cache_data: None,
            })
            .collect::<Vec<_>>()
    });
    #[cfg(target_os = "macos")]
    let locations = std::env::var_os("HOME").map(|base| {
        [
            ("edge", "Microsoft Edge"),
            ("edge-beta", "Microsoft Edge Beta"),
            ("edge-dev", "Microsoft Edge Dev"),
            ("chrome", "Google/Chrome"),
            ("chrome-beta", "Google/Chrome Beta"),
            ("chrome-dev", "Google/Chrome Dev"),
            ("brave", "BraveSoftware/Brave-Browser"),
            ("vivaldi", "Vivaldi"),
        ]
        .into_iter()
        .map(|(label, relative)| BrowserInstallation {
            browser: label.to_string(),
            user_data: relative.split('/').fold(
                PathBuf::from(&base)
                    .join("Library")
                    .join("Application Support"),
                |p, c| p.join(c),
            ),
            cache_data: Some(relative.split('/').fold(
                PathBuf::from(&base).join("Library").join("Caches"),
                |p, c| p.join(c),
            )),
        })
        .collect::<Vec<_>>()
    });
    #[cfg(target_os = "linux")]
    let locations = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|base| PathBuf::from(base).join(".config")))
        .map(|base| {
            [
                ("edge", "microsoft-edge"),
                ("edge-beta", "microsoft-edge-beta"),
                ("edge-dev", "microsoft-edge-dev"),
                ("chrome", "google-chrome"),
                ("chrome-beta", "google-chrome-beta"),
                ("chrome-dev", "google-chrome-unstable"),
                ("chromium", "chromium"),
                ("brave", "BraveSoftware/Brave-Browser"),
                ("vivaldi", "vivaldi"),
            ]
            .into_iter()
            .map(|(label, relative)| BrowserInstallation {
                browser: label.to_string(),
                user_data: relative.split('/').fold(base.clone(), |p, c| p.join(c)),
                cache_data: std::env::var_os("XDG_CACHE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
                    })
                    .filter(|cache| cache.is_absolute())
                    .map(|cache| relative.split('/').fold(cache, |p, c| p.join(c))),
            })
            .collect::<Vec<_>>()
        });
    locations
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.user_data.is_absolute())
        .collect()
}

/// One complete browser-recorded storage key and, for WebStorage, its concrete bucket.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginUsage {
    /// Raw serialized key: partition, port and other suffixes are preserved byte-for-byte.
    pub storage_key: String,
    /// Display grouping only. A domain is not a bucket or an execution identity.
    pub domain: String,
    /// Logical bytes as a decimal string; None means unavailable, never zero.
    pub bytes: Option<String>,
    /// Whether all constituent directory totals are known with complete native coverage.
    pub complete: bool,
    /// Directories represented by this row; LevelDB/blob pairs share one legacy row.
    pub directory_count: usize,
    /// Display paths only, useful for reviewing a future explicit selection.
    pub directories: Vec<PathBuf>,
    /// Numeric WebStorage bucket ID, absent for legacy layouts.
    pub bucket_id: Option<i64>,
    /// Browser-recorded bucket name, absent for legacy layouts.
    pub bucket_name: Option<String>,
}

/// One profile/subsystem observation. Unattributed bytes include metadata and shared databases.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteStorageReport {
    /// Stable browser/channel label.
    pub browser: String,
    /// Browser/profile display label retained for the existing result/v1 format.
    pub profile: String,
    /// Exact profile directory basename, or @installation for shared installation data.
    pub profile_name: String,
    /// Stable subsystem label.
    pub subsystem: String,
    /// Display path of the measured subsystem, not execution authority.
    pub subsystem_path: PathBuf,
    /// Logical total; unavailable totals serialize as null.
    pub subsystem_bytes: Option<String>,
    /// Complete filesystem coverage and a known logical total, independent of attribution.
    pub size_complete: bool,
    /// True only when every observed byte was assigned and attribution observations succeeded.
    pub fully_attributed: bool,
    /// Known/lower-bound bytes outside attributed rows, or null when accounting is unavailable.
    pub unattributed_bytes: Option<String>,
    /// Native observations are not an atomic snapshot across files or browser databases.
    pub snapshot_consistency: &'static str,
    /// Concrete keys/buckets, sorted largest first.
    pub origins: Vec<OriginUsage>,
    /// Bounded diagnostics. Errors never become an empty successful result.
    pub issues: Vec<String>,
}

/// Result of one invocation; data is report-only even when all byte totals are complete.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserStorageAnalysis {
    /// Profile and @installation subsystem observations, including shared data.
    pub profiles: Vec<SiteStorageReport>,
    /// False for discovery/scan/metadata failures, cancellation or resource exhaustion.
    pub complete: bool,
    /// Installation/profile discovery failures, separate from per-subsystem errors.
    pub issues: Vec<String>,
}

/// Runs off the UI thread and reuses native no-follow, volume and permission boundaries.
///
/// At most 32 profiles, 64 MiB of metadata reads and bounded scanner state are admitted. The
/// two-minute cooperative deadline is checked between scanner observations; native OS calls can
/// still delay cancellation. A live QuotaManager main-file observation does not replay WAL/journal
/// state or establish an atomic mapping, and must never authorize removal of a modern bucket.
/// `profile_filter` restricts work before any profile subsystem is opened or traversed.
pub fn analyze_site_storage(
    installations: &[BrowserInstallation],
    profile_filter: Option<&str>,
    cancel: &CancellationToken,
) -> BrowserStorageAnalysis {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut discovery = LayoutDiscovery::new(
        LayoutDiscoveryLimits {
            deadline: Duration::from_secs(120),
            ..Default::default()
        },
        cancel.clone(),
    );
    let mut result = BrowserStorageAnalysis {
        complete: true,
        ..Default::default()
    };
    let mut profiles = 0;
    let mut metadata_bytes = MetadataBudget::default();
    // Do not silently truncate an arbitrary caller-supplied installation list.
    if installations.len() > 32 {
        result.complete = false;
        result.issues.push("installation_limit".into());
        return result;
    }
    for install in installations {
        // Models/components are installation-wide, outside Default/Profile *. They cannot be
        // assigned to domains; report their own totals rather than making a tiny site-data report
        // look like a complete browser footprint. An explicit profile filter excludes this scope.
        if profile_filter.is_none() {
            for (name, subsystem) in [
                ("OptGuideOnDeviceModel", "on_device_model_shared"),
                (
                    "optimization_guide_model_store",
                    "optimization_model_store_shared",
                ),
                ("component_crx_cache", "component_download_cache_shared"),
                ("extensions_crx_cache", "extension_download_cache_shared"),
                ("ProvenanceData", "provenance_data_shared"),
            ] {
                let path = install.user_data.join(name);
                if discovery.directory(&path).is_none() {
                    continue;
                }
                let report = analyze_subsystem(
                    install,
                    "@installation",
                    subsystem,
                    &path,
                    Kind::Shared,
                    cancel,
                    deadline,
                    &mut metadata_bytes,
                );
                result.complete &= report.size_complete && report.issues.is_empty();
                result.profiles.push(report);
            }
        }
        for profile in discovery.profiles(&install.user_data, true).iter() {
            if profile_filter
                .is_some_and(|filter| profile.file_name().and_then(|n| n.to_str()) != Some(filter))
            {
                continue;
            }
            if profiles >= MAX_PROFILES || cancel.is_cancelled() || Instant::now() >= deadline {
                result.complete = false;
                result
                    .issues
                    .push("profile_limit_or_cancelled_or_deadline".into());
                break;
            }
            profiles += 1;
            let Some(profile_root) = discovery.directory(profile) else {
                continue;
            };
            let name = profile
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unresolved");
            for (subsystem, components, kind) in [
                (
                    "service_worker_cache_storage",
                    &["Service Worker", "CacheStorage"][..],
                    Kind::Cache,
                ),
                ("indexed_db", &["IndexedDB"][..], Kind::IndexedDb),
                ("web_storage", &["WebStorage"][..], Kind::WebStorage),
                ("local_storage_shared", &["Local Storage"][..], Kind::Shared),
                (
                    "local_storage_sqlite_shared",
                    &["LocalStorage"][..],
                    Kind::Shared,
                ),
                (
                    "session_storage_shared",
                    &["Session Storage"][..],
                    Kind::Shared,
                ),
                (
                    "service_worker_database_shared",
                    &["Service Worker", "Database"][..],
                    Kind::Shared,
                ),
                (
                    "service_worker_script_cache_shared",
                    &["Service Worker", "ScriptCache"][..],
                    Kind::Shared,
                ),
                ("http_cache_shared", &["Cache"][..], Kind::Shared),
                ("code_cache_shared", &["Code Cache"][..], Kind::Shared),
                ("extensions_shared", &["Extensions"][..], Kind::Shared),
            ] {
                let path = components.iter().fold(profile.clone(), |p, c| p.join(c));
                if discovery.directory(&path).is_none() {
                    continue;
                }
                let report = analyze_subsystem(
                    install,
                    name,
                    subsystem,
                    &path,
                    kind,
                    cancel,
                    deadline,
                    &mut metadata_bytes,
                );
                result.complete &= report.size_complete && report.issues.is_empty();
                result.profiles.push(report);
            }
            if let Some(cache) = &install.cache_data {
                let path = cache.join(name);
                if discovery
                    .directory(&path)
                    .is_some_and(|root| !root.same_object(&profile_root))
                {
                    let report = analyze_subsystem(
                        install,
                        name,
                        "profile_cache_shared",
                        &path,
                        Kind::Shared,
                        cancel,
                        deadline,
                        &mut metadata_bytes,
                    );
                    result.complete &= report.size_complete && report.issues.is_empty();
                    result.profiles.push(report);
                }
            }
        }
    }
    if let Some(failure) = discovery.failure {
        result.complete = false;
        result.issues.push(format!("discovery: {failure:?}"));
    }
    result
}

#[derive(Clone, Copy)]
enum Kind {
    Cache,
    IndexedDb,
    WebStorage,
    Shared,
}

#[allow(clippy::too_many_arguments)]
fn analyze_subsystem(
    install: &BrowserInstallation,
    profile: &str,
    subsystem: &str,
    path: &Path,
    kind: Kind,
    cancel: &CancellationToken,
    deadline: Instant,
    metadata_bytes: &mut MetadataBudget,
) -> SiteStorageReport {
    let mut report = SiteStorageReport {
        browser: install.browser.clone(),
        profile: format!("{}/{profile}", install.browser),
        profile_name: profile.into(),
        subsystem: subsystem.into(),
        subsystem_path: path.to_path_buf(),
        subsystem_bytes: None,
        size_complete: false,
        fully_attributed: false,
        unattributed_bytes: None,
        snapshot_consistency: "non_atomic_live_observations",
        origins: Vec::new(),
        issues: Vec::new(),
    };
    let scan = match observe_directories(path, cancel, deadline) {
        Ok(scan) => scan,
        Err(e) => {
            report.issues.push(e);
            return report;
        }
    };
    let Some(root) = scan.roots.first() else {
        report.issues.push("root_not_observed".into());
        return report;
    };
    let (total, complete) = entry_bytes(&scan, root);
    report.subsystem_bytes = total.map(|n| n.to_string());
    report.size_complete = complete;
    if !complete
        || scan.error_count() != 0
        || scan.progress_retention.resource_limited
        || scan.progress_retention.cancelled
    {
        report.issues.push("incomplete_scan".into());
    }
    let quota = if matches!(kind, Kind::WebStorage) {
        match read_metadata(
            root,
            "QuotaManager",
            MAX_QUOTA_BYTES,
            cancel,
            metadata_bytes,
        )
        .and_then(|bytes| quota_buckets(&bytes))
        {
            Ok(mapping) => mapping,
            Err(e) => {
                report.issues.push(format!("quota_manager: {e}"));
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };
    let mut by_key = BTreeMap::<(String, Option<i64>), OriginUsage>::new();
    for entry in &scan.entries {
        let Some(identity) = &entry.identity else {
            continue;
        };
        if identity.parent_id.as_ref() != Some(&identity.scan_root_id) {
            continue;
        }
        let Some(name) = native_rule_name(&entry.native_basename) else {
            continue;
        };
        let attribution = match kind {
            Kind::Cache => {
                match read_metadata(entry, "index.txt", 1024 * 1024, cancel, metadata_bytes)
                    .and_then(|bytes| {
                        cache_storage_key(&bytes).ok_or_else(|| "invalid_index".into())
                    }) {
                    Ok(key) => Some((key, None, None)),
                    Err(e) => {
                        if report.issues.len() < 64 {
                            report.issues.push(format!("index {name}: {e}"));
                        }
                        None
                    }
                }
            }
            Kind::IndexedDb => indexed_db_key(&name).map(|key| (key, None, None)),
            Kind::WebStorage => name
                .parse::<i64>()
                .ok()
                .filter(|id| id.to_string() == name)
                .and_then(|id| {
                    quota
                        .get(&id)
                        .map(|b| (b.key.clone(), Some(id), Some(b.name.clone())))
                }),
            Kind::Shared => None,
        };
        let Some((key, bucket_id, bucket_name)) = attribution else {
            continue;
        };
        let Some(domain) = storage_key_domain(&key) else {
            continue;
        };
        let (bytes, complete) = entry_bytes(&scan, entry);
        // Charge owned report strings/paths before inserting or cloning them. This estimate does
        // not claim RSS, but bounds the output retained across all profiles/subsystems.
        let retained = key
            .len()
            .saturating_mul(2)
            .saturating_add(entry.display_path.len().saturating_mul(4))
            .saturating_add(
                bucket_name
                    .as_ref()
                    .map_or(0, |n| n.len().saturating_mul(2)),
            )
            .saturating_add(1024);
        if metadata_bytes.origin_rows >= MAX_ORIGIN_ROWS
            || retained > MAX_REPORT_ORIGIN_BYTES.saturating_sub(metadata_bytes.origin_bytes)
        {
            report.issues.push("origin_report_limit".into());
            break;
        }
        metadata_bytes.origin_bytes += retained;
        metadata_bytes.origin_rows += 1;
        let usage = by_key
            .entry((key.clone(), bucket_id))
            .or_insert_with(|| OriginUsage {
                storage_key: key,
                domain,
                bytes: Some("0".into()),
                complete: true,
                directory_count: 0,
                directories: Vec::new(),
                bucket_id,
                bucket_name,
            });
        usage.bytes = match (
            usage.bytes.as_ref().and_then(|n| n.parse::<u128>().ok()),
            bytes,
        ) {
            (Some(a), Some(b)) => a.checked_add(b).map(|n| n.to_string()),
            _ => None,
        };
        usage.complete &= complete;
        usage.directory_count += 1;
        usage.directories.push(PathBuf::from(&entry.display_path));
    }
    report.origins = by_key.into_values().collect();
    report.origins.sort_by_key(|r| {
        std::cmp::Reverse(
            r.bytes
                .as_ref()
                .and_then(|n| n.parse::<u128>().ok())
                .unwrap_or(0),
        )
    });
    let attributed = report.origins.iter().try_fold(0u128, |n, r| {
        n.checked_add(r.bytes.as_ref()?.parse::<u128>().ok()?)
    });
    report.unattributed_bytes = total
        .zip(attributed)
        .and_then(|(all, named)| all.checked_sub(named))
        .map(|n| n.to_string());
    report.fully_attributed = report.size_complete
        && report.issues.is_empty()
        && report.origins.iter().all(|r| r.complete)
        && report.unattributed_bytes.as_deref() == Some("0");
    report
}

fn read_metadata(
    entry: &ScannedEntry,
    name: &str,
    max_bytes: usize,
    cancel: &CancellationToken,
    used: &mut MetadataBudget,
) -> Result<Vec<u8>, String> {
    let remaining = MAX_METADATA_BYTES.saturating_sub(used.bytes);
    if remaining == 0 || used.requests >= 4096 {
        return Err("metadata_byte_limit".into());
    }
    used.requests += 1;
    let reserved = max_bytes.min(remaining);
    // Failed reads retain the whole reservation: a changed file may already have delivered bytes
    // before failing. Successful complete reads refund their unused allowance.
    used.bytes += reserved;
    #[cfg(unix)]
    let name = NativeName::UnixBytes(name.as_bytes().to_vec());
    #[cfg(windows)]
    let name = NativeName::WindowsUtf16(name.encode_utf16().collect());
    let reader = LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 256,
            max_file_bytes: reserved,
            max_total_bytes: reserved,
            ..Default::default()
        },
    );
    let read = reader
        .read_captured_regular_file(entry, &name, cancel)
        .map_err(|e| format!("{e:?}"))?;
    used.bytes -= reserved - read.bytes.len();
    Ok(read.bytes)
}

struct Bucket {
    key: String,
    name: String,
}
fn quota_buckets(bytes: &[u8]) -> Result<BTreeMap<i64, Bucket>, String> {
    let mut db = Connection::open_in_memory().map_err(|e| e.to_string())?;
    db.deserialize_read_exact("main", bytes, bytes.len(), true)
        .map_err(|e| e.to_string())?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|e| e.to_string())?;
    let table: String = db
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name='buckets'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if table != "table" {
        return Err("unsupported_buckets_schema".into());
    }
    let mut statement = db
        .prepare("SELECT id,storage_key,name FROM buckets LIMIT 16385")
        .map_err(|e| e.to_string())?;
    let mut rows = statement.query([]).map_err(|e| e.to_string())?;
    let mut mapping = BTreeMap::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        if mapping.len() >= MAX_BUCKETS {
            return Err("bucket_limit".into());
        }
        let id: i64 = row.get(0).map_err(|e| e.to_string())?;
        let key = row
            .get_ref(1)
            .map_err(|e| e.to_string())?
            .as_str()
            .map_err(|e| e.to_string())?;
        let name = row
            .get_ref(2)
            .map_err(|e| e.to_string())?
            .as_str()
            .map_err(|e| e.to_string())?;
        if id <= 0
            || key.len() > MAX_KEY_BYTES
            || name.len() > MAX_KEY_BYTES
            || storage_key_domain(key).is_none()
        {
            return Err("invalid_bucket_metadata".into());
        }
        if mapping
            .insert(
                id,
                Bucket {
                    key: key.into(),
                    name: name.into(),
                },
            )
            .is_some()
        {
            return Err("ambiguous_bucket_id".into());
        }
    }
    Ok(mapping)
}

/// Display hostname from the origin at the start of a raw storage key; suffixes remain untouched.
pub fn storage_key_domain(key: &str) -> Option<String> {
    let (scheme, rest) = key.split_once("://")?;
    if scheme.is_empty()
        || !scheme.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || (i > 0 && (b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')))
        })
    {
        return None;
    }
    let authority = rest.split('/').next()?;
    let host = if authority.starts_with('[') {
        let (host, suffix) = authority.split_once(']')?;
        if !suffix.is_empty() && !valid_port(suffix.strip_prefix(':')?) {
            return None;
        }
        host.strip_prefix('[')?
            .parse::<std::net::Ipv6Addr>()
            .ok()?
            .to_string()
    } else {
        let host = if let Some((host, port)) = authority.split_once(':') {
            if !valid_port(port) {
                return None;
            }
            host
        } else {
            authority
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        {
            return None;
        }
        host.to_ascii_lowercase()
    };
    Some(host)
}
fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}

// Chromium database_identifier.cc encodes the port, not an origin serial. Default ports use 0.
fn indexed_db_key(name: &str) -> Option<String> {
    let stem = name
        .strip_suffix(".indexeddb.leveldb")
        .or_else(|| name.strip_suffix(".indexeddb.blob"))?;
    let (head, port) = stem.rsplit_once('_')?;
    if !valid_port(port) {
        return None;
    }
    let (scheme, host) = head.split_once('_')?;
    let key = if port == "0" {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };
    storage_key_domain(&key)?;
    Some(key)
}

// Parse actual protobuf wire fields, not URLs found inside arbitrary cache names. The upstream
// CacheStorageIndex defines deprecated origin=2 and storage_key=3; prefer the latter when present.
fn cache_storage_key(bytes: &[u8]) -> Option<String> {
    let mut remaining = bytes;
    let mut origin = None;
    let mut key = None;
    while !remaining.is_empty() {
        let tag = varint(&mut remaining)?;
        if tag >> 3 == 0 {
            return None;
        }
        match tag & 7 {
            0 => {
                varint(&mut remaining)?;
            }
            1 => {
                remaining = remaining.get(8..)?;
            }
            2 => {
                let size = usize::try_from(varint(&mut remaining)?).ok()?;
                let field = remaining.get(..size)?;
                remaining = remaining.get(size..)?;
                if matches!(tag >> 3, 2 | 3) {
                    if size > MAX_KEY_BYTES {
                        return None;
                    }
                    let value = std::str::from_utf8(field).ok()?;
                    storage_key_domain(value)?;
                    let target = if tag >> 3 == 3 { &mut key } else { &mut origin };
                    if target.as_ref().is_some_and(|old| old != value) {
                        return None;
                    }
                    *target = Some(value.to_string());
                }
            }
            5 => {
                remaining = remaining.get(4..)?;
            }
            _ => return None,
        }
    }
    key.or(origin)
}
fn varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let (&byte, rest) = bytes.split_first()?;
        *bytes = rest;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Some(value);
        }
    }
    None
}

/// Browser-owned origin removal request. It does not contain filesystem execution authority.
/// The optional extension must separately confirm the active browser/profile, scope and domain.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserCleanupPlan {
    /// Stable plan schema, accepted only by the reviewed browser adapter.
    pub schema: &'static str,
    /// Browser API operation; never direct directory removal.
    pub operation: &'static str,
    /// Expected browser/channel for explicit user confirmation inside that browser.
    pub browser: String,
    /// Expected profile basename; extensions cannot independently read native profile identity.
    pub profile: String,
    /// Exact selected hostname, excluding subdomains.
    pub domain: String,
    /// HTTP(S) origins derived from observed keys, preserving non-default ports.
    /// The browser origin API handles partitions together and cannot select one bucket.
    pub origins: Vec<String>,
    /// Browser API clearing has no Trash recovery; no action has occurred during export.
    pub recoverable: bool,
    /// How the optional adapter binds execution to its active profile.
    pub profile_binding: &'static str,
}

/// Builds a bounded explicit domain selection from current native reports. Unknown attribution
/// fails instead of expanding to a wildcard. Sizes and directory paths do not authorize execution.
pub fn cleanup_plan(
    analysis: &BrowserStorageAnalysis,
    browser: &str,
    profile: &str,
    domain: &str,
) -> Result<BrowserCleanupPlan, String> {
    if !matches!(
        browser,
        "chrome" | "edge" | "chrome-beta" | "chrome-dev" | "edge-beta" | "edge-dev"
    ) || !(profile == "Default"
        || profile
            .strip_prefix("Profile ")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
    {
        return Err("unsupported_browser_profile".into());
    }
    let domain = domain.to_ascii_lowercase();
    let mut origins = BTreeSet::new();
    for report in analysis
        .profiles
        .iter()
        .filter(|r| r.browser == browser && r.profile_name == profile)
    {
        for usage in report
            .origins
            .iter()
            .filter(|r| r.domain.eq_ignore_ascii_case(&domain))
        {
            if !usage.complete {
                return Err("selected_observation_incomplete".into());
            }
            let (scheme, rest) = usage
                .storage_key
                .split_once("://")
                .ok_or("unsupported_origin")?;
            if !matches!(scheme, "http" | "https") {
                return Err("unsupported_origin".into());
            }
            let authority = rest.split('/').next().ok_or("unsupported_origin")?;
            let authority = if scheme == "https" {
                authority.strip_suffix(":443").unwrap_or(authority)
            } else {
                authority.strip_suffix(":80").unwrap_or(authority)
            };
            let origin = format!("{scheme}://{authority}");
            if storage_key_domain(&origin).as_deref() != Some(domain.as_str()) {
                return Err("origin_domain_mismatch".into());
            }
            origins.insert(origin);
            if origins.len() > 128 {
                return Err("origin_limit".into());
            }
        }
    }
    if origins.is_empty() {
        return Err("domain_not_observed".into());
    }
    Ok(BrowserCleanupPlan {
        schema: "sweepx.browser_cleanup.plan/v1",
        operation: "browser_managed_origin_removal",
        browser: browser.into(),
        profile: profile.into(),
        domain,
        origins: origins.into_iter().collect(),
        recoverable: false,
        profile_binding: "explicit_user_confirmation_in_browser",
    })
}

#[cfg(test)]
#[path = "browser_storage_tests.rs"]
mod tests;
