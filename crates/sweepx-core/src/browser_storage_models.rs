//! Explicit Chrome legacy component selections, distinct from prediction and manifest assets.
use super::*;
use sha2::{Digest, Sha256};

/// One positively identified legacy Chrome foundation-model version.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelVersion {
    /// Component version, read from the component manifest and checked against its directory.
    pub version: String,
    /// Complete logical size of this version directory.
    pub bytes: Option<String>,
    /// Display path only.
    pub path: PathBuf,
    /// Full size coverage and bounded native component-file reads.
    pub complete: bool,
    /// Missing or unsupported observations; none establish disposability.
    pub issues: Vec<String>,
    #[serde(skip)]
    source: ScannedEntry,
    #[serde(skip)]
    manifest_digest: [u8; 32],
    #[serde(skip)]
    config_digest: [u8; 32],
}
impl ModelVersion {
    /// Current native observation for a separate recoverable platform Trash adapter.
    pub fn source_entry(&self) -> &ScannedEntry {
        &self.source
    }
    /// Revalidates native lineage and component metadata. Browser activity is checked separately;
    /// no setting, process kill, component registration or prediction model is modified here.
    pub fn revalidate(&self, cancel: &CancellationToken) -> Result<(), String> {
        if !self.complete {
            return Err("incomplete_model_observation".into());
        }
        crate::storage_inventory::revalidate_directory(&self.source, cancel)?;
        let mut budget = MetadataBudget::default();
        for (name, expected) in [
            ("manifest.json", self.manifest_digest),
            ("on_device_model_execution_config.pb", self.config_digest),
        ] {
            let bytes = read_metadata(&self.source, name, 1024 * 1024, cancel, &mut budget)?;
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != expected {
                return Err("model_metadata_changed".into());
            }
        }
        Ok(())
    }
}
/// Report and current native version selections; unknown versions are retained as blocked rows.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelInventory {
    /// Supported browser label. This adapter intentionally does not assume Edge's model IDs.
    pub browser: String,
    /// Recognized legacy foundation-model component; excludes prediction and manifest stores.
    pub component: &'static str,
    /// Installation-level model versions, independent of profile directories.
    pub versions: Vec<ModelVersion>,
    /// Whether native size and metadata observations completed.
    pub complete: bool,
    /// Root-level failures.
    pub issues: Vec<String>,
}
/// Reads only Chrome's legacy model component. Manifest Broker assets remain separate report-only
/// data; no whole User Data removal or broad component-update disabling is proposed.
pub fn inventory(install: &BrowserInstallation, cancel: &CancellationToken) -> ModelInventory {
    let mut out = ModelInventory {
        browser: install.browser.clone(),
        component: "OptGuideOnDeviceModel",
        versions: Vec::new(),
        complete: false,
        issues: Vec::new(),
    };
    if install.browser != "chrome" {
        out.issues.push("model_adapter_browser_unsupported".into());
        return out;
    }
    let scan = match observe_directories(
        &install.user_data.join("OptGuideOnDeviceModel"),
        cancel,
        Instant::now() + Duration::from_secs(120),
    ) {
        Ok(s) => s,
        Err(e) => {
            out.issues.push(e);
            return out;
        }
    };
    let Some(root) = scan.roots.first() else {
        out.issues.push("model_root_unavailable".into());
        return out;
    };
    out.complete = entry_bytes(&scan, root).1
        && scan.error_count() == 0
        && !scan.progress_retention.resource_limited
        && !scan.progress_retention.cancelled;
    let mut budget = MetadataBudget::default();
    for source in &scan.entries {
        if source
            .identity
            .as_ref()
            .is_none_or(|i| i.parent_id.as_ref() != Some(&i.scan_root_id))
        {
            continue;
        }
        if out.versions.len() >= 64 {
            out.complete = false;
            out.issues.push("model_version_limit".into());
            break;
        }
        let version = native_rule_name(&source.native_basename).unwrap_or_default();
        let (bytes, complete) = entry_bytes(&scan, source);
        let mut row = ModelVersion {
            version: version.clone(),
            bytes: bytes.map(|b| b.to_string()),
            path: source.display_path.clone().into(),
            complete,
            issues: Vec::new(),
            source: source.clone(),
            manifest_digest: [0; 32],
            config_digest: [0; 32],
        };
        let result = (|| {
            if version.split('.').count() != 4
                || !version.split('.').all(|s| {
                    !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit())
                })
            {
                return Err("unsupported_component_version".into());
            }
            let bytes = read_metadata(source, "manifest.json", 64 * 1024, cancel, &mut budget)?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_component_manifest")?;
            if manifest["name"] != "Optimization Guide On Device Model"
                || manifest["version"] != version
                || manifest["manifest_version"] != 2
            {
                return Err("unrecognized_component_manifest".into());
            }
            row.manifest_digest = Sha256::digest(&bytes).into();
            let config = read_metadata(
                source,
                "on_device_model_execution_config.pb",
                1024 * 1024,
                cancel,
                &mut budget,
            )?;
            if config.is_empty() {
                return Err("empty_component_config".into());
            }
            row.config_digest = Sha256::digest(&config).into();
            Ok::<(), String>(())
        })();
        if let Err(e) = result {
            row.complete = false;
            row.issues.push(e);
        }
        out.complete &= row.complete;
        out.versions.push(row);
    }
    out
}

/// Generates an installable macOS configuration profile containing only the documented Chrome
/// foundation-model policy. Export does not install or verify it. The OS may require administrator
/// approval; chrome://policy must show value 1 and OK before persistent disabling is claimed.
pub fn macos_disable_profile() -> &'static str {
    include_str!("assets/chrome-no-local-model.mobileconfig")
}
