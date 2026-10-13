//! Store discovery is advisory. Inventories independently admit every discovered native root.
use super::*;
#[derive(Debug, Default)]
pub(super) struct ModulesMetadata {
    pub store: Option<String>,
    pub virtual_store: Option<String>,
}
pub(super) fn modules_metadata(data: &[u8]) -> Result<ModulesMetadata, String> {
    let text = std::str::from_utf8(data).map_err(|_| "pnpm_marker_utf8")?;
    let validate = |meta: ModulesMetadata| -> Result<ModulesMetadata, String> {
        if meta.store.as_ref().is_some_and(|s| s.len() > 64 * 1024)
            || meta
                .virtual_store
                .as_ref()
                .is_some_and(|s| s.len() > 64 * 1024)
        {
            return Err("pnpm_marker_path_budget".into());
        }
        Ok(meta)
    };
    if text.trim_start().starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let field = |name| -> Result<Option<String>, String> {
            match value.get(name) {
                None => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(format!("pnpm_marker_invalid_{name}")),
            }
        };
        return validate(ModulesMetadata {
            store: field("storeDir")?,
            virtual_store: field("virtualStoreDir")?,
        });
    }
    let field = |key: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(key)
                .map(|v| v.trim().trim_matches(['\'', '"']).to_owned())
        })
    };
    validate(ModulesMetadata {
        store: field("storeDir:"),
        virtual_store: field("virtualStoreDir:"),
    })
}
/// Automatically located versioned stores and explicit discovery limitations.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PnpmLocations {
    /// Versioned store roots; each still requires native admission by an inventory.
    pub stores: Vec<PathBuf>,
    /// Installed declarations pointing to absent stores, or failed native discovery scopes.
    pub issues: Vec<String>,
}
/// Locate stores from installed projects, environment, manager configuration and platform defaults.
/// An explicit store can name a version root or its container. Missing declared stores are reported.
pub fn pnpm_locations(
    explicit: Option<&Path>,
    project_roots: &[PathBuf],
    cancel: &CancellationToken,
) -> PnpmLocations {
    let mut result = PnpmLocations {
        stores: Vec::new(),
        issues: Vec::new(),
    };
    let mut hints = BTreeSet::new();
    let mut required = BTreeSet::new();
    if let Some(root) = explicit {
        hints.insert(root.to_path_buf());
        required.insert(root.to_path_buf());
    } else {
        let (projects, _, issues, local) =
            projects::discover_store_hints(project_roots, &mut Native::new(cancel));
        hints.extend(local);
        result.issues.extend(issues);
        for project in projects {
            if let Some(store) = project.store_dir {
                let path = PathBuf::from(store);
                if path.is_absolute() {
                    hints.insert(path.clone());
                    required.insert(path);
                } else {
                    result
                        .issues
                        .push("relative_declared_store_unresolved".into());
                }
            }
        }
        if let Some(root) = std::env::var_os("PNPM_STORE_DIR") {
            hints.insert(root.into());
        }
        if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
            hints.insert(PathBuf::from(data).join("pnpm/store"));
        }
        if let Some(home) = crate::junk::platform::user_home_dir() {
            hints.extend([
                home.join(".pnpm-store"),
                home.join("Library/pnpm/store"),
                home.join(".local/share/pnpm/store"),
            ]);
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                hints.insert(PathBuf::from(local).join("pnpm/store"));
            }
        }
        let mut runner =
            crate::tools::ProbeRunner::new(crate::tools::ProbeLimits::default(), cancel.clone());
        if let Ok(out) = runner.run(std::process::Command::new("pnpm").args(["store", "path"]))
            && out.status.success()
            && let Ok(text) = std::str::from_utf8(&out.stdout)
        {
            let path = PathBuf::from(text.trim());
            if path.is_absolute() {
                hints.insert(path);
            }
        }
    }
    for hint in hints {
        let mut native = Native::new(cancel);
        match native.root(&hint).and_then(|root| native.children(&root)) {
            Ok(children) => {
                if children
                    .iter()
                    .any(|e| native::basename(e).as_deref() == Some("files"))
                {
                    result.stores.push(hint);
                } else {
                    for child in children {
                        if child.object_type == sweepx_model::ObjectType::Directory
                            && native::basename(&child).is_some_and(|n| {
                                n.len() > 1
                                    && n.starts_with('v')
                                    && n[1..].chars().all(|c| c.is_ascii_digit())
                            })
                            && let Ok(path) = native::path(&child)
                        {
                            result.stores.push(path);
                        }
                    }
                }
            }
            Err(e) if required.contains(&hint) => result.issues.push(format!(
                "declared_store_unavailable {}: {e}",
                hint.display()
            )),
            Err(_) => {}
        }
    }
    result.stores.sort();
    result.stores.dedup();
    if result.stores.len() > 32 {
        result.stores.truncate(32);
        result.issues.push("store_count_budget_exceeded".into());
    }
    result
}
