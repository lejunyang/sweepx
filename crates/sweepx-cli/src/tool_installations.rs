//! Enumeration of multiple installations of a developer tool and the manager controlling each.
//!
//! A single machine routinely carries several copies of `npm` — one from Homebrew, one per Node
//! version under nvm/fnm/volta, and whatever `PATH` resolves first. Treating the resolver's answer
//! as the whole picture hides the rest and cannot answer which copy is actually in use. This module
//! discovers every installation through manager-specific layouts, asks each copy for its own
//! version and effective cache, and measures that cache's last activity from real bytes rather
//! than inferring it from a directory name.
//!
//! All findings are report-only evidence. They grant no deletion authority.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// One installed copy of a tool and what is known about it.
#[derive(Debug, Clone)]
pub struct ToolInstallation {
    /// Stable tool identifier, currently always `npm`.
    pub tool: String,
    /// Stable machine identifier of the manager that owns this copy: `homebrew`, `nvm`, `fnm`,
    /// `volta`, `asdf`, `mise`, `n`, or `path` for an unmanaged copy found on `PATH`.
    pub manager: String,
    /// Manager-scoped installation label, for example the Node version directory `v20.19.0`;
    /// `None` when the manager keeps a single unversioned copy.
    pub manager_label: Option<String>,
    /// Path to the tool executable. Used for version probing and as identity for deduplication.
    pub executable: PathBuf,
    /// The tool's own reported version, or `None` when the copy could not be executed.
    pub tool_version: Option<String>,
    /// Sibling runtime (Node) version, or `None` when it could not be read.
    pub runtime_version: Option<String>,
    /// The cache directory this specific copy reports; distinct copies can point at one shared
    /// cache or at separate configured ones.
    pub cache: Option<PathBuf>,
    /// RFC-3339 time of the cache's most recent modification, the measured last-activity signal.
    pub cache_last_active_at: Option<String>,
    /// True when this executable is the first `PATH` entry for the tool — the copy a bare
    /// invocation resolves to. Exactly one installation carries this on a healthy `PATH`.
    pub is_path_default: bool,
}

/// Declarative description of where one manager installs the tool.
///
/// Kept data-driven rather than matched on rule id: supporting a new manager is adding one
/// descriptor. Globbed managers expand a fixed root and treat each child directory as a separate
/// versioned installation; fixed managers expose a single unversioned executable.
struct ManagerLayout {
    manager: &'static str,
    /// Directory whose direct children are versioned installations; `None` for a fixed layout.
    versions_root: Option<PathBuf>,
    /// Relative path from an installation (version) directory to the executable.
    executable_from_version: &'static [&'static str],
    /// Fixed executable path when `versions_root` is `None`.
    fixed_executable: Option<PathBuf>,
}

/// Every manager layout probed on this host.
///
/// Paths are the documented defaults for each manager; unknown or absent directories are simply
/// skipped. `PATH` itself is handled separately so an unmanaged copy is still found and the
/// default can be marked.
fn manager_layouts() -> Vec<ManagerLayout> {
    let Some(home) = user_home() else {
        return Vec::new();
    };
    let join = |components: &[&str]| {
        let mut path = home.clone();
        for component in components {
            path.push(component);
        }
        path
    };
    let versioned =
        |manager: &'static str, root: PathBuf, from: &'static [&'static str]| ManagerLayout {
            manager,
            versions_root: Some(root),
            executable_from_version: from,
            fixed_executable: None,
        };
    let fixed = |manager: &'static str, executable: PathBuf| ManagerLayout {
        manager,
        versions_root: None,
        executable_from_version: &[],
        fixed_executable: Some(executable),
    };
    let mut layouts = vec![
        fixed("homebrew", PathBuf::from("/opt/homebrew/bin/npm")),
        fixed("homebrew", PathBuf::from("/usr/local/bin/npm")),
        versioned("nvm", join(&[".nvm", "versions", "node"]), &["bin", "npm"]),
        versioned(
            "fnm",
            join(&["Library", "Application Support", "fnm", "node-versions"]),
            &["installation", "bin", "npm"],
        ),
        versioned(
            "fnm",
            join(&[".fnm", "node-versions"]),
            &["installation", "bin", "npm"],
        ),
        versioned(
            "volta",
            join(&[".volta", "tools", "image", "node"]),
            &["bin", "npm"],
        ),
        versioned(
            "asdf",
            join(&[".asdf", "installs", "nodejs"]),
            &["bin", "npm"],
        ),
        versioned(
            "mise",
            join(&[".local", "share", "mise", "installs", "node"]),
            &["bin", "npm"],
        ),
        versioned(
            "n",
            PathBuf::from("/usr/local/n/versions/node"),
            &["bin", "npm"],
        ),
    ];
    // Volta also ships a stable shim on PATH that dispatches to the pinned version. Reported as a
    // fixed copy in addition to the concrete versions above.
    layouts.push(fixed("volta", join(&[".volta", "bin", "npm"])));
    layouts
}

/// Discovers every installation of `npm` on the host, deduplicated by resolved path.
///
/// The first executable `PATH` resolves is marked as the default. Installations that no manager
/// layout recognizes but sit on `PATH` are still admitted under the `path` manager, so a custom
/// build is never silently dropped.
pub fn discover_npm_installations() -> Vec<ToolInstallation> {
    discover_npm(true)
}

/// Discovers cache roots without launching npm/node version probes needed only by inventory UI.
pub fn discover_npm_cache_roots() -> Vec<PathBuf> {
    discover_npm(false)
        .into_iter()
        .filter_map(|installation| installation.cache)
        .collect()
}

fn discover_npm(include_versions: bool) -> Vec<ToolInstallation> {
    let path_executables = path_resolved_executables("npm");
    let default_executable = path_executables.first().cloned();

    let mut raw: Vec<(String, Option<String>, PathBuf)> = Vec::new();
    for layout in manager_layouts() {
        if let Some(fixed) = layout.fixed_executable
            && is_executable_file(&fixed)
        {
            raw.push((layout.manager.to_string(), None, fixed));
        }
        let Some(versions_root) = layout.versions_root else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(&versions_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let label = match entry.file_name().to_str() {
                Some(name) => name.to_string(),
                None => continue,
            };
            let mut executable = entry.path();
            for component in layout.executable_from_version {
                executable.push(component);
            }
            if is_executable_file(&executable) {
                raw.push((layout.manager.to_string(), Some(label), executable));
            }
        }
    }
    // Admit any PATH copy a known layout did not produce, labelled by the unmanaged `path` manager.
    let known: Vec<PathBuf> = raw.iter().map(|(_, _, p)| p.clone()).collect();
    for executable in path_executables {
        if !known.iter().any(|known| same_path(known, &executable)) {
            raw.push(("path".to_string(), None, executable));
        }
    }

    // Deduplicate by resolved identity: a Homebrew npm can also be the first PATH hit, and a
    // versioned copy can appear through more than one manager spelling. Keep the first (most
    // specific) manager label.
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut installations = Vec::new();
    for (manager, label, executable) in raw {
        let identity = std::fs::canonicalize(&executable).unwrap_or_else(|_| executable.clone());
        if !seen.insert(identity) {
            continue;
        }
        let tool_version = include_versions
            .then(|| run_trimmed(&executable, &["--version"]))
            .flatten();
        let runtime_version = include_versions
            .then_some(&executable)
            .and_then(|executable| executable.parent())
            .map(|bin| bin.join(if cfg!(windows) { "node.exe" } else { "node" }))
            .filter(|node| is_executable_file(node))
            .and_then(|node| run_trimmed(&node, &["--version"]));
        let cache = run_trimmed(&executable, &["config", "get", "cache"]).map(PathBuf::from);
        let cache_last_active_at = cache
            .as_ref()
            .filter(|_| include_versions)
            .and_then(|cache| directory_newest_mtime(cache))
            .and_then(rfc3339);
        let is_path_default = default_executable
            .as_ref()
            .is_some_and(|default| same_path(default, &executable));
        installations.push(ToolInstallation {
            tool: "npm".to_string(),
            manager,
            manager_label: label,
            executable,
            tool_version,
            runtime_version,
            cache,
            cache_last_active_at,
            is_path_default,
        });
    }
    installations
}

/// Returns every executable named `program` found by walking `PATH`, in `PATH` order.
fn path_resolved_executables(program: &str) -> Vec<PathBuf> {
    let Some(path_var) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for directory in std::env::split_paths(&path_var) {
        let candidate = directory.join(program);
        if is_executable_file(&candidate)
            && !found
                .iter()
                .any(|existing: &PathBuf| same_path(existing, &candidate))
        {
            found.push(candidate);
        }
    }
    found
}

/// Runs a program with arguments and returns the trimmed first stdout line.
fn run_trimmed(executable: &Path, arguments: &[&str]) -> Option<String> {
    let output = std::process::Command::new(executable)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

/// Returns the newest mtime among the directory and its direct children.
///
/// Direct children only: a full recursive walk over a cache is the scanner's job, and doing it
/// again here would duplicate cost. The root-or-child mtime is a cheap, honest "something wrote
/// here recently" signal and is reported as last activity rather than as an exact use time.
fn directory_newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest = std::fs::symlink_metadata(dir)
        .ok()
        .map(|m| m.modified().ok())?;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata()
                && let Ok(modified) = metadata.modified()
                && newest.is_none_or(|current| modified > current)
            {
                newest = Some(modified);
            }
        }
    }
    newest
}

fn rfc3339(time: SystemTime) -> Option<String> {
    OffsetDateTime::from(time).format(&Rfc3339).ok()
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Follow links: Homebrew's npm is a symlink to the npm-cli.js launcher, and
    // symlink_metadata would classify it as a symlink and hide a real executable.
    std::fs::metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
    })
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

/// Identity comparison through the filesystem, falling back to a raw comparison on failure.
fn same_path(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn rfc3339_formats_a_fixed_instant() {
        // 2026-01-02T03:04:05Z.
        let time = UNIX_EPOCH + Duration::from_secs(1_767_323_045);
        assert_eq!(rfc3339(time).as_deref(), Some("2026-01-02T03:04:05Z"));
    }

    #[test]
    fn directory_newest_mtime_tracks_a_child_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let before = directory_newest_mtime(root).unwrap();

        let child = root.join("newer.bin");
        std::fs::write(&child, b"x").unwrap();
        // Bump mtime into the future so the comparison does not depend on filesystem clock
        // resolution equalizing the two writes.
        let future = UNIX_EPOCH + Duration::from_secs(4_000_000_000);
        let accessed = std::fs::FileTimes::new().set_modified(future);
        std::fs::File::open(&child)
            .unwrap()
            .set_times(accessed)
            .unwrap();

        let after = directory_newest_mtime(root).unwrap();
        assert!(after > before);
        assert_eq!(after, future);
    }

    #[test]
    fn run_trimmed_rejects_a_missing_executable_and_bad_exit() {
        assert!(run_trimmed(Path::new("/nonexistent/npm-xyz"), &["--version"]).is_none());
        // `true` exits zero but prints nothing; an empty line must still be `None`.
        assert!(run_trimmed(Path::new("/usr/bin/true"), &[]).is_none());
    }

    #[test]
    fn is_executable_file_distinguishes_bits() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a");
        std::fs::write(&file, b"x").unwrap();
        #[cfg(unix)]
        {
            assert!(!is_executable_file(&file));
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(is_executable_file(&file));
        assert!(!is_executable_file(temp.path()));
    }

    #[test]
    fn discovery_is_self_consistent_on_this_host() {
        let installations = discover_npm_installations();
        // No executable reported twice after identity resolution.
        let mut identities: Vec<PathBuf> = installations
            .iter()
            .map(|i| std::fs::canonicalize(&i.executable).unwrap_or_else(|_| i.executable.clone()))
            .collect();
        let before = identities.len();
        identities.sort();
        identities.dedup();
        assert_eq!(before, identities.len());
        // At most one copy can be what a bare invocation resolves to.
        assert!(installations.iter().filter(|i| i.is_path_default).count() <= 1);
        // Every measured cache activity is RFC-3339, and a reported cache is absolute.
        for installation in &installations {
            if let Some(at) = &installation.cache_last_active_at {
                assert!(OffsetDateTime::parse(at, &Rfc3339).is_ok());
            }
            if let Some(cache) = &installation.cache {
                assert!(cache.is_absolute());
            }
        }
    }
}
