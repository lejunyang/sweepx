//! Enumeration of multiple installations of a developer tool and the manager controlling each.
//!
//! A single machine routinely carries several copies of `npm` — one from Homebrew, one per Node
//! version under nvm/fnm/volta, and whatever `PATH` resolves first. Treating the resolver's answer
//! as the whole picture hides the rest and cannot answer which copy is actually in use. This module
//! discovers a bounded inventory through manager-specific layouts, asks each copy for its own
//! version and effective cache, and observes the newest root/direct-child modification time
//! without reading cache contents.
//! This is an activity hint, never an exact last-use time or proof of inactivity.
//!
//! All findings are report-only evidence. They grant no deletion authority.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::ProbeRunner;
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
    /// RFC-3339 newest root/direct-child modification time; unknown if observation is incomplete.
    /// This is a non-atomic activity hint, not an exact last-use time or absence-of-use proof.
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

/// Shared bounds for npm installation enumeration, path observations and retained inventory.
/// Filesystem calls share the probe runner's invocation deadline and cancellation token.
#[derive(Debug, Clone, Copy)]
pub struct ToolDiscoveryLimits {
    /// Maximum filesystem operations, including failed probes and directory iterator advances.
    pub max_observations: usize,
    /// Maximum distinct npm installations admitted, including the provisional PATH inventory.
    pub max_installations: usize,
    /// Cumulative admission estimate for paths, strings and collection nodes; not an RSS ceiling.
    pub max_retained_bytes: usize,
    /// Maximum bytes in any input path or environment value, before further expansion.
    pub max_path_bytes: usize,
}

impl Default for ToolDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_observations: 4096,
            max_installations: 64,
            max_retained_bytes: 4 * 1024 * 1024,
            max_path_bytes: 64 * 1024,
        }
    }
}

/// Why this inventory cannot establish complete discovery. Missing evidence is never inactivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolDiscoveryFailure {
    /// A filesystem-operation, inventory, path or retained-data bound was reached.
    ResourceLimit,
    /// The caller cancelled the shared invocation.
    Cancelled,
    /// The runner's shared process count or wall-clock admission budget was exhausted.
    ProbeBudget,
    /// A cache-location probe failed or returned an unusable answer.
    ProbeUnavailable,
    /// Enumeration or metadata was unavailable for a present location.
    ObservationUnavailable,
}

impl ToolDiscoveryFailure {
    /// Stable machine reason, independent of locale and native error strings.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ResourceLimit => "resource_limit",
            Self::Cancelled => "cancelled",
            Self::ProbeBudget => "probe_budget",
            Self::ProbeUnavailable => "probe_unavailable",
            Self::ObservationUnavailable => "observation_unavailable",
        }
    }
}

/// Bounded invocation-local inventory; positive entries survive incomplete discovery.
#[derive(Debug)]
pub struct ToolDiscoveryReport {
    /// Deduplicated installations. Optional answers remain unknown on refusal or failure.
    pub installations: Vec<ToolInstallation>,
    /// First failure to establish complete coverage, if any.
    pub incomplete_reason: Option<ToolDiscoveryFailure>,
    /// Charged filesystem operations, including unsuccessful calls.
    pub observations: usize,
    /// Charged cumulative retained-data estimate, including temporary discovery indexes.
    pub retained_bytes: usize,
}

struct Discovery {
    limits: ToolDiscoveryLimits,
    observations: usize,
    retained_bytes: usize,
    failure: Option<ToolDiscoveryFailure>,
    stopped: bool,
    executable_identities: std::collections::BTreeMap<PathBuf, Option<PathBuf>>,
    cache_activity: std::collections::BTreeMap<PathBuf, Option<SystemTime>>,
}

impl Discovery {
    fn new(limits: ToolDiscoveryLimits) -> Self {
        Self {
            limits,
            observations: 0,
            retained_bytes: 0,
            failure: None,
            stopped: false,
            executable_identities: std::collections::BTreeMap::new(),
            cache_activity: std::collections::BTreeMap::new(),
        }
    }

    fn fail(&mut self, reason: ToolDiscoveryFailure) {
        self.failure.get_or_insert(reason);
        if matches!(
            reason,
            ToolDiscoveryFailure::ResourceLimit
                | ToolDiscoveryFailure::Cancelled
                | ToolDiscoveryFailure::ProbeBudget
        ) {
            self.stopped = true;
        }
    }

    fn available(&mut self, runner: &ProbeRunner) -> bool {
        if let Err(error) = runner.check_budget() {
            self.fail(match error {
                super::ProbeError::Cancelled => ToolDiscoveryFailure::Cancelled,
                _ => ToolDiscoveryFailure::ProbeBudget,
            });
        }
        !self.stopped
    }

    fn charge(&mut self, bytes: usize) -> bool {
        let Some(total) = self
            .retained_bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.max_retained_bytes)
        else {
            self.fail(ToolDiscoveryFailure::ResourceLimit);
            return false;
        };
        self.retained_bytes = total;
        true
    }

    fn path(&mut self, path: &Path) -> bool {
        if path.as_os_str().len() > self.limits.max_path_bytes {
            self.fail(ToolDiscoveryFailure::ResourceLimit);
            return false;
        }
        // Charge temporary clones/keys too. Cumulative admission deliberately overestimates live
        // retained paths, so deduplication does not refund budget for failed or duplicate probes.
        self.charge(256usize.saturating_add(path.as_os_str().len().saturating_mul(4)))
    }

    fn observe<T>(
        &mut self,
        runner: &ProbeRunner,
        read: impl FnOnce() -> std::io::Result<T>,
    ) -> Option<T> {
        if !self.available(runner) {
            return None;
        }
        if self.observations >= self.limits.max_observations {
            self.fail(ToolDiscoveryFailure::ResourceLimit);
            return None;
        }
        self.observations += 1;
        let result = read();
        if !self.available(runner) {
            return None;
        }
        match result {
            Ok(value) => Some(value),
            Err(_) => {
                self.fail(ToolDiscoveryFailure::ObservationUnavailable);
                None
            }
        }
    }

    fn observe_optional_path<T>(
        &mut self,
        runner: &ProbeRunner,
        read: impl FnOnce() -> std::io::Result<T>,
    ) -> Option<T> {
        // A missing documented location is a valid negative path probe. Iterator failures or
        // disappearing children after enumeration are different: never treat them as clean EOF.
        self.observe(runner, || match read() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            result => result.map(Some),
        })?
    }

    fn executable_identity(&mut self, runner: &ProbeRunner, path: &Path) -> Option<PathBuf> {
        if !self.available(runner) {
            return None;
        }
        if let Some(identity) = self.executable_identities.get(path) {
            return identity.clone();
        }
        let identity = self.inspect_executable_identity(runner, path);
        if self.path(path) {
            self.executable_identities
                .insert(path.to_path_buf(), identity.clone());
        }
        identity
    }

    fn inspect_executable_identity(
        &mut self,
        runner: &ProbeRunner,
        path: &Path,
    ) -> Option<PathBuf> {
        if !self.path(path) {
            return None;
        }
        let metadata = self.observe_optional_path(runner, || std::fs::metadata(path))?;
        if !metadata.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        // Executable resolution intentionally follows package-manager launchers. This is tool
        // inventory, never native scanner or mutation authority. Resolve each spelling once.
        let identity = self.observe(runner, || std::fs::canonicalize(path))?;
        self.path(&identity).then_some(identity)
    }

    fn answer(
        &mut self,
        runner: &mut ProbeRunner,
        executable: &Path,
        arguments: &[&str],
        required: bool,
    ) -> Option<String> {
        if !self.available(runner) {
            return None;
        }
        let mut command = std::process::Command::new(executable);
        #[cfg(test)]
        let started = std::time::Instant::now();
        let result = runner.run(command.args(arguments));
        #[cfg(test)]
        if required {
            eprintln!(
                "cache probe {:?}: elapsed={:?}, successful={}, output_bytes={:?}",
                executable.file_name(),
                started.elapsed(),
                result.as_ref().is_ok_and(|output| output.status.success()),
                result.as_ref().ok().map(|output| output.stdout.len())
            );
        }
        let output = match result {
            Ok(output) if output.status.success() => output,
            Err(super::ProbeError::Cancelled) => {
                self.fail(ToolDiscoveryFailure::Cancelled);
                return None;
            }
            Err(super::ProbeError::BudgetExhausted) => {
                self.fail(ToolDiscoveryFailure::ProbeBudget);
                return None;
            }
            rejected => {
                #[cfg(test)]
                if required {
                    match &rejected {
                        Err(error) => eprintln!("required cache probe rejected: {error}"),
                        Ok(output) => eprintln!(
                            "required cache probe exit={:?}, bytes={}",
                            output.status.code(),
                            output.stdout.len()
                        ),
                    }
                }
                #[cfg(not(test))]
                let _ = rejected;
                if required {
                    self.fail(ToolDiscoveryFailure::ProbeUnavailable);
                }
                return None;
            }
        };
        let answer = String::from_utf8(output.stdout).ok().and_then(|text| {
            text.lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
        });
        let Some(answer) = answer else {
            if required {
                self.fail(ToolDiscoveryFailure::ProbeUnavailable);
            }
            return None;
        };
        if answer.len() > self.limits.max_path_bytes
            || !self.charge(128usize.saturating_add(answer.len().saturating_mul(2)))
        {
            self.fail(ToolDiscoveryFailure::ResourceLimit);
            return None;
        }
        Some(answer)
    }

    fn newest_mtime(&mut self, runner: &ProbeRunner, directory: &Path) -> Option<SystemTime> {
        if !self.path(directory) {
            return None;
        }
        let root = self.observe_optional_path(runner, || std::fs::symlink_metadata(directory))?;
        if !root.is_dir() || root.file_type().is_symlink() {
            return None;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
                FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
            };
            // Other reparse tags need not be classified as symbolic links by std. Do not
            // enumerate them or a root declaring recall/offline attributes for an activity hint.
            // https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
            if root.file_attributes()
                & (FILE_ATTRIBUTE_REPARSE_POINT
                    | FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0
            {
                return None;
            }
        }
        let mut newest = root.modified().ok()?;
        let mut entries = self.observe(runner, || std::fs::read_dir(directory))?;
        loop {
            // Iterator advancement consumes budget, including its terminal check. An exhausted
            // prefix cannot prove newest activity, so return unknown and discard its partial max.
            let next = self.observe(runner, || entries.next().transpose())?;
            let Some(entry) = next else {
                break;
            };
            let path = entry.path();
            if !self.path(&path) {
                return None;
            }
            let metadata = self.observe(runner, || std::fs::symlink_metadata(&path))?;
            // Link metadata describes the link itself; do not measure its target or read contents.
            let modified = metadata.modified().ok()?;
            newest = newest.max(modified);
        }
        self.available(runner).then_some(newest)
    }

    fn cache_newest_mtime(&mut self, runner: &ProbeRunner, directory: &Path) -> Option<SystemTime> {
        if !self.available(runner) {
            return None;
        }
        if let Some(observed) = self.cache_activity.get(directory) {
            return *observed;
        }
        let observed = self.newest_mtime(runner, directory);
        if self.path(directory) {
            self.cache_activity
                .insert(directory.to_path_buf(), observed);
        }
        observed
    }
}

/// Discovers a bounded positive npm inventory. For coverage/failure details use
/// [`discover_npm_installations_with_limits`]; this compatibility wrapper does not prove absence.
pub fn discover_npm_installations(runner: &mut ProbeRunner) -> Vec<ToolInstallation> {
    discover_npm_installations_with_limits(runner, ToolDiscoveryLimits::default()).installations
}

/// Discovers npm installations under one shared filesystem/data/probe budget.
///
/// Keeps manager precedence, marks the first supported PATH launcher as default, resolves each
/// executable spelling once, and measures each identical cache answer once per invocation.
/// Unknown answers and partial cache enumeration cannot establish inactivity or stale ownership.
/// Bounds are cooperative between synchronous host calls; they cannot interrupt blocking OS I/O.
pub fn discover_npm_installations_with_limits(
    runner: &mut ProbeRunner,
    limits: ToolDiscoveryLimits,
) -> ToolDiscoveryReport {
    let mut discovery = Discovery::new(limits);
    if !discovery.available(runner) {
        return finish(discovery, Vec::new());
    }
    // std::env owns these copies; reject oversized values before splitting or constructing layout
    // paths. Do not mutate the caller's environment to isolate discovery.
    for name in ["PATH", "HOME"] {
        if let Some(value) = std::env::var_os(name)
            && (value.len() > limits.max_path_bytes
                || !discovery.charge(
                    256usize.saturating_add(value.len().saturating_mul(if name == "HOME" {
                        40
                    } else {
                        4
                    })),
                ))
        {
            discovery.fail(ToolDiscoveryFailure::ResourceLimit);
            return finish(discovery, Vec::new());
        }
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    discover_from(
        runner,
        discovery,
        manager_layouts(),
        std::env::split_paths(&path),
    )
}

fn finish(discovery: Discovery, installations: Vec<ToolInstallation>) -> ToolDiscoveryReport {
    ToolDiscoveryReport {
        installations,
        incomplete_reason: discovery.failure,
        observations: discovery.observations,
        retained_bytes: discovery.retained_bytes,
    }
}

fn discover_from(
    runner: &mut ProbeRunner,
    mut discovery: Discovery,
    layouts: Vec<ManagerLayout>,
    paths: impl IntoIterator<Item = PathBuf>,
) -> ToolDiscoveryReport {
    let mut path_executables = Vec::new();
    let mut default_identity = None;
    for directory in paths {
        if !discovery.available(runner) || !discovery.path(&directory) {
            break;
        }
        #[cfg(windows)]
        let names = ["npm.cmd", "npm.bat", "npm.exe", "npm"];
        #[cfg(not(windows))]
        let names = ["npm"];
        for name in names {
            let executable = directory.join(name);
            if let Some(identity) = discovery.executable_identity(runner, &executable) {
                default_identity.get_or_insert_with(|| identity.clone());
                if !path_executables
                    .iter()
                    .any(|(_, existing)| *existing == identity)
                {
                    if path_executables.len() >= discovery.limits.max_installations {
                        discovery.fail(ToolDiscoveryFailure::ResourceLimit);
                        break;
                    }
                    path_executables.push((executable, identity));
                }
                break;
            }
        }
    }
    let mut raw = Vec::new();
    let mut seen = BTreeSet::new();
    for layout in layouts {
        if !discovery.available(runner) {
            break;
        }
        if let Some(executable) = layout.fixed_executable {
            admit(
                &mut discovery,
                runner,
                &mut seen,
                &mut raw,
                layout.manager,
                None,
                executable,
            );
        }
        let Some(root) = layout.versions_root else {
            continue;
        };
        if !discovery.path(&root) {
            break;
        }
        let Some(mut entries) =
            discovery.observe_optional_path(runner, || std::fs::read_dir(&root))
        else {
            continue;
        };
        while let Some(next) = discovery.observe(runner, || entries.next().transpose()) {
            let Some(entry) = next else {
                break;
            };
            let name = entry.file_name();
            if name.len() > discovery.limits.max_path_bytes
                || !discovery.charge(128usize.saturating_add(name.len().saturating_mul(2)))
            {
                discovery.fail(ToolDiscoveryFailure::ResourceLimit);
                break;
            }
            let mut executable = entry.path();
            for component in layout.executable_from_version {
                executable.push(component);
            }
            admit(
                &mut discovery,
                runner,
                &mut seen,
                &mut raw,
                layout.manager,
                name.to_str().map(str::to_owned),
                executable,
            );
        }
    }
    for (executable, identity) in path_executables {
        // These executable facts were observed before exhaustion. Retain them without new I/O;
        // the later answer pass preserves unknown cache/version values when admission is closed.
        admit_identity(
            &mut discovery,
            &mut seen,
            &mut raw,
            "path",
            None,
            executable,
            identity,
        );
    }
    let mut installations = Vec::new();
    for (manager, label, executable, identity) in raw {
        // Already admitted positive executable facts survive exhaustion with unknown answers.
        let cache = discovery
            .answer(runner, &executable, &["config", "get", "cache"], true)
            .map(PathBuf::from)
            .filter(|path| {
                if path.is_absolute() {
                    true
                } else {
                    discovery.fail(ToolDiscoveryFailure::ProbeUnavailable);
                    false
                }
            });
        let cache_last_active_at = cache
            .as_ref()
            .and_then(|cache| discovery.cache_newest_mtime(runner, cache))
            .and_then(rfc3339);
        installations.push(ToolInstallation {
            tool: "npm".into(),
            manager,
            manager_label: label,
            executable,
            tool_version: None,
            runtime_version: None,
            cache,
            cache_last_active_at,
            is_path_default: default_identity.as_ref() == Some(&identity),
        });
    }
    for installation in &mut installations {
        if !discovery.available(runner) {
            break;
        }
        installation.tool_version =
            discovery.answer(runner, &installation.executable, &["--version"], false);
        if let Some(bin) = installation.executable.parent() {
            let node = bin.join(if cfg!(windows) { "node.exe" } else { "node" });
            if discovery.executable_identity(runner, &node).is_some() {
                installation.runtime_version =
                    discovery.answer(runner, &node, &["--version"], false);
            }
        }
    }
    finish(discovery, installations)
}

type RawInstallation = (String, Option<String>, PathBuf, PathBuf);

fn admit(
    discovery: &mut Discovery,
    runner: &ProbeRunner,
    seen: &mut BTreeSet<PathBuf>,
    raw: &mut Vec<RawInstallation>,
    manager: &str,
    label: Option<String>,
    executable: PathBuf,
) {
    if let Some(identity) = discovery.executable_identity(runner, &executable) {
        admit_identity(discovery, seen, raw, manager, label, executable, identity);
    }
}

fn admit_identity(
    discovery: &mut Discovery,
    seen: &mut BTreeSet<PathBuf>,
    raw: &mut Vec<RawInstallation>,
    manager: &str,
    label: Option<String>,
    executable: PathBuf,
    identity: PathBuf,
) {
    if seen.contains(&identity) {
        return;
    }
    if raw.len() >= discovery.limits.max_installations
        || !discovery.path(&executable)
        || !discovery.path(&identity)
    {
        discovery.fail(ToolDiscoveryFailure::ResourceLimit);
        return;
    }
    seen.insert(identity.clone());
    raw.push((manager.into(), label, executable, identity));
}

fn rfc3339(time: SystemTime) -> Option<String> {
    OffsetDateTime::from(time).format(&Rfc3339).ok()
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests;
