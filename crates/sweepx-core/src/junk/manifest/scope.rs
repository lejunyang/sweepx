//! Invocation-local Cargo output observations. This models a Cargo invocation from the candidate's
//! parent with the captured environment and no CLI overrides, never a future build or Trash permit.
use super::config_native::{ConfigInputs, ConfigTarget};
use super::workspace::{WorkspaceError, resolve_workspace};
use super::workspace_native::{NativeWorkspaceSource, WorkspaceInputs};
use super::{CargoTargetDirPathKind, ProjectContextStatus};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sweepx_model::ScannedEntry;
use sweepx_platform::{CancellationToken, PlatformScanner};
use sweepx_scanner::{
    CargoConfigPairObservation, DirectoryPathObservation, LocatorDirectoryIdentity,
    LocatorDirectoryLookupFailure, LocatorReadError, LocatorReader,
};

/// Source selected in the explicitly modeled project-parent/no-CLI invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoOutputSource {
    /// Special environment variable, preferred to generic build configuration.
    CargoTargetDir,
    /// Generic configuration environment variable, with cwd-relative paths.
    CargoBuildTargetDir,
    /// Selected legacy/modern config below the candidate's parent.
    ProjectConfig,
    /// Nearest observed ancestor configuration declaring this scalar.
    AncestorConfig,
    /// Selected configuration directly in the captured Cargo home.
    CargoHomeConfig,
    /// Default target below the resolved workspace root.
    WorkspaceDefault,
    /// Default target below a standalone package.
    PackageDefault,
}
impl CargoOutputSource {
    /// Stable display/machine value.
    pub fn code(self) -> &'static str {
        match self {
            Self::CargoTargetDir => "cargo_target_dir",
            Self::CargoBuildTargetDir => "cargo_build_target_dir",
            Self::ProjectConfig => "project_config",
            Self::AncestorConfig => "ancestor_config",
            Self::CargoHomeConfig => "cargo_home_config",
            Self::WorkspaceDefault => "workspace_default",
            Self::PackageDefault => "package_default",
        }
    }
}

/// Exact native spelling comparison, separate from alias equivalence and execution identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoOutputPathComparison {
    /// Candidate and resolved spelling agree after candidate/origin native revalidation.
    SameSpelling,
    /// Revalidated candidate has a different exact spelling; aliases may still exist.
    DifferentSpelling,
    /// Missing binding, parent/dot or drive-relative syntax prevents this narrow comparison.
    NotChecked,
}
impl CargoOutputPathComparison {
    /// Stable display/machine value.
    pub fn code(self) -> &'static str {
        match self {
            Self::SameSpelling => "same_spelling",
            Self::DifferentSpelling => "different_spelling",
            Self::NotChecked => "not_checked",
        }
    }
}

/// Complete bounded membership and default-selection counts for this modeled invocation.
/// No member names, paths, build validity, ownership or execution permissions are serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoWorkspaceEvidence {
    /// True for a manifest declaring a workspace, including an empty virtual workspace.
    pub is_workspace: bool,
    /// Distinct package members; virtual manifest nodes are excluded.
    pub member_count: usize,
    /// Distinct packages selected by default from this modeled cwd.
    pub default_member_count: usize,
    /// Whether the modeled cwd is the resolved workspace/standalone root.
    pub project_is_root: bool,
}

/// Fixed-size, non-atomic output evidence. No raw path/config/environment value is serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoOutputEvidence {
    /// This is a modeled invocation, not the actual parameters of an arbitrary future build.
    pub scope: &'static str,
    /// Semantics independently checked against pinned Cargo, not an observed installed version.
    pub config_model: &'static str,
    /// Observed only when all supported source locations have been visited without a gap.
    pub status: ProjectContextStatus,
    /// Stable explanation of the observation or missing evidence.
    pub reason: &'static str,
    /// True for a completed time-local location walk; never a sealed snapshot/absence assertion.
    pub source_locations_observed: bool,
    /// Scalar source selected in this model; does not establish ownership or inactivity.
    pub source: Option<CargoOutputSource>,
    /// Zero for project config, positive for an ancestor, otherwise absent.
    pub ancestor_depth: Option<usize>,
    /// Lexical kind of the selected value on this host.
    pub path_kind: Option<CargoTargetDirPathKind>,
    /// Exact spelling only; no configured path is opened or used as execution authority.
    pub candidate_path: CargoOutputPathComparison,
    /// Membership is present only after every visited native input passes final revalidation.
    pub workspace: Option<CargoWorkspaceEvidence>,
}
impl CargoOutputEvidence {
    fn unknown(reason: &'static str) -> Self {
        Self {
            scope: "project_parent_current_env_no_cli",
            config_model: "cargo_1_98",
            status: if matches!(reason, "malformed_toml" | "duplicate_toml_key") {
                ProjectContextStatus::Invalid
            } else {
                ProjectContextStatus::Unknown
            },
            reason,
            source_locations_observed: false,
            source: None,
            ancestor_depth: None,
            path_kind: None,
            candidate_path: CargoOutputPathComparison::NotChecked,
            workspace: None,
        }
    }
}

/// Bounded private environment snapshot for one modeled Cargo invocation. Reconstruct per scan
/// invocation/revision; values never enter reports or filesystem caches. This type supplies data,
/// not authority, and does not claim knowledge of another process's environment/CLI parameters.
#[derive(Clone)]
pub struct CargoOutputEnvironment {
    target: Result<Option<String>, &'static str>,
    build: Result<Option<String>, &'static str>,
    home: Result<PathBuf, &'static str>,
    /// Only a process-environment snapshot may request a native fallback. Resolve it once,
    /// on the first Cargo observation's worker, within that session's cooperative budget.
    system_home_pending: bool,
}
impl CargoOutputEnvironment {
    /// Captures the three Cargo variables and the host's home variable without native I/O.
    /// Missing/empty user home requests one lazy OS lookup during Cargo interpretation on a
    /// worker. Native errors remain unknown; no tool launch or global environment change runs.
    pub fn current() -> Self {
        let target = std::env::var_os("CARGO_TARGET_DIR");
        let build = std::env::var_os("CARGO_BUILD_TARGET_DIR");
        let home = std::env::var_os("CARGO_HOME");
        let fallback = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
        Self::from_process_values(
            target.as_deref(),
            build.as_deref(),
            home.as_deref(),
            fallback.as_deref(),
        )
    }

    fn from_process_values(
        target: Option<&OsStr>,
        build: Option<&OsStr>,
        home: Option<&OsStr>,
        user_home: Option<&OsStr>,
    ) -> Self {
        let explicit = home.filter(|value| !value.is_empty());
        let fallback = user_home.filter(|value| !value.is_empty());
        let mut snapshot = Self::from_values(target, build, home, fallback);
        snapshot.system_home_pending = explicit.is_none() && fallback.is_none();
        snapshot
    }

    fn resolve_system_home_with(
        &mut self,
        cancel: &CancellationToken,
        budget: &ScopeBudget<'_>,
        lookup: impl FnOnce() -> Result<OsString, &'static str>,
    ) -> Result<(), &'static str> {
        if self.system_home_pending {
            budget.check(cancel)?;
            self.system_home_pending = false;
            let observed = lookup();
            // Native directory services may block in the host. A late/cancelled answer must
            // not become usable evidence; failures also deduplicate for this invocation only.
            self.home = budget.check(cancel).and_then(|()| {
                let user_home = observed?;
                Self::from_values(None, None, None, Some(&user_home)).home
            });
        }
        self.home.as_ref().map(|_| ()).map_err(|reason| *reason)
    }

    /// Admits explicit values for independent callers/tests, without changing process environment.
    /// Path values are capped before copying; non-Unicode output inputs remain unsupported.
    /// Empty Cargo home falls back to user home; relative home uses the explicitly modeled cwd.
    /// `user_home` supplies an already resolved user home, including a valid empty native home
    /// (`.cargo` relative to the modeled cwd). Missing data stays unknown, with no native fallback.
    pub fn from_values(
        target: Option<&OsStr>,
        build: Option<&OsStr>,
        home: Option<&OsStr>,
        user_home: Option<&OsStr>,
    ) -> Self {
        fn output(value: Option<&OsStr>) -> Result<Option<String>, &'static str> {
            let Some(value) = value else { return Ok(None) };
            if value.as_encoded_bytes().len() > 4096 {
                return Err("resource_limit");
            }
            let value = value.to_str().ok_or("environment_path_not_unicode")?;
            if value.is_empty() || value.contains('\0') {
                return Err("environment_output_invalid");
            }
            Ok(Some(value.to_owned()))
        }
        let home = (|| {
            let explicit = home.filter(|value| !value.is_empty());
            let value = explicit.or(user_home).ok_or("cargo_home_unavailable")?;
            if value.as_encoded_bytes().len() > 64 * 1024 {
                return Err("resource_limit");
            }
            if value.as_encoded_bytes().contains(&0) {
                return Err("cargo_home_invalid");
            }
            let mut path = PathBuf::from(value);
            if explicit.is_none() {
                path.push(".cargo")
            }
            if path.as_os_str().as_encoded_bytes().len() > 64 * 1024 {
                return Err("resource_limit");
            }
            Ok(path)
        })();
        Self {
            target: output(target),
            build: output(build),
            home,
            system_home_pending: false,
        }
    }
}

/// Worker-owned invocation configuration/workspace inputs. Each bounded source index is
/// reconstructed on refresh; retained parsing must pass native dependency revalidation.
pub(in crate::junk) struct CargoOutputSession {
    environment: CargoOutputEnvironment,
    config_inputs: ConfigInputs,
    workspace_inputs: WorkspaceInputs,
}

pub(in crate::junk) struct ScopeBudget<'a> {
    pub reserved_bytes: &'a mut usize,
    pub max_reserved_bytes: usize,
    pub file_bytes: usize,
    pub started: Instant,
    pub timeout: Duration,
}
impl ScopeBudget<'_> {
    pub(super) fn check(&self, cancel: &CancellationToken) -> Result<(), &'static str> {
        if cancel.is_cancelled() {
            Err("cancelled")
        } else if self.started.elapsed() >= self.timeout {
            Err("deadline")
        } else {
            Ok(())
        }
    }
    pub(super) fn reserve_file(&mut self, cancel: &CancellationToken) -> Result<(), &'static str> {
        self.check(cancel)?;
        let total = self
            .reserved_bytes
            .checked_add(self.file_bytes)
            .ok_or("resource_limit")?;
        if self.file_bytes == 0 || total > self.max_reserved_bytes {
            return Err("resource_limit");
        }
        *self.reserved_bytes = total;
        Ok(())
    }
    pub(super) fn reserve_pair(&mut self, cancel: &CancellationToken) -> Result<(), &'static str> {
        self.check(cancel)?;
        let total = self
            .file_bytes
            .checked_mul(2)
            .and_then(|n| self.reserved_bytes.checked_add(n))
            .ok_or("resource_limit")?;
        if self.file_bytes == 0 || total > self.max_reserved_bytes {
            return Err("resource_limit");
        }
        *self.reserved_bytes = total;
        Ok(())
    }
}

impl CargoOutputSession {
    pub fn new(environment: CargoOutputEnvironment) -> Self {
        Self {
            environment,
            config_inputs: ConfigInputs::default(),
            workspace_inputs: WorkspaceInputs::default(),
        }
    }

    pub fn observe<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        entry: &ScannedEntry,
        local: &CargoConfigPairObservation,
        cancel: &CancellationToken,
        mut budget: ScopeBudget<'_>,
    ) -> CargoOutputEvidence {
        self.try_observe(reader, entry, local, cancel, &mut budget)
            .unwrap_or_else(CargoOutputEvidence::unknown)
    }

    fn try_observe<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        entry: &ScannedEntry,
        local: &CargoConfigPairObservation,
        cancel: &CancellationToken,
        budget: &mut ScopeBudget<'_>,
    ) -> Result<CargoOutputEvidence, &'static str> {
        budget.check(cancel)?;
        let target = self.environment.target.as_ref().map_err(|reason| *reason)?;
        if target.is_none() {
            self.environment.build.as_ref().map_err(|reason| *reason)?;
        }
        self.environment
            .resolve_system_home_with(cancel, budget, super::home::lookup)?;
        self.config_inputs.begin();
        let project = reader
            .capture_scanned_ancestor_directory(entry, 1, cancel)
            .map_err(read_error)?;
        let mut directory = project.clone();
        let mut selected = None;
        for depth in 0..16 {
            budget.check(cancel)?;
            let value = self.source(
                reader,
                &directory,
                true,
                if depth == 0 { Some(local) } else { None },
                cancel,
                budget,
            )?;
            if selected.is_none()
                && let Some(target) = value
            {
                selected = Some((
                    target.include_base.unwrap_or_else(|| directory.clone()),
                    target.value,
                    if depth == 0 {
                        CargoOutputSource::ProjectConfig
                    } else {
                        CargoOutputSource::AncestorConfig
                    },
                    Some(depth),
                    true,
                ));
            }
            match reader
                .capture_parent_directory(&directory, cancel)
                .map_err(|error| {
                    if error == LocatorReadError::InvalidRequest {
                        "ancestor_binding_unavailable"
                    } else {
                        read_error(error)
                    }
                })? {
                Some(parent) if depth == 15 => {
                    let _ = parent;
                    return Err("ancestor_scope_limit");
                }
                Some(parent) => directory = parent,
                None => break,
            }
        }
        // One bounded invocation-local copy avoids holding an environment borrow while indexing
        // observed configuration sources. The admission cap was checked before environment copy.
        let home_path = self
            .environment
            .home
            .as_ref()
            .map_err(|reason| *reason)?
            .clone();
        budget.check(cancel)?;
        let home_observation = reader
            .observe_directory_path(&project, &home_path, cancel)
            .map_err(directory_reason)?;
        if let DirectoryPathObservation::Present(home) = &home_observation {
            let home_value = self.source(reader, home, false, None, cancel, budget)?;
            if selected.is_none()
                && let Some(target) = home_value
            {
                let value = target.value;
                let (origin, comparable) = if let Some(base) = target.include_base {
                    (base, true)
                } else if Path::new(&value).is_absolute() {
                    (home.clone(), true)
                } else {
                    let (base, comparable) = reader
                        .observe_cargo_home_output_base(&project, &home_path, cancel)
                        .map_err(directory_reason)?;
                    let DirectoryPathObservation::Present(origin) = base else {
                        return Err("cargo_home_path_base_unavailable");
                    };
                    (origin, comparable)
                };
                selected = Some((
                    origin,
                    value,
                    CargoOutputSource::CargoHomeConfig,
                    None,
                    comparable,
                ));
            }
        }
        // The special variable is outside generic config merging; preserve its measured priority.
        if let Some(value) = self.environment.target.as_ref().map_err(|reason| *reason)? {
            selected = Some((
                project.clone(),
                value.clone(),
                CargoOutputSource::CargoTargetDir,
                None,
                true,
            ));
        } else if let Some(value) = self.environment.build.as_ref().map_err(|reason| *reason)? {
            selected = Some((
                project.clone(),
                value.clone(),
                CargoOutputSource::CargoBuildTargetDir,
                None,
                true,
            ));
        }
        budget.check(cancel)?;
        if reader
            .capture_scanned_ancestor_directory(entry, 1, cancel)
            .map_err(read_error)?
            != project
        {
            return Err("project_binding_changed");
        }
        let workspace_observation = (|| -> Result<_, WorkspaceError> {
            let mut native =
                NativeWorkspaceSource::new(reader, cancel, budget, &mut self.workspace_inputs);
            let project_id = native.intern(project.clone())?;
            let resolution = resolve_workspace(&mut native, &project_id)?;
            native.finish()?;
            let facts = CargoWorkspaceEvidence {
                is_workspace: resolution.is_workspace,
                member_count: resolution.members.len(),
                default_member_count: resolution.default_members.len(),
                project_is_root: project_id == resolution.root,
            };
            Ok((native.directory(resolution.root).clone(), facts))
        })();
        let (root, workspace) = match workspace_observation {
            Ok(observed) => observed,
            Err(error) => {
                let mut evidence = CargoOutputEvidence::unknown(error.reason());
                if matches!(error, WorkspaceError::Invalid(_)) {
                    evidence.status = ProjectContextStatus::Invalid;
                }
                return Ok(evidence);
            }
        };
        self.config_inputs.finish(reader, cancel, budget)?;
        budget.check(cancel)?;
        if reader
            .observe_directory_path(&project, &home_path, cancel)
            .map_err(directory_reason)?
            != home_observation
        {
            return Err("cargo_home_binding_changed");
        }
        let default_output = selected.is_none();
        let (origin, value, source, depth, base_comparable) = selected.unwrap_or_else(|| {
            (
                root,
                "target".to_owned(),
                if workspace.is_workspace {
                    CargoOutputSource::WorkspaceDefault
                } else {
                    CargoOutputSource::PackageDefault
                },
                None,
                true,
            )
        });
        // A non-comparable lexical path is separate from failed native revalidation. Do not
        // turn an origin replacement/denial into an apparently complete observation.
        reader
            .revalidate_captured_directory(&origin, cancel)
            .map_err(read_error)?;
        let path = Path::new(&value);
        let unresolved = !base_comparable
            || value
                .split(|ch| ch == '/' || (cfg!(windows) && ch == '\\'))
                .any(|part| matches!(part, "." | ".."))
            || (path.has_root() && !path.is_absolute())
            || (!path.is_absolute()
                && matches!(
                    path.components().next(),
                    Some(std::path::Component::Prefix(_))
                ));
        let candidate_path = if unresolved {
            CargoOutputPathComparison::NotChecked
        } else {
            match reader.compare_scanned_directory_to_configured_path(entry, &origin, path, cancel)
            {
                Ok(true) => CargoOutputPathComparison::SameSpelling,
                Ok(false) => CargoOutputPathComparison::DifferentSpelling,
                Err(error) => return Err(read_error(error)),
            }
        };
        budget.check(cancel)?;
        Ok(CargoOutputEvidence {
            scope: "project_parent_current_env_no_cli",
            config_model: "cargo_1_98",
            status: ProjectContextStatus::Observed,
            reason: if default_output {
                "default_output_observed_non_atomic"
            } else {
                "configured_output_observed_non_atomic"
            },
            source_locations_observed: true,
            source: Some(source),
            ancestor_depth: depth,
            path_kind: Some(CargoTargetDirPathKind::from_value(&value)),
            candidate_path,
            workspace: Some(workspace),
        })
    }

    fn source<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        directory: &LocatorDirectoryIdentity,
        nested: bool,
        supplied: Option<&CargoConfigPairObservation>,
        cancel: &CancellationToken,
        budget: &mut ScopeBudget<'_>,
    ) -> Result<Option<ConfigTarget>, &'static str> {
        self.config_inputs
            .source(reader, directory, nested, supplied, cancel, budget)
    }
}

pub(super) fn read_error(error: LocatorReadError) -> &'static str {
    match error {
        LocatorReadError::Cancelled => "cancelled",
        LocatorReadError::ResourceLimit => "resource_limit",
        LocatorReadError::InvalidRequest => "native_binding_unavailable",
    }
}

fn directory_reason(error: LocatorDirectoryLookupFailure) -> &'static str {
    match error {
        LocatorDirectoryLookupFailure::Read(reason) => super::super::format::read_reason(reason),
        LocatorDirectoryLookupFailure::NotDirectory => "cargo_home_not_directory",
        LocatorDirectoryLookupFailure::NotFoundDuringLookup => "cargo_home_lookup_changed",
    }
}

#[cfg(test)]
#[path = "scope_home_tests.rs"]
mod home_tests;
