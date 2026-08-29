use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

use sweepx_model::{
    EvidenceValue, IdentityEvidence, NativeAbsolutePath, NativeLocatorEvidence, NativeName,
    NativePathComponent, ObjectType, ScannedEntry,
};
use sweepx_platform::{
    BoundedRegularFileReadError, BoundedRegularFileReadRequest, CancellationToken,
    DirectoryEntryRecord, DirectoryHandleAdmission, DirectoryReadLimits, EntryIdentity, EntryKind,
    FilesystemIdentity, MountIdentity, PlatformError, PlatformScanner, PresentRegularFileRead,
    RootAdmission, ScanRoot, WalkEntry, inspect_bound_child,
    inspect_bound_child_with_directory_admission, read_bound_regular_file,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatorReadLimits {
    pub max_requests: usize,
    pub max_components_per_request: usize,
    pub max_total_components: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_directory_entries: usize,
    pub max_directory_bytes: usize,
    pub max_directory_batch_entries: usize,
    pub max_directory_batch_bytes: usize,
}

impl Default for LocatorReadLimits {
    fn default() -> Self {
        Self {
            max_requests: 16,
            max_components_per_request: 8,
            max_total_components: 64,
            max_file_bytes: 4 * 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_directory_entries: 4096,
            max_directory_bytes: 4 * 1024 * 1024,
            max_directory_batch_entries: 256,
            max_directory_batch_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum LocatorFileRequest<'a> {
    ScannedFile { entry: &'a ScannedEntry },
    RelativeOptional { components: &'a [NativeName] },
}

#[derive(Debug, Clone, Copy)]
pub struct LocatorBatchReadRequest<'a> {
    pub base_directory: &'a ScannedEntry,
    pub files: &'a [LocatorFileRequest<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorFileRead {
    Present(Box<PresentRegularFileRead>),
    VerifiedAbsent,
    Failed(LocatorReadFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorBatchReadResult {
    pub files: Vec<LocatorFileRead>,
    pub total_bytes: usize,
}

/// One fixed Cargo configuration member observed during a single, bounded directory walk.
///
/// `AbsentDuringEnumeration` is deliberately weaker than `LocatorFileRead::VerifiedAbsent`:
/// without a platform-sealed directory generation it is only a time-local observation and must
/// never be promoted into an atomic absence claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoConfigMemberObservation {
    Present(Box<PresentRegularFileRead>),
    AbsentDuringEnumeration,
    Failed(LocatorReadFailure),
}

impl CargoConfigMemberObservation {
    pub fn observed_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Present(read) => Some(read.bytes.as_slice()),
            Self::AbsentDuringEnumeration | Self::Failed(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoConfigPairConsistency {
    NonAtomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoConfigPairObservation {
    pub consistency: CargoConfigPairConsistency,
    pub config: CargoConfigMemberObservation,
    pub config_toml: CargoConfigMemberObservation,
    pub total_bytes: usize,
}

/// Presence-only observation for one fixed Cargo configuration member.
///
/// Unlike [`CargoConfigMemberObservation`], `Present` carries neither bytes nor metadata. The
/// scanner establishes it by handle-bound inspection of a regular file with complete
/// identity/filesystem/mount evidence, then immediately discards that private metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CargoConfigMemberPresenceObservation {
    Present,
    AbsentDuringEnumeration,
    Failed(LocatorReadFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoConfigPairPresenceObservation {
    pub consistency: CargoConfigPairConsistency,
    pub config: CargoConfigMemberPresenceObservation,
    pub config_toml: CargoConfigMemberPresenceObservation,
}

#[derive(Debug, Default)]
struct BatchBudget {
    enumerated_entries: usize,
    enumerated_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LocatorReadFailure {
    #[error("request is not bound to the executable base locator")]
    InvalidBinding,
    #[error("filesystem object identity changed")]
    IdentityMismatch,
    #[error("filesystem mount changed")]
    MountChanged,
    #[error("symlink or reparse point rejected")]
    SymlinkOrReparse,
    #[error("resolved object is not a regular file")]
    NotRegular,
    #[error("resource limit exceeded")]
    ResourceLimit,
    #[error("operation cancelled")]
    Cancelled,
    #[error("platform read failed closed")]
    ReadFailed,
    #[error("provider or offline object is unavailable")]
    ProviderOrOffline,
    #[error("platform operation unavailable")]
    Unavailable,
    #[error("fixed-name alias or duplicate is ambiguous")]
    AmbiguousAlias,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LocatorReadError {
    #[error("batch request is invalid")]
    InvalidRequest,
    #[error("batch resource limit exceeded")]
    ResourceLimit,
    #[error("batch cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorDirectoryIdentity {
    native_absolute_path: NativeAbsolutePath,
    kind: EntryKind,
    identity: EntryIdentity,
    filesystem_identity: FilesystemIdentity,
    mount_identity: MountIdentity,
    fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocatorDirectoryComparison {
    PathAndIdentityMatch,
    DifferentNativePath,
    Failed(LocatorDirectoryComparisonFailure),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LocatorDirectoryComparisonFailure {
    #[error("operation cancelled")]
    Cancelled,
    #[error("resource limit exceeded")]
    ResourceLimit,
    #[error("base directory could not be revalidated")]
    RevalidationFailed,
}

pub struct LocatorReader<P> {
    platform: P,
    limits: LocatorReadLimits,
}

impl<P: PlatformScanner> LocatorReader<P> {
    pub fn new(platform: P, limits: LocatorReadLimits) -> Self {
        Self { platform, limits }
    }

    pub fn read_batch(
        &self,
        request: LocatorBatchReadRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<LocatorBatchReadResult, LocatorReadError> {
        self.validate_batch(&request)?;
        if cancel.is_cancelled() {
            return Err(LocatorReadError::Cancelled);
        }
        let mut outputs = Vec::with_capacity(request.files.len());
        let mut total_bytes = 0usize;
        let mut budget = BatchBudget::default();
        for file in request.files {
            if cancel.is_cancelled() {
                outputs.push(LocatorFileRead::Failed(LocatorReadFailure::Cancelled));
                outputs.extend(std::iter::repeat_n(
                    LocatorFileRead::Failed(LocatorReadFailure::Cancelled),
                    request.files.len().saturating_sub(outputs.len()),
                ));
                break;
            }
            let remaining_total_bytes = self.limits.max_total_bytes.saturating_sub(total_bytes);
            let read_limit = self.limits.max_file_bytes.min(remaining_total_bytes);
            let outcome = match file {
                LocatorFileRequest::ScannedFile { entry } => self.read_scanned_file(
                    request.base_directory,
                    entry,
                    read_limit,
                    cancel,
                    &mut budget,
                ),
                LocatorFileRequest::RelativeOptional { components } => self.read_optional(
                    request.base_directory,
                    components,
                    read_limit,
                    cancel,
                    &mut budget,
                ),
            };
            let outcome = match outcome {
                Ok(read) => {
                    let next_total = total_bytes
                        .checked_add(read.bytes.len())
                        .ok_or(LocatorReadError::ResourceLimit)?;
                    if next_total > self.limits.max_total_bytes {
                        LocatorFileRead::Failed(LocatorReadFailure::ResourceLimit)
                    } else {
                        total_bytes = next_total;
                        LocatorFileRead::Present(Box::new(read))
                    }
                }
                Err(ReadAttempt::Absent) => LocatorFileRead::VerifiedAbsent,
                Err(ReadAttempt::Failed(failure)) => LocatorFileRead::Failed(failure),
            };
            outputs.push(outcome);
        }
        Ok(LocatorBatchReadResult {
            files: outputs,
            total_bytes,
        })
    }

    /// Observes Cargo's two workspace-local config names through one retained `.cargo` handle and
    /// one bounded enumeration cursor. This deliberately returns `NonAtomic`: directory
    /// enumeration alone cannot exclude create/delete/rename ABA on any supported platform.
    pub fn observe_cargo_config_pair(
        &self,
        base_directory: &ScannedEntry,
        cancel: &CancellationToken,
    ) -> Result<CargoConfigPairObservation, LocatorReadError> {
        self.validate_base_directory(base_directory)?;
        self.validate_cargo_pair_budget(base_directory)?;
        if cancel.is_cancelled() {
            return Err(LocatorReadError::Cancelled);
        }
        let mut budget = BatchBudget::default();
        let mut root = match self.reopen_base(base_directory, cancel, &mut budget) {
            Ok(root) => root,
            Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled)) => {
                return Err(LocatorReadError::Cancelled);
            }
            Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit)) => {
                return Err(LocatorReadError::ResourceLimit);
            }
            Err(ReadAttempt::Absent) | Err(ReadAttempt::Failed(_)) => {
                return Err(LocatorReadError::InvalidRequest);
            }
        };
        let mut cargo = match self.find_cargo_directory(&mut root, cancel, &mut budget) {
            Ok(Some(cargo)) => cargo,
            Ok(None) | Err(ReadAttempt::Absent) => {
                return Ok(CargoConfigPairObservation {
                    consistency: CargoConfigPairConsistency::NonAtomic,
                    config: CargoConfigMemberObservation::AbsentDuringEnumeration,
                    config_toml: CargoConfigMemberObservation::AbsentDuringEnumeration,
                    total_bytes: 0,
                });
            }
            Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled)) => {
                return Err(LocatorReadError::Cancelled);
            }
            Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit)) => {
                return Err(LocatorReadError::ResourceLimit);
            }
            Err(ReadAttempt::Failed(failure)) => return Ok(pair_failed(failure)),
        };
        Ok(self.observe_cargo_config_members(&mut cargo, cancel, &mut budget))
    }

    /// Observes Cargo's two configuration names directly inside one previously captured
    /// directory, as required for an explicit `CARGO_HOME`.
    ///
    /// The captured native path remains private. It is re-admitted exactly, and the resulting
    /// directory kind, object identity, filesystem, mount, and fingerprint must all match the
    /// capture before this method enumerates anything. Exact members are only inspected as
    /// identity-bearing regular files; their contents are never read or retained. The returned
    /// pair is deliberately `NonAtomic`: one retained handle and one bounded enumeration cursor
    /// prevent pathname substitution, but cannot prove a sealed directory generation.
    pub fn observe_cargo_config_pair_in_captured_directory(
        &self,
        captured: &LocatorDirectoryIdentity,
        cancel: &CancellationToken,
    ) -> Result<CargoConfigPairPresenceObservation, LocatorReadError> {
        self.validate_captured_cargo_pair_budget(captured)?;
        if cancel.is_cancelled() {
            return Err(LocatorReadError::Cancelled);
        }
        let mut directory = match self.reopen_captured_directory(captured, cancel) {
            Ok(directory) => directory,
            Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled)) => {
                return Err(LocatorReadError::Cancelled);
            }
            Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit)) => {
                return Err(LocatorReadError::ResourceLimit);
            }
            Err(ReadAttempt::Absent) => {
                return Ok(presence_pair_failed(LocatorReadFailure::IdentityMismatch));
            }
            Err(ReadAttempt::Failed(failure)) => return Ok(presence_pair_failed(failure)),
        };
        let mut budget = BatchBudget::default();
        Ok(self.observe_cargo_config_member_presence(&mut directory, cancel, &mut budget))
    }

    fn observe_cargo_config_members(
        &self,
        directory: &mut OpenedDirectory<P::DirectoryHandle>,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> CargoConfigPairObservation {
        let mut config = None;
        let mut config_toml = None;
        let mut saw_config = false;
        let mut saw_config_toml = false;
        let mut total_bytes = 0usize;
        let mut alias_collision = false;
        let mut observation_failure = None;

        loop {
            let batch = match self.next_directory_batch(directory, cancel, budget) {
                Ok(batch) => batch,
                Err(failure) => return pair_failed(failure),
            };
            for child in &batch.entries {
                let slot = cargo_config_slot(&child.file_name);
                match slot {
                    CargoConfigSlot::Other => {}
                    CargoConfigSlot::Alias => {
                        alias_collision = true;
                    }
                    CargoConfigSlot::Config => {
                        if saw_config {
                            alias_collision = true;
                        } else {
                            saw_config = true;
                            let observed = self.read_cargo_config_member(
                                directory,
                                child,
                                &mut total_bytes,
                                cancel,
                            );
                            if let Err(failure) = &observed {
                                observation_failure.get_or_insert_with(|| failure.clone());
                            }
                            config = Some(observed);
                        }
                    }
                    CargoConfigSlot::ConfigToml => {
                        if saw_config_toml {
                            alias_collision = true;
                        } else {
                            saw_config_toml = true;
                            let observed = self.read_cargo_config_member(
                                directory,
                                child,
                                &mut total_bytes,
                                cancel,
                            );
                            if let Err(failure) = &observed {
                                observation_failure.get_or_insert_with(|| failure.clone());
                            }
                            config_toml = Some(observed);
                        }
                    }
                }
            }
            if batch.end_of_directory {
                break;
            }
        }

        if alias_collision {
            return pair_failed(LocatorReadFailure::AmbiguousAlias);
        }
        if let Some(failure) = observation_failure {
            return pair_failed(failure);
        }
        let config = match config {
            Some(Err(failure)) => return pair_failed(failure),
            Some(Ok(read)) => CargoConfigMemberObservation::Present(Box::new(read)),
            None => CargoConfigMemberObservation::AbsentDuringEnumeration,
        };
        let config_toml = match config_toml {
            Some(Err(failure)) => return pair_failed(failure),
            Some(Ok(read)) => CargoConfigMemberObservation::Present(Box::new(read)),
            None => CargoConfigMemberObservation::AbsentDuringEnumeration,
        };
        CargoConfigPairObservation {
            consistency: CargoConfigPairConsistency::NonAtomic,
            config,
            config_toml,
            total_bytes,
        }
    }

    fn observe_cargo_config_member_presence(
        &self,
        directory: &mut OpenedDirectory<P::DirectoryHandle>,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> CargoConfigPairPresenceObservation {
        let mut config = None;
        let mut config_toml = None;
        let mut saw_config = false;
        let mut saw_config_toml = false;
        let mut alias_collision = false;
        let mut observation_failure = None;

        loop {
            let batch = match self.next_directory_batch(directory, cancel, budget) {
                Ok(batch) => batch,
                Err(failure) => return presence_pair_failed(failure),
            };
            if cancel.is_cancelled() {
                return presence_pair_failed(LocatorReadFailure::Cancelled);
            }
            for child in &batch.entries {
                match cargo_config_slot(&child.file_name) {
                    CargoConfigSlot::Other => {}
                    CargoConfigSlot::Alias => {
                        alias_collision = true;
                    }
                    CargoConfigSlot::Config => {
                        if saw_config {
                            alias_collision = true;
                        } else {
                            saw_config = true;
                            let observed =
                                self.inspect_cargo_config_member(directory, child, cancel);
                            if let Err(failure) = &observed {
                                observation_failure.get_or_insert_with(|| failure.clone());
                            }
                            config = Some(observed);
                        }
                    }
                    CargoConfigSlot::ConfigToml => {
                        if saw_config_toml {
                            alias_collision = true;
                        } else {
                            saw_config_toml = true;
                            let observed =
                                self.inspect_cargo_config_member(directory, child, cancel);
                            if let Err(failure) = &observed {
                                observation_failure.get_or_insert_with(|| failure.clone());
                            }
                            config_toml = Some(observed);
                        }
                    }
                }
            }
            if batch.end_of_directory {
                break;
            }
        }

        if alias_collision {
            return presence_pair_failed(LocatorReadFailure::AmbiguousAlias);
        }
        if let Some(failure) = observation_failure {
            return presence_pair_failed(failure);
        }
        let config = match config {
            Some(Ok(())) => CargoConfigMemberPresenceObservation::Present,
            Some(Err(failure)) => return presence_pair_failed(failure),
            None => CargoConfigMemberPresenceObservation::AbsentDuringEnumeration,
        };
        let config_toml = match config_toml {
            Some(Ok(())) => CargoConfigMemberPresenceObservation::Present,
            Some(Err(failure)) => return presence_pair_failed(failure),
            None => CargoConfigMemberPresenceObservation::AbsentDuringEnumeration,
        };
        CargoConfigPairPresenceObservation {
            consistency: CargoConfigPairConsistency::NonAtomic,
            config,
            config_toml,
        }
    }

    /// Captures one admitted directory identity snapshot from the current platform without
    /// exposing the path or any forgeable public fields.
    pub fn capture_directory_identity(
        &self,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<LocatorDirectoryIdentity, LocatorReadError> {
        if cancel.is_cancelled() {
            return Err(LocatorReadError::Cancelled);
        }
        let root =
            ScanRoot::new(path.to_path_buf()).map_err(|_| LocatorReadError::InvalidRequest)?;
        let admission = self
            .platform
            .admit_root(&root, cancel)
            .map_err(map_capture_platform_error)?;
        admission
            .validate_for_root(&root)
            .map_err(|_| LocatorReadError::InvalidRequest)?;
        let RootAdmission {
            root_locator,
            metadata,
            ..
        } = admission;
        if cancel.is_cancelled() {
            return Err(LocatorReadError::Cancelled);
        }
        if metadata.kind != EntryKind::Directory {
            return Err(LocatorReadError::InvalidRequest);
        }
        let (Some(identity), Some(filesystem_identity), Some(mount_identity)) = (
            metadata.identity,
            metadata.filesystem_identity,
            metadata.mount_identity,
        ) else {
            return Err(LocatorReadError::InvalidRequest);
        };
        Ok(LocatorDirectoryIdentity {
            native_absolute_path: root_locator,
            kind: metadata.kind,
            identity,
            filesystem_identity,
            mount_identity,
            fingerprint: metadata.fingerprint,
        })
    }

    /// Compares one invocation-time directory snapshot with one live scanned directory. A match
    /// proves exact native path equality and equal captured/revalidated identity metadata, but it
    /// does not retain either directory handle across the interval.
    ///
    /// The exact target path is reconstructed only for comparison from the admitted scan root and
    /// the target's validated native lineage. Revalidation always starts from the admitted scan
    /// root and walks that lineage handle-relatively; the reconstructed target path is never
    /// admitted and `display_path` is never execution authority.
    pub fn compare_scanned_directory_snapshot(
        &self,
        target: &ScannedEntry,
        captured: &LocatorDirectoryIdentity,
        cancel: &CancellationToken,
    ) -> Result<LocatorDirectoryComparison, LocatorReadError> {
        self.validate_scanned_directory(target)?;
        let locator = target
            .executable_native_locator()
            .map_err(|_| LocatorReadError::InvalidRequest)?
            .ok_or(LocatorReadError::InvalidRequest)?;
        let expected_target =
            native_target_absolute_path(locator).map_err(|_| LocatorReadError::InvalidRequest)?;
        if !native_absolute_paths_equal_exact(&captured.native_absolute_path, &expected_target)
            .map_err(|_| LocatorReadError::InvalidRequest)?
        {
            return Ok(LocatorDirectoryComparison::DifferentNativePath);
        }
        if cancel.is_cancelled() {
            return Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::Cancelled,
            ));
        }
        if let Err(error) = self.validate_directory_binding_budget(target) {
            return Ok(match error {
                LocatorReadError::ResourceLimit => LocatorDirectoryComparison::Failed(
                    LocatorDirectoryComparisonFailure::ResourceLimit,
                ),
                LocatorReadError::Cancelled => {
                    LocatorDirectoryComparison::Failed(LocatorDirectoryComparisonFailure::Cancelled)
                }
                LocatorReadError::InvalidRequest => {
                    return Err(LocatorReadError::InvalidRequest);
                }
            });
        }

        let mut budget = BatchBudget::default();
        match self.reopen_base(target, cancel, &mut budget) {
            Ok(reopened) => {
                if cancel.is_cancelled() {
                    Ok(LocatorDirectoryComparison::Failed(
                        LocatorDirectoryComparisonFailure::Cancelled,
                    ))
                } else if directory_identity_matches_capture(&reopened.metadata, captured) {
                    Ok(LocatorDirectoryComparison::PathAndIdentityMatch)
                } else {
                    Ok(LocatorDirectoryComparison::Failed(
                        LocatorDirectoryComparisonFailure::RevalidationFailed,
                    ))
                }
            }
            Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled)) => Ok(
                LocatorDirectoryComparison::Failed(LocatorDirectoryComparisonFailure::Cancelled),
            ),
            Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit)) => {
                Ok(LocatorDirectoryComparison::Failed(
                    LocatorDirectoryComparisonFailure::ResourceLimit,
                ))
            }
            Err(ReadAttempt::Failed(_)) | Err(ReadAttempt::Absent) => {
                Ok(LocatorDirectoryComparison::Failed(
                    LocatorDirectoryComparisonFailure::RevalidationFailed,
                ))
            }
        }
    }

    /// Root-only compatibility wrapper for callers that bind an invocation directory to the scan
    /// base. Non-root directories must use [`Self::compare_scanned_directory_snapshot`].
    pub fn compare_base_directory_snapshot(
        &self,
        base_directory: &ScannedEntry,
        captured: &LocatorDirectoryIdentity,
        cancel: &CancellationToken,
    ) -> Result<LocatorDirectoryComparison, LocatorReadError> {
        self.validate_base_directory(base_directory)?;
        self.compare_scanned_directory_snapshot(base_directory, captured, cancel)
    }

    fn validate_batch(
        &self,
        request: &LocatorBatchReadRequest<'_>,
    ) -> Result<(), LocatorReadError> {
        if request.files.is_empty()
            || request.files.len() > self.limits.max_requests
            || request.base_directory.object_type != ObjectType::Directory
            || request
                .base_directory
                .executable_native_locator()
                .map_err(|_| LocatorReadError::InvalidRequest)?
                .is_none()
        {
            return Err(LocatorReadError::InvalidRequest);
        }
        let base_locator = request
            .base_directory
            .executable_native_locator()
            .map_err(|_| LocatorReadError::InvalidRequest)?
            .ok_or(LocatorReadError::InvalidRequest)?;
        let base_components = base_locator
            .parent_reopen_recipe
            .len()
            .checked_add(1)
            .ok_or(LocatorReadError::ResourceLimit)?;
        let mut total_components = 0usize;
        for file in request.files {
            let relative_components = match file {
                LocatorFileRequest::ScannedFile { entry } => {
                    if entry.object_type != ObjectType::File {
                        return Err(LocatorReadError::InvalidRequest);
                    }
                    1
                }
                LocatorFileRequest::RelativeOptional { components } => {
                    if components.is_empty()
                        || components.len() > self.limits.max_components_per_request
                        || components
                            .iter()
                            .any(|name| name.validate_basename_for_current_platform().is_err())
                    {
                        return Err(LocatorReadError::InvalidRequest);
                    }
                    components.len()
                }
            };
            let operation_components = base_components
                .checked_add(relative_components)
                .ok_or(LocatorReadError::ResourceLimit)?;
            if operation_components > self.limits.max_components_per_request {
                return Err(LocatorReadError::ResourceLimit);
            }
            total_components = total_components
                .checked_add(operation_components)
                .ok_or(LocatorReadError::ResourceLimit)?;
        }
        if total_components > self.limits.max_total_components {
            return Err(LocatorReadError::ResourceLimit);
        }
        Ok(())
    }

    fn validate_directory_binding_budget(
        &self,
        base: &ScannedEntry,
    ) -> Result<(), LocatorReadError> {
        let locator = base
            .executable_native_locator()
            .map_err(|_| LocatorReadError::InvalidRequest)?
            .ok_or(LocatorReadError::InvalidRequest)?;
        let base_components = locator
            .parent_reopen_recipe
            .len()
            .checked_add(1)
            .ok_or(LocatorReadError::ResourceLimit)?;
        if self.limits.max_requests == 0
            || base_components > self.limits.max_components_per_request
            || base_components > self.limits.max_total_components
        {
            return Err(LocatorReadError::ResourceLimit);
        }
        Ok(())
    }

    fn validate_base_directory(&self, base: &ScannedEntry) -> Result<(), LocatorReadError> {
        let identity = base
            .validated_identity()
            .map_err(|_| LocatorReadError::InvalidRequest)?
            .ok_or(LocatorReadError::InvalidRequest)?;
        if base.object_type != ObjectType::Directory
            || identity.parent_id.is_some()
            || identity.entry_id != identity.scan_root_id
            || !matches!(
                base.provenance,
                sweepx_model::FieldProvenance::LiveObservation { .. }
            )
            || !matches!(
                base.coverage.provenance,
                sweepx_model::FieldProvenance::LiveObservation { .. }
            )
            || base
                .executable_native_locator()
                .map_err(|_| LocatorReadError::InvalidRequest)?
                .is_none()
        {
            return Err(LocatorReadError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_scanned_directory(&self, target: &ScannedEntry) -> Result<(), LocatorReadError> {
        if target.object_type != ObjectType::Directory
            || !matches!(
                target.provenance,
                sweepx_model::FieldProvenance::LiveObservation { .. }
            )
            || !matches!(
                target.coverage.provenance,
                sweepx_model::FieldProvenance::LiveObservation { .. }
            )
            || target
                .validated_identity()
                .map_err(|_| LocatorReadError::InvalidRequest)?
                .is_none()
            || target
                .executable_native_locator()
                .map_err(|_| LocatorReadError::InvalidRequest)?
                .is_none()
        {
            return Err(LocatorReadError::InvalidRequest);
        }
        Ok(())
    }

    fn validate_cargo_pair_budget(&self, base: &ScannedEntry) -> Result<(), LocatorReadError> {
        if self.limits.max_requests < 3 {
            return Err(LocatorReadError::ResourceLimit);
        }
        let locator = base
            .executable_native_locator()
            .map_err(|_| LocatorReadError::InvalidRequest)?
            .ok_or(LocatorReadError::InvalidRequest)?;
        let base_components = locator
            .parent_reopen_recipe
            .len()
            .checked_add(1)
            .ok_or(LocatorReadError::ResourceLimit)?;
        let cargo_directory_components = base_components
            .checked_add(1)
            .ok_or(LocatorReadError::ResourceLimit)?;
        let member_components = base_components
            .checked_add(2)
            .ok_or(LocatorReadError::ResourceLimit)?;
        let total_components = member_components
            .checked_mul(2)
            .and_then(|members| members.checked_add(cargo_directory_components))
            .ok_or(LocatorReadError::ResourceLimit)?;
        if member_components > self.limits.max_components_per_request
            || total_components > self.limits.max_total_components
        {
            return Err(LocatorReadError::ResourceLimit);
        }
        Ok(())
    }

    fn validate_captured_cargo_pair_budget(
        &self,
        captured: &LocatorDirectoryIdentity,
    ) -> Result<(), LocatorReadError> {
        if captured.kind != EntryKind::Directory
            || captured
                .native_absolute_path
                .validate_for_current_platform()
                .is_err()
        {
            return Err(LocatorReadError::InvalidRequest);
        }
        if self.limits.max_requests < 2 {
            return Err(LocatorReadError::ResourceLimit);
        }
        // Each possible direct-child observation is one request comprising the admitted root and
        // one basename. Re-admission itself does not create a second path authority.
        let root_components = 1usize;
        let member_components = root_components
            .checked_add(1)
            .ok_or(LocatorReadError::ResourceLimit)?;
        let total_components = member_components
            .checked_mul(2)
            .ok_or(LocatorReadError::ResourceLimit)?;
        if member_components > self.limits.max_components_per_request
            || total_components > self.limits.max_total_components
        {
            return Err(LocatorReadError::ResourceLimit);
        }
        Ok(())
    }

    fn reopen_captured_directory(
        &self,
        captured: &LocatorDirectoryIdentity,
        cancel: &CancellationToken,
    ) -> Result<OpenedDirectory<P::DirectoryHandle>, ReadAttempt> {
        let root = ScanRoot::new(native_absolute_path_buf(&captured.native_absolute_path)?)
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let admission = self
            .platform
            .admit_root(&root, cancel)
            .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
        admission
            .validate_for_root(&root)
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::Unavailable))?;
        let RootAdmission {
            root_locator,
            metadata,
            directory,
            ..
        } = admission;
        if cancel.is_cancelled() {
            return Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled));
        }
        if root_locator != captured.native_absolute_path {
            return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
        }
        if metadata.mount_identity.as_ref() != Some(&captured.mount_identity) {
            return Err(ReadAttempt::Failed(LocatorReadFailure::MountChanged));
        }
        if !directory_identity_matches_capture(&metadata, captured) {
            return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
        }
        Ok(OpenedDirectory {
            path: metadata.path.clone(),
            metadata,
            handle: directory,
        })
    }

    fn next_directory_batch(
        &self,
        directory: &mut OpenedDirectory<P::DirectoryHandle>,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<sweepx_platform::DirectoryEntryBatch, LocatorReadFailure> {
        if cancel.is_cancelled() {
            return Err(LocatorReadFailure::Cancelled);
        }
        let remaining_entries = self
            .limits
            .max_directory_entries
            .saturating_sub(budget.enumerated_entries);
        let remaining_bytes = self
            .limits
            .max_directory_bytes
            .saturating_sub(budget.enumerated_bytes);
        if remaining_entries == 0 || remaining_bytes == 0 {
            return Err(LocatorReadFailure::ResourceLimit);
        }
        let limits = DirectoryReadLimits {
            max_batch_entries: self
                .limits
                .max_directory_batch_entries
                .min(remaining_entries),
            max_batch_bytes: self.limits.max_directory_batch_bytes.min(remaining_bytes),
        };
        if limits.max_batch_entries == 0 || limits.max_batch_bytes == 0 {
            return Err(LocatorReadFailure::ResourceLimit);
        }
        let batch = self
            .platform
            .enumerate_children(&mut directory.handle, cancel, limits)
            .map_err(map_platform_failure)?;
        if batch.entries.is_empty() && !batch.end_of_directory {
            return Err(LocatorReadFailure::Unavailable);
        }
        let retained_bytes = batch.entries.iter().try_fold(0usize, |total, child| {
            child
                .estimated_retained_bytes()
                .and_then(|bytes| total.checked_add(bytes))
        });
        if batch.entries.len() > limits.max_batch_entries
            || retained_bytes.is_none_or(|bytes| bytes > limits.max_batch_bytes)
        {
            return Err(LocatorReadFailure::Unavailable);
        }
        budget.enumerated_entries = budget
            .enumerated_entries
            .checked_add(batch.entries.len())
            .ok_or(LocatorReadFailure::ResourceLimit)?;
        budget.enumerated_bytes = budget
            .enumerated_bytes
            .checked_add(retained_bytes.expect("batch bytes checked above"))
            .ok_or(LocatorReadFailure::ResourceLimit)?;
        Ok(batch)
    }

    fn read_cargo_config_member(
        &self,
        cargo: &OpenedDirectory<P::DirectoryHandle>,
        child: &DirectoryEntryRecord,
        total_bytes: &mut usize,
        cancel: &CancellationToken,
    ) -> Result<PresentRegularFileRead, LocatorReadFailure> {
        let walked =
            match inspect_bound_child(&self.platform, &cargo.handle, &cargo.path, child, cancel) {
                Ok(walked) => walked,
                Err(error) => {
                    return Err(map_platform_failure(error));
                }
            };
        let metadata = match walked {
            WalkEntry::File(metadata) => metadata,
            WalkEntry::Link(_) => {
                return Err(LocatorReadFailure::SymlinkOrReparse);
            }
            WalkEntry::Directory(_) => {
                return Err(LocatorReadFailure::NotRegular);
            }
            WalkEntry::Boundary(boundary) => {
                return Err(map_boundary_failure(boundary.kind));
            }
            WalkEntry::Error(error) => {
                return Err(map_walk_failure(error.kind));
            }
        };
        let (Some(identity), Some(filesystem), Some(mount)) = (
            metadata.identity,
            metadata.filesystem_identity,
            metadata.mount_identity,
        ) else {
            return Err(LocatorReadFailure::IdentityMismatch);
        };
        if let Err(ReadAttempt::Failed(failure)) =
            validate_same_scope(&cargo.metadata, &filesystem, &mount)
        {
            return Err(failure);
        }
        let remaining = self.limits.max_total_bytes.saturating_sub(*total_bytes);
        let max_bytes = self.limits.max_file_bytes.min(remaining);
        let request = match BoundedRegularFileReadRequest::previously_observed(
            child.file_name.clone(),
            identity,
            filesystem,
            mount,
            max_bytes,
        ) {
            Ok(request) => request,
            Err(_) => {
                return Err(LocatorReadFailure::InvalidBinding);
            }
        };
        let read = match read_bound_regular_file(&self.platform, &cargo.handle, &request, cancel) {
            Ok(read) => read,
            Err(error) => {
                return match map_file_read_error(error) {
                    ReadAttempt::Failed(failure) => Err(failure),
                    ReadAttempt::Absent => Err(LocatorReadFailure::IdentityMismatch),
                };
            }
        };
        let Some(next_total) = total_bytes.checked_add(read.bytes.len()) else {
            return Err(LocatorReadFailure::ResourceLimit);
        };
        if next_total > self.limits.max_total_bytes {
            return Err(LocatorReadFailure::ResourceLimit);
        }
        *total_bytes = next_total;
        Ok(read)
    }

    fn inspect_cargo_config_member(
        &self,
        directory: &OpenedDirectory<P::DirectoryHandle>,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<(), LocatorReadFailure> {
        let walked = inspect_bound_child_with_directory_admission(
            &self.platform,
            &directory.handle,
            &directory.path,
            child,
            cancel,
            DirectoryHandleAdmission::Deny,
        )
        .map_err(map_platform_failure)?;
        if cancel.is_cancelled() {
            return Err(LocatorReadFailure::Cancelled);
        }
        let metadata = match walked {
            WalkEntry::File(metadata) => metadata,
            WalkEntry::Link(_) => return Err(LocatorReadFailure::SymlinkOrReparse),
            WalkEntry::Directory(_) => return Err(LocatorReadFailure::NotRegular),
            WalkEntry::Boundary(boundary)
                if boundary.kind == sweepx_platform::BoundaryKind::ResourceLimit =>
            {
                return Err(LocatorReadFailure::NotRegular);
            }
            WalkEntry::Boundary(boundary) => return Err(map_boundary_failure(boundary.kind)),
            WalkEntry::Error(error) => return Err(map_walk_failure(error.kind)),
        };
        let (Some(_identity), Some(filesystem), Some(mount)) = (
            metadata.identity,
            metadata.filesystem_identity,
            metadata.mount_identity,
        ) else {
            return Err(LocatorReadFailure::IdentityMismatch);
        };
        if let Err(ReadAttempt::Failed(failure)) =
            validate_same_scope(&directory.metadata, &filesystem, &mount)
        {
            return Err(failure);
        }
        Ok(())
    }

    fn read_scanned_file(
        &self,
        base: &ScannedEntry,
        entry: &ScannedEntry,
        max_bytes: usize,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<PresentRegularFileRead, ReadAttempt> {
        let base_identity = base
            .identity
            .as_ref()
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let entry_identity = entry
            .identity
            .as_ref()
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let entry_locator = entry
            .executable_native_locator()
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let base_locator = base
            .executable_native_locator()
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        if entry.scan_id != base.scan_id
            || base_identity.entry_id != base_locator.entry.entry_id
            || entry_identity.scan_root_id != base_identity.scan_root_id
            || entry_identity.parent_id.as_ref() != Some(&base_identity.entry_id)
            || entry_locator.scan_root != base_locator.scan_root
            || entry_locator.scan_root_absolute_path != base_locator.scan_root_absolute_path
            || entry_locator.entry.native_basename != entry.native_basename
        {
            return Err(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding));
        }
        let mut expected_parent_recipe = base_locator.parent_reopen_recipe.clone();
        expected_parent_recipe.push(base_locator.entry.clone());
        if entry_locator.parent_reopen_recipe != expected_parent_recipe {
            return Err(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding));
        }
        let expected = expectation_from_component(&entry_locator.entry)
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let reopened = self.reopen_base(base, cancel, budget)?;
        let bounded = BoundedRegularFileReadRequest::previously_observed(
            entry.native_basename.clone(),
            expected.0,
            expected.1,
            expected.2,
            max_bytes,
        )
        .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let read = read_bound_regular_file(&self.platform, &reopened.handle, &bounded, cancel)
            .map_err(map_file_read_error)?;
        let EvidenceValue::Known {
            value: scanned_size,
        } = &entry.logical_bytes
        else {
            return Err(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding));
        };
        let live_fingerprint = sweepx_platform::fingerprint_for(
            Some(&read.observed_before.identity),
            &EntryKind::File,
            &entry.logical_bytes,
        );
        if scanned_size != &read.observed_before.logical_bytes
            || live_fingerprint != entry.metadata_fingerprint
        {
            return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
        }
        Ok(read)
    }

    fn read_optional(
        &self,
        base: &ScannedEntry,
        components: &[NativeName],
        max_bytes: usize,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<PresentRegularFileRead, ReadAttempt> {
        let mut reopened = self.reopen_base(base, cancel, budget)?;
        for component in &components[..components.len() - 1] {
            reopened = self.open_optional_directory(reopened, component, cancel, budget)?;
        }
        let final_name = components
            .last()
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let Some(child) = self.find_child(&mut reopened, final_name, cancel, budget)? else {
            return Err(ReadAttempt::Absent);
        };
        let walked = inspect_bound_child(
            &self.platform,
            &reopened.handle,
            &reopened.path,
            &child,
            cancel,
        )
        .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
        let WalkEntry::File(metadata) = walked else {
            return Err(ReadAttempt::Failed(match walked {
                WalkEntry::Link(_) => LocatorReadFailure::SymlinkOrReparse,
                WalkEntry::Boundary(boundary) => map_boundary_failure(boundary.kind),
                WalkEntry::Error(error) => map_walk_failure(error.kind),
                WalkEntry::Directory(_) => LocatorReadFailure::NotRegular,
                WalkEntry::File(_) => unreachable!(),
            }));
        };
        let identity = metadata
            .identity
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let filesystem = metadata
            .filesystem_identity
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let mount = metadata
            .mount_identity
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        validate_same_scope(&reopened.metadata, &filesystem, &mount)?;
        let bounded = BoundedRegularFileReadRequest::previously_observed(
            final_name.clone(),
            identity,
            filesystem,
            mount,
            max_bytes,
        )
        .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        read_bound_regular_file(&self.platform, &reopened.handle, &bounded, cancel)
            .map_err(map_file_read_error)
    }

    fn reopen_base(
        &self,
        base: &ScannedEntry,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<OpenedDirectory<P::DirectoryHandle>, ReadAttempt> {
        let locator = base
            .executable_native_locator()
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let identity = base
            .identity
            .as_ref()
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let native_root = locator
            .scan_root_absolute_path
            .as_ref()
            .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let root = ScanRoot::new(native_absolute_path_buf(native_root)?)
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
        let admission = self
            .platform
            .admit_root(&root, cancel)
            .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
        admission
            .validate_for_root(&root)
            .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::Unavailable))?;
        let RootAdmission {
            root_locator,
            metadata,
            directory,
            ..
        } = admission;
        if &root_locator != native_root {
            return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
        }
        validate_component(&locator.scan_root, &metadata)?;
        if locator.entry.entry_id == locator.scan_root.entry_id {
            validate_component(&locator.entry, &metadata)?;
            return Ok(OpenedDirectory {
                path: metadata.path.clone(),
                metadata,
                handle: directory,
            });
        }

        let mut current = OpenedDirectory {
            path: metadata.path.clone(),
            metadata,
            handle: directory,
        };
        for expected in locator
            .parent_reopen_recipe
            .iter()
            .skip(1)
            .chain(std::iter::once(&locator.entry))
        {
            let child = self
                .find_child(&mut current, &expected.native_basename, cancel, budget)?
                .ok_or(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch))?;
            let walked = inspect_bound_child(
                &self.platform,
                &current.handle,
                &current.path,
                &child,
                cancel,
            )
            .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
            let WalkEntry::Directory(opened) = walked else {
                return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
            };
            validate_component(expected, &opened.metadata)?;
            current = OpenedDirectory {
                path: opened.metadata.path.clone(),
                metadata: opened.metadata,
                handle: opened.handle,
            };
        }
        validate_component(&locator.entry, &current.metadata)?;
        let _ = identity;
        Ok(current)
    }

    fn open_optional_directory(
        &self,
        mut parent: OpenedDirectory<P::DirectoryHandle>,
        component: &NativeName,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<OpenedDirectory<P::DirectoryHandle>, ReadAttempt> {
        let observed = self.find_child(&mut parent, component, cancel, budget)?;
        let Some(child) = observed else {
            return Err(ReadAttempt::Absent);
        };
        let walked =
            inspect_bound_child(&self.platform, &parent.handle, &parent.path, &child, cancel)
                .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
        match walked {
            WalkEntry::Directory(opened) => {
                let filesystem = opened
                    .metadata
                    .filesystem_identity
                    .as_ref()
                    .ok_or(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch))?;
                let mount = opened
                    .metadata
                    .mount_identity
                    .as_ref()
                    .ok_or(ReadAttempt::Failed(LocatorReadFailure::MountChanged))?;
                validate_same_scope(&parent.metadata, filesystem, mount)?;
                Ok(OpenedDirectory {
                    path: opened.metadata.path.clone(),
                    metadata: opened.metadata,
                    handle: opened.handle,
                })
            }
            WalkEntry::Link(_) => Err(ReadAttempt::Failed(LocatorReadFailure::SymlinkOrReparse)),
            WalkEntry::Boundary(boundary) => {
                Err(ReadAttempt::Failed(map_boundary_failure(boundary.kind)))
            }
            WalkEntry::File(_) => Err(ReadAttempt::Failed(LocatorReadFailure::NotRegular)),
            WalkEntry::Error(error) => Err(ReadAttempt::Failed(map_walk_failure(error.kind))),
        }
    }

    fn find_cargo_directory(
        &self,
        parent: &mut OpenedDirectory<P::DirectoryHandle>,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<Option<OpenedDirectory<P::DirectoryHandle>>, ReadAttempt> {
        let expected = fixed_native_name(".cargo");
        let mut opened_cargo = None;
        loop {
            let batch = self
                .next_directory_batch(parent, cancel, budget)
                .map_err(ReadAttempt::Failed)?;
            for child in &batch.entries {
                if ascii_case_fold_matches(&child.file_name, ".cargo")
                    && child.file_name != expected
                {
                    return Err(ReadAttempt::Failed(LocatorReadFailure::AmbiguousAlias));
                }
                if child.file_name == expected {
                    if opened_cargo.is_some() {
                        return Err(ReadAttempt::Failed(LocatorReadFailure::AmbiguousAlias));
                    }
                    let walked = inspect_bound_child(
                        &self.platform,
                        &parent.handle,
                        &parent.path,
                        child,
                        cancel,
                    )
                    .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
                    let WalkEntry::Directory(opened) = walked else {
                        return Err(ReadAttempt::Failed(match walked {
                            WalkEntry::Link(_) => LocatorReadFailure::SymlinkOrReparse,
                            WalkEntry::Boundary(boundary) => map_boundary_failure(boundary.kind),
                            WalkEntry::Error(error) => map_walk_failure(error.kind),
                            WalkEntry::File(_) => LocatorReadFailure::NotRegular,
                            WalkEntry::Directory(_) => unreachable!(),
                        }));
                    };
                    let filesystem = opened
                        .metadata
                        .filesystem_identity
                        .as_ref()
                        .ok_or(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch))?;
                    let mount = opened
                        .metadata
                        .mount_identity
                        .as_ref()
                        .ok_or(ReadAttempt::Failed(LocatorReadFailure::MountChanged))?;
                    validate_same_scope(&parent.metadata, filesystem, mount)?;
                    opened_cargo = Some(OpenedDirectory {
                        path: opened.metadata.path.clone(),
                        metadata: opened.metadata,
                        handle: opened.handle,
                    });
                }
            }
            if batch.end_of_directory {
                return Ok(opened_cargo);
            }
        }
    }

    fn find_child(
        &self,
        directory: &mut OpenedDirectory<P::DirectoryHandle>,
        name: &NativeName,
        cancel: &CancellationToken,
        budget: &mut BatchBudget,
    ) -> Result<Option<DirectoryEntryRecord>, ReadAttempt> {
        let mut entries = 0usize;
        let mut bytes = 0usize;
        loop {
            if cancel.is_cancelled() {
                return Err(ReadAttempt::Failed(LocatorReadFailure::Cancelled));
            }
            let remaining_entries = self
                .limits
                .max_directory_entries
                .saturating_sub(budget.enumerated_entries);
            let remaining_bytes = self
                .limits
                .max_directory_bytes
                .saturating_sub(budget.enumerated_bytes);
            if remaining_entries == 0 || remaining_bytes == 0 {
                return Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit));
            }
            let batch_limits = DirectoryReadLimits {
                max_batch_entries: self
                    .limits
                    .max_directory_batch_entries
                    .min(remaining_entries),
                max_batch_bytes: self.limits.max_directory_batch_bytes.min(remaining_bytes),
            };
            if batch_limits.max_batch_entries == 0 || batch_limits.max_batch_bytes == 0 {
                return Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit));
            }
            let batch = self
                .platform
                .enumerate_children(&mut directory.handle, cancel, batch_limits)
                .map_err(|error| ReadAttempt::Failed(map_platform_failure(error)))?;
            if batch.entries.is_empty() && !batch.end_of_directory {
                return Err(ReadAttempt::Failed(LocatorReadFailure::Unavailable));
            }
            let batch_bytes = batch.entries.iter().try_fold(0usize, |total, child| {
                child
                    .estimated_retained_bytes()
                    .and_then(|retained| total.checked_add(retained))
            });
            if batch.entries.len() > batch_limits.max_batch_entries
                || batch_bytes.is_none_or(|retained| retained > batch_limits.max_batch_bytes)
            {
                return Err(ReadAttempt::Failed(LocatorReadFailure::Unavailable));
            }
            let mut matched = None;
            for child in &batch.entries {
                entries = entries
                    .checked_add(1)
                    .ok_or(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit))?;
                bytes = bytes
                    .checked_add(
                        child
                            .estimated_retained_bytes()
                            .ok_or(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit))?,
                    )
                    .ok_or(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit))?;
                if entries > self.limits.max_directory_entries
                    || bytes > self.limits.max_directory_bytes
                {
                    return Err(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit));
                }
                if &child.file_name == name && matched.replace(child.clone()).is_some() {
                    return Err(ReadAttempt::Failed(LocatorReadFailure::Unavailable));
                }
            }
            budget.enumerated_entries = budget
                .enumerated_entries
                .checked_add(batch.entries.len())
                .ok_or(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit))?;
            budget.enumerated_bytes = budget
                .enumerated_bytes
                .checked_add(batch_bytes.expect("batch bytes checked above"))
                .ok_or(ReadAttempt::Failed(LocatorReadFailure::ResourceLimit))?;
            if batch.end_of_directory {
                return Ok(matched);
            }
            if matched.is_some() {
                return Ok(matched);
            }
        }
    }
}

#[derive(Debug)]
struct OpenedDirectory<D> {
    path: PathBuf,
    metadata: sweepx_platform::EntryMetadata,
    handle: D,
}

#[derive(Debug)]
enum ReadAttempt {
    Absent,
    Failed(LocatorReadFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoConfigSlot {
    Config,
    ConfigToml,
    Alias,
    Other,
}

fn cargo_config_slot(name: &NativeName) -> CargoConfigSlot {
    if *name == fixed_native_name("config") {
        CargoConfigSlot::Config
    } else if *name == fixed_native_name("config.toml") {
        CargoConfigSlot::ConfigToml
    } else if ascii_case_fold_matches(name, "config")
        || ascii_case_fold_matches(name, "config.toml")
    {
        CargoConfigSlot::Alias
    } else {
        CargoConfigSlot::Other
    }
}

fn ascii_case_fold_matches(name: &NativeName, expected: &str) -> bool {
    match name {
        NativeName::UnixBytes(bytes) => bytes.eq_ignore_ascii_case(expected.as_bytes()),
        NativeName::WindowsUtf16(units) => {
            let expected: Vec<u16> = expected.encode_utf16().collect();
            units.len() == expected.len()
                && units.iter().zip(expected).all(|(actual, expected)| {
                    u8::try_from(*actual)
                        .is_ok_and(|actual| actual.eq_ignore_ascii_case(&(expected as u8)))
                })
        }
    }
}

fn fixed_native_name(value: &str) -> NativeName {
    #[cfg(unix)]
    {
        NativeName::unix(value.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        NativeName::windows_utf16(value.encode_utf16().collect::<Vec<_>>())
    }
    #[cfg(not(any(unix, windows)))]
    {
        NativeName::unix(value.as_bytes().to_vec())
    }
}

fn pair_failed(failure: LocatorReadFailure) -> CargoConfigPairObservation {
    CargoConfigPairObservation {
        consistency: CargoConfigPairConsistency::NonAtomic,
        config: CargoConfigMemberObservation::Failed(failure.clone()),
        config_toml: CargoConfigMemberObservation::Failed(failure),
        total_bytes: 0,
    }
}

fn presence_pair_failed(failure: LocatorReadFailure) -> CargoConfigPairPresenceObservation {
    CargoConfigPairPresenceObservation {
        consistency: CargoConfigPairConsistency::NonAtomic,
        config: CargoConfigMemberPresenceObservation::Failed(failure.clone()),
        config_toml: CargoConfigMemberPresenceObservation::Failed(failure),
    }
}

fn validate_component(
    expected: &NativePathComponent,
    metadata: &sweepx_platform::EntryMetadata,
) -> Result<(), ReadAttempt> {
    if metadata.kind != EntryKind::Directory || expected.object_type != ObjectType::Directory {
        return Err(ReadAttempt::Failed(match metadata.kind {
            EntryKind::Symlink | EntryKind::ReparsePoint => LocatorReadFailure::SymlinkOrReparse,
            _ => LocatorReadFailure::IdentityMismatch,
        }));
    }
    let observed = (
        metadata.identity.as_ref(),
        metadata.filesystem_identity.as_ref(),
        metadata.mount_identity.as_ref(),
    );
    let expected_values = component_identity(expected)
        .ok_or(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
    if observed.2 != Some(&expected_values.2) {
        return Err(ReadAttempt::Failed(LocatorReadFailure::MountChanged));
    }
    if metadata.file_name != expected.native_basename
        || metadata.fingerprint != expected.metadata_fingerprint
        || observed.0 != Some(&expected_values.0)
        || observed.1 != Some(&expected_values.1)
    {
        return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
    }
    Ok(())
}

fn validate_same_scope(
    parent: &sweepx_platform::EntryMetadata,
    child_filesystem: &FilesystemIdentity,
    child_mount: &MountIdentity,
) -> Result<(), ReadAttempt> {
    if parent.mount_identity.as_ref() != Some(child_mount) {
        return Err(ReadAttempt::Failed(LocatorReadFailure::MountChanged));
    }
    if parent.filesystem_identity.as_ref() != Some(child_filesystem) {
        return Err(ReadAttempt::Failed(LocatorReadFailure::IdentityMismatch));
    }
    Ok(())
}

fn component_identity(
    component: &NativePathComponent,
) -> Option<(EntryIdentity, FilesystemIdentity, MountIdentity)> {
    let IdentityEvidence::Known { value: platform } = &component.platform_file_identity else {
        return None;
    };
    let IdentityEvidence::Known { value: filesystem } =
        &component.filesystem_object_domain_identity
    else {
        return None;
    };
    let IdentityEvidence::Known { value: mount } = &component.volume_or_mount_identity else {
        return None;
    };
    let device = u64::try_from(platform.device.0).ok()?;
    let filesystem_device = u64::try_from(filesystem.device.0).ok()?;
    let mount_value = u64::try_from(mount.value.0).ok()?;
    Some((
        EntryIdentity::from_windows_file_id(device, platform.inode.0.to_le_bytes()),
        FilesystemIdentity {
            device: filesystem_device,
        },
        MountIdentity { value: mount_value },
    ))
}

fn expectation_from_component(
    component: &NativePathComponent,
) -> Option<(EntryIdentity, FilesystemIdentity, MountIdentity)> {
    component_identity(component)
}

fn native_absolute_path_buf(path: &NativeAbsolutePath) -> Result<PathBuf, ReadAttempt> {
    path.validate_for_current_platform()
        .map_err(|_| ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))?;
    #[cfg(unix)]
    if let NativeAbsolutePath::UnixBytes(bytes) = path {
        return Ok(PathBuf::from(OsString::from_vec(bytes.clone())));
    }
    #[cfg(windows)]
    if let NativeAbsolutePath::WindowsUtf16(units) = path {
        return Ok(PathBuf::from(OsString::from_wide(units)));
    }
    Err(ReadAttempt::Failed(LocatorReadFailure::InvalidBinding))
}

fn native_target_absolute_path(locator: &NativeLocatorEvidence) -> Result<NativeAbsolutePath, ()> {
    let root = locator.scan_root_absolute_path.as_ref().ok_or(())?;
    root.validate_for_current_platform().map_err(|_| ())?;
    if locator.entry.entry_id == locator.scan_root.entry_id {
        return Ok(root.clone());
    }

    let components = locator
        .parent_reopen_recipe
        .iter()
        .skip(1)
        .chain(std::iter::once(&locator.entry));
    #[cfg(unix)]
    if let NativeAbsolutePath::UnixBytes(root_bytes) = root {
        let mut bytes = root_bytes.clone();
        for component in components {
            component
                .native_basename
                .validate_basename_for_current_platform()
                .map_err(|_| ())?;
            let NativeName::UnixBytes(name) = &component.native_basename else {
                return Err(());
            };
            if bytes.last() != Some(&b'/') {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(name);
        }
        let target = NativeAbsolutePath::unix(bytes);
        target.validate_for_current_platform().map_err(|_| ())?;
        return Ok(target);
    }
    #[cfg(windows)]
    if let NativeAbsolutePath::WindowsUtf16(root_units) = root {
        let mut units = root_units.clone();
        for component in components {
            component
                .native_basename
                .validate_basename_for_current_platform()
                .map_err(|_| ())?;
            let NativeName::WindowsUtf16(name) = &component.native_basename else {
                return Err(());
            };
            if !units.last().is_some_and(
                |unit| matches!(*unit, value if value == b'\\' as u16 || value == b'/' as u16),
            ) {
                units.push(b'\\' as u16);
            }
            units.extend_from_slice(name);
        }
        let target = NativeAbsolutePath::windows_utf16(units);
        target.validate_for_current_platform().map_err(|_| ())?;
        return Ok(target);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = components;
    Err(())
}

fn native_absolute_paths_equal_exact(
    left: &NativeAbsolutePath,
    right: &NativeAbsolutePath,
) -> Result<bool, ()> {
    left.validate_for_current_platform().map_err(|_| ())?;
    right.validate_for_current_platform().map_err(|_| ())?;
    Ok(match (left, right) {
        #[cfg(unix)]
        (NativeAbsolutePath::UnixBytes(left), NativeAbsolutePath::UnixBytes(right)) => {
            left == right
        }
        #[cfg(windows)]
        (NativeAbsolutePath::WindowsUtf16(left), NativeAbsolutePath::WindowsUtf16(right)) => {
            left == right
        }
        _ => false,
    })
}

fn directory_identity_matches_capture(
    metadata: &sweepx_platform::EntryMetadata,
    captured: &LocatorDirectoryIdentity,
) -> bool {
    metadata.kind == captured.kind
        && metadata.identity.as_ref() == Some(&captured.identity)
        && metadata.filesystem_identity.as_ref() == Some(&captured.filesystem_identity)
        && metadata.mount_identity.as_ref() == Some(&captured.mount_identity)
        && metadata.fingerprint == captured.fingerprint
}

fn map_capture_platform_error(error: PlatformError) -> LocatorReadError {
    match error {
        PlatformError::Cancelled => LocatorReadError::Cancelled,
        PlatformError::ResourceLimit(_) => LocatorReadError::ResourceLimit,
        PlatformError::RootRejected(_)
        | PlatformError::InvalidDirectoryEntry { .. }
        | PlatformError::Unsupported(_)
        | PlatformError::Io { .. } => LocatorReadError::InvalidRequest,
    }
}

fn map_platform_failure(error: PlatformError) -> LocatorReadFailure {
    match error {
        PlatformError::Cancelled => LocatorReadFailure::Cancelled,
        PlatformError::ResourceLimit(_) => LocatorReadFailure::ResourceLimit,
        PlatformError::RootRejected(_) | PlatformError::InvalidDirectoryEntry { .. } => {
            LocatorReadFailure::IdentityMismatch
        }
        PlatformError::Unsupported(_) => LocatorReadFailure::Unavailable,
        PlatformError::Io { io_kind, .. } => match io_kind {
            Some(std::io::ErrorKind::Interrupted) => LocatorReadFailure::Cancelled,
            Some(std::io::ErrorKind::NotFound) => LocatorReadFailure::IdentityMismatch,
            _ => LocatorReadFailure::ReadFailed,
        },
    }
}

fn map_file_read_error(error: BoundedRegularFileReadError) -> ReadAttempt {
    let failure = match error {
        BoundedRegularFileReadError::NotFound => LocatorReadFailure::IdentityMismatch,
        BoundedRegularFileReadError::Cancelled => LocatorReadFailure::Cancelled,
        BoundedRegularFileReadError::UnsafeName | BoundedRegularFileReadError::ForeignName => {
            LocatorReadFailure::InvalidBinding
        }
        BoundedRegularFileReadError::NotRegular { .. } => LocatorReadFailure::NotRegular,
        BoundedRegularFileReadError::SymlinkOrReparse { .. } => {
            LocatorReadFailure::SymlinkOrReparse
        }
        BoundedRegularFileReadError::IdentityMismatch(_) => LocatorReadFailure::IdentityMismatch,
        BoundedRegularFileReadError::MountMismatch(_) => LocatorReadFailure::MountChanged,
        BoundedRegularFileReadError::LimitExceeded { .. } => LocatorReadFailure::ResourceLimit,
        BoundedRegularFileReadError::ProviderOrOffline(_) => LocatorReadFailure::ProviderOrOffline,
        BoundedRegularFileReadError::ChangedDuringRead(_)
        | BoundedRegularFileReadError::Io { .. } => LocatorReadFailure::ReadFailed,
        BoundedRegularFileReadError::Unsupported(_) => LocatorReadFailure::Unavailable,
    };
    ReadAttempt::Failed(failure)
}

fn map_boundary_failure(kind: sweepx_platform::BoundaryKind) -> LocatorReadFailure {
    match kind {
        sweepx_platform::BoundaryKind::RootSymlink
        | sweepx_platform::BoundaryKind::Symlink
        | sweepx_platform::BoundaryKind::ReparsePoint => LocatorReadFailure::SymlinkOrReparse,
        sweepx_platform::BoundaryKind::Mount => LocatorReadFailure::MountChanged,
        sweepx_platform::BoundaryKind::ResourceLimit => LocatorReadFailure::ResourceLimit,
        sweepx_platform::BoundaryKind::Cancelled => LocatorReadFailure::Cancelled,
        sweepx_platform::BoundaryKind::OtherFilesystem => LocatorReadFailure::Unavailable,
    }
}

fn map_walk_failure(kind: sweepx_platform::ErrorKind) -> LocatorReadFailure {
    match kind {
        sweepx_platform::ErrorKind::Interrupted => LocatorReadFailure::Cancelled,
        sweepx_platform::ErrorKind::ResourceLimit => LocatorReadFailure::ResourceLimit,
        sweepx_platform::ErrorKind::Unsupported => LocatorReadFailure::Unavailable,
        sweepx_platform::ErrorKind::NotFound => LocatorReadFailure::IdentityMismatch,
        sweepx_platform::ErrorKind::AccessDenied
        | sweepx_platform::ErrorKind::InvalidInput
        | sweepx_platform::ErrorKind::Io => LocatorReadFailure::ReadFailed,
    }
}

#[cfg(all(test, target_os = "linux", feature = "platform-linux"))]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::{HostPlatformScanner, Scanner, ScannerOptions};
    use sweepx_model::ScanId;
    use sweepx_platform::{
        CancellationToken, DirectoryEntryBatch, DirectoryHandleAdmission, PlatformScanner,
    };

    fn scan(root: &std::path::Path, scan_id: &str) -> crate::ScanSummary {
        Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: ScanId::new(scan_id),
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap()
    }

    fn native(name: &str) -> NativeName {
        NativeName::unix(name.as_bytes().to_vec())
    }

    fn reader() -> LocatorReader<HostPlatformScanner> {
        LocatorReader::new(HostPlatformScanner::new(), LocatorReadLimits::default())
    }

    #[derive(Debug, Clone, Copy)]
    enum EnumerationTestAction {
        Passthrough,
        DuplicateConfig,
        Cancel,
        CancelAfterInspect,
        CancelAfterDirectoryInspect,
    }

    #[derive(Debug)]
    struct EnumerationTestScanner {
        inner: HostPlatformScanner,
        action: EnumerationTestAction,
        acted: AtomicBool,
    }

    impl EnumerationTestScanner {
        fn new(action: EnumerationTestAction) -> Self {
            Self {
                inner: HostPlatformScanner::new(),
                action,
                acted: AtomicBool::new(false),
            }
        }
    }

    impl PlatformScanner for EnumerationTestScanner {
        type DirectoryHandle = <HostPlatformScanner as PlatformScanner>::DirectoryHandle;

        fn platform_name(&self) -> &'static str {
            self.inner.platform_name()
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            self.inner.admit_root(root, cancel)
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            let mut batch = self.inner.enumerate_children(directory, cancel, limits)?;
            if matches!(self.action, EnumerationTestAction::Cancel)
                && !self.acted.swap(true, Ordering::SeqCst)
            {
                cancel.cancel();
            }
            if matches!(self.action, EnumerationTestAction::DuplicateConfig)
                && !self.acted.load(Ordering::SeqCst)
                && let Some(config) = batch
                    .entries
                    .iter()
                    .find(|entry| entry.file_name == native("config"))
                    .cloned()
            {
                batch.entries.push(config);
                self.acted.store(true, Ordering::SeqCst);
            }
            Ok(batch)
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inner.inspect_child(parent, child, cancel)
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            let walked = self.inner.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                directory_admission,
            )?;
            if matches!(self.action, EnumerationTestAction::CancelAfterInspect)
                && child.file_name == native("config")
                && !self.acted.swap(true, Ordering::SeqCst)
            {
                cancel.cancel();
            }
            if matches!(
                self.action,
                EnumerationTestAction::CancelAfterDirectoryInspect
            ) && matches!(walked, WalkEntry::Directory(_))
                && !self.acted.swap(true, Ordering::SeqCst)
            {
                cancel.cancel();
            }
            Ok(walked)
        }

        fn is_same_mount(
            &self,
            root: &sweepx_platform::EntryMetadata,
            entry: &sweepx_platform::EntryMetadata,
        ) -> Result<bool, PlatformError> {
            self.inner.is_same_mount(root, entry)
        }

        fn read_regular_file_relative(
            &self,
            _parent: &Self::DirectoryHandle,
            _request: &BoundedRegularFileReadRequest,
            _cancel: &CancellationToken,
        ) -> Result<PresentRegularFileRead, BoundedRegularFileReadError> {
            panic!("presence-only Cargo home observation must not read file contents")
        }
    }

    fn assert_presence_pair_failed(
        observed: &CargoConfigPairPresenceObservation,
        expected: LocatorReadFailure,
    ) {
        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert_eq!(
            observed.config,
            CargoConfigMemberPresenceObservation::Failed(expected.clone())
        );
        assert_eq!(
            observed.config_toml,
            CargoConfigMemberPresenceObservation::Failed(expected)
        );
    }

    #[test]
    fn reads_scanned_file_and_optional_files_without_display_path_authority() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("Cargo.toml"), b"[workspace]\n").unwrap();
        fs::create_dir(root.join(".cargo")).unwrap();
        fs::write(root.join(".cargo/config.toml"), b"[build]\n").unwrap();
        let summary = scan(&root, "locator-read-success");
        let mut base = summary.roots[0].clone();
        base.display_path = "/forged/reporting/path".to_string();
        let manifest = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("Cargo.toml"))
            .unwrap();
        let requests = [
            LocatorFileRequest::ScannedFile { entry: manifest },
            LocatorFileRequest::RelativeOptional {
                components: &[native(".cargo"), native("config.toml")],
            },
            LocatorFileRequest::RelativeOptional {
                components: &[native(".cargo"), native("config")],
            },
        ];

        let result = reader()
            .read_batch(
                LocatorBatchReadRequest {
                    base_directory: &base,
                    files: &requests,
                },
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            &result.files[0],
            LocatorFileRead::Present(read) if read.bytes == b"[workspace]\n"
        ));
        assert!(matches!(
            &result.files[1],
            LocatorFileRead::Present(read) if read.bytes == b"[build]\n"
        ));
        assert_eq!(result.files[2], LocatorFileRead::VerifiedAbsent);
    }

    #[test]
    fn directory_snapshot_matches_exact_native_root_and_ignores_display_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut summary = scan(&root, "cwd-bind-exact");
        summary.roots[0].display_path = "/forged/path".to_string();
        let captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();

        let binding = reader()
            .compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(binding, LocatorDirectoryComparison::PathAndIdentityMatch);
    }

    #[test]
    fn scanned_directory_snapshot_matches_nested_native_lineage_and_ignores_display_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let parent = root.join("parent");
        let target_path = parent.join("target");
        fs::create_dir_all(&target_path).unwrap();
        let summary = scan(&root, "nested-directory-bind");
        let mut target = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("target"))
            .unwrap()
            .clone();
        target.display_path = "/forged/reporting/path".to_string();
        let captured = reader()
            .capture_directory_identity(&target_path, &CancellationToken::new())
            .unwrap();

        assert_eq!(
            reader().compare_scanned_directory_snapshot(
                &target,
                &captured,
                &CancellationToken::new(),
            ),
            Ok(LocatorDirectoryComparison::PathAndIdentityMatch)
        );
        assert_eq!(
            reader()
                .compare_base_directory_snapshot(&target, &captured, &CancellationToken::new(),),
            Err(LocatorReadError::InvalidRequest)
        );
    }

    #[test]
    fn scanned_directory_path_mismatch_is_cheap_and_ignores_cancel_and_reopen_budget() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target_path = root.join("target");
        let other = temp.path().join("other");
        fs::create_dir_all(&target_path).unwrap();
        fs::create_dir(&other).unwrap();
        let summary = scan(&root, "nested-directory-mismatch");
        let target = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("target"))
            .unwrap();
        let captured = reader()
            .capture_directory_identity(&other, &CancellationToken::new())
            .unwrap();
        let reader = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_requests: 0,
                ..LocatorReadLimits::default()
            },
        );
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            reader.compare_scanned_directory_snapshot(target, &captured, &cancel),
            Ok(LocatorDirectoryComparison::DifferentNativePath)
        );
    }

    #[test]
    fn scanned_directory_snapshot_rejects_forged_lineage() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target_path = root.join("target");
        fs::create_dir_all(&target_path).unwrap();
        let summary = scan(&root, "nested-directory-forged-lineage");
        let mut target = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("target"))
            .unwrap()
            .clone();
        target
            .native_locator
            .as_mut()
            .unwrap()
            .parent_reopen_recipe
            .clear();
        let captured = reader()
            .capture_directory_identity(&target_path, &CancellationToken::new())
            .unwrap();

        assert_eq!(
            reader().compare_scanned_directory_snapshot(
                &target,
                &captured,
                &CancellationToken::new(),
            ),
            Err(LocatorReadError::InvalidRequest)
        );
    }

    #[test]
    fn scanned_directory_snapshot_fails_closed_when_nested_target_is_replaced() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target_path = root.join("target");
        fs::create_dir_all(&target_path).unwrap();
        let summary = scan(&root, "nested-directory-replaced");
        let target = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("target"))
            .unwrap();
        let captured = reader()
            .capture_directory_identity(&target_path, &CancellationToken::new())
            .unwrap();
        fs::rename(&target_path, root.join("target-old")).unwrap();
        fs::create_dir(&target_path).unwrap();

        assert_eq!(
            reader().compare_scanned_directory_snapshot(
                target,
                &captured,
                &CancellationToken::new(),
            ),
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::RevalidationFailed,
            ))
        );
    }

    #[test]
    fn scanned_directory_snapshot_reports_lineage_budget_and_post_inspection_cancel() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target_path = root.join("target");
        fs::create_dir_all(&target_path).unwrap();
        let summary = scan(&root, "nested-directory-budget-cancel");
        let target = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("target"))
            .unwrap();
        let captured = reader()
            .capture_directory_identity(&target_path, &CancellationToken::new())
            .unwrap();
        let constrained = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_components_per_request: 1,
                ..LocatorReadLimits::default()
            },
        );
        assert_eq!(
            constrained.compare_scanned_directory_snapshot(
                target,
                &captured,
                &CancellationToken::new(),
            ),
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::ResourceLimit,
            ))
        );

        let cancel = CancellationToken::new();
        let cancelling = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::CancelAfterDirectoryInspect),
            LocatorReadLimits::default(),
        );
        assert_eq!(
            cancelling.compare_scanned_directory_snapshot(target, &captured, &cancel),
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::Cancelled,
            ))
        );
    }

    #[test]
    fn directory_snapshot_reports_a_different_exact_native_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let other = temp.path().join("other");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&other).unwrap();
        let summary = scan(&root, "cwd-bind-different");
        let captured = reader()
            .capture_directory_identity(&other, &CancellationToken::new())
            .unwrap();

        let binding = reader()
            .compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(binding, LocatorDirectoryComparison::DifferentNativePath);
    }

    #[test]
    fn directory_snapshot_comparison_fails_closed_when_root_is_replaced() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cwd-bind-replaced");
        let captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();
        fs::rename(&root, temp.path().join("root-old")).unwrap();
        fs::create_dir(&root).unwrap();

        let binding = reader()
            .compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(
            binding,
            LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::RevalidationFailed
            )
        );
    }

    #[test]
    fn directory_snapshot_comparison_reports_cancelled_before_reopen() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cwd-bind-cancel");
        let captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert_eq!(
            reader().compare_base_directory_snapshot(&summary.roots[0], &captured, &cancel,),
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::Cancelled,
            ))
        );
    }

    #[test]
    fn directory_snapshot_comparison_reports_too_small_component_limits() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cwd-bind-budget");
        let captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();
        let reader = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_requests: 0,
                ..LocatorReadLimits::default()
            },
        );

        assert_eq!(
            reader.compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            ),
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::ResourceLimit,
            ))
        );
    }

    #[test]
    fn different_directory_snapshot_needs_no_reopen_budget() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let other = temp.path().join("other");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&other).unwrap();
        let summary = scan(&root, "cwd-bind-mismatch-no-budget");
        let captured = reader()
            .capture_directory_identity(&other, &CancellationToken::new())
            .unwrap();
        let reader = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_requests: 0,
                ..LocatorReadLimits::default()
            },
        );

        assert_eq!(
            reader.compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            ),
            Ok(LocatorDirectoryComparison::DifferentNativePath)
        );
    }

    #[test]
    fn captured_directory_identity_does_not_match_after_path_rebind_to_new_root() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();
        fs::rename(&root, temp.path().join("root-old")).unwrap();
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cwd-bind-path-rebind");

        let binding = reader()
            .compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(
            binding,
            LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::RevalidationFailed
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_snapshot_rejects_a_foreign_platform_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cwd-bind-foreign-path");
        let mut captured = reader()
            .capture_directory_identity(&root, &CancellationToken::new())
            .unwrap();
        captured.native_absolute_path =
            NativeAbsolutePath::windows_utf16(r"C:\foreign".encode_utf16().collect::<Vec<_>>());

        assert_eq!(
            reader().compare_base_directory_snapshot(
                &summary.roots[0],
                &captured,
                &CancellationToken::new(),
            ),
            Err(LocatorReadError::InvalidRequest)
        );
    }

    #[test]
    fn scanned_file_replacement_and_optional_symlink_fail_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let manifest_path = root.join("Cargo.toml");
        fs::write(&manifest_path, b"[workspace]\n").unwrap();
        let summary = scan(&root, "locator-read-race");
        let manifest = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == native("Cargo.toml"))
            .unwrap();
        fs::rename(&manifest_path, root.join("old.toml")).unwrap();
        fs::write(&manifest_path, b"replacement").unwrap();
        std::os::unix::fs::symlink("old.toml", root.join("link.toml")).unwrap();
        let requests = [
            LocatorFileRequest::ScannedFile { entry: manifest },
            LocatorFileRequest::RelativeOptional {
                components: &[native("link.toml")],
            },
        ];

        let result = reader()
            .read_batch(
                LocatorBatchReadRequest {
                    base_directory: &summary.roots[0],
                    files: &requests,
                },
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            result.files[0],
            LocatorFileRead::Failed(LocatorReadFailure::IdentityMismatch)
        ));
        assert!(matches!(
            result.files[1],
            LocatorFileRead::Failed(LocatorReadFailure::SymlinkOrReparse)
        ));
    }

    #[test]
    fn request_and_total_byte_limits_and_cancellation_fail_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("one"), b"1234").unwrap();
        fs::write(root.join("two"), b"5678").unwrap();
        let summary = scan(&root, "locator-read-limits");
        let requests = [
            LocatorFileRequest::RelativeOptional {
                components: &[native("one")],
            },
            LocatorFileRequest::RelativeOptional {
                components: &[native("two")],
            },
        ];
        let limited = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_file_bytes: 4,
                max_total_bytes: 7,
                ..LocatorReadLimits::default()
            },
        );
        let limited_result = limited
            .read_batch(
                LocatorBatchReadRequest {
                    base_directory: &summary.roots[0],
                    files: &requests,
                },
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(matches!(
            limited_result.files[0],
            LocatorFileRead::Present(_)
        ));
        assert!(matches!(
            limited_result.files[1],
            LocatorFileRead::Failed(LocatorReadFailure::ResourceLimit)
        ));
        assert_eq!(limited_result.total_bytes, 4);

        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            reader().read_batch(
                LocatorBatchReadRequest {
                    base_directory: &summary.roots[0],
                    files: &requests[..1],
                },
                &cancel,
            ),
            Err(LocatorReadError::Cancelled)
        );
    }

    #[test]
    fn optional_final_file_is_bound_to_the_enumerated_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("optional"), b"original").unwrap();
        let summary = scan(&root, "locator-read-optional-binding");
        let requests = [LocatorFileRequest::RelativeOptional {
            components: &[native("optional")],
        }];

        let result = reader()
            .read_batch(
                LocatorBatchReadRequest {
                    base_directory: &summary.roots[0],
                    files: &requests,
                },
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            &result.files[0],
            LocatorFileRead::Present(read) if read.bytes == b"original"
        ));
    }

    #[test]
    fn directory_enumeration_budget_is_shared_across_batch_requests() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("one"), b"1").unwrap();
        fs::write(root.join("two"), b"2").unwrap();
        let summary = scan(&root, "locator-read-enumeration-budget");
        let requests = [
            LocatorFileRequest::RelativeOptional {
                components: &[native("one")],
            },
            LocatorFileRequest::RelativeOptional {
                components: &[native("two")],
            },
        ];
        let bounded = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_directory_entries: 2,
                max_directory_batch_entries: 2,
                ..LocatorReadLimits::default()
            },
        );

        let result = bounded
            .read_batch(
                LocatorBatchReadRequest {
                    base_directory: &summary.roots[0],
                    files: &requests,
                },
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(result.files[0], LocatorFileRead::Present(_)));
        assert!(matches!(
            result.files[1],
            LocatorFileRead::Failed(LocatorReadFailure::ResourceLimit)
        ));
    }

    #[test]
    fn cargo_config_pair_uses_one_non_atomic_observation_and_ignores_display_path() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(root.join(".cargo/config"), b"[build]\ntarget-dir='one'\n").unwrap();
        fs::write(
            root.join(".cargo/config.toml"),
            b"[build]\ntarget-dir='two'\n",
        )
        .unwrap();
        let summary = scan(&root, "cargo-pair-observation");
        let mut base = summary.roots[0].clone();
        base.display_path = "/forged/reporting/path".to_string();

        let paged = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_directory_batch_entries: 1,
                ..LocatorReadLimits::default()
            },
        );
        let observed = paged
            .observe_cargo_config_pair(&base, &CancellationToken::new())
            .unwrap();

        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert!(matches!(
            &observed.config,
            CargoConfigMemberObservation::Present(read)
                if read.bytes == b"[build]\ntarget-dir='one'\n"
        ));
        assert!(matches!(
            &observed.config_toml,
            CargoConfigMemberObservation::Present(read)
                if read.bytes == b"[build]\ntarget-dir='two'\n"
        ));
    }

    #[test]
    fn cargo_config_pair_absence_is_explicitly_non_atomic() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(root.join("other"), b"ignored").unwrap();
        let summary = scan(&root, "cargo-pair-absence");

        let observed = reader()
            .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new())
            .unwrap();

        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert_eq!(
            observed.config,
            CargoConfigMemberObservation::AbsentDuringEnumeration
        );
        assert_eq!(
            observed.config_toml,
            CargoConfigMemberObservation::AbsentDuringEnumeration
        );
    }

    #[test]
    fn missing_cargo_directory_is_explicitly_non_atomic() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let summary = scan(&root, "cargo-directory-missing");

        let observed = reader()
            .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new())
            .unwrap();

        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert_eq!(
            observed.config,
            CargoConfigMemberObservation::AbsentDuringEnumeration
        );
        assert_eq!(
            observed.config_toml,
            CargoConfigMemberObservation::AbsentDuringEnumeration
        );
    }

    #[test]
    fn cargo_config_pair_rejects_ascii_case_aliases_and_symlinks() {
        let alias_temp = tempfile::TempDir::new().unwrap();
        let alias_root = alias_temp.path().join("root");
        fs::create_dir_all(alias_root.join(".cargo")).unwrap();
        fs::write(alias_root.join(".cargo/CONFIG"), b"alias").unwrap();
        let alias_summary = scan(&alias_root, "cargo-pair-alias");
        let alias = reader()
            .observe_cargo_config_pair(&alias_summary.roots[0], &CancellationToken::new())
            .unwrap();
        assert!(matches!(
            alias.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));
        assert!(matches!(
            alias.config_toml,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));

        let link_temp = tempfile::TempDir::new().unwrap();
        let link_root = link_temp.path().join("root");
        fs::create_dir_all(link_root.join(".cargo")).unwrap();
        fs::write(link_root.join("real-config"), b"real").unwrap();
        std::os::unix::fs::symlink("../real-config", link_root.join(".cargo/config")).unwrap();
        let link_summary = scan(&link_root, "cargo-pair-link");
        let link = reader()
            .observe_cargo_config_pair(&link_summary.roots[0], &CancellationToken::new())
            .unwrap();
        assert!(matches!(
            link.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::SymlinkOrReparse)
        ));
        assert!(matches!(
            link.config_toml,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::SymlinkOrReparse)
        ));
    }

    #[test]
    fn cargo_directory_alias_is_rejected_instead_of_treated_as_absent() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".CARGO")).unwrap();
        fs::write(root.join(".CARGO/config"), b"alias").unwrap();
        let summary = scan(&root, "cargo-directory-alias");

        let observed = reader()
            .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new())
            .unwrap();

        assert!(matches!(
            observed.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));
        assert!(matches!(
            observed.config_toml,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));
    }

    #[test]
    fn cargo_config_pair_continues_to_eof_and_rejects_late_alias() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(root.join(".cargo/config"), b"exact").unwrap();
        fs::write(root.join(".cargo/CONFIG"), b"alias").unwrap();
        let summary = scan(&root, "cargo-pair-late-alias");
        let paged = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_directory_batch_entries: 1,
                ..LocatorReadLimits::default()
            },
        );

        let observed = paged
            .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new())
            .unwrap();

        assert!(matches!(
            observed.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));
        assert!(matches!(
            observed.config_toml,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
        ));
    }

    #[test]
    fn cargo_config_pair_obeys_cancellation_and_directory_budget() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(root.join(".cargo/config"), b"config").unwrap();
        let summary = scan(&root, "cargo-pair-bounds");
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            reader().observe_cargo_config_pair(&summary.roots[0], &cancel),
            Err(LocatorReadError::Cancelled)
        );

        let bounded = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_directory_entries: 1,
                max_directory_batch_entries: 1,
                ..LocatorReadLimits::default()
            },
        );
        let observed = bounded
            .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new())
            .unwrap();
        assert!(matches!(
            observed.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::ResourceLimit)
        ));
    }

    #[test]
    fn cargo_config_pair_honors_request_and_component_budgets() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        let summary = scan(&root, "cargo-pair-component-budget");
        for limits in [
            LocatorReadLimits {
                max_requests: 2,
                ..LocatorReadLimits::default()
            },
            LocatorReadLimits {
                max_components_per_request: 2,
                ..LocatorReadLimits::default()
            },
            LocatorReadLimits {
                max_total_components: 7,
                ..LocatorReadLimits::default()
            },
        ] {
            assert_eq!(
                LocatorReader::new(HostPlatformScanner::new(), limits)
                    .observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new()),
                Err(LocatorReadError::ResourceLimit)
            );
        }
    }

    #[test]
    fn captured_cargo_home_pair_reads_direct_members_and_not_dot_cargo() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir_all(cargo_home.join(".cargo")).unwrap();
        fs::write(cargo_home.join("config"), b"[build]\ntarget-dir='legacy'\n").unwrap();
        fs::write(
            cargo_home.join("config.toml"),
            b"[build]\ntarget-dir='modern'\n",
        )
        .unwrap();
        fs::write(cargo_home.join(".cargo/config"), b"wrong-level").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();
        let paged = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::Passthrough),
            LocatorReadLimits {
                max_directory_batch_entries: 1,
                ..LocatorReadLimits::default()
            },
        );

        let observed = paged
            .observe_cargo_config_pair_in_captured_directory(&captured, &CancellationToken::new())
            .unwrap();

        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert_eq!(
            observed.config,
            CargoConfigMemberPresenceObservation::Present
        );
        assert_eq!(
            observed.config_toml,
            CargoConfigMemberPresenceObservation::Present
        );
        let debug = format!("{observed:?}");
        assert!(!debug.contains(&cargo_home.to_string_lossy().to_string()));
        assert!(!debug.contains("target-dir"));
    }

    #[test]
    fn captured_cargo_home_pair_reports_non_atomic_absence_and_ignores_nested_dot_cargo() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir_all(cargo_home.join(".cargo")).unwrap();
        fs::write(cargo_home.join("credentials.toml"), b"[registry]\n").unwrap();
        fs::write(cargo_home.join(".cargo/config"), b"not-a-direct-member").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();

        let observed = reader()
            .observe_cargo_config_pair_in_captured_directory(&captured, &CancellationToken::new())
            .unwrap();

        assert_eq!(observed.consistency, CargoConfigPairConsistency::NonAtomic);
        assert_eq!(
            observed.config,
            CargoConfigMemberPresenceObservation::AbsentDuringEnumeration
        );
        assert_eq!(
            observed.config_toml,
            CargoConfigMemberPresenceObservation::AbsentDuringEnumeration
        );
    }

    #[test]
    fn captured_cargo_home_pair_rejects_aliases_duplicates_and_symlinks() {
        let alias_temp = tempfile::TempDir::new().unwrap();
        let alias_home = alias_temp.path().join("explicit-cargo-home");
        fs::create_dir(&alias_home).unwrap();
        fs::write(alias_home.join("CONFIG"), b"alias").unwrap();
        let alias_capture = reader()
            .capture_directory_identity(&alias_home, &CancellationToken::new())
            .unwrap();
        let alias = reader()
            .observe_cargo_config_pair_in_captured_directory(
                &alias_capture,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_presence_pair_failed(&alias, LocatorReadFailure::AmbiguousAlias);

        let duplicate_temp = tempfile::TempDir::new().unwrap();
        let duplicate_home = duplicate_temp.path().join("explicit-cargo-home");
        fs::create_dir(&duplicate_home).unwrap();
        fs::write(duplicate_home.join("config"), b"exact").unwrap();
        let duplicate_capture = reader()
            .capture_directory_identity(&duplicate_home, &CancellationToken::new())
            .unwrap();
        let duplicate_reader = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::DuplicateConfig),
            LocatorReadLimits::default(),
        );
        let duplicate = duplicate_reader
            .observe_cargo_config_pair_in_captured_directory(
                &duplicate_capture,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_presence_pair_failed(&duplicate, LocatorReadFailure::AmbiguousAlias);

        let link_temp = tempfile::TempDir::new().unwrap();
        let link_home = link_temp.path().join("explicit-cargo-home");
        fs::create_dir(&link_home).unwrap();
        fs::write(link_home.join("real-config"), b"real").unwrap();
        std::os::unix::fs::symlink("real-config", link_home.join("config")).unwrap();
        let link_capture = reader()
            .capture_directory_identity(&link_home, &CancellationToken::new())
            .unwrap();
        let link = reader()
            .observe_cargo_config_pair_in_captured_directory(
                &link_capture,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_presence_pair_failed(&link, LocatorReadFailure::SymlinkOrReparse);

        let directory_temp = tempfile::TempDir::new().unwrap();
        let directory_home = directory_temp.path().join("explicit-cargo-home");
        fs::create_dir_all(directory_home.join("config")).unwrap();
        let directory_capture = reader()
            .capture_directory_identity(&directory_home, &CancellationToken::new())
            .unwrap();
        let directory = reader()
            .observe_cargo_config_pair_in_captured_directory(
                &directory_capture,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_presence_pair_failed(&directory, LocatorReadFailure::NotRegular);
    }

    #[test]
    fn captured_cargo_home_pair_rejects_replaced_directory() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"original").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();
        fs::rename(&cargo_home, temp.path().join("old-cargo-home")).unwrap();
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"replacement").unwrap();

        let observed = reader()
            .observe_cargo_config_pair_in_captured_directory(&captured, &CancellationToken::new())
            .unwrap();

        assert_presence_pair_failed(&observed, LocatorReadFailure::IdentityMismatch);
    }

    #[test]
    fn captured_cargo_home_pair_revalidates_every_directory_identity_field() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"must-not-be-read").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();

        let mut identity_changed = captured.clone();
        identity_changed.identity = EntryIdentity::from_windows_file_id(
            captured.identity.device().wrapping_add(1),
            captured.identity.windows_file_id(),
        );
        let mut filesystem_changed = captured.clone();
        filesystem_changed.filesystem_identity.device = filesystem_changed
            .filesystem_identity
            .device
            .wrapping_add(1);
        let mut mount_changed = captured.clone();
        mount_changed.mount_identity.value = mount_changed.mount_identity.value.wrapping_add(1);
        let mut fingerprint_changed = captured.clone();
        fingerprint_changed.fingerprint.push_str("-changed");

        for (tampered, expected) in [
            (identity_changed, LocatorReadFailure::IdentityMismatch),
            (filesystem_changed, LocatorReadFailure::IdentityMismatch),
            (mount_changed, LocatorReadFailure::MountChanged),
            (fingerprint_changed, LocatorReadFailure::IdentityMismatch),
        ] {
            let observed = reader()
                .observe_cargo_config_pair_in_captured_directory(
                    &tampered,
                    &CancellationToken::new(),
                )
                .unwrap();
            assert_presence_pair_failed(&observed, expected);
        }

        let mut wrong_kind = captured;
        wrong_kind.kind = EntryKind::File;
        assert_eq!(
            reader().observe_cargo_config_pair_in_captured_directory(
                &wrong_kind,
                &CancellationToken::new(),
            ),
            Err(LocatorReadError::InvalidRequest)
        );
    }

    #[test]
    fn captured_cargo_home_pair_reports_cancellation_at_each_public_boundary() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"config").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();

        let cancelled_before_admission = CancellationToken::new();
        cancelled_before_admission.cancel();
        assert_eq!(
            reader().observe_cargo_config_pair_in_captured_directory(
                &captured,
                &cancelled_before_admission,
            ),
            Err(LocatorReadError::Cancelled)
        );

        let cancel_during_enumeration = CancellationToken::new();
        let cancelling_reader = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::Cancel),
            LocatorReadLimits::default(),
        );
        let observed = cancelling_reader
            .observe_cargo_config_pair_in_captured_directory(&captured, &cancel_during_enumeration)
            .unwrap();
        assert_presence_pair_failed(&observed, LocatorReadFailure::Cancelled);

        let cancel_after_inspection = CancellationToken::new();
        let cancelling_reader = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::CancelAfterInspect),
            LocatorReadLimits::default(),
        );
        let observed = cancelling_reader
            .observe_cargo_config_pair_in_captured_directory(&captured, &cancel_after_inspection)
            .unwrap();
        assert_presence_pair_failed(&observed, LocatorReadFailure::Cancelled);
    }

    #[test]
    fn captured_cargo_home_pair_honors_request_component_and_directory_budgets_without_bytes() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"1234").unwrap();
        fs::write(cargo_home.join("credentials.toml"), b"ignored").unwrap();
        let captured = reader()
            .capture_directory_identity(&cargo_home, &CancellationToken::new())
            .unwrap();

        for limits in [
            LocatorReadLimits {
                max_requests: 1,
                ..LocatorReadLimits::default()
            },
            LocatorReadLimits {
                max_components_per_request: 1,
                ..LocatorReadLimits::default()
            },
            LocatorReadLimits {
                max_total_components: 3,
                ..LocatorReadLimits::default()
            },
        ] {
            assert_eq!(
                LocatorReader::new(HostPlatformScanner::new(), limits)
                    .observe_cargo_config_pair_in_captured_directory(
                        &captured,
                        &CancellationToken::new(),
                    ),
                Err(LocatorReadError::ResourceLimit)
            );
        }

        let directory_bounded = LocatorReader::new(
            HostPlatformScanner::new(),
            LocatorReadLimits {
                max_directory_entries: 1,
                max_directory_batch_entries: 1,
                ..LocatorReadLimits::default()
            },
        );
        let directory_observed = directory_bounded
            .observe_cargo_config_pair_in_captured_directory(&captured, &CancellationToken::new())
            .unwrap();
        assert_presence_pair_failed(&directory_observed, LocatorReadFailure::ResourceLimit);

        let byte_bounded = LocatorReader::new(
            EnumerationTestScanner::new(EnumerationTestAction::Passthrough),
            LocatorReadLimits {
                max_file_bytes: 0,
                max_total_bytes: 0,
                ..LocatorReadLimits::default()
            },
        );
        let byte_observed = byte_bounded
            .observe_cargo_config_pair_in_captured_directory(&captured, &CancellationToken::new())
            .unwrap();
        assert_eq!(
            byte_observed.config,
            CargoConfigMemberPresenceObservation::Present
        );
        assert_eq!(
            byte_observed.config_toml,
            CargoConfigMemberPresenceObservation::AbsentDuringEnumeration
        );
    }

    #[test]
    fn cargo_config_pair_rejects_stale_base_provenance() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        let mut summary = scan(&root, "cargo-pair-stale-base");
        summary.roots[0].provenance = sweepx_model::FieldProvenance::StalePreview {
            observed_at: "2026-08-28T00:00:00Z".to_string(),
        };

        assert_eq!(
            reader().observe_cargo_config_pair(&summary.roots[0], &CancellationToken::new()),
            Err(LocatorReadError::InvalidRequest)
        );
    }
}
