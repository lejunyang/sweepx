use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

use sweepx_model::{
    EvidenceValue, IdentityEvidence, NativeAbsolutePath, NativeName, NativePathComponent,
    ObjectType, ScannedEntry,
};
use sweepx_platform::{
    BoundedRegularFileReadError, BoundedRegularFileReadRequest, CancellationToken,
    DirectoryEntryRecord, DirectoryReadLimits, EntryIdentity, EntryKind, FilesystemIdentity,
    MountIdentity, PlatformError, PlatformScanner, PresentRegularFileRead, RootAdmission, ScanRoot,
    WalkEntry, inspect_bound_child, read_bound_regular_file,
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
        let mut config = None;
        let mut config_toml = None;
        let mut saw_config = false;
        let mut saw_config_toml = false;
        let mut total_bytes = 0usize;
        let mut alias_collision = false;
        let mut observation_failure = None;

        loop {
            let batch = match self.next_directory_batch(&mut cargo, cancel, &mut budget) {
                Ok(batch) => batch,
                Err(failure) => return Ok(pair_failed(failure)),
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
                                &cargo,
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
                                &cargo,
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
            return Ok(pair_failed(LocatorReadFailure::AmbiguousAlias));
        }
        if let Some(failure) = observation_failure {
            return Ok(pair_failed(failure));
        }
        let config = match config {
            Some(Err(failure)) => return Ok(pair_failed(failure)),
            Some(Ok(read)) => CargoConfigMemberObservation::Present(Box::new(read)),
            None => CargoConfigMemberObservation::AbsentDuringEnumeration,
        };
        let config_toml = match config_toml {
            Some(Err(failure)) => return Ok(pair_failed(failure)),
            Some(Ok(read)) => CargoConfigMemberObservation::Present(Box::new(read)),
            None => CargoConfigMemberObservation::AbsentDuringEnumeration,
        };
        Ok(CargoConfigPairObservation {
            consistency: CargoConfigPairConsistency::NonAtomic,
            config,
            config_toml,
            total_bytes,
        })
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

    use super::*;
    use crate::{HostPlatformScanner, Scanner, ScannerOptions};
    use sweepx_model::ScanId;

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
