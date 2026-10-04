//! Content access shares detail rescans' native root and directory lineage validation.

use super::*;
use sweepx_platform::inspect_bound_child_with_mount_identity;
use sweepx_platform::{
    BoundedRegularFileReadError, RegularFileObservation, RegularFileReadExpectation,
    RegularFileStreamRequest, RegularFileStreamResult, stream_bound_regular_file,
};

/// One range of a current scanned ordinary file, never a display-path request.
pub struct FileContentRequest<'a> {
    /// Source scan identity and lossless native lineage to revalidate.
    pub entry: &'a ScannedEntry,
    /// First logical byte to read.
    pub offset: u64,
    /// Maximum payload bytes, with no extra EOF probe.
    pub max_bytes: u64,
    /// Prior content stage to bind identity, length and change stamp before reading.
    pub previous: Option<&'a RegularFileObservation>,
}

#[cfg(all(
    test,
    any(
        all(target_os = "macos", feature = "platform-macos"),
        all(target_os = "linux", feature = "platform-linux"),
        all(windows, feature = "platform-windows")
    )
))]
mod tests;

/// Refused native binding or content observation; neither yields accepted hash evidence.
#[derive(Debug, Clone, Error)]
pub enum FileContentError {
    /// Root, parent lineage, mount or source scan facts failed validation.
    #[error(transparent)]
    Binding(#[from] DetailRescanError),
    /// Native content access failed, changed, exceeded its range or was cancelled.
    #[error(transparent)]
    Read(#[from] BoundedRegularFileReadError),
}

impl<P: PlatformScanner> DetailRescanner<P> {
    /// Revalidates source root and parent lineage, observes the file's own native mount, then
    /// streams its bound range. macOS ordinary scan rows can lack file mount evidence: this
    /// operation establishes it live and checks it against the root, rather than copying it.
    /// Provisional chunks must be discarded on failure. Synchronous IO belongs on a worker.
    pub fn stream_file(
        &self,
        request: FileContentRequest<'_>,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, FileContentError> {
        if cancel.is_cancelled() {
            return Err(DetailRescanError::Cancelled.into());
        }
        let entry = request.entry;
        let invalid = || FileContentError::Binding(DetailRescanError::InvalidRequest);
        let identity = entry.identity.as_ref().ok_or_else(invalid)?;
        let locator = entry
            .validated_native_locator()
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if locator.parent_reopen_recipe.len() > 256
            || entry.estimated_retained_bytes() > 1024 * 1024
        {
            return Err(DetailRescanError::ResourceLimit.into());
        }
        if entry.object_type != ObjectType::File
            || locator.entry.object_type != ObjectType::File
            || locator.entry.native_basename != entry.native_basename
        {
            return Err(invalid());
        }
        // Keep the same bounded lineage contract as a detail query. The directory prefix is
        // executable evidence even when the final ordinary file needs live mount observation.
        let root_identity = ScanObjectIdentity {
            entry_id: locator.scan_root.entry_id.clone(),
            scan_root_id: locator.scan_root.entry_id.clone(),
            parent_id: None,
            platform_file_identity: locator.scan_root.platform_file_identity.clone(),
            filesystem_object_domain_identity: locator
                .scan_root
                .filesystem_object_domain_identity
                .clone(),
            volume_or_mount_identity: locator.scan_root.volume_or_mount_identity.clone(),
        };
        let parent = locator.parent_reopen_recipe.last().ok_or_else(invalid)?;
        let parent_identity = identity_from_component(parent, &root_identity);
        let parent_locator = NativeLocatorEvidence {
            scan_root: locator.scan_root.clone(),
            scan_root_absolute_path: locator.scan_root_absolute_path.clone(),
            parent_reopen_recipe: locator.parent_reopen_recipe
                [..locator.parent_reopen_recipe.len() - 1]
                .to_vec(),
            entry: parent.clone(),
        };
        let directory_request = DetailRescanRequest {
            source_scan_id: &entry.scan_id,
            source_root_identity: &root_identity,
            source_directory_identity: &parent_identity,
            directory_locator: &parent_locator,
            revision: 0.into(),
            max_rows: 1,
        };
        let ids = DetailEntryIdAllocator::new(entry.scan_id.clone())?;
        self.validate_request(&directory_request, &ids)?;
        let reopened = self.reopen_target(&directory_request, cancel)?;
        let child = DirectoryEntryRecord::from_parent_and_name(
            &reopened.target_metadata.path,
            entry.native_basename.clone(),
        )
        .map_err(|_| invalid())?;
        let metadata = match inspect_bound_child_with_mount_identity(
            &self.platform,
            &reopened.target_handle,
            &reopened.target_metadata.path,
            &child,
            cancel,
        )
        .map_err(map_platform_error)?
        {
            WalkEntry::File(metadata) => metadata,
            WalkEntry::Link(_) => return Err(DetailRescanError::SymlinkOrReparse.into()),
            WalkEntry::Boundary(boundary) => return Err(map_boundary(&boundary.kind).into()),
            WalkEntry::Error(error) => return Err(map_walk_error(error.kind).into()),
            _ => return Err(DetailRescanError::IdentityMismatch.into()),
        };
        require_same_mount(&self.platform, &reopened.root_metadata, &metadata)?;
        let observed = scan_object_identity(
            identity.entry_id.clone(),
            identity.scan_root_id.clone(),
            identity.parent_id.clone(),
            &metadata,
        );
        if !identity_is_known(&observed) {
            return Err(DetailRescanError::IdentityUnavailable.into());
        }
        if observed.platform_file_identity != identity.platform_file_identity
            || observed.filesystem_object_domain_identity
                != identity.filesystem_object_domain_identity
            || metadata.logical_bytes != entry.logical_bytes
            || (matches!(
                identity.volume_or_mount_identity,
                IdentityEvidence::Known { .. }
            ) && observed.volume_or_mount_identity != identity.volume_or_mount_identity)
        {
            return Err(DetailRescanError::IdentityMismatch.into());
        }
        let expectation = RegularFileReadExpectation::previously_observed(
            metadata
                .identity
                .ok_or(DetailRescanError::IdentityUnavailable)?,
            metadata
                .filesystem_identity
                .ok_or(DetailRescanError::IdentityUnavailable)?,
            metadata
                .mount_identity
                .ok_or(DetailRescanError::IdentityUnavailable)?,
        );
        // Inspect-to-open can race even for the same inode. Establish a zero-payload live stamp
        // before the first stage, preventing a full hash from becoming a grown file's prefix.
        let live = if request.previous.is_none() {
            let probe = RegularFileStreamRequest::new(
                entry.native_basename.clone(),
                expectation.clone(),
                0,
                0,
                None,
            )?;
            let live = stream_bound_regular_file(
                &self.platform,
                &reopened.target_handle,
                &probe,
                cancel,
                &mut |_| unreachable!("metadata-only probe"),
            )?;
            if entry.logical_bytes
                != (EvidenceValue::Known {
                    value: live.observed_after.logical_bytes,
                })
            {
                return Err(DetailRescanError::IdentityMismatch.into());
            }
            Some(live.observed_after)
        } else {
            None
        };
        let bound = RegularFileStreamRequest::new(
            entry.native_basename.clone(),
            expectation,
            request.offset,
            request.max_bytes,
            request.previous.cloned().or(live),
        )?;
        stream_bound_regular_file(
            &self.platform,
            &reopened.target_handle,
            &bound,
            cancel,
            consume,
        )
        .map_err(Into::into)
    }
}
