use super::*;
use sweepx_model::NativeName;

impl<P: PlatformScanner> DetailRescanner<P> {
    /// Obtain a token the backend can inspect. Windows requires the exact current batch token;
    /// constructing the same basename is not enough to bind its enumerated file identity.
    pub(super) fn lookup_child(
        &self,
        parent: &mut P::DirectoryHandle,
        parent_path: &Path,
        name: &NativeName,
        cancel: &CancellationToken,
    ) -> Result<DirectoryEntryRecord, DetailRescanError> {
        let requested = DirectoryEntryRecord::from_parent_and_name(parent_path, name.clone())
            .map_err(|_| DetailRescanError::InvalidRequest)?;
        if !self.platform.child_inspection_requires_enumeration() {
            return Ok(requested);
        }
        let mut remaining_entries = self.limits.max_directory_entries;
        let mut remaining_bytes = self.limits.max_directory_bytes;
        loop {
            if cancel.is_cancelled() {
                return Err(DetailRescanError::Cancelled);
            }
            let limits = DirectoryReadLimits {
                max_batch_entries: self
                    .limits
                    .max_directory_batch_entries
                    .min(remaining_entries),
                max_batch_bytes: self.limits.max_directory_batch_bytes.min(remaining_bytes),
            };
            if limits.max_batch_entries == 0 || limits.max_batch_bytes == 0 {
                return Err(DetailRescanError::ResourceLimit);
            }
            let batch = self
                .platform
                .enumerate_children(parent, cancel, limits)
                .map_err(map_platform_error)?;
            if cancel.is_cancelled() {
                return Err(DetailRescanError::Cancelled);
            }
            let bytes = batch.entries.iter().try_fold(0usize, |total, child| {
                child
                    .estimated_retained_bytes()
                    .and_then(|bytes| total.checked_add(bytes))
            });
            if batch.entries.len() > limits.max_batch_entries
                || bytes.is_none_or(|bytes| bytes > limits.max_batch_bytes)
                || (batch.entries.is_empty() && !batch.end_of_directory)
            {
                return Err(DetailRescanError::Unavailable);
            }
            remaining_entries -= batch.entries.len();
            remaining_bytes -= bytes.expect("batch bytes checked above");
            let mut found = None;
            for child in batch.entries {
                child
                    .validate_for_parent(parent_path)
                    .map_err(|_| DetailRescanError::Unavailable)?;
                if child.file_name == *name && found.replace(child).is_some() {
                    return Err(DetailRescanError::Unavailable);
                }
            }
            if let Some(child) = found {
                // Inspect before requesting another batch: advancing invalidates this token's
                // native evidence even if the next batch happens to contain the same name.
                return Ok(child);
            }
            if batch.end_of_directory {
                return Err(DetailRescanError::IdentityMismatch);
            }
        }
    }
}
