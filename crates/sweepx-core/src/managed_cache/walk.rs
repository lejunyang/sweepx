//! Bounded streaming observations using the same native backend as the scanner.
//! Handles retain enumeration authority; paths returned here remain discovery hints only.
use super::*;
use sweepx_platform::{
    DirectoryEntryRecord, DirectoryReadLimits, EntryMetadata, OpenedDirectory, PlatformScanner,
    ScanRoot, WalkEntry, inspect_bound_child,
};
use sweepx_scanner::HostPlatformScanner;
struct Frame<D> {
    opened: OpenedDirectory<D>,
    pending: std::vec::IntoIter<DirectoryEntryRecord>,
    eof: bool,
}
/// Depth-first pages bound open handles and metadata independently of directory breadth.
pub(super) fn walk(
    root: &Path,
    cancel: &CancellationToken,
    excluded: &[&str],
    mut observe: impl FnMut(&EntryMetadata) -> Result<(), String>,
) -> Result<(), String> {
    let backend = HostPlatformScanner::new();
    let requested = ScanRoot::new(root.to_path_buf()).map_err(|e| e.to_string())?;
    let admitted = backend
        .admit_root(&requested, cancel)
        .map_err(|e| e.to_string())?;
    admitted
        .validate_for_root(&requested)
        .map_err(|e| e.to_string())?;
    let root_metadata = admitted.metadata.clone();
    observe(&root_metadata)?;
    let mut stack = vec![Frame {
        opened: OpenedDirectory {
            metadata: admitted.metadata,
            handle: admitted.directory,
        },
        pending: Vec::new().into_iter(),
        eof: false,
    }];
    let until = Instant::now() + std::time::Duration::from_secs(900);
    let mut visited = 0usize;
    while let Some(frame) = stack.last_mut() {
        if cancel.is_cancelled() || Instant::now() >= until {
            return Err("project_walk_cancelled_or_deadline".into());
        }
        let Some(child) = frame.pending.next() else {
            if frame.eof {
                stack.pop();
                continue;
            }
            let batch = backend
                .enumerate_children(
                    &mut frame.opened.handle,
                    cancel,
                    DirectoryReadLimits {
                        max_batch_entries: 128,
                        max_batch_bytes: 64 * 1024,
                    },
                )
                .map_err(|e| e.to_string())?;
            if batch.entries.is_empty() && !batch.end_of_directory {
                return Err("non_progressing_native_enumeration".into());
            }
            frame.eof = batch.end_of_directory;
            frame.pending = batch.entries.into_iter();
            continue;
        };
        visited += 1;
        if visited > 2_000_000 {
            return Err("project_walk_entry_budget".into());
        }
        let entry = inspect_bound_child(
            &backend,
            &frame.opened.handle,
            &frame.opened.metadata.path,
            &child,
            cancel,
        )
        .map_err(|e| e.to_string())?;
        match entry {
            WalkEntry::Directory(dir) => {
                if !backend
                    .is_same_mount(&root_metadata, &dir.metadata)
                    .map_err(|e| e.to_string())?
                {
                    return Err("project_walk_mount_boundary".into());
                }
                observe(&dir.metadata)?;
                if dir
                    .metadata
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| excluded.contains(&n))
                {
                    continue;
                }
                if stack.len() >= 64 {
                    return Err("project_walk_depth_budget".into());
                }
                stack.push(Frame {
                    opened: dir,
                    pending: Vec::new().into_iter(),
                    eof: false,
                });
            }
            WalkEntry::File(e) | WalkEntry::Link(e) => {
                if e.filesystem_identity != root_metadata.filesystem_identity {
                    return Err("project_file_filesystem_boundary".into());
                }
                if e.mount_identity.is_some()
                    && !backend
                        .is_same_mount(&root_metadata, &e)
                        .map_err(|e| e.to_string())?
                {
                    return Err("project_file_mount_boundary".into());
                }
                // Logical observations use native metadata like ordinary scanner totals. Missing
                // file mount evidence stays unknown; it is never inferred from the parent or used
                // for execution. Traversed directories still require exact mount equality.
                observe(&e)?;
            }
            WalkEntry::Boundary(b) => {
                return Err(format!(
                    "project_walk_boundary: {}: {:?}",
                    b.path.display(),
                    b.reason
                ));
            }
            WalkEntry::Error(e) => {
                return Err(format!(
                    "project_walk_error: {}: {}",
                    e.path.display(),
                    e.detail
                ));
            }
            WalkEntry::CachedFile(_) => return Err("project_walk_full_metadata_required".into()),
        }
    }
    Ok(())
}
/// Sum ordinary virtual-store file lengths once per native filesystem object.
pub(super) fn footprint(roots: &[PathBuf], cancel: &CancellationToken) -> (ByteValue, bool) {
    if roots.is_empty() {
        return (bytes(None, false), false);
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u128;
    let mut complete = true;
    for root in roots {
        let result = walk(root, cancel, &[], |e| {
            if e.kind != sweepx_platform::EntryKind::File {
                return Ok(());
            }
            let identity = e.identity.as_ref().ok_or("package_file_identity_unknown")?;
            let domain = e
                .filesystem_identity
                .as_ref()
                .ok_or("package_filesystem_unknown")?;
            let key = (identity.clone(), domain.device);
            if seen.len() >= 2_000_000 || seen.len().saturating_mul(128) > 128 * 1024 * 1024 {
                return Err("package_footprint_identity_budget".into());
            }
            if seen.insert(key) {
                total = total
                    .checked_add(exact(&e.logical_bytes).ok_or("package_length_unknown")?)
                    .ok_or("package_length_overflow")?;
            }
            Ok(())
        });
        complete &= result.is_ok();
    }
    (bytes(Some(total), complete), complete)
}
