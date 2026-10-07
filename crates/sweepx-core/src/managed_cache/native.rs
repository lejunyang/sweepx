//! Thin bounded adapter over the scanner's native authority; no pathname-based traversal.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use sweepx_model::{DecimalU128, NativeName, ScanId, ScanObjectIdentity, ScannedEntry};
use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};
use sweepx_scanner::{
    DetailEntryIdAllocator, DetailRescanRequest, DetailRescanner, FileContentRequest,
    HostPlatformScanner, Scanner, ScannerOptions,
};
static INVOCATION: AtomicU64 = AtomicU64::new(1);
pub(super) struct Native<'a> {
    pub cancel: &'a CancellationToken,
    until: Instant,
    calls: usize,
    pub bytes: usize,
    ids: BTreeMap<String, DetailEntryIdAllocator>,
}
impl<'a> Native<'a> {
    pub fn new(cancel: &'a CancellationToken) -> Self {
        Self {
            cancel,
            // Large legacy pnpm stores can contain tens of thousands of package indexes.
            // Keep a finite worker budget without cutting the reference graph after five minutes.
            until: Instant::now() + Duration::from_secs(900),
            calls: 0,
            bytes: 0,
            ids: BTreeMap::new(),
        }
    }
    pub fn check(&mut self) -> Result<(), String> {
        self.calls += 1;
        if self.cancel.is_cancelled() {
            Err("cancelled".into())
        } else if self.calls > 200_000 || Instant::now() >= self.until {
            Err("inventory_budget_exceeded".into())
        } else {
            Ok(())
        }
    }
    pub fn root(&mut self, path: &Path) -> Result<ScannedEntry, String> {
        self.check()?;
        let options = ScannerOptions {
            scan_id: ScanId::new(format!(
                "managed-{}",
                INVOCATION.fetch_add(1, Ordering::Relaxed)
            )),
            ..Default::default()
        };
        Scanner::new(HostPlatformScanner::new(), options)
            .scan_roots_only(
                &[ScanRoot::new(path.to_path_buf()).map_err(|e| e.to_string())?],
                self.cancel,
            )
            .map_err(|e| e.to_string())?
            .roots
            .into_iter()
            .next()
            .ok_or("root_not_admitted".into())
    }
    pub fn children(&mut self, parent: &ScannedEntry) -> Result<Vec<ScannedEntry>, String> {
        self.check()?;
        let ids = self.ids.entry(parent.scan_id.to_string()).or_insert(
            DetailEntryIdAllocator::new(parent.scan_id.clone()).map_err(|e| e.to_string())?,
        );
        reserve_lineage(ids, parent)?;
        let root = root_identity(parent)?;
        let request = request(parent, &root)?;
        DetailRescanner::new(HostPlatformScanner::new(), limits())
            .observe_direct_children(request, ids, self.cancel)
            .map_err(|e| e.to_string())
    }
    pub fn child(&mut self, parent: &ScannedEntry, name: &str) -> Result<ScannedEntry, String> {
        self.check()?;
        let ids = self.ids.entry(parent.scan_id.to_string()).or_insert(
            DetailEntryIdAllocator::new(parent.scan_id.clone()).map_err(|e| e.to_string())?,
        );
        reserve_lineage(ids, parent)?;
        let root = root_identity(parent)?;
        DetailRescanner::new(HostPlatformScanner::new(), limits())
            .observe_child(
                request(parent, &root)?,
                &native_name(name),
                ids,
                self.cancel,
            )
            .map_err(|e| e.to_string())
    }
    pub fn read(
        &mut self,
        parent: &ScannedEntry,
        name: &str,
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        self.check()?;
        // Fixed native child inspection and the existing bound streaming reader avoid repeating
        // ancestor sibling enumeration for every package index in a large CAS shard.
        let file = self.child(parent, name)?;
        let length = match &file.logical_bytes {
            sweepx_model::EvidenceValue::Known { value } => usize::try_from(value.0)
                .ok()
                .filter(|n| *n <= limit)
                .ok_or("file_byte_budget_exceeded")?,
            _ => return Err("file_length_unknown".into()),
        };
        if self
            .bytes
            .checked_add(length)
            .is_none_or(|n| n > 1024 * 1024 * 1024)
        {
            return Err("index_byte_budget_exceeded".into());
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| "file_byte_budget_exceeded")?;
        let observed = DetailRescanner::new(HostPlatformScanner::new(), limits())
            .stream_file(
                FileContentRequest {
                    entry: &file,
                    offset: 0,
                    max_bytes: length as u64,
                    previous: None,
                },
                self.cancel,
                &mut |chunk| {
                    bytes.extend_from_slice(chunk);
                    Ok(())
                },
            )
            .map_err(|e| e.to_string())?;
        if bytes.len() != length || observed.observed_after.logical_bytes.0 != length as u128 {
            return Err("file_length_changed".into());
        }
        self.bytes += bytes.len();
        Ok(bytes)
    }
}
fn limits() -> ScanResourceLimits {
    ScanResourceLimits {
        max_visited_entries: 100_000,
        max_retained_entries: 100_000,
        max_retained_aggregates: 100_001,
        ..Default::default()
    }
}
fn root_identity(entry: &ScannedEntry) -> Result<ScanObjectIdentity, String> {
    let l = entry
        .executable_native_locator()
        .map_err(|e| e.to_string())?
        .ok_or("missing_locator")?;
    Ok(ScanObjectIdentity {
        entry_id: l.scan_root.entry_id.clone(),
        scan_root_id: l.scan_root.entry_id.clone(),
        parent_id: None,
        platform_file_identity: l.scan_root.platform_file_identity.clone(),
        filesystem_object_domain_identity: l.scan_root.filesystem_object_domain_identity.clone(),
        volume_or_mount_identity: l.scan_root.volume_or_mount_identity.clone(),
    })
}
fn request<'a>(
    entry: &'a ScannedEntry,
    root: &'a ScanObjectIdentity,
) -> Result<DetailRescanRequest<'a>, String> {
    Ok(DetailRescanRequest {
        source_scan_id: &entry.scan_id,
        source_root_identity: root,
        source_directory_identity: entry
            .validated_identity()
            .map_err(|e| e.to_string())?
            .ok_or("missing_identity")?,
        directory_locator: entry
            .executable_native_locator()
            .map_err(|e| e.to_string())?
            .ok_or("missing_locator")?,
        revision: DecimalU128::new(1),
        max_rows: 100_000,
    })
}
pub(super) fn native_name(s: &str) -> NativeName {
    #[cfg(unix)]
    {
        NativeName::unix(s.as_bytes())
    }
    #[cfg(windows)]
    {
        NativeName::windows_utf16(s.encode_utf16().collect::<Vec<_>>())
    }
}
pub(super) fn basename(e: &ScannedEntry) -> Option<String> {
    match &e.native_basename {
        NativeName::UnixBytes(b) => String::from_utf8(b.clone()).ok(),
        NativeName::WindowsUtf16(u) => String::from_utf16(u).ok(),
    }
}
pub(super) fn same_object(a: &ScannedEntry, b: &ScannedEntry) -> bool {
    a.identity
        .as_ref()
        .zip(b.identity.as_ref())
        .is_some_and(|(a, b)| {
            a.platform_file_identity == b.platform_file_identity
                && a.filesystem_object_domain_identity == b.filesystem_object_domain_identity
                && a.volume_or_mount_identity == b.volume_or_mount_identity
        })
}

pub(super) fn path(entry: &ScannedEntry) -> Result<PathBuf, String> {
    let l = entry
        .executable_native_locator()
        .map_err(|e| e.to_string())?
        .ok_or("missing_locator")?;
    let root = l
        .scan_root_absolute_path
        .as_ref()
        .ok_or("missing_native_root")?;
    #[cfg(unix)]
    let mut p = {
        use std::os::unix::ffi::OsStringExt;
        match root {
            sweepx_model::NativeAbsolutePath::UnixBytes(b) => {
                PathBuf::from(std::ffi::OsString::from_vec(b.clone()))
            }
            _ => return Err("wrong_native_path".into()),
        }
    };
    #[cfg(windows)]
    let mut p = {
        use std::os::windows::ffi::OsStringExt;
        match root {
            sweepx_model::NativeAbsolutePath::WindowsUtf16(u) => {
                PathBuf::from(std::ffi::OsString::from_wide(u))
            }
            _ => return Err("wrong_native_path".into()),
        }
    };
    if l.entry.entry_id != l.scan_root.entry_id {
        for c in l.parent_reopen_recipe.iter().skip(1).chain([&l.entry]) {
            c.native_basename
                .validate_basename_for_current_platform()
                .map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                let NativeName::UnixBytes(b) = &c.native_basename else {
                    return Err("wrong_native_name".into());
                };
                p.push(std::ffi::OsString::from_vec(b.clone()));
            }
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStringExt;
                let NativeName::WindowsUtf16(u) = &c.native_basename else {
                    return Err("wrong_native_name".into());
                };
                p.push(std::ffi::OsString::from_wide(u));
            }
        }
    }
    Ok(p)
}

fn reserve_lineage(ids: &mut DetailEntryIdAllocator, parent: &ScannedEntry) -> Result<(), String> {
    let l = parent
        .executable_native_locator()
        .map_err(|e| e.to_string())?
        .ok_or("missing_locator")?;
    for c in std::iter::once(&l.scan_root)
        .chain(l.parent_reopen_recipe.iter())
        .chain([&l.entry])
    {
        ids.reserve(&c.entry_id).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Reconstruct only the parent already captured in the file's validated native lineage. This is
// not admission from a display path: observe_child reopens and checks every captured component.
pub(super) fn captured_parent(file: &ScannedEntry) -> Result<ScannedEntry, String> {
    let locator = file
        .executable_native_locator()
        .map_err(|e| e.to_string())?
        .ok_or("missing_locator")?;
    let parent = locator
        .parent_reopen_recipe
        .last()
        .ok_or("file_parent_not_captured")?
        .clone();
    if parent.object_type != sweepx_model::ObjectType::Directory {
        return Err("parent_not_directory".into());
    }
    let mut directory = file.clone();
    directory.identity = Some(ScanObjectIdentity {
        entry_id: parent.entry_id.clone(),
        scan_root_id: locator.scan_root.entry_id.clone(),
        parent_id: parent.parent_id.clone(),
        platform_file_identity: parent.platform_file_identity.clone(),
        filesystem_object_domain_identity: parent.filesystem_object_domain_identity.clone(),
        volume_or_mount_identity: parent.volume_or_mount_identity.clone(),
    });
    let mut lineage = locator.clone();
    lineage.parent_reopen_recipe.pop();
    lineage.entry = parent.clone();
    directory.native_locator = Some(lineage);
    directory.object_type = sweepx_model::ObjectType::Directory;
    directory.native_basename = parent.native_basename;
    directory.metadata_fingerprint = parent.metadata_fingerprint;
    directory.logical_bytes =
        sweepx_platform::unknown_u128(sweepx_model::ReasonCode::UnknownIdentity);
    directory.allocated_bytes = directory.logical_bytes.clone();
    directory.reclaimable_estimate = directory.logical_bytes.clone();
    directory.hard_link_count = None;
    directory.display_path = path(&directory)?.display().to_string();
    Ok(directory)
}
