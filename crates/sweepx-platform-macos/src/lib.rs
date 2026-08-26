use std::path::Path;

use sweepx_model::NativeName;
use sweepx_platform::{
    CancellationToken, DirectoryEntryRecord, EntryMetadata, PlatformError, PlatformScanner,
    RootAdmission, ScanRoot, WalkEntry,
};

#[derive(Debug, Default, Clone)]
pub struct MacosPlatformScanner;

impl MacosPlatformScanner {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformScanner for MacosPlatformScanner {
    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn admit_root(
        &self,
        _root: &ScanRoot,
        _cancel: &CancellationToken,
    ) -> Result<RootAdmission, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is not implemented on this host".to_string(),
        ))
    }

    fn read_dir_entries(
        &self,
        _path: &Path,
        _cancel: &CancellationToken,
        _max_entries: usize,
    ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is not implemented on this host".to_string(),
        ))
    }

    fn stat_entry(
        &self,
        _path: &Path,
        _file_name: NativeName,
        _cancel: &CancellationToken,
    ) -> Result<WalkEntry, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is not implemented on this host".to_string(),
        ))
    }

    fn is_same_mount(
        &self,
        _root: &EntryMetadata,
        _entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is not implemented on this host".to_string(),
        ))
    }
}
