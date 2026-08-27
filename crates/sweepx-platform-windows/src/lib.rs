use sweepx_platform::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryMetadata, PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry,
};

/// Fail-closed placeholder for a Windows directory capability.
///
/// The current scanner contract can carry a retained directory handle, but this backend does not
/// yet implement the handle-relative Win32/NT enumeration and child-open operations required to
/// construct one safely. In particular, reopening a directory or child by path would permit a
/// reparse-point swap between validation and use.
#[derive(Debug)]
pub struct WindowsUnavailableDirectory;

#[derive(Debug, Default, Clone)]
pub struct WindowsPlatformScanner;

impl WindowsPlatformScanner {
    pub fn new() -> Self {
        Self
    }

    fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
        if cancel.is_cancelled() {
            return Err(PlatformError::Cancelled);
        }
        Ok(())
    }

    fn unsupported() -> PlatformError {
        PlatformError::Unsupported(
            "Windows scanning is disabled until root admission, enumeration, and child inspection are implemented entirely through retained no-follow directory handles"
                .to_string(),
        )
    }
}

impl PlatformScanner for WindowsPlatformScanner {
    type DirectoryHandle = WindowsUnavailableDirectory;

    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn admit_root(
        &self,
        _root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;
        Err(Self::unsupported())
    }

    fn enumerate_children(
        &self,
        _directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        _limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;
        Err(Self::unsupported())
    }

    fn inspect_child(
        &self,
        _parent: &Self::DirectoryHandle,
        _child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        Self::ensure_not_cancelled(cancel)?;
        Err(Self::unsupported())
    }

    fn is_same_mount(
        &self,
        _root: &EntryMetadata,
        _entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        Err(Self::unsupported())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sweepx_model::NativeName;

    use super::*;

    fn absolute_test_root() -> ScanRoot {
        ScanRoot::new(std::env::current_dir().expect("current directory is available"))
            .expect("current directory is absolute")
    }

    #[test]
    fn identifies_as_windows_backend() {
        assert_eq!(WindowsPlatformScanner::new().platform_name(), "windows");
    }

    #[test]
    fn cancellation_takes_precedence_over_unsupported_root_admission() {
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert!(matches!(
            WindowsPlatformScanner::new().admit_root(&absolute_test_root(), &cancel),
            Err(PlatformError::Cancelled)
        ));
    }

    #[test]
    fn root_admission_fails_closed_without_reopening_a_path() {
        assert!(matches!(
            WindowsPlatformScanner::new()
                .admit_root(&absolute_test_root(), &CancellationToken::new()),
            Err(PlatformError::Unsupported(_))
        ));
    }

    #[test]
    fn enumeration_fails_closed_without_reopening_a_path() {
        let mut directory = WindowsUnavailableDirectory;
        assert!(matches!(
            WindowsPlatformScanner::new().enumerate_children(
                &mut directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 16,
                    max_batch_bytes: 4096,
                },
            ),
            Err(PlatformError::Unsupported(_))
        ));
    }

    #[test]
    fn child_inspection_fails_closed_without_reopening_a_path() {
        let child = DirectoryEntryRecord {
            path: PathBuf::from("child"),
            file_name: NativeName::windows_utf16("child".encode_utf16().collect::<Vec<_>>()),
        };

        assert!(matches!(
            WindowsPlatformScanner::new().inspect_child(
                &WindowsUnavailableDirectory,
                &child,
                &CancellationToken::new(),
            ),
            Err(PlatformError::Unsupported(_))
        ));
    }
}
