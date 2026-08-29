use std::ffi::OsStr;
use std::fs::Metadata;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;

use serde_json::json;
use sweepx_core::OutputFormat;
use sweepx_i18n::Locale;
#[cfg(unix)]
use sweepx_model::IdentityEvidence;
use sweepx_model::{NativeAbsolutePath, NativeName, ObjectType, ScannedEntry};

pub(crate) fn run_cli_trash(
    raw_path: &OsStr,
    format: OutputFormat,
    locale: Locale,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    let path = PathBuf::from(raw_path);
    let candidate = match TrashCandidate::capture(path, None) {
        Ok(candidate) => candidate,
        Err(error) => return print_result(format, locale, None, Err(error)),
    };
    if format != OutputFormat::Human || !stdin_is_terminal {
        return print_result(
            format,
            locale,
            Some(candidate.path()),
            Err(TrashError::ConfirmationRequired),
        );
    }
    if !confirm(candidate.path(), locale) {
        return print_cancelled(format, locale, candidate.path());
    }
    let path = candidate.path().to_path_buf();
    print_result(format, locale, Some(&path), candidate.submit())
}

pub(crate) fn run_tui_trash(entry: &ScannedEntry, locale: Locale) -> ProcessExitCode {
    let candidate = match TrashCandidate::from_scanned_entry(entry) {
        Ok(candidate) => candidate,
        Err(error) => return print_result(OutputFormat::Human, locale, None, Err(error)),
    };
    if !io::stdin().is_terminal() || !confirm(candidate.path(), locale) {
        return print_cancelled(OutputFormat::Human, locale, candidate.path());
    }
    let path = candidate.path().to_path_buf();
    print_result(OutputFormat::Human, locale, Some(&path), candidate.submit())
}

#[derive(Debug)]
struct TrashCandidate {
    path: PathBuf,
    metadata: Metadata,
}

impl TrashCandidate {
    fn capture(path: PathBuf, expected: Option<&ScannedEntry>) -> Result<Self, TrashError> {
        #[cfg(unix)]
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        if unsafe { libc::geteuid() } == 0 {
            return Err(TrashError::ElevatedRuntime);
        }
        if !path.is_absolute() || path.parent().is_none() || path.file_name().is_none() {
            return Err(TrashError::InvalidPath);
        }
        if protected_path(&path) {
            return Err(TrashError::ProtectedPath);
        }
        let metadata = std::fs::symlink_metadata(&path).map_err(TrashError::Inspect)?;
        if metadata.file_type().is_symlink()
            || !(metadata.is_file() || metadata.is_dir())
            || expected.is_some_and(|entry| {
                !matches!(entry.object_type, ObjectType::File | ObjectType::Directory)
            })
        {
            return Err(TrashError::UnsupportedType);
        }
        if let Some(entry) = expected {
            verify_scanned_identity(entry, &metadata)?;
        }
        Ok(Self { path, metadata })
    }

    fn from_scanned_entry(entry: &ScannedEntry) -> Result<Self, TrashError> {
        let path = path_from_live_locator(entry)?;
        Self::capture(path, Some(entry))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn submit(self) -> Result<(), TrashError> {
        let current = std::fs::symlink_metadata(&self.path).map_err(TrashError::Inspect)?;
        if !same_file(&self.metadata, &current) {
            return Err(TrashError::Changed);
        }
        trash::delete(&self.path).map_err(|error| TrashError::Backend(error.to_string()))?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(TrashError::OutcomeUnknown),
        }
    }
}

#[derive(Debug)]
enum TrashError {
    InvalidPath,
    #[cfg(unix)]
    ElevatedRuntime,
    ProtectedPath,
    UnsupportedType,
    ConfirmationRequired,
    MissingLiveIdentity,
    Changed,
    Inspect(io::Error),
    Backend(String),
    OutcomeUnknown,
}

impl std::fmt::Display for TrashError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => formatter.write_str("path must be an absolute non-root path"),
            #[cfg(unix)]
            Self::ElevatedRuntime => {
                formatter.write_str("Trash preview is disabled for an elevated/root process")
            }
            Self::ProtectedPath => formatter.write_str(
                "the selected path is a protected system, home, state, or Trash root",
            ),
            Self::UnsupportedType => {
                formatter.write_str("only regular files and real directories can be trashed")
            }
            Self::ConfirmationRequired => {
                formatter.write_str("interactive terminal confirmation is required")
            }
            Self::MissingLiveIdentity => formatter.write_str(
                "the selected row has no executable live locator or its identity no longer matches",
            ),
            Self::Changed => formatter.write_str("the selected filesystem object changed before submission"),
            Self::Inspect(error) => write!(formatter, "cannot inspect target: {error}"),
            Self::Backend(error) => write!(formatter, "operating-system Trash rejected the item: {error}"),
            Self::OutcomeUnknown => formatter.write_str(
                "Trash returned success but the source path still exists; inspect the Trash before retrying",
            ),
        }
    }
}

fn protected_path(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from)
        && path == home
    {
        return true;
    }
    #[cfg(unix)]
    let protected_exact: Vec<PathBuf> = ["/bin", "/home", "/tmp", "/var"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    #[cfg(not(unix))]
    let protected_exact: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    let mut protected_trees: Vec<PathBuf> = [
        "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys",
        "/usr",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    #[cfg(not(unix))]
    let mut protected_trees: Vec<PathBuf> = Vec::new();
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from) {
        protected_trees.push(state_home.join("sweepx"));
    } else if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        protected_trees.push(home.join(".local/state/sweepx"));
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        protected_trees.push(data_home.join("Trash"));
    } else if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        protected_trees.push(home.join(".local/share/Trash"));
    }
    protected_exact.iter().any(|protected| path == protected)
        || protected_trees
            .iter()
            .any(|protected| path.starts_with(protected))
}

fn confirm(path: &Path, locale: Locale) -> bool {
    let prompt = match locale {
        Locale::ZhCn => format!("将 {} 移到系统回收站？[y/N] ", path.display()),
        Locale::EnUs => format!(
            "Move {} to the operating-system Trash? [y/N] ",
            path.display()
        ),
    };
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).is_ok()
        && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn path_from_live_locator(entry: &ScannedEntry) -> Result<PathBuf, TrashError> {
    let locator = entry
        .executable_native_locator()
        .map_err(|_| TrashError::MissingLiveIdentity)?
        .ok_or(TrashError::MissingLiveIdentity)?;
    if locator.entry == locator.scan_root {
        return Err(TrashError::InvalidPath);
    }
    let root = locator
        .scan_root_absolute_path
        .as_ref()
        .ok_or(TrashError::MissingLiveIdentity)?;
    let mut path = native_absolute_path(root)?;
    for component in locator.parent_reopen_recipe.iter().skip(1) {
        path.push(native_name(&component.native_basename)?);
    }
    path.push(native_name(&locator.entry.native_basename)?);
    Ok(path)
}

#[cfg(unix)]
fn native_absolute_path(path: &NativeAbsolutePath) -> Result<PathBuf, TrashError> {
    use std::os::unix::ffi::OsStringExt;
    match path {
        NativeAbsolutePath::UnixBytes(bytes) => {
            Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.clone())))
        }
        NativeAbsolutePath::WindowsUtf16(_) => Err(TrashError::MissingLiveIdentity),
    }
}

#[cfg(windows)]
fn native_absolute_path(path: &NativeAbsolutePath) -> Result<PathBuf, TrashError> {
    use std::os::windows::ffi::OsStringExt;
    match path {
        NativeAbsolutePath::WindowsUtf16(units) => {
            Ok(PathBuf::from(std::ffi::OsString::from_wide(units)))
        }
        NativeAbsolutePath::UnixBytes(_) => Err(TrashError::MissingLiveIdentity),
    }
}

#[cfg(unix)]
fn native_name(name: &NativeName) -> Result<std::ffi::OsString, TrashError> {
    use std::os::unix::ffi::OsStringExt;
    match name {
        NativeName::UnixBytes(bytes) => Ok(std::ffi::OsString::from_vec(bytes.clone())),
        NativeName::WindowsUtf16(_) => Err(TrashError::MissingLiveIdentity),
    }
}

#[cfg(windows)]
fn native_name(name: &NativeName) -> Result<std::ffi::OsString, TrashError> {
    use std::os::windows::ffi::OsStringExt;
    match name {
        NativeName::WindowsUtf16(units) => Ok(std::ffi::OsString::from_wide(units)),
        NativeName::UnixBytes(_) => Err(TrashError::MissingLiveIdentity),
    }
}

#[cfg(unix)]
fn verify_scanned_identity(entry: &ScannedEntry, metadata: &Metadata) -> Result<(), TrashError> {
    use std::os::unix::fs::MetadataExt;
    let identity = entry
        .validated_identity()
        .map_err(|_| TrashError::MissingLiveIdentity)?
        .ok_or(TrashError::MissingLiveIdentity)?;
    let IdentityEvidence::Known { value } = &identity.platform_file_identity else {
        return Err(TrashError::MissingLiveIdentity);
    };
    if value.device.0 != u128::from(metadata.dev()) || value.inode.0 != u128::from(metadata.ino()) {
        return Err(TrashError::Changed);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_scanned_identity(_entry: &ScannedEntry, _metadata: &Metadata) -> Result<(), TrashError> {
    // The executable locator has already proved a Windows-native identity chain. A dedicated
    // handle-relative Windows mutation adapter will replace this conservative preview seam.
    Ok(())
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.file_type() == after.file_type()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
}

#[cfg(windows)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.file_type() == after.file_type()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
}

fn print_result(
    format: OutputFormat,
    locale: Locale,
    path: Option<&Path>,
    result: Result<(), TrashError>,
) -> ProcessExitCode {
    let path_text = path.map(|path| path.display().to_string());
    match result {
        Ok(()) => {
            if format == OutputFormat::Human {
                println!(
                    "{}",
                    match locale {
                        Locale::ZhCn => format!(
                            "已移到系统回收站：{}\n可通过桌面环境的回收站恢复。",
                            path_text.as_deref().unwrap_or("-")
                        ),
                        Locale::EnUs => format!(
                            "Moved to the operating-system Trash: {}\nRestore it from your desktop Trash.",
                            path_text.as_deref().unwrap_or("-")
                        ),
                    }
                );
            } else {
                println!(
                    "{}",
                    json!({
                        "schema": "sweepx.trash.result/v1",
                        "status": "ok",
                        "exitCode": 0,
                        "path": path_text,
                        "recoverable": true,
                        "permanentFallback": false,
                    })
                );
            }
            ProcessExitCode::SUCCESS
        }
        Err(error) => {
            if format == OutputFormat::Human {
                eprintln!(
                    "{}",
                    match locale {
                        Locale::ZhCn => format!("未移动到回收站：{error}"),
                        Locale::EnUs => format!("Not moved to Trash: {error}"),
                    }
                );
            } else {
                println!(
                    "{}",
                    json!({
                        "schema": "sweepx.trash.result/v1",
                        "status": "failed",
                        "exitCode": 8,
                        "path": path_text,
                        "recoverable": false,
                        "permanentFallback": false,
                        "error": error.to_string(),
                    })
                );
            }
            ProcessExitCode::from(8)
        }
    }
}

fn print_cancelled(format: OutputFormat, locale: Locale, path: &Path) -> ProcessExitCode {
    if format == OutputFormat::Human {
        println!(
            "{}",
            match locale {
                Locale::ZhCn => "已取消；文件未改动。",
                Locale::EnUs => "Cancelled; no files were changed.",
            }
        );
    } else {
        println!(
            "{}",
            json!({
                "schema": "sweepx.trash.result/v1",
                "status": "cancelled",
                "exitCode": 0,
                "path": path.display().to_string(),
                "recoverable": false,
                "permanentFallback": false,
            })
        );
    }
    ProcessExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_roots_include_filesystem_home_state_and_trash() {
        assert!(protected_path(Path::new("/")));
        #[cfg(unix)]
        {
            assert!(protected_path(Path::new("/etc")));
            assert!(protected_path(Path::new("/tmp")));
        }
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            assert!(protected_path(&home));
            assert!(protected_path(&home.join(".local/state/sweepx")));
            assert!(protected_path(&home.join(".local/share/Trash")));
        }
    }

    #[test]
    fn ordinary_descendants_are_not_confused_with_protected_roots() {
        assert!(!protected_path(Path::new("/tmp/sweepx-preview-item")));
    }

    #[test]
    fn protected_trees_include_descendants() {
        #[cfg(unix)]
        assert!(protected_path(Path::new("/etc/sweepx-preview-item")));
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            assert!(protected_path(
                &home.join(".local/share/Trash/files/already-trashed")
            ));
        }
    }
}
