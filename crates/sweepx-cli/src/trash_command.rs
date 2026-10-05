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
    // Ordinary targets move straight to the recoverable Trash. Only important/common directories
    // require an interactive confirmation, and there is no confirmation available outside a human
    // terminal, so such a path is refused to a non-interactive or scripted caller instead.
    if candidate.requires_confirmation() {
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
    }
    let path = candidate.path().to_path_buf();
    print_result(format, locale, Some(&path), candidate.submit())
}

pub(crate) fn run_tui_trash(entry: &ScannedEntry, locale: Locale) -> ProcessExitCode {
    let candidate = match TrashCandidate::from_scanned_entry(entry) {
        Ok(candidate) => candidate,
        Err(error) => return print_result(OutputFormat::Human, locale, None, Err(error)),
    };
    // A selected cache row is ordinary and moves immediately; important directories still confirm.
    if candidate.requires_confirmation()
        && (!io::stdin().is_terminal() || !confirm(candidate.path(), locale))
    {
        return print_cancelled(OutputFormat::Human, locale, candidate.path());
    }
    let path = candidate.path().to_path_buf();
    print_result(OutputFormat::Human, locale, Some(&path), candidate.submit())
}

/// Worker-only selected junk mutation. No printing or terminal confirmation occurs here.
/// Important/common paths are refused rather than blocking a background worker on stdin.
/// Binding checks retain the scanner's no-follow and mount boundaries; the existing OS Trash
/// preview still has a pathname race between its final checks and the system call.
pub(crate) fn trash_session_candidate(
    row: &sweepx_core::junk::session::JunkSessionCandidate,
    cancel: &sweepx_core::CancellationToken,
) -> Result<(), String> {
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    if let Some(blocker) = row.candidate.project_execution_blocker() {
        return Err(blocker.into());
    }
    let aggregate = row
        .directory_aggregate()
        .ok_or_else(|| "temporary objects require independent quarantine preview".to_string())?;
    let entry = row
        .candidate
        .source_entry
        .as_ref()
        .ok_or_else(|| "native source unavailable".to_string())?;
    if !entry.coverage.complete
        || entry.coverage.details_lost
        || !aggregate.coverage.complete
        || aggregate.coverage.details_lost
    {
        return Err("candidate coverage incomplete".into());
    }
    row.revalidate_native_binding(cancel, sweepx_platform::ScanResourceLimits::default())
        .map_err(|failure| format!("{}: {}", failure.code, failure.detail))?;
    let candidate = TrashCandidate::from_scanned_entry(entry).map_err(|error| error.to_string())?;
    if candidate.requires_confirmation() {
        return Err(TrashError::ConfirmationRequired.to_string());
    }
    #[cfg(windows)]
    {
        // capture()'s identity must agree with the selected scanner row, not merely with a new
        // object that happens to occupy the path between revalidation and capture.
        let identity = entry
            .validated_identity()
            .ok()
            .flatten()
            .and_then(|identity| match &identity.platform_file_identity {
                sweepx_model::IdentityEvidence::Known { value } => Some(value),
                _ => None,
            })
            .ok_or_else(|| TrashError::MissingLiveIdentity.to_string())?;
        if !candidate.identity.as_ref().is_some_and(|current| {
            identity.device.0 == u128::from(current.device()) && identity.inode.0 == current.inode()
        }) {
            return Err(TrashError::Changed.to_string());
        }
    }
    row.revalidate_native_binding(cancel, sweepx_platform::ScanResourceLimits::default())
        .map_err(|failure| format!("{}: {}", failure.code, failure.detail))?;
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    candidate.submit().map_err(|error| error.to_string())
}

/// Explicit file selection is independent of junk rules. Worker-only native validation uses
/// the existing provider-safe metadata-only stream and current OS Trash adapter. Expected
/// content stamps protect duplicate choices; neither a path label nor file size authorizes IO.
pub(crate) fn trash_observed_file(
    entry: &ScannedEntry,
    stamp: Option<&sweepx_platform::RegularFileObservation>,
    keeper: Option<(&ScannedEntry, &sweepx_platform::RegularFileObservation)>,
    cancel: &sweepx_core::CancellationToken,
) -> Result<(), String> {
    let reader = sweepx_scanner::DetailRescanner::new(
        sweepx_scanner::HostPlatformScanner::new(),
        sweepx_platform::ScanResourceLimits::default(),
    );
    let check = |entry, previous| {
        reader
            .stream_file(
                sweepx_scanner::FileContentRequest {
                    entry,
                    offset: 0,
                    max_bytes: 0,
                    previous,
                },
                cancel,
                &mut |_| unreachable!("metadata-only validation"),
            )
            .map_err(|error| error.to_string())
    };
    if entry.object_type != ObjectType::File
        || !entry.coverage.complete
        || entry.coverage.details_lost
    {
        return Err("refresh complete ordinary-file observations first".into());
    }
    let live = check(entry, stamp)?;
    let candidate = TrashCandidate::from_scanned_entry(entry).map_err(|error| error.to_string())?;
    if candidate.requires_confirmation() {
        return Err(TrashError::ConfirmationRequired.to_string());
    }
    #[cfg(windows)]
    {
        let expected = entry
            .identity
            .as_ref()
            .and_then(|identity| match &identity.platform_file_identity {
                sweepx_model::IdentityEvidence::Known { value } => Some(value),
                _ => None,
            })
            .ok_or_else(|| TrashError::MissingLiveIdentity.to_string())?;
        if !candidate.identity.as_ref().is_some_and(|actual| {
            expected.device.0 == u128::from(actual.device()) && expected.inode.0 == actual.inode()
        }) {
            return Err(TrashError::Changed.to_string());
        }
    }
    if let Some((keeper, stamp)) = keeper {
        check(keeper, Some(stamp))?;
    }
    check(entry, Some(&live.observed_after))?;
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    candidate.submit().map_err(|error| error.to_string())
}

/// One candidate in a bulk junk-to-Trash plan.
pub(crate) struct BulkTrashItem<'a> {
    /// Display path, shown in the plan only.
    pub(crate) path: String,
    /// Classified rule id, shown for attribution.
    pub(crate) rule_id: String,
    /// Logical bytes measured by the scan.
    pub(crate) size: u128,
    /// Retained scanned row carrying the executable native locator.
    pub(crate) entry: &'a ScannedEntry,
    /// True when the directory aggregate reports complete coverage. Ineligible items are
    /// surfaced as skipped rather than moved.
    pub(crate) eligible: bool,
    /// Current rule's independent project execution restriction, even with complete traversal.
    pub(crate) project_blocker: Option<&'static str>,
}

/// Moves a classified junk set to the operating-system Trash without a confirmation round-trip.
///
/// The targets were already classified as rebuildable/disposable during the walk, and each goes
/// through [`TrashCandidate::from_scanned_entry`], which revalidates native identity immediately
/// before the move, so a stale row is skipped rather than trashing a replacement object. An
/// item classified as an important/common user directory is never auto-moved by a bulk plan even
/// if a rule produced it; it is reported as guarded. One item failing does not stop the others; the
/// summary names every failure. Permanent deletion is never used as a fallback.
///
/// The plan is listed for transparency, but — unlike a destructive, unrecoverable action — it is
/// not typed back: the operating-system Trash is itself reversible, and the protected/important
/// guards plus identity revalidation are the safety boundary. Requiring an exact digest for every
/// routine cache cleanup made the command effectively unusable.
pub(crate) fn run_bulk_trash(locale: Locale, items: Vec<BulkTrashItem<'_>>) -> ProcessExitCode {
    let eligible: Vec<_> = items
        .iter()
        .filter(|item| item.eligible && item.project_blocker.is_none())
        .collect();
    let skipped: Vec<_> = items
        .iter()
        .filter(|item| !item.eligible || item.project_blocker.is_some())
        .collect();
    if eligible.is_empty() {
        eprintln!(
            "{}",
            match locale {
                Locale::ZhCn => "没有满足当前规则约束且覆盖完整的回收候选。",
                Locale::EnUs =>
                    "No candidate meets current rule and complete-coverage requirements for Trash.",
            }
        );
        return ProcessExitCode::from(8);
    }

    let total = eligible
        .iter()
        .fold(0u128, |sum, item| sum.saturating_add(item.size));
    print_bulk_intent(locale, eligible.len(), skipped.len(), total, &eligible);

    let mut moved = 0usize;
    let mut moved_bytes = 0u128;
    let mut guarded = 0usize;
    let mut failures: Vec<(String, TrashError)> = Vec::new();
    for item in eligible {
        // Capture and revalidate this exact row; submit re-checks identity a final time.
        match TrashCandidate::from_scanned_entry(item.entry) {
            Ok(candidate) => {
                // Defense in depth: a bulk, zero-confirmation move must never sweep an important
                // user directory, even if a classifier ever names one.
                if candidate.requires_confirmation() {
                    guarded += 1;
                    continue;
                }
                match candidate.submit() {
                    Ok(()) => {
                        moved += 1;
                        moved_bytes = moved_bytes.saturating_add(item.size);
                    }
                    Err(error) => failures.push((item.path.clone(), error)),
                }
            }
            Err(error) => failures.push((item.path.clone(), error)),
        }
    }
    print_bulk_result(
        locale,
        moved,
        moved_bytes,
        skipped.len(),
        guarded,
        &failures,
    );
    // Partial completion is a distinct exit from full success.
    if failures.is_empty() && skipped.is_empty() && guarded == 0 {
        ProcessExitCode::SUCCESS
    } else {
        ProcessExitCode::from(4)
    }
}

fn print_bulk_intent(
    locale: Locale,
    count: usize,
    skipped: usize,
    total: u128,
    items: &[&BulkTrashItem<'_>],
) {
    match locale {
        Locale::ZhCn => {
            println!("移到系统回收站");
            println!("  候选：{count} 个；跳过（覆盖或项目执行证据不足）：{skipped} 个");
            println!("  已统计逻辑大小：{total} 字节");
            println!("  模式：系统回收站；可恢复；不永久删除；无需再确认");
            for item in items {
                println!("    {} [{}]", item.path, item.rule_id);
            }
        }
        Locale::EnUs => {
            println!("Moving to the operating-system Trash");
            println!(
                "  candidates: {count}; skipped (incomplete coverage or project execution evidence): {skipped}"
            );
            println!("  accounted logical size: {total} bytes");
            println!(
                "  mode: operating-system Trash; recoverable; never permanent; no further prompt"
            );
            for item in items {
                println!("    {} [{}]", item.path, item.rule_id);
            }
        }
    }
}

fn print_bulk_result(
    locale: Locale,
    moved: usize,
    moved_bytes: u128,
    skipped: usize,
    guarded: usize,
    failures: &[(String, TrashError)],
) {
    match locale {
        Locale::ZhCn => {
            println!("已移到回收站：{moved} 个，{moved_bytes} 字节。");
            if skipped > 0 {
                println!("跳过（覆盖或项目执行证据不足）：{skipped} 个。");
            }
            if guarded > 0 {
                println!("未自动删除重要目录：{guarded} 个（如需删除请单独使用 trash 命令）。");
            }
            for (path, error) in failures {
                eprintln!("未移动 {}：{error}", path);
            }
        }
        Locale::EnUs => {
            println!("Moved to Trash: {moved} items ({moved_bytes} bytes).");
            if skipped > 0 {
                println!("Skipped (incomplete coverage or project execution evidence): {skipped}.");
            }
            if guarded > 0 {
                println!(
                    "Important directories not auto-removed: {guarded} (use the trash command on one explicitly)."
                );
            }
            for (path, error) in failures {
                eprintln!("Not moved {}: {error}", path);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct TrashCandidate {
    path: PathBuf,
    metadata: Metadata,
    /// True when the target is an important/common user directory that needs an explicit
    /// confirmation before it is moved. System directories are refused earlier instead.
    important: bool,
    /// Native identity observed at capture time, revalidated immediately before the Trash call.
    ///
    /// Held separately from `metadata` because `std::fs::Metadata` cannot express a Windows file id
    /// on stable Rust, and identity — not size or timestamp — is what makes the target the same
    /// object.
    #[cfg(windows)]
    identity: Option<sweepx_platform::EntryIdentity>,
}

impl TrashCandidate {
    pub(crate) fn capture(
        path: PathBuf,
        expected: Option<&ScannedEntry>,
    ) -> Result<Self, TrashError> {
        #[cfg(unix)]
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        if unsafe { libc::geteuid() } == 0 {
            return Err(TrashError::ElevatedRuntime);
        }
        if !path.is_absolute() || path.parent().is_none() || path.file_name().is_none() {
            return Err(TrashError::InvalidPath);
        }
        #[cfg(target_os = "macos")]
        // trash-rs's Foundation adapter percent-encodes non-UTF-8 path bytes as a different
        // NSString pathname. Refuse that spelling before it can select an unrelated object.
        if path.to_str().is_none() {
            return Err(TrashError::UnsupportedPathEncoding);
        }
        // This is the safety boundary for the zero-confirmation path: system directories are
        // refused outright, while important/common directories are flagged for confirmation.
        let important = match classify_path_safety(&path) {
            PathSafety::Protected => return Err(TrashError::ProtectedPath),
            PathSafety::Important => true,
            PathSafety::Ordinary => false,
        };
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
        #[cfg(windows)]
        let identity = sweepx_platform::windows::read_live_identity(&path)
            .map_err(TrashError::Inspect)?
            .map(Some)
            // A path that resolved a moment ago but has no readable identity is refused below
            // rather than treated as identifiable.
            .unwrap_or(None);
        Ok(Self {
            path,
            metadata,
            important,
            #[cfg(windows)]
            identity,
        })
    }

    /// Captures the exact native scanner object, independently of its display spelling.
    /// Callers revalidate directory lineage and application facts before this final Trash seam.
    pub(crate) fn from_scanned_entry(entry: &ScannedEntry) -> Result<Self, TrashError> {
        let path = path_from_live_locator(entry)?;
        Self::capture(path, Some(entry))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Whether the caller must obtain an explicit confirmation before moving this target.
    pub(crate) fn requires_confirmation(&self) -> bool {
        self.important
    }

    pub(crate) fn submit(self) -> Result<(), TrashError> {
        let current = std::fs::symlink_metadata(&self.path).map_err(TrashError::Inspect)?;
        if !same_file(&self.metadata, &current) {
            return Err(TrashError::Changed);
        }
        // Identity is checked last and closest to the mutation: the window between this check and
        // the OS Trash call is the only one left, and no cheaper comparison can stand in for it.
        #[cfg(windows)]
        if !same_object(self.identity.as_ref(), &self.path) {
            return Err(TrashError::Changed);
        }
        move_to_system_trash(&self.path).map_err(|error| TrashError::Backend {
            detail: error.to_string(),
            cross_filesystem_linux: linux_cross_filesystem_trash(&self.path),
        })?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(TrashError::OutcomeUnknown),
        }
    }
}

/// Selects the platform adapter without a permanent-delete or secondary-adapter fallback.
/// macOS uses Foundation directly: Finder's AppleScript can wait indefinitely for automation
/// authorization or its service. Foundation's system call is still synchronous and cannot be
/// hard-cancelled; callers must not claim cancellation proves that a move did not happen.
/// Some macOS versions omit Finder's Put Back action; recovery by moving out of Trash remains.
fn move_to_system_trash(path: &Path) -> Result<(), trash::Error> {
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        let mut context = trash::TrashContext::new();
        context.set_delete_method(DeleteMethod::NsFileManager);
        context.delete(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        trash::delete(path)
    }
}

#[derive(Debug)]
pub(crate) enum TrashError {
    InvalidPath,
    #[cfg(target_os = "macos")]
    UnsupportedPathEncoding,
    #[cfg(unix)]
    ElevatedRuntime,
    ProtectedPath,
    UnsupportedType,
    ConfirmationRequired,
    MissingLiveIdentity,
    Changed,
    Inspect(io::Error),
    Backend {
        detail: String,
        cross_filesystem_linux: bool,
    },
    OutcomeUnknown,
}

impl std::fmt::Display for TrashError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => formatter.write_str("path must be an absolute non-root path"),
            #[cfg(target_os = "macos")]
            Self::UnsupportedPathEncoding => formatter.write_str(
                "the macOS Trash adapter requires a lossless UTF-8 pathname",
            ),
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
            Self::Backend {
                detail,
                cross_filesystem_linux: true,
            } => write!(
                formatter,
                "operating-system Trash rejected the item: {detail}. On Linux this item is on a different filesystem from the desktop Trash. Cross-filesystem Trash normally requires a usable per-volume Trash on the source mount (for /tmp on the root filesystem, typically /.Trash-UID), so the desktop Trash can exist while this path remains unsupported"
            ),
            Self::Backend { detail, .. } => {
                write!(formatter, "operating-system Trash rejected the item: {detail}")
            }
            Self::OutcomeUnknown => formatter.write_str(
                "Trash returned success but the source path still exists; inspect the Trash before retrying",
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_cross_filesystem_trash(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let source = std::fs::symlink_metadata(path).ok();
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local/share"))
        });
    let trash = data_home.and_then(|data_home| std::fs::symlink_metadata(data_home).ok());
    matches!((source, trash), (Some(source), Some(trash)) if source.dev() != trash.dev())
}

#[cfg(not(target_os = "linux"))]
fn linux_cross_filesystem_trash(_path: &Path) -> bool {
    false
}

/// Where a path sits relative to the zero-confirmation Trash boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathSafety {
    /// Filesystem/system roots, the home directory, the Trash, and SweepX state. Never moved.
    Protected,
    /// Common directories holding a user's primary files. Moved only after explicit confirmation.
    Important,
    /// Everything else, including every classified cache. Moved to Trash without confirmation.
    Ordinary,
}

/// Classifies a path into the Trash safety tiers.
fn classify_path_safety(path: &Path) -> PathSafety {
    if is_protected_path(path) {
        return PathSafety::Protected;
    }
    // Important directories are matched by exact identity, never as a tree: their ordinary
    // descendants — a cache nested under `~/Library`, a build folder on `~/Desktop` — must stay
    // directly trimmable while the directory that holds a user's files still requires a yes.
    if let Some(home) = user_home_for_safety()
        && important_user_dirs(&home)
            .iter()
            .any(|important| same_path_identity(important, path))
    {
        return PathSafety::Important;
    }
    PathSafety::Ordinary
}

/// The home variable is `HOME` on Unix and `USERPROFILE` on Windows.
#[cfg(unix)]
fn user_home_for_safety() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// The home variable is `HOME` on Unix and `USERPROFILE` on Windows.
#[cfg(windows)]
fn user_home_for_safety() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").map(PathBuf::from)
}

/// Exact-name directories treated as important/common on this platform.
///
/// Names (not full paths) keep the list portable; they are joined to the resolved home. Only these
/// exact directories are guarded, so adding a name never blocks their contents.
#[cfg(target_os = "macos")]
fn important_user_dirs(home: &Path) -> Vec<PathBuf> {
    const NAMES: &[&str] = &[
        "Desktop",
        "Documents",
        "Downloads",
        "Pictures",
        "Movies",
        "Music",
        "Applications",
        "Library",
        ".ssh",
    ];
    NAMES.iter().map(|name| home.join(name)).collect()
}

/// Exact-name directories treated as important/common on this platform.
#[cfg(target_os = "windows")]
fn important_user_dirs(home: &Path) -> Vec<PathBuf> {
    const NAMES: &[&str] = &[
        "Desktop",
        "Documents",
        "Downloads",
        "Pictures",
        "Videos",
        "Music",
        ".ssh",
    ];
    NAMES.iter().map(|name| home.join(name)).collect()
}

/// Exact-name directories treated as important/common on this platform.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn important_user_dirs(home: &Path) -> Vec<PathBuf> {
    const NAMES: &[&str] = &[
        "Desktop",
        "Documents",
        "Downloads",
        "Pictures",
        "Videos",
        "Music",
        ".ssh",
    ];
    NAMES.iter().map(|name| home.join(name)).collect()
}

/// Compares two paths by resolved identity, falling back to literal equality.
///
/// Canonicalization handles case-insensitive volumes and symlinked ancestors (macOS `/var` →
/// `/private/var`); when either side cannot be resolved there is no identity to trust, so exact
/// spelling is the weaker fallback rather than a false match.
fn same_path_identity(left: &Path, right: &Path) -> bool {
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(resolved_left), Ok(resolved_right)) => resolved_left == resolved_right,
        _ => left == right,
    }
}

fn is_protected_path(path: &Path) -> bool {
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
    // The desktop Trash is platform-specific: `~/.local/share/Trash` under the XDG layout, but
    // `~/.Trash` on macOS. Trashing the Trash itself (or something already inside it) is refused.
    #[cfg(not(target_os = "macos"))]
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        protected_trees.push(data_home.join("Trash"));
    } else if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        protected_trees.push(home.join(".local/share/Trash"));
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        protected_trees.push(home.join(".Trash"));
    }
    protected_exact.iter().any(|protected| path == protected)
        || protected_trees
            .iter()
            .any(|protected| path.starts_with(protected))
}

pub(crate) fn confirm(path: &Path, locale: Locale) -> bool {
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

/// Decodes a bounded executable native locator for scope comparison; never uses display paths.
/// This supplies a lossless observation path, not permission to mutate without native revalidation.
pub(crate) fn path_from_live_locator(entry: &ScannedEntry) -> Result<PathBuf, TrashError> {
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

/// Confirms the object at `path` is still the one that was inspected, by native identity.
///
/// Windows previously compared only file type, length and modification time. That is not an identity:
/// a directory's length is reported as zero and its timestamps are writable, so a directory deleted
/// and recreated at the same path — or a junction swapped in — satisfied all three while being a
/// different object. `FILE_ID_INFO` answers the question the comparison was actually asking, and is
/// the same source the scanner records identity from, so both sides of the comparison mean one thing.
///
/// A failure to read the identity is not a match. If the object cannot be identified, the caller must
/// refuse rather than proceed on the strength of a name.
#[cfg(windows)]
fn same_object(before_identity: Option<&sweepx_platform::EntryIdentity>, path: &Path) -> bool {
    let Some(before) = before_identity else {
        return false;
    };
    match sweepx_platform::windows::read_live_identity(path) {
        Ok(Some(current)) => &current == before,
        // Absent or unreadable both mean "cannot prove it is the same object".
        Ok(None) | Err(_) => false,
    }
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

    #[cfg(windows)]
    #[test]
    fn a_directory_swapped_after_capture_is_refused() {
        // The check this replaces compared type, length and modified time. A recreated directory
        // matches all three - length is zero and the timestamp is fresh in both - so it passed while
        // being a different object. Identity is what distinguishes them.
        let dir = std::env::temp_dir().join(format!("sweepx-trash-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let captured = sweepx_platform::windows::read_live_identity(&dir)
            .expect("readable")
            .expect("present");
        assert!(
            same_object(Some(&captured), &dir),
            "an untouched directory is still the same object"
        );

        std::fs::remove_dir_all(&dir).expect("removable");
        std::fs::create_dir_all(&dir).expect("recreatable");
        assert!(
            !same_object(Some(&captured), &dir),
            "a recreated directory must not pass as the captured one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn an_unidentifiable_or_absent_target_is_refused() {
        let missing = std::env::temp_dir().join("sweepx-trash-absent-8c1f");
        let _ = std::fs::remove_dir_all(&missing);
        let any = sweepx_platform::windows::read_live_identity(&std::env::temp_dir())
            .expect("readable")
            .expect("present");

        assert!(
            !same_object(Some(&any), &missing),
            "an absent path cannot be proved to be the captured object"
        );
        assert!(
            !same_object(None, &std::env::temp_dir()),
            "without a captured identity there is nothing to compare against"
        );
    }

    #[test]
    fn protected_roots_include_filesystem_home_state_and_trash() {
        assert_eq!(classify_path_safety(Path::new("/")), PathSafety::Protected);
        #[cfg(unix)]
        {
            assert_eq!(
                classify_path_safety(Path::new("/etc")),
                PathSafety::Protected
            );
            assert_eq!(
                classify_path_safety(Path::new("/tmp")),
                PathSafety::Protected
            );
        }
        if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
            assert_eq!(classify_path_safety(&home), PathSafety::Protected);
            assert_eq!(
                classify_path_safety(&home.join(".local/state/sweepx")),
                PathSafety::Protected
            );
        }
    }

    #[test]
    fn ordinary_paths_are_not_confused_with_guarded_roots() {
        assert_eq!(
            classify_path_safety(Path::new("/tmp/sweepx-preview-item")),
            PathSafety::Ordinary
        );
    }

    // These home-relative Trash layouts exist only on Linux and macOS.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn protected_trees_include_descendants() {
        #[cfg(unix)]
        assert_eq!(
            classify_path_safety(Path::new("/etc/sweepx-preview-item")),
            PathSafety::Protected
        );
        if let Some(home) = user_home_for_safety() {
            // The platform trash and anything already inside it are always protected.
            #[cfg(target_os = "macos")]
            assert_eq!(
                classify_path_safety(&home.join(".Trash/files/already-trashed")),
                PathSafety::Protected
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                classify_path_safety(&home.join(".local/share/Trash/files/already-trashed")),
                PathSafety::Protected
            );
        }
    }

    #[test]
    fn important_dirs_are_guarded_but_their_descendants_are_ordinary() {
        let Some(home) = user_home_for_safety() else {
            return;
        };
        // The exact important directory requires confirmation even if it is absent (the identity
        // helper falls back to literal equality), while anything below it stays zero-confirmation.
        assert_eq!(
            classify_path_safety(&home.join("Documents")),
            PathSafety::Important
        );
        assert_eq!(
            classify_path_safety(&home.join("Documents/rebuildable-cache")),
            PathSafety::Ordinary
        );
        assert_eq!(
            classify_path_safety(&home.join(".ssh")),
            PathSafety::Important
        );
        // The macOS junk scan roots live inside `~/Library`; the directory itself is important but
        // its cache descendants must remain directly trimmable.
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                classify_path_safety(&home.join("Library")),
                PathSafety::Important
            );
            assert_eq!(
                classify_path_safety(&home.join("Library/Caches")),
                PathSafety::Ordinary
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cross_filesystem_trash_error_explains_per_volume_requirement() {
        let error = TrashError::Backend {
            detail: "rejected".to_string(),
            cross_filesystem_linux: true,
        }
        .to_string();
        assert!(error.contains("different filesystem"));
        assert!(error.contains("/.Trash-UID"));
    }
}

#[cfg(test)]
mod project_format_tests {
    use super::*;
    use std::collections::BTreeMap;
    use sweepx_core::junk::{
        JunkService,
        format::{ProjectFormatLimits, ProjectFormatSession, ProjectFormatStatus},
        platform::PlatformJunkEvidence,
    };
    use sweepx_platform::{CancellationToken, ScanRoot};
    use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

    #[test]
    fn legacy_and_generic_project_candidates_are_refused_before_bulk_and_worker_trash() {
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = owner.path().to_path_buf();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        std::fs::write(root.join("package.json"), b"{}\n").unwrap();
        for name in ["target", "dist", "__pycache__"] {
            std::fs::create_dir(root.join(name)).unwrap();
            std::fs::write(
                root.join(name).join("personal-data"),
                b"preserve personal data",
            )
            .unwrap();
        }
        let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();
        let aggregates = summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect::<BTreeMap<_, _>>();
        let service = JunkService::built_in().unwrap();
        for (name, rule, blocker) in [
            ("target", "rust.target", "project_ownership_not_verified"),
            ("dist", "project.build-output", "project_report_only"),
            (
                "__pycache__",
                "python.cache",
                "project_ownership_not_verified",
            ),
        ] {
            let entry = summary
                .entries
                .iter()
                .find(|entry| entry.display_path == root.join(name).display().to_string())
                .unwrap();
            let mut candidate = service
                .interpret(
                    &format!("project:{rule}"),
                    entry,
                    &aggregates,
                    &[],
                    &PlatformJunkEvidence::default(),
                )
                .unwrap();
            // A higher-level consumer's confidence/coverage claims cannot override rule constraints.
            candidate.confidence = Some("high".into());
            candidate.blockers.clear();
            assert!(entry.coverage.complete);
            assert_eq!(candidate.project_execution_blocker(), Some(blocker));
            for locale in [Locale::EnUs, Locale::ZhCn] {
                let code = run_bulk_trash(
                    locale,
                    vec![BulkTrashItem {
                        path: candidate.path.clone(),
                        rule_id: candidate.rule_id.clone(),
                        size: 21,
                        entry,
                        eligible: true,
                        project_blocker: candidate.project_execution_blocker(),
                    }],
                );
                assert_eq!(code, ProcessExitCode::from(8));
            }
            let aggregate = summary
                .aggregates
                .iter()
                .find(|aggregate| aggregate.directory_identity == candidate.entry_id.as_str())
                .unwrap()
                .clone();
            let row = sweepx_core::junk::session::JunkSessionCandidate {
                candidate,
                facts: sweepx_core::junk::session::JunkSessionFacts::Directory(Box::new(aggregate)),
            };
            assert_eq!(
                trash_session_candidate(&row, &CancellationToken::new()).unwrap_err(),
                blocker
            );
            assert_eq!(
                std::fs::read(root.join(name).join("personal-data")).unwrap(),
                b"preserve personal data"
            );
        }
    }

    #[test]
    fn recognized_project_format_is_refused_before_any_bulk_or_worker_trash() {
        for svelte in [false, true] {
            check_recognized_profile_refusal(svelte);
        }
    }

    fn check_recognized_profile_refusal(svelte: bool) {
        #[cfg(target_os = "linux")]
        let owner = tempfile::tempdir_in("/dev/shm").unwrap();
        #[cfg(not(target_os = "linux"))]
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = owner.path().to_path_buf();
        let directory = if svelte { ".svelte-kit" } else { ".dart_tool" };
        std::fs::create_dir(root.join(directory)).unwrap();
        std::fs::write(root.join("pubspec.yaml"), b"name: example\n").unwrap();
        std::fs::write(root.join("svelte.config.js"), "export default {}\n").unwrap();
        let file = root.join(directory).join(if svelte {
            "tsconfig.json"
        } else {
            "package_config.json"
        });
        let dart_bytes = br#"{"configVersion":2,"packages":[{"name":"example","rootUri":"../","packageUri":"lib/"}],"generator":"pub","generatorVersion":"3.6.0"}"#;
        let bytes = if svelte {
            sweepx_fixtures::project_junk::SVELTEKIT2_CONFIG.as_bytes()
        } else {
            dart_bytes.as_slice()
        };
        std::fs::write(&file, bytes).unwrap();
        let ambient = root.join(directory).join("ambient.d.ts");
        if svelte {
            std::fs::write(&ambient, sweepx_fixtures::project_junk::SVELTEKIT_AMBIENT).unwrap();
        }
        let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();
        let entry = summary
            .entries
            .iter()
            .find(|e| e.display_path.ends_with(directory))
            .unwrap();
        let aggregates: BTreeMap<_, _> = summary
            .aggregates
            .iter()
            .map(|a| (a.directory_identity.as_str(), a))
            .collect();
        let service = JunkService::built_in().unwrap();
        let mut candidate = service
            .interpret(
                if svelte {
                    "project:node.sveltekit-output"
                } else {
                    "project:dart.tool-state"
                },
                entry,
                &aggregates,
                &[],
                &PlatformJunkEvidence::default(),
            )
            .unwrap();
        ProjectFormatSession::new(ProjectFormatLimits::default(), CancellationToken::new())
            .refresh(&mut candidate);
        assert_eq!(
            candidate.project_format.as_ref().unwrap().status,
            ProjectFormatStatus::Recognized
        );
        assert!(entry.coverage.complete);
        // This deliberately marks traversal eligible; the independent project guard must prevail.
        let code = run_bulk_trash(
            Locale::EnUs,
            vec![BulkTrashItem {
                path: candidate.path.clone(),
                rule_id: candidate.rule_id.clone(),
                size: bytes.len() as u128,
                entry,
                eligible: true,
                project_blocker: candidate.project_execution_blocker(),
            }],
        );
        assert_eq!(code, ProcessExitCode::from(8));
        let aggregate = summary
            .aggregates
            .iter()
            .find(|a| a.directory_identity == candidate.entry_id.as_str())
            .unwrap()
            .clone();
        let row = sweepx_core::junk::session::JunkSessionCandidate {
            candidate,
            facts: sweepx_core::junk::session::JunkSessionFacts::Directory(Box::new(aggregate)),
        };
        assert_eq!(
            trash_session_candidate(&row, &CancellationToken::new()).unwrap_err(),
            "project_ownership_not_verified"
        );
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        if svelte {
            assert_eq!(
                std::fs::read(ambient).unwrap(),
                sweepx_fixtures::project_junk::SVELTEKIT_AMBIENT.as_bytes()
            );
        }
    }
}
