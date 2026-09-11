//! Prefix-free safety evidence for stale direct children of Linux `/tmp`.
//!
//! Classification is based on native identity, recursive timestamps and allocation, safe inode
//! classes, and references observable for the invoking user. A name never grants authority. The
//! same measurement and reference logic is used by the report and by the mutation preview, so a
//! candidate cannot be presented under one rule and executed under another.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, OsStr, OsString};
use std::fs::{self, Metadata};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

pub(crate) const MIN_IDLE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub(crate) const MAX_CANDIDATES: usize = 1024;
pub(crate) const MEASURE_DEADLINE: Duration = Duration::from_secs(180);
pub(crate) const ACTIVITY_CODE: &str = "recursive_inactive_current_user_unreferenced";
pub(crate) const CLASSIFICATION: &str = "stale_temp_report";
pub(crate) const REFERENCE_BLOCKER: &str = "system_wide_reference_view_unavailable";
pub(crate) const RULE_ID: &str = "linux.stale-temp-object";

pub(crate) type TempEntryIdentity = (u64, u64, fs::FileType);

#[derive(Debug, Clone)]
pub(crate) struct LinuxTempCandidate {
    pub(crate) path: PathBuf,
    pub(crate) measurement: LinuxTempMeasurement,
}

/// Symlink targets captured once, together with the measurement observed after that capture.
#[derive(Debug)]
pub(crate) struct PreparedSymlinkCopy {
    /// Relative path to the captured target for each symlink in the candidate tree.
    pub(crate) targets: BTreeMap<PathBuf, PathBuf>,
    /// Measurement including the access-time update caused by reading each symlink target.
    pub(crate) measurement: LinuxTempMeasurement,
}

#[derive(Debug, Clone)]
pub(crate) struct LinuxTempDiscovery {
    pub(crate) candidates: Vec<LinuxTempCandidate>,
    pub(crate) complete: bool,
    pub(crate) incomplete_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct LinuxTempMeasurement {
    pub(crate) top: Metadata,
    pub(crate) allocated_bytes: u128,
    pub(crate) logical_bytes: u128,
    /// Complete no-follow fingerprint of every inode selected from the candidate tree.
    pub(crate) entries: BTreeMap<PathBuf, TempEntryIdentity>,
    /// Inode numbers of named pipes inside the measured tree.
    pub(crate) fifo_inodes: BTreeSet<u64>,
    pub(crate) entry_count: u64,
    pub(crate) last_accessed: SystemTime,
    pub(crate) last_modified: SystemTime,
    pub(crate) last_status_change: SystemTime,
}

impl PartialEq for LinuxTempMeasurement {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint_equals(other)
            && self.top.uid() == other.top.uid()
            && self.entries == other.entries
            && self.fifo_inodes == other.fifo_inodes
            && self.top.gid() == other.top.gid()
            && self.top.mode() == other.top.mode()
    }
}

impl LinuxTempMeasurement {
    /// Compares every durable safety field except recursive access time.
    fn identity_equals_ignoring_access_time(&self, other: &Self) -> bool {
        self.top.dev() == other.top.dev()
            && self.top.ino() == other.top.ino()
            && self.top.file_type() == other.top.file_type()
            && self.allocated_bytes == other.allocated_bytes
            && self.logical_bytes == other.logical_bytes
            && self.entry_count == other.entry_count
            && self.last_modified == other.last_modified
            && self.last_status_change == other.last_status_change
            && self.entries == other.entries
            && self.fifo_inodes == other.fifo_inodes
            && self.top.uid() == other.top.uid()
            && self.top.gid() == other.top.gid()
            && self.top.mode() == other.top.mode()
    }
}

impl LinuxTempMeasurement {
    fn fingerprint_equals(&self, other: &Self) -> bool {
        self.top.dev() == other.top.dev()
            && self.top.ino() == other.top.ino()
            && self.top.file_type() == other.top.file_type()
            && self.allocated_bytes == other.allocated_bytes
            && self.logical_bytes == other.logical_bytes
            && self.entry_count == other.entry_count
            && self.last_accessed == other.last_accessed
            && self.last_modified == other.last_modified
            && self.last_status_change == other.last_status_change
    }
}

pub(crate) fn report_temp_root() -> Option<PathBuf> {
    std::env::var_os("SWEEPX_TEST_LINUX_TMP_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| Some(PathBuf::from("/tmp")))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
}

pub(crate) fn discover(
    temp_root: &Path,
    explicit_roots: Option<&[PathBuf]>,
    deadline: Instant,
) -> LinuxTempDiscovery {
    let mut discovery = LinuxTempDiscovery {
        candidates: Vec::new(),
        complete: true,
        incomplete_reason: None,
    };

    let entries = match explicit_roots {
        Some(roots) => roots.to_vec(),
        None => match enumerate_direct_children(temp_root) {
            Ok(entries) => entries,
            Err(error) => {
                return LinuxTempDiscovery {
                    candidates: Vec::new(),
                    complete: false,
                    incomplete_reason: Some(error),
                };
            }
        },
    };

    for path in entries {
        if Instant::now() >= deadline {
            discovery.complete = false;
            discovery.incomplete_reason = Some("linux tmp discovery deadline reached".to_string());
            break;
        }
        match inspect_candidate(&path, temp_root, deadline, true, true) {
            Ok(measurement) => {
                discovery
                    .candidates
                    .push(LinuxTempCandidate { path, measurement });
                if discovery.candidates.len() > MAX_CANDIDATES {
                    discovery.candidates.truncate(MAX_CANDIDATES);
                    discovery.complete = false;
                    discovery.incomplete_reason =
                        Some("linux tmp candidate limit reached".to_string());
                    break;
                }
            }
            Err(InspectError::Ineligible(_)) => {}
            Err(InspectError::Incomplete(reason)) => {
                discovery.complete = false;
                discovery.incomplete_reason = Some(reason);
            }
        }
    }

    discovery
        .candidates
        .sort_by(|left, right| left.path.as_os_str().cmp(right.path.as_os_str()));
    discovery
}

pub(crate) fn validate_candidate(
    path: &Path,
    temp_root: &Path,
) -> Result<LinuxTempMeasurement, String> {
    validate_candidate_with_seams(path, temp_root, false)
}

pub(crate) fn validate_candidate_with_seams(
    path: &Path,
    temp_root: &Path,
    allow_test_seams: bool,
) -> Result<LinuxTempMeasurement, String> {
    let deadline = Instant::now() + MEASURE_DEADLINE;
    inspect_candidate(path, temp_root, deadline, allow_test_seams, true).map_err(
        |error| match error {
            InspectError::Ineligible(reason) | InspectError::Incomplete(reason) => reason,
        },
    )
}

/// Revalidates a candidate after its symlink targets have intentionally been read.
pub(crate) fn revalidate_prepared_candidate_with_seams(
    path: &Path,
    temp_root: &Path,
    allow_test_seams: bool,
) -> Result<LinuxTempMeasurement, String> {
    let deadline = Instant::now() + MEASURE_DEADLINE;
    inspect_candidate(path, temp_root, deadline, allow_test_seams, false).map_err(|error| {
        match error {
            InspectError::Ineligible(reason) | InspectError::Incomplete(reason) => reason,
        }
    })
}

/// Reads symlink targets once and records the access-time effect on only those symlinks.
pub(crate) fn prepare_symlink_copy(
    path: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
    allow_test_seams: bool,
) -> Result<PreparedSymlinkCopy, String> {
    let before = snapshot_entry_metadata(path, expected)?;
    let mut targets = BTreeMap::new();
    for (relative, (_device, _inode, file_type)) in &expected.entries {
        if file_type.is_symlink() {
            let symlink_path = entry_path(path, relative);
            let target = fs::read_link(&symlink_path)
                .map_err(|error| format!("read symlink {}: {error}", symlink_path.display()))?;
            targets.insert(relative.clone(), target);
        }
    }
    assert_only_symlink_access_times_changed(path, expected, &before)?;

    let deadline = Instant::now() + MEASURE_DEADLINE;
    let measurement = inspect_candidate(path, temp_root, deadline, allow_test_seams, false)
        .map_err(|error| match error {
            InspectError::Ineligible(reason) | InspectError::Incomplete(reason) => reason,
        })?;
    if !measurement.identity_equals_ignoring_access_time(expected) {
        return Err("source changed while symlink targets were captured".to_string());
    }
    Ok(PreparedSymlinkCopy {
        targets,
        measurement,
    })
}

fn snapshot_entry_metadata(
    root: &Path,
    expected: &LinuxTempMeasurement,
) -> Result<BTreeMap<PathBuf, Metadata>, String> {
    let mut snapshot = BTreeMap::new();
    for (relative, expected_identity) in &expected.entries {
        let entry_path = entry_path(root, relative);
        let metadata = fs::symlink_metadata(&entry_path)
            .map_err(|error| format!("inspect {}: {error}", entry_path.display()))?;
        if (metadata.dev(), metadata.ino(), metadata.file_type()) != *expected_identity {
            return Err(format!(
                "{} changed identity before symlink targets were captured",
                entry_path.display()
            ));
        }
        snapshot.insert(relative.clone(), metadata);
    }
    Ok(snapshot)
}

fn assert_only_symlink_access_times_changed(
    root: &Path,
    expected: &LinuxTempMeasurement,
    before: &BTreeMap<PathBuf, Metadata>,
) -> Result<(), String> {
    for (relative, expected_identity) in &expected.entries {
        let entry_path = entry_path(root, relative);
        let after = fs::symlink_metadata(&entry_path)
            .map_err(|error| format!("inspect {}: {error}", entry_path.display()))?;
        let Some(before) = before.get(relative) else {
            return Err(format!("missing pre-read evidence for {relative:?}"));
        };
        if (after.dev(), after.ino(), after.file_type()) != *expected_identity
            || after.mode() != before.mode()
            || after.uid() != before.uid()
            || after.gid() != before.gid()
            || after.nlink() != before.nlink()
            || after.len() != before.len()
            || after.blocks() != before.blocks()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec()
        {
            return Err(format!(
                "{} changed while symlink targets were captured",
                entry_path.display()
            ));
        }
        if expected_identity.2.is_symlink() {
            let before_atime = (before.atime(), before.atime_nsec());
            let after_atime = (after.atime(), after.atime_nsec());
            if after_atime < before_atime {
                return Err(format!(
                    "{} access time moved backward while symlink targets were captured",
                    entry_path.display()
                ));
            }
        } else if (after.atime(), after.atime_nsec()) != (before.atime(), before.atime_nsec()) {
            return Err(format!(
                "{} was accessed while symlink targets were captured",
                entry_path.display()
            ));
        }
    }
    Ok(())
}

fn entry_path(root: &Path, relative: &Path) -> PathBuf {
    if relative.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    }
}

#[derive(Debug)]
enum InspectError {
    Ineligible(String),
    Incomplete(String),
}

fn enumerate_direct_children(temp_root: &Path) -> Result<Vec<PathBuf>, String> {
    let read_dir =
        fs::read_dir(temp_root).map_err(|error| format!("enumerate {temp_root:?}: {error}"))?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|error| format!("enumerate entry in {temp_root:?}: {error}"))?;
        entries.push(entry.path());
    }
    entries.sort_by(|left, right| left.as_os_str().cmp(right.as_os_str()));
    Ok(entries)
}

fn inspect_candidate(
    path: &Path,
    temp_root: &Path,
    deadline: Instant,
    allow_test_seams: bool,
    enforce_idle: bool,
) -> Result<LinuxTempMeasurement, InspectError> {
    if path.parent() != Some(temp_root) {
        return Err(InspectError::Ineligible(format!(
            "{} is not a direct child of the temporary root",
            path.display()
        )));
    }
    let root_metadata = fs::symlink_metadata(temp_root)
        .map_err(|error| InspectError::Incomplete(format!("inspect temp root: {error}")))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        InspectError::Incomplete(format!("inspect {}: {error}", path.display()))
    })?;
    if metadata.uid() != current_uid() || metadata.dev() != root_metadata.dev() {
        return Err(InspectError::Ineligible(format!(
            "{} is not a current-user object on the temporary root filesystem",
            path.display()
        )));
    }
    if !is_supported_temp_type(metadata.file_type()) {
        return Err(InspectError::Ineligible(format!(
            "{} has an inode type that cannot be safely quarantined",
            path.display()
        )));
    }
    if !metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.nlink() > 1 {
        return Err(InspectError::Ineligible(format!(
            "{} has a hard link outside the candidate path",
            path.display()
        )));
    }
    if !parent_is_removable(temp_root) {
        return Err(InspectError::Ineligible(format!(
            "{} cannot be removed from its sticky temporary root",
            path.display()
        )));
    }

    let first = measure_tree(path, metadata.dev(), deadline, allow_test_seams)?;
    let second = measure_tree(path, metadata.dev(), deadline, allow_test_seams)?;
    if !first.fingerprint_equals(&second) {
        return Err(InspectError::Incomplete(format!(
            "{} changed while its recursive activity evidence was collected",
            path.display()
        )));
    }
    // A write, chmod/chown, or recent path access can each make a stale-looking temp object
    // unsafe to displace. Require all recursive timestamp classes to cross the idle threshold.
    let now = reference_now(allow_test_seams);
    let youngest_activity = [
        timestamp_age(&now, second.last_accessed),
        timestamp_age(&now, second.last_modified),
        timestamp_age(&now, second.last_status_change),
    ]
    .into_iter()
    .min()
    .unwrap_or_default();
    if enforce_idle && youngest_activity < MIN_IDLE {
        return Err(InspectError::Ineligible(format!(
            "{} has been active within the last seven days",
            path.display()
        )));
    }
    if has_mount_boundary(path, metadata.dev(), deadline, allow_test_seams)
        .map_err(InspectError::Incomplete)?
    {
        return Err(InspectError::Ineligible(format!(
            "{} is a mount point or contains a mount boundary",
            path.display()
        )));
    }
    if temp_path_is_referenced(path, &second.fifo_inodes, deadline, allow_test_seams)
        .map_err(InspectError::Incomplete)?
    {
        return Err(InspectError::Ineligible(format!(
            "{} is referenced by a process, memory mapping, mount, or socket",
            path.display()
        )));
    }
    Ok(second)
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and only reads the process credentials.
    unsafe { libc::geteuid() }
}

fn is_supported_temp_type(file_type: fs::FileType) -> bool {
    file_type.is_dir()
        || file_type.is_file()
        || file_type.is_symlink()
        || file_type.is_socket()
        || file_type.is_fifo()
}

fn parent_is_removable(path: &Path) -> bool {
    let Ok(bytes) = CPath::new(path.as_os_str()) else {
        return false;
    };
    // SAFETY: the pointer is NUL-terminated and valid for the call. AT_EACCESS uses the effective
    // uid/gid, matching the authority under which cleanup runs.
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            bytes.as_ptr(),
            libc::W_OK | libc::X_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

struct CPath(Vec<u8>);

impl CPath {
    fn new(value: &OsStr) -> io::Result<Self> {
        let mut bytes = value.as_bytes().to_vec();
        if bytes.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
        }
        bytes.push(0);
        Ok(Self(bytes))
    }

    fn as_ptr(&self) -> *const libc::c_char {
        self.0.as_ptr().cast()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn read_dir_names_no_atime(path: &Path) -> io::Result<Vec<OsString>> {
    let path_bytes = CPath::new(path.as_os_str())?;
    // O_NOATIME keeps SweepX's own eligibility read from turning a stale directory into an active
    // one. O_NOFOLLOW and O_DIRECTORY reject a final-component symlink or non-directory race.
    let fd = unsafe {
        libc::open(
            path_bytes.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NOATIME,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = read_dir_names_at(fd);
    unsafe {
        libc::close(fd);
    }
    result
}

#[cfg(target_os = "linux")]
pub(crate) fn read_dir_names_at(fd: i32) -> io::Result<Vec<OsString>> {
    struct DirectoryStream(*mut libc::DIR);

    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: the pointer was acquired from `fdopendir`, which owns the fd and expects
            // exactly one corresponding `closedir`.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    // Duplicate the retained parent descriptor: fdopendir takes ownership, while callers need
    // their descriptor to remain valid for subsequent fd-relative operations.
    let fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(fd) };
    if directory.is_null() {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    let directory = DirectoryStream(directory);
    let mut names = Vec::new();
    loop {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(directory.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                return Err(error);
            }
            break;
        }
        // SAFETY: `readdir` returned a valid entry whose `d_name` is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
    }
    Ok(names)
}

fn read_child_names(path: &Path) -> io::Result<Vec<OsString>> {
    #[cfg(target_os = "linux")]
    {
        read_dir_names_no_atime(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect()
    }
}

fn measure_tree(
    path: &Path,
    root_device: u64,
    deadline: Instant,
    allow_test_seams: bool,
) -> Result<LinuxTempMeasurement, InspectError> {
    let mut top = fs::symlink_metadata(path).map_err(|error| {
        InspectError::Incomplete(format!("inspect {}: {error}", path.display()))
    })?;
    let mut allocated = allocated_bytes(&top)?;
    let mut logical = if top.is_file() {
        u128::from(top.len())
    } else {
        0
    };
    let mut last_accessed = accessed_time(&top)?;
    let mut last_modified = modified_time(&top)?;
    let mut last_status_change = status_change_time(&top)?;
    let mut entry_count = 1;
    let mut entries = BTreeMap::new();
    let mut fifo_inodes = BTreeSet::new();
    entries.insert(PathBuf::new(), entry_identity(&top));
    if top.file_type().is_fifo() {
        fifo_inodes.insert(top.ino());
    }

    if top.file_type().is_dir() {
        let mut stack = vec![path.to_path_buf()];
        let mut hardlinks: BTreeMap<(u64, u64), (u64, u64)> = BTreeMap::new();
        while let Some(directory) = stack.pop() {
            if Instant::now() >= deadline {
                return Err(InspectError::Incomplete(
                    "linux tmp recursive measurement deadline reached".to_string(),
                ));
            }
            if !directory_is_removable(&directory) {
                return Err(InspectError::Ineligible(format!(
                    "{} is not writable enough to remove after a cross-filesystem copy",
                    directory.display()
                )));
            }
            let child_names = read_child_names(&directory).map_err(|error| {
                InspectError::Incomplete(format!("enumerate {}: {error}", directory.display()))
            })?;
            for name in child_names {
                if Instant::now() >= deadline {
                    return Err(InspectError::Incomplete(
                        "linux tmp recursive measurement deadline reached".to_string(),
                    ));
                }
                let child = directory.join(name);
                let metadata = fs::symlink_metadata(&child).map_err(|error| {
                    InspectError::Incomplete(format!("inspect {}: {error}", child.display()))
                })?;
                if metadata.dev() != root_device {
                    return Err(InspectError::Ineligible(format!(
                        "{} crosses a filesystem boundary",
                        child.display()
                    )));
                }
                if metadata.uid() != current_uid() {
                    return Err(InspectError::Ineligible(format!(
                        "{} is owned by another user",
                        child.display()
                    )));
                }
                let relative = child
                    .strip_prefix(path)
                    .expect("recursive traversal stays beneath the candidate")
                    .to_path_buf();
                entries.insert(relative, entry_identity(&metadata));
                let file_type = metadata.file_type();
                if file_type.is_dir() {
                    stack.push(child);
                } else if file_type.is_file() {
                    logical = logical
                        .checked_add(u128::from(metadata.len()))
                        .ok_or_else(|| {
                            InspectError::Incomplete("logical size total overflowed".into())
                        })?;
                    if metadata.nlink() > 1 {
                        hardlinks
                            .entry((metadata.dev(), metadata.ino()))
                            .and_modify(|(_, count)| *count += 1)
                            .or_insert((metadata.nlink(), 1));
                    }
                } else if file_type.is_symlink() {
                    // A symlink is stored as its own small inode. Its target is never traversed.
                    if metadata.nlink() > 1 {
                        return Err(InspectError::Ineligible(format!(
                            "{} has a hard link outside the candidate path",
                            child.display()
                        )));
                    }
                } else if file_type.is_fifo() {
                    fifo_inodes.insert(metadata.ino());
                    if metadata.nlink() > 1 {
                        return Err(InspectError::Ineligible(format!(
                            "{} is a hard-linked named pipe and cannot preserve kernel identity in quarantine",
                            child.display()
                        )));
                    }
                } else if file_type.is_socket() {
                    if metadata.nlink() > 1 {
                        return Err(InspectError::Ineligible(format!(
                            "{} is a hard-linked Unix socket",
                            child.display()
                        )));
                    }
                    if unix_socket_path_is_bound(&child, deadline, allow_test_seams)
                        .map_err(InspectError::Incomplete)?
                    {
                        return Err(InspectError::Ineligible(format!(
                            "{} is a bound Unix-domain socket",
                            child.display()
                        )));
                    }
                } else {
                    return Err(InspectError::Ineligible(format!(
                        "{} is a device inode and cannot be recreated in recoverable quarantine",
                        child.display()
                    )));
                }
                allocated = allocated
                    .checked_add(allocated_bytes(&metadata)?)
                    .ok_or_else(|| {
                        InspectError::Incomplete("allocation total overflowed".into())
                    })?;
                last_accessed = last_accessed.max(accessed_time(&metadata)?);
                last_modified = last_modified.max(modified_time(&metadata)?);
                last_status_change = last_status_change.max(status_change_time(&metadata)?);
                entry_count += 1;
            }
            // Re-stat after enumeration to catch concurrent metadata changes. The enumeration
            // itself uses O_NOATIME so eligibility evidence does not make a stale path active.
            let traversed = fs::symlink_metadata(&directory).map_err(|error| {
                InspectError::Incomplete(format!("re-inspect {}: {error}", directory.display()))
            })?;
            if directory == path {
                top = traversed.clone();
            }
            last_accessed = last_accessed.max(accessed_time(&traversed)?);
            last_modified = last_modified.max(modified_time(&traversed)?);
            last_status_change = last_status_change.max(status_change_time(&traversed)?);
        }

        for ((device, inode), (links, observed)) in hardlinks {
            if links > observed {
                return Err(InspectError::Ineligible(format!(
                    "inode {device}:{inode} has a hard link outside the candidate tree"
                )));
            }
        }
    } else if top.file_type().is_socket()
        && unix_socket_path_is_bound(path, deadline, allow_test_seams)
            .map_err(InspectError::Incomplete)?
    {
        return Err(InspectError::Ineligible(format!(
            "{} is a bound Unix-domain socket",
            path.display()
        )));
    }

    Ok(LinuxTempMeasurement {
        top,
        allocated_bytes: allocated,
        logical_bytes: logical,
        entries,
        fifo_inodes,
        entry_count,
        last_accessed,
        last_modified,
        last_status_change,
    })
}

fn entry_identity(metadata: &Metadata) -> TempEntryIdentity {
    (metadata.dev(), metadata.ino(), metadata.file_type())
}

fn timestamp_age(now: &SystemTime, timestamp: SystemTime) -> Duration {
    now.duration_since(timestamp).unwrap_or_default()
}

fn reference_now(allow_test_seams: bool) -> SystemTime {
    if allow_test_seams
        && let Some(value) = test_path("SWEEPX_TEST_LINUX_NOW_UNIX", true)
            .and_then(|path| path.into_os_string().into_string().ok())
            .and_then(|value| value.parse::<u64>().ok())
    {
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(value))
            .unwrap_or_else(SystemTime::now)
    } else {
        SystemTime::now()
    }
}

fn directory_is_removable(path: &Path) -> bool {
    let Ok(bytes) = CPath::new(path.as_os_str()) else {
        return false;
    };
    // SAFETY: the C pointer is valid and NUL-terminated for the duration of the call.
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            bytes.as_ptr(),
            libc::W_OK | libc::X_OK,
            libc::AT_EACCESS,
        ) == 0
    }
}

fn allocated_bytes(metadata: &Metadata) -> Result<u128, InspectError> {
    Ok(u128::from(metadata.blocks()).saturating_mul(512))
}

fn modified_time(metadata: &Metadata) -> Result<SystemTime, InspectError> {
    system_time(metadata.mtime(), metadata.mtime_nsec())
}

fn accessed_time(metadata: &Metadata) -> Result<SystemTime, InspectError> {
    system_time(metadata.atime(), metadata.atime_nsec())
}

fn status_change_time(metadata: &Metadata) -> Result<SystemTime, InspectError> {
    system_time(metadata.ctime(), metadata.ctime_nsec())
}

fn system_time(seconds: i64, nanoseconds: i64) -> Result<SystemTime, InspectError> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(InspectError::Incomplete(
            "invalid filesystem timestamp".to_string(),
        ));
    }
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(
            u64::try_from(seconds).unwrap_or(0),
            u32::try_from(nanoseconds).unwrap_or(0),
        ))
        .ok_or_else(|| InspectError::Incomplete("timestamp overflow".to_string()))
}

fn has_mount_boundary(
    path: &Path,
    _device: u64,
    deadline: Instant,
    allow_test_seams: bool,
) -> Result<bool, String> {
    let proc_root = proc_root(allow_test_seams);
    let self_mountinfo = proc_root.join("self/mountinfo");
    match fs::read_to_string(&self_mountinfo) {
        Ok(content) => {
            if mountinfo_references_path(&content, path) {
                return Ok(true);
            }
        }
        Err(error) if allow_test_seams && error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("read {}: {error}", self_mountinfo.display())),
    }

    if Instant::now() >= deadline {
        return Err("linux tmp process observation deadline reached".to_string());
    }
    let processes = fs::read_dir(&proc_root)
        .map_err(|error| format!("read {}: {error}", proc_root.display()))?;
    for process in processes {
        if Instant::now() >= deadline {
            return Err("linux tmp process observation deadline reached".to_string());
        }
        let process =
            process.map_err(|error| format!("read {} entry: {error}", proc_root.display()))?;
        if !is_pid(&process.file_name()) {
            continue;
        }
        let process_path = process.path();
        let metadata = match fs::symlink_metadata(&process_path) {
            Ok(metadata) => metadata,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("stat {}: {error}", process_path.display())),
        };
        if metadata.uid() != current_uid() {
            continue;
        }
        let mountinfo_path = process_path.join("mountinfo");
        let content = match fs::read_to_string(&mountinfo_path) {
            Ok(content) => content,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("read {}: {error}", mountinfo_path.display())),
        };
        if mountinfo_references_path(&content, path) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn mountinfo_references_path(content: &str, candidate: &Path) -> bool {
    content.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let Some(root) = fields.nth(3).map(decode_mountinfo_path) else {
            return false;
        };
        let Some(mount_point) = fields.next().map(decode_mountinfo_path) else {
            return false;
        };
        path_is_same_or_inside(&mount_point, candidate) || path_is_same_or_inside(&root, candidate)
    })
}

fn temp_path_is_referenced(
    _path: &Path,
    candidate_fifo_inodes: &BTreeSet<u64>,
    deadline: Instant,
    allow_test_seams: bool,
) -> Result<bool, String> {
    let current_uid = current_uid();
    let proc_root = proc_root(allow_test_seams);
    if Instant::now() >= deadline {
        return Err("linux tmp process observation deadline reached".to_string());
    }
    let processes = fs::read_dir(&proc_root)
        .map_err(|error| format!("read {}: {error}", proc_root.display()))?;
    for process in processes {
        if Instant::now() >= deadline {
            return Err("linux tmp process observation deadline reached".to_string());
        }
        let process =
            process.map_err(|error| format!("read {} entry: {error}", proc_root.display()))?;
        let name = process.file_name();
        if !is_pid(&name) {
            continue;
        }
        let process_path = process.path();
        let metadata = match fs::symlink_metadata(&process_path) {
            Ok(metadata) => metadata,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("stat {}: {error}", process_path.display())),
        };
        if metadata.uid() != current_uid {
            continue;
        }
        for relative in ["cwd", "root", "exe"] {
            match proc_link_references(&process_path.join(relative), _path) {
                Ok(true) => return Ok(true),
                Ok(false) | Err(IsReferenceError::Gone) => {}
                Err(IsReferenceError::Unavailable(reason)) => return Err(reason),
            }
        }
        let fd_entries = match fs::read_dir(process_path.join("fd")) {
            Ok(entries) => entries,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("read fd: {error}")),
        };
        for entry in fd_entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if is_gone(&error) => continue,
                Err(error) => return Err(format!("read fd entry: {error}")),
            };
            let target = match read_proc_link(&entry.path()) {
                Ok(target) => target,
                Err(IsReferenceError::Gone) => continue,
                Err(IsReferenceError::Unavailable(reason)) => return Err(reason),
            };
            if path_is_same_or_inside(&normalize_deleted_link(&target), _path)
                || proc_target_matches_fifo(&target, candidate_fifo_inodes)
            {
                return Ok(true);
            }
        }
        for directory in ["map_files"] {
            let entries = match fs::read_dir(process_path.join(directory)) {
                Ok(entries) => entries,
                Err(error) if is_gone(&error) => continue,
                Err(error) => return Err(format!("read {directory}: {error}")),
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) if is_gone(&error) => continue,
                    Err(error) => return Err(format!("read {directory} entry: {error}")),
                };
                match proc_link_references(&entry.path(), _path) {
                    Ok(true) => return Ok(true),
                    Ok(false) | Err(IsReferenceError::Gone) => {}
                    Err(IsReferenceError::Unavailable(reason)) => return Err(reason),
                }
            }
        }
    }
    unix_socket_path_is_bound(_path, deadline, allow_test_seams)
}

enum IsReferenceError {
    Gone,
    Unavailable(String),
}

fn read_proc_link(link: &Path) -> Result<PathBuf, IsReferenceError> {
    fs::read_link(link).map_err(|error| {
        if is_gone(&error) {
            IsReferenceError::Gone
        } else {
            IsReferenceError::Unavailable(format!("read {}: {error}", link.display()))
        }
    })
}

fn proc_link_references(link: &Path, candidate: &Path) -> Result<bool, IsReferenceError> {
    let target = read_proc_link(link)?;
    Ok(path_is_same_or_inside(
        &normalize_deleted_link(&target),
        candidate,
    ))
}

fn proc_target_matches_fifo(target: &Path, candidate_fifo_inodes: &BTreeSet<u64>) -> bool {
    proc_pipe_inode(target).is_some_and(|inode| candidate_fifo_inodes.contains(&inode))
}

fn proc_pipe_inode(target: &Path) -> Option<u64> {
    let bytes = target.as_os_str().as_bytes();
    bytes
        .strip_prefix(b"pipe:[")
        .and_then(|bytes| bytes.strip_suffix(b"]"))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|inode| inode.parse::<u64>().ok())
}

fn normalize_deleted_link(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let suffix = b" (deleted)";
    bytes
        .strip_suffix(suffix)
        .map(|stripped| PathBuf::from(OsString::from_vec(stripped.to_vec())))
        .unwrap_or_else(|| path.to_path_buf())
}

pub(crate) fn path_is_same_or_inside(target: &Path, candidate: &Path) -> bool {
    // `Path::starts_with` compares complete components, so `/tmp/ab` is not inside `/tmp/a`.
    target.starts_with(candidate)
}

fn is_gone(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::NotFound)
}

fn proc_root(allow_test_seams: bool) -> PathBuf {
    test_path("SWEEPX_TEST_LINUX_PROC_ROOT", allow_test_seams)
        .unwrap_or_else(|| PathBuf::from("/proc"))
}

fn test_path(variable: &str, allow_test_seams: bool) -> Option<PathBuf> {
    allow_test_seams
        .then(|| std::env::var_os(variable))
        .flatten()
        .map(PathBuf::from)
}

fn unix_socket_path_is_bound(
    path: &Path,
    deadline: Instant,
    allow_test_seams: bool,
) -> Result<bool, String> {
    if allow_test_seams && let Some(table) = test_path("SWEEPX_TEST_LINUX_PROC_NET_UNIX", true) {
        return unix_socket_path_is_bound_at(path, &table);
    }

    let proc_root = proc_root(false);
    let mut observed_namespaces = BTreeSet::new();
    let self_table = proc_root.join("self/net/unix");
    let self_namespace = fs::symlink_metadata(proc_root.join("self/ns/net"))
        .map_err(|error| format!("inspect current network namespace: {error}"))?;
    let self_namespace = (self_namespace.dev(), self_namespace.ino());
    observed_namespaces.insert(self_namespace);
    if unix_socket_path_is_bound_at(path, &self_table)? {
        return Ok(true);
    }
    if Instant::now() >= deadline {
        return Err("linux tmp process observation deadline reached".to_string());
    }

    let current_uid = current_uid();
    if Instant::now() >= deadline {
        return Err("linux tmp process observation deadline reached".to_string());
    }
    for process in fs::read_dir(&proc_root)
        .map_err(|error| format!("read {}: {error}", proc_root.display()))?
    {
        if Instant::now() >= deadline {
            return Err("linux tmp process observation deadline reached".to_string());
        }
        let process =
            process.map_err(|error| format!("read {} entry: {error}", proc_root.display()))?;
        if !is_pid(&process.file_name()) {
            continue;
        }
        let process_path = process.path();
        let metadata = match fs::symlink_metadata(&process_path) {
            Ok(metadata) => metadata,
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("stat {}: {error}", process_path.display())),
        };
        if metadata.uid() != current_uid {
            continue;
        }
        let table = process_path.join("net/unix");
        let namespace = match fs::symlink_metadata(process_path.join("ns/net")) {
            Ok(identity) => (identity.dev(), identity.ino()),
            Err(error) if is_gone(&error) => continue,
            Err(error) => return Err(format!("inspect process network namespace: {error}")),
        };
        if socket_table_references_path(path, &table, namespace, &mut observed_namespaces)?
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn socket_table_references_path(
    candidate: &Path,
    table: &Path,
    namespace: (u64, u64),
    observed_namespaces: &mut BTreeSet<(u64, u64)>,
) -> Result<Option<bool>, String> {
    if !observed_namespaces.insert(namespace) {
        return Ok(Some(false));
    }
    match fs::read_to_string(table) {
        Ok(content) => Ok(Some(content.lines().skip(1).any(|line| {
            unix_socket_line_path(line).is_some_and(|socket_path| {
                path_is_same_or_inside(Path::new(&socket_path), candidate)
            })
        }))),
        Err(error) if is_gone(&error) => Ok(None),
        Err(error) => Err(format!("read {}: {error}", table.display())),
    }
}

fn unix_socket_line_path(line: &str) -> Option<OsString> {
    let mut bytes = line.trim_start().as_bytes();
    for _ in 0..7 {
        while let Some(first) = bytes.first()
            && first.is_ascii_whitespace()
        {
            bytes = &bytes[1..];
        }
        let end = bytes.iter().position(|byte| byte.is_ascii_whitespace())?;
        bytes = &bytes[end..];
    }
    while let Some(first) = bytes.first()
        && first.is_ascii_whitespace()
    {
        bytes = &bytes[1..];
    }
    if bytes.is_empty() || bytes[0] == b'@' {
        return None;
    }
    Some(OsString::from(OsStr::from_bytes(bytes.trim_ascii())))
}

fn unix_socket_path_is_bound_at(path: &Path, table: &Path) -> Result<bool, String> {
    let content =
        fs::read_to_string(table).map_err(|error| format!("read {}: {error}", table.display()))?;
    Ok(content.lines().skip(1).any(|line| {
        unix_socket_line_path(line)
            .is_some_and(|socket_path| path_is_same_or_inside(Path::new(&socket_path), path))
    }))
}

fn is_pid(name: &OsStr) -> bool {
    !name.is_empty() && name.as_bytes().iter().all(u8::is_ascii_digit)
}

pub(crate) fn decode_mountinfo_path(encoded: &str) -> PathBuf {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 <= bytes.len() {
            let octal = &bytes[index + 1..index + 4];
            let decoded_octal = std::str::from_utf8(octal)
                .map_err(|_| ())
                .and_then(|text| u8::from_str_radix(text, 8).map_err(|_| ()));
            if let Ok(value) = decoded_octal {
                decoded.push(value);
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    PathBuf::from(OsString::from_vec(decoded))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Serializes tests that replace process observation and clock environment variables.
    pub(crate) struct TestSeams {
        _lock: MutexGuard<'static, ()>,
        pub(crate) proc_root: TempDir,
    }

    impl TestSeams {
        /// Installs empty `/proc` and Unix-socket fixtures without moving the reference clock.
        pub(crate) fn new() -> Self {
            let lock = TEST_ENV_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let proc_root = TempDir::new().unwrap();
            fs::create_dir_all(proc_root.path().join("self")).unwrap();
            fs::write(proc_root.path().join("self/mountinfo"), b"").unwrap();
            let net_unix = proc_root.path().join("net-unix");
            fs::write(
                &net_unix,
                b"Num       RefCount Protocol Flags    Type St Inode Path\n",
            )
            .unwrap();
            // SAFETY: Tests holding `TEST_ENV_LOCK` are the only users of these process globals.
            unsafe {
                std::env::set_var("SWEEPX_TEST_LINUX_PROC_ROOT", proc_root.path());
                std::env::set_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX", net_unix);
            }
            Self {
                _lock: lock,
                proc_root,
            }
        }

        /// Installs fixtures and projects the reference clock beyond every fixture timestamp.
        pub(crate) fn future() -> Self {
            let seams = Self::new();
            // SAFETY: The shared test lock makes this process-global clock deterministic.
            unsafe {
                std::env::set_var("SWEEPX_TEST_LINUX_NOW_UNIX", "4000000000");
            }
            seams
        }
    }

    impl Drop for TestSeams {
        fn drop(&mut self) {
            // SAFETY: Drop still holds the test-serialization lock.
            unsafe {
                std::env::remove_var("SWEEPX_TEST_LINUX_PROC_ROOT");
                std::env::remove_var("SWEEPX_TEST_LINUX_PROC_NET_UNIX");
                std::env::remove_var("SWEEPX_TEST_LINUX_NOW_UNIX");
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn no_atime_enumeration_does_not_refresh_a_stale_directory() {
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("stale-directory");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("payload"), b"x").unwrap();
        let touched = std::process::Command::new("touch")
            .arg("-a")
            .arg("-m")
            .arg("-d")
            .arg("@1600000000")
            .arg(&candidate)
            .arg(candidate.join("payload"))
            .status()
            .unwrap();
        assert!(touched.success());
        let before = fs::symlink_metadata(&candidate).unwrap().atime();

        let names = read_child_names(&candidate).unwrap();
        assert_eq!(names, vec![OsString::from("payload")]);
        let after = fs::symlink_metadata(&candidate).unwrap().atime();
        assert_eq!(before, after);
    }

    use super::test_support::TestSeams as TestProcSeams;
    #[test]
    fn recursive_child_timestamp_overrides_old_directory_mtime() {
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("arbitrary-name");
        fs::create_dir(&candidate).unwrap();
        fs::write(candidate.join("payload"), b"active").unwrap();
        let status = std::process::Command::new("touch")
            .arg("-d")
            .arg("@1600000000")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(status.success());

        let measurement = measure_tree(
            &candidate,
            fs::symlink_metadata(root.path()).unwrap().dev(),
            Instant::now() + Duration::from_secs(10),
            true,
        )
        .unwrap();
        assert!(
            SystemTime::now()
                .duration_since(measurement.last_modified)
                .unwrap()
                < Duration::from_secs(60)
        );
    }

    #[test]
    fn arbitrary_old_regular_file_is_a_supported_temp_object() {
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("arbitrary-old-file");
        fs::write(&candidate, b"old").unwrap();
        let status = std::process::Command::new("touch")
            .arg("-d")
            .arg("@1600000000")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(is_supported_temp_type(
            fs::symlink_metadata(&candidate).unwrap().file_type()
        ));
    }

    #[test]
    fn named_pipe_is_a_supported_temp_object() {
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("arbitrary-old-fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(is_supported_temp_type(
            fs::symlink_metadata(&candidate).unwrap().file_type()
        ));
    }

    #[test]
    fn recent_access_time_keeps_an_old_mtime_object_ineligible() {
        let _seams = TestProcSeams::new();
        unsafe {
            std::env::set_var("SWEEPX_TEST_LINUX_NOW_UNIX", "4000000000");
        }
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("recently-read");
        fs::write(&candidate, b"old").unwrap();
        let old = std::process::Command::new("touch")
            .arg("-d")
            .arg("@1600000000")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(old.success());
        let accessed = std::process::Command::new("touch")
            .arg("-a")
            .arg("-d")
            .arg("@3999999900")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(accessed.success());

        let error = inspect_candidate(
            &candidate,
            root.path(),
            Instant::now() + Duration::from_secs(10),
            true,
            true,
        )
        .unwrap_err();
        unsafe {
            std::env::remove_var("SWEEPX_TEST_LINUX_NOW_UNIX");
        }
        assert!(matches!(error, InspectError::Ineligible(_)));
    }

    #[test]
    fn top_level_regular_file_with_another_hard_link_is_rejected() {
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let candidate = root.path().join("linked");
        let external_link = root.path().join("external-link");
        fs::write(&candidate, b"old").unwrap();
        fs::hard_link(&candidate, &external_link).unwrap();
        let status = std::process::Command::new("touch")
            .arg("-d")
            .arg("@1600000000")
            .arg(&candidate)
            .status()
            .unwrap();
        assert!(status.success());

        let error = inspect_candidate(
            &candidate,
            root.path(),
            Instant::now() + Duration::from_secs(10),
            false,
            true,
        )
        .unwrap_err();
        assert!(matches!(error, InspectError::Ineligible(_)));
    }

    #[test]
    fn path_boundary_matches_do_not_accept_prefix_names() {
        assert!(path_is_same_or_inside(
            Path::new("/tmp/a"),
            Path::new("/tmp/a")
        ));
        assert!(path_is_same_or_inside(
            Path::new("/tmp/a/b"),
            Path::new("/tmp/a")
        ));
        assert!(!path_is_same_or_inside(
            Path::new("/tmp/ab"),
            Path::new("/tmp/a")
        ));
    }

    #[test]
    fn active_and_stale_unix_sockets_are_distinguished() {
        let root = TempDir::new().unwrap();
        let socket_path = root.path().join("active.sock");
        let stale_path = root.path().join("stale.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let net = std::env::temp_dir().join(format!("sweepx-proc-net-unix-{}", std::process::id()));
        fs::write(&net, std::fs::read_to_string("/proc/net/unix").unwrap()).unwrap();
        assert!(unix_socket_path_is_bound_at(&socket_path, &net).unwrap());
        assert!(!unix_socket_path_is_bound_at(&stale_path, &net).unwrap());
    }

    #[test]
    fn deleted_open_file_link_still_matches_its_original_path() {
        let seams = TestProcSeams::new();
        let candidate = seams.proc_root.path().join("candidate");
        fs::create_dir(&candidate).unwrap();
        let fd_root = seams.proc_root.path().join("4242/fd");
        fs::create_dir_all(&fd_root).unwrap();
        std::os::unix::fs::symlink(candidate.join("open-file (deleted)"), fd_root.join("7"))
            .unwrap();

        let referenced = temp_path_is_referenced(
            &candidate,
            &BTreeSet::new(),
            Instant::now() + Duration::from_secs(10),
            true,
        )
        .unwrap();
        assert!(referenced);
    }

    #[test]
    fn held_named_pipe_is_matched_by_inode() {
        let seams = TestProcSeams::new();
        let candidate = seams.proc_root.path().join("candidate");
        fs::create_dir(&candidate).unwrap();
        let fd_root = seams.proc_root.path().join("4244/fd");
        fs::create_dir_all(&fd_root).unwrap();
        std::os::unix::fs::symlink("pipe:[424242]", fd_root.join("8")).unwrap();
        let mut fifos = BTreeSet::new();
        fifos.insert(424242);

        let referenced = temp_path_is_referenced(
            &candidate,
            &fifos,
            Instant::now() + Duration::from_secs(10),
            true,
        )
        .unwrap();
        assert!(referenced);
    }

    #[test]
    fn sparse_file_reports_logical_size_for_space_preflight() {
        let root = TempDir::new().unwrap();
        let candidate = root.path().join("sparse");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .unwrap();
        file.set_len(4 * 1024 * 1024).unwrap();
        drop(file);

        let measurement = measure_tree(
            &candidate,
            fs::symlink_metadata(root.path()).unwrap().dev(),
            Instant::now() + Duration::from_secs(10),
            false,
        )
        .unwrap();
        assert_eq!(measurement.logical_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn discovery_limits_candidates_and_marks_the_report_incomplete() {
        let _seams = TestProcSeams::new();
        unsafe {
            std::env::set_var("SWEEPX_TEST_LINUX_NOW_UNIX", "4000000000");
        }
        let root = TempDir::new().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut paths = Vec::new();
        for index in 0..=MAX_CANDIDATES {
            let path = root.path().join(format!("candidate-{index:04}"));
            fs::write(&path, b"old").unwrap();
            paths.push(path);
        }
        let touched = std::process::Command::new("touch")
            .arg("-d")
            .arg("@1600000000")
            .args(&paths)
            .status()
            .unwrap();
        assert!(touched.success());

        let discovery = discover(root.path(), None, Instant::now() + Duration::from_secs(30));
        assert_eq!(discovery.candidates.len(), MAX_CANDIDATES);
        assert!(!discovery.complete);
        assert_eq!(
            discovery.incomplete_reason.as_deref(),
            Some("linux tmp candidate limit reached")
        );

        let expired = discover(
            root.path(),
            None,
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        );
        assert!(expired.candidates.is_empty());
        assert!(!expired.complete);
    }

    #[test]
    fn same_uid_process_reference_view_that_cannot_be_read_fails_closed() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let seams = TestProcSeams::new();
        let candidate = seams.proc_root.path().join("candidate");
        fs::create_dir(&candidate).unwrap();
        let process = seams.proc_root.path().join("4243");
        fs::create_dir(&process).unwrap();
        fs::set_permissions(&process, fs::Permissions::from_mode(0o000)).unwrap();
        let result = temp_path_is_referenced(
            &candidate,
            &BTreeSet::new(),
            Instant::now() + Duration::from_secs(10),
            true,
        );
        fs::set_permissions(&process, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn mount_boundary_detects_same_or_nested_mount_points() {
        let seams = TestProcSeams::new();
        let mountinfo = seams.proc_root.path().join("self/mountinfo");
        fs::write(
            &mountinfo,
            b"42 1 0:42 / /tmp/old-root rw,noatime - ext4 /dev/sda rw\n",
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(has_mount_boundary(Path::new("/tmp/old-root"), 0, deadline, true).unwrap());
        assert!(!has_mount_boundary(Path::new("/tmp/old"), 0, deadline, true).unwrap());
    }

    #[test]
    fn mountinfo_octal_escapes_are_decoded() {
        assert_eq!(
            decode_mountinfo_path("/tmp/a\\040b").as_os_str().as_bytes(),
            b"/tmp/a b"
        );
        assert_eq!(
            decode_mountinfo_path("/tmp/a\\134b").as_os_str().as_bytes(),
            br"/tmp/a\b"
        );
    }
}
