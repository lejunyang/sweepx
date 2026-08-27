//! Linux-only Trash qualification state-machine substrate.
//!
//! This module is deliberately compiled only for this crate's Linux tests and
//! cannot be reached by the CLI, core, executor, or a normal/all-features
//! library build. Deterministic fakes exercise its state machine; an optional
//! nested GIO adapter can act only on a sealed generated disposable fixture.

use std::ffi::{CStr, CString, OsString, c_int};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sweepx_fixtures::{GeneratedFixture, LinuxTrashTargetQualification};

mod gio_trash;

const INTENT_FILE: &str = "action-intent-v1";
const OUTCOME_FILE: &str = "action-outcome-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualificationErrorKind {
    Admission,
    Probe,
    StaleBeforeSubmit,
    Evidence,
    Io,
}

#[derive(Debug)]
struct QualificationError {
    kind: QualificationErrorKind,
    detail: String,
}

impl QualificationError {
    fn new(kind: QualificationErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    fn io(context: &str, error: io::Error) -> Self {
        Self::new(QualificationErrorKind::Io, format!("{context}: {error}"))
    }
}

impl fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.detail)
    }
}

impl std::error::Error for QualificationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilitySets {
    permitted: u64,
    effective: u64,
    ambient: u64,
}

impl CapabilitySets {
    fn is_empty(self) -> bool {
        self.permitted == 0 && self.effective == 0 && self.ambient == 0
    }
}

trait RuntimeInspector {
    fn effective_uid(&self) -> Result<u32, QualificationError>;
    fn capability_sets(&self) -> Result<CapabilitySets, QualificationError>;
    fn xdg_data_home(&self) -> Option<OsString>;
}

#[derive(Debug)]
struct ProcessRuntime;

impl RuntimeInspector for ProcessRuntime {
    fn effective_uid(&self) -> Result<u32, QualificationError> {
        // SAFETY: geteuid has no preconditions and does not mutate process state.
        Ok(unsafe { libc::geteuid() })
    }

    fn capability_sets(&self) -> Result<CapabilitySets, QualificationError> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| QualificationError::io("read /proc/self/status", error))?;
        Ok(CapabilitySets {
            permitted: parse_proc_status_hex(&status, "CapPrm")?,
            effective: parse_proc_status_hex(&status, "CapEff")?,
            ambient: parse_proc_status_hex(&status, "CapAmb")?,
        })
    }

    fn xdg_data_home(&self) -> Option<OsString> {
        std::env::var_os("XDG_DATA_HOME")
    }
}

fn parse_proc_status_hex(status: &str, field: &str) -> Result<u64, QualificationError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .map(str::trim)
        .ok_or_else(|| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                format!("/proc/self/status omitted {field}"),
            )
        })?;
    u64::from_str_radix(value, 16).map_err(|error| {
        QualificationError::new(
            QualificationErrorKind::Admission,
            format!("invalid {field} in /proc/self/status: {error}"),
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountRecord {
    mount_id: u64,
    parent_id: u64,
    major_minor: String,
    root: Vec<u8>,
    mount_point: PathBuf,
    filesystem: String,
    source: String,
    raw_line: String,
}

impl MountRecord {
    fn for_path(path: &Path) -> Result<Self, QualificationError> {
        let canonical = path.canonicalize().map_err(|error| {
            QualificationError::io(&format!("canonicalize {}", path.display()), error)
        })?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")
            .map_err(|error| QualificationError::io("read /proc/self/mountinfo", error))?;
        let mut best: Option<Self> = None;
        for line in mountinfo.lines() {
            let Some(record) = Self::parse(line) else {
                continue;
            };
            if !path_is_within(&canonical, &record.mount_point) {
                continue;
            }
            if best.as_ref().is_none_or(|current| {
                record.mount_point.as_os_str().len() > current.mount_point.as_os_str().len()
            }) {
                best = Some(record);
            }
        }
        best.ok_or_else(|| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                format!("no mountinfo record for {}", canonical.display()),
            )
        })
    }

    fn parse(line: &str) -> Option<Self> {
        let (left, right) = line.split_once(" - ")?;
        let left_fields: Vec<&str> = left.split_whitespace().collect();
        let right_fields: Vec<&str> = right.split_whitespace().collect();
        if left_fields.len() < 6 || right_fields.len() < 2 {
            return None;
        }
        Some(Self {
            mount_id: left_fields[0].parse().ok()?,
            parent_id: left_fields[1].parse().ok()?,
            major_minor: left_fields[2].to_string(),
            root: decode_mountinfo_field(left_fields[3]),
            mount_point: PathBuf::from(OsString::from_vec(decode_mountinfo_field(left_fields[4]))),
            filesystem: right_fields[0].to_string(),
            source: right_fields[1].to_string(),
            raw_line: line.to_string(),
        })
    }
}

fn decode_mountinfo_field(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1..=index + 3]
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'7'))
        {
            let decoded = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            output.push(decoded);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    output
}

fn path_is_within(path: &Path, ancestor: &Path) -> bool {
    path == ancestor || path.starts_with(ancestor)
}

fn is_qualified_local_filesystem(filesystem: &str) -> bool {
    matches!(filesystem, "ext4" | "xfs" | "btrfs")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NativeIdentity {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount_id: u64,
    mode: u16,
    links: u32,
    uid: u32,
    gid: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: u32,
    changed_seconds: i64,
    changed_nanoseconds: u32,
}

impl NativeIdentity {
    fn from_fd(fd: &impl AsRawFd) -> Result<Self, QualificationError> {
        let mut output = MaybeUninit::<libc::statx>::zeroed();
        let empty = c"";
        // BASIC_STATS explicitly requests MODE, UID, GID, NLINK, INO, SIZE, and
        // timestamps; MNT_ID is additionally mandatory for qualification.
        let required = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
        // SAFETY: output points to writable storage, fd is live, and AT_EMPTY_PATH
        // explicitly permits the empty pathname used to query that descriptor.
        let result = unsafe {
            libc::statx(
                fd.as_raw_fd(),
                empty.as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                required,
                output.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(QualificationError::io(
                "statx qualification descriptor",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: statx returned success and initialized the output structure.
        let output = unsafe { output.assume_init() };
        if output.stx_mask & required != required {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!(
                    "statx omitted required identity fields: mask=0x{:x}",
                    output.stx_mask
                ),
            ));
        }
        Ok(Self {
            device_major: output.stx_dev_major,
            device_minor: output.stx_dev_minor,
            inode: output.stx_ino,
            mount_id: output.stx_mnt_id,
            mode: output.stx_mode,
            links: output.stx_nlink,
            uid: output.stx_uid,
            gid: output.stx_gid,
            size: output.stx_size,
            modified_seconds: output.stx_mtime.tv_sec,
            modified_nanoseconds: output.stx_mtime.tv_nsec,
            changed_seconds: output.stx_ctime.tv_sec,
            changed_nanoseconds: output.stx_ctime.tv_nsec,
        })
    }

    fn is_regular_single_link(self) -> bool {
        (u32::from(self.mode) & libc::S_IFMT) == libc::S_IFREG && self.links == 1
    }

    fn same_object_and_policy(self, other: Self) -> bool {
        self.device_major == other.device_major
            && self.device_minor == other.device_minor
            && self.inode == other.inode
            && self.mount_id == other.mount_id
            && self.mode == other.mode
            && self.links == other.links
            && self.uid == other.uid
            && self.gid == other.gid
    }

    fn same_directory_object_and_policy(self, other: Self) -> bool {
        self.device_major == other.device_major
            && self.device_minor == other.device_minor
            && self.inode == other.inode
            && self.mount_id == other.mount_id
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && (u32::from(self.mode) & libc::S_IFMT) == libc::S_IFDIR
            && (u32::from(other.mode) & libc::S_IFMT) == libc::S_IFDIR
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectorySnapshot {
    identity: NativeIdentity,
    entries: Vec<OsString>,
}

struct PrivateDirectory {
    path: PathBuf,
    fd: OwnedFd,
    identity: NativeIdentity,
}

impl PrivateDirectory {
    fn admit_empty(path: &Path, euid: u32, label: &str) -> Result<Self, QualificationError> {
        let fd = open_absolute_directory(path)?;
        let identity = NativeIdentity::from_fd(&fd)?;
        if (u32::from(identity.mode) & libc::S_IFMT) != libc::S_IFDIR {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!("{label} must be a real directory"),
            ));
        }
        if identity.uid != euid || u32::from(identity.mode) & 0o077 != 0 {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!("{label} must be owned by the runtime user with no group/other access"),
            ));
        }
        let directory = Self {
            path: path.to_path_buf(),
            fd,
            identity,
        };
        let snapshot = directory.held_snapshot(label)?;
        if !snapshot.entries.is_empty() {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!("{label} must be empty"),
            ));
        }
        Ok(directory)
    }

    /// Observes this directory through the descriptor captured at admission.
    /// The original pathname is deliberately not used for enumeration.
    fn held_snapshot(&self, label: &str) -> Result<DirectorySnapshot, QualificationError> {
        let identity_before = NativeIdentity::from_fd(&self.fd)?;
        if !identity_before.same_object_and_policy(self.identity) {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("held {label} identity changed"),
            ));
        }
        let fd_path = self.fd_path();
        let mut entries = fs::read_dir(&fd_path)
            .map_err(|error| QualificationError::io(&format!("enumerate {label}"), error))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| QualificationError::io(&format!("enumerate {label}"), error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        let identity_after = NativeIdentity::from_fd(&self.fd)?;
        if identity_after != identity_before {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("{label} changed while it was observed"),
            ));
        }
        Ok(DirectorySnapshot {
            identity: identity_after,
            entries,
        })
    }

    /// Observes an admitted directory after an operation is expected to add
    /// entries. Directory size, timestamps, and link count may legitimately
    /// change; identity, mount, type, ownership, mode, pathname binding, and a
    /// stable enumeration window remain mandatory.
    fn held_snapshot_after_content_change(
        &self,
        label: &str,
    ) -> Result<DirectorySnapshot, QualificationError> {
        let held_before = NativeIdentity::from_fd(&self.fd)?;
        if !held_before.same_directory_object_and_policy(self.identity) {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                format!("held {label} identity or access policy changed"),
            ));
        }
        let reopened = open_absolute_directory(&self.path)?;
        if !NativeIdentity::from_fd(&reopened)?.same_directory_object_and_policy(self.identity) {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                format!("{label} pathname no longer names the admitted directory"),
            ));
        }
        let mut entries = fs::read_dir(self.fd_path())
            .map_err(|error| QualificationError::io(&format!("enumerate {label}"), error))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| QualificationError::io(&format!("enumerate {label}"), error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();
        let held_after = NativeIdentity::from_fd(&self.fd)?;
        if held_after != held_before {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                format!("{label} changed while it was observed"),
            ));
        }
        Ok(DirectorySnapshot {
            identity: held_after,
            entries,
        })
    }

    /// Separately proves that the configured pathname still names the admitted
    /// directory. Callers must not use this reopened descriptor to observe data.
    fn verify_path_binding(&self, label: &str) -> Result<(), QualificationError> {
        let reopened = open_absolute_directory(&self.path)?;
        let reopened_identity = NativeIdentity::from_fd(&reopened)?;
        let held_identity = NativeIdentity::from_fd(&self.fd)?;
        if !reopened_identity.same_object_and_policy(self.identity)
            || !held_identity.same_object_and_policy(self.identity)
        {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("{label} identity changed"),
            ));
        }
        Ok(())
    }

    fn verify_snapshot(
        &self,
        expected: &DirectorySnapshot,
        label: &str,
    ) -> Result<(), QualificationError> {
        self.verify_path_binding(label)?;
        if self.held_snapshot(label)? != *expected {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("{label} snapshot changed"),
            ));
        }
        Ok(())
    }

    fn verify(&self, expected_entries: &[&str], label: &str) -> Result<(), QualificationError> {
        self.verify_path_binding(label)?;
        let snapshot = self.held_snapshot(label)?;
        let mut expected = expected_entries
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        expected.sort();
        if snapshot.entries != expected {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("{label} contents changed"),
            ));
        }
        Ok(())
    }

    fn fd_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }

    fn duplicate(&self, label: &str) -> Result<Self, QualificationError> {
        let fd = open_beneath(&self.fd, Path::new("."), true)?;
        let identity = NativeIdentity::from_fd(&fd)?;
        if !identity.same_object_and_policy(self.identity) {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                format!("{label} changed while duplicating its handle"),
            ));
        }
        Ok(Self {
            path: self.path.clone(),
            fd,
            identity,
        })
    }
}

struct ContainmentSnapshot {
    top_fd: OwnedFd,
    parent_fd: OwnedFd,
    target_fd: OwnedFd,
    top_relative_parent: PathBuf,
    top_relative_target: PathBuf,
    top_identity: NativeIdentity,
    parent_identity: NativeIdentity,
    target_identity: NativeIdentity,
    mount: MountRecord,
}

impl ContainmentSnapshot {
    fn capture(
        top: &Path,
        target_path: &Path,
        expected_filesystem: &str,
        xdg_data_home: &Path,
    ) -> Result<Self, QualificationError> {
        let relative_target = target_path.strip_prefix(top).map_err(|_| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                "selected target is not below generated top directory",
            )
        })?;
        if relative_target.as_os_str().is_empty()
            || relative_target.components().count() < 1
            || relative_target.is_absolute()
        {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "selected target is not a strict descendant",
            ));
        }
        let relative_parent = relative_target.parent().unwrap_or_else(|| Path::new("."));

        let top_fd = open_absolute_directory(top)?;
        let parent_fd = if relative_parent.as_os_str().is_empty() {
            open_beneath(&top_fd, Path::new("."), true)?
        } else {
            open_beneath(&top_fd, relative_parent, true)?
        };
        let target_fd = open_beneath(&top_fd, relative_target, false)?;
        let top_identity = NativeIdentity::from_fd(&top_fd)?;
        let parent_identity = NativeIdentity::from_fd(&parent_fd)?;
        let target_identity = NativeIdentity::from_fd(&target_fd)?;
        if !target_identity.is_regular_single_link() {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "selected target is not a single-link regular file at statx admission",
            ));
        }
        if top_identity.mount_id != parent_identity.mount_id
            || top_identity.mount_id != target_identity.mount_id
        {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "fixture top, parent, and target are not on one mount",
            ));
        }

        let mount = MountRecord::for_path(target_path)?;
        let xdg_mount = MountRecord::for_path(xdg_data_home)?;
        if mount.mount_id != target_identity.mount_id || xdg_mount.mount_id != mount.mount_id {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "fixture and isolated XDG data home must share the qualified mount",
            ));
        }
        if mount.filesystem != expected_filesystem
            || !is_qualified_local_filesystem(&mount.filesystem)
        {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!(
                    "runtime filesystem {} is not the exact qualified local filesystem {}",
                    mount.filesystem, expected_filesystem
                ),
            ));
        }

        Ok(Self {
            top_fd,
            parent_fd,
            target_fd,
            top_relative_parent: relative_parent.to_path_buf(),
            top_relative_target: relative_target.to_path_buf(),
            top_identity,
            parent_identity,
            target_identity,
            mount,
        })
    }

    fn verify(&self, top_dir: &Path, target_path: &Path) -> Result<(), QualificationError> {
        let current_mount = MountRecord::for_path(target_path)?;
        if current_mount != self.mount {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "relevant mountinfo record changed",
            ));
        }
        let top = open_absolute_directory(top_dir)?;
        let parent = if self.top_relative_parent.as_os_str().is_empty() {
            open_beneath(&top, Path::new("."), true)?
        } else {
            open_beneath(&top, &self.top_relative_parent, true)?
        };
        let selected = open_beneath(&top, &self.top_relative_target, false)?;
        let identities = (
            NativeIdentity::from_fd(&top)?,
            NativeIdentity::from_fd(&parent)?,
            NativeIdentity::from_fd(&selected)?,
        );
        if identities
            != (
                self.top_identity,
                self.parent_identity,
                self.target_identity,
            )
        {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "fixture containment identity changed",
            ));
        }
        // Keep the admitted descriptors live through submission. Their identities
        // are checked as well so an accidental early close cannot go unnoticed.
        if NativeIdentity::from_fd(&self.top_fd)? != self.top_identity
            || NativeIdentity::from_fd(&self.parent_fd)? != self.parent_identity
            || NativeIdentity::from_fd(&self.target_fd)? != self.target_identity
        {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "held qualification descriptor changed",
            ));
        }
        Ok(())
    }
}

fn open_absolute_directory(path: &Path) -> Result<OwnedFd, QualificationError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "qualification directory must be an absolute non-root path",
        ));
    }
    // SAFETY: the static path is NUL-terminated; the returned descriptor is owned.
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let root_fd = owned_fd(root_fd, "open filesystem root")?;
    let relative = path.strip_prefix("/").map_err(|_| {
        QualificationError::new(QualificationErrorKind::Admission, "invalid absolute path")
    })?;
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "qualification directory path must contain only normal components",
        ));
    }
    openat2_relative(&root_fd, relative, true, false)
}

fn open_beneath(
    top: &OwnedFd,
    relative: &Path,
    directory: bool,
) -> Result<OwnedFd, QualificationError> {
    openat2_relative(top, relative, directory, true)
}

fn open_readonly_beneath(top: &OwnedFd, relative: &Path) -> Result<OwnedFd, QualificationError> {
    if relative.is_absolute() {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            "evidence path must be relative",
        ));
    }
    let c_path = path_to_cstring(relative)?;
    // SAFETY: open_how is a plain kernel ABI value; all-zero is its documented
    // forward-compatible initialization and every field we use is set below.
    let mut how: libc::open_how = unsafe { mem::zeroed() };
    how.flags = u64::try_from(libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .expect("open flags fit u64");
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // SAFETY: all pointers are live for the syscall and the kernel receives the
    // exact size of libc::open_how. The returned descriptor is uniquely owned.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            top.as_raw_fd(),
            c_path.as_ptr(),
            &how,
            mem::size_of::<libc::open_how>(),
        ) as c_int
    };
    owned_fd(fd, &format!("open evidence {}", relative.display()))
}

fn openat2_relative(
    base: &OwnedFd,
    relative: &Path,
    directory: bool,
    no_xdev: bool,
) -> Result<OwnedFd, QualificationError> {
    if relative.is_absolute() {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "openat2 path must be relative",
        ));
    }
    let c_path = path_to_cstring(relative)?;
    let mut flags = u64::try_from(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .expect("open flags fit u64");
    if directory {
        flags |= u64::try_from(libc::O_DIRECTORY).expect("directory flag fits u64");
    }
    // SAFETY: open_how is a plain kernel ABI value; all-zero is its documented
    // forward-compatible initialization and every field we use is set below.
    let mut how: libc::open_how = unsafe { mem::zeroed() };
    how.flags = flags;
    how.mode = 0;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS;
    if no_xdev {
        how.resolve |= libc::RESOLVE_NO_XDEV;
    }
    // SAFETY: all pointers are live for the syscall and the kernel receives the
    // exact size of libc::open_how. The returned descriptor is uniquely owned.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            base.as_raw_fd(),
            c_path.as_ptr(),
            &how,
            mem::size_of::<libc::open_how>(),
        ) as c_int
    };
    owned_fd(fd, &format!("openat2 {}", relative.display()))
}

fn owned_fd(fd: c_int, context: &str) -> Result<OwnedFd, QualificationError> {
    if fd < 0 {
        return Err(QualificationError::io(context, io::Error::last_os_error()));
    }
    // SAFETY: a nonnegative successful open/openat2 result is a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn path_to_cstring(path: &Path) -> Result<CString, QualificationError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        QualificationError::new(
            QualificationErrorKind::Admission,
            format!("path contains an embedded NUL: {}", path.display()),
        )
    })
}

fn ensure_disjoint(
    fixture: &Path,
    xdg: &Path,
    evidence: Option<&Path>,
) -> Result<(), QualificationError> {
    let overlaps = path_is_within(fixture, xdg)
        || path_is_within(xdg, fixture)
        || evidence.is_some_and(|path| {
            path_is_within(path, fixture)
                || path_is_within(fixture, path)
                || path_is_within(path, xdg)
                || path_is_within(xdg, path)
        });
    if overlaps {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "fixture, XDG data home, and evidence roots must be disjoint",
        ));
    }
    Ok(())
}

fn manifest_target_path(
    fixture: &GeneratedFixture,
    entry_id: &str,
) -> Result<PathBuf, QualificationError> {
    let mut matches = fixture
        .manifest
        .entries
        .iter()
        .filter(|entry| entry.entry_id == entry_id);
    let entry = matches.next().ok_or_else(|| {
        QualificationError::new(
            QualificationErrorKind::Admission,
            format!("manifest entry id is absent: {entry_id}"),
        )
    })?;
    if matches.next().is_some() || entry.path.len() < 2 {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "manifest entry id is not one strict, unique descendant",
        ));
    }
    let relative = PathBuf::from_iter(entry.path.iter().skip(1));
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(QualificationError::new(
            QualificationErrorKind::Admission,
            "manifest target contains a non-normal path component",
        ));
    }
    Ok(fixture.top_dir().join(relative))
}

enum BackendSubmission {
    ReportedSuccess,
    ReportedFailure(BackendError),
    Ambiguous(BackendError),
    NotSubmitted(BackendError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendErrorClass {
    Unavailable,
    NotSupported,
    Other,
    Ambiguous,
}

#[derive(Debug, PartialEq, Eq)]
struct BackendError {
    domain: u32,
    code: i32,
    class: BackendErrorClass,
    detail: String,
}

impl BackendError {
    fn synthetic(detail: impl Into<String>) -> Self {
        Self {
            domain: 0,
            code: -1,
            class: BackendErrorClass::Other,
            detail: detail.into(),
        }
    }

    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            domain: 0,
            code: -1,
            class: BackendErrorClass::Unavailable,
            detail: detail.into(),
        }
    }

    fn ambiguous(detail: impl Into<String>) -> Self {
        Self {
            domain: 0,
            code: -1,
            class: BackendErrorClass::Ambiguous,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "domain={} code={} class={:?}: {}",
            self.domain, self.code, self.class, self.detail
        )
    }
}

trait TrashBackend {
    type Bound: BoundTrashBackend;

    fn probe_and_bind(self, target: PrivateNativeTarget) -> Result<Self::Bound, BackendError>;
}

trait BoundTrashBackend {
    /// Consumes a sealed, qualification-only target binding after observing an
    /// already verified durable intent. This contract is private to a Linux
    /// `cfg(test)` module; no product caller can construct a target or reach a
    /// native implementation. It deliberately has only a Trash operation.
    fn submit_trash(self, intent: &DurableIntentToken) -> BackendSubmission;
    fn adapter_label(&self) -> &'static str;
}

struct DurableIntentToken {
    file: File,
    file_identity: NativeIdentity,
    content_len: usize,
    content_digest: [u8; 32],
    evidence_root: PrivateDirectory,
    evidence_snapshot: DirectorySnapshot,
}

impl DurableIntentToken {
    fn verify(&self) -> Result<(), QualificationError> {
        self.verify_record()?;
        self.evidence_root
            .verify_snapshot(&self.evidence_snapshot, "evidence root")
    }

    fn verify_record(&self) -> Result<(), QualificationError> {
        if NativeIdentity::from_fd(&self.file)? != self.file_identity {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                "durable intent descriptor identity changed",
            ));
        }
        let named_fd = open_readonly_beneath(&self.evidence_root.fd, Path::new(INTENT_FILE))
            .map_err(|error| {
                QualificationError::new(
                    QualificationErrorKind::Evidence,
                    format!("durable intent namespace binding failed: {error}"),
                )
            })?;
        if NativeIdentity::from_fd(&named_fd)? != self.file_identity {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                "durable intent name no longer resolves to the verified record",
            ));
        }
        let named_file = File::from(named_fd);
        let mut bytes = vec![0; self.content_len];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let read = named_file
                .read_at(&mut bytes[offset..], offset as u64)
                .map_err(|error| QualificationError::io("read durable intent", error))?;
            if read == 0 {
                return Err(QualificationError::new(
                    QualificationErrorKind::Evidence,
                    "durable intent was truncated",
                ));
            }
            offset += read;
        }
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if digest != self.content_digest {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                "durable intent content hash changed",
            ));
        }
        if NativeIdentity::from_fd(&named_file)? != self.file_identity {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                "durable intent name changed while it was verified",
            ));
        }
        Ok(())
    }
}

struct PrivateNativeTarget {
    identity: NativeIdentity,
    parent_identity: NativeIdentity,
    parent_fd: OwnedFd,
    gio_parent_path: PathBuf,
    basename: OsString,
    gio_path: CString,
}

impl PrivateNativeTarget {
    /// Seals the only pathname accepted by the qualification adapter. GIO has
    /// no dirfd-relative Trash API, so the final call must receive a pathname.
    /// That pathname is derived here from the generated manifest (never caller
    /// input), while the held parent plus exact basename remain authoritative
    /// and are revalidated immediately before the GIO handoff. The lookup GIO
    /// performs after that check is an unavoidable residual qualification race.
    fn new(
        identity: NativeIdentity,
        parent_identity: NativeIdentity,
        parent_fd: &OwnedFd,
        target_path: &Path,
    ) -> Result<Self, QualificationError> {
        let gio_parent_path = target_path.parent().ok_or_else(|| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                "manifest-derived target has no parent",
            )
        })?;
        let basename = target_path.file_name().ok_or_else(|| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                "manifest-derived target has no basename",
            )
        })?;
        if !matches!(
            target_path.components().next_back(),
            Some(std::path::Component::Normal(_))
        ) {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "manifest-derived target does not end in one normal basename",
            ));
        }
        let basename = basename.to_owned();
        path_to_cstring(Path::new(&basename))?;
        let gio_path = path_to_cstring(target_path)?;
        // SAFETY: F_DUPFD_CLOEXEC duplicates the live, held parent descriptor
        // and returns a new descriptor owned exclusively by this binding.
        let parent_fd = unsafe { libc::fcntl(parent_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        let parent_fd = owned_fd(parent_fd, "duplicate held Trash parent")?;
        let sealed = Self {
            identity,
            parent_identity,
            parent_fd,
            gio_parent_path: gio_parent_path.to_path_buf(),
            basename,
            gio_path,
        };
        sealed.verify_exact_binding()?;
        Ok(sealed)
    }

    fn verify_exact_binding(&self) -> Result<(), QualificationError> {
        if NativeIdentity::from_fd(&self.parent_fd)? != self.parent_identity {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "held Trash parent identity changed",
            ));
        }
        let selected = open_beneath(&self.parent_fd, Path::new(&self.basename), false)?;
        if NativeIdentity::from_fd(&selected)? != self.identity {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "exact Trash basename no longer resolves to the admitted target",
            ));
        }
        // GIO cannot consume `parent_fd`, so separately require the pathname
        // parent that GIO will traverse to resolve to this exact held parent.
        let path_parent = open_absolute_directory(&self.gio_parent_path)?;
        if NativeIdentity::from_fd(&path_parent)? != self.parent_identity {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "GIO pathname parent no longer resolves to the held Trash parent",
            ));
        }
        let path_selected = open_beneath(&path_parent, Path::new(&self.basename), false)?;
        if NativeIdentity::from_fd(&path_selected)? != self.identity {
            return Err(QualificationError::new(
                QualificationErrorKind::StaleBeforeSubmit,
                "GIO pathname no longer resolves to the admitted target",
            ));
        }
        Ok(())
    }

    fn gio_path(&self) -> &CStr {
        &self.gio_path
    }
}

struct FixtureTrashScope<B> {
    target: LinuxTrashTargetQualification,
    top_dir: PathBuf,
    target_path: PathBuf,
    xdg_data_home: PrivateDirectory,
    backend: B,
    runtime: Box<dyn RuntimeInspector>,
    admitted_euid: u32,
    containment: ContainmentSnapshot,
}

impl<B: TrashBackend> FixtureTrashScope<B> {
    fn admit_with(
        fixture: &GeneratedFixture,
        target_entry_id: &str,
        isolated_xdg_data_home: &Path,
        backend: B,
        runtime: Box<dyn RuntimeInspector>,
    ) -> Result<Self, QualificationError> {
        let euid = runtime.effective_uid()?;
        if euid == 0 {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "native Trash qualification refuses root",
            ));
        }
        if !runtime.capability_sets()?.is_empty() {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "native Trash qualification requires empty permitted/effective/ambient capabilities",
            ));
        }
        let top_dir = fixture.top_dir().to_path_buf();
        let target_path = manifest_target_path(fixture, target_entry_id)?;
        let mount = MountRecord::for_path(&target_path)?;
        let target = fixture
            .select_linux_trash_target(target_entry_id)
            .map_err(|error| {
                QualificationError::new(
                    QualificationErrorKind::Admission,
                    format!("fixture target selection rejected: {error}"),
                )
            })?;
        if !target.matches_manifest_derived_target(&target_path) {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "private platform target does not match the fixture binding",
            ));
        }
        if target.expected_filesystem() != mount.filesystem {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                format!(
                    "manifest filesystem {} does not match observed runtime filesystem {}",
                    target.expected_filesystem(),
                    mount.filesystem
                ),
            ));
        }
        target.verify_unchanged().map_err(|error| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                format!("fixture baseline rejected: {error}"),
            )
        })?;
        let xdg_data_home =
            PrivateDirectory::admit_empty(isolated_xdg_data_home, euid, "XDG data home")?;
        let configured_xdg = runtime.xdg_data_home().ok_or_else(|| {
            QualificationError::new(
                QualificationErrorKind::Admission,
                "XDG_DATA_HOME is not set",
            )
        })?;
        let configured_xdg = PathBuf::from(configured_xdg)
            .canonicalize()
            .map_err(|error| QualificationError::io("canonicalize XDG_DATA_HOME", error))?;
        if configured_xdg != xdg_data_home.path {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "XDG_DATA_HOME does not name the isolated qualification directory",
            ));
        }
        ensure_disjoint(&top_dir, &xdg_data_home.path, None)?;
        let containment = ContainmentSnapshot::capture(
            &top_dir,
            &target_path,
            target.expected_filesystem(),
            &xdg_data_home.path,
        )?;
        Ok(Self {
            target,
            top_dir,
            target_path,
            xdg_data_home,
            backend,
            runtime,
            admitted_euid: euid,
            containment,
        })
    }

    fn probe(self) -> Result<ProbedFixtureTrash<B::Bound>, QualificationError> {
        self.recheck(QualificationErrorKind::Probe)?;
        let Self {
            target,
            top_dir,
            target_path,
            xdg_data_home,
            backend,
            runtime,
            admitted_euid,
            containment,
        } = self;
        let native_target = PrivateNativeTarget::new(
            containment.target_identity,
            containment.parent_identity,
            &containment.parent_fd,
            &target_path,
        )?;
        let backend = backend.probe_and_bind(native_target).map_err(|error| {
            QualificationError::new(QualificationErrorKind::Probe, error.to_string())
        })?;
        let scope = FixtureTrashScope {
            target,
            top_dir,
            target_path,
            xdg_data_home,
            backend,
            runtime,
            admitted_euid,
            containment,
        };
        scope.recheck(QualificationErrorKind::Probe)?;
        Ok(ProbedFixtureTrash { scope })
    }
}

impl<B> FixtureTrashScope<B> {
    fn recheck(&self, kind: QualificationErrorKind) -> Result<(), QualificationError> {
        verify_runtime_binding(
            self.runtime.as_ref(),
            self.admitted_euid,
            &self.xdg_data_home,
            kind,
        )?;
        self.target.verify_unchanged().map_err(|error| {
            QualificationError::new(kind, format!("fixture baseline changed: {error}"))
        })?;
        self.xdg_data_home.verify(&[], "XDG data home")?;
        if !self
            .target
            .matches_manifest_derived_target(&self.target_path)
        {
            return Err(QualificationError::new(
                kind,
                "private platform target no longer matches fixture binding",
            ));
        }
        self.containment
            .verify(&self.top_dir, &self.target_path)
            .map_err(|error| {
                QualificationError::new(kind, format!("containment recheck failed: {error}"))
            })
    }
}

fn verify_runtime_binding(
    runtime: &dyn RuntimeInspector,
    admitted_euid: u32,
    xdg_data_home: &PrivateDirectory,
    kind: QualificationErrorKind,
) -> Result<(), QualificationError> {
    let euid = runtime.effective_uid()?;
    if euid != admitted_euid || !runtime.capability_sets()?.is_empty() {
        return Err(QualificationError::new(
            kind,
            "exact ordinary-user runtime evidence changed",
        ));
    }
    let configured = runtime
        .xdg_data_home()
        .ok_or_else(|| QualificationError::new(kind, "XDG_DATA_HOME disappeared"))?;
    let configured = PathBuf::from(configured)
        .canonicalize()
        .map_err(|error| QualificationError::io("canonicalize XDG_DATA_HOME", error))?;
    if configured != xdg_data_home.path {
        return Err(QualificationError::new(kind, "XDG_DATA_HOME changed"));
    }
    xdg_data_home.verify_path_binding("XDG data home")
}

fn verify_runtime_after_submit(
    runtime: &dyn RuntimeInspector,
    admitted_euid: u32,
    xdg_data_home: &PrivateDirectory,
) -> Result<(), QualificationError> {
    let euid = runtime.effective_uid()?;
    if euid != admitted_euid || !runtime.capability_sets()?.is_empty() {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            "exact ordinary-user runtime evidence changed after submission",
        ));
    }
    let configured = runtime.xdg_data_home().ok_or_else(|| {
        QualificationError::new(
            QualificationErrorKind::Evidence,
            "XDG_DATA_HOME disappeared after submission",
        )
    })?;
    let configured = PathBuf::from(configured)
        .canonicalize()
        .map_err(|error| QualificationError::io("canonicalize XDG_DATA_HOME", error))?;
    if configured != xdg_data_home.path {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            "XDG_DATA_HOME changed after submission",
        ));
    }
    let current = NativeIdentity::from_fd(&xdg_data_home.fd)?;
    if !current.same_directory_object_and_policy(xdg_data_home.identity) {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            "held XDG data home identity or access policy changed after submission",
        ));
    }
    let reopened = open_absolute_directory(&xdg_data_home.path)?;
    if !NativeIdentity::from_fd(&reopened)?.same_directory_object_and_policy(xdg_data_home.identity)
    {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            "XDG data home pathname was rebound after submission",
        ));
    }
    Ok(())
}

struct ProbedFixtureTrash<B: BoundTrashBackend> {
    scope: FixtureTrashScope<B>,
}

impl<B: BoundTrashBackend> ProbedFixtureTrash<B> {
    fn arm(self, evidence_root: &Path) -> Result<ArmedFixtureTrash<B>, QualificationError> {
        self.scope.recheck(QualificationErrorKind::Admission)?;
        let evidence_root = PrivateDirectory::admit_empty(
            evidence_root,
            self.scope.admitted_euid,
            "evidence root",
        )?;
        ensure_disjoint(
            &self.scope.top_dir,
            &self.scope.xdg_data_home.path,
            Some(&evidence_root.path),
        )?;
        if MountRecord::for_path(&evidence_root.path)?.mount_id
            != self.scope.containment.mount.mount_id
        {
            return Err(QualificationError::new(
                QualificationErrorKind::Admission,
                "evidence root must share the qualified fixture mount",
            ));
        }
        self.scope.recheck(QualificationErrorKind::Admission)?;
        Ok(ArmedFixtureTrash {
            scope: self.scope,
            evidence_root,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrashOutcomeKind {
    NotSubmittedStale,
    PlatformReportedSourceRemoved,
    Indeterminate,
}

#[derive(Debug, PartialEq, Eq)]
struct TrashOutcome {
    kind: TrashOutcomeKind,
    detail: String,
}

struct ArmedFixtureTrash<B: BoundTrashBackend> {
    scope: FixtureTrashScope<B>,
    evidence_root: PrivateDirectory,
}

impl<B: BoundTrashBackend> ArmedFixtureTrash<B> {
    fn trash(self) -> Result<TrashOutcome, QualificationError> {
        self.trash_with_hooks(|_| {}, |_| {})
    }

    fn trash_with_hooks<F, G>(
        self,
        after_intent: F,
        after_submission: G,
    ) -> Result<TrashOutcome, QualificationError>
    where
        F: FnOnce(&DurableIntentToken),
        G: FnOnce(&DurableIntentToken),
    {
        self.trash_with_terminal_hooks(after_intent, after_submission, || {}, || {})
    }

    fn trash_with_terminal_hooks<F, G, H, I>(
        self,
        after_intent: F,
        after_submission: G,
        before_final_sync: H,
        after_final_sync: I,
    ) -> Result<TrashOutcome, QualificationError>
    where
        F: FnOnce(&DurableIntentToken),
        G: FnOnce(&DurableIntentToken),
        H: FnOnce(),
        I: FnOnce(),
    {
        if let Err(error) = self
            .scope
            .recheck(QualificationErrorKind::StaleBeforeSubmit)
        {
            return Ok(TrashOutcome {
                kind: TrashOutcomeKind::NotSubmittedStale,
                detail: error.to_string(),
            });
        }

        let intent = write_intent(&self.evidence_root, &self.scope)?;

        // Audit durability can take time. Repeat the full check immediately
        // after fsync and before the one and only qualification submission.
        if let Err(error) = self
            .scope
            .recheck(QualificationErrorKind::StaleBeforeSubmit)
        {
            let outcome = TrashOutcome {
                kind: TrashOutcomeKind::NotSubmittedStale,
                detail: error.to_string(),
            };
            return persist_outcome(&self.evidence_root, &intent, outcome);
        }

        after_intent(&intent);
        if let Err(error) = intent.verify() {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                format!(
                    "durable intent verification failed before submission; reconciliation is required: {error}"
                ),
            ));
        }
        if let Err(error) = self
            .scope
            .recheck(QualificationErrorKind::StaleBeforeSubmit)
        {
            let outcome = TrashOutcome {
                kind: TrashOutcomeKind::NotSubmittedStale,
                detail: format!(
                    "final recheck failed after durable intent; submission was not attempted: {error}"
                ),
            };
            return persist_outcome(&self.evidence_root, &intent, outcome);
        }

        let xdg_before = match self.scope.xdg_data_home.held_snapshot("XDG data home") {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let outcome = TrashOutcome {
                    kind: TrashOutcomeKind::NotSubmittedStale,
                    detail: format!(
                        "XDG observation failed before submission; submission was not attempted: {error}"
                    ),
                };
                return persist_outcome(&self.evidence_root, &intent, outcome);
            }
        };
        let FixtureTrashScope {
            target,
            top_dir,
            target_path,
            xdg_data_home,
            backend,
            runtime,
            admitted_euid,
            containment,
        } = self.scope;
        let platform_result = backend.submit_trash(&intent);
        after_submission(&intent);
        intent.verify().map_err(|error| {
            QualificationError::new(
                QualificationErrorKind::Evidence,
                format!(
                    "durable intent verification failed after submission; reconciliation is required: {error}"
                ),
            )
        })?;
        let runtime_stable =
            verify_runtime_after_submit(runtime.as_ref(), admitted_euid, &xdg_data_home).is_ok();
        let xdg_changed = xdg_data_home
            .held_snapshot_after_content_change("XDG data home")
            .is_ok_and(|snapshot| snapshot.entries != xdg_before.entries);
        let source_removed = target.verify_target_removed_and_rest_unchanged().is_ok();
        let source_unchanged =
            target.verify_unchanged().is_ok() && containment.verify(&top_dir, &target_path).is_ok();

        let outcome = match platform_result {
            BackendSubmission::ReportedSuccess
                if runtime_stable && xdg_changed && source_removed =>
            {
                TrashOutcome {
                    kind: TrashOutcomeKind::PlatformReportedSourceRemoved,
                    detail: "platform reported Trash success, the exact fixture source was removed, the remaining fixture matched its oracle, and the isolated XDG namespace changed".to_string(),
                }
            }
            BackendSubmission::ReportedSuccess => TrashOutcome {
                kind: TrashOutcomeKind::Indeterminate,
                detail: format!(
                    "Trash backend reported success without complete qualification evidence: runtime_stable={runtime_stable} xdg_changed={xdg_changed} source_removed={source_removed}"
                ),
            },
            BackendSubmission::ReportedFailure(error) => TrashOutcome {
                kind: TrashOutcomeKind::Indeterminate,
                detail: format!(
                    "Trash backend reported failure after submission; source_unchanged={source_unchanged}, but reconciliation remains conservative: {error}"
                ),
            },
            BackendSubmission::Ambiguous(error) => TrashOutcome {
                kind: TrashOutcomeKind::Indeterminate,
                detail: format!(
                    "Trash backend returned a contradictory or incomplete result; source_unchanged={source_unchanged}; reconciliation is required: {error}"
                ),
            },
            BackendSubmission::NotSubmitted(error) => TrashOutcome {
                kind: TrashOutcomeKind::Indeterminate,
                detail: format!(
                    "Trash backend did not submit; source_unchanged={source_unchanged}, but this post-intent seam does not promote that report without a durable no-submit attestation: {error}"
                ),
            },
        };
        persist_outcome_with_hooks(
            &self.evidence_root,
            &intent,
            outcome,
            before_final_sync,
            after_final_sync,
        )
    }
}

fn persist_outcome(
    evidence_root: &PrivateDirectory,
    intent: &DurableIntentToken,
    outcome: TrashOutcome,
) -> Result<TrashOutcome, QualificationError> {
    persist_outcome_with_hooks(evidence_root, intent, outcome, || {}, || {})
}

fn persist_outcome_with_hooks<F, G>(
    evidence_root: &PrivateDirectory,
    intent: &DurableIntentToken,
    outcome: TrashOutcome,
    before_final_sync: F,
    after_final_sync: G,
) -> Result<TrashOutcome, QualificationError>
where
    F: FnOnce(),
    G: FnOnce(),
{
    write_outcome_with_hooks(
        evidence_root,
        intent,
        &outcome,
        before_final_sync,
        after_final_sync,
    )?;
    Ok(outcome)
}

fn write_intent<B: BoundTrashBackend>(
    evidence_root: &PrivateDirectory,
    scope: &FixtureTrashScope<B>,
) -> Result<DurableIntentToken, QualificationError> {
    let content = format!(
        "schema=sweepx.test-linux-trash-intent/v1\nentry_id={}\nmanifest_sha256={}\ndevice={}:{}\ninode={}\nmount_id={}\nfilesystem={}\neuid={}\ncap_permitted=0\ncap_effective=0\ncap_ambient=0\nxdg_data_home={}\nadapter={}\ncan_trash=true\nmode=trash\n",
        scope.target.entry_id(),
        scope.target.manifest_digest(),
        scope.containment.target_identity.device_major,
        scope.containment.target_identity.device_minor,
        scope.containment.target_identity.inode,
        scope.containment.target_identity.mount_id,
        scope.containment.mount.filesystem,
        scope.admitted_euid,
        scope.xdg_data_home.path.display(),
        scope.backend.adapter_label(),
    );
    let (file, file_identity) =
        create_new_synced(evidence_root, INTENT_FILE, content.as_bytes(), &[])?;
    let evidence_snapshot = evidence_root.held_snapshot("evidence root")?;
    Ok(DurableIntentToken {
        file,
        file_identity,
        content_len: content.len(),
        content_digest: Sha256::digest(content.as_bytes()).into(),
        evidence_root: evidence_root.duplicate("evidence root")?,
        evidence_snapshot,
    })
}

fn write_outcome_with_hooks<F, G>(
    evidence_root: &PrivateDirectory,
    intent: &DurableIntentToken,
    outcome: &TrashOutcome,
    before_final_sync: F,
    after_final_sync: G,
) -> Result<(), QualificationError>
where
    F: FnOnce(),
    G: FnOnce(),
{
    intent.verify()?;
    let content = format!(
        "schema=sweepx.test-linux-trash-outcome/v1\nstatus={:?}\ndetail={}\n",
        outcome.kind, outcome.detail
    );
    let (outcome_file, outcome_identity) = create_new_synced(
        evidence_root,
        OUTCOME_FILE,
        content.as_bytes(),
        &[INTENT_FILE],
    )?;
    verify_terminal_records(
        evidence_root,
        intent,
        &outcome_file,
        outcome_identity,
        content.as_bytes(),
    )?;

    // The final durability barrier must commit exactly the two records that
    // were verified above. Recheck immediately before the barrier to close a
    // replacement window, then recheck again after it so a namespace change
    // concurrent with fsync cannot be accepted as durable terminal evidence.
    before_final_sync();
    verify_terminal_records(
        evidence_root,
        intent,
        &outcome_file,
        outcome_identity,
        content.as_bytes(),
    )?;
    sync_held_directory(evidence_root)?;
    after_final_sync();
    verify_terminal_records(
        evidence_root,
        intent,
        &outcome_file,
        outcome_identity,
        content.as_bytes(),
    )
}

fn verify_terminal_records(
    evidence_root: &PrivateDirectory,
    intent: &DurableIntentToken,
    outcome_file: &File,
    outcome_identity: NativeIdentity,
    outcome_content: &[u8],
) -> Result<(), QualificationError> {
    intent.verify_record()?;
    verify_named_record(
        evidence_root,
        OUTCOME_FILE,
        outcome_file,
        outcome_identity,
        outcome_content,
    )?;
    evidence_root
        .verify(&[INTENT_FILE, OUTCOME_FILE], "evidence root")
        .map_err(|error| {
            QualificationError::new(
                QualificationErrorKind::Evidence,
                format!("terminal evidence root binding failed: {error}"),
            )
        })
}

fn verify_named_record(
    parent: &PrivateDirectory,
    name: &str,
    held_file: &File,
    expected_identity: NativeIdentity,
    expected_content: &[u8],
) -> Result<(), QualificationError> {
    if NativeIdentity::from_fd(held_file)? != expected_identity {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            format!("held {name} identity changed"),
        ));
    }
    let named_fd = open_readonly_beneath(&parent.fd, Path::new(name))?;
    if NativeIdentity::from_fd(&named_fd)? != expected_identity {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            format!("{name} no longer names the created record"),
        ));
    }
    let named_file = File::from(named_fd);
    let mut bytes = vec![0; expected_content.len()];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = named_file
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(|error| QualificationError::io(&format!("read {name}"), error))?;
        if read == 0 {
            return Err(QualificationError::new(
                QualificationErrorKind::Evidence,
                format!("{name} was truncated"),
            ));
        }
        offset += read;
    }
    if bytes != expected_content || NativeIdentity::from_fd(&named_file)? != expected_identity {
        return Err(QualificationError::new(
            QualificationErrorKind::Evidence,
            format!("{name} changed during verification"),
        ));
    }
    Ok(())
}

fn sync_held_directory(directory: &PrivateDirectory) -> Result<(), QualificationError> {
    let directory_path = path_to_cstring(&directory.fd_path())?;
    // SAFETY: the procfs path refers to the held directory descriptor.
    let directory_fd = unsafe {
        libc::open(
            directory_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    let directory_fd = owned_fd(directory_fd, "open held evidence directory for fsync")?;
    // SAFETY: fsync accepts this live read-only directory descriptor.
    if unsafe { libc::fsync(directory_fd.as_raw_fd()) } != 0 {
        return Err(QualificationError::io(
            "fsync evidence directory",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn create_new_synced(
    parent: &PrivateDirectory,
    name: &str,
    content: &[u8],
    expected_before: &[&str],
) -> Result<(File, NativeIdentity), QualificationError> {
    parent.verify(expected_before, "evidence root")?;
    let name = CString::new(name).expect("fixed evidence filename has no NUL");
    // SAFETY: parent is a held verified directory, name is one fixed basename,
    // and O_EXCL|O_NOFOLLOW prevents replacement or symlink traversal.
    let fd = unsafe {
        libc::openat(
            parent.fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    let fd = owned_fd(fd, "create evidence record")?;
    let mut file = File::from(fd);
    file.write_all(content)
        .map_err(|error| QualificationError::io("write evidence record", error))?;
    file.sync_all()
        .map_err(|error| QualificationError::io("fsync evidence record", error))?;
    let file_identity = NativeIdentity::from_fd(&file)?;
    // O_PATH descriptors cannot be fsync'd. Reopen this held descriptor as a
    // read-only directory descriptor, without resolving the original path.
    sync_held_directory(parent)?;
    let mut expected_after = expected_before.to_vec();
    expected_after.push(name.to_str().expect("fixed evidence name is UTF-8"));
    parent.verify(&expected_after, "evidence root")?;
    Ok((file, file_identity))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::ffi::CStr;
    use std::process::Command;
    use std::rc::Rc;

    use sweepx_fixtures::{generate_from_manifest, linux_p4_trash_manifest};
    use tempfile::TempDir;

    use super::*;

    const TARGET_ENTRY_ID: &str = "trash-target-file";

    #[derive(Clone)]
    struct FakeRuntime {
        euid: Rc<Cell<u32>>,
        capabilities: Rc<Cell<CapabilitySets>>,
        xdg: Rc<std::cell::RefCell<Option<OsString>>>,
    }

    impl FakeRuntime {
        fn ordinary(xdg: &Path) -> Self {
            let owner = fs::symlink_metadata(xdg)
                .expect("inspect fake XDG owner")
                .uid();
            Self {
                euid: Rc::new(Cell::new(owner)),
                capabilities: Rc::new(Cell::new(CapabilitySets {
                    permitted: 0,
                    effective: 0,
                    ambient: 0,
                })),
                xdg: Rc::new(std::cell::RefCell::new(Some(xdg.as_os_str().to_owned()))),
            }
        }
    }

    impl RuntimeInspector for FakeRuntime {
        fn effective_uid(&self) -> Result<u32, QualificationError> {
            Ok(self.euid.get())
        }

        fn capability_sets(&self) -> Result<CapabilitySets, QualificationError> {
            Ok(self.capabilities.get())
        }

        fn xdg_data_home(&self) -> Option<OsString> {
            self.xdg.borrow().clone()
        }
    }

    #[derive(Clone, Copy)]
    enum FakeBehavior {
        ErrorUnchanged,
        ReportedSuccessUnchanged,
    }

    struct FakeBackend {
        behavior: FakeBehavior,
        probe_calls: Rc<Cell<usize>>,
        submit_calls: Rc<Cell<usize>>,
        intent_observed: Rc<Cell<bool>>,
        probe_error: Option<BackendError>,
    }

    struct BoundFakeBackend {
        behavior: FakeBehavior,
        _target: PrivateNativeTarget,
        submit_calls: Rc<Cell<usize>>,
        intent_observed: Rc<Cell<bool>>,
    }

    struct FakeGioCalls {
        can_trash: Result<bool, BackendError>,
        submission: BackendSubmission,
        probe_calls: Rc<Cell<usize>>,
        trash_calls: Rc<Cell<usize>>,
    }

    struct RebindGioParentOnProbe {
        top_dir: PathBuf,
        trash_calls: Rc<Cell<usize>>,
    }

    impl gio_trash::GioCalls for RebindGioParentOnProbe {
        fn can_trash(&self, _path: &CStr) -> Result<bool, BackendError> {
            let parent = self.top_dir.parent().expect("fixture top has a parent");
            let displaced = parent.join("displaced-linux-trash-top");
            fs::rename(&self.top_dir, &displaced).expect("displace admitted target parent");
            fs::create_dir(&self.top_dir).expect("replace target parent pathname");
            fs::set_permissions(&self.top_dir, fs::Permissions::from_mode(0o700))
                .expect("make replacement parent private");
            Ok(true)
        }

        fn trash(&self, _path: &CStr) -> BackendSubmission {
            self.trash_calls.set(self.trash_calls.get() + 1);
            BackendSubmission::ReportedSuccess
        }
    }

    impl gio_trash::GioCalls for FakeGioCalls {
        fn can_trash(&self, _path: &CStr) -> Result<bool, BackendError> {
            self.probe_calls.set(self.probe_calls.get() + 1);
            match &self.can_trash {
                Ok(value) => Ok(*value),
                Err(error) => Err(BackendError {
                    domain: error.domain,
                    code: error.code,
                    class: error.class,
                    detail: error.detail.clone(),
                }),
            }
        }

        fn trash(&self, _path: &CStr) -> BackendSubmission {
            self.trash_calls.set(self.trash_calls.get() + 1);
            match &self.submission {
                BackendSubmission::ReportedSuccess => BackendSubmission::ReportedSuccess,
                BackendSubmission::ReportedFailure(error) => {
                    BackendSubmission::ReportedFailure(clone_backend_error(error))
                }
                BackendSubmission::Ambiguous(error) => {
                    BackendSubmission::Ambiguous(clone_backend_error(error))
                }
                BackendSubmission::NotSubmitted(error) => {
                    BackendSubmission::NotSubmitted(clone_backend_error(error))
                }
            }
        }
    }

    fn clone_backend_error(error: &BackendError) -> BackendError {
        BackendError {
            domain: error.domain,
            code: error.code,
            class: error.class,
            detail: error.detail.clone(),
        }
    }

    impl FakeBackend {
        fn new(behavior: FakeBehavior) -> Self {
            Self {
                behavior,
                probe_calls: Rc::new(Cell::new(0)),
                submit_calls: Rc::new(Cell::new(0)),
                intent_observed: Rc::new(Cell::new(false)),
                probe_error: None,
            }
        }
    }

    impl TrashBackend for FakeBackend {
        type Bound = BoundFakeBackend;

        fn probe_and_bind(self, target: PrivateNativeTarget) -> Result<Self::Bound, BackendError> {
            self.probe_calls.set(self.probe_calls.get() + 1);
            if let Some(error) = self.probe_error {
                return Err(error);
            }
            Ok(BoundFakeBackend {
                behavior: self.behavior,
                _target: target,
                submit_calls: self.submit_calls,
                intent_observed: self.intent_observed,
            })
        }
    }

    impl BoundTrashBackend for BoundFakeBackend {
        fn submit_trash(self, intent: &DurableIntentToken) -> BackendSubmission {
            assert!(
                intent.verify().is_ok(),
                "submission requires a verified intent"
            );
            self.intent_observed.set(true);
            self.submit_calls.set(self.submit_calls.get() + 1);
            match self.behavior {
                FakeBehavior::ErrorUnchanged => {
                    BackendSubmission::ReportedFailure(BackendError::synthetic("synthetic failure"))
                }
                FakeBehavior::ReportedSuccessUnchanged => BackendSubmission::ReportedSuccess,
            }
        }

        fn adapter_label(&self) -> &'static str {
            "fake-trash-backend"
        }
    }

    struct HarnessFixture {
        _temp: TempDir,
        generated: sweepx_fixtures::GeneratedFixture,
        xdg: PathBuf,
        evidence: PathBuf,
    }

    impl HarnessFixture {
        fn new() -> Self {
            let temp = TempDir::new().expect("temp root");
            let fixture_root = temp.path().join("fixture-root");
            let xdg = temp.path().join("xdg-data");
            let evidence = temp.path().join("evidence");
            fs::create_dir(&fixture_root).expect("fixture root");
            fs::create_dir(&xdg).expect("XDG root");
            fs::create_dir(&evidence).expect("evidence root");
            fs::set_permissions(&fixture_root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&xdg, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700)).unwrap();
            let filesystem = MountRecord::for_path(&fixture_root)
                .expect("fixture filesystem")
                .filesystem;
            assert!(
                is_qualified_local_filesystem(&filesystem),
                "default fake tests require an ext4/xfs/btrfs temp directory, got {filesystem}"
            );
            let manifest = linux_p4_trash_manifest(filesystem.clone());
            let generated =
                generate_from_manifest(&fixture_root, &manifest).expect("generate fixture");
            Self {
                _temp: temp,
                generated,
                xdg,
                evidence,
            }
        }

        fn scope(
            &self,
            backend: FakeBackend,
            runtime: FakeRuntime,
        ) -> FixtureTrashScope<FakeBackend> {
            FixtureTrashScope::admit_with(
                &self.generated,
                TARGET_ENTRY_ID,
                &self.xdg,
                backend,
                Box::new(runtime),
            )
            .expect("admit fixture scope")
        }
    }

    #[derive(Clone, Copy)]
    enum TerminalEvidenceTamper {
        ReplaceIntent,
        ReplaceOutcome,
        RebindEvidenceRoot,
    }

    fn tamper_terminal_evidence(tamper: TerminalEvidenceTamper, evidence_root: &Path) {
        match tamper {
            TerminalEvidenceTamper::ReplaceIntent => {
                let path = evidence_root.join(INTENT_FILE);
                fs::remove_file(&path).expect("unlink verified intent");
                fs::write(path, b"replacement intent").expect("recreate intent");
            }
            TerminalEvidenceTamper::ReplaceOutcome => {
                let path = evidence_root.join(OUTCOME_FILE);
                fs::remove_file(&path).expect("unlink verified outcome");
                fs::write(path, b"replacement outcome").expect("recreate outcome");
            }
            TerminalEvidenceTamper::RebindEvidenceRoot => {
                let parent = evidence_root.parent().expect("evidence root parent");
                let replacement = parent.join("evidence-root-replacement");
                let displaced = parent.join("evidence-root-displaced");
                fs::create_dir(&replacement).expect("create replacement evidence root");
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700))
                    .expect("make replacement evidence root private");
                fs::rename(evidence_root, &displaced).expect("displace admitted evidence root");
                fs::rename(replacement, evidence_root).expect("rebind evidence root path");
            }
        }
    }

    fn assert_terminal_evidence_tamper_fails(
        tamper: TerminalEvidenceTamper,
        after_final_sync: bool,
    ) {
        let fixture = HarnessFixture::new();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let armed = fixture
            .scope(backend, FakeRuntime::ordinary(&fixture.xdg))
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap();

        let result = if after_final_sync {
            armed.trash_with_terminal_hooks(
                |_| {},
                |_| {},
                || {},
                || tamper_terminal_evidence(tamper, &fixture.evidence),
            )
        } else {
            armed.trash_with_terminal_hooks(
                |_| {},
                |_| {},
                || tamper_terminal_evidence(tamper, &fixture.evidence),
                || {},
            )
        };

        let error = result.expect_err("terminal evidence tampering must fail closed");
        assert_eq!(error.kind, QualificationErrorKind::Evidence);
        assert_eq!(submit_calls.get(), 1);
        assert!(
            fixture
                .generated
                .top_dir()
                .join("trash-target.txt")
                .is_file(),
            "evidence fault injection must not mutate the fixture target"
        );
    }

    #[test]
    fn admission_rejects_root_and_nonempty_capability_sets() {
        let fixture = HarnessFixture::new();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        runtime.euid.set(0);
        let error = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(runtime),
        )
        .err()
        .expect("root must fail");
        assert_eq!(error.kind, QualificationErrorKind::Admission);

        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        runtime.capabilities.set(CapabilitySets {
            permitted: 1,
            effective: 0,
            ambient: 0,
        });
        let error = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(runtime),
        )
        .err()
        .expect("capability must fail");
        assert_eq!(error.kind, QualificationErrorKind::Admission);
    }

    #[test]
    fn admission_rejects_xdg_alias_non_private_and_nonempty() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.evidence);
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        assert!(
            FixtureTrashScope::admit_with(
                &fixture.generated,
                TARGET_ENTRY_ID,
                &fixture.xdg,
                backend,
                Box::new(runtime),
            )
            .is_err()
        );

        fs::set_permissions(&fixture.xdg, fs::Permissions::from_mode(0o755)).unwrap();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        assert!(
            FixtureTrashScope::admit_with(
                &fixture.generated,
                TARGET_ENTRY_ID,
                &fixture.xdg,
                backend,
                Box::new(runtime),
            )
            .is_err()
        );

        fs::set_permissions(&fixture.xdg, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(fixture.xdg.join("unexpected"), b"x").unwrap();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        assert!(
            FixtureTrashScope::admit_with(
                &fixture.generated,
                TARGET_ENTRY_ID,
                &fixture.xdg,
                backend,
                Box::new(runtime),
            )
            .is_err()
        );
    }

    #[test]
    fn probe_failure_never_submits() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let mut backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        backend.probe_error = Some(BackendError {
            domain: 0,
            code: 15,
            class: BackendErrorClass::NotSupported,
            detail: "can-trash false".to_string(),
        });
        let probe_calls = Rc::clone(&backend.probe_calls);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let error = fixture
            .scope(backend, runtime)
            .probe()
            .err()
            .expect("probe must fail");
        assert_eq!(error.kind, QualificationErrorKind::Probe);
        assert_eq!(probe_calls.get(), 1);
        assert_eq!(submit_calls.get(), 0);
    }

    #[test]
    fn gio_backend_unavailable_never_submits() {
        let fixture = HarnessFixture::new();
        let loader_calls = Rc::new(Cell::new(0));
        let observed_loader_calls = Rc::clone(&loader_calls);
        let backend = gio_trash::GioTrashBackend::with_loader(move || {
            observed_loader_calls.set(observed_loader_calls.get() + 1);
            Err::<FakeGioCalls, _>(BackendError::unavailable("GIO runtime unavailable"))
        });
        let error = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(FakeRuntime::ordinary(&fixture.xdg)),
        )
        .expect("admit fixture scope")
        .probe()
        .err()
        .expect("unavailable backend must fail at probe");
        assert_eq!(error.kind, QualificationErrorKind::Probe);
        assert!(error.detail.contains("GIO runtime unavailable"));
        assert_eq!(loader_calls.get(), 1);
        assert!(
            fixture
                .generated
                .top_dir()
                .join("trash-target.txt")
                .is_file()
        );
        assert!(!fixture.evidence.join(INTENT_FILE).exists());
    }

    #[test]
    fn gio_can_trash_false_never_submits() {
        let fixture = HarnessFixture::new();
        let probe_calls = Rc::new(Cell::new(0));
        let trash_calls = Rc::new(Cell::new(0));
        let calls = FakeGioCalls {
            can_trash: Ok(false),
            submission: BackendSubmission::ReportedSuccess,
            probe_calls: Rc::clone(&probe_calls),
            trash_calls: Rc::clone(&trash_calls),
        };
        let backend = gio_trash::GioTrashBackend::with_loader(move || Ok(calls));
        let error = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(FakeRuntime::ordinary(&fixture.xdg)),
        )
        .expect("admit fixture scope")
        .probe()
        .err()
        .expect("can-trash=false must fail at probe");
        assert_eq!(error.kind, QualificationErrorKind::Probe);
        assert!(error.detail.contains("NotSupported"));
        assert_eq!(probe_calls.get(), 1);
        assert_eq!(trash_calls.get(), 0);
        assert!(!fixture.evidence.join(INTENT_FILE).exists());
    }

    fn assert_gio_submitted_result_is_indeterminate(submission: BackendSubmission) -> String {
        let fixture = HarnessFixture::new();
        let probe_calls = Rc::new(Cell::new(0));
        let trash_calls = Rc::new(Cell::new(0));
        let calls = FakeGioCalls {
            can_trash: Ok(true),
            submission,
            probe_calls: Rc::clone(&probe_calls),
            trash_calls: Rc::clone(&trash_calls),
        };
        let backend = gio_trash::GioTrashBackend::with_loader(move || Ok(calls));
        let outcome = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(FakeRuntime::ordinary(&fixture.xdg)),
        )
        .expect("admit fixture scope")
        .probe()
        .expect("probe GIO backend")
        .arm(&fixture.evidence)
        .expect("arm fixture scope")
        .trash()
        .expect("record conservative outcome");
        assert_eq!(outcome.kind, TrashOutcomeKind::Indeterminate);
        assert_eq!(probe_calls.get(), 1);
        assert_eq!(trash_calls.get(), 1);
        assert!(fixture.evidence.join(INTENT_FILE).is_file());
        assert!(fixture.evidence.join(OUTCOME_FILE).is_file());
        assert!(
            fixture
                .generated
                .top_dir()
                .join("trash-target.txt")
                .is_file(),
            "mocked failure or ambiguity must never trigger a fallback mutation"
        );
        outcome.detail
    }

    #[test]
    fn gio_not_supported_after_submit_is_indeterminate_and_never_falls_back() {
        let detail = assert_gio_submitted_result_is_indeterminate(
            BackendSubmission::ReportedFailure(BackendError {
                domain: 9,
                code: 15,
                class: BackendErrorClass::NotSupported,
                detail: "synthetic G_IO_ERROR_NOT_SUPPORTED".to_string(),
            }),
        );
        assert!(detail.contains("NotSupported"));
    }

    #[test]
    fn gio_exdev_after_submit_is_indeterminate_and_never_falls_back() {
        let detail = assert_gio_submitted_result_is_indeterminate(
            BackendSubmission::ReportedFailure(BackendError {
                domain: 9,
                code: libc::EXDEV,
                class: BackendErrorClass::Other,
                detail: "synthetic cross-device GIO failure".to_string(),
            }),
        );
        assert!(detail.contains(&format!("code={}", libc::EXDEV)));
    }

    #[test]
    fn gio_generic_failure_is_indeterminate_and_never_falls_back() {
        let detail = assert_gio_submitted_result_is_indeterminate(
            BackendSubmission::ReportedFailure(BackendError {
                domain: 9,
                code: 13,
                class: BackendErrorClass::Other,
                detail: "synthetic GIO failure".to_string(),
            }),
        );
        assert!(detail.contains("synthetic GIO failure"));
    }

    #[test]
    fn gio_ambiguous_result_is_indeterminate_and_never_falls_back() {
        let detail = assert_gio_submitted_result_is_indeterminate(BackendSubmission::Ambiguous(
            BackendError::ambiguous("contradictory GIO result"),
        ));
        assert!(detail.contains("reconciliation is required"));
    }

    #[test]
    fn gio_parent_path_rebind_is_rejected_before_submission() {
        let fixture = HarnessFixture::new();
        let trash_calls = Rc::new(Cell::new(0));
        let calls = RebindGioParentOnProbe {
            top_dir: fixture.generated.top_dir().to_path_buf(),
            trash_calls: Rc::clone(&trash_calls),
        };
        let backend = gio_trash::GioTrashBackend::with_loader(move || Ok(calls));
        let error = FixtureTrashScope::admit_with(
            &fixture.generated,
            TARGET_ENTRY_ID,
            &fixture.xdg,
            backend,
            Box::new(FakeRuntime::ordinary(&fixture.xdg)),
        )
        .expect("admit fixture scope")
        .probe()
        .err()
        .expect("rebound GIO parent must fail before submission");
        assert_eq!(error.kind, QualificationErrorKind::Probe);
        assert_eq!(trash_calls.get(), 0);
        assert!(!fixture.evidence.join(INTENT_FILE).exists());
    }

    #[test]
    fn durable_intent_precedes_exactly_one_fake_submission() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ReportedSuccessUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let intent_observed = Rc::clone(&backend.intent_observed);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .expect("probe")
            .arm(&fixture.evidence)
            .expect("arm")
            .trash()
            .expect("trash");
        assert_eq!(outcome.kind, TrashOutcomeKind::Indeterminate);
        assert_eq!(submit_calls.get(), 1);
        assert!(intent_observed.get());
        assert!(fixture.evidence.join(INTENT_FILE).is_file());
        assert!(fixture.evidence.join(OUTCOME_FILE).is_file());
    }

    #[test]
    fn backend_error_with_exact_source_is_indeterminate_without_native_proof() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash()
            .unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::Indeterminate);
        assert_eq!(submit_calls.get(), 1);
        assert!(
            fixture
                .generated
                .top_dir()
                .join("trash-target.txt")
                .is_file()
        );
    }

    #[test]
    fn backend_error_with_changed_runtime_is_indeterminate_and_never_retried() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let changed_runtime = runtime.clone();
        let admitted_euid = runtime.euid.get();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(
                |_| {},
                move |_| changed_runtime.euid.set(admitted_euid.saturating_add(1)),
            )
            .unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::Indeterminate);
        assert_eq!(submit_calls.get(), 1);
    }

    #[test]
    fn nonzero_uid_change_after_durable_intent_is_terminal_without_submission() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let changed_runtime = runtime.clone();
        let changed_euid = runtime.euid.get().checked_add(1).expect("test uid");
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(move |_| changed_runtime.euid.set(changed_euid), |_| {})
            .unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::NotSubmittedStale);
        assert_eq!(submit_calls.get(), 0);
        assert!(fixture.evidence.join(INTENT_FILE).is_file());
        assert!(fixture.evidence.join(OUTCOME_FILE).is_file());
    }

    #[test]
    fn xdg_rebind_after_durable_intent_is_terminal_without_submission() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let changed_runtime = runtime.clone();
        let rebound = fixture.evidence.as_os_str().to_owned();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(
                move |_| {
                    changed_runtime.xdg.replace(Some(rebound));
                },
                |_| {},
            )
            .unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::NotSubmittedStale);
        assert_eq!(submit_calls.get(), 0);
        assert!(fixture.evidence.join(OUTCOME_FILE).is_file());
    }

    #[test]
    fn replaced_intent_name_before_submission_requires_reconciliation() {
        let fixture = HarnessFixture::new();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let intent_path = fixture.evidence.join(INTENT_FILE);
        let error = fixture
            .scope(backend, FakeRuntime::ordinary(&fixture.xdg))
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(
                move |_| {
                    fs::remove_file(&intent_path).unwrap();
                    fs::write(&intent_path, b"replacement intent").unwrap();
                },
                |_| {},
            )
            .expect_err("tampered intent must not look terminal");
        assert_eq!(error.kind, QualificationErrorKind::Evidence);
        assert_eq!(submit_calls.get(), 0);
        assert!(!fixture.evidence.join(OUTCOME_FILE).exists());
    }

    #[test]
    fn replaced_intent_name_after_submission_requires_reconciliation_once() {
        let fixture = HarnessFixture::new();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let intent_path = fixture.evidence.join(INTENT_FILE);
        let error = fixture
            .scope(backend, FakeRuntime::ordinary(&fixture.xdg))
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(
                |_| {},
                move |_| {
                    fs::remove_file(&intent_path).unwrap();
                    fs::write(&intent_path, b"replacement intent").unwrap();
                },
            )
            .expect_err("tampered intent after submission must require recovery");
        assert_eq!(error.kind, QualificationErrorKind::Evidence);
        assert_eq!(submit_calls.get(), 1);
        assert!(!fixture.evidence.join(OUTCOME_FILE).exists());
    }

    #[test]
    fn terminal_persistence_failure_after_submission_is_an_error_once() {
        let fixture = HarnessFixture::new();
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let outcome_path = fixture.evidence.join(OUTCOME_FILE);
        let error = fixture
            .scope(backend, FakeRuntime::ordinary(&fixture.xdg))
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash_with_hooks(
                |_| {},
                move |_| fs::write(&outcome_path, b"adversarial collision").unwrap(),
            )
            .expect_err("terminal persistence failure must propagate");
        assert_eq!(error.kind, QualificationErrorKind::Evidence);
        assert_eq!(submit_calls.get(), 1);
    }

    #[test]
    fn fixed_terminal_names_are_rechecked_before_final_durability_barrier() {
        for tamper in [
            TerminalEvidenceTamper::ReplaceIntent,
            TerminalEvidenceTamper::ReplaceOutcome,
        ] {
            assert_terminal_evidence_tamper_fails(tamper, false);
        }
    }

    #[test]
    fn fixed_terminal_names_are_rechecked_after_final_durability_barrier() {
        for tamper in [
            TerminalEvidenceTamper::ReplaceIntent,
            TerminalEvidenceTamper::ReplaceOutcome,
        ] {
            assert_terminal_evidence_tamper_fails(tamper, true);
        }
    }

    #[test]
    fn evidence_root_rebind_around_final_durability_barrier_fails_closed() {
        assert_terminal_evidence_tamper_fails(TerminalEvidenceTamper::RebindEvidenceRoot, false);
        assert_terminal_evidence_tamper_fails(TerminalEvidenceTamper::RebindEvidenceRoot, true);
    }

    #[test]
    fn reported_success_without_mutation_is_indeterminate() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ReportedSuccessUnchanged);
        let outcome = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap()
            .trash()
            .unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::Indeterminate);
    }

    #[test]
    fn final_recheck_failure_does_not_submit() {
        let fixture = HarnessFixture::new();
        let runtime = FakeRuntime::ordinary(&fixture.xdg);
        let backend = FakeBackend::new(FakeBehavior::ErrorUnchanged);
        let submit_calls = Rc::clone(&backend.submit_calls);
        let armed = fixture
            .scope(backend, runtime)
            .probe()
            .unwrap()
            .arm(&fixture.evidence)
            .unwrap();
        fs::write(
            fixture.generated.top_dir().join("trash-target.txt"),
            b"replacement bytes",
        )
        .unwrap();
        let outcome = armed.trash().unwrap();
        assert_eq!(outcome.kind, TrashOutcomeKind::NotSubmittedStale);
        assert_eq!(submit_calls.get(), 0);
        assert!(!fixture.evidence.join(INTENT_FILE).exists());
    }

    /// This is the sole real OS mutation test. It is ignored unless a human
    /// explicitly starts it with `SWEEPX_RUN_REAL_GIO_TRASH=1`. The parent test
    /// creates a private temporary root and starts an isolated child with XDG
    /// configured before GLib initialization. The child refuses root/capabilities,
    /// nonempty XDG roots, unqualified filesystems, non-generated targets, and
    /// any isolation-root marker that does not name its actual parent process.
    #[test]
    #[ignore = "requires explicit opt-in; test generates an isolated child/XDG fixture"]
    fn real_gio_trash_only_generated_disposable_fixture() {
        if std::env::var_os("SWEEPX_REAL_GIO_CHILD").as_deref() == Some(std::ffi::OsStr::new("1")) {
            run_real_gio_trash_child();
            return;
        }
        assert_eq!(
            std::env::var_os("SWEEPX_RUN_REAL_GIO_TRASH").as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "set SWEEPX_RUN_REAL_GIO_TRASH=1 to create a disposable isolated child process"
        );

        let isolated_parent = std::env::current_dir().expect("current test directory");
        let isolated = tempfile::Builder::new()
            .prefix(".sweepx-real-gio-")
            .tempdir_in(isolated_parent)
            .expect("generated real-GIO isolation root");
        fs::set_permissions(isolated.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let xdg = isolated.path().join("xdg-data");
        fs::create_dir(&xdg).expect("generated isolated XDG_DATA_HOME");
        fs::set_permissions(&xdg, fs::Permissions::from_mode(0o700)).unwrap();
        let parent_pid = std::process::id().to_string();
        fs::write(isolated.path().join("parent.pid"), &parent_pid)
            .expect("write generated-child marker");

        // Spawn this test binary directly (never a shell or gio CLI), so GLib
        // sees its generated XDG_DATA_HOME before it can initialize or cache it.
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--ignored",
                "--exact",
                "trash_qualification::tests::real_gio_trash_only_generated_disposable_fixture",
                "--nocapture",
            ])
            .env("SWEEPX_REAL_GIO_CHILD", "1")
            .env("SWEEPX_REAL_GIO_ROOT", isolated.path())
            .env("XDG_DATA_HOME", &xdg)
            .env_remove("SWEEPX_RUN_REAL_GIO_TRASH")
            .output()
            .expect("run isolated real-GIO child");
        assert!(
            output.status.success(),
            "isolated real-GIO child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn run_real_gio_trash_child() {
        let isolated = std::env::var_os("SWEEPX_REAL_GIO_ROOT")
            .map(PathBuf::from)
            .expect("parent supplied generated real-GIO root")
            .canonicalize()
            .expect("canonical generated real-GIO root");
        let isolated_metadata =
            fs::symlink_metadata(&isolated).expect("inspect generated real-GIO root");
        // SAFETY: geteuid/getppid have no preconditions and do not mutate state.
        let (euid, parent_pid) = unsafe { (libc::geteuid(), libc::getppid()) };
        assert!(
            isolated_metadata.is_dir()
                && isolated_metadata.uid() == euid
                && isolated_metadata.mode() & 0o077 == 0,
            "generated isolation root must be a private runtime-owned directory"
        );
        let recorded_parent = fs::read_to_string(isolated.join("parent.pid"))
            .expect("read generated-child marker")
            .parse::<libc::pid_t>()
            .expect("parse generated-child marker");
        assert_eq!(
            recorded_parent, parent_pid,
            "real GIO child must be attached to the process that generated its fixture"
        );

        let xdg = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .expect("parent supplied generated XDG_DATA_HOME")
            .canonicalize()
            .expect("canonical generated XDG_DATA_HOME");
        assert_eq!(xdg.parent(), Some(isolated.as_path()));
        let xdg_metadata = fs::symlink_metadata(&xdg).expect("inspect isolated XDG_DATA_HOME");
        assert!(
            xdg_metadata.is_dir() && xdg_metadata.uid() == euid && xdg_metadata.mode() & 0o077 == 0
        );
        assert!(
            fs::read_dir(&xdg)
                .expect("enumerate isolated XDG_DATA_HOME")
                .next()
                .is_none(),
            "isolated XDG_DATA_HOME must start empty"
        );

        let fixture_root = isolated.join("fixture-root");
        let evidence_root = isolated.join("evidence");
        fs::create_dir(&fixture_root).expect("generated fixture root");
        fs::create_dir(&evidence_root).expect("generated evidence root");
        fs::set_permissions(&fixture_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&evidence_root, fs::Permissions::from_mode(0o700)).unwrap();
        let filesystem = MountRecord::for_path(&fixture_root)
            .expect("fixture mount")
            .filesystem;
        assert!(is_qualified_local_filesystem(&filesystem));
        let manifest = linux_p4_trash_manifest(filesystem);
        let generated = generate_from_manifest(&fixture_root, &manifest).expect("generate fixture");

        let outcome = FixtureTrashScope::admit_with(
            &generated,
            TARGET_ENTRY_ID,
            &xdg,
            gio_trash::GioTrashBackend::dynamically_loaded(),
            Box::new(ProcessRuntime),
        )
        .expect("admit generated fixture only")
        .probe()
        .expect("probe GIO Trash")
        .arm(&evidence_root)
        .expect("arm durable qualification evidence")
        .trash()
        .expect("submit once and persist conservative outcome");

        assert_eq!(
            outcome.kind,
            TrashOutcomeKind::PlatformReportedSourceRemoved,
            "real GIO qualification was not conclusive: {}",
            outcome.detail
        );
        assert!(
            !generated.top_dir().join("trash-target.txt").exists(),
            "the exact generated fixture target must be absent"
        );
        assert!(
            fs::read_dir(&xdg)
                .expect("enumerate isolated XDG_DATA_HOME after GIO")
                .next()
                .is_some(),
            "GIO must create evidence inside the isolated XDG namespace"
        );
        generated
            .select_linux_trash_target(TARGET_ENTRY_ID)
            .expect_err("single-use authority must already be consumed");
        assert!(evidence_root.join(INTENT_FILE).is_file());
        assert!(evidence_root.join(OUTCOME_FILE).is_file());
    }
}
