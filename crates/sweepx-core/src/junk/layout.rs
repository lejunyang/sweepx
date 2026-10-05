//! Bounded invocation-local platform layout discovery. Native admission and enumeration remain
//! in the platform backend; path observations never supply deletion authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sweepx_model::{IdentityEvidence, NativeAbsolutePath, ScannedEntry};
use sweepx_platform::{
    CancellationToken, DirectoryReadLimits, EntryIdentity, FilesystemIdentity, MountIdentity,
    PlatformError, PlatformScanner, ScanRoot,
};
use sweepx_scanner::HostPlatformScanner;

/// Invocation-wide bounds for tool, browser and known-root layout discovery, separate from tool probes.
#[derive(Debug, Clone, Copy)]
pub struct LayoutDiscoveryLimits {
    /// Maximum distinct directory probes, including absent paths.
    pub max_directory_probes: usize,
    /// Maximum native records consumed across all version/profile/partition/shard enumerations.
    pub max_enumerated_entries: usize,
    /// Maximum root references retained across rules, including shared roots.
    pub max_roots: usize,
    /// Estimated retained bytes for paths, facts and enumeration indexes; not an RSS ceiling.
    pub max_retained_bytes: usize,
    /// Cooperative deadline checked between filesystem calls, not a hard OS I/O deadline.
    pub deadline: Duration,
}

impl Default for LayoutDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_directory_probes: 4096,
            max_enumerated_entries: 16_384,
            max_roots: 1024,
            max_retained_bytes: 8 * 1024 * 1024,
            deadline: Duration::from_secs(5),
        }
    }
}

/// Why layout discovery cannot establish complete coverage. Retained positive facts remain usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutDiscoveryFailure {
    /// A path, root, enumeration or retained-byte bound was reached.
    ResourceLimit,
    /// The caller cancelled discovery.
    Cancelled,
    /// The cooperative deadline expired.
    Deadline,
    /// Permission, I/O, identity or no-follow admission prevented an observation.
    ObservationUnavailable,
}

impl LayoutDiscoveryFailure {
    /// Stable machine code, independent of locale or native error strings.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ResourceLimit => "resource_limit",
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::ObservationUnavailable => "observation_unavailable",
        }
    }
}

/// Native directory observation bound to one path and scanner-compatible identity.
/// Handles are closed after discovery. A later scan must observe the same object and fingerprint;
/// mutations can decline a match, and cleanup still obtains its own current native authorization.
#[derive(Debug)]
pub(super) struct LayoutRoot {
    pub path: PathBuf,
    native_path: NativeAbsolutePath,
    identity: EntryIdentity,
    filesystem: FilesystemIdentity,
    mount: MountIdentity,
    fingerprint: String,
}

impl LayoutRoot {
    pub fn context_fact(&self) -> impl serde::Serialize + '_ {
        (
            &self.native_path,
            self.identity.device(),
            self.identity.inode(),
            self.filesystem.device,
            self.mount.value,
            &self.fingerprint,
        )
    }

    pub fn matches(&self, path: &NativeAbsolutePath, entry: &ScannedEntry) -> bool {
        let Some(locator) = entry.validated_native_locator().ok().flatten() else {
            return false;
        };
        self.native_path == *path
            && locator.entry.metadata_fingerprint == self.fingerprint
            && matches!(&locator.entry.platform_file_identity,
                IdentityEvidence::Known { value }
                    if value.device.0 == u128::from(self.identity.device())
                    && value.inode.0 == self.identity.inode())
            && matches!(&locator.entry.filesystem_object_domain_identity,
                IdentityEvidence::Known { value }
                    if value.device.0 == u128::from(self.filesystem.device))
            && matches!(&locator.entry.volume_or_mount_identity,
                IdentityEvidence::Known { value } if value.value.0 == u128::from(self.mount.value))
    }

    pub fn same_object(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.filesystem == other.filesystem
            && self.mount == other.mount
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ChildSelection {
    All,
    BrowserProfiles,
    VersionPrefix(&'static str),
}

#[derive(Clone)]
struct ChildListing {
    paths: Arc<[PathBuf]>,
    complete: bool,
}

pub(super) struct LayoutDiscovery {
    backend: HostPlatformScanner,
    cancel: CancellationToken,
    limits: LayoutDiscoveryLimits,
    deadline: Option<Instant>,
    directories: BTreeMap<PathBuf, Option<Arc<LayoutRoot>>>,
    // Selection belongs to the memo key: a version listing must not reuse browser filtering.
    profiles: BTreeMap<(PathBuf, ChildSelection), ChildListing>,
    enumerated: usize,
    root_references: usize,
    retained: usize,
    pub failure: Option<LayoutDiscoveryFailure>,
    exhausted: bool,
    #[cfg(test)]
    pub enumerations: usize,
}

impl LayoutDiscovery {
    pub fn new(limits: LayoutDiscoveryLimits, cancel: CancellationToken) -> Self {
        Self {
            backend: HostPlatformScanner::new(),
            cancel,
            limits,
            deadline: Instant::now().checked_add(limits.deadline),
            directories: BTreeMap::new(),
            profiles: BTreeMap::new(),
            enumerated: 0,
            root_references: 0,
            retained: 0,
            failure: None,
            exhausted: false,
            #[cfg(test)]
            enumerations: 0,
        }
    }

    /// Check shared cancellation/deadline before any additional native work.
    pub fn available(&mut self) -> bool {
        if self.cancel.is_cancelled() {
            self.fail(LayoutDiscoveryFailure::Cancelled);
            return false;
        }
        if self
            .deadline
            .is_none_or(|deadline| Instant::now() >= deadline)
        {
            self.fail(LayoutDiscoveryFailure::Deadline);
            return false;
        }
        !self.exhausted
    }

    fn fail(&mut self, failure: LayoutDiscoveryFailure) {
        if failure == LayoutDiscoveryFailure::ResourceLimit {
            self.exhausted = true;
        }
        self.failure.get_or_insert(failure);
    }

    /// Conservative cumulative admission; dropped temporary data does not refund the budget.
    pub fn charge(&mut self, bytes: usize) -> bool {
        if self.retained.saturating_add(bytes) > self.limits.max_retained_bytes {
            self.fail(LayoutDiscoveryFailure::ResourceLimit);
            return false;
        }
        self.retained += bytes;
        true
    }

    fn record_error(&mut self, error: &PlatformError) {
        self.fail(match error {
            PlatformError::Cancelled => LayoutDiscoveryFailure::Cancelled,
            PlatformError::ResourceLimit(_) => LayoutDiscoveryFailure::ResourceLimit,
            _ => LayoutDiscoveryFailure::ObservationUnavailable,
        });
    }

    pub fn admit_rule(&mut self, id: &str) -> bool {
        self.available() && self.charge(256usize.saturating_add(id.len()))
    }

    pub fn unavailable_anchor(&mut self) {
        self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
    }

    /// Charge before copying a caller/environment path. Oversized input never enters native I/O.
    pub fn retain_path(&mut self, path: &Path) -> Option<PathBuf> {
        if !self.available()
            || !self.charge(64usize.saturating_add(path.as_os_str().len().saturating_mul(4)))
        {
            return None;
        }
        if path.as_os_str().len() > 64 * 1024 {
            self.fail(LayoutDiscoveryFailure::ResourceLimit);
            return None;
        }
        Some(path.to_path_buf())
    }

    fn open_observed(
        &mut self,
        observed: &LayoutRoot,
    ) -> Option<
        sweepx_platform::RootAdmission<<HostPlatformScanner as PlatformScanner>::DirectoryHandle>,
    > {
        if !self.available() {
            return None;
        }
        let root =
            ScanRoot::new(observed.path.clone()).expect("native discovery admitted this path");
        let admitted = match self.backend.admit_root(&root, &self.cancel) {
            Ok(admitted)
                if admitted.metadata.identity.as_ref() == Some(&observed.identity)
                    && admitted.metadata.filesystem_identity.as_ref()
                        == Some(&observed.filesystem)
                    && admitted.metadata.mount_identity.as_ref() == Some(&observed.mount)
                    && admitted.metadata.fingerprint == observed.fingerprint =>
            {
                admitted
            }
            Ok(_) => {
                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                return None;
            }
            Err(error) => {
                self.record_error(&error);
                return None;
            }
        };
        self.available().then_some(admitted)
    }

    pub fn directory(&mut self, path: &Path) -> Option<Arc<LayoutRoot>> {
        if !self.available() {
            return None;
        }
        if let Some(observed) = self.directories.get(path) {
            return observed.clone();
        }
        if self.directories.len() >= self.limits.max_directory_probes {
            self.fail(LayoutDiscoveryFailure::ResourceLimit);
            return None;
        }
        let key = self.retain_path(path)?;
        // Account for the node/key even for a negative observation, so absent layouts cannot
        // build an unbounded memoization table. Capacity units are conservatively doubled.
        if !self.charge(256usize.saturating_add(key.capacity().saturating_mul(2))) {
            return None;
        }
        let observed = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => {
                let root = ScanRoot::new(path.to_path_buf()).ok()?;
                match self.backend.admit_root(&root, &self.cancel) {
                    Ok(admitted) => {
                        if !self.available() {
                            return None;
                        }
                        let metadata = admitted.metadata;
                        match (
                            metadata.identity,
                            metadata.filesystem_identity,
                            metadata.mount_identity,
                        ) {
                            (Some(identity), Some(filesystem), Some(mount)) => {
                                let native_cost = match &admitted.root_locator {
                                    NativeAbsolutePath::UnixBytes(bytes) => bytes.capacity(),
                                    NativeAbsolutePath::WindowsUtf16(units) => {
                                        units.capacity().saturating_mul(2)
                                    }
                                };
                                let cost = 256usize
                                    .saturating_add(metadata.path.capacity().saturating_mul(2))
                                    .saturating_add(native_cost)
                                    .saturating_add(metadata.fingerprint.capacity());
                                if !self.charge(cost) {
                                    return None;
                                }
                                Some(Arc::new(LayoutRoot {
                                    path: metadata.path,
                                    native_path: admitted.root_locator,
                                    identity,
                                    filesystem,
                                    mount,
                                    fingerprint: metadata.fingerprint,
                                }))
                            }
                            _ => {
                                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                                None
                            }
                        }
                    }
                    Err(error) => {
                        self.record_error(&error);
                        None
                    }
                }
            }
            Ok(_) => None, // A file/link is an intentional exclusion, not a guessed directory.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => {
                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                None
            }
        };
        self.directories.insert(key, observed.clone());
        observed
    }

    pub fn push_root(&mut self, path: &Path, roots: &mut Vec<Arc<LayoutRoot>>) {
        let Some(root) = self.directory(path) else {
            return;
        };
        self.push_observed(root, roots);
    }

    /// Retain a previously verified root within the shared reference quota.
    pub fn push_observed(&mut self, root: Arc<LayoutRoot>, roots: &mut Vec<Arc<LayoutRoot>>) {
        if !self.available() {
            return;
        }
        if roots.iter().any(|existing| existing.same_object(&root)) {
            return;
        }
        if self.root_references >= self.limits.max_roots || !self.charge(64) {
            self.fail(LayoutDiscoveryFailure::ResourceLimit);
            return;
        }
        // Exact growth avoids unaccounted spare capacity from exponential Vec growth.
        roots.reserve_exact(1);
        roots.push(root);
        self.root_references += 1;
    }

    pub fn has_markers(&mut self, observed: &LayoutRoot, markers: &[String]) -> bool {
        if markers.is_empty() {
            return self.available();
        }
        self.check_markers(observed, markers.iter().map(String::as_str), false)
    }

    /// Require a no-follow ordinary directory on the retained parent's filesystem and mount.
    pub fn has_directory(&mut self, observed: &LayoutRoot, name: &str) -> bool {
        self.check_markers(observed, [name], true)
    }

    fn check_markers<'a>(
        &mut self,
        observed: &LayoutRoot,
        markers: impl IntoIterator<Item = &'a str>,
        directories_only: bool,
    ) -> bool {
        let Some(admitted) = self.open_observed(observed) else {
            return false;
        };
        for marker in markers {
            if !self.available() {
                return false;
            }
            let Ok(child) = child_record(&observed.path, std::ffi::OsStr::new(marker)) else {
                return false;
            };
            // The inspected marker is resolved against the retained root handle. At most the
            // root and one transient child-directory handle are open; no marker payload is read.
            match sweepx_platform::inspect_bound_child(
                &self.backend,
                &admitted.directory,
                &observed.path,
                &child,
                &self.cancel,
            ) {
                Ok(sweepx_platform::WalkEntry::File(_)) if !directories_only => {}
                Ok(sweepx_platform::WalkEntry::Directory(child))
                    if child.metadata.filesystem_identity.as_ref()
                        == Some(&observed.filesystem)
                        && child.metadata.mount_identity.as_ref() == Some(&observed.mount) => {}
                Ok(sweepx_platform::WalkEntry::Boundary(_)) => {
                    self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                    return false;
                }
                Ok(sweepx_platform::WalkEntry::Error(error)) => {
                    if error.kind != sweepx_platform::ErrorKind::NotFound {
                        self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                    }
                    return false;
                }
                Ok(_) => return false,
                Err(error) => {
                    self.record_error(&error);
                    return false;
                }
            }
        }
        self.available()
    }

    pub fn profiles(&mut self, path: &Path, named: bool) -> Arc<[PathBuf]> {
        self.children(
            path,
            if named {
                ChildSelection::BrowserProfiles
            } else {
                ChildSelection::All
            },
        )
        .paths
    }

    /// Share one bounded version-container listing per native path and prefix per invocation.
    pub fn versions(&mut self, path: &Path, prefix: &'static str) -> Arc<[PathBuf]> {
        self.children(path, ChildSelection::VersionPrefix(prefix))
            .paths
    }

    /// Exact count requires clean EOF and independently admitted no-follow directories. A bounded
    /// prefix never establishes the layout. Each shard must remain on the parent's mount. Finder's
    /// `.DS_Store` is allowed only as a native no-follow regular file; other extra entries reject.
    pub fn has_hex_shards(&mut self, parent: &LayoutRoot, expected: usize) -> bool {
        let listing = self.children(&parent.path, ChildSelection::All);
        if !listing.complete
            || listing.paths.len() < expected
            || listing.paths.len() > expected.saturating_add(1)
        {
            return false;
        }
        let Some(admitted) = self.open_observed(parent) else {
            return false;
        };
        let mut shards = 0;
        for path in listing.paths.iter() {
            if !self.available() {
                return false;
            }
            let Some(name) = path.file_name() else {
                return false;
            };
            let valid_name = name.to_str().is_some_and(|name| {
                name.len() == 2
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            });
            let finder_metadata = name == std::ffi::OsStr::new(".DS_Store");
            if !valid_name && !finder_metadata {
                return false;
            }
            let Ok(record) = child_record(&parent.path, name) else {
                return false;
            };
            // One retained parent and one transient shard handle; avoid opening each ancestor
            // chain or retaining a per-shard root index solely to validate a count.
            match sweepx_platform::inspect_bound_child(
                &self.backend,
                &admitted.directory,
                &parent.path,
                &record,
                &self.cancel,
            ) {
                Ok(sweepx_platform::WalkEntry::Directory(child))
                    if valid_name
                        && child.metadata.filesystem_identity.as_ref()
                            == Some(&parent.filesystem)
                        && child.metadata.mount_identity.as_ref() == Some(&parent.mount) =>
                {
                    shards += 1;
                }
                Ok(sweepx_platform::WalkEntry::File(child))
                    if finder_metadata
                        && child.filesystem_identity.as_ref() == Some(&parent.filesystem) => {}
                Ok(sweepx_platform::WalkEntry::Error(_))
                | Ok(sweepx_platform::WalkEntry::Boundary(_)) => {
                    self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                    return false;
                }
                Err(error) => {
                    self.record_error(&error);
                    return false;
                }
                Ok(_) => return false,
            }
        }
        // Detect parent replacement/mutation during the interval; this is not an atomic tree snapshot.
        shards == expected && self.open_observed(parent).is_some()
    }

    fn children(&mut self, path: &Path, selection: ChildSelection) -> ChildListing {
        let empty = || ChildListing {
            paths: Arc::from([]),
            complete: false,
        };
        if !self.available() {
            return empty();
        }
        let Some(key_path) = self.retain_path(path) else {
            return empty();
        };
        let key = (key_path, selection);
        if let Some(found) = self.profiles.get(&key) {
            return found.clone();
        }
        let Some(observed) = self.directory(path) else {
            return empty();
        };
        if !self.charge(256usize.saturating_add(key.0.capacity().saturating_mul(2))) {
            return empty();
        }
        let Some(mut admitted) = self.open_observed(&observed) else {
            return empty();
        };
        let mut complete = false;
        let mut valid_records = true;
        let mut found = Vec::new();
        #[cfg(test)]
        {
            self.enumerations += 1;
        }
        loop {
            if !self.available() {
                break;
            }
            if self.enumerated >= self.limits.max_enumerated_entries {
                self.fail(LayoutDiscoveryFailure::ResourceLimit);
                break;
            }
            // Only one native directory cursor is retained during this enumeration. Its page and
            // returned batch are bounded separately from the invocation's memoized path data.
            let batch = match self.backend.enumerate_children(
                &mut admitted.directory,
                &self.cancel,
                DirectoryReadLimits {
                    max_batch_entries: (self.limits.max_enumerated_entries - self.enumerated)
                        .min(256),
                    max_batch_bytes: 64 * 1024,
                },
            ) {
                Ok(batch) => batch,
                Err(error) => {
                    self.record_error(&error);
                    break;
                }
            };
            self.enumerated += batch.entries.len();
            if !self.available() {
                break;
            }
            if batch.entries.is_empty() && !batch.end_of_directory {
                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                break;
            }
            for entry in batch.entries {
                if entry.validate_for_parent(path).is_err() {
                    valid_records = false;
                    self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                    continue;
                }
                let selected = match selection {
                    ChildSelection::All => true,
                    ChildSelection::BrowserProfiles => is_named_profile(&entry.file_name),
                    ChildSelection::VersionPrefix(prefix) => entry
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(prefix)),
                };
                if !selected {
                    continue;
                }
                if !self.charge(64usize.saturating_add(entry.path.capacity().saturating_mul(2))) {
                    break;
                }
                found.reserve_exact(1);
                found.push(entry.path);
            }
            if batch.end_of_directory {
                complete = self.available();
                break;
            }
        }
        let found = ChildListing {
            paths: Arc::from(found),
            complete: complete && valid_records && self.open_observed(&observed).is_some(),
        };
        self.profiles.insert(key, found.clone());
        found
    }
}

fn child_record(
    parent: &Path,
    name: &std::ffi::OsStr,
) -> Result<sweepx_platform::DirectoryEntryRecord, sweepx_platform::DirectoryEntryInvariantError> {
    #[cfg(unix)]
    let native_name = {
        use std::os::unix::ffi::OsStrExt;
        sweepx_model::NativeName::unix(name.as_bytes().to_vec())
    };
    #[cfg(windows)]
    let native_name = {
        use std::os::windows::ffi::OsStrExt;
        sweepx_model::NativeName::windows_utf16(name.encode_wide().collect::<Vec<_>>())
    };
    sweepx_platform::DirectoryEntryRecord::from_parent_and_name(parent, native_name)
}

fn is_named_profile(name: &sweepx_model::NativeName) -> bool {
    let is_profile = |name: &str| name == "Default" || name.starts_with("Profile ");
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => {
            std::str::from_utf8(bytes).is_ok_and(is_profile)
        }
        sweepx_model::NativeName::WindowsUtf16(units) => {
            String::from_utf16(units).is_ok_and(|name| is_profile(&name))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let root = owner.path().to_path_buf();
        (owner, root)
    }

    #[test]
    fn profiles_are_enumerated_once_and_match_an_independent_directory_set() {
        let (_owner, root) = fixture();
        for name in ["Default", "Profile 7", "Unrelated"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let expected = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name().unwrap() == "Default" || path.file_name().unwrap() == "Profile 7"
            })
            .collect::<BTreeSet<_>>();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let first = discovery.profiles(&root, true);
        assert_eq!(first.iter().cloned().collect::<BTreeSet<_>>(), expected);
        assert_eq!(discovery.enumerations, 1);
        std::fs::create_dir(root.join("Profile 9")).unwrap();
        let second = discovery.profiles(&root, true);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(discovery.enumerations, 1);
        let mut next_invocation =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        assert!(
            next_invocation
                .profiles(&root, true)
                .contains(&root.join("Profile 9"))
        );
        assert!(discovery.failure.is_none());
    }

    #[test]
    fn bounds_and_cancellation_do_not_establish_empty_complete_discovery() {
        let (_owner, root) = fixture();
        for name in ["Default", "Profile 1"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        for limits in [
            LayoutDiscoveryLimits {
                max_directory_probes: 0,
                ..LayoutDiscoveryLimits::default()
            },
            LayoutDiscoveryLimits {
                max_retained_bytes: 1,
                ..LayoutDiscoveryLimits::default()
            },
            LayoutDiscoveryLimits {
                max_enumerated_entries: 1,
                ..LayoutDiscoveryLimits::default()
            },
        ] {
            let mut discovery = LayoutDiscovery::new(limits, CancellationToken::new());
            let profiles = discovery.profiles(&root, true);
            assert!(profiles.len() <= 1);
            assert_eq!(
                discovery.failure,
                Some(LayoutDiscoveryFailure::ResourceLimit)
            );
            assert!(discovery.retained <= limits.max_retained_bytes);
            assert!(discovery.enumerated <= limits.max_enumerated_entries);
        }
        let mut discovery = LayoutDiscovery::new(
            LayoutDiscoveryLimits {
                max_roots: 1,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        let mut roots = Vec::new();
        discovery.push_root(&root.join("Default"), &mut roots);
        discovery.push_root(&root.join("Profile 1"), &mut roots);
        assert_eq!(roots.len(), 1);
        assert_eq!(
            discovery.failure,
            Some(LayoutDiscoveryFailure::ResourceLimit)
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut cancelled = LayoutDiscovery::new(LayoutDiscoveryLimits::default(), cancel);
        assert!(cancelled.directory(&root).is_none());
        assert_eq!(cancelled.failure, Some(LayoutDiscoveryFailure::Cancelled));
        let mut expired = LayoutDiscovery::new(
            LayoutDiscoveryLimits {
                deadline: Duration::ZERO,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        assert!(expired.directory(&root).is_none());
        assert_eq!(expired.failure, Some(LayoutDiscoveryFailure::Deadline));
    }

    #[test]
    fn version_selection_is_memoized_separately_and_truncation_is_explicit() {
        let (_owner, root) = fixture();
        for name in ["v3", "v10", "Default", "unrelated"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let expected = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_str().unwrap().starts_with('v'))
            .collect::<BTreeSet<_>>();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let versions = discovery.versions(&root, "v");
        assert_eq!(versions.iter().cloned().collect::<BTreeSet<_>>(), expected);
        assert!(Arc::ptr_eq(&versions, &discovery.versions(&root, "v")));
        assert_eq!(discovery.enumerations, 1);
        assert_eq!(
            discovery.profiles(&root, true).as_ref(),
            &[root.join("Default")]
        );
        assert_eq!(discovery.enumerations, 2);
        let mut bounded = LayoutDiscovery::new(
            LayoutDiscoveryLimits {
                max_enumerated_entries: 1,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        let listing = bounded.children(&root, ChildSelection::VersionPrefix("v"));
        assert!(!listing.complete);
        assert!(listing.paths.len() <= 1);
        assert_eq!(bounded.failure, Some(LayoutDiscoveryFailure::ResourceLimit));
    }

    #[test]
    fn exact_shards_require_complete_native_directories_without_a_per_shard_root_index() {
        let (_owner, root) = fixture();
        for shard in 0..256u32 {
            std::fs::create_dir(root.join(format!("{shard:02x}"))).unwrap();
        }
        let ordinary = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ordinary.len(), 256);
        assert!(
            ordinary
                .iter()
                .all(|entry| std::fs::symlink_metadata(entry.path()).unwrap().is_dir())
        );
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let observed = discovery.directory(&root).unwrap();
        assert!(discovery.has_hex_shards(&observed, 256));
        assert_eq!(
            discovery.directories.len(),
            1,
            "shards use the retained native parent"
        );
        assert_eq!(discovery.enumerations, 1);
        let mut truncated = LayoutDiscovery::new(
            LayoutDiscoveryLimits {
                max_enumerated_entries: 255,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        let observed = truncated.directory(&root).unwrap();
        assert!(
            !truncated.has_hex_shards(&observed, 255),
            "a matching retained prefix is not a complete count"
        );
        assert_eq!(
            truncated.failure,
            Some(LayoutDiscoveryFailure::ResourceLimit)
        );
        std::fs::remove_dir(root.join("00")).unwrap();
        std::fs::write(root.join("00"), b"user file").unwrap();
        let mut wrong_type =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let observed = wrong_type.directory(&root).unwrap();
        assert!(!wrong_type.has_hex_shards(&observed, 256));
        assert!(
            wrong_type.failure.is_none(),
            "ordinary files are intentional exclusions"
        );
    }

    #[test]
    fn finder_metadata_is_allowed_only_as_an_observed_regular_file() {
        let (_owner, root) = fixture();
        std::fs::create_dir(root.join("00")).unwrap();
        let metadata = root.join(".DS_Store");
        std::fs::write(&metadata, b"Finder metadata").unwrap();
        let check = || {
            let mut discovery =
                LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
            let observed = discovery.directory(&root).unwrap();
            discovery.has_hex_shards(&observed, 1)
        };
        assert!(check());
        std::fs::write(root.join("personal-file"), b"not metadata").unwrap();
        assert!(!check(), "unrecognized extra files still reject the layout");
        std::fs::remove_file(root.join("personal-file")).unwrap();
        std::fs::remove_file(&metadata).unwrap();
        std::fs::create_dir(&metadata).unwrap();
        assert!(!check(), "the metadata name cannot hide a directory");
        std::fs::remove_dir(&metadata).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("00"), &metadata).unwrap();
            assert!(!check(), "metadata symlinks must not be followed");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_hex_named_link_cannot_impersonate_a_directory_shard() {
        let (_owner, root) = fixture();
        std::fs::create_dir(root.join("target")).unwrap();
        let files = root.join("files");
        std::fs::create_dir(&files).unwrap();
        std::os::unix::fs::symlink(root.join("target"), files.join("00")).unwrap();
        assert!(
            std::fs::metadata(files.join("00")).unwrap().is_dir(),
            "following stat reproduces the old false positive"
        );
        assert!(
            std::fs::symlink_metadata(files.join("00"))
                .unwrap()
                .is_symlink()
        );
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let observed = discovery.directory(&files).unwrap();
        assert!(!discovery.has_hex_shards(&observed, 1));
    }

    #[test]
    fn oversized_paths_and_replaced_listing_parents_decline_observation() {
        let (_owner, root) = fixture();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        assert!(
            discovery
                .directory(&root.join("x".repeat(65_537)))
                .is_none()
        );
        assert_eq!(
            discovery.failure,
            Some(LayoutDiscoveryFailure::ResourceLimit)
        );
        assert!(discovery.directories.is_empty());
        let parent = root.join("parent");
        std::fs::create_dir_all(parent.join("00")).unwrap();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        let observed = discovery.directory(&parent).unwrap();
        assert!(discovery.has_hex_shards(&observed, 1));
        std::fs::rename(&parent, root.join("old-parent")).unwrap();
        std::fs::create_dir_all(parent.join("00")).unwrap();
        assert!(
            !discovery.has_hex_shards(&observed, 1),
            "memoized names do not authorize a replaced parent"
        );
        assert_eq!(
            discovery.failure,
            Some(LayoutDiscoveryFailure::ObservationUnavailable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_layout_ancestors_and_markers_cannot_supply_native_facts() {
        let (_owner, root) = fixture();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("cache")).unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        assert!(discovery.directory(&root.join("alias/cache")).is_none());
        assert_eq!(
            discovery.failure,
            Some(LayoutDiscoveryFailure::ObservationUnavailable)
        );
        let observed = discovery.directory(&real).unwrap();
        std::os::unix::fs::symlink(real.join("cache"), real.join("marker")).unwrap();
        assert!(!discovery.has_markers(&observed, &["marker".into()]));
    }
}
