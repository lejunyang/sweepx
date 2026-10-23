//! Bounded invocation-local platform layout discovery. Native admission and enumeration remain
//! in the platform backend; path observations never supply deletion authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sweepx_model::{IdentityEvidence, NativeAbsolutePath, ScannedEntry};
use sweepx_platform::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryIdentity, FilesystemIdentity, MountIdentity, PlatformError, PlatformScanner, ScanRoot,
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
    /// Maximum inactivity between discovery checkpoints, not a total scan or hard OS I/O limit.
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
pub(crate) struct LayoutRoot {
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
        self.matches_component(path, &locator.entry)
    }

    /// Match captured native identity before allocating a lossless absolute path. Most full-disk
    /// directories cannot match any discovered cache, so this keeps classification inexpensive.
    pub fn matches_identity(&self, component: &sweepx_model::NativePathComponent) -> bool {
        component.metadata_fingerprint == self.fingerprint
            && matches!(&component.platform_file_identity,
                IdentityEvidence::Known { value }
                    if value.device.0 == u128::from(self.identity.device())
                    && value.inode.0 == self.identity.inode())
            && matches!(&component.filesystem_object_domain_identity,
                IdentityEvidence::Known { value }
                    if value.device.0 == u128::from(self.filesystem.device))
            && matches!(&component.volume_or_mount_identity,
                IdentityEvidence::Known { value } if value.value.0 == u128::from(self.mount.value))
    }

    /// The path and native component must both match the current discovery snapshot.
    pub fn matches_component(
        &self,
        path: &NativeAbsolutePath,
        component: &sweepx_model::NativePathComponent,
    ) -> bool {
        self.native_path == *path && self.matches_identity(component)
    }

    /// Matches the directory at any depth without substituting the outer scan root's identity.
    pub fn matches_entry(&self, entry: &ScannedEntry) -> bool {
        let Some(locator) = entry.native_locator.as_ref() else {
            return false;
        };
        // This preliminary negative check cannot admit an entry. Validate the entire chain
        // only for an identity match, rather than once per discovered cache for every directory.
        self.matches_identity(&locator.entry)
            && entry.validated_native_locator().ok().flatten().is_some()
            && super::git::native_path(entry)
                .and_then(|path| NativeAbsolutePath::from_path(&path).ok())
                .is_some_and(|path| self.matches(&path, entry))
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

pub(crate) struct LayoutDiscovery<P: PlatformScanner = HostPlatformScanner> {
    backend: P,
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
        Self::with_backend(HostPlatformScanner::new(), limits, cancel)
    }
}

impl<P: PlatformScanner> LayoutDiscovery<P> {
    fn with_backend(backend: P, limits: LayoutDiscoveryLimits, cancel: CancellationToken) -> Self {
        Self {
            backend,
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
        self.available_at(Instant::now())
    }

    fn available_at(&mut self, observed: Instant) -> bool {
        if self.cancel.is_cancelled() {
            self.fail(LayoutDiscoveryFailure::Cancelled);
            return false;
        }
        if self.deadline.is_none_or(|deadline| observed >= deadline) {
            self.fail(LayoutDiscoveryFailure::Deadline);
            return false;
        }
        if !self.exhausted {
            self.deadline = observed.checked_add(self.limits.deadline);
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
    ) -> Option<sweepx_platform::RootAdmission<P::DirectoryHandle>> {
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
        let Some(mut admitted) = self.open_observed(observed) else {
            return false;
        };
        let requires_enumeration = self.backend.child_inspection_requires_enumeration();
        let mut pending = Vec::new();
        for marker in markers {
            if !self.available() {
                return false;
            }
            // Charge before constructing a requested name/path. These records are only lookup
            // keys on backends requiring enumeration, never a substitute for native evidence.
            if requires_enumeration
                && !self.charge(
                    128usize
                        .saturating_add(observed.path.as_os_str().len().saturating_mul(4))
                        .saturating_add(marker.len().saturating_mul(8)),
                )
            {
                return false;
            }
            let Ok(child) = child_record(&observed.path, std::ffi::OsStr::new(marker)) else {
                return false;
            };
            if requires_enumeration {
                if !pending.contains(&child) {
                    pending.reserve_exact(1);
                    pending.push(child);
                }
            } else if !self.inspect_marker(observed, &admitted.directory, &child, directories_only)
            {
                return false;
            }
        }
        if pending.is_empty() {
            return self.available();
        }
        #[cfg(test)]
        {
            self.enumerations += 1;
        }
        loop {
            let Some(batch) = self.next_batch(&mut admitted.directory) else {
                return false;
            };
            for child in batch.entries {
                if !self.available() {
                    return false;
                }
                if child.validate_for_parent(&observed.path).is_err() {
                    self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                    return false;
                }
                let Some(index) = pending
                    .iter()
                    .position(|wanted| wanted.file_name == child.file_name)
                else {
                    continue;
                };
                // Inspect before advancing the cursor: Windows binds the exact name and full
                // identity to this handle's current batch. Retaining a name alone is insufficient.
                if !self.inspect_marker(observed, &admitted.directory, &child, directories_only) {
                    return false;
                }
                pending.swap_remove(index);
            }
            if pending.is_empty() {
                return self.available();
            }
            if batch.end_of_directory {
                return false;
            }
        }
    }

    fn inspect_marker(
        &mut self,
        observed: &LayoutRoot,
        directory: &P::DirectoryHandle,
        child: &DirectoryEntryRecord,
        directories_only: bool,
    ) -> bool {
        // At most the root and one transient child-directory handle are open; no payload is read.
        match sweepx_platform::inspect_bound_child(
            &self.backend,
            directory,
            &observed.path,
            child,
            &self.cancel,
        ) {
            Ok(sweepx_platform::WalkEntry::File(_)) if !directories_only => true,
            Ok(sweepx_platform::WalkEntry::Directory(child))
                if child.metadata.filesystem_identity.as_ref() == Some(&observed.filesystem)
                    && child.metadata.mount_identity.as_ref() == Some(&observed.mount) =>
            {
                true
            }
            Ok(sweepx_platform::WalkEntry::Boundary(_)) => {
                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                false
            }
            Ok(sweepx_platform::WalkEntry::Error(error)) => {
                if error.kind != sweepx_platform::ErrorKind::NotFound {
                    self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                }
                false
            }
            Ok(_) => false,
            Err(error) => {
                self.record_error(&error);
                false
            }
        }
    }

    /// Read one bounded page without weakening backends' current-batch inspection contract.
    fn next_batch(&mut self, directory: &mut P::DirectoryHandle) -> Option<DirectoryEntryBatch> {
        if !self.available() {
            return None;
        }
        if self.enumerated >= self.limits.max_enumerated_entries {
            self.fail(LayoutDiscoveryFailure::ResourceLimit);
            return None;
        }
        let limits = DirectoryReadLimits {
            max_batch_entries: (self.limits.max_enumerated_entries - self.enumerated).min(256),
            max_batch_bytes: 64 * 1024,
        };
        let batch = match self
            .backend
            .enumerate_children(directory, &self.cancel, limits)
        {
            Ok(batch) => batch,
            Err(error) => {
                self.record_error(&error);
                return None;
            }
        };
        if !self.available() {
            return None;
        }
        let bytes = batch.entries.iter().try_fold(0usize, |total, child| {
            total.checked_add(child.estimated_retained_bytes()?)
        });
        if batch.entries.len() > limits.max_batch_entries
            || bytes.is_none_or(|bytes| bytes > limits.max_batch_bytes)
            || (batch.entries.is_empty() && !batch.end_of_directory)
        {
            self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
            return None;
        }
        self.enumerated += batch.entries.len();
        Some(batch)
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
        if !self.backend.child_inspection_requires_enumeration() {
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
                let Some(name) = path.file_name() else {
                    return false;
                };
                let Ok(record) = child_record(&parent.path, name) else {
                    return false;
                };
                let Some(shard) = self.inspect_shard(parent, &admitted.directory, &record) else {
                    return false;
                };
                shards += usize::from(shard);
            }
            return shards == expected && self.open_observed(parent).is_some();
        }
        let Some(mut admitted) = self.open_observed(parent) else {
            return false;
        };
        let mut shards = 0usize;
        let mut records = 0usize;
        #[cfg(test)]
        {
            self.enumerations += 1;
        }
        loop {
            let Some(batch) = self.next_batch(&mut admitted.directory) else {
                return false;
            };
            records = records.saturating_add(batch.entries.len());
            if records > expected.saturating_add(1) {
                return false;
            }
            for record in batch.entries {
                // A memoized path listing or a reopened parent does not preserve Windows' native
                // batch evidence. Inspect on this same retained handle before advancing its cursor.
                let Some(shard) = self.inspect_shard(parent, &admitted.directory, &record) else {
                    return false;
                };
                shards += usize::from(shard);
            }
            if batch.end_of_directory {
                break;
            }
        }
        // Require clean EOF and detect parent replacement/mutation during the interval.
        // This remains a non-atomic native observation, not an atomic tree snapshot.
        shards == expected && self.open_observed(parent).is_some()
    }

    /// Returns whether this is a shard (true) or an allowed Finder metadata file (false).
    fn inspect_shard(
        &mut self,
        parent: &LayoutRoot,
        directory: &P::DirectoryHandle,
        record: &DirectoryEntryRecord,
    ) -> Option<bool> {
        if !self.available() {
            return None;
        }
        if record.validate_for_parent(&parent.path).is_err() {
            self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
            return None;
        }
        let name = record.path.file_name()?;
        let valid_name = name.to_str().is_some_and(|name| {
            name.len() == 2
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
        let finder_metadata = name == std::ffi::OsStr::new(".DS_Store");
        if !valid_name && !finder_metadata {
            return None;
        }
        // One retained parent and one transient shard handle; never retain a per-shard root index.
        match sweepx_platform::inspect_bound_child(
            &self.backend,
            directory,
            &parent.path,
            record,
            &self.cancel,
        ) {
            Ok(sweepx_platform::WalkEntry::Directory(child))
                if valid_name
                    && child.metadata.filesystem_identity.as_ref() == Some(&parent.filesystem)
                    && child.metadata.mount_identity.as_ref() == Some(&parent.mount) =>
            {
                Some(true)
            }
            Ok(sweepx_platform::WalkEntry::File(child))
                if finder_metadata
                    && child.filesystem_identity.as_ref() == Some(&parent.filesystem) =>
            {
                Some(false)
            }
            Ok(sweepx_platform::WalkEntry::Error(_))
            | Ok(sweepx_platform::WalkEntry::Boundary(_)) => {
                self.fail(LayoutDiscoveryFailure::ObservationUnavailable);
                None
            }
            Err(error) => {
                self.record_error(&error);
                None
            }
            Ok(_) => None,
        }
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
        // Only one native cursor and one bounded transient batch are retained.
        while let Some(batch) = self.next_batch(&mut admitted.directory) {
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

    use std::sync::atomic::{AtomicUsize, Ordering};
    use sweepx_platform::{
        DirectoryHandleAdmission, EntryMetadata, OpenedDirectory, RootAdmission, WalkEntry,
    };

    struct BatchHandle {
        native: <HostPlatformScanner as PlatformScanner>::DirectoryHandle,
        current: Vec<DirectoryEntryRecord>,
    }

    #[derive(Default)]
    struct BatchPlatform {
        native: HostPlatformScanner,
        inspections: AtomicUsize,
        cancel_after_batch: bool,
        invalid_record: bool,
        empty_unfinished_batch: bool,
    }

    impl BatchPlatform {
        fn wrap(handle: <HostPlatformScanner as PlatformScanner>::DirectoryHandle) -> BatchHandle {
            BatchHandle {
                native: handle,
                current: Vec::new(),
            }
        }

        fn wrap_entry(
            entry: WalkEntry<<HostPlatformScanner as PlatformScanner>::DirectoryHandle>,
        ) -> WalkEntry<BatchHandle> {
            match entry {
                WalkEntry::Directory(opened) => WalkEntry::Directory(OpenedDirectory {
                    handle: Self::wrap(opened.handle),
                    metadata: opened.metadata,
                }),
                WalkEntry::File(value) => WalkEntry::File(value),
                WalkEntry::Link(value) => WalkEntry::Link(value),
                WalkEntry::Boundary(value) => WalkEntry::Boundary(value),
                WalkEntry::Error(value) => WalkEntry::Error(value),
                WalkEntry::CachedFile(value) => WalkEntry::CachedFile(value),
            }
        }
    }

    // Run the exact-current-batch contract on every host, with one record per page so retaining
    // tokens until EOF or reopening the parent before inspection is observably incorrect.
    impl PlatformScanner for BatchPlatform {
        type DirectoryHandle = BatchHandle;

        fn platform_name(&self) -> &'static str {
            self.native.platform_name()
        }

        fn child_inspection_requires_enumeration(&self) -> bool {
            true
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<BatchHandle>, PlatformError> {
            let admitted = self.native.admit_root(root, cancel)?;
            Ok(RootAdmission::new(
                admitted.root,
                admitted.metadata,
                Self::wrap(admitted.directory),
                admitted.root_locator,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut BatchHandle,
            cancel: &CancellationToken,
            limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            if self.empty_unfinished_batch {
                return Ok(DirectoryEntryBatch::continued(Vec::new()));
            }
            let mut batch = self.native.enumerate_children(
                &mut directory.native,
                cancel,
                DirectoryReadLimits {
                    max_batch_entries: limits.max_batch_entries.min(1),
                    ..limits
                },
            )?;
            if self.invalid_record {
                for child in &mut batch.entries {
                    child.path = child.path.join("unbound");
                }
            }
            directory.current = batch.entries.clone();
            if self.cancel_after_batch {
                cancel.cancel();
            }
            Ok(batch)
        }

        fn inspect_child(
            &self,
            parent: &BatchHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<BatchHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &BatchHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<BatchHandle>, PlatformError> {
            if !parent.current.contains(child) {
                return Err(PlatformError::InvalidDirectoryEntry {
                    parent: child.path.parent().unwrap().to_path_buf(),
                    detail: "child absent from this handle's current native batch".into(),
                });
            }
            self.inspections.fetch_add(1, Ordering::SeqCst);
            self.native
                .inspect_child_with_directory_admission(&parent.native, child, cancel, admission)
                .map(Self::wrap_entry)
        }

        fn is_same_mount(
            &self,
            root: &EntryMetadata,
            entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            self.native.is_same_mount(root, entry)
        }
    }

    #[test]
    fn markers_inspect_each_current_batch_and_keep_absence_and_wrong_type_distinct() {
        let (_owner, root) = fixture();
        std::fs::write(root.join("marker-file"), b"marker").unwrap();
        std::fs::create_dir(root.join("marker-directory")).unwrap();
        let mut discovery = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits::default(),
            CancellationToken::new(),
        );
        let observed = discovery.directory(&root).unwrap();
        let admitted = discovery.open_observed(&observed).unwrap();
        let synthetic = child_record(&root, std::ffi::OsStr::new("marker-file")).unwrap();
        assert!(
            sweepx_platform::inspect_bound_child(
                &discovery.backend,
                &admitted.directory,
                &root,
                &synthetic,
                &discovery.cancel
            )
            .is_err(),
            "the fixture independently refuses synthesized tokens"
        );
        drop(admitted);
        assert!(discovery.has_markers(
            &observed,
            &[
                "marker-file".into(),
                "marker-directory".into(),
                "marker-file".into()
            ]
        ));
        assert_eq!(discovery.backend.inspections.load(Ordering::SeqCst), 2);
        assert!(discovery.enumerated >= 2);
        assert!(discovery.has_directory(&observed, "marker-directory"));
        assert!(!discovery.has_directory(&observed, "marker-file"));
        assert!(!discovery.has_markers(&observed, &["absent".into()]));
        assert!(discovery.failure.is_none());
    }

    #[test]
    fn current_batch_marker_lookup_obeys_shared_bounds_and_cancellation() {
        let (_owner, root) = fixture();
        for name in ["first", "second"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let mut bounded = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits {
                max_enumerated_entries: 1,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        let observed = bounded.directory(&root).unwrap();
        assert!(!bounded.has_markers(&observed, &["first".into(), "second".into()]));
        assert_eq!(bounded.enumerated, 1);
        assert_eq!(bounded.failure, Some(LayoutDiscoveryFailure::ResourceLimit));
        let mut no_retention = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits::default(),
            CancellationToken::new(),
        );
        let observed = no_retention.directory(&root).unwrap();
        no_retention.limits.max_retained_bytes = no_retention.retained;
        assert!(!no_retention.has_directory(&observed, "first"));
        assert_eq!(no_retention.enumerated, 0);
        assert_eq!(
            no_retention.failure,
            Some(LayoutDiscoveryFailure::ResourceLimit)
        );
        for (backend, failure) in [
            (
                BatchPlatform {
                    cancel_after_batch: true,
                    ..BatchPlatform::default()
                },
                LayoutDiscoveryFailure::Cancelled,
            ),
            (
                BatchPlatform {
                    invalid_record: true,
                    ..BatchPlatform::default()
                },
                LayoutDiscoveryFailure::ObservationUnavailable,
            ),
            (
                BatchPlatform {
                    empty_unfinished_batch: true,
                    ..BatchPlatform::default()
                },
                LayoutDiscoveryFailure::ObservationUnavailable,
            ),
        ] {
            let mut discovery = LayoutDiscovery::with_backend(
                backend,
                LayoutDiscoveryLimits::default(),
                CancellationToken::new(),
            );
            let observed = discovery.directory(&root).unwrap();
            assert!(!discovery.has_directory(&observed, "first"));
            assert_eq!(discovery.failure, Some(failure));
            assert_eq!(discovery.backend.inspections.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn exact_shards_inspect_current_batches_and_require_eof_within_the_shared_budget() {
        let (_owner, root) = fixture();
        for name in ["00", "01", "02"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        std::fs::write(root.join(".DS_Store"), b"Finder metadata").unwrap();
        let expected = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_type().unwrap().is_dir())
            .count();
        assert_eq!(expected, 3);
        let mut discovery = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits::default(),
            CancellationToken::new(),
        );
        let observed = discovery.directory(&root).unwrap();
        assert!(discovery.has_hex_shards(&observed, expected));
        assert_eq!(discovery.backend.inspections.load(Ordering::SeqCst), 4);
        assert_eq!(discovery.directories.len(), 1);
        assert_eq!(discovery.enumerations, 1);
        let mut bounded = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits {
                max_enumerated_entries: 3,
                ..LayoutDiscoveryLimits::default()
            },
            CancellationToken::new(),
        );
        let observed = bounded.directory(&root).unwrap();
        assert!(!bounded.has_hex_shards(&observed, expected));
        assert_eq!(bounded.failure, Some(LayoutDiscoveryFailure::ResourceLimit));
        std::fs::remove_dir(root.join("00")).unwrap();
        std::fs::write(root.join("00"), b"user file").unwrap();
        let mut wrong_type = LayoutDiscovery::with_backend(
            BatchPlatform::default(),
            LayoutDiscoveryLimits::default(),
            CancellationToken::new(),
        );
        let observed = wrong_type.directory(&root).unwrap();
        assert!(!wrong_type.has_hex_shards(&observed, expected));
        assert!(wrong_type.failure.is_none());
    }

    #[test]
    fn progressing_layout_work_outlives_the_original_deadline() {
        let start = Instant::now();
        let mut discovery =
            LayoutDiscovery::new(LayoutDiscoveryLimits::default(), CancellationToken::new());
        discovery.deadline = Some(start + Duration::from_secs(5));
        for tick in 1..=20 {
            assert!(discovery.available_at(start + Duration::from_secs(tick * 4)));
        }
        assert!(!discovery.available_at(start + Duration::from_secs(90)));
        assert_eq!(discovery.failure, Some(LayoutDiscoveryFailure::Deadline));
    }
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
