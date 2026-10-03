//! Bounded accounting and retention for the ordinary historical preview namespace.
//!
//! The cooperative lock covers accounting, caller projection and publication. A retained
//! root survives renames; child bindings are checked before mutations. This is a cache quota
//! ledger, not an atomic filesystem snapshot or authority over any scanned payload.

use std::io::{self, ErrorKind};
use std::path::PathBuf;

use crate::{
    AtomicGenerationStore, CacheError, CurrentPointer, INSPECT_CURRENT_POINTER_BYTE_LIMIT,
    PreparedGeneration, STATE_DIRECTORY_BYTE_CAP, StoredGeneration, directory_error, native,
    validate_generation_id,
};

// Three flat directories can each expose two dot entries in the native 4,096-record cap.
const ENTRY_CAP: usize = 4090;
const GENERATION_CAP: usize = 4;

#[derive(Clone, Copy)]
struct Limits {
    entries: usize,
    generations: usize,
    bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: ENTRY_CAP,
            generations: GENERATION_CAP,
            bytes: STATE_DIRECTORY_BYTE_CAP,
        }
    }
}

/// One nonblocking, retained-directory publication session for a historical preview.
///
/// Preparation may evict noncurrent managed generation files to restore the quota. It never
/// removes the current generation, unknown files or quarantine evidence. Dropping a session
/// releases the lock, including when projection/admission fails. Callers retain live scan facts
/// independently. Filesystem actors that ignore this lock can still race observations.
pub struct GenerationWriteSession {
    root: native::Directory,
    lock: native::LockGuard,
    generations: native::Directory,
    quarantine: Option<native::Directory>,
    display: PathBuf,
    inventory: Inventory,
    limits: Limits,
}

impl AtomicGenerationStore {
    /// Prepares bounded native accounting before allocating a preview projection. Missing
    /// directories are created privately; existing permissions are never repaired. Contention,
    /// uncertain accounting or an unsatisfiable quota refuses this disposable cache update.
    pub fn begin_write(&self) -> Result<GenerationWriteSession, CacheError> {
        GenerationWriteSession::open(self, Limits::default())
    }
}

impl GenerationWriteSession {
    fn open(store: &AtomicGenerationStore, limits: Limits) -> Result<Self, CacheError> {
        let root = native::Directory::open(store.root(), true)
            .map_err(|error| directory_error(error, store.root()))?;
        Self::open_retained(root, store, limits)
    }

    fn open_retained(
        root: native::Directory,
        store: &AtomicGenerationStore,
        limits: Limits,
    ) -> Result<Self, CacheError> {
        let lock = root.lock()?;
        let generations = root
            .create_child("generations")
            .map_err(|error| directory_error(error, &store.generations_dir()))?;
        let quarantine = match root.child("quarantine") {
            Ok(directory) => Some(directory),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(directory_error(error, &store.quarantine_dir())),
        };
        let mut session = Self {
            root,
            lock,
            generations,
            quarantine,
            display: store.root().to_path_buf(),
            inventory: Inventory::default(),
            limits,
        };
        session.refresh()?;
        session.prune(0, 0, 0)?;
        Ok(session)
    }

    /// Encoded file lengths observed after baseline retention, including unknown regular
    /// files and quarantine. This measures neither physical allocation nor reclaimable space.
    pub fn state_directory_bytes(&self) -> u64 {
        self.inventory.bytes
    }

    /// Admits and publishes one generation within this retained session. Generation IDs
    /// must be fresh; overwriting an existing generation could change the old pointer's data
    /// before the pointer transaction succeeds. Refusal leaves the current pointer unchanged.
    pub fn write_generation(mut self, generation: &StoredGeneration) -> Result<(), CacheError> {
        let prepared = PreparedGeneration::new(
            generation,
            crate::INSPECT_GENERATION_BYTE_LIMIT as usize,
            crate::json_budget::PARSE_RESERVATION_CAP,
        )?;
        prepared.publish(&mut self)
    }

    pub(super) fn bindings(&self) -> Result<(), CacheError> {
        for (name, child) in [
            ("generations", Some(&self.generations)),
            ("quarantine", self.quarantine.as_ref()),
        ] {
            let same = match child {
                Some(child) => self.root.same_child(name, child),
                None => match self.root.child(name) {
                    Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
                    Err(error) => Err(error),
                    Ok(_) => Ok(false),
                },
            }
            .map_err(|error| directory_error(error, &self.display.join(name)))?;
            if !same {
                return Err(CacheError::InsecurePath(self.display.join(name)));
            }
        }
        Ok(())
    }

    fn refresh(&mut self) -> Result<(), CacheError> {
        self.bindings()?;
        let mut inventory = Inventory::default();
        self.scan(
            &self.root,
            &mut inventory,
            |name| matches!(name, "generations" | "quarantine"),
            false,
        )?;
        self.scan(&self.generations, &mut inventory, |_| false, true)?;
        if let Some(directory) = &self.quarantine {
            self.scan(directory, &mut inventory, |_| false, false)?;
        }
        // The pointer itself has already passed metadata accounting. Unknown/malformed or
        // oversized pointers protect every managed generation rather than guessing an owner.
        inventory.current = match self
            .root
            .read_bytes("current.json", INSPECT_CURRENT_POINTER_BYTE_LIMIT)
        {
            Ok(read) => read.contents.and_then(|bytes| {
                serde_json::from_slice::<CurrentPointer>(&bytes)
                    .ok()
                    .and_then(|pointer| {
                        validate_generation_id(&pointer.generation)
                            .ok()
                            .map(|()| Some(format!("{}.json", pointer.generation)))
                    })
            }),
            Err(error) if error.kind() == ErrorKind::NotFound => Some(None),
            Err(error) => return Err(CacheError::Io(error)),
        };
        self.bindings()?;
        self.inventory = inventory;
        Ok(())
    }

    fn scan(
        &self,
        directory: &native::Directory,
        inventory: &mut Inventory,
        is_child: impl Fn(&str) -> bool,
        managed: bool,
    ) -> Result<(), CacheError> {
        let mut exhausted = false;
        let scanned = directory.entries_all(|name| {
            if inventory.entries == self.limits.entries {
                exhausted = true;
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            inventory.entries += 1;
            let name = name.ok_or_else(|| io::Error::other("unrepresentable cache entry"))?;
            if is_child(name) {
                // The child was admitted and its binding is rechecked around inventory.
                return Ok(());
            }
            // Windows lock handles deny all sharing. Account our own held lock rather than
            // weakening that exclusion just to reopen it for its (usually zero) file length.
            if name == ".lock" && !managed && std::ptr::eq(directory, &self.root) {
                inventory.bytes = inventory
                    .bytes
                    .checked_add(self.lock.encoded_bytes()?)
                    .ok_or_else(|| io::Error::other("cache length overflow"))?;
                return Ok(());
            }
            let metadata = directory.accounting_metadata(name)?;
            inventory.bytes = inventory
                .bytes
                .checked_add(metadata.bytes)
                .ok_or_else(|| io::Error::other("cache length overflow"))?;
            if managed
                && name
                    .strip_suffix(".json")
                    .is_some_and(|id| validate_generation_id(id).is_ok())
            {
                inventory.generations.push(Generation {
                    name: name.to_string(),
                    metadata,
                });
            }
            Ok(())
        });
        if exhausted {
            return Err(resource_limit());
        }
        scanned.map_err(CacheError::Io)
    }

    pub(super) fn reserve(&mut self, name: &str, added_bytes: u64) -> Result<(), CacheError> {
        self.refresh()?;
        // Basename equality is a volume property: ASCII generation IDs can still alias on
        // a case-insensitive filesystem. Native metadata admission detects the actual target.
        match self.generations.accounting_metadata(name) {
            Ok(_) => {
                return Err(CacheError::Io(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "generation ID is already published",
                )));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(CacheError::Io(error)),
        }
        self.prune(added_bytes, 1, 2)
    }

    pub(super) fn quarantine(
        store: &AtomicGenerationStore,
        directory: &native::Directory,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), CacheError> {
        let mut session = Self::open_retained(directory.retain()?, store, Limits::default())?;
        session.prune(
            bytes.len() as u64,
            0,
            if session.quarantine.is_none() { 2 } else { 1 },
        )?;
        if session.quarantine.is_none() {
            session.quarantine = Some(
                session
                    .root
                    .create_child("quarantine")
                    .map_err(|error| directory_error(error, &store.quarantine_dir()))?,
            );
        }
        session.bindings()?;
        session
            .quarantine
            .as_ref()
            .expect("admitted quarantine child")
            .publish(name, |file| {
                use std::io::Write;
                file.write_all(bytes)?;
                file.sync_all()
            })?;
        Ok(())
    }

    fn prune(
        &mut self,
        added_bytes: u64,
        added_generations: usize,
        added_entries: usize,
    ) -> Result<(), CacheError> {
        let mut bytes = self
            .inventory
            .bytes
            .checked_add(added_bytes)
            .ok_or_else(resource_limit)?;
        let mut count = self
            .inventory
            .generations
            .len()
            .checked_add(added_generations)
            .ok_or_else(resource_limit)?;
        let mut entries = self
            .inventory
            .entries
            .checked_add(added_entries)
            .ok_or_else(resource_limit)?;
        if bytes <= self.limits.bytes
            && count <= self.limits.generations
            && entries <= self.limits.entries
        {
            return Ok(());
        }
        let mut eligible: Vec<usize> = self
            .inventory
            .generations
            .iter()
            .enumerate()
            .filter(|(_, generation)| match &self.inventory.current {
                None => false,
                Some(current) => current.as_ref() != Some(&generation.name),
            })
            .map(|(index, _)| index)
            .collect();
        eligible.sort_by(|&left, &right| {
            let left = &self.inventory.generations[left];
            let right = &self.inventory.generations[right];
            (left.metadata.accessed, &left.name).cmp(&(right.metadata.accessed, &right.name))
        });
        let mut needed = 0;
        for &index in &eligible {
            bytes -= self.inventory.generations[index].metadata.bytes;
            count -= 1;
            entries -= 1;
            needed += 1;
            if bytes <= self.limits.bytes
                && count <= self.limits.generations
                && entries <= self.limits.entries
            {
                break;
            }
        }
        // Plan the whole quota repair before deleting anything. Unknown/quarantine files are
        // charged but never evicted, and an unknown pointer pins all generation candidates.
        if bytes > self.limits.bytes
            || count > self.limits.generations
            || entries > self.limits.entries
        {
            return Err(resource_limit());
        }
        for &index in &eligible[..needed] {
            self.bindings()?;
            let generation = &self.inventory.generations[index];
            if self.generations.accounting_metadata(&generation.name)? != generation.metadata {
                return Err(CacheError::Io(io::Error::other(
                    "cache entry changed before retention",
                )));
            }
            // Unix unlinkat has a final basename race with non-cooperating filesystem actors.
            // Only disposable cache metadata is eligible; this is never a scanned-file delete.
            self.generations.remove(&generation.name)?;
        }
        // Reinventory after maintenance, still under the same cooperative exclusion. A failed
        // recount refuses publication; it does not turn incomplete state into a zero total.
        self.refresh()?;
        if self
            .inventory
            .bytes
            .checked_add(added_bytes)
            .is_none_or(|bytes| bytes > self.limits.bytes)
            || self
                .inventory
                .generations
                .len()
                .saturating_add(added_generations)
                > self.limits.generations
            || self.inventory.entries.saturating_add(added_entries) > self.limits.entries
        {
            return Err(resource_limit());
        }
        Ok(())
    }

    pub(super) fn generations(&self) -> &native::Directory {
        &self.generations
    }

    pub(super) fn root(&self) -> &native::Directory {
        &self.root
    }
}

#[derive(Default)]
struct Inventory {
    entries: usize,
    bytes: u64,
    generations: Vec<Generation>,
    // None: unknown pointer; Some(None): absent; Some(Some(name)): known current basename.
    current: Option<Option<String>>,
}

struct Generation {
    name: String,
    metadata: native::AccountedFile,
}

fn resource_limit() -> CacheError {
    CacheError::ResourceLimit {
        reason: sweepx_model::ReasonCode::ResourceLimit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestTempDir, create_fixture_dir, write_fixture};
    use crate::{LoadResult, PreviewBudgets, STORED_PREVIEW_SCHEMA, compact_preview};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    fn generation(id: &str) -> StoredGeneration {
        StoredGeneration {
            generation: id.into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "2026-10-04T00:00:00Z".into(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        }
    }

    // Ordinary metadata is the independent length oracle. Production never recursively walks.
    fn ordinary_total(path: &Path) -> u64 {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                if metadata.is_dir() {
                    ordinary_total(&entry.path())
                } else {
                    metadata.len()
                }
            })
            .sum()
    }

    fn names(path: &Path) -> BTreeSet<String> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    #[test]
    fn quota_accounting_matches_ordinary_lengths_and_retention_preserves_unknown_evidence() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        create_fixture_dir(store.quarantine_dir()).unwrap();
        write_fixture(store.root().join("notes.txt"), b"root evidence").unwrap();
        write_fixture(
            store.quarantine_dir().join("keep.corrupt.json"),
            b"quarantine evidence",
        )
        .unwrap();
        create_fixture_dir(store.generations_dir()).unwrap();
        write_fixture(
            store.generations_dir().join("unmanaged.txt"),
            b"unknown evidence",
        )
        .unwrap();
        for index in 0..12 {
            let value = generation(&format!("gen-{index}"));
            store.write_generation(&value).unwrap();
            assert_eq!(store.load_current().unwrap(), LoadResult::Hit(value));
            let session = store.begin_write().unwrap();
            assert_eq!(
                session.state_directory_bytes(),
                ordinary_total(store.root())
            );
        }
        assert_eq!(names(&store.generations_dir()).len(), 5); // four generations plus unknown
        assert!(store.generation_path("gen-11").exists());
        assert_eq!(
            fs::read(store.root().join("notes.txt")).unwrap(),
            b"root evidence"
        );
        assert_eq!(
            fs::read(store.generations_dir().join("unmanaged.txt")).unwrap(),
            b"unknown evidence"
        );
        assert_eq!(
            fs::read(store.quarantine_dir().join("keep.corrupt.json")).unwrap(),
            b"quarantine evidence"
        );
    }

    #[test]
    fn baseline_maintenance_preserves_current_and_the_ordinary_byte_oracle() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        for id in ["first", "second", "third", "current"] {
            store.write_generation(&generation(id)).unwrap();
        }
        let pointer = fs::read(store.current_pointer_path()).unwrap();
        let current = fs::read(store.generation_path("current")).unwrap();
        let session = GenerationWriteSession::open(
            &store,
            Limits {
                generations: 2,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(names(&store.generations_dir()).len(), 2);
        assert_eq!(
            session.state_directory_bytes(),
            ordinary_total(store.root())
        );
        assert_eq!(fs::read(store.current_pointer_path()).unwrap(), pointer);
        assert_eq!(fs::read(store.generation_path("current")).unwrap(), current);
        drop(session);
        assert_eq!(
            store.load_current().unwrap(),
            LoadResult::Hit(generation("current"))
        );
    }

    #[test]
    fn unsatisfiable_quota_is_planned_without_partial_eviction() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        for id in ["first", "second", "current"] {
            store.write_generation(&generation(id)).unwrap();
        }
        write_fixture(store.root().join("unknown"), [b'x'; 200]).unwrap();
        let before = names(&store.generations_dir());
        let pointer = fs::read(store.current_pointer_path()).unwrap();
        assert!(matches!(
            GenerationWriteSession::open(
                &store,
                Limits {
                    bytes: 100,
                    ..Limits::default()
                }
            ),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert_eq!(names(&store.generations_dir()), before);
        assert_eq!(fs::read(store.current_pointer_path()).unwrap(), pointer);
    }

    #[test]
    fn malformed_pointer_pins_all_generations_but_small_state_can_be_repaired_by_publication() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("previous")).unwrap();
        write_fixture(store.current_pointer_path(), b"malformed").unwrap();
        assert!(matches!(
            GenerationWriteSession::open(
                &store,
                Limits {
                    generations: 0,
                    ..Limits::default()
                }
            ),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert_eq!(
            fs::read(store.current_pointer_path()).unwrap(),
            b"malformed"
        );
        assert!(store.generation_path("previous").exists());
        store.write_generation(&generation("new")).unwrap();
        assert_eq!(
            store.load_current().unwrap(),
            LoadResult::Hit(generation("new"))
        );
        assert!(store.generation_path("previous").exists());
    }

    #[test]
    fn flat_entry_work_and_publication_temporaries_have_shared_limits() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        for index in 0..20 {
            write_fixture(store.root().join(format!("unknown-{index}")), []).unwrap();
        }
        let before = names(store.root());
        assert!(matches!(
            GenerationWriteSession::open(
                &store,
                Limits {
                    entries: 12,
                    ..Limits::default()
                }
            ),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert_eq!(names(store.root()), before);
        let mut session = store.begin_write().unwrap();
        session.limits.entries = session.inventory.entries + 1;
        assert!(matches!(
            session.write_generation(&generation("next")),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert!(!store.generation_path("next").exists());
        assert_eq!(
            store.load_current().unwrap(),
            LoadResult::Hit(generation("current"))
        );
    }

    #[test]
    fn unknown_nested_directory_refuses_complete_accounting_without_traversing_it() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        create_fixture_dir(store.generations_dir().join("nested")).unwrap();
        write_fixture(store.generations_dir().join("nested/keep"), b"retain").unwrap();
        assert!(store.begin_write().is_err());
        assert_eq!(
            fs::read(store.generations_dir().join("nested/keep")).unwrap(),
            b"retain"
        );
        assert_eq!(
            store.load_current().unwrap(),
            LoadResult::Hit(generation("current"))
        );
    }

    #[test]
    fn lock_contention_refuses_writer_and_quarantine_then_releases_on_drop() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        let session = store.begin_write().unwrap();
        assert!(store.begin_write().is_err());
        write_fixture(store.current_pointer_path(), b"bad pointer").unwrap();
        assert!(store.load_current().is_err());
        assert!(!store.quarantine_dir().exists());
        assert_eq!(
            fs::read(store.current_pointer_path()).unwrap(),
            b"bad pointer"
        );
        drop(session);
        assert!(matches!(
            store.load_current(),
            Err(CacheError::Quarantined { .. })
        ));
        assert_eq!(
            fs::read(store.quarantine_dir().join("current.json")).unwrap(),
            b"bad pointer"
        );
    }

    #[test]
    fn fresh_ids_and_a_second_inventory_preserve_current_after_refusal() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        let current = generation("current");
        store.write_generation(&current).unwrap();
        let pointer = fs::read(store.current_pointer_path()).unwrap();
        let data = fs::read(store.generation_path("current")).unwrap();
        let mut replacement = current.clone();
        replacement.created_at = "changed".into();
        assert!(
            matches!(store.write_generation(&replacement), Err(CacheError::Io(error)) if error.kind() == ErrorKind::AlreadyExists)
        );
        let session = GenerationWriteSession::open(
            &store,
            Limits {
                bytes: ordinary_total(store.root()) + 100,
                ..Limits::default()
            },
        )
        .unwrap();
        write_fixture(store.root().join("late-unknown"), [b'x'; 200]).unwrap();
        assert!(matches!(
            session.write_generation(&generation("next")),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert_eq!(fs::read(store.current_pointer_path()).unwrap(), pointer);
        assert_eq!(fs::read(store.generation_path("current")).unwrap(), data);
        assert!(!store.generation_path("next").exists());
    }

    #[test]
    fn native_generation_aliases_cannot_overwrite_current_data() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("Case")).unwrap();
        let data = fs::read(store.generation_path("Case")).unwrap();
        let pointer = fs::read(store.current_pointer_path()).unwrap();
        // Independently observe this fixture volume's spelling behavior, never assume an OS
        // implies case sensitivity. On sensitive volumes these IDs remain distinct and valid.
        let aliases = fs::symlink_metadata(store.generation_path("case")).is_ok();
        let written = store.write_generation(&generation("case"));
        assert_eq!(fs::read(store.generation_path("Case")).unwrap(), data);
        if aliases {
            assert!(
                matches!(written, Err(CacheError::Io(error)) if error.kind() == ErrorKind::AlreadyExists)
            );
            assert_eq!(fs::read(store.current_pointer_path()).unwrap(), pointer);
            assert_eq!(
                store.load_current().unwrap(),
                LoadResult::Hit(generation("Case"))
            );
        } else {
            written.unwrap();
            assert_eq!(
                store.load_current().unwrap(),
                LoadResult::Hit(generation("case"))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn sparse_lengths_are_counted_without_reading_and_quarantine_cannot_bypass_quota() {
        use std::os::unix::fs::MetadataExt;
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        let path = store.generations_dir().join("unmanaged.bin");
        write_fixture(&path, []).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(4_294_967_297).unwrap();
        drop(file);
        assert!(fs::metadata(&path).unwrap().blocks() * 512 < 1_048_576);
        let session = GenerationWriteSession::open(
            &store,
            Limits {
                bytes: 5_368_709_120,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(
            session.state_directory_bytes(),
            ordinary_total(store.root())
        );
        drop(session);
        assert!(matches!(
            store.begin_write(),
            Err(CacheError::ResourceLimit { .. })
        ));
        write_fixture(store.current_pointer_path(), b"bad pointer").unwrap();
        assert!(matches!(
            store.load_current(),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert!(!store.quarantine_dir().exists());
        assert_eq!(
            fs::read(store.current_pointer_path()).unwrap(),
            b"bad pointer"
        );
        assert_eq!(fs::metadata(path).unwrap().len(), 4_294_967_297);
    }

    #[cfg(unix)]
    #[test]
    fn retained_root_rename_publishes_only_in_original_namespace() {
        let fixture = TestTempDir::new();
        let path = fixture.path().join("cache");
        let store = AtomicGenerationStore::new(&path);
        store.write_generation(&generation("current")).unwrap();
        let session = store.begin_write().unwrap();
        let moved = fixture.path().join("moved");
        fs::rename(&path, &moved).unwrap();
        create_fixture_dir(&path).unwrap();
        session.write_generation(&generation("new")).unwrap();
        assert!(names(&path).is_empty());
        assert_eq!(
            AtomicGenerationStore::new(moved).load_current().unwrap(),
            LoadResult::Hit(generation("new"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn substituted_generation_child_refuses_pointer_publication() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        let pointer = fs::read(store.current_pointer_path()).unwrap();
        let session = store.begin_write().unwrap();
        let moved = store.root().join("moved-generations");
        fs::rename(store.generations_dir(), &moved).unwrap();
        create_fixture_dir(store.generations_dir()).unwrap();
        assert!(matches!(
            session.write_generation(&generation("new")),
            Err(CacheError::InsecurePath(_))
        ));
        assert_eq!(fs::read(store.current_pointer_path()).unwrap(), pointer);
        assert_eq!(names(&moved), BTreeSet::from(["current.json".into()]));
        assert!(names(&store.generations_dir()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn linked_aliased_public_and_special_entries_never_become_complete_totals() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        for kind in 0..4 {
            let fixture = TestTempDir::new();
            let store = AtomicGenerationStore::new(fixture.path());
            store.write_generation(&generation("current")).unwrap();
            let entry = store.generations_dir().join("unknown");
            match kind {
                0 => symlink(store.generation_path("current"), &entry).unwrap(),
                1 => fs::hard_link(store.generation_path("current"), &entry).unwrap(),
                2 => {
                    write_fixture(&entry, b"public").unwrap();
                    fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).unwrap();
                }
                3 => {
                    let path =
                        std::ffi::CString::new(entry.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: isolated fixture basename and a terminated native path.
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(store.begin_write().is_err(), "unsafe entry kind {kind}");
            assert!(store.generation_path("current").exists());
            assert!(!store.generation_path("new").exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opaque_unix_names_refuse_complete_accounting() {
        use std::os::unix::ffi::OsStringExt;
        // APFS rejects this native byte spelling with EILSEQ; Linux supplies the actual
        // filesystem fixture. Windows opaque names are covered by literal native pages.
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        store.write_generation(&generation("current")).unwrap();
        write_fixture(
            store
                .generations_dir()
                .join(std::ffi::OsString::from_vec(vec![0xff])),
            b"opaque",
        )
        .unwrap();
        assert!(store.begin_write().is_err());
        assert_eq!(
            store.load_current().unwrap(),
            LoadResult::Hit(generation("current"))
        );
    }
}
