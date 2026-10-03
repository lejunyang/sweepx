//! macOS file-index facts require complete FSEvents history before reuse.

use super::*;

/// Schema marker for independently root-bound file indexes.
const SUBTREE_SCHEMA: &str = "sweepx.subtree-index/v4";

/// File lengths for one root. Partial optional listings do not authorize subtree skipping:
/// every directory is still enumerated and children absent from this index are inspected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredSubtreeIndex {
    pub(super) schema: String,
    /// Lossless absolute root spelling; non-UTF-8 roots are not persisted.
    pub(super) root: String,
    /// Native root binding, checked before and after history observation.
    pub(super) device: u64,
    pub(super) inode: u64,
    /// Pre-observation cursor; racing changes remain visible on the next validation.
    pub(super) since_event_id: FsEventId,
    /// Complete directory enumeration does not imply all optional lengths were retained.
    pub(super) covered: BTreeMap<String, bool>,
    /// Partial optional facts; missing children are always inspected.
    pub(super) listings: BTreeMap<String, StoredDirListing>,
}

/// Persisted child listing of one directory.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct StoredDirListing {
    /// Regular file child name → logical size.
    #[serde(default)]
    pub files: BTreeMap<String, u128>,
    /// Child directory names.
    #[serde(default)]
    pub dirs: BTreeSet<String>,
}

impl StoredSubtreeIndex {
    /// Checks that index capture still refers to the root observed by the traversal.
    pub fn matches_observed_root(&self, source: &sweepx_model::ScannedEntry) -> bool {
        observed_root_binding(source, Path::new(&self.root))
            .map(|(device, inode, _)| (device, inode))
            == Some((u128::from(self.device), u128::from(self.inode)))
    }
    /// Captures file facts under this root with the cursor taken before observation.
    pub fn new(
        root: &Path,
        since_event_id: FsEventId,
        covered: BTreeMap<String, bool>,
        listings: BTreeMap<String, StoredDirListing>,
    ) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() {
            return Err(io::Error::other("index root is not a real directory"));
        }
        Ok(Self {
            schema: SUBTREE_SCHEMA.into(),
            root: root
                .to_str()
                .ok_or_else(|| io::Error::other("index root is not UTF-8"))?
                .into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            since_event_id,
            covered,
            listings,
        })
    }

    pub(super) fn matches_root(&self, root: &Path) -> bool {
        self.schema == SUBTREE_SCHEMA
            && root.to_str() == Some(self.root.as_str())
            && fs::symlink_metadata(root).is_ok_and(|metadata| {
                metadata.is_dir() && metadata.dev() == self.device && metadata.ino() == self.inode
            })
            && self
                .covered
                .keys()
                .chain(self.listings.keys())
                .all(|path| Path::new(path).starts_with(root))
    }

    /// Captures only this root's listings, stopping before the optional wire budget is spent.
    /// Conservative JSON escaping allowances bound copies before serialization. Missing facts
    /// always require live inspection; omission does not create negative classification evidence.
    pub fn capture(
        root: &Path,
        all_roots: &[PathBuf],
        since: FsEventId,
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
    ) -> io::Result<Self> {
        Self::capture_owned(
            root,
            since,
            listings.iter().filter(|(path, _)| {
                covered.get(*path) == Some(&true)
                    && all_roots
                        .iter()
                        .filter(|candidate| Path::new(path).starts_with(candidate))
                        .max_by_key(|candidate| candidate.components().count())
                        .map(PathBuf::as_path)
                        == Some(root)
            }),
        )
    }

    /// Projects already-covered, original-scope-owned listings without revisiting other roots.
    /// Callers must retain BTree order so the independent per-root allowance omits the same tail.
    /// Ownership is a presentation/cache partition; root identity is still checked after capture.
    pub(crate) fn capture_owned<'a>(
        root: &Path,
        since: FsEventId,
        listings: impl IntoIterator<Item = (&'a String, &'a sweepx_scanner::DirListing)>,
    ) -> io::Result<Self> {
        let mut remaining = Limits::default()
            .entry_bytes
            .saturating_sub(1024 + root.as_os_str().len().saturating_mul(6));
        let mut result = Self::new(root, since, BTreeMap::new(), BTreeMap::new())?;
        for (path, listing) in listings {
            // A bad internal view can only omit cache facts, never publish a foreign path.
            if !Path::new(path).starts_with(root) {
                continue;
            }
            let cost = path.len().saturating_mul(12).saturating_add(128);
            if cost > remaining {
                break;
            }
            remaining -= cost;
            let mut saved = StoredDirListing::default();
            for (name, bytes) in &listing.files {
                let cost = name.len().saturating_mul(6).saturating_add(64);
                if cost > remaining {
                    break;
                }
                remaining -= cost;
                saved.files.insert(name.clone(), *bytes);
            }
            result.covered.insert(path.clone(), true);
            result.listings.insert(path.clone(), saved);
        }
        Ok(result)
    }

    /// Earliest event cursor the next validation must cover.
    pub fn since_event_id(&self) -> FsEventId {
        self.since_event_id
    }
    /// Whether this directory was fully enumerated; optional cached lengths may be incomplete.
    pub fn is_covered(&self, path: &str) -> bool {
        self.covered.get(path).copied().unwrap_or(false)
    }
    /// A partial set of cached ordinary-file lengths; unknown children must be inspected.
    pub fn listing(&self, path: &str) -> Option<&StoredDirListing> {
        self.listings.get(path)
    }
}

pub(super) fn index_retained_bytes(index: &StoredSubtreeIndex) -> usize {
    let mut bytes =
        std::mem::size_of::<StoredSubtreeIndex>() + index.schema.capacity() + index.root.capacity();
    for path in index.covered.keys() {
        bytes = bytes.saturating_add(128 + path.capacity());
    }
    for (path, listing) in &index.listings {
        bytes = bytes.saturating_add(256 + path.capacity());
        for name in listing.files.keys().chain(listing.dirs.iter()) {
            bytes = bytes.saturating_add(128 + name.capacity());
        }
    }
    bytes
}

/// Atomically publishes one root's optional file lengths without overwriting other roots.
pub fn write_subtree_index(cache_dir: &Path, index: &StoredSubtreeIndex) -> io::Result<()> {
    publish(
        cache_dir,
        &index_file_name(Path::new(&index.root)),
        index,
        Limits::default(),
    )
}
