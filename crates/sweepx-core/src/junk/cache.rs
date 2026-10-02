//! Persistent, per-root cache of classified junk results, validated with FSEvents.
//!
//! # What is stored
//!
//! For every scan root we persist its filesystem and rule-match facts (without tool activity or
//! Git confidence) together with the
//! FSEvents event id captured *before* the scan. On the next run the root is only reused when
//! FSEvents reports no change at or below it since that id; any event under the root, a
//! dropped/lost-history signal, or a root identity change invalidates it and it is rescanned.
//!
//! # Why this is safe to reuse
//!
//! FSEvents observes file content modifications as well as structure, so an empty history is a
//! stronger statement than a directory-mtime check (which cannot see content writes). The
//! candidates still carry their native locators and identities; the Trash path revalidates each
//! one at execution independently, so a cached report grants no mutation authority on its own.
//!
//! # Failure direction
//!
//! Every error — missing file, unreadable log, timeout, parse failure — is a miss, never a claim
//! of freshness. The cache lives in a user-private directory (`0700`) with `0600` files and
//! rejects symlinks.

#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::time::Duration;

use crate::FsEventId;
#[cfg(test)]
use crate::current_event_id;
#[cfg(test)]
use crate::events_since;
use sha2::{Digest, Sha256};
use sweepx_model::{ByteValue, ScanEntryId};
use sweepx_scanner::ChangeLog;

/// Current directory enumeration with independently validated cached file lengths.
pub mod provider;
mod storage;
use storage::Directory;
pub(crate) use storage::{Limits, ReadBudget};

/// Schema marker for the on-disk root record; bump on an incompatible change.
// v8 invalidates aggregates and native lineage captured with Darwin's old OBJID-as-inode
// observation. File-length indexes are independent and retain their existing schema.
const STORED_SCHEMA: &str = "sweepx.junk-cache/v8";
/// Bounded wall time for one FSEvents drain; a drain that cannot finish fails the cache.
#[cfg(test)]
const FSEVENTS_TIMEOUT: Duration = Duration::from_secs(5);

/// One root's cached result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredJunkRoot {
    schema: String,
    /// Classification data changes invalidate a report even when the filesystem is unchanged.
    rules_digest: String,
    /// Current enabled rules and discovery scope, independent of filesystem history.
    classification_context: [u8; 32],
    /// Lossless absolute root spelling at capture; native identity is verified before reuse.
    root: String,
    /// Native identity of the root directory at capture.
    root_device: String,
    root_inode: String,
    /// FSEvents id captured before the root was scanned.
    since_event_id: FsEventId,
    candidates: Vec<StoredJunkCandidate>,
    /// Nested requested roots own their candidates; a different request scope must rescan.
    excluded_root_keys: Vec<String>,
}

/// Validated filesystem and rule-match facts, excluding transient tool and Git interpretations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredJunkCandidate {
    /// Display-only path; never filesystem authority.
    pub path: String,
    /// Stable matched rule identifier.
    pub rule_id: String,
    /// Risk tier from the loaded rule.
    pub risk: String,
    /// Historical size evidence; interpretation depends on size_is_logical.
    pub reclaimable: ByteValue,
    /// Rule explanation at capture.
    pub evidence: String,
    /// Review date carried by the rule.
    pub source_reviewed_at: String,
    /// Supporting rule references.
    pub references: Vec<String>,
    /// Source scan identity, not a fresh observation.
    pub entry_id: ScanEntryId,
    /// Ancestor identities in the source scan namespace.
    pub ancestor_ids: BTreeSet<ScanEntryId>,
    /// Whether the size evidence is logical rather than allocation evidence.
    pub size_is_logical: bool,
    /// The source scanned row, restored so a cached candidate can be bulk-trashed with the same
    /// identity revalidation as a fresh one. `None` for records that never carried a row.
    #[serde(default)]
    pub source_entry: Option<sweepx_model::ScannedEntry>,
    /// Nested-repository and traversal coverage facts, excluding Git answers.
    pub git_scan_facts: Option<super::git::GitScanFacts>,
    /// Optional historical recursive statistics; absence never proves current coverage.
    #[serde(default)]
    pub aggregate: Option<sweepx_model::DirectoryAggregate>,
}

impl StoredJunkCandidate {
    /// Copies only scan/rule facts, excluding environment-dependent activity and Git answers.
    pub fn from_candidate(candidate: &super::candidate::JunkCandidate) -> Self {
        Self {
            path: candidate.path.clone(),
            rule_id: candidate.rule_id.clone(),
            risk: candidate.risk.clone(),
            reclaimable: candidate.reclaimable.clone(),
            evidence: candidate.evidence.clone(),
            source_reviewed_at: candidate.source_reviewed_at.clone(),
            references: candidate.references.clone(),
            entry_id: candidate.entry_id.clone(),
            ancestor_ids: candidate.ancestor_ids.clone(),
            size_is_logical: candidate.size_is_logical,
            source_entry: candidate.source_entry.clone(),
            git_scan_facts: candidate.git_scan_facts,
            aggregate: None,
        }
    }

    /// Restores report facts with all transient interpretations cleared. The caller must either
    /// retain historical status or rebuild interpretation from this invocation's evidence.
    pub fn into_candidate(self) -> super::candidate::JunkCandidate {
        super::candidate::JunkCandidate {
            path: self.path,
            rule_id: self.rule_id,
            risk: self.risk,
            reclaimable: self.reclaimable,
            evidence: self.evidence,
            source_reviewed_at: self.source_reviewed_at,
            references: self.references,
            entry_id: self.entry_id,
            ancestor_ids: self.ancestor_ids,
            activity: None,
            stale_formats: Vec::new(),
            size_is_logical: self.size_is_logical,
            git: None,
            classification: None,
            confidence: None,
            blockers: Vec::new(),
            // Dynamic content interpretation is reconstructed from current rules, then reread.
            project_format: None,
            project_context: None,
            execution_policy: super::candidate::JunkExecutionPolicy::NotChecked,
            source_entry: self.source_entry,
            git_scan_facts: self.git_scan_facts,
        }
    }
}

impl StoredJunkRoot {
    /// Rejects a root replaced between traversal and publication. This checks captured scan
    /// facts against the record's native binding; display paths do not establish authority.
    pub fn matches_observed_root(&self, source: &sweepx_model::ScannedEntry) -> bool {
        observed_root_binding(source, Path::new(&self.root)).is_some_and(|(device, inode)| {
            device.to_string() == self.root_device && inode.to_string() == self.root_inode
        })
    }
    /// Builds a record from freshly scanned candidates for one absolute root.
    pub fn capture(
        canonical_root: &Path,
        candidates: Vec<StoredJunkCandidate>,
        since_event_id: FsEventId,
        classification_context: [u8; 32],
    ) -> io::Result<Self> {
        Self::capture_with_rule_bytes(
            canonical_root,
            candidates,
            since_event_id,
            classification_context,
            super::PROJECT_RULES_JSON.as_bytes(),
            super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
        )
    }

    /// Captures a root with the actual admitted rule source bytes, including editable catalogs.
    pub fn capture_with_rule_bytes(
        canonical_root: &Path,
        candidates: Vec<StoredJunkCandidate>,
        since_event_id: FsEventId,
        classification_context: [u8; 32],
        project_bytes: &[u8],
        platform_bytes: &[u8],
    ) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(canonical_root)?;
        if !metadata.is_dir() {
            return Err(io::Error::other("cache root is not a real directory"));
        }
        Ok(Self {
            schema: STORED_SCHEMA.to_string(),
            rules_digest: digest_rule_bytes(project_bytes, platform_bytes),
            classification_context,
            root: canonical_root
                .to_str()
                .ok_or_else(|| io::Error::other("cache root is not UTF-8"))?
                .to_string(),
            root_device: metadata.dev().to_string(),
            root_inode: metadata.ino().to_string(),
            // A pre-scan cursor preserves writes racing with the walk for the next validation.
            since_event_id,
            candidates,
            excluded_root_keys: Vec::new(),
        })
    }

    /// Binds candidate attribution to the current set of nested requested roots.
    pub fn bind_scope(&mut self, roots: &[PathBuf]) {
        self.excluded_root_keys = excluded_root_keys(Path::new(&self.root), roots);
    }

    /// Earliest change cursor required to validate this record.
    pub fn since_event_id(&self) -> FsEventId {
        self.since_event_id
    }

    /// Number of candidates in a stored record, used by tests.
    #[cfg(test)]
    pub fn candidates_len(&self) -> usize {
        self.candidates.len()
    }

    /// Consumes the record, returning its owned candidates.
    pub fn into_candidates(self) -> Vec<StoredJunkCandidate> {
        self.candidates
    }

    /// Checks the root binding independently of event history.
    #[cfg(test)]
    fn matches_root(&self, canonical_root: &Path) -> bool {
        self.matches_root_with_rules(canonical_root, rules_digest())
    }

    fn matches_root_with_rules(&self, canonical_root: &Path, expected_rules: &str) -> bool {
        if self.schema != STORED_SCHEMA
            || self.rules_digest != expected_rules
            || Some(self.root.as_str()) != canonical_root.to_str()
        {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(canonical_root) else {
            return false;
        };
        metadata.is_dir()
            && metadata.dev().to_string() == self.root_device
            && metadata.ino().to_string() == self.root_inode
    }

    #[cfg(test)]
    fn is_current(&self, root: &Path) -> bool {
        validate_records(&[root.to_path_buf()], vec![Some(self.clone())])[0].is_some()
    }
}

#[cfg(test)]
fn rules_digest() -> &'static str {
    static DIGEST: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DIGEST.get_or_init(|| {
        digest_rule_bytes(
            super::PROJECT_RULES_JSON.as_bytes(),
            super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
        )
    })
}

fn digest_rule_bytes(project_bytes: &[u8], platform_bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(project_bytes);
    hash.update([0]);
    hash.update(platform_bytes);
    format!("{:x}", hash.finalize())
}

/// Loads only records whose root identity and loaded rules still match.
/// History is validated separately against the same drain used by the file index.
pub struct CacheReader {
    directory: Option<Directory>,
    budget: ReadBudget,
    limits: Limits,
    expected_rules: String,
}

impl CacheReader {
    /// Both cache layers share encoded-input and retained-data limits within an invocation.
    pub fn new(cache_dir: &Path) -> Self {
        Self::with_rule_bytes(
            cache_dir,
            super::PROJECT_RULES_JSON.as_bytes(),
            super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
        )
    }

    /// Shares one input/retention budget and binds reports to the actual loaded rule bytes.
    pub fn with_rule_bytes(cache_dir: &Path, project_bytes: &[u8], platform_bytes: &[u8]) -> Self {
        let limits = Limits::default();
        Self {
            directory: Directory::open(cache_dir, false).ok(),
            budget: ReadBudget::new(limits),
            limits,
            expected_rules: digest_rule_bytes(project_bytes, platform_bytes),
        }
    }

    /// Remaining owned-data estimate after both disk-cache layers were loaded.
    pub fn remaining_retained_bytes(&self) -> usize {
        self.budget.remaining_retained_bytes()
    }

    /// Root identity, loaded rule bytes and current classification context must match before
    /// history is consulted. Unknown context skips candidate reads; file indexes remain independent.
    pub fn roots(
        &mut self,
        roots: &[PathBuf],
        context: Option<&[u8; 32]>,
    ) -> Vec<Option<StoredJunkRoot>> {
        roots
            .iter()
            .enumerate()
            .map(|(ordinal, root)| {
                if ordinal >= self.limits.roots {
                    return None;
                }
                let context = context?;
                let record: StoredJunkRoot = self.budget.read(
                    self.directory.as_ref()?,
                    &record_file_name(root),
                    self.limits,
                    root_retained_bytes,
                )?;
                (record.classification_context == *context
                    && record.matches_root_with_rules(root, &self.expected_rules)
                    && record.excluded_root_keys == excluded_root_keys(root, roots))
                .then_some(record)
            })
            .collect()
    }

    /// Loads report-only historical rows before discovery/history validation. A matching source
    /// digest, native root binding and request scope do not establish current classification.
    /// The caller must mark all returned rows historical and reobserve before any mutation.
    pub fn historical_roots(&mut self, roots: &[PathBuf]) -> Vec<Option<StoredJunkRoot>> {
        roots
            .iter()
            .enumerate()
            .map(|(ordinal, root)| {
                if ordinal >= self.limits.roots {
                    return None;
                }
                let record: StoredJunkRoot = self.budget.read(
                    self.directory.as_ref()?,
                    &record_file_name(root),
                    self.limits,
                    root_retained_bytes,
                )?;
                (record.matches_root_with_rules(root, &self.expected_rules)
                    && record.excluded_root_keys == excluded_root_keys(root, roots))
                .then_some(record)
            })
            .collect()
    }

    /// File indexes have their own root binding and cursor, but share the read allowance.
    pub fn index(&mut self, root: &Path) -> Option<StoredSubtreeIndex> {
        let index: StoredSubtreeIndex = self.budget.read(
            self.directory.as_ref()?,
            &index_file_name(root),
            self.limits,
            index_retained_bytes,
        )?;
        index.matches_root(root).then_some(index)
    }
}

/// Checks each root against its own pre-scan cursor and rechecks its native binding.
/// Input records must already have their loaded rule/context binding admitted by CacheReader.
/// Missing/incomplete history makes every record a miss, never a partial cache hit.
pub fn validate_records_with_log(
    roots: &[PathBuf],
    mut records: Vec<Option<StoredJunkRoot>>,
    log: Option<&ChangeLog>,
) -> Vec<Option<StoredJunkRoot>> {
    for (root, record) in roots.iter().zip(&mut records) {
        let valid = match (log, record.as_ref()) {
            (Some(log), Some(stored))
                if !log.must_rescan
                    && stored.matches_root_with_rules(root, &stored.rules_digest) =>
            {
                !log.events.iter().any(|event| {
                    event.id > stored.since_event_id && paths_overlap(Path::new(&event.path), root)
                })
            }
            _ => false,
        };
        if !valid {
            *record = None;
        }
    }
    records
}

#[cfg(test)]
fn validate_records(
    roots: &[PathBuf],
    records: Vec<Option<StoredJunkRoot>>,
) -> Vec<Option<StoredJunkRoot>> {
    let since = records
        .iter()
        .flatten()
        .map(StoredJunkRoot::since_event_id)
        .min();
    let paths: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    let log = since.and_then(|since| events_since(&paths, since, FSEVENTS_TIMEOUT).ok());
    validate_records_with_log(roots, records, log.as_ref())
}

/// Ancestor events cannot be discarded: a parent change may rename or replace a cached root.
fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn observed_root_binding(source: &sweepx_model::ScannedEntry, root: &Path) -> Option<(u128, u128)> {
    let identity = source.validated_identity().ok()??;
    if source.object_type != sweepx_model::ObjectType::Directory
        || identity.parent_id.is_some()
        || identity.entry_id != identity.scan_root_id
        || super::git::native_path(source)?.as_path() != root
    {
        return None;
    }
    match &identity.platform_file_identity {
        sweepx_model::IdentityEvidence::Known { value } => Some((value.device.0, value.inode.0)),
        _ => None,
    }
}

/// Loads a stored record for `canonical_root`, returning `None` on any failure or absence.
#[cfg(test)]
pub fn load(cache_dir: &Path, canonical_root: &Path) -> Option<StoredJunkRoot> {
    CacheReader::new(cache_dir)
        .roots(&[canonical_root.to_path_buf()], Some(&[0; 32]))
        .pop()
        .flatten()
}

/// Atomically publishes one bounded record; cache errors never fail the report.
pub fn write(cache_dir: &Path, record: &StoredJunkRoot) -> io::Result<()> {
    publish(
        cache_dir,
        &record_file_name(Path::new(&record.root)),
        record,
        Limits::default(),
    )
}

fn publish(
    cache_dir: &Path,
    name: &str,
    value: &impl serde::Serialize,
    limits: Limits,
) -> io::Result<()> {
    let directory = Directory::open(cache_dir, true)?;
    let _lock = directory.lock()?;
    directory.write_json(name, value, limits.entry_bytes)?;
    prune_directory(&directory, limits)
}

/// Evicts the least recently read root groups under count, per-root and total disk limits.
/// Alternating requested roots stay cached while they fit; paired facts/indexes are evicted together.
pub fn prune(cache_dir: &Path) -> io::Result<()> {
    let directory = match Directory::open(cache_dir, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let _lock = directory.lock()?;
    prune_directory(&directory, Limits::default())
}

#[derive(Default)]
struct RootGroup {
    bytes: u64,
    largest_entry: u64,
    accessed: (i64, i64),
}

fn prune_directory(directory: &Directory, limits: Limits) -> io::Result<()> {
    prune_with_observations(directory, limits, |name| directory.metadata(name))
}

// The quota/ordering contract is independent of external readers changing native atime.
// Production observations always come from the same retained native directory.
fn prune_with_observations(
    directory: &Directory,
    limits: Limits,
    mut observe: impl FnMut(&str) -> io::Result<storage::EntryMetadata>,
) -> io::Result<()> {
    let mut groups = BTreeMap::<String, RootGroup>::new();
    // Enumeration retains at most roots + 1 groups, never an unbounded directory inventory.
    directory.entries(|name, _| {
        if legacy_name(name) || (name.starts_with(".sweepx-") && name.ends_with(".tmp")) {
            return directory.remove(name);
        }
        let Some(key) = group_key(name) else {
            return Ok(());
        };
        if groups.contains_key(key) {
            return Ok(());
        }
        let mut group = RootGroup::default();
        // Observe both members now so eviction does not depend on enumeration order.
        for name in [format!("r-{key}.json"), format!("f-{key}.json")] {
            match observe(&name) {
                Ok(metadata) => {
                    group.bytes = group.bytes.saturating_add(metadata.bytes);
                    group.largest_entry = group.largest_entry.max(metadata.bytes);
                    group.accessed = group.accessed.max(metadata.accessed);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if group.bytes > limits.root_bytes || group.largest_entry > limits.entry_bytes as u64 {
            remove_group(directory, key)?;
            return Ok(());
        }
        groups.insert(key.to_string(), group);
        while groups.len() > limits.roots
            || groups.values().map(|group| group.bytes).sum::<u64>() > limits.disk_bytes
        {
            let oldest = groups
                .iter()
                .min_by_key(|(key, group)| (group.accessed, *key))
                .map(|(key, _)| key.clone())
                .expect("over-budget groups");
            remove_group(directory, &oldest)?;
            groups.remove(&oldest);
        }
        Ok(())
    })?;
    // Retired per-device indexes are never read; remove only their known file namespace.
    match directory.child("subtrees") {
        Ok(legacy) => legacy.entries(|name, _| {
            if legacy_name(name) || (name.starts_with('.') && name.ends_with(".json.tmp")) {
                legacy.remove(name)
            } else {
                Ok(())
            }
        })?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn remove_group(directory: &Directory, key: &str) -> io::Result<()> {
    for name in [format!("r-{key}.json"), format!("f-{key}.json")] {
        match directory.remove(&name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn legacy_name(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(hash_name)
}

fn hash_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn group_key(name: &str) -> Option<&str> {
    let key = name
        .strip_prefix("r-")
        .or_else(|| name.strip_prefix("f-"))?
        .strip_suffix(".json")?;
    hash_name(key).then_some(key)
}

fn excluded_root_keys(root: &Path, roots: &[PathBuf]) -> Vec<String> {
    roots
        .iter()
        .filter(|other| other.as_path() != root && other.starts_with(root))
        .map(|other| root_key(other))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn root_key(root: &Path) -> String {
    format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()))
}
fn record_file_name(root: &Path) -> String {
    format!("r-{}.json", root_key(root))
}
fn index_file_name(root: &Path) -> String {
    format!("f-{}.json", root_key(root))
}

fn root_retained_bytes(root: &StoredJunkRoot) -> usize {
    let mut bytes = std::mem::size_of::<StoredJunkRoot>()
        + root.schema.capacity()
        + root.rules_digest.capacity()
        + root.root.capacity()
        + root.root_device.capacity()
        + root.root_inode.capacity()
        + root.candidates.capacity() * std::mem::size_of::<StoredJunkCandidate>();
    bytes = bytes.saturating_add(
        root.excluded_root_keys
            .capacity()
            .saturating_mul(std::mem::size_of::<String>()),
    );
    for key in &root.excluded_root_keys {
        bytes = bytes.saturating_add(key.capacity());
    }
    for candidate in &root.candidates {
        for text in [
            &candidate.path,
            &candidate.rule_id,
            &candidate.risk,
            &candidate.evidence,
            &candidate.source_reviewed_at,
        ] {
            bytes = bytes.saturating_add(text.capacity());
        }
        bytes =
            bytes.saturating_add(candidate.references.capacity() * std::mem::size_of::<String>());
        for reference in &candidate.references {
            bytes = bytes.saturating_add(reference.capacity());
        }
        bytes = bytes.saturating_add(candidate.entry_id.as_str().len() * 2);
        for identity in &candidate.ancestor_ids {
            bytes = bytes.saturating_add(128 + identity.as_str().len() * 2);
        }
        if let Some(entry) = &candidate.source_entry {
            bytes = bytes.saturating_add(entry.estimated_retained_bytes());
        }
        if let Some(aggregate) = &candidate.aggregate {
            bytes = bytes
                .saturating_add(aggregate.scan_id.len())
                .saturating_add(aggregate.directory_identity.capacity())
                .saturating_add(
                    aggregate.coverage.incomplete_reasons.capacity()
                        * std::mem::size_of::<sweepx_model::ReasonCode>(),
                );
        }
    }
    bytes
}

/// Schema marker for independently root-bound file indexes.
const SUBTREE_SCHEMA: &str = "sweepx.subtree-index/v4";

/// File lengths for one root. Partial optional listings do not authorize subtree skipping:
/// every directory is still enumerated and children absent from this index are inspected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredSubtreeIndex {
    schema: String,
    /// Lossless absolute root spelling; non-UTF-8 roots are not persisted.
    root: String,
    /// Native root binding, checked before and after history observation.
    device: u64,
    inode: u64,
    /// Pre-observation cursor; racing changes remain visible on the next validation.
    since_event_id: FsEventId,
    /// Complete directory enumeration does not imply all optional lengths were retained.
    covered: BTreeMap<String, bool>,
    /// Partial optional facts; missing children are always inspected.
    listings: BTreeMap<String, StoredDirListing>,
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

    fn matches_root(&self, root: &Path) -> bool {
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
        let mut remaining = Limits::default()
            .entry_bytes
            .saturating_sub(1024 + root.as_os_str().len().saturating_mul(6));
        let mut result = Self::new(root, since, BTreeMap::new(), BTreeMap::new())?;
        for (path, listing) in listings {
            if covered.get(path) != Some(&true)
                || all_roots
                    .iter()
                    .filter(|candidate| Path::new(path).starts_with(candidate))
                    .max_by_key(|candidate| candidate.components().count())
                    .map(PathBuf::as_path)
                    != Some(root)
            {
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

fn index_retained_bytes(index: &StoredSubtreeIndex) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_reads_bind_actual_rule_bytes_without_claiming_current_context() {
        let (_fixture, cache) = temp_cache();
        let bytes = b"editable project source";
        let platform = b"editable platform source";
        let stored =
            StoredJunkRoot::capture_with_rule_bytes(&cache, vec![], 42, [7; 32], bytes, platform)
                .unwrap();
        write(&cache, &stored).unwrap();
        let roots = [cache.clone()];
        assert!(
            CacheReader::with_rule_bytes(&cache, bytes, platform).historical_roots(&roots)[0]
                .is_some()
        );
        assert!(
            CacheReader::with_rule_bytes(&cache, b"edited source", platform)
                .historical_roots(&roots)[0]
                .is_none()
        );
        assert!(
            CacheReader::with_rule_bytes(&cache, bytes, platform).roots(&roots, Some(&[8; 32]))[0]
                .is_none()
        );
        assert!(CacheReader::new(&cache).historical_roots(&roots)[0].is_none());
    }

    #[test]
    fn publication_binding_rejects_a_root_replaced_after_observation() {
        let (_fixture, base) = temp_cache();
        let root = base.join("root");
        fs::create_dir(&root).unwrap();
        let summary = sweepx_scanner::Scanner::new(
            sweepx_scanner::HostPlatformScanner::new(),
            sweepx_scanner::ScannerOptions::default(),
        )
        .scan(
            &[sweepx_platform::ScanRoot::new(root.clone()).unwrap()],
            &sweepx_platform::CancellationToken::new(),
        )
        .unwrap();
        let source = &summary.roots[0];
        let initial = StoredJunkRoot::capture(&root, vec![], 42, [0; 32]).unwrap();
        assert!(initial.matches_observed_root(source));
        fs::rename(&root, base.join("original-root")).unwrap();
        fs::create_dir(&root).unwrap();
        let replacement = StoredJunkRoot::capture(&root, vec![], 42, [0; 32]).unwrap();
        assert!(!replacement.matches_observed_root(source));
        let index = StoredSubtreeIndex::new(&root, 42, BTreeMap::new(), BTreeMap::new()).unwrap();
        assert!(!index.matches_observed_root(source));
        assert_ne!(
            fs::symlink_metadata(&root).unwrap().ino(),
            fs::symlink_metadata(base.join("original-root"))
                .unwrap()
                .ino()
        );
    }
    fn temp_cache() -> (tempfile::TempDir, PathBuf) {
        // Atomic exclusive creation isolates parallel tests; a timestamp plus create_dir_all
        // can silently alias another fixture. Keep the guard alive through all native queries.
        let fixture = tempfile::TempDir::new().unwrap();
        let path = fs::canonicalize(fixture.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (fixture, path)
    }

    fn sample_candidate(name: &str) -> StoredJunkCandidate {
        StoredJunkCandidate {
            path: name.to_string(),
            rule_id: "rule:x".to_string(),
            risk: "R2".to_string(),
            reclaimable: ByteValue::Unknown {
                reason: sweepx_model::ReasonCode::UnknownIdentity,
            },
            evidence: String::new(),
            source_reviewed_at: String::new(),
            references: Vec::new(),
            entry_id: ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("test"), 1).unwrap(),
            ancestor_ids: BTreeSet::new(),
            size_is_logical: true,
            source_entry: None,
            git_scan_facts: None,
            aggregate: None,
        }
    }

    #[test]
    fn pre_scan_cursor_survives_capture_and_old_schema_is_refused() {
        let (_fixture, cache) = temp_cache();
        let mut stored = StoredJunkRoot::capture(&cache, vec![], 42, [0; 32]).unwrap();
        assert_eq!(stored.since_event_id, 42);
        assert!(stored.matches_root(&cache));
        stored.rules_digest = "old-rules".into();
        assert!(!stored.matches_root(&cache));
        stored.rules_digest = rules_digest().into();
        for old_schema in [
            "sweepx.junk-cache/v1",
            "sweepx.junk-cache/v5",
            "sweepx.junk-cache/v6",
            "sweepx.junk-cache/v7",
        ] {
            stored.schema = old_schema.into();
            assert!(!stored.matches_root(&cache));
        }
        fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn invalidation_uses_path_components_and_includes_ancestors() {
        assert!(paths_overlap(Path::new("/root"), Path::new("/root/cache")));
        assert!(paths_overlap(
            Path::new("/root/cache/file"),
            Path::new("/root/cache")
        ));
        assert!(!paths_overlap(
            Path::new("/root/cache-other"),
            Path::new("/root/cache")
        ));
    }

    // A manual native microbenchmark; excluded from normal CI because event daemon latency is
    // host-dependent. Both paths validate exactly the same roots and assert identical hits.
    #[test]
    #[ignore = "native FSEvents timing experiment; run explicitly with --nocapture"]
    fn benchmark_batched_root_validation() {
        let (_guard, fixture) = temp_cache();
        let roots: Vec<_> = (0..24)
            .map(|index| {
                let root = fixture.join(format!("root-{index}"));
                fs::create_dir(&root).unwrap();
                root
            })
            .collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let records = loop {
            let cursor = current_event_id();
            let records: Vec<_> = roots
                .iter()
                .map(|root| Some(StoredJunkRoot::capture(root, vec![], cursor, [0; 32]).unwrap()))
                .collect();
            if validate_records(&roots, records.clone())
                .iter()
                .all(Option::is_some)
            {
                break records;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fixture history did not settle"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        for _ in 0..3 {
            let started = std::time::Instant::now();
            let serial: Vec<_> = roots
                .iter()
                .zip(&records)
                .map(|(root, record)| record.as_ref().unwrap().is_current(root))
                .collect();
            let serial_elapsed = started.elapsed();
            let started = std::time::Instant::now();
            let batch: Vec<_> = validate_records(&roots, records.clone())
                .iter()
                .map(Option::is_some)
                .collect();
            let batch_elapsed = started.elapsed();
            assert_eq!(serial, batch);
            assert!(batch.iter().all(|hit| *hit));
            eprintln!("24 unchanged roots: serial={serial_elapsed:?}, batch={batch_elapsed:?}");
        }
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn an_untouched_root_round_trips_as_current() {
        let (_fixture, cache) = temp_cache();
        let root = cache.join("root");
        fs::create_dir(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        // Creation events are asynchronous and can be coalesced after HistoryDone. Wait for
        // a quiet fixture instead of incorrectly requiring immediate cache acceptance.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let stored = StoredJunkRoot::capture(
                &canonical,
                vec![sample_candidate("a")],
                current_event_id(),
                [0; 32],
            )
            .unwrap();
            write(&cache, &stored).unwrap();
            let loaded = load(&cache, &canonical).expect("stored");
            assert_eq!(loaded.candidates_len(), 1);
            if loaded.is_current(&canonical) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "fixture history did not settle"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn a_change_under_the_root_invalidates_the_record() {
        let (_fixture, cache) = temp_cache();
        let root = cache.join("root");
        fs::create_dir(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let stored =
            StoredJunkRoot::capture(&canonical, vec![], current_event_id(), [0; 32]).unwrap();
        write(&cache, &stored).unwrap();
        fs::write(canonical.join("new.txt"), b"x").unwrap();
        let loaded = load(&cache, &canonical).expect("stored");
        assert!(!loaded.is_current(&canonical), "a new file must invalidate");
        fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn prune_preserves_other_requested_generations_while_under_budget() {
        let (_fixture, cache) = temp_cache();
        let keep = cache.join("keep");
        let gone = cache.join("gone");
        fs::create_dir(&keep).unwrap();
        fs::create_dir(&gone).unwrap();
        let keep = fs::canonicalize(&keep).unwrap();
        let gone = fs::canonicalize(&gone).unwrap();

        for root in [&keep, &gone] {
            let stored =
                StoredJunkRoot::capture(root, vec![], current_event_id(), [0; 32]).unwrap();
            write(&cache, &stored).unwrap();
        }
        prune(&cache).unwrap();

        assert!(load(&cache, &keep).is_some());
        assert!(load(&cache, &gone).is_some());

        let _ = fs::remove_dir_all(&cache);
    }
    #[test]
    fn disk_eviction_removes_whole_oldest_groups_and_keeps_unknown_files() {
        let (_fixture, cache) = temp_cache();
        let roots: Vec<_> = ["old", "middle", "new"]
            .into_iter()
            .map(|name| {
                let root = cache.join(name);
                fs::create_dir(&root).unwrap();
                let record = StoredJunkRoot::capture(&root, vec![], 12, [0; 32]).unwrap();
                write(&cache, &record).unwrap();
                let index =
                    StoredSubtreeIndex::new(&root, 12, BTreeMap::new(), BTreeMap::new()).unwrap();
                write_subtree_index(&cache, &index).unwrap();
                root
            })
            .collect();
        fs::write(cache.join("user.json"), b"keep").unwrap();
        let directory = Directory::open(&cache, false).unwrap();
        // Host readers can change native atime asynchronously. Inject controlled ordering
        // observations while retaining real no-follow metadata for file existence and bytes.
        let observe = |name: &str| {
            let mut observation = directory.metadata(name)?;
            let ordinal = roots
                .iter()
                .position(|root| name == record_file_name(root) || name == index_file_name(root))
                .unwrap();
            observation.accessed = (100 + ordinal as i64, 0);
            Ok(observation)
        };
        let limits = Limits {
            roots: 2,
            ..Limits::default()
        };
        prune_with_observations(&directory, limits, observe).unwrap();
        for name in [record_file_name(&roots[0]), index_file_name(&roots[0])] {
            assert!(!cache.join(name).exists());
        }
        for root in &roots[1..] {
            for name in [record_file_name(root), index_file_name(root)] {
                assert!(cache.join(name).exists());
            }
        }
        assert_eq!(fs::read(cache.join("user.json")).unwrap(), b"keep");
        // Independent directory metadata checks the encoded disk contract, rather than using
        // the eviction inventory as its own oracle.
        let actual_bytes: u64 = fs::read_dir(&cache)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| group_key(entry.file_name().to_str().unwrap()).is_some())
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        prune_with_observations(
            &directory,
            Limits {
                disk_bytes: actual_bytes - 1,
                ..limits
            },
            observe,
        )
        .unwrap();
        let remaining: u64 = fs::read_dir(&cache)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| group_key(entry.file_name().to_str().unwrap()).is_some())
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        assert!(remaining < actual_bytes);
        assert!(!cache.join(record_file_name(&roots[1])).exists());
        assert!(!cache.join(index_file_name(&roots[1])).exists());
        prune_with_observations(
            &directory,
            Limits {
                root_bytes: 1,
                ..limits
            },
            observe,
        )
        .unwrap();
        assert!(!cache.join(record_file_name(&roots[2])).exists());
        assert!(!cache.join(index_file_name(&roots[2])).exists());
    }

    #[test]
    fn migration_removes_only_known_legacy_cache_entries() {
        use std::os::unix::fs::PermissionsExt;
        let (_fixture, cache) = temp_cache();
        let old_name = format!("{}.json", "a".repeat(64));
        fs::write(cache.join(&old_name), b"retired").unwrap();
        let subtrees = cache.join("subtrees");
        fs::create_dir(&subtrees).unwrap();
        fs::set_permissions(&subtrees, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(subtrees.join(&old_name), b"retired").unwrap();
        fs::write(subtrees.join("notes.json"), b"keep").unwrap();
        fs::write(cache.join("notes.json"), b"keep").unwrap();
        prune(&cache).unwrap();
        assert!(!cache.join(&old_name).exists());
        assert!(!subtrees.join(&old_name).exists());
        assert_eq!(fs::read(subtrees.join("notes.json")).unwrap(), b"keep");
        assert_eq!(fs::read(cache.join("notes.json")).unwrap(), b"keep");
    }

    #[test]
    fn nested_root_attribution_cannot_be_reused_for_a_different_request_scope() {
        let (_fixture, cache) = temp_cache();
        let parent = cache.join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let roots = vec![parent.clone(), child];
        let mut record = StoredJunkRoot::capture(&parent, vec![], 40, [0; 32]).unwrap();
        record.bind_scope(&roots);
        write(&cache, &record).unwrap();
        assert!(CacheReader::new(&cache).roots(&roots, Some(&[0; 32]))[0].is_some());
        assert!(
            CacheReader::new(&cache).roots(&[parent], Some(&[0; 32]))[0].is_none(),
            "child-owned candidates are missing from the parent-only report"
        );
    }

    #[test]
    fn capture_omits_nested_root_facts_and_limits_optional_copies() {
        let (_fixture, cache) = temp_cache();
        let parent = cache.join("parent");
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();
        let roots = vec![parent.clone(), child.clone()];
        let mut files = BTreeMap::new();
        for ordinal in 0..6000 {
            files.insert(format!("{ordinal:04}-{}", "x".repeat(240)), ordinal);
        }
        let parent_path = parent.to_str().unwrap().to_string();
        let child_path = child.to_str().unwrap().to_string();
        let covered = [(parent_path.clone(), true), (child_path.clone(), true)]
            .into_iter()
            .collect();
        let listings = [
            (
                parent_path.clone(),
                sweepx_scanner::DirListing {
                    files,
                    dirs: BTreeSet::new(),
                },
            ),
            (child_path.clone(), sweepx_scanner::DirListing::default()),
        ]
        .into_iter()
        .collect();
        let index = StoredSubtreeIndex::capture(&parent, &roots, 5, &covered, &listings).unwrap();
        assert!(!index.is_covered(&child_path));
        let saved = &index.listing(&parent_path).unwrap().files;
        assert!(!saved.is_empty());
        assert!(
            saved.len() < 6000,
            "optional index must truncate before copying everything"
        );
        for (name, bytes) in saved {
            assert_eq!(Some(bytes), listings[&parent_path].files.get(name));
        }
        write_subtree_index(&cache, &index).unwrap();
        let wire_bytes = fs::metadata(cache.join(index_file_name(&parent)))
            .unwrap()
            .len();
        assert!(wire_bytes <= 4 * 1024 * 1024);
        assert_eq!(CacheReader::new(&cache).index(&parent).unwrap(), index);
    }
    #[test]
    fn unsafe_retired_namespace_cannot_bypass_active_cache_eviction() {
        use std::os::unix::fs::symlink;
        let (_fixture, cache) = temp_cache();
        let root = cache.join("root");
        fs::create_dir(&root).unwrap();
        write(
            &cache,
            &StoredJunkRoot::capture(&root, vec![], 10, [0; 32]).unwrap(),
        )
        .unwrap();
        let external = cache.join("external");
        fs::create_dir(&external).unwrap();
        let outside_file = external.join(format!("{}.json", "a".repeat(64)));
        fs::write(&outside_file, b"must stay").unwrap();
        symlink(&external, cache.join("subtrees")).unwrap();
        let directory = Directory::open(&cache, false).unwrap();
        assert!(
            prune_directory(
                &directory,
                Limits {
                    roots: 0,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(!cache.join(record_file_name(&root)).exists());
        assert_eq!(fs::read(outside_file).unwrap(), b"must stay");
    }
    #[test]
    fn root_scope_vector_reservations_count_as_retained_metadata() {
        let (_fixture, cache) = temp_cache();
        let mut record = StoredJunkRoot::capture(&cache, vec![], 1, [0; 32]).unwrap();
        let baseline = root_retained_bytes(&record);
        record.excluded_root_keys = Vec::with_capacity(4096);
        let owned_slots = record.excluded_root_keys.capacity() * std::mem::size_of::<String>();
        assert!(root_retained_bytes(&record) >= baseline + owned_slots);
    }
}
