//! Current Git evidence over native candidate locators. Traversal facts may be reused only under
//! complete filesystem-history validation; Git answers and repository discovery are invocation-local.

use super::candidate::{GitIgnoreEvidence, JunkCandidate};
use crate::tools::{ProbeLimits, ProbeRunner};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use sweepx_model::{
    Coverage, IdentityEvidence, NativeName, NativePathComponent, ObjectType, ScanEntryId,
};
use sweepx_platform::{CancellationToken, EntryMetadata, PlatformScanner, ScanRoot, WalkEntry};
use sweepx_scanner::HostPlatformScanner;

/// Filesystem traversal facts, without Git configuration, ignore status or confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GitScanFacts {
    /// The candidate subtree had complete traversal and retained classification evidence.
    pub complete: bool,
    /// A `.git` directory or gitfile was observed at or below the candidate.
    pub contains_repository: bool,
}

/// Bounds shared by cold and cached Git enrichment in one invocation.
#[derive(Debug, Clone, Copy)]
pub struct GitEvidenceLimits {
    /// Cooperative filesystem deadline, checked between native calls.
    pub deadline: Duration,
    /// Maximum native directory admissions, including revalidation around queries.
    pub max_observations: usize,
    /// Maximum directory lineage records considered for nested-repository evidence.
    pub max_lineage_records: usize,
    /// Conservative retained-data estimate, including borrowed lineage nodes and discovery facts.
    pub max_retained_bytes: usize,
    /// Process deadlines, launch count and stdout bound for all Git queries.
    pub probes: ProbeLimits,
}

impl Default for GitEvidenceLimits {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(5),
            max_observations: 1024,
            max_lineage_records: 65_536,
            max_retained_bytes: 8 * 1024 * 1024,
            probes: ProbeLimits {
                total_timeout: Duration::from_secs(5),
                max_processes: 256,
                ..ProbeLimits::default()
            },
        }
    }
}

#[derive(Clone)]
enum Marker {
    Absent,
    Gitfile,
    Repository {
        directory: Box<EntryMetadata>,
        git: Box<EntryMetadata>,
    },
    Unavailable,
}

/// Invocation-local current Git queries. Use on a worker; native OS calls may block despite the
/// cooperative deadline. Errors keep base confidence and never supply deletion authorization.
pub struct GitEvidenceSession {
    backend: HostPlatformScanner,
    cancel: CancellationToken,
    limits: GitEvidenceLimits,
    deadline: Option<Instant>,
    probes: ProbeRunner,
    observations: usize,
    retained: usize,
    markers: BTreeMap<PathBuf, Marker>,
}

impl GitEvidenceSession {
    /// Shares one bounded probe/discovery budget across fresh and cached candidates.
    pub fn new(limits: GitEvidenceLimits, cancel: CancellationToken) -> Self {
        Self {
            backend: HostPlatformScanner::new(),
            cancel: cancel.clone(),
            deadline: Instant::now().checked_add(limits.deadline),
            probes: ProbeRunner::new(limits.probes, cancel),
            limits,
            observations: 0,
            retained: 0,
            markers: BTreeMap::new(),
        }
    }

    fn available(&self) -> bool {
        !self.cancel.is_cancelled()
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() < deadline)
    }

    fn charge(&mut self, bytes: usize) -> bool {
        if !self.available() || self.retained.saturating_add(bytes) > self.limits.max_retained_bytes
        {
            return false;
        }
        self.retained += bytes;
        true
    }

    /// Captures only nested-repository/coverage facts from a fresh traversal. Facts absent due to
    /// resource or coverage loss cannot prove that a candidate contains no repository. Caller may
    /// persist these scalars only with the same validated root coverage and pre-scan change cursor.
    pub fn capture_scan_facts<'a>(
        &mut self,
        summary: &crate::ScanSummary,
        coverages: &BTreeMap<ScanEntryId, Coverage>,
        directory_markers: &BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>,
        candidates: impl IntoIterator<Item = &'a mut JunkCandidate>,
    ) {
        // Borrow candidates rather than copying their native locators. The temporary reference
        // index is itself bounded; once it cannot fit, all incoming facts remain unknown.
        let mut retained_candidates = Vec::new();
        let mut incomplete = false;
        for candidate in candidates {
            candidate.git_scan_facts = None;
            if !incomplete && retained_candidates.len() < self.limits.max_lineage_records {
                if retained_candidates.len() == retained_candidates.capacity() {
                    // Reserve in small explicit batches, charging capacity rather than length.
                    // An allocator may grant more slots than requested; charge those too before
                    // using the index. Overflow abandons all facts, including later inputs.
                    let additional =
                        32.min(self.limits.max_lineage_records - retained_candidates.len());
                    let before = retained_candidates.capacity();
                    let slot_bytes = std::mem::size_of::<&mut JunkCandidate>();
                    if !self.charge(additional.saturating_mul(slot_bytes))
                        || retained_candidates.try_reserve_exact(additional).is_err()
                        || !self.charge(
                            retained_candidates
                                .capacity()
                                .saturating_sub(before + additional)
                                .saturating_mul(slot_bytes),
                        )
                    {
                        incomplete = true;
                        retained_candidates.clear();
                        continue;
                    }
                }
                retained_candidates.push(candidate);
            } else {
                incomplete = true;
            }
        }
        if incomplete
            || !retained_candidates
                .iter()
                .any(|candidate| is_project_candidate(candidate))
        {
            return;
        }
        if summary
            .boundaries
            .iter()
            .any(|boundary| boundary.kind == sweepx_platform::BoundaryKind::ResourceLimit)
        {
            return;
        }
        let mut parents = BTreeMap::new();
        let mut repositories = Vec::new();
        for (parent, children) in directory_markers {
            for (name, child) in children {
                if parents.len() >= self.limits.max_lineage_records || !self.charge(96) {
                    return;
                }
                parents.insert(child, parent);
                if name == ".git" {
                    if !self.charge(32) {
                        return;
                    }
                    repositories.push(parent);
                }
            }
        }
        // Classified scans retain sparse gitfile rows, even though other ordinary files are pruned.
        for row in &summary.entries {
            if row.object_type == ObjectType::File
                && is_git_name(&row.native_basename)
                && let Some(parent) = row.identity.as_ref().and_then(|id| id.parent_id.as_ref())
            {
                if !self.charge(32) {
                    return;
                }
                repositories.push(parent);
            }
        }
        for candidate in retained_candidates {
            if !is_project_candidate(candidate) {
                continue;
            }
            let complete = coverages
                .get(&candidate.entry_id)
                .is_some_and(|coverage| coverage.complete && !coverage.details_lost);
            let mut nested = false;
            for repository in &repositories {
                let mut current = Some(*repository);
                let mut depth = 0;
                while let Some(id) = current {
                    if !self.available() || depth >= 4096 {
                        return;
                    }
                    if id == &candidate.entry_id {
                        nested = true;
                        break;
                    }
                    current = parents.get(id).copied();
                    depth += 1;
                }
                if nested {
                    break;
                }
            }
            candidate.git_scan_facts = Some(GitScanFacts {
                complete,
                contains_repository: nested,
            });
        }
    }

    /// Rebuilds current Git interpretation. Historical Git fields are always cleared. Reused
    /// traversal facts require independently validated root history; unknown facts retain a blocker.
    /// The closest current repository may be outside the selected scan root. Linked/gitfile/mount
    /// boundaries, changed identities, query failure, cancellation or budget loss cannot promote.
    pub fn refresh(&mut self, candidates: &mut [JunkCandidate]) {
        for candidate in candidates {
            if !is_project_candidate(candidate) {
                continue;
            }
            candidate.git = None;
            candidate.classification = Some("known_generated".into());
            candidate.confidence = Some("medium".into());
            candidate.reset_project_format_interpretation();
            candidate.blockers.retain(|blocker| {
                !matches!(
                    blocker.as_str(),
                    "git_evidence_not_revalidated"
                        | "git_scan_evidence_incomplete"
                        | "git_path_binding_unavailable"
                        | "git_identity_changed"
                        | "git_query_budget_exhausted"
                        | "git_query_failed"
                        | "gitfile_repository_boundary"
                        | "git_repository_boundary"
                        | "tracked_descendant"
                        | "nested_repository"
                )
            });
            let result = self.refresh_one(candidate);
            if let Err(blocker) = result {
                candidate.blockers.push(blocker.into());
            }
        }
    }

    fn admit(
        &mut self,
        path: &Path,
    ) -> Option<
        sweepx_platform::RootAdmission<<HostPlatformScanner as PlatformScanner>::DirectoryHandle>,
    > {
        if !self.available()
            || self.observations >= self.limits.max_observations
            || path.as_os_str().len() > 64 * 1024
        {
            return None;
        }
        self.observations += 1;
        self.backend
            .admit_root(&ScanRoot::new(path.to_path_buf()).ok()?, &self.cancel)
            .ok()
    }

    fn observation_failure(&self) -> &'static str {
        if !self.available() || self.observations >= self.limits.max_observations {
            "git_query_budget_exhausted"
        } else {
            "git_path_binding_unavailable"
        }
    }

    fn marker(&mut self, path: &Path) -> Marker {
        if let Some(marker) = self.markers.get(path) {
            return marker.clone();
        }
        if !self.charge(1024usize.saturating_add(path.as_os_str().len().saturating_mul(8))) {
            return Marker::Unavailable;
        }
        let observed = self.observe_marker(path);
        self.markers.insert(path.to_path_buf(), observed.clone());
        observed
    }

    fn observe_marker(&mut self, path: &Path) -> Marker {
        let Some(root) = self.admit(path) else {
            return Marker::Unavailable;
        };
        let name = if cfg!(windows) {
            NativeName::windows_utf16(".git".encode_utf16().collect::<Vec<_>>())
        } else {
            NativeName::unix(b".git".to_vec())
        };
        let Ok(child) = sweepx_platform::DirectoryEntryRecord::from_parent_and_name(path, name)
        else {
            return Marker::Unavailable;
        };
        match sweepx_platform::inspect_bound_child(
            &self.backend,
            &root.directory,
            path,
            &child,
            &self.cancel,
        ) {
            Ok(WalkEntry::Error(error)) if error.kind == sweepx_platform::ErrorKind::NotFound => {
                Marker::Absent
            }
            Ok(WalkEntry::File(_)) => Marker::Gitfile,
            Ok(WalkEntry::Directory(opened))
                if self
                    .backend
                    .is_same_mount(&root.metadata, &opened.metadata)
                    .unwrap_or(false) =>
            {
                Marker::Repository {
                    directory: Box::new(root.metadata),
                    git: Box::new(opened.metadata),
                }
            }
            _ => Marker::Unavailable,
        }
    }

    fn refresh_one(&mut self, candidate: &mut JunkCandidate) -> Result<(), &'static str> {
        let facts = candidate
            .git_scan_facts
            .ok_or("git_scan_evidence_incomplete")?;
        if !facts.complete {
            return Err("git_scan_evidence_incomplete");
        }
        if facts.contains_repository {
            return Err("nested_repository");
        }
        if !self.available() {
            return Err("git_query_budget_exhausted");
        }
        let row = candidate
            .source_entry
            .as_ref()
            .ok_or("git_path_binding_unavailable")?;
        let locator = row
            .validated_native_locator()
            .ok()
            .flatten()
            .ok_or("git_path_binding_unavailable")?;
        let path = native_path(row).ok_or("git_path_binding_unavailable")?;
        let admitted = self
            .admit(&path)
            .ok_or_else(|| self.observation_failure())?;
        if !matches_component(&locator.entry, &admitted.metadata) {
            return Err("git_identity_changed");
        }
        let device = admitted.metadata.filesystem_identity.clone();
        let mount = admitted.metadata.mount_identity.clone();
        drop(admitted);
        let mut repository_path = path.clone();
        loop {
            let parent = self
                .admit(&repository_path)
                .ok_or_else(|| self.observation_failure())?;
            if parent.metadata.filesystem_identity != device
                || parent.metadata.mount_identity != mount
            {
                return Err("git_repository_boundary");
            }
            // Captured ancestors still have to name the same native objects; ancestors outside
            // the scan have fresh identities and never inherit authority from display strings.
            let component = component_at_path(row, &repository_path);
            if component.is_some_and(|component| !matches_component(component, &parent.metadata)) {
                return Err("git_identity_changed");
            }
            drop(parent);
            match self.marker(&repository_path) {
                Marker::Absent => {
                    let Some(parent) = repository_path.parent() else {
                        return Ok(());
                    };
                    repository_path = parent.to_path_buf();
                }
                Marker::Gitfile => return Err("gitfile_repository_boundary"),
                Marker::Unavailable => {
                    return Err(
                        if !self.available() || self.observations >= self.limits.max_observations {
                            "git_query_budget_exhausted"
                        } else {
                            "git_repository_boundary"
                        },
                    );
                }
                Marker::Repository { directory, git } => {
                    if !self.repository_current(&directory, &git) {
                        return Err("git_identity_changed");
                    }
                    // Do not let ambient GIT_DIR/INDEX_FILE/WORK_TREE redirect queries away from
                    // the native repository whose scope we just observed.
                    self.check_query_scope(&repository_path, &git)?;
                    let tracked = self.query(
                        &repository_path,
                        &["ls-files", "--error-unmatch"],
                        &path,
                        true,
                    )?;
                    if tracked == 0 {
                        return Err("tracked_descendant");
                    }
                    if tracked != 1 {
                        return Err("git_query_failed");
                    }
                    let ignored =
                        self.query(&repository_path, &["check-ignore", "--quiet"], &path, false)?;
                    if !self.repository_current(&directory, &git) {
                        return Err("git_identity_changed");
                    }
                    match ignored {
                        0 => {
                            let repository_entry_id = component
                                .map(|component| component.entry_id.to_string())
                                .unwrap_or_else(|| {
                                    let identity = directory
                                        .identity
                                        .as_ref()
                                        .expect("known native repository identity");
                                    format!(
                                        "git-native:{}:{}:{}",
                                        identity.device(),
                                        identity.inode(),
                                        mount.as_ref().expect("known mount").value
                                    )
                                });
                            candidate.git = Some(GitIgnoreEvidence {
                                status: "ignored".into(),
                                repository_entry_id,
                                check: "git.check-ignore.v1".into(),
                            });
                            if candidate.project_format.is_none() {
                                candidate.classification = Some("known_generated_ignored".into());
                                candidate.confidence = Some("high".into());
                            }
                            return Ok(());
                        }
                        1 => return Ok(()),
                        _ => return Err("git_query_failed"),
                    }
                }
            }
        }
    }

    fn repository_current(&mut self, directory: &EntryMetadata, git: &EntryMetadata) -> bool {
        match self.observe_marker(&directory.path) {
            Marker::Repository {
                directory: current,
                git: marker,
            } => same_metadata(directory, &current) && same_metadata(git, &marker),
            _ => false,
        }
    }

    fn command(&self, repository: &Path, arguments: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .arg("--no-optional-locks")
            .args(["-c", "core.fsmonitor=false", "-C"])
            .arg(repository)
            .args(arguments);
        // Repository/index redirection is not authority over the candidate's native tree.
        // Keep configuration selectors (GLOBAL/SYSTEM/COUNT) so current ignore policy is
        // observed; rev-parse rejects configuration that changes worktree scope. Command's
        // native environment-key semantics also handle case-insensitive Windows keys.
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_PREFIX",
        ] {
            command.env_remove(key);
        }
        command
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat");
        command
    }

    fn check_query_scope(
        &mut self,
        repository: &Path,
        git: &EntryMetadata,
    ) -> Result<(), &'static str> {
        for (argument, expected) in [
            ("--show-toplevel", repository),
            ("--absolute-git-dir", git.path.as_path()),
        ] {
            if self.probes.is_exhausted() {
                return Err("git_query_budget_exhausted");
            }
            let mut command = self.command(repository, &["rev-parse", argument]);
            let output = self
                .probes
                .run(&mut command)
                .map_err(|_| "git_query_failed")?;
            if !output.status.success() {
                return Err("git_query_failed");
            }
            let path = output_path(&output.stdout).ok_or("git_repository_boundary")?;
            // Git may normalize spelling; native admission compares identity and enforces no-follow.
            let actual = self.admit(&path).ok_or("git_repository_boundary")?;
            let expected = self.admit(expected).ok_or("git_repository_boundary")?;
            if !same_metadata(&actual.metadata, &expected.metadata) {
                return Err("git_repository_boundary");
            }
        }
        Ok(())
    }

    fn query(
        &mut self,
        repository: &Path,
        arguments: &[&str],
        path: &Path,
        literal: bool,
    ) -> Result<i32, &'static str> {
        if !self.available() || self.probes.is_exhausted() {
            return Err("git_query_budget_exhausted");
        }
        let relative = path
            .strip_prefix(repository)
            .map_err(|_| "git_path_binding_unavailable")?;
        if relative.as_os_str().is_empty() {
            return Err("git_repository_boundary");
        }
        let mut command = self.command(repository, arguments);
        command.arg("--").arg(Path::new(".").join(relative));
        if literal {
            command.env("GIT_LITERAL_PATHSPECS", "1");
        }
        self.probes
            .run(&mut command)
            .map_err(|_| "git_query_failed")?
            .status
            .code()
            .ok_or("git_query_failed")
    }
}

fn same_metadata(a: &EntryMetadata, b: &EntryMetadata) -> bool {
    a.identity.is_some()
        && a.identity == b.identity
        && a.filesystem_identity.is_some()
        && a.filesystem_identity == b.filesystem_identity
        && a.mount_identity.is_some()
        && a.mount_identity == b.mount_identity
        && a.fingerprint == b.fingerprint
}

fn is_project_candidate(candidate: &JunkCandidate) -> bool {
    candidate.project_format.is_some()
        || matches!(
            candidate.classification.as_deref(),
            Some("known_generated" | "known_generated_ignored")
        )
}

fn matches_component(component: &NativePathComponent, metadata: &EntryMetadata) -> bool {
    matches!(&component.platform_file_identity, IdentityEvidence::Known { value }
        if metadata.identity.as_ref().is_some_and(|id|
            value.device.0 == u128::from(id.device()) && value.inode.0 == id.inode()))
        && matches!(&component.filesystem_object_domain_identity, IdentityEvidence::Known { value }
            if metadata.filesystem_identity.as_ref().is_some_and(|id| value.device.0 == u128::from(id.device)))
        && matches!(&component.volume_or_mount_identity, IdentityEvidence::Known { value }
            if metadata.mount_identity.as_ref().is_some_and(|id| value.value.0 == u128::from(id.value)))
}

fn native_name(name: &NativeName) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        if let NativeName::UnixBytes(bytes) = name
            && bytes.len() <= 64 * 1024
        {
            return Some(OsString::from_vec(bytes.clone()));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if let NativeName::WindowsUtf16(units) = name
            && units.len() <= 32 * 1024
        {
            return Some(OsString::from_wide(units));
        }
    }
    None
}

fn is_git_name(name: &NativeName) -> bool {
    match name {
        NativeName::UnixBytes(bytes) => bytes == b".git",
        NativeName::WindowsUtf16(units) => {
            units.len() == 4
                && units.iter().zip(b".git").all(|(unit, byte)| {
                    u8::try_from(*unit).is_ok_and(|unit| unit.to_ascii_lowercase() == *byte)
                })
        }
    }
}

fn output_path(bytes: &[u8]) -> Option<PathBuf> {
    let bytes = bytes.strip_suffix(b"\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }
    #[cfg(windows)]
    {
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        Some(PathBuf::from(std::str::from_utf8(bytes).ok()?))
    }
}

fn captured_path<'a>(
    row: &'a sweepx_model::ScannedEntry,
    wanted: Option<&Path>,
) -> Option<(PathBuf, Option<&'a NativePathComponent>)> {
    let locator = row.validated_native_locator().ok().flatten()?;
    if locator.parent_reopen_recipe.len() > 256 {
        return None;
    }
    let mut path = native_root_path(row)?;
    let mut found = (wanted == Some(path.as_path())).then_some(&locator.scan_root);
    if locator.entry.entry_id != locator.scan_root.entry_id {
        for component in locator
            .parent_reopen_recipe
            .iter()
            .skip(1)
            .chain(std::iter::once(&locator.entry))
        {
            path.push(native_name(&component.native_basename)?);
            if path.as_os_str().len() > 64 * 1024 {
                return None;
            }
            if wanted == Some(path.as_path()) {
                found = Some(component);
            }
        }
    }
    Some((path, found))
}

// Shared with scan sessions for presentation keys and read-only refresh roots. Neither decoded
// path carries authority: callers must independently check the captured native binding.
pub(super) fn native_root_path(row: &sweepx_model::ScannedEntry) -> Option<PathBuf> {
    let locator = row.validated_native_locator().ok().flatten()?;
    let absolute = locator.scan_root_absolute_path.as_ref()?;
    #[cfg(unix)]
    let path = {
        use std::os::unix::ffi::OsStringExt;
        match absolute {
            sweepx_model::NativeAbsolutePath::UnixBytes(bytes) if bytes.len() <= 64 * 1024 => {
                PathBuf::from(OsString::from_vec(bytes.clone()))
            }
            _ => return None,
        }
    };
    #[cfg(windows)]
    let path = {
        use std::os::windows::ffi::OsStringExt;
        match absolute {
            sweepx_model::NativeAbsolutePath::WindowsUtf16(units) if units.len() <= 32 * 1024 => {
                PathBuf::from(OsString::from_wide(units))
            }
            _ => return None,
        }
    };
    Some(path)
}

pub(super) fn native_path(row: &sweepx_model::ScannedEntry) -> Option<PathBuf> {
    Some(captured_path(row, None)?.0)
}

fn component_at_path<'a>(
    row: &'a sweepx_model::ScannedEntry,
    path: &Path,
) -> Option<&'a NativePathComponent> {
    captured_path(row, Some(path))?.1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::junk::JunkService;

    fn git(root: &Path, args: &[&str]) {
        let mut command = Command::new("git");
        command.arg("-C").arg(root).args(args);
        let output = ProbeRunner::new(ProbeLimits::default(), CancellationToken::new())
            .run(&mut command)
            .unwrap();
        assert!(output.status.success(), "git {args:?}");
    }

    fn scan(root: &Path) -> Vec<JunkCandidate> {
        scan_with_limits(root, GitEvidenceLimits::default())
    }

    fn scan_with_limits(root: &Path, limits: GitEvidenceLimits) -> Vec<JunkCandidate> {
        let service = JunkService::built_in().unwrap();
        let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
            &context,
            &crate::ScanRequest {
                roots: vec![root.to_path_buf()],
                state_dir: None,
            },
            None,
            &service,
            None,
        )
        .unwrap();
        let aggregates = scan
            .scan
            .summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
            .collect();
        let mut candidates = scan
            .scan
            .summary
            .roots
            .iter()
            .chain(&scan.scan.summary.entries)
            .filter_map(|row| {
                let decision = scan.decisions.get(&row.identity.as_ref()?.entry_id)?;
                service.interpret(
                    decision,
                    row,
                    &aggregates,
                    &[],
                    &super::super::platform::PlatformJunkEvidence::default(),
                )
            })
            .collect::<Vec<_>>();
        GitEvidenceSession::new(limits, CancellationToken::new()).capture_scan_facts(
            &scan.scan.summary,
            &scan.coverages,
            &scan.directory_markers,
            &mut candidates,
        );
        candidates
    }

    fn session() -> GitEvidenceSession {
        GitEvidenceSession::new(GitEvidenceLimits::default(), CancellationToken::new())
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let owner = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let base = owner.path().canonicalize().unwrap();
        #[cfg(windows)]
        let base = owner.path().to_path_buf();
        let project = base.join("project");
        std::fs::create_dir_all(project.join("target")).unwrap();
        std::fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        std::fs::write(project.join("target/file"), b"user-content").unwrap();
        git(&base, &["init", "--quiet"]);
        std::fs::write(base.join("excludes"), b"project/target/\n").unwrap();
        git(
            &base,
            &[
                "config",
                "core.excludesFile",
                base.join("excludes").to_str().unwrap(),
            ],
        );
        (owner, base, project)
    }

    #[test]
    fn retained_filesystem_facts_refresh_external_ignore_index_and_gitfile() {
        let (_owner, base, project) = fixture();
        let mut candidates = scan(&project);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].git_scan_facts.unwrap().complete);
        session().refresh(&mut candidates);
        assert_eq!(candidates[0].confidence.as_deref(), Some("high"));
        candidates[0].path = "/misleading/presentation/path".into();
        candidates[0].source_entry.as_mut().unwrap().display_path = "/also/misleading".into();
        assert!(
            candidates[0]
                .git
                .as_ref()
                .unwrap()
                .repository_entry_id
                .starts_with("git-native:")
        );
        // Only inputs outside the selected scan root change. Reuse exactly the old traversal facts.
        std::fs::write(base.join("excludes"), b"").unwrap();
        session().refresh(&mut candidates);
        assert_eq!(candidates[0].confidence.as_deref(), Some("medium"));
        assert!(candidates[0].git.is_none());
        assert!(candidates[0].blockers.is_empty());
        std::fs::write(base.join("excludes"), b"project/target/\n").unwrap();
        git(&base, &["add", "--force", "project/target/file"]);
        session().refresh(&mut candidates);
        assert_eq!(candidates[0].blockers, ["tracked_descendant"]);
        assert_eq!(candidates[0].confidence.as_deref(), Some("medium"));
        std::fs::rename(base.join(".git"), base.join("retained-git")).unwrap();
        std::fs::write(base.join(".git"), b"gitdir: retained-git\n").unwrap();
        session().refresh(&mut candidates);
        assert_eq!(candidates[0].blockers, ["gitfile_repository_boundary"]);
        #[cfg(unix)]
        {
            std::fs::remove_file(base.join(".git")).unwrap();
            std::os::unix::fs::symlink(base.join("retained-git"), base.join(".git")).unwrap();
            session().refresh(&mut candidates);
            assert_eq!(candidates[0].blockers, ["git_repository_boundary"]);
        }
        let names = std::fs::read_dir(project.join("target"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [OsString::from("file")]);
        assert_eq!(
            std::fs::symlink_metadata(project.join("target/file"))
                .unwrap()
                .len(),
            12
        );
    }

    #[test]
    fn git_ignore_does_not_promote_required_project_content_or_ownership() {
        use crate::junk::format::{ProjectFormatEvidence, ProjectFormatStatus};
        let (_owner, _base, project) = fixture();
        for profile in [
            sweepx_catalog::junk::ProjectContentFormat::DartPubPackageConfigV2,
            sweepx_catalog::junk::ProjectContentFormat::SvelteKitLegacySync,
        ] {
            for status in [
                ProjectFormatStatus::NotChecked,
                ProjectFormatStatus::Unknown,
                ProjectFormatStatus::Invalid,
                ProjectFormatStatus::Recognized,
            ] {
                let mut rows = scan(&project);
                // Exercise the shared Git contract independently of the Dart parser/native reader.
                rows[0].project_format = Some(ProjectFormatEvidence {
                    profile,
                    status,
                    reason: "controlled_test_observation",
                });
                session().refresh(&mut rows);
                assert_eq!(rows[0].git.as_ref().unwrap().status, "ignored");
                assert_eq!(
                    rows[0].confidence.as_deref(),
                    Some(if status == ProjectFormatStatus::Recognized {
                        "medium"
                    } else {
                        "low"
                    })
                );
                assert_ne!(
                    rows[0].classification.as_deref(),
                    Some("known_generated_ignored")
                );
                assert_eq!(
                    rows[0].project_execution_blocker(),
                    Some("project_ownership_not_verified")
                );
            }
        }
    }

    #[test]
    fn nested_gitfiles_missing_facts_budgets_and_replaced_identity_cannot_promote() {
        let (_owner, base, project) = fixture();
        std::fs::create_dir_all(project.join("target/embedded")).unwrap();
        std::fs::write(project.join("target/embedded/.git"), b"gitdir: elsewhere\n").unwrap();
        let mut nested = scan(&project);
        session().refresh(&mut nested);
        assert_eq!(nested[0].blockers, ["nested_repository"]);
        std::fs::remove_file(project.join("target/embedded/.git")).unwrap();
        let original = scan(&project);
        for limits in [
            GitEvidenceLimits {
                max_lineage_records: 0,
                ..GitEvidenceLimits::default()
            },
            GitEvidenceLimits {
                max_retained_bytes: 0,
                ..GitEvidenceLimits::default()
            },
        ] {
            let mut unavailable = scan_with_limits(&project, limits);
            assert!(unavailable[0].git_scan_facts.is_none());
            session().refresh(&mut unavailable);
            assert_eq!(unavailable[0].blockers, ["git_scan_evidence_incomplete"]);
        }
        let mut non_project = original.clone();
        non_project[0].classification = Some("stale_inactive_temp".into());
        session().refresh(&mut non_project);
        assert_eq!(
            non_project[0].classification.as_deref(),
            Some("stale_inactive_temp")
        );
        let mut unknown = original.clone();
        unknown[0].git_scan_facts = None;
        session().refresh(&mut unknown);
        assert_eq!(unknown[0].blockers, ["git_scan_evidence_incomplete"]);
        for limits in [
            GitEvidenceLimits {
                max_observations: 0,
                ..GitEvidenceLimits::default()
            },
            GitEvidenceLimits {
                deadline: Duration::ZERO,
                ..GitEvidenceLimits::default()
            },
            GitEvidenceLimits {
                max_retained_bytes: 0,
                ..GitEvidenceLimits::default()
            },
        ] {
            let mut candidates = original.clone();
            GitEvidenceSession::new(limits, CancellationToken::new()).refresh(&mut candidates);
            assert_eq!(candidates[0].confidence.as_deref(), Some("medium"));
            assert!(candidates[0].git.is_none());
            assert!(!candidates[0].blockers.is_empty());
        }
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut cancelled = original.clone();
        GitEvidenceSession::new(GitEvidenceLimits::default(), cancel).refresh(&mut cancelled);
        assert_eq!(cancelled[0].blockers, ["git_query_budget_exhausted"]);
        // Keep the old inode allocated so replacement cannot accidentally reuse it.
        std::fs::rename(project.join("target"), base.join("retained-target")).unwrap();
        std::fs::create_dir(project.join("target")).unwrap();
        let mut replaced = original;
        session().refresh(&mut replaced);
        assert_eq!(replaced[0].blockers, ["git_identity_changed"]);
    }
}
