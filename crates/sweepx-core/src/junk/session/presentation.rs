//! Session-local presentation scope. Native paths here never become current bindings or permits.

use super::*;
use std::ops::Bound;

/// Every reliably published key, including Base rows whose pending revision later gets cancelled.
/// Only lossless observed paths and their directory-scope kind are retained. Limits reuse the caps;
/// index bytes include path capacity and conservative tree-node overhead, not consumer payloads.
#[derive(Default)]
pub(super) struct PresentationIndex {
    paths: BTreeMap<JunkCandidateKey, PresentedPath>,
    bytes: usize,
    #[cfg(test)]
    pub(super) after_base_sent: Option<Box<dyn FnMut(JunkCandidateKey) + Send>>,
}

/// Independent temporary facts are observed only by full system revisions. A directory Selected
/// scan does not prove their absence even when the path lies inside the selected directory.
struct PresentedPath {
    path: PathBuf,
    directory: bool,
}

impl PresentationIndex {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
    pub(super) fn contains(&self, key: &JunkCandidateKey) -> bool {
        self.paths.contains_key(key)
    }

    fn path_cost(path: &PresentedPath) -> usize {
        std::mem::size_of::<(JunkCandidateKey, PresentedPath)>()
            .saturating_add(128)
            .saturating_add(path.path.capacity())
    }

    /// Reserves presentation scope before enqueueing. An error cannot publish an untracked key.
    /// Existing keys keep their previous scope when publication fails; duplicate spelling must
    /// agree because native path bytes are part of the stable key. No native reopen occurs here.
    pub(super) fn send_candidate(
        &mut self,
        writer: &mut Writer,
        limits: JunkSessionLimits,
        key: JunkCandidateKey,
        state: JunkSessionCandidateState,
        rules_digest: [u8; 32],
        row: Arc<JunkSessionCandidate>,
    ) -> Result<(), JunkSessionFailure> {
        let path = row.observed_native_path().ok_or_else(|| {
            JunkSessionFailure::new(
                "native_binding_unavailable",
                "candidate presentation path unavailable",
            )
        })?;
        if !path.is_absolute() || path.as_os_str().len() > 64 * 1024 {
            return Err(JunkSessionFailure::new(
                "resource_limit",
                "candidate presentation path exceeds the session path budget",
            ));
        }
        let path = PresentedPath {
            path,
            directory: row.directory_aggregate().is_some(),
        };
        let inserted = if let Some(previous) = self.paths.get(&key) {
            if previous.path != path.path || previous.directory != path.directory {
                return Err(JunkSessionFailure::new(
                    "presentation_scope_changed",
                    "one stable candidate key refers to different native presentation paths",
                ));
            }
            false
        } else {
            let cost = Self::path_cost(&path);
            if self.paths.len() >= limits.max_candidates
                || self.bytes.saturating_add(cost) > limits.max_candidate_bytes
            {
                return Err(JunkSessionFailure::new(
                    "resource_limit",
                    "cumulative candidate presentation scope exceeds session budget",
                ));
            }
            self.bytes = self.bytes.saturating_add(cost);
            self.paths.insert(key, path);
            true
        };
        if let Err(error) = writer.send(JunkSessionEventKind::Candidate {
            key,
            state,
            rules_digest,
            row,
        }) {
            if inserted {
                self.remove(&key);
            }
            return Err(error);
        }
        #[cfg(test)]
        if state == JunkSessionCandidateState::Base
            && let Some(after_sent) = &mut self.after_base_sent
        {
            // The reliable enqueue has completed and its mailbox lock is released. Tests can
            // cancel at this exact boundary without delaying a native call or racing phases.
            after_sent(key);
        }
        Ok(())
    }

    fn remove(&mut self, key: &JunkCandidateKey) {
        if let Some(path) = self.paths.remove(key) {
            self.bytes = self.bytes.saturating_sub(Self::path_cost(&path));
        }
    }

    /// Commits absence only for a fully observed scope. The caller alone establishes that this
    /// revision was neither partial, failed nor cancelled before entering Replacement.
    /// A successful reliable Removed releases one key; failure leaves every unsent key intact.
    pub(super) fn replace_complete(
        &mut self,
        writer: &mut Writer,
        selected: Option<&[PathBuf]>,
        pending: &Rows,
        current: &mut Rows,
    ) -> Result<(), JunkSessionFailure> {
        let mut previous = None;
        loop {
            let next = self
                .paths
                .range((
                    previous.map_or(Bound::Unbounded, Bound::Excluded),
                    Bound::Unbounded,
                ))
                .find_map(|(key, path)| {
                    let in_scope = selected.is_none_or(|paths| {
                        path.directory
                            && paths.iter().any(|selected| path.path.starts_with(selected))
                    });
                    (in_scope && !pending.contains_key(key)).then_some(*key)
                });
            let Some(key) = next else { break };
            writer.send(JunkSessionEventKind::Removed { key })?;
            self.remove(&key);
            current.remove(&key);
            // This cursor bounds temporary storage and visits retained prefixes once rather than
            // repeatedly scanning the tree or allocating a second all-keys collection.
            previous = Some(key);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_directory_scope_preserves_independent_temporary_facts_at_the_same_path() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("candidate");
        let directory_key = JunkCandidateKey([1; 32]);
        let temporary_key = JunkCandidateKey([2; 32]);
        // These are presentation-only records, never fabricated native rows or bindings. The
        // same spelling can belong to independently observed directory and temporary analyses.
        let mut index = PresentationIndex::default();
        for (key, directory) in [(directory_key, true), (temporary_key, false)] {
            let scope = PresentedPath {
                path: path.clone(),
                directory,
            };
            index.bytes += PresentationIndex::path_cost(&scope);
            index.paths.insert(key, scope);
        }
        let shared = Arc::new(Shared::new(JunkSessionLimits::default()));
        let mut writer = Writer::new(
            Arc::clone(&shared),
            JunkSessionRevision(2),
            shared.cancel_token(),
        );
        let pending = Rows::new();
        let mut current = Rows::new();
        index
            .replace_complete(&mut writer, Some(&[path]), &pending, &mut current)
            .unwrap();
        assert!(!index.contains(&directory_key));
        assert!(index.contains(&temporary_key));
        assert!(matches!(shared.pop().unwrap().kind,
            JunkSessionEventKind::Removed { key } if key == directory_key));
        assert!(shared.pop().is_none());
        assert!(current.is_empty());

        index
            .replace_complete(&mut writer, None, &pending, &mut current)
            .unwrap();
        assert!(matches!(shared.pop().unwrap().kind,
            JunkSessionEventKind::Removed { key } if key == temporary_key));
        assert!(shared.pop().is_none());
        assert!(index.paths.is_empty());
        assert_eq!(index.bytes, 0);
    }
}
