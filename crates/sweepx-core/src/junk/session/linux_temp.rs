//! Linux temporary reports retain their own native facts, never directory Trash locators.

use super::*;
use crate::junk::linux_temp;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

impl Worker {
    pub(super) fn observe_temporary_objects(
        &mut self,
        platform: &PlatformJunkSetup,
        pending: &mut Rows,
        rules_digest: [u8; 32],
        job: &Job,
        writer: &mut Writer,
    ) -> Result<bool, JunkSessionFailure> {
        writer.phase(JunkSessionPhase::TemporaryObjects)?;
        let rule = platform
            .rules
            .iter()
            .find(|rule| rule.root_kind == "linux_tmp")
            .ok_or_else(|| {
                JunkSessionFailure::new(
                    "temporary_rule_unavailable",
                    "Linux temporary-object rule is unavailable",
                )
            })?;
        let root = linux_temp::report_temp_root().ok_or_else(|| {
            JunkSessionFailure::new(
                "temporary_root_unavailable",
                "Linux temporary-object root is unavailable",
            )
        })?;
        let mut retained_rows = self.current.len().saturating_add(pending.len());
        let mut retained_bytes = self
            .current
            .values()
            .chain(pending.values())
            .fold(0usize, |sum, row| sum.saturating_add(row.cost()));
        let mut limits = self.request.limits.linux_temp;
        // Fingerprints being measured must fit alongside already retained session rows.
        // The existing service's cumulative admission remains conservative rather than RSS.
        limits.max_retained_bytes = limits.max_retained_bytes.min(
            self.request
                .limits
                .max_candidate_bytes
                .saturating_sub(retained_bytes),
        );
        let discovery = linux_temp::discover_with_cancel_and_limits(
            &root,
            None,
            Instant::now() + linux_temp::MEASURE_DEADLINE,
            &job.cancel,
            limits,
        );
        let partial = !discovery.complete;
        if let Some(reason) = &discovery.incomplete_reason {
            writer.failure(JunkSessionFailure::new(
                "temporary_discovery_incomplete",
                reason,
            ));
        }
        if job.cancel.is_cancelled() {
            return Err(JunkSessionFailure::new(
                "cancelled",
                "temporary-object observation cancelled",
            ));
        }
        let reports = linux_temp::report_candidates(rule, &discovery);
        if reports.len() != discovery.candidates.len() {
            return Err(JunkSessionFailure::new(
                "temporary_interpretation_failed",
                "not all observed temporary objects could be interpreted",
            ));
        }
        // Old and pending observations share the same session budget, including full fingerprints.
        // Counting shared directory rows twice is conservative, just as retained old/pending state.
        for (mut candidate, observed) in reports.into_iter().zip(discovery.candidates) {
            let measurement = observed.measurement;
            let key = temporary_candidate_key(&candidate, &measurement);
            // The existing report-only service has no scan namespace. Session rows must not
            // reuse its fixed ID across revisions, even though stable presentation keys persist.
            candidate.entry_id = sweepx_model::ScanEntryId::for_scan_ordinal(
                &ScanId::new(format!("{}:{}:temporary", self.session_id, job.revision.0)),
                u128::from(measurement.top.ino()).saturating_add(1),
            )
            .map_err(|error| {
                JunkSessionFailure::new("temporary_identity_unavailable", error.to_string())
            })?;
            let logical_bytes = sweepx_platform::known_u128(measurement.logical_bytes);
            let row = Arc::new(JunkSessionCandidate {
                candidate,
                facts: JunkSessionFacts::LinuxTemporary {
                    measurement: Arc::new(measurement),
                    logical_bytes,
                },
            });
            retained_rows = retained_rows.saturating_add(1);
            retained_bytes = retained_bytes.saturating_add(row.cost());
            if retained_rows > self.request.limits.max_candidates
                || retained_bytes > self.request.limits.max_candidate_bytes
            {
                return Err(JunkSessionFailure::new(
                    "resource_limit",
                    "temporary-object fingerprints exceed session candidate retention",
                ));
            }
            self.presentations.send_candidate(
                writer,
                self.request.limits,
                key,
                JunkSessionCandidateState::Current,
                rules_digest,
                Arc::clone(&row),
            )?;
            self.current.insert(key, Arc::clone(&row));
            pending.insert(key, row);
        }
        Ok(partial)
    }
}

fn temporary_candidate_key(
    candidate: &JunkCandidate,
    measurement: &linux_temp::LinuxTempMeasurement,
) -> JunkCandidateKey {
    let mut hash = Sha256::new();
    hash.update(b"sweepx-linux-temporary-key/v1");
    for bytes in [
        candidate
            .native_path
            .as_ref()
            .expect("native report path")
            .as_os_str()
            .as_encoded_bytes(),
        candidate.rule_id.as_bytes(),
    ] {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    for value in [
        measurement.top.dev(),
        measurement.top.ino(),
        u64::from(measurement.top.mode() & libc::S_IFMT),
    ] {
        hash.update(value.to_le_bytes());
    }
    JunkCandidateKey(hash.finalize().into())
}
