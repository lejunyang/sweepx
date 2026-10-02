//! Independent, bounded ranking of current regular-file metadata. Size is not disposability.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sweepx_model::{DecimalU128, EvidenceValue, ObjectType, ScannedEntry};

/// Bounds and logical-size threshold for one invocation, across all roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeFileOptions {
    /// Inclusive threshold in exact logical bytes; allocation does not determine ranking.
    pub minimum_logical_bytes: DecimalU128,
    /// Maximum retained files, in 1..=10,000. Equal-size tie order follows observation order.
    pub max_files: usize,
    /// Owned-data admission estimate, in 1..=64 MiB; not allocator RSS or disk allocation.
    pub max_retained_bytes: usize,
}

impl Default for LargeFileOptions {
    fn default() -> Self {
        Self {
            minimum_logical_bytes: DecimalU128::new(100 * 1024 * 1024),
            max_files: 100,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Invalid resource bounds, rejected before observing the filesystem.
#[derive(Debug, thiserror::Error)]
#[error("large-file limits require 1..=10000 files and 1..=64 MiB retained bytes")]
pub struct LargeFileOptionsError;

/// Why the ranking cannot claim coverage of all matching files in the requested scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LargeFileIncompleteReason {
    /// Cancellation, a refused boundary, failed observation or incomplete traversal.
    TraversalIncomplete,
    /// At least one ordinary file lacked an exact logical length and could not be ranked.
    LogicalSizeUnavailable,
    /// Retained native metadata exceeded its byte budget; this is distinct from normal top-K.
    RetentionLimit,
}

/// Ranked file facts from the same metadata walk as the scan. This is not a junk candidate list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeFileReport {
    /// The exact threshold and bounds used for this invocation.
    pub options: LargeFileOptions,
    /// Current observations sorted by descending logical size; hard-link paths remain aliases.
    /// Allocation evidence is retained independently. No sum here proves reclaimable space.
    pub files: Vec<ScannedEntry>,
    /// Number of confirmed ordinary-file paths observed, including unknown logical lengths.
    pub observed_files: DecimalU128,
    /// Observed paths with exact lengths meeting the inclusive threshold, before top-K.
    pub qualifying_files: DecimalU128,
    /// Ordinary files that cannot be ranked; missing evidence is never converted to zero.
    pub unknown_logical_files: DecimalU128,
    /// True when more observed paths meet the threshold than can fit the requested top-K.
    /// Intentional ranking truncation alone does not make coverage incomplete.
    pub top_k_limited: bool,
    /// True only for complete traversal, exact file lengths and sufficient retention evidence.
    pub complete: bool,
    /// Explicit gaps; a complete empty ranking has no reasons.
    pub incomplete_reasons: Vec<LargeFileIncompleteReason>,
}

/// Streaming top-K collector; callers feed every file before optional scan-row retention.
/// It reads no contents, follows no paths, grants no execution authority and keeps no global index.
pub struct LargeFileCollector {
    options: LargeFileOptions,
    // Reverse ordinals keep earlier equal-length observations when the top-K fills. Neither
    // directory order nor tie selection is promised across hosts or separate scans.
    files: BTreeMap<(u128, u128), (ScannedEntry, usize)>,
    retained_bytes: usize,
    observed: u128,
    qualifying: u128,
    unknown: u128,
    retention_limited: bool,
}

impl LargeFileCollector {
    /// Validates finite bounds before allocating or accepting observations.
    pub fn new(options: LargeFileOptions) -> Result<Self, LargeFileOptionsError> {
        if !(1..=10_000).contains(&options.max_files)
            || !(1..=64 * 1024 * 1024).contains(&options.max_retained_bytes)
        {
            return Err(LargeFileOptionsError);
        }
        Ok(Self {
            options,
            files: BTreeMap::new(),
            retained_bytes: 0,
            observed: 0,
            qualifying: 0,
            unknown: 0,
            retention_limited: false,
        })
    }

    /// Consumes a borrowed metadata fact. Only confirmed ordinary files with exact lengths rank.
    /// The full native observation is cloned only when it can enter the bounded result.
    pub fn observe(&mut self, entry: &ScannedEntry) {
        if entry.object_type != ObjectType::File {
            return;
        }
        self.observed = self.observed.saturating_add(1);
        let EvidenceValue::Known { value } = &entry.logical_bytes else {
            self.unknown = self.unknown.saturating_add(1);
            return;
        };
        let length = value.0;
        if length < self.options.minimum_logical_bytes.0 {
            return;
        }
        self.qualifying = self.qualifying.saturating_add(1);
        let key = (length, u128::MAX - self.observed);
        if self.files.len() == self.options.max_files
            && self
                .files
                .first_key_value()
                .is_some_and(|(smallest, _)| key <= *smallest)
        {
            return;
        }
        // Charge native lineage, strings and spare capacities plus conservative map overhead.
        // The multiplier also covers the bounded map-to-Vec transfer at finish.
        let cost = entry
            .estimated_retained_bytes()
            .saturating_mul(2)
            .saturating_add(512);
        if cost > self.options.max_retained_bytes {
            self.retention_limited = true;
            return;
        }
        while self.files.len() == self.options.max_files
            || self.retained_bytes.saturating_add(cost) > self.options.max_retained_bytes
        {
            let Some((smallest, _)) = self.files.first_key_value() else {
                unreachable!("one admitted observation fits an empty collector")
            };
            if *smallest > key {
                self.retention_limited = true;
                return;
            }
            if self.files.len() < self.options.max_files {
                self.retention_limited = true;
            }
            let (_, (_, evicted_cost)) = self.files.pop_first().expect("smallest retained");
            self.retained_bytes -= evicted_cost;
        }
        self.retained_bytes += cost;
        self.files.insert(key, (entry.clone(), cost));
    }

    /// Finalizes the ranking after the caller has established traversal completion independently
    /// of optional scan logs. Earlier files remain useful in an explicitly incomplete result.
    pub fn finish(self, traversal_complete: bool) -> LargeFileReport {
        let mut incomplete_reasons = Vec::new();
        if !traversal_complete {
            incomplete_reasons.push(LargeFileIncompleteReason::TraversalIncomplete);
        }
        if self.unknown > 0 {
            incomplete_reasons.push(LargeFileIncompleteReason::LogicalSizeUnavailable);
        }
        if self.retention_limited {
            incomplete_reasons.push(LargeFileIncompleteReason::RetentionLimit);
        }
        LargeFileReport {
            top_k_limited: self.qualifying > self.options.max_files as u128,
            complete: incomplete_reasons.is_empty(),
            incomplete_reasons,
            options: self.options,
            files: self
                .files
                .into_iter()
                .rev()
                .map(|(_, (entry, _))| entry)
                .collect(),
            observed_files: self.observed.into(),
            qualifying_files: self.qualifying.into(),
            unknown_logical_files: self.unknown.into(),
        }
    }

    /// Copies the bounded current ranking for a coalesced progress snapshot. It always remains
    /// incomplete until traversal closes; callers must bound retained snapshots independently.
    pub fn preview(&self) -> LargeFileReport {
        let mut incomplete_reasons = vec![LargeFileIncompleteReason::TraversalIncomplete];
        if self.unknown > 0 {
            incomplete_reasons.push(LargeFileIncompleteReason::LogicalSizeUnavailable);
        }
        if self.retention_limited {
            incomplete_reasons.push(LargeFileIncompleteReason::RetentionLimit);
        }
        LargeFileReport {
            options: self.options.clone(),
            files: self
                .files
                .values()
                .rev()
                .map(|(entry, _)| entry.clone())
                .collect(),
            observed_files: self.observed.into(),
            qualifying_files: self.qualifying.into(),
            unknown_logical_files: self.unknown.into(),
            top_k_limited: self.qualifying > self.options.max_files as u128,
            complete: false,
            incomplete_reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{Coverage, CoverageState, FieldProvenance, NativeName, ReasonCode, ScanId};

    fn file(name: &str, logical: u128) -> ScannedEntry {
        ScannedEntry {
            scan_id: ScanId::new("controlled"),
            identity: None,
            native_locator: None,
            display_path: format!("/fixture/{name}"),
            native_basename: NativeName::UnixBytes(name.as_bytes().into()),
            object_type: ObjectType::File,
            logical_bytes: EvidenceValue::Known {
                value: logical.into(),
            },
            allocated_bytes: EvidenceValue::NotChecked {
                reason: ReasonCode::NotRevalidated,
            },
            reclaimable_estimate: EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity,
            },
            metadata_fingerprint: name.into(),
            coverage: Coverage {
                state: CoverageState::Complete,
                complete: true,
                incomplete_reasons: vec![],
                details_lost: false,
                provenance: FieldProvenance::Unknown {
                    reason: ReasonCode::Unknown,
                },
            },
            provenance: FieldProvenance::Unknown {
                reason: ReasonCode::Unknown,
            },
        }
    }

    fn options(k: usize) -> LargeFileOptions {
        LargeFileOptions {
            max_files: k,
            minimum_logical_bytes: 0.into(),
            ..Default::default()
        }
    }

    #[test]
    fn preview_reports_observed_gaps_without_claiming_terminal_coverage() {
        let mut collector = LargeFileCollector::new(options(2)).unwrap();
        collector.observe(&file("first", 7));
        collector.observe(&file("later", 13));
        let mut uncertain = file("uncertain", 0);
        uncertain.logical_bytes = EvidenceValue::Unknown {
            reason: ReasonCode::Unknown,
        };
        collector.observe(&uncertain);
        let preview = collector.preview();
        assert!(!preview.complete);
        assert_eq!(
            preview
                .files
                .iter()
                .map(|entry| entry.display_path.as_str())
                .collect::<Vec<_>>(),
            ["/fixture/later", "/fixture/first"]
        );
        assert_eq!(
            preview.incomplete_reasons,
            [
                LargeFileIncompleteReason::TraversalIncomplete,
                LargeFileIncompleteReason::LogicalSizeUnavailable
            ]
        );
        let final_report = collector.finish(true);
        assert_eq!(preview.files, final_report.files);
        assert_eq!(
            final_report.incomplete_reasons,
            [LargeFileIncompleteReason::LogicalSizeUnavailable]
        );
    }

    #[test]
    fn top_k_matches_independent_full_sort_including_late_largest_file() {
        let entries: Vec<_> = (0..73)
            .map(|index| file(&format!("file-{index}"), ((index * 47) % 101) as u128))
            .chain([file("last", u128::from(u64::MAX) + 5)])
            .collect();
        let mut expected: Vec<_> = entries
            .iter()
            .map(|entry| match entry.logical_bytes {
                EvidenceValue::Known { value } => value.0,
                _ => unreachable!(),
            })
            .collect();
        expected.sort_unstable_by(|a, b| b.cmp(a));
        expected.truncate(7);
        let mut collector = LargeFileCollector::new(options(7)).unwrap();
        for entry in &entries {
            collector.observe(entry);
        }
        let report = collector.finish(true);
        let lengths: Vec<_> = report
            .files
            .iter()
            .map(|entry| match entry.logical_bytes {
                EvidenceValue::Known { value } => value.0,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(lengths, expected);
        assert_eq!(report.files[0], *entries.last().unwrap());
        assert_eq!(report.observed_files.0, 74);
        assert!(report.top_k_limited && report.complete);
        assert_eq!(report.qualifying_files.0, 74);
    }

    #[test]
    fn unknown_lengths_are_not_zero_and_non_files_do_not_enter_the_ranking() {
        let mut collector = LargeFileCollector::new(options(10)).unwrap();
        collector.observe(&file("zero", 0));
        for kind in [
            ObjectType::Directory,
            ObjectType::Symlink,
            ObjectType::ReparsePoint,
            ObjectType::Other,
        ] {
            let mut entry = file("not-a-file", 10_000);
            entry.object_type = kind;
            collector.observe(&entry);
        }
        for value in [
            EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            EvidenceValue::NotChecked {
                reason: ReasonCode::NotRevalidated,
            },
            EvidenceValue::Unsupported {
                reason: ReasonCode::UnsupportedFilesystem,
            },
            EvidenceValue::LowerBound {
                value: 999.into(),
                reason: ReasonCode::IncompleteStreamCoverage,
            },
        ] {
            let mut entry = file("uncertain", 0);
            entry.logical_bytes = value;
            collector.observe(&entry);
        }
        let report = collector.finish(true);
        assert_eq!(report.observed_files.0, 5);
        assert_eq!(report.unknown_logical_files.0, 4);
        assert_eq!(report.qualifying_files.0, 1);
        assert_eq!(report.files.len(), 1);
        assert_eq!(
            report.files[0].allocated_bytes,
            file("zero", 0).allocated_bytes
        );
        assert_eq!(
            report.incomplete_reasons,
            vec![LargeFileIncompleteReason::LogicalSizeUnavailable]
        );
    }

    #[test]
    fn threshold_is_inclusive_and_allocation_does_not_control_ranking() {
        let mut collector = LargeFileCollector::new(LargeFileOptions {
            minimum_logical_bytes: 50.into(),
            ..options(2)
        })
        .unwrap();
        let mut small = file("small", 49);
        small.allocated_bytes = EvidenceValue::Known {
            value: 10_000.into(),
        };
        collector.observe(&small);
        collector.observe(&file("threshold", 50));
        let report = collector.finish(true);
        assert_eq!(report.files, vec![file("threshold", 50)]);
        assert!(report.complete);
    }

    #[test]
    fn retention_failure_and_traversal_gap_remain_explicit_with_useful_rows() {
        let mut collector = LargeFileCollector::new(LargeFileOptions {
            max_retained_bytes: 16 * 1024,
            ..options(5)
        })
        .unwrap();
        collector.observe(&file("small", 100));
        collector.observe(&file(&"x".repeat(128 * 1024), 1000));
        let report = collector.finish(false);
        assert_eq!(report.files, vec![file("small", 100)]);
        assert_eq!(report.qualifying_files.0, 2);
        assert!(!report.top_k_limited && !report.complete);
        assert_eq!(
            report.incomplete_reasons,
            vec![
                LargeFileIncompleteReason::TraversalIncomplete,
                LargeFileIncompleteReason::RetentionLimit
            ]
        );
    }

    #[test]
    fn invalid_limits_are_rejected() {
        for (files, bytes) in [(0, 1000), (10_001, 1000), (1, 0), (1, 64 * 1024 * 1024 + 1)] {
            assert!(
                LargeFileCollector::new(LargeFileOptions {
                    max_files: files,
                    max_retained_bytes: bytes,
                    ..Default::default()
                })
                .is_err()
            );
        }
    }
}
