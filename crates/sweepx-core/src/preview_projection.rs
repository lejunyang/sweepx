//! Admit the ordinary preview's owned rows and temporary aggregate index before cloning.
//!
//! This is an auxiliary reservation estimate, separate from encoded JSON and parser budgets.
//! It excludes the caller's existing scan facts and allocator/RSS overhead. Failure publishes
//! no partial cache generation. Aggregate keys stay borrowed; they gain no execution authority.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sweepx_cache::{CacheError, PreviewCoverage, PreviewKind, PreviewRole, PreviewSummary};
use sweepx_model::{
    Coverage, DirectoryAggregate, EvidenceValue, FieldProvenance, NativeName, ObjectType,
    ReasonCode, ScannedEntry,
};
use sweepx_scanner::ScanSummary;

/// Limits for one auxiliary projection, including its temporary borrowing index.
pub(super) struct Limits {
    /// Reservations for cloned dynamic fields, row slots and index-node slack.
    pub retained_bytes: usize,
    /// Additional bound on work and metadata cardinality; output compaction has its own cap.
    pub records: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            retained_bytes: 192 * 1024 * 1024,
            records: 1_000_000,
        }
    }
}

struct Budget {
    remaining: usize,
}
impl Budget {
    fn reserve(&mut self, bytes: usize) -> Result<(), CacheError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(resource_limit)?;
        Ok(())
    }
}

fn resource_limit() -> CacheError {
    CacheError::ResourceLimit {
        reason: ReasonCode::ResourceLimit,
    }
}

fn vector_bytes<T>(len: usize) -> usize {
    // Clone/collect capacity and small initial-allocation slack, not logical file bytes.
    len.saturating_mul(2)
        .saturating_add(8)
        .saturating_mul(std::mem::size_of::<T>())
}
fn string_bytes(len: usize) -> usize {
    len.saturating_mul(2).saturating_add(32)
}
fn name_bytes(name: &NativeName) -> usize {
    match name {
        NativeName::UnixBytes(bytes) => vector_bytes::<u8>(bytes.len()),
        NativeName::WindowsUtf16(units) => vector_bytes::<u16>(units.len()),
    }
}
fn aggregate_bytes(aggregate: &DirectoryAggregate, timestamp_len: usize) -> usize {
    // The aggregate lives inline in PreviewSummary. Only fields actually retained in the
    // historical projection are cloned; old coverage provenance/inputs are not copied first.
    string_bytes(aggregate.scan_id.len())
        .saturating_add(string_bytes(aggregate.directory_identity.len()))
        .saturating_add(vector_bytes::<ReasonCode>(
            aggregate.coverage.incomplete_reasons.len(),
        ))
        .saturating_add(string_bytes(timestamp_len))
}

/// Build the complete historical projection or refuse it before row ownership is duplicated.
pub(super) fn project(
    summary: &ScanSummary,
    limits: &Limits,
) -> Result<Vec<PreviewSummary>, CacheError> {
    let records = summary
        .roots
        .iter()
        .chain(&summary.entries)
        .filter(|entry| entry.identity.is_some())
        .count()
        .checked_add(
            summary
                .boundaries
                .iter()
                .filter(|boundary| boundary.path.file_name().is_some())
                .count(),
        )
        .ok_or_else(resource_limit)?;
    if records > limits.records || summary.aggregates.len() > limits.records {
        return Err(resource_limit());
    }
    let mut budget = Budget {
        remaining: limits.retained_bytes,
    };
    // B-tree nodes have eleven slots; reserve first-node plus split/edge/header slack for
    // borrowed (&str, &aggregate) entries before any index allocation. No owned index keys.
    let index_slot = std::mem::size_of::<(&str, &DirectoryAggregate)>()
        .saturating_mul(3)
        .saturating_add(128);
    budget.reserve(
        summary
            .aggregates
            .len()
            .saturating_add(4)
            .saturating_mul(index_slot),
    )?;
    budget.reserve(records.saturating_mul(std::mem::size_of::<PreviewSummary>()))?;
    // Keep the existing model validator, including aggregate scan-id binding. Its temporary
    // decode/re-encode storage is bounded by the largest input, not retained per index key.
    let validation_scratch = summary
        .aggregates
        .iter()
        .map(|aggregate| {
            aggregate
                .directory_identity
                .len()
                .saturating_add(aggregate.scan_id.len())
                .saturating_mul(8)
                .saturating_add(512)
        })
        .max()
        .unwrap_or(0);
    budget.reserve(validation_scratch)?;
    let mut aggregate_by_id = BTreeMap::new();
    for aggregate in &summary.aggregates {
        if aggregate.scan_entry_id().is_ok() {
            // Insert directly: FromIterator would also allocate a sorting Vec. Duplicate
            // validated ids retain the existing last-wins behavior; keys remain borrowed.
            aggregate_by_id.insert(aggregate.directory_identity.as_str(), aggregate);
        }
    }
    budget.reserve(128)?;
    let observed_at = super::timestamp_now();
    for entry in summary.roots.iter().chain(&summary.entries) {
        let Some(identity) = &entry.identity else {
            continue;
        };
        let aggregate = aggregate_by_id.get(identity.entry_id.as_str()).copied();
        let bytes = string_bytes(identity.entry_id.as_str().len())
            .saturating_add(
                identity
                    .parent_id
                    .as_ref()
                    .map_or(0, |id| string_bytes(id.as_str().len())),
            )
            .saturating_add(name_bytes(&entry.native_basename))
            .saturating_add(string_bytes(entry.display_path.len()))
            .saturating_add(vector_bytes::<ReasonCode>(
                entry.coverage.incomplete_reasons.len(),
            ))
            .saturating_add(string_bytes(observed_at.len()))
            .saturating_add(aggregate.map_or(0, |value| aggregate_bytes(value, observed_at.len())));
        budget.reserve(bytes)?;
    }
    for boundary in &summary.boundaries {
        let Some(name) = boundary.path.file_name() else {
            continue;
        };
        let raw_len = native_units(boundary.path.as_os_str());
        let display_len = raw_len.saturating_mul(3);
        // Lossy display can expand each invalid unit to U+FFFD. Account for display scratch,
        // sanitized id and its prefix before formatting, without deriving native names from it.
        budget.reserve(
            display_len
                .saturating_mul(8)
                .saturating_add(native_units(name).saturating_mul(4))
                .saturating_add(512)
                .saturating_add(string_bytes(observed_at.len())),
        )?;
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(records)
        .map_err(|_| resource_limit())?;
    for entry in summary.roots.iter().chain(&summary.entries) {
        let Some(identity) = &entry.identity else {
            continue;
        };
        rows.push(entry_row(
            entry,
            aggregate_by_id.get(identity.entry_id.as_str()).copied(),
            &observed_at,
        ));
    }
    for boundary in &summary.boundaries {
        let Some(native_name) = boundary_native_name(&boundary.path) else {
            continue;
        };
        let display_name = boundary.path.display().to_string();
        let entry_id = format!(
            "boundary:{}",
            display_name
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        );
        rows.push(PreviewSummary {
            kind: PreviewKind::Boundary,
            parent_id: None,
            entry_id,
            native_name,
            display_name,
            logical_bytes: EvidenceValue::Unknown {
                reason: boundary.reason.clone(),
            },
            allocated_bytes: EvidenceValue::Unknown {
                reason: boundary.reason.clone(),
            },
            direct_child_count: sweepx_platform::known_count(0),
            recursive_entry_count: sweepx_platform::known_count(0),
            aggregate: None,
            coverage: PreviewCoverage {
                complete: false,
                details_lost: true,
                incomplete_reasons: vec![boundary.reason.clone()],
            },
            selectable: false,
            roles: BTreeSet::from([PreviewRole::Boundary]),
            provenance: FieldProvenance::StalePreview {
                observed_at: observed_at.clone(),
            },
        });
    }
    Ok(rows)
}

fn entry_row(
    entry: &ScannedEntry,
    aggregate: Option<&DirectoryAggregate>,
    observed_at: &str,
) -> PreviewSummary {
    let identity = entry.identity.as_ref().expect("admitted identity");
    let kind = match entry.object_type {
        ObjectType::Directory if identity.parent_id.is_none() => PreviewKind::Root,
        ObjectType::Directory => PreviewKind::Directory,
        _ => PreviewKind::Leaf,
    };
    let missing_count = || EvidenceValue::Unknown {
        reason: ReasonCode::Unknown,
    };
    PreviewSummary {
        kind,
        parent_id: identity.parent_id.as_ref().map(ToString::to_string),
        entry_id: identity.entry_id.to_string(),
        native_name: entry.native_basename.clone(),
        display_name: entry.display_path.clone(),
        logical_bytes: stale_value(&entry.logical_bytes),
        allocated_bytes: stale_value(&entry.allocated_bytes),
        direct_child_count: aggregate
            .map(|value| stale_value(&value.direct_child_count))
            .unwrap_or_else(|| {
                if entry.object_type == ObjectType::Directory {
                    missing_count()
                } else {
                    sweepx_platform::known_count(0)
                }
            }),
        recursive_entry_count: aggregate
            .map(|value| stale_value(&value.recursive_entry_count))
            .unwrap_or_else(|| {
                if entry.object_type == ObjectType::Directory {
                    missing_count()
                } else {
                    sweepx_platform::known_count(1)
                }
            }),
        aggregate: aggregate.map(|value| historical_aggregate(value, observed_at)),
        coverage: PreviewCoverage {
            complete: entry.coverage.complete,
            details_lost: !entry.coverage.complete,
            incomplete_reasons: entry.coverage.incomplete_reasons.clone(),
        },
        selectable: false,
        roles: BTreeSet::new(),
        provenance: FieldProvenance::StalePreview {
            observed_at: observed_at.to_owned(),
        },
    }
}

fn stale_value<T: Copy>(value: &EvidenceValue<T>) -> EvidenceValue<T> {
    match value {
        EvidenceValue::Known { value } => EvidenceValue::Known { value: *value },
        EvidenceValue::LowerBound { value, reason } => EvidenceValue::LowerBound {
            value: *value,
            reason: reason.clone(),
        },
        EvidenceValue::Unknown { reason }
        | EvidenceValue::Unsupported { reason }
        | EvidenceValue::NotChecked { reason } => EvidenceValue::Unknown {
            reason: reason.clone(),
        },
    }
}
/// Project only retained aggregate fields, avoiding a temporary clone of obsolete provenance.
pub(super) fn historical_aggregate(
    value: &DirectoryAggregate,
    observed_at: &str,
) -> DirectoryAggregate {
    DirectoryAggregate {
        scan_id: value.scan_id.clone(),
        directory_identity: value.directory_identity.clone(),
        revision: value.revision,
        apparent_logical_bytes: stale_value(&value.apparent_logical_bytes),
        unique_logical_bytes: stale_value(&value.unique_logical_bytes),
        filesystem_reported_allocated_bytes: stale_value(
            &value.filesystem_reported_allocated_bytes,
        ),
        potentially_reclaimable_bytes: stale_value(&value.potentially_reclaimable_bytes),
        direct_child_count: stale_value(&value.direct_child_count),
        recursive_entry_count: stale_value(&value.recursive_entry_count),
        coverage: Coverage {
            state: value.coverage.state.clone(),
            complete: value.coverage.complete,
            incomplete_reasons: value.coverage.incomplete_reasons.clone(),
            details_lost: value.coverage.details_lost,
            provenance: FieldProvenance::StalePreview {
                observed_at: observed_at.to_owned(),
            },
        },
        arithmetic_state: value.arithmetic_state.clone(),
    }
}

#[cfg(unix)]
fn native_units(name: &std::ffi::OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().len()
}
#[cfg(windows)]
fn native_units(name: &std::ffi::OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().count()
}

fn boundary_native_name(path: &Path) -> Option<NativeName> {
    let name = path.file_name()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(NativeName::unix(name.as_bytes().to_vec()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        Some(NativeName::windows_utf16(
            name.encode_wide().collect::<Vec<_>>(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{
        ArithmeticState, CoverageState, DecimalU128, IdentityEvidence, ScanEntryId, ScanId,
        ScanObjectIdentity,
    };
    use sweepx_platform::{BoundaryKind, BoundaryRecord};

    fn known_bytes(value: u128) -> EvidenceValue<DecimalU128> {
        EvidenceValue::Known {
            value: DecimalU128::new(value),
        }
    }

    fn fixture(count: usize) -> ScanSummary {
        let scan_id = ScanId::new("projection-fixture");
        let root_id = ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap();
        let coverage = Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance: FieldProvenance::DerivedFromCurrent {
                inputs: vec!["input".to_owned()],
                algorithm: "fixture".to_owned(),
            },
        };
        let entries = (1..=count)
            .map(|ordinal| ScannedEntry {
                scan_id: scan_id.clone(),
                identity: Some(ScanObjectIdentity {
                    entry_id: ScanEntryId::for_scan_ordinal(&scan_id, ordinal as u128).unwrap(),
                    scan_root_id: root_id.clone(),
                    parent_id: (ordinal != 1).then(|| root_id.clone()),
                    platform_file_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
                    filesystem_object_domain_identity: IdentityEvidence::unknown(
                        ReasonCode::UnknownIdentity,
                    ),
                    volume_or_mount_identity: IdentityEvidence::unknown(
                        ReasonCode::UnknownIdentity,
                    ),
                }),
                native_locator: None,
                display_path: format!("/fixture/entry-{ordinal}"),
                native_basename: NativeName::unix(format!("entry-{ordinal}").into_bytes()),
                object_type: if ordinal == 1 {
                    ObjectType::Directory
                } else {
                    ObjectType::File
                },
                logical_bytes: known_bytes(ordinal as u128 * 17),
                allocated_bytes: EvidenceValue::LowerBound {
                    value: DecimalU128::new(8),
                    reason: ReasonCode::Unknown,
                },
                reclaimable_estimate: EvidenceValue::NotChecked {
                    reason: ReasonCode::Unknown,
                },
                metadata_fingerprint: "unused fingerprint".to_owned(),
                coverage: coverage.clone(),
                provenance: coverage.provenance.clone(),
            })
            .collect::<Vec<_>>();
        let aggregates = vec![DirectoryAggregate {
            scan_id,
            directory_identity: root_id.to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: known_bytes((count as u128 * (count as u128 + 1) / 2) * 17),
            unique_logical_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            filesystem_reported_allocated_bytes: EvidenceValue::Unsupported {
                reason: ReasonCode::Unknown,
            },
            potentially_reclaimable_bytes: EvidenceValue::NotChecked {
                reason: ReasonCode::Unknown,
            },
            direct_child_count: sweepx_platform::known_count(count.saturating_sub(1) as u128),
            recursive_entry_count: sweepx_platform::known_count(count as u128),
            coverage,
            arithmetic_state: ArithmeticState::Exact,
        }];
        ScanSummary {
            roots: Vec::new(),
            entries,
            aggregates,
            boundaries: Vec::new(),
            progress: Vec::new(),
            progress_retention: Default::default(),
        }
    }

    #[test]
    fn projection_preserves_facts_and_marks_all_rows_historical() {
        let summary = fixture(4);
        let before = summary.clone();
        let rows = project(&summary, &Limits::default()).unwrap();
        assert_eq!(summary, before);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].kind, PreviewKind::Root);
        assert_eq!(rows[0].direct_child_count, sweepx_platform::known_count(3));
        assert_eq!(
            rows[0].recursive_entry_count,
            sweepx_platform::known_count(4)
        );
        assert_eq!(
            rows[0].aggregate.as_ref().unwrap().apparent_logical_bytes,
            known_bytes(170)
        );
        for (ordinal, row) in rows.iter().enumerate() {
            assert_eq!(row.logical_bytes, known_bytes((ordinal as u128 + 1) * 17));
            assert_eq!(
                row.allocated_bytes,
                EvidenceValue::LowerBound {
                    value: DecimalU128::new(8),
                    reason: ReasonCode::Unknown
                }
            );
            assert!(!row.selectable);
            assert!(matches!(
                row.provenance,
                FieldProvenance::StalePreview { .. }
            ));
            if ordinal != 0 {
                assert_eq!(row.parent_id.as_deref(), Some(rows[0].entry_id.as_str()));
                assert_eq!(row.direct_child_count, sweepx_platform::known_count(0));
                assert_eq!(row.recursive_entry_count, sweepx_platform::known_count(1));
            }
        }
        let aggregate = rows[0].aggregate.as_ref().unwrap();
        assert!(matches!(
            aggregate.filesystem_reported_allocated_bytes,
            EvidenceValue::Unknown { .. }
        ));
        assert!(matches!(
            aggregate.coverage.provenance,
            FieldProvenance::StalePreview { .. }
        ));
    }

    #[test]
    fn invalid_or_absent_directory_aggregate_never_invents_counts() {
        for invalid in [
            "/fixture/entry-1",
            "scan-entry:v1:!!!!:1",
            "scan-entry:v1:b3RoZXI:1",
        ] {
            let mut summary = fixture(4);
            summary.aggregates[0].directory_identity = invalid.to_owned();
            let row = project(&summary, &Limits::default()).unwrap().remove(0);
            assert!(row.aggregate.is_none());
            assert!(matches!(
                row.direct_child_count,
                EvidenceValue::Unknown { .. }
            ));
            assert!(matches!(
                row.recursive_entry_count,
                EvidenceValue::Unknown { .. }
            ));
        }
        let mut summary = fixture(4);
        let mut wrong_scan = summary.aggregates[0].clone();
        wrong_scan.scan_id = ScanId::new("other");
        wrong_scan.direct_child_count = sweepx_platform::known_count(99);
        summary.aggregates.push(wrong_scan);
        assert_eq!(
            project(&summary, &Limits::default()).unwrap()[0].direct_child_count,
            sweepx_platform::known_count(3)
        );
        summary.aggregates[0].scan_id = ScanId::new("also wrong");
        assert!(
            project(&summary, &Limits::default()).unwrap()[0]
                .aggregate
                .is_none()
        );
    }

    #[test]
    fn byte_and_cardinality_refusals_preserve_input() {
        let mut summary = fixture(3);
        let before = summary.clone();
        for limits in [
            Limits {
                retained_bytes: 1024,
                records: 100,
            },
            Limits {
                retained_bytes: 1024 * 1024,
                records: 2,
            },
        ] {
            assert!(matches!(
                project(&summary, &limits),
                Err(CacheError::ResourceLimit { .. })
            ));
            assert_eq!(summary, before);
        }
        // The aggregate index is bounded independently even when no rows can be projected.
        summary.entries.clear();
        let aggregate = summary.aggregates[0].clone();
        summary.aggregates.extend([aggregate.clone(), aggregate]);
        assert!(matches!(
            project(
                &summary,
                &Limits {
                    retained_bytes: 1024 * 1024,
                    records: 2
                }
            ),
            Err(CacheError::ResourceLimit { .. })
        ));
    }

    // Independent retained-capacity oracle: inspect actual allocated capacities, without
    // calling projection cost helpers. Inline aggregate/coverage storage is in the row slots.
    fn owned_capacity(rows: &[PreviewSummary], capacity: usize) -> usize {
        fn provenance(value: &FieldProvenance) -> usize {
            match value {
                FieldProvenance::StalePreview { observed_at } => observed_at.capacity(),
                _ => panic!("unexpected retained provenance"),
            }
        }
        capacity * std::mem::size_of::<PreviewSummary>()
            + rows
                .iter()
                .map(|row| {
                    let native = match &row.native_name {
                        NativeName::UnixBytes(bytes) => bytes.capacity(),
                        NativeName::WindowsUtf16(units) => units.capacity() * 2,
                    };
                    row.entry_id.capacity()
                        + row.parent_id.as_ref().map_or(0, String::capacity)
                        + native
                        + row.display_name.capacity()
                        + provenance(&row.provenance)
                        + row.coverage.incomplete_reasons.capacity()
                            * std::mem::size_of::<ReasonCode>()
                        + row.aggregate.as_ref().map_or(0, |aggregate| {
                            aggregate.scan_id.len()
                                + aggregate.directory_identity.capacity()
                                + aggregate.coverage.incomplete_reasons.capacity()
                                    * std::mem::size_of::<ReasonCode>()
                                + provenance(&aggregate.coverage.provenance)
                        })
                })
                .sum::<usize>()
    }

    #[test]
    fn admitted_rows_fit_independent_capacity_oracle_at_growth_boundaries() {
        for count in [1, 7, 8, 9, 11, 12, 63, 64, 65, 1000] {
            let mut summary = fixture(count);
            for entry in &mut summary.entries {
                entry.display_path.push_str(&"a".repeat(count));
                entry.coverage.incomplete_reasons = vec![ReasonCode::Unknown; count % 17];
            }
            let limits = Limits {
                retained_bytes: 8 * 1024 * 1024,
                records: 1000,
            };
            let rows = project(&summary, &limits).unwrap();
            assert_eq!(rows.len(), count);
            assert!(owned_capacity(&rows, rows.capacity()) <= limits.retained_bytes);
            // A cap below independently observed storage must refuse the complete projection.
            assert!(matches!(
                project(
                    &summary,
                    &Limits {
                        retained_bytes: owned_capacity(&rows, rows.capacity()) - 1,
                        records: 1000
                    }
                ),
                Err(CacheError::ResourceLimit { .. })
            ));
        }
    }

    #[test]
    fn obsolete_provenance_and_unused_fingerprints_do_not_consume_row_budget() {
        let mut summary = fixture(2);
        let limits = Limits {
            retained_bytes: 32 * 1024,
            records: 10,
        };
        let before = project(&summary, &limits).unwrap();
        let obsolete = FieldProvenance::DerivedFromCurrent {
            inputs: vec!["x".repeat(128 * 1024)],
            algorithm: "unused".to_owned(),
        };
        summary.aggregates[0].coverage.provenance = obsolete.clone();
        for entry in &mut summary.entries {
            entry.provenance = obsolete.clone();
            entry.coverage.provenance = obsolete.clone();
            entry.metadata_fingerprint = "unused".repeat(32 * 1024);
        }
        let after = project(&summary, &limits).unwrap();
        assert_eq!(
            owned_capacity(&before, before.capacity()),
            owned_capacity(&after, after.capacity())
        );
        assert_eq!(after[0].logical_bytes, before[0].logical_bytes);
    }

    fn boundary_projection(name: std::ffi::OsString) -> PreviewSummary {
        let mut summary = fixture(1);
        summary.entries.clear();
        summary.aggregates.clear();
        summary.boundaries.push(BoundaryRecord {
            path: std::path::PathBuf::from("fixture").join(name),
            kind: BoundaryKind::AccessDenied,
            reason: ReasonCode::Unknown,
            detail: "unused".to_owned(),
        });
        let rows = project(
            &summary,
            &Limits {
                retained_bytes: 16 * 1024,
                records: 1,
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        rows.into_iter().next().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn boundary_retains_non_unicode_unix_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let bytes = vec![b'a', 0xff, b'z'];
        let row = boundary_projection(std::ffi::OsString::from_vec(bytes.clone()));
        assert_eq!(row.native_name, NativeName::unix(bytes));
        assert!(row.display_name.contains('\u{fffd}'));
        assert!(row.roles.contains(&PreviewRole::Boundary));
        assert!(!row.selectable);
    }

    #[cfg(windows)]
    #[test]
    fn boundary_retains_unpaired_windows_utf16_units() {
        use std::os::windows::ffi::OsStringExt;
        let units = [b'a' as u16, 0xd800, b'z' as u16];
        let row = boundary_projection(std::ffi::OsString::from_wide(&units));
        assert_eq!(row.native_name, NativeName::windows_utf16(units.to_vec()));
        assert!(row.display_name.contains('\u{fffd}'));
        assert!(!row.selectable);
    }
}
