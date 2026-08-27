use thiserror::Error;

use sweepx_model::{DirectoryAggregate, EvidenceValue, ReasonCode, ScannedEntry};
use sweepx_scanner::ScanSummary;

use crate::{
    Candidate, CandidateBuilder, Explanation, ExplanationBuilder, ExplanationClause,
    ExplanationKind, FactPresence, InferenceStrength, UnknownImpact,
};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("analysis digest error: {0}")]
    Digest(#[from] crate::AnalysisDigestError),
}

pub fn build_candidate_from_scan(
    entry: &ScannedEntry,
    aggregate: Option<&DirectoryAggregate>,
    live_source_required: bool,
) -> Result<Candidate, BuildError> {
    let mut builder = CandidateBuilder::new(entry).live_source_required(live_source_required);
    if let Some(aggregate) = aggregate {
        builder = builder.with_aggregate(aggregate, &aggregate.directory_identity);
    }
    Ok(builder.build()?)
}

pub fn build_explanation_from_candidate(candidate: &Candidate) -> Result<Explanation, BuildError> {
    let mut clauses = Vec::new();

    clauses.push(ExplanationClause {
        kind: ExplanationKind::Fact,
        code: "candidate_path_display".to_string(),
        message: format!(
            "Display path `{}` is presentation only.",
            candidate.path.display_path
        ),
        reason: None,
        fact_presence: Some(FactPresence::Present),
        inference_strength: None,
        unknown_impact: None,
    });

    clauses.push(ExplanationClause {
        kind: ExplanationKind::Inference,
        code: "identity_binding".to_string(),
        message: if candidate.path.stable_identity.is_some() {
            "Stable identity is tracked separately from display path.".to_string()
        } else {
            "No stable identity is attached, so display path is not used as identity.".to_string()
        },
        reason: Some(ReasonCode::IdentityUnstable),
        fact_presence: None,
        inference_strength: Some(InferenceStrength::Strong),
        unknown_impact: None,
    });

    clauses.extend(value_clause(
        "logical_bytes",
        "Logical bytes",
        &candidate.logical_bytes,
    ));
    clauses.extend(value_clause(
        "allocated_bytes",
        "Allocated bytes",
        &candidate.allocated_bytes,
    ));
    clauses.extend(value_clause(
        "reclaimable_estimate",
        "Reclaimable estimate",
        &candidate.reclaimable_estimate,
    ));

    if !candidate.coverage.complete {
        for reason in &candidate.coverage.incomplete_reasons {
            clauses.push(ExplanationClause {
                kind: ExplanationKind::Unknown,
                code: "entry_coverage_incomplete".to_string(),
                message: format!("Coverage is incomplete because of `{reason:?}`."),
                reason: Some(reason.clone()),
                fact_presence: None,
                inference_strength: None,
                unknown_impact: Some(UnknownImpact::RaisesToR4),
            });
        }
    }

    if candidate.eligibility.executable != crate::ExecutableEligibility::Executable {
        clauses.push(ExplanationClause {
            kind: ExplanationKind::Heuristic,
            code: "eligibility_gate".to_string(),
            message: format!(
                "Executable eligibility is `{}`.",
                match candidate.eligibility.executable {
                    crate::ExecutableEligibility::Executable => "executable",
                    crate::ExecutableEligibility::ReportOnly => "report_only",
                    crate::ExecutableEligibility::Blocked => "blocked",
                }
            ),
            reason: candidate.eligibility.reasons.first().cloned(),
            fact_presence: None,
            inference_strength: Some(InferenceStrength::Moderate),
            unknown_impact: None,
        });
    }

    Ok(ExplanationBuilder::new(candidate)
        .extend_clauses(clauses)
        .build()?)
}

pub fn build_candidates_from_summary(
    summary: &ScanSummary,
    live_source_required: bool,
) -> Result<Vec<Candidate>, BuildError> {
    build_candidates_from_summary_with_links(summary, &[], live_source_required)
}

pub fn build_candidates_from_summary_with_links(
    summary: &ScanSummary,
    links: &[DirectoryAggregateLink<'_>],
    live_source_required: bool,
) -> Result<Vec<Candidate>, BuildError> {
    summary
        .entries
        .iter()
        .map(|entry| {
            let mut builder =
                CandidateBuilder::new(entry).live_source_required(live_source_required);
            if let Some(link) = links.iter().find(|link| same_entry(entry, link.entry)) {
                builder = match find_linked_aggregate(entry, summary, link) {
                    Some(aggregate) => {
                        builder.with_aggregate(aggregate, &aggregate.directory_identity)
                    }
                    None => builder.with_expected_directory_identity(link.directory_identity),
                };
            }
            Ok(builder.build()?)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryAggregateLink<'a> {
    pub entry: &'a ScannedEntry,
    pub directory_identity: &'a str,
    pub expected_root_id: Option<&'a str>,
}

fn value_clause(
    code: &str,
    label: &str,
    value: &sweepx_model::ByteValue,
) -> Vec<ExplanationClause> {
    match value {
        EvidenceValue::Known { .. } => vec![ExplanationClause {
            kind: ExplanationKind::Fact,
            code: code.to_string(),
            message: format!("{label} is a known observed value."),
            reason: None,
            fact_presence: Some(FactPresence::Present),
            inference_strength: None,
            unknown_impact: None,
        }],
        EvidenceValue::LowerBound { reason, .. } => vec![ExplanationClause {
            kind: ExplanationKind::Heuristic,
            code: code.to_string(),
            message: format!("{label} is only a lower bound."),
            reason: Some(reason.clone()),
            fact_presence: Some(FactPresence::Partial),
            inference_strength: Some(InferenceStrength::Moderate),
            unknown_impact: None,
        }],
        EvidenceValue::Unknown { reason }
        | EvidenceValue::Unsupported { reason }
        | EvidenceValue::NotChecked { reason } => vec![ExplanationClause {
            kind: ExplanationKind::Unknown,
            code: code.to_string(),
            message: format!("{label} is not currently known."),
            reason: Some(reason.clone()),
            fact_presence: Some(FactPresence::Missing),
            inference_strength: None,
            unknown_impact: Some(if blocks_execution(reason) {
                UnknownImpact::Blocks
            } else {
                UnknownImpact::RaisesToR4
            }),
        }],
    }
}

fn blocks_execution(reason: &ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::IdentityUnstable
            | ReasonCode::UnsupportedPlatform
            | ReasonCode::UnsupportedFilesystem
            | ReasonCode::AdapterCapabilityAbsent
            | ReasonCode::StrictReadOnly
    )
}

fn same_entry(left: &ScannedEntry, right: &ScannedEntry) -> bool {
    std::ptr::eq(left, right)
}

fn find_linked_aggregate<'a>(
    entry: &ScannedEntry,
    summary: &'a ScanSummary,
    link: &DirectoryAggregateLink<'_>,
) -> Option<&'a DirectoryAggregate> {
    let identity = entry.validated_identity().ok().flatten()?;
    summary.aggregates.iter().find(|aggregate| {
        aggregate.scan_id == entry.scan_id
            && aggregate.scan_id == link.entry.scan_id
            && aggregate
                .scan_entry_id()
                .ok()
                .is_some_and(|aggregate_entry_id| aggregate_entry_id == identity.entry_id)
            && link.directory_identity == aggregate.directory_identity
            && link
                .expected_root_id
                .is_none_or(|expected_root_id| expected_root_id == identity.scan_root_id.as_str())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{
        Coverage, CoverageState, FieldProvenance, FilesystemObjectDomainIdentity, IdentityEvidence,
        MethodId, NativeAbsolutePath, NativeLocatorEvidence, NativeName, NativePathComponent,
        ObjectType, PlatformFileIdentity, ScanEntryId, ScanId, ScanObjectIdentity,
        VolumeOrMountIdentity,
    };
    use sweepx_scanner::ScanSummary;

    fn live_provenance() -> FieldProvenance {
        FieldProvenance::LiveObservation {
            observed_at: "2026-08-26T00:00:00Z".to_string(),
            method: MethodId::NativeApi,
        }
    }

    fn complete_coverage() -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance: live_provenance(),
        }
    }

    fn native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/root".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/root".to_vec())
        }
    }

    fn identity(entry_ordinal: u128, root_ordinal: u128) -> ScanObjectIdentity {
        let scan_id = ScanId::new("scan-1");
        let entry_id = ScanEntryId::for_scan_ordinal(&scan_id, entry_ordinal).unwrap();
        let scan_root_id = ScanEntryId::for_scan_ordinal(&scan_id, root_ordinal).unwrap();
        ScanObjectIdentity {
            parent_id: (entry_id != scan_root_id).then(|| scan_root_id.clone()),
            entry_id,
            scan_root_id,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: sweepx_model::DecimalU128::new(1),
                inode: sweepx_model::DecimalU128::new(entry_ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: sweepx_model::DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: sweepx_model::DecimalU128::new(1),
            }),
        }
    }

    fn native_locator(identity: &ScanObjectIdentity, basename: &str) -> NativeLocatorEvidence {
        NativeLocatorEvidence {
            scan_root: NativePathComponent {
                entry_id: identity.scan_root_id.clone(),
                native_basename: NativeName::unix(b"root".to_vec()),
                object_type: ObjectType::Directory,
                platform_file_identity: identity.platform_file_identity.clone(),
                filesystem_object_domain_identity: identity
                    .filesystem_object_domain_identity
                    .clone(),
                volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
                metadata_fingerprint: "root-fingerprint".to_string(),
            },
            scan_root_absolute_path: Some(native_absolute_root()),
            parent_reopen_recipe: identity
                .parent_id
                .as_ref()
                .map(|parent_id| NativePathComponent {
                    entry_id: parent_id.clone(),
                    native_basename: NativeName::unix(b"root".to_vec()),
                    object_type: ObjectType::Directory,
                    platform_file_identity: identity.platform_file_identity.clone(),
                    filesystem_object_domain_identity: identity
                        .filesystem_object_domain_identity
                        .clone(),
                    volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
                    metadata_fingerprint: "root-fingerprint".to_string(),
                })
                .into_iter()
                .collect(),
            entry: NativePathComponent {
                entry_id: identity.entry_id.clone(),
                native_basename: NativeName::unix(basename.as_bytes().to_vec()),
                object_type: ObjectType::Directory,
                platform_file_identity: identity.platform_file_identity.clone(),
                filesystem_object_domain_identity: identity
                    .filesystem_object_domain_identity
                    .clone(),
                volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
                metadata_fingerprint: "fp-1".to_string(),
            },
        }
    }

    fn aggregate(identity: &str, revision: u128, coverage: Coverage) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: ScanId::new("scan-1"),
            directory_identity: identity.to_string(),
            revision: sweepx_model::DecimalU128::new(revision),
            apparent_logical_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(10),
            },
            unique_logical_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(10),
            },
            filesystem_reported_allocated_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(12),
            },
            potentially_reclaimable_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(4),
            },
            direct_child_count: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            recursive_entry_count: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            coverage,
            arithmetic_state: sweepx_model::ArithmeticState::Exact,
        }
    }

    fn candidate() -> Candidate {
        build_candidate_from_scan(
            &ScannedEntry {
                scan_id: ScanId::new("scan-1"),
                identity: None,
                native_locator: None,
                display_path: "/tmp/item".to_string(),
                native_basename: NativeName::unix(b"item".to_vec()),
                object_type: ObjectType::File,
                logical_bytes: EvidenceValue::Known {
                    value: sweepx_model::DecimalU128::new(1),
                },
                allocated_bytes: EvidenceValue::LowerBound {
                    value: sweepx_model::DecimalU128::new(2),
                    reason: ReasonCode::IncompleteStreamCoverage,
                },
                reclaimable_estimate: EvidenceValue::Unknown {
                    reason: ReasonCode::Unknown,
                },
                metadata_fingerprint: "fp-1".to_string(),
                coverage: Coverage {
                    state: CoverageState::Complete,
                    complete: true,
                    incomplete_reasons: Vec::new(),
                    details_lost: false,
                    provenance: FieldProvenance::LiveObservation {
                        observed_at: "2026-08-26T00:00:00Z".to_string(),
                        method: MethodId::NativeApi,
                    },
                },
                provenance: FieldProvenance::LiveObservation {
                    observed_at: "2026-08-26T00:00:00Z".to_string(),
                    method: MethodId::NativeApi,
                },
            },
            None,
            true,
        )
        .unwrap()
    }

    #[test]
    fn explanation_separates_facts_inferences_heuristics_and_unknowns() {
        let explanation = build_explanation_from_candidate(&candidate()).unwrap();

        assert!(!explanation.facts().is_empty());
        assert!(!explanation.inferences().is_empty());
        assert!(!explanation.heuristics().is_empty());
        assert!(!explanation.unknowns().is_empty());
    }

    #[test]
    fn explanation_digest_is_stable() {
        let candidate = candidate();
        let left = build_explanation_from_candidate(&candidate).unwrap();
        let right = build_explanation_from_candidate(&candidate).unwrap();

        assert_eq!(left.canonical_digest, right.canonical_digest);
    }

    #[test]
    fn summary_links_bind_directory_aggregate_revision_and_coverage() {
        let stable_identity = identity(2, 1);
        let entry = ScannedEntry {
            scan_id: ScanId::new("scan-1"),
            identity: Some(stable_identity.clone()),
            native_locator: Some(native_locator(&stable_identity, "dir")),
            display_path: "/tmp/dir".to_string(),
            native_basename: NativeName::unix(b"dir".to_vec()),
            object_type: ObjectType::Directory,
            logical_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            allocated_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(2),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            metadata_fingerprint: "fp-dir".to_string(),
            coverage: complete_coverage(),
            provenance: live_provenance(),
        };
        let aggregate = aggregate(stable_identity.entry_id.as_str(), 99, complete_coverage());
        let summary = ScanSummary {
            roots: Vec::new(),
            entries: vec![entry.clone()],
            aggregates: vec![aggregate],
            boundaries: Vec::new(),
            progress: Vec::new(),
        };

        let candidates = build_candidates_from_summary_with_links(
            &summary,
            &[DirectoryAggregateLink {
                entry: &summary.entries[0],
                directory_identity: stable_identity.entry_id.as_str(),
                expected_root_id: Some(stable_identity.scan_root_id.as_str()),
            }],
            true,
        )
        .unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].aggregate_directory_identity.as_deref(),
            Some(stable_identity.entry_id.as_str())
        );
        assert_eq!(
            candidates[0].aggregate_revision,
            Some(sweepx_model::DecimalU128::new(99))
        );
        assert_eq!(candidates[0].aggregate_coverage, Some(complete_coverage()));
        assert_eq!(
            candidates[0].eligibility.executable,
            crate::ExecutableEligibility::Executable
        );
        assert_eq!(
            candidates[0].path.stable_identity.as_deref(),
            Some(stable_identity.entry_id.as_str())
        );
        assert_eq!(
            candidates[0].locator.scan_object_identity,
            Some(stable_identity)
        );
    }

    #[test]
    fn summary_links_fail_closed_when_identity_has_no_matching_aggregate() {
        let stable_identity = identity(2, 1);
        let entry = ScannedEntry {
            scan_id: ScanId::new("scan-1"),
            identity: Some(stable_identity.clone()),
            native_locator: None,
            display_path: "/tmp/dir".to_string(),
            native_basename: NativeName::unix(b"dir".to_vec()),
            object_type: ObjectType::Directory,
            logical_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            allocated_bytes: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(2),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: sweepx_model::DecimalU128::new(1),
            },
            metadata_fingerprint: "fp-dir".to_string(),
            coverage: complete_coverage(),
            provenance: live_provenance(),
        };
        let summary = ScanSummary {
            roots: Vec::new(),
            entries: vec![entry],
            aggregates: vec![aggregate(
                ScanEntryId::for_scan_ordinal(&ScanId::new("scan-1"), 99)
                    .unwrap()
                    .as_str(),
                1,
                complete_coverage(),
            )],
            boundaries: Vec::new(),
            progress: Vec::new(),
        };

        let candidates = build_candidates_from_summary_with_links(
            &summary,
            &[DirectoryAggregateLink {
                entry: &summary.entries[0],
                directory_identity: stable_identity.entry_id.as_str(),
                expected_root_id: Some(stable_identity.scan_root_id.as_str()),
            }],
            true,
        )
        .unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].aggregate_revision, None);
        assert_eq!(candidates[0].aggregate_coverage, None);
        assert_eq!(
            candidates[0].eligibility.executable,
            crate::ExecutableEligibility::ReportOnly
        );
        assert_eq!(
            candidates[0].path.stable_identity.as_deref(),
            Some(stable_identity.entry_id.as_str())
        );
        assert!(
            candidates[0]
                .eligibility
                .reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }
}
