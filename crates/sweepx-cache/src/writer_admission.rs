//! Check that a new generation fits the loader's reservation ledger before native publication.
//!
//! The existing serde decoder measures one bounded fragment at a time. No complete generation
//! buffer or second owned preview is built. A fixed envelope skeleton accounts for header and
//! empty-container costs; parent/row/token fragments add their actual decoder reservations.
//! Only the outer BTreeMap/Vec seed costs are composed here, using the loader's exact rules.
//! This is a conservative upper bound, not a new JSON parser, schema or process RSS promise.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use sweepx_model::{FieldProvenance, NativeName, ReasonCode};

use crate::{
    CacheError, CompactedPreview, LimitedWriter, ParentPreview, PreviewSummary, StoredEnvelope,
    StoredGeneration, VolumeValidityRecord, json_budget,
};

/// Encoded scratch for one header, parent shell, row or legacy token, reused across fragments.
/// Refusing a large fragment preserves the previous generation and current scan facts.
const FRAGMENT_BYTE_CAP: usize = 1024 * 1024;
/// Decoder reservations for a single fragment; source data and encoded scratch are separate.
const FRAGMENT_RESERVATION_CAP: usize = 8 * 1024 * 1024;

fn resource_limit() -> CacheError {
    CacheError::ResourceLimit {
        reason: ReasonCode::ResourceLimit,
    }
}

fn bounded_provenance(value: &FieldProvenance) -> bool {
    let text = |value: &str| value.len() <= FRAGMENT_BYTE_CAP;
    match value {
        FieldProvenance::LiveObservation { observed_at, .. }
        | FieldProvenance::StalePreview { observed_at } => text(observed_at),
        FieldProvenance::ValidatedCache {
            observed_at, token, ..
        } => text(observed_at) && text(token),
        FieldProvenance::DerivedFromCurrent { inputs, algorithm } => {
            // Even empty JSON strings require two bytes. Bound metadata work before walking
            // the vector; each string is length-checked before serde scans it for escapes.
            inputs.len() <= FRAGMENT_BYTE_CAP / 2
                && text(algorithm)
                && inputs.iter().all(|value| text(value))
        }
        FieldProvenance::Unknown { .. } => true,
    }
}

struct Admission {
    scratch: Vec<u8>,
    remaining: usize,
}

impl Admission {
    fn reserve(&mut self, bytes: usize) -> Result<(), CacheError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(resource_limit)?;
        Ok(())
    }

    fn measure<T: Serialize + DeserializeOwned>(&mut self, value: &T) -> Result<(), CacheError> {
        self.scratch.clear();
        let mut writer = LimitedWriter::new(&mut self.scratch, FRAGMENT_BYTE_CAP);
        let encoded = serde_json::to_writer(&mut writer, value);
        if writer.exhausted {
            return Err(resource_limit());
        }
        encoded?;
        // A fragment cannot consume more than the remaining whole-generation allowance.
        let cap = self.remaining.min(FRAGMENT_RESERVATION_CAP);
        let (decoded, reserved) = json_budget::parse_with_usage::<T>(&self.scratch, cap).map_err(
            |error| match error {
                json_budget::ParseError::ResourceLimit => resource_limit(),
                json_budget::ParseError::Json => CacheError::MalformedManifest(
                    "writer fragment does not round-trip through the generation decoder".into(),
                ),
            },
        )?;
        // Drop the entire temporary row, including enum buffers, before the next fragment.
        drop(decoded);
        self.reserve(reserved)
    }

    fn row(&mut self, row: &PreviewSummary) -> Result<(), CacheError> {
        // serde scans borrowed strings for escaping before submitting a write. A single huge
        // string must therefore fail by O(1) length checks, not only at LimitedWriter::write.
        if row.entry_id.len() > FRAGMENT_BYTE_CAP
            || row.display_name.len() > FRAGMENT_BYTE_CAP
            || row
                .parent_id
                .as_ref()
                .is_some_and(|value| value.len() > FRAGMENT_BYTE_CAP)
            || row.coverage.incomplete_reasons.len() > FRAGMENT_BYTE_CAP
            || !bounded_provenance(&row.provenance)
            || row.aggregate.as_ref().is_some_and(|value| {
                value.scan_id.len() > FRAGMENT_BYTE_CAP
                    || value.directory_identity.len() > FRAGMENT_BYTE_CAP
                    || value.coverage.incomplete_reasons.len() > FRAGMENT_BYTE_CAP
                    || !bounded_provenance(&value.coverage.provenance)
            })
        {
            return Err(resource_limit());
        }
        // NativeName's serializer allocates encoded bytes before writing. Admit that input
        // separately; all other dynamic fields in this DTO serialize by borrowing their data.
        let raw_bytes = match &row.native_name {
            NativeName::UnixBytes(bytes) => bytes.len(),
            NativeName::WindowsUtf16(units) => units.len().saturating_mul(2),
        };
        if raw_bytes > FRAGMENT_BYTE_CAP {
            return Err(resource_limit());
        }
        self.measure(row)
    }
}

/// Admit the loader's whole-generation reservation bound without cloning all retained rows.
/// A successfully published generation fits this target's default loader reservation cap;
/// IO failures, later external edits and independent validation still have their own checks.
pub(super) fn admit(generation: &StoredGeneration, cap: usize) -> Result<usize, CacheError> {
    // Only small header/shell fields are cloned. Reserve their lengths before doing so; JSON
    // escaping can still exceed encoded scratch and is refused by the bounded writer.
    let header_bytes = generation
        .generation
        .len()
        .saturating_mul(2)
        .saturating_add(generation.schema.len())
        .saturating_add(generation.created_at.len());
    if header_bytes > FRAGMENT_BYTE_CAP {
        return Err(resource_limit());
    }
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(FRAGMENT_BYTE_CAP)
        .map_err(|_| resource_limit())?;
    let mut admission = Admission {
        scratch,
        remaining: cap,
    };
    let header = StoredEnvelope {
        generation: generation.generation.clone(),
        // The actual digest has exactly 64 unescaped ASCII bytes and identical storage cost.
        checksum_sha256: "0".repeat(64),
        payload: StoredGeneration {
            generation: generation.generation.clone(),
            schema: generation.schema.clone(),
            created_at: generation.created_at.clone(),
            preview: CompactedPreview {
                parents: BTreeMap::new(),
                total_estimated_bytes: generation.preview.total_estimated_bytes,
                total_records: generation.preview.total_records,
                visible_resource_limit: generation.preview.visible_resource_limit,
            },
            validity: Vec::new(),
        },
    };
    admission.measure(&header)?;
    drop(header);
    if !generation.preview.parents.is_empty() {
        // Empty-map baseline paid the first key seed. A populated tree needs nine extra
        // value slots at its first entry (12 rather than the subsequent 3). Standalone
        // parent measurements already pay two value slots; add one per parent below.
        admission.reserve(
            json_budget::tree_reservation::<ParentPreview>(0)
                .saturating_sub(json_budget::tree_reservation::<ParentPreview>(1)),
        )?;
    }
    for (key, parent) in &generation.preview.parents {
        // Relative to the empty-map baseline: each entry adds a subsequent key reservation,
        // its value's remaining slot, two 64-byte tree allowances, and the decoded key text.
        admission.reserve(
            json_budget::tree_reservation::<String>(1)
                .saturating_add(
                    json_budget::tree_reservation::<ParentPreview>(1)
                        .saturating_sub(json_budget::root_reservation::<ParentPreview>()),
                )
                .saturating_add(json_budget::string_reservation(key.len())),
        )?;
        if parent.parent_id.len() > FRAGMENT_BYTE_CAP {
            return Err(resource_limit());
        }
        let shell = ParentPreview {
            parent_id: parent.parent_id.clone(),
            retained: Vec::new(),
            others: None,
        };
        admission.measure(&shell)?;
        drop(shell);
        // An empty sequence's 8 slots equal the populated sequence's initial/end slack.
        // Each standalone row pays 2 slots, the same as subsequent sequence seeds. This
        // includes the final unsuccessful next_element call. Others' inline row instead
        // needs no seed slots: retaining its standalone charge is deliberately conservative.
        for row in &parent.retained {
            admission.reserve(
                json_budget::sequence_reservation::<PreviewSummary>(1)
                    .saturating_sub(json_budget::root_reservation::<PreviewSummary>()),
            )?;
            admission.row(row)?;
        }
        if let Some(row) = &parent.others {
            admission.row(row)?;
        }
    }
    // Empty validity already paid its sequence's 8-slot/128-byte baseline. Each standalone
    // token contributes two slots plus its actual string/struct costs, matching the Vec path.
    for token in &generation.validity {
        if [
            &token.kind,
            &token.volume,
            &token.sequence_id,
            &token.position,
        ]
        .iter()
        .any(|value| value.len() > FRAGMENT_BYTE_CAP)
        {
            return Err(resource_limit());
        }
        admission.reserve(
            json_budget::sequence_reservation::<VolumeValidityRecord>(1)
                .saturating_sub(json_budget::root_reservation::<VolumeValidityRecord>()),
        )?;
        admission.measure::<VolumeValidityRecord>(token)?;
    }
    Ok(cap - admission.remaining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreviewCoverage, PreviewKind, PreviewRole, STORED_PREVIEW_SCHEMA};
    use std::collections::BTreeSet;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, DirectoryAggregate, EvidenceValue,
        FieldProvenance, MethodId, ScanId,
    };

    fn evidence(index: usize) -> EvidenceValue<DecimalU128> {
        match index % 5 {
            0 => EvidenceValue::Known {
                value: DecimalU128::new(u128::MAX),
            },
            1 => EvidenceValue::LowerBound {
                value: DecimalU128::new(23),
                reason: ReasonCode::ResourceLimit,
            },
            2 => EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            3 => EvidenceValue::Unsupported {
                reason: ReasonCode::AdapterCapabilityAbsent,
            },
            _ => EvidenceValue::NotChecked {
                reason: ReasonCode::StrictReadOnly,
            },
        }
    }

    fn row(index: usize) -> PreviewSummary {
        let provenance = if index.is_multiple_of(2) {
            FieldProvenance::StalePreview {
                observed_at: "escaped\"\n雪".into(),
            }
        } else {
            FieldProvenance::ValidatedCache {
                observed_at: "observed".into(),
                validation: MethodId::ValidatedCacheToken,
                token: "legacy\0token".into(),
            }
        };
        let aggregate = index.is_multiple_of(3).then(|| DirectoryAggregate {
            scan_id: ScanId::new("test"),
            directory_identity: "typed-or-legacy-display".into(),
            revision: DecimalU128::new(u128::MAX),
            apparent_logical_bytes: evidence(index),
            unique_logical_bytes: evidence(index + 1),
            filesystem_reported_allocated_bytes: evidence(index + 2),
            potentially_reclaimable_bytes: evidence(index + 3),
            direct_child_count: evidence(index + 4),
            recursive_entry_count: evidence(index),
            coverage: Coverage {
                state: CoverageState::Incomplete,
                complete: false,
                incomplete_reasons: vec![ReasonCode::ResourceLimit; index % 9],
                details_lost: true,
                provenance: FieldProvenance::DerivedFromCurrent {
                    inputs: vec!["first".into(), "quote\"\n雪".into()],
                    algorithm: "fixture".into(),
                },
            },
            arithmetic_state: ArithmeticState::LowerBound,
        });
        PreviewSummary {
            kind: PreviewKind::Directory,
            parent_id: Some("parent".into()),
            entry_id: format!("entry-{index}"),
            native_name: if index.is_multiple_of(2) {
                NativeName::unix(vec![b'a', 0xff, b'z'])
            } else {
                NativeName::windows_utf16(vec![0x61, 0xd800, 0x7a])
            },
            display_name: format!("/controlled/quote\"\n雪-{index}"),
            logical_bytes: evidence(index),
            allocated_bytes: evidence(index + 1),
            direct_child_count: evidence(index + 2),
            recursive_entry_count: evidence(index + 3),
            aggregate,
            coverage: PreviewCoverage {
                complete: false,
                details_lost: true,
                incomplete_reasons: vec![ReasonCode::Unknown; index % 17],
            },
            selectable: false,
            roles: BTreeSet::from([
                PreviewRole::Root,
                PreviewRole::RequiredAncestor,
                PreviewRole::Boundary,
                PreviewRole::Error,
                PreviewRole::HeavyLeaf,
                PreviewRole::TopHeavyChild,
            ]),
            provenance,
        }
    }

    fn fixture(parents: usize, rows: usize, others: bool, tokens: usize) -> StoredGeneration {
        let parents = (0..parents)
            .map(|index| {
                (
                    format!("key\"\n雪-{index}"),
                    ParentPreview {
                        parent_id: format!("parent-{index}"),
                        retained: (0..rows).map(|row_index| row(index + row_index)).collect(),
                        others: others.then(|| {
                            let mut value = row(index);
                            value.kind = PreviewKind::Others;
                            value.provenance = FieldProvenance::StalePreview {
                                observed_at: "older".into(),
                            };
                            value
                        }),
                    },
                )
            })
            .collect();
        StoredGeneration {
            generation: "writer_fixture".into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "2026-10-04T00:00:00Z".into(),
            preview: CompactedPreview {
                parents,
                total_estimated_bytes: 0,
                total_records: 0,
                visible_resource_limit: true,
            },
            validity: (0..tokens)
                .map(|index| VolumeValidityRecord {
                    kind: "opaque-future".into(),
                    volume: format!("volume-{index}"),
                    sequence_id: "escaped\"\n雪".into(),
                    position: "not-a-number".into(),
                })
                .collect(),
        }
    }

    fn full_parse_usage(generation: &StoredGeneration) -> usize {
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: crate::checksum_hex(generation).unwrap(),
            payload: generation,
        };
        let bytes = serde_json::to_vec(&envelope).unwrap();
        let ordinary: StoredEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ordinary.payload, *generation);
        let (parsed, used) = json_budget::parse_with_usage::<StoredEnvelope>(
            &bytes,
            json_budget::PARSE_RESERVATION_CAP,
        )
        .unwrap();
        assert_eq!(parsed, ordinary);
        used
    }

    #[test]
    fn fragment_composition_covers_full_decoder_and_plain_serde_oracles() {
        for parents in [0, 1, 2, 11, 12, 65] {
            for rows in [0, 1, 2, 7, 8, 9] {
                for others in [false, true] {
                    let generation = fixture(parents, rows, others, rows);
                    let actual = full_parse_usage(&generation);
                    let composed = admit(&generation, json_budget::PARSE_RESERVATION_CAP).unwrap();
                    assert!(
                        composed >= actual,
                        "parents={parents} rows={rows} others={others} composed={composed} actual={actual}"
                    );
                    // Independent observed full-parser cost proves lower caps must refuse.
                    assert!(matches!(
                        admit(&generation, actual - 1),
                        Err(CacheError::ResourceLimit { .. })
                    ));
                }
            }
        }
    }

    #[test]
    fn scratch_and_native_encoding_inputs_are_bounded_before_publication() {
        for field in ["header", "parent", "row", "native", "provenance", "token"] {
            let mut generation = fixture(1, 1, false, 0);
            match field {
                "header" => generation.created_at = "x".repeat(FRAGMENT_BYTE_CAP + 1),
                "parent" => {
                    generation
                        .preview
                        .parents
                        .values_mut()
                        .next()
                        .unwrap()
                        .parent_id = "x".repeat(FRAGMENT_BYTE_CAP + 1)
                }
                "row" => {
                    generation
                        .preview
                        .parents
                        .values_mut()
                        .next()
                        .unwrap()
                        .retained[0]
                        .display_name = "x".repeat(FRAGMENT_BYTE_CAP + 1)
                }
                "native" => {
                    generation
                        .preview
                        .parents
                        .values_mut()
                        .next()
                        .unwrap()
                        .retained[0]
                        .native_name = NativeName::windows_utf16(vec![0x61; FRAGMENT_BYTE_CAP])
                }
                "provenance" => {
                    generation
                        .preview
                        .parents
                        .values_mut()
                        .next()
                        .unwrap()
                        .retained[0]
                        .aggregate
                        .as_mut()
                        .unwrap()
                        .coverage
                        .provenance = FieldProvenance::DerivedFromCurrent {
                        inputs: vec!["x".repeat(FRAGMENT_BYTE_CAP + 1)],
                        algorithm: "fixture".into(),
                    }
                }
                _ => generation.validity.push(VolumeValidityRecord {
                    kind: "fixture".into(),
                    volume: "x".repeat(FRAGMENT_BYTE_CAP + 1),
                    sequence_id: "fixture".into(),
                    position: "fixture".into(),
                }),
            }
            assert!(
                matches!(
                    admit(&generation, json_budget::PARSE_RESERVATION_CAP),
                    Err(CacheError::ResourceLimit { .. })
                ),
                "{field}"
            );
        }
    }

    #[test]
    fn parser_reservations_bound_dense_fragment_independently_of_encoded_bytes() {
        // Unit enums do not retain String slots. Compare that sparse storage shape against
        // enum-buffered empty String slots, whose capacity dominates their encoded content.
        let mut sparse = row(0);
        sparse.coverage.incomplete_reasons = vec![ReasonCode::Unknown; 100_000];
        let sparse_bytes = serde_json::to_vec(&sparse).unwrap();
        let (_, sparse_used) = json_budget::parse_with_usage::<PreviewSummary>(
            &sparse_bytes,
            json_budget::PARSE_RESERVATION_CAP,
        )
        .unwrap();
        assert!(sparse_used < FRAGMENT_RESERVATION_CAP);
        let mut generation = fixture(1, 1, false, 0);
        generation
            .preview
            .parents
            .values_mut()
            .next()
            .unwrap()
            .retained[0]
            .aggregate
            .as_mut()
            .unwrap()
            .coverage
            .provenance = FieldProvenance::DerivedFromCurrent {
            inputs: vec![String::new(); 200_000],
            algorithm: "dense".into(),
        };
        // A dense sequence can fit the encoded fragment cap while exceeding owning storage.
        let bytes =
            serde_json::to_vec(&generation.preview.parents.values().next().unwrap().retained[0])
                .unwrap();
        assert!(bytes.len() < FRAGMENT_BYTE_CAP);
        let (_, actual) = json_budget::parse_with_usage::<PreviewSummary>(
            &bytes,
            json_budget::PARSE_RESERVATION_CAP,
        )
        .unwrap();
        assert!(actual > FRAGMENT_RESERVATION_CAP);
        println!(
            "writer_fragment_density unit_enum_encoded={} unit_enum_reservation={sparse_used} empty_strings_encoded={} empty_strings_reservation={actual}",
            sparse_bytes.len(),
            bytes.len()
        );
        assert!(matches!(
            admit(&generation, json_budget::PARSE_RESERVATION_CAP),
            Err(CacheError::ResourceLimit { .. })
        ));
    }

    #[test]
    fn normal_shape_reservation_measurements_have_decoder_equivalence() {
        for (parents, rows) in [(1, 64), (64, 16), (1000, 1)] {
            let generation = fixture(parents, rows, false, 0);
            let actual = full_parse_usage(&generation);
            let start = std::time::Instant::now();
            let composed = admit(&generation, json_budget::PARSE_RESERVATION_CAP).unwrap();
            println!(
                "writer_admission parents={parents} rows_per_parent={rows} decoder_bytes={actual} composed_bytes={composed} elapsed_micros={}",
                start.elapsed().as_micros()
            );
        }
    }

    #[test]
    fn default_writer_refuses_encoded_small_generation_that_default_loader_cannot_admit() {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let base = std::fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let base = temp.path().to_path_buf();
        let store = crate::AtomicGenerationStore::new(base.join("cache"));
        let previous = fixture(1, 1, false, 0);
        store.write_generation(&previous).unwrap();
        let pointer = std::fs::read(store.current_pointer_path()).unwrap();
        let old_bytes = std::fs::read(store.generation_path(&previous.generation)).unwrap();
        let mut next = fixture(20_000, 1, false, 0);
        next.generation = "encoded_small_but_unreadable".into();
        crate::validate_stored_generation(&next).unwrap();
        let envelope = StoredEnvelope {
            generation: next.generation.clone(),
            checksum_sha256: crate::checksum_hex(&next).unwrap(),
            payload: &next,
        };
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert!(encoded.len() < crate::INSPECT_GENERATION_BYTE_LIMIT as usize);
        let ordinary: StoredEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(ordinary.payload, next);
        drop(ordinary);
        assert!(matches!(
            json_budget::parse_generation(&encoded, json_budget::PARSE_RESERVATION_CAP),
            Err(json_budget::ParseError::ResourceLimit)
        ));
        let start = std::time::Instant::now();
        assert!(matches!(
            store.write_generation(&next),
            Err(CacheError::ResourceLimit { .. })
        ));
        println!(
            "writer_default_refusal parents=20000 encoded_bytes={} elapsed_micros={}",
            encoded.len(),
            start.elapsed().as_micros()
        );
        assert_eq!(
            std::fs::read(store.current_pointer_path()).unwrap(),
            pointer
        );
        assert_eq!(
            std::fs::read(store.generation_path(&previous.generation)).unwrap(),
            old_bytes
        );
        assert_eq!(
            std::fs::read_dir(store.generations_dir()).unwrap().count(),
            1
        );
        assert!(!store.quarantine_dir().exists());
        assert_eq!(
            store.load_current().unwrap(),
            crate::LoadResult::Hit(previous)
        );
    }

    #[test]
    fn writer_refusals_do_not_create_missing_storage() {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let base = std::fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let base = temp.path().to_path_buf();
        let store = crate::AtomicGenerationStore::new(base.join("missing"));
        let mut generation = fixture(1, 1, false, 0);
        assert!(matches!(
            store.write_generation_with_limits(
                &generation,
                crate::INSPECT_GENERATION_BYTE_LIMIT as usize,
                128
            ),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert!(!store.root().exists());
        generation
            .preview
            .parents
            .values_mut()
            .next()
            .unwrap()
            .retained[0]
            .display_name = "x".repeat(FRAGMENT_BYTE_CAP + 1);
        assert!(matches!(
            store.write_generation(&generation),
            Err(CacheError::ResourceLimit { .. })
        ));
        assert!(!store.root().exists());
    }
}
