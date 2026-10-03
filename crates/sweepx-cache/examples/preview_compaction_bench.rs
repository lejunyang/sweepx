//! Controlled, read-only in-memory compaction comparison; no native cache IO or scan timing.
//! The finite fixture deliberately exceeds the record cap to exercise global trimming.
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Instant};
use sweepx_cache::{PreviewBudgets, PreviewCoverage, PreviewKind, PreviewSummary, compact_preview};
use sweepx_model::{DecimalU128, EvidenceValue, FieldProvenance, NativeName};

fn main() {
    let mut rows = Vec::new();
    for parent in 0..32 {
        for child in 0..64 {
            let name = format!("child-{child:03}");
            let known = EvidenceValue::Known {
                value: DecimalU128::new((parent * 64 + child + 1) as u128),
            };
            rows.push(PreviewSummary {
                kind: PreviewKind::Directory,
                parent_id: Some(format!("parent-{parent:03}")),
                entry_id: format!("{parent:03}-{child:03}"),
                native_name: NativeName::unix(name.as_bytes().to_vec()),
                display_name: name,
                logical_bytes: known.clone(),
                allocated_bytes: known,
                direct_child_count: EvidenceValue::Known {
                    value: DecimalU128::new(0),
                },
                recursive_entry_count: EvidenceValue::Known {
                    value: DecimalU128::new(1),
                },
                aggregate: None,
                coverage: PreviewCoverage {
                    complete: true,
                    details_lost: false,
                    incomplete_reasons: Vec::new(),
                },
                selectable: true,
                roles: BTreeSet::new(),
                provenance: FieldProvenance::StalePreview {
                    observed_at: "fixture".into(),
                },
            });
        }
    }
    let budgets = PreviewBudgets {
        preview_record_cap: 256,
        preview_byte_cap: 64 * 1024 * 1024,
        ..Default::default()
    };
    let started = Instant::now();
    let result = compact_preview(rows, &budgets);
    let elapsed = started.elapsed();
    // Independent oracle: rank by plain numerical sizes and count only parents that actually
    // lose a child. Untouched high-rank parents have no Others row. Check all omitted bytes.
    assert_eq!(result.total_records, 256);
    assert_eq!(result.parents.len(), 32);
    let mut retained = BTreeSet::new();
    let mut total = 0u128;
    let mut entries = 0u128;
    for parent in result.parents.values() {
        for row in &parent.retained {
            let EvidenceValue::Known { value } = row.logical_bytes else {
                panic!("exact fixture")
            };
            retained.insert(value.0);
            total += value.0;
            entries += 1;
        }
        if let Some(row) = &parent.others {
            let EvidenceValue::Known { value } = row.logical_bytes else {
                panic!("exact Others")
            };
            total += value.0;
            let EvidenceValue::Known { value } = row.direct_child_count else {
                panic!("exact count")
            };
            entries += value.0;
        }
    }
    let threshold = (1u128..=2049)
        .find(|threshold| {
            let omitted = threshold - 1;
            let kept = 2048 - omitted;
            kept + omitted.div_ceil(64) <= 256
        })
        .unwrap();
    assert_eq!(retained, (threshold..=2048).collect());
    assert_eq!(entries, 2048);
    assert_eq!(total, 2048 * 2049 / 2);
    let encoded = serde_json::to_vec(&result).unwrap();
    println!(
        "{}",
        serde_json::json!({"compactionElapsedNanos": elapsed.as_nanos().to_string(),
        "resultSha256": format!("{:x}", Sha256::digest(&encoded)), "serializedBytes": encoded.len()})
    );
}
