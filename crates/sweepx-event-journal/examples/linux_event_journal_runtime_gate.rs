//! Deterministic Linux event-journal runtime measurement harness.
//!
//! This executable measures the public `append_complete_stream` call with a fixed synthetic
//! workload. It is intentionally not a Criterion microbenchmark: every invocation creates a
//! fresh journal, commits one complete stream, and verifies the durable result. The companion
//! runner records repeated release-profile samples and decides whether to enforce the target.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use sweepx_event_journal::{EventJournal, FinalSnapshotMetadata};
#[cfg(target_os = "linux")]
use sweepx_model::{DecimalU128, OperationId};
#[cfg(target_os = "linux")]
use sweepx_protocol::{
    EventCheckpoint, EventEnvelope, EventPhase, EventType, ExitCode, OutputKind, OutputStatus,
    TerminalEventExpectation, TerminalEventPayload,
};
#[cfg(target_os = "linux")]
use tempfile::TempDir;

#[cfg(target_os = "linux")]
const TRANSACTION_TARGET_NS: u128 = 1_000_000_000;
#[cfg(target_os = "linux")]
const SMOKE_EVENT_COUNT: usize = 256;
#[cfg(target_os = "linux")]
// This fixed v1 qualification-candidate batch leaves conservative headroom below the journal's
// separate 4 MiB WAL cap on the reference SQLite configuration. The public journal count ceiling
// remains 50,000, but it is not a promise that 50,000 maximum-sized records fit the byte/WAL
// quotas.
const QUALIFICATION_EVENT_COUNT: usize = 2_048;
#[cfg(target_os = "linux")]
const JOURNAL_EVENT_CEILING: usize = 50_000;
#[cfg(target_os = "linux")]
const JOURNAL_STORAGE_CEILING_BYTES: u64 = 32 * 1024 * 1024;
#[cfg(target_os = "linux")]
const WORKLOAD_PROFILE_VERSION: &str = "linux-event-journal-v1";
#[cfg(target_os = "linux")]
const QUALIFICATION_WORKLOAD_SHA256: &str =
    "sha256:245ef1f1197c2718433169afd449f2f8b095c9869ce9ca2939795cae624c2552";
#[cfg(target_os = "linux")]
const STREAM_ID: &str = "runtime-gate-stream-v1";
#[cfg(target_os = "linux")]
const OPERATION_ID: &str = "runtime-gate-operation-v1";
#[cfg(target_os = "linux")]
const FIXED_TIMESTAMP: &str = "2026-08-28T00:00:00Z";
#[cfg(target_os = "linux")]
const PRODUCER_CURSOR: &str = "sxcur1.producer-placeholder-v1";

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Smoke,
    Qualification,
}

#[cfg(target_os = "linux")]
impl Profile {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "smoke" => Ok(Self::Smoke),
            "qualification" => Ok(Self::Qualification),
            other => Err(format!(
                "unknown profile {other:?}; expected smoke or qualification"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Qualification => "qualification",
        }
    }

    fn event_count(self) -> usize {
        match self {
            Self::Smoke => SMOKE_EVENT_COUNT,
            Self::Qualification => QUALIFICATION_EVENT_COUNT,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Arguments {
    profile: Profile,
    run_index: u32,
    warmup: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkloadMetrics {
    profile_version: &'static str,
    total_events: usize,
    journal_event_ceiling: usize,
    journal_storage_ceiling_bytes: u64,
    progress_events: usize,
    boundary_events: usize,
    error_events: usize,
    terminal_events: usize,
    input_json_bytes: u64,
    committed_json_bytes: u64,
    workload_sha256: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TimingMetrics {
    build_workload_ns: u128,
    open_journal_ns: u128,
    append_complete_stream_ns: u128,
    verify_integrity_ns: u128,
    read_and_validate_ns: u128,
    total_ns: u128,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageMetrics {
    database_bytes: u64,
    wal_bytes: u64,
    shm_bytes: u64,
    total_bytes: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ThresholdObservation {
    metric: &'static str,
    target_ns: u128,
    observed_ns: u128,
    met: bool,
    enforced_by_harness: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Sample {
    schema: &'static str,
    profile: &'static str,
    run_index: u32,
    warmup: bool,
    api: &'static str,
    measured_append_sqlite_transactions: u8,
    workload: WorkloadMetrics,
    timing: TimingMetrics,
    storage: StorageMetrics,
    threshold: ThresholdObservation,
    correctness_verified: bool,
    formal_qualification: bool,
    scope_note: &'static str,
}

#[cfg(target_os = "linux")]
fn parse_arguments() -> Result<Arguments, String> {
    let mut profile = None;
    let mut run_index = None;
    let mut warmup = false;
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--profile" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                if profile.replace(Profile::parse(&value)?).is_some() {
                    return Err("--profile may be supplied only once".to_string());
                }
            }
            "--run-index" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--run-index requires a value".to_string())?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| "--run-index must be an unsigned integer".to_string())?;
                if run_index.replace(parsed).is_some() {
                    return Err("--run-index may be supplied only once".to_string());
                }
            }
            "--warmup" => warmup = true,
            "--help" | "-h" => {
                println!(
                    "Usage: linux_event_journal_runtime_gate --profile smoke|qualification \
                     --run-index N [--warmup]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    Ok(Arguments {
        profile: profile.ok_or_else(|| "--profile is required".to_string())?,
        run_index: run_index.ok_or_else(|| "--run-index is required".to_string())?,
        warmup,
    })
}

#[cfg(target_os = "linux")]
fn event(event_type: EventType, payload: serde_json::Value, terminal: bool) -> EventEnvelope {
    EventEnvelope {
        schema: sweepx_protocol::EVENT_SCHEMA.to_string(),
        stream_id: STREAM_ID.to_string(),
        operation_id: OperationId::new(OPERATION_ID),
        sequence: DecimalU128::ZERO,
        cursor: PRODUCER_CURSOR.to_string(),
        emitted_at: FIXED_TIMESTAMP.to_string(),
        monotonic_offset_ns: DecimalU128::ZERO,
        r#type: event_type,
        phase: EventPhase::Detect,
        payload,
        terminal,
        checkpoint: EventCheckpoint {
            durable: false,
            last_durable_sequence: DecimalU128::ZERO,
        },
    }
}

#[cfg(target_os = "linux")]
fn final_snapshot() -> Result<FinalSnapshotMetadata, String> {
    FinalSnapshotMetadata::from_json(&serde_json::json!({
        "schema": "sweepx.operation-snapshot/v1",
        "operationId": OPERATION_ID,
        "command": "scan",
        "state": "partial",
        "status": "partial",
        "exitCode": 4,
        "runtimeGateFixture": "linux-event-journal-v1"
    }))
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn build_workload(
    profile: Profile,
    snapshot: &FinalSnapshotMetadata,
) -> Result<(Vec<EventEnvelope>, WorkloadMetrics), String> {
    let event_count = profile.event_count();
    let mut events = Vec::with_capacity(event_count);
    events.push(event(
        EventType::OperationStarted,
        serde_json::json!({
            "command": "scan",
            "requestDigest": "sha256:7d0ee77f276fb417f397d90b15f11b93e44722081f2f56e80bc9f49d41161e4e",
            "rootCount": "4",
            "resumable": false
        }),
        false,
    ));

    let mut progress_events = 0;
    let mut boundary_events = 0;
    let mut error_events = 0;
    for ordinal in 1..event_count - 1 {
        let display_path = format!(
            "/sweepx-runtime-fixture/root-{}/directory-{}/entry-{:08}",
            ordinal % 4,
            (ordinal / 256) % 64,
            ordinal
        );
        if ordinal % 127 == 0 {
            error_events += 1;
            events.push(event(
                EventType::ScanErrorObserved,
                serde_json::json!({
                    "displayPath": display_path,
                    "reason": "permission_denied",
                    "coverageEffect": "incomplete"
                }),
                false,
            ));
        } else if ordinal % 64 == 0 {
            boundary_events += 1;
            events.push(event(
                EventType::ScanBoundaryObserved,
                serde_json::json!({
                    "displayPath": display_path,
                    "boundaryKind": "mount",
                    "coverageEffect": "incomplete"
                }),
                false,
            ));
        } else {
            progress_events += 1;
            events.push(event(
                EventType::ScanProgress,
                serde_json::json!({
                    "displayPath": display_path,
                    "kind": "file",
                    "processed": ordinal.to_string(),
                    "completeState": "streaming"
                }),
                false,
            ));
        }
    }

    events.push(event(
        EventType::OperationTerminal,
        serde_json::to_value(TerminalEventPayload {
            status: OutputStatus::Partial,
            exit_code: ExitCode::Partial,
            kind: OutputKind::ScanResult,
            snapshot_digest: snapshot.snapshot_digest().to_string(),
        })
        .map_err(|error| error.to_string())?,
        true,
    ));

    let canonical_workload = serde_jcs::to_vec(&events).map_err(|error| error.to_string())?;
    let input_json_bytes = events.iter().try_fold(0_u64, |total, item| {
        let bytes = serde_json::to_vec(item)
            .map_err(|error| error.to_string())?
            .len();
        total
            .checked_add(u64::try_from(bytes).map_err(|error| error.to_string())?)
            .ok_or_else(|| "input workload byte count overflowed".to_string())
    })?;
    let workload_sha256 = format!("sha256:{:x}", Sha256::digest(&canonical_workload));
    if profile == Profile::Qualification && workload_sha256 != QUALIFICATION_WORKLOAD_SHA256 {
        return Err(format!(
            "qualification workload digest drifted: expected {QUALIFICATION_WORKLOAD_SHA256}, got {workload_sha256}"
        ));
    }

    Ok((
        events,
        WorkloadMetrics {
            profile_version: WORKLOAD_PROFILE_VERSION,
            total_events: event_count,
            journal_event_ceiling: JOURNAL_EVENT_CEILING,
            journal_storage_ceiling_bytes: JOURNAL_STORAGE_CEILING_BYTES,
            progress_events,
            boundary_events,
            error_events,
            terminal_events: 1,
            input_json_bytes,
            committed_json_bytes: 0,
            workload_sha256,
        },
    ))
}

#[cfg(target_os = "linux")]
fn file_length(path: &Path) -> Result<u64, String> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn storage_metrics(root: &Path) -> Result<StorageMetrics, String> {
    let database_bytes = file_length(&root.join("journal.db"))?;
    let wal_bytes = file_length(&root.join("journal.db-wal"))?;
    let shm_bytes = file_length(&root.join("journal.db-shm"))?;
    let total_bytes = database_bytes
        .checked_add(wal_bytes)
        .and_then(|value| value.checked_add(shm_bytes))
        .ok_or_else(|| "journal storage byte count overflowed".to_string())?;
    Ok(StorageMetrics {
        database_bytes,
        wal_bytes,
        shm_bytes,
        total_bytes,
    })
}

#[cfg(target_os = "linux")]
fn validate_position_rewrite(
    producer_events: &[EventEnvelope],
    rewritten_events: &[EventEnvelope],
    description: &str,
) -> Result<(), String> {
    if rewritten_events.len() != producer_events.len() {
        return Err(format!(
            "{description} event count changed: expected {}, got {}",
            producer_events.len(),
            rewritten_events.len()
        ));
    }

    let mut durable_cursors = BTreeSet::new();
    for (index, (producer, rewritten)) in producer_events
        .iter()
        .zip(rewritten_events.iter())
        .enumerate()
    {
        let expected_sequence = u128::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| format!("{description} sequence overflow at index {index}"))?;
        if u128::from(rewritten.sequence) != expected_sequence {
            return Err(format!(
                "{description} sequence mismatch at index {index}: expected {expected_sequence}, got {}",
                rewritten.sequence
            ));
        }
        if !rewritten.checkpoint.durable
            || u128::from(rewritten.checkpoint.last_durable_sequence) != expected_sequence
        {
            return Err(format!(
                "{description} checkpoint mismatch at index {index}: expected durable sequence {expected_sequence}"
            ));
        }
        rewritten.validate_for_durable_stream().map_err(|error| {
            format!("{description} durable event validation failed at index {index}: {error}")
        })?;
        if !durable_cursors.insert(rewritten.cursor.as_str()) {
            return Err(format!(
                "{description} durable cursor is duplicated at index {index}"
            ));
        }

        // The journal API owns exactly these three fields. Normalize them back to the immutable
        // producer values so PartialEq checks every other EventEnvelope field without duplicating
        // that field list in this harness.
        let mut normalized = rewritten.clone();
        normalized.sequence = producer.sequence;
        normalized.cursor.clone_from(&producer.cursor);
        normalized.checkpoint = producer.checkpoint.clone();
        if &normalized != producer {
            return Err(format!(
                "{description} changed a producer-owned event field at index {index}"
            ));
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn run(arguments: &Arguments) -> Result<Sample, String> {
    let total_started = Instant::now();
    let build_started = Instant::now();
    let snapshot = final_snapshot()?;
    let (mut events, mut workload) = build_workload(arguments.profile, &snapshot)?;
    let producer_events = events.clone();
    let build_workload_ns = build_started.elapsed().as_nanos();

    let temporary = TempDir::new().map_err(|error| error.to_string())?;
    let journal_root = temporary.path().join("journal");
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&journal_root)
        .map_err(|error| error.to_string())?;

    let open_started = Instant::now();
    let journal = EventJournal::open(&journal_root).map_err(|error| error.to_string())?;
    let open_journal_ns = open_started.elapsed().as_nanos();

    let append_started = Instant::now();
    journal
        .append_complete_stream(&mut events, &snapshot)
        .map_err(|error| error.to_string())?;
    let append_complete_stream_ns = append_started.elapsed().as_nanos();
    validate_position_rewrite(&producer_events, &events, "assigned stream")?;

    let verify_started = Instant::now();
    let integrity = journal
        .verify_integrity()
        .map_err(|error| error.to_string())?;
    let verify_integrity_ns = verify_started.elapsed().as_nanos();
    if integrity.event_count != u64::try_from(arguments.profile.event_count()).unwrap_or(u64::MAX)
        || integrity.terminal_sequence != Some(integrity.event_count)
        || !integrity.has_terminal_snapshot()
    {
        return Err(format!("unexpected post-commit integrity: {integrity:?}"));
    }

    let read_started = Instant::now();
    let persisted = journal
        .read_all_validated(&TerminalEventExpectation::new(
            OutputStatus::Partial,
            ExitCode::Partial,
            OutputKind::ScanResult,
            snapshot.snapshot_digest(),
        ))
        .map_err(|error| error.to_string())?;
    let stored_snapshot = journal
        .read_final_snapshot()
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "terminal snapshot was not persisted".to_string())?;
    let read_and_validate_ns = read_started.elapsed().as_nanos();

    validate_position_rewrite(&producer_events, &persisted, "persisted stream")?;
    if persisted != events {
        return Err(
            "persisted stream differs from independently checked assigned stream".to_string(),
        );
    }
    if stored_snapshot != snapshot {
        return Err("persisted terminal snapshot differs from producer snapshot".to_string());
    }
    workload.committed_json_bytes = persisted.iter().try_fold(0_u64, |total, item| {
        let bytes = serde_json::to_vec(item)
            .map_err(|error| error.to_string())?
            .len();
        total
            .checked_add(u64::try_from(bytes).map_err(|error| error.to_string())?)
            .ok_or_else(|| "committed workload byte count overflowed".to_string())
    })?;

    let storage = storage_metrics(&journal_root)?;
    let total_ns = total_started.elapsed().as_nanos();
    Ok(Sample {
        schema: "sweepx.event-journal-runtime-sample/v1",
        profile: arguments.profile.name(),
        run_index: arguments.run_index,
        warmup: arguments.warmup,
        api: "EventJournal::append_complete_stream",
        measured_append_sqlite_transactions: 1,
        workload,
        timing: TimingMetrics {
            build_workload_ns,
            open_journal_ns,
            append_complete_stream_ns,
            verify_integrity_ns,
            read_and_validate_ns,
            total_ns,
        },
        storage,
        threshold: ThresholdObservation {
            metric: "appendCompleteStreamNs",
            target_ns: TRANSACTION_TARGET_NS,
            observed_ns: append_complete_stream_ns,
            met: append_complete_stream_ns <= TRANSACTION_TARGET_NS,
            enforced_by_harness: false,
        },
        correctness_verified: true,
        formal_qualification: false,
        scope_note: "Measures one post-scan complete-stream commit; it does not measure or qualify G-EVENT live delivery latency",
    })
}

#[cfg(target_os = "linux")]
fn main() {
    let arguments = parse_arguments().unwrap_or_else(|message| {
        eprintln!("{message}");
        std::process::exit(2);
    });
    let sample = run(&arguments).unwrap_or_else(|message| {
        eprintln!("runtime gate correctness failure: {message}");
        std::process::exit(1);
    });
    println!(
        "{}",
        serde_json::to_string(&sample).expect("serializing a runtime sample cannot fail")
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the event-journal runtime gate is Linux-only");
    std::process::exit(2);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn smoke_profile_verifies_durable_correctness_without_timing_assertion() {
        let sample = run(&Arguments {
            profile: Profile::Smoke,
            run_index: 1,
            warmup: false,
        })
        .unwrap();

        assert!(sample.correctness_verified);
        assert_eq!(sample.workload.total_events, SMOKE_EVENT_COUNT);
        assert_eq!(sample.workload.terminal_events, 1);
        assert_eq!(
            sample.workload.progress_events
                + sample.workload.boundary_events
                + sample.workload.error_events
                + 2,
            SMOKE_EVENT_COUNT
        );
        assert!(!sample.formal_qualification);
        // Wall-clock is reported for diagnostics, never asserted in an ordinary test.
        assert_eq!(sample.threshold.target_ns, TRANSACTION_TARGET_NS);
    }

    #[test]
    fn workload_is_byte_for_byte_deterministic() {
        let snapshot = final_snapshot().unwrap();
        let (_, first) = build_workload(Profile::Smoke, &snapshot).unwrap();
        let (_, second) = build_workload(Profile::Smoke, &snapshot).unwrap();

        assert_eq!(first.workload_sha256, second.workload_sha256);
        assert_eq!(first.input_json_bytes, second.input_json_bytes);
    }

    #[test]
    fn qualification_workload_contract_is_pinned() {
        let snapshot = final_snapshot().unwrap();
        let (_, workload) = build_workload(Profile::Qualification, &snapshot).unwrap();

        assert_eq!(workload.profile_version, WORKLOAD_PROFILE_VERSION);
        assert_eq!(workload.total_events, QUALIFICATION_EVENT_COUNT);
        assert_eq!(workload.journal_event_ceiling, JOURNAL_EVENT_CEILING);
        assert_eq!(
            workload.journal_storage_ceiling_bytes,
            JOURNAL_STORAGE_CEILING_BYTES
        );
        assert_eq!(workload.progress_events, 1_999);
        assert_eq!(workload.boundary_events, 31);
        assert_eq!(workload.error_events, 16);
        assert_eq!(workload.terminal_events, 1);
        assert_eq!(workload.input_json_bytes, 988_218);
        assert_eq!(workload.workload_sha256, QUALIFICATION_WORKLOAD_SHA256);
    }

    #[test]
    fn rewrite_oracle_rejects_immutable_and_position_changes() {
        let snapshot = final_snapshot().unwrap();
        let (producer, _) = build_workload(Profile::Smoke, &snapshot).unwrap();
        let mut assigned = producer.clone();
        for (index, event) in assigned.iter_mut().enumerate() {
            let sequence = u128::try_from(index + 1).unwrap();
            event.sequence = DecimalU128::new(sequence);
            event.cursor = format!("sxcur1.regression-cursor-{sequence:08}");
            event.checkpoint = EventCheckpoint {
                durable: true,
                last_durable_sequence: DecimalU128::new(sequence),
            };
        }
        validate_position_rewrite(&producer, &assigned, "regression fixture").unwrap();

        let mut immutable_tamper = assigned.clone();
        immutable_tamper[1].payload = serde_json::json!({"tampered": true});
        assert!(
            validate_position_rewrite(&producer, &immutable_tamper, "immutable tamper")
                .unwrap_err()
                .contains("producer-owned event field")
        );

        let mut sequence_tamper = assigned.clone();
        sequence_tamper[1].sequence = DecimalU128::new(99);
        assert!(
            validate_position_rewrite(&producer, &sequence_tamper, "sequence tamper")
                .unwrap_err()
                .contains("sequence mismatch")
        );

        let mut cursor_tamper = assigned;
        cursor_tamper[1].cursor = cursor_tamper[0].cursor.clone();
        assert!(
            validate_position_rewrite(&producer, &cursor_tamper, "cursor tamper")
                .unwrap_err()
                .contains("duplicated")
        );
    }
}
