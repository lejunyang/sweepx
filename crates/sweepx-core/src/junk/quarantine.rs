//! Explicitly approved, recoverable cleanup for stale Linux temporary objects.
//!
//! The report and this command share [`super::linux_temp`], so execution cannot reintroduce a
//! broader or narrower name/timestamp policy. Every target is copied to a private off-filesystem
//! quarantine, file data and directory entries are synchronized, the copy is verified, and only
//! then is the source removed. A failed or interrupted operation never becomes permanent deletion.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::json;

use super::linux_temp::{self, LinuxTempMeasurement};
use sweepx_platform::CancellationToken;
mod operation;
use operation::Operation;
pub use operation::QuarantineLimits;

const PLAN_SCHEMA: &str = "sweepx.temp-clean.plan/v3";
const RESULT_SCHEMA: &str = "sweepx.temp-clean.result/v3";
const COPY_IO_CHUNK: u64 = 32 * 1024 * 1024;
const MIN_FREE_SPACE_MARGIN: u128 = 1024 * 1024;

#[derive(Debug, Clone)]
/// One native stale-tmp candidate retained from the prefix-free discovery pass.
pub struct TempCleanInput {
    /// Native path reconstructed by Linux temporary-root discovery, not display text.
    pub path: PathBuf,
    /// Allocated bytes measured while capturing the report candidate.
    pub allocated_bytes: u128,
    /// Optional captured session facts. A matching allocation alone cannot bind a selected object.
    pub expected: Option<std::sync::Arc<LinuxTempMeasurement>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
/// Serialized display plan; native captures remain private in the opaque preview.
pub struct TempCleanPlanBody {
    /// Stable serialized plan schema.
    pub schema: &'static str,
    /// Recoverable quarantine mode; never a permanent deletion fallback.
    pub mode: &'static str,
    /// Digest of the loaded platform rule bytes, bound into confirmation and rechecked at execution.
    pub rule_bytes_digest: String,
    /// Display-only spelling of the hard-bound native temporary root.
    pub temp_root: String,
    /// Display-only recovery base; the preview retains its native path privately.
    pub quarantine_base: String,
    /// Lossless recovery-base bytes, bound into the digest even when its display spelling is lossy.
    pub quarantine_base_bytes: Vec<u8>,
    /// Required recursive idle interval.
    pub minimum_idle_seconds: u64,
    /// Current-user observation contract; not a system-wide snapshot.
    pub process_observation: &'static str,
    /// Residual evidence limitations retained in the plan.
    pub blockers: [&'static str; 1],
    /// Captured selected objects in stable plan order.
    pub candidates: Vec<TempCleanPlanItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
/// One display-only plan row and its digest-bound evidence.
pub struct TempCleanPlanItem {
    /// Display-only spelling, never execution authority.
    pub path: String,
    /// Lossless native path bytes in the serialized digest, not a reopen permit.
    pub path_bytes: Vec<u8>,
    /// Stable inode class code.
    pub inode_type: &'static str,
    /// Observed allocation, distinct from reclaimable space.
    pub allocated_bytes: String,
    /// Logical ordinary-file length.
    pub logical_bytes: String,
    /// Observed inode count.
    pub entry_count: u64,
    /// Native filesystem device at capture.
    pub device: String,
    /// Native object inode at capture.
    pub inode: String,
    /// Captured owner user ID.
    pub owner_uid: String,
    /// Captured owner group ID.
    pub owner_gid: String,
    /// Captured native permission and type bits.
    pub mode: u32,
    /// Captured top-object modification seconds.
    pub modified_unix_seconds: i64,
    /// Captured top-object modification subsecond fraction.
    pub modified_nanoseconds: i64,
    /// Captured top-object inode change seconds.
    pub status_change_unix_seconds: i64,
    /// Captured top-object inode change subsecond fraction.
    pub status_change_nanoseconds: i64,
    /// Latest recursive access seconds.
    pub recursive_last_access_seconds: i64,
    /// Latest recursive access subsecond fraction.
    pub recursive_last_access_nanoseconds: u32,
    /// Latest recursive activity seconds.
    pub recursive_last_activity_seconds: i64,
    /// Latest recursive activity subsecond fraction.
    pub recursive_last_activity_nanoseconds: u32,
}

#[derive(Debug, Clone)]
struct CapturedCandidate {
    path: PathBuf,
    measurement: LinuxTempMeasurement,
}

#[derive(Debug)]
struct PreparedQuarantine {
    run_dir: PathBuf,
    metadata: std::fs::Metadata,
    outcomes: File,
}

/// An invocation-local preview with private captures. Display plans/digests cannot recreate it.
/// Execution consumes it once and independently reobserves the source and recovery boundaries.
pub struct TempCleanPreview {
    plan: TempCleanPlanBody,
    digest: String,
    captures: Vec<CapturedCandidate>,
    quarantine_base: PathBuf,
    allocated_bytes: u128,
    limits: QuarantineLimits,
}

impl TempCleanPreview {
    /// Display-only plan, including selected native identity facts and remaining blockers.
    pub fn plan(&self) -> &TempCleanPlanBody {
        &self.plan
    }
    /// Full canonical digest that must be confirmed; a prefix or attention fingerprint is insufficient.
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Sum of measured allocation, never a guarantee of reclaimed space.
    pub fn allocated_bytes(&self) -> u128 {
        self.allocated_bytes
    }
}

/// Execution observations; failure can leave a verified recovery copy and a partial source tree.
pub struct TempCleanExecution {
    /// Canonical digest of the confirmed plan.
    pub digest: String,
    /// Native directory containing the durable plan, outcomes and recovery objects.
    pub recovery_directory: PathBuf,
    /// Confirmed transitions as source, destination and previously measured allocation.
    pub moved: Vec<(PathBuf, PathBuf, u128)>,
    /// First failure, with source/destination reconciliation; later objects were not attempted.
    pub failure: Option<(PathBuf, String)>,
}

/// Refuses broader filesystem authority and unknown runtime capability evidence.
pub fn ensure_unprivileged() -> Result<(), String> {
    // SAFETY: geteuid has no preconditions. No caller-supplied UID can replace runtime evidence.
    if unsafe { libc::geteuid() } == 0 || linux_process_has_capabilities() {
        Err("temporary cleanup is disabled for root or capability-bearing processes".into())
    } else {
        Ok(())
    }
}

fn loaded_rule_digest() -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes())
    )
}

/// Reobserves selected objects without creating a recovery directory or touching source names.
/// Product execution is hard-bound to real /tmp; report fixture overrides never authorize mutation.
pub fn preview_temp_clean(
    inputs: &[TempCleanInput],
    explicit_quarantine: Option<&Path>,
    discovery_complete: bool,
    cancel: &CancellationToken,
) -> Result<TempCleanPreview, String> {
    preview_temp_clean_with_limits(
        inputs,
        explicit_quarantine,
        discovery_complete,
        cancel,
        QuarantineLimits::default(),
    )
}

/// Creates a preview with caller-supplied bounds, retained for its separately confirmed execution.
/// Bounds can only restrict work; they do not waive native eligibility or identity checks.
pub fn preview_temp_clean_with_limits(
    inputs: &[TempCleanInput],
    explicit_quarantine: Option<&Path>,
    discovery_complete: bool,
    cancel: &CancellationToken,
    limits: QuarantineLimits,
) -> Result<TempCleanPreview, String> {
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    ensure_unprivileged()?;
    if !discovery_complete {
        return Err("cleanup plan refused: the /tmp report was truncated or incomplete".into());
    }
    if inputs.is_empty() || inputs.len() > 256 {
        return Err("select 1..256 temporary objects per plan".into());
    }
    let root = Path::new("/tmp");
    let mut operation = Operation::new(cancel.clone(), limits)?;
    let base = resolve_quarantine_base(explicit_quarantine)?;
    operation.admit_path(&base)?;
    let captures = capture_all(inputs, root, &mut operation)?;
    let plan = plan_body(&captures, root, &base);
    let digest = sweepx_canonical::plan_digest_hex(&plan)
        .map_err(|error| format!("could not digest cleanup plan: {error}"))?;
    let allocated_bytes = captures
        .iter()
        .try_fold(0u128, |sum, row| {
            sum.checked_add(row.measurement.allocated_bytes)
        })
        .ok_or_else(|| "candidate byte total overflowed".to_string())?;
    operation.check()?;
    Ok(TempCleanPreview {
        plan,
        digest,
        captures,
        quarantine_base: base,
        allocated_bytes,
        limits,
    })
}

/// Executes only the exact, explicitly confirmed opaque preview. Never falls back to deletion.
/// Native I/O remains cooperatively cancellable. A failure retains available recovery material.
pub fn execute_temp_clean(
    preview: TempCleanPreview,
    confirmation: &str,
    cancel: &CancellationToken,
) -> Result<TempCleanExecution, String> {
    if confirmation.len() > 256 || confirmation.trim() != format!("clean {}", preview.digest) {
        return Err("exact plan confirmation required".into());
    }
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    ensure_unprivileged()?;
    if loaded_rule_digest() != preview.plan.rule_bytes_digest {
        return Err("loaded rules changed after preview".into());
    }
    let TempCleanPreview {
        captures,
        plan,
        digest,
        quarantine_base,
        limits,
        ..
    } = preview;
    let temp_root = Path::new("/tmp");
    let mut operation = Operation::new(cancel.clone(), limits)?;
    operation.admit_path(&quarantine_base)?;
    revalidate_all(&captures, temp_root, &mut operation)?;
    if cancel.is_cancelled() {
        return Err("cancelled".into());
    }
    let mut quarantine = prepare_quarantine(&quarantine_base, temp_root, &plan, &digest)?;
    execute_captures(captures, &mut quarantine, temp_root, digest, &mut operation)
}

fn execute_captures(
    captures: Vec<CapturedCandidate>,
    quarantine: &mut PreparedQuarantine,
    temp_root: &Path,
    digest: String,
    operation: &mut Operation,
) -> Result<TempCleanExecution, String> {
    let mut moved = Vec::new();
    let mut failure = None;
    for captured in captures {
        if let Err(error) = operation.check() {
            failure = Some((captured.path.clone(), error));
            break;
        }
        if let Err(error) = revalidate_candidate(&captured, temp_root, operation) {
            failure = Some((captured.path.clone(), error));
            break;
        }
        if let Err(error) = verify_quarantine_identity(quarantine) {
            failure = Some((captured.path.clone(), error));
            break;
        }
        let destination = quarantine.run_dir.join(
            captured
                .path
                .file_name()
                .expect("captured temp child has a basename"),
        );
        if destination.try_exists().unwrap_or(true) {
            failure = Some((
                captured.path.clone(),
                format!(
                    "quarantine destination already exists: {}",
                    destination.display()
                ),
            ));
            break;
        }
        if let Err(error) = require_quarantine_space(
            &quarantine.run_dir,
            captured
                .measurement
                .allocated_bytes
                .max(captured.measurement.logical_bytes),
        ) {
            failure = Some((captured.path.clone(), error));
            break;
        }
        if let Err(error) = append_outcome(
            &mut quarantine.outcomes,
            &digest,
            &captured.path,
            &destination,
            "reserved",
            None,
        ) {
            failure = Some((captured.path.clone(), error));
            break;
        }
        match move_to_quarantine(
            &captured.path,
            &destination,
            temp_root,
            &captured.measurement,
            operation,
        ) {
            Ok(()) if !path_is_present(&captured.path) && path_is_present(&destination) => {
                if let Err(error) = append_outcome(
                    &mut quarantine.outcomes,
                    &digest,
                    &captured.path,
                    &destination,
                    "moved",
                    None,
                ) {
                    failure = Some((captured.path.clone(), error));
                    break;
                }
                moved.push((
                    captured.path,
                    destination,
                    captured.measurement.allocated_bytes,
                ));
            }
            Ok(()) => {
                failure = Some((
                    captured.path.clone(),
                    "move returned success without one source-to-quarantine transition".to_string(),
                ));
                break;
            }
            Err(error) => {
                let source_present = path_is_present(&captured.path);
                let destination_present = path_is_present(&destination);
                let reconciliation = match (source_present, destination_present) {
                    (true, true) => "source_and_destination_exist",
                    (true, false) => "source_only",
                    (false, true) => "destination_only_unconfirmed",
                    (false, false) => "source_and_destination_missing",
                };
                let detail = format!("{error}; reconciliation={reconciliation}");
                let _ = append_outcome(
                    &mut quarantine.outcomes,
                    &digest,
                    &captured.path,
                    &destination,
                    "failed",
                    Some(&detail),
                );
                failure = Some((captured.path.clone(), detail));
                break;
            }
        }
    }

    Ok(TempCleanExecution {
        digest,
        recovery_directory: quarantine.run_dir.clone(),
        moved,
        failure,
    })
}

fn linux_process_has_capabilities() -> bool {
    let mut status = String::new();
    let result = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open("/proc/self/status")
        .and_then(|file| file.take(128 * 1024 + 1).read_to_string(&mut status));
    if result.is_err() || status.len() > 128 * 1024 {
        return true;
    }
    ["CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .map(|key| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::trim)
        })
        // A missing runtime fact cannot prove the process is unprivileged.
        .any(|value| {
            value.is_none_or(|value| value.is_empty() || value.bytes().any(|byte| byte != b'0'))
        })
}

fn capture_all(
    inputs: &[TempCleanInput],
    temp_root: &Path,
    operation: &mut Operation,
) -> Result<Vec<CapturedCandidate>, String> {
    let mut observation = native_observation(operation);
    let mut captures = Vec::with_capacity(inputs.len());
    let mut seen = std::collections::BTreeSet::new();
    for input in inputs {
        operation.admit_path(&input.path)?;
        if !seen.insert(input.path.clone()) {
            return Err("duplicate selected temporary object".into());
        }
        let measurement =
            linux_temp::validate_observed(&input.path, temp_root, &mut observation, false, true)?;
        bind_selected_measurement(input, &measurement)?;
        for relative in measurement.entries.keys() {
            operation.admit_path(relative)?;
        }
        captures.push(CapturedCandidate {
            path: input.path.clone(),
            measurement,
        });
    }
    Ok(captures)
}

fn bind_selected_measurement(
    input: &TempCleanInput,
    measurement: &LinuxTempMeasurement,
) -> Result<(), String> {
    if input
        .expected
        .as_ref()
        .is_some_and(|expected| **expected != *measurement)
    {
        return Err(format!(
            "{} changed identity or activity after selection",
            input.path.display()
        ));
    }
    if measurement.allocated_bytes != input.allocated_bytes {
        return Err(format!(
            "{} changed allocated size after report capture",
            input.path.display()
        ));
    }
    Ok(())
}

fn native_observation(operation: &Operation) -> linux_temp::Observation {
    let limits = operation.limits();
    let native = linux_temp::LinuxTempObservationLimits::default();
    linux_temp::Observation::new(
        operation.deadline(),
        operation.cancel(),
        linux_temp::LinuxTempObservationLimits {
            max_observations: native.max_observations.min(limits.max_path_visits),
            max_retained_bytes: native.max_retained_bytes.min(limits.max_retained_bytes),
            ..native
        },
    )
}

fn revalidate_all(
    captures: &[CapturedCandidate],
    temp_root: &Path,
    operation: &mut Operation,
) -> Result<(), String> {
    let mut observation = native_observation(operation);
    for captured in captures {
        operation.admit_path(&captured.path)?;
        let current = linux_temp::validate_observed(
            &captured.path,
            temp_root,
            &mut observation,
            false,
            true,
        )?;
        if current != captured.measurement {
            return Err("selected source changed after plan capture".into());
        }
    }
    Ok(())
}

fn revalidate_candidate(
    captured: &CapturedCandidate,
    temp_root: &Path,
    operation: &mut Operation,
) -> Result<(), String> {
    operation.check()?;
    let current = linux_temp::validate_observed(
        &captured.path,
        temp_root,
        &mut native_observation(operation),
        false,
        true,
    )?;
    if current != captured.measurement {
        return Err(format!(
            "{} changed size, identity, activity timestamp, or tree shape after plan capture",
            captured.path.display()
        ));
    }
    Ok(())
}

fn inode_type(metadata: &std::fs::Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "regular_file"
    } else if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_socket() {
        "unix_socket"
    } else if file_type.is_fifo() {
        "named_pipe"
    } else {
        "unsupported"
    }
}

fn timestamp_epoch(timestamp: SystemTime) -> std::time::Duration {
    timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
}

fn plan_body(
    captures: &[CapturedCandidate],
    temp_root: &Path,
    quarantine_base: &Path,
) -> TempCleanPlanBody {
    let candidates = captures
        .iter()
        .map(|candidate| {
            let metadata = &candidate.measurement.top;
            let accessed = timestamp_epoch(candidate.measurement.last_accessed);
            let modified = timestamp_epoch(candidate.measurement.last_modified);
            let status_change = timestamp_epoch(candidate.measurement.last_status_change);
            let last_activity = accessed.max(modified).max(status_change);
            TempCleanPlanItem {
                path: candidate.path.display().to_string(),
                path_bytes: candidate.path.as_os_str().as_bytes().to_vec(),
                inode_type: inode_type(metadata),
                allocated_bytes: candidate.measurement.allocated_bytes.to_string(),
                logical_bytes: candidate.measurement.logical_bytes.to_string(),
                entry_count: candidate.measurement.entry_count,
                device: metadata.dev().to_string(),
                inode: metadata.ino().to_string(),
                owner_uid: metadata.uid().to_string(),
                owner_gid: metadata.gid().to_string(),
                mode: metadata.mode(),
                modified_unix_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                status_change_unix_seconds: metadata.ctime(),
                status_change_nanoseconds: metadata.ctime_nsec(),
                recursive_last_access_seconds: accessed.as_secs() as i64,
                recursive_last_access_nanoseconds: accessed.subsec_nanos(),
                recursive_last_activity_seconds: last_activity.as_secs() as i64,
                recursive_last_activity_nanoseconds: last_activity.subsec_nanos(),
            }
        })
        .collect();
    TempCleanPlanBody {
        schema: PLAN_SCHEMA,
        mode: "recoverable_quarantine",
        rule_bytes_digest: loaded_rule_digest(),
        temp_root: temp_root.display().to_string(),
        quarantine_base: quarantine_base.display().to_string(),
        quarantine_base_bytes: quarantine_base.as_os_str().as_bytes().to_vec(),
        minimum_idle_seconds: linux_temp::MIN_IDLE.as_secs(),
        process_observation: "current_user_proc_per_network_namespace_unix_sockets",
        blockers: [linux_temp::REFERENCE_BLOCKER],
        candidates,
    }
}

fn resolve_quarantine_base(explicit: Option<&Path>) -> Result<PathBuf, String> {
    let requested = match explicit {
        Some(path) => {
            if path.as_os_str().len() > 64 * 1024 {
                return Err("quarantine path exceeds 64 KiB".into());
            }
            path.to_path_buf()
        }
        None => {
            let data_home = std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .or_else(|| {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .filter(|path| path.is_absolute())
                        .map(|home| home.join(".local/share"))
                })
                .ok_or_else(|| {
                    "no absolute --quarantine-dir, XDG_DATA_HOME, or HOME is available".to_string()
                })?;
            data_home.join("sweepx/quarantine")
        }
    };
    if !requested.is_absolute() {
        return Err("--quarantine-dir must be absolute".to_string());
    }
    if requested.as_os_str().len() > 64 * 1024 {
        return Err("quarantine path exceeds 64 KiB".into());
    }
    Ok(requested)
}

fn prepare_quarantine(
    base: &Path,
    temp_root: &Path,
    plan: &TempCleanPlanBody,
    digest: &str,
) -> Result<PreparedQuarantine, String> {
    use std::os::unix::fs::PermissionsExt;

    ensure_no_symlink_ancestors(base)?;
    if !base.exists() {
        fs::create_dir_all(base).map_err(|error| format!("create {}: {error}", base.display()))?;
        fs::set_permissions(base, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect {}: {error}", base.display()))?;
    }
    let base_metadata = fs::symlink_metadata(base)
        .map_err(|error| format!("inspect {}: {error}", base.display()))?;
    let current_uid = unsafe { libc::geteuid() };
    if !base_metadata.is_dir()
        || base_metadata.uid() != current_uid
        || base_metadata.mode() & 0o777 != 0o700
    {
        return Err(format!(
            "{} is not a private owned directory",
            base.display()
        ));
    }
    let temp_metadata = fs::symlink_metadata(temp_root)
        .map_err(|error| format!("inspect {}: {error}", temp_root.display()))?;
    if base_metadata.dev() == temp_metadata.dev() {
        return Err(
            "quarantine is on the same filesystem as /tmp and would not reclaim root-disk space"
                .to_string(),
        );
    }

    let run_dir = base.join(format!("linux-temp-{}", &digest[..16]));
    fs::create_dir(&run_dir).map_err(|error| format!("create {}: {error}", run_dir.display()))?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect {}: {error}", run_dir.display()))?;
    let metadata = fs::symlink_metadata(&run_dir)
        .map_err(|error| format!("inspect {}: {error}", run_dir.display()))?;

    let manifest_path = run_dir.join("plan.json");
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&manifest_path)
        .map_err(|error| format!("create {}: {error}", manifest_path.display()))?;
    let manifest_value = json!({
        "plan": plan,
        "canonicalDigest": digest,
        "recoverable": true,
        "permanentFallback": false,
    });
    serde_json::to_writer_pretty(&mut manifest, &manifest_value)
        .map_err(|error| format!("write {}: {error}", manifest_path.display()))?;
    manifest
        .write_all(b"\n")
        .and_then(|()| manifest.sync_all())
        .map_err(|error| format!("sync {}: {error}", manifest_path.display()))?;

    let outcomes_path = run_dir.join("outcomes.jsonl");
    let outcomes = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(&outcomes_path)
        .map_err(|error| format!("create {}: {error}", outcomes_path.display()))?;
    File::open(&run_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync {}: {error}", run_dir.display()))?;
    Ok(PreparedQuarantine {
        run_dir,
        metadata,
        outcomes,
    })
}

fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "quarantine path traverses symlink {}",
                    current.display()
                ));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(format!(
                    "quarantine ancestor is not a directory: {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("inspect {}: {error}", current.display())),
        }
    }
    Ok(())
}

fn verify_quarantine_identity(quarantine: &PreparedQuarantine) -> Result<(), String> {
    let current = fs::symlink_metadata(&quarantine.run_dir)
        .map_err(|error| format!("inspect {}: {error}", quarantine.run_dir.display()))?;
    if current.dev() != quarantine.metadata.dev()
        || current.ino() != quarantine.metadata.ino()
        || !current.file_type().is_dir()
    {
        return Err("quarantine directory identity changed".to_string());
    }
    Ok(())
}

fn require_quarantine_space(quarantine: &Path, bytes_to_copy: u128) -> Result<(), String> {
    let available = available_bytes(quarantine)?;
    // A filesystem without SEEK_DATA falls back to a full logical copy, so sparse logical bytes
    // must be included by callers rather than discovered only after filling the volume.
    let margin = bytes_to_copy / 20 + MIN_FREE_SPACE_MARGIN;
    let required = bytes_to_copy
        .checked_add(margin)
        .ok_or("space requirement overflowed")?;
    if available < required {
        return Err(format!(
            "quarantine has {available} bytes available but this copy requires {required}"
        ));
    }
    Ok(())
}

fn path_is_present(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn available_bytes(path: &Path) -> Result<u128, String> {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    if bytes.contains(&0) {
        return Err("quarantine path contains NUL".to_string());
    }
    bytes.push(0);
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated and the statvfs storage has the correct size/alignment.
    let result = unsafe { libc::statvfs(bytes.as_ptr().cast(), &mut stat) };
    if result != 0 {
        return Err(format!(
            "statvfs {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(u128::from(stat.f_bavail).saturating_mul(u128::from(stat.f_frsize)))
}

fn move_to_quarantine(
    source: &Path,
    destination: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
    operation: &mut Operation,
) -> Result<(), String> {
    move_to_quarantine_impl(source, destination, temp_root, expected, false, operation)
}

#[cfg(test)]
fn move_to_quarantine_for_test(
    source: &Path,
    destination: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
) -> Result<(), String> {
    move_to_quarantine_impl(
        source,
        destination,
        temp_root,
        expected,
        true,
        &mut test_operation(),
    )
}

fn move_to_quarantine_impl(
    source: &Path,
    destination: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
    allow_test_seams: bool,
    operation: &mut Operation,
) -> Result<(), String> {
    operation.admit_path(source)?;
    operation.admit_path(destination)?;
    let mut observation = native_observation(operation);
    let prepared = linux_temp::prepare_symlink_copy_observed(
        source,
        temp_root,
        expected,
        allow_test_seams,
        &mut observation,
    )?;
    copy_tree_observed(
        source,
        destination,
        Path::new(""),
        &prepared.targets,
        operation,
    )?;
    verify_copied_tree_observed(
        source,
        destination,
        Path::new(""),
        &prepared.targets,
        operation,
    )?;

    // Copying can take a long time. Repeat the full shared eligibility check before the source is
    // removed, so a process that reopened the object after the pre-copy check is not displaced.
    let current = linux_temp::validate_observed(
        source,
        temp_root,
        &mut observation,
        allow_test_seams,
        false,
    )?;
    if current != prepared.measurement {
        return Err("source changed during durable copy; it was left in place".to_string());
    }
    // The complete destination tree and its root directory entry must be durable before the
    // source namespace is touched. Syncing only after removal would make crash recovery depend on
    // a write that had not reached the recovery filesystem yet.
    sync_parent(destination)?;
    operation.check()?;
    remove_tree_verified_observed(source, temp_root, &prepared.measurement, operation)?;
    // Failure here cannot resurrect the verified source path or invalidate the durable
    // destination; treating it as a move failure would record a successful quarantine as failed.
    let _ = sync_parent(source);
    Ok(())
}

fn copy_tree_observed(
    source: &Path,
    destination: &Path,
    relative: &Path,
    symlink_targets: &BTreeMap<PathBuf, PathBuf>,
    operation: &mut Operation,
) -> Result<(), String> {
    operation.admit_path(source)?;
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("inspect source {}: {error}", source.display()))?;
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        copy_directory(
            source,
            destination,
            relative,
            &metadata,
            symlink_targets,
            operation,
        )
    } else if file_type.is_file() {
        copy_regular_file_observed(source, destination, &metadata, operation)
    } else if file_type.is_symlink() {
        copy_cached_symlink(source, destination, relative, &metadata, symlink_targets)
    } else if file_type.is_socket() {
        // A stale socket has no payload. Bind without listen merely recreates the filesystem
        // object; it must not present a newly accepting service during recovery.
        bind_unix_socket(destination)?;
        finalize_non_file_metadata(destination, &metadata, true)
    } else if file_type.is_fifo() {
        create_fifo(source, destination, &metadata)
    } else {
        Err(format!("unsupported inode type at {}", source.display()))
    }
}

fn copy_directory(
    source: &Path,
    destination: &Path,
    relative: &Path,
    metadata: &std::fs::Metadata,
    symlink_targets: &BTreeMap<PathBuf, PathBuf>,
    operation: &mut Operation,
) -> Result<(), String> {
    let mut observation = native_observation(operation);
    fs::create_dir(destination)
        .map_err(|error| format!("create directory {}: {error}", destination.display()))?;

    enum Job {
        Enter(PathBuf, PathBuf, PathBuf),
        Finish(PathBuf, PathBuf, std::fs::Metadata),
    }

    // Deep temp trees must not spend the main thread stack on one frame per directory.
    let mut jobs = vec![
        Job::Finish(
            source.to_path_buf(),
            destination.to_path_buf(),
            metadata.clone(),
        ),
        Job::Enter(
            source.to_path_buf(),
            destination.to_path_buf(),
            relative.to_path_buf(),
        ),
    ];
    while let Some(job) = jobs.pop() {
        operation.check()?;
        match job {
            Job::Enter(source_dir, destination_dir, directory_relative) => {
                let child_names =
                    linux_temp::read_dir_names_no_atime_observed(&source_dir, &mut observation)
                        .map_err(|error| format!("enumerate {}: {error}", source_dir.display()))?;
                for child_name in child_names {
                    let child_source = source_dir.join(&child_name);
                    operation.admit_path(&child_source)?;
                    let child_destination = destination_dir.join(&child_name);
                    let mut child_relative = directory_relative.clone();
                    child_relative.push(&child_name);
                    operation.admit_path(&child_destination)?;
                    operation.admit_path(&child_relative)?;
                    let child_metadata = fs::symlink_metadata(&child_source).map_err(|error| {
                        format!("inspect source {}: {error}", child_source.display())
                    })?;
                    if child_metadata.file_type().is_dir() {
                        operation.admit_path(&child_source)?;
                        operation.admit_path(&child_destination)?;
                        fs::create_dir(&child_destination).map_err(|error| {
                            format!("create directory {}: {error}", child_destination.display())
                        })?;
                        jobs.push(Job::Finish(
                            child_source.clone(),
                            child_destination.clone(),
                            child_metadata,
                        ));
                        jobs.push(Job::Enter(child_source, child_destination, child_relative));
                    } else {
                        copy_tree_observed(
                            &child_source,
                            &child_destination,
                            &child_relative,
                            symlink_targets,
                            operation,
                        )?;
                    }
                }
            }
            Job::Finish(source_dir, destination_dir, directory_metadata) => {
                finalize_non_file_metadata(&destination_dir, &directory_metadata, true)?;
                sync_directory(&destination_dir)?;
                let _ = source_dir;
            }
        }
    }
    Ok(())
}

fn copy_regular_file_observed(
    source: &Path,
    destination: &Path,
    metadata: &std::fs::Metadata,
    operation: &mut Operation,
) -> Result<(), String> {
    operation.check()?;
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let opened = input
        .metadata()
        .map_err(|error| format!("inspect opened source: {error}"))?;
    if !opened.is_file()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() != metadata.len()
        || opened.mtime() != metadata.mtime()
        || opened.mtime_nsec() != metadata.mtime_nsec()
        || opened.ctime() != metadata.ctime()
        || opened.ctime_nsec() != metadata.ctime_nsec()
    {
        return Err("source changed before copy".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)
        .map_err(|error| format!("create destination {}: {error}", destination.display()))?;

    let length = metadata.len();
    if let Err(error) = copy_allocated_ranges(&mut input, &mut output, length, operation) {
        // Filesystems without SEEK_DATA/SEEK_HOLE fall back to a full logical copy. ENOSPC still
        // fails before source removal; the conservative allocation estimate is an optimization,
        // not a safety boundary.
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::EXDEV | libc::EOPNOTSUPP | libc::ENOSYS)
        ) {
            return Err(format!(
                "copy allocated ranges {}: {error}",
                source.display()
            ));
        }
        input
            .rewind()
            .map_err(|error| format!("rewind {}: {error}", source.display()))?;
        output
            .rewind()
            .map_err(|error| format!("rewind {}: {error}", destination.display()))?;
        operation::copy_stream(&mut input, &mut output, length, operation)
            .map_err(|error| format!("copy {}: {error}", source.display()))?;
    } else {
        // Allocated ranges preserve data extents; this only records trailing logical holes.
        output.set_len(length).map_err(|error| {
            format!("finalize sparse length {}: {error}", destination.display())
        })?;
    }
    operation.check()?;
    output
        .sync_all()
        .map_err(|error| format!("fsync data {}: {error}", destination.display()))?;
    finalize_open_file(&output, metadata)?;
    output
        .sync_all()
        .map_err(|error| format!("fsync metadata {}: {error}", destination.display()))?;
    sync_parent(destination)?;
    Ok(())
}

fn copy_allocated_ranges(
    input: &mut File,
    output: &mut File,
    length: u64,
    operation: &mut Operation,
) -> io::Result<()> {
    match copy_ranges_with_copy_file_range(input, output, length, operation) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            // copy_file_range can refuse cross-filesystem copies even when both filesystems support
            // SEEK_DATA/SEEK_HOLE. Copy only the allocated extents with ordinary pread/pwrite so the
            // destination remains sparse and the allocated-byte space estimate stays valid.
            return copy_ranges_with_read_write(input, output, length, operation);
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

fn copy_ranges_with_copy_file_range(
    input: &File,
    output: &File,
    length: u64,
    operation: &mut Operation,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut offset = 0u64;
    while offset < length {
        operation.check().map_err(io::Error::other)?;
        let data = match seek_data(input.as_raw_fd(), offset) {
            Ok(data) => data,
            // ENXIO means there is no allocated extent at or after offset: the remainder is a
            // hole. Falling back to a logical read here would allocate zeros on the destination.
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => break,
            Err(error) => return Err(error),
        };
        if data >= length {
            break;
        }
        let hole = seek_hole(input.as_raw_fd(), data)?
            .unwrap_or(length)
            .min(length);
        if hole <= data {
            return Err(io::Error::other("source extent did not advance"));
        }
        let mut range_offset = data;
        while range_offset < hole {
            let length_limit = hole.saturating_sub(range_offset).min(COPY_IO_CHUNK);
            operation.io(length_limit)?;
            let mut input_offset = range_offset as i64;
            let mut output_offset = range_offset as i64;
            let copied = unsafe {
                libc::copy_file_range(
                    input.as_raw_fd(),
                    &mut input_offset,
                    output.as_raw_fd(),
                    &mut output_offset,
                    length_limit as usize,
                    0,
                )
            };
            if copied < 0 {
                return Err(io::Error::last_os_error());
            }
            if copied == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "copy ended early",
                ));
            }
            range_offset = u64::try_from(output_offset).unwrap_or(length);
        }
        offset = hole.max(data.saturating_add(1));
    }
    Ok(())
}

fn copy_ranges_with_read_write(
    input: &mut File,
    output: &mut File,
    length: u64,
    operation: &mut Operation,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let mut offset = 0u64;
    while offset < length {
        operation.check().map_err(io::Error::other)?;
        let data = match seek_data(input.as_raw_fd(), offset) {
            Ok(data) => data,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => break,
            Err(error) => return Err(error),
        };
        if data >= length {
            break;
        }
        let hole = seek_hole(input.as_raw_fd(), data)?
            .unwrap_or(length)
            .min(length);
        if hole <= data {
            return Err(io::Error::other("source extent did not advance"));
        }
        let mut range_remaining = hole - data;
        input.seek(io::SeekFrom::Start(data))?;
        output.seek(io::SeekFrom::Start(data))?;
        while range_remaining > 0 {
            let copied = range_remaining.min(COPY_IO_CHUNK);
            operation::copy_stream(input, output, copied, operation)?;
            range_remaining -= copied;
        }
        offset = hole.max(data.saturating_add(1));
    }
    Ok(())
}

fn seek_data(fd: i32, offset: u64) -> io::Result<u64> {
    let result = unsafe { libc::lseek64(fd, offset as i64, libc::SEEK_DATA) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result as u64)
}

fn seek_hole(fd: i32, offset: u64) -> io::Result<Option<u64>> {
    let result = unsafe { libc::lseek64(fd, offset as i64, libc::SEEK_HOLE) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(result as u64))
}

fn copy_cached_symlink(
    source: &Path,
    destination: &Path,
    relative: &Path,
    metadata: &std::fs::Metadata,
    symlink_targets: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), String> {
    let target = symlink_target(relative, symlink_targets, source)?;
    std::os::unix::fs::symlink(target, destination)
        .map_err(|error| format!("create symlink {}: {error}", destination.display()))?;
    finalize_non_file_metadata(destination, metadata, false)?;
    sync_parent(destination)
}

fn symlink_target<'a>(
    relative: &Path,
    symlink_targets: &'a BTreeMap<PathBuf, PathBuf>,
    source: &Path,
) -> Result<&'a Path, String> {
    symlink_targets
        .get(relative)
        .map(PathBuf::as_path)
        .ok_or_else(|| format!("missing captured symlink target for {}", source.display()))
}

fn bind_unix_socket(path: &Path) -> Result<(), String> {
    use std::os::unix::io::FromRawFd;

    let bytes = path.as_os_str().as_bytes();
    // SAFETY: SOCK_CLOEXEC prevents descriptor inheritance; the fd is closed in all paths.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "create recovery socket: {}",
            io::Error::last_os_error()
        ));
    }
    let socket = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err(format!("socket path is too long: {}", path.display()));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr().cast::<libc::c_char>(),
            address.sun_path.as_mut_ptr().cast(),
            bytes.len(),
        );
    }
    let address_length = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    let result = unsafe {
        libc::bind(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            address_length as libc::socklen_t,
        )
    };
    drop(socket);
    if result != 0 {
        return Err(format!(
            "recreate socket {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn create_fifo(
    source: &Path,
    destination: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), String> {
    let path = c_path(destination)?;
    // SAFETY: the destination path is NUL-terminated and create_new semantics prevent replacing
    // an existing recovery entry.
    if unsafe { libc::mkfifo(path.as_ptr().cast(), metadata.mode() & 0o7777) } != 0 {
        return Err(format!(
            "recreate FIFO {} from {}: {}",
            destination.display(),
            source.display(),
            io::Error::last_os_error()
        ));
    }
    finalize_non_file_metadata(destination, metadata, true)?;
    sync_parent(destination)
}

fn finalize_open_file(file: &File, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    sync_destination_group(fd, metadata.gid())?;
    // Restore mode after chown because a successful group change can clear set-user/group bits.
    // SAFETY: fd is an open regular file owned by this function.
    if unsafe { libc::fchmod(fd, metadata.mode() & 0o7777) } != 0 {
        return Err(format!(
            "fchmod destination: {}",
            io::Error::last_os_error()
        ));
    }
    let times = [
        timespec(metadata.atime(), metadata.atime_nsec()),
        timespec(metadata.mtime(), metadata.mtime_nsec()),
    ];
    // SAFETY: fd is open and the timespec array has exactly two entries.
    if unsafe { libc::futimens(fd, times.as_ptr()) } != 0 {
        return Err(format!(
            "futimens destination: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn finalize_non_file_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    restore_mode: bool,
) -> Result<(), String> {
    let c_path = c_path(path)?;
    sync_destination_path_group(&c_path, path, metadata.gid())?;
    if restore_mode {
        // SAFETY: path is NUL-terminated. Symlink mode is platform-defined and intentionally
        // excluded; directories and stale sockets do have meaningful file modes.
        let mode = metadata.mode() & 0o7777;
        if unsafe { libc::fchmodat(libc::AT_FDCWD, c_path.as_ptr().cast(), mode, 0) } != 0 {
            return Err(format!(
                "fchmodat {}: {}",
                path.display(),
                io::Error::last_os_error()
            ));
        }
    }
    let times = [
        timespec(metadata.atime(), metadata.atime_nsec()),
        timespec(metadata.mtime(), metadata.mtime_nsec()),
    ];
    // SAFETY: path and times are valid for the call; NOFOLLOW prevents symlink target mutation.
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c_path.as_ptr().cast(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(format!(
            "utimensat {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn current_gid() -> u32 {
    // SAFETY: getegid has no preconditions and only reads process credentials.
    unsafe { libc::getegid() }
}

fn sync_destination_group(fd: i32, source_gid: u32) -> Result<(), String> {
    if source_gid == current_gid() {
        return Ok(());
    }
    // Every source inode is owned by the invoking euid, so destination uid never changes. An
    // unprivileged user may be unable to restore a source gid outside their groups; that is
    // recoverable metadata degradation, never a reason to change or delete the source.
    if unsafe { libc::fchown(fd, u32::MAX, source_gid) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(format!("fchown destination group: {error}"));
        }
    }
    Ok(())
}

fn sync_destination_path_group(c_path: &[u8], path: &Path, source_gid: u32) -> Result<(), String> {
    if source_gid == current_gid() {
        return Ok(());
    }
    // SAFETY: path is NUL-terminated and lchown does not traverse a symlink destination.
    if unsafe { libc::lchown(c_path.as_ptr().cast(), u32::MAX, source_gid) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(format!("lchown {} group: {error}", path.display()));
        }
    }
    Ok(())
}

fn timespec(seconds: i64, nanoseconds: i64) -> libc::timespec {
    libc::timespec {
        tv_sec: seconds,
        tv_nsec: nanoseconds as std::os::raw::c_long,
    }
}

fn c_path(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    if bytes.contains(&0) {
        return Err(format!("path contains NUL: {}", path.display()));
    }
    bytes.push(0);
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync directory {}: {error}", path.display()))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    path.parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))
        .map(File::open)?
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync parent of {}: {error}", path.display()))
}

fn verify_copied_tree_observed(
    source: &Path,
    destination: &Path,
    relative: &Path,
    symlink_targets: &BTreeMap<PathBuf, PathBuf>,
    operation: &mut Operation,
) -> Result<(), String> {
    let mut pending = vec![(
        source.to_path_buf(),
        destination.to_path_buf(),
        relative.to_path_buf(),
    )];
    while let Some((source, destination, relative)) = pending.pop() {
        operation.admit_path(&source)?;
        verify_copied_entry(
            &source,
            &destination,
            &relative,
            symlink_targets,
            &mut pending,
            operation,
        )?;
    }
    Ok(())
}

fn verify_copied_entry(
    source: &Path,
    destination: &Path,
    relative: &Path,
    symlink_targets: &BTreeMap<PathBuf, PathBuf>,
    pending: &mut Vec<(PathBuf, PathBuf, PathBuf)>,
    operation: &mut Operation,
) -> Result<(), String> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("inspect source {}: {error}", source.display()))?;
    let destination_metadata = fs::symlink_metadata(destination)
        .map_err(|error| format!("inspect destination {}: {error}", destination.display()))?;
    if source_metadata.file_type() != destination_metadata.file_type()
        || source_metadata.uid() != destination_metadata.uid()
        || source_metadata.mtime() != destination_metadata.mtime()
        || source_metadata.mtime_nsec() != destination_metadata.mtime_nsec()
    {
        return Err(format!("copied metadata mismatch for {}", source.display()));
    }
    if source_metadata.gid() != destination_metadata.gid() && source_metadata.gid() == current_gid()
    {
        return Err(format!("copied group mismatch for {}", source.display()));
    }
    if source_metadata.file_type().is_file() {
        if source_metadata.mode() != destination_metadata.mode()
            || source_metadata.len() != destination_metadata.len()
        {
            return Err(format!("copied file mismatch for {}", source.display()));
        }
        compare_file_contents_observed(source, destination, source_metadata.len(), operation)?;
    } else if source_metadata.file_type().is_socket() || source_metadata.file_type().is_fifo() {
        if source_metadata.mode() != destination_metadata.mode() {
            return Err(format!(
                "copied special-file mode mismatch for {}",
                source.display()
            ));
        }
    } else if source_metadata.file_type().is_symlink() {
        let source_target = symlink_target(relative, symlink_targets, source)?;
        let destination_target = fs::read_link(destination)
            .map_err(|error| format!("read copied link {}: {error}", destination.display()))?;
        if *source_target != destination_target {
            return Err(format!(
                "copied symlink target mismatch for {}",
                source.display()
            ));
        }
    } else if source_metadata.file_type().is_dir() {
        if source_metadata.mode() != destination_metadata.mode() {
            return Err(format!(
                "copied directory mode mismatch for {}",
                source.display()
            ));
        }
        let mut names = BTreeNames::new();
        for name in
            linux_temp::read_dir_names_no_atime_observed(source, &mut native_observation(operation))
                .map_err(|error| format!("read source entries {}: {error}", source.display()))?
        {
            operation.check()?;
            names.source.insert(name);
        }
        for entry in fs::read_dir(destination)
            .map_err(|error| format!("read copied entries {}: {error}", destination.display()))?
        {
            operation.check()?;
            let entry = entry.map_err(|error| format!("read copied entry: {error}"))?;
            operation.admit_path(&entry.path())?;
            names.destination.insert(entry.file_name());
        }
        if names.source != names.destination {
            return Err(format!(
                "copied directory entry set mismatch for {}",
                source.display()
            ));
        }
        for name in names.source {
            let mut child_relative = relative.to_path_buf();
            child_relative.push(&name);
            operation.admit_path(&source.join(&name))?;
            operation.admit_path(&destination.join(&name))?;
            operation.admit_path(&child_relative)?;
            pending.push((source.join(&name), destination.join(&name), child_relative));
        }
    }
    Ok(())
}

fn compare_file_contents_observed(
    source: &Path,
    destination: &Path,
    length: u64,
    operation: &mut Operation,
) -> Result<(), String> {
    operation.check()?;
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)
        .map_err(|error| format!("open source for verification {source:?}: {error}"))?;
    let mut destination = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(destination)
        .map_err(|error| format!("open destination for verification {destination:?}: {error}"))?;
    for file in [&source, &destination] {
        let metadata = file
            .metadata()
            .map_err(|error| format!("verify opened file: {error}"))?;
        if !metadata.is_file() || metadata.len() != length {
            return Err("verification input changed type or length".into());
        }
    }
    let mut remaining = length;
    let mut source_buffer = vec![0_u8; 1024 * 1024];
    let mut destination_buffer = vec![0_u8; 1024 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(source_buffer.len() as u64) as usize;
        operation
            .io((chunk as u64).saturating_mul(2))
            .map_err(|error| error.to_string())?;
        source
            .read_exact(&mut source_buffer[..chunk])
            .map_err(|error| format!("verify source read: {error}"))?;
        destination
            .read_exact(&mut destination_buffer[..chunk])
            .map_err(|error| format!("verify destination read: {error}"))?;
        if source_buffer[..chunk] != destination_buffer[..chunk] {
            return Err("copied file contents differ from source".to_string());
        }
        remaining -= chunk as u64;
    }
    operation.check()
}

#[derive(Default)]
struct BTreeNames {
    source: std::collections::BTreeSet<std::ffi::OsString>,
    destination: std::collections::BTreeSet<std::ffi::OsString>,
}

impl BTreeNames {
    fn new() -> Self {
        Self::default()
    }
}

// Pending siblings borrow ownership of one directory fd rather than dup'ing it per name. Each
// directory is enumerated once; shared offsets are irrelevant to openat/metadata_at/unlinkat.
#[derive(Clone)]
struct SafeDir(std::sync::Arc<File>);

impl SafeDir {
    fn open_root(path: &Path) -> Result<Self, String> {
        let bytes = c_path(path)?;
        let fd = unsafe {
            libc::open(
                bytes.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open temporary root {}: {error}",
                path.display(),
                error = io::Error::last_os_error()
            ));
        }
        Ok(Self(std::sync::Arc::new(unsafe { File::from_raw_fd(fd) })))
    }

    fn open_child(&self, name: &std::ffi::OsStr) -> Result<Self, String> {
        let bytes = c_component(name)?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                bytes.as_ptr().cast(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NOATIME
                    | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open child {name:?}: {error}",
                error = io::Error::last_os_error()
            ));
        }
        Ok(Self(std::sync::Arc::new(unsafe { File::from_raw_fd(fd) })))
    }

    fn make_owner_only(&self) -> Result<(), String> {
        // Closing group/other write access before enumeration prevents a different user from
        // replacing a name while it is being unlinked. The sticky /tmp parent already protects the
        // top entry; every child directory needs this lock through its retained descriptor.
        if unsafe { libc::fchmod(self.0.as_raw_fd(), 0o700) } != 0 {
            return Err(format!(
                "lock directory before removal: {error}",
                error = io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

impl AsRawFd for SafeDir {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

fn metadata_at(parent: &SafeDir, name: &std::ffi::OsStr) -> Result<fs::Metadata, String> {
    let bytes = c_component(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            bytes.as_ptr().cast(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "inspect {name:?}: {error}",
            error = io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    file.metadata()
        .map_err(|error| format!("inspect {name:?}: {error}"))
}

fn unlink_at(parent: &SafeDir, name: &std::ffi::OsStr, directory: bool) -> Result<(), String> {
    let bytes = c_component(name)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(parent.as_raw_fd(), bytes.as_ptr().cast(), flags) } != 0 {
        return Err(format!(
            "remove {name:?}: {error}",
            error = io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn c_component(name: &std::ffi::OsStr) -> Result<Vec<u8>, String> {
    let mut bytes = name.as_bytes().to_vec();
    if bytes.is_empty() || bytes.contains(&0) || bytes == b"." || bytes == b".." {
        return Err(format!("invalid directory component {name:?}"));
    }
    bytes.push(0);
    Ok(bytes)
}

fn remove_tree_verified_observed(
    source: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
    operation: &mut Operation,
) -> Result<(), String> {
    enum Job {
        Visit {
            parent: SafeDir,
            relative: PathBuf,
            name: OsString,
        },
        RemoveDirectory {
            parent: SafeDir,
            relative: PathBuf,
            name: OsString,
            directory: SafeDir,
        },
    }

    operation.admit_path(source)?;
    let mut observation = native_observation(operation);
    let name = source
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .ok_or_else(|| format!("{source:?} has no final component"))?;
    let root = SafeDir::open_root(temp_root)?;
    let mut jobs = vec![Job::Visit {
        parent: root,
        relative: PathBuf::new(),
        name,
    }];

    while let Some(job) = jobs.pop() {
        operation.check()?;
        match job {
            Job::Visit {
                parent,
                relative,
                name,
            } => {
                operation.admit_path(&relative)?;
                let metadata = metadata_at(&parent, &name)?;
                verify_removal_entry(&metadata, &relative, expected)?;
                if metadata.is_dir() {
                    let directory = parent.open_child(&name)?;
                    let opened_metadata = directory
                        .0
                        .metadata()
                        .map_err(|error| format!("inspect opened {name:?}: {error}"))?;
                    verify_removal_entry(&opened_metadata, &relative, expected)?;
                    directory.make_owner_only()?;
                    let child_names = linux_temp::read_dir_names_at_observed(
                        directory.as_raw_fd(),
                        &mut observation,
                    )
                    .map_err(|error| format!("enumerate {name:?}: {error}"))?;
                    // Siblings share one owned descriptor. Duplicating a descriptor per queued
                    // name could exhaust handles on a wide directory; retained depth is bounded.
                    let child_parent = directory.clone();
                    jobs.push(Job::RemoveDirectory {
                        parent,
                        relative: relative.clone(),
                        name: name.clone(),
                        directory,
                    });
                    for child_name in child_names {
                        let mut child_relative = relative.clone();
                        child_relative.push(&child_name);
                        operation.admit_path(&child_relative)?;
                        jobs.push(Job::Visit {
                            parent: child_parent.clone(),
                            relative: child_relative,
                            name: child_name,
                        });
                    }
                } else {
                    unlink_at(&parent, &name, false)?;
                }
            }
            Job::RemoveDirectory {
                parent,
                relative,
                name,
                directory,
            } => {
                let metadata = directory
                    .0
                    .metadata()
                    .map_err(|error| format!("reinspect {name:?}: {error}"))?;
                verify_removal_entry(&metadata, &relative, expected)?;
                drop(directory);
                unlink_at(&parent, &name, true)?;
            }
        }
    }
    Ok(())
}

fn verify_removal_entry(
    metadata: &fs::Metadata,
    relative: &Path,
    expected: &LinuxTempMeasurement,
) -> Result<(), String> {
    let Some(expected_entry) = expected.entries.get(relative) else {
        return Err(format!(
            "unexpected entry appeared during verified removal: {relative:?}"
        ));
    };
    if metadata.dev() != expected_entry.0
        || metadata.ino() != expected_entry.1
        || metadata.file_type() != expected_entry.2
    {
        return Err(format!(
            "entry identity changed before removal: {relative:?}"
        ));
    }
    Ok(())
}

fn append_outcome(
    outcomes: &mut File,
    digest: &str,
    source: &Path,
    destination: &Path,
    status: &str,
    error: Option<&str>,
) -> Result<(), String> {
    serde_json::to_writer(
        &mut *outcomes,
        &json!({
            "schema": RESULT_SCHEMA,
            "canonicalDigest": digest,
            "source": source.display().to_string(),
            "sourceBytes": source.as_os_str().as_bytes(),
            "destination": destination.display().to_string(),
            "status": status,
            "error": error,
        }),
    )
    .map_err(|error| format!("write quarantine outcome: {error}"))?;
    outcomes
        .write_all(b"\n")
        .and_then(|()| outcomes.sync_data())
        .map_err(|error| format!("sync quarantine outcome: {error}"))
}

// Legacy test entry points exercise the same bounded production mechanics with fresh defaults.
#[cfg(test)]
fn test_operation() -> Operation {
    Operation::new(CancellationToken::new(), QuarantineLimits::default()).unwrap()
}
#[cfg(test)]
fn copy_tree(
    source: &Path,
    destination: &Path,
    relative: &Path,
    targets: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), String> {
    copy_tree_observed(
        source,
        destination,
        relative,
        targets,
        &mut test_operation(),
    )
}
#[cfg(test)]
fn copy_regular_file(
    source: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
) -> Result<(), String> {
    copy_regular_file_observed(source, destination, metadata, &mut test_operation())
}
#[cfg(test)]
fn verify_copied_tree(
    source: &Path,
    destination: &Path,
    relative: &Path,
    targets: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), String> {
    verify_copied_tree_observed(
        source,
        destination,
        relative,
        targets,
        &mut test_operation(),
    )
}
#[cfg(test)]
fn compare_file_contents(source: &Path, destination: &Path, length: u64) -> Result<(), String> {
    compare_file_contents_observed(source, destination, length, &mut test_operation())
}
#[cfg(test)]
fn remove_tree_verified(
    source: &Path,
    temp_root: &Path,
    expected: &LinuxTempMeasurement,
) -> Result<(), String> {
    remove_tree_verified_observed(source, temp_root, expected, &mut test_operation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    #[test]
    fn lossy_recovery_spellings_do_not_alias_canonical_plan_digests() {
        use std::os::unix::ffi::OsStringExt;
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        fs::write(&source, b"selected").unwrap();
        let captures = vec![CapturedCandidate {
            path: source.clone(),
            measurement: measurement_fixture(&source),
        }];
        let first = PathBuf::from(OsString::from_vec(b"/volume/recovery-\xff".to_vec()));
        let second = PathBuf::from(OsString::from_vec(b"/volume/recovery-\xfe".to_vec()));
        let a = plan_body(&captures, root.path(), &first);
        let b = plan_body(&captures, root.path(), &second);
        assert_eq!(a.quarantine_base, b.quarantine_base);
        assert_ne!(a.quarantine_base_bytes, b.quarantine_base_bytes);
        assert_ne!(
            sweepx_canonical::plan_digest_hex(&a).unwrap(),
            sweepx_canonical::plan_digest_hex(&b).unwrap()
        );
    }

    #[test]
    fn verified_removal_unlinks_only_the_measured_tree() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("measured-directory");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/payload"), b"payload").unwrap();
        let expected = measurement_fixture(&source);

        remove_tree_verified(&source, root.path(), &expected).unwrap();

        assert!(fs::symlink_metadata(&source).is_err());
    }

    #[test]
    fn verified_removal_refuses_a_replaced_top_inode() {
        let root = TempDir::new().unwrap();
        let outside = root.path().join("outside-target");
        fs::write(&outside, b"must remain").unwrap();
        let source = root.path().join("candidate");
        fs::write(&source, b"original").unwrap();
        let expected = measurement_fixture(&source);

        fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink(&outside, &source).unwrap();

        let result = remove_tree_verified(&source, root.path(), &expected);
        assert!(result.is_err());
        assert!(
            fs::symlink_metadata(&source)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");
    }

    #[test]
    fn verified_removal_refuses_an_unmeasured_child() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("measured-directory");
        fs::create_dir(&source).unwrap();
        let expected = measurement_fixture(&source);
        fs::write(source.join("appeared-after-measurement"), b"new").unwrap();

        let result = remove_tree_verified(&source, root.path(), &expected);
        assert!(result.is_err());
        assert!(source.join("appeared-after-measurement").exists());
        assert!(source.exists());
    }

    fn measurement_fixture(path: &Path) -> LinuxTempMeasurement {
        let top = fs::symlink_metadata(path).unwrap();
        let mut entries = std::collections::BTreeMap::new();
        let mut allocated_bytes = 0u128;
        let mut logical_bytes = 0u128;
        let mut entry_count = 0u64;
        let mut last_accessed = SystemTime::UNIX_EPOCH;
        let mut last_modified = SystemTime::UNIX_EPOCH;
        let mut last_status_change = SystemTime::UNIX_EPOCH;

        if top.is_dir() {
            let mut stack = vec![(path.to_path_buf(), PathBuf::new())];
            while let Some((directory, relative)) = stack.pop() {
                for entry in fs::read_dir(&directory).unwrap() {
                    let entry = entry.unwrap();
                    let mut child_relative = relative.clone();
                    child_relative.push(entry.file_name());
                    let metadata = fs::symlink_metadata(entry.path()).unwrap();
                    if metadata.is_dir() {
                        stack.push((entry.path(), child_relative.clone()));
                    }
                    record_fixture_entry(
                        &metadata,
                        child_relative,
                        &mut entries,
                        &mut allocated_bytes,
                        &mut entry_count,
                        &mut last_accessed,
                        &mut last_modified,
                        &mut last_status_change,
                    );
                    if metadata.is_file() {
                        logical_bytes = logical_bytes.saturating_add(u128::from(metadata.len()));
                    }
                }
                let metadata = fs::symlink_metadata(&directory).unwrap();
                record_fixture_entry(
                    &metadata,
                    relative,
                    &mut entries,
                    &mut allocated_bytes,
                    &mut entry_count,
                    &mut last_accessed,
                    &mut last_modified,
                    &mut last_status_change,
                );
                if metadata.is_file() {
                    logical_bytes = logical_bytes.saturating_add(u128::from(metadata.len()));
                }
            }
            let top = fs::symlink_metadata(path).unwrap();
            last_accessed = last_accessed.max(
                SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::new(
                        u64::try_from(top.atime()).unwrap(),
                        top.atime_nsec() as u32,
                    ))
                    .unwrap(),
            );
            last_modified = last_modified.max(
                SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::new(
                        u64::try_from(top.mtime()).unwrap(),
                        top.mtime_nsec() as u32,
                    ))
                    .unwrap(),
            );
            last_status_change = last_status_change.max(
                SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::new(
                        u64::try_from(top.ctime()).unwrap(),
                        top.ctime_nsec() as u32,
                    ))
                    .unwrap(),
            );
        } else {
            record_fixture_entry(
                &top,
                PathBuf::new(),
                &mut entries,
                &mut allocated_bytes,
                &mut entry_count,
                &mut last_accessed,
                &mut last_modified,
                &mut last_status_change,
            );
            if top.is_file() {
                logical_bytes = logical_bytes.saturating_add(u128::from(top.len()));
            }
        }

        let mut fifo_inodes = std::collections::BTreeSet::new();
        for (_device, inode, file_type) in entries.values() {
            if file_type.is_fifo() {
                fifo_inodes.insert(*inode);
            }
        }

        LinuxTempMeasurement {
            top,
            allocated_bytes,
            logical_bytes,
            entries,
            fifo_inodes,
            entry_count,
            last_accessed,
            last_modified,
            last_status_change,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_fixture_entry(
        metadata: &fs::Metadata,
        relative: PathBuf,
        entries: &mut std::collections::BTreeMap<PathBuf, linux_temp::TempEntryIdentity>,
        allocated_bytes: &mut u128,
        entry_count: &mut u64,
        last_accessed: &mut SystemTime,
        last_modified: &mut SystemTime,
        last_status_change: &mut SystemTime,
    ) {
        use std::os::unix::fs::MetadataExt as _;
        entries.insert(
            relative,
            (metadata.dev(), metadata.ino(), metadata.file_type()),
        );
        *allocated_bytes =
            allocated_bytes.saturating_add(u128::from(metadata.blocks()).saturating_mul(512));
        *entry_count += 1;
        *last_accessed = (*last_accessed).max(
            SystemTime::UNIX_EPOCH
                .checked_add(std::time::Duration::new(
                    u64::try_from(metadata.atime()).unwrap(),
                    metadata.atime_nsec() as u32,
                ))
                .unwrap(),
        );
        *last_modified = (*last_modified).max(
            SystemTime::UNIX_EPOCH
                .checked_add(std::time::Duration::new(
                    u64::try_from(metadata.mtime()).unwrap(),
                    metadata.mtime_nsec() as u32,
                ))
                .unwrap(),
        );
        *last_status_change = (*last_status_change).max(
            SystemTime::UNIX_EPOCH
                .checked_add(std::time::Duration::new(
                    u64::try_from(metadata.ctime()).unwrap(),
                    metadata.ctime_nsec() as u32,
                ))
                .unwrap(),
        );
    }

    #[test]
    fn durable_copy_preserves_files_directories_and_symlinks() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), b"recoverable").unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), b"nested").unwrap();
        std::os::unix::fs::symlink("payload", source.join("link")).unwrap();
        let fifo = std::process::Command::new("mkfifo")
            .arg(source.join("pipe"))
            .status()
            .unwrap();
        assert!(fifo.success());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let symlink_targets = BTreeMap::from([(PathBuf::from("link"), PathBuf::from("payload"))]);

        copy_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
        verify_copied_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
        assert_eq!(
            fs::read(destination.join("payload")).unwrap(),
            b"recoverable"
        );
        assert_eq!(
            fs::read_link(destination.join("link")).unwrap(),
            PathBuf::from("payload")
        );
    }

    #[test]
    fn durable_copy_preserves_stale_unix_sockets() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("stale.sock");
        let destination = root.path().join("copied.sock");
        bind_unix_socket(&source).unwrap();
        let symlink_targets = BTreeMap::new();

        copy_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
        verify_copied_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_socket()
        );
    }

    #[test]
    fn verified_move_preserves_broken_symlink_and_special_inodes() {
        let root = TempDir::new().unwrap();
        let _seams = sweepx_fixtures::linux_temp::TestSeams::future();
        let source = root.path().join("stale-object");
        let destination = root.path().join("recovered-object");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), b"recoverable").unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/file"), b"nested").unwrap();
        std::os::unix::fs::symlink("missing-target", source.join("broken")).unwrap();
        let fifo = std::process::Command::new("mkfifo")
            .arg(source.join("pipe"))
            .status()
            .unwrap();
        assert!(fifo.success());
        bind_unix_socket(&source.join("stale.sock")).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let payload = source.join("payload");
        let nested = source.join("nested");
        let nested_file = nested.join("file");
        let broken = source.join("broken");
        let pipe = source.join("pipe");
        let stale_socket = source.join("stale.sock");
        let paths = [
            source.as_path(),
            payload.as_path(),
            nested.as_path(),
            nested_file.as_path(),
            broken.as_path(),
            pipe.as_path(),
            stale_socket.as_path(),
        ];
        let touched = std::process::Command::new("touch")
            .arg("-h")
            .arg("-d")
            .arg("@1600000000")
            .args(paths)
            .status()
            .unwrap();
        assert!(touched.success());

        let expected =
            linux_temp::validate_candidate_with_seams(&source, root.path(), true).unwrap();
        move_to_quarantine_for_test(&source, &destination, root.path(), &expected).unwrap();

        assert_eq!(
            fs::symlink_metadata(&source).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fs::read(destination.join("payload")).unwrap(),
            b"recoverable"
        );
        let copied_link = destination.join("broken");
        assert!(fs::symlink_metadata(&copied_link).is_ok());
        assert_eq!(
            fs::read_link(&copied_link).unwrap(),
            PathBuf::from("missing-target")
        );
        assert!(
            fs::symlink_metadata(destination.join("pipe"))
                .unwrap()
                .file_type()
                .is_fifo()
        );
        assert!(
            fs::symlink_metadata(destination.join("stale.sock"))
                .unwrap()
                .file_type()
                .is_socket()
        );
    }

    #[test]
    fn verified_move_preserves_a_top_level_broken_symlink() {
        let root = TempDir::new().unwrap();
        let _seams = sweepx_fixtures::linux_temp::TestSeams::future();
        let source = root.path().join("stale-link");
        let destination = root.path().join("recovered-link");
        std::os::unix::fs::symlink("missing-target", &source).unwrap();
        let touched = std::process::Command::new("touch")
            .arg("-h")
            .arg("-d")
            .arg("@1600000000")
            .arg(&source)
            .status()
            .unwrap();
        assert!(touched.success());

        let expected =
            linux_temp::validate_candidate_with_seams(&source, root.path(), true).unwrap();
        move_to_quarantine_for_test(&source, &destination, root.path(), &expected).unwrap();

        assert_eq!(
            fs::symlink_metadata(&source).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fs::read_link(&destination).unwrap(),
            PathBuf::from("missing-target")
        );
    }

    #[test]
    fn verified_move_copies_between_distinct_filesystems_when_available() {
        let shm = Path::new("/dev/shm");
        if !shm.is_dir() {
            return;
        }
        let test = || -> Result<(), String> {
            let temporary_root = TempDir::new_in(shm).map_err(|error| error.to_string())?;
            let _seams = sweepx_fixtures::linux_temp::TestSeams::future();
            let destination_root = TempDir::new().map_err(|error| error.to_string())?;
            let source = temporary_root.path().join("stale-cross-device");
            let destination = destination_root.path().join("recovered");
            let source_metadata =
                fs::symlink_metadata(temporary_root.path()).map_err(|error| error.to_string())?;
            let destination_metadata =
                fs::symlink_metadata(destination_root.path()).map_err(|error| error.to_string())?;
            if source_metadata.dev() == destination_metadata.dev() {
                return Ok(());
            }
            fs::create_dir(&source).map_err(|error| error.to_string())?;
            fs::write(source.join("payload"), b"cross-device")
                .map_err(|error| error.to_string())?;
            std::os::unix::fs::symlink("missing-target", source.join("broken"))
                .map_err(|error| error.to_string())?;
            let touched = std::process::Command::new("touch")
                .arg("-h")
                .arg("-d")
                .arg("@1600000000")
                .arg(&source)
                .arg(source.join("payload"))
                .arg(source.join("broken"))
                .status()
                .map_err(|error| error.to_string())?;
            assert!(touched.success());

            let expected =
                linux_temp::validate_candidate_with_seams(&source, temporary_root.path(), true)
                    .map_err(|error| error.to_string())?;
            move_to_quarantine_for_test(&source, &destination, temporary_root.path(), &expected)?;
            assert_eq!(
                fs::symlink_metadata(&source).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
            assert_eq!(
                fs::read(destination.join("payload")).map_err(|error| error.to_string())?,
                b"cross-device"
            );
            assert_eq!(
                fs::read_link(destination.join("broken")).map_err(|error| error.to_string())?,
                PathBuf::from("missing-target")
            );
            Ok(())
        };
        test().unwrap();
    }

    #[test]
    fn verification_detects_a_corrupted_copy() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::write(&source, b"payload").unwrap();
        let symlink_targets = BTreeMap::new();

        copy_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
        fs::write(&destination, b"different").unwrap();

        assert!(
            verify_copied_tree(&source, &destination, Path::new(""), &BTreeMap::new(),).is_err()
        );
        assert!(fs::symlink_metadata(&source).is_ok());
    }

    #[test]
    fn outcome_records_are_json_lines_bound_to_the_plan_digest() {
        let root = TempDir::new().unwrap();
        let outcomes_path = root.path().join("outcomes.jsonl");
        let mut outcomes = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&outcomes_path)
            .unwrap();
        append_outcome(
            &mut outcomes,
            "digest",
            Path::new("/tmp/source"),
            Path::new("/recovery/destination"),
            "reserved",
            None,
        )
        .unwrap();
        drop(outcomes);

        let line: serde_json::Value =
            serde_json::from_str(fs::read_to_string(&outcomes_path).unwrap().trim()).unwrap();
        assert_eq!(line["schema"], RESULT_SCHEMA);
        assert_eq!(line["canonicalDigest"], "digest");
        assert_eq!(line["status"], "reserved");
    }

    #[test]
    fn space_check_includes_margin() {
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        stat.f_bsize = 4096;
        stat.f_frsize = 4096;
        stat.f_blocks = 100;
        stat.f_bfree = 10;
        stat.f_bavail = 10;
        stat.f_namemax = 255;
        let available =
            u128::from(stat.f_bavail as u64).saturating_mul(u128::from(stat.f_frsize as u64));
        assert!(available < 40_960 + MIN_FREE_SPACE_MARGIN);
    }

    #[test]
    fn oversized_copy_is_refused_before_mutation() {
        let root = TempDir::new().unwrap();
        assert!(require_quarantine_space(root.path(), u128::MAX / 2).is_err());
    }

    #[test]
    fn fully_sparse_file_preserves_logical_length_without_data_copy() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("sparse");
        let destination = root.path().join("sparse-copy");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)
            .unwrap();
        file.set_len(4096).unwrap();
        drop(file);
        let metadata = fs::symlink_metadata(&source).unwrap();
        copy_regular_file(&source, &destination, &metadata).unwrap();
        assert_eq!(fs::symlink_metadata(&destination).unwrap().len(), 4096);
        let symlink_targets = BTreeMap::new();
        verify_copied_tree(&source, &destination, Path::new(""), &symlink_targets).unwrap();
    }

    #[test]
    fn durable_copy_and_verification_do_not_refresh_source_atime() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("stale-file");
        let destination = root.path().join("stale-file-copy");
        fs::write(&source, b"payload").unwrap();
        let touched = std::process::Command::new("touch")
            .arg("-a")
            .arg("-m")
            .arg("-d")
            .arg("@1600000000")
            .arg(&source)
            .status()
            .unwrap();
        assert!(touched.success());
        let before = fs::symlink_metadata(&source).unwrap().atime();
        let metadata = fs::symlink_metadata(&source).unwrap();

        copy_regular_file(&source, &destination, &metadata).unwrap();
        compare_file_contents(&source, &destination, metadata.len()).unwrap();

        let after = fs::symlink_metadata(&source).unwrap().atime();
        assert_eq!(before, after);
    }
    #[test]
    fn cancelled_copy_and_removal_leave_source_and_permissions_intact() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("recovery");
        fs::create_dir(&source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(source.join("payload"), b"retain source").unwrap();
        let expected = measurement_fixture(&source);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut operation = Operation::new(cancel, Default::default()).unwrap();
        assert!(
            move_to_quarantine_impl(
                &source,
                &destination,
                root.path(),
                &expected,
                false,
                &mut operation
            )
            .unwrap_err()
            .contains("cancelled")
        );
        assert!(
            remove_tree_verified_observed(&source, root.path(), &expected, &mut operation).is_err()
        );
        assert!(!destination.exists());
        assert_eq!(fs::read(source.join("payload")).unwrap(), b"retain source");
        assert_eq!(fs::symlink_metadata(&source).unwrap().mode() & 0o777, 0o750);
    }

    #[test]
    fn copy_budget_and_fifo_replacement_fail_without_source_removal() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("payload");
        let destination = root.path().join("copy");
        fs::write(&source, b"retained source").unwrap();
        let original = fs::symlink_metadata(&source).unwrap();
        let mut operation = Operation::new(
            CancellationToken::new(),
            QuarantineLimits {
                max_io_bytes: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            copy_regular_file_observed(&source, &destination, &original, &mut operation)
                .unwrap_err()
                .contains("byte limit")
        );
        assert_eq!(fs::read(&source).unwrap(), b"retained source");
        fs::remove_file(&source).unwrap();
        let bytes = c_path(&source).unwrap();
        assert_eq!(unsafe { libc::mkfifo(bytes.as_ptr().cast(), 0o600) }, 0);
        let error = copy_regular_file_observed(
            &source,
            &root.path().join("fifo-copy"),
            &original,
            &mut test_operation(),
        )
        .unwrap_err();
        assert!(error.contains("source changed before copy"));
        assert!(fs::symlink_metadata(&source).unwrap().file_type().is_fifo());
        assert!(!root.path().join("fifo-copy").exists());
    }

    #[test]
    fn selected_identity_rejects_an_equal_allocation_replacement() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("selected");
        fs::write(&source, []).unwrap();
        let previous = measurement_fixture(&source);
        // Retain the original object at another name so the replacement cannot reuse its inode.
        fs::rename(&source, root.path().join("old")).unwrap();
        fs::write(&source, []).unwrap();
        let current = measurement_fixture(&source);
        assert_eq!(current.allocated_bytes, previous.allocated_bytes);
        assert_ne!(current.top.ino(), previous.top.ino());
        let input = TempCleanInput {
            path: source.clone(),
            allocated_bytes: previous.allocated_bytes,
            expected: Some(std::sync::Arc::new(previous)),
        };
        assert!(
            bind_selected_measurement(&input, &current)
                .unwrap_err()
                .contains("after selection")
        );
        assert!(source.is_file());
    }

    #[test]
    fn pending_siblings_do_not_duplicate_native_directory_handles() {
        let root = TempDir::new().unwrap();
        let directory = SafeDir::open_root(root.path()).unwrap();
        let identity = fs::symlink_metadata(root.path()).unwrap();
        let siblings = vec![directory.clone(); 4096];
        // Independent procfs enumeration, scoped to this unique fixture inode, avoids unrelated
        // concurrently running tests and measures actual descriptors rather than Arc internals.
        let count = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| fs::metadata(entry.path()).ok())
            .filter(|metadata| metadata.dev() == identity.dev() && metadata.ino() == identity.ino())
            .count();
        assert_eq!(count, 1);
        drop(siblings);
        assert_eq!(directory.0.metadata().unwrap().ino(), identity.ino());
    }

    #[test]
    fn opaque_preview_requires_exact_full_confirmation_before_native_work() {
        let root = TempDir::new().unwrap();
        let source = root.path().join("source");
        fs::write(&source, b"must stay").unwrap();
        for confirmation in ["", "clean deadbeef", "clean DEADBEEF", "deadbeef"] {
            let captures = vec![CapturedCandidate {
                path: source.clone(),
                measurement: measurement_fixture(&source),
            }];
            let plan = plan_body(&captures, root.path(), &root.path().join("recovery"));
            let digest = sweepx_canonical::plan_digest_hex(&plan).unwrap();
            let mut changed = plan.clone();
            changed.rule_bytes_digest = "edited-rule-bytes".into();
            assert_ne!(digest, sweepx_canonical::plan_digest_hex(&changed).unwrap());
            let preview = TempCleanPreview {
                plan,
                digest,
                captures,
                quarantine_base: root.path().join("recovery"),
                allocated_bytes: 0,
                limits: Default::default(),
            };
            assert_eq!(
                execute_temp_clean(preview, confirmation, &CancellationToken::new())
                    .err()
                    .unwrap(),
                "exact plan confirmation required"
            );
        }
        assert_eq!(fs::read(&source).unwrap(), b"must stay");
        assert!(!root.path().join("recovery").exists());
    }
}
