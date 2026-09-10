//! Explicitly approved, recoverable cleanup for stale Linux build-temp candidates.
//!
//! This is deliberately narrower than the generic Cleaner design. It accepts only candidates
//! produced by the built-in `/tmp` rule, binds the exact native identities into a digest, and
//! moves them to a private quarantine on another filesystem. It never unlinks a candidate and
//! never treats a failed operating-system Trash attempt as permission for permanent deletion.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode as ProcessExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde_json::json;
use sweepx_core::OutputFormat;
use sweepx_i18n::Locale;

use crate::{
    LINUX_TMP_MIN_IDLE, linux_current_user_process_references_temp_child,
    linux_temp_name_has_known_prefix,
};

const PLAN_SCHEMA: &str = "sweepx.temp-clean.plan/v1";
const RESULT_SCHEMA: &str = "sweepx.temp-clean.result/v1";
const MV_PROGRAM: &str = "/usr/bin/mv";
const FINAL_MEASURE_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
/// One native stale-temp candidate retained from the in-process discovery pass.
pub(crate) struct TempCleanInput {
    /// Native path reconstructed by the Linux temporary-root discovery, not display text.
    pub(crate) path: PathBuf,
    /// Allocated bytes measured while capturing the report candidate.
    pub(crate) allocated_bytes: u128,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TempCleanPlanBody {
    schema: &'static str,
    mode: &'static str,
    temp_root: String,
    quarantine_base: String,
    minimum_idle_seconds: u64,
    process_observation: &'static str,
    blockers: [&'static str; 1],
    candidates: Vec<TempCleanPlanItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TempCleanPlanItem {
    path: String,
    allocated_bytes: String,
    device: String,
    inode: String,
    owner_uid: String,
    modified_unix_seconds: String,
}

impl TempCleanPlanItem {
    fn display_path(&self) -> String {
        sanitize_terminal_text(&self.path)
    }
}

#[derive(Debug)]
struct CapturedCandidate {
    path: PathBuf,
    allocated_bytes: u128,
    metadata: Metadata,
}

#[derive(Debug)]
struct PreparedQuarantine {
    run_dir: PathBuf,
    metadata: Metadata,
    outcomes: File,
}

/// Runs the Linux-only, explicitly confirmed recoverable-quarantine preview.
pub(crate) fn run_temp_clean(
    inputs: Vec<TempCleanInput>,
    explicit_quarantine: Option<&Path>,
    format: OutputFormat,
    locale: Locale,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    run_linux_temp_clean(
        inputs,
        explicit_quarantine,
        format,
        locale,
        stdin_is_terminal,
    )
}

fn run_linux_temp_clean(
    inputs: Vec<TempCleanInput>,
    explicit_quarantine: Option<&Path>,
    format: OutputFormat,
    locale: Locale,
    stdin_is_terminal: bool,
) -> ProcessExitCode {
    // SAFETY: geteuid has no preconditions and does not mutate process state. Cleanup never runs
    // with broader filesystem authority than the user who approved the plan.
    if unsafe { libc::geteuid() } == 0 || linux_process_has_capabilities() {
        eprintln!("temporary cleanup is disabled for root or capability-bearing processes");
        return ProcessExitCode::from(8);
    }
    if format != OutputFormat::Human || !stdin_is_terminal {
        eprintln!(
            "junk --system --clean-temp requires human output and a foreground interactive terminal"
        );
        return ProcessExitCode::from(2);
    }
    if inputs.is_empty() {
        println!(
            "{}",
            match locale {
                Locale::ZhCn => "没有符合安全边界的陈旧 Linux 构建临时目录。",
                Locale::EnUs => "No stale Linux build-temp directory met the safety boundary.",
            }
        );
        return ProcessExitCode::SUCCESS;
    }

    // The report-only test seam may redirect discovery, but an environment variable never
    // authorizes mutation. Product cleanup is hard-bound to the real Linux `/tmp`.
    let temp_root = Path::new("/tmp");
    if !temp_root.is_dir() {
        eprintln!("the Linux temporary root is unavailable");
        return ProcessExitCode::from(8);
    }
    let quarantine_base = match resolve_quarantine_base(explicit_quarantine) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return ProcessExitCode::from(8);
        }
    };
    let captures = match capture_all(&inputs, temp_root) {
        Ok(captures) => captures,
        Err(error) => {
            eprintln!("cleanup plan refused: {error}");
            return ProcessExitCode::from(8);
        }
    };
    let plan = plan_body(&captures, temp_root, &quarantine_base);
    let digest = match sweepx_canonical::plan_digest_hex(&plan) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("could not digest cleanup plan: {error}");
            return ProcessExitCode::from(8);
        }
    };
    let total = captures.iter().try_fold(0u128, |sum, candidate| {
        sum.checked_add(candidate.allocated_bytes)
    });
    let Some(total) = total else {
        eprintln!("cleanup plan refused: candidate byte total overflowed");
        return ProcessExitCode::from(8);
    };

    print_plan(locale, &plan, &digest, total);
    if !confirm_digest(&digest, io::stdin().lock(), io::stdout()) {
        println!(
            "{}",
            match locale {
                Locale::ZhCn => "已取消；没有移动任何目录。",
                Locale::EnUs => "Cancelled; no directory was moved.",
            }
        );
        return ProcessExitCode::SUCCESS;
    }

    // The approval binds only this captured set. Recheck every item before creating durable
    // state so a changed candidate cannot silently become a different plan target.
    if let Err(error) = revalidate_all(&captures, temp_root) {
        eprintln!("cleanup plan became stale before execution: {error}");
        return ProcessExitCode::from(8);
    }
    let mut quarantine = match prepare_quarantine(&quarantine_base, temp_root, &plan, &digest) {
        Ok(quarantine) => quarantine,
        Err(error) => {
            eprintln!("could not prepare recoverable quarantine: {error}");
            return ProcessExitCode::from(8);
        }
    };

    let mut moved = Vec::new();
    let mut failure = None;
    for captured in captures {
        if let Err(error) = revalidate_candidate(&captured, temp_root) {
            failure = Some((captured.path.clone(), error));
            break;
        }
        if let Err(error) = verify_quarantine_identity(&quarantine) {
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
        // Durable reservation precedes the external move. A crash after this record is visible
        // as an indeterminate item that must be reconciled, never as an unrecorded success.
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
        match move_to_quarantine(&captured.path, &destination) {
            Ok(()) if !captured.path.exists() && destination.is_dir() => {
                let destination_metadata = match fs::symlink_metadata(&destination) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        failure = Some((
                            captured.path.clone(),
                            format!(
                                "inspect moved destination {}: {error}",
                                destination.display()
                            ),
                        ));
                        break;
                    }
                };
                if !same_copied_directory(&captured.metadata, &destination_metadata) {
                    failure = Some((
                        captured.path.clone(),
                        "moved destination no longer has the approved owner/type/mode/mtime"
                            .to_string(),
                    ));
                    break;
                }
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
                moved.push((captured.path, destination, captured.allocated_bytes));
            }
            Ok(()) => {
                failure = Some((
                    captured.path.clone(),
                    "move returned success without one source-to-quarantine transition".to_string(),
                ));
                break;
            }
            Err(error) => {
                let reconciliation = match (captured.path.exists(), destination.exists()) {
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

    print_execution_result(
        locale,
        &digest,
        &quarantine.run_dir,
        &moved,
        failure.as_ref(),
    );
    ProcessExitCode::from(if failure.is_some() { 4 } else { 0 })
}

fn same_copied_directory(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.file_type().is_dir()
        && after.file_type().is_dir()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.modified().ok() == after.modified().ok()
}

fn linux_process_has_capabilities() -> bool {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return true;
    };
    ["CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .map(|key| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .map(str::trim)
        })
        // A missing runtime fact cannot prove the process is unprivileged.
        .any(|value| value.is_none_or(|value| value.bytes().any(|byte| byte != b'0')))
}

#[cfg(target_os = "linux")]
fn capture_all(
    inputs: &[TempCleanInput],
    temp_root: &Path,
) -> Result<Vec<CapturedCandidate>, String> {
    let mut captures = Vec::with_capacity(inputs.len());
    for input in inputs {
        let metadata = validate_candidate_path(&input.path, temp_root)?;
        captures.push(CapturedCandidate {
            path: input.path.clone(),
            allocated_bytes: input.allocated_bytes,
            metadata,
        });
    }
    Ok(captures)
}

#[cfg(target_os = "linux")]
fn revalidate_all(captures: &[CapturedCandidate], temp_root: &Path) -> Result<(), String> {
    for captured in captures {
        revalidate_candidate_metadata(captured, temp_root)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_candidate_path(path: &Path, temp_root: &Path) -> Result<Metadata, String> {
    use std::os::unix::fs::MetadataExt;

    if path.parent() != Some(temp_root) {
        return Err(format!("{} is not a direct child of /tmp", path.display()));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has no safe UTF-8 basename", path.display()))?;
    if !linux_temp_name_has_known_prefix(name) {
        return Err(format!(
            "{} is not an approved build-temp name",
            path.display()
        ));
    }
    let root_metadata = fs::symlink_metadata(temp_root)
        .map_err(|error| format!("inspect {}: {error}", temp_root.display()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_dir()
        || metadata.uid() != current_uid
        || metadata.dev() != root_metadata.dev()
    {
        return Err(format!(
            "{} changed type, owner, or filesystem",
            path.display()
        ));
    }
    let age = SystemTime::now()
        .duration_since(
            metadata
                .modified()
                .map_err(|error| format!("read mtime for {}: {error}", path.display()))?,
        )
        .unwrap_or_default();
    if age < LINUX_TMP_MIN_IDLE {
        return Err(format!(
            "{} is no longer at least seven days old",
            path.display()
        ));
    }
    if linux_current_user_process_references_temp_child(temp_root, name) {
        return Err(format!(
            "{} is referenced by a current-user process",
            path.display()
        ));
    }
    if has_nested_mount(path)? {
        return Err(format!("{} contains a mount boundary", path.display()));
    }
    Ok(metadata)
}

#[cfg(target_os = "linux")]
fn revalidate_candidate(captured: &CapturedCandidate, temp_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    revalidate_candidate_metadata(captured, temp_root)?;
    let measurement =
        crate::linux_du_measurement(&captured.path, Instant::now() + FINAL_MEASURE_DEADLINE)
            .ok_or_else(|| {
                format!(
                    "final size measurement failed for {}",
                    captured.path.display()
                )
            })?;
    if measurement.allocated_bytes != captured.allocated_bytes
        || measurement.metadata.dev() != captured.metadata.dev()
        || measurement.metadata.ino() != captured.metadata.ino()
    {
        return Err(format!(
            "{} changed size or identity after plan capture",
            captured.path.display()
        ));
    }
    // The directory may change while `du` walks it, so validate one more time after measurement.
    revalidate_candidate_metadata(captured, temp_root)
}

fn revalidate_candidate_metadata(
    captured: &CapturedCandidate,
    temp_root: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let current = validate_candidate_path(&captured.path, temp_root)?;
    if current.dev() != captured.metadata.dev()
        || current.ino() != captured.metadata.ino()
        || current.uid() != captured.metadata.uid()
        || current.file_type() != captured.metadata.file_type()
        || current.modified().ok() != captured.metadata.modified().ok()
    {
        return Err(format!(
            "{} changed after plan capture",
            captured.path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn has_nested_mount(path: &Path) -> Result<bool, String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read /proc/self/mountinfo: {error}"))?;
    Ok(mountinfo.lines().any(|line| {
        let Some(encoded) = line.split_whitespace().nth(4) else {
            return false;
        };
        let mount = PathBuf::from(decode_mountinfo_path(encoded));
        mount == path || mount.starts_with(path)
    }))
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(encoded: &str) -> String {
    encoded
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn plan_body(
    captures: &[CapturedCandidate],
    temp_root: &Path,
    quarantine_base: &Path,
) -> TempCleanPlanBody {
    use std::os::unix::fs::MetadataExt;

    let candidates = captures
        .iter()
        .map(|candidate| TempCleanPlanItem {
            path: candidate.path.display().to_string(),
            allocated_bytes: candidate.allocated_bytes.to_string(),
            device: candidate.metadata.dev().to_string(),
            inode: candidate.metadata.ino().to_string(),
            owner_uid: candidate.metadata.uid().to_string(),
            modified_unix_seconds: candidate.metadata.mtime().to_string(),
        })
        .collect();
    TempCleanPlanBody {
        schema: PLAN_SCHEMA,
        mode: "recoverable_quarantine",
        temp_root: temp_root.display().to_string(),
        quarantine_base: quarantine_base.display().to_string(),
        minimum_idle_seconds: LINUX_TMP_MIN_IDLE.as_secs(),
        process_observation: "current_user_proc_only",
        blockers: ["process_observation_not_system_wide"],
        candidates,
    }
}

#[cfg(target_os = "linux")]
fn print_plan(locale: Locale, plan: &TempCleanPlanBody, digest: &str, total: u128) {
    let fingerprint = sweepx_canonical::attention_fingerprint_from_digest_hex(digest);
    match locale {
        Locale::ZhCn => {
            println!("可恢复临时目录清理计划");
            println!("  候选：{} 个", plan.candidates.len());
            println!("  已统计大小：{total} 字节");
            println!("  隔离区：{}", plan.quarantine_base);
            println!("  模式：跨文件系统可恢复隔离；不永久删除");
            println!("  剩余边界：只观察当前用户可见进程，不代表系统全局无引用");
            for candidate in &plan.candidates {
                println!(
                    "    {}  {} 字节",
                    candidate.display_path(),
                    candidate.allocated_bytes
                );
            }
            println!("  注意指纹：{fingerprint}");
            println!("  完整计划摘要：{digest}");
        }
        Locale::EnUs => {
            println!("Recoverable temporary-directory cleanup plan");
            println!("  candidates: {}", plan.candidates.len());
            println!("  accounted size: {total} bytes");
            println!("  quarantine: {}", plan.quarantine_base);
            println!("  mode: cross-filesystem recoverable quarantine; never permanent");
            println!(
                "  residual boundary: current-user process view only; not proof of system-wide inactivity"
            );
            for candidate in &plan.candidates {
                println!(
                    "    {}  {} bytes",
                    candidate.display_path(),
                    candidate.allocated_bytes
                );
            }
            println!("  attention fingerprint: {fingerprint}");
            println!("  full plan digest: {digest}");
        }
    }
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn confirm_digest<R: BufRead, W: Write>(digest: &str, mut reader: R, mut writer: W) -> bool {
    let _ = write!(writer, "Type `clean {digest}` to execute this exact plan: ");
    let _ = writer.flush();
    let mut answer = String::new();
    reader.read_line(&mut answer).is_ok() && answer.trim() == format!("clean {digest}")
}

#[cfg(target_os = "linux")]
fn resolve_quarantine_base(explicit: Option<&Path>) -> Result<PathBuf, String> {
    let requested = match explicit {
        Some(path) => path.to_path_buf(),
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
    Ok(requested)
}

#[cfg(target_os = "linux")]
fn prepare_quarantine(
    base: &Path,
    temp_root: &Path,
    plan: &TempCleanPlanBody,
    digest: &str,
) -> Result<PreparedQuarantine, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    ensure_no_symlink_ancestors(base)?;
    let base_existed = base.exists();
    if !base_existed {
        fs::create_dir_all(base).map_err(|error| format!("create {}: {error}", base.display()))?;
        fs::set_permissions(base, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect {}: {error}", base.display()))?;
    }
    let base_metadata = fs::symlink_metadata(base)
        .map_err(|error| format!("inspect {}: {error}", base.display()))?;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    let current_uid = unsafe { libc::geteuid() };
    if !base_metadata.file_type().is_dir()
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn verify_quarantine_identity(quarantine: &PreparedQuarantine) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

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

#[cfg(target_os = "linux")]
fn move_to_quarantine(source: &Path, destination: &Path) -> Result<(), String> {
    let status = Command::new(MV_PROGRAM)
        .arg("--no-clobber")
        .arg("--no-target-directory")
        .arg("--")
        .arg(source)
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("start {MV_PROGRAM}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{MV_PROGRAM} exited with {status}"))
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn print_execution_result(
    locale: Locale,
    digest: &str,
    run_dir: &Path,
    moved: &[(PathBuf, PathBuf, u128)],
    failure: Option<&(PathBuf, String)>,
) {
    let bytes = moved
        .iter()
        .fold(0u128, |sum, (_, _, bytes)| sum.saturating_add(*bytes));
    match locale {
        Locale::ZhCn => {
            println!("已隔离 {} 个目录，共 {bytes} 字节。", moved.len());
            println!("恢复目录：{}", run_dir.display());
            println!("计划摘要：{digest}");
            if let Some((path, error)) = failure {
                eprintln!("后续动作已停止：{}（{error}）", path.display());
            }
        }
        Locale::EnUs => {
            println!("Quarantined {} directories ({bytes} bytes).", moved.len());
            println!("Recovery directory: {}", run_dir.display());
            println!("Plan digest: {digest}");
            if let Some((path, error)) = failure {
                eprintln!("Stopped before later actions: {} ({error})", path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn full_digest_confirmation_is_exact() {
        let digest = "abc123";
        let mut output = Vec::new();
        assert!(confirm_digest(
            digest,
            io::Cursor::new(b"clean abc123\n"),
            &mut output
        ));
        assert!(!confirm_digest(
            digest,
            io::Cursor::new(b"abc123\n"),
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            io::Cursor::new(b"clean ABC123\n"),
            Vec::new()
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_escapes_are_decoded() {
        assert_eq!(decode_mountinfo_path("/tmp/a\\040b"), "/tmp/a b");
        assert_eq!(decode_mountinfo_path("/tmp/a\\134b"), "/tmp/a\\b");
    }
}
