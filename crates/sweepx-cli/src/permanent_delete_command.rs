//! Linux-only bounded file-or-directory Permanent deletion preview.
//!
//! The command is deliberately narrower than the future general plan executor: it admits one
//! regular file or a closed directory manifest, requires an exact foreground-terminal challenge,
//! writes durable intent per action, and submits only parent-relative `unlinkat`/`rmdir` calls.
//! Links, special files, elevated processes, mount roots, protected paths, and marker-protected
//! ancestry or descendants remain outside this preview.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde_json::json;
use sweepx_audit::{
    ActionId, ActionOutcome, AuditStore, AuthorizationBinding, AuthorizationId,
    AuthorizationSource, BatchId, DigestString, HostId, IntentRequest, ItemId, Observation, PlanId,
    RegisterAuthorization, RequestedMode, RiskTier, SessionId, UserId, hash_native_path,
};
use sweepx_core::OutputFormat;
use sweepx_i18n::Locale;

const FILE_PLAN_SCHEMA: &str = "sweepx.permanent-file.plan/v1";
const DIRECTORY_PLAN_SCHEMA: &str = "sweepx.permanent-directory.plan/v1";
const ADAPTER_VERSION: &str = "linux-unlinkat-manifest/v1";
const POLICY_VERSION: &str = "permanent-local-preview/v2";
const PROTECTION_MARKER: &[u8] = b".sweepx-protect";
const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_CONFIRMATION_BYTES: u64 = 256;
const MAX_DIRECTORY_ACTIONS: usize = 256;
const MAX_DIRECTORY_DEPTH: usize = 64;
const MAX_MANIFEST_PATH_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "targetType", rename_all = "snake_case")]
enum PermanentPlan {
    File(Box<PermanentFilePlan>),
    Directory(Box<PermanentDirectoryPlan>),
}

impl PermanentPlan {
    fn action_count(&self) -> usize {
        match self {
            Self::File(_) => 1,
            Self::Directory(plan) => plan.actions.len(),
        }
    }

    fn path(&self) -> &str {
        match self {
            Self::File(plan) => &plan.path,
            Self::Directory(plan) => &plan.path,
        }
    }

    fn size_bytes(&self) -> &str {
        match self {
            Self::File(plan) => &plan.size_bytes,
            Self::Directory(plan) => &plan.logical_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermanentFilePlan {
    schema: &'static str,
    created_at_unix_nanos: String,
    mode: &'static str,
    action_count: u8,
    path: String,
    path_bytes: Vec<u8>,
    parent: String,
    parent_bytes: Vec<u8>,
    basename_bytes: Vec<u8>,
    parent_device: String,
    parent_inode: String,
    parent_mount_id: String,
    device: String,
    inode: String,
    mount_id: String,
    filesystem_magic: String,
    owner_uid: String,
    mode_bits: u32,
    hard_link_count: String,
    size_bytes: String,
    modified_unix_seconds: i64,
    modified_nanoseconds: i64,
    status_change_unix_seconds: i64,
    status_change_nanoseconds: i64,
    policy_version: &'static str,
    adapter_version: &'static str,
    irreversible: bool,
    secure_erase: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermanentDirectoryPlan {
    schema: &'static str,
    created_at_unix_nanos: String,
    mode: &'static str,
    path: String,
    path_bytes: Vec<u8>,
    parent: String,
    parent_bytes: Vec<u8>,
    basename_bytes: Vec<u8>,
    parent_device: String,
    parent_inode: String,
    parent_mount_id: String,
    logical_bytes: String,
    action_count: usize,
    actions: Vec<PermanentDirectoryPlanAction>,
    policy_version: &'static str,
    adapter_version: &'static str,
    irreversible: bool,
    secure_erase: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermanentDirectoryPlanAction {
    action_id: String,
    relative_components: Vec<Vec<u8>>,
    display_path: String,
    object_type: PlannedObjectType,
    identity: FileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PlannedObjectType {
    File,
    Directory,
}

#[derive(Debug)]
enum PermanentCandidate {
    File(PermanentFileCandidate),
    Directory(PermanentDirectoryCandidate),
}

#[derive(Debug)]
struct PermanentFileCandidate {
    path: PathBuf,
    parent_path: PathBuf,
    basename: Vec<u8>,
    parent: OwnedFd,
    object: OwnedFd,
    parent_identity: FileIdentity,
    identity: FileIdentity,
}

#[derive(Debug)]
struct PermanentDirectoryCandidate {
    path: PathBuf,
    parent_path: PathBuf,
    basename: Vec<u8>,
    parent: OwnedFd,
    root: OwnedFd,
    parent_identity: FileIdentity,
    root_identity: FileIdentity,
    actions: Vec<DirectoryAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryAction {
    action_id: String,
    relative_components: Vec<Vec<u8>>,
    display_path: PathBuf,
    object_type: PlannedObjectType,
    identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
    filesystem_magic: i64,
    uid: u32,
    mode: u32,
    hard_link_count: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug)]
enum DeleteError {
    ConfirmationRequired,
    ConfirmationExpired,
    ElevatedRuntime,
    InvalidPath,
    NonCanonicalPath,
    ProtectedPath,
    ProtectionMarker(PathBuf),
    UnsupportedType,
    UnsupportedFilesystem,
    MultipleHardLinks,
    ResourceLimit(&'static str),
    OwnershipMismatch,
    TargetChanged,
    Partial {
        completed: usize,
        total: usize,
        detail: String,
    },
    Audit(String),
    PostSubmitAudit(String),
    Inspect(io::Error),
    Backend(io::Error),
    OutcomeUnknown,
}

impl std::fmt::Display for DeleteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConfirmationRequired => formatter.write_str(
                "human output and foreground interactive terminal confirmation are required",
            ),
            Self::ConfirmationExpired => formatter.write_str(
                "the permanent deletion plan expired before submission; rerun to create a fresh plan",
            ),
            Self::ElevatedRuntime => formatter.write_str(
                "permanent deletion is disabled for root or capability-bearing processes",
            ),
            Self::InvalidPath => {
                formatter.write_str("path must be an absolute, normalized, non-root path")
            }
            Self::NonCanonicalPath => formatter.write_str(
                "path must be the resolved absolute path, with no . or .. components or symbolic-link ancestors; on Linux, pass the output of `realpath -- PATH`",
            ),
            Self::ProtectedPath => formatter.write_str(
                "the selected path is a protected system, home, state, Trash, executable, or current-working-directory path",
            ),
            Self::ProtectionMarker(path) => write!(
                formatter,
                "a .sweepx-protect entry protects this target at {}",
                terminal_text(&path.display().to_string())
            ),
            Self::UnsupportedType => formatter.write_str(
                "this preview accepts regular files and real directories only; links and special files are refused",
            ),
            Self::UnsupportedFilesystem => formatter.write_str(
                "the target filesystem is not in the qualified local-filesystem allowlist",
            ),
            Self::MultipleHardLinks => formatter.write_str(
                "the file has multiple hard links; this preview will not claim permanent removal while another name can retain the inode",
            ),
            Self::ResourceLimit(limit) => {
                write!(formatter, "directory plan exceeds the {limit} safety limit")
            }
            Self::OwnershipMismatch => {
                formatter.write_str("the target must be owned by the invoking user")
            }
            Self::TargetChanged => formatter.write_str(
                "the target or its parent changed before permanent deletion; nothing was submitted",
            ),
            Self::Partial {
                completed,
                total,
                detail,
            } => write!(
                formatter,
                "permanent directory deletion stopped after {completed} of {total} approved actions: {detail}"
            ),
            Self::Audit(detail) => write!(formatter, "durable audit failed: {detail}"),
            Self::PostSubmitAudit(detail) => write!(
                formatter,
                "unlinkat was submitted but durable audit finalization failed; reconcile before retrying: {detail}"
            ),
            Self::Inspect(error) => write!(formatter, "cannot inspect target: {error}"),
            Self::Backend(error) => write!(formatter, "Linux unlinkat failed: {error}"),
            Self::OutcomeUnknown => formatter.write_str(
                "unlinkat was submitted but its durable outcome could not be proven; inspect the target and audit before retrying",
            ),
        }
    }
}

/// Runs the Linux file-or-directory Permanent preview.
pub(crate) fn run_cli_permanent_delete(
    raw_path: &OsStr,
    format: OutputFormat,
    locale: Locale,
    state_dir: &Path,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> ProcessExitCode {
    if format != OutputFormat::Human
        || !stdin_is_terminal
        || !stdout_is_terminal
        || !is_foreground_terminal()
    {
        return print_result(
            format,
            locale,
            Some(Path::new(raw_path)),
            None,
            Err(DeleteError::ConfirmationRequired),
        );
    }
    if is_elevated_runtime() {
        return print_result(
            format,
            locale,
            Some(Path::new(raw_path)),
            None,
            Err(DeleteError::ElevatedRuntime),
        );
    }

    let candidate = match PermanentCandidate::capture(PathBuf::from(raw_path), Some(state_dir)) {
        Ok(candidate) => candidate,
        Err(error) => return print_result(format, locale, None, None, Err(error)),
    };
    let plan = candidate.plan();
    let digest = match sweepx_canonical::plan_digest_hex(&plan) {
        Ok(digest) => digest,
        Err(error) => {
            return print_result(
                format,
                locale,
                Some(candidate.path()),
                None,
                Err(DeleteError::Audit(error.to_string())),
            );
        }
    };

    // Persist the immutable plan before asking for approval. Cancellation leaves this private
    // record behind, but never creates an authorization or intent.
    let audit_root = state_dir.join("permanent-delete-audit");
    let audit = match prepare_audit(&audit_root, state_dir, &plan, &digest) {
        Ok(audit) => audit,
        Err(error) => {
            return print_result(
                format,
                locale,
                Some(candidate.path()),
                Some(&digest),
                Err(error),
            );
        }
    };

    let approval_started = Instant::now();
    print_plan(locale, &plan, &digest);
    if !confirm_digest(
        &digest,
        plan.action_count(),
        io::stdin().lock(),
        io::stdout(),
    ) {
        return print_cancelled(locale, candidate.path(), &digest);
    }
    if approval_started.elapsed() >= APPROVAL_TTL {
        return print_result(
            format,
            locale,
            Some(candidate.path()),
            Some(&digest),
            Err(DeleteError::ConfirmationExpired),
        );
    }

    let path = candidate.path().to_path_buf();
    let result = candidate.submit(state_dir, &audit, &digest, approval_started);
    print_result(format, locale, Some(&path), Some(&digest), result)
}

impl PermanentCandidate {
    fn capture(path: PathBuf, state_dir: Option<&Path>) -> Result<Self, DeleteError> {
        validate_path_shape(&path)?;
        let metadata = fs::symlink_metadata(&path).map_err(DeleteError::Inspect)?;
        if metadata.file_type().is_symlink() {
            return Err(DeleteError::NonCanonicalPath);
        }
        if metadata.is_file() {
            PermanentFileCandidate::capture(path, state_dir).map(Self::File)
        } else if metadata.is_dir() {
            PermanentDirectoryCandidate::capture(path, state_dir).map(Self::Directory)
        } else {
            Err(DeleteError::UnsupportedType)
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::File(candidate) => &candidate.path,
            Self::Directory(candidate) => &candidate.path,
        }
    }

    fn plan(&self) -> PermanentPlan {
        match self {
            Self::File(candidate) => PermanentPlan::File(Box::new(candidate.plan())),
            Self::Directory(candidate) => PermanentPlan::Directory(Box::new(candidate.plan())),
        }
    }

    fn submit(
        self,
        state_dir: &Path,
        audit: &AuditStore,
        digest: &str,
        approval_started: Instant,
    ) -> Result<(), DeleteError> {
        match self {
            Self::File(candidate) => candidate.submit(state_dir, audit, digest, approval_started),
            Self::Directory(candidate) => {
                candidate.submit(state_dir, audit, digest, approval_started)
            }
        }
    }
}

impl PermanentFileCandidate {
    fn capture(path: PathBuf, state_dir: Option<&Path>) -> Result<Self, DeleteError> {
        validate_path_shape(&path)?;
        reject_protected_path(&path, state_dir)?;
        ensure_no_protection_marker(&path)?;
        if path.file_name() == Some(OsStr::from_bytes(PROTECTION_MARKER)) {
            return Err(DeleteError::ProtectionMarker(path));
        }

        let parent_path = path.parent().ok_or(DeleteError::InvalidPath)?.to_path_buf();
        let basename = safe_component(path.file_name().ok_or(DeleteError::InvalidPath)?)?;
        let parent = open_directory(&parent_path).map_err(DeleteError::Inspect)?;
        let parent_identity = identity_for_fd(&parent).map_err(DeleteError::Inspect)?;
        let object = open_regular_file_at(&parent, &basename).map_err(DeleteError::Inspect)?;
        let identity = identity_for_fd(&object).map_err(DeleteError::Inspect)?;
        if !identity.is_regular_file() {
            return Err(DeleteError::UnsupportedType);
        }
        if identity.hard_link_count != 1 {
            return Err(DeleteError::MultipleHardLinks);
        }
        ensure_supported_local_filesystem(&identity)?;
        // A same-user preview must not become a way to unlink somebody else's writable entry.
        if identity.uid != current_euid() {
            return Err(DeleteError::OwnershipMismatch);
        }
        if identity.mount_id != parent_identity.mount_id {
            return Err(DeleteError::ProtectedPath);
        }
        Ok(Self {
            path,
            parent_path,
            basename,
            parent,
            object,
            parent_identity,
            identity,
        })
    }

    fn plan(&self) -> PermanentFilePlan {
        PermanentFilePlan {
            schema: FILE_PLAN_SCHEMA,
            created_at_unix_nanos: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_nanos().to_string())
                .unwrap_or_else(|_| "invalid-clock".to_string()),
            mode: "permanent",
            action_count: 1,
            path: self.path.display().to_string(),
            path_bytes: self.path.as_os_str().as_bytes().to_vec(),
            parent: self.parent_path.display().to_string(),
            parent_bytes: self.parent_path.as_os_str().as_bytes().to_vec(),
            basename_bytes: self.basename[..self.basename.len() - 1].to_vec(),
            parent_device: self.parent_identity.device.to_string(),
            parent_inode: self.parent_identity.inode.to_string(),
            parent_mount_id: self.parent_identity.mount_id.to_string(),
            device: self.identity.device.to_string(),
            inode: self.identity.inode.to_string(),
            mount_id: self.identity.mount_id.to_string(),
            filesystem_magic: format!("0x{:x}", self.identity.filesystem_magic),
            owner_uid: self.identity.uid.to_string(),
            mode_bits: self.identity.mode,
            hard_link_count: self.identity.hard_link_count.to_string(),
            size_bytes: self.identity.size.to_string(),
            modified_unix_seconds: self.identity.modified_seconds,
            modified_nanoseconds: self.identity.modified_nanoseconds,
            status_change_unix_seconds: self.identity.changed_seconds,
            status_change_nanoseconds: self.identity.changed_nanoseconds,
            policy_version: POLICY_VERSION,
            adapter_version: ADAPTER_VERSION,
            irreversible: true,
            secure_erase: false,
        }
    }

    fn submit(
        self,
        state_dir: &Path,
        audit: &AuditStore,
        digest: &str,
        approval_started: Instant,
    ) -> Result<(), DeleteError> {
        if approval_started.elapsed() >= APPROVAL_TTL {
            return Err(DeleteError::ConfirmationExpired);
        }
        self.revalidate(Some(state_dir))?;
        let binding = audit_binding(digest, ["action-000000".to_string()])?;
        let authorization_id = binding.authorization_id.clone();
        let plan_digest = binding.plan_digest.clone();
        audit
            .register_native_authorization(RegisterAuthorization { binding })
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        let mut claim = audit
            .claim_execution(&authorization_id, &plan_digest)
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        let token = audit
            .reserve_intent(
                &claim,
                IntentRequest {
                    item_id: ItemId::new("item-0001").map_err(audit_error)?,
                    action_id: ActionId::new("action-000000").map_err(audit_error)?,
                    source_path_hash: hash_native_path(&self.path).map_err(audit_error)?,
                    before_revalidation_digest: DigestString::new(format!(
                        "sha256:{}",
                        sweepx_canonical::plan_digest_hex(&self.identity)
                            .map_err(|error| DeleteError::Audit(error.to_string()))?
                    ))
                    .map_err(audit_error)?,
                },
            )
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        let armed = audit
            .arm_native_intent(&mut claim, token)
            .map_err(|error| DeleteError::Audit(error.to_string()))?;

        // The audit authority remains armed across final preflight and the platform call. The
        // retained parent descriptor and exact basename, never the display path, are authority.
        armed
            .validate_in_memory_current_process()
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        if let Err(error) = self.final_revalidate(Some(state_dir)) {
            let at = SystemTime::now();
            let token = armed.into_durable_intent();
            // No platform call has happened. The audit schema has no stale-target terminal state,
            // so preserve the contradiction as indeterminate rather than claiming source identity.
            let outcome = ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                at,
                at,
                Observation {
                    exists: true,
                    identity: None,
                },
                vec![format!(
                    "final preflight refused before unlinkat submission: {error}"
                )],
            )
            .map_err(audit_error)?;
            audit
                .record_outcome(&claim, &token, outcome)
                .map_err(|audit_error| DeleteError::Audit(audit_error.to_string()))?;
            audit
                .consume_execution(&claim)
                .map_err(|audit_error| DeleteError::Audit(audit_error.to_string()))?;
            return Err(error);
        }
        if approval_started.elapsed() >= APPROVAL_TTL {
            let at = SystemTime::now();
            let token = armed.into_durable_intent();
            let outcome = ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                at,
                at,
                Observation {
                    exists: true,
                    identity: Some(identity_text(&self.identity)),
                },
                vec!["approval expired before unlinkat submission".to_string()],
            )
            .map_err(audit_error)?;
            audit
                .record_outcome(&claim, &token, outcome)
                .map_err(|audit_error| DeleteError::Audit(audit_error.to_string()))?;
            audit
                .consume_execution(&claim)
                .map_err(|audit_error| DeleteError::Audit(audit_error.to_string()))?;
            return Err(DeleteError::ConfirmationExpired);
        }
        let started_at = SystemTime::now();
        // SAFETY: parent is a retained directory descriptor and basename is one validated,
        // NUL-terminated component. No recursive or path-following operation is requested.
        let unlink_result =
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.basename.as_ptr().cast(), 0) };
        let backend_error = (unlink_result != 0).then(io::Error::last_os_error);
        let sync_error = if backend_error.is_none() {
            File::from(self.parent.try_clone().map_err(DeleteError::Inspect)?)
                .sync_all()
                .err()
        } else {
            None
        };
        let finished_at = SystemTime::now();
        let token = armed.into_durable_intent();
        let observed = metadata_at(&self.parent, &self.basename);
        let source_postcheck = match &observed {
            Ok(current) => Observation {
                exists: true,
                identity: Some(identity_text(current)),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Observation {
                exists: false,
                identity: None,
            },
            Err(_) => Observation {
                exists: true,
                identity: None,
            },
        };
        let outcome = if let Some(error) = &backend_error {
            ActionOutcome::native_permanent_failure(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck.clone(),
                matches!(&observed, Ok(current) if current == &self.identity),
                "errno",
                error.raw_os_error().unwrap_or(-1).to_string(),
                "unlinkat_failed",
                vec!["single-file permanent preview".to_string()],
            )
        } else if let Some(error) = &sync_error {
            ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                vec![format!(
                    "parent directory fsync failed after unlinkat: {error}"
                )],
            )
        } else if !source_postcheck.exists {
            ActionOutcome::native_permanent_success(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                "unlinkat_succeeded",
                vec!["single-file permanent preview; not secure erase".to_string()],
            )
        } else {
            ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                vec!["unlinkat returned success but postcheck observed the basename".to_string()],
            )
        }
        .map_err(audit_error)?;
        audit
            .record_outcome(&claim, &token, outcome)
            .map_err(|error| DeleteError::PostSubmitAudit(error.to_string()))?;
        audit
            .consume_execution(&claim)
            .map_err(|error| DeleteError::PostSubmitAudit(error.to_string()))?;

        match (backend_error, sync_error, observed) {
            (Some(error), _, Ok(current)) if current == self.identity => {
                Err(DeleteError::Backend(error))
            }
            (Some(_), _, _) => Err(DeleteError::OutcomeUnknown),
            (None, Some(_), _) => Err(DeleteError::OutcomeUnknown),
            (None, None, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            (None, None, _) => Err(DeleteError::OutcomeUnknown),
        }
    }

    fn revalidate(&self, state_dir: Option<&Path>) -> Result<(), DeleteError> {
        self.final_revalidate(state_dir)
    }

    fn final_revalidate(&self, state_dir: Option<&Path>) -> Result<(), DeleteError> {
        reject_protected_path(&self.path, state_dir)?;
        ensure_no_protection_marker(&self.path)?;
        let current_parent = identity_for_fd(&self.parent).map_err(DeleteError::Inspect)?;
        if !current_parent.same_object(&self.parent_identity) {
            return Err(DeleteError::TargetChanged);
        }
        let reopened_parent = open_directory(&self.parent_path).map_err(DeleteError::Inspect)?;
        if !identity_for_fd(&reopened_parent)
            .map_err(DeleteError::Inspect)?
            .same_object(&current_parent)
        {
            return Err(DeleteError::TargetChanged);
        }
        let current = metadata_at(&self.parent, &self.basename).map_err(DeleteError::Inspect)?;
        if current != self.identity {
            return Err(DeleteError::TargetChanged);
        }
        if identity_for_fd(&self.object).map_err(DeleteError::Inspect)? != self.identity {
            return Err(DeleteError::TargetChanged);
        }
        Ok(())
    }
}

impl PermanentDirectoryCandidate {
    fn capture(path: PathBuf, state_dir: Option<&Path>) -> Result<Self, DeleteError> {
        validate_path_shape(&path)?;
        reject_protected_path(&path, state_dir)?;
        ensure_no_protection_marker(&path)?;
        if path.file_name() == Some(OsStr::from_bytes(PROTECTION_MARKER)) {
            return Err(DeleteError::ProtectionMarker(path));
        }

        let parent_path = path.parent().ok_or(DeleteError::InvalidPath)?.to_path_buf();
        let basename = safe_component(path.file_name().ok_or(DeleteError::InvalidPath)?)?;
        let parent = open_directory(&parent_path).map_err(DeleteError::Inspect)?;
        let parent_identity = identity_for_fd(&parent).map_err(DeleteError::Inspect)?;
        let root = open_child_directory(&parent, path.file_name().ok_or(DeleteError::InvalidPath)?)
            .map_err(DeleteError::Inspect)?;
        let root_identity = identity_for_fd(&root).map_err(DeleteError::Inspect)?;
        validate_directory_identity(&root_identity, &parent_identity)?;

        let actions = capture_directory_manifest(&path, &root, &root_identity)?;
        Ok(Self {
            path,
            parent_path,
            basename,
            parent,
            root,
            parent_identity,
            root_identity,
            actions,
        })
    }

    fn plan(&self) -> PermanentDirectoryPlan {
        let logical_bytes = self
            .actions
            .iter()
            .filter(|action| action.object_type == PlannedObjectType::File)
            .fold(0_u128, |sum, action| {
                sum.saturating_add(u128::from(action.identity.size))
            });
        PermanentDirectoryPlan {
            schema: DIRECTORY_PLAN_SCHEMA,
            created_at_unix_nanos: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_nanos().to_string())
                .unwrap_or_else(|_| "invalid-clock".to_string()),
            mode: "permanent",
            path: self.path.display().to_string(),
            path_bytes: self.path.as_os_str().as_bytes().to_vec(),
            parent: self.parent_path.display().to_string(),
            parent_bytes: self.parent_path.as_os_str().as_bytes().to_vec(),
            basename_bytes: self.basename[..self.basename.len() - 1].to_vec(),
            parent_device: self.parent_identity.device.to_string(),
            parent_inode: self.parent_identity.inode.to_string(),
            parent_mount_id: self.parent_identity.mount_id.to_string(),
            logical_bytes: logical_bytes.to_string(),
            action_count: self.actions.len(),
            actions: self
                .actions
                .iter()
                .map(|action| PermanentDirectoryPlanAction {
                    action_id: action.action_id.clone(),
                    relative_components: action.relative_components.clone(),
                    display_path: action.display_path.display().to_string(),
                    object_type: action.object_type,
                    identity: action.identity.clone(),
                })
                .collect(),
            policy_version: POLICY_VERSION,
            adapter_version: ADAPTER_VERSION,
            irreversible: true,
            secure_erase: false,
        }
    }

    fn submit(
        self,
        state_dir: &Path,
        audit: &AuditStore,
        digest: &str,
        approval_started: Instant,
    ) -> Result<(), DeleteError> {
        if approval_started.elapsed() >= APPROVAL_TTL {
            return Err(DeleteError::ConfirmationExpired);
        }
        self.revalidate_manifest(Some(state_dir))?;
        let binding = audit_binding(
            digest,
            self.actions.iter().map(|action| action.action_id.clone()),
        )?;
        let authorization_id = binding.authorization_id.clone();
        let plan_digest = binding.plan_digest.clone();
        audit
            .register_native_authorization(RegisterAuthorization { binding })
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        let mut claim = audit
            .claim_execution(&authorization_id, &plan_digest)
            .map_err(|error| DeleteError::Audit(error.to_string()))?;

        let total = self.actions.len();
        let mut completed = 0_usize;
        for action in &self.actions {
            let action_result =
                self.execute_action(state_dir, audit, &mut claim, action, approval_started);
            match action_result {
                Ok(()) => completed += 1,
                Err(error) => {
                    if let Err(finalize_error) = record_remaining_actions_not_submitted(
                        audit,
                        &mut claim,
                        &self.actions[completed + 1..],
                        "skipped after an earlier directory manifest action stopped",
                    ) {
                        return Err(DeleteError::PostSubmitAudit(format!(
                            "{error}; additionally failed to close later audit actions: {finalize_error}"
                        )));
                    }
                    audit.consume_execution(&claim).map_err(|audit_error| {
                        DeleteError::PostSubmitAudit(audit_error.to_string())
                    })?;
                    return Err(DeleteError::Partial {
                        completed,
                        total,
                        detail: error.to_string(),
                    });
                }
            }
        }
        audit
            .consume_execution(&claim)
            .map_err(|error| DeleteError::PostSubmitAudit(error.to_string()))?;
        Ok(())
    }

    fn revalidate_manifest(&self, state_dir: Option<&Path>) -> Result<(), DeleteError> {
        reject_protected_path(&self.path, state_dir)?;
        ensure_no_protection_marker(&self.path)?;
        let current_parent = identity_for_fd(&self.parent).map_err(DeleteError::Inspect)?;
        if !current_parent.same_object(&self.parent_identity) {
            return Err(DeleteError::TargetChanged);
        }
        let reopened_parent = open_directory(&self.parent_path).map_err(DeleteError::Inspect)?;
        if !identity_for_fd(&reopened_parent)
            .map_err(DeleteError::Inspect)?
            .same_object(&current_parent)
        {
            return Err(DeleteError::TargetChanged);
        }
        let current_root = identity_for_fd(&self.root).map_err(DeleteError::Inspect)?;
        if current_root != self.root_identity {
            return Err(DeleteError::TargetChanged);
        }
        let live_actions = capture_directory_manifest(&self.path, &self.root, &self.root_identity)?;
        if live_actions != self.actions {
            return Err(DeleteError::TargetChanged);
        }
        Ok(())
    }

    fn execute_action(
        &self,
        state_dir: &Path,
        audit: &AuditStore,
        claim: &mut sweepx_audit::ClaimedExecution,
        action: &DirectoryAction,
        approval_started: Instant,
    ) -> Result<(), DeleteError> {
        let source_hash = hash_native_path(&action.display_path).map_err(audit_error)?;
        let revalidation_digest = DigestString::new(format!(
            "sha256:{}",
            sweepx_canonical::plan_digest_hex(&action.identity)
                .map_err(|error| DeleteError::Audit(error.to_string()))?
        ))
        .map_err(audit_error)?;
        let token = audit
            .reserve_intent(
                claim,
                IntentRequest {
                    item_id: ItemId::new("item-0001").map_err(audit_error)?,
                    action_id: ActionId::new(action.action_id.clone()).map_err(audit_error)?,
                    source_path_hash: source_hash,
                    before_revalidation_digest: revalidation_digest,
                },
            )
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        let armed = audit
            .arm_native_intent(claim, token)
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        armed
            .validate_in_memory_current_process()
            .map_err(|error| DeleteError::Audit(error.to_string()))?;

        let prepared = match self.prepare_action(state_dir, action) {
            Ok(prepared) if approval_started.elapsed() < APPROVAL_TTL => prepared,
            Ok(prepared) => {
                let token = armed.into_durable_intent();
                record_not_submitted(
                    audit,
                    claim,
                    &token,
                    Some(&prepared.current),
                    "approval expired before directory action submission",
                )?;
                return Err(DeleteError::ConfirmationExpired);
            }
            Err(error) => {
                let token = armed.into_durable_intent();
                record_not_submitted(
                    audit,
                    claim,
                    &token,
                    None,
                    &format!("directory action final preflight refused: {error}"),
                )?;
                return Err(error);
            }
        };

        let flags = if action.object_type == PlannedObjectType::Directory {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        let started_at = SystemTime::now();
        // SAFETY: prepared holds the exact revalidated parent descriptor and a validated,
        // NUL-terminated basename. The flag selects only unlink or nonrecursive rmdir.
        let unlink_result = unsafe {
            libc::unlinkat(
                prepared.parent.as_raw_fd(),
                prepared.basename.as_ptr().cast(),
                flags,
            )
        };
        let backend_error = (unlink_result != 0).then(io::Error::last_os_error);
        let sync_error = if backend_error.is_none() {
            File::from(prepared.parent.try_clone().map_err(DeleteError::Inspect)?)
                .sync_all()
                .err()
        } else {
            None
        };
        let finished_at = SystemTime::now();
        let token = armed.into_durable_intent();
        let observed = metadata_at(&prepared.parent, &prepared.basename);
        let source_postcheck = observation_from_metadata(&observed);
        let outcome = if let Some(error) = &backend_error {
            ActionOutcome::native_permanent_failure(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck.clone(),
                matches!(&observed, Ok(current) if action_identity_matches(action, current)),
                "errno",
                error.raw_os_error().unwrap_or(-1).to_string(),
                "unlinkat_failed",
                vec![format!("directory manifest action {}", action.action_id)],
            )
        } else if let Some(error) = &sync_error {
            ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                vec![format!(
                    "parent directory fsync failed after unlinkat: {error}"
                )],
            )
        } else if !source_postcheck.exists {
            ActionOutcome::native_permanent_success(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                "unlinkat_succeeded",
                vec![format!("directory manifest action {}", action.action_id)],
            )
        } else {
            ActionOutcome::native_permanent_indeterminate(
                ADAPTER_VERSION,
                started_at,
                finished_at,
                source_postcheck,
                vec!["unlinkat returned success but postcheck observed the basename".to_string()],
            )
        }
        .map_err(audit_error)?;
        audit
            .record_outcome(claim, &token, outcome)
            .map_err(|error| DeleteError::PostSubmitAudit(error.to_string()))?;

        match (backend_error, sync_error, observed) {
            (Some(error), _, Ok(current)) if action_identity_matches(action, &current) => {
                Err(DeleteError::Backend(error))
            }
            (Some(_), _, _) | (None, Some(_), _) => Err(DeleteError::OutcomeUnknown),
            (None, None, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            (None, None, _) => Err(DeleteError::OutcomeUnknown),
        }
    }

    fn prepare_action(
        &self,
        state_dir: &Path,
        action: &DirectoryAction,
    ) -> Result<PreparedDirectoryAction, DeleteError> {
        reject_protected_path(&self.path, Some(state_dir))?;
        ensure_no_protection_marker(&self.path)?;
        self.verify_root_binding()?;
        ensure_marker_absent(&self.root, &self.path)?;
        if action.relative_components.is_empty() {
            let current =
                metadata_at(&self.parent, &self.basename).map_err(DeleteError::Inspect)?;
            if !action_identity_matches(action, &current) {
                return Err(DeleteError::TargetChanged);
            }
            return Ok(PreparedDirectoryAction {
                parent: self.parent.try_clone().map_err(DeleteError::Inspect)?,
                basename: self.basename.clone(),
                current,
            });
        }

        let mut parent = self.root.try_clone().map_err(DeleteError::Inspect)?;
        let parent_components = &action.relative_components[..action.relative_components.len() - 1];
        let mut opened_components = Vec::new();
        for component in parent_components {
            parent = open_child_directory(&parent, OsStr::from_bytes(component))
                .map_err(DeleteError::Inspect)?;
            opened_components.push(component.clone());
            let expected = self
                .actions
                .iter()
                .find(|candidate| {
                    candidate.object_type == PlannedObjectType::Directory
                        && candidate.relative_components == opened_components
                })
                .ok_or(DeleteError::TargetChanged)?;
            let observed = identity_for_fd(&parent).map_err(DeleteError::Inspect)?;
            if !action_identity_matches(expected, &observed) {
                return Err(DeleteError::TargetChanged);
            }
            ensure_marker_absent(
                &parent,
                &root_path_from_relative(&self.path, &opened_components),
            )?;
        }
        let basename = safe_component(OsStr::from_bytes(
            action
                .relative_components
                .last()
                .expect("non-root action has basename"),
        ))?;
        let current = metadata_at(&parent, &basename).map_err(DeleteError::Inspect)?;
        if !action_identity_matches(action, &current) {
            return Err(DeleteError::TargetChanged);
        }
        if action.object_type == PlannedObjectType::Directory {
            let target_directory = open_child_directory(
                &parent,
                OsStr::from_bytes(
                    action
                        .relative_components
                        .last()
                        .expect("non-root action has basename"),
                ),
            )
            .map_err(DeleteError::Inspect)?;
            ensure_marker_absent(&target_directory, &action.display_path)?;
        }
        Ok(PreparedDirectoryAction {
            parent,
            basename,
            current,
        })
    }

    fn verify_root_binding(&self) -> Result<(), DeleteError> {
        let parent = identity_for_fd(&self.parent).map_err(DeleteError::Inspect)?;
        if !parent.same_object(&self.parent_identity) {
            return Err(DeleteError::TargetChanged);
        }
        let reopened_parent = open_directory(&self.parent_path).map_err(DeleteError::Inspect)?;
        if !identity_for_fd(&reopened_parent)
            .map_err(DeleteError::Inspect)?
            .same_object(&self.parent_identity)
        {
            return Err(DeleteError::TargetChanged);
        }
        let root = identity_for_fd(&self.root).map_err(DeleteError::Inspect)?;
        if !root.same_object(&self.root_identity) {
            return Err(DeleteError::TargetChanged);
        }
        let named = metadata_at(&self.parent, &self.basename).map_err(DeleteError::Inspect)?;
        if !named.same_object(&self.root_identity) {
            return Err(DeleteError::TargetChanged);
        }
        Ok(())
    }
}

fn record_remaining_actions_not_submitted(
    audit: &AuditStore,
    claim: &mut sweepx_audit::ClaimedExecution,
    actions: &[DirectoryAction],
    note: &str,
) -> Result<(), DeleteError> {
    for action in actions {
        let token = audit
            .reserve_intent(
                claim,
                IntentRequest {
                    item_id: ItemId::new("item-0001").map_err(audit_error)?,
                    action_id: ActionId::new(action.action_id.clone()).map_err(audit_error)?,
                    source_path_hash: hash_native_path(&action.display_path)
                        .map_err(audit_error)?,
                    before_revalidation_digest: DigestString::new(format!(
                        "sha256:{}",
                        sweepx_canonical::plan_digest_hex(&action.identity)
                            .map_err(|error| DeleteError::Audit(error.to_string()))?
                    ))
                    .map_err(audit_error)?,
                },
            )
            .map_err(|error| DeleteError::Audit(error.to_string()))?;
        record_not_submitted(audit, claim, &token, None, note)?;
    }
    Ok(())
}

fn action_identity_matches(action: &DirectoryAction, current: &FileIdentity) -> bool {
    match action.object_type {
        PlannedObjectType::File => current == &action.identity,
        // Removing approved children necessarily changes a directory's ctime, mtime, size and
        // link count. The directory action therefore binds the native object, mount, filesystem,
        // owner and type while the exact child set is enforced separately by nonrecursive rmdir.
        PlannedObjectType::Directory => {
            current.same_object(&action.identity)
                && current.filesystem_magic == action.identity.filesystem_magic
                && current.uid == action.identity.uid
                && current.mode & libc::S_IFMT == libc::S_IFDIR
        }
    }
}

#[derive(Debug)]
struct PreparedDirectoryAction {
    parent: OwnedFd,
    basename: Vec<u8>,
    current: FileIdentity,
}

fn observation_from_metadata(observed: &io::Result<FileIdentity>) -> Observation {
    match observed {
        Ok(current) => Observation {
            exists: true,
            identity: Some(identity_text(current)),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Observation {
            exists: false,
            identity: None,
        },
        Err(_) => Observation {
            exists: true,
            identity: None,
        },
    }
}

fn record_not_submitted(
    audit: &AuditStore,
    claim: &sweepx_audit::ClaimedExecution,
    token: &sweepx_audit::DurableIntentToken,
    current: Option<&FileIdentity>,
    note: &str,
) -> Result<(), DeleteError> {
    let outcome = ActionOutcome::native_permanent_not_submitted(
        ADAPTER_VERSION,
        SystemTime::now(),
        Observation {
            // `None` means the caller could not prove the later action's current identity; it
            // does not prove absence. Keep the action indeterminate instead of inventing vanish.
            exists: true,
            identity: current.map(identity_text),
        },
        vec![note.to_string()],
    )
    .map_err(audit_error)?;
    audit
        .record_outcome(claim, token, outcome)
        .map_err(|error| DeleteError::Audit(error.to_string()))
}

fn validate_directory_identity(
    identity: &FileIdentity,
    parent_identity: &FileIdentity,
) -> Result<(), DeleteError> {
    if identity.mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(DeleteError::UnsupportedType);
    }
    ensure_supported_local_filesystem(identity)?;
    if identity.uid != current_euid() {
        return Err(DeleteError::OwnershipMismatch);
    }
    if identity.mount_id != parent_identity.mount_id {
        return Err(DeleteError::ProtectedPath);
    }
    Ok(())
}

fn capture_directory_manifest(
    root_path: &Path,
    root: &OwnedFd,
    root_identity: &FileIdentity,
) -> Result<Vec<DirectoryAction>, DeleteError> {
    let mut actions = Vec::new();
    let mut visited = HashSet::new();
    visited.insert((
        root_identity.mount_id,
        root_identity.device,
        root_identity.inode,
    ));
    let mut retained_path_bytes = 0_usize;
    capture_directory_postorder(
        root_path,
        root,
        root_identity,
        Vec::new(),
        root_identity.clone(),
        &mut actions,
        &mut visited,
        &mut retained_path_bytes,
    )?;
    for (index, action) in actions.iter_mut().enumerate() {
        action.action_id = format!("action-{index:06}");
    }
    Ok(actions)
}

#[allow(clippy::too_many_arguments)]
fn capture_directory_postorder(
    root_path: &Path,
    directory: &OwnedFd,
    root_identity: &FileIdentity,
    relative_components: Vec<Vec<u8>>,
    identity: FileIdentity,
    actions: &mut Vec<DirectoryAction>,
    visited: &mut HashSet<(u64, u64, u64)>,
    retained_path_bytes: &mut usize,
) -> Result<(), DeleteError> {
    if relative_components.len() > MAX_DIRECTORY_DEPTH {
        return Err(DeleteError::ResourceLimit("maximum depth"));
    }
    let display_path = root_path_from_relative(root_path, &relative_components);
    ensure_marker_absent(directory, &display_path)?;
    let mut children = read_directory_names(directory)?;
    children.sort();
    if actions
        .len()
        .saturating_add(children.len())
        .saturating_add(1)
        > MAX_DIRECTORY_ACTIONS
    {
        return Err(DeleteError::ResourceLimit("256-action"));
    }

    for name in children {
        let name_os = OsStr::from_bytes(&name);
        let mut child_relative = relative_components.clone();
        child_relative.push(name.clone());
        let child_display = root_path_from_relative(root_path, &child_relative);
        if name_os == OsStr::from_bytes(PROTECTION_MARKER) {
            return Err(DeleteError::ProtectionMarker(child_display));
        }
        let pinned = open_entry_at(directory, name_os).map_err(DeleteError::Inspect)?;
        let child_identity = identity_for_fd(&pinned).map_err(DeleteError::Inspect)?;
        if child_identity.mount_id != root_identity.mount_id
            || child_identity.device != root_identity.device
            || child_identity.filesystem_magic != root_identity.filesystem_magic
            || child_identity.uid != current_euid()
        {
            return Err(DeleteError::ProtectedPath);
        }
        if child_identity.mode & libc::S_IFMT == libc::S_IFREG {
            if child_identity.hard_link_count != 1 {
                return Err(DeleteError::MultipleHardLinks);
            }
            account_manifest_path(retained_path_bytes, &child_relative)?;
            ensure_action_capacity(actions)?;
            actions.push(DirectoryAction {
                action_id: String::new(),
                relative_components: child_relative,
                display_path: child_display,
                object_type: PlannedObjectType::File,
                identity: child_identity,
            });
        } else if child_identity.mode & libc::S_IFMT == libc::S_IFDIR {
            if !visited.insert((
                child_identity.mount_id,
                child_identity.device,
                child_identity.inode,
            )) {
                return Err(DeleteError::TargetChanged);
            }
            let child_directory =
                open_child_directory(directory, name_os).map_err(DeleteError::Inspect)?;
            let opened_identity =
                identity_for_fd(&child_directory).map_err(DeleteError::Inspect)?;
            if opened_identity != child_identity {
                return Err(DeleteError::TargetChanged);
            }
            capture_directory_postorder(
                root_path,
                &child_directory,
                root_identity,
                child_relative,
                child_identity,
                actions,
                visited,
                retained_path_bytes,
            )?;
        } else {
            return Err(DeleteError::UnsupportedType);
        }
    }
    account_manifest_path(retained_path_bytes, &relative_components)?;
    ensure_action_capacity(actions)?;
    actions.push(DirectoryAction {
        action_id: String::new(),
        relative_components,
        display_path,
        object_type: PlannedObjectType::Directory,
        identity,
    });
    Ok(())
}

fn account_manifest_path(
    retained_path_bytes: &mut usize,
    relative_components: &[Vec<u8>],
) -> Result<(), DeleteError> {
    let path_bytes = relative_components
        .iter()
        .try_fold(0_usize, |total, component| {
            total.checked_add(component.len().saturating_add(1))
        });
    *retained_path_bytes = retained_path_bytes
        .checked_add(path_bytes.ok_or(DeleteError::ResourceLimit("manifest path-byte"))?)
        .ok_or(DeleteError::ResourceLimit("manifest path-byte"))?;
    if *retained_path_bytes > MAX_MANIFEST_PATH_BYTES {
        Err(DeleteError::ResourceLimit("1 MiB manifest path-byte"))
    } else {
        Ok(())
    }
}

fn ensure_action_capacity(actions: &[DirectoryAction]) -> Result<(), DeleteError> {
    if actions.len() >= MAX_DIRECTORY_ACTIONS {
        Err(DeleteError::ResourceLimit("256-action"))
    } else {
        Ok(())
    }
}

fn root_path_from_relative(root: &Path, components: &[Vec<u8>]) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in components {
        path.push(OsStr::from_bytes(component));
    }
    path
}

fn persist_plan(audit_root: &Path, plan: &PermanentPlan, digest: &str) -> Result<(), DeleteError> {
    let path = audit_root.join(format!("plan-{digest}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| DeleteError::Audit(format!("create {}: {error}", path.display())))?;
    serde_json::to_writer_pretty(
        &mut file,
        &json!({
            "plan": plan,
            "canonicalDigest": digest,
            "risk": "r4",
            "recoverable": false,
            "secureErase": false,
        }),
    )
    .map_err(|error| DeleteError::Audit(format!("write {}: {error}", path.display())))?;
    file.write_all(b"\n")
        .and_then(|()| file.sync_all())
        .map_err(|error| DeleteError::Audit(format!("sync {}: {error}", path.display())))?;
    File::open(audit_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            DeleteError::Audit(format!(
                "sync audit directory {}: {error}",
                audit_root.display()
            ))
        })
}

fn prepare_audit(
    audit_root: &Path,
    state_dir: &Path,
    plan: &PermanentPlan,
    digest: &str,
) -> Result<AuditStore, DeleteError> {
    // Reuse Core's no-follow, owner-private state admission before creating the audit child.
    sweepx_core::durable_store(Some(state_dir))
        .map_err(|error| DeleteError::Audit(error.to_string()))?;
    let audit =
        AuditStore::open(audit_root).map_err(|error| DeleteError::Audit(error.to_string()))?;
    persist_plan(audit_root, plan, digest)?;
    Ok(audit)
}

fn audit_binding(
    digest: &str,
    raw_action_ids: impl IntoIterator<Item = String>,
) -> Result<AuthorizationBinding, DeleteError> {
    let mut item_ids = BTreeSet::new();
    item_ids.insert(ItemId::new("item-0001").map_err(audit_error)?);
    let mut action_ids = BTreeSet::new();
    let mut item_by_action = BTreeMap::new();
    let mut risk_by_action = BTreeMap::new();
    let item_id = ItemId::new("item-0001").map_err(audit_error)?;
    for action_id in raw_action_ids {
        let action = ActionId::new(action_id).map_err(audit_error)?;
        if !action_ids.insert(action.clone()) {
            return Err(DeleteError::Audit("duplicate plan action id".to_string()));
        }
        item_by_action.insert(action.clone(), item_id.clone());
        risk_by_action.insert(action, RiskTier::R4);
    }
    let action_count = action_ids.len() as u64;
    Ok(AuthorizationBinding {
        authorization_id: AuthorizationId::new(format!("permanent-{}", &digest[..32]))
            .map_err(audit_error)?,
        authorization_source: AuthorizationSource::HumanApproval,
        batch_id: BatchId::new(format!("batch-{}", &digest[..24])).map_err(audit_error)?,
        plan_id: PlanId::new(format!("plan-{}", &digest[..24])).map_err(audit_error)?,
        plan_digest: DigestString::new(format!("sha256:{digest}")).map_err(audit_error)?,
        requested_mode: RequestedMode::Permanent,
        item_ids,
        action_ids,
        action_count,
        item_by_action,
        risk_by_action,
        policy_version: POLICY_VERSION.to_string(),
        policy_digest: DigestString::new(format!("sha256:{digest}:policy")).map_err(audit_error)?,
        protected_anchor_snapshot_digest: DigestString::new(format!("sha256:{digest}:anchors"))
            .map_err(audit_error)?,
        adapter_capabilities_digest: DigestString::new(format!("sha256:{digest}:adapter"))
            .map_err(audit_error)?,
        cleaner_set_digest: DigestString::new(format!("sha256:{digest}:cleaners"))
            .map_err(audit_error)?,
        host_instance_id: HostId::new("local-host").map_err(audit_error)?,
        user_identity: UserId::new(format!("uid-{}", current_euid())).map_err(audit_error)?,
        workflow_session: SessionId::new(format!("terminal-{}", std::process::id()))
            .map_err(audit_error)?,
    })
}

fn audit_error(error: sweepx_audit::AuditError) -> DeleteError {
    DeleteError::Audit(error.to_string())
}

fn validate_path_shape(path: &Path) -> Result<(), DeleteError> {
    if !path.is_absolute() || path.parent().is_none() || path.file_name().is_none() {
        return Err(DeleteError::InvalidPath);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DeleteError::InvalidPath);
    }
    let canonical = path.canonicalize().map_err(DeleteError::Inspect)?;
    if canonical != path {
        return Err(DeleteError::NonCanonicalPath);
    }
    Ok(())
}

fn reject_protected_path(path: &Path, state_dir: Option<&Path>) -> Result<(), DeleteError> {
    let executable = std::env::current_exe().map_err(DeleteError::Inspect)?;
    let cwd = std::env::current_dir().map_err(DeleteError::Inspect)?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let exact = [
        Path::new("/"),
        Path::new("/home"),
        Path::new("/tmp"),
        Path::new("/var"),
    ];
    let trees = [
        "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys",
        "/usr", "/var",
    ];
    if exact.contains(&path)
        || trees.iter().any(|protected| path.starts_with(protected))
        || executable.starts_with(path)
        || cwd.starts_with(path)
        || home.as_ref().is_some_and(|home| path == home)
        || state_dir.is_some_and(|state| path.starts_with(state) || state.starts_with(path))
        || protected_user_trees(&home)
            .iter()
            .any(|protected| path.starts_with(protected) || protected.starts_with(path))
    {
        return Err(DeleteError::ProtectedPath);
    }
    Ok(())
}

fn protected_user_trees(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut protected = Vec::new();
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from) {
        protected.push(state_home.join("sweepx"));
    } else if let Some(home) = home {
        protected.push(home.join(".local/state/sweepx"));
    }
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        protected.push(data_home.join("Trash"));
    } else if let Some(home) = home {
        protected.push(home.join(".local/share/Trash"));
    }
    protected
}

fn ensure_no_protection_marker(path: &Path) -> Result<(), DeleteError> {
    let mut current = PathBuf::from("/");
    let mut directory = open_directory(&current).map_err(DeleteError::Inspect)?;
    ensure_marker_absent(&directory, &current)?;
    for component in path.parent().ok_or(DeleteError::InvalidPath)?.components() {
        if matches!(component, Component::RootDir) {
            continue;
        }
        let Component::Normal(name) = component else {
            return Err(DeleteError::InvalidPath);
        };
        current.push(name);
        directory = open_child_directory(&directory, name).map_err(DeleteError::Inspect)?;
        ensure_marker_absent(&directory, &current)?;
    }
    Ok(())
}

fn ensure_marker_absent(directory: &OwnedFd, display_path: &Path) -> Result<(), DeleteError> {
    let marker = safe_component(OsStr::from_bytes(PROTECTION_MARKER))?;
    // SAFETY: directory is live and marker is a validated NUL-terminated basename. O_NOFOLLOW
    // observes the marker entry itself, so even a symlink marker only adds protection.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            marker.as_ptr().cast(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: a nonnegative openat return value is a newly owned descriptor.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        return Err(DeleteError::ProtectionMarker(display_path.to_path_buf()));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(DeleteError::Inspect(error))
    }
}

fn open_child_directory(parent: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    let name = safe_component(name).map_err(|error| io::Error::other(error.to_string()))?;
    // SAFETY: parent is a live directory descriptor and name is one validated, NUL-terminated
    // component. O_NOFOLLOW forbids a symlink at this ancestry step.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_fd(fd)
}

fn open_entry_at(parent: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    let name = safe_component(name).map_err(|error| io::Error::other(error.to_string()))?;
    // SAFETY: parent is live and name is one validated, NUL-terminated component. O_NOFOLLOW
    // pins the directory entry itself and never follows a symlink target.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr().cast(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_fd(fd)
}

fn read_directory_names(directory: &OwnedFd) -> Result<Vec<Vec<u8>>, DeleteError> {
    // A dup shares the directory offset with the retained authority descriptor, so reopening `.`
    // is required for each snapshot. Otherwise a second revalidation would start at EOF and
    // falsely describe a non-empty directory as empty.
    // SAFETY: directory is live and the constant `.` is NUL terminated. The result is a fresh
    // directory descriptor with an independent enumeration offset.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(DeleteError::Inspect(io::Error::last_os_error()));
    }
    // SAFETY: raw is a fresh live directory descriptor. On success fdopendir takes ownership and
    // closedir below becomes its sole closer.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        // SAFETY: fdopendir failed and did not consume the valid descriptor.
        unsafe { libc::close(raw) };
        return Err(DeleteError::Inspect(io::Error::last_os_error()));
    }
    let mut names = Vec::new();
    let result = loop {
        if names.len() >= MAX_DIRECTORY_ACTIONS {
            break Err(DeleteError::ResourceLimit("256-action"));
        }
        // SAFETY: errno location belongs to this thread. Clearing it distinguishes EOF from error.
        unsafe {
            *libc::__errno_location() = 0;
        }
        // SAFETY: stream is live and used only by this loop.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(DeleteError::Inspect(error))
            };
        }
        // SAFETY: readdir returned a valid dirent with a NUL-terminated d_name.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        names.push(name.to_vec());
    };
    // SAFETY: stream was returned by fdopendir and is closed exactly once here.
    unsafe { libc::closedir(stream) };
    result.map(|()| names)
}

fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let raw = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: open_how is a plain Linux kernel ABI structure initialized before the syscall.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags =
        u64::try_from(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .expect("Linux open flags fit u64");
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: raw is a live NUL-terminated path and how points to initialized storage.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            raw.as_ptr(),
            &mut how,
            std::mem::size_of::<libc::open_how>(),
        ) as libc::c_int
    };
    owned_fd(fd)
}

fn open_regular_file_at(parent: &OwnedFd, basename: &[u8]) -> io::Result<OwnedFd> {
    // SAFETY: parent is live and basename is one validated, NUL-terminated component. O_PATH
    // pins the directory entry without reading or modifying file contents.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            basename.as_ptr().cast(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_fd(fd)
}

fn metadata_at(parent: &OwnedFd, basename: &[u8]) -> io::Result<FileIdentity> {
    // SAFETY: parent is live and basename is one validated, NUL-terminated component.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            basename.as_ptr().cast(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let fd = owned_fd(fd)?;
    identity_for_fd(&fd)
}

fn identity_for_fd(fd: &OwnedFd) -> io::Result<FileIdentity> {
    let metadata = File::from(fd.try_clone()?).metadata()?;
    let mut statx = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: fd is live, the empty C string requests that descriptor through AT_EMPTY_PATH, and
    // statx points to writable storage.
    if unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            statx.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful statx initialized the output.
    let statx = unsafe { statx.assume_init() };
    if statx.stx_mask & libc::STATX_MNT_ID != libc::STATX_MNT_ID {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "statx did not report mount identity",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount_id: statx.stx_mnt_id,
        filesystem_magic: filesystem_magic(fd)?,
        uid: metadata.uid(),
        mode: metadata.mode(),
        hard_link_count: metadata.nlink(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

impl FileIdentity {
    fn is_regular_file(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }

    fn same_object(&self, other: &Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.mount_id == other.mount_id
            && self.mode & libc::S_IFMT == other.mode & libc::S_IFMT
    }
}

fn filesystem_magic(fd: &OwnedFd) -> io::Result<i64> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fd is live and stat points to writable storage.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the output.
    Ok(unsafe { stat.assume_init() }.f_type)
}

fn ensure_supported_local_filesystem(identity: &FileIdentity) -> Result<(), DeleteError> {
    let filesystem = u64::try_from(identity.filesystem_magic).unwrap_or_default();
    const KNOWN_LOCAL: &[u64] = &[
        0x0000_ef53, // ext2/3/4
        0x5846_5342, // XFS
        0x9123_683e, // Btrfs
        0xf2f5_2010, // F2FS
    ];
    if KNOWN_LOCAL.contains(&filesystem) {
        Ok(())
    } else {
        Err(DeleteError::UnsupportedFilesystem)
    }
}

fn identity_text(identity: &FileIdentity) -> String {
    format!(
        "dev:{}:ino:{}:mnt:{}",
        identity.device, identity.inode, identity.mount_id
    )
}

fn safe_component(name: &OsStr) -> Result<Vec<u8>, DeleteError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(DeleteError::InvalidPath);
    }
    let mut terminated = bytes.to_vec();
    terminated.push(0);
    Ok(terminated)
}

fn owned_fd(raw: libc::c_int) -> io::Result<OwnedFd> {
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a nonnegative open-style return value is a newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and only reads process credentials.
    unsafe { libc::geteuid() }
}

fn is_elevated_runtime() -> bool {
    if current_euid() == 0 {
        return true;
    }
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
        .any(|value| value.is_none_or(|value| value.bytes().any(|byte| byte != b'0')))
}

fn is_foreground_terminal() -> bool {
    // SAFETY: tcgetpgrp/getpgrp only inspect this process and its controlling terminal state.
    let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
    foreground >= 0 && foreground == unsafe { libc::getpgrp() }
}

fn print_plan(locale: Locale, plan: &PermanentPlan, digest: &str) {
    let fingerprint = sweepx_canonical::attention_fingerprint_from_digest_hex(digest);
    let path = terminal_text(plan.path());
    let target_kind = match plan {
        PermanentPlan::File(_) => "file",
        PermanentPlan::Directory(_) => "directory",
    };
    match locale {
        Locale::ZhCn => {
            println!("永久删除计划（不可恢复，不是安全擦除）");
            println!("  类型：{target_kind}");
            println!("  路径：{path}");
            println!("  动作：{} 个", plan.action_count());
            println!("  大小：{} 字节", plan.size_bytes());
            println!("  风险：R4");
            println!("  计划指纹：{fingerprint}");
            println!("  完整计划摘要：{digest}");
        }
        Locale::EnUs => {
            println!("Permanent deletion plan (irreversible; not secure erase)");
            println!("  type: {target_kind}");
            println!("  path: {path}");
            println!("  actions: {}", plan.action_count());
            println!("  size: {} bytes", plan.size_bytes());
            println!("  risk: R4");
            println!("  plan fingerprint: {fingerprint}");
            println!("  full plan digest: {digest}");
        }
    }
    if let PermanentPlan::Directory(directory) = plan {
        for action in &directory.actions {
            println!(
                "  [{}] {:?}: {}",
                action.action_id,
                action.object_type,
                terminal_text(&action.display_path)
            );
        }
    }
}

fn terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn confirm_digest<R: BufRead, W: Write>(
    digest: &str,
    action_count: usize,
    reader: R,
    mut writer: W,
) -> bool {
    let challenge = format!("PERMANENT 1 {action_count} {digest}");
    let _ = write!(writer, "Type `{challenge}` to delete this exact target: ");
    let _ = writer.flush();
    let mut answer = String::new();
    let read = reader.take(MAX_CONFIRMATION_BYTES).read_line(&mut answer);
    if read.is_err() {
        return false;
    }
    let answer = answer.strip_suffix('\n').unwrap_or(&answer);
    let answer = answer.strip_suffix('\r').unwrap_or(answer);
    answer == challenge
}

fn print_result(
    format: OutputFormat,
    locale: Locale,
    path: Option<&Path>,
    digest: Option<&str>,
    result: Result<(), DeleteError>,
) -> ProcessExitCode {
    let path = path.map(|path| terminal_text(&path.display().to_string()));
    match result {
        Ok(()) => {
            if format == OutputFormat::Human {
                println!(
                    "{}",
                    match locale {
                        Locale::ZhCn => format!(
                            "已永久删除：{}\n此操作绕过回收站，但不等同于安全擦除。",
                            path.as_deref().unwrap_or("-")
                        ),
                        Locale::EnUs => format!(
                            "Permanently deleted: {}\nThis bypassed Trash, but was not secure erase.",
                            path.as_deref().unwrap_or("-")
                        ),
                    }
                );
            } else {
                println!(
                    "{}",
                    json!({
                        "schema": "sweepx.permanent-delete.result/v1",
                        "status": "ok",
                        "exitCode": 0,
                        "path": path,
                        "canonicalDigest": digest,
                        "recoverable": false,
                        "secureErase": false,
                    })
                );
            }
            ProcessExitCode::SUCCESS
        }
        Err(error) => {
            if format == OutputFormat::Human {
                eprintln!(
                    "{}",
                    match locale {
                        Locale::ZhCn => format!("永久删除已停止或需要核对：{error}"),
                        Locale::EnUs => {
                            format!("Permanent deletion stopped or needs reconciliation: {error}")
                        }
                    }
                );
            } else {
                println!(
                    "{}",
                    json!({
                        "schema": "sweepx.permanent-delete.result/v1",
                        "status": "failed",
                        "exitCode": 8,
                        "path": path,
                        "canonicalDigest": digest,
                        "recoverable": false,
                        "secureErase": false,
                        "error": error.to_string(),
                    })
                );
            }
            ProcessExitCode::from(8)
        }
    }
}

fn print_cancelled(locale: Locale, path: &Path, digest: &str) -> ProcessExitCode {
    println!(
        "{}",
        match locale {
            Locale::ZhCn => "已取消；文件未改动。",
            Locale::EnUs => "Cancelled; the file was not changed.",
        }
    );
    let _ = (path, digest);
    ProcessExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn exact_confirmation_rejects_near_matches() {
        let digest = "abc123";
        assert!(confirm_digest(
            digest,
            1,
            &b"PERMANENT 1 1 abc123\n"[..],
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            1,
            &b"permanent 1 1 abc123\n"[..],
            Vec::new()
        ));
        assert!(confirm_digest(
            digest,
            4,
            &b"PERMANENT 1 4 abc123\n"[..],
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            4,
            &b"PERMANENT 1 1 abc123\n"[..],
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            1,
            &b"PERMANENT 1 1 other\n"[..],
            Vec::new()
        ));
        assert!(!confirm_digest(
            digest,
            1,
            &b" PERMANENT 1 1 abc123\n"[..],
            Vec::new()
        ));
    }

    #[test]
    fn rejects_link_and_marker_protected_file() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let file = root.join("file");
        fs::write(&file, b"keep").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(matches!(
            PermanentFileCandidate::capture(link, None),
            Err(DeleteError::NonCanonicalPath)
        ));

        fs::write(root.join(".sweepx-protect"), b"").unwrap();
        assert!(matches!(
            PermanentFileCandidate::capture(file, None),
            Err(DeleteError::ProtectionMarker(_))
        ));
    }

    #[test]
    fn captured_file_rejects_replacement() {
        let fixture = TempDir::new().unwrap();
        let path = fixture.path().canonicalize().unwrap().join("file");
        fs::write(&path, b"first").unwrap();
        let candidate = PermanentFileCandidate::capture(path.clone(), None).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"second").unwrap();
        assert!(matches!(
            candidate.final_revalidate(None),
            Err(DeleteError::TargetChanged)
        ));
    }

    #[test]
    fn multiple_hard_links_are_refused() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let path = root.join("file");
        fs::write(&path, b"keep").unwrap();
        fs::hard_link(&path, root.join("other-name")).unwrap();

        assert!(matches!(
            PermanentFileCandidate::capture(path, None),
            Err(DeleteError::MultipleHardLinks)
        ));
    }

    #[test]
    fn resolved_absolute_path_guidance_is_actionable() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let file = root.join("file");
        fs::write(&file, b"keep").unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let error = PermanentCandidate::capture(link, None).unwrap_err();
        assert!(error.to_string().contains("realpath -- PATH"));
    }

    #[test]
    fn submitted_file_is_unlinked_and_durably_audited() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let path = root.join("file");
        let state = root.join("state");
        fs::write(&path, b"delete me").unwrap();
        let candidate = PermanentFileCandidate::capture(path.clone(), Some(&state)).unwrap();
        let plan = PermanentPlan::File(Box::new(candidate.plan()));
        let digest = sweepx_canonical::plan_digest_hex(&plan).unwrap();

        let audit_root = state.join("permanent-delete-audit");
        let audit = prepare_audit(&audit_root, &state, &plan, &digest).unwrap();
        let plan_path = audit_root.join(format!("plan-{digest}.json"));
        let plan_bytes = fs::read(&plan_path).unwrap();
        let persisted: serde_json::Value = serde_json::from_slice(&plan_bytes).unwrap();
        assert_eq!(persisted["canonicalDigest"], digest);
        assert_eq!(
            sweepx_canonical::plan_digest_hex(&persisted["plan"]).unwrap(),
            digest
        );
        candidate
            .submit(&state, &audit, &digest, Instant::now())
            .unwrap();

        assert!(!path.exists());
        let audit = AuditStore::open(&audit_root).unwrap();
        let integrity = audit.verify_integrity().unwrap();
        let projection = audit.projection_snapshot().unwrap();
        assert_eq!(integrity.action_sequence, 2);
        assert_eq!(integrity.latest_sequence, 5);
        assert_eq!(projection.batches.len(), 1);
        assert_eq!(
            projection.batches[0].state,
            sweepx_protocol::AuditProjectionState::Terminal
        );
        assert!(!projection.batches[0].needs_reconciliation);
        assert_eq!(projection.batches[0].items.len(), 1);
        assert!(plan_path.is_file());
    }

    #[test]
    fn directory_manifest_is_postorder_and_includes_root_last() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        fs::create_dir_all(directory.join("nested")).unwrap();
        fs::write(directory.join("a"), b"a").unwrap();
        fs::write(directory.join("nested/b"), b"b").unwrap();

        let candidate = PermanentDirectoryCandidate::capture(directory, None).unwrap();
        assert_eq!(candidate.actions.len(), 4);
        assert!(
            candidate
                .actions
                .last()
                .unwrap()
                .relative_components
                .is_empty()
        );
        for (directory_index, action) in candidate.actions.iter().enumerate() {
            if action.object_type != PlannedObjectType::Directory {
                continue;
            }
            assert!(
                candidate.actions[directory_index + 1..]
                    .iter()
                    .all(|later| {
                        !later
                            .relative_components
                            .starts_with(&action.relative_components)
                            || later.relative_components.len() <= action.relative_components.len()
                    })
            );
        }
    }

    #[test]
    fn submitted_directory_removes_exact_manifest_and_audits_each_action() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        let state = root.join("state");
        fs::create_dir_all(directory.join("nested")).unwrap();
        fs::write(directory.join("a"), b"a").unwrap();
        fs::write(directory.join("nested/b"), b"b").unwrap();
        let candidate =
            PermanentDirectoryCandidate::capture(directory.clone(), Some(&state)).unwrap();
        let action_count = candidate.actions.len();
        let plan = PermanentPlan::Directory(Box::new(candidate.plan()));
        let digest = sweepx_canonical::plan_digest_hex(&plan).unwrap();
        let audit_root = state.join("permanent-delete-audit");
        let audit = prepare_audit(&audit_root, &state, &plan, &digest).unwrap();

        candidate
            .submit(&state, &audit, &digest, Instant::now())
            .unwrap();

        assert!(!directory.exists());
        let integrity = audit.verify_integrity().unwrap();
        assert_eq!(integrity.action_sequence, (action_count * 2) as u64);
        assert_eq!(integrity.latest_sequence, (action_count * 2 + 3) as u64);
        let projection = audit.projection_snapshot().unwrap();
        assert_eq!(
            projection.batches[0].state,
            sweepx_protocol::AuditProjectionState::Terminal
        );
        assert!(!projection.batches[0].needs_reconciliation);
    }

    #[test]
    fn directory_revalidation_refuses_new_children_without_deleting_anything() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("planned"), b"planned").unwrap();
        let candidate = PermanentDirectoryCandidate::capture(directory.clone(), None).unwrap();
        fs::write(directory.join("late"), b"late").unwrap();

        assert!(matches!(
            candidate.revalidate_manifest(None),
            Err(DeleteError::TargetChanged)
        ));
        assert!(directory.join("planned").exists());
        assert!(directory.join("late").exists());
    }

    #[test]
    fn directory_action_preserves_new_children_and_audits_source_unchanged() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        let state = root.join("state");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("planned"), b"planned").unwrap();
        let candidate =
            PermanentDirectoryCandidate::capture(directory.clone(), Some(&state)).unwrap();
        let plan = PermanentPlan::Directory(Box::new(candidate.plan()));
        let digest = sweepx_canonical::plan_digest_hex(&plan).unwrap();
        let audit_root = state.join("permanent-delete-audit");
        let audit = prepare_audit(&audit_root, &state, &plan, &digest).unwrap();
        let binding = audit_binding(
            &digest,
            candidate
                .actions
                .iter()
                .map(|action| action.action_id.clone()),
        )
        .unwrap();
        let authorization_id = binding.authorization_id.clone();
        let plan_digest = binding.plan_digest.clone();
        audit
            .register_native_authorization(RegisterAuthorization { binding })
            .unwrap();
        let mut claim = audit
            .claim_execution(&authorization_id, &plan_digest)
            .unwrap();

        candidate
            .execute_action(
                &state,
                &audit,
                &mut claim,
                &candidate.actions[0],
                Instant::now(),
            )
            .unwrap();
        fs::write(directory.join("late"), b"late").unwrap();
        let error = candidate
            .execute_action(
                &state,
                &audit,
                &mut claim,
                &candidate.actions[1],
                Instant::now(),
            )
            .unwrap_err();

        assert!(
            matches!(error, DeleteError::Backend(ref source) if source.raw_os_error() == Some(libc::ENOTEMPTY))
        );
        assert!(!directory.join("planned").exists());
        assert!(directory.join("late").exists());
        assert!(directory.exists());
        record_remaining_actions_not_submitted(
            &audit,
            &mut claim,
            &candidate.actions[2..],
            "skipped after root removal observed an unplanned child",
        )
        .unwrap();
        audit.consume_execution(&claim).unwrap();
        let projection = audit.projection_snapshot().unwrap();
        assert_eq!(
            projection.batches[0].state,
            sweepx_protocol::AuditProjectionState::Terminal
        );
        assert!(!projection.batches[0].needs_reconciliation);
    }

    #[test]
    fn directory_manifest_refuses_symlink_and_action_overflow() {
        let symlink_fixture = TempDir::new().unwrap();
        let symlink_root = symlink_fixture.path().canonicalize().unwrap();
        let directory = symlink_root.join("tree");
        fs::create_dir(&directory).unwrap();
        std::os::unix::fs::symlink("target", directory.join("link")).unwrap();
        assert!(matches!(
            PermanentDirectoryCandidate::capture(directory, None),
            Err(DeleteError::UnsupportedType)
        ));

        let limit_fixture = TempDir::new().unwrap();
        let limit_root = limit_fixture.path().canonicalize().unwrap();
        let directory = limit_root.join("tree");
        fs::create_dir(&directory).unwrap();
        for index in 0..MAX_DIRECTORY_ACTIONS {
            fs::write(directory.join(format!("file-{index:03}")), b"x").unwrap();
        }
        assert!(matches!(
            PermanentDirectoryCandidate::capture(directory, None),
            Err(DeleteError::ResourceLimit("256-action"))
        ));
    }

    #[test]
    fn directory_manifest_refuses_nested_protection_marker() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        fs::create_dir_all(directory.join("nested")).unwrap();
        fs::write(directory.join("nested/.sweepx-protect"), b"").unwrap();

        assert!(matches!(
            PermanentDirectoryCandidate::capture(directory, None),
            Err(DeleteError::ProtectionMarker(_))
        ));
    }

    #[test]
    fn empty_directory_is_one_nonrecursive_action() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("empty");
        fs::create_dir(&directory).unwrap();

        let candidate = PermanentDirectoryCandidate::capture(directory, None).unwrap();
        assert_eq!(candidate.actions.len(), 1);
        assert_eq!(
            candidate.actions[0].object_type,
            PlannedObjectType::Directory
        );
        assert!(candidate.actions[0].relative_components.is_empty());
    }

    #[test]
    fn directory_plan_digest_binds_every_manifest_entry() {
        let fixture = TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let directory = root.join("tree");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("a"), b"a").unwrap();
        let candidate = PermanentDirectoryCandidate::capture(directory.clone(), None).unwrap();
        let first = PermanentPlan::Directory(Box::new(candidate.plan()));
        let first_digest = sweepx_canonical::plan_digest_hex(&first).unwrap();

        fs::write(directory.join("b"), b"b").unwrap();
        let candidate = PermanentDirectoryCandidate::capture(directory, None).unwrap();
        let second = PermanentPlan::Directory(Box::new(candidate.plan()));
        let second_digest = sweepx_canonical::plan_digest_hex(&second).unwrap();

        assert_ne!(first_digest, second_digest);
    }
}
