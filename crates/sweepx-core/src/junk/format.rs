//! Current, bounded content/context evidence. No declared path is opened or deletion authorized.
//!
//! Profiles recognize bounded generated signatures, not arbitrary Dart URI/YAML or TypeScript/JS
//! semantics. Unsupported shapes remain unknown. Even a perfect imitation is report-only: a
//! self-declared generator cannot prove exclusive directory ownership or inactivity.

mod sveltekit;
pub use sveltekit::inspect_sveltekit_sync;

use super::candidate::JunkCandidate;
use super::manifest::{
    CargoLocalConfigEvidence, ProjectContextEvidence, inspect_cargo_manifest_context,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use sweepx_catalog::junk::{ProjectContentFormat, ProjectContextProfile};
use sweepx_model::{NativeName, ScanEntryId};
use sweepx_platform::{CancellationToken, PlatformScanner};
use sweepx_scanner::HostPlatformScanner;
use sweepx_scanner::{LocatorReadFailure, LocatorReadLimits, LocatorReader};

/// Stable content evidence state, independent of traversal completeness and Git ignore status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectFormatStatus {
    /// No current content observation has run (including historical/base rows).
    NotChecked,
    /// The bounded profile recognizes generated signatures, not directory ownership.
    Recognized,
    /// Malformed required fields or invalid source encoding for the bounded profile.
    Invalid,
    /// Read/cancellation/resource failure, unsupported version or unrecognized profile shape.
    Unknown,
}
impl ProjectFormatStatus {
    /// Stable machine/display code, independent of locale.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Recognized => "recognized",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }
}

/// Small report payload; never includes configuration bytes, URIs or executable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectFormatEvidence {
    /// Profile from the currently admitted catalog.
    pub profile: ProjectContentFormat,
    /// Current observation outcome, never restored from filesystem cache.
    pub status: ProjectFormatStatus,
    /// Stable reason code, identical in both locales.
    pub reason: &'static str,
}
impl ProjectFormatEvidence {
    /// Starts a profile without inheriting any previous invocation's interpretation.
    pub fn not_checked(profile: ProjectContentFormat) -> Self {
        Self {
            profile,
            status: ProjectFormatStatus::NotChecked,
            reason: "content_not_checked",
        }
    }
}

/// Invocation/revision limits. Each attempt reserves worst-case payload and ancestor enumeration
/// work before I/O, including failed attempts. This is conservative requested work, not actual RSS.
#[derive(Debug, Clone, Copy)]
pub struct ProjectFormatLimits {
    /// Maximum distinct content/context observations, shared across profiles. Repeated scan IDs
    /// reuse current answers within this session only.
    pub max_observations: usize,
    /// Maximum payload for each complete-file read (profiles may require multiple reads).
    pub max_file_bytes: usize,
    /// Cumulative worst-case payload reservations, including all profile rereads. Failed reads
    /// do not refund their allowance; a legacy SvelteKit observation reserves four reads.
    pub max_reserved_file_bytes: usize,
    /// Native lineage, enumeration and handle-bound limits per read/pair call. A profile can
    /// make multiple calls; upfront file reservations and max_observations bound their total.
    pub locator: LocatorReadLimits,
    /// Cooperative deadline for the entire session; cannot interrupt a blocking kernel call.
    pub timeout: Duration,
}
impl Default for ProjectFormatLimits {
    fn default() -> Self {
        Self {
            max_observations: 128,
            max_file_bytes: 256 * 1024,
            max_reserved_file_bytes: 32 * 1024 * 1024,
            locator: LocatorReadLimits {
                max_requests: 5,
                max_components_per_request: 32,
                max_total_components: 32,
                ..LocatorReadLimits::default()
            },
            timeout: Duration::from_secs(5),
        }
    }
}

/// Serial, worker-owned content/context observations. Answers deduplicate only within this session;
/// reconstruct this object for every CLI invocation or TUI revision, including validated cache hits.
pub struct ProjectFormatSession<P: PlatformScanner = HostPlatformScanner> {
    reader: LocatorReader<P>,
    limits: ProjectFormatLimits,
    cancel: CancellationToken,
    started: Instant,
    reserved_bytes: usize,
    attempts: usize,
    observed: BTreeMap<(ScanEntryId, ProjectContentFormat), ProjectFormatEvidence>,
    contexts: BTreeMap<(ScanEntryId, ProjectContextProfile), ProjectContextEvidence>,
}
impl ProjectFormatSession {
    /// Uses the host backend's provider-safe full-file reader, retaining no configuration bytes.
    pub fn new(limits: ProjectFormatLimits, cancel: CancellationToken) -> Self {
        Self::with_platform(HostPlatformScanner::new(), limits, cancel)
    }
}
impl<P: PlatformScanner> ProjectFormatSession<P> {
    /// Injects a native scanner implementation while preserving the same bounds and report contract.
    pub fn with_platform(
        platform: P,
        mut limits: ProjectFormatLimits,
        cancel: CancellationToken,
    ) -> Self {
        limits.max_file_bytes = limits
            .max_file_bytes
            .min(256 * 1024)
            .min(limits.locator.max_file_bytes)
            .min(limits.locator.max_total_bytes);
        limits.locator.max_file_bytes = limits.max_file_bytes;
        // The pair can contain two complete files; preserve stricter caller-supplied limits.
        // Each file stays capped, and the profile reserves manifest + both files before I/O.
        limits.locator.max_total_bytes = limits
            .locator
            .max_total_bytes
            .min(limits.max_file_bytes.saturating_mul(2));
        Self {
            reader: LocatorReader::new(platform, limits.locator),
            limits,
            cancel,
            started: Instant::now(),
            reserved_bytes: 0,
            attempts: 0,
            observed: BTreeMap::new(),
            contexts: BTreeMap::new(),
        }
    }

    /// Refreshes required content and manifest evidence. Unreadable/unsupported inputs stay visible and
    /// report-only. This never changes filesystem coverage, reads display paths or invokes tools.
    pub fn refresh(&mut self, candidate: &mut JunkCandidate) {
        self.refresh_context(candidate);
        let Some(profile) = candidate.project_format.as_ref().map(|e| e.profile) else {
            return;
        };
        // Public loaded IDs can contain arbitrary caller bytes. Bound key retention before clone,
        // even when a caller did not obtain this candidate from our bounded scan session.
        if candidate.entry_id.as_str().len() > 1024 {
            candidate.project_format = Some(outcome(
                profile,
                ProjectFormatStatus::Unknown,
                "resource_limit",
            ));
            candidate.reset_project_format_interpretation();
            return;
        }
        let key = (candidate.entry_id.clone(), profile);
        let reads = match profile {
            ProjectContentFormat::DartPubPackageConfigV2 => 1,
            ProjectContentFormat::SvelteKitLegacySync => 4,
        };
        let evidence = if self.cancel.is_cancelled() {
            outcome(profile, ProjectFormatStatus::Unknown, "cancelled")
        } else if self.started.elapsed() >= self.limits.timeout {
            outcome(profile, ProjectFormatStatus::Unknown, "deadline")
        } else if let Some(current) = self.observed.get(&key) {
            current.clone()
        } else if let Err(reason) = self.reserve_observation(reads) {
            outcome(profile, ProjectFormatStatus::Unknown, reason)
        } else {
            // Count before any failure. Native enumeration is independently bounded per attempt,
            // so max_observations * four bounds cumulative read/metadata/lineage work. Every
            // profile's full worst-case payload (including rereads) is charged before the first I/O.
            let current = self.observe(candidate, profile);
            self.observed.insert(key, current.clone());
            current
        };
        candidate.project_format = Some(evidence);
        candidate.reset_project_format_interpretation();
    }

    fn check_current(&self) -> Result<(), &'static str> {
        if self.cancel.is_cancelled() {
            Err("cancelled")
        } else if self.started.elapsed() >= self.limits.timeout {
            Err("deadline")
        } else {
            Ok(())
        }
    }

    // Context and generated-content inputs share the same attempt/byte/deadline budgets. Failed
    // attempts reserve before native I/O and never refund; neither cache can grow beyond attempts.
    fn reserve_observation(&mut self, reads: usize) -> Result<(), &'static str> {
        self.check_current()?;
        let reservation = self.limits.max_file_bytes.checked_mul(reads);
        let Some(total) = reservation.and_then(|bytes| self.reserved_bytes.checked_add(bytes))
        else {
            return Err("resource_limit");
        };
        if self.attempts >= self.limits.max_observations
            || self.limits.max_file_bytes == 0
            || total > self.limits.max_reserved_file_bytes
        {
            return Err("resource_limit");
        }
        self.attempts += 1;
        self.reserved_bytes = total;
        Ok(())
    }

    fn refresh_context(&mut self, candidate: &mut JunkCandidate) {
        let Some(profile) = candidate.project_context.map(|e| e.profile) else {
            return;
        };
        let evidence = if let Err(reason) = self.check_current() {
            ProjectContextEvidence::unknown(profile, reason)
        } else if candidate.entry_id.as_str().len() > 1024 {
            ProjectContextEvidence::unknown(profile, "resource_limit")
        } else {
            let key = (candidate.entry_id.clone(), profile);
            if let Some(current) = self.contexts.get(&key) {
                *current
            } else if let Err(reason) = self.reserve_observation(3) {
                ProjectContextEvidence::unknown(profile, reason)
            } else {
                let current = self.observe_context(candidate, profile);
                self.contexts.insert(key, current);
                current
            }
        };
        candidate.project_context = Some(evidence);
    }

    fn observe_context(
        &self,
        candidate: &JunkCandidate,
        profile: ProjectContextProfile,
    ) -> ProjectContextEvidence {
        let Some(entry) = candidate.source_entry.as_ref() else {
            return ProjectContextEvidence::unknown(profile, "native_binding_unavailable");
        };
        if entry
            .executable_native_locator()
            .ok()
            .flatten()
            .is_none_or(|locator| locator.parent_reopen_recipe.is_empty())
        {
            return ProjectContextEvidence::unknown(profile, "context_outside_scan_root");
        }
        let read = match profile {
            ProjectContextProfile::CargoManifest => self.read_file_at(entry, "Cargo.toml", 1),
        };
        match read {
            Ok(read) => {
                let mut evidence = inspect_cargo_manifest_context(&read.bytes);
                // One manifest plus two possible config files share the upfront reservation.
                // Config failures do not erase a successfully read manifest declaration.
                evidence.cargo_config = Some(match self.check_current() {
                    Err(reason) => CargoLocalConfigEvidence::failed(reason),
                    Ok(()) => match self.reader.observe_cargo_config_pair_at_captured_ancestor(
                        entry,
                        1,
                        &self.cancel,
                    ) {
                        Ok(pair) => CargoLocalConfigEvidence::from_observation(pair),
                        Err(error) => CargoLocalConfigEvidence::failed(match error {
                            sweepx_scanner::LocatorReadError::Cancelled => "cancelled",
                            sweepx_scanner::LocatorReadError::ResourceLimit => "resource_limit",
                            sweepx_scanner::LocatorReadError::InvalidRequest => {
                                "native_binding_unavailable"
                            }
                        }),
                    },
                });
                if let Err(reason) = self.check_current() {
                    ProjectContextEvidence::unknown(profile, reason)
                } else {
                    evidence
                }
            }
            Err(reason) => ProjectContextEvidence::unknown(profile, reason),
        }
    }

    fn observe(
        &self,
        candidate: &JunkCandidate,
        profile: ProjectContentFormat,
    ) -> ProjectFormatEvidence {
        let Some(entry) = candidate.source_entry.as_ref() else {
            return outcome(
                profile,
                ProjectFormatStatus::Unknown,
                "native_binding_unavailable",
            );
        };
        let evidence = match profile {
            ProjectContentFormat::DartPubPackageConfigV2 => self
                .read_file(entry, "package_config.json")
                .map(|read| inspect_dart_pub_config(&read.bytes)),
            ProjectContentFormat::SvelteKitLegacySync => self.observe_sveltekit(entry),
        }
        .unwrap_or_else(|reason| outcome(profile, ProjectFormatStatus::Unknown, reason));
        if self.cancel.is_cancelled() {
            outcome(profile, ProjectFormatStatus::Unknown, "cancelled")
        } else if self.started.elapsed() >= self.limits.timeout {
            outcome(profile, ProjectFormatStatus::Unknown, "deadline")
        } else {
            evidence
        }
    }

    fn read_file(
        &self,
        entry: &sweepx_model::ScannedEntry,
        name: &str,
    ) -> Result<sweepx_platform::PresentRegularFileRead, &'static str> {
        self.read_file_at(entry, name, 0)
    }

    fn read_file_at(
        &self,
        entry: &sweepx_model::ScannedEntry,
        name: &str,
        ancestor_levels: usize,
    ) -> Result<sweepx_platform::PresentRegularFileRead, &'static str> {
        if self.cancel.is_cancelled() {
            return Err("cancelled");
        }
        if self.started.elapsed() >= self.limits.timeout {
            return Err("deadline");
        }
        let name = if cfg!(windows) {
            NativeName::WindowsUtf16(name.encode_utf16().collect())
        } else {
            NativeName::UnixBytes(name.as_bytes().to_vec())
        };
        let read = self
            .reader
            .read_captured_ancestor_regular_file(entry, ancestor_levels, &name, &self.cancel)
            .map_err(read_reason)?;
        if self.cancel.is_cancelled() {
            return Err("cancelled");
        }
        if self.started.elapsed() >= self.limits.timeout {
            return Err("deadline");
        }
        Ok(read)
    }

    fn observe_sveltekit(
        &self,
        entry: &sweepx_model::ScannedEntry,
    ) -> Result<ProjectFormatEvidence, &'static str> {
        let config = self.read_file(entry, "tsconfig.json")?;
        let ambient = self.read_file(entry, "ambient.d.ts")?;
        // Close the obvious inter-file change window with current identity/stamp/body comparisons.
        // Two path-bound intervals remain non-atomic; neither these comparisons nor their
        // signatures prove a sealed generation, directory ownership or permission to mutate.
        for (name, first) in [("tsconfig.json", &config), ("ambient.d.ts", &ambient)] {
            let current = self.read_file(entry, name)?;
            if current.observed_before != first.observed_after || current.bytes != first.bytes {
                return Err("content_changed_between_reads");
            }
        }
        Ok(inspect_sveltekit_sync(&config.bytes, &ambient.bytes))
    }
}

pub(super) fn read_reason(failure: LocatorReadFailure) -> &'static str {
    match failure {
        LocatorReadFailure::InvalidBinding => "invalid_binding",
        LocatorReadFailure::IdentityMismatch => "identity_changed_or_missing",
        LocatorReadFailure::MountChanged => "mount_changed",
        LocatorReadFailure::SymlinkOrReparse => "linked_file",
        LocatorReadFailure::NotRegular => "not_regular",
        LocatorReadFailure::ResourceLimit => "resource_limit",
        LocatorReadFailure::Cancelled => "cancelled",
        LocatorReadFailure::ReadFailed => "read_failed",
        LocatorReadFailure::ProviderOrOffline => "provider_or_offline",
        LocatorReadFailure::Unavailable => "unavailable",
        LocatorReadFailure::AmbiguousAlias => "ambiguous_alias",
    }
}
fn outcome(
    profile: ProjectContentFormat,
    status: ProjectFormatStatus,
    reason: &'static str,
) -> ProjectFormatEvidence {
    ProjectFormatEvidence {
        profile,
        status,
        reason,
    }
}

// Named field deserialization rejects duplicate recognized fields instead of silently taking the
// last JSON value. Additional extension fields are ignored; their presence is not ownership proof.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DartConfig {
    config_version: u64,
    packages: Vec<DartPackage>,
    generator: Option<String>,
    generator_version: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DartPackage {
    name: String,
    root_uri: String,
    package_uri: Option<String>,
    language_version: Option<String>,
}

/// Recognizes a bounded subset of pub's v2 package map. No URI is followed, no pubspec YAML is
/// parsed and no actual tool version/activity/ownership is inferred from self-declared fields.
/// `Unknown` includes otherwise valid Dart formats outside this profile; it is not invalidity.
pub fn inspect_dart_pub_config(bytes: &[u8]) -> ProjectFormatEvidence {
    let profile = ProjectContentFormat::DartPubPackageConfigV2;
    if bytes.len() > 256 * 1024 || exceeds_json_depth(bytes) {
        return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
    }
    let config: DartConfig = match serde_json::from_slice(bytes) {
        Ok(config) => config,
        Err(error) => {
            if error.to_string().starts_with("recursion limit exceeded") {
                return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
            }
            return outcome(
                profile,
                ProjectFormatStatus::Invalid,
                "invalid_json_or_fields",
            );
        }
    };
    if config.config_version != 2 {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "unsupported_config_version",
        );
    }
    if config.packages.len() > 4096 {
        return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
    }
    let mut names = BTreeSet::new();
    for package in &config.packages {
        if package.name.is_empty() || !names.insert(&package.name) {
            return outcome(
                profile,
                ProjectFormatStatus::Invalid,
                "empty_or_duplicate_package_name",
            );
        }
        if package.name.len() > 256
            || package.root_uri.len() > 4096
            || package.package_uri.as_ref().is_some_and(|s| s.len() > 4096)
            || package
                .language_version
                .as_ref()
                .is_some_and(|s| s.len() > 64)
        {
            return outcome(profile, ProjectFormatStatus::Unknown, "resource_limit");
        }
        // Recognize bounded relative/file path signatures, including pub's percent-encoded UTF-8
        // names. Never resolve a URI; encoded separators/dot components and other schemes decline.
        if !plain_package_uri(&package.root_uri)
            || package
                .package_uri
                .as_ref()
                .is_some_and(|s| !plain_package_uri(s))
        {
            return outcome(
                profile,
                ProjectFormatStatus::Unknown,
                "unsupported_package_uri",
            );
        }
        if let Some(version) = &package.language_version {
            let mut parts = version.split('.');
            let valid = (0..2).all(|_| {
                parts
                    .next()
                    .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            }) && parts.next().is_none();
            if !valid {
                return outcome(
                    profile,
                    ProjectFormatStatus::Invalid,
                    "invalid_language_version",
                );
            }
        }
    }
    if config.generator.as_deref() != Some("pub") {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "pub_generator_not_established",
        );
    }
    if !config
        .generator_version
        .as_deref()
        .is_some_and(|v| v.len() <= 128 && semver::Version::parse(v).is_ok())
    {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "pub_version_not_established",
        );
    }
    if !config
        .packages
        .iter()
        .any(|p| p.root_uri == "../" && p.package_uri.as_deref() == Some("lib/"))
    {
        return outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "parent_root_reference_not_established",
        );
    }
    outcome(
        profile,
        ProjectFormatStatus::Recognized,
        "pub_v2_self_declared_parent_root",
    )
}

fn exceeds_json_depth(bytes: &[u8]) -> bool {
    // serde's IgnoredAny skips unknown extension trees without enforcing its recursive-value
    // limit. Bound lexical nesting for the whole payload before deserialization; this is only
    // resource admission, not another JSON validator. serde still checks strings, structure,
    // field types and syntax. Brackets inside escaped/ordinary strings do not consume depth.
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 128 {
                        return true;
                    }
                }
                b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    false
}
fn plain_package_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.len() > 4096 {
        return false;
    }
    let path = if let Some(path) = uri.strip_prefix("file:///") {
        // Ordinary Windows drive file URIs occur in pub maps too. This checks only the bounded
        // signature; it never resolves a drive, a mount or a dependency location.
        if path.as_bytes().get(0..3).is_some_and(|prefix| {
            prefix[0].is_ascii_alphabetic() && prefix[1] == b':' && prefix[2] == b'/'
        }) {
            &path[3..]
        } else {
            path
        }
    } else {
        uri
    };
    // Preserve the ordinary URI fast path without allocating a decode buffer.
    if !path.contains('%') {
        return path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
    }
    if !path.is_ascii() {
        return false;
    }
    // SDK recordings establish UTF-8 names and spaces encoded with %HH. Bound the temporary
    // buffer by the admitted URI length, decode once, and retain no decoded location. This is
    // format evidence only: accepting an escaped filename must never create path authority.
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(high) = bytes.next().and_then(|b| char::from(b).to_digit(16)) else {
                return false;
            };
            let Some(low) = bytes.next().and_then(|b| char::from(b).to_digit(16)) else {
                return false;
            };
            let byte = (high * 16 + low) as u8;
            // Decline structural escapes, recursive encoding and ASCII controls rather than
            // interpreting a different directory topology or hiding path syntax in a name.
            if matches!(
                byte,
                b'/' | b'.' | b'\\' | b':' | b'?' | b'#' | b'%' | 0..=31 | 127
            ) {
                return false;
            }
            decoded.push(byte);
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-') {
            decoded.push(byte);
        } else {
            return false;
        }
    }
    std::str::from_utf8(&decoded).is_ok_and(|path| {
        path.chars().all(|ch| {
            if ch.is_ascii() {
                ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ' ')
            } else {
                !ch.is_control() && !ch.is_whitespace()
            }
        })
    })
}

#[cfg(test)]
mod tests;
