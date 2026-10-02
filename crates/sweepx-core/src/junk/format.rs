//! Current, bounded content evidence. No package URI is opened and no deletion is authorized.
//!
//! Pub permits optional generator metadata and additional fields. This profile deliberately
//! recognizes a narrower pub-generated shape rather than claiming to implement Dart's URI/YAML
//! semantics. Unsupported shapes remain unknown. Even a perfect imitation is report-only: a
//! self-declared generator and parent-root reference cannot prove exclusive directory ownership.

use super::candidate::JunkCandidate;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use sweepx_catalog::junk::ProjectContentFormat;
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
    /// The bounded profile recognizes the self-declared pub format, not directory ownership.
    Recognized,
    /// Malformed required JSON fields or contradictory package-map fields.
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
    /// Maximum distinct candidate observations (repeated scan IDs reuse current answers).
    pub max_observations: usize,
    /// Maximum complete-file payload for one observation.
    pub max_file_bytes: usize,
    /// Cumulative payload reservations; failed reads do not refund their allowance.
    pub max_reserved_file_bytes: usize,
    /// Native lineage, enumeration and handle-bound read limits per observation.
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
                max_requests: 2,
                max_components_per_request: 32,
                max_total_components: 32,
                ..LocatorReadLimits::default()
            },
            timeout: Duration::from_secs(5),
        }
    }
}

/// Serial, worker-owned content observations. Answers are deduplicated only within this session;
/// reconstruct this object for every CLI invocation or TUI revision, including validated cache hits.
pub struct ProjectFormatSession<P: PlatformScanner = HostPlatformScanner> {
    reader: LocatorReader<P>,
    limits: ProjectFormatLimits,
    cancel: CancellationToken,
    started: Instant,
    reserved_bytes: usize,
    attempts: usize,
    observed: BTreeMap<(ScanEntryId, ProjectContentFormat), ProjectFormatEvidence>,
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
        limits.locator.max_total_bytes = limits.max_file_bytes;
        Self {
            reader: LocatorReader::new(platform, limits.locator),
            limits,
            cancel,
            started: Instant::now(),
            reserved_bytes: 0,
            attempts: 0,
            observed: BTreeMap::new(),
        }
    }

    /// Refreshes required content evidence. Unreadable/unsupported formats stay visible and
    /// report-only. This never changes filesystem coverage, reads display paths or invokes tools.
    pub fn refresh(&mut self, candidate: &mut JunkCandidate) {
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
        let evidence = if self.cancel.is_cancelled() {
            outcome(profile, ProjectFormatStatus::Unknown, "cancelled")
        } else if self.started.elapsed() >= self.limits.timeout {
            outcome(profile, ProjectFormatStatus::Unknown, "deadline")
        } else if let Some(current) = self.observed.get(&key) {
            current.clone()
        } else if self.attempts >= self.limits.max_observations
            || self.limits.max_file_bytes == 0
            || self
                .reserved_bytes
                .checked_add(self.limits.max_file_bytes)
                .is_none_or(|sum| sum > self.limits.max_reserved_file_bytes)
        {
            outcome(profile, ProjectFormatStatus::Unknown, "resource_limit")
        } else {
            // Count before any failure. Native enumeration is independently bounded per attempt,
            // so max_observations also bounds cumulative metadata/lineage work and retained keys.
            self.attempts += 1;
            self.reserved_bytes += self.limits.max_file_bytes;
            let current = self.observe(candidate, profile);
            self.observed.insert(key, current.clone());
            current
        };
        candidate.project_format = Some(evidence);
        candidate.reset_project_format_interpretation();
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
        let name = if cfg!(windows) {
            NativeName::WindowsUtf16("package_config.json".encode_utf16().collect())
        } else {
            NativeName::UnixBytes(b"package_config.json".to_vec())
        };
        let result = self
            .reader
            .read_captured_regular_file(entry, &name, &self.cancel);
        if self.cancel.is_cancelled() {
            return outcome(profile, ProjectFormatStatus::Unknown, "cancelled");
        }
        if self.started.elapsed() >= self.limits.timeout {
            return outcome(profile, ProjectFormatStatus::Unknown, "deadline");
        }
        let evidence = match result {
            Ok(read) => inspect_dart_pub_config(&read.bytes),
            Err(failure) => outcome(profile, ProjectFormatStatus::Unknown, read_reason(failure)),
        };
        if self.cancel.is_cancelled() {
            outcome(profile, ProjectFormatStatus::Unknown, "cancelled")
        } else if self.started.elapsed() >= self.limits.timeout {
            outcome(profile, ProjectFormatStatus::Unknown, "deadline")
        } else {
            evidence
        }
    }
}

fn read_reason(failure: LocatorReadFailure) -> &'static str {
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
        // The recognizer does not implement arbitrary URI escaping/resolution. Only ordinary
        // ASCII relative paths and file: dependency locations are recognized; all others decline.
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
    if uri.is_empty() {
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
    path.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests;
