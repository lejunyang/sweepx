//! Current project declarations, separate from effective configuration, ownership and activity.

pub use crate::cargo_cleaner_evidence::{CargoManifestDeclarationKind, CargoManifestDeclarations};
use serde::Serialize;
use sweepx_catalog::junk::ProjectContextProfile;

/// Stable context-observation state; an observed declaration is never execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectContextStatus {
    /// No current observation, including historical/base rows.
    NotChecked,
    /// Supported declarations were parsed from current bytes; effective context remains separate.
    Observed,
    /// Invalid UTF-8 or malformed/duplicate TOML input.
    Invalid,
    /// Unsupported declarations, missing binding, cancellation, read failure or resource limit.
    Unknown,
}
impl ProjectContextStatus {
    /// Locale-independent machine/display code.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Observed => "observed",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }
}

/// Fixed-size, invocation-only context evidence. Contains no names, paths or configuration bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectContextEvidence {
    /// Fixed input required by the currently admitted rule.
    pub profile: ProjectContextProfile,
    /// Current observation outcome, independent of filesystem coverage and generated signatures.
    pub status: ProjectContextStatus,
    /// Locale-independent explanation of the observed or missing evidence.
    pub reason: &'static str,
    /// Cargo declarations only; no resolved membership or exclusive-ownership inference.
    pub cargo_manifest: Option<CargoManifestDeclarations>,
}
impl ProjectContextEvidence {
    /// Starts a profile without inheriting prior rules, invocation or cache answers.
    pub fn not_checked(profile: ProjectContextProfile) -> Self {
        Self {
            profile,
            status: ProjectContextStatus::NotChecked,
            reason: "context_not_checked",
            cargo_manifest: None,
        }
    }

    pub(super) fn unknown(profile: ProjectContextProfile, reason: &'static str) -> Self {
        Self {
            profile,
            status: ProjectContextStatus::Unknown,
            reason,
            cargo_manifest: None,
        }
    }
}

/// Projects supported Cargo declarations with the existing cleaner provider's TOML/manifest
/// decoder. Pure parsing does not establish native provenance or validate full Cargo semantics.
pub fn inspect_cargo_manifest_context(bytes: &[u8]) -> ProjectContextEvidence {
    let profile = ProjectContextProfile::CargoManifest;
    match crate::cargo_cleaner_evidence::inspect_cargo_manifest_declarations(bytes) {
        Ok(declarations) => ProjectContextEvidence {
            profile,
            status: ProjectContextStatus::Observed,
            reason: "manifest_declarations_observed",
            cargo_manifest: Some(declarations),
        },
        Err(reason) => ProjectContextEvidence {
            profile,
            status: if matches!(reason, "malformed_toml" | "duplicate_toml_key") {
                ProjectContextStatus::Invalid
            } else {
                ProjectContextStatus::Unknown
            },
            reason,
            cargo_manifest: None,
        },
    }
}

#[cfg(test)]
mod tests;
