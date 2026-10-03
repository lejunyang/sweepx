//! Current project declarations, separate from effective configuration, ownership and activity.

mod config;
mod config_native;
mod home;
mod scope;
mod workspace;
mod workspace_native;
pub use scope::{
    CargoOutputEnvironment, CargoOutputEvidence, CargoOutputPathComparison, CargoOutputSource,
    CargoWorkspaceEvidence,
};
pub(super) use scope::{CargoOutputSession, ScopeBudget};

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
    /// Current project-local config declarations, separate from globally effective configuration.
    pub cargo_config: Option<CargoLocalConfigEvidence>,
    /// Current bounded project-parent/no-CLI output model; never actual future-build authority.
    pub cargo_output: Option<CargoOutputEvidence>,
}
impl ProjectContextEvidence {
    /// Starts a profile without inheriting prior rules, invocation or cache answers.
    pub fn not_checked(profile: ProjectContextProfile) -> Self {
        Self {
            profile,
            status: ProjectContextStatus::NotChecked,
            reason: "context_not_checked",
            cargo_manifest: None,
            cargo_config: None,
            cargo_output: None,
        }
    }

    pub(super) fn unknown(profile: ProjectContextProfile, reason: &'static str) -> Self {
        Self {
            profile,
            status: ProjectContextStatus::Unknown,
            reason,
            cargo_manifest: None,
            cargo_config: None,
            cargo_output: None,
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
            cargo_config: None,
            cargo_output: None,
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
            cargo_config: None,
            cargo_output: None,
        },
    }
}

/// Lexical kind of a target-dir declaration on the host platform. No tilde/environment
/// expansion, normalization, filesystem access or relationship to the candidate is inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoTargetDirPathKind {
    /// Host-absolute path; it may refer to shared or unrelated data.
    Absolute,
    /// Relative spelling containing a parent component; confinement is not inferred.
    ParentRelative,
    /// Host-relative spelling, including literal `~`/`$` and `.` components.
    Relative,
    /// Windows drive prefix without an absolute root, such as `C:output`.
    DriveRelative,
    /// Windows root without an absolute drive, such as `\\output`.
    RootRelative,
}
impl CargoTargetDirPathKind {
    /// Locale-independent report code, with host-specific interpretation of path syntax.
    pub fn code(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::ParentRelative => "parent_relative",
            Self::Relative => "relative",
            Self::DriveRelative => "drive_relative",
            Self::RootRelative => "root_relative",
        }
    }

    pub(super) fn from_value(value: &str) -> Self {
        use std::path::{Component, Path};
        let path = Path::new(value);
        if path.is_absolute() {
            Self::Absolute
        } else if path.has_root() {
            Self::RootRelative
        } else if matches!(path.components().next(), Some(Component::Prefix(_))) {
            Self::DriveRelative
        } else if path
            .components()
            .any(|component| component == Component::ParentDir)
        {
            Self::ParentRelative
        } else {
            Self::Relative
        }
    }
}

/// Declaration from one observed config file; no raw target path is retained or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoTargetDirDeclaration {
    /// Parsing/read outcome for the current file, never proof of global configuration absence.
    pub status: ProjectContextStatus,
    /// Locale-independent explanation, including non-atomic enumeration absence.
    pub reason: &'static str,
    /// True/false only for a supported, completely read config; `None` means unknown.
    pub declared: Option<bool>,
    /// Host lexical path kind for a supported declaration, independent of precedence/ownership.
    /// `None` distinguishes no declaration or an unknown input from a known relative path.
    pub path_kind: Option<CargoTargetDirPathKind>,
}

/// Fixed-size local configuration observations. No resolved output directory or selection claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoLocalConfigEvidence {
    /// Both names are observed under one directory handle, without a sealed snapshot.
    pub consistency: CargoConfigConsistency,
    /// Declarations in the legacy `.cargo/config` file; Cargo normally prefers this name.
    pub config: CargoTargetDirDeclaration,
    /// Declarations in `.cargo/config.toml`, independently reported even when both names exist.
    pub config_toml: CargoTargetDirDeclaration,
    /// Remains false until cwd/ancestor/home/environment/CLI precedence is independently resolved.
    pub precedence_complete: bool,
}

/// Consistency of local Cargo configuration observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoConfigConsistency {
    /// Current observations cannot exclude cross-file or enumeration races.
    NonAtomic,
}

/// Inspects one file's target-dir declaration with the shared Cargo TOML/shape decoder.
/// Accepts bounded, nonempty host path spellings, including absolute and parent-relative values;
/// these reporting facts do not enter the cleaner's narrower execution-path contract.
pub fn inspect_cargo_target_dir_declaration(bytes: &[u8]) -> CargoTargetDirDeclaration {
    match crate::cargo_cleaner_evidence::inspect_cargo_target_dir_value(bytes) {
        Ok(Some(value)) if value.len() > 4096 => {
            CargoTargetDirDeclaration::unknown("resource_limit")
        }
        Ok(Some(value)) if value.is_empty() || value.contains('\0') => {
            CargoTargetDirDeclaration::unknown("invalid_target_dir_declaration")
        }
        Ok(Some(value)) => CargoTargetDirDeclaration {
            status: ProjectContextStatus::Observed,
            reason: "target_dir_declared",
            declared: Some(true),
            path_kind: Some(CargoTargetDirPathKind::from_value(&value)),
        },
        Ok(None) => CargoTargetDirDeclaration {
            status: ProjectContextStatus::Observed,
            reason: "target_dir_not_declared_in_file",
            declared: Some(false),
            path_kind: None,
        },
        Err(reason) => CargoTargetDirDeclaration::unknown(reason),
    }
}
impl CargoTargetDirDeclaration {
    fn unknown(reason: &'static str) -> Self {
        Self {
            status: if matches!(reason, "malformed_toml" | "duplicate_toml_key") {
                ProjectContextStatus::Invalid
            } else {
                ProjectContextStatus::Unknown
            },
            reason,
            declared: None,
            path_kind: None,
        }
    }
}
impl CargoLocalConfigEvidence {
    pub(super) fn failed(reason: &'static str) -> Self {
        Self {
            consistency: CargoConfigConsistency::NonAtomic,
            config: CargoTargetDirDeclaration::unknown(reason),
            config_toml: CargoTargetDirDeclaration::unknown(reason),
            precedence_complete: false,
        }
    }

    pub(super) fn from_observation(pair: &sweepx_scanner::CargoConfigPairObservation) -> Self {
        use sweepx_scanner::CargoConfigMemberObservation;
        fn inspect(member: &CargoConfigMemberObservation) -> CargoTargetDirDeclaration {
            match member {
                CargoConfigMemberObservation::Present(read) => {
                    inspect_cargo_target_dir_declaration(&read.bytes)
                }
                CargoConfigMemberObservation::AbsentDuringEnumeration
                | CargoConfigMemberObservation::AbsentDuringLookup => {
                    CargoTargetDirDeclaration::unknown("config_not_observed_non_atomic")
                }
                CargoConfigMemberObservation::Failed(reason) => {
                    CargoTargetDirDeclaration::unknown(super::format::read_reason(reason.clone()))
                }
            }
        }
        Self {
            consistency: CargoConfigConsistency::NonAtomic,
            config: inspect(&pair.config),
            config_toml: inspect(&pair.config_toml),
            precedence_complete: false,
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "manifest/scope_include_tests.rs"]
mod include_tests;
