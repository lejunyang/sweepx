use std::collections::BTreeSet;
use std::fmt;

use schemars::JsonSchema;
use semver::VersionReq;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sweepx_canonical::canonicalize_value;
use thiserror::Error;

pub const CLEANER_MANIFEST_SCHEMA: &str = "sweepx.cleaner-manifest/v1";
pub const CLEANER_RULE_SCHEMA: &str = "sweepx.cleaner-rule/v1";
pub const CLEANER_EVIDENCE_SCHEMA: &str = "sweepx.cleaner-evidence/v1";
pub const CLEANER_SIGNATURE_SCHEMA: &str = "sweepx.cleaner-signature/v1";
pub const MAX_AST_DEPTH: usize = 32;
pub const MAX_AST_NODES: usize = 1024;
pub const PACKAGE_DIGEST_DOMAIN: &[u8] = b"SweepX cleaner package v1\0";
pub const PACKAGE_SIGNATURE_DOMAIN: &[u8] = b"SweepX cleaner signature v1\0";
const PLACEHOLDER_DIGESTS: [&str; 16] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444",
    "5555555555555555555555555555555555555555555555555555555555555555",
    "6666666666666666666666666666666666666666666666666666666666666666",
    "7777777777777777777777777777777777777777777777777777777777777777",
    "8888888888888888888888888888888888888888888888888888888888888888",
    "9999999999999999999999999999999999999999999999999999999999999999",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CleanerManifest {
    pub schema: String,
    pub id: String,
    pub version: String,
    pub description: String,
    pub publisher: PublisherRef,
    pub package_digest: String,
    pub requires: ManifestRequirements,
    pub platforms: Vec<PlatformSpec>,
    pub target_versions: TargetVersions,
    pub capabilities: ManifestCapabilities,
    pub roots: Vec<RootRef>,
    pub config_decoders: Vec<ConfigDecoder>,
    pub rules: Vec<ManifestRuleRef>,
    pub probes: Vec<NativeProbeDescriptor>,
    pub official_commands: Vec<OfficialCommandDescriptor>,
    pub risk_floor: RiskTier,
    pub supported_actions: Vec<SupportedAction>,
    pub references: Vec<String>,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublisherRef {
    pub id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct CleanerSignatureEnvelope {
    pub schema: String,
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub publisher_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_digest: String,
    pub manifest_schema: String,
    pub signed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency_proof: Option<Value>,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRequirements {
    pub core: String,
    pub scanner_semantics: Vec<u32>,
    pub candidate_schema: Vec<u32>,
    pub rule_schema: Vec<u32>,
    pub native_probe_abi: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSpec {
    pub os: Os,
    pub arch: Vec<Arch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TargetVersions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    pub unknown: UnknownVersionBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestCapabilities {
    pub discover: ManifestCapabilityStage,
    pub semantic_query: Vec<String>,
    pub analyze: Vec<String>,
    pub plan_proposal: Vec<String>,
    pub official_mutation: Vec<String>,
    pub post_action_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManifestCapabilityStage {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RootRef {
    KnownFolder { id: String },
    ExplicitScanRoot,
    AdmittedWorkspace { evidence: String },
    ProbeVerifiedProfileCacheRoot { evidence: String },
    FixedRelativeComponents { values: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDecoder {
    pub id: String,
    pub schema: String,
    pub formats: Vec<String>,
    pub allowlisted_relative_names: Vec<String>,
    pub single_file_bytes: u64,
    pub total_bytes: u64,
    pub network: DenyPolicy,
    pub includes: DenyPolicy,
    pub credentials: DenyPolicy,
    pub output_schema: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRuleRef {
    pub id: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CleanerRule {
    pub schema: String,
    pub id: String,
    pub artifact_class: String,
    pub platforms: Vec<PlatformSpec>,
    pub root_ref: RootRef,
    pub discovery: DiscoverySpec,
    pub selectors: Vec<Selector>,
    pub required_evidence: Vec<String>,
    pub optional_evidence: Vec<String>,
    pub exclusion_evidence: Vec<String>,
    pub grouping: Grouping,
    pub analysis: AnalysisSpec,
    pub risk: RiskSpec,
    pub proposal: ProposalSpec,
    pub recovery_requirements: Vec<String>,
    pub activity_blockers: Vec<String>,
    pub sharing_rules: Vec<String>,
    pub explanation_keys: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySpec {
    pub effect_class: EffectClass,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_probe_id: Option<String>,
    pub semantic_read_only: bool,
    pub zero_write_verified: bool,
    pub unknown_version_behavior: UnknownVersionBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Selector {
    ExactBasename {
        values: Vec<String>,
    },
    ExactRelativeComponents {
        values: Vec<Vec<String>>,
    },
    TypedRelativePath {
        field: String,
        #[serde(rename = "mustBeWithinAdmittedRoot")]
        must_be_within_admitted_root: bool,
    },
    TypedMetadata {
        field: String,
        expected: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisSpec {
    pub fact_predicates: Vec<Predicate>,
    pub inference_predicates: Vec<Predicate>,
    pub unknown_policy: UnknownPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RiskSpec {
    pub floor: RiskTier,
    pub monotonic_raises: Vec<MonotonicRaise>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MonotonicRaise {
    pub when: Predicate,
    pub to: RiskTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProposalSpec {
    pub disposition: Disposition,
    pub supported_action: SupportedAction,
    pub target_granularity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CleanerEvidence {
    pub schema: String,
    pub owner: String,
    pub canonical_path: String,
    pub path_source: String,
    pub artifact_class: String,
    pub object_id: String,
    pub object_version: TaggedString,
    pub manager_version: TaggedString,
    pub action_granularity: String,
    pub logical_bytes: TaggedU64,
    pub exclusive_reclaimable_bytes: TaggedU64,
    pub recoverability: TaggedString,
    pub activity_state: TaggedString,
    pub sharing_state: TaggedString,
    pub confidence: EvidenceConfidence,
    pub risk: RiskTier,
    pub supported_action: SupportedAction,
    pub facts: Vec<EvidenceFact>,
    pub inferences: Vec<EvidenceInference>,
    pub recommendations: Vec<String>,
    pub uncertainties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceFact {
    pub id: String,
    pub source_url: String,
    pub access_date: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceInference {
    pub summary: String,
    pub fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaggedString {
    Known { value: String },
    LowerBound { value: String, reason: String },
    Unknown { reason: String },
    Unsupported { reason: String },
    NotChecked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaggedU64 {
    Known { value: u64 },
    LowerBound { value: u64, reason: String },
    Unknown { reason: String },
    Unsupported { reason: String },
    NotChecked { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NativeProbeDescriptor {
    pub schema: String,
    pub id: String,
    pub abi_version: u32,
    pub artifacts: Vec<ProbeArtifact>,
    pub input_schema: String,
    pub output_schema: String,
    pub capabilities: Vec<String>,
    pub sandbox_profile: String,
    pub network: DenyPolicy,
    pub filesystem_read_scopes: Vec<String>,
    pub cpu_millis: u64,
    pub rss_bytes: u64,
    pub handle_count: u64,
    pub timeout_millis: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ProbeArtifact {
    pub os: Os,
    pub arch: Arch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tested_os: Option<String>,
    pub package_relative_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OfficialCommandDescriptor {
    pub schema: String,
    pub id: String,
    pub effect_class: EffectClass,
    pub vendor: String,
    pub semantic_read_only: bool,
    pub zero_write_verified: bool,
    pub executable: CommandExecutable,
    pub argv_template: Vec<ArgvSegment>,
    pub cwd_source: String,
    pub environment_allowlist: Vec<String>,
    pub stripped_environment: Vec<String>,
    pub stdin: StdioMode,
    pub tty: bool,
    pub network_policy: DenyPolicy,
    pub no_update_flags: Vec<String>,
    pub no_daemon_flags: Vec<String>,
    pub lock_or_offline_flags: Vec<String>,
    pub write_monitor: WriteMonitor,
    pub timeout_millis: u64,
    pub process_tree_grace_millis: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output: CommandOutput,
    pub exit_map: std::collections::BTreeMap<String, String>,
    pub transient_retry_policy: RetryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandExecutable {
    pub absolute_path_source: Value,
    pub owner_policy: Value,
    pub identity_policy: Value,
    pub version_range: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ArgvSegment {
    Literal {
        literal: String,
    },
    TypedPlaceholder {
        typed_placeholder: String,
        validation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WriteMonitor {
    pub allowed_disposable_scopes: Vec<String>,
    pub fail_on_other_write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub schema: String,
    pub parser_id: String,
    pub parser_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    pub max_retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    High,
    Medium,
    Low,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskTier {
    R1,
    R2,
    R3,
    R4,
    Blocked,
}

impl RiskTier {
    pub fn is_monotonic_raise_from(self, floor: Self) -> bool {
        self >= floor
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::R1 => f.write_str("R1"),
            Self::R2 => f.write_str("R2"),
            Self::R3 => f.write_str("R3"),
            Self::R4 => f.write_str("R4"),
            Self::Blocked => f.write_str("BLOCKED"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SupportedAction {
    Report,
    FilesystemTrash,
    ManagerPermanentRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    ReportOnly,
    EligibleWithConfirmation,
    LowRiskCandidate,
    ManagerGcCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownPolicy {
    RaiseRisk,
    ReportOnly,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Grouping {
    Object,
    Directory,
    ManagerScope,
    StorageKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Z0,
    Z1,
    Z2,
    M,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DenyPolicy {
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StdioMode {
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownVersionBehavior {
    ReportOnly,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Predicate {
    Call {
        op: PredicateOp,
        args: Vec<PredicateArg>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PredicateArg {
    FieldRef { field: String },
    Predicate(Box<Predicate>),
    String(String),
    Bool(bool),
    StringList(Vec<String>),
    NestedStringList(Vec<Vec<String>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOp {
    And,
    Or,
    Not,
    Eq,
    In,
    Exists,
    StateIs,
    VersionIn,
    IsDescendantOf,
    SetIntersects,
}

impl CleanerManifest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CLEANER_MANIFEST_SCHEMA {
            return Err(ValidationError::SchemaMismatch {
                expected: CLEANER_MANIFEST_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_identifier(&self.id, "manifest.id")?;
        validate_identifier(&self.publisher.id, "manifest.publisher.id")?;
        validate_identifier(&self.publisher.key_id, "manifest.publisher.key_id")?;
        validate_version(&self.version, "manifest.version")?;
        validate_sha256_prefixed(&self.package_digest, "manifest.package_digest")?;
        validate_non_placeholder_sha256_prefixed(&self.package_digest, "manifest.package_digest")?;
        validate_version_req(&self.requires.core, "manifest.requires.core")?;
        validate_non_empty_unique(&self.supported_actions, "manifest.supported_actions")?;
        validate_non_empty_unique(&self.platforms, "manifest.platforms")?;
        validate_non_empty_unique(&self.rules, "manifest.rules")?;
        validate_reference_strings(&self.references, "manifest.references")?;

        if self.risk_floor == RiskTier::Blocked {
            return Err(ValidationError::InvalidRiskFloor);
        }
        if self.expires_at.is_empty() {
            return Err(ValidationError::EmptyField("manifest.expires_at"));
        }
        if !self.official_commands.is_empty() {
            return Err(ValidationError::UnsupportedFeature(
                "manifest.official_commands must stay empty for P2 foundation".into(),
            ));
        }
        for path in self.rules.iter().map(|rule| rule.path.as_str()) {
            validate_relative_package_path(path, "manifest.rules[].path")?;
        }
        for decoder in &self.config_decoders {
            validate_identifier(&decoder.id, "manifest.config_decoders[].id")?;
            if decoder.schema.is_empty() || decoder.output_schema.is_empty() {
                return Err(ValidationError::EmptyField(
                    "manifest.config_decoders[].schema/output_schema",
                ));
            }
            if decoder.formats.is_empty() || decoder.allowlisted_relative_names.is_empty() {
                return Err(ValidationError::EmptyField(
                    "manifest.config_decoders[].formats/allowlisted_relative_names",
                ));
            }
            for rel in &decoder.allowlisted_relative_names {
                validate_allowlisted_relative_name(rel)?;
            }
        }
        for rule in &self.rules {
            validate_identifier(&rule.id, "manifest.rules[].id")?;
            validate_sha256(rule.sha256.as_str(), "manifest.rules[].sha256")?;
        }
        for probe in &self.probes {
            probe.validate()?;
        }
        Ok(())
    }
}

impl CleanerManifest {
    pub fn canonical_without_package_digest(&self) -> Result<Vec<u8>, ValidationError> {
        let mut value = serde_json::to_value(self)
            .map_err(|_| ValidationError::UnsupportedFeature("cannot serialize manifest".into()))?;
        if let Value::Object(object) = &mut value {
            object.remove("packageDigest");
        }
        canonicalize_value(&value).map_err(|_| {
            ValidationError::UnsupportedFeature("cannot encode canonical manifest".into())
        })
    }
}

impl CleanerSignatureEnvelope {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CLEANER_SIGNATURE_SCHEMA {
            return Err(ValidationError::SchemaMismatch {
                expected: CLEANER_SIGNATURE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.manifest_schema != CLEANER_MANIFEST_SCHEMA {
            return Err(ValidationError::SchemaMismatch {
                expected: CLEANER_MANIFEST_SCHEMA,
                actual: self.manifest_schema.clone(),
            });
        }
        validate_identifier(&self.key_id, "signature.keyId")?;
        validate_identifier(&self.publisher_id, "signature.publisherId")?;
        validate_identifier(&self.package_id, "signature.packageId")?;
        validate_version(&self.package_version, "signature.packageVersion")?;
        validate_sha256_prefixed(&self.package_digest, "signature.packageDigest")?;
        validate_non_placeholder_sha256_prefixed(&self.package_digest, "signature.packageDigest")?;
        if self.signed_at.is_empty() {
            return Err(ValidationError::EmptyField("signature.signed_at"));
        }
        if matches!(self.expires_at.as_deref(), Some("")) {
            return Err(ValidationError::EmptyField("signature.expires_at"));
        }
        if self.transparency_proof.is_some() {
            return Err(ValidationError::UnsupportedFeature(
                "signature.transparencyProof is not supported".into(),
            ));
        }
        validate_base64url_nopad_exact_len(&self.signature, "signature.signature", 64)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PackageDigestEntry {
    pub path: String,
    pub bytes: String,
    pub sha256: String,
}

pub fn compute_package_digest(
    file_table: &[PackageDigestEntry],
) -> Result<String, ValidationError> {
    let payload = serde_json::to_value(file_table)
        .map_err(|_| ValidationError::UnsupportedFeature("cannot serialize file table".into()))?;
    let payload_bytes = canonicalize_value(&payload).map_err(|_| {
        ValidationError::UnsupportedFeature("cannot encode package digest payload".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_DIGEST_DOMAIN);
    hasher.update(payload_bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub fn canonical_signature_payload(
    statement: &CleanerSignatureEnvelope,
) -> Result<Vec<u8>, ValidationError> {
    let mut payload = serde_json::to_value(statement)
        .map_err(|_| ValidationError::UnsupportedFeature("cannot serialize signature".into()))?;
    if let Value::Object(object) = &mut payload {
        object.remove("signature");
    }
    let payload_bytes = canonicalize_value(&payload).map_err(|_| {
        ValidationError::UnsupportedFeature("cannot encode signature payload".into())
    })?;
    let mut framed = Vec::with_capacity(PACKAGE_SIGNATURE_DOMAIN.len() + payload_bytes.len());
    framed.extend_from_slice(PACKAGE_SIGNATURE_DOMAIN);
    framed.extend_from_slice(&payload_bytes);
    Ok(framed)
}

impl CleanerRule {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CLEANER_RULE_SCHEMA {
            return Err(ValidationError::SchemaMismatch {
                expected: CLEANER_RULE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_identifier(&self.id, "rule.id")?;
        if self.artifact_class.is_empty() {
            return Err(ValidationError::EmptyField("rule.artifact_class"));
        }
        validate_non_empty_unique(&self.platforms, "rule.platforms")?;
        if self.required_evidence.is_empty() {
            return Err(ValidationError::EmptyField("rule.required_evidence"));
        }
        if self.selectors.is_empty() {
            return Err(ValidationError::EmptyField("rule.selectors"));
        }
        if self.risk.floor == RiskTier::Blocked {
            return Err(ValidationError::InvalidRiskFloor);
        }
        if matches!(
            self.proposal.supported_action,
            SupportedAction::ManagerPermanentRecommendation
        ) {
            return Err(ValidationError::UnsupportedFeature(
                "managerPermanentRecommendation is not part of the P2 built-ins".into(),
            ));
        }
        self.analysis.validate("rule.analysis")?;
        self.risk.validate()?;
        Ok(())
    }
}

impl AnalysisSpec {
    fn validate(&self, path: &str) -> Result<(), ValidationError> {
        for predicate in &self.fact_predicates {
            validate_predicate(predicate, &format!("{path}.fact_predicates[]"))?;
        }
        for predicate in &self.inference_predicates {
            validate_predicate(predicate, &format!("{path}.inference_predicates[]"))?;
        }
        Ok(())
    }
}

impl RiskSpec {
    fn validate(&self) -> Result<(), ValidationError> {
        for raise in &self.monotonic_raises {
            validate_predicate(&raise.when, "rule.risk.monotonic_raises[].when")?;
            if !raise.to.is_monotonic_raise_from(self.floor) {
                return Err(ValidationError::RiskLowering {
                    floor: self.floor,
                    attempted: raise.to,
                });
            }
        }
        Ok(())
    }
}

impl NativeProbeDescriptor {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != "sweepx.native-probe/v1" {
            return Err(ValidationError::SchemaMismatch {
                expected: "sweepx.native-probe/v1",
                actual: self.schema.clone(),
            });
        }
        validate_identifier(&self.id, "probe.id")?;
        if self.abi_version == 0 {
            return Err(ValidationError::InvalidNumber("probe.abi_version"));
        }
        validate_non_empty_unique(&self.artifacts, "probe.artifacts")?;
        for artifact in &self.artifacts {
            validate_relative_package_path(
                &artifact.package_relative_path,
                "probe.artifacts[].package_relative_path",
            )?;
            validate_sha256(&artifact.sha256, "probe.artifacts[].sha256")?;
        }
        Ok(())
    }
}

impl CleanerEvidence {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != CLEANER_EVIDENCE_SCHEMA {
            return Err(ValidationError::SchemaMismatch {
                expected: CLEANER_EVIDENCE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.owner.is_empty() || self.canonical_path.is_empty() || self.object_id.is_empty() {
            return Err(ValidationError::EmptyField(
                "evidence.owner/canonical_path/object_id",
            ));
        }
        if self.facts.is_empty() {
            return Err(ValidationError::EmptyField("evidence.facts"));
        }
        Ok(())
    }
}

fn validate_predicate(predicate: &Predicate, path: &str) -> Result<(), ValidationError> {
    let (depth, nodes) = predicate.metrics();
    if depth > MAX_AST_DEPTH {
        return Err(ValidationError::AstTooDeep {
            depth,
            max: MAX_AST_DEPTH,
        });
    }
    if nodes > MAX_AST_NODES {
        return Err(ValidationError::AstTooLarge {
            nodes,
            max: MAX_AST_NODES,
        });
    }
    predicate.validate_shape(path)
}

impl Predicate {
    pub fn metrics(&self) -> (usize, usize) {
        match self {
            Self::Call { args, .. } => {
                let mut max_depth = 1usize;
                let mut node_count = 1usize;
                for arg in args {
                    let (depth, nodes) = arg.metrics();
                    max_depth = max_depth.max(depth + 1);
                    node_count += nodes;
                }
                (max_depth, node_count)
            }
        }
    }

    fn validate_shape(&self, path: &str) -> Result<(), ValidationError> {
        match self {
            Self::Call { op, args } => {
                match op {
                    PredicateOp::Not | PredicateOp::Exists => {
                        if args.len() != 1 {
                            return Err(ValidationError::InvalidPredicateArity {
                                path: path.into(),
                                op: *op,
                                expected: 1,
                                actual: args.len(),
                            });
                        }
                    }
                    PredicateOp::And | PredicateOp::Or => {
                        if args.len() < 2 {
                            return Err(ValidationError::InvalidPredicateMinArity {
                                path: path.into(),
                                op: *op,
                                min_expected: 2,
                                actual: args.len(),
                            });
                        }
                    }
                    PredicateOp::Eq
                    | PredicateOp::In
                    | PredicateOp::StateIs
                    | PredicateOp::VersionIn
                    | PredicateOp::IsDescendantOf
                    | PredicateOp::SetIntersects => {
                        if args.len() != 2 {
                            return Err(ValidationError::InvalidPredicateArity {
                                path: path.into(),
                                op: *op,
                                expected: 2,
                                actual: args.len(),
                            });
                        }
                    }
                }
                for arg in args {
                    arg.validate_shape(path)?;
                }
                Ok(())
            }
        }
    }
}

impl PredicateArg {
    fn metrics(&self) -> (usize, usize) {
        match self {
            Self::FieldRef { .. } | Self::String(_) | Self::Bool(_) => (0, 1),
            Self::StringList(values) => (0, values.len().saturating_add(1)),
            Self::NestedStringList(values) => (
                0,
                values
                    .iter()
                    .map(|inner| inner.len().saturating_add(1))
                    .sum::<usize>()
                    .saturating_add(1),
            ),
            Self::Predicate(predicate) => predicate.metrics(),
        }
    }

    fn validate_shape(&self, path: &str) -> Result<(), ValidationError> {
        match self {
            Self::FieldRef { field } => validate_field_name(field, path),
            Self::Predicate(predicate) => predicate.validate_shape(path),
            Self::String(value) => {
                if value.is_empty() {
                    Err(ValidationError::EmptyField("predicate.literal"))
                } else {
                    Ok(())
                }
            }
            Self::Bool(_) => Ok(()),
            Self::StringList(values) => {
                if values.is_empty() {
                    Err(ValidationError::EmptyField("predicate.string_list"))
                } else if values.iter().any(String::is_empty) {
                    Err(ValidationError::EmptyField("predicate.string_list[]"))
                } else {
                    Ok(())
                }
            }
            Self::NestedStringList(values) => {
                if values.is_empty() || values.iter().any(Vec::is_empty) {
                    Err(ValidationError::EmptyField("predicate.nested_string_list"))
                } else if values.iter().flatten().any(String::is_empty) {
                    Err(ValidationError::EmptyField(
                        "predicate.nested_string_list[][]",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

fn validate_identifier(value: &str, path: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyDynamicField(path.into()));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@'))
    {
        return Err(ValidationError::InvalidIdentifier(path.into()));
    }
    Ok(())
}

fn validate_field_name(value: &str, path: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyDynamicField(path.into()));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(ValidationError::InvalidFieldName(path.into()));
    }
    Ok(())
}

fn validate_version(value: &str, path: &str) -> Result<(), ValidationError> {
    semver::Version::parse(value).map_err(|_| ValidationError::InvalidSemver(path.into()))?;
    Ok(())
}

fn validate_version_req(value: &str, path: &str) -> Result<(), ValidationError> {
    VersionReq::parse(value).map_err(|_| ValidationError::InvalidVersionReq(path.into()))?;
    Ok(())
}

fn validate_sha256_prefixed(value: &str, path: &str) -> Result<(), ValidationError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ValidationError::InvalidDigest(path.into()));
    };
    validate_sha256(digest, path)
}

fn validate_non_placeholder_sha256_prefixed(
    value: &str,
    path: &str,
) -> Result<(), ValidationError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ValidationError::InvalidDigest(path.into()));
    };
    if PLACEHOLDER_DIGESTS.contains(&digest) {
        return Err(ValidationError::PlaceholderDigest(path.into()));
    }
    Ok(())
}

fn validate_sha256(value: &str, path: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(ValidationError::InvalidDigest(path.into()));
    }
    Ok(())
}

fn validate_base64url_nopad_exact_len(
    value: &str,
    path: &str,
    expected_len: usize,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyDynamicField(path.into()));
    }
    if value.contains('=') {
        return Err(ValidationError::InvalidBase64(path.into()));
    }
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded = base64::Engine::decode(&engine, value)
        .map_err(|_| ValidationError::InvalidBase64(path.into()))?;
    let canonical = base64::Engine::encode(&engine, &decoded);
    if canonical != value {
        return Err(ValidationError::InvalidBase64(path.into()));
    }
    if decoded.len() != expected_len {
        return Err(ValidationError::InvalidSignatureLength {
            path: path.into(),
            expected: expected_len,
            actual: decoded.len(),
        });
    }
    Ok(())
}

pub fn validate_decimal_string(value: &str, path: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::EmptyDynamicField(path.into()));
    }
    if value != "0" && value.starts_with('0') {
        return Err(ValidationError::InvalidDecimal(path.into()));
    }
    value
        .parse::<u64>()
        .map(|_| ())
        .map_err(|_| ValidationError::InvalidDecimal(path.into()))
}

fn validate_relative_package_path(path: &str, field: &str) -> Result<(), ValidationError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(ValidationError::InvalidPackagePath(field.into()));
    }
    let parts: Vec<_> = path.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || matches!(*part, "." | ".."))
    {
        return Err(ValidationError::InvalidPackagePath(field.into()));
    }
    Ok(())
}

fn validate_allowlisted_relative_name(path: &str) -> Result<(), ValidationError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains("..") {
        return Err(ValidationError::InvalidPackagePath(
            "manifest.config_decoders[].allowlisted_relative_names".into(),
        ));
    }
    Ok(())
}

fn validate_reference_strings(values: &[String], path: &str) -> Result<(), ValidationError> {
    for value in values {
        if value.is_empty() {
            return Err(ValidationError::EmptyDynamicField(path.into()));
        }
    }
    Ok(())
}

fn validate_non_empty_unique<T>(values: &[T], path: &str) -> Result<(), ValidationError>
where
    T: Serialize,
{
    if values.is_empty() {
        return Err(ValidationError::EmptyDynamicField(path.into()));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        let canonical = serde_json::to_string(value).map_err(|_| {
            ValidationError::UnsupportedFeature(format!("cannot canonicalize {path}"))
        })?;
        if !seen.insert(canonical) {
            return Err(ValidationError::DuplicateEntry(path.into()));
        }
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("field is empty: {0}")]
    EmptyField(&'static str),
    #[error("field is empty: {0}")]
    EmptyDynamicField(String),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid field name: {0}")]
    InvalidFieldName(String),
    #[error("invalid semver: {0}")]
    InvalidSemver(String),
    #[error("invalid version requirement: {0}")]
    InvalidVersionReq(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    #[error("invalid base64url without padding: {0}")]
    InvalidBase64(String),
    #[error("invalid decimal string: {0}")]
    InvalidDecimal(String),
    #[error("placeholder or repeated digest is not allowed: {0}")]
    PlaceholderDigest(String),
    #[error("invalid package path: {0}")]
    InvalidPackagePath(String),
    #[error("duplicate entry in {0}")]
    DuplicateEntry(String),
    #[error("ast exceeds max depth {max}: {depth}")]
    AstTooDeep { depth: usize, max: usize },
    #[error("ast exceeds max node count {max}: {nodes}")]
    AstTooLarge { nodes: usize, max: usize },
    #[error("invalid predicate arity for {path}: {op:?} expected {expected}, got {actual}")]
    InvalidPredicateArity {
        path: String,
        op: PredicateOp,
        expected: usize,
        actual: usize,
    },
    #[error(
        "invalid predicate arity for {path}: {op:?} expected at least {min_expected}, got {actual}"
    )]
    InvalidPredicateMinArity {
        path: String,
        op: PredicateOp,
        min_expected: usize,
        actual: usize,
    },
    #[error("risk floor cannot be BLOCKED")]
    InvalidRiskFloor,
    #[error("rule attempts to lower risk from {floor} to {attempted}")]
    RiskLowering {
        floor: RiskTier,
        attempted: RiskTier,
    },
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
    #[error("signature binding mismatch: {0}")]
    SignatureBindingMismatch(String),
    #[error("invalid signature length for {path}: expected {expected}, got {actual}")]
    InvalidSignatureLength {
        path: String,
        expected: usize,
        actual: usize,
    },
    #[error("invalid numeric field: {0}")]
    InvalidNumber(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cargo_rule_json() -> Value {
        json!({
            "schema": CLEANER_RULE_SCHEMA,
            "id": "cargo-target-v1",
            "artifactClass": "regenerable-project-output",
            "platforms": [{"os": "windows", "arch": ["x86_64", "aarch64"]}, {"os": "macos", "arch": ["x86_64", "aarch64"]}, {"os": "linux", "arch": ["x86_64", "aarch64"]}],
            "rootRef": {"kind": "admitted-workspace", "evidence": "cargo.workspace.v1"},
            "discovery": {"effectClass": "z0", "capabilities": ["filesystem.metadata.read.scoped", "config.read.scoped"], "nativeProbeId": null, "semanticReadOnly": true, "zeroWriteVerified": true, "unknownVersionBehavior": "report_only"},
            "selectors": [{"kind": "typed-relative-path", "field": "cargo.targetDir", "mustBeWithinAdmittedRoot": true}],
            "requiredEvidence": ["cargo.workspace.v1", "cargo.config.target-dir.v1", "scan.final-complete-aggregate.v1"],
            "optionalEvidence": ["process.cargo-family.observed.v1"],
            "exclusionEvidence": ["workspace.shared-target.v1"],
            "grouping": "directory",
            "analysis": {
                "factPredicates": [{"op": "eq", "args": [{"field": "cargo.targetDir"}, {"field": "candidate.relativePath"}]}],
                "inferencePredicates": [{"op": "exists", "args": [{"field": "cargo.workspaceId"}]}],
                "unknownPolicy": "report_only"
            },
            "risk": {
                "floor": "R1",
                "monotonicRaises": [{"when": {"op": "eq", "args": [{"field": "objectType"}, "Directory"]}, "to": "R2"}]
            },
            "proposal": {"disposition": "eligible_with_confirmation", "supportedAction": "filesystemTrash", "targetGranularity": "closed-directory-manifest"},
            "recoveryRequirements": ["workspace retained"],
            "activityBlockers": ["observed cargo holder"],
            "sharingRules": ["shared target report only"],
            "explanationKeys": ["cargo.rebuild-cost"],
            "references": ["cargo-clean-official-docs@accessed-2026-08-26"]
        })
    }

    #[test]
    fn valid_rule_passes_validation() {
        let rule: CleanerRule = serde_json::from_value(cargo_rule_json()).expect("parse rule");
        assert_eq!(rule.validate(), Ok(()));
    }

    #[test]
    fn cannot_lower_risk() {
        let mut value = cargo_rule_json();
        value["risk"]["monotonicRaises"][0]["to"] = json!("R1");
        value["risk"]["floor"] = json!("R2");
        let rule: CleanerRule = serde_json::from_value(value).expect("parse rule");
        let err = rule.validate().expect_err("should reject lowering");
        assert!(matches!(err, ValidationError::RiskLowering { .. }));
    }

    #[test]
    fn rejects_unknown_policy_outside_enum() {
        let mut value = cargo_rule_json();
        value["analysis"]["unknownPolicy"] = json!("ignore");
        serde_json::from_value::<CleanerRule>(value)
            .expect_err("enum should reject unknown policy");
    }

    #[test]
    fn rejects_too_deep_ast() {
        let mut predicate = json!({"field": "x"});
        for _ in 0..(MAX_AST_DEPTH + 1) {
            predicate = json!({"op": "not", "args": [predicate]});
        }
        let mut value = cargo_rule_json();
        value["analysis"]["factPredicates"] = json!([predicate]);
        let rule: CleanerRule = serde_json::from_value(value).expect("parse rule");
        let err = rule.validate().expect_err("too deep");
        assert!(matches!(err, ValidationError::AstTooDeep { .. }));
    }

    #[test]
    fn rejects_invalid_package_path() {
        let manifest = CleanerManifest {
            schema: CLEANER_MANIFEST_SCHEMA.into(),
            id: "org.sweepx.test".into(),
            version: "1.0.0".into(),
            description: "desc".into(),
            publisher: PublisherRef {
                id: "org.sweepx".into(),
                key_id: "key-1".into(),
            },
            package_digest:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            requires: ManifestRequirements {
                core: ">=1.0.0, <2.0.0".into(),
                scanner_semantics: vec![1],
                candidate_schema: vec![1],
                rule_schema: vec![1],
                native_probe_abi: vec![1],
            },
            platforms: vec![PlatformSpec {
                os: Os::Linux,
                arch: vec![Arch::X86_64],
            }],
            target_versions: TargetVersions {
                cargo: Some(">=1.70 <2.0".into()),
                browser: None,
                unknown: UnknownVersionBehavior::ReportOnly,
            },
            capabilities: ManifestCapabilities {
                discover: ManifestCapabilityStage {
                    required: vec!["filesystem.metadata.read.scoped".into()],
                    optional: vec![],
                },
                semantic_query: vec![],
                analyze: vec!["rule.evaluate.pure".into()],
                plan_proposal: vec!["candidate.propose.filesystemTrash".into()],
                official_mutation: vec![],
                post_action_verification: vec!["filesystem.identity.read.scoped".into()],
            },
            roots: vec![RootRef::ExplicitScanRoot],
            config_decoders: vec![ConfigDecoder {
                id: "decoder".into(),
                schema: "sweepx.config-decoder/v1".into(),
                formats: vec!["cargo-toml".into()],
                allowlisted_relative_names: vec!["Cargo.toml".into()],
                single_file_bytes: 1,
                total_bytes: 1,
                network: DenyPolicy::Deny,
                includes: DenyPolicy::Deny,
                credentials: DenyPolicy::Deny,
                output_schema: "cargo.workspace-evidence/v1".into(),
            }],
            rules: vec![ManifestRuleRef {
                id: "cargo-target-v1".into(),
                path: "../escape.json".into(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            }],
            probes: vec![],
            official_commands: vec![],
            risk_floor: RiskTier::R1,
            supported_actions: vec![SupportedAction::Report, SupportedAction::FilesystemTrash],
            references: vec!["ref".into()],
            expires_at: "2027-08-26T00:00:00Z".into(),
        };
        let err = manifest
            .validate()
            .expect_err("should reject path traversal");
        assert!(matches!(err, ValidationError::InvalidPackagePath(_)));
    }

    #[test]
    fn rejects_placeholder_package_digest() {
        let manifest = CleanerManifest {
            schema: CLEANER_MANIFEST_SCHEMA.into(),
            id: "org.sweepx.test".into(),
            version: "1.0.0".into(),
            description: "desc".into(),
            publisher: PublisherRef {
                id: "org.sweepx".into(),
                key_id: "key-1".into(),
            },
            package_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            requires: ManifestRequirements {
                core: ">=1.0.0, <2.0.0".into(),
                scanner_semantics: vec![1],
                candidate_schema: vec![1],
                rule_schema: vec![1],
                native_probe_abi: vec![1],
            },
            platforms: vec![PlatformSpec {
                os: Os::Linux,
                arch: vec![Arch::X86_64],
            }],
            target_versions: TargetVersions {
                cargo: Some(">=1.70 <2.0".into()),
                browser: None,
                unknown: UnknownVersionBehavior::ReportOnly,
            },
            capabilities: ManifestCapabilities {
                discover: ManifestCapabilityStage {
                    required: vec!["filesystem.metadata.read.scoped".into()],
                    optional: vec![],
                },
                semantic_query: vec![],
                analyze: vec!["rule.evaluate.pure".into()],
                plan_proposal: vec!["candidate.propose.filesystemTrash".into()],
                official_mutation: vec![],
                post_action_verification: vec!["filesystem.identity.read.scoped".into()],
            },
            roots: vec![RootRef::ExplicitScanRoot],
            config_decoders: vec![],
            rules: vec![ManifestRuleRef {
                id: "cargo-target-v1".into(),
                path: "rules/cargo-target.json".into(),
                sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            }],
            probes: vec![],
            official_commands: vec![],
            risk_floor: RiskTier::R1,
            supported_actions: vec![SupportedAction::Report, SupportedAction::FilesystemTrash],
            references: vec!["ref".into()],
            expires_at: "2027-08-26T00:00:00Z".into(),
        };
        let err = manifest
            .validate()
            .expect_err("placeholder digest must fail");
        assert!(matches!(err, ValidationError::PlaceholderDigest(_)));
    }

    #[test]
    fn rejects_unsupported_transparency_proof() {
        let envelope = CleanerSignatureEnvelope {
            schema: CLEANER_SIGNATURE_SCHEMA.into(),
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "key-1".into(),
            publisher_id: "org.sweepx".into(),
            package_id: "org.sweepx.test".into(),
            package_version: "1.0.0".into(),
            package_digest:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            manifest_schema: CLEANER_MANIFEST_SCHEMA.into(),
            signed_at: "2026-08-27T00:00:00Z".into(),
            expires_at: Some("2027-08-27T00:00:00Z".into()),
            transparency_proof: Some(json!({"kind": "rekor"})),
            signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        };
        let err = envelope
            .validate()
            .expect_err("transparencyProof must fail closed");
        assert!(matches!(err, ValidationError::UnsupportedFeature(_)));
    }

    #[test]
    fn rejects_noncanonical_decimal_bytes_and_short_signature() {
        let err = validate_decimal_string("001", "signature.files[].bytes")
            .expect_err("bytes must be canonical decimal");
        assert!(matches!(err, ValidationError::InvalidDecimal(_)));

        let envelope = CleanerSignatureEnvelope {
            schema: CLEANER_SIGNATURE_SCHEMA.into(),
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "key-1".into(),
            publisher_id: "org.sweepx".into(),
            package_id: "org.sweepx.test".into(),
            package_version: "1.0.0".into(),
            package_digest:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            manifest_schema: CLEANER_MANIFEST_SCHEMA.into(),
            signed_at: "2026-08-27T00:00:00Z".into(),
            expires_at: Some("2027-08-27T00:00:00Z".into()),
            transparency_proof: None,
            signature: "AQ".into(),
        };
        let err = envelope
            .validate()
            .expect_err("signature must decode to exactly 64 bytes");
        assert!(matches!(
            err,
            ValidationError::InvalidSignatureLength { .. }
        ));
    }
}
