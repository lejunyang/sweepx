mod candidate;
mod digest;
mod duplicates;
mod explain;
mod large_files;

pub use duplicates::{
    DuplicateCollector, DuplicateContentSource, DuplicateGroup, DuplicateIncompleteReason,
    DuplicateOptions, DuplicateOptionsError, DuplicateReport,
};

pub use large_files::{
    LargeFileCollector, LargeFileIncompleteReason, LargeFileOptions, LargeFileOptionsError,
    LargeFileReport,
};

pub use candidate::{
    Candidate, CandidateBuilder, CandidateDigestInput, CandidateEligibility, CandidateLocator,
    CandidateSourceState, ExecutableEligibility, Explanation, ExplanationBuilder,
    ExplanationClause, ExplanationDigestInput, ExplanationKind, FactPresence, InferenceStrength,
    MonotonicClassifier, PathPresentation, RiskAssessment, RiskSignal, UnknownImpact,
};
pub use digest::{AnalysisDigestError, analysis_attention_fingerprint, analysis_digest_hex};
pub use explain::{
    BuildError, DirectoryAggregateLink, build_candidate_from_scan, build_candidates_from_summary,
    build_candidates_from_summary_with_links, build_explanation_from_candidate,
};
