mod candidate;
mod digest;
mod explain;

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
