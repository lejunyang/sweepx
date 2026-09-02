//! Platform-agnostic privilege detection and opt-in elevation contracts.
//!
//! Two questions are kept strictly apart here, because conflating them is how a
//! cleanup tool silently becomes a tool that runs as Administrator:
//!
//! 1. *What privilege does this process already hold?* Answering this is always
//!    allowed, is read-only, and never prompts the user.
//! 2. *May this process acquire more privilege?* This only ever happens when the
//!    user explicitly asked for it, and it can always be declined.
//!
//! `DESIGN.md` R-23 fixes the policy that this module encodes: a user may well
//! start SweepX from an elevated session, in which case read-only capabilities may
//! report what they can see, but destructive mode is refused outright rather than
//! silently dropping privilege and continuing. Elevation therefore may widen what a
//! *scan* can observe; it must never widen what a *deletion* is allowed to touch.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Whether the current process already holds host-defined elevated privilege.
///
/// Deliberately three-valued. A backend that cannot answer must say so instead of
/// guessing `NotElevated`, because "assume unprivileged" reads as a safe default
/// yet quietly turns into "assume the destructive-mode refusal does not apply".
/// Both a definite answer and an admitted unknown are safe; a fabricated one is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevel {
    /// The process runs with ordinary user privilege.
    NotElevated,
    /// The process already holds elevated privilege, without SweepX requesting it.
    Elevated,
    /// The host could not be queried. Treated as "not elevated" for granting
    /// capability, and as "possibly elevated" for refusing destructive mode.
    Unknown,
}

impl PrivilegeLevel {
    /// Reports whether an elevation-gated read-only capability may be enabled.
    ///
    /// Only a definite `Elevated` grants anything: an unknown answer must not
    /// unlock a fast path whose failure mode is an unreadable volume handle.
    pub fn grants_elevated_capability(self) -> bool {
        matches!(self, Self::Elevated)
    }

    /// Reports whether destructive mode must be refused under R-23.
    ///
    /// Note the asymmetry with [`Self::grants_elevated_capability`]: `Unknown`
    /// refuses here but grants nothing there. Each direction independently
    /// resolves uncertainty toward the safer outcome, which is why one predicate
    /// cannot simply be the negation of the other.
    pub fn must_refuse_destructive_mode(self) -> bool {
        matches!(self, Self::Elevated | Self::Unknown)
    }
}

impl fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NotElevated => "not_elevated",
            Self::Elevated => "elevated",
            Self::Unknown => "unknown",
        };
        f.write_str(text)
    }
}

/// How the current privilege level was established.
///
/// Recorded so a report can distinguish "the user started us elevated" from "the
/// user approved a prompt we raised", which are different consent facts even
/// though they produce the same [`PrivilegeLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeOrigin {
    /// Privilege was inherited from how the user launched the process.
    InheritedFromSession,
    /// Privilege was granted by the user in response to an explicit request.
    GrantedOnRequest,
    /// No elevated privilege is held.
    None,
}

/// A read-only observation of the process privilege state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegeObservation {
    /// The privilege level held at observation time.
    pub level: PrivilegeLevel,
    /// How that level came to be held.
    pub origin: PrivilegeOrigin,
}

impl PrivilegeObservation {
    /// Records an unelevated process.
    pub const fn not_elevated() -> Self {
        Self {
            level: PrivilegeLevel::NotElevated,
            origin: PrivilegeOrigin::None,
        }
    }

    /// Records privilege inherited from the launching session.
    pub const fn inherited() -> Self {
        Self {
            level: PrivilegeLevel::Elevated,
            origin: PrivilegeOrigin::InheritedFromSession,
        }
    }

    /// Records an indeterminate observation, carrying the reason it failed.
    pub const fn unknown() -> Self {
        Self {
            level: PrivilegeLevel::Unknown,
            origin: PrivilegeOrigin::None,
        }
    }
}

/// Whether SweepX may ask the host to raise privilege.
///
/// The default is [`Self::DetectOnly`] so that merely wiring this type into a code
/// path can never introduce a prompt; requesting elevation requires naming the
/// other variant explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElevationPolicy {
    /// Observe existing privilege only. Never prompt.
    #[default]
    DetectOnly,
    /// The user explicitly opted in, so a host elevation prompt is permitted.
    RequestWhenUserOptedIn,
}

/// Why an elevation request did not result in elevated privilege.
///
/// A declined prompt is a first-class, expected outcome and not an error state:
/// the caller must continue on its unprivileged path. It is kept distinct from
/// `Unavailable` and `Failed` so a report can tell the user "you declined" rather
/// than implying something broke.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ElevationRefusal {
    /// The user or the OS declined the request.
    #[error("elevation was declined")]
    Declined,
    /// The policy in effect did not permit requesting elevation.
    #[error("elevation was not requested because the policy is detect-only")]
    PolicyForbidsRequest,
    /// The host offers no elevation mechanism SweepX is willing to use.
    #[error("no supported elevation mechanism is available on this host: {0}")]
    Unavailable(String),
    /// The request mechanism itself failed.
    #[error("the elevation request failed: {0}")]
    Failed(String),
}

/// Host-specific privilege detection and opt-in elevation.
///
/// Implementations must keep detection free of side effects: no prompt, no process
/// launch, no persistent change. [`Self::request_elevation`] is the only method
/// permitted to surface a host consent dialog, and only under
/// [`ElevationPolicy::RequestWhenUserOptedIn`].
pub trait PrivilegeProvider: Send + Sync {
    /// Names the backend, for diagnostics and evidence records.
    fn provider_name(&self) -> &'static str;

    /// Observes current privilege without prompting or mutating any state.
    fn observe(&self) -> PrivilegeObservation;

    /// Asks the host to raise privilege, honoring `policy`.
    ///
    /// Implementations must return [`ElevationRefusal::PolicyForbidsRequest`]
    /// without contacting the host when `policy` is
    /// [`ElevationPolicy::DetectOnly`], so that the policy check cannot be
    /// bypassed by calling this directly. The default implementation refuses
    /// everything, keeping a new backend fail-closed until it deliberately opts
    /// into supporting elevation.
    fn request_elevation(
        &self,
        policy: ElevationPolicy,
    ) -> Result<PrivilegeObservation, ElevationRefusal> {
        if policy == ElevationPolicy::DetectOnly {
            return Err(ElevationRefusal::PolicyForbidsRequest);
        }
        Err(ElevationRefusal::Unavailable(format!(
            "{} does not implement elevation requests",
            self.provider_name()
        )))
    }

    /// Re-runs this program elevated and reports the child's exit code.
    ///
    /// Some hosts, Windows among them, grant elevation only when a process is
    /// *created*; a running process cannot raise its own privilege. On those hosts
    /// honoring an opt-in means launching a second, elevated copy and adopting its
    /// result, which is why this is separate from [`Self::request_elevation`] and
    /// why the caller must invoke it before any run state exists.
    ///
    /// Returning `Ok` means a child ran to completion and its exit code is
    /// authoritative for the whole invocation; the caller must exit with it and must
    /// not also do the work itself. Every refusal leaves the current process intact
    /// and responsible for continuing unprivileged.
    fn relaunch_elevated(&self, _request: &ElevatedRelaunch) -> Result<u8, ElevationRefusal> {
        Err(ElevationRefusal::Unavailable(format!(
            "{} does not implement elevated relaunch",
            self.provider_name()
        )))
    }
}

/// What to re-run when elevating by relaunch.
///
/// The forwarded arguments deliberately exclude the opt-in flag itself. If the child
/// saw it again it would evaluate the same opt-in, find itself already elevated or
/// still unable to elevate, and could relaunch once more; excluding it makes a
/// second relaunch structurally impossible rather than merely unlikely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevatedRelaunch {
    /// Absolute path to the executable image to run.
    pub program: PathBuf,
    /// Arguments to forward, without the program name and without the opt-in flag.
    pub arguments: Vec<OsString>,
}

impl ElevatedRelaunch {
    /// Describes a relaunch of `program` with `arguments`.
    pub fn new(program: PathBuf, arguments: Vec<OsString>) -> Self {
        Self { program, arguments }
    }
}

/// Resolves the privilege to use for a run, applying `policy` at most once.
///
/// Returns the observation plus whether elevation was requested, so a caller can
/// report the consent path it actually took. Elevation is requested only when the
/// process is *definitely* not elevated: an `Unknown` observation must not trigger
/// a prompt, because prompting on an unreadable token would nag a user who may
/// already hold privilege.
pub fn resolve_privilege<P: PrivilegeProvider + ?Sized>(
    provider: &P,
    policy: ElevationPolicy,
) -> (PrivilegeObservation, Option<ElevationRefusal>) {
    let observed = provider.observe();
    if observed.level == PrivilegeLevel::Elevated || policy == ElevationPolicy::DetectOnly {
        return (observed, None);
    }
    if observed.level == PrivilegeLevel::Unknown {
        return (observed, None);
    }
    match provider.request_elevation(policy) {
        Ok(granted) => (granted, None),
        Err(refusal) => (observed, Some(refusal)),
    }
}

/// What an entry point should do about privilege, decided before any work begins.
///
/// Deliberately a decision *value* rather than an action: the CLI's first job is to
/// find out whether this process is the one that does the work, and that answer must
/// be inspectable in a test without launching a process or raising a dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPrivilegeDecision {
    /// Continue in this process with the given privilege.
    Continue {
        /// Privilege this process holds.
        observed: PrivilegeObservation,
        /// Set when an opt-in elevation was attempted and did not succeed. The run
        /// continues unprivileged; this is reportable, not fatal.
        refusal: Option<ElevationRefusal>,
    },
    /// An elevated child already performed the work. Exit with this code and do nothing else.
    ElevatedChildCompleted {
        /// The child's exit code, authoritative for this invocation.
        exit_code: u8,
    },
}

/// Decides, at process start, whether to elevate by relaunch or to continue as-is.
///
/// The ordering is what makes this safe, and each step exists to rule out a specific
/// failure:
///
/// * Detection runs first, so an already-elevated process never prompts and never
///   relaunches. Without this, launching from an Administrator shell with the opt-in
///   set would spawn an endless chain of children.
/// * `DetectOnly` returns before anything host-facing happens, so the default path
///   cannot produce a dialog no matter what the backend implements.
/// * `Unknown` continues rather than relaunching, because relaunching on an
///   unreadable token would restart the process to reach a state it may already be in.
/// * Any refusal keeps the current process running, so a declined prompt degrades to
///   the unprivileged path instead of aborting the run.
pub fn decide_startup_privilege<P: PrivilegeProvider + ?Sized>(
    provider: &P,
    policy: ElevationPolicy,
    relaunch: &ElevatedRelaunch,
) -> StartupPrivilegeDecision {
    let observed = provider.observe();
    if policy == ElevationPolicy::DetectOnly
        || observed.level == PrivilegeLevel::Elevated
        || observed.level == PrivilegeLevel::Unknown
    {
        return StartupPrivilegeDecision::Continue {
            observed,
            refusal: None,
        };
    }
    match provider.relaunch_elevated(relaunch) {
        Ok(exit_code) => StartupPrivilegeDecision::ElevatedChildCompleted { exit_code },
        Err(refusal) => StartupPrivilegeDecision::Continue {
            observed,
            refusal: Some(refusal),
        },
    }
}

#[cfg(test)]
mod privilege_tests {
    use super::*;

    struct FixedProvider {
        observation: PrivilegeObservation,
        request_result: Option<Result<PrivilegeObservation, ElevationRefusal>>,
        requests: std::sync::atomic::AtomicUsize,
        relaunch_result: Option<Result<u8, ElevationRefusal>>,
        relaunches: std::sync::atomic::AtomicUsize,
    }

    impl FixedProvider {
        fn new(observation: PrivilegeObservation) -> Self {
            Self {
                observation,
                request_result: None,
                requests: std::sync::atomic::AtomicUsize::new(0),
                relaunch_result: None,
                relaunches: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn with_request(mut self, result: Result<PrivilegeObservation, ElevationRefusal>) -> Self {
            self.request_result = Some(result);
            self
        }

        fn with_relaunch(mut self, result: Result<u8, ElevationRefusal>) -> Self {
            self.relaunch_result = Some(result);
            self
        }

        fn request_count(&self) -> usize {
            self.requests.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn relaunch_count(&self) -> usize {
            self.relaunches.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl PrivilegeProvider for FixedProvider {
        fn provider_name(&self) -> &'static str {
            "fixed-test-provider"
        }

        fn observe(&self) -> PrivilegeObservation {
            self.observation
        }

        fn request_elevation(
            &self,
            policy: ElevationPolicy,
        ) -> Result<PrivilegeObservation, ElevationRefusal> {
            self.requests
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if policy == ElevationPolicy::DetectOnly {
                return Err(ElevationRefusal::PolicyForbidsRequest);
            }
            self.request_result
                .clone()
                .unwrap_or(Err(ElevationRefusal::Declined))
        }

        fn relaunch_elevated(&self, _request: &ElevatedRelaunch) -> Result<u8, ElevationRefusal> {
            self.relaunches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.relaunch_result
                .clone()
                .unwrap_or(Err(ElevationRefusal::Declined))
        }
    }

    fn test_relaunch() -> ElevatedRelaunch {
        ElevatedRelaunch::new(PathBuf::from("/test/sweepx"), vec![OsString::from("scan")])
    }

    #[test]
    fn detect_only_never_contacts_the_host() {
        let provider = FixedProvider::new(PrivilegeObservation::not_elevated());
        let (observed, refusal) = resolve_privilege(&provider, ElevationPolicy::DetectOnly);

        assert_eq!(observed, PrivilegeObservation::not_elevated());
        assert_eq!(refusal, None);
        // The prompt must not merely be discarded; it must never be raised.
        assert_eq!(provider.request_count(), 0);
    }

    #[test]
    fn inherited_privilege_is_used_without_requesting_more() {
        let provider = FixedProvider::new(PrivilegeObservation::inherited());
        let (observed, refusal) =
            resolve_privilege(&provider, ElevationPolicy::RequestWhenUserOptedIn);

        assert_eq!(observed.level, PrivilegeLevel::Elevated);
        assert_eq!(observed.origin, PrivilegeOrigin::InheritedFromSession);
        assert_eq!(refusal, None);
        assert_eq!(provider.request_count(), 0);
    }

    #[test]
    fn opted_in_request_records_granted_origin() {
        let granted = PrivilegeObservation {
            level: PrivilegeLevel::Elevated,
            origin: PrivilegeOrigin::GrantedOnRequest,
        };
        let provider =
            FixedProvider::new(PrivilegeObservation::not_elevated()).with_request(Ok(granted));
        let (observed, refusal) =
            resolve_privilege(&provider, ElevationPolicy::RequestWhenUserOptedIn);

        assert_eq!(observed, granted);
        assert_eq!(refusal, None);
        assert_eq!(provider.request_count(), 1);
    }

    #[test]
    fn declined_elevation_keeps_the_unprivileged_observation() {
        let provider = FixedProvider::new(PrivilegeObservation::not_elevated())
            .with_request(Err(ElevationRefusal::Declined));
        let (observed, refusal) =
            resolve_privilege(&provider, ElevationPolicy::RequestWhenUserOptedIn);

        // A decline must leave the caller on its unprivileged path, not in an error state.
        assert_eq!(observed.level, PrivilegeLevel::NotElevated);
        assert_eq!(refusal, Some(ElevationRefusal::Declined));
        assert!(!observed.level.grants_elevated_capability());
    }

    #[test]
    fn unknown_privilege_does_not_prompt_and_resolves_both_ways_safely() {
        let provider = FixedProvider::new(PrivilegeObservation::unknown());
        let (observed, refusal) =
            resolve_privilege(&provider, ElevationPolicy::RequestWhenUserOptedIn);

        assert_eq!(observed.level, PrivilegeLevel::Unknown);
        assert_eq!(refusal, None);
        assert_eq!(provider.request_count(), 0);
        // Uncertainty grants no capability yet still forbids destructive mode.
        assert!(!observed.level.grants_elevated_capability());
        assert!(observed.level.must_refuse_destructive_mode());
    }

    #[test]
    fn default_provider_refuses_elevation_fail_closed() {
        struct Minimal;
        impl PrivilegeProvider for Minimal {
            fn provider_name(&self) -> &'static str {
                "minimal"
            }
            fn observe(&self) -> PrivilegeObservation {
                PrivilegeObservation::not_elevated()
            }
        }

        assert_eq!(
            Minimal.request_elevation(ElevationPolicy::DetectOnly),
            Err(ElevationRefusal::PolicyForbidsRequest)
        );
        assert!(matches!(
            Minimal.request_elevation(ElevationPolicy::RequestWhenUserOptedIn),
            Err(ElevationRefusal::Unavailable(_))
        ));
    }

    #[test]
    fn r23_destructive_refusal_covers_elevated_and_unknown_only() {
        assert!(!PrivilegeLevel::NotElevated.must_refuse_destructive_mode());
        assert!(PrivilegeLevel::Elevated.must_refuse_destructive_mode());
        assert!(PrivilegeLevel::Unknown.must_refuse_destructive_mode());

        assert!(!PrivilegeLevel::NotElevated.grants_elevated_capability());
        assert!(PrivilegeLevel::Elevated.grants_elevated_capability());
        assert!(!PrivilegeLevel::Unknown.grants_elevated_capability());
    }

    /// The default path must be incapable of relaunching or prompting.
    #[test]
    fn startup_default_policy_neither_prompts_nor_relaunches() {
        let provider = FixedProvider::new(PrivilegeObservation::not_elevated())
            .with_relaunch(Ok(0))
            .with_request(Ok(PrivilegeObservation::inherited()));

        let decision =
            decide_startup_privilege(&provider, ElevationPolicy::default(), &test_relaunch());

        assert_eq!(
            decision,
            StartupPrivilegeDecision::Continue {
                observed: PrivilegeObservation::not_elevated(),
                refusal: None,
            }
        );
        // Not "the result was ignored" but "the host was never contacted".
        assert_eq!(provider.relaunch_count(), 0);
        assert_eq!(provider.request_count(), 0);
    }

    /// An already-elevated process must never relaunch itself.
    ///
    /// This is the fork-bomb guard: each child would inherit the opt-in reasoning and
    /// spawn another. Detection ordering is what prevents it, so it is asserted
    /// directly rather than assumed.
    #[test]
    fn startup_does_not_relaunch_when_already_elevated() {
        let provider = FixedProvider::new(PrivilegeObservation::inherited()).with_relaunch(Ok(0));

        let decision = decide_startup_privilege(
            &provider,
            ElevationPolicy::RequestWhenUserOptedIn,
            &test_relaunch(),
        );

        assert_eq!(
            decision,
            StartupPrivilegeDecision::Continue {
                observed: PrivilegeObservation::inherited(),
                refusal: None,
            }
        );
        assert_eq!(provider.relaunch_count(), 0);
    }

    /// An opted-in relaunch hands the whole invocation to the child.
    #[test]
    fn startup_adopts_the_elevated_child_exit_code() {
        let provider =
            FixedProvider::new(PrivilegeObservation::not_elevated()).with_relaunch(Ok(4));

        let decision = decide_startup_privilege(
            &provider,
            ElevationPolicy::RequestWhenUserOptedIn,
            &test_relaunch(),
        );

        // Exit code 4 is `partial`, not success: the parent must forward whatever the
        // child reported rather than collapsing it to 0.
        assert_eq!(
            decision,
            StartupPrivilegeDecision::ElevatedChildCompleted { exit_code: 4 }
        );
        assert_eq!(provider.relaunch_count(), 1);
    }

    /// A declined prompt must fall back to the unprivileged path, not abort.
    #[test]
    fn startup_declined_elevation_continues_unprivileged() {
        let provider = FixedProvider::new(PrivilegeObservation::not_elevated())
            .with_relaunch(Err(ElevationRefusal::Declined));

        let decision = decide_startup_privilege(
            &provider,
            ElevationPolicy::RequestWhenUserOptedIn,
            &test_relaunch(),
        );

        match decision {
            StartupPrivilegeDecision::Continue { observed, refusal } => {
                assert_eq!(observed.level, PrivilegeLevel::NotElevated);
                assert_eq!(refusal, Some(ElevationRefusal::Declined));
                assert!(!observed.level.grants_elevated_capability());
            }
            other => panic!("a declined elevation must continue in-process, got {other:?}"),
        }
    }

    /// An unreadable token must not cause a relaunch.
    #[test]
    fn startup_unknown_privilege_does_not_relaunch() {
        let provider = FixedProvider::new(PrivilegeObservation::unknown()).with_relaunch(Ok(0));

        let decision = decide_startup_privilege(
            &provider,
            ElevationPolicy::RequestWhenUserOptedIn,
            &test_relaunch(),
        );

        assert_eq!(
            decision,
            StartupPrivilegeDecision::Continue {
                observed: PrivilegeObservation::unknown(),
                refusal: None,
            }
        );
        assert_eq!(provider.relaunch_count(), 0);
    }

    /// A backend that has not implemented relaunch must refuse, not silently succeed.
    #[test]
    fn startup_default_backend_refuses_relaunch_fail_closed() {
        struct Minimal;
        impl PrivilegeProvider for Minimal {
            fn provider_name(&self) -> &'static str {
                "minimal"
            }
            fn observe(&self) -> PrivilegeObservation {
                PrivilegeObservation::not_elevated()
            }
        }

        let decision = decide_startup_privilege(
            &Minimal,
            ElevationPolicy::RequestWhenUserOptedIn,
            &test_relaunch(),
        );

        match decision {
            StartupPrivilegeDecision::Continue { refusal, .. } => {
                assert!(matches!(refusal, Some(ElevationRefusal::Unavailable(_))));
            }
            other => panic!("an unimplemented relaunch must not appear to succeed: {other:?}"),
        }
    }
}
