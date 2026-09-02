//! Executor behavior on hosts without durable audit state.
//!
//! The main [`super::tests`] suite is Unix-only because every case needs a real
//! `AuditStore` to observe durable reservation. Rather than leave Windows with no
//! executor coverage at all, this module pins the contract that actually applies
//! there: the executor must refuse to start, before any adapter call, because
//! at-most-once submission cannot be proven without durable state.

use sweepx_audit::{AuditError, AuditStore};
use tempfile::TempDir;

/// Execution cannot be claimed on a host where the audit store is refused.
///
/// This is the fail-closed half of the durability contract. A host that cannot
/// record an intent must not be allowed to run a destructive action "best effort":
/// without a durable reservation a crash between submit and outcome would be
/// indistinguishable from a never-submitted action, so a retry could delete twice.
/// Refusing at store construction is what keeps that ambiguity unreachable.
#[test]
fn executor_cannot_be_claimed_without_a_durable_audit_store() {
    let temp = TempDir::new().expect("temporary directory is created");
    let root = temp.path().join("audit");
    std::fs::create_dir(&root).expect("audit directory is created");

    assert!(
        matches!(
            AuditStore::open(&root),
            Err(AuditError::UnsupportedPlatform)
        ),
        "durable state must be refused rather than silently degraded"
    );
    // The refusal must be inert: no lock, no database, nothing to recover from.
    assert_eq!(
        std::fs::read_dir(&root)
            .expect("audit directory is readable")
            .count(),
        0,
        "a refused audit store must not leave partial state behind"
    );
}
