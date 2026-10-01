use super::*;
use std::fs;
use std::time::{Duration, Instant};

fn complete(provider: &mut Provider) -> Vec<JunkEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "session did not finish");
        if let Some(event) = provider.poll() {
            let done = matches!(event, JunkEvent::Completed { .. });
            events.push(event);
            if done {
                return events;
            }
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn bridge_refreshes_current_native_evidence_and_refuses_replaced_object_before_trash() {
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"original").unwrap();
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root.clone()])).unwrap());
    let events = complete(&mut provider);
    assert!(matches!(
        events.last().unwrap(),
        JunkEvent::Completed {
            outcome: JunkOutcome::Complete,
            replaced: true,
            ..
        }
    ));
    let key = provider.rows.keys().next().unwrap().clone();
    assert_eq!(
        provider.rows[&key].row.aggregate.apparent_logical_bytes,
        sweepx_platform::known_u128(8)
    );
    fs::write(target.join("payload"), b"updated-current").unwrap();
    provider.refresh(std::slice::from_ref(&key)).unwrap();
    let events = complete(&mut provider);
    assert!(
        matches!(events.first().unwrap(), JunkEvent::Started { revision: 2, keys: Some(keys) } if keys == std::slice::from_ref(&key))
    );
    assert_eq!(
        provider.rows[&key].row.aggregate.apparent_logical_bytes,
        sweepx_platform::known_u128(u128::from(
            fs::symlink_metadata(target.join("payload")).unwrap().len()
        ))
    );
    let old = provider.rows[&key].row.clone();
    fs::rename(&target, root.join("retained-old-target")).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"replacement").unwrap();
    // The real native preflight rejects before reaching the host Trash backend, preserving both.
    let failure =
        crate::trash_command::trash_session_candidate(&old, &CancellationToken::new()).unwrap_err();
    assert!(failure.starts_with("refresh_binding_changed:"), "{failure}");
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"replacement");
    assert_eq!(
        fs::read(root.join("retained-old-target/payload")).unwrap(),
        b"updated-current"
    );
    #[cfg(unix)]
    {
        fs::rename(&target, root.join("retained-replacement")).unwrap();
        std::os::unix::fs::symlink(root.join("retained-replacement"), &target).unwrap();
        let failure =
            crate::trash_command::trash_session_candidate(&old, &CancellationToken::new())
                .unwrap_err();
        assert!(failure.starts_with("refresh_binding_changed:"), "{failure}");
        assert_eq!(
            fs::read(root.join("retained-replacement/payload")).unwrap(),
            b"replacement"
        );
    }
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}
