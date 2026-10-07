use super::*;
use crate::NeverTerminate;
use crossterm::event::{KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use std::collections::VecDeque;
use sweepx_model::{DecimalU128, EvidenceValue, ReasonCode};

struct FixtureRow {
    key: &'static str,
    path: &'static str,
    bytes: ByteValue,
    complete: bool,
    report_only: bool,
    cost: usize,
}
impl JunkRow for FixtureRow {
    fn key(&self) -> &str {
        self.key
    }
    fn path(&self) -> &str {
        self.path
    }
    fn rule(&self) -> &str {
        if self.key == "artifact" {
            "rust.incremental"
        } else {
            "rust_target"
        }
    }
    fn evidence(&self) -> &str {
        "controlled rebuildable output"
    }
    fn context(&self) -> String {
        if self.key == "verbose" {
            return "Long rule context with current evidence and restrictions. ".repeat(32);
        }
        "risk=R1 · classification=known_generated · confidence=medium".into()
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.bytes
    }
    fn complete(&self) -> bool {
        self.complete
    }
    fn report_allows_trash(&self) -> bool {
        !self.report_only
    }
    fn retained_bytes(&self) -> usize {
        self.cost
    }
}

#[test]
fn action_result_stays_visible_above_verbose_rule_context() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    model.apply(JunkEvent::Candidate {
        revision: 0,
        current: true,
        historical: false,
        row: row("verbose", "/project/target"),
    });
    model.reorder();
    model.diagnostic("Review list (deletion not authorized)\n/project/target/debug".into());
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("Review list (deletion not authorized)"));
    assert!(screen.contains("/project/target/debug"));
}

#[test]
fn artifact_rows_render_local_labels_without_changing_rule_or_trash_policy() {
    for (locale, expected) in [
        (Locale::ZhCn, "Rust 增量缓存"),
        (Locale::EnUs, "Rust incremental cache"),
    ] {
        let row: Arc<dyn JunkRow> = Arc::new(FixtureRow {
            key: "artifact",
            path: "/project/target/debug/incremental",
            bytes: EvidenceValue::Known {
                value: DecimalU128::new(8),
            },
            complete: true,
            report_only: true,
            cost: 256,
        });
        assert_eq!(row.rule(), "rust.incremental");
        assert!(!row.report_allows_trash());
        let mut model = JunkModel::new(locale, HumanSizeUnit::Bytes);
        model.apply(JunkEvent::Candidate {
            revision: 0,
            current: true,
            historical: false,
            row,
        });
        model.reorder();
        let mut terminal = Terminal::new(TestBackend::new(160, 24)).unwrap();
        terminal.draw(|frame| render_junk(frame, &model)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        // TestBackend keeps a blank continuation cell for each double-width Chinese glyph.
        assert!(
            screen.replace(' ', "").contains(&expected.replace(' ', "")),
            "{screen}"
        );
    }
}
fn row(key: &'static str, path: &'static str) -> Arc<dyn JunkRow> {
    Arc::new(FixtureRow {
        key,
        path,
        bytes: EvidenceValue::Known {
            value: DecimalU128::new(8),
        },
        complete: true,
        report_only: false,
        cost: 256,
    })
}
fn initial() -> VecDeque<JunkEvent> {
    VecDeque::from([
        JunkEvent::Started {
            revision: 1,
            keys: None,
        },
        JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: row("a", "/a"),
        },
        JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: row("b", "/b"),
        },
        JunkEvent::Completed {
            revision: 1,
            outcome: JunkOutcome::Complete,
            replaced: true,
        },
    ])
}

#[test]
fn early_complete_base_is_visible_during_scan_and_selection_survives_current_replacement() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    model.apply(JunkEvent::Started {
        revision: 1,
        keys: None,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: false,
        historical: false,
        row: row("early", "/project/target"),
    });
    model.reorder();
    model.marked.insert("early".into());
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("/project/target"));
    assert!(screen.contains("Interpreting"));
    assert!(model.busy && model.rows["early"].row.complete());
    assert!(!model.eligible("early"));
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row: row("early", "/project/target"),
    });
    assert!(!model.eligible("early"), "enrichment does not end the scan");
    model.apply(JunkEvent::Completed {
        revision: 1,
        outcome: JunkOutcome::Complete,
        replaced: true,
    });
    model.reorder();
    assert!(model.eligible("early"));
    assert!(model.marked.contains("early"));
    assert_eq!(model.order[model.cursor], "early");
}

#[test]
fn local_refresh_invalidates_only_ancestors_and_preserves_them_after_scope_completion() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    model.marked.insert("a".into());
    model.apply(JunkEvent::Started {
        revision: 2,
        keys: Some(vec!["b".into()]),
    });
    model.apply(JunkEvent::Invalidated {
        revision: 2,
        key: "a".into(),
    });
    model.apply(JunkEvent::Candidate {
        revision: 2,
        current: true,
        historical: false,
        row: row("b", "/b"),
    });
    model.apply(JunkEvent::Completed {
        revision: 2,
        outcome: JunkOutcome::Complete,
        replaced: true,
    });
    assert!(model.rows["a"].historical);
    assert!(!model.eligible("a"));
    assert!(model.eligible("b"));
    assert!(model.marked.contains("a"));
    model.apply(JunkEvent::Invalidated {
        revision: 1,
        key: "b".into(),
    });
    assert!(
        model.eligible("b"),
        "stale invalidation cannot overwrite a newer row"
    );
}

#[test]
fn cached_preview_stays_historical_and_preserves_selection_when_current_replaces_it() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    model.apply(JunkEvent::Started {
        revision: 1,
        keys: None,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: false,
        historical: true,
        row: row("a", "/a"),
    });
    model.reorder();
    model.marked.insert("a".into());
    assert!(model.rows["a"].historical);
    assert!(!model.eligible("a"));
    model.apply(JunkEvent::Completed {
        revision: 1,
        outcome: JunkOutcome::Complete,
        replaced: true,
    });
    // A complete terminal cannot promote a cached row that never got a fresh observation.
    assert!(!model.eligible("a"));
    model.apply(JunkEvent::Started {
        revision: 2,
        keys: None,
    });
    model.apply(JunkEvent::Candidate {
        revision: 2,
        current: true,
        historical: false,
        row: row("a", "/a"),
    });
    model.apply(JunkEvent::Completed {
        revision: 2,
        outcome: JunkOutcome::Complete,
        replaced: true,
    });
    model.reorder();
    assert!(model.eligible("a"));
    assert!(model.marked.contains("a"));
    assert_eq!(model.order[model.cursor], "a");
}

#[test]
fn size_sort_keeps_unknown_last_and_path_sort_preserves_focus() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    let large: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "large",
        path: "/z",
        bytes: EvidenceValue::Known {
            value: DecimalU128::new(32),
        },
        complete: true,
        report_only: false,
        cost: 256,
    });
    let unknown: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "unknown",
        path: "/0",
        bytes: EvidenceValue::Unknown {
            reason: ReasonCode::ResourceLimit,
        },
        complete: false,
        report_only: false,
        cost: 256,
    });
    let zero: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "zero",
        path: "/zzz-zero",
        bytes: EvidenceValue::Known {
            value: DecimalU128::new(0),
        },
        complete: true,
        report_only: false,
        cost: 256,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row: large,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row: unknown,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row: zero,
    });
    model.reorder();
    assert_eq!(model.order, ["large", "a", "b", "zero", "unknown"]);
    model = model.with_sort(ScanSort::Path);
    model.reorder();
    assert_eq!(model.order, ["unknown", "a", "b", "large", "zero"]);
    assert_eq!(model.order[model.cursor], "large");
}

#[test]
fn selection_and_cursor_survive_reordering_and_incomplete_replacement() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    model.reorder();
    model.marked.insert("a".into());
    model.apply(JunkEvent::Started {
        revision: 2,
        keys: Some(vec!["a".into()]),
    });
    assert!(model.rows["a"].historical);
    assert!(!model.rows["b"].historical);
    model.apply(JunkEvent::Candidate {
        revision: 2,
        current: true,
        historical: false,
        row: row("a", "/z"),
    });
    model.reorder();
    assert_eq!(model.order[model.cursor], "a");
    assert!(model.marked.contains("a"));
    model.apply(JunkEvent::Completed {
        revision: 2,
        outcome: JunkOutcome::Partial,
        replaced: false,
    });
    assert!(model.rows["a"].historical);
    assert!(!model.eligible("a"));
    assert!(model.eligible("b"));
    model.apply(JunkEvent::Removed {
        revision: 1,
        key: "a".into(),
    });
    assert!(model.rows.contains_key("a")); // older revisions cannot overwrite the view
    model.apply(JunkEvent::Started {
        revision: 3,
        keys: Some(vec!["a".into()]),
    });
    model.apply(JunkEvent::Removed {
        revision: 3,
        key: "a".into(),
    });
    assert!(!model.marked.contains("a"));
    assert!(model.rows.contains_key("b"));
}

struct Events(VecDeque<KeyCode>);
impl BrowserEventSource for Events {
    fn poll_event(&mut self, _: Duration) -> io::Result<Option<Event>> {
        Ok(Some(Event::Key(KeyEvent::new(
            self.0.pop_front().expect("script exhausted"),
            KeyModifiers::NONE,
        ))))
    }
}
#[derive(Default)]
struct Provider {
    events: VecDeque<JunkEvent>,
    refreshed: Vec<Vec<String>>,
    trashed: Vec<Vec<String>>,
    cancelled: bool,
    previews: Vec<Vec<String>>,
    confirmations: Vec<String>,
    dismissed: Vec<u64>,
    keepers: Vec<String>,
    inspected: Vec<String>,
    detail_text: Option<String>,
}
impl JunkProvider for Provider {
    fn inspect_text(&self, _: &str) -> Option<String> {
        self.detail_text.clone()
    }
    fn inspect(&mut self, key: &str) -> Result<JunkInspection, String> {
        self.inspected.push(key.into());
        Err("controlled native directory unavailable".into())
    }
    fn toggle_keeper(&mut self, key: &str) -> Result<(), String> {
        self.keepers.push(key.into());
        self.events.push_back(JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: Arc::new(FixtureRow {
                key: "a",
                path: "/a",
                bytes: EvidenceValue::Known { value: 8.into() },
                complete: true,
                report_only: true,
                cost: 256,
            }),
        });
        Ok(())
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        self.events.pop_front()
    }
    fn cancel(&mut self) {
        self.cancelled = true;
    }
    fn refresh(&mut self, keys: &[String]) -> Result<(), String> {
        self.refreshed.push(keys.to_vec());
        self.events.push_back(JunkEvent::Started {
            revision: 2,
            keys: Some(keys.to_vec()),
        });
        self.events.push_back(JunkEvent::Candidate {
            revision: 2,
            current: true,
            historical: false,
            row: row("a", "/a"),
        });
        self.events.push_back(JunkEvent::Candidate {
            revision: 2,
            current: true,
            historical: false,
            row: row("b", "/b"),
        });
        self.events.push_back(JunkEvent::Completed {
            revision: 2,
            outcome: JunkOutcome::Complete,
            replaced: true,
        });
        Ok(())
    }
    fn prioritize(&mut self, _: &str) {}
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        self.trashed.push(keys.to_vec());
        for key in keys {
            self.events.push_back(JunkEvent::TrashResult {
                key: key.clone(),
                error: None,
            });
        }
        Ok(())
    }
    fn close(&mut self) {}
    fn preview_quarantine(&mut self, keys: &[String]) -> Result<u64, String> {
        self.previews.push(keys.to_vec());
        let operation = self.previews.len() as u64;
        self.events.push_back(JunkEvent::QuarantinePreview {
            operation,
            digest: "0".repeat(64),
            plan: "selected /a\nlogical=8 allocated=4096\nRecovery directory: /volume/recovery"
                .into(),
        });
        Ok(operation)
    }
    fn confirm_quarantine(&mut self, operation: u64, answer: &str) -> Result<(), String> {
        self.confirmations.push(answer.into());
        self.events.push_back(JunkEvent::QuarantineFinished {
            operation,
            moved: self.previews.last().unwrap().clone(),
            failed: false,
            message: "Confirmed transitions.\nRecovery directory: /volume/recovery".into(),
        });
        Ok(())
    }
    fn dismiss_quarantine(&mut self, operation: u64) {
        self.dismissed.push(operation);
    }
}

#[test]
fn enter_inspects_only_the_cursor_and_keeps_report_only_guards() {
    let mut provider = Provider {
        events: initial(),
        ..Default::default()
    };
    let mut input = Events(VecDeque::from([KeyCode::Enter, KeyCode::Char('q')]));
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut input,
            &mut provider,
            &NeverTerminate
        )
        .unwrap(),
        0
    );
    assert_eq!(provider.inspected, ["a"]);
    assert!(provider.trashed.is_empty());
    assert!(model.diagnostic.contains("native directory unavailable"));
    model.rows.get_mut("a").unwrap().historical = true;
    let mut input = Events(VecDeque::from([KeyCode::Enter, KeyCode::Char('q')]));
    run_junk_loop(
        &mut terminal,
        &mut model,
        &mut input,
        &mut provider,
        &NeverTerminate,
    )
    .unwrap();
    assert_eq!(provider.inspected.len(), 1);
    assert!(model.diagnostic.contains("Refresh this candidate"));
}

struct TimedEvents {
    script: VecDeque<Option<KeyCode>>,
    waits: Vec<Duration>,
}
impl BrowserEventSource for TimedEvents {
    fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        self.waits.push(timeout);
        Ok(self
            .script
            .pop_front()
            .expect("script exhausted")
            .map(|code| Event::Key(KeyEvent::new(code, KeyModifiers::NONE))))
    }
}

#[test]
fn active_batches_do_not_wait_for_input_and_preserve_result_selection() {
    let mut queued = VecDeque::from([
        JunkEvent::Started {
            revision: 1,
            keys: None,
        },
        JunkEvent::Candidate {
            revision: 1,
            current: false,
            historical: false,
            row: row("a", "/a"),
        },
    ]);
    // The first 128-event batch contains the base row but not its current replacement. This
    // fixture pins the public per-tick limit independently of producer timing or native I/O.
    for count in 0..126 {
        queued.push_back(JunkEvent::Progress {
            revision: 1,
            count,
            path: "/a".into(),
        });
    }
    queued.extend([
        JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: row("a", "/a"),
        },
        JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: row("b", "/b"),
        },
        JunkEvent::Completed {
            revision: 1,
            outcome: JunkOutcome::Complete,
            replaced: true,
        },
    ]);
    let mut provider = Provider {
        events: queued,
        ..Default::default()
    };
    let mut input = TimedEvents {
        // Select the base before the next drain, then let the full terminal event arrive.
        script: VecDeque::from([Some(KeyCode::Char(' ')), None, Some(KeyCode::Char('q'))]),
        waits: Vec::new(),
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut input,
            &mut provider,
            &NeverTerminate,
        )
        .unwrap(),
        0
    );
    assert_eq!(
        input.waits,
        [Duration::ZERO, Duration::ZERO, Duration::from_millis(50)]
    );
    assert!(input.script.is_empty() && provider.events.is_empty());
    assert_eq!(model.marked, BTreeSet::from(["a".into()]));
    assert_eq!(model.rows.len(), 2);
    assert!(model.rows["a"].current && model.rows["b"].current);
    assert_eq!(model.outcome, Some(JunkOutcome::Complete));
    assert!(!model.busy && !provider.cancelled && provider.trashed.is_empty());
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("Complete") && screen.contains("Current"));
}

#[test]
fn short_active_batch_returns_to_idle_input_wait_when_provider_is_empty() {
    let mut provider = Provider {
        events: initial(),
        ..Default::default()
    };
    let mut input = TimedEvents {
        script: VecDeque::from([None, None, Some(KeyCode::Char('q'))]),
        waits: Vec::new(),
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut input,
            &mut provider,
            &NeverTerminate,
        )
        .unwrap(),
        0
    );
    assert_eq!(
        input.waits,
        [
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(50),
        ]
    );
    assert_eq!(model.outcome, Some(JunkOutcome::Complete));
    assert!(input.script.is_empty() && provider.events.is_empty());
}

#[test]
fn initially_empty_view_keeps_idle_wait_and_can_exit_before_completion() {
    let mut provider = Provider::default();
    let mut input = TimedEvents {
        script: VecDeque::from([None, Some(KeyCode::Char('q'))]),
        waits: Vec::new(),
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut input,
            &mut provider,
            &NeverTerminate,
        )
        .unwrap(),
        4
    );
    assert_eq!(input.waits, [Duration::from_millis(50); 2]);
    assert!(model.busy && input.script.is_empty());
}

#[test]
fn duplicate_keeper_key_updates_the_row_and_prevents_its_trash_selection() {
    let mut provider = Provider {
        events: initial(),
        ..Default::default()
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes)
        .with_presentation(ResultPresentation::Duplicates);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    let keys = VecDeque::from([
        KeyCode::Char('p'),
        KeyCode::Char(' '),
        KeyCode::Char('d'),
        KeyCode::Char('q'),
    ]);
    let exit = run_junk_loop(
        &mut terminal,
        &mut model,
        &mut Events(keys),
        &mut provider,
        &NeverTerminate,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(provider.keepers, ["a"]);
    assert!(!model.eligible("a"));
    assert!(provider.trashed.is_empty());
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("Duplicate content"));
}

#[test]
fn file_views_require_complete_scope_and_preserve_group_adjacency() {
    struct GroupRow {
        row: Arc<dyn JunkRow>,
        group: &'static str,
    }
    impl JunkRow for GroupRow {
        fn key(&self) -> &str {
            self.row.key()
        }
        fn path(&self) -> &str {
            self.row.path()
        }
        fn rule(&self) -> &str {
            self.group
        }
        fn evidence(&self) -> &str {
            self.row.evidence()
        }
        fn context(&self) -> String {
            self.row.context()
        }
        fn logical_bytes(&self) -> &ByteValue {
            self.row.logical_bytes()
        }
        fn complete(&self) -> bool {
            true
        }
        fn retained_bytes(&self) -> usize {
            512
        }
    }
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes)
        .with_presentation(ResultPresentation::Duplicates);
    let entries = [
        ("a", "/a", "digest-1"),
        ("b", "/b", "digest-2"),
        ("z", "/z", "digest-1"),
    ];
    for (revision, outcome) in [(1, JunkOutcome::Partial), (2, JunkOutcome::Complete)] {
        model.apply(JunkEvent::Started {
            revision,
            keys: None,
        });
        for (key, path, group) in entries {
            model.apply(JunkEvent::Candidate {
                revision,
                current: true,
                historical: false,
                row: Arc::new(GroupRow {
                    row: row(key, path),
                    group,
                }),
            });
        }
        model.apply(JunkEvent::Completed {
            revision,
            outcome,
            replaced: outcome == JunkOutcome::Complete,
        });
        model.reorder();
        assert_eq!(model.order, ["a", "z", "b"]);
        assert_eq!(model.eligible("a"), outcome == JunkOutcome::Complete);
    }
}

#[test]
fn long_file_paths_keep_distinct_filenames_visible_with_safe_cell_width() {
    let first = "/a/very/long/shared/root/中文/duplicate-one";
    let second = "/a/very/long/shared/root/中文/duplicate-two";
    for path in [first, second] {
        let tail = crate::live::tail_with_ellipsis(path, 20);
        assert!(tail.starts_with('…'));
        assert!(tail.ends_with(path.rsplit('/').next().unwrap()));
        assert_eq!(unicode_width::UnicodeWidthStr::width(tail.as_str()), 20);
    }
    assert_eq!(crate::live::tail_with_ellipsis(first, 0), "");
    assert_eq!(crate::live::tail_with_ellipsis(first, 1), "…");
    assert_eq!(crate::live::tail_with_ellipsis("中文", 3), "…文");
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes)
        .with_presentation(ResultPresentation::LargeFiles);
    model.apply(JunkEvent::Started {
        revision: 1,
        keys: None,
    });
    for (key, path) in [("one", first), ("two", second)] {
        model.apply(JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: row(key, path),
        });
    }
    model.reorder();
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(screen.contains("duplicate-one") && screen.contains("duplicate-two"));
}

#[test]
fn quarantine_loop_requires_full_typed_digest_and_shows_recovery_result() {
    let mut provider = Provider {
        events: initial(),
        ..Default::default()
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    let mut keys = VecDeque::from([KeyCode::Char('x'), KeyCode::Enter]);
    keys.extend(
        format!("clean {}", "0".repeat(64))
            .chars()
            .map(KeyCode::Char),
    );
    keys.extend([KeyCode::Enter, KeyCode::Esc, KeyCode::Char('q')]);
    let exit = run_junk_loop(
        &mut terminal,
        &mut model,
        &mut Events(keys),
        &mut provider,
        &NeverTerminate,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(provider.previews, [vec!["a"]]);
    assert_eq!(
        provider.confirmations,
        [format!("clean {}", "0".repeat(64))]
    );
    assert!(!model.rows.contains_key("a"));
    assert!(model.rows.contains_key("b"));
    assert!(provider.trashed.is_empty());
}

#[test]
fn prefix_confirmation_and_dismissal_do_not_submit_or_remove_rows() {
    let mut provider = Provider {
        events: initial(),
        ..Default::default()
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(100, 22)).unwrap();
    let mut keys = VecDeque::from([KeyCode::Char('x')]);
    keys.extend(
        format!("clean {}", "0".repeat(63))
            .chars()
            .map(KeyCode::Char),
    );
    keys.extend([KeyCode::Enter, KeyCode::Esc, KeyCode::Char('q')]);
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut Events(keys),
            &mut provider,
            &NeverTerminate
        )
        .unwrap(),
        0
    );
    assert!(provider.confirmations.is_empty());
    assert_eq!(provider.dismissed, [1]);
    assert_eq!(model.rows.len(), 2);
}

#[test]
fn quarantine_rejects_stale_oversized_and_uppercase_digest_events() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    model.quarantine = Some(QuarantineView::new(2, vec!["a".into()]));
    model.apply(JunkEvent::QuarantinePreview {
        operation: 1,
        digest: "0".repeat(64),
        plan: "stale".into(),
    });
    let mut provider = Provider::default();
    model.quarantine_key(
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &mut provider,
    );
    assert!(provider.confirmations.is_empty());
    model.apply(JunkEvent::QuarantineFinished {
        operation: 1,
        moved: vec!["a".into()],
        message: "stale".into(),
        failed: false,
    });
    assert!(model.rows.contains_key("a"));
    for (digest, plan) in [
        ("a".repeat(64), "x".repeat(1024 * 1024 + 1)),
        ("A".repeat(64), "small".into()),
    ] {
        model.quarantine = Some(QuarantineView::new(2, vec!["a".into()]));
        model.apply(JunkEvent::QuarantinePreview {
            operation: 2,
            digest,
            plan,
        });
        model.quarantine_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut provider,
        );
        assert!(provider.confirmations.is_empty());
    }
}

#[test]
fn cancelling_execution_keeps_view_until_confirmed_and_uncertain_outcomes_arrive() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    model.quarantine = Some(QuarantineView::new(1, vec!["a".into(), "b".into()]));
    model.apply(JunkEvent::QuarantinePreview {
        operation: 1,
        digest: "0".repeat(64),
        plan: "recovery=/volume/private".into(),
    });
    let mut provider = Provider {
        previews: vec![vec!["a".into(), "b".into()]],
        ..Default::default()
    };
    for character in format!("clean {}", "0".repeat(64)).chars() {
        model.quarantine_key(
            KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
            &mut provider,
        );
    }
    model.quarantine_key(
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        &mut provider,
    );
    model.quarantine_key(
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        &mut provider,
    );
    assert!(model.quarantine.is_some());
    assert_eq!(provider.dismissed, [1]);
    model.apply(JunkEvent::QuarantineFinished {
        operation: 1,
        moved: vec!["a".into()],
        message: "Recovery directory: /volume/private\npartial source retained".into(),
        failed: true,
    });
    assert!(!model.rows.contains_key("a"));
    assert!(model.rows["b"].historical);
    assert_eq!(model.outcome, Some(JunkOutcome::Partial));
    assert!(!model.eligible("b"));
    let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(screen.contains("/volume/private"));
    assert!(screen.contains("partial source retained"));
}

#[test]
fn quarantine_typing_is_bounded_and_does_not_trigger_scan_or_trash_keys() {
    let mut model = JunkModel::new(Locale::ZhCn, HumanSizeUnit::Bytes);
    model.quarantine = Some(QuarantineView::new(1, vec!["a".into()]));
    model.apply(JunkEvent::QuarantinePreview {
        operation: 1,
        digest: "0".repeat(64),
        plan: "safe\u{1b}[31m native evidence".into(),
    });
    let mut provider = Provider::default();
    for _ in 0..200 {
        model.quarantine_key(
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            &mut provider,
        );
    }
    model.quarantine_key(
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        &mut provider,
    );
    assert!(provider.refreshed.is_empty());
    assert!(provider.trashed.is_empty());
    assert!(provider.confirmations.is_empty());
    let mut terminal = Terminal::new(TestBackend::new(90, 22)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(!screen.contains('\u{1b}'));
}

#[test]
fn loop_selects_refreshes_and_consumes_trash_without_leaving_the_view() {
    let mut provider = Provider {
        events: initial(),
        ..Provider::default()
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    let mut terminal = Terminal::new(TestBackend::new(120, 22)).unwrap();
    let mut events = Events(VecDeque::from([
        KeyCode::Char(' '),
        KeyCode::Down,
        KeyCode::Char(' '),
        KeyCode::Char('r'),
        KeyCode::Char('d'),
        KeyCode::Char('q'),
    ]));
    let exit = run_junk_loop(
        &mut terminal,
        &mut model,
        &mut events,
        &mut provider,
        &NeverTerminate,
    )
    .unwrap();
    assert_eq!(exit, 0);
    assert_eq!(provider.refreshed, [vec!["a", "b"]]);
    assert_eq!(provider.trashed, [vec!["a", "b"]]);
    assert!(model.rows.is_empty());
    assert!(model.marked.is_empty());
}

#[test]
fn empty_view_and_uppercase_refresh_request_all_roots() {
    for code in [KeyCode::Char('r'), KeyCode::Char('R')] {
        let mut provider = Provider {
            events: VecDeque::from([
                JunkEvent::Started {
                    revision: 1,
                    keys: None,
                },
                JunkEvent::Completed {
                    revision: 1,
                    outcome: JunkOutcome::Complete,
                    replaced: true,
                },
            ]),
            ..Provider::default()
        };
        let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
        let mut terminal = Terminal::new(TestBackend::new(120, 22)).unwrap();
        let mut events = Events(VecDeque::from([code, KeyCode::Char('q')]));
        assert_eq!(
            run_junk_loop(
                &mut terminal,
                &mut model,
                &mut events,
                &mut provider,
                &NeverTerminate
            )
            .unwrap(),
            0
        );
        assert_eq!(provider.refreshed, [Vec::<String>::new()]);
    }
}

#[test]
fn budget_loss_and_partial_rows_never_reach_trash() {
    let huge: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "oversize",
        path: "/oversize",
        bytes: EvidenceValue::Unknown {
            reason: ReasonCode::ResourceLimit,
        },
        complete: false,
        report_only: false,
        cost: MAX_BYTES,
    });
    let mut provider = Provider {
        events: initial(),
        ..Provider::default()
    };
    provider.events.insert(
        3,
        JunkEvent::Candidate {
            revision: 1,
            current: true,
            historical: false,
            row: huge,
        },
    );
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Auto);
    let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
    let mut events = Events(VecDeque::from([KeyCode::Char('d'), KeyCode::Char('q')]));
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut events,
            &mut provider,
            &NeverTerminate
        )
        .unwrap(),
        4
    );
    assert!(provider.trashed.is_empty());
    assert!(model.rows.values().all(|row| row.historical));
    assert_eq!(model.rows.len(), 2);
}

#[test]
fn renderer_preserves_lower_bounds_unknowns_and_locale() {
    let mut model = JunkModel::new(Locale::ZhCn, HumanSizeUnit::Bytes);
    model.apply(JunkEvent::Started {
        revision: 1,
        keys: None,
    });
    let row: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "partial",
        path: "/partial",
        bytes: EvidenceValue::LowerBound {
            value: DecimalU128::new(17),
            reason: ReasonCode::ResourceLimit,
        },
        complete: false,
        report_only: false,
        cost: 256,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row,
    });
    model.apply(JunkEvent::Completed {
        revision: 1,
        outcome: JunkOutcome::Partial,
        replaced: false,
    });
    model.reorder();
    let mut terminal = Terminal::new(TestBackend::new(140, 22)).unwrap();
    terminal.draw(|frame| render_junk(frame, &model)).unwrap();
    // Wide glyphs occupy a symbol cell and a padding cell. Decode terminal columns rather
    // than concatenating padding into the text (which spuriously separates Chinese glyphs).
    use unicode_width::UnicodeWidthStr;
    let buffer = terminal.backend().buffer();
    let mut rendered = String::new();
    for y in 0..buffer.area.height {
        let mut x = 0;
        while x < buffer.area.width {
            let symbol = buffer[(x, y)].symbol();
            rendered.push_str(symbol);
            x += u16::try_from(symbol.width().max(1)).unwrap();
        }
        rendered.push('\n');
    }
    assert!(rendered.contains("逻辑大小"), "{rendered:?}");
    assert!(rendered.contains("未报告"));
    assert!(rendered.contains(">= 17"));
    assert!(rendered.contains("历史/不完整"));
    assert!(!model.eligible("partial"));
    assert!(!rendered.contains("可回收"));
}

#[test]
fn failed_trash_retains_historical_row_and_requires_refresh() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Auto);
    for event in initial() {
        model.apply(event);
    }
    model.trash_pending.insert("a".into());
    model.apply(JunkEvent::TrashResult {
        key: "a".into(),
        error: Some("identity changed".into()),
    });
    assert!(model.rows.contains_key("a"));
    assert!(model.rows["a"].historical);
    assert!(!model.eligible("a"));
    assert!(model.trash_pending.is_empty());
    assert_eq!(model.outcome, Some(JunkOutcome::Partial));
}

#[test]
fn complete_report_only_project_rows_remain_visible_without_offering_trash() {
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    for event in initial() {
        model.apply(event);
    }
    let report: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "dart",
        path: "/project/.dart_tool",
        bytes: EvidenceValue::Known {
            value: DecimalU128::new(8),
        },
        complete: true,
        report_only: true,
        cost: 256,
    });
    model.apply(JunkEvent::Candidate {
        revision: 1,
        current: true,
        historical: false,
        row: report,
    });
    assert!(model.rows["dart"].row.complete());
    assert!(!model.eligible("dart"));
    assert_eq!(
        model.trash_unavailable_message(&["dart".into()]),
        "Selected evidence is report-only and does not meet Trash requirements"
    );
    assert!(model.eligible("a"));
    model.apply(JunkEvent::Phase {
        revision: 1,
        phase: "formats",
    });
    assert_eq!(model.phase_label(), "Checking project file formats");
}

#[test]
fn managed_details_scroll_and_return_without_a_cleanup_request() {
    let mut provider = Provider {
        events: initial(),
        detail_text: Some(
            "/projects/one total=4096\n/projects/two total=8192\nSingle link can be a clone import"
                .into(),
        ),
        ..Default::default()
    };
    let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
    model.presentation = ResultPresentation::ManagedCaches;
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    let mut input = Events(VecDeque::from([
        KeyCode::Enter,
        KeyCode::PageDown,
        KeyCode::Esc,
        KeyCode::Char('q'),
    ]));
    assert_eq!(
        run_junk_loop(
            &mut terminal,
            &mut model,
            &mut input,
            &mut provider,
            &NeverTerminate
        )
        .unwrap(),
        0
    );
    assert!(model.inspection_text.is_none());
    assert!(provider.trashed.is_empty());
    assert!(provider.inspected.is_empty());
    model.inspection_text = Some((provider.detail_text.unwrap(), 0));
    terminal.draw(|f| render_junk(f, &model)).unwrap();
    let screen: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(screen.contains("/projects/one total=4096"));
    assert!(screen.contains("Single link can be a clone import"));
    let line = |y: usize| -> String {
        terminal.backend().buffer().content[y * 100..(y + 1) * 100]
            .iter()
            .map(|c| c.symbol())
            .collect()
    };
    assert!(line(1).contains("/projects/one total=4096"));
    assert!(line(2).contains("/projects/two total=8192"));
    assert!(line(3).contains("Single link can be a clone import"));
}
