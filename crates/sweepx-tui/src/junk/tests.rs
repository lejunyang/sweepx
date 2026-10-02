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
        "rust_target"
    }
    fn evidence(&self) -> &str {
        "controlled rebuildable output"
    }
    fn context(&self) -> String {
        "risk=R1 · classification=known_generated · confidence=medium".into()
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.bytes
    }
    fn complete(&self) -> bool {
        self.complete
    }
    fn retained_bytes(&self) -> usize {
        self.cost
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
        cost: 256,
    });
    let unknown: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "unknown",
        path: "/0",
        bytes: EvidenceValue::Unknown {
            reason: ReasonCode::ResourceLimit,
        },
        complete: false,
        cost: 256,
    });
    let zero: Arc<dyn JunkRow> = Arc::new(FixtureRow {
        key: "zero",
        path: "/zzz-zero",
        bytes: EvidenceValue::Known {
            value: DecimalU128::new(0),
        },
        complete: true,
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
}
impl JunkProvider for Provider {
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
