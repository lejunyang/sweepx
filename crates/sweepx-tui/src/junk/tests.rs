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
