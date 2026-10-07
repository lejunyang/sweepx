//! Live junk presentation. Native scanning and mutation remain provider-owned worker operations.

use crate::{
    BrowserError, BrowserEventSource, CrosstermEventSource, TerminalGuard, TerminationFlag,
};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use sweepx_i18n::Locale;
use sweepx_model::{ByteValue, EvidenceValue, HumanSizeUnit, ScanSort};

const MAX_ROWS: usize = 16_384;
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_SELECTION: usize = 256;
/// Distinct analyses share list mechanics while preserving their user-visible meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResultPresentation {
    /// Rule-based junk candidates.
    #[default]
    Junk,
    /// Logical-size ranking; size does not establish disposability.
    LargeFiles,
    /// Complete content hashes; an explicit keeper is required before Trash.
    Duplicates,
}
mod quarantine;
use quarantine::QuarantineView;
mod inspection;
pub use inspection::JunkInspection;

/// Shared presentation data; no display field can authorize filesystem operations.
pub trait JunkRow: Send + Sync {
    /// Opaque stable presentation key, bounded to 128 bytes.
    fn key(&self) -> &str;
    /// Display-only path.
    fn path(&self) -> &str;
    /// Stable rule ID, not a translated name.
    fn rule(&self) -> &str;
    /// Classification explanation from the shared rule service.
    fn evidence(&self) -> &str;
    /// Current risk, classification, activity and blockers; stable machine values remain intact.
    fn context(&self) -> String;
    /// Logical bytes, preserving known/lower-bound/unknown evidence.
    fn logical_bytes(&self) -> &ByteValue;
    /// Whether native source and aggregate coverage are complete; never mutation authority.
    fn complete(&self) -> bool;
    /// Whether current report restrictions permit offering Trash. This is only a presentation
    /// filter: the provider and native worker must independently enforce execution guards.
    fn report_allows_trash(&self) -> bool {
        true
    }
    /// Conservative retained-data estimate, including shared data; not RSS.
    fn retained_bytes(&self) -> usize;
}

/// Terminal state of a scan, distinct from a progress update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkOutcome {
    Complete,
    Partial,
    Cancelled,
    Failed,
}

/// UI events converted from worker observations. Providers bound their queues and payloads.
pub enum JunkEvent {
    /// Mark the entire old view, or these expanded subtree keys, historical.
    Started {
        revision: u64,
        keys: Option<Vec<String>>,
    },
    /// Stable phase identifier, rendered locally.
    Phase { revision: u64, phase: &'static str },
    /// Coalesced traversal count and display-only path.
    Progress {
        revision: u64,
        count: u64,
        path: String,
    },
    /// Replace one row without changing the user's selection or cursor key.
    Candidate {
        revision: u64,
        current: bool,
        /// Cached preview; fresh observations clear this independently of interpretation state.
        historical: bool,
        row: Arc<dyn JunkRow>,
    },
    /// Confirmed disappearance after complete observation.
    Removed { revision: u64, key: String },
    /// Keep an existing row historical when local refresh cannot recompute ancestor accounting.
    /// Its provider may retain a native binding for a later independent refresh.
    Invalidated { revision: u64, key: String },
    /// Bounded diagnostic; never treated as an empty successful result.
    Error { revision: u64, message: String },
    /// Commit a scope or retain its rows as historical after incomplete work.
    Completed {
        revision: u64,
        outcome: JunkOutcome,
        replaced: bool,
    },
    /// Result from the separate Trash worker; success removes this selected row.
    TrashResult { key: String, error: Option<String> },
    /// Display-only plan from the worker retaining the native preview privately.
    QuarantinePreview {
        /// Invocation-local worker ID, separate from scan revisions and execution authority.
        operation: u64,
        /// Full lowercase canonical digest; never auto-filled into the confirmation input.
        digest: String,
        /// Complete display-only plan, at most 1 MiB; truncation must refuse confirmation.
        plan: String,
    },
    /// Reliable final observation; only confirmed transitions may remove rows.
    QuarantineFinished {
        /// ID of the worker that retained this preview and received its explicit confirmation.
        operation: u64,
        /// Selected stable keys whose source-to-recovery transitions were confirmed.
        moved: Vec<String>,
        /// Recovery location and failure reconciliation, retained for user review.
        message: String,
        /// Partial, cancelled, ambiguous or failed execution; unconfirmed rows remain historical.
        failed: bool,
    },
}

/// Nonblocking bridge to scanning and Trash workers. Implementations must not do native work here.
pub trait JunkProvider {
    /// Meaning of this list, independent of rendering and execution authority.
    fn presentation(&self) -> ResultPresentation {
        ResultPresentation::Junk
    }
    /// Poll at most one event without waiting.
    fn poll(&mut self) -> Option<JunkEvent>;
    /// Request cooperative cancellation.
    fn cancel(&mut self);
    /// Refresh selected stable keys; an empty selection requests the entire current scope.
    /// A system provider rediscovers its roots for full refresh.
    /// Stale/unknown selected bindings fail on the worker.
    fn refresh(&mut self, keys: &[String]) -> Result<(), String>;
    /// Prioritize the native directory behind a presentation key; affects ordering only.
    fn prioritize(&mut self, key: &str);
    /// Begin a bounded, explicitly selected Trash batch on a worker.
    fn trash(&mut self, keys: &[String]) -> Result<(), String>;
    /// Prepare an identity-bound directory inspection without filesystem work on this thread.
    /// The returned provider owns any scan-admission lease needed while the modal is open.
    fn inspect(&mut self, _key: &str) -> Result<JunkInspection, String> {
        Err("directory inspection is unavailable for this analysis".into())
    }
    /// Explicitly choose/clear the keeper for a duplicate group. No native work runs here.
    fn toggle_keeper(&mut self, _key: &str) -> Result<(), String> {
        Err("keeper selection is available only for duplicate groups".into())
    }
    /// Begin an independent quarantine preview; return an invocation-local operation ID.
    fn preview_quarantine(&mut self, _keys: &[String]) -> Result<u64, String> {
        Err("temporary-object quarantine is unavailable on this provider".into())
    }
    /// Send explicitly typed confirmation to the worker retaining that native preview.
    fn confirm_quarantine(&mut self, _operation: u64, _answer: &str) -> Result<(), String> {
        Err("no quarantine preview is pending".into())
    }
    /// Dismiss an unexecuted preview or cooperatively cancel an executing operation.
    fn dismiss_quarantine(&mut self, _operation: u64) {}
    /// Close without joining a possibly blocked OS worker on the UI thread.
    fn close(&mut self);
}

struct ViewRow {
    row: Arc<dyn JunkRow>,
    revision: u64,
    historical: bool,
    current: bool,
}

/// Bounded presentation state. Stable keys retain selection across revisions and reordered rows.
pub struct JunkModel {
    presentation: ResultPresentation,
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
    rows: BTreeMap<String, ViewRow>,
    order: Vec<String>,
    marked: BTreeSet<String>,
    affected: Option<BTreeSet<String>>,
    cursor: usize,
    bytes: usize,
    revision: u64,
    busy: bool,
    trash_pending: BTreeSet<String>,
    outcome: Option<JunkOutcome>,
    phase: &'static str,
    progress: Option<u64>,
    path: String,
    diagnostic: String,
    dirty: bool,
    rejected: bool,
    quarantine: Option<QuarantineView>,
    /// Latest modal's display-only choices; at most 32 bounded paths, never provider Trash keys.
    review_paths: Vec<String>,
}

impl JunkModel {
    /// Creates an empty live view; no scan, cache read or default selection is performed.
    pub fn new(locale: Locale, unit: HumanSizeUnit) -> Self {
        Self {
            presentation: ResultPresentation::Junk,
            locale,
            unit,
            sort: ScanSort::Size,
            rows: BTreeMap::new(),
            order: Vec::new(),
            marked: BTreeSet::new(),
            affected: None,
            cursor: 0,
            bytes: 0,
            revision: 0,
            busy: true,
            trash_pending: BTreeSet::new(),
            outcome: None,
            phase: "rules",
            progress: None,
            path: String::new(),
            diagnostic: String::new(),
            dirty: false,
            rejected: false,
            quarantine: None,
            review_paths: Vec::new(),
        }
    }

    /// Selects path order or descending logical-size order; unknown sizes remain distinct and last.
    pub fn with_sort(mut self, sort: ScanSort) -> Self {
        self.sort = sort;
        self.dirty = true;
        self
    }

    /// Selects the analysis vocabulary without changing safety or queue semantics.
    pub fn with_presentation(mut self, presentation: ResultPresentation) -> Self {
        self.presentation = presentation;
        self
    }

    fn text<'a>(&self, zh: &'a str, en: &'a str) -> &'a str {
        match self.locale {
            Locale::ZhCn => zh,
            Locale::EnUs => en,
        }
    }

    fn diagnostic(&mut self, mut message: String) {
        if message.len() > 2048 {
            let mut end = 2000;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
            message.push_str(" …");
        }
        self.diagnostic = message;
    }

    fn apply(&mut self, event: JunkEvent) {
        if self.apply_quarantine_event(&event) {
            return;
        }
        if let JunkEvent::TrashResult { key, error } = event {
            self.trash_pending.remove(&key);
            if let Some(error) = error {
                if let Some(row) = self.rows.get_mut(&key) {
                    row.historical = true;
                }
                self.outcome = Some(JunkOutcome::Partial);
                self.diagnostic(error);
            } else {
                self.remove(&key);
            }
            return;
        }
        let revision = match &event {
            JunkEvent::Started { revision, .. }
            | JunkEvent::Phase { revision, .. }
            | JunkEvent::Progress { revision, .. }
            | JunkEvent::Candidate { revision, .. }
            | JunkEvent::Removed { revision, .. }
            | JunkEvent::Invalidated { revision, .. }
            | JunkEvent::Error { revision, .. }
            | JunkEvent::Completed { revision, .. } => *revision,
            JunkEvent::TrashResult { .. } => unreachable!(),
            JunkEvent::QuarantinePreview { .. } | JunkEvent::QuarantineFinished { .. } => {
                unreachable!()
            }
        };
        if revision < self.revision {
            return;
        }
        if !matches!(event, JunkEvent::Started { .. }) && revision != self.revision {
            return;
        }
        match event {
            JunkEvent::Started { revision, keys } => {
                self.revision = revision;
                self.affected = keys.map(|keys| keys.into_iter().collect());
                for (key, row) in &mut self.rows {
                    if self.affected.as_ref().is_none_or(|keys| keys.contains(key)) {
                        row.historical = true;
                    }
                }
                self.busy = true;
                self.outcome = None;
                self.progress = None;
                self.rejected = false;
            }
            JunkEvent::Phase { phase, .. } => self.phase = phase,
            JunkEvent::Progress { count, path, .. } => {
                self.progress = Some(count);
                self.path = path;
            }
            JunkEvent::Candidate {
                current,
                historical,
                row,
                ..
            } => {
                let key = row.key();
                let cost = row.retained_bytes().saturating_add(512);
                let old = self
                    .rows
                    .get(key)
                    .map_or(0, |row| row.row.retained_bytes().saturating_add(512));
                let bytes = self.bytes.saturating_sub(old).saturating_add(cost);
                if key.len() > 128
                    || bytes > MAX_BYTES
                    || (!self.rows.contains_key(key) && self.rows.len() >= MAX_ROWS)
                {
                    self.rejected = true;
                    self.diagnostic(
                        self.text(
                            "展示预算耗尽；结果不完整",
                            "Presentation budget exceeded; results incomplete",
                        )
                        .into(),
                    );
                    return;
                }
                self.bytes = bytes;
                self.rows.insert(
                    key.to_owned(),
                    ViewRow {
                        row,
                        revision,
                        historical,
                        current,
                    },
                );
                self.dirty = true;
            }
            JunkEvent::Removed { key, .. } => self.remove(&key),
            JunkEvent::Invalidated { key, .. } => {
                if let Some(row) = self.rows.get_mut(&key) {
                    row.historical = true;
                }
            }
            JunkEvent::Error { message, .. } => self.diagnostic(message),
            JunkEvent::Completed {
                outcome, replaced, ..
            } => {
                self.busy = false;
                self.outcome = Some(if self.rejected {
                    JunkOutcome::Partial
                } else {
                    outcome
                });
                if !replaced || self.rejected {
                    for (key, row) in &mut self.rows {
                        if row.revision == revision
                            || self.affected.as_ref().is_none_or(|keys| keys.contains(key))
                        {
                            row.historical = true;
                        }
                    }
                }
            }
            JunkEvent::TrashResult { .. } => unreachable!(),
            JunkEvent::QuarantinePreview { .. } | JunkEvent::QuarantineFinished { .. } => {
                unreachable!()
            }
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(row) = self.rows.remove(key) {
            self.bytes = self
                .bytes
                .saturating_sub(row.row.retained_bytes().saturating_add(512));
        }
        self.marked.remove(key);
        self.dirty = true;
    }

    fn reorder(&mut self) {
        if !self.dirty {
            return;
        }
        let selected = self.order.get(self.cursor).cloned();
        self.order = self.rows.keys().cloned().collect();
        self.order.sort_by(|a, b| {
            let bytes = |row: &ViewRow| match row.row.logical_bytes() {
                EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => {
                    Some(value.0)
                }
                _ => None,
            };
            let size_order = match self.sort {
                ScanSort::Size => bytes(&self.rows[b]).cmp(&bytes(&self.rows[a])),
                ScanSort::Path => std::cmp::Ordering::Equal,
            };
            let group_order = if self.presentation == ResultPresentation::Duplicates {
                self.rows[a].row.rule().cmp(self.rows[b].row.rule())
            } else {
                std::cmp::Ordering::Equal
            };
            size_order.then(group_order).then_with(|| {
                self.rows[a]
                    .row
                    .path()
                    .cmp(self.rows[b].row.path())
                    .then(a.cmp(b))
            })
        });
        self.cursor = selected
            .and_then(|key| self.order.iter().position(|item| *item == key))
            .unwrap_or(self.cursor)
            .min(self.order.len().saturating_sub(1));
        self.dirty = false;
    }

    fn chosen(&self) -> Vec<String> {
        if self.marked.is_empty() {
            self.order.get(self.cursor).cloned().into_iter().collect()
        } else {
            self.marked.iter().cloned().collect()
        }
    }

    fn eligible(&self, key: &str) -> bool {
        if self.presentation != ResultPresentation::Junk
            && self.outcome != Some(JunkOutcome::Complete)
        {
            return false;
        }
        !self.busy
            && self.rows.get(key).is_some_and(|row| {
                !row.historical
                    && row.current
                    && row.row.complete()
                    && row.row.report_allows_trash()
            })
    }

    fn trash_unavailable_message(&self, keys: &[String]) -> &str {
        if keys.iter().any(|key| {
            self.rows
                .get(key)
                .is_some_and(|row| !row.row.report_allows_trash())
        }) {
            if self.presentation == ResultPresentation::Duplicates {
                return self.text(
                    "保留者不能回收，请先取消选中保留者",
                    "Keepers cannot be moved; unselect them before Trash",
                );
            }
            self.text(
                "所选项证据仅供报告，尚不满足回收条件",
                "Selected evidence is report-only and does not meet Trash requirements",
            )
        } else {
            self.text(
                "先完整刷新选中项，再移到回收站",
                "Complete a refresh of selected rows before moving to Trash",
            )
        }
    }

    fn phase_label(&self) -> &str {
        match self.phase {
            "rules" => self.text("加载规则", "Loading rules"),
            "cache" => self.text("读取与核验缓存", "Reading and validating cache"),
            "cache_write" => self.text("保存扫描事实", "Saving scan facts"),
            "discovery" => self.text("发现上下文", "Discovering context"),
            "traversal" => self.text("扫描", "Scanning"),
            "formats" => self.text("核验项目文件格式", "Checking project file formats"),
            "content" => self.text(
                "读取与核验内容（进度为已读字节）",
                "Reading and validating content (progress: delivered bytes)",
            ),
            "temporary_objects" => self.text(
                "核验临时对象与进程引用",
                "Checking temporary objects and process references",
            ),
            "git" => self.text("核验 Git", "Checking Git"),
            "replacement" => self.text("更新结果", "Replacing results"),
            _ => self.phase,
        }
    }

    fn status(&self) -> &str {
        if self.busy {
            return self.phase_label();
        }
        if !self.trash_pending.is_empty() {
            return self.text("移到回收站中", "Moving to Trash");
        }
        match self.outcome {
            Some(JunkOutcome::Complete) => self.text("完成", "Complete"),
            Some(JunkOutcome::Partial) => self.text("不完整", "Partial"),
            Some(JunkOutcome::Cancelled) => self.text("已取消", "Cancelled"),
            _ => self.text("失败", "Failed"),
        }
    }
}

/// Renders only bounded presentation data; logical size is never labeled reclaimable.
pub fn render_junk(frame: &mut Frame<'_>, model: &JunkModel) {
    if let Some(view) = &model.quarantine {
        quarantine::render(frame, model, view);
        return;
    }
    let [header, list, details, help] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(3),
        Constraint::Length(7),
        Constraint::Length(3),
    ])
    .areas(frame.area());
    let title = match model.presentation {
        ResultPresentation::Junk => model.text("垃圾候选", "Junk candidates"),
        ResultPresentation::LargeFiles => {
            model.text("大文件（大小不代表垃圾）", "Large files (size is not junk)")
        }
        ResultPresentation::Duplicates => model.text(
            "重复内容组（明确选择保留者）",
            "Duplicate content (choose a keeper)",
        ),
    };
    frame.render_widget(
        Paragraph::new(format!(
            "{title} · {} · {} {} · {} {} · {} {}\n{}",
            model.status(),
            model.text("候选", "candidates"),
            model.rows.len(),
            model.text("已选", "selected"),
            model.marked.len(),
            model.text("观察", "observed"),
            model
                .progress
                .map(|count| count.to_string())
                .unwrap_or_else(|| model.text("未报告", "not reported").into()),
            crate::live::sanitize_terminal_text(&model.path)
        ))
        .block(Block::default().borders(Borders::ALL)),
        header,
    );
    // Build only a viewport, rather than formatting every retained candidate on each UI tick.
    let visible = usize::from(list.height.saturating_sub(3)).clamp(1, crate::MAX_PAGE_ROWS);
    let start = model
        .cursor
        .saturating_sub(visible / 2)
        .min(model.order.len().saturating_sub(visible));
    let rows = model.order.iter().skip(start).take(visible).map(|key| {
        let row = &model.rows[key];
        let state = if model.trash_pending.contains(key) {
            model.text("回收中", "Moving")
        } else if row.historical {
            model.text("历史/不完整", "Historical/partial")
        } else if model.presentation == ResultPresentation::Duplicates
            && !row.row.report_allows_trash()
        {
            model.text("保留者", "Keeper")
        } else if model.presentation != ResultPresentation::Junk && !row.row.complete() {
            model.text("暂定", "Provisional")
        } else if row.current {
            model.text("当前", "Current")
        } else {
            model.text("解释中", "Interpreting")
        };
        Row::new(vec![
            Cell::from(if model.marked.contains(key) {
                "●"
            } else {
                " "
            }),
            Cell::from(if model.presentation == ResultPresentation::Junk {
                crate::live::sanitize_terminal_text(row.row.path())
            } else {
                // Keep a conservative width below the table's path allocation. Details still
                // show the full sanitized path; this label never changes native row authority.
                crate::live::tail_with_ellipsis(
                    &crate::live::sanitize_terminal_text(row.row.path()),
                    usize::from(list.width.saturating_sub(40) / 2),
                )
            }),
            Cell::from(crate::live::sanitize_terminal_text(row.row.rule())),
            Cell::from(crate::byte_value_label_with_unit(
                row.row.logical_bytes(),
                model.unit,
            )),
            Cell::from(state),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Percentage(50),
            Constraint::Percentage(23),
            Constraint::Length(14),
            Constraint::Length(18),
        ],
    )
    .header(Row::new([
        "",
        model.text("路径", "Path"),
        if model.presentation == ResultPresentation::Junk {
            model.text("规则", "Rule")
        } else {
            model.text("分析", "Analysis")
        },
        model.text("逻辑大小", "Logical size"),
        model.text("状态", "State"),
    ]))
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    let mut state = TableState::default()
        .with_selected((!model.order.is_empty()).then_some(model.cursor.saturating_sub(start)));
    frame.render_stateful_widget(table, list, &mut state);
    let evidence = model
        .order
        .get(model.cursor)
        .map_or("", |key| model.rows[key].row.evidence());
    let context = model
        .order
        .get(model.cursor)
        .map_or_else(String::new, |key| model.rows[key].row.context());
    let full_path = model
        .order
        .get(model.cursor)
        .map_or("", |key| model.rows[key].row.path());
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}\n{}\n{}",
            crate::live::sanitize_terminal_text(full_path),
            // Action results must stay visible when a verbose rule context wraps beyond the pane.
            model
                .diagnostic
                .lines()
                .map(crate::live::sanitize_terminal_text)
                .collect::<Vec<_>>()
                .join("\n"),
            crate::live::sanitize_terminal_text(evidence),
            crate::live::sanitize_terminal_text(&context)
        ))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL)),
        details,
    );
    let hint = if model.presentation == ResultPresentation::Duplicates {
        model.text("↑↓ 移动 · Space 选择 · p 保留/取消保留 · r/R 全量刷新 · c 取消 · d/Delete 回收所选副本 · q 退出", "↑↓ Move · Space Select · p Choose/clear keeper · r/R Refresh all · c Cancel · d/Delete Trash selected copies · q Quit")
    } else if model.presentation == ResultPresentation::LargeFiles {
        model.text("↑↓ 移动 · Space 选择 · a 全选(≤256) · u 清空 · r/R 全量刷新 · c 取消 · d/Delete 回收所选文件 · q 退出", "↑↓ Move · Space Select · a Select all (≤256) · u Clear · r/R Refresh all · c Cancel · d/Delete Trash selected files · q Quit")
    } else {
        model.text(
        "↑↓ 移动 · Enter 细分 · Space 选择 · a 全选(≤256) · u 清空 · r/R 刷新 · c 取消 · d/Delete 回收 · x 临时对象隔离 · q 退出",
        "↑↓ Move · Enter Breakdown · Space Select · a Select all (≤256) · u Clear · r/R Refresh · c Cancel · d/Delete Trash · x Quarantine temporary objects · q Quit",
    )
    };
    frame.render_widget(
        Paragraph::new(hint)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL)),
        help,
    );
}

/// Runs with injectable terminal/events for independent rendering and interaction tests.
pub fn run_junk_loop<B: Backend, E: BrowserEventSource, P: JunkProvider, T: TerminationFlag>(
    terminal: &mut Terminal<B>,
    model: &mut JunkModel,
    events: &mut E,
    provider: &mut P,
    termination: &T,
) -> Result<u8, BrowserError> {
    loop {
        if let Some(signal) = termination.termination_signal() {
            return Ok(128u8.saturating_add(signal));
        }
        // Bound work per tick so a fast producer cannot starve input or painting.
        let mut received_event = false;
        for _ in 0..128 {
            let Some(event) = provider.poll() else {
                break;
            };
            received_event = true;
            if matches!(event, JunkEvent::Started { .. })
                && let Some(view) = model.quarantine.take()
            {
                provider.dismiss_quarantine(view.operation);
            }
            model.apply(event);
        }
        if model.rejected && model.busy {
            provider.cancel();
        }
        model.reorder();
        terminal.draw(|frame| render_junk(frame, model))?;
        // A bounded producer can temporarily run out of queued events before this batch fills.
        // Give it another drain opportunity after any activity, while still checking keyboard
        // input each tick. The next empty batch restores the idle wait, avoiding a busy loop.
        let input_wait = if received_event {
            Duration::ZERO
        } else {
            Duration::from_millis(50)
        };
        let event = match events.poll_event(input_wait) {
            Ok(event) => event,
            Err(_) if termination.termination_signal().is_some() => continue,
            Err(error) => return Err(error.into()),
        };
        let Some(Event::Key(key)) = event else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(130);
        }
        if model.quarantine_key(key, provider) {
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                return Ok(match model.outcome {
                    Some(JunkOutcome::Complete)
                        if !model.busy && model.trash_pending.is_empty() =>
                    {
                        0
                    }
                    Some(JunkOutcome::Failed) => 8,
                    _ => 4,
                });
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(130),
            KeyCode::Char('c') => provider.cancel(),
            KeyCode::Up | KeyCode::Char('k') => model.cursor = model.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                model.cursor = (model.cursor + 1).min(model.order.len().saturating_sub(1))
            }
            KeyCode::PageUp => model.cursor = model.cursor.saturating_sub(10),
            KeyCode::PageDown => {
                model.cursor = (model.cursor + 10).min(model.order.len().saturating_sub(1))
            }
            KeyCode::Char(' ') => {
                if let Some(key) = model.order.get(model.cursor)
                    && !model.marked.remove(key)
                    && model.marked.len() < MAX_SELECTION
                {
                    model.marked.insert(key.clone());
                }
            }
            KeyCode::Char('a') => {
                if model.order.len() <= MAX_SELECTION {
                    model.marked = model.order.iter().cloned().collect();
                } else {
                    model.diagnostic(
                        model
                            .text("每次最多选择 256 项", "Select at most 256 items per batch")
                            .into(),
                    );
                }
            }
            KeyCode::Char('u') => model.marked.clear(),
            KeyCode::Enter
                if model.presentation == ResultPresentation::Junk
                    && !model.busy
                    && model.trash_pending.is_empty() =>
            {
                if let Some(key) = model.order.get(model.cursor).cloned() {
                    let row = &model.rows[&key];
                    if row.historical || !row.current {
                        model.diagnostic(
                            model
                                .text(
                                    "先刷新当前候选再查看细分",
                                    "Refresh this candidate before opening its breakdown",
                                )
                                .into(),
                        );
                        continue;
                    }
                    match provider.inspect(&key) {
                        Ok(inspection) => {
                            let result = inspection::run(
                                terminal,
                                events,
                                termination,
                                model.locale,
                                model.unit,
                                model.sort,
                                inspection,
                            )?;
                            if let crate::BrowserExit::Terminated { signal } = result.exit {
                                return Ok(signal.map_or(130, |signal| 128 + signal));
                            }
                            model.review_paths = result.paths;
                            if !model.review_paths.is_empty() {
                                model.diagnostic(format!(
                                    "{}\n{}",
                                    model.text(
                                        "待核验清单（未授权删除）",
                                        "Review list (deletion not authorized)"
                                    ),
                                    model.review_paths.join("\n")
                                ));
                            }
                        }
                        Err(error) => model.diagnostic(error),
                    }
                }
            }
            KeyCode::Char('p')
                if model.presentation == ResultPresentation::Duplicates
                    && !model.busy
                    && model.trash_pending.is_empty() =>
            {
                if let Some(key) = model.order.get(model.cursor)
                    && let Err(error) = provider.toggle_keeper(key)
                {
                    model.diagnostic(error);
                }
            }
            KeyCode::Char('r' | 'R') if !model.busy && model.trash_pending.is_empty() => {
                let keys = if key.code == KeyCode::Char('R') {
                    Vec::new()
                } else {
                    model.chosen()
                };
                match provider.refresh(&keys) {
                    Ok(()) => model.busy = true,
                    Err(error) => model.diagnostic(error),
                }
            }
            KeyCode::Char('d') | KeyCode::Delete
                if !model.busy && model.trash_pending.is_empty() =>
            {
                let keys = model.chosen();
                if keys.is_empty() {
                    continue;
                }
                if keys.iter().all(|key| model.eligible(key)) {
                    match provider.trash(&keys) {
                        Ok(()) => model.trash_pending = keys.into_iter().collect(),
                        Err(error) => model.diagnostic(error),
                    }
                } else {
                    model.diagnostic(model.trash_unavailable_message(&keys).into());
                }
            }
            KeyCode::Char('x') if !model.busy && model.trash_pending.is_empty() => {
                let keys = model.chosen();
                if !keys.is_empty() && keys.iter().all(|key| model.eligible(key)) {
                    match provider.preview_quarantine(&keys) {
                        Ok(operation) => {
                            model.quarantine = Some(QuarantineView::new(operation, keys))
                        }
                        Err(error) => model.diagnostic(error),
                    }
                } else {
                    model.diagnostic(
                        model
                            .text(
                                "先完整刷新所选临时对象",
                                "Complete a refresh of selected temporary objects first",
                            )
                            .into(),
                    );
                }
            }
            _ => {}
        }
        if let Some(key) = model.order.get(model.cursor) {
            provider.prioritize(key);
        }
    }
}

/// Runs the interactive view and closes workers after restoring the terminal, including on errors.
pub fn run_junk_browser<P: JunkProvider>(
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
    mut provider: P,
) -> Result<u8, BrowserError> {
    let result = (|| {
        #[cfg(unix)]
        let termination = crate::live::UnixTerminationFlag::install()?;
        #[cfg(not(unix))]
        let termination = crate::NeverTerminate;
        let mut guard = TerminalGuard::enter()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        terminal.clear()?;
        let mut model = JunkModel::new(locale, unit)
            .with_sort(sort)
            .with_presentation(provider.presentation());
        let result = run_junk_loop(
            &mut terminal,
            &mut model,
            &mut CrosstermEventSource,
            &mut provider,
            &termination,
        );
        drop(terminal);
        guard.restore();
        if !model.review_paths.is_empty() {
            println!(
                "{}",
                model.text(
                    "待核验清单（未授权删除；大小不代表可删除性）",
                    "Review list (deletion not authorized; size does not establish disposability)"
                )
            );
            for path in &model.review_paths {
                println!("{}", crate::live::sanitize_terminal_text(path));
            }
        }
        result
    })();
    provider.close();
    result
}

#[cfg(test)]
mod tests;
