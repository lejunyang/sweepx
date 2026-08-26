use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell as TableCell, Paragraph, Row, Table};
use ratatui::{Frame, Terminal};
use sweepx_i18n::Locale;
use sweepx_model::{DirectoryAggregate, ObjectType, ScannedEntry};
use sweepx_protocol::OutputStatus;
use thiserror::Error;

use crate::{byte_value_label, coverage_label, object_type_label, output_status_label};

pub const BROWSER_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// One row in the in-memory scan snapshot browser.
///
/// Aggregate evidence is attached to its matching directory row. Aggregates are
/// deliberately never represented as independent browser rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRow {
    entry: ScannedEntry,
    aggregate: Option<DirectoryAggregate>,
    root: bool,
    label: String,
}

impl BrowserRow {
    fn from_owned(entry: ScannedEntry, aggregate: Option<DirectoryAggregate>, root: bool) -> Self {
        let label = if root {
            sanitize_terminal_text(&entry.display_path)
        } else {
            sanitize_terminal_text(&display_basename(&entry.display_path))
        };
        Self {
            entry,
            aggregate,
            root,
            label,
        }
    }

    pub fn entry(&self) -> &ScannedEntry {
        &self.entry
    }

    pub fn aggregate(&self) -> Option<&DirectoryAggregate> {
        self.aggregate.as_ref()
    }

    pub fn display_path(&self) -> &str {
        &self.entry.display_path
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn object_type(&self) -> &ObjectType {
        &self.entry.object_type
    }

    pub const fn is_root(&self) -> bool {
        self.root
    }

    /// Only real directory entries are enterable. In particular, symlinks and
    /// reparse points remain leaf rows even if malformed input lists descendants.
    pub fn can_enter(&self) -> bool {
        matches!(self.entry.object_type, ObjectType::Directory)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserLevel {
    directory: String,
    parent_selection: usize,
}

/// A read-only hierarchy built entirely from one completed scan snapshot.
///
/// It never enumerates or stats the filesystem. The initial level is a
/// synthetic virtual-roots screen; entered levels expose only direct children
/// already present in `entries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserModel {
    locale: Locale,
    status: OutputStatus,
    scan_id: Option<String>,
    roots: Vec<BrowserRow>,
    children: BTreeMap<String, Vec<BrowserRow>>,
    levels: Vec<BrowserLevel>,
    selected: usize,
}

impl BrowserModel {
    pub fn from_scan_parts(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: &[ScannedEntry],
        entries: &[ScannedEntry],
        aggregates: &[DirectoryAggregate],
    ) -> BrowserModel {
        Self::from_owned_scan_parts(
            locale,
            status,
            scan_id,
            roots.to_vec(),
            entries.to_vec(),
            aggregates.to_vec(),
        )
    }

    pub fn from_owned_scan_parts(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: Vec<ScannedEntry>,
        entries: Vec<ScannedEntry>,
        aggregates: Vec<DirectoryAggregate>,
    ) -> BrowserModel {
        let mut aggregate_by_identity = highest_revision_aggregates(aggregates);
        let mut entry_by_path = deduplicate_entries(entries);
        let (root_by_path, demoted_roots) = normalize_roots(roots);
        for entry in demoted_roots {
            insert_preferred_entry(&mut entry_by_path, entry);
        }
        for path in root_by_path.keys() {
            entry_by_path.remove(path);
        }

        // A parent can expose children only when the snapshot identifies it as
        // a directory. This prevents navigation through symlink/reparse rows.
        let directory_keys: BTreeSet<String> = root_by_path
            .values()
            .chain(entry_by_path.values())
            .filter(|entry| matches!(entry.object_type, ObjectType::Directory))
            .map(|entry| hierarchy_key(&entry.display_path))
            .collect();
        let mut children: BTreeMap<String, Vec<BrowserRow>> = directory_keys
            .iter()
            .cloned()
            .map(|key| (key, Vec::new()))
            .collect();

        for (_, entry) in entry_by_path {
            let Some(parent) = lexical_parent_key(&entry.display_path) else {
                continue;
            };
            let Some(rows) = children.get_mut(&parent) else {
                continue;
            };
            let aggregate = if matches!(entry.object_type, ObjectType::Directory) {
                aggregate_by_identity.remove(&hierarchy_key(&entry.display_path))
            } else {
                None
            };
            rows.push(BrowserRow::from_owned(entry, aggregate, false));
        }
        for rows in children.values_mut() {
            rows.sort_by(browser_row_order);
        }

        let mut roots: Vec<BrowserRow> = root_by_path
            .into_values()
            .map(|entry| {
                let aggregate = aggregate_by_identity.remove(&hierarchy_key(&entry.display_path));
                BrowserRow::from_owned(entry, aggregate, true)
            })
            .collect();
        roots.sort_by(browser_row_order);

        BrowserModel {
            locale,
            status,
            scan_id,
            roots,
            children,
            levels: Vec::new(),
            selected: 0,
        }
    }

    pub const fn locale(&self) -> Locale {
        self.locale
    }

    pub const fn status(&self) -> OutputStatus {
        self.status
    }

    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }

    pub fn visible_rows(&self) -> &[BrowserRow] {
        match self.levels.last() {
            Some(level) => self
                .children
                .get(&hierarchy_key(&level.directory))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => &self.roots,
        }
    }

    pub const fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn selected_row(&self) -> Option<&BrowserRow> {
        self.visible_rows().get(self.selected)
    }

    pub fn current_directory(&self) -> Option<&str> {
        self.levels.last().map(|level| level.directory.as_str())
    }

    pub fn is_virtual_roots(&self) -> bool {
        self.levels.is_empty()
    }

    pub fn breadcrumbs(&self) -> Vec<String> {
        std::iter::once(virtual_roots_label(self.locale).to_string())
            .chain(
                self.levels
                    .iter()
                    .map(|level| sanitize_terminal_text(&level.directory)),
            )
            .collect()
    }

    fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn move_down(&mut self) {
        if self.selected + 1 < self.visible_rows().len() {
            self.selected += 1;
        }
    }

    fn enter_selected(&mut self) {
        let Some(row) = self.selected_row() else {
            return;
        };
        if !row.can_enter() {
            return;
        }

        let directory = row.display_path().to_string();
        self.levels.push(BrowserLevel {
            directory,
            parent_selection: self.selected,
        });
        self.selected = 0;
    }

    fn return_to_parent(&mut self) {
        let Some(level) = self.levels.pop() else {
            return;
        };
        self.selected = level.parent_selection;
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.visible_rows().len().saturating_sub(1));
    }
}

fn highest_revision_aggregates(
    aggregates: Vec<DirectoryAggregate>,
) -> BTreeMap<String, DirectoryAggregate> {
    let mut by_identity = BTreeMap::new();
    for aggregate in aggregates {
        let identity = hierarchy_key(&aggregate.directory_identity);
        match by_identity.entry(identity) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(aggregate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let current = entry.get();
                if aggregate.revision > current.revision
                    || (aggregate.revision == current.revision
                        && stable_debug_key(&aggregate) < stable_debug_key(current))
                {
                    entry.insert(aggregate);
                }
            }
        }
    }
    by_identity
}

fn deduplicate_entries(entries: Vec<ScannedEntry>) -> BTreeMap<String, ScannedEntry> {
    let mut by_path = BTreeMap::new();
    for entry in entries {
        insert_preferred_entry(&mut by_path, entry);
    }
    by_path
}

fn insert_preferred_entry(by_path: &mut BTreeMap<String, ScannedEntry>, candidate: ScannedEntry) {
    let key = hierarchy_key(&candidate.display_path);
    match by_path.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if entry_preference(&candidate, entry.get()).is_lt() {
                entry.insert(candidate);
            }
        }
    }
}

fn entry_preference(left: &ScannedEntry, right: &ScannedEntry) -> std::cmp::Ordering {
    object_safety_rank(&left.object_type)
        .cmp(&object_safety_rank(&right.object_type))
        .then_with(|| stable_debug_key(left).cmp(&stable_debug_key(right)))
}

fn object_safety_rank(object_type: &ObjectType) -> u8 {
    match object_type {
        ObjectType::Symlink => 0,
        ObjectType::ReparsePoint => 1,
        ObjectType::Other => 2,
        ObjectType::File => 3,
        ObjectType::Directory => 4,
    }
}

fn stable_debug_key(value: &impl std::fmt::Debug) -> String {
    format!("{value:?}")
}

fn normalize_roots(
    roots: Vec<ScannedEntry>,
) -> (BTreeMap<String, ScannedEntry>, Vec<ScannedEntry>) {
    let mut by_path = deduplicate_entries(roots);
    let root_keys = by_path.keys().cloned().collect::<Vec<_>>();
    let mut demoted = Vec::new();
    for candidate in &root_keys {
        if root_keys
            .iter()
            .any(|ancestor| ancestor != candidate && is_path_ancestor(ancestor, candidate))
            && let Some(entry) = by_path.remove(candidate)
        {
            demoted.push(entry);
        }
    }
    (by_path, demoted)
}

fn is_path_ancestor(ancestor: &str, candidate: &str) -> bool {
    if ancestor == candidate {
        return false;
    }
    let Some(separator) = separator_for(candidate) else {
        return false;
    };
    let ancestor = hierarchy_key(ancestor);
    let candidate = hierarchy_key(candidate);
    if ancestor == separator.to_string() {
        return candidate.starts_with(separator);
    }
    candidate
        .strip_prefix(&ancestor)
        .is_some_and(|suffix| suffix.starts_with(separator))
}

fn browser_row_order(left: &BrowserRow, right: &BrowserRow) -> std::cmp::Ordering {
    left.display_path().cmp(right.display_path())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserAction {
    MoveUp,
    MoveDown,
    EnterDirectory,
    ReturnToParent,
    Quit,
}

impl BrowserAction {
    pub const fn is_destructive(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserControl {
    Continue,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserExit {
    Quit,
    Terminated { signal: Option<u8> },
}

pub trait BrowserKeyMapper {
    fn map_key(&self, key: &KeyEvent) -> Option<BrowserAction>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultBrowserKeyMapper;

impl BrowserKeyMapper for DefaultBrowserKeyMapper {
    fn map_key(&self, key: &KeyEvent) -> Option<BrowserAction> {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return None;
        }

        match key.code {
            KeyCode::Char(character)
                if character.eq_ignore_ascii_case(&'c')
                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                Some(BrowserAction::Quit)
            }
            KeyCode::Up | KeyCode::Char('k') => Some(BrowserAction::MoveUp),
            KeyCode::Down | KeyCode::Char('j') => Some(BrowserAction::MoveDown),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                Some(BrowserAction::EnterDirectory)
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                Some(BrowserAction::ReturnToParent)
            }
            KeyCode::Char('q') => Some(BrowserAction::Quit),
            _ => None,
        }
    }
}

pub trait BrowserReducer {
    fn reduce(&self, model: &mut BrowserModel, action: BrowserAction) -> BrowserControl;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReadOnlyBrowserReducer;

impl BrowserReducer for ReadOnlyBrowserReducer {
    fn reduce(&self, model: &mut BrowserModel, action: BrowserAction) -> BrowserControl {
        match action {
            BrowserAction::MoveUp => model.move_up(),
            BrowserAction::MoveDown => model.move_down(),
            BrowserAction::EnterDirectory => model.enter_selected(),
            BrowserAction::ReturnToParent => model.return_to_parent(),
            BrowserAction::Quit => return BrowserControl::Quit,
        }
        BrowserControl::Continue
    }
}

pub trait BrowserEventSource {
    fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CrosstermEventSource;

impl BrowserEventSource for CrosstermEventSource {
    fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        if event::poll(timeout)? {
            event::read().map(Some)
        } else {
            Ok(None)
        }
    }
}

pub trait TerminationFlag {
    fn termination_signal(&self) -> Option<u8>;
}

impl TerminationFlag for AtomicUsize {
    fn termination_signal(&self) -> Option<u8> {
        u8::try_from(self.load(Ordering::SeqCst))
            .ok()
            .filter(|signal| *signal != 0)
    }
}

impl<T> TerminationFlag for Arc<T>
where
    T: TerminationFlag + ?Sized,
{
    fn termination_signal(&self) -> Option<u8> {
        (**self).termination_signal()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NeverTerminate;

impl TerminationFlag for NeverTerminate {
    fn termination_signal(&self) -> Option<u8> {
        None
    }
}

#[cfg(unix)]
struct UnixTerminationFlag {
    previous: libc::sigaction,
    _exclusive_registration: MutexGuard<'static, ()>,
}

#[cfg(unix)]
impl std::fmt::Debug for UnixTerminationFlag {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixTerminationFlag")
            .field("signal", &self.termination_signal())
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
static TERMINATION_SIGNAL: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn record_sigterm(signal: libc::c_int) {
    TERMINATION_SIGNAL.store(signal as usize, Ordering::SeqCst);
}

#[cfg(unix)]
impl UnixTerminationFlag {
    fn install() -> io::Result<Self> {
        static INSTALL_LOCK: Mutex<()> = Mutex::new(());
        let registration = INSTALL_LOCK
            .lock()
            .map_err(|_| io::Error::other("termination handler lock poisoned"))?;
        TERMINATION_SIGNAL.store(0, Ordering::SeqCst);

        // SAFETY: the value is initialized for sigaction, and the handler
        // performs only an atomic store. The mutex guard prevents overlapping
        // browser registrations in this process.
        let action = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_sigterm as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            action
        };
        // SAFETY: the pointers reference live sigaction values and SIGTERM is
        // a valid Unix signal.
        let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
        if unsafe { libc::sigaction(libc::SIGTERM, &action, &mut previous) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            previous,
            _exclusive_registration: registration,
        })
    }
}

#[cfg(unix)]
impl TerminationFlag for UnixTerminationFlag {
    fn termination_signal(&self) -> Option<u8> {
        TERMINATION_SIGNAL.termination_signal()
    }
}

#[cfg(unix)]
impl Drop for UnixTerminationFlag {
    fn drop(&mut self) {
        // SAFETY: previous was populated by successful installation, and the
        // exclusive registration guard remains held here.
        let _ = unsafe { libc::sigaction(libc::SIGTERM, &self.previous, std::ptr::null_mut()) };
    }
}

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("terminal I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Restores all terminal modes independently on explicit restore or drop.
///
/// The guard exists before the first setup operation, so even a partial setup
/// failure runs all three best-effort restoration steps.
#[derive(Debug)]
pub struct TerminalGuard {
    restore_on_drop: bool,
}

impl TerminalGuard {
    pub fn enter() -> Result<Self, BrowserError> {
        let guard = Self {
            restore_on_drop: true,
        };

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        execute!(stdout, Hide)?;
        stdout.flush()?;
        Ok(guard)
    }

    pub fn restore(&mut self) {
        if self.restore_on_drop {
            restore_terminal_best_effort();
            self.restore_on_drop = false;
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

fn restore_terminal_best_effort() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = execute!(stdout, Show);
    let _ = stdout.flush();
}

pub fn run_live_browser(mut model: BrowserModel) -> Result<BrowserExit, BrowserError> {
    #[cfg(unix)]
    let termination = UnixTerminationFlag::install()?;
    #[cfg(not(unix))]
    let termination = NeverTerminate;
    let mut guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut events = CrosstermEventSource;
    let mapper = DefaultBrowserKeyMapper;
    let reducer = ReadOnlyBrowserReducer;
    let result = run_browser_loop_until(
        &mut terminal,
        &mut model,
        &mut events,
        &mapper,
        &reducer,
        &termination,
    );

    drop(terminal);
    guard.restore();
    result
}

pub fn run_browser_loop<B, E, K, R>(
    terminal: &mut Terminal<B>,
    model: &mut BrowserModel,
    events: &mut E,
    key_mapper: &K,
    reducer: &R,
) -> Result<BrowserExit, BrowserError>
where
    B: Backend,
    E: BrowserEventSource,
    K: BrowserKeyMapper,
    R: BrowserReducer,
{
    run_browser_loop_until(
        terminal,
        model,
        events,
        key_mapper,
        reducer,
        &NeverTerminate,
    )
}

pub fn run_browser_loop_until<B, E, K, R, T>(
    terminal: &mut Terminal<B>,
    model: &mut BrowserModel,
    events: &mut E,
    key_mapper: &K,
    reducer: &R,
    termination: &T,
) -> Result<BrowserExit, BrowserError>
where
    B: Backend,
    E: BrowserEventSource,
    K: BrowserKeyMapper,
    R: BrowserReducer,
    T: TerminationFlag + ?Sized,
{
    loop {
        if let Some(signal) = termination.termination_signal() {
            return Ok(BrowserExit::Terminated {
                signal: Some(signal),
            });
        }
        terminal.draw(|frame| render_live_browser(frame, frame.area(), model))?;

        let event = match events.poll_event(BROWSER_EVENT_POLL_INTERVAL) {
            Ok(event) => event,
            Err(_) if termination.termination_signal().is_some() => {
                return Ok(BrowserExit::Terminated {
                    signal: termination.termination_signal(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(signal) = termination.termination_signal() {
            return Ok(BrowserExit::Terminated {
                signal: Some(signal),
            });
        }

        if let Some(Event::Key(key)) = event
            && let Some(action) = key_mapper.map_key(&key)
            && reducer.reduce(model, action) == BrowserControl::Quit
        {
            return Ok(BrowserExit::Quit);
        }
    }
}

pub fn render_live_browser(frame: &mut Frame<'_>, area: Rect, model: &BrowserModel) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    let title = match model.scan_id() {
        Some(scan_id) => {
            let scan_id = sanitize_terminal_text(scan_id);
            format!(
                "SweepX | {}: {scan_id} | {}: {}",
                scan_label(model.locale()),
                status_label(model.locale()),
                output_status_label(model.status())
            )
        }
        None => format!(
            "SweepX | {}: {}",
            status_label(model.locale()),
            output_status_label(model.status())
        ),
    };
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
        sections[0],
    );

    let breadcrumb = model.breadcrumbs().join(" > ");
    frame.render_widget(
        Paragraph::new(breadcrumb).block(
            Block::default()
                .borders(Borders::ALL)
                .title(breadcrumb_label(model.locale())),
        ),
        sections[1],
    );

    render_browser_rows(frame, sections[2], model);

    frame.render_widget(
        Paragraph::new(help_text(model.locale())).block(
            Block::default()
                .borders(Borders::ALL)
                .title(read_only_label(model.locale())),
        ),
        sections[3],
    );
}

fn render_browser_rows(frame: &mut Frame<'_>, area: Rect, model: &BrowserModel) {
    let rows = model.visible_rows();
    let visible_count = usize::from(area.height.saturating_sub(3)).max(1);
    let start = model
        .selected_index()
        .saturating_sub(visible_count.saturating_sub(1));
    let end = (start + visible_count).min(rows.len());

    let header = Row::new([
        TableCell::from(name_label(model.locale())),
        TableCell::from(type_label(model.locale())),
        TableCell::from(size_label(model.locale())),
        TableCell::from(reclaimable_label(model.locale())),
        TableCell::from(children_label(model.locale())),
        TableCell::from(coverage_header_label(model.locale())),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let table_rows = rows[start..end].iter().enumerate().map(|(offset, row)| {
        let index = start + offset;
        let aggregate = row.aggregate();
        let logical = aggregate
            .map(|value| byte_value_label(&value.apparent_logical_bytes))
            .unwrap_or_else(|| byte_value_label(&row.entry().logical_bytes));
        let reclaimable = aggregate
            .map(|value| byte_value_label(&value.potentially_reclaimable_bytes))
            .unwrap_or_else(|| byte_value_label(&row.entry().reclaimable_estimate));
        let children = aggregate
            .map(|value| count_value_label(&value.direct_child_count))
            .unwrap_or_else(|| "-".to_string());
        let coverage = aggregate
            .map(|value| &value.coverage.state)
            .unwrap_or(&row.entry().coverage.state);
        let style = if index == model.selected_index() {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };

        Row::new([
            TableCell::from(row.label().to_string()),
            TableCell::from(object_type_label(row.object_type().clone())),
            TableCell::from(logical),
            TableCell::from(reclaimable),
            TableCell::from(children),
            TableCell::from(coverage_label(coverage)),
        ])
        .style(style)
    });

    let empty_title = if rows.is_empty() {
        empty_label(model.locale())
    } else {
        contents_label(model.locale())
    };
    let table = Table::new(
        table_rows,
        [
            Constraint::Percentage(42),
            Constraint::Length(11),
            Constraint::Length(13),
            Constraint::Length(13),
            Constraint::Length(10),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(empty_title));
    frame.render_widget(table, area);
}

fn count_value_label(value: &sweepx_model::CountValue) -> String {
    byte_value_label(value)
}

fn separator_for(path: &str) -> Option<char> {
    if path.contains('/') {
        Some('/')
    } else if path.contains('\\') {
        Some('\\')
    } else {
        None
    }
}

fn hierarchy_key(path: &str) -> String {
    let Some(separator) = separator_for(path) else {
        return path.to_string();
    };
    let trimmed = path.trim_end_matches(separator);
    if trimmed.is_empty() {
        separator.to_string()
    } else {
        trimmed.to_string()
    }
}

fn lexical_parent_key(path: &str) -> Option<String> {
    let separator = separator_for(path)?;
    let cleaned = hierarchy_key(path);
    let index = cleaned.rfind(separator)?;
    if index == 0 {
        return Some(separator.to_string());
    }
    Some(hierarchy_key(&cleaned[..index]))
}

fn display_basename(path: &str) -> String {
    let cleaned = hierarchy_key(path);
    separator_for(&cleaned)
        .and_then(|separator| cleaned.rsplit(separator).next())
        .filter(|name| !name.is_empty())
        .unwrap_or(&cleaned)
        .to_string()
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn virtual_roots_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "扫描根目录",
        Locale::EnUs => "Scan roots",
    }
}

fn breadcrumb_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "位置",
        Locale::EnUs => "Location",
    }
}

fn scan_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "扫描",
        Locale::EnUs => "scan",
    }
}

fn status_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "状态",
        Locale::EnUs => "status",
    }
}

fn read_only_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "只读",
        Locale::EnUs => "Read-only",
    }
}

fn help_text(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "↑/↓ 选择  Enter/→ 进入目录  Esc/Backspace/← 返回  q/Ctrl-C 退出",
        Locale::EnUs => "↑/↓ select  Enter/→ open directory  Esc/Backspace/← back  q/Ctrl-C quit",
    }
}

fn name_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "名称",
        Locale::EnUs => "Name",
    }
}

fn type_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "类型",
        Locale::EnUs => "Type",
    }
}

fn size_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "大小",
        Locale::EnUs => "Size",
    }
}

fn reclaimable_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "可回收",
        Locale::EnUs => "Reclaimable",
    }
}

fn children_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "直接子项",
        Locale::EnUs => "Children",
    }
}

fn coverage_header_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "覆盖状态",
        Locale::EnUs => "Coverage",
    }
}

fn contents_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "内容",
        Locale::EnUs => "Contents",
    }
}

fn empty_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "无直接子项",
        Locale::EnUs => "No direct children",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crossterm::event::{KeyEventState, KeyModifiers};
    use ratatui::backend::TestBackend;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, EvidenceValue, FieldProvenance,
        MethodId, NativeName, ReasonCode, ScanId,
    };

    use super::*;

    fn coverage() -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-27T00:00:00Z".to_string(),
                method: MethodId::MetadataNoFollow,
            },
        }
    }

    fn entry(path: &str, object_type: ObjectType) -> ScannedEntry {
        ScannedEntry {
            scan_id: ScanId::new("scan-live"),
            display_path: path.to_string(),
            native_basename: NativeName::unix(display_basename(path).into_bytes()),
            object_type,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(7),
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(8),
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::new(5),
            },
            metadata_fingerprint: format!("fingerprint:{path}"),
            coverage: coverage(),
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-27T00:00:00Z".to_string(),
                method: MethodId::MetadataNoFollow,
            },
        }
    }

    fn aggregate(path: &str) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: ScanId::new("scan-live"),
            directory_identity: path.to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(70),
            },
            unique_logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(60),
            },
            filesystem_reported_allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::new(80),
            },
            potentially_reclaimable_bytes: EvidenceValue::LowerBound {
                value: DecimalU128::new(50),
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            direct_child_count: EvidenceValue::Known {
                value: DecimalU128::new(2),
            },
            recursive_entry_count: EvidenceValue::Known {
                value: DecimalU128::new(3),
            },
            coverage: coverage(),
            arithmetic_state: ArithmeticState::Exact,
        }
    }

    fn model() -> BrowserModel {
        BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[entry("/root", ObjectType::Directory)],
            &[
                entry("/root/file.txt", ObjectType::File),
                entry("/root/sub", ObjectType::Directory),
                entry("/root/sub/deep.txt", ObjectType::File),
            ],
            &[aggregate("/root"), aggregate("/root/sub")],
        )
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn starts_at_synthetic_roots_and_shows_only_direct_children() {
        let mut model = model();
        assert!(model.is_virtual_roots());
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].display_path(), "/root");
        assert!(model.visible_rows()[0].aggregate().is_some());

        model.enter_selected();
        let paths = model
            .visible_rows()
            .iter()
            .map(BrowserRow::display_path)
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/root/file.txt", "/root/sub"]);
        assert!(!paths.contains(&"/root/sub/deep.txt"));
        assert_eq!(model.breadcrumbs(), ["Scan roots", "/root"]);
    }

    #[test]
    fn aggregates_are_joined_without_creating_rows() {
        let mut model = model();
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(
            model.visible_rows()[0]
                .aggregate()
                .unwrap()
                .directory_identity,
            "/root"
        );

        model.enter_selected();
        assert_eq!(model.visible_rows().len(), 2);
        assert!(model.visible_rows()[0].aggregate().is_none());
        assert_eq!(
            model.visible_rows()[1]
                .aggregate()
                .unwrap()
                .directory_identity,
            "/root/sub"
        );
    }

    #[test]
    fn reducer_enters_directories_and_restores_parent_selection() {
        let reducer = ReadOnlyBrowserReducer;
        let mut model = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Partial,
            None,
            &[
                entry("/first", ObjectType::Directory),
                entry("/second", ObjectType::Directory),
            ],
            &[entry("/second/file", ObjectType::File)],
            &[],
        );

        reducer.reduce(&mut model, BrowserAction::MoveDown);
        assert_eq!(model.selected_index(), 1);
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        assert_eq!(model.current_directory(), Some("/second"));
        assert_eq!(model.selected_index(), 0);
        reducer.reduce(&mut model, BrowserAction::ReturnToParent);
        assert!(model.is_virtual_roots());
        assert_eq!(model.selected_index(), 1);
        assert_eq!(
            reducer.reduce(&mut model, BrowserAction::Quit),
            BrowserControl::Quit
        );
        assert!(!BrowserAction::EnterDirectory.is_destructive());
    }

    #[test]
    fn symlink_and_reparse_rows_cannot_be_entered() {
        for object_type in [ObjectType::Symlink, ObjectType::ReparsePoint] {
            let mut model = BrowserModel::from_scan_parts(
                Locale::EnUs,
                OutputStatus::Ok,
                None,
                &[entry("/root", ObjectType::Directory)],
                &[
                    entry("/root/link", object_type),
                    entry("/root/link/hidden", ObjectType::File),
                ],
                &[],
            );
            model.enter_selected();
            assert_eq!(model.visible_rows().len(), 1);
            assert!(!model.selected_row().unwrap().can_enter());
            model.enter_selected();
            assert_eq!(model.current_directory(), Some("/root"));
        }
    }

    #[test]
    fn default_key_mapping_is_navigation_only_and_ignores_release() {
        let mapper = DefaultBrowserKeyMapper;
        assert_eq!(
            mapper.map_key(&key(KeyCode::Up)),
            Some(BrowserAction::MoveUp)
        );
        assert_eq!(
            mapper.map_key(&key(KeyCode::Char('j'))),
            Some(BrowserAction::MoveDown)
        );
        assert_eq!(
            mapper.map_key(&key(KeyCode::Right)),
            Some(BrowserAction::EnterDirectory)
        );
        assert_eq!(
            mapper.map_key(&key(KeyCode::Backspace)),
            Some(BrowserAction::ReturnToParent)
        );
        assert_eq!(
            mapper.map_key(&key(KeyCode::Char('q'))),
            Some(BrowserAction::Quit)
        );
        let ctrl_c = KeyEvent {
            modifiers: KeyModifiers::CONTROL,
            ..key(KeyCode::Char('c'))
        };
        assert_eq!(mapper.map_key(&ctrl_c), Some(BrowserAction::Quit));
        assert_eq!(mapper.map_key(&key(KeyCode::Char('c'))), None);
        let ctrl_c_release = KeyEvent {
            kind: KeyEventKind::Release,
            ..ctrl_c
        };
        assert_eq!(mapper.map_key(&ctrl_c_release), None);

        let mut release = key(KeyCode::Down);
        release.kind = KeyEventKind::Release;
        assert_eq!(mapper.map_key(&release), None);
        assert_eq!(mapper.map_key(&key(KeyCode::Delete)), None);
    }

    #[derive(Debug)]
    struct ScriptedEvents {
        events: VecDeque<Option<Event>>,
        polls: Vec<Duration>,
    }

    impl BrowserEventSource for ScriptedEvents {
        fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
            self.polls.push(timeout);
            self.events
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "script exhausted"))
        }
    }

    fn rendered_text(backend: &TestBackend) -> String {
        let buffer = backend.buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn injected_event_loop_renders_entered_directory_with_test_backend() {
        let backend = TestBackend::new(100, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = model();
        let mut events = ScriptedEvents {
            events: VecDeque::from([
                Some(Event::Key(key(KeyCode::Enter))),
                Some(Event::Key(key(KeyCode::Char('q')))),
            ]),
            polls: Vec::new(),
        };

        let exit = run_browser_loop(
            &mut terminal,
            &mut model,
            &mut events,
            &DefaultBrowserKeyMapper,
            &ReadOnlyBrowserReducer,
        )
        .unwrap();

        assert_eq!(exit, BrowserExit::Quit);
        assert_eq!(model.current_directory(), Some("/root"));
        let rendered = rendered_text(terminal.backend());
        assert!(rendered.contains("Scan roots > /root"));
        assert!(rendered.contains("file.txt"));
        assert!(rendered.contains("sub"));
        assert!(!rendered.contains("deep.txt"));
        assert!(rendered.contains("Read-only"));
        assert_eq!(
            events.polls,
            [BROWSER_EVENT_POLL_INTERVAL, BROWSER_EVENT_POLL_INTERVAL]
        );
    }

    #[derive(Debug)]
    struct TerminateAfterPoll {
        terminated: Arc<AtomicUsize>,
        polls: usize,
    }

    impl BrowserEventSource for TerminateAfterPoll {
        fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
            assert_eq!(timeout, BROWSER_EVENT_POLL_INTERVAL);
            self.polls += 1;
            self.terminated.store(15, Ordering::SeqCst);
            Ok(None)
        }
    }

    #[test]
    fn bounded_poll_observes_injected_termination_and_exits_normally() {
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = model();
        let terminated = Arc::new(AtomicUsize::new(0));
        let mut events = TerminateAfterPoll {
            terminated: Arc::clone(&terminated),
            polls: 0,
        };

        let exit = run_browser_loop_until(
            &mut terminal,
            &mut model,
            &mut events,
            &DefaultBrowserKeyMapper,
            &ReadOnlyBrowserReducer,
            &terminated,
        )
        .unwrap();

        assert_eq!(exit, BrowserExit::Terminated { signal: Some(15) });
        assert_eq!(events.polls, 1);
    }

    #[derive(Debug)]
    struct InterruptOnTermination {
        terminated: Arc<AtomicUsize>,
    }

    impl BrowserEventSource for InterruptOnTermination {
        fn poll_event(&mut self, _timeout: Duration) -> io::Result<Option<Event>> {
            self.terminated.store(15, Ordering::SeqCst);
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }

    #[test]
    fn interrupted_poll_after_termination_is_a_graceful_exit() {
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = model();
        let terminated = Arc::new(AtomicUsize::new(0));
        let mut events = InterruptOnTermination {
            terminated: Arc::clone(&terminated),
        };

        let exit = run_browser_loop_until(
            &mut terminal,
            &mut model,
            &mut events,
            &DefaultBrowserKeyMapper,
            &ReadOnlyBrowserReducer,
            &terminated,
        )
        .unwrap();

        assert_eq!(exit, BrowserExit::Terminated { signal: Some(15) });
    }

    #[test]
    fn an_already_set_termination_flag_exits_before_polling() {
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = model();
        let terminated = AtomicUsize::new(2);
        let mut events = ScriptedEvents {
            events: VecDeque::new(),
            polls: Vec::new(),
        };

        let exit = run_browser_loop_until(
            &mut terminal,
            &mut model,
            &mut events,
            &DefaultBrowserKeyMapper,
            &ReadOnlyBrowserReducer,
            &terminated,
        )
        .unwrap();

        assert_eq!(exit, BrowserExit::Terminated { signal: Some(2) });
        assert!(events.polls.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn unix_sigterm_handler_sets_the_graceful_termination_flag() {
        // SAFETY: querying a disposition with a null new-action pointer writes
        // the current disposition into before.
        let mut before = unsafe { std::mem::zeroed::<libc::sigaction>() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut before) },
            0
        );
        {
            let termination = UnixTerminationFlag::install().unwrap();
            // SAFETY: raising SIGTERM targets this process while the scoped
            // test handler is installed.
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            assert_eq!(termination.termination_signal(), Some(libc::SIGTERM as u8));
        }
        // SAFETY: query the disposition restored by the guard's Drop.
        let mut after = unsafe { std::mem::zeroed::<libc::sigaction>() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut after) },
            0
        );
        assert_eq!(after.sa_sigaction, before.sa_sigaction);
    }

    #[test]
    fn owned_constructor_deduplicates_sorts_and_uses_highest_aggregate_revision() {
        let mut old = aggregate("/root/dir");
        old.revision = DecimalU128::new(1);
        old.apparent_logical_bytes = EvidenceValue::Known {
            value: DecimalU128::new(10),
        };
        let mut newest = aggregate("/root/dir");
        newest.revision = DecimalU128::new(9);
        newest.apparent_logical_bytes = EvidenceValue::Known {
            value: DecimalU128::new(90),
        };

        let mut model = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            vec![
                entry("/root/subroot", ObjectType::Directory),
                entry("/z-root", ObjectType::Directory),
                entry("/root", ObjectType::Directory),
                entry("/root", ObjectType::Directory),
            ],
            vec![
                entry("/root/z.txt", ObjectType::File),
                entry("/root/dir", ObjectType::Directory),
                entry("/root/a.txt", ObjectType::File),
                entry("/root/a.txt", ObjectType::File),
            ],
            vec![newest, old],
        );

        assert_eq!(
            model
                .visible_rows()
                .iter()
                .map(BrowserRow::display_path)
                .collect::<Vec<_>>(),
            ["/root", "/z-root"]
        );
        model.enter_selected();
        let paths = model
            .visible_rows()
            .iter()
            .map(BrowserRow::display_path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            ["/root/a.txt", "/root/dir", "/root/subroot", "/root/z.txt"]
        );
        let directory = &model.visible_rows()[1];
        assert_eq!(directory.aggregate().unwrap().revision, DecimalU128::new(9));
        assert_eq!(
            directory.aggregate().unwrap().apparent_logical_bytes,
            EvidenceValue::Known {
                value: DecimalU128::new(90)
            }
        );
    }

    #[test]
    fn normalization_is_independent_of_input_order() {
        let roots = vec![
            entry("/root/nested", ObjectType::Directory),
            entry("/other", ObjectType::Directory),
            entry("/root/", ObjectType::Directory),
            entry("/root", ObjectType::Directory),
        ];
        let entries = vec![
            entry("/root/z", ObjectType::File),
            entry("/root/a", ObjectType::File),
            entry("/root/a/", ObjectType::File),
            entry("/root/z", ObjectType::File),
        ];
        let aggregates = vec![aggregate("/root"), aggregate("/root/nested")];
        let forward = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            roots.clone(),
            entries.clone(),
            aggregates.clone(),
        );
        let reverse = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            roots.into_iter().rev().collect(),
            entries.into_iter().rev().collect(),
            aggregates.into_iter().rev().collect(),
        );

        assert_eq!(forward, reverse);
        assert_eq!(forward.visible_rows().len(), 2);
    }

    #[test]
    fn windows_style_paths_use_lexical_direct_children() {
        let mut model = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            &[entry("C:\\", ObjectType::Directory)],
            &[
                entry("C:\\file", ObjectType::File),
                entry("C:\\dir", ObjectType::Directory),
                entry("C:\\dir\\nested", ObjectType::File),
            ],
            &[],
        );
        model.enter_selected();
        let paths = model
            .visible_rows()
            .iter()
            .map(BrowserRow::display_path)
            .collect::<Vec<_>>();
        assert_eq!(paths, ["C:\\dir", "C:\\file"]);
    }

    #[test]
    fn terminal_control_characters_are_sanitized_in_labels_and_breadcrumbs() {
        let malicious = "/root/\u{1b}]52;c;clipboard\u{7}";
        let mut model = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            &[entry(malicious, ObjectType::Directory)],
            &[],
            &[],
        );

        assert!(!model.visible_rows()[0].label().contains('\u{1b}'));
        assert!(!model.visible_rows()[0].label().contains('\u{7}'));
        model.enter_selected();
        assert!(
            model
                .breadcrumbs()
                .iter()
                .all(|part| !part.chars().any(char::is_control))
        );
    }
}
