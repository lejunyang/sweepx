use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell as TableCell, Paragraph, Row, Table, Tabs, Wrap};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::cell::Cell as FlagCell;
use std::cmp::min;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::rc::Rc;
use sweepx_i18n::{Catalog, Locale, MessageArgs, MessageKey};
use sweepx_model::{ArithmeticState, CoverageState, DirectoryAggregate, ObjectType, ScannedEntry};
use sweepx_protocol::{OutputKind, OutputStatus};
use thiserror::Error;

mod live;

pub use live::{
    BrowserAction, BrowserControl, BrowserError, BrowserEventSource, BrowserExit, BrowserKeyMapper,
    BrowserLoadLimits, BrowserModel, BrowserModelError, BrowserReducer, BrowserResourceLimitKind,
    BrowserRow, CrosstermEventSource, DefaultBrowserKeyMapper, NeverTerminate,
    ReadOnlyBrowserReducer, TerminalGuard, TerminationFlag, render_live_browser, run_browser_loop,
    run_browser_loop_until, run_live_browser,
};

pub const MAX_PAGE_ROWS: usize = 500;
pub const DEFAULT_MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_ROWS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Overview,
    List,
    Explain,
}

impl Pane {
    pub const ALL: [Self; 3] = [Self::Overview, Self::List, Self::Explain];

    pub const fn next(self) -> Self {
        match self {
            Self::Overview => Self::List,
            Self::List => Self::Explain,
            Self::Explain => Self::Overview,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Overview => Self::Explain,
            Self::List => Self::Overview,
            Self::Explain => Self::List,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationAction {
    NextPane,
    PreviousPane,
    NextRow,
    PreviousRow,
    NextPage,
    PreviousPage,
    RefreshRevision(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOnlyAction {
    Navigate(NavigationAction),
}

impl ReadOnlyAction {
    pub const fn is_destructive(self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PageCursor {
    pub page_index: usize,
    pub row_index: usize,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorStatus {
    Valid,
    ResetForRevisionChange {
        previous_revision: u64,
        new_revision: u64,
    },
    ResetForBounds {
        requested_page: usize,
        max_page: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorValidation {
    pub cursor: PageCursor,
    pub status: CursorStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageWindow {
    pub page_index: usize,
    pub page_count: usize,
    pub total_rows: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKind {
    Root,
    Entry,
    Aggregate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualRow {
    pub key: String,
    pub kind: RowKind,
    pub primary: String,
    pub secondary: String,
    pub status: String,
    pub amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewModel {
    locale: Locale,
    revision: u64,
    title: String,
    status: OutputStatus,
    scan_id: Option<String>,
    root_count: usize,
    entry_count: usize,
    aggregate_count: usize,
    total_rows: usize,
    loaded_page_index: usize,
    rows: Vec<VirtualRow>,
    limits: LoadLimits,
}

impl ViewModel {
    pub fn from_path(
        path: impl AsRef<Path>,
        locale: Locale,
        page_index: usize,
        limits: LoadLimits,
    ) -> Result<Self, ViewModelError> {
        let file = File::open(path).map_err(ViewModelError::Io)?;
        Self::from_reader(file, locale, page_index, limits)
    }

    pub fn from_reader<R: Read>(
        reader: R,
        locale: Locale,
        page_index: usize,
        limits: LoadLimits,
    ) -> Result<Self, ViewModelError> {
        let overflowed = Rc::new(FlagCell::new(false));
        let capped = CappedReader::new(reader, limits.max_input_bytes, overflowed.clone());
        let mut builder = StreamingViewModelBuilder::new(locale, page_index, limits);
        let mut deserializer = serde_json::Deserializer::from_reader(capped);

        match (&mut builder).deserialize(&mut deserializer) {
            Ok(()) => builder.finish(),
            Err(source) => {
                if overflowed.get() {
                    Err(ViewModelError::ResourceLimit {
                        kind: ResourceLimitKind::InputBytes,
                        limit: builder.limits.max_input_bytes,
                        observed: builder.limits.max_input_bytes.saturating_add(1),
                    })
                } else if let Some(limit_error) = builder.limit_error.take() {
                    Err(ViewModelError::ResourceLimit {
                        kind: limit_error.kind,
                        limit: limit_error.limit,
                        observed: limit_error.observed,
                    })
                } else {
                    Err(ViewModelError::Json { source })
                }
            }
        }
    }

    pub fn locale(&self) -> Locale {
        self.locale
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn scan_id(&self) -> Option<&str> {
        self.scan_id.as_deref()
    }

    pub fn loaded_page_index(&self) -> usize {
        self.loaded_page_index
    }

    pub fn retained_row_count(&self) -> usize {
        self.rows.len()
    }

    pub fn limits(&self) -> LoadLimits {
        self.limits
    }

    pub fn needs_reload(&self, cursor: &PageCursor) -> bool {
        cursor.page_index != self.loaded_page_index
    }

    pub fn status(&self) -> OutputStatus {
        self.status
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn root_count(&self) -> usize {
        self.root_count
    }

    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub fn aggregate_count(&self) -> usize {
        self.aggregate_count
    }

    pub fn row_count(&self) -> usize {
        self.total_rows
    }

    pub fn page_count(&self) -> usize {
        if self.total_rows == 0 {
            1
        } else {
            self.total_rows.div_ceil(MAX_PAGE_ROWS)
        }
    }

    pub fn page_window(&self) -> PageWindow {
        let page_count = self.page_count();
        let clamped_page = min(self.loaded_page_index, page_count.saturating_sub(1));
        let start = clamped_page * MAX_PAGE_ROWS;
        let end = min(start + self.rows.len(), self.total_rows);

        PageWindow {
            page_index: clamped_page,
            page_count,
            total_rows: self.total_rows,
            start,
            end,
        }
    }

    pub fn page_rows(&self) -> &[VirtualRow] {
        &self.rows
    }

    pub fn validate_cursor(&self, cursor: PageCursor) -> CursorValidation {
        if cursor.revision != self.revision {
            return CursorValidation {
                cursor: PageCursor {
                    page_index: 0,
                    row_index: 0,
                    revision: self.revision,
                },
                status: CursorStatus::ResetForRevisionChange {
                    previous_revision: cursor.revision,
                    new_revision: self.revision,
                },
            };
        }

        let max_page = self.page_count().saturating_sub(1);
        if cursor.page_index > max_page {
            return CursorValidation {
                cursor: PageCursor {
                    page_index: max_page,
                    row_index: 0,
                    revision: self.revision,
                },
                status: CursorStatus::ResetForBounds {
                    requested_page: cursor.page_index,
                    max_page,
                },
            };
        }

        if cursor.page_index != self.loaded_page_index {
            return CursorValidation {
                cursor: PageCursor {
                    page_index: cursor.page_index,
                    row_index: 0,
                    revision: self.revision,
                },
                status: CursorStatus::Valid,
            };
        }

        let rows = self.page_rows();
        if rows.is_empty() {
            return CursorValidation {
                cursor: PageCursor {
                    page_index: cursor.page_index,
                    row_index: 0,
                    revision: self.revision,
                },
                status: CursorStatus::Valid,
            };
        }

        let row_index = min(cursor.row_index, rows.len() - 1);
        let status = if row_index == cursor.row_index {
            CursorStatus::Valid
        } else {
            CursorStatus::ResetForBounds {
                requested_page: cursor.page_index,
                max_page,
            }
        };

        CursorValidation {
            cursor: PageCursor {
                page_index: cursor.page_index,
                row_index,
                revision: self.revision,
            },
            status,
        }
    }

    pub fn with_revision(mut self, revision: u64) -> Self {
        self.revision = revision;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiState {
    pane: Pane,
    cursor: PageCursor,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            pane: Pane::Overview,
            cursor: PageCursor::default(),
        }
    }
}

impl TuiState {
    pub fn pane(&self) -> Pane {
        self.pane
    }

    pub fn cursor(&self) -> &PageCursor {
        &self.cursor
    }

    pub fn reduce(&self, action: ReadOnlyAction, view: &ViewModel) -> Self {
        let mut next = self.clone();
        match action {
            ReadOnlyAction::Navigate(nav) => match nav {
                NavigationAction::NextPane => next.pane = next.pane.next(),
                NavigationAction::PreviousPane => next.pane = next.pane.previous(),
                NavigationAction::NextRow => {
                    let validated = view.validate_cursor(next.cursor.clone());
                    let rows = if validated.cursor.page_index == view.loaded_page_index() {
                        view.page_rows()
                    } else {
                        &[]
                    };
                    next.cursor = validated.cursor;
                    if !rows.is_empty() && next.cursor.row_index + 1 < rows.len() {
                        next.cursor.row_index += 1;
                    }
                }
                NavigationAction::PreviousRow => {
                    let validated = view.validate_cursor(next.cursor.clone());
                    next.cursor = validated.cursor;
                    next.cursor.row_index = next.cursor.row_index.saturating_sub(1);
                }
                NavigationAction::NextPage => {
                    let validated = view.validate_cursor(next.cursor.clone());
                    next.cursor = validated.cursor;
                    next.cursor.page_index = min(
                        next.cursor.page_index + 1,
                        view.page_count().saturating_sub(1),
                    );
                    next.cursor.row_index = 0;
                }
                NavigationAction::PreviousPage => {
                    let validated = view.validate_cursor(next.cursor.clone());
                    next.cursor = validated.cursor;
                    next.cursor.page_index = next.cursor.page_index.saturating_sub(1);
                    next.cursor.row_index = 0;
                }
                NavigationAction::RefreshRevision(revision) => {
                    next.cursor.revision = revision;
                }
            },
        }

        next.cursor = view.validate_cursor(next.cursor).cursor;
        next
    }
}

#[derive(Debug, Error)]
pub enum ViewModelError {
    #[error("unsupported output kind for TUI: {0:?}")]
    UnsupportedOutputKind(OutputKind),
    #[error("resource limit exceeded for {kind}: limit={limit}, observed={observed}")]
    ResourceLimit {
        kind: ResourceLimitKind,
        limit: usize,
        observed: usize,
    },
    #[error("failed to open input: {0}")]
    Io(#[source] io::Error),
    #[error("failed to parse input: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    #[error("missing scan status in input")]
    MissingStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceLimitKind {
    InputBytes,
    TotalRows,
}

impl fmt::Display for ResourceLimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputBytes => f.write_str("input_bytes"),
            Self::TotalRows => f.write_str("total_rows"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLimits {
    pub max_input_bytes: usize,
    pub max_total_rows: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_total_rows: DEFAULT_MAX_TOTAL_ROWS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LimitError {
    kind: ResourceLimitKind,
    limit: usize,
    observed: usize,
}

struct CappedReader<R> {
    inner: R,
    limit: usize,
    bytes_read: usize,
    overflowed: Rc<FlagCell<bool>>,
}

impl<R> CappedReader<R> {
    fn new(inner: R, limit: usize, overflowed: Rc<FlagCell<bool>>) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
            overflowed,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.bytes_read >= self.limit {
            self.overflowed.set(true);
            return Err(io::Error::other("input byte limit exceeded"));
        }

        let allowed = min(buf.len(), self.limit - self.bytes_read);
        let read = self.inner.read(&mut buf[..allowed])?;
        self.bytes_read += read;
        Ok(read)
    }
}

struct StreamingViewModelBuilder {
    locale: Locale,
    requested_page_index: usize,
    limits: LoadLimits,
    kind: Option<OutputKind>,
    status: Option<OutputStatus>,
    data_scan_id: Option<String>,
    summary_scan_id: Option<String>,
    root_count: usize,
    entry_count: usize,
    aggregate_count: usize,
    total_rows: usize,
    requested_rows: Vec<VirtualRow>,
    trailing_rows: VecDeque<VirtualRow>,
    limit_error: Option<LimitError>,
}

impl StreamingViewModelBuilder {
    fn new(locale: Locale, requested_page_index: usize, limits: LoadLimits) -> Self {
        Self {
            locale,
            requested_page_index,
            limits,
            kind: None,
            status: None,
            data_scan_id: None,
            summary_scan_id: None,
            root_count: 0,
            entry_count: 0,
            aggregate_count: 0,
            total_rows: 0,
            requested_rows: Vec::with_capacity(MAX_PAGE_ROWS),
            trailing_rows: VecDeque::with_capacity(MAX_PAGE_ROWS),
            limit_error: None,
        }
    }

    fn requested_page_start(&self) -> usize {
        self.requested_page_index.saturating_mul(MAX_PAGE_ROWS)
    }

    fn push_root(&mut self, root: ScannedEntry) -> Result<(), LimitError> {
        self.root_count += 1;
        self.push_row(VirtualRow::from_root(&root))
    }

    fn push_entry(&mut self, entry: ScannedEntry) -> Result<(), LimitError> {
        self.entry_count += 1;
        self.push_row(VirtualRow::from_entry(&entry))
    }

    fn push_aggregate(&mut self, aggregate: DirectoryAggregate) -> Result<(), LimitError> {
        self.aggregate_count += 1;
        self.push_row(VirtualRow::from_aggregate(&aggregate))
    }

    fn push_row(&mut self, row: VirtualRow) -> Result<(), LimitError> {
        let observed = self.total_rows.saturating_add(1);
        if observed > self.limits.max_total_rows {
            return Err(LimitError {
                kind: ResourceLimitKind::TotalRows,
                limit: self.limits.max_total_rows,
                observed,
            });
        }

        let current_index = self.total_rows;
        self.total_rows = observed;

        let requested_start = self.requested_page_start();
        let requested_end = requested_start.saturating_add(MAX_PAGE_ROWS);
        if current_index >= requested_start && current_index < requested_end {
            self.requested_rows.push(row.clone());
        }

        if self.trailing_rows.len() == MAX_PAGE_ROWS {
            self.trailing_rows.pop_front();
        }
        self.trailing_rows.push_back(row);
        Ok(())
    }

    fn finish(self) -> Result<ViewModel, ViewModelError> {
        let kind = self.kind.unwrap_or(OutputKind::StatusResult);
        if kind != OutputKind::ScanResult {
            return Err(ViewModelError::UnsupportedOutputKind(kind));
        }

        let scan_id = self.data_scan_id.or(self.summary_scan_id);
        let title = scan_id
            .clone()
            .map(|id| format!("SweepX TUI | {id}"))
            .unwrap_or_else(|| "SweepX TUI".to_string());

        let max_page = if self.total_rows == 0 {
            0
        } else {
            self.total_rows.div_ceil(MAX_PAGE_ROWS).saturating_sub(1)
        };
        let effective_page_index = min(self.requested_page_index, max_page);
        let retained_rows = if effective_page_index == self.requested_page_index {
            self.requested_rows
        } else {
            self.trailing_rows.into_iter().collect()
        };

        Ok(ViewModel {
            locale: self.locale,
            revision: 0,
            title,
            status: self.status.ok_or(ViewModelError::MissingStatus)?,
            scan_id,
            root_count: self.root_count,
            entry_count: self.entry_count,
            aggregate_count: self.aggregate_count,
            total_rows: self.total_rows,
            loaded_page_index: effective_page_index,
            rows: retained_rows,
            limits: self.limits,
        })
    }
}

impl<'de> DeserializeSeed<'de> for &mut StreamingViewModelBuilder {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(EnvelopeVisitor { builder: self })
    }
}

struct EnvelopeVisitor<'a> {
    builder: &'a mut StreamingViewModelBuilder,
}

impl<'de> Visitor<'de> for EnvelopeVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sweepx output envelope")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "kind" => self.builder.kind = Some(map.next_value()?),
                "status" => self.builder.status = Some(map.next_value()?),
                "summary" => {
                    map.next_value_seed(SummarySeed {
                        scan_id: &mut self.builder.summary_scan_id,
                    })?;
                }
                "data" => {
                    map.next_value_seed(DataSeed {
                        builder: self.builder,
                    })?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct SummarySeed<'a> {
    scan_id: &'a mut Option<String>,
}

impl<'de> DeserializeSeed<'de> for SummarySeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(SummaryVisitor {
            scan_id: self.scan_id,
        })
    }
}

struct SummaryVisitor<'a> {
    scan_id: &'a mut Option<String>,
}

impl<'de> Visitor<'de> for SummaryVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a summary object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if key == "scanId" || key == "scan_id" {
                *self.scan_id = map.next_value()?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct DataSeed<'a> {
    builder: &'a mut StreamingViewModelBuilder,
}

impl<'de> DeserializeSeed<'de> for DataSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DataVisitor {
            builder: self.builder,
        })
    }
}

struct DataVisitor<'a> {
    builder: &'a mut StreamingViewModelBuilder,
}

impl<'de> Visitor<'de> for DataVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a data object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "scanId" | "scan_id" => self.builder.data_scan_id = map.next_value()?,
                "roots" => map.next_value_seed(EntryArraySeed {
                    builder: self.builder,
                    kind: ArraySection::Roots,
                })?,
                "entries" => map.next_value_seed(EntryArraySeed {
                    builder: self.builder,
                    kind: ArraySection::Entries,
                })?,
                "aggregates" => map.next_value_seed(AggregateArraySeed {
                    builder: self.builder,
                })?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ArraySection {
    Roots,
    Entries,
}

struct EntryArraySeed<'a> {
    builder: &'a mut StreamingViewModelBuilder,
    kind: ArraySection,
}

impl<'de> DeserializeSeed<'de> for EntryArraySeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(EntryArrayVisitor {
            builder: self.builder,
            kind: self.kind,
        })
    }
}

struct EntryArrayVisitor<'a> {
    builder: &'a mut StreamingViewModelBuilder,
    kind: ArraySection,
}

impl<'de> Visitor<'de> for EntryArrayVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a scanned entry array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(item) = seq.next_element::<Value>()? {
            let item = parse_scanned_entry_value(item).map_err(de::Error::custom)?;
            let result = match self.kind {
                ArraySection::Roots => self.builder.push_root(item),
                ArraySection::Entries => self.builder.push_entry(item),
            };
            if let Err(limit_error) = result {
                self.builder.limit_error = Some(limit_error);
                return Err(de::Error::custom("row resource limit exceeded"));
            }
        }
        Ok(())
    }
}

struct AggregateArraySeed<'a> {
    builder: &'a mut StreamingViewModelBuilder,
}

impl<'de> DeserializeSeed<'de> for AggregateArraySeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(AggregateArrayVisitor {
            builder: self.builder,
        })
    }
}

struct AggregateArrayVisitor<'a> {
    builder: &'a mut StreamingViewModelBuilder,
}

impl<'de> Visitor<'de> for AggregateArrayVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a directory aggregate array")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(item) = seq.next_element::<Value>()? {
            let item = parse_directory_aggregate_value(item).map_err(de::Error::custom)?;
            if let Err(limit_error) = self.builder.push_aggregate(item) {
                self.builder.limit_error = Some(limit_error);
                return Err(de::Error::custom("row resource limit exceeded"));
            }
        }
        Ok(())
    }
}

fn parse_scanned_entry_value(value: Value) -> Result<ScannedEntry, serde_json::Error> {
    serde_json::from_value(decamelize_json_keys(value))
}

fn parse_directory_aggregate_value(value: Value) -> Result<DirectoryAggregate, serde_json::Error> {
    serde_json::from_value(decamelize_json_keys(value))
}

fn decamelize_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (to_snake_case(&key), decamelize_json_keys(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(decamelize_json_keys).collect()),
        other => other,
    }
}

fn to_snake_case(input: &str) -> String {
    let mut result = String::with_capacity(input.len() + 4);
    for (index, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                result.push('_');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}

impl VirtualRow {
    fn from_root(root: &ScannedEntry) -> Self {
        Self {
            key: format!("root:{}", root.display_path),
            kind: RowKind::Root,
            primary: root.display_path.clone(),
            secondary: row_kind_label(RowKind::Root).to_string(),
            status: coverage_label(&root.coverage.state).to_string(),
            amount: byte_value_label(&root.logical_bytes),
        }
    }

    fn from_entry(entry: &ScannedEntry) -> Self {
        Self {
            key: format!("entry:{}", entry.display_path),
            kind: RowKind::Entry,
            primary: entry.display_path.clone(),
            secondary: object_type_label(entry.object_type.clone()).to_string(),
            status: coverage_label(&entry.coverage.state).to_string(),
            amount: byte_value_label(&entry.reclaimable_estimate),
        }
    }

    fn from_aggregate(aggregate: &DirectoryAggregate) -> Self {
        Self {
            key: format!(
                "aggregate:{}:{}",
                aggregate.directory_identity, aggregate.revision
            ),
            kind: RowKind::Aggregate,
            primary: aggregate.directory_identity.clone(),
            secondary: arithmetic_label(aggregate.arithmetic_state.clone()).to_string(),
            status: coverage_label(&aggregate.coverage.state).to_string(),
            amount: byte_value_label(&aggregate.potentially_reclaimable_bytes),
        }
    }
}

fn row_kind_label(kind: RowKind) -> &'static str {
    match kind {
        RowKind::Root => "root",
        RowKind::Entry => "entry",
        RowKind::Aggregate => "aggregate",
    }
}

fn object_type_label(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::File => "file",
        ObjectType::Directory => "directory",
        ObjectType::Symlink => "symlink",
        ObjectType::ReparsePoint => "reparse",
        ObjectType::Other => "other",
    }
}

fn arithmetic_label(state: ArithmeticState) -> &'static str {
    match state {
        ArithmeticState::Exact => "exact",
        ArithmeticState::LowerBound => "lower_bound",
        ArithmeticState::Overflowed => "overflowed",
        ArithmeticState::Unknown => "unknown",
    }
}

fn coverage_label(state: &CoverageState) -> &'static str {
    match state {
        CoverageState::Complete => "complete",
        CoverageState::Incomplete => "incomplete",
        CoverageState::DetailsLost => "details_lost",
    }
}

fn byte_value_label(value: &sweepx_model::ByteValue) -> String {
    match value {
        sweepx_model::EvidenceValue::Known { value } => value.to_string(),
        sweepx_model::EvidenceValue::LowerBound { value, .. } => format!(">= {value}"),
        sweepx_model::EvidenceValue::Unknown { .. } => "unknown".to_string(),
        sweepx_model::EvidenceValue::Unsupported { .. } => "unsupported".to_string(),
        sweepx_model::EvidenceValue::NotChecked { .. } => "not_checked".to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct Labels {
    catalog: Catalog,
}

impl Labels {
    pub fn new(locale: Locale) -> Self {
        Self {
            catalog: Catalog::new(locale),
        }
    }

    pub fn locale(&self) -> Locale {
        self.catalog.locale()
    }

    pub fn overview(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "概览".to_string(),
            Locale::EnUs => "Overview".to_string(),
        }
    }

    pub fn list(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "列表".to_string(),
            Locale::EnUs => "List".to_string(),
        }
    }

    pub fn explain(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "解释".to_string(),
            Locale::EnUs => "Explain".to_string(),
        }
    }

    pub fn row_kind(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "类型".to_string(),
            Locale::EnUs => "Kind".to_string(),
        }
    }

    pub fn path(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "路径".to_string(),
            Locale::EnUs => "Path".to_string(),
        }
    }

    pub fn detail(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "详情".to_string(),
            Locale::EnUs => "Detail".to_string(),
        }
    }

    pub fn amount(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "大小".to_string(),
            Locale::EnUs => "Amount".to_string(),
        }
    }

    pub fn status(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "状态".to_string(),
            Locale::EnUs => "Status".to_string(),
        }
    }

    pub fn summary(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "摘要".to_string(),
            Locale::EnUs => "Summary".to_string(),
        }
    }

    pub fn placeholder(&self) -> String {
        self.catalog.render(
            MessageKey::SafetyReadOnlyNotice,
            &MessageArgs {
                detail: "",
                ..MessageArgs::default()
            },
        )
    }

    pub fn page(&self, current: usize, total: usize) -> String {
        match self.locale() {
            Locale::ZhCn => format!("第 {} / {} 页", current + 1, total),
            Locale::EnUs => format!("Page {} / {}", current + 1, total),
        }
    }

    pub fn read_only(&self) -> String {
        match self.locale() {
            Locale::ZhCn => "只读".to_string(),
            Locale::EnUs => "Read-only".to_string(),
        }
    }
}

pub fn render(frame: &mut Frame<'_>, area: Rect, state: &TuiState, view: &ViewModel) {
    let labels = Labels::new(view.locale());
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let tabs = Tabs::new(
        Pane::ALL
            .iter()
            .map(|pane| match pane {
                Pane::Overview => Line::from(labels.overview()),
                Pane::List => Line::from(labels.list()),
                Pane::Explain => Line::from(labels.explain()),
            })
            .collect::<Vec<_>>(),
    )
    .select(match state.pane() {
        Pane::Overview => 0,
        Pane::List => 1,
        Pane::Explain => 2,
    })
    .block(Block::default().borders(Borders::ALL).title(view.title()))
    .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, layout[0]);

    match state.pane() {
        Pane::Overview => render_overview(frame, layout[1], view, &labels),
        Pane::List => render_list(frame, layout[1], state, view, &labels),
        Pane::Explain => render_explain(frame, layout[1], view, &labels),
    }

    let page = labels.page(view.page_window().page_index, view.page_count());
    let footer = Paragraph::new(format!(
        "{} | {} | rows {} | retained {}",
        labels.read_only(),
        page,
        view.row_count(),
        view.retained_row_count()
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(labels.summary()),
    );
    frame.render_widget(footer, layout[2]);
}

fn render_overview(frame: &mut Frame<'_>, area: Rect, view: &ViewModel, labels: &Labels) {
    let lines = vec![
        Line::from(format!(
            "{}: {}",
            labels.status(),
            output_status_label(view.status())
        )),
        Line::from(format!("scanId: {}", view.scan_id().unwrap_or("-"))),
        Line::from(format!("roots: {}", view.root_count())),
        Line::from(format!("entries: {}", view.entry_count())),
        Line::from(format!("aggregates: {}", view.aggregate_count())),
        Line::from(labels.placeholder()),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(labels.overview()),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_list(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &TuiState,
    view: &ViewModel,
    labels: &Labels,
) {
    let cursor = view.validate_cursor(state.cursor().clone()).cursor;
    let rows = view.page_rows();

    let header = Row::new(vec![
        TableCell::from(labels.path()),
        TableCell::from(labels.row_kind()),
        TableCell::from(labels.status()),
        TableCell::from(labels.amount()),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let table_rows = rows.iter().enumerate().map(|(index, row)| {
        let style = if index == cursor.row_index {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        Row::new(vec![
            TableCell::from(row.primary.clone()),
            TableCell::from(row.secondary.clone()),
            TableCell::from(row.status.clone()),
            TableCell::from(row.amount.clone()),
        ])
        .style(style)
    });

    let table = Table::new(
        table_rows,
        [
            Constraint::Percentage(48),
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(labels.list()));
    frame.render_widget(table, area);
}

fn render_explain(frame: &mut Frame<'_>, area: Rect, view: &ViewModel, labels: &Labels) {
    let lines = vec![
        Line::from(Span::raw(labels.placeholder())),
        Line::from(Span::raw(match labels.locale() {
            Locale::ZhCn => "无计划、审批或执行动作。",
            Locale::EnUs => "No plan, approval, or execute actions.",
        })),
        Line::from(Span::raw(format!("revision: {}", view.revision()))),
    ];

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(labels.explain()),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn output_status_label(status: OutputStatus) -> &'static str {
    match status {
        OutputStatus::Ok => "ok",
        OutputStatus::Partial => "partial",
        OutputStatus::Blocked => "blocked",
        OutputStatus::AuthorizationRequired => "authorization_required",
        OutputStatus::Stale => "stale",
        OutputStatus::Failed => "failed",
        OutputStatus::NeedsReconciliation => "needs_reconciliation",
        OutputStatus::Cancelled => "cancelled",
        OutputStatus::Unsupported => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;
    use sweepx_i18n::Locale;
    use sweepx_model::{Coverage, DecimalU128, FieldProvenance, NativeName, ReasonCode, ScanId};

    fn coverage() -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: vec![],
            details_lost: false,
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-26T00:00:00Z".to_string(),
                method: sweepx_model::MethodId::MetadataNoFollow,
            },
        }
    }

    fn entry(path: String) -> ScannedEntry {
        ScannedEntry {
            scan_id: ScanId::new("scan-1"),
            identity: None,
            display_path: path,
            native_basename: NativeName::unix(b"demo".to_vec()),
            object_type: ObjectType::File,
            logical_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            allocated_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            reclaimable_estimate: sweepx_model::EvidenceValue::LowerBound {
                value: DecimalU128::new(1),
                reason: ReasonCode::IncompleteStreamCoverage,
            },
            metadata_fingerprint: "meta".to_string(),
            coverage: coverage(),
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-26T00:00:00Z".to_string(),
                method: sweepx_model::MethodId::MetadataNoFollow,
            },
        }
    }

    fn aggregate() -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: ScanId::new("scan-1"),
            directory_identity: "dir-1".to_string(),
            revision: DecimalU128::new(3),
            apparent_logical_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(3),
            },
            unique_logical_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(2),
            },
            filesystem_reported_allocated_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(2),
            },
            potentially_reclaimable_bytes: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(2),
            },
            direct_child_count: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(2),
            },
            recursive_entry_count: sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(4),
            },
            coverage: coverage(),
            arithmetic_state: ArithmeticState::Exact,
        }
    }

    fn output_json_with_entries(count: usize) -> String {
        let entries = (0..count)
            .map(|index| {
                camelize_json_keys(serde_json::to_value(entry(format!("/tmp/{index}"))).unwrap())
            })
            .collect::<Vec<_>>();
        let root = camelize_json_keys(serde_json::to_value(entry("/tmp".to_string())).unwrap());
        let aggregate = camelize_json_keys(serde_json::to_value(aggregate()).unwrap());

        serde_json::to_string(&json!({
            "schema": sweepx_protocol::OUTPUT_SCHEMA,
            "kind": "scan.result",
            "requestId": "req-1",
            "operationId": "op-1",
            "generatedAt": "2026-08-26T00:00:00Z",
            "status": "partial",
            "exitCode": 4,
            "compat": {
                "coreVersion": "0.1.0",
                "scannerSemanticsVersion": 1,
                "safetyPolicyVersion": 1,
                "platformAdapter": {
                    "id": "linux",
                    "version": "0.1.0"
                },
                "cleanerSetDigest": "sha256:test",
                "requiredFeatures": [],
                "extensions": []
            },
            "summary": {
                "scanId": "scan-1"
            },
            "data": {
                "scanId": "scan-1",
                "roots": [root],
                "entries": entries,
                "aggregates": [aggregate],
                "boundaries": []
            },
            "warnings": [],
            "errors": []
        }))
        .unwrap()
    }

    fn output_json_with_entries_snake_case(count: usize) -> String {
        let entries = (0..count)
            .map(|index| serde_json::to_value(entry(format!("/tmp/{index}"))).unwrap())
            .collect::<Vec<_>>();
        let root = serde_json::to_value(entry("/tmp".to_string())).unwrap();
        let aggregate = serde_json::to_value(aggregate()).unwrap();

        serde_json::to_string(&json!({
            "schema": sweepx_protocol::OUTPUT_SCHEMA,
            "kind": "scan.result",
            "requestId": "req-1",
            "operationId": "op-1",
            "generatedAt": "2026-08-26T00:00:00Z",
            "status": "partial",
            "exitCode": 4,
            "compat": {
                "coreVersion": "0.1.0",
                "scannerSemanticsVersion": 1,
                "safetyPolicyVersion": 1,
                "platformAdapter": {
                    "id": "linux",
                    "version": "0.1.0"
                },
                "cleanerSetDigest": "sha256:test",
                "requiredFeatures": [],
                "extensions": []
            },
            "summary": {
                "scan_id": "scan-1"
            },
            "data": {
                "scan_id": "scan-1",
                "roots": [root],
                "entries": entries,
                "aggregates": [aggregate],
                "boundaries": []
            },
            "warnings": [],
            "errors": []
        }))
        .unwrap()
    }

    #[test]
    fn paging_is_limited_to_five_hundred_rows_and_retains_only_one_page() {
        let json = output_json_with_entries(1200);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            1,
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(view.page_count(), 3);
        assert_eq!(view.row_count(), 1202);
        assert_eq!(view.retained_row_count(), 500);
        assert_eq!(view.page_rows().len(), 500);
        assert_eq!(view.loaded_page_index(), 1);
        assert_eq!(view.page_window().start, 500);
        assert_eq!(view.page_window().end, 1000);
    }

    #[test]
    fn far_requested_page_does_not_scale_retention_with_page_index() {
        let json = output_json_with_entries(99_998);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            100,
            LoadLimits {
                max_input_bytes: 64 * 1024 * 1024,
                max_total_rows: DEFAULT_MAX_TOTAL_ROWS,
            },
        )
        .unwrap();
        assert_eq!(view.row_count(), 100_000);
        assert_eq!(view.loaded_page_index(), 100);
        assert_eq!(view.retained_row_count(), 500);
        assert!(view.retained_row_count() <= 500);
        assert_eq!(view.page_window().start, 50_000);
        assert_eq!(view.page_window().end, 50_500);
    }

    #[test]
    fn huge_requested_page_is_clamped_to_last_nonempty_page() {
        let json = output_json_with_entries(10);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            9999,
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(view.page_count(), 1);
        assert_eq!(view.loaded_page_index(), 0);
        assert_eq!(view.retained_row_count(), 12);
        assert_eq!(view.page_window().page_index, 0);
        assert_eq!(view.page_window().start, 0);
        assert_eq!(view.page_window().end, 12);
    }

    #[test]
    fn huge_requested_page_on_empty_input_stays_on_page_zero() {
        let json = output_json_with_entries(0);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            9999,
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(view.page_count(), 1);
        assert_eq!(view.loaded_page_index(), 0);
        assert_eq!(view.retained_row_count(), 2);
        assert_eq!(view.page_window().page_index, 0);
        assert_eq!(view.page_window().start, 0);
        assert_eq!(view.page_window().end, 2);
    }

    #[test]
    fn recursively_camel_case_cli_payload_is_accepted() {
        let json = output_json_with_entries(3);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(view.scan_id(), Some("scan-1"));
        assert_eq!(view.root_count(), 1);
        assert_eq!(view.entry_count(), 3);
        assert_eq!(view.aggregate_count(), 1);
        assert_eq!(view.row_count(), 5);
        assert_eq!(view.retained_row_count(), 5);
    }

    #[test]
    fn snake_case_payload_remains_accepted() {
        let json = output_json_with_entries_snake_case(2);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(view.scan_id(), Some("scan-1"));
        assert_eq!(view.root_count(), 1);
        assert_eq!(view.entry_count(), 2);
        assert_eq!(view.aggregate_count(), 1);
        assert_eq!(view.row_count(), 4);
    }

    #[test]
    fn cursor_resets_when_revision_changes() {
        let json = output_json_with_entries(10);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits::default(),
        )
        .unwrap()
        .with_revision(4);
        let validation = view.validate_cursor(PageCursor {
            page_index: 1,
            row_index: 4,
            revision: 1,
        });
        assert_eq!(
            validation.status,
            CursorStatus::ResetForRevisionChange {
                previous_revision: 1,
                new_revision: 4,
            }
        );
        assert_eq!(validation.cursor.page_index, 0);
        assert_eq!(validation.cursor.row_index, 0);
        assert_eq!(validation.cursor.revision, 4);
    }

    #[test]
    fn cursor_is_clamped_when_page_is_out_of_bounds() {
        let json = output_json_with_entries(10);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits::default(),
        )
        .unwrap();
        let validation = view.validate_cursor(PageCursor {
            page_index: 9,
            row_index: 8,
            revision: 0,
        });
        assert_eq!(
            validation.status,
            CursorStatus::ResetForBounds {
                requested_page: 9,
                max_page: 0,
            }
        );
        assert_eq!(validation.cursor.page_index, 0);
        assert_eq!(validation.cursor.row_index, 0);
    }

    #[test]
    fn state_transitions_are_deterministic_and_read_only() {
        let json = output_json_with_entries(10);
        let view = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits::default(),
        )
        .unwrap();
        let initial = TuiState::default();
        let next = initial.reduce(ReadOnlyAction::Navigate(NavigationAction::NextPane), &view);
        let again = initial.reduce(ReadOnlyAction::Navigate(NavigationAction::NextPane), &view);
        assert_eq!(next, again);
        assert_eq!(next.pane(), Pane::List);
    }

    #[test]
    fn localized_labels_render_for_both_locales() {
        let zh = Labels::new(Locale::ZhCn);
        let en = Labels::new(Locale::EnUs);
        assert_eq!(zh.overview(), "概览");
        assert_eq!(zh.list(), "列表");
        assert_eq!(zh.explain(), "解释");
        assert_eq!(en.overview(), "Overview");
        assert_eq!(en.list(), "List");
        assert_eq!(en.explain(), "Explain");
        assert!(zh.placeholder().contains("不会修改"));
        assert!(en.placeholder().contains("does not modify"));
    }

    #[test]
    fn read_only_action_enum_has_no_destructive_variant() {
        assert!(!ReadOnlyAction::Navigate(NavigationAction::NextPane).is_destructive());
    }

    #[test]
    fn oversized_input_is_rejected_with_resource_limit() {
        let json = output_json_with_entries(10);
        let error = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits {
                max_input_bytes: 128,
                max_total_rows: DEFAULT_MAX_TOTAL_ROWS,
            },
        )
        .unwrap_err();

        match error {
            ViewModelError::ResourceLimit {
                kind: ResourceLimitKind::InputBytes,
                limit,
                observed,
            } => {
                assert_eq!(limit, 128);
                assert_eq!(observed, 129);
            }
            other => panic!("expected input byte limit error, got {other:?}"),
        }
    }

    #[test]
    fn total_row_cap_is_rejected_with_resource_limit() {
        let json = output_json_with_entries(10);
        let error = ViewModel::from_reader(
            Cursor::new(json.as_bytes()),
            Locale::EnUs,
            0,
            LoadLimits {
                max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
                max_total_rows: 8,
            },
        )
        .unwrap_err();

        match error {
            ViewModelError::ResourceLimit {
                kind: ResourceLimitKind::TotalRows,
                limit,
                observed,
            } => {
                assert_eq!(limit, 8);
                assert_eq!(observed, 9);
            }
            other => panic!("expected total row limit error, got {other:?}"),
        }
    }

    fn camelize_json_keys(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| (to_camel_case(&key), camelize_json_keys(value)))
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.into_iter().map(camelize_json_keys).collect())
            }
            other => other,
        }
    }

    fn to_camel_case(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut uppercase_next = false;
        for ch in input.chars() {
            if ch == '_' {
                uppercase_next = true;
                continue;
            }
            if uppercase_next {
                result.extend(ch.to_uppercase());
                uppercase_next = false;
            } else {
                result.push(ch);
            }
        }
        result
    }
}
