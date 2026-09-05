use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, OnceLock};
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Cell as TableCell, Paragraph, Row, Table, Wrap};
use ratatui::{Frame, Terminal};
use sweepx_i18n::Locale;
use sweepx_model::{
    ArithmeticState, Coverage, CoverageState, DecimalU128, DirectoryAggregate, FieldProvenance,
    HumanSizeUnit, NativeLocatorEvidence, NativeName, ObjectType, ScanEntryId, ScanEntryIdError,
    ScanId, ScanObjectIdentity, ScanSort, ScannedEntry,
};
use sweepx_protocol::OutputStatus;
use thiserror::Error;
use unicode_width::UnicodeWidthStr;

use crate::{
    MAX_PAGE_ROWS, byte_value_label_with_unit, coverage_label, object_type_label,
    output_status_label,
};

pub const BROWSER_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const DETAIL_RESCAN_QUERY_DEADLINE: Duration = Duration::from_secs(30);
pub const MAX_DETAIL_RESCAN_WORKERS: usize = 32;
pub const DEFAULT_MAX_BROWSER_ENTRIES: usize = 16_384;
pub const DEFAULT_MAX_BROWSER_INDEX_BYTES: usize = 48 * 1024 * 1024;

static DETAIL_RESCAN_WORKER_LIMITER: OnceLock<Arc<DetailRescanWorkerLimiter>> = OnceLock::new();

/// Why an entered directory needs a bounded, prioritized detail rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailRescanReason {
    Incomplete,
    Evicted,
    /// Fast first phase: enumerate only direct children so navigation becomes available quickly.
    ProgressiveListing,
    /// Background second phase: aggregate descendants without retaining them as browser rows.
    ProgressiveAggregate,
}

/// Correlation data which a detail result must echo exactly.
///
/// Every issued `revision` is strictly greater than `base_revision`, including
/// after a failed attempt. Scan entry ids remain scoped to `source_scan_id`;
/// they are not treated as cross-scan identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRescanBinding {
    pub source_scan_id: ScanId,
    pub source_root_identity: ScanObjectIdentity,
    pub source_directory_identity: ScanObjectIdentity,
    pub base_revision: DecimalU128,
    pub revision: DecimalU128,
}

/// A bounded request for a scanner-owned detail enumeration.
///
/// The TUI never opens or traverses `directory_locator`. A caller-provided
/// scanner adapter must reopen it without following links, revalidate every
/// identity component, and honor `max_rows`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRescanRequest {
    pub binding: DetailRescanBinding,
    pub directory_locator: NativeLocatorEvidence,
    pub reason: DetailRescanReason,
    pub max_rows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailRescanFailure {
    IdentityUnavailable,
    IdentityMismatch,
    MountChanged,
    SymlinkOrReparse,
    Cancelled,
    ResourceLimit,
    InvalidResult,
    RevisionExhausted,
    TimedOut,
    Unavailable,
}

impl DetailRescanFailure {
    const fn label(self) -> &'static str {
        match self {
            Self::IdentityUnavailable => "identity_unavailable",
            Self::IdentityMismatch => "identity_mismatch",
            Self::MountChanged => "mount_changed",
            Self::SymlinkOrReparse => "symlink_or_reparse",
            Self::Cancelled => "cancelled",
            Self::ResourceLimit => "resource_limit",
            Self::InvalidResult => "invalid_result",
            Self::RevisionExhausted => "revision_exhausted",
            Self::TimedOut => "timed_out",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Scanner-owned output for one detail request.
///
/// Refreshed rows must be the complete retained direct-child set for this
/// bounded result. The browser rejects, rather than truncates, an oversized or
/// internally inconsistent result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshedDetail {
    pub binding: DetailRescanBinding,
    pub observed_root: ScannedEntry,
    pub observed_directory: ScannedEntry,
    pub rows: Vec<ScannedEntry>,
    pub aggregate: DirectoryAggregate,
}

/// One validated lower-bound update for the active progressive aggregate scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRescanProgress {
    pub binding: DetailRescanBinding,
    pub row: ScannedEntry,
    pub aggregate: DirectoryAggregate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailRescanResult {
    Refreshed(Box<RefreshedDetail>),
    Failed {
        binding: Box<DetailRescanBinding>,
        failure: DetailRescanFailure,
    },
}

/// Executes bounded detail queries outside the terminal event thread.
///
/// Implementations should finish a query promptly after
/// `cancel_detail_rescan` is called. A non-cooperative provider is quarantined
/// after `DETAIL_RESCAN_QUERY_DEADLINE` and retains one process-wide worker
/// permit until it really returns; capacity exhaustion rejects a new browser
/// instead of creating unbounded detached threads.
pub trait DetailRescanProvider: Send + Sync + 'static {
    /// Starts a new single-flight query generation before it is queued to the
    /// background worker. Providers can use this hook to replace cancellation
    /// state left by the preceding query without losing a cancellation that
    /// arrives after the new query has been queued but before the worker runs.
    fn prepare_detail_rescan(&self) {}

    fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult;

    /// Installs a non-blocking sink for advisory lower-bound progress snapshots.
    ///
    /// Providers which cannot stream progress may ignore this hook. The reducer validates every
    /// update against its active binding before exposing it to the terminal model.
    fn set_progress_sink(&self, _sink: Option<SyncSender<DetailRescanProgress>>) {}

    fn cancel_detail_rescan(&self) {}
}

impl<F> DetailRescanProvider for F
where
    F: Fn(&DetailRescanRequest) -> DetailRescanResult + Send + Sync + 'static,
{
    fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult {
        self(request)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableDetailRescanProvider;

impl DetailRescanProvider for UnavailableDetailRescanProvider {
    fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult {
        DetailRescanResult::Failed {
            binding: Box::new(request.binding.clone()),
            failure: DetailRescanFailure::Unavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailRescanState {
    Snapshot {
        revision: DecimalU128,
    },
    Refreshed {
        revision: DecimalU128,
    },
    Pending {
        revision: DecimalU128,
    },
    Stale {
        revision: DecimalU128,
        failure: DetailRescanFailure,
    },
}

impl DetailRescanState {
    pub const fn revision(&self) -> DecimalU128 {
        match self {
            Self::Snapshot { revision }
            | Self::Refreshed { revision }
            | Self::Pending { revision }
            | Self::Stale { revision, .. } => *revision,
        }
    }

    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// How long one marquee step lasts.
///
/// The event loop already wakes every `BROWSER_EVENT_POLL_INTERVAL` (100 ms) and repaints
/// unconditionally, so scrolling needs no timer of its own - only a phase derived from elapsed
/// time. Three ticks per cell is slow enough to read a path while it moves.
const MARQUEE_TICK: Duration = Duration::from_millis(300);

/// Cells of blank run between the end of the text and its repetition.
///
/// Without a gap the tail runs straight into the head and a path looks like it contains its own
/// prefix, which is actively misleading for a path.
const MARQUEE_GAP: usize = 4;

/// The display width of `value` in terminal cells.
///
/// Not the character count: CJK path components occupy two cells each, so a byte- or char-based
/// measure would under-report the width of exactly the paths most likely to overflow.
fn text_cells(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

/// Whether `value` cannot be shown in full within `width` cells.
fn overflows(value: &str, width: usize) -> bool {
    width > 0 && text_cells(value) > width
}

/// Takes exactly `width` cells starting at cell offset `skip`, never splitting a wide character.
///
/// A double-width character straddling an edge cannot be halved: terminals render a split wide
/// character as a stray blank or a replacement glyph, which shifts every following column by one
/// cell. So a straddling character contributes blanks for the cells it still owes, and the result is
/// padded to `width` when the source runs out.
///
/// Both of those matter beyond tidiness. Dropping a straddling character outright made an
/// odd-numbered offset render identically to the even one before it, which is why CJK paths stuttered
/// every second scroll step. Returning a short window let the columns to the right shift as the text
/// moved.
fn cell_window(value: &str, skip: usize, width: usize) -> String {
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut used = 0usize;
    for character in value.chars() {
        if used >= width {
            break;
        }
        let cells = char_cells(character);
        if cursor + cells <= skip {
            cursor += cells;
            continue;
        }
        if cursor < skip {
            // Partly scrolled off the left edge: keep the cells that remain visible as blanks.
            let visible = (cursor + cells).saturating_sub(skip).min(width - used);
            out.push_str(&" ".repeat(visible));
            used += visible;
            cursor += cells;
            continue;
        }
        if used + cells > width {
            // Does not fit the right edge; blanks keep the window exactly `width` cells wide.
            out.push_str(&" ".repeat(width - used));
            used = width;
            break;
        }
        out.push(character);
        used += cells;
        cursor += cells;
    }
    if used < width {
        out.push_str(&" ".repeat(width - used));
    }
    out
}

/// The display width of one character in terminal cells, treating unknown control cases as one cell.
fn char_cells(character: char) -> usize {
    UnicodeWidthStr::width(character.to_string().as_str()).max(1)
}

/// The visible slice of a row label for one frame, always exactly `width` cells wide.
///
/// Rows that fit are returned unchanged. Overflowing rows are scrolled: the text advances by one
/// cell per phase, runs off the left edge, and reappears after a short gap.
///
/// Two properties are load-bearing and were both wrong in the first version:
///
/// * The result is padded to exactly `width` cells. A double-width character that does not fit the
///   last cell has to be dropped, which leaves the window one cell short; letting that through makes
///   the columns to the right jitter left and right as the text scrolls.
/// * The phase advances in cells, not in characters. Skipping a partially-scrolled wide character
///   made two consecutive phases render identically, so CJK paths visibly stuttered.
fn marquee_window(value: &str, width: usize, phase: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if !overflows(value, width) {
        return value.to_string();
    }
    let cells = text_cells(value);
    let span = cells + MARQUEE_GAP;
    let skip = phase % span.max(1);

    // Render the text, then the gap, then the text again, and read one window out of that. Building
    // the strip explicitly is what keeps the wrap-around seam correct; computing it from offsets is
    // where the earlier version went wrong.
    let mut strip = String::with_capacity(value.len() * 2 + MARQUEE_GAP);
    strip.push_str(value);
    strip.push_str(&" ".repeat(MARQUEE_GAP));
    strip.push_str(value);

    // cell_window guarantees the full width, including the blanks a straddling wide character owes.
    cell_window(&strip, skip, width)
}

/// Truncates to `width` cells, marking the elision with a trailing ellipsis.
fn truncate_with_ellipsis(value: &str, width: usize) -> String {
    if !overflows(value, width) {
        return value.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    // Trim the padding cell_window guarantees; the ellipsis occupies the final cell instead.
    format!(
        "{}…",
        cell_window(value, 0, width.saturating_sub(1)).trim_end()
    )
}
/// The fewest trailing path components that still tell every root apart.
///
/// A fixed component count cannot work: `…\Default\IndexedDB` and
/// `…\Default\Service Worker\CacheStorage` sit at different depths, so taking the last four
/// components keeps the browser name for one and drops it for the other - rendering Edge and Edge
/// Dev CacheStorage as the very same string. In a view that can delete data, two rows that read
/// identically are not a cosmetic problem.
///
/// So the count is chosen from the paths actually on screen: grow it until no two labels collide, or
/// until the paths are exhausted (identical paths cannot be separated, and duplicates are not
/// produced by root discovery anyway).
const MIN_ROOT_LABEL_COMPONENTS: usize = 2;

fn path_components(path: &str) -> Option<(char, Vec<&str>)> {
    let separator = separator_for(path)?;
    Some((
        separator,
        path.split(separator)
            .filter(|part| !part.is_empty())
            .collect(),
    ))
}

/// Renders one path as its trailing `components` segments, marking any elision.
fn root_label_with_components(path: &str, components: usize) -> String {
    let cleaned = hierarchy_key(path);
    let Some((separator, parts)) = path_components(&cleaned) else {
        return cleaned;
    };
    if parts.len() <= components {
        return cleaned;
    }
    let tail = parts[parts.len() - components..].join(&separator.to_string());
    format!("…{separator}{tail}")
}

/// Chooses the shared component count that keeps every root label distinct.
fn root_label_components(paths: &[String]) -> usize {
    let deepest = paths
        .iter()
        .filter_map(|path| path_components(&hierarchy_key(path)).map(|(_, parts)| parts.len()))
        .max()
        .unwrap_or(MIN_ROOT_LABEL_COMPONENTS);
    for components in MIN_ROOT_LABEL_COMPONENTS..=deepest.max(MIN_ROOT_LABEL_COMPONENTS) {
        let mut rendered: Vec<String> = paths
            .iter()
            .map(|path| root_label_with_components(path, components))
            .collect();
        rendered.sort();
        let before = rendered.len();
        rendered.dedup();
        if rendered.len() == before {
            return components;
        }
    }
    deepest.max(MIN_ROOT_LABEL_COMPONENTS)
}

/// One row in the in-memory scan snapshot browser.
///
/// Aggregate evidence is attached to its matching directory row. Aggregates are
/// deliberately never represented as independent browser rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserRow {
    entry: ScannedEntry,
    aggregate: Option<DirectoryAggregate>,
    detail_rescan_state: DetailRescanState,
    root: bool,
    label: String,
}

impl BrowserRow {
    fn from_owned(
        entry: ScannedEntry,
        aggregate: Option<DirectoryAggregate>,
        detail_rescan_state: DetailRescanState,
        root: bool,
    ) -> Self {
        // Root rows are relabelled together once the level is assembled, because how short a label
        // can safely be depends on the other roots beside it. A single root keeps its full path.
        let label = if root {
            sanitize_terminal_text(&entry.display_path)
        } else {
            sanitize_terminal_text(&display_basename(&entry.display_path))
        };
        Self {
            entry,
            aggregate,
            detail_rescan_state,
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

    pub const fn detail_rescan_state(&self) -> &DetailRescanState {
        &self.detail_rescan_state
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

    fn effective_coverage(&self) -> &Coverage {
        self.aggregate
            .as_ref()
            .map(|aggregate| &aggregate.coverage)
            .unwrap_or(&self.entry.coverage)
    }

    fn detail_rescan_reason(&self) -> Option<DetailRescanReason> {
        detail_rescan_reason(self.can_enter(), self.effective_coverage())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserLoadLimits {
    pub max_level_rows: usize,
    pub max_entries: usize,
    pub max_index_bytes: usize,
}

impl Default for BrowserLoadLimits {
    fn default() -> Self {
        Self {
            max_level_rows: MAX_PAGE_ROWS.max(1),
            max_entries: DEFAULT_MAX_BROWSER_ENTRIES,
            max_index_bytes: DEFAULT_MAX_BROWSER_INDEX_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserResourceLimitKind {
    Entries,
    IndexBytes,
}

impl std::fmt::Display for BrowserResourceLimitKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entries => formatter.write_str("entries"),
            Self::IndexBytes => formatter.write_str("index_bytes"),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BrowserModelError {
    #[error("browser resource limit exceeded for {kind}: limit={limit}, observed={observed}")]
    ResourceLimit {
        kind: BrowserResourceLimitKind,
        limit: usize,
        observed: usize,
    },
    #[error("invalid scan identity: {0}")]
    InvalidIdentity(#[from] ScanEntryIdError),
    #[error("live browser requires validated entry identity for {display_path}")]
    MissingIdentity { display_path: String },
    #[error("duplicate scan entry id in browser snapshot: {entry_id}")]
    DuplicateEntryId { entry_id: String },
    #[error("root entry must not declare a parent: {entry_id}")]
    RootEntryMustNotHaveParent { entry_id: String },
    #[error(
        "root entry must reference itself as scan root: entry_id={entry_id}, root_id={root_id}"
    )]
    RootEntryMustReferenceSelf { entry_id: String, root_id: String },
    #[error("non-root entry must declare a parent: {entry_id}")]
    NonRootEntryMustHaveParent { entry_id: String },
    #[error(
        "non-root entry must not reference itself as scan root: entry_id={entry_id}, root_id={root_id}"
    )]
    NonRootEntryMustNotReferenceSelfAsRoot { entry_id: String, root_id: String },
    #[error("entry references missing scan root: entry_id={entry_id}, root_id={root_id}")]
    MissingRoot { entry_id: String, root_id: String },
    #[error("entry references missing parent: entry_id={entry_id}, parent_id={parent_id}")]
    MissingParent { entry_id: String, parent_id: String },
    #[error("entry parent is not a directory: entry_id={entry_id}, parent_id={parent_id}")]
    ParentNotDirectory { entry_id: String, parent_id: String },
    #[error(
        "entry parent belongs to a different root: entry_id={entry_id}, parent_id={parent_id}, root_id={root_id}, parent_root_id={parent_root_id}"
    )]
    ParentRootMismatch {
        entry_id: String,
        parent_id: String,
        root_id: String,
        parent_root_id: String,
    },
    #[error("entry is unreachable from its declared root: {entry_id}")]
    UnreachableEntry { entry_id: String },
    #[error("duplicate aggregate for scan entry id: {entry_id}")]
    DuplicateAggregate { entry_id: String },
    #[error("aggregate target missing from browser snapshot: {entry_id}")]
    AggregateTargetMissing { entry_id: String },
    #[error("aggregate target is not a directory: {entry_id}")]
    AggregateTargetNotDirectory { entry_id: String },
    #[error(
        "aggregate scan id does not match target entry scan id: entry_id={entry_id}, aggregate_scan_id={aggregate_scan_id}, entry_scan_id={entry_scan_id}"
    )]
    AggregateScanMismatch {
        entry_id: String,
        aggregate_scan_id: String,
        entry_scan_id: String,
    },
    #[error(
        "browser snapshot mixes scan ids: expected={expected_scan_id}, observed={observed_scan_id}"
    )]
    SnapshotScanMismatch {
        expected_scan_id: String,
        observed_scan_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserNode {
    entry: ScannedEntry,
    aggregate: Option<DirectoryAggregate>,
    detail_rescan_state: DetailRescanState,
    root: bool,
}

impl BrowserNode {
    fn to_row(&self) -> BrowserRow {
        BrowserRow::from_owned(
            self.entry.clone(),
            self.aggregate.clone(),
            self.detail_rescan_state.clone(),
            self.root,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingNode {
    entry: ScannedEntry,
    entry_id: ScanEntryId,
    root_id: ScanEntryId,
    parent_id: Option<ScanEntryId>,
    root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserLevel {
    directory_index: usize,
    directory: String,
    parent_selection: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct LoadedLevel {
    total_rows: usize,
    page_start: usize,
    row_indices: Vec<usize>,
    rows: Vec<BrowserRow>,
}

/// A read-only hierarchy built entirely from one completed scan snapshot.
///
/// It never enumerates or stats the filesystem. The initial level is a
/// synthetic virtual-roots screen; entered levels expose only direct children
/// already linked by validated scan identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserModel {
    locale: Locale,
    status: OutputStatus,
    scan_id: Option<String>,
    limits: BrowserLoadLimits,
    nodes: Vec<BrowserNode>,
    roots: Vec<usize>,
    children_by_index: Vec<Vec<usize>>,
    levels: Vec<BrowserLevel>,
    selected: usize,
    loaded_level: LoadedLevel,
    size_unit: HumanSizeUnit,
    sort: ScanSort,
    progressive_navigation: bool,
    /// Whether the selected row's full path is currently pinned open.
    ///
    /// Marquee phase is deliberately *not* stored here: the model derives `PartialEq`/`Eq`, and a
    /// clock reading inside it would make two otherwise identical models compare unequal. The phase
    /// is supplied to the renderer instead, which also keeps painting a pure function of its inputs.
    show_path_detail: bool,
}

impl BrowserModel {
    pub fn from_scan_parts(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: &[ScannedEntry],
        entries: &[ScannedEntry],
        aggregates: &[DirectoryAggregate],
    ) -> Result<BrowserModel, BrowserModelError> {
        Self::from_scan_parts_with_limits(
            locale,
            status,
            scan_id,
            roots,
            entries,
            aggregates,
            BrowserLoadLimits::default(),
        )
    }

    pub fn from_scan_parts_with_limits(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: &[ScannedEntry],
        entries: &[ScannedEntry],
        aggregates: &[DirectoryAggregate],
        limits: BrowserLoadLimits,
    ) -> Result<BrowserModel, BrowserModelError> {
        preflight_limits(roots, entries, aggregates, limits)?;
        Self::from_owned_scan_parts_with_limits(
            locale,
            status,
            scan_id,
            roots.to_vec(),
            entries.to_vec(),
            aggregates.to_vec(),
            limits,
        )
    }

    pub fn from_owned_scan_parts(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: Vec<ScannedEntry>,
        entries: Vec<ScannedEntry>,
        aggregates: Vec<DirectoryAggregate>,
    ) -> Result<BrowserModel, BrowserModelError> {
        Self::from_owned_scan_parts_with_limits(
            locale,
            status,
            scan_id,
            roots,
            entries,
            aggregates,
            BrowserLoadLimits::default(),
        )
    }

    /// Creates the first progressive browser frame from roots only. The root rows preserve
    /// executable locator evidence, but their aggregates are intentionally incomplete until the
    /// user enters a root and the background detail provider computes its direct rows and total.
    pub fn from_progressive_roots(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        mut roots: Vec<ScannedEntry>,
        aggregates: Vec<DirectoryAggregate>,
        size_unit: HumanSizeUnit,
        sort: ScanSort,
    ) -> Result<BrowserModel, BrowserModelError> {
        for root in &mut roots {
            mark_coverage_details_lost(&mut root.coverage);
            root.logical_bytes = sweepx_model::EvidenceValue::NotChecked {
                reason: sweepx_model::ReasonCode::NotRevalidated,
            };
            root.allocated_bytes = sweepx_model::EvidenceValue::NotChecked {
                reason: sweepx_model::ReasonCode::NotRevalidated,
            };
            root.reclaimable_estimate = sweepx_model::EvidenceValue::NotChecked {
                reason: sweepx_model::ReasonCode::NotRevalidated,
            };
        }
        let mut model =
            Self::from_owned_scan_parts(locale, status, scan_id, roots, Vec::new(), aggregates)?;
        for index in &model.roots {
            model.nodes[*index].detail_rescan_state = DetailRescanState::Snapshot {
                revision: DecimalU128::ZERO,
            };
        }
        model.size_unit = size_unit;
        model.sort = sort;
        model.progressive_navigation = true;
        model.sort_rows();
        model.reload_loaded_level();
        Ok(model)
    }

    pub fn from_owned_scan_parts_with_limits(
        locale: Locale,
        status: OutputStatus,
        scan_id: Option<String>,
        roots: Vec<ScannedEntry>,
        entries: Vec<ScannedEntry>,
        aggregates: Vec<DirectoryAggregate>,
        limits: BrowserLoadLimits,
    ) -> Result<BrowserModel, BrowserModelError> {
        preflight_limits(&roots, &entries, &aggregates, limits)?;
        enforce_snapshot_scan_ids(scan_id.as_deref(), &roots, &entries, &aggregates)?;

        let mut pending_nodes = Vec::with_capacity(roots.len() + entries.len());
        let mut id_to_index = HashMap::with_capacity(roots.len() + entries.len());

        for entry in roots {
            let identity = required_identity(&entry)?.clone();
            if identity.parent_id.is_some() {
                return Err(BrowserModelError::RootEntryMustNotHaveParent {
                    entry_id: identity.entry_id.to_string(),
                });
            }
            if identity.entry_id != identity.scan_root_id {
                return Err(BrowserModelError::RootEntryMustReferenceSelf {
                    entry_id: identity.entry_id.to_string(),
                    root_id: identity.scan_root_id.to_string(),
                });
            }
            insert_pending_node(
                &mut pending_nodes,
                &mut id_to_index,
                PendingNode {
                    entry,
                    entry_id: identity.entry_id.clone(),
                    root_id: identity.scan_root_id.clone(),
                    parent_id: None,
                    root: true,
                },
            )?;
        }

        for entry in entries {
            let identity = required_identity(&entry)?.clone();
            let Some(parent_id) = identity.parent_id.clone() else {
                return Err(BrowserModelError::NonRootEntryMustHaveParent {
                    entry_id: identity.entry_id.to_string(),
                });
            };
            if identity.entry_id == identity.scan_root_id {
                return Err(BrowserModelError::NonRootEntryMustNotReferenceSelfAsRoot {
                    entry_id: identity.entry_id.to_string(),
                    root_id: identity.scan_root_id.to_string(),
                });
            }
            insert_pending_node(
                &mut pending_nodes,
                &mut id_to_index,
                PendingNode {
                    entry,
                    entry_id: identity.entry_id.clone(),
                    root_id: identity.scan_root_id.clone(),
                    parent_id: Some(parent_id),
                    root: false,
                },
            )?;
        }

        let mut children_by_index = vec![Vec::new(); pending_nodes.len()];
        let mut roots = Vec::new();
        for (index, node) in pending_nodes.iter().enumerate() {
            if node.root {
                roots.push(index);
                continue;
            }
            let root_index = id_to_index.get(&node.root_id).copied().ok_or_else(|| {
                BrowserModelError::MissingRoot {
                    entry_id: node.entry_id.to_string(),
                    root_id: node.root_id.to_string(),
                }
            })?;
            if !pending_nodes[root_index].root {
                return Err(BrowserModelError::MissingRoot {
                    entry_id: node.entry_id.to_string(),
                    root_id: node.root_id.to_string(),
                });
            }

            let parent_id = node.parent_id.as_ref().expect("validated child has parent");
            let parent_index = id_to_index.get(parent_id).copied().ok_or_else(|| {
                BrowserModelError::MissingParent {
                    entry_id: node.entry_id.to_string(),
                    parent_id: parent_id.to_string(),
                }
            })?;
            let parent = &pending_nodes[parent_index];
            if !matches!(parent.entry.object_type, ObjectType::Directory) {
                return Err(BrowserModelError::ParentNotDirectory {
                    entry_id: node.entry_id.to_string(),
                    parent_id: parent_id.to_string(),
                });
            }
            if parent.root_id != node.root_id {
                return Err(BrowserModelError::ParentRootMismatch {
                    entry_id: node.entry_id.to_string(),
                    parent_id: parent_id.to_string(),
                    root_id: node.root_id.to_string(),
                    parent_root_id: parent.root_id.to_string(),
                });
            }
            children_by_index[parent_index].push(index);
        }

        let mut aggregate_by_index = vec![None; pending_nodes.len()];
        for aggregate in aggregates {
            let entry_id = aggregate.scan_entry_id()?;
            let index = id_to_index.get(&entry_id).copied().ok_or_else(|| {
                BrowserModelError::AggregateTargetMissing {
                    entry_id: entry_id.to_string(),
                }
            })?;
            let node = &pending_nodes[index];
            if aggregate.scan_id != node.entry.scan_id {
                return Err(BrowserModelError::AggregateScanMismatch {
                    entry_id: entry_id.to_string(),
                    aggregate_scan_id: aggregate.scan_id.to_string(),
                    entry_scan_id: node.entry.scan_id.to_string(),
                });
            }
            if !matches!(node.entry.object_type, ObjectType::Directory) {
                return Err(BrowserModelError::AggregateTargetNotDirectory {
                    entry_id: entry_id.to_string(),
                });
            }
            if aggregate_by_index[index].is_some() {
                return Err(BrowserModelError::DuplicateAggregate {
                    entry_id: entry_id.to_string(),
                });
            }
            aggregate_by_index[index] = Some(aggregate);
        }

        roots.sort_by(|left, right| {
            browser_path_order(&pending_nodes[*left], &pending_nodes[*right])
        });
        for rows in &mut children_by_index {
            rows.sort_by(|left, right| {
                browser_path_order(&pending_nodes[*left], &pending_nodes[*right])
            });
        }

        let mut visited = vec![false; pending_nodes.len()];
        let mut stack = roots.clone();
        while let Some(index) = stack.pop() {
            if visited[index] {
                continue;
            }
            visited[index] = true;
            stack.extend(children_by_index[index].iter().copied());
        }
        for (index, visited_flag) in visited.iter().enumerate() {
            if !visited_flag {
                return Err(BrowserModelError::UnreachableEntry {
                    entry_id: pending_nodes[index].entry_id.to_string(),
                });
            }
        }

        let nodes = pending_nodes
            .into_iter()
            .zip(aggregate_by_index)
            .map(|(pending, aggregate)| {
                let revision = aggregate
                    .as_ref()
                    .map(|aggregate| aggregate.revision)
                    .unwrap_or(DecimalU128::ZERO);
                BrowserNode {
                    entry: pending.entry,
                    aggregate,
                    detail_rescan_state: DetailRescanState::Snapshot { revision },
                    root: pending.root,
                }
            })
            .collect();

        let mut model = BrowserModel {
            locale,
            status,
            scan_id,
            limits: normalized_limits(limits),
            nodes,
            roots,
            children_by_index,
            levels: Vec::new(),
            selected: 0,
            loaded_level: LoadedLevel::default(),
            size_unit: HumanSizeUnit::Auto,
            sort: ScanSort::Path,
            progressive_navigation: false,
            show_path_detail: false,
        };
        model.sort_rows();
        model.reload_loaded_level();
        Ok(model)
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

    /// Pins or unpins the full path of the selected row.
    pub const fn toggle_path_detail(&mut self) {
        self.show_path_detail = !self.show_path_detail;
    }

    pub const fn path_detail_shown(&self) -> bool {
        self.show_path_detail
    }

    pub fn visible_rows(&self) -> &[BrowserRow] {
        &self.loaded_level.rows
    }

    pub const fn selected_index(&self) -> usize {
        self.selected.saturating_sub(self.loaded_level.page_start)
    }

    pub fn selected_row(&self) -> Option<&BrowserRow> {
        self.visible_rows().get(self.selected_index())
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

    pub const fn current_level_total_rows(&self) -> usize {
        self.loaded_level.total_rows
    }

    pub fn current_page_bounds(&self) -> Option<(usize, usize)> {
        if self.loaded_level.total_rows == 0 {
            None
        } else {
            Some((
                self.loaded_level.page_start + 1,
                self.loaded_level.page_start + self.loaded_level.rows.len(),
            ))
        }
    }

    pub const fn max_level_rows(&self) -> usize {
        self.limits.max_level_rows
    }

    pub fn current_detail_rescan_state(&self) -> Option<&DetailRescanState> {
        self.levels
            .last()
            .map(|level| &self.nodes[level.directory_index].detail_rescan_state)
    }

    fn begin_detail_rescan(&mut self) -> Option<PendingDetailRescan> {
        let node_index = self.selected_node_index()?;
        let reason = if self.progressive_navigation {
            if !self.nodes[node_index].to_row().can_enter() {
                return None;
            }
            DetailRescanReason::ProgressiveListing
        } else {
            self.nodes[node_index].to_row().detail_rescan_reason()?
        };

        let base_revision = self.nodes[node_index].detail_rescan_state.revision();
        let Some(revision) = base_revision.checked_add(DecimalU128::new(1)) else {
            self.mark_detail_stale(
                node_index,
                base_revision,
                DetailRescanFailure::RevisionExhausted,
            );
            return None;
        };
        let Some(request) = self.detail_rescan_request(node_index, reason, base_revision, revision)
        else {
            self.mark_detail_stale(
                node_index,
                revision,
                DetailRescanFailure::IdentityUnavailable,
            );
            return None;
        };

        let previous_state = self.nodes[node_index].detail_rescan_state.clone();
        self.nodes[node_index].detail_rescan_state = DetailRescanState::Pending { revision };
        self.reload_loaded_level();
        Some(PendingDetailRescan {
            node_index,
            request,
            previous_state,
            last_activity_at: Instant::now(),
            timed_out: false,
        })
    }

    fn begin_progressive_aggregate(&mut self) -> Option<PendingDetailRescan> {
        if !self.progressive_navigation {
            return None;
        }
        let node_index = self.levels.last()?.directory_index;
        let base_revision = self.nodes[node_index].detail_rescan_state.revision();
        let revision = base_revision.checked_add(DecimalU128::new(1))?;
        let request = self.detail_rescan_request(
            node_index,
            DetailRescanReason::ProgressiveAggregate,
            base_revision,
            revision,
        )?;
        let previous_state = self.nodes[node_index].detail_rescan_state.clone();
        self.nodes[node_index].detail_rescan_state = DetailRescanState::Pending { revision };
        self.reload_loaded_level();
        Some(PendingDetailRescan {
            node_index,
            request,
            previous_state,
            last_activity_at: Instant::now(),
            timed_out: false,
        })
    }

    fn finish_detail_rescan(
        &mut self,
        pending: PendingDetailRescan,
        result: DetailRescanResult,
    ) -> bool {
        if !self.detail_rescan_binding_matches(&pending) {
            return false;
        }
        let selection_still_bound = if self.progressive_navigation {
            self.levels
                .last()
                .is_some_and(|level| level.directory_index == pending.node_index)
        } else {
            self.selected_node_index() == Some(pending.node_index)
        };
        if !selection_still_bound {
            self.restore_detail_rescan_state(&pending);
            return false;
        }
        let revision = pending.request.binding.revision;
        let failure = self
            .apply_detail_rescan_result(pending.node_index, &pending.request, result)
            .err();
        if let Some(failure) = failure
            && self.node_binding_matches(pending.node_index, &pending.request.binding)
        {
            self.mark_detail_stale(pending.node_index, revision, failure);
        }
        !self.progressive_navigation
    }

    fn expire_detail_rescan(&mut self, pending: &PendingDetailRescan) -> bool {
        self.fail_detail_rescan(pending, DetailRescanFailure::TimedOut)
    }

    fn fail_detail_rescan(
        &mut self,
        pending: &PendingDetailRescan,
        failure: DetailRescanFailure,
    ) -> bool {
        if self.detail_rescan_binding_matches(pending) {
            let should_enter = !self.progressive_navigation
                && self.selected_node_index() == Some(pending.node_index);
            self.mark_detail_stale(
                pending.node_index,
                pending.request.binding.revision,
                failure,
            );
            should_enter
        } else {
            false
        }
    }

    fn detail_rescan_binding_matches(&self, pending: &PendingDetailRescan) -> bool {
        self.node_binding_matches(pending.node_index, &pending.request.binding)
    }

    fn restore_detail_rescan_state(&mut self, pending: &PendingDetailRescan) {
        if self.detail_rescan_binding_matches(pending) {
            self.nodes[pending.node_index].detail_rescan_state = pending.previous_state.clone();
            self.reload_loaded_level();
        }
    }

    fn node_binding_matches(&self, node_index: usize, binding: &DetailRescanBinding) -> bool {
        let Some(node) = self.nodes.get(node_index) else {
            return false;
        };
        let Ok(Some(identity)) = node.entry.validated_identity() else {
            return false;
        };
        node.entry.scan_id == binding.source_scan_id
            && identity == &binding.source_directory_identity
            && matches!(
                node.detail_rescan_state,
                DetailRescanState::Pending { revision } if revision == binding.revision
            )
    }

    fn detail_rescan_request(
        &self,
        node_index: usize,
        reason: DetailRescanReason,
        base_revision: DecimalU128,
        revision: DecimalU128,
    ) -> Option<DetailRescanRequest> {
        let directory = &self.nodes[node_index].entry;
        if directory.object_type != ObjectType::Directory {
            return None;
        }
        let directory_identity = directory.validated_identity().ok()??;
        if !identity_is_known(directory_identity) {
            return None;
        }
        let locator = directory.executable_native_locator().ok()??.clone();
        let root =
            self.nodes.iter().find(|node| {
                node.root
                    && node.entry.identity.as_ref().is_some_and(|identity| {
                        identity.entry_id == directory_identity.scan_root_id
                    })
            })?;
        let root_identity = root.entry.validated_identity().ok()??;
        if !identity_is_known(root_identity) {
            return None;
        }

        Some(DetailRescanRequest {
            binding: DetailRescanBinding {
                source_scan_id: directory.scan_id.clone(),
                source_root_identity: root_identity.clone(),
                source_directory_identity: directory_identity.clone(),
                base_revision,
                revision,
            },
            directory_locator: locator,
            reason,
            // Progressive mode retains one whole directory level and pages it in the UI. Legacy
            // snapshot mode preserves the older single-page request contract.
            max_rows: if self.progressive_navigation {
                self.limits.max_entries
            } else {
                self.limits.max_level_rows
            },
        })
    }

    fn apply_detail_rescan_result(
        &mut self,
        node_index: usize,
        request: &DetailRescanRequest,
        result: DetailRescanResult,
    ) -> Result<(), DetailRescanFailure> {
        let (binding, observed_root, observed_directory, mut rows, aggregate) = match result {
            DetailRescanResult::Failed { binding, failure } => {
                return if *binding == request.binding {
                    Err(failure)
                } else {
                    Err(DetailRescanFailure::InvalidResult)
                };
            }
            DetailRescanResult::Refreshed(refreshed) => {
                let RefreshedDetail {
                    binding,
                    observed_root,
                    observed_directory,
                    rows,
                    aggregate,
                } = *refreshed;
                (binding, observed_root, observed_directory, rows, aggregate)
            }
        };
        if binding != request.binding {
            return Err(DetailRescanFailure::InvalidResult);
        }
        validate_refreshed_target(request, &observed_root, &observed_directory)?;
        validate_detail_rows(request, &observed_directory, &rows, &aggregate)?;

        // A targeted detail result contains only this directory's direct rows.
        // Conservatively mark any returned subdirectory's own detail as evicted;
        // it can be refreshed only when the user actually enters that row.
        for row in &mut rows {
            if row.object_type == ObjectType::Directory {
                mark_coverage_details_lost(&mut row.coverage);
            }
        }

        let mut replacement = self.rebuilt_with_detail_rows(
            node_index,
            observed_directory,
            rows,
            aggregate,
            binding.revision,
        )?;
        std::mem::swap(self, &mut replacement);
        Ok(())
    }

    fn apply_detail_rescan_progress(
        &mut self,
        pending: &PendingDetailRescan,
        progress: DetailRescanProgress,
    ) -> bool {
        if pending.request.reason != DetailRescanReason::ProgressiveAggregate
            || progress.binding != pending.request.binding
            || !self.detail_rescan_binding_matches(pending)
        {
            return false;
        }
        let Some(directory_identity) = self.nodes[pending.node_index].entry.identity.as_ref()
        else {
            return false;
        };
        if progress.aggregate.scan_id != pending.request.binding.source_scan_id
            || progress.aggregate.revision != pending.request.binding.revision
            || progress.aggregate.scan_entry_id().ok().as_ref()
                != Some(&directory_identity.entry_id)
        {
            return false;
        }
        let Ok(Some(progress_identity)) = progress.row.validated_identity() else {
            return false;
        };
        if progress.row.scan_id != pending.request.binding.source_scan_id
            || progress_identity.parent_id.as_ref() != Some(&directory_identity.entry_id)
            || progress.row.object_type != ObjectType::Directory
            || progress.aggregate.coverage.complete
            || progress.aggregate.coverage.state == CoverageState::Complete
            || progress.aggregate.arithmetic_state != ArithmeticState::LowerBound
            || !matches!(
                progress.row.logical_bytes,
                sweepx_model::EvidenceValue::LowerBound { .. }
            )
        {
            return false;
        }
        let Some(index) = self.children_by_index[pending.node_index]
            .iter()
            .copied()
            .find(|index| progressive_row_matches(&self.nodes[*index].entry, &progress.row))
        else {
            return false;
        };
        if lower_bound_bytes(&progress.row.logical_bytes)
            < lower_bound_bytes(&self.nodes[index].entry.logical_bytes)
            || lower_bound_bytes(&progress.aggregate.apparent_logical_bytes)
                < self.nodes[pending.node_index]
                    .aggregate
                    .as_ref()
                    .and_then(|aggregate| lower_bound_bytes(&aggregate.apparent_logical_bytes))
        {
            return false;
        }
        self.nodes[index].entry.logical_bytes = progress.row.logical_bytes;
        self.nodes[index].entry.allocated_bytes = progress.row.allocated_bytes;
        self.nodes[index].entry.reclaimable_estimate = progress.row.reclaimable_estimate;
        self.nodes[index].entry.coverage = progress.row.coverage;
        self.nodes[pending.node_index].aggregate = Some(progress.aggregate);
        self.sort_rows();
        self.reload_loaded_level();
        true
    }

    fn rebuilt_with_detail_rows(
        &self,
        node_index: usize,
        observed_directory: ScannedEntry,
        rows: Vec<ScannedEntry>,
        aggregate: DirectoryAggregate,
        revision: DecimalU128,
    ) -> Result<Self, DetailRescanFailure> {
        let mut removed = vec![false; self.nodes.len()];
        let mut frontier = self.children_by_index[node_index].clone();
        while let Some(index) = frontier.pop() {
            if removed[index] {
                continue;
            }
            removed[index] = true;
            frontier.extend(self.children_by_index[index].iter().copied());
        }

        let retained_states =
            self.nodes
                .iter()
                .enumerate()
                .filter(|(index, _)| !removed[*index])
                .filter_map(|(_, node)| {
                    node.entry.identity.as_ref().map(|identity| {
                        (identity.entry_id.clone(), node.detail_rescan_state.clone())
                    })
                })
                .collect::<HashMap<_, _>>();
        let level_ids = self
            .levels
            .iter()
            .map(|level| {
                (
                    self.nodes[level.directory_index]
                        .entry
                        .identity
                        .as_ref()
                        .expect("browser nodes have validated identities")
                        .entry_id
                        .clone(),
                    level.parent_selection,
                )
            })
            .collect::<Vec<_>>();

        let mut roots = Vec::new();
        let mut entries = Vec::new();
        let mut aggregates = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            if removed[index] {
                continue;
            }
            let entry = if index == node_index {
                observed_directory.clone()
            } else {
                node.entry.clone()
            };
            if node.root {
                roots.push(entry);
            } else {
                entries.push(entry);
            }
            if index == node_index {
                aggregates.push(aggregate.clone());
            } else if let Some(aggregate) = &node.aggregate {
                aggregates.push(aggregate.clone());
            }
        }
        entries.extend(rows);

        let mut rebuilt = Self::from_owned_scan_parts_with_limits(
            self.locale,
            self.status,
            self.scan_id.clone(),
            roots,
            entries,
            aggregates,
            self.limits,
        )
        .map_err(|error| match error {
            BrowserModelError::ResourceLimit { .. } => DetailRescanFailure::ResourceLimit,
            _ => DetailRescanFailure::InvalidResult,
        })?;
        rebuilt.size_unit = self.size_unit;
        rebuilt.sort = self.sort;
        rebuilt.progressive_navigation = self.progressive_navigation;
        rebuilt.sort_rows();

        for node in &mut rebuilt.nodes {
            let identity = node
                .entry
                .identity
                .as_ref()
                .expect("rebuilt browser nodes have validated identities");
            if identity.entry_id == request_entry_id(&observed_directory) {
                node.detail_rescan_state = DetailRescanState::Refreshed { revision };
            } else if let Some(state) = retained_states.get(&identity.entry_id) {
                node.detail_rescan_state = state.clone();
            }
        }

        rebuilt.levels.clear();
        for (entry_id, parent_selection) in level_ids {
            let directory_index = rebuilt
                .nodes
                .iter()
                .position(|node| {
                    node.entry
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.entry_id == entry_id)
                })
                .ok_or(DetailRescanFailure::InvalidResult)?;
            rebuilt.levels.push(BrowserLevel {
                directory_index,
                directory: rebuilt.nodes[directory_index].entry.display_path.clone(),
                parent_selection,
            });
        }
        if self.progressive_navigation {
            // The user is already inside the refreshed directory, so selection belongs to its
            // newly arrived direct-child rows rather than to the directory row in its parent.
            rebuilt.selected = 0;
        } else {
            let target_id = request_entry_id(&observed_directory);
            rebuilt.selected = rebuilt
                .current_level_rows()
                .iter()
                .position(|index| {
                    rebuilt.nodes[*index]
                        .entry
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.entry_id == target_id)
                })
                .ok_or(DetailRescanFailure::InvalidResult)?;
        }
        rebuilt.reload_loaded_level();
        rebuilt.clamp_selection();
        Ok(rebuilt)
    }

    fn mark_detail_stale(
        &mut self,
        node_index: usize,
        revision: DecimalU128,
        failure: DetailRescanFailure,
    ) {
        self.nodes[node_index].detail_rescan_state = DetailRescanState::Stale { revision, failure };
        self.reload_loaded_level();
    }

    fn move_up(&mut self) {
        let next = self.selected.saturating_sub(1);
        self.set_selected(next);
    }

    fn move_down(&mut self) {
        let limit = self.current_level_total_rows().saturating_sub(1);
        if self.current_level_total_rows() > 0 && self.selected < limit {
            self.set_selected(self.selected + 1);
        }
    }

    fn enter_selected(&mut self) {
        let Some(node_index) = self.selected_node_index() else {
            return;
        };
        let node = &self.nodes[node_index];
        if !matches!(node.entry.object_type, ObjectType::Directory) {
            return;
        }

        let directory = node.entry.display_path.clone();
        self.levels.push(BrowserLevel {
            directory_index: node_index,
            directory,
            parent_selection: self.selected,
        });
        self.set_selected(0);
    }

    fn return_to_parent(&mut self) {
        let Some(level) = self.levels.pop() else {
            return;
        };
        self.selected = level.parent_selection;
        self.reload_loaded_level();
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let next = self
            .selected
            .min(self.current_level_total_rows().saturating_sub(1));
        self.set_selected(next);
    }

    fn set_selected(&mut self, selected: usize) {
        self.selected = selected.min(self.current_level_total_rows().saturating_sub(1));
        self.reload_loaded_level();
    }

    fn selected_node_index(&self) -> Option<usize> {
        self.loaded_level
            .row_indices
            .get(self.selected_index())
            .copied()
    }

    fn current_level_rows(&self) -> &[usize] {
        match self.levels.last() {
            Some(level) => &self.children_by_index[level.directory_index],
            None => &self.roots,
        }
    }

    fn reload_loaded_level(&mut self) {
        let total_rows = self.current_level_rows().len();
        let max_level_rows = self.limits.max_level_rows.max(1);
        self.selected = self.selected.min(total_rows.saturating_sub(1));
        let page_start = if total_rows == 0 {
            0
        } else {
            (self.selected / max_level_rows) * max_level_rows
        };
        let page_end = total_rows.min(page_start + max_level_rows);
        let row_indices = self.current_level_rows()[page_start..page_end].to_vec();
        let mut rows: Vec<BrowserRow> = row_indices
            .iter()
            .map(|index| self.nodes[*index].to_row())
            .collect();
        shorten_root_labels(&mut rows);
        self.loaded_level = LoadedLevel {
            total_rows,
            page_start,
            row_indices,
            rows,
        };
    }

    fn sort_rows(&mut self) {
        let sort = self.sort;
        let nodes = &self.nodes;
        for rows in &mut self.children_by_index {
            rows.sort_by(|left, right| browser_node_order(nodes, *left, *right, sort));
        }
        self.roots
            .sort_by(|left, right| browser_node_order(nodes, *left, *right, sort));
    }
}

fn browser_node_order(
    nodes: &[BrowserNode],
    left: usize,
    right: usize,
    sort: ScanSort,
) -> std::cmp::Ordering {
    let left_node = &nodes[left];
    let right_node = &nodes[right];
    if sort == ScanSort::Size {
        let left_bytes = browser_node_bytes(left_node);
        let right_bytes = browser_node_bytes(right_node);
        right_bytes.cmp(&left_bytes).then_with(|| {
            left_node
                .entry
                .display_path
                .cmp(&right_node.entry.display_path)
        })
    } else {
        left_node
            .entry
            .display_path
            .cmp(&right_node.entry.display_path)
    }
}

fn browser_node_bytes(node: &BrowserNode) -> Option<u128> {
    let value = node
        .aggregate
        .as_ref()
        .map(|aggregate| &aggregate.potentially_reclaimable_bytes)
        .unwrap_or(&node.entry.reclaimable_estimate);
    match value {
        sweepx_model::EvidenceValue::Known { value }
        | sweepx_model::EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}

fn progressive_row_matches(current: &ScannedEntry, progress: &ScannedEntry) -> bool {
    let (Some(current_identity), Some(progress_identity)) =
        (current.identity.as_ref(), progress.identity.as_ref())
    else {
        return false;
    };
    // The aggregate pass re-enumerates direct children and therefore allocates fresh scan-local
    // entry ids. Match the already validated listing row by its no-follow native identity tuple;
    // display paths are deliberately excluded from this authority decision.
    current.scan_id == progress.scan_id
        && current.object_type == progress.object_type
        && current.native_basename == progress.native_basename
        && current_identity.platform_file_identity == progress_identity.platform_file_identity
        && current_identity.filesystem_object_domain_identity
            == progress_identity.filesystem_object_domain_identity
        && current_identity.volume_or_mount_identity == progress_identity.volume_or_mount_identity
}

fn lower_bound_bytes(value: &sweepx_model::ByteValue) -> Option<u128> {
    match value {
        sweepx_model::EvidenceValue::Known { value }
        | sweepx_model::EvidenceValue::LowerBound { value, .. } => Some(value.0),
        _ => None,
    }
}

fn normalized_limits(limits: BrowserLoadLimits) -> BrowserLoadLimits {
    BrowserLoadLimits {
        max_level_rows: limits.max_level_rows.clamp(1, MAX_PAGE_ROWS.max(1)),
        max_entries: limits.max_entries.clamp(1, DEFAULT_MAX_BROWSER_ENTRIES),
        max_index_bytes: limits
            .max_index_bytes
            .clamp(1, DEFAULT_MAX_BROWSER_INDEX_BYTES),
    }
}

fn preflight_limits(
    roots: &[ScannedEntry],
    entries: &[ScannedEntry],
    aggregates: &[DirectoryAggregate],
    limits: BrowserLoadLimits,
) -> Result<(), BrowserModelError> {
    let limits = normalized_limits(limits);
    let entry_count = roots.len().saturating_add(entries.len());
    if entry_count > limits.max_entries {
        return Err(BrowserModelError::ResourceLimit {
            kind: BrowserResourceLimitKind::Entries,
            limit: limits.max_entries,
            observed: entry_count,
        });
    }

    let observed = estimate_total_index_bytes(roots, entries, aggregates, limits);
    if observed > limits.max_index_bytes {
        return Err(BrowserModelError::ResourceLimit {
            kind: BrowserResourceLimitKind::IndexBytes,
            limit: limits.max_index_bytes,
            observed,
        });
    }
    Ok(())
}

fn estimate_total_index_bytes(
    roots: &[ScannedEntry],
    entries: &[ScannedEntry],
    aggregates: &[DirectoryAggregate],
    limits: BrowserLoadLimits,
) -> usize {
    let limits = normalized_limits(limits);
    let entry_count = roots.len().saturating_add(entries.len());
    let persistent = entry_count
        .saturating_mul(size_of::<BrowserNode>())
        .saturating_add(entry_count.saturating_mul(size_of::<Vec<usize>>()))
        .saturating_add(entry_count.saturating_mul(size_of::<usize>()))
        .saturating_add(roots.len().saturating_mul(size_of::<usize>()))
        .saturating_add(
            limits
                .max_level_rows
                .saturating_mul(size_of::<BrowserRow>() + size_of::<usize>()),
        );
    let transient = entry_count
        .saturating_mul(size_of::<PendingNode>())
        .saturating_add(entry_count.saturating_mul(size_of::<(ScanEntryId, usize)>()))
        .saturating_add(entry_count.saturating_mul(size_of::<Option<DirectoryAggregate>>()))
        .saturating_add(entry_count.saturating_mul(size_of::<bool>()));
    let mut total = persistent.max(transient);
    for entry in roots.iter().chain(entries.iter()) {
        total = total.saturating_add(estimate_entry_bytes(entry));
    }
    for aggregate in aggregates {
        total = total.saturating_add(estimate_aggregate_bytes(aggregate));
    }
    total
}

fn estimate_entry_bytes(entry: &ScannedEntry) -> usize {
    let mut total = size_of::<ScannedEntry>();
    total = total.saturating_add(entry.scan_id.len());
    total = total.saturating_add(entry.display_path.len());
    total = total.saturating_add(entry.metadata_fingerprint.len());
    total = total.saturating_add(estimate_native_name_bytes(&entry.native_basename));
    total = total.saturating_add(estimate_field_provenance_bytes(&entry.provenance));
    if let Some(identity) = &entry.identity {
        total = total.saturating_add(estimate_identity_bytes(identity));
    }
    total
}

fn estimate_identity_bytes(identity: &ScanObjectIdentity) -> usize {
    identity.entry_id.as_str().len()
        + identity.scan_root_id.as_str().len()
        + identity
            .parent_id
            .as_ref()
            .map(|id| id.as_str().len())
            .unwrap_or_default()
}

fn estimate_aggregate_bytes(aggregate: &DirectoryAggregate) -> usize {
    size_of::<DirectoryAggregate>()
        .saturating_add(aggregate.scan_id.len())
        .saturating_add(aggregate.directory_identity.len())
        .saturating_add(estimate_field_provenance_bytes(
            &aggregate.coverage.provenance,
        ))
}

fn estimate_native_name_bytes(name: &NativeName) -> usize {
    match name {
        NativeName::UnixBytes(bytes) => bytes.len(),
        NativeName::WindowsUtf16(units) => units.len().saturating_mul(2),
    }
}

fn estimate_field_provenance_bytes(provenance: &FieldProvenance) -> usize {
    match provenance {
        FieldProvenance::LiveObservation {
            observed_at,
            method: _,
        } => observed_at.len(),
        FieldProvenance::ValidatedCache {
            observed_at,
            validation: _,
            token,
        } => observed_at.len().saturating_add(token.len()),
        FieldProvenance::DerivedFromCurrent { inputs, algorithm } => {
            inputs.iter().fold(algorithm.len(), |total, input| {
                total.saturating_add(input.len())
            })
        }
        FieldProvenance::StalePreview { observed_at } => observed_at.len(),
        FieldProvenance::Unknown { reason: _ } => 0,
    }
}

fn required_identity(entry: &ScannedEntry) -> Result<&ScanObjectIdentity, BrowserModelError> {
    entry
        .validated_identity()?
        .ok_or_else(|| BrowserModelError::MissingIdentity {
            display_path: entry.display_path.clone(),
        })
}

fn detail_rescan_reason(can_enter: bool, coverage: &Coverage) -> Option<DetailRescanReason> {
    if !can_enter {
        return None;
    }
    match coverage.state {
        CoverageState::DetailsLost if coverage.details_lost && !coverage.complete => {
            Some(DetailRescanReason::Evicted)
        }
        CoverageState::Incomplete if !coverage.complete && !coverage.details_lost => {
            Some(DetailRescanReason::Incomplete)
        }
        CoverageState::Complete | CoverageState::Incomplete | CoverageState::DetailsLost => None,
    }
}

fn identity_is_known(identity: &ScanObjectIdentity) -> bool {
    use sweepx_model::IdentityEvidence::Known;

    matches!(identity.platform_file_identity, Known { .. })
        && matches!(identity.filesystem_object_domain_identity, Known { .. })
        && matches!(identity.volume_or_mount_identity, Known { .. })
}

fn request_entry_id(entry: &ScannedEntry) -> ScanEntryId {
    entry
        .identity
        .as_ref()
        .expect("validated detail entry has identity")
        .entry_id
        .clone()
}

fn mark_coverage_details_lost(coverage: &mut Coverage) {
    coverage.state = CoverageState::DetailsLost;
    coverage.complete = false;
    coverage.details_lost = true;
}

fn validate_refreshed_target(
    request: &DetailRescanRequest,
    observed_root: &ScannedEntry,
    observed_directory: &ScannedEntry,
) -> Result<(), DetailRescanFailure> {
    if observed_root.scan_id != request.binding.source_scan_id
        || observed_directory.scan_id != request.binding.source_scan_id
    {
        return Err(DetailRescanFailure::InvalidResult);
    }
    let root_identity = observed_root
        .validated_identity()
        .map_err(|_| DetailRescanFailure::InvalidResult)?
        .ok_or(DetailRescanFailure::IdentityUnavailable)?;
    let directory_identity = observed_directory
        .validated_identity()
        .map_err(|_| DetailRescanFailure::InvalidResult)?
        .ok_or(DetailRescanFailure::IdentityUnavailable)?;
    if observed_root.object_type != ObjectType::Directory
        || observed_directory.object_type != ObjectType::Directory
    {
        return Err(DetailRescanFailure::SymlinkOrReparse);
    }
    if !identity_is_known(root_identity) || !identity_is_known(directory_identity) {
        return Err(DetailRescanFailure::IdentityUnavailable);
    }
    if root_identity.volume_or_mount_identity
        != request
            .binding
            .source_root_identity
            .volume_or_mount_identity
        || directory_identity.volume_or_mount_identity
            != request
                .binding
                .source_directory_identity
                .volume_or_mount_identity
    {
        return Err(DetailRescanFailure::MountChanged);
    }
    let observed_locator = observed_directory
        .executable_native_locator()
        .map_err(|_| DetailRescanFailure::InvalidResult)?
        .ok_or(DetailRescanFailure::IdentityUnavailable)?;
    if root_identity != &request.binding.source_root_identity
        || directory_identity != &request.binding.source_directory_identity
        || !locator_identity_matches(&request.directory_locator, observed_locator)
    {
        return Err(DetailRescanFailure::IdentityMismatch);
    }
    Ok(())
}

fn locator_identity_matches(
    expected: &NativeLocatorEvidence,
    observed: &NativeLocatorEvidence,
) -> bool {
    expected.scan_root_absolute_path == observed.scan_root_absolute_path
        && native_component_identity_matches(&expected.scan_root, &observed.scan_root)
        && native_component_identity_matches(&expected.entry, &observed.entry)
        && expected.parent_reopen_recipe.len() == observed.parent_reopen_recipe.len()
        && expected
            .parent_reopen_recipe
            .iter()
            .zip(&observed.parent_reopen_recipe)
            .all(|(expected, observed)| native_component_identity_matches(expected, observed))
}

fn native_component_identity_matches(
    expected: &sweepx_model::NativePathComponent,
    observed: &sweepx_model::NativePathComponent,
) -> bool {
    expected.entry_id == observed.entry_id
        && expected.parent_id == observed.parent_id
        && expected.native_basename == observed.native_basename
        && expected.object_type == observed.object_type
        && expected.platform_file_identity == observed.platform_file_identity
        && expected.filesystem_object_domain_identity == observed.filesystem_object_domain_identity
        && expected.volume_or_mount_identity == observed.volume_or_mount_identity
}

fn validate_detail_rows(
    request: &DetailRescanRequest,
    directory: &ScannedEntry,
    rows: &[ScannedEntry],
    aggregate: &DirectoryAggregate,
) -> Result<(), DetailRescanFailure> {
    if rows.len() > request.max_rows {
        return Err(DetailRescanFailure::ResourceLimit);
    }
    let directory_identity = directory
        .validated_identity()
        .map_err(|_| DetailRescanFailure::InvalidResult)?
        .ok_or(DetailRescanFailure::IdentityUnavailable)?;
    if aggregate.scan_id != request.binding.source_scan_id
        || aggregate.revision != request.binding.revision
        || aggregate
            .scan_entry_id()
            .map_err(|_| DetailRescanFailure::InvalidResult)?
            != directory_identity.entry_id
    {
        return Err(DetailRescanFailure::InvalidResult);
    }
    let complete_result = aggregate.coverage.state == CoverageState::Complete
        && aggregate.coverage.complete
        && !aggregate.coverage.details_lost
        && aggregate.coverage.incomplete_reasons.is_empty();
    if (!complete_result
        && !matches!(
            request.reason,
            DetailRescanReason::ProgressiveListing | DetailRescanReason::ProgressiveAggregate
        ))
        || aggregate.direct_child_count
            != (sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(rows.len() as u128),
            })
    {
        return Err(DetailRescanFailure::InvalidResult);
    }
    let mut seen = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        if row.scan_id != request.binding.source_scan_id {
            return Err(DetailRescanFailure::InvalidResult);
        }
        let identity = row
            .validated_identity()
            .map_err(|_| DetailRescanFailure::InvalidResult)?
            .ok_or(DetailRescanFailure::IdentityUnavailable)?;
        if !identity_is_known(identity)
            || identity.parent_id.as_ref() != Some(&directory_identity.entry_id)
            || identity.scan_root_id != directory_identity.scan_root_id
            || !seen.insert(identity.entry_id.clone())
        {
            return Err(if identity_is_known(identity) {
                DetailRescanFailure::InvalidResult
            } else {
                DetailRescanFailure::IdentityUnavailable
            });
        }
        if row.object_type == ObjectType::Directory
            && row
                .executable_native_locator()
                .map_err(|_| DetailRescanFailure::InvalidResult)?
                .is_none()
        {
            return Err(DetailRescanFailure::IdentityUnavailable);
        }
        if matches!(
            row.object_type,
            ObjectType::Symlink | ObjectType::ReparsePoint
        ) {
            // Links are valid result rows but remain leaves; they are never
            // interpreted as directories by the browser.
            continue;
        }
    }
    Ok(())
}

fn insert_pending_node(
    pending_nodes: &mut Vec<PendingNode>,
    id_to_index: &mut HashMap<ScanEntryId, usize>,
    node: PendingNode,
) -> Result<(), BrowserModelError> {
    if id_to_index.contains_key(&node.entry_id) {
        return Err(BrowserModelError::DuplicateEntryId {
            entry_id: node.entry_id.to_string(),
        });
    }
    let index = pending_nodes.len();
    id_to_index.insert(node.entry_id.clone(), index);
    pending_nodes.push(node);
    Ok(())
}

fn browser_path_order(left: &PendingNode, right: &PendingNode) -> std::cmp::Ordering {
    left.entry.display_path.cmp(&right.entry.display_path)
}

fn enforce_snapshot_scan_ids(
    requested_scan_id: Option<&str>,
    roots: &[ScannedEntry],
    entries: &[ScannedEntry],
    aggregates: &[DirectoryAggregate],
) -> Result<(), BrowserModelError> {
    let mut expected = requested_scan_id.map(ToOwned::to_owned);
    for observed in roots
        .iter()
        .map(|entry| entry.scan_id.to_string())
        .chain(entries.iter().map(|entry| entry.scan_id.to_string()))
        .chain(
            aggregates
                .iter()
                .map(|aggregate| aggregate.scan_id.to_string()),
        )
    {
        match &expected {
            Some(expected_scan_id) if expected_scan_id != &observed => {
                return Err(BrowserModelError::SnapshotScanMismatch {
                    expected_scan_id: expected_scan_id.clone(),
                    observed_scan_id: observed,
                });
            }
            Some(_) => {}
            None => expected = Some(observed),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserAction {
    MoveUp,
    MoveDown,
    EnterDirectory,
    ReturnToParent,
    TrashSelected,
    /// Shows the selected row's full, untruncated path.
    ///
    /// The list is width-constrained by design, so a long path is either shortened or scrolling. This
    /// gives a way to read it verbatim without leaving the row - which matters because the next key
    /// the user might press moves that row to the Trash.
    TogglePathDetail,
    Quit,
}

impl BrowserAction {
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::TrashSelected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserControl {
    Continue,
    TrashSelected,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserExit {
    Quit,
    TrashSelected { entry: Box<ScannedEntry> },
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
            KeyCode::Delete | KeyCode::Char('d') => Some(BrowserAction::TrashSelected),
            KeyCode::Char('p') => Some(BrowserAction::TogglePathDetail),
            KeyCode::Char('q') => Some(BrowserAction::Quit),
            _ => None,
        }
    }
}

pub trait BrowserReducer {
    fn reduce(&self, model: &mut BrowserModel, action: BrowserAction) -> BrowserControl;

    fn poll_background(&self, _model: &mut BrowserModel) {}

    fn cancel_background(&self) {}
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
            BrowserAction::TogglePathDetail => model.toggle_path_detail(),
            BrowserAction::TrashSelected => return BrowserControl::TrashSelected,
            BrowserAction::Quit => return BrowserControl::Quit,
        }
        BrowserControl::Continue
    }
}

#[derive(Debug)]
struct PendingDetailRescan {
    node_index: usize,
    request: DetailRescanRequest,
    previous_state: DetailRescanState,
    last_activity_at: Instant,
    timed_out: bool,
}

struct CompletedDetailRescan {
    request: DetailRescanRequest,
    result: DetailRescanResult,
    finished_at: Instant,
}

#[derive(Debug)]
struct DetailRescanWorkerLimiter {
    active: AtomicUsize,
    limit: usize,
}

impl DetailRescanWorkerLimiter {
    const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<DetailRescanWorkerPermit, BrowserError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .map_err(|_| BrowserError::DetailRescanWorkerCapacity { limit: self.limit })?;
        Ok(DetailRescanWorkerPermit {
            limiter: Arc::clone(self),
        })
    }
}

fn detail_rescan_worker_limiter() -> Arc<DetailRescanWorkerLimiter> {
    Arc::clone(
        DETAIL_RESCAN_WORKER_LIMITER
            .get_or_init(|| Arc::new(DetailRescanWorkerLimiter::new(MAX_DETAIL_RESCAN_WORKERS))),
    )
}

#[derive(Debug)]
struct DetailRescanWorkerPermit {
    limiter: Arc<DetailRescanWorkerLimiter>,
}

impl Drop for DetailRescanWorkerPermit {
    fn drop(&mut self) {
        let previous = self.limiter.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

/// Navigation reducer which delegates bounded detail enumeration to one
/// background worker. The bounded channels and `pending` slot permit at most
/// one outstanding query, while the terminal thread keeps polling input and
/// redrawing.
pub struct DetailRescanBrowserReducer<P: DetailRescanProvider> {
    provider: Option<Arc<P>>,
    requests: Option<SyncSender<DetailRescanRequest>>,
    completions: Receiver<CompletedDetailRescan>,
    progress: Receiver<DetailRescanProgress>,
    worker_done: Receiver<()>,
    worker: Option<JoinHandle<()>>,
    pending: RefCell<Option<PendingDetailRescan>>,
    deadline: Duration,
}

impl<P: DetailRescanProvider> DetailRescanBrowserReducer<P> {
    pub fn new(provider: P) -> Result<Self, BrowserError> {
        Self::try_new_with_deadline(provider, DETAIL_RESCAN_QUERY_DEADLINE)
    }

    fn try_new_with_deadline(provider: P, deadline: Duration) -> Result<Self, BrowserError> {
        Self::try_new_with_limiter(provider, deadline, detail_rescan_worker_limiter())
    }

    fn try_new_with_limiter(
        provider: P,
        deadline: Duration,
        limiter: Arc<DetailRescanWorkerLimiter>,
    ) -> Result<Self, BrowserError> {
        let worker_permit = limiter.acquire()?;
        let provider = Arc::new(provider);
        let worker_provider = Arc::clone(&provider);
        let (request_sender, request_receiver) = sync_channel::<DetailRescanRequest>(1);
        let (completion_sender, completion_receiver) = sync_channel(1);
        // A capacity of one coalesces UI work: scanner throughput is never coupled to terminal
        // redraw speed, and the next successful snapshot supersedes any skipped lower bound.
        let (progress_sender, progress_receiver) = sync_channel(1);
        provider.set_progress_sink(Some(progress_sender));
        let (worker_done_sender, worker_done_receiver) = sync_channel(1);
        let worker = thread::Builder::new()
            .name("sweepx-detail-rescan".to_string())
            .spawn(move || {
                let _worker_permit = worker_permit;
                while let Ok(request) = request_receiver.recv() {
                    let result = worker_provider.rescan_detail(&request);
                    if completion_sender
                        .send(CompletedDetailRescan {
                            request,
                            result,
                            finished_at: Instant::now(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = worker_done_sender.send(());
            })?;
        Ok(Self {
            provider: Some(provider),
            requests: Some(request_sender),
            completions: completion_receiver,
            progress: progress_receiver,
            worker_done: worker_done_receiver,
            worker: Some(worker),
            pending: RefCell::new(None),
            deadline,
        })
    }

    fn shutdown_worker(&mut self) {
        let wait = self
            .pending
            .borrow()
            .as_ref()
            .map_or(self.deadline, |pending| {
                self.deadline
                    .saturating_sub(pending.last_activity_at.elapsed())
            });
        if self.pending.borrow().is_some()
            && let Some(provider) = &self.provider
        {
            provider.cancel_detail_rescan();
        }
        if let Some(provider) = &self.provider {
            provider.set_progress_sink(None);
        }
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            match self.worker_done.recv_timeout(wait) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Rust cannot forcibly stop a blocked OS thread. Quarantine
                    // this single worker after the provider's bounded deadline.
                    // Its process-wide permit remains owned by the thread, so
                    // repeated browser runs cannot leak workers without bound.
                    drop(worker);
                }
            }
        }
    }

    fn submit(&self, pending: PendingDetailRescan) -> Result<(), Box<PendingDetailRescan>> {
        let Some(requests) = &self.requests else {
            return Err(Box::new(pending));
        };
        self.provider().prepare_detail_rescan();
        match requests.try_send(pending.request.clone()) {
            Ok(()) => {
                *self.pending.borrow_mut() = Some(pending);
                Ok(())
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                Err(Box::new(pending))
            }
        }
    }

    fn complete_or_expire(&self, model: &mut BrowserModel) {
        if let Some(pending) = self.pending.borrow_mut().as_mut() {
            while let Ok(progress) = self.progress.try_recv() {
                if model.apply_detail_rescan_progress(pending, progress) {
                    pending.last_activity_at = Instant::now();
                }
            }
        } else {
            while self.progress.try_recv().is_ok() {}
        }
        match self.completions.try_recv() {
            Ok(completed) => {
                let Some(pending) = self.pending.borrow_mut().take() else {
                    return;
                };
                let progressive_listing =
                    pending.request.reason == DetailRescanReason::ProgressiveListing;
                if !pending.timed_out {
                    let completed_in_time = completed
                        .finished_at
                        .saturating_duration_since(pending.last_activity_at)
                        <= self.deadline;
                    let should_enter = if !completed_in_time {
                        model.expire_detail_rescan(&pending)
                    } else if completed.request == pending.request {
                        model.finish_detail_rescan(pending, completed.result)
                    } else {
                        model.fail_detail_rescan(&pending, DetailRescanFailure::InvalidResult)
                    };
                    if should_enter {
                        model.enter_selected();
                    }
                    if progressive_listing && let Some(next) = model.begin_progressive_aggregate() {
                        let _ = self.submit(next);
                    }
                }
            }
            Err(TryRecvError::Disconnected) => {
                if let Some(pending) = self.pending.borrow_mut().take()
                    && !pending.timed_out
                    && model.fail_detail_rescan(&pending, DetailRescanFailure::Unavailable)
                {
                    model.enter_selected();
                }
            }
            Err(TryRecvError::Empty) => {
                let mut pending = self.pending.borrow_mut();
                if let Some(pending) = pending.as_mut()
                    && !pending.timed_out
                    && pending.last_activity_at.elapsed() >= self.deadline
                {
                    self.provider().cancel_detail_rescan();
                    if model.expire_detail_rescan(pending) {
                        model.enter_selected();
                    }
                    pending.timed_out = true;
                }
            }
        }
    }

    fn provider(&self) -> &P {
        self.provider
            .as_deref()
            .expect("provider remains available while reducer is active")
    }
}

impl<P> BrowserReducer for DetailRescanBrowserReducer<P>
where
    P: DetailRescanProvider,
{
    fn reduce(&self, model: &mut BrowserModel, action: BrowserAction) -> BrowserControl {
        self.complete_or_expire(model);
        if matches!(action, BrowserAction::Quit | BrowserAction::TrashSelected) {
            self.cancel_background();
            return if action == BrowserAction::Quit {
                BrowserControl::Quit
            } else {
                BrowserControl::TrashSelected
            };
        }

        if self.pending.borrow().is_some() {
            return if action == BrowserAction::EnterDirectory {
                BrowserControl::Continue
            } else {
                ReadOnlyBrowserReducer.reduce(model, action)
            };
        }

        if action == BrowserAction::EnterDirectory
            && let Some(pending) = model.begin_detail_rescan()
        {
            if let Err(pending) = self.submit(pending)
                && model.fail_detail_rescan(&pending, DetailRescanFailure::Unavailable)
            {
                model.enter_selected();
            }
            if model.progressive_navigation {
                // Product TUI navigation never waits for recursive aggregation. The entered
                // directory renders immediately and its rows arrive from the background scan.
                model.enter_selected();
            }
            return BrowserControl::Continue;
        }
        ReadOnlyBrowserReducer.reduce(model, action)
    }

    fn poll_background(&self, model: &mut BrowserModel) {
        self.complete_or_expire(model);
    }

    fn cancel_background(&self) {
        if self.pending.borrow().is_some() {
            self.provider().cancel_detail_rescan();
        }
    }
}

impl<P: DetailRescanProvider> Drop for DetailRescanBrowserReducer<P> {
    fn drop(&mut self) {
        self.shutdown_worker();
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
    #[error("detail rescan worker capacity exhausted: limit={limit}")]
    DetailRescanWorkerCapacity { limit: usize },
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

pub fn run_live_browser(model: BrowserModel) -> Result<BrowserExit, BrowserError> {
    run_live_browser_with_detail_rescan(model, UnavailableDetailRescanProvider)
}

pub fn run_live_browser_with_detail_rescan<P>(
    mut model: BrowserModel,
    provider: P,
) -> Result<BrowserExit, BrowserError>
where
    P: DetailRescanProvider,
{
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
    let reducer =
        DetailRescanBrowserReducer::try_new_with_deadline(provider, DETAIL_RESCAN_QUERY_DEADLINE)?;
    if model.progressive_navigation && model.roots.len() == 1 {
        // A single explicit/default root is the user's intended starting directory. Enter it and
        // launch the direct-child listing before the first paint instead of showing an extra
        // virtual-root screen that requires a redundant key press.
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
    }
    let result = run_browser_loop_until(
        &mut terminal,
        &mut model,
        &mut events,
        &mapper,
        &reducer,
        &termination,
    );
    reducer.cancel_background();

    drop(terminal);
    guard.restore();
    // Join only after terminal restoration. Cooperative providers receive the
    // cancellation hook before loop exit, so shutdown cannot strand raw mode
    // even if the final worker cleanup takes up to the provider's own bound.
    drop(reducer);
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
    let started_at = Instant::now();
    loop {
        if let Some(signal) = termination.termination_signal() {
            reducer.cancel_background();
            return Ok(BrowserExit::Terminated {
                signal: Some(signal),
            });
        }
        reducer.poll_background(model);
        // One cell per MARQUEE_TICK of elapsed time. Derived from the clock rather than counted in
        // frames so the scroll speed does not change when the poll interval or redraw rate does.
        let phase = (started_at.elapsed().as_millis() / MARQUEE_TICK.as_millis()) as usize;
        terminal.draw(|frame| render_live_browser_at_phase(frame, frame.area(), model, phase))?;

        let event = match events.poll_event(BROWSER_EVENT_POLL_INTERVAL) {
            Ok(event) => event,
            Err(_) if termination.termination_signal().is_some() => {
                reducer.cancel_background();
                return Ok(BrowserExit::Terminated {
                    signal: termination.termination_signal(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(signal) = termination.termination_signal() {
            reducer.cancel_background();
            return Ok(BrowserExit::Terminated {
                signal: Some(signal),
            });
        }

        if let Some(Event::Key(key)) = event
            && let Some(action) = key_mapper.map_key(&key)
        {
            match reducer.reduce(model, action) {
                BrowserControl::Continue => {}
                BrowserControl::Quit => return Ok(BrowserExit::Quit),
                BrowserControl::TrashSelected => {
                    if let Some(row) = model.selected_row() {
                        return Ok(BrowserExit::TrashSelected {
                            entry: Box::new(row.entry().clone()),
                        });
                    }
                }
            }
        }
    }
}

pub fn render_live_browser(frame: &mut Frame<'_>, area: Rect, model: &BrowserModel) {
    render_live_browser_at_phase(frame, area, model, 0);
}

/// Paints one frame with an explicit marquee phase.
///
/// `phase` advances one cell per `MARQUEE_TICK`. Taking it as a parameter rather than reading a clock
/// keeps painting a pure function of its inputs, so a test can assert on any frame of the animation
/// without sleeping.
pub fn render_live_browser_at_phase(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &BrowserModel,
    phase: usize,
) {
    // The footer grows when a full path is pinned, because a path long enough to need this feature is
    // usually long enough to wrap. Taking the space from the list keeps the layout total unchanged.
    let footer_height = if model.path_detail_shown() { 6 } else { 3 };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(footer_height),
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

    render_browser_rows(frame, sections[2], model, phase);

    frame.render_widget(
        Paragraph::new(browser_footer_text(model))
            // Wrapping is what makes a pinned path readable in full; without it the footer would clip
            // the path exactly like the name column already does.
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(read_only_label(model.locale())),
            ),
        sections[3],
    );
}

/// The browser table's column constraints.
///
/// Shared between layout and overflow detection on purpose. The name column is a percentage of what
/// the fixed columns leave over, so its real width is not obvious: on an 80-column terminal the five
/// fixed columns take 67 cells and the name column resolves to 11, not to 42% of 80. Measuring
/// overflow against an independently re-derived guess would therefore be wrong on exactly the narrow
/// terminals where overflow matters most.
const BROWSER_COLUMNS: [Constraint; 6] = [
    Constraint::Percentage(42),
    Constraint::Length(11),
    Constraint::Length(13),
    Constraint::Length(13),
    Constraint::Length(10),
    Constraint::Length(20),
];

/// The column gap `Table` inserts between columns.
///
/// `Table::default()` sets `column_spacing: 1` and passes it to the layout as `.spacing(...)`, so the
/// six columns lose five cells that a plain constraint split does not account for. Leaving this out
/// made the computed name width 11 while the rendered one was 6 - and overflow detection that is five
/// cells too generous truncates nothing on exactly the terminals that need it.
const BROWSER_COLUMN_SPACING: u16 = 1;

/// The cells the name column actually gets inside `area`.
///
/// Resolved through the same layout the table uses - same constraints, same spacing, minus the block
/// borders - so it matches what the widget will really do rather than an approximation of it.
fn name_column_cells(area: Rect) -> usize {
    let inner = Block::default().borders(Borders::ALL).inner(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(BROWSER_COLUMNS)
        .spacing(BROWSER_COLUMN_SPACING)
        .split(inner);
    usize::from(columns[0].width)
}

fn render_browser_rows(frame: &mut Frame<'_>, area: Rect, model: &BrowserModel, phase: usize) {
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

    let name_cells = name_column_cells(area);
    let table_rows = rows[start..end].iter().enumerate().map(|(offset, row)| {
        let index = start + offset;
        let selected = index == model.selected_index();
        let aggregate = row.aggregate();
        let logical = aggregate
            .map(|value| byte_value_label_with_unit(&value.apparent_logical_bytes, model.size_unit))
            .unwrap_or_else(|| {
                byte_value_label_with_unit(&row.entry().logical_bytes, model.size_unit)
            });
        let reclaimable = aggregate
            .map(|value| {
                byte_value_label_with_unit(&value.potentially_reclaimable_bytes, model.size_unit)
            })
            .unwrap_or_else(|| {
                byte_value_label_with_unit(&row.entry().reclaimable_estimate, model.size_unit)
            });
        let children = aggregate
            .map(|value| count_value_label(&value.direct_child_count))
            .unwrap_or_else(|| "-".to_string());
        let coverage = browser_row_coverage_label(row);
        let style = if index == model.selected_index() {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        // Only the selected row scrolls. Animating every overflowing row at once would make the whole
        // list move while the user is trying to read one line of it.
        let name = if selected {
            marquee_window(row.label(), name_cells, phase)
        } else {
            truncate_with_ellipsis(row.label(), name_cells)
        };

        Row::new([
            TableCell::from(name),
            TableCell::from(object_type_label(row.object_type().clone())),
            TableCell::from(logical),
            TableCell::from(reclaimable),
            TableCell::from(children),
            TableCell::from(coverage),
        ])
        .style(style)
    });

    let empty_title = if rows.is_empty() {
        if matches!(
            model.current_detail_rescan_state(),
            Some(DetailRescanState::Pending { .. })
        ) {
            scanning_label(model.locale()).to_string()
        } else {
            empty_label(model.locale()).to_string()
        }
    } else {
        contents_title(
            model.locale(),
            model.current_page_bounds(),
            model.current_level_total_rows(),
            model.max_level_rows(),
        )
    };
    let table = Table::new(table_rows, BROWSER_COLUMNS)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(empty_title));
    frame.render_widget(table, area);
}

/// Shortens the root labels of one rendered level so they stay distinct but fit the name column.
///
/// Applied to the level actually on screen rather than at row construction, since the shortest safe
/// label depends on the other roots visible beside it. Non-root rows already show a basename and are
/// left untouched. A single root keeps its full path: there is nothing to disambiguate, and the whole
/// path is the more useful text.
fn shorten_root_labels(rows: &mut [BrowserRow]) {
    let root_paths: Vec<String> = rows
        .iter()
        .filter(|row| row.root)
        .map(|row| row.entry.display_path.clone())
        .collect();
    if root_paths.len() < 2 {
        return;
    }
    let components = root_label_components(&root_paths);
    for row in rows.iter_mut().filter(|row| row.root) {
        row.label = sanitize_terminal_text(&root_label_with_components(
            &row.entry.display_path,
            components,
        ));
    }
}

fn count_value_label(value: &sweepx_model::CountValue) -> String {
    match value {
        sweepx_model::EvidenceValue::Known { value } => value.to_string(),
        sweepx_model::EvidenceValue::LowerBound { value, .. } => format!(">= {value}"),
        sweepx_model::EvidenceValue::Unknown { .. } => "unknown".to_string(),
        sweepx_model::EvidenceValue::Unsupported { .. } => "unsupported".to_string(),
        sweepx_model::EvidenceValue::NotChecked { .. } => "not_checked".to_string(),
    }
}

fn browser_row_coverage_label(row: &BrowserRow) -> String {
    if row.detail_rescan_state().is_stale() {
        "incomplete/stale".to_string()
    } else {
        coverage_label(&row.effective_coverage().state).to_string()
    }
}

/// The footer text, including the pinned full path when the user asked for it.
///
/// The path goes in the footer rather than in the row because the footer spans the whole width and can
/// wrap, while the name column is the very thing that was too narrow. It is wrapped in an explicit
/// marker so a path that itself ends in whitespace, or that is empty, still reads unambiguously.
fn browser_footer_text(model: &BrowserModel) -> String {
    let help = help_text(model.locale());
    let detail = match model.current_detail_rescan_state() {
        Some(DetailRescanState::Stale { revision, failure }) => {
            format!(
                "{help} | detail: incomplete/stale ({}, revision {revision})",
                failure.label()
            )
        }
        Some(DetailRescanState::Refreshed { revision }) => {
            format!("{help} | detail revision {revision}")
        }
        Some(DetailRescanState::Pending { revision }) => {
            format!("{help} | detail: refreshing (revision {revision})")
        }
        _ => help.to_string(),
    };
    if !model.path_detail_shown() {
        return detail;
    }
    // The displayed path is not authority for anything; it is shown so the user can read what the
    // shortened or scrolling label refers to before pressing a key that moves it to the Trash.
    match model.selected_row() {
        Some(row) => format!(
            "{detail}\n{}: [{}]",
            full_path_label(model.locale()),
            sanitize_terminal_text(row.display_path())
        ),
        None => detail,
    }
}

fn full_path_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "完整路径",
        Locale::EnUs => "full path",
    }
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
        Locale::ZhCn => "扫描 + 回收站预览",
        Locale::EnUs => "Scan + Trash preview",
    }
}

fn help_text(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => {
            "↑/↓ 选择  Enter/→ 进入目录  Esc/Backspace/← 返回  p 完整路径  d/Delete 移到回收站  q/Ctrl-C 退出"
        }
        Locale::EnUs => {
            "↑/↓ select  Enter/→ open  Esc/Backspace/← back  p full path  d/Delete move to Trash  q/Ctrl-C quit"
        }
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

fn scanning_label(locale: Locale) -> &'static str {
    match locale {
        Locale::ZhCn => "正在扫描当前目录…",
        Locale::EnUs => "Scanning current directory…",
    }
}

fn contents_title(
    locale: Locale,
    page_bounds: Option<(usize, usize)>,
    total_rows: usize,
    max_level_rows: usize,
) -> String {
    let base = contents_label(locale);
    match page_bounds {
        Some((start, end)) if total_rows > max_level_rows => match locale {
            Locale::ZhCn => format!("{base} ({start}-{end}/{total_rows})"),
            Locale::EnUs => format!("{base} ({start}-{end}/{total_rows})"),
        },
        _ => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Condvar;
    use std::sync::Mutex as StdMutex;

    use crossterm::event::{KeyEventState, KeyModifiers};
    use ratatui::backend::TestBackend;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, EvidenceValue, FieldProvenance,
        FilesystemObjectDomainIdentity, IdentityEvidence, MethodId, NativeAbsolutePath,
        NativeLocatorEvidence, NativeName, NativePathComponent, PlatformFileIdentity, ReasonCode,
        ScanEntryId, ScanId, ScanObjectIdentity, VolumeOrMountIdentity,
    };

    use super::*;

    fn finish_background<P: DetailRescanProvider>(
        reducer: &DetailRescanBrowserReducer<P>,
        model: &mut BrowserModel,
    ) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            reducer.poll_background(model);
            if reducer.pending.borrow().is_none() {
                return;
            }
            thread::sleep(Duration::from_millis(1));
        }
        panic!("detail rescan did not finish");
    }

    #[derive(Clone)]
    struct BlockingProvider {
        state: Arc<(StdMutex<BlockingProviderState>, Condvar)>,
    }

    #[derive(Default)]
    struct BlockingProviderState {
        calls: usize,
        active: usize,
        max_active: usize,
        cancelled: bool,
    }

    impl BlockingProvider {
        fn new() -> Self {
            Self {
                state: Arc::new((
                    StdMutex::new(BlockingProviderState::default()),
                    Condvar::new(),
                )),
            }
        }

        fn wait_until_called(&self) {
            let (state, changed) = &*self.state;
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut state = state.lock().unwrap();
            while state.calls == 0 && Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                state = changed.wait_timeout(state, remaining).unwrap().0;
            }
            assert_eq!(state.calls, 1);
        }
    }

    impl DetailRescanProvider for BlockingProvider {
        fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult {
            let (state, changed) = &*self.state;
            let mut state = state.lock().unwrap();
            state.calls += 1;
            state.active += 1;
            state.max_active = state.max_active.max(state.active);
            changed.notify_all();
            while !state.cancelled {
                state = changed.wait(state).unwrap();
            }
            state.active -= 1;
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Cancelled,
            }
        }

        fn cancel_detail_rescan(&self) {
            let (state, changed) = &*self.state;
            state.lock().unwrap().cancelled = true;
            changed.notify_all();
        }
    }

    fn scan_id() -> ScanId {
        ScanId::new("scan-live")
    }

    fn other_scan_id() -> ScanId {
        ScanId::new("scan-other")
    }

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

    fn incomplete_coverage() -> Coverage {
        Coverage {
            state: CoverageState::Incomplete,
            complete: false,
            incomplete_reasons: vec![ReasonCode::IncompleteStreamCoverage],
            details_lost: false,
            provenance: FieldProvenance::LiveObservation {
                observed_at: "2026-08-27T00:00:00Z".to_string(),
                method: MethodId::MetadataNoFollow,
            },
        }
    }

    fn evicted_coverage() -> Coverage {
        Coverage {
            state: CoverageState::DetailsLost,
            complete: false,
            incomplete_reasons: vec![ReasonCode::ResourceLimit],
            details_lost: true,
            provenance: FieldProvenance::StalePreview {
                observed_at: "2026-08-27T00:00:00Z".to_string(),
            },
        }
    }

    fn entry_id(scan_id: &ScanId, ordinal: u128) -> ScanEntryId {
        ScanEntryId::for_scan_ordinal(scan_id, ordinal).unwrap()
    }

    fn identity(
        scan_id: &ScanId,
        entry_ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
    ) -> ScanObjectIdentity {
        ScanObjectIdentity {
            entry_id: entry_id(scan_id, entry_ordinal),
            scan_root_id: entry_id(scan_id, root_ordinal),
            parent_id: parent_ordinal.map(|ordinal| entry_id(scan_id, ordinal)),
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(root_ordinal),
                inode: DecimalU128::new(entry_ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(root_ordinal),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        }
    }

    fn native_name(value: &str) -> NativeName {
        #[cfg(windows)]
        {
            NativeName::windows_utf16(value.encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(windows))]
        {
            NativeName::unix(value.as_bytes().to_vec())
        }
    }

    fn native_absolute_path(value: &str) -> NativeAbsolutePath {
        #[cfg(windows)]
        {
            let relative = value.trim_start_matches('/').replace('/', "\\");
            NativeAbsolutePath::windows_utf16(
                format!(r"C:\{relative}").encode_utf16().collect::<Vec<_>>(),
            )
        }
        #[cfg(not(windows))]
        {
            NativeAbsolutePath::unix(value.as_bytes().to_vec())
        }
    }

    #[test]
    fn native_fixture_helpers_match_the_host_platform() {
        let name = native_name("child");
        let path = native_absolute_path("/root");
        name.validate_basename_for_current_platform().unwrap();
        path.validate_for_current_platform().unwrap();

        #[cfg(windows)]
        {
            assert!(matches!(name, NativeName::WindowsUtf16(_)));
            assert!(matches!(path, NativeAbsolutePath::WindowsUtf16(_)));
        }
        #[cfg(not(windows))]
        {
            assert!(matches!(name, NativeName::UnixBytes(_)));
            assert!(matches!(path, NativeAbsolutePath::UnixBytes(_)));
        }
    }

    fn entry_with_scan(
        scan_id: ScanId,
        path: &str,
        object_type: ObjectType,
        entry_ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
    ) -> ScannedEntry {
        ScannedEntry {
            scan_id: scan_id.clone(),
            identity: Some(identity(
                &scan_id,
                entry_ordinal,
                root_ordinal,
                parent_ordinal,
            )),
            native_locator: None,
            display_path: path.to_string(),
            native_basename: native_name(&display_basename(path)),
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

    fn native_component(entry: &ScannedEntry) -> NativePathComponent {
        let identity = entry.identity.as_ref().unwrap();
        NativePathComponent {
            entry_id: identity.entry_id.clone(),
            parent_id: identity.parent_id.clone(),
            native_basename: entry.native_basename.clone(),
            object_type: entry.object_type.clone(),
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: entry.metadata_fingerprint.clone(),
        }
    }

    fn attach_root_locator(root: &mut ScannedEntry) {
        let root_component = native_component(root);
        root.native_locator = Some(NativeLocatorEvidence {
            scan_root: root_component.clone(),
            scan_root_absolute_path: Some(native_absolute_path(&root.display_path)),
            parent_reopen_recipe: Vec::new(),
            entry: root_component,
        });
    }

    fn rescan_model(coverage: Coverage) -> BrowserModel {
        let mut root = entry("/root", ObjectType::Directory, 1, 1, None);
        root.coverage = coverage.clone();
        attach_root_locator(&mut root);
        let mut aggregate = aggregate(1);
        aggregate.coverage = coverage;
        BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Partial,
            Some("scan-live".to_string()),
            vec![root],
            vec![entry("/root/old.txt", ObjectType::File, 2, 1, Some(1))],
            vec![aggregate],
        )
        .unwrap()
    }

    fn refreshed_result(
        request: &DetailRescanRequest,
        rows: Vec<ScannedEntry>,
    ) -> DetailRescanResult {
        let mut root = entry("/root", ObjectType::Directory, 1, 1, None);
        attach_root_locator(&mut root);
        let mut aggregate = aggregate(1);
        aggregate.revision = request.binding.revision;
        aggregate.coverage = coverage();
        aggregate.direct_child_count = EvidenceValue::Known {
            value: DecimalU128::new(rows.len() as u128),
        };
        DetailRescanResult::Refreshed(Box::new(RefreshedDetail {
            binding: request.binding.clone(),
            observed_root: root.clone(),
            observed_directory: root,
            rows,
            aggregate,
        }))
    }

    fn progressive_listing_result(
        request: &DetailRescanRequest,
        mut rows: Vec<ScannedEntry>,
    ) -> DetailRescanResult {
        attach_child_locators(request, &mut rows);
        let DetailRescanResult::Refreshed(mut refreshed) = refreshed_result(request, rows) else {
            unreachable!()
        };
        refreshed.aggregate.coverage = incomplete_coverage();
        refreshed.aggregate.arithmetic_state = ArithmeticState::LowerBound;
        DetailRescanResult::Refreshed(refreshed)
    }

    fn progressive_aggregate_result(
        request: &DetailRescanRequest,
        mut rows: Vec<ScannedEntry>,
    ) -> DetailRescanResult {
        attach_child_locators(request, &mut rows);
        refreshed_result(request, rows)
    }

    fn partial_progressive_aggregate_result(
        request: &DetailRescanRequest,
        rows: Vec<ScannedEntry>,
    ) -> DetailRescanResult {
        let DetailRescanResult::Refreshed(mut refreshed) =
            progressive_aggregate_result(request, rows)
        else {
            unreachable!()
        };
        refreshed.aggregate.coverage = incomplete_coverage();
        refreshed.aggregate.arithmetic_state = ArithmeticState::LowerBound;
        DetailRescanResult::Refreshed(refreshed)
    }

    fn progressive_aggregate_progress(
        request: &DetailRescanRequest,
        mut row: ScannedEntry,
        bytes: u128,
    ) -> DetailRescanProgress {
        row.logical_bytes = EvidenceValue::LowerBound {
            value: DecimalU128::new(bytes),
            reason: ReasonCode::IncompleteStreamCoverage,
        };
        row.reclaimable_estimate = row.logical_bytes.clone();
        let mut aggregate = aggregate(1);
        aggregate.revision = request.binding.revision;
        aggregate.coverage = incomplete_coverage();
        aggregate.arithmetic_state = ArithmeticState::LowerBound;
        DetailRescanProgress {
            binding: request.binding.clone(),
            row,
            aggregate,
        }
    }

    fn attach_child_locators(request: &DetailRescanRequest, rows: &mut [ScannedEntry]) {
        for row in rows {
            if row.object_type == ObjectType::Directory {
                let mut locator = request.directory_locator.clone();
                locator.parent_reopen_recipe.push(locator.entry.clone());
                locator.entry = native_component(row);
                row.native_locator = Some(locator);
            }
        }
    }

    fn entry(
        path: &str,
        object_type: ObjectType,
        entry_ordinal: u128,
        root_ordinal: u128,
        parent_ordinal: Option<u128>,
    ) -> ScannedEntry {
        entry_with_scan(
            scan_id(),
            path,
            object_type,
            entry_ordinal,
            root_ordinal,
            parent_ordinal,
        )
    }

    fn legacy_entry(path: &str, object_type: ObjectType) -> ScannedEntry {
        ScannedEntry {
            scan_id: scan_id(),
            identity: None,
            native_locator: None,
            display_path: path.to_string(),
            native_basename: native_name(&display_basename(path)),
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

    fn aggregate_with_scan(scan_id: ScanId, entry_ordinal: u128) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: scan_id.clone(),
            directory_identity: entry_id(&scan_id, entry_ordinal).to_string(),
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

    fn aggregate(entry_ordinal: u128) -> DirectoryAggregate {
        aggregate_with_scan(scan_id(), entry_ordinal)
    }

    fn model() -> BrowserModel {
        BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[entry("/root", ObjectType::Directory, 1, 1, None)],
            &[
                entry("/root/file.txt", ObjectType::File, 2, 1, Some(1)),
                entry("/root/sub", ObjectType::Directory, 3, 1, Some(1)),
                entry("/root/sub/deep.txt", ObjectType::File, 4, 1, Some(3)),
            ],
            &[aggregate(1), aggregate(3)],
        )
        .unwrap()
    }

    fn paged_model(limit: usize, rows: usize) -> BrowserModel {
        BrowserModel::from_owned_scan_parts_with_limits(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            vec![entry("/root", ObjectType::Directory, 1, 1, None)],
            (0..rows)
                .map(|index| {
                    entry(
                        &format!("/root/file-{index:04}"),
                        ObjectType::File,
                        index as u128 + 2,
                        1,
                        Some(1),
                    )
                })
                .collect(),
            vec![aggregate(1)],
            BrowserLoadLimits {
                max_level_rows: limit,
                ..BrowserLoadLimits::default()
            },
        )
        .unwrap()
    }

    /// A root row for label tests, built from the shared entry fixture so it carries real identity.
    fn root_row_for(path: &str) -> BrowserRow {
        BrowserRow::from_owned(
            entry(path, ObjectType::Directory, 1, 1, None),
            None,
            DetailRescanState::Snapshot {
                revision: DecimalU128::ZERO,
            },
            true,
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
    fn the_selected_row_scrolls_in_the_real_render() {
        // Asserted against the widget's own output buffer, not against the helper that produced the
        // string. A helper agreeing with itself proves nothing about what reaches the terminal.
        use ratatui::backend::TestBackend;
        let model = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            vec![entry(
                r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB",
                ObjectType::Directory,
                1,
                1,
                None,
            )],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        let render_at = |phase: usize| -> String {
            let mut terminal = Terminal::new(TestBackend::new(80, 14)).unwrap();
            terminal
                .draw(|frame| render_live_browser_at_phase(frame, frame.area(), &model, phase))
                .unwrap();
            let buffer = terminal.backend().buffer();
            (0..80u16)
                .map(|x| buffer[(x, 8)].symbol().to_string())
                .collect()
        };

        let first = render_at(0);
        let later = render_at(3);
        assert_ne!(first, later, "the selected row must advance between phases");
        // The columns after the name must not move as the label scrolls.
        let type_column_at = |row: &str| row.find("directory");
        assert_eq!(
            type_column_at(&first),
            type_column_at(&later),
            "scrolling must not shift the following columns: {first:?} vs {later:?}"
        );
    }

    #[test]
    fn a_scrolling_window_is_always_exactly_the_column_width() {
        // A short window would let the columns to the right shift as the text scrolls. Wide characters
        // are where this breaks, because one may not fit the last cell and has to become a blank.
        for value in ["ABCDEFGH", "扫描根目录ABC", "a扫b描c根d"] {
            for width in 1..=12usize {
                for phase in 0..24usize {
                    let window = marquee_window(value, width, phase);
                    let cells = text_cells(&window);
                    if overflows(value, width) {
                        assert_eq!(
                            cells, width,
                            "value={value:?} width={width} phase={phase} window={window:?}"
                        );
                    } else {
                        assert_eq!(window, value, "a fitting value must not be altered");
                    }
                }
            }
        }
    }

    #[test]
    fn scrolling_advances_every_step_and_returns_to_the_start() {
        // Two consecutive phases rendering the same text is a visible stutter. It happened for CJK
        // when a partially-scrolled wide character was dropped instead of replaced by a blank.
        let value = "扫描根目录ABC";
        let width = 6;
        let span = text_cells(value) + MARQUEE_GAP;
        let frames: Vec<String> = (0..span)
            .map(|phase| marquee_window(value, width, phase))
            .collect();
        for pair in frames.windows(2) {
            assert_ne!(
                pair[0], pair[1],
                "consecutive frames must differ: {frames:?}"
            );
        }
        assert_eq!(
            marquee_window(value, width, 0),
            marquee_window(value, width, span),
            "the animation must be periodic in span"
        );
    }

    #[test]
    fn an_unselected_overflowing_row_is_marked_as_elided() {
        // The ellipsis is the signal that text is missing; without it a truncated path looks complete.
        let long = r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB";
        let shown = truncate_with_ellipsis(long, 20);
        assert_eq!(text_cells(&shown), 20);
        assert!(shown.ends_with('…'), "got {shown}");
        assert_eq!(
            truncate_with_ellipsis("short", 20),
            "short",
            "a fitting value gets no ellipsis"
        );
    }

    #[test]
    fn a_split_wide_character_never_reaches_the_terminal() {
        // Half a double-width character shifts every following column by one cell. The window must
        // substitute a blank instead of emitting the character.
        let value = "扫描";
        // Skipping into the middle of a wide character yields a blank for the half-cell it still owes.
        assert_eq!(cell_window(value, 0, 1), " ");
        // Width 2 cannot hold that blank plus a 2-cell character, so the remainder is blank too.
        assert_eq!(cell_window(value, 1, 2), "  ");
        // Width 3 fits the owed blank and the next character exactly.
        assert_eq!(cell_window(value, 1, 3), " 描");
        // Every window is exactly the requested width, even when the source runs out.
        assert_eq!(text_cells(&cell_window(value, 1, 4)), 4);
    }

    #[test]
    fn the_computed_name_width_matches_what_the_table_really_renders() {
        // Cross-checked against an actual render rather than against a second copy of the same
        // arithmetic. This is what caught the missing column_spacing: the computation said 11 cells on
        // an 80-column terminal while the widget painted 6, and an overflow threshold five cells too
        // generous truncates nothing on precisely the terminals that need it most.
        use ratatui::backend::TestBackend;
        for width in [80u16, 100, 120] {
            let model = BrowserModel::from_owned_scan_parts(
                Locale::EnUs,
                OutputStatus::Ok,
                Some("scan-live".to_string()),
                // One 'X' per cell, longer than any column can hold, so the painted run reveals the
                // column's true width.
                vec![entry(&"X".repeat(160), ObjectType::Directory, 1, 1, None)],
                Vec::new(),
                Vec::new(),
            )
            .unwrap();
            let mut terminal = Terminal::new(TestBackend::new(width, 14)).unwrap();
            terminal
                .draw(|frame| render_live_browser_at_phase(frame, frame.area(), &model, 0))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let row: String = (0..width)
                .map(|x| buffer[(x, 8)].symbol().to_string())
                .collect();
            let painted = row.chars().filter(|character| *character == 'X').count();
            assert_eq!(
                painted,
                name_column_cells(Rect::new(0, 0, width, 14)),
                "terminal width {width}: computed name width disagrees with the rendered row {row:?}"
            );
        }
    }

    #[test]
    fn pinning_the_path_shows_it_in_full_and_can_be_switched_off() {
        let mut model = model();
        assert!(!model.path_detail_shown());
        assert!(!browser_footer_text(&model).contains("full path: ["));

        ReadOnlyBrowserReducer.reduce(&mut model, BrowserAction::TogglePathDetail);
        assert!(model.path_detail_shown());
        let footer = browser_footer_text(&model);
        assert!(footer.contains("full path: [/root]"), "got {footer}");

        ReadOnlyBrowserReducer.reduce(&mut model, BrowserAction::TogglePathDetail);
        assert!(!model.path_detail_shown());
        assert!(!browser_footer_text(&model).contains("full path: ["));
    }

    #[test]
    fn showing_a_path_is_not_a_destructive_action() {
        assert!(!BrowserAction::TogglePathDetail.is_destructive());
        assert_eq!(
            DefaultBrowserKeyMapper.map_key(&key(KeyCode::Char('p'))),
            Some(BrowserAction::TogglePathDetail)
        );
    }

    #[test]
    fn root_labels_grow_until_no_two_roots_read_alike() {
        // The exact case that a fixed component count got wrong: IndexedDB sits one level shallower
        // than Service Worker\CacheStorage, so four components kept the browser name for the former
        // and dropped it for the latter - Edge and Edge Dev CacheStorage rendered identically.
        let paths: Vec<String> = vec![
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB".to_string(),
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage".to_string(),
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge Dev\User Data\Default\IndexedDB".to_string(),
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge Dev\User Data\Default\Service Worker\CacheStorage".to_string(),
        ];
        let components = root_label_components(&paths);
        let rendered: Vec<String> = paths
            .iter()
            .map(|path| root_label_with_components(path, components))
            .collect();
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            rendered.len(),
            "no two roots may render the same text in a view that can delete: {rendered:?}"
        );
        for label in &rendered {
            assert!(
                label.contains("Edge Dev") || label.contains(r"Edge\"),
                "each label must still name its browser: {label}"
            );
        }
    }

    #[test]
    fn a_lone_root_keeps_its_full_path() {
        // Nothing to disambiguate, and the complete path is the more useful text.
        let mut rows = vec![root_row_for(
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB",
        )];
        shorten_root_labels(&mut rows);
        assert_eq!(
            rows[0].label(),
            r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB"
        );
    }

    #[test]
    fn shortened_root_labels_stay_distinct_and_name_the_browser() {
        let mut rows = vec![
            root_row_for(
                r"C:\Users\LJY\AppData\Local\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage",
            ),
            root_row_for(
                r"C:\Users\LJY\AppData\Local\Microsoft\Edge Dev\User Data\Default\Service Worker\CacheStorage",
            ),
        ];
        shorten_root_labels(&mut rows);
        assert_ne!(rows[0].label(), rows[1].label());
        assert!(rows[0].label().starts_with('…'), "got {}", rows[0].label());
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
            entry_id(&scan_id(), 1).to_string()
        );

        model.enter_selected();
        assert_eq!(model.visible_rows().len(), 2);
        assert!(model.visible_rows()[0].aggregate().is_none());
        assert_eq!(
            model.visible_rows()[1]
                .aggregate()
                .unwrap()
                .directory_identity,
            entry_id(&scan_id(), 3).to_string()
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
                entry("/first", ObjectType::Directory, 1, 1, None),
                entry("/second", ObjectType::Directory, 2, 2, None),
            ],
            &[entry("/second/file", ObjectType::File, 3, 2, Some(2))],
            &[],
        )
        .unwrap();

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
    fn complete_directory_enters_without_rescan_even_when_scan_is_partial() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Unavailable,
            }
        })
        .unwrap();
        let mut model = model();
        model.status = OutputStatus::Partial;

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(model.current_directory(), Some("/root"));
    }

    #[test]
    fn progressive_navigation_paints_direct_rows_then_replaces_them_with_aggregates() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let callback_requests = Arc::clone(&requests);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_requests.lock().unwrap().push(request.clone());
            let mut child = entry("/root/sub", ObjectType::Directory, 2, 1, Some(1));
            child.logical_bytes = EvidenceValue::Known {
                value: DecimalU128::new(
                    if request.reason == DetailRescanReason::ProgressiveListing {
                        0
                    } else {
                        4096
                    },
                ),
            };
            child.reclaimable_estimate = child.logical_bytes.clone();
            if request.reason == DetailRescanReason::ProgressiveListing {
                progressive_listing_result(request, vec![child])
            } else {
                progressive_aggregate_result(request, vec![child])
            }
        })
        .unwrap();
        let mut root = entry("/root", ObjectType::Directory, 1, 1, None);
        attach_root_locator(&mut root);
        let mut model = BrowserModel::from_progressive_roots(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            vec![root],
            Vec::new(),
            HumanSizeUnit::Auto,
            ScanSort::Size,
        )
        .unwrap();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        assert_eq!(model.current_directory(), Some("/root"));
        assert!(model.visible_rows().is_empty());

        let deadline = Instant::now() + Duration::from_secs(1);
        while requests.lock().unwrap().len() < 2 && Instant::now() < deadline {
            reducer.poll_background(&mut model);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].display_path(), "/root/sub");
        assert!(matches!(
            model.visible_rows()[0].entry().logical_bytes,
            EvidenceValue::Known { value } if value == DecimalU128::ZERO
        ));

        finish_background(&reducer, &mut model);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].reason, DetailRescanReason::ProgressiveListing);
        assert_eq!(requests[1].reason, DetailRescanReason::ProgressiveAggregate);
        assert_eq!(model.visible_rows().len(), 1);
        assert!(matches!(
            model.visible_rows()[0].entry().logical_bytes,
            EvidenceValue::Known { value } if value == DecimalU128::new(4096)
        ));
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Refreshed {
                revision: DecimalU128::new(2),
            })
        );
    }

    #[test]
    fn progressive_aggregate_applies_lower_bound_updates_before_completion() {
        #[derive(Clone)]
        struct ProgressProvider {
            sink: Arc<StdMutex<Option<SyncSender<DetailRescanProgress>>>>,
        }

        impl DetailRescanProvider for ProgressProvider {
            fn set_progress_sink(&self, sink: Option<SyncSender<DetailRescanProgress>>) {
                *self.sink.lock().unwrap() = sink;
            }

            fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult {
                let child = entry("/root/sub", ObjectType::Directory, 2, 1, Some(1));
                if request.reason == DetailRescanReason::ProgressiveListing {
                    return progressive_listing_result(request, vec![child]);
                }
                let mut progress_row = child.clone();
                progress_row.identity.as_mut().unwrap().entry_id = entry_id(&scan_id(), 99);
                self.sink
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .send(progressive_aggregate_progress(request, progress_row, 2048))
                    .unwrap();
                thread::sleep(Duration::from_millis(50));
                progressive_aggregate_result(request, vec![child])
            }
        }

        let reducer = DetailRescanBrowserReducer::new(ProgressProvider {
            sink: Arc::new(StdMutex::new(None)),
        })
        .unwrap();
        let mut root = entry("/root", ObjectType::Directory, 1, 1, None);
        attach_root_locator(&mut root);
        let mut model = BrowserModel::from_progressive_roots(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            vec![root],
            Vec::new(),
            HumanSizeUnit::Auto,
            ScanSort::Size,
        )
        .unwrap();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        let deadline = Instant::now() + Duration::from_secs(1);
        while model.visible_rows().is_empty() && Instant::now() < deadline {
            reducer.poll_background(&mut model);
            thread::sleep(Duration::from_millis(1));
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while !matches!(
            model.visible_rows()[0].entry().logical_bytes,
            EvidenceValue::LowerBound { value, .. } if value == DecimalU128::new(2048)
        ) && Instant::now() < deadline
        {
            reducer.poll_background(&mut model);
            thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            model.visible_rows()[0].entry().logical_bytes,
            EvidenceValue::LowerBound { value, .. } if value == DecimalU128::new(2048)
        ));
        assert!(matches!(
            model.current_detail_rescan_state(),
            Some(DetailRescanState::Pending { .. })
        ));
        finish_background(&reducer, &mut model);
    }

    #[test]
    fn progressive_aggregate_keeps_partial_rows_visible() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let callback_requests = Arc::clone(&requests);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_requests.lock().unwrap().push(request.clone());
            let child = entry("/root/sub", ObjectType::Directory, 2, 1, Some(1));
            if request.reason == DetailRescanReason::ProgressiveListing {
                progressive_listing_result(request, vec![child])
            } else {
                partial_progressive_aggregate_result(request, vec![child])
            }
        })
        .unwrap();
        let mut root = entry("/root", ObjectType::Directory, 1, 1, None);
        attach_root_locator(&mut root);
        let mut model = BrowserModel::from_progressive_roots(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            vec![root],
            Vec::new(),
            HumanSizeUnit::Auto,
            ScanSort::Size,
        )
        .unwrap();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);

        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].display_path(), "/root/sub");
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Refreshed {
                revision: DecimalU128::new(2),
            })
        );
    }

    #[test]
    fn incomplete_directory_requests_bound_identity_and_applies_refreshed_rows() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let callback_requests = Arc::clone(&requests);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_requests.lock().unwrap().push(request.clone());
            refreshed_result(
                request,
                vec![entry("/root/new.txt", ObjectType::File, 3, 1, Some(1))],
            )
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].reason, DetailRescanReason::Incomplete);
        assert_eq!(requests[0].max_rows, MAX_PAGE_ROWS);
        assert_eq!(requests[0].binding.base_revision, DecimalU128::new(1));
        assert_eq!(requests[0].binding.revision, DecimalU128::new(2));
        assert_eq!(
            requests[0].binding.source_directory_identity.entry_id,
            entry_id(&scan_id(), 1)
        );
        assert_eq!(model.current_directory(), Some("/root"));
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].display_path(), "/root/new.txt");
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Refreshed {
                revision: DecimalU128::new(2)
            })
        );
    }

    #[test]
    fn evicted_directory_requests_rescan_but_failure_keeps_old_rows_stale() {
        let reducer = DetailRescanBrowserReducer::new(|request: &DetailRescanRequest| {
            assert_eq!(request.reason, DetailRescanReason::Evicted);
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Cancelled,
            }
        })
        .unwrap();
        let mut model = rescan_model(evicted_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);

        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(model.visible_rows()[0].display_path(), "/root/old.txt");
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(2),
                failure: DetailRescanFailure::Cancelled,
            })
        );
        // Assert on the part this test is about. Pinning the whole help string made an unrelated
        // keybinding change fail here, which says nothing about rescan staleness.
        let footer = browser_footer_text(&model);
        assert!(
            footer.starts_with(help_text(Locale::EnUs)),
            "footer must lead with the help line: {footer}"
        );
        assert!(
            footer.ends_with("| detail: incomplete/stale (cancelled, revision 2)"),
            "footer must report the stale detail state: {footer}"
        );
    }

    #[test]
    fn mount_change_and_oversized_result_fail_closed_without_replacing_rows() {
        for failure_mode in [
            DetailRescanFailure::MountChanged,
            DetailRescanFailure::ResourceLimit,
        ] {
            let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
                match failure_mode {
                    DetailRescanFailure::MountChanged => {
                        let mut result = refreshed_result(request, Vec::new());
                        if let DetailRescanResult::Refreshed(refreshed) = &mut result {
                            refreshed
                                .observed_directory
                                .identity
                                .as_mut()
                                .unwrap()
                                .volume_or_mount_identity =
                                IdentityEvidence::known(VolumeOrMountIdentity {
                                    value: DecimalU128::new(99),
                                });
                        }
                        result
                    }
                    DetailRescanFailure::ResourceLimit => refreshed_result(
                        request,
                        (0..=MAX_PAGE_ROWS)
                            .map(|index| {
                                entry(
                                    &format!("/root/file-{index}"),
                                    ObjectType::File,
                                    index as u128 + 3,
                                    1,
                                    Some(1),
                                )
                            })
                            .collect(),
                    ),
                    _ => unreachable!(),
                }
            })
            .unwrap();
            let mut model = rescan_model(incomplete_coverage());

            reducer.reduce(&mut model, BrowserAction::EnterDirectory);
            finish_background(&reducer, &mut model);

            assert_eq!(model.visible_rows().len(), 1);
            assert_eq!(model.visible_rows()[0].display_path(), "/root/old.txt");
            assert_eq!(
                model.current_detail_rescan_state(),
                Some(&DetailRescanState::Stale {
                    revision: DecimalU128::new(2),
                    failure: failure_mode,
                })
            );
        }
    }

    #[test]
    fn identity_mismatch_and_reparse_target_fail_closed() {
        for failure_mode in [
            DetailRescanFailure::IdentityMismatch,
            DetailRescanFailure::SymlinkOrReparse,
        ] {
            let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
                let mut result = refreshed_result(request, Vec::new());
                let DetailRescanResult::Refreshed(refreshed) = &mut result else {
                    unreachable!()
                };
                match failure_mode {
                    DetailRescanFailure::IdentityMismatch => {
                        let replacement_identity = IdentityEvidence::known(PlatformFileIdentity {
                            device: DecimalU128::new(1),
                            inode: DecimalU128::new(99),
                        });
                        refreshed
                            .observed_directory
                            .identity
                            .as_mut()
                            .unwrap()
                            .platform_file_identity = replacement_identity.clone();
                        let locator = refreshed
                            .observed_directory
                            .native_locator
                            .as_mut()
                            .unwrap();
                        locator.scan_root.platform_file_identity = replacement_identity.clone();
                        locator.entry.platform_file_identity = replacement_identity;
                    }
                    DetailRescanFailure::SymlinkOrReparse => {
                        refreshed.observed_directory.object_type = ObjectType::ReparsePoint;
                    }
                    _ => unreachable!(),
                }
                result
            })
            .unwrap();
            let mut model = rescan_model(incomplete_coverage());

            reducer.reduce(&mut model, BrowserAction::EnterDirectory);
            finish_background(&reducer, &mut model);

            assert_eq!(model.visible_rows()[0].display_path(), "/root/old.txt");
            assert_eq!(
                model.current_detail_rescan_state(),
                Some(&DetailRescanState::Stale {
                    revision: DecimalU128::new(2),
                    failure: failure_mode,
                })
            );
        }
    }

    #[test]
    fn mismatched_binding_is_rejected_and_failed_attempts_increment_revision() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            let mut binding = request.binding.clone();
            binding.base_revision = DecimalU128::ZERO;
            DetailRescanResult::Failed {
                binding: Box::new(binding),
                failure: DetailRescanFailure::Cancelled,
            }
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);
        model.return_to_parent();
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(3),
                failure: DetailRescanFailure::InvalidResult,
            })
        );
    }

    #[test]
    fn file_and_symlink_rows_never_request_detail_rescan() {
        for object_type in [
            ObjectType::File,
            ObjectType::Symlink,
            ObjectType::ReparsePoint,
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let callback_calls = Arc::clone(&calls);
            let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                DetailRescanResult::Failed {
                    binding: Box::new(request.binding.clone()),
                    failure: DetailRescanFailure::Unavailable,
                }
            })
            .unwrap();
            let root = entry("/root", ObjectType::Directory, 1, 1, None);
            let mut child = entry("/root/item", object_type, 2, 1, Some(1));
            child.coverage = incomplete_coverage();
            let mut model = BrowserModel::from_owned_scan_parts(
                Locale::EnUs,
                OutputStatus::Partial,
                None,
                vec![root],
                vec![child],
                Vec::new(),
            )
            .unwrap();
            model.enter_selected();

            reducer.reduce(&mut model, BrowserAction::EnterDirectory);

            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(model.current_directory(), Some("/root"));
        }
    }

    #[test]
    fn missing_executable_identity_fails_closed_without_calling_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Unavailable,
            }
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());
        model.nodes[0].entry.native_locator = None;

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(2),
                failure: DetailRescanFailure::IdentityUnavailable,
            })
        );
    }

    #[test]
    fn inconsistent_coverage_does_not_trigger_a_detail_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Unavailable,
            }
        })
        .unwrap();
        let mut malformed = coverage();
        malformed.complete = false;
        let mut model = rescan_model(malformed);

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(model.current_directory(), Some("/root"));
    }

    #[test]
    fn inconsistent_aggregate_and_unknown_row_identity_are_rejected_atomically() {
        for failure_mode in [
            DetailRescanFailure::InvalidResult,
            DetailRescanFailure::IdentityUnavailable,
        ] {
            let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
                let mut row = entry("/root/new.txt", ObjectType::File, 3, 1, Some(1));
                if failure_mode == DetailRescanFailure::IdentityUnavailable {
                    row.identity.as_mut().unwrap().volume_or_mount_identity =
                        IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
                }
                let mut result = refreshed_result(request, vec![row]);
                if failure_mode == DetailRescanFailure::InvalidResult {
                    let DetailRescanResult::Refreshed(refreshed) = &mut result else {
                        unreachable!()
                    };
                    refreshed.aggregate.direct_child_count = EvidenceValue::Known {
                        value: DecimalU128::new(2),
                    };
                }
                result
            })
            .unwrap();
            let mut model = rescan_model(incomplete_coverage());

            reducer.reduce(&mut model, BrowserAction::EnterDirectory);
            finish_background(&reducer, &mut model);

            assert_eq!(model.visible_rows()[0].display_path(), "/root/old.txt");
            assert_eq!(
                model.current_detail_rescan_state(),
                Some(&DetailRescanState::Stale {
                    revision: DecimalU128::new(2),
                    failure: failure_mode,
                })
            );
        }
    }

    #[test]
    fn returned_directory_requires_an_executable_locator() {
        let reducer = DetailRescanBrowserReducer::new(|request: &DetailRescanRequest| {
            refreshed_result(
                request,
                vec![entry(
                    "/root/subdirectory",
                    ObjectType::Directory,
                    3,
                    1,
                    Some(1),
                )],
            )
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        finish_background(&reducer, &mut model);

        assert_eq!(model.visible_rows()[0].display_path(), "/root/old.txt");
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(2),
                failure: DetailRescanFailure::IdentityUnavailable,
            })
        );
    }

    #[test]
    fn revision_exhaustion_does_not_issue_an_unbound_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            DetailRescanResult::Failed {
                binding: Box::new(request.binding.clone()),
                failure: DetailRescanFailure::Unavailable,
            }
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());
        model.nodes[0].detail_rescan_state = DetailRescanState::Snapshot {
            revision: DecimalU128::new(u128::MAX),
        };

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(u128::MAX),
                failure: DetailRescanFailure::RevisionExhausted,
            })
        );
    }

    #[test]
    fn detail_rescan_is_single_flight_and_does_not_block_quit() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let reducer = DetailRescanBrowserReducer::new(provider).unwrap();
        let mut model = rescan_model(incomplete_coverage());

        assert_eq!(
            reducer.reduce(&mut model, BrowserAction::EnterDirectory),
            BrowserControl::Continue
        );
        observer.wait_until_called();
        assert!(model.is_virtual_roots());

        // A second Enter is ignored while the one bounded worker is active.
        assert_eq!(
            reducer.reduce(&mut model, BrowserAction::EnterDirectory),
            BrowserControl::Continue
        );
        let (state, _) = &*observer.state;
        let state = state.lock().unwrap();
        assert_eq!(state.calls, 1);
        assert_eq!(state.max_active, 1);
        drop(state);

        // Quit remains immediately actionable and asks the provider to stop.
        assert_eq!(
            reducer.reduce(&mut model, BrowserAction::Quit),
            BrowserControl::Quit
        );
        assert!(observer.state.0.lock().unwrap().cancelled);
    }

    #[test]
    fn inflight_rescan_allows_navigation_but_rejects_a_second_enter() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let reducer =
            DetailRescanBrowserReducer::try_new_with_deadline(provider, Duration::from_millis(100))
                .unwrap();
        let mut model = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Partial,
            Some("scan-live".to_string()),
            vec![
                {
                    let mut root = entry("/first", ObjectType::Directory, 1, 1, None);
                    root.coverage = incomplete_coverage();
                    attach_root_locator(&mut root);
                    root
                },
                entry("/second", ObjectType::Directory, 2, 2, None),
            ],
            Vec::new(),
            vec![{
                let mut aggregate = aggregate(1);
                aggregate.coverage = incomplete_coverage();
                aggregate
            }],
        )
        .unwrap();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        observer.wait_until_called();
        reducer.reduce(&mut model, BrowserAction::MoveDown);
        assert_eq!(model.selected_row().unwrap().display_path(), "/second");
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        assert!(model.is_virtual_roots());
        assert_eq!(observer.state.0.lock().unwrap().calls, 1);
        thread::sleep(Duration::from_millis(110));
        reducer.poll_background(&mut model);
        assert!(model.is_virtual_roots());
        assert_eq!(model.selected_row().unwrap().display_path(), "/second");
        assert_eq!(observer.state.0.lock().unwrap().calls, 1);

        reducer.reduce(&mut model, BrowserAction::MoveUp);
        assert_eq!(model.selected_row().unwrap().display_path(), "/first");
        reducer.reduce(&mut model, BrowserAction::ReturnToParent);
        assert!(model.is_virtual_roots());
        assert_eq!(observer.state.0.lock().unwrap().calls, 1);
    }

    #[test]
    fn inflight_rescan_allows_back_and_discards_the_completion() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let reducer = DetailRescanBrowserReducer::new(provider).unwrap();
        let mut model = rescan_model(coverage());
        model.enter_selected();
        model.nodes[1].entry.object_type = ObjectType::Directory;
        model.nodes[1].entry.coverage = incomplete_coverage();
        model.nodes[1].aggregate = Some({
            let mut aggregate = aggregate(2);
            aggregate.coverage = incomplete_coverage();
            aggregate
        });
        model.nodes[1].entry.native_locator = model.nodes[0].entry.native_locator.clone();
        let child_identity = model.nodes[1].entry.identity.clone().unwrap();
        let child_component = native_component(&model.nodes[1].entry);
        if let Some(locator) = &mut model.nodes[1].entry.native_locator {
            locator.entry = child_component;
            locator.parent_reopen_recipe = vec![locator.scan_root.clone()];
            locator.entry.entry_id = child_identity.entry_id.clone();
            locator.entry.parent_id = child_identity.parent_id.clone();
        }
        model.reload_loaded_level();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        observer.wait_until_called();
        reducer.reduce(&mut model, BrowserAction::ReturnToParent);
        assert!(model.is_virtual_roots());

        reducer.cancel_background();
        finish_background(&reducer, &mut model);
        assert!(model.is_virtual_roots());
        assert_eq!(model.visible_rows()[0].display_path(), "/root");
    }

    #[test]
    fn event_loop_accepts_quit_keys_while_detail_rescan_is_running() {
        let quit_keys = [
            key(KeyCode::Char('q')),
            KeyEvent {
                modifiers: KeyModifiers::CONTROL,
                ..key(KeyCode::Char('c'))
            },
        ];
        for quit_key in quit_keys {
            let provider = BlockingProvider::new();
            let observer = provider.clone();
            let reducer = DetailRescanBrowserReducer::new(provider).unwrap();
            let backend = TestBackend::new(80, 14);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut model = rescan_model(incomplete_coverage());
            let mut events = ScriptedEvents {
                events: VecDeque::from([
                    Some(Event::Key(key(KeyCode::Enter))),
                    Some(Event::Key(quit_key)),
                ]),
                polls: Vec::new(),
            };

            let exit = run_browser_loop(
                &mut terminal,
                &mut model,
                &mut events,
                &DefaultBrowserKeyMapper,
                &reducer,
            )
            .unwrap();

            assert_eq!(exit, BrowserExit::Quit);
            assert_eq!(events.polls.len(), 2);
            drop(reducer);
            assert!(observer.state.0.lock().unwrap().cancelled);
        }
    }

    #[test]
    fn event_loop_termination_cancels_an_inflight_detail_rescan() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let reducer = DetailRescanBrowserReducer::new(provider).unwrap();
        let backend = TestBackend::new(80, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = rescan_model(incomplete_coverage());
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        observer.wait_until_called();
        let terminated = AtomicUsize::new(15);
        let mut events = ScriptedEvents {
            events: VecDeque::new(),
            polls: Vec::new(),
        };

        let exit = run_browser_loop_until(
            &mut terminal,
            &mut model,
            &mut events,
            &DefaultBrowserKeyMapper,
            &reducer,
            &terminated,
        )
        .unwrap();

        assert_eq!(exit, BrowserExit::Terminated { signal: Some(15) });
        assert!(events.polls.is_empty());
        drop(reducer);
        assert!(observer.state.0.lock().unwrap().cancelled);
    }

    #[test]
    fn dropping_reducer_cancels_and_joins_the_only_worker() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let mut model = rescan_model(incomplete_coverage());
        let reducer = DetailRescanBrowserReducer::new(provider).unwrap();

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        observer.wait_until_called();
        drop(reducer);

        let state = observer.state.0.lock().unwrap();
        assert!(state.cancelled);
        assert_eq!(state.active, 0);
        assert_eq!(state.max_active, 1);
    }

    #[test]
    fn non_cooperative_worker_is_quarantined_after_the_deadline() {
        let release = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_release = Arc::clone(&release);
        let reducer = DetailRescanBrowserReducer::try_new_with_deadline(
            move |request: &DetailRescanRequest| {
                let (released, changed) = &*worker_release;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
                DetailRescanResult::Failed {
                    binding: Box::new(request.binding.clone()),
                    failure: DetailRescanFailure::Cancelled,
                }
            },
            Duration::from_millis(10),
        )
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());
        reducer.reduce(&mut model, BrowserAction::EnterDirectory);

        let started = Instant::now();
        drop(reducer);
        assert!(started.elapsed() < Duration::from_secs(1));

        let (released, changed) = &*release;
        *released.lock().unwrap() = true;
        changed.notify_all();
    }

    #[test]
    fn repeated_non_cooperative_workers_exhaust_a_strict_shared_limit() {
        let limiter = Arc::new(DetailRescanWorkerLimiter::new(2));
        let release = Arc::new((StdMutex::new(false), Condvar::new()));
        let mut reducers = Vec::new();
        for _ in 0..2 {
            let worker_release = Arc::clone(&release);
            let reducer = DetailRescanBrowserReducer::try_new_with_limiter(
                move |request: &DetailRescanRequest| {
                    let (released, changed) = &*worker_release;
                    let mut released = released.lock().unwrap();
                    while !*released {
                        released = changed.wait(released).unwrap();
                    }
                    DetailRescanResult::Failed {
                        binding: Box::new(request.binding.clone()),
                        failure: DetailRescanFailure::Cancelled,
                    }
                },
                Duration::from_millis(1),
                Arc::clone(&limiter),
            )
            .unwrap();
            let mut model = rescan_model(incomplete_coverage());
            reducer.reduce(&mut model, BrowserAction::EnterDirectory);
            thread::sleep(Duration::from_millis(2));
            drop(reducer);
            reducers.push(model);
        }
        assert_eq!(limiter.active.load(Ordering::Acquire), 2);

        let error = match DetailRescanBrowserReducer::try_new_with_limiter(
            UnavailableDetailRescanProvider,
            Duration::from_millis(1),
            Arc::clone(&limiter),
        ) {
            Ok(_) => panic!("worker capacity must be exhausted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            BrowserError::DetailRescanWorkerCapacity { limit: 2 }
        ));

        let (released, changed) = &*release;
        *released.lock().unwrap() = true;
        changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(1);
        while limiter.active.load(Ordering::Acquire) != 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(limiter.active.load(Ordering::Acquire), 0);
        drop(reducers);
    }

    #[test]
    fn detail_rescan_deadline_is_visible_and_late_result_is_discarded() {
        let provider = BlockingProvider::new();
        let observer = provider.clone();
        let reducer =
            DetailRescanBrowserReducer::try_new_with_deadline(provider, Duration::from_millis(1))
                .unwrap();
        let mut model = rescan_model(incomplete_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        observer.wait_until_called();
        thread::sleep(Duration::from_millis(2));
        reducer.poll_background(&mut model);

        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(2),
                failure: DetailRescanFailure::TimedOut,
            })
        );
        assert_eq!(model.current_directory(), Some("/root"));
        assert!(observer.state.0.lock().unwrap().cancelled);

        finish_background(&reducer, &mut model);
        assert_eq!(
            model.current_detail_rescan_state(),
            Some(&DetailRescanState::Stale {
                revision: DecimalU128::new(2),
                failure: DetailRescanFailure::TimedOut,
            })
        );
    }

    #[test]
    fn completed_result_is_discarded_after_selection_binding_changes() {
        let release = Arc::new((StdMutex::new(false), Condvar::new()));
        let worker_release = Arc::clone(&release);
        let reducer = DetailRescanBrowserReducer::new(move |request: &DetailRescanRequest| {
            let (released, changed) = &*worker_release;
            let mut released = released.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            refreshed_result(
                request,
                vec![entry("/root/new.txt", ObjectType::File, 3, 1, Some(1))],
            )
        })
        .unwrap();
        let mut model = rescan_model(incomplete_coverage());

        reducer.reduce(&mut model, BrowserAction::EnterDirectory);
        model.nodes[0].detail_rescan_state = DetailRescanState::Snapshot {
            revision: DecimalU128::new(99),
        };
        model.reload_loaded_level();
        let (released, changed) = &*release;
        *released.lock().unwrap() = true;
        changed.notify_all();
        finish_background(&reducer, &mut model);

        assert!(model.is_virtual_roots());
        assert_eq!(
            model.nodes[0].detail_rescan_state,
            DetailRescanState::Snapshot {
                revision: DecimalU128::new(99)
            }
        );
        assert_eq!(model.visible_rows()[0].display_path(), "/root");
    }

    #[test]
    fn symlink_and_reparse_rows_cannot_be_entered() {
        for object_type in [ObjectType::Symlink, ObjectType::ReparsePoint] {
            let mut model = BrowserModel::from_scan_parts(
                Locale::EnUs,
                OutputStatus::Ok,
                None,
                &[entry("/root", ObjectType::Directory, 1, 1, None)],
                &[entry("/root/link", object_type.clone(), 2, 1, Some(1))],
                &[],
            )
            .unwrap();
            model.enter_selected();
            assert_eq!(model.visible_rows().len(), 1);
            assert!(!model.selected_row().unwrap().can_enter());
            model.enter_selected();
            assert_eq!(model.current_directory(), Some("/root"));

            let error = BrowserModel::from_scan_parts(
                Locale::EnUs,
                OutputStatus::Ok,
                None,
                &[entry("/root", ObjectType::Directory, 1, 1, None)],
                &[
                    entry("/root/link", object_type.clone(), 2, 1, Some(1)),
                    entry("/root/link/hidden", ObjectType::File, 3, 1, Some(2)),
                ],
                &[],
            )
            .unwrap_err();
            assert_eq!(
                error,
                BrowserModelError::ParentNotDirectory {
                    entry_id: entry_id(&scan_id(), 3).to_string(),
                    parent_id: entry_id(&scan_id(), 2).to_string(),
                }
            );
        }
    }

    #[test]
    fn default_key_mapping_includes_explicit_trash_and_ignores_release() {
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
        assert_eq!(
            mapper.map_key(&key(KeyCode::Delete)),
            Some(BrowserAction::TrashSelected)
        );
        assert_eq!(
            mapper.map_key(&key(KeyCode::Char('d'))),
            Some(BrowserAction::TrashSelected)
        );
        assert!(BrowserAction::TrashSelected.is_destructive());
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
        assert!(rendered.contains("Scan + Trash preview"));
        assert_eq!(
            events.polls,
            [BROWSER_EVENT_POLL_INTERVAL, BROWSER_EVENT_POLL_INTERVAL]
        );
    }

    #[test]
    fn delete_key_returns_the_selected_live_scan_entry() {
        let backend = TestBackend::new(100, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = model();
        let expected = model.selected_row().unwrap().entry().clone();
        let mut events = ScriptedEvents {
            events: VecDeque::from([Some(Event::Key(key(KeyCode::Delete)))]),
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

        assert_eq!(
            exit,
            BrowserExit::TrashSelected {
                entry: Box::new(expected),
            }
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
    fn aggregates_are_joined_by_scan_entry_id() {
        let mut model = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            vec![
                entry("/root", ObjectType::Directory, 1, 1, None),
                entry("/z-root", ObjectType::Directory, 2, 2, None),
            ],
            vec![
                entry("/elsewhere/z.txt", ObjectType::File, 3, 1, Some(1)),
                entry("/not-lexical/dir", ObjectType::Directory, 4, 1, Some(1)),
                entry("/elsewhere/a.txt", ObjectType::File, 5, 1, Some(1)),
            ],
            vec![aggregate(4)],
        )
        .unwrap();

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
            ["/elsewhere/a.txt", "/elsewhere/z.txt", "/not-lexical/dir"]
        );
        let directory = &model.visible_rows()[2];
        assert_eq!(
            directory.aggregate().unwrap().directory_identity,
            entry_id(&scan_id(), 4).to_string()
        );
    }

    #[test]
    fn constructor_rejects_legacy_entries_without_identity() {
        let error = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[legacy_entry("/root", ObjectType::Directory)],
            &[],
            &[],
        )
        .unwrap_err();

        assert_eq!(
            error,
            BrowserModelError::MissingIdentity {
                display_path: "/root".to_string()
            }
        );
    }

    #[test]
    fn constructor_rejects_entry_limit_before_building() {
        let error = BrowserModel::from_scan_parts_with_limits(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[entry("/root", ObjectType::Directory, 1, 1, None)],
            &[entry("/root/file.txt", ObjectType::File, 2, 1, Some(1))],
            &[],
            BrowserLoadLimits {
                max_level_rows: 10,
                max_entries: 1,
                max_index_bytes: DEFAULT_MAX_BROWSER_INDEX_BYTES,
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            BrowserModelError::ResourceLimit {
                kind: BrowserResourceLimitKind::Entries,
                limit: 1,
                observed: 2,
            }
        );
    }

    #[test]
    fn caller_limits_can_only_tighten_architectural_caps() {
        let normalized = normalized_limits(BrowserLoadLimits {
            max_level_rows: usize::MAX,
            max_entries: usize::MAX,
            max_index_bytes: usize::MAX,
        });

        assert_eq!(normalized.max_level_rows, MAX_PAGE_ROWS);
        assert_eq!(normalized.max_entries, DEFAULT_MAX_BROWSER_ENTRIES);
        assert_eq!(normalized.max_index_bytes, DEFAULT_MAX_BROWSER_INDEX_BYTES);
    }

    #[test]
    fn constructor_rejects_index_byte_limit_before_building() {
        let error = BrowserModel::from_scan_parts_with_limits(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[entry("/root", ObjectType::Directory, 1, 1, None)],
            &[entry("/root/file.txt", ObjectType::File, 2, 1, Some(1))],
            &[aggregate(1)],
            BrowserLoadLimits {
                max_level_rows: 1,
                max_entries: 10,
                max_index_bytes: 1,
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            BrowserModelError::ResourceLimit {
                kind: BrowserResourceLimitKind::IndexBytes,
                limit: 1,
                observed: _,
            }
        ));
    }

    #[test]
    fn constructor_rejects_duplicate_aggregate_targets() {
        let error = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-live".to_string()),
            &[entry("/root", ObjectType::Directory, 1, 1, None)],
            &[],
            &[aggregate(1), aggregate(1)],
        )
        .unwrap_err();

        assert_eq!(
            error,
            BrowserModelError::DuplicateAggregate {
                entry_id: entry_id(&scan_id(), 1).to_string()
            }
        );
    }

    #[test]
    fn constructor_rejects_explicit_scan_id_mismatch() {
        let error = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            Some("scan-other".to_string()),
            &[entry("/root", ObjectType::Directory, 1, 1, None)],
            &[],
            &[],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            BrowserModelError::SnapshotScanMismatch { .. }
        ));
    }

    #[test]
    fn constructor_rejects_mixed_scan_payloads() {
        let error = BrowserModel::from_owned_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            vec![entry("/root", ObjectType::Directory, 1, 1, None)],
            vec![entry_with_scan(
                other_scan_id(),
                "/root/file.txt",
                ObjectType::File,
                2,
                1,
                Some(1),
            )],
            vec![],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            BrowserModelError::SnapshotScanMismatch { .. }
        ));
    }

    #[test]
    fn terminal_control_characters_are_sanitized_in_labels_and_breadcrumbs() {
        let malicious = "/root/\u{1b}]52;c;clipboard\u{7}";
        let mut model = BrowserModel::from_scan_parts(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            &[entry(malicious, ObjectType::Directory, 1, 1, None)],
            &[],
            &[],
        )
        .unwrap();

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

    #[test]
    fn large_directory_keeps_only_a_bounded_page_loaded() {
        let mut model = paged_model(5, 13);
        model.enter_selected();

        assert_eq!(model.current_level_total_rows(), 13);
        assert_eq!(model.visible_rows().len(), 5);
        assert_eq!(model.current_page_bounds(), Some((1, 5)));
        assert_eq!(model.visible_rows()[0].display_path(), "/root/file-0000");
        assert_eq!(model.visible_rows()[4].display_path(), "/root/file-0004");

        for _ in 0..5 {
            model.move_down();
        }

        assert_eq!(model.selected_index(), 0);
        assert_eq!(model.current_page_bounds(), Some((6, 10)));
        assert_eq!(
            model.selected_row().unwrap().display_path(),
            "/root/file-0005"
        );
        assert_eq!(model.visible_rows().len(), 5);

        for _ in 0..5 {
            model.move_down();
        }

        assert_eq!(model.current_page_bounds(), Some((11, 13)));
        assert_eq!(model.visible_rows().len(), 3);
        assert_eq!(
            model.selected_row().unwrap().display_path(),
            "/root/file-0010"
        );
    }

    #[test]
    fn returning_to_parent_restores_selection_across_root_pages() {
        let mut roots = Vec::new();
        for index in 0..8 {
            let ordinal = index as u128 + 1;
            roots.push(entry(
                &format!("/root-{index:04}"),
                ObjectType::Directory,
                ordinal,
                ordinal,
                None,
            ));
        }
        let mut model = BrowserModel::from_owned_scan_parts_with_limits(
            Locale::EnUs,
            OutputStatus::Ok,
            None,
            roots,
            vec![entry(
                "/root-0005/file.txt",
                ObjectType::File,
                9,
                6,
                Some(6),
            )],
            vec![],
            BrowserLoadLimits {
                max_level_rows: 3,
                ..BrowserLoadLimits::default()
            },
        )
        .unwrap();

        for _ in 0..5 {
            model.move_down();
        }
        assert_eq!(model.current_page_bounds(), Some((4, 6)));
        assert_eq!(model.selected_row().unwrap().display_path(), "/root-0005");

        model.enter_selected();
        assert_eq!(model.current_directory(), Some("/root-0005"));
        assert_eq!(model.visible_rows().len(), 1);
        assert_eq!(
            model.visible_rows()[0].display_path(),
            "/root-0005/file.txt"
        );

        model.return_to_parent();
        assert!(model.is_virtual_roots());
        assert_eq!(model.current_page_bounds(), Some((4, 6)));
        assert_eq!(model.selected_index(), 2);
        assert_eq!(model.selected_row().unwrap().display_path(), "/root-0005");
    }

    #[test]
    fn render_shows_current_page_window_for_large_levels() {
        let backend = TestBackend::new(100, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut model = paged_model(4, 10);
        model.enter_selected();
        for _ in 0..4 {
            model.move_down();
        }

        terminal
            .draw(|frame| render_live_browser(frame, frame.area(), &model))
            .unwrap();

        let rendered = rendered_text(terminal.backend());
        assert!(rendered.contains("Contents (5-8/10)"));
        assert!(rendered.contains("file-0004"));
        assert!(rendered.contains("file-0007"));
        assert!(!rendered.contains("file-0003"));
    }
}
