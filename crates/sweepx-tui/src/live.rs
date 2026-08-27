use std::collections::HashMap;
use std::io::{self, Write};
use std::mem::size_of;
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
use sweepx_model::{
    DirectoryAggregate, FieldProvenance, NativeName, ObjectType, ScanEntryId, ScanEntryIdError,
    ScanObjectIdentity, ScannedEntry,
};
use sweepx_protocol::OutputStatus;
use thiserror::Error;

use crate::{
    MAX_PAGE_ROWS, byte_value_label, coverage_label, object_type_label, output_status_label,
};

pub const BROWSER_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const DEFAULT_MAX_BROWSER_ENTRIES: usize = 16_384;
pub const DEFAULT_MAX_BROWSER_INDEX_BYTES: usize = 48 * 1024 * 1024;

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
    root: bool,
}

impl BrowserNode {
    fn to_row(&self) -> BrowserRow {
        BrowserRow::from_owned(self.entry.clone(), self.aggregate.clone(), self.root)
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
            .map(|(pending, aggregate)| BrowserNode {
                entry: pending.entry,
                aggregate,
                root: pending.root,
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
        };
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
        let rows = row_indices
            .iter()
            .map(|index| self.nodes[*index].to_row())
            .collect();
        self.loaded_level = LoadedLevel {
            total_rows,
            page_start,
            row_indices,
            rows,
        };
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
        empty_label(model.locale()).to_string()
    } else {
        contents_title(
            model.locale(),
            model.current_page_bounds(),
            model.current_level_total_rows(),
            model.max_level_rows(),
        )
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

    use crossterm::event::{KeyEventState, KeyModifiers};
    use ratatui::backend::TestBackend;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, EvidenceValue, FieldProvenance,
        FilesystemObjectDomainIdentity, IdentityEvidence, MethodId, NativeName,
        PlatformFileIdentity, ReasonCode, ScanEntryId, ScanId, ScanObjectIdentity,
        VolumeOrMountIdentity,
    };

    use super::*;

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
