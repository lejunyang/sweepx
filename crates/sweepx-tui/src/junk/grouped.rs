//! Bounded hierarchy over admitted rows. Group keys and paths are presentation only.

use super::*;
use sweepx_model::{DecimalU128, ReasonCode};

/// Optional application/project grouping supplied by the shared candidate interpreter.
#[derive(Clone, Debug)]
pub struct JunkGrouping {
    /// Stable category key.
    pub category: String,
    /// Localized category name.
    pub category_label: String,
    /// Stable application or source-location key; not filesystem authority.
    pub owner: String,
    /// Application name or source-directory basename.
    pub owner_label: String,
    /// Whether the label names a recognized application/tool rather than a source location.
    pub named_application: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
enum Location {
    #[default]
    Categories,
    Owners(String),
    Items(String, String),
    Children(String),
}

struct Node {
    id: String,
    label: String,
    keys: Vec<String>,
    bytes: ByteValue,
    past_bytes: Option<ByteValue>,
    next: Location,
    candidate: Option<String>,
}

#[derive(Default)]
pub(super) struct GroupedView {
    location: Location,
    title: String,
    stack: Vec<(Location, usize)>,
    nodes: Vec<Node>,
    parents: BTreeMap<String, String>,
    cursor: usize,
    pub(super) preview: Option<(u64, Vec<String>)>,
    preview_offset: u16,
}

impl GroupedView {
    pub(super) fn focused_keys(&self) -> Vec<String> {
        self.nodes
            .get(self.cursor)
            .map_or_else(Vec::new, |node| node.keys.clone())
    }
}

fn roots<'a>(keys: &'a [String], parents: &BTreeMap<String, String>) -> Vec<&'a String> {
    let set: BTreeSet<_> = keys.iter().collect();
    keys.iter()
        .filter(|key| {
            let mut current = key.as_str();
            while let Some(parent) = parents.get(current) {
                if set.contains(parent) {
                    return false;
                }
                current = parent;
            }
            true
        })
        .collect()
}

fn contains(parents: &BTreeMap<String, String>, ancestor: &str, key: &str) -> bool {
    let mut current = key;
    loop {
        if current == ancestor {
            return true;
        }
        let Some(parent) = parents.get(current) else {
            return false;
        };
        current = parent;
    }
}

fn effectively_selected(model: &JunkModel, view: &GroupedView, key: &str) -> bool {
    let mut current = key;
    loop {
        if model.marked.contains(current) {
            return true;
        }
        let Some(parent) = view.parents.get(current) else {
            return false;
        };
        current = parent;
    }
}

fn total(model: &JunkModel, keys: &[String], parents: &BTreeMap<String, String>) -> ByteValue {
    sum_rows(model, keys, parents, false)
}

fn sum_rows(
    model: &JunkModel,
    keys: &[String],
    parents: &BTreeMap<String, String>,
    historical: bool,
) -> ByteValue {
    let mut sum = 0u128;
    let mut incomplete = false;
    let mut known = false;
    for key in roots(keys, parents) {
        let Some(row) = model.rows.get(key) else {
            incomplete = true;
            continue;
        };
        // A historical amount is useful in row details but cannot become a current group total.
        if !historical && (row.historical || !row.current) && !row.observed_partial {
            incomplete = true;
            continue;
        }
        incomplete |= (!historical && (row.historical || !row.current)) || !row.row.complete();
        let value = match row.row.logical_bytes() {
            EvidenceValue::Known { value } => value.0,
            EvidenceValue::LowerBound { value, .. } => {
                incomplete = true;
                value.0
            }
            _ => {
                incomplete = true;
                continue;
            }
        };
        let Some(next) = sum.checked_add(value) else {
            return EvidenceValue::Unknown {
                reason: ReasonCode::Overflow,
            };
        };
        sum = next;
        known = true;
    }
    if incomplete && !known {
        EvidenceValue::Unknown {
            reason: ReasonCode::NotRevalidated,
        }
    } else if incomplete {
        EvidenceValue::LowerBound {
            value: DecimalU128::new(sum),
            reason: ReasonCode::NotRevalidated,
        }
    } else {
        EvidenceValue::Known {
            value: DecimalU128::new(sum),
        }
    }
}

fn item_label(row: &dyn JunkRow, locale: Locale) -> String {
    let path = std::path::Path::new(row.path());
    let name = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy();
    let parent = path
        .parent()
        .and_then(std::path::Path::file_name)
        .map(|name| name.to_string_lossy());
    let location = parent.map_or_else(|| name.to_string(), |parent| format!("{parent}/{name}"));
    format!("{} · {location}", rule_label(row.rule(), locale))
}

impl JunkModel {
    pub(super) fn rebuild_groups(&mut self) {
        let Some(mut view) = self.grouped.take() else {
            return;
        };
        let selected = view.nodes.get(view.cursor).map(|node| node.id.clone());
        // Join captured identities, never path prefixes. Strictly increasing ancestor depth
        // prevents malformed provider input from forming a cycle. Work is bounded by retained
        // rows and their existing lineage, and runs only after data/navigation changes.
        let identities: BTreeMap<_, _> = self
            .rows
            .iter()
            .filter_map(|(key, row)| row.row.entry_identity().map(|id| (id, key)))
            .collect();
        let ancestors: BTreeMap<_, _> = self
            .rows
            .iter()
            .map(|(key, row)| (key, row.row.ancestor_identities()))
            .collect();
        view.parents.clear();
        for (key, ids) in &ancestors {
            if let Some(parent) = ids
                .iter()
                .filter_map(|id| identities.get(id).copied())
                .filter(|parent| *parent != *key && ancestors[parent].len() < ids.len())
                .max_by_key(|parent| ancestors[parent].len())
            {
                view.parents.insert((*key).clone(), parent.clone());
            }
        }
        // Every descendant inherits its outer candidate's accounting group. This prevents
        // generic and specific nested rules from inflating different category totals.
        let mut top = BTreeMap::new();
        for key in self.rows.keys() {
            let mut root = key;
            while let Some(parent) = view.parents.get(root) {
                root = parent;
            }
            top.insert(key.clone(), root.clone());
        }
        let groups: BTreeMap<_, _> = top
            .values()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|key| {
                self.rows[key]
                    .row
                    .grouping(self.locale)
                    .map(|group| (key.clone(), group))
            })
            .collect();
        let fallback = JunkGrouping {
            category: "review".into(),
            category_label: self.text("待单独核验", "Separate review required").into(),
            owner: "unknown".into(),
            owner_label: self.text("未识别来源", "Unidentified source").into(),
            named_application: false,
        };
        loop {
            view.title = match &view.location {
                Location::Categories => self.text("分类总览", "Categories").into(),
                Location::Owners(category) => groups
                    .values()
                    .find(|group| &group.category == category)
                    .map_or_else(
                        || self.text("扫描结果", "Results").into(),
                        |group| group.category_label.clone(),
                    ),
                Location::Items(_, owner) => owner.clone(),
                Location::Children(key) => self.rows.get(key).map_or_else(
                    || self.text("候选已移除", "Candidate removed").into(),
                    |row| row.row.path().into(),
                ),
            };
            let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
            for key in self.rows.keys() {
                let outer = &top[key];
                let group = groups.get(outer).unwrap_or(&fallback);
                let (id, label, next, candidate) = match &view.location {
                    Location::Categories => (
                        group.category.clone(),
                        group.category_label.clone(),
                        Location::Owners(group.category.clone()),
                        None,
                    ),
                    Location::Owners(category) if category == &group.category => {
                        let label = if group.named_application {
                            group.owner_label.clone()
                        } else {
                            format!(
                                "{} · {}",
                                group.owner_label,
                                self.text("来源目录", "source location")
                            )
                        };
                        (
                            group.owner.clone(),
                            label,
                            Location::Items(category.clone(), group.owner.clone()),
                            None,
                        )
                    }
                    Location::Items(category, owner)
                        if category == &group.category && owner == &group.owner =>
                    {
                        (
                            outer.clone(),
                            item_label(self.rows[outer].row.as_ref(), self.locale),
                            Location::Children(outer.clone()),
                            Some(outer.clone()),
                        )
                    }
                    Location::Children(parent) => {
                        let mut child = key;
                        while let Some(ancestor) = view.parents.get(child) {
                            if ancestor == parent {
                                break;
                            }
                            child = ancestor;
                        }
                        if view.parents.get(child) != Some(parent) {
                            continue;
                        }
                        (
                            child.clone(),
                            item_label(self.rows[child].row.as_ref(), self.locale),
                            Location::Children(child.clone()),
                            Some(child.clone()),
                        )
                    }
                    _ => continue,
                };
                nodes
                    .entry(id.clone())
                    .or_insert_with(|| Node {
                        id,
                        label,
                        keys: Vec::new(),
                        bytes: EvidenceValue::Unknown {
                            reason: ReasonCode::NotRevalidated,
                        },
                        past_bytes: None,
                        next,
                        candidate,
                    })
                    .keys
                    .push(key.clone());
            }
            view.nodes =
                nodes
                    .into_values()
                    .map(|mut node| {
                        node.bytes = total(self, &node.keys, &view.parents);
                        if node.keys.iter().all(|key| {
                            self.rows[key].historical && !self.rows[key].observed_partial
                        }) {
                            node.past_bytes = Some(sum_rows(self, &node.keys, &view.parents, true));
                        }
                        node
                    })
                    .collect();
            if !view.nodes.is_empty() || matches!(view.location, Location::Categories) {
                break;
            }
            // A freshly completed outer candidate can absorb the source/category the user
            // entered while scanning. Recover through the existing bounded navigation stack
            // instead of trapping keyboard navigation in a permanently empty location.
            if let Some((location, cursor)) = view.stack.pop() {
                view.location = location;
                view.cursor = cursor;
            } else {
                view.location = Location::Categories;
            }
        }
        view.nodes.sort_by(|a, b| {
            let value = |node: &Node| match node.past_bytes.as_ref().unwrap_or(&node.bytes) {
                EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => {
                    Some(value.0)
                }
                _ => None,
            };
            let size = if self.sort == ScanSort::Size {
                value(b).cmp(&value(a))
            } else {
                std::cmp::Ordering::Equal
            };
            size.then(a.label.cmp(&b.label)).then(a.id.cmp(&b.id))
        });
        view.cursor = selected
            .and_then(|id| view.nodes.iter().position(|node| node.id == id))
            .unwrap_or(view.cursor)
            .min(view.nodes.len().saturating_sub(1));
        self.grouped = Some(view);
    }

    pub(super) fn finish_group_selection(&mut self) {
        if !self.busy
            && let Some(keys) = self.pending_selection.take()
        {
            self.group_select(keys);
        }
    }

    fn group_select_or_check<P: JunkProvider>(&mut self, keys: Vec<String>, provider: &mut P) {
        if !self.busy {
            let actionable: Vec<_> = keys
                .iter()
                .filter(|key| {
                    self.rows.get(*key).is_some_and(|row| {
                        row.current && row.row.complete() && row.row.report_allows_trash()
                    })
                })
                .cloned()
                .collect();
            let recheck: Vec<_> = actionable
                .iter()
                .filter(|key| !self.eligible(key))
                .cloned()
                .collect();
            if !recheck.is_empty() {
                if actionable.len() > MAX_SELECTION {
                    self.diagnostic(
                        self.text(
                            "请展开后分批选择，每次最多 256 项",
                            "Expand and select at most 256 items per batch",
                        )
                        .into(),
                    );
                    return;
                }
                match provider.refresh(&recheck) {
                    Ok(()) => {
                        self.pending_selection = Some(actionable);
                        self.busy = true;
                        self.diagnostic(
                            self.text("正在检查所选项目…", "Checking selected items…")
                                .into(),
                        );
                    }
                    Err(error) => self.diagnostic(error),
                }
                return;
            }
        }
        self.group_select(keys);
    }

    fn group_select(&mut self, keys: Vec<String>) {
        let Some(view) = &self.grouped else {
            return;
        };
        if self.busy {
            self.diagnostic(
                self.text(
                    "扫描中，完成后可选择清理项；Enter 可查看文件",
                    "Scanning; select items when finished. Enter opens files",
                )
                .into(),
            );
            return;
        }
        let eligible: Vec<_> = keys
            .iter()
            .filter(|key| self.eligible(key))
            .cloned()
            .collect();
        if eligible.is_empty()
            && !self
                .marked
                .iter()
                .any(|marked| keys.iter().any(|key| contains(&view.parents, marked, key)))
        {
            self.diagnostic(self.selection_message(&keys).into());
            return;
        }
        // Preserve eligible children if their outer candidate is report-only, otherwise select
        // only the outer row. Existing selections outside this group survive.
        let eligible: Vec<_> = roots(&eligible, &view.parents)
            .into_iter()
            .cloned()
            .collect();
        let inherited: Vec<_> = self
            .marked
            .iter()
            .filter(|marked| {
                !keys.contains(marked)
                    && keys.iter().any(|key| contains(&view.parents, marked, key))
            })
            .cloned()
            .collect();
        let mut selection = self.marked.clone();
        if !inherited.is_empty() {
            // Deselecting part of a selected ancestor keeps only independently admitted sibling
            // candidates. Unclassified remainder is never manufactured into cleanup targets.
            for ancestor in &inherited {
                selection.remove(ancestor);
            }
            for sibling in self.rows.keys() {
                if self.eligible(sibling)
                    && inherited
                        .iter()
                        .any(|ancestor| contains(&view.parents, ancestor, sibling))
                    && !keys.iter().any(|key| {
                        contains(&view.parents, key, sibling)
                            || contains(&view.parents, sibling, key)
                    })
                {
                    selection.insert(sibling.clone());
                }
            }
        } else if !eligible.is_empty() && eligible.iter().all(|key| self.marked.contains(key)) {
            for key in &keys {
                selection.remove(key);
            }
        } else {
            selection.extend(eligible);
        }
        let selection: Vec<_> = selection.into_iter().collect();
        let selection: BTreeSet<_> = roots(&selection, &view.parents)
            .into_iter()
            .cloned()
            .collect();
        if selection.len() > MAX_SELECTION {
            self.diagnostic(
                self.text(
                    "所选组超过 256 项；请展开后分批选择",
                    "Selection exceeds 256 items; expand and select a smaller batch",
                )
                .into(),
            );
            return;
        }
        self.marked = selection;
        self.diagnostic(format!(
            "{} {} {}",
            self.text("已选择", "Selected"),
            self.marked.len(),
            self.text("项", "items")
        ));
    }

    /// Returns true when the hierarchy consumed the key. Leaf inspection continues through the
    /// existing native-bound inspector; no group label is ever sent to a provider operation.
    pub(super) fn grouped_key<P: JunkProvider>(
        &mut self,
        key: &mut crossterm::event::KeyEvent,
        provider: &mut P,
    ) -> bool {
        if self.grouped.is_none() {
            return false;
        }
        if self.grouped.as_ref().unwrap().preview.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.grouped.as_mut().unwrap().preview = None,
                KeyCode::Up | KeyCode::PageUp => {
                    let view = self.grouped.as_mut().unwrap();
                    view.preview_offset = view.preview_offset.saturating_sub(10);
                }
                KeyCode::Down | KeyCode::PageDown => {
                    let view = self.grouped.as_mut().unwrap();
                    view.preview_offset = view.preview_offset.saturating_add(10);
                }
                KeyCode::Enter => {
                    let (revision, keys) = self.grouped.as_mut().unwrap().preview.take().unwrap();
                    if revision != self.revision
                        || self.busy
                        || !keys.iter().all(|key| self.eligible(key))
                    {
                        self.diagnostic(
                            self.text(
                                "扫描结果已变化，请重新预览",
                                "Scan results changed; review a new preview",
                            )
                            .into(),
                        );
                    } else {
                        match provider.trash(&keys) {
                            Ok(()) => self.trash_pending = keys.into_iter().collect(),
                            Err(error) => self.diagnostic(error),
                        }
                    }
                }
                _ => {}
            }
            return true;
        }
        match key.code {
            KeyCode::Up
            | KeyCode::Char('k')
            | KeyCode::Down
            | KeyCode::Char('j')
            | KeyCode::PageUp
            | KeyCode::PageDown => {
                let view = self.grouped.as_mut().unwrap();
                view.cursor = match key.code {
                    KeyCode::Up | KeyCode::Char('k') => view.cursor.saturating_sub(1),
                    KeyCode::PageUp => view.cursor.saturating_sub(10),
                    KeyCode::PageDown => view.cursor.saturating_add(10),
                    _ => view.cursor.saturating_add(1),
                }
                .min(view.nodes.len().saturating_sub(1));
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('q') => {
                let view = self.grouped.as_mut().unwrap();
                if let Some((location, cursor)) = view.stack.pop() {
                    view.location = location;
                    view.nodes.clear();
                    view.cursor = cursor;
                    self.rebuild_groups();
                } else {
                    return false;
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('i') => {
                let view = self.grouped.as_mut().unwrap();
                let Some(node) = view.nodes.get(view.cursor) else {
                    return true;
                };
                let inspect = node
                    .candidate
                    .as_ref()
                    .filter(|candidate| {
                        key.code == KeyCode::Char('i')
                            || !view.parents.values().any(|parent| parent == *candidate)
                    })
                    .cloned();
                if let Some(candidate) = inspect {
                    self.cursor = self
                        .order
                        .iter()
                        .position(|key| key == &candidate)
                        .unwrap_or(0);
                    key.code = KeyCode::Enter;
                    return false;
                }
                if view.stack.len() >= 64 {
                    return true;
                }
                view.stack.push((view.location.clone(), view.cursor));
                view.location = node.next.clone();
                view.nodes.clear();
                view.cursor = 0;
                self.rebuild_groups();
            }
            KeyCode::Char(' ') => {
                self.group_select_or_check(self.grouped.as_ref().unwrap().focused_keys(), provider)
            }
            KeyCode::Char('a') => {
                let keys: Vec<String> = self
                    .grouped
                    .as_ref()
                    .unwrap()
                    .nodes
                    .iter()
                    .flat_map(|node| node.keys.clone())
                    .collect();
                let view = self.grouped.as_ref().unwrap();
                if !keys.iter().any(|key| self.eligible(key))
                    || !keys
                        .iter()
                        .filter(|key| self.eligible(key))
                        .all(|key| effectively_selected(self, view, key))
                {
                    self.group_select_or_check(keys, provider);
                }
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let keys = self.chosen();
                let eligible: Vec<_> = keys
                    .iter()
                    .filter(|key| self.eligible(key))
                    .cloned()
                    .collect();
                let view = self.grouped.as_ref().unwrap();
                let eligible: Vec<_> = roots(&eligible, &view.parents)
                    .into_iter()
                    .cloned()
                    .collect();
                let preview_bytes = eligible
                    .iter()
                    .filter_map(|key| self.rows.get(key))
                    .fold(0usize, |bytes, row| {
                        bytes.saturating_add(row.row.path().len()).saturating_add(1)
                    });
                if preview_bytes > 1024 * 1024 {
                    self.diagnostic(
                        self.text(
                            "预览路径过长，请展开后减少选择项",
                            "Preview paths exceed the display budget; select a smaller batch",
                        )
                        .into(),
                    );
                    return true;
                }
                if eligible.is_empty()
                    || eligible.len() > MAX_SELECTION
                    || !self.trash_pending.is_empty()
                {
                    self.diagnostic(self.selection_message(&keys).into());
                } else {
                    self.grouped.as_mut().unwrap().preview_offset = 0;
                    self.grouped.as_mut().unwrap().preview = Some((self.revision, eligible));
                }
            }
            KeyCode::Char('e') => {
                self.inspection_text = Some((self.coverage_details(), 0));
            }
            _ => return false,
        }
        true
    }
}

pub(super) fn render(frame: &mut Frame<'_>, model: &JunkModel) {
    let view = model.grouped.as_ref().unwrap();
    let [header, list, detail, help] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(3),
        Constraint::Length(5),
        Constraint::Length(3),
    ])
    .areas(frame.area());
    let mode = match model.scan_mode {
        "regular" => model.text("常规清理扫描", "Regular cleanup scan"),
        "deep" => model.text("全盘深度扫描", "Deep disk cleanup scan"),
        _ => model.text("指定目录扫描", "Selected directory scan"),
    };
    let keys: Vec<_> = model.marked.iter().cloned().collect();
    let selected_size =
        crate::byte_value_label_with_unit(&total(model, &keys, &view.parents), model.unit);
    let breadcrumb = &view.title;
    let coverage = model.coverage_summary();
    frame.render_widget(
        Paragraph::new(format!(
            "{mode} · {} · {} {} · {} {} ({selected_size}) · {} {}\n{}\n{} {} · {}",
            if !model.busy
                && model.outcome == Some(JunkOutcome::Complete)
                && model.affected.is_some()
            {
                model.text("所选项目检查完成", "Selected items checked")
            } else if !model.busy && model.outcome == Some(JunkOutcome::Partial) {
                if model.discovery_pending() {
                    model.text(
                        "文件扫描已结束（应用位置待检查）",
                        "File scan finished; application locations need checking",
                    )
                } else if model.has_unchecked_locations() {
                    model.text("扫描完成（有未检查项）", "Finished with omissions")
                } else {
                    model.text("扫描完成（有跳过项）", "Finished with exclusions")
                }
            } else {
                model.status()
            },
            model.text("项目", "items"),
            model.rows.len(),
            model.text("已选", "selected"),
            model.marked.len(),
            model.text("未检查原因", "reasons"),
            model.unchecked_kind_count(),
            crate::live::sanitize_terminal_text(breadcrumb),
            model.text("已观察", "observed"),
            model.progress.map_or_else(|| "—".into(), |v| v.to_string()),
            crate::live::sanitize_terminal_text(if model.busy { &model.path } else { &coverage })
        ))
        .block(Block::default().borders(Borders::ALL)),
        header,
    );
    let visible = usize::from(list.height.saturating_sub(3)).clamp(1, crate::MAX_PAGE_ROWS);
    let start = view
        .cursor
        .saturating_sub(visible / 2)
        .min(view.nodes.len().saturating_sub(visible));
    let rows = view.nodes.iter().skip(start).take(visible).map(|node| {
        let selected = node
            .keys
            .iter()
            .filter(|key| effectively_selected(model, view, key))
            .count();
        let eligible = node.keys.iter().filter(|key| model.eligible(key)).count();
        let check = if selected == 0 {
            "☐"
        } else if roots(&node.keys, &view.parents)
            .iter()
            .all(|key| effectively_selected(model, view, key))
        {
            "●"
        } else {
            "◐"
        };
        Row::new(vec![
            Cell::from(check),
            Cell::from(crate::live::sanitize_terminal_text(&node.label)),
            Cell::from(if let Some(bytes) = &node.past_bytes {
                format!(
                    "{} {}",
                    model.text("上次", "Previous"),
                    crate::byte_value_label_with_unit(bytes, model.unit)
                )
            } else {
                crate::byte_value_label_with_unit(&node.bytes, model.unit)
            }),
            Cell::from(format!("{} / {eligible} / {selected}", node.keys.len())),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Min(20),
            Constraint::Length(16),
            Constraint::Length(26),
        ],
    )
    .header(Row::new([
        "",
        model.text("分类 / 应用 / 清理项", "Category / application / item"),
        model.text("大小", "Size"),
        model.text("项目 / 可清理 / 已选", "Items / cleanable / selected"),
    ]))
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .block(Block::default().borders(Borders::ALL));
    let mut state = TableState::default()
        .with_selected((!view.nodes.is_empty()).then_some(view.cursor.saturating_sub(start)));
    frame.render_stateful_widget(table, list, &mut state);
    let description = view.nodes.get(view.cursor).map_or_else(
        || {
            if model.busy {
                model
                    .text(
                        "正在扫描，结果会逐步出现",
                        "Scanning; results appear as they arrive",
                    )
                    .into()
            } else if model.outcome == Some(JunkOutcome::Complete) {
                model
                    .text(
                        "当前检查范围没有匹配的候选",
                        "No matching candidates in the checked scope",
                    )
                    .into()
            } else {
                model
                    .text(
                        "有位置未检查，按 e 查看原因",
                        "Some locations were not checked. Press e for details",
                    )
                    .into()
            }
        },
        |node| {
            node.candidate
                .as_ref()
                .and_then(|key| model.rows.get(key))
                .map_or_else(|| node.label.clone(), |row| row.row.path().into())
        },
    );
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}",
            crate::live::sanitize_terminal_text(&model.diagnostic),
            crate::live::sanitize_terminal_text(&description)
        ))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL)),
        detail,
    );
    frame.render_widget(Paragraph::new(model.text("↑↓ 移动 · Enter 展开 · Esc 返回 · Space 选组/项 · a 选当前层 · u 清空 · d 清理预览 · i 文件详情 · e 未检查原因 · r/R 刷新 · c 暂停 · q 返回/退出", "↑↓ Move · Enter Open · Esc Back · Space Select group/item · a Select level · u Clear · d Preview Trash · i Files · e Reasons · r/R Refresh · c Pause · q Back/quit")).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL)), help);
    if let Some((_, keys)) = &view.preview {
        let size =
            crate::byte_value_label_with_unit(&total(model, keys, &view.parents), model.unit);
        let mut text = format!(
            "{} · {} · {size}\n{}\n\n",
            model.text("清理预览", "Cleanup preview"),
            keys.len(),
            model.text(
                "Enter 确认移入回收站 · Esc 取消",
                "Enter confirms Trash · Esc cancels"
            )
        );
        for key in keys {
            if let Some(row) = model.rows.get(key) {
                text.push_str(row.row.path());
                text.push('\n');
            }
        }
        render_overlay(
            frame,
            &text,
            view.preview_offset,
            model.text("清理预览", "Cleanup preview"),
        );
    } else if let Some((text, offset)) = &model.inspection_text {
        render_overlay(
            frame,
            text,
            *offset,
            model.text(
                "详情 · ↑↓ 滚动 · Esc 返回",
                "Details · ↑↓ Scroll · Esc Back",
            ),
        );
    }
}

fn render_overlay(frame: &mut Frame<'_>, text: &str, offset: u16, title: &str) {
    frame.render_widget(ratatui::widgets::Clear, frame.area());
    frame.render_widget(
        Paragraph::new(
            text.lines()
                .map(crate::live::sanitize_terminal_text)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .wrap(Wrap { trim: false })
        .scroll((offset, 0))
        .block(Block::default().borders(Borders::ALL).title(title)),
        frame.area(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;

    #[test]
    fn expected_exclusions_cannot_hide_failures_or_rebuild_groups() {
        let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        model.dirty = false;
        model.apply(JunkEvent::Error {
            revision: 1,
            message: "metadata budget exhausted".into(),
        });
        for _ in 0..100 {
            model.apply(JunkEvent::Notice {
                revision: 1,
                message: "symlink not followed".into(),
            });
        }
        assert_eq!(model.issue_count, 101);
        assert_eq!(model.diagnostic, "metadata budget exhausted");
        assert_eq!(model.issue_history, ["metadata budget exhausted"]);
        assert_eq!(model.notice_history.len(), 16);
        assert!(
            !model.dirty,
            "diagnostics do not change candidate membership or totals"
        );
    }

    struct Item {
        key: String,
        ancestors: Vec<String>,
        owner: String,
        path: String,
        bytes: ByteValue,
        allowed: bool,
        complete: bool,
    }
    impl JunkRow for Item {
        fn key(&self) -> &str {
            &self.key
        }
        fn path(&self) -> &str {
            &self.path
        }
        fn rule(&self) -> &str {
            "rust.target"
        }
        fn evidence(&self) -> &str {
            "fixture evidence"
        }
        fn context(&self) -> String {
            "fixture".into()
        }
        fn logical_bytes(&self) -> &ByteValue {
            &self.bytes
        }
        fn complete(&self) -> bool {
            self.complete
        }
        fn report_allows_trash(&self) -> bool {
            self.allowed
        }
        fn retained_bytes(&self) -> usize {
            1024
        }
        fn grouping(&self, _: Locale) -> Option<JunkGrouping> {
            Some(JunkGrouping {
                category: "projects".into(),
                category_label: "Projects".into(),
                owner: self.owner.clone(),
                owner_label: "app".into(),
                named_application: false,
            })
        }
        fn entry_identity(&self) -> Option<&str> {
            Some(&self.key)
        }
        fn ancestor_identities(&self) -> Vec<&str> {
            self.ancestors.iter().map(String::as_str).collect()
        }
    }
    fn known(n: u128) -> ByteValue {
        EvidenceValue::Known {
            value: DecimalU128::new(n),
        }
    }
    fn model() -> JunkModel {
        let mut model = JunkModel::new(Locale::EnUs, HumanSizeUnit::Bytes);
        model.grouped = Some(GroupedView::default());
        model.busy = false;
        model.outcome = Some(JunkOutcome::Complete);
        model
    }
    fn add(
        model: &mut JunkModel,
        key: &str,
        ancestors: &[&str],
        owner: &str,
        bytes: ByteValue,
        allowed: bool,
    ) {
        model.apply(JunkEvent::Candidate {
            revision: 0,
            current: true,
            historical: false,
            row: Arc::new(Item {
                key: key.into(),
                ancestors: ancestors.iter().map(|s| s.to_string()).collect(),
                owner: owner.into(),
                path: format!("/{owner}/target/{key}"),
                bytes,
                allowed,
                complete: true,
            }),
        });
        model.reorder();
    }
    #[derive(Default)]
    struct Provider {
        trashed: Vec<String>,
        refreshed: Vec<Vec<String>>,
    }
    impl JunkProvider for Provider {
        fn poll(&mut self) -> Option<JunkEvent> {
            None
        }
        fn cancel(&mut self) {}
        fn refresh(&mut self, keys: &[String]) -> Result<(), String> {
            self.refreshed.push(keys.to_vec());
            Ok(())
        }
        fn prioritize(&mut self, _: &str) {}
        fn trash(&mut self, keys: &[String]) -> Result<(), String> {
            self.trashed.extend_from_slice(keys);
            Ok(())
        }
        fn close(&mut self) {}
    }
    fn press(model: &mut JunkModel, provider: &mut Provider, code: KeyCode) {
        assert!(model.grouped_key(&mut KeyEvent::new(code, KeyModifiers::NONE), provider));
    }
    #[test]
    fn hierarchy_counts_native_outer_candidates_once_and_separates_same_project_names() {
        let mut model = model();
        add(&mut model, "outer", &[], "a/app", known(100), true);
        add(
            &mut model,
            "child",
            &["outer"],
            "wrong/nested/group",
            known(60),
            true,
        );
        add(&mut model, "other", &[], "b/app", known(40), true);
        assert_eq!(model.grouped.as_ref().unwrap().nodes[0].bytes, known(140));
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Enter);
        let view = model.grouped.as_ref().unwrap();
        assert_eq!(view.nodes.len(), 2);
        assert_eq!(view.nodes[0].label, view.nodes[1].label);
        assert_ne!(view.nodes[0].id, view.nodes[1].id);
        press(&mut model, &mut provider, KeyCode::Enter);
        assert_eq!(model.grouped.as_ref().unwrap().nodes.len(), 1);
        press(&mut model, &mut provider, KeyCode::Enter);
        assert_eq!(
            model.grouped.as_ref().unwrap().nodes[0]
                .candidate
                .as_deref(),
            Some("child")
        );
        press(&mut model, &mut provider, KeyCode::Esc);
        assert_eq!(
            model.grouped.as_ref().unwrap().nodes[0]
                .candidate
                .as_deref(),
            Some("outer")
        );
    }
    #[test]
    fn deselecting_a_child_of_a_selected_parent_retains_only_admitted_siblings() {
        let mut model = model();
        add(&mut model, "outer", &[], "a", known(100), true);
        add(&mut model, "child", &["outer"], "a", known(60), true);
        add(&mut model, "sibling", &["outer"], "a", known(20), true);
        model.group_select(vec!["outer".into(), "child".into(), "sibling".into()]);
        assert_eq!(model.marked, BTreeSet::from(["outer".into()]));
        assert!(effectively_selected(
            &model,
            model.grouped.as_ref().unwrap(),
            "child"
        ));
        model.group_select(vec!["child".into()]);
        assert_eq!(model.marked, BTreeSet::from(["sibling".into()]));
        assert_eq!(
            total(
                &model,
                &model.marked.iter().cloned().collect::<Vec<_>>(),
                &model.grouped.as_ref().unwrap().parents
            ),
            known(20)
        );
    }

    #[test]
    fn unknown_and_historical_amounts_never_become_exact_group_totals() {
        let mut model = model();
        add(&mut model, "a", &[], "a", known(10), true);
        add(
            &mut model,
            "b",
            &[],
            "b",
            EvidenceValue::Unknown {
                reason: ReasonCode::Unknown,
            },
            false,
        );
        assert!(
            matches!(model.grouped.as_ref().unwrap().nodes[0].bytes, EvidenceValue::LowerBound { value, .. } if value.0 == 10)
        );
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        model.reorder();
        assert!(matches!(
            model.grouped.as_ref().unwrap().nodes[0].bytes,
            EvidenceValue::Unknown { .. }
        ));
    }

    #[test]
    fn prior_group_size_is_available_only_as_explicit_history_without_selection_authority() {
        let mut model = model();
        add(&mut model, "a", &[], "a", known(10), true);
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        model.reorder();
        let node = &model.grouped.as_ref().unwrap().nodes[0];
        assert!(matches!(node.bytes, EvidenceValue::Unknown { .. }));
        assert_eq!(node.past_bytes, Some(known(10)));
        assert!(!model.eligible("a"));
        model.group_select(vec!["a".into()]);
        assert!(model.marked.is_empty());
    }
    #[test]
    fn fresh_partial_amounts_are_lower_bounds_without_cleanup_authority() {
        let mut model = model();
        add(&mut model, "a", &[], "a", known(10), true);
        model.apply(JunkEvent::Completed {
            revision: 0,
            outcome: JunkOutcome::Partial,
            replaced: false,
        });
        model.reorder();
        assert!(
            matches!(model.grouped.as_ref().unwrap().nodes[0].bytes, EvidenceValue::LowerBound { value, .. } if value.0 == 10)
        );
        assert!(!model.eligible("a"));
        model.apply(JunkEvent::TrashResult {
            key: "a".into(),
            error: Some("uncertain outcome".into()),
        });
        model.reorder();
        assert!(matches!(
            model.grouped.as_ref().unwrap().nodes[0].bytes,
            EvidenceValue::Unknown { .. }
        ));
    }

    #[test]
    fn fresh_incomplete_subtrees_keep_their_measured_lower_bound_until_refresh() {
        let mut model = model();
        add(&mut model, "sibling", &[], "a", known(19), true);
        model.apply(JunkEvent::Candidate {
            revision: 0,
            current: false,
            historical: false,
            row: Arc::new(Item {
                key: "partial".into(),
                ancestors: Vec::new(),
                owner: "a".into(),
                path: "/a/partial".into(),
                bytes: EvidenceValue::LowerBound {
                    value: DecimalU128::new(8192),
                    reason: ReasonCode::NotRevalidated,
                },
                allowed: true,
                complete: false,
            }),
        });
        model.apply(JunkEvent::Completed {
            revision: 0,
            outcome: JunkOutcome::Partial,
            replaced: false,
        });
        model.reorder();
        assert!(matches!(model.grouped.as_ref().unwrap().nodes[0].bytes,
            EvidenceValue::LowerBound { value, .. } if value.0 == 8211));
        assert!(!model.eligible("partial"));
        assert!(
            model.grouped.as_ref().unwrap().nodes[0]
                .past_bytes
                .is_none()
        );
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        model.reorder();
        assert!(matches!(
            model.grouped.as_ref().unwrap().nodes[0].bytes,
            EvidenceValue::Unknown { .. }
        ));
    }

    #[test]
    fn selection_skips_restricted_outer_rows_and_preserves_eligible_children() {
        let mut model = model();
        add(&mut model, "outer", &[], "a", known(100), false);
        add(&mut model, "child", &["outer"], "a", known(60), true);
        add(&mut model, "other", &[], "b", known(40), true);
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Char(' '));
        assert_eq!(
            model.marked,
            BTreeSet::from(["child".into(), "other".into()])
        );
        press(&mut model, &mut provider, KeyCode::Char('d'));
        assert!(provider.trashed.is_empty());
        press(&mut model, &mut provider, KeyCode::Enter);
        assert_eq!(provider.trashed, vec!["child", "other"]);
    }
    #[test]
    fn preview_is_invalidated_by_refresh_or_same_revision_candidate_replacement() {
        let mut model = model();
        add(&mut model, "a", &[], "a", known(10), true);
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Char('d'));
        assert!(model.grouped.as_ref().unwrap().preview.is_some());
        add(&mut model, "a", &[], "a", known(20), true);
        assert!(model.grouped.as_ref().unwrap().preview.is_none());
        press(&mut model, &mut provider, KeyCode::Char('d'));
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        assert!(model.grouped.as_ref().unwrap().preview.is_none());
        assert!(provider.trashed.is_empty());
    }
    #[test]
    fn oversized_group_selection_is_atomic_and_reports_the_limit() {
        let mut model = model();
        for n in 0..257 {
            add(&mut model, &format!("item{n}"), &[], "a", known(1), true);
        }
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Char(' '));
        assert!(model.marked.is_empty());
        assert!(model.diagnostic.contains("256"));
    }
    #[test]
    fn fresh_base_sizes_survive_partial_completion_without_cleanup_authority() {
        let mut model = model();
        model.apply(JunkEvent::Started {
            revision: 1,
            keys: None,
        });
        for (key, historical) in [("fresh", false), ("cached", true)] {
            model.apply(JunkEvent::Candidate {
                revision: 1,
                current: false,
                historical,
                row: Arc::new(Item {
                    key: key.into(),
                    ancestors: vec![],
                    owner: key.into(),
                    path: format!("/{key}/target"),
                    bytes: known(17),
                    allowed: true,
                    complete: true,
                }),
            });
        }
        model.reorder();
        assert_eq!(
            total(&model, &["fresh".into()], &BTreeMap::new()),
            EvidenceValue::LowerBound {
                value: DecimalU128::new(17),
                reason: ReasonCode::NotRevalidated,
            }
        );
        model.apply(JunkEvent::Completed {
            revision: 1,
            outcome: JunkOutcome::Partial,
            replaced: false,
        });
        model.reorder();
        assert!(
            matches!(total(&model, &["fresh".into(), "cached".into()], &BTreeMap::new()),
            EvidenceValue::LowerBound { value, .. } if value.0 == 17)
        );
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Char('a'));
        assert!(model.marked.is_empty());
        assert!(!model.eligible("fresh") && !model.eligible("cached"));
        model.apply(JunkEvent::Started {
            revision: 2,
            keys: None,
        });
        assert!(matches!(
            total(&model, &["fresh".into()], &BTreeMap::new()),
            EvidenceValue::Unknown { .. }
        ));
    }

    #[test]
    fn regrouped_results_return_to_a_populated_parent_instead_of_an_empty_level() {
        let mut model = model();
        add(&mut model, "child", &["outer"], "old", known(10), true);
        let mut provider = Provider::default();
        press(&mut model, &mut provider, KeyCode::Enter);
        press(&mut model, &mut provider, KeyCode::Enter);
        assert!(matches!(
            model.grouped.as_ref().unwrap().location,
            Location::Items(_, _)
        ));
        add(&mut model, "outer", &[], "new", known(20), true);
        let view = model.grouped.as_ref().unwrap();
        assert!(!view.nodes.is_empty());
        assert!(matches!(view.location, Location::Owners(_)));
        assert_eq!(view.nodes[0].id, "new");
        assert_ne!(view.title, "projects");
    }

    #[test]
    fn selecting_a_fresh_partial_item_checks_it_before_marking_and_never_cleans_it() {
        for checked_outcome in [JunkOutcome::Complete, JunkOutcome::Partial] {
            let mut model = model();
            add(&mut model, "safe", &[], "app", known(10), true);
            model.apply(JunkEvent::Completed {
                revision: 0,
                outcome: JunkOutcome::Partial,
                replaced: false,
            });
            model.reorder();
            let mut provider = Provider::default();
            press(&mut model, &mut provider, KeyCode::Char(' '));
            assert_eq!(provider.refreshed, [vec!["safe"]]);
            assert!(model.busy && model.marked.is_empty() && provider.trashed.is_empty());
            model.apply(JunkEvent::Started {
                revision: 1,
                keys: Some(vec!["safe".into()]),
            });
            model.apply(JunkEvent::Candidate {
                revision: 1,
                current: true,
                historical: false,
                row: Arc::new(Item {
                    key: "safe".into(),
                    ancestors: vec![],
                    owner: "app".into(),
                    path: "/app/target".into(),
                    bytes: known(10),
                    allowed: true,
                    complete: true,
                }),
            });
            model.apply(JunkEvent::Completed {
                revision: 1,
                outcome: checked_outcome,
                replaced: checked_outcome == JunkOutcome::Complete,
            });
            model.reorder();
            if checked_outcome == JunkOutcome::Complete {
                assert_eq!(model.marked, BTreeSet::from(["safe".into()]));
            } else {
                assert!(model.marked.is_empty() && model.pending_selection.is_none());
            }
            assert!(provider.trashed.is_empty());
        }
    }

    #[test]
    fn narrow_and_wide_screens_show_categories_and_explicit_partial_state() {
        let mut model = model();
        add(&mut model, "a", &[], "a", known(10), false);
        model.outcome = Some(JunkOutcome::Partial);
        for width in [60, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|frame| render(frame, &model)).unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(screen.contains("Finished with omissions"));
            assert!(!screen.contains("Nested candidates counted once"));
            assert!(screen.contains("Projects"));
        }
    }
}
