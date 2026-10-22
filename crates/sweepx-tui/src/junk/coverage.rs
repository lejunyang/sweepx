//! Location-level coverage and explicit retries. Display keys resolve only inside the provider.
use super::*;
pub(super) struct Location {
    pub revision: u64,
    pub path: String,
    pub status: &'static str,
    pub detail: String,
}
impl JunkModel {
    fn location_label(&self, location: &Location) -> &str {
        match location.status {
            "checked" => self.text("已检查", "Checked"),
            "excluded" => self.text("已跳过", "Skipped"),
            "partial" => self.text("未读完", "Not fully read"),
            _ if self.busy => self.text("等待或检查中", "Pending / checking"),
            _ => self.text("未完成", "Not completed"),
        }
    }
    pub(super) fn coverage_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        provider: &mut (impl JunkProvider + ?Sized),
    ) -> bool {
        let Some(cursor) = self.coverage_cursor else {
            return false;
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'e') => self.coverage_cursor = None,
            KeyCode::Up | KeyCode::Char('k') => {
                self.coverage_cursor = Some(cursor.saturating_sub(1))
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.coverage_cursor =
                    Some((cursor + 1).min(self.locations.len().saturating_sub(1)))
            }
            KeyCode::PageUp => self.coverage_cursor = Some(cursor.saturating_sub(10)),
            KeyCode::PageDown => {
                self.coverage_cursor =
                    Some((cursor + 10).min(self.locations.len().saturating_sub(1)))
            }
            KeyCode::Enter if !self.busy && self.trash_pending.is_empty() => {
                if let Some((id, location)) = self.locations.iter().nth(cursor)
                    && location.status != "excluded"
                {
                    match provider.retry_location(id) {
                        Ok(()) => {
                            self.busy = true;
                            self.coverage_cursor = None;
                        }
                        Err(error) => self.diagnostic(error),
                    }
                }
            }
            KeyCode::Char('i') => {
                self.coverage_cursor = None;
                self.inspection_text = Some((self.coverage_details(), 0));
            }
            _ => {}
        }
        true
    }
}
pub(super) fn render(frame: &mut Frame<'_>, model: &JunkModel) {
    let [header, list, details] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(6),
    ])
    .areas(frame.area());
    frame.render_widget(
        Paragraph::new(model.text(
            "扫描范围 · ↑↓ 选择位置 · Enter 重新检查该位置 · i 原因详情 · Esc 返回",
            "Scan coverage · ↑↓ Select location · Enter Recheck location · i Reasons · Esc Back",
        ))
        .wrap(Wrap { trim: true }),
        header,
    );
    let cursor = model
        .coverage_cursor
        .unwrap_or(0)
        .min(model.locations.len().saturating_sub(1));
    let start = cursor.saturating_sub(list.height.saturating_sub(4) as usize);
    let rows = model.locations.values().skip(start).map(|location| {
        Row::new(vec![
            Cell::from(crate::live::sanitize_terminal_text(&location.path)),
            Cell::from(format!(
                "{}{}",
                if location.revision != model.revision {
                    model.text("上次 · ", "Previous · ")
                } else {
                    ""
                },
                model.location_label(location)
            )),
        ])
    });
    let table = Table::new(
        rows,
        [Constraint::Percentage(75), Constraint::Percentage(25)],
    )
    .header(Row::new([
        model.text("位置", "Location"),
        model.text("检查情况", "Coverage"),
    ]))
    .block(Block::default().borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    let mut state = TableState::default()
        .with_selected((!model.locations.is_empty()).then_some(cursor.saturating_sub(start)));
    frame.render_stateful_widget(table, list, &mut state);
    let detail = model.locations.values().nth(cursor).map_or("", |location| {
        match location.detail.as_str() {
            "special filesystem entry rejected" => model.text(
                "应用通信文件，无需清理。",
                "Application communication file; no cleanup needed.",
            ),
            text if text.to_ascii_lowercase().contains("permission") || text.contains("denied") => {
                model.text(
                    "当前账户没有读取权限。授权后可重新检查此位置。",
                    "The current account cannot read this location. Recheck after granting access.",
                )
            }
            text => text,
        }
    });
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}\n{}",
            model.coverage_summary(),
            crate::live::sanitize_terminal_text(detail),
            crate::live::sanitize_terminal_text(&model.diagnostic)
        ))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL)),
        details,
    );
}
