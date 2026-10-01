//! Display-only confirmation state. Native previews stay on the provider worker.

use super::*;
use crossterm::event::KeyEvent;

const MAX_PLAN_BYTES: usize = 1024 * 1024;

pub(super) struct QuarantineView {
    pub operation: u64,
    keys: Vec<String>,
    digest: Option<String>,
    plan: String,
    answer: String,
    scroll: usize,
    horizontal: u16,
    executing: bool,
    finished: bool,
}
impl QuarantineView {
    pub fn new(operation: u64, keys: Vec<String>) -> Self {
        Self {
            operation,
            keys,
            digest: None,
            plan: String::new(),
            answer: String::new(),
            scroll: 0,
            horizontal: 0,
            executing: false,
            finished: false,
        }
    }
}

impl JunkModel {
    pub(super) fn apply_quarantine_event(&mut self, event: &JunkEvent) -> bool {
        match event {
            JunkEvent::QuarantinePreview {
                operation,
                digest,
                plan,
            } => {
                if let Some(view) = &mut self.quarantine
                    && view.operation == *operation
                    && !view.executing
                    && !view.finished
                {
                    if digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                        || plan.len() > MAX_PLAN_BYTES
                    {
                        // No confirmable digest remains. The user can dismiss; never execute a
                        // truncated or malformed display plan merely because the worker has one.
                        view.finished = true;
                        view.plan = "Quarantine preview exceeded its display budget or has an invalid digest; execution refused".into();
                        self.outcome = Some(JunkOutcome::Partial);
                    } else {
                        view.digest = Some(digest.clone());
                        view.plan = plan.clone();
                    }
                }
                true
            }
            JunkEvent::QuarantineFinished {
                operation,
                moved,
                message,
                failed,
            } => {
                if !self
                    .quarantine
                    .as_ref()
                    .is_some_and(|view| view.operation == *operation)
                {
                    return true;
                }
                let keys = self.quarantine.as_ref().unwrap().keys.clone();
                let failed = *failed || keys.iter().any(|key| !moved.contains(key));
                // Accept transitions only for this explicitly selected batch. Native reconciliation
                // remains the provider's job; a presentation event alone never grants authority.
                for key in &keys {
                    if moved.contains(key) {
                        self.remove(key);
                    } else if failed && let Some(row) = self.rows.get_mut(key) {
                        row.historical = true;
                    }
                }
                let view = self.quarantine.as_mut().unwrap();
                self.diagnostic.clear();
                view.finished = true;
                view.executing = false;
                view.scroll = 0;
                view.plan = crate::live::sanitize_terminal_text(message);
                // Bound malformed provider diagnostics as well as plans. Production messages carry
                // the complete recovery location within this budget.
                if view.plan.len() > MAX_PLAN_BYTES {
                    let mut end = MAX_PLAN_BYTES;
                    while !view.plan.is_char_boundary(end) {
                        end -= 1;
                    }
                    view.plan.truncate(end);
                }
                if failed {
                    self.outcome = Some(JunkOutcome::Partial);
                }
                true
            }
            _ => false,
        }
    }

    pub(super) fn quarantine_key(
        &mut self,
        key: KeyEvent,
        provider: &mut impl JunkProvider,
    ) -> bool {
        let Some(view) = self.quarantine.as_mut() else {
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                provider.dismiss_quarantine(view.operation);
                if view.executing {
                    self.diagnostic(
                        "Cancellation requested; a partial source and recovery copy may remain"
                            .into(),
                    );
                } else {
                    self.quarantine = None;
                }
            }
            KeyCode::Char('q') if view.finished => {
                self.quarantine = None;
                return false;
            }
            KeyCode::Up => view.scroll = view.scroll.saturating_sub(1),
            KeyCode::Down => {
                view.scroll = (view.scroll + 1).min(view.plan.lines().count().saturating_sub(1))
            }
            KeyCode::PageUp => view.scroll = view.scroll.saturating_sub(10),
            KeyCode::PageDown => {
                view.scroll = (view.scroll + 10).min(view.plan.lines().count().saturating_sub(1))
            }
            KeyCode::Left => view.horizontal = view.horizontal.saturating_sub(8),
            KeyCode::Right => view.horizontal = view.horizontal.saturating_add(8),
            KeyCode::Backspace if !view.executing && !view.finished => {
                view.answer.pop();
            }
            KeyCode::Char(character)
                if !view.executing
                    && !view.finished
                    && view.digest.is_some()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                    && character.is_ascii()
                    && !character.is_ascii_control()
                    && view.answer.len() < 160 =>
            {
                view.answer.push(character);
            }
            KeyCode::Enter if !view.executing && !view.finished && view.digest.is_some() => {
                if view.answer.trim() != format!("clean {}", view.digest.as_ref().unwrap()) {
                    self.diagnostic("Type clean followed by the full plan digest exactly".into());
                } else {
                    match provider.confirm_quarantine(view.operation, &view.answer) {
                        Ok(()) => {
                            view.executing = true;
                            self.diagnostic.clear();
                        }
                        Err(error) => self.diagnostic(error),
                    }
                }
            }
            _ => {}
        }
        true
    }
}

pub(super) fn render(frame: &mut Frame<'_>, model: &JunkModel, view: &QuarantineView) {
    let [header, plan, input, help] = Layout::vertical([
        Constraint::Length(6),
        Constraint::Min(2),
        Constraint::Length(4),
        Constraint::Length(3),
    ])
    .areas(frame.area());
    let state = if view.finished {
        model.text("隔离结果", "Quarantine result")
    } else if view.executing {
        model.text("正在隔离", "Quarantining")
    } else if view.digest.is_some() {
        model.text("核对隔离计划", "Review quarantine plan")
    } else {
        model.text("后台核验隔离计划", "Checking quarantine plan on worker")
    };
    let digest = view.digest.as_deref().unwrap_or("pending");
    frame.render_widget(Paragraph::new(format!("{state}\n{digest}\n{}",
        model.text("其他用户的进程引用可能不可见；取消移除可留下部分源和完整恢复副本。",
            "Other users' references may be invisible; cancelling removal can leave a partial source and a complete recovery copy.")))
        .wrap(Wrap { trim: false }).block(Block::default().borders(Borders::ALL)), header);
    // Format only visible logical lines. Horizontal scrolling retains full paths and exact native
    // identity fields without making a truncated plan confirmable.
    let lines = view
        .plan
        .lines()
        .skip(view.scroll)
        .take(usize::from(plan.height.saturating_sub(2)))
        .map(crate::live::sanitize_terminal_text)
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((0, view.horizontal))
            .block(Block::default().borders(Borders::ALL)),
        plan,
    );
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}",
            view.answer,
            crate::live::sanitize_terminal_text(&model.diagnostic)
        ))
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(model.text(
            "输入 clean + 空格 + 完整摘要，再按 Enter",
            "Type clean + space + full digest, then Enter",
        ))),
        input,
    );
    frame.render_widget(
        Paragraph::new(model.text(
            "↑↓/PgUp/PgDn 滚动 · ←→ 查看长行 · Esc 取消/关闭 · Ctrl-C 退出",
            "↑↓/PgUp/PgDn Scroll · ←→ Long lines · Esc Cancel/close · Ctrl-C Quit",
        ))
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL)),
        help,
    );
}
