//! Cancellable single-worker inventories; presentation is prepared off the UI thread as well.
use crate::managed_cache::{Config, details, execute, link_range};
use std::collections::{BTreeMap, VecDeque};
use std::process::ExitCode;
use std::sync::{
    Arc,
    mpsc::{Receiver, TryRecvError, sync_channel},
};
use sweepx_core::{
    CancellationToken,
    managed_cache::{Action, Inventory},
};
use sweepx_i18n::Locale;
use sweepx_model::{ByteValue, HumanSizeUnit, ScanSort};
use sweepx_tui::junk::{
    JunkEvent, JunkOutcome, JunkProvider, JunkRow, ResultPresentation, run_junk_browser,
};
struct Row {
    key: String,
    name: String,
    rule: String,
    size: ByteValue,
    eligible: bool,
    action: Action,
    text: String,
    locale: Locale,
}
impl JunkRow for Row {
    fn key(&self) -> &str {
        &self.key
    }
    fn path(&self) -> &str {
        &self.name
    }
    fn rule(&self) -> &str {
        &self.rule
    }
    fn evidence(&self) -> &str {
        if self.locale == Locale::ZhCn {
            "引用仅覆盖指定搜索范围；单链接不代表未使用，大小不代表可释放空间。"
        } else {
            "References cover the declared search scope; single links do not establish unused content or freed space."
        }
    }
    fn context(&self) -> String {
        self.text.clone()
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.size
    }
    fn complete(&self) -> bool {
        self.eligible
    }
    fn report_allows_trash(&self) -> bool {
        self.action != Action::OsdkModelRemove && self.eligible
    }
    fn retained_bytes(&self) -> usize {
        self.text.capacity()
            + self.key.capacity()
            + self.name.capacity()
            + self.rule.capacity()
            + 512
    }
}
struct Prepared {
    report: Inventory,
    rows: Vec<Arc<Row>>,
    limited: bool,
}
fn prepare(config: &Config, report: Inventory, unit: HumanSizeUnit, locale: Locale) -> Prepared {
    let mut rows = Vec::new();
    let mut retained = 0usize;
    let mut limited = false;
    for item in report.entries.iter().filter(|e| config.visible(e)) {
        let mut text = format!(
            "{}@{}\nlinks={}, single={}, projects={}\n{}\nSearch roots: {}",
            item.name,
            item.version.as_deref().unwrap_or("?"),
            link_range(item.min_links, item.max_links),
            item.single_link_files,
            item.projects.len(),
            details(item, &report, unit, locale),
            report.project_roots.join("\n")
        );
        if text.len() > 64 * 1024 {
            let mut end = 64 * 1024;
            while !text.is_char_boundary(end) {
                end -= 1
            }
            text.truncate(end);
            text.push_str("\n[detail text limit; full references in JSON report]");
        }
        let row = Row {
            key: item.id.clone(),
            name: format!("{}@{}", item.name, item.version.as_deref().unwrap_or("?")),
            rule: item.rule_id.clone(),
            size: item.logical_bytes.clone(),
            eligible: item.eligible,
            action: item.action,
            text,
            locale,
        };
        retained = retained.saturating_add(row.retained_bytes());
        if rows.len() >= 16_384 || retained > 64 * 1024 * 1024 {
            limited = true;
            break;
        }
        rows.push(Arc::new(row));
    }
    Prepared {
        report,
        rows,
        limited,
    }
}
enum ResultEvent {
    Scan(Box<Prepared>),
    Trash(Vec<String>, Result<Vec<serde_json::Value>, String>),
}
struct Provider {
    config: Config,
    locale: Locale,
    unit: HumanSizeUnit,
    cancel: CancellationToken,
    receiver: Option<Receiver<ResultEvent>>,
    report: Option<Arc<Inventory>>,
    rows: BTreeMap<String, Arc<Row>>,
    pending_rows: Option<std::vec::IntoIter<Arc<Row>>>,
    events: VecDeque<JunkEvent>,
    revision: u64,
    busy: bool,
}
impl Provider {
    fn scan(&mut self) -> Result<(), String> {
        if self.busy {
            return Err("worker_busy".into());
        }
        self.cancel = CancellationToken::new();
        self.revision += 1;
        self.busy = true;
        self.events.push_back(JunkEvent::Started {
            revision: self.revision,
            keys: None,
        });
        self.events.push_back(JunkEvent::Phase {
            revision: self.revision,
            phase: "scan",
        });
        let config = self.config.clone();
        let cancel = self.cancel.clone();
        let (unit, locale) = (self.unit, self.locale);
        let (tx, rx) = sync_channel(1);
        self.receiver = Some(rx);
        std::thread::Builder::new()
            .name("managed-cache-inventory".into())
            .spawn(move || {
                let report = config.inventory(&cancel);
                let prepared = prepare(&config, report, unit, locale);
                let _ = tx.send(ResultEvent::Scan(Box::new(prepared)));
            })
            .map_err(|e| {
                self.busy = false;
                e.to_string()
            })?;
        Ok(())
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl JunkProvider for Provider {
    fn presentation(&self) -> ResultPresentation {
        ResultPresentation::ManagedCaches
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        if let Some(rows) = &mut self.pending_rows {
            if let Some(row) = rows.next() {
                return Some(JunkEvent::Candidate {
                    revision: self.revision,
                    current: true,
                    historical: false,
                    row,
                });
            }
            self.pending_rows = None;
            self.busy = false;
        }
        if let Some(e) = self.events.pop_front() {
            return Some(e);
        }
        let result = match self.receiver.as_ref()?.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => {
                self.receiver = None;
                self.busy = false;
                self.events.push_back(JunkEvent::Error {
                    revision: self.revision,
                    message: "inventory worker exited unexpectedly".into(),
                });
                self.events.push_back(JunkEvent::Completed {
                    revision: self.revision,
                    outcome: JunkOutcome::Failed,
                    replaced: false,
                });
                return self.events.pop_front();
            }
        };
        self.receiver = None;
        match result {
            ResultEvent::Scan(prepared) => {
                let Prepared {
                    report,
                    rows,
                    limited,
                } = *prepared;
                self.rows = rows
                    .iter()
                    .map(|row| (row.key.clone(), row.clone()))
                    .collect();
                self.pending_rows = Some(rows.into_iter());
                if limited {
                    self.events.push_back(JunkEvent::Error {
                        revision: self.revision,
                        message: "view budget exceeded; narrow --package or --max-links".into(),
                    });
                }
                for issue in report.issues.iter().take(32) {
                    self.events.push_back(JunkEvent::Error {
                        revision: self.revision,
                        message: issue.clone(),
                    });
                }
                self.events.push_back(JunkEvent::Completed {
                    revision: self.revision,
                    outcome: if self.cancel.is_cancelled() {
                        JunkOutcome::Cancelled
                    } else if report.complete && !limited {
                        JunkOutcome::Complete
                    } else {
                        JunkOutcome::Partial
                    },
                    replaced: report.complete && !limited,
                });
                self.report = Some(Arc::new(report));
            }
            ResultEvent::Trash(keys, result) => {
                self.busy = false;
                let error = match result {
                    Err(e) => Some(e),
                    Ok(rows) if rows.iter().any(|r| r["completed"] != true) => {
                        Some("batch partially moved; refresh before another selection".into())
                    }
                    Ok(_) => None,
                };
                for key in keys {
                    self.events.push_back(JunkEvent::TrashResult {
                        key,
                        error: error.clone(),
                    });
                }
                self.events.push_back(JunkEvent::Error {
                    revision: self.revision,
                    message: "Refresh to observe remaining shared content and changed item state"
                        .into(),
                });
                self.report = None;
            }
        }
        self.poll()
    }
    fn cancel(&mut self) {
        self.cancel.cancel();
    }
    fn refresh(&mut self, _: &[String]) -> Result<(), String> {
        self.scan()
    }
    fn prioritize(&mut self, _: &str) {}
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        if self.busy {
            return Err("worker_busy".into());
        }
        let report = self
            .report
            .clone()
            .ok_or("refresh_current_inventory_first")?;
        if keys.is_empty()
            || keys.len() > 256
            || keys.iter().any(|k| {
                !self
                    .rows
                    .get(k)
                    .is_some_and(|e| e.eligible && e.action != Action::OsdkModelRemove)
            })
        {
            return Err("select_eligible_cache_items_models_require_tool_removal".into());
        }
        let config = self.config.clone();
        let keys = keys.to_vec();
        self.cancel = CancellationToken::new();
        let cancel = self.cancel.clone();
        let (tx, rx) = sync_channel(1);
        self.receiver = Some(rx);
        self.busy = true;
        std::thread::Builder::new()
            .name("managed-cache-trash".into())
            .spawn(move || {
                let result = execute(&config, &report, &keys, false, &cancel);
                let _ = tx.send(ResultEvent::Trash(keys, result));
            })
            .map_err(|e| {
                self.busy = false;
                e.to_string()
            })?;
        Ok(())
    }
    fn inspect_text(&self, key: &str) -> Option<String> {
        self.rows.get(key).map(|r| r.text.clone())
    }
    fn close(&mut self) {
        self.cancel.cancel();
        self.receiver = None;
    }
}
pub(crate) fn run(config: Config, locale: Locale, unit: HumanSizeUnit, sort: ScanSort) -> ExitCode {
    let mut provider = Provider {
        config,
        locale,
        unit,
        cancel: CancellationToken::new(),
        receiver: None,
        report: None,
        rows: BTreeMap::new(),
        pending_rows: None,
        events: VecDeque::new(),
        revision: 0,
        busy: false,
    };
    if let Err(e) = provider.scan() {
        eprintln!("{e}");
        return ExitCode::from(8);
    }
    match run_junk_browser(locale, unit, sort, provider) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(8)
        }
    }
}
