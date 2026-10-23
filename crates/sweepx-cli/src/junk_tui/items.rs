//! Nested inventories share the parent's terminal, but retain independent native observations.
//! Closing drops the receiver and cancels the child; no UI thread joins native filesystem work.
use super::*;
use sweepx_core::npx::NpxInventory;
use sweepx_tui::junk::ResultPresentation;

pub(super) struct Child {
    pub provider: Box<dyn JunkProvider>,
    pub _pause: JunkAutoRefreshPause,
}
impl JunkProvider for Child {
    fn presentation(&self) -> ResultPresentation {
        self.provider.presentation()
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        self.provider.poll()
    }
    fn cancel(&mut self) {
        self.provider.cancel();
    }
    fn refresh(&mut self, keys: &[String]) -> Result<(), String> {
        self.provider.refresh(keys)
    }
    fn prioritize(&mut self, key: &str) {
        self.provider.prioritize(key);
    }
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        self.provider.trash(keys)
    }
    fn inspect_text(&self, key: &str) -> Option<String> {
        self.provider.inspect_text(key)
    }
    fn close(&mut self) {
        self.provider.close();
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        self.provider.close();
    }
}

struct NpxRow {
    key: String,
    name: String,
    text: String,
    bytes: ByteValue,
    complete: bool,
}
impl JunkRow for NpxRow {
    fn key(&self) -> &str {
        &self.key
    }
    fn path(&self) -> &str {
        &self.name
    }
    fn rule(&self) -> &str {
        "tool.npm-npx"
    }
    fn evidence(&self) -> &str {
        ""
    }
    fn context(&self) -> String {
        self.text.clone()
    }
    fn logical_bytes(&self) -> &ByteValue {
        &self.bytes
    }
    fn complete(&self) -> bool {
        self.complete
    }
    fn report_allows_trash(&self) -> bool {
        self.complete
    }
    fn retained_bytes(&self) -> usize {
        self.key.capacity() + self.name.capacity() + self.text.capacity() + 512
    }
}
struct Prepared {
    inventory: NpxInventory,
    rows: Vec<Arc<NpxRow>>,
    limited: bool,
}
fn prepare(inventory: NpxInventory, locale: Locale) -> Prepared {
    let mut rows = Vec::new();
    let zh = locale == Locale::ZhCn;
    let mut bytes = 0usize;
    let mut limited = false;
    for entry in &inventory.entries {
        let name = entry
            .packages
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version.as_deref().unwrap_or("?")))
            .collect::<Vec<_>>()
            .join(", ");
        let label = if entry.older_version {
            if zh { "旧版本" } else { "Older version" }
        } else if entry.complete {
            if zh { "已安装" } else { "Installed" }
        } else {
            if zh {
                "未能完整检查"
            } else {
                "Not fully checked"
            }
        };
        let row = Arc::new(NpxRow {
            key: entry.id.clone(),
            name: format!(
                "{} · {} · {label}",
                if name.is_empty() { &entry.id } else { &name },
                entry.id
            ),
            text: format!(
                "{label}\n{}\n{}",
                entry.path.display(),
                if zh {
                    "选择此项将回收整套工具安装及其依赖；再次使用时会重新安装。"
                } else {
                    "This selection moves the whole tool installation and its dependencies to Trash; using it again reinstalls it."
                }
            ),
            bytes: entry
                .bytes
                .as_deref()
                .and_then(|s| s.parse::<u128>().ok())
                .map(|n| sweepx_model::EvidenceValue::Known {
                    value: sweepx_model::DecimalU128(n),
                })
                .unwrap_or(sweepx_model::EvidenceValue::Unknown {
                    reason: sweepx_model::ReasonCode::Unknown,
                }),
            complete: entry.complete,
        });
        bytes = bytes.saturating_add(row.retained_bytes());
        if bytes > 8 * 1024 * 1024 {
            limited = true;
            break;
        }
        rows.push(row);
    }
    Prepared {
        inventory,
        rows,
        limited,
    }
}
enum ResultEvent {
    Inventory(Result<Prepared, String>),
    Trash(Vec<(String, Option<String>)>),
}
struct NpxProvider {
    binding: Arc<JunkSessionCandidate>,
    pause: JunkAutoRefreshPause,
    trash_keys: Vec<String>,
    root: PathBuf,
    locale: Locale,
    cancel: CancellationToken,
    receiver: Option<Receiver<ResultEvent>>,
    inventory: Option<Arc<NpxInventory>>,
    rows: BTreeMap<String, Arc<NpxRow>>,
    events: VecDeque<JunkEvent>,
    revision: u64,
    busy: bool,
}
impl NpxProvider {
    fn scan(&mut self) -> Result<(), String> {
        if self.busy {
            return Err("请等待当前检查完成 / Wait for the current check".into());
        }
        self.cancel = CancellationToken::new();
        self.revision += 1;
        let pause = self.pause.clone();
        let (tx, rx) = sync_channel(1);
        let root = self.root.clone();
        let locale = self.locale;
        let binding = self.binding.clone();
        let cancel = self.cancel.clone();
        std::thread::Builder::new()
            .name("npx-inventory".into())
            .spawn(move || {
                let _pause = pause;
                let result = binding
                    .revalidate_native_binding(&cancel, sweepx_core::junk::scan_limits())
                    .map_err(|e| e.detail)
                    .map(|_| prepare(sweepx_core::npx::inventory(&root, &cancel), locale));
                let _ = tx.send(ResultEvent::Inventory(result));
            })
            .map_err(|e| e.to_string())?;
        self.receiver = Some(rx);
        self.busy = true;
        self.inventory = None;
        self.events.push_back(JunkEvent::Started {
            revision: self.revision,
            keys: None,
        });
        Ok(())
    }
    fn finish(&mut self, outcome: JunkOutcome) {
        self.busy = false;
        self.events.push_back(JunkEvent::Completed {
            revision: self.revision,
            outcome,
            replaced: outcome == JunkOutcome::Complete,
        });
    }
}
impl JunkProvider for NpxProvider {
    fn presentation(&self) -> ResultPresentation {
        ResultPresentation::ManagedCaches
    }
    fn poll(&mut self) -> Option<JunkEvent> {
        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }
        let result = match self.receiver.as_ref()?.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.receiver = None;
                self.inventory = None;
                for key in std::mem::take(&mut self.trash_keys) {
                    self.events.push_back(JunkEvent::TrashResult {
                        key,
                        error: Some("Cleanup stopped; refresh this installation".into()),
                    });
                }
                self.events.push_back(JunkEvent::Error {
                    revision: self.revision,
                    message: "npx 检查意外停止 / npx check stopped unexpectedly".into(),
                });
                self.finish(JunkOutcome::Failed);
                return self.events.pop_front();
            }
        };
        self.receiver = None;
        match result {
            ResultEvent::Inventory(Err(message)) => {
                self.events.push_back(JunkEvent::Error {
                    revision: self.revision,
                    message,
                });
                self.finish(JunkOutcome::Failed);
            }
            ResultEvent::Inventory(Ok(Prepared {
                inventory,
                rows,
                limited,
            })) => {
                self.rows = rows
                    .iter()
                    .map(|row| (row.key.clone(), row.clone()))
                    .collect();
                for row in rows {
                    self.events.push_back(JunkEvent::Candidate {
                        revision: self.revision,
                        current: true,
                        historical: false,
                        row,
                    });
                }
                for message in inventory.issues.iter().take(32) {
                    self.events.push_back(JunkEvent::Error {
                        revision: self.revision,
                        message: message.clone(),
                    });
                }
                if limited {
                    self.events.push_back(JunkEvent::Error {
                        revision: self.revision,
                        message: "安装结果过多，部分未显示 / Too many installations to display"
                            .into(),
                    });
                }
                self.finish(if self.cancel.is_cancelled() {
                    JunkOutcome::Cancelled
                } else if inventory.complete && !limited {
                    JunkOutcome::Complete
                } else {
                    JunkOutcome::Partial
                });
                self.inventory = Some(Arc::new(inventory));
            }
            ResultEvent::Trash(results) => {
                self.trash_keys.clear();
                self.busy = false;
                self.inventory = None;
                for (key, error) in results {
                    self.events.push_back(JunkEvent::TrashResult { key, error });
                }
            }
        }
        self.events.pop_front()
    }
    fn cancel(&mut self) {
        self.cancel.cancel();
    }
    fn refresh(&mut self, _: &[String]) -> Result<(), String> {
        self.scan()
    }
    fn prioritize(&mut self, _: &str) {}
    fn inspect_text(&self, key: &str) -> Option<String> {
        self.rows.get(key).map(|r| r.text.clone())
    }
    fn trash(&mut self, keys: &[String]) -> Result<(), String> {
        let inventory = self.inventory.clone().ok_or("请先刷新 / Refresh first")?;
        if self.busy
            || keys.is_empty()
            || keys.len() > 256
            || keys
                .iter()
                .any(|k| !inventory.entries.iter().any(|e| e.id == *k && e.complete))
        {
            return Err("请选择已检查的安装 / Select checked installations".into());
        }
        self.trash_keys = keys.to_vec();
        let keys = keys.to_vec();
        self.cancel = CancellationToken::new();
        let cancel = self.cancel.clone();
        let pause = self.pause.clone();
        let (tx, rx) = sync_channel(1);
        std::thread::Builder::new()
            .name("npx-trash".into())
            .spawn(move || {
                let _pause = pause;
                let results = keys
                    .into_iter()
                    .map(|key| {
                        let error = inventory
                            .entries
                            .iter()
                            .find(|e| e.id == key)
                            .ok_or_else(|| "installation_missing".into())
                            .and_then(|e| crate::npx_command::move_entry(e, &cancel))
                            .err();
                        (key, error)
                    })
                    .collect();
                let _ = tx.send(ResultEvent::Trash(results));
            })
            .map_err(|e| e.to_string())?;
        self.busy = true;
        self.receiver = Some(rx);
        Ok(())
    }
    fn close(&mut self) {
        self.cancel.cancel();
        self.receiver = None;
    }
}
impl Drop for NpxProvider {
    fn drop(&mut self) {
        self.close();
    }
}
pub(super) fn npx(
    binding: Arc<JunkSessionCandidate>,
    root: PathBuf,
    locale: Locale,
    pause: JunkAutoRefreshPause,
) -> Result<Box<dyn JunkProvider>, String> {
    let mut provider = NpxProvider {
        binding,
        pause,
        trash_keys: Vec::new(),
        root,
        locale,
        cancel: CancellationToken::new(),
        receiver: None,
        inventory: None,
        rows: BTreeMap::new(),
        events: VecDeque::new(),
        revision: 0,
        busy: false,
    };
    provider.scan()?;
    Ok(Box::new(provider))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_names_and_older_versions_come_from_native_manifests() {
        let fixture = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let root = std::fs::canonicalize(fixture.path()).unwrap();
        // Windows canonicalization creates a verbatim path, which is deliberately not an
        // admitted native scan root. Keep the same ordinary absolute path as the core fixtures.
        #[cfg(windows)]
        let root = fixture.path().to_path_buf();
        for (slot, version) in [("aaaaaaaaaaaaaaaa", "1.0.0"), ("bbbbbbbbbbbbbbbb", "2.0.0")] {
            let path = root.join(slot);
            std::fs::create_dir_all(path.join("node_modules/example")).unwrap();
            std::fs::write(
                path.join("package.json"),
                r#"{"dependencies":{"example":"*"}}"#,
            )
            .unwrap();
            std::fs::write(
                path.join("node_modules/example/package.json"),
                format!(r#"{{"name":"example","version":"{version}"}}"#),
            )
            .unwrap();
        }
        let prepared = prepare(
            sweepx_core::npx::inventory(&root, &CancellationToken::new()),
            Locale::ZhCn,
        );
        assert!(!prepared.limited);
        assert!(prepared.inventory.complete, "{:?}", prepared.inventory);
        assert_eq!(prepared.rows.len(), 2);
        assert!(
            prepared
                .rows
                .iter()
                .any(|r| r.name.contains("example@1.0.0") && r.name.contains("旧版本"))
        );
        assert!(
            prepared
                .rows
                .iter()
                .all(|r| !r.text.contains("risk=") && !r.text.contains("sweepx "))
        );
    }
}
