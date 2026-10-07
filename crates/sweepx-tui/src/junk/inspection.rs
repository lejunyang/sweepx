//! Candidate inspection shares the progressive scanner protocol and the existing terminal.
//! It cannot emit a Trash request or promote a child's size into a junk classification.

use super::*;
use crate::{
    BrowserAction, BrowserExit, BrowserKeyMapper, BrowserModel, BrowserReducer,
    DefaultBrowserKeyMapper, DetailRescanBrowserReducer, DetailRescanProgress,
    DetailRescanProvider, DetailRescanRequest, DetailRescanResult, run_browser_loop_until,
};
use sweepx_model::ScannedEntry;

/// Native directory evidence and a bounded background detail provider for a read-only modal.
/// Providers retain original root/ancestor identity and any admission lease through worker exit.
pub struct JunkInspection {
    /// Current typed source entry; display paths alone cannot create an inspection.
    pub directory: ScannedEntry,
    /// Reuses the same identity-bound detail scanner as ordinary progressive browsing.
    pub provider: Arc<dyn DetailRescanProvider>,
}

struct SharedProvider(Arc<dyn DetailRescanProvider>);

/// A process interrupt must escape the modal rather than merely returning to the candidate list.
struct InspectionKeys(std::cell::Cell<bool>);
impl BrowserKeyMapper for InspectionKeys {
    fn map_key(&self, key: &crossterm::event::KeyEvent) -> Option<BrowserAction> {
        let action = DefaultBrowserKeyMapper.map_key(key);
        if action == Some(BrowserAction::Quit)
            && matches!(key.code, KeyCode::Char(character) if character.eq_ignore_ascii_case(&'c'))
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            self.0.set(true);
        }
        action
    }
}
impl DetailRescanProvider for SharedProvider {
    fn prepare_detail_rescan(&self) {
        self.0.prepare_detail_rescan();
    }
    fn rescan_detail(&self, request: &DetailRescanRequest) -> DetailRescanResult {
        self.0.rescan_detail(request)
    }
    fn cancel_detail_rescan(&self) {
        self.0.cancel_detail_rescan();
    }
    fn set_progress_sink(&self, sink: Option<std::sync::mpsc::SyncSender<DetailRescanProgress>>) {
        self.0.set_progress_sink(sink);
    }
}

pub(super) struct InspectionResult {
    pub exit: BrowserExit,
    pub paths: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run<B: Backend, E: BrowserEventSource, T: TerminationFlag>(
    terminal: &mut Terminal<B>,
    events: &mut E,
    termination: &T,
    locale: Locale,
    unit: HumanSizeUnit,
    sort: ScanSort,
    inspection: JunkInspection,
) -> Result<InspectionResult, BrowserError> {
    let mut model =
        BrowserModel::from_progressive_inspection(locale, inspection.directory, unit, sort)?;
    let reducer = DetailRescanBrowserReducer::new(SharedProvider(inspection.provider))?;
    reducer.reduce(&mut model, BrowserAction::EnterDirectory);
    let keys = InspectionKeys(std::cell::Cell::new(false));
    let result = run_browser_loop_until(terminal, &mut model, events, &keys, &reducer, termination);
    reducer.cancel_background();
    let paths = model.review_paths().map(str::to_owned).collect();
    let exit = result?;
    Ok(InspectionResult {
        exit: if keys.0.get() {
            BrowserExit::Terminated { signal: None }
        } else {
            exit
        },
        paths,
    })
}
