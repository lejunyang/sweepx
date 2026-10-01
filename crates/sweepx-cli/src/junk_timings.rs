//! Opt-in phase diagnostics kept separate from the stable junk result on stdout.

use std::time::Instant;

/// Measures sequential phases, including failed runs, without retaining per-file telemetry.
pub(crate) struct JunkTimings {
    enabled: bool,
    started: Instant,
    checkpoint: Instant,
    phases: Vec<(&'static str, u128)>,
    roots: usize,
    root_hits: usize,
    candidates: usize,
    complete: bool,
}

impl JunkTimings {
    pub(crate) fn new(enabled: bool) -> Self {
        let started = Instant::now();
        Self {
            enabled,
            started,
            checkpoint: started,
            phases: Vec::new(),
            roots: 0,
            root_hits: 0,
            candidates: 0,
            complete: false,
        }
    }

    pub(crate) fn phase(&mut self, name: &'static str) {
        if self.enabled {
            let now = Instant::now();
            self.phases
                .push((name, now.duration_since(self.checkpoint).as_nanos()));
            self.checkpoint = now;
        }
    }

    pub(crate) fn cache_roots(&mut self, roots: usize, hits: usize) {
        self.roots = roots;
        self.root_hits = hits;
    }

    pub(crate) fn finish(&mut self, candidates: usize) {
        self.candidates = candidates;
        self.complete = true;
    }
}

impl Drop for JunkTimings {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        // A failed phase remains visible as unfinished work. Never imply that a short failed
        // scan is a fast complete scan; the harness also checks the report and process status.
        self.phase("tail");
        let phases: serde_json::Map<String, serde_json::Value> = self
            .phases
            .iter()
            .map(|(name, nanos)| ((*name).to_string(), serde_json::json!(nanos)))
            .collect();
        eprintln!(
            "{}",
            serde_json::json!({
                "schema": "sweepx.junk.timings/v1",
                "complete": self.complete,
                "totalNs": self.started.elapsed().as_nanos(),
                "phasesNs": phases,
                "rootCount": self.roots,
                "rootCacheHits": self.root_hits,
                "rootCacheMisses": self.roots.saturating_sub(self.root_hits),
                "candidateCount": self.candidates,
            })
        );
    }
}
