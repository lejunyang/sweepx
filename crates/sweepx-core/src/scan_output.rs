//! Scan presentation borrows the bounded native snapshot instead of retaining a second JSON tree.
//! Machine output still includes every retained fact and boundary; rendering grants no authority.

use super::*;
use serde::ser::{SerializeMap, SerializeSeq};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use sweepx_model::{ByteValue, DirectoryAggregate};

/// Owned scan facts with small protocol metadata and bounded analysis reports.
///
/// Unlike the legacy [`ScanSuccess`], this does not materialize scan rows in `metadata.data`.
/// Use [`Self::write_json`] for the complete machine envelope or [`Self::render_human`] for a
/// bounded display. The scan/snapshot/event semantics are shared with the legacy entry points.
#[derive(Debug)]
pub struct ScanOutput {
    metadata: OutputEnvelope,
    summary: ScanSummary,
    events: Vec<EventEnvelope>,
    snapshot: OperationSnapshot,
}

impl ScanOutput {
    pub(super) fn new(scan: ScanSuccess) -> Self {
        Self {
            metadata: scan.output,
            summary: scan.summary,
            events: scan.events,
            snapshot: scan.snapshot,
        }
    }

    /// Small status, compatibility and count metadata. `data` contains only optional analysis
    /// reports; serializing this alone does not export the scan rows. Use [`Self::write_json`].
    pub fn metadata(&self) -> &OutputEnvelope {
        &self.metadata
    }

    /// The original typed scan facts, including incomplete coverage and resource boundaries.
    pub fn summary(&self) -> &ScanSummary {
        &self.summary
    }

    /// Retained terminal operation snapshot, independent of subsequent output IO failures.
    pub fn snapshot(&self) -> &OperationSnapshot {
        &self.snapshot
    }

    /// Bounded post-scan events; this is not a live event stream or replay qualification.
    pub fn events(&self) -> &[EventEnvelope] {
        &self.events
    }

    /// Writes the complete compact machine envelope without a document-sized buffer/tree.
    ///
    /// At most one retained row is projected through the existing key converter at a time.
    /// Native encodings and evidence enum values remain unchanged. IO errors stop export and
    /// propagate to the caller; partial output is not a valid completed JSON document. Blocking
    /// writer calls have no hard deadline, and the caller owns any buffering/cancellation policy.
    pub fn write_json<W: Write>(&self, writer: W) -> Result<(), serde_json::Error> {
        if self.metadata.status == OutputStatus::Unsupported {
            return serde_json::to_writer(writer, &self.metadata);
        }
        serde_json::to_writer(writer, &Envelope(self))
    }

    /// Renders the ordinary human scan table with the existing locale/evidence formatters.
    /// Selection keeps only the best 40 row references. Borrowed path/aggregate indexes are
    /// bounded by the scanner's retained facts; native locators are never copied into the table.
    pub fn render_human(
        &self,
        context: &CoreContext,
        size_unit: HumanSizeUnit,
        sort: ScanSort,
    ) -> String {
        if self.metadata.status == OutputStatus::Unsupported {
            return render_human_output_with_size_unit(context, &self.metadata, size_unit, sort);
        }
        let selected = select_rows(&self.summary, sort, DEFAULT_HUMAN_SCAN_ROWS);
        let mut output = self.metadata.clone();
        let rows = selected
            .rows
            .into_sorted_vec()
            .into_iter()
            .map(|row| {
                // Only presentation fields reach the existing formatter. Identity, native
                // lineage, allocation claims and execution policy remain in the owned facts.
                json!({
                    "displayPath": row.entry.display_path,
                    "objectType": row.entry.object_type,
                    "reclaimableEstimate": row.bytes(),
                    "coverage": { "state": row.coverage().state }
                })
            })
            .collect::<Vec<_>>();
        let displayed = rows.len();
        output.data["roots"] = Value::Array(rows);
        output.data["entries"] = json!([]);
        output.data["aggregates"] = json!([]);
        render_human_scan_output_selected(
            context,
            &output,
            DEFAULT_HUMAN_SCAN_ROWS,
            size_unit,
            sort,
            selected.total.saturating_sub(displayed),
        )
    }
}

struct Envelope<'a>(&'a ScanOutput);
impl Serialize for Envelope<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let metadata = &self.0.metadata;
        let mut map = serializer.serialize_map(Some(12))?;
        map.serialize_entry("schema", &metadata.schema)?;
        map.serialize_entry("kind", &metadata.kind)?;
        map.serialize_entry("requestId", &metadata.request_id)?;
        map.serialize_entry("operationId", &metadata.operation_id)?;
        map.serialize_entry("generatedAt", &metadata.generated_at)?;
        map.serialize_entry("status", &metadata.status)?;
        map.serialize_entry("exitCode", &metadata.exit_code)?;
        map.serialize_entry("compat", &metadata.compat)?;
        map.serialize_entry("summary", &metadata.summary)?;
        map.serialize_entry("data", &Data(self.0))?;
        map.serialize_entry("warnings", &metadata.warnings)?;
        map.serialize_entry("errors", &metadata.errors)?;
        map.end()
    }
}

struct Data<'a>(&'a ScanOutput);
impl Serialize for Data<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let scan = self.0;
        let extras = scan.metadata.data.as_object();
        let mut map = serializer.serialize_map(Some(5 + extras.map_or(0, |map| map.len())))?;
        map.serialize_entry("scanId", &scan.metadata.summary["scanId"])?;
        map.serialize_entry("roots", &Rows(&scan.summary.roots))?;
        map.serialize_entry("entries", &Rows(&scan.summary.entries))?;
        map.serialize_entry("aggregates", &Rows(&scan.summary.aggregates))?;
        map.serialize_entry("boundaries", &Boundaries(&scan.summary.boundaries))?;
        for (key, value) in extras.into_iter().flatten() {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

struct Rows<'a, T>(&'a [T]);
impl<T: Serialize> Serialize for Rows<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for row in self.0 {
            let row = serde_json::to_value(row).map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&camelize_json_keys(row))?;
        }
        sequence.end()
    }
}

struct Boundaries<'a>(&'a [BoundaryRecord]);
impl Serialize for Boundaries<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for boundary in self.0 {
            sequence.serialize_element(&json!({
                "path": boundary.path.display().to_string(),
                "kind": boundary_label(&boundary.kind),
                "reason": boundary.reason,
                "detail": boundary.detail,
            }))?;
        }
        sequence.end()
    }
}

struct Selection<'a> {
    rows: BinaryHeap<Row<'a>>,
    total: usize,
}

fn select_rows(summary: &ScanSummary, sort: ScanSort, max_rows: usize) -> Selection<'_> {
    let mut aggregates = summary.aggregates.iter().collect::<Vec<_>>();
    aggregates.sort_unstable_by_key(|aggregate| aggregate.directory_identity.as_str());
    let mut seen = BTreeSet::new();
    let mut rows = BinaryHeap::with_capacity(max_rows);
    for entry in summary.roots.iter().chain(&summary.entries) {
        // Preserve the legacy table's display-path deduplication and root-first precedence.
        // The index borrows strings already charged by scan retention; no native facts are cloned.
        if !seen.insert(entry.display_path.as_str()) {
            continue;
        }
        let aggregate = entry.identity.as_ref().and_then(|identity| {
            aggregates
                .binary_search_by_key(&identity.entry_id.as_str(), |aggregate| {
                    aggregate.directory_identity.as_str()
                })
                .ok()
                .map(|index| aggregates[index])
        });
        let row = Row {
            entry,
            aggregate,
            sort,
        };
        if rows.len() < max_rows {
            rows.push(row);
        } else if rows.peek().is_some_and(|worst| row < *worst) {
            *rows.peek_mut().expect("nonempty selection") = row;
        }
    }
    Selection {
        rows,
        total: seen.len(),
    }
}

struct Row<'a> {
    entry: &'a ScannedEntry,
    aggregate: Option<&'a DirectoryAggregate>,
    sort: ScanSort,
}
impl Row<'_> {
    fn bytes(&self) -> &ByteValue {
        self.aggregate
            .map(|aggregate| &aggregate.potentially_reclaimable_bytes)
            .unwrap_or(&self.entry.reclaimable_estimate)
    }
    fn coverage(&self) -> &Coverage {
        self.aggregate
            .map(|aggregate| &aggregate.coverage)
            .unwrap_or(&self.entry.coverage)
    }
    fn value(&self) -> Option<u128> {
        match self.bytes() {
            EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => {
                Some(value.0)
            }
            _ => None,
        }
    }
}
impl PartialEq for Row<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Row<'_> {}
impl PartialOrd for Row<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Row<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Display order is ascending; BinaryHeap keeps the worst selected row on top.
        let size = match self.sort {
            ScanSort::Size => other.value().cmp(&self.value()),
            ScanSort::Path => Ordering::Equal,
        };
        size.then_with(|| self.entry.display_path.cmp(&other.entry.display_path))
    }
}

#[cfg(test)]
mod tests;
