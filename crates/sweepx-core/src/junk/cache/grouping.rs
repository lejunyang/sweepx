//! Optional cache publication views. Borrowed facts are assigned once to their original scope.

#[cfg(any(target_os = "macos", test))]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sweepx_platform::CancellationToken;
#[cfg(any(target_os = "macos", test))]
use sweepx_scanner::DirListing;

/// Independent capacity allowance for publication views; this is an estimate, not allocator RSS.
pub(crate) const DEFAULT_GROUPING_BYTES: usize = 8 * 1024 * 1024;

/// Charges auxiliary allocation capacities before optional publication copies are made.
pub(crate) struct GroupingBudget {
    limit: usize,
    used: usize,
}

impl GroupingBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    pub(crate) fn used_bytes(&self) -> usize {
        self.used
    }

    /// Charges auxiliary nodes whose allocation has no capacity API, such as ordered-map nodes.
    pub(crate) fn charge(&mut self, bytes: usize) -> bool {
        let Some(used) = self
            .used
            .checked_add(bytes)
            .filter(|used| *used <= self.limit)
        else {
            return false;
        };
        self.used = used;
        true
    }

    /// Geometric growth avoids a reallocation per borrowed row, while charging spare capacity.
    fn reserve<T>(&mut self, values: &mut Vec<T>, needed: usize) -> bool {
        if needed <= values.capacity() {
            return true;
        }
        let Some(target) = values
            .capacity()
            .checked_mul(2)
            .map(|size| size.max(needed))
        else {
            return false;
        };
        let old_capacity = values.capacity();
        let Some(cost) = target
            .checked_sub(old_capacity)
            .and_then(|count| count.checked_mul(std::mem::size_of::<T>()))
        else {
            return false;
        };
        if cost > self.limit.saturating_sub(self.used)
            || values.try_reserve_exact(target - values.len()).is_err()
        {
            return false;
        }
        // Vec may provide more capacity than requested. Account for the capacity actually kept;
        // on failure the entire optional view is discarded instead of weakening scan evidence.
        let Some(cost) = values
            .capacity()
            .checked_sub(old_capacity)
            .and_then(|count| count.checked_mul(std::mem::size_of::<T>()))
        else {
            return false;
        };
        self.charge(cost)
    }
}

/// Native lexical root ownership, retaining the caller's original order and spelling.
pub(crate) struct RootScope<'a> {
    roots: &'a [PathBuf],
    depths: Vec<usize>,
}

impl<'a> RootScope<'a> {
    pub(crate) fn new(roots: &'a [PathBuf], budget: &mut GroupingBudget) -> Option<Self> {
        let mut depths = Vec::new();
        if !budget.reserve(&mut depths, roots.len()) {
            return None;
        }
        depths.extend(roots.iter().map(|root| root.components().count()));
        Some(Self { roots, depths })
    }

    pub(crate) fn len(&self) -> usize {
        self.roots.len()
    }

    /// Only the last occurrence of the same native root spelling may publish a root record.
    pub(crate) fn is_representative(&self, ordinal: usize) -> bool {
        self.roots
            .get(ordinal)
            .is_some_and(|root| self.owner_index(root) == Some(ordinal))
    }

    /// Matches the previous `max_by_key`: deepest prefix wins, and equal depths choose last.
    /// This attribution is only for cache facts. It never admits or authorizes a native object.
    pub(crate) fn owner_index(&self, path: &Path) -> Option<usize> {
        let mut owner = None;
        let mut depth = 0;
        for (ordinal, (root, candidate_depth)) in self.roots.iter().zip(&self.depths).enumerate() {
            if *candidate_depth >= depth && path.starts_with(root) {
                owner = Some(ordinal);
                depth = *candidate_depth;
            }
        }
        owner
    }
}

/// Borrowed per-root buckets, charged together with the scope and other publication views.
pub(crate) struct RootGroups<T> {
    groups: Vec<Vec<T>>,
}

impl<T> RootGroups<T> {
    pub(crate) fn new(roots: usize, budget: &mut GroupingBudget) -> Option<Self> {
        let mut groups = Vec::new();
        if !budget.reserve(&mut groups, roots) {
            return None;
        }
        groups.resize_with(roots, Vec::new);
        Some(Self { groups })
    }

    pub(crate) fn push(&mut self, owner: usize, item: T, budget: &mut GroupingBudget) -> bool {
        let Some(group) = self.groups.get_mut(owner) else {
            return false;
        };
        let Some(needed) = group.len().checked_add(1) else {
            return false;
        };
        if !budget.reserve(group, needed) {
            return false;
        }
        group.push(item);
        true
    }

    pub(crate) fn get(&self, owner: usize) -> &[T] {
        &self.groups[owner]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.groups.iter().all(Vec::is_empty)
    }
}

/// Assigns native-bound borrowed facts once. Missing native evidence rejects the whole optional
/// view rather than publishing a truncated candidate set as a complete root or selected fragment.
pub(crate) fn group_native<T>(
    scope: &RootScope<'_>,
    items: impl IntoIterator<Item = T>,
    mut native_path: impl FnMut(&T) -> Option<PathBuf>,
    selected: Option<&[PathBuf]>,
    budget: &mut GroupingBudget,
    cancel: &CancellationToken,
) -> Option<RootGroups<T>> {
    let mut groups = RootGroups::new(scope.len(), budget)?;
    for item in items {
        if cancel.is_cancelled() {
            return None;
        }
        let path = native_path(&item)?;
        if selected.is_none_or(|paths| paths.iter().any(|selected| path.starts_with(selected)))
            && let Some(owner) = scope.owner_index(&path)
            && !groups.push(owner, item, budget)
        {
            return None;
        }
    }
    (!cancel.is_cancelled()).then_some(groups)
}

/// Finds the first observed source for each original root, decoding each native locator once.
/// Equal root spellings use their final scope ordinal so no earlier empty duplicate is published.
pub(crate) fn group_sources<'a>(
    scope: &RootScope<'_>,
    sources: &'a [sweepx_model::ScannedEntry],
    budget: &mut GroupingBudget,
    cancel: &CancellationToken,
) -> Option<RootGroups<&'a sweepx_model::ScannedEntry>> {
    let mut groups = RootGroups::new(scope.len(), budget)?;
    for source in sources {
        if cancel.is_cancelled() {
            return None;
        }
        let Some(path) = crate::junk::git::native_path(source) else {
            continue;
        };
        if let Some(owner) = scope.owner_index(&path)
            && path == scope.roots[owner]
            && groups.get(owner).is_empty()
            && !groups.push(owner, source, budget)
        {
            return None;
        }
    }
    (!cancel.is_cancelled()).then_some(groups)
}

/// Partitions fully enumerated listings once, preserving each root's previous BTree order.
/// Exhaustion or cancellation omits optional cache publication; it does not lose live facts.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn group_listings<'a>(
    scope: &RootScope<'_>,
    covered: &BTreeMap<String, bool>,
    listings: &'a BTreeMap<String, DirListing>,
    budget: &mut GroupingBudget,
    cancel: &CancellationToken,
) -> Option<RootGroups<(&'a String, &'a DirListing)>> {
    let mut groups = RootGroups::new(scope.len(), budget)?;
    for (path, listing) in listings {
        if cancel.is_cancelled() {
            return None;
        }
        if covered.get(path) == Some(&true)
            && let Some(owner) = scope.owner_index(Path::new(path))
            && !groups.push(owner, (path, listing), budget)
        {
            return None;
        }
    }
    (!cancel.is_cancelled()).then_some(groups)
}

#[cfg(test)]
#[path = "grouping_contract_tests.rs"]
mod tests;
