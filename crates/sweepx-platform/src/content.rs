//! Explicit content access, separate from metadata scanning and deletion authority.

use crate::{
    BoundedRegularFileReadError, BoundedRegularFileReadRequest, CancellationToken, PlatformScanner,
    RegularFileObservation, RegularFileObservationMismatch, RegularFileReadExpectation,
    validate_bounded_read_child_name, validate_regular_file_expectation,
    validate_regular_file_observation_kind,
};
use sweepx_model::NativeName;

/// One validated basename and bounded range, paired with a retained parent capability.
/// Offsets/counts are limited to signed 64-bit file positions; no payload is retained here.
#[derive(Debug, Clone)]
pub struct RegularFileStreamRequest {
    binding: BoundedRegularFileReadRequest,
    offset: u64,
    max_bytes: u64,
    previous: Option<RegularFileObservation>,
}

impl RegularFileStreamRequest {
    /// Validates the name and range before opening anything. A prior observation binds size and
    /// change stamp across sample/full-hash stages, in addition to native identity and mount.
    pub fn new(
        name: NativeName,
        expectation: RegularFileReadExpectation,
        offset: u64,
        max_bytes: u64,
        previous: Option<RegularFileObservation>,
    ) -> Result<Self, BoundedRegularFileReadError> {
        if offset
            .checked_add(max_bytes)
            .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(BoundedRegularFileReadError::Unsupported(
                "content range exceeds signed 64-bit file positions".into(),
            ));
        }
        Ok(Self {
            binding: BoundedRegularFileReadRequest::new(name, expectation, 0)?,
            offset,
            max_bytes,
            previous,
        })
    }

    /// Validated native basename; never a display path.
    pub fn child_name(&self) -> &NativeName {
        self.binding.child_name()
    }

    /// Native identity/filesystem/mount expectation checked before content access.
    pub fn expectation(&self) -> &RegularFileReadExpectation {
        self.binding.expectation()
    }

    /// First requested logical byte.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Maximum bytes delivered, including all chunks, with no extra EOF probe.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Prior stage's complete observation, if present.
    pub fn previous(&self) -> Option<&RegularFileObservation> {
        self.previous.as_ref()
    }

    fn expected_bytes(&self, observed: &RegularFileObservation) -> u64 {
        observed
            .logical_bytes
            .0
            .saturating_sub(u128::from(self.offset))
            .min(u128::from(self.max_bytes)) as u64
    }
}

/// Successful range evidence; consumers must discard provisional chunks on an error instead.
/// This describes a stable observation interval, not an atomic filesystem snapshot or clean plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularFileStreamResult {
    /// Ordinary-file identity, size and change stamp checked before the first payload byte.
    pub observed_before: RegularFileObservation,
    /// Matching observation checked after all requested bytes.
    pub observed_after: RegularFileObservation,
    /// Exact delivered bytes, at most the request count and the available logical range.
    pub bytes_read: u64,
}

fn cancelled(cancel: &CancellationToken) -> Result<(), BoundedRegularFileReadError> {
    if cancel.is_cancelled() {
        Err(BoundedRegularFileReadError::Cancelled)
    } else {
        Ok(())
    }
}

fn unchanged(
    before: &RegularFileObservation,
    after: &RegularFileObservation,
) -> Result<(), BoundedRegularFileReadError> {
    validate_regular_file_observation_kind(after)?;
    if before != after {
        return Err(BoundedRegularFileReadError::ChangedDuringRead(Box::new(
            RegularFileObservationMismatch {
                observed_before: before.clone(),
                observed_after: after.clone(),
            },
        )));
    }
    Ok(())
}

fn validate_before(
    request: &RegularFileStreamRequest,
    observed: &RegularFileObservation,
) -> Result<(), BoundedRegularFileReadError> {
    validate_regular_file_observation_kind(observed)?;
    validate_regular_file_expectation(&request.binding, observed)?;
    if let Some(previous) = &request.previous {
        unchanged(previous, observed)?;
    }
    Ok(())
}

/// Checks range/count/stability around a backend's retained-parent streaming operation.
/// Chunks are provisional until this returns success. Cancellation or consumer refusal stops
/// delivery; backends lacking provider-safe content access return Unsupported without fallback.
pub fn stream_bound_regular_file<P: PlatformScanner + ?Sized>(
    platform: &P,
    parent: &P::DirectoryHandle,
    request: &RegularFileStreamRequest,
    cancel: &CancellationToken,
    consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
) -> Result<RegularFileStreamResult, BoundedRegularFileReadError> {
    cancelled(cancel)?;
    validate_bounded_read_child_name(request.child_name())?;
    let mut delivered = 0u64;
    let mut refused: Option<BoundedRegularFileReadError> = None;
    let mut guarded = |bytes: &[u8]| {
        if let Some(error) = &refused {
            return Err(error.clone());
        }
        let result = (|| {
            cancelled(cancel)?;
            let next = delivered
                .checked_add(bytes.len() as u64)
                .filter(|count| *count <= request.max_bytes)
                .ok_or_else(|| {
                    BoundedRegularFileReadError::io(std::io::Error::other(
                        "backend exceeded content range",
                    ))
                })?;
            consume(bytes)?;
            delivered = next;
            cancelled(cancel)
        })();
        if let Err(error) = &result {
            refused = Some(error.clone());
        }
        result
    };
    let result = platform.stream_regular_file_relative(parent, request, cancel, &mut guarded);
    if let Some(error) = refused {
        return Err(error);
    }
    let result = result?;
    cancelled(cancel)?;
    validate_before(request, &result.observed_before)?;
    unchanged(&result.observed_before, &result.observed_after)?;
    if result.bytes_read != delivered
        || delivered != request.expected_bytes(&result.observed_before)
    {
        return Err(BoundedRegularFileReadError::io(std::io::Error::other(
            "backend returned an incomplete or inconsistent content range",
        )));
    }
    Ok(result)
}

// Native backends share the same fixed-size transfer and checks. Their opens, no-recall guards,
// mount evidence and positional reads remain platform-owned. No file-size-proportional Vec.
#[cfg(any(
    all(target_os = "macos", feature = "backend-macos"),
    all(target_os = "linux", feature = "backend-linux"),
    all(windows, feature = "backend-windows"),
    test
))]
pub(crate) fn stream_observed_file(
    request: &RegularFileStreamRequest,
    cancel: &CancellationToken,
    before: RegularFileObservation,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Result<usize, BoundedRegularFileReadError>,
    observe_after: impl FnOnce() -> Result<RegularFileObservation, BoundedRegularFileReadError>,
    consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
) -> Result<RegularFileStreamResult, BoundedRegularFileReadError> {
    cancelled(cancel)?;
    validate_before(request, &before)?;
    let expected = request.expected_bytes(&before);
    let mut delivered = 0;
    let mut buffer = [0u8; 64 * 1024];
    while delivered < expected {
        cancelled(cancel)?;
        let requested = (expected - delivered).min(buffer.len() as u64) as usize;
        let count = read_at(request.offset + delivered, &mut buffer[..requested])?;
        cancelled(cancel)?;
        if count == 0 || count > requested {
            return Err(BoundedRegularFileReadError::io(std::io::Error::other(
                "content read returned early EOF or an invalid chunk count",
            )));
        }
        consume(&buffer[..count])?;
        delivered += count as u64;
    }
    cancelled(cancel)?;
    let after = observe_after()?;
    cancelled(cancel)?;
    unchanged(&before, &after)?;
    Ok(RegularFileStreamResult {
        observed_before: before,
        observed_after: after,
        bytes_read: delivered,
    })
}

#[cfg(test)]
mod tests;

#[cfg(all(
    test,
    any(
        all(target_os = "macos", feature = "backend-macos"),
        all(target_os = "linux", feature = "backend-linux"),
        all(windows, feature = "backend-windows")
    )
))]
mod native_tests;
