//! Cooperatively bounded quarantine work. Checks cannot forcibly interrupt native kernel calls.

use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use sweepx_platform::CancellationToken;

/// Bounds for one preview or execution, renewed only by a new explicit operation.
#[derive(Debug, Clone, Copy)]
pub struct QuarantineLimits {
    /// Total native path visits, including copy and verification passes.
    pub max_path_visits: usize,
    /// Cumulative path/model admission estimate; not peak allocator RSS.
    pub max_retained_bytes: usize,
    /// Maximum native path depth; also bounds retained removal directory descriptors.
    pub max_depth: usize,
    /// Total copied/verified bytes; logical verification of sparse files also counts.
    pub max_io_bytes: u128,
    /// Cooperative deadline; cannot forcibly interrupt a blocked kernel I/O operation.
    pub deadline: Duration,
}

/// Bounded logical fallback; a file growing concurrently cannot turn a planned copy into unbounded I/O.
pub(super) fn copy_stream(
    input: &mut impl Read,
    output: &mut impl Write,
    mut remaining: u64,
    operation: &mut Operation,
) -> io::Result<()> {
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        operation.io(chunk as u64)?;
        input.read_exact(&mut buffer[..chunk])?;
        // A cancellation raised by/while reading must not silently continue into writes.
        operation.check().map_err(io::Error::other)?;
        output.write_all(&buffer[..chunk])?;
        remaining -= chunk as u64;
    }
    operation.check().map_err(io::Error::other)
}
impl Default for QuarantineLimits {
    fn default() -> Self {
        Self {
            max_path_visits: 1_000_000,
            max_retained_bytes: 64 * 1024 * 1024,
            max_depth: 128,
            max_io_bytes: 1024 * 1024 * 1024 * 1024,
            deadline: Duration::from_secs(900),
        }
    }
}

pub(super) struct Operation {
    cancel: CancellationToken,
    deadline: Instant,
    limits: QuarantineLimits,
    visits: usize,
    retained: usize,
    io_bytes: u128,
    failure: Option<&'static str>,
}
impl Operation {
    pub fn new(cancel: CancellationToken, limits: QuarantineLimits) -> Result<Self, String> {
        let deadline = Instant::now()
            .checked_add(limits.deadline)
            .ok_or_else(|| "quarantine deadline overflow".to_string())?;
        Ok(Self {
            cancel,
            deadline,
            limits,
            visits: 0,
            retained: 0,
            io_bytes: 0,
            failure: None,
        })
    }
    pub fn check(&self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            Err("quarantine cancelled".into())
        } else if Instant::now() >= self.deadline {
            Err("quarantine deadline reached".into())
        } else if let Some(reason) = self.failure {
            Err(reason.into())
        } else {
            Ok(())
        }
    }
    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn limits(&self) -> QuarantineLimits {
        self.limits
    }
    pub fn admit_path(&mut self, path: &Path) -> Result<(), String> {
        self.check()?;
        if self.visits >= self.limits.max_path_visits
            || path.components().count() > self.limits.max_depth
        {
            self.failure = Some("quarantine path/depth limit reached");
            return self.check();
        }
        let total = self
            .retained
            .checked_add(512)
            .and_then(|value| value.checked_add(path.as_os_str().len()));
        let Some(total) = total.filter(|value| *value <= self.limits.max_retained_bytes) else {
            self.failure = Some("quarantine retained model limit reached");
            return self.check();
        };
        self.visits += 1;
        self.retained = total;
        Ok(())
    }
    pub fn io(&mut self, bytes: u64) -> io::Result<()> {
        self.check().map_err(io::Error::other)?;
        let total = self.io_bytes.checked_add(u128::from(bytes));
        let Some(total) = total.filter(|value| *value <= self.limits.max_io_bytes) else {
            self.failure = Some("quarantine I/O byte limit reached");
            return Err(io::Error::other("quarantine I/O byte limit reached"));
        };
        self.io_bytes = total;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_deadline_and_byte_failures_stay_failed() {
        let cancel = CancellationToken::new();
        let mut op = Operation::new(
            cancel.clone(),
            QuarantineLimits {
                max_io_bytes: 7,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(op.limits().max_io_bytes, 7);
        op.io(4).unwrap();
        assert!(op.io(4).is_err());
        assert!(op.io(0).is_err());
        let op = Operation::new(cancel.clone(), Default::default()).unwrap();
        assert!(op.deadline() > Instant::now());
        assert!(!op.cancel().is_cancelled());
        cancel.cancel();
        assert!(op.check().unwrap_err().contains("cancelled"));
        let op = Operation::new(
            CancellationToken::new(),
            QuarantineLimits {
                deadline: Duration::ZERO,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(op.check().unwrap_err().contains("deadline"));
    }
    #[test]
    fn path_frontier_and_retained_model_have_independent_limits() {
        let mut op = Operation::new(
            CancellationToken::new(),
            QuarantineLimits {
                max_depth: 2,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(op.admit_path(Path::new("one/two/three")).is_err());
        let mut op = Operation::new(
            CancellationToken::new(),
            QuarantineLimits {
                max_path_visits: 1,
                ..Default::default()
            },
        )
        .unwrap();
        op.admit_path(Path::new("first")).unwrap();
        assert!(op.admit_path(Path::new("next")).is_err());
        let mut op = Operation::new(
            CancellationToken::new(),
            QuarantineLimits {
                max_retained_bytes: 513,
                ..Default::default()
            },
        )
        .unwrap();
        op.admit_path(Path::new("a")).unwrap();
        assert!(op.admit_path(Path::new("b")).is_err());
    }

    #[test]
    fn logical_copy_is_exact_and_stops_before_writes_after_cancellation() {
        let mut source = io::Cursor::new(b"planned-extra-growth");
        let mut output = Vec::new();
        let mut op = Operation::new(CancellationToken::new(), Default::default()).unwrap();
        copy_stream(&mut source, &mut output, 7, &mut op).unwrap();
        assert_eq!(output, b"planned");
        struct CancellingRead(CancellationToken);
        impl Read for CancellingRead {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                output.fill(b'x');
                self.0.cancel();
                Ok(output.len())
            }
        }
        let cancel = CancellationToken::new();
        let mut source = CancellingRead(cancel.clone());
        let mut output = Vec::new();
        let mut op = Operation::new(cancel, Default::default()).unwrap();
        assert!(copy_stream(&mut source, &mut output, 5, &mut op).is_err());
        assert!(output.is_empty());
    }
}
