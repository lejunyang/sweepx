//! Invocation-local bounds for temporary-object facts and current-user process observations.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Instant;
use sweepx_platform::CancellationToken;

/// Bounds for one Linux temporary-object discovery or independent cleanup revalidation.
/// Exhaustion is incomplete evidence, never proof of inactivity or absence of references.
#[derive(Debug, Clone, Copy)]
pub struct LinuxTempObservationLimits {
    /// Total enumerated directory/process records, including repeated safety observations.
    pub max_observations: usize,
    /// Cumulative retained-model admission estimate; conservative, not an allocator RSS cap.
    pub max_retained_bytes: usize,
    /// Names admitted in one directory enumeration, before returning any name list.
    pub max_directory_entries: usize,
    /// Native name bytes admitted in one directory enumeration.
    pub max_directory_name_bytes: usize,
    /// Bytes read from one process mount/socket table; oversized tables are refused in full.
    pub max_proc_table_bytes: usize,
    /// Cumulative process-table input bytes across this invocation, including overflow probes.
    pub max_proc_read_bytes: usize,
}

impl Default for LinuxTempObservationLimits {
    fn default() -> Self {
        Self {
            max_observations: 1_000_000,
            max_retained_bytes: 64 * 1024 * 1024,
            max_directory_entries: 65_536,
            max_directory_name_bytes: 8 * 1024 * 1024,
            max_proc_table_bytes: 4 * 1024 * 1024,
            max_proc_read_bytes: 64 * 1024 * 1024,
        }
    }
}

pub(super) struct Observation {
    pub limits: LinuxTempObservationLimits,
    deadline: Instant,
    cancel: CancellationToken,
    observations: usize,
    retained_bytes: usize,
    read_bytes: usize,
    // A failed resource admission ends this invocation. It cannot regain validity by accepting
    // a smaller later candidate or observing an empty table after truncation.
    failure: Option<&'static str>,
}

impl Observation {
    pub fn new(
        deadline: Instant,
        cancel: CancellationToken,
        limits: LinuxTempObservationLimits,
    ) -> Self {
        Self {
            deadline,
            cancel,
            limits,
            observations: 0,
            retained_bytes: 0,
            read_bytes: 0,
            failure: None,
        }
    }

    pub fn check(&self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            Err("linux tmp observation cancelled".into())
        } else if Instant::now() >= self.deadline {
            Err("linux tmp observation deadline reached".into())
        } else if let Some(reason) = self.failure {
            Err(reason.into())
        } else {
            Ok(())
        }
    }

    pub fn observe(&mut self) -> Result<(), String> {
        self.check()?;
        if self.observations >= self.limits.max_observations {
            self.failure = Some("linux tmp observation count limit reached");
            return Err("linux tmp observation count limit reached".into());
        }
        self.observations += 1;
        Ok(())
    }

    pub fn retain(&mut self, cost: usize) -> Result<(), String> {
        self.check()?;
        let Some(total) = self
            .retained_bytes
            .checked_add(cost)
            .filter(|total| *total <= self.limits.max_retained_bytes)
        else {
            self.failure = Some("linux tmp retained fact budget reached");
            return Err("linux tmp retained fact budget reached".into());
        };
        self.retained_bytes = total;
        Ok(())
    }

    pub fn directory_record(
        &mut self,
        count: usize,
        previous_name_bytes: usize,
        name_bytes: usize,
        retained_cost: usize,
    ) -> Result<usize, String> {
        self.observe()?;
        if count >= self.limits.max_directory_entries {
            self.failure = Some("linux tmp directory entry limit reached");
            return Err("linux tmp directory entry limit reached".into());
        }
        let Some(total) = previous_name_bytes
            .checked_add(name_bytes)
            .filter(|bytes| *bytes <= self.limits.max_directory_name_bytes)
        else {
            self.failure = Some("linux tmp directory name byte limit reached");
            return Err("linux tmp directory name byte limit reached".into());
        };
        self.retain(retained_cost)?;
        Ok(total)
    }

    /// Never parse a prefix of an oversized table as complete negative reference evidence.
    /// Reads are chunked with cancellation/deadline checks; native calls remain cooperative.
    pub fn read_table(&mut self, path: &Path) -> io::Result<String> {
        self.check().map_err(io::Error::other)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other(
                "process observation table is not a regular file",
            ));
        }
        let mut content = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            self.check().map_err(io::Error::other)?;
            let remaining = self
                .limits
                .max_proc_read_bytes
                .saturating_sub(self.read_bytes);
            if remaining == 0 {
                self.failure = Some("linux tmp process input budget reached");
                return Err(io::Error::other("linux tmp process input budget reached"));
            }
            let probe = self
                .limits
                .max_proc_table_bytes
                .saturating_sub(content.len())
                .saturating_add(1)
                .min(remaining)
                .min(chunk.len());
            let count = file.read(&mut chunk[..probe])?;
            self.read_bytes += count;
            if count == 0 {
                break;
            }
            if count
                > self
                    .limits
                    .max_proc_table_bytes
                    .saturating_sub(content.len())
            {
                self.failure = Some("linux tmp process table byte limit reached");
                return Err(io::Error::other(
                    "linux tmp process table byte limit reached",
                ));
            }
            // Explicit capacity avoids a geometrically grown buffer crossing the input bound.
            content.reserve_exact(count);
            content.extend_from_slice(&chunk[..count]);
        }
        self.check().map_err(io::Error::other)?;
        String::from_utf8(content)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn observation(limits: LinuxTempObservationLimits) -> Observation {
        Observation::new(
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            limits,
        )
    }

    #[test]
    fn cancellation_and_deadline_refuse_before_opening_a_table() {
        let cancel = CancellationToken::new();
        let mut budget = Observation::new(
            Instant::now() + Duration::from_secs(5),
            cancel.clone(),
            LinuxTempObservationLimits::default(),
        );
        cancel.cancel();
        assert!(
            budget
                .read_table(Path::new("/definitely-missing-table"))
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        assert!(budget.observe().is_err());
        let mut expired = Observation::new(
            Instant::now(),
            CancellationToken::new(),
            LinuxTempObservationLimits::default(),
        );
        assert!(
            expired
                .read_table(Path::new("/definitely-missing-table"))
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
    }

    #[test]
    fn oversized_process_input_cannot_return_a_negative_prefix() {
        let fixture = tempfile::tempdir().unwrap();
        let table = fixture.path().join("table");
        std::fs::write(&table, b"ordinary\nreference-at-end\n").unwrap();
        let mut budget = observation(LinuxTempObservationLimits {
            max_proc_table_bytes: 9,
            ..Default::default()
        });
        assert!(
            budget
                .read_table(&table)
                .unwrap_err()
                .to_string()
                .contains("table byte limit")
        );
        std::fs::write(&table, b"ordinary\n").unwrap();
        let mut budget = observation(LinuxTempObservationLimits {
            max_proc_table_bytes: 9,
            ..Default::default()
        });
        assert_eq!(budget.read_table(&table).unwrap(), "ordinary\n");
    }

    #[test]
    fn input_budget_is_shared_across_tables() {
        let fixture = tempfile::tempdir().unwrap();
        let table = fixture.path().join("table");
        std::fs::write(&table, b"1234").unwrap();
        let mut budget = observation(LinuxTempObservationLimits {
            max_proc_read_bytes: 9,
            ..Default::default()
        });
        assert_eq!(budget.read_table(&table).unwrap(), "1234");
        assert_eq!(budget.read_table(&table).unwrap(), "1234");
        assert!(
            budget
                .read_table(&table)
                .unwrap_err()
                .to_string()
                .contains("input budget")
        );
    }

    #[test]
    fn directory_limits_refuse_surplus_names_before_retention() {
        let mut budget = observation(LinuxTempObservationLimits {
            max_directory_entries: 2,
            max_directory_name_bytes: 4,
            ..Default::default()
        });
        let bytes = budget.directory_record(0, 0, 2, 128).unwrap();
        let bytes = budget.directory_record(1, bytes, 2, 128).unwrap();
        assert_eq!(bytes, 4);
        assert!(
            budget
                .directory_record(2, bytes, 1, 128)
                .unwrap_err()
                .contains("entry limit")
        );
        let mut budget = observation(LinuxTempObservationLimits {
            max_directory_name_bytes: 3,
            ..Default::default()
        });
        let bytes = budget.directory_record(0, 0, 2, 128).unwrap();
        assert!(
            budget
                .directory_record(1, bytes, 2, 128)
                .unwrap_err()
                .contains("name byte limit")
        );
    }

    #[test]
    fn model_and_observation_limits_do_not_reset_between_candidates() {
        let mut budget = observation(LinuxTempObservationLimits {
            max_observations: 2,
            max_retained_bytes: 7,
            ..Default::default()
        });
        budget.observe().unwrap();
        budget.observe().unwrap();
        assert!(budget.observe().is_err());
        assert!(budget.check().is_err());
        let mut budget = observation(LinuxTempObservationLimits {
            max_retained_bytes: 7,
            ..Default::default()
        });
        budget.retain(3).unwrap();
        budget.retain(4).unwrap();
        assert!(budget.retain(1).is_err());
    }

    #[test]
    fn table_links_and_special_files_cannot_block_the_reader() {
        let fixture = tempfile::tempdir().unwrap();
        let table = fixture.path().join("table");
        let link = fixture.path().join("link");
        std::fs::write(&table, b"valid").unwrap();
        std::os::unix::fs::symlink(&table, &link).unwrap();
        let mut budget = observation(LinuxTempObservationLimits::default());
        assert!(budget.read_table(&link).is_err());
        assert!(budget.read_table(fixture.path()).is_err());
        let fifo = fixture.path().join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let native = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: the fixture owns the path and CString supplies a valid terminated argument.
        assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
        assert!(
            budget
                .read_table(&fifo)
                .unwrap_err()
                .to_string()
                .contains("not a regular file")
        );
    }
}
