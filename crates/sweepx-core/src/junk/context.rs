//! Streaming classification context digests. A filesystem history validates observations inside
//! a root; it cannot validate enabled rules or discovery driven by configuration outside that root.

use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub(super) struct ContextHash {
    hash: Sha256,
    bytes: usize,
}

impl ContextHash {
    pub fn new(project_bytes: &[u8; 32]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"sweepx.junk-classification-context/v1\0");
        hash.update(project_bytes);
        Self { hash, bytes: 0 }
    }

    pub fn fact(&mut self, fact: impl serde::Serialize) -> Option<()> {
        // Stream into fixed hash state rather than allocating another discovery-sized JSON blob.
        serde_json::to_writer(&mut *self, &fact).ok()?;
        self.hash.update([0]);
        Some(())
    }

    pub fn finish(self) -> [u8; 32] {
        self.hash.finalize().into()
    }
}

impl Write for ContextHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Independently bound serialization work even for a caller supplying custom rule structs.
        // Exhaustion declines candidate reuse; the live classifier and file index remain available.
        if self.bytes.saturating_add(bytes.len()) > 1024 * 1024 {
            return Err(io::Error::other(
                "classification context exceeds byte budget",
            ));
        }
        self.bytes += bytes.len();
        self.hash.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
