use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const ANALYSIS_DIGEST_DOMAIN: &[u8] = b"SweepX analysis v1\0";

#[derive(Debug, Error)]
pub enum AnalysisDigestError {
    #[error("failed to canonicalize analysis payload: {0}")]
    Canonical(#[from] sweepx_canonical::CanonicalError),
}

pub fn analysis_digest_hex<T>(value: &T) -> Result<String, AnalysisDigestError>
where
    T: Serialize,
{
    let canonical = sweepx_canonical::canonical_json_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(ANALYSIS_DIGEST_DOMAIN);
    hasher.update(&canonical);
    Ok(hex_lower(hasher.finalize().as_slice()))
}

pub fn analysis_attention_fingerprint<T>(value: &T) -> Result<String, AnalysisDigestError>
where
    T: Serialize,
{
    Ok(sweepx_canonical::attention_fingerprint_from_digest_hex(
        &analysis_digest_hex(value)?,
    ))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
