use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PLAN_DIGEST_DOMAIN: &[u8] = b"SweepX plan v1\0";
pub const ATTENTION_FINGERPRINT_PREFIX: &str = "SX1-";

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to convert value to canonical JSON: {0}")]
    Canonicalize(#[from] serde_json::Error),
    #[error("expected JSON object at root for plan digest")]
    RootNotObject,
}

pub fn canonical_json_bytes<T>(value: &T) -> Result<Vec<u8>, CanonicalError>
where
    T: Serialize,
{
    Ok(serde_jcs::to_vec(value)?)
}

pub fn canonical_json_string<T>(value: &T) -> Result<String, CanonicalError>
where
    T: Serialize,
{
    Ok(String::from_utf8(canonical_json_bytes(value)?).expect("JCS is UTF-8"))
}

pub fn canonicalize_value(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    Ok(serde_jcs::to_vec(value)?)
}

pub fn plan_digest_hex<T>(plan_without_canonical_digest: &T) -> Result<String, CanonicalError>
where
    T: Serialize,
{
    let canonical = canonical_json_bytes(plan_without_canonical_digest)?;
    Ok(plan_digest_hex_from_canonical(&canonical))
}

pub fn plan_digest_hex_from_value_without_canonical_digest(
    value: &Value,
) -> Result<String, CanonicalError> {
    Ok(plan_digest_hex_from_canonical(&canonicalize_value(value)?))
}

pub fn plan_digest_hex_from_canonical(canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(canonical);
    hex_lower(hasher.finalize().as_slice())
}

pub fn attention_fingerprint_from_digest_hex(digest_hex: &str) -> String {
    let prefix: String = digest_hex
        .chars()
        .take(12)
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    format!("{ATTENTION_FINGERPRINT_PREFIX}{prefix}")
}

pub fn plan_attention_fingerprint<T>(
    plan_without_canonical_digest: &T,
) -> Result<String, CanonicalError>
where
    T: Serialize,
{
    Ok(attention_fingerprint_from_digest_hex(&plan_digest_hex(
        plan_without_canonical_digest,
    )?))
}

pub fn strip_object_key(root: &Value, key: &str) -> Result<Value, CanonicalError> {
    let mut object = match root {
        Value::Object(map) => map.clone(),
        _ => return Err(CanonicalError::RootNotObject),
    };
    object.remove(key);
    Ok(Value::Object(object))
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_is_deterministic_across_key_order() {
        let left = json!({
            "b": 2,
            "a": 1,
            "nested": {"z": 3, "y": 2}
        });
        let right = json!({
            "nested": {"y": 2, "z": 3},
            "a": 1,
            "b": 2
        });

        let left_canonical = canonical_json_string(&left).unwrap();
        let right_canonical = canonical_json_string(&right).unwrap();

        assert_eq!(left_canonical, right_canonical);
        assert_eq!(left_canonical, r#"{"a":1,"b":2,"nested":{"y":2,"z":3}}"#);
    }

    #[test]
    fn plan_digest_uses_domain_separation_and_is_deterministic() {
        let plan = json!({
            "schema": "sweepx.plan/v1",
            "plan_id": "plan-1",
            "mode": "Trash",
            "items": [{"item_id": "item-1"}]
        });

        let digest1 = plan_digest_hex(&plan).unwrap();
        let digest2 = plan_digest_hex(&plan).unwrap();

        assert_eq!(digest1, digest2);
        assert_eq!(digest1.len(), 64);

        let raw_sha = {
            let canonical = canonical_json_bytes(&plan).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(canonical);
            hex_lower(hasher.finalize().as_slice())
        };
        assert_ne!(digest1, raw_sha);
    }

    #[test]
    fn attention_fingerprint_is_short_and_not_the_full_digest() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let fingerprint = attention_fingerprint_from_digest_hex(digest);
        assert_eq!(fingerprint, "SX1-0123456789AB");
        assert_ne!(fingerprint, digest);
        assert!(fingerprint.len() < digest.len());
    }

    #[test]
    fn strip_object_key_removes_canonical_digest_before_hashing() {
        let plan = json!({
            "schema": "sweepx.plan/v1",
            "plan_id": "plan-1",
            "canonical_digest": "placeholder"
        });
        let stripped = strip_object_key(&plan, "canonical_digest").unwrap();
        assert_eq!(
            stripped,
            json!({
                "schema": "sweepx.plan/v1",
                "plan_id": "plan-1"
            })
        );
    }
}
