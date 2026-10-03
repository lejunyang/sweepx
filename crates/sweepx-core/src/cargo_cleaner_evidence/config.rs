//! One TOML decoder shared by bounded reporting and the narrower cleaner contract.

use super::{CargoEvidenceReason, MAX_CARGO_INPUT_FILE_BYTES, parse_toml};

#[derive(Clone)]
/// One admitted include declaration; optional means typed missing input, never failed reads.
pub(crate) struct CargoConfigInclude {
    /// Private config-relative spelling; the native reader normalizes the complete joined path.
    pub path: String,
    /// A missing parent/file may be skipped, but errors or invalid TOML may not.
    pub optional: bool,
}

#[derive(Clone)]
/// One bounded decoded configuration, before recursive composition or scalar selection.
pub(crate) struct CargoConfigInput {
    /// File-owned values with top-level include removed; never serialized or persisted.
    pub values: toml::Table,
    /// Ordered inputs: later includes override earlier ones before this file's own values.
    pub includes: Vec<CargoConfigInclude>,
}

/// Decodes the input once. Include fields are data only; no filesystem operation runs here.
/// Unknown inline fields are ignored like pinned Cargo; path/optional types and lowercase
/// `.toml` extensions are checked even when an optional file may be absent.
pub(crate) fn decode_cargo_config_input(bytes: &[u8]) -> Result<CargoConfigInput, &'static str> {
    let mut values = parse_config_table(bytes).map_err(CargoEvidenceReason::code)?;
    let mut includes = Vec::new();
    if let Some(value) = values.remove("include") {
        let toml::Value::Array(entries) = value else {
            return Err("invalid_config_include");
        };
        if entries.len() > 128 {
            return Err("config_include_limit");
        }
        for entry in entries {
            let (path, optional) = match entry {
                toml::Value::String(path) => (path, false),
                toml::Value::Table(mut fields) => {
                    let Some(toml::Value::String(path)) = fields.remove("path") else {
                        return Err("invalid_config_include");
                    };
                    let optional = match fields.remove("optional") {
                        None => false,
                        Some(toml::Value::Boolean(optional)) => optional,
                        Some(_) => return Err("invalid_config_include"),
                    };
                    (path, optional)
                }
                _ => return Err("invalid_config_include"),
            };
            if path.len() > 4096 {
                return Err("resource_limit");
            }
            if !path.ends_with(".toml") || path.contains('\0') {
                return Err("invalid_config_include");
            }
            includes.push(CargoConfigInclude { path, optional });
        }
    }
    Ok(CargoConfigInput { values, includes })
}

pub(super) fn parse_config_table(bytes: &[u8]) -> Result<toml::Table, CargoEvidenceReason> {
    if bytes.len() > MAX_CARGO_INPUT_FILE_BYTES {
        return Err(CargoEvidenceReason::ResourceLimit);
    }
    parse_toml(bytes)
}
