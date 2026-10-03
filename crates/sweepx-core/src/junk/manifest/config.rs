//! Bounded recursive Cargo include composition, independent of native reads or rendering.
//! Paths/origins remain private data. This computes a scalar model, never cleanup authority.

use crate::cargo_cleaner_evidence::CargoConfigInput;

/// A bounded input source. Missing inputs are separate from denied/failed observations.
pub(super) trait ConfigSource {
    type Key: Clone + Eq;
    fn check(&mut self) -> Result<(), &'static str>;
    fn load(&mut self, key: &Self::Key) -> Result<Option<CargoConfigInput>, &'static str>;
    fn resolve(&mut self, from: &Self::Key, path: &str) -> Result<Option<Self::Key>, &'static str>;
}

/// Composed values plus the defining input of the selected scalar, before native projection.
pub(super) struct ConfigResolution<K> {
    pub values: toml::Table,
    pub target_origin: Option<K>,
}

/// The visited set is per discovered config root, not a recursion stack: pinned Cargo rejects
/// repeated files and diamond references too, while separate ancestor/home roots can share one.
pub(super) fn resolve_config<S: ConfigSource>(
    source: &mut S,
    root: &S::Key,
) -> Result<ConfigResolution<S::Key>, &'static str> {
    visit(source, root, false, 0, &mut Vec::with_capacity(128))?.ok_or("config_include_missing")
}

fn visit<S: ConfigSource>(
    source: &mut S,
    key: &S::Key,
    optional: bool,
    depth: usize,
    seen: &mut Vec<S::Key>,
) -> Result<Option<ConfigResolution<S::Key>>, &'static str> {
    source.check()?;
    if depth >= 32 || seen.len() >= 128 {
        return Err("config_include_limit");
    }
    if seen.contains(key) {
        return Err("config_include_cycle");
    }
    let Some(input) = source.load(key)? else {
        return if optional {
            Ok(None)
        } else {
            Err("config_include_missing")
        };
    };
    seen.push(key.clone());
    let mut result = ConfigResolution {
        values: toml::Table::new(),
        target_origin: None,
    };
    for include in input.includes {
        source.check()?;
        let Some(child) = source.resolve(key, &include.path)? else {
            if include.optional {
                continue;
            }
            return Err("config_include_missing");
        };
        if let Some(included) = visit(source, &child, include.optional, depth + 1, seen)? {
            merge_tables(source, &mut result.values, included.values, 0)?;
            if included.target_origin.is_some() {
                result.target_origin = included.target_origin;
            }
        }
    }
    let declares_target = input
        .values
        .get("build")
        .and_then(toml::Value::as_table)
        .is_some_and(|build| build.contains_key("target-dir"));
    merge_tables(source, &mut result.values, input.values, 0)?;
    if declares_target {
        result.target_origin = Some(key.clone());
    }
    Ok(Some(result))
}

fn merge_tables<S: ConfigSource>(
    source: &mut S,
    into: &mut toml::Table,
    higher: toml::Table,
    depth: usize,
) -> Result<(), &'static str> {
    if depth >= 64 {
        return Err("resource_limit");
    }
    for (name, value) in higher {
        source.check()?;
        match into.get_mut(&name) {
            None => {
                into.insert(name, value);
            }
            Some(lower) => match (lower, value) {
                (toml::Value::Table(lower), toml::Value::Table(higher)) => {
                    merge_tables(source, lower, higher, depth + 1)?;
                }
                (toml::Value::Array(lower), toml::Value::Array(mut higher)) => {
                    if lower.len().saturating_add(higher.len()) > 65_536 {
                        return Err("resource_limit");
                    }
                    lower.append(&mut higher);
                }
                (toml::Value::Array(_) | toml::Value::Table(_), _)
                | (_, toml::Value::Array(_) | toml::Value::Table(_)) => {
                    return Err("config_merge_conflict");
                }
                (lower, higher) => *lower = higher,
            },
        }
    }
    if table_retained_bytes(into)? > 8 * 1024 * 1024 {
        return Err("resource_limit");
    }
    Ok(())
}

/// Conservative retained-tree estimate, with an independent node/depth cap. Includes native
/// containers and string capacity; it is not a guarantee about allocator or TOML parser RSS.
pub(super) fn table_retained_bytes(table: &toml::Table) -> Result<usize, &'static str> {
    fn value_bytes(
        value: &toml::Value,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<usize, &'static str> {
        *nodes += 1;
        if *nodes > 65_536 || depth >= 64 {
            return Err("resource_limit");
        }
        Ok(std::mem::size_of::<toml::Value>()
            + match value {
                toml::Value::String(value) => value.capacity(),
                toml::Value::Array(values) => {
                    let mut bytes = values
                        .capacity()
                        .saturating_mul(std::mem::size_of::<toml::Value>());
                    for value in values {
                        bytes = bytes.saturating_add(value_bytes(value, nodes, depth + 1)?);
                    }
                    bytes
                }
                toml::Value::Table(values) => table_bytes(values, nodes, depth + 1)?,
                _ => 0,
            })
    }
    fn table_bytes(
        table: &toml::Table,
        nodes: &mut usize,
        depth: usize,
    ) -> Result<usize, &'static str> {
        let mut bytes = std::mem::size_of::<toml::Table>();
        for (key, value) in table {
            bytes = bytes
                .saturating_add(128)
                .saturating_add(key.capacity())
                .saturating_add(value_bytes(value, nodes, depth)?);
        }
        Ok(bytes)
    }
    table_bytes(table, &mut 0, 0)
}
