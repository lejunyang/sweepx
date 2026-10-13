//! Streaming legacy ownership projection: discard non-ownership fields, union platform effects.
//! One file record is decoded at a time; unique compact digests and input bytes remain bounded.
use super::*;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
#[derive(Default)]
pub(super) struct Parsed {
    pub identity: Value,
    pub content: BTreeSet<ContentKey>,
    records: usize,
    fields: usize,
    files_seen: bool,
    top_fields: BTreeSet<String>,
}
#[derive(Deserialize)]
struct FileRecord {
    integrity: String,
    #[serde(default)]
    mode: u64,
}
struct Seed<'a> {
    out: &'a mut Parsed,
    kind: Kind,
}
#[derive(Clone, Copy)]
enum Kind {
    Index,
    Files,
    Effects,
    Effect,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pnpm index object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        use serde::de::Error;
        let mut added = false;
        let mut deleted = false;
        let mut ordinary = false;
        while let Some(key) = map.next_key::<String>()? {
            self.out.fields += 1;
            if key.len() > 16 * 1024 || self.out.fields > 8_000_000 {
                return Err(M::Error::custom("package_index_field_budget"));
            }
            match self.kind {
                Kind::Index => {
                    if matches!(key.as_str(), "name" | "version" | "files" | "sideEffects")
                        && !self.out.top_fields.insert(key.clone())
                    {
                        return Err(M::Error::custom("duplicate_index_field"));
                    }
                    match key.as_str() {
                        "name" | "version" => {
                            let label = map.next_value::<String>()?;
                            if label.len() > 512 {
                                return Err(M::Error::custom("package_label_budget"));
                            }
                            self.out.identity[&key] = Value::String(label);
                        }
                        "files" => {
                            self.out.files_seen = true;
                            map.next_value_seed(Seed {
                                out: self.out,
                                kind: Kind::Files,
                            })?;
                        }
                        "sideEffects" => map.next_value_seed(Seed {
                            out: self.out,
                            kind: Kind::Effects,
                        })?,
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Kind::Effects => map.next_value_seed(Seed {
                    out: self.out,
                    kind: Kind::Effect,
                })?,
                Kind::Effect => {
                    let delta = map.next_value_seed(EffectValue {
                        out: self.out,
                        key: &key,
                    })?;
                    if delta {
                        if key == "added" {
                            added = true;
                        } else {
                            deleted = true;
                        }
                    } else {
                        ordinary = true;
                    }
                }
                Kind::Files => {
                    ordinary = true;
                    let record = map.next_value::<FileRecord>()?;
                    if record.integrity.len() > 256 {
                        return Err(M::Error::custom("pnpm_integrity_budget"));
                    }
                    let file = json!({"integrity": record.integrity, "mode": record.mode});
                    let digest = super::pnpm::content_key(&file, &Value::Null, false)
                        .map_err(M::Error::custom)?;
                    self.out.records += 1;
                    if self.out.records > 4_000_000 || self.out.content.len() >= 2_000_000 {
                        return Err(M::Error::custom("package_content_reference_budget"));
                    }
                    self.out.content.insert(digest);
                    if matches!(self.kind, Kind::Files)
                        && key == "package.json"
                        && self.out.identity["files"]["package.json"].is_null()
                    {
                        self.out.identity["files"]["package.json"] = file;
                    }
                }
            }
        }
        if matches!(self.kind, Kind::Effect) && ordinary && (added || deleted) {
            return Err(M::Error::custom("unsupported_side_effects_delta"));
        }
        Ok(())
    }
}
// An effect field named `added`/`deleted` can also be an ordinary v3 filename.
// Inspect the value shape without buffering a potentially huge delta file map.
struct EffectValue<'a> {
    out: &'a mut Parsed,
    key: &'a str,
}
impl<'de> DeserializeSeed<'de> for EffectValue<'_> {
    type Value = bool;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for EffectValue<'_> {
    type Value = bool;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("file record or build delta")
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, s: S) -> Result<bool, S::Error> {
        if self.key != "deleted" {
            return Err(serde::de::Error::custom("unsupported_side_effects"));
        }
        Deleted.visit_seq(s)?;
        Ok(true)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<bool, M::Error> {
        use serde::de::Error;
        let mut integrity = None;
        let mut mode = 0;
        let mut nested = false;
        let mut scalar = false;
        while let Some(key) = map.next_key::<String>()? {
            self.out.fields += 1;
            if key.len() > 16 * 1024 || self.out.fields > 8_000_000 {
                return Err(M::Error::custom("package_index_field_budget"));
            }
            match map.next_value::<Atom>()? {
                Atom::File(record) => {
                    nested = true;
                    if self.key != "added" {
                        return Err(M::Error::custom("unsupported_side_effects"));
                    }
                    retain_effect(self.out, record).map_err(M::Error::custom)?;
                }
                Atom::Text(s) if key == "integrity" => {
                    scalar = true;
                    integrity = Some(s);
                }
                Atom::Number(n) if key == "mode" => {
                    scalar = true;
                    mode = n;
                }
                _ => scalar = true,
            }
        }
        if let Some(integrity) = integrity {
            if nested {
                return Err(M::Error::custom("unsupported_side_effects"));
            }
            retain_effect(self.out, FileRecord { integrity, mode }).map_err(M::Error::custom)?;
            Ok(false)
        } else if self.key == "added" && !scalar {
            Ok(true)
        } else {
            Err(M::Error::custom("pnpm_integrity_missing"))
        }
    }
}
fn retain_effect(out: &mut Parsed, record: FileRecord) -> Result<(), String> {
    if record.integrity.len() > 256 {
        return Err("pnpm_integrity_budget".into());
    }
    out.records += 1;
    if out.records > 4_000_000 || out.content.len() >= 2_000_000 {
        return Err("package_content_reference_budget".into());
    }
    out.content.insert(super::pnpm::content_key(
        &json!({"integrity":record.integrity,"mode":record.mode}),
        &Value::Null,
        false,
    )?);
    Ok(())
}
enum Atom {
    Text(String),
    Number(u64),
    File(FileRecord),
    Ignored,
}
impl<'de> Deserialize<'de> for Atom {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(AtomVisitor)
    }
}
struct AtomVisitor;
impl<'de> Visitor<'de> for AtomVisitor {
    type Value = Atom;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("file field")
    }
    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Atom, E> {
        Ok(Atom::Text(s.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Atom, E> {
        Ok(Atom::Number(n))
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Atom, E> {
        Ok(Atom::Ignored)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Atom, E> {
        Ok(Atom::Ignored)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Atom, E> {
        Ok(Atom::Ignored)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Atom, E> {
        Ok(Atom::Ignored)
    }
    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Atom, M::Error> {
        FileRecord::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Atom::File)
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut s: S) -> Result<Atom, S::Error> {
        while s.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Atom::Ignored)
    }
}
struct Deleted;
impl<'de> DeserializeSeed<'de> for Deleted {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Deleted {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deleted array")
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut s: S) -> Result<(), S::Error> {
        let mut count = 0usize;
        while s.next_element::<IgnoredAny>()?.is_some() {
            count += 1;
            if count > 2_000_000 {
                return Err(serde::de::Error::custom("deleted_file_budget"));
            }
        }
        Ok(())
    }
}
/// Cap token scratch space before serde can allocate an arbitrarily large string. The native
/// snapshot bounds total bytes; this adapter also makes cancellation/deadlines effective while
/// parsing a private spool. JSON escape bytes count conservatively toward the token limit.
struct GuardedReader<R> {
    reader: R,
    cancel: CancellationToken,
    until: Instant,
    string: bool,
    escape: bool,
    token: usize,
}
impl<R: std::io::Read> std::io::Read for GuardedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.is_cancelled() || Instant::now() >= self.until {
            return Err(std::io::Error::other("index_parse_cancelled_or_deadline"));
        }
        let count = self.reader.read(buf)?;
        for &b in &buf[..count] {
            if self.string {
                self.token += 1;
                if self.token > 64 * 1024 {
                    return Err(std::io::Error::other("index_string_token_budget"));
                }
                if self.escape {
                    self.escape = false;
                } else if b == b'\\' {
                    self.escape = true;
                } else if b == b'"' {
                    self.string = false;
                }
            } else if b == b'"' {
                self.string = true;
                self.token = 0;
            }
        }
        Ok(count)
    }
}
pub(super) fn parse(
    reader: impl std::io::Read,
    cancel: &CancellationToken,
) -> Result<Parsed, String> {
    let mut out = Parsed {
        identity: json!({"files":{}}),
        ..Default::default()
    };
    let reader = GuardedReader {
        reader,
        cancel: cancel.clone(),
        until: Instant::now() + std::time::Duration::from_secs(900),
        string: false,
        escape: false,
        token: 0,
    };
    let mut d = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    Seed {
        out: &mut out,
        kind: Kind::Index,
    }
    .deserialize(&mut d)
    .map_err(|e| e.to_string())?;
    d.end().map_err(|e| e.to_string())?;
    if !out.files_seen {
        return Err("pnpm_files_index_missing".into());
    }
    Ok(out)
}
