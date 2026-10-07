//! Bounded subset of msgpackr's self-contained records used by pnpm v11 indexes.
//! Unsupported extensions/record layouts fail closed; no executable callbacks or shared records.
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
pub(super) fn decode(bytes: &[u8]) -> Result<Value, String> {
    let mut d = Decoder {
        bytes,
        pos: 0,
        nodes: 0,
        records: BTreeMap::new(),
    };
    let value = d.value(0)?;
    if d.pos != bytes.len() {
        return Err("msgpack_trailing_bytes".into());
    }
    Ok(value)
}
struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
    records: BTreeMap<u8, Vec<String>>,
}
impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.pos.checked_add(n).ok_or("msgpack_overflow")?;
        let b = self.bytes.get(self.pos..end).ok_or("msgpack_truncated")?;
        self.pos = end;
        Ok(b)
    }
    fn int(&mut self, n: usize) -> Result<u64, String> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |v, b| (v << 8) | u64::from(*b)))
    }
    fn string(&mut self, n: usize) -> Result<Value, String> {
        if n > 1024 * 1024 {
            return Err("msgpack_string_budget".into());
        }
        Ok(Value::String(
            std::str::from_utf8(self.take(n)?)
                .map_err(|_| "msgpack_utf8")?
                .into(),
        ))
    }
    fn array(&mut self, n: usize, depth: usize) -> Result<Value, String> {
        if n > 100_000 {
            return Err("msgpack_array_budget".into());
        }
        let mut a = Vec::new();
        for _ in 0..n {
            a.push(self.value(depth + 1)?)
        }
        Ok(Value::Array(a))
    }
    fn map(&mut self, n: usize, depth: usize) -> Result<Value, String> {
        if n > 100_000 {
            return Err("msgpack_map_budget".into());
        }
        let mut m = Map::new();
        for _ in 0..n {
            let k = self
                .value(depth + 1)?
                .as_str()
                .ok_or("msgpack_key")?
                .to_owned();
            if m.insert(k, self.value(depth + 1)?).is_some() {
                return Err("msgpack_duplicate_key".into());
            }
        }
        Ok(Value::Object(m))
    }
    fn record(&mut self, id: u8, depth: usize) -> Result<Value, String> {
        let keys = self
            .records
            .get(&id)
            .ok_or("msgpack_unknown_record")?
            .clone();
        let mut m = Map::new();
        for k in keys {
            m.insert(k, self.value(depth + 1)?);
        }
        Ok(Value::Object(m))
    }
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        self.nodes += 1;
        if depth > 32 || self.nodes > 500_000 {
            return Err("msgpack_node_budget".into());
        }
        let tag = self.int(1)? as u8;
        match tag {
            0x40..=0x7f if self.records.contains_key(&tag) => self.record(tag, depth),
            0x00..=0x7f => Ok(Value::from(tag)),
            0x80..=0x8f => self.map((tag & 15) as usize, depth),
            0x90..=0x9f => self.array((tag & 15) as usize, depth),
            0xa0..=0xbf => self.string((tag & 31) as usize),
            0xc0 => Ok(Value::Null),
            0xc2 => Ok(Value::Bool(false)),
            0xc3 => Ok(Value::Bool(true)),
            0xcc => Ok(Value::from(self.int(1)?)),
            0xcd => Ok(Value::from(self.int(2)?)),
            0xce => Ok(Value::from(self.int(4)?)),
            0xcf => Ok(Value::from(self.int(8)?)),
            0xd0 => Ok(Value::from(self.int(1)? as i8)),
            0xd1 => Ok(Value::from(self.int(2)? as i16)),
            0xd2 => Ok(Value::from(self.int(4)? as i32)),
            0xd3 => Ok(Value::from(self.int(8)? as i64)),
            0xcb => {
                let f = f64::from_bits(self.int(8)?);
                Ok(Value::Number(
                    Number::from_f64(f).ok_or("msgpack_nonfinite")?,
                ))
            }
            0xca => {
                let f = f32::from_bits(self.int(4)? as u32);
                Ok(Value::Number(
                    Number::from_f64(f as f64).ok_or("msgpack_nonfinite")?,
                ))
            }
            0xd4 => {
                if self.int(1)? != 0x72 {
                    return Err("msgpack_unsupported_extension".into());
                }
                let id = self.int(1)? as u8;
                if !(0x40..=0x7f).contains(&id) {
                    return Err("msgpack_record_id".into());
                }
                let keys = self
                    .value(depth + 1)?
                    .as_array()
                    .ok_or("msgpack_record_keys")?
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned).ok_or("msgpack_record_key"))
                    .collect::<Result<Vec<_>, _>>()?;
                let unique = keys.iter().collect::<std::collections::BTreeSet<_>>();
                if keys.len() > 128 || unique.len() != keys.len() {
                    return Err("msgpack_record_keys_budget".into());
                }
                self.records.insert(id, keys);
                self.record(id, depth)
            }
            0xd9 => {
                let n = self.int(1)? as usize;
                self.string(n)
            }
            0xda => {
                let n = self.int(2)? as usize;
                self.string(n)
            }
            0xdb => {
                let n = self.int(4)? as usize;
                self.string(n)
            }
            0xdc => {
                let n = self.int(2)? as usize;
                self.array(n, depth)
            }
            0xdd => {
                let n = self.int(4)? as usize;
                self.array(n, depth)
            }
            0xde => {
                let n = self.int(2)? as usize;
                self.map(n, depth)
            }
            0xdf => {
                let n = self.int(4)? as usize;
                self.map(n, depth)
            }
            0xe0..=0xff => Ok(Value::from(tag as i8)),
            _ => Err("msgpack_unsupported_tag".into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_record_fixture_and_truncation() {
        let bytes = [
            0xd4, 0x72, 0x40, 0x92, 0xa1, b'a', 0xa1, b'b', 0x01, 0x92, 0x40, 0x02, 0x03, 0xc0,
        ];
        assert_eq!(
            decode(&bytes).unwrap(),
            serde_json::json!({"a":1,"b":[{"a":2,"b":3},null]})
        );
        for n in 0..bytes.len() {
            assert!(decode(&bytes[..n]).is_err())
        }
    }
    #[test]
    fn unsupported_extensions_decline() {
        assert!(decode(&[0xd4, 0x01, 0x40]).is_err());
        assert!(decode(&[0x81, 0xa1, b'x', 0xcf]).is_err())
    }
}
