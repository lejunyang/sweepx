//! Reserve deserialization storage before handing values to serde's owning visitors.
//!
//! The encoded input cap bounds JSON parser scratch separately. This ledger bounds requests
//! for the typed result and serde's buffered enum content; it is not an RSS measurement.
//! Vecs receive no size hint and reserve initial capacity and doubling slack before decoding.
//! Heap maps reserve a full first B-tree node, then three slots per entry (including slack).
//! Struct fields already reside in their parent's admitted value. `deserialize_any` maps in
//! this fixed cache schema are serde enum-content pair vectors, charged like Vecs; the schema
//! contains no JSON Value or custom any-map collector. Audit that assumption when adding fields.
//! Sequence visitors also reserve a small-node allowance: the DTO's role BTreeSet has only
//! six distinct unit variants and therefore at most one leaf. Other sequence collectors are
//! Vecs or fixed inline tuples. This private adapter is exposed only for the generation DTO.
//! Strings charge four times their
//! decoded length before the owning visitor can copy them: native names also decode, re-encode
//! for canonical validation and sometimes convert to UTF-16. Nested seeds share one ledger;
//! failed attempts never refund it. No second JSON parser or intermediate Value tree is used.

use serde::de::{
    DeserializeOwned, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};
use serde::{Deserializer, de};

/// Reservation cap excluding the already bounded input and JSON parser scratch.
pub(crate) const PARSE_RESERVATION_CAP: usize = 256 * 1024 * 1024;

#[derive(Debug)]
/// Coarse admission failure: callers keep resource pressure separate from corrupt JSON.
pub(crate) enum ParseError {
    /// A reservation failed, including an error swallowed by a fallback visitor.
    ResourceLimit,
    /// Normal JSON syntax/type/trailing-input refusal with budget remaining.
    Json,
}

#[derive(Default)]
struct Budget {
    remaining: usize,
    exhausted: bool,
}

impl Budget {
    fn reserve<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        match self.remaining.checked_sub(bytes) {
            Some(remaining) => {
                self.remaining = remaining;
                Ok(())
            }
            None => {
                self.exhausted = true;
                Err(E::custom("cache JSON storage reservation exhausted"))
            }
        }
    }
}

/// Decode the fixed generation envelope using its audited serde storage shapes.
pub(crate) fn parse_generation(
    bytes: &[u8],
    cap: usize,
) -> Result<crate::StoredEnvelope, ParseError> {
    parse(bytes, cap)
}

fn parse<T: DeserializeOwned>(bytes: &[u8], cap: usize) -> Result<T, ParseError> {
    parse_with_usage(bytes, cap).map(|(value, _)| value)
}

fn parse_with_usage<T: DeserializeOwned>(
    bytes: &[u8],
    cap: usize,
) -> Result<(T, usize), ParseError> {
    let mut budget = Budget {
        remaining: cap,
        exhausted: false,
    };
    let result = budget
        .reserve::<serde_json::Error>(std::mem::size_of::<T>().saturating_mul(2))
        .and_then(|()| {
            let mut json = serde_json::Deserializer::from_slice(bytes);
            let value = T::deserialize(Decoder {
                inner: &mut json,
                budget: &mut budget,
            })?;
            json.end()?;
            Ok(value)
        });
    // A custom/untagged visitor can swallow a child error. Exhaustion is sticky even if
    // that visitor returns a fallback success after consuming the refused JSON value.
    if budget.exhausted {
        return Err(ParseError::ResourceLimit);
    }
    result
        .map(|value| (value, cap - budget.remaining))
        .map_err(|_| ParseError::Json)
}

struct Decoder<'a, D> {
    inner: D,
    budget: &'a mut Budget,
}

struct Guard<'a, V> {
    inner: V,
    budget: &'a mut Budget,
    map_storage: MapStorage,
}

#[derive(Clone, Copy)]
enum MapStorage {
    Struct,
    Pairs,
    Tree,
}

impl MapStorage {
    fn factor(self, entries: usize) -> usize {
        // Pinned alloc uses 11 key/value slots per B-tree node and non-root nodes with
        // at least five occupied slots. Twelve initial / three subsequent slots plus
        // per-entry header/edge allowance cover initial allocation and split slack.
        // Enum Content maps instead use Vec<(Content, Content)>; none of the generation
        // DTO's deserialize_any collectors build a heap tree. See the dated audit.
        match (self, entries) {
            (Self::Struct, _) => 0,
            (Self::Pairs, 0) => 8,
            (Self::Pairs, _) => 2,
            (Self::Tree, 0) => 12,
            (Self::Tree, _) => 3,
        }
    }
    fn overhead(self) -> usize {
        if matches!(self, Self::Tree) { 64 } else { 0 }
    }
}

macro_rules! forward {
    ($($method:ident $(($($arg:ident: $ty:ty),*))?;)*) => {$(
        fn $method<V: Visitor<'de>>(self, $($($arg: $ty,)*)? visitor: V) -> Result<V::Value, Self::Error> {
            self.inner.$method($($($arg,)*)? Guard { inner: visitor, budget: self.budget, map_storage: MapStorage::Tree })
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Decoder<'_, D> {
    type Error = D::Error;
    forward! {
        deserialize_bool;
        deserialize_i8; deserialize_i16; deserialize_i32; deserialize_i64; deserialize_i128;
        deserialize_u8; deserialize_u16; deserialize_u32; deserialize_u64; deserialize_u128;
        deserialize_f32; deserialize_f64; deserialize_char; deserialize_str; deserialize_string;
        deserialize_bytes; deserialize_byte_buf; deserialize_option; deserialize_unit;
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_seq; deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map; deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier; deserialize_ignored_any;
    }
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_any(Guard {
            inner: visitor,
            budget: self.budget,
            map_storage: MapStorage::Pairs,
        })
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.inner.deserialize_struct(
            name,
            fields,
            Guard {
                inner: visitor,
                budget: self.budget,
                map_storage: MapStorage::Struct,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! scalar {
    ($($method:ident($ty:ty);)*) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> {
            self.inner.$method(value)
        }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Guard<'_, V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }
    scalar! {
        visit_bool(bool); visit_i8(i8); visit_i16(i16); visit_i32(i32); visit_i64(i64); visit_i128(i128);
        visit_u8(u8); visit_u16(u16); visit_u32(u32); visit_u64(u64); visit_u128(u128);
        visit_f32(f32); visit_f64(f64); visit_char(char);
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.budget.reserve(value.len().saturating_mul(4))?;
        self.inner.visit_str(value)
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.budget.reserve(value.len().saturating_mul(4))?;
        self.inner.visit_borrowed_str(value)
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.budget.reserve(value.capacity().saturating_mul(4))?;
        self.inner.visit_string(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        self.budget.reserve(value.len().saturating_mul(2))?;
        self.inner.visit_bytes(value)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.budget.reserve(value.len().saturating_mul(2))?;
        self.inner.visit_borrowed_bytes(value)
    }
    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.budget.reserve(value.capacity().saturating_mul(2))?;
        self.inner.visit_byte_buf(value)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Decoder {
            inner: decoder,
            budget: self.budget,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Decoder {
            inner: decoder,
            budget: self.budget,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        // The fixed role alphabet uses a BTreeSet sequence collector, not a Vec. Cover
        // its single leaf and container bookkeeping before allowing the visitor to retain.
        self.budget.reserve(128)?;
        self.inner.visit_seq(Sequence {
            inner: access,
            budget: self.budget,
            entries: 0,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(Map {
            inner: access,
            budget: self.budget,
            storage: self.map_storage,
            entries: 0,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Enum {
            inner: access,
            budget: self.budget,
        })
    }
}

struct Seed<'a, S> {
    inner: S,
    budget: &'a mut Budget,
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Decoder {
            inner: decoder,
            budget: self.budget,
        })
    }
}

struct Sequence<'a, A> {
    inner: A,
    budget: &'a mut Budget,
    entries: usize,
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Sequence<'_, A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        // Rust's small initial Vec allocation can exceed twice the first element. Charge
        // eight initial slots, then growth slack, rather than trusting a length hint.
        let factor = if self.entries == 0 { 8 } else { 2 };
        self.budget
            .reserve(std::mem::size_of::<S::Value>().saturating_mul(factor))?;
        self.entries = self.entries.saturating_add(1);
        self.inner.next_element_seed(Seed {
            inner: seed,
            budget: self.budget,
        })
    }
    // Never let a parser-provided hint cause an allocation before the element reservations.
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

struct Map<'a, A> {
    inner: A,
    budget: &'a mut Budget,
    storage: MapStorage,
    entries: usize,
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for Map<'_, A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        let factor = self.storage.factor(self.entries);
        self.budget.reserve(
            std::mem::size_of::<S::Value>()
                .saturating_mul(factor)
                .saturating_add(self.storage.overhead()),
        )?;
        self.inner.next_key_seed(Seed {
            inner: seed,
            budget: self.budget,
        })
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        let factor = self.storage.factor(self.entries);
        self.budget.reserve(
            std::mem::size_of::<S::Value>()
                .saturating_mul(factor)
                .saturating_add(self.storage.overhead()),
        )?;
        self.entries = self.entries.saturating_add(1);
        self.inner.next_value_seed(Seed {
            inner: seed,
            budget: self.budget,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

struct Enum<'a, A> {
    inner: A,
    budget: &'a mut Budget,
}
impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for Enum<'a, A> {
    type Error = A::Error;
    type Variant = Variant<'a, A::Variant>;
    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), A::Error> {
        self.budget
            .reserve(std::mem::size_of::<S::Value>().saturating_mul(2))?;
        let (value, variant) = self.inner.variant_seed(Seed {
            inner: seed,
            budget: self.budget,
        })?;
        Ok((
            value,
            Variant {
                inner: variant,
                budget: self.budget,
            },
        ))
    }
}
struct Variant<'a, A> {
    inner: A,
    budget: &'a mut Budget,
}
impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Variant<'_, A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, A::Error> {
        self.budget
            .reserve(std::mem::size_of::<S::Value>().saturating_mul(2))?;
        self.inner.newtype_variant_seed(Seed {
            inner: seed,
            budget: self.budget,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Guard {
                inner: visitor,
                budget: self.budget,
                map_storage: MapStorage::Tree,
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.struct_variant(
            fields,
            Guard {
                inner: visitor,
                budget: self.budget,
                map_storage: MapStorage::Struct,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use sweepx_model::{DecimalU128, EvidenceValue, NativeName, ReasonCode};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Shape {
        Unit,
        Tuple(u128, String),
        Struct { names: Vec<String> },
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Record {
        name: NativeName,
        bytes: EvidenceValue<DecimalU128>,
        extra: Option<Shape>,
    }

    #[test]
    fn owning_decoder_matches_the_ordinary_serde_oracle() {
        let values = vec![
            Record {
                name: NativeName::unix(vec![b'a', 0xff]),
                bytes: EvidenceValue::Known {
                    value: DecimalU128::new(u128::MAX),
                },
                extra: Some(Shape::Tuple(u128::MAX, "quote\"\n雪".into())),
            },
            Record {
                name: NativeName::windows_utf16(vec![0x61, 0xd800]),
                bytes: EvidenceValue::LowerBound {
                    value: DecimalU128::new(12),
                    reason: ReasonCode::ResourceLimit,
                },
                extra: Some(Shape::Struct {
                    names: vec!["a".into(), "\0escape".into()],
                }),
            },
            Record {
                name: NativeName::unix(b"empty".to_vec()),
                bytes: EvidenceValue::Unknown {
                    reason: ReasonCode::ResourceLimit,
                },
                extra: Some(Shape::Unit),
            },
        ];
        let bytes = serde_json::to_vec(&values).unwrap();
        let ordinary: Vec<Record> = serde_json::from_slice(&bytes).unwrap();
        let admitted: Vec<Record> = parse(&bytes, PARSE_RESERVATION_CAP).unwrap();
        assert_eq!(admitted, ordinary);
        assert_eq!(ordinary, values);
    }

    static PROBE_VISITS: AtomicUsize = AtomicUsize::new(0);
    struct Probe([u64; 1024]);
    impl<'de> Deserialize<'de> for Probe {
        fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct ProbeVisitor;
            impl<'de> Visitor<'de> for ProbeVisitor {
                type Value = Probe;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("null")
                }
                fn visit_unit<E: de::Error>(self) -> Result<Probe, E> {
                    PROBE_VISITS.fetch_add(1, Ordering::SeqCst);
                    Ok(Probe([0; 1024]))
                }
            }
            decoder.deserialize_unit(ProbeVisitor)
        }
    }

    #[test]
    fn a_large_element_is_refused_before_its_owning_visitor_runs() {
        PROBE_VISITS.store(0, Ordering::SeqCst);
        // Independently chosen 4 KiB budget is smaller than the fixture's 8 KiB value.
        assert!(matches!(
            parse::<Vec<Probe>>(b"[null]", 4096),
            Err(ParseError::ResourceLimit)
        ));
        assert_eq!(PROBE_VISITS.load(Ordering::SeqCst), 0);
        let admitted: Vec<Probe> = parse(b"[null]", 128 * 1024).unwrap();
        assert_eq!(PROBE_VISITS.load(Ordering::SeqCst), 1);
        assert_eq!(admitted[0].0[0], 0);
    }

    static STRING_VISITS: AtomicUsize = AtomicUsize::new(0);
    struct StringProbe(String);
    impl<'de> Deserialize<'de> for StringProbe {
        fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
            struct StringVisitor;
            impl<'de> Visitor<'de> for StringVisitor {
                type Value = StringProbe;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("string")
                }
                fn visit_str<E: de::Error>(self, value: &str) -> Result<StringProbe, E> {
                    STRING_VISITS.fetch_add(1, Ordering::SeqCst);
                    Ok(StringProbe(value.to_owned()))
                }
            }
            decoder.deserialize_string(StringVisitor)
        }
    }

    #[test]
    fn decoded_strings_are_reserved_before_the_owned_copy() {
        STRING_VISITS.store(0, Ordering::SeqCst);
        // Escaped JSON exercises parser scratch and decoded-byte charging, not raw length.
        let encoded = format!("\"{}\"", "\\u0061".repeat(2048));
        assert!(matches!(
            parse::<StringProbe>(encoded.as_bytes(), 1024),
            Err(ParseError::ResourceLimit)
        ));
        assert_eq!(STRING_VISITS.load(Ordering::SeqCst), 0);
        let admitted: StringProbe = parse(encoded.as_bytes(), 32 * 1024).unwrap();
        assert_eq!(STRING_VISITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            admitted.0,
            serde_json::from_str::<String>(&encoded).unwrap()
        );
    }

    #[test]
    fn reservations_cover_independently_observed_nested_vector_storage() {
        for count in [0, 1, 2, 3, 4, 8, 9, 64, 65, 257] {
            let fixture = vec![vec!["payload".to_owned(); count]; 3];
            let bytes = serde_json::to_vec(&fixture).unwrap();
            let (parsed, reserved) =
                parse_with_usage::<Vec<Vec<String>>>(&bytes, PARSE_RESERVATION_CAP).unwrap();
            let observed_storage = parsed.capacity() * std::mem::size_of::<Vec<String>>()
                + parsed
                    .iter()
                    .map(|row| {
                        row.capacity() * std::mem::size_of::<String>()
                            + row.iter().map(String::capacity).sum::<usize>()
                    })
                    .sum::<usize>();
            assert!(
                reserved >= observed_storage,
                "count={count} reserved={reserved} observed={observed_storage}"
            );
            assert_eq!(
                parsed,
                serde_json::from_slice::<Vec<Vec<String>>>(&bytes).unwrap()
            );
        }
    }

    #[test]
    fn heap_maps_and_nested_values_share_one_budget() {
        let fixture = (0..257)
            .map(|index| (format!("key-{index}"), vec!["value".to_owned(); 9]))
            .collect::<BTreeMap<_, _>>();
        let bytes = serde_json::to_vec(&fixture).unwrap();
        let admitted: BTreeMap<String, Vec<String>> = parse(&bytes, PARSE_RESERVATION_CAP).unwrap();
        assert_eq!(
            admitted,
            serde_json::from_slice::<BTreeMap<String, Vec<String>>>(&bytes).unwrap()
        );
        assert!(matches!(
            parse::<BTreeMap<String, Vec<String>>>(&bytes, 8192),
            Err(ParseError::ResourceLimit)
        ));
    }

    #[test]
    fn sequence_admission_covers_the_closed_role_set_collector() {
        use crate::PreviewRole;
        use std::collections::BTreeSet;
        let fixture = BTreeSet::from([
            PreviewRole::Root,
            PreviewRole::RequiredAncestor,
            PreviewRole::Boundary,
            PreviewRole::Error,
            PreviewRole::HeavyLeaf,
            PreviewRole::TopHeavyChild,
        ]);
        let bytes = serde_json::to_vec(&fixture).unwrap();
        assert!(matches!(
            parse::<BTreeSet<PreviewRole>>(&bytes, 64),
            Err(ParseError::ResourceLimit)
        ));
        let admitted: BTreeSet<PreviewRole> = parse(&bytes, 8192).unwrap();
        assert_eq!(
            admitted,
            serde_json::from_slice::<BTreeSet<PreviewRole>>(&bytes).unwrap()
        );
        assert_eq!(admitted, fixture);
    }

    #[test]
    fn syntax_failures_and_trailing_values_remain_json_errors() {
        for bytes in [b"[\"unterminated]".as_slice(), b"[] []", b"[null]"] {
            assert!(matches!(
                parse::<Vec<String>>(bytes, 64 * 1024),
                Err(ParseError::Json)
            ));
        }
    }

    #[test]
    fn a_visitor_cannot_turn_a_swallowed_budget_error_into_success() {
        struct Fallback;
        impl<'de> Deserialize<'de> for Fallback {
            fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                let _ = decoder.deserialize_any(de::IgnoredAny);
                Ok(Self)
            }
        }
        let encoded = serde_json::to_vec(&"x".repeat(4096)).unwrap();
        // This independent visitor deliberately consumes then ignores a decoder refusal.
        assert!(matches!(
            parse::<Fallback>(&encoded, 1024),
            Err(ParseError::ResourceLimit)
        ));
    }

    #[test]
    fn real_generation_shapes_match_the_oracle_with_measured_reservations() {
        use crate::{
            CompactedPreview, ParentPreview, PreviewCoverage, PreviewKind, PreviewSummary,
            STORED_PREVIEW_SCHEMA, StoredGeneration,
        };
        use std::collections::BTreeSet;
        use sweepx_model::FieldProvenance;
        let row = PreviewSummary {
            kind: PreviewKind::Root,
            parent_id: None,
            entry_id: "entry".into(),
            native_name: NativeName::unix(b"fixture".to_vec()),
            display_name: "/controlled/fixture".into(),
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::new(7),
            },
            allocated_bytes: EvidenceValue::Unknown {
                reason: ReasonCode::ResourceLimit,
            },
            direct_child_count: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            recursive_entry_count: EvidenceValue::Known {
                value: DecimalU128::new(1),
            },
            aggregate: None,
            coverage: PreviewCoverage {
                complete: true,
                details_lost: false,
                incomplete_reasons: Vec::new(),
            },
            selectable: false,
            roles: BTreeSet::new(),
            provenance: FieldProvenance::StalePreview {
                observed_at: "2026-10-03T00:00:00Z".into(),
            },
        };
        for count in [1, 1000, 10_000] {
            let parents = (0..count)
                .map(|index| {
                    (
                        format!("parent-{index}"),
                        ParentPreview {
                            parent_id: format!("parent-{index}"),
                            retained: vec![row.clone()],
                            others: None,
                        },
                    )
                })
                .collect();
            let generation = StoredGeneration {
                generation: "measure".into(),
                schema: STORED_PREVIEW_SCHEMA.into(),
                created_at: "2026-10-03T00:00:00Z".into(),
                preview: CompactedPreview {
                    parents,
                    total_estimated_bytes: 0,
                    total_records: count,
                    visible_resource_limit: false,
                },
                validity: Vec::new(),
            };
            let bytes = serde_json::to_vec(&generation).unwrap();
            let (admitted, reserved) =
                parse_with_usage::<StoredGeneration>(&bytes, PARSE_RESERVATION_CAP).unwrap();
            let ordinary: StoredGeneration = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(admitted, ordinary);
            assert_eq!(ordinary, generation);
            println!(
                "generation_parse rows={count} encoded_bytes={} reservation_bytes={reserved} preview_summary_size={} parent_preview_size={}",
                bytes.len(),
                std::mem::size_of::<PreviewSummary>(),
                std::mem::size_of::<ParentPreview>()
            );
        }
    }
}
