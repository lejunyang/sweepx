//! Bounded operation snapshots. Native handles own I/O; encoded/shape limits precede DTO decode.

use super::{OperationSnapshot, StateError};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::io::{self, Write};

pub(super) const ENCODED_CAP: usize = 8 * 1024 * 1024;
const VALUE_VISITS: usize = 65_536;

pub(super) fn resource(resource: &'static str, limit: usize) -> StateError {
    StateError::SnapshotResourceLimit { resource, limit }
}

#[cfg(any(unix, windows))]
pub(super) fn state_error(error: io::Error) -> StateError {
    if let Some(quota) = sweepx_cache::state_directory::resource_limit(&error) {
        StateError::StateResourceLimit {
            resource: quota.resource,
            limit: quota.limit,
        }
    } else {
        error.into()
    }
}

pub(super) fn encode(snapshot: &OperationSnapshot) -> Result<Vec<u8>, StateError> {
    let mut output = Buffer {
        bytes: Vec::new(),
        rejected: false,
    };
    let encoded = serde_json::to_writer(&mut output, snapshot);
    if output.rejected {
        return Err(resource("encoded_bytes", ENCODED_CAP));
    }
    encoded?;
    // A newly written snapshot must meet the same shape admission as its next load.
    check_shape(&output.bytes)?;
    Ok(output.bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<OperationSnapshot, StateError> {
    check_shape(bytes)?;
    Ok(serde_json::from_slice(bytes)?)
}

struct Buffer {
    bytes: Vec<u8>,
    rejected: bool,
}

impl Write for Buffer {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let Some(needed) = self
            .bytes
            .len()
            .checked_add(input.len())
            .filter(|&size| size <= ENCODED_CAP)
        else {
            self.rejected = true;
            return Err(io::Error::other("snapshot encoded byte limit"));
        };
        if self.bytes.capacity() < needed {
            // Geometric requests avoid per-fragment reallocations while never requesting
            // storage past the wire cap. Allocator overhead is outside this admission.
            let requested = needed.max(256).next_power_of_two().min(ENCODED_CAP);
            self.bytes
                .try_reserve_exact(requested - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The fixed DTO owns strings, one Vec<String> and one optional string BTreeMap. Counting
// every JSON value/key before ordinary serde decode bounds their cardinality without a
// second JSON parser or intermediate Value tree. Unknown fields pay the same work budget.
// String/parser scratch is separately bounded by encoded input. This is not allocator RSS.
struct Shape {
    remaining: usize,
    exhausted: bool,
}

struct Seed<'a>(&'a mut Shape);
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        let Some(remaining) = self.0.remaining.checked_sub(1) else {
            self.0.exhausted = true;
            return Err(serde::de::Error::custom("snapshot value visit limit"));
        };
        self.0.remaining = remaining;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded snapshot JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Seed(self.0))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(Seed(self.0))?.is_some() {
            map.next_value_seed(Seed(self.0))?;
        }
        Ok(())
    }
}

fn check_shape(bytes: &[u8]) -> Result<(), StateError> {
    if bytes.len() > ENCODED_CAP {
        return Err(resource("encoded_bytes", ENCODED_CAP));
    }
    let mut shape = Shape {
        remaining: VALUE_VISITS,
        exhausted: false,
    };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = Seed(&mut shape)
        .deserialize(&mut decoder)
        .and_then(|()| decoder.end());
    if shape.exhausted {
        return Err(resource("json_value_visits", VALUE_VISITS));
    }
    result?;
    Ok(())
}

#[cfg(any(unix, windows))]
pub(super) fn native_error(path: &std::path::Path, error: io::Error) -> StateError {
    if sweepx_cache::native::handle_limit(&error).is_some() {
        return error.into();
    }
    if sweepx_cache::native::is_link_refusal(&error) {
        return StateError::SymlinkStateDir(path.to_path_buf());
    }
    match error.kind() {
        io::ErrorKind::NotADirectory => StateError::InvalidStateDir(path.to_path_buf()),
        io::ErrorKind::Other | io::ErrorKind::PermissionDenied => {
            StateError::InsecureStateDir(path.to_path_buf())
        }
        _ => StateError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableSnapshotStore, SnapshotStore};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn snapshot() -> OperationSnapshot {
        let mut snapshot = OperationSnapshot::not_found("op_fixture", sweepx_i18n::Locale::EnUs);
        snapshot.root_paths = vec!["/fixture/中文/🧹".to_owned(), "escaped\n\"path".to_owned()];
        snapshot
    }

    #[cfg(any(unix, windows))]
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, DurableSnapshotStore) {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let parent = fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let parent = temp.path().to_path_buf();
        let path = parent.join("state");
        let store = DurableSnapshotStore::new(&path).unwrap();
        (temp, path, store)
    }

    #[test]
    fn bounded_codec_matches_ordinary_serde_for_legacy_and_current_snapshots() {
        let snapshot = snapshot();
        let mut legacy = serde_json::to_value(&snapshot).unwrap();
        legacy["unknownFutureField"] =
            serde_json::json!({"rows": [1, -2, 0.5, null, true, "\\雪"]});
        let bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        let independent: OperationSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decode(&bytes).unwrap(), independent);
        assert_eq!(independent, snapshot);
        let encoded = encode(&snapshot).unwrap();
        assert_eq!(
            serde_json::from_slice::<OperationSnapshot>(&encoded).unwrap(),
            snapshot
        );
        assert_eq!(decode(&encoded).unwrap(), snapshot);
    }

    #[test]
    fn dense_input_is_refused_before_typed_decode_even_below_byte_cap() {
        let mut independent = serde_json::to_value(snapshot()).unwrap();
        independent["rootPaths"] = serde_json::json!(vec![""; 65_536]);
        let bytes = serde_json::to_vec(&independent).unwrap();
        assert!(bytes.len() < 8_388_608);
        assert_eq!(
            serde_json::from_slice::<OperationSnapshot>(&bytes)
                .unwrap()
                .root_paths
                .len(),
            65_536
        );
        assert!(matches!(
            decode(&bytes),
            Err(StateError::SnapshotResourceLimit {
                resource: "json_value_visits",
                limit: 65_536
            })
        ));
        independent["rootPaths"] = serde_json::json!([]);
        independent["unknownFutureField"] = serde_json::json!(vec![false; 65_536]);
        let bytes = serde_json::to_vec(&independent).unwrap();
        assert!(serde_json::from_slice::<OperationSnapshot>(&bytes).is_ok());
        assert!(matches!(
            decode(&bytes),
            Err(StateError::SnapshotResourceLimit {
                resource: "json_value_visits",
                ..
            })
        ));
    }

    #[test]
    fn unrepresentable_unknown_numbers_fail_preflight_instead_of_being_silently_ignored() {
        let mut bytes = serde_json::to_vec(&snapshot()).unwrap();
        bytes.pop();
        bytes.extend_from_slice(br#", "unknownFutureNumber": 1e999}"#);
        // Typed serde ignores unknown values without representing their numbers. The bounded
        // whole-JSON visitor is intentionally stricter; no such value is written by this DTO.
        assert!(serde_json::from_slice::<OperationSnapshot>(&bytes).is_ok());
        assert!(matches!(decode(&bytes), Err(StateError::Json(_))));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn missing_root_and_operations_are_not_created_by_read_only_load() {
        let (_temp, path, store) = fixture();
        assert!(store.load("op_missing").unwrap().is_none());
        assert!(!path.join("operations").exists());
        let missing = path.join("not-created/child");
        assert!(
            DurableSnapshotStore::open_existing(&missing)
                .unwrap()
                .is_none()
        );
        assert!(!path.join("not-created").exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn aggregate_refusal_preserves_previous_snapshot_and_still_allows_load() {
        let (_temp, path, store) = fixture();
        let original = snapshot();
        store.save(&original).unwrap();
        let filename = path.join("operations").join(format!(
            "{}.json",
            crate::digest_hex(&original.operation_id)
        ));
        let previous = fs::read(&filename).unwrap();
        store
            .directory
            .write_synced_bytes("protected-record", b"keep", 4)
            .unwrap();
        let protected = path.join("protected-record");
        fs::OpenOptions::new()
            .write(true)
            .open(&protected)
            .unwrap()
            .set_len(536_870_912 - previous.len() as u64)
            .unwrap();
        let mut changed = original.clone();
        changed.root_paths.push("/new-root".into());
        assert!(matches!(
            store.save(&changed),
            Err(StateError::StateResourceLimit {
                resource: "state_bytes",
                limit: 536_870_912
            })
        ));
        assert_eq!(fs::read(filename).unwrap(), previous);
        assert_eq!(store.load(&original.operation_id).unwrap(), Some(original));
        assert_eq!(
            fs::metadata(protected).unwrap().len(),
            536_870_912 - previous.len() as u64
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn full_state_refuses_snapshot_before_creating_operations() {
        let (_temp, path, store) = fixture();
        store
            .directory
            .write_synced_bytes("protected-record", b"keep", 4)
            .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(path.join("protected-record"))
            .unwrap()
            .set_len(536_870_912)
            .unwrap();
        assert!(matches!(
            store.save(&snapshot()),
            Err(StateError::StateResourceLimit {
                resource: "state_bytes",
                limit: 536_870_912
            })
        ));
        assert!(!path.join("operations").exists());
        assert_eq!(
            fs::metadata(path.join("protected-record")).unwrap().len(),
            536_870_912
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journal_peak_reservation_refuses_before_creating_journal_children() {
        let (_temp, path, store) = fixture();
        store
            .directory
            .write_synced_bytes("protected-record", b"keep", 4)
            .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(path.join("protected-record"))
            .unwrap()
            .set_len(503_316_481)
            .unwrap();
        let id = crate::ValidatedOperationId::parse("quota-fixture").unwrap();
        assert!(matches!(
            store.create_journal(&id),
            Err(StateError::StateResourceLimit {
                resource: "state_bytes",
                limit: 536_870_912
            })
        ));
        assert!(!path.join("event-journals").exists());
        assert_eq!(
            fs::metadata(path.join("protected-record")).unwrap().len(),
            503_316_481
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn root_replacement_and_clone_keep_snapshot_io_in_original_namespace() {
        let (_temp, path, store) = fixture();
        let clone = store.clone();
        let retained = path.with_file_name("retained-state");
        fs::rename(&path, &retained).unwrap();
        let replacement = DurableSnapshotStore::new(&path).unwrap();
        let snapshot = snapshot();
        store.save(&snapshot).unwrap();
        assert_eq!(
            clone.load(&snapshot.operation_id).unwrap(),
            Some(snapshot.clone())
        );
        assert!(replacement.load(&snapshot.operation_id).unwrap().is_none());
        assert!(!path.join("operations").exists());
        let file = retained.join("operations").join(format!(
            "{}.json",
            crate::digest_hex(&snapshot.operation_id)
        ));
        assert_eq!(
            serde_json::from_slice::<OperationSnapshot>(&fs::read(file).unwrap()).unwrap(),
            snapshot
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn writer_refusal_creates_no_children_and_preserves_previous_snapshot() {
        let (_temp, path, store) = fixture();
        let mut dense = snapshot();
        dense.root_paths = vec![String::new(); 65_536];
        assert!(matches!(
            store.save(&dense),
            Err(StateError::SnapshotResourceLimit {
                resource: "json_value_visits",
                ..
            })
        ));
        assert!(!path.join("operations").exists());
        let old = snapshot();
        store.save(&old).unwrap();
        let file = path
            .join("operations")
            .join(format!("{}.json", crate::digest_hex(&old.operation_id)));
        let before = fs::read(&file).unwrap();
        let mut large = old.clone();
        large.request_id = "a".repeat(8_388_608);
        assert!(matches!(
            store.save(&large),
            Err(StateError::SnapshotResourceLimit {
                resource: "encoded_bytes",
                limit: 8_388_608
            })
        ));
        assert_eq!(fs::read(file).unwrap(), before);
        assert_eq!(store.load(&old.operation_id).unwrap(), Some(old));
        assert_eq!(fs::read_dir(path.join("operations")).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn oversized_private_sparse_file_is_refused_before_json_decode() {
        let (_temp, path, store) = fixture();
        store.save(&snapshot()).unwrap();
        let file = path
            .join("operations")
            .join(format!("{}.json", crate::digest_hex("op_fixture")));
        fs::OpenOptions::new()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(8_388_609)
            .unwrap();
        assert_eq!(fs::metadata(&file).unwrap().len(), 8_388_609);
        assert!(matches!(
            store.load("op_fixture"),
            Err(StateError::SnapshotResourceLimit {
                resource: "encoded_bytes",
                limit: 8_388_608
            })
        ));
        assert_eq!(fs::metadata(file).unwrap().len(), 8_388_609);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_snapshot_objects_are_refused_without_repair_or_replacement() {
        use std::os::unix::fs::symlink;
        for kind in ["link", "hardlink", "public", "fifo"] {
            let (_temp, path, store) = fixture();
            let snapshot = snapshot();
            store.save(&snapshot).unwrap();
            let file = path.join("operations").join(format!(
                "{}.json",
                crate::digest_hex(&snapshot.operation_id)
            ));
            let original = fs::read(&file).unwrap();
            let other = path.join("preserved");
            match kind {
                "link" => {
                    fs::rename(&file, &other).unwrap();
                    symlink(&other, &file).unwrap();
                }
                "hardlink" => fs::hard_link(&file, &other).unwrap(),
                "public" => fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(),
                "fifo" => {
                    fs::rename(&file, &other).unwrap();
                    let name = std::ffi::CString::new(file.as_os_str().as_encoded_bytes()).unwrap();
                    // SAFETY: a NUL-terminated isolated FIFO fixture, never a user path.
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            assert!(store.load(&snapshot.operation_id).is_err(), "{kind}");
            assert!(store.save(&snapshot).is_err(), "{kind}");
            if kind == "public" {
                assert_eq!(
                    fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                    0o644
                );
                assert_eq!(fs::read(&file).unwrap(), original);
            } else {
                assert_eq!(fs::read(other).unwrap(), original);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn public_state_and_operations_permissions_are_refused_without_chmod() {
        let (_temp, path, store) = fixture();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(DurableSnapshotStore::new(&path).is_err());
        assert!(DurableSnapshotStore::open_existing(&path).is_err());
        assert!(store.load("op_fixture").is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let child = path.join("operations");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(store.load("op_fixture").is_err());
        assert!(store.save(&snapshot()).is_err());
        assert_eq!(
            fs::metadata(child).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
