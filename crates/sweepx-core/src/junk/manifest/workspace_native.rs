//! Invocation-local workspace inputs. Captured paths remain private configuration observations,
//! never scan coverage or execution authority. Final rereads reject changed inputs; these are
//! time-point checks, not an atomic filesystem snapshot or a certificate that Cargo can build.

use super::scope::{ScopeBudget, read_error};
use super::workspace::{WorkspaceError, WorkspaceSource};
use crate::cargo_cleaner_evidence::{WorkspaceManifest, decode_cargo_workspace_manifest};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use sweepx_model::NativeName;
use sweepx_platform::{CancellationToken, PlatformScanner, RegularFileObservation};
use sweepx_scanner::{
    CargoManifestObservation, LocatorDirectoryIdentity, LocatorDirectoryLookupFailure,
    LocatorReader,
};

#[derive(Clone, PartialEq, Eq)]
enum InputStamp {
    Missing,
    Present {
        digest: [u8; 32],
        native: Box<RegularFileObservation>,
    },
}

#[derive(Clone)]
struct ManifestInput {
    value: Option<WorkspaceManifest>,
    stamp: InputStamp,
}

struct Node {
    directory: LocatorDirectoryIdentity,
    manifest: Option<ManifestInput>,
    names: Option<Vec<String>>,
}

/// Reused within this invocation/revision only. Captured directory aliases with different
/// spellings are rejected rather than counted twice or promoted to an equivalence proof.
pub(super) struct WorkspaceInputs {
    nodes: Vec<Node>,
    retained: usize,
}
impl Default for WorkspaceInputs {
    fn default() -> Self {
        Self {
            nodes: Vec::with_capacity(256),
            retained: 256 * std::mem::size_of::<Node>(),
        }
    }
}

pub(super) struct NativeWorkspaceSource<'a, 'b, P: PlatformScanner> {
    pub reader: &'a LocatorReader<P>,
    pub cancel: &'a CancellationToken,
    pub budget: &'a mut ScopeBudget<'b>,
    pub inputs: &'a mut WorkspaceInputs,
    used: Vec<usize>,
    operations: usize,
}

impl<'a, 'b, P: PlatformScanner> NativeWorkspaceSource<'a, 'b, P> {
    pub fn new(
        reader: &'a LocatorReader<P>,
        cancel: &'a CancellationToken,
        budget: &'a mut ScopeBudget<'b>,
        inputs: &'a mut WorkspaceInputs,
    ) -> Self {
        Self {
            reader,
            cancel,
            budget,
            inputs,
            used: Vec::with_capacity(256),
            operations: 0,
        }
    }

    fn check(&mut self) -> Result<(), WorkspaceError> {
        self.budget
            .check(self.cancel)
            .map_err(WorkspaceError::Unavailable)?;
        self.operations += 1;
        if self.operations > 16_384 {
            return Err(WorkspaceError::Unavailable("workspace_work_limit"));
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), WorkspaceError> {
        let total = self
            .inputs
            .retained
            .checked_add(bytes)
            .filter(|total| *total <= 8 * 1024 * 1024)
            .ok_or(WorkspaceError::Unavailable("workspace_input_limit"))?;
        self.inputs.retained = total;
        Ok(())
    }

    pub fn intern(&mut self, directory: LocatorDirectoryIdentity) -> Result<usize, WorkspaceError> {
        self.check()?;
        if let Some(id) = self
            .inputs
            .nodes
            .iter()
            .position(|node| node.directory == directory)
        {
            if !self.used.contains(&id) {
                self.used.push(id);
            }
            return Ok(id);
        }
        if self
            .inputs
            .nodes
            .iter()
            .any(|node| node.directory.same_captured_native_object(&directory))
        {
            return Err(WorkspaceError::Unavailable(
                "workspace_native_alias_or_change",
            ));
        }
        if self.inputs.nodes.len() >= 256 {
            return Err(WorkspaceError::Unavailable("workspace_directory_limit"));
        }
        self.charge(directory.retained_bytes_estimate())?;
        let id = self.inputs.nodes.len();
        self.inputs.nodes.push(Node {
            directory,
            manifest: None,
            names: None,
        });
        self.used.push(id);
        Ok(id)
    }

    pub fn directory(&self, id: usize) -> &LocatorDirectoryIdentity {
        &self.inputs.nodes[id].directory
    }

    fn touch(&mut self, id: usize) -> Result<(), WorkspaceError> {
        self.check()?;
        if !self.used.contains(&id) {
            self.used.push(id);
        }
        Ok(())
    }

    fn observe_manifest(
        &mut self,
        id: usize,
        parse: bool,
    ) -> Result<ManifestInput, WorkspaceError> {
        self.budget
            .reserve_file(self.cancel)
            .map_err(WorkspaceError::Unavailable)?;
        let observed = self
            .reader
            .read_cargo_manifest_in_captured_directory(self.directory(id), self.cancel);
        self.check()?;
        match observed {
            CargoManifestObservation::AbsentDuringLookup => Ok(ManifestInput {
                value: None,
                stamp: InputStamp::Missing,
            }),
            CargoManifestObservation::Failed(reason) => Err(WorkspaceError::Unavailable(
                super::super::format::read_reason(reason),
            )),
            CargoManifestObservation::Present(mut read) => {
                let bytes = read.observed_after.change_stamp.as_bytes();
                if bytes.len() > 4096 {
                    return Err(WorkspaceError::Unavailable("workspace_input_limit"));
                }
                read.observed_after.change_stamp =
                    sweepx_platform::RegularFileChangeStamp::new(bytes.to_vec());
                let stamp = InputStamp::Present {
                    digest: Sha256::digest(&read.bytes).into(),
                    native: Box::new(read.observed_after),
                };
                let value = if parse {
                    Some(
                        decode_cargo_workspace_manifest(&read.bytes)
                            .map_err(WorkspaceError::from_manifest_reason)?,
                    )
                } else {
                    None
                };
                Ok(ManifestInput { value, stamp })
            }
        }
    }

    fn observe_names(&mut self, id: usize) -> Result<Vec<String>, WorkspaceError> {
        self.check()?;
        let names = self
            .reader
            .captured_directory_child_names(self.directory(id), self.cancel)
            .map_err(directory_error)?;
        let mut values = Vec::with_capacity(names.len());
        for name in names {
            self.check()?;
            values.push(match name {
                NativeName::UnixBytes(bytes) => String::from_utf8(bytes)
                    .map_err(|_| WorkspaceError::Unavailable("workspace_path_encoding"))?,
                NativeName::WindowsUtf16(units) => String::from_utf16(&units)
                    .map_err(|_| WorkspaceError::Unavailable("workspace_path_encoding"))?,
            });
        }
        values.sort_unstable();
        Ok(values)
    }

    /// All visited source inputs are checked again before publishing any member/default counts.
    /// Missing remains a repeated time-local lookup, never sealed absence. Cached projections do
    /// not skip this check, and failed reads consume reservations rather than refund work.
    pub fn finish(&mut self) -> Result<(), WorkspaceError> {
        for id in self.used.clone() {
            self.check()?;
            self.reader
                .revalidate_captured_directory(self.directory(id), self.cancel)
                .map_err(|e| WorkspaceError::Unavailable(read_error(e)))?;
            if let Some(old) = &self.inputs.nodes[id].manifest {
                let stamp = old.stamp.clone();
                if self.observe_manifest(id, false)?.stamp != stamp {
                    return Err(WorkspaceError::Unavailable("workspace_manifest_changed"));
                }
            }
            if self.inputs.nodes[id].names.is_some() {
                let current = self.observe_names(id)?;
                if self.inputs.nodes[id].names.as_ref() != Some(&current) {
                    return Err(WorkspaceError::Unavailable("workspace_enumeration_changed"));
                }
            }
        }
        self.check()
    }
}

impl<P: PlatformScanner> WorkspaceSource for NativeWorkspaceSource<'_, '_, P> {
    type Directory = usize;
    fn parent(&mut self, id: &usize) -> Result<Option<usize>, WorkspaceError> {
        self.touch(*id)?;
        self.reader
            .capture_parent_directory(self.directory(*id), self.cancel)
            .map_err(|e| WorkspaceError::Unavailable(read_error(e)))?
            .map(|directory| self.intern(directory))
            .transpose()
    }
    fn resolve(&mut self, id: &usize, value: &str) -> Result<Option<usize>, WorkspaceError> {
        self.touch(*id)?;
        let path = Path::new(value);
        let resolved = if path.is_absolute() {
            // Independently admit the full literal prefix. Walking from filesystem root would
            // incorrectly reject an explicitly declared root on another legitimate volume.
            let mut prefix = PathBuf::new();
            let mut suffix = PathBuf::new();
            let mut relative = false;
            for component in path.components() {
                relative |= matches!(component, Component::ParentDir | Component::CurDir);
                if relative {
                    suffix.push(component);
                } else {
                    prefix.push(component);
                }
            }
            let origin = self
                .reader
                .capture_directory_identity(&prefix, self.cancel)
                .map_err(|e| WorkspaceError::Unavailable(read_error(e)))?;
            if suffix.as_os_str().is_empty() {
                Ok(origin)
            } else {
                self.reader
                    .capture_relative_directory(&origin, &suffix, self.cancel)
            }
        } else {
            self.reader
                .capture_relative_directory(self.directory(*id), path, self.cancel)
        };
        match resolved {
            Ok(directory) => self.intern(directory).map(Some),
            Err(
                LocatorDirectoryLookupFailure::NotFoundDuringLookup
                | LocatorDirectoryLookupFailure::NotDirectory,
            ) => Ok(None),
            Err(error) => Err(directory_error(error)),
        }
    }
    fn manifest(&mut self, id: &usize) -> Result<Option<WorkspaceManifest>, WorkspaceError> {
        self.touch(*id)?;
        if self.inputs.nodes[*id].manifest.is_none() {
            let input = self.observe_manifest(*id, true)?;
            let stamp_bytes = match &input.stamp {
                InputStamp::Missing => 0,
                InputStamp::Present { native, .. } => {
                    std::mem::size_of::<RegularFileObservation>()
                        + native.change_stamp.as_bytes().len()
                }
            };
            self.charge(stamp_bytes)?;
            self.charge(
                input
                    .value
                    .as_ref()
                    .map_or(0, WorkspaceManifest::retained_bytes_estimate),
            )?;
            self.inputs.nodes[*id].manifest = Some(input);
        }
        Ok(self.inputs.nodes[*id]
            .manifest
            .as_ref()
            .unwrap()
            .value
            .clone())
    }
    fn children(&mut self, id: &usize) -> Result<Vec<String>, WorkspaceError> {
        self.touch(*id)?;
        if self.inputs.nodes[*id].names.is_none() {
            let names = self.observe_names(*id)?;
            self.charge(
                names.capacity() * std::mem::size_of::<String>()
                    + names.iter().map(String::capacity).sum::<usize>(),
            )?;
            self.inputs.nodes[*id].names = Some(names);
        }
        Ok(self.inputs.nodes[*id].names.clone().unwrap())
    }
    fn contains(&mut self, descendant: &usize, ancestor: &usize) -> Result<bool, WorkspaceError> {
        self.touch(*descendant)?;
        self.touch(*ancestor)?;
        let result = self
            .reader
            .captured_directory_relative_components(
                self.directory(*descendant),
                self.directory(*ancestor),
                self.cancel,
            )
            .map_err(directory_error)?;
        // The model only needs the relation; do not allocate or lossy-convert these native names.
        Ok(result.is_some())
    }
    fn prefix(
        &mut self,
        descendant: &usize,
        origin: &usize,
        declared: &str,
    ) -> Result<bool, WorkspaceError> {
        self.touch(*descendant)?;
        self.touch(*origin)?;
        self.reader
            .captured_directory_matches_declared_prefix(
                self.directory(*descendant),
                self.directory(*origin),
                Path::new(declared),
                self.cancel,
            )
            .map_err(directory_error)
    }
}

fn directory_error(error: LocatorDirectoryLookupFailure) -> WorkspaceError {
    WorkspaceError::Unavailable(match error {
        LocatorDirectoryLookupFailure::Read(reason) => super::super::format::read_reason(reason),
        LocatorDirectoryLookupFailure::NotDirectory => "workspace_not_directory",
        LocatorDirectoryLookupFailure::NotFoundDuringLookup => "workspace_directory_missing",
    })
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
#[path = "workspace_native_tests.rs"]
mod tests;
