//! Invocation-local Cargo configuration graph. Every read uses the existing native reader;
//! cached parsing is rechecked against current bytes/identity before a result is published.
//! Includes admit their own configuration inputs, never expand scan or deletion coverage.

use super::config::{ConfigSource, resolve_config, table_retained_bytes};
use super::scope::{ScopeBudget, read_error};
use crate::cargo_cleaner_evidence::{CargoConfigInput, decode_cargo_config_input};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use sweepx_model::NativeName;
use sweepx_platform::{CancellationToken, PlatformScanner, RegularFileObservation};
use sweepx_scanner::{
    CargoConfigMemberObservation, CargoConfigPairObservation, DirectoryPathObservation,
    LocatorDirectoryIdentity, LocatorDirectoryLookupFailure, LocatorReadFailure, LocatorReader,
};

#[derive(PartialEq, Eq)]
enum Stamp {
    // Enumeration and fixed lookup have different provenance, but both observed this name
    // absent at a time point. Rechecking one by the other does not turn it into an atomic fact.
    Missing,
    Failed(LocatorReadFailure),
    Present {
        digest: [u8; 32],
        native: Box<RegularFileObservation>,
    },
}
impl Stamp {
    fn of(member: &CargoConfigMemberObservation) -> Result<Self, &'static str> {
        Ok(match member {
            CargoConfigMemberObservation::AbsentDuringEnumeration
            | CargoConfigMemberObservation::AbsentDuringLookup => Self::Missing,
            CargoConfigMemberObservation::Failed(reason) => Self::Failed(reason.clone()),
            CargoConfigMemberObservation::Present(read) => {
                let bytes = read.observed_after.change_stamp.as_bytes();
                if bytes.len() > 4096 {
                    return Err("resource_limit");
                }
                let mut native = read.observed_after.clone();
                native.change_stamp = sweepx_platform::RegularFileChangeStamp::new(bytes.to_vec());
                Self::Present {
                    digest: Sha256::digest(&read.bytes).into(),
                    native: Box::new(native),
                }
            }
        })
    }

    fn retained(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Present { native, .. } => {
                    std::mem::size_of::<RegularFileObservation>()
                        + native.change_stamp.as_bytes().len()
                }
                _ => 0,
            }
    }
}

struct FileInput {
    directory: LocatorDirectoryIdentity,
    name: NativeName,
    stamp: Stamp,
    input: Result<Option<CargoConfigInput>, &'static str>,
}
struct RootInput {
    directory: LocatorDirectoryIdentity,
    nested: bool,
    stamps: [Stamp; 2],
    selected: Option<usize>,
}
struct MissingParent {
    base: LocatorDirectoryIdentity,
    path: PathBuf,
    observed: DirectoryPathObservation,
}

/// A scalar's private defining-file base. `None` keeps the root source's existing origin,
/// including Cargo home's lexical-parent model; includes carry their own admitted base.
pub(super) struct ConfigTarget {
    /// Private selected scalar, bounded to 4 KiB before returning to the output model.
    pub value: String,
    /// Independently admitted lexical grandparent of the defining include file.
    pub include_base: Option<LocatorDirectoryIdentity>,
}

/// Fixed invocation index: at most 64 discovered roots, 128 files/absent parent inputs and
/// 8 MiB estimated retained storage. No config bytes or answers enter durable caches/reports.
pub(super) struct ConfigInputs {
    roots: Vec<RootInput>,
    files: Vec<FileInput>,
    missing: Vec<MissingParent>,
    used_roots: Vec<usize>,
    used_files: Vec<usize>,
    used_missing: Vec<usize>,
    retained: usize,
    operations: usize,
}
impl Default for ConfigInputs {
    fn default() -> Self {
        Self {
            roots: Vec::with_capacity(64),
            files: Vec::with_capacity(128),
            missing: Vec::with_capacity(128),
            used_roots: Vec::with_capacity(64),
            used_files: Vec::with_capacity(128),
            used_missing: Vec::with_capacity(128),
            retained: 64 * std::mem::size_of::<RootInput>()
                + 128 * std::mem::size_of::<FileInput>()
                + 128 * std::mem::size_of::<MissingParent>()
                + 320 * std::mem::size_of::<usize>(),
            operations: 0,
        }
    }
}
impl ConfigInputs {
    /// Starts one candidate's dependency accounting without forgetting the invocation's inputs.
    pub fn begin(&mut self) {
        self.used_roots.clear();
        self.used_files.clear();
        self.used_missing.clear();
        self.operations = 0;
    }

    fn check(
        &mut self,
        cancel: &CancellationToken,
        budget: &ScopeBudget<'_>,
    ) -> Result<(), &'static str> {
        budget.check(cancel)?;
        self.operations += 1;
        if self.operations > 16_384 {
            return Err("config_work_limit");
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), &'static str> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .filter(|bytes| *bytes <= 8 * 1024 * 1024)
            .ok_or("resource_limit")?;
        Ok(())
    }

    fn intern_file<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        directory: LocatorDirectoryIdentity,
        name: NativeName,
        supplied: Option<&CargoConfigMemberObservation>,
        cancel: &CancellationToken,
        budget: &mut ScopeBudget<'_>,
    ) -> Result<usize, &'static str> {
        self.check(cancel, budget)?;
        if let Some(id) = self
            .files
            .iter()
            .position(|file| file.directory == directory && file.name == name)
        {
            return Ok(id);
        }
        if self.files.iter().any(|file| {
            file.directory.same_captured_native_object(&directory) && file.directory != directory
        }) {
            return Err("config_input_alias_or_change");
        }
        if self.files.len() >= 128 {
            return Err("config_include_limit");
        }
        let owned;
        let member = if let Some(member) = supplied {
            member
        } else {
            budget.reserve_file(cancel)?;
            owned =
                reader.read_cargo_config_include_in_captured_directory(&directory, &name, cancel);
            &owned
        };
        self.check(cancel, budget)?;
        let stamp = Stamp::of(member)?;
        let input = match member {
            CargoConfigMemberObservation::Present(read) => {
                decode_cargo_config_input(&read.bytes).map(Some)
            }
            CargoConfigMemberObservation::AbsentDuringEnumeration
            | CargoConfigMemberObservation::AbsentDuringLookup => Ok(None),
            CargoConfigMemberObservation::Failed(reason) => {
                Err(super::super::format::read_reason(reason.clone()))
            }
        };
        let mut bytes = directory.retained_bytes_estimate() + name_bytes(&name) + stamp.retained();
        if let Ok(Some(input)) = &input {
            bytes = bytes
                .saturating_add(table_retained_bytes(&input.values)?)
                .saturating_add(
                    input.includes.capacity()
                        * std::mem::size_of::<crate::cargo_cleaner_evidence::CargoConfigInclude>(),
                );
            for include in &input.includes {
                bytes = bytes.saturating_add(include.path.capacity());
            }
        }
        self.charge(bytes)?;
        let id = self.files.len();
        self.files.push(FileInput {
            directory,
            name,
            stamp,
            input,
        });
        Ok(id)
    }

    /// Resolves this discovered root's includes and moves only the selected scalar into the
    /// output model. Repeated files are rejected per root; different roots share parsing only.
    pub fn source<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        directory: &LocatorDirectoryIdentity,
        nested: bool,
        supplied: Option<&CargoConfigPairObservation>,
        cancel: &CancellationToken,
        budget: &mut ScopeBudget<'_>,
    ) -> Result<Option<ConfigTarget>, &'static str> {
        self.check(cancel, budget)?;
        let id = if let Some(id) = self
            .roots
            .iter()
            .position(|root| &root.directory == directory && root.nested == nested)
        {
            id
        } else {
            if self.roots.len() >= 64 {
                return Err("config_source_limit");
            }
            let owned;
            let pair = if let Some(pair) = supplied {
                pair
            } else {
                budget.reserve_pair(cancel)?;
                owned = reader
                    .read_cargo_config_pair_in_captured_directory(directory, nested, cancel)
                    .map_err(read_error)?;
                &owned
            };
            let stamps = [Stamp::of(&pair.config)?, Stamp::of(&pair.config_toml)?];
            let (name, member) = match &pair.config {
                CargoConfigMemberObservation::AbsentDuringEnumeration
                | CargoConfigMemberObservation::AbsentDuringLookup => {
                    (native("config.toml"), &pair.config_toml)
                }
                other => (native("config"), other),
            };
            let selected = match member {
                CargoConfigMemberObservation::Present(_) => {
                    let parent = if nested {
                        match reader
                            .observe_directory_path(directory, Path::new(".cargo"), cancel)
                            .map_err(directory_reason)?
                        {
                            DirectoryPathObservation::Present(parent) => parent,
                            DirectoryPathObservation::AbsentDuringLookup(_) => {
                                return Err("config_input_changed");
                            }
                        }
                    } else {
                        directory.clone()
                    };
                    Some(self.intern_file(reader, parent, name, Some(member), cancel, budget)?)
                }
                CargoConfigMemberObservation::AbsentDuringEnumeration
                | CargoConfigMemberObservation::AbsentDuringLookup => None,
                CargoConfigMemberObservation::Failed(reason) => {
                    return Err(super::super::format::read_reason(reason.clone()));
                }
            };
            self.charge(
                directory.retained_bytes_estimate()
                    + stamps.iter().map(Stamp::retained).sum::<usize>(),
            )?;
            let id = self.roots.len();
            self.roots.push(RootInput {
                directory: directory.clone(),
                nested,
                stamps,
                selected,
            });
            id
        };
        if !self.used_roots.contains(&id) {
            self.used_roots.push(id);
        }
        let Some(root) = self.roots[id].selected else {
            return Ok(None);
        };
        let mut source = NativeConfigSource {
            inputs: self,
            reader,
            cancel,
            budget,
        };
        let mut resolved = resolve_config(&mut source, &root)?;
        let Some(build) = resolved.values.remove("build") else {
            return Ok(None);
        };
        let toml::Value::Table(mut build) = build else {
            return Err("unsupported_manifest_shape");
        };
        let Some(value) = build.remove("target-dir") else {
            return Ok(None);
        };
        let toml::Value::String(value) = value else {
            return Err("unsupported_manifest_shape");
        };
        if value.len() > 4096 {
            return Err("resource_limit");
        }
        if value.is_empty() || value.contains('\0') {
            return Err("invalid_target_dir_declaration");
        }
        let origin = resolved
            .target_origin
            .ok_or("config_source_binding_unavailable")?;
        let include_base = if origin == root {
            None
        } else {
            Some(
                reader
                    .capture_parent_directory(&source.inputs.files[origin].directory, cancel)
                    .map_err(read_error)?
                    .ok_or("config_source_binding_unavailable")?,
            )
        };
        Ok(Some(ConfigTarget {
            value,
            include_base,
        }))
    }

    /// Rechecks every used root/file/optional-parent against its first observation. Parsing reuse
    /// cannot conceal a changed dependency. These bounded time points do not seal absence or ABA.
    pub fn finish<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        cancel: &CancellationToken,
        budget: &mut ScopeBudget<'_>,
    ) -> Result<(), &'static str> {
        for index in 0..self.used_roots.len() {
            self.check(cancel, budget)?;
            budget.reserve_pair(cancel)?;
            let root = &self.roots[self.used_roots[index]];
            let pair = reader
                .read_cargo_config_pair_in_captured_directory(&root.directory, root.nested, cancel)
                .map_err(read_error)?;
            if [Stamp::of(&pair.config)?, Stamp::of(&pair.config_toml)?] != root.stamps {
                return Err("config_input_changed");
            }
        }
        for index in 0..self.used_files.len() {
            self.check(cancel, budget)?;
            budget.reserve_file(cancel)?;
            let file = &self.files[self.used_files[index]];
            let member = reader.read_cargo_config_include_in_captured_directory(
                &file.directory,
                &file.name,
                cancel,
            );
            if Stamp::of(&member)? != file.stamp {
                return Err("config_input_changed");
            }
        }
        for index in 0..self.used_missing.len() {
            self.check(cancel, budget)?;
            let absent = &self.missing[self.used_missing[index]];
            if reader
                .observe_cargo_config_include_parent(&absent.base, &absent.path, cancel)
                .map_err(directory_reason)?
                .0
                != absent.observed
            {
                return Err("config_input_changed");
            }
        }
        self.check(cancel, budget)
    }
}

struct NativeConfigSource<'a, 'b, P: PlatformScanner> {
    inputs: &'a mut ConfigInputs,
    reader: &'a LocatorReader<P>,
    cancel: &'a CancellationToken,
    budget: &'a mut ScopeBudget<'b>,
}
impl<P: PlatformScanner> ConfigSource for NativeConfigSource<'_, '_, P> {
    type Key = usize;
    fn check(&mut self) -> Result<(), &'static str> {
        self.inputs.check(self.cancel, self.budget)
    }
    fn load(&mut self, id: &usize) -> Result<Option<CargoConfigInput>, &'static str> {
        self.check()?;
        if !self.inputs.used_files.contains(id) {
            self.inputs.used_files.push(*id);
        }
        self.inputs.files[*id].input.clone()
    }
    fn resolve(&mut self, from: &usize, path: &str) -> Result<Option<usize>, &'static str> {
        self.check()?;
        let path = Path::new(path);
        let base = self.inputs.files[*from].directory.clone();
        let (observed, name) = self
            .reader
            .observe_cargo_config_include_parent(&base, path, self.cancel)
            .map_err(directory_reason)?;
        match observed {
            DirectoryPathObservation::Present(directory) => self
                .inputs
                .intern_file(self.reader, directory, name, None, self.cancel, self.budget)
                .map(Some),
            observed @ DirectoryPathObservation::AbsentDuringLookup(_) => {
                let id = if let Some(id) = self
                    .inputs
                    .missing
                    .iter()
                    .position(|old| old.base == base && old.path == path)
                {
                    id
                } else {
                    if self.inputs.missing.len() >= 128 {
                        return Err("config_include_limit");
                    }
                    self.inputs.charge(
                        base.retained_bytes_estimate()
                            + path.as_os_str().as_encoded_bytes().len()
                            + observed.retained_bytes_estimate(),
                    )?;
                    let id = self.inputs.missing.len();
                    self.inputs.missing.push(MissingParent {
                        base,
                        path: path.to_path_buf(),
                        observed,
                    });
                    id
                };
                if !self.inputs.used_missing.contains(&id) {
                    self.inputs.used_missing.push(id);
                }
                Ok(None)
            }
        }
    }
}

fn native(value: &str) -> NativeName {
    native_os(std::ffi::OsStr::new(value))
}
fn native_os(value: &std::ffi::OsStr) -> NativeName {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        NativeName::UnixBytes(value.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        NativeName::WindowsUtf16(value.encode_wide().collect())
    }
}
fn name_bytes(name: &NativeName) -> usize {
    match name {
        NativeName::UnixBytes(bytes) => bytes.capacity(),
        NativeName::WindowsUtf16(units) => units.capacity().saturating_mul(2),
    }
}
fn directory_reason(error: LocatorDirectoryLookupFailure) -> &'static str {
    match error {
        LocatorDirectoryLookupFailure::Read(reason) => super::super::format::read_reason(reason),
        LocatorDirectoryLookupFailure::NotDirectory
        | LocatorDirectoryLookupFailure::NotFoundDuringLookup => "config_include_lookup_changed",
    }
}
