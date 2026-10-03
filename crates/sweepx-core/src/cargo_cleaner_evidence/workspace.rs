//! Pure, bounded Cargo workspace declarations for the native workspace observer.
//!
//! This projection shares the cleaner's TOML parser. It does not resolve paths, expand globs,
//! execute Cargo, validate a build or establish ownership, activity or deletion authority. The
//! caller must preserve errors as incomplete observations rather than substitute an empty graph.

use std::mem::size_of;

use super::{CargoEvidenceReason, MAX_CARGO_INPUT_FILE_BYTES, parse_toml};

const MAX_STRING_BYTES: usize = 4096;
const MAX_ARRAY_ITEMS: usize = 1024;
const MAX_DEPENDENCIES: usize = 1024;
const MAX_TARGET_TABLES: usize = 256;
const MAX_PROJECTED_BYTES: usize = 512 * 1024;
const DEPENDENCY_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// Declaration substrate for one manifest, without filesystem bindings or resolved membership.
/// The input is at most 4 MiB; relevant strings are at most 4 KiB, arrays 1,024 items, dependency
/// rows 1,024 across all supported tables, and target tables 256. Supported payloads and actual
/// vector capacities share a 512 KiB conservative projection ledger. The temporary TOML tree is
/// separately bounded by input bytes; neither limit claims to be a total RSS bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceManifest {
    /// Root package declarations; `None` identifies a virtual workspace when `workspace` exists.
    pub(crate) package: Option<WorkspacePackage>,
    /// Workspace-root declarations, distinct from a package's explicit workspace pointer.
    pub(crate) workspace: Option<WorkspaceDeclaration>,
    /// Normal, dev, build and all target-specific dependencies, including optional/inactive ones.
    /// Flattening does not evaluate cfg, since Cargo workspace membership uses their path edges.
    pub(crate) dependencies: Vec<WorkspaceDependency>,
}

impl WorkspaceManifest {
    /// Capacity-based retention ledger for invocation-local native indexes; not total RSS.
    pub(crate) fn retained_bytes_estimate(&self) -> usize {
        fn version(value: &Option<WorkspacePackageVersion>) -> usize {
            match value {
                Some(WorkspacePackageVersion::Literal(s)) => s.capacity(),
                _ => 0,
            }
        }
        fn strings(values: &Option<Vec<String>>) -> usize {
            values.as_ref().map_or(0, |v| {
                v.capacity() * size_of::<String>() + v.iter().map(String::capacity).sum::<usize>()
            })
        }
        fn dependencies(values: &Vec<WorkspaceDependency>) -> usize {
            values.capacity() * size_of::<WorkspaceDependency>()
                + values
                    .iter()
                    .map(|d| {
                        d.name.capacity()
                            + d.package.as_ref().map_or(0, String::capacity)
                            + match &d.source {
                                WorkspaceDependencySource::Path(s) => s.capacity(),
                                _ => 0,
                            }
                    })
                    .sum::<usize>()
        }
        size_of::<Self>()
            + self.package.as_ref().map_or(0, |p| {
                p.name.capacity()
                    + version(&p.version)
                    + p.workspace.as_ref().map_or(0, String::capacity)
            })
            + self.workspace.as_ref().map_or(0, |w| {
                strings(&w.members)
                    + strings(&w.exclude)
                    + strings(&w.default_members)
                    + version(&w.package_version)
                    + dependencies(&w.dependencies)
            })
            + dependencies(&self.dependencies)
    }
}

/// Package fields needed to relate a package to a workspace; no package validity certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspacePackage {
    /// Manifest package name, independent from dependency aliases that refer to this package.
    pub(crate) name: String,
    /// Missing, literal and workspace-inherited versions remain distinct for the caller.
    pub(crate) version: Option<WorkspacePackageVersion>,
    /// Exact `package.workspace` spelling; the native observer must resolve and revalidate it.
    pub(crate) workspace: Option<String>,
}

/// A version declaration, deliberately without semver/build validation or inherited defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkspacePackageVersion {
    /// Exact string from the declaring manifest.
    Literal(String),
    /// `{ workspace = true }`; an observed workspace-package version must supply its value.
    Inherited,
}

/// Workspace-root declarations. Missing arrays differ from explicitly empty arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceDeclaration {
    /// Exact member patterns, which can contain literal paths or Cargo glob spellings.
    pub(crate) members: Option<Vec<String>>,
    /// Exact exclusions; this layer does not treat their spellings as globs or path prefixes.
    pub(crate) exclude: Option<Vec<String>>,
    /// Root-invocation selection declarations, separate from workspace membership.
    pub(crate) default_members: Option<Vec<String>>,
    /// `workspace.package.version`, retained so unresolved inheritance cannot become success.
    pub(crate) package_version: Option<WorkspacePackageVersion>,
    /// Dependency definitions keyed by alias. Unused definitions do not establish membership.
    pub(crate) dependencies: Vec<WorkspaceDependency>,
}

/// One declared dependency. Duplicate aliases in distinct dependency/target tables are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceDependency {
    /// Table key used to look up workspace inheritance, including renamed dependency aliases.
    pub(crate) name: String,
    /// Exact `package` rename, when declared; it does not replace the inheritance lookup key.
    pub(crate) package: Option<String>,
    /// Membership-relevant source. No source here is an admitted filesystem path.
    pub(crate) source: WorkspaceDependencySource,
}

/// Membership-relevant dependency source, without registry resolution or build interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkspaceDependencySource {
    /// Exact path relative to the declaring manifest, or workspace root for an inherited value.
    Path(String),
    /// `workspace = true`; the caller must look up the same alias in workspace definitions.
    Inherited,
    /// String version or a table without path/inheritance; it adds no local membership edge.
    Other,
}

/// Decodes supported declarations through the existing unique TOML parser.
/// Missing/invalid shapes, duplicate TOML keys and exhausted limits reject the entire projection.
/// Patch/replace declarations are not dependency edges and are not inspected by this model.
/// `conflicting_workspace_declarations` separately identifies the Cargo-semantic conflict of a
/// package workspace pointer plus its own workspace. General unsupported/resource failures do
/// not certify that Cargo would reject the manifest.
pub(crate) fn decode_cargo_workspace_manifest(
    bytes: &[u8],
) -> Result<WorkspaceManifest, &'static str> {
    let manifest =
        decode(bytes, &mut ProjectionBudget::default()).map_err(CargoEvidenceReason::code)?;
    if manifest.workspace.is_some()
        && manifest
            .package
            .as_ref()
            .is_some_and(|package| package.workspace.is_some())
    {
        return Err("conflicting_workspace_declarations");
    }
    Ok(manifest)
}

#[derive(Debug)]
struct ProjectionBudget {
    remaining: usize,
    dependencies: usize,
}

impl Default for ProjectionBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_PROJECTED_BYTES,
            dependencies: 0,
        }
    }
}

impl ProjectionBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), CargoEvidenceReason> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(CargoEvidenceReason::ResourceLimit)?;
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<String, CargoEvidenceReason> {
        self.inspect_string(value)?;
        let owned = value.to_owned();
        self.charge(owned.capacity() - value.len())?;
        Ok(owned)
    }

    fn inspect_string(&mut self, value: &str) -> Result<(), CargoEvidenceReason> {
        if value.is_empty() || value.trim().is_empty() || value.contains('\0') {
            return Err(CargoEvidenceReason::UnsupportedManifestShape);
        }
        if value.len() > MAX_STRING_BYTES {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
        // String slots/payloads that are only checked are charged too. This deliberately
        // overestimates the retained projection rather than omit supported input complexity.
        self.charge(size_of::<String>() + value.len())
    }

    fn reserve<T>(
        &mut self,
        values: &mut Vec<T>,
        additional: usize,
    ) -> Result<(), CargoEvidenceReason> {
        let required = values
            .len()
            .checked_add(additional)
            .ok_or(CargoEvidenceReason::ResourceLimit)?;
        if required <= values.capacity() {
            return Ok(());
        }
        let old_capacity = values.capacity();
        let slots = required - old_capacity;
        self.charge(
            slots
                .checked_mul(size_of::<T>())
                .ok_or(CargoEvidenceReason::ResourceLimit)?,
        )?;
        values
            .try_reserve_exact(additional)
            .map_err(|_| CargoEvidenceReason::ResourceLimit)?;
        // Account any allocator-provided spare capacity; it must not become an uncharged view.
        self.charge(
            (values.capacity() - required)
                .checked_mul(size_of::<T>())
                .ok_or(CargoEvidenceReason::ResourceLimit)?,
        )
    }
}

fn decode(
    bytes: &[u8],
    budget: &mut ProjectionBudget,
) -> Result<WorkspaceManifest, CargoEvidenceReason> {
    if bytes.is_empty() {
        return Err(CargoEvidenceReason::MissingManifest);
    }
    if bytes.len() > MAX_CARGO_INPUT_FILE_BYTES {
        return Err(CargoEvidenceReason::ResourceLimit);
    }
    budget.charge(size_of::<WorkspaceManifest>())?;
    let table = parse_toml(bytes)?;
    let package_table = optional_table(&table, "package")?;
    let workspace_table = optional_table(&table, "workspace")?;
    if package_table.is_none() && workspace_table.is_none() {
        return Err(CargoEvidenceReason::UnsupportedManifestShape);
    }
    let package = package_table
        .map(|package| {
            let name = package
                .get("name")
                .and_then(toml::Value::as_str)
                .ok_or(CargoEvidenceReason::UnsupportedManifestShape)?;
            let workspace = optional_string(package, "workspace", budget)?;
            Ok::<_, CargoEvidenceReason>(WorkspacePackage {
                name: budget.string(name)?,
                version: optional_version(package, "version", budget)?,
                workspace,
            })
        })
        .transpose()?;
    let workspace = workspace_table
        .map(|workspace| {
            let mut dependencies = Vec::new();
            append_dependency_table(workspace, "dependencies", false, &mut dependencies, budget)?;
            Ok::<_, CargoEvidenceReason>(WorkspaceDeclaration {
                members: optional_strings(workspace, "members", budget)?,
                exclude: optional_strings(workspace, "exclude", budget)?,
                default_members: optional_strings(workspace, "default-members", budget)?,
                package_version: optional_table(workspace, "package")?
                    .map(|package| optional_version(package, "version", budget))
                    .transpose()?
                    .flatten(),
                dependencies,
            })
        })
        .transpose()?;
    let mut dependencies = Vec::new();
    append_dependencies(&table, &mut dependencies, budget)?;
    if let Some(targets) = optional_table(&table, "target")? {
        if targets.len() > MAX_TARGET_TABLES {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
        for (selector, target) in targets {
            budget.inspect_string(selector)?;
            let target = target
                .as_table()
                .ok_or(CargoEvidenceReason::UnsupportedManifestShape)?;
            append_dependencies(target, &mut dependencies, budget)?;
        }
    }
    Ok(WorkspaceManifest {
        package,
        workspace,
        dependencies,
    })
}

fn optional_table<'a>(
    table: &'a toml::Table,
    key: &str,
) -> Result<Option<&'a toml::Table>, CargoEvidenceReason> {
    table
        .get(key)
        .map(|value| {
            value
                .as_table()
                .ok_or(CargoEvidenceReason::UnsupportedManifestShape)
        })
        .transpose()
}

fn optional_string(
    table: &toml::Table,
    key: &str,
    budget: &mut ProjectionBudget,
) -> Result<Option<String>, CargoEvidenceReason> {
    table
        .get(key)
        .map(|value| {
            budget.string(
                value
                    .as_str()
                    .ok_or(CargoEvidenceReason::UnsupportedManifestShape)?,
            )
        })
        .transpose()
}

fn optional_version(
    table: &toml::Table,
    key: &str,
    budget: &mut ProjectionBudget,
) -> Result<Option<WorkspacePackageVersion>, CargoEvidenceReason> {
    table
        .get(key)
        .map(|value| match value {
            toml::Value::String(value) => {
                budget.string(value).map(WorkspacePackageVersion::Literal)
            }
            toml::Value::Table(value)
                if value.len() == 1
                    && value.get("workspace").and_then(toml::Value::as_bool) == Some(true) =>
            {
                Ok(WorkspacePackageVersion::Inherited)
            }
            _ => Err(CargoEvidenceReason::UnsupportedManifestShape),
        })
        .transpose()
}

fn optional_strings(
    table: &toml::Table,
    key: &str,
    budget: &mut ProjectionBudget,
) -> Result<Option<Vec<String>>, CargoEvidenceReason> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let source = value
        .as_array()
        .ok_or(CargoEvidenceReason::UnsupportedManifestShape)?;
    if source.len() > MAX_ARRAY_ITEMS {
        return Err(CargoEvidenceReason::ResourceLimit);
    }
    let mut values = Vec::new();
    budget.reserve(&mut values, source.len())?;
    for value in source {
        values.push(
            budget.string(
                value
                    .as_str()
                    .ok_or(CargoEvidenceReason::UnsupportedManifestShape)?,
            )?,
        );
    }
    Ok(Some(values))
}

fn append_dependencies(
    table: &toml::Table,
    dependencies: &mut Vec<WorkspaceDependency>,
    budget: &mut ProjectionBudget,
) -> Result<(), CargoEvidenceReason> {
    // Legacy spelling support differs by Cargo edition. Leave it explicitly unsupported until
    // an independent pinned-Cargo observation establishes its scope; never hide a possible edge.
    if ["dev_dependencies", "build_dependencies"]
        .iter()
        .any(|key| table.contains_key(*key))
    {
        return Err(CargoEvidenceReason::UnsupportedManifestShape);
    }
    for key in DEPENDENCY_TABLES {
        append_dependency_table(table, key, true, dependencies, budget)?;
    }
    Ok(())
}

fn append_dependency_table(
    table: &toml::Table,
    key: &str,
    allow_inheritance: bool,
    dependencies: &mut Vec<WorkspaceDependency>,
    budget: &mut ProjectionBudget,
) -> Result<(), CargoEvidenceReason> {
    let Some(source) = optional_table(table, key)? else {
        return Ok(());
    };
    budget.dependencies = budget
        .dependencies
        .checked_add(source.len())
        .filter(|count| *count <= MAX_DEPENDENCIES)
        .ok_or(CargoEvidenceReason::ResourceLimit)?;
    budget.reserve(dependencies, source.len())?;
    for (name, value) in source {
        let name = budget.string(name)?;
        let (package, source) = match value {
            toml::Value::String(version) => {
                budget.inspect_string(version)?;
                (None, WorkspaceDependencySource::Other)
            }
            toml::Value::Table(table) => decode_dependency(table, allow_inheritance, budget)?,
            _ => return Err(CargoEvidenceReason::UnsupportedManifestShape),
        };
        dependencies.push(WorkspaceDependency {
            name,
            package,
            source,
        });
    }
    Ok(())
}

fn decode_dependency(
    table: &toml::Table,
    allow_inheritance: bool,
    budget: &mut ProjectionBudget,
) -> Result<(Option<String>, WorkspaceDependencySource), CargoEvidenceReason> {
    use CargoEvidenceReason::UnsupportedManifestShape;
    let path = optional_string(table, "path", budget)?;
    let package = optional_string(table, "package", budget)?;
    let inherited = match table.get("workspace") {
        None => false,
        Some(toml::Value::Boolean(true)) if allow_inheritance => true,
        Some(_) => return Err(UnsupportedManifestShape),
    };
    // These supported source spellings are inspected without resolving a registry or Git.
    for key in ["version", "git", "branch", "tag", "rev", "registry"] {
        if let Some(value) = table.get(key) {
            budget.inspect_string(value.as_str().ok_or(UnsupportedManifestShape)?)?;
        }
    }
    for key in ["optional", "default-features", "default_features"] {
        if table.get(key).is_some_and(|value| !value.is_bool()) {
            return Err(UnsupportedManifestShape);
        }
    }
    if let Some(features) = table.get("features") {
        let features = features.as_array().ok_or(UnsupportedManifestShape)?;
        if features.len() > MAX_ARRAY_ITEMS {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
        budget.charge(features.len() * size_of::<String>())?;
        for feature in features {
            budget.inspect_string(feature.as_str().ok_or(UnsupportedManifestShape)?)?;
        }
    }
    if inherited
        && (path.is_some()
            || package.is_some()
            || ["version", "git", "branch", "tag", "rev", "registry"]
                .iter()
                .any(|key| table.contains_key(*key)))
        || (path.is_some() && table.contains_key("git"))
    {
        return Err(UnsupportedManifestShape);
    }
    let source = if inherited {
        WorkspaceDependencySource::Inherited
    } else if let Some(path) = path {
        WorkspaceDependencySource::Path(path)
    } else {
        WorkspaceDependencySource::Other
    };
    Ok((package, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_workspace_lists_package_pointer_and_inherited_version() {
        let standalone = decode_cargo_workspace_manifest(
            b"[package]\nname='renamed'\nversion.workspace=true\nworkspace='../root'\n",
        )
        .unwrap();
        assert_eq!(
            standalone.package.unwrap(),
            WorkspacePackage {
                name: "renamed".into(),
                version: Some(WorkspacePackageVersion::Inherited),
                workspace: Some("../root".into()),
            }
        );
        let absent = decode_cargo_workspace_manifest(b"[workspace]\n")
            .unwrap()
            .workspace
            .unwrap();
        assert_eq!(absent.members, None);
        assert_eq!(absent.exclude, None);
        assert_eq!(absent.default_members, None);
        let empty = decode_cargo_workspace_manifest(
            b"[workspace]\nmembers=[]\nexclude=[]\ndefault-members=[]\n[workspace.package]\nversion='1.2.3'\n",
        )
        .unwrap()
        .workspace
        .unwrap();
        assert_eq!(empty.members, Some(vec![]));
        assert_eq!(empty.exclude, Some(vec![]));
        assert_eq!(empty.default_members, Some(vec![]));
        assert_eq!(
            empty.package_version,
            Some(WorkspacePackageVersion::Literal("1.2.3".into()))
        );
    }

    #[test]
    fn projects_renamed_inline_table_target_and_inherited_path_edges() {
        let manifest = decode_cargo_workspace_manifest(
            br#"[package]
name='root_package'
version='0.1.0'
[workspace]
members=['a','crates/*','../external']
exclude=['foo','crates/a']
default-members=['a']
[workspace.dependencies]
inherited_alias={path='shared',package='actual_shared'}
unused={path='unused'}
[dependencies]
inline_alias={path='a',package='actual_a',optional=true}
inherited_alias.workspace=true
registry='1'
[dev-dependencies.table_alias]
path='b'
package='actual_b'
[build-dependencies]
build={path='c'}
[target.'cfg(target_os="none")'.dependencies]
inactive={path='d'}
[target.x86_64_unknown_linux_gnu.dev-dependencies]
target_dev={path='e'}
[target.x86_64_unknown_linux_gnu.build-dependencies]
target_build={path='f'}
[patch.crates-io]
ignored={path='not_a_member'}
"#,
        )
        .unwrap();
        let paths: std::collections::BTreeSet<_> = manifest
            .dependencies
            .iter()
            .filter_map(|dependency| match &dependency.source {
                WorkspaceDependencySource::Path(path) => {
                    Some((dependency.name.as_str(), path.as_str()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            [
                ("inline_alias", "a"),
                ("table_alias", "b"),
                ("build", "c"),
                ("inactive", "d"),
                ("target_dev", "e"),
                ("target_build", "f"),
            ]
            .into_iter()
            .collect()
        );
        let inherited = manifest
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "inherited_alias")
            .unwrap();
        assert_eq!(inherited.source, WorkspaceDependencySource::Inherited);
        let definitions = manifest.workspace.unwrap().dependencies;
        let definition = definitions
            .iter()
            .find(|dependency| dependency.name == inherited.name)
            .unwrap();
        assert_eq!(definition.package.as_deref(), Some("actual_shared"));
        assert_eq!(
            definition.source,
            WorkspaceDependencySource::Path("shared".into())
        );
        assert_eq!(definitions.len(), 2); // Unused definition remains distinct from observed edges.
        assert!(
            manifest
                .dependencies
                .iter()
                .all(|dependency| dependency.name != "ignored")
        );
    }

    #[test]
    fn projection_preserves_literal_patterns_and_does_not_inspect_unused_patch() {
        let manifest = decode_cargo_workspace_manifest(
            br#"[workspace]
members=['a/../b','foo/child','crates/*']
exclude=['foo','crates/*']
default-members=[]
[patch.crates-io]
unused={path=false}
"#,
        )
        .unwrap();
        assert!(manifest.dependencies.is_empty());
        let workspace = manifest.workspace.unwrap();
        assert_eq!(
            workspace.members,
            Some(vec!["a/../b".into(), "foo/child".into(), "crates/*".into()])
        );
        assert_eq!(
            workspace.exclude,
            Some(vec!["foo".into(), "crates/*".into()])
        );
        assert_eq!(workspace.default_members, Some(vec![]));
        assert!(workspace.dependencies.is_empty());
    }

    #[test]
    fn rejects_invalid_shapes_and_duplicate_toml_without_empty_success() {
        assert_eq!(
            decode_cargo_workspace_manifest(b"[package]\nname='a'\nworkspace='..'\n[workspace]\n"),
            Err("conflicting_workspace_declarations")
        );
        for input in [
            "[package]\nname='a'\nversion={workspace=false}\n",
            "[workspace]\nmembers=[1]\n",
            "[workspace]\nexclude='a'\n",
            "[workspace]\ndefault-members=[[]]\n",
            "[workspace]\n[dependencies]\na={path=true}\n",
            "[workspace]\n[dependencies]\na={workspace=false}\n",
            "[workspace]\n[dependencies]\na={workspace=true,path='a'}\n",
            "[workspace]\n[dependencies]\na={workspace=true,package='a'}\n",
            "[workspace.dependencies]\na={workspace=true}\n",
            "[workspace]\n[target]\na=[]\n",
            "[workspace]\n[dependencies]\na=[]\n",
            "[workspace]\n[dev_dependencies]\na={path='a'}\n",
        ] {
            assert_eq!(
                decode_cargo_workspace_manifest(input.as_bytes()),
                Err("unsupported_manifest_shape"),
                "{input}"
            );
        }
        assert_eq!(
            decode_cargo_workspace_manifest(b"[workspace]\nmembers=[]\nmembers=[]\n"),
            Err("duplicate_toml_key")
        );
        assert_eq!(
            decode_cargo_workspace_manifest(
                b"[workspace]\n[dependencies]\na={path='a',path='b'}\n"
            ),
            Err("duplicate_toml_key")
        );
        assert_eq!(
            decode_cargo_workspace_manifest(b"[workspace]\nmembers=[\n"),
            Err("malformed_toml")
        );
    }

    #[test]
    fn projection_budget_is_shared_across_arrays_and_dependency_tables() {
        let first = b"[workspace]\nmembers=['a']\n";
        let mut control = ProjectionBudget::default();
        decode(first, &mut control).unwrap();
        let consumed = MAX_PROJECTED_BYTES - control.remaining;
        assert!(consumed > 0);
        let mut exact = ProjectionBudget {
            remaining: consumed,
            dependencies: 0,
        };
        assert!(decode(first, &mut exact).is_ok());
        for extra in ["exclude=['b']\n", "[dependencies]\nb={path='b'}\n"] {
            let input = String::from_utf8(first.to_vec()).unwrap() + extra;
            let mut exhausted = ProjectionBudget {
                remaining: consumed,
                dependencies: 0,
            };
            assert_eq!(
                decode(input.as_bytes(), &mut exhausted),
                Err(CargoEvidenceReason::ResourceLimit)
            );
        }
        let oversized_string = format!("[workspace]\nmembers=['{}']\n", "x".repeat(4097));
        assert_eq!(
            decode_cargo_workspace_manifest(oversized_string.as_bytes()),
            Err("resource_limit")
        );
        let oversized_array = format!("[workspace]\nmembers=[{}]\n", "'a',".repeat(1025));
        assert_eq!(
            decode_cargo_workspace_manifest(oversized_array.as_bytes()),
            Err("resource_limit")
        );
    }

    #[test]
    fn dependency_and_target_limits_apply_to_the_entire_supported_projection() {
        let definitions = (0..512)
            .map(|index| format!("definition{index}={{path='a'}}\n"))
            .collect::<String>();
        let direct = (0..513)
            .map(|index| format!("direct{index}={{path='a'}}\n"))
            .collect::<String>();
        let input =
            format!("[workspace]\n[workspace.dependencies]\n{definitions}[dependencies]\n{direct}");
        assert_eq!(
            decode_cargo_workspace_manifest(input.as_bytes()),
            Err("resource_limit")
        );
        let targets = (0..257)
            .map(|index| format!("[target.'cfg(custom{index})'.dependencies]\na={{path='a'}}\n"))
            .collect::<String>();
        let input = format!("[workspace]\n{targets}");
        assert_eq!(
            decode_cargo_workspace_manifest(input.as_bytes()),
            Err("resource_limit")
        );
    }
}
