//! Independent Cargo observations drive the graph expectations; fixtures never invoke Cargo.

use super::{WorkspaceError, WorkspaceSource, resolve_workspace};
use crate::cargo_cleaner_evidence::{WorkspaceManifest, decode_cargo_workspace_manifest};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const ORACLE: &str = sweepx_fixtures::project_junk::CARGO_WORKSPACE_ORACLE;

/// POSIX fixture components are portable test labels, not host filesystem paths or authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FixturePath(Vec<String>);

impl FixturePath {
    fn relative(value: &str) -> Self {
        assert!(!value.starts_with('/'), "fixture paths must be relative");
        let parts: Vec<_> = value.split('/').map(str::to_owned).collect();
        assert!(
            parts
                .iter()
                .all(|part| !part.is_empty() && part != "." && part != "..")
        );
        Self(parts)
    }

    fn join_declaration(&self, value: &str) -> Result<Self, &'static str> {
        let mut result = if value.starts_with('/') {
            Vec::new()
        } else {
            self.0.clone()
        };
        for part in value.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    result.pop().ok_or("oracle_fixture_escape")?;
                }
                name => result.push(name.to_owned()),
            }
        }
        Ok(Self(result))
    }
}

/// Models only the supplied fixture tree. It has no workspace-membership or glob algorithm.
struct MemorySource {
    directories: BTreeSet<FixturePath>,
    manifests: BTreeMap<FixturePath, Vec<u8>>,
    entries: BTreeMap<FixturePath, BTreeSet<String>>,
}

impl MemorySource {
    fn from_record(record: &Value) -> Self {
        let inputs = record["inputs"].as_array().unwrap();
        assert!(inputs.len() <= 64);
        let mut source = Self {
            directories: BTreeSet::from([FixturePath(Vec::new())]),
            manifests: BTreeMap::new(),
            entries: BTreeMap::new(),
        };
        let mut total_bytes = 0;
        for input in inputs {
            let path = FixturePath::relative(input["path"].as_str().unwrap());
            let bytes = input["utf8"].as_str().unwrap().as_bytes();
            assert_eq!(bytes.len() as u64, input["bytes"].as_u64().unwrap());
            total_bytes += bytes.len();
            for (ordinal, name) in path.0.iter().enumerate() {
                let parent = FixturePath(path.0[..ordinal].to_vec());
                source.directories.insert(parent.clone());
                source
                    .entries
                    .entry(parent)
                    .or_default()
                    .insert(name.clone());
            }
            if path.0.last().unwrap() == "Cargo.toml" {
                let directory = FixturePath(path.0[..path.0.len() - 1].to_vec());
                assert!(source.manifests.insert(directory, bytes.to_vec()).is_none());
            }
        }
        assert!(total_bytes <= 128 * 1024);
        source
    }

    fn require_directory(&self, directory: &FixturePath) -> Result<(), WorkspaceError> {
        self.directories
            .contains(directory)
            .then_some(())
            .ok_or(WorkspaceError::Unavailable("oracle_unknown_directory"))
    }
}

impl WorkspaceSource for MemorySource {
    type Directory = FixturePath;

    fn parent(&mut self, directory: &FixturePath) -> Result<Option<FixturePath>, WorkspaceError> {
        self.require_directory(directory)?;
        Ok((!directory.0.is_empty())
            .then(|| FixturePath(directory.0[..directory.0.len() - 1].to_vec())))
    }

    fn resolve(
        &mut self,
        directory: &FixturePath,
        declared: &str,
    ) -> Result<Option<FixturePath>, WorkspaceError> {
        self.require_directory(directory)?;
        let joined = directory
            .join_declaration(declared)
            .map_err(WorkspaceError::Unavailable)?;
        Ok(self.directories.contains(&joined).then_some(joined))
    }

    fn manifest(
        &mut self,
        directory: &FixturePath,
    ) -> Result<Option<WorkspaceManifest>, WorkspaceError> {
        self.require_directory(directory)?;
        self.manifests
            .get(directory)
            .map(|bytes| decode_cargo_workspace_manifest(bytes))
            .transpose()
            .map_err(WorkspaceError::from_manifest_reason)
    }

    fn children(&mut self, directory: &FixturePath) -> Result<Vec<String>, WorkspaceError> {
        self.require_directory(directory)?;
        // File names are present too. The resolver must resolve a matched path as a directory
        // instead of inferring package existence from a glob or a basename.
        Ok(self
            .entries
            .get(directory)
            .into_iter()
            .flatten()
            .cloned()
            .collect())
    }

    fn prefix(
        &mut self,
        descendant: &FixturePath,
        origin: &FixturePath,
        declared: &str,
    ) -> Result<bool, WorkspaceError> {
        self.require_directory(descendant)?;
        self.require_directory(origin)?;
        // Raw component prefix, intentionally without the fixture resolver's normalization.
        let mut parts = if declared.starts_with('/') {
            Vec::new()
        } else {
            origin.0.clone()
        };
        parts.extend(
            declared
                .split('/')
                .filter(|p| !p.is_empty() && *p != ".")
                .map(str::to_owned),
        );
        Ok(descendant.0.starts_with(&parts))
    }

    fn contains(
        &mut self,
        descendant: &FixturePath,
        ancestor: &FixturePath,
    ) -> Result<bool, WorkspaceError> {
        self.require_directory(descendant)?;
        self.require_directory(ancestor)?;
        Ok(descendant.0.starts_with(&ancestor.0))
    }
}

fn fixture_prefix(record: &Value) -> String {
    let suffix = format!("/{}", record["fixtureRelativeCwd"].as_str().unwrap());
    let directory = record["cwd"]
        .as_str()
        .unwrap()
        .strip_suffix(&suffix)
        .unwrap();
    format!("{directory}/")
}

fn raw_directory(path: &str, prefix: &str) -> FixturePath {
    FixturePath::relative(path.strip_prefix(prefix).unwrap())
}

fn raw_member_directories(metadata: &Value, field: &str, prefix: &str) -> BTreeSet<FixturePath> {
    // Join Cargo's raw IDs to Cargo's raw package records. Neither the harness's derived
    // workspaceMembers fields nor SweepX's declaration interpretation supplies expectations.
    let packages: BTreeMap<_, _> = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            (
                package["id"].as_str().unwrap(),
                package["manifest_path"].as_str().unwrap(),
            )
        })
        .collect();
    let ids = metadata[field].as_array().unwrap();
    let directories: BTreeSet<_> = ids
        .iter()
        .map(|id| {
            let manifest = packages[id.as_str().unwrap()];
            raw_directory(manifest.strip_suffix("/Cargo.toml").unwrap(), prefix)
        })
        .collect();
    assert_eq!(
        directories.len(),
        ids.len(),
        "raw Cargo members must be unique"
    );
    directories
}

#[test]
fn workspace_graph_matches_all_53_pinned_cargo_observations() {
    let oracle: Value = serde_json::from_str(ORACLE).unwrap();
    assert_eq!(oracle["schema"], "sweepx.cargo-workspace-oracle/v1");
    assert_eq!(oracle["complete"], true);
    let records = oracle["records"].as_array().unwrap();
    assert_eq!(records.len(), 53);
    let planned: BTreeSet<_> = oracle["plannedCases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    let recorded: BTreeSet<_> = records
        .iter()
        .map(|record| record["name"].as_str().unwrap())
        .collect();
    assert_eq!(planned, recorded);
    assert_eq!(recorded.len(), records.len());
    let mut differences = Vec::new();
    let mut successes = 0;
    let mut rejections = 0;
    for record in records {
        let name = record["name"].as_str().unwrap();
        let cargo = &record["cargo"];
        assert!(
            cargo["boundedFailure"].is_null(),
            "incomplete oracle case {name}"
        );
        let mut source = MemorySource::from_record(record);
        let project = FixturePath::relative(record["fixtureRelativeCwd"].as_str().unwrap());
        let actual = resolve_workspace(&mut source, &project);
        match cargo["status"].as_i64().unwrap() {
            0 => {
                successes += 1;
                let metadata: Value =
                    serde_json::from_str(cargo["stdout"].as_str().unwrap()).unwrap();
                let prefix = fixture_prefix(record);
                let expected_root =
                    raw_directory(metadata["workspace_root"].as_str().unwrap(), &prefix);
                let expected_members =
                    raw_member_directories(&metadata, "workspace_members", &prefix);
                let expected_defaults =
                    raw_member_directories(&metadata, "workspace_default_members", &prefix);
                match actual {
                    Ok(actual) => {
                        let members: BTreeSet<_> = actual.members.iter().cloned().collect();
                        let defaults: BTreeSet<_> =
                            actual.default_members.iter().cloned().collect();
                        if actual.root != expected_root
                            || members != expected_members
                            || defaults != expected_defaults
                            || members.len() != actual.members.len()
                            || defaults.len() != actual.default_members.len()
                        {
                            differences.push(format!(
                                "{name}: expected root={expected_root:?}, members={expected_members:?}, defaults={expected_defaults:?}; got root={:?}, members={:?}, defaults={:?}",
                                actual.root, actual.members, actual.default_members
                            ));
                        }
                    }
                    Err(error) => differences
                        .push(format!("{name}: Cargo accepted; SweepX returned {error:?}")),
                }
            }
            101 => {
                rejections += 1;
                assert!(cargo["stderr"].as_str().unwrap().contains("error:"));
                // The controlled tree has known absence and no unreadable/linked/native inputs.
                // An unavailable/unsupported/budget result cannot stand in for Cargo rejection.
                if !matches!(&actual, Err(WorkspaceError::Invalid(_))) {
                    differences.push(format!(
                        "{name}: Cargo rejected; expected Invalid, got {actual:?}"
                    ));
                }
            }
            status => panic!("unexpected Cargo status {status} for {name}"),
        }
    }
    assert_eq!((successes, rejections), (40, 13));
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}
