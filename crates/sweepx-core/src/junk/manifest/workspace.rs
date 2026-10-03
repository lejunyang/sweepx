//! Bounded Cargo membership/default-selection model. Sources supply current native observations;
//! declarations alone do not create filesystem, ownership, activity or execution authority.

use crate::cargo_cleaner_evidence::{
    WorkspaceDeclaration, WorkspaceDependencySource, WorkspaceManifest, WorkspacePackageVersion,
};
use glob::Pattern;
use std::path::{Path, PathBuf};

/// A known model contradiction differs from an unsupported or missing observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkspaceError {
    Invalid(&'static str),
    Unavailable(&'static str),
}
impl WorkspaceError {
    pub(super) fn from_manifest_reason(reason: &'static str) -> Self {
        match reason {
            "malformed_toml" | "duplicate_toml_key" | "conflicting_workspace_declarations" => {
                Self::Invalid(reason)
            }
            other => Self::Unavailable(other),
        }
    }
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Invalid(reason) | Self::Unavailable(reason) => reason,
        }
    }
}

/// Implementations must preserve absence/failure and complete bounded enumeration. Native
/// implementations resolve every component through their own no-follow scope, never display paths.
pub(super) trait WorkspaceSource {
    type Directory: Clone + Eq;
    fn parent(
        &mut self,
        directory: &Self::Directory,
    ) -> Result<Option<Self::Directory>, WorkspaceError>;
    fn resolve(
        &mut self,
        directory: &Self::Directory,
        path: &str,
    ) -> Result<Option<Self::Directory>, WorkspaceError>;
    fn manifest(
        &mut self,
        directory: &Self::Directory,
    ) -> Result<Option<WorkspaceManifest>, WorkspaceError>;
    fn children(&mut self, directory: &Self::Directory) -> Result<Vec<String>, WorkspaceError>;
    fn prefix(
        &mut self,
        descendant: &Self::Directory,
        origin: &Self::Directory,
        declared: &str,
    ) -> Result<bool, WorkspaceError>;
    fn contains(
        &mut self,
        descendant: &Self::Directory,
        ancestor: &Self::Directory,
    ) -> Result<bool, WorkspaceError>;
}

#[derive(Debug)]
pub(super) struct WorkspaceResolution<D> {
    pub root: D,
    pub members: Vec<D>,
    pub default_members: Vec<D>,
    pub is_workspace: bool,
}

/// Uses Cargo's membership semantics, not build/dependency resolution. Invalid inputs cannot be
/// reported as an empty workspace. Every traversal has bounded nodes, steps and glob expansion;
/// a limit returns unavailable rather than silently truncating the member/default sets.
pub(super) fn resolve_workspace<S: WorkspaceSource>(
    source: &mut S,
    project: &S::Directory,
) -> Result<WorkspaceResolution<S::Directory>, WorkspaceError> {
    let mut model = Model {
        source,
        steps: 0,
        members: Vec::new(),
    };
    let current = model.required(project)?;
    let root = model.find_root(project)?.unwrap_or_else(|| project.clone());
    let root_manifest = model.required(&root)?;
    let Some(workspace) = root_manifest.workspace.as_ref() else {
        if root != *project
            || current
                .package
                .as_ref()
                .is_some_and(|p| p.workspace.is_some())
        {
            return Err(WorkspaceError::Invalid(
                "workspace_pointer_has_no_workspace",
            ));
        }
        model.validate_version(&current, None)?;
        return Ok(WorkspaceResolution {
            root,
            members: vec![project.clone()],
            default_members: vec![project.clone()],
            is_workspace: false,
        });
    };
    let declared = model.expand(&root, workspace.members.as_deref().unwrap_or_default())?;
    for directory in &declared {
        model.add_member(directory, &root, workspace, false)?;
    }
    model.add_member(&root, &root, workspace, false)?;
    // Check every collected package independently: nested roots, wrong explicit pointers and
    // unrelated external packages cannot borrow the root's membership by path proximity alone.
    let mut names = Vec::new();
    for directory in model.members.clone() {
        let manifest = model.required(&directory)?;
        if let Some(package) = &manifest.package {
            if names.contains(&package.name) {
                return Err(WorkspaceError::Invalid("workspace_duplicate_package_name"));
            }
            names.push(package.name.clone());
        }
        if model.find_root(&directory)?.as_ref() != Some(&root) {
            return Err(WorkspaceError::Invalid("workspace_member_has_wrong_root"));
        }
    }
    if !model.members.contains(project) {
        return Err(WorkspaceError::Invalid(
            "workspace_current_package_not_member",
        ));
    }
    let mut defaults = Vec::new();
    if project == &root {
        if let Some(patterns) = &workspace.default_members {
            for directory in model.expand(&root, patterns)? {
                if model.members.contains(&directory) {
                    if !defaults.contains(&directory) {
                        defaults.push(directory);
                    }
                } else if !(declared.contains(&directory)
                    && model.excluded(&directory, &root, workspace)?)
                {
                    return Err(WorkspaceError::Invalid("workspace_default_not_member"));
                }
            }
        } else if root_manifest.package.is_some() {
            defaults.push(root.clone());
        } else {
            defaults = model.members.clone();
        }
    } else {
        // Cargo does not inspect the root's default-members selection for a member invocation.
        defaults.push(project.clone());
    }
    // Virtual workspace manifests are traversed but not packages in metadata's member lists.
    let members = model
        .members
        .iter()
        .filter_map(|d| match model.source.manifest(d) {
            Ok(Some(manifest)) if manifest.package.is_some() => Some(Ok(d.clone())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    defaults.retain(|d| members.contains(d));
    Ok(WorkspaceResolution {
        root,
        members,
        default_members: defaults,
        is_workspace: true,
    })
}

struct Model<'a, S: WorkspaceSource> {
    source: &'a mut S,
    steps: usize,
    members: Vec<S::Directory>,
}
impl<S: WorkspaceSource> Model<'_, S> {
    fn step(&mut self) -> Result<(), WorkspaceError> {
        self.steps += 1;
        if self.steps > 16_384 {
            Err(WorkspaceError::Unavailable("workspace_work_limit"))
        } else {
            Ok(())
        }
    }
    fn required(&mut self, d: &S::Directory) -> Result<WorkspaceManifest, WorkspaceError> {
        self.step()?;
        self.source
            .manifest(d)?
            .ok_or(WorkspaceError::Invalid("workspace_manifest_missing"))
    }
    fn find_root(
        &mut self,
        project: &S::Directory,
    ) -> Result<Option<S::Directory>, WorkspaceError> {
        let local = self.required(project)?;
        if local.workspace.is_some() {
            return Ok(Some(project.clone()));
        }
        if let Some(pointer) = local.package.as_ref().and_then(|p| p.workspace.as_deref()) {
            self.step()?;
            return self
                .source
                .resolve(project, pointer)?
                .map(Some)
                .ok_or(WorkspaceError::Invalid("workspace_pointer_missing"));
        }
        let mut directory = project.clone();
        for _ in 0..64 {
            self.step()?;
            let Some(parent) = self.source.parent(&directory)? else {
                return Ok(None);
            };
            if let Some(manifest) = self.source.manifest(&parent)? {
                if let Some(workspace) = &manifest.workspace {
                    if !self.excluded(project, &parent, workspace)? {
                        return Ok(Some(parent));
                    }
                } else if let Some(pointer) = manifest
                    .package
                    .as_ref()
                    .and_then(|p| p.workspace.as_deref())
                {
                    return self
                        .source
                        .resolve(&parent, pointer)?
                        .map(Some)
                        .ok_or(WorkspaceError::Invalid("workspace_pointer_missing"));
                }
            }
            directory = parent;
        }
        Err(WorkspaceError::Unavailable("workspace_ancestor_limit"))
    }
    fn excluded(
        &mut self,
        d: &S::Directory,
        root: &S::Directory,
        ws: &WorkspaceDeclaration,
    ) -> Result<bool, WorkspaceError> {
        self.step()?;
        // Cargo uses raw component prefixes here, without resolving parent components or
        // expanding glob declarations. Native sources preserve the original spelling.
        let mut excluded = false;
        for p in ws.exclude.as_deref().unwrap_or_default() {
            excluded |= self.source.prefix(d, root, p)?;
        }
        for p in ws.members.as_deref().unwrap_or_default() {
            if self.source.prefix(d, root, p)? {
                return Ok(false);
            }
        }
        Ok(excluded)
    }
    fn validate_version(
        &self,
        manifest: &WorkspaceManifest,
        ws: Option<&WorkspaceDeclaration>,
    ) -> Result<(), WorkspaceError> {
        if let Some(package) = &manifest.package
            && matches!(package.version, Some(WorkspacePackageVersion::Inherited))
            && !ws.is_some_and(|w| {
                matches!(w.package_version, Some(WorkspacePackageVersion::Literal(_)))
            })
        {
            return Err(WorkspaceError::Invalid(
                "workspace_version_inheritance_missing",
            ));
        }
        Ok(())
    }
    fn add_member(
        &mut self,
        first: &S::Directory,
        root: &S::Directory,
        ws: &WorkspaceDeclaration,
        path_dependency: bool,
    ) -> Result<(), WorkspaceError> {
        let mut pending = vec![(first.clone(), path_dependency)];
        while let Some((directory, is_dependency)) = pending.pop() {
            self.step()?;
            if self.members.contains(&directory) {
                continue;
            }
            if is_dependency
                && !self.source.contains(&directory, root)?
                && self.find_root(&directory)?.as_ref() != Some(root)
            {
                continue;
            }
            if self.excluded(&directory, root, ws)? {
                continue;
            }
            if self.members.len() >= 256 || pending.len() >= 1024 {
                return Err(WorkspaceError::Unavailable("workspace_member_limit"));
            }
            let manifest = self.required(&directory)?;
            self.validate_version(&manifest, Some(ws))?;
            self.members.push(directory.clone());
            for dependency in &manifest.dependencies {
                let (origin, path) = match &dependency.source {
                    WorkspaceDependencySource::Path(path) => (&directory, path),
                    WorkspaceDependencySource::Inherited => {
                        let inherited = ws
                            .dependencies
                            .iter()
                            .find(|d| d.name == dependency.name)
                            .ok_or(WorkspaceError::Invalid(
                                "workspace_dependency_inheritance_missing",
                            ))?;
                        match &inherited.source {
                            WorkspaceDependencySource::Path(path) => (root, path),
                            WorkspaceDependencySource::Other => continue,
                            WorkspaceDependencySource::Inherited => {
                                return Err(WorkspaceError::Invalid(
                                    "workspace_dependency_inheritance_recursive",
                                ));
                            }
                        }
                    }
                    WorkspaceDependencySource::Other => continue,
                };
                self.step()?;
                let child = self
                    .source
                    .resolve(origin, path)?
                    .ok_or(WorkspaceError::Invalid("workspace_path_dependency_missing"))?;
                if pending.len() >= 1024 {
                    return Err(WorkspaceError::Unavailable("workspace_member_limit"));
                }
                pending.push((child, true));
            }
        }
        Ok(())
    }
    fn expand(
        &mut self,
        root: &S::Directory,
        patterns: &[String],
    ) -> Result<Vec<S::Directory>, WorkspaceError> {
        let mut output = Vec::new();
        for spelling in patterns {
            self.step()?;
            Pattern::new(spelling)
                .map_err(|_| WorkspaceError::Invalid("workspace_glob_invalid"))?;
            if !spelling.contains(['*', '?', '[']) {
                let directory = self
                    .source
                    .resolve(root, spelling)?
                    .ok_or(WorkspaceError::Invalid("workspace_member_missing"))?;
                if !output.contains(&directory) {
                    if output.len() >= 256 {
                        return Err(WorkspaceError::Unavailable("workspace_member_limit"));
                    }
                    output.push(directory);
                }
                continue;
            }
            let (prefix, components) = glob_components(spelling)?;
            let start = if prefix.as_os_str().is_empty() {
                Some(root.clone())
            } else {
                self.source.resolve(
                    root,
                    prefix
                        .to_str()
                        .ok_or(WorkspaceError::Unavailable("workspace_path_encoding"))?,
                )?
            }
            .ok_or(WorkspaceError::Invalid("workspace_member_missing"))?;
            let mut pending = vec![(start, 0usize)];
            let mut visited = Vec::new();
            let mut matched_entry = false;
            while let Some((directory, index)) = pending.pop() {
                self.step()?;
                if visited.contains(&(directory.clone(), index)) {
                    continue;
                }
                if visited.len() >= 4096 {
                    return Err(WorkspaceError::Unavailable("workspace_glob_limit"));
                }
                visited.push((directory.clone(), index));
                if index == components.len() {
                    matched_entry = true;
                    if !output.contains(&directory) {
                        if output.len() >= 256 {
                            return Err(WorkspaceError::Unavailable("workspace_member_limit"));
                        }
                        output.push(directory);
                    }
                    continue;
                }
                let component = &components[index];
                if !component.contains(['*', '?', '[']) {
                    if let Some(child) = self.source.resolve(&directory, component)? {
                        pending.push((child, index + 1));
                    }
                    continue;
                }
                if component == "**" {
                    if pending.len() >= 4096 {
                        return Err(WorkspaceError::Unavailable("workspace_glob_limit"));
                    }
                    pending.push((directory.clone(), index + 1));
                }
                let pattern = Pattern::new(component)
                    .map_err(|_| WorkspaceError::Invalid("workspace_glob_invalid"))?;
                for name in self.source.children(&directory)? {
                    self.step()?;
                    if !pattern.matches(&name) {
                        continue;
                    }
                    if index + 1 == components.len() {
                        matched_entry = true;
                    }
                    if let Some(child) = self.source.resolve(&directory, &name)? {
                        if pending.len() >= 4096 {
                            return Err(WorkspaceError::Unavailable("workspace_glob_limit"));
                        }
                        pending.push((child, if component == "**" { index } else { index + 1 }));
                    }
                }
            }
            if !matched_entry {
                // Cargo preserves an unmatched original path, which then fails as a member.
                return Err(WorkspaceError::Invalid("workspace_member_missing"));
            }
            if output.len() > 256 {
                return Err(WorkspaceError::Unavailable("workspace_member_limit"));
            }
        }
        Ok(output)
    }
}
// Split before the first wildcard, keeping an absolute prefix and any parent components.
// Enumeration stays in WorkspaceSource; glob::Pattern never performs filesystem I/O.
fn glob_components(value: &str) -> Result<(PathBuf, Vec<String>), WorkspaceError> {
    let mut prefix = PathBuf::new();
    let mut patterns = Vec::new();
    let mut wildcard = false;
    for component in Path::new(value).components() {
        let spelling = component
            .as_os_str()
            .to_str()
            .ok_or(WorkspaceError::Unavailable("workspace_path_encoding"))?;
        wildcard |= spelling.contains(['*', '?', '[']);
        if wildcard {
            patterns.push(spelling.to_owned());
        } else {
            prefix.push(component);
        }
    }
    Ok((prefix, patterns))
}

#[cfg(test)]
#[path = "workspace_oracle_tests.rs"]
mod tests;
