//! Bounded format signatures for installable environments and generated dependency bundles.
//! These inputs are self-declared; no referenced path is opened and no restoration is promised.

use super::{ProjectContentFormat, ProjectFormatEvidence, ProjectFormatStatus, outcome};

/// Recognizes ordinary CPython/uv environment configuration without using its executable paths.
/// Missing, duplicate or unsupported signatures remain unknown rather than empty or disposable.
pub fn inspect_python_venv_config(bytes: &[u8]) -> ProjectFormatEvidence {
    let profile = ProjectContentFormat::PythonVenvConfig;
    let unknown = || {
        outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "venv_signature_unknown",
        )
    };
    if bytes.len() > 256 * 1024 {
        return unknown();
    }
    let Ok(body) = std::str::from_utf8(bytes) else {
        return unknown();
    };
    let mut fields = std::collections::BTreeMap::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let Some((key, value)) = line.split_once('=') else {
            return unknown();
        };
        if fields.insert(key.trim(), value.trim()).is_some() {
            return unknown();
        }
    }
    let version = fields.get("version").or_else(|| fields.get("version_info"));
    if !fields.get("home").is_some_and(|home| !home.is_empty())
        || !matches!(
            fields.get("include-system-site-packages"),
            Some(&"true" | &"false")
        )
        || !version.is_some_and(|value| {
            value.split('.').count() >= 2
                && value
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        return unknown();
    }
    outcome(
        profile,
        ProjectFormatStatus::Recognized,
        "venv_self_declared_configuration",
    )
}

/// Recognizes Vite prebundle metadata; dependency paths and package code are never followed.
/// Matching metadata does not establish that every file in the directory belongs to Vite.
pub fn inspect_vite_dependency_metadata(bytes: &[u8]) -> ProjectFormatEvidence {
    let profile = ProjectContentFormat::ViteDependencyMetadata;
    let unknown = || {
        outcome(
            profile,
            ProjectFormatStatus::Unknown,
            "vite_metadata_unknown",
        )
    };
    if bytes.len() > 256 * 1024 {
        return unknown();
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return unknown();
    };
    let Some(optimized) = value.get("optimized").and_then(|v| v.as_object()) else {
        return unknown();
    };
    if optimized.len() > 4096
        || !["hash", "configHash", "browserHash"].iter().all(|key| {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty() && s.len() <= 128)
        })
        || !optimized.values().all(|dependency| {
            ["src", "file"].iter().all(|key| {
                dependency
                    .get(key)
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty() && s.len() <= 4096)
            })
        })
    {
        return unknown();
    }
    outcome(
        profile,
        ProjectFormatStatus::Recognized,
        "vite_self_declared_prebundle_metadata",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_signature_does_not_accept_partial_or_duplicate_configuration() {
        for version in ["version = 3.12.14", "version_info = 3.12.14"] {
            let bytes = format!(
                "home = /does/not/exist\ninclude-system-site-packages = false\n{version}\n"
            );
            assert_eq!(
                inspect_python_venv_config(bytes.as_bytes()).status,
                ProjectFormatStatus::Recognized
            );
            assert_eq!(
                inspect_python_venv_config(format!("{bytes}home = /other\n").as_bytes()).status,
                ProjectFormatStatus::Unknown
            );
        }
        for bytes in [
            &b"home = /python\n"[..],
            b"home = /python\nversion = 3.x\ninclude-system-site-packages = false\n",
            b"personal notes",
        ] {
            assert_eq!(
                inspect_python_venv_config(bytes).status,
                ProjectFormatStatus::Unknown
            );
        }
    }

    #[test]
    fn prebundle_signature_requires_hashes_and_declared_dependency_records() {
        let mut value = serde_json::json!({"hash":"abc", "configHash":"def", "browserHash":"123", "optimized":{"vue":{"src":"/unopened/private/source", "file":"vue.js"}}});
        assert_eq!(
            inspect_vite_dependency_metadata(&serde_json::to_vec(&value).unwrap()).status,
            ProjectFormatStatus::Recognized
        );
        value["optimized"]["vue"]["file"] = serde_json::Value::Null;
        assert_eq!(
            inspect_vite_dependency_metadata(&serde_json::to_vec(&value).unwrap()).status,
            ProjectFormatStatus::Unknown
        );
        assert_eq!(
            inspect_vite_dependency_metadata(b"{}").status,
            ProjectFormatStatus::Unknown
        );
        assert_eq!(
            inspect_vite_dependency_metadata(&vec![b' '; 256 * 1024 + 1]).status,
            ProjectFormatStatus::Unknown
        );
    }
}
