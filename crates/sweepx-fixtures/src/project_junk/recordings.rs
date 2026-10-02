//! Actual SDK execution recordings. Receipts bind raw bytes, controlled inputs and dependency
//! locks; they are evidence of format compatibility, never ownership or current tool installation.

/// One unmodified file from a controlled SDK execution.
pub struct RecordedFile {
    /// File name in the checked-in recording and receipt.
    pub recording_name: &'static str,
    /// Relative location in the original disposable project; license/lock remain outside output.
    pub project_path: &'static str,
    /// Exact captured bytes, without newline/comment normalization.
    pub bytes: &'static [u8],
}

/// Recorded default-config output from a fixed, actually executed SvelteKit version.
pub struct SvelteKitRecording {
    /// Installed package version checked independently of the format decoder.
    pub version: &'static str,
    /// Acquisition metadata and SHA-256/length of every file in this recording.
    pub receipt: &'static str,
    /// Controlled source inputs, frozen dependency lock, generated files and upstream license.
    pub files: &'static [RecordedFile],
}

macro_rules! file {
    ($version:literal, $recording:literal, $project:literal) => {
        RecordedFile {
            recording_name: $recording,
            project_path: $project,
            bytes: include_bytes!(concat!(
                "../../resources/project-junk/sveltekit-",
                $version,
                "/",
                $recording
            )),
        }
    };
}
macro_rules! recording {
    ($version:literal) => {
        SvelteKitRecording {
            version: $version,
            receipt: include_str!(concat!(
                "../../resources/project-junk/sveltekit-",
                $version,
                "/receipt.json"
            )),
            files: &[
                file!($version, "package.json", "package.json"),
                file!($version, "svelte.config.js", "svelte.config.js"),
                file!(
                    $version,
                    "src/routes/+page.svelte",
                    "src/routes/+page.svelte"
                ),
                file!($version, "tsconfig.json", "tsconfig.json"),
                file!($version, "pnpm-lock.yaml", "pnpm-lock.yaml"),
                file!(
                    $version,
                    "generated-tsconfig.json",
                    ".svelte-kit/tsconfig.json"
                ),
                file!($version, "ambient.d.ts", ".svelte-kit/ambient.d.ts"),
                file!($version, "UPSTREAM-LICENSE", "UPSTREAM-LICENSE"),
            ],
        }
    };
}

/// Two independent, actual sync runs, using installed 1.0.0/2.0.0 packages and controlled env.
/// Tests use these recordings offline and must not substitute authored decoder-shaped examples.
pub const SVELTEKIT: &[SvelteKitRecording] = &[recording!("1.0.0"), recording!("2.0.0")];

/// Recorded offline pub output with source inputs and workspace-member counterexamples.
pub struct DartRecording {
    /// Stable controlled scenario identifier; not a scanned object's identity.
    pub case_id: &'static str,
    /// Actually executed SDK version, recorded independently of its self-declared JSON output.
    pub version: &'static str,
    /// Raw-file hashes, actual SDK revision and invocation directory.
    pub receipt: &'static str,
    /// Source inputs, generated map/lock, preserved personal notes and upstream license.
    pub files: &'static [RecordedFile],
}

macro_rules! dart_file {
    ($case:literal, $name:expr, $project:expr) => {
        RecordedFile {
            recording_name: $name,
            project_path: $project,
            bytes: include_bytes!(concat!(
                "../../resources/project-junk/dart-",
                $case,
                "/",
                $name
            )),
        }
    };
}
macro_rules! dart_standalone {
    ($version:literal, $case:literal) => {
        DartRecording {
            case_id: $case,
            version: $version,
            receipt: include_str!(concat!(
                "../../resources/project-junk/dart-",
                $case,
                "/receipt.json"
            )),
            files: &[
                dart_file!($case, "pubspec.yaml", "pubspec.yaml"),
                dart_file!($case, "lib/example.dart", "lib/example.dart"),
                dart_file!($case, "pubspec.lock", "pubspec.lock"),
                dart_file!(
                    $case,
                    "package_config.json",
                    ".dart_tool/package_config.json"
                ),
                dart_file!($case, "UPSTREAM-LICENSE", "UPSTREAM-LICENSE"),
            ],
        }
    };
}
macro_rules! dart_workspace {
    ($case:literal, $member:literal) => {
        DartRecording {
            case_id: $case,
            version: "3.6.0",
            receipt: include_str!(concat!(
                "../../resources/project-junk/dart-",
                $case,
                "/receipt.json"
            )),
            files: &[
                dart_file!($case, "pubspec.yaml", "pubspec.yaml"),
                dart_file!($case, "lib/example.dart", "lib/example.dart"),
                dart_file!(
                    $case,
                    concat!($member, "/pubspec.yaml"),
                    concat!($member, "/pubspec.yaml")
                ),
                dart_file!(
                    $case,
                    concat!($member, "/lib/example.dart"),
                    concat!($member, "/lib/example.dart")
                ),
                dart_file!($case, "packages/b/pubspec.yaml", "packages/b/pubspec.yaml"),
                dart_file!(
                    $case,
                    "packages/b/lib/example.dart",
                    "packages/b/lib/example.dart"
                ),
                dart_file!(
                    $case,
                    "member-personal-notes.txt",
                    concat!($member, "/.dart_tool/personal-notes")
                ),
                dart_file!($case, "pubspec.lock", "pubspec.lock"),
                dart_file!(
                    $case,
                    "package_config.json",
                    ".dart_tool/package_config.json"
                ),
                dart_file!($case, "UPSTREAM-LICENSE", "UPSTREAM-LICENSE"),
            ],
        }
    };
}

/// Actual standalone 2.18.0/3.6.0 and member-invoked 3.6.0 shared-workspace pub runs.
/// Unicode/space names are SDK-encoded URI data; consumers must never open those URI locations.
pub const DART: &[DartRecording] = &[
    dart_standalone!("2.18.0", "2.18.0-standalone"),
    dart_standalone!("3.6.0", "3.6.0-standalone"),
    dart_workspace!("3.6.0-workspace", "packages/a"),
    dart_workspace!("3.6.0-unicode-workspace", "packages/组件 a"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn receipts_bind_every_unmodified_input_and_generated_file() {
        for recording in SVELTEKIT {
            let receipt: serde_json::Value = serde_json::from_str(recording.receipt).unwrap();
            assert_eq!(receipt["schema"], "sweepx.generated-format-recording/v1");
            assert_eq!(receipt["tool"], "@sveltejs/kit");
            assert_eq!(receipt["version"], recording.version);
            assert_eq!(receipt["installScripts"], false);
            let files = receipt["files"].as_object().unwrap();
            assert_eq!(files.len(), recording.files.len());
            for file in recording.files {
                assert_eq!(files[file.recording_name]["bytes"], file.bytes.len());
                assert_eq!(
                    files[file.recording_name]["sha256"],
                    format!("{:x}", Sha256::digest(file.bytes))
                );
            }
            let package: serde_json::Value =
                serde_json::from_slice(recording.files[0].bytes).unwrap();
            assert_eq!(
                package["devDependencies"]["@sveltejs/kit"],
                recording.version
            );
        }
    }

    #[test]
    fn dart_receipts_bind_raw_sdk_output_and_preserved_workspace_inputs() {
        for recording in DART {
            let receipt: serde_json::Value = serde_json::from_str(recording.receipt).unwrap();
            assert_eq!(receipt["tool"], "dart pub");
            assert_eq!(receipt["version"], recording.version);
            assert_eq!(receipt["generator"], "dart pub get --offline");
            let files = receipt["files"].as_object().unwrap();
            assert_eq!(files.len(), recording.files.len());
            for file in recording.files {
                assert_eq!(files[file.recording_name]["bytes"], file.bytes.len());
                assert_eq!(
                    files[file.recording_name]["sha256"],
                    format!("{:x}", Sha256::digest(file.bytes))
                );
            }
            let config: serde_json::Value = serde_json::from_slice(
                recording
                    .files
                    .iter()
                    .find(|file| file.recording_name == "package_config.json")
                    .unwrap()
                    .bytes,
            )
            .unwrap();
            assert_eq!(config["generatorVersion"], recording.version);
            assert_eq!(
                config["packages"].as_array().unwrap().len(),
                if recording.case_id.ends_with("workspace") {
                    3
                } else {
                    1
                }
            );
        }
    }
}
