//! Actual SDK execution recordings. Receipts bind raw bytes, controlled inputs and dependency
//! locks; they are evidence of format compatibility, never ownership or current tool installation.

/// One unmodified file from a controlled SvelteKit execution.
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
}
