//! Controlled structural fixtures and separately attributed SDK execution recordings.
//!
//! Dart package-config layouts: https://dart.dev/tools/pub/cmd/pub-get and
//! https://dart.dev/tools/pub/workspaces (workspaces introduced in 3.6).
//! SvelteKit 1.0/2.0 sync writes: tagged `packages/kit/src/core/sync` sources at
//! https://github.com/sveltejs/kit. Version 3 moved configuration and generated type files;
//! https://svelte.dev/docs/kit/project-structure documents the current project layout.
//! The authored Dart/SvelteKit cases below are not SDK execution recordings or complete
//! TypeScript grammar fixtures. Actual recordings live in the separately attributed module.

/// Actual version-pinned SDK recordings, kept separate from authored structural cases below.
pub mod recordings;

use std::path::{Path, PathBuf};

/// Independently authored default-output signature from the SvelteKit 1.0.0 sync source.
/// This is not an SDK execution recording and is not derived from the production parser.
pub const SVELTEKIT1_CONFIG: &str = r#"{"compilerOptions":{"baseUrl":"..","paths":{},"rootDirs":["..","./types"],"isolatedModules":true,"importsNotUsedAsValues":"error","preserveValueImports":true,"moduleResolution":"node","module":"esnext","target":"esnext"},"include":["ambient.d.ts","./types/**/$types.d.ts","../src/**/*.svelte"],"exclude":["../node_modules/**","./[!ambient.d.ts]**"]}"#;

/// Independently authored default-output signature from the SvelteKit 2.0.0 sync source.
pub const SVELTEKIT2_CONFIG: &str = r#"{"compilerOptions":{"paths":{},"rootDirs":["..","./types"],"isolatedModules":true,"verbatimModuleSyntax":true,"noEmit":true,"moduleResolution":"bundler","module":"esnext","target":"esnext"},"include":["ambient.d.ts","non-ambient.d.ts","./types/**/$types.d.ts","../src/**/*.svelte"],"exclude":["../node_modules/**"]}"#;

/// Minimal generated ambient signatures from both legacy source layouts, without real env values.
/// Recognition of these strings is not proof of TypeScript correctness or exclusive ownership.
pub const SVELTEKIT_AMBIENT: &str = "\n// this file is generated — do not edit it\n\n/// <reference types=\"@sveltejs/kit\" />\n\ndeclare module '$env/static/private' {\n}\ndeclare module '$env/static/public' {\n}\ndeclare module '$env/dynamic/private' {\n}\ndeclare module '$env/dynamic/public' {\n}\n";

/// One independently authored layout with exact expected candidate paths and rule IDs.
pub struct ProjectJunkLayoutCase {
    /// Unique fixture directory component.
    pub id: &'static str,
    /// Source version/layout represented; this does not assert that a tool was executed.
    pub version: &'static str,
    /// Relative paths and payloads of ordinary files to create.
    pub files: &'static [(&'static str, &'static str)],
    /// Relative empty directories (including same-named-file counterexamples).
    pub directories: &'static [&'static str],
    /// Expected relative candidate paths and stable machine rule IDs.
    pub candidates: &'static [(&'static str, &'static str)],
}

/// Positive versions and deliberately misplaced, incomplete and user-data layouts.
/// Expectations are independent of the production catalog; do not derive them from loaded rules.
pub const CASES: &[ProjectJunkLayoutCase] = &[
    ProjectJunkLayoutCase {
        id: "dart-standalone",
        version: "Dart 2.18 package-config layout",
        files: &[
            ("pubspec.yaml", "name: example\n"),
            ("pubspec.lock", "packages: {}\n"),
            (
                ".dart_tool/package_config.json",
                r#"{"configVersion":2,"packages":[{"name":"example","rootUri":"../","packageUri":"lib/","languageVersion":"2.18"}],"generator":"pub","generatorVersion":"2.18.0"}"#,
            ),
            ("lib/example.dart", "void main() {}"),
        ],
        directories: &[],
        candidates: &[(".dart_tool", "dart.tool-state")],
    },
    ProjectJunkLayoutCase {
        id: "dart-workspace",
        version: "Dart 3.6 workspace root",
        files: &[
            ("pubspec.yaml", "name: workspace\nworkspace: [packages/a]\n"),
            (
                ".dart_tool/package_config.json",
                r#"{"configVersion":2,"packages":[{"name":"workspace","rootUri":"../","packageUri":"lib/","languageVersion":"3.6"},{"name":"a","rootUri":"../packages/a","packageUri":"lib/","languageVersion":"3.6"}],"generator":"pub","generatorVersion":"3.6.0"}"#,
            ),
            (
                "packages/a/pubspec.yaml",
                "name: a\nresolution: workspace\n",
            ),
            ("packages/a/.dart_tool/notes", "user data"),
        ],
        directories: &[],
        candidates: &[(".dart_tool", "dart.tool-state")],
    },
    ProjectJunkLayoutCase {
        id: "sveltekit-1",
        version: "SvelteKit 1.0.0 default sync output",
        files: &[
            ("svelte.config.js", "export default {}"),
            (".svelte-kit/tsconfig.json", SVELTEKIT1_CONFIG),
            (".svelte-kit/ambient.d.ts", SVELTEKIT_AMBIENT),
            ("src/routes/+page.svelte", "<p>source</p>"),
        ],
        directories: &[],
        candidates: &[(".svelte-kit", "node.sveltekit-output")],
    },
    ProjectJunkLayoutCase {
        id: "sveltekit-2",
        version: "SvelteKit 2.0.0 default sync output",
        files: &[
            ("svelte.config.js", "export default {}"),
            (".svelte-kit/tsconfig.json", SVELTEKIT2_CONFIG),
            (".svelte-kit/ambient.d.ts", SVELTEKIT_AMBIENT),
            (".svelte-kit/non-ambient.d.ts", "export {}"),
        ],
        directories: &[],
        candidates: &[(".svelte-kit", "node.sveltekit-output")],
    },
    ProjectJunkLayoutCase {
        id: "same-named-user-data",
        version: "user directories beside project files",
        files: &[
            ("pubspec.yaml", "name: example"),
            ("svelte.config.js", "export default {}"),
            (".dart_tool/notes", "keep"),
            (".svelte-kit/photos", "keep"),
        ],
        directories: &[],
        candidates: &[],
    },
    ProjectJunkLayoutCase {
        id: "misplaced-markers",
        version: "own markers in parent/sibling, parent marker in candidate",
        files: &[
            ("pubspec.yaml", "name: example"),
            ("package_config.json", "{}"),
            ("sibling/package_config.json", "{}"),
            (".dart_tool/notes", "keep"),
            (".svelte-kit/svelte.config.js", "export default {}"),
            (".svelte-kit/tsconfig.json", "{}"),
            (".svelte-kit/ambient.d.ts", "export {}"),
        ],
        directories: &[],
        candidates: &[],
    },
    ProjectJunkLayoutCase {
        id: "directories-are-not-files",
        version: "marker names with directory type",
        files: &[
            ("pubspec.yaml", "name: example"),
            ("svelte.config.js", "export default {}"),
            (".svelte-kit/tsconfig.json", "{}"),
        ],
        directories: &[".dart_tool/package_config.json", ".svelte-kit/ambient.d.ts"],
        candidates: &[],
    },
    ProjectJunkLayoutCase {
        id: "incomplete-sveltekit",
        version: "only one of two required own markers",
        files: &[
            ("svelte.config.js", "export default {}"),
            (".svelte-kit/tsconfig.json", "{}"),
        ],
        directories: &[],
        candidates: &[],
    },
    ProjectJunkLayoutCase {
        id: "sveltekit-3",
        version: "SvelteKit 3 changed output; legacy rule must decline",
        files: &[
            ("vite.config.js", "export default {}"),
            (".svelte-kit/generated/dev/client/app.js", "export {}"),
        ],
        directories: &[],
        candidates: &[],
    },
];

/// Generates only the fixed corpus beneath the caller's isolated fixture root.
/// Returns the generated roots paired with their independent expected outcomes.
/// The caller must own a fresh isolated root without concurrent mutations. This is fixture setup,
/// not a no-follow filesystem authority API. It runs no tools, scanner or classifier.
pub fn generate(root: &Path) -> std::io::Result<Vec<(&'static ProjectJunkLayoutCase, PathBuf)>> {
    let mut generated = Vec::with_capacity(CASES.len());
    for case in CASES {
        let case_root = root.join(case.id);
        std::fs::create_dir(&case_root)?;
        for directory in case.directories {
            std::fs::create_dir_all(case_root.join(directory))?;
        }
        for (path, payload) in case.files {
            let path = case_root.join(path);
            std::fs::create_dir_all(path.parent().expect("fixed corpus has file parents"))?;
            std::fs::write(path, payload)?;
        }
        generated.push((case, case_root));
    }
    Ok(generated)
}
