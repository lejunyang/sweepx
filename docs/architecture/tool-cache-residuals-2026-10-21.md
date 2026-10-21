# Tool configuration and residual cache recognition — 2026-10-21

This supersedes the tool-query coverage semantics in [discovery and history](discovery-and-history-2026-10-21.md). A present but unconfigured version-manager shim cannot invalidate independently observed cache contents. Queries still have deadlines, cancellation and invocation-local deduplication; filesystem traversal has no absolute elapsed-time cutoff.

## Current filesystem facts and supplementary configuration

`PlatformJunkEvidence::discovery_incomplete()` describes required native layout observations. Failed optional tool/configuration queries and incomplete npm installation inventory remain diagnostics, emitted as `ToolQueryWarning` rather than session errors. They do not mark a completed native scan partial, prohibit a targeted cache recheck or block eligible cleanup. Permission, layout, resource and traversal gaps retain their existing coverage effects. JSON keeps `npmDiscovery.complete` and `toolQueryFailures`, adding `toolQueriesRequiredForScan: false`. A complete filesystem report can therefore coexist with an incomplete supplementary npm inventory.

All successful concrete npm installations contribute configuration answers even when PATH resolves to a failed shim. A different answer cannot prove another cache is unused: recognized locations are `live` when named by a current successful answer and otherwise `unknown`. The legacy `stale` machine value remains compatible but is no longer inferred from a mismatch. A partial discovery context still cannot certify legacy cached classifications. Default product history remains presentation-only; none of this enables whole-subtree skipping or turns cached rows into deletion authority.

Regular scans combine defaults, absolute environment hints and successful configuration answers. pnpm location hints are shared with its independent inventory and include conventional legacy paths; pip includes platform and XDG cache defaults. The dedicated npx command reads `NPM_CONFIG_CACHE` or the platform default without launching npm. Missing declared pnpm stores remain reference issues; optional query failure does not erase stores found from declarations or native layouts.

## One structural evaluator

The scanner supplies identity-keyed ordinary directory markers separately from ordinary file markers. Links and same-named files cannot satisfy a directory requirement. The existing retained-metadata budget applies; local marker sets are released after complete postorder closure. Shared core classification consumes those facts without filesystem I/O in the classifier or a second traversal implementation.

Deep scans can recognize supported layouts in unconfigured/archived positions: npm `_cacache` with `content-v2` and `index-v5` directories, pip wheel/HTTP cache layouts and pnpm versioned CAS shards. These are format/location observations, never proof of abandonment. A path already captured by layout discovery cannot inherit a structural fallback after native replacement.

npm adds three categories to the existing download-cache rule:

| Rule | Evidence and action |
| --- | --- |
| `tool.npm-cache` | Supported content-addressable download-cache directories; current coverage and native Trash guards remain required. |
| `tool.npm-logs` | Cache-context `_logs`; every direct entry must be verified npm diagnostic content before directory cleanup is enabled. |
| `tool.npm-npx` | Hex installation slot with ordinary manifests and `node_modules`; uses the existing `npx-cache` package/version inventory and whole-slot workflow. Blanket junk Trash is blocked. |
| `tool.npm-other-data` | Other directories within observed npm cache context; review-only. Old names and third-party binary downloads alone do not establish disposability. |

pnpm remains subject to its independent index/project-reference/link accounting. Deep structural recognition cannot bypass that inventory.

## Log and execution checks

Log verification uses the existing native detail/content adapter. It checks no-follow direct entries and bounded prefixes of npm timestamped debug logs, rotations with a matching initial log, and dependency-resolution reports. Timing JSON requires a complete document with npm timing metadata. Resolution reports accept npm's diagnostic-path wrapper; paths inside the report are never reopened. An ordinary Finder `.DS_Store` may accompany logs. Scanner identity/type/length fingerprints do not encode a directory listing: a second bounded native enumeration must have the same native names, types and fingerprints as the first. A controlled insertion regression verifies that identity-only revalidation cannot substitute for this comparison. Unrecognized, mixed, linked, changed, cancelled or over-budget content leaves the row report-only.

Limits are 2,048 files and 8 MiB of requested reads per verification session, 1,024 direct entries / 16 MiB enumeration byte budget per listing, 4 KiB prefixes for debug/resolution files and a complete timing document within 64 KiB. Limits are charged even for failed reads. Native OS calls retain their existing cooperative cancellation boundary.

Both interactive and bulk cleanup call the same rule-kind-aware log guard immediately before Trash: repeat content/native checks and current-user process/open-file checks. Editable rule IDs cannot bypass it. The existing final native identity checks and OS Trash operation remain; a process observation is not an exclusive lock and the final pathname race is unchanged.

A related execution regression refused a cache solely because it was the scan root. Executable root locators now decode to the bound absolute root path without appending the basename. Protected filesystem/home/state/Trash roots are still refused. Capture checks the selected native identity on Unix and Windows, and replacement is rejected before submission. Display paths do not participate.

## Sources

- [npm cache documentation](https://docs.npmjs.com/cli/v11/commands/npm-cache/).
- [npm logging documentation](https://docs.npmjs.com/cli/v11/using-npm/logging/).
- [npm exec documentation](https://docs.npmjs.com/cli/v11/commands/npm-exec/).
- [pnpm store documentation](https://pnpm.io/cli/store).
- The installed official npm implementation was checked for diagnostic formats: `lib/utils/log-file.js`, `lib/utils/timers.js`, `lib/utils/explain-eresolve.js`, `lib/utils/error-message.js` and `lib/npm.js`. Fixtures include its wrapped resolution-report framing; file contents and diagnostic paths are not retained in reports.

## Validation and boundaries

Validation used Rust 1.98.0 on an arm64 macOS host on 2026-10-21. Full workspace tests were started under normal native permissions. One CLI test assumed removing npm from PATH made every configuration answer unavailable; a concrete Homebrew installation disproved it. The fixture now supplies an explicitly different configuration location and pins `unknown`, rather than abandonment. Its corrected suite passes. Already passing crates were retained and the remaining workspace tests resumed. A new scan-root regression first reproduced `InvalidPath`, then passed with the native root-path fix. Initial sandbox-only FSEvents failures were preserved and passed under normal native permissions.

Final affected counts: Core 438 unit tests plus 2 native-resource tests; CLI 78 unit tests plus 90 integration tests; scanner 133 unit tests plus 5 native tests; TUI 141 tests; catalog 30 tests. Five existing opt-in benchmarks and four existing native pnpm-cleanup tests remain ignored. Other workspace tests and documentation tests passed. The final resolution-report, directory-listing and compact-marker refinements were followed by focused native-layout/CLI tests and the core junk suite; earlier passing unchanged tests were reused. No excluded test is presented as passed.

Host, desktop Linux GNU and Windows GNU workspace/all-target/all-feature Clippy, formatting and both-language documentation build are checked. Cross-target lint is compilation/static evidence, not Linux/Windows runtime acceptance.

A controlled native PTY run used failed npm/pnpm/pip shims and only task-owned temporary download/log caches. Completion, supplementary reasons, targeted recheck, selection, navigation, preview/cancel, confirmed native Trash and exit were exercised. An independent check found both original directory identities and payloads in native Trash; an unselected notes directory remained intact. The read-only real-host report retained the actual OSDK npm/pnpm failures while completing current native coverage and separating download caches, logs, npx slots and review-only residuals. A real-host PTY run also selected downloads/logs, explicitly refreshed the selection and previewed/cancelled cleanup. Its initial harness waited for “Complete” instead of the actual selected-refresh terminal label; that harness predicate was corrected, with the product already showing “Selected items checked”. No user cache was cleaned. This does not establish whole-disk completeness or iTerm2 renderer acceptance.

[Portable acceptance record](tool-cache-residuals-2026-10-21.json). Raw terminal captures and host-specific diagnostic output are retained locally rather than committed.
