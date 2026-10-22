# Interactive cleanup improvements (2026-10-22)

## Discovery and completion

Known native layouts are scanned while one optional tool-discovery worker runs. A process-wide four-worker permit also bounds detached discovery tasks. Probes retain their independent deadlines, cancellation and output limits. There is no total 90-second scan deadline. Native OS calls remain cooperative.

One revision emits one Started and one Completed. The first pass publishes candidates but defers the terminal event; the supplementary pass uses a distinct scan identity and reopens only additional admitted scopes. Known-root tool activity is updated without replacing filesystem, format or Git evidence. Query failure is a warning. Native layout failures remain coverage failures. Root expansion and ancestors retain explicit invalidations; old presentation never grants cleanup authority.

## Nested cleanup

The TUI embeds an independent provider in the same terminal/event loop. A scan-admission lease survives the modal. npx inventories and native manifests use the existing core implementation; both CLI and TUI share the same activity, manifest and native-Trash function. pnpm uses the existing bounded inventory/reference/ownership accounting and cleanup service. Items require explicit selection and a cancellable confirmation preview. Returning requests a parent-directory refresh so deleted npx slots can disappear without validating the now-missing slot as an executable target.

Ordinary details explain purpose and next action. Machine fields remain available to diagnostic/API consumers. npm residual folders remain review-only when their contents do not establish cleanup eligibility.

## Incremental scope and coverage

The interactive browser retains bounded native change notifications but does not launch automatic refreshes. `f` explicitly consumes delivered changes and reobserves affected subtrees; missing/empty/gapped history, unavailable watchers or changed roots fall back to a complete scan. Events racing with a scan are retained for the next request. Scope expansion records a gap before further reuse. Physical System/Data aliases preserve the existing full-root fallback.

This is session-local incremental refresh, not persistent whole-subtree replay. An empty FSEvents history cannot prove that recent writes reached the journal. On restart, disk history remains historical first paint and current native enumeration is required. Untouched local-refresh rows retain their previous observation; native execution revalidation is never skipped. Candidate classification and environmental facts are not persisted as current.

Coverage locations are bounded to 256 rows; native root completion and exact boundary locations are separate from result completeness. Opaque provider keys retain lossless native retry paths privately; displayed strings do not authorize reopening or deletion. `e` lists locations; Enter rechecks one scope; `i` retains grouped reasons. A partial/local check is not a whole-disk completion claim.

## Validation

Host: macOS 26.5.2 (25F84), arm64, pinned Rust 1.98.0. Baseline: `a975956`. These are functional checks on 2026-10-22, not performance benchmarks.

The [machine-readable acceptance record](interactive-cleanup-evidence-2026-10-22.json) contains the fixture outcomes, build identity and validation boundaries without user filesystem contents.

- Workspace tests passed, followed by focused checks for the final child-worker lease and cross-phase candidate-digest assertions. The workspace run includes 442 passing core tests and 144 passing TUI tests; the final CLI junk-TUI check passed all 12 selected tests. Five existing opt-in benchmarks were not run.
- Workspace all-target/all-feature Clippy and formatting passed. Linux GNU and Windows GNU workspace cross-target Clippy passed using the real Zig C toolchain; these are compile/lint checks, not Linux or Windows runtime acceptance. The last subsequent changes were a human-readable CLI sentence and a host-independent test assertion.
- Both site languages built successfully with VitePress. The shell's unselected OSDK Node shim was bypassed using the already installed Node executable; no project toolchain pin changed.
- Native PTY acceptance used fresh npx and pnpm fixtures and the optimized binary. Known rows appeared before deliberately delayed failing tool queries. Package browsing, selection preview, cancellation, return refresh, individual-location retry, changed-scope refresh and normal exit passed. The npx acceptance moved only its own old-version fixture; independent device/inode checks found it in native Trash and preserved the newer sibling. The pnpm interactive acceptance cancelled its preview without moving data.
- The four opt-in macOS pnpm integration tests also passed separately with native permissions: automatic store cleanup, dependency-only retirement, whole-project retirement and preservation of another project's copy/shared store content. They used newly created temporary fixtures and checked native Trash identities. They remain opt-in in the default suite.
- The scanner and native Trash checks initially encountered sandbox permission restrictions. They were rerun with normal native permissions; no production guard or test assertion was relaxed. An initial TUI regression intercepted `e` while typing a quarantine confirmation; modal input now has priority and the quarantine regressions pass. A first npx harness fixture lacked its required lockfile; the fixture was corrected without relaxing the shipped rule.

Private raw terminal and fixture evidence is under `/private/tmp/sweepx-interactive-20261022/`; `final-release/result.json` records the controlled terminal checks. Native PTY verifies application input handling but does not verify the iTerm2 renderer. No user cache was moved or deleted.

The installed command links to the rebuilt optimized binary. Its final SHA-256 is `8002be8fe04e48eb36127636fca4f26803ab72bb57e4b9f4fc6df83cb277018c`.

### Whole-disk observation

The final optimized binary completed a native read-only deep TUI run in 713.49 seconds. The main pass observed 7,956,023 entries; the final view contained 13,470 candidates and correctly reported **Finished with omissions**, exiting with status 4 after `q`. Coverage navigation worked during the scan; after completion, `e`, `i`, Escape and `q` opened the coverage/reasons views and exited normally. The recorded progress count is not a unique-object total or a claim of complete whole-disk coverage.

The final details separated actual omissions from exclusions and optional notifications:

- Three capacity records: the retained boundary cap was exceeded; the repository's very wide `target/debug/deps` directory exceeded native enumeration retention; and `/` exhausted the classified-metadata budget (256 MiB in this configuration). This work does not implement disk spilling for these live scan structures. Increasing the elapsed-time allowance or reading historical candidates cannot remove these limits.
- 310 observation failures were reported; the retained examples were `StrictReadOnly` failures. This is a native observation restriction, not an npm query timeout. These entries remain unchecked.
- Eight other-volume/filesystem exclusions and 518 special-file exclusions were shown separately, including application sockets. They do not establish that ordinary cache files were missed.
- Two optional query failures (`pnpm store path` and `npm config get cache`) were listed as optional notifications, separate from the two categories affecting file-read completeness. Neither ended the known-location scan.

The final run used a fresh SweepX state directory; OS cache state was uncontrolled. An earlier development-binary observation also finished with omissions, but its harness initially expected the wrong English terminal label and stayed open after completion; that harness was stopped after observing completion, corrected, and replaced by the final optimized run above. The earlier development run had concurrent build/tests and predates final UI/lease refinements. These runs are not equivalent-workload performance samples and establish no speedup, percentile or warm-cache claim. Raw final captures are `deep-release/deep-complete.txt`, `deep-coverage.txt`, `deep-reasons.txt` and `deep-result.json` below the private evidence directory.
