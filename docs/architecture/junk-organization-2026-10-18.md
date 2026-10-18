# Layered cleanup results and scan scopes — 2026-10-18

## Scope

Regular cleanup is the no-root `junk` default, also spelled `--regular` or `--system`.
It discovers supported platform cache roots. Deep cleanup (`--deep`) traverses the system
root with both project and platform rules; explicit roots keep their previous project-only
contract. Every CLI junk TUI scope uses one pass plus manual refresh; notifications cannot
restart a completed result while the user reviews it. Native listeners remain opt-in Core API
capabilities. macOS System/Data admission, no-follow traversal, other-volume exclusions and all
queue, handle and traversal-count bounds remain unchanged. Deep cleanup is not a claim to read every attached disk.

Exact tool/browser cache rules now compare their captured native directory at any traversal
depth, rather than only at depth zero. Generic direct-child/named-descendant rules bind depth
to a current native cache anchor; a shallow directory under an unrelated disk root cannot match.
Identity mismatches reject before expensive full-lineage/path reconstruction. Matching still
requires the complete validated locator, native path, object, filesystem, mount and fingerprint.
Regular discovery reuses these same native anchor observations.

## Presentation and operation contracts

Core's organization projection maps admitted rule IDs to stable categories and application/tool
or source-location groups. Unknown rules remain separate review. A source-directory basename
is not an application ownership claim; same-named projects retain different full-location keys.
JSON adds `scanMode` and per-candidate `organization` without renaming existing machine fields.
Coverage metadata exposes traversal termination, resource exhaustion and retained boundary
counts/examples without claiming exhaustive boundary retention. Human reports summarize categories and sources; `--details` retains path/evidence output.

The junk TUI starts at categories, then sources, then outer candidates and their captured
nested candidates. It joins scan identities and ancestor identities, never display-path prefixes,
to suppress overlap. Descendants inherit the outer candidate's accounting group. Only changed
rows/navigation rebuild the bounded projection; progress does not force rebuilding it. Group
membership is bounded by the existing row retention, and navigation is limited to 64 levels.

Fresh native measurements can appear as lower bounds while interpretation is pending, and
remain lower bounds if the revision ends partial. Cached/invalidated rows stay unknown; neither
base-size display nor partial completion grants selection or cleanup authority.
Current logical amounts remain distinct from lower bounds and unknown/historical amounts.
Group totals never claim physical reclamation. Selection is bounded to 256 native candidate
keys. Oversized selections fail atomically. Report-only, historical and incomplete candidates
are excluded; eligible nested candidates can still be selected when their outer row is restricted.
Deselecting a child of a selected ancestor replaces whole-directory selection with independently
admitted eligible siblings only, never arbitrary unclassified remainder.

Trash first displays the exact selected paths and logical total. Confirmation is a separate
keystroke. Revision changes, candidate replacements, removals and invalidations discard the
preview; the existing provider still independently checks the current native identities,
coverage and execution restrictions. No grouping label is execution authority. File inspection
remains read-only, and arbitrary inspector marks remain review paths. Linux temporary objects
retain their independent quarantine plan and full-digest confirmation.

The header distinguishes regular/deep/custom scope, scan phase, outcome, observations and issue
count. The issue panel groups structured reasons with counters and at most three bounded examples
per kind. Normal symlink exclusions do not become coverage failures or overwrite action feedback. Diagnostic events do not
rebuild candidate groups. Permission/resource failures and
cancelled scans do not turn empty results into a claim that no junk exists.

## Cache and live validation

The current default junk paths do not use historical candidate rows or a file-length index to
skip fresh traversal. Historical preview, current rule/tool interpretation, native scan facts and
cleanup authorization remain distinct. A warm OS cache or early preview is not a SweepX subtree
cache hit. A native deep TUI run exposed a separate presentation limit: its 64 MiB estimate exhausted at
3,293 rows and cancelled the worker after 74.3 seconds. Deep mode now uses a consistent,
bounded 256 MiB candidate estimate in the worker, bridge and view, leaving the 16,384-row cap
and traversal-count/queue limits intact. This accommodates native ancestor evidence and a retained
prior generation during refresh. These are conservative retention estimates, not RSS guarantees.
Deep candidate retention exhaustion now stops admitting new rows while allowing the bounded
read-only traversal to finish. The bridge no longer cancels a deep worker because its view is full.
One explicit resource error marks coverage incomplete; neither replacement nor complete cache
publication is permitted. Later interpretation growth also returns partial without granting authority.
Regular/custom sessions retain their prior cancellation/failure behavior. A controlled 12-project
fixture with a one-candidate limit verified all payload paths were observed, one row retained and
an explicit partial terminal emitted. Retention exhaustion reports its cause after the terminal
event and never grants cleanup authority. Regular/custom sessions retain the 64 MiB candidate default. Classified junk scans now allow
one root to use the existing shared 256 MiB metadata budget (previously 128 MiB per root within
that same global limit). A second native TUI run continued traversal but stopped adding candidates
at 7,502; the per-root classified metadata ceiling explained this separate truncation. Increasing
this per-root share does not remove or increase the scanner's global metadata ceiling.
A disk larger than these budgets still reports partial/resource-limited results.

### Native observations

Measurements are from 2026-10-18, macOS arm64, Rust 1.98.0 release builds, one run per workload.
Each used a new private SweepX state directory; OS caches were not cleared. Other than the
explicitly sandboxed baseline, live scans ran with native user filesystem access. Builds/tests and
some scans overlapped, so these are completion/coverage observations, not comparative benchmarks.
No user files were cleaned.

- Baseline `junk /` (project rules only, Codex filesystem sandbox): 505.2 seconds; 4,747 candidates, partial. Sampling
  showed native traversal rather than a cache wait.
- Regular default `junk --timings`: 44.6 seconds; 203 candidates across 83 discovered roots;
  traversal finished, no cancellation/resource limit or traversal errors. Partial coverage
  included a different-filesystem boundary and unavailable npm discovery. Retained boundaries:
  1,095 symlinks and one different filesystem. Categories: 121 application, 53 browser,
  13 developer tool, 16 review rows.
- Intermediate `junk --deep --timings`: 600.7 seconds, 4,416 candidates, partial. Traversal
  finished without cancellation, but resource exhaustion and 303 errors were reported;
  the capped boundary log is not exhaustive. Traversal took 596.7 seconds, cache writing
  1.8 milliseconds, root cache hits zero. This run preceded the cheaper native-identity
  mismatch rejection. It establishes termination, not complete disk coverage.
- Intermediate TUI with the original per-root metadata share: 603.6 seconds, 7,673,138 observed
  entries, 7,502 candidates, exit 4 / partial. It reached Git interpretation and terminated after
  traversal, establishing that the long disk walk itself finished without a timer cutoff.
- Earlier deep TUI engine acceptance (before continuing after retention exhaustion and the
  display-only base-size adjustment;
  `junk --deep --tui`, release SHA-256
  `c864ca6fb501dc708bb040ca3b6155c38183ec41994e4d3d33e1a49e984aa5a0`): 206.7 seconds,
  13,167 retained candidates and 2,558,396 observed entries at termination. Exit 4, **partial**:
  the bridge's 256 MiB candidate estimate exhausted and cooperatively stopped traversal.
  The issue view retained this cause alongside a wide build-directory byte-cap exclusion and
  other volume/special-entry boundaries. This is **not** completed whole-disk coverage on this
  host. No cache hang or 90-second cutoff occurred. Further scaling needs compact/paged native
  candidate evidence or smaller explicit roots; merely enlarging every limit is not established
  as a complete solution. No candidate was selected or cleaned.
- Final bounded deep TUI (`junk --deep --tui`, release SHA-256
  `0345a98041bf6e6c1dd253dcfc38cb6ac99b868bd65ee88d0058190aa9fc2511`): 529.2 seconds,
  7,673,284 observed entries and 13,418 retained candidates. Traversal reached Git interpretation
  after the candidate limit, then exited 4 / **partial**, without cancellation or cleanup.
  The final view preserved the retention-limit cause; project/tool totals remained lower bounds.
  Classified metadata and a wide-directory byte limit still truncate classification/coverage,
  alongside native permission, filesystem and special-entry boundaries. This proves bounded
  traversal termination on this host, **not** a complete inventory of all disk junk or reclaimable
  space. Retained counts also depend on traversal order; no speed comparison is inferred.
- Controlled native regular TUI: category → pip → cache item, selection, exact-path preview,
  preview cancellation and read-only inspection were exercised through a PTY. Exit zero;
  the fixture payload remained unchanged. Mock-provider regressions cover confirmation dispatch,
  invalidated previews, nested selection, overlapping totals and selection bounds.

### Automated verification

The affected CLI suite passed 76 unit tests and integrations (3 browser, 78 CLI contract,
1 elevation, 7 pnpm; 4 opt-in native pnpm cases ignored). Core's full native run passed 419
and ignored 3, with one FSEvents startup-handshake timeout after five seconds. The same
listener test passed alone in 0.78 seconds after the overlapping command-line disk scan ended;
the final focused junk run reproduced this startup timeout under overlapping disk scans
(209 passed, 1 failed, 3 ignored). This remains an unresolved native listener validation gap,
not a claimed fix or fully green suite. Both failures occurred before the test's mailbox
assertions; the test was preserved. Native authority, deep classification and platform-anchor
regressions passed. Native platform/scanner coverage passed 104/133 unit tests plus 2
System/Data and 3 wide-cache integrations; two opt-in cases remained ignored across these suites.

TUI passed 124 tests, including expected-exclusion/error separation; the final bridge suite
passed 8 tests. Host and desktop Linux/Windows cross-target workspace Clippy cover all targets/features with
warnings denied. Cross-compilation does not establish Windows/Linux runtime behavior.


Commands with the unresolved native listener result:

```sh
cargo test -p sweepx-core -p sweepx-cli -p sweepx-tui --all-targets --all-features -- --test-threads=1
cargo test -p sweepx-core junk:: -- --test-threads=1
```

The earlier combined run stopped after core's failure; TUI and bridge suites were then run
separately. After adding bounded deep traversal continuation, the required final affected matrix
passed: core 421 (+ 3 ignored), CLI 76 plus its integrations, native authority 2, and TUI 124.
The listener also passed in that final matrix. This does not establish that the two earlier
startup timeouts are fixed; no listener implementation was changed. No test was removed,
newly ignored or changed to conceal that intermittent failure.


## Interaction correction after real regular-scan reproduction

A native regular TUI reproduction navigated categories during scanning, but the first terminal
was immediately followed by another discovery revision due to cache notifications. Enter on a
leaf was ignored while busy, and a global partial result prevented read-only inspection. The
CLI now performs one pass for every scope. Inspection delegates fresh native bindings during
scanning and after a partial terminal to the independent read-only detail worker; the reliable
mailbox provides backpressure while inspecting. Idle sessions retain the existing admission
lease. Cleanup continues to require fresh complete eligible rows and native revalidation.

When a completed outer candidate absorbs a group that the user entered, the bounded navigation
stack now returns to the nearest populated parent instead of retaining an empty unreachable
location. Busy/unavailable selection reports the action that is available. Implementation notes
about duplicate accounting and reclaimed bytes have been removed from the result footer.

The vague npm discovery failure was reproduced as an attempted read of
`versions/node/.DS_Store/bin/npm`: manager inventory appended an executable suffix to every
entry without checking its type. Ordinary files in version roots are now ignored; directory
links are independently observed. Genuine iterator/metadata or required-probe failures still report partial and
retain a bounded first location/error. A regular file under a version root is not an installation.
Special-file exclusions such as an application IPC socket are explained separately from volume
boundaries. The machine partial state is preserved; the UI distinguishes expected exclusions
from locations that could not be checked. A targeted recheck invokes only the selected platform
rules, while retaining the current native binding and cleanup guards.

The live machine also had an unconfigured OSDK Node shim on PATH. `/opt/homebrew/bin/npm
config get cache` exited 1 because its env-based launcher found that shim. Inventory probes
now prefer an executable sibling Node in the same npm installation, changing only the child
PATH. A controlled env-shebang fixture with deliberately invalid JavaScript and a matching
sibling runtime verifies that the ambient Node cannot be substituted. Probe deadlines,
filesystem-operation counts and retained-data bounds remain in force. Broken installations
still retain their executable, reason and exit/probe error instead of fabricating a cache root.
The read-only file view also presents file-loading states without internal scan IDs, synthetic
partial state, revision numbers or implementation disclaimers.

Selecting a fresh, policy-eligible row retained by a partial scan now requests a targeted check
instead of silently ignoring Space. The view records at most 256 pending selection keys,
selects only after a complete replacement terminal, and clears pending selection on a failed,
partial or cancelled check. This never submits Trash. Clearing selection cancels pending marking.
The targeted scope is named explicitly in the completion label, rather than implying the entire
original scan is now complete. Unsupported/report-only rows keep their restrictions.

Follow-up validation on 2026-10-18, macOS arm64, pinned Rust 1.98.0:

- Real regular-scan PTY reproduction showed a completed scan immediately entering another
  discovery revision. The fixed native interaction run exercised files during scanning and
  after partial completion, q/back navigation, the grouped reasons panel, stable completion,
  a targeted Go check, selection, exact-path cleanup preview and cancellation. User data was
  not cleaned. Current real omissions included an IPC socket and an OSDK npm shim without a
  configured npm version; neither was relabeled a completed npm observation.
- A private pip-cache fixture was changed from 33 to 999 bytes after completion. Its view stayed
  stable without an automatic refresh; manual R showed 999 bytes. Selection, preview cancellation
  and file inspection passed with the expected payload still present.
- Focused tool discovery passed 18 tests, including ordinary host files in version roots,
  explicit failure locations and matching sibling Node. Native session tests passed 33 with
  one opt-in case ignored. Final TUI tests passed 130 and cover active/partial inspection, regrouped empty
  navigation, structured reason retention, and successful/failed selection rechecks.

- The final real regular-scan interaction (50.7 seconds including intentional navigation and
  pauses, not a timing benchmark) also exercised Space on the Go row retained by partial scope.
  It automatically completed the targeted check, selected exactly one row, opened the native
  cleanup preview and cancelled it. The original full-scope omissions remained distinguishable
  from the selected-scope completion. No Trash confirmation was sent.
- Core's final native suite passed 424 tests with 3 existing opt-in cases ignored; native authority
  integrations passed 2. CLI passed 77 unit tests, browser integrations 3, CLI contracts 78
  (the additive JSON-detail assertion was corrected and rerun separately), elevation 1 and pnpm
  integrations 7 with 4 opt-in cases ignored. Earlier failure of the old read-only-inspection
  expectation was corrected to the new inspection contract, retaining mutation refusal checks.
  Host/Linux/Windows all-target, all-feature workspace Clippy and documentation checks are
  recorded with this change. Cross-target checks are compile evidence, not native runtime tests.
