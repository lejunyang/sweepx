# Shared macOS System/Data scan policy — 2026-10-15

An explicit macOS `/` scan uses one native volume-admission policy across ordinary reports,
directory browsing, junk, large-file analysis and duplicate-content analysis. The System root
and `/System/Volumes/Data` are independently admitted; auxiliary, virtual and external volumes
remain excluded. Other explicit roots keep their original mount scope. This supersedes the
size-browser-only distinction recorded in the [October 11 validation](scan-tui-volumes-2026-10-11.md)
and the original-mount-only junk observation in the [October 12 budget record](junk-root-budget-2026-10-12.md).

The shared policy does not unify every analysis contract. Ordinary size browsing may omit
deep file identities and allocation facts while streaming logical totals. Junk needs local
rule markers, candidate coverage and directory identity; duplicate analysis reads and hashes
ordinary files under its own byte and request budgets. Each retains its cancellation, queues,
handles, metadata retention and completion/error rules. Admitting Data does not remove a work
or memory limit, establish complete coverage, or prove reclaimable space.

## Native scope and alias counting

- Read the sealed System firmlink map without following links, within 64 KiB and 256
  non-overlapping mappings. Paths select native observations; matching path text never proves
  that two entrances identify the same object.
- Verify each logical entrance independently. A physical Data entrance is omitted from recursive
  contribution only after its directory identity, filesystem domain and mount match the logical
  entrance's native observation. Alias replacement or unknown identity rejects that claim.
- Count verified logical entrances once and retain ordinary-browser alias notices. Data-only
  directories contribute normally. If a logical entrance is unavailable, its physical Data
  entrance may contribute after normal admission; the logical entrance remains an exclusion.
- Deduplicate a physical entrance only when the current requested subtree scope also covers its
  verified logical entrance. Selecting only a physical Data subtree must traverse it, even when
  the captured `/` root has another logical entrance elsewhere. Root reachability alone does not
  establish that the other entrance contributes to this request.
- Keep the System root identity and mount unchanged in every captured locator. Descendants and
  ancestors carry their own native filesystem/mount evidence; Data identity is not substituted
  for the root identity.
- Reopening validates every recorded component against its own current identity and mount, then
  verifies that the object belongs to the freshly admitted root/System/Data scope. A changed,
  unknown or unadmitted component fails closed.
- macOS can reject a foreign device before opening a directory, independently of the later mount
  filter. A verified entrance uses a separate identity-bound observation: fresh no-follow metadata
  must match its captured object and filesystem before a relative open, and the opened capability
  must also match its mount. Unverified foreign-device entrances retain the pre-open refusal.

## Reading, cache and mutation boundaries

`DetailRescanner` uses the shared admitted scope for all directory modes, fixed-child
observations, file-content streams and directory revalidation. `LocatorReader` validates the
captured root and every parent component under the same scope before fixed-input reads. Newly
discovered optional configuration directories and ordinary payload files still must match the
retained parent's local filesystem and mount; this policy does not permit an arbitrary nested
mount to supply project configuration or content.

Historical junk records remain bound to the original root's platform, native identity, mount,
loaded rules and requested root scope. Candidate records retain their captured native lineage.
The cache is presentation only; unchanged System identity, an empty notification queue or a
historical Data candidate does not establish current subtree coverage. Current observations
and execution revalidation remain independent. Default junk scans still do not use a file index
or a scan-state spill; a partial/cancelled scan does not replace historical records.

Trash selection still requires complete eligible candidate evidence and independent live
binding checks immediately before the existing operating-system Trash seam. Protected roots,
project execution restrictions, provider-safe content reads, no-follow traversal and identity
changes keep their existing refusal behavior. Scanning System/Data does not approve deleting
either volume root, widen permanent-deletion contracts, or remove the existing pathname race
at the operating-system Trash API.

Root normalization remains syntactic: duplicate and nested explicit paths are removed without
canonicalizing linked ancestors. Firmlink deduplication inside a `/` scan does not imply global
deduplication of independently requested alias roots such as `/Users` and its physical Data
entrance. Cross-root identity totals and duplicate-content alias exclusion keep their existing
analysis-specific contracts; no cross-root reclaimability claim follows from the shared scope.

## Live root namespace aliases

A macOS junk session containing explicit root `/` can receive a physical
`/System/Volumes/Data/...` FSEvents dirty path for a directory whose current candidate is stored
under a logical entrance such as `/Users/...` or `/private/...`. Prefix replacement in the
physical namespace cannot safely remove the old logical row. The current watcher has no
native-verified advisory alias mapping, so it promotes these dirty paths to a full fresh
revision with `Started` scope `All`. The existing full replacement removes the prior candidates
instead of retaining logical and physical rows simultaneously as current.

`All` describes the requested scope, not completed coverage. Permission failures, cancellation
and resource limits still produce their existing partial/error states and replacement behavior.

This is a conservative scheduling fallback, not a cache hit or a claim that events prove
freshness. It rescans the original session scope and can enter unrelated sibling trees, so root
alias events can cost substantially more work than a directory-local refresh. Sessions with an
explicit Data root, project roots or other scopes that do not contain `/` keep local refresh.
The [October 7 local-refresh measurements](live-directory-refresh-validation-2026-10-07.json)
do not measure this root namespace case. Notifications remain advisory; all admitted objects,
markers and candidate bindings are freshly observed and independently revalidated as before.

## Validation

The two macOS-only `native_system_data` integration tests passed with pinned/active Rust 1.98.0
in a debug all-feature build. Private `/private/tmp` fixtures are scanned separately through their
logical and physical `/System/Volumes/Data/private/tmp` entrances with selected-subtree traversal
and captured root `/`; both assert that the candidate's native mount differs from the captured
System root. An independent ordinary no-follow walk checks exact recursive file lengths and entry
counts for each entrance. Default full detail rescan, fixed-child observation, directory binding revalidation,
`LocatorReader` marker reads and an ordinary Scanner file-content stream all use that original
cross-volume lineage. Replacing the candidate with a different directory at the same spelling
rejects both binding revalidation and marker reads, while the original fixture bytes remain intact.
No Trash move is performed. A device number alone is deliberately not used
to prove a mount boundary: this host exposes equal `std::fs` device numbers for `/` and the fixture.

Validation used pinned Rust 1.98.0 on macOS arm64:

- Platform all-target/all-feature tests: 104 unit tests passed; one opt-in timing test remained
  ignored. The native expected-directory tests use the real different-device `/dev` entrance:
  ordinary inspection excludes it, a complete matching preflight allows the relative observation,
  and changed/missing identity, mount, path, denied handle and symlink cases are refused.
- Scanner all-target/all-feature tests: 133 unit tests, two native System/Data integrations and
  three native wide-directory integrations passed; one opt-in benchmark remained ignored. The
  Linux-only fixture integration did not execute on this host. Controlled namespaces cover exact
  totals, candidate and file-observer deduplication, physical and mixed subtree selections,
  entrance type/identity changes, unknown/external mounts and cancellation at root acceptance.
- Core and CLI all-target/all-feature tests passed: Core had 414 passing unit tests and three
  ignored benchmarks before the final watcher addition; the changed session module subsequently
  passed 46 tests (two existing benchmarks ignored), and the two final physical-notification
  fallback regressions passed after the ancestor-scope correction. Unchanged Core checks were
  reused. Native authority-resource integrations passed. CLI passed 74 unit, three browser-bridge,
  78 command-contract, one elevation and seven pnpm-project tests; four opt-in native pnpm Trash
  fixtures remained ignored and are not part of this scanning change's runtime evidence.
- The initial sandbox run denied FSEvents and the existing ordinary-path Trash contract. Normal
  macOS permissions passed the full affected commands without excluding those failures. The
  Trash contract operates only on its own temporary fixture; System/Data integrations perform
  no Trash move.
- Formatting, documentation lint (71 Markdown files), diff checks and affected-crate/workspace
  all-target/all-feature host Clippy passed. Final Linux GNU and Windows GNU workspace
  all-target/all-feature Clippy with `-D warnings` also passed, including the final platform API
  and watcher regressions; cross-lint does not establish native target runtime behavior.

The installed command still links to the rebuilt release executable. A native 160-column,
32-row root junk TUI was observed for 40 seconds and then quit cooperatively. Its last captured
observation counter was 519,885; no resource-limit or mount-limit diagnostic was captured. This
counter is not an exact inventory, and the bounded run did not establish complete root coverage.
The native selected logical/physical fixtures above provide the explicit System/Data lineage
evidence. There is no whole-disk completion, reclaimability or performance claim.
