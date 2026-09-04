# MangoDisk rules not yet adopted by SweepX

Source snapshot date: 2026-08-30. Upstream commit:
`b011da813795e3221022b6b731be998a2eb2bf2f`.

SweepX has not imported any MangoDisk rule *definition*. Its current platform cache reports overlap
with some upstream locations at a coarser level, but that is not equivalent to adopting the named
rule, matcher, process policy, risk, or execution behavior. The generated
[`mangodisk-rule-source-audit.csv`](mangodisk-rule-source-audit.csv) is the exact 205-row inventory.

Three tool-cache rules (npm, pnpm, pip) were admitted on 2026-09-02, but they were written from
first-party measurement on this host rather than copied from upstream — see the batch-1 outcome
below. The coverage table describes the upstream inventory and is unchanged by that admission.

## Coverage gap

| SweepX relation | Rules | Meaning |
|---|---:|---|
| Coarse platform report fully contains every upstream root | 35 | Visible as a generic macOS cache candidate; no named-rule semantics were adopted |
| Coarse platform report contains only some upstream roots | 31 | Some bytes may be visible, but the rule is incomplete |
| Not covered | 139 | No equivalent SweepX report path exists |

The 139 uncovered rules include all Windows system categories outside packaged-app
`LocalCache`/`TempState`, almost all Windows browser/application/development rules, macOS
`Application Support` renderer caches, user temp/log rules, AI/model caches, container caches, and
specialized cleaners.

## Evidence gaps found so far

Fifteen rules have no cited reference in the pinned source. They remain research-only until an
independent source and native observation close the gap:

- Both platforms: `ai.huggingface-xet-cache`, `app.obs-diagnostic-cache`, and
  `system.stale-partial-downloads`.
- macOS: `app.dingtalk-diagnostic-cache`, `browser.arc-cache`, `browser.opera-cache`, and
  `browser.vivaldi-cache`.
- Windows: `app.douyin-live-updater-cache`, `app.wechat-diagnostic-cache`,
  `browser.duckduckgo-cache`, `browser.gecko-family-cache`, and
  `system.directx-shader-cache`.

Further checking already found useful first-party leads for Hugging Face Xet, OBS, Arc, Opera,
Vivaldi, DuckDuckGo/WebView2, and browser partial downloads. Those leads can improve the source
record, but most still do not prove the exact on-disk root and deletion boundary. DirectX shader
cache and Windows system categories should be measured through Windows-owned cleanup APIs rather
than by copying vendor directory lists.

## Batch 1 Windows measurements (2026-09-01)

Measured on a Windows host with a standard user token. The purpose was to test the batch-1
instruction "resolve effective configured locations" against reality, rather than to confirm that
vendor default paths exist.

**Every tool queried reports a cache location that differs from its documented default, and both
locations exist on disk.** Each tool was asked through its own supported interface:

| Tool | Interface | Reported effective location | Hardcoded default | Same? |
|---|---|---|---|---|
| npm | `npm config get cache` | `…\DoubaoWork\User Data\sandbox_runtime\.cache\node\npm-cache` (C:) | `%LOCALAPPDATA%\npm-cache` | no |
| pnpm | `pnpm store path` | `E:\.pnpm-store\v3` | `%LOCALAPPDATA%\pnpm\store` | no |
| pip | `pip cache dir` | `…\DoubaoWork\User Data\sandbox_runtime\.cache\python\pip` (C:) | `%LOCALAPPDATA%\pip\Cache` | no |

This was first read as the decisive argument against shipping documented defaults, and that reading
was **wrong**. Re-measured on 2026-09-05, the inference inverts: a resolver answers *which copy is
live*, and the live copy is precisely the one that must not be reclaimed. The abandoned copy at the
default location is the junk, and no resolver will ever name it.

On this host the default location held the *larger* copy: a pnpm store of 146.8 MB last written
2024-10-26, against 127.5 MB in the store actually in use on another volume. A resolver-only rule
misses 146.8 MB of inert bytes while correctly identifying the one directory it should leave alone.

Two further facts came out of the same re-measurement, and neither is visible from a path:

- **Format generations age out inside a live root.** pip's cache held the legacy `http` format at
  73.1 MB last written 2023-12-09 beside the current `http-v2` at 0 MB — 99.9% of the bytes in a
  format nothing writes to any more. The original `tool.pip-cache` rule required `http-v2` as its
  marker, which would have skipped a cache written by an older pip entirely: exactly the roots where
  those bytes sit.
- **The earlier npm and pip measurements sampled the wrong environment.** Both tools on this host
  resolve into `sandbox_runtime`, so those two rows describe a vendored runtime rather than a user
  installation. Only the pnpm row was first-party. The claim that "every tool reports a location
  differing from its default" therefore rests on a smaller sample than it appeared to.

So admission enumerates the reported path, the environment override, and the documented defaults,
and verifies each candidate against the cache's own structure — for a pnpm store, `files/` holding
exactly 256 two-hex-digit shards. The resolver is retained as a *guard*: it marks which candidate is
`live` so that copy is never presented as reclaimable. When the tool cannot be asked the marker is
`unknown`, never `stale`, because absence of an answer is not evidence of abandonment — measured
directly, since npm ships as a `.cmd`/`.ps1` shim and a bare process spawn does not apply `PATHEXT`. `pnpm` further shows the root can sit on a **different volume** from the
user profile, so a rule may not assume a cache lives under `%LOCALAPPDATA%` or on the system drive.

Admission consequence: a batch-1 rule must carry a resolver step (invoke the tool's own query, or
read the config/env precedence it documents) and must record which interface produced the answer.
A rule that cannot resolve its location on the current host must report nothing rather than fall
back to a guessed default.

### Scanner behavior observed on these roots

The current scanner reports these trees read-only and correctly. Scanning an npm `_cacache` tree
(24,453 directories, a 256-way `content-v2` fan-out) originally exhausted the default
`max_frontier_entries` of 4,096 and yielded 7,011 `resource_limit` boundaries with `partial` status
and exit code 4. The evidence stayed honest — the boundaries and lower-bound totals were all
recorded — but a routine developer cache could not be reported completely.

**Resolved (2026-09-02).** The frontier now expands depth-first and the cap was raised to 32,768,
so a wide tree no longer holds every sibling in memory before descending. Two follow-on defects
surfaced and were fixed with it: directories deferred their unexamined children instead of
refusing them when permits ran out, and a first attempt at that deadlocked until the scheduler was
made to always grant a strictly positive share of the idle pool. Cross-checked against an
independent `os.walk` oracle: npm `_cacache` **1,542 = 1,542 entries, 200,244,568 bytes exact**;
the pnpm store **1,054 = 1,054, 52,215,614 bytes exact**. Cargo (`registry\cache`) and the pip
cache also complete with 0 boundaries and 0 errors.

A residual `partial` on a synthetic 12,001-directory tree was traced to the *result* retention cap
rather than to coverage, and the two are now distinguished: per-entry rows and progress events are
folded into their directory aggregate before being dropped, so truncating them makes the listing
partial without making any total wrong. On that tree all 12,001 aggregates are exact.

### Admission blocker resolved: signing now exists in this repository

**Superseded (2026-09-02).** The blocker described below was real: adopting a rule is not an
editing task, because `BuiltInCleaner::load` recomputes each package's digest and verifies the
`SIGNATURE` envelope against `BUILTIN_TRUST_STORE`, so an edited rule file fails
`built_ins_load_and_validate` unless the package is re-signed. At the time the repository held only
the ed25519 **public** keys (`builtin-cleaner-key-2026`, `builtin-cargo-cleaner-key-2026-08`), no
private key, and no signing binary — which also meant a contributor on a different machine could
not modify a rule at all.

`DESIGN.md` R-24 already required build-time signature generation, so the gap was a missing tool,
not a missing design. The `sweepx-cleaner-sign` crate now provides `keygen` and `sign`. Two
decisions matter for anyone using it:

- It **reuses the verifier's own functions** (`package_file_table`, `load_package_bytes`) rather
  than reimplementing them. A second implementation would drift on canonical form, path ordering,
  or digest coverage, and the drift would only appear as a verification failure much later.
- A development key is by definition absent from the built-in trust store, so the tool's final
  self-check would always fail against the shipped loader. `load_package_bytes_with_key` accepts an
  explicit publisher key and applies structurally identical checks, differing only in key source.
  The tool deliberately prints the trust-anchor entry instead of editing `BUILTIN_TRUST_STORE`, so
  a new anchor always appears in a reviewed diff.

Verified on this host: editing a rule moved the package digest from `5edda6…` to `30b339…`;
re-signing unchanged content reports `unchanged` and reproduces the same digest, so signing
produces no diff noise. Acceptance tests cover both directions, including that a development
signature is rejected by the built-in trust store as `UnknownKey`.

Rule JSON edits still change the package digest, so the `SIGNATURE` must be regenerated in the
same change, and the files must stay LF-normalized: the digest is computed over exact bytes, which
is why `.gitattributes` pins these paths.

### Batch 1 admission outcome (2026-09-02)

Three rules were admitted: npm (R2), pnpm (R3), pip (R2). All are `platform: "any"`,
`matchKind: "verified_tool_root"`, `depth: 0`, and every one of the six rules in
`platform-junk-rules.json` now carries `requiredMarkers`.

The measurements above are encoded as behavior, not as paths:

- `ToolReportedRoot` returns `None` when the tool is missing, exits non-zero, prints nothing, or
  prints a relative path — so an unresolvable host reports nothing rather than a guessed default.
- `root_has_required_markers()` confirms the structural signature of each cache (npm `_cacache`,
  pnpm `files`, pip `http-v2`) using `symlink_metadata`, so a symlink cannot impersonate a real
  marker.
- Classification compares the lossless native path via `NativeAbsolutePath::equals_path`, never
  the display path.

pnpm is deliberately R3 rather than R2, recorded in its evidence: installed projects hard-link
into the store, so deleting it can force a dependency reinstall.

Go, uv, Gradle, Maven and NuGet are not installed on this host and were not admitted, holding to
the rule that no admission happens without independent evidence.

## Next admission batches

1. **Official tool caches:** Cargo, npm, pnpm, Go, uv, pip, Gradle, Maven, NuGet, ccache, and
   browser-automation caches. Resolve effective configured locations; prefer each tool's supported
   clean/prune interface for future mutation. *Partly done: npm, pnpm and pip admitted report-only
   on 2026-09-02. Go, uv, Gradle, Maven, NuGet, ccache and browser-automation caches remain open,
   each blocked on a host where the tool is installed and can be queried through its own
   interface.*
2. **Browser rendering caches:** Chromium-family HTTP/code/GPU caches and Firefox `cache2`, with
   exact profile/partition discovery, stopped-process evidence, and explicit exclusion of cookies,
   sessions, local storage, IndexedDB, extensions, and offline application state.
3. **OS diagnostics:** Windows WER/crash dumps and macOS diagnostic logs, with retention windows and
   native ownership checks. Windows update/Defender/Delivery Optimization remain API-backed only.
4. **Application caches:** only when an application document or source tree establishes both the
   location and rebuild behavior. Download pages and product homepages are discovery evidence only.
5. **No-reference rules:** remain blocked until the exact path boundary is independently proven.

Every batch lands report-only first. Native process/activity checks, exact identity, complete
coverage, planning, approval, and mutation qualification remain separate gates.
