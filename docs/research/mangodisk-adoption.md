# MangoDisk adoption decisions

Research target: `harry0703/MangoDisk` at `b011da813795e3221022b6b731be998a2eb2bf2f`.

Source snapshot date: 2026-08-29. The upstream project is GPL-3.0. SweepX therefore treats its source and
catalog as research evidence, not as code or rule text that can be copied into this MIT/Apache-2.0
repository.

## What SweepX adopts now

- **Progressive UI with bounded backpressure.** MangoDisk throttles duplicate-scan progress to
  120 ms. SweepX now applies the same independently implemented product principle to TUI directory
  aggregation: the scanner emits advisory lower-bound snapshots at most once per 120 ms window, a
  one-slot channel drops superseded snapshots, and the final result remains authoritative.
- **Bounded parallel traversal.** SweepX already had a four-worker default, a hard cap of 32,
  bounded work/result channels, stable commit ordering, cancellation checks, and handle ownership
  per worker. This overlaps MangoDisk's CPU/device-bounded worker pool and backpressure design.
- **Independent, evidence-bearing rules.** A rule must identify its platform, controlled root, risk,
  rebuild boundary, verification date, and first-party references. An upstream catalog entry may
  suggest an investigation but cannot prove safety or become deletion authority.

## Acceleration work that remains platform-qualified

Status as of 2026-09-03. "Landed" means wired into a user-visible path on Windows, not merely
implemented.

| Technique | MangoDisk evidence | SweepX status |
|---|---|---|
| NTFS volume layout enumeration | `FSCTL_QUERY_FILE_LAYOUT`, 8 MiB pages, bounded fallback | **Landed** as a non-authoritative preview source, elevation-gated, cross-checked against a directory walk. Measured 1.06 s vs 133 s on this repo (~126×), 36531 paths agreeing exactly. |
| NTFS USN change tokens | `FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` | **Landed** as cache validity: a per-volume token is stored in the generation and re-checked on load, upgrading `stale_preview` to `verified_preview`. Confirmed elevated in both directions on a live volume. Two limits, both measured: it needs elevation (see the access-mask table in `native-scan-qualification.md`), and it only verifies when the state directory is on a *different* volume from the scan root, because the cache's own write advances the journal it records. The second was attacked twice and both attempts are recorded as dead ends in `native-scan-qualification.md`: capturing the token after the write does not converge, and per-record attribution via `FSCTL_READ_USN_JOURNAL` was fully built and then withdrawn on measurement — a busy system volume is never quiet (182 records in a 20,000-USN window, none of them the cache's), and the range read costs 1.9-2.6 s against ~1.06 s for the preview it would save. Cross-volume state is the supported route to verified reuse; same-volume stays at `stale_preview`. |
| macOS bulk enumeration | `getattrlistbulk`, 64 KiB pages | Not applicable to the current Windows work. Unchanged: macOS still uses `readdir` plus handle-relative inspection, so no bulk-speed claim is made. |
| Device-aware concurrency | SSD 4, rotational 2, removable/network/unknown 1 | **Not implemented.** `max_workers` is a fixed default of 4, capped at 32. Blocked on evidence, not effort: this host has no rotational, removable or network volume, so any tuning here would be an unmeasured guess. |
| Applicability probes | Skip known-absent apps and branches outside active rule roots | **Landed** via tool-reported roots and required-marker checks; a probe failure still leaves the root eligible. |
| Path-trie pruning | Skip branches outside active rule roots | **Not implemented**, and the payoff is doubtful here: rule roots are already few and shallow, so the walk it would prune is small next to the layout read it cannot. |
| Index reuse | LRU plus filesystem change token | **Partly landed.** The change token and durable state both exist, so a verified preview can now cross runs. There is no LRU or multi-generation retention: one current generation, older ones pruned. |

## Cross-platform junk strategy

The first system catalog should be deliberately smaller than MangoDisk's 205 filesystem rules.
SweepX will expand by evidence class, with read-only reporting before any rule participates in a
plan.

### macOS

Start at the direct children of `~/Library/Caches` and other narrowly documented cache roots. Apple says the
`Caches` directory contains discardable data that applications must be able to recreate. Do not
classify `Application Support`, preferences, cookies, containers, or arbitrary logs as equivalent
cache data. Application-specific paths require a bundle/application probe and a source proving the
selected child is rebuildable.

Sources:

- <https://developer.apple.com/documentation/foundation/url/cachesdirectory>
- <https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/MacOSXDirectories/MacOSXDirectories.html>

### Windows

Use OS-owned APIs for system categories rather than deleting guessed directories. Windows Storage
Settings / Disk Cleanup owns Windows Update, Delivery Optimization, Defender, Internet Cache, and
other system handlers. Per-app rules may target a documented `LocalCacheFolder` or temporary
folder, but must not generalize all of `%LOCALAPPDATA%` or an application's `LocalFolder` as junk.

Sources:

- <https://learn.microsoft.com/windows/apps/develop/data/store-and-retrieve-app-data>
- <https://learn.microsoft.com/windows/win32/api/emptyvc/nn-emptyvc-iemptyvolumecache>

### Linux

Linux needs its own policy rather than a mechanical macOS port:

1. `$XDG_CACHE_HOME` (default `~/.cache`) is the primary user-cache namespace because the XDG Base
   Directory specification defines it for non-essential data. Report application-owned direct
   children; do not treat `$XDG_DATA_HOME` or `$XDG_CONFIG_HOME` as cache.
2. Freedesktop thumbnail caches under `$XDG_CACHE_HOME/thumbnails` are a narrow, documented first
   rule.
3. `/tmp` and `/var/tmp` require an age/ownership/activity policy and should normally defer to the
   distribution's `systemd-tmpfiles` policy. Never report either entire shared root as one candidate.
4. Package managers, Flatpak/Snap, containers, journals, and language toolchains need dedicated
   adapters or first-party commands because shared stores and reference graphs are not safe
   directory-name matches.
5. Any XDG environment override is accepted only when absolute. Symlinks, mount changes, unknown
   ownership, active processes, and incomplete enumeration keep a rule report-only.

Sources:

- <https://specifications.freedesktop.org/basedir-spec/latest/>
- <https://specifications.freedesktop.org/thumbnail-spec/latest-single/>
- <https://systemd.io/TEMPORARY_DIRECTORIES/>

## Rule intake gate

A candidate advances from research only after all of these are present: first-party ownership and
rebuild evidence, explicit preserved-data boundary, platform/version scope, controlled root,
no-follow identity-safe scanner fixture, real-system verification date, and a conservative risk and
default-selection decision. Execution remains separately gated by immutable planning, approval,
live revalidation, and platform qualification.

## Reproducible upstream reference audit

`scripts/audit_mangodisk_rules.py <MangoDisk rules/filesystem> --csv <output.csv> --redact-urls` reads only rule
IDs, platform/category labels, and reference URLs. It intentionally does not export roots, matchers,
execution policy, or evidence prose. Against the pinned 2026-08-29 snapshot it found 205 rules and
318 references: 135 rules have at least one URL whose target looks like cache/storage/cleanup
documentation, 55 have references that are only identity or research leads pending manual review,
and 15 have no reference at all. These are triage buckets, not safety verdicts. Every candidate still
requires manual reading of the source and native verification under the intake gate above.
The checked-in [triage snapshot](mangodisk-rule-source-audit.csv) preserves those 205 rule IDs and
their reference domains without copying upstream path or execution definitions. Omitting
`--redact-urls` from a local audit retains complete public reference URLs for reviewers. A
reachability check on 2026-08-30 found
144 of 152 unique URLs returning HTTP 200/206; six returned 403, one returned 451 after redirect,
and one Electron Builder URL returned 404. Reachability does not establish cleanup safety.
The snapshot also distinguishes exact named-rule adoption from incidental coverage by SweepX's
coarse platform cache roots: 35 upstream rules are wholly inside those report roots, 31 are only
partly inside, and 139 are not covered. None is marked as an exact adopted rule merely because a
broader read-only report contains the same directory.

The 135/55 split is a deterministic URL-path triage heuristic, not a content review result. The
implementation-versus-native-test boundary for NTFS layout, USN, macOS bulk enumeration, and
device-aware concurrency is tracked in [the native qualification matrix](native-scan-qualification.md).
