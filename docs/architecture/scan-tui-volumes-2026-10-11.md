# macOS System + Data size browsing — 2026-10-11

`scan --tui /` previously counted only its original mount, approximately 19 GiB on the
validation host, and silently removed the Data entrances. Ordinary macOS size browsing now
independently admits `/System/Volumes/Data`, validates its native mount, and includes both
System and Data in the captured `/` tree. `/Users`, `/Applications`, `/Library`, `/private`
and other Data entrances remain visible and browsable. Virtual, auxiliary and external volumes
remain visible exclusions and need independent admission; this does not promise whole-device
allocation, snapshots or reclaimable bytes. Explicit permission denials remain gaps.

One physical SSD can contain several APFS volumes sharing container space. macOS creates
separate System and Data volumes, then presents their contents as a unified tree using firmlinks.
The same directory may therefore have both `/Users` and `/System/Volumes/Data/Users` entrances.
See Apple's [APFS volume roles](https://support.apple.com/en-ca/guide/security/seca6147599e/web)
and [firmlink explanation](https://developer.apple.com/videos/play/wwdc2019/710/).

## Counting and authority

- Read the sealed system's `/usr/share/firmlinks` with `O_NOFOLLOW_ANY`, at most 64 KiB and
  256 non-overlapping mappings. Parsing rejects escapes, overlapping/duplicate mappings and
  the Data subtree as a logical entrance. Mapping paths select observations; they are not
  native identity or deletion evidence.
- Admit logical directories independently. Admit physical entrances when available; before
  excluding a Data alias, its actual directory must match the logical entrance's complete
  native object, filesystem-domain and mount evidence. Identity changes reject the generation.
  Missing physical admission is not assumed equality: later observation must still match.
- Traverse each logical entrance once. Retain its physical Data entrance with size `—` and
  `Counted at another path` / `已从其他路径统计`; entering it still reads the list. Data-only
  directories contribute normally. If a logical entrance cannot be admitted, scan its Data
  entrance instead and preserve the unverified logical entrance with its identity reason.
  Thus uncertain entrances cannot both contribute. The scan remains non-atomic while files change.
- Cross-volume captured lineage still revalidates every component's native identity and mount.
  Only the ordinary size browser enables this scope. Strict inventories, fixed-child observations,
  content reads, junk and cleanup keep their original mount boundaries and execution checks.
- Scope preparation retains bounded metadata and at most root + two temporary admission handles;
  these close before recursive traversal. Cumulative traversal work is uncapped in ordinary size browsing; directory batches, retained rows, DFS handles, two
  worker lanes, cancellation and publication gates remain bounded.

Unreadable, vanished and other-volume direct entries retain scan-scoped presentation IDs,
explicitly unknown native identity and no executable locator. They are leaf rows, cannot be
entered and cannot request Trash or cancel scanning by pressing Delete. Permission denial is
also an explicit refresh failure. Subtree exclusion reasons survive live size updates, including
when a newly observed gap leaves the byte lower bound unchanged. Chinese and English statuses
fit the widened status column; unknown sizes display `—`, never assumed zero.

The recursive worker continues during independently listed child pages. Native-keyed advisory
sizes still update visible and offscreen folders and reorder them by descending size while
preserving selection. Completed-size retention now favors larger completed directories and their parents; equal sizes
favor later completion. It preserves that priority when publishing a successful staged generation. Both indexes/key copies count toward 16,384 directories and a 16 MiB owned-data
estimate. This prevents the early System subtree from occupying every reusable slot on a large
Data scan. Capacity still cannot guarantee retaining every descendant; scan-time display reuse
is not current filesystem evidence or cleanup authority. Failed/cancelled traversal publishes no
completed generation.

## Evidence

Controlled native namespace fixtures model two mount IDs and two entrances identifying the
same directory. An ordinary metadata oracle counts 13 system bytes + 7 user bytes + 11 Data-only
bytes = **31 bytes**. The combined scan agrees, the Data subtree contributes only 11 bytes,
its 7-byte alias stays navigable with a counted-elsewhere notice, other-volume and denied entries
remain visible, and strict inventories still reject cross-mount lineage. A replaced or unknown
alias identity rejects deduplication. Native macOS admission additionally checks real `/Users`
and `/System/Volumes/Data/Users` against independent `std::fs` device/inode observations.

Darwin rejected an initial `O_NOFOLLOW | O_NOFOLLOW_ANY` experiment with `EINVAL`; the production
code uses only `O_NOFOLLOW_ANY`, matching the backend root-admission contract. A native regression
compares that actual open/read with an ordinary independent read of the system mapping. No test
was weakened to accept unavailable admission. Presentation tests cover both locales, incomplete
leaf authority, equal-byte permission updates, selection retention and existing held-worker live
navigation/sorting contracts.

Host: macOS 26.5.2 arm64, pinned/active Rust 1.98.0. Native acceptance uses fresh `--no-state`
invocations, 160×32 terminal, file metadata only, no cleanup. OS caches were not cleared;
concurrent validation and other host activity are uncontrolled. These are functional observations,
not speed comparisons, cold-cache benchmarks or percentile estimates.

The first release root run reached **6,571,896 entries / 168,425,962,559 bytes** before
failing with `resource_limit` after 1,407.9 traversal seconds. The terminal driver originally
waited to its 1,800-second deadline; this was a product failure, not a hung platform call or
permission blocker. An ordinary `os.scandir` found over 154,000 children in `target/debug/deps`.
The logical browser had lifted the total visited-entry cap but retained cumulative per-directory
limits of 131,072 children / 16 MiB of consumed record estimates. Those limits bounded work,
not live memory, and incorrectly aborted streamed traversal.

The fix removes both cumulative directory-work limits from ordinary streamed size browsing.
One batch, retained visible rows, per-directory observation caches and ancestor handles remain
bounded; full-fact inventories retain all their limits. The native regression uses six nested
files with independently summed lengths and deliberately small total and directory work caps,
while keeping two-entry batches and one retained row. Streamed browsing completes; full-fact
inventory still rejects its work budget.

The final optimized build then scanned the real `target/debug` tree to completion: **210,920
entries / 47,094,674,316 bytes**. Its `deps` row reported **30,242,078,882 bytes**, exactly matching
independent file-property sums before and after the scan for **156,169 entries**. The complete
terminal interaction took 3.254 seconds; this small, hot metadata workload is not a whole-root
speed claim. The full root was not rerun to completion after the fix. The earlier combined root
run proves Data traversal and exposes the now-corrected work cap; it is not final full-disk
acceptance. Final root navigation was rerun separately with a bounded invocation.

Checks: workspace all-target/all-feature tests passed before final presentation/work-cap changes;
subsequent affected native tests cover the final changes (scanner 118 unit + 3 integration, TUI
114 unit, CLI 74 unit + browser/contract/elevation integrations). Existing five opt-in workspace
benchmarks remain ignored; no regression test was newly excluded. Final workspace and affected
Clippy, format checks, documentation link/content lint, Linux GNU cross-target workspace lint
and Windows GNU cross-target workspace lint passed. Cross-target checks cover production/test
configuration and compilation, not native Linux/Windows runtime.

See [terminal acceptance evidence](scan-tui-volumes-2026-10-11.json) for captured screens,
independent oracle values, cache/build scope and bounded-run outcomes.
