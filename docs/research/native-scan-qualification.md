# Native scan acceleration qualification matrix

Source snapshot date: 2026-08-30. This matrix separates implementation work that can be completed
on any development host from claims that require the target operating system and filesystem.

| Accelerator | Can implement without target OS | Native functional gate | Physical/performance gate | Fallback |
|---|---|---|---|---|
| Windows NTFS layout reader | Protocol types, bounded parser, malformed-buffer corpus, path/identity projection, fallback contract | Real NTFS `FSCTL_QUERY_FILE_LAYOUT`; normal/denied/elevated access; hard links, alternate streams, reparse points, cloud placeholders, corrupt or unknown records, cancellation, very large volume bound | Windows devices covering SSD, rotational disk, removable storage, network paths, and representative small-file trees | Existing handle-relative `NtQueryDirectoryFile` traversal; fallback must preserve coverage reasons and never claim the fast path |
| Windows USN cache token | Token model, USN record parser, reason classification, wrap/range fixtures, cache-miss state machine | Real journal create/delete/rename/data/metadata events; journal-ID replacement, wrap, disabled journal, privilege denial, volume remount, cancellation | Measure warm-scan wins and invalidation cost on NTFS SSD/HDD; no cache hit may rely only on wall clock or path text | Any missing, ambiguous, wrapped, denied, or mismatched token is a cache miss and full scan |
| macOS bulk directory reader | Buffer parser, attribute validation, page limits, fallback contract | Real APFS/HFS+ `getattrlistbulk`; permission denial, package/dataless files, symlinks, mount boundaries, cancellation, malformed/truncated attributes | Intel and Apple Silicon; local SSD plus removable/network volumes; compare syscall count and wall time against current handle-bound path | Existing `readdir` plus no-follow handle-relative inspection; unsupported attributes never become invented metadata |
| Device-aware concurrency | Stable enum and scheduling policy, conservative unknown behavior, deterministic scheduler tests | Windows Storage property/drive classification and macOS IOKit media classification on native hosts | At least SSD/HDD/removable/network samples; retain a benchmark only when it beats the conservative baseline without tail-latency regression | Unknown, remote, removable, or probe failure uses one worker; no inference from a path label |

## Current implementation state

- macOS `sweepx-platform-macos` now uses a 64 KiB aligned `getattrlistbulk` name page for directory
  enumeration. It accepts only checked, NUL-terminated native names, keeps the existing no-follow
  handle-relative metadata inspection as authority, and falls back to `readdir` only when the first
  bulk call reports a documented unsupported condition. Failure after an accepted page fails closed
  instead of restarting and risking duplicates or omissions. Native macOS CI exercises the path.
- Windows `sweepx-platform-windows` now has independent bounded parsers for
  `QUERY_FILE_LAYOUT_OUTPUT` and USN v2 pages, a fail-closed USN cursor validator, and a read-only
  native probe that opens an NTFS volume, queries the journal, and consumes bounded layout pages.
  Path reconstruction and identity verification now exist and are validated against the OS, and the
  reader supplies a non-authoritative preview; the ordinary scanner remains authoritative because
  only a live handle yields the reopen recipe an execution step revalidates. Native Windows CI runs
  the ignored probe explicitly and accepts only an available
  result or one of the enumerated safe fallbacks. Neither accelerator is reachable at all on a
  standard user token; see the measured privilege floor below.
- Device classification and adaptive scheduling are not yet implemented. SweepX retains its
  existing bounded four-worker default until the native probes and physical-device benchmarks exist.

## Measured elevated capability floor (2026-09-02)

Re-ran the read-only probe under a genuinely elevated token (`TokenIsElevated=1`,
`TokenElevationType=2`) on the same host, against both `C:` and `E:`. Results were identical on
both volumes:

| Desired access | Not elevated | Elevated |
| --- | --- | --- |
| `0` | handle opens; both FSCTLs `ERROR_INVALID_FUNCTION (1)` | **unchanged**: still `1` |
| `FILE_READ_ATTRIBUTES` | handle opens; both FSCTLs `1` | **unchanged**: still `1` |
| `FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | handle opens; both FSCTLs `1` | **unchanged**: still `1` |
| `GENERIC_READ` | open refused, `ERROR_ACCESS_DENIED (5)` | **open succeeds** |
| ↳ `FSCTL_QUERY_USN_JOURNAL` | unreachable | **succeeds** |
| ↳ `FSCTL_QUERY_FILE_LAYOUT` | unreachable | `ERROR_INVALID_PARAMETER (87)` — see below |

Three consequences:

1. Elevation is a hard gate, and it changes behavior **only** at `GENERIC_READ`. The lower access
   levels still report both control codes as absent even when elevated, which confirms the earlier
   reading: this is not "insufficient rights" but "the function does not exist at that handle
   level". There is therefore no reduced-privilege access level to trade down to, and
   `NtfsAccelerationFallback::NotElevated` is the accurate reason on an unelevated host.
2. `FSCTL_QUERY_USN_JOURNAL` is confirmed usable once elevated. The USN-based accelerator has a
   real foundation.
3. The `87` for `FSCTL_QUERY_FILE_LAYOUT` is **an artifact of the throwaway probe, not a platform
   limit**, and must not be recorded as a capability finding. The probe passed a hand-rolled input
   with `Flags = INCLUDE_NAMES | INCLUDE_STREAMS` (omitting the mandatory
   `QUERY_FILE_LAYOUT_RESTART` on the first call) and `FilterType = ..._CLUSTERS` with a
   `[0, u64::MAX]` interval. The shipped `native::query_file_layout` instead sets
   `QUERY_FILE_LAYOUT_RESTART | INCLUDE_NAMES | INCLUDE_STREAMS |
   INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED` with `FILTER_TYPE_NONE` and `FilterEntryCount = 0`,
   which is the documented form. Distinguishing `87` from `1`/`5` matters: `87` means the handle and
   control code were both reached and only the input was wrong, so treating it as "unsupported"
   would have discarded a working accelerator.

## Both accelerators qualified elevated (2026-09-02)

Confirmed by running the **shipped** call forms — not a throwaway probe — under an elevated token,
via the `#[ignore]`d test `shipped_fsctl_call_forms_are_accepted_when_elevated`. The predicted
correction held: `FSCTL_QUERY_FILE_LAYOUT` is accepted, and `87` was indeed only the old probe's
malformed input.

| Volume | `FSCTL_QUERY_USN_JOURNAL` | `FSCTL_QUERY_FILE_LAYOUT` records | First page |
| --- | --- | --- | --- |
| `C:` | succeeds, real journal bounds | **2,647,335** | 8,388,592 B / 17,410 records |
| `E:` | succeeds, real journal bounds | **326,874** | 8,388,408 B / 23,467 records |

One real defect was found and fixed on the way, and it is the reason this had to be measured
rather than reasoned about. The first elevated run returned `Err(13)`, which `query_file_layout`
emits for *both* a short kernel buffer and a parser rejection. Splitting those apart showed the
kernel had returned a perfectly healthy page (8,388,136 bytes, 17,409 records, first record at
offset 16) and that **our own parser** rejected it with `layout_name_invalid`:
`parse_layout_names` treated the name `.` as corruption, but NTFS names the volume root record
`.`. One legitimate record therefore invalidated the entire page, and every NTFS volume would
have reported acceleration as unsupported forever. `.` is now accepted but deliberately not
emitted as a composable path component; `..` still fails closed, since it is never a real NTFS
filename and admitting it could escape a reconstructed directory.

### Measured speedup

Same host, same release profile, whole `E:` volume:

| Path | Time | Coverage |
| --- | --- | --- |
| Portable handle-relative traversal | **137.08 s** | `partial`, 459 boundaries, root `lower_bound` |
| Native MFT enumeration, elevated | **1.03 s** | 326,874 records |

That is roughly **133×** on this volume. `C:` enumerated 2,647,335 records in 10.31 s, i.e. eight
times the records in a fraction of the traversal cost. Two caveats keep this honest: the native
figure is enumeration only and does not yet include path reconstruction or identity verification,
which the portable number does include; and elevation is required, so an ordinary run cannot
realize it. The comparison establishes the ceiling worth building toward, not a shipped result.

## Path reconstruction and identity verification: measured feasibility (2026-09-02)

These are the two pieces standing between "the MFT can be enumerated" and "the accelerator can be
a scan source". Enumeration yields a `file_reference_number: u64` plus a name and a
`parent_file_reference_number`; the scanner's authoritative output is an
`EntryIdentity::from_windows_file_id(VolumeSerialNumber, FILE_ID_128)` and a full display path. So:

- **Path reconstruction** turns "my name plus my parent's number" into `E:\Projects\sweepx\...` by
  walking the parent chain to the volume root. It must handle cycles, orphaned records, records
  with several names (hard links), and the root record, whose NTFS name is literally `.`.
- **Identity verification** exists because an MFT page is a point-in-time snapshot while this
  repository's rule is that a display path never carries filesystem authority. Every accelerated
  record must be provable to name the same object the portable traversal would have reached.

Measured **entirely without elevation** (this matters: it decides how much of the work is even
testable on an ordinary account).

| Experiment | Result |
| --- | --- |
| Resolve a 64-bit FRN via `OpenFileById` using an ordinary **directory** handle as the volume hint | **works unprivileged**; reopened `FILE_ID_128` and volume serial match the original exactly |
| Same, using a **file** handle as the hint | works |
| Same FRN against a hint on a **different volume** | refused, `ERROR_INVALID_PARAMETER (87)` |
| FRN of a **deleted** record | refused, `87` |
| FRN of a deep directory, and of the volume **root** | both resolve, identity matches |
| Cost, 153 resolves | 64.7 µs per resolve |

Four consequences:

1. **Identity verification needs no privilege.** `OpenFileById` accepts any handle on the volume as
   its hint, not a volume handle, so an accelerated record can be verified against the very same
   `EntryIdentity` the portable scanner produces. Only the MFT read itself requires elevation.
2. **Staleness fails closed for free.** A deleted record's FRN is refused rather than silently
   resolving to whatever reused that id, and a hint on the wrong volume is refused too, so an FRN
   cannot cross a volume boundary. Both are the safe direction by default.
3. **Comparing by the 64-bit FRN is sound here, but only because it was checked.** Sampling 3000
   entries under `E:\Projects\sweepx` and 3000 under `C:\Windows\System32` found the high 64 bits of
   `FILE_ID_128` always zero. The first sample also showed 260 low-64 collisions, which looked like
   distinct objects sharing an id — that would have made FRN comparison unsound. A follow-up over
   6000 entries resolved it: **1208 colliding groups, all 1208 explained by hard links** (every
   member reporting `NumberOfLinks > 1` and byte-identical full 128-bit ids), zero suspicious
   groups. That is Cargo/rustup sharing crate files by hard link. The id is unique per *object*,
   not per name, which is exactly what `HardLinkKey` already assumes. Note this was verified, not
   assumed: the high bits being zero is a per-volume property, so the implementation should compare
   the full 128-bit identity and must not hard-code the assumption.
4. **Verification must be selective, or it erases the win.** At 64.7 µs per resolve, verifying all
   326,874 records on `E:` would cost roughly 21 s — still far below the 137 s traversal, but ~20×
   the 1.03 s enumeration. Verifying only records that reach a reported candidate keeps the
   advantage; verifying everything does not.

Remaining unknowns, none of which this measurement settles: parent-chain reconstruction itself
(the parent FRN comes only from the MFT, so the walk cannot be exercised unprivileged), cycle and
orphan handling on a live volume, name selection for multi-link records, and whether reconstructed
paths agree with portable traversal across a whole volume. The honest status is that identity
verification is now known to be buildable and unit-testable without privilege, while reconstruction
still needs one elevated run to validate against real parent links.

### Path reconstruction, validated against the OS (2026-09-02)

`crates/sweepx-platform-windows/src/path_reconstruction.rs` walks a record's parent chain to the
volume root. It is pure logic over parsed records, so cycles, missing ancestors, overlong chains,
a file appearing as an ancestor, and lossless handling of unpaired surrogates are all unit-tested
without privilege; only the input has to come from an elevated read. Every failure is a refusal,
never a partially-built path, because "as much of the path as we could determine" produces a
string that looks addressable while naming the wrong object.

Validated by `reconstructed_paths_match_the_paths_the_os_reports`, which resolves each record by
reference number and compares the reconstruction against `GetFinalPathNameByHandleW`:

| Volume | Compared | Agreed | Refused | Unresolvable |
| --- | --- | --- | --- | --- |
| `E:` | 2537 | **2537** | 1436 | 27 |
| `C:` | 797 | **797** | 3171 | 32 |

Refusals are the designed outcome for records whose parents are on a page not yet read, so they
are counted rather than asserted away; `unresolvable` is dominated by filesystem metadata files.

**This cross-check earned its keep immediately.** The first elevated run agreed on only 3 of 797
records on `C:`, rebuilding `C:\PROGRA~1\COMMON~1\MICROS~1\VSTO` where the OS reports
`C:\Program Files\Common Files\microsoft shared\VSTO`. NTFS stores both an 8.3 short name and a
long name, and taking the first name in the record picked whichever the volume happened to store
first. The wrong path still *resolves*, so no resolution-based test could ever have caught it —
only comparison against an independent authority.

The repair was itself instructive. The first attempt assumed `0x1` meant DOS and `0x2` meant
NTFS, and the cross-check numbers did not move **at all** — identical output, 3/797 again. Rather
than adjust the guess, the run was changed to print the observed flag histogram, which showed the
assignment was inverted: `flags=0x1` accompanies `ClickToRun`, `flags=0x2` accompanies
`CLICKT~1`. Note also that `E:` reports `flags=0x0` for 23483 of 23494 names, so unflagged names
are the norm on volumes without 8.3 generation and must not be treated as second class. The
regression test writes the measured literals `0x1`/`0x2` directly instead of referencing the
named constants, because the earlier version of that test referenced the constants and passed
happily while they were defined backwards.


### Identity verification (unprivileged)

`crates/sweepx-platform-windows/src/accelerated_verification.rs` implements the half the
measurements qualified. It resolves a record's reference number through `OpenFileById` using an
ordinary handle the scanner already holds, then compares the **full 128-bit** file id plus volume
serial against the claim, and also checks the record's directory/file claim — identity equality
alone would accept a snapshot that calls a file a directory, which is a different scanning subject
at the same id. This mirrors the existing post-enumeration `matches_enumerated_identity` check
rather than introducing a second notion of sameness.

The open requests only `FILE_READ_ATTRIBUTES` and passes `FILE_FLAG_OPEN_REPARSE_POINT`, so
verification observes the object the record names, never follows a link to a different one, and
never reads contents or triggers cloud hydration. A `VerifiedRecord` carries the identity read
back from the live open, not the record's claim, so an unverified value cannot be propagated by
mistake.

Nine tests run against the live filesystem, unprivileged, in 0.01 s, covering files, directories,
hard links sharing one identity, a wrong type claim, a deleted record, a zero reference number,
and a plain **file** handle serving as the volume hint. Two mutations were used to confirm the
tests can actually fail: disabling the type-claim check failed
`a_record_whose_type_claim_is_wrong_is_refused`, and misclassifying staleness failed two
independent tests.

## Showing MFT results provisionally

The evidence model already supports this, so no new "provisional" concept is required:

- `EvidenceValue::LowerBound { value, reason }` renders as `>= 1.2 GB`, so a not-yet-final size is
  visibly a bound rather than a number pretending to be exact. The TUI already does exactly this
  while backfilling recursive directory sizes.
- `FieldProvenance::LiveObservation { method: MethodId::NativeApi }` distinguishes MFT-derived
  fields from `MetadataNoFollow` traversal fields in machine-readable output, so a consumer can
  tell which reader produced a row.
- `ArithmeticState` and `Coverage` retain the evidence that a value is not final.

Two constraints bind. First, a provisional value must never be rendered as exact; incomplete or
lower-bound evidence has to survive into the output. Second, display authority is not execution
authority: the `AUTHORIZED -> REVALIDATING -> READY -> EXECUTING` sequence requires a live
no-follow revalidation before any destructive step, which is precisely what the verification
module above provides.

Worth separating the two halves when sequencing this. A record's **size** is in the MFT record
itself and is trustworthy as soon as it is read; a record's **path** depends on parent-chain
reconstruction, which is still unvalidated. Using MFT data for totals and ordering while letting
traversal remain authoritative for paths is therefore available earlier than a full switch, and
worth noting that Windows currently reports `allocated_bytes` as
`unknown(IncompleteStreamCoverage)` because it only sees the unnamed stream — the MFT covers all
streams, so on that field the accelerated reader is the better source, not merely the faster one.



Both Windows accelerators need a **volume** handle, and that requirement — not the choice of
IOCTL flags or path syntax — is what decides whether they can run. Measured on Windows with a
standard (non-elevated, non-Administrator) token against local NTFS volumes `C:` and `E:`:

| `CreateFileW` desired access on `\\.\C:` / `\\.\E:` | Handle | `FSCTL_QUERY_FILE_LAYOUT` | `FSCTL_QUERY_USN_JOURNAL` |
|---|---|---|---|
| `0` (no access) | opens | `ERROR_INVALID_FUNCTION` (1) | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_ATTRIBUTES` | opens | `ERROR_INVALID_FUNCTION` (1) | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | opens | `ERROR_INVALID_FUNCTION` (1) | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_DATA` | `ERROR_ACCESS_DENIED` (5) | not reachable | not reachable |
| `GENERIC_READ` | `ERROR_ACCESS_DENIED` (5) | not reachable | not reachable |

Two conclusions follow, and they are stronger than "permission is missing":

- There is no reduced-access compromise. An attribute-only volume handle *does* open, but the
  filesystem refuses both control codes on it with `ERROR_INVALID_FUNCTION`, so the capability is
  absent at that handle level rather than merely unauthorized. Any access level that could carry
  volume data is refused outright. Elevation is therefore a hard floor, not a tuning knob.
- The floor is a property of the platform, not of any particular implementation. MangoDisk
  (`windows/native_io.rs`, `open_volume`) requests exactly `GENERIC_READ` with full sharing, which
  is the row measured as `ERROR_ACCESS_DENIED` above, so it does not evade the requirement either.

### What MangoDisk actually elevates for

MangoDisk does implement real elevation: `disk_cleanup_helper.rs` and `system_maintenance_helper.rs`
launch a helper through `ShellExecuteExW` with the `runas` verb, and it re-uses one elevated helper
process because Windows grants elevation per process rather than caching consent for later `runas`
calls. That elevation serves *system maintenance* — for example estimating and removing previous
Windows installations — and not the layout reader. Searching those elevated helper sources for
`FSCTL_QUERY_FILE_LAYOUT`, `FSCTL_READ_USN_JOURNAL`, or `MFT` yields no matches: the elevated path
and the acceleration path do not meet.

Consequently, MangoDisk's own NTFS fast path degrades on a standard token exactly as SweepX's does.
Its USN cache treats an unopenable volume as "no cached token" and returns `Ok(None)`, and its
layout scan surfaces an `open_volume` platform error to the caller. Copying its elevation code would
not make acceleration available to a normal user; it would only change who SweepX scans as.

### Consequence for SweepX

`DESIGN.md` already resolves this: v1 does not enable a privileged MFT path for ordinary users, and
scanning as Administrator to raise coverage is on the explicit non-goals list. The probe-only state
of `ntfs_acceleration.rs` is therefore the designed endpoint for an unprivileged run, and reporting
`AccessDeniedOrUnavailable` and falling back is correct behavior rather than an unfinished feature.
Any future work must detect privilege that the user has already granted, never request it, and must
still treat the handle-relative traversal as authoritative.

## Wired in as a preview source (2026-09-02)

The accelerated reader is now an actual scan input, not just a qualification probe. When a root
qualifies, `scan_root` reads the volume's layout once, selects the records under the root, and
emits an `AcceleratedPreview` before the traversal starts. The traversal still runs unchanged and
still produces every authoritative record.

### Why a preview rather than a replacement

`ScannedEntry` carries a `native_locator`: a reopen recipe built from handles the traversal
actually held, and the thing a Trash operation revalidates against. An MFT snapshot cannot produce
one — it has names and sizes, not handles. So accelerated results are surfaced with
`authoritative: false` and no locator, and nothing may be deleted on their strength. This matches
the existing rule that a display path is never execution authority.

### Measured on this host

| Path | Subject | Result |
| --- | --- | --- |
| Accelerated preview | `E:\Projects\sweepx` | 37,371 entries, 14,812,812,602 B, **1.06 s** |
| Full authoritative scan | same tree, elevated | **133.4 s** |
| Full authoritative scan | same tree, unelevated | 113.3 s |

About **126x faster to a first answer**. The scan itself is not faster: the preview is additive,
and the ~1 s whole-volume read is a fixed cost that only pays off on large trees. On a small
subtree (`crates`, 156 entries) the preview costs 1.05 s against a 0.004 s raw walk, so it is
worth surfacing only because the authoritative scanner — which opens a handle per entry — needs
0.75 s there and minutes on a build tree.

### Correctness, checked against an independent oracle

`the_accelerated_source_agrees_with_a_directory_walk` compares the accelerated selection against
an ordinary `std::fs` recursive walk, which reaches the filesystem through a completely different
code path than `FSCTL_QUERY_FILE_LAYOUT`. Both the path set and the summed bytes must match.

Final run on `E:\Projects\sweepx`: **36,531 = 36,531 paths, 14,487,653,815 = 14,487,653,815 bytes,
0 missing, 0 extra, 0 skipped.**

That test earned its place by failing twice, and both defects were silent under-reporting — the
worst kind, because the totals still looked exact:

1. **One path per record lost every extra hard link.** 8,932 paths and 1.3 GB missing, with
   `skipped=0`. An NTFS record holds one name per link and a walk sees all of them, so selection
   had to iterate directory entries, not records.
2. **Collapsing all names under one parent lost same-directory hard links.** 88 paths and 87 MB
   missing. The first fix assumed a second name under one parent could only be an 8.3 alias, but
   Cargo links `build-script-build.exe` to `build_script_build-<hash>.exe` in the same directory.
   The distinguishing evidence is the name flag, not the parent: only a name flagged DOS-without-
   NTFS is a duplicate. Diagnosing this required printing whether each missing path predated the
   snapshot — all 40 sampled did, which ruled out a live-tree race and pointed at selection.

Both are pinned by regression tests using the measured flag values.

### Where it surfaces

`--format ndjson` is disabled for `scan`, so the progress stream is not observable to users. The
outcome is therefore reported in the scan summary under `acceleration`:

- qualified: `{"used": true, "preview": {"entryCount", "logicalBytes", "elapsedMicros", "exact",
  "authoritative": false}}`
- declined: `{"used": false, "reason": "not_elevated", "elevationMightHelp": true}`

`exact` is false when any record under the root could not be resolved, marking the size a lower
bound that must never be rendered as precise.

## Volume change detection via the USN journal (2026-09-03)

The parser and cursor validation for the USN journal existed but had no caller: nothing captured a
position and nothing compared one, so layer 3 of the seven-layer scheme was inert. It is now a
usable primitive.

### What was measured

Elevated, on this host (`C:`, NTFS):

| Observation | Value |
|---|---|
| `FSCTL_QUERY_USN_JOURNAL`, unelevated | `ERROR_ACCESS_DENIED (5)` |
| `FSCTL_QUERY_USN_JOURNAL`, elevated `GENERIC_READ` | succeeds |
| Cost of one bounds read | 0.055 ms, mean of 50 calls |
| Whole-volume `FSCTL_QUERY_FILE_LAYOUT` read | 1.06 s |
| Verdict on an untouched volume | `unchanged` |
| Verdict after writing one file | `changed`, range starting exactly at the captured USN |

Validation is roughly four orders of magnitude cheaper than the metadata read it can avoid, which
is what makes the layer worth having. Both directions were exercised against the live volume: a
token that never matched would detect every change and still be useless, so "quiet stays quiet" is
asserted alongside "a write is noticed".

### What a token proves

`VolumeChangeToken` pairs the journal id with the volume's `NextUsn`. The journal id is part of the
identity because a deleted and recreated journal restarts numbering, so a bare USN can compare two
unrelated sequences as equal — the test for that case pins the same USN under a different journal
id and requires a rescan.

The token describes a **volume**, not a subtree. Equality proves no journal activity anywhere on
the volume, which is sufficient but stronger than necessary for any single root. Narrowing it would
mean resolving each changed record's parent chain, and a wrong answer there would serve stale sizes
for a directory the user just edited.

`compare_to_current` delegates to the existing `validate_usn_cursor` rather than restating its
rules, so there is only one implementation of what makes a cursor trustworthy. It adds one
judgement: an accepted cursor equal to `NextUsn` is `Unchanged`, otherwise it is `Changed` carrying
the exact range still to examine.

### Wired into the cache (2026-09-03)

The validity half now has a consumer. `store_stale_preview` captures a per-volume token after the
walk and stores it inside `StoredGeneration.validity`; `load_stale_preview` re-checks it and, when
every recorded volume compares `Unchanged`, reports `verified_preview` instead of `stale_preview`.

Three constraints fixed where the token lives, and they are worth keeping in mind before moving it:

- It is inside the generation payload, so the same atomic rename replaces data and evidence
  together. Two files could disagree after a crash, and the dangerous direction — fresh evidence
  vouching for stale data — is exactly the accident the journal exists to prevent. Being under the
  envelope checksum also means editing a token on disk costs the whole generation rather than
  buying a false `Unchanged`.
- It is `#[serde(default)]`, so every generation written before this existed reads back as *no*
  evidence and is never reusable. Absence fails closed and no migration is needed.
- It is a platform-neutral record (`kind` / `volume` / `sequence_id` / `position`) rather than a
  `VolumeChangeToken`, because `sweepx-cache` depends only on `sweepx-model`. Core owns the
  conversion, so the on-disk format does not acquire a Windows shape.

Reuse requires *all* recorded volumes to be unchanged, since one generation can span volumes. A
half-valid preview is worse than a miss: part of the tree would be correct and part stale, and it
would look correct.

Durable state on Windows is no longer the blocker — it landed with a current-user-private ACL and
reparse-point guard, and `%LOCALAPPDATA%\sweepx\state` persists across runs.

### The remaining blocker is elevation, and it cannot be worked around

Capture needs the journal, and the journal needs an elevated volume handle. Measured on this host
against `C:\` and `E:\`, trying access masks from cheapest upward:

| Access requested | `CreateFileW` | `FSCTL_QUERY_USN_JOURNAL` |
| --- | --- | --- |
| zero | opens | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_ATTRIBUTES` | opens | `ERROR_INVALID_FUNCTION` (1) |
| `SYNCHRONIZE` | opens | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_ATTRIBUTES \| SYNCHRONIZE` | opens | `ERROR_INVALID_FUNCTION` (1) |
| `FILE_READ_DATA` | `ERROR_ACCESS_DENIED` (5) | — |
| `GENERIC_READ` | `ERROR_ACCESS_DENIED` (5) | — |

There is no middle rung: the masks that open cannot issue the FSCTL, and the masks that could are
refused at open. So L3 raises an unelevated run's ceiling by nothing, and shares the elevation gate
with the accelerated reader rather than sitting behind a cheaper one.

Verified end to end unelevated: two consecutive scans store empty validity and the second reports
`stale_preview` with `cache.preview.unverified.no_evidence` — the pre-L3 behavior exactly, which is
the intended degradation.

Verified end to end **elevated** (2026-09-04, `E:\Projects\sweepx\crates\sweepx-cache`, state
directory on `C:`): the token is captured (`journal_id=134088063902297767`, `next_usn=837099952`), a
second scan of a quiescent volume reports `verified_preview`, and writing one file into the tree
drops the next scan back to `stale_preview` with `cache.preview.unverified.changed`. Both directions
matter: a token that never matched would also "detect every change" while being useless.

### A same-volume cache cannot verify, and two-phase writing does not fix it

When the state directory shares a volume with the scan root — **the default shape**, since
`%LOCALAPPDATA%` is on `C:` — the preview never reaches `verified_preview`. The cache's own write is
journalled on the volume it is recording, so the stored position is stale the instant it lands.

Measured on `C:` with a probe reading the journal directly:

| Activity | USN advance |
| --- | --- |
| idle, two reads back to back | 0 |
| one small file write | 240 |
| a cache-shaped write (two temp files, two renames) | 1080 |
| writes to `C:` only, measured on `E:` | 0 |

The idle delta of 0 confirms the volume-level token is not simply too noisy to be useful, and the
cross-volume 0 confirms volumes are independent — which is why the cross-volume case works.

The obvious fix, capturing the token *after* `write_generation` and rewriting the generation with
it, was implemented and measured: **it does not converge.** Four consecutive same-volume runs each
reported `cache.preview.unverified.changed`, because the second write is journalled exactly like the
first. It was reverted rather than tuned; adding a third write would only move the problem.

Excluding the cache's own records needs per-record attribution via `FSCTL_READ_USN_JOURNAL`, which
is not wired up. Until it is, a same-volume cache degrades to `stale_preview`, which is the pre-L3
behavior and never a false claim of freshness. A user who wants verified reuse today can put the
state directory on a different volume from the trees being scanned.

## Gate meanings

- Cross-compilation proves that conditional code type-checks; it does not prove kernel ABI behavior.
- A hosted Windows/macOS CI runner can close smoke and ordinary failure cases. It does not replace
  real HDD, removable, network, cloud-provider, journal-wrap, or large-volume evidence.
- Until the native functional gate passes, an accelerator remains experimental and the existing
  scanner is authoritative. Until the physical gate passes, SweepX makes no performance claim.
- Every fallback preserves cancellation, resource bounds, no-follow identity checks, lower-bound
  evidence, and the rule that display paths never grant filesystem authority.

Primary API references:

- <https://learn.microsoft.com/windows-hardware/drivers/ifs/fsctl-query-file-layout>
- <https://learn.microsoft.com/windows/win32/fileio/change-journals>
- <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getattrlistbulk.2.html>
- <https://developer.apple.com/documentation/iokit>
