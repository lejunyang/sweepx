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
  The ordinary scanner remains authoritative while path reconstruction and complete semantic parity
  are unfinished. Native Windows CI runs the ignored probe explicitly and accepts only an available
  result or one of the enumerated safe fallbacks.
- Device classification and adaptive scheduling are not yet implemented. SweepX retains its
  existing bounded four-worker default until the native probes and physical-device benchmarks exist.

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
