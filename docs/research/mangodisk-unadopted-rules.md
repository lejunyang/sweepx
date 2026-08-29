# MangoDisk rules not yet adopted by SweepX

Source snapshot date: 2026-08-30. Upstream commit:
`b011da813795e3221022b6b731be998a2eb2bf2f`.

SweepX has not imported any MangoDisk rule definition. Its current platform cache reports overlap
with some upstream locations at a coarser level, but that is not equivalent to adopting the named
rule, matcher, process policy, risk, or execution behavior. The generated
[`mangodisk-rule-source-audit.csv`](mangodisk-rule-source-audit.csv) is the exact 205-row inventory.

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

## Next admission batches

1. **Official tool caches:** Cargo, npm, pnpm, Go, uv, pip, Gradle, Maven, NuGet, ccache, and
   browser-automation caches. Resolve effective configured locations; prefer each tool's supported
   clean/prune interface for future mutation.
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
