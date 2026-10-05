# Browser-managed website removal

The extension must be installed separately in Chrome/Edge. SweepX alone can analyze and export plans but cannot perform domain removal. This optional local extension clears selected origins using Chrome/Edge's `browsingData` API. It does not unlink browser database directories. No network, host permission, remote debugging, telemetry or external service is used. Its only permission is `browsingData`; install it manually only in the browser profile you intend to clean.

1. Export an explicit selection: `sweepx site-storage --browser edge --profile Default --domain example.com --export-delete-plan /absolute/new-plan.json`.
2. In the matching browser profile, enable extension developer mode and load this directory as an unpacked extension. Organizational policy may prohibit this; SweepX does not bypass it.
3. Click the SweepX extension, load the local plan, review browser/profile and exact origins, and choose caches or caches plus website storage. Confirm the profile and type the exact domain before applying.
4. Keep the review tab open until the browser returns completion. Rescan in SweepX to verify current storage. Active websites can recreate data; completion does not prove reclaimed bytes.

Browser removal has no Trash recovery. Storage can contain unsynced drafts. Cookies, history, passwords, permissions, extension data and protected hosted apps are excluded. The origin-based API does not let this adapter select one partition or bucket. The extension cannot read the native profile identity: the active profile is explicitly confirmed by the user. A completed callback confirms the API request, not every site's absence or a particular disk delta.

The adapter's input, scope and asynchronous completion contracts have local tests (`node --test integrations/chromium-cleanup/logic.test.mjs`). Actual Chrome/Edge extension installation and deletion remain a separate native acceptance step. See the [official API](https://developer.chrome.com/docs/extensions/reference/api/browsingData) for supported scope and behavior.
