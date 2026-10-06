# Bundled browser cleanup and local bridge

SweepX embeds this Manifest V3 extension and exports a private bundle containing the extension, a copied native host executable, its manifest and `INSTALL.txt`. No network download, listener, remote debugging, page injection or telemetry is used. The browser starts the native host when the review tab connects; no SweepX daemon needs to keep running.

## Installation and updates

```sh
sweepx browser-extension bundle --output /absolute/new-bundle
sweepx browser-extension register --browser chrome --bundle /absolute/new-bundle
```

In the matching browser profile, open Extensions, enable Developer mode and load `/absolute/new-bundle/extension` unpacked. For Edge register with `--browser edge`. Click SweepX and use Site storage to connect and scan. Choose the actual browser and profile directory (e.g. `Default`) in Connection & settings. Check the profile directory in the browser version information if unsure: extensions cannot prove the native profile identity.

`register` supports stable Chrome/Edge on macOS/Linux, uses the current user's official NativeMessagingHosts location and only allows the fixed unpacked extension ID. Existing final registration directories must be current-user private; unsafe permissions or linked ancestors are refused without repair. Exported bundles must match this SweepX build's embedded assets and executable digest. Windows bundles include the host executable and manifest, but require manual HKCU registration following `INSTALL.txt`; no registry automation is implemented. Beta/Dev native registration is not automated.

Update by exporting a NEW bundle from the new SweepX build, registering it with `--replace`, then loading/reloading the new extension directory in the browser. The old bundle is preserved. Replacement only admits an existing SweepX host registration and never overwrites another host. Keep the registered bundle at its installed location. This is a local development distribution, not a signed/store release; silent install and automatic store updates are not implemented. Organizational refusal is never bypassed.

The public manifest key pins the development ID `bcidfcdfefinmefhopannchcnicdopad`. It is not a secret, a code signature or user authentication; the private generation key is not shipped. Publishing to a store needs a separately verified signing/store identity and corresponding allowlist registration. Do not widen the allowlist to arbitrary extensions.

## List and clear in the extension

The extension requests the existing SweepX native browser analysis, displays exact-domain summaries, concrete storage keys/buckets and category totals with shared/unattributed bytes. Unknown (`?`), lower-bound (`≥`) and exact logical values stay separate. This is recognized default-location/default-partition storage, not every site's total footprint: legacy IndexedDB/CacheStorage and modern WebStorage can be attributed, whereas shared HTTP/code cache and shared databases generally cannot. Observations are non-atomic; live QuotaManager WAL is not replayed. Paths never become removal authority.

The workbench has single-language Chinese/English views, size summaries, searchable/sortable domain pages, a storage breakdown, human-readable partition context and expandable raw evidence. Connection configuration is separate from website review. Select a domain to inspect its rows. Complete recognized HTTP(S) origins can produce a reviewed plan; incomplete/unsupported rows refuse a cleanup selection. Choose website caches, or caches plus IndexedDB, Local Storage, Service Workers and website files. Confirm the active browser/profile and type the exact domain before applying. Keep the tab open until the browser API finishes, then rescan.

Removal is irreversible and has no Trash/SweepX undo. Website storage can contain unsynced drafts. Cookies, history, passwords, permissions, extension data and protected hosted apps are excluded. The origin API handles partitions together and cannot select one bucket. A completed browser request is not proof of site absence or reclaimed bytes; active websites may recreate data. Only `browsingData` and `nativeMessaging` permissions are requested, with no broad URL/host access. The Clear a website view works without connecting to SweepX: enter an exact hostname (explicitly selects its HTTP and HTTPS default-port origins) or an exact HTTP(S) origin with a port. Paths, credentials, wildcards and unrelated subdomains are refused. Size is unknown in this mode, and the current browser profile is confirmed directly rather than inventing a native profile directory. A local exported plan can also be imported without connecting. The extension does not offer an independent full-profile disk inventory: browsingData exposes removal, and chrome.storage measures the extension’s own storage, not every website’s files.

## Send a request from SweepX

```sh
sweepx browser-extension request --browser chrome --profile Default --domain example.com
sweepx browser-extension status
```

The CLI scans and queues one exact selection for up to 15 minutes. It does not delete, open a page, install software or silently choose a removal mode. Open/connect the extension review tab in the matching profile and check requests. Connecting checks requests immediately; visible, idle review tabs also poll every five seconds without replacing a domain under review. The explicit Check requests button works during domain review, and an incoming request resets all removal confirmations. Request status distinguishes no request, an expired request, another browser/profile target and a read error. The page rechecks the queued request deadline immediately before calling the browser removal API, even if the button was enabled earlier. Reconnecting allows the same unhandled request to be reviewed again. The user can reject the request or confirm clearing. Acknowledgements retain the selected plan, mode and browser-reported status; they explicitly leave reclaimed bytes unknown and independent verification false. Requests expire; an expired or mismatched acknowledgement is refused. If a browser operation finishes but acknowledgement fails, the extension distinguishes that failure from the completed operation.

A separate private `.sweepx-browser-bridge` root stores at most `pending.json`, `result.json` and its lock, rather than an unbounded queue/history. The host exposes only hello, scan, plan, pending and completion messages: no arbitrary paths, shell commands or filesystem deletion. Input is capped at 64 KiB, output at 768 KiB per frame, input queue at eight frames; inventory is paged and staged until completion. The extension bounds retained pages and pending requests, disconnects on timeout and rejects unfinished responses. Browser disconnect cancels cooperative native traversal; a blocking OS call can still delay cancellation.

## Verification

```sh
cd crates/sweepx-cli/browser-ui
pnpm install --frozen-lockfile --ignore-scripts
pnpm check
pnpm format:check
pnpm test
cd ../../..
cargo test -p sweepx-cli browser_extension --all-features
cargo test -p sweepx-cli --test browser_bridge --all-features
```

See [frontend source/build/preview instructions](../../browser-ui/README.md). Tests cover wire framing/bounds, private mailbox refusal, stable identity, exact origin scope, asynchronous browser API failure and real exported-host scan/request/rejection with isolated data. Actual Chrome/Edge extension installation and browser-managed deletion remain native acceptance steps; process tests do not prove them. See [Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [external installation constraints](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions), [browsingData](https://developer.chrome.com/docs/extensions/reference/api/browsingData) and [Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging).

Official API sources accessed 2026-10-06: [browsingData](https://developer.chrome.com/docs/extensions/reference/api/browsingData), [extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage). The absence of a comparable public full-profile byte inventory is an inference from these documented capabilities under the extension’s two existing permissions.
