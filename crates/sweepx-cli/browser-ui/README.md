# Browser cleanup UI

The frontend source lives here; compiled `review.html`, `review.css` and `review.mjs`
in [the extension assets](../assets/chromium-cleanup/) are committed and embedded by
Rust. SweepX users do not need Node. The page has no runtime framework or remote
dependencies. Shared `logic.mjs` and `bridge.mjs` remain the sole removal and Native
Messaging implementations. UI summaries never become execution authority.

With Node 24.15+ and the pinned pnpm version:

```sh
cd crates/sweepx-cli/browser-ui
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm check
pnpm format:check
pnpm test
pnpm preview
```

`build` generates embedded assets. `check` compares all generated output with the
committed files; CI refuses stale output. Format source with Prettier before building.
Dependency installation scripts are disabled; esbuild uses its optional platform binary.

`preview` serves a static, whitelisted development page at `http://127.0.0.1:4173/`.
All data is fictional, and clearing is inert. It never reads browser profiles, exposes
a native host, or invokes the actual browsingData API. The preview entry and fixtures
are **not exported** in the extension bundle. HTTP preview verification is separate
from installation and actual browser-managed removal acceptance.

The presentation model preserves unknown/lower-bound logical sizes and unfamiliar
partition keys. Domain and storage-detail pages create at most 50 rows each, while
totals include the bounded complete inventory. Scan responses remain staged until
completion. Language and target preferences use a small, optional localStorage value;
no scan facts, plan, confirmation or cleanup result is persisted as authority.

DOM tests exercise the compiled page against an independently controlled native port
and removal promise. They cover reconnection, manual versus automatic checks, request
expiry at action time, rejection, cancellation, standalone scope, failure and completion.
See [the installation and cleanup guide](../assets/chromium-cleanup/README.md).
