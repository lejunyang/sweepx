# SweepX Chromium cleanup extension

The adapter is now bundled in the SweepX executable. Its single source is [`crates/sweepx-cli/assets/chromium-cleanup`](../../crates/sweepx-cli/assets/chromium-cleanup/README.md), so Cargo packages and binary releases include the same reviewed assets without a separate download.

```sh
sweepx browser-extension bundle --output /absolute/new-bundle
sweepx browser-extension register --browser chrome --bundle /absolute/new-bundle
```

Load `/absolute/new-bundle/extension` as an unpacked extension in the matching Chrome/Edge profile, then click SweepX and connect. For Edge use `--browser edge`. Registration is supported on macOS/Linux stable channels; Windows registration is manual as described in the exported `INSTALL.txt`. Browser installation, permission acceptance and extension reload remain user actions. SweepX does not alter enterprise policy or claim store publication.

See the [adapter guide](../../crates/sweepx-cli/assets/chromium-cleanup/README.md) for inventory coverage, requests, update steps, deletion scope and verification limits.
