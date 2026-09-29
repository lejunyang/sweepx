#!/usr/bin/env bash
# Lint the workspace (default: sweepx-cli) against a non-host Rust target using Zig as the
# cross C toolchain.
#
# Why this exists: rusqlite's `bundled` feature compiles C for the *target*, so building the
# linux std off macOS needs a libc-bearing C compiler. Zig carries its own libc; the macOS SDK
# cannot target linux. cc-rs additionally appends `--target=<rust-triple>`, which Zig rejects
# (its own spelling differs, e.g. `x86_64-linux-gnu`), so the CC wrapper must strip the caller
# flag and pin Zig's. A wrapper that merely prepends `--target` fails because the last value wins.
set -euo pipefail

RUST_TARGET="${1:-x86_64-unknown-linux-gnu}"
CRATE="${2:-sweepx-cli}"
# Map the Rust target triple to Zig's `-target` spelling.
case "$RUST_TARGET" in
    x86_64-unknown-linux-gnu)  ZIG_TARGET="x86_64-linux-gnu" ;;
    aarch64-unknown-linux-gnu) ZIG_TARGET="aarch64-linux-gnu" ;;
    x86_64-unknown-linux-musl) ZIG_TARGET="x86_64-linux-musl" ;;
    *) echo "unsupported rust target: $RUST_TARGET" >&2; exit 2 ;;
esac

# Resolve the real Zig executable, not the osdk version-selector shim: cc-rs spawns this
# wrapper with a cwd/env where the project pin is not visible and the shim would refuse.
ZIG_INSTALL_DIR="$(osdk where zig 2>/dev/null | tail -1 || true)"
if [[ -n "$ZIG_INSTALL_DIR" && -x "$ZIG_INSTALL_DIR/zig" ]]; then
    ZIG_BIN="$ZIG_INSTALL_DIR/zig"
else
    ZIG_BIN="$(command -v zig)"
fi
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# CC wrapper: forward every argument except cc-rs's own `--target` (both `--target x` and
# `--target=x` forms), then invoke Zig with the pinned spelling.
CC_WRAPPER="$WORKDIR/cc-wrap"
cat > "$CC_WRAPPER" <<EOF
#!/usr/bin/env bash
args=()
skip_next=0
for arg in "\$@"; do
    if (( skip_next )); then skip_next=0; continue; fi
    case "\$arg" in
        --target=*) continue ;;
        --target)   skip_next=1; continue ;;
        *) args+=("\$arg") ;;
    esac
done
exec "$ZIG_BIN" cc -target "$ZIG_TARGET" "\${args[@]}"
EOF
chmod +x "$CC_WRAPPER"

# Archiver wrapper: Zig's ar handles linux objects; the host ar may not.
AR_WRAPPER="$WORKDIR/ar-wrap"
cat > "$AR_WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$ZIG_BIN" ar "\$@"
EOF
chmod +x "$AR_WRAPPER"

# Encode the Rust triple as the cc-rs env-var spelling (lowercase, underscores).
ENV_TARGET="$(printf '%s' "$RUST_TARGET" | tr 'a-z-' 'a-z_')"
export "CC_${ENV_TARGET}=$CC_WRAPPER"
export "AR_${ENV_TARGET}=$AR_WRAPPER"

# `all` sweeps the whole workspace; anything else selects one crate. The workspace sweep is the
# pre-push gate (cargo only lints the cfg branches selected for the host), while a single crate
# is the fast in-the-loop path.
if [[ "$CRATE" == "all" ]]; then
    exec cargo clippy --workspace --all-targets --all-features \
        --target "$RUST_TARGET" -- -D warnings
fi
exec cargo clippy -p "$CRATE" --all-targets --all-features \
    --target "$RUST_TARGET" -- -D warnings
