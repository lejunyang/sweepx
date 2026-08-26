#!/bin/sh

set -eu

DEFAULT_BASE_URL=https://github.com/lejunyang/sweepx/releases
VERSION=${SWEEPX_VERSION:-latest}
BASE_URL=${SWEEPX_BASE_URL:-${SWEEPX_DOWNLOAD_BASE_URL:-$DEFAULT_BASE_URL}}
INSTALL_DIR=${SWEEPX_BIN_DIR:-${HOME:+$HOME/.local/bin}}
NO_MODIFY_PATH=${SWEEPX_NO_MODIFY_PATH:-0}
WORK_DIR=
STAGED_BINARY=

usage() {
  cat <<'EOF'
Install SweepX from a release archive.

Usage:
  install.sh [options]

Options:
  --version <version>   Release version, with or without the leading "v"
                        (default: latest)
  --install-dir <path>  Binary directory (default: SWEEPX_BIN_DIR or
                        $HOME/.local/bin)
  --base-url <url>      Release URL root (default:
                        https://github.com/lejunyang/sweepx/releases)
  --no-modify-path      Do not add the install directory to a shell profile
  -h, --help            Show this help

Environment equivalents:
  SWEEPX_VERSION, SWEEPX_BIN_DIR, SWEEPX_BASE_URL,
  SWEEPX_NO_MODIFY_PATH
EOF
}

fail() {
  printf 'sweepx installer: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  if [ -n "$STAGED_BINARY" ]; then
    rm -f "$STAGED_BINARY" 2>/dev/null || :
  fi
  if [ -n "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR" 2>/dev/null || :
  fi
  exit "$status"
}

on_signal() {
  exit 1
}

need_value() {
  [ "$#" -ge 2 ] || fail "$1 requires a value"
  [ -n "$2" ] || fail "$1 requires a non-empty value"
}

while [ "$#" -gt 0 ]; do
  case $1 in
    --version)
      need_value "$@"
      VERSION=$2
      shift 2
      ;;
    --install-dir)
      need_value "$@"
      INSTALL_DIR=$2
      shift 2
      ;;
    --base-url)
      need_value "$@"
      BASE_URL=$2
      shift 2
      ;;
    --no-modify-path)
      NO_MODIFY_PATH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

[ -n "$INSTALL_DIR" ] ||
  fail 'HOME is not set; pass --install-dir or set SWEEPX_BIN_DIR'
[ -n "$BASE_URL" ] || fail '--base-url must not be empty'
newline='
'
carriage_return=$(printf '\r')
case $INSTALL_DIR$BASE_URL in
  *"$newline"*|*"$carriage_return"*)
    fail 'paths and URLs must not contain newlines'
    ;;
esac
case $NO_MODIFY_PATH in
  0|1) ;;
  *) fail 'SWEEPX_NO_MODIFY_PATH must be 0 or 1' ;;
esac

case $INSTALL_DIR in
  /*) ;;
  *) INSTALL_DIR=$(pwd)/$INSTALL_DIR ;;
esac

detect_target() {
  kernel=$(uname -s 2>/dev/null) || fail 'could not detect the operating system'
  machine=$(uname -m 2>/dev/null) || fail 'could not detect the CPU architecture'

  case $kernel:$machine in
    Linux:x86_64|Linux:amd64)
      printf '%s\n' x86_64-unknown-linux-gnu
      ;;
    Linux:aarch64|Linux:arm64)
      printf '%s\n' aarch64-unknown-linux-gnu
      ;;
    Darwin:x86_64|Darwin:amd64)
      printf '%s\n' x86_64-apple-darwin
      ;;
    Darwin:arm64|Darwin:aarch64)
      printf '%s\n' aarch64-apple-darwin
      ;;
    *)
      fail "unsupported platform: $kernel $machine"
      ;;
  esac
}

download() {
  source_url=$1
  destination=$2

  case $source_url in
    file://*)
      cp "${source_url#file://}" "$destination"
      return
      ;;
    /*)
      cp "$source_url" "$destination"
      return
      ;;
  esac

  if command -v curl >/dev/null 2>&1; then
    curl --disable --fail --location --silent --show-error \
      --retry 2 --connect-timeout 15 --proto '=https,http,file' \
      --output "$destination" "$source_url"
  elif command -v wget >/dev/null 2>&1; then
    wget --quiet --output-document="$destination" "$source_url"
  else
    fail 'curl or wget is required'
  fi
}

sha256_file() {
  file=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{ print tolower($1) }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{ print tolower($1) }'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{ print tolower($NF) }'
  else
    fail 'sha256sum, shasum, or openssl is required for checksum verification'
  fi
}

checksum_for() {
  manifest=$1
  wanted=$2
  awk -v wanted="$wanted" '
    NF == 2 {
      hash = $1
      name = $2
      sub(/^\*/, "", name)
      sub(/\r$/, "", name)
      if (name == wanted && length(hash) == 64 && hash !~ /[^0-9A-Fa-f]/) {
        count++
        result = tolower(hash)
      }
    }
    END {
      if (count == 1) {
        print result
      } else {
        exit 1
      }
    }
  ' "$manifest"
}

latest_archive_for() {
  manifest=$1
  target=$2
  suffix=-$target.tar.gz
  awk -v suffix="$suffix" '
    NF == 2 {
      hash = $1
      name = $2
      sub(/^\*/, "", name)
      sub(/\r$/, "", name)
      prefix = "sweepx-v"
      if (length(hash) != 64 || hash ~ /[^0-9A-Fa-f]/ ||
          index(name, prefix) != 1 ||
          length(name) <= length(prefix) + length(suffix) ||
          substr(name, length(name) - length(suffix) + 1) != suffix) {
        next
      }
      version = substr(name, length(prefix) + 1,
        length(name) - length(prefix) - length(suffix))
      if (version !~ /^[0-9][0-9A-Za-z._+-]*$/) {
        next
      }
      count++
      result = name
    }
    END {
      if (count == 1) {
        print result
      } else {
        exit 1
      }
    }
  ' "$manifest"
}

shell_quote() {
  escaped=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
  printf "'%s'" "$escaped"
}

add_to_path() {
  case :${PATH:-}: in
    *:"$INSTALL_DIR":*)
      return 0
      ;;
  esac

  if [ -z "${HOME:-}" ]; then
    printf 'sweepx installer: warning: HOME is unset; PATH was not modified.\n' >&2
    printf 'Add %s to PATH manually.\n' "$INSTALL_DIR" >&2
    return 0
  fi

  shell_path=${SHELL:-}
  shell_name=${shell_path##*/}
  case $shell_name in
    zsh) profile=$HOME/.zshrc ;;
    bash) profile=$HOME/.bashrc ;;
    *) profile=$HOME/.profile ;;
  esac
  if [ -L "$profile" ] || { [ -e "$profile" ] && [ ! -f "$profile" ]; }; then
    printf 'sweepx installer: warning: refusing to modify non-regular profile %s\n' \
      "$profile" >&2
    printf 'Add %s to PATH manually.\n' "$INSTALL_DIR" >&2
    return 0
  fi

  quoted_dir=$(shell_quote "$INSTALL_DIR")
  path_line="export PATH=$quoted_dir:\$PATH"
  if [ -f "$profile" ] && grep -F -x "$path_line" "$profile" >/dev/null 2>&1; then
    return 0
  fi

  if {
    printf '\n# Added by the SweepX installer.\n%s\n' "$path_line" >>"$profile"
  } 2>/dev/null; then
    printf 'Added %s to PATH in %s. Restart your shell to use sweepx.\n' \
      "$INSTALL_DIR" "$profile"
  else
    printf 'sweepx installer: warning: could not update %s\n' "$profile" >&2
    printf 'Add %s to PATH manually.\n' "$INSTALL_DIR" >&2
  fi
}

command -v tar >/dev/null 2>&1 || fail 'tar is required'
command -v awk >/dev/null 2>&1 || fail 'awk is required'
TARGET=$(detect_target)

case $VERSION in
  latest)
    release_path=latest/download
    ;;
  v*)
    normalized_version=${VERSION#v}
    ;;
  *)
    normalized_version=$VERSION
    ;;
esac

if [ "$VERSION" != latest ]; then
  case $normalized_version in
    ''|[!0-9]*|*[!0-9A-Za-z._+-]*)
      fail "invalid release version: $VERSION"
      ;;
  esac
  release_path=download/v$normalized_version
  archive=sweepx-v$normalized_version-$TARGET.tar.gz
fi

BASE_URL=${BASE_URL%/}
umask 077
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sweepx-install.XXXXXX") ||
  fail 'could not create a temporary directory'
trap cleanup 0
trap on_signal HUP INT TERM

checksums=$WORK_DIR/SHA256SUMS
release_url=$BASE_URL/$release_path
printf 'Downloading checksums from %s/SHA256SUMS\n' "$release_url"
download "$release_url/SHA256SUMS" "$checksums" ||
  fail 'could not download SHA256SUMS'

if [ "$VERSION" = latest ]; then
  archive=$(latest_archive_for "$checksums" "$TARGET") ||
    fail "SHA256SUMS does not contain exactly one SweepX archive for $TARGET"
fi
expected=$(checksum_for "$checksums" "$archive") ||
  fail "SHA256SUMS does not contain exactly one valid checksum for $archive"

archive_path=$WORK_DIR/$archive
printf 'Downloading %s\n' "$release_url/$archive"
download "$release_url/$archive" "$archive_path" ||
  fail "could not download $archive"
actual=$(sha256_file "$archive_path") || fail "could not hash $archive"
[ "$actual" = "$expected" ] || fail "checksum verification failed for $archive"
printf 'Verified SHA-256 checksum for %s.\n' "$archive"

members=$WORK_DIR/archive-members
tar -tzf "$archive_path" >"$members" || fail "could not inspect $archive"
member=$(awk '
  $0 == "sweepx" || $0 == "./sweepx" { count++; result = $0; next }
  { unexpected++ }
  END { if (count == 1 && unexpected == 0) print result; else exit 1 }
' "$members") || fail "$archive must contain only one root-level sweepx binary"
unpack_dir=$WORK_DIR/unpack
mkdir "$unpack_dir" || fail 'could not create the extraction directory'
tar -xzf "$archive_path" -C "$unpack_dir" || fail "could not extract $archive"
case $member in
  ./sweepx) extracted=$unpack_dir/sweepx ;;
  *) extracted=$unpack_dir/$member ;;
esac
[ -f "$extracted" ] && [ ! -L "$extracted" ] ||
  fail "the sweepx entry in $archive is not a regular file"
[ -s "$extracted" ] || fail "the sweepx binary in $archive is empty"
chmod 0755 "$extracted" || fail 'could not mark sweepx executable'

mkdir -p "$INSTALL_DIR" || fail "could not create $INSTALL_DIR"
[ -d "$INSTALL_DIR" ] || fail "install path is not a directory: $INSTALL_DIR"
destination=$INSTALL_DIR/sweepx
if [ -e "$destination" ] || [ -L "$destination" ]; then
  [ -f "$destination" ] && [ ! -L "$destination" ] ||
    fail "install destination is not a regular file: $destination"
fi
STAGED_BINARY=$(mktemp "$INSTALL_DIR/.sweepx-install.XXXXXX") ||
  fail "could not stage sweepx in $INSTALL_DIR"
cp "$extracted" "$STAGED_BINARY" || fail 'could not stage sweepx'
chmod 0755 "$STAGED_BINARY" || fail 'could not set sweepx permissions'
mv -f "$STAGED_BINARY" "$destination" || fail "could not install $destination"
STAGED_BINARY=

printf 'Installed sweepx to %s\n' "$destination"
if [ "$NO_MODIFY_PATH" = 0 ]; then
  add_to_path
else
  case :${PATH:-}: in
    *:"$INSTALL_DIR":*) ;;
    *) printf 'PATH was not modified. Add %s to PATH to use sweepx.\n' "$INSTALL_DIR" ;;
  esac
fi
