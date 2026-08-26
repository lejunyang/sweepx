#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/sweepx-installer-test.XXXXXX")
outside_root=$(mktemp -d "${TMPDIR:-/tmp}/sweepx-installer-outside.XXXXXX")
target=
version=9.8.7
archive=
release_dir=

cleanup() {
  rm -rf "$test_root" "$outside_root"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'installer test: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print tolower($1) }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{ print tolower($1) }'
  else
    openssl dgst -sha256 "$1" | awk '{ print tolower($NF) }'
  fi
}

case $(uname -s):$(uname -m) in
  Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
  Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin:x86_64|Darwin:amd64) target=x86_64-apple-darwin ;;
  Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
  *) fail "unsupported installer-test host: $(uname -s) $(uname -m)" ;;
esac
archive=sweepx-v$version-$target.tar.gz
release_dir=$test_root/releases/download/v$version
latest_dir=$test_root/releases/latest/download

home_dir=$test_root/home
tmp_dir=$test_root/tmp
fixture_dir=$test_root/fixture
mkdir -p "$home_dir" "$tmp_dir" "$fixture_dir" "$release_dir" "$latest_dir"
printf '%s\n' \
  '#!/bin/sh' \
  "printf '%s\\n' 'fixture-sweepx'" \
  >"$fixture_dir/sweepx"
chmod 0755 "$fixture_dir/sweepx"
tar -C "$fixture_dir" -czf "$release_dir/$archive" sweepx
digest=$(sha256_file "$release_dir/$archive")
printf '%s  %s\n' "$digest" "$archive" >"$release_dir/SHA256SUMS"
cp "$release_dir/$archive" "$release_dir/SHA256SUMS" "$latest_dir/"

printf '%s\n' protected >"$outside_root/.profile"
printf '%s\n' protected >"$outside_root/.bashrc"
printf '%s\n' protected >"$outside_root/.zshrc"
outside_before=$(
  sha256_file "$outside_root/.profile"
  sha256_file "$outside_root/.bashrc"
  sha256_file "$outside_root/.zshrc"
)

run_installer() {
  env -i \
    HOME="$home_dir" \
    TMPDIR="$tmp_dir" \
    PATH="$PATH" \
    SHELL=/bin/sh \
    SWEEPX_NO_MODIFY_PATH=1 \
    sh "$repo_root/install.sh" "$@"
}

install_dir=$test_root/custom-bin
mkdir -p "$install_dir"
printf '%s\n' old-sweepx >"$install_dir/sweepx"
chmod 0755 "$install_dir/sweepx"
run_installer \
  --version "$version" \
  --base-url "file://$test_root/releases" \
  --install-dir "$install_dir" \
  --no-modify-path
[[ -x "$install_dir/sweepx" ]] || fail 'successful install did not create sweepx'
[[ $("$install_dir/sweepx") == fixture-sweepx ]] || fail 'installed binary content is wrong'
shopt -s dotglob nullglob
install_entries=("$install_dir"/*)
[[ ${#install_entries[@]} -eq 1 && ${install_entries[0]##*/} == sweepx ]] ||
  fail 'successful install left unexpected destination files'
[[ ! -e "$home_dir/.profile" ]] || fail '--no-modify-path wrote a shell profile'

latest_install_dir=$test_root/latest-bin
env -i \
  HOME="$home_dir" \
  TMPDIR="$tmp_dir" \
  PATH="$PATH" \
  SHELL=/bin/sh \
  SWEEPX_BIN_DIR="$latest_install_dir" \
  SWEEPX_BASE_URL="file://$test_root/releases" \
  SWEEPX_NO_MODIFY_PATH=1 \
  sh "$repo_root/install.sh"
[[ $("$latest_install_dir/sweepx") == fixture-sweepx ]] ||
  fail 'latest/default-environment install failed'

hash_failure_dir=$test_root/hash-failure-bin
mkdir -p "$hash_failure_dir"
printf '%s\n' old-sweepx >"$hash_failure_dir/sweepx"
chmod 0755 "$hash_failure_dir/sweepx"
printf '%064d  %s\n' 0 "$archive" >"$release_dir/SHA256SUMS"
if run_installer \
  --version "$version" \
  --base-url "file://$test_root/releases" \
  --install-dir "$hash_failure_dir" \
  --no-modify-path >"$test_root/hash.stdout" 2>"$test_root/hash.stderr"; then
  fail 'installer accepted an invalid checksum'
fi
grep -F 'checksum verification failed' "$test_root/hash.stderr" >/dev/null ||
  fail 'checksum failure did not report the expected error'
[[ $(<"$hash_failure_dir/sweepx") == old-sweepx ]] ||
  fail 'checksum failure changed the existing installation'

missing_dir=$test_root/missing-bin
mkdir -p "$missing_dir"
printf '%s\n' old-sweepx >"$missing_dir/sweepx"
chmod 0755 "$missing_dir/sweepx"
missing_release_dir=$test_root/releases/download/v9.8.6
missing_archive=sweepx-v9.8.6-$target.tar.gz
mkdir -p "$missing_release_dir"
printf '%064d  %s\n' 0 "$missing_archive" >"$missing_release_dir/SHA256SUMS"
if run_installer \
  --version 9.8.6 \
  --base-url "file://$test_root/releases" \
  --install-dir "$missing_dir" \
  --no-modify-path >"$test_root/missing.stdout" 2>"$test_root/missing.stderr"; then
  fail 'installer accepted a missing release artifact'
fi
grep -F "could not download $missing_archive" "$test_root/missing.stderr" >/dev/null ||
  fail 'missing release did not report the expected error'
[[ $(<"$missing_dir/sweepx") == old-sweepx ]] ||
  fail 'missing artifact changed the existing installation'
printf '%s  %s\n' "$digest" "$archive" >"$release_dir/SHA256SUMS"

outside_after=$(
  sha256_file "$outside_root/.profile"
  sha256_file "$outside_root/.bashrc"
  sha256_file "$outside_root/.zshrc"
)
[[ "$outside_after" == "$outside_before" ]] || fail 'installer wrote outside isolated roots'
tmp_entries=("$tmp_dir"/*)
[[ ${#tmp_entries[@]} -eq 0 ]] || fail 'installer left temporary files behind'

help_output=$(sh "$repo_root/install.sh" --help)
grep -F -- '--version <version>' <<<"$help_output" >/dev/null
grep -F -- '--install-dir <path>' <<<"$help_output" >/dev/null
grep -F -- '--base-url <url>' <<<"$help_output" >/dev/null
grep -F -- '--no-modify-path' <<<"$help_output" >/dev/null

quoted_home=$test_root/quoted-home
quoted_install_dir="$quoted_home/it's-bin"
mkdir -p "$quoted_home"
env -i \
  HOME="$quoted_home" \
  TMPDIR="$tmp_dir" \
  PATH="$PATH" \
  SHELL=/bin/sh \
  sh "$repo_root/install.sh" \
    --version "$version" \
    --base-url "file://$test_root/releases" \
    --install-dir "$quoted_install_dir" >/dev/null
expected_path_line="export PATH='$quoted_home/it'\\''s-bin':\$PATH"
grep -F -x "$expected_path_line" "$quoted_home/.profile" >/dev/null ||
  fail 'PATH profile entry did not safely quote the install directory'
profile_hash=$(sha256_file "$quoted_home/.profile")
env -i \
  HOME="$quoted_home" \
  TMPDIR="$tmp_dir" \
  PATH="$PATH" \
  SHELL=/bin/sh \
  sh "$repo_root/install.sh" \
    --version "$version" \
    --base-url "file://$test_root/releases" \
    --install-dir "$quoted_install_dir" >/dev/null
[[ $(sha256_file "$quoted_home/.profile") == "$profile_hash" ]] ||
  fail 'PATH profile entry was duplicated'

printf 'Unix installer tests passed.\n'
