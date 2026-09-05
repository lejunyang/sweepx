#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: scripts/publish-crates.sh [--check]

Publish all SweepX crates to crates.io in dependency order. The helper skips a
crate only when crates.io already contains its exact name, version, and local
package checksum. Failed publishes are retried a bounded number of times to
tolerate index propagation.

Environment:
  CARGO_REGISTRY_TOKEN          Required for publishing; never passed on argv.
  PUBLISH_MAX_ATTEMPTS          Attempts per crate (default 5, range 1..10).
  PUBLISH_RETRY_DELAY_SECONDS   Initial delay (default 15, range 1..120).
EOF
}

fail() {
  printf 'crates publish error: %s\n' "$*" >&2
  exit 1
}

check_only=false
while (($# > 0)); do
  case $1 in
    --check)
      check_only=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

max_attempts=${PUBLISH_MAX_ATTEMPTS:-5}
initial_delay=${PUBLISH_RETRY_DELAY_SECONDS:-15}
if ! [[ $max_attempts =~ ^[0-9]+$ ]] ||
  ! ((10#$max_attempts >= 1 && 10#$max_attempts <= 10)); then
  fail 'PUBLISH_MAX_ATTEMPTS must be an integer from 1 through 10'
fi
if ! [[ $initial_delay =~ ^[0-9]+$ ]] ||
  ! ((10#$initial_delay >= 1 && 10#$initial_delay <= 120)); then
  fail 'PUBLISH_RETRY_DELAY_SECONDS must be an integer from 1 through 120'
fi
max_attempts=$((10#$max_attempts))
initial_delay=$((10#$initial_delay))

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'
if command -v sha256sum >/dev/null 2>&1; then
  sha256_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  sha256_command=shasum
else
  fail 'sha256sum or shasum is required'
fi
if [[ $check_only == false && -z ${CARGO_REGISTRY_TOKEN:-} ]]; then
  fail 'CARGO_REGISTRY_TOKEN is required'
fi

# Exact topological order. Keep leaf crates before every workspace dependent.
publish_order=(
  sweepx-canonical
  sweepx-i18n
  sweepx-model
  sweepx-cache
  sweepx-cleaner-schema
  sweepx-fixtures
  sweepx-platform
  sweepx-protocol
  sweepx-audit
  sweepx-catalog
  sweepx-cleaner-vm
  sweepx-event-journal
  sweepx-platform-linux
  sweepx-platform-macos
  sweepx-platform-windows
  sweepx-tui
  sweepx-scanner
  sweepx-analysis
  sweepx-core
  sweepx-safety
  sweepx-cli
  sweepx-executor
)

metadata_file=$(mktemp)
package_file=$(mktemp)
package_target=$(mktemp -d)
response_file=
fetched_checksum=
cleanup() {
  rm -f -- "$metadata_file" "$package_file"
  [[ -z $response_file ]] || rm -f -- "$response_file"
  rm -rf -- "$package_target"
}
trap cleanup EXIT

cargo metadata --locked --all-features --format-version 1 >"$metadata_file"
python3 - "$metadata_file" "${publish_order[@]}" >"$package_file" <<'PY'
import json
import sys

metadata_path, *order = sys.argv[1:]
with open(metadata_path, encoding="utf-8") as handle:
    metadata = json.load(handle)

members = set(metadata["workspace_members"])
all_packages = {
    package["name"]: package
    for package in metadata["packages"]
    if package["id"] in members
}
# A publish=false crate is intentionally not a release artifact: sweepx-cleaner-sign
# carries signing authority and must stay off crates.io. Coverage is therefore asserted
# against the publishable set, so such a crate belongs in neither publish_order nor the
# missing list. Leaving it in the comparison made the two release gates unsatisfiable:
# this script demanded its presence while check-release-metadata.sh rejected it.
unpublishable = sorted(
    name for name, package in all_packages.items() if package.get("publish") == []
)
packages = {
    name: package
    for name, package in all_packages.items()
    if package.get("publish") != []
}
resolved_by_id = {
    node["id"]: set(node["dependencies"])
    for node in metadata["resolve"]["nodes"]
}

missing = sorted(set(packages) - set(order))
extra = sorted(set(order) - set(packages))
if missing or extra or len(order) != len(set(order)):
    raise SystemExit(
        "publish order does not exactly cover the publishable workspace; "
        f"missing={missing}, extra={extra}, duplicates={len(order) != len(set(order))}, "
        f"excluded_unpublishable={unpublishable}"
    )

position = {name: index for index, name in enumerate(order)}
for name in order:
    package = packages[name]
    if package.get("publish") == []:
        raise SystemExit(f"{name} has publish=false")
    for dependency in package["dependencies"]:
        dependency_name = dependency["name"]
        if not dependency.get("path"):
            continue
        # Narrowing `packages` to the publishable set would otherwise silently skip a
        # path dependency on an unpublishable crate, which cannot resolve from crates.io
        # and would fail mid-publish after earlier crates were already uploaded.
        if dependency_name in unpublishable:
            raise SystemExit(
                f"{name} depends on publish=false crate {dependency_name}; "
                "it could never be published from crates.io"
            )
        if dependency_name not in packages:
            continue
        if dependency.get("req") in (None, "", "*"):
            raise SystemExit(
                f"{name} dependency {dependency_name} needs a crates.io version requirement"
            )
        dependency_package = packages[dependency_name]
        if dependency_package["id"] not in resolved_by_id.get(package["id"], set()):
            raise SystemExit(
                f"{name} dependency requirement {dependency['req']!r} does not admit "
                f"workspace {dependency_name}@{dependency_package['version']}"
            )
        if position[dependency_name] >= position[name]:
            raise SystemExit(
                f"publish order places {name} before dependency {dependency_name}"
            )
    print(f"{name}\t{package['version']}")
PY

sha256_file() {
  local path=$1
  if [[ $sha256_command == sha256sum ]]; then
    sha256sum -- "$path" | awk '{print tolower($1)}'
  else
    shasum -a 256 -- "$path" | awk '{print tolower($1)}'
  fi
}

package_path() {
  local crate=$1
  local version=$2
  printf '%s/package/%s-%s.crate\n' "$package_target" "$crate" "$version"
}

package_workspace_for_check() {
  # `cargo package --workspace` resolves path dependencies as one batch. This
  # lets preflight produce every archive before the first SweepX crate exists
  # on crates.io. The release workflow separately builds and tests the source.
  cargo package \
    --locked \
    --allow-dirty \
    --no-verify \
    --workspace \
    --target-dir "$package_target"
}

package_crate() {
  local crate=$1
  local version=$2
  local expected_path
  local attempt
  local delay=$initial_delay
  expected_path=$(package_path "$crate" "$version")

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    rm -f -- "$expected_path"
    if cargo package \
      --locked \
      --allow-dirty \
      --package "$crate" \
      --target-dir "$package_target"; then
      [[ -f $expected_path ]] || fail "cargo package did not create $expected_path"
      printf '%s\n' "$expected_path"
      return 0
    fi

    if ((attempt < max_attempts)); then
      printf 'Packaging %s@%s failed; retrying in %d seconds for registry propagation.\n' \
        "$crate" "$version" "$delay" >&2
      sleep "$delay"
      delay=$((delay * 2))
      ((delay <= 120)) || delay=120
    fi
  done

  fail "could not package $crate@$version after $max_attempts attempts"
}

if [[ $check_only == true ]]; then
  package_workspace_for_check
fi

fetch_remote_checksum() {
  local crate=$1
  local version=$2
  local response_file
  local status
  local curl_status
  local parsed_checksum

  fetched_checksum=
  response_file=$package_target/crates-io-response.json
  rm -f -- "$response_file"
  set +e
  status=$(curl \
    --silent \
    --show-error \
    --location \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 15 \
    --max-time 45 \
    --user-agent 'sweepx-release-helper/1' \
    --output "$response_file" \
    --write-out '%{http_code}' \
    "https://crates.io/api/v1/crates/$crate/$version")
  curl_status=$?
  set -e

  if ((curl_status != 0)); then
    rm -f -- "$response_file"
    fail "crates.io lookup failed for $crate@$version"
  fi
  case $status in
    200)
      set +e
      parsed_checksum=$(python3 - "$response_file" "$crate" "$version" <<'PY'
import json
import re
import sys

path, expected_crate, expected_version = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    payload = json.load(handle)
record = payload.get("version") or {}
if record.get("crate") != expected_crate or record.get("num") != expected_version:
    raise SystemExit("crates.io returned the wrong crate/version record")
checksum = record.get("checksum", "")
if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
    raise SystemExit("crates.io returned an invalid package checksum")
print(checksum.lower())
PY
      )
      parse_status=$?
      set -e
      rm -f -- "$response_file"
      ((parse_status == 0)) || fail "invalid crates.io response for $crate@$version"
      fetched_checksum=$parsed_checksum
      return 0
      ;;
    404)
      rm -f -- "$response_file"
      return 1
      ;;
    *)
      rm -f -- "$response_file"
      fail "crates.io returned HTTP $status for $crate@$version"
      ;;
  esac
}

verify_remote_checksum() {
  local crate=$1
  local version=$2
  local local_checksum=$3

  if ! fetch_remote_checksum "$crate" "$version"; then
    return 1
  fi
  verify_checksum_match "$crate" "$version" "$local_checksum" "$fetched_checksum"
}

verify_checksum_match() {
  local crate=$1
  local version=$2
  local local_checksum=$3
  local remote_checksum=$4

  if [[ $local_checksum != "$remote_checksum" ]]; then
    fail "checksum mismatch for published $crate@$version: local=$local_checksum crates.io=$remote_checksum"
  fi
  printf 'Verified existing crate checksum: %s@%s (%s).\n' \
    "$crate" "$version" "$local_checksum"
}

while IFS=$'\t' read -r crate version; do
  [[ -n $crate && -n $version ]] || fail 'invalid generated package list'
  if [[ $check_only == true ]]; then
    crate_file=$(package_path "$crate" "$version")
    [[ -f $crate_file ]] || fail "cargo package did not create $crate_file"
    if fetch_remote_checksum "$crate" "$version"; then
      # Existing versions must also pass the exact per-package command used by
      # real publication, including Cargo's package verification build.
      crate_file=$(package_crate "$crate" "$version")
      local_checksum=$(sha256_file "$crate_file")
      [[ $local_checksum =~ ^[0-9a-f]{64}$ ]] || fail "could not hash $crate_file"
      verify_checksum_match "$crate" "$version" "$local_checksum" "$fetched_checksum"
      printf 'Already published with identical package bytes: %s@%s\n' \
        "$crate" "$version"
    else
      local_checksum=$(sha256_file "$crate_file")
      [[ $local_checksum =~ ^[0-9a-f]{64}$ ]] || fail "could not hash $crate_file"
      printf 'Unpublished: %s@%s (local checksum %s; publish mode will run exact per-crate packaging)\n' \
        "$crate" "$version" "$local_checksum"
    fi
    continue
  fi

  crate_file=$(package_crate "$crate" "$version")
  local_checksum=$(sha256_file "$crate_file")
  [[ $local_checksum =~ ^[0-9a-f]{64}$ ]] || fail "could not hash $crate_file"

  if verify_remote_checksum "$crate" "$version" "$local_checksum"; then
    printf 'Already published with identical package bytes; skipping: %s@%s\n' \
      "$crate" "$version"
    continue
  fi

  # Cargo reads CARGO_REGISTRY_TOKEN from the environment. Never put it on the
  # command line, where process listings and workflow logs could expose it.
  delay=$initial_delay
  published=false
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    printf 'Publishing %s@%s (attempt %d/%d)...\n' \
      "$crate" "$version" "$attempt" "$max_attempts"
    set +e
    cargo publish \
      --locked \
      --registry crates-io \
      --package "$crate" \
      --no-verify \
      --target-dir "$package_target"
    publish_status=$?
    set -e

    # Cargo regenerates the archive during `publish`. Confirm that it is still
    # byte-for-byte the package validated above before accepting the upload.
    published_local_checksum=$(sha256_file "$crate_file")
    if [[ $published_local_checksum != "$local_checksum" ]]; then
      fail "cargo publish regenerated different bytes for $crate@$version: before=$local_checksum after=$published_local_checksum"
    fi
    # A lost client response can follow a successful server-side publish; the
    # remote checksum, not the process status alone, is authoritative.
    remote_visible=false
    for ((visibility_attempt = 1; visibility_attempt <= 6; visibility_attempt++)); do
      if verify_remote_checksum "$crate" "$version" "$local_checksum"; then
        remote_visible=true
        break
      fi
      if ((publish_status != 0 || visibility_attempt == 6)); then
        break
      fi
      printf 'Publish accepted; waiting 10 seconds for %s@%s API visibility (%d/6).\n' \
        "$crate" "$version" "$visibility_attempt" >&2
      sleep 10
    done
    if [[ $remote_visible == true ]]; then
      printf 'crates.io now contains identical %s@%s; treating publish as successful.\n' \
        "$crate" "$version"
      published=true
      break
    fi
    if ((publish_status == 0)); then
      printf 'Publish succeeded but %s@%s is not visible yet.\n' "$crate" "$version" >&2
    fi

    if ((attempt < max_attempts)); then
      printf 'Publish failed; retrying in %d seconds.\n' "$delay" >&2
      sleep "$delay"
      delay=$((delay * 2))
      ((delay <= 120)) || delay=120
    fi
  done

  [[ $published == true ]] || fail "could not publish $crate@$version after $max_attempts attempts"
done <"$package_file"

if [[ $check_only == true ]]; then
  printf 'Crate metadata and dependency order are valid.\n'
else
  printf 'All workspace crates are published at their exact workspace versions.\n'
fi
