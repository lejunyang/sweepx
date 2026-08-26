#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: scripts/check-release-metadata.sh [--require-publish-marker] [--github-output PATH]

Validate that every publishable workspace crate has one common SemVer version,
every internal dependency requirement admits its workspace package version, and
the corresponding v<VERSION> tag is absent locally and on origin.
EOF
}

fail() {
  printf 'release metadata error: %s\n' "$*" >&2
  exit 1
}

require_marker=false
github_output=
while (($# > 0)); do
  case $1 in
    --require-publish-marker)
      require_marker=true
      shift
      ;;
    --github-output)
      (($# >= 2)) || fail '--github-output requires a path'
      github_output=$2
      shift 2
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

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd -P)
cd "$repo_root"

command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v git >/dev/null 2>&1 || fail 'git is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

if [[ $require_marker == true ]]; then
  head_message=$(git log -1 --format=%B)
  [[ $head_message == *'[publish]'* ]] ||
    fail 'HEAD commit message does not contain the literal [publish] marker'
fi

metadata_file=$(mktemp)
cleanup() {
  rm -f -- "$metadata_file"
}
trap cleanup EXIT

cargo metadata --locked --all-features --format-version 1 >"$metadata_file"
version=$(python3 - "$metadata_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    metadata = json.load(handle)

members = set(metadata["workspace_members"])
packages = [package for package in metadata["packages"] if package["id"] in members]
if not packages:
    raise SystemExit("workspace contains no packages")
packages_by_id = {package["id"]: package for package in packages}
packages_by_name = {package["name"]: package for package in packages}
if len(packages_by_name) != len(packages):
    raise SystemExit("workspace package names must be unique")

resolve = metadata.get("resolve")
if not resolve:
    raise SystemExit("cargo metadata did not return a resolved dependency graph")
resolved_by_id = {node["id"]: set(node["dependencies"]) for node in resolve["nodes"]}

blocked = sorted(package["name"] for package in packages if package.get("publish") == [])
if blocked:
    raise SystemExit("workspace contains publish=false crates: " + ", ".join(blocked))

versions = sorted({package["version"] for package in packages})
if len(versions) != 1:
    details = ", ".join(
        f"{package['name']}={package['version']}"
        for package in sorted(packages, key=lambda item: item["name"])
    )
    raise SystemExit("workspace crates do not share one release version: " + details)

version = versions[0]
semver = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
if not semver.fullmatch(version):
    raise SystemExit(f"workspace version is not valid SemVer: {version}")

# Cargo is the source of truth for Cargo-style SemVer requirements. A complete
# resolved graph proves that each declared requirement admits the selected
# package version; checking the resolved package ID also prevents a path entry
# from silently referring to some other package.
for package in packages:
    resolved_dependencies = resolved_by_id.get(package["id"], set())
    for dependency in package["dependencies"]:
        if not dependency.get("path"):
            continue
        dependency_name = dependency["name"]
        target = packages_by_name.get(dependency_name)
        if target is None:
            raise SystemExit(
                f"{package['name']} has path dependency {dependency_name} outside the workspace"
            )
        requirement = dependency.get("req")
        if requirement in (None, "", "*"):
            raise SystemExit(
                f"{package['name']} dependency {dependency_name} needs a crates.io version requirement"
            )
        if target["id"] not in resolved_dependencies:
            raise SystemExit(
                f"{package['name']} dependency requirement {requirement!r} does not resolve "
                f"to workspace {dependency_name}@{target['version']}"
            )

print(version)
PY
) || fail 'Cargo workspace version validation failed'

tag=v$version
if git show-ref --verify --quiet "refs/tags/$tag"; then
  fail "tag $tag already exists locally"
fi

if git remote get-url origin >/dev/null 2>&1; then
  set +e
  git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1
  remote_status=$?
  set -e
  case $remote_status in
    0) fail "tag $tag already exists on origin" ;;
    2) ;;
    *) fail "could not verify whether tag $tag exists on origin" ;;
  esac
fi

if [[ -n $github_output ]]; then
  {
    printf 'version=%s\n' "$version"
    printf 'tag=%s\n' "$tag"
  } >>"$github_output"
fi

printf 'Release metadata is valid: version=%s tag=%s (unpublished tag).\n' "$version" "$tag"
