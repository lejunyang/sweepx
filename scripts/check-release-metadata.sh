#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: scripts/check-release-metadata.sh [--require-publish-marker] [--skip-tag-check] [--github-output PATH]

Validate that every publishable workspace crate has one common SemVer version,
every internal dependency requirement admits its workspace package version, and
the corresponding v<VERSION> tag is absent locally and on origin.

Crates marked publish = false are excluded from the release version contract;
no publishable crate may depend on one.

  --skip-tag-check   Validate versions and dependencies only, leaving tag
                     availability unchecked. Intended for ordinary CI runs, where
                     an already-released version is expected rather than an error.
EOF
}

fail() {
  printf 'release metadata error: %s\n' "$*" >&2
  exit 1
}

require_marker=false
skip_tag_check=false
github_output=
while (($# > 0)); do
  case $1 in
    --require-publish-marker)
      require_marker=true
      shift
      ;;
    --skip-tag-check)
      skip_tag_check=true
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
unpublishable = set(blocked)
# publish=false is a deliberate state, not an error. Such a crate is excluded from the
# release version contract rather than rejecting the whole workspace, but it still has to
# build and test, which the CI workflow covers separately. No workspace member is currently
# publish=false; this stays so the gate does not deadlock when one is added.
packages = [package for package in packages if package.get("publish") != []]
if not packages:
    raise SystemExit("workspace contains no publishable packages")
packages_by_id = {package["id"]: package for package in packages}
packages_by_name = {package["name"]: package for package in packages}
if blocked:
    print("Excluded from release (publish=false): " + ", ".join(blocked), file=sys.stderr)

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
            # Distinguish the two ways a lookup can miss, because the fixes differ: an
            # unpublishable dependency would make this crate impossible to publish,
            # whereas a genuinely external path dependency is a manifest error.
            if dependency_name in unpublishable:
                raise SystemExit(
                    f"{package['name']} depends on publish=false crate {dependency_name}; "
                    "it could never be published from crates.io"
                )
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
# The tag gate protects a release from overwriting a version that already shipped, which is
# only meaningful at the moment of publication. Applying it to every ordinary build would turn
# CI permanently red the day after a release, until someone bumped the version - a red signal
# that means nothing gets ignored, and then it protects nothing. Everything above this line is
# a genuine invariant of the tree and is always checked.
if [[ $skip_tag_check == false ]]; then
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
fi

if [[ -n $github_output ]]; then
  {
    printf 'version=%s\n' "$version"
    printf 'tag=%s\n' "$tag"
  } >>"$github_output"
fi

if [[ $skip_tag_check == true ]]; then
  printf 'Release metadata is valid: version=%s tag=%s (tag availability not checked).\n' \
    "$version" "$tag"
else
  printf 'Release metadata is valid: version=%s tag=%s (unpublished tag).\n' "$version" "$tag"
fi
