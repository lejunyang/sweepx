#!/usr/bin/env python3
"""Record pinned Cargo workspace semantics using bounded, disposable fixtures only.

This is an independent Cargo oracle, not a SweepX parser or a production probe. Metadata may
write Cargo.lock inside these fixtures. No build, network, user project or global env mutation
is requested. Each invocation has its own HOME/CARGO_HOME and a finite output/deadline budget.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import sys
import tempfile
import time

MAX_CASES = 64
MAX_FILES = 64
MAX_INPUT_BYTES = 128 * 1024
TIMEOUT_SECONDS = 5
MAX_OUTPUT_BYTES = 256 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run_bounded(command, cwd, env, timeout=TIMEOUT_SECONDS, maximum=MAX_OUTPUT_BYTES):
    """Drain both pipes without blocking or retaining more than one combined output allowance."""
    started = time.monotonic()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    retained = 0
    stop = None
    process = subprocess.Popen(
        command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    for stream, name in [(process.stdout, "stdout"), (process.stderr, "stderr")]:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    try:
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                stop = "deadline"
                break
            for key, _ in selector.select(min(remaining, 0.05)):
                chunk = os.read(key.fileobj.fileno(), min(65536, maximum - retained + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                elif retained + len(chunk) > maximum:
                    output[key.data].extend(chunk[:maximum - retained])
                    retained = maximum
                    stop = "output_limit"
                    break
                else:
                    output[key.data].extend(chunk)
                    retained += len(chunk)
            if stop:
                break
        if stop:
            os.killpg(process.pid, signal.SIGKILL)
        # Cleanup has its own finite allowance after a bounded stop. Do not issue a second
        # group kill just because the original observation deadline has already elapsed.
        remaining = 2 if stop else max(0, timeout - (time.monotonic() - started))
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            stop = "deadline"
            os.killpg(process.pid, signal.SIGKILL)
            status = process.wait(timeout=2)
    except BaseException:
        # Only this owned process group is stopped, including on an operator's pause signal.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return {
        "status": status,
        "boundedFailure": stop,
        "stdout": output["stdout"].decode("utf-8", errors="strict"),
        "stderr": output["stderr"].decode("utf-8", errors="strict"),
        "retainedOutputBytes": retained,
    }


def package(files, directory, name, extra="", workspace=None):
    prefix = f"{directory}/" if directory else ""
    manifest = f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n'
    if workspace is not None:
        manifest += f"workspace={json.dumps(workspace, ensure_ascii=False)}\n"
    files[prefix + "Cargo.toml"] = manifest + extra
    files[prefix + "src/lib.rs"] = "pub fn answer() -> u8 { 42 }\n"
    files[prefix + "target/personal"] = "personal fixture bytes, preserved\n"


def matrix():
    cases = []

    def add(name, files, cwd="root", question=""):
        cases.append({"name": name, "files": files, "cwd": cwd, "question": question})

    def root(extra="[workspace]\n", members=None):
        files = {}
        package(files, "root", "root_package", extra)
        for member in members or []:
            package(files, "root/" + member, member.replace("/", "_"))
        return files

    def virtual(extra='members=["a","b"]\n', members=("a", "b")):
        files = {"root/Cargo.toml": '[workspace]\nresolver="3"\n' + extra}
        for member in members:
            package(files, "root/" + member, member.replace("/", "_"))
        return files

    add("standalone_package", root(""), question="No workspace declaration or ancestor workspace")
    add("root_workspace_no_members_key", root(), question="A root package is itself a member")
    add("root_workspace_empty_members", root("[workspace]\nmembers=[]\n"))
    add("virtual_literal_members_root_cwd", virtual())
    add("virtual_literal_members_member_cwd", virtual(), "root/a")
    glob_files = virtual('members=["crates/*"]\n', ())
    for directory, name in [("a", "a"), ("b", "b"), ("中文 空格", "unicode_member")]:
        package(glob_files, "root/crates/" + directory, name)
    add("virtual_glob_members_unicode_space", glob_files)
    add("root_workspace_glob_members", root('[workspace]\nmembers=["crates/*"]\n', ["crates/a", "crates/b"]))
    add("literal_member_and_exclude_overlap", root('[workspace]\nmembers=["a"]\nexclude=["a"]\n', ["a"]), question="Do literal explicit members override an identical exclusion?")
    add("glob_member_and_exclude_overlap", root('[workspace]\nmembers=["crates/*"]\nexclude=["crates/a"]\n', ["crates/a", "crates/b"]), question="Does glob expansion have the same priority as literal members?")
    add("literal_member_under_excluded_parent", root('[workspace]\nmembers=["foo/child"]\nexclude=["foo"]\n', ["foo/child"]))
    files = root('[workspace]\nexclude=["foo"]\n[dependencies]\nexcluded={path="foo/child"}\nkept={path="foobar"}\n')
    package(files, "root/foo/child", "excluded")
    package(files, "root/foobar", "kept")
    add("exclude_subtree_does_not_match_foobar", files, question="Path-component prefix exclusion versus textual prefix")
    files = root('[workspace]\nexclude=["crates/*"]\n[dependencies]\na={path="crates/a"}\n')
    package(files, "root/crates/a", "a")
    add("exclude_glob_spelling_with_path_dependency", files, question="Is exclude glob-expanded or treated as a path prefix?")
    files = root('[workspace]\nmembers=["a"]\n', ["a", "b"])
    add("unlisted_nested_package_root_workspace", files, "root/b")
    files = virtual('members=["a"]\n', ["a", "b"])
    add("unlisted_nested_package_virtual_workspace", files, "root/b")
    files = root('[workspace]\nmembers=["a"]\nexclude=["b"]\n', ["a", "b"])
    add("excluded_nested_package_is_standalone", files, "root/b")
    files = root('[workspace]\nmembers=["a"]\n', ["a"])
    package(files, "root/b", "b", "[workspace]\n")
    add("nested_own_workspace_package", files, "root/b")
    add("empty_virtual_no_members_key", virtual("", ()))
    add("empty_virtual_empty_members", virtual("members=[]\n", ()))
    add("virtual_missing_literal_member", virtual('members=["missing"]\n', ()))
    add("virtual_unmatched_member_glob", virtual('members=["missing/*"]\n', ()))
    add("virtual_invalid_member_glob", virtual('members=["crates/["]\n', ()))
    for label, dependency in [
        ("normal", '[dependencies]\na={path="a"}\n'),
        ("dev", '[dev-dependencies]\na={path="a"}\n'),
        ("build", '[build-dependencies]\na={path="a"}\n'),
        ("target_inactive", '[target.\'cfg(target_os = "none")\'.dependencies]\na={path="a"}\n'),
        ("optional", '[dependencies]\na={path="a",optional=true}\n'),
    ]:
        files = root("[workspace]\n" + dependency)
        package(files, "root/a", "a")
        add("implicit_path_dependency_" + label, files)
    files = root('[workspace]\nmembers=[]\n[dependencies]\na={path="a"}\n')
    package(files, "root/a", "a")
    add("empty_members_still_include_path_dependency", files)
    files = root('[workspace]\n[dependencies]\na={path="a"}\n')
    package(files, "root/a", "a", '[dependencies]\nb={path="../b"}\n')
    package(files, "root/b", "b")
    add("transitive_path_dependency", files)
    files = virtual('members=["a"]\n', ["a"])
    package(files, "root/a", "a", '[dependencies]\nb={path="../b"}\n')
    package(files, "root/b", "b")
    add("virtual_member_adds_implicit_path_dependency", files)
    files = virtual('members=["a"]\n[workspace.dependencies]\nb={path="b"}\n', ["a", "b"])
    add("workspace_dependency_unused", files)
    package(files := dict(files), "root/a", "a", '[dependencies]\nb.workspace=true\n')
    add("workspace_dependency_inherited", files)
    files = virtual('members=[]\n[workspace.dependencies]\nb={path="b"}\n', ["b"])
    add("empty_virtual_workspace_dependency_unused", files)
    for label, member_workspace in [("with_pointer", "../root"), ("without_pointer", None)]:
        files = root('[workspace]\nmembers=["../external"]\n')
        package(files, "external", "external", workspace=member_workspace)
        add("external_explicit_member_" + label, files)
        add("external_explicit_member_invoked_" + label, dict(files), "external")
        files = root('[workspace]\n[dependencies]\nexternal={path="../external"}\n')
        package(files, "external", "external", workspace=member_workspace)
        add("external_path_dependency_" + label, files)
    files = root('[workspace]\nmembers=["nested"]\n')
    package(files, "root/nested", "nested", "[workspace]\n")
    add("nested_workspace_member_conflict", files)
    files = root('[workspace]\nmembers=["a"]\n', ["a"])
    package(files, "other", "other", "[workspace]\n")
    package(files, "root/a", "a", workspace="../../other")
    add("member_points_to_wrong_workspace", files)
    files = root("")
    package(files, "external", "external", workspace="../root")
    add("workspace_pointer_to_nonworkspace_package", files, "external")
    files = root()
    package(files, "root/a", "a", "[workspace]\n", workspace="..")
    add("package_workspace_and_workspace_conflict", files, "root/a")
    add("default_members_virtual_all", virtual())
    add("default_members_virtual_subset", virtual('members=["a","b"]\ndefault-members=["b"]\n'))
    add("default_members_virtual_empty", virtual('members=["a","b"]\ndefault-members=[]\n'))
    add("default_members_root_subset", root('[workspace]\nmembers=["a","b"]\ndefault-members=["b"]\n', ["a", "b"]))
    files = virtual('members=["a"]\ndefault-members=["missing"]\n', ["a"])
    add("invalid_default_members_root_cwd", files)
    add("invalid_default_members_member_cwd", dict(files), "root/a")
    files = root('[workspace]\n[dependencies]\na={path="a"}\n')
    package(files, "root/a", "a", '[dependencies]\nmissing={path="../missing"}\n')
    add("missing_transitive_path_dependency", files)
    files = virtual('members=["a"]\n', ["a"])
    package(files, "root/a", "a", '[dependencies]\nb={path="../b"}\n')
    package(files, "root/b", "b", '[dependencies]\na={path="../a"}\n')
    add("path_dependency_membership_cycle", files)
    files = root('[workspace]\nmembers=["a"]\n', ["a", "a/child"])
    add("literal_member_is_not_nested_descendant_membership", files, "root/a/child")
    add("normalized_literal_member_path", root('[workspace]\nmembers=["a/../b"]\n', ["a", "b"]))
    files = root('[workspace]\n[patch.crates-io]\nb={path="b"}\n')
    package(files, "root/b", "b")
    add("unused_patch_path_is_not_dependency_member", files)
    return cases


def self_test():
    env = {"PATH": "/usr/bin:/bin"}
    with tempfile.TemporaryDirectory(prefix="sweepx-oracle-runner-") as directory:
        result = run_bounded([sys.executable, "-c", "import sys;print('out');print('err',file=sys.stderr);sys.exit(7)"], directory, env)
        assert result["status"] == 7 and result["boundedFailure"] is None
        assert result["stdout"] == "out\n" and result["stderr"] == "err\n"
        result = run_bounded([sys.executable, "-c", "import os;os.write(1,b'x'*4096)"], directory, env, maximum=64)
        assert result["boundedFailure"] == "output_limit" and result["retainedOutputBytes"] == 64
        result = run_bounded([sys.executable, "-c", "import threading;threading.Event().wait()"], directory, env, timeout=0.1)
        assert result["boundedFailure"] == "deadline"
    cases = matrix()
    assert len(cases) <= MAX_CASES and len({case["name"] for case in cases}) == len(cases)
    for case in cases:
        assert len(case["files"]) <= MAX_FILES
        assert sum(len(value.encode("utf-8")) for value in case["files"].values()) <= MAX_INPUT_BYTES
        assert all(not Path(path).is_absolute() and ".." not in Path(path).parts for path in case["files"])
    print(f"runner boundaries and {len(cases)} fixture definitions verified")


def main():
    def pause_owned_run(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, pause_owned_run)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--base-commit")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not all([args.cargo, args.rustc, args.output, args.base_commit]):
        parser.error("--cargo, --rustc, --output and --base-commit are required")
    if not args.cargo.is_absolute() or not args.rustc.is_absolute():
        parser.error("Cargo and rustc must use fixed absolute binary paths")
    self_test()
    cases = matrix()
    report = {
        "schema": "sweepx.cargo-workspace-oracle/v1", "date": "2026-10-03",
        "baseCommit": args.base_commit,
        "recordedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "scope": "Pinned Cargo observations only; no production SweepX implementation, build, ownership/activity, Trash or performance claim",
        "bounds": {"cases": MAX_CASES, "fixtureFilesPerCase": MAX_FILES, "fixtureBytesPerCase": MAX_INPUT_BYTES,
                   "metadataSecondsPerCase": TIMEOUT_SECONDS, "combinedOutputBytesPerInvocation": MAX_OUTPUT_BYTES},
        "harness": {"path": "scripts/cargo-workspace-oracle.py", "sha256": digest(Path(__file__).read_bytes())},
        "python": {"path": sys.executable, "version": platform.python_version()},
        "cargoBinary": {"path": str(args.cargo), "sha256": digest(args.cargo.read_bytes())},
        "rustcBinary": {"path": str(args.rustc), "sha256": digest(args.rustc.read_bytes())},
        "plannedCases": [case["name"] for case in cases], "records": [], "complete": False,
        "harnessDevelopmentNotes": [
            "The shell python3 shim had no backend; no Cargo oracle process started. The bundled absolute Python runtime is used.",
            "Initial runner self-test reached its deadline but waited with zero cleanup time, causing a redundant group kill to fail after the owned child was already killed. Fixed by a separate finite cleanup allowance; no Cargo fixture result was produced by this attempt.",
        ],
    }

    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="sweepx-cargo-workspace-", dir="/private/tmp") as temporary:
        base = Path(temporary).resolve()
        version_home = base / "version-home"
        version_home.mkdir()
        env = {"HOME": str(version_home), "CARGO_HOME": str(version_home), "RUSTC": str(args.rustc),
               "PATH": str(args.cargo.parent) + ":/usr/bin:/bin", "CARGO_NET_OFFLINE": "true"}
        report["cargoVersion"] = run_bounded([str(args.cargo), "--version"], base, env)
        report["rustcVersion"] = run_bounded([str(args.rustc), "--version"], base, env)
        if report["cargoVersion"]["stdout"].strip() != "cargo 1.98.0 (797e8a9bc 2026-08-05)":
            report["failure"] = "unexpected Cargo version; no fixture metadata started"
            save()
            raise SystemExit(report["failure"])
        save()
        try:
            for number, case in enumerate(cases):
                directory = base / f"{number:02}-{case['name']}"
                directory.mkdir()
                home = directory / "isolated-home"
                home.mkdir()
                inputs = []
                for relative, contents in sorted(case["files"].items()):
                    path = directory / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    encoded = contents.encode("utf-8")
                    path.write_bytes(encoded)
                    inputs.append({"path": relative, "bytes": len(encoded), "sha256": digest(encoded), "utf8": contents})
                cwd = directory / case["cwd"]
                command = [str(args.cargo), "metadata", "--offline", "--no-deps", "--format-version=1"]
                case_env = dict(env, HOME=str(home), CARGO_HOME=str(home))
                result = run_bounded(command, cwd, case_env)
                record = {"name": case["name"], "question": case["question"], "cwd": str(cwd),
                          "fixtureRelativeCwd": case["cwd"], "command": command, "environment": case_env,
                          "inputs": inputs, "cargo": result}
                changed = []
                for original in inputs:
                    path = directory / original["path"]
                    if not path.is_file() or digest(path.read_bytes()) != original["sha256"]:
                        changed.append(original["path"])
                record["inputChanges"] = changed
                record["createdFiles"] = sorted(str(path.relative_to(directory)) for path in directory.rglob("*")
                                                if path.is_file() and str(path.relative_to(directory)) not in case["files"])
                if result["status"] == 0 and result["boundedFailure"] is None:
                    metadata = json.loads(result["stdout"])
                    packages = {package["id"]: package for package in metadata["packages"]}
                    record["workspaceRoot"] = metadata["workspace_root"]
                    record["targetDirectory"] = metadata["target_directory"]
                    for key, field in [("workspaceMembers", "workspace_members"), ("workspaceDefaultMembers", "workspace_default_members")]:
                        record[key] = sorted([{"id": ident, "name": packages[ident]["name"],
                                               "manifestPath": packages[ident]["manifest_path"]}
                                              for ident in metadata[field]], key=lambda package: package["manifestPath"])
                report["records"].append(record)
                save()
                print(f"{number + 1}/{len(cases)} {case['name']}: Cargo status={result['status']}, boundary={result['boundedFailure']}", flush=True)
                if changed:
                    raise RuntimeError("Cargo altered fixture inputs: " + repr(changed))
            report["complete"] = True
        except KeyboardInterrupt:
            report["interrupted"] = "Operator paused this owned oracle; completed records preserved; remaining cases untested"
        finally:
            report["summary"] = {
                "recorded": len(report["records"]),
                "cargoSucceeded": sum(record["cargo"]["status"] == 0 and record["cargo"]["boundedFailure"] is None for record in report["records"]),
                "cargoRejected": sum(record["cargo"]["status"] != 0 and record["cargo"]["boundedFailure"] is None for record in report["records"]),
                "boundedFailures": sum(record["cargo"]["boundedFailure"] is not None for record in report["records"]),
                "inputChanges": sum(len(record["inputChanges"]) for record in report["records"]),
            }
            save()
    if not report["complete"]:
        raise SystemExit(130)


if __name__ == "__main__":
    main()
