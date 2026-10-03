#!/usr/bin/env python3
"""Record pinned Cargo include semantics in bounded disposable POSIX fixtures.

Metadata is offline/no-deps, without a build or user configuration. The workspace oracle
supplies subprocess bounds. Expected output paths and errors come only from Cargo itself.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location("workspace_oracle", Path(__file__).with_name("cargo-workspace-oracle.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def matrix():
    cases = []

    def add(name, config, extra=None, environment=None, config_name="config.toml", location="project/.cargo"):
        files = {
            "project/Cargo.toml": '[package]\nname="include_oracle"\nversion="0.1.0"\nedition="2024"\n',
            "project/src/lib.rs": "pub fn answer() -> u8 { 42 }\n",
            "project/target/personal": "personal bytes preserved\n",
            location + "/" + config_name: config,
        }
        files.update(extra or {})
        cases.append({"name": name, "files": files, "environment": environment or {}})

    first = '[build]\ntarget-dir="first-output"\n'
    second = '[build]\ntarget-dir="second-output"\n'
    pair = {"project/.cargo/first.toml": first, "project/.cargo/second.toml": second}
    add("simple", 'include=["first.toml"]\n', pair)
    add("later_sibling", 'include=["first.toml","second.toml"]\n', pair)
    add("reversed_siblings", 'include=["second.toml","first.toml"]\n', pair)
    add("local_override", 'include=["first.toml"]\n[build]\ntarget-dir="local-output"\n', pair)
    add("local_empty_build", 'include=["first.toml"]\n[build]\njobs=1\n', pair)
    add("nested", 'include=["nested/a.toml"]\n', {
        "project/.cargo/nested/a.toml": 'include=["b.toml"]\n',
        "project/.cargo/nested/b.toml": first,
    })
    add("nested_override", 'include=["nested/a.toml"]\n', {
        "project/.cargo/nested/a.toml": 'include=["b.toml"]\n' + second,
        "project/.cargo/nested/b.toml": first,
    })
    add("parent_include", 'include=["../shared/input.toml"]\n', {"project/shared/input.toml": first})
    add("absolute_include", 'include=["{ROOT}/shared/input.toml"]\n', {"shared/input.toml": first})
    add("dot_include", 'include=["./first.toml"]\n', pair)
    add("parent_steps", 'include=["nested/../first.toml"]\n', {**pair, "project/.cargo/nested/keep": "keep"})
    add("missing_parent_step", 'include=["missing/../first.toml"]\n', pair)
    add("required_missing", 'include=["missing.toml"]\n')
    add("optional_missing", 'include=[{path="missing.toml",optional=true}]\n')
    add("optional_missing_parent", 'include=[{path="missing/input.toml",optional=true}]\n')
    add("optional_non_directory_parent", 'include=[{path="regular/input.toml",optional=true}]\n', {"project/.cargo/regular": "ordinary file"})
    add("optional_present", 'include=[{path="first.toml",optional=true}]\n', pair)
    add("required_table", 'include=[{path="first.toml"}]\n', pair)
    add("optional_false_missing", 'include=[{path="missing.toml",optional=false}]\n')
    add("optional_malformed", 'include=[{path="bad.toml",optional=true}]\n', {"project/.cargo/bad.toml": "[build\n"})
    add("optional_directory", 'include=[{path="directory.toml",optional=true}]\n', {"project/.cargo/directory.toml/keep": "keep"})
    add("duplicate", 'include=["first.toml","second.toml","first.toml"]\n', pair)
    add("self_cycle", 'include=["config.toml"]\n' + first)
    add("mutual_cycle", 'include=["first.toml"]\n', {"project/.cargo/first.toml": 'include=["config.toml"]\n' + first})
    add("diamond", 'include=["a.toml","b.toml"]\n', {
        "project/.cargo/a.toml": 'include=["shared.toml"]\n' + first,
        "project/.cargo/b.toml": 'include=["shared.toml"]\n',
        "project/.cargo/shared.toml": second,
    })
    add("empty_include", 'include=[]\n' + first)
    add("scalar_string", 'include="first.toml"\n', pair)
    add("integer_include", 'include=1\n')
    add("mixed_array", 'include=["first.toml",1]\n', pair)
    add("unknown_table_field", 'include=[{path="first.toml",unexpected=true}]\n', pair)
    add("bad_optional_type", 'include=[{path="first.toml",optional="true"}]\n', pair)
    add("table_without_path", 'include=[{optional=true}]\n')
    add("bad_path_type", 'include=[{path=1}]\n')
    add("scalar_table", 'include={path="first.toml"}\n', pair)
    add("wrong_extension", 'include=["input.conf"]\n', {"project/.cargo/input.conf": first})
    add("uppercase_extension", 'include=["input.TOML"]\n', {"project/.cargo/input.TOML": first})
    add("empty_path", 'include=[""]\n')
    add("optional_wrong_extension", 'include=[{path="missing.conf",optional=true}]\n')
    add("empty_input", 'include=["empty.toml"]\n', {"project/.cargo/empty.toml": ""})
    add("malformed_input", 'include=["bad.toml"]\n', {"project/.cargo/bad.toml": "[build\n"})
    add("duplicate_input_key", 'include=["bad.toml"]\n', {"project/.cargo/bad.toml": "[build]\ntarget-dir='a'\ntarget-dir='b'\n"})
    add("bad_target_overridden", 'include=["bad.toml"]\n' + first, {"project/.cargo/bad.toml": "[build]\ntarget-dir=1\n"})
    add("bad_build_overridden", 'include=["bad.toml"]\n' + first, {"project/.cargo/bad.toml": "build=1\n"})
    add("empty_target_overridden", 'include=["bad.toml"]\n' + first, {"project/.cargo/bad.toml": "[build]\ntarget-dir=''\n"})
    add("empty_target_selected", 'include=["bad.toml"]\n', {"project/.cargo/bad.toml": "[build]\ntarget-dir=''\n"})
    add("home_include", 'include=["inputs/input.toml"]\n', {"home/inputs/input.toml": first}, location="home")
    add("ancestor_include", 'include=["input.toml"]\n', {".cargo/input.toml": first}, location=".cargo")
    add("nearest_over_ancestor", 'include=["first.toml"]\n', {**pair, ".cargo/config.toml": 'include=["input.toml"]\n', ".cargo/input.toml": second})
    add("special_env_override", 'include=["first.toml"]\n', pair, {"CARGO_TARGET_DIR": "env-output"})
    add("generic_env_override", 'include=["first.toml"]\n', pair, {"CARGO_BUILD_TARGET_DIR": "env-output"})
    add("legacy_include", 'include=["first.toml"]\n', pair, config_name="config")
    add("unused_modern_invalid", 'include=["first.toml"]\n', {**pair, "project/.cargo/config.toml": 'include=["missing.toml"]\n'}, config_name="config")
    add("literal_tilde", 'include=["~/input.toml"]\n', {"project/.cargo/~/input.toml": first})
    add("literal_dollar", 'include=["$INPUT/input.toml"]\n', {"project/.cargo/$INPUT/input.toml": first})
    add("shared_across_ancestors", 'include=["{ROOT}/shared/input.toml"]\n', {
        "shared/input.toml": first, ".cargo/config.toml": 'include=["{ROOT}/shared/input.toml"]\n',
    })
    add("shared_with_home", 'include=["{ROOT}/shared/input.toml"]\n', {
        "shared/input.toml": first, "home/config.toml": 'include=["{ROOT}/shared/input.toml"]\n',
    })
    add("target_array_overridden", 'include=["bad.toml"]\n' + first, {"project/.cargo/bad.toml": "[build]\ntarget-dir=['a']\n"})
    add("target_table_overridden", 'include=["bad.toml"]\n' + first, {"project/.cargo/bad.toml": "[build.target-dir]\nvalue='a'\n"})
    add("target_table_selected", 'include=["bad.toml"]\n', {"project/.cargo/bad.toml": "[build.target-dir]\nvalue='a'\n"})
    add("local_scalar_build", 'include=["first.toml"]\nbuild=1\n', pair)
    add("mixed_table_string", 'include=[{path="first.toml"},"second.toml"]\n', pair)
    add("normalized_duplicate", 'include=["first.toml","./first.toml"]\n', pair)
    add("absolute_output", 'include=["input.toml"]\n', {"project/.cargo/input.toml": '[build]\ntarget-dir="{ROOT}/project/target"\n'})
    add("empty_table_array", 'include=[{}]\n')
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-commit", required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite an existing or partial recording")
    cases = matrix()
    assert len(cases) <= runner.MAX_CASES
    report = {
        "schema": "sweepx.cargo-include-oracle.v1", "baseCommit": args.base_commit,
        "recordedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "scope": "Pinned offline/no-deps Cargo include observations; no build, user config, ownership/activity, Trash or performance claim",
        "bounds": {"cases": runner.MAX_CASES, "fixtureFilesPerCase": runner.MAX_FILES,
                   "fixtureBytesPerCase": runner.MAX_INPUT_BYTES, "secondsPerInvocation": runner.TIMEOUT_SECONDS,
                   "combinedOutputBytes": runner.MAX_OUTPUT_BYTES},
        "harness": {"path": "scripts/cargo-include-oracle.py", "sha256": runner.digest(Path(__file__).read_bytes()),
                    "runnerSha256": runner.digest(Path(runner.__file__).read_bytes())},
        "python": {"path": sys.executable, "version": platform.python_version()},
        "cargoBinary": {"path": str(args.cargo), "sha256": runner.digest(args.cargo.read_bytes())},
        "rustcBinary": {"path": str(args.rustc), "sha256": runner.digest(args.rustc.read_bytes())},
        "plannedCases": [case["name"] for case in cases], "records": [], "complete": False,
    }

    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="sweepx-cargo-include-", dir="/private/tmp") as temporary:
        base = Path(temporary).resolve()
        env = {"HOME": str(base), "CARGO_HOME": str(base), "RUSTC": str(args.rustc),
               "PATH": str(args.cargo.parent) + ":/usr/bin:/bin", "CARGO_NET_OFFLINE": "true"}
        for executable, key in [(args.cargo, "cargoVersion"), (args.rustc, "rustcVersion")]:
            report[key] = runner.run_bounded([str(executable), "--version"], base, env)
        if report["cargoVersion"]["stdout"].strip() != "cargo 1.98.0 (797e8a9bc 2026-08-05)":
            report["failure"] = "unexpected Cargo version; no metadata started"
            save()
            raise SystemExit(report["failure"])
        save()
        try:
            for case in cases:
                fixture = base / case["name"]
                inputs = []
                assert len(case["files"]) <= runner.MAX_FILES
                for relative, body in sorted(case["files"].items()):
                    body = body.replace("{ROOT}", str(fixture))
                    path = fixture / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body, encoding="utf-8")
                    inputs.append({"path": relative, "utf8": body, "sha256": runner.digest(body.encode())})
                assert sum(len(item["utf8"].encode()) for item in inputs) <= runner.MAX_INPUT_BYTES
                (fixture / "home").mkdir(exist_ok=True)
                case_env = dict(env, HOME=str(fixture / "user"), CARGO_HOME=str(fixture / "home"), **case["environment"])
                command = [str(args.cargo), "metadata", "--offline", "--no-deps", "--format-version=1"]
                result = runner.run_bounded(command, fixture / "project", case_env)
                changes = [item["path"] for item in inputs
                           if not (fixture / item["path"]).is_file()
                           or runner.digest((fixture / item["path"]).read_bytes()) != item["sha256"]]
                report["records"].append({"name": case["name"], "fixtureRoot": str(fixture),
                                          "fixtureRelativeCwd": "project", "inputs": inputs,
                                          "command": command, "environment": case_env, "cargo": result,
                                          "inputChanges": changes})
                save()
                print(f"{case['name']}: status={result['status']}, bound={result['boundedFailure']}", flush=True)
                if changes or result["boundedFailure"] is not None:
                    raise RuntimeError("input mutation or subprocess boundary; remaining cases untested")
            report["complete"] = True
        finally:
            report["summary"] = {"recorded": len(report["records"]),
                                 "cargoSucceeded": sum(record["cargo"]["status"] == 0 for record in report["records"]),
                                 "inputChanges": sum(len(record["inputChanges"]) for record in report["records"])}
            save()


if __name__ == "__main__":
    main()
