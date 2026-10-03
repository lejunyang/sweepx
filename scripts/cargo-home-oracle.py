#!/usr/bin/env python3
"""Record pinned Cargo home lookup/base semantics in bounded disposable POSIX fixtures.

Reuses the workspace oracle's subprocess bounds. This never runs a build or reads user
configuration: HOME is always an isolated fixture, even for empty/unset CARGO_HOME.
"""

import argparse
import hashlib
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
    """Independent inputs; expected output paths are supplied only by Cargo metadata."""
    return [
        ("absolute_existing", "home", "absolute", False, False),
        ("absolute_missing", "missing/deep", "absolute", False, False),
        ("relative_existing", "home", "relative", False, False),
        ("relative_missing", "missing", "relative", False, False),
        ("relative_parent", "../home", "relative", False, False),
        ("dot", ".", "relative", False, False),
        ("empty", "", "relative", False, False),
        ("unset", None, "relative", False, False),
        ("fallback_missing", None, "relative", True, False),
        ("parent_steps", "tmp/../home", "relative", False, False),
        ("missing_parent_step", "missing/../home", "relative", False, False),
        ("regular_home", "regular", "relative", False, False),
        ("parent_end", "home/..", "relative", False, False),
        ("dot_prefix", "./home", "relative", False, False),
        ("absolute_parent_steps", "project/tmp/../home", "absolute", False, False),
        ("relative_fallback", None, "relative", False, True),
        ("legacy_home_config", "legacy", "relative", False, False),
    ]


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
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report = {
        "schema": "sweepx.cargo-home-oracle.v1", "baseCommit": args.base_commit,
        "recordedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "scope": "Pinned offline/no-deps Cargo home observations; no build, user config, ownership/activity, Trash or performance claim",
        "bounds": {"cases": runner.MAX_CASES, "fixtureFilesPerCase": runner.MAX_FILES,
                   "fixtureBytesPerCase": runner.MAX_INPUT_BYTES, "secondsPerInvocation": runner.TIMEOUT_SECONDS,
                   "combinedOutputBytes": runner.MAX_OUTPUT_BYTES},
        "harness": {"path": "scripts/cargo-home-oracle.py", "sha256": digest(Path(__file__).read_bytes()),
                    "runnerSha256": digest(Path(runner.__file__).read_bytes())},
        "python": {"path": sys.executable, "version": platform.python_version()},
        "cargoBinary": {"path": str(args.cargo), "sha256": digest(args.cargo.read_bytes())},
        "rustcBinary": {"path": str(args.rustc), "sha256": digest(args.rustc.read_bytes())},
        "plannedCases": [case[0] for case in cases], "records": [], "complete": False,
    }

    def save():
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="sweepx-cargo-home-", dir="/private/tmp") as temporary:
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
            for name, home_value, kind, missing, relative_fallback in cases:
                fixture = base / name
                files = {
                    "project/Cargo.toml": '[package]\nname="home_oracle"\nversion="0.1.0"\nedition="2024"\n',
                    "project/src/lib.rs": "pub fn answer() -> u8 { 42 }\n",
                    "project/target/personal": "personal fixture bytes, preserved\n",
                    "project/regular": "personal file used as configured home\n",
                    "project/config.toml": '[build]\ntarget-dir="dot-output"\n',
                    "home/config.toml": '[build]\ntarget-dir="home-output"\n',
                    "project/home/config.toml": '[build]\ntarget-dir="home-output"\n',
                    "project/legacy/config": '[build]\ntarget-dir="legacy-output"\n',
                    "project/legacy/config.toml": '[build]\ntarget-dir="unused-output"\n',
                }
                fallback = "project/user-home" if relative_fallback else "user-home"
                if not missing:
                    files[fallback + "/.cargo/config.toml"] = '[build]\ntarget-dir="fallback-output"\n'
                directories = ["project/tmp", fallback]
                assert len(files) <= runner.MAX_FILES
                assert sum(len(body.encode()) for body in files.values()) <= runner.MAX_INPUT_BYTES
                for relative in directories:
                    (fixture / relative).mkdir(parents=True, exist_ok=True)
                inputs = []
                for relative, body in sorted(files.items()):
                    path = fixture / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body, encoding="utf-8")
                    inputs.append({"path": relative, "utf8": body, "sha256": digest(body.encode())})
                cwd = fixture / "project"
                case_env = dict(env, HOME="user-home" if relative_fallback else str(fixture / fallback))
                case_env.pop("CARGO_HOME")
                if home_value is not None:
                    case_env["CARGO_HOME"] = str(fixture / home_value) if kind == "absolute" else home_value
                command = [str(args.cargo), "metadata", "--offline", "--no-deps", "--format-version=1"]
                result = runner.run_bounded(command, cwd, case_env)
                changes = [original["path"] for original in inputs
                           if not (fixture / original["path"]).is_file()
                           or digest((fixture / original["path"]).read_bytes()) != original["sha256"]]
                record = {"name": name, "fixtureRoot": str(fixture), "cwd": str(cwd),
                          "fixtureRelativeCwd": "project", "homeValue": home_value, "homeKind": kind,
                          "fallbackHome": "user-home" if relative_fallback else fallback,
                          "fallbackRelative": relative_fallback, "inputs": inputs, "directories": directories,
                          "command": command, "environment": case_env, "cargo": result, "inputChanges": changes,
                          "createdFiles": sorted(str(path.relative_to(fixture)) for path in fixture.rglob("*")
                                                 if path.is_file() and str(path.relative_to(fixture)) not in files)}
                report["records"].append(record)
                save()
                print(f"{name}: status={result['status']}, bound={result['boundedFailure']}", flush=True)
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
