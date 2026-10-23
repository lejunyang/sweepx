"""Offline contract tests for preflight versus irreversible publication checks."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "publish-crates.sh"
CRATES = (
    "sweepx-canonical", "sweepx-i18n", "sweepx-model", "sweepx-fixtures",
    "sweepx-platform", "sweepx-cache", "sweepx-protocol", "sweepx-audit",
    "sweepx-catalog", "sweepx-event-journal", "sweepx-tui", "sweepx-scanner",
    "sweepx-analysis", "sweepx-core", "sweepx-safety", "sweepx-cli",
    "sweepx-executor",
)
VERSION = "0.0.1"

# Exercise the actual Bash control flow without Rust, the network, or credentials.
# Every executable call is recorded, and the fake publisher always refuses upload.
FAKE_TOOL = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["PUBLISH_TEST_ROOT"])
config = json.loads((root / "config.json").read_text())
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps([tool, *args]) + "\n")

if tool == "cargo":
    if args[0] == "metadata":
        print(json.dumps(config["metadata"]))
    elif args[0] == "package":
        if config.get("package_failure"):
            raise SystemExit(42)
        destination = Path(args[args.index("--target-dir") + 1]) / "package"
        destination.mkdir(parents=True, exist_ok=True)
        crates = config["crates"] if "--workspace" in args else [
            args[args.index("--package") + 1]
        ]
        for crate in crates:
            if crate != config.get("missing_archive"):
                filename = f"{crate}-0.0.1.crate"
                shutil.copyfile(root / "local" / filename, destination / filename)
    else:
        print("unexpected cargo command; publishing is forbidden in tests", file=sys.stderr)
        raise SystemExit(70)
elif tool == "curl":
    destination = Path(args[args.index("--output") + 1])
    url = args[-1]
    if "/api/v1/crates/" in url:
        crate, version = url.rsplit("/", 2)[-2:]
        destination.write_text(json.dumps({"version": {
            "crate": crate, "num": version,
            "checksum": config["checksums"][crate],
        }}))
        print("200", end="")
    elif url.startswith("https://static.crates.io/crates/"):
        shutil.copyfile(root / "remote" / url.rsplit("/", 1)[-1], destination)
    else:
        raise SystemExit("unexpected URL: " + url)
else:
    raise SystemExit("unexpected command: " + tool)
'''


class PublishCratesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for directory in ("scripts", "bin", "local", "remote"):
            (self.root / directory).mkdir()
        self.script = self.root / "scripts" / SCRIPT.name
        shutil.copyfile(SCRIPT, self.script)
        for tool in ("cargo", "curl"):
            executable = self.root / "bin" / tool
            executable.write_text(FAKE_TOOL)
            executable.chmod(0o755)
        packages = [
            {"name": name, "id": name, "version": VERSION,
             "dependencies": [], "publish": None}
            for name in CRATES
        ]
        self.config = {
            "crates": CRATES,
            "metadata": {
                "workspace_members": list(CRATES), "packages": packages,
                "resolve": {"nodes": [
                    {"id": name, "dependencies": []} for name in CRATES
                ]},
            },
            "checksums": {},
        }
        self.contents = {
            "Cargo.toml": b'[package]\nname = "fixture"\nversion = "0.0.1"\n',
            "README.md": b"current documentation\n",
            "src/lib.rs": b"pub fn current_api() {}\n",
            ".cargo_vcs_info.json": b'{"git":{"sha1":"current-commit"}}\n',
        }
        for crate in CRATES:
            path = self.archive_path("local", crate)
            self.write_archive(path, crate, self.contents)
            shutil.copyfile(path, self.archive_path("remote", crate))
            self.config["checksums"][crate] = hashlib.sha256(path.read_bytes()).hexdigest()

    def archive_path(self, location, crate):
        return self.root / location / f"{crate}-{VERSION}.crate"

    @staticmethod
    def write_archive(path, crate, contents):
        with tarfile.open(path, "w:gz") as archive:
            for name, data in contents.items():
                member = tarfile.TarInfo(f"{crate}-{VERSION}/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def change_published_file(self, filename):
        crate = CRATES[0]
        contents = {**self.contents, filename: b"older published content\n"}
        path = self.archive_path("remote", crate)
        self.write_archive(path, crate, contents)
        self.config["checksums"][crate] = hashlib.sha256(path.read_bytes()).hexdigest()

    def run_script(self, *args):
        (self.root / "config.json").write_text(json.dumps(self.config))
        (self.root / "calls.jsonl").write_text("")
        env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("PUBLISH_") and key != "CARGO_REGISTRY_TOKEN"
        }
        env.update({
            "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"],
            "PUBLISH_TEST_ROOT": str(self.root),
            "PUBLISH_MAX_ATTEMPTS": "1",
            "PUBLISH_NEW_CRATE_INTERVAL_SECONDS": "0",
        })
        if "--check" not in args:
            env["CARGO_REGISTRY_TOKEN"] = "test-only-not-a-credential"
        result = subprocess.run(
            ["bash", str(self.script), *args], env=env,
            capture_output=True, text=True, timeout=30,
        )
        self.calls = [json.loads(line) for line in
                      (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertNotIn(["cargo", "publish"], [call[:2] for call in self.calls])
        return result

    def test_check_accepts_development_changes_without_registry_identity_checks(self):
        self.change_published_file("README.md")
        result = self.run_script("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("workspace packaging are valid", result.stdout)
        self.assertEqual(result.stdout.count("Validated local package:"), len(CRATES))
        self.assertFalse(any(call[0] == "curl" for call in self.calls))
        packages = [call for call in self.calls if call[:2] == ["cargo", "package"]]
        self.assertEqual(len(packages), 1)
        self.assertIn("--workspace", packages[0])
        self.assertIn("--no-verify", packages[0])
        self.assertIn("--locked", packages[0])

    def test_check_propagates_packaging_failure(self):
        self.config["package_failure"] = True
        result = self.run_script("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("workspace packaging are valid", result.stdout)

    def test_check_requires_every_package_archive(self):
        self.config["missing_archive"] = CRATES[-1]
        result = self.run_script("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cargo package did not create", result.stderr)
        self.assertIn(CRATES[-1], result.stderr)

    def test_check_rejects_incorrect_dependency_order_before_packaging(self):
        self.config["metadata"]["packages"][0]["dependencies"] = [{
            "name": CRATES[1], "path": "/fixture/dependency", "req": "^0.0.1",
        }]
        self.config["metadata"]["resolve"]["nodes"][0]["dependencies"] = [CRATES[1]]
        result = self.run_script("--check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publish order places", result.stderr)
        self.assertEqual([call[:2] for call in self.calls], [["cargo", "metadata"]])

    def test_publish_rejects_changed_source_and_package_metadata(self):
        for filename in ("src/lib.rs", "Cargo.toml", "README.md"):
            with self.subTest(filename=filename):
                self.change_published_file(filename)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"differs: {filename}", result.stderr)
                self.assertIn("differs in content", result.stderr)
                packages = [call for call in self.calls
                            if call[:2] == ["cargo", "package"]]
                self.assertEqual(len(packages), 1)
                self.assertNotIn("--no-verify", packages[0])

    def test_publish_can_resume_with_only_generated_commit_metadata_changed(self):
        self.change_published_file(".cargo_vcs_info.json")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("identical contents, differing commit record", result.stdout)
        self.assertEqual(result.stdout.count("skipping:"), len(CRATES))

    def test_publish_skips_exactly_identical_existing_packages(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("Verified existing crate checksum:"), len(CRATES))
        self.assertFalse(any("static.crates.io" in call[-1] for call in self.calls))


if __name__ == "__main__":
    unittest.main()
