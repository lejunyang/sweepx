"""Verify that failed oracle admission cannot invoke metadata or replace old evidence."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("home_oracle", Path(__file__).resolve().parents[1] / "cargo-home-oracle.py")
home_oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(home_oracle)


class HomeOracleAdmissionTests(unittest.TestCase):
    def arguments(self, executable, output):
        return ["cargo-home-oracle.py", "--cargo", str(executable), "--rustc", str(executable),
                "--output", str(output), "--base-commit", "fixture"]

    def test_existing_recording_is_preserved_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "record.json"
            output.write_bytes(b"previous partial recording")
            with patch("sys.argv", self.arguments(root / "missing", output)), \
                 patch.object(home_oracle.runner, "run_bounded") as run, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    home_oracle.main()
            run.assert_not_called()
            self.assertEqual(output.read_bytes(), b"previous partial recording")

    def test_unexpected_version_records_failure_without_starting_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "fake"
            executable.write_bytes(b"not executed")
            output = root / "record.json"
            answer = {"status": 0, "boundedFailure": None, "stdout": "unexpected version\n", "stderr": ""}
            with patch("sys.argv", self.arguments(executable, output)), \
                 patch.object(home_oracle.runner, "run_bounded", return_value=answer) as run:
                with self.assertRaises(SystemExit):
                    home_oracle.main()
            self.assertEqual(run.call_count, 2)
            self.assertTrue(all(call.args[0][-1] == "--version" for call in run.call_args_list))
            evidence = json.loads(output.read_text())
            self.assertFalse(evidence["complete"])
            self.assertEqual(evidence["records"], [])
            self.assertIn("unexpected Cargo version", evidence["failure"])


if __name__ == "__main__":
    unittest.main()
