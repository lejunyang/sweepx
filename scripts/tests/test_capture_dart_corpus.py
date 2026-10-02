from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import shlex
import unittest


SPEC = importlib.util.spec_from_file_location(
    "capture_dart_corpus", Path(__file__).resolve().parents[1] / "capture-dart-corpus.py"
)
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


@unittest.skipUnless(os.name == "posix", "acquisition uses the shared POSIX runner")
class DartAcquisitionTests(unittest.TestCase):
    def test_wrong_actual_sdk_version_cannot_issue_a_recording(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / "dart"
            sdk.write_text("#!/bin/sh\necho 'Dart SDK version: 2.17.0 (stable)'\n")
            sdk.chmod(0o700)
            output = root / "recording"
            with self.assertRaisesRegex(ValueError, "fixed version"):
                corpus.capture(sdk, sdk, output)
            self.assertEqual(list(output.rglob("receipt.json")), [])

    def test_existing_capture_is_preserved_without_executing_sdk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            touched = root / "sdk-executed"
            sdk = root / "dart"
            sdk.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(touched))}\n")
            sdk.chmod(0o700)
            output = root / "recording"
            output.mkdir()
            payload = output / "personal"
            payload.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                corpus.capture(sdk, sdk, output)
            self.assertFalse(touched.exists())
            self.assertEqual(payload.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
