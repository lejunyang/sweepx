from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest


SPEC = importlib.util.spec_from_file_location(
    "capture_sveltekit_corpus", Path(__file__).resolve().parents[1] / "capture-sveltekit-corpus.py"
)
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


@unittest.skipUnless(os.name == "posix", "acquisition requires POSIX process groups")
class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, code, **kwargs):
        return corpus.run([sys.executable, "-c", code], self.root, {}, **kwargs)

    def test_nonzero_exit_never_returns_a_successful_recording(self):
        with self.assertRaisesRegex(ValueError, "tool exited 7"):
            self.invoke("import sys; print('partial'); sys.exit(7)")

    def test_output_budget_stops_unbounded_writer(self):
        with self.assertRaisesRegex(ValueError, "output budget"):
            self.invoke("import os\nwhile True: os.write(1, b'x' * 4096)", max_output=128)

    def test_deadline_reaps_child_after_leader_exits(self):
        # A real child holds the inherited output pipe after its parent exits successfully.
        # Its sentinel is an independent oracle: killing only the leader would let it appear.
        sentinel = self.root / "late-child-output"
        ready = self.root / "child-ready"
        child = ("import time; from pathlib import Path; "
                 f"Path({str(ready)!r}).write_text('running'); time.sleep(2); "
                 f"Path({str(sentinel)!r}).touch()")
        leader = ("import subprocess, sys; "
                  f"subprocess.Popen([sys.executable, '-c', {child!r}]); print('spawned', flush=True)")
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.invoke(leader, timeout=1)
        self.assertEqual(ready.read_text(), "running", "the child must actually reach the wait")
        time.sleep(2.1)
        self.assertFalse(sentinel.exists())

    def test_existing_capture_is_preserved_before_any_tool_runs(self):
        output = self.root / "recording"
        output.mkdir()
        payload = output / "existing"
        payload.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            corpus.capture(Path(sys.executable), Path(__file__), output)
        self.assertEqual(payload.read_bytes(), b"keep")

    def test_recording_read_obeys_documented_byte_limit(self):
        path = self.root / "output"
        path.write_bytes(b"x" * 262144)
        self.assertEqual(corpus.read_file(path), path.read_bytes())
        path.write_bytes(b"x" * 262145)
        with self.assertRaisesRegex(ValueError, "oversized"):
            corpus.read_file(path)

    def test_recording_read_refuses_link_and_fifo_without_waiting(self):
        target = self.root / "personal"
        target.write_bytes(b"keep")
        link = self.root / "linked-output"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            corpus.read_file(link)
        fifo = self.root / "pipe-output"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "invalid"):
            corpus.read_file(fifo)
        self.assertEqual(target.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
