from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "benchmark_junk", Path(__file__).resolve().parents[1] / "benchmark-junk.py"
)
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.roots = benchmark.fixture_roots(Path(self.temp.name), 1, 3)
        target = self.roots[0] / "target"
        # Three independently known payload lengths: 1024, 1025 and 1026.
        self.report = {
            "schema": "sweepx.junk.result/v1", "status": "ok", "candidateCount": 1,
            "candidates": [{"path": str(target), "ruleId": "rust.target", "risk": "R2",
                            "reclaimable": {"state": "known", "value": "3075"},
                            "sizeIsLogical": True}],
        }
        self.timings = {
            "schema": "sweepx.junk.timings/v1", "complete": True, "totalNs": 12,
            "phasesNs": {"traversal": 8, "report": 2}, "rootCount": 1,
            "rootCacheHits": 0, "rootCacheMisses": 1, "candidateCount": 1,
        }

    def test_fixture_checks_independent_sizes_after_mutation(self):
        benchmark.verify_fixture(self.report, self.roots)
        artifact = self.roots[0] / "target/bucket-000/artifact-000000.bin"
        artifact.write_bytes(b"replacement")
        with self.assertRaisesRegex(ValueError, "logical byte total"):
            benchmark.verify_fixture(self.report, self.roots)

    def test_fixture_rejects_false_positive_even_with_matching_count(self):
        self.report["candidates"][0]["path"] = str(self.roots[0] / "notes/dist")
        with self.assertRaisesRegex(ValueError, "candidate paths"):
            benchmark.verify_fixture(self.report, self.roots)

    def test_rejects_partial_reports_and_unknown_quantities(self):
        self.report["status"] = "partial"
        with self.assertRaisesRegex(ValueError, "complete junk report"):
            benchmark.facts(self.report)
        self.report["status"] = "ok"
        self.report["candidates"][0]["reclaimable"] = {"state": "unknown"}
        with self.assertRaisesRegex(ValueError, "not known"):
            benchmark.verify_fixture(self.report, self.roots)

    def test_timing_counts_and_totals_cannot_manufacture_fast_results(self):
        benchmark.validate_timings(self.timings, self.report)
        for key, bad in [("rootCacheHits", 1), ("candidateCount", 0),
                         ("totalNs", 9), ("complete", False)]:
            changed = copy.deepcopy(self.timings)
            changed[key] = bad
            with self.assertRaises(ValueError, msg=key):
                benchmark.validate_timings(changed, self.report)

    def test_comparison_keeps_quantity_state_and_excludes_dynamic_claims(self):
        other = copy.deepcopy(self.report)
        other["candidates"][0]["confidence"] = "medium"
        other["candidates"][0]["blockers"] = ["git_evidence_not_revalidated"]
        self.assertEqual(benchmark.facts(other), benchmark.facts(self.report))
        other["candidates"][0]["reclaimable"]["state"] = "lower_bound"
        self.assertNotEqual(benchmark.facts(other), benchmark.facts(self.report))


if __name__ == "__main__":
    unittest.main()
