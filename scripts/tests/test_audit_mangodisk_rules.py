import csv
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts" / "audit_mangodisk_rules.py"


class MangoDiskRuleAuditTests(unittest.TestCase):
    def test_audit_reports_source_tiers_without_copying_rule_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "filesystem"
            rules = root / "windows" / "system"
            rules.mkdir(parents=True)
            (rules / "documented.toml").write_text(
                """
id = "system.documented"
platform = "windows"
category = "system"
[[roots]]
template = "${local_app_data}/SecretCache"
[verification]
references = ["https://learn.microsoft.com/example/cache-folder"]
""",
                encoding="utf-8",
            )
            (rules / "missing.toml").write_text(
                """
id = "system.missing"
platform = "windows"
category = "system"
[verification]
references = []
""",
                encoding="utf-8",
            )
            output = Path(directory) / "audit.csv"
            result = subprocess.run(
                [str(SCRIPT), str(root), "--csv", str(output), "--redact-urls"],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("rules=2 references=1", result.stdout)
            with output.open(encoding="utf-8") as audit_file:
                rows = list(csv.DictReader(audit_file))
            self.assertEqual(
                [row["source_tier"] for row in rows],
                ["documentation_candidate", "missing_reference"],
            )
            serialized = output.read_text(encoding="utf-8")
            self.assertNotIn("SecretCache", serialized)
            self.assertNotIn("cache-folder", serialized)


if __name__ == "__main__":
    unittest.main()
