#!/usr/bin/env python3
"""Build a source audit of MangoDisk cleanup-rule research leads."""

from __future__ import annotations

import argparse
import csv
import sys
import tomllib
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


DOCUMENTATION_TERMS = (
    "backup",
    "build",
    "cache",
    "clean",
    "config",
    "directory",
    "dump",
    "file-system",
    "filesystem",
    "folder",
    "log",
    "storage",
    "temp",
    "troubleshoot",
    "user-data",
    "user_data",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit MangoDisk rule references without copying rule paths, matchers, "
            "evidence prose, or execution policy into SweepX. Reference URLs are retained "
            "so reviewers can inspect the cited public sources."
        )
    )
    parser.add_argument(
        "rules_root", type=Path, help="MangoDisk rules/filesystem directory"
    )
    parser.add_argument("--csv", type=Path, help="optional CSV output path")
    parser.add_argument(
        "--redact-urls",
        action="store_true",
        help="omit complete URLs and retain only source domains in CSV output",
    )
    return parser.parse_args()


def source_tier(references: list[str]) -> str:
    if not references:
        return "missing_reference"
    paths = [urlparse(reference).path.lower() for reference in references]
    if any(term in path for path in paths for term in DOCUMENTATION_TERMS):
        return "documentation_candidate"
    return "identity_or_lead_only"


def load_rows(root: Path, redact_urls: bool) -> list[dict[str, str | int]]:
    if not root.is_dir():
        raise ValueError(f"rules root is not a directory: {root}")
    rows: list[dict[str, str | int]] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*.toml")):
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        rule_id = document.get("id")
        platform = document.get("platform")
        category = document.get("category")
        verification = document.get("verification", {})
        references = verification.get("references", [])
        key = (platform, rule_id)
        if (
            not isinstance(rule_id, str)
            or platform not in {"windows", "macos"}
            or key in seen
            or not isinstance(category, str)
            or not isinstance(references, list)
            or not all(isinstance(reference, str) for reference in references)
        ):
            raise ValueError(f"invalid or duplicate rule metadata: {path}")
        seen.add(key)
        domains = sorted({urlparse(reference).netloc.lower() for reference in references})
        rows.append(
            {
                "rule_id": rule_id,
                "platform": platform,
                "category": category,
                "reference_count": len(references),
                "reference_domains": ";".join(domains),
                "reference_urls": "" if redact_urls else ";".join(references),
                "source_tier": source_tier(references),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, str | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    try:
        rows = load_rows(args.rules_root, args.redact_urls)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 2
    if not rows:
        print("audit failed: no TOML rules found", file=sys.stderr)
        return 2
    if args.csv is not None:
        write_csv(args.csv, rows)
    counts = Counter((row["platform"], row["source_tier"]) for row in rows)
    print(f"rules={len(rows)} references={sum(int(row['reference_count']) for row in rows)}")
    for (platform, tier), count in sorted(counts.items()):
        print(f"{platform}.{tier}={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
