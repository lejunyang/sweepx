#!/usr/bin/env python3
"""Measure report-only junk scans; validate results before comparing elapsed times.

Only the generated fixture is mutated. --root workloads are read-only and use an isolated
SweepX state directory. OS page/directory caches are not flushed or described as cold.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def facts(report):
    """Compare filesystem quantities/rules, excluding invocation-dependent Git/tool claims."""
    if report.get("schema") != "sweepx.junk.result/v1" or report.get("status") != "ok":
        raise ValueError("scan did not produce a complete junk report")
    rows = report.get("candidates")
    if not isinstance(rows, list) or len(rows) != report.get("candidateCount"):
        raise ValueError("candidate count disagrees with rows")
    selected = [
        {key: row[key] for key in (
            "path", "ruleId", "risk", "reclaimable", "sizeIsLogical",
        )} for row in rows
    ]
    if len({row["path"] for row in selected}) != len(selected):
        raise ValueError("duplicate candidate paths")
    return sorted(selected, key=lambda row: (row["path"], row["ruleId"]))


def validate_timings(timings, report):
    if timings.get("schema") != "sweepx.junk.timings/v1" or not timings.get("complete"):
        raise ValueError("missing or incomplete phase diagnostics")
    counts = [timings.get(key) for key in (
        "rootCount", "rootCacheHits", "rootCacheMisses", "candidateCount",
    )]
    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("invalid timing counts")
    if counts[0] != counts[1] + counts[2] or counts[3] != report["candidateCount"]:
        raise ValueError("timing counts disagree with roots/report")
    phases = timings.get("phasesNs")
    total = timings.get("totalNs")
    if not isinstance(phases, dict) or type(total) is not int or total < 0:
        raise ValueError("invalid timing object")
    if any(type(value) is not int or value < 0 for value in phases.values()):
        raise ValueError("invalid phase duration")
    if sum(phases.values()) > total:
        raise ValueError("phase durations exceed total")


def fixture_roots(base, root_count, files_per_root):
    roots = []
    for index in range(root_count):
        root = base / ("project-%03d" % index)
        root.mkdir()
        (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n")
        # A matching generic name without the required project context must remain absent.
        (root / "notes" / "dist").mkdir(parents=True)
        (root / "notes" / "dist" / "personal.txt").write_bytes(b"user data")
        target = root / "target"
        target.mkdir()
        for file_index in range(files_per_root):
            directory = target / ("bucket-%03d" % (file_index % 16))
            directory.mkdir(exist_ok=True)
            (directory / ("artifact-%06d.bin" % file_index)).write_bytes(
                bytes([file_index % 251]) * (1024 + file_index % 1024)
            )
        roots.append(root)
    return roots


def verify_fixture(report, roots):
    rows = facts(report)
    expected_paths = {str(root / "target") for root in roots}
    if {row["path"] for row in rows} != expected_paths:
        raise ValueError("fixture candidate paths differ from the independent oracle")
    for row in rows:
        if row["ruleId"] != "rust.target" or row["risk"] != "R2":
            raise ValueError("fixture rule/risk differs from the contract")
        # Ordinary os.walk/stat, not the scanner or its cache. Fixtures contain no links or
        # hardlinks, so sum regular-file logical lengths; never infer physical allocation.
        logical = sum(
            (Path(directory) / name).stat().st_size
            for directory, _, names in os.walk(row["path"])
            for name in names
        )
        quantity = row["reclaimable"]
        if quantity.get("state") != "known":
            raise ValueError("complete fixture quantity is not known")
        if row["sizeIsLogical"] and int(quantity["value"]) != logical:
            raise ValueError("logical byte total differs from ordinary walk/stat")


def invoke(binary, roots, state, timeout):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    command = [str(binary), "--format", "json", "--state-dir", str(state),
               "junk", "--timings", *map(str, roots)]
    started = time.perf_counter_ns()
    process = subprocess.run(command, capture_output=True, timeout=timeout)
    elapsed = time.perf_counter_ns() - started
    if process.returncode != 0:
        raise ValueError("scan failed (%s): %s" % (
            process.returncode, process.stderr.decode(errors="replace")))
    report = json.loads(process.stdout)
    diagnostics = []
    other_stderr = []
    for line in process.stderr.decode().splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            other_stderr.append(line)
            continue
        if isinstance(value, dict) and value.get("schema") == "sweepx.junk.timings/v1":
            diagnostics.append(value)
        else:
            other_stderr.append(line)
    if len(diagnostics) != 1:
        raise ValueError("expected exactly one phase diagnostic")
    validate_timings(diagnostics[0], report)
    return report, {"wallNs": elapsed, "timings": diagnostics[0], "stderr": other_stderr}


def measure(args):
    binary = args.binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), "--version"], text=True).strip()
    binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="sweepx-junk-benchmark-") as temp:
        base = Path(temp).resolve()
        generated = not args.root
        roots = ([path.resolve(strict=True) for path in args.root] if args.root else
                 fixture_roots(base, args.roots, args.files))
        if any(not root.is_dir() for root in roots):
            raise ValueError("every root must be a directory")
        # Fixture setup may leave delayed FSEvents. This is only conditioning, not a claimed
        # guarantee of quiescence; record actual hit/miss counts for every measured invocation.
        time.sleep(args.settle_seconds)
        samples = []
        baseline = None
        warm_state = base / "cold-0"
        for label in ("cold", "warm-attempt", "changed"):
            if label == "changed" and not generated:
                continue
            for repetition in range(args.repetitions):
                state = base / ("cold-%d" % repetition) if label == "cold" else warm_state
                if label == "changed":
                    artifact = next((roots[0] / "target").rglob("artifact-*.bin"))
                    with artifact.open("ab") as stream:
                        stream.write(b"mutation")
                    time.sleep(args.settle_seconds)
                report, sample = invoke(binary, roots, state, args.timeout)
                observed = facts(report)
                if generated:
                    verify_fixture(report, roots)
                if label != "changed":
                    if baseline is None:
                        baseline = observed
                    elif baseline != observed:
                        raise ValueError("cold/warm filesystem facts differ; timings not comparable")
                sample.update({"requestedState": label, "repetition": repetition + 1,
                               "factsSha256": hashlib.sha256(json.dumps(
                                   observed, sort_keys=True).encode()).hexdigest()})
                samples.append(sample)
        groups = {}
        for sample in samples:
            timing = sample["timings"]
            label = sample["requestedState"]
            if label == "warm-attempt":
                label = ("root-cache-hit" if timing["rootCacheHits"] == len(roots) else
                         "warm-os-cache-root-miss")
            groups.setdefault(label, []).append(sample)
        summary = {label: {
            "samples": len(group),
            "medianWallNs": int(statistics.median(item["wallNs"] for item in group)),
            "medianPhasesNs": {phase: int(statistics.median(
                item["timings"]["phasesNs"].get(phase, 0) for item in group))
                for phase in sorted({phase for item in group
                                     for phase in item["timings"]["phasesNs"]})},
        } for label, group in groups.items()}
        return {
            "schema": "sweepx.junk.benchmark/v1",
            "dateUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "host": {"system": platform.system(), "release": platform.release(),
                     "machine": platform.machine(), "python": platform.python_version()},
            "binary": {"path": str(binary), "version": version, "sha256": binary_digest,
                       "buildLabel": args.build_label},
            "workload": {"generated": generated, "roots": list(map(str, roots)),
                         "filesPerRoot": args.files if generated else None,
                         "repetitions": args.repetitions, "settleSeconds": args.settle_seconds},
            "verification": {"coldWarmFilesystemFactsEqual": True,
                             "independentFixtureWalk": generated,
                             "dynamicGitToolInterpretationsCompared": False},
            "osCache": "uncontrolled; cold means empty SweepX cache only",
            "summary": summary, "samples": samples,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/sweepx"))
    parser.add_argument("--build-label", default="unspecified")
    parser.add_argument("--root", action="append", type=Path, default=[],
                        help="existing project root (read-only); repeat for multiple roots")
    parser.add_argument("--roots", type=positive, default=8, help="generated project count")
    parser.add_argument("--files", type=positive, default=1024, help="files per generated project")
    parser.add_argument("--repetitions", type=positive, default=3)
    parser.add_argument("--timeout", type=positive, default=120)
    parser.add_argument("--settle-seconds", type=float, default=1.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.settle_seconds < 0:
        parser.error("--settle-seconds must be nonnegative")
    result = measure(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    main()
