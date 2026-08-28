#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/benchmark-linux-event-journal.sh [OPTIONS]

Measure the deterministic Linux event-journal complete-stream workload.

Options:
  --profile smoke|qualification  Workload profile (default: qualification).
  --runs N                      Scored fresh-journal runs (default: 15).
  --output-dir PATH             New evidence directory (default: unique path under target/).
  --enforce-target              Exit nonzero if any scored append exceeds the 1 s target.
  -h, --help                    Show this help.

The runner always performs one unscored warm-up, preserves every raw JSON sample, and records
host/build evidence. A local pass is not formal qualification: this harness measures post-scan
complete-stream persistence only. It does not measure the G-EVENT live creation-to-delivery p95,
prove controlled OS-cache/storage state, or cover the required real-OS/filesystem matrix. Every
sample process has a 10 s external watchdog; the measured append target remains 1 s.
EOF
}

fail() {
  printf 'event-journal benchmark: %s\n' "$*" >&2
  exit 2
}

profile=qualification
runs=15
output_dir=
enforce_target=0
watchdog_timeout_seconds=10
watchdog_kill_after_seconds=2

while (($#)); do
  case $1 in
    --profile)
      (($# >= 2)) || fail '--profile requires a value'
      profile=$2
      shift 2
      ;;
    --runs)
      (($# >= 2)) || fail '--runs requires a value'
      runs=$2
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || fail '--output-dir requires a value'
      output_dir=$2
      shift 2
      ;;
    --enforce-target)
      enforce_target=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown option: $1" ;;
  esac
done

[[ $profile == smoke || $profile == qualification ]] ||
  fail '--profile must be smoke or qualification'
[[ $runs =~ ^[1-9][0-9]*$ ]] || fail '--runs must be a positive integer'
if ((enforce_target)) && [[ $profile != qualification ]]; then
  fail '--enforce-target requires --profile qualification'
fi
if ((enforce_target)) && ((runs < 15)); then
  fail '--enforce-target requires at least 15 scored runs'
fi
[[ $(uname -s) == Linux ]] || fail 'this benchmark is Linux-only'
command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v rustc >/dev/null 2>&1 || fail 'rustc is required'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required to write evidence JSON'
command -v git >/dev/null 2>&1 || fail 'git is required to identify the source revision'

watchdog_kind=none
watchdog_path=
if command -v timeout >/dev/null 2>&1; then
  candidate_timeout=$(command -v timeout)
  timeout_version=$($candidate_timeout --version 2>/dev/null || true)
  if [[ $timeout_version == *"GNU coreutils"* ]]; then
    watchdog_kind=gnu-timeout
    watchdog_path=$candidate_timeout
  fi
fi
if [[ $watchdog_kind == none ]] && command -v python3 >/dev/null 2>&1; then
  watchdog_kind=python-subprocess-timeout
  watchdog_path=$(command -v python3)
fi
if [[ $watchdog_kind == none ]]; then
  ((enforce_target == 0)) || fail '--enforce-target requires an external bounded watchdog'
  fail 'an external bounded watchdog is required for every sample'
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
[[ -f $repo_root/Cargo.lock ]] || fail "repository root is missing Cargo.lock: $repo_root"

if [[ -z $output_dir ]]; then
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  output_dir=$repo_root/target/event-journal-runtime-evidence/$timestamp-$$
elif [[ $output_dir != /* ]]; then
  output_dir=$PWD/$output_dir
fi
[[ ! -e $output_dir ]] || fail "output directory already exists: $output_dir"
umask 077
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
measured_tmp_dir=$output_dir/measurement-tmp
mkdir -m 0700 -- "$measured_tmp_dir"

build_dir=$repo_root/target/event-journal-runtime-gate-build
binary=$build_dir/release/examples/linux_event_journal_runtime_gate
build_log=$output_dir/build.log
raw_samples=$output_dir/raw-samples.ndjson
warmup_sample=$output_dir/warmup.json
environment_record=$output_dir/environment.json
aggregate_report=$output_dir/report.json
example_relative=crates/sweepx-event-journal/examples/linux_event_journal_runtime_gate.rs
runner_relative=scripts/benchmark-linux-event-journal.sh
example_source=$repo_root/$example_relative
runner_source=$repo_root/$runner_relative
source_copy_dir=$output_dir/harness-source
source_status=$output_dir/harness-status.txt
source_patch=$output_dir/harness.patch
mkdir -m 0700 -- "$source_copy_dir"
cp -- "$example_source" "$source_copy_dir/linux_event_journal_runtime_gate.rs"
cp -- "$runner_source" "$source_copy_dir/benchmark-linux-event-journal.sh"
(
  cd -- "$repo_root"
  git status --porcelain=v1 --untracked-files=all -- "$example_relative" "$runner_relative"
) >"$source_status"
: >"$source_patch"
for relative_path in "$example_relative" "$runner_relative"; do
  if (cd -- "$repo_root" && git ls-files --error-unmatch -- "$relative_path" >/dev/null 2>&1); then
    (cd -- "$repo_root" && git diff --binary HEAD -- "$relative_path") >>"$source_patch"
  else
    if (cd -- "$repo_root" && git diff --no-index --binary -- /dev/null "$relative_path") >>"$source_patch"; then
      :
    else
      diff_status=$?
      [[ $diff_status -eq 1 ]] || exit "$diff_status"
    fi
  fi
done

run_bounded_sample() {
  local destination=$1
  shift
  if [[ $watchdog_kind == gnu-timeout ]]; then
    TMPDIR="$measured_tmp_dir" "$watchdog_path" \
      --signal=TERM --kill-after="${watchdog_kill_after_seconds}s" \
      "${watchdog_timeout_seconds}s" "$binary" "$@" >"$destination"
    return
  fi

  TMPDIR="$measured_tmp_dir" "$watchdog_path" - \
    "$watchdog_timeout_seconds" "$binary" "$@" >"$destination" <<'PY'
import subprocess
import sys

timeout_seconds = float(sys.argv[1])
command = sys.argv[2:]
try:
    completed = subprocess.run(command, timeout=timeout_seconds, check=False)
except subprocess.TimeoutExpired:
    print(
        f"event-journal benchmark: sample exceeded external {timeout_seconds:g} s watchdog",
        file=sys.stderr,
    )
    raise SystemExit(124)
if completed.returncode < 0:
    raise SystemExit(128 - completed.returncode)
raise SystemExit(completed.returncode)
PY
}

run_or_preserve_status() {
  local description=$1
  local destination=$2
  shift 2
  if run_bounded_sample "$destination" "$@"; then
    return 0
  else
    local sample_status=$?
    printf 'event-journal benchmark: %s failed with status %d\n' \
      "$description" "$sample_status" >&2
    exit "$sample_status"
  fi
}

printf 'Building fixed release-profile harness...\n' >&2
(
  cd -- "$repo_root"
  cargo build --release --locked --target-dir "$build_dir" \
    --package sweepx-event-journal --example linux_event_journal_runtime_gate
) >"$build_log" 2>&1 || {
  tail -100 "$build_log" >&2
  exit 1
}
[[ -x $binary ]] || fail "benchmark binary was not produced at $binary"

REPO_ROOT=$repo_root \
OUTPUT_DIR=$output_dir \
PROFILE=$profile \
RUNS=$runs \
BINARY=$binary \
ENFORCE_TARGET=$enforce_target \
MEASURED_TMP_DIR=$measured_tmp_dir \
EXAMPLE_SOURCE=$example_source \
RUNNER_SOURCE=$runner_source \
SOURCE_COPY_DIR=$source_copy_dir \
SOURCE_STATUS=$source_status \
SOURCE_PATCH=$source_patch \
WATCHDOG_KIND=$watchdog_kind \
WATCHDOG_PATH=$watchdog_path \
WATCHDOG_TIMEOUT_SECONDS=$watchdog_timeout_seconds \
python3 - <<'PY' >"$environment_record"
import hashlib
import json
import os
import pathlib
import platform
import subprocess

repo = pathlib.Path(os.environ["REPO_ROOT"])
output = pathlib.Path(os.environ["OUTPUT_DIR"])
binary = pathlib.Path(os.environ["BINARY"])
measured_tmp = pathlib.Path(os.environ["MEASURED_TMP_DIR"])
example_source = pathlib.Path(os.environ["EXAMPLE_SOURCE"])
runner_source = pathlib.Path(os.environ["RUNNER_SOURCE"])
source_copy_dir = pathlib.Path(os.environ["SOURCE_COPY_DIR"])
source_status = pathlib.Path(os.environ["SOURCE_STATUS"])
source_patch = pathlib.Path(os.environ["SOURCE_PATCH"])

def command(*args):
    try:
        result = subprocess.run(
            args, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
        )
    except FileNotFoundError as error:
        return {"argv": list(args), "available": False, "exitCode": None, "output": str(error)}
    return {
        "argv": list(args),
        "available": True,
        "exitCode": result.returncode,
        "output": result.stdout.strip(),
    }

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()

status_text = source_status.read_text(encoding="utf-8").strip()
example_copy = source_copy_dir / "linux_event_journal_runtime_gate.rs"
runner_copy = source_copy_dir / "benchmark-linux-event-journal.sh"
example_hash = sha256(example_source)
runner_hash = sha256(runner_source)
if sha256(example_copy) != example_hash or sha256(runner_copy) != runner_hash:
    raise SystemExit("copied harness source differs from the source used for the build")
record = {
    "schema": "sweepx.event-journal-runtime-environment/v1",
    "formalQualification": False,
    "capturedAtUtc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    "source": {
        "revision": command("git", "rev-parse", "HEAD"),
        "sourceDirty": bool(status_text),
        "cargoLockSha256": sha256(repo / "Cargo.lock"),
        "harnessFiles": [
            {
                "repositoryPath": "crates/sweepx-event-journal/examples/linux_event_journal_runtime_gate.rs",
                "sha256": example_hash,
                "evidenceCopy": "harness-source/linux_event_journal_runtime_gate.rs",
            },
            {
                "repositoryPath": "scripts/benchmark-linux-event-journal.sh",
                "sha256": runner_hash,
                "evidenceCopy": "harness-source/benchmark-linux-event-journal.sh",
            },
        ],
        "harnessStatus": {
            "path": source_status.name,
            "sha256": sha256(source_status),
            "scope": "only the two harness source paths",
        },
        "harnessPatch": {
            "path": source_patch.name,
            "sha256": sha256(source_patch),
            "format": "git diff --binary; untracked files represented with git diff --no-index --binary",
            "scope": "only the two harness source paths",
        },
    },
    "build": {
        "profile": "release",
        "locked": True,
        "rustc": command("rustc", "-vV"),
        "cargo": command("cargo", "-V"),
        "rustflags": os.environ.get("RUSTFLAGS"),
        "binarySha256": sha256(binary),
    },
    "host": {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "uname": command("uname", "-a"),
        "cpu": command("lscpu"),
        "memory": command("sh", "-c", "sed -n '1,8p' /proc/meminfo"),
        "blockDevices": command("lsblk", "-J", "-o", "NAME,TYPE,SIZE,ROTA,RO,FSTYPE,MOUNTPOINTS"),
        "measuredJournalFilesystem": command(
            "findmnt", "-J", "-T", str(measured_tmp), "-o", "SOURCE,FSTYPE,OPTIONS,TARGET"
        ),
    },
    "runtimeIdentity": {
        "uid": os.getuid(),
        "effectiveUid": os.geteuid(),
        "gid": os.getgid(),
        "effectiveGid": os.getegid(),
        "processStatus": command("sh", "-c", "grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' /proc/self/status"),
    },
    "invocation": {
        "profile": os.environ["PROFILE"],
        "warmupRuns": 1,
        "scoredRuns": int(os.environ["RUNS"]),
        "enforceTargetRequested": os.environ["ENFORCE_TARGET"] == "1",
        "watchdog": {
            "kind": os.environ["WATCHDOG_KIND"],
            "path": os.environ["WATCHDOG_PATH"],
            "timeoutSeconds": int(os.environ["WATCHDOG_TIMEOUT_SECONDS"]),
            "measuredAppendTargetSeconds": 1,
        },
        "temporaryDirectory": str(measured_tmp),
        "cacheState": "uncontrolled; every sample uses a new journal under the dedicated temporary directory",
        "storageState": "uncontrolled",
    },
    "missingFormalEvidence": [
        "independent controlled host and storage attestation",
        "controlled cold or warm OS page-cache classification",
        "required Linux filesystem and hardware matrix",
        "approved same-environment baseline comparison",
        "G-EVENT live creation-to-delivery latency observations",
        "independent review of the captured dirty or untracked harness source",
    ],
}
json.dump(record, __import__("sys").stdout, sort_keys=True, separators=(",", ":"))
print()
PY

printf 'Running one unscored warm-up...\n' >&2
run_or_preserve_status "warm-up sample" "$warmup_sample" \
  --profile "$profile" --run-index 0 --warmup

: >"$raw_samples"
for ((run_index = 1; run_index <= runs; run_index++)); do
  printf 'Running scored sample %d/%d...\n' "$run_index" "$runs" >&2
  sample_file=$output_dir/scored-sample.tmp
  run_or_preserve_status "scored sample $run_index" "$sample_file" \
    --profile "$profile" --run-index "$run_index"
  cat -- "$sample_file" >>"$raw_samples"
  rm -- "$sample_file"
done

RAW_SAMPLES=$raw_samples \
WARMUP_SAMPLE=$warmup_sample \
ENVIRONMENT_RECORD=$environment_record \
PROFILE=$profile \
RUNS=$runs \
ENFORCE_TARGET=$enforce_target \
python3 - <<'PY' >"$aggregate_report"
import hashlib
import json
import os
import pathlib
import statistics
import sys

raw_path = pathlib.Path(os.environ["RAW_SAMPLES"])
warmup_path = pathlib.Path(os.environ["WARMUP_SAMPLE"])
environment_path = pathlib.Path(os.environ["ENVIRONMENT_RECORD"])
expected_profile = os.environ["PROFILE"]
expected_runs = int(os.environ["RUNS"])
enforce_requested = os.environ["ENFORCE_TARGET"] == "1"
sample_schema = "sweepx.event-journal-runtime-sample/v1"
sample_api = "EventJournal::append_complete_stream"
sample_scope_note = (
    "Measures one post-scan complete-stream commit; it does not measure or qualify "
    "G-EVENT live delivery latency"
)
qualification_contract = {
    "profileVersion": "linux-event-journal-v1",
    "totalEvents": 2_048,
    "journalEventCeiling": 50_000,
    "journalStorageCeilingBytes": 32 * 1024 * 1024,
    "progressEvents": 1_999,
    "boundaryEvents": 31,
    "errorEvents": 16,
    "terminalEvents": 1,
    "inputJsonBytes": 988_218,
    "committedJsonBytes": 1_037_204,
    "workloadSha256": "sha256:245ef1f1197c2718433169afd449f2f8b095c9869ce9ca2939795cae624c2552",
}
sample_keys = {
    "schema", "profile", "runIndex", "warmup", "api",
    "measuredAppendSqliteTransactions", "workload", "timing", "storage",
    "threshold", "correctnessVerified", "formalQualification", "scopeNote",
}
workload_keys = set(qualification_contract)
timing_keys = {
    "buildWorkloadNs", "openJournalNs", "appendCompleteStreamNs",
    "verifyIntegrityNs", "readAndValidateNs", "totalNs",
}
storage_keys = {"databaseBytes", "walBytes", "shmBytes", "totalBytes"}
threshold_keys = {"metric", "targetNs", "observedNs", "met", "enforcedByHarness"}

def reject(message):
    raise SystemExit(f"invalid runtime evidence: {message}")

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()

def load_object(path, description):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        reject(f"cannot read {description}: {error}")
    if not isinstance(value, dict):
        reject(f"{description} must be one JSON object")
    return value

def require_exact(sample, field, expected, description):
    if sample.get(field) != expected or type(sample.get(field)) is not type(expected):
        reject(f"{description} has unexpected {field}")

def require_keys(value, expected, description):
    actual = set(value)
    if actual != expected:
        reject(
            f"{description} fields differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )

def require_nonnegative_int(value, field, description, *, positive=False):
    actual = value.get(field)
    if type(actual) is not int or actual < (1 if positive else 0):
        qualifier = "positive" if positive else "non-negative"
        reject(f"{description} {field} must be a {qualifier} integer")
    return actual

def validate_sample(sample, *, expected_index, expected_warmup, description):
    if not isinstance(sample, dict):
        reject(f"{description} must be a JSON object")
    require_keys(sample, sample_keys, description)
    require_exact(sample, "schema", sample_schema, description)
    require_exact(sample, "profile", expected_profile, description)
    require_exact(sample, "runIndex", expected_index, description)
    require_exact(sample, "warmup", expected_warmup, description)
    require_exact(sample, "api", sample_api, description)
    require_exact(sample, "measuredAppendSqliteTransactions", 1, description)
    require_exact(sample, "correctnessVerified", True, description)
    require_exact(sample, "formalQualification", False, description)
    require_exact(sample, "scopeNote", sample_scope_note, description)

    workload = sample.get("workload")
    timing = sample.get("timing")
    storage = sample.get("storage")
    threshold = sample.get("threshold")
    if not all(isinstance(value, dict) for value in (workload, timing, storage, threshold)):
        reject(f"{description} is missing workload, timing, storage, or threshold objects")
    require_keys(workload, workload_keys, f"{description} workload")
    require_keys(timing, timing_keys, f"{description} timing")
    require_keys(storage, storage_keys, f"{description} storage")
    require_keys(threshold, threshold_keys, f"{description} threshold")

    require_exact(workload, "profileVersion", "linux-event-journal-v1", description)
    for field in (
        "totalEvents", "journalEventCeiling", "journalStorageCeilingBytes",
        "progressEvents", "boundaryEvents", "errorEvents", "terminalEvents",
        "inputJsonBytes", "committedJsonBytes",
    ):
        require_nonnegative_int(workload, field, description, positive=True)
    workload_digest = workload.get("workloadSha256")
    if (
        type(workload_digest) is not str
        or len(workload_digest) != 71
        or not workload_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in workload_digest[7:])
    ):
        reject(f"{description} workloadSha256 is not a canonical SHA-256 digest")
    if workload["totalEvents"] != (
        workload["progressEvents"]
        + workload["boundaryEvents"]
        + workload["errorEvents"]
        + workload["terminalEvents"]
        + 1
    ):
        reject(f"{description} event-type counts do not reconcile")
    if workload["totalEvents"] > workload["journalEventCeiling"]:
        reject(f"{description} event count exceeds its journal ceiling")
    if workload["committedJsonBytes"] < workload["inputJsonBytes"]:
        reject(f"{description} committed JSON bytes are smaller than producer input")
    if workload["committedJsonBytes"] > 32 * 1024 * 1024:
        reject(f"{description} committed JSON bytes exceed 32 MiB")

    for field in timing_keys:
        require_nonnegative_int(timing, field, description)
    component_total = sum(timing[field] for field in timing_keys if field != "totalNs")
    if timing["totalNs"] < component_total:
        reject(f"{description} total timing is smaller than its measured components")

    for field in storage_keys:
        require_nonnegative_int(storage, field, description)
    if storage["totalBytes"] != (
        storage["databaseBytes"] + storage["walBytes"] + storage["shmBytes"]
    ):
        reject(f"{description} storage byte counts do not reconcile")
    if storage["totalBytes"] <= 0:
        reject(f"{description} persisted no journal storage")
    if storage["databaseBytes"] <= 0:
        reject(f"{description} persisted no SQLite database bytes")
    if (
        storage["totalBytes"] > workload["journalStorageCeilingBytes"]
        or storage["totalBytes"] > 32 * 1024 * 1024
    ):
        reject(f"{description} storage exceeds the declared journal ceiling")

    require_exact(threshold, "metric", "appendCompleteStreamNs", description)
    require_exact(threshold, "targetNs", 1_000_000_000, description)
    require_exact(threshold, "enforcedByHarness", False, description)
    observed = require_nonnegative_int(threshold, "observedNs", description)
    if timing.get("appendCompleteStreamNs") != observed:
        reject(f"{description} threshold and timing observations differ")
    if threshold.get("met") is not (observed <= threshold["targetNs"]):
        reject(f"{description} threshold disposition is inconsistent")
    if expected_profile == "qualification":
        for field, expected in qualification_contract.items():
            require_exact(workload, field, expected, description)
    return workload, threshold

warmup = load_object(warmup_path, "warm-up sample")
warmup_workload, warmup_threshold = validate_sample(
    warmup, expected_index=0, expected_warmup=True, description="warm-up sample"
)

lines = raw_path.read_text(encoding="utf-8").splitlines()
if len(lines) != expected_runs or any(not line.strip() for line in lines):
    reject(f"expected {expected_runs} non-empty scored samples, found {len(lines)}")
try:
    samples = [json.loads(line) for line in lines]
except json.JSONDecodeError as error:
    reject(f"scored sample is invalid JSON: {error}")
for expected_index, sample in enumerate(samples, start=1):
    workload, threshold = validate_sample(
        sample,
        expected_index=expected_index,
        expected_warmup=False,
        description=f"scored sample {expected_index}",
    )
    if workload != warmup_workload:
        reject(f"scored sample {expected_index} workload differs from warm-up")
    if threshold["targetNs"] != warmup_threshold["targetNs"]:
        reject(f"scored sample {expected_index} target differs from warm-up")

values = [sample["timing"]["appendCompleteStreamNs"] for sample in samples]
target = samples[0]["threshold"]["targetNs"]
median = statistics.median(values)
mad = statistics.median(abs(value - median) for value in values)
exceeded = [sample["runIndex"] for sample in samples if not sample["threshold"]["met"]]
environment = json.loads(environment_path.read_text(encoding="utf-8"))
if environment.get("schema") != "sweepx.event-journal-runtime-environment/v1":
    reject("environment record schema mismatch")
if environment.get("formalQualification") is not False:
    reject("environment record must not claim formal qualification")
source = environment.get("source")
if not isinstance(source, dict) or type(source.get("sourceDirty")) is not bool:
    reject("environment source record is missing sourceDirty")
source_files = source.get("harnessFiles")
if not isinstance(source_files, list) or len(source_files) != 2:
    reject("environment must identify exactly two harness source copies")
for source_file in source_files:
    if not isinstance(source_file, dict) or set(source_file) != {
        "repositoryPath", "sha256", "evidenceCopy"
    }:
        reject("harness source record has unexpected fields")
    copied_path = environment_path.parent / source_file["evidenceCopy"]
    if not copied_path.is_file() or sha256(copied_path) != source_file["sha256"]:
        reject(f"harness source copy failed hash validation: {copied_path}")
for field in ("harnessStatus", "harnessPatch"):
    artifact = source.get(field)
    if not isinstance(artifact, dict) or type(artifact.get("path")) is not str:
        reject(f"environment source record is missing {field}")
    artifact_path = environment_path.parent / artifact["path"]
    if not artifact_path.is_file() or sha256(artifact_path) != artifact.get("sha256"):
        reject(f"{field} failed hash validation")
invocation = environment.get("invocation", {})
if (
    invocation.get("profile") != expected_profile
    or invocation.get("warmupRuns") != 1
    or invocation.get("scoredRuns") != expected_runs
    or invocation.get("enforceTargetRequested") is not enforce_requested
):
    reject("environment invocation does not match collected samples")
watchdog = invocation.get("watchdog")
if (
    not isinstance(watchdog, dict)
    or watchdog.get("kind") not in {"gnu-timeout", "python-subprocess-timeout"}
    or type(watchdog.get("path")) is not str
    or not watchdog["path"]
    or watchdog.get("timeoutSeconds") != 10
    or watchdog.get("measuredAppendTargetSeconds") != 1
):
    reject("environment watchdog record does not match the bounded runner contract")
report = {
    "schema": "sweepx.event-journal-runtime-report/v1",
    "profile": os.environ["PROFILE"],
    "warmupRuns": 1,
    "scoredRuns": len(samples),
    "requiredScoredRuns": 15,
    "minimumRunCountMet": len(samples) >= 15,
    "enforceTargetRequested": enforce_requested,
    "metric": "appendCompleteStreamNs",
    "targetNs": target,
    "minimumNs": min(values),
    "medianNs": median,
    "maximumNs": max(values),
    "medianAbsoluteDeviationNs": mad,
    "allRunsMetTarget": not exceeded,
    "runsExceedingTarget": exceeded,
    "correctnessVerifiedEveryRun": all(sample["correctnessVerified"] for sample in samples),
    "workloadSha256": samples[0]["workload"]["workloadSha256"],
    "workloadStableEveryRun": len({sample["workload"]["workloadSha256"] for sample in samples}) == 1,
    "eventCount": samples[0]["workload"]["totalEvents"],
    "formalQualification": False,
    "qualificationBlockedBy": environment["missingFormalEvidence"],
    "gEventQualified": False,
    "gEventNote": "This workload has no live event source or subscriber and cannot measure G-EVENT p95 latency or 10 Hz coalescing",
    "artifacts": {
        "environment": environment_path.name,
        "warmup": "warmup.json",
        "rawSamples": raw_path.name,
        "buildLog": "build.log",
        "harnessSource": "harness-source/",
        "harnessStatus": source["harnessStatus"]["path"],
        "harnessPatch": source["harnessPatch"]["path"],
    },
}
json.dump(report, sys.stdout, sort_keys=True, separators=(",", ":"))
print()
PY

python3 -m json.tool "$aggregate_report"
printf 'Evidence written to %s\n' "$output_dir" >&2

if ((enforce_target)); then
  python3 - "$aggregate_report" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not report["minimumRunCountMet"]:
    raise SystemExit(1)
if not report["correctnessVerifiedEveryRun"] or not report["workloadStableEveryRun"]:
    raise SystemExit(1)
if not report["allRunsMetTarget"]:
    raise SystemExit(1)
PY
fi
