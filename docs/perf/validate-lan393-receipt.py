#!/usr/bin/env python3
"""Fail-closed validators for the LAN-393 full-daemon receipt."""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import math
import re
import sys
from pathlib import Path

import yaml


RUST_BUILDER_IMAGE = (
    "rust:1.95-bookworm@sha256:"
    "6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1"
)
DEBIAN_RUNTIME_IMAGE = (
    "debian:bookworm-slim@sha256:"
    "60eac759739651111db372c07be67863818726f754804b8707c90979bda511df"
)
BGPERF2_COMMIT = "fe4fdab9f7efb56e2e98ad6e6bcffeda047761a9"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
PID_RE = re.compile(r"[1-9][0-9]*")


def fail(message: str) -> None:
    raise SystemExit(message)


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        fail(f"{label}: expected {expected!r}, got {actual!r}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_no_symlink_components(path: Path, label: str) -> None:
    """Reject a path whose leaf or any existing parent is a symlink."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            fail(f"{label} contains a symlink component: {current}")


def require_regular_file(path: Path, label: str) -> None:
    require_no_symlink_components(path, label)
    if not path.is_file():
        fail(f"{label} is not a regular file: {path}")


def require_directory(path: Path, label: str) -> None:
    require_no_symlink_components(path, label)
    if not path.is_dir():
        fail(f"{label} is not a directory: {path}")


def read_text(path: Path, label: str, *, encoding: str = "utf-8") -> str:
    """Read retained text without leaking a traceback or a private path."""
    try:
        return path.read_text(encoding=encoding, errors="strict")
    except OSError as error:
        fail(f"cannot read {label}: {error.strerror or error.__class__.__name__}")
    except UnicodeError as error:
        fail(f"cannot decode {label}: {error}")


def validate_identity(args: argparse.Namespace) -> None:
    candidate_baseline_ancestor = getattr(args, "candidate_baseline_ancestor", None)
    identities = {
        "source HEAD": args.source_head,
        "baseline commit": args.baseline_commit,
        "baseline ref commit": args.baseline_ref_commit,
    }
    if args.candidate_commit is not None:
        identities["candidate commit"] = args.candidate_commit
    for label, commit in identities.items():
        if COMMIT_RE.fullmatch(commit) is None:
            fail(f"{label} is not an exact 40-character commit: {commit!r}")

    require_equal(
        args.baseline_ref_commit,
        args.baseline_commit,
        "recorded baseline/ref identity",
    )
    if args.phase == "baseline":
        if args.candidate_commit is not None:
            fail("baseline identity must not include a candidate commit")
        if candidate_baseline_ancestor is not None:
            fail("baseline identity must not include candidate ancestry")
        require_equal(args.source_head, args.baseline_commit, "baseline source HEAD")
    else:
        if args.candidate_commit is None:
            fail("candidate identity requires --candidate-commit")
        if args.candidate_commit == args.baseline_commit:
            fail("candidate commit matches recorded baseline")
        require_equal(
            candidate_baseline_ancestor,
            "true",
            "candidate baseline-ancestor validation",
        )
        require_equal(args.source_head, args.candidate_commit, "candidate source HEAD")

    print(f"profile_phase={args.phase}")
    print(f"source_head={args.source_head}")
    print(f"baseline_commit={args.baseline_commit}")
    if args.candidate_commit is not None:
        print(f"candidate_commit={args.candidate_commit}")
        print("candidate_baseline_ancestor=true")


def validate_image(args: argparse.Namespace) -> None:
    require_regular_file(args.inspect, "Docker image inspection")
    require_regular_file(args.builder_provenance, "builder provenance")
    require_regular_file(args.runtime_provenance, "runtime provenance")
    require_equal(args.bgperf2_commit, BGPERF2_COMMIT, "pinned bgperf2 commit")
    try:
        inspect = json.loads(read_text(args.inspect, "Docker image inspection"))
    except json.JSONDecodeError as error:
        fail(f"cannot parse Docker image inspection JSON: {error.msg}")
    if not isinstance(inspect, list) or len(inspect) != 1:
        fail("Docker image inspection must contain exactly one image")
    image = inspect[0]
    image_id = image.get("Id", "")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        fail(f"Docker image ID is not a content digest: {image_id!r}")

    labels = image.get("Config", {}).get("Labels") or {}
    expected_labels = {
        "org.opencontainers.image.revision": args.source_commit,
        "org.rustbgpd.bgperf2.revision": args.bgperf2_commit,
        "org.opencontainers.image.base.name": DEBIAN_RUNTIME_IMAGE,
        "org.opencontainers.image.base.digest": DEBIAN_RUNTIME_IMAGE.split("sha256:", 1)[1],
        "org.rustbgpd.bgperf2.builder-base.digest": RUST_BUILDER_IMAGE.split(
            "sha256:", 1
        )[1],
        "org.rustbgpd.bgperf2.rust-toolchain": "1.95",
        "org.rustbgpd.lan393.profile-phase": args.phase,
        "org.rustbgpd.lan393.event-history-mode": args.mode,
    }
    for name, expected in expected_labels.items():
        require_equal(labels.get(name), expected, f"OCI label {name}")

    builder = read_text(args.builder_provenance, "builder provenance")
    runtime = read_text(args.runtime_provenance, "runtime provenance")
    required_builder_lines = (
        f"rustbgpd_commit={args.source_commit}",
        f"bgperf2_commit={args.bgperf2_commit}",
        f"builder_base={RUST_BUILDER_IMAGE}",
    )
    required_runtime_lines = (
        f"rustbgpd_commit={args.source_commit}",
        f"bgperf2_commit={args.bgperf2_commit}",
        f"runtime_base={DEBIAN_RUNTIME_IMAGE}",
    )
    for line in required_builder_lines:
        if line not in builder.splitlines():
            fail(f"builder provenance is missing {line!r}")
    for line in required_runtime_lines:
        if line not in runtime.splitlines():
            fail(f"runtime provenance is missing {line!r}")

    required_patterns = (
        (builder, r"(?m)^rustc 1\.95(?:\.\d+)?(?: |$)", "rustc 1.95 provenance"),
        (builder, r"(?m)^cargo 1\.95(?:\.\d+)?(?: |$)", "cargo 1.95 provenance"),
        (builder, r"(?m)^libprotoc \S+", "protoc provenance"),
        (builder, r"(?m)^protobuf-compiler=\S+", "builder package provenance"),
        (runtime, r"(?m)^iproute2=\S+", "runtime package provenance"),
    )
    for content, pattern, label in required_patterns:
        if re.search(pattern, content) is None:
            fail(f"{label} is missing")

    print(f"image_id={image_id}")
    print(f"source_commit={args.source_commit}")
    print(f"bgperf2_commit={args.bgperf2_commit}")
    print(f"event_history_mode={args.mode}")
    print(f"builder_provenance_sha256={sha256_file(args.builder_provenance)}")
    print(f"runtime_provenance_sha256={sha256_file(args.runtime_provenance)}")


def validate_barrier(args: argparse.Namespace) -> None:
    """Bind the stopped wrapper barrier without publishing its host PID."""
    require_regular_file(args.raw, "private profile-ready barrier")
    try:
        raw = args.raw.read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read private profile-ready barrier: {error}")
    if re.fullmatch(r"[1-9][0-9]*\n", raw) is None:
        fail("private profile-ready barrier must contain exactly one positive PID")
    observed_pid = raw.removesuffix("\n")
    if PID_RE.fullmatch(args.expected_pid) is None:
        fail(f"expected profile PID is malformed: {args.expected_pid!r}")
    require_equal(observed_pid, args.expected_pid, "profile-ready barrier PID")

    require_directory(args.output.parent, "barrier receipt directory")
    require_no_symlink_components(args.output, "barrier receipt")
    if args.output.exists():
        fail(f"refusing existing barrier receipt: {args.output}")
    args.output.write_text("barrier_reached=1\n", encoding="ascii")
    print("barrier_reached=1")


def load_scenario(path: Path) -> dict[str, object]:
    require_regular_file(path, "scenario")
    raw = read_text(path, "scenario")
    # bgperf2 stores a Mako helper followed by ordinary YAML. The unexpanded
    # ${gen_paths(...)} token is useful receipt identity and need not allocate
    # 200k route strings merely to validate the scenario.
    if raw.startswith("<%"):
        end = raw.find("%>")
        if end < 0:
            fail("scenario has an unterminated Mako preamble")
        raw = raw[end + 2 :]
    try:
        scenario = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        detail = getattr(error, "problem", None) or error.__class__.__name__
        fail(f"cannot parse scenario YAML: {detail}")
    if not isinstance(scenario, dict):
        fail("scenario must decode to a mapping")
    return scenario


def validate_scenario(path: Path) -> dict[str, object]:
    scenario = load_scenario(path)
    require_equal(
        set(scenario),
        {"local_prefix", "monitor", "policy", "target", "testers"},
        "scenario top-level keys",
    )
    require_equal(scenario.get("local_prefix"), "10.10.0.0/16", "scenario local_prefix")
    require_equal(scenario.get("policy"), {}, "scenario policy")

    monitor = scenario.get("monitor")
    if not isinstance(monitor, dict):
        fail("scenario monitor must be a mapping")
    expected_monitor = {
        "as": 1001,
        "check-points": [200_000],
        "local-address": "10.10.0.2",
        "router-id": "10.10.0.2",
    }
    require_equal(monitor, expected_monitor, "scenario monitor identity")

    target = scenario.get("target")
    if not isinstance(target, dict):
        fail("scenario target must be a mapping")
    expected_target = {
        "as": 1000,
        "local-address": "10.10.255.254",
        "router-id": "10.10.255.254",
        "single-table": False,
    }
    require_equal(target, expected_target, "scenario target identity")

    testers = scenario.get("testers")
    if not isinstance(testers, list) or len(testers) != 1:
        fail("scenario must contain exactly one tester group")
    tester = testers[0]
    if not isinstance(tester, dict):
        fail("scenario tester must be a mapping")
    require_equal(tester.get("name"), "tester", "tester name")
    require_equal(tester.get("type"), "bird", "tester type")
    neighbors = tester.get("neighbors")
    if not isinstance(neighbors, dict):
        fail("tester neighbors must be a mapping")
    require_equal(set(neighbors), {"10.10.0.3", "10.10.0.4"}, "tester peers")
    for position, address in enumerate(sorted(neighbors), start=3):
        neighbor = neighbors[address]
        if not isinstance(neighbor, dict):
            fail(f"neighbor {address} must be a mapping")
        expected = {
            "as": 1000 + position,
            "check-points": 100_000,
            "count": 100_000,
            "filter": {"in": []},
            "local-address": address,
            "paths": "${gen_paths(100000)}",
            "router-id": address,
        }
        require_equal(neighbor, expected, f"neighbor {address} identity")
    return scenario


def bird_log_inventory(
    directory: Path,
    expected_names: set[str],
    *,
    label: str,
    allow_non_log_entries: bool,
) -> dict[str, Path]:
    """Return an exact, regular-file-only BIRD log inventory."""
    require_directory(directory, label)
    try:
        entries = list(directory.iterdir())
    except OSError as error:
        fail(f"cannot read {label} directory: {error}")

    log_entries = [entry for entry in entries if entry.name.endswith(".log")]
    actual_names = {entry.name for entry in log_entries}
    require_equal(actual_names, expected_names, f"{label} files")
    if len(log_entries) != len(expected_names):
        fail(f"{label} contains duplicate log names")
    for entry in log_entries:
        if entry.is_symlink():
            fail(f"{label} contains a symlink: {entry.name}")
        if not entry.is_file():
            fail(f"{label} contains a non-regular log: {entry.name}")

    if not allow_non_log_entries and len(entries) != len(expected_names):
        fail(f"{label} contains non-log entries")
    return {entry.name: entry for entry in log_entries}


def validate_bird_tester_logs(
    args: argparse.Namespace, scenario: dict[str, object]
) -> None:
    """Validate the retained logs from this exact bgperf BIRD run.

    The pinned adapter's BIRD error helper intends to count case-sensitive
    ``RMT`` diagnostics except ``NEXT_HOP`` diagnostics, but reads a hard-coded
    directory unrelated to ``--dir``/``--bench-name``. Apply that exact rule to
    the two run-scoped logs copied by the driver. The adapter implements no
    BIRD timeout detector; its CSV timeout field is therefore compatibility
    data, not timeout evidence.
    """
    expected_bench_name = f"lan393-{args.phase}-{args.mode}"
    require_equal(args.bench_name, expected_bench_name, "bgperf bench name")
    require_equal(
        args.run_receipt_dir.name,
        args.bench_name,
        "run receipt directory",
    )
    require_directory(args.run_receipt_dir, "run receipt directory")
    require_equal(
        args.source_tester_log_dir.absolute(),
        (args.run_receipt_dir / "tester").absolute(),
        "source tester-log directory",
    )
    require_equal(
        args.source_scenario.absolute(),
        (args.run_receipt_dir / "scenario.yaml").absolute(),
        "source scenario path",
    )
    require_equal(
        args.tester_log_dir.name,
        f"full-daemon-{args.phase}-{args.mode}-tester-logs",
        "retained tester-log directory",
    )
    require_regular_file(args.source_scenario, "source run-scoped scenario")
    require_regular_file(args.scenario, "retained run-scoped scenario")
    require_equal(
        sha256_file(args.scenario),
        sha256_file(args.source_scenario),
        "copied run-scoped scenario",
    )

    testers = scenario.get("testers")
    if not isinstance(testers, list) or len(testers) != 1:
        fail("scenario must contain exactly one tester group before log validation")
    tester = testers[0]
    if not isinstance(tester, dict) or tester.get("type") != "bird":
        fail("run-scoped log validation supports exactly the pinned BIRD tester")
    neighbors = tester.get("neighbors")
    if not isinstance(neighbors, dict):
        fail("scenario tester neighbors are unavailable for log validation")

    expected_names = {f"{peer}.log" for peer in neighbors}
    source_logs = bird_log_inventory(
        args.source_tester_log_dir,
        expected_names,
        label="source run-scoped BIRD logs",
        allow_non_log_entries=True,
    )
    retained_logs = bird_log_inventory(
        args.tester_log_dir,
        expected_names,
        label="retained run-scoped BIRD logs",
        allow_non_log_entries=False,
    )

    errors: list[str] = []
    for name in sorted(expected_names):
        source_path = source_logs[name]
        path = retained_logs[name]
        require_equal(
            sha256_file(path),
            sha256_file(source_path),
            f"copied BIRD log {name}",
        )
        content = read_text(path, f"tester log {path.name}")
        for line_number, line in enumerate(content.splitlines(), start=1):
            if "RMT" in line and "NEXT_HOP" not in line:
                errors.append(f"{path.name}:{line_number}")
        print(f"tester_log_sha256[{path.name}]={sha256_file(path)}")
    if errors:
        fail(
            "run-scoped BIRD logs contain RMT diagnostics other than "
            f"NEXT_HOP: {errors!r}"
        )

    print(f"profile_phase={args.phase}")
    print(f"event_history_mode={args.mode}")
    print(f"bgperf_bench_name={args.bench_name}")
    print("bird_error_rule=case-sensitive RMT excluding NEXT_HOP")
    print("bird_error_lines=0")
    print("tester_timeout_evidence=unsupported_by_pinned_bird_adapter")


RESULT_HEADER = [
    "name",
    "target",
    "version",
    "peers",
    "prefixes per peer",
    "required",
    "received",
    "monitor (s)",
    "elapsed (s)",
    "prefix received (s)",
    "testers (s)",
    "total time",
    "max cpu %",
    "max mem (GB)",
    "min idle%",
    "min free mem (GB)",
    "flags",
    "date",
    "cores",
    "Mem (GB)",
    "tester errors",
    "tester timeouts",
    "failed",
    "MSG",
    "filters",
]


def validate_bgperf(args: argparse.Namespace) -> None:
    require_regular_file(args.log, "retained bgperf log")
    scenario = validate_scenario(args.scenario)
    validate_bird_tester_logs(args, scenario)
    log = read_text(args.log, "retained bgperf log")
    if "FAILED" in log:
        fail("bgperf log contains FAILED")

    rows: list[list[str]] = []
    for raw_line in log.splitlines():
        # Progress redraws can leave carriage-return fragments in a captured
        # log. The final machine row is still a single RFC 4180 CSV record.
        line = raw_line.rsplit("\r", 1)[-1]
        try:
            row = next(csv.reader([line]))
        except csv.Error:
            continue
        if len(row) == len(RESULT_HEADER) and row[1].strip() == "rustbgpd":
            rows.append([field.strip() for field in row])
    if len(rows) != 1:
        fail(f"expected exactly one rustbgpd result row, found {len(rows)}")
    row = rows[0]

    expected = {
        0: "rustbgpd",
        1: "rustbgpd",
        3: "2",
        4: "100000",
        5: "200000",
        6: "200000",
        21: "0",
        22: "",
        23: "",
        24: "",
    }
    for index, value in expected.items():
        require_equal(row[index], value, f"bgperf result field {RESULT_HEADER[index]}")
    if not row[2]:
        fail("bgperf result has no rustbgpd version identity")

    def finite_number(index: int, *, positive: bool = False) -> float:
        label = RESULT_HEADER[index]
        try:
            value = float(row[index])
        except ValueError:
            fail(f"bgperf result field {label} is not numeric: {row[index]!r}")
        if not math.isfinite(value) or value < 0 or (positive and value == 0):
            fail(f"bgperf result field {label} is not finite and valid: {row[index]!r}")
        return value

    monitor_wait = finite_number(7)
    elapsed = finite_number(8)
    first_received = finite_number(9)
    tester_window = finite_number(10)
    total_time = finite_number(11, positive=True)
    finite_number(12)
    finite_number(13, positive=True)
    min_idle = finite_number(14)
    finite_number(15)
    cores = finite_number(18, positive=True)
    if not cores.is_integer():
        fail(f"bgperf result field cores is not an integer: {row[18]!r}")
    if min_idle > 100:
        fail(f"bgperf result min idle exceeds 100%: {row[14]!r}")
    if first_received > elapsed or tester_window > elapsed or elapsed > total_time:
        fail("bgperf timing fields violate first/tester <= elapsed <= total")
    if monitor_wait > total_time:
        fail("bgperf monitor wait exceeds total time")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?(?:B|KB|MB|GB|TB)", row[19]) is None:
        fail(f"bgperf result memory identity is malformed: {row[19]!r}")
    try:
        datetime.date.fromisoformat(row[17])
    except ValueError:
        fail(f"bgperf result date is malformed: {row[17]!r}")
    try:
        adapter_tester_errors = int(row[20])
    except ValueError:
        fail(f"bgperf adapter tester-error field is not an integer: {row[20]!r}")
    if adapter_tester_errors < 0:
        fail(f"bgperf adapter tester-error field is negative: {adapter_tester_errors}")
    # The raw log retains the adapter's hard-coded-directory value. Replace it
    # in the normalized receipt with the authoritative run-scoped verdict.
    row[20] = "0"

    args.result.parent.mkdir(parents=True, exist_ok=True)
    with args.result.open("w", encoding="utf-8", newline="") as result:
        writer = csv.writer(result, lineterminator="\n")
        writer.writerow(RESULT_HEADER)
        writer.writerow(row)
    print(f"result_sha256={sha256_file(args.result)}")
    print("peers=2")
    print("prefixes_per_peer=100000")
    print("required=200000")
    print("received=200000")
    print(f"event_history_mode={args.mode}")
    print("tester_errors=0")
    print("tester_error_authority=run_scoped_bird_logs")
    print(f"adapter_tester_errors_ignored={adapter_tester_errors}")
    print("tester_timeouts_field=0")
    print("tester_timeout_evidence=unsupported_by_pinned_bird_adapter")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    identity = commands.add_parser("identity", help="validate baseline/candidate commits")
    identity.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    identity.add_argument("--source-head", required=True)
    identity.add_argument("--baseline-commit", required=True)
    identity.add_argument("--baseline-ref-commit", required=True)
    identity.add_argument("--candidate-commit")
    identity.add_argument("--candidate-baseline-ancestor", choices=("true", "false"))
    identity.set_defaults(func=validate_identity)

    image = commands.add_parser("image", help="validate image labels and provenance")
    image.add_argument("--inspect", type=Path, required=True)
    image.add_argument("--builder-provenance", type=Path, required=True)
    image.add_argument("--runtime-provenance", type=Path, required=True)
    image.add_argument("--source-commit", required=True)
    image.add_argument("--bgperf2-commit", required=True)
    image.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    image.add_argument("--mode", choices=("enabled", "disabled"), required=True)
    image.set_defaults(func=validate_image)

    barrier = commands.add_parser(
        "barrier", help="validate the private wrapper barrier and normalize its receipt"
    )
    barrier.add_argument("--raw", type=Path, required=True)
    barrier.add_argument("--expected-pid", required=True)
    barrier.add_argument("--output", type=Path, required=True)
    barrier.set_defaults(func=validate_barrier)

    bgperf = commands.add_parser("bgperf", help="validate scenario and final result")
    bgperf.add_argument("--log", type=Path, required=True)
    bgperf.add_argument("--scenario", type=Path, required=True)
    bgperf.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    bgperf.add_argument("--mode", choices=("enabled", "disabled"), required=True)
    bgperf.add_argument("--bench-name", required=True)
    bgperf.add_argument("--run-receipt-dir", type=Path, required=True)
    bgperf.add_argument("--source-scenario", type=Path, required=True)
    bgperf.add_argument("--source-tester-log-dir", type=Path, required=True)
    bgperf.add_argument("--tester-log-dir", type=Path, required=True)
    bgperf.add_argument("--result", type=Path, required=True)
    bgperf.set_defaults(func=validate_bgperf)
    return root


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
