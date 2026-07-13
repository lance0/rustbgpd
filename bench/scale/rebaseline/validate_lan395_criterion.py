#!/usr/bin/env python3
"""Validate and sanitize the pinned LAN-395 Criterion comparison receipt."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import socket
import tempfile


SCHEMA = "rustbgpd.lan395-criterion-receipt.v1"
PIN_SCHEMA = "rustbgpd.lan395-run-pin.v1"
ATTEMPTS = (1, 2)
POLICIES = ("no_policy", "with_policy")
PEER_COUNTS = (1, 8, 64, 256)
CI_GATE_PEERS = (64, 256)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_DIR_RE = re.compile(r"^attempt-[0-9]+-(?:base|head)$")
MAX_TEXT_INPUT = 1024 * 1024

PIN_FIELDS = (
    "schema",
    "base_commit",
    "head_commit",
    "production_diff_sha256",
    "tooling_commit",
)

METADATA_FIELDS = (
    "run_id",
    "base_ref",
    "base_sha",
    "head_ref",
    "head_sha",
    "package",
    "bench",
    "filter",
    "features",
    "core",
    "attempts",
    "fail_on_regression",
    "regression_threshold_pct",
    "regression_max_stddev_pct",
    "verdict_min_attempts",
    "governor",
    "use_taskset",
    "base_target_dir",
    "head_target_dir",
    "criterion_dir",
)

CSV_FIELDS = (
    "policy",
    "peers",
    "attempt",
    "base_median_ns",
    "base_ci95_low_ns",
    "base_ci95_high_ns",
    "head_median_ns",
    "head_ci95_low_ns",
    "head_ci95_high_ns",
    "delta_percent",
    "conservative_ci95_low_percent",
    "conservative_ci95_high_percent",
    "gate",
    "verdict",
    "base_estimates_sha256",
    "head_estimates_sha256",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular(path: Path, description: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{description} is missing, not regular, or a symlink: {path}")


def require_directory(path: Path, description: str) -> None:
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"{description} is missing, not a directory, or a symlink: {path}")


def reject_symlink_chain(root: Path, path: Path) -> None:
    """Reject a symlink in any input component at or beneath root."""
    require_directory(root, "Criterion artifact root")
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"Criterion input escapes artifact root: {path}") from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Criterion input contains a symlink component: {current}")


def read_bounded(path: Path, description: str) -> bytes:
    require_regular(path, description)
    size = path.stat().st_size
    if size <= 0 or size > MAX_TEXT_INPUT:
        raise ValueError(f"{description} must be between 1 and {MAX_TEXT_INPUT} bytes")
    return path.read_bytes()


def parse_canonical_kv_prefix(
    path: Path, expected_fields: tuple[str, ...], description: str
) -> tuple[dict[str, str], bytes]:
    data = read_bounded(path, description)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{description} is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise ValueError(f"{description} is not canonical newline-terminated text")
    lines = text.splitlines()
    prefix = lines[: len(expected_fields)]
    if len(prefix) != len(expected_fields):
        raise ValueError(f"{description} is missing required fields")
    values: dict[str, str] = {}
    for expected, line in zip(expected_fields, prefix, strict=True):
        if "=" not in line:
            raise ValueError(f"{description} contains a malformed field")
        key, value = line.split("=", 1)
        if key != expected or not value:
            raise ValueError(
                f"{description} expected nonempty {expected!r}, found {key!r}"
            )
        if key in values:
            raise ValueError(f"{description} contains duplicate field {key!r}")
        values[key] = value
    return values, data


def parse_pin(path: Path) -> tuple[dict[str, str], bytes]:
    values, data = parse_canonical_kv_prefix(path, PIN_FIELDS, "LAN-395 run pin")
    if len(data.decode("utf-8").splitlines()) != len(PIN_FIELDS):
        raise ValueError("LAN-395 run pin must contain exactly five canonical rows")
    if values["schema"] != PIN_SCHEMA:
        raise ValueError("LAN-395 run pin schema mismatch")
    for field in ("base_commit", "head_commit", "tooling_commit"):
        if not SHA1_RE.fullmatch(values[field]):
            raise ValueError(f"LAN-395 run pin {field} is not a full lowercase SHA-1")
    if not SHA256_RE.fullmatch(values["production_diff_sha256"]):
        raise ValueError("LAN-395 production diff digest is not a lowercase SHA-256")
    if values["base_commit"] == values["head_commit"]:
        raise ValueError("LAN-395 base and head commits are identical")
    return values, data


def parse_metadata(path: Path, run_dir: Path, pin: dict[str, str]) -> dict[str, str]:
    values, data = parse_canonical_kv_prefix(
        path, METADATA_FIELDS, "Criterion comparison metadata"
    )
    lines = data.decode("utf-8").splitlines()
    if len(lines) <= len(METADATA_FIELDS) or lines[len(METADATA_FIELDS)] != "":
        raise ValueError("Criterion metadata key block must end after the canonical fields")
    exact = {
        "base_sha": pin["base_commit"],
        "head_sha": pin["head_commit"],
        "package": "rustbgpd-transport",
        "bench": "fanout",
        "filter": "distribute_fanout",
        "features": "bench-internals",
        "core": "5",
        "attempts": "2",
        "fail_on_regression": "0",
        "regression_threshold_pct": "3",
        "regression_max_stddev_pct": "10",
        "verdict_min_attempts": "3",
        "governor": "performance",
        "use_taskset": "1",
    }
    for field, expected in exact.items():
        if values[field] != expected:
            raise ValueError(
                f"Criterion metadata {field} must be {expected!r}, got {values[field]!r}"
            )
    expected_paths = {
        "base_target_dir": run_dir / "target-base",
        "head_target_dir": run_dir / "target-head",
        "criterion_dir": run_dir / "criterion",
    }
    for field, expected in expected_paths.items():
        require_directory(expected, f"Criterion metadata {field}")
        try:
            actual = Path(values[field]).resolve(strict=True)
            resolved_expected = expected.resolve(strict=True)
        except OSError as error:
            raise ValueError(f"Criterion metadata {field} does not resolve") from error
        if actual != resolved_expected:
            raise ValueError(f"Criterion metadata {field} does not bind the run directory")
    return values


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def number(value: object, field: str, *, positive: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a JSON number")
    converted = float(value)
    if not math.isfinite(converted):
        raise ValueError(f"{field} must be finite")
    if positive and converted <= 0:
        raise ValueError(f"{field} must be positive")
    if not positive and converted < 0:
        raise ValueError(f"{field} must be nonnegative")
    return converted


def parse_estimate(
    path: Path, criterion_root: Path
) -> tuple[tuple[float, float, float], bytes]:
    reject_symlink_chain(criterion_root, path)
    data = read_bounded(path, "Criterion estimates input")
    try:
        document = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid Criterion estimates JSON: {path}") from error
    if not isinstance(document, dict) or not isinstance(document.get("median"), dict):
        raise ValueError(f"Criterion estimates JSON lacks a median object: {path}")
    median = document["median"]
    if set(median) != {"confidence_interval", "point_estimate", "standard_error"}:
        raise ValueError(f"Criterion median schema mismatch: {path}")
    interval = median["confidence_interval"]
    if not isinstance(interval, dict) or set(interval) != {
        "confidence_level",
        "lower_bound",
        "upper_bound",
    }:
        raise ValueError(f"Criterion median confidence interval schema mismatch: {path}")
    confidence = number(interval["confidence_level"], "confidence_level", positive=True)
    if not math.isclose(confidence, 0.95, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError(f"Criterion median confidence level is not 95 percent: {path}")
    low = number(interval["lower_bound"], "median lower bound", positive=True)
    point = number(median["point_estimate"], "median point estimate", positive=True)
    high = number(interval["upper_bound"], "median upper bound", positive=True)
    number(median["standard_error"], "median standard error", positive=False)
    if not low <= point <= high:
        raise ValueError(f"Criterion median confidence bounds do not contain the point: {path}")
    return (point, low, high), data


def expected_estimate_paths(criterion_root: Path) -> dict[tuple[str, int, int, str], Path]:
    return {
        (policy, peers, attempt, variant): (
            criterion_root
            / "distribute_fanout"
            / policy
            / str(peers)
            / f"attempt-{attempt}-{variant}"
            / "estimates.json"
        )
        for policy in POLICIES
        for peers in PEER_COUNTS
        for attempt in ATTEMPTS
        for variant in ("base", "head")
    }


def reject_unexpected_attempts(criterion_root: Path, expected: set[Path]) -> None:
    expected_dirs = {path.parent for path in expected}
    actual_dirs: set[Path] = set()
    for path in criterion_root.rglob("*"):
        if not path.name.startswith("attempt-"):
            continue
        reject_symlink_chain(criterion_root, path)
        if not path.is_dir() or not ATTEMPT_DIR_RE.fullmatch(path.name):
            raise ValueError(f"non-canonical Criterion attempt directory: {path}")
        actual_dirs.add(path)
    if actual_dirs != expected_dirs:
        missing = sorted(
            str(path.relative_to(criterion_root)) for path in expected_dirs - actual_dirs
        )
        extra = sorted(
            str(path.relative_to(criterion_root)) for path in actual_dirs - expected_dirs
        )
        raise ValueError(
            "Criterion attempt matrix mismatch; "
            f"missing={missing!r}, unexpected={extra!r}"
        )


def write_receipt(
    output_dir: Path,
    run_dir: Path,
    pin_path: Path,
) -> None:
    require_directory(run_dir, "Criterion run directory")
    pin, pin_data = parse_pin(pin_path)
    metadata = parse_metadata(run_dir / "metadata.txt", run_dir, pin)
    criterion_root = run_dir / "criterion"
    require_directory(criterion_root, "Criterion artifact root")
    expected_paths = expected_estimate_paths(criterion_root)
    reject_unexpected_attempts(criterion_root, set(expected_paths.values()))

    parsed: dict[
        tuple[str, int, int, str], tuple[tuple[float, float, float], bytes]
    ] = {}
    for key, path in expected_paths.items():
        parsed[key] = parse_estimate(path, criterion_root)

    rows: list[dict[str, object]] = []
    ci_gates: list[dict[str, object]] = []
    one_peer_deltas: dict[str, list[float]] = {policy: [] for policy in POLICIES}
    gate_failed = False
    for policy in POLICIES:
        for peers in PEER_COUNTS:
            for attempt in ATTEMPTS:
                base, base_data = parsed[(policy, peers, attempt, "base")]
                head, head_data = parsed[(policy, peers, attempt, "head")]
                base_point, base_low, base_high = base
                head_point, head_low, head_high = head
                delta = (head_point / base_point - 1.0) * 100.0
                ci_low = (head_low / base_high - 1.0) * 100.0
                ci_high = (head_high / base_low - 1.0) * 100.0
                if peers in CI_GATE_PEERS:
                    gate = "ci-entirely-below-zero"
                    passed = ci_high < 0.0
                    verdict = "pass" if passed else "fail"
                    gate_failed |= not passed
                    ci_gates.append(
                        {
                            "attempt": attempt,
                            "conservative_ci95_high_percent": round(ci_high, 9),
                            "passed": passed,
                            "peers": peers,
                            "policy": policy,
                        }
                    )
                elif peers == 1:
                    gate = "mean-delta-below-five-percent"
                    verdict = "aggregate"
                    one_peer_deltas[policy].append(delta)
                else:
                    gate = "informational"
                    verdict = "informational"
                rows.append(
                    {
                        "policy": policy,
                        "peers": peers,
                        "attempt": attempt,
                        "base_median_ns": f"{base_point:.9f}",
                        "base_ci95_low_ns": f"{base_low:.9f}",
                        "base_ci95_high_ns": f"{base_high:.9f}",
                        "head_median_ns": f"{head_point:.9f}",
                        "head_ci95_low_ns": f"{head_low:.9f}",
                        "head_ci95_high_ns": f"{head_high:.9f}",
                        "delta_percent": f"{delta:.9f}",
                        "conservative_ci95_low_percent": f"{ci_low:.9f}",
                        "conservative_ci95_high_percent": f"{ci_high:.9f}",
                        "gate": gate,
                        "verdict": verdict,
                        "base_estimates_sha256": sha256_bytes(base_data),
                        "head_estimates_sha256": sha256_bytes(head_data),
                    }
                )

    one_peer_gates: list[dict[str, object]] = []
    for policy in POLICIES:
        deltas = one_peer_deltas[policy]
        if len(deltas) != len(ATTEMPTS):
            raise AssertionError("complete input matrix did not produce two one-peer deltas")
        mean_delta = sum(deltas) / len(deltas)
        passed = mean_delta < 5.0
        gate_failed |= not passed
        one_peer_gates.append(
            {
                "mean_delta_percent": round(mean_delta, 9),
                "passed": passed,
                "policy": policy,
                "strict_upper_bound_percent": 5.0,
            }
        )
    if gate_failed:
        raise ValueError("one or more LAN-395 Criterion acceptance gates failed")

    output_dir = output_dir.absolute()
    parent = output_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    require_directory(parent, "Criterion receipt parent")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError(f"Criterion receipt output already exists: {output_dir}")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=parent))
    try:
        csv_path = temporary / "criterion-attempts.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

        input_hashes_path = temporary / "criterion-inputs.sha256"
        input_hash_lines = []
        for key, path in sorted(expected_paths.items()):
            reject_symlink_chain(criterion_root, path)
            relative = path.relative_to(run_dir).as_posix()
            data = path.read_bytes()
            # Reconcile the retained file with the exact bytes already parsed.
            parsed_data = parsed[key][1]
            if data != parsed_data:
                raise ValueError(f"Criterion estimates changed during validation: {path}")
            input_hash_lines.append(f"{sha256_bytes(data)}  {relative}\n")
        input_hashes_path.write_text("".join(input_hash_lines), encoding="utf-8")

        gates = {
            "attempts": len(ATTEMPTS),
            "base_commit": pin["base_commit"],
            "benchmark": "fanout",
            "ci_gates": ci_gates,
            "feature_set": ["bench-internals"],
            "filter": "distribute_fanout",
            "governor": "performance",
            "head_commit": pin["head_commit"],
            "matrix_rows": len(rows),
            "one_peer_gates": one_peer_gates,
            "overall_verdict": "pass",
            "package": "rustbgpd-transport",
            "pin_sha256": sha256_bytes(pin_data),
            "production_diff_sha256": pin["production_diff_sha256"],
            "schema": SCHEMA,
            "taskset_core": int(metadata["core"]),
            "tooling_commit": pin["tooling_commit"],
        }
        gates_path = temporary / "criterion-gates.json"
        gates_path.write_text(
            json.dumps(gates, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )

        forbidden = {
            value
            for value in (
                str(run_dir.absolute()),
                str(Path.home()),
                socket.gethostname(),
            )
            if len(value) >= 4
        }
        for path in (csv_path, input_hashes_path, gates_path):
            text = path.read_text(encoding="utf-8")
            if any(value and value in text for value in forbidden):
                raise ValueError("sanitized Criterion receipt contains private host data")

        checksum_path = temporary / "SHA256SUMS"
        checksum_members = (csv_path, gates_path, input_hashes_path)
        checksum_path.write_text(
            "".join(
                f"{sha256_file(path)}  {path.name}\n"
                for path in sorted(checksum_members, key=lambda item: item.name)
            ),
            encoding="utf-8",
        )
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            if sha256_file(temporary / name) != digest:
                raise ValueError("Criterion receipt checksum reconciliation failed")
        completed_path = temporary / "COMPLETED"
        completed_path.write_text(
            f"schema={SCHEMA}\n"
            f"sha256sums_sha256={sha256_file(checksum_path)}\n"
            "matrix_complete=1\n"
            "criterion_gates_passed=1\n",
            encoding="utf-8",
        )
        temporary.rename(output_dir)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--pin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        write_receipt(args.output_dir, args.run_dir, args.pin)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
