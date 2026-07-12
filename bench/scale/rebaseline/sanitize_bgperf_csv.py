#!/usr/bin/env python3
"""Validate and reduce one bgperf2 result to the bounded receipt schema."""

from __future__ import annotations

import argparse
import csv
from decimal import Decimal, InvalidOperation
import difflib
import io
from pathlib import Path
import re
import sys


MAX_INPUT_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 4 * 1024
RAW_HEADER = (
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
    "failed",
    "MSG",
    "filters",
)
# jauderho/bgperf2 commit 17216483e779f1484ef38562fb8f6b5ea6ad4d8f emits
# tester_timeouts in the data row but omits that label from stats_header(). Pin
# the actual 25-value row explicitly so upstream drift fails closed instead of
# shifting metrics by a column.
RAW_ROW_FIELDS = RAW_HEADER[:21] + ("tester timeouts",) + RAW_HEADER[21:]
OUTPUT_FIELDS = (
    "target",
    "version",
    "peers",
    "prefixes_per_peer",
    "required",
    "received",
    "monitor_seconds",
    "elapsed_seconds",
    "prefix_received_seconds",
    "testers_seconds",
    "total_time_seconds",
    "max_cpu_percent",
    "max_mem_gb",
    "tester_errors",
    "tester_timeouts",
)
LONG_HEX_ID = re.compile(r"\b[0-9a-fA-F]{16,}\b")
SAFE_VERSION = re.compile(r"[A-Za-z0-9._+() -]{1,80}")
SAFE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,12})(?:\.[0-9]{1,6})?")


def integer(value: str, field: str) -> str:
    if not value.isascii() or not value.isdigit():
        raise ValueError(f"{field} must be an unsigned decimal integer")
    return str(int(value))


def decimal(value: str, field: str, maximum: Decimal) -> str:
    if len(value) > 32 or not SAFE_DECIMAL.fullmatch(value):
        raise ValueError(f"{field} must use bounded fixed decimal syntax")
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"{field} must be a decimal number") from error
    if not number.is_finite() or number < 0 or number > maximum:
        raise ValueError(f"{field} is outside the permitted range 0..{maximum}")
    result = format(number, "f")
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return result


def render_output(output: dict[str, str]) -> str:
    rendered = io.StringIO(newline="")
    writer = csv.DictWriter(rendered, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerow(output)
    result = rendered.getvalue()
    if len(result.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("sanitized output exceeded fixed byte limit")
    return result


def require_loaded_metrics(output: dict[str, str], source: Path) -> None:
    for field in ("elapsed_seconds", "total_time_seconds", "max_cpu_percent", "max_mem_gb"):
        if Decimal(output[field]) <= 0:
            raise ValueError(f"{source}: loaded receipt metric {field} must be positive")


def load(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"{path}: input is {len(raw)} bytes; limit is {MAX_INPUT_BYTES}")
    text = raw.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text), skipinitialspace=True))
    if len(rows) != 2:
        raise ValueError(f"{path}: expected exactly one header and one result row")
    header = tuple(value.strip() for value in rows[0])
    values = tuple(value.strip() for value in rows[1])
    if header != RAW_HEADER:
        raise ValueError(f"{path}: unsupported bgperf2 header/schema")
    if len(values) != len(RAW_ROW_FIELDS):
        raise ValueError(f"{path}: expected {len(RAW_ROW_FIELDS)} result fields")
    for value in values:
        if any(marker in value for marker in ("/", "\\", "\0", "\t", "\n", "\r")):
            raise ValueError(f"{path}: result contains a path or control character")
        if LONG_HEX_ID.search(value):
            raise ValueError(f"{path}: result contains a process/container-like identifier")

    row = dict(zip(RAW_ROW_FIELDS, values, strict=True))
    if row["name"] != "rustbgpd" or row["target"] != "rustbgpd":
        raise ValueError(f"{path}: receipt target/name must both be rustbgpd")
    if not SAFE_VERSION.fullmatch(row["version"]):
        raise ValueError(f"{path}: unsafe or empty target version")
    peers = integer(row["peers"], "peers")
    prefixes = integer(row["prefixes per peer"], "prefixes per peer")
    if peers != "2" or prefixes != "100000":
        raise ValueError(f"{path}: expected the pinned 2 peers x 100000 prefixes shape")
    required = integer(row["required"], "required")
    received = integer(row["received"], "received")
    expected = int(peers) * int(prefixes)
    if int(required) != expected or received != required:
        raise ValueError(
            f"{path}: required and received must equal peers x prefixes ({expected})"
        )
    errors = integer(row["tester errors"], "tester errors")
    timeouts = integer(row["tester timeouts"], "tester timeouts")
    if errors != "0" or timeouts != "0" or any(
        row[field] for field in ("failed", "MSG", "filters", "flags")
    ):
        raise ValueError(f"{path}: failed/filtered/error runs are not valid receipts")

    output = {
        "target": row["target"],
        "version": row["version"],
        "peers": peers,
        "prefixes_per_peer": prefixes,
        "required": required,
        "received": received,
        "monitor_seconds": decimal(row["monitor (s)"], "monitor (s)", Decimal(86400)),
        "elapsed_seconds": decimal(row["elapsed (s)"], "elapsed (s)", Decimal(86400)),
        "prefix_received_seconds": decimal(
            row["prefix received (s)"], "prefix received (s)", Decimal(86400)
        ),
        "testers_seconds": decimal(row["testers (s)"], "testers (s)", Decimal(86400)),
        "total_time_seconds": decimal(row["total time"], "total time", Decimal(86400)),
        "max_cpu_percent": decimal(row["max cpu %"], "max cpu %", Decimal(100000)),
        "max_mem_gb": decimal(row["max mem (GB)"], "max mem (GB)", Decimal(1000000)),
        "tester_errors": errors,
        "tester_timeouts": timeouts,
    }
    require_loaded_metrics(output, path)
    return render_output(output)


def load_sanitized(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError(f"{path}: sanitized CSV exceeds {MAX_OUTPUT_BYTES} bytes")
    text = raw.decode("utf-8")
    rows = list(csv.reader(io.StringIO(text)))
    if len(rows) != 2 or tuple(rows[0]) != OUTPUT_FIELDS or len(rows[1]) != len(OUTPUT_FIELDS):
        raise ValueError(f"{path}: invalid sanitized CSV schema or row count")
    row = dict(zip(OUTPUT_FIELDS, rows[1], strict=True))
    if row["target"] != "rustbgpd" or not SAFE_VERSION.fullmatch(row["version"]):
        raise ValueError(f"{path}: invalid sanitized target/version")
    peers = integer(row["peers"], "peers")
    prefixes = integer(row["prefixes_per_peer"], "prefixes_per_peer")
    required = integer(row["required"], "required")
    received = integer(row["received"], "received")
    if peers != "2" or prefixes != "100000" or int(required) != 200000 or received != required:
        raise ValueError(f"{path}: sanitized CSV is not a converged 2x100k run")
    validated = {
        "target": row["target"],
        "version": row["version"],
        "peers": peers,
        "prefixes_per_peer": prefixes,
        "required": required,
        "received": received,
        "monitor_seconds": decimal(row["monitor_seconds"], "monitor_seconds", Decimal(86400)),
        "elapsed_seconds": decimal(row["elapsed_seconds"], "elapsed_seconds", Decimal(86400)),
        "prefix_received_seconds": decimal(
            row["prefix_received_seconds"], "prefix_received_seconds", Decimal(86400)
        ),
        "testers_seconds": decimal(row["testers_seconds"], "testers_seconds", Decimal(86400)),
        "total_time_seconds": decimal(
            row["total_time_seconds"], "total_time_seconds", Decimal(86400)
        ),
        "max_cpu_percent": decimal(
            row["max_cpu_percent"], "max_cpu_percent", Decimal(100000)
        ),
        "max_mem_gb": decimal(row["max_mem_gb"], "max_mem_gb", Decimal(1000000)),
        "tester_errors": integer(row["tester_errors"], "tester_errors"),
        "tester_timeouts": integer(row["tester_timeouts"], "tester_timeouts"),
    }
    if validated["tester_errors"] != "0" or validated["tester_timeouts"] != "0":
        raise ValueError(f"{path}: sanitized CSV records tester failures")
    require_loaded_metrics(validated, path)
    canonical = render_output(validated)
    if canonical != text:
        raise ValueError(f"{path}: sanitized CSV is not canonical")
    return canonical


def check(expected_path: Path, actual: str) -> None:
    expected = expected_path.read_text(encoding="utf-8")
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=str(expected_path),
            tofile="sanitized output",
        )
    )
    raise ValueError(f"sanitized output differs from fixture:\n{diff}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bgperf_csv", type=Path, nargs="?")
    parser.add_argument("--from-sanitized", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path, metavar="EXPECTED")
    args = parser.parse_args()
    try:
        if (args.bgperf_csv is None) == (args.from_sanitized is None):
            raise ValueError("provide exactly one raw CSV or --from-sanitized PATH")
        if args.from_sanitized:
            output = load_sanitized(args.from_sanitized)
        else:
            assert args.bgperf_csv is not None
            output = load(args.bgperf_csv)
        if args.check:
            check(args.check, output)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        elif not args.check:
            sys.stdout.write(output)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
