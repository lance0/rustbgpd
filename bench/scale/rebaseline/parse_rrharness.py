#!/usr/bin/env python3
"""Parse and gate the pinned LAN-395 rrharness comparison matrix."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
from pathlib import Path
import re
import sys

from classify_cpu import OUTPUT_PHASES


RESULT_FIELDS = (
    "variant",
    "commit",
    "mode",
    "clients",
    "candidates",
    "prefixes",
    "seconds",
    "repetition",
    "pair_order",
    "run_position",
    "rate_name",
    "rate",
    "rss_established_mib",
    "rss_converged_mib",
    "rss_end_mib",
    "setup_s",
    "window_s",
    "work_units",
    "mgr_cpu_s",
    "mgr_busy_frac",
    "folded_sha256",
    "classified_sha256",
    "total_samples",
)

COMPARISON_FIELDS = (
    "mode",
    "clients",
    "candidates",
    "prefixes",
    "repetition",
    "pair_order",
    "base_rate",
    "head_rate",
    "head_improvement_percent",
    "required_improvement_percent",
    "maximum_regression_percent",
    "verdict",
)

EXPECTED_SHAPES = {
    ("flood", 256, 0, 100_000, 20),
    ("flood", 1000, 0, 100_000, 20),
    ("churn", 256, 256, 3000, 20),
    ("churn", 1000, 1000, 3000, 20),
}

MODE_KEYS = {
    "flood": {
        "rss_established_mib",
        "cold_staged_s",
        "cold_drained_s",
        "rss_converged_mib",
        "sustained_blocks",
        "sustained_window_s",
        "mgr_cpu_s",
        "mgr_busy_frac",
        "rss_end_mib",
    },
    "churn": {
        "rss_established_mib",
        "prime_s",
        "rss_primed_mib",
        "waves",
        "waves_per_s",
        "window_s",
        "mgr_cpu_s",
        "mgr_busy_frac",
        "rss_end_mib",
    },
}

HEADER_RE = {
    "flood": re.compile(r"^# flood clients=(\d+) prefixes=(\d+) secs=(\d+)$"),
    "churn": re.compile(
        r"^# churn clients=(\d+) candidates=(\d+) prefixes=(\d+) secs=(\d+)$"
    ),
}

HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def finite_number(text: str, field: str) -> float:
    try:
        value = float(text)
    except ValueError as error:
        raise ValueError(f"{field} is not a number: {text!r}") from error
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return value


def positive_integer(text: str, field: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", text):
        raise ValueError(f"{field} must be a positive integer: {text!r}")
    return int(text)


def nonnegative_integer(text: str, field: str) -> int:
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", text):
        raise ValueError(f"{field} must be a nonnegative integer: {text!r}")
    return int(text)


def parse_log(path: Path, mode: str) -> tuple[tuple[int, ...], dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"{path}: empty log")
    header_matches: list[re.Match[str]] = []
    values: dict[str, str] = {}
    for line_number, line in enumerate(lines, 1):
        match = HEADER_RE[mode].fullmatch(line)
        if match:
            header_matches.append(match)
            continue
        if not line or line != line.strip():
            raise ValueError(f"{path}:{line_number}: blank or non-canonical row")
        columns = line.split(" ")
        if len(columns) != 2 or not columns[0] or not columns[1]:
            raise ValueError(f"{path}:{line_number}: expected exactly 'key value'")
        key, value = columns
        if key not in MODE_KEYS[mode]:
            raise ValueError(f"{path}:{line_number}: unknown key {key!r}")
        if key in values:
            raise ValueError(f"{path}:{line_number}: duplicate key {key!r}")
        values[key] = value
    if len(header_matches) != 1:
        raise ValueError(f"{path}: expected exactly one {mode} header")
    missing = MODE_KEYS[mode] - values.keys()
    if missing:
        raise ValueError(f"{path}: missing keys: {', '.join(sorted(missing))}")
    return tuple(int(value) for value in header_matches[0].groups()), values


def validate_classified(path: Path) -> int:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        fieldnames = tuple(reader.fieldnames or ())
        rows = list(reader)
    if fieldnames != ("phase", "samples", "share_percent"):
        raise ValueError(f"{path}: unexpected classified header")
    expected_names = (*OUTPUT_PHASES, "TOTAL")
    if tuple(row["phase"] for row in rows) != expected_names:
        raise ValueError(f"{path}: phases are incomplete, duplicated, or out of order")
    samples: list[int] = []
    shares: list[float] = []
    for row in rows:
        samples.append(nonnegative_integer(row["samples"], f"{row['phase']} samples"))
        shares.append(finite_number(row["share_percent"], f"{row['phase']} share"))
    total = samples[-1]
    if total <= 0 or sum(samples[:-1]) != total:
        raise ValueError(f"{path}: classified sample total mismatch")
    if not math.isclose(shares[-1], 100.0, abs_tol=0.000001):
        raise ValueError(f"{path}: TOTAL share is not 100 percent")
    if not math.isclose(sum(shares[:-1]), 100.0, abs_tol=0.00002):
        raise ValueError(f"{path}: phase shares do not sum to 100 percent")
    return total


def parse_command(args: argparse.Namespace) -> None:
    header, values = parse_log(args.log, args.mode)
    if args.mode == "flood":
        clients, prefixes, seconds = header
        candidates = 0
        units = positive_integer(values["sustained_blocks"], "sustained_blocks")
        window = finite_number(values["sustained_window_s"], "sustained_window_s")
        setup = finite_number(values["cold_staged_s"], "cold_staged_s") + finite_number(
            values["cold_drained_s"], "cold_drained_s"
        )
        if setup <= 0:
            raise ValueError("cold stage/drain timing must be positive")
        rate_name = "blocks_per_s"
        rate = units / window if window else 0.0
        converged_rss = finite_number(values["rss_converged_mib"], "rss_converged_mib")
    else:
        clients, candidates, prefixes, seconds = header
        units = positive_integer(values["waves"], "waves")
        window = finite_number(values["window_s"], "window_s")
        setup = finite_number(values["prime_s"], "prime_s")
        if setup <= 0:
            raise ValueError("prime_s must be positive")
        rate_name = "waves_per_s"
        rate = units / window if window else 0.0
        printed_rate = finite_number(values["waves_per_s"], "waves_per_s")
        if not math.isclose(printed_rate, rate, abs_tol=0.011, rel_tol=0.001):
            raise ValueError("printed waves_per_s does not match waves/window_s")
        converged_rss = finite_number(values["rss_primed_mib"], "rss_primed_mib")

    expected_shape = (args.mode, clients, candidates, prefixes, seconds)
    if expected_shape not in EXPECTED_SHAPES:
        raise ValueError(f"unexpected rrharness shape: {expected_shape}")
    if window < seconds:
        raise ValueError(f"profile window {window} is shorter than requested {seconds}s")
    if rate <= 0:
        raise ValueError(f"{rate_name} must be positive")
    cpu = finite_number(values["mgr_cpu_s"], "mgr_cpu_s")
    busy = finite_number(values["mgr_busy_frac"], "mgr_busy_frac")
    if busy > 1.05 or cpu > window * 1.05:
        raise ValueError("manager CPU/busy fraction exceeds a single-threaded bound")
    if not math.isclose(busy, cpu / window, abs_tol=0.0025, rel_tol=0.01):
        raise ValueError("mgr_busy_frac does not match mgr_cpu_s/window")
    if not args.folded.is_file() or args.folded.stat().st_size == 0:
        raise ValueError(f"{args.folded}: folded profile is missing or empty")
    if not args.classified.is_file() or args.classified.stat().st_size == 0:
        raise ValueError(f"{args.classified}: classified profile is missing or empty")
    total_samples = validate_classified(args.classified)
    if args.variant not in ("base", "head"):
        raise ValueError("variant must be base or head")
    if not COMMIT_RE.fullmatch(args.commit):
        raise ValueError("commit must be a full lowercase SHA-1")
    if args.repetition not in (1, 2):
        raise ValueError("repetition must be 1 or 2")
    expected_order = "base-first" if args.repetition == 1 else "head-first"
    if args.pair_order != expected_order:
        raise ValueError(f"repetition {args.repetition} must use {expected_order}")
    expected_position = {
        ("base-first", "base"): "first",
        ("base-first", "head"): "second",
        ("head-first", "head"): "first",
        ("head-first", "base"): "second",
    }[(args.pair_order, args.variant)]
    if args.run_position != expected_position:
        raise ValueError("run position does not match variant and pair order")

    row = {
        "variant": args.variant,
        "commit": args.commit,
        "mode": args.mode,
        "clients": clients,
        "candidates": candidates,
        "prefixes": prefixes,
        "seconds": seconds,
        "repetition": args.repetition,
        "pair_order": args.pair_order,
        "run_position": args.run_position,
        "rate_name": rate_name,
        "rate": f"{rate:.9f}",
        "rss_established_mib": f"{finite_number(values['rss_established_mib'], 'rss_established_mib'):.3f}",
        "rss_converged_mib": f"{converged_rss:.3f}",
        "rss_end_mib": f"{finite_number(values['rss_end_mib'], 'rss_end_mib'):.3f}",
        "setup_s": f"{setup:.6f}",
        "window_s": f"{window:.6f}",
        "work_units": units,
        "mgr_cpu_s": f"{cpu:.6f}",
        "mgr_busy_frac": f"{busy:.6f}",
        "folded_sha256": sha256(args.folded),
        "classified_sha256": sha256(args.classified),
        "total_samples": total_samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)


def read_results(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != RESULT_FIELDS:
            raise ValueError(f"{path}: unexpected results header")
        rows = list(reader)
    if len(rows) != 16:
        raise ValueError(f"{path}: expected 16 result rows, got {len(rows)}")
    return rows


def compare_command(args: argparse.Namespace) -> None:
    rows = read_results(args.input)
    pairs: dict[tuple[str, int, int, int, int], dict[str, dict[str, str]]] = {}
    commits: dict[str, str] = {}
    expected_raw_names: set[str] = set()
    for row in rows:
        variant = row["variant"]
        if variant not in ("base", "head"):
            raise ValueError(f"unexpected variant {variant!r}")
        if not COMMIT_RE.fullmatch(row["commit"]):
            raise ValueError("result contains a non-canonical commit")
        prior_commit = commits.setdefault(variant, row["commit"])
        if prior_commit != row["commit"]:
            raise ValueError(f"multiple {variant} commits in matrix")
        mode = row["mode"]
        clients = positive_integer(row["clients"], "clients")
        candidates = nonnegative_integer(row["candidates"], "candidates")
        prefixes = positive_integer(row["prefixes"], "prefixes")
        seconds = positive_integer(row["seconds"], "seconds")
        repetition = positive_integer(row["repetition"], "repetition")
        shape = (mode, clients, candidates, prefixes, seconds)
        if shape not in EXPECTED_SHAPES or repetition not in (1, 2):
            raise ValueError(f"unexpected matrix cell: {shape}, repetition={repetition}")
        expected_order = "base-first" if repetition == 1 else "head-first"
        if row["pair_order"] != expected_order:
            raise ValueError(f"invalid pair order for {shape}, repetition={repetition}")
        expected_position = (
            "first"
            if (expected_order, variant) in (("base-first", "base"), ("head-first", "head"))
            else "second"
        )
        if row["run_position"] != expected_position:
            raise ValueError(f"invalid run position for {shape}, repetition={repetition}")
        rate_name = "blocks_per_s" if mode == "flood" else "waves_per_s"
        if row["rate_name"] != rate_name or finite_number(row["rate"], "rate") <= 0:
            raise ValueError(f"invalid rate for {shape}, repetition={repetition}")
        for metric in (
            "rss_established_mib",
            "rss_converged_mib",
            "rss_end_mib",
            "setup_s",
            "window_s",
            "mgr_cpu_s",
            "mgr_busy_frac",
        ):
            finite_number(row[metric], metric)
        window = finite_number(row["window_s"], "window_s")
        cpu = finite_number(row["mgr_cpu_s"], "mgr_cpu_s")
        busy = finite_number(row["mgr_busy_frac"], "mgr_busy_frac")
        if window < seconds or cpu > window * 1.05 or busy > 1.05:
            raise ValueError(f"invalid timing/CPU evidence for {shape}")
        positive_integer(row["work_units"], "work_units")
        for digest_field in ("folded_sha256", "classified_sha256"):
            if not HEX_64_RE.fullmatch(row[digest_field]):
                raise ValueError(f"invalid {digest_field} for {shape}")
        if positive_integer(row["total_samples"], "total_samples") <= 0:
            raise AssertionError("unreachable")
        cell = (
            f"{mode}-{clients}-{candidates}-{prefixes}-"
            f"rep{repetition}-{variant}"
        )
        cell_paths = {
            "log": args.raw_dir / f"{cell}.log",
            "stderr": args.raw_dir / f"{cell}.stderr",
            "folded": args.raw_dir / f"{cell}.folded",
            "classified": args.raw_dir / f"{cell}.cpu.tsv",
        }
        expected_raw_names.update(path.name for path in cell_paths.values())
        for kind, path in cell_paths.items():
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"retained {kind} file is missing or not regular: {path}")
        if cell_paths["stderr"].stat().st_size != 0:
            raise ValueError(f"retained stderr is nonempty: {cell_paths['stderr']}")
        if sha256(cell_paths["folded"]) != row["folded_sha256"]:
            raise ValueError(f"retained folded hash differs from results row: {cell}")
        if sha256(cell_paths["classified"]) != row["classified_sha256"]:
            raise ValueError(f"retained classified hash differs from results row: {cell}")
        key = (mode, clients, candidates, prefixes, repetition)
        variants = pairs.setdefault(key, {})
        if variant in variants:
            raise ValueError(f"duplicate {variant} cell for {key}")
        variants[variant] = row

    expected_keys = {
        (mode, clients, candidates, prefixes, repetition)
        for mode, clients, candidates, prefixes, _seconds in EXPECTED_SHAPES
        for repetition in (1, 2)
    }
    if set(pairs) != expected_keys or any(set(variants) != {"base", "head"} for variants in pairs.values()):
        raise ValueError("matrix is incomplete or contains an unexpected pair")
    if commits.get("base") == commits.get("head"):
        raise ValueError("base and head commits are identical")
    if not args.raw_dir.is_dir() or args.raw_dir.is_symlink():
        raise ValueError(f"raw artifact root is missing or not a directory: {args.raw_dir}")
    actual_raw_names = {path.name for path in args.raw_dir.iterdir()}
    if actual_raw_names != expected_raw_names:
        raise ValueError("raw artifact set is incomplete or contains unexpected entries")

    comparisons: list[dict[str, object]] = []
    failed = False
    for key in sorted(pairs):
        mode, clients, candidates, prefixes, repetition = key
        variants = pairs[key]
        base_rate = finite_number(variants["base"]["rate"], "base rate")
        head_rate = finite_number(variants["head"]["rate"], "head rate")
        improvement = (head_rate / base_rate - 1.0) * 100.0
        required_improvement = 15.0 if mode == "churn" or clients == 1000 else 0.0
        maximum_regression = 5.0 if clients == 256 else 0.0
        verdict = "pass"
        if required_improvement and improvement + 1e-9 < required_improvement:
            verdict = "fail-improvement"
        elif maximum_regression and improvement < -maximum_regression - 1e-9:
            verdict = "fail-regression"
        failed |= verdict != "pass"
        comparisons.append(
            {
                "mode": mode,
                "clients": clients,
                "candidates": candidates,
                "prefixes": prefixes,
                "repetition": repetition,
                "pair_order": variants["base"]["pair_order"],
                "base_rate": f"{base_rate:.9f}",
                "head_rate": f"{head_rate:.9f}",
                "head_improvement_percent": f"{improvement:.6f}",
                "required_improvement_percent": f"{required_improvement:.1f}",
                "maximum_regression_percent": f"{maximum_regression:.1f}",
                "verdict": verdict,
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=COMPARISON_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(comparisons)
    if failed:
        raise ValueError("one or more LAN-395 throughput gates failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    parse = commands.add_parser("parse", help="validate one rrharness cell")
    parse.add_argument("--mode", choices=("flood", "churn"), required=True)
    parse.add_argument("--variant", choices=("base", "head"), required=True)
    parse.add_argument("--commit", required=True)
    parse.add_argument("--repetition", type=int, required=True)
    parse.add_argument("--pair-order", choices=("base-first", "head-first"), required=True)
    parse.add_argument("--run-position", choices=("first", "second"), required=True)
    parse.add_argument("--log", type=Path, required=True)
    parse.add_argument("--folded", type=Path, required=True)
    parse.add_argument("--classified", type=Path, required=True)
    parse.add_argument("--output", type=Path, required=True)
    parse.set_defaults(run=parse_command)
    compare = commands.add_parser("compare", help="validate and gate the complete matrix")
    compare.add_argument("--input", type=Path, required=True)
    compare.add_argument("--raw-dir", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.set_defaults(run=compare_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
