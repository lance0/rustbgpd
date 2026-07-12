#!/usr/bin/env python3
"""Classify DHAT v2 live-at-t-gmax bytes into deterministic components."""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import re
import sys
from typing import Any


COMPONENTS = (
    "Group RIB-Out table",
    "Loc-RIB best-path map",
    "Adj-RIB-In route storage",
    "Transport known-path memory",
    "Announcing-peers index",
    "Transport session buffers/scratch",
    "Prefix-trie index - Adj-RIB-In",
    "Prefix-trie index - group table",
    "Daemon core",
    "Transport import-decision cache",
    "RIB other",
    "API / peer-manager",
    "Per-peer Adj-RIB-Out",
    "Telemetry / tokio / rest",
    "other",
)

MAX_U64 = (1 << 64) - 1
DEFAULT_MAX_DERIVATIVE_ROWS = 10_000
DEFAULT_MAX_DERIVATIVE_BYTES = 8 * 1024 * 1024
DERIVATIVE_HEADER = "component\tlive_at_t_gmax_bytes\tstack_leaf_to_root"
RAW_FRAME = re.compile(r"^0x[0-9a-fA-F]+: (.+) \((.+):([0-9]+):([0-9]+)\)$")
ADDRESS = re.compile(r"(^|[^A-Za-z0-9_])0x[0-9a-fA-F]+")


def has(stack: list[str], *markers: str) -> bool:
    return any(any(marker in frame for marker in markers) for frame in stack)


def classify_stack(stack: list[str]) -> str:
    """Return the first owning component while walking DHAT leaf to root."""
    is_group = has(stack, "GroupRibOut::", "stage_group_prefixes")
    is_adj_in = has(stack, "AdjRibIn::")
    is_adj_out = has(stack, "AdjRibOut::")

    for frame in stack:  # DHAT/backtrace stores leaf to root.
        if "prefix_trie::" in frame or "FamilyPrefixMap" in frame:
            if is_adj_in:
                return "Prefix-trie index - Adj-RIB-In"
            if is_group:
                return "Prefix-trie index - group table"
        if "RouteSlab::" in frame and is_adj_in:
            return "Adj-RIB-In route storage"
        if "GroupRibOut::" in frame or ("AdjRibOut::" in frame and is_group):
            return "Group RIB-Out table"
        if "LocRib::" in frame:
            return "Loc-RIB best-path map"
        if "AdjRibIn::" in frame:
            return "Adj-RIB-In route storage"
        if "remember_known_path" in frame or "known_prefix_refcounts" in frame:
            return "Transport known-path memory"
        if "register_unicast_announcer" in frame or "unicast_prefix_peers" in frame:
            return "Announcing-peers index"
        if "ImportDecisionCache::" in frame or "import_decision_cache" in frame:
            return "Transport import-decision cache"
        if any(
            marker in frame
            for marker in (
                "ReadBuffer::",
                "process_read_buffer",
                "read_tcp",
                "writer::",
                "write_updates",
                "prepare_update",
            )
        ):
            return "Transport session buffers/scratch"
        if "RibManager::new" in frame or "PeerSession::new" in frame:
            return "Daemon core"
        if "rustbgpd_api::" in frame or "peer_manager::" in frame:
            return "API / peer-manager"
        if "AdjRibOut::" in frame and is_adj_out:
            return "Per-peer Adj-RIB-Out"
    # Generic crate/runtime markers are fallbacks, not owners. A leaf tokio
    # allocation under read_tcp or RibManager::new belongs to that later,
    # project-specific owner.
    if has(stack, "rustbgpd_rib::"):
        return "RIB other"
    if has(stack, "rustbgpd_telemetry::", "tokio::", "axum::"):
        return "Telemetry / tokio / rest"
    return "other"


def checked_add(left: int, right: int, context: str) -> int:
    if right < 0 or right > MAX_U64 or left > MAX_U64 - right:
        raise ValueError(f"{context} exceeds u64")
    return left + right


def checked_total(values: Any, context: str) -> int:
    total = 0
    for value in values:
        total = checked_add(total, value, context)
    return total


def encode_normalized_symbol(symbol: str) -> str:
    if symbol == "[root]":
        return symbol
    if not symbol or any(delimiter in symbol for delimiter in ("\t", "\n", "\r")):
        raise ValueError("normalized DHAT symbol is empty or contains a tab or newline")
    if "/" in symbol or "\\" in symbol or ADDRESS.search(symbol):
        raise ValueError(f"normalized DHAT symbol still contains a path or address: {symbol!r}")
    return symbol.replace("%", "%25").replace(";", "%3B")


def validate_encoded_symbol(symbol: str) -> str:
    if symbol == "[root]":
        return symbol
    if not symbol or any(delimiter in symbol for delimiter in ("\t", "\n", "\r", ";")):
        raise ValueError("encoded DHAT symbol is empty or contains a TSV/stack delimiter")
    decoded: list[str] = []
    index = 0
    while index < len(symbol):
        if symbol[index] != "%":
            decoded.append(symbol[index])
            index += 1
            continue
        escape = symbol[index : index + 3]
        if escape == "%25":
            decoded.append("%")
        elif escape == "%3B":
            decoded.append(";")
        else:
            raise ValueError(f"encoded DHAT symbol has invalid percent escape: {symbol!r}")
        index += 3
    raw = "".join(decoded)
    if encode_normalized_symbol(raw) != symbol:
        raise ValueError(f"encoded DHAT symbol is not canonical: {symbol!r}")
    return symbol


def normalized_symbol(frame: str) -> str:
    # DHAT frames are `0xADDR: symbol (trimmed/path.rs:line:column)`. Keeping
    # only the symbol removes addresses and host paths while retaining enough
    # stack context to audit or reclassify the compact derivative.
    if frame == "[root]":
        return frame
    match = RAW_FRAME.fullmatch(frame)
    if not match:
        raise ValueError(f"unrecognized DHAT frame; refusing unsanitized derivative: {frame!r}")
    return encode_normalized_symbol(match.group(1))


def load_profile(path: Path) -> tuple[dict[str, int], list[tuple[str, int, tuple[str, ...]]]]:
    document: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("dhatFileVersion") != 2:
        raise ValueError(f"{path}: expected DHAT file format version 2")
    frames = document.get("ftbl")
    points = document.get("pps")
    if not isinstance(frames, list) or not all(isinstance(frame, str) for frame in frames):
        raise ValueError(f"{path}: ftbl must be an array of strings")
    if not isinstance(points, list):
        raise ValueError(f"{path}: pps must be an array")

    totals = {component: 0 for component in COMPONENTS}
    derivative: dict[tuple[str, tuple[str, ...]], int] = {}
    for index, point in enumerate(points):
        if not isinstance(point, dict):
            raise ValueError(f"{path}: pps[{index}] must be an object")
        live_bytes = point.get("gb")
        frame_indexes = point.get("fs")
        if not isinstance(live_bytes, int) or isinstance(live_bytes, bool) or live_bytes < 0:
            raise ValueError(f"{path}: pps[{index}].gb must be a non-negative integer")
        if not isinstance(frame_indexes, list) or not all(
            isinstance(item, int) and not isinstance(item, bool) for item in frame_indexes
        ):
            raise ValueError(f"{path}: pps[{index}].fs must be an array of integers")
        try:
            stack = [frames[item] for item in frame_indexes]
        except IndexError as error:
            raise ValueError(f"{path}: pps[{index}].fs contains an invalid ftbl index") from error
        if any(item < 0 for item in frame_indexes):
            raise ValueError(f"{path}: pps[{index}].fs contains an invalid ftbl index")
        if live_bytes:
            normalized_stack = tuple(normalized_symbol(frame) for frame in stack)
            component = classify_stack(list(normalized_stack))
            totals[component] = checked_add(
                totals[component], live_bytes, f"{component} live-byte total"
            )
            key = (component, normalized_stack)
            derivative[key] = checked_add(
                derivative.get(key, 0), live_bytes, "derivative stack live-byte total"
            )
    if checked_total(totals.values(), "profile live-byte total") == 0:
        raise ValueError(f"{path}: profile has no live bytes at t-gmax")
    rows = [
        (component, count, stack) for (component, stack), count in derivative.items()
    ]
    rows.sort(key=lambda row: (COMPONENTS.index(row[0]), -row[1], row[2]))
    return totals, rows


def render(totals: dict[str, int]) -> str:
    total = checked_total(totals.values(), "classified live-byte total")
    lines = ["component\tlive_at_t_gmax_bytes\tshare_percent"]
    for component in COMPONENTS:
        count = totals[component]
        lines.append(f"{component}\t{count}\t{count * 100.0 / total:.6f}")
    lines.append(f"TOTAL\t{total}\t100.000000")
    return "\n".join(lines) + "\n"


def render_derivative(
    rows: list[tuple[str, int, tuple[str, ...]]], max_rows: int, max_bytes: int
) -> str:
    if len(rows) > max_rows:
        raise ValueError(f"derivative has {len(rows)} rows; limit is {max_rows}")
    lines = [DERIVATIVE_HEADER]
    lines.extend(
        f"{component}\t{count}\t{';'.join(stack)}" for component, count, stack in rows
    )
    output = "\n".join(lines) + "\n"
    size = len(output.encode("utf-8"))
    if size > max_bytes:
        raise ValueError(f"derivative is {size} bytes; limit is {max_bytes}")
    return output


def parse_derivative(
    text: str, source: str, max_rows: int, max_bytes: int
) -> tuple[dict[str, int], list[tuple[str, int, tuple[str, ...]]]]:
    size = len(text.encode("utf-8"))
    if size > max_bytes:
        raise ValueError(f"{source}: derivative is {size} bytes; limit is {max_bytes}")
    lines = text.splitlines()
    if not lines or lines[0] != DERIVATIVE_HEADER:
        raise ValueError(f"{source}: invalid derivative header")
    if len(lines) - 1 > max_rows:
        raise ValueError(f"{source}: derivative has {len(lines) - 1} rows; limit is {max_rows}")

    totals = {component: 0 for component in COMPONENTS}
    aggregated: dict[tuple[str, tuple[str, ...]], int] = {}
    for line_number, line in enumerate(lines[1:], 2):
        columns = line.split("\t")
        if len(columns) != 3:
            raise ValueError(f"{source}:{line_number}: expected three tab-separated columns")
        recorded_component, count_text, stack_text = columns
        if recorded_component not in COMPONENTS:
            raise ValueError(f"{source}:{line_number}: unknown component {recorded_component!r}")
        try:
            count = int(count_text)
        except ValueError as error:
            raise ValueError(f"{source}:{line_number}: invalid live-byte count") from error
        if count <= 0 or count > MAX_U64:
            raise ValueError(f"{source}:{line_number}: live-byte count must fit positive u64")
        stack = tuple(validate_encoded_symbol(frame) for frame in stack_text.split(";"))
        actual_component = classify_stack(list(stack))
        if actual_component != recorded_component:
            raise ValueError(
                f"{source}:{line_number}: recorded component {recorded_component!r} "
                f"does not match classifier result {actual_component!r}"
            )
        totals[actual_component] = checked_add(
            totals[actual_component], count, f"{actual_component} derivative total"
        )
        key = (actual_component, stack)
        aggregated[key] = checked_add(
            aggregated.get(key, 0), count, "derivative stack live-byte total"
        )

    if checked_total(totals.values(), "derivative live-byte total") == 0:
        raise ValueError(f"{source}: derivative contains no live bytes")
    rows = [(component, count, stack) for (component, stack), count in aggregated.items()]
    rows.sort(key=lambda row: (COMPONENTS.index(row[0]), -row[1], row[2]))
    canonical = render_derivative(rows, max_rows, max_bytes)
    if canonical != text:
        raise ValueError(f"{source}: derivative is not canonical (sorted, aggregated, final newline)")
    return totals, rows


def load_derivative(
    path: Path, max_rows: int, max_bytes: int
) -> tuple[dict[str, int], list[tuple[str, int, tuple[str, ...]]]]:
    return parse_derivative(path.read_text(encoding="utf-8"), str(path), max_rows, max_bytes)


def check(expected_path: Path, actual: str) -> None:
    expected = expected_path.read_text(encoding="utf-8")
    if actual == expected:
        return
    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=str(expected_path),
            tofile="classified output",
        )
    )
    raise ValueError(f"classified output differs from fixture:\n{diff}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dhat_json", type=Path, nargs="?")
    parser.add_argument("--from-derivative", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--derivative", type=Path)
    parser.add_argument("--check", type=Path, metavar="EXPECTED")
    parser.add_argument("--max-derivative-rows", type=int, default=DEFAULT_MAX_DERIVATIVE_ROWS)
    parser.add_argument("--max-derivative-bytes", type=int, default=DEFAULT_MAX_DERIVATIVE_BYTES)
    args = parser.parse_args()

    try:
        if (args.dhat_json is None) == (args.from_derivative is None):
            raise ValueError("provide exactly one DHAT JSON path or --from-derivative PATH")
        if args.max_derivative_rows <= 0 or args.max_derivative_bytes <= 0:
            raise ValueError("derivative row and byte limits must be positive")
        if args.from_derivative:
            if args.derivative:
                raise ValueError("--derivative cannot be combined with --from-derivative")
            totals, _ = load_derivative(
                args.from_derivative, args.max_derivative_rows, args.max_derivative_bytes
            )
            derivative_output = None
        else:
            assert args.dhat_json is not None
            totals, derivative = load_profile(args.dhat_json)
            derivative_output = render_derivative(
                derivative, args.max_derivative_rows, args.max_derivative_bytes
            )
            # Capture fails unless the sanitized derivative independently
            # reclassifies to exactly the raw profile's totals.
            verified, _ = parse_derivative(
                derivative_output,
                "generated derivative",
                args.max_derivative_rows,
                args.max_derivative_bytes,
            )
            if verified != totals:
                raise ValueError("generated derivative totals differ from raw DHAT profile")
        output = render(totals)
        if args.check:
            check(args.check, output)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        elif not args.check:
            sys.stdout.write(output)
        if args.derivative:
            assert derivative_output is not None
            args.derivative.write_text(derivative_output, encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
