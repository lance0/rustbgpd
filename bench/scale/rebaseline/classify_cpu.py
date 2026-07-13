#!/usr/bin/env python3
"""Classify rrharness folded samples into the committed RIB phase map."""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path
import sys


# The input is standard folded-stack order (root to leaf). Classification walks
# it leaf first; the first owning-function marker wins. Marker order only breaks
# ties when one symbol contains markers from more than one phase.
PHASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("exact encode", ("probe_exact_export_announcements",)),
    ("ceiling reuse", ("reuse_grouped_exact_export_ceiling",)),
    ("overlay reconciliation", ("reconcile_exact_export_overlay",)),
    ("group-prior materialization", ("materialize_clean_group_prior",)),
    ("channel enqueue", ("enqueue_outbound_update",)),
    ("group-table commit", ("GroupRibOut::apply_delta", "GroupRibOut::apply_vpn_delta")),
    ("member-emit", ("emit_group_deltas_for_member", "emit_vpn_group_deltas_for_member")),
    ("event-publish", ("publish_route_event", "publish_best_change_events")),
    ("shared-emit build", ("build_shared_emit",)),
    ("staging eval", ("distribute_single_best_prefix",)),
    ("staging walk", ("stage_group_prefixes", "stage_update_groups")),
    (
        "recompute",
        (
            "recompute_best_after_announce",
            "recompute_best_after_withdraw",
            "recompute_best",
            "LocRib::recompute",
        ),
    ),
    ("distribute residual", ("distribute_changes",)),
    (
        "ingest + Adj-RIB-In insert",
        (
            "AdjRibIn::insert",
            "process_announce_chunk",
            "process_withdraw_chunk",
            "process_next_route_chunk",
        ),
    ),
)

OUTPUT_PHASES = (
    "ingest + Adj-RIB-In insert",
    "recompute",
    "group-table commit",
    "member-emit",
    "exact encode",
    "ceiling reuse",
    "overlay reconciliation",
    "group-prior materialization",
    "channel enqueue",
    "distribute residual",
    "event-publish",
    "staging walk",
    "staging eval",
    "shared-emit build",
    "other",
)

MAX_U64 = (1 << 64) - 1


def validate_encoded_frame(frame: str, path: Path, line_number: int) -> None:
    index = 0
    while index < len(frame):
        if frame[index] != "%":
            index += 1
            continue
        escape = frame[index : index + 3]
        if escape not in ("%25", "%3B"):
            raise ValueError(
                f"{path}:{line_number}: frame contains non-canonical percent escape {escape!r}"
            )
        index += 3


def classify_stack(frames: list[str]) -> str:
    for frame in reversed(frames):
        for phase, markers in PHASES:
            if any(marker in frame for marker in markers):
                return phase
    return "other"


def parse_folded(path: Path) -> dict[str, int]:
    totals = {phase: 0 for phase in OUTPUT_PHASES}
    previous_key: tuple[str, tuple[str, ...]] | None = None
    all_samples = 0
    ribmgr_samples = 0
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            raise ValueError(f"{path}:{line_number}: empty folded row")
        columns = raw.split("\t")
        if len(columns) != 3:
            raise ValueError(f"{path}:{line_number}: expected three tab-separated columns")
        thread, stack, count_text = columns
        if not thread:
            raise ValueError(f"{path}:{line_number}: thread name must not be empty")
        validate_encoded_frame(thread, path, line_number)
        try:
            count = int(count_text)
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: invalid sample count {count_text!r}") from error
        if count <= 0 or count > MAX_U64:
            raise ValueError(f"{path}:{line_number}: sample count must fit positive u64")
        frames = stack.split(";") if stack else []
        if not frames or any(not frame for frame in frames):
            raise ValueError(f"{path}:{line_number}: stack frames must not be empty")
        for frame in frames:
            validate_encoded_frame(frame, path, line_number)
        key = (thread, tuple(frames))
        if previous_key is not None and key <= previous_key:
            raise ValueError(f"{path}:{line_number}: folded rows must be unique and sorted")
        previous_key = key
        if all_samples > MAX_U64 - count:
            raise ValueError(f"{path}:{line_number}: total sample count exceeds u64")
        all_samples += count
        if thread == "ribmgr":
            if ribmgr_samples > MAX_U64 - count:
                raise ValueError(f"{path}:{line_number}: ribmgr sample count exceeds u64")
            ribmgr_samples += count
            phase = classify_stack(frames)
            if totals[phase] > MAX_U64 - count:
                raise ValueError(f"{path}:{line_number}: phase sample count exceeds u64")
            totals[phase] += count
    if ribmgr_samples == 0:
        raise ValueError(f"{path}: no ribmgr samples")
    if sum(totals.values()) != ribmgr_samples or all_samples < ribmgr_samples:
        raise ValueError(f"{path}: folded sample accounting mismatch")
    return totals


def render(totals: dict[str, int]) -> str:
    total = sum(totals.values())
    lines = ["phase\tsamples\tshare_percent"]
    for phase in OUTPUT_PHASES:
        count = totals[phase]
        lines.append(f"{phase}\t{count}\t{count * 100.0 / total:.6f}")
    lines.append(f"TOTAL\t{total}\t100.000000")
    return "\n".join(lines) + "\n"


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
    parser.add_argument("folded", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path, metavar="EXPECTED")
    args = parser.parse_args()

    try:
        output = render(parse_folded(args.folded))
        if args.check:
            check(args.check, output)
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        elif not args.check:
            sys.stdout.write(output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
