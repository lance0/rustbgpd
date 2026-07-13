#!/usr/bin/env python3
"""Classify sanitized event-history producer full-daemon perf stacks and apply the proceed gate."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


MANAGER_MARKERS = (
    "rustbgpd_rib::manager::",
    "rustbgpd_rib::manager::RibManager",
)
PRODUCER_MARKERS = (
    "EhmRibSink",
    "route_event_to_bgp_event",
    "evpn_event_to_bgp_event",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def require_no_symlink_components(path: Path) -> None:
    """Reject a perf input whose leaf or any existing parent is a symlink."""
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            fail("perf script contains a symlink component")


def classify(path: Path, phase: str, mode: str) -> dict[str, object]:
    require_no_symlink_components(path)
    if not path.is_file():
        fail("perf script is not a regular file")
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except OSError as error:
        fail(f"cannot read perf script: {error.strerror or error.__class__.__name__}")
    except UnicodeError as error:
        fail(f"cannot decode perf script: {error}")
    if "/home/" in text or "/Users/" in text:
        fail("perf script contains an unsanitized host path")
    blocks = [block for block in text.split("\n\n") if block.strip()]
    total = manager = producer = 0
    for block in blocks:
        lines = block.splitlines()
        if not any("PID/TID [CPU] TIME:" in line for line in lines[:2]):
            continue
        if len(lines) < 2:
            fail("perf sample has no callchain")
        total += 1
        stack = "\n".join(lines[1:])
        is_manager = any(marker in stack for marker in MANAGER_MARKERS)
        is_producer = any(marker in stack for marker in PRODUCER_MARKERS)
        manager += int(is_manager)
        producer += int(is_manager and is_producer)
    if total == 0:
        fail("perf script contains no sanitized samples")
    if manager == 0:
        fail("perf script contains no RIB-manager samples")
    percent = producer * 100.0 / manager
    if not math.isfinite(percent):
        fail("producer attribution is non-finite")
    if mode == "disabled" and producer != 0:
        fail("disabled/default profile contains EHM producer samples")
    result = {
        "phase": phase,
        "event_history_mode": mode,
        "total_samples": total,
        "rib_manager_samples": manager,
        "ehm_producer_samples": producer,
        "ehm_producer_pct_of_rib_manager": percent,
        "baseline_proceed_threshold_pct": 5.0,
        "baseline_proceed_pass": mode == "enabled" and phase == "baseline" and percent >= 5.0,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--mode", choices=("enabled", "disabled"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = classify(args.input, args.phase, args.mode)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"rib_manager_samples={result['rib_manager_samples']}")
    print(f"ehm_producer_samples={result['ehm_producer_samples']}")
    print(f"ehm_producer_pct={result['ehm_producer_pct_of_rib_manager']:.6f}")


if __name__ == "__main__":
    main()
