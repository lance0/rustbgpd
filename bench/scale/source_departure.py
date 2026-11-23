#!/usr/bin/env python3
"""Run a prebuilt source-departure cell in a fresh swap-fenced cgroup per trial.

The caller owns the host lock and campaign order. Smoke is untimed qualification.
Each invocation takes one arm and a new artifact directory, including failed trials.
`source_departure_summary.py` grades a campaign of these directories.

Exit status: 0 every trial PASS; 1 FAIL; 2 INVALID; 3 SKIP. A --break-witness
control runs every mode and exits 4 only when each trial reproduced the expected
missing witness (verdict CONTROL); anything else in a control run is INVALID.
"""

import argparse
import hashlib
import math
import os
from pathlib import Path
import resource
import subprocess
import sys

from recovery_memory import InvalidReceipt, read_object, require, snapshot_scope, uint, write_json


MODES = ("private-unicast", "grouped-unicast", "private-flowspec")
SHAPES = {"smoke": (8, 1_024), "standard": (150, 37_000), "large": (700, 400_000)}
CGROUP_ROOT = Path("/sys/fs/cgroup")
GIB = 1024**3
MISSING_WITNESS = "missing Loc-RIB application witness"
EXIT = {"PASS": 0, "FAIL": 1, "INVALID": 2, "SKIP": 3, "CONTROL": 4}


def available_memory(scope, root, meminfo):
    """Record both host headroom and remaining room under every ancestor limit."""
    available_kib = next(
        (line.split() for line in meminfo.splitlines() if line.startswith("MemAvailable:")), []
    )
    require(len(available_kib) == 3 and available_kib[2] == "kB", "missing host MemAvailable")
    host = int(available_kib[1]) * 1024
    # Leave a host reserve for the kernel and unrelated services even with no cgroup cap.
    limits = [
        {
            "source": "host MemAvailable less 4 GiB reserve",
            "available_bytes": max(0, host - 4 * GIB),
        }
    ]
    require(scope != root and scope.is_relative_to(root), "unexpected cgroup mount")
    group = scope
    while group != root:
        current = int((group / "memory.current").read_text())
        for filename in ("memory.high", "memory.max"):
            cap = (group / filename).read_text().strip()
            if cap != "max":
                limits.append(
                    {
                        "source": str(group / filename),
                        "limit_bytes": int(cap),
                        "current_bytes": current,
                        "available_bytes": max(0, int(cap) - current),
                    }
                )
        group = group.parent
    return {
        "host_available_bytes": host,
        "limits": limits,
        "limiting": min(limits, key=lambda row: row["available_bytes"]),
    }


def projected_budget(reference, digest, arm):
    receipt = read_object(reference)
    require(
        receipt["binary_sha256"] == digest
        and receipt["arm"] == arm
        and receipt["shape"] == "standard",
        "large projection requires same-binary, same-arm standard receipt",
    )
    trials = [r for r in receipt["trials"] if r["mode"] == "private-unicast"]
    require(
        trials and all(r["verdict"] == "PASS" for r in trials),
        "large projection requires passing standard private-unicast trials",
    )
    peak = max(uint(r["cgroup_peak_bytes"], "standard peak") for r in trials)
    require(peak > 0, "zero standard peak")
    # Scale the *whole* scope peak by receiver-rows, round up, then add 25%.
    # Fixed process and shared costs are therefore scaled too.
    scaled_peak = peak * math.prod(SHAPES["large"]) * 5
    divisor = math.prod(SHAPES["standard"]) * 4
    budget = (scaled_peak + divisor - 1) // divisor
    return {"bytes": budget, "source": str(reference), "standard_peak_bytes": peak}


def witness(row, spec):
    """Separate a behavioral FAIL from an absent or internally inconsistent instrument."""
    require(
        all(row.get(k) == spec[k] for k in ("mode", "receivers", "rows")), "wrong workload identity"
    )
    values = {
        k: uint(row.get(k), k)
        for k in (
            "departure_queued_ns",
            "update_queued_ns",
            "detach_started_ns",
            "selection_finished_ns",
            "loc_rib_applied_ns",
            "rib_last_withdrawal_ns",
            "rib_withdrawal_rows",
            "receiver_last_withdrawal_ns",
            "receiver_last_probe_ns",
            "update_to_applied_ns",
            "convergence_ns",
            "max_rib_poll_ns",
            "max_withdrawals_per_poll",
            "source_detach_selection_ns",
        )
    }
    started, queued, detach, selected, applied, last = (
        values[k]
        for k in (
            "departure_queued_ns",
            "update_queued_ns",
            "detach_started_ns",
            "selection_finished_ns",
            "loc_rib_applied_ns",
            "rib_last_withdrawal_ns",
        )
    )
    require(
        started <= queued <= detach <= selected <= applied, "invalid source-departure chronology"
    )
    require(queued <= last and applied != last, "ambiguous publication clocks")
    wire, probe = values["receiver_last_withdrawal_ns"], values["receiver_last_probe_ns"]
    # The winner hook precedes probe export. The withdrawal hook runs after send,
    # so a receiver can decode the last withdrawal before that hook records it.
    require(wire >= started and probe >= applied, "receiver clocks violate event chronology")
    require(
        values["convergence_ns"] == max(wire, probe) - started,
        "convergence duration disagrees with clocks",
    )
    require(
        values["source_detach_selection_ns"] == selected - detach,
        "source detach/selection duration disagrees with clocks",
    )
    require(
        values["update_to_applied_ns"] == applied - queued, "UPDATE duration disagrees with clocks"
    )
    require(
        min(
            values[name]
            for name in ("convergence_ns", "max_rib_poll_ns", "source_detach_selection_ns")
        )
        > 0,
        "empty timing evidence",
    )
    # Recovery counters describe how the receivers converged. Transient debt
    # is allowed once the departure has begun.
    recovery = row.get("post_departure_recovery")
    require(isinstance(recovery, dict), "missing post-departure recovery diagnostics")
    for name in (
        "commit_refusals",
        "route_drops",
        "dirty_resync_ticks",
        "owing_fallbacks",
        "owing_flips",
        "owed_drain_steps",
    ):
        uint(recovery.get(name), name)
    reasons = recovery.get("commit_refusals_by_reason")
    require(isinstance(reasons, dict), "missing refusal reasons")
    for reason, count in reasons.items():
        uint(count, reason)
    require(type(row.get("exact")) is bool, "missing receiver exactness")
    early = applied < last
    require(
        row.get("update_applied_before_departure_complete") is early,
        "application order disagrees with independent publication clocks",
    )
    if not row["exact"] or values["rib_withdrawal_rows"] != spec["receivers"] * spec["rows"]:
        return "FAIL", "departure rows or final receiver inventory differ"
    if early != (spec["arm"] == "candidate"):
        return (
            "FAIL",
            "unexpected Loc-RIB application order relative to final withdrawal publication",
        )
    return "PASS", "exact receiver inventory and expected Loc-RIB application order"


def classify_exit(code, stderr, broken_witness):
    """Only the driver's explicit oracle failures establish a behavioral regression."""
    failures = [line for line in stderr.splitlines() if line.startswith("FAIL: source-departure: ")]
    missing = f"source-departure: {MISSING_WITNESS}" in stderr.splitlines()
    if broken_witness:
        if code == 1 and missing and not failures:
            return "CONTROL", MISSING_WITNESS
        return "INVALID", "broken-witness control did not produce the expected missing witness"
    if code == 1 and len(failures) == 1:
        return "FAIL", failures[0]
    return "INVALID", f"rrharness exited {code}, see stderr.log"


def scoped_trial(directory):
    spec = read_object(directory / "spec.json")
    result = {"verdict": "INVALID", "mode": spec["mode"], "repetition": spec["repetition"]}
    try:
        hierarchy = Path("/proc/self/cgroup").read_text().splitlines()
        location = next(line.removeprefix("0::/") for line in hierarchy if line.startswith("0::/"))
        scope = CGROUP_ROOT / location
        require(scope.name.endswith(".scope"), "trial requires a fresh systemd scope")
        require(
            int((scope / "memory.max").read_text()) == spec["scope_limit_bytes"],
            "wrong memory fence",
        )
        snapshot_scope(scope, directory / "before")
        if spec["shape"] == "large":
            headroom = available_memory(scope, CGROUP_ROOT, Path("/proc/meminfo").read_text())
            budget = spec["large_budget"]
            write_json(directory / "preflight.json", {"budget": budget, **headroom})
            limiting = headroom["limiting"]
            if budget["bytes"] is None or budget["bytes"] > limiting["available_bytes"]:
                reason = (
                    budget["reason"]
                    if budget["bytes"] is None
                    else f"need {budget['bytes']} bytes; {limiting['source']} "
                    f"has {limiting['available_bytes']} bytes available"
                )
                result.update(verdict="SKIP", reason=reason)
                return result
        command = [
            spec["binary"],
            "source-departure",
            spec["mode"],
            str(spec["receivers"]),
            str(spec["rows"]),
        ]
        env = dict(os.environ)
        env.pop("RRHARNESS_BREAK_DEPARTURE_WITNESS", None)
        if spec["break_witness"]:
            env["RRHARNESS_BREAK_DEPARTURE_WITNESS"] = "1"
        with (
            (directory / "stdout.json").open("w") as stdout,
            (directory / "stderr.log").open("w") as stderr,
        ):
            child = subprocess.run(
                command, env=env, stdout=stdout, stderr=stderr, timeout=spec["timeout"]
            )
        result["exit"] = child.returncode
        result["process_peak_rss_bytes"] = (
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * 1024
        )
        after = snapshot_scope(scope, directory / "after")
        require(after["memory.peak"] > 0, "missing cgroup peak")
        require(
            after["memory.peak"] <= spec["scope_limit_bytes"], "trial exceeded its memory ceiling"
        )
        result["cgroup_peak_bytes"] = after["memory.peak"]
        result["swap_peak_bytes"] = after["memory.swap.peak"]
        if child.returncode:
            result["verdict"], result["reason"] = classify_exit(
                child.returncode, (directory / "stderr.log").read_text(), spec["break_witness"]
            )
        elif spec["break_witness"]:
            result.update(verdict="INVALID", reason="broken application witness falsely passed")
        else:
            row = read_object(directory / "stdout.json")
            result["observation"] = row
            result["verdict"], result["reason"] = witness(row, spec)
    except (KeyError, ValueError, OSError, StopIteration, subprocess.TimeoutExpired) as err:
        result.update(verdict="INVALID", reason=str(err) or "missing cgroup v2 hierarchy")
    finally:
        write_json(directory / "trial.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--arm", choices=("parent", "candidate"), required=True)
    parser.add_argument("--shape", choices=SHAPES, default="smoke")
    parser.add_argument("--mode", choices=MODES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, help="default: two for smoke, one otherwise")
    parser.add_argument(
        "--memory-max-bytes", type=int, default=64 * GIB, help="hard scope limit, default 64 GiB"
    )
    parser.add_argument(
        "--reference", type=Path, help="same-arm standard receipt.json for large projection"
    )
    parser.add_argument("--timeout", type=int, default=3600, help="seconds per trial")
    parser.add_argument(
        "--break-witness", action="store_true", help="smoke only; expect a witness failure"
    )
    args = parser.parse_args()
    repetitions = (
        args.repetitions if args.repetitions is not None else (2 if args.shape == "smoke" else 1)
    )
    if min(repetitions, args.memory_max_bytes, args.timeout) <= 0:
        parser.error("repetitions, scope limit and timeout must be positive")
    if args.shape == "large" and args.mode not in (None, "private-unicast"):
        parser.error("large is a private-unicast cell")
    if args.break_witness and args.shape != "smoke":
        parser.error("break-witness is a smoke-only control")
    if args.shape != "large" and args.reference:
        parser.error("memory projections only apply to the large shape")
    binary = args.binary.resolve(strict=True)
    with binary.open("rb") as artifact:
        digest = hashlib.file_digest(artifact, "sha256").hexdigest()
    large_budget = {
        "bytes": None,
        "reason": "no large-shape projection: supply a same-arm standard --reference receipt",
    }
    if args.reference:
        try:
            large_budget = projected_budget(args.reference, digest, args.arm)
        except (KeyError, OSError, ValueError) as err:
            large_budget = {
                "bytes": None,
                "source": str(args.reference),
                "reason": f"invalid standard reference: {err}",
            }

    modes = (
        (args.mode,) if args.mode else (("private-unicast",) if args.shape == "large" else MODES)
    )
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {
        "arm": args.arm,
        "shape": args.shape,
        "binary": str(binary),
        "binary_sha256": digest,
        "break_witness": args.break_witness,
        "trials": [],
    }
    receivers, rows = SHAPES[args.shape]
    for mode in modes:
        for rep in range(1, repetitions + 1):
            directory = out / f"{mode}-{rep}"
            directory.mkdir()
            write_json(
                directory / "spec.json",
                {
                    "arm": args.arm,
                    "shape": args.shape,
                    "mode": mode,
                    "rows": rows,
                    "receivers": receivers,
                    "repetition": rep,
                    "binary": str(binary),
                    "timeout": args.timeout,
                    "scope_limit_bytes": args.memory_max_bytes,
                    "break_witness": args.break_witness,
                    "large_budget": large_budget,
                },
            )
            with (directory / "scope.log").open("w") as log:
                command = [
                    "systemd-run",
                    "--user",
                    "--scope",
                    "--quiet",
                    "-p",
                    "MemorySwapMax=0",
                    "-p",
                    f"MemoryMax={args.memory_max_bytes}",
                    "--",
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "_trial",
                    str(directory),
                ]
                try:
                    completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
                    trial = read_object(directory / "trial.json")
                    require(completed.returncode == 0, f"scope exited {completed.returncode}")
                except (OSError, ValueError) as err:
                    trial = {
                        "mode": mode,
                        "repetition": rep,
                        "verdict": "INVALID",
                        "reason": f"scope could not produce a receipt: {err}",
                    }
                    write_json(directory / "trial.json", trial)
            receipt["trials"].append(trial)
            write_json(out / "receipt.json", receipt)
            print(f"{mode} rep {rep}: {trial['verdict']} — {trial['reason']}", flush=True)
            expected = "CONTROL" if args.break_witness else "PASS"
            if trial["verdict"] != expected:
                return EXIT["INVALID" if args.break_witness else trial["verdict"]]
    return EXIT["CONTROL" if args.break_witness else "PASS"]


def entry():
    """An unusable invocation is INVALID (2), never the FAIL status."""
    if sys.argv[1:2] == ["_trial"]:
        scoped_trial(Path(sys.argv[2]))
        return
    try:
        sys.exit(main())
    except (InvalidReceipt, OSError, KeyError, ValueError) as err:
        print(f"INVALID: {err}", file=sys.stderr)
        sys.exit(EXIT["INVALID"])


if __name__ == "__main__":
    entry()
