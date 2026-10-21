#!/usr/bin/env python3
"""Post-hoc analyzer for the gRPC inject-churn soak.

Reads samples.csv, run.json and rustbgpd.log from the matching runner
and emits a JSON verdict against the soak-specific gates:

  - RSS slope (MB/hour) < 1.0, fitted over post-warmup samples only
  - intern table size (bgp_rib_attr_intern_global_size) slope per hour < 1.0,
    fitted over the same post-warmup samples
  - peak RSS < 512 MB
  - session established in the final CSV sample (no flap)
  - churn cycles meet 50% of the configured post-warmup cadence (at least one)
  - final consumer route count exactly matches the live target
  - unchanged flap count and nondecreasing session uptime
  - valid daemon log with no ERROR records

With run.json lease_mode == 1 (ADR-0141 owner leases), also:

  - every owner controller exits 0 with no failed add, and every ordinary
    renewal succeeds
  - healthy owners hold all their keys at FRR and a live lease in every
    post-warmup sample
  - each flap cycle: FRR drops the flapping owner's keys no earlier than
    lease after the send of its last renewal and has lost them all within
    lease + 5 s of that renewal's reply, then holds them all again after
    the re-add; at least max(1, active / (2 * (flap interval + lease)))
    cycles complete
  - every stale-generation renewal is refused (attempts > 0): one after the
    expiry (no resurrection) and one after the re-add (superseded
    generation) in each cycle
  - the flapping owner's generation keeps its incarnation and its
    sequence strictly increases at every add
  - every 1 Hz /readyz probe returns 200, at least soak_seconds / 2 probes

Stdlib only. Exit code 0 on pass, 1 on any gate failure, 2 on
harness/input error, including fewer than MIN_SLOPE_SAMPLES samples at or
after warmup_sec (insufficient evidence for a slope).
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Optional

from flagship_daemon_log import analyze_daemon_log, unique_members

REQUIRED = {
    "elapsed_sec", "rss_mb", "intern_size", "live_target", "frr_route_count",
    "bgp_established", "churn_cycles", "add_total", "del_total",
    "flap_count", "uptime_seconds",
}
COUNTERS = REQUIRED - {"elapsed_sec", "rss_mb", "bgp_established"}
LEASE_META = ("lease_owners", "lease_keys_per_owner", "lease_seconds",
              "lease_renew_sec", "lease_flap_interval_sec")
EXPIRY_SLACK_SEC = 5.0
MIN_SLOPE_SAMPLES = 2


def safe_float(value: str | None) -> Optional[float]:
    if value is None or value in ("", "NaN", "nan"):
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def linreg(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2:
        return float("nan")
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return float("nan")
    return num / den


def analyze(rows: list[dict[str, str]], minimum_cycles: int, warmup_sec: int) -> dict:
    rss_pts: list[tuple[float, float]] = []
    intern_pts: list[tuple[float, float]] = []
    peak_rss = max(float(row["rss_mb"]) for row in rows)
    established_final: list[str] = []
    max_cycles = 0
    first_flaps = first_uptime = final_flaps = final_uptime = 0
    final_target = final_routes = 0

    for row in rows:
        e = safe_float(row.get("elapsed_sec"))
        r = safe_float(row.get("rss_mb"))
        i = safe_float(row.get("intern_size"))
        # The slope gates fit only post-warmup samples; peak RSS spans the run.
        if e is not None and r is not None and e >= warmup_sec:
            rss_pts.append((e, r))
        if e is not None and i is not None and e >= warmup_sec:
            intern_pts.append((e, i))
        c = safe_float(row.get("churn_cycles"))
        if c is not None:
            max_cycles = max(max_cycles, int(c))
        established_final.append(row.get("bgp_established", ""))
        flaps = int(safe_float(row.get("flap_count")))
        uptime = int(safe_float(row.get("uptime_seconds")))
        if len(established_final) == 1:
            first_flaps, first_uptime = flaps, uptime
        final_flaps, final_uptime = flaps, uptime
        final_target = int(safe_float(row.get("live_target")))
        final_routes = int(safe_float(row.get("frr_route_count")))

    distinct = len({e for e, _ in rss_pts})
    if distinct < MIN_SLOPE_SAMPLES:
        raise ValueError(
            f"insufficient evidence: {distinct} distinct sample time(s) at or after "
            f"warmup_sec={warmup_sec}, need {MIN_SLOPE_SAMPLES} for the slope gates")
    rss_slope = linreg([e / 3600 for e, _ in rss_pts], [r for _, r in rss_pts])
    intern_slope = linreg([e / 3600 for e, _ in intern_pts], [i for _, i in intern_pts])

    final_established = bool(established_final) and established_final[-1] == "1"

    gates = {
        "intern_slope_per_hour": {
            "value": intern_slope if not math.isnan(intern_slope) else None,
            "limit": 1.0,
            "pass": (not math.isnan(intern_slope)) and intern_slope < 1.0,
        },
        "rss_slope_per_hour": {
            "value": rss_slope if not math.isnan(rss_slope) else None,
            "limit": 1.0,
            "pass": (not math.isnan(rss_slope)) and rss_slope < 1.0,
        },
        "peak_rss_mb": {
            "value": peak_rss if not math.isnan(peak_rss) else None,
            "limit": 512.0,
            "pass": (not math.isnan(peak_rss)) and peak_rss < 512.0,
        },
        "churn_cycles": {
            "value": max_cycles,
            "limit": minimum_cycles,
            "pass": max_cycles >= minimum_cycles,
        },
        "final_session_established": {
            "value": final_established,
            "pass": final_established,
        },
        "final_consumer_convergence": {
            "value": {"target": final_target, "routes": final_routes},
            "pass": final_target > 0 and final_routes == final_target,
        },
        "session_continuity": {
            "value": {"flap_delta": final_flaps - first_flaps,
                      "uptime_delta": final_uptime - first_uptime},
            "pass": final_flaps == first_flaps and final_uptime >= first_uptime,
        },
    }

    all_pass = all(g["pass"] for g in gates.values())
    return {
        "verdict": "pass" if all_pass else "fail",
        "churn_cycles": max_cycles,
        "intern_slope_per_hour": intern_slope if not math.isnan(intern_slope) else None,
        "rss_slope_per_hour": rss_slope if not math.isnan(rss_slope) else None,
        "peak_rss_mb": peak_rss if not math.isnan(peak_rss) else None,
        "samples": len(rows),
        "slope_window": {"from_elapsed_sec": warmup_sec, "samples": len(rss_pts)},
        "gates": gates,
    }


def gate(value, ok: bool) -> dict:
    return {"value": value, "pass": bool(ok)}


def load_lease_evidence(run_dir: str, meta: dict):
    """Parse the lease evidence; any malformed or missing file is ValueError."""
    for key in LEASE_META:
        if type(meta.get(key)) is not int or meta[key] < 1:
            raise ValueError(f"run.json has invalid {key}")
    owners = [f"soak-lease-{k}" for k in range(1, meta["lease_owners"] + 1)]
    root = Path(run_dir)
    events = []
    for number, line in enumerate(
            (root / "lease-events.log").read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split()
        if len(parts) < 3 or parts[1] not in owners:
            raise ValueError(f"lease-events.log line {number} is malformed")
        stamp = safe_float(parts[0])
        if stamp is None:
            raise ValueError(f"lease-events.log line {number} has no timestamp")
        fields = dict(p.split("=", 1) for p in parts[3:] if "=" in p)
        events.append((stamp, parts[1], parts[2], parts[3:], fields))
    samples = []
    for number, line in enumerate(
            (root / "lease-samples.jsonl").read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(line, object_pairs_hook=unique_members)
        if (not isinstance(row, dict) or type(row.get("elapsed_sec")) is not int
                or not isinstance(row.get("leases"), list)
                or not isinstance(row.get("frr_counts"), list)
                or len(row["frr_counts"]) != len(owners)
                or any(type(c) is not int for c in row["frr_counts"])):
            raise ValueError(f"lease-samples.jsonl line {number} is malformed")
        samples.append(row)
    with (root / "readyz.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["epoch", "code", "seconds"]:
            raise ValueError("readyz.csv has the wrong header")
        readyz = []
        for number, row in enumerate(reader, 2):
            seconds = safe_float(row["seconds"])
            if not (row["code"] or "").isdigit() or seconds is None:
                raise ValueError(f"readyz.csv row {number} is malformed")
            readyz.append((int(row["code"]), seconds))
    return owners, events, samples, readyz


def generation(text: str):
    incarnation, _, sequence = (text or "").partition(":")
    if not incarnation.isdigit() or not sequence.isdigit():
        return None
    return int(incarnation), int(sequence)


def analyze_leases(run_dir: str, meta: dict) -> dict:
    owners, events, samples, readyz = load_lease_evidence(run_dir, meta)
    keys, lease = meta["lease_keys_per_owner"], meta["lease_seconds"]
    flapper, healthy = owners[-1], owners[:-1]

    exits = {o: [f.get("rc") for _, owner, kind, _, f in events
                 if owner == o and kind == "controller_exit"] for o in owners}
    add_failures = sum(1 for e in events if e[2] == "add_failed")
    renewals = {o: {"renewed": 0, "other": 0} for o in owners}
    for _, owner, kind, args, _ in events:
        if kind == "renew":
            renewals[owner]["renewed" if args == ["renewed"] else "other"] += 1

    presence_violations = []
    checked = 0
    for row in samples:
        if row["elapsed_sec"] < meta["warmup_sec"]:
            continue
        checked += 1
        live = {entry.get("owner") for entry in row["leases"]
                if isinstance(entry, dict)
                and safe_float(str(entry.get("leaseRemainingMs", 0))) not in (None, 0.0)}
        for index, owner in enumerate(healthy):
            if row["frr_counts"][index] != keys or owner not in live:
                presence_violations.append(
                    {"elapsed_sec": row["elapsed_sec"], "owner": owner,
                     "frr_count": row["frr_counts"][index], "lease_live": owner in live})

    # Flap cycles, in this order.
    order = ["flap_stop", "frr_gone", "stale_renew:expired", "added",
             "stale_renew:superseded", "frr_back"]
    cycles, cycle_violations, gens = [], [], []
    current = None
    for _, owner, kind, _args, fields in events:
        if owner != flapper:
            continue
        if kind == "added":
            gens.append(fields.get("gen"))
        if kind == "flap_stop":
            if current is not None:
                cycle_violations.append({"cycle": len(cycles) + 1, "error": "incomplete"})
            current = {"steps": [kind], "fields": fields}
            continue
        step = f"{kind}:{fields.get('phase')}" if kind == "stale_renew" else kind
        if current is None or step not in order:
            continue
        current["steps"].append(step)
        current[kind] = fields
        if kind != "frr_back":
            continue
        cycle_number = len(cycles) + 1
        stop = current["fields"]
        t0, t1 = safe_float(stop.get("t0")), safe_float(stop.get("t1"))
        gone = current.get("frr_gone", {})
        drop, gone_at = safe_float(gone.get("drop")), safe_float(gone.get("at"))
        back_at = safe_float(fields.get("at"))
        error = None
        if current["steps"] != order:
            error = f"out-of-order steps {current['steps']}"
        elif t0 is None or t1 is None or drop is None or gone_at is None:
            error = "FRR never lost the keys"
        elif drop < t0 + lease:
            error = f"dropped {t0 + lease - drop:.2f} s before the deadline"
        elif gone_at > t1 + lease + EXPIRY_SLACK_SEC:
            error = f"still present {gone_at - t1 - lease:.2f} s after the deadline"
        elif back_at is None:
            error = "FRR never regained the keys after the re-add"
        cycles.append(None if gone_at is None or t1 is None
                      else round(gone_at - t1 - lease, 3))
        if error:
            cycle_violations.append({"cycle": cycle_number, "error": error})
        current = None
    if current is not None:
        cycle_violations.append({"cycle": len(cycles) + 1, "error": "incomplete"})
    active = meta["soak_seconds"] - meta["warmup_sec"]
    minimum_cycles = max(1, active // (2 * (meta["lease_flap_interval_sec"] + lease)))

    stale = {"expired": [0, 0], "superseded": [0, 0]}
    for _, _, kind, args, fields in events:
        if kind == "stale_renew":
            counts = stale.setdefault(str(fields.get("phase")), [0, 0])
            counts[0] += 1
            counts[1] += args[0] == "refused"
    attempts = sum(a for a, _ in stale.values())
    refused = sum(r for _, r in stale.values())

    parsed = [generation(g) for g in gens]
    increasing = (len(parsed) >= 2 and None not in parsed
                  and len({g[0] for g in parsed}) == 1
                  and all(a[1] < b[1] for a, b in zip(parsed, parsed[1:])))

    failures = [code for code, _ in readyz if code != 200]
    minimum_probes = meta["soak_seconds"] // 2

    return {
        "lease_controllers": gate(
            {"exits": exits, "add_failures": add_failures},
            add_failures == 0 and all(v == ["0"] for v in exits.values())),
        "lease_renewals": gate(
            renewals, all(r["renewed"] > 0 and r["other"] == 0 for r in renewals.values())),
        "lease_healthy_presence": gate(
            {"samples": checked, "violations": presence_violations[:20]},
            checked > 0 and not presence_violations),
        "lease_flap_expiry": gate(
            {"cycles": len(cycles), "minimum": minimum_cycles,
             "seconds_past_deadline": cycles, "violations": cycle_violations},
            len(cycles) >= minimum_cycles and not cycle_violations),
        "lease_stale_renewals_refused": gate(
            {"attempts": attempts, "refused": refused,
             "by_phase": {k: {"attempts": a, "refused": r} for k, (a, r) in stale.items()}},
            attempts > 0 and refused == attempts),
        "lease_generation_increase": gate(gens, increasing),
        "readyz": gate(
            {"probes": len(readyz), "minimum": minimum_probes, "failures": len(failures),
             "max_seconds": max((t for _, t in readyz), default=None)},
            len(readyz) >= minimum_probes and not failures),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze inject-churn soak")
    parser.add_argument("run_dir",
                        help="Soak run directory containing samples.csv, run.json and rustbgpd.log")
    parser.add_argument("--output", help="Write verdict JSON to this path")
    args = parser.parse_args()

    csv_path = f"{args.run_dir}/samples.csv"
    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            missing = REQUIRED - set(reader.fieldnames or [])
            if missing:
                print(f"error: missing required columns: {', '.join(sorted(missing))}", file=sys.stderr)
                return 2
            rows = list(reader)
    except OSError as e:
        print(f"error reading {csv_path}: {e}", file=sys.stderr)
        return 2

    if not rows:
        print("error: samples.csv is empty", file=sys.stderr)
        return 2
    for line, row in enumerate(rows, 2):
        for column in REQUIRED - {"bgp_established"}:
            value = safe_float(row.get(column))
            if value is None:
                print(f"error: row {line}: invalid {column}", file=sys.stderr)
                return 2
            if column in COUNTERS and (value < 0 or not value.is_integer()):
                print(f"error: row {line}: invalid counter {column}", file=sys.stderr)
                return 2
        if row["bgp_established"] not in {"0", "1"}:
            print(f"error: row {line}: invalid bgp_established", file=sys.stderr)
            return 2

    try:
        with open(f"{args.run_dir}/run.json", encoding="utf-8") as stream:
            meta = json.load(stream, object_pairs_hook=unique_members)
        if not isinstance(meta, dict):
            raise ValueError("run.json must be an object")
        for key in ("soak_seconds", "churn_interval_sec", "warmup_sec"):
            value = meta.get(key)
            minimum = 0 if key == "warmup_sec" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"run.json has invalid {key}")
        if meta["warmup_sec"] >= meta["soak_seconds"]:
            raise ValueError("warmup_sec must be less than soak_seconds")
        active_seconds = meta["soak_seconds"] - meta["warmup_sec"]
    except (OSError, ValueError) as exc:
        print(f"error reading run metadata: {exc}", file=sys.stderr)
        return 2
    # Integer ceiling preserves the documented fractional window floor.
    denominator = 2 * meta["churn_interval_sec"]
    minimum_cycles = max(1, (active_seconds + denominator - 1) // denominator)

    try:
        result = analyze(rows, minimum_cycles, meta["warmup_sec"])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    result["gates"]["daemon_log"] = analyze_daemon_log(args.run_dir)
    lease_mode = meta.get("lease_mode", 0)
    if type(lease_mode) is not int or lease_mode not in (0, 1):
        print("error reading run metadata: run.json has invalid lease_mode", file=sys.stderr)
        return 2
    if lease_mode:
        try:
            result["gates"].update(analyze_leases(args.run_dir, meta))
        except (OSError, ValueError) as exc:
            print(f"error reading lease evidence: {exc}", file=sys.stderr)
            return 2
    result["verdict"] = "pass" if all(g["pass"] for g in result["gates"].values()) else "fail"
    out = json.dumps(result, indent=2)
    print(out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
